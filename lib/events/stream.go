/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gravitational/teleport/lib/auth/proto"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"

	"github.com/sirupsen/logrus"
)

const (
	stateInit = 0

	stateOpenRaw  = 1
	stateChunkRaw = 2
	stateCloseRaw = 3

	stateOpenEvents  = 4
	stateChunkEvents = 5
	stateCloseEvents = 6

	stateComplete = 7
)

//const (
//	typeRaw   = 0
//	typeEvent = 1
//)

const (
	concurrentStreams = 2
)

type SessionUploader interface {
	UploadSessionRecording(r SessionRecording) error
}

type StreamManager struct {
	log *logrus.Entry

	pool         sync.Pool
	semaphore    chan struct{}
	closeContext context.Context
}

type Stream struct {
	manager  *StreamManager
	state    int64
	uploader SessionUploader

	sessionID string

	// tarWriter is used to create the archive itself.
	tarWriter *tar.Writer

	// zipBuffer
	zipBuffer *bytes.Buffer

	// zipWriter is used to create the zip files within the archive.
	zipWriter *gzip.Writer

	closeContext context.Context
	closeCancel  context.CancelFunc
}

func NewStreamManger(ctx context.Context) *StreamManager {
	return &StreamManager{
		log: logrus.WithFields(logrus.Fields{
			trace.Component: "stream",
		}),
		pool: sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
		semaphore:    make(chan struct{}, concurrentStreams),
		closeContext: ctx,
	}
}

func (s *StreamManager) NewStream(ctx context.Context, uploader SessionUploader) (*Stream, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &Stream{
		manager:      s,
		state:        stateInit,
		uploader:     uploader,
		closeContext: ctx,
		closeCancel:  cancel,
	}, nil
}

func (s *StreamManager) takeSemaphore() error {
	select {
	case s.semaphore <- struct{}{}:
		return nil
	case <-s.closeContext.Done():
		return errContext
	}
}

func (s *StreamManager) releaseSemaphore() error {
	select {
	case <-s.semaphore:
		return nil
	case <-s.closeContext.Done():
		return errContext
	}
}

func (s *Stream) Process(chunk *proto.SessionChunk) error {
	// Check that the state transitions are sane.
	err := s.checkTransition(chunk)
	if err != nil {
		return trace.Wrap(err)
	}
	// TODO: Is it safe to transition the state without knowing if it was successful?
	s.setState(chunk.GetState())

	switch chunk.GetState() {
	case stateInit:
		s.sessionID = chunk.GetSessionID()
		s.manager.log.Debugf("Changing state to INIT for stream %v.", s.sessionID)

		// Create a streaming tar reader/writer to reduce how much of the archive
		// is buffered in memory.
		pr, pw := io.Pipe()
		s.tarWriter = tar.NewWriter(pw)

		// Kick off the upload in a goroutine so it can be uploaded as it
		// is processed.
		go s.upload(chunk.GetNamespace(), session.ID(chunk.GetSessionID()), pr)
	case stateComplete:
		s.manager.log.Debugf("Changing state to COMPLETE for stream %v.", s.sessionID)

		err = s.tarWriter.Close()
		if err != nil {
			return trace.Wrap(err)
		}
	// Raw events are directly streamed into the tar archive.
	case stateOpenRaw, stateCloseRaw, stateChunkRaw:
		err = s.processRaw(chunk)
		if err != nil {
			return trace.Wrap(err)
		}
	// Events are aggregated into a gzip archive in memory first, then streamed
	// to the tar archive.
	case stateOpenEvents, stateCloseEvents, stateChunkEvents:
		err = s.processEvents(chunk)
		if err != nil {
			return trace.Wrap(err)
		}
	// Reject all unknown event types.
	default:
		err = trace.BadParameter("unknown event type %v", chunk.GetState())
	}
	return nil
}

// processRaw takes chunks and directly streams them into the tar archive.
func (s *Stream) processRaw(chunk *proto.SessionChunk) error {
	var err error

	switch chunk.GetState() {
	// Open the tar archive by writing the header. Since this is a raw stream
	// the size of the content to be written is known.
	case stateOpenRaw:
		s.manager.log.Debugf("Changing state to OPEN RAW for stream %v.", s.sessionID)

		err := s.tarWriter.WriteHeader(&tar.Header{
			Name: chunk.GetName(),
			Mode: 0600,
			Size: chunk.GetFileSize(),
		})
		if err != nil {
			return trace.Wrap(err)
		}
	// Close is a NOP because writing a header indicates the size of file and
	// where the next file starts.
	case stateCloseRaw:
		s.manager.log.Debugf("Changing state to CLOSE RAW for stream %v.", s.sessionID)
	// Chunk can be written directly to the tar archive.
	case stateChunkRaw:
		s.manager.log.Debugf("Changing state to CHUNK RAW for stream %v.", s.sessionID)

		fmt.Printf("--> Raw chunk: %v.\n", hex.Dump(chunk.GetData()))

		_, err = s.tarWriter.Write(chunk.GetData())
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// processEvents takes chunks, validates them, and then buffers them in a
// gzip stream until complete then writes them to the tar archive.
func (s *Stream) processEvents(chunk *proto.SessionChunk) error {
	var err error

	switch chunk.GetState() {
	case stateOpenEvents:
		s.manager.log.Debugf("Changing state to OPEN EVENTS for stream %v.", s.sessionID)

		// Get a buffer from the pool.
		s.zipBuffer = s.manager.pool.Get().(*bytes.Buffer)

		s.zipWriter, err = gzip.NewWriterLevel(s.zipBuffer, gzip.BestSpeed)
		if err != nil {
			return trace.Wrap(err)
		}
	case stateCloseEvents:
		s.manager.log.Debugf("Changing state to CLOSE EVENTS for stream %v.", s.sessionID)

		// Close zip file and after writing it to the tar archive, release
		// any resources.
		err = s.zipWriter.Close()
		if err != nil {
			return trace.Wrap(err)
		}
		defer s.zipBuffer.Reset()
		defer s.manager.pool.Put(s.zipBuffer)

		// Copy the zip archive into the tar stream.
		err := s.tarWriter.WriteHeader(&tar.Header{
			Name: chunk.GetName(),
			Mode: 0600,
			Size: int64(s.zipBuffer.Len()),
		})
		if err != nil {
			return trace.Wrap(err)
		}
		_, err = io.Copy(s.tarWriter, s.zipBuffer)
		if err != nil {
			return trace.Wrap(err)
		}
	case stateChunkEvents:
		s.manager.log.Debugf("Changing state to CHUNK EVENTS for stream %v.", s.sessionID)

		_, err = s.zipWriter.Write(append(chunk.GetData(), '\n'))
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (s *Stream) GetState() int64 {
	return atomic.LoadInt64(&s.state)
}

func (s *Stream) setState(state int64) {
	atomic.StoreInt64(&s.state, state)
}

func (s *Stream) checkTransition(chunk *proto.SessionChunk) error {
	return nil
}

func (s *Stream) Reader() io.Reader {
	return nil
}

func (s *Stream) Close() error {
	s.closeCancel()
	return nil
}

func (s *Stream) upload(namespace string, sessionID session.ID, reader io.Reader) {
	err := s.uploader.UploadSessionRecording(SessionRecording{
		CancelContext: s.closeContext,
		SessionID:     sessionID,
		Namespace:     namespace,
		Recording:     reader,
	})
	if err != nil {
		s.manager.log.Warnf("Failed to upload session recording: %v.", err)
	}
}

func StreamSessionRecording(stream proto.AuthService_StreamSessionRecordingClient, r SessionRecording) error {
	// Initialize stream.
	err := stream.Send(&proto.SessionChunk{
		State:     stateInit,
		Namespace: r.Namespace,
		SessionID: r.SessionID.String(),
	})
	if err != nil {
		return trail.FromGRPC(err)
	}

	// Open the tarball for reading, some content (like chunks) will be sent
	// raw and some uncompressed and sent.
	tr := tar.NewReader(r.Recording)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return trace.Wrap(err)
		}

		// All files that end with an events suffix are opened then sent.
		isEvents := strings.HasSuffix(header.Name, eventsSuffix)

		// Send file open chunk.
		err = sendOpenEvent(stream, header, isEvents)
		if err != nil {
			return trace.Wrap(err)
		}

		// Send content chunks. Raw chunks will be sent as-is, event chunks are
		// un-compressed and sent so they can be validated and the archive
		// re-constructed.
		if !isEvents {
			err = sendRawChunks(stream, tr)
		} else {
			err = sendEventChunks(stream, tr)
		}
		if err != nil {
			return trace.Wrap(err)
		}

		// Send file close chunk.
		err = sendCloseEvent(stream, header, isEvents)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// Send complete event.
	err = stream.Send(&proto.SessionChunk{
		State: stateComplete,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// All done, send a complete message and close the stream.
	err = stream.CloseSend()
	if err != nil {
		return trail.FromGRPC(err)
	}
	return nil
}

// sendOpenEvent sends either a stateOpenRaw or stateOpenEvents chunk.
func sendOpenEvent(stream proto.AuthService_StreamSessionRecordingClient, header *tar.Header, isEvents bool) error {
	chunkState := stateOpenRaw
	if isEvents {
		chunkState = stateOpenEvents
	}

	err := stream.Send(&proto.SessionChunk{
		State:    int64(chunkState),
		Name:     header.Name,
		FileSize: header.Size,
	})
	if err != nil {
		return trail.FromGRPC(err)
	}

	return nil
}

// sendCloseEvent sends either a stateCloseRaw or stateCloseEvents chunk.
func sendCloseEvent(stream proto.AuthService_StreamSessionRecordingClient, header *tar.Header, isEvents bool) error {
	chunkState := stateCloseRaw
	if isEvents {
		chunkState = stateCloseEvents
	}

	err := stream.Send(&proto.SessionChunk{
		State:    int64(chunkState),
		Name:     header.Name,
		FileSize: header.Size,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// sendRawChunks breaks and streams file in 1 MB chunks.
func sendRawChunks(stream proto.AuthService_StreamSessionRecordingClient, reader io.Reader) error {
	var fileDone bool

	for {
		// Read in one megabyte at a time until the end of the file.
		data := make([]byte, 4096)
		n, err := reader.Read(data)
		if err != nil && err != io.EOF {
			return trace.Wrap(err)
		}
		if err == io.EOF {
			fileDone = true
		}

		// Send raw file chunk.
		if len(data) > 0 {
			err = stream.Send(&proto.SessionChunk{
				State: stateChunkRaw,
				Data:  data[:n],
			})
			if err != nil {
				return trace.Wrap(err)
			}
		}

		// Exit out if no more data to be read or the file is done (got io.EOF).
		if len(data) == 0 || fileDone {
			break
		}
	}

	return nil
}

// sendEventChunks sends the events file one line at a time to allow the
// server to validate each incoming event.
func sendEventChunks(stream proto.AuthService_StreamSessionRecordingClient, reader io.Reader) error {
	// Wrap the reader in a gzip reader to uncompress the archive.
	zr, err := gzip.NewReader(reader)
	if err != nil {
		return trace.Wrap(err)
	}
	defer zr.Close()

	// Loop over file line by line.
	scanner := bufio.NewScanner(zr)
	for scanner.Scan() {
		// Send event chunk.
		err = stream.Send(&proto.SessionChunk{
			State: stateChunkEvents,
			Data:  scanner.Bytes(),
		})
	}
	err = scanner.Err()
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}
