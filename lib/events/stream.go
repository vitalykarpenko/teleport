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
	"fmt"
	"io"
	"io/ioutil"
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
	stateInit     = 0
	stateOpen     = 1
	stateChunk    = 2
	stateClose    = 3
	stateComplete = 4
)

const (
	typeRaw   = 0
	typeEvent = 1
)

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
	var err error

	switch chunk.GetState() {
	case stateInit:
		s.sessionID = chunk.GetSessionID()
		s.manager.Debugf("Changing state to INIT for stream %v.", s.sessionID)

		// Create a streaming tar reader/writer to reduce how much of the archive
		// is buffered in memory.
		pr, pw := io.Pipe()
		s.tarWriter = tar.NewWriter(pw)

		// Kick off the upload in a goroutine so it can be uploaded as it
		// is processed.
		go s.upload(chunk.GetNamespace(), session.ID(chunk.GetSessionID()), pr)
	case stateOpen:
		s.manager.Debugf("Changing state to OPEN for stream %v.", s.sessionID)

		//// Get a buffer from the pool.
		s.zipBuffer = s.manager.pool.Get().(*bytes.Buffer)

		//s.zipWriter = gzip.NewWriter(s.zipBuffer)
		s.zipWriter, err = gzip.NewWriterLevel(s.zipBuffer, gzip.BestSpeed)
		//s.zipWriter, err = gzip.NewWriterLevel(&s.zipBuffer, gzip.BestSpeed)
		if err != nil {
			return trace.Wrap(err)
		}
	case stateChunk:
		//fmt.Printf("--> Process: stateChunk.\n")

		// If the chunk is an events chunk, then validate it.
		switch {
		case strings.Contains(chunk.GetType(), "events"):
			// TODO: Validate event.
			//fmt.Printf("--> Process: stateChunk: %v.\n", string(chunk.GetPayload()))

			_, err = s.zipWriter.Write(append(chunk.GetPayload(), '\n'))
			if err != nil {
				return trace.Wrap(err)
			}
		default:
			_, err = s.zipWriter.Write(chunk.GetPayload())
			if err != nil {
				return trace.Wrap(err)
			}
		}
	case stateClose:
		//fmt.Printf("--> Process: stateClose. Filename: %v, Len: %v.\n", chunk.GetFilename(), s.zipBuffer.Len())

		err = s.zipWriter.Close()
		if err != nil {
			return trace.Wrap(err)
		}
		err := s.tarWriter.WriteHeader(&tar.Header{
			Name: chunk.GetFilename(),
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

		s.zipBuffer.Reset()
		s.manager.pool.Put(s.zipBuffer)

		//err = s.manager.releaseSemaphore()
		//if err != nil {
		//	return trace.Wrap(err)
		//}
	case stateComplete:
		//fmt.Printf("--> Process: stateComplete.\n")

		err = s.tarWriter.Close()
		if err != nil {
			return trace.Wrap(err)
		}

		return fmt.Errorf("blahblah")

	}
	return nil
}

func (s *Stream) GetState() int64 {
	return atomic.LoadInt64(&s.state)
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

		// Send file open chunk.
		openChunk := &proto.SessionChunk{
			State:    stateOpen,
			Type:     typeRaw,
			Name:     header.Name,
			FileSize: header.Size,
		}
		if strings.HasSuffix(header.Name, eventsSuffix) {
			openChunk.Type = typeEvent
		}
		err = stream.Send(openChunk)
		if err != nil {
			return trail.FromGRPC(err)
		}

		// Send content chunks. Raw chunks will be sent as-is, event chunks are
		// un-compressed and sent so they can be validated and the archive
		// re-constructed.
		if strings.HasSuffix(header.Name, eventsSuffix) {
			err = sendRawChunks(stream, tr)
		} else {
			err = sendEventChunks(tr, header, stream)
		}
		if err != nil {
			return trace.Wrap(err)
		}

		// Send file close chunk.
		closeChunk := &proto.SessionChunk{
			State:    stateClose,
			Type:     typeRaw,
			Name:     header.Name,
			Filename: header.Size,
		}
		if strings.HasSuffix(header.Name, eventsSuffix) {
			closeChunk.Type = typeEvent
		}
		err = stream.Send(closeChunk)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	//// Send complete event.
	//err = stream.Send(&proto.SessionChunk{
	//	State: stateComplete,
	//})
	//if err != nil {
	//	return trace.Wrap(err)
	//}

	// All done, send a complete message and close the stream.
	err = stream.CloseSend()
	if err != nil {
		return trail.FromGRPC(err)
	}
	return nil
}

// sendRawChunks breaks and streams file in 1 MB chunks.
func sendRawChunks(stream proto.AuthService_StreamSessionRecordingClient, reader io.Reader) error {
	for {
		// Read in one megabyte at a time until the end of the file.
		data := make([]byte, 0, megabyte)
		_, err := reader.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			return trace.Wrap(err)
		}

		// Send raw file chunk.
		err = stream.Send(&proto.SessionChunk{
			State: stateChunk,
			Type:  typeRaw,
			Data:  data,
		})
		if err != nil {
			return trace.Wrap(err)
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
			State:   stateChunk,
			Type:    typeEvent,
			Payload: scanner.Bytes(),
		})
	}
	err = scanner.Err()
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

const (
	megabyte = 1000000
)
