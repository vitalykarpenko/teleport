/*
Copyright 2017 Gravitational, Inc.

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

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/tool/teleport/common"
)

func main() {
	_, cfg := common.Run(common.Options{
		Args:     os.Args[1:],
		InitOnly: true,
	}, nil)

	//	cfg := service.MakeDefaultConfig()

	// bc := &process.Config.Auth.StorageConfig

	bk, err := lite.New(context.TODO(), cfg.Auth.StorageConfig.Params)
	if err != nil {
		panic(fmt.Errorf("No config in backend on start: %s", err))
	}
	//cfg.Trust = local.NewCAService(bk)
	cfg.Trust = NewMyCAService(bk, cfg).CA

	// precomputeCount := native.PrecomputedNum
	// // in case if not auth or proxy services are enabled,
	// // there is no need to precompute any SSH keys in the pool
	// if !cfg.Auth.Enabled && !cfg.Proxy.Enabled {
	// 	precomputeCount = 0
	// }
	// if cfg.Keygen, err = native.New(context.TODO(), native.PrecomputeKeys(precomputeCount)); err != nil {
	// 	panic(fmt.Errorf("Error on keygen alt creation: %s", err))
	// }

	common.Run(common.Options{
		Args: os.Args[1:],
	}, cfg)

	// p, err := service.NewTeleport(cfg)

	// authServer := p.GetAuthServer()
	// authServer.Trust = NewMyCAService(p.GetBackend(), cfg)

	// fmt.Println("err:", err)
	// p.Run()
}

//MyCA ..
type MyCA struct {
	*local.CA
}

//NewMyCAService ..
func NewMyCAService(b backend.Backend, config *service.Config) *MyCA {
	bk, err := lite.New(context.TODO(), config.Auth.StorageConfig.Params)
	if err != nil {
		panic(fmt.Errorf("No config in backend on start: %s", err))
	}

	return &MyCA{
		CA: local.NewCAService(bk),
	}
}

/*
type CA struct {
	backend.Backend
}

// NewCAService returns new instance of CAService
func NewCAService(b backend.Backend) *CA {
	log.Error("*** NewCAService")
	return &CA{
		Backend: b,
	}
}
*/
