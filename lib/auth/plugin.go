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

package auth

import (
	"sync"
)

var pluginMutex = &sync.Mutex{}
var plugin Plugin

var pluginAltMutex = &sync.Mutex{}
var pluginAlt PluginAlt

// GetPlugin returns auth API server plugin that allows injecting handlers
func GetPlugin() Plugin {
	pluginMutex.Lock()
	defer pluginMutex.Unlock()
	return plugin
}

func GetPluginAlt() PluginAlt {
	pluginAltMutex.Lock()
	defer pluginAltMutex.Unlock()
	return pluginAlt
}

// SetPluginAlt sets plugin for the auth API server
func SetPluginAlt(p PluginAlt) {
	pluginAltMutex.Lock()
	defer pluginAltMutex.Unlock()
	pluginAlt = p
}

func SetPlugin(p Plugin) {
	pluginMutex.Lock()
	defer pluginMutex.Unlock()
	plugin = p
}

// PluginAlt is auth API server extension setter
type PluginAlt interface {
	// AddHandlers adds handlers to the auth API server
	AddHandlers(srv *APIServerAlt)
}

type Plugin interface {
	// AddHandlers adds handlers to the auth API server
	AddHandlers(srv *APIServer)
}
