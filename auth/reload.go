// Copyright 2026 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

// Watch starts hot-reloading the auth config at path: on fsnotify events
// touching the file and on SIGHUP. A reload that fails validation is
// rejected — the previous token keeps serving. Returns a stop function.
func (a *Authenticator) Watch(path string) (func(), error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	// Watch the parent directory, not the file itself: many editors
	// replace the file on save, which would detach a file-level watch.
	if err := watcher.Add(filepath.Dir(abs)); err != nil {
		watcher.Close()
		return nil, err
	}

	done := make(chan struct{})

	reload := func(reason string) {
		if err := a.Reload(abs); err != nil {
			log.Printf("auth: rejecting config reload (%s): %v — keeping previous token", reason, err)
			return
		}
		log.Printf("auth: config reloaded (%s)", reason)
	}

	go func() {
		for {
			select {
			case <-done:
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				eventPath, err := filepath.Abs(event.Name)
				if err != nil || eventPath != abs {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					reload("file changed")
				}
			case err, ok := <-watcher.Errors:
				if ok {
					log.Printf("auth: watcher error: %v", err)
				}
			}
		}
	}()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for {
			select {
			case <-done:
				signal.Stop(sig)
				return
			case <-sig:
				reload("SIGHUP")
			}
		}
	}()

	return func() {
		close(done)
		watcher.Close()
	}, nil
}
