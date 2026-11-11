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

// Package auth implements a static-token unary interceptor for the gRPC
// server, with hot-reloadable configuration.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// DefaultWhitelist is used when the config file does not declare
// "auth_whitelist". The gRPC health probe must stay reachable.
var DefaultWhitelist = []string{"/grpc.health.v1.Health/Check"}

// Config is the auth-related section of config/connection_config.json.
// Unknown fields are ignored so old/new config files stay compatible.
type Config struct {
	Enable        bool     `json:"enable"`
	Token         string   `json:"token"`
	AuthWhitelist []string `json:"auth_whitelist"`
}

// Snapshot is the immutable auth state swapped atomically on rotation.
// In-flight requests keep judging by the Snapshot loaded at entry.
type Snapshot struct {
	enabled   bool
	tokenHash [32]byte
	whitelist map[string]bool
}

// validate is the single validation rule shared by startup (fail-fast)
// and runtime reload (reject and keep the old state).
func validate(cfg Config) error {
	if cfg.Enable && strings.TrimSpace(cfg.Token) == "" {
		return fmt.Errorf("auth is enabled but token is empty")
	}
	return nil
}

// snapshotFromConfig converts a validated config into an immutable Snapshot.
func snapshotFromConfig(cfg Config) (Snapshot, error) {
	if err := validate(cfg); err != nil {
		return Snapshot{}, err
	}
	whitelist := cfg.AuthWhitelist
	if len(whitelist) == 0 {
		whitelist = DefaultWhitelist
	}
	snap := Snapshot{
		enabled:   cfg.Enable,
		tokenHash: sha256.Sum256([]byte(cfg.Token)),
		whitelist: make(map[string]bool, len(whitelist)),
	}
	for _, m := range whitelist {
		snap.whitelist[m] = true
	}
	return snap, nil
}

// LoadFile reads and validates the auth config from path.
func LoadFile(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	cfg := Config{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Snapshot{}, fmt.Errorf("invalid config JSON: %w", err)
	}
	return snapshotFromConfig(cfg)
}

// DisabledSnapshot returns a Snapshot with authentication turned off.
func DisabledSnapshot() Snapshot {
	snap, _ := snapshotFromConfig(Config{})
	return snap
}

// Authenticator holds the current auth Snapshot. The hot path is lock-free:
// readers atomically load the Snapshot, rotation stores a whole new one.
type Authenticator struct {
	current atomic.Value // stores Snapshot
}

// New returns an Authenticator seeded with the given Snapshot.
func New(snap Snapshot) *Authenticator {
	a := &Authenticator{}
	a.current.Store(snap)
	return a
}

// NewFromFile loads the auth config from path. Startup should treat an
// error as fatal (fail-fast).
func NewFromFile(path string) (*Authenticator, error) {
	snap, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	return New(snap), nil
}

// Reload re-reads the config file and atomically swaps the Snapshot.
// On any error the old Snapshot is kept and the error is returned, so a
// bad reload degrades gracefully instead of breaking a running server.
func (a *Authenticator) Reload(path string) error {
	snap, err := LoadFile(path)
	if err != nil {
		return err
	}
	a.current.Store(snap)
	return nil
}

// UnaryInterceptor enforces the static token on every non-whitelisted call.
func (a *Authenticator) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		snap := a.current.Load().(Snapshot)
		if !snap.enabled {
			return handler(ctx, req)
		}
		if snap.whitelist[info.FullMethod] {
			return handler(ctx, req)
		}
		token, ok := extractToken(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing authorization credentials")
		}
		// Hash the client credential first so the comparison runs on
		// fixed-length values and never leaks the token length.
		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(sum[:], snap.tokenHash[:]) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		return handler(ctx, req)
	}
}

// extractToken pulls the credential from the "authorization" metadata,
// tolerating an optional "Bearer " prefix (any case).
func extractToken(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", false
	}
	token := strings.TrimSpace(vals[0])
	if len(token) >= 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		return "", false
	}
	return token, true
}
