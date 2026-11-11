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

package auth_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/casbin/casbin-server/auth"
	pb "github.com/casbin/casbin-server/proto"
	"github.com/casbin/casbin-server/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	tokenA = "token-alpha"
	tokenB = "token-bravo"
)

// testServer is a real gRPC server (over bufconn) wired with the auth
// interceptor, the casbin service and the health service.
type testServer struct {
	authenticator *auth.Authenticator
	grpcServer    *grpc.Server
	conn          *grpc.ClientConn
	client        pb.CasbinClient
	health        healthpb.HealthClient
	enforcer      int32
}

func writeConfig(t *testing.T, dir string, enable bool, token string) string {
	t.Helper()
	path := filepath.Join(dir, "connection_config.json")
	content := fmt.Sprintf(`{"driver":"file","connection":"x","enforcer":"y","enable":%t,"token":%q}`, enable, token)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startServer(t *testing.T, configPath string) *testServer {
	t.Helper()

	authenticator, err := auth.NewFromFile(configPath)
	if err != nil {
		t.Fatalf("startup load: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer(grpc.UnaryInterceptor(authenticator.UnaryInterceptor()))
	pb.RegisterCasbinServer(s, server.NewServer())
	healthpb.RegisterHealthServer(s, health.NewServer())
	go func() { _ = s.Serve(lis) }()

	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}

	ts := &testServer{
		authenticator: authenticator,
		grpcServer:    s,
		conn:          conn,
		client:        pb.NewCasbinClient(conn),
		health:        healthpb.NewHealthClient(conn),
	}
	t.Cleanup(func() {
		conn.Close()
		s.Stop()
	})

	// NewEnforcer is itself a protected call; set it up with a token that
	// works regardless of which fixture token the test uses, by doing it
	// through a raw (unauthenticated-disabled) path is not possible — so
	// tests pass the current token to setupEnforcer.
	return ts
}

func (ts *testServer) setupEnforcer(t *testing.T, token string) {
	t.Helper()
	modelText, err := os.ReadFile("../examples/rbac_model.conf")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", token)
	}
	resp, err := ts.client.NewEnforcer(ctx, &pb.NewEnforcerRequest{
		ModelText:     string(modelText),
		AdapterHandle: -1,
	})
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	ts.enforcer = resp.Handler
}

// enforce issues one Enforce call; token "" means no credentials attached.
func (ts *testServer) enforce(token string) error {
	ctx := context.Background()
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", token)
	}
	_, err := ts.client.Enforce(ctx, &pb.EnforceRequest{
		EnforcerHandler: ts.enforcer,
		Params:          []string{"alice", "data1", "read"},
	})
	return err
}

func isUnauthenticated(err error) bool {
	return status.Code(err) == codes.Unauthenticated
}

func TestAuthDisabled(t *testing.T) {
	dir := t.TempDir()
	ts := startServer(t, writeConfig(t, dir, false, ""))
	ts.setupEnforcer(t, "")

	if err := ts.enforce(""); err != nil {
		t.Fatalf("auth disabled: request without token should pass, got %v", err)
	}
	if err := ts.enforce("anything"); err != nil {
		t.Fatalf("auth disabled: any token should pass, got %v", err)
	}
}

func TestAuthValidToken(t *testing.T) {
	dir := t.TempDir()
	ts := startServer(t, writeConfig(t, dir, true, tokenA))
	ts.setupEnforcer(t, tokenA)

	if err := ts.enforce(tokenA); err != nil {
		t.Fatalf("raw token should pass, got %v", err)
	}
	if err := ts.enforce("Bearer " + tokenA); err != nil {
		t.Fatalf("Bearer-prefixed token should pass, got %v", err)
	}
	if err := ts.enforce("bearer " + tokenA); err != nil {
		t.Fatalf("case-insensitive Bearer prefix should pass, got %v", err)
	}
}

func TestAuthMissingToken(t *testing.T) {
	dir := t.TempDir()
	ts := startServer(t, writeConfig(t, dir, true, tokenA))
	ts.setupEnforcer(t, tokenA)

	if err := ts.enforce(""); !isUnauthenticated(err) {
		t.Fatalf("missing token should be Unauthenticated, got %v", err)
	}
	if err := ts.enforce("Bearer "); !isUnauthenticated(err) {
		t.Fatalf("empty Bearer credential should be Unauthenticated, got %v", err)
	}
}

func TestAuthWrongToken(t *testing.T) {
	dir := t.TempDir()
	ts := startServer(t, writeConfig(t, dir, true, tokenA))
	ts.setupEnforcer(t, tokenA)

	if err := ts.enforce("wrong-token"); !isUnauthenticated(err) {
		t.Fatalf("wrong token should be Unauthenticated, got %v", err)
	}
	// A token that shares a prefix with the real one must still fail.
	if err := ts.enforce(tokenA + "-suffix"); !isUnauthenticated(err) {
		t.Fatalf("near-miss token should be Unauthenticated, got %v", err)
	}
}

func TestAuthHealthCheckWhitelisted(t *testing.T) {
	dir := t.TempDir()
	ts := startServer(t, writeConfig(t, dir, true, tokenA))

	// No credentials at all — the probe must get through.
	resp, err := ts.health.Check(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("health check should be whitelisted, got %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("unexpected health status: %v", resp.Status)
	}
}

func TestAuthStartupFailFast(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, true, "")
	if _, err := auth.NewFromFile(path); err == nil {
		t.Fatal("enabled auth with empty token must fail at startup")
	}

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.NewFromFile(badJSON); err == nil {
		t.Fatal("malformed config must fail at startup")
	}
}

func TestAuthReloadInvalidKeepsOldToken(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, true, tokenA)
	ts := startServer(t, path)
	ts.setupEnforcer(t, tokenA)

	// Invalid reload: enabled but empty token.
	writeConfig(t, dir, true, "")
	if err := ts.authenticator.Reload(path); err == nil {
		t.Fatal("reload with empty token must be rejected")
	}
	if err := ts.enforce(tokenA); err != nil {
		t.Fatalf("old token must keep working after rejected reload, got %v", err)
	}

	// Invalid reload: malformed JSON.
	if err := os.WriteFile(path, []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ts.authenticator.Reload(path); err == nil {
		t.Fatal("reload with malformed JSON must be rejected")
	}
	if err := ts.enforce(tokenA); err != nil {
		t.Fatalf("old token must keep working after rejected reload, got %v", err)
	}

	// Valid reload: rotate to tokenB.
	writeConfig(t, dir, true, tokenB)
	if err := ts.authenticator.Reload(path); err != nil {
		t.Fatalf("valid reload failed: %v", err)
	}
	if err := ts.enforce(tokenB); err != nil {
		t.Fatalf("new token should work after rotation, got %v", err)
	}
	if err := ts.enforce(tokenA); !isUnauthenticated(err) {
		t.Fatalf("old token should be rejected after rotation, got %v", err)
	}
}

// TestAuthConcurrentRotation hammers Enforce from several goroutines while
// the token rotates between tokenA and tokenB. Run with -race. Every request
// must be judged by exactly one snapshot: the never-valid token must always
// fail, and valid-token calls may only ever see nil or Unauthenticated —
// never a third state.
func TestAuthConcurrentRotation(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, true, tokenA)
	ts := startServer(t, path)
	ts.setupEnforcer(t, tokenA)

	const callers = 8
	const rotations = 50

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errCh := make(chan error, callers)

	worker := func(token string, expectAlwaysFail bool) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			err := ts.enforce(token)
			if expectAlwaysFail {
				if !isUnauthenticated(err) {
					errCh <- fmt.Errorf("never-valid token got non-Unauthenticated result: %v", err)
					return
				}
				continue
			}
			if err != nil && !isUnauthenticated(err) {
				errCh <- fmt.Errorf("token %q got unexpected error (third state): %v", token, err)
				return
			}
		}
	}

	// Half the workers carry tokenA, half tokenB, plus one with a
	// never-valid token.
	for i := 0; i < callers; i++ {
		wg.Add(1)
		switch {
		case i == 0:
			go worker("never-valid", true)
		case i%2 == 0:
			go worker(tokenA, false)
		default:
			go worker(tokenB, false)
		}
	}

	// Rotate the token back and forth while requests are in flight.
	for i := 0; i < rotations; i++ {
		token := tokenA
		if i%2 == 1 {
			token = tokenB
		}
		writeConfig(t, dir, true, token)
		if err := ts.authenticator.Reload(path); err != nil {
			t.Fatalf("rotation %d failed: %v", i, err)
		}
	}

	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// Final state is tokenB: it must work, tokenA must not.
	if err := ts.enforce(tokenB); err != nil {
		t.Fatalf("final token should work, got %v", err)
	}
	if err := ts.enforce(tokenA); !isUnauthenticated(err) {
		t.Fatalf("rotated-out token should fail, got %v", err)
	}
}

// TestAuthWatchHotReload rewrites the config file on disk and expects the
// fsnotify watcher to rotate the token without a restart.
func TestAuthWatchHotReload(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, true, tokenA)
	ts := startServer(t, path)
	ts.setupEnforcer(t, tokenA)

	stopWatch, err := ts.authenticator.Watch(path)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	t.Cleanup(stopWatch)

	writeConfig(t, dir, true, tokenB)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := ts.enforce(tokenB); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watcher did not pick up the token rotation in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := ts.enforce(tokenA); !isUnauthenticated(err) {
		t.Fatalf("old token should be rejected after hot reload, got %v", err)
	}

	// A broken rewrite must be rejected and keep the current token.
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := ts.enforce(tokenB); err != nil {
			t.Fatalf("token must survive a rejected hot reload, got %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
