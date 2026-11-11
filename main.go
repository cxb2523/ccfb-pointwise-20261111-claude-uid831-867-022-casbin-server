// Copyright 2018 The casbin Authors. All Rights Reserved.
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

//go:generate protoc -I proto --go_out=plugins=grpc:proto proto/casbin.proto

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"os"

	"github.com/casbin/casbin-server/auth"
	pb "github.com/casbin/casbin-server/proto"
	"github.com/casbin/casbin-server/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

func recoverInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in %s: %v", info.FullMethod, r)
			err = status.Errorf(codes.Internal, "internal error: %v", r)
		}
	}()
	return handler(ctx, req)
}

func main() {
	var port int
	var configPath string
	flag.IntVar(&port, "port", 50051, "listening port")
	flag.StringVar(&configPath, "config", "config/connection_config.json", "path to the connection/auth config file")
	flag.Parse()

	if port < 1 || port > 65535 {
		panic(fmt.Sprintf("invalid port number: %d", port))
	}

	if envPath := os.Getenv("CONNECTION_CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}

	// Fail fast: an enabled-but-tokenless auth config must not start.
	authenticator, err := auth.NewFromFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file: keep the historical behavior of running
			// without auth, but make it loud.
			log.Printf("auth: config file %q not found, authentication disabled", configPath)
			authenticator = auth.New(auth.DisabledSnapshot())
		} else {
			log.Fatalf("auth: invalid config: %v", err)
		}
	}
	stopWatch, err := authenticator.Watch(configPath)
	if err != nil {
		log.Printf("auth: hot-reload watcher unavailable: %v", err)
	} else {
		defer stopWatch()
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.ChainUnaryInterceptor(authenticator.UnaryInterceptor(), recoverInterceptor))
	pb.RegisterCasbinServer(s, server.NewServer())
	// Register the health service so probes can use the whitelisted check.
	healthpb.RegisterHealthServer(s, health.NewServer())
	// Register reflection service on gRPC server.
	reflection.Register(s)
	log.Println("Listening on", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
