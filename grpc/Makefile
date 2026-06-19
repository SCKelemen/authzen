# Makefile for the AuthZEN gRPC binding (nested module).
#
# Tooling:
#   - buf                 (https://buf.build) drives protoc
#   - protoc-gen-go       google.golang.org/protobuf/cmd/protoc-gen-go
#   - protoc-gen-go-grpc  google.golang.org/grpc/cmd/protoc-gen-go-grpc
#
# Install the Go plugins onto your PATH, e.g.:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

.PHONY: all generate deps lint format build test tidy clean check

all: generate build test

## deps: fetch the buf module dependencies (googleapis) into buf.lock.
deps:
	buf dep update

## generate: regenerate the Go + gRPC stubs under gen/.
generate:
	buf generate

## lint: lint the proto files.
lint:
	buf lint

## format: format the proto files in place.
format:
	buf format -w

## build: compile the module.
build:
	go build ./...

## test: run the test suite.
test:
	go test ./...

## tidy: tidy the Go module.
tidy:
	go mod tidy

## check: the full local gate (lint, vet, build, test).
check: lint
	go vet ./...
	go build ./...
	go test ./...

## clean: remove generated code (regenerate with `make generate`).
clean:
	rm -rf gen
