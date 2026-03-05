# x-identity gRPC service
BINARY_NAME ?= xidentity
MAIN_PKG    := ./cmd/xidentity
GO          := go
GOFLAGS     :=
LDFLAGS     := -s -w
PROTO_ROOT  ?= ../x-proto

.PHONY: all build build-linux test run clean deps lint generate

all: deps build

deps:
	$(GO) mod tidy
	$(GO) mod download

build:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) $(MAIN_PKG)

build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-amd64 $(MAIN_PKG)

test:
	$(GO) test $(GOFLAGS) ./...

test-coverage:
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

run: build
	./bin/$(BINARY_NAME)

lint:
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || $(GO) vet ./...

clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Regenerate gRPC Go stubs from the proto file in x-proto.
# Requires protoc, protoc-gen-go, and protoc-gen-go-grpc to be installed.
generate:
	mkdir -p internal/gen
	protoc \
		--plugin=protoc-gen-go=$(shell which protoc-gen-go) \
		--plugin=protoc-gen-go-grpc=$(shell which protoc-gen-go-grpc) \
		--proto_path=$(PROTO_ROOT) \
		--go_out=paths=source_relative:internal/gen \
		--go-grpc_out=paths=source_relative:internal/gen \
		$(PROTO_ROOT)/identity/v1/identity.proto
