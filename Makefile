SHELL := /bin/bash

BINARY      := kernledger
FIXTURE     := ir-lab-target
PKG         := github.com/example/kernledger
CMD         := ./cmd/kernledger
FIXTURE_CMD := ./cmd/ir-lab-target
VERSION     ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS     := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

# Target host is Amazon Linux 2 → linux/amd64 by default. Cross-compile
# from any dev workstation.
GOOS   ?= linux
GOARCH ?= amd64

.PHONY: all build build-host build-fixture build-fixture-host test vet tidy fmt clean release

all: build

# Cross-compiled production binary (the one you ship to the IR host).
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-$(GOOS)-$(GOARCH) $(CMD)

# Native build for local development / running unit tests.
build-host:
	go build -ldflags '$(LDFLAGS)' -o dist/$(BINARY) $(CMD)

# Cross-compiled lab fixture for validating collection on a target host.
build-fixture:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -trimpath -o dist/$(FIXTURE)-$(GOOS)-$(GOARCH) $(FIXTURE_CMD)

# Native build of the lab fixture for local experiments.
build-fixture-host:
	go build -o dist/$(FIXTURE) $(FIXTURE_CMD)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

# Convenience target: build static linux/amd64 and linux/arm64 (Graviton).
release:
	$(MAKE) build GOOS=linux GOARCH=amd64
	$(MAKE) build GOOS=linux GOARCH=arm64

clean:
	rm -rf dist/
