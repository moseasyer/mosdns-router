GO ?= go

# The DHCP bridge is half of this project: the state document the Go plugin reads
# is written by Python, and a change to one half that only the other half's tests
# can see is a change nobody notices. Its suite therefore runs with the Go one.
PYTHON ?= python3
BRIDGE_TESTS := bridge/tests

# Every entry point refuses to run on a different Go release: the module pins
# go 1.25.0 and the reproducible build metadata assumes exactly that compiler.
GO_REQUIRED_VERSION := 1.25.0

LDFLAGS ?= -s -w
BUILDINFO_PKG := mosdns-router/internal/buildinfo

# The build identity is supplied by the caller, or derived from this checkout.
# `ifndef` keeps an explicit VERSION=, REVISION=, or BUILD_TIME= override
# authoritative while still freezing the derived value once.
ifndef VERSION
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
endif
ifndef REVISION
REVISION := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
endif
ifndef BUILD_TIME
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
endif

METADATA_LDFLAGS := -X $(BUILDINFO_PKG).Version=$(VERSION) -X $(BUILDINFO_PKG).Revision=$(REVISION) -X $(BUILDINFO_PKG).BuildTime=$(BUILD_TIME)

.PHONY: check-go test test-python test-make-entrypoints build cross-build verify verify-build-info

# The guard is the only place that decides whether this host's Go is acceptable.
check-go:
	@if ! version=$$($(GO) version 2>&1); then \
		echo "mosdns-router: '$(GO)' is not a usable Go toolchain: $$version" >&2; \
		exit 1; \
	fi; \
	set -- $$version; \
	if [ "$$3" != "go$(GO_REQUIRED_VERSION)" ]; then \
		echo "mosdns-router: Go $(GO_REQUIRED_VERSION) is required, found $${3:-unknown}" >&2; \
		exit 1; \
	fi

# -mod=readonly on every Go command makes the entry points unable to act as an
# implicit dependency updater: a stale go.mod or go.sum fails the command
# instead of being silently rewritten. Run `go mod tidy` explicitly and review
# its module-file changes as a separate step.
test: check-go test-python
	@$(GO) test -mod=readonly ./...
	@sh scripts/test-make-entrypoints.sh

# A separate, non-recursive target, so the bridge suite can be run on its own
# while it is being changed. `test` and therefore `verify` depend on it, because
# the two halves of the bridge share one state schema and one committed fixture.
test-python:
	@$(PYTHON) -m unittest discover -s $(BRIDGE_TESTS)

# This is a separate, non-recursive target: the regression harness inspects the
# real Makefile with `make -n` and never invokes `make test` recursively.
test-make-entrypoints:
	@sh scripts/test-make-entrypoints.sh

build: check-go
	@mkdir -p build
	@$(GO) build -mod=readonly -trimpath -ldflags '$(LDFLAGS) $(METADATA_LDFLAGS)' -o build/mosdns-router ./cmd/mosdns-router
	@$(GO) build -mod=readonly -trimpath -ldflags '$(LDFLAGS) $(METADATA_LDFLAGS)' -o build/mosdns-cdnctl ./cmd/mosdns-cdnctl

cross-build: check-go
	@mkdir -p build/linux-amd64 build/linux-arm64
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -mod=readonly -trimpath -ldflags '$(METADATA_LDFLAGS)' -o build/linux-amd64/mosdns-router ./cmd/mosdns-router
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -mod=readonly -trimpath -ldflags '$(METADATA_LDFLAGS)' -o build/linux-arm64/mosdns-router ./cmd/mosdns-router

# A build that forgot the metadata injection would otherwise ship a binary that
# reports dev/unknown/unknown, so verification reads the metadata back out of
# the built router instead of trusting the linker flags.
verify-build-info: build
	@$(GO) run -mod=readonly ./internal/buildinfo/cmd/check build/mosdns-router

verify: test verify-build-info
	@$(GO) vet -mod=readonly ./...
