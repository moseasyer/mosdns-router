GO ?= go

# The DHCP bridge is half of this project: the state document the Go plugin reads
# is written by Python, and a change to one half that only the other half's tests
# can see is a change nobody notices. Its suite therefore runs with the Go one.
PYTHON ?= python3
BRIDGE_TESTS := bridge/tests

# Every entry point refuses to run on a different Go release: the module pins
# go 1.25.8, the reproducible build metadata assumes exactly that compiler, and
# the packaged dnscrypt-proxy 2.1.18 declares `go 1.25.8` in its own go.mod.
GO_REQUIRED_VERSION := 1.25.8

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

.PHONY: check-go test test-integration test-python test-make-entrypoints build cross-build verify verify-build-info

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
#
# -short is what makes this the unit suite. The end-to-end suite in
# tests/integration builds the router and starts a process per case, so it
# honours -short and skips itself. `verify` reaches it through test-integration
# below, and the entry-point regression asserts that it does, so the acceptance
# gate cannot pass without the end-to-end cases and cannot pay for them twice.
test: check-go test-python
	@$(GO) test -mod=readonly -short ./...
	@sh scripts/test-make-entrypoints.sh

# A separate, non-recursive target, so the end-to-end suite can be run on its own
# while the routing is being changed. It builds the router itself rather than
# reading build/mosdns-router, because `go test ./...` runs this package and
# nothing guarantees that a `make build` has already happened. MOSDNS_ROUTER_GO
# carries GO through, so the binary under test is built by the toolchain check-go
# just accepted rather than by whichever go happens to be on PATH.
#
# -count=1 because this suite's work is not something the test cache can see: it
# binds sockets and runs a child process, and a cached pass would be a gate
# satisfied without a single case having been asked. The entry-point regression
# asserts this flag is here, so it cannot be dropped and left as a comment.
#
# The suite skips on a host with no non-loopback IPv4 address, because the
# production DHCP state decoder refuses a loopback upstream and the alternative
# would be a bypass of the validation these cases exist to hold to. A skip is the
# right answer on a laptop and the wrong answer in a gate, so MOSDNS_REQUIRE_INTEGRATION=1
# turns it into a failure. It is exported from the recipe rather than left to CI,
# because nothing else set it: a loopback-only host passed this gate with zero
# end-to-end coverage and said nothing about it. `?=` so a developer on such a host
# can still run the gate and take the skip, with
# `make verify MOSDNS_REQUIRE_INTEGRATION=0`; the entry-point regression asserts
# both the export and the default, so neither can be dropped and left as a comment.
#
# The value is assigned in the recipe line rather than by a bare `export`
# directive, so what reaches the suite is the make variable and nothing else. A
# caller relaxes it either way -- `make verify MOSDNS_REQUIRE_INTEGRATION=0` or a
# MOSDNS_REQUIRE_INTEGRATION=0 in the environment, since `?=` respects both -- but
# the recipe line is what `make -n` prints, and that is the line the entry-point
# regression asserts, so the two cannot drift apart while the recipe still works.
MOSDNS_REQUIRE_INTEGRATION ?= 1

test-integration: check-go
	@MOSDNS_REQUIRE_INTEGRATION='$(MOSDNS_REQUIRE_INTEGRATION)' MOSDNS_ROUTER_GO='$(GO)' $(GO) test -mod=readonly -count=1 ./tests/integration

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

verify: test test-integration verify-build-info
	@$(GO) vet -mod=readonly ./...
