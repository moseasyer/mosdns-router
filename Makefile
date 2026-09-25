GO ?= go

# Every entry point refuses to run on a different Go release: the module pins
# go 1.25.0 and the reproducible build metadata assumes exactly that compiler.
GO_REQUIRED_VERSION := 1.25.0

LDFLAGS ?= -s -w

.PHONY: check-go test test-make-entrypoints build cross-build verify

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
test: check-go
	@$(GO) test -mod=readonly ./...
	@sh scripts/test-make-entrypoints.sh

# This is a separate, non-recursive target: the regression harness inspects the
# real Makefile with `make -n` and never invokes `make test` recursively.
test-make-entrypoints:
	@sh scripts/test-make-entrypoints.sh

build: check-go
	@mkdir -p build
	@$(GO) build -mod=readonly -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-router ./cmd/mosdns-router
	@$(GO) build -mod=readonly -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-cdnctl ./cmd/mosdns-cdnctl

cross-build: check-go
	@mkdir -p build/linux-amd64 build/linux-arm64
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -mod=readonly -trimpath -o build/linux-amd64/mosdns-router ./cmd/mosdns-router
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -mod=readonly -trimpath -o build/linux-arm64/mosdns-router ./cmd/mosdns-router

verify: test
	@$(GO) vet -mod=readonly ./...
