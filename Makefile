GO ?= go
LDFLAGS = -s -w
MODULE_SAFE = sh scripts/go-module-safe.sh

.PHONY: test test-go-module-wrapper build cross-build verify

# The wrapper snapshots and byte-restores go.mod and go.sum around every
# module-mutating Go invocation, including failures and signals. Build targets
# therefore cannot act as an implicit dependency updater; use an explicit tidy
# workflow and review its module-file changes separately.
test: test-go-module-wrapper
	@$(MODULE_SAFE) $(GO) test -mod=mod ./...

# This is a separate, non-recursive target: the regression harness exercises
# the wrapper in an isolated fixture and never invokes `make test` recursively.
test-go-module-wrapper:
	@sh scripts/test-go-module-safe.sh

build:
	@mkdir -p build
	@$(MODULE_SAFE) $(GO) build -mod=mod -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-router ./cmd/mosdns-router
	@$(MODULE_SAFE) $(GO) build -mod=mod -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-cdnctl ./cmd/mosdns-cdnctl

cross-build:
	@mkdir -p build/linux-amd64 build/linux-arm64
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(MODULE_SAFE) $(GO) build -mod=mod -trimpath -o build/linux-amd64/mosdns-router ./cmd/mosdns-router
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(MODULE_SAFE) $(GO) build -mod=mod -trimpath -o build/linux-arm64/mosdns-router ./cmd/mosdns-router

verify: test
	@$(MODULE_SAFE) $(GO) vet -mod=mod ./...
