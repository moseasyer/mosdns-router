GO ?= go
LDFLAGS = -s -w

.PHONY: test build cross-build verify restore-toolchain check-go-mod

# Go 1.25.0 removes the explicitly required, redundant toolchain directive when
# it is allowed to update go.mod. Restore only that directive; any other module
# change remains visible instead of being silently discarded.
restore-toolchain:
	@$(GO) mod edit -toolchain=go1.25.0

# A successful module command is only reproducible if it did not leave an
# unrelated go.mod edit behind. The check is intentionally after restoration so
# the required toolchain line itself is not reported as drift.
check-go-mod:
	@git diff --exit-code -- go.mod

# The EXIT trap runs for both successful commands and failures. It preserves
# the command's status, while a failure to restore metadata is still reported.
test:
	@trap 'set +e; status=$$?; $(MAKE) --no-print-directory restore-toolchain; restore_status=$$?; if [ $$restore_status -ne 0 ] && [ $$status -eq 0 ]; then status=$$restore_status; fi; exit $$status' EXIT; set -e; \
	$(GO) test -mod=mod ./...; \
	$(MAKE) --no-print-directory restore-toolchain; \
	$(MAKE) --no-print-directory check-go-mod

build:
	@mkdir -p build
	@trap 'set +e; status=$$?; $(MAKE) --no-print-directory restore-toolchain; restore_status=$$?; if [ $$restore_status -ne 0 ] && [ $$status -eq 0 ]; then status=$$restore_status; fi; exit $$status' EXIT; set -e; \
	$(GO) build -mod=mod -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-router ./cmd/mosdns-router; \
	$(GO) build -mod=mod -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-cdnctl ./cmd/mosdns-cdnctl; \
	$(MAKE) --no-print-directory restore-toolchain; \
	$(MAKE) --no-print-directory check-go-mod

cross-build:
	@mkdir -p build/linux-amd64 build/linux-arm64
	@trap 'set +e; status=$$?; $(MAKE) --no-print-directory restore-toolchain; restore_status=$$?; if [ $$restore_status -ne 0 ] && [ $$status -eq 0 ]; then status=$$restore_status; fi; exit $$status' EXIT; set -e; \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -mod=mod -trimpath -o build/linux-amd64/mosdns-router ./cmd/mosdns-router; \
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -mod=mod -trimpath -o build/linux-arm64/mosdns-router ./cmd/mosdns-router; \
	$(MAKE) --no-print-directory restore-toolchain; \
	$(MAKE) --no-print-directory check-go-mod

verify: test
	@trap 'set +e; status=$$?; $(MAKE) --no-print-directory restore-toolchain; restore_status=$$?; if [ $$restore_status -ne 0 ] && [ $$status -eq 0 ]; then status=$$restore_status; fi; exit $$status' EXIT; set -e; \
	$(GO) vet -mod=mod ./...; \
	$(MAKE) --no-print-directory restore-toolchain; \
	$(MAKE) --no-print-directory check-go-mod
