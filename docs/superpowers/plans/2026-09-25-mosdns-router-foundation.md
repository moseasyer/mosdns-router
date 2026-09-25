# MOSDNS Router Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the reproducible Go/Python workspace, strict policy schema, atomic runtime-state formats, file locking, and build entry points required by every later subsystem.

**Architecture:** A small Go module named `mosdns-router` wraps upstream MOSDNS v5.3.4 through its public plugin APIs rather than forking the repository. Shared policy and runtime-state contracts live under `internal/`; later plans implement the DHCP bridge, DNSCrypt integration, optimizer, and response plugins against those contracts.

**Tech Stack:** Go 1.25, MOSDNS v5.3.4, `miekg/dns` v1.1.72 through MOSDNS, Cobra v1.10.2, YAML v3, standard-library tests, Make.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- Support Ubuntu 22.04 LTS, 24.04 LTS, and 26.04 LTS on amd64 and arm64.
- Do not modify the development host's NetworkManager, resolved, Firefox, `/etc/resolv.conf`, or DNS services.
- Never generate a default Chinese public DNS address.
- Never add a local DoH listener, custom CA, TLS MITM, SNI DPI, ClearDNS, or Docker runtime dependency.
- All runtime state files use schema version 1, same-directory temporary files, `fsync`, validation, and atomic rename.
- Initial pinned versions are MOSDNS v5.3.4, dnscrypt-proxy 2.1.18, and Go 1.25.0.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- Unknown YAML keys must fail instead of silently selecting a less-safe default.
- A crash between temporary-file write and rename must leave the previous valid state untouched.
- Concurrent automatic and manual operations must not both hold the selector lock.
- Cross-compiled binaries must not depend on the development host's glibc version.
- `status` output must not reveal complete ECHConfig bytes or future sensitive fields.

---

## File Map

```text
go.mod
go.sum
.gitignore
Makefile
cmd/mosdns-router/main.go
cmd/mosdns-cdnctl/main.go
internal/buildinfo/buildinfo.go
internal/buildinfo/buildinfo_test.go
internal/config/policy.go
internal/config/defaults.go
internal/config/load.go
internal/config/load_test.go
internal/state/atomic.go
internal/state/types.go
internal/state/atomic_test.go
internal/state/types_test.go
internal/filelock/lock.go
internal/filelock/lock_test.go
internal/status/render.go
internal/status/render_test.go
scripts/test-make-entrypoints.sh
```

### Shared interfaces produced by this plan

```go
package config

type Policy struct {
    SchemaVersion int
    Foreign       ForeignPolicy
    CDN           CDNPolicy
    ECH           ECHPolicy
    DHCP          DHCPPolicy
    Cache         CachePolicy
}

func Defaults() Policy
func Load(path string) (Policy, error)
func (p Policy) Validate() error
```

```go
package state

const SchemaVersion = 1

type DHCPState struct {
    SchemaVersion  int       `json:"schema_version"`
    Generation     uint64    `json:"generation"`
    Interface      string    `json:"interface"`
    ConnectionUUID string    `json:"connection_uuid"`
    Upstreams      []string  `json:"upstreams"`
    ObservedAt     time.Time `json:"observed_at"`
    Source         string    `json:"source"`
    LastGood       bool      `json:"last_good"`
}

type Selector struct {
    SchemaVersion    int               `json:"schema_version"`
    Generation       uint64            `json:"generation"`
    Mode             string            `json:"mode"`
    Provider         string            `json:"provider"`
    WinnerIP         string            `json:"winner_ip,omitempty"`
    WinnerProofUntil time.Time         `json:"winner_proof_until,omitempty"`
    FallbackIP       string            `json:"fallback_ip,omitempty"`
    CloudFront       map[string]string `json:"cloudfront,omitempty"`
    LastSuccess      time.Time         `json:"last_success,omitempty"`
    LastFailure      string            `json:"last_failure,omitempty"`
    ConfigSHA256     string            `json:"config_sha256"`
}

type ECHState struct {
    SchemaVersion int       `json:"schema_version"`
    Generation    uint64    `json:"generation"`
    Source        string    `json:"source"`
    FetchedAt     time.Time `json:"fetched_at"`
    ExpiresAt     time.Time `json:"expires_at"`
    StaleUntil    time.Time `json:"stale_until"`
    ConfigSHA256  string    `json:"config_sha256"`
    PublicName    string    `json:"public_name"`
    Status        string    `json:"status"`
}

type BandwidthBudgetState struct {
    SchemaVersion int    `json:"schema_version"`
    LocalDate     string `json:"local_date"`
    LimitBytes    int64  `json:"limit_bytes"`
    UsedBytes     int64  `json:"used_bytes"`
}

type HealthState struct {
    SchemaVersion       int       `json:"schema_version"`
    Healthy             bool      `json:"healthy"`
    ConsecutiveFailures int       `json:"consecutive_failures"`
    LastSuccess         time.Time `json:"last_success,omitempty"`
    LastFailure         time.Time `json:"last_failure,omitempty"`
}

func WriteJSONAtomic(path string, value any) error
func ReadJSON(path string, destination any) error
```

```go
package filelock

type Lock struct { /* private */ }
func Acquire(path string) (*Lock, error)
func (l *Lock) Close() error
```

---

### Task 1: Bootstrap the module and reproducible build metadata

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `internal/buildinfo/buildinfo_test.go`
- Create: `internal/buildinfo/buildinfo.go`
- Create: `cmd/mosdns-router/main.go`

**Interfaces:**
- Consumes: upstream MOSDNS `coremain.Run()` and `coremain.AddSubCmd()`.
- Produces: `buildinfo.Version`, `buildinfo.Revision`, `buildinfo.BuildTime`, and the `mosdns-router build-info` command.

- [ ] **Step 1: Create the module and a failing build-info test**

Create `go.mod`:

```go
module mosdns-router

go 1.25.0

require (
    github.com/IrineSistiana/mosdns/v5 v5.3.4
    github.com/spf13/cobra v1.10.2
    gopkg.in/yaml.v3 v3.0.1
)
```

A `toolchain` directive is not added: `go 1.25.0` already pins the language
version, `go mod tidy` strips a redundant `toolchain` line, and the Make entry
points enforce the exact compiler instead.

Create `internal/buildinfo/buildinfo_test.go`:

```go
package buildinfo

import "testing"

func TestSnapshotUsesLinkerValues(t *testing.T) {
    oldVersion, oldRevision, oldBuildTime := Version, Revision, BuildTime
    t.Cleanup(func() { Version, Revision, BuildTime = oldVersion, oldRevision, oldBuildTime })
    Version, Revision, BuildTime = "test-version", "test-revision", "2026-09-25T00:00:00Z"

    got := Snapshot()
    if got.Version != "test-version" || got.Revision != "test-revision" || got.BuildTime != "2026-09-25T00:00:00Z" {
        t.Fatalf("unexpected build info: %#v", got)
    }
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
go test ./internal/buildinfo -run TestSnapshotUsesLinkerValues -v
```

Expected: FAIL because `Snapshot` is undefined.

- [ ] **Step 3: Implement build metadata**

Create `internal/buildinfo/buildinfo.go`:

```go
package buildinfo

var (
    Version   = "dev"
    Revision  = "unknown"
    BuildTime = "unknown"
)

type Info struct {
    Version   string `json:"version"`
    Revision  string `json:"revision"`
    BuildTime string `json:"build_time"`
}

func Snapshot() Info {
    return Info{Version: Version, Revision: Revision, BuildTime: BuildTime}
}
```

- [ ] **Step 4: Add the router entry point**

Create `cmd/mosdns-router/main.go`:

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/IrineSistiana/mosdns/v5/coremain"
    "github.com/spf13/cobra"
    _ "github.com/IrineSistiana/mosdns/v5/plugin"
    "mosdns-router/internal/buildinfo"
)

func init() {
    coremain.AddSubCmd(&cobra.Command{
        Use: "build-info",
        RunE: func(_ *cobra.Command, _ []string) error {
            return json.NewEncoder(os.Stdout).Encode(buildinfo.Snapshot())
        },
    })
}

func main() {
    if err := coremain.Run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

- [ ] **Step 5: Resolve modules and run the test**

Run:

```bash
go mod tidy
go test ./internal/buildinfo -v
```

Expected: PASS.

- [ ] **Step 6: Verify the command**

Run:

```bash
go run -ldflags '-X mosdns-router/internal/buildinfo.Version=test-version -X mosdns-router/internal/buildinfo.Revision=test-revision -X mosdns-router/internal/buildinfo.BuildTime=2026-09-25T00:00:00Z' ./cmd/mosdns-router build-info
```

Expected: JSON containing the three test values.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum .gitignore cmd/mosdns-router/main.go internal/buildinfo
git commit -m "build: bootstrap mosdns router module"
```

---

### Task 2: Define and validate the policy schema

**Files:**
- Create: `internal/config/policy.go`
- Create: `internal/config/defaults.go`
- Create: `internal/config/load.go`
- Create: `internal/config/load_test.go`

**Interfaces:**
- Consumes: `policy.yaml` from `/etc/mosdns/policy.yaml` in production and temporary files in tests.
- Produces: `config.Defaults`, `config.Load`, and the nested policy fields consumed by all later plans.

- [ ] **Step 1: Write failing tests for defaults and unknown keys**

Create `internal/config/load_test.go` with table tests that assert:

```go
func TestDefaultsMatchApprovedSpec(t *testing.T) {
    got := Defaults()
    if got.Schedule != "03:00" || got.CDN.Bandwidth.DailyBytes != 100*1024*1024 {
        t.Fatalf("unexpected defaults: %#v", got)
    }
    if got.ECH.FailurePolicy != "strict" || got.DHCP.FailurePolicy != "disable-current" {
        t.Fatalf("unsafe defaults: %#v", got)
    }
}

func TestLoadRejectsUnknownKey(t *testing.T) {
    path := writeYAML(t, "schema_version: 1\nunknown_key: true\n")
    if _, err := Load(path); err == nil {
        t.Fatal("expected unknown key error")
    }
}
```

Also test rejection of negative byte limits, schedule other than `HH:MM`, unsupported failure policies, and schema versions other than 1.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/config -v
```

Expected: compile failure because `Defaults`, `Load`, and policy types do not exist.

- [ ] **Step 3: Implement concrete policy types**

Create `internal/config/policy.go` with these exact field names and YAML keys:

```go
type Policy struct {
    SchemaVersion int          `yaml:"schema_version"`
    Foreign       ForeignPolicy `yaml:"foreign"`
    CDN           CDNPolicy     `yaml:"cdn"`
    ECH           ECHPolicy     `yaml:"ech"`
    DHCP          DHCPPolicy    `yaml:"dhcp"`
    Cache         CachePolicy   `yaml:"cache"`
}
type ForeignPolicy struct { DefaultProvider string `yaml:"default_provider"`; ECS bool `yaml:"ecs"` }
type CDNPolicy struct {
    IPVersion string `yaml:"ip_version"`
    SuppressAAAA bool `yaml:"suppress_aaaa"`
    Cloudflare CloudflarePolicy `yaml:"cloudflare"`
    LatencyCandidateCount int `yaml:"latency_candidate_count"`
    Combined CombinedPolicy `yaml:"combined"`
    SwitchImprovementPercent float64 `yaml:"switch_improvement_percent"`
    Health HealthPolicy `yaml:"health"`
    Bandwidth BandwidthPolicy `yaml:"bandwidth"`
}
type CloudflarePolicy struct { MaxCandidates int `yaml:"max_candidates"` }
type CombinedPolicy struct { LatencyTop int `yaml:"latency_top"`; BandwidthTop int `yaml:"bandwidth_top"` }
type HealthPolicy struct { IntervalSeconds int `yaml:"interval"`; FailureThreshold int `yaml:"failure_threshold"` }
type BandwidthPolicy struct { DailyBytes int64 `yaml:"daily_budget"`; PerCandidateBytes int64 `yaml:"per_candidate_limit"`; PerCandidateSeconds int `yaml:"per_candidate_seconds"` }
type ECHPolicy struct { Enabled bool `yaml:"enabled"`; FailurePolicy string `yaml:"failure_policy"`; StaleGraceSeconds int `yaml:"stale_grace"`; Sources []string `yaml:"sources"` }
type DHCPPolicy struct { FailurePolicy string `yaml:"failure_policy"` }
type CachePolicy struct { PersistentDump bool `yaml:"persistent_dump"` }
```

- [ ] **Step 4: Implement approved defaults**

`Defaults()` must return schema 1, `Quad9 Secure DNSCrypt v2`, IPv4, AAAA suppression, 512 Cloudflare candidates, 100 MiB daily budget, 10 MiB/3 seconds per candidate, top 10 latency, top 3/top 3 combined, 10% switch improvement, 120-second health interval, 3 failures, ECH enabled/strict/900 seconds/`cloudflare-ech.com`, DHCP `disable-current`, and persistent cache dump disabled.

- [ ] **Step 5: Implement strict YAML loading and validation**

Use `yaml.NewDecoder`, call `KnownFields(true)`, reject multiple documents, require exactly one `---` document, and return path-wrapped errors. `Validate()` must enforce every numeric lower bound and the exact enums `strict|fallback` and `disable-current|use-last-good`.

- [ ] **Step 6: Run focused and package tests**

```bash
go test ./internal/config -v
go test ./internal/... -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/config
git commit -m "feat: add strict policy configuration"
```

---

### Task 3: Implement versioned atomic runtime state

**Files:**
- Create: `internal/state/types.go`
- Create: `internal/state/atomic.go`
- Create: `internal/state/types_test.go`
- Create: `internal/state/atomic_test.go`

**Interfaces:**
- Consumes: the state structs declared in this plan's Shared interfaces.
- Produces: `state.WriteJSONAtomic`, `state.ReadJSON`, and constructors `NewDHCPState`, `NewSelector`, `NewECHState` that set schema version and UTC timestamps.

- [ ] **Step 1: Write failing atomicity tests**

Test that:

```go
func TestWriteJSONAtomicReplacesCompleteFile(t *testing.T) { /* write v1 then v2; read v2 */ }
func TestReadJSONRejectsTruncatedFile(t *testing.T) { /* old valid file remains unchanged */ }
func TestWriteJSONAtomicNeverLeavesTempFile(t *testing.T) { /* directory contains only target */ }
func TestSelectorRejectsInvalidMode(t *testing.T) { /* mode=invalid */ }
```

Also test mode `auto`, `manual`, and `disabled`; IPv4 validation for winner/fallback; monotonic non-negative generation; UTC timestamp serialization; budget dates and non-negative byte counters; health failure counters; and directory fsync failure propagation where the platform allows injecting it.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/state -v
```

Expected: compile failure for missing state APIs.

- [ ] **Step 3: Implement state types and validation**

Copy the exact JSON tags from the Shared interfaces. Add:

```go
func (s Selector) Validate() error
func (s DHCPState) Validate() error
func (s ECHState) Validate() error
```

Require `SchemaVersion == 1`, valid IP addresses, non-empty provider, `ECHState.Status` in `fresh|stale|invalid`, RFC3339 `BandwidthBudgetState.LocalDate`, non-negative budget bytes, and non-negative health failure counters.

- [ ] **Step 4: Implement atomic JSON writes**

`WriteJSONAtomic` must:

1. Validate through a type switch over the five supported state types.
2. Call `os.MkdirAll(filepath.Dir(path), 0750)` when the parent is absent.
3. Create a file in the same directory with mode `0640`.
4. Encode one indented JSON document.
5. Call `Sync`, `Close`, `Rename`, then sync the parent directory.
6. Remove the temporary file on every error path.

- [ ] **Step 5: Implement strict reads**

`ReadJSON` must reject unknown fields, trailing data, schema mismatch, and validation errors. Wrap all errors with the file path but do not include file contents.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/state -v
go test -race ./internal/state -v
```

Expected: PASS with no race.

- [ ] **Step 7: Commit**

```bash
git add internal/state
git commit -m "feat: add atomic runtime state"
```

---

### Task 4: Add cross-process file locking

**Files:**
- Create: `internal/filelock/lock.go`
- Create: `internal/filelock/lock_test.go`

**Interfaces:**
- Consumes: lock-file path such as `/var/lib/mosdns/runtime/control.lock`.
- Produces: non-blocking `Acquire` and idempotent `Close`, used by CLI and timers.

- [ ] **Step 1: Write a failing mutual-exclusion test**

```go
func TestSecondAcquireFailsWhileHeld(t *testing.T) {
    path := filepath.Join(t.TempDir(), "control.lock")
    first, err := Acquire(path)
    if err != nil { t.Fatal(err) }
    defer first.Close()
    if _, err := Acquire(path); !errors.Is(err, ErrLocked) {
        t.Fatalf("expected ErrLocked, got %v", err)
    }
}
```

Add a second-process test using `os/exec` so the lock is proven to use the kernel, not a Go mutex.

- [ ] **Step 2: Run the test and verify failure**

```bash
go test ./internal/filelock -v
```

Expected: compile failure.

- [ ] **Step 3: Implement the lock**

Use `golang.org/x/sys/unix.Flock` with `LOCK_EX|LOCK_NB`, mode `0640`, sentinel `ErrLocked = errors.New("control lock is already held")`, and a `sync.Once`-guarded close. If the dependency is indirect, run `go mod tidy` rather than adding an unpinned version manually.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/filelock -v
go test -race ./internal/filelock -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/filelock
git commit -m "feat: add control file locking"
```

---

### Task 5: Add safe status rendering and reproducible build targets

**Files:**
- Create: `internal/status/render.go`
- Create: `internal/status/render_test.go`
- Create: `cmd/mosdns-cdnctl/main.go`
- Create: `Makefile`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `state.Selector`, `state.DHCPState`, `state.ECHState`.
- Produces: redacted `status.Render`, the initial `mosdns-cdnctl status` command, and `make test/build/cross-build/verify`.

- [ ] **Step 1: Write failing redaction tests**

```go
func TestRenderDoesNotExposeECHBytes(t *testing.T) {
    var b bytes.Buffer
    RenderSelector(&b, state.Selector{SchemaVersion: 1, Mode: "disabled", Provider: "cloudflare", ConfigSHA256: "abc"})
    got := b.String()
    if strings.Contains(got, "ECHConfig") || strings.Contains(got, "private") {
        t.Fatalf("sensitive output: %s", got)
    }
}
```

Test stable sorted output and omission of empty fallback fields.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/status -v
```

Expected: compile failure.

- [ ] **Step 3: Implement deterministic rendering**

Render plain `key=value` lines, never JSON-encode unknown future fields, and include only `schema_version`, `generation`, `mode`, `provider`, `winner_ip`, `fallback_ip`, and timestamps. `ECHState` rendering is limited to source, status, expiry, public name, and config hash.

- [ ] **Step 4: Implement the initial CLI**

Support:

```text
mosdns-cdnctl validate --policy PATH
mosdns-cdnctl status --selector PATH --dhcp PATH --ech PATH
```

`validate` calls `config.Load` and `Policy.Validate` and writes no files. Exit codes: 0 success, 2 invalid CLI/config, 3 state unavailable, 4 lock held. Do not add other commands until their owning plan.

- [ ] **Step 5: Add Make targets**

`Makefile` must provide:

```make
GO ?= go
GO_REQUIRED_VERSION := 1.25.0
LDFLAGS ?= -s -w
.PHONY: check-go test build cross-build verify
check-go:
	@# refuse any Go release other than $(GO_REQUIRED_VERSION)
test:
	@$(GO) test -mod=readonly ./...
	@sh scripts/test-make-entrypoints.sh
build:
	@$(GO) build -mod=readonly -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-router ./cmd/mosdns-router
	@$(GO) build -mod=readonly -trimpath -ldflags '$(LDFLAGS)' -o build/mosdns-cdnctl ./cmd/mosdns-cdnctl
cross-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -mod=readonly -trimpath -o build/linux-amd64/mosdns-router ./cmd/mosdns-router
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -mod=readonly -trimpath -o build/linux-arm64/mosdns-router ./cmd/mosdns-router
verify: test
	@$(GO) vet -mod=readonly ./...
```

Every entry point depends on `check-go`, and every Go command uses
`-mod=readonly`, so no build target can act as an implicit dependency updater.
`scripts/test-make-entrypoints.sh` proves the guard and the readonly flag on
every entry point; a missing or missing-version `go.mod` fix therefore has to be
applied by an explicit `go mod tidy` that a developer reviews.

- [ ] **Step 6: Run complete local verification**

```bash
make verify
make cross-build
file build/linux-amd64/mosdns-router build/linux-arm64/mosdns-router
```

Expected: tests/vet pass; binaries identify as Linux amd64 and arm64.

- [ ] **Step 7: Commit**

```bash
git add .gitignore Makefile cmd/mosdns-cdnctl internal/status
git commit -m "build: add reproducible project entry points"
```

---

## Plan Acceptance

Run:

```bash
go mod tidy -diff
go test ./...
go vet ./...
make verify
make cross-build
git status --short
```

Expected:

- `go mod tidy -diff` reports no difference and leaves `go.mod`/`go.sum` untouched;
- plain `go test ./...` and `go vet ./...` work with no `GOFLAGS` and no `-mod=mod`;
- all Go tests and vet pass;
- amd64 and arm64 static binaries build;
- no system networking or browser configuration changed;
- only documented project files are modified.
