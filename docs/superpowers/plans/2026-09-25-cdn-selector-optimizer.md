# CDN Selector and Optimizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect user and official CDN candidates, measure latency and capped bandwidth, select a stable IPv4 winner, support manual pin/unpin, and enforce the 100 MiB daily budget.

**Architecture:** Candidate sources produce normalized candidates without trusting third-party “best IP” feeds. A prober validates TCP, certificate/SNI/Host, and response identity; a budgeted runner selects the top ten by latency, measures at most 10 MiB or 3 seconds each, computes a documented score, and atomically updates `state.Selector` under the control lock.

**Tech Stack:** Go 1.25, standard `net/http`, `crypto/tls`, `miekg/dns`, Cloudflare IP API, AWS IP ranges JSON, local TCP/TLS/HTTP mocks, atomic JSON state.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- Enforce a hard daily download budget of 100 MiB in code.
- Default Cloudflare candidate limit is 512; user candidates are always included.
- CloudFront is measured only for explicit user domain profiles.
- Every final candidate must pass certificate validation; `InsecureSkipVerify` is forbidden.
- Cloudflare and CloudFront results are never compared in one raw score table.
- Keep current and last-known-good winners until a new winner passes final validation.
- Automatic and manual operations use `filelock.Acquire` on the same control lock.
- Do not run real-network tests in the default unit/integration suite.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- A fast TCP handshake must not make an IP eligible without Host/SNI/certificate validation.
- A download that reaches 10 MiB in one second and one that takes three seconds must both count as consumed bytes.
- The eleventh download must be rejected when 100 MiB are already consumed.
- **Identity probes are deliberately outside the budget, so their body bytes are the one uncharged egress the report must account for: `prober.HTTPMetrics.BodyBytes` counts them per probe and a run sums them and shows the operator the uncharged identity total. The exposure is `prober.DefaultMaxIdentityBodyBytes` times the number of candidates proved.**
- **`HTTPMetrics.BodyBytes` must be added in before the error is looked at.** `metrics, err := HTTPS(...); if err != nil { continue }` discards the only record of the bytes, and a refused probe is exactly the case where bytes were spent and nothing was published. A refused probe reports no other number, so `BodyBytes` is the whole accounting it has.
- **A settle goes through `optimizer.Budget.Settle`, never `Consume`.** `Consume` cannot report a refusal, so a repeated settle, a settle of an amount this budget never reserved, and a failed persist are all silent, and each leaves the day over-charged. The runner keeps its own counters and reports them.
- **One `*optimizer.Budget` lives for the whole life of every reservation it makes.** The outstanding-reservation set belongs to the value, not the document: a second `Budget` opened on the same document mid-run refuses every settle with `ErrNoReservation` and the day fills up with no transfer behind it. The document records no owner, because its schema is fixed and a crashed holder must not block the next run, so this is a requirement on the runner rather than something the budget can check.
- **A `ByteBudget` that is not `*optimizer.Budget` re-opens the double-settle hole.** The settle-once rule lives in the concrete type, because the interface has no way to report a refusal. The prober's transfer call sites settle once by construction, so passing another implementation is safe there and unsafe anywhere else; the runner passes the concrete type.
- A CloudFront winner validated for one hostname must never be copied to another hostname.
- Corrupt selector state must not be overwritten by a failed test or pin operation.
- A run that cannot refresh the official ranges must not silently measure nothing. **Decision (Task 1):** the
  last range document this build validated stands in for the one it could not read — a transport
  failure or any status that is neither 200 nor 304 — and the candidate set is returned with a stale
  marker, which the report must carry. Serve-stale never covers a document that arrived and could
  not be understood: that is a hard error, and the cached document is neither substituted for it nor
  overwritten by it. With no cache at all, or a 304 that cannot be satisfied, the run fails rather
  than measuring an empty set. Serving stale is safe because every candidate in a stale set still has
  to pass the final identity proof before it can be published.

---

## File Map

```text
internal/candidate/types.go
internal/candidate/cloudflare.go
internal/candidate/user.go
internal/candidate/cloudfront.go
internal/candidate/cloudflare_test.go
internal/candidate/user_test.go
internal/candidate/cloudfront_test.go
internal/prober/prober.go
internal/prober/tcp.go
internal/prober/http.go
internal/prober/download.go
internal/prober/prober_test.go
internal/optimizer/budget.go
internal/optimizer/score.go
internal/optimizer/runner.go
internal/optimizer/runner_test.go
internal/health/checker.go
internal/health/checker_test.go
cmd/mosdns-cdnctl/main.go
Makefile
```

### Interfaces produced by this plan

```go
package candidate

type Provider string
const (
    ProviderCloudflare Provider = "cloudflare"
    ProviderCloudFront Provider = "cloudfront"
)

type Candidate struct {
    Provider Provider
    IP       netip.Addr
    Source   string
    Hostname string // CloudFront profile hostname; empty for global Cloudflare
}

type ProbeProfile struct {
    Hostname       string
    URL            string
    Method         string
    Port           uint16
    ExpectedStatus []int
    RequiredHeader map[string]string
    BodySHA256     string
}
type CloudFrontProfile struct {
    Profile    ProbeProfile
    Candidates []netip.Addr
}

type CloudFrontSource interface { Profiles(context.Context) ([]CloudFrontProfile, error) }
type CloudflareSource interface { Candidates(context.Context, int, time.Time) (CandidateSet, error) }
// CandidateSet carries the stale marker the serve-stale decision needs, so a report
// can say the set came from an older document instead of presenting it as current.
```

```go
package prober

type TCPMetrics struct { Samples int; P50MS float64; P95MS float64; JitterMS float64; Loss float64 }
type HTTPMetrics struct { Status int; TLSMS float64; TTFBMS float64; TotalMS float64; Colocation string; BodyBytes int64 }
type DownloadMetrics struct { Bytes int64; Elapsed time.Duration; BytesPerSecond float64 }
// The only implementation of ByteBudget is *optimizer.Budget. The settle-once rule
// lives in that concrete type, because this interface cannot report a refusal, so
// another implementation would have to reimplement it to be as safe.
type ByteBudget interface {
    Reserve(int64) (int64, error)
    Consume(reserved, actual int64)
}

type Prober interface {
    TCP(context.Context, netip.Addr, uint16, int) (TCPMetrics, error)
    HTTPS(context.Context, Candidate, ProbeProfile) (HTTPMetrics, error)
    Download(context.Context, Candidate, ProbeProfile, int64, time.Duration, ByteBudget) (DownloadMetrics, error)
}
```

```go
package optimizer

type Budget struct { Remaining int64 }
func NewBudget(bytes int64) *Budget
func NewPersistentBudget(path string, limit int64, location *time.Location, now time.Time) (*Budget, error)
func (b *Budget) Reserve(requested int64) (int64, error)
// Settle is the settle a caller must use. It closes exactly one outstanding
// reservation and reports the three refusals — no such reservation (a repeated
// settle, or a second Budget on the same document), a negative count, and a
// persist that failed. Consume below is Settle with the error dropped, because
// prober.ByteBudget has nowhere to put one; the one-shot guarantee is the same
// either way, but a refusal is invisible through it.
func (b *Budget) Settle(reserved, actual int64) error
// Release hands back a whole reservation a caller will not use. Also one-shot.
func (b *Budget) Release(reserved int64) error
func (b *Budget) Consume(reserved, actual int64)
func (b *Budget) Used() int64

type CandidateResult struct {
    Candidate candidate.Candidate
    TCP       prober.TCPMetrics
    HTTP      prober.HTTPMetrics
    Download  prober.DownloadMetrics
    Score     float64
    Eligible  bool
    Reason    string
}
type Input struct {
    Cloudflare         []candidate.Candidate
    CloudflareProfiles []candidate.ProbeProfile
    CloudFront         []candidate.Candidate
    CloudFrontRules    []candidate.CloudFrontProfile
    LastGood           state.Selector
}
type ScoreWeights struct { Latency float64; Bandwidth float64; Stability float64 }
type Report struct { GeneratedAt time.Time; Candidates []CandidateResult; Winner candidate.Candidate; BudgetUsed int64 }
type Runner struct { /* private */ }
func NewRunner(config.Policy, prober.Prober) *Runner
func (r *Runner) Run(context.Context, Input) (Report, error)
```

---

### Task 1: Normalize user, Cloudflare, and CloudFront candidates

**Files:**
- Create: `internal/candidate/types.go`
- Create: `internal/candidate/cloudflare.go`
- Create: `internal/candidate/user.go`
- Create: `internal/candidate/cloudfront.go`
- Create: corresponding `*_test.go` files

**Interfaces:**
- Consumes: Cloudflare API JSON, user candidate text, and CloudFront YAML profiles.
- Produces: normalized `Candidate` values with IPv4 enforced.

- [ ] **Step 1: Write failing user-list tests**

Cover single IPv4, `/32`, CIDR, comments, duplicates, IPv6 rejection, malformed input, and deterministic ordering. A user candidate must retain `Source="user"` even if it also appears in an official range.

- [ ] **Step 2: Write failing Cloudflare API tests**

Serve a fixture with `ipv4_cidrs`, `ipv6_cidrs`, and `etag`. Assert:

- only IPv4 CIDRs are expanded;
- one deterministic address per `/24` is sampled;
- the daily seed changes the sample but is reproducible for the same date;
- output count never exceeds 512 unless user candidates are counted separately;
- ETag body is cached separately and a 304 response reuses the last CIDRs.

- [ ] **Step 3: Write failing CloudFront profile tests**

Decode YAML with strict fields and reject a profile containing a hostname, IP, URL, port, expected status, required headers, or body hash that is internally inconsistent. Prove two hostnames cannot share an implicit mapping.

- [ ] **Step 4: Run tests and verify failure**

```bash
go test ./internal/candidate -v
```

Expected: compile failure.

- [ ] **Step 5: Implement candidate types and parsing**

Use `netip.ParseAddr` and `netip.ParsePrefix`, canonicalize IPv4-mapped input with `Unmap`, reject non-IPv4 for this release, and sort by provider/hostname/IP/source.

- [ ] **Step 6: Implement official-source caching**

Cloudflare source URL:

```text
https://api.cloudflare.com/client/v4/ips
```

Cache raw JSON plus ETag under `/var/lib/mosdns/lists/cloudflare-ips.json`. AWS CloudFront ranges are used only as reference data; they are not expanded into global candidates in this release.

- [ ] **Step 7: Run tests**

```bash
go test ./internal/candidate -v
go test -race ./internal/candidate -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/candidate
git commit -m "feat: normalize CDN candidates"
```

---

### Task 2: Implement verified TCP, HTTPS, and capped download probes

**Files:**
- Create: `internal/prober/prober.go`
- Create: `internal/prober/tcp.go`
- Create: `internal/prober/http.go`
- Create: `internal/prober/download.go`
- Create: `internal/prober/prober_test.go`
- Create: `internal/optimizer/budget.go`
- Create: `internal/optimizer/budget_test.go`

**Interfaces:**
- Consumes: normalized candidates, profile data, and a shared budget.
- Produces: latency, identity-validation, and download metrics.

- [ ] **Step 1: Write failing budget tests**

```go
func TestBudgetRejectsRequestOverRemaining(t *testing.T)
func TestBudgetReturnsUnusedReservation(t *testing.T)
func TestBudgetNeverNegative(t *testing.T)
func TestHundredMiBBoundary(t *testing.T)
```

Use `optimizer.NewBudget(100*1024*1024)` and prove the eleventh 10 MiB request is rejected. Add persistent tests that open the same budget file twice on one local date, reject a second process after 100 MiB, reset on the next local date, and keep a crashed process's full reservation charged rather than returning unused bytes.

- [ ] **Step 2: Write failing TCP tests**

Start local TCP listeners. Assert sample count, p50/p95, jitter, timeout, refused connection, and zero successful samples all behave as specified.

- [ ] **Step 3: Write failing HTTPS identity tests**

Start local TLS servers with certificates for `example.test`. Assert a correct SNI/Host succeeds, a wrong hostname fails certificate verification, a 421/403 is rejected unless allowed by profile, missing required CloudFront headers fails, and a body hash mismatch fails. Add a test that scans source/build settings to reject `InsecureSkipVerify: true`.

- [ ] **Step 4: Write failing download-limit tests**

Serve bodies larger than 10 MiB and slow bodies lasting over 3 seconds. Assert the reader stops at the lower of byte/time limit, `io.LimitReader` never reads one byte beyond the reservation, redirects are disabled unless the final URL host equals the profile host, and actual bytes are charged to the budget.

- [ ] **Step 5: Run tests and verify failure**

```bash
go test ./internal/optimizer ./internal/prober -v
```

Expected: compile failure.

- [ ] **Step 6: Implement budget reservation**

Reserve the requested maximum before I/O, persist the reservation in `/var/lib/mosdns/runtime/bandwidth-budget.json` with `state.WriteJSONAtomic` under the control lock, wrap the body in a counting limited reader, stop on timer, consume actual bytes, and return unused reservation. A process crash conservatively leaves the reservation charged until the local date changes. Reset `used_bytes` only when the recorded local date differs. Use `sync.Mutex`; never infer budget from file size or cache headers.

- [ ] **Step 7: Implement probes**

For HTTPS, use a custom `http.Transport.DialContext` that dials the candidate IP while retaining URL hostname for TLS `ServerName` and HTTP Host. Use a dedicated `http.Client` with redirects disabled, a response-header timeout, and a total context deadline. Never mutate global `http.DefaultTransport`.

- [ ] **Step 8: Run tests**

```bash
go test ./internal/optimizer ./internal/prober -v
go test -race ./internal/optimizer ./internal/prober -v
```

Expected: PASS and downloaded bytes never exceed the reservation.

- [ ] **Step 9: Commit**

```bash
git add internal/optimizer/budget.go internal/optimizer/budget_test.go internal/prober
git commit -m "feat: add verified CDN probes and budget"
```

---

### Task 3: Implement latency filtering and combined scoring

**Files:**
- Create: `internal/optimizer/score.go`
- Create: `internal/optimizer/score_test.go`

**Interfaces:**
- Consumes: candidate metrics from the prober.
- Produces: deterministic rank and winner-selection functions.

- [ ] **Step 1: Write failing score tests**

Construct 12 candidates with controlled p50, p95, jitter, loss, and speed. Assert:

- candidates above loss/latency policy limits are excluded;
- top ten latency candidates are selected;
- bandwidth top three and latency top three form the union;
- weights 0.45/0.45/0.10 produce the documented ordering;
- equal scores sort by lower loss, higher p10 speed, lower jitter, then IP;
- a CloudFront result is scored only inside its own hostname group.

- [ ] **Step 2: Write failing switch-gate tests**

Assert a new candidate is accepted only if it beats the current winner by at least 10% under the normalized score and passes a final HTTPS identity probe. A 9% improvement keeps the current winner.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./internal/optimizer -run 'TestScore|TestSwitch' -v
```

Expected: compile failure.

- [ ] **Step 4: Implement pure scoring functions**

Use:

```go
type Weights struct { Latency, Bandwidth, Stability float64 }
func RankLatency([]CandidateResult, int) []CandidateResult
func CombinedScore(CandidateResult, []CandidateResult, Weights) float64
func SwitchAllowed(newScore, currentScore, improvementPercent float64) bool
```

Do not use floating-point equality for candidate ordering; normalize ranks to integer percentiles before applying weights.

- [ ] **Step 5: Run tests**

```bash
go test ./internal/optimizer -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/optimizer/score.go internal/optimizer/score_test.go
git commit -m "feat: score stable CDN candidates"
```

---

### Task 4: Orchestrate tests and atomic apply/pin operations

**Files:**
- Create: `internal/optimizer/runner.go`
- Create: `internal/optimizer/runner_test.go`
- Modify: `cmd/mosdns-cdnctl/main.go`

**Interfaces:**
- Consumes: policy, sources, prober, current selector, and control lock.
- Produces: `Report`, `Apply`, `Pin`, `Unpin`, and CLI commands.

- [ ] **Step 1: Write a failing end-to-end runner test with fakes**

Use deterministic fake sources/prober results. Assert phase order:

```text
collect -> TCP -> HTTPS identity -> latency top 10 -> bandwidth -> score -> final proof
```

Assert the report records valid candidate count, actual budget used, source, timestamps, and reason when no candidate qualifies.

- [ ] **Step 2: Write failing apply tests**

Start with selector generation 4. A successful apply writes generation 5 and moves old winner to `FallbackIP`. A failed final proof, malformed report, or lock conflict leaves the file byte-for-byte unchanged.

- [ ] **Step 3: Write failing pin/unpin tests**

`Pin` validates the address against every `Input.CloudflareProfiles` entry and every CloudFront profile, stores mode `manual`, increments generation once, and never changes the file on failure. `Unpin` stores mode `auto`, keeps current winner as fallback, and increments generation.

- [ ] **Step 4: Run tests and verify failure**

```bash
go test ./internal/optimizer -run 'TestRunner|TestApply|TestPin' -v
```

Expected: compile failure.

- [ ] **Step 5: Implement `Runner.Run`**

Collect `Input` from the candidate sources, open the persistent daily budget once with `optimizer.NewPersistentBudget` and keep that one `*Budget` for the whole run, execute probes with bounded concurrency, stop on context cancellation, and return a partial report plus error without applying. The budget takes its own `bandwidth-budget.json.lock` around each persist and must never be opened under the control lock, which a multi-minute run would hold for the length of every download and which `apply`, `pin`, and `health-check` need. Settle each reservation with `Budget.Settle` and report a refusal; settle through `Consume` only where a caller cannot report one. Sum `HTTPMetrics.BodyBytes` across every identity probe, refused ones included, and report the uncharged identity total. If the daily budget is exhausted, finish latency/health phases but skip further downloads and keep the current winner. A report is valid only if the policy and config SHA-256 match current configuration.

- [ ] **Step 6: Implement apply/pin/unpin**

Acquire `filelock.Acquire(control.lock)`, read/validate current selector, increment generation, call `state.WriteJSONAtomic`, and return a typed conflict error. No command may write a temp file before it owns the lock.

- [ ] **Step 7: Extend the CLI**

Implement:

```text
mosdns-cdnctl test [--apply]
mosdns-cdnctl apply REPORT.json
mosdns-cdnctl pin IPV4
mosdns-cdnctl unpin
```

`test` defaults to report-only. `--apply` requires the same invocation to reacquire the lock and re-run final proof; it must not apply a stale report generated earlier.

- [ ] **Step 8: Run tests**

```bash
go test ./internal/optimizer -v
go test -race ./internal/optimizer -v
go test ./...
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/optimizer/runner.go internal/optimizer/runner_test.go cmd/mosdns-cdnctl/main.go
git commit -m "feat: apply CDN selections atomically"
```

---

### Task 5: Add low-traffic winner health checks

**Files:**
- Create: `internal/health/checker.go`
- Create: `internal/health/checker_test.go`
- Modify: `cmd/mosdns-cdnctl/main.go`

**Interfaces:**
- Consumes: selector, profiles, HTTPS prober, and consecutive failure state.
- Produces: health transitions and fallback selector updates.

- [ ] **Step 1: Write failing health-state tests**

Assert one or two failures do not move state; the third consecutive failure does. A successful check resets the count. A strict ECH domain remains blocked when the winner fails; fallback mode receives the selected fallback.

- [ ] **Step 2: Write failing persistence tests**

Store only `healthy`, `consecutive_failures`, `last_success`, and `last_failure` in `/var/lib/mosdns/runtime/health.json`. A corrupt health file fails closed to three failures for a strict selector and is never treated as healthy.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./internal/health -v
```

Expected: compile failure.

- [ ] **Step 4: Implement health checks**

Use the same verified HTTPS identity path as final proof, HEAD when the profile supports it, GET with a zero-length/body limit otherwise, and no bandwidth-budget charge. Validate every CloudFront hostname separately.

- [ ] **Step 5: Add the CLI command**

```text
mosdns-cdnctl health-check
```

It holds the control lock only when a selector transition is required; read-only successful checks do not block the optimizer for the full probe duration.

- [ ] **Step 6: Run full tests**

```bash
go test ./internal/health ./internal/optimizer -v
go test -race ./internal/health ./internal/optimizer -v
go test ./...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/health cmd/mosdns-cdnctl/main.go
git commit -m "feat: health check selected CDN IPs"
```

---

## Plan Acceptance

Run:

```bash
go test ./internal/candidate ./internal/prober ./internal/optimizer ./internal/health -v
go test -race ./internal/candidate ./internal/prober ./internal/optimizer ./internal/health
go test ./...
```

Expected:

- deterministic candidates and scores;
- strict certificate/Host/profile validation;
- no more than 100 MiB measured;
- failed operations never overwrite selector state;
- manual pin and health fallback work under concurrency;
- no real external network dependency in default tests.
