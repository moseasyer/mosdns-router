# CDN Selector and Optimizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect user and official CDN candidates, measure latency and capped bandwidth, select a stable IPv4 winner, support manual pin/unpin, and enforce the 100 MiB daily budget.

**Architecture:** Candidate sources produce normalized candidates without trusting third-party “best IP” feeds. A prober validates TCP, certificate/SNI/Host, and response identity; a budgeted runner selects the top ten by latency, measures at most 10 MiB or 3 seconds each, computes a documented score, and atomically updates `state.Selector` under the control lock.

**Tech Stack:** Go 1.25, standard `net/http`, `crypto/tls`, `miekg/dns`, Cloudflare IP API, local TCP/TLS/HTTP mocks, atomic JSON state.

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
- **`mode: "disabled"` is an operator's statement, and no command in this project may undo it.** Nothing here writes that mode — it is reachable only by a hand edit — and the three commands that act on the selector disagreed about it: `health.Check` honoured it, `Apply` published over it, and `Pin` re-enabled it by writing `manual`, all while reporting success. `Apply` and `Pin` now carry the same guard with a named `ErrModeDisabled`, refused the way `ErrModeManual` is, and `Unpin` already refuses any mode but `manual`. A review of the runner must confirm all three refuse a disabled selector without opening a socket (`Pin`) or writing anything (`Apply` leaves the file byte-for-byte and reports `outcome: refused`), and that the health check's own honouring of the mode is the third of the three rather than the only one.
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
- **The group barrier is enforced on every exported function that takes a group, not only on the three that take a slice.** `RankScore`, `CombinedScore` and `TenthPercentileSpeed` each take a group without going through `Select`, and a check on the *subject* is not a check on the *group*: a subject can be a good member of a slice that also holds another hostname's results, and the percentile arithmetic then compares the two. All six refuse a slice that is not one group. A review of this must check the entry points, not the call graph inside the package.
- **The exclusion ceilings are `optimizer.DefaultLimits()` and Task 4 must pass them.** `config.Policy` has no loss or latency ceiling field and this plan may not add one, so the ceilings are a parameter with a documented default: `DefaultMaxLossFraction` 0.10 and `DefaultMaxP50MS` 150ms, both inclusive. `optimizer.Limits{}` still means "no ceiling" and a caller can still ask for it, but a caller that writes `Params{}` by accident must reach for `DefaultLimits()` rather than for the zero value, which measures and publishes a candidate that dropped 40% of its handshakes. A review of the runner must confirm the value it passes.
- **`Params.Validate()` is a gate, not a convenience.** A non-positive `latency_candidate_count`, `latency_top` or `bandwidth_top` cannot select anything, and the three come from three separate policy fields. `Select` refuses every candidate with `ReasonUnusableCounts` rather than returning an empty union that reads as "nothing was good enough", and `Validate` lets the runner find it out before it spends the day's bandwidth.
- **Two identity gates, and the scorer deliberately holds neither.** The phase order is `collect -> TCP -> HTTPS identity -> latency shortlist -> bandwidth -> score -> final proof`. A candidate reaches the scorer only if it already passed the identity probe for the hostname it is scored for, and the proof runs again on the winner before anything is published. `optimizer.CandidateResult.HTTP` is therefore carried and never read, and that is the design: a third gate over a fact two others hold would be the one a caller mistakes for the gate itself. A review of the runner must confirm both gates run, because a candidate with no proof will be scored, and scored well.
- **AMENDED (Task 4): a proof covers one group, and a global address is proved only against the global profiles.** The brief's "`Pin` validates the address against every `Input.CloudflareProfiles` entry and every CloudFront profile" is withdrawn. A global (hostname-less) address is proved against the global identity profiles only — the provider's representative domain and every forced-ECH domain, which is what §11.6 holds a manual Cloudflare address to — and a per-hostname address against its own hostname's profile only. The reason is the mapping, not convenience: the CloudFront mapping is per-hostname, so the global winner is never published for one of those hostnames, and a Cloudflare anycast address cannot present a chain for a CloudFront hostname in any case, so the mixed rule would refuse `test --apply` and `pin` on every router that has a CloudFront domain list. A review of the runner must confirm `Profiles.forSubject` keeps the two kinds apart in both the in-run gate and the final proof, because the failure mode is a permanent refusal rather than a wrong publish.
- **A report names the day's limit and what is left of it, and a report-only run spends the same budget as an applying one.** The shipped policy is 100 MiB a day against a ten-candidate shortlist at 10 MiB each, which is exactly the day: at most one switching run fits per local date. A report that named only `budget_used_bytes` would be truthful and useless, because the operator learns the day's budget by having the next run refused with every group kept - so `Report.BudgetLimit` and `Report.BudgetRemaining` exist and the CLI prints `budget-limit-bytes:` and `budget-remaining-bytes:`. Both come from one read of the one budget the run spent from (`Budget.Standing`), never from a re-read of the policy document, because `dayRule` holds a day to the smaller of the policy's limit and the one the document already carries and an operator may tighten it by hand. `runCDNTest`'s doc and the `--report` and `--apply` flag help say that a report-only run spends the same budget; no behaviour changed to say it.
- `optimizer.TCPMetrics.P95MS` is measured and **not read by the selector**. It is not a deferred item: the p50 and the jitter are what the three weighted ranks use, and p95 has no term. It is carried because the prober measures it and a report may show it; a review should not read its absence as a missing term.
- **The health check refreshes the published winner's proof window, because its own successful pass is the proof that window is about.** `optimizer.WinnerProofTTL` used to carry the claim that "the health check is what refreshes both", and the claim was false: a check wrote `health.json` on every pass and `cdn-selector.json` only inside a transition, so on a router whose nightly `test --apply` publishes at 03:00 the window was 03:05 and nothing advanced it for the next 23h55m while `health.json` said `healthy: true` and re-proved the same address every 120 s. A check's pass is the same certificate + Host + SNI proof an apply's final proof is, against the same profiles of the same address, so the window it maintains is the window the response-rewrite plan gates on: on a healthy verdict the check writes `last_success` and `winner_proof_until` from one reading taken under the control lock it already holds, leaves `generation` alone because no selection changed, and reports that it did (`Result.RefreshedProof`, `Result.ProofUntil`, and a `winner-proof:` line that is printed either way). A failed or an unknown verdict refreshes nothing; a transition keeps its own single stamp for the address it moved to and is reported as a transition rather than as a refresh; a pinned or manual selector refreshes on the same rule, because a pin is a decision about the address and not about its window. A review of `internal/health` must confirm that a healthy pass advances the window and changes nothing else, and that the document it leaves is one `state.Selector.Validate` accepts.
- **`optimizer.normalizeWeights` places the rounding remainder on the latency share.** Three rounded ten-thousandths need not sum to the scale, and the remainder goes to the first share so the total is always exact. The choice is arbitrary and the arithmetic is not: with `Weights{1,1,1}` the shares are 3334/3333/3333 rather than 3333/3333/3333, and the second and third candidates' scores differ by 2 points. Any placement is acceptable; a change must keep the sum at exactly 10000.
- **A duplicate candidate in the input survives `Select`'s deduplication.** The union is deduplicated by `candidate.Candidate`, which is the whole candidate including its source, so the same address under two sources stays two entries. `candidate.Combine` dedupes on provider/hostname/address and produces one entry per address, so a run cannot produce such a pair; a caller that does has a bug the selector is not the place to report.
- **The `internal/measure` leaf package exists because reversing it re-creates an import cycle.** `prober`'s in-package test uses `*optimizer.Budget` in fifteen places, and Go forbids an in-package test file importing a package that imports the one under test. Declaring `TCPMetrics`/`HTTPMetrics`/`DownloadMetrics` in `internal/measure` and naming them in `prober` as type aliases keeps both names working and the cycle gone. Moving them back into `prober`, or adding any further `optimizer -> prober` import, brings the cycle straight back; the alternatives are a test double in `prober_test.go` or a subpackage for the scorer, both of which cost coverage or the plan's acceptance commands.

---

## File Map

```text
cmd/mosdns-cdnctl/main.go
cmd/mosdns-cdnctl/main_test.go
cmd/mosdns-cdnctl/update_lists.go
internal/candidate/types.go
internal/candidate/types_test.go
internal/candidate/user.go
internal/candidate/user_test.go
internal/candidate/cloudflare.go
internal/candidate/cloudflare_test.go
internal/candidate/fetch.go
internal/candidate/cloudfront.go
internal/candidate/cloudfront_test.go
internal/prober/prober.go
internal/prober/tcp.go
internal/prober/http.go
internal/prober/download.go
internal/prober/prober_test.go
internal/optimizer/budget.go
internal/optimizer/budget_test.go
internal/optimizer/score.go
internal/optimizer/score_test.go
internal/optimizer/runner.go
internal/optimizer/runner_test.go
internal/measure/measure.go
internal/health/checker.go
internal/health/checker_test.go
internal/health/verdict_test.go
internal/state/atomic.go
internal/state/atomic_test.go
```

`internal/measure/measure.go` is here because `prober`'s in-package test uses `*optimizer.Budget` and Go forbids the cycle; `internal/state/atomic.go` because the health document is written by the state package's own writer rather than by the checker; and `internal/health/verdict_test.go` because the verdict's `String` is a reporting contract. The Makefile is **not** in this range: no build target, packaging rule or entry point changed, and this plan touched no file outside the four directories above plus `internal/measure` and `internal/state`.

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
// CloudFrontSource has no implementation in this release: the AWS document is not
// fetched (Task 1 Step 6), so the interface is the seam a CloudFront source would
// satisfy and the CLI reaches CloudFront through ParseCloudFrontProfiles.
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

// Budget has no exported field: the day is a document and a day rule, not a
// number a caller may read or write. Used, Standing, Reserve, Settle, Release and
// Consume are the whole surface, and the one-shot settlement rule lives in this
// concrete type because the prober's interface has nowhere to report a refusal.
type Budget struct { /* private: mutex, counter, limit, location, moment, outstanding, lastKnown */ }
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
// Standing is Used and the limit the day is held to, from one read, so a report
// cannot show a total and a limit from two different moments.
func (b *Budget) Standing() (used, limit int64)

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
    // Stale is candidate.CandidateSet.Stale: the official ranges could not be
    // refreshed and the last document this build accepted stood in for them. It
    // becomes Report.Stale, which is the only place a reader learns the addresses
    // in a report are yesterday's.
    Stale bool
}
type ScoreWeights struct { Latency float64; Bandwidth float64; Stability float64 }
// The exclusion ceilings, as parameters with a documented default. config.Policy
// has no field for either and this plan may not add one, so the caller chooses
// and DefaultLimits() is the value Task 4 must pass. Both are inclusive; a zero
// means no ceiling for that dimension.
type Limits struct { MaxLoss float64; MaxP50MS float64 }
const DefaultMaxLossFraction = 0.10
const DefaultMaxP50MS = 150.0
func DefaultLimits() Limits
// The three top-N counts and the weights a selection needs, gathered so a caller
// cannot pass a count from one policy and a ceiling from another. Validate
// reports a non-positive count, which cannot select anything, and Select refuses
// every candidate with ReasonUnusableCounts rather than returning an empty union
// that reads as an absence of good candidates.
type Params struct {
    LatencyCandidates int  // cdn.latency_candidate_count
    LatencyTop        int  // cdn.combined.latency_top
    BandwidthTop      int  // cdn.combined.bandwidth_top
    Limits            Limits
    Weights           ScoreWeights
}
func (p Params) Validate() error
// GroupKey is the one set of candidates that may be compared. Every function
// below that takes a group refuses a slice holding more than one, including
// RankScore, CombinedScore and TenthPercentileSpeed, which take a group without
// going through Select. Six entry points share that barrier: RankLatency,
// RankBandwidth, Select, RankScore, CombinedScore and TenthPercentileSpeed.
type GroupKey struct { Provider candidate.Provider; Hostname string }
func GroupOf(candidate.Candidate) GroupKey
func (k GroupKey) Same(other GroupKey) bool
func TenthPercentileSpeed(group []CandidateResult) float64
// Report is per group, because the winner is per group and the anti-leak rule is
// the whole reason: a CloudFront address is one hostname's answer, so a report
// with a single winner would either drop the CloudFront groups or publish one of
// them for everything. The brief's Candidates and Winner are Groups[].Candidates
// and Groups[].Winner; GeneratedAt, IdentityBytes, BudgetUsed, BudgetLimit and
// BudgetRemaining are the run's. Every field is JSON-tagged and read back by an
// apply that refuses anything it does not recognize.
type Report struct {
    SchemaVersion   int           `json:"schema_version"`
    GeneratedAt     time.Time     `json:"generated_at"`
    PolicySHA256    string        `json:"policy_sha256"`
    ConfigSHA256    string        `json:"config_sha256"`
    Stale           bool          `json:"stale_candidates"`
    Groups          []GroupReport `json:"groups"`
    IdentityBytes   int64         `json:"identity_body_bytes"`
    BudgetUsed      int64         `json:"budget_used_bytes"`
    BudgetLimit     int64         `json:"budget_limit_bytes"`
    BudgetRemaining int64         `json:"budget_remaining_bytes"`
    BudgetExhausted bool          `json:"budget_exhausted"`
    Phases          PhaseTimes    `json:"phases"`
    FinalProofPassed  bool        `json:"final_proof_passed"`
    FinalProofRefused string       `json:"final_proof_refused,omitempty"`
    Outcome         Outcome       `json:"outcome,omitempty"`
}
type GroupReport struct {
    Group             GroupKey          `json:"-"`
    Provider          string            `json:"provider"`
    Hostname          string            `json:"hostname,omitempty"`
    Candidates        []ReportCandidate `json:"candidates"`
    Winner            *ReportWinner     `json:"winner,omitempty"`
    NoWinner          string            `json:"no_winner_reason,omitempty"`
    P10BytesPerSecond float64           `json:"p10_bytes_per_second"`
    Outcome           Outcome           `json:"outcome,omitempty"`
    OutcomeReason     string            `json:"outcome_reason,omitempty"`
}
type Runner struct { /* private */ }
// NewRunner takes the paths, the clock and the configuration digest as Options,
// because a runner with no budget path, selector path, control lock or digest is a
// runner that cannot be checked and cannot be used - and it returns an error
// because the counts are validated here, before any measurement, rather than by a
// run that has already spent the user's bandwidth.
func NewRunner(policy config.Policy, prober Prober, options Options) (*Runner, error)
func (r *Runner) Run(context.Context, Input) (Report, error)
func (r *Runner) Apply(context.Context, Report, Profiles) (Report, state.Selector, error)
func (r *Runner) Pin(context.Context, netip.Addr, Profiles) (PinResult, error)
func (r *Runner) Unpin() (state.Selector, error)
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

**The group boundary a user list is subject to.** Every entry in the user's own list becomes a **global** candidate: it is a `ProviderCloudflare` candidate with an empty `Hostname`, whichever provider it was meant for, because the list has no per-hostname structure and the anti-leak rule needs one. A per-hostname address therefore comes from a CloudFront profile (`cloudfront-domains.yaml`), never from the user list — a user who wants an address published for one hostname must write that hostname into a profile. This does not violate the anti-leak rule, which is about copying a *winner* across hostnames rather than about where an address is measured: a user's global entry is only ever published in the global group, and never into a CloudFront mapping. The obligation is that the plan state it rather than leave the guarantee ambiguous.

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

Cache raw JSON plus ETag under `/var/lib/mosdns/lists/cloudflare-ips.json`. **The cache's own file discipline is 0644 and the directory it creates is 0755**, because the cached document is published reference data rather than router state and the reader in the other half of this project runs unprivileged. `/var/lib/mosdns/lists` is a *packaging* obligation and the two plans have to agree about it: the packaging plan must provision it beside `/var/lib/mosdns` and `/var/lib/mosdns/runtime`, as `root:mosdns 2770` setgid with the same default ACL, because two service identities (the optimizer timer and the DHCP bridge) share it and a directory one of them cannot rename over is a cache that fails on the second run. (`2770`, not the `2750` this paragraph first named: measured on the system-level test machine, a member of the owning group cannot create a file in a `2750` directory at all. See the packaging plan's mode table and its correction.) The writer still creates the directory when it is absent — so a hand-built tree works — but the shipped tree is packaging's. **This release does not fetch the AWS published ranges document at all** — it is not read, not cached, and not exposed. A per-hostname CloudFront address comes from a CloudFront profile, so the range list has no consumer: a CloudFront address means nothing behind a hostname no profile names, and the thousands of addresses AWS announces have no profile to be proved against. An earlier build of this task fetched the document, validated it and exposed it through `ReferencePrefixes`; nothing read it, so it was deleted rather than delivered as a component described as active reference data. `CloudFrontSource` is kept as the interface a CloudFront source would satisfy; the CLI reaches CloudFront through `ParseCloudFrontProfiles` on the operator's YAML.

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

Reserve the requested maximum before I/O, persist the reservation in `/var/lib/mosdns/runtime/bandwidth-budget.json`, wrap the body in a counting limited reader, stop on timer, consume actual bytes, and return unused reservation. **The persist takes the budget's own `bandwidth-budget.json.lock` and is never made under the control lock** — a multi-minute run would hold the control lock for the length of every download, and `apply`, `pin` and `health-check` need it; the preflight ruling that superseded the Foundation's shared-control-lock ruling for this document is the one that stands. A process crash conservatively leaves the reservation charged until the local date changes. Reset `used_bytes` only when the recorded local date differs. Use `sync.Mutex`; never infer budget from file size or cache headers.

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
- equal scores sort by lower loss, then lower jitter, then the lower address.
  **Ruling (Task 3):** this line replaces the original "lower loss, higher p10 speed, lower jitter, then IP". A p10 speed is not a tie-break term: a p10 is a property of the group, so comparing two candidates' p10 values compares a number with itself, and the one predicate reading — at or above the group's p10 — is satisfied by every candidate while the group holds ten or fewer, which is the common case. A tie-break that cannot change an order is worse than no tie-break. The group's p10 speed is still computed and reported (`optimizer.TenthPercentileSpeed`, the *lower* tail by ascending nearest-rank, the same form as the prober's p50 and p95) for Task 4's report.
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

`Pin` proves the address against the profiles of the group it would be published for — **every global profile for an address with no hostname of its own, and only its own hostname's profile for one that has** (the AMENDED rule in Review Focus; the withdrawn wording was "every `Input.CloudflareProfiles` entry and every CloudFront profile", which refuses every pin and `test --apply` on a router that has a CloudFront domain list) — then stores mode `manual`, increments generation once, and never changes the file on failure. `Unpin` stores mode `auto`, keeps current winner as fallback, and increments generation. Both refuse a `disabled` selector with `ErrModeDisabled` before either opens a socket, and `Pin`'s result carries the uncharged identity bytes its proofs read (`optimizer.PinResult`).

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

Store only `healthy`, `consecutive_failures`, `last_success`, and `last_failure` in `/var/lib/mosdns/runtime/health.json`. A corrupt health file **fails closed to the policy's failure threshold**: the document this build cannot read is not a history that vouches for an address, so the count starts at the threshold and this check's own verdict is added to it. It is the *document* that is never treated as healthy — the check that then succeeds replaces it with a real one, because a successful pass is a proof and the next check is the thing that decides; a corrupt file that no check could ever replace would leave the router failing closed forever.

**Correction (Task 5, fix round 1).** The preflight ruling that this file "is written through `state.WriteJSONAtomic`" cannot stand beside the corrupt-file rule above, and the two were written as if they could. `state.WriteJSONAtomic` refuses to replace a target it cannot read — the right answer for the selector, and the wrong one here: a corrupt health document is exactly the state this rule requires recovering from, so a writer that refuses to overwrite it would leave every future check failing closed to a history no real verdict could ever clear. The durable answer is the state package's, and the review ruled for it: `state.WriteReplacementJSONAtomic`, which is the same discipline — validate, same-directory temporary file, fsync, atomic rename at 0640, backup taken before the rename, rollback on a post-rename flush failure — plus a "may replace an unreadable target" policy that `state` honours for the health kind only. Every other kind, the selector above all, is still refused, and that asymmetry is a property of the document rather than a convention. `internal/health` keeps only what is the checker's: reading the previous document and composing the fail-closed sentence.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./internal/health -v
```

Expected: compile failure.

- [ ] **Step 4: Implement health checks**

Use the same verified HTTPS identity path as final proof, HEAD when the profile supports it, GET with a zero-length/body limit otherwise, and no bandwidth-budget charge. Validate every CloudFront hostname separately.

**Correction (Task 5, fix round 1).** "Every CloudFront hostname separately" and the same verified identity path are compatible, but a *serial* walk over the profile list is not, and the first implementation was serial. A health check's deadline covered the winner and every mapping, so a router with a long `--identity-domains` list on a slow edge expired mid-walk, read the cut-short walk as a failure, reached the threshold, and moved the resolver onto its fallback — including for a newly published winner, which failed for the same reason. The walk is now concurrent under `optimizer.ProofConcurrency`, the same documented limit the optimizer's final proof uses, and the pass deadline scales with the number of waves the pass needs (`Options.WaveTimeout × waves`, capped at `health.MaximumPassTimeout`, half the shipped 120-second interval). A transition's proof keeps one fixed deadline, because it runs under the control lock and a hold that grows with the list is a hold nobody can take; a list that overruns it is refused, which moves nothing and is retried two minutes later.

- [ ] **Step 5: Add the CLI command**

```text
mosdns-cdnctl health-check
```

It takes the control lock for the health document's read-validate-change-write, for the proof window a successful pass refreshes, and for a transition when one is required; it never holds it for the length of the probe, so a successful check does not block the optimizer, and it never changes the address in service.

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

## Outstanding for the final review

- **A CloudFront mapping that has stopped serving is reported, not acted on.** Task 5
  proves every published per-hostname mapping on every health check and gives each one
  its own verdict, and the CLI prints it, but nothing moves it. `state.Selector` is
  frozen: it carries one `winner_ip`, one `fallback_ip` and a per-hostname `cloudfront`
  map with no fallback of its own, and `state.HealthState` carries four fields that can
  describe one address. A failing mapping therefore stays published until the nightly
  run replaces it — the identity phase of a run refuses an address that is not serving
  its hostname, so the replacement is the next day's work — or an operator edits the
  document. This is the right failure direction (nothing unproved is ever published) and
  it is not this plan's to fix: **the response-rewrite plan owns the schema change** that
  gives a per-hostname mapping a fallback, and until it does, this is the standing gap
  between a health check's coverage and a health check's action.

## Recorded: accepted findings this release does not change

These were raised in review, accepted, and are recorded here so they are not
rediscovered as open questions. Each is either a deliberate decision with its reason
or a bound in the safe direction.

- **The daily sample rotates only the host octet, and that is the specification's own
  requirement.** The design samples one address per `/24` and rotates *the sampled
  address* by a daily seed; `dailySeed.addressIn` hashes the block's own address with
  the local date and moves only `raw[3]`, so the block set is identical every day. A
  persistently bad *block* is therefore never rotated out, which is the cost of the
  specified rule and not a defect in this implementation. (Previously filed as an open
  question; it conforms.)
- **`prober.HTTPMetrics.BodyBytes` is a floor, not an exact wire charge**, because the
  transport may have buffered one read before the probe stopped. And with the shipped
  CLI it is **always 0**: the global identity profile is a `GET /` expecting 200 with
  no body digest, and no CloudFront profile the CLI builds names one either, so no
  identity probe this project's own configuration performs has a body to count. The
  figure is still reported because it is the only account of an uncharged egress a
  caller that *does* name a digest can have.
- **Only body bytes are charged** to the daily budget: headers, request bytes and
  handshake buffering are not, and neither is the 3xx body of a followed same-host
  redirect — `net/http` drains a bounded amount of it while following the hop, outside
  the counting reader. Every one of these is bounded and in the under-counting
  direction, so none of them can break the cap.
- **The redirect host comparison ignores the port.** Its impact is nil rather than
  merely bounded: the transfer's dialer ignores the URL's port and always dials the
  profile's port, so a same-host redirect naming a different port reaches the same
  address, and every hop still completes its own certificate check for the same name.
- **The global identity profile is `GET /`, 200, no body digest** — the provider's
  representative domain and the forced-ECH domains. That is a real gap in *content*
  verification: it proves routing and identity, not that the document behind the
  hostname is the one expected. The plan names it rather than weakening the check,
  because a domain that answers something else is a domain to take out of the list.
- **`candidate.Combine` caps the official channel by input order** rather than the
  package sort order. It is deterministic and coherent with the report's collection
  order, which is the order the report lists candidates in.
- **A user `/24`-or-narrower prefix expansion includes `.0` and `.255`.** A deliberate
  enumeration, pinned as intended.
- **`health.Options.ProofConcurrency` exists for one order-sensitive case**; the
  production value is `optimizer.ProofConcurrency`, the number an apply's final proof
  uses over the same profiles.
- **The one-`*Budget`-per-document rule is a convention, not an invariant.** The
  document records no owner because its schema is fixed and a crashed holder must not
  block the next run, so the requirement is on the runner — see `Budget`'s own doc.
- **A post-rename directory-sync failure inside `state.WriteJSONAtomic` can return an
  error with the new selector live**, so the report under-claims rather than
  over-claims. The safe direction.
- **`Apply`'s zero `Selector` return means both "published nothing" and "refused"**,
  distinguished by the error and by the report's `Outcome`. Safe because the zero value
  is refused by `state.Selector.Validate` and no shipped caller discards the error.
