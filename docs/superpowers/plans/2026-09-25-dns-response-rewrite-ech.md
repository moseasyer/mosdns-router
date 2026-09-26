# DNS Response Rewrite and ECH Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Post-process MOSDNS responses to replace validated Cloudflare/CloudFront IPv4 answers, suppress AAAA for rewritten names, and provide user-allowlisted Cloudflare ECH in strict fail-closed or fallback mode.

**Architecture:** One recursive MOSDNS plugin wraps the foreign cache/forward path. It can short-circuit strict A/AAAA queries before any upstream/cache lookup, call the next sequence for normal queries, and then mutate only validated responses. ECHConfig bytes are fetched directly through the foreign DNSCrypt upstream, validated in memory, and never routed back through the rewrite plugin.

**Tech Stack:** Go 1.25, MOSDNS v5.3.4 recursive plugin API, `miekg/dns` v1.1.70 SVCB/HTTPS support, RFC 9848/9849 binary parsing, atomic state, local DNS/TLS mocks.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- Rewrite only IPv4; when A is rewritten, suppress AAAA for the same CDN name.
- Cloudflare rewriting requires all terminal A records to be Cloudflare addresses and a healthy selected IPv4.
- CloudFront rewriting is exact-hostname/profile based and never global.
- Force-ECH domains come only from `/etc/mosdns/force-ech-domains.txt`.
- Strict mode returns no A/AAAA and an HTTPS ServiceMode with `target="."`, ECH, `mandatory=ech`, and the selected `ipv4hint`.
- Strict ECH source/config failure returns DNS failure and never restores A/AAAA.
- Preserve compatible HTTPS SvcParams; remove incompatible endpoints and IPv6 hints.
- Any modified RRset must clear AD and remove inconsistent DNSSEC records.
- No local DoH, CA, MITM, SNI DPI, or Firefox profile modification.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- A single Cloudflare address in a mixed-CDN response must not trigger rewriting.
- CloudFront mapping for one hostname must not affect a sibling or subdomain.
- A stale/corrupt selector file must keep the last valid in-memory generation.
- Unknown or malformed ECHConfig bytes must never be inserted into HTTPS RR.
- Modified DNSSEC responses must not retain AD=true or stale RRSIG/NSEC/NSEC3 data.

---

## File Map

```text
internal/echconfig/parse.go
internal/echconfig/parse_test.go
internal/echconfig/testdata/cloudflare-ech-base64.txt
internal/dnsclassify/classify.go
internal/dnsclassify/classify_test.go
internal/dnsrewrite/address.go
internal/dnsrewrite/address_test.go
internal/dnsrewrite/dnssec.go
internal/dnsrewrite/dnssec_test.go
internal/dnsrewrite/https.go
internal/dnsrewrite/https_test.go
internal/statewatch/watcher.go
internal/statewatch/text.go
internal/statewatch/watcher_test.go
plugin/executable/cdn_rewrite/cdn_rewrite.go
plugin/executable/cdn_rewrite/ech_provider.go
plugin/executable/cdn_rewrite/cdn_rewrite_test.go
internal/mosdnsconfig/render.go
internal/mosdnsconfig/render_test.go
cmd/mosdns-router/main.go
tests/integration/rewrite_test.go
Makefile
```

### Interfaces produced by this plan

```go
package echconfig

type Config struct { Version uint16; ConfigID uint8; KEMID uint16; PublicName string; Raw []byte }
type List struct { Configs []Config; Raw []byte }
func Parse(raw []byte) (List, error)
func (l List) Validate() error

package dnsclassify

// Result authorizes a rewrite only when AllMatch is true. On every refusal
// Provider and TerminalName are empty, so a Result that is forwarded without
// being read carries nothing the rewriter would accept. Refusal is the reason
// there is none; RefusalNone is a rewriteable response.
type Result struct { Provider candidate.Provider; TerminalName string; AllMatch bool; Mixed bool; Refusal Refusal }
type Refusal string
func Cloudflare(msg *dns.Msg, prefixes []netip.Prefix) Result
// Chain is the one bounded CNAME walk, exported so the rewriter uses it rather
// than writing a second one: it keys the names it has been on by their canonical
// form, so a self-alias and any cycle terminate at the first repeat.
func Chain(msg *dns.Msg) ([]string, Refusal)
func CanonicalName(name string) string

package dnsrewrite

type AddressInput struct { Response *dns.Msg; QType uint16; Provider candidate.Provider; Selected netip.Addr; SuppressAAAA bool; TerminalName string; Hostname string; Prefixes []netip.Prefix }
// TerminalName is the owner dnsclassify walked to, required and checked against
// the response's own chain. Hostname is the exact CloudFront hostname, and
// applies to candidate.ProviderCloudFront only. Prefixes is the caller's
// published Cloudflare ranges: the Cloudflare arm re-derives the verdict from
// them rather than trusting the label, and the CloudFront arm refuses a response
// they call Cloudflare-served.
func Address(in AddressInput) (*dns.Msg, error)
func StripModifiedDNSSEC(msg *dns.Msg)

package statewatch
// Document is the union of the five state documents state.ReadJSON accepts as a
// destination. It is a constraint and not `any` because the watcher decodes with
// state.ReadJSON, so a second opinion about what a valid state document is has
// nowhere to be expressed -- a plugin cannot pass its own reader.
type Document interface {
    state.DHCPState | state.Selector | state.ECHState | state.BandwidthBudgetState | state.HealthState
}
// DefaultPollInterval is 500ms. Options.PollInterval of zero means it; a negative
// interval is refused rather than rounded, because time.NewTicker panics on one.
type Options struct {
    PollInterval time.Duration
    // ReloadError is called once per episode of failed reloads, from the poll.
    // It is how a refusal that happens without the caller asking is still loud.
    ReloadError func(error)
}
type Watcher[T Document] struct { /* private */ }
func NewJSON[T Document](path string, validate func(T) error, initial T, options ...Options) (*Watcher[T], error)
func (w *Watcher[T]) Snapshot() T
func (w *Watcher[T]) ReloadNow() error
func (w *Watcher[T]) Close() error

type TextWatcher struct { /* private */ }
func NewTrimmedLines(path string, initial []string, options ...Options) (*TextWatcher, error)
func (w *TextWatcher) Snapshot() []string
func (w *TextWatcher) ReloadNow() error
func (w *TextWatcher) Close() error

// LineError names the line a force-ECH list was refused for. A value, so a caller
// holding one cannot edit what the watcher recorded.
type LineError struct { Path string; Line int; Text string; Reason string }
// UnsupportedDocument names a state document the watcher cannot hold, because
// documentCloners has no entry for it. Returned by NewJSON, never panicked: a
// plugin's Init is the only caller and nothing recovers from a panic there.
type UnsupportedDocument struct { Document string }
```

```go
// plugin/executable/cdn_rewrite
const PluginType = "cdn_rewrite"

type Args struct {
    PolicyFile         string `yaml:"policy_file"`
    SelectorFile       string `yaml:"selector_file"`
    ForceECHFile       string `yaml:"force_ech_file"`
    ECHStateFile       string `yaml:"ech_state_file"`
    ForeignUpstream    string `yaml:"foreign_upstream"`
    CloudflareCIDRFile string `yaml:"cloudflare_cidr_file"`
}
```

### Amendments from Task 4

Task 4 shipped the watchers, and the `statewatch` block above is its shipped
shape. Four departures from the block this plan first wrote, each forced by a
ruling or by a refusal the original did not anticipate. A Task 5 author must read
this section, not the plan's original block.

- **`T` is constrained to the `Document` union rather than `any`.** The plan's
  ruling was that the watcher's decode-and-validate step IS `state.ReadJSON`, and
  `state.ReadJSON` accepts only those five document types as a destination. The
  constraint is what makes that ruling structural rather than a convention: a
  caller that could name any type at all would be able to ask for a watcher with a
  second opinion about what a valid state document is. A caller's `validate` is
  still accepted and is applied AFTER `state.ReadJSON`, so it may only ADD a
  refusal, never remove one.
- **Both constructors return an error.** An empty path and a negative
  `PollInterval` are programming errors, and `time.NewTicker` panics on a
  non-positive interval inside the poll goroutine, after the router has started.
  A plugin's `Init` already returns an error, so the cost to Task 5 is one `if`.
- **One optional `Options` value, variadic.** Zero `Options` means the documented
  500 ms and no reporting, so a production call site reads as
  `NewJSON[state.Selector](path, validate, initial)`. A second `Options` value is
  refused rather than half-honoured.
- **`Options.ReloadError`.** The plan's own ruling is that a malformed force-ECH
  list "keeps the last valid list, logs the offending line, and is caught at
  startup". The poll happens inside the watcher, so without a callback the plugin
  cannot learn of a failure except through `ReloadNow`, which it does not call on
  a timer. The handler is called once per episode of the same failure, and is not
  called for a `ReloadNow` the caller asked for, because the caller has that
  error as a return value. **Task 5 must pass a handler that logs**, or a
  corrupt-allowlist replacement will be refused silently in production.

Two behaviours Task 5 depends on that the plan did not state, both pinned by
tests in `internal/statewatch`:

- **A failed reload changes nothing.** The last valid document stays, whether the
  refusal was a missing file, a truncated write, a schema version this build does
  not know, or the caller's own check. A corrupt replacement never reaches a query.
- **A force-ECH list is refused whole, and a zero-byte file is refused too.** One
  malformed line keeps the last valid list and reports the line. A file of **no
  bytes** is refused as well, because the list is not producer-written and an
  operator's in-place write (`> file`, `sed -i`, a truncating editor) leaves
  exactly zero bytes there for as long as the write takes; accepting it would drop
  every forced domain silently. A **comments-only or blank-lines-only file is
  accepted** as the intentional empty list, so the operator can still turn forcing
  off. Names must be written punycoded; a domain with a non-ASCII character is
  refused.

Three obligations for whoever adds a state document to `state`, which the
compiler will **not** remind them of for the last two:

- add it to the `Document` union in `internal/statewatch/watcher.go`;
- give it an entry in `documentCloners` in the same file, and clone its map and
  slice fields there -- `documentCloner` refuses to build a copy function for a
  document with no entry, so a new document cannot be watched until it has one,
  and that refusal is the only thing standing between a new document and a silent
  shallow copy;
- add a subtest to `TestJSONWatcherSnapshotIsIndependentOfEveryDocumentItCanHold`,
  which fails on a count mismatch, so a document nobody thought about cannot sit
  in the union unwatched.

### Amendments from Task 2

`Address` returns `(*dns.Msg, error)` rather than `error` because the rule that a
rewrite is applied to a clone and the error-only signature are jointly
unsatisfiable: a function that neither returns a message nor mutates its argument
has nowhere to put a rewrite, so returning the message is the only shape that
leaves the caller's object untouched. `AddressInput` carries the three fields that
make the call checkable: `TerminalName`, `Hostname` and `Prefixes`. `Result`
carries `Refusal`. Task 2 shipped all of these; the block above is the shipped
shape, and it compiles verbatim against it.

Three obligations no other section of this plan states, which the later tasks
inherit:

- **Task 5 must handle both shapes `Address` returns.** A refusal is
  `(nil, error)`; a call that had nothing to change is `(in.Response, nil)`, the
  caller's own message. A caller that discards the error is left holding a `nil`
  message, which is the loud direction on purpose, and a caller that assumes a
  non-nil first return is always a message is wrong. Decide on one shape and hold
  to it: on a refusal, return the original upstream response unchanged, and in
  strict ECH mode fail closed instead.
- **Task 5 must gate the AAAA-suppression path itself.** `Address` classifies only
  the Cloudflare A path, because an AAAA answer carries no A records for the
  published ranges to be checked against, so a `QType: dns.TypeAAAA` call with
  `SuppressAAAA` set arrives at the rewriter with no Cloudflare verdict required of
  it. Task 5 must reach that path only with a verdict it already holds, and never
  for a name whose classification was refused.
- **Task 3 must call `StripModifiedDNSSEC` after rewriting the HTTPS RR.** The
  ruling that any modified RRset drops all DNSSEC records and clears AD applies to
  the SVCB parameters as much as to an address: an ECH-rewritten HTTPS record
  that keeps the RRSIG over the old RRset would ship a message with `AD=true` and
  a signature that contradicts the parameters in front of it, which is the exact
  state the ruling exists to prevent. The function is exported and takes the
  message in place, so call it on the copy the plugin already made.

### Amendments from the Task 3 review (fix round 1)

Task 3 shipped and was reviewed. Five defects were Important and are fixed; the plan
now states the behaviour they changed, because two of them are decisions a package
cannot make on its own and a third is a rule Task 5 inherits.

**Interfaces (shipped).** `internal/dnsrewrite` now exports, and this is the shape Task
5 compiles against:

```go
func HTTPS(in HTTPSInput) (*dns.Msg, error)

type FailurePolicy int

const (
    FailClosed        FailurePolicy = iota // strict
    FallbackToOriginal                    // fallback
)

type HTTPSInput struct {
    Response *dns.Msg      // never modified, and never read for parameters
    QName    string        // required, checked against the response's own question
    Selected netip.Addr    // must be a routable public IPv4
    ECH      []byte        // ECHConfigList bytes, validated here; nil means none
    Policy   FailurePolicy
    Report   func(Report)  // optional: what the synthesis left out, and why
}

type Report struct{ Dropped []DroppedParameter }
type DroppedParameter struct {
    Key    dns.SVCBKey
    Reason string
}

var (
    ErrNoECHConfig          // the ECH source published nothing
    ErrInvalidECHConfig     // it published something this router will not forward
    ErrNoSelectedAddress    // no address to hint: absent, unproved, or unhealthy
    ErrNoCompatibleEndpoint // the name published service bindings, none usable here
    ErrDelegatedName        // a CNAME at the owner, or an AliasMode record in its RRset
    ErrUpstreamDenial       // the upstream's rcode is a statement, not an absence
    ErrNoOriginal           // nothing to forward; wraps whichever refusal led there
)
```

Four obligations, each one a change from what round 1 shipped:

- **`HTTPS` returns the message and the refusal together under the fallback policy.**
  A `FallbackToOriginal` caller gets `(in.Response, err)` for every refusal, and
  `(clone, nil)` for a synthesis. A `FailClosed` caller gets `(nil, err)` for every
  refusal. There is no third shape. **Task 5 must forward whatever message arrived and
  log the error, and must fail closed when the message is nil.** A caller that returns
  as soon as it sees an error throws away the upstream's own answer and turns a working
  fallback domain into a SERVFAIL; a caller that ignores the error is safe but blind to
  a broken ECH source, a dead selector, or a name the upstream delegated. Note the
  ordering requirement, which is the shape of the last sentinel: `ErrNoOriginal` wraps
  the refusal that left nothing to forward, so `errors.Is(err, ErrNoECHConfig)` is also
  true of it. Test `ErrNoOriginal` first; forward the message either way; fail closed
  when it is nil. This amends the Task 2 obligation above for `HTTPS` only: `Address`
  still returns a message only with a nil error.
- **A missing or unhealthy selected address is fatal under strict only.** Under
  `FailClosed` an address that is absent, unproved or failed its health check is
  `ErrNoSelectedAddress`, because a record with no hint sends the client to resolve the
  name and a force-ECH domain has that resolution emptied. Under
  `FallbackToOriginal` the same input yields `(in.Response, ErrNoSelectedAddress)`: the
  upstream's record still describes the service, its own hint is still the upstream's to
  vouch for, and no `ipv4hint` and no `ech` are written, because there is no address to
  point at. Falling back to SERVFAIL there would take a fallback domain offline through
  the project's own health gate, which is the opposite of what the policy is for. The
  cost is recorded rather than hidden: a fallback domain whose selector is down serves
  an answer whose ClientHello this router could not encrypt, and the error is the only
  thing that says so.
- **A name the upstream delegated is never synthesized into.** Two shapes: a CNAME at
  the owner, and an RRset at the owner containing an AliasMode record (RFC 9460
  Section 2.4.1). Both are `ErrDelegatedName`, both are refusals under strict, and both
  hand the upstream's own answer back under fallback. **Task 5 must not attempt to
  rewrite a name this package refused as delegated, and must not treat the refusal as an
  ECH-source failure** -- the two sentinels are separate on purpose. Note the cost,
  which is real: a force-ECH domain that is a CNAME is unreachable over HTTPS in strict
  mode, because the service is described under the other name. The alternative, which
  round 1 did, is to drop the chain and synthesize a service mode for the queried name,
  which covers more domains and relies on a certificate this router cannot check.
- **The addresses of the queried name are removed from every section, by this package.**
  RFC 9460 Section 7.3 has a client ignore the hints when it already holds an A or AAAA
  answer for the record's effective TargetName, which is the name the client asked
  about, so an address for that name in either the answer or the additional section is
  an answer that beats the selected address. **Task 5 must not add an address for the
  queried name to an HTTPS answer after calling `HTTPS`**, and must not rely on this
  package for an A or AAAA query: `Address` owns the terminal A and AAAA records of a
  CDN name on an A or AAAA answer, this owns the addresses of the queried name inside an
  HTTPS answer, and the two cover disjoint messages. A caller that answered an HTTPS
  query and then rewrote its addresses would be answering a question the client did not
  ask.

Two rules that were already in the plan and are now stated in the code as well:

- **A parameter is inherited only when every retained endpoint carries it with the same
  value.** RFC 9460 Section 7.2 makes an absent key an instruction to use the default,
  so an endpoint that omits a parameter has claimed the default and one endpoint's value
  is not the service's value. A dropped parameter leaves a usable record, and every drop
  is reported through `Report` so Task 5 can log and count the degraded answers.
- **An upstream answer this router may not turn positive.** A NODATA, a SERVFAIL and a
  REFUSED with an empty answer are absences; NXDOMAIN, FORMERR, NOTIMP, and any failure
  carrying records, are `ErrUpstreamDenial`. Task 5 forwards the upstream's own denial
  under the fallback policy and fails closed under strict.

---

### Task 1: Parse and validate ECHConfigList bytes

**Files:**
- Create: `internal/echconfig/parse.go`
- Create: `internal/echconfig/parse_test.go`
- Create: `internal/echconfig/testdata/cloudflare-ech-base64.txt`

**Interfaces:**
- Consumes: the ECHConfigList bytes carried by `dns.SVCBECHConfig.ECH`.
- Produces: validated config metadata and the exact original bytes for DNS insertion.

- [ ] **Step 1: Add a current-format non-secret fixture**

Create `cloudflare-ech-base64.txt` with the public ECHConfigList observed on 2026-09-25:

```text
AEX+DQBBuAAgACBeWfLyd08MrrxQgz3O0ws1h/j6yhgH1+4jTfFQ5Y6qawAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=
```

The test must decode standard base64 and must not contact Cloudflare.

- [ ] **Step 2: Write failing parser tests**

Assert the fixture yields ECH version `0xfe0d`, public name `cloudflare-ech.com`, non-empty HPKE public key, at least one supported cipher suite, and a maximum name length. Add malformed cases for bad outer length, truncated config, unsupported version, empty public name, duplicate config IDs, and trailing bytes.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./internal/echconfig -v
```

Expected: compile failure.

- [ ] **Step 4: Implement bounded parsing**

Honor the outer uint16 list length, then each config's uint16 length. Parse version, config ID, KEM ID, public-key length, cipher-suite vector length, maximum name length, and public-name bytes according to RFC 9849. Reject lengths that exceed the remaining buffer; never allocate based on an untrusted unchecked length.

- [ ] **Step 5: Implement validation**

Require version `0xfe0d`, KEM ID `0x0020` (DHKEM X25519), at least one recognized AEAD cipher suite, unique config IDs, and a valid DNS public name. Return the original list bytes unchanged for `dns.SVCBECHConfig`.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/echconfig -v
go test -race ./internal/echconfig -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/echconfig
git commit -m "feat: parse and validate ECH configs"
```

---

### Task 2: Classify CDN responses and rewrite A/AAAA safely

**Files:**
- Create: `internal/dnsclassify/classify.go`
- Create: `internal/dnsclassify/classify_test.go`
- Create: `internal/dnsrewrite/address.go`
- Create: `internal/dnsrewrite/address_test.go`
- Create: `internal/dnsrewrite/dnssec.go`
- Create: `internal/dnsrewrite/dnssec_test.go`

**Interfaces:**
- Consumes: DNS responses, official Cloudflare prefixes, selected IPv4, and exact CloudFront hostname mappings.
- Produces: conservative provider classification and DNSSEC-safe address rewrites.

- [ ] **Step 1: Write failing CNAME-chain classification tests**

Build responses for direct A, one CNAME, multiple CNAMEs, mixed Cloudflare/non-Cloudflare A, empty terminal A, and CNAME loops. Assert `AllMatch` is true only when every terminal A belongs to Cloudflare.

- [ ] **Step 2: Write failing address rewrite tests**

Assert:

- direct A becomes exactly one selected A with the original owner/TTL;
- CNAME records are preserved and only terminal A records are replaced;
- AAAA records for the qname/CNAME chain are removed when suppression is enabled;
- non-CDN responses are byte-preserved;
- selected IPv6 is rejected;
- CloudFront mapping is used only for the exact configured hostname.

- [ ] **Step 3: Write failing DNSSEC tests**

Start with `AD=true` and synthetic RRSIG/NSEC/NSEC3. After a rewrite assert `AD=false`, no RRSIG covers A/AAAA/HTTPS, and no NSEC/NSEC3 remains in Answer/NS. Assert a response not modified by the plugin retains its original DNSSEC records.

- [ ] **Step 4: Run tests and verify failure**

```bash
go test ./internal/dnsclassify ./internal/dnsrewrite -v
```

Expected: compile failure.

- [ ] **Step 5: Implement conservative classification**

Walk the CNAME graph from the question name, reject loops, collect terminal A owners, and require at least one address. Compare canonical IPv4 using `netip.Prefix.Contains`. Treat any non-Cloudflare terminal address as `Mixed=true` and do not rewrite globally.

- [ ] **Step 6: Implement address mutation**

Clone the response before mutation. Preserve CNAME chain and non-address RRs, remove terminal A RRs, append one `dns.A` at the terminal owner using the selected IPv4, and filter AAAA only when `SuppressAAAA=true`. Preserve the minimum TTL of the replaced A records; do not synthesize a new fixed TTL.

- [ ] **Step 7: Implement DNSSEC cleanup**

Set `MsgHdr.AuthenticatedData=false`. Remove RRSIG records covering A, AAAA, HTTPS, CNAME chains affected by the rewrite, plus NSEC/NSEC3 records. Keep OPT handling exclusively through MOSDNS query context.

- [ ] **Step 8: Run tests**

```bash
go test ./internal/dnsclassify ./internal/dnsrewrite -v
go test -race ./internal/dnsclassify ./internal/dnsrewrite -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/dnsclassify internal/dnsrewrite/address.go internal/dnsrewrite/address_test.go internal/dnsrewrite/dnssec.go internal/dnsrewrite/dnssec_test.go
git commit -m "feat: rewrite validated CDN addresses"
```

---

### Task 3: Implement strict and fallback HTTPS/ECH synthesis

**Files:**
- Create: `internal/dnsrewrite/https.go`
- Create: `internal/dnsrewrite/https_test.go`

**Interfaces:**
- Consumes: qname, selected IPv4, upstream HTTPS RR, validated ECH list, and failure policy.
- Produces: strict ServiceMode or a fallback-compatible HTTPS RR.

- [ ] **Step 1: Write failing strict synthesis test**

Given an upstream HTTPS RR with ALPN, port, dohpath, and unknown local parameters, assert the strict output:

```text
Priority = 1
Target = "."
mandatory contains ech
ech contains exact validated bytes
ipv4hint contains only selected IPv4
ipv6hint absent
alpn preserved
port/dohpath/unknown parameters preserved
```

- [ ] **Step 2: Write failing strict failure tests**

Assert missing config, invalid config, unhealthy/missing selected IP, and incompatible upstream endpoints produce SERVFAIL or no usable ServiceMode according to the plugin contract, never original A/AAAA. A missing upstream HTTPS RR is not itself a config failure: when ECHConfig and selected IPv4 are valid, synthesize a minimal ServiceMode with ALPN `h2,h3`; an upstream SERVFAIL may still be bypassed because the ECH source lookup and selected address are independent.

- [ ] **Step 3: Write failing fallback tests**

Assert valid config updates ECH/hints while retaining other compatible parameters. Missing config preserves the original usable HTTPS RR, and A fallback remains the selector/fallback/original chain defined by the optimizer.

- [ ] **Step 4: Write endpoint compatibility tests**

Test multiple upstream HTTPS RRs: retain only endpoints whose target/hints can use the selected IPv4 and shared ECH config. Reject an endpoint with an IPv6-only target when the project is IPv4-only. Ensure `mandatory` has no duplicates and every mandatory key is present.

- [ ] **Step 5: Run tests and verify failure**

```bash
go test ./internal/dnsrewrite -run TestHTTPS -v
```

Expected: compile failure.

- [ ] **Step 6: Implement SVCB parameter editing**

Use `dns.SVCBMandatory`, `dns.SVCBAlpn`, `dns.SVCBIPv4Hint`, `dns.SVCBIPv6Hint`, and `dns.SVCBECHConfig`. Sort mandatory keys through the library's pack behavior, deduplicate before packing, and preserve unknown `dns.SVCBLocal` parameters by deep copy.

- [ ] **Step 7: Run tests**

```bash
go test ./internal/dnsrewrite -v
go test -race ./internal/dnsrewrite -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/dnsrewrite/https.go internal/dnsrewrite/https_test.go
git commit -m "feat: synthesize strict and fallback ECH"
```

---

### Task 4: Add generic atomic-file watchers

**Files:**
- Create: `internal/statewatch/watcher.go`
- Create: `internal/statewatch/text.go`
- Create: `internal/statewatch/watcher_test.go`

**Interfaces:**
- Consumes: schema version 1 JSON files replaced by atomic rename.
- Produces: race-free last-valid snapshots for selector and health/ECH metadata.

- [ ] **Step 1: Write failing watcher tests**

Cover unchanged content, valid replacement, corrupt replacement, rapid double replacement, close during poll, and a file replaced between stat and open. Assert the previous valid snapshot remains after a failed reload. For `TextWatcher`, assert comments/blank lines are removed, domains are lowercased and deduplicated, malformed non-domain text is rejected, and a corrupt allowlist replacement keeps the previous valid list.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/statewatch -v
```

Expected: compile failure.

- [ ] **Step 3: Implement polling watcher**

Poll every 500 ms by default. Read by path, validate, then atomically store a value copy. Use `RWMutex`; `Snapshot` returns a deep enough copy for maps/slices to prevent caller mutation. `Close` stops the goroutine and waits for it.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/statewatch -v
go test -race ./internal/statewatch -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/statewatch
git commit -m "feat: watch atomic state files"
```

---

### Task 5: Implement the recursive `cdn_rewrite` MOSDNS plugin

**Files:**
- Create: `plugin/executable/cdn_rewrite/ech_provider.go`
- Create: `plugin/executable/cdn_rewrite/cdn_rewrite.go`
- Create: `plugin/executable/cdn_rewrite/cdn_rewrite_test.go`
- Modify: `cmd/mosdns-router/main.go`

**Interfaces:**
- Consumes: selector, allowlist, ECH source, Cloudflare CIDRs, and the downstream foreign sequence.
- Produces: plugin tag `cdn_rewrite` implementing `sequence.RecursiveExecutable`.

- [ ] **Step 1: Write failing short-circuit tests**

For a strict force-ECH domain, send A and AAAA queries and assert the plugin does not call `next`, returns NOERROR with an empty Answer, and writes no upstream query to the mock.

- [ ] **Step 2: Write failing post-processing tests**

For normal A/AAAA/HTTPS queries, assert `next` is called exactly once before mutation. Return the same cached response pointer from a fake next execution and prove the plugin writes mutations to `qCtx.R().Copy()`, leaving the cached object unchanged. Cover disabled ECH, no selector, disabled provider, healthy winner, unhealthy winner, Cloudflare, exact CloudFront hostname, mixed CDN, and non-CDN response.

- [ ] **Step 3: Write failing ECH provider tests**

Use a fake `upstream.Upstream` returning the fixture HTTPS RR. Assert direct query type 65, TTL-derived refresh, no re-entry into the main sequence, valid public-name enforcement, stale grace, and strict SERVFAIL after grace.

- [ ] **Step 4: Write failing reload tests**

Atomically replace selector and force-ECH files. Assert new queries see the new generation; corrupt replacements keep the prior valid list. Add a Cloudflare CIDR reload test.

- [ ] **Step 5: Run tests and verify failure**

```bash
go test ./plugin/executable/cdn_rewrite -v
```

Expected: compile failure.

- [ ] **Step 6: Implement ECH provider**

Create a direct client with `upstream.NewUpstream(ForeignUpstream, upstream.Opt{Logger: bp.L()})`. Build a fresh DNS query for each configured source, require one IN/HTTPS answer, extract `dns.SVCBECHConfig`, parse it, require a consistent public name, and retain bytes in memory. Respect TTL with a 60-second minimum refresh and configured stale grace. Write only metadata/hash to `ech-state.json`.

- [ ] **Step 7: Implement recursive execution order**

```text
strict force + A/AAAA -> synthesize NODATA, do not call next
strict force + HTTPS   -> call next, use compatible upstream parameters when present, otherwise synthesize minimal h2,h3 ServiceMode
all other supported    -> call next, classify/mutate
unsupported qtype      -> call next unchanged
```

A nil downstream response becomes SERVFAIL through plugin error handling. Never call the main sequence recursively for ECH source lookups.

- [ ] **Step 8: Register and import the plugin**

Use `coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })`. At initialization call `config.Load(PolicyFile)` and retain the validated policy for AAAA suppression, ECH policy, and stale grace. After `next.ExecNext`, copy the downstream response with `qCtx.R().Copy()` before any mutation and set the copy back, so a cache hit is never modified in place. Implement `Close` to stop JSON/text watchers and the ECH provider, and add the blank import to `cmd/mosdns-router/main.go`.

- [ ] **Step 9: Run tests**

```bash
go test ./plugin/executable/cdn_rewrite -v
go test -race ./plugin/executable/cdn_rewrite -v
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add plugin/executable/cdn_rewrite cmd/mosdns-router/main.go
git commit -m "feat: add CDN and ECH rewrite plugin"
```

---

### Task 6: Integrate the plugin before foreign cache and prove wire behavior

**Files:**
- Modify: `internal/mosdnsconfig/render.go`
- Modify: `internal/mosdnsconfig/render_test.go`
- Create: `tests/integration/rewrite_test.go`
- Modify: `Makefile`

**Interfaces:**
- Consumes: approved system paths and the plugin Args.
- Produces: final foreign sequence with rewrite wrapping cache and forward.

- [ ] **Step 1: Update renderer tests first**

Assert foreign path order:

```text
cdn_rewrite -> foreign_cache -> foreign_forward
```

Assert `cdn_rewrite` is not in the domestic path and receives the policy file, selector, allowlist, ECH metadata, direct foreign upstream, and Cloudflare CIDR file. That direct foreign upstream is `tcp://127.0.0.1:15353`, the same loopback TCP listener the foreign forward uses: ECHConfig bytes are fetched from the same resolver through the same transport, and MOSDNS's stock UDP transport is measured re-sending unanswered queries and dropping answers, so an ECH fetch must not be the one place that uses it. The plugin loads AAAA suppression, ECH failure policy, and stale grace through `config.Load` so one policy file is authoritative.

- [ ] **Step 2: Run renderer tests and verify failure**

```bash
go test ./internal/mosdnsconfig -v
```

Expected: FAIL because the plugin is not rendered.

- [ ] **Step 3: Update the renderer**

Insert `cdn_rewrite` as the first executable in `foreign_path`. Keep cache downstream so normal upstream responses are cached before the outer recursive plugin mutates a deep copy of the returned response. A cache-hit integration assertion must query again after changing selector generation and prove the second query returns the new IP without corrupting the first cached object.

- [ ] **Step 4: Write integration wire tests**

Start local DNS and HTTPS upstreams. Query A/AAAA/HTTPS for Cloudflare, mixed CDN, and a CloudFront profile. Assert exact owner names, answer counts, selected IP, empty AAAA, ECH parameter, mandatory key, hints, AD bit, and RRSIG removal.

- [ ] **Step 5: Add strict ECH integration cases**

Assert A/AAAA never reach either cache or upstream, valid HTTPS reaches only the foreign upstream, strict config failure returns SERVFAIL, and fallback mode returns an A answer when ECH is unavailable.

- [ ] **Step 6: Run all verification**

```bash
go test ./internal/dnsclassify ./internal/dnsrewrite ./internal/echconfig ./internal/statewatch ./plugin/executable/cdn_rewrite -v
go test ./tests/integration -run 'TestRewrite|TestECH' -v
go test ./...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/mosdnsconfig tests/integration/rewrite_test.go Makefile
git commit -m "test: prove CDN rewrite and ECH wire behavior"
```

---

## Plan Acceptance

Run:

```bash
go test ./internal/echconfig ./internal/dnsclassify ./internal/dnsrewrite ./internal/statewatch ./plugin/executable/cdn_rewrite -v
go test -race ./internal/echconfig ./internal/dnsrewrite ./plugin/executable/cdn_rewrite
go test ./tests/integration -run 'TestRewrite|TestECH' -v
```

Expected:

- only validated CDN responses change;
- strict force-ECH A/AAAA never reach upstream;
- HTTPS strict/fallback behavior matches policy;
- modified responses never claim DNSSEC validation;
- no local DoH/CA/MITM component exists.
