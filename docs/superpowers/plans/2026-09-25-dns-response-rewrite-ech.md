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
internal/candidate/cloudflare.go
internal/candidate/cloudflare_test.go
internal/candidate/prefixes.go
internal/candidate/prefixes_test.go
plugin/executable/cdn_rewrite/cdn_rewrite.go
plugin/executable/cdn_rewrite/ech_provider.go
plugin/executable/cdn_rewrite/cdn_rewrite_test.go
internal/mosdnsconfig/render.go
internal/mosdnsconfig/render_test.go
cmd/mosdns-router/main.go
tests/integration/rewrite_test.go
tests/integration/routing_test.go
cmd/mosdns-cdnctl/render_test.go
configs/mosdns.yaml
scripts/test-make-entrypoints.sh
Makefile
```

The four `internal/candidate` files are Task 5's addition to the producer, added for
the reason recorded in the amendments below: nothing produced a plain prefix list
for the plugin's `cloudflare_cidr_file` to name, and the cached Cloudflare envelope
is not one. Two of the four are the files the producer already had — the change to
`cloudflare.go` is the call that publishes the list from the document a run has just
accepted, and the change to `cloudflare_test.go` is one assertion in
`TestCloudflareCacheIsWrittenOnlyUnderTheInjectedPath`, which a second artifact
under the injected root made wrong in its letter while leaving its property intact.

The last six entries are Task 6's, and three of them are not in Task 6's own file
list, which is the first thing a later reader needs to know:

- **`tests/integration/routing_test.go`** is modified because the plugin is now
  rendered into every configuration this package starts. That is the point of the
  change rather than a side effect: a routing case that ran without the rewriter
  would be proving the routing of a document nobody ships, and the claim that a
  China answer is byte-identical "with the plugin installed" cannot be made in a
  process where the plugin is absent. The harness now writes the five documents the
  rewriter reads, with a **disabled** selector and an allowlist that is a comment,
  so a routing case gets a plugin that starts and changes nothing beyond what the
  case is about.
- **`cmd/mosdns-cdnctl/render_test.go`** is modified because the committed routing
  document names the policy path **twice** now: once in the generated header and
  once as the rewriter's `policy_file`. The test derived its expectation by replacing
  the first occurrence and refused to run when there was more than one, which is a
  correct guard against an ambiguous replacement applied to a document that had only
  one. It now requires exactly two, replaces all of them, and additionally asserts
  that the published document carries `policy_file: <the policy the render was
  given>` — a byte comparison against the committed file could not tell a document
  whose header named one policy from a document whose plugin argument named another.
  This is the obligation a policy path appearing twice in one generated document
  creates for anything that derives an expectation from that document.
- **`configs/mosdns.yaml`** is the renderer's output, regenerated through
  `MOSDNS_ROUTER_UPDATE=1 go test ./internal/mosdnsconfig` and never hand-edited.
  Its header gained a paragraph, because the file is read by whoever is diagnosing a
  wrong answer and a rewriter nothing mentions is a rewriter nobody knows is there.
- **`scripts/test-make-entrypoints.sh`** now asserts `-count=1` on the line `verify`
  plans for the end-to-end package, not only on the one `test-integration` plans. The
  flag is the difference between a gate that ran the wire tests and a gate that
  replayed a cached result, and it belonged to the gate's contract rather than to one
  target's comment.
- **`Makefile`** needed no functional change: `test-integration` already ran the
  whole package with `-count=1`, and the new cases are in that package. Its comment
  is what changed, to say what the suite now covers.

### Interfaces produced by this plan

```go
package echconfig

type CipherSuite struct { KDFID uint16; AEADID uint16 }
// Config carries the validated metadata, never the bytes: Raw below is the list the
// parser was given, and every field here was read from a config's own declared
// length. A config is in a List only if all of them passed.
type Config struct { Version uint16; ConfigID uint8; KEMID uint16; PublicKey []byte; CipherSuites []CipherSuite; MaximumNameLength uint8; PublicName string }
type List struct { Configs []Config; Raw []byte }
// Parse returns a POINTER, and nil on every refusal, so a caller cannot read an
// empty list as a list with nothing wrong in it. There is no Validate method: the
// validation is the parse, and a caller that wanted to re-validate the bytes has
// them in Raw and a parser that will refuse them again.
func Parse(b []byte) (*List, error)

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

// The HTTPS surface, added by Task 3 and shipped in internal/dnsrewrite/https.go.
// It is here rather than only in the Task 3 amendment below because a Task 5
// implementer is most likely to miss an amendment 250 lines above their own
// section, and a caller that compiles against this block needs all of it.
func HTTPS(in HTTPSInput) (*dns.Msg, error)

type FailurePolicy int

const (
    FailClosed        FailurePolicy = iota // strict
    FallbackToOriginal                    // fallback
)

type HTTPSInput struct {
    Response *dns.Msg      // never modified; every parameter is read from a clone
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
carries `Refusal`. Task 2 shipped all of these.

**The canonical block above is the shipped shape, and it has been compiled against
it.** A throwaway package declared the block verbatim — one file per package, the
real imports — and a test in it compared every declaration with the package it
names: every function and method signature, every struct's fields by name, type and
tag, every constant's value, and each of the five state documents against the
block's own `Document` constraint. It is deleted, and it is not part of `make
verify`: a document that later plans are told to compile against needs checking
once, by a person, rather than permanently.

Two things that check cannot see, so a later editor must not treat a green run as
permission to stop reading:

- The seven sentinels are declared in the block by name and comment with no
  `errors.New` call, because that is how a reader wants them; the throwaway
  supplied throwaway values, so what was verified is the seven names, their
  `error` type, and their being distinct from one another.
- The `Document` constraint admits exactly those five documents only because
  `internal/statewatch/watcher.go` says so. Go exposes no reflection over a type
  set, so a sixth member in a copy of this block would satisfy the check.

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

**Interfaces (shipped).** `internal/dnsrewrite` exports, and this is the shape Task
5 compiles against. The block itself now lives in **Interfaces produced by this
plan** above, with the rest of that package's surface, so there is one copy of it to
be right; it is:

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

The canonical copy carries one correction to the text above it: `Response` is never
modified, but the parameters a synthesis inherits **are** read from it, out of a
`Copy()` of it. The line above said "never read for parameters", which is false and
would have been read as "a caller may hand this a response with no records in it and
still get a synthesis" — which is true, and for a different reason: what the
response carried is an *absence or a statement* the synthesis answers over, never an
authority for it.

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

### Amendments from Task 5

Task 5 shipped the plugin. Three things the plan did not say are now recorded here,
because each is a decision a later reader would otherwise have to rediscover, and
two of them are places where the shipped behaviour is narrower or wider than the
plan's own words.

**The Cloudflare range list is produced by this plan, not by a later one.** The
plan's ruling was that the same cached fetch that `update-lists` performs also
publishes a parsed `cloudflare-prefixes.txt` beside the envelope, with no second
network request. The shipped change is in `internal/candidate`, because that is
where the cached fetch is: `HTTPCloudflareSource.Candidates` is the one function
that reads the document, validates it, samples it and caches it, and the
`update-lists` command is about the China domain list rather than about Cloudflare.
So the list is published there, from the same document the run just accepted,
beside the same cache path, as `cloudflare-prefixes.txt` — one prefix per line,
masked, deduplicated, sorted, published through a temporary file and a rename with
the cache's own 0644 mode discipline. A run now writes **two** files under its
cache directory rather than one, which is why
`TestCloudflareCacheIsWrittenOnlyUnderTheInjectedPath` was amended: its property
(nothing outside the injected root) is unchanged and its expectation (one file) was
not. Cost if wrong: one more artifact for packaging to provision, exactly as the
ruling recorded.

**The AAAA-suppression path is entered only for a name this router has classified.**
The plan said Task 5 must reach `Address`'s AAAA arm only with a Cloudflare verdict
it already holds, and an AAAA answer carries no address the published IPv4 ranges
could be checked against — so the only evidence available is an A answer for that
name which the classifier accepted. The plugin therefore keeps a bounded record of
the terminal names it has classified as Cloudflare-served in the selector's current
generation (`cdnNames`), and the AAAA path is entered only for a name that record
holds, only under that generation, and only while the winner's proof window is open
— the same two conditions under which the A answer was rewritten, so the two
answers for one name always agree. A name that fell out of the bounded record, a
name whose classification was refused, and every name under a new generation or a
closed window keep every record they arrived with. This is state the plan did not
describe, and it is the one addition in Task 5 that a reviewer should look at
hardest: without it, either a CDN name's IPv6 answer keeps its addresses (a
half-applied suppression) or every domain's does not (a suppression with no
verdict behind it). Cost if wrong: a bounded amount of memory and one map lookup
per AAAA query.

**Suppressing an IPv6 answer requires the A answer to have been rewritten FIRST,
and a concurrent pair of queries can apply only the A half.** This is the outcome
users will see, so it is stated here rather than left to be discovered. A browser
asking for A and AAAA at the same time — the ordinary case, the one Happy Eyeballs
exists for — routinely has the IPv6 query processed first, and the plugin then has
no verdict to work from: the client is sent to the selected IPv4 and keeps the
upstream's real IPv6 addresses beside it. The direction of that miss is **no
suppression**, so the client holds exactly the IPv6 answer it would have had without
this router; the opposite miss, an IPv6 answer emptied on the strength of an A query
for a different generation or a closed proof window, is what the generation and
window checks rule out. The mechanism is forced rather than chosen — an IPv6 answer
carries no address for the published ranges to classify, so there is nothing the
plugin could inspect instead of the A answer it is waiting for — and the two halves
are pinned by one test that runs the pair in both orders.

**A fallback forced domain's A becomes the selected IPv4 only when its response is
Cloudflare-classified, and the spec says both things.** Spec §12.4 lists the
fallback arm's `A → 当前优选 IPv4` with no condition on it, while §10.1 item 3 admits
a response to the Cloudflare verdict only when every terminal address is inside the
published ranges. The two cannot both hold for a forced domain whose A answer is
not Cloudflare-served, and the code follows the narrower of them — the classification
— because §10.1 is the section that decides what may be rewritten at all, and
because installing a selected address into an answer belonging to some other network
is the failure the whole classification exists to prevent. This is recorded here so
nobody reads plan against spec and concludes the difference was a silent
re-interpretation: it is a deliberate choice between two spec sentences, and the
consequence is that a forced domain fronted by a CDN this router does not publish
ranges for keeps its upstream address and gets its ECHConfig anyway. The
per-hostname CloudFront arm is a separate authorisation and is not in question
here: a mapping installs the distribution's own proved address, not the global
selected IPv4.

**A per-hostname CloudFront mapping authorises the QUERY, and the addresses it
replaces are the ones at the end of the response's CNAME chain.** A distribution
reached through an alias is the ordinary shape of a per-hostname mapping, and
requiring the terminal to *be* the queried name would refuse every such setup,
which is the whole point of a mapping. The proof and the authorisation agree: the
health check proves a mapping against the queried name's own profile, and the
queried name is the name the operator configured. The guard that keeps it honest is
the published ranges, which must NOT say the response is Cloudflare-served — a
mapping is a distribution's address, and a Cloudflare address is not a
distribution's. A mapped name whose response is Cloudflare-served, at the end of a
chain or not, is refused and keeps the upstream's own answer.

**A missing force-ECH allowlist leaves the plugin serving with nothing forced, and
says so; a missing Cloudflare range list refuses to start.** The asymmetry is
deliberate, and it is a choice about what is inert. An absent allowlist claims no
domain the operator did not list, so the router is serving correctly with a safety
setting unset, and refusing to start would take a resolver offline over a file an
operator may not have created yet; the absence is reported once through the
watcher's reload handler, so an operator who believes they are forcing ECH for a
domain is told the list is not there. An absent or unreadable range list is the
other shape: it classifies every response as somebody else's, so every rewrite in
the router silently stops while the router looks healthy, and a router whose whole
selection feature is off is not serving.

**The ECH key is fetched independently of the address it is installed beside.** The
plugin asks the ECH source for a key on every force-ECH HTTPS query, including the
queries where the selector's proof window is closed and the address will be
refused. The reason is a refusal that would otherwise name the wrong thing: with
no key fetched, `dnsrewrite.HTTPS` refuses with `ErrNoECHConfig` before it reaches
the address check, so an operator reading the log would be told the ECH source is
broken when the selector is what failed. The cost is one query per source per key
lifetime while no address is available — the same query a healthy deployment makes
anyway — and the benefit is that the held key and `ech-state.json` stay current
across a selector outage. Cost if wrong: none; the key is a public HPKE key and the
query is on the listener the router already uses for every foreign query.

**`ech-state.json` is published on what changed, and the highest generation wins.**
Two rules the first cut got wrong, both about the document rather than the key. A
document written only when the status word changed froze after the first fetch,
because every successful refresh publishes `fresh`: the file went on describing the
first key's expiry — in the past — and its digest while the router served a newer
key, so an operator and `mosdns-cdnctl status` were shown a document about a key no
longer in service. The comparison is now against the whole of what the document says
about the key: its generation, which moves with the fetched, expiry and grace times
and with the digest, and the status, which one key changes on its own as it ages.
And two callers can be inside the write with different snapshots — the fetcher with
the key it just stored, a waiter with one it read before waiting — so the older one
must not end up on disk; the rule is the highest generation wins, which is exact
rather than a heuristic, because a generation comes from the provider's own counter
under its lock and only a stored key has one. The strict state writer would refuse
a rollback in any case, so the loser was safe; a refusal that logs a warning every
time is not a mechanism. Cost if wrong: one file write per refresh as well as per
transition, which is one write per key lifetime more than the first cut did.

**A caller that loses the ECH single-flight race gets the key the winner stored.**
The first cut returned an internal sentinel to a caller that had read an empty key
before the race, which turned the first concurrent pair of force-ECH HTTPS queries
after a boot into an intermittent SERVFAIL on a strict name — the key had been
fetched successfully a moment earlier. Every caller now re-reads the stored value
after a wait and decides from that; the sentinel surfaces only when there is still
nothing, and the loop is bounded at two attempts, each of which is a real fetch
rather than a spin. The same case one lifetime later — a caller past the grace
while another caller refreshes — is the same fix. Cost if wrong: a second query to
the source in the case where the first one failed, which is a case that is already a
failure.

### The `Paths` the renderer carries, and what each refusal is for

`internal/mosdnsconfig.Paths` grew four fields, and the distinction between them is
the whole of the refusals they carry:

| field | production value | checked for | why |
|---|---|---|---|
| `Selector` | `/var/lib/mosdns/runtime/cdn-selector.json` | empty, absolute, not under `/etc` | the optimizer and the health check rewrite it while the router runs; it is `optimizer.DefaultSelectorPath`, and a test ties the two together |
| `ForceECH` | `/etc/mosdns/force-ech-domains.txt` | empty, absolute **only** | nothing rewrites it while the router runs: an operator edits it and expects to find it beside the rest of the configuration |
| `ECHState` | `/var/lib/mosdns/runtime/ech-state.json` | empty, absolute, not under `/etc` | the rewriter publishes it; under a root-owned directory the write fails and a force-ECH name loses the record of the key it is holding |
| `CloudflarePrefixes` | `/var/lib/mosdns/lists/cloudflare-prefixes.txt` | empty, absolute, not under `/etc` | the list updater rewrites it; the list updater refuses a prefix list that is not under `/var/lib`, so rendering one anywhere else produces a document whose list will never be published |

`CloudflarePrefixes` is the **published prefix list**, beside
`candidate.DefaultCloudflareCachePath` and named
`candidate.DefaultCloudflarePrefixFileName`. It is not the API cache envelope: the
envelope is a JSON document with a schema, a URL and an etag, and the ranges inside
it are quoted strings in a nested object. A `cloudflare_cidr_file` naming it makes
the plugin **refuse to load** — a range list with no prefix in it classifies every
response as somebody else's, which stops every rewrite in the router while the router
looks healthy — and `TestTheRenderedConfigRefusesToLoadWithoutAPrefixList` proves that
on the real loader rather than assuming it, because a renderer pointing the plugin at
the envelope produces a document no installed router can start and only a test that
loads it would have said so.

**The plugin's `foreign_upstream` is the same checked value as the forward's
`upstreams[0].addr`.** Not a second literal, not a second field: one `Paths` entry,
resolved once by `checkForeignListener`, written into both places. So the two cannot
disagree, and the plugin's own refusal of a non-`tcp://` scheme is a second opinion on
a value this renderer has already refused for the forward: port 53, a hostname, a
path, credentials and a query are all refused before either line is written. The cost
of the coupling is that a deployment cannot fetch the ECH key somewhere other than
where it forwards, and that is deliberate — the ECH fetch exists to be the same
exchange the foreign branch makes, through the transport that cannot drop an answer.

### What the wire tests can and cannot observe about the cache

A strict force-ECH A/AAAA query is answered before `next` runs, so nothing
downstream is reached at all. From outside the process that is observable in exactly
two ways, and the case asserts both:

- **The upstream was not asked.** The foreign resolver's per-name and per-type counts
  do not move, and neither does its grand total — which also covers the ECH fetch,
  because that goes to the same listener.
- **The cache's answer was not used.** Both forced names are asked for *before* they
  are forced, so the cache holds a real, unexpired answer for both of them, and the
  strict queries are then answered with the plugin's own empty answer instead.

What is **not** observable from outside is whether the cache was *consulted* and
returned nothing, because the pinned mosdns cache plugin logs nothing per query at the
level this document renders. No test claims otherwise: the property the order buys is
stated as "a cached answer is not used", which is what a client can tell, and the
structural claim ("the rewriter is the first rule of `foreign_path`") is pinned by the
renderer test instead. The two together are the whole argument, and a rewriter moved
behind the cache fails both the structural test and
`TestARewriteAcrossASelectorGenerationLeavesTheCachedObjectAlone` — because the
`has_resp → accept` rule ends the branch on a cache hit, the plugin would then never
run for a strict name at all.

### Obligations a later task inherits

1. **`mosdnsconfig.Render` is not free of a populated `Paths`.** Every caller that
   builds a path set must now supply the four new paths or be refused, and the
   documents they name must exist: the plugin reads its policy and its range list at
   construction, so a rendered document naming a path nothing wrote is a document no
   real mosdns can start. `internal/mosdnsconfig`'s own `temporaryPaths` and
   `tests/integration`'s harness both write the five documents for this reason; a new
   caller must do the same or it is testing a document that would not load.
2. **The policy path now appears twice in the routing document.** Anything that
   derives an expectation from `configs/mosdns.yaml` by rewriting a path has to
   account for both occurrences: the generated header and the rewriter's
   `policy_file`. `cmd/mosdns-cdnctl`'s render test is the one place that did, and
   its amendment is recorded above.
3. **The rewriter is in the foreign branch, so a change to the foreign path's rule
   order is a change to a privacy property.** The three rules that follow the rewriter
   (`$foreign_cache`, the `has_resp` guard, `$foreign_forward`) are the cache-hit
   guard and the forward, and the first of them is now the only thing between a
   rewrite and a cache.
4. **The Cloudflare prefix list is a second artifact for packaging to provision**, as
   the ruling that created it already said. It is written by `internal/candidate` on
   every run of the Cloudflare fetch, beside the cache envelope, and the router
   refuses to start without it. An installation that provisions only
   `cloudflare-ips.json` does not start.
5. **`/etc/mosdns/force-ech-domains.txt` is now named by a generated document**, and
   `mosdns-cdnctl`'s default for the same file is an unexported constant in a `main`
   package. Nothing ties the two together at compile time; the only check is
   `TestTheCommittedConfigNamesThePathsTheOtherComponentsPublish`, which pins the
   literal this plan's own constraint fixes. If a later plan moves that file, both
   places have to move with it.

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
strict force + A/AAAA -> synthesize NOERROR with an empty Answer and NO SOA, do not call next
strict force + HTTPS   -> call next, use compatible upstream parameters when present, otherwise synthesize minimal h2,h3 ServiceMode
all other supported    -> call next, classify/mutate
unsupported qtype      -> call next unchanged
```

**No SOA, and that is the whole of the difference from a NODATA.** An SOA in the
authority section is a negative caching claim, and its SOA.MINIMUM is a TTL this
router would then be vouching for on a name it deliberately refused to resolve.
An empty answer with an empty authority section claims no lifetime, is recomputed
for free on every query, and cannot be cached against this router's word. The word
in this line was NODATA until the final review, which is the plan's own earlier
ruling being read as a label rather than as the claim it makes; the code and the
ruling agree with the line above.

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
- Modify: `tests/integration/routing_test.go` (the plugin is rendered into every configuration this suite starts)
- Modify: `cmd/mosdns-cdnctl/render_test.go` (the committed document now names the policy path twice)
- Modify: `configs/mosdns.yaml` (regenerated by the renderer, never by hand)
- Modify: `scripts/test-make-entrypoints.sh` (the `-count=1` assertion extended to `verify`)
- Modify: `Makefile`

**Interfaces:**
- Consumes: approved system paths and the plugin Args.
- Produces: final foreign sequence with rewrite wrapping cache and forward.

- [x] **Step 1: Update renderer tests first**

Assert foreign path order:

```text
cdn_rewrite -> foreign_cache -> foreign_forward
```

Assert `cdn_rewrite` is not in the domestic path and receives the policy file, selector, allowlist, ECH metadata, direct foreign upstream, and Cloudflare CIDR file. That direct foreign upstream is `tcp://127.0.0.1:15353`, the same loopback TCP listener the foreign forward uses: ECHConfig bytes are fetched from the same resolver through the same transport, and MOSDNS's stock UDP transport is measured re-sending unanswered queries and dropping answers, so an ECH fetch must not be the one place that uses it. The plugin loads AAAA suppression, ECH failure policy, and stale grace through `config.Load` so one policy file is authoritative.

- [x] **Step 2: Run renderer tests and verify failure**

```bash
go test ./internal/mosdnsconfig -v
```

Expected: FAIL because the plugin is not rendered. Observed: every new assertion
failed for that reason, and `TestCommittedMosdnsConfigIsExactlyTheRenderedDefault`
failed afterwards with the plugin rendered and the committed file not yet regenerated.

- [x] **Step 3: Update the renderer**

Insert `cdn_rewrite` as the first executable in `foreign_path`. Keep cache downstream so normal upstream responses are cached before the outer recursive plugin mutates a deep copy of the returned response. A cache-hit integration assertion must query again after changing selector generation and prove the second query returns the new IP without corrupting the first cached object.

- [x] **Step 4: Write integration wire tests**

Start local DNS and HTTPS upstreams. Query A/AAAA/HTTPS for Cloudflare, mixed CDN, and a CloudFront profile. Assert exact owner names, answer counts, selected IP, empty AAAA, ECH parameter, mandatory key, hints, AD bit, and RRSIG removal.

- [x] **Step 5: Add strict ECH integration cases**

Assert A/AAAA never reach either cache or upstream, valid HTTPS reaches only the foreign upstream, strict config failure returns SERVFAIL, and fallback mode returns an A answer when ECH is unavailable.

- [x] **Step 6: Run all verification**

```bash
go test ./internal/dnsclassify ./internal/dnsrewrite ./internal/echconfig ./internal/statewatch ./plugin/executable/cdn_rewrite -v
go test ./tests/integration -run 'TestRewrite|TestECH' -v
go test ./...
```

Expected: PASS. **This step's own commands were corrected rather than run as
written**: the `-run` filter matched a subset and carried no `-count=1`, so it is
replaced in the acceptance block above by the whole package, twice.

- [x] **Step 7: Commit**

```bash
git add internal/mosdnsconfig tests/integration/rewrite_test.go Makefile
git commit -m "test: prove CDN rewrite and ECH wire behavior"
```

The commit stages more than this line names: `tests/integration/routing_test.go`,
`cmd/mosdns-cdnctl/render_test.go`, `configs/mosdns.yaml` and
`scripts/test-make-entrypoints.sh` are all part of the same change, for the reasons
the File Map records.

---

## Plan Acceptance

Run the whole gate, which is what a merge should be measured by:

```bash
make verify
```

`verify` runs `test` (every unit suite with `-short`, plus the Python bridge and the
Make entry-point regression), then `test-integration`, then `verify-build-info`, then
`go vet`. The end-to-end suite is the part that cannot be replayed from a cache: it
runs with `-count=1`, which `scripts/test-make-entrypoints.sh` asserts for both
`test-integration` and the line `verify` plans for it.

To run one layer on its own, with the same flags the gate uses:

```bash
go test -mod=readonly -count=1 -timeout 300s \
  ./internal/echconfig ./internal/dnsclassify ./internal/dnsrewrite \
  ./internal/statewatch ./internal/state ./internal/candidate \
  ./internal/mosdnsconfig ./plugin/executable/cdn_rewrite ./plugin/executable/dhcp_forward

go test -mod=readonly -race -count=1 -timeout 300s \
  ./internal/echconfig ./internal/dnsclassify ./internal/dnsrewrite \
  ./internal/statewatch ./internal/candidate ./plugin/executable/cdn_rewrite

go test -mod=readonly -count=1 -timeout 300s ./tests/integration
```

**There is no `-run` filter here, and that is deliberate.** An earlier draft of this
block filtered the end-to-end package with `-run 'TestRewrite|TestECH'`, which matched
a subset of the cases and carried no `-count=1`, so a cached result could satisfy it
and the gate could be green without the wire cases ever having been asked. A filter is
only worth writing when it is anchored (`-run '^TestARewritten'`) and carries
`-count=1` beside it; the honest form is to run the package.

Expected:

- only validated CDN responses change;
- strict force-ECH A/AAAA never reach upstream;
- HTTPS strict/fallback behavior matches policy;
- modified responses never claim DNSSEC validation;
- no local DoH/CA/MITM component exists.
