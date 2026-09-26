package optimizer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/measure"
	"mosdns-router/internal/state"
)

// This file is the runner: the one thing in this project that publishes an
// address into cdn-selector.json, which the response rewriter then puts into
// every DNS answer. Everything here exists because of that, and the three
// properties the rest of the file is built around are these:
//
//   - The phases run in one order, and the order is the safety property. It is
//     collect, TCP, HTTPS identity, latency shortlist, bandwidth, score, final
//     proof. A candidate is proved before it is scored, and the winner is proved
//     again after scoring, immediately before it is written, under the control
//     lock. A candidate that reached the scorer without a proof would be scored,
//     and scored well, for an address that cannot serve the hostname: the scorer
//     deliberately holds neither identity gate, and this file is the caller the
//     two gates are written for.
//
//   - Nothing is written without the control lock, and the lock is not held
//     across the network I/O of a measurement run. A run holds the budget's own
//     lock around each persist and the control lock only for the
//     read-validate-increment-write of the selector and for the final proof in
//     front of it. No command writes a temporary file before it owns the lock.
//
//   - Nothing is written from a measurement that has not been accounted for.
//     HTTPMetrics.BodyBytes is summed before the error that came with it is
//     looked at, because a refused identity probe is exactly the case where
//     bytes were spent and nothing was published, and a settle goes through
//     Budget.Settle rather than Consume so a refusal is visible.

// The phase order, as the names the report carries its boundaries under. They
// are the words an operator reads and the ones a test compares against, so they
// are one list rather than seven strings spelled at the call sites.
const (
	PhaseCollect    = "collect"
	PhaseTCP        = "tcp"
	PhaseIdentity   = "identity"
	PhaseLatency    = "latency"
	PhaseBandwidth  = "bandwidth"
	PhaseScore      = "score"
	PhaseFinalProof = "final-proof"
)

// The documented phase order, in the order it runs. The runner walks it, and a
// test walks the same list to say that no probe of one kind ever arrived after a
// probe of a later one.
var documentedPhases = []string{
	PhaseCollect, PhaseTCP, PhaseIdentity, PhaseLatency, PhaseBandwidth, PhaseScore, PhaseFinalProof,
}

// The concurrency each phase is bounded by. They are package constants rather
// than options because they are not a deployment's to choose: a run that
// measured latency with unbounded parallelism would rank a link it had just
// saturated, and a run that transferred in parallel would report a speed no user
// would ever see. They are deliberately different, and the bandwidth one is the
// smallest, because the number the report publishes is a transfer rate.
//
// These are not what keeps the daily budget: every transfer reserves before it
// reads, so the budget is authoritative whatever these are. A slower run on a
// busy link is the cost.
const (
	connectConcurrency  = 8
	identityConcurrency = 4
	downloadConcurrency = 2

	// connectSamples is how many handshakes one connect measurement takes. It is
	// more than one because a single successful handshake carries no loss figure,
	// and the loss figure is one of the three terms the score is built from.
	connectSamples = 3
)

// FinalProofTimeout bounds the whole final-proof phase of an apply: every group,
// every profile, in one deadline.
//
// The reason it is a constant and not a multiple of the profile count is that the
// final proof runs under the control lock, so its duration *is* the time apply,
// pin and the health check are locked out. It is set just above the prober's own
// per-probe bound (prober.DefaultProbeTimeout, ten seconds) because a deadline
// below that would cut short a proof the host was still going to answer, and it is
// far below the shipped 120 second health interval so a health check cannot be
// starved by an apply. It does not grow with the number of configured profiles: a
// list long enough to overrun it is answered as far as it gets and then refused,
// which is the direction that costs an operator one report rather than a lock
// nobody can take.
const FinalProofTimeout = 15 * time.Second

// ProofConcurrency is how many of a subject's profile proofs run at once.
//
// It is high enough that a realistic profile list - the provider's representative
// domain and a handful of forced-ECH domains - is a single wave, and low enough
// that a long list is answered in bounded waves rather than all at once. The
// deadline above is what bounds the hold either way; this bounds how much of the
// host a single apply leans on.
//
// It is exported because it is a decision a second caller of the same walk has to
// share: the health check proves the addresses a selector has published over
// exactly these profiles, and a limit of its own would be a second number with the
// same meaning and no reason to be different.
const ProofConcurrency = 16

// The three refusals the runner adds, as named constants for the same reason the
// scorer's are: a report has to say which rule refused a candidate, and a rule
// that can only be recognised by its wording is a rule nobody can match on.
//
// These are the runner's and not the scorer's, because the scorer holds neither
// identity gate. It never sees an unproved candidate at all: the runner keeps
// such a candidate out of the group it scores, and gives it one of these.
const (
	// ReasonIdentityRefused is the refusal for a candidate the HTTPS identity
	// proof would not vouch for: a chain that is not for the profile's hostname,
	// a status the profile does not expect, a header it requires that is not
	// there, or a body that is not the document the profile names. It is the most
	// consequential line in a report, because a candidate refused here is exactly
	// the one that would otherwise have been published.
	ReasonIdentityRefused = "the HTTPS identity proof was refused"

	// ReasonNoProfile is the refusal for a candidate whose group has no identity
	// profile at all. Nothing proved it, so nothing may publish it, and the
	// difference between "refused" and "never asked" is the difference between a
	// misconfigured run and a broken address.
	ReasonNoProfile = "no identity profile names this group"

	// ReasonProfileInvalid is the refusal for a group whose profile is not one a
	// prober could hold to, which is reported before a socket is opened.
	ReasonProfileInvalid = "the identity profile for this group is not usable"

	// ReasonProfilePortsDiffer is the refusal for a global group whose profiles
	// name two different ports. One connect measurement has to be aimed at one
	// port, and a group that cannot say which would be measured at a port nothing
	// is served on.
	ReasonProfilePortsDiffer = "the identity profiles of this group name different ports"
)

// The two reasons a group produced no winner at all, as named constants for the
// same reason. They are different failures and a report has to tell them apart: a
// run where nothing was proved and a run where everything was over a ceiling are
// not the same incident, and an operator cannot act on one of them the way they
// can on the other.
const (
	// ReasonNoProvedCandidate is why a group with candidates but no winner
	// produced none: the identity phase proved nothing, so the scorer was never
	// given a candidate to score.
	ReasonNoProvedCandidate = "no candidate passed the HTTPS identity proof"

	// ReasonNoEligibleCandidate is why a group of proved candidates produced no
	// winner: every one of them was over a ceiling the scorer holds to, or
	// answered no handshake at all.
	ReasonNoEligibleCandidate = "no candidate came under the documented loss and latency ceilings"

	// ReasonBudgetExhaustedSwitch is the refusal recorded against every winner of
	// a run whose daily bandwidth budget ran out. The run measured no speed, so
	// the scores it produced are not comparable with yesterday's, and the current
	// winner is kept: a run that cannot afford to measure does not get to
	// change the address in service.
	ReasonBudgetExhaustedSwitch = "the daily bandwidth budget ran out, so this run measured no speed"
)

// ReportSchemaVersion is the shape of the document a run writes and an apply
// reads. A report of another version is refused rather than interpreted: it is
// the document a selector is published from, and a field this build ignored
// would be a decision this build never made.
const ReportSchemaVersion = 1

// MaxReportAge is the oldest a report may be and still be applied.
//
// A report is a record of what the network looked like at one moment, and the
// address it names can stop serving between that moment and the write. Two hours
// is long enough for an operator to read a report, decide, and apply it in the
// same working session, and short enough that a report left on a router overnight
// is refused rather than published. The refusal is not a dead end: `test --apply`
// re-runs the whole measurement in one invocation, so an operator who wants a
// fresh report is never stuck with yesterday's.
//
// The age is measured from generated_at, which is when the run *started*, so a
// report's own measurement time counts against it: a run that took an hour is
// applied with an hour and one minute less than the two it had left. That is the
// stricter direction, so it stands.
const MaxReportAge = 2 * time.Hour

// WinnerProofTTL is how long a published winner's proof is good for.
//
// The state package refuses a proof that does not follow the last success, and the
// window is refreshed by everything that actually re-proves the address in service:
// an apply, a pin, a health transition, and - every two minutes, on the shipped
// interval - a health check whose own pass succeeded. A health check's pass is the
// same certificate, Host and SNI proof an apply's final proof is, against the same
// profiles, so it is the same kind of evidence; that is why the check writes the
// window rather than only reporting on the address. Which means the only question
// this constant answers is how stale a proof may get before the rewriter stops
// trusting it. Five minutes covers the shipped 120 second interval with margin, and
// if an operator raises the interval this is the fail-closed direction: a shorter
// TTL than the interval needs only makes the address be re-proved more often.
const WinnerProofTTL = 5 * time.Minute

// The refusals an apply can return. They are named so a caller matches them with
// errors.Is rather than with their wording, and each names one thing that went
// wrong: an apply that failed for four different reasons has told an operator
// nothing it can act on.
var (
	// ErrInvalidReport reports a document that is not a report this build can
	// apply: an unknown field, a schema version it does not implement, a winner
	// that is not among the report's own candidates, or phase boundaries that do
	// not run in the documented order.
	ErrInvalidReport = errors.New("the report is not one this build can apply")

	// ErrConfigChanged reports that the report was measured under a different
	// policy document. Its shortlists and thresholds are not the ones in force, so
	// its decision is about a router that is not this one.
	ErrConfigChanged = errors.New("the report was measured under a different configuration")

	// ErrReportTooOld reports a report older than MaxReportAge, or one dated in the
	// future, which cannot be a record of anything that has happened.
	ErrReportTooOld = errors.New("the report is outside the age an apply accepts")

	// ErrSwitchNotAllowed reports a report whose winner is not the required
	// improvement over the address already in service, or whose recorded decision
	// disagrees with the one this configuration reaches from the same numbers. It is
	// a refusal of the whole apply, because it is a statement about the document
	// rather than about one group's address: a group whose own switch the gate
	// refuses keeps its mapping and is reported as kept, not refused.
	ErrSwitchNotAllowed = errors.New("the winner is not enough of an improvement over the incumbent")

	// ErrModeManual reports an automatic apply against a selector an operator has
	// pinned by hand. A manual address outranks an automatic result, so the apply
	// is refused rather than quietly unpinning by side effect.
	ErrModeManual = errors.New("the selector is pinned by hand; unpin before applying an automatic selection")

	// ErrControlLocked reports that another process holds the control lock. It is
	// a conflict rather than a failure: the caller is told at once and changes
	// nothing, which is the whole point of taking the lock at all.
	ErrControlLocked = errors.New("the control lock is held by another process")

	// ErrIdentityRefused reports that the final identity proof, run under the
	// control lock immediately before the write, would not vouch for the address.
	// It carries the same words as ReasonIdentityRefused, because it is the same
	// refusal: one is a field of a report and the other is what a caller matches.
	ErrIdentityRefused = errors.New(ReasonIdentityRefused)

	// ErrNoProfile reports that this configuration names no identity profile for
	// the address it was asked to publish, so there is nothing to prove it against.
	// The profiles come from the router's own configuration and never from the
	// report, so a report cannot choose what it is proved against.
	ErrNoProfile = errors.New("no identity profile names this address")

	// ErrNotPublishable reports an address a published rewrite target may not name:
	// a private, reserved, loopback, multicast or otherwise unusable address. It is
	// the candidate package's own rule, reached through the candidate package's own
	// call, so a pin cannot store an address a candidate could never be.
	ErrNotPublishable = errors.New("the address is not one a published rewrite target may name")

	// ErrProofTimeout reports that the final identity proof did not finish inside
	// FinalProofTimeout, which is a statement about this build's patience and not
	// about the host: a host that is merely slow is not a host that refused. The
	// refusal leaves the file as it was, and the report carries the bytes the
	// cut-short proof did read.
	ErrProofTimeout = errors.New("the final identity proof did not finish in time")

	// ErrNothingPinned reports an unpin of a selector that is not pinned: either
	// there is no selector document at all, or the mode is already automatic. Both
	// are a mistake rather than a change, and saying so is better than bumping the
	// generation for a decision nobody made.
	ErrNothingPinned = errors.New("the selector is not pinned by hand")
)

// The production runtime paths, as a name and a full path for each. The names
// are exported for the same reason DefaultBudgetName is: the runtime directory
// stays a parameter, so a test cannot be tempted to write to the production one.
const (
	// DefaultSelectorPathName is the document a winner is published into.
	DefaultSelectorPathName = "cdn-selector.json"

	// DefaultControlLockPathName is the lock every control operation serializes
	// on.
	DefaultControlLockPathName = "control.lock"

	// DefaultSelectorPath is where the production router keeps the address its
	// responses are rewritten to.
	DefaultSelectorPath = "/var/lib/mosdns/runtime/" + DefaultSelectorPathName

	// DefaultControlLockPath is where the production router keeps the lock the
	// router, its CLI and the timers serialize on.
	DefaultControlLockPath = "/var/lib/mosdns/runtime/" + DefaultControlLockPathName
)

// The default weights, as §11.4 of the design fixes them: 45 percent latency
// percentile, 45 percent bandwidth percentile, 10 percent the loss and jitter
// penalty. There is no policy field for them and this plan may not add one, so
// they are a documented default a caller may override through Options.
//
// DefaultWeights is the value the runner passes when Options.Weights is the zero
// value, because a zero weighting is not "no weighting": it normalizes to
// nothing, every score is zero, and SwitchAllowed refuses a zero score, so a
// runner built with a zero would measure everything and publish nothing.
func DefaultWeights() Weights {
	return Weights{Latency: 0.45, Bandwidth: 0.45, Stability: 0.10}
}

// Prober measures candidates. It is the prober package's own interface declared
// here over internal/measure's types, rather than imported, and the reason is
// structural: that package's in-package tests use *Budget, and Go forbids a
// package's test importing a package that imports it. internal/measure is the
// leaf that lets both spellings name one type, and the assertion in runner_test.go
// that the real prober satisfies this interface is what keeps the two honest.
type Prober interface {
	// TCP measures connect latency to an address and port.
	TCP(ctx context.Context, address netip.Addr, port uint16, samples int) (measure.TCPMetrics, error)
	// HTTPS proves that an address is serving a profile's hostname.
	HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (measure.HTTPMetrics, error)
	// Download measures how much an address delivers within a byte and a time
	// limit, reserving from budget before it opens a connection.
	Download(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile, maxBytes int64, maxDuration time.Duration, budget ByteBudget) (measure.DownloadMetrics, error)
}

// ByteBudget is the daily allowance a transfer reserves from. It is
// optimizer.Budget's own contract rather than the prober package's, for the same
// reason Prober is: internal/measure cannot carry an interface, and the two
// declarations have to be the same shape for *Budget to satisfy both.
//
// The narrowness has a cost a caller must know: the guarantee that a reservation
// settles only once lives in the concrete budget, not in this interface, because
// this interface has no way to report a refusal. The runner therefore never
// settles through it directly: it hands the prober a settlingBudget, which calls
// Budget.Settle and keeps the refusals for the report.
type ByteBudget interface {
	// Reserve charges up to requested bytes and returns the amount reserved, or an
	// error when the day cannot cover it.
	Reserve(requested int64) (int64, error)
	// Consume settles reserved with actual. It hands back the difference and never
	// more than the reservation.
	Consume(reserved, actual int64)
}

// Options are the paths and the clock a runner works through. Every one of them
// is a parameter rather than a constant because a test that wrote to
// /var/lib/mosdns would be writing to the production router's state, and because
// a run whose report is dated by an injectable clock is one whose age a test can
// hand-derive.
type Options struct {
	// BudgetPath is the daily bandwidth budget document. Required: a run that
	// cannot name it would measure transfers it cannot charge.
	BudgetPath string

	// SelectorPath is the document a winner is published into. Required.
	SelectorPath string

	// ControlLockPath is the lock every control operation serializes on. Required.
	ControlLockPath string

	// ConfigSHA256 is the SHA-256 of the exact policy document bytes as loaded.
	// Required, and it must be a digest: a report that cannot name the
	// configuration it measured under cannot be checked against one.
	ConfigSHA256 string

	// Location decides which local date a reservation belongs to. A nil value
	// means time.Local, which is what the production router wants.
	Location *time.Location

	// Now is the clock. A nil value means time.Now. It decides a report's date,
	// the budget's local date, and the age of a report an apply is reading, so
	// all three are one clock in production.
	Now func() time.Time

	// Weights are the three shares of the combined score. The zero value means
	// DefaultWeights, which is what a run with no policy weighting must use.
	Weights Weights

	// ProofTimeout bounds the final-proof phase of an apply. The zero value means
	// FinalProofTimeout, which is the production bound; it is a field so a test can
	// exercise the deadline without waiting fifteen seconds for it, and the
	// mechanism it covers - one deadline over the whole phase, profiles proved
	// concurrently under a limit - is the same either way.
	ProofTimeout time.Duration
}

// Runner measures candidates and publishes a winner. It is safe to use from more
// than one goroutine as long as two runs are not in flight over one budget
// document, which the budget's own lock turns into a refusal rather than a
// double spend.
type Runner struct {
	policy  config.Policy
	prober  Prober
	options Options
	params  Params
}

// NewRunner builds a runner for one policy and one prober.
//
// It returns an error because a runner with no budget path, no selector path, no
// control lock, or no configuration digest is a runner that cannot be checked
// and cannot be used, and the plan's two-argument form is not that. The counts
// are validated here, before any measurement: a non-positive latency_candidate_count,
// latency_top or bandwidth_top cannot select anything, and a caller that wired
// one of them to the wrong variable should learn it without spending the user's
// bandwidth to find out.
func NewRunner(policy config.Policy, prober Prober, options Options) (*Runner, error) {
	if prober == nil {
		return nil, errors.New("a runner needs a prober to measure with")
	}
	var missing []string
	for _, required := range []struct {
		name  string
		value string
	}{
		{"BudgetPath", options.BudgetPath},
		{"SelectorPath", options.SelectorPath},
		{"ControlLockPath", options.ControlLockPath},
		{"ConfigSHA256", options.ConfigSHA256},
	} {
		if strings.TrimSpace(required.value) == "" {
			missing = append(missing, required.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("a runner needs %s", strings.Join(missing, ", "))
	}
	if !isLowerHexDigest(options.ConfigSHA256) {
		return nil, fmt.Errorf("ConfigSHA256 must be a 64 character lowercase hex SHA-256, got %q", options.ConfigSHA256)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Location == nil {
		options.Location = time.Local
	}
	if options.Weights == (Weights{}) {
		options.Weights = DefaultWeights()
	}
	if options.ProofTimeout <= 0 {
		options.ProofTimeout = FinalProofTimeout
	}
	params := Params{
		LatencyCandidates: policy.CDN.LatencyCandidateCount,
		LatencyTop:        policy.CDN.Combined.LatencyTop,
		BandwidthTop:      policy.CDN.Combined.BandwidthTop,
		// The exclusion ceilings are the documented defaults, and this is the
		// caller their doc comment names. config.Policy has no field for either
		// and this plan may not add one, so the zero Limits - which means no
		// ceiling at all, and would measure and publish an address that dropped
		// 40 percent of its handshakes - is not reachable from here.
		Limits:  DefaultLimits(),
		Weights: options.Weights,
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	return &Runner{policy: policy, prober: prober, options: options, params: params}, nil
}

// Input is everything one run measures. The candidate sources are the caller's
// to gather, because they are the caller's to configure: a test hands over a
// fixed list, and production hands over what the Cloudflare API and the
// operator's files said.
type Input struct {
	// Cloudflare are the global candidates, from the official range list, the
	// user's own list, and the addresses this selector is already using. They are
	// partitioned by source inside the run, so one slice may carry all three.
	Cloudflare []candidate.Candidate

	// CloudflareProfiles are the hostnames a global candidate is proved against.
	// The design fixes what they are: the provider's representative domain and
	// every forced-ECH domain. A global candidate is eligible only if every one
	// of them accepts it, which is the strict direction and the same rule Pin
	// holds an address to.
	CloudflareProfiles []candidate.ProbeProfile

	// CloudFront are the per-hostname candidates, and CloudFrontRules are the
	// profiles they are proved against. A rule's own addresses are added to its
	// group, so a caller that supplies only the rules still measures them.
	CloudFront      []candidate.Candidate
	CloudFrontRules []candidate.CloudFrontProfile

	// LastGood is the selector as this run found it. Its winner and its fallback
	// are always measured again, so a daily reseed of the official ranges can
	// never leave the switch gate comparing against an address it cannot re-prove.
	LastGood state.Selector

	// Stale is candidate.CandidateSet.Stale: the official ranges could not be
	// refreshed and the last document this build accepted stood in for them. The
	// addresses are still the ones a run would have measured, but a report that
	// cannot say so is presenting yesterday's ranges as today's.
	Stale bool
}

// Outcome is what an apply did with one group, or with a whole report.
//
// It is per group because the decision is: a group that found an address clearing
// the switch gate is published, and a group that did not keeps the mapping it had.
// One verdict for the whole report would let a single group's ordinary "not better
// tonight" stop every other group from improving, for as long as the conditions
// lasted.
type Outcome string

const (
	// OutcomePublished means this group's winner was proved again and written into
	// the selector.
	OutcomePublished Outcome = "published"

	// OutcomeKept means nothing was written for this group and its current mapping
	// stands. The group's OutcomeReason says which of the reasons it was: the run
	// measured nothing publishable, or the winner was not enough of an improvement
	// over the address already in service.
	OutcomeKept Outcome = "kept"

	// OutcomeRefused means the apply stopped at one of its gates and wrote nothing
	// at all. It is a third answer rather than an empty one because an apply that
	// recorded what it had decided and was then refused has the most misleading
	// document to hand back: its group says "published" and a reader who does not
	// notice the error alongside it believes the address is in service. The
	// per-group outcomes say what the run decided; this says what the apply did, and
	// the two are only the same thing when the apply got as far as the write.
	OutcomeRefused Outcome = "refused"
)

// ReasonApplyRefused is a group's outcome reason when the apply was stopped at a
// gate. It is a run reason and not a run's, so it is named here beside the
// outcomes it explains: nothing was published for this group because the apply did
// not get as far as publishing anything.
const ReasonApplyRefused = "the apply refused, so nothing was published"

// Report is what a run produces: the measurement, the decision, and the two
// digests that let an apply check both. It is a document, so every field is
// JSON-tagged and every field is read back by an apply that refuses anything it
// does not recognize.
//
// The three things the brief names live per group rather than at the top level,
// because the winner is per group and the anti-leak rule is the whole reason: a
// CloudFront address is one hostname's answer, so a report that carried a single
// winner would either drop the CloudFront groups or publish one of them for
// everything. Groups[].Candidates is the brief's Candidates and Groups[].Winner
// is the brief's Winner; BudgetUsed and GeneratedAt are the run's.
type Report struct {
	// SchemaVersion is the shape of this document.
	SchemaVersion int `json:"schema_version"`
	// GeneratedAt is when the run finished collecting, in UTC. An apply refuses a
	// report older than MaxReportAge, and this is what it measures the age from.
	GeneratedAt time.Time `json:"generated_at"`
	// PolicySHA256 is the digest of the policy document the run measured under.
	PolicySHA256 string `json:"policy_sha256"`
	// ConfigSHA256 is the same digest, under the name the selector state carries
	// it as. Both are published because both are read by a different consumer,
	// and they are required to agree: a document whose two digests disagree was
	// assembled by something that did not measure it, and is refused.
	ConfigSHA256 string `json:"config_sha256"`
	// Stale is the run's candidate-set stale marker. See Input.Stale.
	Stale bool `json:"stale_candidates"`
	// Groups is one entry per group this run measured, ordered by provider and
	// then hostname so two runs over the same input produce the same document.
	Groups []GroupReport `json:"groups"`
	// IdentityBytes is every body byte every identity probe of this run read,
	// refused probes included. It is the run's one uncharged egress and the
	// budget cannot account for it, so the report does.
	IdentityBytes int64 `json:"identity_body_bytes"`
	// BudgetUsed is what the day's budget stands at after this run, which
	// includes spending by other runs today. A report that hid that would read
	// as though this run had spent the day.
	BudgetUsed int64 `json:"budget_used_bytes"`
	// BudgetLimit is the limit the day is held to, as the budget itself resolved
	// it: the smaller of the policy's cdn.bandwidth.daily_budget and the limit the
	// document already carries, so an operator who tightened the day by hand sees
	// the number their own document is enforcing. It comes from the same read as
	// BudgetUsed, because a total and a limit from two different reads can show
	// more room than the day has.
	BudgetLimit int64 `json:"budget_limit_bytes"`
	// BudgetRemaining is what is left of the day after this run, which is the
	// number an operator needs before spending it: with the shipped policy a
	// ten-candidate shortlist at 10 MiB each is exactly the 100 MiB day, so at
	// most one switching run fits - and a report-only run spends it just as an
	// applying one does. It is never negative, because an overspent day is
	// reported as fully spent rather than as room in the other direction.
	BudgetRemaining int64 `json:"budget_remaining_bytes"`
	// BudgetExhausted is true when the day could not pay for every transfer this
	// run wanted to make. The run is not a failure: the latency and identity
	// phases finish, the transfers that did not fit are skipped, and no winner
	// is allowed to switch.
	BudgetExhausted bool `json:"budget_exhausted"`
	// SettleRefusals is every settlement the budget refused, in the order it
	// happened. A refusal is a day charged for a transfer that was handed back,
	// or a second settle of one reservation, and it is exactly what Consume
	// cannot report and Settle can.
	SettleRefusals []string `json:"settle_refusals,omitempty"`
	// SkippedRetained names every address of the selector this run could not
	// measure, and why. A winner this build cannot even take a candidate for is
	// a winner the operator has to know about.
	SkippedRetained []string `json:"skipped_retained,omitempty"`
	// Phases is when each phase of the run started and ended, each boundary read
	// from the clock where the phase happened, so the document is an account of how
	// long each phase took as well as of the order they ran in. It is corroboration
	// and not the proof of the order: the proof is the order the runner called the
	// prober in, which a clock cannot show. An apply reads the boundaries as part of
	// validating the document.
	Phases PhaseTimes `json:"phases"`
	// FinalProofPassed is true once the winner has been proved again under the
	// control lock. A report read back from disk never has it, which is exactly
	// why apply has to run the proof itself.
	FinalProofPassed bool `json:"final_proof_passed"`
	// ProofedAt is when that second proof completed.
	ProofedAt time.Time `json:"proofed_at,omitzero"`
	// Outcome is what the apply did with the report as a whole: published if any
	// group was, kept if every group kept its mapping. It is empty in a report that
	// has not been applied, and it is the answer to "did this run change anything"
	// without reading every group.
	Outcome Outcome `json:"outcome,omitempty"`
}

// GroupReport is one group's whole measurement and decision. A run may hold more
// than one, and each is scored on its own: nothing here compares a CloudFront
// hostname's addresses with a global one.
type GroupReport struct {
	// Group is the same fact as Provider and Hostname below, kept as the named
	// type so a caller can render or compare it. It is not decoded from the
	// document, because GroupKey carries no JSON shape and two spellings of one
	// field on a document is one too many; ReadReport rebuilds it.
	Group GroupKey `json:"-"`
	// Provider is cloudflare or cloudfront.
	Provider string `json:"provider"`
	// Hostname is the CloudFront profile hostname, and empty for the global group.
	Hostname string `json:"hostname,omitempty"`
	// Candidates is every candidate of the group in the order the run collected
	// them, each with what was measured of it, whether it was eligible, its score
	// and, where it was not, the named rule that refused it.
	Candidates []ReportCandidate `json:"candidates"`
	// Winner is the group's best scored candidate, and is absent when the group
	// produced none.
	Winner *ReportWinner `json:"winner,omitempty"`
	// NoWinner is why the group produced none, and is empty when it did.
	NoWinner string `json:"no_winner_reason,omitempty"`
	// P10BytesPerSecond is the scored set's tenth-percentile transfer speed, the
	// lower tail the scorer exports for a report. It is the population the speed
	// rank is taken over, not the whole group: a shortlist candidate that never
	// entered the comparison has no say in the floor of the set that did.
	P10BytesPerSecond float64 `json:"p10_bytes_per_second"`
	// Outcome is what an apply did with this group, and OutcomeReason why. Both are
	// empty in a report that has not been applied.
	Outcome Outcome `json:"outcome,omitempty"`
	// OutcomeReason is the named reason a group was kept rather than published:
	// which group measured nothing publishable, or which winner was not enough of
	// an improvement. A published group leaves it empty, because the switch
	// decision's own reason already covers the one case that has one.
	OutcomeReason string `json:"outcome_reason,omitempty"`
}

// ReportCandidate is one candidate as a report states it. Every measurement is
// a number the run read, and Eligible and Reason together say whether it took
// part: a report that lists twelve candidates and says nothing about the two
// that lost is a report nobody can act on.
type ReportCandidate struct {
	Provider string `json:"provider"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	// Source is the channel that named the address: cloudflare, cloudfront, user
	// or retained. It records provenance, not ownership.
	Source         string  `json:"source"`
	Samples        int     `json:"samples"`
	P50MS          float64 `json:"p50_ms"`
	P95MS          float64 `json:"p95_ms"`
	JitterMS       float64 `json:"jitter_ms"`
	Loss           float64 `json:"loss"`
	HTTPStatus     int     `json:"http_status,omitempty"`
	TLSMS          float64 `json:"tls_ms,omitempty"`
	TTFBMS         float64 `json:"ttfb_ms,omitempty"`
	TotalMS        float64 `json:"total_ms,omitempty"`
	Colocation     string  `json:"colocation,omitempty"`
	IdentityBytes  int64   `json:"identity_body_bytes"`
	DownloadBytes  int64   `json:"download_bytes"`
	BytesPerSecond float64 `json:"bytes_per_second,omitempty"`
	// Score is the combined rank score, a report figure. No ordering decision
	// reads it; the integer behind it is what ordered the group.
	Score    float64 `json:"score,omitempty"`
	Eligible bool    `json:"eligible"`
	// Reason is the named refusal for a candidate that did not take part.
	Reason string `json:"reason,omitempty"`
	// Detail is what the probe said when it refused this candidate, so a report
	// says which host refused it and not only that something did. It is never an
	// input to any decision: apply proves the winner again against the live
	// profiles.
	Detail string `json:"detail,omitempty"`
}

// ReportWinner is the group's decision: which address, what it scored, and
// whether it is allowed to take the place of the one already in service.
type ReportWinner struct {
	IP     string `json:"ip"`
	Source string `json:"source"`
	// Score is the winner's combined score, the number the switch gate reads.
	Score float64 `json:"score"`
	// CurrentIP is the address this group had in service when the run started,
	// and is empty for a group that had none.
	CurrentIP string `json:"current_ip,omitempty"`
	// CurrentScore is the incumbent's score in this run, and zero when the
	// incumbent is not in this report or was not scored. A zero is the
	// empty-winner case SwitchAllowed documents: there is no measured incumbent
	// to beat.
	CurrentScore float64 `json:"current_score"`
	// SwitchAllowed is the scoring half of the switch gate, decided here so an
	// operator can see it. Apply recomputes it and refuses a report that
	// disagrees.
	SwitchAllowed bool `json:"switch_allowed"`
	// SwitchRefusal says why it was not, and is empty when it was.
	SwitchRefusal string `json:"switch_refusal,omitempty"`
}

// PhaseBound is one phase's start and end. A phase that never ran carries two
// zero times, which is how a partial report says where it stopped.
type PhaseBound struct {
	StartedAt time.Time `json:"started_at,omitzero"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
}

// PhaseTimes is the run's own account of its order, one entry per documented
// phase, each boundary a reading of the clock taken where the phase happened. The
// seven phases run in the order the fields are declared, and a report whose stamps
// are not in that order is refused: a run that claims to have measured speed before
// it proved identity is describing something it did not do.
//
// A phase that never ran carries two zero times, which is how a partial report says
// where it stopped. The stamps order the phases that were recorded; they cannot
// show that a phase happened, which is what the runner's own call order is for.
type PhaseTimes struct {
	Collect    PhaseBound `json:"collect"`
	TCP        PhaseBound `json:"tcp"`
	Identity   PhaseBound `json:"identity"`
	Latency    PhaseBound `json:"latency"`
	Bandwidth  PhaseBound `json:"bandwidth"`
	Score      PhaseBound `json:"score"`
	FinalProof PhaseBound `json:"final_proof"`
}

// sequence is the phase boundaries in the order they ran, which is the order the
// struct declares them.
func (p PhaseTimes) sequence() []PhaseBound {
	return []PhaseBound{p.Collect, p.TCP, p.Identity, p.Latency, p.Bandwidth, p.Score, p.FinalProof}
}

// Validate reports whether this document is a report this build can apply. It is
// the whole of what stands between a file on disk and a published address, so
// every field it checks is one whose value could change which address the
// rewriter hands to a user:
//
//   - the two digests are present, well formed, and equal, because a document
//     whose own two accountings disagree was assembled by something that did not
//     measure it;
//   - the report is dated, because its age is measured from that and an undated
//     document is not evidence about any moment;
//   - the first six phase boundaries are present and in the documented order,
//     because a report claiming to have measured speed before it proved identity
//     is describing something it did not do. The final proof's boundaries are
//     absent from any report read back from disk, which is why an apply runs the
//     proof itself rather than trusting the field;
//   - every group's key is one group, and every candidate in it is a candidate
//     this build could have probed: a public IPv4 address, a provider that is one
//     of the two, a hostname that belongs to that provider, and a source token;
//   - a group's winner is one of that group's own candidates, is marked eligible,
//     and has a score. A winner that is not a candidate this report measured is
//     not a measurement, and publishing it would be publishing an address no
//     probe in this document ever looked at.
func (r Report) Validate() error {
	if r.SchemaVersion != ReportSchemaVersion {
		return fmt.Errorf("schema_version must be %d, got %d", ReportSchemaVersion, r.SchemaVersion)
	}
	if r.GeneratedAt.IsZero() {
		return errors.New("generated_at must record when the run measured")
	}
	if !isLowerHexDigest(r.PolicySHA256) || !isLowerHexDigest(r.ConfigSHA256) {
		return errors.New("policy_sha256 and config_sha256 must both be a 64 character lowercase hex SHA-256")
	}
	if r.PolicySHA256 != r.ConfigSHA256 {
		return fmt.Errorf("the report carries policy digest %s and config digest %s, which are two accounts of one configuration and do not agree", r.PolicySHA256, r.ConfigSHA256)
	}
	if r.IdentityBytes < 0 || r.BudgetUsed < 0 || r.BudgetLimit < 0 || r.BudgetRemaining < 0 {
		return errors.New("identity_body_bytes, budget_used_bytes, budget_limit_bytes and budget_remaining_bytes must not be negative")
	}
	if err := validatePhases(r.Phases); err != nil {
		return err
	}
	if err := r.validateOutcomes(); err != nil {
		return err
	}
	if len(r.Groups) == 0 {
		return errors.New("the report holds no group, so it measured nothing")
	}
	for index := range r.Groups {
		if err := r.Groups[index].validate(); err != nil {
			return fmt.Errorf("groups[%d]: %w", index, err)
		}
	}
	return nil
}

// validateOutcomes is the coherence of an applied report's decisions, checked
// where it is read rather than trusted.
//
// A report straight from a run carries no outcomes at all, and that is the common
// case: the apply is what fills them in. A report that does carry them was applied
// once, and re-applying it means these fields have to describe the same document -
// so a kept group has to say why, and the overall outcome has to be the aggregate
// of the groups' rather than a second opinion about them.
func (r Report) validateOutcomes() error {
	published := 0
	recorded := false
	for index := range r.Groups {
		switch r.Groups[index].Outcome {
		case "":
			if r.Groups[index].OutcomeReason != "" {
				return fmt.Errorf("groups[%d]: a group with no outcome carries an outcome reason %q", index, r.Groups[index].OutcomeReason)
			}
			continue
		case OutcomePublished:
			published++
		case OutcomeKept:
			if r.Groups[index].OutcomeReason == "" {
				return fmt.Errorf("groups[%d]: a kept group must say why it kept its mapping", index)
			}
		default:
			return fmt.Errorf("groups[%d]: outcome must be %q or %q, got %q", index, OutcomePublished, OutcomeKept, r.Groups[index].Outcome)
		}
		recorded = true
	}
	switch r.Outcome {
	case "":
		if recorded {
			return errors.New("the report records a decision for a group and no outcome for the report")
		}
	case OutcomePublished:
		if !recorded {
			return errors.New("the report claims it published and records no group's decision")
		}
		if published == 0 {
			return errors.New("the report claims it published and every group kept its mapping")
		}
	case OutcomeKept:
		if published != 0 {
			return errors.New("the report claims it kept everything while a group was published")
		}
	case OutcomeRefused:
		// The apply stopped at a gate, so nothing reached the file. A group that
		// claims a publication here is the mislabel this outcome exists to prevent,
		// and a hand-edited document saying both is refused rather than believed.
		if published != 0 {
			return errors.New("the report claims the apply refused while a group says it was published")
		}
	default:
		return fmt.Errorf("outcome must be %q, %q or %q, got %q", OutcomePublished, OutcomeKept, OutcomeRefused, r.Outcome)
	}
	return nil
}

// validate is one group's own rules, and the winner's membership of the group's
// own candidate list.
func (g *GroupReport) validate() error {
	switch candidate.Provider(g.Provider) {
	case candidate.ProviderCloudflare:
		if g.Hostname != "" {
			return fmt.Errorf("a %s group must not carry the hostname %q", candidate.ProviderCloudflare, g.Hostname)
		}
	case candidate.ProviderCloudFront:
		if g.Hostname == "" {
			return fmt.Errorf("a %s group must name the hostname it is for", candidate.ProviderCloudFront)
		}
		// The hostname is held to the candidate package's own rule, reached through
		// the only exported way to reach it: a profile built around the name. The
		// state package holds it to the same rule when the name becomes a key of the
		// published mapping, so this is the earlier of the two refusals rather than
		// a second rule.
		probe := candidate.ProbeProfile{
			Hostname:       g.Hostname,
			URL:            "https://" + g.Hostname + "/",
			Method:         http.MethodGet,
			Port:           443,
			ExpectedStatus: []int{200},
		}
		if err := (candidate.CloudFrontProfile{Profile: probe}).Validate(); err != nil {
			return fmt.Errorf("hostname %q cannot be published: %v", g.Hostname, err)
		}
	default:
		return fmt.Errorf("provider must be %q or %q, got %q", candidate.ProviderCloudflare, candidate.ProviderCloudFront, g.Provider)
	}
	if len(g.Candidates) == 0 {
		return errors.New("the group holds no candidate, so nothing was measured for it")
	}
	// Note on a gap that is not exploitable: a candidate entry carries its own
	// hostname and this validation holds each entry to the rules for the provider
	// and hostname *it* names, without comparing that hostname to the one the group
	// it is listed under. It costs nothing, because neither the published key nor
	// the final proof reads the entry's hostname - the group's is what is written and
	// what is proved - so a hand-edited entry with a foreign hostname changes no
	// decision. It is named here rather than left for a reader to wonder.
	for index, entry := range g.Candidates {
		subject := candidate.Candidate{
			Provider: candidate.Provider(entry.Provider),
			IP:       parseRetained(entry.IP),
			Source:   entry.Source,
			Hostname: entry.Hostname,
		}
		if err := subject.Validate(); err != nil {
			return fmt.Errorf("candidates[%d]: %w", index, err)
		}
		if entry.IdentityBytes < 0 || entry.DownloadBytes < 0 {
			return fmt.Errorf("candidates[%d]: a byte count must not be negative", index)
		}
	}
	switch {
	case g.Winner == nil && g.NoWinner == "":
		return errors.New("the group named no winner and no reason for it")
	case g.Winner != nil && g.NoWinner != "":
		return fmt.Errorf("the group names a winner and %q as its no-winner reason", g.NoWinner)
	case g.Winner == nil:
		return nil
	}
	for _, entry := range g.Candidates {
		if entry.IP != g.Winner.IP {
			continue
		}
		if !entry.Eligible {
			return fmt.Errorf("the winner %s is a candidate this report marks ineligible", entry.IP)
		}
		if entry.Score <= 0 {
			return fmt.Errorf("the winner %s has the score %g, and a report may not publish a candidate that could not be scored", entry.IP, entry.Score)
		}
		return nil
	}
	return fmt.Errorf("the winner %s is not one of this group's own candidates, so no probe in this report measured it", g.Winner.IP)
}

// validatePhases is the phase order a report claims, and it is checked here
// because it is the property the whole design rests on: an apply that read a
// report whose phases were out of order would be publishing from a measurement
// that did not happen in that order.
//
// The first six phases are required, because a report that measured anything has
// all six. The seventh - the final proof - is not, and that asymmetry is the
// point: the proof is run by the apply, under the control lock, immediately before
// the write, so no report read back from disk has it. A report that does carry it
// is one whose own apply has already run, and its boundaries have to follow the
// score phase like any other.
func validatePhases(phases PhaseTimes) error {
	bounds := phases.sequence()
	for index, bound := range bounds[:len(bounds)-1] {
		if bound.StartedAt.IsZero() || bound.EndedAt.IsZero() {
			return fmt.Errorf("the %s phase has no recorded boundaries", documentedPhases[index])
		}
		if bound.EndedAt.Before(bound.StartedAt) {
			return fmt.Errorf("the %s phase ends before it starts", documentedPhases[index])
		}
		if index > 0 && bound.StartedAt.Before(bounds[index-1].EndedAt) {
			return fmt.Errorf("the %s phase starts before the %s phase ends", documentedPhases[index], documentedPhases[index-1])
		}
	}
	final := bounds[len(bounds)-1]
	if final.StartedAt.IsZero() && final.EndedAt.IsZero() {
		return nil
	}
	if final.StartedAt.IsZero() || final.EndedAt.IsZero() {
		return fmt.Errorf("the %s phase has one boundary and not the other", documentedPhases[len(bounds)-1])
	}
	if final.EndedAt.Before(final.StartedAt) {
		return fmt.Errorf("the %s phase ends before it starts", documentedPhases[len(bounds)-1])
	}
	if final.StartedAt.Before(bounds[len(bounds)-2].EndedAt) {
		return fmt.Errorf("the %s phase starts before the %s phase ends", documentedPhases[len(bounds)-1], documentedPhases[len(bounds)-2])
	}
	return nil
}

// ReadReport reads a report document and refuses anything it does not fully
// understand: an unknown field, a second document behind the first, and every
// inconsistency Validate names.
//
// The strictness is the requirement, not a nicety. This document is what an
// apply publishes from, so a field this build ignored would be a decision this
// build never made, and a permissive decoder is how that happens: a report
// written by a newer build would be read by an older one, quietly, with half its
// fields missing and the rest interpreted as something they are not.
func ReadReport(path string) (Report, error) {
	report := Report{}
	file, err := os.Open(path)
	if err != nil {
		return report, fmt.Errorf("%s: open the report: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		// A field this build does not know, a value of the wrong shape, and a
		// truncated document are all the same failure: this document is not one this
		// build can apply. They are wrapped in ErrInvalidReport so a caller matches
		// one error for every way a report can be inapplicable.
		return Report{}, fmt.Errorf("%s: %w: decode the report: %v", path, ErrInvalidReport, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Report{}, fmt.Errorf("%s: %w: the report carries more than one document", path, ErrInvalidReport)
	}
	// The named group key is rebuilt from the two fields it is made of, because it
	// is the same fact as a value an operator reads and it carries no JSON shape.
	for index := range report.Groups {
		report.Groups[index].Group = GroupKey{Provider: candidate.Provider(report.Groups[index].Provider), Hostname: report.Groups[index].Hostname}
	}
	if err := report.Validate(); err != nil {
		return Report{}, fmt.Errorf("%s: %w: %v", path, ErrInvalidReport, err)
	}
	return report, nil
}

// WriteReport writes a report document through a same-directory temporary file
// and a rename, so a reader either sees the whole document or the one before it.
//
// The temporary file is written without the control lock, and that is deliberate
// where it would not be for the selector: the control lock exists to serialise
// mutations of the state the router reads, this file is the output of a command
// rather than state anything reads, and no reader in this project ever opens a
// report path. Taking the lock here would mean a report-only run - which is the
// default and the one an operator runs to look before leaping - could not run
// while a pin or a health check was in flight. The temporary file's name says
// what it is, so it can never be mistaken for a state temporary either.
func WriteReport(path string, report Report) (err error) {
	if strings.TrimSpace(path) == "" {
		return errors.New("a report needs a path to be written to")
	}
	if err := report.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReport, err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("%s: create the report directory: %w", path, err)
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".report.tmp")
	if err != nil {
		return fmt.Errorf("%s: create the report temporary file: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporaryPath == "" {
			return
		}
		_ = temporary.Close()
		if removeErr := os.Remove(temporaryPath); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("%s: remove the report temporary file: %w", path, removeErr))
		}
	}()
	if err := temporary.Chmod(0o640); err != nil {
		return fmt.Errorf("%s: set the report mode: %w", path, err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("%s: encode the report: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("%s: sync the report: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		temporaryPath = ""
		return fmt.Errorf("%s: close the report: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("%s: publish the report: %w", path, err)
	}
	temporaryPath = ""
	// The rename has to reach the disk as well, or a power cut can leave the name
	// pointing at nothing.
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("%s: open the report directory: %w", path, err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("%s: sync the report directory: %w", path, err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("%s: close the report directory: %w", path, err)
	}
	return nil
}

// PolicyDigest is the SHA-256 of the exact policy document bytes as loaded, in
// the lowercase hex the selector state accepts.
//
// It takes the bytes rather than a path on purpose. The digest is what says a
// report and an apply are talking about the same configuration, and reading the
// document twice - once to hash it and once to decode it - leaves a window in
// which the two disagree. A caller that reads the document once, hashes it with
// this, and hands the same content to the policy loader is the caller whose
// digest describes the policy it loaded.
func PolicyDigest(document []byte) string {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])
}

// Apply publishes a report's winners into the selector, and it is the only path
// in this project that writes that file.
//
// The order of the six steps below is the whole of the safety argument, and each
// one is a gate that can refuse:
//
//  1. the document itself, strictly decoded and validated;
//  2. the configuration digest, which has to be the one this router is running;
//  3. the report's age, against MaxReportAge;
//  4. the control lock, taken before anything is read or written;
//  5. the current selector, read under the lock, with a manual pin refusing the
//     apply outright;
//  6. the final identity proof for every winner, under the lock, immediately
//     before the write, against the profiles this configuration names rather than
//     any the report carries.
//
// Only then is a temporary file written, and it is written by
// state.WriteJSONAtomic under the lock that is still held. Every refusal returns
// before step 6 or from it, so the file is left exactly as it was found: there is
// no path through this function that changes the address in service without
// having proved it twice.
//
// The proof inside step 6 is network I/O under the control lock, which is the one
// place this project does that, and it is a deliberate exception rather than an
// oversight. The proof has to be immediately before the write - an address proved
// and then written after a pause is an address proved at some other time - and it
// is bounded by the prober's own probe timeout, so the lock is held for seconds
// rather than for the minutes a measurement run takes. That is also why a run
// itself never takes this lock: it would block apply, pin and the health timer
// behind a download.
//
// The returned selector is what this call wrote, and the zero selector means it
// wrote nothing: an apply in which every group kept its mapping succeeds, returns
// the zero selector, and returns a report whose Outcome is OutcomeKept. Handing
// back the selector as it stands in that case would be indistinguishable from a
// publication to a caller that prints what it was given - and a timer reading
// "applied: <ip>" off a night the file was not touched records a publication that
// never happened. A caller that wants the selector either way reads it from
// Options.SelectorPath.
//
// The zero selector on its own does not say which of the two happened, and the
// error is what tells them apart; the report's Outcome is the second witness, so a
// caller that has only the report can still tell a refusal from a no-op.
func (r *Runner) Apply(ctx context.Context, report Report, profiles Profiles) (applied Report, published state.Selector, err error) {
	// What the apply did is not known until the write, and the report it hands back
	// says so. A report's own outcome is whatever it carried on the way in - empty
	// for a run's report, and *published* for one an apply wrote out and an operator
	// is applying a second time - so an error returning that claim unchanged would
	// report a publication for an apply that published nothing. The defer takes it
	// back, on every error path, including the gates before the per-group outcomes
	// are recorded at all.
	defer func() {
		if err == nil {
			return
		}
		applied.Outcome = OutcomeRefused
		published = state.Selector{}
		// Per group, the decision the run reached is left standing - it is what the
		// group entries are for, and what an operator reads to find out which address
		// was about to go into service - but a group that was about to be published
		// did not get published, and a reader who missed the error line beside the
		// outcome would be told otherwise. "kept", with the refusal as its reason, is
		// the honest record: nothing was written for that group either way.
		for index := range applied.Groups {
			if applied.Groups[index].Outcome != OutcomePublished {
				continue
			}
			applied.Groups[index].Outcome = OutcomeKept
			applied.Groups[index].OutcomeReason = ReasonApplyRefused
		}
	}()
	if err := report.Validate(); err != nil {
		return report, state.Selector{}, fmt.Errorf("%w: %v", ErrInvalidReport, err)
	}
	if report.ConfigSHA256 != r.options.ConfigSHA256 {
		return report, state.Selector{}, fmt.Errorf("%w: the report carries %s and this router is running %s", ErrConfigChanged, report.ConfigSHA256, r.options.ConfigSHA256)
	}
	if age := r.now().Sub(report.GeneratedAt); age > MaxReportAge || age < 0 {
		return report, state.Selector{}, fmt.Errorf("%w: the report is dated %s, which is %s from now, and the limit is %s", ErrReportTooOld, report.GeneratedAt.Format(time.RFC3339), age, MaxReportAge)
	}
	// The named err is assigned rather than shadowed from here on: the deferred
	// refusal above reads it, and a local of the same name would be a second value
	// with a job already done.
	var decisions []groupDecision
	if decisions, err = report.decisions(r.policy.CDN.SwitchImprovementPercent); err != nil {
		return report, state.Selector{}, err
	}
	// Every group's own outcome is recorded in the report before anything is
	// written, so a refusal below still leaves a document that says which group was
	// being published and which was keeping its mapping. The report is the record;
	// the decision's own copy of the group is not written to, so there is no second
	// version of the outcome that could disagree with the first.
	publishedAnywhere := false
	for index := range decisions {
		if decisions[index].published {
			report.Groups[index].Outcome = OutcomePublished
			publishedAnywhere = true
			continue
		}
		report.Groups[index].Outcome = OutcomeKept
		report.Groups[index].OutcomeReason = decisions[index].reason
	}
	if publishedAnywhere {
		report.Outcome = OutcomePublished
	} else {
		report.Outcome = OutcomeKept
	}

	var lock *filelock.Lock
	if lock, err = filelock.Acquire(r.options.ControlLockPath); err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			return report, state.Selector{}, fmt.Errorf("%s: %w", r.options.ControlLockPath, ErrControlLocked)
		}
		return report, state.Selector{}, err
	}
	defer func() { _ = lock.Close() }()

	var current state.Selector
	if current, err = r.currentSelector(); err != nil {
		return report, state.Selector{}, err
	}
	// A pinned address is the operator's decision. Publishing an automatic result
	// over it would unpin by side effect, and the operator would find out from a
	// report rather than from the pin they wrote.
	if current.Mode == "manual" {
		return report, state.Selector{}, fmt.Errorf("%w: %s is pinned to %s", ErrModeManual, r.options.SelectorPath, current.WinnerIP)
	}
	if !publishedAnywhere {
		// Every group kept its mapping, so there is nothing to write: no generation
		// move for a run that changed nothing, and no refreshed proof for a winner
		// this apply did not touch. The zero selector is what says so - see the
		// note on the return value above - and the report's OutcomeKept is the
		// other half of the same fact.
		return report, state.Selector{}, nil
	}

	// The final proof, for every published group, under the lock, before the write.
	// One deadline covers the whole phase rather than one per group, so the hold is
	// bounded by FinalProofTimeout whatever the number of groups is; a per-group
	// deadline would make it a multiple of the group count again. A group that keeps
	// its mapping is not proved, because nothing of it is being published and a proof
	// is the cost of a publish.
	report.Phases.FinalProof.StartedAt = r.now()
	proof, cancelProof := context.WithTimeout(ctx, r.options.ProofTimeout)
	proved := make([]groupDecision, 0, len(decisions))
	for _, decision := range decisions {
		if !decision.published {
			continue
		}
		metrics, err := r.proveAddress(proof, decision.winner, profiles)
		// The bytes a cut-short proof spent are accounted for whether or not it
		// answered: they crossed the network, and the report is the only place that
		// can say so.
		report.IdentityBytes += metrics.BodyBytes
		if err != nil {
			report.Phases.FinalProof.EndedAt = r.now()
			cancelProof()
			return report, state.Selector{}, err
		}
		proved = append(proved, decision)
	}
	cancelProof()
	report.Phases.FinalProof.EndedAt = r.now()
	report.FinalProofPassed = true
	report.ProofedAt = report.Phases.FinalProof.EndedAt

	published = current
	published.SchemaVersion = state.SchemaVersion
	published.Generation = current.Generation + 1
	published.ConfigSHA256 = r.options.ConfigSHA256
	published.LastFailure = ""
	// The last success and the proof expiry describe the *global* winner's proof, so
	// they move only when the global group was proved in this apply. A CloudFront
	// mapping changing says nothing about whether the global address is still
	// serving, and the state package refuses a proof that does not follow its last
	// success - so refreshing one without the other would produce a document no
	// writer of this project can produce.
	globalProved := false
	for _, decision := range proved {
		if decision.group.Hostname == "" {
			globalProved = true
		}
	}
	if globalProved {
		published.LastSuccess = r.now()
		published.WinnerProofUntil = r.now().Add(WinnerProofTTL)
	}
	for _, decision := range proved {
		switch decision.group.Hostname {
		case "":
			published.WinnerIP = decision.winner.IP.String()
			published.FallbackIP = fallbackAfter(decision.winner.IP.String(), current)
			published.Provider = string(candidate.ProviderCloudflare)
		default:
			if published.CloudFront == nil {
				published.CloudFront = make(map[string]string, len(current.CloudFront)+1)
			} else {
				published.CloudFront = maps.Clone(current.CloudFront)
			}
			published.CloudFront[decision.group.Hostname] = decision.winner.IP.String()
		}
	}
	// A selector that has never run has no provider, and the state package refuses
	// one without. A CloudFront-only first apply takes the provider of the group it
	// did publish, which names the CDN the mappings belong to.
	if published.Provider == "" && len(proved) > 0 {
		published.Provider = string(proved[0].group.Provider)
	}
	if err := state.WriteJSONAtomic(r.options.SelectorPath, published); err != nil {
		return report, state.Selector{}, err
	}
	return report, published, nil
}

// groupDecision is what one group decided, before any proof and before any write.
type groupDecision struct {
	// group is the group's own report entry, held so the decision carries the
	// hostname and provider it was made about. The outcome is written to the report
	// and not to this copy, so the two cannot drift apart.
	group GroupReport
	// winner is the address to prove and publish, and it is the zero value for a
	// group that keeps its mapping.
	winner candidate.Candidate
	// published is this group's decision on its own account, with no reference to
	// any other group.
	published bool
	// reason is why a group keeps its mapping, and is empty for a published one.
	reason string
}

// decisions is every group's own decision, in report order.
//
// The three outcomes are per group and not one verdict for the report:
//
//   - a group whose winner clears the switch gate publishes;
//   - a group whose winner is refused keeps the mapping it has, because "not an
//     improvement tonight" is an ordinary outcome and not a failure;
//   - a group that measured nothing publishable keeps its mapping for the same
//     reason, and the report says which of the two it was.
//
// The one refusal that is still the whole apply's is a group whose *recorded*
// decision disagrees with the one this configuration reaches from the same
// numbers. That is an integrity failure about the document rather than a routing
// decision about an address, and it is reported before any group is acted on.
func (r Report) decisions(threshold float64) ([]groupDecision, error) {
	decided := make([]groupDecision, 0, len(r.Groups))
	for _, group := range r.Groups {
		decision := groupDecision{group: group}
		switch {
		case group.Winner == nil:
			decision.reason = group.NoWinner
			if decision.reason == "" {
				decision.reason = "the group measured nothing publishable"
			}
		default:
			allowed, refusal := switchDecision(*group.Winner, threshold, r.BudgetExhausted)
			if group.Winner.SwitchAllowed != allowed || group.Winner.SwitchRefusal != refusal {
				return nil, fmt.Errorf("%w: the report records %q for %s, and this configuration reaches %q from the same numbers",
					ErrSwitchNotAllowed, group.Winner.SwitchRefusal, group.Winner.IP, refusal)
			}
			if !allowed {
				decision.reason = refusal
				break
			}
			decision.published = true
			decision.winner = candidate.Candidate{
				Provider: candidate.Provider(group.Provider),
				IP:       parseRetained(group.Winner.IP),
				Source:   group.Winner.Source,
				Hostname: group.Hostname,
			}
		}
		decided = append(decided, decision)
	}
	return decided, nil
}

// switchDecision is the switch gate as the whole system applies it, in one place
// so that the decision a report records and the decision an apply recomputes are
// the same function of the same numbers.
//
// Three things can refuse a switch, and each names itself:
//
//   - the day's bandwidth budget ran out, so this run measured no speed and its
//     scores are not comparable with the incumbent's;
//   - the winner is not at least improvementPercent better than the incumbent,
//     which is the empty-winner case when the incumbent has no score of its own;
//   - nothing at all, because the winner is the address already in service. There
//     is no switch to allow, and refusing that would leave a report claiming the
//     run found nothing to say about the address it is using.
func switchDecision(winner ReportWinner, improvementPercent float64, budgetExhausted bool) (bool, string) {
	switch {
	case budgetExhausted:
		return false, ReasonBudgetExhaustedSwitch
	case winner.IP == winner.CurrentIP:
		return true, "the winner is the address already in service"
	case SwitchAllowed(winner.Score, winner.CurrentScore, improvementPercent):
		return true, ""
	default:
		return false, fmt.Sprintf("the winner scores %g, which is not %g percent better than the incumbent's %g",
			winner.Score, improvementPercent, winner.CurrentScore)
	}
}

// Profiles is the set of identity profiles a proof is held to, kept apart by what
// each one is for, because the two kinds answer to different hostnames and a
// proof of one is not evidence about the other.
//
// The separation is the anti-leak rule at the point where a proof is run. A global
// address is proved against the global profiles - the provider's representative
// domain and every forced-ECH domain, which is what §11.6 of the design holds a
// manual Cloudflare address to. A per-hostname address is proved against its own
// hostname's profile and no other.
//
// A global address is never proved against a per-hostname profile, and that is
// deliberate in both directions. It cannot succeed: a Cloudflare anycast address
// cannot present a chain for a CloudFront hostname, so an apply on any router with
// a CloudFront domain list would be refused every time. And it is not needed: the
// CloudFront mapping is per-hostname, so the global winner is never published for
// one of those hostnames, and asking a Cloudflare address to impersonate a
// CloudFront one tests a relationship that does not exist.
type Profiles struct {
	// Global are the profiles a hostname-less address is proved against.
	Global []candidate.ProbeProfile
	// ByHostname is one profile per CloudFront hostname, which is the only profile
	// an address of that hostname may be proved against. DNS names are matched
	// case-insensitively, as they are everywhere else here.
	ByHostname map[string]candidate.ProbeProfile
}

// ForSubject is the profiles one address has to satisfy, and an empty result means
// this configuration names none for it - which is a refusal, not a pass.
//
// It is exported because it is the whole of the anti-leak rule, and the health
// check has to hold every address it proves to exactly the profiles this method
// names. A second copy of the rule in a second package is a second rule that can
// drift from the first, and a proof that drifted would be a proof of the wrong
// group.
func (p Profiles) ForSubject(subject candidate.Candidate) []candidate.ProbeProfile {
	if subject.Hostname == "" {
		return p.Global
	}
	for hostname, profile := range p.ByHostname {
		if strings.EqualFold(hostname, subject.Hostname) {
			return []candidate.ProbeProfile{profile}
		}
	}
	return nil
}

// all is every configured profile, which a refusal message quotes so an operator
// can see whether the set is empty or merely does not cover this address.
func (p Profiles) all() []candidate.ProbeProfile {
	every := make([]candidate.ProbeProfile, 0, len(p.Global)+len(p.ByHostname))
	every = append(every, p.Global...)
	for _, profile := range p.ByHostname {
		every = append(every, profile)
	}
	return every
}

// proveAddress is the final identity proof: it proves that an address is serving
// the hostnames this configuration will publish it for, and it is the same rule a
// manual pin is held to.
//
// Which hostnames those are is Profiles' decision and not this function's: a
// global address is held to the global profiles and a per-hostname address to its
// own hostname's, so a proof never crosses the boundary between the global group
// and a per-hostname one.
//
// The profiles of one address are proved concurrently, under ProofConcurrency, so
// the time the whole proof takes is one probe's time rather than the sum of the
// list's. The deadline is the caller's - Apply puts one over the entire final-proof
// phase, which is what bounds the control lock's hold - and this function adds
// none of its own, because a second deadline per group would make the hold a
// multiple of the group count again.
//
// The profiles are the ones this router is running. They are never taken from the
// report, so a report cannot choose what it is about to be proved against, and a
// report naming a hostname this configuration no longer has a profile for is
// refused rather than proved against something else.
func (r *Runner) proveAddress(ctx context.Context, subject candidate.Candidate, profiles Profiles) (measure.HTTPMetrics, error) {
	// Both callers hold the subject to the candidate rules before they get here -
	// Pin validates the address it was given, and Validate has checked every
	// candidate in the report - so this is the backstop that turns a subject built
	// by a future caller into a named refusal rather than a dialled zero address.
	if err := subject.Validate(); err != nil {
		return measure.HTTPMetrics{}, fmt.Errorf("%w: %v", ErrNotPublishable, err)
	}
	applicable := profiles.ForSubject(subject)
	if len(applicable) == 0 {
		kind := "for a global address"
		if subject.Hostname != "" {
			kind = fmt.Sprintf("for %s", subject.Hostname)
		}
		return measure.HTTPMetrics{}, fmt.Errorf("%w: %s is proved against none of the %d configured profiles %s",
			ErrNoProfile, subject.IP, len(profiles.all()), kind)
	}
	// Each profile's answer is kept in its own slot, and the walk afterwards is in
	// profile order: the bytes are summed whatever happened, and the refusal named is
	// the first profile's rather than whichever goroutine lost the race.
	//
	// The slot carries a state and not only an error, because "no error" cannot mean
	// "proved" here. The dispatcher may stop without ever handing an index to a
	// worker - a context that is already done when the phase starts, or a deadline
	// that arrives while the feeder is blocked - and an untouched slot is then
	// indistinguishable from a successful one if success is the absence of an error.
	// That was a fail-open in the gate immediately before an address reaches DNS
	// answers: with the context already done, every worker returned before calling
	// the prober, not one index was fed, every slot read as a silent pass, and
	// Apply and Pin both wrote. So a slot is marked answered only when a worker has
	// actually run the profile's probe, and the walk treats anything else as a
	// refusal.
	answers := make([]proofAnswer, len(applicable))
	// forEachIndex's error is deliberately not consulted. It is only ever the
	// context's error, so it says whether the run was cut short and not which
	// profiles were reached; the per-slot state is what says that, and it is the one
	// guard here because it cannot be satisfied by a slot nobody filled.
	_ = forEachIndex(ctx, len(applicable), ProofConcurrency, func(ctx context.Context, index int) error {
		metrics, err := r.prober.HTTPS(ctx, subject, applicable[index])
		answers[index] = proofAnswer{state: proofAnswered, metrics: metrics, err: err}
		return nil
	})
	summed := measure.HTTPMetrics{}
	attempted := 0
	for index, answer := range answers {
		hostname := applicable[index].Hostname
		if answer.state != proofAnswered {
			// A slot no worker filled. This is a refusal and not a pass, and it is
			// named with the profile that went unproved and how many of the list were
			// reached, because the operator's only way to act on it is to trim the
			// list or wait for a host that answers in time.
			reached := fmt.Errorf("the final proof reached %d of the %d profiles it is held to and never asked about this one",
				attempted, len(applicable))
			if err := ctx.Err(); err != nil {
				return summed, fmt.Errorf("%w: %s was never proved against %s: %w: %w",
					ErrIdentityRefused, subject.IP, hostname, reached, err)
			}
			return summed, fmt.Errorf("%w: %s was never proved against %s: %s",
				ErrIdentityRefused, subject.IP, hostname, reached)
		}
		attempted++
		// Summed before the error is looked at, for the same reason the run sums
		// them: a refused proof still spent the bytes it read to reach its verdict,
		// and the report is the only place that can say so.
		summed.BodyBytes += answer.metrics.BodyBytes
		if answer.err == nil {
			summed.Status = answer.metrics.Status
			summed.TLSMS = answer.metrics.TLSMS
			summed.Colocation = answer.metrics.Colocation
			continue
		}
		// The three verdicts are told apart by what this one probe returned, and not
		// by asking whether the context happens to be done. A refusal and a timeout
		// can be in the same phase, and asking the context relabelled an ordinary
		// refusal as a cut-short proof whenever a slower profile's timeout landed
		// first - so a host that had stopped serving looked like a host that was
		// slow.
		switch {
		case errors.Is(answer.err, context.DeadlineExceeded):
			// The phase's deadline, which is this build's patience rather than a
			// verdict about the host: a slow host is not a refusing host.
			return summed, fmt.Errorf("%w: %s did not answer for %s within %s",
				ErrProofTimeout, subject.IP, hostname, r.options.ProofTimeout)
		case errors.Is(answer.err, context.Canceled):
			// The caller went away, which is likewise not a statement about the host
			// and is not this build's patience either.
			return summed, fmt.Errorf("the proof of %s against %s was cut short: %w", subject.IP, hostname, answer.err)
		default:
			return summed, fmt.Errorf("%w: %s does not serve %s: %v", ErrIdentityRefused, subject.IP, hostname, answer.err)
		}
	}
	return summed, nil
}

// proofState is what a slot in a proof's answers holds, and it is a named type
// rather than a bool so that "not attempted" cannot be read as "not refused".
type proofState int

const (
	// proofNotAttempted is the zero value: no worker ever ran this profile's probe.
	// The walk must treat it as a refusal. It is the zero value deliberately - a
	// slot that is never written has to land here rather than anywhere that could
	// read as success.
	proofNotAttempted proofState = iota

	// proofAnswered is a slot a worker filled by running the profile's probe, which
	// either served it or refused it. The err field says which.
	proofAnswered
)

// proofAnswer is one profile's answer to a proof: whether its probe ran at all, what
// it measured, and what it said if it refused.
type proofAnswer struct {
	state   proofState
	metrics measure.HTTPMetrics
	err     error
}

// currentSelector is the selector as it stands, read under the control lock.
//
// A document that is absent is a router that has never selected anything, and the
// first apply is how it gets one, so absence is a generation-zero selector rather
// than a refusal. A document that is present and cannot be read is refused: it is
// the last-known-good address, and overwriting it because this build cannot parse
// it would destroy the one thing a broken router still has.
func (r *Runner) currentSelector() (state.Selector, error) {
	selector := state.Selector{}
	if err := state.ReadJSON(r.options.SelectorPath, &selector); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state.Selector{SchemaVersion: state.SchemaVersion, Mode: "auto"}, nil
		}
		return selector, fmt.Errorf("%s: read the selector: %w", r.options.SelectorPath, err)
	}
	return selector, nil
}

// fallbackAfter is the address the selector keeps as its first fallback once
// winner takes the field.
//
// The design says the old winner is kept as the first fallback rather than
// dropped. It cannot also be the winner, and the state package refuses a selector
// whose fallback equals its winner, so the two cases are: an apply that changed
// the address moves the old winner down, and an apply that confirmed the address
// already in service keeps whatever fallback was already there. An apply that
// finds no address to fall back to leaves the field empty rather than naming the
// winner twice.
func fallbackAfter(winner string, current state.Selector) string {
	if current.WinnerIP != "" && current.WinnerIP != winner {
		return current.WinnerIP
	}
	if current.FallbackIP != "" && current.FallbackIP != winner {
		return current.FallbackIP
	}
	return ""
}

// Pin stores an address as the manual winner, after proving that it serves
// everything this configuration will ask it to serve.
//
// The shape is Apply's, deliberately, because the two commands write the same file
// and a second shape would be a second thing to get wrong. The address is held to
// the candidate package's own rule first, so a LAN or reserved address is refused
// before a socket is opened; then the control lock is taken, the selector read
// under it, the identity proof run under it against the profiles of the group this
// address would be published for - every global profile for an address with no
// hostname of its own, and only its own hostname's profile for one that has - and
// only then the generation incremented and the file written. A refusal at any step
// leaves the file exactly as it was, which is the whole of what an operator is
// relying on when they type an address in.
//
// The proof is under the lock for the reason Apply's is: the store has to follow
// the proof immediately, or the file records an address that was proved at some
// other time. It is bounded by the prober's probe timeout, and a pin is a manual
// action, so seconds under the lock is the right trade.
func (r *Runner) Pin(ctx context.Context, address netip.Addr, profiles Profiles) (state.Selector, error) {
	subject := candidate.Candidate{
		Provider: candidate.ProviderCloudflare,
		IP:       address,
		// The source records that the operator named this address, which is what the
		// report and the status page will show about it.
		Source: candidate.SourceUser,
	}
	if err := subject.Validate(); err != nil {
		return state.Selector{}, fmt.Errorf("%w: %s: %v", ErrNotPublishable, address, err)
	}
	lock, current, err := r.holdControlLock()
	if err != nil {
		return state.Selector{}, err
	}
	defer func() { _ = lock.Close() }()

	// The proof is bounded by the same deadline an apply's is, and for the same
	// reason: it runs under the control lock. Its metrics are discarded, because a
	// pin has no report to account identity bytes in - the gap Task 2 named - and
	// the bytes are the operator's data allowance either way, bounded by the
	// identity body cap on each probe.
	proof, cancel := context.WithTimeout(ctx, r.options.ProofTimeout)
	defer cancel()
	if _, err := r.proveAddress(proof, subject, profiles); err != nil {
		return state.Selector{}, err
	}
	published := current
	published.SchemaVersion = state.SchemaVersion
	published.Generation = current.Generation + 1
	published.Mode = "manual"
	published.Provider = string(candidate.ProviderCloudflare)
	published.WinnerIP = subject.IP.String()
	published.FallbackIP = fallbackAfter(published.WinnerIP, current)
	published.ConfigSHA256 = r.options.ConfigSHA256
	published.LastSuccess = r.now()
	published.WinnerProofUntil = r.now().Add(WinnerProofTTL)
	published.LastFailure = ""
	if err := state.WriteJSONAtomic(r.options.SelectorPath, published); err != nil {
		return state.Selector{}, err
	}
	return published, nil
}

// Unpin restores automatic selection, and keeps the address that was pinned as the
// first fallback rather than discarding it.
//
// The winner field is emptied and the address moves to the fallback, which is the
// only shape the state package accepts: it refuses a selector whose fallback equals
// its winner, so an unpin that left both fields naming the same address would be a
// document no writer of this project can produce. What the operator gets is a
// selector with no chosen winner, the address they pinned still named as the one to
// fall back to, and the proof cleared with the winner - a proof that outlived its
// winner would be refused by the same rule.
//
// It takes no context and no profiles because it opens no socket: there is nothing
// to prove about an address that is being taken out of service.
func (r *Runner) Unpin() (state.Selector, error) {
	lock, current, err := r.holdControlLock()
	if err != nil {
		return state.Selector{}, err
	}
	defer func() { _ = lock.Close() }()

	if current.Mode != "manual" {
		return state.Selector{}, fmt.Errorf("%w: %s is in mode %q", ErrNothingPinned, r.options.SelectorPath, current.Mode)
	}
	published := current
	published.SchemaVersion = state.SchemaVersion
	published.Generation = current.Generation + 1
	published.Mode = "auto"
	published.ConfigSHA256 = r.options.ConfigSHA256
	// The pinned address is kept as the fallback, and the per-hostname mappings are
	// left alone: a mapping is measured for its own hostname and is not the global
	// pin the operator is removing.
	if current.WinnerIP != "" {
		published.WinnerIP = ""
		published.FallbackIP = current.WinnerIP
		published.WinnerProofUntil = time.Time{}
	}
	if err := state.WriteJSONAtomic(r.options.SelectorPath, published); err != nil {
		return state.Selector{}, err
	}
	return published, nil
}

// holdControlLock takes the control lock and reads the selector under it, which is
// the read-validate half of the two commands whose whole body is a write. The two
// are one call because taking the lock and then reading the file without it would
// be the one way to make the lock decorative.
//
// Apply does not use it, and the difference is deliberate: Apply has three gates
// that are pure - the document, the digest and the age - and it runs them before
// taking the lock, so a report that is going to be refused never blocks a peer's
// apply or pin for the length of a validation.
func (r *Runner) holdControlLock() (*filelock.Lock, state.Selector, error) {
	lock, err := filelock.Acquire(r.options.ControlLockPath)
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			return nil, state.Selector{}, fmt.Errorf("%s: %w", r.options.ControlLockPath, ErrControlLocked)
		}
		return nil, state.Selector{}, err
	}
	current, err := r.currentSelector()
	if err != nil {
		_ = lock.Close()
		return nil, state.Selector{}, err
	}
	return lock, current, nil
}

// Run measures the candidates the input names and reports the decision. It
// writes nothing: the selector is published by Apply, under the control lock,
// after the winner has been proved again. A run that could not finish returns
// the part of the report it did produce together with the error, so an operator
// can see how far it got.
// The report is a named return so the deferred finalisation below is what the
// caller receives: `return run.report, nil` copies the report as it stood before
// the defer ran, which is the copy that had the zero totals.
func (r *Runner) Run(ctx context.Context, input Input) (report Report, err error) {
	run := &runState{runner: r, input: input, startedAt: r.now()}
	run.report = Report{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   run.startedAt.UTC(),
		PolicySHA256:  r.options.ConfigSHA256,
		ConfigSHA256:  r.options.ConfigSHA256,
		Stale:         input.Stale,
	}
	// The day's total and the refused settlements are read on the way out however the
	// run ended, not on the way in when it succeeded. A cancelled run's report is the
	// only record of what it cost, and a report that printed zero bytes spent because
	// the run did not finish would be the one document an operator reads to find out
	// what a run cost.
	//
	// The defer is what makes that true for every early return below, including the
	// ones added later.
	defer func() {
		run.finalize()
		report = run.report
	}()

	// One budget for the whole run, opened once. The outstanding-reservation set
	// lives in this value rather than in the document, so a second Budget over
	// the same document mid-run would refuse every settle and leave the day
	// charged for transfers that were handed back.
	budget, err := NewPersistentBudget(r.options.BudgetPath, r.policy.CDN.Bandwidth.DailyBytes, r.options.Location, run.startedAt)
	if err != nil {
		return run.report, err
	}
	run.budget = budget
	run.spend = &settlingBudget{budget: budget}

	if err := run.collect(); err != nil {
		return run.report, err
	}
	if err := run.measureConnect(ctx); err != nil {
		return run.report, err
	}
	if err := run.proveIdentity(ctx); err != nil {
		return run.report, err
	}
	if err := run.shortlistByLatency(); err != nil {
		return run.report, err
	}
	if err := run.measureBandwidth(ctx); err != nil {
		return run.report, err
	}
	run.score()
	return run.report, nil
}

// finalize reads the day's total, the limit it is held to and the refused
// settlements into the report.
//
// It is a separate step and not the tail of the scoring phase because a run that
// stopped early has still spent bytes, and the run's own counters are only complete
// once every probe it started has been joined - which the phase boundaries are.
//
// The day's two numbers come from one read of the one budget this run spent from,
// through Budget.Standing, and never from the policy: a document an operator has
// tightened holds the day to the tighter number, and a report that quoted the
// policy beside it would show room this run did not have. The remaining figure is
// the same arithmetic a refused reservation is measured with, clamped at zero for
// the same reason: an overspent day has no room, not negative room.
func (run *runState) finalize() {
	if run.spend != nil {
		run.report.SettleRefusals = run.spend.refused()
	}
	if run.budget != nil {
		used, limit := run.budget.Standing()
		run.report.BudgetUsed = used
		run.report.BudgetLimit = limit
		run.report.BudgetRemaining = max(0, limit-used)
	}
	run.report.BudgetExhausted = run.exhausted.Load()
}

// now is the runner's clock. Every reading is taken where it is needed rather than
// at the start of the run, so the boundaries a report carries are the instants the
// phases happened - see runState.stamp - and the two readings a run does take once
// up front are the ones that have to agree with each other: the report's
// generated_at and the local date the budget is charged to.
func (r *Runner) now() time.Time {
	return r.options.Now().UTC()
}

// runState is one run in progress. It is a struct rather than a set of return
// values because the report is assembled across seven phases and the budget, the
// groups and the accounting all have to survive from one to the next.
type runState struct {
	runner *Runner
	input  Input
	// startedAt is the one reading that dates the run: the report's generated_at and
	// the local date the budget is charged to both come from it, so a run cannot
	// straddle two days and split its spending between them. Every phase boundary is
	// a separate reading - see stamp.
	startedAt time.Time
	report    Report

	// groups is every group this run measures, in the order the report lists
	// them, and current is the group a phase is working on.
	groups []*measuredGroup

	// budget is the one *Budget for this document and this run, and spend is the
	// prober-facing view of it that settles through Settle and keeps refusals.
	budget *Budget
	spend  *settlingBudget

	// exhausted is set the moment a transfer cannot be reserved, and every later
	// transfer is skipped rather than attempted. It is atomic because the
	// bandwidth phase sets it from whichever probe hit the cap first and reads it
	// from the ones still waiting to start.
	exhausted atomic.Bool
}

// stamp is one reading of the clock, taken where a phase boundary happens.
//
// It is a call and not a field for the reason the report carries the boundaries at
// all: a run that stamped all twelve of them with the reading it already had would
// produce a document whose boundaries are one instant, and both a reader and
// validatePhases would have nothing to order. Read at the moment, the fourteen
// stamps are an actual account of how long each phase took and in what order they
// happened.
//
// It is corroboration, not the proof of the phase order. The proof is the order
// the runner calls the prober in, which the prober itself sees; a clock cannot show
// that a phase did not happen, only that the ones that were stamped are in order.
func (run *runState) stamp() time.Time {
	return run.runner.now()
}

// measuredGroup is one group's candidates, its identity profile, and what has
// been measured of each candidate so far.
type measuredGroup struct {
	key GroupKey
	// profiles are the hostnames a candidate of this group is proved against:
	// every profile of a global group, and the one profile of a CloudFront
	// hostname. An empty slice refuses every candidate with ReasonNoProfile.
	profiles []candidate.ProbeProfile
	// port is the port this group is measured at, which is the port its profiles
	// name. A group whose profiles disagree has no port and refuses every
	// candidate.
	port uint16
	// refusal is why this group cannot be measured at all, if it cannot. It is
	// reported against every candidate rather than as a run error, so one broken
	// group does not cost the others their measurement.
	refusal string
	// detail is the probe's or parser's own words for that refusal.
	detail string
	// order is the group's candidates in the order the run collected them, and
	// measurements is indexed with it.
	order        []candidate.Candidate
	measurements []*measurement
	// shortlist is the indices of the candidates the latency phase kept.
	shortlist []int
	// currentIP is the address this group had in service when the run started.
	currentIP string
	// proved is how many of the group's candidates the identity gate vouched for.
	// It is the size of the only population the scorer is ever given.
	proved int
}

// measurement is what one candidate was measured as, through the run so far.
type measurement struct {
	tcp      measure.TCPMetrics
	identity measure.HTTPMetrics
	// identityBytes is what this candidate's identity probes read in total.
	identityBytes int64
	// proved is whether every profile of the group vouched for this candidate.
	proved bool
	// tcpErr, identityErr and downloadErr are what the probes said when they
	// refused, and are the Detail a report gives for a candidate.
	tcpErr      error
	identityErr error
	download    measure.DownloadMetrics
	downloadErr error
}

// collect is the first phase: it turns the caller's slices into groups, adds the
// addresses the selector is already using back in, and decides which profile each
// group is proved against. It opens no socket, which is why it is a phase at all:
// a run that collects a mixed group has already made the mistake the scorer
// refuses to fix afterwards.
func (run *runState) collect() error {
	run.report.Phases.Collect.StartedAt = run.stamp()
	groups, err := run.collectGroups()
	run.groups = groups
	run.report.Phases.Collect.EndedAt = run.stamp()
	return err
}

// collectGroups gathers every group of the run and returns them in report order.
func (run *runState) collectGroups() ([]*measuredGroup, error) {
	// A CloudFront rule is held to what a prober could check before a socket is
	// opened, so a broken document is a named refusal rather than a probe failure.
	// A CloudFront group's profile is its own rule and no other: that is the
	// anti-leak rule, and it is why the profiles are keyed by hostname here.
	byName := make(map[string]candidate.ProbeProfile, len(run.input.CloudFrontRules))
	for _, rule := range run.input.CloudFrontRules {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("the CloudFront profile for %q is not usable: %w", rule.Profile.Hostname, err)
		}
		byName[rule.Profile.Hostname] = rule.Profile
	}
	global := run.input.CloudflareProfiles

	groups := make(map[GroupKey]*measuredGroup)
	add := func(subject candidate.Candidate) {
		key := GroupOf(subject)
		group, known := groups[key]
		if !known {
			group = &measuredGroup{key: key}
			groups[key] = group
		}
		group.order = append(group.order, subject)
	}
	for _, subject := range run.input.Cloudflare {
		add(subject)
	}
	for _, subject := range run.input.CloudFront {
		add(subject)
	}
	// A rule's own addresses are part of what the operator asked to be measured, so
	// they are measured whether or not the caller also listed them as candidates.
	for _, rule := range run.input.CloudFrontRules {
		for _, address := range rule.Candidates {
			add(candidate.Candidate{
				Provider: candidate.ProviderCloudFront,
				IP:       address,
				Source:   candidate.SourceCloudFront,
				Hostname: rule.Profile.Hostname,
			})
		}
	}

	// The addresses the selector is already using are measured again, whatever the
	// ranges said today, so the switch gate is never comparing against an address
	// this run could not re-prove. A retained address that cannot be measured is
	// named in the report rather than refused the run: a hand-written winner in
	// private space, or a hostname no rule names any more, is one operator problem,
	// and failing the whole run over it would cost every other group its
	// measurement.
	retain := func(subject candidate.Candidate) {
		key := GroupOf(subject)
		group, known := groups[key]
		if !known {
			// A group whose only candidate would be the retained one is still worth
			// measuring, as long as this run can prove an address for it. A group
			// nothing can be proved against is not a group this run can say anything
			// about.
			if len(byName) == 0 && len(global) == 0 {
				run.report.SkippedRetained = append(run.report.SkippedRetained,
					fmt.Sprintf("%s: %s: this run was given no identity profile at all", subject.IP, ReasonNoProfile))
				return
			}
			group = &measuredGroup{key: key}
			groups[key] = group
		}
		if err := subject.Validate(); err != nil {
			run.report.SkippedRetained = append(run.report.SkippedRetained, fmt.Sprintf("%s: %s", subject.IP, err))
			return
		}
		group.order = append(group.order, subject)
	}
	selector := run.input.LastGood
	if selector.WinnerIP != "" {
		retain(candidate.Candidate{Provider: candidate.ProviderCloudflare, IP: parseRetained(selector.WinnerIP), Source: candidate.SourceRetained})
	}
	if selector.FallbackIP != "" && selector.FallbackIP != selector.WinnerIP {
		retain(candidate.Candidate{Provider: candidate.ProviderCloudflare, IP: parseRetained(selector.FallbackIP), Source: candidate.SourceRetained})
	}
	for _, hostname := range sortedKeys(selector.CloudFront) {
		retain(candidate.Candidate{Provider: candidate.ProviderCloudFront, IP: parseRetained(selector.CloudFront[hostname]), Source: candidate.SourceRetained, Hostname: hostname})
	}

	keys := make([]GroupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareGroupKeys)

	measured := make([]*measuredGroup, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		run.identify(group, key, global, byName)
		combined, err := combineForGroup(run.runner, group.order)
		if err != nil {
			return nil, err
		}
		group.order = combined
		group.measurements = make([]*measurement, len(combined))
		for index := range group.measurements {
			group.measurements[index] = &measurement{}
		}
		group.currentIP = incumbentOf(selector, key)
		measured = append(measured, group)
	}
	return measured, nil
}

// compareGroupKeys orders the report's groups by provider and then hostname, so
// two runs over one input produce one document whatever order the sources
// answered in.
func compareGroupKeys(first, second GroupKey) int {
	if order := strings.Compare(string(first.Provider), string(second.Provider)); order != 0 {
		return order
	}
	return strings.Compare(first.Hostname, second.Hostname)
}

// identify gives a group the profiles it is proved against, or the named reason
// it cannot be measured. A global group is proved against every profile it was
// given, because the design holds a manual Cloudflare address to the provider's
// representative domain and every forced-ECH domain; a CloudFront group is proved
// against its own hostname and no other, which is the anti-leak rule.
func (run *runState) identify(group *measuredGroup, key GroupKey, global []candidate.ProbeProfile, byName map[string]candidate.ProbeProfile) {
	if key.Hostname != "" {
		profile, known := byName[key.Hostname]
		if !known {
			group.refusal = ReasonNoProfile
			group.detail = fmt.Sprintf("no CloudFront profile names %q", key.Hostname)
			return
		}
		group.profiles = []candidate.ProbeProfile{profile}
		group.port = profile.Port
		return
	}
	if len(global) == 0 {
		group.refusal = ReasonNoProfile
		group.detail = "the run was given no Cloudflare identity profile"
		return
	}
	for index, profile := range global {
		if err := (candidate.CloudFrontProfile{Profile: profile}).Validate(); err != nil {
			group.refusal = ReasonProfileInvalid
			group.detail = err.Error()
			return
		}
		if index > 0 && profile.Port != group.port {
			group.refusal = ReasonProfilePortsDiffer
			group.detail = fmt.Sprintf("%s is served on port %d and %s on port %d", global[0].Hostname, group.port, profile.Hostname, profile.Port)
			return
		}
		if index == 0 {
			group.port = profile.Port
		}
	}
	group.profiles = global
}

// combineForGroup merges one group's channels: the official ones under the
// policy's cap, the user's uncapped, and the ones the selector is already using
// uncapped, so a wide official sample can never push the current winner out of the
// run.
func combineForGroup(runner *Runner, subjects []candidate.Candidate) ([]candidate.Candidate, error) {
	var official, user, retained []candidate.Candidate
	for _, subject := range subjects {
		switch {
		case subject.Source == candidate.SourceRetained:
			retained = append(retained, subject)
		case subject.Source == candidate.SourceUser:
			user = append(user, subject)
		default:
			official = append(official, subject)
		}
	}
	combined, err := candidate.Combine(official, user, retained, runner.policy.CDN.Cloudflare.MaxCandidates)
	if err != nil {
		return nil, err
	}
	if len(combined) == 0 {
		return nil, nil
	}
	return combined, nil
}

// measureConnect is the TCP phase: one connect measurement per candidate, at the
// port its group's profile names. A candidate whose measurement failed carries no
// sample, and the scorer refuses it for that on its own: a p50 of zero would
// otherwise make an address nothing answered the fastest in the group.
func (run *runState) measureConnect(ctx context.Context) error {
	run.report.Phases.TCP.StartedAt = run.stamp()
	err := run.forEachCandidate(ctx, connectConcurrency, func(ctx context.Context, group *measuredGroup, index int) error {
		// A group that cannot be identified has no port to aim at, and dialling
		// port zero would measure nothing for a candidate the identity gate is
		// already going to refuse. It carries no sample, which is what the
		// scorer's own no-sample rule refuses it for.
		if group.refusal != "" {
			return nil
		}
		subject := group.order[index]
		metrics, err := run.runner.prober.TCP(ctx, subject.IP, group.port, connectSamples)
		// The metrics are kept whatever the error says: a connect measurement that
		// lost some of its attempts is a measurement, and the loss it reports is
		// one of the three terms the score is built from.
		group.measurements[index].tcp = metrics
		group.measurements[index].tcpErr = err
		return nil
	})
	run.report.Phases.TCP.EndedAt = run.stamp()
	return err
}

// proveIdentity is the first of the two identity gates. Every candidate is
// proved against every profile of its group, and a candidate one of them will
// not vouch for never reaches the scorer.
//
// The body bytes are added in before the error is looked at. That order is the
// whole point: an identity probe is deliberately outside the budget, so
// HTTPMetrics.BodyBytes is the only record of what it cost, and a refused probe
// is exactly the case where bytes were spent and nothing was published. The
// idiomatic "metrics, err := HTTPS(...); if err != nil { continue }" throws that
// record away.
func (run *runState) proveIdentity(ctx context.Context) error {
	run.report.Phases.Identity.StartedAt = run.stamp()
	err := run.forEachCandidate(ctx, identityConcurrency, func(ctx context.Context, group *measuredGroup, index int) error {
		subject := group.order[index]
		found := group.measurements[index]
		if group.refusal != "" {
			found.identityErr = errors.New(group.detail)
			return nil
		}
		proved := true
		for _, profile := range group.profiles {
			metrics, probeErr := run.runner.prober.HTTPS(ctx, subject, profile)
			// Summed first, always, and summed per candidate rather than into one
			// running total: every probe of this phase writes to its own candidate's
			// measurement, and the run's total is added up after the phase has
			// joined every probe that was going to run. The refused probe reports the
			// bytes it read to reach its verdict and nothing else.
			found.identityBytes += metrics.BodyBytes
			if probeErr != nil {
				proved = false
				found.identityErr = fmt.Errorf("%s: %w", profile.Hostname, probeErr)
				continue
			}
			found.identity = metrics
		}
		found.proved = proved
		return nil
	})
	// The gate's output is counted here, while the phase that produced it is
	// still the phase in progress, and so is the run's uncharged egress: every
	// probe of the phase has been joined, so each candidate's own total is final
	// and the run's is their sum.
	//
	// Unconditionally, which is the whole of the fix. The sum was behind
	// `err == nil`, and a cancelled phase is the case where the accounting is most
	// needed: the probes that DID run spent their bytes, nothing on disk pays for
	// an identity probe, and a partial report that dropped them would be the one
	// document an operator reads to find out what a run cost. Nothing downstream
	// reads these two numbers on this path - the run returns the error and no
	// group is ever scored - so counting them changes no decision, only what the
	// report is able to say.
	for _, group := range run.groups {
		group.proved = 0
		for _, found := range group.measurements {
			if found.proved {
				group.proved++
			}
			run.report.IdentityBytes += found.identityBytes
		}
	}
	run.report.Phases.Identity.EndedAt = run.stamp()
	return err
}

// shortlistByLatency is the latency phase: the top cdn.latency_candidate_count of
// the group, by the scorer's own ranking and under the same ceilings. It opens no
// socket, and it is where the run decides which candidates are worth a transfer.
func (run *runState) shortlistByLatency() error {
	run.report.Phases.Latency.StartedAt = run.stamp()
	for _, group := range run.groups {
		// The ranking reads the connect measurement only, which is all this phase
		// has: a transfer is exactly what the shortlist decides whether to spend.
		ranking := RankLatency(group.provedResults(false), run.runner.params.LatencyCandidates, run.runner.params.Limits)
		group.shortlist = group.shortlistFrom(ranking.Ranked)
	}
	run.report.Phases.Latency.EndedAt = run.stamp()
	return nil
}

// provedResults is the population the scorer is given: the candidates that passed
// the identity gate, and nothing else, with the measurements taken so far.
//
// The transfer is filled in only after the bandwidth phase, which is why the
// population is built again here rather than kept from the identity phase: a
// CandidateResult handed to the scorer with no speed in it would rank last on
// bandwidth whatever the address can actually deliver.
func (g *measuredGroup) provedResults(includeTransfers bool) []CandidateResult {
	results := make([]CandidateResult, 0, g.proved)
	for index, subject := range g.order {
		found := g.measurements[index]
		if !found.proved {
			continue
		}
		result := CandidateResult{Candidate: subject, TCP: found.tcp, HTTP: found.identity}
		if includeTransfers {
			result.Download = found.download
		}
		results = append(results, result)
	}
	return results
}

// shortlistFrom maps the candidates of a ranking back to their positions in the
// group's collection, which is what the bandwidth phase walks.
func (g *measuredGroup) shortlistFrom(ranked []CandidateResult) []int {
	positions := make(map[candidate.Candidate]int, len(g.order))
	for index, subject := range g.order {
		positions[subject] = index
	}
	shortlist := make([]int, 0, len(ranked))
	for _, result := range ranked {
		if index, known := positions[result.Candidate]; known {
			shortlist = append(shortlist, index)
		}
	}
	return shortlist
}

// measureBandwidth is the bandwidth phase: one capped transfer per shortlist
// candidate, reserving from the day's budget before each. When the day cannot pay
// for one, the rest are skipped rather than attempted, the run says so, and no
// winner is allowed to switch: a run that could not afford to measure does not
// get to change the address in service.
func (run *runState) measureBandwidth(ctx context.Context) error {
	run.report.Phases.Bandwidth.StartedAt = run.stamp()
	err := run.forEachShortlisted(ctx, downloadConcurrency, func(ctx context.Context, group *measuredGroup, index int) error {
		// A transfer that has not started has not spent anything, so a day that is
		// already full costs this run one refused reservation rather than one
		// refusal per shortlist candidate. The run still says the day ran out.
		if run.exhausted.Load() {
			return nil
		}
		subject := group.order[index]
		found := group.measurements[index]
		metrics, transferErr := run.runner.prober.Download(
			ctx, subject, group.profiles[0],
			run.runner.policy.CDN.Bandwidth.PerCandidateBytes,
			time.Duration(run.runner.policy.CDN.Bandwidth.PerCandidateSeconds)*time.Second,
			run.spend,
		)
		// What it read is what it read, whatever the error says.
		found.download = metrics
		found.downloadErr = transferErr
		if errors.Is(transferErr, ErrBudgetExhausted) {
			run.exhausted.Store(true)
		}
		return nil
	})
	run.report.Phases.Bandwidth.EndedAt = run.stamp()
	return err
}

// score is the scoring phase: the scorer's whole per-group decision, once per
// group, over the candidates that passed the identity gate and nothing else.
func (run *runState) score() {
	run.report.Phases.Score.StartedAt = run.stamp()
	for _, group := range run.groups {
		run.scoreGroup(group)
	}
	run.report.Phases.Score.EndedAt = run.stamp()
}

// scoreGroup runs one group's selection and records it, including the winner and
// the switch decision. The group isolation is the scorer's, and this is where the
// runner's part of it happens: one Select call per group, over a slice that
// holds one group, with the unproved candidates kept out of it entirely.
func (run *runState) scoreGroup(group *measuredGroup) {
	selection := Select(group.provedResults(true), run.runner.params)

	report := GroupReport{
		// The named key is carried beside the two fields it is made of, because
		// GroupKey has no JSON shape and this is the same fact twice in a value an
		// operator reads as well as a document a machine does.
		Group:    group.key,
		Provider: string(group.key.Provider),
		Hostname: group.key.Hostname,
		// The p10 is the scored set's: that is the population the bandwidth rank is
		// taken over, and a shortlist candidate that never entered the comparison
		// has no say in the floor of the set that did.
		P10BytesPerSecond: TenthPercentileSpeed(selection.Scored),
	}
	// The report lists the group's candidates in the order the run collected them,
	// not the order the scorer ranked them, so two runs over one input produce one
	// document whatever the measurements finished in.
	// The scorer accounts for every candidate it was given, in two halves: the set
	// it scored and the set it refused. The report looks the two up by candidate, so
	// a candidate the gate kept out of the population falls through to the gate's
	// own refusal.
	decided := make(map[candidate.Candidate]CandidateResult, len(selection.Scored)+len(selection.Excluded))
	for _, result := range selection.Scored {
		decided[result.Candidate] = result
	}
	for _, result := range selection.Excluded {
		decided[result.Candidate] = result
	}
	for index, subject := range group.order {
		found := group.measurements[index]
		if result, scored := decided[subject]; scored {
			report.Candidates = append(report.Candidates, reportCandidateOf(result, found))
			continue
		}
		report.Candidates = append(report.Candidates, unprovedCandidate(group, subject, found))
	}

	switch {
	case len(selection.Scored) > 0:
		winner := selection.Scored[0]
		report.Winner = run.chooseWinner(group, winner, report.Candidates)
	default:
		report.NoWinner = run.noWinnerReason(group, selection)
	}
	run.report.Groups = append(run.report.Groups, report)
}

// chooseWinner records a group's winner and the switch decision the report
// publishes, so an operator can see why a measurement that found a winner did or
// did not change anything. The decision itself is switchDecision, which an apply
// recomputes from the same numbers, so the two cannot drift apart.
func (run *runState) chooseWinner(group *measuredGroup, winner CandidateResult, reported []ReportCandidate) *ReportWinner {
	recorded := &ReportWinner{
		IP:           winner.Candidate.IP.String(),
		Source:       winner.Candidate.Source,
		Score:        winner.Score,
		CurrentIP:    group.currentIP,
		CurrentScore: currentScoreOf(reported, group.currentIP),
	}
	recorded.SwitchAllowed, recorded.SwitchRefusal = switchDecision(
		*recorded, run.runner.policy.CDN.SwitchImprovementPercent, run.exhausted.Load(),
	)
	return recorded
}

// noWinnerReason says which stage emptied a group, because "no candidate
// qualified" cannot distinguish a run where nothing was proved from a run where
// everything was over a ceiling, and an operator cannot act on the first without
// looking at the second.
func (run *runState) noWinnerReason(group *measuredGroup, selection Selection) string {
	switch {
	case group.proved == 0:
		return ReasonNoProvedCandidate
	case len(selection.Latency.Ranked) == 0:
		return ReasonNoEligibleCandidate
	default:
		// The third case is the invariant rather than a stage: with the counts
		// validated and a non-empty shortlist, the union of the best three by
		// latency and the best three by speed cannot be empty. It is here because
		// a report that reached this line would be describing something the scorer
		// cannot do, and a report must still say what it found.
		return "the group produced no winner"
	}
}

// unprovedCandidate is what the report says about a candidate the scorer was
// never given, which is every candidate the identity gate refused. The reason is
// the gate that refused it rather than a scorer's, because a scorer's reasons
// would claim a comparison that was never made.
func unprovedCandidate(group *measuredGroup, subject candidate.Candidate, found *measurement) ReportCandidate {
	reason := ReasonIdentityRefused
	if group.refusal != "" {
		reason = group.refusal
	}
	entry := ReportCandidate{
		Provider:      string(subject.Provider),
		IP:            subject.IP.String(),
		Hostname:      subject.Hostname,
		Source:        subject.Source,
		Samples:       found.tcp.Samples,
		P50MS:         found.tcp.P50MS,
		P95MS:         found.tcp.P95MS,
		JitterMS:      found.tcp.JitterMS,
		Loss:          found.tcp.Loss,
		IdentityBytes: found.identityBytes,
		Reason:        reason,
		Detail:        detailOf(found.identityErr, found.tcpErr),
	}
	return entry
}

// detailOf is what the probes said about a candidate, preferring the identity
// refusal over the connect one: a candidate that could not be proved is not in
// the running, whatever its handshake did.
func detailOf(identityErr, tcpErr error) string {
	switch {
	case identityErr != nil:
		return identityErr.Error()
	case tcpErr != nil:
		return tcpErr.Error()
	default:
		return ""
	}
}

// reportCandidateOf states one candidate the scorer did rank or refuse, with the
// numbers the probes read and the verdict the scorer reached.
func reportCandidateOf(result CandidateResult, found *measurement) ReportCandidate {
	entry := ReportCandidate{
		Provider:      string(result.Candidate.Provider),
		IP:            result.Candidate.IP.String(),
		Hostname:      result.Candidate.Hostname,
		Source:        result.Candidate.Source,
		Samples:       result.TCP.Samples,
		P50MS:         result.TCP.P50MS,
		P95MS:         result.TCP.P95MS,
		JitterMS:      result.TCP.JitterMS,
		Loss:          result.TCP.Loss,
		HTTPStatus:    result.HTTP.Status,
		TLSMS:         result.HTTP.TLSMS,
		TTFBMS:        result.HTTP.TTFBMS,
		TotalMS:       result.HTTP.TotalMS,
		Colocation:    result.HTTP.Colocation,
		IdentityBytes: found.identityBytes,
		DownloadBytes: result.Download.Bytes,
		// A transfer that was skipped because the day was full has no speed, and
		// the report says zero rather than a number nobody measured.
		BytesPerSecond: result.Download.BytesPerSecond,
		Score:          result.Score,
		Eligible:       result.Eligible,
		Reason:         result.Reason,
	}
	if found.downloadErr != nil && entry.Reason == "" {
		entry.Detail = found.downloadErr.Error()
	}
	return entry
}

// forEachCandidate runs body over every candidate of every group with at most
// limit calls in flight, and stops handing out work the moment the context is
// done. The only error it returns is the context's: a probe that refused is a
// measurement, and a run of them is a report rather than a failure.
func (run *runState) forEachCandidate(ctx context.Context, limit int, body func(context.Context, *measuredGroup, int) error) error {
	return run.forEachGroupCandidate(ctx, limit, false, body)
}

// forEachShortlisted is forEachCandidate over the latency shortlist only.
func (run *runState) forEachShortlisted(ctx context.Context, limit int, body func(context.Context, *measuredGroup, int) error) error {
	return run.forEachGroupCandidate(ctx, limit, true, body)
}

func (run *runState) forEachGroupCandidate(ctx context.Context, limit int, shortlistedOnly bool, body func(context.Context, *measuredGroup, int) error) error {
	type task struct {
		group *measuredGroup
		index int
	}
	var tasks []task
	for _, group := range run.groups {
		if shortlistedOnly {
			for _, index := range group.shortlist {
				tasks = append(tasks, task{group: group, index: index})
			}
			continue
		}
		for index := range group.order {
			tasks = append(tasks, task{group: group, index: index})
		}
	}
	return forEachIndex(ctx, len(tasks), limit, func(ctx context.Context, position int) error {
		return body(ctx, tasks[position].group, tasks[position].index)
	})
}

// forEachIndex runs body over every index below count with at most limit calls in
// flight, and returns the context's error if the run was cancelled part way
// through. The remaining indexes are left unrun rather than started, so a
// cancelled run does not open sockets it is going to abandon.
//
// A trap for the next caller, recorded here because it is a deadlock and not a
// failure: body must not return a non-nil error. A worker that returns one leaves
// its slot unfilled, the feeder blocks on an unbuffered channel with no reader left
// to take the next index, and nothing closes that channel - the run hangs rather
// than failing. Every body in this file returns nil and records a probe's refusal
// in the report instead, which is the shape that keeps the workers fed. If a future
// body needs to fail, it has to cancel the context or collect its own errors
// outside this loop.
func forEachIndex(ctx context.Context, count, limit int, body func(context.Context, int) error) error {
	if count == 0 {
		return ctx.Err()
	}
	if limit < 1 {
		limit = 1
	}
	work := make(chan int)
	var group sync.WaitGroup
	for worker := 0; worker < limit && worker < count; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range work {
				if ctx.Err() != nil {
					return
				}
				if err := body(ctx, index); err != nil {
					return
				}
			}
		}()
	}
	for index := 0; index < count; index++ {
		select {
		case work <- index:
		case <-ctx.Done():
			close(work)
			group.Wait()
			return ctx.Err()
		}
	}
	close(work)
	group.Wait()
	return ctx.Err()
}

// settlingBudget is the prober's view of the day's budget. It exists so the
// runner settles through Budget.Settle rather than Budget.Consume: Consume cannot
// report a refusal, and a refused settlement is a day charged for bytes that were
// handed back, which is a real outcome a run has to be able to show.
type settlingBudget struct {
	budget *Budget

	mutex    sync.Mutex
	refusals []string
}

var _ ByteBudget = (*settlingBudget)(nil)

func (s *settlingBudget) Reserve(requested int64) (int64, error) {
	return s.budget.Reserve(requested)
}

func (s *settlingBudget) Consume(reserved, actual int64) {
	if err := s.budget.Settle(reserved, actual); err != nil {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		s.refusals = append(s.refusals, err.Error())
	}
}

// refused returns the settlements this budget would not make, in the order they
// happened.
func (s *settlingBudget) refused() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return slices.Clone(s.refusals)
}

// incumbentOf is the address a group had in service, which is the global winner
// for the global group and this hostname's own mapping for a CloudFront one. It
// is the address the switch gate compares against, and it is read from the
// selector the run was given rather than from disk under the control lock: a
// report says what the run saw, and an apply reads the selector again itself.
func incumbentOf(selector state.Selector, key GroupKey) string {
	if key.Hostname == "" {
		return selector.WinnerIP
	}
	return selector.CloudFront[key.Hostname]
}

// currentScoreOf is the incumbent's score in this run, and zero when the
// incumbent is not among the group's candidates. A zero is the empty-winner case
// SwitchAllowed documents: there is no measured incumbent to beat.
func currentScoreOf(reported []ReportCandidate, currentIP string) float64 {
	if currentIP == "" {
		return 0
	}
	for _, entry := range reported {
		if entry.IP == currentIP {
			return entry.Score
		}
	}
	return 0
}

// parseRetained parses an address the selector is holding, so a state document
// that names something unparseable is skipped and named rather than refused: the
// rest of the run is still worth measuring.
func parseRetained(value string) netip.Addr {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}

func sortedKeys(mapping map[string]string) []string {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func isLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}
