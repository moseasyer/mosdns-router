// Package health watches the addresses a CDN selector has published and moves the
// resolver off one that has stopped working.
//
// This is the component whose failures are worse than its gaps, and the whole
// file is arranged around that. A health check that never notices a dead address
// costs a user's queries until the next nightly run; a health check that moves a
// working address costs them the wrong address instead. So every decision here is
// taken towards refusing, and the three ways that shows are:
//
//   - A verdict is a named type with three values, and "we do not know" is one of
//     them. A cancellation is not a failure, because a cancellation is not a
//     statement about the host; and a proof that was skipped, cut short, or never
//     dispatched is never a pass, because a check that could not run has learned
//     nothing and saying "healthy" would be the one claim it cannot support. The
//     zero value is "we do not know" for the same reason Task 4's proof walk made
//     its unattempted slot the zero value.
//
//   - Nothing is published that was not proved. A transition moves the resolver
//     to the fallback only after the fallback has been proved against the same
//     profiles a winner is held to, and the document that results is one the
//     state package accepts. A health check spends no bandwidth budget, for the
//     same reason the identity probe does not: a check that decides whether the
//     address in service may stay there must not be able to spend the day. The
//     body bytes those probes read are uncharged, so they are summed before any
//     error is looked at and reported in the result.
//
//   - The control lock is taken for a mutation, never for a measurement. Probing
//     takes seconds, and holding a shared lock for that would put every apply,
//     pin and unpin behind a health check. So the selector is read without the
//     lock, the addresses are proved without it, and the lock is taken only for
//     the read-validate-change-write of the health document and, when one is
//     required, of the selector. The one exception is the fallback's proof inside
//     a transition, which runs under the lock and is bounded by one deadline,
//     because the store has to follow the proof immediately.
//
// One of the brief's cases belongs to the response rewriter rather than to this
// file, and the boundary is worth naming because it is a safety one. For a strict
// ECH domain the branch stays blocked while the published address does not serve
// that domain, and a health check can never be the thing that unblocks it: nothing
// here writes an input the branch reads except the selector's winner, and a verdict
// is not an input to it. What a health check does is move the resolver onto an
// address that has been proved to serve every forced-ECH domain - that is exactly
// what the fallback's proof covers, because a global address is held to the global
// profiles and those are the representative domain plus every forced-ECH domain - so
// a domain the rewriter had to block because the winner had stopped serving it
// becomes serviceable again, and only ever against an address something proved.
//
// The health document holds the four fields the plan documents and nothing else,
// which is a constraint and not a choice: four fields describe one address, and
// the one address a selector can move away from is its global winner. The
// per-hostname CloudFront mappings are proved in the same pass and each carries
// its own verdict in the result, because the brief asks for every hostname to be
// validated separately; what they cannot do is move the counter, which belongs to
// the address the fallback would replace.
package health

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/measure"
	"mosdns-router/internal/optimizer"
	"mosdns-router/internal/state"
)

const (
	// DefaultHealthPathName is the document the consecutive-failure count is kept
	// in, and it is published next to the selector it describes.
	DefaultHealthPathName = "health.json"

	// DefaultHealthPath is where the production router keeps it, beside the
	// selector and the control lock the other control commands use.
	DefaultHealthPath = "/var/lib/mosdns/runtime/" + DefaultHealthPathName

	// DefaultWaveTimeout bounds one wave of concurrent identity proofs: a single
	// answer's time on a healthy host. It carries the same value as the prober's own
	// per-probe bound, so a host slow enough to exhaust one probe exhausts its wave
	// with it.
	//
	// It is a wave and not a pass because the pass is not one wave. A check that is
	// held to a single fixed deadline has to choose between refusing a long profile
	// list and leaving it unproved, and a health check makes that choice in the worst
	// possible direction: a deadline that cuts a healthy address's walk short reports
	// a failure, three of those report a rollback, and the router spends the rest of
	// the day on its fallback for a list it would have answered. The pass deadline is
	// therefore this bound times the number of waves the pass needs - see
	// MaximumPassTimeout for the ceiling on that.
	DefaultWaveTimeout = 10 * time.Second

	// MaximumPassTimeout is the ceiling on a pass's deadline however many waves it
	// needs, and it is half the shipped 120 second health interval on purpose: two
	// passes may not overlap, and a pass that overran its interval would be
	// measuring the state the previous pass had already changed. A list long enough
	// to hit the ceiling is answered as far as it gets, and the rest of the walk is
	// reported as cut short - a failure, because an address whose profile was never
	// asked has not been proved.
	MaximumPassTimeout = 60 * time.Second
)

// Prober is the only measurement a health check makes. It is the HTTPS identity
// proof and nothing else, which is what makes "health probing spends no bandwidth
// budget" a property of the type rather than a promise: there is no transfer in
// this interface, and a caller has nothing to charge.
//
// It is declared here rather than taken as prober.Prober because it is narrower on
// purpose. The prober package's own interface also offers a budgeted transfer, and
// taking that one would let a later change hand this checker something it could
// charge the day with. A caller holding the prober package's value passes it
// straight in - the CLI's prober satisfies both, and the CLI is where the two
// interfaces meet - so the narrowness costs no adapter. The metrics type is the
// same one by alias, so a value a prober returns is assignable to a field here with
// no conversion.
type Prober interface {
	// HTTPS proves that an address is serving a profile's hostname.
	HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (measure.HTTPMetrics, error)
}

// HTTPMetrics is what one identity proof reported. See measure.HTTPMetrics for
// the fields; the alias keeps one spelling of one type.
type HTTPMetrics = measure.HTTPMetrics

// Verdict is what one check of one published address concluded.
//
// It is a named type with an explicit "we do not know" rather than a bool for a
// reason a caller has to be able to rely on: a check that could not run, and a
// check that ran and found a host refusing, are different answers, and a caller
// that cannot tell them apart will eventually treat the second as the first. The
// zero value is VerdictUnknown, so a value nobody set reads as the absence of a
// conclusion rather than as success.
type Verdict int

const (
	// VerdictUnknown is the absence of a conclusion: the caller cancelled, or
	// nothing was there to check. It never means the address is serving.
	VerdictUnknown Verdict = iota

	// VerdictHealthy means every profile the address is held to was proved, by a
	// probe that ran to completion.
	VerdictHealthy

	// VerdictFailed means the address is not serving something it is held to. It
	// covers a chain that is not for the hostname, a status the profile does not
	// expect, a required header that is missing, a refusal, a timeout, and a
	// proof that could not be run at all - the last because "we could not check"
	// must not leave an address in service with nothing behind the claim that it
	// is working.
	VerdictFailed
)

func (v Verdict) String() string {
	switch v {
	case VerdictHealthy:
		return "healthy"
	case VerdictFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// The refusals a check can return, named so a caller matches them with errors.Is
// rather than with their wording, and each naming one thing that went wrong.
var (
	// ErrSelectorChanged reports that the selector was published again between the
	// moment this check read it and the moment it took the control lock, so its
	// verdicts and any transition it was about to make are about an address that
	// is no longer in service. The check writes nothing at all in that case: not
	// the transition, and not a failure count, which would be the new winner's
	// first failure on a history it never had.
	ErrSelectorChanged = errors.New("the selector changed while this check was probing")

	// ErrNoFallback reports that the winner has failed at the policy's threshold
	// and the selector names no fallback to move to. There is nothing to publish
	// that has been proved, so the file is left as it is and the address in
	// service stays there until an apply or a pin gives the selector one.
	ErrNoFallback = errors.New("the failing winner has no fallback to move to")

	// ErrFallbackRefused reports that the fallback could not be published: it is
	// not an address a rewrite target may name, or its identity proof did not
	// pass. Either way the transition is refused and the selector is untouched,
	// while the failure count stays on disk at the threshold so the next check
	// tries again rather than starting the count over.
	ErrFallbackRefused = errors.New("the fallback could not be published")
)

// AddressReport is one published address's own verdict from one check. It is per
// address rather than per check because the addresses are held to different things:
// a global winner answers to the global profiles and a CloudFront mapping to its
// own hostname's, and a verdict about one says nothing about the other.
type AddressReport struct {
	// Address is the published address, and is empty when the selector names none.
	Address string
	// Hostname is the CloudFront profile hostname this address is published for,
	// and is empty for the global winner.
	Hostname string
	// Verdict is what the proof of this address concluded.
	Verdict Verdict
	// Detail is what the proof said when it refused, or why there was no
	// conclusion. It is never an input to any decision.
	Detail string
	// Bytes is the uncharged body this address's probes read to reach their
	// verdict, refusals included.
	Bytes int64
}

// Result is what one check did.
//
// Every field describes what happened. Health is the document this check wrote and
// is the zero value when it wrote none, which is a state no writer of this project
// produces and is how a caller tells a written document from an unwritten one.
// Transition is the selector this check published, and is nil on every path that
// did not publish one - including every path that returned an error, which is
// what keeps a report from naming a transition that was never written.
type Result struct {
	// Winner is the global winner's own verdict. The health document records this
	// verdict and no other: it is the one address the selector can move away from.
	Winner AddressReport
	// CloudFront is one entry per published per-hostname mapping, ordered by
	// hostname. A mapping that failed is reported here and does not count against
	// the winner, because the four fields the document has describe one address.
	CloudFront []AddressReport
	// Bytes is every uncharged body byte this check read, including the refused
	// probes' and the fallback's. Nothing on disk records it, because the daily
	// bandwidth budget does not pay for identity proofs, and health checking is
	// not allowed to start paying for them.
	Bytes int64
	// FailedClosed is why the previous health document could not be read, and is
	// empty when it could. It is reported rather than swallowed because a count
	// that starts at the policy's threshold has to say that it did.
	FailedClosed string
	// Health is the document this check wrote.
	Health state.HealthState
	// Transition is the selector this check published, or nil when it published
	// none.
	Transition *state.Selector
}

// WroteHealth reports whether this check wrote the health document, which is what
// a report has to know before it prints the counter: a counter it did not write
// is not a fact about the router.
func (r Result) WroteHealth() bool {
	return r.Health.SchemaVersion == state.SchemaVersion
}

// Options are the paths, the profiles, the policy's threshold, the clock and the
// deadlines one checker works through. Every path is a parameter rather than a
// constant because a test that wrote to /var/lib would be writing to the
// production router's state, and because a document whose timestamps a test can
// hand-derive is a document whose validator has something to check.
type Options struct {
	// Profiles are the identity profiles a proof is held to, kept apart by what
	// each is for. This is the optimizer's own set, so the rule that a proof covers
	// the subject's own group is one rule in the project rather than one per
	// package. Required: a checker with no profile could not prove anything, and
	// one that proved nothing would report a failure every two minutes forever.
	Profiles optimizer.Profiles

	// HealthPath is the document the consecutive-failure count is kept in.
	// Required.
	HealthPath string

	// SelectorPath is the document the published addresses are read from and, when
	// a transition is required, written to. Required.
	SelectorPath string

	// ControlLockPath is the lock every mutation of either document serialises on.
	// Required.
	ControlLockPath string

	// FailureThreshold is cdn.health.failure_threshold: how many consecutive
	// failures of the published winner move the resolver to the fallback. It is
	// the policy's number and not a constant of this package, because it is the
	// operator's tolerance for a broken address and not a decision of the
	// implementation. Required and greater than zero.
	FailureThreshold int

	// Now is the clock. A nil value means time.Now. One check reads it once, so
	// the health document and a selector written in the same check carry the same
	// instant.
	Now func() time.Time

	// WaveTimeout bounds one wave of concurrent proofs in the watch phase, before the
	// control lock is taken. The zero value means DefaultWaveTimeout, and the pass's
	// own deadline is this times the number of waves the pass needs, capped at
	// MaximumPassTimeout.
	WaveTimeout time.Duration

	// ProofConcurrency is how many of a subject's profile proofs run at once. The zero
	// value means optimizer.ProofConcurrency, which is the number an apply's final
	// proof uses over the same profiles; a case sets it to one when it needs the order
	// of the walk to be the order the profiles are configured in.
	ProofConcurrency int

	// ProofTimeout bounds the fallback's proof inside a transition, which is the
	// one piece of network I/O this package does under the control lock. The zero
	// value means the optimizer's FinalProofTimeout, the same bound an apply's
	// final proof has, because it is the same work under the same lock.
	ProofTimeout time.Duration
}

// Checker proves the addresses a selector has published and moves the resolver to
// the fallback when the published winner has failed at the policy's threshold.
//
// It is safe to use from more than one goroutine. Two checks in flight at once
// serialise on the control lock around each document's read-validate-change-write,
// so neither can add a failure on top of the other's, and a check that finds the
// selector published again under the lock refuses rather than acting on a
// conclusion about an address that is out of service.
type Checker struct {
	prober  Prober
	options Options
}

// NewChecker builds a checker for one set of profiles and one pair of documents.
//
// It returns an error rather than a checker that would report a healthy router
// every two minutes: a checker with no prober cannot prove anything, one with no
// path cannot read or write anything, a threshold of zero would move the address
// on its first refusal, and a configuration with no identity profile at all is a
// misconfigured router that is better told once than every two minutes.
func NewChecker(prober Prober, options Options) (*Checker, error) {
	if prober == nil {
		return nil, errors.New("a health check needs a prober to prove addresses with")
	}
	var missing []string
	for _, required := range []struct{ name, value string }{
		{"HealthPath", options.HealthPath},
		{"SelectorPath", options.SelectorPath},
		{"ControlLockPath", options.ControlLockPath},
	} {
		if strings.TrimSpace(required.value) == "" {
			missing = append(missing, required.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("a health check needs %s", strings.Join(missing, ", "))
	}
	if options.FailureThreshold <= 0 {
		return nil, fmt.Errorf("FailureThreshold must be greater than zero, got %d", options.FailureThreshold)
	}
	if len(options.Profiles.Global) == 0 && len(options.Profiles.ByHostname) == 0 {
		return nil, errors.New("a health check needs at least one identity profile: without one nothing could be proved")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.WaveTimeout <= 0 {
		options.WaveTimeout = DefaultWaveTimeout
	}
	if options.ProofConcurrency <= 0 {
		options.ProofConcurrency = optimizer.ProofConcurrency
	}
	if options.ProofTimeout <= 0 {
		options.ProofTimeout = optimizer.FinalProofTimeout
	}
	return &Checker{prober: prober, options: options}, nil
}

// Check proves every address the selector has published, records this check's
// verdict on the winner in the health document, and moves the resolver to the
// fallback when the winner has failed at the policy's threshold.
//
// The order is the whole of the safety argument:
//
//  1. read the selector, without the control lock;
//  2. prove the winner and every published mapping, without the control lock, under
//     one deadline for the pass;
//  3. if the winner's verdict is a cancellation, stop there - nothing is known, so
//     nothing is written;
//  4. take the control lock, read the selector again under it, and refuse if it was
//     published again in the meantime;
//  5. read the health document under the lock, apply the verdict, and write it
//     atomically at mode 0640 - a same-directory temporary file, a flush, and a
//     rename;
//  6. only if the counter has reached the threshold, prove the fallback and write
//     the selector through state.WriteJSONAtomic, both under the lock that is still
//     held.
//
// Step 5 is deliberately before step 6: a refused transition has to leave the
// counter at the threshold so the next check tries again, and a counter that was
// never stored would start the count over and never reach the threshold at all.
//
// The two deadlines are the two phases'. Step 6 is given the caller's context and
// its own ProofTimeout, not the watch deadline: the watch deadline was spent proving
// the address that just failed, and a transition that had to finish inside what is
// left of it would be refused by the check that was slow rather than by the host.
func (c *Checker) Check(ctx context.Context) (result Result, err error) {
	// The one thing a Result must never carry on a failing path is a transition
	// that was not published. The field is only set on the one path that publishes
	// one, and this takes it back on every other, so a caller that prints what it
	// was handed cannot print a publication that did not happen.
	defer func() {
		if err != nil {
			result.Transition = nil
		}
	}()

	current, err := c.readSelector()
	if err != nil {
		return Result{}, err
	}
	if current.Mode == "disabled" {
		// A disabled selector is not in service, whatever address its document still
		// names, and a check that moved one would be publishing a change nothing
		// asked for.
		return Result{Winner: AddressReport{
			Address: current.WinnerIP,
			Verdict: VerdictUnknown,
			Detail:  "the selector is disabled, so no address is in service to check",
		}}, nil
	}
	if current.WinnerIP == "" {
		return Result{Winner: AddressReport{
			Verdict: VerdictUnknown,
			Detail:  "the selector names no winner, so there is no address in service to check",
		}}, nil
	}

	// The watch phase, with no control lock held. The proofs are the reason: they take
	// seconds, and a shared lock held for that is a lock every apply, pin and unpin
	// waits behind.
	//
	// The deadline is the pass's own rather than one wave's, because the pass is not
	// one wave: the winner's profiles are answered at the documented limit and then
	// each published mapping is answered, and a pass that gave both of those one wave
	// would be reporting cut-short walks on any list longer than the limit.
	watch, cancelWatch := context.WithTimeout(ctx, c.passTimeout(len(current.CloudFront)))
	defer cancelWatch()
	winner := c.proveSubject(watch, publishedAddress(current.WinnerIP, ""))
	mappings := c.proveMappings(watch, current.CloudFront)
	result = Result{
		Winner:     winner,
		CloudFront: mappings,
		Bytes:      winner.Bytes + mappingsBytes(mappings),
	}
	if winner.Verdict == VerdictUnknown {
		// A cancellation is not a verdict about the address, so there is nothing to
		// record. The document stays as it was: a check that learned nothing may not
		// clear a count it did not earn, and may not invent one either.
		return result, nil
	}

	lock, err := filelock.Acquire(c.options.ControlLockPath)
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			return result, fmt.Errorf("%s: %w", c.options.ControlLockPath, optimizer.ErrControlLocked)
		}
		return result, err
	}
	defer func() { _ = lock.Close() }()

	// The selector is read again under the lock, because the read above happened
	// without it and a publication may have landed in between. A check that proved
	// generation 4 has nothing to say about the address in generation 5.
	fresh, err := c.readSelector()
	if err != nil {
		return result, err
	}
	if fresh.Generation != current.Generation {
		return result, fmt.Errorf("%w: this check proved generation %d and the selector now stands at %d",
			ErrSelectorChanged, current.Generation, fresh.Generation)
	}

	document, failedClosed := c.readHealth()
	moment := c.now()
	updated := applyVerdict(document, winner.Verdict, moment, c.options.FailureThreshold, fresh.LastSuccess, failedClosed)
	result.FailedClosed = failedClosed
	if err := state.WriteReplacementJSONAtomic(c.options.HealthPath, updated); err != nil {
		// The previous document is still on disk and no conclusion has been
		// recorded, so the next check reads the count as it was and adds to it.
		return result, err
	}
	result.Health = updated

	if winner.Verdict != VerdictFailed || updated.ConsecutiveFailures < c.options.FailureThreshold {
		return result, nil
	}
	published, proofBytes, err := c.moveToFallback(ctx, fresh, moment, winner.Detail)
	result.Bytes += proofBytes
	if err != nil {
		return result, err
	}
	result.Transition = &published
	return result, nil
}

// now is the checker's clock. One check reads it once, where the verdict is
// applied, so the health document and a selector written in the same check carry
// one instant rather than two readings that could differ across a year boundary or
// a second.
func (c *Checker) now() time.Time {
	return c.options.Now().UTC()
}

// readSelector reads the published selector. A document that is not there is a
// router that has never selected anything, which is a generation-zero selector
// rather than a refusal - there is nothing in service to check, and the caller is
// told so by the verdict rather than by an error. A document that is present and
// cannot be read is refused: it is the address the resolver is rewriting to right
// now, and reading past it would be reporting on a document nobody has.
func (c *Checker) readSelector() (state.Selector, error) {
	selector := state.Selector{}
	if err := state.ReadJSON(c.options.SelectorPath, &selector); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state.Selector{SchemaVersion: state.SchemaVersion, Mode: "auto"}, nil
		}
		return selector, fmt.Errorf("%s: read the selector: %w", c.options.SelectorPath, err)
	}
	return selector, nil
}

// readHealth reads the consecutive-failure document under the control lock and
// says why it had to be failed closed if it could not be read.
//
// A document that is absent is a router that has not been checked yet, which is
// not the same as one whose history is lost: a missing count starts at zero and a
// lost one starts at the policy's threshold. A document that is present and cannot
// be read - truncated, hand-edited, written by another build - is a history this
// build does not have, and the only safe reading of a history nobody can see is the
// one that does not vouch for the address.
func (c *Checker) readHealth() (state.HealthState, string) {
	document := state.HealthState{}
	if err := state.ReadJSON(c.options.HealthPath, &document); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return document, ""
		}
		return state.HealthState{}, fmt.Sprintf("%s could not be read, so the failure count starts at the policy threshold: %v",
			c.options.HealthPath, err)
	}
	return document, ""
}

// applyVerdict is the whole counter, and each branch is a decision about what may
// be claimed rather than an arithmetic detail:
//
//   - A corrupt document is read as the threshold already reached, and this check's
//     own verdict is then added to it. The two are separate facts - the history is
//     lost, and this check failed - and a count that pretended otherwise would hide
//     either one.
//   - A document whose verdicts are older than the selector's own last success is
//     about an address that is no longer in service, so the count starts again
//     rather than inheriting another address's failures. A new winner has to fail
//     the threshold in its own right, and the cost of getting this backwards is
//     only that an address with two accumulated failures has to fail twice more,
//     which is at most two more check intervals.
//   - A success clears the count, because the count is of *consecutive* failures
//     and two failures either side of a success are not consecutive.
//   - Healthy is true only where a completed proof set it. Nothing else in this
//     file can make it true, which is the property the whole package is for.
func applyVerdict(previous state.HealthState, verdict Verdict, moment time.Time, threshold int, publishedAt time.Time, failedClosed string) state.HealthState {
	updated := state.HealthState{SchemaVersion: state.SchemaVersion}
	if failedClosed == "" {
		updated = previous
		updated.SchemaVersion = state.SchemaVersion
		if !describesPublishedAddress(previous, publishedAt) {
			updated.ConsecutiveFailures = 0
			updated.Healthy = false
		}
	} else {
		updated.ConsecutiveFailures = threshold
	}
	switch verdict {
	case VerdictHealthy:
		updated.ConsecutiveFailures = 0
		updated.Healthy = true
		updated.LastSuccess = moment
	case VerdictFailed:
		updated.ConsecutiveFailures++
		updated.Healthy = false
		updated.LastFailure = moment
	}
	return updated
}

// describesPublishedAddress reports whether the health document's verdicts are
// about the address the selector is publishing now, which is the question the
// counter's attribution turns on.
//
// The document has no address and no generation of its own - it holds the four
// fields the plan documents and nothing else - so the attribution is made from the
// two timestamps it does have against the selector's own: the selector's
// last_success is the instant its current winner was proved, and every verdict this
// package writes is stamped after that. Strictly after, and not at or after, so
// the transition's own write - which stamps the same instant on both documents -
// counts as a new winner rather than as a verdict about the old one.
func describesPublishedAddress(document state.HealthState, publishedAt time.Time) bool {
	latest := document.LastFailure
	if document.LastSuccess.After(latest) {
		latest = document.LastSuccess
	}
	return latest.After(publishedAt)
}

// moveToFallback is the transition: the resolver moves to the fallback, and the
// address that failed becomes the fallback itself.
//
// The fallback is proved first, under the control lock that is already held, and
// for the same reason an apply's final proof is: the store has to follow the proof
// immediately, because an address proved and then written after a pause is an
// address proved at some other time. The proof is the group-scoped one - a fallback
// is a global address, so it is held to the global profiles and no other - and it
// is bounded by ProofTimeout, so the hold is seconds rather than minutes.
//
// The document that comes out of it is one the state package accepts, field by
// field:
//
//   - winner_ip becomes the address that was just proved, and last_success is the
//     instant of that proof, because a winner with no last_success is refused;
//   - winner_proof_until is that instant plus the optimizer's proof TTL, because a
//     proof may not precede the success it was issued for;
//   - fallback_ip becomes the address that failed. It differs from the new winner
//     because the state package already refuses a selector whose fallback equals
//     its winner, which is also why the swap is the only shape available;
//   - generation moves once, so the change is visible to a reader of the document
//     and so the next check sees a different generation from the one this check
//     probed;
//   - mode, provider, the CloudFront mappings and the configuration digest are
//     carried over untouched, because a health check changes which address is in
//     service and nothing else. A pinned selector stays pinned, with the address
//     the operator pinned now named as the fallback.
//
// A refusal returns before the write, so the file is left exactly as it was found
// and the caller is told which of the three reasons it was: no fallback to move to,
// an address a rewrite target may not name, or a proof that did not pass.
func (c *Checker) moveToFallback(ctx context.Context, current state.Selector, moment time.Time, detail string) (state.Selector, int64, error) {
	if current.FallbackIP == "" {
		return state.Selector{}, 0, fmt.Errorf("%w: %s is failing and %s names none",
			ErrNoFallback, current.WinnerIP, c.options.SelectorPath)
	}
	subject := publishedAddress(current.FallbackIP, "")
	if err := subject.Validate(); err != nil {
		return state.Selector{}, 0, fmt.Errorf("%w: the fallback %s is not an address a rewrite target may name: %v",
			ErrFallbackRefused, current.FallbackIP, err)
	}
	proof, cancelProof := context.WithTimeout(ctx, c.options.ProofTimeout)
	defer cancelProof()
	report := c.proveSubject(proof, subject)
	if report.Verdict != VerdictHealthy {
		return state.Selector{}, report.Bytes, fmt.Errorf("%w: the fallback %s is not serving: %s",
			ErrFallbackRefused, current.FallbackIP, report.Detail)
	}

	published := current
	published.SchemaVersion = state.SchemaVersion
	published.Generation = current.Generation + 1
	published.WinnerIP = current.FallbackIP
	published.FallbackIP = current.WinnerIP
	published.LastSuccess = moment
	published.WinnerProofUntil = moment.Add(optimizer.WinnerProofTTL)
	if detail != "" {
		published.LastFailure = detail
	}
	if err := state.WriteJSONAtomic(c.options.SelectorPath, published); err != nil {
		return state.Selector{}, report.Bytes, err
	}
	return published, report.Bytes, nil
}

// proveMappings proves every published per-hostname mapping, in hostname order so the
// verdicts a check reports are the same whatever order the selector's map happened to
// iterate in, and at the same concurrency limit the winner's own profiles are proved
// at. Each mapping is one address held to one profile, so this is the second fan-out
// of the pass rather than part of the first.
//
// Every mapping gets a verdict, including the ones a deadline or a cancellation kept
// the check from reaching: a hostname that was not checked is reported as not checked,
// which is the unattempted-slot rule applied to the loop rather than to a single
// address's profile list. Each report owns its own slot, so the two orderings - the
// walk's and the document's - never have to agree.
func (c *Checker) proveMappings(ctx context.Context, mappings map[string]string) []AddressReport {
	if len(mappings) == 0 {
		return nil
	}
	hostnames := make([]string, 0, len(mappings))
	for hostname := range mappings {
		hostnames = append(hostnames, hostname)
	}
	slices.Sort(hostnames)
	reports := make([]AddressReport, len(hostnames))
	parallelFor(ctx, len(hostnames), c.options.ProofConcurrency, func(index int) {
		hostname := hostnames[index]
		reports[index] = c.proveSubject(ctx, publishedAddress(mappings[hostname], hostname))
	})
	return reports
}

// mappingsBytes is the uncharged body total of the per-hostname verdicts.
func mappingsBytes(reports []AddressReport) int64 {
	var total int64
	for _, report := range reports {
		total += report.Bytes
	}
	return total
}

// proofAnswer is one profile's answer to a proof: whether its probe ran at all,
// what it measured, and what it said if it refused. The state is a named field
// rather than an absent error because a profile that was never dispatched and a
// profile that answered cleanly are otherwise indistinguishable, and one of them
// must not read as the other.
type proofAnswer struct {
	// dispatched is true only once a probe has actually been made for this
	// profile. It is the zero value of a slot nobody filled, which is the direction
	// that fails.
	dispatched bool
	// bytes is what this one proof read, refusals included, carried in the slot
	// because a concurrent walk cannot add to one counter without either a lock or a
	// total that depends on which worker finished first.
	bytes int64
	err   error
}

// proveSubject proves one published address against the profiles its own group is
// held to, and returns that address's own verdict.
//
// The walk is concurrent, at the same documented limit an apply's final proof uses and
// for the same reason: the time a proof takes is one answer's time rather than the sum
// of the list's, and a serial walk over a realistic forced-ECH list would spend the
// pass deadline on a perfectly healthy address and report a cut-short walk as a
// failure. The verdict is then read in profile order, so which profile refused is a
// statement about the configuration rather than about which worker lost a race.
//
// Two refusals happen before a socket is opened. An address the selector names that
// is not one a rewrite target may name is not dialled at all, because a candidate
// built from it would connect somewhere nobody chose. And a group this
// configuration names no profile for is a failure rather than a pass, because
// nothing proved it.
func (c *Checker) proveSubject(ctx context.Context, subject candidate.Candidate) AddressReport {
	report := AddressReport{Address: subject.IP.String(), Hostname: subject.Hostname}
	if err := subject.Validate(); err != nil {
		report.Verdict = VerdictFailed
		report.Detail = fmt.Sprintf("%s cannot be proved: %v", report.Address, err)
		return report
	}
	applicable := c.options.Profiles.ForSubject(subject)
	if len(applicable) == 0 {
		report.Verdict = VerdictFailed
		report.Detail = fmt.Sprintf("no identity profile names %s, so nothing proved it", describeSubject(subject))
		return report
	}

	answers := make([]proofAnswer, len(applicable))
	parallelFor(ctx, len(applicable), c.options.ProofConcurrency, func(index int) {
		metrics, err := c.prober.HTTPS(ctx, subject, healthProfile(applicable[index]))
		// Each answer owns its own slot: no two workers write the same element, and
		// the bytes are carried in the slot rather than added to a shared counter, so
		// the total does not depend on which worker finished first.
		//
		// The bytes are carried rather than dropped because an identity proof is
		// deliberately outside the daily budget: the refused proof - the one that spent
		// bytes and published nothing - is exactly the case whose cost would otherwise
		// go unrecorded, and the sum below adds them all before any error is looked at.
		answers[index] = proofAnswer{dispatched: true, bytes: metrics.BodyBytes, err: err}
	})
	// Summed before the verdict, whatever the answers say.
	for _, answer := range answers {
		report.Bytes += answer.bytes
	}
	report.Verdict, report.Detail = decideVerdict(ctx, subject, answers)
	return report
}

// passTimeout is the deadline for a watch phase with this many published mappings.
// The winner's own group and the mappings are two separate fan-outs, so the pass
// costs a wave for each wave either of them needs.
func (c *Checker) passTimeout(mappings int) time.Duration {
	limit := c.options.ProofConcurrency
	waves := wavesFor(len(c.options.Profiles.Global), limit) + wavesFor(mappings, limit)
	if waves < 1 {
		waves = 1
	}
	scaled := time.Duration(waves) * c.options.WaveTimeout
	if scaled > MaximumPassTimeout {
		return MaximumPassTimeout
	}
	return scaled
}

// wavesFor is how many waves of limit-at-a-time a list of count items needs. An empty
// list needs none, because there is nothing to wait for.
func wavesFor(count, limit int) int {
	if count <= 0 || limit < 1 {
		return 0
	}
	return (count + limit - 1) / limit
}

// parallelFor runs body for every index below count, with at most limit calls in
// flight, and stops handing out work the moment ctx is done. The indexes it never
// reached are therefore left for the caller to notice: a slot no body filled is the
// unattempted case, and the verdict walk treats it as the refusal it is.
//
// A trap for the next caller, recorded because it is a hang and not a failure: body
// must not return an error and must not leave its worker. A worker that returns early
// leaves a slot unfilled, the feeder blocks on an unbuffered channel with no reader
// left to take the next index, and nothing closes that channel - so the pass hangs
// rather than failing. Both bodies here record into their own slot and return.
func parallelFor(ctx context.Context, count, limit int, body func(index int)) {
	if count == 0 {
		return
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
				body(index)
			}
		}()
	}
	for index := 0; index < count; index++ {
		select {
		case work <- index:
		case <-ctx.Done():
			close(work)
			group.Wait()
			return
		}
	}
	close(work)
	group.Wait()
}

// decideVerdict turns a walk's answers into one verdict, and the order of the
// three cases is the design:
//
//  1. A profile that was dispatched and refused is a failure, whatever the refusal
//     was. A chain that is not for the hostname, a status the profile does not
//     expect, a required header that is missing, a refused connection and a probe
//     that ran out of time are all the same fact about the host: it is not serving
//     what the selector is publishing it for. The first such refusal names the
//     verdict, because a report that lists three of them says nothing an operator
//     can act on that one does not.
//  2. A walk that did not finish is not a pass. It is "we do not know" when the walk
//     was cut short by a cancellation, which says nothing about the host whoever
//     asked for it, and a failure when a deadline expired before the profiles were
//     asked - which is this build's patience running out on a host that did not
//     answer, and noticing that is what a health check is for.
//  3. Everything else is healthy, which is reachable only when every profile of the
//     group was dispatched and none of them refused.
func decideVerdict(ctx context.Context, subject candidate.Candidate, answers []proofAnswer) (Verdict, string) {
	dispatched := 0
	incomplete := false
	for _, answer := range answers {
		if !answer.dispatched {
			incomplete = true
			continue
		}
		dispatched++
		switch {
		case answer.err == nil:
			continue
		case errors.Is(answer.err, context.Canceled):
			// The caller went away. That is not a statement about the host, so it
			// can neither fail the address nor vouch for it.
			incomplete = true
		default:
			// The prober's own message names the profile hostname and the address
			// it was asked about, so it is carried as it stands: repeating it here
			// would make an operator read the same sentence twice.
			return VerdictFailed, answer.err.Error()
		}
	}
	if !incomplete {
		return VerdictHealthy, ""
	}
	reached := fmt.Sprintf("%d of the %d profiles it is held to", dispatched, len(answers))
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return VerdictUnknown, fmt.Sprintf("the proof of %s was cut short after %s", subject.IP, reached)
	case ctx.Err() == nil:
		// A profile gave up on a walk this check never cut short. It is still not
		// knowledge of the host, so it is still "we do not know" rather than a
		// verdict, and the detail says which of the two it was.
		return VerdictUnknown, fmt.Sprintf("the proof of %s stopped after %s because a profile was cancelled", subject.IP, reached)
	default:
		return VerdictFailed, fmt.Sprintf("%s was proved against only %s: %v", subject.IP, reached, ctx.Err())
	}
}

// healthProfile is the profile a health check proves an address with, and the one
// change it makes is the method.
//
// A profile that names no body is proved with a HEAD. It asks the same question -
// the same chain for the same hostname, the same name in SNI and in Host, the same
// expected status and the same required headers - and asks it without transferring
// a document, which is what makes the check low-traffic: the selector is watched
// every two minutes and the response body is the one part of the identity the
// profile itself never claimed anything about.
//
// A profile that names a body digest keeps its GET, because a HEAD response has no
// body to hash and a check that asked for HEAD from such a profile would be
// answering a question the profile did not pose. The body is then read through the
// same identity path and the same cap as every other identity probe
// (prober.DefaultMaxIdentityBodyBytes, 64 KiB), because a health check that raised
// the ceiling for itself would be a second, larger uncharged egress.
//
// A profile that already asks for a HEAD is left asking for one. There is no third
// case: the candidate package's own validator holds a profile to GET or HEAD, so a
// method outside those two cannot reach this.
func healthProfile(profile candidate.ProbeProfile) candidate.ProbeProfile {
	if profile.BodySHA256 != "" {
		return profile
	}
	if profile.Method == "" || profile.Method == http.MethodGet {
		profile.Method = http.MethodHead
	}
	return profile
}

// publishedAddress is a candidate built from an address the selector is already
// publishing. The source is the retained one, because that is what the optimizer
// labels an address the selector is already using with, and the group is decided
// by whether the address is published for a hostname.
func publishedAddress(address, hostname string) candidate.Candidate {
	provider := candidate.ProviderCloudflare
	if hostname != "" {
		provider = candidate.ProviderCloudFront
	}
	return candidate.Candidate{
		Provider: provider,
		IP:       parseAddress(address),
		Source:   candidate.SourceRetained,
		Hostname: hostname,
	}
}

// parseAddress parses an address a selector document names. A value that is not an
// address becomes the zero value, which proveSubject refuses through the candidate
// package's own rule, so a hand-edited document cannot reach a socket.
func parseAddress(value string) netip.Addr {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
}

// describeSubject names what a profile set is missing, for a refusal that has to
// say which group it is about.
func describeSubject(subject candidate.Candidate) string {
	if subject.Hostname != "" {
		return fmt.Sprintf("the group of %s", subject.Hostname)
	}
	return "the global group"
}
