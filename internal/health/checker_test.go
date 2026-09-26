package health_test

// This file is an external test package, and it has to be: the checker takes
// optimizer.Profiles, so an in-package test file could not import the package it
// is testing. Every case here drives the real checker, the real filelock, the
// real state writer and the real state validators, and the only thing replaced is
// the prober - the one component whose job is to open a socket to a CDN.
//
// The expectations are hand-derived literals. The three that matter most are the
// failure counter, the generation a transition moves to, and the timestamps: a
// transition at 04:04 with a five minute proof is a selector stamped 04:09, and
// those are written out rather than computed from the package's own constants.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/health"
	"mosdns-router/internal/measure"
	"mosdns-router/internal/optimizer"
	"mosdns-router/internal/state"
)

// baseMoment is the clock the first check of a case runs at, and publishedMoment
// is when the fixture's winner was proved: an hour earlier, so every timestamp
// this file stamps is later than the selector's own last_success. That is what
// makes a health document read from disk a document about the address still in
// service, which is the question the checker's counter restart rule answers.
var (
	baseMoment      = time.Date(2026, 9, 26, 4, 0, 0, 0, time.UTC)
	publishedMoment = time.Date(2026, 9, 26, 3, 0, 0, 0, time.UTC)
)

// The two addresses every fixture publishes. They differ because the state
// package refuses a selector whose fallback equals its winner, and because
// different is what makes the health transition's swap a document that package
// can accept at all.
const (
	winnerIP   = "104.16.1.1"
	fallbackIP = "104.16.0.1"
)

// deadlineWindow is the tolerance on a case that reads a context deadline. The
// deadline is a wall-clock instant built from the moment the check asked for one, so
// it lands within microseconds of that moment; a window this wide absorbs a loaded
// host without being wide enough to confuse one wave's worth of time with two.
const deadlineWindow = 30 * time.Millisecond

// representativeDomain is the global identity profile every fixture is proved
// against, and cloudFrontHostname is the per-hostname half of the anti-leak rule:
// a global address is never proved against it, and its own address is never
// proved against the representative domain.
const (
	representativeDomain = "speed.cloudflare.com"
	cloudFrontHostname   = "assets.example.test"
	secondFrontHostname  = "media.example.test"
)

// notServing is what a host that has stopped serving looks like to a prober. The
// message is the prober's own, so the detail a report carries is the one an
// operator would see from a measurement run.
var notServing = errors.New("speed.cloudflare.com at 104.16.1.1: tls: failed to verify certificate")

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// probeCall is one identity proof as the prober was asked to make it. The method
// is recorded because the choice between HEAD and GET is the difference between
// a check that asks a server for nothing and one that asks it for a document.
type probeCall struct {
	address  string
	hostname string
	method   string
	digest   string
}

// fakeProber answers every identity proof from the case's own function and
// records what it was asked. It mirrors the complete real call: the subject and
// the whole profile, because a case that asserts the method can only do so from
// the profile the checker actually handed over.
type fakeProber struct {
	mutex  sync.Mutex
	calls  []probeCall
	answer func(probeCall) (measure.HTTPMetrics, error)
	// delay is how long every proof takes, which is how a slow edge is expressed
	// without a socket: the wall time a walk spends is the delay times the number of
	// waves, and a case that cannot see a wave has no way to see the bug.
	delay time.Duration
	// deadlines records the deadline each proof was handed, so a case can read the
	// pass's own budget rather than infer it from what happened.
	deadlines []time.Time
	// inFlight and peakInFlight are how many proofs were running at the same moment,
	// and the most that ever were. A serial walk peaks at one.
	inFlight, peakInFlight int
}

func (p *fakeProber) HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (measure.HTTPMetrics, error) {
	call := probeCall{
		address:  subject.IP.String(),
		hostname: profile.Hostname,
		method:   profile.Method,
		digest:   profile.BodySHA256,
	}
	p.mutex.Lock()
	p.calls = append(p.calls, call)
	if deadline, ok := ctx.Deadline(); ok {
		p.deadlines = append(p.deadlines, deadline)
	}
	p.inFlight++
	if p.inFlight > p.peakInFlight {
		p.peakInFlight = p.inFlight
	}
	p.mutex.Unlock()

	defer func() {
		p.mutex.Lock()
		p.inFlight--
		p.mutex.Unlock()
	}()
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			// The prober package's own rule: a request cut short by its context
			// answers with the context's error and no measurements, because a number
			// beside a timeout is a number a caller can mistake for one.
			return measure.HTTPMetrics{}, ctx.Err()
		}
	}
	if p.answer == nil {
		return measure.HTTPMetrics{Status: http.StatusOK}, nil
	}
	return p.answer(call)
}

// peak records the most proofs that were ever in flight at once, which is what tells
// a concurrent walk from a serial one.
func (p *fakeProber) peak() int {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.peakInFlight
}

// deadline is the pass deadline the proofs were handed. Every proof of a pass shares
// one context, so the first reading is the pass's budget.
func (p *fakeProber) deadline(t *testing.T) time.Time {
	t.Helper()
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.deadlines) == 0 {
		t.Fatal("no proof recorded the deadline it was handed")
	}
	return p.deadlines[0]
}

// asked returns the recorded proofs as "address hostname method", sorted, so a
// case compares a literal list rather than the order two runs happened to finish
// in.
func (p *fakeProber) asked() []string {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	described := make([]string, 0, len(p.calls))
	for _, call := range p.calls {
		described = append(described, call.address+" "+call.hostname+" "+call.method)
	}
	slices.Sort(described)
	return described
}

// probesOf returns how many proofs were made of one address, which is what tells
// a check that re-proved the address from one that only reported about it.
func (p *fakeProber) probesOf(address string) int {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	count := 0
	for _, call := range p.calls {
		if call.address == address {
			count++
		}
	}
	return count
}

// refusing answers every proof with a refusal and the given body bytes, which is
// a host that has stopped serving the hostname it used to.
func refusing(bytes int64) func(probeCall) (measure.HTTPMetrics, error) {
	return func(probeCall) (measure.HTTPMetrics, error) {
		return measure.HTTPMetrics{BodyBytes: bytes}, notServing
	}
}

// refusingWinner refuses the winner's proofs and answers everything else, which is
// the shape of the incident this component exists for: the address in service has
// stopped serving while the address beside it still works, and that is what makes
// the fallback worth falling back to.
func refusingWinner(bytes int64) func(probeCall) (measure.HTTPMetrics, error) {
	return func(call probeCall) (measure.HTTPMetrics, error) {
		if call.address != winnerIP {
			return measure.HTTPMetrics{Status: http.StatusOK}, nil
		}
		return measure.HTTPMetrics{BodyBytes: bytes}, notServing
	}
}

// world is one checker's world: the three paths, the prober, the clock and the
// options. Everything is inside a temporary directory, so no case can reach
// /var/lib.
type world struct {
	t            *testing.T
	directory    string
	selectorPath string
	healthPath   string
	lockPath     string
	prober       *fakeProber
	moment       time.Time
	// step is how far the clock moves on each reading, and readings counts them. A
	// zero step is a fixed clock, which is what a case whose subject is a single
	// document's contents wants; a case whose subject is *which* reading a timestamp
	// came from needs a clock that moves.
	step     time.Duration
	readings int
	options  health.Options
	checker  *health.Checker
}

func newWorld(t *testing.T, selector state.Selector, profiles optimizer.Profiles, threshold int) *world {
	t.Helper()
	directory := t.TempDir()
	w := &world{
		t:            t,
		directory:    directory,
		selectorPath: filepath.Join(directory, "cdn-selector.json"),
		healthPath:   filepath.Join(directory, "health.json"),
		lockPath:     filepath.Join(directory, "control.lock"),
		prober:       &fakeProber{},
		moment:       baseMoment,
	}
	w.options = health.Options{
		Profiles:         profiles,
		HealthPath:       w.healthPath,
		SelectorPath:     w.selectorPath,
		ControlLockPath:  w.lockPath,
		FailureThreshold: threshold,
		Now: func() time.Time {
			if w.step == 0 {
				return w.moment
			}
			w.readings++
			return w.moment.Add(time.Duration(w.readings) * w.step)
		},
		WaveTimeout:  time.Second,
		ProofTimeout: time.Second,
	}
	w.rebuild()
	w.writeSelector(selector)
	return w
}

// rebuild makes a checker from the world's current options, which is how a case
// changes a deadline or a profile set and gets a checker that uses it.
func (w *world) rebuild() {
	w.t.Helper()
	checker, err := health.NewChecker(w.prober, w.options)
	if err != nil {
		w.t.Fatalf("build the checker: %v", err)
	}
	w.checker = checker
}

func (w *world) writeSelector(selector state.Selector) {
	w.t.Helper()
	if err := state.WriteJSONAtomic(w.selectorPath, selector); err != nil {
		w.t.Fatalf("write the selector fixture: %v", err)
	}
}

// writeHealth stores a health document as a previous check left it, so a case can
// start from a counter that is already counting.
func (w *world) writeHealth(document state.HealthState) {
	w.t.Helper()
	if err := state.WriteJSONAtomic(w.healthPath, document); err != nil {
		w.t.Fatalf("write the health fixture: %v", err)
	}
}

// writeRaw puts bytes on disk without validating them, which is how a corrupt
// document is presented to a check.
func (w *world) writeRaw(path, contents string) {
	w.t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		w.t.Fatalf("write %s: %v", path, err)
	}
}

func (w *world) readSelectorBytes() string {
	w.t.Helper()
	contents, err := os.ReadFile(w.selectorPath)
	if err != nil {
		w.t.Fatalf("read the selector: %v", err)
	}
	return string(contents)
}

// readSelector reads the published selector back through the state package, so a
// case asserts the document that is on disk rather than the value the checker
// handed back.
func (w *world) readSelector() state.Selector {
	w.t.Helper()
	published := state.Selector{}
	if err := state.ReadJSON(w.selectorPath, &published); err != nil {
		w.t.Fatalf("read the selector: %v", err)
	}
	return published
}

func (w *world) healthFileExists() bool {
	w.t.Helper()
	if _, err := os.Stat(w.healthPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		w.t.Fatalf("inspect the health document: %v", err)
	}
	return true
}

func (w *world) readHealthBytes() string {
	w.t.Helper()
	contents, err := os.ReadFile(w.healthPath)
	if err != nil {
		w.t.Fatalf("read the health document: %v", err)
	}
	return string(contents)
}

// identityProfile is one global identity profile as this project builds it: a GET
// of the hostname's root expecting 200, with no body digest named.
func identityProfile(hostname string) candidate.ProbeProfile {
	return candidate.ProbeProfile{
		Hostname:       hostname,
		URL:            "https://" + hostname + "/",
		Method:         http.MethodGet,
		Port:           443,
		ExpectedStatus: []int{http.StatusOK},
	}
}

// profilesFor is the profile set every case uses unless it says otherwise: one
// global profile and one profile per CloudFront hostname, which is the shape the
// CLI builds from the policy and the operator's documents.
func profilesFor() optimizer.Profiles {
	return optimizer.Profiles{
		Global: []candidate.ProbeProfile{identityProfile(representativeDomain)},
		ByHostname: map[string]candidate.ProbeProfile{
			cloudFrontHostname: identityProfile(cloudFrontHostname),
		},
	}
}

// publishedSelector is the selector a nightly apply leaves behind: a winner proved
// an hour ago, a first fallback, and one CloudFront mapping.
func publishedSelector() state.Selector {
	return state.Selector{
		SchemaVersion: state.SchemaVersion,
		Generation:    4,
		Mode:          "auto",
		Provider:      "cloudflare",
		WinnerIP:      winnerIP,
		FallbackIP:    fallbackIP,
		CloudFront:    map[string]string{cloudFrontHostname: "104.16.2.10"},
		LastSuccess:   publishedMoment,
	}
}

// check runs one check and fails the case if it returned an error, which is what
// a case that is not about a refusal wants.
func (w *world) check() health.Result {
	w.t.Helper()
	result, err := w.checker.Check(context.Background())
	if err != nil {
		w.t.Fatalf("check: %v", err)
	}
	return result
}

// ---------------------------------------------------------------------------
// the failure counter and the transition
// ---------------------------------------------------------------------------

// The threshold is three, and the first two failures are the ones that must not
// move anything: a check that moved the selector on its first refusal would take
// a working address out of service over one lost packet.
func TestOneAndTwoConsecutiveFailuresDoNotMoveTheSelector(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	before := w.readSelectorBytes()

	first := w.check()
	if first.Winner.Verdict != health.VerdictFailed {
		t.Fatalf("the first failure's verdict = %v, want %v", first.Winner.Verdict, health.VerdictFailed)
	}
	if first.Transition != nil {
		t.Fatalf("the first failure published a transition: %+v", *first.Transition)
	}
	if first.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures after one check = %d, want 1", first.Health.ConsecutiveFailures)
	}
	if first.Health.Healthy {
		t.Error("the health document reports a failed winner as healthy")
	}
	if !first.Health.LastFailure.Equal(baseMoment) {
		t.Errorf("last failure = %s, want %s", first.Health.LastFailure, baseMoment)
	}

	w.moment = baseMoment.Add(2 * time.Minute)
	second := w.check()
	if second.Health.ConsecutiveFailures != 2 {
		t.Errorf("consecutive failures after two checks = %d, want 2", second.Health.ConsecutiveFailures)
	}
	if second.Transition != nil {
		t.Fatalf("the second failure published a transition: %+v", *second.Transition)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Errorf("two failures changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// The third consecutive failure is the one the policy documents as a rollback,
// and the document it leaves behind is the one the state package has to accept:
// the fallback becomes the winner, the address that failed becomes the fallback
// (they must differ, which is what makes the swap legal), the generation moves
// once, and the winner's proof follows the success it was issued for.
func TestTheThirdConsecutiveFailureMovesTheSelectorToItsFallback(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	w.check()
	w.moment = baseMoment.Add(2 * time.Minute)
	w.check()

	w.moment = baseMoment.Add(4 * time.Minute)
	third := w.check()
	if third.Transition == nil {
		t.Fatalf("the third failure published no transition, detail: %s", third.Winner.Detail)
	}
	// The three failures were counted against the address that just left service, and
	// the document this check leaves describes the one that replaced it.
	documented := state.HealthState{}
	if err := state.ReadJSON(w.healthPath, &documented); err != nil {
		t.Fatalf("read the health document: %v", err)
	}
	if !documented.Healthy || documented.ConsecutiveFailures != 0 {
		t.Errorf("the document after a transition = %+v, want a healthy count of 0 for the address in service", documented)
	}

	published := w.readSelector()
	want := state.Selector{
		SchemaVersion:    state.SchemaVersion,
		Generation:       5,
		Mode:             "auto",
		Provider:         "cloudflare",
		WinnerIP:         fallbackIP,
		WinnerProofUntil: time.Date(2026, 9, 26, 4, 9, 0, 0, time.UTC),
		FallbackIP:       winnerIP,
		CloudFront:       map[string]string{cloudFrontHostname: "104.16.2.10"},
		LastSuccess:      time.Date(2026, 9, 26, 4, 4, 0, 0, time.UTC),
		LastFailure:      notServing.Error(),
	}
	if published.WinnerIP != want.WinnerIP || published.FallbackIP != want.FallbackIP ||
		published.Generation != want.Generation || !published.LastSuccess.Equal(want.LastSuccess) ||
		!published.WinnerProofUntil.Equal(want.WinnerProofUntil) || published.Mode != want.Mode ||
		published.Provider != want.Provider || published.LastFailure != want.LastFailure {
		t.Errorf("published selector:\n got %+v\nwant %+v", published, want)
	}
	if err := published.Validate(); err != nil {
		t.Errorf("the published selector is not one the state package accepts: %v", err)
	}
	if published.CloudFront[cloudFrontHostname] != "104.16.2.10" {
		t.Errorf("the transition changed the CloudFront mapping: %v", published.CloudFront)
	}
	if got := w.prober.probesOf(fallbackIP); got != 1 {
		t.Errorf("the fallback was proved %d times, want 1 proof before publication", got)
	}
}

// A success is the only thing that clears the counter, and clearing it is what
// stops two failures tonight and two tomorrow from adding up to a rollback of an
// address that is serving.
func TestASuccessfulCheckResetsTheFailureCount(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	w.check()
	w.moment = baseMoment.Add(2 * time.Minute)
	w.check()

	w.moment = baseMoment.Add(4 * time.Minute)
	w.prober.answer = nil
	third := w.check()
	if third.Winner.Verdict != health.VerdictHealthy {
		t.Fatalf("the verdict = %v, want %v", third.Winner.Verdict, health.VerdictHealthy)
	}
	if third.Health.ConsecutiveFailures != 0 {
		t.Errorf("consecutive failures after a success = %d, want 0", third.Health.ConsecutiveFailures)
	}
	if !third.Health.Healthy {
		t.Error("a successful check left the health document unhealthy")
	}
	if !third.Health.LastSuccess.Equal(baseMoment.Add(4 * time.Minute)) {
		t.Errorf("last success = %s, want %s", third.Health.LastSuccess, baseMoment.Add(4*time.Minute))
	}
	if !third.Health.LastFailure.Equal(baseMoment.Add(2 * time.Minute)) {
		t.Errorf("last failure = %s, want the second check's %s", third.Health.LastFailure, baseMoment.Add(2*time.Minute))
	}
	if third.Transition != nil {
		t.Errorf("a successful check published a transition: %+v", *third.Transition)
	}
}

// The counter counts consecutive failures of the address in service, so a success
// in the middle has to start the count again rather than leaving the earlier two
// failures on the books for the next one.
func TestTheCountRestartsAfterASuccess(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	w.check()
	w.moment = baseMoment.Add(2 * time.Minute)
	w.check()

	w.moment = baseMoment.Add(4 * time.Minute)
	w.prober.answer = nil
	w.check()

	w.moment = baseMoment.Add(6 * time.Minute)
	w.prober.answer = refusingWinner(12)
	fourth := w.check()
	w.moment = baseMoment.Add(8 * time.Minute)
	fifth := w.check()
	if fifth.Health.ConsecutiveFailures != 2 {
		t.Errorf("two failures after a success = %d, want 2", fifth.Health.ConsecutiveFailures)
	}
	if fifth.Transition != nil {
		t.Errorf("two failures after a success published a transition: %+v", *fifth.Transition)
	}
	if fourth.Transition != nil {
		t.Errorf("the first failure after a success published a transition: %+v", *fourth.Transition)
	}
}

// The health document's verdicts are about the address that was in service when
// they were written, so a selector published after them describes a different
// address and the count starts again rather than inheriting a dead address's
// failures.
func TestACounterFromAPreviousWinnerDoesNotCountAgainstTheNewOne(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	// A document written before this selector's winner was published: two
	// failures, at 02:00 and 02:02, both before the selector's own 03:00 proof.
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         time.Date(2026, 9, 26, 2, 2, 0, 0, time.UTC),
	})
	w.prober.answer = refusingWinner(12)

	first := w.check()
	if first.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1: the count must not inherit the previous winner's", first.Health.ConsecutiveFailures)
	}
	if first.Transition != nil {
		t.Errorf("one failure of a new winner published a transition: %+v", *first.Transition)
	}
}

// ---------------------------------------------------------------------------
// the proof window the response rewriter gates on
// ---------------------------------------------------------------------------

// The contract the rewriter plan gates on: a check whose winner's proof completed
// is itself a certificate, Host and SNI proof of the address in service, so it is
// the check that keeps that window open. The window therefore advances to this
// check's own instant plus five minutes - 04:00 becomes 04:05, written out as
// literals rather than computed from the package's constant - the generation does
// not move, because nothing about the selection changed, and the document is one
// the state package accepts. Every other field is the address that was already in
// service, untouched.
func TestASuccessfulCheckRefreshesThePublishedWinnersProofWindow(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)

	result := w.check()
	if result.Winner.Verdict != health.VerdictHealthy {
		t.Fatalf("the verdict = %v, want %v (detail: %s)", result.Winner.Verdict, health.VerdictHealthy, result.Winner.Detail)
	}
	if !result.RefreshedProof {
		t.Fatal("a check that proved the winner reports no refreshed proof window, so a reader cannot tell the window is still open")
	}
	if !result.ProofUntil.Equal(time.Date(2026, 9, 26, 4, 5, 0, 0, time.UTC)) {
		t.Errorf("the result reports the window closing at %s, want 2026-09-26T04:05:00Z: the proof completed at 04:00", result.ProofUntil)
	}

	published := w.readSelector()
	if !published.LastSuccess.Equal(baseMoment) {
		t.Errorf("the refreshed selector records its last success at %s, want %s: the proof completed at 04:00", published.LastSuccess, baseMoment)
	}
	if !published.WinnerProofUntil.Equal(time.Date(2026, 9, 26, 4, 5, 0, 0, time.UTC)) {
		t.Errorf("the refreshed selector's proof expires at %s, want 2026-09-26T04:05:00Z", published.WinnerProofUntil)
	}
	if published.Generation != 4 {
		t.Errorf("a proof refresh moved the generation to %d, want 4: no address, mapping or mode changed", published.Generation)
	}
	if published.WinnerIP != winnerIP || published.FallbackIP != fallbackIP {
		t.Errorf("a proof refresh changed the addresses: winner %q, fallback %q", published.WinnerIP, published.FallbackIP)
	}
	if published.CloudFront[cloudFrontHostname] != "104.16.2.10" {
		t.Errorf("a proof refresh changed the CloudFront mapping: %v", published.CloudFront)
	}
	if err := published.Validate(); err != nil {
		t.Errorf("the refreshed selector is not one the state package accepts: %v", err)
	}
}

// A pinned address is proved against the same profiles a winner is, by the same
// walk, in the same pass - so its window is refreshed on the same rule. A pin is
// the operator's decision about the address, not a decision about the window, and
// a check that refreshed one and not the other would leave a manual selector's
// proof to expire on a router where everything is answering.
func TestASuccessfulCheckRefreshesTheProofOfAPinnedAddress(t *testing.T) {
	pinned := publishedSelector()
	pinned.Mode = "manual"
	w := newWorld(t, pinned, profilesFor(), 3)

	result := w.check()
	if !result.RefreshedProof {
		t.Fatalf("a healthy check of a pinned address reports no refreshed proof (verdict %v, detail %s)", result.Winner.Verdict, result.Winner.Detail)
	}
	published := w.readSelector()
	if !published.WinnerProofUntil.Equal(time.Date(2026, 9, 26, 4, 5, 0, 0, time.UTC)) {
		t.Errorf("the pinned selector's proof expires at %s, want 2026-09-26T04:05:00Z", published.WinnerProofUntil)
	}
	if published.Mode != "manual" || published.Generation != 4 {
		t.Errorf("refreshing a pinned proof changed the selection: mode %q, generation %d", published.Mode, published.Generation)
	}
	if err := published.Validate(); err != nil {
		t.Errorf("the refreshed selector is not one the state package accepts: %v", err)
	}
}

// A refusal is not a proof, so it refreshes nothing: the window keeps the instant
// of the last proof that passed, and the document is byte-for-byte what it was. A
// check that advanced the window on a failure would be keeping an address's proof
// alive with a verdict that says it is not serving.
func TestAFailedCheckRefreshesNoProof(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	before := w.readSelectorBytes()

	result := w.check()
	if result.RefreshedProof {
		t.Error("a failed check reported a refreshed proof window")
	}
	if !result.ProofUntil.IsZero() {
		t.Errorf("a failed check reports a window closing at %s, want none", result.ProofUntil)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Errorf("a failed check changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// The two paths that stamp a window are mutually exclusive, and the transition's
// is its own: it stamps the window of the address it just moved to, four minutes
// and five minutes out, and reports itself as a transition rather than as a
// refresh - so a reader is never told a window was refreshed when what happened
// was a different address taking service.
func TestTheTransitionRefreshesTheProofOfTheAddressItPublishedAndOnlyThat(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	w.check()
	w.moment = baseMoment.Add(2 * time.Minute)
	w.check()
	w.moment = baseMoment.Add(4 * time.Minute)

	result := w.check()
	if result.Transition == nil {
		t.Fatalf("the third failure published no transition, detail: %s", result.Winner.Detail)
	}
	if result.RefreshedProof {
		t.Error("a transition also reported a refreshed proof window, so the two paths are not exclusive")
	}
	if !result.ProofUntil.IsZero() {
		t.Errorf("a transition reports a proof window of %s, want none: the window it wrote belongs to the transition", result.ProofUntil)
	}
	published := w.readSelector()
	if !published.LastSuccess.Equal(time.Date(2026, 9, 26, 4, 4, 0, 0, time.UTC)) {
		t.Errorf("the transitioned selector records its last success at %s, want the transition's own 04:04", published.LastSuccess)
	}
	if !published.WinnerProofUntil.Equal(time.Date(2026, 9, 26, 4, 9, 0, 0, time.UTC)) {
		t.Errorf("the transitioned selector's proof expires at %s, want 2026-09-26T04:09:00Z", published.WinnerProofUntil)
	}
	if published.Generation != 5 {
		t.Errorf("the transitioned selector is generation %d, want 5", published.Generation)
	}
}

// ---------------------------------------------------------------------------
// success, failure, and the difference between them and not knowing
// ---------------------------------------------------------------------------

// A cancellation says the caller went away, not that the host stopped serving, so
// it is not a failure verdict and it is not a success either: the document is left
// exactly as it was, and nothing is published.
func TestACancelledCheckLearnsNothingAndWritesNothing(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	w.check()
	before := w.readHealthBytes()
	beforeSelector := w.readSelectorBytes()
	w.moment = baseMoment.Add(2 * time.Minute)

	w.prober.answer = func(probeCall) (measure.HTTPMetrics, error) {
		return measure.HTTPMetrics{}, context.Canceled
	}
	result, err := w.checker.Check(context.Background())
	if err != nil {
		t.Fatalf("a cancelled check returned an error: %v", err)
	}
	if result.Winner.Verdict != health.VerdictUnknown {
		t.Fatalf("a cancelled check's verdict = %v, want %v", result.Winner.Verdict, health.VerdictUnknown)
	}
	if result.Health.SchemaVersion != 0 {
		t.Errorf("a cancelled check reported a written health document: %+v", result.Health)
	}
	if result.Transition != nil {
		t.Errorf("a cancelled check published a transition: %+v", *result.Transition)
	}
	if after := w.readHealthBytes(); after != before {
		t.Errorf("a cancelled check changed the health document:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if after := w.readSelectorBytes(); after != beforeSelector {
		t.Errorf("a cancelled check changed the selector:\nbefore:\n%s\nafter:\n%s", beforeSelector, after)
	}
}

// A timeout is a statement about the host: it did not answer in the time the
// check is allowed, which is the whole condition the threshold exists to catch.
func TestAProbeThatRanOutOfTimeIsAFailure(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = func(call probeCall) (measure.HTTPMetrics, error) {
		if call.address != winnerIP {
			return measure.HTTPMetrics{Status: http.StatusOK}, nil
		}
		return measure.HTTPMetrics{BodyBytes: 7}, context.DeadlineExceeded
	}

	result := w.check()
	if result.Winner.Verdict != health.VerdictFailed {
		t.Fatalf("a timed out probe's verdict = %v, want %v", result.Winner.Verdict, health.VerdictFailed)
	}
	if result.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", result.Health.ConsecutiveFailures)
	}
	if result.Bytes != 7 {
		t.Errorf("identity bytes = %d, want 7", result.Bytes)
	}
}

// A proof that never ran proves nothing, and a check whose deadline had already
// passed when it started asked no question at all. Reading that as a pass is the
// fail-open this whole walk is built to refuse, so it is a failure and the
// counter advances on it.
func TestAnExpiredDeadlineFailsTheCheckWithoutProbingAnything(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	expired, cancel := context.WithDeadline(context.Background(), baseMoment.Add(-time.Hour))
	defer cancel()

	result, err := w.checker.Check(expired)
	if err != nil {
		t.Fatalf("a check that could not run returned an error: %v", err)
	}
	if result.Winner.Verdict != health.VerdictFailed {
		t.Fatalf("a check that proved nothing = %v, want %v", result.Winner.Verdict, health.VerdictFailed)
	}
	if asked := w.prober.asked(); len(asked) != 0 {
		t.Errorf("a check with an expired deadline asked for proofs: %v", asked)
	}
	if result.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", result.Health.ConsecutiveFailures)
	}
	if result.Health.Healthy {
		t.Error("a check that proved nothing reported a healthy winner")
	}
	if result.Winner.Detail == "" {
		t.Error("a check that proved nothing gave no reason")
	}
}

// The other half of the same walk: when the caller cancelled mid-proof, the
// profiles after the one that was cut short were never asked, and "we do not
// know" is the verdict. It is not a failure - a cancellation is not the host
// refusing - and it is not a pass either.
//
// The walk is pinned to one proof at a time here, because the property under test is
// the order of the walk and not its width: at the documented limit, whether the second
// profile is dispatched before the first one's cancellation lands is a race, and a
// case that depended on it would be testing the scheduler.
func TestACancelledMidProofIsNeitherAFailureNorAPass(t *testing.T) {
	w := newWorld(t, publishedSelector(), optimizer.Profiles{
		Global: []candidate.ProbeProfile{
			identityProfile(representativeDomain),
			identityProfile("forced.example.test"),
		},
	}, 3)
	w.options.ProofConcurrency = 1
	w.rebuild()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.prober.answer = func(probeCall) (measure.HTTPMetrics, error) {
		cancel()
		return measure.HTTPMetrics{}, context.Canceled
	}

	result, err := w.checker.Check(ctx)
	if err != nil {
		t.Fatalf("a cancelled check returned an error: %v", err)
	}
	if result.Winner.Verdict != health.VerdictUnknown {
		t.Fatalf("a proof cut short by a cancellation = %v, want %v", result.Winner.Verdict, health.VerdictUnknown)
	}
	if w.healthFileExists() {
		t.Error("a cancelled check wrote a health document")
	}
	if asked := w.prober.asked(); len(asked) != 1 {
		t.Errorf("the check asked for %d proofs, want 1: the second was never dispatched", len(asked))
	}
}

// Every published address is proved, and the uncharged body bytes of a refused
// probe are added in before the error is looked at, because a refused probe is
// exactly the case where bytes crossed the network and nothing was published.
func TestTheUnchargedBodyBytesOfRefusedProbesAreReported(t *testing.T) {
	w := newWorld(t, publishedSelector(), optimizer.Profiles{
		Global: []candidate.ProbeProfile{
			identityProfile(representativeDomain),
			identityProfile("forced.example.test"),
		},
	}, 3)
	w.prober.answer = func(call probeCall) (measure.HTTPMetrics, error) {
		if call.hostname == "forced.example.test" {
			return measure.HTTPMetrics{BodyBytes: 250}, notServing
		}
		return measure.HTTPMetrics{Status: http.StatusOK, BodyBytes: 100}, nil
	}

	result := w.check()
	if result.Winner.Verdict != health.VerdictFailed {
		t.Fatalf("the verdict = %v, want %v", result.Winner.Verdict, health.VerdictFailed)
	}
	if result.Bytes != 350 {
		t.Errorf("identity bytes = %d, want 350: the refused probe's 250 are spent whatever it answered", result.Bytes)
	}
}

// ---------------------------------------------------------------------------
// what a check asks, and of what
// ---------------------------------------------------------------------------

// A proof covers the subject's own group. The global winner is held to the global
// profiles and each CloudFront address to its own hostname's, and neither is ever
// asked about the other's: a Cloudflare anycast address cannot present a chain for
// a CloudFront hostname, and the mapping is per hostname.
func TestTheWinnerIsProvedAgainstItsOwnGroupOnly(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.check()

	want := []string{
		"104.16.1.1 " + representativeDomain + " HEAD",
		"104.16.2.10 " + cloudFrontHostname + " HEAD",
	}
	if got := w.prober.asked(); !slices.Equal(got, want) {
		t.Errorf("proofs asked for:\n got %v\nwant %v", got, want)
	}
}

// Every CloudFront hostname the selector publishes is checked separately, against
// its own profile, in the same pass as the winner.
func TestEachCloudFrontHostnameIsCheckedSeparately(t *testing.T) {
	profiles := optimizer.Profiles{
		Global: []candidate.ProbeProfile{identityProfile(representativeDomain)},
		ByHostname: map[string]candidate.ProbeProfile{
			cloudFrontHostname:  identityProfile(cloudFrontHostname),
			secondFrontHostname: identityProfile(secondFrontHostname),
		},
	}
	selector := publishedSelector()
	selector.CloudFront = map[string]string{
		cloudFrontHostname:  "104.16.2.10",
		secondFrontHostname: "104.16.2.11",
	}
	w := newWorld(t, selector, profiles, 3)

	result := w.check()
	if len(result.CloudFront) != 2 {
		t.Fatalf("the check reported %d CloudFront verdicts, want 2", len(result.CloudFront))
	}
	want := []string{
		"104.16.1.1 " + representativeDomain + " HEAD",
		"104.16.2.10 " + cloudFrontHostname + " HEAD",
		"104.16.2.11 " + secondFrontHostname + " HEAD",
	}
	if got := w.prober.asked(); !slices.Equal(got, want) {
		t.Errorf("proofs asked for:\n got %v\nwant %v", got, want)
	}
	if result.CloudFront[0].Hostname != cloudFrontHostname || result.CloudFront[0].Address != "104.16.2.10" {
		t.Errorf("the first mapping's verdict is about %s/%s", result.CloudFront[0].Hostname, result.CloudFront[0].Address)
	}
	if result.CloudFront[1].Hostname != secondFrontHostname || result.CloudFront[1].Address != "104.16.2.11" {
		t.Errorf("the second mapping's verdict is about %s/%s", result.CloudFront[1].Hostname, result.CloudFront[1].Address)
	}
}

// The four fields the health document has can describe one address, and the
// selector can only move the global winner, so the counter follows the winner. A
// mapping that has stopped serving is reported - with its own verdict - rather
// than counted against an address it says nothing about.
func TestAFailingCloudFrontMappingIsReportedWithoutCountingAgainstTheWinner(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = func(call probeCall) (measure.HTTPMetrics, error) {
		if call.address == "104.16.2.10" {
			return measure.HTTPMetrics{BodyBytes: 40}, errors.New("assets.example.test: status 403 is not one the profile expects (200)")
		}
		return measure.HTTPMetrics{Status: http.StatusOK}, nil
	}

	result := w.check()
	if result.Winner.Verdict != health.VerdictHealthy {
		t.Fatalf("the winner's verdict = %v, want %v", result.Winner.Verdict, health.VerdictHealthy)
	}
	if len(result.CloudFront) != 1 || result.CloudFront[0].Verdict != health.VerdictFailed {
		t.Fatalf("the mapping's verdict = %+v, want a failure", result.CloudFront)
	}
	if result.Health.ConsecutiveFailures != 0 {
		t.Errorf("consecutive failures = %d, want 0: a mapping is not the winner", result.Health.ConsecutiveFailures)
	}
	if !result.Health.Healthy {
		t.Error("a healthy winner did not leave the document healthy")
	}
	if result.Transition != nil {
		t.Errorf("a mapping failure published a transition: %+v", *result.Transition)
	}
	if result.Bytes != 40 {
		t.Errorf("identity bytes = %d, want 40", result.Bytes)
	}
}

// A profile that names no body is proved with a HEAD: the same chain, the same
// hostname in SNI and Host, the same status and the same headers, with no
// document transferred. A profile that does name a body is proved with a GET,
// because a HEAD cannot produce the document whose digest the profile names.
func TestTheHealthProbeUsesHeadOnlyWhenTheProfileNamesNoBody(t *testing.T) {
	withBody := identityProfile(cloudFrontHostname)
	withBody.BodySHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	profiles := optimizer.Profiles{
		Global: []candidate.ProbeProfile{
			identityProfile(representativeDomain),
			identityProfile("forced.example.test"),
			withBody,
		},
	}
	w := newWorld(t, publishedSelector(), profiles, 3)
	w.check()

	asked := w.prober.asked()
	want := []string{
		"104.16.1.1 " + withBody.Hostname + " GET",
		"104.16.1.1 forced.example.test HEAD",
		"104.16.1.1 " + representativeDomain + " HEAD",
	}
	if !slices.Equal(asked, want) {
		t.Errorf("proofs asked for:\n got %v\nwant %v", asked, want)
	}
}

// ---------------------------------------------------------------------------
// what a transition does
// ---------------------------------------------------------------------------

// The fallback is proved before it is published, exactly as a winner is before it
// goes into service, and a proof that refuses leaves the address in service alone.
// The counter stays on disk at the threshold so the next check tries again rather
// than starting the count again.
func TestTheFallbackIsProvedBeforeItIsPublished(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})
	before := w.readSelectorBytes()
	w.prober.answer = func(call probeCall) (measure.HTTPMetrics, error) {
		switch call.address {
		case fallbackIP:
			return measure.HTTPMetrics{BodyBytes: 64}, errors.New("speed.cloudflare.com at 104.16.0.1: dial tcp: i/o timeout")
		case winnerIP:
			return measure.HTTPMetrics{BodyBytes: 12}, notServing
		default:
			return measure.HTTPMetrics{Status: http.StatusOK}, nil
		}
	}

	result, err := w.checker.Check(context.Background())
	if !errors.Is(err, health.ErrFallbackRefused) {
		t.Fatalf("the check's error = %v, want %v", err, health.ErrFallbackRefused)
	}
	if result.Transition != nil {
		t.Errorf("a refused fallback proof published a transition: %+v", *result.Transition)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Errorf("a refused fallback proof changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if result.Health.ConsecutiveFailures != 3 {
		t.Errorf("consecutive failures = %d, want 3: the count has to survive a refused transition", result.Health.ConsecutiveFailures)
	}
	// The winner's 12 bytes and the fallback's 64 are both spent and neither is
	// charged, so both are reported.
	if result.Bytes != 76 {
		t.Errorf("identity bytes = %d, want 76", result.Bytes)
	}
	if got := w.prober.probesOf(fallbackIP); got != 1 {
		t.Errorf("the fallback was proved %d times, want 1", got)
	}
}

// A winner that has failed and has no fallback cannot be moved anywhere, and
// pretending otherwise would publish an address nothing has proved. The counter
// stays at the threshold and the file is left alone.
func TestAWinnerWithNoFallbackIsNotMoved(t *testing.T) {
	selector := publishedSelector()
	selector.FallbackIP = ""
	w := newWorld(t, selector, profilesFor(), 3)
	before := w.readSelectorBytes()

	w.prober.answer = refusing(12)
	w.check()
	w.moment = baseMoment.Add(2 * time.Minute)
	w.check()
	w.moment = baseMoment.Add(4 * time.Minute)
	result, err := w.checker.Check(context.Background())
	if !errors.Is(err, health.ErrNoFallback) {
		t.Fatalf("the check's error = %v, want %v", err, health.ErrNoFallback)
	}
	if result.Transition != nil {
		t.Errorf("a winner with no fallback published a transition: %+v", *result.Transition)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Errorf("a winner with no fallback changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if result.Health.ConsecutiveFailures != 3 {
		t.Errorf("consecutive failures = %d, want 3", result.Health.ConsecutiveFailures)
	}
}

// A selector that moved while this check was probing is a selector about a
// different address, so this check's verdict is about an address that is no
// longer in service. It writes nothing: not the transition it may have been about
// to make, and not a count that would be the new winner's.
func TestASelectorThatChangedDuringTheCheckIsNeitherTransitionedNorCounted(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})
	before := w.readSelectorBytes()
	healthBefore := w.readHealthBytes()
	// The nightly apply lands while the health check is on the network: it
	// publishes generation 5, and the address this check probed is out of service.
	moved := publishedSelector()
	moved.Generation = 5
	moved.WinnerIP = fallbackIP
	moved.FallbackIP = ""
	moved.LastSuccess = baseMoment.Add(-time.Minute)
	w.prober.answer = func(probeCall) (measure.HTTPMetrics, error) {
		w.writeSelector(moved)
		return measure.HTTPMetrics{BodyBytes: 12}, notServing
	}

	result, err := w.checker.Check(context.Background())
	if !errors.Is(err, health.ErrSelectorChanged) {
		t.Fatalf("the check's error = %v, want %v", err, health.ErrSelectorChanged)
	}
	if result.Transition != nil {
		t.Errorf("a stale check published a transition: %+v", *result.Transition)
	}
	if after := w.readHealthBytes(); after != healthBefore {
		t.Errorf("a stale check changed the health document:\nbefore:\n%s\nafter:\n%s", healthBefore, after)
	}
	// The published selector is the one the concurrent apply wrote. A transition on
	// top of it would have swapped the two fields back and moved the generation to
	// 6, so these three facts are what say the stale check wrote nothing.
	published := w.readSelector()
	if published.Generation != 5 || published.WinnerIP != fallbackIP || published.FallbackIP != "" {
		t.Errorf("a stale check published over the concurrent apply: %+v", published)
	}
	if w.readSelectorBytes() == before {
		t.Error("the test did not stage a concurrent publication, so it proved nothing")
	}
	if result.Winner.Verdict != health.VerdictFailed {
		t.Errorf("a stale check's own verdict was not reported: %v", result.Winner.Verdict)
	}
	if result.Health.SchemaVersion != 0 {
		t.Errorf("a stale check reported a written health document: %+v", result.Health)
	}
}

// A selector an operator pinned by hand is still the selector, and a pinned
// address that has stopped serving is the case the health timer exists for. The
// mode is not changed: the address that was pinned becomes the fallback, which is
// the one shape the state package accepts and the one that leaves the operator
// able to see what happened.
func TestAManualWinnerStillFallsBack(t *testing.T) {
	selector := publishedSelector()
	selector.Mode = "manual"
	w := newWorld(t, selector, profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})

	result := w.check()
	published := w.readSelector()
	if result.Transition == nil {
		t.Fatalf("a pinned winner that failed was not moved, detail: %s", result.Winner.Detail)
	}
	if published.WinnerIP != fallbackIP {
		t.Errorf("winner = %s, want the fallback %s", published.WinnerIP, fallbackIP)
	}
	if published.Mode != "manual" {
		t.Errorf("mode = %q, want the operator's %q", published.Mode, "manual")
	}
	if err := published.Validate(); err != nil {
		t.Errorf("the published selector is not one the state package accepts: %v", err)
	}
}

// ---------------------------------------------------------------------------
// the health document
// ---------------------------------------------------------------------------

// A health document that cannot be read is a history this build does not have, so
// it is read as the threshold already reached and never as healthy. This check's
// own verdict is then added to that, which is why the count is one past the
// threshold rather than at it: the lost history and this failure are two facts.
func TestACorruptHealthDocumentFailsClosedToTheThreshold(t *testing.T) {
	// The selector names no fallback, so the threshold the corrupt document reached
	// cannot be acted on and the count it reached is the one left on disk - which is
	// where the arithmetic is visible. A corrupt document that does lead to the
	// fallback is the same path with somewhere to move to, and the document it leaves
	// describes the address that replaced the failed one.
	selector := publishedSelector()
	selector.FallbackIP = ""
	w := newWorld(t, selector, profilesFor(), 3)
	w.writeRaw(w.healthPath, `{"schema_version": 1, "healthy": true, "consecutive_failures": 0,`)
	before := w.readSelectorBytes()
	w.prober.answer = refusingWinner(12)

	result, err := w.checker.Check(context.Background())
	if !errors.Is(err, health.ErrNoFallback) {
		t.Fatalf("the check's error = %v, want %v", err, health.ErrNoFallback)
	}
	if result.FailedClosed == "" {
		t.Error("a corrupt health document was not reported as such")
	}
	if result.Health.Healthy {
		t.Error("a corrupt health document left the winner healthy")
	}
	if result.Health.ConsecutiveFailures != 4 {
		t.Errorf("consecutive failures = %d, want 4: the threshold from the lost history plus this failure", result.Health.ConsecutiveFailures)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Error("a corrupt document changed a selector that named no fallback")
	}
}

// A corrupt document is not a permanent verdict: a check that proves the address
// is serving replaces the lost history with a real one, and clears the count that
// was standing in for it.
func TestACorruptHealthDocumentIsReplacedByASuccessfulCheck(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeRaw(w.healthPath, `{"schema_version": 1, "healthy": true, "consecutive_failures": 0,`)

	result := w.check()
	if result.FailedClosed == "" {
		t.Error("a corrupt health document was not reported as such")
	}
	if result.Winner.Verdict != health.VerdictHealthy {
		t.Fatalf("the verdict = %v, want %v", result.Winner.Verdict, health.VerdictHealthy)
	}
	if result.Health.ConsecutiveFailures != 0 {
		t.Errorf("consecutive failures = %d, want 0 after a successful check", result.Health.ConsecutiveFailures)
	}
	if !result.Health.Healthy {
		t.Error("a successful check left the document unhealthy")
	}
	if result.Transition != nil {
		t.Errorf("a successful check published a transition: %+v", *result.Transition)
	}
}

// A document that is not there is a router that has not been checked yet, which is
// not the same as one whose history was lost: the count starts at one rather than
// at the threshold.
func TestAMissingHealthDocumentIsAFreshCount(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)

	result := w.check()
	if result.FailedClosed != "" {
		t.Errorf("a missing health document was reported as corrupt: %q", result.FailedClosed)
	}
	if result.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", result.Health.ConsecutiveFailures)
	}
}

// The four fields the plan documents are the only ones stored, and the file is
// readable afterwards through the state package, which is what makes a document
// left by a previous run and a document left by this one the same thing.
func TestTheHealthDocumentHoldsOnlyTheDocumentedFields(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)

	// A failure first, so the document holds one of each timestamp: the second
	// check's success must not erase the first check's failure.
	w.prober.answer = refusingWinner(12)
	w.check()
	w.moment = baseMoment.Add(2 * time.Minute)
	w.prober.answer = nil
	w.check()
	raw := w.readHealthBytes()
	for _, field := range []string{`"schema_version"`, `"healthy"`, `"consecutive_failures"`, `"last_success"`} {
		if !strings.Contains(raw, field) {
			t.Errorf("the health document has no %s field:\n%s", field, raw)
		}
	}
	for _, field := range []string{`"winner_ip"`, `"generation"`, `"last_failure_reason"`, `"address"`} {
		if strings.Contains(raw, field) {
			t.Errorf("the health document carries an undocumented %s field:\n%s", field, raw)
		}
	}
	documented := state.HealthState{}
	if err := state.ReadJSON(w.healthPath, &documented); err != nil {
		t.Fatalf("the health document this check wrote cannot be read back: %v", err)
	}
	if documented.LastFailure.IsZero() {
		t.Errorf("the read-back document lost the failure the second check recorded:\n%s", raw)
	}
}

// A write that fails leaves the previous document and this check's conclusion alone:
// there is no half-written counter, and nothing is published behind a document that
// was never stored.
//
// The step-by-step fault injection for this discipline lives in the state package,
// beside the harness that can fail the rename, the file flush and the directory
// flush individually, because the health writer is that writer and has no steps of its
// own to inject into. What is left for this package to hold is the consequence the
// check itself owns: a write that did not happen is reported as no document written.
func TestAFailedHealthWriteLeavesThePreviousDocumentAndConclusion(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	previous := state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	}
	w.writeHealth(previous)
	before := w.readHealthBytes()
	selectorBefore := w.readSelectorBytes()
	w.prober.answer = refusingWinner(12)
	// A directory that cannot be written to makes the same-directory temporary
	// file fail, which is a write failure rather than a refusal to start.
	if err := os.Chmod(w.directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(w.directory, 0o700) })

	result, err := w.checker.Check(context.Background())
	if err == nil {
		t.Fatal("a check whose health document could not be written reported success")
	}
	if result.Health.SchemaVersion != 0 {
		t.Errorf("a failed write reported a document: %+v", result.Health)
	}
	if result.Transition != nil {
		t.Errorf("a failed health write still published a transition: %+v", *result.Transition)
	}
	if after := w.readHealthBytes(); after != before {
		t.Errorf("a failed write changed the health document:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if after := w.readSelectorBytes(); after != selectorBefore {
		t.Errorf("a failed health write changed the selector:\nbefore:\n%s\nafter:\n%s", selectorBefore, after)
	}
}

// ---------------------------------------------------------------------------
// the lock
// ---------------------------------------------------------------------------

// A successful check probes without the control lock. The lock exists to serialise
// a mutation of the state the router reads, and holding it for the seconds a
// probe takes would put every apply, pin and unpin behind a health check. The
// proof is that the prober itself can take the lock while it is being asked: a
// check that held it would refuse it.
func TestTheWinnerProbeRunsWithoutTheControlLock(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	heldDuringProbe := false
	w.prober.answer = func(probeCall) (measure.HTTPMetrics, error) {
		lock, err := filelock.Acquire(w.lockPath)
		if err != nil {
			heldDuringProbe = true
			return measure.HTTPMetrics{Status: http.StatusOK}, nil
		}
		_ = lock.Close()
		return measure.HTTPMetrics{Status: http.StatusOK}, nil
	}

	w.check()
	if heldDuringProbe {
		t.Error("the health check held the control lock while it was probing the winner")
	}
	if !w.healthFileExists() {
		t.Error("a successful check wrote no health document")
	}
}

// The transition's proof of the fallback is the one piece of network I/O that runs
// under the control lock, because the store has to follow the proof immediately:
// an address proved and then written after a pause is an address proved at some
// other time. It is bounded by one deadline, as an apply's is.
func TestTheFallbackProofRunsUnderTheControlLock(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})
	heldDuringProof := false
	w.prober.answer = func(call probeCall) (measure.HTTPMetrics, error) {
		if call.address == fallbackIP {
			if _, err := filelock.Acquire(w.lockPath); err != nil {
				heldDuringProof = true
			} else {
				heldDuringProof = false
			}
			return measure.HTTPMetrics{Status: http.StatusOK}, nil
		}
		return measure.HTTPMetrics{BodyBytes: 12}, notServing
	}

	result := w.check()
	if result.Transition == nil {
		t.Fatalf("no transition was published, detail: %s", result.Winner.Detail)
	}
	if !heldDuringProof {
		t.Error("the fallback was proved without the control lock, so the store does not follow the proof immediately")
	}
}

// The counter is read under the control lock, not before it. A check that probed
// against a count another check has since changed counts from what the document
// says when it takes the lock, which is the only way two checks in flight can both
// be right about the count they add to.
func TestACheckCountsFromTheHealthDocumentItFindsUnderTheLock(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 5)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 1,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})
	// Another check writes the document while this one is on the network, so the
	// count this check finds is not the one it could have read before it started.
	w.prober.answer = func(probeCall) (measure.HTTPMetrics, error) {
		w.writeHealth(state.HealthState{
			SchemaVersion:       state.SchemaVersion,
			ConsecutiveFailures: 2,
			LastFailure:         baseMoment.Add(-time.Minute),
		})
		return measure.HTTPMetrics{BodyBytes: 12}, notServing
	}

	result := w.check()
	if result.Health.ConsecutiveFailures != 3 {
		t.Errorf("consecutive failures = %d, want 3: the count must come from the document the lock found, not from one read before the probe",
			result.Health.ConsecutiveFailures)
	}
	if result.Transition != nil {
		t.Errorf("a check below the threshold published a transition: %+v", *result.Transition)
	}
}

// A check that cannot take the control lock reports the conflict and changes
// nothing: no document is written, no count advances, and the verdict it did reach
// is still reported. The lock is a mutual-exclusion device and not a queue, so a
// check that waited for it would be a check that held up apply, pin and unpin for
// the length of a probe.
func TestACheckThatCannotTakeTheControlLockChangesNothing(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})
	before := w.readSelectorBytes()
	healthBefore := w.readHealthBytes()
	held, err := filelock.Acquire(w.lockPath)
	if err != nil {
		t.Fatalf("take the control lock: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })
	w.prober.answer = refusingWinner(12)

	result, err := w.checker.Check(context.Background())
	if !errors.Is(err, optimizer.ErrControlLocked) {
		t.Fatalf("a check with the control lock held returned %v, want %v", err, optimizer.ErrControlLocked)
	}
	if result.Health.SchemaVersion != 0 {
		t.Errorf("a refused check reported a written health document: %+v", result.Health)
	}
	if result.Transition != nil {
		t.Errorf("a refused check published a transition: %+v", *result.Transition)
	}
	// The verdict the check did reach is still reported: it proved the address on
	// the network, and that measurement is not the lock's to discard.
	if result.Winner.Verdict != health.VerdictFailed {
		t.Errorf("a refused check's verdict = %v, want %v", result.Winner.Verdict, health.VerdictFailed)
	}
	if after := w.readHealthBytes(); after != healthBefore {
		t.Errorf("a refused check changed the health document:\nbefore:\n%s\nafter:\n%s", healthBefore, after)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Errorf("a refused check changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// Several checks in flight at once are several checks. Each one either adds its own
// failure to the count it finds under the lock or is told the lock is held and adds
// nothing, so the count after them all is the number that got in - never more, which
// is what one check counted twice would look like, and never fewer.
func TestConcurrentChecksCountOneFailureEachAndRefuseTheRest(t *testing.T) {
	const checks = 4
	// A threshold above the number of checks, so no check in this case transitions
	// and the count is the only thing the document carries.
	w := newWorld(t, publishedSelector(), profilesFor(), checks+4)
	w.prober.answer = refusingWinner(12)

	var group sync.WaitGroup
	results := make([]health.Result, checks)
	failures := make([]error, checks)
	for index := range results {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index], failures[index] = w.checker.Check(context.Background())
		}(index)
	}
	group.Wait()

	admitted := 0
	for index, err := range failures {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, optimizer.ErrControlLocked):
		default:
			t.Fatalf("check %d: %v", index, err)
		}
	}
	documented := state.HealthState{}
	if err := state.ReadJSON(w.healthPath, &documented); err != nil {
		t.Fatalf("read the health document: %v", err)
	}
	if documented.ConsecutiveFailures != admitted {
		t.Errorf("consecutive failures after %d concurrent checks = %d, want %d: every check counts once or not at all",
			checks, documented.ConsecutiveFailures, admitted)
	}
	for index, result := range results {
		if result.Transition != nil {
			t.Errorf("check %d published a transition below the threshold: %+v", index, *result.Transition)
		}
	}
}

// ---------------------------------------------------------------------------
// what a check does when there is nothing to check
// ---------------------------------------------------------------------------

// A selector that has never selected an address has nothing in service, so there
// is nothing to prove and nothing to write. The verdict says so rather than
// reporting a healthy address that does not exist. The same is true of a router
// that has never published a selector at all.
func TestACheckOnASelectorWithNoWinnerProbesNothing(t *testing.T) {
	t.Run("a selector with no winner", func(t *testing.T) {
		w := newWorld(t, state.Selector{
			SchemaVersion: state.SchemaVersion,
			Generation:    1,
			Mode:          "auto",
			Provider:      "cloudflare",
		}, profilesFor(), 3)

		result := w.check()
		if result.Winner.Verdict != health.VerdictUnknown {
			t.Errorf("a selector with no winner = %v, want %v", result.Winner.Verdict, health.VerdictUnknown)
		}
		if result.Winner.Detail == "" {
			t.Error("a selector with no winner gave no reason")
		}
		if asked := w.prober.asked(); len(asked) != 0 {
			t.Errorf("a selector with no winner was probed: %v", asked)
		}
		if w.healthFileExists() {
			t.Error("a selector with no winner wrote a health document")
		}
	})

	t.Run("no selector at all", func(t *testing.T) {
		w := newWorld(t, publishedSelector(), profilesFor(), 3)
		if err := os.Remove(w.selectorPath); err != nil {
			t.Fatal(err)
		}

		result := w.check()
		if result.Winner.Verdict != health.VerdictUnknown {
			t.Errorf("a router with no selector = %v, want %v", result.Winner.Verdict, health.VerdictUnknown)
		}
		if asked := w.prober.asked(); len(asked) != 0 {
			t.Errorf("a router with no selector was probed: %v", asked)
		}
		if w.healthFileExists() {
			t.Error("a router with no selector wrote a health document")
		}
	})
}

// The state package holds a winner to "a valid IPv4 address" and a rewrite target
// to "a public one", so a document written by an older build or edited by hand can
// name 10.0.0.1. A check that built a candidate from it would dial the LAN, and one
// that ignored the address would report a router it never looked at, so the
// candidate package's own refusal is what a check reaches for first.
func TestAnAddressNoRewriteTargetMayNameIsNeverDialled(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	// A document the state writer would accept - the winner only has to be an IPv4
	// address - and that a rewrite target may not name.
	w.writeRaw(w.selectorPath, `{"schema_version": 1, "generation": 4, "mode": "auto", "provider": "cloudflare", "winner_ip": "10.0.0.1", "last_success": "2026-09-26T03:00:00Z"}`)

	result := w.check()
	if result.Winner.Verdict != health.VerdictFailed {
		t.Fatalf("an unpublishable winner = %v, want %v", result.Winner.Verdict, health.VerdictFailed)
	}
	if result.Winner.Detail == "" {
		t.Error("an unpublishable winner gave no reason")
	}
	if asked := w.prober.asked(); len(asked) != 0 {
		t.Errorf("an unpublishable winner was dialled: %v", asked)
	}
	if result.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", result.Health.ConsecutiveFailures)
	}
}

// A disabled selector is not in service either, whatever address its document
// still names, and a check that moved one would be publishing a change nothing
// asked for.
func TestACheckOnADisabledSelectorProbesNothing(t *testing.T) {
	selector := publishedSelector()
	selector.Mode = "disabled"
	w := newWorld(t, selector, profilesFor(), 3)
	before := w.readSelectorBytes()

	result := w.check()
	if result.Winner.Verdict != health.VerdictUnknown {
		t.Errorf("a disabled selector = %v, want %v", result.Winner.Verdict, health.VerdictUnknown)
	}
	if asked := w.prober.asked(); len(asked) != 0 {
		t.Errorf("a disabled selector was probed: %v", asked)
	}
	if w.healthFileExists() {
		t.Error("a disabled selector wrote a health document")
	}
	if after := w.readSelectorBytes(); after != before {
		t.Error("a disabled selector's document was changed")
	}
}

// A selector that cannot be read is the last-known-good address of a router that
// is already in trouble, and a check that treated it as an absent one would
// report a clean bill of health for a document it never read.
func TestACheckRefusesAnUnreadableSelector(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeRaw(w.selectorPath, `{"schema_version": 1, "generation": 4, "mode": "auto",`)

	if _, err := w.checker.Check(context.Background()); err == nil {
		t.Fatal("a check on an unreadable selector reported success")
	}
	if asked := w.prober.asked(); len(asked) != 0 {
		t.Errorf("an unreadable selector was probed: %v", asked)
	}
	if w.healthFileExists() {
		t.Error("an unreadable selector produced a health document")
	}
}

// ---------------------------------------------------------------------------
// the checker itself
// ---------------------------------------------------------------------------

// A checker with no prober cannot prove anything, and one with no path cannot
// write or read anything: a health check that silently had neither would report a
// healthy router every two minutes.
func TestNewCheckerRefusesAnIncompleteConfiguration(t *testing.T) {
	directory := t.TempDir()
	complete := health.Options{
		Profiles:         profilesFor(),
		HealthPath:       filepath.Join(directory, "health.json"),
		SelectorPath:     filepath.Join(directory, "cdn-selector.json"),
		ControlLockPath:  filepath.Join(directory, "control.lock"),
		FailureThreshold: 3,
	}
	cases := map[string]func(health.Options) health.Options{
		"no health path":       func(o health.Options) health.Options { o.HealthPath = ""; return o },
		"no selector path":     func(o health.Options) health.Options { o.SelectorPath = ""; return o },
		"no control lock path": func(o health.Options) health.Options { o.ControlLockPath = ""; return o },
		"no failure threshold": func(o health.Options) health.Options { o.FailureThreshold = 0; return o },
		"a negative threshold": func(o health.Options) health.Options { o.FailureThreshold = -1; return o },
		"no identity profile":  func(o health.Options) health.Options { o.Profiles = optimizer.Profiles{}; return o },
	}
	for name, incomplete := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := health.NewChecker(&fakeProber{}, incomplete(complete)); err == nil {
				t.Error("an incomplete checker was built")
			}
		})
	}
	if _, err := health.NewChecker(nil, complete); err == nil {
		t.Error("a checker with no prober was built")
	}
}

// The failure threshold a case is given is the policy's, and a threshold of one
// would move the address on the first refusal: the counter has to be the policy's
// number, not a constant in this package.
func TestTheFailureThresholdIsThePolicys(t *testing.T) {
	for _, threshold := range []int{1, 2, 5} {
		w := newWorld(t, publishedSelector(), profilesFor(), threshold)
		w.prober.answer = refusingWinner(12)
		w.writeHealth(state.HealthState{
			SchemaVersion:       state.SchemaVersion,
			ConsecutiveFailures: threshold - 1,
			LastFailure:         baseMoment.Add(-2 * time.Minute),
		})
		result := w.check()
		if result.Transition == nil {
			t.Errorf("a threshold of %d did not move the address on its %dth failure", threshold, threshold)
			continue
		}
		if published := w.readSelector(); published.WinnerIP != fallbackIP {
			t.Errorf("a threshold of %d published %s, want the fallback", threshold, published.WinnerIP)
		}
		// The count on disk after a transition belongs to the address that replaced
		// the failed one, so what pins the threshold is that the transition happened on
		// the threshold's own failure and not one before it: the document started at
		// threshold-1 and this check added one.
		if published := w.readSelector(); published.Generation != 5 {
			t.Errorf("a threshold of %d published generation %d, want 5", threshold, published.Generation)
		}
	}
}

// The verdicts have to be nameable, because a timer reads them and a report prints
// them: "unknown" and "failed" are different answers and a caller must not have to
// guess which one a check produced.
func TestVerdictNamesAreDistinctAndTheZeroValueIsUnknown(t *testing.T) {
	names := map[string]health.Verdict{}
	for _, verdict := range []health.Verdict{health.VerdictUnknown, health.VerdictHealthy, health.VerdictFailed} {
		name := verdict.String()
		if previous, repeated := names[name]; repeated {
			t.Fatalf("%v and %v both name themselves %q", previous, verdict, name)
		}
		names[name] = verdict
	}
	if health.VerdictUnknown.String() != "unknown" || health.VerdictHealthy.String() != "healthy" || health.VerdictFailed.String() != "failed" {
		t.Fatalf("verdict names = %q/%q/%q, want unknown/healthy/failed",
			health.VerdictUnknown, health.VerdictHealthy, health.VerdictFailed)
	}
	var zero health.Verdict
	if zero != health.VerdictUnknown {
		t.Errorf("the zero verdict = %v, want %v: a value nobody set has to read as not knowing", zero, health.VerdictUnknown)
	}
}

// The production path is the one the packaged service installs, and it is
// published so a caller with no layout of its own writes where the router reads.
func TestTheDefaultHealthPathIsTheRuntimeDirectory(t *testing.T) {
	want := "/var/lib/mosdns/runtime/health.json"
	if health.DefaultHealthPath != want {
		t.Errorf("DefaultHealthPath = %q, want %q", health.DefaultHealthPath, want)
	}
}

// ---------------------------------------------------------------------------
// the walk's shape
// ---------------------------------------------------------------------------

// globalProfilesOf builds a global identity profile list of n hostnames, so a case can
// ask what a walk over a long list costs. The names are numbered rather than invented
// because a list's length is the point and its contents are not.
func globalProfilesOf(n int) optimizer.Profiles {
	profiles := make([]candidate.ProbeProfile, 0, n)
	for index := 0; index < n; index++ {
		profiles = append(profiles, identityProfile(fmt.Sprintf("domain%02d.example.test", index)))
	}
	return optimizer.Profiles{Global: profiles}
}

// A long profile list is answered in waves rather than one at a time, so the time a
// check spends is the number of waves and not the length of the list. The number
// itself is the documented one the optimizer's final proof uses; what is being pinned
// here is that this walk uses it at all, because a serial walk over a realistic
// forced-ECH list times the pass deadline out on a perfectly healthy address.
func TestTheProfilesOfOneAddressAreProvedInWaves(t *testing.T) {
	const proofs = 24
	w := newWorld(t, publishedSelector(), globalProfilesOf(proofs), 3)
	// Forty milliseconds a proof: a serial walk would spend 960 milliseconds here, and
	// the pass deadline below is two waves of a second, so the deadline is not what
	// the case is measuring.
	w.prober.delay = 40 * time.Millisecond

	began := time.Now()
	result := w.check()
	elapsed := time.Since(began)

	if result.Winner.Verdict != health.VerdictHealthy {
		t.Fatalf("the verdict = %v, want %v (detail: %s)", result.Winner.Verdict, health.VerdictHealthy, result.Winner.Detail)
	}
	if peak := w.prober.peak(); peak < 2 {
		t.Errorf("the walk proved one profile at a time: peak in flight = %d over %d proofs", peak, proofs)
	}
	if peak := w.prober.peak(); peak > optimizer.ProofConcurrency {
		t.Errorf("peak in flight = %d, above the documented limit %d", peak, optimizer.ProofConcurrency)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("the pass took %s for %d proofs, want about two waves of 40ms rather than %d of them", elapsed, proofs, proofs)
	}
}

// The pass deadline is one wave's bound for every wave the pass needs, so a list
// longer than the concurrency limit is given the time its extra waves cost instead of
// being cut short. The numbers are the fixture's own: a wave is 100ms, the limit is
// sixteen proofs at a time, and the cap is the documented maximum.
func TestThePassDeadlineScalesWithTheNumberOfWaves(t *testing.T) {
	cases := []struct {
		name     string
		profiles int
		mappings int
		want     time.Duration
	}{
		{name: "one profile", profiles: 1, want: 100 * time.Millisecond},
		{name: "a full wave", profiles: optimizer.ProofConcurrency, want: 100 * time.Millisecond},
		{name: "one profile over a wave", profiles: optimizer.ProofConcurrency + 1, want: 200 * time.Millisecond},
		{name: "three waves", profiles: 2*optimizer.ProofConcurrency + 1, want: 300 * time.Millisecond},
		// The mappings are the pass's second fan-out, so each wave of them is a wave
		// the winner's own profiles do not get.
		{name: "one mapping of its own", profiles: 1, mappings: 1, want: 200 * time.Millisecond},
		{name: "mappings beyond a wave", profiles: 1, mappings: optimizer.ProofConcurrency + 1, want: 300 * time.Millisecond},
	}
	for _, testCase := range cases {
		selector := publishedSelector()
		selector.CloudFront = nil
		for index := 0; index < testCase.mappings; index++ {
			if selector.CloudFront == nil {
				selector.CloudFront = map[string]string{}
			}
			selector.CloudFront[fmt.Sprintf("front%02d.example.test", index)] = fmt.Sprintf("104.16.3.%d", index+1)
		}
		profiles := globalProfilesOf(testCase.profiles)
		for index := 0; index < testCase.mappings; index++ {
			hostname := fmt.Sprintf("front%02d.example.test", index)
			if profiles.ByHostname == nil {
				profiles.ByHostname = map[string]candidate.ProbeProfile{}
			}
			profiles.ByHostname[hostname] = identityProfile(hostname)
		}
		w := newWorld(t, selector, profiles, 3)
		w.options.WaveTimeout = 100 * time.Millisecond
		w.rebuild()

		began := time.Now()
		w.check()
		// The deadline is a wall-clock instant built from the moment the check asked
		// for it, so it is compared with a small window around that moment rather than
		// with the case's own injected clock, which the context builder does not read.
		granted := w.prober.deadline(t).Sub(began)
		if granted < testCase.want-deadlineWindow || granted > testCase.want+deadlineWindow {
			t.Errorf("%s: the pass was given %s, want %s", testCase.name, granted, testCase.want)
		}
	}

	// A list long enough to overrun the cap gets the cap and no more: a pass that ran
	// for longer than the health interval would overlap the next one.
	w := newWorld(t, publishedSelector(), globalProfilesOf(1000), 3)
	w.options.WaveTimeout = 2 * time.Second
	w.rebuild()
	began := time.Now()
	w.check()
	if granted := w.prober.deadline(t).Sub(began); granted < health.MaximumPassTimeout-deadlineWindow || granted > health.MaximumPassTimeout+deadlineWindow {
		t.Errorf("a list of 1000 profiles was given %s, want the cap %s", granted, health.MaximumPassTimeout)
	}
}

// The hazard the scaling exists for: a long list on a slow edge is a healthy winner,
// and a deadline that cannot cover its waves turns it into three failures and a
// rollback onto the fallback. Three passes of the same list must leave the selection
// exactly as it was.
//
// "The selection" is the address, the fallback, the mapping and the generation. The
// proof window is not part of it and moves on every pass, which is the contract the
// rewriter gates on: three healthy passes end with the window open until 04:11.
func TestALongListOnASlowEdgeDoesNotTripTheThreshold(t *testing.T) {
	w := newWorld(t, publishedSelector(), globalProfilesOf(20), 3)
	w.prober.delay = 30 * time.Millisecond
	// Thirty milliseconds a proof, two waves, so a healthy pass needs 60ms of a
	// 200ms budget. A serial walk would need 600ms of it and would be cut short.
	w.options.WaveTimeout = 100 * time.Millisecond
	w.rebuild()

	for attempt := 1; attempt <= 3; attempt++ {
		w.moment = baseMoment.Add(time.Duration(attempt) * 2 * time.Minute)
		result := w.check()
		if result.Winner.Verdict != health.VerdictHealthy {
			t.Fatalf("check %d = %v, want %v (detail: %s)", attempt, result.Winner.Verdict, health.VerdictHealthy, result.Winner.Detail)
		}
		if result.Health.ConsecutiveFailures != 0 {
			t.Fatalf("check %d recorded %d failures", attempt, result.Health.ConsecutiveFailures)
		}
		if result.Transition != nil {
			t.Fatalf("check %d published a transition: %+v", attempt, *result.Transition)
		}
	}
	published := w.readSelector()
	if published.Generation != 4 || published.WinnerIP != winnerIP || published.FallbackIP != fallbackIP {
		t.Errorf("three healthy passes changed the selection: generation %d, winner %q, fallback %q",
			published.Generation, published.WinnerIP, published.FallbackIP)
	}
	if published.CloudFront[cloudFrontHostname] != "104.16.2.10" {
		t.Errorf("three healthy passes changed the CloudFront mapping: %v", published.CloudFront)
	}
	if !published.WinnerProofUntil.Equal(time.Date(2026, 9, 26, 4, 11, 0, 0, time.UTC)) {
		t.Errorf("the proof window closes at %s, want 2026-09-26T04:11:00Z: the last pass proved the winner at 04:06", published.WinnerProofUntil)
	}
}

// One profile is one wave, and a single-profile check is exactly what it was: the
// probe is handed the wave bound itself, with nothing added to it.
func TestASingleProfileCheckIsUnchanged(t *testing.T) {
	// No published mapping, so this is one address with one profile and one wave.
	selector := publishedSelector()
	selector.CloudFront = nil
	w := newWorld(t, selector, profilesFor(), 3)
	w.prober.answer = refusingWinner(12)

	began := time.Now()
	result := w.check()
	if result.Winner.Verdict != health.VerdictFailed {
		t.Fatalf("the verdict = %v, want %v", result.Winner.Verdict, health.VerdictFailed)
	}
	if granted := w.prober.deadline(t).Sub(began); granted < time.Second-deadlineWindow || granted > time.Second+deadlineWindow {
		t.Errorf("a one-profile pass was given %s, want the wave bound 1s unscaled", granted)
	}
	if result.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", result.Health.ConsecutiveFailures)
	}
	if peak := w.prober.peak(); peak != 1 {
		t.Errorf("peak in flight = %d for one profile, want 1", peak)
	}
}

// The transition's proof is bounded by one deadline rather than by the list's waves,
// and the reason is the lock it runs under: a hold that grows with the list is a hold
// nobody can take, while a list that overruns the bound is refused - which moves
// nothing, leaves the count at the threshold, and is tried again in two minutes. The
// direction is the safe one, and this case is it.
func TestTheTransitionIsRefusedWhenItsProofRunsOutOfTime(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})
	before := w.readSelectorBytes()
	// The winner refuses immediately; the fallback is slower than the whole bound the
	// transition gives its proof.
	w.options.ProofTimeout = 20 * time.Millisecond
	w.prober.answer = refusingWinner(12)
	w.prober.delay = 60 * time.Millisecond
	w.rebuild()

	result, err := w.checker.Check(context.Background())
	if !errors.Is(err, health.ErrFallbackRefused) {
		t.Fatalf("the check's error = %v, want %v", err, health.ErrFallbackRefused)
	}
	if result.Transition != nil {
		t.Errorf("an overrunning proof published a transition: %+v", *result.Transition)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Errorf("an overrunning proof changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if result.Health.ConsecutiveFailures != 3 {
		t.Errorf("consecutive failures = %d, want 3: the count has to survive for the next tick", result.Health.ConsecutiveFailures)
	}
}

// ---------------------------------------------------------------------------
// which instant a check stamps
// ---------------------------------------------------------------------------

// The winner's proof window starts when the fallback was proved, not when the check
// began: the proof can take seconds under the lock, and a window that started before
// it is that much shorter than the published one says. The clock here moves a second
// per reading, so the two instants are two different literals.
func TestTheProofWindowStartsWhenTheFallbackWasProved(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.step = time.Second
	w.prober.answer = refusingWinner(12)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})

	result := w.check()
	if result.Transition == nil {
		t.Fatalf("no transition was published, detail: %s", result.Winner.Detail)
	}
	published := w.readSelector()
	// First reading: the health document's verdict of the address that failed.
	if !published.LastSuccess.Equal(baseMoment.Add(2 * time.Second)) {
		t.Errorf("last success = %s, want the second reading %s", published.LastSuccess, baseMoment.Add(2*time.Second))
	}
	if !published.WinnerProofUntil.Equal(baseMoment.Add(2 * time.Second).Add(5 * time.Minute)) {
		t.Errorf("winner proof until = %s, want %s", published.WinnerProofUntil,
			baseMoment.Add(2*time.Second).Add(5*time.Minute))
	}
	// The document that follows the transition carries that same instant, so the two
	// cannot drift apart.
	if !result.Health.LastSuccess.Equal(published.LastSuccess) {
		t.Errorf("the health document's success = %s, want the selector's own %s", result.Health.LastSuccess, published.LastSuccess)
	}
}

// A transition leaves a new address in service, and that address was proved on the way
// in, so the health document describes it rather than the address that just left. A
// document left saying "three failures, not healthy" would be a claim about an address
// that is no longer published, and the counter it holds would have to be read as
// belonging to the address that replaced it.
func TestTheHealthDocumentFollowsTheAddressInServiceAfterATransition(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})

	result := w.check()
	if result.Transition == nil {
		t.Fatalf("no transition was published, detail: %s", result.Winner.Detail)
	}
	documented := state.HealthState{}
	if err := state.ReadJSON(w.healthPath, &documented); err != nil {
		t.Fatalf("read the health document: %v", err)
	}
	proofed := w.readSelector().LastSuccess
	if !documented.Healthy {
		t.Error("the document describes the address that just left service")
	}
	if documented.ConsecutiveFailures != 0 {
		t.Errorf("consecutive failures = %d, want 0: the address in service was proved on the way in", documented.ConsecutiveFailures)
	}
	if !documented.LastSuccess.Equal(proofed) {
		t.Errorf("last success = %s, want the instant the new winner was proved, %s", documented.LastSuccess, proofed)
	}
	if result.Health.Healthy != documented.Healthy {
		t.Errorf("the reported document = %+v, want what is on disk %+v", result.Health, documented)
	}
}

// A caller that goes away between the watch and the transition is not a host that
// refused, and the two must not be reported as one: the first is this invocation
// giving up, the second is the fallback not serving, and only the second says anything
// about the address the router would have moved to.
func TestACancellationBeforeTheTransitionIsNotAHostRefusal(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.writeHealth(state.HealthState{
		SchemaVersion:       state.SchemaVersion,
		ConsecutiveFailures: 2,
		LastFailure:         baseMoment.Add(-2 * time.Minute),
	})
	before := w.readSelectorBytes()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.prober.answer = func(call probeCall) (measure.HTTPMetrics, error) {
		if call.address == fallbackIP {
			cancel()
			return measure.HTTPMetrics{}, context.Canceled
		}
		return measure.HTTPMetrics{BodyBytes: 12}, notServing
	}

	result, err := w.checker.Check(ctx)
	if !errors.Is(err, health.ErrTransitionCancelled) {
		t.Fatalf("the check's error = %v, want %v", err, health.ErrTransitionCancelled)
	}
	if errors.Is(err, health.ErrFallbackRefused) {
		t.Errorf("a cancellation was reported as a host refusal: %v", err)
	}
	if result.Transition != nil {
		t.Errorf("a cancelled transition published one: %+v", *result.Transition)
	}
	if after := w.readSelectorBytes(); after != before {
		t.Errorf("a cancelled transition changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// The count is still recorded: the winner did fail, and the next tick has to start
	// from where this one left it.
	if result.Health.ConsecutiveFailures != 3 {
		t.Errorf("consecutive failures = %d, want 3", result.Health.ConsecutiveFailures)
	}
}

// The global winner is proved as the provider the selector names, not as a Cloudflare
// address the checker assumed. A selector that says cloudfront while naming a
// hostname-less winner is describing an arrangement the candidate package refuses, and
// the check says so instead of proving a subject nobody published.
func TestTheWinnerIsRefusedWhenTheSelectorNamesAnotherProvider(t *testing.T) {
	selector := publishedSelector()
	selector.Provider = "cloudfront"
	w := newWorld(t, selector, profilesFor(), 3)

	result := w.check()
	if result.Winner.Verdict != health.VerdictFailed {
		t.Fatalf("a mismatched provider = %v, want %v", result.Winner.Verdict, health.VerdictFailed)
	}
	// The mapping is a subject of its own and is still proved; the winner is not.
	want := []string{"104.16.2.10 " + cloudFrontHostname + " HEAD"}
	if got := w.prober.asked(); !slices.Equal(got, want) {
		t.Errorf("proofs asked for:\n got %v\nwant %v", got, want)
	}
	if result.Winner.Detail == "" {
		t.Error("a mismatched provider gave no reason")
	}
	if result.Health.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", result.Health.ConsecutiveFailures)
	}
}

// The brief's strict-ECH sentence, from this side of the boundary: a failed verdict
// leaves the document saying the winner is not healthy, and that is the field the
// response rewriter will read. Nothing here decides whether a strict domain stays
// blocked - that is the rewriter's branch - but a document that reported a failing
// address as healthy would be the half of that decision this package is responsible
// for getting wrong.
func TestAFailedVerdictNeverReadsAsHealthyForAStrictDomain(t *testing.T) {
	w := newWorld(t, publishedSelector(), profilesFor(), 3)
	w.prober.answer = refusingWinner(12)

	w.check()
	documented := state.HealthState{}
	if err := state.ReadJSON(w.healthPath, &documented); err != nil {
		t.Fatalf("read the health document: %v", err)
	}
	if documented.Healthy {
		t.Error("the document reports a failing winner as healthy")
	}
	if documented.ConsecutiveFailures != 1 {
		t.Errorf("consecutive failures = %d, want 1", documented.ConsecutiveFailures)
	}
	if documented.LastSuccess.After(baseMoment) {
		t.Errorf("a check that never proved the winner stamped a success at %s", documented.LastSuccess)
	}
}
