package optimizer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/measure"
	"mosdns-router/internal/prober"
	"mosdns-router/internal/state"
)

// The runner is the only thing in this project that publishes an address into
// cdn-selector.json, and the response rewriter puts whatever is in that file
// into every DNS answer. A wrong line here is wrong traffic, so the tests below
// are about the two things that can do that: the order the phases run in (an
// address that is scored before it is proved will be scored well) and the
// conditions under which anything is written at all (a file that changes on a
// failed apply is a router rewriting to an address nobody proved).
//
// Every expectation in this file is a hand-derived literal. The measurements the
// fake prober returns are literals, and so is every number derived from them: a
// percentile, a score and a byte total that were computed by the code under test
// would pass no matter what the code does.
//
// The fixture of record is the three-candidate group below, chosen so that all
// three orderings agree:
//
//	address       p50   jitter   loss   speed
//	104.16.0.1    10ms  1ms      0.00   5 MiB/s
//	104.16.1.1    20ms  2ms      0.00   3 MiB/s
//	104.16.2.1    30ms  3ms      0.00   1 MiB/s
//
// With the documented weights 0.45/0.45/0.10 in ten-thousandths, a group of
// three whose latency, bandwidth and stability orders are the same ranks 3.0,
// 2.0 and 1.0: the best candidate takes 4500*3 + 4500*3 + 1000*3 = 30000 points
// over 10000, and each step down loses one rank in all three terms.

const (
	// runnerIdentityBytes is what one identity probe reads in the fixture of
	// record. A refused probe reports the same number, because the bytes crossed
	// the network whether or not the proof worked.
	runnerIdentityBytes = 2048

	// runnerDownloadBytes is what one transfer delivers in the fixture of record,
	// and runnerDownloadSpeed is how fast it does it, so the report's speed figure
	// is a literal rather than a division the test would have to reproduce.
	runnerDownloadBytes = 2 * mib
	runnerDownloadSpeed = float64(4 * mib)

	// runnerTCPSamples is what each fixture reports for the connect measurement.
	runnerTCPSamples = 10
)

// runnerPolicy is the shipped policy: cdn.latency_candidate_count 10, combined
// latency_top 3 and bandwidth_top 3, a 10 percent switch threshold, a 100 MiB
// daily budget and a 10 MiB / 3 second per-candidate transfer.
func runnerPolicy() config.Policy {
	return config.Policy{
		SchemaVersion: 1,
		Schedule:      "03:00",
		CDN: config.CDNPolicy{
			IPVersion:                "IPv4",
			Cloudflare:               config.CloudflarePolicy{MaxCandidates: 512},
			LatencyCandidateCount:    10,
			Combined:                 config.CombinedPolicy{LatencyTop: 3, BandwidthTop: 3},
			SwitchImprovementPercent: 10,
			Health:                   config.HealthPolicy{IntervalSeconds: 120, FailureThreshold: 3},
			Bandwidth: config.BandwidthPolicy{
				DailyBytes:          100 * mib,
				PerCandidateBytes:   10 * mib,
				PerCandidateSeconds: 3,
			},
		},
	}
}

// runnerSHA256 is the digest every fixture's runner is configured with, so the
// reports they produce carry a value a test can state as a literal.
//
// It is computed here from the literal bytes rather than pasted, so it cannot
// drift from them. It is not what pins the digest *function*: the document it
// hashes is not one a test could state a published digest for, so a case that
// wants the function itself checked uses a document every SHA-256 agrees on -
// see TestPolicyDigestIsTheDigestOfTheDocumentBytes.
var runnerSHA256 = func() string {
	sum := sha256.Sum256([]byte("schema_version: 1\n"))
	return hex.EncodeToString(sum[:])
}()

// The runner measures through its own narrow Prober interface rather than
// importing the prober package's, because that package's in-package tests use
// *Budget and Go forbids a package's test importing a package that imports it.
// internal/measure is the leaf that lets both spell the metric types the same
// way, and the assertions below are what keep the two declarations honest: the
// two calls whose types come from internal/measure have to agree exactly, and a
// day where one of them drifts is a compile error here rather than a run that
// measured nothing.
type proberMeasures interface {
	TCP(ctx context.Context, address netip.Addr, port uint16, samples int) (measure.TCPMetrics, error)
	HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (measure.HTTPMetrics, error)
}

var (
	_ proberMeasures    = Prober(nil)
	_ proberMeasures    = prober.Prober(nil)
	_ proberMeasures    = (*prober.NetworkProber)(nil)
	_ prober.ByteBudget = ByteBudget(nil)

	_ measure.TCPMetrics      = CandidateResult{}.TCP
	_ measure.HTTPMetrics     = CandidateResult{}.HTTP
	_ measure.DownloadMetrics = CandidateResult{}.Download
)

// addressFixture is everything the fake prober answers for one address. It is
// spelled out per address rather than defaulted, so a probe the runner should not
// have made is refused instead of answered: a fixture that answered anything
// would let a wrong phase order pass.
type addressFixture struct {
	// port is the port this address is served on. A connect measurement of any
	// other port fails, so a run that measures the wrong port cannot pass.
	port uint16
	// tcp is the connect measurement.
	tcp measure.TCPMetrics
	// identityBodyBytes is what the identity probe reports, whether or not it
	// succeeds.
	identityBodyBytes int64
	// identityErr refuses the identity proof for every profile, as an address that
	// is serving none of them does.
	identityErr error
	// identityRefusedFor refuses the identity proof for named profile hostnames and
	// answers the rest, which is the shape a real refusal has: a Cloudflare anycast
	// address serves the provider's own domains and cannot present a chain for a
	// CloudFront hostname.
	identityRefusedFor map[string]error
	// identityStatus is the status a successful identity proof reports.
	identityStatus int
	// transferLimit is the most this address will transfer. A run that asks the
	// prober for more is refused, so an unbounded transfer cannot pass.
	transferLimit int64
	// transferBytes and transferSpeed are what one transfer delivers and how fast.
	transferBytes int64
	transferSpeed float64
	// transferErr refuses the transfer after the reservation, as a truncated
	// transfer does.
	transferErr error
	// settleTwice makes the transfer settle the same reservation a second time,
	// which the budget refuses and a report has to show.
	settleTwice bool
	// identityCallsBeforeFailure is how many identity proofs this address answers
	// before it starts refusing them. One is the shape of an address that served
	// the run and then stopped serving: the first proof passes and the one the apply
	// runs afterwards does not.
	identityCallsBeforeFailure int
	// proofDelay is how long an identity proof of this address takes, so a case can
	// make the final proof outlive its deadline or make a set of them only fit
	// concurrently.
	proofDelay time.Duration
	// proofDelayAfterCalls is how many identity proofs this address answers at full
	// speed before its proofs start taking proofDelay. One is the shape of a host
	// that served the run and then stopped answering quickly: the run's proof is
	// quick and the apply's is not.
	proofDelayAfterCalls int
	// proofOutlivesDeadline makes a delayed proof answer in full even after the
	// caller's deadline, which is the shape of a transfer that has already started:
	// the bytes crossed the wire, so the prober reports them rather than pretending
	// it read nothing. It exists so a case can have a wave of proofs that all
	// succeed after the deadline, which is the only way to reach an un-fed tail in
	// the walk without the earlier profiles refusing first.
	proofOutlivesDeadline bool
}

// probeCall is one call the fake prober received, in the order it arrived.
type probeCall struct {
	Kind    string
	Address string
	Port    uint16
	Samples int
	// Hostname is the profile hostname an identity probe was made against, which is
	// the whole of what decides which profiles a proof covers.
	Hostname string
	// Reserve is what a transfer asked the budget for, which is the run's own
	// per-candidate limit, and Reserved is what the budget actually gave it. A
	// transfer whose Reserved is zero was refused by the day and read nothing, so
	// the two together say what the run spent rather than what it attempted.
	Reserve  int64
	Reserved int64
}

// fakeProber answers probes from a fixture and records the order they arrived
// in. It is a fake rather than a socket because the thing under test is the
// order the runner calls a prober in, and a real socket cannot report that.
type fakeProber struct {
	mutex    sync.Mutex
	calls    []probeCall
	fixtures map[string]*addressFixture
	// https counts the identity proofs each address has been asked for, so a
	// fixture can answer the run's proof and refuse the apply's.
	https map[string]int
	// inFlight and peak record how many identity proofs the prober is answering at
	// once, which is how a case sees whether the run proved a set of profiles
	// concurrently and under what limit.
	inFlight, peak int
	// before runs inside every probe, so a test can cancel the run from the
	// prober's side the way a real deadline would.
	before func(kind, address string)
}

var _ Prober = (*fakeProber)(nil)

func newFakeProber(fixtures map[string]*addressFixture) *fakeProber {
	return &fakeProber{fixtures: fixtures, https: make(map[string]int)}
}

func (f *fakeProber) record(call probeCall) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeProber) note(kind, address string) {
	if f.before != nil {
		f.before(kind, address)
	}
}

func (f *fakeProber) fixture(address netip.Addr) (*addressFixture, error) {
	found, ok := f.fixtures[address.String()]
	if !ok {
		return nil, fmt.Errorf("the fake prober has no fixture for %s", address)
	}
	return found, nil
}

func (f *fakeProber) TCP(ctx context.Context, address netip.Addr, port uint16, samples int) (measure.TCPMetrics, error) {
	f.record(probeCall{Kind: "tcp", Address: address.String(), Port: port, Samples: samples})
	f.note("tcp", address.String())
	fixture, err := f.fixture(address)
	if err != nil {
		return measure.TCPMetrics{}, err
	}
	if port != fixture.port {
		return measure.TCPMetrics{}, fmt.Errorf("%s is served on port %d, not %d", address, fixture.port, port)
	}
	if err := ctx.Err(); err != nil {
		return measure.TCPMetrics{}, err
	}
	return fixture.tcp, nil
}

func (f *fakeProber) HTTPS(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (measure.HTTPMetrics, error) {
	f.record(probeCall{Kind: "https", Address: subject.IP.String(), Port: profile.Port, Hostname: profile.Hostname})
	f.note("https", subject.IP.String())
	fixture, err := f.fixture(subject.IP)
	if err != nil {
		return measure.HTTPMetrics{}, err
	}
	if err := ctx.Err(); err != nil {
		return measure.HTTPMetrics{}, err
	}
	f.mutex.Lock()
	f.https[subject.IP.String()]++
	answered := f.https[subject.IP.String()]
	f.inFlight++
	if f.inFlight > f.peak {
		f.peak = f.inFlight
	}
	f.mutex.Unlock()
	_, refuses := fixture.identityRefusedFor[profile.Hostname]
	if fixture.proofDelay > 0 && !refuses &&
		(fixture.proofDelayAfterCalls == 0 || answered > fixture.proofDelayAfterCalls) {
		// A slow host, and a prober that gives up when the caller's deadline is
		// done, exactly as the real one does.
		if fixture.proofOutlivesDeadline {
			time.Sleep(fixture.proofDelay)
		} else {
			timer := time.NewTimer(fixture.proofDelay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				f.settle()
				return measure.HTTPMetrics{BodyBytes: fixture.identityBodyBytes}, ctx.Err()
			}
		}
	}
	f.settle()
	if fixture.identityCallsBeforeFailure > 0 && answered > fixture.identityCallsBeforeFailure {
		return measure.HTTPMetrics{BodyBytes: fixture.identityBodyBytes},
			fmt.Errorf("%s at %s: the response is a 403, which the profile does not expect", profile.Hostname, subject.IP)
	}
	// A refusal for this hostname alone, which is how a Cloudflare address behaves
	// against a CloudFront hostname: the other profiles are answered normally.
	if refused, is := fixture.identityRefusedFor[profile.Hostname]; is {
		return measure.HTTPMetrics{BodyBytes: fixture.identityBodyBytes}, refused
	}
	if fixture.identityErr != nil {
		// A refused probe reports what it read to reach its verdict, which is the
		// only accounting of the uncharged identity bytes there is.
		return measure.HTTPMetrics{BodyBytes: fixture.identityBodyBytes}, fixture.identityErr
	}
	return measure.HTTPMetrics{
		Status:     fixture.identityStatus,
		TLSMS:      8,
		TTFBMS:     12,
		TotalMS:    25,
		Colocation: "TEST",
		BodyBytes:  fixture.identityBodyBytes,
	}, nil
}

func (f *fakeProber) Download(ctx context.Context, subject candidate.Candidate, profile candidate.ProbeProfile, maxBytes int64, maxDuration time.Duration, budget ByteBudget) (measure.DownloadMetrics, error) {
	f.record(probeCall{Kind: "download", Address: subject.IP.String(), Port: profile.Port, Reserve: maxBytes})
	f.note("download", subject.IP.String())
	fixture, err := f.fixture(subject.IP)
	if err != nil {
		return measure.DownloadMetrics{}, err
	}
	if maxBytes > fixture.transferLimit {
		return measure.DownloadMetrics{}, fmt.Errorf("%s will not transfer more than %d bytes, the run asked for %d", subject.IP, fixture.transferLimit, maxBytes)
	}
	// The reservation comes before the transfer, as the prober's own contract
	// says it does, so a day that is full refuses here and the run sees why.
	reserved, err := budget.Reserve(maxBytes)
	f.mutex.Lock()
	f.calls[len(f.calls)-1].Reserved = reserved
	f.mutex.Unlock()
	if err != nil {
		return measure.DownloadMetrics{}, err
	}
	elapsed := time.Duration(float64(fixture.transferBytes) / fixture.transferSpeed * float64(time.Second))
	metrics := measure.DownloadMetrics{
		Bytes:          fixture.transferBytes,
		Elapsed:        elapsed,
		BytesPerSecond: fixture.transferSpeed,
	}
	budget.Consume(reserved, fixture.transferBytes)
	if fixture.settleTwice {
		budget.Consume(reserved, fixture.transferBytes)
	}
	if err := ctx.Err(); err != nil {
		return metrics, err
	}
	return metrics, fixture.transferErr
}

// kinds returns the phase of every call in the order it arrived, which is how a
// test sees the phase order rather than a set of phases.
func (f *fakeProber) kinds() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	kinds := make([]string, 0, len(f.calls))
	for _, call := range f.calls {
		kinds = append(kinds, call.Kind)
	}
	return kinds
}

func (f *fakeProber) addressesOf(kind string) []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	addresses := make([]string, 0, len(f.calls))
	for _, call := range f.calls {
		if call.Kind == kind {
			addresses = append(addresses, call.Address)
		}
	}
	slices.Sort(addresses)
	return addresses
}

func (f *fakeProber) count() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return len(f.calls)
}

// transfers returns the transfers the day's budget paid for, which is not the
// same list as the transfer calls: a call the budget refused read nothing.
func (f *fakeProber) transfers() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	addresses := make([]string, 0, len(f.calls))
	for _, call := range f.calls {
		if call.Kind == "download" && call.Reserved > 0 {
			addresses = append(addresses, call.Address)
		}
	}
	slices.Sort(addresses)
	return addresses
}

// settle records that one identity proof has stopped being answered.
func (f *fakeProber) settle() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.inFlight--
}

// peakProofs is the most identity proofs the prober was answering at once.
func (f *fakeProber) peakProofs() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.peak
}

// profiledCalls returns the identity proofs with the hostname each was made
// against, which is what says which profiles a proof covered.
func (f *fakeProber) profiledCalls() []probeCall {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	proofs := make([]probeCall, 0, len(f.calls))
	for _, call := range f.calls {
		if call.Kind == "https" {
			proofs = append(proofs, call)
		}
	}
	return proofs
}

// served builds the fixture of a global candidate that measures cleanly: a p50,
// a jitter, no loss, an identity proof, and a transfer of the recorded size.
func served(p50MS, jitterMS, loss, transferSpeed float64) *addressFixture {
	return &addressFixture{
		port:              443,
		tcp:               measure.TCPMetrics{Samples: runnerTCPSamples, P50MS: p50MS, P95MS: p50MS * 2, JitterMS: jitterMS, Loss: loss},
		identityBodyBytes: runnerIdentityBytes,
		identityStatus:    200,
		transferLimit:     10 * mib,
		transferBytes:     runnerDownloadBytes,
		transferSpeed:     transferSpeed,
	}
}

// globalProfiles is the profile set for a run whose groups are all global, which is
// every fixture in this file except the ones that name a CloudFront hostname. It
// exists so the common case reads as one call rather than a struct literal, and so
// a case that means to mix the two kinds cannot do it by accident.
func globalProfiles(profiles ...candidate.ProbeProfile) Profiles {
	return Profiles{Global: profiles}
}

// globalCandidate is one address of the global Cloudflare group.
func globalCandidate(address string) candidate.Candidate {
	return candidate.Candidate{
		Provider: candidate.ProviderCloudflare,
		IP:       netip.MustParseAddr(address),
		Source:   candidate.SourceCloudflare,
	}
}

// cloudFrontCandidate is one address of one CloudFront profile's group.
func cloudFrontCandidate(address, hostname string) candidate.Candidate {
	return candidate.Candidate{
		Provider: candidate.ProviderCloudFront,
		IP:       netip.MustParseAddr(address),
		Source:   candidate.SourceCloudFront,
		Hostname: hostname,
	}
}

// testProfile is a usable identity profile on the port every CDN serves on. The
// hostname is a reserved test name and is never resolved, because the prober is
// injected.
func testProfile(hostname string, port uint16) candidate.ProbeProfile {
	return candidate.ProbeProfile{
		Hostname:       hostname,
		URL:            fmt.Sprintf("https://%s/", hostname),
		Method:         http.MethodGet,
		Port:           port,
		ExpectedStatus: []int{200},
	}
}

// testProfileOnPort is a profile on a port that is not 443, which the URL has to
// name as well: the candidate package holds a profile's port to the one its URL
// resolves to, so a profile that said 8443 beside a URL that said 443 would be a
// document this build refuses before it opens a socket.
func testProfileOnPort(hostname string, port uint16) candidate.ProbeProfile {
	profile := testProfile(hostname, port)
	profile.URL = fmt.Sprintf("https://%s:%d/", hostname, port)
	return profile
}

// threeGlobals is the fixture of record: three global candidates whose latency,
// bandwidth and stability orders are the same, so their combined scores are the
// three literals 3.0, 2.0 and 1.0.
func threeGlobals() (map[string]*addressFixture, []candidate.Candidate) {
	fixtures := map[string]*addressFixture{
		"104.16.0.1": served(10, 1, 0, 5*mib),
		"104.16.1.1": served(20, 2, 0, 3*mib),
		"104.16.2.1": served(30, 3, 0, 1*mib),
	}
	candidates := []candidate.Candidate{
		globalCandidate("104.16.0.1"),
		globalCandidate("104.16.1.1"),
		globalCandidate("104.16.2.1"),
	}
	return fixtures, candidates
}

// runnerTuning is what a test may change about the runner it builds: the policy
// it reads its counts and its threshold from, and the paths and clock it works
// through.
type runnerTuning struct {
	policy  *config.Policy
	options *Options
}

// testRunner is a runner over a temporary directory, carrying the paths a test
// needs in order to read the files it wrote and compare them afterwards. It
// embeds the runner so a test reads as a run and an apply and not as a
// configuration.
type testRunner struct {
	*Runner
	directory    string
	selectorPath string
	budgetPath   string
	lockPath     string
}

// tickingClock is a clock that advances a millisecond every reading, which is what
// makes a phase boundary assertion mean something: under a frozen clock every
// stamp is the same instant and an ordering assertion over them is vacuous.
type tickingClock struct {
	mutex  sync.Mutex
	origin time.Time
	reads  int
}

func (c *tickingClock) now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	moment := c.origin.Add(time.Duration(c.reads) * time.Millisecond)
	c.reads++
	return moment
}

// newTestRunner builds a runner over a temporary directory, so nothing here can
// reach /var/lib, and fails the test if it cannot be built.
func newTestRunner(t *testing.T, prober Prober, tune ...func(*runnerTuning)) *testRunner {
	t.Helper()
	directory := t.TempDir()
	policy := runnerPolicy()
	options := Options{
		BudgetPath:      filepath.Join(directory, DefaultBudgetName),
		SelectorPath:    filepath.Join(directory, DefaultSelectorPathName),
		ControlLockPath: filepath.Join(directory, DefaultControlLockPathName),
		ConfigSHA256:    runnerSHA256,
		Location:        time.UTC,
		Now:             func() time.Time { return runnerNow },
	}
	for _, change := range tune {
		change(&runnerTuning{policy: &policy, options: &options})
	}
	runner, err := NewRunner(policy, prober, options)
	if err != nil {
		t.Fatalf("build the runner: %v", err)
	}
	return &testRunner{
		Runner:       runner,
		directory:    directory,
		selectorPath: options.SelectorPath,
		budgetPath:   options.BudgetPath,
		lockPath:     options.ControlLockPath,
	}
}

// newTestRunnerWithSelector is newTestRunner for the cases that need the selector
// path as well, which is every case that writes one.
func newTestRunnerWithSelector(t *testing.T, prober Prober, tune ...func(*runnerTuning)) (*Runner, string) {
	t.Helper()
	built := newTestRunner(t, prober, tune...)
	return built.Runner, built.selectorPath
}

// mustRunWithIncumbent measures the given candidates against a selector whose
// winner is incumbent, which is what makes the run's switch decision a real one.
func mustRunWithIncumbent(t *testing.T, runner *Runner, candidates []candidate.Candidate, incumbent string) Report {
	t.Helper()
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		LastGood:           mustSelector(t, 4, incumbent, ""),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return report
}

// runnerNow is the moment every test run is dated, so a report's age and a
// selector's timestamps are literals rather than whatever the clock said.
var runnerNow = time.Date(2026, 9, 26, 3, 0, 0, 0, time.UTC)

// phaseOrder is the documented order, as the names the report carries them under.
// A test that asserts the runner's calls never go backwards through this list is
// asserting the phase order rather than the presence of each phase.
var phaseOrder = []string{"tcp", "https", "download"}

// assertPhasesInOrder fails the test when any probe of one kind arrived after a
// probe of a later kind. This is the property the plan names: collect, TCP,
// HTTPS identity, latency shortlist, bandwidth, score, final proof.
func assertPhasesInOrder(t *testing.T, kinds []string) {
	t.Helper()
	position := make(map[string]int, len(phaseOrder))
	for index, kind := range phaseOrder {
		position[kind] = index
	}
	previous := -1
	previousName := "the start of the run"
	for _, kind := range kinds {
		current, known := position[kind]
		if !known {
			t.Fatalf("the runner made a %q call, which is not one of %v", kind, phaseOrder)
		}
		if current < previous {
			t.Fatalf("a %q call arrived after %s: the phase order is %v, the run called %v", kind, previousName, phaseOrder, kinds)
		}
		previous, previousName = current, "a "+kind+" call"
	}
}

// assertPhaseStamps fails the test when a phase boundary is missing or out of
// order. The labels are the report's own field names, so a failure says which
// boundary is wrong rather than that "a timestamp" is wrong.
//
// It is corroboration and not the proof of the phase order: under the frozen clock
// the other cases use, every boundary is the same instant, so what this checks here
// is that the fields are present and not out of order.
// TestRunnerStampsEachPhaseBoundaryFromTheClockAtTheMoment is the case that gives
// the check something to chew on, and assertPhasesInOrder - the prober's own call
// log - is what actually proves the order.
func assertPhaseStamps(t *testing.T, phases PhaseTimes) {
	t.Helper()
	for _, bound := range labelledPhases(phases)[:12] {
		if bound.value.IsZero() {
			t.Fatalf("the report has no %s: the phase was never recorded", bound.name)
		}
	}
	assertNonDecreasing(t, labelledPhases(phases)[:12])
	if !phases.FinalProof.StartedAt.IsZero() || !phases.FinalProof.EndedAt.IsZero() {
		t.Fatalf("a report-only run recorded a final proof at %s/%s: only an apply proves the winner again",
			phases.FinalProof.StartedAt, phases.FinalProof.EndedAt)
	}
}

// assertPhaseOrderWithProof is assertPhaseStamps for a report an apply has
// already published from, where the final proof has run too.
func assertPhaseOrderWithProof(t *testing.T, phases PhaseTimes) {
	t.Helper()
	labelled := labelledPhases(phases)
	for _, bound := range labelled {
		if bound.value.IsZero() {
			t.Fatalf("the applied report has no %s: the phase was never recorded", bound.name)
		}
	}
	assertNonDecreasing(t, labelled)
}

// labelledPhases is every phase boundary in the order the phases run, with the
// field names a report carries them under.
func labelledPhases(phases PhaseTimes) []struct {
	name  string
	value time.Time
} {
	bounds := []struct {
		name  string
		value time.Time
	}{
		{"collect.started_at", phases.Collect.StartedAt},
		{"collect.ended_at", phases.Collect.EndedAt},
		{"tcp.started_at", phases.TCP.StartedAt},
		{"tcp.ended_at", phases.TCP.EndedAt},
		{"identity.started_at", phases.Identity.StartedAt},
		{"identity.ended_at", phases.Identity.EndedAt},
		{"latency.started_at", phases.Latency.StartedAt},
		{"latency.ended_at", phases.Latency.EndedAt},
		{"bandwidth.started_at", phases.Bandwidth.StartedAt},
		{"bandwidth.ended_at", phases.Bandwidth.EndedAt},
		{"score.started_at", phases.Score.StartedAt},
		{"score.ended_at", phases.Score.EndedAt},
		{"final_proof.started_at", phases.FinalProof.StartedAt},
		{"final_proof.ended_at", phases.FinalProof.EndedAt},
	}
	return bounds
}

func assertNonDecreasing(t *testing.T, bounds []struct {
	name  string
	value time.Time
}) {
	t.Helper()
	for index := 1; index < len(bounds); index++ {
		if bounds[index].value.Before(bounds[index-1].value) {
			t.Fatalf("%s (%s) is before %s (%s): the phases ran out of order",
				bounds[index].name, bounds[index].value.Format(time.RFC3339Nano),
				bounds[index-1].name, bounds[index-1].value.Format(time.RFC3339Nano))
		}
	}
}

// mustGroup fails the test unless the report holds exactly one group, and returns
// it. Every single-group fixture in this file measures one group unless it says
// otherwise, so a run that invented a second group fails here rather than in a
// later expectation about the wrong one.
func mustGroup(t *testing.T, report Report, group string) GroupReport {
	t.Helper()
	if len(report.Groups) != 1 {
		t.Fatalf("the report holds %d groups, want 1: %v", len(report.Groups), groupNames(report))
	}
	if report.Groups[0].Group.String() != group {
		t.Fatalf("the report's group is %q, want %q", report.Groups[0].Group.String(), group)
	}
	return report.Groups[0]
}

// groupNamed is the group a multi-group run measured, found by the name the report
// carries it under.
func groupNamed(t *testing.T, report Report, group string) GroupReport {
	t.Helper()
	for _, candidateGroup := range report.Groups {
		if candidateGroup.Group.String() == group {
			return candidateGroup
		}
	}
	t.Fatalf("the report has no group %q; it holds %v", group, groupNames(report))
	return GroupReport{}
}

func groupNames(report Report) []string {
	names := make([]string, 0, len(report.Groups))
	for _, group := range report.Groups {
		names = append(names, group.Group.String())
	}
	return names
}

// mustWinner fails the test unless the group named a winner, and returns it.
func mustWinner(t *testing.T, group GroupReport) ReportWinner {
	t.Helper()
	if group.Winner == nil {
		t.Fatalf("the group %s named no winner, with %q as the reason", group.Group, group.NoWinner)
	}
	return *group.Winner
}

// candidateFor finds one candidate of a group report by address, and fails the
// test when it is not there.
func candidateFor(t *testing.T, group GroupReport, address string) ReportCandidate {
	t.Helper()
	for _, entry := range group.Candidates {
		if entry.IP == address {
			return entry
		}
	}
	present := make([]string, 0, len(group.Candidates))
	for _, entry := range group.Candidates {
		present = append(present, entry.IP)
	}
	t.Fatalf("the report has no candidate %s; it holds %v", address, present)
	return ReportCandidate{}
}

func TestRunnerRunsThePhasesInOrderAndReportsTheWinner(t *testing.T) {
	// The spine of this task. A run has to collect, measure connect latency, prove
	// every candidate's identity, shortlist by latency, measure bandwidth, score,
	// and only then be applied -- and the report has to say what each candidate
	// measured, which one won, what it cost, and under which two digests.
	fixtures, candidates := threeGlobals()
	fake := newFakeProber(fixtures)
	runner := newTestRunner(t, fake)

	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The phase order, from the prober's side: every connect measurement before
	// any identity proof, and every identity proof before any transfer.
	kinds := fake.kinds()
	wantKinds := []string{
		"tcp", "tcp", "tcp",
		"https", "https", "https",
		"download", "download", "download",
	}
	if !slices.Equal(kinds, wantKinds) {
		t.Fatalf("the run called the prober %v, want %v", kinds, wantKinds)
	}
	assertPhasesInOrder(t, kinds)
	assertPhaseStamps(t, report.Phases)

	group := mustGroup(t, report, "cloudflare/")
	if len(group.Candidates) != 3 {
		t.Fatalf("the report holds %d candidates, want the 3 the run collected", len(group.Candidates))
	}
	if group.NoWinner != "" {
		t.Errorf("the group reports %q as its no-winner reason, but it named a winner", group.NoWinner)
	}

	// Every measured number is the fixture's, and every derived number is a
	// literal: 3.0, 2.0 and 1.0 out of 4500/4500/1000 over a group of three.
	for _, want := range []struct {
		address string
		p50     float64
		jitter  float64
		speed   float64
		score   float64
	}{
		{"104.16.0.1", 10, 1, 5 * mib, 3.0},
		{"104.16.1.1", 20, 2, 3 * mib, 2.0},
		{"104.16.2.1", 30, 3, 1 * mib, 1.0},
	} {
		entry := candidateFor(t, group, want.address)
		if entry.Provider != string(candidate.ProviderCloudflare) {
			t.Errorf("%s reports provider %q, want %q", want.address, entry.Provider, candidate.ProviderCloudflare)
		}
		if entry.Source != candidate.SourceCloudflare {
			t.Errorf("%s reports source %q, want %q", want.address, entry.Source, candidate.SourceCloudflare)
		}
		if entry.Hostname != "" {
			t.Errorf("%s reports hostname %q, want none for a global candidate", want.address, entry.Hostname)
		}
		if entry.Samples != runnerTCPSamples {
			t.Errorf("%s reports %d samples, want %d", want.address, entry.Samples, runnerTCPSamples)
		}
		if entry.P50MS != want.p50 || entry.JitterMS != want.jitter || entry.Loss != 0 {
			t.Errorf("%s reports p50 %gms, jitter %gms, loss %g; want %gms, %gms, 0", want.address, entry.P50MS, entry.JitterMS, entry.Loss, want.p50, want.jitter)
		}
		if entry.IdentityBytes != runnerIdentityBytes {
			t.Errorf("%s reports %d identity bytes, want %d", want.address, entry.IdentityBytes, runnerIdentityBytes)
		}
		if entry.DownloadBytes != runnerDownloadBytes {
			t.Errorf("%s reports %d transfer bytes, want %d", want.address, entry.DownloadBytes, runnerDownloadBytes)
		}
		if entry.BytesPerSecond != want.speed {
			t.Errorf("%s reports %g B/s, want %g", want.address, entry.BytesPerSecond, want.speed)
		}
		if !entry.Eligible || entry.Reason != "" {
			t.Errorf("%s reports eligible=%v reason=%q, want an eligible candidate with no reason", want.address, entry.Eligible, entry.Reason)
		}
		if entry.Score != want.score {
			t.Errorf("%s scores %g, want %g", want.address, entry.Score, want.score)
		}
	}

	// The group's lower tail, the one figure the scorer exports for a report:
	// three speeds of 5, 3 and 1 MiB/s ascending, and ceil(0.10*3) = 1 of them is
	// the slowest.
	if group.P10BytesPerSecond != float64(mib) {
		t.Errorf("the group reports a p10 speed of %g B/s, want %g (the slowest of 1, 3 and 5 MiB/s)", group.P10BytesPerSecond, float64(mib))
	}

	winner := mustWinner(t, group)
	if winner.IP != "104.16.0.1" {
		t.Errorf("the winner is %s, want 104.16.0.1 (the best on all three ranks)", winner.IP)
	}
	if winner.Score != 3.0 {
		t.Errorf("the winner scores %g, want 3", winner.Score)
	}
	if winner.Source != candidate.SourceCloudflare {
		t.Errorf("the winner records source %q, want %q", winner.Source, candidate.SourceCloudflare)
	}
	// No selector existed, so there is no incumbent to beat and the gate is the
	// empty-winner case the scorer documents.
	if winner.CurrentIP != "" || winner.CurrentScore != 0 {
		t.Errorf("the winner records an incumbent %q at score %g, want none", winner.CurrentIP, winner.CurrentScore)
	}
	if !winner.SwitchAllowed {
		t.Errorf("the winner is not allowed to switch, with %q as the reason", winner.SwitchRefusal)
	}
	if report.FinalProofPassed {
		t.Error("a report-only run claims the winner was proved again; only an apply does that")
	}

	// The two digests, and the budget the day ended up at: three reservations of
	// 10 MiB settled at 2 MiB each, so the day stands at 3 * 2 MiB.
	if report.ConfigSHA256 != runnerSHA256 {
		t.Errorf("the report carries config digest %q, want %q", report.ConfigSHA256, runnerSHA256)
	}
	if report.PolicySHA256 != runnerSHA256 {
		t.Errorf("the report carries policy digest %q, want the digest of the policy document bytes", report.PolicySHA256)
	}
	if report.IdentityBytes != 3*runnerIdentityBytes {
		t.Errorf("the report accounts for %d identity bytes, want %d", report.IdentityBytes, 3*runnerIdentityBytes)
	}
	if report.BudgetUsed != 3*runnerDownloadBytes {
		t.Errorf("the report says the day stands at %d bytes, want %d", report.BudgetUsed, 3*runnerDownloadBytes)
	}
	if report.BudgetExhausted {
		t.Error("the report says the day ran out, but every transfer was charged against it")
	}
	if len(report.SettleRefusals) != 0 {
		t.Errorf("the report carries settlement refusals %v, want none", report.SettleRefusals)
	}
	if report.Stale {
		t.Error("the report says the candidate set was stale, but the source was not marked stale")
	}
	if !report.GeneratedAt.Equal(runnerNow) {
		t.Errorf("the report is generated at %s, want %s", report.GeneratedAt, runnerNow)
	}
}

func TestRunnerRecordsTheStaleMarkerOfTheCandidateSetItWasGiven(t *testing.T) {
	// A run whose ranges could not be refreshed measured yesterday's addresses.
	// A report that says "3 candidates" without saying so is presenting a cached
	// document as today's, which is the one thing the serve-stale decision has to
	// be visible about.
	fixtures, candidates := threeGlobals()
	runner := newTestRunner(t, newFakeProber(fixtures))

	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		Stale:              true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.Stale {
		t.Error("the report does not say the candidate set was stale, but the source was marked stale")
	}
}

func TestRunnerAccountsForTheIdentityBytesOfARefusedProbe(t *testing.T) {
	// Identity probing is deliberately outside the daily budget, so
	// HTTPMetrics.BodyBytes is the only record of what it cost, and a refused probe
	// is exactly the case where bytes were spent and nothing was published in
	// exchange. The idiomatic "metrics, err := HTTPS(...); if err != nil { continue }"
	// throws that record away, and the total below would come to 2048 instead of
	// 6144.
	fixtures, candidates := threeGlobals()
	// The middle candidate refuses its proof, having read 4096 bytes to reach the
	// verdict, and the other two succeed after reading 1024 each.
	refused := served(20, 2, 0, 3*mib)
	refused.identityErr = errors.New("the response for speed.example.test is a 403, which the profile does not expect")
	refused.identityBodyBytes = 4096
	fixtures["104.16.1.1"] = refused
	quick := served(10, 1, 0, 5*mib)
	quick.identityBodyBytes = 1024
	fixtures["104.16.0.1"] = quick
	slow := served(30, 3, 0, 1*mib)
	slow.identityBodyBytes = 1024
	fixtures["104.16.2.1"] = slow

	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.IdentityBytes != 1024+4096+1024 {
		t.Errorf("the report accounts for %d uncharged identity bytes, want %d (the refused probe's 4096 included)", report.IdentityBytes, 1024+4096+1024)
	}
	// The refused probe's bytes are also on its own line, because that is the line
	// an operator looks at when a run spends more than the budget explained.
	group := mustGroup(t, report, "cloudflare/")
	if got := candidateFor(t, group, "104.16.1.1").IdentityBytes; got != 4096 {
		t.Errorf("the refused candidate reports %d identity bytes, want the 4096 its probe read", got)
	}
}

func TestRunnerKeepsAnUnprovedCandidateOutOfTheScoredGroup(t *testing.T) {
	// The first identity gate. A candidate the proof will not vouch for is not
	// slower than the others, it is not eligible, and the scorer is never given it:
	// a candidate that reached the scorer without a proof would be scored, and
	// scored well, for an address that cannot serve the hostname.
	fixtures, candidates := threeGlobals()
	// The best candidate on every rank is the one that cannot be proved, which is
	// the shape of the failure this gate exists for: without it, 104.16.0.1 wins
	// with 3.0 and is published.
	unproved := served(10, 1, 0, 5*mib)
	unproved.identityErr = errors.New("the certificate presented is for other.example.test, not speed.example.test")
	unproved.identityBodyBytes = 0
	fixtures["104.16.0.1"] = unproved

	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := mustGroup(t, report, "cloudflare/")
	refused := candidateFor(t, group, "104.16.0.1")
	if refused.Reason != ReasonIdentityRefused {
		t.Errorf("the unproved candidate is refused with %q, want %q", refused.Reason, ReasonIdentityRefused)
	}
	if refused.Eligible || refused.Score != 0 {
		t.Errorf("the unproved candidate is eligible=%v with score %g, want ineligible and un scored", refused.Eligible, refused.Score)
	}
	if refused.Detail == "" {
		t.Error("the unproved candidate carries no detail, so the report does not say which host refused it")
	}
	// It is not transferred either: a transfer to an address that cannot serve the
	// hostname spends the user's bandwidth to learn nothing.
	for _, address := range newFakeProber(fixtures).addressesOf("download") {
		if address == "104.16.0.1" {
			t.Error("the run transferred from the candidate the identity gate refused")
		}
	}
	winner := mustWinner(t, group)
	if winner.IP != "104.16.1.1" {
		t.Errorf("the winner is %s, want 104.16.1.1: the two proved candidates are all that is left", winner.IP)
	}
}

func TestRunnerReportsTheNamedReasonNoCandidateQualified(t *testing.T) {
	// A run where nothing was proved and a run where everything was over a ceiling
	// are different incidents, and a report that says only "no winner" sends the
	// operator looking in the wrong place.
	fixtures, candidates := threeGlobals()
	for _, fixture := range fixtures {
		fixture.identityErr = errors.New("the response for speed.example.test is a 521, which the profile does not expect")
	}
	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := mustGroup(t, report, "cloudflare/")
	if group.Winner != nil {
		t.Fatalf("the group named a winner (%s) although no candidate was proved", group.Winner.IP)
	}
	if group.NoWinner != ReasonNoProvedCandidate {
		t.Errorf("the group reports %q as its no-winner reason, want %q", group.NoWinner, ReasonNoProvedCandidate)
	}
	if len(group.Candidates) != 3 {
		t.Errorf("the report lists %d candidates, want the 3 that were refused, so the report shows what was measured", len(group.Candidates))
	}
	// A report with no winner has nothing to prove again, and says so by leaving
	// the final proof's boundaries empty.
	if !report.Phases.FinalProof.StartedAt.IsZero() || !report.Phases.FinalProof.EndedAt.IsZero() {
		t.Error("a report with no winner recorded a final proof")
	}
}

func TestRunnerReportsTheNamedReasonEveryCandidateWasOverACeiling(t *testing.T) {
	// The other half of the same question: every candidate connected and was
	// proved, and every one of them was over a ceiling. That is a different incident
	// from a run where the proof refused everything, and it is the one an operator
	// fixes by widening the ceilings rather than by looking at the network. The two
	// ceilings also have to name themselves, because "excluded" does not say which
	// of them to widen.
	fixtures, _ := threeGlobals()
	candidates := []candidate.Candidate{globalCandidate("104.16.1.1"), globalCandidate("104.16.2.1")}
	// A loss of 0.5 against the documented 0.10 ceiling, and a p50 of 400ms against
	// the documented 150ms.
	fixtures["104.16.1.1"] = served(20, 2, 0.50, 3*mib)
	fixtures["104.16.2.1"] = served(400, 3, 0, 1*mib)
	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := mustGroup(t, report, "cloudflare/")
	if group.Winner != nil {
		t.Fatalf("the group named a winner (%s) although every candidate was over a ceiling", group.Winner.IP)
	}
	if group.NoWinner != ReasonNoEligibleCandidate {
		t.Errorf("the group reports %q as its no-winner reason, want %q", group.NoWinner, ReasonNoEligibleCandidate)
	}
	if reason := candidateFor(t, group, "104.16.1.1").Reason; reason != ReasonLossAboveLimit {
		t.Errorf("the lossy candidate is refused with %q, want %q", reason, ReasonLossAboveLimit)
	}
	if reason := candidateFor(t, group, "104.16.2.1").Reason; reason != ReasonLatencyAboveLimit {
		t.Errorf("the slow candidate is refused with %q, want %q", reason, ReasonLatencyAboveLimit)
	}
}

func TestRunnerReportsTheSwitchesItRefusedAndTheirReason(t *testing.T) {
	// The switch gate is the other half of what keeps a worse address out of
	// service: the new winner has to be at least cdn.switch_improvement_percent
	// better than the incumbent. A run that found a winner and could not switch has
	// to say so, and say why, because "the run succeeded" is otherwise the whole
	// of what an operator hears.
	fixtures, candidates := threeGlobals()
	// The incumbent is measured in the same run, as every run does, and it is the
	// best of the group: 3.0. The best proved candidate is 104.16.1.1 at 2.0,
	// which is not ten percent better than 3.0 and may not take the address.
	incumbent := served(20, 2, 0, 3*mib)
	fixtures["104.16.0.1"] = incumbent
	retained := globalCandidate("104.16.0.1")
	retained.Source = candidate.SourceRetained

	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		LastGood:           mustSelector(t, 4, "104.16.0.1", ""),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := mustGroup(t, report, "cloudflare/")
	winner := mustWinner(t, group)
	if winner.IP != "104.16.0.1" {
		t.Fatalf("the winner is %s, want the incumbent 104.16.0.1 at 3.0", winner.IP)
	}
	if winner.CurrentIP != "104.16.0.1" || winner.CurrentScore != 3.0 {
		t.Errorf("the winner records an incumbent %q at %g, want 104.16.0.1 at 3", winner.CurrentIP, winner.CurrentScore)
	}
	if !winner.SwitchAllowed {
		t.Errorf("the winner is not allowed to switch, with %q as the reason", winner.SwitchRefusal)
	}
	// The winner IS the address already in service, so there is no switch to
	// allow and the report says that rather than claiming an improvement of zero
	// percent over itself, which the gate would refuse.
	if winner.SwitchRefusal != "the winner is the address already in service" {
		t.Errorf("the winner records %q, want the note that it is the address already in service", winner.SwitchRefusal)
	}
}

func TestRunnerReportsARefusedSwitchWhenTheWinnerIsNotAnImprovement(t *testing.T) {
	// The switch gate is the other half of what keeps a worse address out of
	// service: a new winner has to be at least cdn.switch_improvement_percent
	// better than the incumbent, and a run that found a winner and could not switch
	// has to say so, because "the run succeeded" is otherwise the whole of what an
	// operator hears.
	//
	// The threshold is 100 percent here for clarity about the arithmetic rather than
	// for reachability: the scores are 3.0, 2.0 and 1.0, the incumbent is the middle
	// one, and 3.0 is not twice 2.0. The shipped ten percent refuses switches too -
	// closeCallCloudFront below is a group where the winner's 2.45 is 4.3 percent
	// above the runner-up's 2.35 and the gate says no - but that takes a group whose
	// three rank orders disagree, and this case is about the run recording a
	// refusal at all.
	fixtures, candidates := threeGlobals()
	report, err := newTestRunner(t, newFakeProber(fixtures), func(tuning *runnerTuning) {
		tuning.policy.CDN.SwitchImprovementPercent = 100
	}).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		LastGood:           mustSelector(t, 4, "104.16.1.1", ""),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	winner := mustWinner(t, mustGroup(t, report, "cloudflare/"))
	if winner.IP != "104.16.0.1" {
		t.Fatalf("the winner is %s, want 104.16.0.1 at 3.0", winner.IP)
	}
	if winner.CurrentIP != "104.16.1.1" || winner.CurrentScore != 2.0 {
		t.Fatalf("the winner records an incumbent %q at %g, want 104.16.1.1 at 2.0", winner.CurrentIP, winner.CurrentScore)
	}
	if winner.SwitchAllowed {
		t.Error("a winner of 3.0 was allowed to replace an incumbent of 2.0 under a 100 percent threshold, but 3.0 is not twice 2.0")
	}
	if !strings.Contains(winner.SwitchRefusal, "100") {
		t.Errorf("the refusal %q does not name the threshold it failed", winner.SwitchRefusal)
	}
}

func TestRunnerKeepsTheCurrentWinnerWhenTheDaysBudgetIsFull(t *testing.T) {
	// The day's budget is the hard cap the whole project exists to keep, and a run
	// that cannot afford to measure speed is not a failed run: the latency and
	// identity phases still finish, the transfers that do not fit are skipped, the
	// report says the day ran out, and no winner is allowed to switch. A run that
	// could not measure must not get to change the address in service.
	directory := t.TempDir()
	// The day is spent before the run starts: ten reservations of 10 MiB, left
	// charged exactly as a crashed process would leave them.
	spent := mustNewPersistentBudget(t, directory, dailyBudgetBytes, runnerNow)
	for attempt := 1; attempt <= 10; attempt++ {
		mustReserve(t, spent, perCandidateBytes)
	}
	fixtures, candidates := threeGlobals()
	fake := newFakeProber(fixtures)
	report, err := newTestRunner(t, fake, func(tuning *runnerTuning) {
		tuning.options.BudgetPath = filepath.Join(directory, DefaultBudgetName)
	}).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		LastGood:           mustSelector(t, 4, "104.16.0.1", ""),
	})
	if err != nil {
		t.Fatalf("Run returned %v, want a report with no error: a full budget is not a failed run", err)
	}
	if !report.BudgetExhausted {
		t.Error("the report does not say the day ran out")
	}
	if got := len(fake.transfers()); got != 0 {
		t.Errorf("the run read from %d candidates against a full day, want 0: %v", got, fake.transfers())
	}
	// The phases that cost nothing still ran, so the report describes a real
	// measurement rather than a refusal.
	if len(fake.addressesOf("https")) != 3 {
		t.Errorf("the run proved %d candidates, want 3: the identity phase does not spend the budget", len(fake.addressesOf("https")))
	}
	if report.IdentityBytes != 3*runnerIdentityBytes {
		t.Errorf("the report accounts for %d identity bytes, want %d", report.IdentityBytes, 3*runnerIdentityBytes)
	}
	winner := mustWinner(t, mustGroup(t, report, "cloudflare/"))
	if winner.SwitchAllowed {
		t.Error("a winner from a run that measured no speed was allowed to replace the address in service")
	}
	if winner.SwitchRefusal != ReasonBudgetExhaustedSwitch {
		t.Errorf("the refusal is %q, want %q", winner.SwitchRefusal, ReasonBudgetExhaustedSwitch)
	}
	// The day still stands where the previous run left it: nothing was reserved
	// and so nothing had to be handed back.
	if report.BudgetUsed != dailyBudgetBytes {
		t.Errorf("the report says the day stands at %d bytes, want the %d it was left at", report.BudgetUsed, dailyBudgetBytes)
	}
}

func TestRunnerSettlesThroughSettleAndReportsARefusedSettlement(t *testing.T) {
	// The runner settles through Budget.Settle, never through Consume, because
	// Consume cannot report a refusal and a refused settlement is the day charged
	// for bytes that were handed back. A transfer that settles the same reservation
	// twice is the shape of it: the second settle is refused, the day keeps the one
	// charge it is owed, and the report names the refusal rather than swallowing it.
	fixtures, candidates := threeGlobals()
	doubleSettling := served(20, 2, 0, 3*mib)
	doubleSettling.settleTwice = true
	fixtures["104.16.1.1"] = doubleSettling
	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.SettleRefusals) != 1 {
		t.Fatalf("the report carries %d settlement refusals, want 1: %v", len(report.SettleRefusals), report.SettleRefusals)
	}
	if !strings.Contains(report.SettleRefusals[0], "no outstanding reservation") {
		t.Errorf("the refusal %q does not name the refused settlement", report.SettleRefusals[0])
	}
	// The double settle handed back nothing the second time, so the day stands at
	// three transfers of 2 MiB and not at one of them twice refunded.
	if report.BudgetUsed != 3*runnerDownloadBytes {
		t.Errorf("the day stands at %d bytes, want %d: the refused settle must not hand back the same bytes again", report.BudgetUsed, 3*runnerDownloadBytes)
	}
}

func TestRunnerDownloadsOnlyTheLatencyShortlist(t *testing.T) {
	// The bandwidth phase is where the user's traffic goes, so it runs on the ten
	// fastest candidates and not on the other two, and the two are reported as
	// outside the shortlist with the named reason. This is also the case that pins
	// the shortlist count to the policy: cdn.latency_candidate_count is 10.
	fixtures, candidates := runnerTwelveGlobals()
	fake := newFakeProber(fixtures)
	report, err := newTestRunner(t, fake).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Twelve candidates with p50s of 10ms to 32ms in address order, so the ten
	// fastest are 104.16.0.1 through 104.16.9.1 and the two left out are the last
	// two addresses.
	want := []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1", "104.16.3.1", "104.16.4.1", "104.16.5.1",
		"104.16.6.1", "104.16.7.1", "104.16.8.1", "104.16.9.1",
	}
	if got := fake.addressesOf("download"); !slices.Equal(got, want) {
		t.Errorf("the run transferred from %v, want the ten fastest %v", got, want)
	}
	group := mustGroup(t, report, "cloudflare/")
	if len(group.Candidates) != 12 {
		t.Fatalf("the report lists %d candidates, want all 12", len(group.Candidates))
	}
	for _, address := range []string{"104.16.10.1", "104.16.11.1"} {
		entry := candidateFor(t, group, address)
		if entry.Reason != ReasonOutsideLatencyTop {
			t.Errorf("%s is refused with %q, want %q", address, entry.Reason, ReasonOutsideLatencyTop)
		}
		if entry.DownloadBytes != 0 {
			t.Errorf("%s reports %d transfer bytes, but it was never transferred to", address, entry.DownloadBytes)
		}
	}
}

func TestRunnerReportsACandidateOnTheShortlistButInNeitherHalfOfTheCombinedSet(t *testing.T) {
	// The scored population is the union of the best three of the shortlist on
	// latency and the best three of it on speed, not the whole shortlist, and a
	// candidate that is on the shortlist and in neither half is measured and has no
	// score. A report that scored it would be reporting a percentile of a group it
	// never entered.
	fixtures := map[string]*addressFixture{
		// The best on both halves.
		"104.16.0.1": served(10, 1, 0, 5*mib),
		// Second on both halves.
		"104.16.1.1": served(20, 2, 0, 4*mib),
		// Third on both halves.
		"104.16.2.1": served(30, 3, 0, 3*mib),
		// Fourth on both halves: outside both halves of a group of five.
		"104.16.3.1": served(40, 4, 0, 2*mib),
		// Fifth on both halves.
		"104.16.4.1": served(50, 5, 0, 1*mib),
	}
	candidates := []candidate.Candidate{
		globalCandidate("104.16.0.1"),
		globalCandidate("104.16.1.1"),
		globalCandidate("104.16.2.1"),
		globalCandidate("104.16.3.1"),
		globalCandidate("104.16.4.1"),
	}
	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := mustGroup(t, report, "cloudflare/")
	// Every candidate was transferred to, because every one of them was on the
	// shortlist, and the one outside the union still shows what it delivered.
	outside := candidateFor(t, group, "104.16.3.1")
	if outside.Reason != ReasonOutsideCombined {
		t.Errorf("104.16.3.1 is refused with %q, want %q", outside.Reason, ReasonOutsideCombined)
	}
	if outside.Eligible || outside.Score != 0 {
		t.Errorf("104.16.3.1 is eligible=%v with score %g, want ineligible and un scored", outside.Eligible, outside.Score)
	}
	if outside.DownloadBytes != runnerDownloadBytes {
		t.Errorf("104.16.3.1 reports %d transfer bytes, want %d: it was on the shortlist and was measured", outside.DownloadBytes, runnerDownloadBytes)
	}
	// The group's reported floor is the scored set's, so it is the third-best of
	// the five speeds: 5, 4, 3, 2 and 1 MiB/s ascending, and ceil(0.10*3) = 1 of
	// the three scored is the slowest of them.
	if group.P10BytesPerSecond != 3*float64(mib) {
		t.Errorf("the group reports a p10 of %g B/s, want %g (the slowest of the three scored: 3, 4 and 5 MiB/s)", group.P10BytesPerSecond, 3*float64(mib))
	}
}

func TestRunnerReturnsAPartialReportWhenTheRunIsCancelled(t *testing.T) {
	// A cancelled run is not a run that published something half measured: it
	// returns what it did, says the error, and applies nothing. The phase stamps
	// are how a reader tells how far it got.
	fixtures, candidates := threeGlobals()
	fake := newFakeProber(fixtures)
	ctx, cancel := context.WithCancel(t.Context())
	fake.before = func(kind, _ string) {
		if kind == "https" {
			cancel()
		}
	}
	report, err := newTestRunner(t, fake).Run(ctx, Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err == nil {
		t.Fatal("Run returned no error for a cancelled run, want the context's error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v, want an error that is context.Canceled", err)
	}
	// The collect and connect phases finished, and so did the identity phase the
	// cancellation happened inside: its boundaries say where it got to. Nothing
	// after it started, and a report that claimed a latency shortlist or a score for
	// a cancelled run would be describing work that was not done.
	if report.Phases.Collect.EndedAt.IsZero() || report.Phases.TCP.EndedAt.IsZero() {
		t.Error("the partial report is missing the boundaries of the phases that did finish")
	}
	if report.Phases.Identity.StartedAt.IsZero() || report.Phases.Identity.EndedAt.IsZero() {
		t.Error("the partial report is missing the identity phase's boundaries, which is the phase the run was cancelled inside")
	}
	if !report.Phases.Latency.StartedAt.IsZero() || !report.Phases.Bandwidth.StartedAt.IsZero() || !report.Phases.Score.StartedAt.IsZero() {
		t.Error("the partial report records a phase that never ran")
	}
	if len(report.Groups) != 0 {
		t.Errorf("the partial report holds %d groups, want none: nothing was scored", len(report.Groups))
	}
	// Nothing was transferred to, so the day is not charged for a run that could
	// not finish.
	if report.BudgetUsed != 0 {
		t.Errorf("the partial report says the day stands at %d bytes, want 0: the run never reserved", report.BudgetUsed)
	}
}

// A cancellation is not a reason to forget what the run already spent. The
// identity phase's own bytes are the one egress the budget does not pay for, so
// the report is the only accounting of them there is - and a run cut short
// half way through the phase is exactly the case where an operator needs it,
// because the day's report will not add up otherwise.
//
// One candidate against two profiles makes the order of the two facts certain: the
// first proof runs to completion and reads its 2048 bytes, and the cancellation
// arrives at the second. So the phase ends having spent exactly one probe's worth,
// and the report has to say so rather than nothing.
func TestACancelledIdentityPhaseStillReportsTheUnchargedBytesItSpent(t *testing.T) {
	fixtures, candidates := threeGlobals()
	fake := newFakeProber(fixtures)
	ctx, cancel := context.WithCancel(t.Context())
	proofs := 0
	fake.before = func(kind, _ string) {
		if kind != "https" {
			return
		}
		proofs++
		if proofs == 2 {
			cancel()
		}
	}
	profiles := []candidate.ProbeProfile{
		testProfile("speed.example.test", 443),
		testProfile("secure.example.test", 443),
	}
	report, err := newTestRunner(t, fake).Run(ctx, Input{
		Cloudflare:         candidates[:1],
		CloudflareProfiles: profiles,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want an error that is context.Canceled", err)
	}
	if proofs < 2 {
		t.Fatalf("the phase made %d identity proofs, want at least 2: the case needs one that completes and one that is cancelled", proofs)
	}
	// One probe of the record read 2048 bytes and one was cancelled before it read
	// any, so the run's uncharged egress is exactly one probe's worth.
	if report.IdentityBytes != runnerIdentityBytes {
		t.Errorf("the partial report's identity total = %d, want %d: the proof that completed spent them, and the budget does not account for identity probes",
			report.IdentityBytes, runnerIdentityBytes)
	}
}

// A report that names only what this run spent cannot answer the question an
// operator has before they spend it: with the shipped policy a ten-candidate
// shortlist at 10 MiB each is exactly the 100 MiB day, so at most one switching
// run is possible per local date - and a report-only run spends the same budget as
// an applying one. So the report carries the limit and what is left of it.
//
// This run transfers three candidates at 2 MiB each, so the day stands at 6 MiB
// of 100 MiB and 94 MiB is left: 6 * 1048576 = 6291456, and 100 * 1048576 minus
// that is 98566144.
func TestARunReportsTheDaysLimitAndWhatIsLeftOfIt(t *testing.T) {
	fixtures, candidates := threeGlobals()
	report := mustRunWithIncumbent(t, newTestRunner(t, newFakeProber(fixtures)).Runner, candidates, "104.16.1.1")

	if report.BudgetUsed != 3*runnerDownloadBytes {
		t.Fatalf("the report says the day stands at %d bytes, want %d: three transfers of 2 MiB", report.BudgetUsed, 3*runnerDownloadBytes)
	}
	if report.BudgetLimit != 100*mib {
		t.Errorf("the report names a limit of %d bytes, want the policy's %d", report.BudgetLimit, 100*mib)
	}
	if report.BudgetRemaining != 98566144 {
		t.Errorf("the report says %d bytes remain, want 98566144: 100 MiB less the 6 MiB this run transferred", report.BudgetRemaining)
	}
}

// The limit in the report is the one the run was held to, not the one the policy
// document names. A day can be tightened by hand in the budget document, and
// dayRule holds the day to the smaller of the two, so a report that quoted the
// policy instead would show an operator 90 MiB of room on a 50 MiB day.
//
// The document says 10 MiB already spent and allows 50, so this run's three 2 MiB
// transfers leave 16 MiB spent: 10 + 6 MiB = 16777216, and 50 MiB less that is
// 35651584.
func TestTheReportsBudgetLimitIsTheOneTheRunWasHeldTo(t *testing.T) {
	fixtures, candidates := threeGlobals()
	built := newTestRunner(t, newFakeProber(fixtures))
	record := state.BandwidthBudgetState{
		SchemaVersion: state.SchemaVersion,
		LocalDate:     runnerNow.Format("2006-01-02"),
		LimitBytes:    50 * mib,
		UsedBytes:     10 * mib,
	}
	if err := state.WriteJSONAtomic(built.budgetPath, record); err != nil {
		t.Fatalf("write the budget fixture: %v", err)
	}

	report := mustRunWithIncumbent(t, built.Runner, candidates, "104.16.1.1")
	if report.BudgetLimit != 50*mib {
		t.Errorf("the report names a limit of %d bytes, want the 50 MiB the document tightened it to", report.BudgetLimit)
	}
	if report.BudgetUsed != 16*mib {
		t.Errorf("the report says the day stands at %d bytes, want %d: 10 MiB already spent plus this run's 6 MiB", report.BudgetUsed, 16*mib)
	}
	if report.BudgetRemaining != 35651584 {
		t.Errorf("the report says %d bytes remain, want 35651584: 50 MiB less the 16 MiB spent", report.BudgetRemaining)
	}
}

func TestRunnerMeasuresWhileAnotherProcessHoldsTheControlLock(t *testing.T) {
	// The control lock is held for the read-validate-increment-write of the
	// selector and for the final proof in front of it, and for nothing else. A
	// measurement run that needed it would block apply, pin and the health timer
	// behind a download, so this run has to be possible with the lock held by
	// somebody else.
	directory := t.TempDir()
	lockPath := filepath.Join(directory, DefaultControlLockPathName)
	held, err := filelock.Acquire(lockPath)
	if err != nil {
		t.Fatalf("take the control lock: %v", err)
	}
	defer func() { _ = held.Close() }()

	fixtures, candidates := threeGlobals()
	report, err := newTestRunner(t, newFakeProber(fixtures), func(tuning *runnerTuning) {
		tuning.options.ControlLockPath = lockPath
	}).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run with the control lock held by another descriptor: %v", err)
	}
	if mustWinner(t, mustGroup(t, report, "cloudflare/")).IP != "104.16.0.1" {
		t.Error("the run did not reach a winner while the control lock was held")
	}
}

// twelveGlobals is the brief's candidate count, with a p50 that rises with the
// address so the latency shortlist is the first ten addresses and the two that
// fall outside it are the last two. Every candidate is proved and transfers, so
// the only thing that keeps the two out is the shortlist.
//
//	address        p50   jitter   loss   speed
//	104.16.0.1     10ms  1ms      0.00   5 MiB/s
//	...
//	104.16.9.1     28ms  10ms     0.00   10 MiB/s
//	104.16.10.1    30ms  11ms     0.00   0.5 MiB/s
//	104.16.11.1    32ms  12ms     0.00   11 MiB/s
func runnerTwelveGlobals() (map[string]*addressFixture, []candidate.Candidate) {
	fixtures := make(map[string]*addressFixture, 12)
	candidates := make([]candidate.Candidate, 0, 12)
	for index := 0; index < 12; index++ {
		address := fmt.Sprintf("104.16.%d.1", index)
		speed := float64((12-index)*mib) / 2
		fixtures[address] = served(float64(10+2*index), float64(1+index), 0, speed)
		candidates = append(candidates, globalCandidate(address))
	}
	// The last two are the slowest to connect and the two the shortlist leaves out.
	fixtures["104.16.10.1"] = served(30, 11, 0, 0.5*float64(mib))
	fixtures["104.16.11.1"] = served(32, 12, 0, 11*float64(mib))
	return fixtures, candidates
}

// mustSelector writes a selector state with the given generation and addresses,
// and returns it, so a test starts from a real document rather than a struct the
// production code never wrote.
func mustSelector(t *testing.T, generation uint64, winner, fallback string) state.Selector {
	t.Helper()
	selector := state.Selector{
		SchemaVersion: state.SchemaVersion,
		Generation:    generation,
		Mode:          "auto",
		Provider:      string(candidate.ProviderCloudflare),
		WinnerIP:      winner,
		FallbackIP:    fallback,
		LastSuccess:   runnerNow.Add(-time.Hour),
	}
	if err := selector.Validate(); err != nil {
		t.Fatalf("the fixture selector is not one the state package accepts: %v", err)
	}
	return selector
}

// ---------------------------------------------------------------------------
// Applying a report
// ---------------------------------------------------------------------------

// selectorFixture writes a selector state and returns the bytes, so every apply
// case starts from a real document on disk and can be compared with it
// afterwards, byte for byte.
func writeSelector(t *testing.T, path string, selector state.Selector) []byte {
	t.Helper()
	if err := state.WriteJSONAtomic(path, selector); err != nil {
		t.Fatalf("write the selector: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the selector back: %v", err)
	}
	return before
}

func readSelector(t *testing.T, path string) state.Selector {
	t.Helper()
	selector := state.Selector{}
	if err := state.ReadJSON(path, &selector); err != nil {
		t.Fatalf("read the selector at %s: %v", path, err)
	}
	return selector
}

// mustBeUnchanged fails the test unless the file at path still holds exactly
// these bytes, and names the generation it left behind. Every refusal case ends
// with this, because "the apply failed" is not the same claim as "the file the
// rewriter reads did not move".
func mustBeUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the selector after a refusal: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("a refused apply changed the selector:\nbefore %d bytes:\n%s\nafter %d bytes:\n%s",
			len(before), before, len(after), after)
	}
	entries := mustReadDirectory(t, filepath.Dir(path))
	for _, entry := range entries {
		if strings.HasPrefix(entry, ".") && strings.HasSuffix(entry, ".tmp") {
			t.Errorf("a refused apply left a temporary file behind: %s", entry)
		}
	}
}

func TestApplyWritesTheNextGenerationAndMovesTheOldWinnerToTheFallback(t *testing.T) {
	// The case the design fixes: starting from generation 4, a successful apply
	// writes generation 5, the new winner takes the field, and the address that was
	// in service becomes the first fallback rather than being dropped.
	fixtures, candidates := threeGlobals()
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))

	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		LastGood:           readSelector(t, selectorPath),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	applied, published, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if published.Generation != 5 {
		t.Errorf("the published selector is generation %d, want 5", published.Generation)
	}
	if published.WinnerIP != "104.16.0.1" {
		t.Errorf("the published winner is %q, want 104.16.0.1", published.WinnerIP)
	}
	if published.FallbackIP != "104.16.1.1" {
		t.Errorf("the published fallback is %q, want the old winner 104.16.1.1", published.FallbackIP)
	}
	if published.Mode != "auto" {
		t.Errorf("the published mode is %q, want auto", published.Mode)
	}
	if published.ConfigSHA256 != runnerSHA256 {
		t.Errorf("the published selector carries config digest %q, want %q", published.ConfigSHA256, runnerSHA256)
	}
	if !published.LastSuccess.Equal(runnerNow) {
		t.Errorf("the published selector records last success at %s, want %s", published.LastSuccess, runnerNow)
	}
	// The state package holds a winner to a proof that follows its last success,
	// so both are set and in that order.
	if !published.WinnerProofUntil.After(published.LastSuccess) {
		t.Errorf("the published proof expires at %s, which does not follow the last success at %s", published.WinnerProofUntil, published.LastSuccess)
	}
	// The file is the state the rewriter reads, so it has to be one the state
	// package itself accepts.
	if got := readSelector(t, selectorPath); got.Generation != 5 || got.WinnerIP != "104.16.0.1" {
		t.Errorf("the file on disk holds %+v, want generation 5 of 104.16.0.1", got)
	}
	if string(before) == "" {
		t.Fatal("the fixture selector was not written")
	}

	// The second identity gate ran, under the lock, immediately before the write:
	// the winner was proved once in the run and once more here, and the report says
	// when.
	if got := len(fake.addressesOf("https")); got != 4 {
		t.Errorf("the prober was asked for %d identity proofs, want 4: three in the run and the winner's again in the apply", got)
	}
	if !applied.FinalProofPassed {
		t.Error("the applied report does not record the final proof")
	}
	if applied.ProofedAt.IsZero() {
		t.Error("the applied report records no time for the final proof")
	}
	if applied.Phases.FinalProof.StartedAt.IsZero() || applied.Phases.FinalProof.EndedAt.IsZero() {
		t.Error("the applied report records no boundaries for the final proof phase")
	}
	// The documented order is collect, TCP, HTTPS identity, latency shortlist,
	// bandwidth, score, final proof, and the seventh phase is the last one.
	if applied.Phases.FinalProof.StartedAt.Before(applied.Phases.Score.EndedAt) {
		t.Error("the final proof is stamped before the score, so the phases did not run in the documented order")
	}
	if applied.Phases.FinalProof.EndedAt.Before(applied.Phases.Identity.EndedAt) {
		t.Error("the final proof is stamped before the identity phase finished")
	}
	// The first six phases keep their order with the seventh in place, so the whole
	// sequence is still the documented one.
	assertPhaseOrderWithProof(t, applied.Phases)
}

func TestApplyRefusesAReportMeasuredUnderAnotherConfiguration(t *testing.T) {
	// The two digests are the whole of the "is this report about this router"
	// question. A report measured under a policy this router is no longer running
	// measured against ceilings and counts that are not in force, so it is refused
	// rather than reinterpreted.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	edited := report
	// A report measured under another policy carries that policy's digest in both
	// of its own fields, because it is one document describing one configuration.
	// A report whose two digests disagree is a different failure, and ReadReport
	// refuses that as the incoherent document it is.
	otherDigest := "0000000000000000000000000000000000000000000000000000000000000000"
	edited.PolicySHA256, edited.ConfigSHA256 = otherDigest, otherDigest
	if _, _, err := runner.Apply(t.Context(), edited, globalProfiles(testProfile("speed.example.test", 443))); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("Apply with a report from another configuration returned %v, want %v", err, ErrConfigChanged)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyRefusesAReportOlderThanTheMaximumAge(t *testing.T) {
	// A report is evidence about the network at the moment it was measured. Past
	// the maximum age it is evidence about nothing, and an address it names may
	// have stopped serving since; the operator re-runs test --apply instead.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")
	profiles := []candidate.ProbeProfile{testProfile("speed.example.test", 443)}

	// One second past the limit is refused.
	stale := report
	stale.GeneratedAt = runnerNow.Add(-MaxReportAge - time.Second)
	if _, _, err := runner.Apply(t.Context(), stale, globalProfiles(profiles...)); !errors.Is(err, ErrReportTooOld) {
		t.Fatalf("Apply with a report %s old returned %v, want %v", MaxReportAge+time.Second, err, ErrReportTooOld)
	}
	mustBeUnchanged(t, selectorPath, before)

	// A report from the future is refused as well: it cannot be a record of
	// anything that has happened, and a clock that far apart is a fault worth
	// stopping for rather than a report worth applying.
	future := report
	future.GeneratedAt = runnerNow.Add(time.Second)
	if _, _, err := runner.Apply(t.Context(), future, globalProfiles(profiles...)); !errors.Is(err, ErrReportTooOld) {
		t.Fatalf("Apply with a report dated in the future returned %v, want %v", err, ErrReportTooOld)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyAcceptsAReportExactlyAtTheMaximumAge(t *testing.T) {
	// The boundary is inclusive, so "two hours old" is applied and "two hours and a
	// second old" is not. Deciding the boundary here rather than leaving it to the
	// comparison is what makes the two cases above and this one the same rule.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")
	aged := report
	aged.GeneratedAt = runnerNow.Add(-MaxReportAge)
	_, published, err := runner.Apply(t.Context(), aged, globalProfiles(testProfile("speed.example.test", 443)))
	if err != nil {
		t.Fatalf("Apply with a report exactly %s old: %v", MaxReportAge, err)
	}
	if published.WinnerIP != "104.16.0.1" {
		t.Errorf("the published winner is %q, want 104.16.0.1", published.WinnerIP)
	}
}

func TestApplyRefusesWhenTheFinalIdentityProofFails(t *testing.T) {
	// The second identity gate. Everything the run measured can still be true while
	// the address has stopped serving, so the winner is proved again under the lock
	// immediately before the write, and a refusal there leaves the file exactly as
	// it was: the old winner keeps serving.
	fixtures, candidates := threeGlobals()
	// The winner proves cleanly during the run and is refused when the apply proves
	// it again, which is the shape of an address that stopped serving between the
	// two moments.
	fixtures["104.16.0.1"].identityCallsBeforeFailure = 1
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	if _, _, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443))); !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Apply whose final proof was refused returned %v, want %v", err, ErrIdentityRefused)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyRefusesWhileAnotherProcessHoldsTheControlLock(t *testing.T) {
	// A real second process, because the conflict that matters is between two
	// processes and not between two values in one: the timer applying a report while
	// an operator pins an address has to lose one of the two, and the loser has to
	// change nothing. The lock is taken here rather than faked, because a fake
	// acquire would only prove that the runner calls what it was handed.
	fixtures, candidates := threeGlobals()
	built := newTestRunner(t, newFakeProber(fixtures))
	runner, selectorPath := built.Runner, built.selectorPath
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	release := holdLockInAnotherProcess(t, built.lockPath)
	_, _, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	release()
	if !errors.Is(err, ErrControlLocked) {
		t.Fatalf("Apply while another process held the control lock returned %v, want %v", err, ErrControlLocked)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyRefusesWhileTheSelectorIsPinnedByHand(t *testing.T) {
	// A pinned address is the operator's decision and outranks an automatic
	// result, so an automatic apply has to refuse rather than quietly unpin by side
	// effect. The operator unpins first, which is a decision they make on purpose.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	pinned := mustSelector(t, 7, "104.16.2.1", "104.16.1.1")
	pinned.Mode = "manual"
	before := writeSelector(t, selectorPath, pinned)
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.2.1")

	if _, _, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443))); !errors.Is(err, ErrModeManual) {
		t.Fatalf("Apply against a pinned selector returned %v, want %v", err, ErrModeManual)
	}
	mustBeUnchanged(t, selectorPath, before)
}

// A disabled selector is an operator's statement, not a state a command may
// resolve by writing over it. Nothing in this project writes `disabled` - it is
// reachable only by a hand edit - and an automatic apply that published over one
// would put every user's answers back on a CDN the operator had just taken out of
// service, while reporting a success. The health check already honours the mode;
// this is the other two commands reaching the same conclusion, with a named
// refusal rather than a string.
func TestApplyRefusesWhileTheSelectorIsDisabled(t *testing.T) {
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	disabled := mustSelector(t, 7, "104.16.2.1", "104.16.1.1")
	disabled.Mode = "disabled"
	before := writeSelector(t, selectorPath, disabled)
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.2.1")

	applied, published, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if !errors.Is(err, ErrModeDisabled) {
		t.Fatalf("Apply against a disabled selector returned %v, want %v", err, ErrModeDisabled)
	}
	if published.WinnerIP != "" || published.Generation != 0 {
		t.Errorf("a refused apply returned a published selector: %+v", published)
	}
	if applied.Outcome != OutcomeRefused {
		t.Errorf("a refused apply's report outcome is %q, want %q", applied.Outcome, OutcomeRefused)
	}
	for index := range applied.Groups {
		if applied.Groups[index].Outcome == OutcomePublished {
			t.Errorf("group %d says it was published by a refused apply: %+v", index, applied.Groups[index])
		}
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestPinRefusesWhileTheSelectorIsDisabled(t *testing.T) {
	// The other half of the same rule, and the more dangerous one: Pin writes
	// `mode: manual`, so without the guard it would re-enable a disabled selector
	// by side effect and the operator would never be told.
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(map[string]*addressFixture{
		"104.16.9.9": served(10, 1, 0, 5*mib),
	}))
	disabled := mustSelector(t, 7, "104.16.2.1", "104.16.1.1")
	disabled.Mode = "disabled"
	before := writeSelector(t, selectorPath, disabled)

	if _, err := runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), globalProfiles(testProfile("speed.example.test", 443))); !errors.Is(err, ErrModeDisabled) {
		t.Fatalf("Pin against a disabled selector returned %v, want %v", err, ErrModeDisabled)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyRefusesAReportWhoseRecordedSwitchTheConfigurationDoesNotAgreeWith(t *testing.T) {
	// The recorded decision is an integrity claim, not an input. An apply
	// recomputes it from the report's own numbers and the threshold in force, and a
	// report whose two halves disagree was not written by the run that measured it.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	// The run recorded a refused switch with the threshold it had. The runner this
	// apply is made through has a hundred percent threshold, under which the same
	// numbers would be refused too, and the report's recorded reason names a
	// different threshold.
	edited := report
	winner := *edited.Groups[0].Winner
	winner.SwitchAllowed = false
	winner.SwitchRefusal = "the winner is the address already in service"
	edited.Groups[0].Winner = &winner
	if _, _, err := runner.Apply(t.Context(), edited, globalProfiles(testProfile("speed.example.test", 443))); !errors.Is(err, ErrSwitchNotAllowed) {
		t.Fatalf("Apply of a report whose recorded switch does not agree with its own numbers returned %v, want %v", err, ErrSwitchNotAllowed)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyKeepsTheFallbackWhenTheWinnerDoesNotChange(t *testing.T) {
	// Applying the address that is already in service is a confirmation, not a
	// change, and the state package refuses a selector whose fallback equals its
	// winner. So the existing fallback is kept rather than the winner moved into
	// the field it already occupies, and the generation still moves: the run did
	// re-prove and re-measure it.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.0.1", "104.16.1.1"))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.0.1")

	_, published, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if published.WinnerIP != "104.16.0.1" {
		t.Errorf("the published winner is %q, want the address already in service, 104.16.0.1", published.WinnerIP)
	}
	if published.FallbackIP != "104.16.1.1" {
		t.Errorf("the published fallback is %q, want the existing 104.16.1.1 to be kept", published.FallbackIP)
	}
	if published.Generation != 5 {
		t.Errorf("the published selector is generation %d, want 5: the run re-proved it", published.Generation)
	}
}

func TestApplyCreatesTheFirstSelectorWhenThereIsNoneYet(t *testing.T) {
	// A router that has never selected anything has no selector document, and the
	// first apply is how it gets one. Generation 1 is the first generation, and the
	// provider is the winner's own, because a state file has to name one.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_, published, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if err != nil {
		t.Fatalf("Apply with no selector on disk: %v", err)
	}
	if published.Generation != 1 {
		t.Errorf("the first published selector is generation %d, want 1", published.Generation)
	}
	if published.WinnerIP != "104.16.0.1" || published.Provider != string(candidate.ProviderCloudflare) {
		t.Errorf("the first published selector holds %+v, want 104.16.0.1 of provider cloudflare", published)
	}
	if published.FallbackIP != "" {
		t.Errorf("the first published selector has a fallback %q, want none: there was no previous winner", published.FallbackIP)
	}
	if got := readSelector(t, selectorPath); got.Generation != 1 {
		t.Errorf("the file on disk holds generation %d, want 1", got.Generation)
	}
}

func TestApplyRefusesACorruptSelectorRatherThanOverwritingIt(t *testing.T) {
	// A selector this build cannot read is not a selector to overwrite. Replacing it
	// would destroy the last-known-good address - the one thing a broken router has
	// left - and the state package's own rules are the only description of what a
	// valid document is, so the refusal has to come from reading it.
	fixtures, candidates := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	corrupt := []byte("{\"schema_version\": 1, \"generation\": 4, \"mode\": \"nonsense\"}\n")
	if err := os.WriteFile(selectorPath, corrupt, 0o640); err != nil {
		t.Fatal(err)
	}
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	if _, _, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443))); err == nil {
		t.Fatal("Apply over a corrupt selector returned no error, want a refusal")
	}
	mustBeUnchanged(t, selectorPath, corrupt)
}

func TestApplyPublishesACloudFrontWinnerOnlyForItsOwnHostname(t *testing.T) {
	// The anti-leak rule, enforced at the only place an address is published. A
	// CloudFront winner is one hostname's answer: it goes into that hostname's
	// mapping and nowhere else, and the global winner is left exactly as it was
	// because a CloudFront address published as the global winner would be handed to
	// every hostname the router serves.
	fixtures := map[string]*addressFixture{"205.251.192.1": served(10, 1, 0, 5*mib)}
	profile := testProfile("assets.example.test", 443)
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	existing := mustSelector(t, 4, "104.16.0.1", "")
	existing.CloudFront = map[string]string{"old.example.test": "205.251.192.9"}
	writeSelector(t, selectorPath, existing)

	rule := candidate.CloudFrontProfile{Profile: profile, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}
	report, err := runner.Run(t.Context(), Input{
		CloudFront:      []candidate.Candidate{cloudFrontCandidate("205.251.192.1", "assets.example.test")},
		CloudFrontRules: []candidate.CloudFrontProfile{rule},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := mustGroup(t, report, "cloudfront/assets.example.test")
	if mustWinner(t, group).IP != "205.251.192.1" {
		t.Fatalf("the CloudFront winner is %s, want 205.251.192.1", group.Winner.IP)
	}
	_, published, err := runner.Apply(t.Context(), report, Profiles{ByHostname: map[string]candidate.ProbeProfile{profile.Hostname: profile}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if published.CloudFront["assets.example.test"] != "205.251.192.1" {
		t.Errorf("the published mapping is %v, want assets.example.test of 205.251.192.1", published.CloudFront)
	}
	if published.WinnerIP != "104.16.0.1" {
		t.Errorf("the global winner is %q, want the 104.16.0.1 it was: a CloudFront winner may not replace it", published.WinnerIP)
	}
	if published.CloudFront["old.example.test"] != "205.251.192.9" {
		t.Errorf("the published mapping dropped another hostname's entry: %v", published.CloudFront)
	}
	if got := readSelector(t, selectorPath); got.CloudFront["assets.example.test"] != "205.251.192.1" {
		t.Errorf("the file on disk holds the mapping %v", got.CloudFront)
	}
	// The global winner is byte-for-byte what it was: a CloudFront apply writes the
	// mapping and touches nothing else the rewriter reads for a global query.
	if got := readSelector(t, selectorPath); got.WinnerIP != "104.16.0.1" {
		t.Errorf("the file on disk names the global winner %q, want the 104.16.0.1 it already had", got.WinnerIP)
	}
}

func TestApplyRefusesACloudFrontWinnerWhoseProfileThisConfigurationNoLongerNames(t *testing.T) {
	// The final proof is run against the profiles this router is running, not the
	// ones the report carries. A report naming a hostname this configuration no
	// longer has a profile for is refused rather than proved against something else,
	// which is the substitution the identity probe exists to refuse.
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(map[string]*addressFixture{
		"205.251.192.1": served(10, 1, 0, 5*mib),
	}))
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.0.1", ""))
	profile := testProfile("assets.example.test", 443)
	rule := candidate.CloudFrontProfile{Profile: profile, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}
	report, err := runner.Run(t.Context(), Input{
		CloudFront:      []candidate.Candidate{cloudFrontCandidate("205.251.192.1", "assets.example.test")},
		CloudFrontRules: []candidate.CloudFrontProfile{rule},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, _, err := runner.Apply(t.Context(), report, Profiles{ByHostname: map[string]candidate.ProbeProfile{"other.example.test": testProfile("other.example.test", 443)}}); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("Apply of a CloudFront winner with no live profile returned %v, want %v", err, ErrNoProfile)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyProvesAGlobalWinnerOnlyAgainstTheGlobalProfiles(t *testing.T) {
	// A global address is proved against the global identity profiles and nothing
	// else. The operator's CloudFront hostnames are per-hostname answers: the global
	// winner is never published for one of them, so requiring a Cloudflare anycast
	// address to present a chain for a CloudFront hostname tests a relationship that
	// does not exist - and it fails every time, because it cannot succeed.
	//
	// The fixture refuses the CloudFront hostname for the global address exactly as
	// a real Cloudflare address would, so an apply that proved against it would be
	// refused with ErrIdentityRefused on any router that has a CloudFront domain
	// list at all.
	fixtures, candidates := threeGlobals()
	// The global winner answers the two global profiles and is refused by the
	// CloudFront one.
	fixtures["104.16.0.1"].identityRefusedFor = map[string]error{
		"assets.example.test": errors.New("the certificate presented is for speed.example.test, not assets.example.test"),
	}
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	// The configuration this run and this apply share: two global identity profiles
	// and one CloudFront rule.
	globals := []candidate.ProbeProfile{
		testProfile("speed.example.test", 443),
		testProfile("secure.example.test", 443),
	}
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: globals,
		LastGood:           readSelector(t, selectorPath),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	profiles := Profiles{
		Global: globals,
		ByHostname: map[string]candidate.ProbeProfile{
			"assets.example.test": testProfile("assets.example.test", 443),
		},
	}
	_, published, err := runner.Apply(t.Context(), report, profiles)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if published.WinnerIP != "104.16.0.1" {
		t.Errorf("the published winner is %q, want 104.16.0.1", published.WinnerIP)
	}
	// Three candidates proved against the two global profiles in the run, and the
	// winner proved against those same two in the apply. The CloudFront hostname is
	// never asked about a global address.
	if got := len(fake.addressesOf("https")); got != 3*2+2 {
		t.Errorf("the prober was asked for %d identity proofs, want 8: three candidates against two global profiles, then the winner against the same two", got)
	}
	for _, call := range fake.profiledCalls() {
		if call.Hostname == "assets.example.test" {
			t.Errorf("a global address was proved against the per-hostname profile %q, which no global winner is ever published for", call.Hostname)
		}
	}
}

func TestApplyProvesAPerHostnameWinnerOnlyAgainstItsOwnProfile(t *testing.T) {
	// The other half of the same rule. A per-hostname address is proved against its
	// own hostname's profile and no other: a proof for one hostname says nothing
	// about another, which is the anti-leak rule and the reason the mapping is
	// per-hostname in the first place.
	fixtures := map[string]*addressFixture{"205.251.192.1": served(10, 1, 0, 5*mib)}
	own := testProfile("assets.example.test", 443)
	other := testProfile("other.example.test", 443)
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.0.1", ""))
	rule := candidate.CloudFrontProfile{Profile: own, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}
	report, err := runner.Run(t.Context(), Input{
		CloudFront:      []candidate.Candidate{cloudFrontCandidate("205.251.192.1", "assets.example.test")},
		CloudFrontRules: []candidate.CloudFrontProfile{rule},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	profiles := Profiles{
		Global:     []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		ByHostname: map[string]candidate.ProbeProfile{"assets.example.test": own, "other.example.test": other},
	}
	if _, _, err := runner.Apply(t.Context(), report, profiles); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// One candidate proved against its own profile in the run, and once more in the
	// apply: two proofs, and the global profile is never involved.
	if got := len(fake.addressesOf("https")); got != 2 {
		t.Errorf("the prober was asked for %d identity proofs, want 2: the candidate's own hostname twice", got)
	}
	for _, call := range fake.profiledCalls() {
		if call.Hostname != "assets.example.test" {
			t.Errorf("a per-hostname address was proved against %q, want only its own hostname", call.Hostname)
		}
	}
}

func TestApplyRefusesAPerHostnameWinnerWhoseOwnProfileThisConfigurationNoLongerNames(t *testing.T) {
	// The profiles come from the router's configuration and never from the report,
	// so a report naming a hostname this configuration has no profile for is refused
	// rather than proved against something else.
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(map[string]*addressFixture{
		"205.251.192.1": served(10, 1, 0, 5*mib),
	}))
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.0.1", ""))
	profile := testProfile("assets.example.test", 443)
	rule := candidate.CloudFrontProfile{Profile: profile, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}
	report, err := runner.Run(t.Context(), Input{
		CloudFront:      []candidate.Candidate{cloudFrontCandidate("205.251.192.1", "assets.example.test")},
		CloudFrontRules: []candidate.CloudFrontProfile{rule},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The configuration no longer names the hostname at all, and names another one.
	profiles := Profiles{ByHostname: map[string]candidate.ProbeProfile{"other.example.test": testProfile("other.example.test", 443)}}
	if _, _, err := runner.Apply(t.Context(), report, profiles); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("Apply of a per-hostname winner with no profile of its own returned %v, want %v", err, ErrNoProfile)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyStillRefusesAGlobalWinnerOneGlobalProfileWillNotVouchFor(t *testing.T) {
	// The scoping does not weaken the rule it narrows: a global address that serves
	// the provider's domain but not a forced-ECH domain cannot be published, because
	// a user on that domain would have every query rewritten to an address that will
	// not serve it.
	fixtures, candidates := threeGlobals()
	// The winner serves the first global profile and is refused by the second.
	fixtures["104.16.0.1"].identityCallsBeforeFailure = 1
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")
	profiles := Profiles{Global: []candidate.ProbeProfile{
		testProfile("speed.example.test", 443),
		testProfile("secure.example.test", 443),
	}}

	if _, _, err := runner.Apply(t.Context(), report, profiles); !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Apply with a global profile that will not vouch for the winner returned %v, want %v", err, ErrIdentityRefused)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyKeepsTheSelectorWhenTheReportHasNoWinnerAtAll(t *testing.T) {
	// A report that found nothing publishable in any group keeps everything, and says
	// which group produced nothing and why. There is no address to publish, so there
	// is no proof to run and no write to make: the operator's address stays in
	// service and the report carries the reason.
	fixtures, candidates := threeGlobals()
	for _, fixture := range fixtures {
		fixture.identityErr = errors.New("the response is a 521, which the profile does not expect")
	}
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	applied, published, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if err != nil {
		t.Fatalf("Apply of a report with no winner anywhere: %v", err)
	}
	mustBeNothingWritten(t, published)
	if applied.Outcome != OutcomeKept {
		t.Errorf("the apply's outcome is %q, want %q", applied.Outcome, OutcomeKept)
	}
	if groupOutcome(t, applied, "cloudflare/") != OutcomeKept {
		t.Errorf("the group's outcome is %q, want %q", groupOutcome(t, applied, "cloudflare/"), OutcomeKept)
	}
	if reason := groupOutcomeReason(t, applied, "cloudflare/"); reason != ReasonNoProvedCandidate {
		t.Errorf("the group's reason is %q, want %q", reason, ReasonNoProvedCandidate)
	}
	mustBeUnchanged(t, selectorPath, before)
}

// The child process of the control-lock conflict case. It shares nothing with its
// parent but the lock file, which is the point: the conflict that matters is
// between two processes, and a fake acquire in the same process would only prove
// that the runner calls whatever it was handed.
const (
	lockHelperLockPath  = "MOSDNS_TEST_LOCK_PATH"
	lockHelperReadyPath = "MOSDNS_TEST_LOCK_READY"

	// lockHelperWait is how long the child holds the lock when its parent dies
	// without releasing it. It is longer than any test waits and short enough that
	// a leaked child does not outlive the suite.
	lockHelperWait = 30 * time.Second
)

func TestControlLockHelperProcessOnlyRunsAsASeparateProcess(t *testing.T) {
	lockPath := os.Getenv(lockHelperLockPath)
	if lockPath == "" {
		t.Skip("this test is the body of a separate process; see holdLockInAnotherProcess")
	}
	lock, err := filelock.Acquire(lockPath)
	if err != nil {
		// The parent is not ready for this child to hold anything, which is a
		// failure of the harness rather than of the code under test.
		t.Fatalf("take the control lock at %s: %v", lockPath, err)
	}
	defer func() { _ = lock.Close() }()
	// The marker is what tells the parent the lock is genuinely held: a child that
	// had not taken it would let the parent's apply succeed and the case would pass
	// for the wrong reason.
	if err := os.WriteFile(os.Getenv(lockHelperReadyPath), []byte("held\n"), 0o600); err != nil {
		t.Fatalf("write the ready marker: %v", err)
	}
	time.Sleep(lockHelperWait)
}

// holdLockInAnotherProcess starts a process that takes the control lock and holds
// it, waits until it demonstrably holds it, and returns the function that stops
// it.
func holdLockInAnotherProcess(t *testing.T, lockPath string) func() {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(os.Args[0], "-test.run=^TestControlLockHelperProcessOnlyRunsAsASeparateProcess$")
	command.Env = append(os.Environ(), lockHelperLockPath+"="+lockPath, lockHelperReadyPath+"="+ready)
	if err := command.Start(); err != nil {
		t.Fatalf("start the lock-holding process: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
			t.Fatal("the second process never reported holding the control lock")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}
}

// ---------------------------------------------------------------------------
// Pinning and unpinning by hand
// ---------------------------------------------------------------------------

func TestPinProvesAGlobalAddressOnlyAgainstTheGlobalProfiles(t *testing.T) {
	// The same scoping a pin gets, and the same reason: a Cloudflare anycast address
	// cannot present a chain for the operator's CloudFront hostnames, so a pin that
	// demanded it would be refused on every router that has one. The address is
	// refused by the CloudFront profile here, exactly as a real one would be.
	fake := newFakeProber(map[string]*addressFixture{"104.16.9.9": served(10, 1, 0, 5*mib)})
	fixture, err := fake.fixture(netip.MustParseAddr("104.16.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.identityRefusedFor = map[string]error{
		"assets.example.test": errors.New("the certificate presented is for speed.example.test, not assets.example.test"),
	}
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	profiles := Profiles{
		Global: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		ByHostname: map[string]candidate.ProbeProfile{
			"assets.example.test": testProfile("assets.example.test", 443),
		},
	}

	pinned, err := runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), profiles)
	if err != nil {
		t.Fatalf("Pin of an address the CloudFront profile refuses: %v", err)
	}
	if pinned.Selector.WinnerIP != "104.16.9.9" {
		t.Errorf("the pinned winner is %q, want 104.16.9.9", pinned.Selector.WinnerIP)
	}
	// One proof: the global profile. The CloudFront hostname is never asked about a
	// global address.
	if got := len(fake.profiledCalls()); got != 1 {
		t.Errorf("the prober was asked for %d identity proofs, want 1: the global profile only", got)
	}
}

func TestPinReportsTheUnchargedIdentityBytesItSpent(t *testing.T) {
	// A pin's proofs are identity probes, which are deliberately outside the daily
	// budget for the same reason a health check's are, so nothing on disk accounts
	// for the bodies they read. The health check already reports its total; a pin
	// spent the operator's data allowance to reach the same verdict and reported
	// none of it, which is the gap this closes.
	//
	// Three global profiles, 2048 bytes each: 6144 in total.
	fake := newFakeProber(map[string]*addressFixture{
		"104.16.9.9": served(10, 1, 0, 5*mib),
	})
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	profiles := []candidate.ProbeProfile{
		testProfile("speed.example.test", 443),
		testProfile("secure.example.test", 443),
		testProfile("strict.example.test", 443),
	}

	pinned, err := runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), globalProfiles(profiles...))
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if pinned.IdentityBytes != 3*runnerIdentityBytes {
		t.Errorf("the pin reports %d uncharged identity bytes, want %d: three probes of %d each",
			pinned.IdentityBytes, 3*runnerIdentityBytes, runnerIdentityBytes)
	}
}

// A refused pin spends the same bytes and publishes nothing, so it reports them
// too: a refused probe is exactly the case where money was spent and no address
// was stored, which is why the sum is taken before the error is looked at.
func TestARefusedPinReportsTheUnchargedIdentityBytesItSpent(t *testing.T) {
	fake := newFakeProber(map[string]*addressFixture{
		"104.16.9.9": served(10, 1, 0, 5*mib),
	})
	// The second profile refuses, so the pin is refused after one proof has already
	// read its body and one has read its way to a refusal.
	fake.fixtures["104.16.9.9"].identityRefusedFor = map[string]error{
		"secure.example.test": errors.New("the certificate presented is not for secure.example.test"),
	}
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	profiles := []candidate.ProbeProfile{
		testProfile("speed.example.test", 443),
		testProfile("secure.example.test", 443),
	}

	pinned, err := runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), globalProfiles(profiles...))
	if !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Pin of an address one profile refuses returned %v, want %v", err, ErrIdentityRefused)
	}
	if pinned.IdentityBytes != 2*runnerIdentityBytes {
		t.Errorf("the refused pin reports %d uncharged identity bytes, want %d: both probes read their body, refused or not",
			pinned.IdentityBytes, 2*runnerIdentityBytes)
	}
	if pinned.Selector.WinnerIP != "" || pinned.Selector.Generation != 0 {
		t.Errorf("a refused pin returned a published selector: %+v", pinned.Selector)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestPinStoresAManualWinnerAfterProvingItAgainstEveryGlobalProfile(t *testing.T) {
	// A pinned address is the operator's decision, and it outranks every automatic
	// result, so it is held to a stricter rule than a measurement: it is proved
	// against the profiles of the group it would be published for before it is
	// stored, and the store is one generation on from what was there.
	fake := newFakeProber(map[string]*addressFixture{
		"104.16.9.9": served(10, 1, 0, 5*mib),
	})
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", "104.16.2.1"))
	profiles := []candidate.ProbeProfile{
		testProfile("speed.example.test", 443),
		testProfile("secure.example.test", 443),
		testProfile("strict.example.test", 443),
	}

	pinned, err := runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), globalProfiles(profiles...))
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if got := len(fake.addressesOf("https")); got != 3 {
		t.Errorf("the prober was asked for %d identity proofs, want 3: one per configured profile", got)
	}
	if pinned.Selector.Mode != "manual" {
		t.Errorf("the pinned selector's mode is %q, want manual", pinned.Selector.Mode)
	}
	if pinned.Selector.WinnerIP != "104.16.9.9" {
		t.Errorf("the pinned winner is %q, want 104.16.9.9", pinned.Selector.WinnerIP)
	}
	if pinned.Selector.FallbackIP != "104.16.1.1" {
		t.Errorf("the pinned fallback is %q, want the address that was in service, 104.16.1.1", pinned.Selector.FallbackIP)
	}
	if pinned.Selector.Generation != 5 {
		t.Errorf("the pinned selector is generation %d, want 5: a pin is one generation on", pinned.Selector.Generation)
	}
	if pinned.Selector.Provider != string(candidate.ProviderCloudflare) {
		t.Errorf("the pinned selector names provider %q, want cloudflare", pinned.Selector.Provider)
	}
	if !pinned.Selector.LastSuccess.Equal(runnerNow) || !pinned.Selector.WinnerProofUntil.After(pinned.Selector.LastSuccess) {
		t.Errorf("the pinned selector records success at %s and a proof until %s, want the run's clock and a later proof", pinned.Selector.LastSuccess, pinned.Selector.WinnerProofUntil)
	}
	if pinned.Selector.ConfigSHA256 != runnerSHA256 {
		t.Errorf("the pinned selector carries config digest %q, want %q", pinned.Selector.ConfigSHA256, runnerSHA256)
	}
	if got := readSelector(t, selectorPath); got.Mode != "manual" || got.WinnerIP != "104.16.9.9" {
		t.Errorf("the file on disk holds %+v, want a manual 104.16.9.9", got)
	}
}

func TestPinRefusesAnAddressARewriteTargetMayNotName(t *testing.T) {
	// The same rule the candidate package applies to every candidate, reached
	// through the same call, so a pinned address cannot be a LAN address, a
	// loopback, a link-local or a reserved range while an official candidate
	// could not be one. And it is refused before a socket is opened: the probe count
	// is the proof of that.
	for _, address := range []string{
		"192.168.1.1", // the LAN
		"10.0.0.1",    // the LAN
		"127.0.0.1",   // this host
		"169.254.1.1", // link-local
		"224.0.0.1",   // multicast
		"0.0.0.0",     // unspecified
		"100.64.0.1",  // carrier-grade NAT
		"198.18.0.1",  // benchmarking
		"240.0.0.1",   // reserved
	} {
		t.Run(address, func(t *testing.T) {
			fake := newFakeProber(map[string]*addressFixture{address: served(10, 1, 0, 5*mib)})
			runner, selectorPath := newTestRunnerWithSelector(t, fake)
			before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))

			if _, err := runner.Pin(t.Context(), netip.MustParseAddr(address), globalProfiles(testProfile("speed.example.test", 443))); !errors.Is(err, ErrNotPublishable) {
				t.Fatalf("Pin of %s returned %v, want %v", address, err, ErrNotPublishable)
			}
			if got := len(fake.addressesOf("https")); got != 0 {
				t.Errorf("the prober was asked for %d identity proofs for %s, want 0: the address is refused before a socket is opened", got, address)
			}
			mustBeUnchanged(t, selectorPath, before)
		})
	}
}

func TestPinRefusesWhenAProfileWillNotVouchForTheAddress(t *testing.T) {
	// An address that does not serve everything this router will ask it to serve
	// cannot be pinned, whatever the operator says: a user on a domain the address
	// refuses would have every query rewritten to it. The file does not move.
	fake := newFakeProber(map[string]*addressFixture{
		"104.16.9.9": served(10, 1, 0, 5*mib),
	})
	fixture, err := fake.fixture(netip.MustParseAddr("104.16.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.identityErr = errors.New("the response for strict.example.test is a 403, which the profile does not expect")
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))

	profiles := []candidate.ProbeProfile{testProfile("speed.example.test", 443), testProfile("strict.example.test", 443)}
	if _, err := runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), globalProfiles(profiles...)); !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Pin of an address one profile refuses returned %v, want %v", err, ErrIdentityRefused)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestPinRefusesWithoutAProfileToProveItAgainst(t *testing.T) {
	// A pin with nothing to prove it against is a pin on trust, and the whole
	// project exists to refuse that. The refusal happens before the lock is taken,
	// so nothing is even read.
	fake := newFakeProber(map[string]*addressFixture{"104.16.9.9": served(10, 1, 0, 5*mib)})
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))

	if _, err := runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), Profiles{}); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("Pin with no profile returned %v, want %v", err, ErrNoProfile)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestPinRefusesWhileAnotherProcessHoldsTheControlLock(t *testing.T) {
	// The same conflict as an apply, on the other command that writes the selector.
	// An operator pinning while the timer applies has to lose one of the two, and
	// the loser changes nothing.
	fake := newFakeProber(map[string]*addressFixture{"104.16.9.9": served(10, 1, 0, 5*mib)})
	built := newTestRunner(t, fake)
	before := writeSelector(t, built.selectorPath, mustSelector(t, 4, "104.16.1.1", ""))

	release := holdLockInAnotherProcess(t, built.lockPath)
	_, err := built.Runner.Pin(t.Context(), netip.MustParseAddr("104.16.9.9"), globalProfiles(testProfile("speed.example.test", 443)))
	release()
	if !errors.Is(err, ErrControlLocked) {
		t.Fatalf("Pin while another process held the control lock returned %v, want %v", err, ErrControlLocked)
	}
	mustBeUnchanged(t, built.selectorPath, before)
}

func TestUnpinStoresAutomaticModeAndKeepsTheWinnerAsTheFallback(t *testing.T) {
	// Unpinning restores automatic selection and does not throw the address away:
	// it becomes the fallback, because the design says the last-known-good winner is
	// what traffic falls back to and an address that was serving a moment ago is the
	// best candidate for that. The state package refuses a selector whose fallback
	// equals its winner, so the field is emptied and the address moves down rather
	// than being named twice.
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(nil))
	writeSelector(t, selectorPath, mustSelector(t, 7, "104.16.9.9", "104.16.1.1"))
	current := readSelector(t, selectorPath)
	current.Mode = "manual"
	writeSelector(t, selectorPath, current)

	unpinned, err := runner.Unpin()
	if err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	if unpinned.Mode != "auto" {
		t.Errorf("the unpinned selector's mode is %q, want auto", unpinned.Mode)
	}
	if unpinned.WinnerIP != "" {
		t.Errorf("the unpinned selector still names the winner %q, want none: the next automatic run chooses it", unpinned.WinnerIP)
	}
	if unpinned.FallbackIP != "104.16.9.9" {
		t.Errorf("the unpinned selector's fallback is %q, want the address that was pinned, 104.16.9.9", unpinned.FallbackIP)
	}
	if unpinned.Generation != 8 {
		t.Errorf("the unpinned selector is generation %d, want 8: an unpin is one generation on", unpinned.Generation)
	}
	// The state package refuses a proof that outlives a winner, so the proof goes
	// with the winner rather than being left behind to expire on its own.
	if !unpinned.WinnerProofUntil.IsZero() {
		t.Errorf("the unpinned selector still carries a proof until %s, want none", unpinned.WinnerProofUntil)
	}
	if got := readSelector(t, selectorPath); got.Mode != "auto" || got.FallbackIP != "104.16.9.9" {
		t.Errorf("the file on disk holds %+v, want automatic with 104.16.9.9 as the fallback", got)
	}
}

func TestUnpinLeavesThePerHostnameMappingsAlone(t *testing.T) {
	// A per-hostname mapping is a different thing from the global pin: it is
	// measured for its own hostname and published for that hostname only. An unpin
	// of the global winner has no business touching it, and a mapping left behind
	// for a hostname the operator still serves is worth more than the one that was
	// there before.
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(nil))
	pinned := mustSelector(t, 3, "104.16.9.9", "")
	pinned.Mode = "manual"
	pinned.CloudFront = map[string]string{"assets.example.test": "205.251.192.1"}
	writeSelector(t, selectorPath, pinned)

	unpinned, err := runner.Unpin()
	if err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	if unpinned.CloudFront["assets.example.test"] != "205.251.192.1" {
		t.Errorf("the unpinned selector holds the mapping %v, want assets.example.test of 205.251.192.1 to be kept", unpinned.CloudFront)
	}
}

func TestUnpinRefusesWhenNothingIsPinned(t *testing.T) {
	// Two cases, both of which are a mistake rather than a change: a selector that
	// does not exist, and one that is already automatic. Refusing says so instead of
	// bumping the generation for a decision nobody made.
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(nil))
	if _, err := runner.Unpin(); !errors.Is(err, ErrNothingPinned) {
		t.Fatalf("Unpin with no selector returned %v, want %v", err, ErrNothingPinned)
	}
	if _, err := os.Stat(selectorPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unpin with nothing to unpin created a selector at %s", selectorPath)
	}

	before := writeSelector(t, selectorPath, mustSelector(t, 2, "104.16.0.1", ""))
	if _, err := runner.Unpin(); !errors.Is(err, ErrNothingPinned) {
		t.Fatalf("Unpin of an automatic selector returned %v, want %v", err, ErrNothingPinned)
	}
	mustBeUnchanged(t, selectorPath, before)
}

// ---------------------------------------------------------------------------
// The report document on disk
// ---------------------------------------------------------------------------

func TestReadReportRefusesAFieldThisBuildDoesNotKnow(t *testing.T) {
	// A report is what an apply publishes from, so a permissive decoder is how an
	// older build ends up interpreting a field it does not understand as something
	// it is not. The refusal has to happen at the decode.
	document := strings.Replace(mustReportJSON(t), `  "stale_candidates": false,`, `  "stale_candidates": false,
  "winner_ip": "104.16.0.1",`, 1)
	path := filepath.Join(t.TempDir(), DefaultSelectorPathName+".report")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReport(path); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("ReadReport of a document with an unknown field returned %v, want %v", err, ErrInvalidReport)
	}
}

func TestReadReportRefusesMoreThanOneDocument(t *testing.T) {
	// A second document behind the first is a concatenation, not a report, and the
	// part of it that was read first is not what an operator thinks they wrote.
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(mustReportJSON(t)+mustReportJSON(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReport(path); err == nil {
		t.Fatal("ReadReport of two documents returned no error, want a refusal")
	}
}

func TestReadReportRefusesPhasesThatAreOutOfOrder(t *testing.T) {
	// The report claims the run measured bandwidth before it proved identity, and
	// applying it would publish from a measurement that did not happen in that
	// order. This is the property the whole phase design exists for, so it is
	// checked in the document rather than trusted.
	document := strings.Replace(mustReportJSON(t),
		`    "identity": {
      "started_at": "2026-09-26T03:00:00Z",
      "ended_at": "2026-09-26T03:00:00Z"
    },
    "latency": {
      "started_at": "2026-09-26T03:00:00Z",
      "ended_at": "2026-09-26T03:00:00Z"
    },
    "bandwidth": {
      "started_at": "2026-09-26T03:00:00Z",
      "ended_at": "2026-09-26T03:00:00Z"
    },`,
		`    "identity": {
      "started_at": "2026-09-26T03:00:10Z",
      "ended_at": "2026-09-26T03:00:20Z"
    },
    "latency": {
      "started_at": "2026-09-26T03:00:20Z",
      "ended_at": "2026-09-26T03:00:30Z"
    },
    "bandwidth": {
      "started_at": "2026-09-26T03:00:00Z",
      "ended_at": "2026-09-26T03:00:10Z"
    },`, 1)
	if !strings.Contains(document, `"started_at": "2026-09-26T03:00:10Z"`) {
		t.Fatal("the fixture no longer has the phase layout this case rewrites")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadReport(path)
	if !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("ReadReport of a report whose phases run out of order returned %v, want %v", err, ErrInvalidReport)
	}
	named := false
	for _, phase := range documentedPhases {
		if strings.Contains(err.Error(), phase) {
			named = true
		}
	}
	if !named {
		t.Errorf("the refusal %q does not name the phase that is out of order", err)
	}
}

func TestReadReportRefusesAWinnerThatIsNotOneOfItsOwnCandidates(t *testing.T) {
	// A report whose winner is an address none of its probes measured is not a
	// measurement, and applying it would publish an address this document says
	// nothing about.
	document := strings.Replace(mustReportJSON(t), `      "winner": {
        "ip": "104.16.0.1",`, `      "winner": {
        "ip": "104.16.7.7",`, 1)
	if !strings.Contains(document, "104.16.7.7") {
		t.Fatal("the fixture no longer has the winner this case rewrites")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadReport(path)
	if !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("ReadReport of a report naming a winner it did not measure returned %v, want %v", err, ErrInvalidReport)
	}
	if !strings.Contains(err.Error(), "104.16.7.7") {
		t.Errorf("the refusal %q does not name the address", err)
	}
}

func TestWriteReportAndReadReportCarryTheWholeDocument(t *testing.T) {
	// The report has to survive the file it is applied from: the two digests, the
	// accounting and the phase boundaries all have to come back, because those are
	// the fields an apply decides on.
	fixtures, candidates := threeGlobals()
	runner := newTestRunner(t, newFakeProber(fixtures))
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteReport(path, report); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	read, err := ReadReport(path)
	if err != nil {
		t.Fatalf("ReadReport: %v", err)
	}
	if read.ConfigSHA256 != runnerSHA256 || read.PolicySHA256 != runnerSHA256 {
		t.Errorf("the report read back carries %q and %q, want %q twice", read.PolicySHA256, read.ConfigSHA256, runnerSHA256)
	}
	if read.IdentityBytes != 3*runnerIdentityBytes {
		t.Errorf("the report read back accounts for %d identity bytes, want %d", read.IdentityBytes, 3*runnerIdentityBytes)
	}
	if read.BudgetUsed != 3*runnerDownloadBytes {
		t.Errorf("the report read back says the day stands at %d bytes, want %d", read.BudgetUsed, 3*runnerDownloadBytes)
	}
	group := mustGroup(t, read, "cloudflare/")
	if winner := mustWinner(t, group); winner.IP != "104.16.0.1" || winner.Score != 3.0 {
		t.Errorf("the report read back names %s at %g, want 104.16.0.1 at 3", winner.IP, winner.Score)
	}
	if len(group.Candidates) != 3 {
		t.Errorf("the report read back lists %d candidates, want 3", len(group.Candidates))
	}
	// The group key is rebuilt from the document's own two fields, because it is
	// carried beside them rather than decoded.
	if group.Group.Provider != candidate.ProviderCloudflare {
		t.Errorf("the report read back names the group %q, want the cloudflare group", group.Group)
	}
	assertPhaseStamps(t, read.Phases)
	// A report this build wrote must be one it can apply, or the two halves have
	// drifted apart.
	if _, _, err := runner.Apply(t.Context(), read, globalProfiles(testProfile("speed.example.test", 443))); err != nil {
		t.Errorf("the report read back from its own file is not one the runner will apply: %v", err)
	}
}

func TestPolicyDigestIsTheDigestOfTheDocumentBytes(t *testing.T) {
	// The digest is what says a report and a router are talking about the same
	// configuration, and the value it produces is checked against the published
	// SHA-256 of a document every SHA-256 implementation agrees on.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := PolicyDigest([]byte("abc")); got != want {
		t.Errorf("PolicyDigest of \"abc\" is %q, want the published digest %q", got, want)
	}
	if got := PolicyDigest(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("PolicyDigest of no document is %q, want the published digest of the empty string", got)
	}
}

// mustReportJSON is a report document as a run writes it, for the cases that
// rewrite one field of it. It is a literal rather than a produced document so the
// rewriter above is rewriting a shape a reader can see.
func mustReportJSON(t *testing.T) string {
	t.Helper()
	fixtures, candidates := threeGlobals()
	runner := newTestRunner(t, newFakeProber(fixtures))
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteReport(path, report); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"stale_candidates": false,`) {
		t.Fatalf("the report this case rewrites no longer has the shape it expects:\n%s", document)
	}
	return string(document)
}

func TestRunnerMeasuresEveryGroupInOnePassThroughThePhases(t *testing.T) {
	// Two groups in one run: the global Cloudflare group and one CloudFront
	// hostname's. The phases are global barriers rather than per-group loops, so the
	// boundaries stay in the documented order however many groups there are, and
	// each group's winner is its own - which is the anti-leak rule: a CloudFront
	// address is one hostname's answer and never becomes the global one.
	fixtures, globals := threeGlobals()
	fixtures["205.251.192.1"] = served(15, 1, 0, 7*mib)
	profile := testProfile("assets.example.test", 443)
	rule := candidate.CloudFrontProfile{Profile: profile, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}
	fake := newFakeProber(fixtures)

	report, err := newTestRunner(t, fake).Run(t.Context(), Input{
		Cloudflare:         globals,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		CloudFrontRules:    []candidate.CloudFrontProfile{rule},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertPhaseStamps(t, report.Phases)
	// The groups are ordered by provider and then hostname, so two runs over one
	// input produce one document.
	if got := groupNames(report); !slices.Equal(got, []string{"cloudflare/", "cloudfront/assets.example.test"}) {
		t.Fatalf("the report holds the groups %v, want cloudflare/ and cloudfront/assets.example.test in that order", got)
	}
	// Each group was measured only against its own profile: three global candidates
	// against the global one, and the CloudFront address against its own hostname.
	// The CloudFront address is proved for its hostname and no other, so the probe
	// log names that hostname's profile rather than the global one.
	if got := len(fake.addressesOf("https")); got != 4 {
		t.Errorf("the prober was asked for %d identity proofs, want 4: three global and one per-hostname", got)
	}
	if winner := mustWinner(t, groupNamed(t, report, "cloudflare/")); winner.IP != "104.16.0.1" {
		t.Errorf("the global winner is %s, want 104.16.0.1", winner.IP)
	}
	front := groupNamed(t, report, "cloudfront/assets.example.test")
	if winner := mustWinner(t, front); winner.IP != "205.251.192.1" {
		t.Errorf("the CloudFront winner is %s, want 205.251.192.1", winner.IP)
	}
	// The CloudFront group's own p10 is its one measured speed.
	if front.P10BytesPerSecond != 7*float64(mib) {
		t.Errorf("the CloudFront group reports a p10 of %g B/s, want %g", front.P10BytesPerSecond, 7*float64(mib))
	}
	// Nothing was in service for either group, so neither winner has an incumbent to
	// beat and both are allowed to switch.
	if front.Winner.CurrentIP != "" || !front.Winner.SwitchAllowed {
		t.Errorf("the CloudFront winner records an incumbent %q with switch allowed %v, want none and true",
			front.Winner.CurrentIP, front.Winner.SwitchAllowed)
	}
}

func TestRunnerReportsEachGroupsOwnReasonWhenOneOfThemProducesNoWinner(t *testing.T) {
	// One group measuring cleanly and one measuring nothing are two facts, and a
	// report that said only "no winner" for the run would lose one of them. The
	// CloudFront address cannot serve its hostname, so its group has no winner while
	// the global group does.
	fixtures, globals := threeGlobals()
	broken := served(15, 1, 0, 7*mib)
	broken.identityErr = errors.New("the certificate presented is for other.example.test, not assets.example.test")
	fixtures["205.251.192.1"] = broken
	profile := testProfile("assets.example.test", 443)
	rule := candidate.CloudFrontProfile{Profile: profile, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}

	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         globals,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		CloudFrontRules:    []candidate.CloudFrontProfile{rule},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if winner := mustWinner(t, groupNamed(t, report, "cloudflare/")); winner.IP != "104.16.0.1" {
		t.Errorf("the global winner is %s, want 104.16.0.1: one group failing is not a failed run", winner.IP)
	}
	front := groupNamed(t, report, "cloudfront/assets.example.test")
	if front.Winner != nil {
		t.Errorf("the CloudFront group named a winner (%s) although its address could not be proved", front.Winner.IP)
	}
	if front.NoWinner != ReasonNoProvedCandidate {
		t.Errorf("the CloudFront group reports %q, want %q", front.NoWinner, ReasonNoProvedCandidate)
	}
}

// The rule for which profiles a group is held to has exactly one implementation in
// this project, `Profiles.ForSubject`, and it matches DNS names case
// insensitively - as DNS names are matched everywhere else here. A CloudFront rule
// and a candidate that spell the same hostname differently are the same group, and
// the in-run gate has to reach the same verdict the final proof and the health
// check do; a second copy of the rule that compares exactly is a group the run
// refuses with "no identity profile" while the proof of the same address would
// have found a profile.
func TestRunnerHoldsAGroupToTheProfileThatNamesItsHostnameInAnyCase(t *testing.T) {
	profile := testProfile("Assets.Example.test", 443)
	rule := candidate.CloudFrontProfile{Profile: profile, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}
	runner := newTestRunner(t, newFakeProber(map[string]*addressFixture{
		"205.251.192.1": served(10, 1, 0, 5*mib),
	}))

	report, err := runner.Run(t.Context(), Input{
		// The candidate spells the hostname the rule does not.
		CloudFront:      []candidate.Candidate{cloudFrontCandidate("205.251.192.1", "assets.example.test")},
		CloudFrontRules: []candidate.CloudFrontProfile{rule},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := groupNamed(t, report, "cloudfront/assets.example.test")
	entry := candidateFor(t, group, "205.251.192.1")
	if entry.Reason != "" {
		t.Errorf("the candidate is refused with %q, want no refusal: the rule names %q and DNS names are case insensitive",
			entry.Reason, profile.Hostname)
	}
	if !entry.Eligible {
		t.Fatalf("the candidate is ineligible: %+v", entry)
	}
	if group.Winner == nil || group.Winner.IP != "205.251.192.1" {
		t.Errorf("the group has no winner, want 205.251.192.1: the proof found the profile the exact match missed")
	}
}

func TestRunnerRefusesAGroupWithNoIdentityProfile(t *testing.T) {
	// A group nothing can be proved against cannot produce a winner, and the report
	// has to say that rather than measuring candidates against nothing and calling
	// the result a measurement.
	// The run is given CloudFront candidates and no rule naming their hostname, so
	// the group exists and cannot be identified.
	fixtures, _ := threeGlobals()
	fixtures["205.251.192.1"] = served(15, 1, 0, 7*mib)
	fake := newFakeProber(fixtures)

	report, err := newTestRunner(t, fake).Run(t.Context(), Input{
		Cloudflare:         threeGlobalsCandidates(t),
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		CloudFront:         []candidate.Candidate{cloudFrontCandidate("205.251.192.1", "assets.example.test")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	front := groupNamed(t, report, "cloudfront/assets.example.test")
	if front.Winner != nil {
		t.Errorf("the unproved group named a winner (%s)", front.Winner.IP)
	}
	if front.NoWinner != ReasonNoProvedCandidate {
		t.Errorf("the unproved group reports %q, want %q", front.NoWinner, ReasonNoProvedCandidate)
	}
	entry := candidateFor(t, front, "205.251.192.1")
	if entry.Reason != ReasonNoProfile {
		t.Errorf("the candidate is refused with %q, want %q", entry.Reason, ReasonNoProfile)
	}
	// Nothing was dialled for it: a group with no port to aim at is not measured at
	// port zero.
	for _, call := range fake.calls {
		if call.Address == "205.251.192.1" {
			t.Errorf("the run made a %s call for a group with no profile", call.Kind)
		}
	}
}

func TestRunnerSkipsAnAddressOfTheSelectorItCannotEvenMeasure(t *testing.T) {
	// A hand-written selector can name a winner the candidate rules refuse - private
	// space, say. That winner cannot be re-proved and cannot be published, and it
	// is named in the report rather than silently dropped, because an operator whose
	// router is pointing at 192.168.1.1 needs to be told.
	fixtures, candidates := threeGlobals()
	report, err := newTestRunner(t, newFakeProber(fixtures)).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		LastGood:           mustSelector(t, 4, "192.168.1.1", ""),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.SkippedRetained) != 1 {
		t.Fatalf("the report names %d skipped addresses, want 1: %v", len(report.SkippedRetained), report.SkippedRetained)
	}
	if !strings.Contains(report.SkippedRetained[0], "192.168.1.1") || !strings.Contains(report.SkippedRetained[0], "public") {
		t.Errorf("the skipped line %q does not name the address and the rule", report.SkippedRetained[0])
	}
	// The rest of the run is unaffected: the three measurable candidates are still
	// measured and one of them still wins.
	if winner := mustWinner(t, mustGroup(t, report, "cloudflare/")); winner.IP != "104.16.0.1" {
		t.Errorf("the winner is %s, want 104.16.0.1: one unusable address must not cost the run", winner.IP)
	}
	// The report still names the address the selector holds - that is what it holds
	// - and gives it a score of zero, because it was not measured. A zero is the
	// empty-winner case the switch gate documents: there is no measured incumbent to
	// beat, and an address in private space is not one worth keeping in service.
	winner := mustWinner(t, mustGroup(t, report, "cloudflare/"))
	if winner.CurrentIP != "192.168.1.1" || winner.CurrentScore != 0 {
		t.Errorf("the winner records an incumbent %q at %g, want 192.168.1.1 at 0", winner.CurrentIP, winner.CurrentScore)
	}
}

func TestRunnerMeasuresThePortItsProfileNames(t *testing.T) {
	// The connect measurement is aimed at the port the group's profile names, not at
	// a port this project guesses. A CloudFront profile on 8443 that was measured at
	// 443 would be measuring a port nothing is served on, and the report would show a
	// p50 for it.
	fixtures, _ := threeGlobals()
	// The CloudFront address is served on 8443, and the fake refuses any other port.
	fixtures["205.251.192.1"] = served(15, 1, 0, 7*mib)
	fixtures["205.251.192.1"].port = 8443
	profile := testProfileOnPort("assets.example.test", 8443)
	rule := candidate.CloudFrontProfile{Profile: profile, Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.1")}}
	fake := newFakeProber(fixtures)

	report, err := newTestRunner(t, fake).Run(t.Context(), Input{
		Cloudflare:         threeGlobalsCandidates(t),
		CloudFrontRules:    []candidate.CloudFrontProfile{rule},
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry := candidateFor(t, groupNamed(t, report, "cloudfront/assets.example.test"), "205.251.192.1")
	if entry.Samples != runnerTCPSamples {
		t.Errorf("the CloudFront candidate reports %d samples, want %d: it was measured on the port its profile names", entry.Samples, runnerTCPSamples)
	}
	if entry.P50MS != 15 {
		t.Errorf("the CloudFront candidate reports a p50 of %gms, want the fixture's 15ms", entry.P50MS)
	}
}

func TestRunnerRefusesAGroupWhoseProfilesNameDifferentPorts(t *testing.T) {
	// One connect measurement has to be aimed at one port. A global group whose
	// profiles name two of them cannot say which, and measuring at either would
	// publish a number for a port nothing may be served on.
	fixtures, _ := threeGlobals()
	runner := newTestRunner(t, newFakeProber(fixtures))
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         threeGlobalsCandidates(t),
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443), testProfileOnPort("secure.example.test", 8443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	group := mustGroup(t, report, "cloudflare/")
	if group.Winner != nil {
		t.Errorf("the group named a winner (%s) although it cannot be measured", group.Winner.IP)
	}
	entry := candidateFor(t, group, "104.16.0.1")
	if entry.Reason != ReasonProfilePortsDiffer {
		t.Errorf("the candidate is refused with %q, want %q", entry.Reason, ReasonProfilePortsDiffer)
	}
}

// threeGlobalsCandidates is the candidate list of the fixture of record on its own,
// for the cases that add a second group to it.
func threeGlobalsCandidates(t *testing.T) []candidate.Candidate {
	t.Helper()
	_, candidates := threeGlobals()
	return candidates
}

func TestReadReportRefusesTheDocumentsItCannotApply(t *testing.T) {
	// Every one of these is a field a hand-edited or machine-edited document could
	// get wrong in a way that changes which address the rewriter is handed, so each
	// is refused by name rather than interpreted. The report they are all derived
	// from is a real one this build wrote, so the only thing under test is the rule
	// each edit breaks.
	document := mustReportJSON(t)
	edits := map[string][2]string{
		"a schema version this build does not implement": {`"schema_version": 1,`, `"schema_version": 2,`},
		"no time": {`"generated_at": "2026-09-26T03:00:00Z",`, ``},
		"two accountings of one configuration that disagree": {
			`"policy_sha256": "5c9536c0f64193f535c425baf9f2c7431b89eb46bab5fb85d4bfcffabb565f43",`,
			`"policy_sha256": "0000000000000000000000000000000000000000000000000000000000000000",`,
		},
		"a digest that is not one":                     {`"config_sha256": "5c9536`, `"config_sha256": "not-a-dig`},
		"a negative byte count":                        {`"identity_body_bytes": 6144,`, `"identity_body_bytes": -1,`},
		"a group that is not a group this build knows": {`"provider": "cloudflare",`, `"provider": "akamai",`},
		"a global group carrying a hostname": {`"provider": "cloudflare",`, `"provider": "cloudflare",
              "hostname": "assets.example.test",`},
		"a winner and a no-winner reason together": {
			`      "winner": {`,
			`      "no_winner_reason": "the group produced no winner",
      "winner": {`,
		},
		"a candidate that is not a public address": {`"ip": "104.16.0.1",`, `"ip": "192.168.1.1",`},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			rewritten := strings.Replace(document, edit[0], edit[1], 1)
			if rewritten == document {
				t.Skipf("the fixture no longer carries %q, so this case cannot rewrite it", edit[0])
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadReport(path); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("ReadReport of a report with %s returned %v, want %v", name, err, ErrInvalidReport)
			}
		})
	}
}

func TestRunnerStampsEachPhaseBoundaryFromTheClockAtTheMoment(t *testing.T) {
	// The report's phase boundaries are only worth carrying if each one is a reading
	// taken when the phase happened. A run that stamped all of them with one reading
	// would produce a document whose fourteen boundaries are the same instant, and an
	// ordering check over them would be checking nothing.
	//
	// The clock here advances a millisecond per reading, so every boundary is a
	// distinct literal. Under the frozen clock the other cases use, all of them are
	// equal and this assertion would be vacuous - which is exactly why this case
	// exists.
	clock := &tickingClock{origin: runnerNow}
	fixtures, candidates := threeGlobals()
	report, err := newTestRunner(t, newFakeProber(fixtures), func(tuning *runnerTuning) {
		tuning.options.Now = clock.now
	}).Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// One reading dates the run, and then one per boundary: collect, TCP, identity,
	// latency, bandwidth and score, two each, in that order.
	want := []struct {
		name  string
		value time.Time
	}{
		{"generated_at", runnerNow},
		{"collect.started_at", runnerNow.Add(1 * time.Millisecond)},
		{"collect.ended_at", runnerNow.Add(2 * time.Millisecond)},
		{"tcp.started_at", runnerNow.Add(3 * time.Millisecond)},
		{"tcp.ended_at", runnerNow.Add(4 * time.Millisecond)},
		{"identity.started_at", runnerNow.Add(5 * time.Millisecond)},
		{"identity.ended_at", runnerNow.Add(6 * time.Millisecond)},
		{"latency.started_at", runnerNow.Add(7 * time.Millisecond)},
		{"latency.ended_at", runnerNow.Add(8 * time.Millisecond)},
		{"bandwidth.started_at", runnerNow.Add(9 * time.Millisecond)},
		{"bandwidth.ended_at", runnerNow.Add(10 * time.Millisecond)},
		{"score.started_at", runnerNow.Add(11 * time.Millisecond)},
		{"score.ended_at", runnerNow.Add(12 * time.Millisecond)},
	}
	if !report.GeneratedAt.Equal(want[0].value) {
		t.Errorf("generated_at is %s, want %s: one reading dates the run", report.GeneratedAt, want[0].value)
	}
	got := labelledPhases(report.Phases)
	for index, bound := range want[1:] {
		if got[index].value.IsZero() {
			t.Fatalf("the report has no %s", bound.name)
		}
		if !got[index].value.Equal(bound.value) {
			t.Errorf("%s is %s, want %s: every boundary is its own reading of the clock",
				bound.name, got[index].value.Format(time.RFC3339Nano), bound.value.Format(time.RFC3339Nano))
		}
	}
}

func TestApplyStampsTheFinalProofFromTheClockAtTheMoment(t *testing.T) {
	// The seventh phase is the apply's, and its boundaries are read the same way. A
	// proof that started at one instant and ended at another is what says the lock
	// was held for a while, which is the number an operator needs when a health
	// check times out behind an apply - and a pair of equal stamps would say the
	// hold was instantaneous whatever it was.
	//
	// The exact offsets are not asserted here: how many times an apply reads the
	// clock before the proof is its own business, and a test that pinned it would
	// break for a change that improved nothing. What is asserted is the ordering the
	// report exists to carry.
	clock := &tickingClock{origin: runnerNow}
	fixtures, candidates := threeGlobals()
	runner := newTestRunner(t, newFakeProber(fixtures), func(tuning *runnerTuning) {
		tuning.options.Now = clock.now
	})
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         candidates,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	applied, published, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	proof := applied.Phases.FinalProof
	if proof.StartedAt.IsZero() || proof.EndedAt.IsZero() {
		t.Fatalf("the applied report has no final proof boundaries: %+v", proof)
	}
	if !proof.StartedAt.After(report.Phases.Score.EndedAt) {
		t.Errorf("the final proof starts at %s, which is not after the score phase ended at %s: the seventh phase is the last one",
			proof.StartedAt, report.Phases.Score.EndedAt)
	}
	if !proof.EndedAt.After(proof.StartedAt) {
		t.Errorf("the final proof ends at %s and starts at %s, so its two boundaries are one reading of the clock",
			proof.EndedAt, proof.StartedAt)
	}
	// The whole stamped sequence, the run's six phases and then the apply's, is
	// strictly increasing: that is the property a reader takes from the document.
	ordered := append(labelledPhases(report.Phases)[:12], labelledPhases(applied.Phases)[12:]...)
	for index := 1; index < len(ordered); index++ {
		if !ordered[index].value.After(ordered[index-1].value) {
			t.Fatalf("%s (%s) is not after %s (%s): the stamped sequence is not increasing",
				ordered[index].name, ordered[index].value.Format(time.RFC3339Nano),
				ordered[index-1].name, ordered[index-1].value.Format(time.RFC3339Nano))
		}
	}
	if !published.LastSuccess.After(proof.EndedAt) {
		t.Errorf("the published selector records success at %s, which is not after the proof ended at %s",
			published.LastSuccess, proof.EndedAt)
	}
}

// A three-candidate group whose three rank orders disagree, so the winner's score
// is only about four percent above the runner-up's and the ten percent gate can
// refuse a same-run switch. This is the shape the shipped shortlists really
// produce, and it is why a per-group switch decision is reachable at all:
//
//	address        p50   jitter   speed          ranks (lat, bw, stab)   score
//	205.251.192.1  10ms  30ms     3 MiB/s        1, 2, 3                 2.35
//	205.251.192.2  20ms  20ms     5 MiB/s        2, 1, 2                 2.45
//	205.251.192.3  30ms  10ms     1 MiB/s        3, 3, 1                 1.20
//
// 2.45 is not ten percent better than 2.35, so a winner of .2 over an incumbent
// of .1 is refused. Each figure is 4500*rank-share + 1000*rank-share over the
// three ranks 3, 2 and 1.
func closeCallCloudFront(t *testing.T) (map[string]*addressFixture, []candidate.Candidate, candidate.CloudFrontProfile) {
	t.Helper()
	fixtures := map[string]*addressFixture{
		"205.251.192.1": served(10, 30, 0, 3*float64(mib)),
		"205.251.192.2": served(20, 20, 0, 5*float64(mib)),
		"205.251.192.3": served(30, 10, 0, 1*float64(mib)),
	}
	listed := []candidate.Candidate{
		cloudFrontCandidate("205.251.192.1", "assets.example.test"),
		cloudFrontCandidate("205.251.192.3", "assets.example.test"),
	}
	rule := candidate.CloudFrontProfile{
		Profile:    testProfile("assets.example.test", 443),
		Candidates: []netip.Addr{netip.MustParseAddr("205.251.192.2")},
	}
	return fixtures, listed, rule
}

// twoGroups is one run over the global group and one CloudFront group, against a
// selector holding an address in service for each: the global group's runner-up, and
// the CloudFront group's runner-up, whose score is within four percent of that
// group's winner. So the global group clears the ten percent gate and switches, and
// the CloudFront group does not - which is the ordinary night this ruling is about.
//
// It returns the runner, the report and the profile set, and each case applies it
// and looks at one thing.
func twoGroups(t *testing.T, frontFixtures map[string]*addressFixture) (*testRunner, Report, Profiles) {
	t.Helper()
	fixtures, globals := threeGlobals()
	_, listed, rule := closeCallCloudFront(t)
	for address, fixture := range frontFixtures {
		fixtures[address] = fixture
	}
	runner := newTestRunner(t, newFakeProber(fixtures))
	current := mustSelector(t, 4, "104.16.1.1", "")
	current.CloudFront = map[string]string{"assets.example.test": "205.251.192.1"}
	writeSelector(t, runner.selectorPath, current)
	report, err := runner.Run(t.Context(), Input{
		Cloudflare:         globals,
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		CloudFront:         listed,
		CloudFrontRules:    []candidate.CloudFrontProfile{rule},
		LastGood:           readSelector(t, runner.selectorPath),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return runner, report, Profiles{
		Global:     []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
		ByHostname: map[string]candidate.ProbeProfile{"assets.example.test": rule.Profile},
	}
}

//

func TestApplySwitchesTheGroupsThatImprovedAndKeepsTheOnesThatDidNot(t *testing.T) {
	// Each group's decision is its own. The global group found an address that
	// clears the improvement gate and the CloudFront group found one that does not,
	// and the first is published while the second keeps the mapping it had - because
	// an all-or-nothing apply would let one group's ordinary "not better tonight"
	// stop the other group from improving, every night, for as long as it lasted.
	clean, _, _ := closeCallCloudFront(t)
	runner, report, profiles := twoGroups(t, clean)
	selectorPath := runner.selectorPath
	before := mustReadSelectorBytes(t, selectorPath)

	if winner := mustWinner(t, groupNamed(t, report, "cloudflare/")); !winner.SwitchAllowed {
		t.Errorf("the global winner %s is refused its switch, want it allowed: 3.0 is more than ten percent better than 2.0", winner.IP)
	}
	frontWinner := mustWinner(t, groupNamed(t, report, "cloudfront/assets.example.test"))
	if frontWinner.IP != "205.251.192.2" {
		t.Fatalf("the CloudFront winner is %s at %g, want 205.251.192.2 at 2.45", frontWinner.IP, frontWinner.Score)
	}
	if frontWinner.SwitchAllowed {
		t.Error("the CloudFront winner was allowed to switch, want it refused: 2.45 is not ten percent better than 2.35")
	}

	applied, published, err := runner.Apply(t.Context(), report, profiles)
	if err != nil {
		t.Fatalf("Apply with one group refusing its switch: %v", err)
	}
	// The global group switched.
	if published.WinnerIP != "104.16.0.1" {
		t.Errorf("the published global winner is %q, want 104.16.0.1", published.WinnerIP)
	}
	// The CloudFront group kept the address it had, and did not fall back to
	// clearing the mapping either: a refusal is not a withdrawal.
	if published.CloudFront["assets.example.test"] != "205.251.192.1" {
		t.Errorf("the published CloudFront mapping is %q, want the 205.251.192.1 it already had",
			published.CloudFront["assets.example.test"])
	}
	// The document did change - the global winner moved - so the generation moved
	// and the file is not what it was.
	if published.Generation != 5 {
		t.Errorf("the published selector is generation %d, want 5", published.Generation)
	}
	if string(before) == string(mustReadSelectorBytes(t, selectorPath)) {
		t.Error("the apply changed nothing, but the global winner should have moved")
	}
	// The report says which group did what.
	if applied.Outcome != OutcomePublished {
		t.Errorf("the apply's overall outcome is %q, want %q: one group published", applied.Outcome, OutcomePublished)
	}
	if got := groupOutcome(t, applied, "cloudfront/assets.example.test"); got != OutcomeKept {
		t.Errorf("the CloudFront group's outcome is %q, want %q", got, OutcomeKept)
	}
	if reason := groupOutcomeReason(t, applied, "cloudfront/assets.example.test"); !strings.Contains(reason, "2.45") {
		t.Errorf("the CloudFront group's reason is %q, want the refusal that names the two scores", reason)
	}
	// Only the published group was proved again. The run proved all six candidates -
	// three global against the global profile, three per-hostname against their own -
	// and the apply proved the one winner it was about to write. The kept group is
	// not proved, because a proof is the cost of a publish and nothing of it is being
	// published.
	proofs := runner.prober.(*fakeProber).profiledCalls()
	if len(proofs) != 7 {
		t.Errorf("the prober was asked for %d identity proofs, want 7: six candidates in the run and the published winner", len(proofs))
	} else if last := proofs[len(proofs)-1]; last.Address != "104.16.0.1" || last.Hostname != "speed.example.test" {
		t.Errorf("the last proof was %s against %q, want the published global winner against the global profile", last.Address, last.Hostname)
	}
}

func TestApplyKeepsAGroupsMappingWhenThatGroupProducedNoWinner(t *testing.T) {
	// A group that measured nothing publishable keeps its mapping, and does not stop
	// the groups that did. The CloudFront addresses here cannot be proved, so that
	// group has no winner at all - which is a different fact from a refused switch and
	// is reported as one.
	frontFixtures, _, _ := closeCallCloudFront(t)
	for _, fixture := range frontFixtures {
		fixture.identityErr = errors.New("the certificate presented is for other.example.test, not assets.example.test")
	}
	runner, report, profiles := twoGroups(t, frontFixtures)
	selectorPath := runner.selectorPath

	if groupNamed(t, report, "cloudfront/assets.example.test").Winner != nil {
		t.Fatal("the CloudFront group named a winner although none of its addresses could be proved")
	}
	applied, published, err := runner.Apply(t.Context(), report, profiles)
	if err != nil {
		t.Fatalf("Apply with one group measuring nothing: %v", err)
	}
	if published.WinnerIP != "104.16.0.1" {
		t.Errorf("the published global winner is %q, want 104.16.0.1: one group failing is not a failed apply", published.WinnerIP)
	}
	if published.CloudFront["assets.example.test"] != "205.251.192.1" {
		t.Errorf("the published CloudFront mapping is %q, want the 205.251.192.1 it already had",
			published.CloudFront["assets.example.test"])
	}
	// The report says which group did what, and why the other one did nothing.
	if got := groupOutcome(t, applied, "cloudfront/assets.example.test"); got != OutcomeKept {
		t.Errorf("the CloudFront group's outcome is %q, want %q", got, OutcomeKept)
	}
	if reason := groupOutcomeReason(t, applied, "cloudfront/assets.example.test"); reason != ReasonNoProvedCandidate {
		t.Errorf("the CloudFront group's reason is %q, want the no-winner reason the run reported", reason)
	}
	if got := groupOutcome(t, applied, "cloudflare/"); got != OutcomePublished {
		t.Errorf("the global group's outcome is %q, want %q", got, OutcomePublished)
	}
	if applied.Outcome != OutcomePublished {
		t.Errorf("the apply's overall outcome is %q, want %q: one group published", applied.Outcome, OutcomePublished)
	}
	_ = selectorPath
}

func TestApplyWritesNothingWhenEveryGroupIsKept(t *testing.T) {
	// Nothing was published, so there is nothing to write: no generation move, no
	// refreshed proof, and a file an operator can see is byte-for-byte what it was.
	// A generation that moved for a run that changed nothing would tell the
	// rewriter that something happened when nothing did.
	fixtures, globals := threeGlobals()
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	// The incumbent is the winner of its own run, and a winner that is the address
	// already in service is published - so make it a group where the winner is
	// barely better instead: the two candidates of a three-candidate group with the
	// close call.
	closeFixtures, listed, rule := closeCallCloudFront(t)
	frontRunner, frontPath := newTestRunnerWithSelector(t, newFakeProber(closeFixtures))
	current := mustSelector(t, 4, "205.251.192.1", "")
	current.CloudFront = map[string]string{"assets.example.test": "205.251.192.1"}
	current.WinnerIP = ""
	before := writeSelector(t, frontPath, current)
	report, err := frontRunner.Run(t.Context(), Input{
		CloudFront:      listed,
		CloudFrontRules: []candidate.CloudFrontProfile{rule},
		LastGood:        readSelector(t, frontPath),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = runner
	_ = selectorPath
	_ = globals
	applied, published, err := frontRunner.Apply(t.Context(), report, Profiles{
		ByHostname: map[string]candidate.ProbeProfile{"assets.example.test": rule.Profile},
	})
	if err != nil {
		t.Fatalf("Apply with every group kept: %v", err)
	}
	if applied.Outcome != OutcomeKept {
		t.Errorf("the apply's overall outcome is %q, want %q", applied.Outcome, OutcomeKept)
	}
	mustBeNothingWritten(t, published)
	mustBeUnchanged(t, frontPath, before)
}

// mustBeNothingWritten asserts that an apply handed back no selector at all, which
// is how it says it wrote nothing.
//
// The returned document is checked against the state package's own rules as well as
// field by field, because that is the stronger claim and the one a caller can rely
// on: the zero selector is not a document any writer of this project would produce,
// so a caller that prints what it was given cannot print an address in service as
// one it applied. (The struct holds a map, so it cannot be compared with ==.)
func mustBeNothingWritten(t *testing.T, published state.Selector) {
	t.Helper()
	if published.WinnerIP != "" || published.FallbackIP != "" || published.Generation != 0 {
		t.Errorf("an apply that published nothing returned the selector %+v, want no selector at all: a caller that prints it would claim a write that did not happen", published)
	}
	if err := published.Validate(); err == nil {
		t.Error("the selector an apply that published nothing returned is one the state package accepts, so it reads as a written document rather than as nothing")
	}
}

// groupOutcome and groupOutcomeReason read one group's decision out of an applied
// report, which is where an operator looks for it.
func groupOutcome(t *testing.T, report Report, group string) Outcome {
	t.Helper()
	return groupNamed(t, report, group).Outcome
}

func groupOutcomeReason(t *testing.T, report Report, group string) string {
	t.Helper()
	return groupNamed(t, report, group).OutcomeReason
}

func mustReadSelectorBytes(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func TestAnAppliedReportIsWrittenBackAndReadBackWithItsOutcomes(t *testing.T) {
	// The outcomes an apply fills in are part of the document, so they survive a
	// round trip through the file and Validate still accepts the result. A report
	// that only validated in memory would be a document an operator could read and
	// an apply could not.
	clean, _, _ := closeCallCloudFront(t)
	applied := mustRunAndApplyTwoGroups(t, clean)
	path := filepath.Join(t.TempDir(), "applied.json")
	if err := WriteReport(path, applied); err != nil {
		t.Fatalf("WriteReport of an applied report: %v", err)
	}
	read, err := ReadReport(path)
	if err != nil {
		t.Fatalf("ReadReport of an applied report: %v", err)
	}
	if read.Outcome != OutcomePublished {
		t.Errorf("the report read back says the outcome is %q, want %q", read.Outcome, OutcomePublished)
	}
	if got := groupOutcome(t, read, "cloudfront/assets.example.test"); got != OutcomeKept {
		t.Errorf("the CloudFront group's outcome read back is %q, want %q", got, OutcomeKept)
	}
	if reason := groupOutcomeReason(t, read, "cloudfront/assets.example.test"); !strings.Contains(reason, "2.45") {
		t.Errorf("the CloudFront group's reason read back is %q, want the refusal that names the two scores", reason)
	}
	// The document's raw text carries the fields, so an operator reading the file
	// sees the decisions rather than having to infer them.
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"outcome": "published"`, `"outcome": "kept"`, `"outcome_reason"`} {
		if !strings.Contains(string(document), field) {
			t.Errorf("the written report has no %s:\n%s", field, document)
		}
	}
}

func TestReadReportRefusesAnOutcomeThatDoesNotMatchItsGroups(t *testing.T) {
	// The recorded decisions are an integrity claim about the document, so the
	// incoherent ones are refused rather than interpreted: a kept group that does not
	// say why, an outcome nothing recognises, and an overall outcome that contradicts
	// its own groups.
	//
	// The edits are made to the decoded value and the document re-encoded, because
	// that is what a hand-edited or machine-edited report is, and because rewriting
	// the text of a real document here would pin the JSON's indentation as well as
	// its meaning.
	clean, _, _ := closeCallCloudFront(t)
	applied := mustAppliedTwoGroupReport(t, clean)
	cases := map[string]func(*Report){
		"a kept group with no reason": func(report *Report) {
			report.Groups[1].OutcomeReason = ""
		},
		"an outcome nothing recognises": func(report *Report) {
			report.Groups[0].Outcome = "published-mostly"
		},
		"an overall outcome its groups contradict": func(report *Report) {
			report.Outcome = OutcomeKept
		},
		"a report that published with every group kept": func(report *Report) {
			report.Groups[0].Outcome = OutcomeKept
			report.Groups[0].OutcomeReason = "the winner is the address already in service"
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			edited := applied
			edited.Groups = slices.Clone(applied.Groups)
			edit(&edited)
			document, err := json.MarshalIndent(edited, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, document, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadReport(path); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("ReadReport of a report with %s returned %v, want %v", name, err, ErrInvalidReport)
			}
		})
	}
}

// mustAppliedTwoGroupReport is a run and an apply over two groups, one of which
// keeps its mapping, which is the shape the outcome cases need.
func mustAppliedTwoGroupReport(t *testing.T, frontFixtures map[string]*addressFixture) Report {
	t.Helper()
	applied := mustRunAndApplyTwoGroups(t, frontFixtures)
	if applied.Outcome != OutcomePublished {
		t.Fatalf("the fixture's overall outcome is %q, want %q", applied.Outcome, OutcomePublished)
	}
	return applied
}

func mustRunAndApplyTwoGroups(t *testing.T, frontFixtures map[string]*addressFixture) Report {
	t.Helper()
	runner, report, profiles := twoGroups(t, frontFixtures)
	applied, _, err := runner.Apply(t.Context(), report, profiles)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return applied
}

func TestApplyRefusesWhenTheFinalProofWouldOutliveItsDeadline(t *testing.T) {
	// The final proof runs under the control lock, so its hold has to be bounded
	// whatever the number of configured profiles and however slow the host is. One
	// deadline covers the whole phase; a host that cannot answer inside it is refused
	// and the selector is left exactly as it was.
	fixtures, candidates := threeGlobals()
	// The winner answers the run's proof at full speed and then stops answering in
	// time: two seconds of proof against a deadline of a tenth of one.
	fixtures["104.16.0.1"].proofDelay = 2 * time.Second
	fixtures["104.16.0.1"].proofDelayAfterCalls = 1
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures), func(tuning *runnerTuning) {
		tuning.options.ProofTimeout = 100 * time.Millisecond
	})
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	started := time.Now()
	_, _, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	elapsed := time.Since(started)
	if !errors.Is(err, ErrProofTimeout) {
		t.Fatalf("Apply whose proof outlives the deadline returned %v, want %v", err, ErrProofTimeout)
	}
	if elapsed > time.Second {
		t.Errorf("the apply took %s to refuse, want the deadline to cut it short at about 100ms", elapsed)
	}
	if !strings.Contains(err.Error(), "speed.example.test") {
		t.Errorf("the refusal %q does not name the profile that did not answer", err)
	}
	mustBeUnchanged(t, selectorPath, before)
}

// A report has to say which of the three things happened to its final proof: it
// never ran, it ran and was refused, or it ran and ran out of time. A reader that
// cannot tell the second from the third is reading "not run" for a proof that ran,
// which is what the CLI used to print - and a proof that ran and was refused is the
// important one, because it says the address stopped serving.
func TestARefusedFinalProofIsRecordedAsRefusedAndATimeoutAsTimedOut(t *testing.T) {
	// Refused: the winner serves the run and refuses the apply's second proof.
	fixtures, candidates := threeGlobals()
	fixtures["104.16.0.1"].identityCallsBeforeFailure = 1
	runner, _ := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	refused, _, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Apply whose proof was refused returned %v, want %v", err, ErrIdentityRefused)
	}
	if refused.FinalProofRefused != "refused" {
		t.Errorf("a refused final proof is recorded as %q, want %q", refused.FinalProofRefused, "refused")
	}
	if refused.FinalProofPassed {
		t.Error("a refused final proof is recorded as passed")
	}
	if refused.Phases.FinalProof.StartedAt.IsZero() {
		t.Error("a refused final proof recorded no start, so the phase cannot be told from one that never ran")
	}

	// Timed out: the same run against a host that cannot answer in time.
	fixtures, candidates = threeGlobals()
	fixtures["104.16.0.1"].proofDelay = 2 * time.Second
	fixtures["104.16.0.1"].proofDelayAfterCalls = 1
	slow, _ := newTestRunnerWithSelector(t, newFakeProber(fixtures), func(tuning *runnerTuning) {
		tuning.options.ProofTimeout = 100 * time.Millisecond
	})
	report = mustRunWithIncumbent(t, slow, candidates, "104.16.1.1")

	timedOut, _, err := slow.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if !errors.Is(err, ErrProofTimeout) {
		t.Fatalf("Apply whose proof ran out of time returned %v, want %v", err, ErrProofTimeout)
	}
	if timedOut.FinalProofRefused != "timed out" {
		t.Errorf("a final proof that ran out of time is recorded as %q, want %q", timedOut.FinalProofRefused, "timed out")
	}
}

func TestApplyProvesEveryProfileOfAGlobalAddressConcurrently(t *testing.T) {
	// A global address is held to the provider's representative domain and every
	// forced-ECH domain, and the list is the operator's to grow. Proving them one
	// after another would hold the control lock for the sum of their times, which is
	// the unbounded aggregate this is the fix for: five profiles answered in
	// parallel take one probe timeout, not five.
	profiles := make([]candidate.ProbeProfile, 0, 5)
	for index := 0; index < 5; index++ {
		profiles = append(profiles, testProfile(fmt.Sprintf("ech-%d.example.test", index), 443))
	}
	fixtures, candidates := threeGlobals()
	// Every proof of the winner is slow enough that five of them in sequence would
	// take five times the deadline below.
	fixtures["104.16.0.1"].proofDelay = 100 * time.Millisecond
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake, func(tuning *runnerTuning) {
		tuning.options.ProofTimeout = 2 * time.Second
	})
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	if _, _, err := runner.Apply(t.Context(), report, globalProfiles(profiles...)); err != nil {
		t.Fatalf("Apply with five profiles: %v", err)
	}
	// All five were proved, and all five at once: the prober never had more than one
	// and never fewer than five in flight.
	if got := fake.peakProofs(); got != 5 {
		t.Errorf("the prober was answering %d proofs at once, want 5: the profiles are proved concurrently", got)
	}
	proofs := fake.profiledCalls()
	if len(proofs) != 3+5 {
		t.Errorf("the prober was asked for %d identity proofs, want 8: three candidates in the run and five in the apply", len(proofs))
	}
}

func TestApplyNeverRunsMoreProfileProofsAtOnceThanTheLimit(t *testing.T) {
	// The concurrency is bounded as well as parallel. A profile list long enough to
	// overrun the limit is answered in waves, and the limit is what keeps the hold
	// predictable rather than proportional to whatever the operator has listed.
	profiles := make([]candidate.ProbeProfile, 0, ProofConcurrency+4)
	for index := 0; index < ProofConcurrency+4; index++ {
		profiles = append(profiles, testProfile(fmt.Sprintf("ech-%d.example.test", index), 443))
	}
	fixtures, candidates := threeGlobals()
	fixtures["104.16.0.1"].proofDelay = 20 * time.Millisecond
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake, func(tuning *runnerTuning) {
		tuning.options.ProofTimeout = 5 * time.Second
	})
	writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	if _, _, err := runner.Apply(t.Context(), report, globalProfiles(profiles...)); err != nil {
		t.Fatalf("Apply with %d profiles: %v", len(profiles), err)
	}
	if got := fake.peakProofs(); got != ProofConcurrency {
		t.Errorf("the prober was answering %d proofs at once, want the limit of %d", got, ProofConcurrency)
	}
	if got := len(fake.profiledCalls()); got != 3+ProofConcurrency+4 {
		t.Errorf("the prober was asked for %d identity proofs, want %d: every profile is still proved", got, 3+ProofConcurrency+4)
	}
}

func TestApplyAccountsForTheIdentityBytesOfARefusedFinalProof(t *testing.T) {
	// A refused proof still read the body it took to reach its verdict, and those
	// bytes are the operator's data allowance whether or not anything was published.
	// The report an apply hands back on a refusal is the only place that can say so,
	// because the report on disk predates the proof entirely.
	fixtures, candidates := threeGlobals()
	// The winner answers the run's proof and is refused by the apply's, having read
	// a body to reach the verdict.
	refused := served(10, 1, 0, 5*mib)
	refused.identityCallsBeforeFailure = 1
	refused.identityBodyBytes = 4096
	fixtures["104.16.0.1"] = refused
	runner, selectorPath := newTestRunnerWithSelector(t, newFakeProber(fixtures))
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")
	runBytes := report.IdentityBytes

	applied, _, err := runner.Apply(t.Context(), report, globalProfiles(testProfile("speed.example.test", 443)))
	if !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Apply whose final proof was refused returned %v, want %v", err, ErrIdentityRefused)
	}
	// The run's three candidates read 1024 each, and the refused proof read 4096 more.
	if want := runBytes + 4096; applied.IdentityBytes != want {
		t.Errorf("the refused apply's report accounts for %d identity bytes, want %d: the refused proof's 4096 are uncharged and unaccounted", applied.IdentityBytes, want)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestRunnerFinalisesAPartialReportSoItsAccountOfTheDayIsTrue(t *testing.T) {
	// A cancelled run returns the part of the report it did produce, and that part
	// has to be true: the day stands where the transfers left it and the settlements
	// the budget refused are named. A partial report that printed zero bytes spent
	// would be the one document an operator reads to find out what a run cost.
	//
	// One candidate, so the bandwidth phase has one task and the cancellation cannot
	// race the dispatch of another. The fake's transfer does not consult the context,
	// so the reservation is made and settled - twice, and the second settle is refused
	// - and the phase discovers the cancellation only as it finishes.
	fixtures := map[string]*addressFixture{"104.16.0.1": served(10, 1, 0, 5*mib)}
	fixtures["104.16.0.1"].settleTwice = true
	fake := newFakeProber(fixtures)
	ctx, cancel := context.WithCancel(t.Context())
	fake.before = func(kind, _ string) {
		if kind == "download" {
			cancel()
		}
	}

	report, err := newTestRunner(t, fake).Run(ctx, Input{
		Cloudflare:         []candidate.Candidate{globalCandidate("104.16.0.1")},
		CloudflareProfiles: []candidate.ProbeProfile{testProfile("speed.example.test", 443)},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want the context's error", err)
	}
	if report.BudgetUsed != runnerDownloadBytes {
		t.Errorf("the partial report says the day stands at %d bytes, want the %d the transfer left it at",
			report.BudgetUsed, runnerDownloadBytes)
	}
	if len(report.SettleRefusals) != 1 {
		t.Errorf("the partial report carries %d settlement refusals, want the 1 the double settle produced: %v",
			len(report.SettleRefusals), report.SettleRefusals)
	}
	// The phases the run finished still say so, which is what makes this a partial
	// report rather than an empty one.
	if report.Phases.Identity.EndedAt.IsZero() {
		t.Error("the partial report is missing the identity phase's end, so the run got no further than the fixtures claim")
	}
}

// echProfiles is a global identity profile per forced-ECH domain, named by its
// index, so a case can say exactly which of them a proof did and did not reach.
func echProfiles(count int) []candidate.ProbeProfile {
	profiles := make([]candidate.ProbeProfile, 0, count)
	for index := 0; index < count; index++ {
		profiles = append(profiles, testProfile(fmt.Sprintf("ech-%d.example.test", index), 443))
	}
	return profiles
}

func TestApplyRefusesWhenTheContextIsAlreadyDoneBeforeTheProof(t *testing.T) {
	// The final proof is the last gate before an address reaches DNS answers, so a
	// proof that never ran is not a proof. A context that is already done when the
	// phase starts is the shape that used to publish: every worker returns before it
	// calls the prober, not one index is fed, and every slot in the answer slice is
	// left in its zero value - which the walk then reads as a silent pass.
	//
	// Nothing may be written here, and nothing may be asked of the network.
	fixtures, candidates := threeGlobals()
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")
	asked := len(fake.profiledCalls())

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := runner.Apply(ctx, report, globalProfiles(echProfiles(3)...))
	if err == nil {
		t.Fatal("Apply whose context was already done published, want a refusal: a proof that never ran is not a proof")
	}
	if !errors.Is(err, ErrIdentityRefused) {
		t.Errorf("Apply of a proof that never ran returned %v, want %v", err, ErrIdentityRefused)
	}
	if got := len(fake.profiledCalls()); got != asked {
		t.Errorf("the prober was asked for %d proofs after the context was done, want the %d it had already answered: a proof that cannot run must not dial", got-asked, asked)
	}
	// The refusal names a profile, because an operator has to know which one went
	// unproved to be able to act on it.
	if !strings.Contains(err.Error(), "ech-0.example.test") {
		t.Errorf("the refusal %q does not name the profile that went unproved", err)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyRefusesWhenTheDeadlineFiresWhileTheProfilesAreStillBeingFed(t *testing.T) {
	// More profiles than the concurrency limit means the dispatcher feeds the list
	// in waves, and the deadline can arrive while it is blocked waiting for a worker
	// to free. Everything from that point on was never handed to a worker, so its
	// slot is untouched - and an untouched slot read as a pass is how a host that was
	// never asked for four of its twenty names would have been published.
	//
	// The first wave answers in full even after the deadline, which is the shape
	// that puts the un-fed tail in the walk: the sixteen that ran succeeded, so the
	// walk reaches index sixteen, and index sixteen is the one that must refuse.
	count := ProofConcurrency + 4
	profiles := echProfiles(count)
	fixtures, candidates := threeGlobals()
	// The winner answers every profile slowly and in full. It is the apply's proofs
	// that are slow: the run's own proof of it is quick.
	fixtures["104.16.0.1"].proofDelay = 200 * time.Millisecond
	fixtures["104.16.0.1"].proofDelayAfterCalls = 1
	fixtures["104.16.0.1"].proofOutlivesDeadline = true
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake, func(tuning *runnerTuning) {
		tuning.options.ProofTimeout = 50 * time.Millisecond
	})
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	_, _, err := runner.Apply(t.Context(), report, globalProfiles(profiles...))
	if err == nil {
		t.Fatal("Apply whose deadline arrived with four profiles un-fed published, want a refusal")
	}
	if !errors.Is(err, ErrIdentityRefused) {
		t.Errorf("Apply with an un-fed tail returned %v, want %v", err, ErrIdentityRefused)
	}
	// The refusal names the first profile the dispatcher never reached, and says how
	// far it got, so an operator can see which names went unasked.
	if !strings.Contains(err.Error(), "ech-16.example.test") {
		t.Errorf("the refusal %q does not name the first profile that was never reached", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("of the %d profiles", count)) {
		t.Errorf("the refusal %q does not say how many of the %d profiles were proved", err, count)
	}
	// Exactly one wave was asked, and it was the first sixteen: the prober is the
	// record of which names this router actually put to the network. The set is
	// compared as a set, because the wave's own order is the dispatcher's business
	// and the gate's only claim is about which names it reached.
	asked := fake.profiledCalls()
	if len(asked) != 3+ProofConcurrency {
		t.Fatalf("the prober was asked for %d proofs, want %d: the run's three and one full wave of %d", len(asked), 3+ProofConcurrency, ProofConcurrency)
	}
	names := make([]string, 0, len(asked)-3)
	for _, call := range asked[3:] {
		names = append(names, call.Hostname)
	}
	slices.Sort(names)
	want := make([]string, 0, ProofConcurrency)
	for index := 0; index < ProofConcurrency; index++ {
		want = append(want, fmt.Sprintf("ech-%d.example.test", index))
	}
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("the one wave asked for was %v,\nwant %v: the wave must be the first %d profiles and no other", names, want, ProofConcurrency)
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyProvesEveryConfiguredProfileAndNamesTheOneThatRefused(t *testing.T) {
	// The ordinary case, stated per profile rather than as a total: every configured
	// profile is put to the network, the one that refuses is named, and the refusal
	// does not stop the others from being asked. A walk that skipped an index would
	// satisfy a count and fail this.
	//
	// The refusing profile is in the middle of the list rather than at either end,
	// because a walk that stopped at the first failure would then leave the tail
	// unasked - which is the shape the sentinel has to survive too.
	profiles := echProfiles(5)
	refused := profiles[2].Hostname
	fixtures, candidates := threeGlobals()
	fixtures["104.16.0.1"].identityRefusedFor = map[string]error{
		refused: errors.New("the response is a 403, which the profile does not expect"),
	}
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake)
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	_, _, err := runner.Apply(t.Context(), report, globalProfiles(profiles...))
	if !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Apply with a refusing profile returned %v, want %v", err, ErrIdentityRefused)
	}
	if !strings.Contains(err.Error(), refused) {
		t.Errorf("the refusal %q does not name the profile that refused", err)
	}
	// All five were asked, and the refusing one is among them: the refusal is a
	// verdict about the host, not an excuse to ask about fewer names. The proofs of
	// one address run concurrently, so this compares the set of names rather than
	// their order - the order is ProofConcurrency's business, not this gate's.
	asked := fake.profiledCalls()[3:]
	names := make([]string, 0, len(asked))
	for _, call := range asked {
		names = append(names, call.Hostname)
	}
	if len(names) != len(profiles) {
		t.Fatalf("the prober was asked for %d proofs in the apply, want one per profile: %d", len(names), len(profiles))
	}
	slices.Sort(names)
	for index, profile := range profiles {
		if names[index] != profile.Hostname {
			t.Errorf("profile %d of the apply was %q, want %q: every configured profile is proved, not a prefix of them", index, names[index], profile.Hostname)
		}
	}
	mustBeUnchanged(t, selectorPath, before)
}

func TestApplyNamesAHostRefusalEvenWhenTheProofRanOutOfTimeBesideIt(t *testing.T) {
	// A refusal and a timeout can be in the same proof phase, and the report has to
	// name which of them happened. A walk that classified by asking the context
	// whether it was done relabelled an ordinary refusal as "cut short" whenever a
	// slower profile's timeout happened first - so a host that stopped serving looked
	// like a host that was slow.
	profiles := echProfiles(2)
	refused := profiles[0].Hostname
	fixtures, candidates := threeGlobals()
	// The first profile is refused outright. The second is slow past the deadline, so
	// the context is done by the time the walk reaches either of them.
	fixtures["104.16.0.1"].identityRefusedFor = map[string]error{
		refused: errors.New("the response is a 403, which the profile does not expect"),
	}
	fixtures["104.16.0.1"].proofDelay = 2 * time.Second
	fixtures["104.16.0.1"].proofDelayAfterCalls = 1
	fake := newFakeProber(fixtures)
	runner, selectorPath := newTestRunnerWithSelector(t, fake, func(tuning *runnerTuning) {
		tuning.options.ProofTimeout = 100 * time.Millisecond
	})
	before := writeSelector(t, selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
	report := mustRunWithIncumbent(t, runner, candidates, "104.16.1.1")

	_, _, err := runner.Apply(t.Context(), report, globalProfiles(profiles...))
	if !errors.Is(err, ErrIdentityRefused) {
		t.Fatalf("Apply with one refused profile beside one slow profile returned %v, want %v: the host refused, it was not merely slow", err, ErrIdentityRefused)
	}
	if strings.Contains(err.Error(), "cut short") {
		t.Errorf("the refusal %q blames the context, want the profile the host refused", err)
	}
	if !strings.Contains(err.Error(), refused) {
		t.Errorf("the refusal %q does not name the profile the host refused", err)
	}
	mustBeUnchanged(t, selectorPath, before)
}

// mustSayRefused asserts that a report an apply refused says so at both levels: the
// report as a whole, and every group inside it.
//
// The report-level outcome is what a script reads, and the per-group one is what a
// reader reads, so a refusal that only fixed the first would still tell a reader
// the group was published. Both are asserted here, and neither is allowed to be
// "published" - the pair is the only place in this file where an apply's outcome is
// checked rather than assumed.
func mustSayRefused(t *testing.T, report Report) {
	t.Helper()
	if report.Outcome == OutcomePublished {
		t.Errorf("a refused apply returned a report whose outcome is %q: a refusal is not a publication", report.Outcome)
	}
	if report.Outcome != OutcomeRefused {
		t.Errorf("a refused apply returned a report whose outcome is %q, want %q", report.Outcome, OutcomeRefused)
	}
	for _, group := range report.Groups {
		if group.Outcome == OutcomePublished {
			t.Errorf("a refused apply left %s's outcome as %q: nothing was published for it", group.Group, group.Outcome)
		}
		if group.Outcome != "" && group.OutcomeReason == "" {
			t.Errorf("a refused apply left %s's outcome %q with no reason", group.Group, group.Outcome)
		}
	}
}

// refuseRefusal is how a case prepares one refusal: it arranges the router's own
// state, and edits the report in place when the gate is one about the report rather
// than about the router.
type refuseRefusal func(t *testing.T, runner *testRunner, report *Report)

func TestApplyReportsARefusalRatherThanAPublication(t *testing.T) {
	// Every gate an apply can be stopped at, and the claim each of them has to stop
	// making. Apply records what it *decided* before it takes the lock, so a
	// refusal after that point hands back a report whose group says "published" and
	// whose own outcome says "published" - printed next to "applied: nothing", which
	// is the same mislabel round 2 fixed for the all-kept path and left in place for
	// this one. A script keying on outcome: rather than applied: would record a
	// publication on every one of them.
	profiles := globalProfiles(testProfile("speed.example.test", 443))
	for name, refuse := range map[string]refuseRefusal{
		// The four gates before the lock, which is where the per-group outcomes are
		// not yet recorded. They are here because the outcome claim has to be
		// *absent* on these paths, which is a different thing from being refused, and
		// a report read back from a previously applied document still carries one.
		"a report whose phase stamps are out of order": func(_ *testing.T, _ *testRunner, report *Report) {
			report.Phases.Collect.EndedAt = runnerNow.Add(time.Hour)
		},
		"a report measured under another configuration": func(_ *testing.T, _ *testRunner, report *Report) {
			other := "0000000000000000000000000000000000000000000000000000000000000000"
			report.PolicySHA256, report.ConfigSHA256 = other, other
		},
		"a report older than the maximum age": func(_ *testing.T, _ *testRunner, report *Report) {
			report.GeneratedAt = runnerNow.Add(-MaxReportAge - time.Second)
		},
		"a report that already claims a publication": func(t *testing.T, runner *testRunner, report *Report) {
			// The document an apply wrote out carries its outcomes, so an operator
			// applying that file again hands the apply a report that already says
			// published. The lock below stops it, and the stale claim must not survive
			// the refusal.
			report.Outcome = OutcomePublished
			report.Groups[0].Outcome = OutcomePublished
			t.Cleanup(holdLockInAnotherProcess(t, runner.lockPath))
		},
		// The gates under the lock, which is where the per-group outcomes are
		// recorded and therefore where the mislabel lived.
		"a control lock another process holds": func(t *testing.T, runner *testRunner, _ *Report) {
			t.Cleanup(holdLockInAnotherProcess(t, runner.lockPath))
		},
		"a selector pinned by hand": func(t *testing.T, runner *testRunner, _ *Report) {
			selector := mustSelector(t, 4, "104.16.1.1", "")
			selector.Mode = "manual"
			writeSelector(t, runner.selectorPath, selector)
		},
		"a selector document it cannot parse": func(t *testing.T, runner *testRunner, _ *Report) {
			if err := os.WriteFile(runner.selectorPath, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a winner that will not serve its own profile": func(_ *testing.T, runner *testRunner, _ *Report) {
			// The winner answers the run's proof and is refused by the apply's, which
			// is the shape of a host that stopped serving between the two.
			runner.prober.(*fakeProber).fixtures["104.16.0.1"].identityCallsBeforeFailure = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixtures, candidates := threeGlobals()
			runner := newTestRunner(t, newFakeProber(fixtures))
			writeSelector(t, runner.selectorPath, mustSelector(t, 4, "104.16.1.1", ""))
			report := mustRunWithIncumbent(t, runner.Runner, candidates, "104.16.1.1")
			// The run decided this report would publish, so the refusal below is the
			// one that has to undo the claim: a gate that fires before the decision
			// cannot mislabel anything, which is why the first four rows above are
			// the weaker half of this case.
			if winner := mustWinner(t, mustGroup(t, report, "cloudflare/")); !winner.SwitchAllowed {
				t.Fatal("the fixture's winner is refused its switch, so this case proves nothing")
			}
			refuse(t, runner, &report)
			// The selector as the refusal will find it: two of the rows above write it,
			// so it cannot be read before them.
			before := string(mustReadSelectorBytes(t, runner.selectorPath))

			applied, published, err := runner.Apply(t.Context(), report, profiles)
			if err == nil {
				t.Fatalf("Apply refused by %s succeeded, want a refusal", name)
			}
			mustSayRefused(t, applied)
			// A refusal returns no selector at all, on the same contract as an
			// all-kept apply: the returned document means "this is what was written",
			// and nothing was.
			if published.WinnerIP != "" || published.Generation != 0 {
				t.Errorf("a refused apply returned the selector %+v, want no selector", published)
			}
			// The decision is still readable. An operator's question on a refusal is
			// which group was about to be published, and the group entry keeps its
			// candidates, its winner and the switch verdict the run reached.
			if winner := mustWinner(t, mustGroup(t, applied, "cloudflare/")); winner.IP != "104.16.0.1" {
				t.Errorf("the refused report names the winner %q, want the 104.16.0.1 it had decided on", winner.IP)
			}
			if got := string(mustReadSelectorBytes(t, runner.selectorPath)); got != before {
				t.Errorf("a refused apply changed the selector:\nbefore: %s\nafter:  %s", before, got)
			}
		})
	}
}
