package dhcp_forward

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"mosdns-router/internal/state"
	"mosdns-router/internal/testdns"
)

// The policy values are spelled as the configuration file spells them, not
// through this package's own constants, so a renamed constant cannot make a
// test agree with a renderer that no longer accepts what a policy file says.
const (
	disableCurrent = "disable-current"
	useLastGood    = "use-last-good"
)

// retainedGenerationAge is how old a retained generation is when the test that
// watches the log publishes it. It is a literal so the logged age is checked
// against an instant this test chose rather than against the clock.
const retainedGenerationAge = 90 * time.Second

// newObservedForward builds a plugin the way newTestForward does, with a logger
// whose output the test can read. A policy decision is reported once and never
// per query, which is only checkable when the report is counted.
func newObservedForward(t *testing.T, args Args, upstreams []string, port uint16) (*Forward, *testState, *observer.ObservedLogs) {
	t.Helper()
	if args.StateFile == "" {
		args.StateFile = filepath.Join(t.TempDir(), "dhcp-upstreams.json")
	}
	core, recorded := observer.New(zap.DebugLevel)
	published := &testState{t: t, path: args.StateFile}
	published.publish(1, upstreams...)
	forward, err := newForwardWithState(args, zap.New(core), published.read, port)
	if err != nil {
		t.Fatalf("build the plugin: %v", err)
	}
	t.Cleanup(func() { _ = forward.Close() })
	return forward, published, recorded
}

// publishObserved publishes a document whose observed_at is an instant this
// test chose, because the age a retained generation is reported with is derived
// from that instant and from nothing else.
func (s *testState) publishObserved(generation uint64, observedAt time.Time, lastGood bool, upstreams ...string) {
	s.t.Helper()
	s.mu.Lock()
	s.current = state.NewDHCPState(generation, testInterface, "uuid", upstreams, observedAt, "dhcp4", lastGood)
	s.mu.Unlock()
	writeStateDocument(s.t, s.path, s.current)
	s.setModified()
}

// TestUseLastGoodKeepsTheLastGenerationThatHadAnUpstream pins the whole point of
// the policy. A lease that renews without naming any resolver is a real event,
// and adopting it would take the domestic branch down while a generation that
// does answer is already in hand. The break it catches is a reload that adopts
// the empty generation anyway, which every foreign query's SERVFAIL and every
// domestic lookup's failure would follow from.
func TestUseLastGoodKeepsTheLastGenerationThatHadAnUpstream(t *testing.T) {
	answering := startServer(t, answerWith("192.0.2.81", 300))
	successor := samePortServer(t, answering, "127.0.0.2", answerWith("198.51.100.81", 300))
	forward, published, _ := newObservedForward(t, Args{FailurePolicy: useLastGood}, []string{hostOf(t, answering)}, portOf(t, answering))

	if got := answersOf(t, exec(t, forward, "cn-first.example.cn.", dns.TypeA)); len(got) != 1 || got[0] != "192.0.2.81" {
		t.Fatalf("answers = %v, want the generation 1 answer [192.0.2.81]", got)
	}

	// A newer generation that names no resolver at all.
	published.publish(2)

	if got := answersOf(t, exec(t, forward, "cn-after-empty.example.cn.", dns.TypeA)); len(got) != 1 || got[0] != "192.0.2.81" {
		t.Fatalf("answers = %v, want the retained generation's answer [192.0.2.81]", got)
	}
	if count := answering.Count(testdns.ProtocolUDP, "cn-after-empty.example.cn."); count != 1 {
		t.Fatalf("the retained generation's upstream received %d queries, want 1", count)
	}

	// A retained generation is not a permanent one: the next usable generation
	// is still adopted, so a real DNS change is not held back by the policy.
	published.publish(3, hostOf(t, successor))
	if got := answersOf(t, exec(t, forward, "cn-after-new.example.cn.", dns.TypeA)); len(got) != 1 || got[0] != "198.51.100.81" {
		t.Fatalf("answers = %v, want the generation 3 answer [198.51.100.81]", got)
	}
}

// retainedGenerationReports returns the fields of every report the runtime made
// about a generation it kept serving. A policy decision has to be countable, so
// it is counted by what it reports rather than by the words it reports it with.
func retainedGenerationReports(recorded *observer.ObservedLogs) []map[string]any {
	var reports []map[string]any
	for _, entry := range recorded.All() {
		fields := entry.ContextMap()
		if _, kept := fields["retained_generation"]; kept {
			reports = append(reports, fields)
		}
	}
	return reports
}

// TestUseLastGoodReportsTheRetainedGenerationAndItsAgeExactlyOnce covers what an
// operator has to be able to answer from the log: that the branch is still
// serving a generation this old because the newest one named no resolver. A
// report repeated per query turns one DHCP event into a log flood, and a report
// without the age cannot be acted on.
func TestUseLastGoodReportsTheRetainedGenerationAndItsAgeExactlyOnce(t *testing.T) {
	answering := startServer(t, answerWith("192.0.2.82", 300))
	forward, published, recorded := newObservedForward(t, Args{FailurePolicy: useLastGood}, []string{hostOf(t, answering)}, portOf(t, answering))

	observedAt := time.Now().Add(-retainedGenerationAge).UTC().Truncate(time.Second)
	published.publishObserved(4, observedAt, true, hostOf(t, answering))
	exec(t, forward, "cn-observed.example.cn.", dns.TypeA)

	published.publish(5)
	for range 3 {
		exec(t, forward, "cn-repeated.example.cn.", dns.TypeA)
	}

	reports := retainedGenerationReports(recorded)
	if len(reports) != 1 {
		t.Fatalf("the runtime reported %d retained generations, want exactly one: the decision is made once per published generation, not once per query: %+v", len(reports), reports)
	}
	fields := reports[0]
	if got, ok := fields["retained_generation"].(uint64); !ok || got != 4 {
		t.Errorf("retained_generation = %v, want 4", fields["retained_generation"])
	}
	if got, ok := fields["observed_at"].(time.Time); !ok || !got.Equal(observedAt) {
		t.Errorf("observed_at = %v, want the instant the retained generation was published, %s", fields["observed_at"], observedAt)
	}
	age, ok := fields["age"].(time.Duration)
	if !ok {
		t.Fatalf("the report carries no age: %+v", fields)
	}
	// The age has to come from the retained generation's observed_at. An age
	// taken from when the decision was made, or from the file's timestamp, is
	// near zero and is exactly what a stale generation must not report.
	if age < retainedGenerationAge || age >= retainedGenerationAge+time.Second {
		t.Errorf("age = %v, want the %v the retained generation was observed ago", age, retainedGenerationAge)
	}

	// More queries change nothing: the decision was already made.
	for range 3 {
		exec(t, forward, "cn-repeated-again.example.cn.", dns.TypeA)
	}
	if repeated := retainedGenerationReports(recorded); len(repeated) != 1 {
		t.Fatalf("later queries produced %d reports, want the same one: %+v", len(repeated), repeated)
	}

	// A second empty generation is a second decision, and is reported as one:
	// a report suppressed after the first would hide a branch that has been
	// serving a stale generation ever since.
	published.publish(6)
	exec(t, forward, "cn-after-second.example.cn.", dns.TypeA)
	if later := retainedGenerationReports(recorded); len(later) != 2 {
		t.Fatalf("a second empty generation produced %d reports, want 2: %+v", len(later), later)
	}
}

// TestDisableCurrentAdoptsAnEmptyGenerationAndReportsNothing is the other half
// of the policy pair, and the default. The newest published state is the truth
// about the network, so an empty one disables the branch; and because nothing is
// retained there is no retained generation whose age could be reported.
func TestDisableCurrentAdoptsAnEmptyGenerationAndReportsNothing(t *testing.T) {
	answering := startServer(t, answerWith("192.0.2.83", 300))
	forward, published, recorded := newObservedForward(t, Args{FailurePolicy: disableCurrent}, []string{hostOf(t, answering)}, portOf(t, answering))

	exec(t, forward, "cn-working.example.cn.", dns.TypeA)
	published.publish(2)

	qCtx := newQueryContext("cn-disabled.example.cn.", dns.TypeA)
	if err := forward.Exec(t.Context(), qCtx); err == nil {
		t.Fatal("Exec returned no error for a generation the policy was told to adopt")
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none: the branch fails closed", response)
	}
	if count := answering.Count("", "cn-disabled.example.cn."); count != 0 {
		t.Fatalf("the replaced upstream received %d queries, want 0", count)
	}
	if reports := retainedGenerationReports(recorded); len(reports) != 0 {
		t.Fatalf("adopting an empty generation reported %+v, want no retained generation", reports)
	}
}

// TestUseLastGoodAdoptsTheFirstEmptyGenerationBecauseNothingCanBeRetained
// covers the branch that keeps the policy from refusing the only generation
// there is. With nothing in hand there is no last good set to keep serving, and
// a plugin that refused it would report no generation at all rather than a
// disabled one.
func TestUseLastGoodAdoptsTheFirstEmptyGenerationBecauseNothingCanBeRetained(t *testing.T) {
	answering := startServer(t, answerWith("192.0.2.84", 300))
	forward, published, recorded := newObservedForward(t, Args{FailurePolicy: useLastGood}, nil, portOf(t, answering))

	qCtx := newQueryContext("cn-first-generation.example.cn.", dns.TypeA)
	err := forward.Exec(t.Context(), qCtx)
	if !errors.Is(err, errDisabled) {
		t.Fatalf("Exec error = %v, want the adopted empty generation's %v", err, errDisabled)
	}
	if response := qCtx.R(); response != nil {
		t.Fatalf("response = %v, want none", response)
	}
	if reports := retainedGenerationReports(recorded); len(reports) != 0 {
		t.Fatalf("adopting the first generation reported %+v, want none: nothing was retained", reports)
	}

	published.publish(2, hostOf(t, answering))
	if got := answersOf(t, exec(t, forward, "cn-enabled.example.cn.", dns.TypeA)); len(got) != 1 || got[0] != "192.0.2.84" {
		t.Fatalf("answers = %v, want [192.0.2.84] once a generation names an upstream", got)
	}
}

// TestAnUnknownFailurePolicyIsRefusedAtPluginInit covers the value the policy
// file could carry and this plugin does not implement. A typo in a safety switch
// must stop the router rather than be treated as one of the two behaviours.
func TestAnUnknownFailurePolicyIsRefusedAtPluginInit(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dhcp-upstreams.json")
	read := staticState(state.NewDHCPState(1, testInterface, "uuid", []string{"192.0.2.40"}, time.Unix(0, 0).UTC(), "dhcp4", true))

	if _, err := newForwardWithState(Args{StateFile: stateFile, FailurePolicy: useLastGood}, zap.NewNop(), read, 53); err != nil {
		t.Fatalf("the documented use-last-good policy was rejected: %v", err)
	}

	for name, policy := range map[string]string{
		"another word":          "keep-forever",
		"a different case":      "Use-Last-Good",
		"a value with a space":  "use-last-good ",
		"a bare true":           "true",
		"an unconfigured value": "0",
	} {
		args := Args{StateFile: stateFile, FailurePolicy: policy}
		if _, err := newForwardWithState(args, zap.NewNop(), read, 53); err == nil {
			t.Fatalf("%s failure_policy %q was accepted, want it refused at init", name, policy)
		}
	}
}

// TestAnUnknownFailurePolicyStopsTheConfigFromLoading is the same refusal seen
// from where an operator meets it. A safety switch the router does not implement
// has to fail the load that names it, not reach the first query.
func TestAnUnknownFailurePolicyStopsTheConfigFromLoading(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "dhcp-upstreams.json")

	forward, err := forwardFromConfigArgs(t, map[string]any{"state_file": stateFile, "failure_policy": useLastGood})
	if err != nil {
		t.Fatalf("mosdns refused the documented use-last-good policy: %v", err)
	}
	if forward.rt.failurePolicy != useLastGood {
		t.Fatalf("loaded failure policy = %q, want %q", forward.rt.failurePolicy, useLastGood)
	}

	if loaded, err := forwardFromConfigArgs(t, map[string]any{"state_file": stateFile, "failure_policy": "disable-everything"}); err == nil {
		t.Fatalf("mosdns loaded a plugin configured to %q", loaded.rt.failurePolicy)
	}
}
