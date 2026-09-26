package optimizer

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/prober"
)

// The measurements in this file are literals, and every expectation is a
// hand-derived literal rather than a number the production code produced. That
// is the only way a wrong percentile, a wrong tie-break, a cross-group leak, a
// threshold boundary or a duplicated union member can be caught: a number
// copied out of the implementation passes no matter what the implementation
// does.
//
// The group is the core invariant. Every global Cloudflare candidate competes
// in one group and every CloudFront hostname competes in its own, so a
// CloudFront address can never be compared with a global one and a winner
// proved for one hostname can never be published for another.

// The measurement types are named here through the prober, not through
// internal/measure, and the declarations below say so at compile time: a value
// the runner builds from a probe's result has to go straight into a
// CandidateResult, and a fixture that had to convert one would not be the same
// fixture the runner has.
var (
	_ prober.TCPMetrics      = CandidateResult{}.TCP
	_ prober.HTTPMetrics     = CandidateResult{}.HTTP
	_ prober.DownloadMetrics = CandidateResult{}.Download
	_                        = prober.TCPMetrics{}
)

// mib is the unit the budget's own tests use for the same package.
var (
	// documentedWeights is the brief's 0.45/0.45/0.10, spelled here rather
	// than read from a constant: a test that read the production constant would
	// pass whatever it was changed to.
	documentedWeights = Weights{Latency: 0.45, Bandwidth: 0.45, Stability: 0.10}
	// evenWeights is 0.50/0.25/0.25, used where a tie needs the stability step
	// to be a whole 2500 rather than 1000.
	evenWeights = Weights{Latency: 0.50, Bandwidth: 0.25, Stability: 0.25}
	// tightLimits refuse the two candidates the twelve-candidate fixture puts
	// over the line: 104.16.10.1 at 5% loss and 104.16.11.1 at a p50 of 32ms.
	tightLimits = Limits{MaxLoss: 0.02, MaxP50MS: 30}
	// noLimits sets no ceiling at all. The rule about a candidate with no
	// successful sample still applies, because that candidate has no latency to
	// rank.
	noLimits = Limits{}
)

// measured builds one result. Only BytesPerSecond of the transfer is read by
// the scoring functions, so Elapsed is derived from the same speed rather than
// left to disagree with it.
func measured(provider candidate.Provider, hostname, address string, samples int, p50, p95, jitter, loss, bytesPerSecond float64) CandidateResult {
	const bodyBytes = 10 << 20
	result := CandidateResult{
		Candidate: candidate.Candidate{
			Provider: provider,
			IP:       netip.MustParseAddr(address),
			Source:   candidate.SourceCloudflare,
			Hostname: hostname,
		},
		TCP: prober.TCPMetrics{Samples: samples, P50MS: p50, P95MS: p95, JitterMS: jitter, Loss: loss},
	}
	if bytesPerSecond > 0 {
		result.Download = prober.DownloadMetrics{
			Bytes:          bodyBytes,
			Elapsed:        time.Duration(float64(bodyBytes) / bytesPerSecond * float64(time.Second)),
			BytesPerSecond: bytesPerSecond,
		}
	}
	return result
}

// twelveGlobals is the brief's fixture: twelve global Cloudflare candidates with
// controlled p50, p95, jitter, loss and speed.
//
//	#   address         samples  p50  p95  jitter  loss   speed
//	1   104.16.0.1      10       10   20   1      0.00    5 MB/s
//	2   104.16.1.1      10       12   22   2      0.00    4 MB/s
//	3   104.16.2.1      10       14   24   3      0.00   12 MB/s
//	4   104.16.3.1      10       16   26   4      0.00    3 MB/s
//	5   104.16.4.1      10       18   28   5      0.00    9 MB/s
//	6   104.16.5.1      10       20   30   6      0.00    7 MB/s
//	7   104.16.6.1      10       22   32   7      0.00    2 MB/s
//	8   104.16.7.1      10       24   34   8      0.00    8 MB/s
//	9   104.16.8.1      10       26   36   9      0.00    1 MB/s
//	10  104.16.9.1      10       28   38   10     0.00   10 MB/s
//	11  104.16.10.1     10       30   40   11     0.05    0.5 MB/s
//	12  104.16.11.1     10       32   42   12     0.00   11 MB/s
func twelveGlobals() []CandidateResult {
	return []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 12, 22, 2, 0.00, 4*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 14, 24, 3, 0.00, 12*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.3.1", 10, 16, 26, 4, 0.00, 3*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.4.1", 10, 18, 28, 5, 0.00, 9*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.5.1", 10, 20, 30, 6, 0.00, 7*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.6.1", 10, 22, 32, 7, 0.00, 2*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.7.1", 10, 24, 34, 8, 0.00, 8*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.8.1", 10, 26, 36, 9, 0.00, 1*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.9.1", 10, 28, 38, 10, 0.00, 10*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.10.1", 10, 30, 40, 11, 0.05, 0.5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.11.1", 10, 32, 42, 12, 0.00, 11*mib),
	}
}

func addressesOf(results []CandidateResult) []string {
	addresses := make([]string, 0, len(results))
	for _, result := range results {
		addresses = append(addresses, result.Candidate.IP.String())
	}
	return addresses
}

func equalAddresses(t *testing.T, label string, got []CandidateResult, want []string) {
	t.Helper()
	if slices.Equal(addressesOf(got), want) {
		return
	}
	t.Fatalf("%s = %v, want %v", label, addressesOf(got), want)
}

func byAddress(t *testing.T, group []CandidateResult, address string) CandidateResult {
	t.Helper()
	for _, result := range group {
		if result.Candidate.IP.String() == address {
			return result
		}
	}
	t.Fatalf("the fixture has no %s", address)
	return CandidateResult{}
}

// orderByScore is the ordering Select applies, obtained from Select itself
// rather than restated here. A helper that copied the comparator would pass its
// own expectations whatever the production comparator did, which is exactly the
// mistake the mutation run found: with the comparator copied, removing a term
// from the real one failed nothing. The counts are the whole group, so the
// combined set is the whole group and the scores are the ones the fixtures
// derive by hand.
func orderByScore(group []CandidateResult, weights Weights) []CandidateResult {
	return Select(group, Params{
		LatencyCandidates: len(group),
		LatencyTop:        len(group),
		BandwidthTop:      len(group),
		Weights:           weights,
	}).Scored
}

func reasonOf(t *testing.T, results []CandidateResult, address string) string {
	t.Helper()
	return byAddress(t, results, address).Reason
}

// The group barrier has to hold on every exported function that takes a group,
// not only on the three that take a slice. RankScore and CombinedScore take a
// subject and a group *separately*, so checking the subject is not enough: the
// subject can be a perfectly good member of a slice that also holds another
// hostname's results, and the percentile arithmetic then compares it against
// those foreign results. TenthPercentileSpeed takes a group alone and was
// reporting a percentile across a mixed set.
//
// The reproduction is the one in the review: a global Cloudflare candidate that
// *is* a member of a slice which also carries a CloudFront candidate for another
// hostname, twenty times faster.
func TestScoreAMixedGroupIsRefusedByEveryExportedFunctionThatTakesAGroup(t *testing.T) {
	global := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib)
	global2 := measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 40, 60, 9, 0.10, 1*mib)
	foreign := measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.1", 10, 1, 5, 0.1, 0.00, 20*mib)
	params := Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Weights: documentedWeights}

	for name, mixed := range map[string][]CandidateResult{
		"the foreign result last":    {global, global2, foreign},
		"the foreign result first":   {foreign, global, global2},
		"the foreign result between": {global, foreign, global2},
		"one of each":                {global, foreign},
	} {
		// The subject is a member of the slice in every case, so the membership
		// check cannot be what refuses it: only the group barrier can.
		if got := RankScore(global, mixed, documentedWeights); got != 0 {
			t.Errorf("%s: RankScore of a member of a mixed group = %d, want 0", name, got)
		}
		if got := RankScore(global2, mixed, documentedWeights); got != 0 {
			t.Errorf("%s: RankScore of the other member of a mixed group = %d, want 0", name, got)
		}
		if got := RankScore(foreign, mixed, documentedWeights); got != 0 {
			t.Errorf("%s: RankScore of the foreign member of a mixed group = %d, want 0", name, got)
		}
		if got := CombinedScore(global, mixed, documentedWeights); got != 0 {
			t.Errorf("%s: CombinedScore of a member of a mixed group = %v, want 0", name, got)
		}
		if got := TenthPercentileSpeed(mixed); got != 0 {
			t.Errorf("%s: the p10 speed of a mixed group = %v, want 0", name, got)
		}
		// The three slice entry points already refused the whole slice; they are
		// here so that this test is the one place that states the whole barrier.
		if ranking := RankLatency(mixed, 3, noLimits); len(ranking.Ranked) != 0 {
			t.Errorf("%s: RankLatency ranked %v from a mixed group", name, addressesOf(ranking.Ranked))
		}
		if ranking := RankBandwidth(mixed, 3, noLimits); len(ranking.Ranked) != 0 {
			t.Errorf("%s: RankBandwidth ranked %v from a mixed group", name, addressesOf(ranking.Ranked))
		}
		selection := Select(mixed, params)
		if len(selection.Scored) != 0 {
			t.Errorf("%s: Select scored %v from a mixed group", name, addressesOf(selection.Scored))
		}
		// A zero score is the one the switch gate refuses, so even a caller that
		// ignored the return value cannot publish a mixed-group number.
		if SwitchAllowed(CombinedScore(global, mixed, documentedWeights), 3.65, 10) {
			t.Errorf("%s: a mixed group's score was accepted by the switch gate", name)
		}
		if SwitchAllowed(float64(RankScore(global, mixed, documentedWeights)), 0, 10) {
			t.Errorf("%s: a mixed group's score won against no incumbent", name)
		}
	}

	// The same subject against its own group scores exactly what it scored
	// before, so the barrier refuses the mixed slice and nothing else. A group
	// of two: 4500*2 + 4500*2 + 1000*2 = 20000, and the worse candidate
	// 4500*1 + 4500*1 + 1000*1 = 10000.
	own := []CandidateResult{global, global2}
	if got, want := RankScore(global, own, documentedWeights), 20000; got != want {
		t.Errorf("RankScore inside one group = %d, want %d", got, want)
	}
	if got, want := CombinedScore(global, own, documentedWeights), 2.0; got != want {
		t.Errorf("CombinedScore inside one group = %v, want %v", got, want)
	}
	if got, want := RankScore(global2, own, documentedWeights), 10000; got != want {
		t.Errorf("the other candidate's RankScore inside one group = %d, want %d", got, want)
	}
	// One candidate's p10 speed is that candidate's speed, whatever convention
	// the percentile uses, so this assertion does not move with the p10 fix.
	if got, want := TenthPercentileSpeed(own[:1]), 5.0*mib; got != want {
		t.Errorf("the p10 speed of a group of one = %v, want %v", got, want)
	}
	// A group of one hostname's results is still one group, and the barrier does
	// not fire on it.
	perHost := []CandidateResult{
		measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.1", 10, 2, 5, 0.1, 0.00, 20*mib),
		measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.2", 10, 30, 50, 5, 0.10, 2*mib),
	}
	if got := RankScore(perHost[0], perHost, documentedWeights); got == 0 {
		t.Error("a CloudFront candidate scored zero inside its own hostname's group")
	}
	if got := TenthPercentileSpeed(perHost); got == 0 {
		t.Error("a CloudFront group of one hostname reported a p10 speed of zero")
	}
}

// The group key is one named type with one constructor, so no call site can
// spell "provider plus hostname" as a string and get it subtly wrong.
func TestScoreTheGroupKeyNamesTheProviderAndTheHostname(t *testing.T) {
	global := GroupOf(candidate.Candidate{Provider: candidate.ProviderCloudflare, IP: netip.MustParseAddr("104.16.0.1")})
	perHost := GroupOf(candidate.Candidate{Provider: candidate.ProviderCloudFront, Hostname: "a.example.test", IP: netip.MustParseAddr("13.32.0.1")})
	otherHost := GroupOf(candidate.Candidate{Provider: candidate.ProviderCloudFront, Hostname: "b.example.test", IP: netip.MustParseAddr("13.32.1.1")})

	if global.Same(perHost) || global.Same(otherHost) || perHost.Same(otherHost) {
		t.Fatalf("three different groups compare equal: %v %v %v", global, perHost, otherHost)
	}
	if !global.Same(GroupOf(candidate.Candidate{Provider: candidate.ProviderCloudflare, IP: netip.MustParseAddr("198.16.0.1")})) {
		t.Error("two global Cloudflare candidates are in different groups, want the same one")
	}
	if !perHost.Same(GroupOf(candidate.Candidate{Provider: candidate.ProviderCloudFront, Hostname: "a.example.test", IP: netip.MustParseAddr("13.32.9.9")})) {
		t.Error("one hostname's candidates are in two groups, want one")
	}
	if got, want := global.String(), "cloudflare/"; got != want {
		t.Errorf("the global group renders as %q, want %q", got, want)
	}
	if got, want := perHost.String(), "cloudfront/a.example.test"; got != want {
		t.Errorf("the per-hostname group renders as %q, want %q", got, want)
	}
}

// The cross-group leak, in both directions. The CloudFront candidate is twenty
// times faster, 2ms of p50 and a tenth of the loss of the best Cloudflare one,
// and it must still never appear in the global ranking, and the best Cloudflare
// one must never appear in a CloudFront one.
func TestScoreRanksEachCandidateOnlyInsideItsOwnProviderAndHostnameGroup(t *testing.T) {
	global := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 40, 60, 8, 0.40, 1*mib)
	global2 := measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 80, 90, 12, 0.50, 0.5*mib)
	frontA := measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.1", 10, 2, 5, 0.1, 0.00, 20*mib)
	frontA2 := measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.2", 10, 30, 50, 5, 0.10, 2*mib)
	frontB := measured(candidate.ProviderCloudFront, "b.example.test", "13.32.1.1", 10, 4, 8, 0.2, 0.00, 18*mib)
	frontB2 := measured(candidate.ProviderCloudFront, "b.example.test", "13.32.1.2", 10, 50, 70, 9, 0.20, 1*mib)

	params := Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Weights: documentedWeights}

	globalSelection := Select([]CandidateResult{global, global2}, params)
	equalAddresses(t, "the global selection", globalSelection.Scored, []string{"104.16.0.1", "104.16.1.1"})

	hostA := Select([]CandidateResult{frontA, frontA2}, params)
	equalAddresses(t, "the a.example.test selection", hostA.Scored, []string{"13.32.0.1", "13.32.0.2"})

	hostB := Select([]CandidateResult{frontB, frontB2}, params)
	equalAddresses(t, "the b.example.test selection", hostB.Scored, []string{"13.32.1.1", "13.32.1.2"})

	// The global winner is the worst of everything measured in this test, and
	// the CloudFront winner is the best, yet neither group may show it.
	if got := hostA.Scored[0].Candidate.Hostname; got != "a.example.test" {
		t.Fatalf("the winner of the a.example.test group carries hostname %q", got)
	}
	if got := globalSelection.Scored[0].Candidate.Hostname; got != "" {
		t.Fatalf("the global winner carries hostname %q, want a global candidate", got)
	}
	for _, result := range globalSelection.Scored {
		if result.Candidate.Provider != candidate.ProviderCloudflare {
			t.Fatalf("a %s candidate reached the global selection", result.Candidate.Provider)
		}
	}
	// A per-hostname winner is never copied to another hostname.
	if hostA.Scored[0].Candidate.IP == hostB.Scored[0].Candidate.IP {
		t.Fatal("a.example.test and b.example.test published the same winner")
	}
	for _, result := range hostA.Scored {
		if result.Candidate.Hostname != "a.example.test" {
			t.Fatalf("the a.example.test selection carries a %q candidate", result.Candidate.Hostname)
		}
	}
	for _, result := range hostB.Scored {
		if result.Candidate.Hostname != "b.example.test" {
			t.Fatalf("the b.example.test selection carries a %q candidate", result.Candidate.Hostname)
		}
	}
	// The groups are named on the way out, so a caller cannot mistake one for
	// another when it assembles the report.
	if got, want := globalSelection.Group.String(), "cloudflare/"; got != want {
		t.Errorf("the global selection's group is %q, want %q", got, want)
	}
	if got, want := hostA.Group.String(), "cloudfront/a.example.test"; got != want {
		t.Errorf("the a.example.test selection's group is %q, want %q", got, want)
	}
}

// A slice that mixes groups is refused whole rather than ranked, because
// ranking it is the one operation that would compare a CloudFront address with
// a global one. Nothing is scored, in any order.
func TestScoreRefusesAGroupThatMixesProvidersOrHostnames(t *testing.T) {
	global := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 40, 60, 8, 0.40, 1*mib)
	frontA := measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.1", 10, 2, 5, 0.1, 0.00, 20*mib)
	frontB := measured(candidate.ProviderCloudFront, "b.example.test", "13.32.1.1", 10, 1, 4, 0.1, 0.00, 25*mib)

	for name, mixed := range map[string][]CandidateResult{
		"global first":      {global, frontA, frontB},
		"front first":       {frontA, global, frontB},
		"two of each":       {frontA, frontB, global, global},
		"reversed":          {frontB, frontA, global},
		"one Cloudflare":    {global, frontA},
		"two CloudFronts":   {frontA, frontB, global},
		"all four distinct": {global, global, frontA, frontB},
	} {
		selection := Select(mixed, Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Weights: documentedWeights})
		if len(selection.Scored) != 0 {
			t.Errorf("%s: %d candidates were scored from a mixed group, want none: %v", name, len(selection.Scored), addressesOf(selection.Scored))
		}
		if len(selection.Excluded) != len(mixed) {
			t.Errorf("%s: %d candidates were accounted for, want all %d", name, len(selection.Excluded), len(mixed))
		}
		for _, result := range selection.Excluded {
			if result.Reason != ReasonMixedGroups {
				t.Errorf("%s: %s is excluded with %q, want %q", name, result.Candidate.IP, result.Reason, ReasonMixedGroups)
			}
			if result.Eligible {
				t.Errorf("%s: %s is marked eligible in a mixed group", name, result.Candidate.IP)
			}
		}
		// The rankings a mixed slice produced are empty too, so a caller that
		// reads the shortlist instead of the union also gets nothing.
		if len(selection.Latency.Ranked) != 0 || len(selection.Bandwidth.Ranked) != 0 {
			t.Errorf("%s: a mixed group produced a shortlist: %v", name, selection.Latency.Ranked)
		}
	}
	// The same refusal from the two ranking functions on their own.
	front := measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.1", 10, 2, 5, 0.1, 0.00, 20*mib)
	mixed := []CandidateResult{global, front}
	if ranking := RankLatency(mixed, 2, noLimits); len(ranking.Ranked) != 0 {
		t.Errorf("RankLatency ranked %d candidates from a mixed group", len(ranking.Ranked))
	}
	if ranking := RankBandwidth(mixed, 2, noLimits); len(ranking.Ranked) != 0 {
		t.Errorf("RankBandwidth ranked %d candidates from a mixed group", len(ranking.Ranked))
	}
}

// A subject that is not a member of the group it is being scored against has no
// rank here, and the only answer is zero: a cross-group call can never produce
// a number that could be compared with a score from another group.
func TestScoreRefusesToScoreACandidateAgainstAnotherGroup(t *testing.T) {
	group := []CandidateResult{measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib)}
	outsider := measured(candidate.ProviderCloudFront, "a.example.test", "13.32.0.1", 10, 1, 2, 0.1, 0.00, 40*mib)

	if got := RankScore(outsider, group, documentedWeights); got != 0 {
		t.Errorf("RankScore of an outsider = %d, want 0", got)
	}
	if got := CombinedScore(outsider, group, documentedWeights); got != 0 {
		t.Errorf("CombinedScore of an outsider = %v, want 0", got)
	}
	// The member is scored, and the outsider's far better numbers change nothing.
	if got, want := RankScore(group[0], group, documentedWeights), 10000; got != want {
		t.Errorf("RankScore of the only member = %d, want %d", got, want)
	}
}

// The percentile rank of a group of one is 1 in every metric: there is nothing
// to be better than, and the score of the single candidate is exactly 1.
func TestScoreThePercentileRankOfAGroupOfOneIsOne(t *testing.T) {
	only := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib)
	group := []CandidateResult{only}

	// 4500*1 + 4500*1 + 1000*1, all three firsts of a group of one.
	if got := RankScore(only, group, documentedWeights); got != 10000 {
		t.Errorf("RankScore of a group of one = %d, want 10000", got)
	}
	if got := CombinedScore(only, group, documentedWeights); got != 1.0 {
		t.Errorf("CombinedScore of a group of one = %v, want 1", got)
	}
	// An empty group has no rank at all, and zero is the one score the switch
	// gate refuses.
	if got := CombinedScore(only, nil, documentedWeights); got != 0 {
		t.Errorf("CombinedScore against no group = %v, want 0", got)
	}
	if got := RankScore(only, nil, documentedWeights); got != 0 {
		t.Errorf("RankScore against no group = %d, want 0", got)
	}
}

// Two candidates: the best is rank 1 and the worst is rank 2, so the rank score
// of rank r is (3 - r) and the numbers below follow from 4500/4500/1000.
func TestScoreThePercentileRanksOfATwoCandidateGroup(t *testing.T) {
	fast := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib)
	slow := measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 40, 50, 9, 0.10, 1*mib)
	group := []CandidateResult{fast, slow}

	// fast: 4500*2 + 4500*2 + 1000*2 = 20000.
	if got := RankScore(fast, group, documentedWeights); got != 20000 {
		t.Errorf("RankScore of the better candidate = %d, want 20000", got)
	}
	// slow: 4500*1 + 4500*1 + 1000*1 = 10000.
	if got := RankScore(slow, group, documentedWeights); got != 10000 {
		t.Errorf("RankScore of the worse candidate = %d, want 10000", got)
	}
	if got := CombinedScore(fast, group, documentedWeights); got != 2.0 {
		t.Errorf("CombinedScore of the better candidate = %v, want 2", got)
	}
	if got := CombinedScore(slow, group, documentedWeights); got != 1.0 {
		t.Errorf("CombinedScore of the worse candidate = %v, want 1", got)
	}
	// The same pair the other way round.
	reversed := []CandidateResult{slow, fast}
	if got := RankScore(fast, reversed, documentedWeights); got != 20000 {
		t.Errorf("RankScore of the better candidate in a reversed group = %d, want 20000", got)
	}
}

// Three candidates, two of which tie exactly on p50. The rank of a tie is
// decided by the documented chain and not by the order the group arrived in.
func TestScoreThePercentileRanksOfAThreeCandidateGroupWithTies(t *testing.T) {
	smooth := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib)
	rough := measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 10, 20, 4, 0.00, 5*mib)
	slowest := measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 30, 40, 7, 0.00, 1*mib)

	// p50 ties between smooth and rough. Their loss is equal, so the chain
	// moves to jitter: 1ms against 4ms. So smooth is latency rank 1 and rough
	// rank 2, and the same chain settles their equal speeds.
	// With n = 3 the rank score of rank r is (4 - r):
	//	smooth: 4500*3 + 4500*3 + 1000*3 = 30000
	//	rough:  4500*2 + 4500*2 + 1000*2 = 20000
	//	slowest: 4500*1 + 4500*1 + 1000*1 = 10000
	for name, group := range map[string][]CandidateResult{
		"as written":      {smooth, rough, slowest},
		"tied pair apart": {rough, slowest, smooth},
		"slowest first":   {slowest, rough, smooth},
	} {
		for address, want := range map[string]int{
			"104.16.0.1": 30000,
			"104.16.1.1": 20000,
			"104.16.2.1": 10000,
		} {
			if got := RankScore(byAddress(t, group, address), group, documentedWeights); got != want {
				t.Errorf("%s: %s RankScore = %d, want %d", name, address, got, want)
			}
		}
		equalAddresses(t, "the latency order of a p50 tie in "+name, orderByScore(group, documentedWeights), []string{
			"104.16.0.1", "104.16.1.1", "104.16.2.1",
		})
	}

	// A group of three where all three tie on everything the latency ranking
	// reads: the address decides, and the p95 it never reads cannot.
	alpha := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 90, 1, 0.00, 5*mib)
	beta := measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 10, 20, 1, 0.00, 5*mib)
	gamma := measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 10, 20, 1, 0.00, 5*mib)
	allTied := []CandidateResult{beta, gamma, alpha}
	equalAddresses(t, "the latency order of a three-way tie", orderByScore(allTied, documentedWeights), []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1",
	})
	equalAddresses(t, "the latency ranking of a three-way tie", RankLatency(allTied, 3, noLimits).Ranked, []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1",
	})
}

// The ranks are positions in the group's ordering, so they cannot depend on the
// order the caller happened to assemble the slice in. This is the guarantee
// that no Go map iteration order can reach a published winner.
func TestScoreTheRanksDoNotDependOnTheOrderTheGroupArrivedIn(t *testing.T) {
	forward := twelveGlobals()
	reversed := slices.Clone(forward)
	slices.Reverse(reversed)
	shuffled := []CandidateResult{forward[5], forward[0], forward[11], forward[3], forward[9], forward[1], forward[7], forward[2], forward[10], forward[4], forward[8], forward[6]}

	params := Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Limits: tightLimits, Weights: documentedWeights}
	want := Select(forward, params)

	for name, group := range map[string][]CandidateResult{"reversed": reversed, "shuffled": shuffled} {
		got := Select(group, params)
		equalAddresses(t, "the selection from a "+name+" group", got.Scored, addressesOf(want.Scored))
		equalAddresses(t, "the exclusions from a "+name+" group", got.Excluded, addressesOf(want.Excluded))
		equalAddresses(t, "the latency shortlist from a "+name+" group", got.Latency.Ranked, addressesOf(want.Latency.Ranked))
		equalAddresses(t, "the bandwidth shortlist from a "+name+" group", got.Bandwidth.Ranked, addressesOf(want.Bandwidth.Ranked))
		for index := range want.Scored {
			if got.Scored[index].Score != want.Scored[index].Score {
				t.Errorf("%s: the score of %s = %v, want %v", name, got.Scored[index].Candidate.IP, got.Scored[index].Score, want.Scored[index].Score)
			}
		}
	}
	// The caller's own slice is never reordered by scoring it.
	if !slices.Equal(addressesOf(forward), addressesOf(twelveGlobals())) {
		t.Error("scoring reordered the caller's slice")
	}
}

func TestScoreExcludesCandidatesAboveTheLossLimit(t *testing.T) {
	// 104.16.10.1 is at 5% loss, above the 2% limit, and 104.16.11.1 at a p50
	// of 32ms is above the 30ms one. Every other candidate is inside both.
	ranking := RankLatency(twelveGlobals(), 12, tightLimits)

	if len(ranking.Excluded) != 2 {
		t.Fatalf("%d candidates were excluded, want 2", len(ranking.Excluded))
	}
	for _, result := range ranking.Excluded {
		if result.Eligible {
			t.Errorf("%s is marked eligible", result.Candidate.IP)
		}
		if result.Reason == "" {
			t.Errorf("%s is excluded with no reason", result.Candidate.IP)
		}
	}
	if got := reasonOf(t, ranking.Excluded, "104.16.10.1"); got != ReasonLossAboveLimit {
		t.Errorf("the 5%% loss candidate is refused with %q, want %q", got, ReasonLossAboveLimit)
	}
	if got := reasonOf(t, ranking.Excluded, "104.16.11.1"); got != ReasonLatencyAboveLimit {
		t.Errorf("the 32ms candidate is refused with %q, want %q", got, ReasonLatencyAboveLimit)
	}
	for _, result := range ranking.Ranked {
		if result.TCP.Loss > 0.02 {
			t.Errorf("%s is ranked at %v loss, above the 0.02 limit", result.Candidate.IP, result.TCP.Loss)
		}
	}
	if len(ranking.Ranked) != 10 {
		t.Errorf("%d candidates were ranked, want 10", len(ranking.Ranked))
	}
	// A candidate exactly at the limit is not excluded: the ceiling is
	// inclusive, and 0.02 loss is allowed under a 0.02 limit.
	exact := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.02, 5*mib)
	if ranking := RankLatency([]CandidateResult{exact}, 1, tightLimits); len(ranking.Ranked) != 1 {
		t.Errorf("a candidate exactly at the loss limit was excluded with %q", ranking.Excluded[0].Reason)
	}
	// One part in ten thousand more is excluded.
	over := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.0201, 5*mib)
	if ranking := RankLatency([]CandidateResult{over}, 1, tightLimits); len(ranking.Ranked) != 0 {
		t.Error("a candidate just over the loss limit was ranked")
	}
}

func TestScoreExcludesCandidatesAboveTheLatencyLimit(t *testing.T) {
	// 104.16.10.1 is at a p50 of exactly 30ms, which the inclusive ceiling
	// allows, and 104.16.11.1 at 32ms, which it does not.
	ranking := RankLatency(twelveGlobals(), 12, Limits{MaxLoss: 0.02, MaxP50MS: 31})

	if len(ranking.Excluded) != 2 {
		t.Fatalf("%d candidates were excluded under a 31ms ceiling, want 2", len(ranking.Excluded))
	}
	if got := reasonOf(t, ranking.Excluded, "104.16.11.1"); got != ReasonLatencyAboveLimit {
		t.Errorf("the 32ms candidate is refused with %q, want %q", got, ReasonLatencyAboveLimit)
	}
	if got := reasonOf(t, ranking.Excluded, "104.16.10.1"); got != ReasonLossAboveLimit {
		t.Errorf("the 5%% loss candidate is refused with %q, want %q", got, ReasonLossAboveLimit)
	}
	// A ceiling of exactly 30ms refuses it, and one of 30.0001 does not.
	if got := reasonOf(t, RankLatency(twelveGlobals(), 12, Limits{MaxLoss: 0.02, MaxP50MS: 30}).Excluded, "104.16.11.1"); got != ReasonLatencyAboveLimit {
		t.Errorf("under a 30ms ceiling the 32ms candidate is refused with %q", got)
	}
	under := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 30, 40, 1, 0.00, 5*mib)
	if ranking := RankLatency([]CandidateResult{under}, 1, Limits{MaxP50MS: 30}); len(ranking.Ranked) != 1 {
		t.Error("a candidate exactly at the latency limit was excluded")
	}
	over := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 30.0001, 40, 1, 0.00, 5*mib)
	if ranking := RankLatency([]CandidateResult{over}, 1, Limits{MaxP50MS: 30}); len(ranking.Ranked) != 0 {
		t.Error("a candidate just over the latency limit was ranked")
	}
	// No ceiling at all admits everything that has a sample.
	if ranking := RankLatency(twelveGlobals(), 12, noLimits); len(ranking.Excluded) != 0 {
		t.Errorf("with no ceilings %d candidates were excluded", len(ranking.Excluded))
	}
}

// An address nothing answered has a loss of 1.0 and a p50 of 0ms, so without
// this rule it would rank first on latency. That is the whole point of
// excluding it.
func TestScoreExcludesACandidateWithNoSuccessfulSample(t *testing.T) {
	silent := measured(candidate.ProviderCloudflare, "", "104.16.9.1", 0, 0, 0, 0, 1.0, 0)
	quiet := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib)

	for name, limits := range map[string]Limits{"with ceilings": tightLimits, "with none": noLimits} {
		ranking := RankLatency([]CandidateResult{silent, quiet}, 2, limits)
		equalAddresses(t, "the ranking "+name, ranking.Ranked, []string{"104.16.0.1"})
		if len(ranking.Excluded) != 1 {
			t.Fatalf("%d excluded %s, want 1", len(ranking.Excluded), name)
		}
		if got := ranking.Excluded[0].Reason; got != ReasonNoSample {
			t.Errorf("%s: the reason is %q, want %q", name, got, ReasonNoSample)
		}
		if got := ranking.Excluded[0].Candidate.IP.String(); got != "104.16.9.1" {
			t.Errorf("%s: the excluded candidate is %s, want the silent one", name, got)
		}
	}
	// A candidate with a sample is never refused for the sample rule, however
	// many attempts it lost.
	lucky := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 1, 500, 500, 0, 0.90, 5*mib)
	if ranking := RankLatency([]CandidateResult{lucky}, 1, noLimits); len(ranking.Ranked) != 1 {
		t.Error("a candidate with one successful sample out of ten was excluded")
	}
}

// The ceilings are parameters, so the caller's numbers are the ones applied and
// a wider limit admits a candidate a narrower one refused.
func TestScoreTheExclusionLimitsAreTheOnesTheCallerPassed(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 50, 60, 9, 0.20, 1*mib),
	}

	narrow := RankLatency(group, 2, Limits{MaxLoss: 0.10, MaxP50MS: 20})
	if len(narrow.Ranked) != 1 {
		t.Errorf("a 0.10/20ms limit left %d candidates, want 1", len(narrow.Ranked))
	}
	// The lossy candidate is refused for its loss, which is checked first: an
	// address that drops packets is out whatever its latency.
	if got := narrow.Excluded[0].Reason; got != ReasonLossAboveLimit {
		t.Errorf("the 50ms candidate is refused with %q, want the loss reason", got)
	}

	wide := RankLatency(group, 2, Limits{MaxLoss: 0.25, MaxP50MS: 60})
	if len(wide.Ranked) != 2 {
		t.Errorf("a 0.25/60ms limit left %d candidates, want 2", len(wide.Ranked))
	}
	// Latency only, with the loss ceiling high enough to let the candidate in.
	latencyOnly := RankLatency(group, 2, Limits{MaxP50MS: 20})
	if got := latencyOnly.Excluded[0].Reason; got != ReasonLatencyAboveLimit {
		t.Errorf("with only a latency ceiling the 50ms candidate is refused with %q", got)
	}
	// Loss only.
	lossOnly := RankLatency(group, 2, Limits{MaxLoss: 0.10})
	if got := lossOnly.Excluded[0].Reason; got != ReasonLossAboveLimit {
		t.Errorf("with only a loss ceiling the 0.20 candidate is refused with %q", got)
	}
	// The bandwidth ranking applies the same ceilings, so it cannot be handed a
	// group the latency ranking already refused.
	if ranking := RankBandwidth(group, 2, Limits{MaxLoss: 0.10, MaxP50MS: 20}); len(ranking.Ranked) != 1 {
		t.Errorf("the bandwidth ranking kept %d candidates, want 1", len(ranking.Ranked))
	}
}

// The brief's "top ten latency candidates are selected": twelve measured, all
// inside the ceilings, ten kept, and the two slowest dropped by the cap.
func TestScoreSelectsTheTopTenLatencyCandidatesOfTwelve(t *testing.T) {
	ranking := RankLatency(twelveGlobals(), 10, noLimits)

	if len(ranking.Ranked) != 10 {
		t.Fatalf("%d candidates were kept, want 10", len(ranking.Ranked))
	}
	equalAddresses(t, "the kept candidates", ranking.Ranked, []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1", "104.16.3.1", "104.16.4.1",
		"104.16.5.1", "104.16.6.1", "104.16.7.1", "104.16.8.1", "104.16.9.1",
	})
	// The two dropped are the two slowest and the reason says which rule did it.
	equalAddresses(t, "the dropped candidates", ranking.Excluded, []string{"104.16.10.1", "104.16.11.1"})
	for _, result := range ranking.Excluded {
		if result.Reason != ReasonOutsideLatencyTop {
			t.Errorf("%s is dropped with %q, want %q", result.Candidate.IP, result.Reason, ReasonOutsideLatencyTop)
		}
	}
	// A count of eleven keeps eleven.
	if all := RankLatency(twelveGlobals(), 11, noLimits); len(all.Ranked) != 11 {
		t.Errorf("a count of 11 kept %d candidates, want 11", len(all.Ranked))
	}
	// A count of twelve keeps all twelve and drops nothing.
	if all := RankLatency(twelveGlobals(), 12, noLimits); len(all.Ranked) != 12 || len(all.Excluded) != 0 {
		t.Errorf("a count of 12 kept %d and dropped %d, want 12 and 0", len(all.Ranked), len(all.Excluded))
	}
	// A count of zero ranks nothing rather than handing back the whole group.
	none := RankLatency(twelveGlobals(), 0, noLimits)
	if len(none.Ranked) != 0 {
		t.Errorf("a count of zero kept %d candidates, want 0", len(none.Ranked))
	}
	if len(none.Excluded) != 12 {
		t.Errorf("a count of zero dropped %d candidates, want 12", len(none.Excluded))
	}
	for _, result := range none.Excluded {
		if result.Reason != ReasonOutsideLatencyTop {
			t.Errorf("%s is dropped with %q, want %q", result.Candidate.IP, result.Reason, ReasonOutsideLatencyTop)
		}
	}
	if negative := RankLatency(twelveGlobals(), -1, noLimits); len(negative.Ranked) != 0 {
		t.Errorf("a count of -1 kept %d candidates, want 0", len(negative.Ranked))
	}
}

// The union: latency top three and bandwidth top three, measured once each, in
// a deterministic order. Over the twelve-candidate fixture the two sets share
// 104.16.2.1, so the union has five members and not six.
func TestScoreTheBandwidthTopThreeAndTheLatencyTopThreeFormTheUnion(t *testing.T) {
	params := Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Limits: tightLimits, Weights: documentedWeights}
	selection := Select(twelveGlobals(), params)

	// Latency top three of the ten eligible, by p50: 10ms, 12ms, 14ms.
	equalAddresses(t, "the latency shortlist", selection.Latency.Ranked, []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1", "104.16.3.1", "104.16.4.1",
		"104.16.5.1", "104.16.6.1", "104.16.7.1", "104.16.8.1", "104.16.9.1",
	})
	// Bandwidth top three of those same ten, by speed: 12, 10 and 9 MB/s.
	equalAddresses(t, "the bandwidth shortlist", selection.Bandwidth.Ranked, []string{
		"104.16.2.1", "104.16.9.1", "104.16.4.1",
	})
	// The union, scored and ordered best first by the combined score.
	equalAddresses(t, "the union", selection.Scored, []string{
		"104.16.2.1", "104.16.0.1", "104.16.1.1", "104.16.4.1", "104.16.9.1",
	})
	// 104.16.2.1 is in both halves and appears once.
	occurrences := 0
	for _, result := range selection.Scored {
		if result.Candidate.IP.String() == "104.16.2.1" {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Errorf("the candidate in both halves appears %d times, want 1", occurrences)
	}
	// Every candidate is accounted for exactly once: five scored, seven not.
	if len(selection.Scored)+len(selection.Excluded) != 12 {
		t.Errorf("%d scored plus %d excluded is not the twelve measured", len(selection.Scored), len(selection.Excluded))
	}
	// The refusals are listed in the chain's order, which is a function of the
	// measurements and not of the order the caller assembled the group in, so
	// the two ceilings appear the same way round every run.
	equalAddresses(t, "the excluded candidates", selection.Excluded, []string{
		"104.16.11.1", "104.16.10.1",
		"104.16.3.1", "104.16.5.1", "104.16.6.1", "104.16.7.1", "104.16.8.1",
	})
	if got := reasonOf(t, selection.Excluded, "104.16.10.1"); got != ReasonLossAboveLimit {
		t.Errorf("the 5%% loss candidate is refused with %q", got)
	}
	if got := reasonOf(t, selection.Excluded, "104.16.11.1"); got != ReasonLatencyAboveLimit {
		t.Errorf("the 32ms candidate is refused with %q", got)
	}
	for _, address := range []string{"104.16.3.1", "104.16.5.1", "104.16.6.1", "104.16.7.1", "104.16.8.1"} {
		if got := reasonOf(t, selection.Excluded, address); got != ReasonOutsideCombined {
			t.Errorf("%s is refused with %q, want %q", address, got, ReasonOutsideCombined)
		}
	}
	// A union of one: LatencyTop 1 over a group of one candidate, and the same
	// candidate in both halves.
	single := Select([]CandidateResult{twelveGlobals()[0]}, Params{LatencyCandidates: 10, LatencyTop: 1, BandwidthTop: 1, Limits: tightLimits, Weights: documentedWeights})
	equalAddresses(t, "a union of one", single.Scored, []string{"104.16.0.1"})
	// LatencyTop and BandwidthTop that exceed the group are clamped to it, not
	// padded.
	wide := Select(twelveGlobals()[:3], Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Limits: tightLimits, Weights: documentedWeights})
	if len(wide.Scored) != 3 {
		t.Errorf("a top-3 union over three candidates has %d members, want 3", len(wide.Scored))
	}
	if len(wide.Excluded) != 0 {
		t.Errorf("a top-3 union over three candidates excluded %v", addressesOf(wide.Excluded))
	}
}

// The bandwidth ranking is a ranking inside the latency shortlist, not over
// every candidate, so an address that was never short-listed for latency cannot
// be shortlisted for speed.
func TestScoreTheBandwidthRankingCoversOnlyTheLatencyShortlist(t *testing.T) {
	// The slowest candidate by p50 is also the fastest by speed. If the
	// bandwidth ranking saw the whole group it would rank first; through Select
	// it never enters the shortlist.
	fastButSlow := measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 90, 99, 9, 0.00, 50*mib)
	modest := measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 20, 30, 2, 0.00, 4*mib)
	modestToo := measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 30, 40, 3, 0.00, 3*mib)

	selection := Select([]CandidateResult{fastButSlow, modest, modestToo}, Params{LatencyCandidates: 2, LatencyTop: 2, BandwidthTop: 1, Weights: documentedWeights})

	equalAddresses(t, "the latency shortlist", selection.Latency.Ranked, []string{"104.16.1.1", "104.16.2.1"})
	equalAddresses(t, "the bandwidth shortlist", selection.Bandwidth.Ranked, []string{"104.16.1.1"})
	equalAddresses(t, "the union", selection.Scored, []string{"104.16.1.1", "104.16.2.1"})
	// The fast but slow address is reported as left out, with the rule that
	// left it out named.
	if got := selection.Excluded[0].Candidate.IP.String(); got != "104.16.0.1" {
		t.Fatalf("the excluded candidate is %s, want the fast but slow one", got)
	}
	if got := selection.Excluded[0].Reason; got != ReasonOutsideLatencyTop {
		t.Errorf("its reason is %q, want %q", got, ReasonOutsideLatencyTop)
	}
	// Given the shortlist directly, the bandwidth ranking does rank it first:
	// the nesting is Select's job, not the function's.
	direct := RankBandwidth([]CandidateResult{fastButSlow, modest, modestToo}, 1, noLimits)
	equalAddresses(t, "the bandwidth ranking of the whole group", direct.Ranked, []string{"104.16.0.1"})
}

// The documented weights over the five-member union of the twelve-candidate
// fixture. Every number below is derived by hand: n = 5, so the rank score of
// rank r is (6 - r) and
//
//	score = 4500*(6-latencyRank) + 4500*(6-bandwidthRank) + 1000*(6-stabilityRank)
//
//	address    p50  speed    jitter  latency  bandwidth  stability  integer    score
//	.2.1       14   12 MB/s  3       3        1          3          39000      3.90
//	.0.1       10    5 MB/s  1       1        4          1          36500      3.65
//	.1.1       12    4 MB/s  2       2        5          2          26500      2.65
//	.4.1       18    9 MB/s  5       4        3          4          24500      2.45
//	.9.1       28   10 MB/s 10       5        2          5          23500      2.35
func TestScoreWeightsPointFiveFourFiveFourFiveAndOneTenthProduceTheDocumentedOrder(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 12, 22, 2, 0.00, 4*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 14, 24, 3, 0.00, 12*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.4.1", 10, 18, 28, 5, 0.00, 9*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.9.1", 10, 28, 38, 10, 0.00, 10*mib),
	}
	for address, want := range map[string]int{
		"104.16.0.1": 36500,
		"104.16.1.1": 26500,
		"104.16.2.1": 39000,
		"104.16.4.1": 24500,
		"104.16.9.1": 23500,
	} {
		if got := RankScore(byAddress(t, group, address), group, documentedWeights); got != want {
			t.Errorf("%s: RankScore = %d, want %d", address, got, want)
		}
	}
	for address, want := range map[string]float64{
		"104.16.0.1": 3.65,
		"104.16.1.1": 2.65,
		"104.16.2.1": 3.90,
		"104.16.4.1": 2.45,
		"104.16.9.1": 2.35,
	} {
		if got := CombinedScore(byAddress(t, group, address), group, documentedWeights); got != want {
			t.Errorf("%s: CombinedScore = %v, want %v", address, got, want)
		}
	}
	equalAddresses(t, "the order by integer score", orderByScore(group, documentedWeights), []string{
		"104.16.2.1", "104.16.0.1", "104.16.1.1", "104.16.4.1", "104.16.9.1",
	})
	// The same five candidates reached through Select, in the order the union
	// produced, carry those same scores.
	selection := Select(twelveGlobals(), Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Limits: tightLimits, Weights: documentedWeights})
	for index, want := range []float64{3.90, 3.65, 2.65, 2.45, 2.35} {
		if selection.Scored[index].Score != want {
			t.Errorf("the selection's %s scored %v, want %v", selection.Scored[index].Candidate.IP, selection.Scored[index].Score, want)
		}
	}
}

// Weights that do not sum to one are normalized before they are used, so a
// caller that wrote 0.9/0.9/0.2 gets the same verdict as one that wrote
// 0.45/0.45/0.10.
func TestScoreWeightsThatDoNotSumToOneAreNormalized(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 12, 22, 2, 0.00, 4*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 14, 24, 3, 0.00, 12*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.4.1", 10, 18, 28, 5, 0.00, 9*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.9.1", 10, 28, 38, 10, 0.00, 10*mib),
	}
	for name, weights := range map[string]Weights{
		"the documented 0.45/0.45/0.10":  documentedWeights,
		"doubled to 0.9/0.9/0.2":         {Latency: 0.9, Bandwidth: 0.9, Stability: 0.2},
		"halved to 0.225/0.225/0.05":     {Latency: 0.225, Bandwidth: 0.225, Stability: 0.05},
		"scaled up to 4.5/4.5/1.0":       {Latency: 4.5, Bandwidth: 4.5, Stability: 1.0},
		"in whole points, 45/45/10":      {Latency: 45, Bandwidth: 45, Stability: 10},
		"in thousandths, 4500/4500/1000": {Latency: 4500, Bandwidth: 4500, Stability: 1000},
	} {
		for address, want := range map[string]int{
			"104.16.0.1": 36500, "104.16.1.1": 26500, "104.16.2.1": 39000,
			"104.16.4.1": 24500, "104.16.9.1": 23500,
		} {
			if got := RankScore(byAddress(t, group, address), group, weights); got != want {
				t.Errorf("%s: %s RankScore = %d, want %d", name, address, got, want)
			}
		}
		equalAddresses(t, "the order under "+name, orderByScore(group, weights), []string{
			"104.16.2.1", "104.16.0.1", "104.16.1.1", "104.16.4.1", "104.16.9.1",
		})
	}
	// 0.9/0.45/0.05 is the same ratio as 0.45/0.225/0.025, so it is the same
	// order again: the point is that a caller may write a ratio in any scale.
	// It is not the same ratio as 0.45/0.45/0.10, and it says so in its order.
	uneven := Weights{Latency: 0.9, Bandwidth: 0.45, Stability: 0.05}
	for address, want := range map[string]int{
		"104.16.0.1": 40358, "104.16.2.1": 36428, "104.16.1.1": 30358,
		"104.16.4.1": 23214, "104.16.9.1": 19642,
	} {
		if got := RankScore(byAddress(t, group, address), group, uneven); got != want {
			t.Errorf("%s: an uneven weighting scored %d, want %d", address, got, want)
		}
	}
	equalAddresses(t, "the order under 0.9/0.45/0.05", orderByScore(group, uneven), []string{
		"104.16.0.1", "104.16.2.1", "104.16.1.1", "104.16.4.1", "104.16.9.1",
	})
	// The half-scale form of the same ratio scores identically.
	halfScale := Weights{Latency: 0.45, Bandwidth: 0.225, Stability: 0.025}
	for _, address := range []string{"104.16.0.1", "104.16.2.1", "104.16.1.1", "104.16.4.1", "104.16.9.1"} {
		if got, want := RankScore(byAddress(t, group, address), group, halfScale), RankScore(byAddress(t, group, address), group, uneven); got != want {
			t.Errorf("%s: the half-scale ratio scored %d and the full one %d", address, got, want)
		}
	}
	// A weighting that throws its mass at bandwidth only gives a different
	// order, so the weights are not being ignored.
	speedOnly := Weights{Latency: 0, Bandwidth: 1, Stability: 0}
	if got, want := RankScore(group[0], group, speedOnly), RankScore(group[2], group, speedOnly); got >= want {
		t.Errorf("under a bandwidth-only weighting .0.1 (%d) did not fall behind .2.1 (%d)", got, want)
	}
	// Three equal shares do not divide ten thousand, so the rounding leaves a
	// remainder that has to land somewhere: 1/3 is 3333.333, three of them round
	// to 3333 and sum to 9999. The remainder goes to the first share, so the
	// three shares are 3334/3333/3333 and the total is exactly ten thousand -
	// without that the best possible score of a group of three would be 29997
	// rather than 30000, and every score in the package would be off by a third
	// of a part per ten thousand.
	thirds := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 20, 30, 2, 0.00, 12*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 30, 40, 3, 0.00, 1*mib),
	}
	// A is rank 1 of 3 on latency and 2 on speed: 3334*3 + 3333*2 = 16668.
	// B is rank 2 on latency and 1 on speed: 3334*2 + 3333*3 = 16667.
	// C is rank 3 on both: 3334*1 + 3333*1 = 6667.
	// With 3333/3333/3333 they would be 16665, 16665 and 6666, and A and B would
	// be indistinguishable - which is the whole reason the remainder is placed
	// rather than discarded.
	for address, want := range map[string]int{
		"104.16.0.1": 26667,
		"104.16.1.1": 23333,
		"104.16.2.1": 10000,
	} {
		if got := RankScore(byAddress(t, thirds, address), thirds, Weights{Latency: 1, Bandwidth: 1, Stability: 1}); got != want {
			t.Errorf("%s: an even weighting scored %d, want %d", address, got, want)
		}
	}
	equalAddresses(t, "the order under three equal shares", orderByScore(thirds, Weights{Latency: 1, Bandwidth: 1, Stability: 1}), []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1",
	})
}

// A weighting that cannot be normalized scores nothing, and nothing scored zero
// is ever a winner. A gate that failed open here would rewrite a user's DNS on
// the strength of an unusable policy.
func TestScoreWeightsThatCannotBeNormalizedScoreZeroAndNeverWin(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 12, 22, 2, 0.00, 4*mib),
	}
	for name, weights := range map[string]Weights{
		"all zero":          {},
		"all negative":      {Latency: -1, Bandwidth: -1, Stability: -1},
		"one negative":      {Latency: 0.45, Bandwidth: 0.45, Stability: -0.10},
		"cancelling":        {Latency: 0.5, Bandwidth: -0.5, Stability: 0},
		"not a number":      {Latency: math.NaN(), Bandwidth: 0.45, Stability: 0.10},
		"positive infinity": {Latency: math.Inf(1), Bandwidth: 0.45, Stability: 0.10},
		"negative infinity": {Latency: 0.45, Bandwidth: math.Inf(-1), Stability: 0.10},
	} {
		for _, subject := range group {
			if got := RankScore(subject, group, weights); got != 0 {
				t.Errorf("%s: RankScore = %d, want 0", name, got)
			}
			if got := CombinedScore(subject, group, weights); got != 0 {
				t.Errorf("%s: CombinedScore = %v, want 0", name, got)
			}
		}
		// No incumbent, and a real incumbent: neither may take a zero score.
		if SwitchAllowed(0, 0, 10) {
			t.Errorf("%s: a zero score won against no incumbent", name)
		}
		if SwitchAllowed(0, 3.65, 10) {
			t.Errorf("%s: a zero score beat a real incumbent", name)
		}
		if SwitchAllowed(-1, 0, 10) {
			t.Errorf("%s: a negative score won against no incumbent", name)
		}
		// A selection built with such a weighting scores nothing at all, so the
		// caller has nothing to publish rather than a wrong winner.
		selection := Select(group, Params{LatencyCandidates: 10, LatencyTop: 1, BandwidthTop: 1, Weights: weights})
		for _, result := range selection.Scored {
			if result.Score != 0 {
				t.Errorf("%s: %s was published with the score %v", name, result.Candidate.IP, result.Score)
			}
		}
	}
	// A single negative share makes the whole set unusable rather than being
	// read as a weight of nothing: a weighting that arrived with a negative
	// number is a configuration error, and reinterpreting it would change which
	// address is published. Refusing to score changes nothing.
	if got := RankScore(group[0], group, Weights{Latency: 0.45, Bandwidth: 0.45, Stability: -0.10}); got != 0 {
		t.Errorf("a negative stability weight scored %d, want 0", got)
	}
}

// A different weighting may legitimately order the same candidates
// differently; the weights are the caller's, not a constant buried in here.
func TestScoreDifferentWeightsOrderTheSameCandidatesDifferently(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 5*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 12, 22, 2, 0.00, 4*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 14, 24, 3, 0.00, 12*mib),
	}
	latencyOnly := Weights{Latency: 1, Bandwidth: 0, Stability: 0}
	speedOnly := Weights{Latency: 0, Bandwidth: 1, Stability: 0}

	// Under latency only, the p50 leader is rank 1 of 3: 10000*(3-1+1) = 30000.
	if got, want := RankScore(group[0], group, latencyOnly), 30000; got != want {
		t.Errorf("a latency-only weighting scored the p50 leader %d, want %d", got, want)
	}
	// Under speed only the same candidate is rank 2 of 3: 10000*(3-2+1) = 20000.
	if got, want := RankScore(group[0], group, speedOnly), 20000; got != want {
		t.Errorf("a speed-only weighting scored the p50 leader %d, want %d", got, want)
	}
	equalAddresses(t, "the order under a latency-only weighting", orderByScore(group, latencyOnly), []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1",
	})
	equalAddresses(t, "the order under a speed-only weighting", orderByScore(group, speedOnly), []string{
		"104.16.2.1", "104.16.0.1", "104.16.1.1",
	})
	// A stability-only weighting follows the jitter order.
	stabilityOnly := Weights{Latency: 0, Bandwidth: 0, Stability: 1}
	equalAddresses(t, "the order under a stability-only weighting", orderByScore(group, stabilityOnly), []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1",
	})
	// The same candidate's stability score: rank 1 of 3, weight 10000.
	if got, want := RankScore(group[0], group, stabilityOnly), 30000; got != want {
		t.Errorf("a stability-only weighting scored the smoothest %d, want %d", got, want)
	}
}

// The p10 speed is the group's own tenth percentile of the download speeds, by
// the nearest-rank method the prober's own percentiles use: with n speeds in
// descending order it is the one at index ceil(0.10*n)-1, which for ten
// candidates or fewer is the fastest.
func TestScoreTheTenthPercentileSpeedIsTheNearestRankOfTheGroup(t *testing.T) {
	// Twenty-one strictly decreasing speeds, so the nearest-rank index at each
	// group size lands on a different, named candidate.
	speeds := []float64{
		100, 90, 80, 70, 60, 50, 40, 30, 20, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
		0.5, 0.25,
	}
	var group []CandidateResult
	for index, speed := range speeds {
		group = append(group, measured(candidate.ProviderCloudflare, "", fmt.Sprintf("104.16.%d.1", index), 10, float64(10+index), 20, 1, 0.00, speed*mib))
	}
	for size, want := range map[int]float64{
		0:  0,
		1:  100 * mib, // ceil(0.10) = 1: the only speed
		2:  100 * mib, // ceil(0.20) = 1
		5:  100 * mib, // ceil(0.50) = 1
		10: 100 * mib, // ceil(1.00) = 1
		11: 90 * mib,  // ceil(1.10) = 2
		12: 90 * mib,  // ceil(1.20) = 2
		20: 90 * mib,  // ceil(2.00) = 2
		21: 80 * mib,  // ceil(2.10) = 3
	} {
		if got := TenthPercentileSpeed(group[:size]); got != want {
			t.Errorf("the p10 speed of %d candidates = %v, want %v", size, got, want)
		}
	}
	// The order the speeds arrived in does not matter, because a percentile is
	// a statement about the group's sizes and not about the order of a list.
	// The reversed group still holds all twenty-one candidates, so its p10 is
	// still the third fastest.
	shuffled := slices.Clone(group)
	slices.Reverse(shuffled)
	if got, want := TenthPercentileSpeed(shuffled), float64(80*mib); got != want {
		t.Errorf("the p10 speed of the reversed group = %v, want %v", got, want)
	}
	// A group where nothing was measured reports zero, not a division by zero
	// or the slowest speed.
	if got := TenthPercentileSpeed([]CandidateResult{measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 1, 0.00, 0)}); got != 0 {
		t.Errorf("the p10 speed of one unmeasured candidate = %v, want 0", got)
	}
}

// A combined score can be exactly equal for two candidates that are first and
// second on latency and bandwidth in opposite orders, because the stability
// step is smaller than either. The chain decides, and its first term is loss: the
// candidate that drops 40% of its handshakes loses to one that drops none,
// however rough it is.
//
//	n = 10, rank score of rank r is (11 - r)
//	score = 4500*(11-La) + 4500*(11-Lb) + 1000*(11-S)
//
//	address   p50   speed    jitter  loss   La  Lb  S
//	.0.1 (A)  20    80 MB/s  0.1ms   0.40    2   3   1
//	.1.1 (B)  10    90 MB/s  100ms   0.00    1   2  10
//	.2.1 (C)  30   100 MB/s  10ms    0.00    3   1   2
//	.3.1      40    70 MB/s  20ms    0.00    4   4   3
//	.4.1      50    60 MB/s  30ms    0.00    5   5   4
//	.5.1      60    50 MB/s  40ms    0.00    6   6   5
//	.6.1      70    40 MB/s  50ms    0.00    7   7   6
//	.7.1      80    30 MB/s  60ms    0.00    8   8   7
//	.8.1      90    20 MB/s  70ms    0.00    9   9   8
//	.9.1     100    10 MB/s  80ms    0.00   10  10   9
//
//	A = 4500*9 + 4500*8 + 1000*10 = 40500 + 36000 + 10000 = 86500
//	B = 4500*10 + 4500*9 + 1000*1 = 45000 + 40500 +  1000 = 86500  (equal)
//	C = 4500*8 + 4500*10 + 1000*9 = 36000 + 45000 + 9000 = 90000
func TestScoreEqualCombinedScoresSortByLowerLoss(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 20, 30, 0.1, 0.40, 80*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 10, 20, 100, 0.00, 90*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 30, 40, 10, 0.00, 100*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.3.1", 10, 40, 50, 20, 0.00, 70*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.4.1", 10, 50, 60, 30, 0.00, 60*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.5.1", 10, 60, 70, 40, 0.00, 50*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.6.1", 10, 70, 80, 50, 0.00, 40*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.7.1", 10, 80, 90, 60, 0.00, 30*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.8.1", 10, 90, 99, 70, 0.00, 20*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.9.1", 10, 100, 109, 80, 0.00, 10*mib),
	}
	for address, want := range map[string]int{
		"104.16.0.1": 86500,
		"104.16.1.1": 86500,
		"104.16.2.1": 90000,
		"104.16.3.1": 71000,
		"104.16.4.1": 61000,
		"104.16.5.1": 51000,
		"104.16.6.1": 41000,
		"104.16.7.1": 31000,
		"104.16.8.1": 21000,
		"104.16.9.1": 11000,
	} {
		if got := RankScore(byAddress(t, group, address), group, documentedWeights); got != want {
			t.Errorf("%s: RankScore = %d, want %d", address, got, want)
		}
	}
	// A and B are equal on the score. A loses 40% of its handshakes and B
	// loses none, so the loss term puts B first even though B is a thousand
	// times rougher. Remove the loss term and A would lead on jitter instead,
	// so this assertion is the loss term's own.
	equalAddresses(t, "the score order of an exact tie", orderByScore(group, documentedWeights), []string{
		"104.16.2.1", "104.16.1.1", "104.16.0.1", "104.16.3.1", "104.16.4.1",
		"104.16.5.1", "104.16.6.1", "104.16.7.1", "104.16.8.1", "104.16.9.1",
	})
}

// With the loss equal, the chain moves on to jitter. Two candidates that tie on
// the score and on the loss, where the rougher one has the lower address, are
// separated by the smoother one.
//
//	n = 10, score = 4500*(11-La) + 4500*(11-Lb) + 1000*(11-S)
//	address   p50   speed    jitter  loss   La  Lb  S
//	.0.1 (A)  10   100 MB/s  100ms   0.00    1   1  10
//	.1.1 (B)  20    90 MB/s    1ms   0.00    2   2   1
//	A = 4500*10 + 4500*10 + 1000*1  = 91000
//	B = 4500*9  + 4500*9  + 1000*10 = 91000  (equal)
//	C = 4500*8  + 4500*8  + 1000*9  = 81000, and 71000, 61000 ... 11000
func TestScoreEqualCombinedScoresSortByLowerJitter(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 10, 20, 100, 0.00, 100*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 20, 30, 1, 0.00, 90*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 30, 40, 2, 0.00, 80*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.3.1", 10, 40, 50, 3, 0.00, 70*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.4.1", 10, 50, 60, 4, 0.00, 60*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.5.1", 10, 60, 70, 5, 0.00, 50*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.6.1", 10, 70, 80, 6, 0.00, 40*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.7.1", 10, 80, 90, 7, 0.00, 30*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.8.1", 10, 90, 99, 8, 0.00, 20*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.9.1", 10, 100, 109, 9, 0.00, 10*mib),
	}
	for address, want := range map[string]int{
		"104.16.0.1": 91000,
		"104.16.1.1": 91000,
		"104.16.2.1": 81000,
		"104.16.3.1": 71000,
		"104.16.4.1": 61000,
		"104.16.5.1": 51000,
		"104.16.6.1": 41000,
		"104.16.7.1": 31000,
		"104.16.8.1": 21000,
		"104.16.9.1": 11000,
	} {
		if got := RankScore(byAddress(t, group, address), group, documentedWeights); got != want {
			t.Errorf("%s: RankScore = %d, want %d", address, got, want)
		}
	}
	// A jitters 100ms and B jitters 1ms, and their losses are equal, so only
	// the jitter term can put B first - A has the lower address.
	equalAddresses(t, "the score order of a jitter tie", orderByScore(group, documentedWeights), []string{
		"104.16.1.1", "104.16.0.1", "104.16.2.1", "104.16.3.1", "104.16.4.1",
		"104.16.5.1", "104.16.6.1", "104.16.7.1", "104.16.8.1", "104.16.9.1",
	})
}

// With the score, the loss and the jitter all equal, the last documented term
// is the address. The fixture is written with the higher address first, so a
// chain that stopped before the address term would hand back the wrong pair.
//
//	weights 0.50/0.25/0.25, n = 4, rank score of rank r is (5 - r)
//	score = 5000*(5-La) + 2500*(5-Lb) + 2500*(5-S)
//	address   p50   speed    jitter  loss   La  Lb  S
//	.1.1 (B)  10    90 MB/s   5ms    0.00    1   2   2
//	.0.1 (A)  20   100 MB/s   5ms    0.00    2   1   1
//	.2.1 (C)  30    80 MB/s   6ms    0.10    3   3   3
//	.3.1 (D)  40    70 MB/s   7ms    0.20    4   4   4
//	A = 5000*3 + 2500*4 + 2500*4 = 15000 + 10000 + 10000 = 35000
//	B = 5000*4 + 2500*3 + 2500*3 = 20000 +  7500 +  7500 = 35000  (equal)
//	C = 5000*2 + 2500*2 + 2500*2 = 10000 +  5000 +  5000 = 20000
//	D = 5000*1 + 2500*1 + 2500*1 =  5000 +  2500 +  2500 = 10000
func TestScoreEqualCombinedScoresSortByTheLowerAddress(t *testing.T) {
	group := []CandidateResult{
		measured(candidate.ProviderCloudflare, "", "104.16.1.1", 10, 10, 20, 5, 0.00, 90*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.0.1", 10, 20, 30, 5, 0.00, 100*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.2.1", 10, 30, 40, 6, 0.10, 80*mib),
		measured(candidate.ProviderCloudflare, "", "104.16.3.1", 10, 40, 50, 7, 0.20, 70*mib),
	}
	for address, want := range map[string]int{
		"104.16.0.1": 35000,
		"104.16.1.1": 35000,
		"104.16.2.1": 20000,
		"104.16.3.1": 10000,
	} {
		if got := RankScore(byAddress(t, group, address), group, evenWeights); got != want {
			t.Errorf("%s: RankScore = %d, want %d", address, got, want)
		}
	}
	equalAddresses(t, "the score order of an address tie", orderByScore(group, evenWeights), []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1", "104.16.3.1",
	})
	// The same answer from every other order the group could arrive in, which
	// is the guarantee that a caller's map iteration cannot reach the winner.
	for index, permutation := range [][]CandidateResult{
		{group[3], group[2], group[1], group[0]},
		{group[1], group[3], group[0], group[2]},
		{group[2], group[0], group[3], group[1]},
		{group[3], group[0], group[2], group[1]},
	} {
		equalAddresses(t, fmt.Sprintf("the score order of permutation %d", index), orderByScore(permutation, evenWeights), []string{
			"104.16.0.1", "104.16.1.1", "104.16.2.1", "104.16.3.1",
		})
	}
	// The same four candidates through Select, where the whole group is the
	// combined set and the same chain orders it.
	selection := Select(group, Params{LatencyCandidates: 10, LatencyTop: 4, BandwidthTop: 4, Weights: evenWeights})
	equalAddresses(t, "the selection's union", selection.Scored, []string{
		"104.16.0.1", "104.16.1.1", "104.16.2.1", "104.16.3.1",
	})
	for index, want := range []float64{3.50, 3.50, 2.00, 1.00} {
		if selection.Scored[index].Score != want {
			t.Errorf("the selection's %s scored %v, want %v", selection.Scored[index].Candidate.IP, selection.Scored[index].Score, want)
		}
	}
}

// The switch gate, at the boundary the brief fixes.
//
// The comparison is 100*new >= (100+threshold)*current rather than
// (new-current)/current*100 >= threshold, so the exact-threshold case is defined
// by a multiplication and not by how a subtraction and a division round. 3.3
// over 3.0 is ten percent exactly; the percentage form computes 9.999999999999993
// for it, which would refuse a switch that has reached the threshold.
func TestSwitchAllowsAnImprovementOfExactlyTheThreshold(t *testing.T) {
	for name, table := range map[string]struct {
		newScore      float64
		currentScore  float64
		improvementPc float64
	}{
		"ten percent of ten":       {11.0, 10.0, 10},
		"ten percent of one":       {1.1, 1.0, 10},
		"ten percent of three":     {3.3, 3.0, 10},
		"ten percent of seven":     {7.7, 7.0, 10},
		"ten percent of four":      {4.4, 4.0, 10},
		"ten percent of a hundred": {110.0, 100.0, 10},
		"ten percent of 3.65":      {4.015, 3.65, 10},
		"ten percent of 3.3":       {3.63, 3.3, 10},
		"ten percent of 1.9":       {2.09, 1.9, 10},
		"ten percent of 2.35":      {2.585, 2.35, 10},
		"ten percent of 2.65":      {2.915, 2.65, 10},
		"twenty percent of three":  {3.6, 3.0, 20},
		"a quarter of four":        {5.0, 4.0, 25},
		"half of two":              {3.0, 2.0, 50},
		"a doubling of three":      {6.0, 3.0, 100},
		"well past the threshold":  {12.0, 10.0, 10},
	} {
		if !SwitchAllowed(table.newScore, table.currentScore, table.improvementPc) {
			t.Errorf("%s: %v over %v at %v%% was refused, want accepted", name, table.newScore, table.currentScore, table.improvementPc)
		}
	}
}

func TestSwitchRefusesAnImprovementJustBelowTheThreshold(t *testing.T) {
	for name, table := range map[string]struct {
		newScore      float64
		currentScore  float64
		improvementPc float64
	}{
		"the brief's nine percent":   {10.9, 10.0, 10},
		"9.999 percent":              {109.99, 100.0, 10},
		"just under a tenth":         {3.29, 3.0, 10},
		"one part in a thousand":     {1.0999, 1.0, 10},
		"just under a tenth of 3.65": {3.64, 3.65, 10},
		"just under a quarter":       {4.99, 4.0, 25},
		"just under a doubling":      {5.9, 3.0, 100},
		"just under a fifth":         {3.5, 3.0, 20},
	} {
		if SwitchAllowed(table.newScore, table.currentScore, table.improvementPc) {
			t.Errorf("%s: %v over %v at %v%% was accepted, want refused", name, table.newScore, table.currentScore, table.improvementPc)
		}
	}
	// The boundary itself is accepted, so the pair either side of ten percent
	// on the same incumbent is a boundary and not a rounding accident.
	if SwitchAllowed(109.99, 100.0, 10) {
		t.Error("a 9.999% improvement was accepted")
	}
	if !SwitchAllowed(110, 100.0, 10) {
		t.Error("an improvement of exactly ten percent was refused")
	}
}

func TestSwitchRefusesAChangeThatIsNotAnImprovement(t *testing.T) {
	for name, table := range map[string]struct {
		newScore     float64
		currentScore float64
	}{
		"identical":        {3.65, 3.65},
		"a hundredth less": {3.64, 3.65},
		"half as good":     {1.80, 3.65},
		"a negative score": {-1, 3.65},
		"the worst scored": {1, 12},
	} {
		if SwitchAllowed(table.newScore, table.currentScore, 10) {
			t.Errorf("%s: %v over %v was accepted, want refused", name, table.newScore, table.currentScore)
		}
	}
}

// No incumbent means any candidate that could be scored may take the place, and
// it is decided without dividing by a score that is not there. A zero or a
// negative current score is the "no incumbent" case; a real score is never below
// 1, which the group-of-one case above pins.
func TestSwitchAcceptsAnyScoredCandidateWhenThereIsNoIncumbent(t *testing.T) {
	// A real combined score is never below one, which the group-of-one case
	// pins, so a zero or a negative incumbent can only mean there is no winner.
	for name, incumbent := range map[string]float64{
		"no winner at all": 0,
		"an unset score":   -1,
		"a negative score": -12.5,
	} {
		if !SwitchAllowed(1.0, incumbent, 10) {
			t.Errorf("%s: the lowest scored candidate was refused against %v", name, incumbent)
		}
		if !SwitchAllowed(12.0, incumbent, 10) {
			t.Errorf("%s: the best candidate was refused against %v", name, incumbent)
		}
	}
	// A real incumbent is a real incumbent: a candidate is only accepted against
	// one when it beats it by the threshold, and these are the two ends of the
	// range a real score covers.
	if !SwitchAllowed(1.1, 1.0, 10) {
		t.Error("the lowest scored candidate did not beat the lowest possible incumbent by 10%")
	}
	if !SwitchAllowed(13.2, 12.0, 10) {
		t.Error("the best candidate did not beat the highest possible incumbent by 10%")
	}
	if !SwitchAllowed(1.0000001, 1e-12, 10) {
		t.Error("a candidate did not beat a real but tiny incumbent by 10%")
	}
	if SwitchAllowed(1.0, 1.0, 10) {
		t.Error("a candidate identical to a real incumbent was accepted")
	}
	// A threshold of zero still refuses a candidate that scored nothing, so a
	// policy that switched on "any improvement" cannot adopt a zero score.
	if SwitchAllowed(0, 0, 0) {
		t.Error("a zero score was accepted against no incumbent at a zero threshold")
	}
}

// A candidate that could not be scored is never a winner, with or without an
// incumbent, and a number that is not a finite number is refused rather than
// compared.
func TestSwitchRefusesACandidateThatCouldNotBeScored(t *testing.T) {
	for name, table := range map[string]struct {
		newScore     float64
		currentScore float64
	}{
		"zero, no incumbent":          {0, 0},
		"zero, with an incumbent":     {0, 3.65},
		"negative, no incumbent":      {-0.001, 0},
		"negative, with an incumbent": {-99, 3.65},
		"not a number, no incumbent":  {math.NaN(), 0},
		"not a number, incumbent":     {math.NaN(), 3.65},
		"an infinite score":           {math.Inf(1), 0},
		"an infinite incumbent":       {12, math.Inf(1)},
		"an incumbent that is NaN":    {12, math.NaN()},
	} {
		if SwitchAllowed(table.newScore, table.currentScore, 10) {
			t.Errorf("%s: %v over %v was accepted, want refused", name, table.newScore, table.currentScore)
		}
	}
	// A threshold that is not a number, or a negative one, is refused too: an
	// unreadable policy must not lower the bar.
	if SwitchAllowed(12, 10, math.NaN()) {
		t.Error("a threshold of NaN accepted a switch")
	}
	if SwitchAllowed(12, 10, math.Inf(1)) {
		t.Error("a threshold of infinity accepted a switch")
	}
	if SwitchAllowed(12, 10, -50) {
		t.Error("a negative threshold accepted a switch")
	}
	if !SwitchAllowed(12, 10, 0) {
		t.Error("a threshold of exactly zero refused a strictly better candidate")
	}
}

// The threshold is the policy's number, cdn.switch_improvement_percent, and not
// a constant inside this function.
func TestSwitchUsesTheThresholdThePolicyCarries(t *testing.T) {
	if SwitchAllowed(3.5, 3.0, 20) {
		t.Error("a 16.7% improvement was accepted at a 20% threshold")
	}
	if !SwitchAllowed(3.6, 3.0, 20) {
		t.Error("an improvement of exactly 20% was refused")
	}
	if !SwitchAllowed(3.01, 3.0, 0) {
		t.Error("a 0.33% improvement was refused at a zero threshold")
	}
	// A hundred percent accepts a doubling exactly, because the boundary is
	// inclusive, and refuses anything short of it.
	if !SwitchAllowed(6, 3, 100) {
		t.Error("a doubling was refused at a 100% threshold")
	}
	if SwitchAllowed(5.9, 3, 100) {
		t.Error("a 96.7% improvement was accepted at a 100% threshold")
	}
	if !SwitchAllowed(6.1, 3, 100) {
		t.Error("an improvement past 100% was refused")
	}
}

// The whole chain, on the numbers the union of the twelve-candidate fixture
// produced. The best-scoring candidate is refused against the incumbent in
// front of it, because 3.90 over 3.65 is 6.8%, and accepted against a weaker
// incumbent.
func TestScoreTheSwitchGateRefusesTheBestCandidateWhenItIsUnderTheThreshold(t *testing.T) {
	params := Params{LatencyCandidates: 10, LatencyTop: 3, BandwidthTop: 3, Limits: tightLimits, Weights: documentedWeights}
	selection := Select(twelveGlobals(), params)

	if got, want := selection.Scored[0].Candidate.IP.String(), "104.16.2.1"; got != want {
		t.Fatalf("the winner is %s, want %s", got, want)
	}
	if got, want := selection.Scored[0].Score, 3.90; got != want {
		t.Fatalf("the winner scored %v, want %v", got, want)
	}
	incumbent := byAddress(t, selection.Scored, "104.16.0.1")
	if got, want := incumbent.Score, 3.65; got != want {
		t.Fatalf("the incumbent scored %v, want %v", got, want)
	}
	// 100*(3.90-3.65)/3.65 = 6.85%, under the 10%.
	if SwitchAllowed(selection.Scored[0].Score, incumbent.Score, 10) {
		t.Error("a 6.8% improvement over the incumbent was accepted")
	}
	// The same winner against the candidate behind it: 100*(3.90-2.65)/2.65 =
	// 47.2%, comfortably over the 10%.
	behind := byAddress(t, selection.Scored, "104.16.1.1")
	if got, want := behind.Score, 2.65; got != want {
		t.Fatalf("the candidate behind scored %v, want %v", got, want)
	}
	if !SwitchAllowed(selection.Scored[0].Score, behind.Score, 10) {
		t.Error("a 47.2% improvement was refused")
	}
	// The winner carries its own score and its eligibility, which is what the
	// caller combines with the final identity proof.
	if !selection.Scored[0].Eligible {
		t.Error("the winner is not marked eligible")
	}
	if selection.Scored[0].Reason != "" {
		t.Errorf("the winner carries the reason %q, want none", selection.Scored[0].Reason)
	}
}
