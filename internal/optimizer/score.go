// Package optimizer selects a CDN address from measured candidates. This file
// holds the other half of it: what to do with the numbers the probes returned.
//
// Everything here is a pure function over measured results. Nothing opens a
// socket, reads a clock, or reads a policy, because this is the part that
// decides which address a user's DNS is rewritten to, and a decision that
// depended on what the machine happened to be doing is not a decision that can
// be reproduced, explained, or argued with.
//
// Three properties carry the whole file, and each of them is a response to a
// way this can go wrong:
//
//   - Nothing is compared across a group. A Cloudflare address is global and a
//     CloudFront address means one hostname, so every ranking, every score and
//     the switch gate all run inside a group keyed by provider plus hostname. A
//     group is a named type with a method rather than a string assembled at
//     each call site, and a slice that mixes two of them is refused whole
//     rather than ranked, because ranking it is the one operation that would
//     compare a CloudFront result with a global one.
//
//   - Nothing is ordered by a float. Each metric becomes an integer percentile
//     rank within its own group first, the weights are integers in
//     ten-thousandths, and the combined rank score is an exact integer. The
//     float CombinedScore reports is that integer divided by a constant, and
//     no ordering decision reads it: a rank cannot be reordered by a rounding
//     difference, and a weight of 0.45 is 4500 ten-thousandths rather than a
//     float that a sum of three of them might round.
//
//   - Nothing depends on the order a group arrived in. A rank is a position
//     computed by counting, and every sort starts from a copy, so a Go map's
//     iteration order cannot reach a published winner.
//
// The one thing that does decide an order is a pair of results that share a
// provider, a hostname, an address and a source, and agree on the loss, the
// jitter and the p50 while disagreeing on something no chain term reads: the
// chain has nothing left to separate them with, and the stable sort keeps the
// order the caller gave. candidate.Combine dedupes on
// provider/hostname/address, so a run that measures one address once cannot
// produce such a pair, and a caller that does has a bug the chain is not the
// place to report. Where both entries carry identical measurements the
// question does not arise, because they are the same value.
package optimizer

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/measure"
)

// The five reasons a candidate is not scored. They are named constants and
// not formatted strings because a report has to say which rule refused a
// candidate, and a rule that can only be recognised by its wording is a rule
// nobody can match on.
const (
	// ReasonNoSample is the refusal for an address that completed no handshake
	// at all. Such a result carries a p50 of 0ms, because a median of nothing
	// is reported as no median at all, and a candidate with no latency measured
	// must never win a latency ranking.
	ReasonNoSample = "no successful TCP sample"

	// ReasonLossAboveLimit is the refusal for a candidate whose packet loss
	// fraction is above the caller's ceiling. Loss is checked before latency,
	// because an address that drops handshakes is out whatever its median says:
	// the two numbers are reported in that order so a reader is not left
	// choosing between them.
	ReasonLossAboveLimit = "packet loss above the limit"

	// ReasonLatencyAboveLimit is the refusal for a candidate whose p50 is above
	// the caller's ceiling.
	ReasonLatencyAboveLimit = "p50 latency above the limit"

	// ReasonOutsideLatencyTop is the refusal for a candidate that was measured
	// and passed both ceilings but fell outside the latency shortlist, so it was
	// never given a download measurement.
	ReasonOutsideLatencyTop = "outside the latency shortlist"

	// ReasonOutsideBandwidthTop is the refusal for a candidate that was measured
	// and fell outside the bandwidth shortlist. It is a different rule from
	// ReasonOutsideLatencyTop and gets its own name: a report that says a
	// candidate was outside the latency shortlist when it was outside the
	// bandwidth one sends the reader looking for a latency filter that was never
	// run.
	ReasonOutsideBandwidthTop = "outside the bandwidth shortlist"

	// ReasonOutsideCombined is the refusal for a candidate that was on the
	// latency shortlist but in neither half of the combined set, so it was
	// measured and has a score but was not scored against the others.
	ReasonOutsideCombined = "outside the combined shortlist"

	// ReasonUnusableCounts is the refusal for every candidate in a call whose
	// shortlist counts could not select anything. Naming the cause is the point:
	// a report that lists twelve candidates and no scores, with no reason, is a
	// report that reads as "nothing was good enough" when the truth is that the
	// caller wired a policy field to the wrong variable.
	ReasonUnusableCounts = "the shortlist counts cannot select anything"

	// ReasonMixedGroups is the refusal for a slice holding more than one group.
	// Nothing in it is ranked, and the reason says why: comparing them is the
	// thing this package must never do.
	ReasonMixedGroups = "the group mixes providers or hostnames"
)

// weightScale is the denominator of the integer weights. Ten thousand is large
// enough for the three documented weights to be exact (0.45, 0.45 and 0.10 are
// 4500, 4500 and 1000) and small enough that a product of two weights and a
// group size cannot approach the point where an int64 would be needed.
const weightScale = 10000

// GroupKey names the one set of candidates that may be compared with each
// other. Global Cloudflare candidates form a single group, and every CloudFront
// hostname forms a group of its own.
//
// It is a named type with a constructor and a comparison method rather than a
// string built where it is needed, because "provider plus hostname" assembled
// at four call sites is four chances to spell it differently, and a spelling
// that differs by a trailing dot is a comparison that crosses a group boundary
// without anybody deciding to cross one.
type GroupKey struct {
	// Provider is the group a candidate competes in.
	Provider candidate.Provider
	// Hostname is the CloudFront profile hostname this group belongs to, and
	// is empty for the global group.
	Hostname string
}

// GroupOf is the group a candidate competes in. Every key in this file is
// derived from it, so the rule that a Cloudflare candidate has no hostname and a
// CloudFront candidate has exactly one is stated once, by the candidate package,
// and reused.
func GroupOf(subject candidate.Candidate) GroupKey {
	return GroupKey{Provider: subject.Provider, Hostname: subject.Hostname}
}

// Same reports whether two keys name the same group. It is a method so a
// comparison cannot be written as a field-by-field equality that a future field
// addition would silently drop.
func (k GroupKey) Same(other GroupKey) bool {
	return k.Provider == other.Provider && k.Hostname == other.Hostname
}

// String renders the key for a report. The global group ends in a slash, so a
// report line reads "cloudfront/a.example.test" or "cloudflare/" and never an
// ambiguous "cloudfront" with the hostname lost.
//
// The zero key renders as "(no group)" rather than as "/". The zero key means
// two different things — there was no group at all, or the slice was refused for
// mixing groups — and neither is a group whose provider failed to load, which is
// what a bare "/" would look like in a report a reader has to act on.
func (k GroupKey) String() string {
	if k.Provider == "" && k.Hostname == "" {
		return "(no group)"
	}
	return string(k.Provider) + "/" + k.Hostname
}

// CandidateResult is one candidate with everything the probes measured about
// it, and the two fields the selection fills in. It is a value: scoring a group
// returns copies, so nothing the caller passed in is reordered or overwritten.
//
// The three measurement fields are internal/measure's types, which the prober
// also names: prober.TCPMetrics, prober.HTTPMetrics and prober.DownloadMetrics
// are aliases for them, so a value the runner fills in from a probe goes
// straight into a CandidateResult with no conversion. The measurement types are
// declared apart from the prober because a scorer has to be able to name what it
// scores, and the prober's own tests reach for the scorer.
type CandidateResult struct {
	// Candidate is the address that was measured, and its group.
	Candidate candidate.Candidate
	// TCP is the connect measurement, which carries the latency, the jitter and
	// the loss.
	TCP measure.TCPMetrics
	// HTTP is what the address proved about itself, and it is the only field
	// that can make a candidate eligible. A caller that reached this file
	// without one has not proved anything, and the selectors here do not read
	// it: eligibility is the caller's condition and this package scores the
	// candidates that already passed it.
	HTTP measure.HTTPMetrics
	// Download is what the address delivered within its limits. A run whose
	// daily budget ran out leaves BytesPerSecond at zero, which is not an
	// error here: a candidate that was never measured for speed ranks last on
	// speed, and a caller that cannot afford the measurement is the caller's
	// decision to make, not this file's to undo.
	Download measure.DownloadMetrics
	// Score is the combined rank score, which CombinedScore computes. It is a
	// report and comparison figure: no ordering decision reads it, because the
	// integer RankScore behind it is what orders.
	Score float64
	// Eligible is true for a candidate that took part in the scoring, and false
	// for one that did not.
	Eligible bool
	// Reason is the named refusal for a candidate that did not take part, and
	// empty for one that did. It is set on every value this package excludes,
	// because a report that lists twelve candidates and says nothing about the
	// two that lost is a report that cannot be acted on.
	Reason string
}

// Weights are the three shares of the combined score. They are supplied by the
// caller for every call, because a weight read from a package variable is a
// weight no test can vary and no report can name.
//
// The three are shares, not absolute numbers: a set that does not sum to one is
// normalized before it is used, so 0.9/0.9/0.2 and 0.45/0.45/0.10 are the same
// weighting written at two scales.
type Weights struct {
	// Latency weights the percentile rank of p50 connect latency.
	Latency float64
	// Bandwidth weights the percentile rank of the measured transfer speed.
	Bandwidth float64
	// Stability weights the percentile rank of the jitter, the loss being the
	// second term of that order.
	Stability float64
}

// Limits are the ceilings a candidate must come under to be scored at all. They
// are parameters rather than policy fields, because config.Policy has no field
// for a loss ceiling or a latency ceiling and this plan may not add one: the
// ceilings are the caller's to choose, and the caller is the runner that reads
// the policy. A zero or negative ceiling means no ceiling for that dimension,
// which is the only way to say "measure everything" without a second type.
type Limits struct {
	// MaxLoss is the largest packet loss fraction a candidate may have. A
	// candidate exactly at it is kept: the ceiling is inclusive, so a policy
	// that says 2% means 2% is allowed.
	MaxLoss float64
	// MaxP50MS is the largest median connect time in milliseconds a candidate
	// may have, inclusive in the same way.
	MaxP50MS float64
}

// The default exclusion ceilings, as named constants rather than as literals
// inside a function, because they are the two numbers a reviewer has to agree
// with and a number buried in a return statement is a number nobody reads.
//
// They are the values Task 4 must pass as optimizer.Params.Limits. The zero
// Limits still means "no ceiling" and a caller can still ask for it, but a caller
// who writes Params{} by accident has a documented value here to reach for
// instead of the one that measures and publishes a candidate which dropped 40% of
// its handshakes.
//
// Neither number is a config.Policy field, because this plan may not add one.
// They are the caller's to override and these are the documented defaults.
const (
	// DefaultMaxLossFraction refuses a candidate that lost more than one
	// handshake in ten. A tenth is already an edge that drops queries, and it is
	// well above the loss a healthy anycast address shows.
	DefaultMaxLossFraction = 0.10

	// DefaultMaxP50MS refuses a candidate whose median connect took longer than
	// 150 milliseconds. Past that the delay is one a user feels on every query
	// rather than on a slow one, which is the whole thing a selector is for.
	DefaultMaxP50MS = 150.0
)

// DefaultLimits is the documented exclusion set, and the value Task 4 must pass
// as optimizer.Params.Limits. Both ceilings are inclusive, so a candidate exactly
// at either one is kept.
func DefaultLimits() Limits {
	return Limits{MaxLoss: DefaultMaxLossFraction, MaxP50MS: DefaultMaxP50MS}
}

// Params is everything a selection needs from the policy, gathered in one value
// so a caller cannot pass a shortlist count from one policy and a ceiling from
// another. The fields name the policy they come from.
type Params struct {
	// LatencyCandidates is how many candidates the latency ranking keeps, from
	// cdn.latency_candidate_count.
	LatencyCandidates int
	// LatencyTop is how many of that shortlist join the combined set on latency
	// alone, from cdn.combined.latency_top.
	LatencyTop int
	// BandwidthTop is how many of that shortlist join it on speed alone, from
	// cdn.combined.bandwidth_top.
	BandwidthTop int
	// Limits are the loss and latency ceilings. Pass DefaultLimits() unless the
	// operator has said otherwise; the zero value is no ceiling at all, which
	// measures everything and excludes nothing.
	Limits Limits
	// Weights are the three shares of the combined score.
	Weights Weights
}

// ErrUnusableCounts reports a Params whose three top-N counts cannot select
// anything. It is a named error so a caller can test for it with errors.Is
// instead of matching the message, and it is returned before any measurement is
// worth starting: the counts come from three separate policy fields, and a
// caller that wired one of them to the wrong variable would otherwise spend the
// user's bandwidth to learn it.
var ErrUnusableCounts = errors.New("the shortlist counts cannot select anything")

// Validate reports whether these parameters can select anything at all.
//
// It checks the three counts and nothing else, deliberately. The ceilings are not
// checked because a zero Limits means "no ceiling" by definition and a caller
// must be able to ask for that; the weights are not checked because a weighting
// that cannot be normalized already scores zero, and zero is a score
// SwitchAllowed refuses, so an unusable weighting produces no winner rather than
// a wrong one.
//
// Every count that is wrong is named in the message, not just the first, because
// a caller fixing one field should not have to run again to find the next.
func (p Params) Validate() error {
	var unusable []string
	for _, count := range []struct {
		name  string
		value int
	}{
		{"latency_candidate_count", p.LatencyCandidates},
		{"latency_top", p.LatencyTop},
		{"bandwidth_top", p.BandwidthTop},
	} {
		if count.value <= 0 {
			unusable = append(unusable, fmt.Sprintf("%s is %d, want more than zero", count.name, count.value))
		}
	}
	if len(unusable) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnusableCounts, strings.Join(unusable, "; "))
}

// Ranking is one ranking of one group: the candidates that took part, best
// first, and every candidate that did not, each with the rule that refused it.
//
// Both halves are returned together because a report needs both. A caller that
// got only the shortlist could not say why the address it expected to see is
// missing, and a caller that got only the refusals could not say what was
// measured.
type Ranking struct {
	// Group is the group this ranking is of, and is the zero key for a slice
	// that was refused for mixing groups.
	Group GroupKey
	// Ranked holds at most the requested count, best first, every entry marked
	// eligible with no reason.
	Ranked []CandidateResult
	// Excluded holds every candidate this call did not rank, each carrying the
	// named reason it was refused.
	Excluded []CandidateResult
}

// Selection is the whole per-group decision: the two shortlists, the combined
// set they form, and every candidate that is not in it.
type Selection struct {
	// Group is the group this selection is of.
	Group GroupKey
	// Scored is the combined set, ordered best first by the integer rank score
	// and then by the documented chain. Its first entry is the group's winner.
	Scored []CandidateResult
	// Excluded holds every candidate that is not in the combined set, each
	// carrying the named reason it is not there: over a ceiling, outside the
	// latency shortlist, or outside the combined set.
	Excluded []CandidateResult
	// Latency is the latency shortlist, with its own refusals.
	Latency Ranking
	// Bandwidth is the bandwidth half of the combined set, ranked inside the
	// latency shortlist.
	Bandwidth Ranking
}

// RankLatency orders one group by p50 connect latency and keeps the best top of
// them. It is the cdn.latency_candidate_count step: what is left after the
// ceilings is ranked, and only the shortlist is worth a download measurement.
//
// A slice holding more than one group is refused whole and nothing is ranked,
// so a caller that assembles a group wrongly loses the call rather than
// comparing two hostnames' addresses. A count of zero or less ranks nothing for
// the same reason in the other direction: a caller that asked for none of them
// is not handed all of them.
func RankLatency(group []CandidateResult, top int, limits Limits) Ranking {
	group, ok := singleGroup(group)
	if !ok {
		return refuseAll(group, ReasonMixedGroups)
	}
	eligible, refused := splitByLimits(group, limits)
	ordered := slices.Clone(eligible)
	// A stable sort over a total order, so a candidate that is identical to
	// another in every field keeps the order the caller gave and no other
	// property of the input can reach the result.
	slices.SortStableFunc(ordered, latencyOrder)

	kept, dropped := atMost(ordered, top, ReasonOutsideLatencyTop)
	markRanked(kept)
	markExcluded(dropped)
	return Ranking{Group: groupKeyOf(group), Ranked: kept, Excluded: append(refused, dropped...)}
}

// RankBandwidth orders one group by measured transfer speed, fastest first, and
// keeps the best top of them.
//
// The ranking is a ranking of what it is given. A bandwidth ranking that saw
// every candidate would rank an address the latency shortlist never admitted,
// which is not a bandwidth ranking the specification means: the bandwidth
// ranking is inside the latency shortlist. Select passes the shortlist in, and
// TestScoreTheBandwidthRankingCoversOnlyTheLatencyShortlist pins both halves.
func RankBandwidth(group []CandidateResult, top int, limits Limits) Ranking {
	group, ok := singleGroup(group)
	if !ok {
		return refuseAll(group, ReasonMixedGroups)
	}
	eligible, refused := splitByLimits(group, limits)
	ordered := slices.Clone(eligible)
	slices.SortStableFunc(ordered, bandwidthOrder)

	// The drops are named after this ranking, not after the latency one: a
	// candidate that reached a bandwidth ranking has already been through a
	// latency ranking, and saying it did not would be a report about a filter
	// this call never ran.
	kept, dropped := atMost(ordered, top, ReasonOutsideBandwidthTop)
	markRanked(kept)
	markDropped(dropped, ReasonOutsideBandwidthTop)
	return Ranking{Group: groupKeyOf(group), Ranked: kept, Excluded: append(refused, dropped...)}
}

// Select runs the whole per-group decision and is what a caller should reach
// for: it applies the ceilings, takes the latency shortlist, takes the
// bandwidth half inside that shortlist, forms the union of the two, scores the
// union, and returns it best first with every other candidate accounted for.
//
// The union is the scoring population, not the shortlist. A percentile is a
// statement about the set it is taken over, and the set the specification scores
// is LatencyTopN united with BandwidthTopN; ranking the ten of the shortlist
// instead would give a candidate a better percentile for being eleventh in a
// group it was only carried into.
//
// The three slices returned are the same values with different fields set. The
// input is never reordered.
func Select(group []CandidateResult, params Params) Selection {
	group, ok := singleGroup(group)
	if !ok {
		refusal := refuseAll(group, ReasonMixedGroups)
		return Selection{Group: refusal.Group, Excluded: refusal.Excluded, Latency: refusal, Bandwidth: refusal}
	}
	// The counts are checked before anything is ranked, so a malformed call is a
	// refusal that says why rather than an empty union that looks like an
	// absence of good candidates. Validate is exported for a caller that wants to
	// find this out before a run starts spending the user's bandwidth.
	if err := params.Validate(); err != nil {
		refusal := refuseAll(group, ReasonUnusableCounts)
		return Selection{Group: groupKeyOf(group), Excluded: refusal.Excluded, Latency: refusal, Bandwidth: refusal}
	}
	key := groupKeyOf(group)
	eligible, refused := splitByLimits(group, params.Limits)

	byLatency := slices.Clone(eligible)
	slices.SortStableFunc(byLatency, latencyOrder)
	shortlist, outOfShortlist := atMost(byLatency, params.LatencyCandidates, ReasonOutsideLatencyTop)
	markRanked(shortlist)
	markExcluded(outOfShortlist)

	bySpeed := slices.Clone(shortlist)
	slices.SortStableFunc(bySpeed, bandwidthOrder)
	bandwidthKept, _ := atMost(bySpeed, params.BandwidthTop, ReasonOutsideBandwidthTop)
	markRanked(bandwidthKept)

	// The combined set: the best of the shortlist on latency, and the best of
	// it on speed. A candidate in both halves is one entry, and the two halves
	// are deduplicated by the candidate's own identity rather than by a
	// position, so a duplicated half cannot produce a twice-measured candidate.
	latencyKept, _ := atMost(shortlist, params.LatencyTop, ReasonOutsideCombined)
	union := dedupe(append(slices.Clone(latencyKept), bandwidthKept...))

	// Ordered by the chain first and by the integer rank score second, so that
	// the score is what decides and the chain is what the stable sort falls back
	// on. A candidate that scores exactly the same as another therefore lands in
	// the documented order, and the result is the same whatever order the
	// caller assembled the group in.
	//
	// The scores are computed against a *copy* of the combined set, not against
	// the slice being sorted. The rank arithmetic counts rather than sorts, so
	// the two are equal today; taking the live slice would make that an
	// assumption rather than a guarantee, and a future rank that sorts would
	// then read a half-ordered population and report percentiles of it.
	population := slices.Clone(union)
	slices.SortStableFunc(union, chainOrder)
	slices.SortStableFunc(union, func(first, second CandidateResult) int {
		return cmp.Compare(RankScore(second, population, params.Weights), RankScore(first, population, params.Weights))
	})
	present := make(map[candidate.Candidate]bool, len(union))
	for _, result := range union {
		present[result.Candidate] = true
	}
	for index := range union {
		union[index].Score = CombinedScore(union[index], population, params.Weights)
		union[index].Eligible = true
		union[index].Reason = ""
	}

	outOfUnion := make([]CandidateResult, 0, len(shortlist))
	for _, result := range shortlist {
		if present[result.Candidate] {
			continue
		}
		result.Eligible = false
		result.Reason = ReasonOutsideCombined
		outOfUnion = append(outOfUnion, result)
	}
	excluded := make([]CandidateResult, 0, len(refused)+len(outOfShortlist)+len(outOfUnion))
	excluded = append(excluded, refused...)
	excluded = append(excluded, outOfShortlist...)
	excluded = append(excluded, outOfUnion...)

	latency := Ranking{Group: key, Ranked: shortlist, Excluded: append(slices.Clone(refused), outOfShortlist...)}
	bandwidth := Ranking{Group: key, Ranked: bandwidthKept}
	return Selection{Group: key, Scored: union, Excluded: excluded, Latency: latency, Bandwidth: bandwidth}
}

// RankScore is the integer the combined ordering is decided on: the three
// percentile ranks, each turned into a point value out of the group's size and
// weighted by the caller's shares in ten-thousandths.
//
// Higher is better. Rank r of n becomes (n + 1 - r), so the best candidate in a
// group of n is worth n points and the worst is worth one, and the best
// candidate in a group of one is worth exactly one. A weighting that cannot be
// normalized scores zero, and zero is a score no switch gate will accept, so an
// unusable policy cannot produce a winner.
//
// The score is a pure function of the group as a set. It does not depend on the
// order the group arrived in, and that is the whole reason a rank is computed by
// counting rather than by sorting: a sort's output depends on its input order
// for tied entries, and a tie here is a fact about two measurements, not about
// the slice a caller built them into.
//
// subject must be one of the results in the group, by value, and the group must
// be one group. A result from another group, or a value that is not in the slice
// at all, has no rank here and scores zero; and a slice that holds two groups is
// refused whole, because the percentile arithmetic compares the subject against
// every member of the slice and a foreign hostname's member is not a comparison
// this package may make. Checking the subject is not enough on its own: a
// subject can be a perfectly good member of a slice that also holds another
// hostname's results, which is how
// TestScoreAMixedGroupIsRefusedByEveryExportedFunctionThatTakesAGroup reaches
// this from outside.
func RankScore(subject CandidateResult, group []CandidateResult, weights Weights) int {
	if _, ok := singleGroup(group); !ok {
		return 0
	}
	if !isMember(group, subject) {
		return 0
	}
	size := len(group)
	shares := normalizeWeights(weights)
	if shares == (weightParts{}) {
		return 0
	}
	latency := size + 1 - rankOf(group, subject, latencyOrder)
	bandwidth := size + 1 - rankOf(group, subject, bandwidthOrder)
	stability := size + 1 - rankOf(group, subject, stabilityOrder)
	return shares.latency*latency + shares.bandwidth*bandwidth + shares.stability*stability
}

// CombinedScore is RankScore as the number a report and the switch gate read.
//
// It is the exact integer divided by weightScale, so it is the ordering's
// number and not a second, independently rounded one. The scale is bounded: a
// group of n produces scores in [1, n], because the smallest possible rank
// score is the sum of the shares times one and the shares are
// weightScale. A score of 1 is therefore the worst a real group can produce and
// 0 is a score no real group produces, which is what lets SwitchAllowed read a
// zero as "this candidate could not be scored" without a second rule.
//
// Nothing in this package orders by this value. The ordering is the integer
// RankScore, and a float that a sum of three weights might have rounded is not
// what decides which address a user's DNS is rewritten to.
//
// It inherits the group barrier from RankScore rather than repeating it, and it
// must: a mixed group scores zero here as well, because a report that printed a
// score derived from two hostnames' candidates would be a report nobody could
// act on. TestScoreAMixedGroupIsRefusedByEveryExportedFunctionThatTakesAGroup
// requires the zero from this function directly, so the inheritance is a
// contract rather than a coincidence.
func CombinedScore(subject CandidateResult, group []CandidateResult, weights Weights) float64 {
	return float64(RankScore(subject, group, weights)) / weightScale
}

// TenthPercentileSpeed is the group's tenth-percentile transfer speed, by the
// nearest-rank method the prober's own percentiles use: with n speeds in
// ASCENDING order it is the one at index ceil(0.10*n)-1, computed as
// (10*n+99)/100 in integer arithmetic with no interpolation between neighbours —
// the same shape as measure.TCPMetrics' p50 and p95.
//
// It is the lower tail, which is the only reading that makes the name true and
// the report useful: for ten candidates or fewer it is the slowest speed
// measured, and a "group floor" that was the fastest candidate in the group would
// be a ceiling. Taking the index into a descending slice gives the
// ceil(0.10*n)-th *fastest* instead, which is the 90th percentile; the function
// did that once and
// TestScoreTheTenthPercentileSpeedIsTheNearestRankOfTheGroup now pins n = 10 and
// n = 21, the two sizes at which the conventions are told apart.
//
// It is a property of the group, not of a candidate, and it is reported for the
// operator rather than compared between candidates: two candidates of one group
// share the group's p10, so a term built on it cannot separate them, and the
// comparator below does not pretend it can. The tie-break order is lower loss,
// then lower jitter, then the lower address. The number is exported because a
// report has to show the group's floor, and pinned by
// TestScoreTheTenthPercentileSpeedIsTheNearestRankOfTheGroup because Task 4
// reads it.
//
// A group that is not one group reports zero, on the same grounds as a score: a
// percentile across two hostnames' candidates is a number about neither. An
// empty group, and a group in which nothing was measured, also report zero.
func TenthPercentileSpeed(group []CandidateResult) float64 {
	if _, ok := singleGroup(group); !ok {
		return 0
	}
	if len(group) == 0 {
		return 0
	}
	speeds := make([]float64, 0, len(group))
	for _, result := range group {
		speeds = append(speeds, result.Download.BytesPerSecond)
	}
	slices.Sort(speeds)
	rank := (10*len(speeds) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > len(speeds) {
		rank = len(speeds)
	}
	return speeds[rank-1]
}

// SwitchAllowed is the scoring half of the switch gate: it reports whether a
// candidate is at least improvementPercent better than the incumbent under the
// normalized score, where improvementPercent is the policy's
// cdn.switch_improvement_percent.
//
// The other half of the gate is the final HTTPS identity proof, and it is not
// here because no pure function can stand in for it: proving an address is
// serving the hostname costs a connection. A caller must run that proof and this
// check, and accept a switch only when both agree. The order does not matter,
// because a switch is published atomically after both.
//
// The improvement is never computed as a percentage. The requirement is built
// from the incumbent alone and the new score is compared against it:
//
//	newScore >= currentScore * (100 + improvementPercent) / 100
//
// One multiplication and one division produce the requirement, and the
// comparison is a plain greater-or-equal, so a caller that produced the new
// score as exactly the thresholded value lands on equality and is accepted: the
// boundary is inclusive and it is defined here rather than arriving out of a
// quotient. For the shipped ten percent the factor is 1.1.
//
// The percentage form ((new-current)/current*100 >= threshold) is not used
// because it is three rounded operations and a comparison of the result, and its
// boundary is an accident. 3.3 over 3.0 is ten percent exactly, and
// (3.3-3.0)/3.0*100 evaluates to 9.999999999999993, so a percentage form refuses
// a switch that has reached the threshold. Multiplying both sides instead
// (100*new >= (100+threshold)*current) removes the division but not the accident:
// for 4.015 over 3.65 it compares 401.49999999999994 against 401.5 and refuses,
// because the two products round independently. Building the requirement from the
// incumbent once accepts it, and every exact-threshold pair in
// TestSwitchAllowsAnImprovementOfExactlyTheThreshold is accepted.
//
// An incumbent that is not a real score means there is no winner to keep: a zero
// or a negative current score is the empty-winner case, and any scored candidate
// may take the place. It is stated here rather than left to the arithmetic,
// because a non-positive incumbent times a positive factor is a non-positive
// requirement and a scored candidate is positive, so the comparison below would
// reach the same verdict on its own. Stating it is what makes the empty case a
// decision instead of a coincidence: a refactor of the requirement back into a
// percentage would divide by a score that is not there, and this branch is where
// that would have to be caught. The mutation run confirms the branch is not
// load-bearing for any real input; it is kept for the reason just given.
//
// A candidate that could not be scored is never a winner. A new score that is
// zero, negative, or not a finite number is refused whatever the incumbent is,
// because a combined score of a real group is never below one and a zero can
// only mean the weights could not be normalized. A threshold that is not a
// finite non-negative number is refused too, since an unreadable policy must not
// lower the bar. An incumbent so large that the requirement overflows is refused
// as well, which is the same direction: no incumbent is readable, so nothing is
// switched.
func SwitchAllowed(newScore, currentScore, improvementPercent float64) bool {
	if !isFinite(newScore) || newScore <= 0 {
		return false
	}
	if !isFinite(improvementPercent) || improvementPercent < 0 {
		return false
	}
	if !isFinite(currentScore) {
		return false
	}
	if currentScore <= 0 {
		return true
	}
	return newScore >= currentScore*(100+improvementPercent)/100
}

// The three orderings a rank is taken over. Each is a total order, so a rank is
// a position rather than a range, and each falls back to the chain below so that
// two candidates the metric cannot separate still have a defined order.
//
// The order of the chain inside them is redundant on purpose: stabilityOrder
// already ends with the chain, and latencyOrder leads with a metric the chain
// also reads. A redundant key costs a comparison and saves the reasoning about
// which key is skipped when a metric is also a chain term.
func latencyOrder(first, second CandidateResult) int {
	if order := compareFloat(first.TCP.P50MS, second.TCP.P50MS); order != 0 {
		return order
	}
	return chainOrder(first, second)
}

// bandwidthOrder is descending, because more bytes per second is better.
func bandwidthOrder(first, second CandidateResult) int {
	if order := -compareFloat(first.Download.BytesPerSecond, second.Download.BytesPerSecond); order != 0 {
		return order
	}
	return chainOrder(first, second)
}

// stabilityOrder is the spec's loss-and-jitter penalty: jitter first, because
// jitter is the variation a user feels between two queries while a median
// hides it, and loss second, because two candidates that are equally smooth are
// separated by the one that drops packets. Every candidate of a group is at or
// below the loss ceiling by the time this runs, so this is a ranking and not a
// second filter.
func stabilityOrder(first, second CandidateResult) int {
	if order := compareFloat(first.TCP.JitterMS, second.TCP.JitterMS); order != 0 {
		return order
	}
	return chainOrder(first, second)
}

// chainOrder is the documented tie-break, in the order the brief fixes: lower
// loss, then lower jitter, then the lower address.
//
// The brief's second term is a p10 speed, and TenthPercentileSpeed is the
// group's own tenth percentile: a property of the group, identical on both
// sides of every comparison this chain makes. It cannot separate two candidates
// of one group, so it is reported rather than compared, and a reader who wants
// to see it reads TenthPercentileSpeed.
//
// candidate.Compare is the last term rather than a bare address comparison
// because it is the package's own total order of candidates, and a chain that
// ended in the address alone would still tie two entries that share an address
// and differ only in their source. Ending the chain in the total order is what
// makes every ordering here a function of the group as a set.
func chainOrder(first, second CandidateResult) int {
	if order := compareFloat(first.TCP.Loss, second.TCP.Loss); order != 0 {
		return order
	}
	if order := compareFloat(first.TCP.JitterMS, second.TCP.JitterMS); order != 0 {
		return order
	}
	return candidate.Compare(first.Candidate, second.Candidate)
}

// rankOf is the 1-based position of subject in group under order, 1 being the
// best and len(group) the worst. It is computed by counting the members that
// come before it rather than by sorting, so the answer cannot depend on the
// order the group arrived in: two members the order compares equally do not
// count, so a member's rank is its position and a non-member's is the position
// it would have taken.
//
// The floats here are measurements, and comparing two measurements is the only
// way to rank them. What is never done is adding three of them together and
// comparing the sums, because that sum is the rank score and it is an integer.
func rankOf(group []CandidateResult, subject CandidateResult, order func(first, second CandidateResult) int) int {
	rank := 1
	for _, member := range group {
		if order(subject, member) > 0 {
			rank++
		}
	}
	return rank
}

// weightParts is the three weights as integers in ten-thousandths. It is the
// reason the combined score is exact.
type weightParts struct {
	latency   int
	bandwidth int
	stability int
}

// normalizeWeights turns shares into integer ten-thousandths summing to
// weightScale.
//
// It normalizes rather than refusing a set that does not sum to one, because a
// ratio is what a weighting is and 0.9/0.9/0.2 is the same ratio as
// 0.45/0.45/0.10.
//
// A weight that is negative or not a finite number makes the whole set
// unusable, and a zero score is one SwitchAllowed refuses. Silently treating a
// negative share as a weight of nothing would be the other choice, and it is
// the wrong one: a weighting that arrived with a negative share is a
// configuration error, and reinterpreting it changes which address a user's DNS
// is rewritten to. Refusing to score changes nothing, which is the direction
// that costs the user no traffic.
func normalizeWeights(weights Weights) weightParts {
	values := [3]float64{weights.Latency, weights.Bandwidth, weights.Stability}
	var total float64
	for _, value := range values {
		if !isFinite(value) || value < 0 {
			return weightParts{}
		}
		total += value
	}
	if total <= 0 {
		return weightParts{}
	}
	shares := weightParts{}
	sum := 0
	for index, value := range values {
		share := int(math.Round(value / total * weightScale))
		if share < 0 {
			share = 0
		}
		switch index {
		case 0:
			shares.latency = share
		case 1:
			shares.bandwidth = share
		default:
			shares.stability = share
		}
		sum += share
	}
	// Three rounded shares need not add up to the scale, and a score divided by
	// a scale it does not divide is a number whose best case is not the group's
	// size. The remainder goes to the first share, so the total is always
	// weightScale and the scale in CombinedScore is a constant.
	if remainder := weightScale - sum; remainder != 0 {
		shares.latency += remainder
	}
	if shares.latency < 0 {
		shares.latency = 0
	}
	return shares
}

// isMember reports whether subject is one of the results in the group, by value.
// A candidate that is not a member has no rank in the group, and scoring it
// against a group it is not in is the shape of a cross-group comparison, so the
// answer is zero rather than a plausible number.
func isMember(group []CandidateResult, subject CandidateResult) bool {
	for _, member := range group {
		if candidate.Compare(member.Candidate, subject.Candidate) == 0 &&
			member.TCP == subject.TCP && member.Download == subject.Download {
			return true
		}
	}
	return false
}

// singleGroup is the group of every candidate in the slice, and whether the
// slice holds only that one. A slice that mixes groups is returned whole with
// false, so the caller can refuse it rather than choose a group to keep: which
// group a mixed slice is "really" about depends on the order the caller
// happened to build it in, and an answer that depends on that is not an answer.
func singleGroup(group []CandidateResult) ([]CandidateResult, bool) {
	for _, result := range group {
		if !GroupOf(result.Candidate).Same(groupKeyOf(group)) {
			return group, false
		}
	}
	return group, true
}

// groupKeyOf is the group of the first candidate, and the zero key for an empty
// slice. A single group has been established before this is called with a slice
// of two, so reading the first entry is reading the group rather than guessing
// at it.
func groupKeyOf(group []CandidateResult) GroupKey {
	if len(group) == 0 {
		return GroupKey{}
	}
	return GroupOf(group[0].Candidate)
}

// splitByLimits partitions a group into the candidates that may be scored and
// the candidates refused by a ceiling, each refusal carrying the name of the rule
// that refused it.
//
// The refusals come back in the chain's order rather than the order the caller
// assembled the group in, so a report lists the same candidates in the same
// places whichever order the measurements finished in. The eligible half keeps
// the caller's order, which nothing depends on: every ranking sorts it.
func splitByLimits(group []CandidateResult, limits Limits) (eligible, refused []CandidateResult) {
	for _, result := range group {
		reason := refusalFor(result, limits)
		if reason == "" {
			eligible = append(eligible, result)
			continue
		}
		result.Eligible = false
		result.Reason = reason
		refused = append(refused, result)
	}
	slices.SortStableFunc(refused, chainOrder)
	return eligible, refused
}

// refusalFor is the one place a ceiling is applied, so the order the rules are
// checked in and the names they are refused with cannot drift between the
// latency ranking and the bandwidth ranking.
//
// A candidate with no successful sample is refused first and unconditionally.
// It carries a p50 of zero, so without this rule an address nothing answered
// would be the fastest candidate in the group, and a run that measured nothing
// would publish the address that answered nothing. That direction is not
// recoverable from a report.
func refusalFor(result CandidateResult, limits Limits) string {
	switch {
	case result.TCP.Samples <= 0:
		return ReasonNoSample
	case limits.MaxLoss > 0 && result.TCP.Loss > limits.MaxLoss:
		return ReasonLossAboveLimit
	case limits.MaxP50MS > 0 && result.TCP.P50MS > limits.MaxP50MS:
		return ReasonLatencyAboveLimit
	default:
		return ""
	}
}

// atMost keeps the first top of an ordered slice and refuses the rest with the
// named reason. A count of zero or less keeps nothing, because a caller that
// asked for none of them is not to be handed all of them.
func atMost(ordered []CandidateResult, top int, reason string) (kept, dropped []CandidateResult) {
	if top > len(ordered) {
		top = len(ordered)
	}
	if top < 0 {
		top = 0
	}
	kept = slices.Clone(ordered[:top])
	for _, result := range ordered[top:] {
		result.Eligible = false
		result.Reason = reason
		dropped = append(dropped, result)
	}
	return kept, dropped
}

// markRanked, markDropped and markExcluded set the two fields a report reads, so
// every value this package returns says plainly whether it took part and why not.
// markDropped takes the reason rather than assuming one, because two of the caps
// it applies are different rules and a report must not conflate them.
func markRanked(results []CandidateResult) {
	for index := range results {
		results[index].Eligible = true
		results[index].Reason = ""
	}
}

func markDropped(results []CandidateResult, reason string) {
	for index := range results {
		results[index].Eligible = false
		if results[index].Reason == "" {
			results[index].Reason = reason
		}
	}
}

func markExcluded(results []CandidateResult) {
	markDropped(results, ReasonOutsideLatencyTop)
}

// refuseAll is the answer to a slice that mixes groups: nothing is ranked, and
// every candidate carries the reason. The group is the zero key, because a
// slice of two groups is not a group.
func refuseAll(group []CandidateResult, reason string) Ranking {
	refused := make([]CandidateResult, 0, len(group))
	for _, result := range group {
		result.Eligible = false
		result.Reason = reason
		refused = append(refused, result)
	}
	return Ranking{Group: GroupKey{}, Excluded: refused}
}

// dedupe removes the entries a second half of the union repeats, by the
// candidate's own identity, keeping the first occurrence. A candidate in both
// the latency and the bandwidth half is one candidate measured once; if it were
// not deduplicated it would be scored twice against a set containing itself,
// which would give it a percentile in a group one larger than it belongs to.
func dedupe(results []CandidateResult) []CandidateResult {
	unique := make([]CandidateResult, 0, len(results))
	seen := make(map[candidate.Candidate]bool, len(results))
	for _, result := range results {
		if seen[result.Candidate] {
			continue
		}
		seen[result.Candidate] = true
		unique = append(unique, result)
	}
	return unique
}

// compareFloat orders two measured numbers without ever asking whether they are
// equal as a decision in its own right: it reports -1, 0 or 1, and the zero it
// returns for two identical measurements is a fact about the two measurements
// rather than a rounding coincidence. A number that is not a number compares as
// equal to everything, which is the prober's contract not to produce one.
func compareFloat(first, second float64) int {
	switch {
	case first < second:
		return -1
	case first > second:
		return 1
	default:
		return 0
	}
}

// isFinite reports whether a number is one a policy or a measurement may carry.
// A NaN would make every comparison false and a threshold of NaN would make the
// gate refuse everything, and an infinity would make it accept everything; both
// are refused rather than obeyed.
func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
