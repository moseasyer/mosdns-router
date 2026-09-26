package candidate

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

// Every expected value below is a literal written from the contract, never from
// the code under test: an address is spelled out, a count is written down, and an
// order is derived by hand from the four sort keys. The address literals are
// real public IPv4 space (104.16.0.0/13, 172.64.0.0/13, 13.32.0.0/15) and are
// never dialled: nothing in this package opens a connection.

// assertCandidates compares two candidate lists field by field, so a failure
// names the candidate and the field that differs instead of printing two struct
// dumps the reader has to diff.
func assertCandidates(t *testing.T, got, want []Candidate) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d candidates %v, want %d %v", len(got), got, len(want), want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("candidate %d: got %+v, want %+v", index, got[index], want[index])
		}
	}
}

// publicCandidate returns a candidate for a public address in the global
// Cloudflare group, so a table case only has to name the field under test.
func publicCandidate(source, address string) Candidate {
	return Candidate{Provider: ProviderCloudflare, IP: netip.MustParseAddr(address), Source: source}
}

func TestCandidateValidationRefusesAnAddressARewriteTargetMustNotUse(t *testing.T) {
	// The same ranges internal/state refuses for a published rewrite target: a
	// candidate list is the only channel a user controls, so a LAN, loopback,
	// link-local, multicast or reserved address accepted here would become a
	// rewrite target the user chose.
	for _, address := range []string{
		"0.0.0.0",
		"10.1.2.3",
		"100.64.0.1",
		"127.0.0.1",
		"169.254.1.1",
		"172.16.5.4",
		"192.0.0.9",
		"192.0.2.1",
		"192.168.1.1",
		"198.18.0.1",
		"198.51.100.7",
		"203.0.113.9",
		"224.0.0.1",
		"240.0.0.1",
	} {
		candidate := publicCandidate(SourceUser, address)
		if err := candidate.Validate(); err == nil {
			t.Errorf("Validate accepted %s: %+v", address, candidate)
		}
	}
}

func TestCandidateValidationRefusesAnAddressThatIsNotPlainIPv4(t *testing.T) {
	for _, address := range []string{
		"2606:4700::1",
		"::1",
		"::ffff:104.16.0.1",
	} {
		candidate := publicCandidate(SourceUser, address)
		if err := candidate.Validate(); err == nil {
			t.Errorf("Validate accepted %s: %+v", address, candidate)
		}
	}
}

func TestCandidateValidationAcceptsAPublicIPv4Address(t *testing.T) {
	for _, address := range []string{
		"104.16.0.1",
		"172.64.1.1",
		"13.32.0.1",
		"223.255.255.254",
	} {
		candidate := publicCandidate(SourceUser, address)
		if err := candidate.Validate(); err != nil {
			t.Errorf("Validate refused %s: %v", address, err)
		}
	}
}

func TestCandidateValidationBoundsTheSourceToken(t *testing.T) {
	// Source is published into the selector state and the status renderer, so it
	// has to stay a short lowercase token whatever source produced it.
	longToken := "u" + repeat("x", 32)
	for name, source := range map[string]string{
		"empty":              "",
		"upper case":         "User",
		"with a space":       "user candidate",
		"with an underscore": "user_candidate",
		"with a slash":       "user/candidate",
		"longer than 32":     longToken,
		"leading hyphen":     "-user",
		"non ascii":          "usér",
	} {
		candidate := publicCandidate(source, "104.16.0.1")
		if err := candidate.Validate(); err == nil {
			t.Errorf("Validate accepted a source token that is %s: %q", name, source)
		}
	}
	for _, source := range []string{"user", "retained", "cloudflare", "cloudfront", "installer-2", "u"} {
		candidate := publicCandidate(source, "104.16.0.1")
		if err := candidate.Validate(); err != nil {
			t.Errorf("Validate refused the source token %q: %v", source, err)
		}
	}
}

func TestCandidateValidationKeepsTheProviderAndHostnameGroupsApart(t *testing.T) {
	// A CloudFront candidate without a hostname would land in the global group
	// and be compared with Cloudflare results, and a Cloudflare candidate with a
	// hostname would publish a per-host mapping that no probe ever proved.
	global := publicCandidate(SourceUser, "104.16.0.1")
	if err := global.Validate(); err != nil {
		t.Fatalf("Validate refused a global candidate: %v", err)
	}
	globalWithHostname := global
	globalWithHostname.Hostname = "cdn.example"
	if err := globalWithHostname.Validate(); err == nil {
		t.Errorf("Validate accepted a global Cloudflare candidate with a hostname: %+v", globalWithHostname)
	}
	unnamed := Candidate{Provider: ProviderCloudFront, IP: netip.MustParseAddr("13.32.0.1"), Source: SourceCloudFront}
	if err := unnamed.Validate(); err == nil {
		t.Errorf("Validate accepted a CloudFront candidate with no hostname: %+v", unnamed)
	}
	named := unnamed
	named.Hostname = "cdn.example"
	if err := named.Validate(); err != nil {
		t.Errorf("Validate refused a named CloudFront candidate: %v", err)
	}
	for _, hostname := range []string{"*.example", "cdn.example.", "1.2.3.4", "-cdn.example", "cdn example"} {
		invalid := named
		invalid.Hostname = hostname
		if err := invalid.Validate(); err == nil {
			t.Errorf("Validate accepted the hostname %q", hostname)
		}
	}
}

func TestCompareOrdersByProviderThenHostnameThenAddressThenSource(t *testing.T) {
	// The four keys are applied one after another, and each case below is a pair
	// where a later key would reverse the order if it were consulted first.
	globalLow := publicCandidate(SourceUser, "13.32.0.1")
	globalHigh := publicCandidate(SourceRetained, "13.32.0.2")
	perHostnameFirst := Candidate{Provider: ProviderCloudFront, IP: netip.MustParseAddr("13.32.0.9"), Source: SourceUser, Hostname: "a.example"}
	perHostnameSecond := Candidate{Provider: ProviderCloudFront, IP: netip.MustParseAddr("13.32.0.1"), Source: SourceUser, Hostname: "b.example"}

	unsorted := []Candidate{perHostnameSecond, perHostnameFirst, globalHigh, globalLow}
	Sort(unsorted)
	// The provider puts every global candidate first, the address outranks the
	// source, and the hostname outranks the address.
	assertCandidates(t, unsorted, []Candidate{globalLow, globalHigh, perHostnameFirst, perHostnameSecond})
}

func TestSortIsRepeatableForTheSameInput(t *testing.T) {
	// Two runs over the same values must land on the same list, whatever order
	// the values arrived in: a ranking built on this order is published.
	values := []Candidate{
		publicCandidate(SourceCloudflare, "104.16.0.5"),
		publicCandidate(SourceUser, "104.16.0.5"),
		publicCandidate(SourceUser, "104.16.0.2"),
		publicCandidate(SourceRetained, "104.16.0.5"),
	}
	first := slices.Clone(values)
	Sort(first)
	for range 8 {
		again := slices.Clone(values)
		Sort(again)
		assertCandidates(t, again, first)
	}
	// The source breaks the tie between the three candidates for one address.
	assertCandidates(t, first, []Candidate{
		publicCandidate(SourceUser, "104.16.0.2"),
		publicCandidate(SourceCloudflare, "104.16.0.5"),
		publicCandidate(SourceRetained, "104.16.0.5"),
		publicCandidate(SourceUser, "104.16.0.5"),
	})
}

func TestCombineKeepsUserAndRetainedCandidatesOutsideTheOfficialLimit(t *testing.T) {
	official := make([]Candidate, 0, 600)
	for index := range 600 {
		official = append(official, publicCandidate(SourceCloudflare, fmt.Sprintf("104.16.%d.%d", index/256, index%256)))
	}
	user := []Candidate{publicCandidate(SourceUser, "9.1.1.1"), publicCandidate(SourceUser, "9.1.1.2")}
	retained := []Candidate{publicCandidate(SourceRetained, "9.2.2.1"), publicCandidate(SourceRetained, "9.2.2.2")}

	got, err := Combine(official, user, retained, 512)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if len(got) != 516 {
		t.Fatalf("got %d candidates, want the 512 official ones plus 2 user plus 2 retained", len(got))
	}
	officialCount := 0
	for _, candidate := range got {
		switch candidate.Source {
		case SourceCloudflare:
			officialCount++
		case SourceUser, SourceRetained:
		default:
			t.Errorf("unexpected source %q in %+v", candidate.Source, candidate)
		}
	}
	if officialCount != 512 {
		t.Errorf("got %d official candidates, want 512", officialCount)
	}
	want := append(slices.Clone(user), retained...)
	for _, candidate := range want {
		if !slices.Contains(got, candidate) {
			t.Errorf("Combine dropped the always-included candidate %+v", candidate)
		}
	}
}

func TestCombineKeepsTheOfficialLimitUncappedWhenItExceedsIt(t *testing.T) {
	// The limit is a cap, not a quota: a document with fewer official
	// candidates than the limit must come back whole.
	official := []Candidate{publicCandidate(SourceCloudflare, "104.16.0.1"), publicCandidate(SourceCloudflare, "104.16.0.2")}
	got, err := Combine(official, nil, nil, 512)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	assertCandidates(t, got, official)
}

func TestCombineNeverCapsTheAlwaysIncludedCandidates(t *testing.T) {
	// The limit is about official candidates only, so a limit of one still leaves
	// room for three user candidates and three retained ones. A limit that were
	// applied to either channel would drop two of them here.
	official := []Candidate{
		publicCandidate(SourceCloudflare, "104.16.0.1"),
		publicCandidate(SourceCloudflare, "104.16.0.2"),
	}
	user := []Candidate{
		publicCandidate(SourceUser, "9.1.1.1"),
		publicCandidate(SourceUser, "9.1.1.2"),
		publicCandidate(SourceUser, "9.1.1.3"),
	}
	retained := []Candidate{
		publicCandidate(SourceRetained, "9.2.2.1"),
		publicCandidate(SourceRetained, "9.2.2.2"),
		publicCandidate(SourceRetained, "9.2.2.3"),
	}
	got, err := Combine(official, user, retained, 1)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if len(got) != 7 {
		t.Fatalf("got %d candidates %v, want one official, three user and three retained", len(got), got)
	}
	for _, candidate := range append(slices.Clone(user), retained...) {
		if !slices.Contains(got, candidate) {
			t.Errorf("Combine dropped %+v", candidate)
		}
	}
}

func TestCombineRefusesARetainedCandidateOfferedThroughAnotherChannel(t *testing.T) {
	// A retained candidate in the official slice would be dropped by the limit
	// and a user candidate in the retained slice would be dropped by whatever
	// limit the caller passed, so both misroutes are refused rather than
	// silently capped.
	official := []Candidate{publicCandidate(SourceRetained, "104.16.0.1")}
	if _, err := Combine(official, nil, nil, 512); err == nil {
		t.Errorf("Combine accepted a retained candidate in the official channel")
	}
	user := []Candidate{publicCandidate(SourceRetained, "104.16.0.1")}
	if _, err := Combine(nil, user, nil, 512); err == nil {
		t.Errorf("Combine accepted a retained candidate in the user channel")
	}
	retained := []Candidate{publicCandidate(SourceUser, "104.16.0.1")}
	if _, err := Combine(nil, nil, retained, 512); err == nil {
		t.Errorf("Combine accepted a user candidate in the retained channel")
	}
}

func TestCombineRefusesACandidateItWouldPublish(t *testing.T) {
	// The user list is the only channel a user controls and the retained set is
	// the one a later task fills from state, so no channel may offer an address
	// or a group a published rewrite target could not use.
	invalid := map[string]Candidate{
		"a LAN address":                      {Provider: ProviderCloudflare, IP: netip.MustParseAddr("10.0.0.1")},
		"a loopback address":                 {Provider: ProviderCloudflare, IP: netip.MustParseAddr("127.0.0.1")},
		"a reserved address":                 {Provider: ProviderCloudflare, IP: netip.MustParseAddr("203.0.113.1")},
		"an IPv6 address":                    {Provider: ProviderCloudflare, IP: netip.MustParseAddr("2606:4700::1")},
		"an unnamed CloudFront":              {Provider: ProviderCloudFront, IP: netip.MustParseAddr("13.32.0.1")},
		"a global candidate with a hostname": {Provider: ProviderCloudflare, IP: netip.MustParseAddr("13.32.0.1"), Hostname: "cdn.example"},
		"an unknown provider":                {Provider: Provider("other"), IP: netip.MustParseAddr("13.32.0.1")},
		"no provider at all":                 {IP: netip.MustParseAddr("13.32.0.1")},
	}
	channels := map[string]struct {
		source  string
		combine func([]Candidate) ([]Candidate, error)
	}{
		"official": {SourceCloudflare, func(values []Candidate) ([]Candidate, error) { return Combine(values, nil, nil, 512) }},
		"user":     {SourceUser, func(values []Candidate) ([]Candidate, error) { return Combine(nil, values, nil, 512) }},
		"retained": {SourceRetained, func(values []Candidate) ([]Candidate, error) { return Combine(nil, nil, values, 512) }},
	}
	for channel, entry := range channels {
		for name, template := range invalid {
			candidate := template
			candidate.Source = entry.source
			if _, err := entry.combine([]Candidate{candidate}); err == nil {
				t.Errorf("the %s channel offered a candidate that is %s: %+v", channel, name, candidate)
			}
		}
		if _, err := entry.combine([]Candidate{publicCandidate(repeat("x", 33), "13.32.0.1")}); err == nil {
			t.Errorf("the %s channel offered a candidate with an unbounded source token", channel)
		}
	}
}

func TestCombineRefusesANonPositiveLimit(t *testing.T) {
	for _, limit := range []int{0, -1} {
		if _, err := Combine(nil, nil, nil, limit); err == nil {
			t.Errorf("Combine accepted the limit %d", limit)
		}
	}
}

func TestCombineKeepsOneCandidateForAnAddressNamedBySeveralChannels(t *testing.T) {
	// The source field records provenance, so the address a user pinned keeps
	// the user label even where an official range names it too, and the winner
	// the switch gate must re-prove keeps the retained label even where a user
	// list names it.
	shared := publicCandidate(SourceCloudflare, "104.16.0.1")
	asUser := shared
	asUser.Source = SourceUser
	asRetained := shared
	asRetained.Source = SourceRetained
	for name, testCase := range map[string]struct {
		official []Candidate
		user     []Candidate
		retained []Candidate
		want     string
	}{
		"official and user":        {official: []Candidate{shared}, user: []Candidate{asUser}, want: SourceUser},
		"official and retained":    {official: []Candidate{shared}, retained: []Candidate{asRetained}, want: SourceRetained},
		"user and retained":        {user: []Candidate{asUser}, retained: []Candidate{asRetained}, want: SourceRetained},
		"official, user, retained": {official: []Candidate{shared}, user: []Candidate{asUser}, retained: []Candidate{asRetained}, want: SourceRetained},
	} {
		got, err := Combine(testCase.official, testCase.user, testCase.retained, 512)
		if err != nil {
			t.Fatalf("%s: Combine: %v", name, err)
		}
		if len(got) != 1 {
			t.Errorf("%s: got %d candidates, want one: %v", name, len(got), got)
			continue
		}
		if got[0].Source != testCase.want {
			t.Errorf("%s: got source %q, want %q", name, got[0].Source, testCase.want)
		}
	}
}

func TestCombineKeepsTheSameAddressApartInTwoProviderGroups(t *testing.T) {
	// The same address reached through a user list and through a CloudFront
	// profile names two different rewrite targets, so it is one candidate in each
	// group and never one shared row.
	global := publicCandidate(SourceUser, "13.32.0.1")
	perHostname := Candidate{Provider: ProviderCloudFront, IP: netip.MustParseAddr("13.32.0.1"), Source: SourceUser, Hostname: "cdn.example"}
	got, err := Combine(nil, []Candidate{global, perHostname}, nil, 512)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	assertCandidates(t, got, []Candidate{global, perHostname})
}

func TestCombineLeavesItsInputAlone(t *testing.T) {
	official := []Candidate{publicCandidate(SourceCloudflare, "104.16.0.2"), publicCandidate(SourceCloudflare, "104.16.0.1")}
	user := []Candidate{publicCandidate(SourceUser, "9.1.1.2"), publicCandidate(SourceUser, "9.1.1.1")}
	before := append(slices.Clone(official), user...)
	if _, err := Combine(official, user, nil, 1); err != nil {
		t.Fatalf("Combine: %v", err)
	}
	after := append(slices.Clone(official), user...)
	assertCandidates(t, after, before)
}

// repeat returns a string of count copies of character, so a length boundary is
// written as "one character too long" instead of a hand-counted literal.
func repeat(character string, count int) string {
	out := make([]byte, count)
	for index := range out {
		out[index] = character[0]
	}
	return string(out)
}
