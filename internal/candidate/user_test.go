package candidate

import (
	"fmt"
	"strings"
	"testing"
)

// The user list is the only channel a user controls, so every case here is a
// case where an ambiguous or unusable line must be refused rather than guessed
// at. The input is an in-memory string: nothing in this test reads a file, a
// clock, or a network.

func TestParseUserListKeepsASingleAddress(t *testing.T) {
	got, err := ParseUserList(strings.NewReader("104.16.0.1\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	assertCandidates(t, got, []Candidate{publicCandidate(SourceUser, "104.16.0.1")})
}

func TestParseUserListAcceptsAnEmptyList(t *testing.T) {
	got, err := ParseUserList(strings.NewReader("\n   \n# nothing pinned yet\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want no candidates", got)
	}
}

func TestParseUserListReadsASlash32AsTheSameAddress(t *testing.T) {
	got, err := ParseUserList(strings.NewReader("104.16.0.1/32\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	assertCandidates(t, got, []Candidate{publicCandidate(SourceUser, "104.16.0.1")})
}

func TestParseUserListExpandsEveryAddressOfANarrowPrefix(t *testing.T) {
	// A prefix narrower than a block names addresses, not blocks, so every one of
	// them is a candidate the user asked for.
	got, err := ParseUserList(strings.NewReader("1.2.3.0/30\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	assertCandidates(t, got, []Candidate{
		publicCandidate(SourceUser, "1.2.3.0"),
		publicCandidate(SourceUser, "1.2.3.1"),
		publicCandidate(SourceUser, "1.2.3.2"),
		publicCandidate(SourceUser, "1.2.3.3"),
	})
}

func TestParseUserListExpandsTheFirstHostAddressOfEveryBlockInAWidePrefix(t *testing.T) {
	// A prefix wider than a block cannot be expanded address by address without
	// producing millions of probes, so it contributes the first host address of
	// each block it covers: 256 blocks, 256 candidates, no two in one block.
	got, err := ParseUserList(strings.NewReader("1.2.0.0/16\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	if len(got) != 256 {
		t.Fatalf("got %d candidates, want one for each of the 256 blocks", len(got))
	}
	for index := range 256 {
		want := publicCandidate(SourceUser, fmt.Sprintf("1.2.%d.1", index))
		if got[index] != want {
			t.Fatalf("candidate %d: got %+v, want %+v", index, got[index], want)
		}
	}
}

func TestParseUserListSkipsCommentsAndBlankLines(t *testing.T) {
	document := strings.Join([]string{
		"# the addresses the operator pinned by hand",
		"",
		"   ",
		"104.16.0.2   # the second one",
		"\t104.16.0.1\t",
		"104.16.0.3#a third one",
		"#104.16.0.4 is commented out",
	}, "\n")
	got, err := ParseUserList(strings.NewReader(document))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	assertCandidates(t, got, []Candidate{
		publicCandidate(SourceUser, "104.16.0.1"),
		publicCandidate(SourceUser, "104.16.0.2"),
		publicCandidate(SourceUser, "104.16.0.3"),
	})
}

func TestParseUserListCollapsesDuplicates(t *testing.T) {
	// The same address written three ways is one candidate, and it keeps the
	// user source: the list is where it came from.
	got, err := ParseUserList(strings.NewReader("104.16.0.1\n104.16.0.1\n104.16.0.1/32\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	assertCandidates(t, got, []Candidate{publicCandidate(SourceUser, "104.16.0.1")})
}

func TestParseUserListCanonicalizesAnIPv4MappedEntry(t *testing.T) {
	// An IPv4-mapped literal is IPv4 input written in IPv6 notation, so it is
	// unmapped to the address it stands for rather than refused. The mapping
	// prefix itself is 96 bits wide, so /126 here is the IPv4 /30.
	got, err := ParseUserList(strings.NewReader("::ffff:104.16.0.1\n::ffff:1.2.3.0/126\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	assertCandidates(t, got, []Candidate{
		publicCandidate(SourceUser, "1.2.3.0"),
		publicCandidate(SourceUser, "1.2.3.1"),
		publicCandidate(SourceUser, "1.2.3.2"),
		publicCandidate(SourceUser, "1.2.3.3"),
		publicCandidate(SourceUser, "104.16.0.1"),
	})
}

func TestParseUserListRejectsAnIPv6Entry(t *testing.T) {
	for _, line := range []string{
		"2606:4700::1",
		"2606:4700::/32",
		"::1",
		"fe80::1",
	} {
		got, err := ParseUserList(strings.NewReader(line + "\n"))
		if err == nil {
			t.Errorf("ParseUserList accepted the IPv6 entry %q and returned %v", line, got)
		}
	}
}

func TestParseUserListRejectsAnAddressARewriteTargetMustNotUse(t *testing.T) {
	// A candidate list is the only channel a user controls, so a private,
	// loopback, link-local, multicast or reserved address has to be refused here
	// or it becomes a rewrite target the user chose. The prefix forms matter as
	// much as the single addresses: a range that contains one of them is refused
	// whole rather than partly used.
	for _, line := range []string{
		"10.1.2.3",
		"10.0.0.0/8",
		"10.0.0.0/30",
		"127.0.0.1",
		"169.254.1.1",
		"172.16.0.1",
		"192.168.1.1",
		"100.64.0.1",
		"0.0.0.0",
		"224.0.0.1",
		"240.0.0.1",
		"192.0.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
	} {
		got, err := ParseUserList(strings.NewReader("104.16.0.1\n" + line + "\n"))
		if err == nil {
			t.Errorf("ParseUserList accepted %q and returned %v", line, got)
		}
	}
}

func TestParseUserListRejectsMalformedInput(t *testing.T) {
	for name, line := range map[string]string{
		"not an address":           "example.test",
		"two entries on a line":    "104.16.0.1 104.16.0.2",
		"an address and words":     "104.16.0.1 anycast",
		"a prefix length too long": "104.16.0.0/33",
		"a prefix with no length":  "104.16.0.0/",
		"a negative prefix length": "104.16.0.0/-1",
		"an octet too large":       "104.16.0.256",
		"too few octets":           "104.16.0",
		"too many octets":          "104.16.0.1.1",
		"a leading zero octet":     "104.016.0.1",
		"a tab inside the entry":   "104.16.\t0.1",
		"a host mask":              "104.16.0.1/255.255.255.0",
		"a bare slash":             "/32",
	} {
		got, err := ParseUserList(strings.NewReader(line + "\n"))
		if err == nil {
			t.Errorf("ParseUserList accepted %s (%q) and returned %v", name, line, got)
		}
	}
}

func TestParseUserListEnforcesTheCandidateBound(t *testing.T) {
	// A list is bounded so a single line cannot hand the prober an unbounded
	// number of addresses. The bound is itself a candidate, not an exclusion.
	atBound := strings.Builder{}
	for index := range 512 {
		fmt.Fprintf(&atBound, "9.0.%d.%d\n", index/256, index%256)
	}
	got, err := ParseUserList(strings.NewReader(atBound.String()))
	if err != nil {
		t.Fatalf("ParseUserList refused a list of exactly 512 candidates: %v", err)
	}
	if len(got) != 512 {
		t.Fatalf("got %d candidates, want 512", len(got))
	}
	if last := got[len(got)-1]; last != publicCandidate(SourceUser, "9.0.1.255") {
		t.Errorf("got last candidate %+v, want the last one written", last)
	}
	overBound := atBound.String() + "9.9.9.9\n"
	if _, err := ParseUserList(strings.NewReader(overBound)); err == nil {
		t.Errorf("ParseUserList accepted 513 candidates")
	}
}

func TestParseUserListRefusesOnePrefixWiderThanTheBound(t *testing.T) {
	// A single wide prefix is refused for the same reason a long list is: it
	// would hand the prober more addresses than a run can measure, and the
	// refusal costs the work of the bound rather than the work of the prefix.
	if candidates, err := ParseUserList(strings.NewReader("1.0.0.0/8\n")); err == nil {
		t.Errorf("ParseUserList accepted 1.0.0.0/8 and returned %d candidates", len(candidates))
	}
}

func TestParseUserListOrdersCandidatesByAddress(t *testing.T) {
	// The output order is the sort order of the package, so a report built from
	// two runs of the same list does not change.
	document := strings.Join([]string{
		"104.16.0.100",
		"104.16.0.9",
		"104.16.0.2",
		"13.32.0.1",
		"104.16.0.20",
		"13.32.0.1",
	}, "\n")
	got, err := ParseUserList(strings.NewReader(document))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	assertCandidates(t, got, []Candidate{
		publicCandidate(SourceUser, "13.32.0.1"),
		publicCandidate(SourceUser, "104.16.0.2"),
		publicCandidate(SourceUser, "104.16.0.9"),
		publicCandidate(SourceUser, "104.16.0.20"),
		publicCandidate(SourceUser, "104.16.0.100"),
	})
}

func TestParseUserListKeepsTheUserSourceOnEveryCandidate(t *testing.T) {
	// The source is provenance, so nothing a list produces is relabelled as
	// official, and a list address that an official range also names keeps the
	// user label when the two are combined.
	list, err := ParseUserList(strings.NewReader("104.16.0.1\n104.16.0.2\n"))
	if err != nil {
		t.Fatalf("ParseUserList: %v", err)
	}
	official := []Candidate{publicCandidate(SourceCloudflare, "104.16.0.1"), publicCandidate(SourceCloudflare, "104.16.0.2")}
	got, err := Combine(official, list, nil, 512)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	assertCandidates(t, got, []Candidate{
		publicCandidate(SourceUser, "104.16.0.1"),
		publicCandidate(SourceUser, "104.16.0.2"),
	})
}
