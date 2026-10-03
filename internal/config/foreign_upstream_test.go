package config

import (
	"strings"
	"testing"
)

// The measured surface of pkg/upstream/upstream.go:274-553 plus the normalisation
// at :131-156. A scheme outside this set is refused by mosdns at construction,
// and the refusal would happen inside the router rather than at render time.
func TestOnlyTheSchemesMosdnsActuallyAcceptsAreValid(t *testing.T) {
	for _, scheme := range []string{"udp", "tcp", "tcp+pipeline", "tls", "tls+pipeline", "https", "h3", "quic", "doq"} {
		if !ValidUpstreamScheme(scheme) {
			t.Errorf("mosdns v5.3.4 accepts %q and ValidUpstreamScheme refuses it", scheme)
		}
	}
	for _, scheme := range []string{"", "sdns", "http", "dot", "ssh", "h2", "TLS", "TCP"} {
		if ValidUpstreamScheme(scheme) {
			t.Errorf("ValidUpstreamScheme accepts %q, which mosdns v5.3.4 does not "+
				"(and an EMPTY scheme is the one that silently becomes udp://)", scheme)
		}
	}
	// And the empty scheme in its own case, because that is the one an operator
	// types by accident and the one the refusal message has to name.
	if err := ValidateOneUpstream(ForeignUpstream{
		Kind: UpstreamKindUpstream, Name: "bare", Addr: "1.1.1.1:53",
	}); err == nil || !strings.Contains(err.Error(), "no transport") {
		t.Fatalf("a bare address was accepted or refused for the wrong reason; got %v", err)
	}
}

// One table, one row per rule in spec section 3.4 rules 2-6, and each row says which
// rule it is so a failure names the rule rather than the symptom.
func TestEachAddressRuleRefusesExactlyWhatItClaims(t *testing.T) {
	ok := ForeignUpstream{Kind: UpstreamKindUpstream, Name: "n", Addr: "quic://dns.quad9.net:853"}
	cases := []struct {
		rule  string
		entry ForeignUpstream
		wants string
	}{
		{"not a URL", withAddr(ok, "://"), "not a URL"},
		// "no scheme" is the input an operator types by forgetting the scheme, and
		// it is the one this rule exists for. url.Parse reads its Scheme as
		// "dns.quad9.net", so a `Scheme == ""` test never fires on it -- which is
		// why the rule matches on the literal "://" the way mosdns does.
		{"no scheme", withAddr(ok, "dns.quad9.net:853"), "no transport"},
		{"no scheme, with port", withAddr(ok, "9.9.9.9:53"), "no transport"},
		{"unknown scheme", withAddr(ok, "sdns://dns.quad9.net"), "scheme"},
		{"credentials", withAddr(ok, "https://user:pw@dns.quad9.net/dns-query"), "credentials or query"},
		{"query", withAddr(ok, "https://dns.quad9.net/dns-query?a=b"), "credentials or query"},
		{"DoH with no path", withAddr(ok, "https://dns.quad9.net"), "DoH endpoint with no path"},
		{"DoH with a bare slash", withAddr(ok, "https://dns.quad9.net/"), "DoH endpoint with no path"},
		{"h3 with no path", withAddr(ok, "h3://dns.quad9.net"), "DoH endpoint with no path"},
		// A path on a non-HTTP scheme is a silent no-op in mosdns, which reads only
		// the host and the port, so refusing it here is refusing a typo that would
		// otherwise look like it worked.
		{"path on a DoT upstream", withAddr(ok, "tls://dns.quad9.net:853/oops"), "silently discarded"},
		{"loopback host", withAddr(ok, "tcp://127.0.0.1:5353"), "loopback"},
		{"unspecified host", withAddr(ok, "tcp://0.0.0.0:53"), "loopback"},
		// An unbracketed IPv6 literal cannot be told from a scheme by a colon, so
		// this one is refused as naming no transport -- which is the same outcome
		// the operator needs (it does not resolve) for a different stated reason.
		{"unbracketed IPv6", withAddr(ok, "fe80::1:53"), "no transport"},
		{"link-local host", withAddr(ok, "tcp://[fe80::1]:853"), "loopback"},
		{"link-local v4 host", withAddr(ok, "tcp://169.254.1.1:853"), "loopback"},
		{"port 53", withAddr(ok, "tcp://9.9.9.9:53"), "system resolver"},
		{"bootstrap loopback", withBootstrap(ok, "127.0.0.1:53"), "loopback"},
		{"bootstrap not IP:port", withBootstrap(ok, "9.9.9.9"), "IP address and a port"},
		{"dnscrypt with addr", ForeignUpstream{Kind: UpstreamKindDNSCrypt, Name: "d", Addr: "tcp://127.0.0.1:15353"}, "must not carry an addr"},
		{"upstream without addr", ForeignUpstream{Kind: UpstreamKindUpstream, Name: "u"}, "must carry an addr"},
		{"unknown kind", ForeignUpstream{Kind: "carrier-pigeon", Name: "p"}, "kind"},
		{"empty name", withAddr(ForeignUpstream{Kind: UpstreamKindUpstream, Addr: "quic://a.example:853"}, ""), "name"},
		{"bad name characters", withAddr(ForeignUpstream{Kind: UpstreamKindUpstream, Name: "Quad9 DoQ", Addr: "quic://a.example:853"}, ""), "name"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			err := ValidateOneUpstream(c.entry)
			if c.wants == "" {
				if err != nil {
					t.Fatalf("rule %q should have accepted %+v: %v", c.rule, c.entry, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("rule %q accepted %+v", c.rule, c.entry)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("rule %q refused %+v for the wrong reason: %v", c.rule, c.entry, err)
			}
		})
	}
}

func TestAWellFormedEntryIsAccepted(t *testing.T) {
	enabled := false
	for _, entry := range []ForeignUpstream{
		{Kind: UpstreamKindDNSCrypt, Name: "quad9-dnscrypt"},
		{Kind: UpstreamKindUpstream, Name: "quad9-doq", Addr: "quic://dns.quad9.net:853",
			Bootstrap: []string{"9.9.9.9:53"}},
		{Kind: UpstreamKindUpstream, Name: "off", Addr: "tls://dns.quad9.net:853", Enabled: &enabled},
		// A DoH endpoint REQUIRES its path, because mosdns passes the whole URL
		// through as the endpoint (upstream.go:474). An earlier version of this
		// validation refused every URL carrying a path, which would have refused
		// every real DoH configuration in existence.
		{Kind: UpstreamKindUpstream, Name: "by-ip", Addr: "https://9.9.9.9/dns-query"},
		{Kind: UpstreamKindUpstream, Name: "bare-ok", Addr: "tcp://[2606:4700:4700::1111]:853"},
	} {
		if err := ValidateOneUpstream(entry); err != nil {
			t.Errorf("a well-formed entry was refused: %+v: %v", entry, err)
		}
	}
}

func TestADisabledEntryStillHasToBeWellFormed(t *testing.T) {
	// A disabled entry with a malformed address is refused, and that is the safe
	// direction: an operator who disables an entry and later re-enables it by
	// flipping one word should not find a configuration that cannot be rendered.
	disabled := false
	err := ValidateOneUpstream(ForeignUpstream{
		Kind: UpstreamKindUpstream, Name: "broken", Addr: "sdns://x", Enabled: &disabled,
	})
	if err == nil {
		t.Fatal("a disabled entry with an unusable addr was accepted, so re-enabling it " +
			"by one word would produce a policy that cannot be rendered")
	}
}

func withAddr(u ForeignUpstream, addr string) ForeignUpstream { u.Addr = addr; return u }

func withBootstrap(u ForeignUpstream, addr string) ForeignUpstream {
	u.Bootstrap = []string{addr}
	return u
}

func TestTheListRulesRefuseWhatASingleEntryCannot(t *testing.T) {
	cases := []struct {
		rule  string
		list  []ForeignUpstream
		wants string
	}{
		{"empty list", nil, "at least one"},
		{"all disabled", []ForeignUpstream{disabledEntry(UpstreamKindDNSCrypt, "d", "")}, "at least one enabled"},
		{"two dnscrypt", []ForeignUpstream{
			{Kind: UpstreamKindDNSCrypt, Name: "a"}, {Kind: UpstreamKindDNSCrypt, Name: "b"},
		}, "at most one"},
		{"duplicate name", []ForeignUpstream{
			{Kind: UpstreamKindDNSCrypt, Name: "same"},
			{Kind: UpstreamKindUpstream, Name: "same", Addr: "quic://a.example:853"},
		}, "unique"},
		{"no ECH source", []ForeignUpstream{
			{Kind: UpstreamKindUpstream, Name: "doh", Addr: "https://dns.quad9.net/dns-query"},
		}, "ECH"},
		{"disabled dnscrypt and no tcp", []ForeignUpstream{
			disabledEntry(UpstreamKindDNSCrypt, "d", ""),
			{Kind: UpstreamKindUpstream, Name: "doh", Addr: "https://dns.quad9.net/dns-query"},
		}, "ECH"},
		{"DoQ only, nothing ECH-capable", []ForeignUpstream{
			{Kind: UpstreamKindUpstream, Name: "doq", Addr: "quic://dns.quad9.net:853"},
			{Kind: UpstreamKindUpstream, Name: "doh", Addr: "https://dns.quad9.net/dns-query"},
		}, "ECH"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			err := ValidateForeignUpstreams(c.list)
			if err == nil {
				t.Fatalf("rule %q accepted %+v", c.rule, c.list)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("rule %q refused for the wrong reason: %v", c.rule, err)
			}
		})
	}
}

func TestADisabledTCPUpstreamDoesNotBecomeTheECHSource(t *testing.T) {
	// Review Focus #1, in the form that matters: a tcp:// entry that is switched
	// off must not be what ECH is fetched through, because the switch is the
	// operator saying "do not use this".
	list := []ForeignUpstream{
		disabledEntry(UpstreamKindUpstream, "off", "tcp://9.9.9.9:5353"),
		{Kind: UpstreamKindDNSCrypt, Name: "on"},
	}
	if got := ECHSource(list, "tcp://127.0.0.1:15353"); got != "tcp://127.0.0.1:15353" {
		t.Fatalf("the ECH source is %q, want the enabled dnscrypt entry's listener", got)
	}
}

func TestTheECHSourceIsTheListenerOrTheFirstEnabledTCPUpstream(t *testing.T) {
	listener := "tcp://127.0.0.1:15353"
	cases := []struct {
		name string
		list []ForeignUpstream
		want string
	}{
		{"dnscrypt wins while enabled", []ForeignUpstream{
			{Kind: UpstreamKindDNSCrypt, Name: "d"},
			{Kind: UpstreamKindUpstream, Name: "t", Addr: "tcp://9.9.9.9:5353"},
		}, listener},
		{"falls to the first tcp when dnscrypt is off", []ForeignUpstream{
			disabledEntry(UpstreamKindDNSCrypt, "d", ""),
			{Kind: UpstreamKindUpstream, Name: "doh", Addr: "https://dns.quad9.net/dns-query"},
			{Kind: UpstreamKindUpstream, Name: "t1", Addr: "tcp://9.9.9.9:5353"},
			{Kind: UpstreamKindUpstream, Name: "t2", Addr: "tcp://1.1.1.1:5353"},
		}, "tcp://9.9.9.9:5353"},
		{"a udp entry is never the source", []ForeignUpstream{
			{Kind: UpstreamKindUpstream, Name: "u", Addr: "udp://9.9.9.9:53"},
			{Kind: UpstreamKindUpstream, Name: "t", Addr: "tcp://9.9.9.9:5353"},
		}, "tcp://9.9.9.9:5353"},
		// **This row is why the table has a disabled entry in the middle of it.**
		// Every other row's answer is decided by Kind and Addr alone, so a
		// derivation that ignored `enabled` entirely would still get all of them
		// right. This one has a DISABLED tcp entry ahead of the answer, so an
		// implementation that forgot the switch would pick 9.9.9.9 and this row is
		// the only thing that catches it. (It did not, on the first run: the
		// disabled-entry case elsewhere in this file puts the disabled entry where
		// the dnscrypt entry's own loop answers first, which hides the bug.)
		{"a disabled tcp entry ahead of the answer", []ForeignUpstream{
			disabledEntry(UpstreamKindDNSCrypt, "d", ""),
			disabledEntry(UpstreamKindUpstream, "off-first", "tcp://9.9.9.9:5353"),
			disabledEntry(UpstreamKindUpstream, "off-second", "tcp://1.0.0.1:5353"),
			{Kind: UpstreamKindUpstream, Name: "on", Addr: "tcp://1.1.1.1:5353"},
		}, "tcp://1.1.1.1:5353"},
		{"nothing to choose from", []ForeignUpstream{
			{Kind: UpstreamKindUpstream, Name: "u", Addr: "udp://9.9.9.9:53"},
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ECHSource(c.list, listener); got != c.want {
				t.Fatalf("ECHSource = %q, want %q", got, c.want)
			}
		})
	}
}

func disabledEntry(kind UpstreamKind, name, addr string) ForeignUpstream {
	off := false
	return ForeignUpstream{Kind: kind, Name: name, Addr: addr, Enabled: &off}
}

func TestConcurrentIsBoundedByWhatMosdnsItselfEnforces(t *testing.T) {
	for _, value := range []int{0, -1, 4, 100} {
		policy := Defaults()
		policy.Foreign.Concurrent = value
		if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "foreign.concurrent") {
			t.Errorf("foreign.concurrent = %d was accepted or refused for the wrong reason: %v", value, err)
		}
	}
	for _, value := range []int{1, 2, 3} {
		policy := Defaults()
		policy.Foreign.Concurrent = value
		if err := policy.Validate(); err != nil {
			t.Errorf("foreign.concurrent = %d was refused: %v", value, err)
		}
	}
}

func TestTheCacheBlockIsBoundedToo(t *testing.T) {
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.ForeignCache.Size = 0 },
		func(p *Policy) { p.ForeignCache.TTLMax = -1 },
		func(p *Policy) { p.ForeignCache.TTLMin = -1 },
	} {
		policy := Defaults()
		mutate(&policy)
		if err := policy.Validate(); err == nil {
			t.Errorf("a cache block with %+v was accepted", policy.ForeignCache)
		}
	}
}

// The default ECH source is the packaged listener, and it stays that way even
// though a tcp:// upstream could be present.
func TestTheDefaultECHRouteIsThePackagedResolver(t *testing.T) {
	policy := Defaults()
	got := ECHSource(policy.Foreign.Upstreams, "tcp://127.0.0.1:15353")
	if got != "tcp://127.0.0.1:15353" {
		t.Fatalf("the default ECH source is %q, want the packaged resolver's listener", got)
	}
}

// **The case the dry run of this task found.** An earlier ECHSource required a
// non-empty dnscrypt listener before it would choose the dnscrypt entry, and
// ValidateForeignUpstreams calls it with "" because it has no listener in hand.
// The result was that rule 7 could never be satisfied by a list containing a
// dnscrypt entry -- which is every default policy -- so Defaults().Validate()
// failed with ErrNoECHSource.
func TestTheDefaultPolicySatisfiesTheNoECHSourceRule(t *testing.T) {
	if err := ValidateForeignUpstreams(Defaults().Foreign.Upstreams); err != nil {
		t.Fatalf("the shipped route was refused by the very rule that exists to protect "+
			"it: %v", err)
	}
}

// The whole default policy has to validate, not just the upstream list: the other
// rules this task added (concurrent, foreign_cache) are in the same Validate.
func TestTheDefaultPolicyValidates(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("Defaults() does not validate: %v", err)
	}
}

// mosdns reads ONE bootstrap per upstream, and the way it reads it makes two a
// malformed address rather than a list: parseBootstrapAp splits the port off and
// calls netip.ParseAddr on the rest (pkg/upstream/utils.go:77-90). So a second
// resolver has to be a second entry, and this case says so rather than leaving the
// operator to find out at startup.
func TestTwoBootstrapsAreRefusedBecauseMosdnsReadsOnlyOne(t *testing.T) {
	entry := ForeignUpstream{
		Kind: UpstreamKindUpstream, Name: "doq", Addr: "quic://dns.quad9.net:853",
		Bootstrap: []string{"9.9.9.9:53", "149.112.112.9:53"},
	}
	err := ValidateOneUpstream(entry)
	if err == nil {
		t.Fatal("two bootstraps were accepted, so they render into one comma-joined " +
			"string that mosdns refuses as a malformed address")
	}
	for _, want := range []string{"ONE", "utils.go:77-90"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so an operator cannot tell that "+
				"the limit is mosdns's rather than arbitrary: %v", want, err)
		}
	}
}
