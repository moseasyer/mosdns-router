package dnsrewrite

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"mosdns-router/internal/dnsclassify"
)

// The fixtures below are whole responses rather than answer fragments, because
// what Address promises is about the message a client receives: one address, the
// chain that reached it kept, the sections it never owned kept, and the header
// untouched apart from the AD bit. Every expectation is written out as a literal
// address, name, class and TTL, so a rewritten answer can be compared against
// what a resolver's contract says it must be rather than against whatever the
// implementation produced.

// selectedIP is the address a selector would publish. It is in the TEST-NET-3
// documentation range, so no test here can reach a real host.
const selectedIP = "203.0.113.9"

func selected() netip.Addr {
	return netip.MustParseAddr(selectedIP)
}

func answerA(name, address string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(address),
	}
}

func answerAAAA(name, address string, ttl uint32) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(address),
	}
}

func answerCNAME(from, to string, ttl uint32) *dns.CNAME {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: from, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
		Target: to,
	}
}

func answerSOA() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.net.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 900},
		Ns:      "ns1.example.net.",
		Mbox:    "hostmaster.example.net.",
		Serial:  2026092501,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  300,
	}
}

func answerOPT() *dns.OPT {
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.SetDo()
	return opt
}

// response builds the answer a recursive resolver hands back for one question.
func response(qname string, qtype uint16, answers ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Answer = answers
	return msg
}

// publishedRanges is the argument a Cloudflare rewrite is checked against. The
// addresses it names are the ones the fixtures below answer with, and the ones
// they must never be able to answer with.
func publishedRanges() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("104.16.0.0/13"),
		netip.MustParsePrefix("172.64.0.0/13"),
	}
}

// cloudflareInput is the authorization a plugin passes once dnsclassify has
// accepted a response: the provider group, the exact terminal owner it walked to,
// the published ranges it checked against, and the address the selector published.
func cloudflareInput(msg *dns.Msg, terminal string) AddressInput {
	return AddressInput{
		Response:     msg,
		QType:        msg.Question[0].Qtype,
		Provider:     "cloudflare",
		TerminalName: terminal,
		Prefixes:     publishedRanges(),
		Selected:     selected(),
	}
}

func packed(t *testing.T, msg *dns.Msg) []byte {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	return wire
}

// answered renders whatever a call returned, for a failure message. A caller that
// was refused gets no message and a caller that was served gets one, so a test
// that reports the wrong one has to be able to print either without dereferencing
// the one it did not get.
func answered(msg *dns.Msg) string {
	if msg == nil {
		return "no message"
	}
	parts := make([]string, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		parts = append(parts, rr.String())
	}
	return strings.Join(parts, "; ")
}

// answerAddresses lists the IPv4 addresses in an answer section, in order, as
// dotted quads. An empty list is what a suppressed or replaced A RRset leaves.
func answerAddresses(msg *dns.Msg) []string {
	out := []string{}
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}

func answerNames(msg *dns.Msg) []string {
	out := []string{}
	for _, rr := range msg.Answer {
		out = append(out, rr.Header().Name)
	}
	return out
}

func answerTypes(msg *dns.Msg) []uint16 {
	out := []uint16{}
	for _, rr := range msg.Answer {
		out = append(out, rr.Header().Rrtype)
	}
	return out
}

func nsTypes(msg *dns.Msg) []uint16 {
	out := []uint16{}
	for _, rr := range msg.Ns {
		out = append(out, rr.Header().Rrtype)
	}
	return out
}

// TestAddressReplacesEveryAddressOfADirectAnswerWithTheSelectedOne is the whole
// point of the package in one response: two published addresses become the one
// address the selector proved, and the TTL the client is handed is the shorter of
// the two it was going to be handed anyway. A synthesized constant TTL, or the
// first record's TTL, fails this.
func TestAddressReplacesEveryAddressOfADirectAnswerWithTheSelectedOne(t *testing.T) {
	msg := response("cdn.example.", dns.TypeA,
		answerA("cdn.example.", "104.16.1.1", 300),
		answerA("cdn.example.", "104.16.2.2", 120),
	)
	msg.Ns = []dns.RR{answerSOA()}
	msg.Extra = []dns.RR{answerOPT()}

	got, err := Address(cloudflareInput(msg, "cdn.example."))
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	if addresses := answerAddresses(got); len(addresses) != 1 || addresses[0] != selectedIP {
		t.Fatalf("answer addresses = %v, want exactly [%s]", addresses, selectedIP)
	}
	rewritten, ok := got.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer[0] is %T, want *dns.A", got.Answer[0])
	}
	if rewritten.Hdr.Name != "cdn.example." {
		t.Fatalf("rewritten owner = %q, want %q", rewritten.Hdr.Name, "cdn.example.")
	}
	if rewritten.Hdr.Class != dns.ClassINET {
		t.Fatalf("rewritten class = %d, want %d", rewritten.Hdr.Class, dns.ClassINET)
	}
	if rewritten.Hdr.Rrtype != dns.TypeA {
		t.Fatalf("rewritten type = %d, want %d", rewritten.Hdr.Rrtype, dns.TypeA)
	}
	if rewritten.Hdr.Ttl != 120 {
		t.Fatalf("rewritten TTL = %d, want 120, the minimum of the replaced records", rewritten.Hdr.Ttl)
	}
	if types := nsTypes(got); len(types) != 1 || types[0] != dns.TypeSOA {
		t.Fatalf("authority types = %v, want [SOA] untouched", types)
	}
	if len(got.Extra) != 1 || got.Extra[0].Header().Rrtype != dns.TypeOPT {
		t.Fatalf("additional section = %v, want the OPT record untouched", got.Extra)
	}
	if !got.RecursionAvailable {
		t.Fatal("the RA bit was cleared by a rewrite that only owns one RRset")
	}
}

// TestAddressKeepsTheChainAndReplacesOnlyItsTerminalAddress pins the difference
// between a rewrite and a replacement: the CNAMEs a client has to follow are the
// address the CDN chose, not this router's business, so they survive untouched,
// and the one new address is appended after them. The CNAME TTL of 600 is
// deliberately the longest in the message, so a TTL read from the wrong record is
// a failing test rather than an accident.
func TestAddressKeepsTheChainAndReplacesOnlyItsTerminalAddress(t *testing.T) {
	msg := response("cdn.example.", dns.TypeA,
		answerCNAME("cdn.example.", "edge.example.net.", 600),
		answerCNAME("edge.example.net.", "final.example.net.", 600),
		answerA("final.example.net.", "104.16.1.1", 300),
		answerA("final.example.net.", "104.16.2.2", 90),
	)

	got, err := Address(cloudflareInput(msg, "final.example.net."))
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	wantNames := []string{"cdn.example.", "edge.example.net.", "final.example.net."}
	names := answerNames(got)
	if len(names) != len(wantNames) {
		t.Fatalf("answer owner names = %v, want %v", names, wantNames)
	}
	for i := range wantNames {
		if names[i] != wantNames[i] {
			t.Fatalf("answer owner names = %v, want %v", names, wantNames)
		}
	}
	wantTypes := []uint16{dns.TypeCNAME, dns.TypeCNAME, dns.TypeA}
	types := answerTypes(got)
	for i := range wantTypes {
		if types[i] != wantTypes[i] {
			t.Fatalf("answer types = %v, want %v", types, wantTypes)
		}
	}
	if addresses := answerAddresses(got); len(addresses) != 1 || addresses[0] != selectedIP {
		t.Fatalf("answer addresses = %v, want exactly [%s]", addresses, selectedIP)
	}
	if got.Answer[2].Header().Ttl != 90 {
		t.Fatalf("rewritten TTL = %d, want 90, the minimum of the replaced terminal records", got.Answer[2].Header().Ttl)
	}
	// The two CNAMEs are the CDN's own records and a rewrite has no business
	// changing them, so they are compared as text against the originals.
	for i, rr := range msg.Answer[:2] {
		if got.Answer[i].String() != rr.String() {
			t.Fatalf("preserved record %d = %s, want the original %s", i, got.Answer[i], rr)
		}
	}
}

// TestAddressKeepsTheOwnerNameAsTheAnswerSpelledIt pins one detail a rewrite
// cannot afford to normalise: the owner name of the RRset it replaces is carried
// over as the answer spelled it, because a client that compares names case
// insensitively is fine either way and a log that compares them literally is not.
func TestAddressKeepsTheOwnerNameAsTheAnswerSpelledIt(t *testing.T) {
	msg := response("CDN.Example.com.", dns.TypeA,
		answerA("cdn.Example.com.", "104.16.1.1", 300),
	)

	got, err := Address(cloudflareInput(msg, "CDN.Example.com."))
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	if len(got.Answer) != 1 {
		t.Fatalf("answer = %v, want the one rewritten record", got.Answer)
	}
	if got.Answer[0].Header().Name != "cdn.Example.com." {
		t.Fatalf("rewritten owner = %q, want %q, the spelling the answer used", got.Answer[0].Header().Name, "cdn.Example.com.")
	}
}

// TestAddressNeverMutatesTheResponseItIsGiven is the clone contract. The caller
// is a plugin in front of a cache that owns the object, so a rewrite applied in
// place corrupts the next reader. The message is packed before and after and
// compared byte for byte, which catches a mutation that restores the answer but
// not some other field. Each sub-case also says what Address owes the caller --
// a message of its own, or none at all beside the error -- so the two halves of
// the contract cannot both be satisfied by one absence.
func TestAddressNeverMutatesTheResponseItIsGiven(t *testing.T) {
	tests := []struct {
		name string
		// build returns the message and the input for one case, so the input
		// always carries the very message the case asserts is untouched.
		build func() (*dns.Msg, AddressInput)
		// wantRewrite is what the call owes the caller: a rewritten message that
		// is not the one it was handed, or no message beside an error.
		wantRewrite bool
	}{
		{
			name: "a rewritten direct answer",
			build: func() (*dns.Msg, AddressInput) {
				msg := response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300))
				return msg, cloudflareInput(msg, "cdn.example.")
			},
			wantRewrite: true,
		},
		{
			name: "a refused rewrite",
			build: func() (*dns.Msg, AddressInput) {
				msg := response("other-distribution.example.", dns.TypeA, answerA("other-distribution.example.", "203.0.113.40", 300))
				return msg, AddressInput{
					Response:     msg,
					QType:        dns.TypeA,
					Provider:     "cloudfront",
					Hostname:     "distribution.example",
					TerminalName: "other-distribution.example.",
					Selected:     selected(),
				}
			},
			wantRewrite: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, in := tt.build()
			before := packed(t, msg)

			got, err := Address(in)

			if after := packed(t, msg); string(after) != string(before) {
				t.Fatalf("the response handed to Address changed:\n before %s\n after  %s", before, after)
			}
			if !tt.wantRewrite {
				if err == nil {
					t.Fatalf("the call was expected to be refused and answered %s", answered(got))
				}
				if got != nil {
					t.Fatalf("a refused call returned a message beside its error: %s", answered(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("Address: %v", err)
			}
			if got == nil {
				t.Fatal("Address reported a rewrite and returned no message")
			}
			if got == msg {
				t.Fatal("Address returned the message it was given, so the rewrite was applied in place")
			}
		})
	}
}

// TestAddressSuppressesAAAAForTheQuestionAndChainOnly is the blanket-filter trap.
// The answer carries an AAAA at the question name, a stray AAAA at the CNAME
// owner, and an AAAA belonging to a name this question never reaches. The first
// two are what a rewritten A suppresses; the third belongs to somebody else and
// removing it would corrupt an unrelated record set in the same message.
func TestAddressSuppressesAAAAForTheQuestionAndChainOnly(t *testing.T) {
	msg := response("cdn.example.", dns.TypeA,
		answerCNAME("cdn.example.", "edge.example.net.", 300),
		answerAAAA("cdn.example.", "2606:4700::1111", 300),
		answerA("edge.example.net.", "104.16.1.1", 300),
		answerAAAA("edge.example.net.", "2606:4700::2222", 300),
		answerAAAA("unrelated.example.", "2001:db8::1", 300),
	)
	in := cloudflareInput(msg, "edge.example.net.")
	in.SuppressAAAA = true

	got, err := Address(in)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	for _, rr := range got.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA && rr.Header().Name != "unrelated.example." {
			t.Fatalf("an AAAA record survived at %q: %s", rr.Header().Name, rr)
		}
	}
	if n := countType(got.Answer, dns.TypeAAAA); n != 1 {
		t.Fatalf("%d AAAA records survived, want only the one belonging to the unrelated name", n)
	}
	var unrelated *dns.AAAA
	for _, rr := range got.Answer {
		if record, ok := rr.(*dns.AAAA); ok {
			unrelated = record
		}
	}
	if unrelated == nil || unrelated.Hdr.Name != "unrelated.example." {
		t.Fatalf("the AAAA record that survived belongs to %v, want the one at unrelated.example.", answerNames(got))
	}
	if addresses := answerAddresses(got); len(addresses) != 1 || addresses[0] != selectedIP {
		t.Fatalf("answer addresses = %v, want exactly [%s]", addresses, selectedIP)
	}
}

// TestAddressKeepsAAAAWhenSuppressionIsOff is the same fixture with the caller's
// switch in the other position, because a suppression that cannot be turned off
// is a policy the operator does not have.
func TestAddressKeepsAAAAWhenSuppressionIsOff(t *testing.T) {
	msg := response("cdn.example.", dns.TypeA,
		answerA("cdn.example.", "104.16.1.1", 300),
		answerAAAA("cdn.example.", "2606:4700::1111", 300),
	)

	got, err := Address(cloudflareInput(msg, "cdn.example."))
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	seen := false
	for _, rr := range got.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("the AAAA record was removed with SuppressAAAA off: %s", answered(got))
	}
}

// TestAddressEmptiesTheAnswerOfAnAAAAQuestionWhenSuppressionIsOn is the AAAA
// query: a client that asked for IPv6 gets an empty NOERROR rather than an
// address this router has not proved can serve IPv6, and no A record is invented
// in an answer to a question about IPv6.
func TestAddressEmptiesTheAnswerOfAnAAAAQuestionWhenSuppressionIsOn(t *testing.T) {
	msg := response("cdn.example.", dns.TypeAAAA,
		answerCNAME("cdn.example.", "edge.example.net.", 300),
		answerAAAA("edge.example.net.", "2606:4700::2222", 300),
	)
	in := cloudflareInput(msg, "edge.example.net.")
	in.SuppressAAAA = true

	got, err := Address(in)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	wantTypes := []uint16{dns.TypeCNAME}
	types := answerTypes(got)
	if len(types) != len(wantTypes) {
		t.Fatalf("answer types = %v, want %v", types, wantTypes)
	}
	for i := range wantTypes {
		if types[i] != wantTypes[i] {
			t.Fatalf("answer types = %v, want %v", types, wantTypes)
		}
	}
	if addresses := answerAddresses(got); len(addresses) != 0 {
		t.Fatalf("answer addresses = %v, want none in an answer to an AAAA question", addresses)
	}
}

// TestAddressKeepsTheAAAAOfAnotherNameOnTheAAAAQuestionPath is the same scope
// rule on the suppression-only path, where there is no address replacement to
// carry it. The answer to the AAAA question holds an AAAA at the terminal the
// walk reached and an AAAA belonging to a name this question never reaches; the
// first is what suppression empties and the second is not this call's to remove.
func TestAddressKeepsTheAAAAOfAnotherNameOnTheAAAAQuestionPath(t *testing.T) {
	msg := response("cdn.example.", dns.TypeAAAA,
		answerCNAME("cdn.example.", "edge.example.net.", 300),
		answerAAAA("edge.example.net.", "2606:4700::2222", 300),
		answerAAAA("unrelated.example.", "2001:db8::1", 300),
	)
	in := cloudflareInput(msg, "edge.example.net.")
	in.SuppressAAAA = true

	got, err := Address(in)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	if n := countType(got.Answer, dns.TypeAAAA); n != 1 {
		t.Fatalf("%d AAAA records survived, want only the one belonging to the unrelated name", n)
	}
	kept := got.Answer[len(got.Answer)-1]
	record, ok := kept.(*dns.AAAA)
	if !ok {
		t.Fatalf("the last answer record is %T, want the AAAA of the unrelated name", kept)
	}
	if record.Hdr.Name != "unrelated.example." {
		t.Fatalf("the AAAA that survived belongs to %q, want the one at unrelated.example.", record.Hdr.Name)
	}
	if addresses := answerAddresses(got); len(addresses) != 0 {
		t.Fatalf("answer addresses = %v, want none in an answer to an AAAA question", addresses)
	}
}

// TestAddressLeavesAnAnswerWithNothingToSuppressUntouched covers the AAAA
// question whose answer is already empty: a message this function does not
// change is handed back exactly as it arrived, because the caller then has one
// path for "no rewrite" and one for "rewritten".
func TestAddressLeavesAnAnswerWithNothingToSuppressUntouched(t *testing.T) {
	msg := response("cdn.example.", dns.TypeAAAA, answerCNAME("cdn.example.", "edge.example.net.", 300))
	in := cloudflareInput(msg, "edge.example.net.")
	in.SuppressAAAA = true

	got, err := Address(in)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	if got != msg {
		t.Fatalf("Address returned a rewritten message where there was nothing to suppress: %s", answered(got))
	}
}

// TestAddressRefusesTheAddressesItCannotInstall is the refusal table. An IPv6
// selection is a refusal and not a no-op, because a caller that silently got
// nothing back would believe a rewrite happened; the rest are addresses that must
// never become a client's answer, whatever the selector file says.
func TestAddressRefusesTheAddressesItCannotInstall(t *testing.T) {
	tests := []struct {
		name     string
		selected netip.Addr
	}{
		{name: "an IPv6 address", selected: netip.MustParseAddr("2606:4700::1111")},
		{name: "an IPv4-mapped IPv6 address", selected: netip.MustParseAddr("::ffff:203.0.113.9")},
		{name: "an IPv6 address with a zone", selected: netip.MustParseAddr("fe80::1%eth0")},
		{name: "a loopback address", selected: netip.MustParseAddr("127.0.0.1")},
		{name: "a private address", selected: netip.MustParseAddr("10.1.2.3")},
		{name: "a carrier NAT address", selected: netip.MustParseAddr("100.64.0.1")},
		{name: "a link-local address", selected: netip.MustParseAddr("169.254.1.1")},
		{name: "a multicast address", selected: netip.MustParseAddr("224.0.1.1")},
		{name: "the unspecified address", selected: netip.MustParseAddr("0.0.0.0")},
		{name: "no address at all", selected: netip.Addr{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300))
			in := cloudflareInput(msg, "cdn.example.")
			in.Selected = tt.selected

			got, err := Address(in)
			if err == nil {
				t.Fatalf("Address accepted %s and answered %s", tt.selected, answered(got))
			}
			if got != nil {
				t.Fatalf("Address returned a message beside the error: %s", answered(got))
			}
			if after := packed(t, msg); len(answerAddresses(msg)) != 1 || answerAddresses(msg)[0] != "104.16.1.1" {
				t.Fatalf("the refused call changed the response: %s", after)
			}
		})
	}
}

// TestAddressRefusesARecordSetItCannotReplace pins the TTL rule and the malformed
// record beside it. A TTL of zero is what an answer with no usable lifetime looks
// like, and defaulting it would be a claim this router cannot support; a record
// with no address in it is not an address at all.
func TestAddressRefusesARecordSetItCannotReplace(t *testing.T) {
	tests := []struct {
		name string
		rr   dns.RR
	}{
		{name: "a record with no TTL", rr: answerA("cdn.example.", "104.16.1.1", 0)},
		{name: "a record with no address", rr: &dns.A{Hdr: dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := response("cdn.example.", dns.TypeA, tt.rr)

			got, err := Address(cloudflareInput(msg, "cdn.example."))
			if err == nil {
				t.Fatalf("Address accepted %s and answered %s", tt.rr, answered(got))
			}
			if got != nil {
				t.Fatalf("Address returned a message beside the error: %s", answered(got))
			}
		})
	}
}

// TestAddressRefusesACloudFrontMappingForAResponseTheRangesCallCloudflare closes
// the last gap between the two provider paths. A CloudFront mapping is authorised
// by a hostname and nothing else, because there is no range list that says which
// networks serve a distribution. That makes the CloudFront arm the one arm with
// no cross-check -- until this one: a response whose own addresses are all inside
// the published Cloudflare ranges says it is Cloudflare-served, and no
// per-hostname mapping may claim it. Without this, a Task 5 that mislabels such a
// response `cloudfront` would replace a Cloudflare answer with a CloudFront
// address, which is the wrong CDN for the name and the one mistake the exact
// hostname rule cannot catch.
//
// The case is deliberately the inverse of the CloudFront fixtures above: those
// answer with 203.0.113.40, which is in no published range, and they must keep
// working with the ranges supplied.
func TestAddressRefusesACloudFrontMappingForAResponseTheRangesCallCloudflare(t *testing.T) {
	msg := response("distribution.example.", dns.TypeA,
		answerCNAME("distribution.example.", "d111111abcdef8.cloudfront.net.", 300),
		answerA("d111111abcdef8.cloudfront.net.", "104.16.1.1", 300),
	)
	in := AddressInput{
		Response:     msg,
		QType:        dns.TypeA,
		Provider:     "cloudfront",
		Hostname:     "distribution.example",
		TerminalName: "d111111abcdef8.cloudfront.net.",
		Prefixes:     publishedRanges(),
		Selected:     selected(),
	}
	if !dnsclassify.Cloudflare(msg, publishedRanges()).AllMatch {
		t.Fatal("the fixture is not a Cloudflare response, so it does not test the cross-check")
	}
	before := packed(t, msg)

	got, err := Address(in)
	if err == nil {
		t.Fatalf("a CloudFront mapping rewrote a response the published ranges call Cloudflare: %s", answered(got))
	}
	if got != nil {
		t.Fatal("Address returned a message beside the error")
	}
	if after := packed(t, msg); string(after) != string(before) {
		t.Fatalf("the response changed:\n before %s\n after  %s", before, after)
	}
}

// TestAddressUsesTheCloudFrontMappingOnlyForTheExactHostname is the second
// review focus: a per-hostname mapping is proved for one distribution and means
// nothing for a sibling distribution, for a name below it, or for the parent
// that merely ends with the same label. Each of those is a refusal rather than a
// rewrite of somebody else's CDN.
func TestAddressUsesTheCloudFrontMappingOnlyForTheExactHostname(t *testing.T) {
	tests := []struct {
		name       string
		qname      string
		hostname   string
		terminal   string
		wantErr    bool
		wantAnswer []string
	}{
		{
			name:       "the configured hostname",
			qname:      "distribution.example.",
			hostname:   "distribution.example",
			terminal:   "d111111abcdef8.cloudfront.net.",
			wantAnswer: []string{selectedIP},
		},
		{
			name:     "a sibling hostname",
			qname:    "other-distribution.example.",
			hostname: "distribution.example",
			terminal: "d222222abcdef8.cloudfront.net.",
			wantErr:  true,
		},
		{
			name:     "a name below the configured hostname",
			qname:    "www.distribution.example.",
			hostname: "distribution.example",
			terminal: "d333333abcdef8.cloudfront.net.",
			wantErr:  true,
		},
		{
			name:     "the parent of the configured hostname",
			qname:    "example.",
			hostname: "distribution.example",
			terminal: "d444444abcdef8.cloudfront.net.",
			wantErr:  true,
		},
		{
			name:     "a hostname that only shares a suffix",
			qname:    "notdistribution.example.",
			hostname: "distribution.example",
			terminal: "d555555abcdef8.cloudfront.net.",
			wantErr:  true,
		},
		{
			name:       "the same hostname spelled differently",
			qname:      "Distribution.Example.",
			hostname:   "distribution.example",
			terminal:   "d111111abcdef8.cloudfront.net.",
			wantAnswer: []string{selectedIP},
		},
		{
			name:     "no configured hostname at all",
			qname:    "distribution.example.",
			terminal: "d111111abcdef8.cloudfront.net.",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := response(tt.qname, dns.TypeA,
				answerCNAME(tt.qname, tt.terminal, 300),
				answerA(tt.terminal, "203.0.113.40", 300),
			)
			// The published ranges are supplied on purpose. The rewriter
			// cross-checks a CloudFront mapping against them, and a fixture whose
			// answer is in no published range is what proves the cross-check does
			// not fire on a real distribution answer.
			if verdict := dnsclassify.Cloudflare(msg, publishedRanges()); verdict.AllMatch {
				t.Fatalf("the fixture is a Cloudflare response, so it cannot test a CloudFront mapping: %+v", verdict)
			}
			in := AddressInput{
				Response:     msg,
				QType:        dns.TypeA,
				Provider:     "cloudfront",
				Hostname:     tt.hostname,
				TerminalName: tt.terminal,
				Prefixes:     publishedRanges(),
				Selected:     selected(),
			}

			got, err := Address(in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("a mapping for %q rewrote %q: %s", tt.hostname, tt.qname, answered(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("Address: %v", err)
			}
			addresses := answerAddresses(got)
			if len(addresses) != len(tt.wantAnswer) {
				t.Fatalf("answer addresses = %v, want %v", addresses, tt.wantAnswer)
			}
			for i := range tt.wantAnswer {
				if addresses[i] != tt.wantAnswer[i] {
					t.Fatalf("answer addresses = %v, want %v", addresses, tt.wantAnswer)
				}
			}
		})
	}
}

// TestAddressIgnoresAHostnameOnTheGlobalCloudflarePath states the other half of
// the rule above: a Cloudflare rewrite is global, decided by the prefixes, so a
// hostname left in a shared configuration cannot make it narrower. The caller's
// verdict for that path is the classification, and it is already in hand.
func TestAddressIgnoresAHostnameOnTheGlobalCloudflarePath(t *testing.T) {
	msg := response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300))
	in := cloudflareInput(msg, "cdn.example.")
	in.Hostname = "distribution.example"

	got, err := Address(in)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	if addresses := answerAddresses(got); len(addresses) != 1 || addresses[0] != selectedIP {
		t.Fatalf("answer addresses = %v, want exactly [%s]", addresses, selectedIP)
	}
}

// TestAddressRefusesACallerItCannotConfirm is the authorization table. Each case
// is a mistake a plugin could make while wiring this together, and each one has
// to arrive as an error rather than as a rewritten answer: a message whose
// terminal owner is not the one that was classified, an empty one, a provider
// this release does not select, a question type this function does not own, a
// response whose question is not the question the caller is answering, and a
// response with no question to walk from.
func TestAddressRefusesACallerItCannotConfirm(t *testing.T) {
	direct := response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300))
	chained := response("cdn.example.", dns.TypeA,
		answerCNAME("cdn.example.", "edge.example.net.", 300),
		answerA("edge.example.net.", "104.16.1.1", 300),
	)
	looped := response("cdn.example.", dns.TypeA,
		answerCNAME("cdn.example.", "one.example.", 300),
		answerCNAME("one.example.", "cdn.example.", 300),
		answerA("cdn.example.", "104.16.1.1", 300),
	)
	chainAndAddress := response("cdn.example.", dns.TypeA,
		answerCNAME("cdn.example.", "edge.example.net.", 300),
		answerA("cdn.example.", "198.51.100.5", 300),
		answerA("edge.example.net.", "104.16.1.1", 300),
	)
	noQuestion := func() *dns.Msg {
		msg := new(dns.Msg)
		msg.Response = true
		msg.Answer = []dns.RR{answerA("cdn.example.", "104.16.1.1", 300)}
		return msg
	}()

	tests := []struct {
		name string
		in   AddressInput
	}{
		{
			name: "a terminal name this response does not carry",
			in:   cloudflareInput(direct, "edge.example.net."),
		},
		{
			name: "a terminal name that is only a link of the chain",
			in:   cloudflareInput(chained, "cdn.example."),
		},
		{
			name: "no terminal name",
			in: func() AddressInput {
				in := cloudflareInput(direct, "cdn.example.")
				in.TerminalName = ""
				return in
			}(),
		},
		{
			name: "a provider this release does not select",
			in: func() AddressInput {
				in := cloudflareInput(direct, "cdn.example.")
				in.Provider = "akamai"
				return in
			}(),
		},
		{
			name: "a question type this function does not own",
			in: func() AddressInput {
				in := cloudflareInput(direct, "cdn.example.")
				in.QType = dns.TypeHTTPS
				return in
			}(),
		},
		{
			name: "a response whose question is not the caller's question",
			in: func() AddressInput {
				in := cloudflareInput(direct, "cdn.example.")
				in.QType = dns.TypeAAAA
				return in
			}(),
		},
		{
			name: "a response with no question",
			in: AddressInput{
				Response:     noQuestion,
				QType:        dns.TypeA,
				Provider:     "cloudflare",
				TerminalName: "cdn.example.",
				Selected:     selected(),
			},
		},
		{
			name: "no response at all",
			in: func() AddressInput {
				in := cloudflareInput(direct, "cdn.example.")
				in.Response = nil
				return in
			}(),
		},
		{
			name: "a chain that loops",
			in:   cloudflareInput(looped, "cdn.example."),
		},
		{
			name: "a chain name that also carries an address",
			in:   cloudflareInput(chainAndAddress, "edge.example.net."),
		},
		{
			name: "no published ranges to check the response against",
			in: func() AddressInput {
				in := cloudflareInput(direct, "cdn.example.")
				in.Prefixes = nil
				return in
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Address(tt.in)
			if err == nil {
				t.Fatalf("Address accepted the input and answered %s", answered(got))
			}
			if got != nil {
				t.Fatalf("Address returned a message beside the error: %s", answered(got))
			}
		})
	}
}

// TestAResponseOutsideThePublishedPrefixesIsNeverRewritten runs the two packages
// the way a plugin runs them, on responses that belong to no CDN or to more than
// one, and against two kinds of caller. The first forwards the classification
// result as it stands, which after the refusal carries no provider and no name at
// all. The second is a caller that ignored the verdict and built the
// authorization itself, which is the mistake the rewriter has to survive: it holds
// a real provider label and a real terminal name, so nothing about its input looks
// wrong. Both must be refused, and in both cases the bytes the client receives
// must be the bytes the upstream sent.
//
// The second caller is the one that matters. A mixed response is exactly the case
// where replacing the pair of addresses with the preferred one would send every
// client to a network the answer never named.
func TestAResponseOutsideThePublishedPrefixesIsNeverRewritten(t *testing.T) {
	tests := []struct {
		name     string
		answer   []dns.RR
		terminal string
	}{
		{
			name: "a response that belongs to another network",
			answer: []dns.RR{
				answerCNAME("cdn.example.", "origin.example.net.", 300),
				answerA("origin.example.net.", "198.51.100.5", 300),
			},
			terminal: "origin.example.net.",
		},
		{
			name: "a response that names two networks",
			answer: []dns.RR{
				answerA("cdn.example.", "104.16.1.1", 300),
				answerA("cdn.example.", "198.51.100.5", 300),
			},
			terminal: "cdn.example.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := response("cdn.example.", dns.TypeA, tt.answer...)
			msg.AuthenticatedData = true
			before := packed(t, msg)

			result := dnsclassify.Cloudflare(msg, publishedRanges())
			if result.AllMatch {
				t.Fatalf("a response with a foreign address was classified as rewriteable: %+v", result)
			}

			for _, caller := range []struct {
				name string
				in   AddressInput
			}{
				{
					name: "a caller that forwards the classification result",
					in: AddressInput{
						Response:     msg,
						QType:        dns.TypeA,
						Provider:     result.Provider,
						TerminalName: result.TerminalName,
						Prefixes:     publishedRanges(),
						Selected:     selected(),
					},
				},
				{
					name: "a caller that ignored the verdict and named the Cloudflare group itself",
					in: AddressInput{
						Response:     msg,
						QType:        dns.TypeA,
						Provider:     "cloudflare",
						TerminalName: tt.terminal,
						Prefixes:     publishedRanges(),
						Selected:     selected(),
					},
				},
			} {
				got, err := Address(caller.in)
				if err == nil {
					t.Fatalf("%s rewrote a response the classification refused: %s", caller.name, answered(got))
				}
				if got != nil {
					t.Fatalf("%s was answered with a message beside its error", caller.name)
				}
			}
			if after := packed(t, msg); string(after) != string(before) {
				t.Fatalf("the response changed:\n before %s\n after  %s", before, after)
			}
			if !msg.AuthenticatedData {
				t.Fatal("AD was cleared on a response nothing rewrote")
			}
		})
	}
}
