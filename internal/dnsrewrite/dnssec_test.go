package dnsrewrite

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"mosdns-router/internal/dnsclassify"
)

// The DNSSEC rule this file holds to is all-or-nothing. A response this router
// changed cannot carry a signature over the records it replaced, and it cannot
// carry a denial of existence that was computed for the record set it replaced
// either: a validator that reads the NSEC and finds the address it is looking at
// is reading a proof that the answer should not contain. So a modified response
// drops every RRSIG and every NSEC/NSEC3 in the message, clears AD, and leaves
// CD exactly as the client sent it.

// signature builds an RRSIG covering one RRset. The signature bytes are
// synthetic: nothing here validates anything, and a rewrite must not start
// caring whether they would.
func signature(owner, covered string, typeCovered uint16, ttl uint32) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
		TypeCovered: typeCovered,
		Algorithm:   dns.ECDSAP256SHA256,
		Labels:      2,
		OrigTtl:     ttl,
		Expiration:  1780000000,
		Inception:   1770000000,
		KeyTag:      12345,
		SignerName:  "example.net.",
		Signature:   "AQIDBA==",
	}
}

func nsec(owner, next string, types ...uint16) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: next,
		TypeBitMap: types,
	}
}

func nsec3(owner string, hash uint8, iterations uint16, salt string, types ...uint16) *dns.NSEC3 {
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       hash,
		Flags:      0,
		Iterations: iterations,
		SaltLength: uint8(len(salt)),
		Salt:       salt,
		HashLength: 20,
		NextDomain: strings.Repeat("A", 32),
		TypeBitMap: types,
	}
}

// recordTypes lists the record types in a section, so a case can name exactly
// what it expects to be left and assert the absence of a type by name rather
// than by counting records.
func recordTypes(section []dns.RR) []uint16 {
	out := []uint16{}
	for _, rr := range section {
		out = append(out, rr.Header().Rrtype)
	}
	return out
}

func countType(section []dns.RR, typeCovered uint16) int {
	n := 0
	for _, rr := range section {
		if rr.Header().Rrtype == typeCovered {
			n++
		}
	}
	return n
}

func hasType(section []dns.RR, want uint16) bool {
	return countType(section, want) > 0
}

// signedResponse is a positive answer with a signature over it, a signed denial
// of existence in the authority section, and a signature the additional section
// carried for the zone's other records.
func signedResponse() *dns.Msg {
	msg := response("cdn.example.", dns.TypeA,
		answerA("cdn.example.", "104.16.1.1", 300),
		answerA("cdn.example.", "104.16.2.2", 300),
		signature("cdn.example.", "example.net.", dns.TypeA, 300),
	)
	msg.AuthenticatedData = true
	msg.Ns = []dns.RR{
		answerSOA(),
		nsec("example.net.", "example.org.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
		signature("example.net.", "example.net.", dns.TypeNSEC, 3600),
		nsec3("example.net.", 1, 0, "a1b2", dns.TypeA, dns.TypeRRSIG),
		signature("example.net.", "example.net.", dns.TypeDNSKEY, 3600),
	}
	msg.Extra = []dns.RR{answerOPT()}
	return msg
}

// TestStripModifiedDNSSECRemovesEveryProofFromEverySection puts a signature and
// a denial of existence in each section that can hold one and checks that none of
// them survives, while the records this function never owned do. A filter that
// looked at only the answer section, or only at the types covering the address
// records, fails here.
func TestStripModifiedDNSSECRemovesEveryProofFromEverySection(t *testing.T) {
	msg := signedResponse()

	StripModifiedDNSSEC(msg)

	for _, section := range []struct {
		name string
		rrs  []dns.RR
	}{
		{name: "answer", rrs: msg.Answer},
		{name: "authority", rrs: msg.Ns},
		{name: "additional", rrs: msg.Extra},
	} {
		for _, typeCovered := range []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3} {
			if n := countType(section.rrs, typeCovered); n != 0 {
				t.Errorf("%d record(s) of type %s survived in the %s section", n, dns.TypeToString[typeCovered], section.name)
			}
		}
	}
	if msg.AuthenticatedData {
		t.Error("AD survived a strip of a modified response")
	}
	wantAnswer := []uint16{dns.TypeA, dns.TypeA}
	gotAnswer := recordTypes(msg.Answer)
	if len(gotAnswer) != len(wantAnswer) {
		t.Fatalf("answer types = %v, want the two A records and nothing else", gotAnswer)
	}
	for i := range wantAnswer {
		if gotAnswer[i] != wantAnswer[i] {
			t.Fatalf("answer types = %v, want %v", gotAnswer, wantAnswer)
		}
	}
	if !hasType(msg.Ns, dns.TypeSOA) {
		t.Fatalf("authority section = %v, want the SOA kept", recordTypes(msg.Ns))
	}
	if len(msg.Extra) != 1 || msg.Extra[0].Header().Rrtype != dns.TypeOPT {
		t.Fatalf("additional section = %v, want the OPT record kept", recordTypes(msg.Extra))
	}
}

// TestStripModifiedDNSSECKeepsTheHeaderButTheADBit is the flag contract: the
// response still is the same response, and the client that asked for validation
// still gets to know the answer is unsigned rather than being told it validated.
func TestStripModifiedDNSSECKeepsTheHeaderButTheADBit(t *testing.T) {
	tests := []struct {
		name string
		msg  *dns.Msg
	}{
		{
			name: "a response with a proof to remove",
			msg:  signedResponse(),
		},
		{
			name: "a response with nothing signed in it",
			msg: func() *dns.Msg {
				msg := response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300))
				msg.AuthenticatedData = true
				return msg
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.msg
			id, rcode, authoritative, recursionDesired, checkingDisabled := msg.Id, msg.Rcode, msg.Authoritative, msg.RecursionDesired, msg.CheckingDisabled

			StripModifiedDNSSEC(msg)

			if msg.Id != id || msg.Rcode != rcode || msg.Authoritative != authoritative || msg.RecursionDesired != recursionDesired {
				t.Fatalf("the header changed: id %d->%d rcode %d->%d aa %v->%v rd %v->%v",
					id, msg.Id, rcode, msg.Rcode, authoritative, msg.Authoritative, recursionDesired, msg.RecursionDesired)
			}
			if msg.CheckingDisabled != checkingDisabled {
				t.Fatalf("CD was changed: %v -> %v", checkingDisabled, msg.CheckingDisabled)
			}
			if msg.AuthenticatedData {
				t.Fatal("AD is still set after a modified response was stripped")
			}
		})
	}
}

// TestStripModifiedDNSSECLeavesTheClientCheckingDisabledBit states the one header
// bit this function does not touch, in both positions. CD is the client's own
// statement that it will validate itself, and answering a different question than
// the client asked is not this router's decision to make.
func TestStripModifiedDNSSECLeavesTheClientCheckingDisabledBit(t *testing.T) {
	for _, checkingDisabled := range []bool{false, true} {
		msg := signedResponse()
		msg.CheckingDisabled = checkingDisabled

		StripModifiedDNSSEC(msg)

		if msg.CheckingDisabled != checkingDisabled {
			t.Fatalf("CD = %v, want the %v the client sent", msg.CheckingDisabled, checkingDisabled)
		}
	}
}

// TestAddressLeavesNoSignatureOnARewrittenResponse is the rule at the level the
// plugin meets it: a response this package rewrote carries no signature over its
// address records, no signature over an HTTPS record, and no denial of existence
// anywhere, and it no longer claims to be validated. The HTTPS record and its
// signature are in the answer because a client can ask for HTTPS and A in the
// same message over a transport that carries both, and a filter that only removed
// the signatures covering A and AAAA would leave that one behind.
func TestAddressLeavesNoSignatureOnARewrittenResponse(t *testing.T) {
	msg := signedResponse()
	msg.Answer = append(msg.Answer,
		&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: "cdn.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   "cdn.example.",
		}},
		signature("cdn.example.", "example.net.", dns.TypeHTTPS, 300),
		signature("cdn.example.", "example.net.", dns.TypeAAAA, 300),
		signature("cdn.example.", "example.net.", dns.TypeCNAME, 300),
	)
	msg.Ns = append(msg.Ns,
		signature("example.net.", "example.net.", dns.TypeNS, 3600),
		signature("example.net.", "example.net.", dns.TypeSOA, 3600),
	)

	got, err := Address(cloudflareInput(msg, "cdn.example."))
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	if got.AuthenticatedData {
		t.Error("a rewritten response still claims AD")
	}
	if got.CheckingDisabled {
		t.Error("CD was invented on a response whose client did not send it")
	}
	for _, section := range []struct {
		name string
		rrs  []dns.RR
	}{
		{name: "answer", rrs: got.Answer},
		{name: "authority", rrs: got.Ns},
		{name: "additional", rrs: got.Extra},
	} {
		for _, typeCovered := range []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3} {
			if n := countType(section.rrs, typeCovered); n != 0 {
				t.Errorf("%d record(s) of type %s survived in the %s section of a rewritten response", n, dns.TypeToString[typeCovered], section.name)
			}
		}
	}
	if !hasType(got.Answer, dns.TypeHTTPS) {
		t.Errorf("the HTTPS record was removed along with its signature: %v", recordTypes(got.Answer))
	}
	if addresses := answerAddresses(got); len(addresses) != 1 || addresses[0] != selectedIP {
		t.Errorf("answer addresses = %v, want exactly [%s]", addresses, selectedIP)
	}
	if len(got.Extra) != 1 || got.Extra[0].Header().Rrtype != dns.TypeOPT {
		t.Fatalf("the additional section of a rewritten response is %v, want the client's OPT record kept", recordTypes(got.Extra))
	}
	if !got.Extra[0].(*dns.OPT).Do() {
		t.Error("the client's DO bit was dropped, so it can no longer tell an unsigned answer from a signed one")
	}
}

// TestAResponseThePluginDidNotModifyKeepsItsDNSSECRecords is the other half of
// the rule, and the half that protects every name this router has no business
// touching. Two things must hold, and they are checked separately because a
// change in either is a different fault. The plugin's own gate: dnsclassify
// refuses this response, so Address is never called and the upstream's message
// is what the client receives. And the rewriter's own refusals: a call that
// changes nothing, whether it is refused or has nothing to do, must leave the
// signature, the denial of existence and the AD bit exactly where they were.
func TestAResponseThePluginDidNotModifyKeepsItsDNSSECRecords(t *testing.T) {
	msg := signedResponse()
	// One address outside the published ranges, so the classification refuses
	// the whole response. That is what "a response the plugin did not modify"
	// means here: not a response that happens to be unsigned, but one the gate
	// turned away, signature and all.
	msg.Answer = append(msg.Answer, answerA("cdn.example.", "198.51.100.5", 300))
	msg.Answer = append(msg.Answer, answerAAAA("cdn.example.", "2606:4700::1111", 300))
	before := packed(t, msg)

	if result := dnsclassify.Cloudflare(msg, publishedRanges()); result.AllMatch {
		t.Fatalf("a response with a foreign address was classified as rewriteable: %+v", result)
	}

	// The call the plugin would make if it ignored the verdict, and the answer it
	// has to get: an error, and a response still carrying its proof.
	result := dnsclassify.Cloudflare(msg, publishedRanges())
	got, err := Address(AddressInput{
		Response:     msg,
		QType:        dns.TypeA,
		Provider:     "cloudflare",
		TerminalName: result.TerminalName,
		Prefixes:     publishedRanges(),
		Selected:     netip.MustParseAddr("203.0.113.9"),
	})
	if err == nil {
		t.Fatalf("Address rewrote a response the classification refused: %s", answered(got))
	}
	assertUnmodified(t, msg, before)

	// And the path that changes nothing on purpose: a question about IPv6 with
	// suppression off, which is a response this package has no reason to touch.
	quiet := signedResponse()
	quiet.Question[0].Qtype = dns.TypeAAAA
	quietBefore := packed(t, quiet)
	kept, err := Address(AddressInput{
		Response:     quiet,
		QType:        dns.TypeAAAA,
		Provider:     "cloudflare",
		TerminalName: "cdn.example.",
		Selected:     netip.MustParseAddr("203.0.113.9"),
	})
	if err != nil {
		t.Fatalf("Address refused a response it had nothing to do with: %v", err)
	}
	if kept != quiet {
		t.Fatalf("Address returned a new message where it had nothing to change: %v", kept.Answer)
	}
	assertUnmodified(t, quiet, quietBefore)
}

// assertUnmodified states the invariant of a response no one changed: the bytes
// are the bytes that arrived, the AD bit is still set, and the proofs are still
// there.
func assertUnmodified(t *testing.T, msg *dns.Msg, before []byte) {
	t.Helper()
	if after := packed(t, msg); string(after) != string(before) {
		t.Fatalf("a response the plugin did not modify changed:\n before %s\n after  %s", before, after)
	}
	if !msg.AuthenticatedData {
		t.Error("AD was cleared on a response the plugin did not modify")
	}
	for _, section := range []struct {
		name string
		rrs  []dns.RR
	}{
		{name: "answer", rrs: msg.Answer},
		{name: "authority", rrs: msg.Ns},
	} {
		if !hasType(section.rrs, dns.TypeRRSIG) {
			t.Errorf("the RRSIG records in the %s section of an unmodified response were removed", section.name)
		}
	}
	if !hasType(msg.Ns, dns.TypeNSEC) || !hasType(msg.Ns, dns.TypeNSEC3) {
		t.Errorf("the NSEC/NSEC3 records of an unmodified response were removed: %v", recordTypes(msg.Ns))
	}
}
