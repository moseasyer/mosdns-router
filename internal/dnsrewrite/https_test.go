package dnsrewrite

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The HTTPS record is the one place this project tells a client to encrypt its
// ClientHello, so the fixtures below are whole records with every field written
// out as a literal: a service mode, a hint, a mandatory list and a local
// parameter the library does not interpret. A wrong mandatory key or a hint the
// client follows instead of the selected address is a broken feature or a silent
// downgrade, and neither is visible in a summary. Every expectation is therefore
// spelled out as the literal a resolver's contract requires, rather than compared
// against whatever the implementation produced.

// echFixtureBase64 is the ECHConfigList a public ECH source published on
// 2026-09-25, the same non-secret fixture internal/echconfig is tested against. It
// is used here so the expectations can be written against real bytes a browser
// would receive rather than a shape this package invented.
const echFixtureBase64 = "AEX+DQBBuAAgACBeWfLyd08MrrxQgz3O0ws1h/j6yhgH1+4jTfFQ5Y6qawAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

// echFixture decodes the list above. The 71 bytes are the outer uint16 length
// 0x0045 declaring the 69 bytes that follow it, then one ECHConfig of version
// 0xfe0d whose declared length 0x0041 covers the 65 bytes that follow it, and
// whose public name is cloudflare-ech.com.
func echFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(echFixtureBase64)
	if err != nil {
		t.Fatalf("decode the ECH fixture: %v", err)
	}
	return raw
}

// localKey is a SvcParamKey in the range RFC 9460 reserves for experimental and
// private use, so no client has an opinion about it. It is the parameter a
// synthesis that only copies the keys it understands would lose.
const localKey = dns.SVCBKey(65400)

// httpsRecord builds an HTTPS record the way a zone would publish one: an owner
// name, a TTL, the SvcPriority, the TargetName and its SvcParams in the order
// they were written.
func httpsRecord(name string, ttl uint32, priority uint16, target string, pairs ...dns.SVCBKeyValue) *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl},
		Priority: priority,
		Target:   target,
		Value:    pairs,
	}}
}

// httpsInput is the authorization a plugin passes once it has a response to work
// on: the response, the name it is answering, the address the selector proved, and
// the ECHConfigList the ECH source published. The policy is the default one, a
// refusal that fails closed, so a test that names no policy is testing the
// strict arm.
func httpsInput(t *testing.T, msg *dns.Msg) HTTPSInput {
	t.Helper()
	return HTTPSInput{
		Response: msg,
		QName:    msg.Question[0].Name,
		Selected: selected(),
		ECH:      echFixture(t),
		Policy:   FailClosed,
	}
}

// param returns the SvcParam a record carries under one key. A key that is absent
// and a key that appears twice are both failures here, and different ones: the
// first is a parameter the client will not find, and the second is a record that
// cannot be packed at all.
func param(t *testing.T, rr *dns.HTTPS, key dns.SVCBKey) dns.SVCBKeyValue {
	t.Helper()
	var found dns.SVCBKeyValue
	seen := 0
	for _, pair := range rr.Value {
		if pair.Key() != key {
			continue
		}
		seen++
		found = pair
	}
	if seen != 1 {
		t.Fatalf("the record carries %d %s parameters, want exactly one: %s", seen, key, carried(rr))
	}
	return found
}

// alpnOf returns the alpn list a record carries, failing when it carries none.
func alpnOf(t *testing.T, rr *dns.HTTPS) []string {
	t.Helper()
	alpn, ok := param(t, rr, dns.SVCB_ALPN).(*dns.SVCBAlpn)
	if !ok {
		t.Fatalf("the alpn parameter is %T, want *dns.SVCBAlpn", param(t, rr, dns.SVCB_ALPN))
	}
	return alpn.Alpn
}

// echOf returns the bytes a record's ech parameter carries, failing when it
// carries none.
func echOf(t *testing.T, rr *dns.HTTPS) []byte {
	t.Helper()
	ech, ok := param(t, rr, dns.SVCB_ECHCONFIG).(*dns.SVCBECHConfig)
	if !ok {
		t.Fatalf("the ech parameter is %T, want *dns.SVCBECHConfig", param(t, rr, dns.SVCB_ECHCONFIG))
	}
	return ech.ECH
}

// hintOf returns the IPv4 addresses a record's ipv4hint parameter carries,
// failing when it carries none. An empty list and an absent parameter are the
// same thing to a client, and both are refused here so a test cannot pass on an
// empty hint.
func hintOf(t *testing.T, rr *dns.HTTPS) []string {
	t.Helper()
	hint, ok := param(t, rr, dns.SVCB_IPV4HINT).(*dns.SVCBIPv4Hint)
	if !ok {
		t.Fatalf("the ipv4hint parameter is %T, want *dns.SVCBIPv4Hint", param(t, rr, dns.SVCB_IPV4HINT))
	}
	out := make([]string, 0, len(hint.Hint))
	for _, address := range hint.Hint {
		out = append(out, address.String())
	}
	return out
}

// carriedOnTheWire is what a client sees: the keys of the record in the order they
// appear on the wire, which is the order RFC 9460 Section 2.2 requires and the
// order the library's packer imposes whatever order the record holds them in. An
// expectation written against the order the record was built in would pin this
// package's own sequence instead of the format.
func carriedOnTheWire(t *testing.T, rr *dns.HTTPS) string {
	t.Helper()
	return carried(roundTripped(t, &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
		Question: []dns.Question{{
			Name:   rr.Hdr.Name,
			Qtype:  dns.TypeHTTPS,
			Qclass: rr.Hdr.Class,
		}},
		Answer: []dns.RR{rr},
	}).Answer[0].(*dns.HTTPS))
}

// carried lists the keys a record holds, in the order it holds them, so a failure
// names what is actually there rather than a count of nothing.
func carried(rr *dns.HTTPS) string {
	names := make([]string, 0, len(rr.Value))
	for _, pair := range rr.Value {
		names = append(names, pair.Key().String())
	}
	return strings.Join(names, " ")
}

// carries reports whether a record holds a parameter under one key.
func carries(rr *dns.HTTPS, key dns.SVCBKey) bool {
	for _, pair := range rr.Value {
		if pair.Key() == key {
			return true
		}
	}
	return false
}

// mandatoryOf returns the keys a record's mandatory list names, failing when it
// carries no mandatory list at all. A mandatory list is not optional on a record
// this project synthesizes, so its absence is a failure rather than an empty
// answer.
func mandatoryOf(t *testing.T, rr *dns.HTTPS) []dns.SVCBKey {
	t.Helper()
	list, ok := param(t, rr, dns.SVCB_MANDATORY).(*dns.SVCBMandatory)
	if !ok {
		t.Fatalf("the mandatory parameter is %T, want *dns.SVCBMandatory", param(t, rr, dns.SVCB_MANDATORY))
	}
	return list.Code
}

// keptHTTPS is the record a client reads out of an answer this router did not
// synthesize. It is the first record, and it has to be an HTTPS one: the upstream
// put it first and this router has no reason to move it, and a preserved answer
// keeps the signature that follows it.
func keptHTTPS(t *testing.T, msg *dns.Msg) *dns.HTTPS {
	t.Helper()
	if len(msg.Answer) == 0 {
		t.Fatal("the answer is empty")
	}
	rr, ok := msg.Answer[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("the first record of the answer is %s, want the upstream's HTTPS record", msg.Answer[0])
	}
	return rr
}

// httpsIn returns the one HTTPS record in a section, failing when the section holds
// none or more than one. A synthesized answer is allowed to keep records that belong
// to other names, so a test that wants the record itself cannot insist the whole
// section is one record.
func httpsIn(t *testing.T, section []dns.RR) *dns.HTTPS {
	t.Helper()
	found := []*dns.HTTPS{}
	for _, rr := range section {
		if record, ok := rr.(*dns.HTTPS); ok {
			found = append(found, record)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the section holds %d HTTPS records, want exactly one: %v", len(found), recordTypes(section))
	}
	return found[0]
}

// onlyHTTPS is the answer a client received, as a single record. Every synthesis
// is supposed to leave exactly one, so a test that wants to look at it does not
// have to search and cannot read a later record after an earlier one failed.
func onlyHTTPS(t *testing.T, msg *dns.Msg) *dns.HTTPS {
	t.Helper()
	if len(msg.Answer) != 1 {
		t.Fatalf("the answer holds %d records (%v), want exactly one HTTPS record", len(msg.Answer), answered(msg))
	}
	rr, ok := msg.Answer[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("the answer is %s, want an HTTPS record", msg.Answer[0])
	}
	return rr
}

// TestHTTPSStrictRecordIsOneServiceModePointedAtTheSelectedAddress is the whole
// feature in one record: a client that reads it encrypts its ClientHello to the
// key it carries, connects to the address the selector proved, and keeps the
// service description the upstream published. It is checked field by field
// because a synthesis that drops alpn, mangles the dohpath template, loses a
// parameter the library does not interpret, or points the client at a hint other
// than the selected address all produce a record that looks plausible.
func TestHTTPSStrictRecordIsOneServiceModePointedAtTheSelectedAddress(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 8443},
		&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
		&dns.SVCBLocal{KeyCode: 65400, Data: []byte("probe")},
	))

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS refused a response it should have rewritten: %v", err)
	}
	if got.Rcode != dns.RcodeSuccess {
		t.Errorf("the synthesized answer is %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}
	if len(got.Question) != 1 || got.Question[0].Name != "cdn.example." || got.Question[0].Qtype != dns.TypeHTTPS {
		t.Errorf("the question the client asked is %v, want the one HTTPS question it was sent", got.Question)
	}
	out := onlyHTTPS(t, got)

	// The three fields that make the record a service mode for this name.
	if out.Hdr.Name != "cdn.example." {
		t.Errorf("owner = %q, want %q", out.Hdr.Name, "cdn.example.")
	}
	if out.Hdr.Rrtype != dns.TypeHTTPS || out.Hdr.Class != dns.ClassINET {
		t.Errorf("the record is %d/%d, want %d/%d", out.Hdr.Rrtype, out.Hdr.Class, dns.TypeHTTPS, dns.ClassINET)
	}
	if out.Hdr.Ttl != 300 {
		t.Errorf("TTL = %d, want the upstream record's 300 rather than an invented lifetime", out.Hdr.Ttl)
	}
	if out.Priority != 1 {
		t.Errorf("SvcPriority = %d, want 1: a priority of 0 is an alias, and any other value is an order this router has no standing to set", out.Priority)
	}
	if out.Target != "." {
		t.Errorf("TargetName = %q, want %q: the selected address is reached under the name the client asked for", out.Target, ".")
	}

	// The parameters the client needs to talk to the service.
	if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2", "h3"}) {
		t.Errorf("alpn = %v, want the upstream's [h2 h3]", alpn)
	}
	port, ok := param(t, out, dns.SVCB_PORT).(*dns.SVCBPort)
	if !ok {
		t.Fatalf("the port parameter is %T, want *dns.SVCBPort", param(t, out, dns.SVCB_PORT))
	}
	if port.Port != 8443 {
		t.Errorf("port = %d, want the upstream's 8443", port.Port)
	}
	dohpath, ok := param(t, out, dns.SVCB_DOHPATH).(*dns.SVCBDoHPath)
	if !ok {
		t.Fatalf("the dohpath parameter is %T, want *dns.SVCBDoHPath", param(t, out, dns.SVCB_DOHPATH))
	}
	if dohpath.Template != "/dns-query{?dns}" {
		t.Errorf("dohpath = %q, want the upstream's template verbatim", dohpath.Template)
	}
	local, ok := param(t, out, localKey).(*dns.SVCBLocal)
	if !ok {
		t.Fatalf("the key65400 parameter is %T, want *dns.SVCBLocal", param(t, out, localKey))
	}
	if string(local.Data) != "probe" {
		t.Errorf("key65400 = %q, want the upstream's %q", local.Data, "probe")
	}

	// The two parameters this router owns.
	if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
		t.Errorf("ech = %d bytes, want the %d validated bytes the source published, byte for byte", len(ech), len(echFixture(t)))
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
		t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
	}
	if carries(out, dns.SVCB_IPV6HINT) {
		t.Errorf("the record carries an ipv6hint: %s", carried(out))
	}
	if mandatory := mandatoryOf(t, out); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG}) {
		t.Errorf("mandatory = %v, want exactly [ech] for a record whose only mandatory key is ech", mandatory)
	}

	// A record the client can read: packing the message is the check the library
	// makes for a repeated key, and it is the one a hand-built record can fail.
	if _, err := got.Pack(); err != nil {
		t.Errorf("the synthesized message cannot be packed: %v", err)
	}
}

// TestHTTPSNeverModifiesTheResponseItIsGiven is the rule the whole package is
// built on: the caller is a plugin standing in front of a cache that owns the
// object, so a rewrite applied in place is a rewrite the next reader inherits.
// The upstream record below carries an ech parameter and two hints, and every one
// of them must be exactly as it arrived after a call that rewrote it, compared as
// wire bytes rather than field by field so that a change to any header bit, to
// the record's order, or to a parameter's bytes is caught.
func TestHTTPSNeverModifiesTheResponseItIsGiven(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
		&dns.SVCBECHConfig{ECH: echFixture(t)},
	))
	before := packed(t, upstream)

	if _, err := HTTPS(httpsInput(t, upstream)); err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	if after := packed(t, upstream); string(after) != string(before) {
		t.Fatalf("HTTPS changed the response it was given:\n before %s\n after  %s", before, after)
	}
}

// signedHTTPSResponse is the answer that arrived with everything a rewrite has to
// remove and a fallback has to keep: the AD bit a validating resolver set, a
// signature over the HTTPS RRset, a signed denial of existence beside it, and the
// client's OPT.
func signedHTTPSResponse(records ...dns.RR) *dns.Msg {
	msg := response("cdn.example.", dns.TypeHTTPS, records...)
	msg.AuthenticatedData = true
	msg.Answer = append(msg.Answer, signature("cdn.example.", "example.net.", dns.TypeHTTPS, 300))
	msg.Ns = []dns.RR{
		answerSOA(),
		nsec("example.net.", "example.org.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
		nsec3("example.net.", 1, 0, "a1b2", dns.TypeRRSIG, dns.TypeHTTPS),
		signature("example.net.", "example.net.", dns.TypeNSEC, 3600),
	}
	msg.Extra = []dns.RR{answerOPT()}
	return msg
}

// TestHTTPSRefusesACallerItCannotConfirm covers the four doors a call has to come
// through before a record may be synthesized: there is a response, it carries a
// question, that question is an HTTPS question, and the confirmed name is the name
// the response answers. Each of them is a wiring mistake, and each of them would
// install a record a client did not ask for.
func TestHTTPSRefusesACallerItCannotConfirm(t *testing.T) {
	answerHTTPS := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
	))
	answeredAAAA := response("cdn.example.", dns.TypeAAAA, answerAAAA("cdn.example.", "2606:4700::1111", 300))
	answeredOther := response("other.example.", dns.TypeHTTPS, httpsRecord("other.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2"}},
	))
	noQuestion := func() *dns.Msg {
		msg := new(dns.Msg)
		msg.Response = true
		msg.Answer = []dns.RR{httpsRecord("cdn.example.", 300, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h2"}})}
		return msg
	}()
	// A well-formed query: the client's own message, which happens to carry the
	// question this function would answer. Answering it would produce a message that
	// says nothing about being a response at all.
	aQuery := func() *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("cdn.example.", dns.TypeHTTPS)
		return msg
	}()

	with := func(msg *dns.Msg, name string) HTTPSInput {
		return HTTPSInput{
			Response: msg,
			QName:    name,
			Selected: selected(),
			ECH:      echFixture(t),
			Policy:   FailClosed,
		}
	}
	tests := []struct {
		name string
		in   HTTPSInput
	}{
		{name: "no response at all", in: with(nil, "cdn.example.")},
		{name: "a response with no question", in: with(noQuestion, "cdn.example.")},
		{name: "a query rather than a response", in: with(aQuery, "cdn.example.")},
		{name: "a question type this function does not own", in: with(answeredAAAA, "cdn.example.")},
		{name: "no confirmed name", in: with(answerHTTPS, "")},
		{name: "a name this response does not answer", in: with(answeredOther, "cdn.example.")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HTTPS(tt.in)
			if err == nil {
				t.Fatalf("HTTPS synthesized a record for a call it cannot confirm: %s", answered(got))
			}
			if got != nil {
				t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
			}
		})
	}
}

// TestHTTPSRefusesWithoutAnECHConfigAndSaysWhichKindItWas is the taxonomy a caller
// needs to choose a policy, so it is checked as a pair: a source that published
// nothing and a source that published something this router will not forward are
// different faults, and a caller that cannot tell them apart will treat a corrupt
// config as a missing one. The errors are checked with errors.Is rather than by
// their text, because the text is a message for an operator and the sentinel is the
// contract.
func TestHTTPSRefusesWithoutAnECHConfigAndSaysWhichKindItWas(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
	))
	// The fixture's own version field, 0xfe0d, with its low byte changed: a
	// version whose contents layout this router has not read.
	unsupportedVersion := echFixture(t)
	unsupportedVersion[3] = 0x0e

	tests := []struct {
		name string
		in   HTTPSInput
		want error
	}{
		{
			name: "the source published nothing",
			in:   HTTPSInput{Response: upstream, QName: "cdn.example.", Selected: selected(), ECH: nil, Policy: FailClosed},
			want: ErrNoECHConfig,
		},
		{
			name: "the source published a version this router has not read",
			in:   HTTPSInput{Response: upstream, QName: "cdn.example.", Selected: selected(), ECH: unsupportedVersion, Policy: FailClosed},
			want: ErrInvalidECHConfig,
		},
	}
	var missing, invalid error
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HTTPS(tt.in)
			if err == nil {
				t.Fatalf("HTTPS synthesized a record with no ECHConfig to install: %s", answered(got))
			}
			if got != nil {
				t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want one a caller can recognise as %v", err, tt.want)
			}
			if tt.want == ErrNoECHConfig {
				missing = err
			} else {
				invalid = err
			}
		})
	}
	if errors.Is(missing, ErrInvalidECHConfig) {
		t.Errorf("a source that published nothing is also reported as %v, so a caller cannot tell a missing config from a corrupt one", ErrInvalidECHConfig)
	}
	if errors.Is(invalid, ErrNoECHConfig) {
		t.Errorf("a config this router will not forward is also reported as %v, so a strict caller would look for a retry that cannot help", ErrNoECHConfig)
	}
}

// TestHTTPSRefusesWithoutASelectedAddress is the health gate reaching the record.
// The hint is the only address in the answer, so a missing one, a zero address, or
// an address nobody proved all reach a client as a connection to something this
// router never checked unless they arrive as a refusal. The sentinel is distinct
// from the ECHConfig ones so that a caller does not answer an unhealthy address by
// keeping a record it would then have to rewrite anyway.
func TestHTTPSRefusesWithoutASelectedAddress(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
	))
	tests := []struct {
		name     string
		selected netip.Addr
	}{
		{name: "no address at all", selected: netip.Addr{}},
		{name: "an IPv6 selection", selected: netip.MustParseAddr("2606:4700::1111")},
		{name: "a loopback selection", selected: netip.MustParseAddr("127.0.0.1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HTTPS(HTTPSInput{
				Response: upstream,
				QName:    "cdn.example.",
				Selected: tt.selected,
				ECH:      echFixture(t),
				Policy:   FailClosed,
			})
			if err == nil {
				t.Fatalf("HTTPS hinted an address nobody proved: %s", answered(got))
			}
			if got != nil {
				t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
			}
			if !errors.Is(err, ErrNoSelectedAddress) {
				t.Fatalf("error = %v, want one a caller can recognise as %v", err, ErrNoSelectedAddress)
			}
			if errors.Is(err, ErrNoECHConfig) {
				t.Errorf("an unusable address is reported as %v, so a caller cannot tell the two faults apart", ErrNoECHConfig)
			}
		})
	}
}

// TestHTTPSKeepsTheOriginalRecordWhenThereIsNoECHConfigToInstall is the fallback
// arm's whole promise. The upstream record was a working answer and this router has
// no key to install in it, so the client must receive that record and everything
// that came with it: the parameters the upstream published, the hint it published,
// the signature over the RRset, the denial of existence beside it, and the AD bit
// the validating resolver set. The ipv6hint is part of that record and stays in
// it. The rule that a record this router writes carries no IPv6 hint applies to
// the records it writes; a record it forwards untouched is not its own, and
// removing a parameter from it is the degradation this arm exists to prevent.
func TestHTTPSKeepsTheOriginalRecordWhenThereIsNoECHConfigToInstall(t *testing.T) {
	upstream := signedHTTPSResponse(httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 443},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
	))
	before := packed(t, upstream)

	got, err := HTTPS(HTTPSInput{
		Response: upstream,
		QName:    "cdn.example.",
		Selected: selected(),
		ECH:      nil,
		Policy:   FallbackToOriginal,
	})
	// The message is the upstream's own, and the error says why no key went into it.
	// A caller that discards the error is not unsafe -- it forwards what the client
	// would have got anyway -- but it cannot see that the ECH source is broken, which
	// is the whole reason this arm exists.
	if !errors.Is(err, ErrNoECHConfig) {
		t.Fatalf("error = %v, want %v beside the message: the caller has to learn the ECH source failed or it flies blind", err, ErrNoECHConfig)
	}
	if got != upstream {
		t.Fatalf("HTTPS built a new message where the policy was to keep the original one: %s", answered(got))
	}
	assertUnmodified(t, upstream, before)

	out := keptHTTPS(t, got)
	if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2", "h3"}) {
		t.Errorf("alpn = %v, want the upstream's [h2 h3]", alpn)
	}
	port, ok := param(t, out, dns.SVCB_PORT).(*dns.SVCBPort)
	if !ok {
		t.Fatalf("the port parameter is %T, want *dns.SVCBPort", param(t, out, dns.SVCB_PORT))
	}
	if port.Port != 443 {
		t.Errorf("port = %d, want the upstream's 443", port.Port)
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{"104.16.1.1"}) {
		t.Errorf("ipv4hint = %v, want the upstream's own [104.16.1.1]: there was no config to install, so there was no reason to touch it", hints)
	}
	if !carries(out, dns.SVCB_IPV6HINT) {
		t.Errorf("the upstream's ipv6hint was removed from a record this router did not write: %s", carried(out))
	}
	if carries(out, dns.SVCB_ECHCONFIG) {
		t.Errorf("an ech parameter was invented for a record with no ECHConfig: %s", carried(out))
	}
	if carries(out, dns.SVCB_MANDATORY) {
		t.Errorf("a mandatory list was added to a record with no ECHConfig in it: %s", carried(out))
	}
}

// TestHTTPSRefusesWhenThereIsNothingToKeepAndNoConfigToInstall is the corner the
// fallback arm has to name rather than guess at: no ECHConfig means the record
// cannot be rewritten, and no upstream record means there is nothing to hand back
// either. The error is the no-original refusal, and it carries the ECH refusal
// inside it so a caller that logs it can see both facts.
func TestHTTPSRefusesWhenThereIsNothingToKeepAndNoConfigToInstall(t *testing.T) {
	empty := response("cdn.example.", dns.TypeHTTPS)

	got, err := HTTPS(HTTPSInput{
		Response: empty,
		QName:    "cdn.example.",
		Selected: selected(),
		ECH:      nil,
		Policy:   FallbackToOriginal,
	})
	if err == nil {
		t.Fatalf("HTTPS answered a question it had neither a key nor a record for: %s", answered(got))
	}
	if got != nil {
		t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
	}
	if !errors.Is(err, ErrNoOriginal) {
		t.Errorf("error = %v, want one a caller can recognise as %v", err, ErrNoOriginal)
	}
	if !errors.Is(err, ErrNoECHConfig) {
		t.Errorf("error = %v, want the ECH refusal inside it: there was no config to install and nothing to keep instead", err)
	}
}

// TestHTTPSRewritesTheECHConfigAndTheHintsUnderEitherPolicy states that the two
// policies differ only in what happens to an answer this package cannot make. With
// a config to install there is one correct answer, and it is the same one whether
// the caller fails closed or falls back: the key is the source's, the hint is the
// selected address, and the other parameters the upstream published are still
// there.
func TestHTTPSRewritesTheECHConfigAndTheHintsUnderEitherPolicy(t *testing.T) {
	for _, policy := range []struct {
		name   string
		policy FailurePolicy
	}{
		{name: "failing closed", policy: FailClosed},
		{name: "falling back", policy: FallbackToOriginal},
	} {
		t.Run(policy.name, func(t *testing.T) {
			upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
				&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}},
				&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
				&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
			))

			got, err := HTTPS(HTTPSInput{
				Response: upstream,
				QName:    "cdn.example.",
				Selected: selected(),
				ECH:      echFixture(t),
				Policy:   policy.policy,
			})
			if err != nil {
				t.Fatalf("HTTPS: %v", err)
			}
			out := onlyHTTPS(t, got)
			if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
				t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
			}
			if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
				t.Errorf("ipv4hint = %v, want exactly [%s]: the hint is the selection, not the upstream's anycast address", hints, selectedIP)
			}
			if carries(out, dns.SVCB_IPV6HINT) {
				t.Errorf("the record this router wrote carries an ipv6hint: %s", carried(out))
			}
			if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h3", "h2"}) {
				t.Errorf("alpn = %v, want the upstream's own order [h3 h2]", alpn)
			}
			dohpath, ok := param(t, out, dns.SVCB_DOHPATH).(*dns.SVCBDoHPath)
			if !ok {
				t.Fatalf("the dohpath parameter is %T, want *dns.SVCBDoHPath", param(t, out, dns.SVCB_DOHPATH))
			}
			if dohpath.Template != "/dns-query{?dns}" {
				t.Errorf("dohpath = %q, want the upstream's template verbatim", dohpath.Template)
			}
			if mandatory := mandatoryOf(t, out); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG}) {
				t.Errorf("mandatory = %v, want exactly [ech]", mandatory)
			}
		})
	}
}

// TestHTTPSSynthesizesAMinimalServiceModeWhenTheUpstreamHasNoRecord is the ruling
// that a missing upstream record is not a configuration failure. The ECH source
// lookup and the selected address do not depend on what the upstream had, so a
// resolver that returned NODATA for the name is no reason to hand a force-ECH
// client nothing. The synthesized record names the two protocols a TLS edge
// serves, points at the selected address and carries the key. Its TTL is zero
// because there is no upstream lifetime behind it to inherit, and a zero TTL says
// do not cache a record this router made up rather than inventing a lifetime it
// cannot honour.
func TestHTTPSSynthesizesAMinimalServiceModeWhenTheUpstreamHasNoRecord(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS)
	upstream.AuthenticatedData = true
	upstream.Extra = []dns.RR{answerOPT()}

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS refused a name the ECH source and the selector can both answer: %v", err)
	}
	if got.Rcode != dns.RcodeSuccess {
		t.Errorf("the synthesized answer is %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}
	if len(got.Ns) != 0 {
		t.Errorf("the authority section holds %v: a synthesized positive answer claims no denial of existence and no negative caching TTL", recordTypes(got.Ns))
	}
	if len(got.Extra) != 1 || got.Extra[0].Header().Rrtype != dns.TypeOPT {
		t.Errorf("the additional section is %v, want the client's OPT record kept", recordTypes(got.Extra))
	}

	out := onlyHTTPS(t, got)
	if out.Priority != 1 || out.Target != "." {
		t.Errorf("the synthesized record is priority %d target %q, want priority 1 target \".\"", out.Priority, out.Target)
	}
	if out.Hdr.Ttl != 0 {
		t.Errorf("TTL = %d, want 0: no upstream record means no lifetime to inherit, and an invented one would be cached as if the upstream had said it", out.Hdr.Ttl)
	}
	if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2", "h3"}) {
		t.Errorf("alpn = %v, want [h2 h3]: with no upstream record the record has to name the protocols a TLS edge serves", alpn)
	}
	if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
		t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
		t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
	}
	if mandatory := mandatoryOf(t, out); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG}) {
		t.Errorf("mandatory = %v, want exactly [ech]", mandatory)
	}
	if keys := carried(out); keys != "alpn ech ipv4hint mandatory" {
		t.Errorf("the record carries %s, want only alpn, ech, ipv4hint and mandatory", keys)
	}
}

// TestHTTPSBypassesAnUpstreamServfailForAQueryItCanAnswer runs the same ruling
// against the response a resolver actually sends when it has failed: a SERVFAIL
// carrying the client's OPT and no records at all. The answer must not inherit the
// failure's rcode, because the client asked a question this router can answer
// without the upstream.
func TestHTTPSBypassesAnUpstreamServfailForAQueryItCanAnswer(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS)
	upstream.Rcode = dns.RcodeServerFailure
	upstream.Extra = []dns.RR{answerOPT()}

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS let an upstream SERVFAIL stop an answer it could give: %v", err)
	}
	if got.Rcode != dns.RcodeSuccess {
		t.Fatalf("the answer is %s, want NOERROR: the client must not be handed the upstream's failure", dns.RcodeToString[got.Rcode])
	}
	out := onlyHTTPS(t, got)
	if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
		t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
		t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
	}
}

// TestHTTPSSetsPriorityOneWhicheverPriorityTheUpstreamPublished pins the one field
// this router sets rather than inherits. A priority of 0 is an alias, which a
// client reads as a delegation and never as a service to connect to, and any other
// value is an ordering the upstream chose between endpoints of its own. The
// synthesized record is the only endpoint in the answer, so the number that makes
// it usable is 1.
func TestHTTPSSetsPriorityOneWhicheverPriorityTheUpstreamPublished(t *testing.T) {
	for _, priority := range []uint16{1, 2, 5, 65535} {
		upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, priority, ".",
			&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		))

		got, err := HTTPS(httpsInput(t, upstream))
		if err != nil {
			t.Fatalf("HTTPS refused a record published at priority %d: %v", priority, err)
		}
		if out := onlyHTTPS(t, got); out.Priority != 1 {
			t.Errorf("an upstream priority of %d became %d, want 1", priority, out.Priority)
		}
	}
}

// roundTripped hands a message back as the resolver library hands it back after
// reading it off the wire, so a case that depends on how a record is decoded is
// tested against the decoder rather than against a value built to suit the check.
func roundTripped(t *testing.T, msg *dns.Msg) *dns.Msg {
	t.Helper()
	var got dns.Msg
	if err := got.Unpack(packed(t, msg)); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	return &got
}

// wireIPv6Target is the TargetName an IPv6 address becomes on the wire. RFC 9460
// Section 2.2 carries the TargetName in the RDATA as an uncompressed sequence of
// length-prefixed labels, so an address spelled as an address is sixteen one-octet
// labels, and a resolver library reads that back as the string those labels spell.
// The two forms are the same target and a compatibility rule that only recognized
// one of them would pass on a fixture and fail on a real response.
func wireIPv6Target(t *testing.T, address string) string {
	t.Helper()
	octets := net.ParseIP(address).To16()
	if octets == nil {
		t.Fatalf("%q is not an address this helper can write on the wire", address)
	}
	labels := make([]string, 0, len(octets))
	for _, octet := range octets {
		labels = append(labels, strconv.Itoa(int(octet)))
	}
	return strings.Join(labels, ".") + "."
}

// selfConsistent fails the test when the record's mandatory list names a key the
// record does not carry, or names one key twice. RFC 9460 Section 8 makes such a
// record one a client must reject, which for a force-ECH name means the connection
// fails rather than that the connection is plaintext, and the failure is silent
// from the client's side: there is no error to show an operator.
func selfConsistent(t *testing.T, rr *dns.HTTPS) {
	t.Helper()
	present := map[dns.SVCBKey]int{}
	for _, pair := range rr.Value {
		present[pair.Key()]++
	}
	for _, pair := range rr.Value {
		list, ok := pair.(*dns.SVCBMandatory)
		if !ok {
			continue
		}
		seen := map[dns.SVCBKey]bool{}
		for _, key := range list.Code {
			if seen[key] {
				t.Errorf("the mandatory list names %s twice, which makes the record one a client must reject", key)
			}
			seen[key] = true
			switch {
			case key == dns.SVCB_MANDATORY:
				t.Errorf("the mandatory list names mandatory itself, which RFC 9460 Section 8 forbids")
			case present[key] == 0:
				t.Errorf("the mandatory list names %s and the record does not carry it: %s", key, carried(rr))
			}
		}
	}
}

// TestHTTPSDropsAnEndpointWhoseTargetIsAnIPv6Address is the project constraint
// meeting a record that says otherwise. This release installs an IPv4 address and
// no AAAA, so an endpoint under an IPv6 address is one a client cannot reach
// through anything this router publishes, and keeping its parameters would claim
// the name is served over a network nothing here can select. It is checked in both
// of the forms a target arrives in, and in the wire form the record is put through
// the resolver's own decoder first.
func TestHTTPSDropsAnEndpointWhoseTargetIsAnIPv6Address(t *testing.T) {
	spelled := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, "2606:4700::1111.",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 8443},
	))
	onTheWire := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, wireIPv6Target(t, "2606:4700::1111"),
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 8443},
	))

	for _, tt := range []struct {
		name string
		in   *dns.Msg
	}{
		{name: "as a zone file spells it", in: spelled},
		{name: "as the wire carries it", in: roundTripped(t, onTheWire)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HTTPS(httpsInput(t, tt.in))
			if err == nil {
				t.Fatalf("HTTPS answered with an endpoint under an IPv6 address: %s", answered(got))
			}
			if got != nil {
				t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
			}
			if !errors.Is(err, ErrNoCompatibleEndpoint) {
				t.Fatalf("error = %v, want one a caller can recognise as %v", err, ErrNoCompatibleEndpoint)
			}
		})
	}
}

// TestHTTPSKeepsAnEndpointWhoseOnlyAddressIsIPv4 is the other side of the same
// rule, and it is the case that has to keep working. An endpoint that offers an
// IPv4 address stays, with its parameters, and its IPv6 hint leaves: the rule is
// not "drop every record with a hint in it", it is "leave behind a record a client
// can reach with the address this router proved". An endpoint with both hints is
// kept for the same reason: its IPv4 hint is the one this router replaces, and the
// IPv6 one is not the only way in.
func TestHTTPSKeepsAnEndpointWhoseOnlyAddressIsIPv4(t *testing.T) {
	for _, tt := range []struct {
		name    string
		hints   []dns.SVCBKeyValue
		wanted  []string
		carried bool
	}{
		{
			name:   "an IPv4 hint on its own",
			hints:  []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}}},
			wanted: []string{selectedIP},
		},
		{
			name: "an IPv4 hint and an IPv6 hint",
			hints: []dns.SVCBKeyValue{
				&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
			},
			wanted: []string{selectedIP},
		},
		{
			name:   "no hint at all",
			hints:  nil,
			wanted: []string{selectedIP},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pairs := append([]dns.SVCBKeyValue{
				&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
				&dns.SVCBPort{Port: 8443},
			}, tt.hints...)
			upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, "svc.example.net.", pairs...))

			got, err := HTTPS(httpsInput(t, upstream))
			if err != nil {
				t.Fatalf("HTTPS dropped an endpoint a client can reach over IPv4: %v", err)
			}
			out := onlyHTTPS(t, got)
			if hints := hintOf(t, out); !reflect.DeepEqual(hints, tt.wanted) {
				t.Errorf("ipv4hint = %v, want exactly %v", hints, tt.wanted)
			}
			if carries(out, dns.SVCB_IPV6HINT) {
				t.Errorf("the record this router wrote carries an ipv6hint: %s", carried(out))
			}
			port, ok := param(t, out, dns.SVCB_PORT).(*dns.SVCBPort)
			if !ok {
				t.Fatalf("the port parameter is %T, want *dns.SVCBPort", param(t, out, dns.SVCB_PORT))
			}
			if port.Port != 8443 {
				t.Errorf("port = %d, want the endpoint's 8443: a compatible endpoint keeps the whole of itself", port.Port)
			}
		})
	}
}

// TestHTTPSDropsAnEndpointWhoseOnlyAddressIsIPv6 is the case where the rule has
// to be per endpoint rather than per message. One endpoint that offers nothing but
// an IPv6 address is not an answer to a question this router can rewrite, and it
// must not poison an answer another endpoint can serve. So the record is refused
// when it stands alone, and skipped when it stands beside one a client can reach.
func TestHTTPSDropsAnEndpointWhoseOnlyAddressIsIPv6(t *testing.T) {
	ipv6Only := func(ttl uint32, port uint16) *dns.HTTPS {
		return httpsRecord("cdn.example.", ttl, 1, ".", &dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}}, &dns.SVCBPort{Port: port})
	}
	usable := func() *dns.HTTPS {
		return httpsRecord("cdn.example.", 300, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}, &dns.SVCBPort{Port: 443})
	}

	alone := response("cdn.example.", dns.TypeHTTPS, ipv6Only(300, 8443))
	t.Run("alone it is a refusal", func(t *testing.T) {
		got, err := HTTPS(httpsInput(t, alone))
		if err == nil {
			t.Fatalf("HTTPS answered with an endpoint whose only address is IPv6: %s", answered(got))
		}
		if got != nil {
			t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
		}
		if !errors.Is(err, ErrNoCompatibleEndpoint) {
			t.Fatalf("error = %v, want one a caller can recognise as %v", err, ErrNoCompatibleEndpoint)
		}
	})

	t.Run("beside one a client can reach it is skipped", func(t *testing.T) {
		beside := response("cdn.example.", dns.TypeHTTPS, ipv6Only(600, 8443), usable())
		got, err := HTTPS(httpsInput(t, beside))
		if err != nil {
			t.Fatalf("HTTPS refused an answer one endpoint of which is usable: %v", err)
		}
		out := onlyHTTPS(t, got)
		port, ok := param(t, out, dns.SVCB_PORT).(*dns.SVCBPort)
		if !ok {
			t.Fatalf("the port parameter is %T, want *dns.SVCBPort", param(t, out, dns.SVCB_PORT))
		}
		if port.Port != 443 {
			t.Errorf("port = %d, want 443 from the endpoint a client can reach, not 8443 from the one it cannot", port.Port)
		}
		if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
			t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
		}
		if carries(out, dns.SVCB_IPV6HINT) {
			t.Errorf("the record this router wrote carries an ipv6hint: %s", carried(out))
		}
		selfConsistent(t, out)
	})
}

// TestHTTPSDropsNoDefaultAlpnWithNoAlpnToDefault is the self-consistency rule
// RFC 9460 Section 7.1.1 states, applied where it can actually be broken. The
// default protocol set is what a client falls back to when a record names no alpn,
// so a record carrying no-default-alpn and no alpn claims that the service speaks
// nothing at all, and a client is entitled to reject the whole RRset over it. It
// is reachable here because a disagreement between endpoints removes the alpn.
func TestHTTPSDropsNoDefaultAlpnWithNoAlpnToDefault(t *testing.T) {
	// Both endpoints carry no-default-alpn, so the presence rule keeps it: what the two
	// disagree about is the alpn, and only the coherence rule can drop the other key
	// as a consequence. A fixture where one endpoint omitted it would pass for the
	// wrong reason.
	upstream := response("cdn.example.", dns.TypeHTTPS,
		httpsRecord("cdn.example.", 300, 1, ".",
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
			&dns.SVCBNoDefaultAlpn{},
		),
		httpsRecord("cdn.example.", 300, 1, ".",
			&dns.SVCBAlpn{Alpn: []string{"h3"}},
			&dns.SVCBNoDefaultAlpn{},
		),
	)

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	out := onlyHTTPS(t, got)
	if carries(out, dns.SVCB_ALPN) {
		t.Errorf("alpn survived from endpoints that name different protocol sets: %s", carried(out))
	}
	if carries(out, dns.SVCB_NO_DEFAULT_ALPN) {
		t.Errorf("no-default-alpn survived without the alpn it requires: %s", carried(out))
	}
	if dropped := droppedKeys(reportOf(t, httpsInput(t, upstream))); !reflect.DeepEqual(dropped, []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_NO_DEFAULT_ALPN}) {
		t.Errorf("the report names %v as left out, want [alpn no-default-alpn]: a key dropped for incoherence is a degradation the caller has to see", dropped)
	}
	selfConsistent(t, out)
}

// TestHTTPSRefusesAnRRsetThatContainsAnAlias is the delegation rule for the shape it
// takes inside an HTTPS RRset. RFC 9460 Section 2.4.1 says a client that finds an
// AliasMode record in an RRset must ignore the ServiceMode records in the same set,
// because the alias is the whole instruction: the service lives at the TargetName and
// this name has none of its own. Harvesting the service mode's parameters and writing
// them under a TargetName of "." therefore does two wrong things at once. It claims a
// service exists at this name when the upstream says it does not, and it reuses
// parameters the upstream published for a binding a client is required to ignore --
// the port and the protocol set of a host this router has never looked at.
//
// So an RRset at the queried name that contains an alias is not synthesized into. A
// strict caller is refused, and a fallback caller is handed the upstream's own
// message, which is a working answer: the client follows the alias to the name the
// service really has, and connects to whatever that name resolves to. That is the
// client's business and not this router's; what this router will not do is answer
// under the delegated name with a service binding of its own invention.
//
// Both shapes are covered, because they fail differently if the rule is implemented
// on the wrong record: an alias alone, where there is nothing to harvest and so
// nothing to catch a mistake, and an alias beside a service mode, which is the case
// with parameters to take.
func TestHTTPSRefusesAnRRsetThatContainsAnAlias(t *testing.T) {
	alias := httpsRecord("cdn.example.", 300, 0, "svc.example.net.",
		&dns.SVCBAlpn{Alpn: []string{"h1"}},
		&dns.SVCBPort{Port: 8443},
	)
	service := httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 443},
	)

	for _, tt := range []struct {
		name    string
		records []dns.RR
	}{
		{name: "an alias on its own", records: []dns.RR{alias}},
		{name: "an alias beside a service mode", records: []dns.RR{alias, service}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream := response("cdn.example.", dns.TypeHTTPS, tt.records...)
			before := packed(t, upstream)

			t.Run("a strict caller is refused", func(t *testing.T) {
				got, err := HTTPS(httpsInput(t, upstream))
				if err == nil {
					t.Fatalf("HTTPS synthesized into an RRset that delegates the name: %s", answered(got))
				}
				if got != nil {
					t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
				}
				if !errors.Is(err, ErrDelegatedName) {
					t.Fatalf("error = %v, want one a caller can recognise as %v", err, ErrDelegatedName)
				}
			})

			t.Run("a fallback caller keeps the upstream's own RRset", func(t *testing.T) {
				got, err := HTTPS(HTTPSInput{
					Response: upstream,
					QName:    "cdn.example.",
					Selected: selected(),
					ECH:      echFixture(t),
					Policy:   FallbackToOriginal,
				})
				if !errors.Is(err, ErrDelegatedName) {
					t.Errorf("error = %v, want %v beside the message", err, ErrDelegatedName)
				}
				if got != upstream {
					t.Fatalf("HTTPS built a new message where the policy was to keep the upstream's own: %s", answered(got))
				}
				if after := packed(t, upstream); string(after) != string(before) {
					t.Errorf("HTTPS changed the response it was given:\n before %s\n after  %s", before, after)
				}
				// Nothing of either record was inherited: the client receives the
				// alias and the service mode exactly as published, so the alias's own
				// target and the service mode's priority are both still there.
				if got := answerTypes(got); len(got) != len(tt.records) {
					t.Errorf("the answer holds %d record(s), want the %d the upstream published", len(got), len(tt.records))
				}
			})
		})
	}
}

// TestHTTPSStillRefusesAnEndpointUnderAnIPv6AddressWithoutTheAliasRule guards the
// two rules against being confused for one another. An alias means the name is not
// ours to describe; an endpoint under an IPv6 address means this release cannot
// reach the one it describes. They are different faults with different sentinels, and
// a caller that treated them as one would log a network reachability problem as a
// delegation and the other way round.
func TestHTTPSStillRefusesAnEndpointUnderAnIPv6AddressWithoutTheAliasRule(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, "2606:4700::1111.",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
	))

	_, err := HTTPS(httpsInput(t, upstream))
	if !errors.Is(err, ErrNoCompatibleEndpoint) {
		t.Fatalf("error = %v, want %v: an unreachable endpoint is not a delegation", err, ErrNoCompatibleEndpoint)
	}
	if errors.Is(err, ErrDelegatedName) {
		t.Errorf("error = %v also matches %v, so a caller cannot tell an unreachable endpoint from a delegated name", err, ErrDelegatedName)
	}
}

// TestHTTPSTakesTheShortestLifetimeOfTheEndpointsItInherits is the TTL rule at the
// level of an RRset with more than one endpoint. The record this router writes
// replaces records the upstream was willing to publish for a stated time, and the
// shortest of those times is the only one it can pass on: a client that caches the
// record for longer than the shortest-lived record it replaces is holding a
// description of a service that may already have moved. An endpoint this router
// refused contributes no lifetime, because nothing of it was inherited.
func TestHTTPSTakesTheShortestLifetimeOfTheEndpointsItInherits(t *testing.T) {
	long := httpsRecord("cdn.example.", 600, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h2"}}, &dns.SVCBPort{Port: 8443})
	short := httpsRecord("cdn.example.", 120, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h2"}}, &dns.SVCBPort{Port: 8443})
	refused := httpsRecord("cdn.example.", 900, 1, ".",
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
		&dns.SVCBPort{Port: 443},
	)
	for _, tt := range []struct {
		name  string
		first *dns.HTTPS
		rest  *dns.HTTPS
		want  uint32
	}{
		{name: "the shortest of two endpoints, whatever the order", first: long, rest: short, want: 120},
		{name: "the same pair the other way round", first: short, rest: long, want: 120},
		{name: "a refused endpoint contributes no lifetime", first: long, rest: refused, want: 600},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream := response("cdn.example.", dns.TypeHTTPS, tt.first, tt.rest)

			got, err := HTTPS(httpsInput(t, upstream))
			if err != nil {
				t.Fatalf("HTTPS: %v", err)
			}
			if out := onlyHTTPS(t, got); out.Hdr.Ttl != tt.want {
				t.Errorf("TTL = %d, want %d", out.Hdr.Ttl, tt.want)
			}
		})
	}
}

// TestHTTPSMandatoryNamesOnlyTheKeysTheRecordCarries is the rule a client cannot
// recover from. RFC 9460 Section 8 says a record whose mandatory list names a key it
// does not carry is one a client must reject, and for a force-ECH name that
// rejection is a failed connection with nothing on the wire to explain it. The
// upstream record below names ipv6hint beside an IPv4 hint, so the endpoint is
// reachable and its parameters are inherited, and this router drops the IPv6 hint
// because this release installs no IPv6 address. The synthesized list must not name
// it either, while alpn, which survives, must still be named: a record whose service
// is not usable without a parameter the client would otherwise ignore is exactly
// what the list is for.
func TestHTTPSMandatoryNamesOnlyTheKeysTheRecordCarries(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_IPV6HINT}},
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
	))

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	out := onlyHTTPS(t, got)
	if mandatory := mandatoryOf(t, out); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG, dns.SVCB_ALPN}) {
		t.Errorf("mandatory = %v, want [ech alpn]: ipv6hint is named by no parameter the record carries any more", mandatory)
	}
	if carries(out, dns.SVCB_IPV6HINT) {
		t.Errorf("the record this router wrote carries an ipv6hint: %s", carried(out))
	}
	selfConsistent(t, out)
}

// TestHTTPSMandatoryKeepsAKeyThisRouterInstalled is the same rule from the other
// side, and it exists because the two cases are indistinguishable to a reader of the
// code that implements them. An upstream that says mandatory=ipv4hint is naming a
// parameter that names nothing at all once this router has taken the address over:
// the upstream's own hint is dropped, and the record carries the SELECTED address in
// its place. The key is therefore in the record, and a mandatory list that leaves it
// out is a degraded answer in the direction RFC 9460 Section 8 forbids -- the client
// is no longer told that this record is unusable without its hint, which is the whole
// reason the endpoint declared it.
//
// The same upstream list names ipv6hint, which this release never installs, and that
// one must still be dropped. So one record covers both halves of the rule: a key the
// synthesized record carries is named, a key it does not is not, and the difference
// between the two is whether this router put the parameter there or inherited it.
func TestHTTPSMandatoryKeepsAKeyThisRouterInstalled(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_IPV4HINT, dns.SVCB_IPV6HINT}},
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
	))

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	out := onlyHTTPS(t, got)
	if mandatory := mandatoryOf(t, out); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG, dns.SVCB_IPV4HINT}) {
		t.Errorf("mandatory = %v, want [ech ipv4hint]: the record carries the selected address as its ipv4hint and the endpoint declared the key mandatory, while ipv6hint is named by no parameter the record has", mandatory)
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
		t.Errorf("ipv4hint = %v, want exactly [%s]: the upstream's own hint is replaced by the selected address", hints, selectedIP)
	}
	if carries(out, dns.SVCB_IPV6HINT) {
		t.Errorf("the record this router wrote carries an ipv6hint: %s", carried(out))
	}
	selfConsistent(t, out)
	selfConsistent(t, onlyHTTPS(t, roundTripped(t, got)))
}

// TestHTTPSMandatoryNeverRepeatsAKeyTheUpstreamRepeated is the duplicate case, and
// it is checked on the wire as well as in memory because a repeat is invisible in
// the list itself: the library sorts the keys when it packs them and does not
// deduplicate them, so a list that names alpn twice leaves two 0x0001 fields in the
// record, and a client reading that rejects the RRset. The upstream repeats both
// ech and alpn, because ech is seeded into the list this router writes and a repeat
// of it would be hidden by that seed unless the other key is repeated too. The
// packed form is read back by unpacking the message, so the order asserted is the
// order the bytes are in, not the order this package happened to build the list in.
func TestHTTPSMandatoryNeverRepeatsAKeyTheUpstreamRepeated(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_ALPN, dns.SVCB_ECHCONFIG, dns.SVCB_ECHCONFIG}},
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
	))

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	inMemory := onlyHTTPS(t, got)
	if mandatory := mandatoryOf(t, inMemory); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG, dns.SVCB_ALPN}) {
		t.Errorf("mandatory = %v, want [ech alpn] with ech named once", mandatory)
	}

	onTheWire := onlyHTTPS(t, roundTripped(t, got))
	if mandatory := mandatoryOf(t, onTheWire); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_ECHCONFIG}) {
		t.Errorf("the mandatory list on the wire is %v, want [alpn ech]: RFC 9460 Section 8 puts the keys in strictly increasing order, and a client reading them is what matters", mandatory)
	}
	selfConsistent(t, onTheWire)
}

// TestHTTPSRoundTripsTheSynthesizedRecordThroughTheWire is the check that the
// record a browser parses is the record this package built. Everything in it is
// written out as a literal, including the order the SvcParamKeys appear in on the
// wire: mandatory(0), alpn(1), port(3), ipv4hint(4), ech(5), dohpath(7),
// key65400(65400), which is the order RFC 9460 Section 2.2 requires and the
// library's packer imposes. A synthesis that builds the same record in a different
// order, or that packs a parameter the library then drops, fails here.
func TestHTTPSRoundTripsTheSynthesizedRecordThroughTheWire(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 8443},
		&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
		&dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")},
	))

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	out := onlyHTTPS(t, roundTripped(t, got))

	if keys := carried(out); keys != "mandatory alpn port ipv4hint ech dohpath key65400" {
		t.Errorf("the record carries %s, want mandatory alpn port ipv4hint ech dohpath key65400 in the order the wire requires", keys)
	}
	if mandatory := mandatoryOf(t, out); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG}) {
		t.Errorf("mandatory = %v, want [ech]", mandatory)
	}
	if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2", "h3"}) {
		t.Errorf("alpn = %v, want [h2 h3]", alpn)
	}
	port, ok := param(t, out, dns.SVCB_PORT).(*dns.SVCBPort)
	if !ok {
		t.Fatalf("the port parameter is %T, want *dns.SVCBPort", param(t, out, dns.SVCB_PORT))
	}
	if port.Port != 8443 {
		t.Errorf("port = %d, want 8443", port.Port)
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
		t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
	}
	if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
		t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
	}
	dohpath, ok := param(t, out, dns.SVCB_DOHPATH).(*dns.SVCBDoHPath)
	if !ok {
		t.Fatalf("the dohpath parameter is %T, want *dns.SVCBDoHPath", param(t, out, dns.SVCB_DOHPATH))
	}
	if dohpath.Template != "/dns-query{?dns}" {
		t.Errorf("dohpath = %q, want the upstream's template", dohpath.Template)
	}
	local, ok := param(t, out, localKey).(*dns.SVCBLocal)
	if !ok {
		t.Fatalf("the key65400 parameter is %T, want *dns.SVCBLocal", param(t, out, localKey))
	}
	if string(local.Data) != "probe" {
		t.Errorf("key65400 = %q, want %q", local.Data, "probe")
	}
	if out.Priority != 1 || out.Target != "." {
		t.Errorf("the record is priority %d target %q, want priority 1 target \".\"", out.Priority, out.Target)
	}
	if out.Hdr.Name != "cdn.example." || out.Hdr.Ttl != 300 {
		t.Errorf("the record is %q TTL %d, want cdn.example. TTL 300", out.Hdr.Name, out.Hdr.Ttl)
	}
}

// TestHTTPSLeavesNoSignatureOnTheRecordItWrote is the plan's obligation, and it is
// the same rule the address rewrite holds to: a response this router changed can
// no longer carry a signature over the records it replaced, because the signature
// covers the parameters that are no longer there, and a client that validated it
// would be told the ECH key is one it is not. So the AD bit goes, every RRSIG and
// every NSEC and NSEC3 in the message goes, and the client's own CD bit and OPT
// record stay. Both starting points are checked, because they fail differently: a
// rewritten record set still holds the records the signature covered, and a
// synthesized one begins from an upstream failure that carried proofs of nothing.
func TestHTTPSLeavesNoSignatureOnTheRecordItWrote(t *testing.T) {
	rewritten := signedHTTPSResponse(httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 443},
	))
	// A signed NODATA: the shape a validating resolver sends when the name has no
	// HTTPS record, with the denial of existence and its signature in the authority
	// section and an address for the name left in the additional section. It is the
	// realistic starting point for the path where this router makes the record
	// itself, and it carries everything a rewrite has to remove.
	synthesized := response("cdn.example.", dns.TypeHTTPS)
	synthesized.AuthenticatedData = true
	synthesized.CheckingDisabled = true
	synthesized.Ns = []dns.RR{
		answerSOA(),
		nsec("example.net.", "example.org.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
		nsec3("example.net.", 1, 0, "a1b2", dns.TypeRRSIG, dns.TypeHTTPS),
		signature("example.net.", "example.net.", dns.TypeSOA, 3600),
	}
	synthesized.Extra = []dns.RR{answerOPT(), answerA("cdn.example.", "104.16.1.1", 300)}

	for _, tt := range []struct {
		name             string
		in               *dns.Msg
		checkingDisabled bool
	}{
		{name: "a rewritten record set", in: rewritten},
		{name: "a record synthesized over a signed NODATA", in: synthesized, checkingDisabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := packed(t, tt.in)

			got, err := HTTPS(httpsInput(t, tt.in))
			if err != nil {
				t.Fatalf("HTTPS: %v", err)
			}
			if got.AuthenticatedData {
				t.Error("a response this router rewrote still claims AD")
			}
			if got.CheckingDisabled != tt.checkingDisabled {
				t.Errorf("CheckingDisabled = %v, want %v: the bit is the client's own decision and this router does not make it", got.CheckingDisabled, tt.checkingDisabled)
			}
			for _, section := range []struct {
				name string
				rrs  []dns.RR
			}{
				{name: "answer", rrs: got.Answer},
				{name: "authority", rrs: got.Ns},
				{name: "additional", rrs: got.Extra},
			} {
				for _, covered := range []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3} {
					if n := countType(section.rrs, covered); n != 0 {
						t.Errorf("%d record(s) of type %s survived in the %s section of a response this router rewrote", n, dns.TypeToString[covered], section.name)
					}
				}
			}
			out := onlyHTTPS(t, got)
			if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
				t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
			}
			if len(got.Extra) == 0 || got.Extra[len(got.Extra)-1].Header().Rrtype != dns.TypeOPT {
				t.Fatalf("the additional section is %v, want the client's OPT record kept", recordTypes(got.Extra))
			}
			if !got.Extra[len(got.Extra)-1].(*dns.OPT).Do() {
				t.Error("the client's DO bit was dropped, so it can no longer tell an unsigned answer from a signed one")
			}
			if after := packed(t, tt.in); string(after) != string(before) {
				t.Errorf("HTTPS changed the response it was given:\n before %s\n after  %s", before, after)
			}
		})
	}
}

// TestHTTPSRemovesTheAddressOfTheNameItNowPointsAt is the one record outside the
// HTTPS RRset that would undo the selection, and it is the rule this router has to
// own because the record makes the queried name the effective target. RFC 9460
// Section 7.3 has a client ignore the hints when it already holds an A or AAAA
// answer for that name, so an address for it in the message is an answer that beats
// the selected address and sends the browser to the anycast address the health check
// never proved. The rule is about the name, not about the section: a client that
// finds the address in the answer section has found it just as surely as one that
// finds it beside the answer, which is why both branches and both sections are
// checked here.
//
// The division of labour with the address rewrite is what makes this safe. `Address`
// owns the terminal A and AAAA of a CDN name on an A or AAAA query, and it is the
// function that installs the selected address there. This function owns a different
// thing: the addresses of the queried name inside an HTTPS answer, which exist only
// to let a client skip the hint. Neither can do the other's job, and a caller that
// answered an HTTPS query and then rewrote its A record would be answering a question
// the client did not ask.
func TestHTTPSRemovesTheAddressOfTheNameItNowPointsAt(t *testing.T) {
	rewritten := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
	))
	rewritten.Answer = append(rewritten.Answer,
		answerA("cdn.example.", "104.16.1.1", 300),
		answerAAAA("cdn.example.", "2606:4700::1111", 300),
		answerA("svc.example.net.", "104.16.2.2", 300),
	)
	rewritten.Extra = []dns.RR{
		answerA("cdn.example.", "104.16.3.3", 300),
		answerA("svc.example.net.", "104.16.2.2", 300),
		answerOPT(),
	}

	// The same thing on the path where nothing was published for the name: the
	// answer is the synthesized record, and an address for the name can still be in
	// the answer section, where a client will use it in preference to the hint.
	fromNothing := response("cdn.example.", dns.TypeHTTPS)
	fromNothing.Extra = []dns.RR{answerOPT()}
	fromNothing.Answer = []dns.RR{
		answerA("cdn.example.", "104.16.1.1", 300),
		answerA("svc.example.net.", "104.16.2.2", 300),
	}

	for _, tt := range []struct {
		name string
		in   *dns.Msg
	}{
		{name: "a record this router replaced", in: rewritten},
		{name: "a record this router synthesized", in: fromNothing},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HTTPS(httpsInput(t, tt.in))
			if err != nil {
				t.Fatalf("HTTPS: %v", err)
			}
			for _, section := range []struct {
				name string
				rrs  []dns.RR
			}{
				{name: "answer", rrs: got.Answer},
				{name: "additional", rrs: got.Extra},
			} {
				for _, rr := range section.rrs {
					switch record := rr.(type) {
					case *dns.A:
						if sameName(record.Hdr.Name, "cdn.example.") {
							t.Errorf("the address %s of the name this record points at survived in the %s section: %s", record.A, section.name, record)
						}
					case *dns.AAAA:
						if sameName(record.Hdr.Name, "cdn.example.") {
							t.Errorf("the IPv6 address %s of the name this record points at survived in the %s section: %s", record.AAAA, section.name, record)
						}
					}
				}
			}
			// The addresses of any other name are a different RRset and stay, so
			// this is not a filter that empties a section.
			if !hasType(got.Answer, dns.TypeA) && !hasType(got.Extra, dns.TypeA) {
				t.Errorf("every A record was removed: the answer holds %v and the additional section %v", recordTypes(got.Answer), recordTypes(got.Extra))
			}
			if len(got.Extra) == 0 || got.Extra[len(got.Extra)-1].Header().Rrtype != dns.TypeOPT {
				t.Errorf("the additional section is %v, want the client's OPT record kept", recordTypes(got.Extra))
			}
			// And the hint the record carries is still the only address the client
			// is left with.
			if hints := hintOf(t, httpsIn(t, got.Answer)); !reflect.DeepEqual(hints, []string{selectedIP}) {
				t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
			}
		})
	}
}

// TestHTTPSRefusesToSynthesizeBesideACnameAtTheQueriedOwner is what the branch
// unification forced into the open. Once both branches put the synthesized record
// where the records of the name were, a response whose answer already carries a CNAME
// at that name would be answered with a CNAME and a service mode at one owner, which
// RFC 1034 Section 3.6.2 calls an illegal combination and a client is entitled to
// reject. So a CNAME at the name the plugin is rewriting for is a refusal, and the
// reason is worth stating: the upstream has delegated this name to another one, and
// the service the client would reach is described under the other name. A caller that
// wanted the delegation followed is the caller that should follow it -- the address
// rewrite, which walks a chain to its terminal name and rewrites the address there --
// not this one, whose whole output is a service mode for the name it was asked about.
//
// Both policies are checked, because they disagree here in a way an operator has to be
// able to see: a strict domain is unreachable over HTTPS while the delegation stands,
// and a fallback domain keeps the upstream's own chain and stays reachable with a
// ClientHello this router could not encrypt.
func TestHTTPSRefusesToSynthesizeBesideACnameAtTheQueriedOwner(t *testing.T) {
	chained := response("cdn.example.", dns.TypeHTTPS,
		answerCNAME("cdn.example.", "edge.example.net.", 300),
		httpsRecord("edge.example.net.", 300, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h1"}}),
	)

	t.Run("a strict caller is refused", func(t *testing.T) {
		got, err := HTTPS(httpsInput(t, chained))
		if err == nil {
			t.Fatalf("HTTPS answered a name the upstream delegated: %s", answered(got))
		}
		if got != nil {
			t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
		}
		if !errors.Is(err, ErrDelegatedName) {
			t.Fatalf("error = %v, want one a caller can recognise as %v", err, ErrDelegatedName)
		}
	})

	t.Run("a fallback caller keeps the upstream's own chain", func(t *testing.T) {
		before := packed(t, chained)
		got, err := HTTPS(HTTPSInput{
			Response: chained,
			QName:    "cdn.example.",
			Selected: selected(),
			ECH:      echFixture(t),
			Policy:   FallbackToOriginal,
		})
		if got != chained {
			t.Fatalf("HTTPS built a new message where the policy was to keep the upstream's own: %s", answered(got))
		}
		if !errors.Is(err, ErrDelegatedName) {
			t.Errorf("error = %v, want %v beside the message: the caller has to learn the name is delegated or it flies blind", err, ErrDelegatedName)
		}
		if after := packed(t, chained); string(after) != string(before) {
			t.Errorf("HTTPS changed the response it was given:\n before %s\n after  %s", before, after)
		}
	})
}

// TestHTTPSFallsBackToTheOriginalWhenTheSelectorHasNoAddress is the health gate
// reaching the record, and it is the one refusal whose two policies genuinely differ.
//
// The strict arm refuses. A record with no hint is a record that sends the client to
// resolve the name, and for a force-ECH domain that resolution is the one this router
// empties, so a hint at an address nobody proved -- or no hint at all -- is the failure
// the project exists to prevent rather than a degraded answer.
//
// The fallback arm keeps working, and that is the decision the plan now specifies. A
// selector that is down, or a winner that has not passed its health check, takes no
// address away from anybody: the upstream's HTTPS record is still there, it still
// describes the service, and a client that can use it should not be told SERVFAIL
// because this router's own health check had a bad minute. Nothing is injected in its
// place either, and that is the point: with no address to hint there is no hint to
// write, and a record carrying the upstream's own address is one this router can
// forward without claiming anything about it. The one thing it cannot do is encrypt the
// ClientHello, which is what the refusal beside the message says.
func TestHTTPSFallsBackToTheOriginalWhenTheSelectorHasNoAddress(t *testing.T) {
	newUpstream := func() *dns.Msg {
		return signedHTTPSResponse(httpsRecord("cdn.example.", 300, 1, ".",
			&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
			&dns.SVCBPort{Port: 443},
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("104.16.1.1").To4()}},
		))
	}

	t.Run("a strict caller is refused", func(t *testing.T) {
		upstream := newUpstream()
		got, err := HTTPS(HTTPSInput{
			Response: upstream,
			QName:    "cdn.example.",
			Selected: netip.Addr{},
			ECH:      echFixture(t),
			Policy:   FailClosed,
		})
		if err == nil {
			t.Fatalf("HTTPS answered without an address to hint: %s", answered(got))
		}
		if got != nil {
			t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
		}
		if !errors.Is(err, ErrNoSelectedAddress) {
			t.Fatalf("error = %v, want one a caller can recognise as %v", err, ErrNoSelectedAddress)
		}
	})

	t.Run("a fallback caller keeps the upstream's own record", func(t *testing.T) {
		upstream := newUpstream()
		before := packed(t, upstream)

		got, err := HTTPS(HTTPSInput{
			Response: upstream,
			QName:    "cdn.example.",
			Selected: netip.Addr{},
			ECH:      echFixture(t),
			Policy:   FallbackToOriginal,
		})
		if !errors.Is(err, ErrNoSelectedAddress) {
			t.Errorf("error = %v, want %v beside the message: the caller has to learn the selector failed or it flies blind", err, ErrNoSelectedAddress)
		}
		if got != upstream {
			t.Fatalf("HTTPS built a new message where the policy was to keep the upstream's own: %s", answered(got))
		}
		assertUnmodified(t, upstream, before)

		// The record the client reads is the upstream's, so the address in it is the
		// upstream's own and no key was put into a record this router could not
		// vouch for the address of.
		out := keptHTTPS(t, got)
		if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{"104.16.1.1"}) {
			t.Errorf("ipv4hint = %v, want the upstream's own [104.16.1.1]: there is no address to hint, so no hint may be written", hints)
		}
		if carries(out, dns.SVCB_ECHCONFIG) {
			t.Errorf("an ech parameter was added to a record with no address to point at: %s", carried(out))
		}
		if carries(out, dns.SVCB_MANDATORY) {
			t.Errorf("a mandatory list was added to a record with no key in it: %s", carried(out))
		}
		if !got.AuthenticatedData {
			t.Error("AD was cleared on a response this router did not modify")
		}
	})
}

// TestHTTPSRefusesAnUpstreamAnswerItMustNotTurnIntoAPositiveOne is the boundary
// between an absence and a statement. The ECH source lookup and the selected address
// do not depend on what the upstream had, so an upstream that had nothing to say --
// a NODATA, a SERVFAIL, a REFUSED -- is no reason to hand a force-ECH client nothing,
// and those are the rcodes this router will build an answer on top of.
//
// Everything else is a statement about the name. NXDOMAIN says the name does not
// exist, and manufacturing a service binding for a name the authoritative data denies
// is not this router's decision to make; a FORMERR or a NOTIMP says the resolver could
// not do what was asked, and reading a synthesized service mode out of that is reading
// something the upstream never said. A failure that carries records is refused too:
// a SERVFAIL with an answer in it is not a failure this router can see past, and the
// records in it are for a question whose answer nobody has.
//
// The fallback arm is checked for the case where the client is better served by the
// upstream's own denial: an NXDOMAIN is an answer, a client caches it, and forwarding it
// is what the client would have got without this router in the path.
func TestHTTPSRefusesAnUpstreamAnswerItMustNotTurnIntoAPositiveOne(t *testing.T) {
	denial := func() *dns.Msg {
		msg := response("cdn.example.", dns.TypeHTTPS)
		msg.Rcode = dns.RcodeNameError
		msg.Ns = []dns.RR{answerSOA()}
		return msg
	}

	for _, tt := range []struct {
		name    string
		in      *dns.Msg
		wantErr error
	}{
		{
			name: "NOERROR with nothing published for the name",
			in:   response("cdn.example.", dns.TypeHTTPS),
		},
		{
			name: "a SERVFAIL with no records",
			in: func() *dns.Msg {
				msg := response("cdn.example.", dns.TypeHTTPS)
				msg.Rcode = dns.RcodeServerFailure
				return msg
			}(),
		},
		{
			name: "a REFUSED with no records",
			in: func() *dns.Msg {
				msg := response("cdn.example.", dns.TypeHTTPS)
				msg.Rcode = dns.RcodeRefused
				return msg
			}(),
		},
		{
			name:    "an NXDOMAIN",
			in:      denial(),
			wantErr: ErrUpstreamDenial,
		},
		{
			name: "a FORMERR",
			in: func() *dns.Msg {
				msg := response("cdn.example.", dns.TypeHTTPS)
				msg.Rcode = dns.RcodeFormatError
				return msg
			}(),
			wantErr: ErrUpstreamDenial,
		},
		{
			name: "a NOTIMP",
			in: func() *dns.Msg {
				msg := response("cdn.example.", dns.TypeHTTPS)
				msg.Rcode = dns.RcodeNotImplemented
				return msg
			}(),
			wantErr: ErrUpstreamDenial,
		},
		{
			name: "a SERVFAIL that carries records anyway",
			in: func() *dns.Msg {
				msg := response("cdn.example.", dns.TypeHTTPS, answerA("other.example.", "104.16.1.1", 300))
				msg.Rcode = dns.RcodeServerFailure
				return msg
			}(),
			wantErr: ErrUpstreamDenial,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HTTPS(httpsInput(t, tt.in))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("HTTPS refused an answer it may build on: %v", err)
				}
				if got.Rcode != dns.RcodeSuccess {
					t.Errorf("the answer is %s, want NOERROR", dns.RcodeToString[got.Rcode])
				}
				if ech := echOf(t, httpsIn(t, got.Answer)); !reflect.DeepEqual(ech, echFixture(t)) {
					t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
				}
				return
			}
			if err == nil {
				t.Fatalf("HTTPS turned the upstream's answer into a positive one: %s", answered(got))
			}
			if got != nil {
				t.Fatalf("HTTPS returned a message beside the error: %s", answered(got))
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want one a caller can recognise as %v", err, tt.wantErr)
			}
		})
	}

	t.Run("a fallback caller forwards the upstream's own denial", func(t *testing.T) {
		upstream := denial()
		before := packed(t, upstream)

		got, err := HTTPS(HTTPSInput{
			Response: upstream,
			QName:    "cdn.example.",
			Selected: selected(),
			ECH:      echFixture(t),
			Policy:   FallbackToOriginal,
		})
		if !errors.Is(err, ErrUpstreamDenial) {
			t.Errorf("error = %v, want %v beside the message", err, ErrUpstreamDenial)
		}
		if got != upstream {
			t.Fatalf("HTTPS built a new message where the policy was to keep the upstream's own: %s", answered(got))
		}
		if after := packed(t, upstream); string(after) != string(before) {
			t.Errorf("HTTPS changed the response it was given:\n before %s\n after  %s", before, after)
		}
	})
}

// TestHTTPSRoundTripsTheMinimalRecordThroughTheWire is the wire check for the path
// with no upstream record to copy anything from, which is the one a browser in a
// strict domain is most likely to meet: the resolver had nothing, and the answer was
// made here. Everything about the record is written out as a literal, including the
// order the keys reach the wire in, which is mandatory(0), alpn(1), ipv4hint(4),
// ech(5) -- the library's packer sorts them, and this package does not choose.
func TestHTTPSRoundTripsTheMinimalRecordThroughTheWire(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS)
	upstream.Extra = []dns.RR{answerOPT()}

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	out := httpsIn(t, roundTripped(t, got).Answer)

	if keys := carried(out); keys != "mandatory alpn ipv4hint ech" {
		t.Errorf("the record carries %s, want mandatory alpn ipv4hint ech in the order the wire requires", keys)
	}
	if out.Hdr.Name != "cdn.example." || out.Hdr.Class != dns.ClassINET || out.Hdr.Ttl != 0 {
		t.Errorf("the record is %q %d/%d TTL %d, want cdn.example. IN TTL 0", out.Hdr.Name, out.Hdr.Class, out.Hdr.Rrtype, out.Hdr.Ttl)
	}
	if out.Priority != 1 || out.Target != "." {
		t.Errorf("the record is priority %d target %q, want priority 1 target \".\"", out.Priority, out.Target)
	}
	if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2", "h3"}) {
		t.Errorf("alpn = %v, want [h2 h3]", alpn)
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
		t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
	}
	if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
		t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
	}
	if mandatory := mandatoryOf(t, out); !reflect.DeepEqual(mandatory, []dns.SVCBKey{dns.SVCB_ECHCONFIG}) {
		t.Errorf("mandatory = %v, want [ech]", mandatory)
	}
	if carried(out) == carried(&dns.HTTPS{SVCB: dns.SVCB{}}) {
		t.Error("the round trip produced an empty record")
	}
	selfConsistent(t, out)
}

// TestHTTPSKeepsAZeroLifetimeTheUpstreamPublished is where this package and the
// address rewrite disagree on purpose, and the disagreement is worth stating rather
// than papering over. Address refuses to replace a record set whose TTL is zero,
// because it has to invent a lifetime for the replacement and a record with no
// lifetime is a record it cannot make any claim about. This function has no such
// problem: a TTL of zero here is never invented. It is either the shortest of the TTLs
// the records being replaced carried -- the upstream saying it does not want these
// cached, which the replacement repeats -- or the zero a record made from nothing
// carries because there was no lifetime to inherit. Both are claims somebody else made,
// or the absence of one, and neither is a lifetime this router chose.
func TestHTTPSKeepsAZeroLifetimeTheUpstreamPublished(t *testing.T) {
	zero := httpsRecord("cdn.example.", 0, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}})
	live := httpsRecord("cdn.example.", 300, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}})
	mixed := httpsRecord("cdn.example.", 120, 1, "svc.example.net.", &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}})

	for _, tt := range []struct {
		name    string
		records []dns.RR
		want    uint32
	}{
		{name: "one record that says do not cache it", records: []dns.RR{zero}, want: 0},
		{name: "one of two says do not cache it", records: []dns.RR{live, zero}, want: 0},
		{name: "one of two says cache it longer", records: []dns.RR{zero, live}, want: 0},
		{name: "neither says anything about caching", records: []dns.RR{live, mixed}, want: 120},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream := response("cdn.example.", dns.TypeHTTPS, tt.records...)

			got, err := HTTPS(httpsInput(t, upstream))
			if err != nil {
				t.Fatalf("HTTPS refused a record set over its lifetime: %v", err)
			}
			if out := httpsIn(t, got.Answer); out.Hdr.Ttl != tt.want {
				t.Errorf("TTL = %d, want %d", out.Hdr.Ttl, tt.want)
			}
		})
	}
}

// TestHTTPSSharesNoBufferWithTheResponseItWasGiven is the other half of the rule the
// test above states as non-mutation, and the two fail independently. Not writing to
// the caller's response is what a read-only synthesis looks like; sharing no buffer
// with it is what a copy looks like, and a synthesis that reads a parameter and keeps
// the pointer it read has done the first and not the second. The difference matters
// because the caller is a plugin in front of a cache that owns the object: the next
// reader of that cache may rewrite the very parameters this answer now refers to, and
// a browser would be handed a parameter set that changed under it.
//
// So the caller's own parameters are corrupted after the call and the answer is compared
// as wire bytes before and after. Comparing the bytes catches a change in a header bit,
// in a length prefix, or in the order of anything; the value assertions say which
// parameter it was. That the caller's own object does change here is the point -- the
// other test above holds that HTTPS itself never writes to it.
func TestHTTPSSharesNoBufferWithTheResponseItWasGiven(t *testing.T) {
	local := &dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")}
	alpn := &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}
	dohpath := &dns.SVCBDoHPath{Template: "/dns-query{?dns}"}
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".", alpn, dohpath, local))

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	wire := packed(t, got)

	// The caller keeps using its own response: it is going into a cache, and
	// something else is entitled to edit it. Three of its parameters are edited here,
	// one buffer at a time.
	local.Data[0] = 'X'
	alpn.Alpn[0] = "h9"
	dohpath.Template = "/elsewhere"

	if now := packed(t, got); string(now) != string(wire) {
		t.Errorf("the answer changed when the caller's own parameters were edited:\n before %s\n after  %s", wire, now)
	}
	out := httpsIn(t, got.Answer)
	if kept := param(t, out, localKey).(*dns.SVCBLocal).Data; string(kept) != "probe" {
		t.Errorf("key65400 = %q after the caller edited its own buffer, want %q: the answer refers to the caller's parameter", kept, "probe")
	}
	if kept := alpnOf(t, out); kept[0] != "h2" {
		t.Errorf("alpn = %v after the caller edited its own parameter, want [h2 h3]: the answer refers to the caller's parameter", kept)
	}
	if kept := param(t, out, dns.SVCB_DOHPATH).(*dns.SVCBDoHPath).Template; kept != "/dns-query{?dns}" {
		t.Errorf("dohpath = %q after the caller edited its own parameter, want the upstream's template: the answer refers to the caller's parameter", kept)
	}
}

// reportRecorder is the caller side of the report channel: it stands in for a plugin
// that logs or counts what the synthesis left out.
type reportRecorder struct {
	calls  int
	report Report
}

func (r *reportRecorder) capture(report Report) {
	r.calls++
	r.report = report
}

// reportOf runs a call with the report channel attached and returns what it said. A
// channel that was never called is a report with nothing in it, which is what a
// synthesis that kept every parameter it inherited has to say.
func reportOf(t *testing.T, in HTTPSInput) Report {
	t.Helper()
	recorder := &reportRecorder{}
	in.Report = recorder.capture
	if _, err := HTTPS(in); err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	return recorder.report
}

// droppedKeys lists the keys a report named, in the order it named them. A report that
// named nothing yields nothing rather than an empty list, so a test can say "nothing
// was dropped" by leaving its expectation unset.
func droppedKeys(report Report) []dns.SVCBKey {
	if len(report.Dropped) == 0 {
		return nil
	}
	out := make([]dns.SVCBKey, 0, len(report.Dropped))
	for _, drop := range report.Dropped {
		out = append(out, drop.Key)
	}
	return out
}

// droppedReason returns the reason a report gave for one key, or the empty string if
// it named no such key.
func droppedReason(report Report, key dns.SVCBKey) string {
	for _, drop := range report.Dropped {
		if drop.Key == key {
			return drop.Reason
		}
	}
	return ""
}

// TestHTTPSKeepsAParameterOnlyWhenEveryEndpointAgreesOnIt is the merge rule for an
// RRset with more than one service mode, and it is one rule rather than two: a
// parameter survives only when every retained endpoint carries it and every one of
// them carries the same value.
//
// The presence half is the half that decides this. RFC 9460 Section 7.2 says a client
// that finds no port uses the authority endpoint's port, so an endpoint that omits a
// parameter is not silent, it is claiming the default. Merging an endpoint that names
// port 8443 with one that names no port and keeping 8443 tells every client to hit a
// port the second endpoint never offered, and no client can tell that from a service
// that really does listen on 8443. So absence loses the parameter the same way a
// disagreement does: the key goes, every client falls back to the default the endpoints
// implied, and the caller is told which key went and why, because a record missing a
// parameter the upstream published is a degraded answer and a plugin that cannot see
// the degradation cannot log it.
func TestHTTPSKeepsAParameterOnlyWhenEveryEndpointAgreesOnIt(t *testing.T) {
	// Four parameters, the two the endpoints below agree about and the two they are
	// made to disagree about.
	agreeing := func() *dns.HTTPS {
		return httpsRecord("cdn.example.", 300, 1, "svc.example.net.",
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
			&dns.SVCBPort{Port: 8443},
			&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
			&dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")},
		)
	}
	differentValue := func() *dns.HTTPS {
		return httpsRecord("cdn.example.", 300, 1, "edge.example.net.",
			&dns.SVCBAlpn{Alpn: []string{"h3"}},
			&dns.SVCBPort{Port: 8443},
			&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
			&dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")},
		)
	}
	// The same endpoint as the one above with the port left out. Everything else is
	// identical, so the port is the only thing the two disagree about.
	noPort := func() *dns.HTTPS {
		return httpsRecord("cdn.example.", 300, 1, "edge.example.net.",
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
			&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
			&dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")},
		)
	}
	// And the same again with the alpn left out, so the rule is shown to be about every
	// key rather than about the one that happens to matter most.
	noAlpn := func() *dns.HTTPS {
		return httpsRecord("cdn.example.", 300, 1, "edge.example.net.",
			&dns.SVCBPort{Port: 8443},
			&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
			&dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")},
		)
	}
	// The pair for the mandatory case, which agrees about the alpn and about nothing
	// else: the second record is the first without the port.
	alpnOnly := func() *dns.HTTPS {
		return httpsRecord("cdn.example.", 300, 1, "edge.example.net.",
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
		)
	}
	portIsMandatory := func() *dns.HTTPS {
		return httpsRecord("cdn.example.", 300, 1, ".",
			&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_PORT}},
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
			&dns.SVCBPort{Port: 8443},
		)
	}

	tests := []struct {
		name    string
		records []*dns.HTTPS
		carried string
		dropped []dns.SVCBKey
		// names is a word the reason for each dropped key has to contain, so the
		// report is checked for saying which fault it was rather than for the exact
		// sentence, which is a message and not a contract.
		names string
		// mandatory, when set, is the exact list the record has to carry, written in
		// the order the package builds it. It is set only where the case is about the
		// list rather than about the parameters.
		mandatory string
	}{
		{
			name:    "endpoints that describe the same service keep everything",
			records: []*dns.HTTPS{agreeing(), agreeing()},
			carried: "mandatory alpn port ipv4hint ech dohpath key65400",
		},
		{
			name:    "a value the endpoints describe differently is dropped",
			records: []*dns.HTTPS{agreeing(), differentValue()},
			carried: "mandatory port ipv4hint ech dohpath key65400",
			dropped: []dns.SVCBKey{dns.SVCB_ALPN},
			names:   "differently",
		},
		{
			name:    "a parameter only one endpoint carries is dropped",
			records: []*dns.HTTPS{agreeing(), noPort()},
			carried: "mandatory alpn ipv4hint ech dohpath key65400",
			dropped: []dns.SVCBKey{dns.SVCB_PORT},
			names:   "omits",
		},
		{
			name:    "alpn is dropped for the same reason as any other key",
			records: []*dns.HTTPS{agreeing(), noAlpn()},
			carried: "mandatory port ipv4hint ech dohpath key65400",
			dropped: []dns.SVCBKey{dns.SVCB_ALPN},
			names:   "omits",
		},
		{
			name:      "a mandatory key lost with the parameter leaves the list",
			records:   []*dns.HTTPS{portIsMandatory(), alpnOnly()},
			carried:   "mandatory alpn ipv4hint ech",
			dropped:   []dns.SVCBKey{dns.SVCB_PORT},
			names:     "omits",
			mandatory: "ech alpn",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answers := make([]dns.RR, 0, len(tt.records))
			for _, record := range tt.records {
				answers = append(answers, record)
			}
			upstream := response("cdn.example.", dns.TypeHTTPS, answers...)

			report := reportOf(t, httpsInput(t, upstream))
			got, err := HTTPS(httpsInput(t, upstream))
			if err != nil {
				t.Fatalf("HTTPS: %v", err)
			}
			out := httpsIn(t, got.Answer)

			if keys := carriedOnTheWire(t, out); keys != tt.carried {
				t.Errorf("the record carries %s, want %s", keys, tt.carried)
			}
			if dropped := droppedKeys(report); !reflect.DeepEqual(dropped, tt.dropped) {
				t.Errorf("the report names %v as left out, want %v", dropped, tt.dropped)
			}
			if tt.names != "" {
				for _, key := range tt.dropped {
					if reason := droppedReason(report, key); !strings.Contains(reason, tt.names) {
						t.Errorf("the reason for leaving out %s is %q, want a reason that says %q", key, reason, tt.names)
					}
				}
			}
			// Whatever the endpoints disagreed about, the record this router wrote is
			// still a record a client can use, and still one whose mandatory list
			// names nothing it does not carry.
			if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
				t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
			}
			if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
				t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
			}
			if tt.mandatory != "" {
				keys := mandatoryOf(t, out)
				names := make([]string, 0, len(keys))
				for _, key := range keys {
					names = append(names, key.String())
				}
				if got := strings.Join(names, " "); got != tt.mandatory {
					t.Errorf("mandatory = %q, want %q: a parameter the record no longer carries must not be named", got, tt.mandatory)
				}
			}
			selfConsistent(t, out)
		})
	}
}

// TestHTTPSReportsNothingWhenEveryEndpointAgrees states the other side of the report:
// a synthesis that lost nothing says nothing, so a plugin counting degraded answers is
// not counting every answer. A report channel that fires on every call trains an
// operator to ignore it.
func TestHTTPSReportsNothingWhenEveryEndpointAgrees(t *testing.T) {
	record := httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 443},
	)
	upstream := response("cdn.example.", dns.TypeHTTPS, record)

	recorder := &reportRecorder{}
	in := httpsInput(t, upstream)
	in.Report = recorder.capture
	if _, err := HTTPS(in); err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	if recorder.calls != 0 {
		t.Errorf("the report channel was called %d time(s) for a synthesis that lost nothing", recorder.calls)
	}

	// And the same call with no channel at all must be the same answer: the channel is
	// a report and not a result.
	without, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	with, err := HTTPS(in)
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	if a, b := packed(t, without), packed(t, with); string(a) != string(b) {
		t.Errorf("attaching a report channel changed the answer:\n without %s\n with    %s", a, b)
	}
}
