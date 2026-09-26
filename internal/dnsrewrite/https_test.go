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
	if err != nil {
		t.Fatalf("HTTPS refused a response it should have kept: %v", err)
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

// TestHTTPSMergesCompatibleEndpointsAndDropsWhatTheyDisagreeAbout is the rule for
// an RRset with more than one service mode, which is what a CDN publishes when it
// has more than one endpoint. Every endpoint that can be used contributes, and a
// parameter the endpoints describe differently is dropped rather than resolved:
// this router cannot tell which of two claims about a port or a protocol set the
// service really has, and a value it picked would be one it invented. The
// consequence of dropping a parameter is a record a client can still connect
// through, which is why a disagreement is not a refusal.
func TestHTTPSMergesCompatibleEndpointsAndDropsWhatTheyDisagreeAbout(t *testing.T) {
	first := httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2"}},
		&dns.SVCBPort{Port: 8443},
		&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
	)
	agreeing := httpsRecord("cdn.example.", 300, 1, "svc.example.net.",
		&dns.SVCBAlpn{Alpn: []string{"h2"}},
		&dns.SVCBPort{Port: 8443},
		&dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")},
	)
	disagreeing := httpsRecord("cdn.example.", 300, 1, "edge.example.net.",
		&dns.SVCBAlpn{Alpn: []string{"h3"}},
		&dns.SVCBPort{Port: 443},
		&dns.SVCBLocal{KeyCode: localKey, Data: []byte("probe")},
	)

	t.Run("endpoints that agree keep every parameter", func(t *testing.T) {
		upstream := response("cdn.example.", dns.TypeHTTPS, first, agreeing)
		got, err := HTTPS(httpsInput(t, upstream))
		if err != nil {
			t.Fatalf("HTTPS: %v", err)
		}
		out := onlyHTTPS(t, got)
		if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2"}) {
			t.Errorf("alpn = %v, want [h2]: both endpoints say the same thing", alpn)
		}
		port, _ := param(t, out, dns.SVCB_PORT).(*dns.SVCBPort)
		if port == nil || port.Port != 8443 {
			t.Errorf("port = %v, want 8443: both endpoints say the same thing", port)
		}
		local, ok := param(t, out, localKey).(*dns.SVCBLocal)
		if !ok {
			t.Fatalf("the key65400 parameter is %T, want *dns.SVCBLocal", param(t, out, localKey))
		}
		if string(local.Data) != "probe" {
			t.Errorf("key65400 = %q, want %q: a parameter only one endpoint carries is still a parameter it carries", local.Data, "probe")
		}
	})

	t.Run("endpoints that disagree lose the parameter and keep the record", func(t *testing.T) {
		upstream := response("cdn.example.", dns.TypeHTTPS, first, disagreeing)
		got, err := HTTPS(httpsInput(t, upstream))
		if err != nil {
			t.Fatalf("HTTPS refused an answer whose endpoints disagree: %v", err)
		}
		out := onlyHTTPS(t, got)
		if carries(out, dns.SVCB_ALPN) {
			t.Errorf("alpn survived from endpoints that name different protocol sets: %s", carried(out))
		}
		if carries(out, dns.SVCB_PORT) {
			t.Errorf("port survived from endpoints that name different ports: %s", carried(out))
		}
		if !carries(out, dns.SVCB_DOHPATH) {
			t.Errorf("dohpath was dropped although only one endpoint carries it: %s", carried(out))
		}
		if !carries(out, localKey) {
			t.Errorf("key65400 was dropped although only one endpoint carries it: %s", carried(out))
		}
		if ech := echOf(t, out); !reflect.DeepEqual(ech, echFixture(t)) {
			t.Errorf("ech = %d bytes, want the %d validated bytes, byte for byte", len(ech), len(echFixture(t)))
		}
		if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
			t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
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
	upstream := response("cdn.example.", dns.TypeHTTPS,
		httpsRecord("cdn.example.", 300, 1, ".",
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
			&dns.SVCBNoDefaultAlpn{},
		),
		httpsRecord("cdn.example.", 300, 1, ".",
			&dns.SVCBAlpn{Alpn: []string{"h3"}},
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
	selfConsistent(t, out)
}

// TestHTTPSUsesNothingFromAnAliasModeRecord states what an alias is. RFC 9460
// Section 2.4.2 has recipients ignore every SvcParam on an alias, so a port or an
// alpn read out of one describes a service this router cannot know anything about,
// and copying it into a service mode would be inventing a binding. An alias also
// carries no address, which is the same situation as no record at all: the key and
// the selected address are enough to answer, and nothing is inherited.
func TestHTTPSUsesNothingFromAnAliasModeRecord(t *testing.T) {
	alias := httpsRecord("cdn.example.", 300, 0, "svc.example.net.",
		&dns.SVCBAlpn{Alpn: []string{"h1"}},
		&dns.SVCBPort{Port: 8443},
	)

	t.Run("alone it yields the minimal record", func(t *testing.T) {
		upstream := response("cdn.example.", dns.TypeHTTPS, alias)
		got, err := HTTPS(httpsInput(t, upstream))
		if err != nil {
			t.Fatalf("HTTPS refused a name whose only record is an alias: %v", err)
		}
		out := onlyHTTPS(t, got)
		if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2", "h3"}) {
			t.Errorf("alpn = %v, want [h2 h3]: an alias's parameters are ignored, so none of them may be inherited", alpn)
		}
		if carries(out, dns.SVCB_PORT) {
			t.Errorf("a port was read out of an alias: %s", carried(out))
		}
		if out.Hdr.Ttl != 0 {
			t.Errorf("TTL = %d, want 0: an alias's lifetime is not the lifetime of a record this router synthesized", out.Hdr.Ttl)
		}
		if out.Priority != 1 || out.Target != "." {
			t.Errorf("the record is priority %d target %q, want priority 1 target \".\"", out.Priority, out.Target)
		}
	})

	t.Run("beside a service mode only the service mode is read", func(t *testing.T) {
		upstream := response("cdn.example.", dns.TypeHTTPS, alias, httpsRecord("cdn.example.", 300, 1, ".",
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
			&dns.SVCBPort{Port: 443},
		))
		got, err := HTTPS(httpsInput(t, upstream))
		if err != nil {
			t.Fatalf("HTTPS: %v", err)
		}
		out := onlyHTTPS(t, got)
		if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2"}) {
			t.Errorf("alpn = %v, want [h2] from the service mode record alone", alpn)
		}
		port, _ := param(t, out, dns.SVCB_PORT).(*dns.SVCBPort)
		if port == nil || port.Port != 443 {
			t.Errorf("port = %v, want 443 from the service mode record, not 8443 from the alias", port)
		}
		if out.Hdr.Ttl != 300 {
			t.Errorf("TTL = %d, want the service mode record's 300", out.Hdr.Ttl)
		}
	})
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
	synthesized := response("cdn.example.", dns.TypeHTTPS)
	synthesized.Rcode = dns.RcodeServerFailure
	synthesized.AuthenticatedData = true
	synthesized.CheckingDisabled = true
	synthesized.Answer = []dns.RR{signature("cdn.example.", "example.net.", dns.TypeHTTPS, 300)}
	synthesized.Ns = []dns.RR{
		answerSOA(),
		nsec("example.net.", "example.org.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC),
		signature("example.net.", "example.net.", dns.TypeSOA, 3600),
	}
	synthesized.Extra = []dns.RR{answerOPT(), answerA("cdn.example.", "104.16.1.1", 300)}

	for _, tt := range []struct {
		name             string
		in               *dns.Msg
		checkingDisabled bool
	}{
		{name: "a rewritten record set", in: rewritten},
		{name: "a record synthesized from an upstream failure", in: synthesized, checkingDisabled: true},
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
// HTTPS RRset that would undo the selection. RFC 9460 Section 7.3 has a client
// ignore the hints when it already holds an A or AAAA answer for the effective
// target, and the effective target of the record this router writes is the name the
// client asked about. A resolver that put that name's anycast address in the
// additional section has therefore published an answer that beats the hint, and the
// browser would connect to the address the health check never proved. Addresses for
// any other name belong to a different RRset and are left alone, and the OPT record
// is not an address at all.
func TestHTTPSRemovesTheAddressOfTheNameItNowPointsAt(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS, httpsRecord("cdn.example.", 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
	))
	upstream.Extra = []dns.RR{
		answerA("cdn.example.", "104.16.1.1", 300),
		answerAAAA("cdn.example.", "2606:4700::1111", 300),
		answerA("svc.example.net.", "104.16.2.2", 300),
		answerOPT(),
	}

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	if countType(got.Extra, dns.TypeA) != 1 {
		t.Errorf("the additional section is %v, want the address of cdn.example. gone and the one of svc.example.net. kept", recordTypes(got.Extra))
	}
	for _, rr := range got.Extra {
		if !sameName(rr.Header().Name, "cdn.example.") {
			continue
		}
		if record, ok := rr.(*dns.A); ok {
			t.Errorf("the address of the name this record now points at survived in the additional section: %s", record)
		}
		if record, ok := rr.(*dns.AAAA); ok {
			t.Errorf("the IPv6 address of the name this record now points at survived in the additional section: %s", record)
		}
	}
	if len(got.Extra) == 0 || got.Extra[len(got.Extra)-1].Header().Rrtype != dns.TypeOPT {
		t.Errorf("the additional section is %v, want the client's OPT record kept", recordTypes(got.Extra))
	}
}

// TestHTTPSAnswersTheNameTheClientAskedAbout is the CNAME case, and it is a
// property of the answer rather than of a parameter. A client that followed a CNAME
// would ask the resolver for the name at the end of the chain, and for a force-ECH
// domain that name has no address either, so a synthesis that left the chain in
// front of the record would be answered with nothing at all. The record therefore
// answers the question that was asked, and the chain is not in the answer.
func TestHTTPSAnswersTheNameTheClientAskedAbout(t *testing.T) {
	upstream := response("cdn.example.", dns.TypeHTTPS,
		answerCNAME("cdn.example.", "edge.example.net.", 300),
		httpsRecord("edge.example.net.", 300, 1, ".", &dns.SVCBAlpn{Alpn: []string{"h1"}}),
	)

	got, err := HTTPS(httpsInput(t, upstream))
	if err != nil {
		t.Fatalf("HTTPS let a CNAME chain stop an answer it could give: %v", err)
	}
	out := onlyHTTPS(t, got)
	if out.Hdr.Name != "cdn.example." {
		t.Errorf("the record answers for %q, want the name the client asked about, %q", out.Hdr.Name, "cdn.example.")
	}
	if alpn := alpnOf(t, out); !reflect.DeepEqual(alpn, []string{"h2", "h3"}) {
		t.Errorf("alpn = %v, want [h2 h3]: a record published under the name at the end of a chain is not a record for this name", alpn)
	}
	if hints := hintOf(t, out); !reflect.DeepEqual(hints, []string{selectedIP}) {
		t.Errorf("ipv4hint = %v, want exactly [%s]", hints, selectedIP)
	}
}
