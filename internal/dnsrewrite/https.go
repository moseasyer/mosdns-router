package dnsrewrite

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"mosdns-router/internal/echconfig"
)

// FailurePolicy is what a caller wants done with an answer this package cannot
// synthesize. It is the plugin's ech.failure_policy, and it is an argument rather
// than a decision because the two policies are opposites in a way only the caller
// is placed to judge: a strict domain must fail closed, so a refusal is the whole
// point, and a fallback domain must keep what the upstream published, so there a
// refusal means the original is handed back instead.
type FailurePolicy int

const (
	// FailClosed refuses every answer this package cannot synthesize. It is the
	// strict arm: the client is given nothing rather than something that would
	// connect in the clear.
	FailClosed FailurePolicy = iota
	// FallbackToOriginal hands the caller's own response back whenever this router
	// cannot rewrite, and is the fallback arm: the upstream's HTTPS record is a
	// working answer, and removing it would be a downgrade this router has no
	// standing to impose. The refusal still comes back beside the message, so the
	// caller can see that the ECH source, the selector or the answer's shape is what
	// stopped the rewrite.
	FallbackToOriginal
)

// The refusals a caller has to be able to tell apart, because the two policies answer
// them differently and a caller that cannot tell which happened picks the wrong one.
// The taxonomy, in the order a caller has to test it:
//
//   - ErrNoECHConfig and ErrInvalidECHConfig: the ECH source has nothing to install,
//     or has something this router will not forward. They are separate because a
//     missing config is worth a retry and a corrupt one is not, and because a caller
//     that cannot tell them apart will keep a record when it should have blocked.
//   - ErrNoSelectedAddress: there is no address to point the client at -- none at all,
//     none proved, or one that failed its health check.
//   - ErrNoCompatibleEndpoint: the name published a service binding and every one of
//     them is unusable here. Nothing about the ECHConfig or the selected address is at
//     fault, so both policies fail: there is no better answer to hand back than the
//     endpoints that are unusable.
//   - ErrDelegatedName: the name belongs to somebody else. It is either a CNAME at
//     that owner, or an RRset there that contains an alias. The upstream describes a
//     service under another name, and a service mode synthesized here would contradict
//     that description rather than answer it.
//   - ErrUpstreamDenial: the upstream's answer is a statement about the name rather
//     than an absence of one, so there is nothing here to rewrite and nothing to
//     invent an answer from.
//   - ErrNoOriginal: there is no upstream answer to hand back.
//
// The order matters for one reason, and a caller that gets it wrong forwards a nil
// message. ErrNoOriginal wraps whichever refusal left nothing to forward, so
// errors.Is(err, ErrNoECHConfig) is also true of an ErrNoOriginal, and a caller that
// tests the inner cause first concludes there is an upstream record to keep and
// forwards the nil one. Test ErrNoOriginal first; forward whatever message arrived
// whatever the error; and fail closed when the message is nil, which is the shape a
// FailClosed caller always gets on a refusal.
var (
	ErrNoECHConfig          = errors.New("dnsrewrite: there is no ECHConfig to install")
	ErrInvalidECHConfig     = errors.New("dnsrewrite: the ECHConfig cannot be forwarded")
	ErrNoSelectedAddress    = errors.New("dnsrewrite: there is no selected IPv4 address to point the client at")
	ErrNoCompatibleEndpoint = errors.New("dnsrewrite: no upstream HTTPS endpoint can be used with the selected address")
	ErrDelegatedName        = errors.New("dnsrewrite: the name is delegated to another name, so no service binding may be synthesized for it")
	ErrUpstreamDenial       = errors.New("dnsrewrite: the upstream's answer is a statement about the name, not an absence of one")
	ErrNoOriginal           = errors.New("dnsrewrite: there is no upstream HTTPS record to keep")
)

// HTTPSInput is one authorized HTTPS rewrite: the response, the name it is being
// asked about, the address the selector proved, the ECHConfigList the ECH source
// published, and what to do about a refusal.
type HTTPSInput struct {
	// Response is the upstream response, and it is never modified. A synthesis
	// replaces an RRset this router does not own, so the caller's object belongs to
	// whoever reads the cache next.
	Response *dns.Msg
	// QName is the name the plugin is rewriting for. It is required, and it is
	// checked against the response's own question, because a record synthesized
	// under a name the response does not answer is an answer to a question nobody
	// asked.
	QName string
	// Selected is the address to hint, and it must be a routable public IPv4 address
	// on the same terms as the address rewrite. The hint is the only thing standing
	// between a client and a network the selector has not proved, so an address that
	// failed its health check must never become a hint. What happens then depends on
	// the policy: a strict caller is refused, because a record with no hint sends the
	// client to resolve the name and this router has emptied that resolution, while a
	// fallback caller is handed the upstream's own record, which carries the
	// upstream's own address and no key.
	Selected netip.Addr
	// ECH is the ECHConfigList the ECH source published: the SvcParamValue of an
	// ech parameter including the outer uint16 list length, which is exactly what
	// echconfig.List.Raw holds. It is taken as bytes rather than as a parsed list
	// so that the bytes installed here are the bytes this package validated, and
	// so that a list nobody validated cannot be forwarded.
	ECH []byte
	// Policy is what to do with an answer that cannot be synthesized. The zero
	// value fails closed, which is the safe direction for a name an operator put
	// on the force-ECH list.
	Policy FailurePolicy
	// Report, when it is set, is called once with the SvcParamKeys this router left
	// out of the record it synthesized, and why each one was left out. It is a
	// report and not a result: the record is the answer either way, and a caller
	// that does not set it loses nothing but the log line. It exists because a
	// record missing a parameter the upstream published is a degraded answer, and a
	// plugin that cannot see the degradation cannot log it or count it. The channel
	// is not called when nothing was left out, so a caller counting the calls is
	// counting degraded answers and nothing else.
	Report func(Report)
}

// Report is what one synthesis left out of the record it wrote.
type Report struct {
	// Dropped are the SvcParamKeys the record does not carry, in the order the
	// synthesis decided them.
	Dropped []DroppedParameter
}

// DroppedParameter is one SvcParamKey the synthesized record does not carry, and the
// reason. There are two reasons, and both are a client falling back to a default
// rather than being told one endpoint's claim: the endpoints described the value
// differently, or they did not all describe it at all. The second is the same kind
// of disagreement, and RFC 9460 Section 7.2 is why: a key that is not present is not
// silence, it is the instruction to use the value the authority endpoint implies.
type DroppedParameter struct {
	Key    dns.SVCBKey
	Reason string
}

// HTTPS synthesizes the HTTPS record a client reads to decide how to reach a name,
// or refuses to.
//
// It returns a copy carrying the synthesis when there is one to make, and the
// caller's own message with a refusal beside it when the policy says to keep what the
// upstream published. A strict caller is refused with a nil message instead, so the
// shape a caller has to handle is: a non-nil message may arrive with a non-nil error,
// and forward the message while logging the error. What never arrives is an error
// without a message on the fallback arm, or a message without a message-worthy cause:
// there is no third shape, and a caller that checks the error before using the
// message cannot get this wrong in the unsafe direction.
//
// The synthesized answer is always exactly one record: a ServiceMode for the name
// the client asked about, carrying the ECHConfig as its ech parameter, the selected
// address as its only IPv4 hint, and a mandatory list naming ech. A client that
// reads it encrypts its ClientHello to the key the source published and connects to
// the address the selector proved, and a client that can do neither is meant to
// fail rather than connect in the clear.
//
// Five rules decide what goes into that record, and each of them exists because the
// other answer is worse than none:
//
//   - A missing upstream record is not a failure. The ECH source lookup and the
//     selected address do not depend on what the upstream had, so a NODATA or a
//     SERVFAIL for the name is no reason to hand a force-ECH client nothing. The
//     record is then synthesized from the key and the address alone, and it claims
//     a TTL of zero because there is no upstream lifetime behind it to inherit.
//   - Compatibility is decided per endpoint, not per message. One record under an
//     IPv6 address, or one whose only address is an IPv6 hint, is an endpoint no
//     client can reach through anything this router publishes, so it contributes
//     nothing; a name that published service bindings and has no usable one left is
//     a refusal rather than a guess.
//   - A name the upstream has delegated is not answered for at all. A CNAME at the
//     queried owner, or an AliasMode record in the RRset there, means the service is
//     described under another name, and a service mode synthesized here would claim a
//     service that description denies. Both are refusals, and a fallback caller is
//     handed the upstream's own answer, which sends the client to the name the service
//     really has.
//   - A parameter is inherited only when every usable endpoint carries it and every
//     one of them carries the same value. A disagreement about a value is the
//     obvious case; a disagreement about whether the key is there at all is the
//     common one. RFC 9460 Section 7.2 makes an absent key an instruction to use the
//     default, so an endpoint that omits a parameter has claimed the default, and
//     one endpoint's value is not the service's value. A dropped parameter leaves a
//     record a client can still connect through, which is why a drop is not a
//     refusal, and every drop is reported through Report so a caller can see that
//     the answer it got is a degraded one.
//   - A mandatory list names only keys the record carries, each of them once. RFC
//     9460 Section 8 makes a record that names a key it does not carry, or names one
//     twice, one a client must reject, and for a force-ECH name that rejection is a
//     failed connection with nothing on the wire to explain it.
//   - Nothing this router writes carries an IPv6 hint, and no address of the name the
//     record now points at survives in any section, because RFC 9460 Section 7.3 has
//     a client prefer an answer it already holds to the hint beside it.
func HTTPS(in HTTPSInput) (*dns.Msg, error) {
	question, err := httpsQuestion(in)
	if err != nil {
		return nil, err
	}
	// Everything below reads the copy, not the caller's response. The parameters a
	// synthesis inherits are pointers, and a pointer the answer keeps is a pointer
	// the next reader of the caller's cache can rewrite under a browser that has
	// already been handed this answer, so the records harvested below are harvested
	// from the copy: nothing a client reads shares a buffer with the object the
	// caller still holds.
	clone := in.Response.Copy()
	if err := delegated(clone, question.Name); err != nil {
		return keepOrRefuse(in, question.Name, err)
	}
	published := recordsAt(clone, question.Name)

	list, err := validatedECH(in.ECH)
	if err != nil {
		return keepOrRefuse(in, question.Name, err)
	}
	if err := checkSelected(in.Selected); err != nil {
		return keepOrRefuse(in, question.Name, fmt.Errorf("%w: %s", ErrNoSelectedAddress, err))
	}
	if err := bypassable(clone); err != nil {
		return keepOrRefuse(in, question.Name, err)
	}
	found := classify(published)
	if found.aliases > 0 {
		return keepOrRefuse(in, question.Name, aliasRefusal(question.Name, found))
	}
	if found.bindings > 0 && len(found.usable) == 0 {
		return keepOrRefuse(in, question.Name, fmt.Errorf("%w: %q published %d service mode record(s) and none of them is usable: %s",
			ErrNoCompatibleEndpoint, question.Name, found.bindings, strings.Join(found.refusals, "; ")))
	}
	record, dropped := synthesized(question, found, list, in.Selected)

	// The answer is positive whatever the upstream said, because the record in it is
	// this router's and not the upstream's.
	intoPositiveAnswer(clone)
	// The record goes in where the records of this name were, whether there were any
	// or not, and the addresses of this name go from wherever they were. Neither
	// cares which branch this is.
	clone.Answer = replaceAt(clone.Answer, question.Name, record)
	dropAddressesOf(clone, question.Name)
	if len(published) == 0 {
		// Nothing was published for this name, so the whole answer is the synthesized
		// record and the sections that described the answer that is not being sent go
		// with it.
		discardSupersededSections(clone)
	}
	// The record in the message is not the record that was signed, so the message
	// says so: the signature over the HTTPS RRset this router replaced describes
	// parameters that are no longer there, and a client that validated it would be
	// told the ECH key is one it is not.
	StripModifiedDNSSEC(clone)
	if in.Report != nil && len(dropped) > 0 {
		in.Report(Report{Dropped: dropped})
	}
	return clone, nil
}

// keepOrRefuse turns a refusal into the answer the policy asks for. A strict caller
// gets nothing and the refusal. A fallback caller gets its own response back where
// there is something worth forwarding, and the refusal either way: the message is the
// upstream's own answer, which is exactly what the fallback policy says to do when
// this router cannot rewrite, and the error is why no key went into it. A caller that
// discards the error is not unsafe -- the message is the one it would have sent
// without this router in the path -- but it is blind, so the contract is to forward
// the message and log the error.
//
// Where there is nothing to forward, the refusal says so, and ErrNoOriginal carries
// the refusal that led to it, which is why a caller has to test that one first.
func keepOrRefuse(in HTTPSInput, name string, cause error) (*dns.Msg, error) {
	if in.Policy != FallbackToOriginal {
		return nil, cause
	}
	if !forwardable(in.Response, name) {
		return nil, fmt.Errorf("%w, and there is no upstream answer to forward instead: %w", ErrNoOriginal, cause)
	}
	return in.Response, cause
}

// forwardable reports whether the response is something a client can be handed as the
// answer to this question. A record at the queried name is an answer. So is a denial of
// existence: a NOERROR with no records and an SOA, or an NXDOMAIN, states a fact about
// the name that a client caches and acts on, and forwarding it is exactly what the
// client would have got without this router in the path. A failure that carries nothing
// is not an answer, and neither is an empty response with no authority section: there is
// nothing there to hand on, so the caller has to produce the failure itself.
func forwardable(msg *dns.Msg, name string) bool {
	for _, rr := range msg.Answer {
		if sameName(rr.Header().Name, name) {
			return true
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

// aliasRefusal is what an AliasMode record in the RRset at the queried name means for
// this router. RFC 9460 Section 2.4.1 says a client that finds one must ignore the
// ServiceMode records in the same set, because the alias is the whole instruction: the
// service lives at the TargetName and this name has none of its own. Harvesting the
// service mode's parameters and writing them under a TargetName of "." would claim a
// service exists here that the upstream says does not, and would reuse a port and a
// protocol set published for a binding a client is required to ignore.
//
// One clarification about the rule it implements, because the reasoning is easy to
// overstate: the "ignore the service modes" clause is not on its own enough, because
// this synthesis replaces the whole RRset and so leaves no alias behind for a client to
// ignore. What makes it wrong is the first half of it -- the upstream describes a
// service under another name, and a service mode for this name is a claim about a
// service this router cannot see, made with parameters taken from a host it never
// looked at. The delegation is the fault; the client's rule is the symptom. A fallback
// caller is better served by the upstream's own RRset, which sends the client to the
// name the service really has.
func aliasRefusal(name string, found endpoints) error {
	target := ""
	for _, record := range found.published() {
		if record.Priority == 0 {
			target = record.Target
			break
		}
	}
	return fmt.Errorf("%w: the RRset at %q contains an AliasMode record to %q, so the service it describes is the other name's",
		ErrDelegatedName, name, target)
}

// delegated refuses a name the upstream has handed to somebody else, in the shape a CNAME
// takes in an answer. The other shape, an AliasMode record in the RRset there, is
// refused above, because it is a property of the HTTPS records themselves rather than of
// the answer.
//
// The CNAME is checked before anything is synthesized because the two cannot share an
// owner: RFC 1034 Section 3.6.2 forbids an answer carrying a CNAME and other data at
// the same name, and a client is entitled to reject the whole thing. A caller that wants
// the delegation followed is the caller that follows chains -- the address rewrite walks
// to the terminal name and rewrites the address there -- and this function's whole
// output is a service mode for the name it was asked about.
func delegated(msg *dns.Msg, name string) error {
	for _, rr := range msg.Answer {
		record, ok := rr.(*dns.CNAME)
		if !ok || !sameName(record.Hdr.Name, name) {
			continue
		}
		return fmt.Errorf("%w: %q is a CNAME to %q, so the service the client would reach is the other name's", ErrDelegatedName, name, record.Target)
	}
	return nil
}

// httpsQuestion checks that the response is one this function can answer, and
// returns the question it answers. The type is the first door: a caller that wants
// an address rewritten with an HTTPS record has misunderstood which function it
// wants. The name is the second: a synthesis installed under a name the response
// does not answer is an answer to a question nobody asked.
func httpsQuestion(in HTTPSInput) (dns.Question, error) {
	if in.Response == nil {
		return dns.Question{}, errors.New("dnsrewrite: there is no response to rewrite")
	}
	if !in.Response.Response {
		return dns.Question{}, errors.New("dnsrewrite: the message is a query, not a response, and answering it would produce a message that says nothing about being a response")
	}
	if len(in.Response.Question) == 0 {
		return dns.Question{}, errors.New("dnsrewrite: the response carries no question, so there is no name to synthesize for")
	}
	question := in.Response.Question[0]
	if question.Qtype != dns.TypeHTTPS {
		return dns.Question{}, fmt.Errorf("dnsrewrite: the response answers %s but the caller is rewriting an HTTPS query",
			dns.TypeToString[question.Qtype])
	}
	if in.QName == "" {
		return dns.Question{}, errors.New("dnsrewrite: no name was confirmed for this response, so there is nothing this function may synthesize")
	}
	if !sameName(in.QName, question.Name) {
		return dns.Question{}, fmt.Errorf("dnsrewrite: the confirmed name %q is not the name this response answers, which is %q",
			in.QName, question.Name)
	}
	return question, nil
}

// validatedECH turns the bytes the ECH source published into the list this package
// is willing to forward, and refuses the two ways that can fail: nothing at all,
// and something this router cannot vouch for. The bytes installed in the record are
// the bytes that were validated, never the caller's buffer, so an extension this
// router does not interpret still reaches the client that does.
func validatedECH(raw []byte) (*echconfig.List, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: the ECH source published no config", ErrNoECHConfig)
	}
	list, err := echconfig.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidECHConfig, err)
	}
	return list, nil
}

// recordsAt returns the HTTPS records in an answer that belong to one name, in the
// order the answer carried them. A record under any other name is a different
// RRset: it is either part of a CNAME chain the client walks itself, or an
// addition for a target this router is about to replace, and neither is an
// endpoint for the name being asked about.
func recordsAt(msg *dns.Msg, name string) []*dns.HTTPS {
	out := []*dns.HTTPS{}
	for _, rr := range msg.Answer {
		record, ok := rr.(*dns.HTTPS)
		if !ok || !sameName(record.Hdr.Name, name) {
			continue
		}
		out = append(out, record)
	}
	return out
}

// endpoints is the verdict on every record one name published: how many were
// service bindings, which of them can be used here, and why the rest cannot.
type endpoints struct {
	// bindings counts the records that were service modes. It is what separates a
	// name that published something unusable from a name that published nothing,
	// which are different faults: the first is a service the upstream describes and
	// this router cannot offer, the second is nothing to inherit.
	bindings int
	// usable are the records whose parameters may go into the record this router
	// writes, in the order the answer carried them.
	usable []*dns.HTTPS
	// refusals name each unusable service mode, so a refusal says which endpoints
	// were considered and why none of them was offered.
	refusals []string
	// aliases counts the AliasMode records the name published. One is enough to stop
	// the whole synthesis, so they are counted rather than merged: see aliasRefusal.
	aliases int
	// seen is every record the name published, in the order the answer carried them,
	// so a refusal can name what it was looking at.
	seen []*dns.HTTPS
}

// published returns every record the name published, aliases included.
func (e endpoints) published() []*dns.HTTPS {
	return e.seen
}

// classify applies the compatibility rule. A record with a SvcPriority of 0 is an
// alias: it is not a service binding, it is a statement that the service lives at its
// TargetName, and RFC 9460 Section 2.4.1 has a recipient that finds one ignore every
// ServiceMode record in the same RRset. So it is counted, not merged, and one of them
// stops the whole synthesis -- see aliasRefusal. Everything else is a service mode,
// and a service mode is usable only when a client can reach it through the one
// address this router installs.
func classify(published []*dns.HTTPS) endpoints {
	var out endpoints
	out.seen = published
	for _, record := range published {
		if record.Priority == 0 {
			out.aliases++
			continue
		}
		out.bindings++
		reason := unusable(record)
		if reason == "" {
			out.usable = append(out.usable, record)
			continue
		}
		out.refusals = append(out.refusals, fmt.Sprintf("the record at priority %d: %s", record.Priority, reason))
	}
	return out
}

// unusable states why one service mode cannot be used, and returns an empty string
// when it can. The two reasons are the only ones this release has, and both are
// about reachability rather than about the key: an endpoint under an IPv6 address
// names a network this release does not install, and an endpoint whose only address
// is an IPv6 hint names the same network by the only route it offers. An endpoint
// with an IPv4 hint is reachable, and the hint is replaced, so an IPv6 hint beside
// one is simply left out of the record this router writes.
func unusable(record *dns.HTTPS) string {
	if ipv6Target(record.Target) {
		return fmt.Sprintf("its target %q is an IPv6 address", record.Target)
	}
	ipv4, ipv6 := countHints(record)
	if ipv6 > 0 && ipv4 == 0 {
		return "its only address is an IPv6 hint, and this release installs no IPv6 address"
	}
	return ""
}

// ipv6Target names a TargetName that is an IPv6 address, in either of the two forms
// one can arrive in. A zone file spells it as the address, with or without a
// trailing dot. The wire carries the TargetName in the RDATA as an uncompressed
// sequence of length-prefixed labels (RFC 9460 Section 2.2), so an address arrives
// as one label per octet, and the resolver library reads that back as the string
// those sixteen labels spell, each label being the decimal rendering of one octet
// and therefore one to three characters long. A rule that recognized only the first
// form would pass on a fixture and fail on a real response, and a rule that
// rejected every address would refuse an endpoint published under an IPv4 literal,
// which names no network this release cannot serve.
//
// The known overlap: a name of sixteen labels that are all decimal numbers no
// larger than 255 is a legal domain name as well as the wire form of an address,
// and this function cannot tell the two apart. No zone publishes such a name, and
// being wrong about it drops an endpoint rather than installing one, which is the
// safe direction for a rule whose whole purpose is to refuse.
func ipv6Target(target string) bool {
	name := strings.TrimSuffix(target, ".")
	if address := net.ParseIP(name); address != nil {
		return address.To4() == nil
	}
	labels := dns.SplitDomainName(name)
	if len(labels) != net.IPv6len {
		return false
	}
	for _, label := range labels {
		octet, err := strconv.Atoi(label)
		if err != nil || octet < 0 || octet > 255 {
			return false
		}
	}
	return true
}

// countHints reports how many IPv4 and IPv6 addresses a record offers.
func countHints(record *dns.HTTPS) (ipv4, ipv6 int) {
	for _, pair := range record.Value {
		switch pair.Key() {
		case dns.SVCB_IPV4HINT:
			ipv4++
		case dns.SVCB_IPV6HINT:
			ipv6++
		}
	}
	return ipv4, ipv6
}

// synthesized builds the one record the answer will carry. Every refusal about what
// the upstream published has already been made by the caller, so this function only
// builds.
func synthesized(question dns.Question, found endpoints, list *echconfig.List, address netip.Addr) (*dns.HTTPS, []DroppedParameter) {
	record := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr: dns.RR_Header{
			Name:   question.Name,
			Rrtype: dns.TypeHTTPS,
			Class:  question.Qclass,
		},
		// A priority of 0 is an alias, which a client reads as a delegation and
		// never as a service to connect to. This record is the only endpoint in
		// the answer, so 1 is the priority that makes it usable, and the target is
		// the name the client asked about because that is the name the certificate
		// and the ECHConfig's public name are checked against.
		Priority: 1,
		Target:   ".",
	}}
	var dropped []DroppedParameter
	if len(found.usable) > 0 {
		inherited, left := inheritedParameters(found.usable)
		dropped = left
		record.Value = append(record.Value, inherited...)
		record.Hdr.Ttl = shortestTTL(found.usable)
	} else {
		// Nothing to inherit, and a ServiceMode carrying no alpn tells a client
		// that the HTTPS default set of http/1.1 alone is all this service speaks,
		// which is not what a TLS edge serves. The two protocols it does serve are
		// named instead, and nothing else is invented. The TTL stays zero: see
		// shortestTTL.
		record.Value = append(record.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}})
	}

	// The three parameters this router owns. The key is the source's, the hint is
	// the selection, and the mandatory list is what tells a client that a record
	// without the key is not an answer to this question. The order they are
	// appended in is not the order they reach the wire in: the library's packer
	// sorts SvcParamKeys into the increasing order RFC 9460 Section 2.2 requires,
	// and this package does not second-guess it.
	record.Value = append(record.Value,
		&dns.SVCBECHConfig{ECH: list.Raw},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.IP(address.AsSlice())}},
		&dns.SVCBMandatory{Code: mandatoryList(record.Value, found.usable)},
	)
	return record, dropped
}

// inheritedParameters collects what the usable endpoints describe, and reports what
// it left out. There is one rule: a parameter survives only when every retained
// endpoint carries it and every one of them carries the same value.
//
// The value half is the obvious one. Two endpoints naming different ports or
// different protocol sets mean the service is described two ways, and this router
// cannot tell which description is the service's; either value it picked would be
// one it invented, and a wrong port is a connection that cannot be made.
//
// The presence half decides more cases than the value half, and it is the half that
// is easy to get wrong. RFC 9460 Section 7.2 says a client that finds no port uses
// the authority endpoint's port number, and every other key has a default of its
// own. An endpoint that omits a parameter is therefore not silent: it is claiming
// the default, which is a claim about the service just as much as a value is.
// Keeping the value from the endpoint that did name a key turns that second
// endpoint's default into the first endpoint's number, and no client can tell the
// result from a service that really does listen there. So a key that is not in every
// retained endpoint is dropped exactly as a key they describe differently is
// dropped, and every client falls back to the default the endpoints implied.
//
// Dropping a parameter is not a refusal. What is left is still a service mode, still
// carries the key and the selected address, and a client connects to it using the
// default the endpoints agreed on. But it is a degraded answer, so every drop is
// reported with the fault that caused it, and a caller that wants to count or log
// the degradation can.
func inheritedParameters(usable []*dns.HTTPS) ([]dns.SVCBKeyValue, []DroppedParameter) {
	order := make([]dns.SVCBKey, 0, len(usable)*2)
	kept := map[dns.SVCBKey]dns.SVCBKeyValue{}
	claimed := map[dns.SVCBKey]int{}
	differed := map[dns.SVCBKey]bool{}
	for _, record := range usable {
		for _, pair := range record.Value {
			key := pair.Key()
			if ownedByThisRouter(key) {
				continue
			}
			if _, seen := claimed[key]; !seen {
				claimed[key] = 0
				order = append(order, key)
			}
			claimed[key]++
			have, present := kept[key]
			if !present {
				kept[key] = pair
				continue
			}
			// The values are compared as the values the library will pack, not as a
			// rendering of them. A presentation form is lossy for a key whose value
			// is arbitrary bytes, and two different values must never compare equal
			// here. A deep comparison of the pair is exact for every key the library
			// defines, an unknown one included.
			if !differed[key] && !reflect.DeepEqual(have, pair) {
				delete(kept, key)
				differed[key] = true
			}
		}
	}

	carried := make([]dns.SVCBKey, 0, len(order))
	dropped := make([]DroppedParameter, 0, len(order))
	for _, key := range order {
		switch {
		case differed[key]:
			dropped = append(dropped, DroppedParameter{
				Key:    key,
				Reason: fmt.Sprintf("the %d retained endpoints describe it differently, and this router will not pick one endpoint's claim for the whole service", len(usable)),
			})
		case claimed[key] < len(usable):
			dropped = append(dropped, DroppedParameter{
				Key: key,
				Reason: fmt.Sprintf("only %d of the %d retained endpoints carry it, and an endpoint that omits a parameter has claimed the default (RFC 9460 Section 7.2), so no endpoint published a value to keep",
					claimed[key], len(usable)),
			})
		default:
			carried = append(carried, key)
		}
	}

	// RFC 9460 Section 7.1.1: no-default-alpn without alpn is not self-consistent,
	// and a client may reject the whole RRset over it. The default set is what a
	// client falls back to when a record names no alpn, so a record carrying
	// no-default-alpn and no alpn claims the service speaks nothing at all. This is
	// reachable because a disagreement above can remove the alpn.
	if !slices.Contains(carried, dns.SVCB_ALPN) && slices.Contains(carried, dns.SVCB_NO_DEFAULT_ALPN) {
		carried = slices.DeleteFunc(carried, func(key dns.SVCBKey) bool { return key == dns.SVCB_NO_DEFAULT_ALPN })
		dropped = append(dropped, DroppedParameter{
			Key:    dns.SVCB_NO_DEFAULT_ALPN,
			Reason: "the record carries no alpn for it to modify, and RFC 9460 Section 7.1.1 makes the two together one a client may reject the whole RRset over",
		})
	}

	out := make([]dns.SVCBKeyValue, 0, len(carried))
	for _, key := range carried {
		out = append(out, kept[key])
	}
	return out, dropped
}

// mandatoryList is the list this router writes: ech, because the record carries the
// key and a client that ignored it would connect in the clear, plus every key an
// endpoint called mandatory that the record this package built still carries. The
// three filters are all required by RFC 9460 Section 8, and each of them is a way a
// client is entitled to reject the record: a key named twice leaves two fields
// where the format allows one, a key named that is not there leaves a client
// required to understand a parameter that is not in the record, and mandatory
// naming itself is forbidden outright. Deduping happens here, before packing,
// because the library sorts the keys it packs and does not deduplicate them.
//
// The set of keys the record carries cannot be read off `record` alone, and the
// reason is the order the caller builds the record in: it appends the ech parameter
// and the IPv4 hint and THIS list in one statement, so Go evaluates the operands
// first and this function is handed the record as it stood before any of the three
// existed. Filtering on that snapshot alone loses a key the record ends up
// carrying -- an upstream that declared mandatory=ipv4hint has its key dropped even
// though the record answers with the selected address in that parameter -- and the
// degradation is invisible afterwards, because the record is usable and nobody
// reports a missing key on a usable record. So the two parameters this router
// installs on every synthesis are named here as well. ipv6hint is not among them,
// and must not be: no synthesis writes one, so an endpoint that made it mandatory is
// a key the record does not carry, which is the case the filter above exists for.
func mandatoryList(record []dns.SVCBKeyValue, usable []*dns.HTTPS) []dns.SVCBKey {
	present := map[dns.SVCBKey]bool{
		dns.SVCB_ECHCONFIG: true,
		dns.SVCB_IPV4HINT:  true,
	}
	for _, pair := range record {
		present[pair.Key()] = true
	}
	keys := []dns.SVCBKey{dns.SVCB_ECHCONFIG}
	seen := map[dns.SVCBKey]bool{dns.SVCB_ECHCONFIG: true}
	for _, endpoint := range usable {
		for _, pair := range endpoint.Value {
			list, ok := pair.(*dns.SVCBMandatory)
			if !ok {
				continue
			}
			for _, key := range list.Code {
				if key == dns.SVCB_MANDATORY || seen[key] || !present[key] {
					continue
				}
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// shortestTTL is the lifetime of the record set being replaced: the shortest of the
// TTLs the records the synthesis inherited from carried, because that is the
// shortest time the upstream was willing to vouch for what it published. It is zero
// when there was nothing to inherit, which is the honest value for a record this
// router wrote from nothing. A record with no lifetime behind it should not be
// cached as though the upstream had said it was good for any, and a TTL invented here
// would be a claim nobody made.
//
// This is where the package disagrees with Address on purpose, and the disagreement is
// worth stating rather than papering over. Address refuses to replace a record set whose
// TTL is zero, because it has to invent a lifetime for the replacement and a record with
// no lifetime is one it cannot make any claim about. Nothing is invented here: a zero is
// either the shortest of the TTLs the records being replaced carried -- the upstream
// saying it does not want these cached, which the replacement repeats -- or the zero a
// record made from nothing carries because there was no lifetime to inherit. Both are
// somebody else's claim, or the absence of one, and neither is a number this router
// chose. A record the upstream said not to cache is therefore not cached.
func shortestTTL(usable []*dns.HTTPS) uint32 {
	shortest := uint32(0)
	for i, record := range usable {
		if i == 0 || record.Hdr.Ttl < shortest {
			shortest = record.Hdr.Ttl
		}
	}
	return shortest
}

// ownedByThisRouter names the parameters this package decides rather than copies.
// The ech parameter, the IPv4 hint and the IPv6 hint are the key and the address
// this router installed, and mandatory is the list that says so. Inheriting any of
// them would either install an address nobody proved or leave a mandatory list
// naming parameters that are no longer in the record.
func ownedByThisRouter(key dns.SVCBKey) bool {
	switch key {
	case dns.SVCB_ECHCONFIG, dns.SVCB_IPV4HINT, dns.SVCB_IPV6HINT, dns.SVCB_MANDATORY:
		return true
	}
	return false
}

// replaceAt puts one record where the records of one name were in a section, and
// keeps everything else where it was. The synthesized record takes the position of
// the first record it replaces, so a chain in front of it stays in front of it and
// an answer that is not only about this name keeps its order.
func replaceAt(section []dns.RR, name string, record *dns.HTTPS) []dns.RR {
	out := make([]dns.RR, 0, len(section)+1)
	placed := false
	for _, rr := range section {
		if existing, ok := rr.(*dns.HTTPS); ok && sameName(existing.Hdr.Name, name) {
			if !placed {
				out = append(out, record)
				placed = true
			}
			continue
		}
		out = append(out, rr)
	}
	if !placed {
		out = append(out, record)
	}
	return out
}

// bypassable reports whether the upstream's answer is one this router may replace with
// a synthesized record, and refuses the ones that are not.
//
// The distinction is between an absence and a statement. A NODATA, a SERVFAIL and a
// REFUSED with nothing in the answer are absences: the resolver had nothing to say about
// the name, and the ECH source lookup and the selected address do not depend on what it
// would have said, so there is nothing here to be faithful to and no reason to hand a
// force-ECH client nothing. Everything else is a statement. NXDOMAIN says the name does
// not exist, and manufacturing a service binding for a name the authoritative data
// denies is not this router's decision to make. A FORMERR or a NOTIMP says the resolver
// could not do what was asked, and reading a service mode out of that is reading
// something the upstream never said. A failure that carries records is refused as well,
// because a SERVFAIL with an answer in it is not a failure this router can see past and
// the records in it belong to a question nobody answered.
//
// A record the upstream did publish is never in this position: a response that carries
// an HTTPS record for the name is being replaced, not turned into a positive answer out
// of nothing, so the rcode is left as the upstream set it.
func bypassable(msg *dns.Msg) error {
	switch msg.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeServerFailure, dns.RcodeRefused:
		if len(msg.Answer) == 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: the upstream answered %s, and a service mode for this name would be an answer it did not give",
		ErrUpstreamDenial, dns.RcodeToString[msg.Rcode])
}

// intoPositiveAnswer makes the message say what it now is. The rcode goes to NOERROR
// because the record in the answer is this router's, not the upstream's. The AA bit is
// cleared deliberately: the synthesized record is not the zone's data, so leaving the
// authoritative-answer bit set would tell a client the answer came from the
// authoritative server. No client acts on that bit -- RFC 1035 defines it for a
// resolver-to-resolver conversation and this response is resolver-to-stub -- so clearing
// it costs nothing, and the bits that are the client's own, the recursion and
// checking-disabled ones, are left exactly as the upstream echoed them.
//
// The truncated bit goes the same way, and this is the one place where the direction of
// the change was a decision rather than an obviousness. What is in the message is now
// the whole of the answer: one record this router built, replacing whatever the
// upstream published for this name rather than sitting beside it, so a TC=1 answer
// would tell the client to come back over TCP for a message this router has finished
// writing. What a truncated upstream answer leaves unseen is whatever the upstream had
// not sent: an alias at the owner, a second service binding, anything that would have
// made this a refusal. That is the same position a NODATA or an empty SERVFAIL puts
// the synthesis in, which is why bypassable treats those as an absence rather than a
// statement, and it is corroborated elsewhere on this path: the pinned cache refuses
// to store a truncated response either, so nothing downstream of this plugin treats
// one as an answer to keep.
//
// The direction is still fail-closed, because every parameter in the record is one this
// router chose: the key from a source it validated and the address from a selector that
// proved it. A partial view of the upstream cannot become a connection in the clear
// here, and the client is not sent to an address the health check did not prove. The
// cost is the other one, and it is real rather than hidden: a name whose service
// description this router never saw in full is answered with a record describing the
// selected address, which may not be the service the upstream meant to publish.
// Refusing TC=1 was the alternative and was rejected, because it turns a transport
// condition into a strict-mode SERVFAIL over a name whose ECH key and proved address
// are both sitting right there, and buys nothing on either side. A caller that wants
// the other trade is ErrUpstreamDenial, and it decides for itself.
func intoPositiveAnswer(msg *dns.Msg) {
	msg.Rcode = dns.RcodeSuccess
	msg.Authoritative = false
	msg.Truncated = false
}

// discardSupersededSections drops what the message carried for an answer that is no
// longer being sent, once a synthesized record has taken the answer's place. The
// authority section goes because a synthesized positive answer claims no denial of
// existence and no negative caching TTL, and an SOA saying "no records of this type for
// this name" beside a record this router just published is a statement the message
// contradicts. The additional section keeps the client's OPT and nothing else, because
// every other record in it described the answer being replaced.
func discardSupersededSections(msg *dns.Msg) {
	msg.Ns = nil
	kept := make([]dns.RR, 0, 1)
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			kept = append(kept, rr)
		}
	}
	msg.Extra = kept
}

// dropAddressesOf removes the addresses of the name the synthesized record now points
// at, from every section that can carry one. That name is the record's effective
// TargetName, and RFC 9460 Section 7.3 has a client ignore the hints when it already
// holds an A or AAAA answer for it, so an address for it anywhere in the message is an
// answer that beats the selected address and sends the browser to the anycast address
// the health check never proved. The rule is about the name rather than about the
// section: a client that finds the address in the answer section has found it as
// surely as one that finds it beside the answer, and a resolver is free to put it in
// either.
//
// This is why the plugin owns it rather than the caller. The address rewrite, Address,
// owns the terminal A and AAAA records of a CDN name on an A or AAAA query, and it is
// what installs the selected address there; it never sees an HTTPS answer, and it must
// not, because installing an address into an HTTPS answer is a different claim from
// replacing the addresses of a name. So the two functions cover disjoint messages, and
// a caller answers an HTTPS question with this one and an A question with that one.
//
// Addresses of any other name belong to a different RRset and are left alone, as is
// the client's OPT record, which is not an address at all. A section with nothing to
// remove is the section it was handed, so a message that carried no address for this
// name is not given new slices for having asked.
func dropAddressesOf(msg *dns.Msg, name string) {
	msg.Answer = withoutAddressesOf(msg.Answer, name)
	msg.Extra = withoutAddressesOf(msg.Extra, name)
}

// withoutAddressesOf is one section of the rule above: the section it was handed when
// there was nothing to remove, so an untouched message keeps the slices it arrived
// with.
func withoutAddressesOf(section []dns.RR, name string) []dns.RR {
	kept := make([]dns.RR, 0, len(section))
	removed := false
	for _, rr := range section {
		switch record := rr.(type) {
		case *dns.A:
			if sameName(record.Hdr.Name, name) {
				removed = true
				continue
			}
		case *dns.AAAA:
			if sameName(record.Hdr.Name, name) {
				removed = true
				continue
			}
		}
		kept = append(kept, rr)
	}
	if !removed {
		return section
	}
	return kept
}
