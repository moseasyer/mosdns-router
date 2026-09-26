// Package dnsrewrite changes the addresses a DNS response hands to a client, and
// the DNSSEC records that stop being true once it has.
//
// Three rules govern everything here, and each of them exists because the wrong
// answer is worse than no answer.
//
// The first is that a rewrite is a claim about whose network a client should
// reach, so it happens only for a response the caller has already classified and
// only at the exact owner the classification ended at. This package is not the
// classifier: it takes the name dnsclassify walked to, checks that the response
// in front of it really does end there, and refuses anything else. A caller that
// passes a name the response does not carry, a provider this release does not
// select, or a question type it does not own gets an error rather than a rewritten
// message, because a rewrite nobody asked for is a redirect nobody authorised.
//
// The second is that the response the caller holds is never modified. The caller
// is a plugin standing in front of a cache that owns the object, so a rewrite
// applied in place is a rewrite the next reader inherits, and the next reader is
// a different client asking about a different name. Every change is made on a
// copy, and a call with nothing to change hands the caller's own message back
// unchanged, so a caller has one path for "not rewritten" and one for "rewritten".
//
// The third is the DNSSEC rule in StripModifiedDNSSEC, and it is all-or-nothing:
// a response this router changed carries no signature and no denial of existence
// at all, and no longer claims to be validated.
//
// The A record that replaces a set of A records carries the minimum TTL of the
// records it replaced. That is the honest value: it is the shortest time the
// upstream was willing to vouch for those addresses, and a rewritten address is
// no fresher than the answer it came from. A TTL of zero is refused rather than
// defaulted, because a record with no lifetime is a record this router cannot make
// any claim about.
package dnsrewrite

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/dnsclassify"
)

// AddressInput is one authorized rewrite: the response, the question it answers,
// the group the address belongs to, the name the classification ended at, the
// address to install, and the caller's AAAA switch.
type AddressInput struct {
	// Response is the upstream response. It is never modified: a rewrite is
	// applied to a copy and the copy is what Address returns.
	Response *dns.Msg
	// QType is the question type the caller is rewriting for, and it must be the
	// type the response actually answers. A caller that holds one question and
	// claims another is misreading a cache or an upstream, and neither is a place
	// to install an address.
	QType uint16
	// Provider is the group the selected address belongs to. Only the two groups
	// this release selects are accepted; anything else is a configuration or a
	// wiring mistake, and both are refused rather than guessed at.
	Provider candidate.Provider
	// TerminalName is the exact owner of the address records to replace, as
	// dnsclassify reported it. It is required, and it is checked against the
	// response's own chain: this function replaces records at the name the
	// classification ended at, not at a name the caller would like to have been
	// the answer to.
	TerminalName string
	// Hostname is the exact CloudFront hostname the address was proved for. It
	// applies to candidate.ProviderCloudFront only, where a mapping is valid for
	// one distribution and for nothing else: no suffix, no parent, no sibling, no
	// name below it. A Cloudflare rewrite is global and decided by the published
	// ranges, so a hostname left in a shared configuration is ignored there.
	Hostname string
	// Selected is the address to install. It must be a routable public IPv4
	// address, and an IPv6 selection is refused with an error rather than
	// ignored: a caller that silently got nothing back would go on believing a
	// rewrite had happened, which is the state a strict-mode caller must never
	// be in.
	Selected netip.Addr
	// Prefixes is the caller's published Cloudflare ranges, the same argument the
	// classification was made with. A Cloudflare rewrite installs an address into
	// a client's answer, so it checks the response against these ranges here as
	// well as trusting the caller's verdict: one foreign address, an empty prefix
	// set, a chain that will not follow and a response with no address are all
	// refusals here too, so a wiring mistake that names the Cloudflare group for a
	// response that is not one stops at this door. The same ranges keep a
	// CloudFront mapping off a response that is Cloudflare-served, because the two
	// paths claim disjoint sets of responses and a label that crosses between them
	// is a mistake worth refusing rather than serving. A CloudFront rewrite has no
	// range list of its own -- no published set of CloudFront ranges exists, and a
	// distribution is proved for one hostname by a probe rather than by a range --
	// so on that path the exact hostname is the authorisation and these ranges are
	// only the thing that says the answer is somebody else's.
	Prefixes []netip.Prefix
	// SuppressAAAA removes the AAAA records of the question name and of every
	// name on its CNAME chain, and nothing else. A record belonging to a name
	// this question never reaches is left alone however it got into the message.
	SuppressAAAA bool
}

// Address rewrites the addresses in a response, or refuses to.
//
// It returns the caller's own message when there is nothing to change, a copy
// carrying the rewrite when there is, and a nil message with an error when the
// call cannot be confirmed. An error is never returned beside a rewritten
// message, and a rewritten message is never returned without one having been
// possible to check first.
func Address(in AddressInput) (*dns.Msg, error) {
	owners, terminal, err := authorize(in)
	if err != nil {
		return nil, err
	}
	switch in.QType {
	case dns.TypeA:
		return replaceAddresses(in, owners, terminal)
	case dns.TypeAAAA:
		return suppressAAAA(in, owners)
	default:
		return nil, fmt.Errorf("dnsrewrite: this function does not rewrite %s answers", dns.TypeToString[in.QType])
	}
}

// authorize checks everything that has to hold before a message may be changed,
// and returns the names the response's own chain reached. Every check in it is
// about the call being one this function is willing to act on: a response it can
// walk, a question it asked for, a terminal name the response really ends at, a
// provider it selects, and for CloudFront a mapping that covers the name being
// asked about and nothing else.
func authorize(in AddressInput) ([]string, string, error) {
	if in.Response == nil {
		return nil, "", errors.New("dnsrewrite: there is no response to rewrite")
	}
	switch in.Provider {
	case candidate.ProviderCloudflare, candidate.ProviderCloudFront:
	default:
		return nil, "", fmt.Errorf("dnsrewrite: %q is not a provider this release rewrites for", in.Provider)
	}
	if err := checkSelected(in.Selected); err != nil {
		return nil, "", err
	}

	owners, refusal := dnsclassify.Chain(in.Response)
	if refusal != dnsclassify.RefusalNone {
		return nil, "", fmt.Errorf("dnsrewrite: the response's CNAME chain cannot be followed: %w", refusal)
	}
	terminal := owners[len(owners)-1]
	question := in.Response.Question[0]
	if question.Qtype != in.QType {
		return nil, "", fmt.Errorf("dnsrewrite: the response answers %s but the caller is rewriting a %s query",
			dns.TypeToString[question.Qtype], dns.TypeToString[in.QType])
	}
	if in.TerminalName == "" {
		return nil, "", errors.New("dnsrewrite: no terminal name was confirmed for this response, so there is nothing this function may replace")
	}
	if !sameName(in.TerminalName, terminal) {
		return nil, "", fmt.Errorf("dnsrewrite: the confirmed terminal name %q is not the name this response's chain ends at, which is %q",
			in.TerminalName, terminal)
	}
	if in.Provider == candidate.ProviderCloudFront {
		if in.Hostname == "" {
			return nil, "", errors.New("dnsrewrite: a CloudFront rewrite needs the exact hostname the address was proved for")
		}
		if !sameName(in.Hostname, question.Name) {
			return nil, "", fmt.Errorf("dnsrewrite: the CloudFront mapping for %q does not cover the queried name %q",
				in.Hostname, question.Name)
		}
		// The cross-check that the exact hostname cannot provide. A mapping is
		// authorised by a hostname and nothing else, because no published range
		// list says which networks serve a distribution, so without this a
		// response that is Cloudflare-served by the caller's own ranges could be
		// rewritten into a CloudFront address by a caller that mislabelled it --
		// the wrong CDN for the name, from a name the mapping genuinely covers.
		// A distribution answer is in no published range, so this does not fire on
		// the path it is meant to allow.
		if verdict := dnsclassify.Cloudflare(in.Response, in.Prefixes); verdict.AllMatch {
			return nil, "", errors.New("dnsrewrite: the response is served by Cloudflare according to the caller's own published ranges, so no per-hostname CloudFront mapping may claim it")
		}
	}
	// The published ranges gate the one path that installs an address, and they
	// gate it here rather than only in the caller's verdict: the whole cost of
	// getting that wrong is a browser sent to a network the response never named.
	if in.Provider == candidate.ProviderCloudflare && in.QType == dns.TypeA {
		if verdict := dnsclassify.Cloudflare(in.Response, in.Prefixes); !verdict.AllMatch {
			return nil, "", fmt.Errorf("dnsrewrite: the response is not a Cloudflare response by the caller's own published ranges: %s", verdict.Refusal)
		}
	}
	return owners, terminal, nil
}

// replaceAddresses puts one selected address where the response's terminal
// addresses were, and leaves the chain and every other record alone.
func replaceAddresses(in AddressInput, owners []string, terminal string) (*dns.Msg, error) {
	replaced := terminalAddresses(in.Response, terminal)
	if len(replaced) == 0 {
		return nil, fmt.Errorf("dnsrewrite: the confirmed terminal name %q carries no address to replace", terminal)
	}

	// The TTL is the minimum over the records being replaced, and the owner name
	// is the one the answer used, so a rewritten record set is the record set
	// that was there with a different address in it.
	ttl := replaced[0].Hdr.Ttl
	for _, record := range replaced {
		if record.Hdr.Ttl < ttl {
			ttl = record.Hdr.Ttl
		}
		if record.A.To4() == nil {
			return nil, fmt.Errorf("dnsrewrite: the record %q carries no IPv4 address to replace", record.Hdr.Name)
		}
	}
	if ttl == 0 {
		return nil, fmt.Errorf("dnsrewrite: the records at %q carry no TTL, so there is no lifetime to give the replacement", terminal)
	}

	header := replaced[0].Hdr
	header.Ttl = ttl

	clone := in.Response.Copy()
	kept := make([]dns.RR, 0, len(clone.Answer)+1)
	var suppressed map[string]bool
	if in.SuppressAAAA {
		suppressed = chainOwners(owners)
	}
	for _, rr := range clone.Answer {
		switch record := rr.(type) {
		case *dns.A:
			if sameName(record.Hdr.Name, terminal) {
				continue
			}
		case *dns.AAAA:
			if suppressed[dnsclassify.CanonicalName(record.Hdr.Name)] {
				continue
			}
		}
		kept = append(kept, rr)
	}
	clone.Answer = append(kept, &dns.A{Hdr: header, A: net.IP(in.Selected.AsSlice())})
	StripModifiedDNSSEC(clone)
	return clone, nil
}

// suppressAAAA empties the answer to a question about IPv6 for the names the
// question reached. It installs nothing: an answer to an AAAA question gains no
// A record, because the client asked about IPv6 and a record it did not ask for
// is not a way to answer that.
func suppressAAAA(in AddressInput, owners []string) (*dns.Msg, error) {
	if !in.SuppressAAAA {
		return in.Response, nil
	}
	suppressed := chainOwners(owners)

	found := false
	for _, rr := range in.Response.Answer {
		if record, ok := rr.(*dns.AAAA); ok && suppressed[dnsclassify.CanonicalName(record.Hdr.Name)] {
			found = true
			break
		}
	}
	if !found {
		return in.Response, nil
	}

	clone := in.Response.Copy()
	kept := make([]dns.RR, 0, len(clone.Answer))
	for _, rr := range clone.Answer {
		if record, ok := rr.(*dns.AAAA); ok && suppressed[dnsclassify.CanonicalName(record.Hdr.Name)] {
			continue
		}
		kept = append(kept, rr)
	}
	clone.Answer = kept
	StripModifiedDNSSEC(clone)
	return clone, nil
}

// terminalAddresses returns the answer's A records at the name the CNAME chain
// ended at, in the order the answer carried them.
func terminalAddresses(msg *dns.Msg, terminal string) []*dns.A {
	out := []*dns.A{}
	for _, rr := range msg.Answer {
		record, ok := rr.(*dns.A)
		if ok && sameName(record.Hdr.Name, terminal) {
			out = append(out, record)
		}
	}
	return out
}

// chainOwners is the set of names a rewrite owns: the question name and every
// name its CNAME chain reached. A record outside this set belongs to somebody
// else, however it came to be in the same message.
func chainOwners(owners []string) map[string]bool {
	set := make(map[string]bool, len(owners))
	for _, owner := range owners {
		set[owner] = true
	}
	return set
}

// checkSelected refuses an address that must never become a client's answer. The
// selection is read from a file on disk, and a file can hold anything an operator
// or a broken writer put in it, so the value is checked here as well as where it
// was published: a loopback, LAN, shared-space or IPv6 address installed as a CDN
// answer points a browser at this router or at a network it cannot reach.
//
// This check is a cheap second opinion, not the authority. state is: every value
// that reaches this function was published as a public IPv4 address by
// state.validPublicIPv4Address, which holds the full 14-range list and refuses
// all of them. This one is deliberately narrower, and a narrower allow list is a
// weaker check, so what it adds is a cheap second opinion on the mistakes an
// operator actually makes by hand -- a loopback address, a LAN address, a
// carrier-grade NAT address, an IPv6 address, an address that is not an address
// at all.
//
// The known narrowing: it does not cover 0.0.0.0/8 beyond 0.0.0.0 itself,
// 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24
// and 240.0.0.0/4, so an address in one of those would be installed if it ever
// reached here. It cannot, because state refuses to publish it, and the gap is
// recorded rather than closed here so that one list owns the rule. The
// documentation ranges being in the gap is also why the tests in this package
// select 203.0.113.9: a fixture address that no test can reach, and one this
// check accepts on purpose.
func checkSelected(address netip.Addr) error {
	switch {
	case !address.IsValid():
		return errors.New("dnsrewrite: the selected address is not an address at all")
	case !address.Is4():
		return fmt.Errorf("dnsrewrite: the selected address %s is not IPv4, and this release rewrites IPv4 answers only", address)
	case !address.IsGlobalUnicast() || address.IsPrivate():
		return fmt.Errorf("dnsrewrite: the selected address %s is not a routable public IPv4 address", address)
	case sharedAddressSpace.Contains(address):
		return fmt.Errorf("dnsrewrite: the selected address %s is in the shared address space of RFC 6598, which is not a CDN", address)
	}
	return nil
}

// sharedAddressSpace is 100.64.0.0/10, the carrier-grade NAT range. It is global
// unicast as far as netip is concerned and it is not private, so the two
// predicates above both accept it.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// sameName compares two DNS names the way a resolver does: case insensitively,
// and with or without the trailing dot. It is the form dnsclassify reports, so
// this is a comparison against that form and not a second way of folding a name.
func sameName(a, b string) bool {
	return dnsclassify.CanonicalName(a) == dnsclassify.CanonicalName(b)
}
