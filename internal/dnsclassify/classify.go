// Package dnsclassify decides whether a DNS response is served by Cloudflare,
// conservatively enough that a wrong answer cannot send a browser to a CDN the
// operator never chose.
//
// The decision rests on one fact and one argument. The fact is that this release
// selects Cloudflare IPv4 globally: an address inside a published range can serve
// any name, so a response whose every terminal address is inside one may be
// rewritten to a preferred address. The argument is the prefix list, and it is
// always an argument. This package holds no ranges of its own, so a caller that
// supplies a different list gets a different verdict, and a caller that supplies
// no list gets no rewrite at all.
//
// "Terminal" is the point a CNAME chain ends at, and "every" is what makes the
// classification safe. A response that names a Cloudflare address and a foreign
// one is a mixed-CDN response, and the only safe thing to do with it is not
// rewrite it: replacing the whole set with one Cloudflare address would send
// every client to a network the response never named. So one foreign address, a
// chain that loops, a chain this package cannot follow, and a response with no
// address at the end of its chain are all refusals, and a refusal never has a
// Provider beside it that invites a rewrite.
//
// The walk is bounded by construction rather than by a hop limit. It keys the
// names it has already been on by their canonical form, so the first repeat of a
// name is the end of the walk, and the walk cannot run longer than the answer
// section is long. A name aliased to itself, a two-name cycle and a sixty-four
// name cycle all end at that same check, which is why the suite can assert
// termination in a second instead of waiting for the package timeout.
package dnsclassify

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"mosdns-router/internal/candidate"
)

// Refusal names the one reason a response is not a Cloudflare response this
// package will let a caller rewrite. It is a value rather than a bare false so a
// plugin can log why it left an answer alone, and it is an error as well so a
// caller that has to fail closed on it can.
type Refusal string

// The reasons. Each is a state of the response or of the caller's argument, not a
// style of failure, and none of them is recoverable by a second attempt: a
// different prefix list or a different answer is what changes the verdict.
const (
	// RefusalNone is the zero Refusal: the walk finished, at least one terminal
	// address exists, and every one of them is inside a published range.
	RefusalNone Refusal = ""
	// RefusalNoResponse is a message that was never there. A plugin that gets
	// nothing back from the sequence is not holding a response to classify.
	RefusalNoResponse Refusal = "no_response"
	// RefusalNoQuestion is a message with no question to walk from, or with more
	// than one, in which case which chain the answer belongs to is ambiguous.
	RefusalNoQuestion Refusal = "no_question"
	// RefusalNoPrefixes is a caller with no published ranges to check against.
	// Nothing can be verified from no argument, so nothing is rewritten.
	RefusalNoPrefixes Refusal = "no_published_prefixes"
	// RefusalCNAMELoop is a chain that comes back to a name it has already been
	// on, including a name aliased to itself. There is no end to such a chain.
	RefusalCNAMELoop Refusal = "cname_loop"
	// RefusalAmbiguousChain is a name with more than one CNAME. Which target a
	// client follows is a guess, and a guess about the chain is a guess about
	// whose address this is.
	RefusalAmbiguousChain Refusal = "ambiguous_cname_chain"
	// RefusalAddressInChain is a name in the chain that carries an address of its
	// own. RFC 1034 Section 3.6.2 says a CNAME is the only record at its name, so
	// a response that breaks the rule offers a client two ways to answer and this
	// package will not choose between them.
	RefusalAddressInChain Refusal = "address_in_cname_chain"
	// RefusalNoAddress is a chain that ends at a name with no IPv4 address at it.
	// A name answered only over IPv6 cannot be checked against IPv4 ranges, and a
	// name with no records at all is not a CDN this router can rewrite for.
	RefusalNoAddress Refusal = "no_terminal_address"
	// RefusalMixed is a response naming both a published address and a foreign
	// one. This is the mixed-CDN case, and it is the reason this package exists
	// in its current form: one Cloudflare address in a set of several is not
	// permission to replace the set.
	RefusalMixed Refusal = "mixed_cdn"
	// RefusalForeignAddress is a response whose terminal addresses are all outside
	// every published range. It belongs to some other network and stays as it is.
	RefusalForeignAddress Refusal = "foreign_address"
)

// Error lets a Refusal travel as the error of a function that has to refuse, so a
// caller can match a refusal with errors.Is instead of comparing text.
func (r Refusal) Error() string { return string(r) }

// Result is one classification, and it is a verdict plus the reason for it
// rather than a set of booleans a caller has to interpret in the right order.
//
// The two fields that authorize a rewrite -- Provider and TerminalName -- are set
// only on a result that authorizes one. A refusal returns both empty, so a caller
// that forwards a Result without reading it forwards nothing: there is no field
// left in it that the rewriter would accept. A refusal that still named the
// network and the owner would be indistinguishable from a success except by
// reading a boolean, and the mistake would be invisible at the call site.
type Result struct {
	// Provider is candidate.ProviderCloudflare when every terminal address is
	// inside a published range, and empty on every refusal.
	Provider candidate.Provider
	// TerminalName is the canonical owner of the terminal address records, and is
	// what a rewrite has to replace. It is empty on every refusal, and a result
	// that authorizes a rewrite never has it empty: such a result always says
	// which RRset to replace.
	TerminalName string
	// AllMatch is true when every terminal address is inside a published range
	// and there is at least one of them. It is the only field that authorises a
	// global Cloudflare rewrite.
	AllMatch bool
	// Mixed is true when at least one terminal address is inside a published
	// range and at least one is not. It names a response that serves more than
	// one network. It is reported, and it is not a partial success: the refusal
	// carrying it is a whole refusal.
	Mixed bool
	// Refusal is the reason this response is not rewriteable, and RefusalNone
	// when it is.
	Refusal Refusal
}

// Cloudflare classifies one response against the caller's published IPv4 ranges.
// Every refusal is reported in Result.Refusal with AllMatch false and with
// Provider and TerminalName empty, so a caller that forwards the fields which
// authorize a rewrite cannot be led into one by a refusal.
func Cloudflare(msg *dns.Msg, prefixes []netip.Prefix) Result {
	owners, refusal := Chain(msg)
	if refusal != RefusalNone {
		return Result{Refusal: refusal}
	}
	if len(prefixes) == 0 {
		return Result{Refusal: RefusalNoPrefixes}
	}

	terminal := owners[len(owners)-1]
	addresses := terminalAddresses(msg, terminal)
	if len(addresses) == 0 {
		return Result{Refusal: RefusalNoAddress}
	}

	published, total := 0, 0
	for _, address := range addresses {
		total++
		if insideAny(address, prefixes) {
			published++
		}
	}
	switch {
	case published == total:
		return Result{
			Provider:     candidate.ProviderCloudflare,
			TerminalName: terminal,
			AllMatch:     true,
		}
	case published > 0:
		return Result{Mixed: true, Refusal: RefusalMixed}
	default:
		return Result{Refusal: RefusalForeignAddress}
	}
}

// Chain walks the CNAME chain in a response's answer section and reports the
// canonical owner of every name on it, starting at the question name and ending
// at the name that owns no CNAME. The names are canonical because that is the
// only form a comparison against another name can be made in: DNS names are case
// insensitive and the trailing dot is optional in every place a name is written.
//
// It is exported because the rewriter needs the same walk, and because a second
// walk written for the rewriter would be a second chance to get the bound wrong.
// The bound is here: the walk refuses the first name it is asked to visit twice,
// so it visits each name at most once and cannot run longer than the answer
// section it reads.
func Chain(msg *dns.Msg) ([]string, Refusal) {
	if msg == nil {
		return nil, RefusalNoResponse
	}
	if len(msg.Question) != 1 {
		return nil, RefusalNoQuestion
	}

	aliases := make(map[string][]string)
	hasAddress := make(map[string]bool)
	for _, rr := range msg.Answer {
		owner := CanonicalName(rr.Header().Name)
		switch record := rr.(type) {
		case *dns.CNAME:
			aliases[owner] = append(aliases[owner], CanonicalName(record.Target))
		case *dns.A:
			hasAddress[owner] = true
		}
	}

	current := CanonicalName(msg.Question[0].Name)
	owners := []string{current}
	visited := map[string]bool{current: true}
	for {
		targets := aliases[current]
		switch {
		case len(targets) == 0:
			return owners, RefusalNone
		case len(targets) > 1:
			return nil, RefusalAmbiguousChain
		}

		// The loop test comes before the per-name test below because a name
		// aliased to itself arrives here on its very first step, and a report
		// that blamed the record set instead would send an operator looking at
		// the wrong thing. Termination does not depend on where the test sits:
		// every step that does not return marks a name this walk has not been
		// on, and there are only as many names as the answer section holds, so
		// the walk cannot run longer than that section is long.
		next := targets[0]
		if visited[next] {
			return nil, RefusalCNAMELoop
		}
		if hasAddress[current] {
			return nil, RefusalAddressInChain
		}

		visited[next] = true
		owners = append(owners, next)
		current = next
	}
}

// terminalAddresses returns every IPv4 address in the answer section that the
// chain ended at. A record whose address cannot be read as an address is left in
// the list as an address that is in no published range, so a malformed record
// counts against a rewrite rather than being skipped.
func terminalAddresses(msg *dns.Msg, terminal string) []netip.Addr {
	out := []netip.Addr{}
	for _, rr := range msg.Answer {
		record, ok := rr.(*dns.A)
		if !ok || CanonicalName(record.Hdr.Name) != terminal {
			continue
		}
		address, ok := netip.AddrFromSlice(record.A)
		if !ok {
			out = append(out, netip.Addr{})
			continue
		}
		out = append(out, address.Unmap())
	}
	return out
}

// insideAny reports whether one address falls inside any of the caller's ranges.
// It is netip.Prefix.Contains and nothing else, so a caller that publishes IPv4
// ranges gets IPv4 comparisons and a caller that publishes anything else gets no
// match rather than a wrong one: an invalid prefix, an IPv6 prefix and a
// IPv4-mapped IPv6 prefix all leave the address unclassified.
func insideAny(address netip.Addr, prefixes []netip.Prefix) bool {
	if !address.IsValid() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// CanonicalName is the form every name this package compares is folded into:
// lowercase, because DNS names are case insensitive and a client may send any
// case, and fully qualified, because the trailing dot is optional wherever a name
// is written and absent wherever one is compared.
//
// It is exported because the rewriter compares a name against the names this
// package reports, and a second folding of a name is a second rule about when two
// names are the same.
func CanonicalName(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}
