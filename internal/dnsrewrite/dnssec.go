package dnsrewrite

import (
	"github.com/miekg/dns"
)

// StripModifiedDNSSEC makes a modified response honest about what it is.
//
// A response this router has changed can no longer carry the DNSSEC records that
// came with it, and the rule is all-or-nothing rather than selective. An RRSIG
// over the records that were replaced is a signature this router cannot produce
// and did not verify; an NSEC or NSEC3 is a statement that a validator may act on,
// and a statement about the RRset that was there before the rewrite now sits in a
// message that no longer contains that RRset. Leaving a denial of existence
// beside a rewritten answer is worse than leaving a signature beside it, because a
// validator is entitled to read the denial and conclude the answer is forged. So
// every RRSIG and every NSEC and NSEC3 leaves the message, wherever it was, and
// the AD bit is cleared so a client is told the answer is unsigned rather than
// being left to work it out.
//
// Three things are deliberately not touched. The OPT record stays, including the
// client's DO bit, because it is the request's own description of what the client
// asked for and this router does not answer a different question than the one it
// was sent. The CD bit stays exactly as the client set it, because whether a
// client validates for itself is the client's decision, and echoing it back
// differently would be this router making that decision for it. And an NSEC3PARAM
// is left alone: it is the parameter of an NSEC3 chain rather than a proof about
// this answer, and the ruling this implements names the three record types above.
//
// The message is modified in place, so it is called on a copy. The rule that an
// unmodified response keeps every record it arrived with is therefore a rule about
// the caller, not about this function: it runs only after a rewrite has happened.
func StripModifiedDNSSEC(msg *dns.Msg) {
	if msg == nil {
		return
	}
	msg.AuthenticatedData = false
	msg.Answer = withoutProofs(msg.Answer)
	msg.Ns = withoutProofs(msg.Ns)
	msg.Extra = withoutProofs(msg.Extra)
}

// withoutProofs returns one section with the three proof types removed, and the
// section it was handed when there was nothing to remove. An empty section is
// returned as the empty section it arrived as, so a response whose authority
// section was absent is not given one.
func withoutProofs(section []dns.RR) []dns.RR {
	kept := make([]dns.RR, 0, len(section))
	removed := false
	for _, rr := range section {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			removed = true
		default:
			kept = append(kept, rr)
		}
	}
	if !removed {
		return section
	}
	return kept
}
