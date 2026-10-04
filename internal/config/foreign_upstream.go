package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// UpstreamKind is what a foreign upstream entry routes through.
type UpstreamKind string

const (
	// UpstreamKindDNSCrypt is this package's resolver process, reached on its
	// loopback listener. The entry carries no address: the listener is
	// dnscrypt.ListenAddress(), so the two generated documents cannot disagree.
	UpstreamKindDNSCrypt UpstreamKind = "dnscrypt"
	// UpstreamKindUpstream is an address mosdns dials itself.
	UpstreamKindUpstream UpstreamKind = "upstream"
)

// ForeignUpstream is one entry of the foreign branch's upstream list.
type ForeignUpstream struct {
	Kind UpstreamKind `yaml:"kind"`
	// Name is unique and is what a report, a refusal and the control centre name
	// this entry by. Without it an operator is reading a URL.
	Name string `yaml:"name"`
	// Enabled is a pointer so the zero value of a decoded entry is enabled, and
	// `omitempty` so the shipped policy does not say `enabled: null` on every
	// entry. A pointer that is nil is written as nothing and read back as nil;
	// an operator who wants the entry off writes `enabled: false`, which is a
	// different value and is written out.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Addr is the URL mosdns dials. Required for `upstream`, refused for `dnscrypt`.
	Addr string `yaml:"addr,omitempty"`
	// Bootstrap resolves THIS entry's own host name and is never a query path. The
	// machine's only resolver is the router, so a domain upstream without one
	// cannot be dialled at all.
	//
	// **A list of at most one, and that is forced by mosdns rather than by taste.**
	// The plugin takes a single string (forward.UpstreamConfig.Bootstrap, type
	// string) and hands it to parseBootstrapAp, which splits off the port and calls
	// netip.ParseAddr on the REST -- so "9.9.9.9:53,149.112.112.9:53" is refused as
	// one malformed address (measured: pkg/upstream/utils.go:77-90, and
	// bootstrap.New takes a single netip.AddrPort at :47-60). A comma-joined list
	// was what the design plan assumed and it does not load.
	//
	// So a second resolver has to be a second ENTRY. Which costs an operator
	// nothing here: the bootstrap is not a query path, so a second entry with the
	// same addr and a different bootstrap is one more upstream in the race, and the
	// answer they get is the same either way.
	Bootstrap []string `yaml:"bootstrap,omitempty"`
}

// IsEnabled reports whether the entry routes queries.
func (u ForeignUpstream) IsEnabled() bool { return u.Enabled == nil || *u.Enabled }

// validUpstreamSchemes is every scheme mosdns v5.3.4 accepts, MEASURED at
// pkg/upstream/upstream.go:274-553 with the normalisation at :131-156 (`h3`
// becomes https, `+pipeline` becomes its base). `sdns` is absent because DNSCrypt
// is not a transport mosdns can dial -- which is why this package runs
// dnscrypt-proxy as a separate process.
var validUpstreamSchemes = map[string]bool{
	"udp": true, "tcp": true, "tcp+pipeline": true,
	"tls": true, "tls+pipeline": true,
	"https": true, "h3": true,
	"quic": true, "doq": true,
}

// ValidUpstreamScheme reports whether mosdns v5.3.4 accepts the scheme.
func ValidUpstreamScheme(scheme string) bool { return validUpstreamSchemes[scheme] }

// systemResolverPort is the port a foreign upstream may not be on. It is the
// fallback this project refuses to build, whatever a scheme says about it, and it
// is the same constant the renderer refuses the DNSCrypt listener on.
const systemResolverPort = 53

// ValidateOneUpstream is spec section 3.4 rules 2 through 6 for one entry.
//
// A DISABLED entry is validated exactly like an enabled one, deliberately. An
// operator who turns an entry off and later turns it back on by flipping one word
// should not find a configuration that cannot be rendered, and the alternative --
// validating only what is currently routed -- means the refusal arrives at the
// moment the operator re-enables it, which is the worst moment to arrive.
func ValidateOneUpstream(u ForeignUpstream) error {
	if !validUpstreamName(u.Name) {
		return fmt.Errorf("foreign.upstreams[].name must be non-empty and carry only [a-z0-9-], got %q", u.Name)
	}
	switch u.Kind {
	case UpstreamKindDNSCrypt:
		if u.Addr != "" {
			return fmt.Errorf("foreign.upstreams[] kind dnscrypt must not carry an addr (%q): the listener is the packaged resolver's own address, not a configured one", u.Addr)
		}
		if len(u.Bootstrap) > 0 {
			return fmt.Errorf("foreign.upstreams[] kind dnscrypt must not carry a bootstrap list (%v): it resolves no host name", u.Bootstrap)
		}
		return nil
	case UpstreamKindUpstream:
		if u.Addr == "" {
			return fmt.Errorf("foreign.upstreams[] kind upstream must carry an addr")
		}
	default:
		return fmt.Errorf("foreign.upstreams[].kind must be %q or %q, got %q", UpstreamKindDNSCrypt, UpstreamKindUpstream, u.Kind)
	}
	return validateUpstreamAddr(u)
}

func validateUpstreamAddr(u ForeignUpstream) error {
	// The transport is found the way mosdns finds it, NOT by reading
	// url.Parse's Scheme field. mosdns checks for the literal "://"
	// (pkg/upstream/upstream.go:140-142), and the difference is not academic:
	// url.Parse("dns.quad9.net:853") reports Scheme == "dns.quad9.net", because
	// a colon before the first slash looks like a scheme to Go. So a
	// Scheme == "" test never fires on the exact input an operator types by
	// forgetting the scheme, and that is the one input this rule exists for.
	if !strings.Contains(u.Addr, "://") {
		return fmt.Errorf("foreign.upstreams[] addr %q names no transport, so mosdns would dial it as udp://; "+
			"write the scheme out, and note that udp is the one transport this router refuses for "+
			"anything on the ECH path", u.Addr)
	}
	parsed, err := url.Parse(u.Addr)
	if err != nil {
		return fmt.Errorf("foreign.upstreams[] addr %q is not a URL: %w", u.Addr, err)
	}
	if !ValidUpstreamScheme(parsed.Scheme) {
		return fmt.Errorf("foreign.upstreams[] addr %q has scheme %q, which mosdns v5.3.4 does not accept; "+
			"the accepted schemes are udp, tcp, tcp+pipeline, tls, tls+pipeline, https, h3, quic and doq",
			u.Addr, parsed.Scheme)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("foreign.upstreams[] addr %q must be a plain endpoint, with no credentials or query", u.Addr)
	}
	// A path is REQUIRED for the two HTTP transports and REFUSED for the rest,
	// and the asymmetry is mosdns's, not this package's taste.
	//
	// upstream.go:474 hands `addrURL.String()` -- the WHOLE url -- to
	// doh.NewUpstream as the endpoint, so `https://dns.quad9.net/dns-query` is
	// the configuration and `/dns-query` is load-bearing. Refusing a path there
	// would refuse every real DoH endpoint there is.
	//
	// For the other seven schemes mosdns reads only the host and the port and
	// ignores the path entirely, so a path there is a silent no-op: an operator
	// who wrote `tls://dns.quad9.net:853/oops` would get a working resolver and
	// no indication that a third of what they typed went nowhere.
	if isHTTPTransport(parsed.Scheme) {
		if parsed.Path == "" || parsed.Path == "/" {
			return fmt.Errorf("foreign.upstreams[] addr %q is a DoH endpoint with no path; "+
				"mosdns passes the whole URL through as the endpoint, so it needs its "+
				"/dns-query (upstream.go:474)", u.Addr)
		}
	} else if parsed.Path != "" {
		return fmt.Errorf("foreign.upstreams[] addr %q carries a path, but mosdns reads only the "+
			"host and port of a %s:// upstream and ignores the rest -- so the path would be "+
			"silently discarded rather than dialled", u.Addr, parsed.Scheme)
	}
	if err := refuseLoopbackHost(parsed.Host); err != nil {
		return fmt.Errorf("foreign.upstreams[] addr %q: %w", u.Addr, err)
	}
	if port := parsed.Port(); port != "" && port == "53" {
		return fmt.Errorf("foreign.upstreams[] addr %q is on port %d, which belongs to the system resolver", u.Addr, systemResolverPort)
	}
	// At most ONE bootstrap, for the measured reason on the field: mosdns parses the
	// whole string as a single address. Two would render into a document that the
	// router refuses to load, and the operator would learn it at startup rather than
	// at the moment they wrote the policy.
	if len(u.Bootstrap) > 1 {
		return fmt.Errorf("foreign.upstreams[] bootstrap names %d resolvers (%v) but mosdns reads exactly "+
			"ONE per upstream -- it hands the string to parseBootstrapAp, which parses the whole thing "+
			"as a single address (pkg/upstream/utils.go:77-90). Give each resolver its own entry; the "+
			"bootstrap is not a query path, so a second entry with the same addr answers the same queries "+
			"from the same place", len(u.Bootstrap), u.Bootstrap)
	}
	for _, resolver := range u.Bootstrap {
		address, err := netip.ParseAddrPort(resolver)
		if err != nil {
			return fmt.Errorf("foreign.upstreams[] bootstrap %q must be an IP address and a port: %w", resolver, err)
		}
		if !address.Addr().IsGlobalUnicast() || address.Addr().IsLoopback() {
			return fmt.Errorf("foreign.upstreams[] bootstrap %q is a loopback or non-global address; "+
				"the bootstrap resolves this entry's own host name and has to be somewhere the router is not", resolver)
		}
	}
	return nil
}

// isHTTPTransport reports whether the scheme's endpoint includes a path. Only the
// two DoH schemes do, measured at pkg/upstream/upstream.go:474.
func isHTTPTransport(scheme string) bool { return scheme == "https" || scheme == "h3" }

// refuseLoopbackHost refuses a host that would make this router forward foreign
// queries to itself, or to nothing.
//
// The host is re-parsed as an AddrPort where it can be one, so an unbracketed IPv6
// literal is still recognised. url.Parse cannot help there: `fe80::1:53` has a
// colon before the first slash, so Go reads `fe80` as the SCHEME and the rest as
// an opaque body -- which is exactly why the transport check above tests for the
// literal "://" instead of reading the Scheme field.
func refuseLoopbackHost(host string) error {
	if host == "" {
		return fmt.Errorf("names no host")
	}
	if addressPort, err := netip.ParseAddrPort(host); err == nil {
		return refuseNonGlobalAddress(addressPort.Addr())
	}
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return refuseNonGlobalAddress(address)
	}
	// A bracketed IPv6 literal with something after the bracket, or anything else
	// that is not an address at all: a name is somebody else's problem to resolve,
	// and the bootstrap list is where this router says where.
	return nil
}

func refuseNonGlobalAddress(address netip.Addr) error {
	if address.IsLoopback() || address.IsUnspecified() || address.IsLinkLocalUnicast() {
		return fmt.Errorf("names %s, which is a loopback, unspecified or link-local address; "+
			"a foreign upstream has to be somewhere this router is not", address)
	}
	return nil
}

// validUpstreamName keeps a name to what can appear in a log line and a report
// without quoting: [a-z0-9-], non-empty. It is deliberately narrower than
// validHostname -- a name is an identifier, not a name to be resolved.
func validUpstreamName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for index := 0; index < len(name); index++ {
		c := name[index]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// ErrNoECHSource is rule 7's refusal, and it is a sentinel so the renderer can
// tell "this policy has no way to fetch an ECH key" from "this policy has a
// malformed address". The two need different operator answers.
var ErrNoECHSource = errors.New(
	"foreign.upstreams must leave at least one ENABLED entry the ECH key can be fetched through: " +
		"either a dnscrypt entry, or an upstream whose addr is tcp://. " +
		"cdn_rewrite refuses every other transport for the ECH fetch on a measured ground " +
		"(mosdns's UDP upstream re-sends an unanswered query and can drop an early answer, and an " +
		"ECH fetch has no client watching it), so a policy that leaves no tcp:// route would let " +
		"every forced-ECH name fail closed once the key's grace ended, with nothing in the log saying why")

// ValidateForeignUpstreams is spec section 3.4 rules 1, 2, 3 and 7 for the whole
// list, after ValidateOneUpstream has run over every entry.
func ValidateForeignUpstreams(upstreams []ForeignUpstream) error {
	if len(upstreams) == 0 {
		// **The refusal states the SHAPE, not just the absence.** `policy.yaml` is
		// a dpkg conffile, so an operator who customised it keeps their copy across
		// an upgrade -- and the first message this produced for such a file was
		// "foreign.upstreams must name at least one upstream", which names a key
		// the operator has never heard of and says nothing about what to write.
		// A refusal an operator cannot act on is a refusal that sends them to the
		// source.
		return fmt.Errorf("foreign.upstreams must name at least one upstream. If this policy was " +
			"written before the foreign route became configurable, it has no `foreign.upstreams` key " +
			"at all: add the two lines the shipped policy carries, which route through the packaged " +
			"DNSCrypt resolver and one DoQ endpoint. See mosdns-cdnctl(1) under \"The foreign route\"")
	}
	enabled := 0
	dnscrypt := 0
	seen := map[string]bool{}
	for _, u := range upstreams {
		if err := ValidateOneUpstream(u); err != nil {
			return err
		}
		if seen[u.Name] {
			return fmt.Errorf("foreign.upstreams[].name must be unique, and %q appears twice: "+
				"a name is what a report and a refusal identify an entry by", u.Name)
		}
		seen[u.Name] = true
		if u.IsEnabled() {
			enabled++
		}
		if u.Kind == UpstreamKindDNSCrypt {
			dnscrypt++
		}
	}
	if enabled == 0 {
		return fmt.Errorf("foreign.upstreams must leave at least one enabled entry; all %d are disabled, "+
			"which leaves the foreign branch with nowhere to send a query", len(upstreams))
	}
	if dnscrypt > 1 {
		return fmt.Errorf("foreign.upstreams may name at most one dnscrypt entry, and %d do: "+
			"there is one packaged resolver and it listens on one address", dnscrypt)
	}
	// The question rule 7 asks is "is there an ENABLED entry the ECH key can be
	// fetched through", which is a property of the LIST and not of any address the
	// caller happens to hold. So it asks the list directly rather than asking
	// ECHSource for a string: ECHSource("" listener) legitimately returns "" for a
	// dnscrypt-only route, because with no listener in hand there is no string to
	// hand back, and treating that empty string as "no ECH source" refused every
	// route whose ECH source is the packaged resolver. That is the default route.
	if !hasECHSource(upstreams) {
		return ErrNoECHSource
	}
	return nil
}

// hasECHSource is rule 7 as a question about the LIST: does any enabled entry
// serve the ECH fetch? It is separate from ECHSource because ECHSource answers a
// different question -- "what string do I put in the document" -- and that one
// needs an address this package does not have.
func hasECHSource(upstreams []ForeignUpstream) bool {
	for _, u := range upstreams {
		if !u.IsEnabled() {
			continue
		}
		if u.Kind == UpstreamKindDNSCrypt {
			return true
		}
		if u.Kind == UpstreamKindUpstream && strings.HasPrefix(u.Addr, "tcp://") {
			return true
		}
	}
	return false
}

// ECHSource returns the upstream the ECH key may be fetched through, or "" when
// no enabled entry can serve one.
//
// **The dnscrypt entry wins over a tcp:// upstream even when both are enabled**,
// and that order is the design rather than an accident: the packaged resolver is
// already started, already probed by the installer, and already the road an ECH
// failure has to be diagnosable against. A tcp:// upstream is the fallback for a
// machine that turned the dnscrypt entry off.
//
// Rule 7 makes "" unreachable for a validated policy, so "" means "this list was
// never validated" -- which is why the dnscrypt listener is passed as "" by
// ValidateForeignUpstreams and a real URL by the renderer.
func ECHSource(upstreams []ForeignUpstream, dnscryptListener string) string {
	for _, u := range upstreams {
		// The listener being empty is NOT a reason to skip this entry. An earlier
		// version required `dnscryptListener != ""` here to "prove" the entry had
		// something to point at, and that made rule 7 permanently unsatisfiable for
		// the DEFAULT policy: ValidateForeignUpstreams calls this with "" (it has no
		// listener to pass), so the dnscrypt entry could never be chosen, and every
		// list containing one was refused with ErrNoECHSource. Whether the dnscrypt
		// entry can serve the fetch does not depend on the CALLER having the address
		// in hand.
		if u.IsEnabled() && u.Kind == UpstreamKindDNSCrypt {
			return dnscryptListener
		}
	}
	for _, u := range upstreams {
		if u.IsEnabled() && u.Kind == UpstreamKindUpstream && strings.HasPrefix(u.Addr, "tcp://") {
			return u.Addr
		}
	}
	return ""
}
