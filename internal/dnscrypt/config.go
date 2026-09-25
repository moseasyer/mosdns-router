// Package dnscrypt renders the foreign resolver's dnscrypt-proxy 2.1.18
// configuration.
//
// The rendered file is the whole trust boundary for a foreign query: it decides
// which addresses the resolver talks to and which key it will believe. Every
// resolver is therefore pinned as a complete DNS stamp, so the provider public
// key travels with the address it belongs to and an on-path substitution of a
// bare resolver IP cannot authenticate itself. The switches the document
// enables and the properties the stamps must carry are checked against each
// other here, because dnscrypt-proxy silently registers fewer resolvers than
// the file names rather than refusing to start.
package dnscrypt

import (
	"fmt"
	"net/netip"
	"strings"

	dnsstamps "github.com/jedisct1/go-dnsstamps"
	"mosdns-router/internal/config"
)

// The foreign forward enters the resolver here. It is loopback so the resolver
// is not reachable from off-host, and not port 53 so it can never be mistaken
// for the system resolver this router is meant to keep out of foreign queries.
const (
	listenAddress = "127.0.0.1:15353"
	netprobeHost  = "9.9.9.9:443"
)

// bootstrapResolvers resolve DNSCrypt provider names, and nothing else. They are
// Quad9's own anycast addresses, so the bootstrap path cannot become a second,
// differently-trusted route for a user's query either.
var bootstrapResolvers = []string{"9.9.9.9:53", "149.112.112.9:53"}

// Stamp is one named DNSCrypt resolver. The name is the key dnscrypt-proxy
// matches `server_names` against, so it has to be unique in a document.
type Stamp struct {
	Name  string
	Value string
}

// Defaults returns Quad9's published Secure DNSCrypt v2 IPv4 endpoints: two
// anycast addresses plus one more, all three authenticating the same provider
// certificate key.
//
// The third stamp is Quad9's published `dnscrypt-ip4-filter-alt2` value, taken
// from https://quad9.net/dnscrypt/quad9-resolvers.md and byte-for-byte identical
// to what that list serves as of 2026-09-26, as are the first two. Nothing here
// is a locally doctored stamp, and a diff against upstream should come back empty.
//
// An earlier copy of that list, and the plan text derived from it, carried a
// corrupt string instead. Both declare the same 25-byte provider name, but the
// stale one fills those 25 bytes with `2.dnscrypt.dnscrypt-cert.` rather than
// `2.dnscrypt-cert.quad9.net` and then appends nine leftover bytes (`quad9.net`).
// So the stale string differs in 15 contiguous bytes at offsets 74-88 and is nine
// bytes longer, while its protocol byte, property word, every length byte, its
// address `149.112.112.112:8443` and its 32-byte provider public key are
// byte-for-byte identical to the published stamp's and to the other two
// defaults'. The pinned decoder reads the declared name, finds the leftovers, and
// refuses the stale stamp with "garbage after end"; dnscrypt-proxy 2.1.18 then
// exits 255 with "Stamp error for the static [quad9-dnscrypt-ip4-filter-3]
// definition", checked against a real 2.1.18 build. That stale string is kept
// only as a test fixture, because a stamp that does not decode is a mistake this
// renderer has to refuse.
func Defaults() []Stamp {
	return []Stamp{
		{
			Name:  "quad9-dnscrypt-ip4-filter-1",
			Value: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
		},
		{
			Name:  "quad9-dnscrypt-ip4-filter-2",
			Value: "sdns://AQMAAAAAAAAAEjE0OS4xMTIuMTEyLjk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
		},
		{
			Name:  "quad9-dnscrypt-ip4-filter-3",
			Value: "sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ",
		},
	}
}

// Render writes the dnscrypt-proxy 2.1.18 configuration for the given policy and
// stamps. The output is a pure function of its arguments, so the same inputs
// always produce the same bytes and the committed file can be compared against
// the renderer instead of being trusted on sight.
//
// Only the supplied stamps are rendered. Defaults are never merged into a custom
// list, because a custom list is how an operator replaces Quad9 with a provider
// this project knows nothing about; quietly keeping the defaults would route
// foreign queries back through the provider that was just replaced.
func Render(policy config.Policy, stamps []Stamp) ([]byte, error) {
	if policy.Foreign.ECS {
		// ECS hands the resolver the client's subnet, and no stamp in this
		// project can forward it, so a document claiming ECS would advertise a
		// privacy property the transport does not have.
		return nil, fmt.Errorf("foreign.ecs requires an ECS-capable DNSCrypt stamp set, which this renderer does not carry")
	}
	if len(stamps) == 0 {
		return nil, fmt.Errorf("no DNSCrypt stamps supplied")
	}

	names := make([]string, 0, len(stamps))
	seen := make(map[string]struct{}, len(stamps))
	for _, stamp := range stamps {
		if stamp.Name == "" {
			return nil, fmt.Errorf("a DNSCrypt stamp has an empty name")
		}
		if _, duplicate := seen[stamp.Name]; duplicate {
			return nil, fmt.Errorf("DNSCrypt stamp name %q is used more than once", stamp.Name)
		}
		seen[stamp.Name] = struct{}{}
		if err := validateStamp(stamp); err != nil {
			return nil, fmt.Errorf("DNSCrypt stamp %q: %w", stamp.Name, err)
		}
		names = append(names, stamp.Name)
	}

	document := new(strings.Builder)
	writePreamble(document, policy)
	writeSwitches(document, names)
	document.WriteString("\n# The stamps below are complete: each one carries the 32-byte Ed25519\n# provider public key the resolver's certificate is signed with, so the address\n# and the key it must prove cannot be separated. Nothing in this file is a bare\n# resolver IP, because an unauthenticated address is exactly what an on-path\n# party substitutes.\n")
	for _, stamp := range stamps {
		fmt.Fprintf(document, "\n[static.%s]\n  stamp = '%s'\n", stamp.Name, stamp.Value)
	}
	return []byte(document.String()), nil
}

// validateStamp refuses any stamp the rendered document would not actually use.
//
// The checks are not a restatement of the policy: each one corresponds to a
// switch Render writes. dnscrypt-proxy drops a registered server whose protocol
// is disabled or whose address family is off, and refuses a stamp it cannot
// decode at all, so a stamp that parses but violates one of these would leave a
// file that names a resolver the proxy silently does not have.
func validateStamp(stamp Stamp) error {
	if !strings.HasPrefix(stamp.Value, dnsstamps.StampScheme) {
		return fmt.Errorf("value must start with %q, not %q", dnsstamps.StampScheme, stamp.Value)
	}
	decoded, err := dnsstamps.NewServerStampFromString(stamp.Value)
	if err != nil {
		return fmt.Errorf("stamp does not decode: %w", err)
	}
	if decoded.Proto != dnsstamps.StampProtoTypeDNSCrypt {
		return fmt.Errorf("protocol is %s, but this document enables dnscrypt_servers only", decoded.Proto.String())
	}
	endpoint, err := netip.ParseAddrPort(decoded.ServerAddrStr)
	if err != nil {
		return fmt.Errorf("server address %q is not an IP:port: %w", decoded.ServerAddrStr, err)
	}
	if !endpoint.Addr().Is4() {
		return fmt.Errorf("server address %q is IPv6, but this document enables ipv4_servers only", decoded.ServerAddrStr)
	}
	if len(decoded.ServerPk) != 32 {
		return fmt.Errorf("provider public key is %d bytes, want the 32 bytes an Ed25519 certificate is signed with", len(decoded.ServerPk))
	}
	// No provider-name check is needed. The pinned decoder refuses a DNSCrypt
	// stamp shorter than 66 bytes, and the longest IPv4 host:port is 21 bytes, so
	// 9 header + 1 address length + 21 address + 1 key length + 32 key bytes + 1
	// name length is 65. A stamp that decodes with an accepted address and a
	// 32-byte key therefore has at least one byte of provider name, which is the
	// name bootstrap_resolvers has to look up.
	if decoded.Props&dnsstamps.ServerInformalPropertyDNSSEC == 0 {
		return fmt.Errorf("stamp does not advertise DNSSEC, but this document sets require_dnssec")
	}
	if decoded.Props&dnsstamps.ServerInformalPropertyNoLog == 0 {
		return fmt.Errorf("stamp does not advertise NoLog, but this document sets require_nolog")
	}
	return nil
}

func writePreamble(document *strings.Builder, policy config.Policy) {
	fmt.Fprintf(document, `# mosdns-router foreign resolver configuration for dnscrypt-proxy 2.1.18.
#
# Generated by internal/dnscrypt.Render. Edit the policy or the stamps, not this
# file: configs/dnscrypt-proxy.toml is the committed output of
# Render(config.Defaults(), Defaults()) and a test compares the two byte for
# byte, so a hand edit here is an edit the project stops being able to explain.
#
# The default foreign provider is %q. Every resolver below
# is a complete authenticated DNSCrypt stamp over IPv4, with no ECS endpoint: the
# client's subnet is never handed to a resolver, and the filtering the policy is
# named for is not traded away for speed.
`, policy.Foreign.DefaultProvider)
}

func writeSwitches(document *strings.Builder, names []string) {
	fmt.Fprintf(document, `
# The only listener is loopback, and never port 53, so this resolver is neither
# reachable from off-host nor mistakable for the system resolver. dnscrypt-proxy
# registers a UDP and a TCP listener for every listen address, and the foreign
# forward uses TCP, so nothing below narrows the listener to one transport.
listen_addresses = ['%s']
server_names = ['%s']

# dnscrypt-proxy consults the host resolver list to bootstrap DNSCrypt provider
# names. That list is a DHCP address this router does not control, so it is
# ignored: a foreign query must never be answered by the network the user is
# leaving. The resolvers below only ever resolve DNSCrypt provider names, and
# they never receive ordinary user queries.
ignore_system_dns = true
bootstrap_resolvers = ['%s']

# A reachability probe of Quad9 over TCP 443, so a captive portal or a
# blackholed network is reported before the router claims to resolve anything.
# It is pinned rather than defaulted to the first bootstrap resolver, which
# would probe plain DNS on port 53 where a portal happily answers.
netprobe_address = '%s'

# No cache and no query log here. The foreign cache belongs to MOSDNS, which is
# the only component that knows when an answer has been superseded; a second
# cache inside the resolver would answer from a copy nothing can invalidate, and
# a query log would write the user's names to disk.
cache = false

# Only DNSCrypt over IPv4. DoH and ODoH are off, so no stamp may name one of
# those endpoints: dnscrypt-proxy would drop such a stamp and keep serving with
# fewer resolvers than this file lists, without saying so.
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = false
odoh_servers = false

# The stamps must advertise DNSSEC and no-log, so a resolver that cannot promise
# either is refused rather than used. NoFilter is deliberately not required: the
# endpoints above are Quad9's filtered ones, and requiring the property would
# leave this document with no resolver at all.
require_dnssec = true
require_nolog = true
require_nofilter = false
`,
		listenAddress,
		strings.Join(names, "', '"),
		strings.Join(bootstrapResolvers, "', '"),
		netprobeHost,
	)
}
