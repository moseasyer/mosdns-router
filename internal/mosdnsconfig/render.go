// Package mosdnsconfig renders the MOSDNS v5.3.4 configuration that splits
// queries into a domestic and a foreign branch.
//
// Two branches and no third. A name the pinned China list matches is forwarded to
// the DNS servers the DHCP client is currently configured with, and every other
// name is forwarded to the loopback DNSCrypt resolver over TCP. There is no
// fallback between them in either direction: a foreign query that cannot be
// answered fails, and is never re-asked inside the network the user is leaving.
//
// The rendered document is a pure function of a policy and a set of paths, so
// the same inputs always produce the same bytes, and the committed
// configs/mosdns.yaml is compared against a fresh render rather than trusted on
// sight. The paths are refused rather than rendered when they cannot be served:
// a generated file that a service can only half honour is worse than a refusal
// at generation time, because the failure it causes appears on someone's
// resolver rather than in the build.
package mosdnsconfig

import (
	"bytes"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	"mosdns-router/internal/config"

	// The document names plugin types, so this package links the plugins it
	// names: importing it registers them, and a consumer that loads a rendered
	// configuration does not have to know which of them to import. The router's
	// own plugin is not in that bundle, so it is linked here as well.
	_ "github.com/IrineSistiana/mosdns/v5/plugin"

	dhcpforward "mosdns-router/plugin/executable/dhcp_forward"
)

// The tags the rendered document uses. The two servers and the three sequences
// are the entry points the rest of the document refers to by name, so they are
// spelled once here and nowhere else.
const (
	tagCNDomains      = "cn_domains"
	tagDHCPForward    = "dhcp_forward"
	tagForeignCache   = "foreign_cache"
	tagForeignForward = "foreign_forward"
	tagCNPath         = "cn_path"
	tagForeignPath    = "foreign_path"
	tagMain           = "main"
	tagUDPServer      = "udp_server"
	tagTCPServer      = "tcp_server"
)

// The bounds and addresses this document renders rather than inherits. They are
// written out instead of left to the plugins' defaults so that the committed
// file states them: a file that says nothing is a file that changes meaning when
// an upstream release changes a default.
const (
	// dhcpCacheEntries bounds one DHCP generation's cache. The cache is
	// generation-scoped, so an entry can never be served by the next DHCP DNS
	// set, and its size cannot be a stale-answer risk -- only a hit rate.
	dhcpCacheEntries = 4096

	// dhcpUpstreamPort is the port a published DHCP DNS address is dialled on. A
	// published state carries bare addresses, so the port is a property of this
	// configuration rather than of the state.
	dhcpUpstreamPort = 53

	// foreignCacheEntries bounds the foreign cache. The bound is the cache
	// plugin's own documented default, stated here so the file does not follow a
	// default that an upstream release can change; it is not a measurement, and
	// nothing in this project has measured one yet.
	foreignCacheEntries = 1024

	// logLevel is the level the reports an operator reads are written at: the
	// plugin logs every generation it adopts at info, and the reports that a
	// branch has stopped answering are warnings above it. It is rendered rather
	// than left to the logger's zero value, which happens to be info today.
	logLevel = "info"
)

// foreignListenerScheme is the transport the foreign branch enters the DNSCrypt
// resolver with. MOSDNS v5.3.4's stock UDP upstream re-sends a query that has
// gone unanswered for a second and can drop an answer that arrived before its
// exchange started waiting for it; the foreign branch has no client of its own
// to own that exchange, so it is given the transport that cannot lose a query.
const foreignListenerScheme = "tcp"

// systemResolverPort is the port a foreign upstream must never be given. A
// resolver listening there is the system resolver this router exists to keep out
// of foreign queries, so forwarding to it would be the fallback this project
// refuses to build.
const systemResolverPort = 53

// readOnlyConfigurationRoot is where a root-owned configuration directory lives.
// The China list and the state document are mutable, so they may not be rendered
// into it: a rule file the package cannot replace without rewriting the
// configuration, and a state document the bridge publishes into a directory the
// service user may not write.
const readOnlyConfigurationRoot = "/etc"

// chinesePublicDNSAddresses must never appear in a generated configuration. The
// foreign branch exists so a query can be answered somewhere that is not the
// network the user is leaving, and these are the resolvers of exactly that
// network. This is a scan of the finished document, not a substitute for the
// routing tests: a data flow that reached one of these addresses would be caught
// by a test that follows the queries, and this scan is the last line against one
// that arrives through a path, a comment or a default nobody thought about.
var chinesePublicDNSAddresses = []string{
	"223.5.5.5",       // AliDNS
	"223.6.6.6",       // AliDNS
	"119.29.29.29",    // DNSPod
	"114.114.114.114", // 114DNS
	"180.76.76.76",    // Baidu DNS
}

// Paths are the fixed system paths a rendered configuration reads and writes.
// Nothing here is discovered at runtime: the router is started by a unit that
// names them, and a path that is derived from a working directory or an
// environment is a path a different invocation resolves differently.
type Paths struct {
	// Policy is the policy file the document is generated from. It is named in
	// the generated header so an operator can tell which policy produced it.
	Policy string
	// CNDomains is the pinned China rule list the domestic dispatch matches
	// against. It is rewritten by the list updater, so it is not under /etc.
	CNDomains string
	// DHCPState is the state document the DHCP bridge publishes, with the DNS
	// servers the client is currently configured with. It is rewritten on every
	// renewal, so it is not under /etc.
	DHCPState string
	// ForeignListener is the DNSCrypt resolver's address as a tcp://host:port
	// URL. It is the only foreign upstream this document may name.
	ForeignListener string
	// Listen is the address both servers bind, as host:port. The production value
	// is the loopback the system's own stub resolver points at.
	Listen string
}

// ProductionPaths returns the paths an installed router uses. They are the spec's
// file layout: read-only configuration under /etc, the rule list the updater
// rewrites under /var/lib, and the DHCP bridge's published state on the tmpfs
// under /run.
func ProductionPaths() Paths {
	return Paths{
		Policy:          "/etc/mosdns/policy.yaml",
		CNDomains:       "/var/lib/mosdns/lists/cn-domains.txt",
		DHCPState:       "/run/mosdns/dhcp-upstreams.json",
		ForeignListener: "tcp://127.0.0.1:15353",
		Listen:          "127.0.0.1:53",
	}
}

// --- the document, as typed values ---

// document is a MOSDNS v5 configuration. Every field carries the yaml key the
// pinned mosdns release reads it under, and Args is filled with the argument
// types of the plugins themselves, so the document is assembled from typed values
// and marshalled once, never concatenated out of strings.
type document struct {
	Log     logArgs      `yaml:"log"`
	Plugins []pluginArgs `yaml:"plugins"`
}

type logArgs struct {
	Level string `yaml:"level"`
}

type pluginArgs struct {
	Tag  string `yaml:"tag"`
	Type string `yaml:"type"`
	Args any    `yaml:"args"`
}

// rule is one step of a sequence: the conditions under which it runs, and what
// it runs. A step with no conditions is unconditional, and the key is left out
// rather than written empty.
type rule struct {
	Matches []string `yaml:"matches,omitempty"`
	Exec    string   `yaml:"exec"`
}

// The plugins' argument sets, restricted to the keys this document writes.
// A plugin refuses arguments it does not recognise, so an unrecognised key here
// fails the load rather than being ignored, and a missing key fails the same
// way: nothing in a generated document is left to a default that is not stated
// somewhere in the file.
type (
	// domainSetArgs is the domain_set data provider: the rule list.
	domainSetArgs struct {
		Files []string `yaml:"files"`
	}
	// dhcpForwardArgs is the router's own DHCP forwarder.
	dhcpForwardArgs struct {
		StateFile     string `yaml:"state_file"`
		CacheEntries  int    `yaml:"cache_entries"`
		UpstreamPort  int    `yaml:"upstream_port"`
		FailurePolicy string `yaml:"failure_policy"`
	}
	// cacheArgs is the foreign cache. No dump file: a dump would write the
	// user's query names to disk.
	cacheArgs struct {
		Size int `yaml:"size"`
	}
	// forwardArgs is the foreign forward, into the DNSCrypt resolver.
	forwardArgs struct {
		Upstreams []upstreamArgs `yaml:"upstreams"`
	}
	upstreamArgs struct {
		Addr string `yaml:"addr"`
	}
	// serverArgs is a listener, over either transport.
	serverArgs struct {
		Entry  string `yaml:"entry"`
		Listen string `yaml:"listen"`
	}
)

// --- rendering ---

// Render writes the MOSDNS configuration for a policy and a set of paths. The
// output is a pure function of its arguments, so the committed file can be
// compared against a fresh render instead of being trusted on sight.
//
// Every path is checked before anything is written, and the finished document is
// scanned once more, because the cost of a configuration that renders a wrong
// path or a wrong upstream is a resolver that answers from somewhere nobody
// chose.
func Render(policy config.Policy, paths Paths) ([]byte, error) {
	resolved, err := resolve(paths)
	if err != nil {
		return nil, err
	}
	if policy.Cache.PersistentDump {
		// A persistent cache needs a dump file, and no path for one is part of
		// this document. Rendering the cache without one would honour the
		// policy's intent as a cache that is thrown away on every restart, so
		// the policy is refused until there is somewhere to put the dump.
		return nil, fmt.Errorf("mosdnsconfig: cache.persistent_dump needs a dump path, which this document does not carry")
	}

	encoded, err := marshal(renderable(policy, resolved))
	if err != nil {
		return nil, fmt.Errorf("mosdnsconfig: encode the mosdns configuration: %w", err)
	}
	document := append([]byte(header(resolved.Policy)), encoded...)
	if err := scanForChinesePublicDNS(document); err != nil {
		return nil, err
	}
	return document, nil
}

// renderable builds the document as typed values. The plugin order is load
// order: mosdns builds each sequence while it loads it, so a sequence that
// refers to a tag has to come after the plugin that answers to it.
func renderable(policy config.Policy, paths resolvedPaths) document {
	return document{
		Log: logArgs{Level: logLevel},
		Plugins: []pluginArgs{
			{
				Tag:  tagCNDomains,
				Type: "domain_set",
				Args: domainSetArgs{Files: []string{paths.CNDomains}},
			},
			{
				Tag:  tagDHCPForward,
				Type: dhcpforward.PluginType,
				Args: dhcpForwardArgs{
					StateFile:     paths.DHCPState,
					CacheEntries:  dhcpCacheEntries,
					UpstreamPort:  dhcpUpstreamPort,
					FailurePolicy: policy.DHCP.FailurePolicy,
				},
			},
			{
				Tag:  tagForeignCache,
				Type: "cache",
				Args: cacheArgs{Size: foreignCacheEntries},
			},
			{
				Tag:  tagForeignForward,
				Type: "forward",
				Args: forwardArgs{Upstreams: []upstreamArgs{{Addr: paths.ForeignListener}}},
			},
			{
				// The domestic branch. The forwarder is the only executable: a
				// China name can only be answered by the DHCP-configured
				// resolvers, and a forwarder that fails ends the branch instead
				// of falling through to the foreign one.
				Tag:  tagCNPath,
				Type: "sequence",
				Args: []rule{
					{Exec: "$" + tagDHCPForward},
					{Exec: "accept"},
				},
			},
			{
				// The foreign branch. The cache is a recursive executable: it
				// always runs the rules after it, so the has_resp check is what
				// keeps a cache hit from being forwarded as well.
				Tag:  tagForeignPath,
				Type: "sequence",
				Args: []rule{
					{Exec: "$" + tagForeignCache},
					{Matches: []string{"has_resp"}, Exec: "accept"},
					{Exec: "$" + tagForeignForward},
					{Exec: "accept"},
				},
			},
			{
				// The dispatch. The China list is checked first and the foreign
				// path is the unconditional default, so no name is unrouted.
				Tag:  tagMain,
				Type: "sequence",
				Args: []rule{
					{Matches: []string{"qname $" + tagCNDomains}, Exec: "$" + tagCNPath},
					{Exec: "$" + tagForeignPath},
				},
			},
			{
				Tag:  tagUDPServer,
				Type: "udp_server",
				Args: serverArgs{Entry: tagMain, Listen: paths.Listen},
			},
			{
				Tag:  tagTCPServer,
				Type: "tcp_server",
				Args: serverArgs{Entry: tagMain, Listen: paths.Listen},
			},
		},
	}
}

// marshal encodes the document. The indent is set so the file reads like the
// examples in the pinned mosdns documentation: this file is read by operators
// when something answers wrongly, and a sequence indented four spaces deeper
// than its key is harder to scan than one indented under it.
func marshal(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// header explains where the document came from, so the file an operator reads is
// not mistaken for the one they should edit.
func header(policyPath string) string {
	return fmt.Sprintf(`# mosdns-router routing configuration for MOSDNS v5.3.4.
#
# Generated by internal/mosdnsconfig.Render from the policy at %s.
# Edit the policy or the paths, not this file: configs/mosdns.yaml is the
# committed output of Render(config.Defaults(), ProductionPaths()) and a test
# compares the two byte for byte, so a hand edit here is an edit the project
# stops being able to explain.
#
# Two branches and no third. A name the pinned China list matches goes to the
# DNS servers DHCP published, and every other name goes to the loopback DNSCrypt
# resolver over TCP. There is no fallback between them: a foreign query that
# cannot be answered fails, and is never re-asked inside the network the user is
# leaving.
`, policyPath)
}

// --- paths ---

// resolvedPaths is a Paths that has passed every check. The document is built
// from it and from nothing else, so no unchecked value can reach an argument.
type resolvedPaths struct {
	Policy          string
	CNDomains       string
	DHCPState       string
	ForeignListener string
	Listen          string
}

// resolve checks the paths and returns them in the form the document will carry.
// A path is cleaned first, so a path that only looks outside /etc cannot be
// rendered into it, and every refusal names the value that caused it.
func resolve(paths Paths) (resolvedPaths, error) {
	resolved := resolvedPaths{}

	for _, field := range []struct {
		name  string
		value string
	}{
		{"policy path", paths.Policy},
		{"China list path", paths.CNDomains},
		{"state document path", paths.DHCPState},
		{"foreign listener", paths.ForeignListener},
		{"listen address", paths.Listen},
	} {
		if strings.TrimSpace(field.value) == "" {
			return resolvedPaths{}, fmt.Errorf("mosdnsconfig: the %s must not be empty", field.name)
		}
	}
	resolved.Policy = cleanPath(paths.Policy)
	resolved.CNDomains = cleanPath(paths.CNDomains)
	resolved.DHCPState = cleanPath(paths.DHCPState)
	resolved.Listen = strings.TrimSpace(paths.Listen)

	// A path that is resolved against a working directory is a path that means
	// something different under systemd, under a shell and under a test.
	for _, field := range []struct {
		name  string
		value string
	}{
		{"policy path", resolved.Policy},
		{"China list path", resolved.CNDomains},
		{"state document path", resolved.DHCPState},
	} {
		if !strings.HasPrefix(field.value, "/") {
			return resolvedPaths{}, fmt.Errorf("mosdnsconfig: the %s %q must be absolute", field.name, field.value)
		}
	}
	// The China list and the state document are both rewritten while the router
	// runs. A file under /etc is replaced by packaging, and /etc/mosdns is
	// root-owned configuration: a rule list published there would be lost on the
	// next upgrade, and a state document the service user cannot write would stop
	// the domestic branch at the first DHCP renewal.
	for _, field := range []struct {
		name  string
		value string
	}{
		{"China list path", resolved.CNDomains},
		{"state document path", resolved.DHCPState},
	} {
		if under(field.value, readOnlyConfigurationRoot) {
			return resolvedPaths{}, fmt.Errorf(
				"mosdnsconfig: the %s %q is under %s, which is read-only configuration; a file rewritten while the router runs belongs under /var/lib or /run",
				field.name, field.value, readOnlyConfigurationRoot,
			)
		}
	}

	if err := checkListen(resolved.Listen); err != nil {
		return resolvedPaths{}, err
	}
	listener, err := checkForeignListener(strings.TrimSpace(paths.ForeignListener))
	if err != nil {
		return resolvedPaths{}, err
	}
	resolved.ForeignListener = listener
	return resolved, nil
}

// cleanPath is filepath.Clean for a path that has already been checked for
// emptiness, and it is what the document carries so that a path written with a
// redundant element cannot change the document's bytes.
func cleanPath(value string) string {
	return filepath.Clean(strings.TrimSpace(value))
}

// under reports whether a cleaned absolute path is a directory or something
// inside it. It compares path elements, so /etcetera is not /etc.
func under(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

// checkListen refuses a listen address that is not an address and a port. Both
// servers bind it, so a value that is only half an address is a router that
// cannot answer on the transport a client happened to use.
func checkListen(value string) error {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return fmt.Errorf("mosdnsconfig: the listen address %q must be an IP address and a port: %w", value, err)
	}
	if address.Port() == 0 {
		return fmt.Errorf("mosdnsconfig: the listen address %q names no port, so nothing would answer on a known one", value)
	}
	return nil
}

// checkForeignListener refuses anything that is not the DNSCrypt resolver's own
// tcp://host:port URL, and refuses port 53 in particular: a foreign upstream on
// the system resolver's port is the fallback this project refuses to build,
// whatever a path or a scheme says about it.
func checkForeignListener(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("mosdnsconfig: the foreign listener %q is not a URL: %w", value, err)
	}
	if parsed.Scheme != foreignListenerScheme {
		return "", fmt.Errorf("mosdnsconfig: the foreign listener %q must be a %s:// URL, want the DNSCrypt resolver entered over TCP", value, foreignListenerScheme)
	}
	// Anything after the host would be sent to the resolver as part of the URL
	// mosdns dials, which is not what a listener address is.
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("mosdnsconfig: the foreign listener %q must be a bare tcp://host:port URL, with no credentials, path or query", value)
	}
	address, err := netip.ParseAddrPort(parsed.Host)
	if err != nil {
		return "", fmt.Errorf("mosdnsconfig: the foreign listener %q must name an IP address and a port: %w", value, err)
	}
	if address.Port() == systemResolverPort {
		return "", fmt.Errorf("mosdnsconfig: the foreign listener %q is on port %d, which belongs to the system resolver", value, systemResolverPort)
	}
	if address.Port() == 0 {
		return "", fmt.Errorf("mosdnsconfig: the foreign listener %q names no port", value)
	}
	// The address is rebuilt from the parsed parts, so a listener that carried
	// anything a URL would have to escape cannot reach the document.
	return (&url.URL{Scheme: foreignListenerScheme, Host: address.String()}).String(), nil
}

// scanForChinesePublicDNS is the last line of defence over the finished
// document. It cannot tell how a resolver would be reached, so it is not a
// substitute for the routing tests; what it does catch is a name that arrived
// through a path, a comment or a default, where a test that follows queries
// would not look.
func scanForChinesePublicDNS(document []byte) error {
	for _, address := range chinesePublicDNSAddresses {
		if strings.Contains(string(document), address) {
			return fmt.Errorf("mosdnsconfig: the rendered document names %s, a resolver inside the network the foreign branch exists to leave", address)
		}
	}
	return nil
}
