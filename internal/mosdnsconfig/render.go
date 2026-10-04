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
	"mosdns-router/internal/dnscrypt"

	// The document names plugin types, so this package links the plugins it
	// names: importing it registers them, and a consumer that loads a rendered
	// configuration does not have to know which of them to import. The router's
	// own plugin is not in that bundle, so it is linked here as well.
	_ "github.com/IrineSistiana/mosdns/v5/plugin"

	cdnrewrite "mosdns-router/plugin/executable/cdn_rewrite"
	dhcpforward "mosdns-router/plugin/executable/dhcp_forward"
	ttlclamp "mosdns-router/plugin/executable/ttl_clamp"
)

// The tags the rendered document uses. The two servers and the three sequences
// are the entry points the rest of the document refers to by name, so they are
// spelled once here and nowhere else.
const (
	tagCNDomains      = "cn_domains"
	tagDHCPForward    = "dhcp_forward"
	tagCDNRewrite     = "cdn_rewrite"
	tagForeignCache   = "foreign_cache"
	tagForeignForward = "foreign_forward"
	tagForeignTTL     = "foreign_ttl"
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

// The bounds of the port a published DHCP DNS address is dialled on. A
// published state carries bare addresses, so the port is a property of this
// document; the default is the port a DHCP DNS server answers on.
const (
	defaultDHCPUpstreamPort = 53
	maximumDHCPUpstreamPort = 65535
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
	// the generated header so an operator can tell which policy produced it, and
	// the response rewriter reads it as well: the switches an operator edits --
	// IPv6 suppression, whether ECH is forced at all, what happens when the key
	// cannot be fetched -- are read from this one file, so there is no second
	// place to set them.
	Policy string
	// Selector is the published selection: which address is in service, the window
	// its proof is good for, and the per-hostname CloudFront mappings. The
	// optimizer and the health check write it, so it is rewritten while the router
	// runs and is not under /etc.
	Selector string
	// ForceECH is the operator's list of the domains to force ECH for. It is
	// written by hand and replaced by packaging, so it belongs in the
	// read-only configuration directory: nothing rewrites it while the router
	// runs, and an operator has to find it.
	ForceECH string
	// ECHState is the document the response rewriter publishes about the key it
	// fetched: the source, the times, the digest and the public name, and never a
	// byte of the key itself. The router writes it, so it is not under /etc.
	ECHState string
	// CNDomains is the pinned China rule list the domestic dispatch matches
	// against. It is rewritten by the list updater, so it is not under /etc.
	CNDomains string
	// CloudflarePrefixes is the PUBLISHED Cloudflare range list, one prefix per
	// line, that the same cached fetch writes beside the API's own document. It is
	// the only argument the response classifier has, so it is the one path in this
	// document whose absence stops the router rather than silencing a feature.
	CloudflarePrefixes string
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
	// DHCPUpstreamPort is the port a published DHCP DNS address is dialled on.
	// A published state carries bare addresses, so the port is a property of this
	// configuration rather than of the state. Zero means the port a DHCP DNS
	// server answers on, 53.
	DHCPUpstreamPort int
}

// ProductionPaths returns the paths an installed router uses. They are the spec's
// file layout: read-only configuration under /etc, the rule list the updater
// rewrites under /var/lib, and the DHCP bridge's published state on the tmpfs
// under /run.
// The clamp's plugin type is referenced here as well as where it is rendered, so
// that a change to the rendered name is a change the compiler can see rather than
// one that leaves an import behind. It is the kind of line that looks redundant and
// is not: a mutation script that changes the one rendered use would otherwise fail
// to build, and a build failure reads as "no failures" to any check that counts
// test failures.
var _ = ttlclamp.PluginType

func ProductionPaths() Paths {
	return Paths{
		Policy:             "/etc/mosdns/policy.yaml",
		Selector:           "/var/lib/mosdns/runtime/cdn-selector.json",
		ForceECH:           "/etc/mosdns/force-ech-domains.txt",
		ECHState:           "/var/lib/mosdns/runtime/ech-state.json",
		CNDomains:          "/var/lib/mosdns/lists/cn-domains.txt",
		CloudflarePrefixes: "/var/lib/mosdns/lists/cloudflare-prefixes.txt",
		DHCPState:          "/run/mosdns/dhcp-upstreams.json",
		// ForeignListener is deliberately EMPTY. It is the injection seam the
		// integration tests use to point the document at a mock resolver, and in
		// production the listener is DERIVED from the policy's dnscrypt entry --
		// read from the dnscrypt package, so the routing document and the resolver
		// document cannot name different addresses for the same socket. A constant
		// here would be the second copy that derivation exists to remove.
		ForeignListener:  "",
		Listen:           "127.0.0.1:53",
		DHCPUpstreamPort: 53,
	}
}

// --- the document, as typed values ---

// document is a MOSDNS v5 configuration. Every field carries the yaml key the
// pinned mosdns release reads it under, and Args is filled with the argument
// types of the plugins themselves, so the document is assembled from typed values
// and marshalled once, never concatenated out of strings.
// document is the whole configuration. API is here because the cache plugin
// registers its own flush endpoint unconditionally -- `GET /flush` on the plugin's
// own mux (mosdns plugin/executable/cache/cache.go:320-324), mounted at /plugins/<tag>
// by :108's `bp.RegAPI(c.Api())` -- and the server only starts when the document
// carries an `api.http` address (mosdns coremain/mosdns.go:67).
//
// This package emitted no `api` key, so that endpoint has been registered and
// unreachable in every document shipped so far. It is loopback for the same reason
// every other listener in this file is, and unprivileged because the router binds
// 53: an api listener that needed privilege would be one more thing that cannot
// run as an unprivileged service user.
type document struct {
	Log     logArgs      `yaml:"log"`
	Plugins []pluginArgs `yaml:"plugins"`
	API     apiArgs      `yaml:"api"`
}

type apiArgs struct {
	HTTP string `yaml:"http"`
}

// apiListenAddress is the address the document's api block binds. It is a constant
// rather than a policy field because it is not an operator's decision to make:
// there is one HTTP endpoint, it belongs to this machine, and a second one would be
// a second thing to bind.
//
// It is EXPORTED through APIListenAddress so the flush verb asks the address the
// document actually writes. A second copy of "127.0.0.1:15354" in the command would
// be a flush that talks to nothing and reports success forever, and the only thing
// that would ever notice is an operator who had already given up on it.
const apiListenAddress = "127.0.0.1:15354"

// APIListenAddress is the loopback address the routing document's api block binds.
func APIListenAddress() string { return apiListenAddress }

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
	// cdnRewriteArgs is the response rewriter: the six documents it reads, and
	// the one address it dials. Every path is required, and the plugin refuses to
	// start without any of them, so a document that names one of them has to name
	// a file that exists: this renderer cannot check that, which is why the
	// renderer tests load what it renders rather than only reading it.
	cdnRewriteArgs struct {
		PolicyFile         string `yaml:"policy_file"`
		SelectorFile       string `yaml:"selector_file"`
		ForceECHFile       string `yaml:"force_ech_file"`
		ECHStateFile       string `yaml:"ech_state_file"`
		ForeignUpstream    string `yaml:"foreign_upstream"`
		CloudflareCIDRFile string `yaml:"cloudflare_cidr_file"`
	}
	// forwardArgs is the foreign forward: how many of the upstreams ONE query
	// races, and which upstreams those are.
	//
	// Concurrent is written rather than defaulted because mosdns's own default of 1
	// is a RANDOM PICK rather than a race (pkg/executable/forward/forward.go:265-267:
	// `rand.IntN` plus `us[(r+i)%len(us)]`), which is load balancing and not
	// redundancy. An operator who configures two upstreams and reads a document that
	// does not mention `concurrent` has no way to tell they got load balancing, so
	// the document states it. The value is bounded to 1..3 by config.Validate, and 3
	// is mosdns's own cap.
	forwardArgs struct {
		Concurrent int            `yaml:"concurrent"`
		Upstreams  []upstreamArgs `yaml:"upstreams"`
	}
	upstreamArgs struct {
		Addr string `yaml:"addr"`
		// Bootstrap resolves THIS upstream's own host name and is never a query
		// path. The machine's only resolver is the router, so a domain upstream
		// without one cannot be dialled at all -- which is why it is rendered even
		// though it is easy to mistake for "send these queries here".
		//
		// ONE address, not a list. mosdns takes a single string
		// (forward.UpstreamConfig.Bootstrap) and calls netip.ParseAddr on all of it
		// after splitting the port (pkg/upstream/utils.go:77-90), so a
		// comma-joined pair is one malformed address. omitempty because an upstream
		// given by IP address needs none, and writing `bootstrap: ""` would be a
		// key mosdns would then have to reject.
		Bootstrap string `yaml:"bootstrap,omitempty"`
	}
	// ttlArgs clamps the TTL on every record in an answer. **BOTH keys are
	// omitempty and that is load-bearing**: mosdns reads `t.max > 0` before applying
	// a maximum (plugin/executable/ttl/ttl.go:91) and `t.min > 0` before applying a
	// floor (:88), and ApplyMaximumTTL(m, 0) sets every record's TTL to 0
	// (pkg/dnsutils/msg.go:65-67 -> :94-112). A zero bound must therefore be an
	// ABSENT key, not a written zero.
	ttlArgs struct {
		Max uint32 `yaml:"max,omitempty"`
		Min uint32 `yaml:"min,omitempty"`
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
	resolved, err := resolve(policy, paths)
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
		Log:     logArgs{Level: logLevel},
		API:     apiArgs{HTTP: apiListenAddress},
		Plugins: buildPlugins(policy, paths),
	}
}

// buildPlugins assembles the plugin table.
//
// It is three pieces rather than one literal because the foreign branch's piece has
// a CONDITIONAL member -- the TTL clamp -- and a Go literal cannot hold a
// conditional entry. They are appended, never spliced by index: a splice point is a
// number somebody has to keep correct, and a number that drifts puts the clamp in
// the wrong chain, which is a change nobody would read as a change at all.
func buildPlugins(policy config.Policy, paths resolvedPaths) []pluginArgs {
	plugins := foreignBranchPlugins(policy, paths)

	// The TTL clamp, and ITS POSITION IS THE WHOLE OF IT.
	//
	// The plugin table order IS the next chain, and the cache stores whatever its
	// next returned (mosdns plugin/executable/cache/cache.go:209-211). So a clamp
	// BEFORE the forward would shape only the answer on the way out while the
	// router's own cache still expired on the upstream's TTL -- which is not what
	// an operator asking for a record time means. After the forward the chain is
	// cache -> forward -> clamp, so the cache stores the clamped value and a hit
	// returns the clamped value.
	//
	// It lands here, between the forward and cn_path, for a second reason: the
	// foreign_path sequence that will exec it is further down the table, and this
	// file's own rule is that a sequence may not name a tag defined after it. A
	// clamp placed after foreign_path would be a clamp the branch cannot reach.
	//
	// Rendered only when the policy asks for one, so an unchanged policy leaves the
	// committed document byte-identical. Zero means "no clamp" rather than a clamp
	// of zero, because ApplyMaximumTTL(m, 0) sets every record's TTL to 0
	// (pkg/dnsutils/msg.go:65-67 -> :94-112): zero is not "no bound", it is
	// "expire immediately".
	if policy.ForeignCache.TTLMax > 0 || policy.ForeignCache.TTLMin > 0 {
		plugins = append(plugins, pluginArgs{
			Tag:  tagForeignTTL,
			Type: ttlclamp.PluginType,
			Args: ttlArgs{
				Max: uint32(policy.ForeignCache.TTLMax),
				Min: uint32(policy.ForeignCache.TTLMin),
			},
		})
	}
	return append(plugins, afterForeignBranch(policy, paths)...)
}

// foreignBranchPlugins is the part of the table the foreign branch's chain is made
// of, in the order it runs: the rewriter, then the cache, then the forward.
func foreignBranchPlugins(policy config.Policy, paths resolvedPaths) []pluginArgs {
	return []pluginArgs{
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
				UpstreamPort:  paths.DHCPUpstreamPort,
				FailurePolicy: policy.DHCP.FailurePolicy,
			},
		},
		{
			// The response rewriter, the first executable of the foreign branch.
			// It sits AHEAD of the cache rather than behind it, and the two
			// orders are not interchangeable:
			//
			// Ahead, a rewrite is applied to a copy of whatever the cache hands
			// back, and the object the cache owns still holds the upstream's
			// answer. A client asking again after the optimizer publishes a
			// different address gets that address, and the cached entry is
			// still the upstream's answer to rewrite next time.
			//
			// Behind, the cache stores what the rewriter returns, so the
			// selected address becomes the cached answer for as long as the
			// entry lives: one generation's selection pinned for the entry's
			// whole lifetime, and every client after the first sent there
			// whatever the health check last decided.
			//
			// That last property is a consequence of the order rather than the
			// reason for it, and the reason is the `has_resp` guard two rules
			// further down: on a cache hit it accepts and the branch ends, so
			// behind the cache the rewriter would never run at all. A strict
			// force-ECH A or AAAA is answered without calling `next` -- that is
			// the whole of the short circuit -- so with a cached upstream answer
			// in front of it the guard would accept that answer and the domain
			// would resolve in the clear. The pinned cache copies on both store
			// and load, so the rewriter could not reach the cached object even
			// if it did run behind the cache: the never-cached property above is
			// what this order buys, and it is not the reason for it.
			//
			// It is a recursive executable, so the cache and the forwarder are
			// its `next` chain, and mosdns hands it exactly that. The order of
			// the plugin list follows the order the branch runs in, so the file
			// an operator reads lists the three executables in that order.
			Tag:  tagCDNRewrite,
			Type: cdnrewrite.PluginType,
			Args: cdnRewriteArgs{
				PolicyFile:   paths.Policy,
				SelectorFile: paths.Selector,
				ForceECHFile: paths.ForceECH,
				ECHStateFile: paths.ECHState,
				// The same listener the forward below enters, taken from the
				// same checked value, so the two cannot disagree about where
				// the resolver is. The ECH key is fetched over this TCP
				// listener and not through mosdns's UDP transport, which
				// re-sends an unanswered query and can drop an answer that
				// arrived early.
				ForeignUpstream: paths.echUpstream,
				// The PUBLISHED prefix list, not the API's cached document: one
				// prefix per line, written by the same fetch that writes the
				// envelope. See candidate.DefaultCloudflarePrefixFileName.
				CloudflareCIDRFile: paths.CloudflarePrefixes,
			},
		},
		{
			Tag:  tagForeignCache,
			Type: "cache",
			Args: cacheArgs{Size: policy.ForeignCache.Size},
		},
		{
			Tag:  tagForeignForward,
			Type: "forward",
			Args: forwardArgs{
				Concurrent: policy.Foreign.Concurrent,
				Upstreams:  paths.forwardUpstreams,
			},
		},
	}
}

// foreignPathRules is the foreign branch's sequence, with the clamp exec'd where it
// has to be exec'd.
//
// **Being in the plugin table is not enough.** mosdns runs nothing a sequence does
// not exec: `forward` is a plain Executable that sets the response and returns
// (mosdns plugin/executable/forward/forward.go:198-204), so a clamp merely RENDERED
// sits in the document doing nothing forever. That was the defect in this change's
// first draft, and the tests beside it did not catch it because they asserted table
// position and text.
//
// The rule goes BETWEEN the forward and the final accept, and the position is the
// whole of it:
//
//   - the cache is exec'd above, and a cache's `next` is the REST of the sequence
//     after it, so what the cache stores on a miss is what this rule returns -- the
//     CLAMPED answer. A clamp before the cache would shape only the answer on the
//     way out, and the router's own cache would still expire on the upstream's TTL,
//     which is not what "the cache record time" means to an operator.
//   - on a cache HIT the `has_resp` rule accepts and the branch ends, so this does
//     not run twice: the stored value was clamped when it was stored.
//
// The rule is CONDITIONAL for the same reason the plugin is: a document naming
// `$foreign_ttl` with no such plugin is refused by the loader, so a policy that
// asks for no clamp would get a document that cannot start.
func foreignPathRules(policy config.Policy) []rule {
	rules := []rule{
		{Exec: "$" + tagCDNRewrite},
		{Exec: "$" + tagForeignCache},
		{Matches: []string{"has_resp"}, Exec: "accept"},
		{Exec: "$" + tagForeignForward},
	}
	if policy.ForeignCache.TTLMax > 0 || policy.ForeignCache.TTLMin > 0 {
		rules = append(rules, rule{Exec: "$" + tagForeignTTL})
	}
	return append(rules, rule{Exec: "accept"})
}

// afterForeignBranch is everything that is NOT part of the foreign branch's chain:
// the China sequence, the foreign sequence that execs the branch above, the dispatch
// that chooses between them, and the two servers.
//
// foreign_path sits here rather than beside the plugins it names because it is the
// thing that names them, and a sequence may only name a tag defined above it.
func afterForeignBranch(policy config.Policy, paths resolvedPaths) []pluginArgs {
	return []pluginArgs{
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
			// The foreign branch. The rewriter runs first and the cache is
			// downstream of it, so a rewrite lands on a copy of a cache hit
			// and a rewritten answer is never itself stored. The cache is a
			// recursive executable: it always runs the rules after it, so the
			// has_resp check is what keeps a cache hit from being forwarded as
			// well.
			Tag:  tagForeignPath,
			Type: "sequence",
			Args: foreignPathRules(policy),
		},
		{
			// The dispatch. The China list is checked first and the foreign
			// path is the unconditional default, so no name is unrouted.
			//
			// Both rules jump rather than call. `exec: $cn_path` would call
			// the sequence and then resume this chain at the next rule, so a
			// domestic answer would be carried into the foreign branch,
			// stored there, and later overwritten by the stored copy. That
			// cache is not generation-scoped, so a China answer cached under
			// one DHCP DNS set would outlive that set. `goto` abandons the
			// parent chain instead, which is what makes "no fallback between
			// the branches" a property of this document rather than of a
			// response check further down it. The has_resp rule in
			// foreign_path is only the cache-hit guard.
			Tag:  tagMain,
			Type: "sequence",
			Args: []rule{
				{Matches: []string{"qname $" + tagCNDomains}, Exec: "goto " + tagCNPath},
				{Exec: "goto " + tagForeignPath},
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
//
// It also says where the log level comes from, because the rest of the header
// sends the reader to the policy for everything and the level is the one value in
// this document with no policy field: it is the renderer's own logLevel constant
// (the level the plugin logs a generation it adopts at, which the warnings above it
// report through), not something an operator can choose. Naming it here is what
// stops "edit the policy" from being advice that cannot be followed.
func header(policyPath string) string {
	return fmt.Sprintf(`# mosdns-router routing configuration for MOSDNS v5.3.4.
#
# Generated by internal/mosdnsconfig.Render from the policy at %s.
# Edit the policy or the paths, not this file: configs/mosdns.yaml is the
# committed output of Render(config.Defaults(), ProductionPaths()) and a test
# compares the two byte for byte, so a hand edit here is an edit the project
# stops being able to explain. The one value here with no policy field is the log
# level: it is the renderer's own constant (logLevel in
# internal/mosdnsconfig/render.go), and a level is a diagnostic an operator reads
# rather than a setting a policy chooses.
#
# Two branches and no third. A name the pinned China list matches goes to the
# DNS servers DHCP published, and every other name goes to the loopback DNSCrypt
# resolver over TCP. There is no fallback between them: a foreign query that
# cannot be answered fails, and is never re-asked inside the network the user is
# leaving.
#
# The foreign branch rewrites what comes back from that resolver, and only what
# comes back from it: cdn_rewrite runs first, so a rewritten answer is never
# itself cached, and a cached answer is rewritten on the way out to every client
# rather than stored rewritten. It replaces an address only for a response every
# one of whose addresses is inside a published Cloudflare range, and only while
# the published selection's proof window is open. Nothing in the domestic branch
# is rewritten: those answers come from the network the user is not leaving, and
# nothing here has proved anything about them.
`, policyPath)
}

// --- paths ---

// resolvedPaths is a Paths that has passed every check. The document is built
// from it and from nothing else, so no unchecked value can reach an argument.
type resolvedPaths struct {
	Policy             string
	Selector           string
	ForceECH           string
	ECHState           string
	CNDomains          string
	CloudflarePrefixes string
	DHCPState          string
	ForeignListener    string
	Listen             string
	DHCPUpstreamPort   int

	// echUpstream is the ONE address the ECH key is fetched through. It is derived
	// here rather than in renderable so that the routing document and the
	// rewriter's own argument cannot disagree about it: it is the same value, read
	// once, and there is no second place it is written.
	//
	// It is not the same thing as ForeignListener and it is not required to be. The
	// foreign branch may forward to several upstreams while the ECH fetch -- which
	// has no client watching it and no second answer to fall back on -- goes to the
	// one that satisfies cdn_rewrite's tcp:// requirement.
	echUpstream string
	// forwardUpstreams is the enabled `upstream` entries, in policy order, already
	// in the form the document carries. Derived here for the same reason.
	forwardUpstreams []upstreamArgs
}

// resolve checks the paths and returns them in the form the document will carry.
// A path is cleaned first, so a path that only looks outside /etc cannot be
// rendered into it, and every refusal names the value that caused it.
func resolve(policy config.Policy, paths Paths) (resolvedPaths, error) {
	resolved := resolvedPaths{}

	for _, field := range []struct {
		name  string
		value string
	}{
		{"policy path", paths.Policy},
		{"selector path", paths.Selector},
		{"force-ECH allowlist path", paths.ForceECH},
		{"ECH state document path", paths.ECHState},
		{"China list path", paths.CNDomains},
		{"Cloudflare prefix list path", paths.CloudflarePrefixes},
		{"state document path", paths.DHCPState},
		{"listen address", paths.Listen},
	} {
		if strings.TrimSpace(field.value) == "" {
			return resolvedPaths{}, fmt.Errorf("mosdnsconfig: the %s must not be empty", field.name)
		}
	}
	resolved.Policy = cleanPath(paths.Policy)
	resolved.Selector = cleanPath(paths.Selector)
	resolved.ForceECH = cleanPath(paths.ForceECH)
	resolved.ECHState = cleanPath(paths.ECHState)
	resolved.CNDomains = cleanPath(paths.CNDomains)
	resolved.CloudflarePrefixes = cleanPath(paths.CloudflarePrefixes)
	resolved.DHCPState = cleanPath(paths.DHCPState)
	resolved.Listen = strings.TrimSpace(paths.Listen)

	// A path that is resolved against a working directory is a path that means
	// something different under systemd, under a shell and under a test. The
	// allowlist is in this list because it is the one of the four an operator
	// edits by hand, and a hand-edited path is the one most likely to be written
	// relative to wherever the operator happened to be.
	for _, field := range []struct {
		name  string
		value string
	}{
		{"policy path", resolved.Policy},
		{"selector path", resolved.Selector},
		{"force-ECH allowlist path", resolved.ForceECH},
		{"ECH state document path", resolved.ECHState},
		{"China list path", resolved.CNDomains},
		{"Cloudflare prefix list path", resolved.CloudflarePrefixes},
		{"state document path", resolved.DHCPState},
	} {
		if !strings.HasPrefix(field.value, "/") {
			return resolvedPaths{}, fmt.Errorf("mosdnsconfig: the %s %q must be absolute", field.name, field.value)
		}
	}
	// The China list, the state document, the selector, the ECH metadata document
	// and the range list are all rewritten while the router runs. A file under
	// /etc is replaced by packaging, and /etc/mosdns is root-owned configuration:
	// a rule list published there would be lost on the next upgrade, a state
	// document the service user cannot write would stop the domestic branch at the
	// first DHCP renewal, and an ECH document under a root-owned directory would
	// cost a force-ECH name its key for as long as the write kept failing.
	//
	// The force-ECH allowlist is the one path of the four that is NOT in this
	// list, and that is the difference between the two kinds of file: nothing
	// rewrites it while the router runs, an operator edits it and expects to find
	// it where the other configuration is, and a file the router cannot replace
	// under /etc is a file that survives the upgrade nobody meant to keep it. The
	// renderer therefore refuses it for emptiness and for being relative, and
	// leaves it where the operator put it.
	for _, field := range []struct {
		name  string
		value string
	}{
		{"China list path", resolved.CNDomains},
		{"Cloudflare prefix list path", resolved.CloudflarePrefixes},
		{"state document path", resolved.DHCPState},
		{"selector path", resolved.Selector},
		{"ECH state document path", resolved.ECHState},
	} {
		if under(field.value, readOnlyConfigurationRoot) {
			return resolvedPaths{}, fmt.Errorf(
				"mosdnsconfig: the %s %q is under %s, which is read-only configuration; a file rewritten while the router runs belongs under /var/lib or /run",
				field.name, field.value, readOnlyConfigurationRoot,
			)
		}
	}

	listen, err := checkListen(resolved.Listen)
	if err != nil {
		return resolvedPaths{}, err
	}
	// The foreign route is DERIVED from the policy, and the packaged resolver's
	// address is dnscrypt.ListenAddress() rather than a second copy of the string
	// in this package.
	//
	// Paths.ForeignListener is still read, and still WINS when it is set, because it
	// is the injection seam the integration tests use to point the document at a
	// mock resolver (tests/integration/routing_test.go:457). ProductionPaths()
	// leaves it empty, so the production document derives the listener from the
	// dnscrypt entry -- and reads it from the dnscrypt package, so the two
	// documents cannot disagree about where the resolver listens.
	//
	// What is derived here, in order, because each step needs the previous one:
	//
	//  1. the forward's upstream list, which is every enabled `upstream` entry in
	//     policy order. A `dnscrypt` entry contributes none: it is a process, not
	//     an address. Its listener becomes a forward upstream only when the
	//     dnscrypt entry is on AND it is the injected listener (below), which is
	//     the shape the tests inject.
	//  2. the ECH source, which is the dnscrypt entry's listener when that entry is
	//     on, and otherwise the first enabled tcp:// entry's address.
	//
	// cdn_rewrite refuses every non-tcp transport for the ECH fetch
	// (plugin/executable/cdn_rewrite/cdn_rewrite.go:353) on a measured ground, so
	// the udp and DoH entries an operator adds are ROUTED and are never the ECH
	// source. config.Validate has already refused a policy with no ECH source at
	// all; this is where a validated policy's ECH source is read once.
	injected := strings.TrimSpace(paths.ForeignListener)
	if injected != "" {
		if _, err := checkForeignListener(injected); err != nil {
			return resolvedPaths{}, err
		}
	}
	// The dnscrypt entry's own listener, from the package that renders it.
	listener := "tcp://" + dnscrypt.ListenAddress
	if injected != "" {
		listener = injected
	}
	resolved.ForeignListener = listener

	if err := resolveForeignRoute(&resolved, policy, listener); err != nil {
		return resolvedPaths{}, err
	}

	// The listener the router will dial, as an address it can be compared with.
	foreign, err := checkForeignListener(listener)
	if err != nil {
		return resolvedPaths{}, err
	}
	// The router binds the listen address and dials the foreign listener, so a
	// document where the two are the same endpoint is a router that either
	// cannot bind, or binds the port its own foreign branch forwards to. Both are
	// refused here, where the two addresses can still be compared, rather than by
	// the bind that would fail. The comparison is exact because both checks
	// require an IP address: a hostname would have to be resolved before it could
	// be compared, and a document that needs a resolver to be loaded is a
	// document this renderer will not produce.
	if listen == foreign {
		return resolvedPaths{}, fmt.Errorf(
			"mosdnsconfig: the listen address %s is the foreign listener %s: the router would bind the port its own foreign branch forwards to",
			listen, foreign,
		)
	}

	port, err := checkDHCPUpstreamPort(paths.DHCPUpstreamPort)
	if err != nil {
		return resolvedPaths{}, err
	}
	resolved.DHCPUpstreamPort = port
	return resolved, nil
}

// resolveForeignRoute derives the forward's upstream list and the ECH source from
// the policy, and writes both onto resolved. It is separate from resolve() because
// it is the one part of path resolution that reads the POLICY rather than the
// paths, and because it is the part with the reasoning worth keeping whole.
//
// listener is the address the dnscrypt entry stands for, already decided by the
// caller: the packaged resolver's own address, or the injected one.
func resolveForeignRoute(resolved *resolvedPaths, policy config.Policy, listener string) error {
	// Every enabled `upstream` entry becomes exactly one forward upstream, in policy
	// order, so the document and the policy are comparable by reading them side by
	// side. A `dnscrypt` entry contributes none of its own: the entry names a
	// process, and the address that reaches the process is the listener, which is
	// added below when that entry is the route.
	//
	// The dnscrypt listener IS added when its entry is enabled, because a policy
	// whose dnscrypt entry is on and which renders a forward that never dials it
	// is a document that ignores the entry the operator left switched on. It is
	// added FIRST when it is enabled, because the packaged resolver is the road an
	// ECH failure is diagnosable against, and a document that races it against a
	// DoQ endpoint it cannot diagnose is worse than one that offers both in order.
	resolved.forwardUpstreams = nil
	// The dnscrypt entry, when it is on, contributes the listener -- ALWAYS, and not
	// only when no other upstream is configured.
	//
	// The first version of this added it in the "no upstream entries" branch, on the
	// reasoning that a dnscrypt entry "names a process, not an address". That
	// reasoning stopped one step short: the entry does not carry an address, but the
	// route still has to REACH the process, and the only way to reach it is its
	// listener. So the default policy -- one dnscrypt entry and one DoQ entry --
	// rendered a forward that never dialled the packaged resolver at all, and the
	// test that says the enabled entry is in the route is what caught it.
	//
	// It goes FIRST because it is the road an ECH failure is diagnosable against: a
	// document that races the packaged resolver against a DoQ endpoint whose
	// behaviour nothing in this project can observe is worse than one that offers
	// both, in an order a reader can follow.
	// Computed ONCE and used twice: the source decides whether the packaged entry is
	// in the route, and it IS the answer written into the rewriter's arguments. The
	// first version called it three times, and guarded the whole block on a call
	// whose result the inner loop already established.
	source := config.ECHSource(policy.Foreign.Upstreams, listener)
	for _, entry := range policy.Foreign.Upstreams {
		if entry.IsEnabled() && entry.Kind == config.UpstreamKindDNSCrypt && source != "" {
			resolved.forwardUpstreams = append(resolved.forwardUpstreams, upstreamArgs{Addr: listener})
			break
		}
	}
	for _, entry := range policy.Foreign.Upstreams {
		if !entry.IsEnabled() || entry.Kind != config.UpstreamKindUpstream {
			continue
		}
		// The policy's list holds at most one entry, enforced by
		// config.ValidateOneUpstream against mosdns's own single-address parsing.
		// Joining a list here would render a document the router refuses to load,
		// so the first entry is taken and the validation is what makes that safe.
		bootstrap := ""
		if len(entry.Bootstrap) > 0 {
			bootstrap = entry.Bootstrap[0]
		}
		resolved.forwardUpstreams = append(resolved.forwardUpstreams, upstreamArgs{
			Addr:      entry.Addr,
			Bootstrap: bootstrap,
		})
	}
	// **Reaching either refusal below is a FAULT, not the default configuration.**
	// The first version's comment here said the opposite -- "that is the DEFAULT
	// configuration, not a fault" -- and then returned an error three lines later.
	// The enabled-dnscrypt case is handled above, where the listener is added, so an
	// empty list here means no enabled entry of either kind reached the route.
	if len(resolved.forwardUpstreams) == 0 {
		return config.ErrNoECHSource
	}
	if source == "" {
		// config.Validate refuses this policy before it reaches here, so an empty
		// source means the caller handed a policy that was never validated. This is
		// what keeps the renderer from producing a document whose ECH fetch
		// silently has nowhere to go.
		return config.ErrNoECHSource
	}
	resolved.echUpstream = source
	return nil
}

// checkDHCPUpstreamPort resolves the port a published DHCP DNS address is dialled
// on. An unset value is the port a DHCP DNS server answers on, 53; a value
// outside the range of a port number is refused, because the plugin would be
// handed a port it cannot dial and the domestic branch would be dead in a
// document that looked configured.
//
// The refusal states what 0 means rather than only the accepted range. By the
// time a reader has this message they are looking at a value that was refused, and
// "must be between 1 and 65535" reads as though 0 were also outside the range --
// which is false, because 0 is accepted and rendered as 53. A document that named
// upstream_port: 0 and then a document that named upstream_port: 65536 would
// otherwise produce refusals that differ only in the number.
func checkDHCPUpstreamPort(value int) (int, error) {
	if value == 0 {
		return defaultDHCPUpstreamPort, nil
	}
	if value < 0 || value > maximumDHCPUpstreamPort {
		return 0, fmt.Errorf(
			"mosdnsconfig: the DHCP upstream port %d is not a port a published address can be dialled on; 0 means the default %d, and any other value must be between 1 and %d",
			value, defaultDHCPUpstreamPort, maximumDHCPUpstreamPort,
		)
	}
	return value, nil
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
// cannot answer on the transport a client happened to use. The parsed address is
// returned so it can be compared with the foreign listener's.
func checkListen(value string) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the listen address %q must be an IP address and a port: %w", value, err)
	}
	if address.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the listen address %q names no port, so nothing would answer on a known one", value)
	}
	return address, nil
}

// checkForeignListener refuses anything that is not the DNSCrypt resolver's own
// tcp://host:port URL, and refuses port 53 in particular: a foreign upstream on
// the system resolver's port is the fallback this project refuses to build,
// whatever a path or a scheme says about it. The parsed address is returned so it
// can be compared with the address the router binds.
func checkForeignListener(value string) (netip.AddrPort, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the foreign listener %q is not a URL: %w", value, err)
	}
	if parsed.Scheme != foreignListenerScheme {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the foreign listener %q must be a %s:// URL, want the DNSCrypt resolver entered over TCP", value, foreignListenerScheme)
	}
	// Anything after the host would be sent to the resolver as part of the URL
	// mosdns dials, which is not what a listener address is.
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the foreign listener %q must be a bare tcp://host:port URL, with no credentials, path or query", value)
	}
	address, err := netip.ParseAddrPort(parsed.Host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the foreign listener %q must name an IP address and a port: %w", value, err)
	}
	if address.Port() == systemResolverPort {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the foreign listener %q is on port %d, which belongs to the system resolver", value, systemResolverPort)
	}
	if address.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("mosdnsconfig: the foreign listener %q names no port", value)
	}
	return address, nil
}

// foreignURL is the URL the document carries for the resolver's address. It is
// rebuilt from the parsed parts, so a listener that carried anything a URL would
// have to escape cannot reach the document.
func foreignURL(address netip.AddrPort) string {
	return (&url.URL{Scheme: foreignListenerScheme, Host: address.String()}).String()
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
