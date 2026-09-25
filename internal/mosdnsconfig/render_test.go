package mosdnsconfig

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"mosdns-router/internal/config"
	"mosdns-router/internal/state"
	"mosdns-router/internal/testdns"
)

// The expectations below are stated literally, and decoded by this test into its
// own types rather than through the renderer's, so a renderer that got a path,
// a port, a URL scheme, a tag order or a policy value wrong cannot be agreed
// with by a test that reuses its own structures.

const (
	// The committed files this package generates. They are compared against a
	// fresh render rather than trusted on sight.
	committedMosdnsConfig = "../../configs/mosdns.yaml"
	committedDNSCryptTOML = "../../configs/dnscrypt-proxy.toml"
	committedCNList       = "../../configs/cn-domains.txt"

	// The listener the foreign forward enters. It is the loopback DNSCrypt
	// resolver's own listener, never port 53, so a foreign query can never be
	// answered by the system resolver this router exists to keep out of the way.
	productionForeignListener = "tcp://127.0.0.1:15353"
	productionListen          = "127.0.0.1:53"

	// The two names a routing test uses, one from each branch of the committed
	// China list. They are fully qualified, because that is the form a name has
	// when it arrives over the wire.
	chinaDomain   = "baidu.com."
	foreignDomain = "www.google.com."
)

// ipv4Address finds every dotted-quad in a generated document, so a test can say
// which addresses a file names at all.
var ipv4Address = regexp.MustCompile(`[0-9]{1,3}(\.[0-9]{1,3}){3}`)

// --- what a mosdns configuration file decodes into ---

type rendered struct {
	Log     renderedLog     `yaml:"log"`
	Plugins []renderedEntry `yaml:"plugins"`
}

type renderedLog struct {
	Level string `yaml:"level"`
}

type renderedEntry struct {
	Tag  string    `yaml:"tag"`
	Type string    `yaml:"type"`
	Args yaml.Node `yaml:"args"`
}

type renderedRule struct {
	Matches []string `yaml:"matches"`
	Exec    string   `yaml:"exec"`
}

type renderedDomainSet struct {
	Files []string `yaml:"files"`
}

type renderedDHCPForward struct {
	StateFile     string `yaml:"state_file"`
	CacheEntries  int    `yaml:"cache_entries"`
	UpstreamPort  int    `yaml:"upstream_port"`
	FailurePolicy string `yaml:"failure_policy"`
}

type renderedCache struct {
	Size     int    `yaml:"size"`
	DumpFile string `yaml:"dump_file"`
}

type renderedForward struct {
	Upstreams []struct {
		Addr string `yaml:"addr"`
	} `yaml:"upstreams"`
}

type renderedServer struct {
	Entry  string `yaml:"entry"`
	Listen string `yaml:"listen"`
}

func decodeRendered(t *testing.T, document []byte) rendered {
	t.Helper()
	var parsed rendered
	decoder := yaml.NewDecoder(strings.NewReader(string(document)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		t.Fatalf("the rendered document does not decode: %v\n%s", err, document)
	}
	return parsed
}

// entry returns the one plugin a tag names. A tag used twice, or not at all, is
// a routing bug rather than a cosmetic one, so both are failures here.
func (r rendered) entry(t *testing.T, tag string) renderedEntry {
	t.Helper()
	var found []renderedEntry
	for _, plugin := range r.Plugins {
		if plugin.Tag == tag {
			found = append(found, plugin)
		}
	}
	if len(found) != 1 {
		t.Fatalf("tag %q names %d plugins, want exactly one", tag, len(found))
	}
	return found[0]
}

func tags(r rendered) []string {
	names := make([]string, 0, len(r.Plugins))
	for _, plugin := range r.Plugins {
		names = append(names, plugin.Tag)
	}
	return names
}

func rulesOf(t *testing.T, entry renderedEntry) []renderedRule {
	t.Helper()
	var rules []renderedRule
	if err := entry.Args.Decode(&rules); err != nil {
		t.Fatalf("the %s sequence does not decode into rules: %v", entry.Tag, err)
	}
	return rules
}

func argsOf[T any](t *testing.T, entry renderedEntry) T {
	t.Helper()
	var args T
	if err := entry.Args.Decode(&args); err != nil {
		t.Fatalf("the %s arguments do not decode: %v", entry.Tag, err)
	}
	return args
}

// --- the rendered routing ---

// TestRenderedRoutingNamesEachPluginExactlyOnceInLoadOrder pins the shape of the
// document as a whole. A tag used twice would make mosdns refuse to start, and a
// tag out of order would be missing the plugin it refers to: the sequences are
// built while the document is loaded, so cn_domains has to exist before the
// sequence that matches against it, and cn_path before the sequence that jumps
// into it.
func TestRenderedRoutingNamesEachPluginExactlyOnceInLoadOrder(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	want := []struct {
		tag  string
		kind string
	}{
		{"cn_domains", "domain_set"},
		{"dhcp_forward", "dhcp_forward"},
		{"foreign_cache", "cache"},
		{"foreign_forward", "forward"},
		{"cn_path", "sequence"},
		{"foreign_path", "sequence"},
		{"main", "sequence"},
		{"udp_server", "udp_server"},
		{"tcp_server", "tcp_server"},
	}
	var wantTags []string
	for _, plugin := range want {
		wantTags = append(wantTags, plugin.tag)
	}
	if got := tags(parsed); !equalTags(got, wantTags) {
		t.Errorf("plugin tags, in order:\n got %v\nwant %v", got, wantTags)
	}
	for _, plugin := range want {
		if got := parsed.entry(t, plugin.tag).Type; got != plugin.kind {
			t.Errorf("tag %q has type %q, want %q", plugin.tag, got, plugin.kind)
		}
	}
	if parsed.Log.Level == "" {
		t.Error("the document sets no log level, and mosdns refuses to start without one")
	}
}

// TestCNDispatchRunsBeforeTheForeignDefault covers the one routing decision the
// whole project turns on: a name the China list matches goes to the DHCP branch,
// and every other name goes to the foreign branch. The order is the routing, so
// a reversed pair of rules would send China names abroad and never fail.
func TestCNDispatchRunsBeforeTheForeignDefault(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	domainSet := argsOf[renderedDomainSet](t, parsed.entry(t, "cn_domains"))
	if len(domainSet.Files) != 1 || domainSet.Files[0] != "/var/lib/mosdns/lists/cn-domains.txt" {
		t.Errorf("the cn_domains set reads %v, want the one committed list [/var/lib/mosdns/lists/cn-domains.txt]", domainSet.Files)
	}

	want := []renderedRule{
		{Matches: []string{"qname $cn_domains"}, Exec: "$cn_path"},
		{Exec: "$foreign_path"},
	}
	if got := rulesOf(t, parsed.entry(t, "main")); !equalRules(got, want) {
		t.Errorf("the main sequence is\n got %+v\nwant %+v", got, want)
	}
}

// TestDomesticBranchForwardsToTheDHCPPluginAndEnds covers the domestic branch's
// two steps. The forwarder is the only executable, so a China name can only be
// answered by the DNS servers DHCP published, and the branch ends there instead
// of falling through to the foreign branch when the forwarder fails.
func TestDomesticBranchForwardsToTheDHCPPluginAndEnds(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	want := []renderedRule{{Exec: "$dhcp_forward"}, {Exec: "accept"}}
	if got := rulesOf(t, parsed.entry(t, "cn_path")); !equalRules(got, want) {
		t.Errorf("the cn_path sequence is\n got %+v\nwant %+v", got, want)
	}

	// The cache bound is rendered rather than inherited, so the committed file
	// states the bound instead of following an upstream default that can change.
	// A published state carries bare addresses, so the port is stated too.
	forwarder := argsOf[renderedDHCPForward](t, parsed.entry(t, "dhcp_forward"))
	if forwarder.StateFile != "/run/mosdns/dhcp-upstreams.json" {
		t.Errorf("dhcp_forward reads %q, want the published state document /run/mosdns/dhcp-upstreams.json", forwarder.StateFile)
	}
	if forwarder.CacheEntries != 4096 {
		t.Errorf("dhcp_forward cache_entries = %d, want 4096", forwarder.CacheEntries)
	}
	if forwarder.UpstreamPort != 53 {
		t.Errorf("dhcp_forward upstream_port = %d, want the DNS port a published address is dialled on, 53", forwarder.UpstreamPort)
	}
	if forwarder.FailurePolicy != "disable-current" {
		t.Errorf("dhcp_forward failure_policy = %q, want the default policy's disable-current", forwarder.FailurePolicy)
	}
}

// TestTheFailurePolicyTheOperatorChoseReachesThePlugin proves the rendered
// argument is the policy's own value. A renderer that wrote its own default
// would ignore an operator who chose the other behaviour, and the choice would
// be discovered only when the network changed.
func TestTheFailurePolicyTheOperatorChoseReachesThePlugin(t *testing.T) {
	chosen := config.Defaults()
	chosen.DHCP.FailurePolicy = "use-last-good"

	document, err := Render(chosen, ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	forwarder := argsOf[renderedDHCPForward](t, parsed.entry(t, "dhcp_forward"))
	if forwarder.FailurePolicy != chosen.DHCP.FailurePolicy {
		t.Fatalf("rendered failure_policy = %q, want the policy's own %q", forwarder.FailurePolicy, chosen.DHCP.FailurePolicy)
	}
}

// TestForeignPathAnswersFromTheCacheBeforeItForwards covers the foreign branch's
// four steps, and the second one is the load-bearing one: the cache is a
// recursive executable that always runs the rules after it, so a cache hit is
// only kept when a has_resp check ends the branch there. Without that check every
// cache hit would be forwarded as well, and the cache would save nothing.
func TestForeignPathAnswersFromTheCacheBeforeItForwards(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	want := []renderedRule{
		{Exec: "$foreign_cache"},
		{Matches: []string{"has_resp"}, Exec: "accept"},
		{Exec: "$foreign_forward"},
		{Exec: "accept"},
	}
	if got := rulesOf(t, parsed.entry(t, "foreign_path")); !equalRules(got, want) {
		t.Errorf("the foreign_path sequence is\n got %+v\nwant %+v", got, want)
	}

	// The cache is rendered with a stated bound and no dump file: a dump would
	// write the user's query names to disk, which is the foreign resolver's
	// cache's job not to do.
	forward := argsOf[renderedCache](t, parsed.entry(t, "foreign_cache"))
	if forward.Size != 1024 {
		t.Errorf("foreign_cache size = %d, want the stated 1024 entries", forward.Size)
	}
	if forward.DumpFile != "" {
		t.Errorf("foreign_cache dumps to %q, want no dump file", forward.DumpFile)
	}
}

// TestTheForeignForwardUsesOnlyTheDNSCryptListenerOverTCP covers the transport
// and the single upstream. The listener is the loopback DNSCrypt resolver, which
// the foreign path must reach over TCP: mosdns's stock UDP transport re-sends a
// query that has not been answered and can drop an answer that arrives before its
// exchange waits for it, and a second upstream would be a second route out.
func TestTheForeignForwardUsesOnlyTheDNSCryptListenerOverTCP(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	forward := argsOf[renderedForward](t, parsed.entry(t, "foreign_forward"))
	if len(forward.Upstreams) != 1 {
		t.Fatalf("the foreign forward has %d upstreams, want exactly one: %+v", len(forward.Upstreams), forward.Upstreams)
	}
	if got := forward.Upstreams[0].Addr; got != productionForeignListener {
		t.Fatalf("the foreign forward enters %q, want %q", got, productionForeignListener)
	}
	if !strings.HasPrefix(forward.Upstreams[0].Addr, "tcp://") {
		t.Errorf("the foreign upstream is %q, want a tcp:// URL", forward.Upstreams[0].Addr)
	}
}

// TestBothServersListenOnTheSameLoopbackAddressForMain covers the only two
// listeners the router opens. Both have to serve the main entry, or half the
// transports would answer from somewhere else, and the address is the loopback
// the system's own stub resolver points at.
func TestBothServersListenOnTheSameLoopbackAddressForMain(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	for _, tag := range []string{"udp_server", "tcp_server"} {
		server := argsOf[renderedServer](t, parsed.entry(t, tag))
		if server.Entry != "main" {
			t.Errorf("%s serves %q, want the main entry", tag, server.Entry)
		}
		if server.Listen != productionListen {
			t.Errorf("%s listens on %q, want %q", tag, server.Listen, productionListen)
		}
	}
}

// TestRenderRefusesAPathSetThatCannotBeServed is the safety table. Every entry is
// a configuration that would render a document nobody can run, or worse, one that
// would run with a different meaning than the operator asked for: an empty path
// would be read relative to whatever directory the service started in, and a
// mutable rule list under /etc would be a file a root-owned configuration
// directory is not supposed to hold. Each case also says which value the refusal
// has to name, so a refusal raised by a different check than the one under test
// cannot stand in for it.
func TestRenderRefusesAPathSetThatCannotBeServed(t *testing.T) {
	for name, testCase := range map[string]struct {
		paths       Paths
		wantMention string
	}{
		"no policy path":                 {withoutPolicy(ProductionPaths()), "must not be empty"},
		"no China list path":             {withoutCNDomains(ProductionPaths()), "must not be empty"},
		"no state document path":         {withoutDHCPState(ProductionPaths()), "must not be empty"},
		"no foreign listener":            {withoutForeignListener(ProductionPaths()), "must not be empty"},
		"no listen address":              {withoutListen(ProductionPaths()), "must not be empty"},
		"a blank policy path":            {withPolicy(ProductionPaths(), "   "), "must not be empty"},
		"a relative China list":          {withCNDomains(ProductionPaths(), "lists/cn-domains.txt"), "lists/cn-domains.txt"},
		"a China list under etc":         {withCNDomains(ProductionPaths(), "/etc/mosdns/lists/cn-domains.txt"), "/etc/mosdns/lists/cn-domains.txt"},
		"a state file under etc":         {withDHCPState(ProductionPaths(), "/etc/mosdns/dhcp-upstreams.json"), "/etc/mosdns/dhcp-upstreams.json"},
		"a listen address with no port":  {withListen(ProductionPaths(), "127.0.0.1"), "127.0.0.1"},
		"a listen address on port zero":  {withListen(ProductionPaths(), "127.0.0.1:0"), "127.0.0.1:0"},
		"a foreign listener on 53":       {withForeignListener(ProductionPaths(), "tcp://127.0.0.1:53"), "tcp://127.0.0.1:53"},
		"a udp foreign listener":         {withForeignListener(ProductionPaths(), "udp://127.0.0.1:15353"), "udp://127.0.0.1:15353"},
		"a bare foreign address":         {withForeignListener(ProductionPaths(), "127.0.0.1:15353"), "127.0.0.1:15353"},
		"an https foreign listener":      {withForeignListener(ProductionPaths(), "https://127.0.0.1:15353"), "https://127.0.0.1:15353"},
		"a foreign listener with a path": {withForeignListener(ProductionPaths(), "tcp://127.0.0.1:15353/dns-query"), "/dns-query"},
		"a foreign listener by name":     {withForeignListener(ProductionPaths(), "tcp://resolver.example.com:15353"), "resolver.example.com"},
		"a list named after a Chinese resolver": {
			// The resolver is named in a path rather than in a plugin argument,
			// because a path is a value this renderer takes from its caller: the
			// scan has to see the finished document, not just the arguments.
			withCNDomains(ProductionPaths(), "/var/lib/mosdns/lists/223.5.5.5.txt"),
			"223.5.5.5",
		},
	} {
		t.Run(name, func(t *testing.T) {
			document, err := Render(config.Defaults(), testCase.paths)
			if err == nil {
				t.Fatalf("Render accepted %+v and wrote:\n%s", testCase.paths, document)
			}
			if testCase.wantMention != "" && !strings.Contains(err.Error(), testCase.wantMention) {
				t.Errorf("the refusal %q does not name the offending value %q", err, testCase.wantMention)
			}
		})
	}
}

// TestRenderRefusesAPolicyItCannotHonour covers a policy field this document has
// no way to satisfy. A persistent cache needs a dump file, and there is no path
// for one here, so a policy that asks for one is refused instead of rendered as
// a cache that quietly keeps nothing.
func TestRenderRefusesAPolicyItCannotHonour(t *testing.T) {
	policy := config.Defaults()
	policy.Cache.PersistentDump = true

	if document, err := Render(policy, ProductionPaths()); err == nil {
		t.Fatalf("Render accepted a policy asking for a persistent cache and wrote:\n%s", document)
	}
}

// TestRenderIsAStableFunctionOfItsInputs covers the property the committed file
// depends on. A document that varied between two renders of the same inputs
// could not be committed and compared, and the comparison is the only thing
// holding the shipped file to what this project believes it deploys.
func TestRenderIsAStableFunctionOfItsInputs(t *testing.T) {
	first, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("first Render: %v", err)
	}
	second, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("second Render: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("two renders of the same inputs differ:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}

	// Every path this renderer takes has to reach the document. A renderer that
	// ignored one would be stable in the way an empty document is stable.
	for name, elsewhere := range map[string]Paths{
		"the China list path":  withCNDomains(ProductionPaths(), "/var/lib/mosdns/lists/other.txt"),
		"the state document":   withDHCPState(ProductionPaths(), "/run/mosdns/other.json"),
		"the listen address":   withListen(ProductionPaths(), "127.0.0.1:5353"),
		"the policy path":      withPolicy(ProductionPaths(), "/etc/mosdns/other-policy.yaml"),
		"the foreign listener": withForeignListener(ProductionPaths(), "tcp://127.0.0.1:25353"),
	} {
		other, err := Render(config.Defaults(), elsewhere)
		if err != nil {
			t.Fatalf("Render with %s: %v", name, err)
		}
		if string(other) == string(first) {
			t.Errorf("%s is rendered nowhere in the document", name)
		}
	}
}

// TestCommittedMosdnsConfigIsExactlyTheRenderedDefault proves the shipped
// configs/mosdns.yaml is the output of the renderer for the shipped policy and
// the production paths. The break it catches is hand-editing the file mosdns is
// started with away from what this project believes it deploys.
func TestCommittedMosdnsConfigIsExactlyTheRenderedDefault(t *testing.T) {
	rendered, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render(config.Defaults(), ProductionPaths()): %v", err)
	}
	updateCommitted(t, committedMosdnsConfig, rendered)

	committed, err := os.ReadFile(filepath.Clean(committedMosdnsConfig))
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", committedMosdnsConfig, err)
	}
	if string(committed) != string(rendered) {
		t.Errorf("%s is not the output of Render(config.Defaults(), ProductionPaths())\n--- committed ---\n%s\n--- rendered ---\n%s", committedMosdnsConfig, committed, rendered)
	}
}

// updateCommitted rewrites a committed file from the code that produces it, so
// the bytes in the repository are never hand-edited. Set MOSDNS_ROUTER_UPDATE=1
// to regenerate them; without it this does nothing and the comparison stands.
func updateCommitted(t *testing.T, path string, want []byte) {
	t.Helper()
	if os.Getenv("MOSDNS_ROUTER_UPDATE") == "" {
		return
	}
	if err := os.WriteFile(filepath.Clean(path), want, 0o644); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
	t.Logf("rewrote %s from Render", path)
}

// TestTheForeignListenerIsWhereTheCommittedDNSCryptProxyListens ties the two
// committed documents together. MOSDNS forwards foreign queries to an address
// this project chose, and the resolver that has to be listening there is
// configured by a file this project also generated; if one moves and the other
// does not, every foreign query goes to a closed port and no test of either file
// alone would notice.
func TestTheForeignListenerIsWhereTheCommittedDNSCryptProxyListens(t *testing.T) {
	var resolver struct {
		ListenAddresses []string `toml:"listen_addresses"`
	}
	if _, err := toml.DecodeFile(filepath.Clean(committedDNSCryptTOML), &resolver); err != nil {
		t.Fatalf("cannot decode the committed %s: %v", committedDNSCryptTOML, err)
	}
	if len(resolver.ListenAddresses) != 1 {
		t.Fatalf("the committed resolver listens on %v, want exactly one address", resolver.ListenAddresses)
	}

	rendered, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, rendered)
	forward := argsOf[renderedForward](t, parsed.entry(t, "foreign_forward"))
	if got, want := forward.Upstreams[0].Addr, "tcp://"+resolver.ListenAddresses[0]; got != want {
		t.Fatalf("the foreign forward enters %q, but the committed resolver listens on %q", got, resolver.ListenAddresses[0])
	}
	if _, port, err := net.SplitHostPort(resolver.ListenAddresses[0]); err != nil || port == "53" {
		t.Errorf("the committed resolver listens on port %q, want a port that is not the system resolver's 53", port)
	}
}

// TestNoAddressButLoopbackIsCommitted proves the committed routing file names no
// user-specific address. The list and the state document carry the addresses, and
// a repository that named one of them would ship a machine's network to everyone
// who cloned it.
func TestNoAddressButLoopbackIsCommitted(t *testing.T) {
	committed, err := os.ReadFile(filepath.Clean(committedMosdnsConfig))
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", committedMosdnsConfig, err)
	}
	for _, address := range ipv4Address.FindAllString(string(committed), -1) {
		if address != "127.0.0.1" {
			t.Errorf("the committed %s names %s, want only the loopback 127.0.0.1", committedMosdnsConfig, address)
		}
	}
}

// TestRenderedConfigLoadsInAMosdnsInstance is the load proof: the rendered
// document is decoded the way the router's own start command decodes a file,
// handed to a real mosdns instance, and queried over real sockets. Every other
// test in this file reads bytes.
func TestRenderedConfigLoadsInAMosdnsInstance(t *testing.T) {
	temporary := t.TempDir()

	// The China list is the committed one, copied: a list that does not load
	// would fail the instance, and an empty one would send every name abroad.
	committedList, err := os.ReadFile(filepath.Clean(committedCNList))
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", committedCNList, err)
	}
	cnList := filepath.Join(temporary, "cn-domains.txt")
	if err := os.WriteFile(cnList, committedList, 0o600); err != nil {
		t.Fatalf("copy the China list: %v", err)
	}

	// The state document is a valid one that names no resolver. That is the
	// fail-closed state the bridge publishes when it cannot vouch for a set, so
	// the domestic branch answers without a network and the test stays
	// hermetic while still going through the production state decoder.
	stateFile := filepath.Join(temporary, "dhcp-upstreams.json")
	published, err := json.Marshal(state.NewDHCPState(1, "enp3s0", "connection-uuid", nil, time.Unix(1750000000, 0).UTC(), "dhcp4", false))
	if err != nil {
		t.Fatalf("encode the state document: %v", err)
	}
	if err := os.WriteFile(stateFile, published, 0o600); err != nil {
		t.Fatalf("write the state document: %v", err)
	}

	// The foreign listener is a real loopback DNS server, and the router's own
	// listeners take a port nothing else holds.
	foreign := startForeignMock(t)
	listen := freeLoopbackPort(t)
	document, err := Render(config.Defaults(), Paths{
		Policy:          "/etc/mosdns/policy.yaml",
		CNDomains:       cnList,
		DHCPState:       stateFile,
		ForeignListener: "tcp://" + foreign.Address(),
		Listen:          net.JoinHostPort("127.0.0.1", listen),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	instance := loadMosdns(t, document)
	listenAddress := net.JoinHostPort("127.0.0.1", listen)

	// A name the committed list matches must not reach the foreign resolver.
	// The domestic branch is disabled, so the query fails closed here, and a
	// query that were forwarded anyway would show up in the mock's count.
	domestic := ask(t, listenAddress, chinaDomain)
	if domestic.Rcode != dns.RcodeServerFailure {
		t.Errorf("%s over the rendered config = %s, want SERVFAIL: the domestic branch is disabled and fails closed",
			chinaDomain, dns.RcodeToString[domestic.Rcode])
	}
	if count := foreign.Count("", chinaDomain); count != 0 {
		t.Errorf("the foreign resolver received %d queries for %s, want 0", count, chinaDomain)
	}

	// Every other name goes to the foreign resolver, over TCP, and is answered.
	foreignResponse := ask(t, listenAddress, foreignDomain)
	if got := addressesIn(t, foreignResponse); len(got) != 1 || got[0] != "203.0.113.10" {
		t.Errorf("%s over the rendered config = %v, want the mock's answer [203.0.113.10]", foreignDomain, got)
	}
	if count := foreign.Count(testdns.ProtocolTCP, foreignDomain); count != 1 {
		t.Errorf("the foreign resolver received %d queries for %s over tcp, want 1: the forward is a tcp:// upstream", count, foreignDomain)
	}
	if count := foreign.Count(testdns.ProtocolUDP, foreignDomain); count != 0 {
		t.Errorf("the foreign resolver received %d queries for %s over udp, want 0", count, foreignDomain)
	}

	// Asking again is answered by the foreign cache, and the resolver is not
	// asked twice. The cache plugin always runs the rules after it, so this only
	// holds because the branch ends on has_resp: without that check a cache hit
	// would be forwarded as well and the cache would save nothing.
	if got := addressesIn(t, ask(t, listenAddress, foreignDomain)); len(got) != 1 || got[0] != "203.0.113.10" {
		t.Errorf("the repeated %s = %v, want the cached answer [203.0.113.10]", foreignDomain, got)
	}
	if count := foreign.Count("", foreignDomain); count != 1 {
		t.Errorf("the foreign resolver received %d queries for %s in total, want 1: the second must come from the cache", count, foreignDomain)
	}

	instance.CloseWithErr(nil)
	_ = instance.GetSafeClose().WaitClosed()
}

// loadMosdns hands the rendered document to a real mosdns instance, decoded the
// way the router's own start command decodes a file.
func loadMosdns(t *testing.T, document []byte) *coremain.Mosdns {
	t.Helper()
	var loaded coremain.Config
	decoder := yaml.NewDecoder(strings.NewReader(string(document)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&loaded); err != nil {
		t.Fatalf("the rendered document does not decode as a mosdns configuration: %v\n%s", err, document)
	}
	// The rendered level is the shipped one; this test lowers it so the
	// instance's own per-query reports do not fill the test output.
	loaded.Log = mlog.LogConfig{Level: "error"}

	instance, err := coremain.NewMosdns(&loaded)
	if err != nil {
		t.Fatalf("mosdns refused the rendered configuration: %v\n%s", err, document)
	}
	t.Cleanup(func() {
		instance.CloseWithErr(nil)
		_ = instance.GetSafeClose().WaitClosed()
	})
	return instance
}

// startForeignMock is the resolver the foreign path is pointed at.
func startForeignMock(t *testing.T) *testdns.Server {
	t.Helper()
	server, err := testdns.Start(func(_ context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.ParseIP("203.0.113.10").To4(),
		})
		return response
	})
	if err != nil {
		t.Fatalf("start the foreign resolver mock: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

// freeLoopbackPort returns a port that is free on both transports right now. The
// servers bind it inside this process, so the port has to be given up first.
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a udp port: %v", err)
	}
	address := packetConn.LocalAddr().String()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("reserve a tcp port: %v", err)
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split %q: %v", address, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("release the tcp port: %v", err)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatalf("release the udp port: %v", err)
	}
	return port
}

// ask sends one query to a listener and returns the answer, waiting for the
// listener to come up: a query that arrives before the read loop starts is
// dropped by the socket rather than answered.
func ask(t *testing.T, address, name string) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}

	var lastErr error
	for range 20 {
		response, _, err := client.Exchange(query, address)
		if err == nil {
			return response
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no answer for %s from %s after 20 attempts: %v", name, address, lastErr)
	return nil
}

func addressesIn(t *testing.T, response *dns.Msg) []string {
	t.Helper()
	addresses := make([]string, 0, len(response.Answer))
	for _, record := range response.Answer {
		address, ok := record.(*dns.A)
		if !ok {
			t.Fatalf("answer %v is not an A record", record)
		}
		addresses = append(addresses, address.A.String())
	}
	return addresses
}

func equalTags(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func equalRules(got, want []renderedRule) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index].Exec != want[index].Exec || len(got[index].Matches) != len(want[index].Matches) {
			return false
		}
		for position := range want[index].Matches {
			if got[index].Matches[position] != want[index].Matches[position] {
				return false
			}
		}
	}
	return true
}

func withPolicy(paths Paths, value string) Paths {
	paths.Policy = value
	return paths
}

func withCNDomains(paths Paths, value string) Paths {
	paths.CNDomains = value
	return paths
}

func withDHCPState(paths Paths, value string) Paths {
	paths.DHCPState = value
	return paths
}

func withForeignListener(paths Paths, value string) Paths {
	paths.ForeignListener = value
	return paths
}

func withListen(paths Paths, value string) Paths {
	paths.Listen = value
	return paths
}

func withoutPolicy(paths Paths) Paths {
	return withPolicy(paths, "")
}

func withoutCNDomains(paths Paths) Paths {
	return withCNDomains(paths, "")
}

func withoutDHCPState(paths Paths) Paths {
	return withDHCPState(paths, "")
}

func withoutForeignListener(paths Paths) Paths {
	return withForeignListener(paths, "")
}

func withoutListen(paths Paths) Paths {
	return withListen(paths, "")
}
