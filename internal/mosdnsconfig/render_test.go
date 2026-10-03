package mosdnsconfig

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/dnscrypt"
	"mosdns-router/internal/optimizer"
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
	// API is decoded here rather than being left out of the type on purpose: the
	// decoder is a KnownFields one, so a document that grows an `api` block while
	// this type has no field for it would fail to decode -- which is the decoder
	// doing its job, and the reason the field has to be added rather than the test
	// relaxed.
	API renderedAPI `yaml:"api"`
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

// ttlBlock is the clamp's argument set. Both keys are optional in the document, so
// this type says nothing about which ones are present -- which is the point of
// checking the VALUES rather than the keys.
type ttlBlock struct {
	Max uint32 `yaml:"max"`
	Min uint32 `yaml:"min"`
}

type renderedCache struct {
	Size     int    `yaml:"size"`
	DumpFile string `yaml:"dump_file"`
}

// renderedCDNRewrite is the response rewriter's own argument set, decoded into
// this test's type rather than the plugin's, so a renderer that got a key or a
// value wrong cannot be agreed with by a test that reuses the plugin's structures.
type renderedCDNRewrite struct {
	PolicyFile         string `yaml:"policy_file"`
	SelectorFile       string `yaml:"selector_file"`
	ForceECHFile       string `yaml:"force_ech_file"`
	ECHStateFile       string `yaml:"ech_state_file"`
	ForeignUpstream    string `yaml:"foreign_upstream"`
	CloudflareCIDRFile string `yaml:"cloudflare_cidr_file"`
}

// renderedForward is the foreign forward's argument set, decoded into this test's
// own type. Bootstrap is here because an entry's bootstrap is rendered into the
// document and nothing else in the tests would notice its absence.
type renderedForward struct {
	Concurrent int `yaml:"concurrent"`
	Upstreams  []struct {
		Addr      string `yaml:"addr"`
		Bootstrap string `yaml:"bootstrap"`
	} `yaml:"upstreams"`
}

// renderedAPI is the document's api block. It is a separate type from `rendered`
// only because a missing block and an empty one have to be told apart, and a
// missing block decodes to the zero value of a missing field.
type renderedAPI struct {
	HTTP string `yaml:"http"`
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
		{"cdn_rewrite", "cdn_rewrite"},
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
		t.Error("the document states no log level, so the level the router runs at is whatever the logger's zero value happens to be")
	}
}

// TestCNDispatchRunsBeforeTheForeignDefault covers the one routing decision the
// whole project turns on: a name the China list matches goes to the DHCP branch,
// and every other name goes to the foreign branch. The order is the routing, so
// a reversed pair of rules would send China names abroad and never fail.
//
// Both rules are jumps, not calls. `exec: $cn_path` would *call* the sequence
// and then resume main at the next rule, so a domestic answer would be carried
// into the foreign branch and could be replaced there; `goto` abandons the
// parent chain, which is what makes "no foreign fallback" a property of the
// document rather than of an accidental response check further down.
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
		{Matches: []string{"qname $cn_domains"}, Exec: "goto cn_path"},
		{Exec: "goto foreign_path"},
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

// TestTheDialPortTheCallerChoseReachesThePlugin covers the one upstream address
// the renderer does not get to choose. A published state document carries bare
// addresses, so the port they are dialled on is a property of this document: a
// caller that pointed the plugin at a resolver on another port has to have that
// port rendered, or the plugin would dial 53 and the domestic branch would only
// work by accident.
func TestTheDialPortTheCallerChoseReachesThePlugin(t *testing.T) {
	document, err := Render(config.Defaults(), withDHCPUpstreamPort(ProductionPaths(), 15354))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	forwarder := argsOf[renderedDHCPForward](t, decodeRendered(t, document).entry(t, "dhcp_forward"))
	if forwarder.UpstreamPort != 15354 {
		t.Errorf("dhcp_forward upstream_port = %d, want the caller's 15354", forwarder.UpstreamPort)
	}
}

// TestAnUnsetDialPortRendersThePortADHCPResolverAnswersOn is the default. A
// caller that says nothing about the port has to get 53 rendered rather than a
// zero, because a zero is not a port: the plugin would refuse to dial it, and
// the domestic branch would be dead in a document that looked configured.
func TestAnUnsetDialPortRendersThePortADHCPResolverAnswersOn(t *testing.T) {
	document, err := Render(config.Defaults(), withDHCPUpstreamPort(ProductionPaths(), 0))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	forwarder := argsOf[renderedDHCPForward](t, decodeRendered(t, document).entry(t, "dhcp_forward"))
	if forwarder.UpstreamPort != 53 {
		t.Errorf("dhcp_forward upstream_port = %d, want 53: an unset dial port is the port a DHCP DNS server answers on", forwarder.UpstreamPort)
	}
}

// TestRenderRefusesADialPortNothingCanDial is the safety table for the new
// field. A port outside the range of a TCP or UDP port number is a document the
// plugin would refuse at load, or one it would dial into nothing, and both are
// worth a refusal here where the value can still be named. The control case is
// the two ends of the range, which are diallable and must keep rendering.
func TestRenderRefusesADialPortNothingCanDial(t *testing.T) {
	for name, testCase := range map[string]struct {
		port         int
		wantMention  string
		wantAccepted bool
	}{
		"a negative port":   {port: -1, wantMention: "-1"},
		"a port past 65535": {port: 65536, wantMention: "65536"},
		"the lowest port":   {port: 1, wantAccepted: true},
		"the highest port":  {port: 65535, wantAccepted: true},
	} {
		t.Run(name, func(t *testing.T) {
			document, err := Render(config.Defaults(), withDHCPUpstreamPort(ProductionPaths(), testCase.port))
			if testCase.wantAccepted {
				if err != nil {
					t.Fatalf("Render refused a diallable port %d: %v", testCase.port, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Render accepted upstream_port %d and wrote:\n%s", testCase.port, document)
			}
			if !strings.Contains(err.Error(), testCase.wantMention) {
				t.Errorf("the refusal %q does not name the offending port %q", err, testCase.wantMention)
			}
		})
	}
}

// TestTheDialPortRefusalSaysWhatZeroMeans covers the message rather than the
// range. 0 is accepted and rendered as 53, so a refusal that only says "must be
// between 1 and 65535" describes a range 0 is not outside of, and a reader who
// wrote upstream_port: 0 has no way to tell that from a value that was refused.
// The document this renderer produces is read by whoever set that field, so the
// two facts have to be in the message together.
func TestTheDialPortRefusalSaysWhatZeroMeans(t *testing.T) {
	_, err := Render(config.Defaults(), withDHCPUpstreamPort(ProductionPaths(), 65536))
	if err == nil {
		t.Fatal("Render accepted a port past 65535")
	}
	for name, want := range map[string]string{
		"the port it refused":  "65536",
		"that zero means 53":   "0 means the default 53",
		"the range it accepts": "between 1 and 65535",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %s (%q):\n%v", name, want, err)
		}
	}
	// And the value it accepts is still accepted: the message must not have
	// changed what 0 means.
	document, err := Render(config.Defaults(), withDHCPUpstreamPort(ProductionPaths(), 0))
	if err != nil {
		t.Fatalf("Render refused the port the message says means 53: %v", err)
	}
	if forwarder := argsOf[renderedDHCPForward](t, decodeRendered(t, document).entry(t, "dhcp_forward")); forwarder.UpstreamPort != 53 {
		t.Errorf("upstream_port 0 rendered as %d, want the 53 the refusal names", forwarder.UpstreamPort)
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
// five steps, and the second and third are the load-bearing ones. The cache is a
// recursive executable that always runs the rules after it, so a cache hit is only
// kept when a has_resp check ends the branch there; and the rewriter is ahead of
// the cache, so what it changes is a copy of what the cache hands back rather than
// the object the cache owns.
func TestForeignPathAnswersFromTheCacheBeforeItForwards(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	want := []renderedRule{
		{Exec: "$cdn_rewrite"},
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

// TestTheRewritePluginIsTheFirstExecutableOfTheForeignBranchAndOfNoOther is where
// the plugin's place in the document is decided, and both halves of it are the
// same claim. A name the China list matches is answered inside the network the
// user is not leaving, and this router does not rewrite answers there: an address
// installed in a domestic answer would be a claim about a network the domestic
// branch chose, made by a component that proved nothing about it. So the plugin
// appears in the foreign branch and in no other, exactly once, and the domestic
// sequence names the DHCP forwarder and nothing else.
//
// The break it catches is the plugin landing downstream of the cache, which is
// the order this file's foreign branch is written to prevent: the rewrite would
// then be applied to the object the cache owns and stored, pinning one selector
// generation's address for as long as the entry lived.
func TestTheRewritePluginIsTheFirstExecutableOfTheForeignBranchAndOfNoOther(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	parsed := decodeRendered(t, document)

	// entry fails unless the tag names exactly one plugin, so this is also the
	// assertion that the tag is not used twice.
	if got := parsed.entry(t, "cdn_rewrite").Type; got != "cdn_rewrite" {
		t.Errorf("the cdn_rewrite tag has type %q, want the plugin itself", got)
	}

	// The foreign branch's first rule is the plugin, before the cache it wraps.
	rules := rulesOf(t, parsed.entry(t, "foreign_path"))
	if len(rules) == 0 {
		t.Fatal("the foreign_path sequence has no rules")
	}
	if rules[0].Exec != "$cdn_rewrite" {
		t.Errorf("the first rule of foreign_path is %q, want the rewrite plugin ahead of the cache it wraps", rules[0].Exec)
	}
	for index, rule := range rules {
		if rule.Exec == "$cdn_rewrite" && index != 0 {
			t.Errorf("foreign_path rule %d runs the rewrite plugin, want it once and first", index+1)
		}
	}

	// The domestic branch, which must be untouched by all of this.
	want := []renderedRule{{Exec: "$dhcp_forward"}, {Exec: "accept"}}
	if got := rulesOf(t, parsed.entry(t, "cn_path")); !equalRules(got, want) {
		t.Errorf("the cn_path sequence is\n got %+v\nwant %+v", got, want)
	}
	// And the dispatch itself must not run it either: a plugin reached from main
	// rather than from the foreign branch would see a China name as well.
	for index, rule := range rulesOf(t, parsed.entry(t, "main")) {
		if strings.Contains(rule.Exec, "cdn_rewrite") {
			t.Errorf("main rule %d runs the rewrite plugin (%q), want the rewrite confined to the foreign branch", index+1, rule.Exec)
		}
	}
}

// TestTheRewritePluginIsGivenEveryDocumentItReads covers the six arguments, one
// at a time, because the plugin refuses to start without any of them: a mistyped
// path is a router that classifies nothing and looks healthy, and the two files it
// writes (the ECH metadata document) or reads continuously (the selector, the
// allowlist, the range list) are each a document some other component of this
// project owns.
//
// The break it catches is a key this document does not write, a value written under
// the wrong key, or a path pointed at the wrong file -- and the last of those has a
// documented victim: the Cloudflare API cache envelope is a JSON document with the
// ranges inside it as quoted strings, so a cloudflare_cidr_file naming it is a
// plugin that refuses to load rather than one that classifies.
func TestTheRewritePluginIsGivenEveryDocumentItReads(t *testing.T) {
	document, err := Render(config.Defaults(), ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	rewriter := argsOf[renderedCDNRewrite](t, decodeRendered(t, document).entry(t, "cdn_rewrite"))

	for name, testCase := range map[string]struct{ got, want string }{
		"the policy it is configured by":       {rewriter.PolicyFile, "/etc/mosdns/policy.yaml"},
		"the published selector":               {rewriter.SelectorFile, "/var/lib/mosdns/runtime/cdn-selector.json"},
		"the operator's force-ECH allowlist":   {rewriter.ForceECHFile, "/etc/mosdns/force-ech-domains.txt"},
		"the ECH metadata it publishes":        {rewriter.ECHStateFile, "/var/lib/mosdns/runtime/ech-state.json"},
		"the direct ECH upstream":              {rewriter.ForeignUpstream, productionForeignListener},
		"the published Cloudflare prefix list": {rewriter.CloudflareCIDRFile, "/var/lib/mosdns/lists/cloudflare-prefixes.txt"},
	} {
		if testCase.got != testCase.want {
			t.Errorf("cdn_rewrite is given %s as %q, want %q", name, testCase.got, testCase.want)
		}
	}
}

// TestTheCommittedConfigNamesThePathsTheOtherComponentsPublish ties three of the
// six to the components that write the files, because a literal in this package and
// a constant in another can drift and nothing would notice: the document would
// name a file nothing publishes, and the plugin would serve with the last document
// it read, which is no document at all.
//
// The selector and the range list are checked against the constants their writers
// use. The allowlist has no exported constant -- the command that reads it is a
// main package -- so it is checked against the path this plan's own constraint
// fixes, and that is the whole of what the check is: two places spelling the same
// path is two places to fix it.
func TestTheCommittedConfigNamesThePathsTheOtherComponentsPublish(t *testing.T) {
	rewriter := argsOf[renderedCDNRewrite](t,
		decodeRendered(t, mustRender(t, ProductionPaths())).entry(t, "cdn_rewrite"))

	if want := optimizer.DefaultSelectorPath; rewriter.SelectorFile != want {
		t.Errorf("cdn_rewrite reads the selector at %q, but the optimizer publishes it at %q", rewriter.SelectorFile, want)
	}
	published := filepath.Join(filepath.Dir(candidate.DefaultCloudflareCachePath), candidate.DefaultCloudflarePrefixFileName)
	if rewriter.CloudflareCIDRFile != published {
		t.Errorf("cdn_rewrite reads the Cloudflare ranges from %q, but the fetch that publishes them writes %q", rewriter.CloudflareCIDRFile, published)
	}
	// And the envelope itself is not that file, which is the mistake this path
	// exists to prevent: the cache is a JSON document with a schema, a URL and an
	// etag, and the ranges inside it are strings in a nested object.
	if rewriter.CloudflareCIDRFile == candidate.DefaultCloudflareCachePath {
		t.Error("cdn_rewrite is pointed at the Cloudflare API cache envelope rather than the published prefix list beside it")
	}
	if want := "/etc/mosdns/force-ech-domains.txt"; rewriter.ForceECHFile != want {
		t.Errorf("cdn_rewrite reads the force-ECH allowlist at %q, want %q", rewriter.ForceECHFile, want)
	}
}

// TestTheECHKeyIsFetchedThroughTheSameListenerTheForeignBranchDials covers the
// transport the ECH fetch uses, and it is the one value in the plugin's arguments
// that is not a path. The key comes from the same resolver the foreign branch
// forwards to, and it has to come through the same tcp:// listener: mosdns's stock
// UDP upstream re-sends a query that has gone unanswered and can drop an answer that
// arrived before its exchange waited for it, and an ECH fetch is the one exchange on
// this path with no client watching it, so a lost query is a force-ECH name that
// fails closed for as long as the last key lasts.
//
// The two are one value, and the control case is the proof of it: move the listener
// and both the forward's upstream and the plugin's carry the new address. A renderer
// that gave the plugin its own literal would leave one of the two behind.
//
// **The forward may now carry SEVERAL upstreams while the ECH fetch still goes to
// one**, and this case had to be rewritten rather than deleted when that became true.
// The property it was written for -- "the two cannot disagree about where the
// resolver is" -- is still worth holding, and it now reads as: the ECH source is
// either the injected listener or one of the forward's own upstreams. What is NOT
// true any more is that it is the forward's only upstream, because the whole point
// of the route being a list is that it is not.
func TestTheECHKeyIsFetchedThroughTheSameListenerTheForeignBranchDials(t *testing.T) {
	for name, listener := range map[string]string{
		"the production listener":    "tcp://127.0.0.1:15353",
		"a listener on another port": "tcp://127.0.0.2:25353",
	} {
		t.Run(name, func(t *testing.T) {
			paths := withForeignListener(ProductionPaths(), listener)
			document := mustRender(t, paths)
			parsed := decodeRendered(t, document)

			forward := argsOf[renderedForward](t, parsed.entry(t, "foreign_forward"))
			if len(forward.Upstreams) == 0 {
				t.Fatal("the foreign forward names no upstream, so the foreign branch has nowhere to send a query")
			}
			rewriter := argsOf[renderedCDNRewrite](t, parsed.entry(t, "cdn_rewrite"))
			// The ECH source is reachable from the route: it is the injected
			// listener, or it is one of the addresses the forward actually dials.
			// An ECH source the forward never enters would be a resolver the
			// rewriter uses and the route does not -- which works right up until
			// the operator removes that entry and nothing says why ECH stopped.
			if rewriter.ForeignUpstream != listener && !containsAddr(forward, rewriter.ForeignUpstream) {
				t.Errorf("cdn_rewrite fetches ECH through %q, which the foreign forward does not "+
					"enter (it enters %v and was injected with %q): the rewriter would use a "+
					"resolver the route does not",
					rewriter.ForeignUpstream, forwardAddrs(forward), listener)
			}
			if !strings.HasPrefix(rewriter.ForeignUpstream, "tcp://") {
				t.Errorf("cdn_rewrite fetches ECH through %q, want a tcp:// URL: the UDP transport re-sends and drops answers", rewriter.ForeignUpstream)
			}
			address, err := netip.ParseAddrPort(strings.TrimPrefix(rewriter.ForeignUpstream, "tcp://"))
			if err != nil {
				t.Fatalf("the rendered ECH upstream %q is not an address and a port: %v", rewriter.ForeignUpstream, err)
			}
			if address.Port() == 53 {
				t.Error("cdn_rewrite fetches ECH through port 53, which belongs to the system resolver this router exists to keep out of foreign queries")
			}
		})
	}
}

// TestTheForeignForwardCarriesEveryEnabledEntryOverATCPTransport covers the
// transport and the list. It USED to be named ...UsesOnlyTheDNSCryptListener... and
// asserted a single upstream, and both of those are gone: the route is a policy
// list now, so "only" is the opposite of the property.
//
// What is kept, and what the name now says, is the part that is still true and
// still load-bearing:
//
//   - the packaged resolver IS entered, over tcp://, when its entry is on -- a
//     policy that leaves it on and renders a forward that never dials it is a
//     document that ignores the operator's own configuration;
//   - every enabled `upstream` entry becomes exactly one upstream, in policy order;
//   - the DNSCrypt listener comes from the dnscrypt package rather than a second
//     copy of the string, which is what makes the two documents agree by
//     construction instead of by two literals happening to agree today.
func TestTheForeignForwardCarriesEveryEnabledEntryOverATCPTransport(t *testing.T) {
	document := mustRenderPolicy(t, config.Defaults())
	parsed := decodeRendered(t, document)

	forward := argsOf[renderedForward](t, parsed.entry(t, tagForeignForward))
	// The expectation is DERIVED from the policy rather than written out, and it is
	// derived as the LIST the policy describes: the packaged listener when the
	// dnscrypt entry is on, then one address per enabled upstream entry. Writing
	// three literals here would be a second copy of the policy that could drift.
	var enabled []string
	for _, entry := range config.Defaults().Foreign.Upstreams {
		if entry.IsEnabled() && entry.Kind == config.UpstreamKindDNSCrypt {
			enabled = append(enabled, productionForeignListener)
			continue
		}
		if entry.IsEnabled() && entry.Kind == config.UpstreamKindUpstream {
			enabled = append(enabled, entry.Addr)
		}
	}
	got := forwardAddrs(forward)
	if len(got) != len(enabled) {
		t.Fatalf("the foreign forward carries %v, want one upstream per enabled upstream entry %v",
			got, enabled)
	}
	for index, addr := range enabled {
		if got[index] != addr {
			t.Fatalf("upstream %d is %q, want %q: the document's order is the policy's order",
				index, got[index], addr)
		}
	}
	// The packaged listener has to be one of them, because the dnscrypt entry is on
	// in the shipped policy and it is a process this route has to reach.
	if !containsAddr(forward, productionForeignListener) {
		t.Errorf("the foreign forward carries %v, none of them the packaged resolver %q, "+
			"so an enabled dnscrypt entry is not in the route", got, productionForeignListener)
	}
	// And the packaged listener is the dnscrypt package's own constant, so the two
	// documents cannot name different sockets.
	if want := "tcp://" + dnscrypt.ListenAddress; !containsAddr(forward, want) {
		t.Errorf("the foreign forward carries %v, none of them %q: this renderer holds a "+
			"second copy of the resolver's address", got, want)
	}
	for _, addr := range got {
		if strings.HasPrefix(addr, "udp://") {
			t.Errorf("the foreign upstream %q is udp, and the ECH fetch shares this branch: "+
				"mosdns's UDP transport re-sends an unanswered query and can drop an early answer",
				addr)
		}
	}
}

func containsAddr(forward renderedForward, addr string) bool {
	for _, upstream := range forward.Upstreams {
		if upstream.Addr == addr {
			return true
		}
	}
	return false
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
		"no listen address":              {withoutListen(ProductionPaths()), "must not be empty"},
		"no selector path":               {withoutSelector(ProductionPaths()), "must not be empty"},
		"no force-ECH allowlist":         {withoutForceECH(ProductionPaths()), "must not be empty"},
		"no ECH state path":              {withoutECHState(ProductionPaths()), "must not be empty"},
		"no Cloudflare prefix list":      {withoutCloudflarePrefixes(ProductionPaths()), "must not be empty"},
		"a relative selector":            {withSelector(ProductionPaths(), "runtime/cdn-selector.json"), "runtime/cdn-selector.json"},
		"a relative ECH state document":  {withECHState(ProductionPaths(), "runtime/ech-state.json"), "runtime/ech-state.json"},
		"a relative prefix list":         {withCloudflarePrefixes(ProductionPaths(), "lists/cloudflare-prefixes.txt"), "lists/cloudflare-prefixes.txt"},
		"a relative force-ECH allowlist": {withForceECH(ProductionPaths(), "mosdns/force-ech-domains.txt"), "mosdns/force-ech-domains.txt"},
		"a selector under etc":           {withSelector(ProductionPaths(), "/etc/mosdns/cdn-selector.json"), "/etc/mosdns/cdn-selector.json"},
		"an ECH state document under etc": {
			withECHState(ProductionPaths(), "/etc/mosdns/ech-state.json"), "/etc/mosdns/ech-state.json",
		},
		"a prefix list under etc": {
			withCloudflarePrefixes(ProductionPaths(), "/etc/mosdns/cloudflare-prefixes.txt"), "/etc/mosdns/cloudflare-prefixes.txt",
		},
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
		"a prefix list named after a Chinese resolver": {
			// The same scan, through the one of the four new paths an operator is
			// most likely to fill in from a resolver's address.
			withCloudflarePrefixes(ProductionPaths(), "/var/lib/mosdns/lists/223.5.5.5.txt"),
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

// TestTheForceECHCallowlistMayLiveUnderEtc is the control for the four refusals
// above that are about /etc, and the reason they are not a fifth. The allowlist is
// written by an operator and replaced by packaging, so /etc/mosdns is exactly where
// it belongs; the other three are rewritten while the router runs, and a rule the
// router cannot replace under a root-owned configuration directory is a rule that
// survives an upgrade nobody meant to keep it.
//
// The break it catches is the /etc refusal generalised to a file it does not apply
// to, which would refuse every document that names a path this plan's own global
// constraint fixes at /etc/mosdns/force-ech-domains.txt.
func TestTheForceECHCallowlistMayLiveUnderEtc(t *testing.T) {
	document, err := Render(config.Defaults(), withForceECH(ProductionPaths(), "/etc/mosdns/force-ech-domains.txt"))
	if err != nil {
		t.Fatalf("Render refused the operator's own allowlist under /etc: %v", err)
	}
	rewriter := argsOf[renderedCDNRewrite](t, decodeRendered(t, document).entry(t, "cdn_rewrite"))
	if rewriter.ForceECHFile != "/etc/mosdns/force-ech-domains.txt" {
		t.Errorf("cdn_rewrite reads the allowlist at %q, want the path the caller chose", rewriter.ForceECHFile)
	}
}

// TestTheRenderedConfigRefusesToLoadWithoutAPrefixList is the load-time proof of
// the file the renderer points the plugin at, and it is the reason the renderer
// carries a field for it at all.
//
// What a run of the Cloudflare fetch caches is the API's own JSON: a schema
// version, the URL it came from, an etag, and the document as a string. A
// cloudflare_cidr_file naming that file is a plugin whose range list holds no
// prefix, and this release refuses to start over one -- correctly, because a
// classification with no argument classifies every response as somebody else's and
// stops every rewrite in the router while the router looks healthy. So the refusal
// is asserted here, on the real loader, rather than being assumed: a renderer that
// pointed the plugin at the envelope would produce a document no installed router
// could start, and no test that only read bytes would have said so.
func TestTheRenderedConfigRefusesToLoadWithoutAPrefixList(t *testing.T) {
	directory := t.TempDir()
	envelope := filepath.Join(directory, "cloudflare-ips.json")
	// The shape a run of the fetch leaves behind: a schema, a URL, an etag, and
	// the document as a string rather than as ranges.
	published := `{"schema_version":1,"url":"https://example.invalid/ips-v4","etag":"W/\"abc\"",` +
		`"body":"{\"result\":{\"ipv4_cidrs\":[\"104.16.0.0/13\"],\"etag\":\"x\"}}"}`
	if err := os.WriteFile(envelope, []byte(published), 0o600); err != nil {
		t.Fatalf("write the cache envelope: %v", err)
	}
	prefixesOnly, _ := temporaryPaths(t, "tcp://127.0.0.1:15353")
	paths := withCloudflarePrefixes(prefixesOnly, envelope)
	// A literal listen address, because nothing binds it: this case is about the
	// loader refusing, and reserving a free port for a process that must not start
	// would make a case about a refusal depend on the port allocator.
	paths.Listen = "127.0.0.1:15354"

	document, err := Render(config.Defaults(), paths)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	loaded := decodeMosdnsConfig(t, document)
	instance, err := coremain.NewMosdns(loaded)
	if err == nil {
		instance.CloseWithErr(nil)
		_ = instance.GetSafeClose().WaitClosed()
		t.Fatal("a configuration whose cloudflare_cidr_file is the API cache envelope loaded, so the plugin would classify every response as somebody else's")
	}
	// The refusal has to name the file, because an operator who is told only that
	// a plugin refused has no idea which of the six arguments to look at. It does
	// not name the ARGUMENT: the plugin reports the path it could not read, which
	// is the value the operator has to change, and the six arguments are one per
	// path in the document.
	for _, want := range []string{envelope, "is not a prefix"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
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

// TestRenderRefusesListenersThatWouldCollide covers the one thing two addresses
// in this document must never both be. The router binds the listen address and
// dials the foreign listener, so a document where the two are the same endpoint
// is a router that cannot bind, or binds the port its own foreign branch
// forwards to. The two control cases keep the shipped shape -- both endpoints on
// 127.0.0.1, on different ports, and the same port on two loopback addresses --
// rendering.
func TestRenderRefusesListenersThatWouldCollide(t *testing.T) {
	for name, testCase := range map[string]struct {
		paths Paths
		// wantRefusal is what has to be named, so a refusal raised by some other
		// check cannot stand in for the collision check.
		wantRefusal string
	}{
		"the router would bind the resolver's own address": {
			withListen(withForeignListener(ProductionPaths(), "tcp://127.0.0.1:15353"), "127.0.0.1:15353"),
			"127.0.0.1:15353",
		},
		"the resolver is named by address and the router binds the same one": {
			// A port nothing else refuses, so the collision is the only reason
			// left to refuse it.
			withListen(withForeignListener(ProductionPaths(), "tcp://127.0.0.2:25353"), "127.0.0.2:25353"),
			"127.0.0.2:25353",
		},
		// The control: the shipped document has both on 127.0.0.1, on different
		// ports, and must keep rendering.
		"two ports on the same address": {
			withListen(withForeignListener(ProductionPaths(), "tcp://127.0.0.1:15353"), "127.0.0.1:53"),
			"",
		},
		"one port on two loopback addresses": {
			withListen(withForeignListener(ProductionPaths(), "tcp://127.0.0.2:15353"), "127.0.0.1:15353"),
			"",
		},
	} {
		t.Run(name, func(t *testing.T) {
			document, err := Render(config.Defaults(), testCase.paths)
			if testCase.wantRefusal == "" {
				if err != nil {
					t.Fatalf("Render refused a document with two different endpoints: %v", err)
				}
				if len(document) == 0 {
					t.Fatal("Render wrote nothing")
				}
				return
			}
			if err == nil {
				t.Fatalf("Render accepted listeners that are the same address and wrote:\n%s", document)
			}
			if !strings.Contains(err.Error(), testCase.wantRefusal) {
				t.Errorf("the refusal %q does not name the colliding address %q", err, testCase.wantRefusal)
			}
		})
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
		"the selector path":    withSelector(ProductionPaths(), "/var/lib/mosdns/runtime/other.json"),
		"the force-ECH list":   withForceECH(ProductionPaths(), "/etc/mosdns/other-domains.txt"),
		"the ECH state path":   withECHState(ProductionPaths(), "/var/lib/mosdns/runtime/other-ech.json"),
		"the prefix list path": withCloudflarePrefixes(ProductionPaths(), "/var/lib/mosdns/lists/other-prefixes.txt"),
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

// TestNoMachineLocalAddressIsCommitted proves the committed routing file names no
// user-specific address. The list and the state document carry the addresses, and
// a repository that named one of them would ship a machine's network to everyone
// who cloned it.
//
// **The rule was "loopback only" and it is now "loopback, or a published public
// resolver".** `foreign.upstreams[].bootstrap` puts an address in this document for
// the first time: a domain upstream has to be told where to resolve its own name,
// because the machine's only resolver is the router. The default is Quad9's
// published 9.9.9.9, which identifies nothing about the machine.
//
// So the property is not "every address is loopback" -- it is "every address is one
// this package chose deliberately". That is the same inversion the policy's own
// address gate needed (internal/config/marshal_test.go), and it is the stronger
// claim: a LAN resolver or a DHCP-discovered nameserver in a bootstrap is refused
// here, where the old rule would have refused Quad9 too.
func TestNoMachineLocalAddressIsCommitted(t *testing.T) {
	committed, err := os.ReadFile(filepath.Clean(committedMosdnsConfig))
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", committedMosdnsConfig, err)
	}
	// The closed set this document may name. Loopback is this machine's own; the
	// Quad9 address is published by Quad9 and is the only non-loopback bootstrap the
	// shipped policy uses. A denylist could not be used here: it cannot know an
	// address nobody has written down, and the failure this guards against is
	// precisely an address somebody's own network contributed.
	allowed := map[string]bool{"127.0.0.1": true, "9.9.9.9": true}
	for _, address := range ipv4Address.FindAllString(string(committed), -1) {
		if !allowed[address] {
			t.Errorf("the committed %s names %s, which is neither loopback nor one of the "+
				"published resolvers %v this package is allowed to configure: a bootstrap "+
				"pointing into somebody's own network would ship that network to every clone",
				committedMosdnsConfig, address, allowed)
		}
	}
	// And the set is closed, so adding a fourth kind of address to the shipped
	// document has to be a decision somebody wrote down here.
	if !allowed["127.0.0.1"] || !allowed["9.9.9.9"] {
		t.Fatal("the allowed set no longer contains what the shipped document uses; the set " +
			"and the document have drifted and one of them is wrong")
	}
}

// TestRenderedConfigLoadsInAMosdnsInstance is the load proof: the rendered
// document is decoded the way the router's own start command decodes a file,
// handed to a real mosdns instance, and queried over real sockets. Every other
// test in this file reads bytes.
func TestRenderedConfigLoadsInAMosdnsInstance(t *testing.T) {
	foreign := startForeignMock(t)
	paths, listenAddress := temporaryPaths(t, "tcp://"+foreign.Address())

	document, err := Render(mockRoute(paths.ForeignListener), paths)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	instance := loadMosdns(t, decodeMosdnsConfig(t, document))

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
	// The count is the ROUTE's count, not one upstream's: `concurrent: 2` asks two
	// upstreams for every uncached query, and this test's two entries are the same
	// mock, so one client query is two upstream queries. It was `want 1` before the
	// route became a list, and `want 1` was the assertion that said "one upstream".
	//
	// What is still held here, and is the part worth holding, is the transport: TCP
	// only, and never UDP. A udp:// upstream in the list would be routable and
	// would break the ECH fetch, which shares this branch.
	// mosdns picks `concurrent` upstreams out of the list, starting at a random
	// offset (forward.go:265-267). Two upstreams and concurrent 2 means it picks
	// both, whichever offset it starts from -- so the count is `concurrent`, not
	// len(upstreams) times concurrent.
	concurrent := config.Defaults().Foreign.Concurrent
	if len(config.Defaults().Foreign.Upstreams) < concurrent {
		t.Fatalf("this case needs at least `concurrent` upstreams; the default route has %d and "+
			"concurrent is %d", len(config.Defaults().Foreign.Upstreams), concurrent)
	}
	raced := concurrent
	if count := foreign.Count(testdns.ProtocolTCP, foreignDomain); count != raced {
		t.Errorf("the foreign resolver received %d queries for %s over tcp, want %d: one per racer "+
			"per upstream for concurrent=%d", count, foreignDomain, raced, concurrent)
	}
	if count := foreign.Count(testdns.ProtocolUDP, foreignDomain); count != 0 {
		t.Errorf("the foreign resolver received %d queries for %s over udp, want 0: the UDP transport "+
			"re-sends an unanswered query and can drop an early answer, and the ECH fetch shares this branch",
			count, foreignDomain)
	}

	// Asking again is answered by the foreign cache, and the resolver is not
	// asked twice. The cache plugin always runs the rules after it, so this only
	// holds because the branch ends on has_resp: without that check a cache hit
	// would be forwarded as well and the cache would save nothing. That check is
	// the cache-hit guard and nothing else; what keeps a China name out of this
	// branch is the jump out of main.
	if got := addressesIn(t, ask(t, listenAddress, foreignDomain)); len(got) != 1 || got[0] != "203.0.113.10" {
		t.Errorf("the repeated %s = %v, want the cached answer [203.0.113.10]", foreignDomain, got)
	}
	if count := foreign.Count("", foreignDomain); count != raced {
		t.Errorf("the foreign resolver received %d queries for %s in total, want %d: the repeated query "+
			"must come from the cache and add NO upstream query at all", count, foreignDomain, raced)
	}

	instance.CloseWithErr(nil)
	_ = instance.GetSafeClose().WaitClosed()
}

// TestASuccessfulDomesticAnswerIsNeverReplacedByTheForeignCache is the routing
// defect this document is built to avoid, and it is invisible to a structural
// test: `exec: $cn_path` *calls* the domestic sequence and then resumes main at
// the next rule, so a fresh domestic answer is carried into the foreign branch.
// The foreign cache is not generation-scoped, and it overwrites a response it
// already holds, so from the second query on a China name would be answered with
// the previous domestic answer while the fresh one was fetched and discarded.
//
// The router's own plugin cannot be driven from a test, because the production
// state decoder refuses the loopback address a mock listens on. So the document
// is rendered for real and only the `dhcp_forward` entry is swapped for a
// `forward` at a loopback mock. The swap replaces one decoded entry and touches
// nothing else, so the sequences under test -- main, cn_path, foreign_path,
// foreign_cache and the dispatch between them -- are the ones this renderer
// writes, and the mock answers a different address on every call so a stale
// answer cannot be mistaken for a fresh one.
func TestASuccessfulDomesticAnswerIsNeverReplacedByTheForeignCache(t *testing.T) {
	foreign := startForeignMock(t)
	domestic := startDomesticMock(t)
	paths, listenAddress := temporaryPaths(t, "tcp://"+foreign.Address())

	document, err := Render(mockRoute(paths.ForeignListener), paths)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	instance := loadMosdns(t, swapPlugin(t, document, "dhcp_forward", coremain.PluginConfig{
		Tag:  "dhcp_forward",
		Type: "forward",
		// TCP, so one exchange is one query: the stock UDP upstream re-sends a
		// query it has not heard back from, and a re-send would shift which
		// answer belongs to which call.
		Args: map[string]any{"upstreams": []any{map[string]any{"addr": "tcp://" + domestic.Address()}}},
	}))

	// The same China name three times, which is what makes the foreign cache a
	// cache hit: one question, one key, three answers. If the domestic answer
	// ever reaches the foreign cache, the second and third queries come back with
	// the first one.
	var answers []string
	for attempt := range 3 {
		answers = append(answers, addressesIn(t, ask(t, listenAddress, chinaDomain))...)
		if got := foreign.Count("", chinaDomain); got != 0 {
			t.Fatalf("after %d queries the foreign resolver had received %d for %s, want none: a China name must never be forwarded abroad",
				attempt+1, got, chinaDomain)
		}
	}
	want := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	if !equalStrings(answers, want) {
		t.Fatalf("three %s answers = %v, want %v: every query must be answered from the domestic upstream", chinaDomain, answers, want)
	}
	if got := domestic.Count("", chinaDomain); got != 3 {
		t.Errorf("the domestic upstream received %d queries for %s, want 3: the later queries came from somewhere else", got, chinaDomain)
	}
	if got := foreign.Count("", ""); got != 0 {
		t.Errorf("the foreign resolver received %d queries in total, want none", got)
	}

	instance.CloseWithErr(nil)
	_ = instance.GetSafeClose().WaitClosed()
}

// temporaryPaths builds a path set a test can load: the committed China list in
// a temporary directory, a valid state document, the four documents the response
// rewriter reads, a foreign listener on the caller's mock, and a listen address
// whose port nothing else holds. The state document names no resolver, which is
// the fail-closed state the bridge publishes when it cannot vouch for a set, so a
// test that runs the real domestic plugin answers without a network.
//
// The rewriter's files are written rather than pointed at, because the plugin
// refuses to start without a readable range list and reads its policy at
// construction: a document naming a path nothing wrote is a document no real
// mosdns could load, and a test that proved the sequences worked around an
// unstartable document would be proving nothing. The selector is disabled and the
// allowlist is a comment, so a test that is not about the rewrite gets a plugin
// that starts and changes nothing.
// mockRoute is the foreign route every router-starting test in this file uses.
//
// **It replaced config.Defaults()'s own upstreams, and that was not optional.** The
// shipped policy names `quic://dns.quad9.net:853`, and a test that starts a real
// mosdns with it asks the real internet -- which is a test that fails on a machine
// without a route, takes five seconds per query while it does, and proves nothing
// about the router.
//
// Two entries rather than one, deliberately: the shipped route races two upstreams
// and these tests must exercise that shape or `concurrent: 2` is untested. The
// second is the SAME mock, so the race is real (two queries, two answers) without a
// second dependency on the network. No bootstrap, because the mock is given by IP.
func mockRoute(foreignListener string) config.Policy {
	policy := config.Defaults()
	policy.Foreign.Upstreams = []config.ForeignUpstream{
		{Kind: config.UpstreamKindDNSCrypt, Name: "mock-resolver"},
		{
			Kind: config.UpstreamKindUpstream,
			Name: "mock-second",
			Addr: foreignListener,
		},
	}
	return policy
}

func temporaryPaths(t *testing.T, foreignListener string) (Paths, string) {
	t.Helper()
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

	stateFile := filepath.Join(temporary, "dhcp-upstreams.json")
	published, err := json.Marshal(state.NewDHCPState(1, "enp3s0", "connection-uuid", nil, time.Unix(1750000000, 0).UTC(), "dhcp4", false))
	if err != nil {
		t.Fatalf("encode the state document: %v", err)
	}
	if err := os.WriteFile(stateFile, published, 0o600); err != nil {
		t.Fatalf("write the state document: %v", err)
	}

	policyFile := filepath.Join(temporary, "policy.yaml")
	policy, err := config.Marshal(config.Defaults())
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	if err := os.WriteFile(policyFile, policy, 0o600); err != nil {
		t.Fatalf("write the policy: %v", err)
	}

	selectorFile := filepath.Join(temporary, "cdn-selector.json")
	disabled := state.NewSelector(0, "disabled", "cloudflare", time.Unix(0, 0).UTC())
	if err := state.WriteJSONAtomic(selectorFile, disabled); err != nil {
		t.Fatalf("write the disabled selector: %v", err)
	}

	allowlist := filepath.Join(temporary, "force-ech-domains.txt")
	if err := os.WriteFile(allowlist, []byte("# no domain is forced in this document\n"), 0o600); err != nil {
		t.Fatalf("write the allowlist: %v", err)
	}

	prefixes := filepath.Join(temporary, "cloudflare-prefixes.txt")
	if err := os.WriteFile(prefixes, []byte("104.16.0.0/13\n"), 0o600); err != nil {
		t.Fatalf("write the Cloudflare prefix list: %v", err)
	}

	listenAddress := net.JoinHostPort("127.0.0.1", freeLoopbackPort(t))
	return Paths{
		Policy:             policyFile,
		Selector:           selectorFile,
		ForceECH:           allowlist,
		ECHState:           filepath.Join(temporary, "ech-state.json"),
		CNDomains:          cnList,
		CloudflarePrefixes: prefixes,
		DHCPState:          stateFile,
		ForeignListener:    foreignListener,
		Listen:             listenAddress,
	}, listenAddress
}

// mustRender renders a document for a path set that is expected to be renderable,
// and fails the test with the document if it is not. It is the one place a test
// that is about something other than a refusal stops repeating the same four
// lines.
func mustRender(t *testing.T, paths Paths) []byte {
	t.Helper()
	document, err := Render(config.Defaults(), paths)
	if err != nil {
		t.Fatalf("Render(%+v): %v", paths, err)
	}
	return document
}

// decodeMosdnsConfig decodes a rendered document the way the router's own start
// command decodes a file.
func decodeMosdnsConfig(t *testing.T, document []byte) *coremain.Config {
	t.Helper()
	var loaded coremain.Config
	decoder := yaml.NewDecoder(strings.NewReader(string(document)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&loaded); err != nil {
		t.Fatalf("the rendered document does not decode as a mosdns configuration: %v\n%s", err, document)
	}
	// The rendered level is the shipped one; the tests lower it so the
	// instance's own per-query reports do not fill the test output.
	loaded.Log = mlog.LogConfig{Level: "error"}
	return &loaded
}

// loadMosdns hands a decoded document to a real mosdns instance.
func loadMosdns(t *testing.T, loaded *coremain.Config) *coremain.Mosdns {
	t.Helper()
	instance, err := coremain.NewMosdns(loaded)
	if err != nil {
		t.Fatalf("mosdns refused the rendered configuration: %v", err)
	}
	t.Cleanup(func() {
		instance.CloseWithErr(nil)
		_ = instance.GetSafeClose().WaitClosed()
	})
	return instance
}

// swapPlugin returns the document's decoded configuration with one plugin entry
// replaced. It works on the decoded entries rather than on the bytes, so
// replacing one entry cannot disturb any other: the sequences under test are the
// same values the shipped document carries.
func swapPlugin(t *testing.T, document []byte, tag string, replacement coremain.PluginConfig) *coremain.Config {
	t.Helper()
	loaded := decodeMosdnsConfig(t, document)
	for index := range loaded.Plugins {
		if loaded.Plugins[index].Tag == tag {
			loaded.Plugins[index] = replacement
			return loaded
		}
	}
	t.Fatalf("the rendered document has no entry tagged %s:\n%s", tag, document)
	return nil
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

// startDomesticMock answers every query with a different address, so an answer
// that came from an earlier call cannot be mistaken for a fresh one. The TTL is
// long enough to be cacheable, because a cache that would not have stored the
// answer would hide the defect.
func startDomesticMock(t *testing.T) *testdns.Server {
	t.Helper()
	var answered atomic.Int64
	server, err := testdns.Start(func(_ context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(198, 51, 100, byte(answered.Add(1))).To4(),
		})
		return response
	})
	if err != nil {
		t.Fatalf("start the domestic resolver mock: %v", err)
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
	return equalStrings(got, want)
}

func equalStrings(got, want []string) bool {
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

func withSelector(paths Paths, value string) Paths {
	paths.Selector = value
	return paths
}

func withForceECH(paths Paths, value string) Paths {
	paths.ForceECH = value
	return paths
}

func withECHState(paths Paths, value string) Paths {
	paths.ECHState = value
	return paths
}

func withCloudflarePrefixes(paths Paths, value string) Paths {
	paths.CloudflarePrefixes = value
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

func withDHCPUpstreamPort(paths Paths, value int) Paths {
	paths.DHCPUpstreamPort = value
	return paths
}

func withoutPolicy(paths Paths) Paths {
	return withPolicy(paths, "")
}

func withoutSelector(paths Paths) Paths {
	return withSelector(paths, "")
}

func withoutForceECH(paths Paths) Paths {
	return withForceECH(paths, "")
}

func withoutECHState(paths Paths) Paths {
	return withECHState(paths, "")
}

func withoutCloudflarePrefixes(paths Paths) Paths {
	return withCloudflarePrefixes(paths, "")
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

// --- the foreign route as the policy configures it ---

// Every enabled `upstream` entry becomes exactly one forward upstream, in policy
// order, and a `dnscrypt` entry becomes none -- it is a process, not an address.
func TestEveryEnabledUpstreamEntryBecomesOneForwardUpstream(t *testing.T) {
	policy := config.Defaults()
	policy.Foreign.Upstreams = append(policy.Foreign.Upstreams, config.ForeignUpstream{
		Kind: config.UpstreamKindUpstream, Name: "extra", Addr: "tls://dns.quad9.net:853",
	})
	parsed := decodeRendered(t, mustRenderPolicy(t, policy))
	forward := argsOf[renderedForward](t, parsed.entry(t, tagForeignForward))
	// The packaged listener first (the dnscrypt entry is still on), then one address
	// per enabled upstream entry, in policy order. Derived from the policy above the
	// renderer runs rather than written out, so this case fails if the ORDER is wrong
	// and not merely if the count is.
	want := []string{"tcp://127.0.0.1:15353", "quic://dns.quad9.net:853", "tls://dns.quad9.net:853"}
	if len(forward.Upstreams) != len(want) {
		t.Fatalf("the forward names %d upstreams %v, want %v", len(forward.Upstreams), forwardAddrs(forward), want)
	}
	for index, addr := range want {
		if forward.Upstreams[index].Addr != addr {
			t.Fatalf("upstream %d is %q, want %q: the document's order is the policy's "+
				"order, because a reader comparing the two needs them to be comparable",
				index, forward.Upstreams[index].Addr, addr)
		}
	}
}

func TestADisabledEntryIsNotRenderedButIsStillInThePolicy(t *testing.T) {
	off := false
	policy := config.Defaults()
	policy.Foreign.Upstreams = append(policy.Foreign.Upstreams, config.ForeignUpstream{
		Kind: config.UpstreamKindUpstream, Name: "spare", Addr: "tls://1.1.1.1:853", Enabled: &off,
	})
	parsed := decodeRendered(t, mustRenderPolicy(t, policy))
	for _, addr := range forwardAddrs(argsOf[renderedForward](t, parsed.entry(t, tagForeignForward))) {
		if addr == "tls://1.1.1.1:853" {
			t.Fatal("a disabled entry was rendered into the forward, so disabling an entry " +
				"does not take it out of the route")
		}
	}
	// And it is still IN the policy, or "disabled" would mean "deleted" and an
	// operator switching an entry off would lose their configuration.
	if len(policy.Foreign.Upstreams) != 3 {
		t.Fatalf("the policy has %d entries after adding one, want 3: rendering must not "+
			"reach back and edit the policy it read", len(policy.Foreign.Upstreams))
	}
}

// A udp:// entry is routable and is never the ECH source, because cdn_rewrite
// refuses every non-tcp transport for the ECH fetch (cdn_rewrite.go:353). This is
// the shape of the mistake an operator makes when they add a DoH upstream and
// switch the packaged resolver off.
func TestAUdpEntryIsRoutableButIsNeverTheECHSource(t *testing.T) {
	off := false
	policy := config.Defaults()
	// Port 853 rather than 53: config.Validate refuses a foreign upstream on the
	// system resolver's port, which is the right refusal and is not what this case
	// is about. The plan's example said :53 and would have been testing that rule
	// twice instead of this one.
	policy.Foreign.Upstreams = []config.ForeignUpstream{
		{Kind: config.UpstreamKindUpstream, Name: "plain", Addr: "udp://9.9.9.9:853"},
		{Kind: config.UpstreamKindDNSCrypt, Name: "packaged", Enabled: &off},
	}
	// This policy is REFUSED, and that is the point: with the dnscrypt entry off
	// and only a udp entry left, there is nothing ECH may be fetched through.
	if err := policy.Validate(); !errors.Is(err, config.ErrNoECHSource) {
		t.Fatalf("a udp-only route with the packaged resolver off was accepted (err = %v), "+
			"so an operator can leave the ECH fetch with no transport at all", err)
	}
	// With a tcp:// entry added it renders, the udp entry IS routed, and the ECH
	// source is the tcp entry rather than either of the other two.
	policy.Foreign.Upstreams = append(policy.Foreign.Upstreams, config.ForeignUpstream{
		Kind: config.UpstreamKindUpstream, Name: "stream", Addr: "tcp://9.9.9.9:5353",
	})
	parsed := decodeRendered(t, mustRenderPolicy(t, policy))
	forward := argsOf[renderedForward](t, parsed.entry(t, tagForeignForward))
	if got := forwardAddrs(forward); len(got) != 2 || got[0] != "udp://9.9.9.9:853" {
		t.Fatalf("the forward carries %v, want the udp entry routed first and the tcp entry "+
			"second: a udp entry being routable is the premise of this case", got)
	}
	rewrite := argsOf[renderedCDNRewrite](t, parsed.entry(t, tagCDNRewrite))
	if rewrite.ForeignUpstream != "tcp://9.9.9.9:5353" {
		t.Fatalf("the ECH source is %q, want the tcp:// entry's addr", rewrite.ForeignUpstream)
	}
}

// scanForChinesePublicDNS already scans the WHOLE finished document
// (render.go:298), so an upstream entry that renders into that document is covered
// without a line of new code. "It is covered automatically" is a claim about code
// nobody changed, and the only thing that makes it more than a claim is a case that
// puts a Chinese resolver where a new entry can put one and refuses the render.
func TestAChineseResolverIsRefusedWhereverAnUpstreamEntryPutsIt(t *testing.T) {
	for _, chinese := range chinesePublicDNSAddresses {
		policy := config.Defaults()
		policy.Foreign.Upstreams = append(policy.Foreign.Upstreams, config.ForeignUpstream{
			Kind: config.UpstreamKindUpstream, Name: "extra",
			Addr: "https://" + chinese + "/dns-query",
		})
		if _, err := Render(policy, ProductionPaths()); err == nil {
			t.Errorf("%s was rendered into the document, so an operator can point the "+
				"foreign branch at a resolver this package exists to avoid", chinese)
		}
	}
	// And the case that matters more, because it is the one an operator reaches by
	// accident: a bootstrap pointing at a Chinese resolver. The forward list would
	// carry a public DoQ endpoint and look entirely correct, while the machine
	// resolved this router's own upstream name in China.
	policy := config.Defaults()
	policy.Foreign.Upstreams[1].Bootstrap = []string{chinesePublicDNSAddresses[0] + ":53"}
	if _, err := Render(policy, ProductionPaths()); err == nil {
		t.Errorf("a bootstrap of %s was rendered, so the one place a Chinese resolver "+
			"would arrive without looking wrong is unchecked", chinesePublicDNSAddresses[0])
	}
	// And the clean default is not caught by any of this.
	if _, err := Render(config.Defaults(), ProductionPaths()); err != nil {
		t.Errorf("the shipped route was refused alongside the Chinese-resolver cases: %v", err)
	}
}

func TestConcurrentIsWrittenIntoTheForward(t *testing.T) {
	for _, value := range []int{1, 2, 3} {
		policy := config.Defaults()
		policy.Foreign.Concurrent = value
		parsed := decodeRendered(t, mustRenderPolicy(t, policy))
		if got := argsOf[renderedForward](t, parsed.entry(t, tagForeignForward)).Concurrent; got != value {
			t.Fatalf("the forward says concurrent = %d, want %d: at 1 mosdns picks RANDOMLY "+
				"(forward.go:265-267) and an operator who asked for two upstreams would have "+
				"neither redundancy nor a document that says so", got, value)
		}
	}
}

// The api block is what makes the cache plugin's OWN flush endpoint reachable: the
// plugin registers GET /flush unconditionally (mosdns cache.go:320-324, mounted at
// :108) and the server only starts when the document carries api.http
// (coremain/mosdns.go:67). This package emitted no api key, so the endpoint has
// been unreachable in every document shipped so far.
func TestTheAPIListenerIsLoopbackAndPresent(t *testing.T) {
	parsed := decodeRendered(t, mustRenderPolicy(t, config.Defaults()))
	if parsed.API.HTTP != apiListenAddress {
		t.Fatalf("api.http is %q, want %q: without it the cache plugin's own flush "+
			"endpoint (mosdns cache.go:320-324) is registered and unreachable",
			parsed.API.HTTP, apiListenAddress)
	}
	if !strings.HasPrefix(parsed.API.HTTP, "127.0.0.1:") {
		t.Fatalf("api.http is %q, which is not loopback; this package's promise is that "+
			"every listener it configures is loopback-only", parsed.API.HTTP)
	}
}

// The api address must not collide with anything else the document binds. Two
// listeners on one port means the second one fails at startup, which is a router
// that does not start rather than a router that misbehaves.
func TestTheAPIListenerCollidesWithNothingTheDocumentBinds(t *testing.T) {
	document := mustRenderPolicy(t, config.Defaults())
	parsed := decodeRendered(t, document)
	for _, tag := range []string{tagUDPServer, tagTCPServer} {
		entry := parsed.entry(t, tag)
		var server renderedServer
		if err := entry.Args.Decode(&server); err != nil {
			t.Fatalf("the %s arguments do not decode: %v", tag, err)
		}
		if server.Listen == parsed.API.HTTP {
			t.Fatalf("api.http is %s, which the %s server also binds", parsed.API.HTTP, tag)
		}
	}
}

// mustRenderPolicy is the other shape: a caller that wants to render a policy
// other than the default, which is most of what the foreign-route cases below do.
func mustRenderPolicy(t *testing.T, policy config.Policy) []byte {
	t.Helper()
	document, err := Render(policy, ProductionPaths())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return document
}

func forwardAddrs(forward renderedForward) []string {
	out := make([]string, 0, len(forward.Upstreams))
	for _, upstream := range forward.Upstreams {
		out = append(out, upstream.Addr)
	}
	return out
}

// TestTheForeignListenerIsDerivedRatherThanConfigured is the case that replaced
// "no foreign listener" in the refusal table.
//
// That row asserted an empty Paths.ForeignListener is a fault. It stopped being one
// and the row had to go, because ProductionPaths() now leaves the field EMPTY on
// purpose: the listener is derived from the policy's dnscrypt entry so that the
// routing document and the resolver document cannot name different sockets. So the
// property worth holding is the derivation itself, and it is held here instead:
//
//   - ProductionPaths() really does leave it empty, which is what makes the
//     derivation the production path rather than a fallback nobody exercises;
//   - the derived value is dnscrypt.ListenAddress, read from the package that
//     renders the resolver -- not a literal in this package;
//   - an INJECTED listener still wins, because it is the seam the integration tests
//     point at a mock resolver, and a seam that stopped working would silently turn
//     every integration test into a test of the real socket.
func TestTheForeignListenerIsDerivedRatherThanConfigured(t *testing.T) {
	if got := ProductionPaths().ForeignListener; got != "" {
		t.Fatalf("ProductionPaths().ForeignListener is %q; it must be EMPTY so the production "+
			"document derives the listener from the policy's dnscrypt entry", got)
	}

	derived := decodeRendered(t, mustRenderPolicy(t, config.Defaults()))
	if got := argsOf[renderedForward](t, derived.entry(t, tagForeignForward)).Upstreams[0].Addr; got != "tcp://"+dnscrypt.ListenAddress {
		t.Fatalf("the derived forward enters %q, want the dnscrypt package's own %q: a literal "+
			"here is the second copy this derivation exists to remove", got, "tcp://"+dnscrypt.ListenAddress)
	}
	if got := argsOf[renderedCDNRewrite](t, derived.entry(t, tagCDNRewrite)).ForeignUpstream; got != "tcp://"+dnscrypt.ListenAddress {
		t.Fatalf("the derived ECH source is %q, want %q", got, "tcp://"+dnscrypt.ListenAddress)
	}

	// And the injection seam, which the integration tests depend on.
	const injected = "tcp://127.0.0.2:25353"
	seam := decodeRendered(t, mustRender(t, withForeignListener(ProductionPaths(), injected)))
	if got := argsOf[renderedCDNRewrite](t, seam.entry(t, tagCDNRewrite)).ForeignUpstream; got != injected {
		t.Fatalf("an injected listener of %q produced an ECH source of %q: the seam the "+
			"integration tests use to reach a mock resolver is not working", injected, got)
	}
	if got := argsOf[renderedForward](t, seam.entry(t, tagForeignForward)).Upstreams[0].Addr; got != injected {
		t.Fatalf("an injected listener of %q produced a forward entering %q", injected, got)
	}
}

// --- the cache's record time ---

// **The trap this case exists for.** mosdns's ApplyMaximumTTL(m, 0) sets EVERY
// record's TTL to 0 (pkg/dnsutils/msg.go:65-67 -> :94-112, the clamp at :101-104)
// -- zero is not "no bound", it is "expire immediately". So a zero max must render
// NO clamp at all rather than a clamp with a zero bound, and it must keep the
// committed document byte-identical.
func TestATtlClampIsNotRenderedWhenThePolicyAsksForNone(t *testing.T) {
	for _, mutate := range []func(*config.Policy){
		func(p *config.Policy) { p.ForeignCache.TTLMax = 0 },
		func(p *config.Policy) { p.ForeignCache.TTLMin = 0 },
		func(p *config.Policy) { p.ForeignCache.TTLMax = 0; p.ForeignCache.TTLMin = 0 },
	} {
		value := config.Defaults()
		mutate(&value)
		document := mustRenderPolicy(t, value)
		if strings.Contains(string(document), tagForeignTTL) {
			t.Fatalf("a policy asking for no clamp rendered a %s plugin:\n%s", tagForeignTTL, document)
		}
	}
}

// The clamp goes AFTER the forward, and the position is the whole of it: the
// plugin table order IS the next chain, and the cache stores whatever its next
// returned. A clamp before the forward would shape only the answer on the way out
// while the router's own cache still expired on the upstream's TTL.
func TestATtlClampIsRenderedAfterTheForwardSoTheCacheStoresIt(t *testing.T) {
	value := config.Defaults()
	value.ForeignCache.TTLMax = 300
	parsed := decodeRendered(t, mustRenderPolicy(t, value))
	names := tags(parsed)
	forward, clamp := -1, -1
	for index, name := range names {
		switch name {
		case tagForeignForward:
			forward = index
		case tagForeignTTL:
			clamp = index
		}
	}
	if clamp < 0 {
		t.Fatalf("foreign_cache.ttl_max = 300 rendered no %s plugin", tagForeignTTL)
	}
	if clamp < forward {
		t.Fatalf("%s is at %d, before %s at %d. The plugin table order IS the next chain, "+
			"and the cache stores whatever its next returned: a clamp before the forward "+
			"would only shape the answer on the way out while the router's own cache still "+
			"expired on the upstream's TTL", tagForeignTTL, clamp, tagForeignForward, forward)
	}
}

// And it is before the CN sequence, because the branch ends at the forward's answer
// and a clamp the branch never runs is a clamp that does nothing.
func TestATtlClampIsInsideTheForeignBranch(t *testing.T) {
	value := config.Defaults()
	value.ForeignCache.TTLMax = 300
	parsed := decodeRendered(t, mustRenderPolicy(t, value))
	names := tags(parsed)
	clamp, cnPath := -1, -1
	for index, name := range names {
		switch name {
		case tagForeignTTL:
			clamp = index
		case tagCNPath:
			cnPath = index
		}
	}
	if clamp < 0 || cnPath < 0 {
		t.Fatalf("the document has no %s or no %s: %v", tagForeignTTL, tagCNPath, names)
	}
	if clamp > cnPath {
		t.Fatalf("%s is at %d, after %s at %d: the foreign branch ends on the forward's "+
			"answer, so a clamp after that runs on nothing", tagForeignTTL, clamp, tagCNPath, cnPath)
	}
}

// Both keys are omitted rather than written zero, because mosdns reads `max > 0`
// before applying a maximum (ttl.go:91). A written `min: 0` would happen to work --
// ttl.go:88 guards on `t.min > 0` too -- but only by accident of the guard order, and
// a reader of the document would conclude a floor of zero was asked for.
func TestAZeroBoundIsOmittedRatherThanWritten(t *testing.T) {
	value := config.Defaults()
	value.ForeignCache.TTLMax = 120
	parsed := decodeRendered(t, mustRenderPolicy(t, value))
	block := string(mustRenderPolicy(t, value))
	// **The check is on the DOCUMENT TEXT, not on the decoded value, and that
	// distinction is the whole case.** `min: 0` decodes into the same 0 as an absent
	// key, so a test that decodes and compares values cannot tell the two apart --
	// it passed against the very mutation it exists to forbid. What differs is the
	// KEY, and mosdns reads the key's absence (`if t.min > 0`, ttl.go:88), so the key
	// is what has to be asserted.
	_, before, _ := strings.Cut(block, "- tag: "+tagForeignTTL)
	clamp, _, _ := strings.Cut(before, "- tag:")
	if strings.Contains(clamp, "min:") {
		t.Errorf("a zero ttl_min was written out as a key:\n%s\nmosdns reads `t.min > 0` "+
			"before applying a floor (ttl.go:88), so the value would be inert and the "+
			"document would claim a bound the router is not applying", clamp)
	}
	if !strings.Contains(clamp, "max: 120") {
		t.Errorf("ttl_max = 120 was not written:\n%s", clamp)
	}
	args := argsOf[ttlBlock](t, parsed.entry(t, tagForeignTTL))
	if args.Max != 120 {
		t.Errorf("the clamp says max = %d, want the policy's 120", args.Max)
	}
}

// And with BOTH set, both are written -- the case that proves the omitempty is not
// simply dropping everything.
func TestBothBoundsAreWrittenWhenBothAreAsked(t *testing.T) {
	value := config.Defaults()
	value.ForeignCache.TTLMax = 300
	value.ForeignCache.TTLMin = 30
	parsed := decodeRendered(t, mustRenderPolicy(t, value))
	args := argsOf[ttlBlock](t, parsed.entry(t, tagForeignTTL))
	if args.Max != 300 || args.Min != 30 {
		t.Fatalf("the clamp says max=%d min=%d, want max=300 min=30", args.Max, args.Min)
	}
}

func TestTheCacheSizeComesFromThePolicy(t *testing.T) {
	value := config.Defaults()
	value.ForeignCache.Size = 77
	parsed := decodeRendered(t, mustRenderPolicy(t, value))
	if got := argsOf[renderedCache](t, parsed.entry(t, tagForeignCache)).Size; got != 77 {
		t.Fatalf("the cache size is %d, want the policy's 77: it was a render constant "+
			"writing 1024 and this is the change that makes it the operator's", got)
	}
}
