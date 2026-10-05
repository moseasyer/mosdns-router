package config

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const validPolicyYAML = `schema_version: 1
schedule: "03:30"
foreign:
  default_provider: Quad9 Secure DNSCrypt v2
  ecs: false
  concurrent: 2
  upstreams:
    - kind: dnscrypt
      name: quad9-dnscrypt
    - kind: upstream
      name: quad9-doq
      addr: quic://dns.quad9.net:853
      bootstrap:
        - 9.9.9.9:53
cdn:
  ip_version: IPv4
  suppress_aaaa: true
  cloudflare:
    max_candidates: 512
  latency_candidate_count: 10
  combined:
    latency_top: 3
    bandwidth_top: 3
  switch_improvement_percent: 10
  health:
    interval: 120
    failure_threshold: 3
  bandwidth:
    daily_budget: 104857600
    per_candidate_limit: 10485760
    per_candidate_seconds: 3
ech:
  enabled: true
  failure_policy: strict
  stale_grace: 600
  sources:
    - cloudflare-ech.com
    - crypto.cloudflare.com
    - discordapp.com
    - cdn.discordapp.com
    - encryptedsni.com
    - www.encryptedsni.com
    - ech.encryptedsni.com
    - api.encryptedsni.com
    - mail.encryptedsni.com
dhcp:
  failure_policy: disable-current
cache:
  persistent_dump: false
foreign_cache:
  size: 1024
  ttl_max: 0
  ttl_min: 0
`

func TestDefaultsMatchApprovedSpec(t *testing.T) {
	got := Defaults()
	want := Policy{
		SchemaVersion: 1,
		Schedule:      "03:30",
		Foreign: ForeignPolicy{
			DefaultProvider: "Quad9 Secure DNSCrypt v2",
			ECS:             false,
			Concurrent:      2,
			// Written out rather than referenced through
			// defaultForeignUpstreams(), for the same reason the ECH sources
			// below are: this test IS the assertion that Defaults() still says
			// what was approved, and a reference would pass for any route anyone
			// liked.
			Upstreams: []ForeignUpstream{
				{Kind: UpstreamKindDNSCrypt, Name: "quad9-dnscrypt"},
				{
					Kind:      UpstreamKindUpstream,
					Name:      "quad9-doq",
					Addr:      "quic://dns.quad9.net:853",
					Bootstrap: []string{"9.9.9.9:53"},
				},
			},
		},
		CDN: CDNPolicy{
			IPVersion:                "IPv4",
			SuppressAAAA:             true,
			Cloudflare:               CloudflarePolicy{MaxCandidates: 512},
			LatencyCandidateCount:    10,
			Combined:                 CombinedPolicy{LatencyTop: 3, BandwidthTop: 3},
			SwitchImprovementPercent: 10,
			Health: HealthPolicy{
				IntervalSeconds:  120,
				FailureThreshold: 3,
			},
			Bandwidth: BandwidthPolicy{
				DailyBytes:          100 * 1024 * 1024,
				PerCandidateBytes:   10 * 1024 * 1024,
				PerCandidateSeconds: 3,
			},
		},
		ECH: ECHPolicy{
			Enabled:           true,
			FailurePolicy:     "strict",
			StaleGraceSeconds: 600,
			// The nine measured names, written out rather than referenced, because
			// this test IS the assertion that Defaults() still says what was
			// approved: `Sources: echDefaultSources` would pass for any list anyone
			// liked. The Yaml fixture above is a second copy for the same reason and
			// has to be edited together with this one.
			Sources: []string{
				"cloudflare-ech.com",
				"crypto.cloudflare.com",
				"discordapp.com",
				"cdn.discordapp.com",
				"encryptedsni.com",
				"www.encryptedsni.com",
				"ech.encryptedsni.com",
				"api.encryptedsni.com",
				"mail.encryptedsni.com",
			},
		},
		DHCP:         DHCPPolicy{FailurePolicy: "disable-current"},
		Cache:        CachePolicy{PersistentDump: false},
		ForeignCache: ForeignCache{Size: 1024, TTLMax: 0, TTLMin: 0},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected defaults:\n got: %#v\nwant: %#v", got, want)
	}
}

// TestTheECHSourcesAreSpreadOverMoreThanOneZone is the property the list is FOR,
// and nothing else in this file holds it.
//
// The count is held by TestDefaultsMatchApprovedSpec, which writes the nine names
// out. What that cannot see is whether they are nine NAMES or nine PATHS INTO ONE
// ZONE, and ECH is enabled per zone: a zone that drops it is one edit, so a list of
// nine subdomains of a single zone loses all nine at the same instant and is worth
// exactly one.
//
// The heuristic is the registrable domain by its last two labels, and it
// UNDERCOUNTS on purpose. `crypto.cloudflare.com` and `cloudflare-ech.com` are two
// distinct DNS zones but share the label pair `cloudflare.com`, so a list that
// spread over five real zones reads here as four. Asserting four therefore holds
// "more than one zone" with a margin, and it is the direction that matters: the case
// that must fail is a list made entirely of one zone's subdomains, and that scores
// 1.
func TestTheECHSourcesAreSpreadOverMoreThanOneZone(t *testing.T) {
	registrable := map[string]bool{}
	for _, source := range Defaults().ECH.Sources {
		labels := strings.Split(strings.TrimSuffix(source, "."), ".")
		if len(labels) < 2 {
			t.Fatalf("the source %q has fewer than two labels, so it cannot be a hostname this "+
				"project measured", source)
		}
		registrable[strings.Join(labels[len(labels)-2:], ".")] = true
	}
	const wantZones = 4
	if len(registrable) < wantZones {
		t.Fatalf("the %d shipped ECH sources span %d registrable domains (%v), want at least %d: ECH "+
			"is enabled per zone, so a list concentrated in one zone is worth one source however many "+
			"names it has. The nine measured names span five real zones and this counts four, because "+
			"crypto.cloudflare.com and cloudflare-ech.com share a label pair.",
			len(Defaults().ECH.Sources), len(registrable), keysOf(registrable), wantZones)
	}
	if len(Defaults().ECH.Sources) < 9 {
		t.Fatalf("the shipped ECH source list has %d names, want at least 9: the list exists so that a "+
			"zone dropping ECH does not end forced ECH, and its length is that margin",
			len(Defaults().ECH.Sources))
	}
}

func keysOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func TestLoadAcceptsOneDocumentAndLoadsPolicy(t *testing.T) {
	for _, prefix := range []string{"", "---\n"} {
		t.Run("leading_marker_"+strings.TrimSpace(prefix), func(t *testing.T) {
			path := writeYAML(t, prefix+validPolicyYAML)
			got, err := Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if !reflect.DeepEqual(got, Defaults()) {
				t.Fatalf("loaded policy = %#v, want defaults %#v", got, Defaults())
			}
		})
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	path := writeYAML(t, validPolicyYAML+"unknown_key: true\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected unknown key error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not include policy path %q", err, path)
	}
}

func TestLoadRejectsInvalidPolicyValues(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "negative daily budget", old: "daily_budget: 104857600", new: "daily_budget: -1"},
		{name: "negative per candidate limit", old: "per_candidate_limit: 10485760", new: "per_candidate_limit: -1"},
		{name: "zero daily budget", old: "daily_budget: 104857600", new: "daily_budget: 0"},
		{name: "zero per candidate limit", old: "per_candidate_limit: 10485760", new: "per_candidate_limit: 0"},
		{name: "invalid schedule hour", old: `schedule: "03:30"`, new: `schedule: "24:00"`},
		{name: "invalid schedule minute", old: `schedule: "03:30"`, new: `schedule: "03:60"`},
		{name: "schedule without zero padding", old: `schedule: "03:30"`, new: `schedule: "3:00"`},
		{name: "unsupported ECH policy", old: "failure_policy: strict", new: "failure_policy: permissive"},
		{name: "unsupported DHCP policy", old: "failure_policy: disable-current", new: "failure_policy: keep-stale"},
		{name: "zero schema version", old: "schema_version: 1", new: "schema_version: 0"},
		{name: "unsupported schema version", old: "schema_version: 1", new: "schema_version: 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := strings.Replace(validPolicyYAML, tt.old, tt.new, 1)
			if content == validPolicyYAML {
				t.Fatalf("fixture replacement %q did not apply", tt.old)
			}
			path := writeYAML(t, content)
			if _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateRejectsNegativeNumericValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "cloudflare candidates", mutate: func(p *Policy) { p.CDN.Cloudflare.MaxCandidates = -1 }},
		{name: "latency candidates", mutate: func(p *Policy) { p.CDN.LatencyCandidateCount = -1 }},
		{name: "latency top", mutate: func(p *Policy) { p.CDN.Combined.LatencyTop = -1 }},
		{name: "bandwidth top", mutate: func(p *Policy) { p.CDN.Combined.BandwidthTop = -1 }},
		{name: "switch improvement", mutate: func(p *Policy) { p.CDN.SwitchImprovementPercent = -1 }},
		{name: "health interval", mutate: func(p *Policy) { p.CDN.Health.IntervalSeconds = -1 }},
		{name: "failure threshold", mutate: func(p *Policy) { p.CDN.Health.FailureThreshold = -1 }},
		{name: "daily bytes", mutate: func(p *Policy) { p.CDN.Bandwidth.DailyBytes = -1 }},
		{name: "per candidate bytes", mutate: func(p *Policy) { p.CDN.Bandwidth.PerCandidateBytes = -1 }},
		{name: "per candidate seconds", mutate: func(p *Policy) { p.CDN.Bandwidth.PerCandidateSeconds = -1 }},
		{name: "stale grace", mutate: func(p *Policy) { p.ECH.StaleGraceSeconds = -1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := Defaults()
			tt.mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

// The design is IPv4-only, so a policy that asks for anything else would make
// every later response-rewrite decision unsafe.
func TestValidateAcceptsOnlyIPv4Selection(t *testing.T) {
	policy := Defaults()
	if err := policy.Validate(); err != nil {
		t.Fatalf("default ip_version rejected: %v", err)
	}
	for _, value := range []string{"IPv6", "ipv4", "both", ""} {
		policy := Defaults()
		policy.CDN.IPVersion = value
		if err := policy.Validate(); err == nil {
			t.Errorf("ip_version %q accepted", value)
		}
	}
}

// The spec fixes hard upper bounds on measurement traffic. A policy above them
// would let a later optimizer exceed the daily budget or hold one candidate
// open longer than the approved limit, so the caps are enforced here.
func TestValidateEnforcesApprovedBandwidthCaps(t *testing.T) {
	atCap := Defaults()
	atCap.CDN.Bandwidth.DailyBytes = 100 * 1024 * 1024
	atCap.CDN.Bandwidth.PerCandidateBytes = 10 * 1024 * 1024
	atCap.CDN.Bandwidth.PerCandidateSeconds = 3
	if err := atCap.Validate(); err != nil {
		t.Fatalf("budgets exactly at the approved caps rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "daily budget one byte over", mutate: func(p *Policy) { p.CDN.Bandwidth.DailyBytes = 100*1024*1024 + 1 }},
		{name: "daily budget doubled", mutate: func(p *Policy) { p.CDN.Bandwidth.DailyBytes = 200 * 1024 * 1024 }},
		{name: "per-candidate limit one byte over", mutate: func(p *Policy) { p.CDN.Bandwidth.PerCandidateBytes = 10*1024*1024 + 1 }},
		{name: "per-candidate seconds over", mutate: func(p *Policy) { p.CDN.Bandwidth.PerCandidateSeconds = 4 }},
		{name: "per-candidate seconds far over", mutate: func(p *Policy) { p.CDN.Bandwidth.PerCandidateSeconds = 60 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := Defaults()
			tt.mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("expected a validation error above the approved cap")
			}
		})
	}
}

// An ECH source is queried as a DNS name over the foreign path, so a URL, an
// address, or a wildcard cannot be a valid source.
func TestValidateRejectsNonHostnameECHSources(t *testing.T) {
	invalid := []string{
		"https://cloudflare-ech.com",
		"cloudflare-ech.com/ech.txt",
		"192.0.2.1",
		"::1",
		"cloudflare ech.com",
		"*.example",
		"-cloudflare-ech.com",
		"cloudflare-ech.com.",
		"",
	}
	for _, source := range invalid {
		policy := Defaults()
		policy.ECH.Sources = []string{source}
		if err := policy.Validate(); err == nil {
			t.Errorf("ECH source %q accepted", source)
		}
	}

	policy := Defaults()
	policy.ECH.Sources = []string{"cloudflare-ech.com", "ech.example.org"}
	if err := policy.Validate(); err != nil {
		t.Fatalf("hostname ECH sources rejected: %v", err)
	}
}

func TestValidateAcceptsBoundaryValues(t *testing.T) {
	policy := Defaults()
	policy.Schedule = "00:00"
	policy.CDN.SwitchImprovementPercent = 0
	policy.ECH.StaleGraceSeconds = 0
	if err := policy.Validate(); err != nil {
		t.Fatalf("boundary values should be valid: %v", err)
	}

	policy.Schedule = "23:59"
	if err := policy.Validate(); err != nil {
		t.Fatalf("latest valid schedule should be valid: %v", err)
	}
}

func TestValidateAcceptsSupportedFailurePolicies(t *testing.T) {
	policy := Defaults()
	policy.ECH.FailurePolicy = "fallback"
	policy.DHCP.FailurePolicy = "use-last-good"
	if err := policy.Validate(); err != nil {
		t.Fatalf("supported failure policies should be valid: %v", err)
	}
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	for _, suffix := range []string{"---\nschema_version: 1\n", "---\n"} {
		t.Run("suffix_"+strings.TrimSpace(suffix), func(t *testing.T) {
			path := writeYAML(t, validPolicyYAML+suffix)
			if _, err := Load(path); err == nil {
				t.Fatal("expected multiple-document error")
			}
		})
	}
}

func TestLoadRejectsTrailingContent(t *testing.T) {
	path := writeYAML(t, validPolicyYAML+"trailing content\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected trailing-content error")
	}
}

func TestLoadWrapsFileErrorsWithPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected file error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not include policy path %q", err, path)
	}
}

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestTheDefaultPolicyRefreshesNothing(t *testing.T) {
	policy := Defaults()
	if policy.Lists.China.Automatic {
		t.Error("china list automatic refresh is on by default; data/cn is curated and any " +
			"upstream commit moves the split, so this must be an operator's explicit choice")
	}
	if policy.Lists.Cloudflare.Automatic {
		t.Error("cloudflare range automatic refresh is on by default")
	}
}

// The two are separate switches because the two are not the same kind of risk. One
// switch would mean opening the low-risk action opens the high-risk one.
func TestTheTwoSwitchesAreIndependent(t *testing.T) {
	policy := Defaults()
	policy.Lists.Cloudflare.Automatic = true
	if policy.Lists.China.Automatic {
		t.Error("turning the cloudflare refresh on also turned the china one on")
	}
	policy = Defaults()
	policy.Lists.China.Automatic = true
	if policy.Lists.Cloudflare.Automatic {
		t.Error("turning the china refresh on also turned the cloudflare one on")
	}
}

// An absent lists: group decodes to both-off rather than failing, because that is the
// safe direction: a policy written before this field existed must keep working and
// must not start refreshing anything.
func TestAPolicyWithoutTheListsGroupLoads(t *testing.T) {
	// The default policy with its lists: block cut out, rather than a hand-written
	// minimal one: this is the shape of a policy an operator wrote before the field
	// existed, and a minimal fixture would be refused for an unrelated missing key
	// and prove nothing about lists.
	encoded, err := Marshal(Defaults())
	if err != nil {
		t.Fatalf("marshal the defaults: %v", err)
	}
	var kept []string
	skipping := false
	for _, line := range strings.Split(string(encoded), "\n") {
		if strings.HasPrefix(line, "lists:") {
			skipping = true
			continue
		}
		if skipping && (strings.HasPrefix(line, " ") || line == "") {
			continue
		}
		skipping = false
		kept = append(kept, line)
	}
	path := writeYAML(t, strings.Join(kept, "\n"))
	policy, err := Load(path)
	if err != nil {
		t.Fatalf("a policy with no lists: group was refused: %v", err)
	}
	if policy.Lists.China.Automatic || policy.Lists.Cloudflare.Automatic {
		t.Errorf("a policy with no lists: group decoded to %+v, and zero must mean both off",
			policy.Lists)
	}
}

// 03:30, not 03:00: the field has been decorative and 03:30 is what was actually
// running, so the default states the truth rather than moving the machine.
func TestTheDefaultScheduleIsTheTimeThatWasRunning(t *testing.T) {
	if got := Defaults().Schedule; got != "03:30" {
		t.Errorf("default schedule is %q, want 03:30 -- the value the hardcoded timer "+
			"has been using, so making the field real does not also move the machine", got)
	}
}
