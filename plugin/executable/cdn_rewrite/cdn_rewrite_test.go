package cdn_rewrite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/dnsrewrite"
	"mosdns-router/internal/echconfig"
	"mosdns-router/internal/state"
)

// Every expectation in this file is written as a literal a resolver's contract
// requires: the address that must be in an answer, the record that must be
// absent from it, the question that must never have been asked. A comparison
// against whatever the implementation produced would pass whether the rewrite
// happened or not.

// --- the addresses and names the fixtures use ---

const (
	// cloudflareName is a name whose A answer is served entirely from the
	// published Cloudflare range this plugin is configured with, so the
	// classifier calls it rewriteable.
	cloudflareName = "www.served.example.com."
	// plainName is a name whose A answer is served from an address in no
	// published range, so nothing about it may be changed.
	plainName = "www.plain.example.com."
	// forceECHName is a domain the operator put on the force-ECH list, and it is
	// a Cloudflare name besides, so the two decisions cannot be told apart by the
	// name alone. forceECHEntry is how the operator writes it in the file: the
	// list is a document a person edits, and a trailing dot there is refused by
	// the watcher as the name it is not.
	forceECHName  = "secure.example.com."
	forceECHEntry = "secure.example.com"
	// cloudFrontName is a distribution hostname the selector carries a
	// per-hostname mapping for, and cloudFrontSibling is a sibling of it that the
	// mapping does not cover. cloudFrontEntry is how the mapping's key is written:
	// the optimizer publishes the profile's hostname, which carries no trailing
	// dot, and the state package refuses one.
	cloudFrontName    = "assets.example.net."
	cloudFrontSibling = "other.example.net."
	cloudFrontEntry   = "assets.example.net"
	// mappedName is a name that is on neither list, for the cases where a query
	// has to reach the upstream untouched.
	untouchedName = "untouched.example.com."
)

const (
	// cloudflareAddress is inside the published 104.16.0.0/13 range below.
	cloudflareAddress = "104.16.0.1"
	// secondCloudflareAddress is a second address in the same range, so a
	// response carrying both is still wholly Cloudflare-served and a response
	// carrying one of them and a foreign one is mixed.
	secondCloudflareAddress = "104.16.2.2"
	// foreignAddress is in no published range. 203.0.113.0/24 is the
	// documentation range, which no rewrite target may be, and which no
	// published Cloudflare range contains.
	foreignAddress = "203.0.113.9"
	// cloudFrontAddress is a CloudFront-served address: outside every published
	// Cloudflare range, and public IPv4 the state package will publish.
	cloudFrontAddress = "13.35.1.2"
	// winnerAddress is the address the selector's proof window authorises.
	winnerAddress = "104.16.99.99"
	// cloudFrontWinnerAddress is the address the selector publishes for the
	// distribution hostname.
	cloudFrontWinnerAddress = "13.35.0.1"
)

// publishedPrefixes is what the Cloudflare prefix file holds in these tests: one
// real Cloudflare range and nothing else, so a fixture address is either
// unambiguously inside a published range or unambiguously outside every one.
const publishedPrefixes = "104.16.0.0/13\n173.245.48.0/20\n"

// echFixtureBase64 is the ECHConfigList a public ECH source published on
// 2026-09-25: the same non-secret fixture internal/echconfig and
// internal/dnsrewrite are tested against, so the bytes a browser would receive
// here are bytes a browser has received before. It decodes to 71 bytes, the outer
// uint16 length 0x0045 and one ECHConfig of version 0xfe0d whose public name is
// cloudflare-ech.com.
const echFixtureBase64 = "AEX+DQBBuAAgACBeWfLyd08MrrxQgz3O0ws1h/j6yhgH1+4jTfFQ5Y6qawAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

func echFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(echFixtureBase64)
	if err != nil {
		t.Fatalf("decode the ECH fixture: %v", err)
	}
	return raw
}

// --- the downstream sequence, the ECH client, and the files ---

// fakeNext is the sequence this plugin sits in front of. It counts how often it
// was asked and hands back the response it was built with: the same pointer every
// time, standing in for the object a cache owns and hands to more than one query.
// A plugin that modified it in place would be visible here.
type fakeNext struct {
	calls    int
	response *dns.Msg
	err      error
}

func (f *fakeNext) exec(_ context.Context, qCtx *query_context.Context, _ sequence.ChainWalker) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	qCtx.SetResponse(f.response)
	return nil
}

// walker is the real mosdns chain walker with this one node in it, so the
// plugin's own call into next goes through the framework's dispatch rather than
// around it.
func (f *fakeNext) walker() sequence.ChainWalker {
	return sequence.NewChainWalker([]*sequence.ChainNode{
		{RE: sequence.RecursiveExecutableFunc(f.exec)},
	}, nil)
}

// echQuery is one query the ECH client was handed, recorded from the wire.
type echQuery struct {
	id       uint16
	question dns.Question
	bytes    int
}

// fakeECHUpstream is the direct foreign client the ECH provider is built with. It
// records every query it received, because two of the properties under test are
// about what it was asked: that an ECH fetch is a type 65 query of its own, and
// that a strict short-circuit reaches it not at all.
type fakeECHUpstream struct {
	mu      sync.Mutex
	queries []echQuery
	answer  func(question dns.Question) (*dns.Msg, error)
}

func (f *fakeECHUpstream) ExchangeContext(_ context.Context, payload []byte) (*[]byte, error) {
	var query dns.Msg
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.queries = append(f.queries, echQuery{id: query.Id, question: query.Question[0], bytes: len(payload)})
	answer := f.answer
	f.mu.Unlock()

	response, err := answer(query.Question[0])
	if err != nil {
		return nil, err
	}
	// A pooled buffer, because that is the contract every mosdns upstream
	// implements and the one the provider releases against: a caller that handed
	// back a buffer it did not get from the pool would be handing back something
	// the pool cannot take again.
	buffer := pool.GetBuf(dns.MaxMsgSize)
	packed, err := response.PackBuffer(*buffer)
	if err != nil {
		pool.ReleaseBuf(buffer)
		return nil, err
	}
	copy(*buffer, packed)
	return buffer, nil
}

func (f *fakeECHUpstream) Close() error { return nil }

// failWith makes the client refuse every query from now on, which is what a
// listener that has stopped answering looks like from the provider's side.
func (f *fakeECHUpstream) failWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = func(dns.Question) (*dns.Msg, error) { return nil, err }
}

// setAnswer replaces what the client answers with, for a test whose source
// changes its mind part way through.
func (f *fakeECHUpstream) setAnswer(answer func(dns.Question) (*dns.Msg, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

func (f *fakeECHUpstream) asked() []echQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]echQuery(nil), f.queries...)
}

// harness is one plugin, the files it reads, and the two fakes it talks to.
type harness struct {
	dir          string
	policyPath   string
	selectorPath string
	forcePath    string
	echStatePath string
	prefixPath   string
	upstream     *fakeECHUpstream
	next         *fakeNext
	now          time.Time
	// started is when the harness was built, so a test can wait for a number of
	// poll intervals rather than for a wall-clock time it chose itself.
	started time.Time
	logs    *observer.ObservedLogs
	plugin  *Plugin
}

// harnessConfig is what a test changes about a harness. Every field has a value
// that makes the plugin do nothing interesting, so a test names only the one thing
// it is about.
type harnessConfig struct {
	mutatePolicy func(*config.Policy)
	selector     *state.Selector
	forceList    string
	prefixes     string
	echAnswer    func(dns.Question) (*dns.Msg, error)
	// upstreamError is returned by the injected ECH client factory, standing in for
	// a listener that cannot be built at all.
	upstreamError error
	// foreignUpstream is the URL the ECH key would be fetched through.
	foreignUpstream string
	// echRefreshEvery is the ECH background refresh's period. Zero leaves the plugin's
	// own value, which is the production cadence — so every case that is not about
	// the refresher keeps the real five minutes and cannot be made to pass or fail by
	// it.
	echRefreshEvery time.Duration
	// blankArg names one argument to leave empty, which is how the construction
	// refusals are presented: every one of the six paths is required, and the test
	// says which one it took away.
	blankArg string
	// noForceFile leaves the allowlist unwritten, which is the state a router whose
	// operator has not created it yet is in.
	noForceFile bool
	// ownPolicy replaces the policy document the harness writes, for the one case
	// where the document is meant to be something the config package refuses.
	ownPolicy func(t *testing.T) []byte
}

// defaultConfig is the configuration every test starts from: a policy with ECH
// enabled and failing closed, a selector whose winner was proved a minute ago, an
// allowlist naming one domain, the published Cloudflare ranges, and a source that
// publishes a key.
func defaultConfig(t *testing.T) harnessConfig {
	t.Helper()
	return harnessConfig{
		selector:        liveSelector(),
		forceList:       "# force ECH for the domains the operator listed\n" + forceECHEntry + "\n",
		prefixes:        publishedPrefixes,
		echAnswer:       answerWithECH(echFixture(t), 300),
		foreignUpstream: "tcp://127.0.0.1:15353",
	}
}

// newHarness builds a plugin that is expected to start, and fails the test if it
// does not.
func newHarness(t *testing.T, configure ...func(*harnessConfig)) *harness {
	t.Helper()
	h, err := buildHarness(t, configure...)
	if err != nil {
		t.Fatalf("build the plugin: %v", err)
	}
	t.Cleanup(func() { _ = h.plugin.Close() })
	return h
}

// newHarnessExpectingRefusal builds a plugin the test expects to be refused, and
// hands back the refusal.
func newHarnessExpectingRefusal(t *testing.T, configure ...func(*harnessConfig)) (*harness, error) {
	t.Helper()
	return buildHarness(t, configure...)
}

// buildHarness writes the files, builds the plugin over them, and returns whatever
// the construction said. The ECH client and the clock are injected, so no test
// opens a socket or reads the wall clock.
func buildHarness(t *testing.T, configure ...func(*harnessConfig)) (*harness, error) {
	t.Helper()
	settings := defaultConfig(t)
	for _, apply := range configure {
		apply(&settings)
	}
	// The clock is a value the harness owns, so a test can move it and every
	// decision that reads a time reads this one.
	h := &harness{
		dir:          t.TempDir(),
		now:          time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC),
		upstream:     &fakeECHUpstream{answer: settings.echAnswer},
		next:         &fakeNext{},
		policyPath:   filepath.Join(t.TempDir(), "policy.yaml"),
		selectorPath: filepath.Join(t.TempDir(), "cdn-selector.json"),
		forcePath:    filepath.Join(t.TempDir(), "force-ech-domains.txt"),
		echStatePath: filepath.Join(t.TempDir(), "ech-state.json"),
		prefixPath:   filepath.Join(t.TempDir(), "cloudflare-prefixes.txt"),
		started:      time.Now(),
	}
	policyContents := policyDocument(t, settings.mutatePolicy)
	if settings.ownPolicy != nil {
		policyContents = settings.ownPolicy(t)
	}
	writeFile(t, h.policyPath, policyContents)
	writeFile(t, h.selectorPath, selectorDocument(t, settings.selector))
	if !settings.noForceFile {
		writeFile(t, h.forcePath, []byte(settings.forceList))
	}
	writeFile(t, h.prefixPath, []byte(settings.prefixes))

	args := Args{
		PolicyFile:         h.policyPath,
		SelectorFile:       h.selectorPath,
		ForceECHFile:       h.forcePath,
		ECHStateFile:       h.echStatePath,
		ForeignUpstream:    settings.foreignUpstream,
		CloudflareCIDRFile: h.prefixPath,
	}
	switch settings.blankArg {
	case "policy_file":
		args.PolicyFile = ""
	case "selector_file":
		args.SelectorFile = ""
	case "force_ech_file":
		args.ForceECHFile = ""
	case "ech_state_file":
		args.ECHStateFile = ""
	case "foreign_upstream":
		args.ForeignUpstream = ""
	case "cloudflare_cidr_file":
		args.CloudflareCIDRFile = ""
	}

	core, logs := observer.New(zap.WarnLevel)
	h.logs = logs
	client := h.upstream
	plugin, err := newPlugin(args, options{
		logger:          zap.New(core),
		now:             func() time.Time { return h.now },
		pollEvery:       testPollInterval,
		echRefreshEvery: settings.echRefreshEvery,
		newClient: func(string, upstream.Opt) (upstream.Upstream, error) {
			if settings.upstreamError != nil {
				return nil, settings.upstreamError
			}
			return client, nil
		},
	})
	if err != nil {
		return h, err
	}
	h.plugin = plugin
	return h, nil
}

// testPollInterval is how often the plugin's three watchers look at their files in
// these tests. It is the production default divided by a hundred, so a reload lands
// inside a test's deadline rather than inside its timeout, and it is the one thing
// about these tests that a deployment gets differently: nothing here asserts how
// often a file is read, only that a document which was published is served.
const testPollInterval = 5 * time.Millisecond

// --- running one query ---

// exec runs one query through the plugin with the harness's downstream sequence,
// and returns whatever the plugin left behind: the response it set, and the error
// it returned. An Exec error is what mosdns turns into SERVFAIL, and a nil
// response with no error is what it turns into REFUSED, so a test that wants to
// know which of the two a case produced has to look at both.
func (h *harness) exec(t *testing.T, name string, qtype uint16) (*dns.Msg, error) {
	t.Helper()
	qCtx := query_context.NewContext(newQuery(name, qtype))
	err := h.plugin.Exec(t.Context(), qCtx, h.next.walker())
	return qCtx.R(), err
}

// mustExec runs one query and insists it produced an answer.
func (h *harness) mustExec(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	response, err := h.exec(t, name, qtype)
	if err != nil {
		t.Fatalf("Exec %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	if response == nil {
		t.Fatalf("Exec %s %s left no response, which mosdns answers as REFUSED", name, dns.TypeToString[qtype])
	}
	return response
}

func newQuery(name string, qtype uint16) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	return query
}

// --- building the answers a test reasons about ---

// answerWith builds a NOERROR answer for one question, in the shape a recursive
// resolver hands back: the question echoed, and the records the test cares about.
func answerWith(name string, qtype uint16, records ...dns.RR) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(newQuery(name, qtype))
	for _, record := range records {
		response.Answer = append(response.Answer, record)
	}
	return response
}

// aRecord is one A answer with the TTL a real published record carries.
func aRecord(name, address string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(address),
	}
}

// aaaaRecord is one AAAA answer.
func aaaaRecord(name, address string, ttl uint32) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(address),
	}
}

// cnameRecord is one CNAME answer.
func cnameRecord(name, target string, ttl uint32) *dns.CNAME {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
		Target: dns.Fqdn(target),
	}
}

// rrsigRecord is one RRSIG over an A RRset, which is what a validating upstream
// puts beside an address this plugin is about to replace.
func rrsigRecord(name string, ttl uint32) *dns.RRSIG {
	return &dns.RRSIG{
		// The record's own type is RRSIG; TypeCovered is what names the RRset it
		// signs, and a fixture that got the two the wrong way round would be
		// counted as an address record by every assertion about record types.
		Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.ECDSAP256SHA256,
		Labels:      2,
		OrigTtl:     ttl,
		Expiration:  1788000000,
		Inception:   1787000000,
		KeyTag:      1234,
		SignerName:  "example.com.",
		// The library packs a signature as base64, so a fixture is written the
		// way a zone file carries it: "AQIDBA==" is these four bytes.
		Signature: "AQIDBA==",
	}
}

// nsecRecord is one NSEC denial, which a validating upstream adds beside a name
// that does not exist and which must not survive a rewrite of another RRset.
func nsecRecord(name string, ttl uint32) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
		NextDomain: "next.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
}

// httpsRecord builds an HTTPS record the way a zone publishes one.
func httpsRecord(name string, ttl uint32, priority uint16, target string, pairs ...dns.SVCBKeyValue) *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl},
		Priority: priority,
		Target:   target,
		Value:    pairs,
	}}
}

// localKey is a SvcParamKey in the range RFC 9460 reserves for private use, so no
// client has an opinion about it. It is the parameter a synthesis that copied
// only the keys it understood would lose.
const localKey = dns.SVCBKey(65400)

// echParam is the parameter the ECH source published, holding exactly the bytes
// echFixture decodes to.
func echParam(t *testing.T) *dns.SVCBECHConfig {
	t.Helper()
	return &dns.SVCBECHConfig{ECH: echFixture(t)}
}

// answerWithECH is the fake ECH client's answer: one HTTPS service mode carrying
// an ech parameter, the way a real ECH source publishes its key.
func answerWithECH(raw []byte, ttl uint32) func(dns.Question) (*dns.Msg, error) {
	return func(question dns.Question) (*dns.Msg, error) {
		return &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{question},
			Answer: []dns.RR{httpsRecord(question.Name, ttl, 1, ".",
				&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
				&dns.SVCBECHConfig{ECH: raw},
			)},
		}, nil
	}
}

// --- the files the plugin reads ---

// liveSelector is a selector whose winner has a proof window two minutes ahead of
// the harness clock, which is the shape a health check that has just passed
// publishes. The window is the short one on purpose: the two-minute health
// interval is what makes the gate track real liveness, and a fixture with a
// generous window would not exercise that.
func liveSelector() *state.Selector {
	provedAt := time.Date(2026, 9, 25, 11, 59, 0, 0, time.UTC)
	published := state.NewSelector(7, "auto", string(candidate.ProviderCloudflare), provedAt)
	published.WinnerIP = winnerAddress
	published.FallbackIP = "104.16.98.98"
	published.WinnerProofUntil = provedAt.Add(2 * time.Minute)
	published.ConfigSHA256 = strings.Repeat("a", 64)
	return &published
}

// provenFor is a selector whose window reaches until, for the tests about the ECH
// key's own lifetime: those move the clock past the health interval on purpose, and
// a window that closed with it would fail them for a reason that has nothing to do
// with the key.
func provenFor(until time.Time) *state.Selector {
	selector := liveSelector()
	selector.LastSuccess = until.Add(-time.Minute)
	selector.WinnerProofUntil = until
	return selector
}

// selectorDocument renders a selector the way the optimizer's writer does, so the
// plugin reads it through the same reader every other component uses.
func selectorDocument(t *testing.T, selector *state.Selector) []byte {
	t.Helper()
	if selector == nil {
		return []byte("{ this is not a document")
	}
	if err := selector.Validate(); err != nil {
		t.Fatalf("the fixture selector is not one the state package accepts: %v", err)
	}
	published := *selector
	published.SchemaVersion = state.SchemaVersion
	return mustMarshal(t, published)
}

// policyDocument renders a policy file with every field this plugin reads set to
// something explicit, so a test that changes one of them changes exactly one.
func policyDocument(t *testing.T, mutate func(*config.Policy)) []byte {
	t.Helper()
	policy := config.Defaults()
	policy.ECH.Sources = []string{"cloudflare-ech.com"}
	if mutate != nil {
		mutate(&policy)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the fixture policy is not one the config package accepts: %v", err)
	}
	document := "schema_version: 1\n" +
		"schedule: \"" + policy.Schedule + "\"\n" +
		"foreign:\n" +
		"  default_provider: \"" + policy.Foreign.DefaultProvider + "\"\n" +
		"  ecs: false\n" +
		"  concurrent: " + itoa(policy.Foreign.Concurrent) + "\n" +
		// The upstream list is rendered from the POLICY rather than written out,
		// for the reason the rest of this fixture is: a case that changes one field
		// must change exactly one. And it has to be here at all, because a policy
		// with no upstream list no longer validates -- which is the point of the
		// rule, but it means this fixture is a second reader of the new schema.
		"  upstreams:\n" +
		upstreamLines(policy.Foreign.Upstreams) +
		"cdn:\n" +
		"  ip_version: IPv4\n" +
		"  suppress_aaaa: " + yesNo(policy.CDN.SuppressAAAA) + "\n" +
		"  cloudflare:\n" +
		"    max_candidates: 512\n" +
		"  latency_candidate_count: 10\n" +
		"  combined:\n" +
		"    latency_top: 3\n" +
		"    bandwidth_top: 3\n" +
		"  switch_improvement_percent: 10\n" +
		"  health:\n" +
		"    interval: 120\n" +
		"    failure_threshold: 3\n" +
		"  bandwidth:\n" +
		"    daily_budget: 104857600\n" +
		"    per_candidate_limit: 10485760\n" +
		"    per_candidate_seconds: 3\n" +
		"ech:\n" +
		"  enabled: " + yesNo(policy.ECH.Enabled) + "\n" +
		"  failure_policy: " + policy.ECH.FailurePolicy + "\n" +
		"  stale_grace: " + itoa(policy.ECH.StaleGraceSeconds) + "\n" +
		"  sources:\n" +
		sourceLines(policy.ECH.Sources) +
		"dhcp:\n" +
		"  failure_policy: disable-current\n" +
		"cache:\n" +
		"  persistent_dump: false\n" +
		"foreign_cache:\n" +
		"  size: " + itoa(policy.ForeignCache.Size) + "\n" +
		"  ttl_max: " + itoa(policy.ForeignCache.TTLMax) + "\n" +
		"  ttl_min: " + itoa(policy.ForeignCache.TTLMin) + "\n"
	return []byte(document)
}

// upstreamLines renders the foreign route's upstream list, every entry of it. The
// omitted keys are omitted rather than written empty, which is what the config
// package's own marshaller does and therefore what the plugin reads in production.
func upstreamLines(upstreams []config.ForeignUpstream) string {
	out := ""
	for _, entry := range upstreams {
		out += "    - kind: " + string(entry.Kind) + "\n"
		out += "      name: " + entry.Name + "\n"
		if entry.Addr != "" {
			out += "      addr: \"" + entry.Addr + "\"\n"
		}
		// The list header comes once, before its items. Writing it inside the loop
		// is the bug this shape exists to prevent: two bootstrap resolvers would
		// emit the key twice and the strict decoder would refuse the document, so
		// the fixture would only ever work for an entry with at most one.
		if len(entry.Bootstrap) > 0 {
			out += "      bootstrap:\n"
			for _, resolver := range entry.Bootstrap {
				out += "        - " + resolver + "\n"
			}
		}
	}
	return out
}

// sourceLines renders the policy's ECH source list, every entry of it: a policy
// naming two sources is a case under test, and a fixture that quietly wrote only
// the first would make that case unreachable.
func sourceLines(sources []string) string {
	out := ""
	for _, source := range sources {
		out += "    - " + source + "\n"
	}
	return out
}

// writeFile publishes a file the way every writer in this project does: a
// temporary name in the same directory, then a rename, so a reader never sees a
// half-written document.
func writeFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, contents, 0o644); err != nil {
		t.Fatalf("write %s: %v", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatalf("replace %s: %v", path, err)
	}
}

// mustMarshal renders a state document as JSON, so a fixture reaches the plugin
// through the same reader every other component uses rather than as a literal
// this file would have to keep in step with the schema.
func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode the fixture document: %v", err)
	}
	return encoded
}

func yesNo(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

// --- reading a plugin's decisions, and waiting for a reload ---

// fixedSelector is a selector document the plugin is handed directly, so a test
// can present it with a combination the state package would have refused. The two
// properties under test that way are the plugin's own second opinion: a winner
// with no successful validation behind it, and a document that names no selection
// at all. Both are states the watcher cannot serve, which is the point -- the
// plugin must not depend on the watcher's validation for either of them.
type fixedSelector struct {
	published state.Selector
}

func (f fixedSelector) Snapshot() state.Selector { return f.published }

// writeSelector publishes a new selector document, the way the optimizer's writer
// does: a temporary file in the same directory, then a rename.
func (h *harness) writeSelector(t *testing.T, selector *state.Selector) {
	t.Helper()
	writeFile(t, h.selectorPath, selectorDocument(t, selector))
}

// selectorWithMapping is the live selector plus one per-hostname CloudFront
// mapping, which is the shape an apply publishes when it proved a distribution
// and the global address together.
func selectorWithMapping(hostname, address string) *state.Selector {
	selector := liveSelector()
	selector.CloudFront = map[string]string{hostname: address}
	return selector
}

// awaitSelector waits until the plugin is serving a selector document the test
// recognises. The watchers poll in the background, so this is a wait rather than a
// call: what is under test is that a new document reaches the next query, not that
// a particular goroutine was told to look. Each caller says which field it is
// waiting on, because a generation number on its own is not a change -- a
// document that differs only in its provider carries the same one.
func (h *harness) awaitSelector(t *testing.T, what string, accepted func(state.Selector) bool) {
	t.Helper()
	h.waitFor(t, what, func() bool { return accepted(h.plugin.selector.Snapshot()) })
}

// waitPolls waits for n poll intervals to pass, and fails the test if they do not
// inside the deadline. It is how a test that asserts a poller did NOT do something
// reaches a state where it would have: the number of polls is the evidence, and
// the only way to get it is to let them happen.
func (h *harness) waitPolls(t *testing.T, n int) {
	t.Helper()
	h.waitFor(t, itoa(n)+" poll intervals to pass", func() bool {
		return time.Since(h.started) >= time.Duration(n)*testPollInterval
	})
}

// waitFor polls a condition until it holds, and fails the test when it does not
// inside the deadline. It is the only waiting in this file, and every use of it is
// a background reload that a real deployment also has to wait for.
func (h *harness) waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// mustPack renders a message as it would go on the wire, so "unchanged" means the
// bytes a client would receive and not merely the same records in the same order.
func mustPack(t *testing.T, msg *dns.Msg) []byte {
	t.Helper()
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack the message: %v", err)
	}
	return packed
}

// --- assertions shared by more than one test ---

// addressesIn lists the addresses in an answer section, in the order the answer
// carried them, so a test can say which record set a client would have been given.
func addressesIn(t *testing.T, section []dns.RR) []string {
	t.Helper()
	out := []string{}
	for _, record := range section {
		switch typed := record.(type) {
		case *dns.A:
			out = append(out, typed.A.String())
		case *dns.AAAA:
			out = append(out, typed.AAAA.String())
		}
	}
	return out
}

func aAddresses(t *testing.T, section []dns.RR) []string {
	t.Helper()
	out := []string{}
	for _, record := range section {
		if typed, ok := record.(*dns.A); ok {
			out = append(out, typed.A.String())
		}
	}
	return out
}

// svcParam returns the SvcParamValue a record carries under one key, and reports
// whether the key is there at all. A missing key and a key that appears twice are
// different failures: the first is a parameter the client will not find.
func svcParam(t *testing.T, record *dns.HTTPS, key dns.SVCBKey) (dns.SVCBKeyValue, bool) {
	t.Helper()
	var found dns.SVCBKeyValue
	count := 0
	for _, pair := range record.Value {
		if pair.Key() == key {
			found = pair
			count++
		}
	}
	if count > 1 {
		t.Fatalf("the record carries SvcParamKey %d %d times, which no client can read", key, count)
	}
	return found, count == 1
}

// svcParamPresent asks whether one address parameter carries one address. It is
// written as a question about a specific address rather than as "which hint is
// there", because the case that matters is the one where two different addresses
// are in play and the record must carry one of them and not the other: a test that
// only checked that SOME hint was present would pass against a record pointing at
// an address nothing proved, which is the half of the defect that is a privacy
// claim rather than an availability one.
func svcParamPresent(t *testing.T, record *dns.HTTPS, key dns.SVCBKey, address string) bool {
	t.Helper()
	pair, present := svcParam(t, record, key)
	if !present {
		return false
	}
	ip := net.ParseIP(address).To4()
	if ip == nil {
		t.Fatalf("%s is not an IPv4 address, which is the only hint this release writes", address)
	}
	switch hint := pair.(type) {
	case *dns.SVCBIPv4Hint:
		return len(hint.Hint) == 1 && hint.Hint[0].Equal(ip)
	default:
		t.Fatalf("the %d parameter is %T, want *dns.SVCBIPv4Hint", key, pair)
		return false
	}
}

// svcCarried lists the SvcParamKeys a record carries, in the order it carries them,
// so a failure message names the record's shape instead of asserting it.
func svcCarried(t *testing.T, record *dns.HTTPS) string {
	t.Helper()
	keys := make([]string, 0, len(record.Value))
	for _, pair := range record.Value {
		keys = append(keys, pair.Key().String())
	}
	return strings.Join(keys, " ")
}

// countType reports how many records of one type a message carries anywhere.
func countType(msg *dns.Msg, rrtype uint16) int {
	total := 0
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, record := range section {
			if record.Header().Rrtype == rrtype {
				total++
			}
		}
	}
	return total
}

// --- Step 2: the address rewrite, and the window that authorises it ---

func TestHealthyWinnerReplacesTheCloudflareAddresses(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(cloudflareName, dns.TypeA,
		aRecord(cloudflareName, cloudflareAddress, 300),
		aRecord(cloudflareName, secondCloudflareAddress, 300),
	)

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := aAddresses(t, response.Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want exactly [%s]: the answer carries the address the selector proved, and nothing else", got, winnerAddress)
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
	if got := response.Answer[0].Header().Ttl; got != 300 {
		t.Fatalf("ttl = %d, want 300: the replacement carries the shortest lifetime of the records it replaced", got)
	}
}

// The object a cache owns must come back out of the plugin exactly as it went in.
// A rewrite applied in place is a rewrite the next reader of that cache inherits,
// and the next reader is a different client asking about a different name.
func TestTheCachedResponseIsNotModifiedInPlace(t *testing.T) {
	h := newHarness(t)
	cached := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	before := mustPack(t, cached)
	h.next.response = cached

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if response == cached {
		t.Fatal("the plugin returned the very object the cache handed it, so the rewrite was applied to the cache's own record")
	}
	if got := mustPack(t, cached); string(got) != string(before) {
		t.Fatalf("the cached object changed:\n before %s\n after  %s", before, got)
	}
	if got := aAddresses(t, response.Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("the client's addresses = %v, want [%s]", got, winnerAddress)
	}
}

// A response serving more than one network is nobody's to rewrite: replacing the
// whole set with one Cloudflare address would send every client to a network the
// response never named.
func TestMixedCDNResponseIsNotRewritten(t *testing.T) {
	h := newHarness(t)
	original := answerWith(cloudflareName, dns.TypeA,
		aRecord(cloudflareName, cloudflareAddress, 300),
		aRecord(cloudflareName, foreignAddress, 300),
	)
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the answer was changed:\n before %s\n after  %s", before, got)
	}
	if response.AuthenticatedData {
		t.Fatal("AD was cleared on a response this plugin did not modify")
	}
	if got := countType(response, dns.TypeRRSIG); got != 0 {
		t.Fatalf("the answer carries %d RRSIG records, and an untouched response must keep the ones it arrived with", got)
	}
}

// A name in no published range belongs to some other network, and the plugin has
// no opinion about it.
func TestNonCDNResponseIsNotRewritten(t *testing.T) {
	h := newHarness(t)
	original := answerWith(plainName, dns.TypeA, aRecord(plainName, foreignAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, plainName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the answer was changed:\n before %s\n after  %s", before, got)
	}
}

// The window's boundary is where a decision turns into a wrong address, so all
// three instants around it are pinned: one nanosecond past the end, the end
// itself, and one nanosecond inside.
func TestProofWindowOneNanosecondPastItsEndDoesNotRewrite(t *testing.T) {
	h := newHarness(t)
	h.now = time.Date(2026, 9, 25, 12, 1, 0, 1, time.UTC)
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("an expired proof window still rewrote the answer:\n before %s\n after  %s", before, got)
	}
}

func TestProofWindowExactlyAtItsEndDoesNotRewrite(t *testing.T) {
	h := newHarness(t)
	h.now = time.Date(2026, 9, 25, 12, 1, 0, 0, time.UTC)
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a window that ends now still rewrote the answer:\n before %s\n after  %s", before, got)
	}
}

func TestProofWindowOneNanosecondInsideItsEndRewrites(t *testing.T) {
	h := newHarness(t)
	// One nanosecond before the window closes, which is the last instant at which
	// the address in service is still the one the health check proved.
	h.now = time.Date(2026, 9, 25, 12, 0, 59, 999999999, time.UTC)
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := aAddresses(t, response.Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want [%s] one nanosecond before the window closes", got, winnerAddress)
	}
}

// A winner with no successful validation time is not a winner this router has any
// evidence about. The state package refuses to publish one, so this is the plugin
// holding the second door itself shut rather than trusting a document it did not
// write.
func TestSelectorWithoutALastSuccessNeverRewrites(t *testing.T) {
	h := newHarness(t)
	// The document the plugin is handed, which the state package would have
	// refused: an address in service with nothing behind it.
	h.plugin.selector = fixedSelector{state.Selector{
		SchemaVersion:    state.SchemaVersion,
		Generation:       9,
		Mode:             "auto",
		Provider:         "cloudflare",
		WinnerIP:         winnerAddress,
		WinnerProofUntil: h.now.Add(2 * time.Minute),
	}}
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a winner with no last_success still rewrote the answer:\n before %s\n after  %s", before, got)
	}
}

// A selector in the disabled mode has published no selection, and the plugin
// installs nothing on the strength of a document that says so.
func TestDisabledSelectorNeverRewrites(t *testing.T) {
	h := newHarness(t)
	h.plugin.selector = fixedSelector{disabledSelector()}
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a disabled selector still rewrote the answer:\n before %s\n after  %s", before, got)
	}
}

// The provider field is the selector's own statement about which group published
// the winner. A selector that published a CloudFront mapping is not a licence to
// install a global Cloudflare address, and there is no default to fall back on.
func TestCloudFrontProviderSelectorNeverInstallsTheGlobalWinner(t *testing.T) {
	h := newHarness(t)
	published := liveSelector()
	published.Provider = string(candidate.ProviderCloudFront)
	h.writeSelector(t, published)
	h.awaitSelector(t, "the cloudfront provider to be published", func(s state.Selector) bool {
		return s.Provider == string(candidate.ProviderCloudFront)
	})
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a cloudfront selector installed the global winner:\n before %s\n after  %s", before, got)
	}
}

// A CloudFront mapping is proved for one distribution, so it covers the name it
// was published for.
func TestCloudFrontMappingRewritesTheExactHostname(t *testing.T) {
	h := newHarness(t)
	mapped := selectorWithMapping(cloudFrontEntry, cloudFrontWinnerAddress)
	h.writeSelector(t, mapped)
	h.awaitSelector(t, "the CloudFront mapping to be published", func(s state.Selector) bool {
		return s.CloudFront[cloudFrontEntry] == cloudFrontWinnerAddress
	})
	original := answerWith(cloudFrontName, dns.TypeA, aRecord(cloudFrontName, cloudFrontAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudFrontName, dns.TypeA)

	if got := aAddresses(t, response.Answer); len(got) != 1 || got[0] != cloudFrontWinnerAddress {
		t.Fatalf("addresses = %v, want [%s]: the mapping's own address, for the hostname it was proved for", got, cloudFrontWinnerAddress)
	}
	if got := mustPack(t, original); string(got) != string(before) {
		t.Fatalf("the cached object changed:\n before %s\n after  %s", before, got)
	}
}

// A sibling of a mapped hostname is a different distribution, and an address
// proved for one of them means nothing behind the other.
func TestCloudFrontMappingLeavesAnotherHostnameAlone(t *testing.T) {
	h := newHarness(t)
	mapped := selectorWithMapping(cloudFrontEntry, cloudFrontWinnerAddress)
	h.writeSelector(t, mapped)
	h.awaitSelector(t, "the CloudFront mapping to be published", func(s state.Selector) bool {
		return s.CloudFront[cloudFrontEntry] == cloudFrontWinnerAddress
	})
	original := answerWith(cloudFrontSibling, dns.TypeA, aRecord(cloudFrontSibling, cloudFrontAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudFrontSibling, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a mapping for %s rewrote %s:\n before %s\n after  %s", cloudFrontName, cloudFrontSibling, before, got)
	}
}

// An ECH policy with ECH turned off has no list to honour: the name is queried
// like any other, and the strict short circuit is not this plugin's to take.
func TestDisabledECHPolicyIgnoresTheForceList(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.Enabled = false }
	})
	original := answerWith(forceECHName, dns.TypeA, aRecord(forceECHName, foreignAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, forceECHName, dns.TypeA)

	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want 1: with ECH disabled there is nothing to short circuit", h.next.calls)
	}
	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the answer was changed:\n before %s\n after  %s", before, got)
	}
	if asked := h.upstream.asked(); len(asked) != 0 {
		t.Fatalf("the ECH client was asked %d queries, want 0 with ECH disabled", len(asked))
	}
}

// A question type this plugin does not own is forwarded and left exactly as it
// came back, and the sequence is asked exactly once.
func TestUnsupportedQuestionTypeIsForwardedUnchanged(t *testing.T) {
	h := newHarness(t)
	original := answerWith(forceECHName, dns.TypeTXT, &dns.TXT{
		Hdr: dns.RR_Header{Name: forceECHName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=spf1 -all"},
	})
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, forceECHName, dns.TypeTXT)

	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want exactly 1", h.next.calls)
	}
	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the answer was changed:\n before %s\n after  %s", before, got)
	}
}

// --- the AAAA path, and the verdict it needs ---

// An AAAA answer carries no address the published IPv4 ranges can be checked
// against, so a name this plugin has never classified keeps every record it came
// with. This is the case that would fail first if the suppression path were
// reached on the question type alone.
func TestAAAAOfANonCDNNameIsNeverSuppressed(t *testing.T) {
	h := newHarness(t)
	original := answerWith(plainName, dns.TypeAAAA, aaaaRecord(plainName, "2606:4700::1111", 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, plainName, dns.TypeAAAA)

	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want 1", h.next.calls)
	}
	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a non-CDN name's IPv6 answer was suppressed:\n before %s\n after  %s", before, got)
	}
}

// A name whose A answer this router rewrote is a name whose IPv6 answer has
// nothing to offer: the client was sent to the selected address, and an AAAA
// record beside it would be a second, unproved place to go.
func TestAAAAIsSuppressedForANameWhoseAAnswerWasRewritten(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	h.mustExec(t, cloudflareName, dns.TypeA)

	h.next.response = answerWith(cloudflareName, dns.TypeAAAA, aaaaRecord(cloudflareName, "2606:4700::1111", 300))
	response := h.mustExec(t, cloudflareName, dns.TypeAAAA)

	if len(response.Answer) != 0 {
		t.Fatalf("answer = %v, want no records: the A answer for this name was rewritten", addressesIn(t, response.Answer))
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
}

// The record of a name is scoped to the generation that produced it, so a new
// selection starts with nothing proved and every IPv6 answer is the upstream's
// own until an A answer says otherwise.
func TestAAAAIsNotSuppressedOnTheStrengthOfThePreviousGeneration(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	h.mustExec(t, cloudflareName, dns.TypeA)

	replacement := liveSelector()
	replacement.Generation = 8
	h.writeSelector(t, replacement)
	h.awaitSelector(t, "the new selector generation", func(s state.Selector) bool {
		return s.Generation == replacement.Generation
	})

	original := answerWith(cloudflareName, dns.TypeAAAA, aaaaRecord(cloudflareName, "2606:4700::1111", 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeAAAA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a verdict from the previous generation suppressed an IPv6 answer:\n before %s\n after  %s", before, got)
	}
}

// --- Step 1: what the force-ECH list does to an address query ---

// Nothing. A listed name's A and AAAA queries are asked downstream and answered
// exactly as an unlisted name's are.
//
// They used to be answered from this router's own empty answer without asking
// anybody, on the reasoning that a strict force-ECH name must not have its address
// disclosed. That reasoning does not hold here, and the cost of acting on it was
// the feature defeating itself. cdn_rewrite runs only in the foreign path, so the
// HTTPS query that named the domain has ALREADY gone to the foreign resolver -- the
// suppression never had anything to withhold from the party that mattered, because
// that party had the domain name and the SNI before the A lookup was made. What it
// did remove is the client's address, and a client with no address has nothing to
// connect to, so the encrypted ClientHello this package works to produce was never
// sent to anything.
//
// The comparison is against an unlisted name rather than against a literal, because
// "the same as any other name" is the entire claim. An expectation written out
// would pass against an implementation that suppressed A for one name and not
// another.
func TestTheForceECHListMakesNoDifferenceToAnAddressQuery(t *testing.T) {
	for _, tt := range []struct {
		name  string
		qtype uint16
		// reply builds the upstream's answer for a name, because the record has to
		// carry the name it was asked about: the classifier reads the name off the
		// record, not off the question.
		reply func(string) []dns.RR
		// wantAddress is whether the answer must carry one. AAAA is suppressed by
		// cdn.suppress_aaaa, which is a different mechanism from the short circuit
		// this group deleted and is still wanted: an empty AAAA answer reached
		// through the resolver is the suppression working, and the same empty answer
		// with nothing asked is the bug.
		wantAddress bool
	}{
		{
			name:  "A",
			qtype: dns.TypeA,
			reply: func(name string) []dns.RR {
				return []dns.RR{aRecord(name, cloudflareAddress, 300)}
			},
			wantAddress: true,
		},
		{
			name:  "AAAA",
			qtype: dns.TypeAAAA,
			reply: func(name string) []dns.RR {
				return []dns.RR{aaaaRecord(name, "2606:4700::1111", 300)}
			},
			wantAddress: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listed := newHarness(t)
			unlisted := newHarness(t)
			listed.next.response = answerWith(forceECHName, tt.qtype, tt.reply(forceECHName)...)
			unlisted.next.response = answerWith(cloudflareName, tt.qtype, tt.reply(cloudflareName)...)

			got := listed.mustExec(t, forceECHName, tt.qtype)
			ordinary := unlisted.mustExec(t, cloudflareName, tt.qtype)

			if listed.next.calls != 1 {
				t.Fatalf("the downstream sequence ran %d times for a listed name, want 1: the force-ECH list is a statement about the HTTPS answer and says nothing about %s",
					listed.next.calls, dns.TypeToString[tt.qtype])
			}
			if got.Rcode != ordinary.Rcode {
				t.Errorf("rcode = %s for a listed name, %s for an unlisted one: the list changed the shape of the answer",
					dns.RcodeToString[got.Rcode], dns.RcodeToString[ordinary.Rcode])
			}
			if a, b := addressesIn(t, got.Answer), addressesIn(t, ordinary.Answer); !reflect.DeepEqual(a, b) {
				t.Errorf("addresses = %v for a listed name, %v for an unlisted one: the list changed what the name resolves to", a, b)
			}
			if tt.wantAddress && len(addressesIn(t, got.Answer)) == 0 {
				t.Errorf("a listed name's %s was answered with nothing at all: a client with no address has nothing to connect to, so the encrypted ClientHello this package builds for it is never sent",
					dns.TypeToString[tt.qtype])
			}
			if asked := listed.upstream.asked(); len(asked) != 0 {
				t.Errorf("the ECH client was asked %d queries by an address lookup, want 0: the key belongs to the HTTPS answer only", len(asked))
			}
		})
	}
}

// A name the operator did not list is an ordinary query, and a strict policy
// changes nothing about it.
func TestStrictPolicyStillAsksDownstreamForANameItDoesNotForce(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))

	h.mustExec(t, cloudflareName, dns.TypeA)

	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want 1", h.next.calls)
	}
}

// --- Step 2 and Step 3: the HTTPS answer a force-ECH name gets ---

// theHTTPSIn is the answer an upstream publishes for a force-ECH name: a service
// mode under its own name with an ipv4hint, the parameters a client needs to reach
// it, and a local parameter no client has an opinion about. It is the shape the
// synthesis has to read without losing what it may keep.
func theHTTPSIn(t *testing.T, name string) *dns.Msg {
	t.Helper()
	service := httpsRecord(name, 300, 1, ".",
		&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
		&dns.SVCBPort{Port: 8443},
		&dns.SVCBDoHPath{Template: "/dns-query{?dns}"},
		&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(cloudflareAddress)}},
		&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("2606:4700::1111")}},
		&dns.SVCBLocal{KeyCode: localKey, Data: []byte{0xde, 0xad}},
	)
	upstream := answerWith(name, dns.TypeHTTPS, service)
	upstream.AuthenticatedData = true
	upstream.CheckingDisabled = true
	upstream.Answer = append(upstream.Answer, rrsigForHTTPS(name, 300))
	upstream.Ns = append(upstream.Ns, nsecRecord(name, 300))
	return upstream
}

// rrsigForHTTPS is a signature over the HTTPS RRset the synthesis replaces, which
// is the record that must not survive it.
func rrsigForHTTPS(name string, ttl uint32) *dns.RRSIG {
	signature := rrsigRecord(name, ttl)
	signature.TypeCovered = dns.TypeHTTPS
	return signature
}

// theSynthesized is the one record a strict force-ECH answer must carry, found in
// the answer section.
func theSynthesized(t *testing.T, response *dns.Msg) *dns.HTTPS {
	t.Helper()
	found := []*dns.HTTPS{}
	for _, rr := range response.Answer {
		if record, ok := rr.(*dns.HTTPS); ok {
			found = append(found, record)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the answer carries %d HTTPS records, want exactly one", len(found))
	}
	return found[0]
}

func TestStrictForcedHTTPSGetsAnEncryptedServiceModeForTheProvedAddress(t *testing.T) {
	h := newHarness(t)
	upstream := theHTTPSIn(t, forceECHName)
	before := mustPack(t, upstream)
	h.next.response = upstream

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if response == nil {
		t.Fatal("the plugin left no response, which mosdns answers as REFUSED")
	}
	record := theSynthesized(t, response)
	if record.Priority != 1 {
		t.Fatalf("priority = %d, want 1: a priority of 0 is an alias, which a client reads as a delegation", record.Priority)
	}
	if record.Target != "." {
		t.Fatalf("target = %q, want %q", record.Target, ".")
	}
	if got := record.Hdr.Name; got != forceECHName {
		t.Fatalf("owner = %q, want the queried name %q", got, forceECHName)
	}
	if _, present := svcParam(t, record, dns.SVCB_IPV6HINT); present {
		t.Fatal("the record carries an ipv6hint, and this release installs no IPv6 address")
	}
	hint, present := svcParam(t, record, dns.SVCB_IPV4HINT)
	if !present {
		t.Fatal("the record carries no ipv4hint, so the client has nothing to connect to")
	}
	if got := hint.(*dns.SVCBIPv4Hint).Hint; len(got) != 1 || !got[0].Equal(net.ParseIP(winnerAddress)) {
		t.Fatalf("ipv4hint = %v, want exactly [%s]", got, winnerAddress)
	}
	ech, present := svcParam(t, record, dns.SVCB_ECHCONFIG)
	if !present {
		t.Fatal("the record carries no ech parameter, so a client would connect in the clear")
	}
	if got := ech.(*dns.SVCBECHConfig).ECH; string(got) != string(echFixture(t)) {
		t.Fatalf("ech = %d bytes, want the %d bytes the source published", len(got), len(echFixture(t)))
	}
	mandatory, present := svcParam(t, record, dns.SVCB_MANDATORY)
	if !present {
		t.Fatal("the record carries no mandatory list, so a client that ignored ech could connect in the clear")
	}
	codes := mandatory.(*dns.SVCBMandatory).Code
	if len(codes) != 1 || codes[0] != dns.SVCB_ECHCONFIG {
		t.Fatalf("mandatory = %v, want exactly [ech]", codes)
	}
	// The parameters a client needs and this router has no opinion about are
	// inherited. The local one is here because only a synthesis that copies the
	// keys it does not understand loses it.
	alpn, present := svcParam(t, record, dns.SVCB_ALPN)
	if !present || strings.Join(alpn.(*dns.SVCBAlpn).Alpn, ",") != "h2,h3" {
		t.Fatalf("alpn = %v, want the upstream's h2,h3", alpn)
	}
	if _, present := svcParam(t, record, dns.SVCB_PORT); !present {
		t.Fatal("the upstream's port was dropped")
	}
	if _, present := svcParam(t, record, dns.SVCB_DOHPATH); !present {
		t.Fatal("the upstream's dohpath was dropped")
	}
	local, present := svcParam(t, record, localKey)
	if !present || string(local.(*dns.SVCBLocal).Data) != "\xde\xad" {
		t.Fatalf("the local parameter = %v, want the upstream's own bytes", local)
	}
	if got := mustPack(t, upstream); string(got) != string(before) {
		t.Fatalf("the cached object changed:\n before %s\n after  %s", before, got)
	}
}

// A record this router wrote is not the record the upstream signed, so the message
// must not go on claiming to be validated. This is the rule the rewrite package
// applies, and this test is what would fail if the plugin ever grew a second copy
// of it that a path forgot to call.
func TestAModifiedHTTPSAnswerDropsItsSignaturesAndItsADBit(t *testing.T) {
	h := newHarness(t)
	h.next.response = theHTTPSIn(t, forceECHName)

	response := h.mustExec(t, forceECHName, dns.TypeHTTPS)

	if response.AuthenticatedData {
		t.Fatal("AD survived a rewrite, so a client is told a record this router invented was validated by the zone")
	}
	for _, rrtype := range []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3} {
		if got := countType(response, rrtype); got != 0 {
			t.Fatalf("the answer carries %d %s records, and a modified response carries none", got, dns.TypeToString[rrtype])
		}
	}
	if !response.CheckingDisabled {
		t.Fatal("CD was cleared, and it is the client's own bit: a client that asked not to be checked stays that way")
	}
}

// A closed proof window used to be fatal under strict, and that was the defect
// ruling 191(a) names: a window that has closed means the selector has no address,
// and a strict force-ECH name was then answered SERVFAIL -- which is worse than not
// listing the domain at all, because an unlisted name still gets a working ech-less
// answer. It stayed fatal on a real install because nothing ever produces a winner
// there: `mosdns-cdnctl test --apply` is the only producer of one, and neither the
// installer nor the postinst calls it.
//
// So a closed window now costs the client the selector's address and nothing else.
// The answer is a service mode carrying the ECH key, pointed at the address the
// UPSTREAM published, because that is a claim somebody made. What it must not be is
// a refusal, and it must not be a record pointing at an address nothing proved.
func TestAClosedProofWindowStillAnswersWithTheKeyAndTheUpstreamsOwnAddress(t *testing.T) {
	h := newHarness(t)
	// Five minutes past the two-minute window the default selector carries, so the
	// selector has no live winner at all.
	h.now = time.Date(2026, 9, 25, 12, 5, 0, 0, time.UTC)
	h.next.response = theHTTPSIn(t, forceECHName)

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err != nil {
		t.Fatalf("Exec refused a strict force-ECH name over a selector that has no address: %v", err)
	}
	record := theSynthesized(t, response)

	ech, present := svcParam(t, record, dns.SVCB_ECHCONFIG)
	if !present {
		t.Fatal("the answer carries no ech parameter: the key is the whole point and it is the only thing that must never be dropped for want of an address")
	}
	if got := string(ech.(*dns.SVCBECHConfig).ECH); got != string(echFixture(t)) {
		t.Fatal("the answer carries a key other than the one the source published")
	}
	// The address in it is the upstream's, and the winner's is nowhere: the window
	// that authorised the winner has closed, so installing it would be installing an
	// address this router cannot vouch for -- which is the one thing the hint has
	// never been for.
	if !svcParamPresent(t, record, dns.SVCB_IPV4HINT, cloudflareAddress) {
		t.Errorf("the record does not carry the upstream's own published address %s: %s", cloudflareAddress, svcCarried(t, record))
	}
	if svcParamPresent(t, record, dns.SVCB_IPV4HINT, winnerAddress) {
		t.Errorf("the record points at %s, which a closed proof window does not authorise", winnerAddress)
	}
	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want 1", h.next.calls)
	}
	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("the ECH client was asked %d queries, want 1: the key is still needed with no selector address", len(asked))
	}
}

// The fallback arm is the one a caller gets wrong by returning as soon as it sees
// an error: the upstream's own record comes back, and a caller that throws it away
// turns a working fallback domain into a SERVFAIL through this router's own health
// gate. At this layer the refusal is reported in the LOG and Exec returns nil,
// which is the whole contract -- the answer is the upstream's and forwarding it is
// not an error condition, so returning one would make mosdns discard a good answer.
//
// What triggers the arm is now the key and nothing else. A closed proof window used
// to be the other trigger, and it was the more common one on a real install, where
// nothing ever populates the selector; ruling 191(a) removed it because refusing
// over an address this router does not own cost every force-ECH name its answer.
// So the case sets up the one refusal that survives: an ECH source that cannot be
// read at all.
func TestFallbackForcedHTTPSWithNoKeyKeepsTheUpstreamRecord(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.FailurePolicy = "fallback" }
	})
	upstream := theHTTPSIn(t, forceECHName)
	before := mustPack(t, upstream)
	h.next.response = upstream
	// The source is unreachable from the first query, so there is never a key.
	h.upstream.failWith(errors.New("the listener is gone"))

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err != nil {
		t.Fatalf("Exec returned %v: the fallback arm forwards the upstream's answer and reports the refusal in the log, and an error here makes mosdns throw that answer away", err)
	}
	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want exactly 1", h.next.calls)
	}
	if response == nil {
		t.Fatal("the plugin left no response, which mosdns answers as REFUSED: the caller returned on the error and threw away the answer the upstream published")
	}
	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the upstream's own record was not kept:\n before %s\n after  %s", before, got)
	}
	if _, present := svcParam(t, theSynthesized(t, response), dns.SVCB_ECHCONFIG); present {
		t.Error("a key was invented for a record there was no key to put in")
	}
	if got := theSynthesized(t, response); len(got.Value) == 0 {
		t.Fatal("the kept record carries no parameters at all")
	}
	// And the refusal is still said out loud. Forwarding the upstream's record is
	// safe; doing it silently is how a broken ECH source goes unnoticed for weeks.
	if !h.loggedText("the ECH source could not be read") {
		t.Error("the ECH source failure was swallowed: a caller reading only the log cannot tell a fallback from a rewrite")
	}
}

// An upstream that published nothing for the name is not a reason to hand a
// force-ECH client nothing: the key and the address do not depend on what it would
// have said. The record written from nothing says so by naming the two protocols a
// TLS edge serves, and by claiming no lifetime at all.
func TestForcedHTTPSSynthesizesAMinimalServiceModeWhenTheUpstreamPublishedNone(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(forceECHName, dns.TypeHTTPS)

	response := h.mustExec(t, forceECHName, dns.TypeHTTPS)

	record := theSynthesized(t, response)
	if len(record.Value) == 0 {
		t.Fatal("the synthesized record carries no parameters")
	}
	alpn, present := svcParam(t, record, dns.SVCB_ALPN)
	if !present || strings.Join(alpn.(*dns.SVCBAlpn).Alpn, ",") != "h2,h3" {
		t.Fatalf("alpn = %v, want h2,h3: a record with no alpn tells a client the service speaks http/1.1 alone", alpn)
	}
	if _, present := svcParam(t, record, dns.SVCB_ECHCONFIG); !present {
		t.Fatal("the synthesized record carries no ech parameter")
	}
	if got := record.Hdr.Ttl; got != 0 {
		t.Fatalf("ttl = %d, want 0: there was no upstream lifetime behind this record to inherit", got)
	}
	if len(response.Ns) != 0 {
		t.Fatalf("authority = %v, want nothing: a synthesized positive answer claims no denial of existence", response.Ns)
	}
}

// A name the upstream delegated is described under another name, and a service
// mode synthesized here would claim a service the upstream says this name does
// not have. Under strict that is fatal, and the plugin does not work around it by
// following the chain: the chain belongs to the caller that resolves names.
func TestStrictForcedHTTPSRefusesANameTheUpstreamDelegated(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(forceECHName, dns.TypeHTTPS, cnameRecord(forceECHName, "elsewhere.example.net.", 300))

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err == nil {
		t.Fatal("Exec returned no error, so a delegated name was synthesized into")
	}
	if !errors.Is(err, dnsrewrite.ErrDelegatedName) {
		t.Fatalf("error = %v, want one wrapping ErrDelegatedName", err)
	}
	if response != nil {
		t.Fatalf("a refused delegation was set on the context: %v", response.Answer)
	}
}

// The other half of the same rule: a fallback name that the upstream delegated
// keeps the upstream's own answer, which sends the client to the name the service
// really has.
func TestFallbackForcedHTTPSKeepsTheAnswerForADelegatedName(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.FailurePolicy = "fallback" }
	})
	delegated := answerWith(forceECHName, dns.TypeHTTPS, cnameRecord(forceECHName, "elsewhere.example.net.", 300))
	before := mustPack(t, delegated)
	h.next.response = delegated

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the upstream's delegation was not kept:\n before %s\n after  %s", before, got)
	}
}

// A name the operator did not list keeps its own HTTPS record whole, signatures
// and all. The DNSSEC rule belongs to a message this plugin changed, and an answer
// it did not change must arrive with everything it arrived with.
func TestAnUntouchedHTTPSAnswerKeepsEveryRecordItArrivedWith(t *testing.T) {
	h := newHarness(t)
	untouched := theHTTPSIn(t, untouchedName)
	before := mustPack(t, untouched)
	h.next.response = untouched

	response := h.mustExec(t, untouchedName, dns.TypeHTTPS)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("an answer this plugin did not modify changed:\n before %s\n after  %s", before, got)
	}
	if !response.AuthenticatedData {
		t.Fatal("AD was cleared on a response this plugin did not modify")
	}
	if got := countType(response, dns.TypeRRSIG); got != 1 {
		t.Fatalf("the answer carries %d RRSIG records, want the one it arrived with", got)
	}
	if got := countType(response, dns.TypeNSEC); got != 1 {
		t.Fatalf("the answer carries %d NSEC records, want the one it arrived with", got)
	}
}

// --- Step 3: the ECH fetch itself ---

// The fetch is a question this router asks its own listener, and it is a question
// about the source's own HTTPS record. Every property of it is asserted here
// because each is a way the key could be fetched wrongly: the wrong question type
// reads a record with no ech parameter, a borrowed query id is a transaction
// somebody else is waiting on, and a fetch that went through the main sequence
// would be classified and possibly rewritten like any other answer.
func TestTheECHFetchAsksTheSourceForItsHTTPSRecordOverItsOwnClient(t *testing.T) {
	h := newHarness(t)
	h.next.response = theHTTPSIn(t, forceECHName)

	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	asked := h.upstream.asked()
	if len(asked) != 1 {
		t.Fatalf("the ECH client was asked %d queries, want 1: %+v", len(asked), asked)
	}
	question := asked[0].question
	if question.Qtype != dns.TypeHTTPS {
		t.Fatalf("the ECH query was for %s, want HTTPS, which is type 65: the key is in the ech parameter of an HTTPS record",
			dns.TypeToString[question.Qtype])
	}
	if question.Name != "cloudflare-ech.com." {
		t.Fatalf("the ECH query was for %q, want the source the policy names", question.Name)
	}
	if question.Qclass != dns.ClassINET {
		t.Fatalf("the ECH query was in class %d, want IN", question.Qclass)
	}
	if asked[0].id == 0 {
		t.Fatal("the ECH query carried id 0, which is a fixed fingerprint on every key this router fetches")
	}
	if h.next.calls != 1 {
		t.Fatalf("the main sequence ran %d times, want 1: the ECH fetch must not re-enter it", h.next.calls)
	}
}

// A key is fetched as often as its TTL says and no more often, so two queries
// inside one lifetime are one fetch.
func TestTheKeyIsFetchedOnceWhileItIsFresh(t *testing.T) {
	h := newHarness(t)
	h.next.response = theHTTPSIn(t, forceECHName)

	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("the ECH client was asked %d queries for two queries inside one TTL, want 1", len(asked))
	}
}

func TestARefreshIsDueAfterThePublishedTTL(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.echAnswer = answerWithECH(echFixture(t), 300)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	// One second before the published lifetime is up, the held key is still the
	// one in service.
	h.now = h.now.Add(299 * time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("the ECH client was asked %d queries inside the published TTL, want 1", len(asked))
	}
	// Two seconds after it, the key is past its lifetime and a new one is due.
	h.now = h.now.Add(2 * time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	if asked := h.upstream.asked(); len(asked) != 2 {
		t.Fatalf("the ECH client was asked %d queries after the published TTL, want 2", len(asked))
	}
}

// The cadence does not move with the TTL. It used to -- the lifetime was
// max(TTL, 60s) -- and a source publishing anything under that floor was protected
// from being asked once per client query, which was the whole reason the floor
// existed. The cadence is now a fixed five minutes (echCadence, and
// TestTheCadenceIsTheOneTheseCasesHold pins it), so the property that matters is
// this one: whatever a source publishes, the client-query rate never sets the
// refresh rate.
//
// The five-second TTL is the hostile case for it. A scheduler keyed on the TTL would
// ask a source publishing five seconds sixty times a minute, on the listener this
// router forwards every foreign query through, and the floor is what stopped that;
// a scheduler keyed on the cadence asks it once. The cost, stated because it is a
// real one, is that a publisher withdrawing its key is noticed up to one interval
// late rather than up to its own TTL -- which is the trade the fixed cadence makes
// deliberately, and which the measured 295-300s TTL puts inside one interval anyway.
func TestTheRefreshRateIsTheCadenceWhateverTheSourcePublishes(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.echAnswer = answerWithECH(echFixture(t), 5)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	// A minute is twelve times the five-second TTL the source published, and eight
	// client queries' worth of asking if the TTL were the schedule.
	for range 8 {
		h.now = h.now.Add(5 * time.Second)
		h.mustExec(t, forceECHName, dns.TypeHTTPS)
	}
	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("a source publishing a 5 second TTL was asked %d times over 40 seconds, want 1: the refresh rate is the cadence, and a TTL-keyed one spends a query per client query on this router's listener", len(asked))
	}

	// One second short of the interval it is still the held key.
	h.now = h.now.Add(echCadence - 41*time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("the ECH client was asked %d times one second before the cadence elapsed, want 1", len(asked))
	}

	// And at the interval a new source is due.
	h.now = h.now.Add(2 * time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	if asked := h.upstream.asked(); len(asked) != 2 {
		t.Fatalf("the ECH client was asked %d times one second past the cadence, want 2", len(asked))
	}
}

// The grace is the difference between a source that was briefly unreachable and a
// source that is gone: inside it the last key is still served, and a refresh that
// fails does not throw it away.
func TestTheLastKeyIsStillServedInsideItsStaleGrace(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.StaleGraceSeconds = 900 }
		c.echAnswer = answerWithECH(echFixture(t), 300)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	// 299 seconds of lifetime and 899 seconds of grace: one second before the
	// grace ends.
	h.now = h.now.Add(299*time.Second + 899*time.Second)
	response := h.mustExec(t, forceECHName, dns.TypeHTTPS)

	record := theSynthesized(t, response)
	ech, present := svcParam(t, record, dns.SVCB_ECHCONFIG)
	if !present {
		t.Fatal("the answer carries no ech parameter one second before the stale grace ends")
	}
	if string(ech.(*dns.SVCBECHConfig).ECH) != string(echFixture(t)) {
		t.Fatal("the answer carries a key other than the one that was fetched")
	}
}

// A refresh that fails while the held key is still inside its grace is the case
// the grace exists for: the source is unreachable, the key it published is not
// expired, and the answer a force-ECH client gets is that key.
func TestAFailedRefreshInsideTheGraceKeepsTheHeldKey(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.StaleGraceSeconds = 900 }
		c.echAnswer = answerWithECH(echFixture(t), 300)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	h.upstream.failWith(errors.New("the listener is gone"))

	// One second past the key's own lifetime, and well inside the grace.
	h.now = h.now.Add(301 * time.Second)
	response := h.mustExec(t, forceECHName, dns.TypeHTTPS)

	ech, present := svcParam(t, theSynthesized(t, response), dns.SVCB_ECHCONFIG)
	if !present || string(ech.(*dns.SVCBECHConfig).ECH) != string(echFixture(t)) {
		t.Fatal("a refresh that failed one second past the key's lifetime threw the held key away")
	}
	if asked := h.upstream.asked(); len(asked) != 2 {
		t.Fatalf("the ECH client was asked %d times, want 2: a key past its own lifetime must be refreshed before it is served", len(asked))
	}
}

func TestStrictForcedHTTPSFailsClosedAfterTheStaleGrace(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.StaleGraceSeconds = 900 }
		c.echAnswer = answerWithECH(echFixture(t), 300)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	// The source has stopped answering and the grace is over, so there is no key.
	h.upstream.failWith(errors.New("the listener is gone"))
	h.now = h.now.Add(300*time.Second + 901*time.Second)

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err == nil {
		t.Fatal("Exec returned no error, so a strict name was answered with no ECH key at all")
	}
	if !errors.Is(err, dnsrewrite.ErrNoECHConfig) {
		t.Fatalf("error = %v, want one wrapping ErrNoECHConfig", err)
	}
	if response != nil {
		t.Fatalf("a strict answer with no key was set on the context: %v", response.Answer)
	}
}

// A refusal nobody can see is not a refusal an operator can act on, and this one is
// the one they most need to act on: a source publishing a public name the router
// will not install is a misconfiguration of `ech.sources`, and the two names in the
// message are the only place both the offending source and the name it is being held
// to appear together.
//
// It used to assert that BOTH sources were read and the pair refused, which was the
// whole refresh failing over one disagreement -- the shape ruling 191(c) records as
// the reason one bad source used to take every force-ECH domain on the router down.
// The refusal itself is now held by
// TestASourcePublishingADifferentPublicNameDoesNotReplaceTheHeldKey; this holds that
// it is said out loud, and it says it with both names because "the sources disagree"
// is not something an operator can act on from a log line.
func TestARefusedReplacementNamesBothTheSourceAndTheHeldKey(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = rotationSources
		c.echAnswer = func(question dns.Question) (*dns.Msg, error) {
			// A public name is a name, so it is the source's name as a person writes
			// one: without the dot the wire carries. This is how defo.ie behaves --
			// it publishes cover.defo.ie where the Cloudflare sources publish
			// cloudflare-ech.com -- and an operator who adds it by mistake sees this.
			publicName := strings.TrimSuffix(question.Name, ".")
			return &dns.Msg{
				MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
				Question: []dns.Question{question},
				Answer: []dns.RR{httpsRecord(question.Name, 300, 1, ".",
					&dns.SVCBECHConfig{ECH: echFixtureFor(t, publicName)},
				)},
			}, nil
		}
	})
	h.next.response = theHTTPSIn(t, forceECHName)

	// The first fetch holds a key named after the first source; the interval after
	// reaches the second, which names itself, and that is the disagreement.
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	h.now = h.now.Add(echCadence)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	for _, want := range []string{
		echSourceSecond,
		"cdn.discordapp.com", // the name it published
		echSourceFirst,
		"cloudflare-ech.com", // the name in the key that is still in service
	} {
		if !h.loggedText(want) {
			t.Errorf("the refusal does not name %q, and an operator cannot act on a disagreement they cannot see:\n%s",
				want, h.routerDiagnostics())
		}
	}
}

// routerDiagnostics is every logged line, for a failure that has to quote the log it
// is complaining about.
func (h *harness) routerDiagnostics() string {
	var out strings.Builder
	for _, entry := range h.logs.All() {
		fmt.Fprintf(&out, "  %s %v\n", entry.Message, entry.ContextMap())
	}
	return out.String()
}

// --- the ECH source rotation ---
//
// Three sources, one request every five minutes, so each of them is asked once
// every fifteen. The three names below are not fixtures chosen for symmetry:
// they are the three MEASURED on 2026-10-02 to publish a BYTE-IDENTICAL
// ECHConfigList, all of them carrying public_name cloudflare-ech.com, which is
// what makes rotation between them safe and what makes a fourth name a
// decision rather than an addition.

const (
	echSourceFirst  = "cloudflare-ech.com"
	echSourceSecond = "cdn.discordapp.com"
	echSourceThird  = "discordapp.com"
)

// echCadence is the interval these cases hold the rotation to. It is written out here
// rather than taken from the plugin's own constant on purpose: a test whose
// expectation is imported from the code under test passes whatever that code says,
// and the cadence is the whole subject of this group. TestTheCadenceIsTheOneThese
// CasesHold pins the production constant to it, so changing the cadence has to
// change a case rather than quietly move every expectation with it.
const echCadence = 5 * time.Minute

// TestTheCadenceIsTheOneTheseCasesHold is that pin. Five minutes is the product
// decision ruling 191(c) records -- one request every five minutes over three
// interchangeable sources, so each domain is asked once every fifteen -- and it is
// written here rather than only in the plugin so that a change to it is a change
// somebody made on purpose.
func TestTheCadenceIsTheOneTheseCasesHold(t *testing.T) {
	if echRotationInterval != echCadence {
		t.Fatalf("the refresh cadence = %s, want %s: one request per interval over three sources is what makes each domain cost one fifteenth of the refresh traffic, and it is a decision rather than a consequence",
			echRotationInterval, echCadence)
	}
}

// echSourceTTL is what a source publishes. cloudflare-ech.com's HTTPS TTL
// MEASURED 295-300s, so the fixture is the real number rather than one picked to
// make the interval convenient -- which is also why the interval and the TTL are
// the same size here, so a case about WHICH source is asked cannot be satisfied or
// broken by a change to WHEN it is asked.
const echSourceTTL = 300

// rotationSources is the policy for the rotation cases: the three measured names,
// in the order the rotation walks them.
func rotationSources(p *config.Policy) {
	p.ECH.Sources = []string{echSourceFirst, echSourceSecond, echSourceThird}
}

// rotationAnswer is what the three sources publish. The key each one is given is
// passed in per source rather than baked in, because a disagreement is the case
// the rotation has to survive and an answer that cannot disagree cannot test it.
// A source the map does not name is an error rather than a key: an unlisted
// source answering here would be a fourth source the rotation is not making, and
// it would show up in the query list and read as one that was.
func rotationAnswer(t *testing.T, keys map[string][]byte) func(dns.Question) (*dns.Msg, error) {
	t.Helper()
	return func(question dns.Question) (*dns.Msg, error) {
		name := strings.TrimSuffix(question.Name, ".")
		raw, ok := keys[name]
		if !ok {
			return nil, fmt.Errorf("%s was asked but no key was given to it to publish", name)
		}
		return &dns.Msg{
			MsgHdr:   dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Question: []dns.Question{question},
			Answer: []dns.RR{httpsRecord(question.Name, echSourceTTL, 1, ".",
				&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
				&dns.SVCBECHConfig{ECH: raw},
			)},
		}, nil
	}
}

// askedSources is the order the ECH client was queried in, as bare names. The
// rotation is a property of WHICH source is asked and in WHAT ORDER, so the
// evidence is the sequence: a count cannot tell a rotation that returned to the
// first source from one that never left it, and a set cannot tell them from one
// that asked all three at once.
func askedSources(h *harness) []string {
	asked := h.upstream.asked()
	names := make([]string, 0, len(asked))
	for _, query := range asked {
		names = append(names, strings.TrimSuffix(query.question.Name, "."))
	}
	return names
}

// sameSources compares two sequences of source names by their joined text rather
// than through reflect.DeepEqual, so a failure prints both orders side by side
// instead of a bool.
func sameSources(got, want []string) bool {
	return strings.Join(got, " -> ") == strings.Join(want, " -> ")
}

// heldGeneration is the generation in the metadata document, which is the
// evidence for whether a refresh STORED anything. The answer a client gets is
// also worth reading, but it cannot tell a refused replacement from a refresh
// that never happened: both leave the held key in service. Only the generation
// moves when a fetch stored a key, so it is the half that distinguishes them.
func heldGeneration(t *testing.T, h *harness) uint64 {
	t.Helper()
	var document state.ECHState
	if err := state.ReadJSON(h.echStatePath, &document); err != nil {
		t.Fatalf("read the ECH state document: %v", err)
	}
	return document.Generation
}

// Rotation, the first step. One request per interval, and the interval after the
// first fetch asks the SECOND source rather than beginning the list again -- which
// is also what makes the round cost a third of what a fetch of every source cost.
func TestTheRotationAsksTheSecondSourceAtTheNextInterval(t *testing.T) {
	key := echFixture(t)
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = rotationSources
		c.echAnswer = rotationAnswer(t, map[string][]byte{
			echSourceFirst: key, echSourceSecond: key, echSourceThird: key,
		})
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	if got := askedSources(h); !sameSources(got, []string{echSourceFirst}) {
		t.Fatalf("the first fetch asked %v, want only %s", got, echSourceFirst)
	}

	h.now = h.now.Add(echCadence)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	// ONE query, and it is the second source. A rotation that asked all three here
	// would still contain echSourceSecond, which is why this asserts the whole
	// sequence and not the presence of one name.
	want := []string{echSourceFirst, echSourceSecond}
	if got := askedSources(h); !sameSources(got, want) {
		t.Fatalf("asked %v, want %v: one interval asks the next source, once", got, want)
	}
}

// Rotation, the whole cycle. Three intervals return to the first source, so the
// three sources are covered evenly instead of the first one carrying every
// request -- which is what makes a source going quiet cost one third of the key
// rather than all of it.
func TestTheRotationComesBackToTheFirstSourceAfterThreeIntervals(t *testing.T) {
	key := echFixture(t)
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = rotationSources
		c.echAnswer = rotationAnswer(t, map[string][]byte{
			echSourceFirst: key, echSourceSecond: key, echSourceThird: key,
		})
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)

	want := []string{echSourceFirst, echSourceSecond, echSourceThird, echSourceFirst}
	for interval := range want {
		if interval > 0 {
			h.now = h.now.Add(echCadence)
		}
		h.mustExec(t, forceECHName, dns.TypeHTTPS)
		if got := askedSources(h); !sameSources(got, want[:interval+1]) {
			t.Fatalf("after interval %d the ECH client was asked %v, want %v", interval, got, want[:interval+1])
		}
	}
}

// A source that publishes a different public_name is refused WITHOUT replacing the
// key that is held -- and, the half that is easy to get backwards, refusing it does
// not stop the rotation: the interval after the disagreeing source lands on one
// that agrees, and that refresh is stored. Those are the two halves of the relaxed
// rule and each is a way the other can be implemented wrongly. Refusing a
// disagreement by refusing to refresh at all passes the first half and fails the
// second, and costs every force-ECH domain the interval as well as the disagreeing
// source its own. Refreshing from the disagreeing source passes the second and
// fails the first.
//
// The disagreement is present from the FIRST fetch, which is what makes this case
// different from one that introduces it later. A refresh that reads every source
// refuses the whole refresh the moment one of them disagrees, so it holds no key at
// all and a strict force-ECH name SERVFAILs on the very first query -- the
// availability half of the bug, and the reason one misconfigured source out of
// three takes down every force-ECH domain on the router rather than costing one
// third of its freshness.
//
// The disagreement is modelled on defo.ie, MEASURED on 2026-10-02 to publish
// cover.defo.ie where the other three publish cloudflare-ech.com. Mixing it in
// would make that name the inner SNI, which no other site's edge accepts.
func TestASourcePublishingADifferentPublicNameDoesNotReplaceTheHeldKey(t *testing.T) {
	agreed := echFixture(t)
	// The second source disagrees from the start, and the first and third agree,
	// so the disagreement is a property of the SOURCES rather than of a moment.
	// The map is read by the closure on every exchange, so nothing here has to be
	// rewired to change what a source publishes.
	published := map[string][]byte{
		echSourceFirst:  agreed,
		echSourceSecond: echFixtureFor(t, "cover.defo.ie"),
		echSourceThird:  agreed,
	}
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = rotationSources
		c.echAnswer = rotationAnswer(t, published)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)

	// Every assertion below reads the response this query already produced. Asking
	// again to look at an answer would be a second query, and on a key that is past
	// its lifetime a second query is also a REFRESH -- so a helper that issued its
	// own question would spend the very interval the case is counting, and the
	// rotation would appear to ask sources this test never asked it to.
	first := keyIn(t, h.mustExec(t, forceECHName, dns.TypeHTTPS))

	// One disagreeing source out of three must not take the key down, so the very
	// first fetch is answered from the agreed key the first source published.
	if !bytes.Equal(first, agreed) {
		t.Fatalf("the first answer carries a key other than the agreed one, with %s publishing cover.defo.ie and the other two publishing cloudflare-ech.com: one source that disagrees costs one third of the key's freshness, not all of it",
			echSourceSecond)
	}
	if got := askedSources(h); !sameSources(got, []string{echSourceFirst}) {
		t.Fatalf("the first fetch asked %v, want only %s", got, echSourceFirst)
	}
	firstGeneration := heldGeneration(t, h)

	// The next interval is the one that reaches the disagreeing source. This is
	// what makes the refusal observable at all: a rotation that never asked it
	// would pass this case while never having checked anything.
	h.now = h.now.Add(echCadence)
	second := keyIn(t, h.mustExec(t, forceECHName, dns.TypeHTTPS))

	if got := askedSources(h); !sameSources(got, []string{echSourceFirst, echSourceSecond}) {
		t.Fatalf("asked %v, want the rotation to have reached %s, which is the source that disagrees",
			got, echSourceSecond)
	}
	// Nothing was stored. The answer alone cannot carry this half, because a
	// refused replacement and a refresh that never ran leave the client with the
	// same bytes; the generation is what separates them, and it moves on a stored
	// key and on nothing else.
	if got := heldGeneration(t, h); got != firstGeneration {
		t.Fatalf("generation = %d after %s published a different public_name, want %d unchanged: the disagreeing list must not replace the held key",
			got, echSourceSecond, firstGeneration)
	}
	if !bytes.Equal(second, agreed) {
		t.Fatal("a source publishing cover.defo.ie replaced the held key")
	}

	// The interval after that lands on the third source, which agrees, so the key
	// IS refreshed. This is the half that separates refusing a disagreement from
	// refusing to refresh -- and it is what fixes the position: a rotation that held
	// on the disagreeing source would ask it again here, reach neither of the two
	// healthy ones, and let the grace end with nothing stored.
	h.now = h.now.Add(echCadence)
	third := keyIn(t, h.mustExec(t, forceECHName, dns.TypeHTTPS))

	want := []string{echSourceFirst, echSourceSecond, echSourceThird}
	if got := askedSources(h); !sameSources(got, want) {
		t.Fatalf("asked %v, want the rotation to have continued to %s", got, echSourceThird)
	}
	if got, want := heldGeneration(t, h), firstGeneration+1; got != want {
		t.Fatalf("generation = %d after the agreeing source was fetched, want %d: one source that disagrees must not stop the refresh",
			got, want)
	}
	if !bytes.Equal(third, agreed) {
		t.Fatal("the agreeing source's refresh did not leave the agreed key in service")
	}
}

// keyIn is the ECH key an answer carries. It reads a response the case already has
// rather than asking a question of its own, because on a key past its lifetime a
// question is a refresh, and a helper that issued one would spend the interval the
// case is counting.
func keyIn(t *testing.T, response *dns.Msg) []byte {
	t.Helper()
	ech, present := svcParam(t, theSynthesized(t, response), dns.SVCB_ECHCONFIG)
	if !present {
		t.Fatal("the answer carries no ech parameter at all")
	}
	return ech.(*dns.SVCBECHConfig).ECH
}

// The metadata document is what an operator and `mosdns-cdnctl status` read, and it
// records the key without carrying it.
func TestTheECHStateDocumentRecordsTheKeyWithoutCarryingIt(t *testing.T) {
	h := newHarness(t)
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	var document state.ECHState
	if err := state.ReadJSON(h.echStatePath, &document); err != nil {
		t.Fatalf("read the ECH state document: %v", err)
	}
	if document.Source != "cloudflare-ech.com" {
		t.Fatalf("source = %q, want the source the key was fetched from", document.Source)
	}
	if document.PublicName != "cloudflare-ech.com" {
		t.Fatalf("public_name = %q, want the name inside the key", document.PublicName)
	}
	if document.Status != "fresh" {
		t.Fatalf("status = %q, want fresh", document.Status)
	}
	if want := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC); !document.FetchedAt.Equal(want) {
		t.Fatalf("fetched_at = %s, want the clock's reading %s", document.FetchedAt, want)
	}
	if want := time.Date(2026, 9, 25, 12, 5, 0, 0, time.UTC); !document.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %s, want the fetch plus one cadence, %s", document.ExpiresAt, want)
	}
	// The grace is the policy's, and the policy here is the shipped default. It is
	// read from the defaults rather than written out, because it is a DERIVED number
	// -- two refresh intervals, and the derivation lives in the comment on
	// echStaleGraceSeconds -- and a literal here would be a fourth copy of it to go
	// stale. defaults.go holds the reasoning; this holds that the document agrees
	// with it.
	if want := document.ExpiresAt.Add(time.Duration(config.Defaults().ECH.StaleGraceSeconds) * time.Second); !document.StaleUntil.Equal(want) {
		t.Fatalf("stale_until = %s, want the expiry plus the shipped grace of %d seconds, %s",
			document.StaleUntil, config.Defaults().ECH.StaleGraceSeconds, want)
	}
	if got, want := document.StaleUntil.Sub(document.ExpiresAt), 2*echCadence; got != want {
		t.Fatalf("the grace is %s, want %s: it is two refresh intervals, one failed fetch and the retry after it, and a constant with no derivation is a constant that gets re-picked by whoever is next", got, want)
	}
	// The digest is of the list as published, so an operator can tell two keys
	// apart without the router handing the key to everything that can read a file.
	digest := sha256.Sum256(echFixture(t))
	if document.ConfigSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("config_sha256 = %q, want the digest of the published list", document.ConfigSHA256)
	}
	contents, err := os.ReadFile(h.echStatePath)
	if err != nil {
		t.Fatalf("read the ECH state document: %v", err)
	}
	// Checked as a whole-block search rather than field by field, because a field
	// this package does not know about could carry the key just as well.
	if bytes.Contains(contents, echFixture(t)[:16]) {
		t.Fatalf("the ECH state document carries bytes of the key:\n%s", contents)
	}
}

// --- an ECHConfigList built for a named public name ---

// echFixtureFor builds a valid ECHConfigList whose public name is the name given.
//
// It exists for the one case the published fixture cannot express: two sources
// that disagree about the public name a client authenticates. The layout is RFC
// 9849 Section 4 as the parser reads it -- a version, a length, then the config's
// fields filling that length exactly: config_id, kem_id, the key's own length and
// the 32 bytes of an X25519 key, the cipher suite vector's length and one HKDF-
// SHA256/AES-128-GCM suite, the maximum name length, the public name's own
// one-byte length and the name, and an empty extensions vector. The list itself
// carries the outer uint16 length as well, because that is what a dns.SVCBECHConfig
// holds.
func echFixtureFor(t *testing.T, publicName string) []byte {
	t.Helper()
	contents := []byte{0x01} // config_id
	contents = append(contents, 0x00, 0x20)
	contents = append(contents, 0x00, 0x20)
	contents = append(contents, bytes.Repeat([]byte{0x2a}, 32)...)
	contents = append(contents, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01)
	contents = append(contents, 0x00)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0x00, 0x00)

	config := []byte{0xfe, 0x0d}
	config = append(config, byte(len(contents)>>8), byte(len(contents)))
	config = append(config, contents...)

	list := []byte{byte(len(config) >> 8), byte(len(config))}
	list = append(list, config...)

	// A fixture this package's own parser refuses would make every test that uses
	// it a test of the fixture, so it is checked here rather than assumed.
	if _, err := echconfig.Parse(list); err != nil {
		t.Fatalf("the ECH fixture for %q does not parse: %v", publicName, err)
	}
	return list
}

// --- Step 4: what a replacement document does to the next query ---

// A new selector generation is the whole point of watching the file rather than
// reading it once: the optimizer publishes a new address in the middle of the day
// and the next query has to see it.
func TestANewSelectorGenerationIsServedToTheNextQuery(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	if got := aAddresses(t, h.mustExec(t, cloudflareName, dns.TypeA).Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want the first generation's winner [%s]", got, winnerAddress)
	}

	replacement := liveSelector()
	replacement.Generation = 8
	replacement.WinnerIP = "104.16.77.77"
	h.writeSelector(t, replacement)
	h.awaitSelector(t, "the new selector generation", func(s state.Selector) bool {
		return s.Generation == 8 && s.WinnerIP == "104.16.77.77"
	})

	if got := aAddresses(t, h.mustExec(t, cloudflareName, dns.TypeA).Answer); len(got) != 1 || got[0] != "104.16.77.77" {
		t.Fatalf("addresses = %v, want the new generation's winner [104.16.77.77]", got)
	}
}

// A document this build cannot read changes nothing, and it is reported: an
// operator whose optimizer has started publishing something unreadable has to be
// able to see that the router is still serving the last address it understood.
func TestACorruptSelectorReplacementKeepsTheLastValidGeneration(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))

	writeFile(t, h.selectorPath, []byte("{ this is not a selector"))
	h.waitFor(t, "the corrupt selector to be reported", func() bool { return h.loggedRefusal() })

	if got := aAddresses(t, h.mustExec(t, cloudflareName, dns.TypeA).Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want the last valid generation's winner [%s]", got, winnerAddress)
	}
	if !h.loggedRefusal() {
		t.Fatal("a selector that could not be read was refused silently, so an operator would not know the router is serving an old address")
	}
}

// forcedIsServed asks whether a name is being force-ECH'd, by running the one query
// the force list is actually about and looking for the key in the answer.
//
// These list cases used to probe it with an A query and the empty answer this router
// used to write for a listed name, which made the short circuit a side effect
// several unrelated tests came to depend on. With the short circuit deleted there is
// no difference at all between a listed name and an unlisted one on an address
// query -- that is the point of deleting it -- so the HTTPS answer is the only place
// left where the two differ, and the list is only about that answer anyway.
func forcedIsServed(t *testing.T, h *harness, name string) bool {
	t.Helper()
	h.next.response = theHTTPSIn(t, name)
	record := theSynthesized(t, h.mustExec(t, name, dns.TypeHTTPS))
	_, present := svcParam(t, record, dns.SVCB_ECHCONFIG)
	return present
}

// A new allowlist is served to the next query: the new domain is forced and the
// domain that came off the list is not.
func TestANewForceECHListIsServedToTheNextQuery(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.forcePath, []byte("# the operator replaced the list\nsecure2.example.com\n"))
	h.waitFor(t, "the new allowlist to be served", func() bool {
		return len(h.plugin.force.Snapshot()) == 1 && h.plugin.force.Snapshot()[0] == "secure2.example.com"
	})

	if !forcedIsServed(t, h, "secure2.example.com.") {
		t.Error("the newly listed domain is not being force-ECH'd")
	}
	if forcedIsServed(t, h, forceECHName) {
		t.Error("a domain that came off the list is still being force-ECH'd")
	}
}

// One malformed line keeps the last valid list, and says which line stopped it.
// Losing strict ECH silently is the failure this file exists to prevent, so the
// list is kept whole and the refusal is loud.
func TestACorruptForceECHListKeepsTheLastValidList(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.forcePath, []byte("secure3.example.com\nnot a domain at all\n"))
	h.waitFor(t, "the corrupt allowlist to be reported", func() bool {
		return h.loggedRefusal() && h.loggedText("not a domain at all")
	})

	if !forcedIsServed(t, h, forceECHName) {
		t.Error("the last valid list stopped being honoured")
	}
	if forcedIsServed(t, h, "secure3.example.com.") {
		t.Error("a domain from a list that was refused whole was forced anyway")
	}
}

// A file of no bytes is what an operator's interrupted in-place write leaves
// there, and accepting it would drop every forced domain in the router without a
// word. The last valid list survives it.
func TestAZeroByteForceECHListKeepsTheLastValidList(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.forcePath, nil)
	h.waitFor(t, "the empty allowlist to be reported", func() bool { return h.loggedRefusal() })

	if !forcedIsServed(t, h, forceECHName) {
		t.Error("a zero-byte allowlist dropped every forced domain")
	}
}

// The published ranges are the only argument the classifier has, and the list
// updater rewrites them, so a range that becomes published has to reach the next
// query: the address that was nobody's is now Cloudflare's.
func TestNewCloudflarePrefixesAreServedToTheNextQuery(t *testing.T) {
	h := newHarness(t)
	original := answerWith(plainName, dns.TypeA, aRecord(plainName, foreignAddress, 300))
	before := mustPack(t, original)
	h.next.response = original
	if got := mustPack(t, h.mustExec(t, plainName, dns.TypeA)); string(got) != string(before) {
		t.Fatalf("the answer was rewritten before any range named it:\n before %s\n after  %s", before, got)
	}

	// The documentation range this fixture uses is not a Cloudflare range, and a
	// file that names it is a file this build must obey: the classifier is told
	// what Cloudflare serves, not what it should.
	writeFile(t, h.prefixPath, []byte("104.16.0.0/13\n203.0.113.0/24\n"))
	h.waitFor(t, "the new range list to be served", func() bool {
		prefixes := h.plugin.prefixes.Prefixes()
		return len(prefixes) == 2 && prefixes[1].String() == "203.0.113.0/24"
	})

	if got := aAddresses(t, h.mustExec(t, plainName, dns.TypeA).Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want the winner now that the range is published [%s]", got, winnerAddress)
	}
}

// A range list this build cannot read changes nothing, and says so. The failure
// mode it prevents is quiet and total: an empty list classifies every response as
// somebody else's, so every rewrite in the router stops while the router looks
// healthy.
func TestACorruptPrefixListKeepsTheLastValidRanges(t *testing.T) {
	h := newHarness(t)
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	h.next.response = original
	if got := aAddresses(t, h.mustExec(t, cloudflareName, dns.TypeA).Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want [%s]", got, winnerAddress)
	}

	writeFile(t, h.prefixPath, []byte("104.16.0.0/13\nnot-a-prefix\n"))
	h.waitFor(t, "the corrupt range list to be reported", func() bool {
		return h.loggedRefusal() && h.loggedText("not-a-prefix")
	})

	if got := aAddresses(t, h.mustExec(t, cloudflareName, dns.TypeA).Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want the last valid ranges to keep rewriting [%s]", got, winnerAddress)
	}
}

// loggedRefusal reports whether the plugin has logged a refused reload at all.
func (h *harness) loggedRefusal() bool {
	return h.loggedText("keeping the last valid document")
}

// countLogged counts the logged entries that name this text, in the message or in
// any of its rendered fields. A refusal arrives as the error field of a warning, so
// the message alone would not find it.
func (h *harness) countLogged(text string) int {
	count := 0
	for _, entry := range h.logs.All() {
		if strings.Contains(entry.Message, text) {
			count++
			continue
		}
		for _, field := range entry.ContextMap() {
			if strings.Contains(fmt.Sprint(field), text) {
				count++
				break
			}
		}
	}
	return count
}

// loggedPath reports whether a refused reload named this file, which is how a test
// says WHICH document was refused. A test that only counted log lines would be
// satisfied by a different watcher's healthy poll, so every refusal assertion in
// this file names the path the refusal is about.
func (h *harness) loggedPath(path string) bool {
	for _, entry := range h.logs.All() {
		if strings.Contains(entry.Message, path) {
			return true
		}
		for _, field := range entry.ContextMap() {
			if strings.Contains(fmt.Sprint(field), path) {
				return true
			}
		}
	}
	return false
}

// loggedText reports whether a refused reload named this text, which is how a
// test checks that the operator is told which line stopped the list. The fields
// are rendered rather than inspected, because a refusal arrives as the error field
// of a warning and the field itself holds the error as an unexported interface
// value.
func (h *harness) loggedText(text string) bool {
	for _, entry := range h.logs.All() {
		if strings.Contains(entry.Message, text) {
			return true
		}
		for _, field := range entry.ContextMap() {
			if strings.Contains(fmt.Sprint(field), text) {
				return true
			}
		}
	}
	return false
}

// --- what a query costs, and what a closed plugin does ---

// The sequence is asked exactly once per query that reaches it, and not at all for
// the one case that must cost nothing. The count is the assertion, because a
// second call is invisible in the answer: it would forward the same question twice
// and the client would see whichever answer arrived last.
func TestTheSequenceIsAskedAtMostOncePerQuery(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		qname    string
		qtype    uint16
		answer   func(t *testing.T) *dns.Msg
		wantNext int
	}{
		{
			// A listed name's address queries are ordinary queries now, so this row
			// says one lookup like every other row. It used to say zero, and the zero
			// was the short circuit this package deleted -- a client that cannot
			// resolve the name has nothing to connect to.
			name:  "an A query for a listed name",
			qname: forceECHName,
			qtype: dns.TypeA,
			answer: func(t *testing.T) *dns.Msg {
				return answerWith(forceECHName, dns.TypeA, aRecord(forceECHName, cloudflareAddress, 300))
			},
			wantNext: 1,
		},
		{
			name:  "an AAAA query for a listed name",
			qname: forceECHName,
			qtype: dns.TypeAAAA,
			answer: func(t *testing.T) *dns.Msg {
				return answerWith(forceECHName, dns.TypeAAAA, aaaaRecord(forceECHName, "2606:4700::1111", 300))
			},
			wantNext: 1,
		},
		{
			name:  "an A query for a listed name",
			qname: cloudflareName,
			qtype: dns.TypeA,
			answer: func(t *testing.T) *dns.Msg {
				return answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
			},
			wantNext: 1,
		},
		{
			name:  "an HTTPS query for a listed name",
			qname: forceECHName,
			qtype: dns.TypeHTTPS,
			answer: func(t *testing.T) *dns.Msg {
				return theHTTPSIn(t, forceECHName)
			},
			wantNext: 1,
		},
		{
			name:  "a TXT query",
			qname: forceECHName,
			qtype: dns.TypeTXT,
			answer: func(t *testing.T) *dns.Msg {
				return answerWith(forceECHName, dns.TypeTXT, &dns.TXT{
					Hdr: dns.RR_Header{Name: forceECHName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{"v=spf1 -all"},
				})
			},
			wantNext: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			h.next.response = testCase.answer(t)

			h.exec(t, testCase.qname, testCase.qtype)

			if h.next.calls != testCase.wantNext {
				t.Fatalf("the downstream sequence ran %d times, want %d", h.next.calls, testCase.wantNext)
			}
		})
	}
}

// A sequence that returned nothing is a failure of the sequence, and it is said
// so: the plugin returns an error, which is what mosdns turns into SERVFAIL. A
// plugin that returned no response instead would leave mosdns to answer REFUSED,
// which a client reads as a decision about the name rather than about the path.
func TestANilResponseFromTheSequenceIsAFailure(t *testing.T) {
	h := newHarness(t)
	h.next.response = nil

	response, err := h.exec(t, cloudflareName, dns.TypeA)

	if err == nil {
		t.Fatal("Exec returned no error for a sequence that produced nothing, so mosdns would answer REFUSED")
	}
	if !errors.Is(err, errNoResponse) {
		t.Fatalf("error = %v, want one wrapping errNoResponse", err)
	}
	if response != nil {
		t.Fatalf("a response was set on the context: %v", response.Answer)
	}
}

// A closed plugin fails closed rather than reaching a half-closed one, and closing
// twice is not an error.
func TestAClosedPluginRefusesQueries(t *testing.T) {
	h := newHarness(t)
	if err := h.plugin.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.plugin.Close(); err != nil {
		t.Fatalf("Close again: %v", err)
	}

	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	if _, err := h.exec(t, cloudflareName, dns.TypeA); !errors.Is(err, errClosed) {
		t.Fatalf("error = %v, want one wrapping errClosed", err)
	}
	if h.next.calls != 0 {
		t.Fatalf("the downstream sequence ran %d times after Close, want 0", h.next.calls)
	}
}

// --- construction: every refusal is an error, never a panic ---

func TestEveryRequiredPathIsRefusedWhenItIsEmpty(t *testing.T) {
	for _, field := range []struct {
		name string
		arg  string
	}{
		{"policy_file", "policy_file"},
		{"selector_file", "selector_file"},
		{"force_ech_file", "force_ech_file"},
		{"ech_state_file", "ech_state_file"},
		{"foreign_upstream", "foreign_upstream"},
		{"cloudflare_cidr_file", "cloudflare_cidr_file"},
	} {
		t.Run(field.name, func(t *testing.T) {
			_, err := newHarnessExpectingRefusal(t, func(c *harnessConfig) { c.blankArg = field.arg })
			if err == nil {
				t.Fatalf("%s was accepted empty, want a refusal naming the field", field.name)
			}
			if !strings.Contains(err.Error(), field.arg) {
				t.Fatalf("error = %v, want it to name %s", err, field.arg)
			}
		})
	}
}

// An ECH fetch through a transport this project has measured unsafe is refused at
// construction, where the operator who wrote the configuration is reading.
func TestAnUnsafeECHUpstreamIsRefused(t *testing.T) {
	for _, addr := range []string{"udp://127.0.0.1:15353", "127.0.0.1:15353", "https://127.0.0.1:15353"} {
		t.Run(addr, func(t *testing.T) {
			_, err := newHarnessExpectingRefusal(t, func(c *harnessConfig) { c.foreignUpstream = addr })
			if err == nil {
				t.Fatalf("an ECH fetch through %q was accepted, want a refusal", addr)
			}
			if !errors.Is(err, errUnsafeRoute) {
				t.Fatalf("error = %v, want one wrapping errUnsafeRoute", err)
			}
		})
	}
}

// A range list this build cannot use is a refusal at construction rather than a
// plugin that starts up and rewrites nothing.
func TestAnUnusableCloudflareRangeListIsRefused(t *testing.T) {
	for name, contents := range map[string]string{
		"a file of no bytes":          "",
		"a file of comments":          "# nothing here yet\n",
		"a line that is not a prefix": "104.16.0.0/13\nhello\n",
		"an IPv6 range":               "104.16.0.0/13\n2606:4700::/32\n",
		"a private range":             "104.16.0.0/13\n10.0.0.0/8\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newHarnessExpectingRefusal(t, func(c *harnessConfig) { c.prefixes = contents }); err == nil {
				t.Fatalf("a range list holding %q was accepted, want a refusal", contents)
			}
		})
	}
}

// A listener that cannot be built is a refusal, not a plugin whose every key fetch
// fails later with nothing in the log to say why.
func TestAnUnbuildableECHClientIsRefused(t *testing.T) {
	_, err := newHarnessExpectingRefusal(t, func(c *harnessConfig) {
		c.upstreamError = errors.New("no such listener")
	})
	if err == nil {
		t.Fatal("an ECH client that cannot be built was accepted, want a refusal")
	}
	if !strings.Contains(err.Error(), "no such listener") {
		t.Fatalf("error = %v, want it to name the client failure", err)
	}
}

// A policy this build will not validate is a refusal, and the message says which
// file and what was wrong with it.
func TestAnUnreadablePolicyIsRefused(t *testing.T) {
	_, err := newHarnessExpectingRefusal(t, func(c *harnessConfig) {
		c.ownPolicy = func(t *testing.T) []byte {
			return []byte("schema_version: 1\nech:\n  failure_policy: whenever\n")
		}
	})
	if err == nil {
		t.Fatal("a policy that does not validate was accepted, want a refusal")
	}
	if !strings.Contains(err.Error(), "policy.yaml") {
		t.Fatalf("error = %v, want it to name the policy file", err)
	}
}

// The plugin is registered under its tag and is loadable from a mosdns
// configuration, with the argument names the rendered document uses. This is the
// only test that builds the real thing: the real policy reader, the real watchers
// and the real TCP client, which is constructed but never dialled.
func TestThePluginLoadsFromAMosdnsConfiguration(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	selector := filepath.Join(dir, "cdn-selector.json")
	force := filepath.Join(dir, "force-ech-domains.txt")
	echState := filepath.Join(dir, "ech-state.json")
	prefixes := filepath.Join(dir, "cloudflare-prefixes.txt")
	writeFile(t, policy, policyDocument(t, nil))
	writeFile(t, selector, selectorDocument(t, liveSelector()))
	writeFile(t, force, []byte(forceECHEntry+"\n"))
	writeFile(t, prefixes, []byte(publishedPrefixes))

	mosdns, err := coremain.NewMosdns(&coremain.Config{
		Log: mlog.LogConfig{Level: "error"},
		Plugins: []coremain.PluginConfig{{
			Tag:  "cdn_rewrite",
			Type: "cdn_rewrite",
			Args: map[string]any{
				"policy_file":          policy,
				"selector_file":        selector,
				"force_ech_file":       force,
				"ech_state_file":       echState,
				"foreign_upstream":     "tcp://127.0.0.1:15353",
				"cloudflare_cidr_file": prefixes,
			},
		}},
	})
	if err != nil {
		t.Fatalf("mosdns refused the cdn_rewrite plugin: %v", err)
	}
	t.Cleanup(func() {
		mosdns.CloseWithErr(nil)
		_ = mosdns.GetSafeClose().WaitClosed()
	})

	plugin := mosdns.GetPlugin("cdn_rewrite")
	if _, ok := plugin.(sequence.RecursiveExecutable); !ok {
		t.Fatalf("plugin %T does not implement sequence.RecursiveExecutable", plugin)
	}
	closer, ok := plugin.(interface{ Close() error })
	if !ok {
		t.Fatalf("plugin %T is not closed on shutdown", plugin)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// The other shape `Address` returns is a refusal: a nil message beside an error.
// A caller that returns that error to the query throws away an answer the upstream
// had already given, and a browser behind it loses the name for a reason that has
// nothing to do with the browser. The case here is a response this router cannot
// rewrite because the records it would replace carry no lifetime -- there is no
// honest TTL for a replacement -- and the answer that must survive is the
// upstream's own.
func TestAnAddressRewriteThisRouterRefusesLeavesTheUpstreamAnswerInPlace(t *testing.T) {
	h := newHarness(t)
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 0))
	before := mustPack(t, original)
	h.next.response = original

	response, err := h.exec(t, cloudflareName, dns.TypeA)

	if err != nil {
		t.Fatalf("Exec: %v: a rewrite this router declined is not a failure of the query", err)
	}
	if response == nil {
		t.Fatal("the plugin left no response, which mosdns answers as REFUSED")
	}
	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the upstream's answer was not kept:\n before %s\n after  %s", before, got)
	}
	if got := aAddresses(t, response.Answer); len(got) != 1 || got[0] != cloudflareAddress {
		t.Fatalf("addresses = %v, want the upstream's own [%s]", got, cloudflareAddress)
	}
	if !h.loggedText("left as the upstream published it") {
		t.Fatal("a rewrite this router refused was not reported, so an operator would not know the router is not rewriting")
	}
}

// A mosdns context carries one question, and a context carrying two is one this
// plugin cannot answer: the rewrite rules are all about one question and one name,
// and guessing which of two the client meant is a guess about whose address this
// is.
func TestAQueryWithNoSingleQuestionIsRefused(t *testing.T) {
	h := newHarness(t)
	query := new(dns.Msg)
	query.Question = []dns.Question{
		{Name: cloudflareName, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: plainName, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	qCtx := query_context.NewContext(query)

	err := h.plugin.Exec(t.Context(), qCtx, h.next.walker())

	if !errors.Is(err, errNoQuestion) {
		t.Fatalf("error = %v, want one wrapping errNoQuestion", err)
	}
	if h.next.calls != 0 {
		t.Fatalf("the downstream sequence ran %d times for a query with two questions, want 0", h.next.calls)
	}
}

// --- Fix round 1: the prefix poller, the record, and the CloudFront arm ---

// A poll that succeeds is not an event. The poller runs twice a second for the
// life of the router, so a handler called on every successful tick writes a line
// every time, and a line that says "keeping the last valid document" when nothing
// was refused is not a warning an operator can act on -- it is noise that hides the
// one time it matters.
func TestThePrefixPollerLogsNothingWhileItsFileIsReadable(t *testing.T) {
	h := newHarness(t)

	// Two hundred polls at the test poll interval: at the production default of half
	// a second that is the same number of seconds this test spends one.
	h.waitPolls(t, 200)

	if entries := h.logs.All(); len(entries) != 0 {
		for _, entry := range entries {
			t.Errorf("a successful poll logged %q", entry.Message)
		}
	}
}

// A poll that succeeds reports nothing, and a refusal that keeps happening is
// reported once until something changes. Both are decisions the poller makes, so
// both are decided here where nothing else can be mistaken for them: the
// integration test above proves the plugin's log is quiet, and this one proves why.
func TestThePrefixPollerReportsOncePerEpisodeAndNotAtAllOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare-prefixes.txt")
	writeFile(t, path, []byte(publishedPrefixes))

	// The handler runs on the poll goroutine, so what it records is read through a
	// lock: a test that asserted a count of refusals is asserting about two
	// goroutines, and the race detector is part of this file's gate.
	var recorded refusalRecorder
	list, err := newPrefixList(path, time.Millisecond, recorded.record)
	if err != nil {
		t.Fatalf("newPrefixList: %v", err)
	}
	t.Cleanup(func() { _ = list.Close() })

	h := &harness{started: time.Now()}
	h.waitPolls(t, 50)
	if got := recorded.all(); len(got) != 0 {
		t.Fatalf("fifty successful polls reported %d times, want nothing: %v", len(got), got)
	}

	// Now break it, and leave it broken.
	writeFile(t, path, []byte("not-a-prefix\n"))
	h.waitFor(t, "the first refusal", func() bool { return len(recorded.all()) > 0 })
	h.waitPolls(t, 50)
	if got := recorded.all(); len(got) != 1 {
		t.Fatalf("one continuing episode reported %d times, want 1: %v", len(got), got)
	}

	// Repair it, which ends the episode, and break it again.
	writeFile(t, path, []byte(publishedPrefixes))
	h.waitFor(t, "the repaired list to be served", func() bool { return len(list.Prefixes()) == 2 })
	writeFile(t, path, []byte("still-not-a-prefix\n"))
	h.waitFor(t, "the second episode to be reported", func() bool { return len(recorded.all()) > 1 })
	if got := recorded.all(); len(got) != 2 {
		t.Fatalf("the second episode reported %d times in total, want 2: %v", len(got), got)
	}
}

// refusalRecorder is what a poll's report handler writes into. A nil is recorded
// rather than dereferenced, so a poller that reports its successes fails a test
// with a message instead of taking the process down -- which is what a handler
// assuming it was never handed one would do in production.
type refusalRecorder struct {
	mu      sync.Mutex
	entries []string
}

func (r *refusalRecorder) record(failure error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if failure == nil {
		r.entries = append(r.entries, "<a reload that succeeded>")
		return
	}
	r.entries = append(r.entries, failure.Error())
}

func (r *refusalRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.entries...)
}

// A refusal that keeps happening is one problem, not two hundred a second, so it
// is reported once until something changes.
func TestAContinuingRefusalOfTheRangeListIsReportedOnce(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.prefixPath, []byte("not-a-prefix\n"))
	h.waitFor(t, "the refusal to be reported", func() bool { return h.loggedText("not-a-prefix") })

	h.waitPolls(t, 100)
	if got := h.countLogged("not-a-prefix"); got != 1 {
		t.Fatalf("the same refusal was reported %d times across a hundred polls, want 1", got)
	}
}

// A repair ends the episode: a file that breaks again after it was fixed is a new
// problem and has to be reported again, or an operator who repaired it and then
// broke it again gets silence.
func TestARepairedRangeListReportsItsNextRefusalAgain(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.prefixPath, []byte("not-a-prefix\n"))
	h.waitFor(t, "the first refusal to be reported", func() bool { return h.loggedText("not-a-prefix") })

	writeFile(t, h.prefixPath, []byte(publishedPrefixes))
	h.waitFor(t, "the list to be served again", func() bool {
		return len(h.plugin.prefixes.Prefixes()) == 2
	})
	writeFile(t, h.prefixPath, []byte("still-not-a-prefix\n"))
	h.waitFor(t, "the second refusal to be reported", func() bool {
		return h.loggedText("still-not-a-prefix")
	})
}

// The two refusals below are about the selector and the allowlist, so what they
// assert is that the refusal names THOSE files. A test that only counted log lines
// would be satisfied by the range list's own healthy poll, which is the trap this
// pair of assertions exists to close.
func TestTheSelectorRefusalNamesTheSelectorFile(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.selectorPath, []byte("{ this is not a selector"))

	h.waitFor(t, "the selector refusal", func() bool { return h.loggedPath(h.selectorPath) })
}

func TestAZeroByteForceECHListNamesTheAllowlistFile(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.forcePath, nil)

	h.waitFor(t, "the allowlist refusal", func() bool { return h.loggedPath(h.forcePath) })
}

// A rewrite this router refused leaves the name out of the record, so a following
// IPv6 answer is not suppressed on the strength of a rewrite that never happened.
// The plan's constraint is "when A is rewritten, suppress AAAA for the same CDN
// name", and a name whose A answer was left alone has not been rewritten.
func TestARefusedAddressRewriteDoesNotEarnItsNameAnIPv6Suppression(t *testing.T) {
	h := newHarness(t)
	// A Cloudflare answer whose records carry no TTL, which the rewrite refuses:
	// there is no lifetime to give a replacement.
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 0))
	h.mustExec(t, cloudflareName, dns.TypeA)

	original := answerWith(cloudflareName, dns.TypeAAAA, aaaaRecord(cloudflareName, "2606:4700::1111", 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeAAAA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("an IPv6 answer was suppressed for a name whose A answer was never rewritten:\n before %s\n after  %s", before, got)
	}
}

// --- the CloudFront arm, for a name answered through a CNAME ---

// A per-hostname mapping authorises the QUERY, and a CNAME's terminal addresses
// are that query's answer. The health check proves the mapping against the queried
// name's own profile, so the proof and the authorisation are about the same name,
// and a distribution reached through an alias is exactly what a per-hostname
// mapping exists for.
func TestACloudFrontMappingRewritesTheTerminalNameOfAnAliasedAnswer(t *testing.T) {
	h := newHarness(t)
	mapped := selectorWithMapping(cloudFrontEntry, cloudFrontWinnerAddress)
	h.writeSelector(t, mapped)
	h.awaitSelector(t, "the CloudFront mapping to be published", func(s state.Selector) bool {
		return s.CloudFront[cloudFrontEntry] == cloudFrontWinnerAddress
	})
	upstream := answerWith(cloudFrontName, dns.TypeA,
		cnameRecord(cloudFrontName, "origin.cdn-vendor.example.", 300),
		aRecord("origin.cdn-vendor.example.", cloudFrontAddress, 300),
	)
	h.next.response = upstream

	response := h.mustExec(t, cloudFrontName, dns.TypeA)

	if got := aAddresses(t, response.Answer); len(got) != 1 || got[0] != cloudFrontWinnerAddress {
		t.Fatalf("addresses = %v, want the mapping's own address [%s] at the end of the chain", got, cloudFrontWinnerAddress)
	}
	if _, ok := response.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("the answer's first record is %T, want the CNAME the upstream published: a rewrite replaces addresses, never the chain", response.Answer[0])
	}
	// The cached object is untouched, chain included: the plugin replaces
	// addresses and never a delegation.
	cached := upstream.Answer[0].(*dns.CNAME)
	if cached.Target != "origin.cdn-vendor.example." {
		t.Fatalf("the cached object's CNAME now points at %q", cached.Target)
	}
}

// The adjacent hazard, and it is the reason the mapping arm passes the ranges at
// all: a response the caller's OWN published ranges call Cloudflare-served is not a
// distribution's, so no per-hostname mapping may claim it. The aliased shape is
// the one that matters, because the Cloudflare addresses are at the far end of a
// chain whose first name is the mapped one.
func TestACloudFrontMappingIsRefusedAChainThatEndsInCloudflareSpace(t *testing.T) {
	h := newHarness(t)
	mapped := selectorWithMapping(cloudFrontEntry, cloudFrontWinnerAddress)
	h.writeSelector(t, mapped)
	h.awaitSelector(t, "the CloudFront mapping to be published", func(s state.Selector) bool {
		return s.CloudFront[cloudFrontEntry] == cloudFrontWinnerAddress
	})
	original := answerWith(cloudFrontName, dns.TypeA,
		cnameRecord(cloudFrontName, "origin.cdn-vendor.example.", 300),
		aRecord("origin.cdn-vendor.example.", cloudflareAddress, 300),
	)
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudFrontName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a Cloudflare-served answer was rewritten through a CloudFront mapping:\n before %s\n after  %s", before, got)
	}
}

// The same guard without a chain in front of it: the mapped name is answered
// directly with addresses the published ranges call Cloudflare's, which is the
// shape a proxied name has, and no mapping may claim it either.
func TestACloudFrontMappingIsRefusedADirectCloudflareAnswer(t *testing.T) {
	h := newHarness(t)
	mapped := selectorWithMapping(cloudFrontEntry, cloudFrontWinnerAddress)
	h.writeSelector(t, mapped)
	h.awaitSelector(t, "the CloudFront mapping to be published", func(s state.Selector) bool {
		return s.CloudFront[cloudFrontEntry] == cloudFrontWinnerAddress
	})
	original := answerWith(cloudFrontName, dns.TypeA, aRecord(cloudFrontName, cloudflareAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudFrontName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a Cloudflare-served answer was rewritten through a CloudFront mapping:\n before %s\n after  %s", before, got)
	}
}

// --- the order of an A answer and an IPv6 answer for one name ---

// Suppression of an IPv6 answer depends on the A answer for the same name having
// been rewritten FIRST, and a browser asking for both at once is the ordinary case
// rather than the corner one. Whichever the router happens to process first
// decides, and the half that has no verdict to work from keeps the upstream's own
// records. This test pins both halves of that property, in the order a client
// produces them, so the outcome users see is the one the documentation describes.
func TestAnIPv6AnswerProcessedBeforeItsAAnswerIsNotSuppressed(t *testing.T) {
	h := newHarness(t)

	// The IPv6 answer first, with no A answer behind it.
	original := answerWith(cloudflareName, dns.TypeAAAA, aaaaRecord(cloudflareName, "2606:4700::1111", 300))
	before := mustPack(t, original)
	h.next.response = original
	if got := mustPack(t, h.mustExec(t, cloudflareName, dns.TypeAAAA)); string(got) != string(before) {
		t.Fatalf("an IPv6 answer arrived with no A answer behind it and was suppressed anyway:\n before %s\n after  %s", before, got)
	}

	// Then the A answer, which is rewritten and earns the suppression.
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	if got := aAddresses(t, h.mustExec(t, cloudflareName, dns.TypeA).Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want [%s]", got, winnerAddress)
	}

	// And the next IPv6 answer for the same name is emptied.
	h.next.response = answerWith(cloudflareName, dns.TypeAAAA, aaaaRecord(cloudflareName, "2606:4700::1111", 300))
	if got := len(h.mustExec(t, cloudflareName, dns.TypeAAAA).Answer); got != 0 {
		t.Fatalf("the IPv6 answer carries %d records after its A answer was rewritten, want 0", got)
	}
}

// A missing allowlist is an inert router, not a broken one -- and it is said out
// loud, because an operator who believes they are forcing ECH for a domain is
// otherwise getting nothing and no reason. This is the documented contrast with the
// range list, which refuses to start instead: a missing allowlist claims no domain
// the operator did not list, while a missing range list stops every rewrite in the
// router without saying so.
func TestAMissingForceECHListStartsThePluginAndSaysTheListIsNotThere(t *testing.T) {
	h, err := buildHarness(t, func(c *harnessConfig) { c.noForceFile = true })
	if err != nil {
		t.Fatalf("a plugin whose allowlist is absent refused to start, want it to start with an empty list: %v", err)
	}
	if !h.loggedPath(h.forcePath) {
		t.Fatal("the absent allowlist was not reported, so an operator forcing ECH for a domain has no reason to think the list is missing")
	}
	// And the router serves: a name nobody listed is answered by the ordinary path.
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	if got := aAddresses(t, h.mustExec(t, cloudflareName, dns.TypeA).Answer); len(got) != 1 || got[0] != winnerAddress {
		t.Fatalf("addresses = %v, want the ordinary path to keep serving [%s]", got, winnerAddress)
	}
}

// A live selector that publishes no winner is a state the optimizer really does
// produce -- a CloudFront-only first apply leaves the global group with nothing in
// it -- so the plugin must not read an empty winner as an address to install.
func TestALiveSelectorWithNoWinnerIPInstallsNothing(t *testing.T) {
	h := newHarness(t)
	h.plugin.selector = fixedSelector{state.Selector{
		SchemaVersion: state.SchemaVersion,
		Generation:    11,
		Mode:          "auto",
		Provider:      string(candidate.ProviderCloudflare),
		LastSuccess:   h.now,
	}}
	original := answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))
	before := mustPack(t, original)
	h.next.response = original

	response := h.mustExec(t, cloudflareName, dns.TypeA)

	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("a selector with no winner installed an address:\n before %s\n after  %s", before, got)
	}
}

// --- Fix round 1: the cold race, and the document that froze ---

// The first pair of force-ECH HTTPS queries after a boot is the case the
// single-flight exists for, and it is a pair: a browser's tab asks for several
// names at once, and each of them needs the key. One of them fetches; the others
// wait. What they must all get is the key that was fetched -- a caller that lost
// the race and returned its own error would SERVFAIL a strict name for no reason at
// all, on the first page load after a restart, intermittently.
//
// The origin's request count is the assertion that matters, because "nobody
// errored" alone would also be true of an implementation that let every caller
// fetch.
func TestTheFirstConcurrentCallersShareOneFetchAndAllGetTheKey(t *testing.T) {
	const callers = 8
	h := newHarness(t)
	// The answer blocks until the test releases it, so the fetch is still running
	// while the other callers arrive and queue behind it. The assertion does not
	// depend on that: a caller arriving after the fetch finds a fresh key at the
	// top and fetches nothing either, so exactly one request is the only possible
	// outcome and the count is what proves it. The block is here to make the
	// interesting interleaving the likely one.
	release := make(chan struct{})
	h.upstream.setAnswer(func(question dns.Question) (*dns.Msg, error) {
		<-release
		return answerWithECH(echFixture(t), 300)(question)
	})

	type outcome struct {
		key []byte
		err error
	}
	results := make([]outcome, callers)
	var group, ready sync.WaitGroup
	group.Add(callers)
	ready.Add(callers)
	for index := range callers {
		go func(index int) {
			defer group.Done()
			ready.Done()
			results[index].key, results[index].err = h.plugin.ech.Config(t.Context())
		}(index)
	}
	ready.Wait()
	time.Sleep(30 * time.Millisecond)
	close(release)
	group.Wait()

	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("the source was asked %d times by %d concurrent callers, want 1: %+v", len(asked), callers, asked)
	}
	for index, result := range results {
		if result.err != nil {
			t.Fatalf("caller %d got the error %v, want the key the shared fetch published", index, result.err)
		}
		if string(result.key) != string(echFixture(t)) {
			t.Fatalf("caller %d got %d bytes, want the %d bytes the source published", index, len(result.key), len(echFixture(t)))
		}
	}
}

// The losing half of that race, on a source that never answers. The two tests above
// share a fetch that SUCCEEDS, so the key is published and every caller that waited
// finds it at the top of the loop: the second attempt is free and nothing is wrong.
// On the failure path the same loop is a queue. The winner's fetch stores nothing,
// so a waiter that re-reads finds exactly what it read before the wait, and starting
// a fetch of its own is the only thing left for it to do -- one at a time, because
// the single flight still holds the flag the winner is about to release. So eight
// concurrent force-ECH HTTPS queries against an unreachable source cost a second
// exchange on tcp://127.0.0.1:15353, the listener every foreign query in this router
// depends on, and the callers that queue behind it are told a source fault they never
// observed. At the production fetch timeout each of those exchanges is three seconds,
// so the last client's context can expire while it waits for a key nobody is fetching.
//
// The assertions are exact, and none of them is a threshold on a clock. The origin is
// held open on any exchange after the first -- a second exchange never returns until
// this test releases it -- so "every caller is answered" and "a second exchange was
// started" cannot both be true, and the race between the two is the whole property:
// a caller answered while the origin is left alone was answered by the one exchange,
// and a caller that had to wait for a second one is caught. The count then says how
// many requests the source saw, and the split of errors says how many callers claimed
// to have read it: one exchange, one reporter.
func TestConcurrentCallersShareOneExchangeWithASourceThatKeepsFailing(t *testing.T) {
	const callers = 8
	// One exchange with a listener that has stopped answering: a cost the provider
	// pays, not an error on the first byte. It only has to be long enough that the
	// other seven callers are behind it rather than after it, because the assertion
	// below does not depend on how long it is.
	const exchange = 50 * time.Millisecond

	var (
		exchanges    atomic.Int64
		announceLate sync.Once
		late         = make(chan struct{})
		release      = make(chan struct{})
	)
	sourceDown := errors.New("the ECH source is not answering")
	h := newHarness(t)
	h.upstream.setAnswer(func(dns.Question) (*dns.Msg, error) {
		if exchanges.Add(1) == 1 {
			time.Sleep(exchange)
			return nil, sourceDown
		}
		// A second exchange is one nothing asked for, and this test will not let it
		// finish: a caller that is waiting for it is the defect, and a caller waiting
		// for the test is a test that hangs.
		announceLate.Do(func() { close(late) })
		<-release
		return nil, sourceDown
	})

	results := make([]error, callers)
	var group, ready sync.WaitGroup
	group.Add(callers)
	ready.Add(callers)
	for index := range callers {
		go func(index int) {
			defer group.Done()
			ready.Done()
			_, results[index] = h.plugin.ech.Config(t.Context())
		}(index)
	}
	ready.Wait()
	// The first exchange is in flight by now and the others are behind it, which is
	// the shape this test is about. Nothing below depends on the sleep: a caller that
	// arrived after the first exchange is over would also find nothing stored, so one
	// exchange is the only correct outcome either way.
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	start := time.Now()
	go func() {
		group.Wait()
		close(done)
	}()

	lateStarted := false
	select {
	case <-done:
	case <-late:
		lateStarted = true
		close(release)
		<-done
	case <-time.After(30 * time.Second):
		close(release)
		<-done
		t.Fatal("the callers never finished: one of them is waiting for an exchange this test never released")
	}
	elapsed := time.Since(start)

	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("the source was asked %d times by %d concurrent callers against a source that fails, want 1: %+v", len(asked), callers, asked)
	}
	if lateStarted {
		t.Fatalf("a caller started a second exchange after the first had already failed, and %d callers waited for it rather than being answered by the one exchange: %s", len(h.upstream.asked()), elapsed)
	}
	// Every caller fails closed rather than holding a key, and the seven that waited
	// say so with the sentinel rather than with a fault of their own: logFetchFailure
	// reads that sentinel as "you did not read the source, someone else did", and a
	// caller reporting a source outage it never observed sends an operator after the
	// wrong thing.
	read, waited := 0, 0
	for index, err := range results {
		if err == nil {
			t.Fatalf("caller %d got a key from a source that publishes none", index)
		}
		if errors.Is(err, errECHNotRefetched) {
			waited++
			continue
		}
		read++
	}
	if read != 1 || waited != callers-1 {
		t.Fatalf("%d callers reported the source's own failure and %d reported waiting for another caller's fetch, want 1 and %d: one exchange has one reader", read, waited, callers-1)
	}
}

// The same race one lifetime later, which is the quieter half of the same defect:
// a caller whose key is past its grace gets ErrECHExpired if another caller's
// refresh has already stored a new one, and a strict name then fails closed over a
// key that is sitting right there.
func TestACallerPastTheGraceIsServedByAConcurrentRefresh(t *testing.T) {
	const callers = 4
	h := newHarness(t, func(c *harnessConfig) {
		c.echAnswer = answerWithECH(echFixture(t), 300)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	// One key, fetched, and then a clock past its grace: the next caller has to
	// fetch, and the one after it has to wait.
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	h.now = h.now.Add(300*time.Second + 901*time.Second)

	release := make(chan struct{})
	h.upstream.setAnswer(func(question dns.Question) (*dns.Msg, error) {
		<-release
		return answerWithECH(echFixture(t), 300)(question)
	})

	type outcome struct {
		key []byte
		err error
	}
	results := make([]outcome, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for index := range callers {
		go func(index int) {
			defer group.Done()
			results[index].key, results[index].err = h.plugin.ech.Config(t.Context())
		}(index)
	}
	time.Sleep(30 * time.Millisecond)
	close(release)
	group.Wait()

	if asked := h.upstream.asked(); len(asked) != 2 {
		t.Fatalf("the source was asked %d times, want 2: one for the key already fetched and one for the refresh", len(asked))
	}
	for index, result := range results {
		if result.err != nil {
			t.Fatalf("caller %d got the error %v, want the key a concurrent refresh published", index, result.err)
		}
		if string(result.key) != string(echFixture(t)) {
			t.Fatalf("caller %d got %d bytes, want a usable key", index, len(result.key))
		}
	}
}

// The metadata document is what an operator and `mosdns-cdnctl status` read, so it
// has to describe the key in service. A refresh that moved the times has to write
// them: a file whose expiry is in the past while the router is serving a newer key
// tells the reader the opposite of the truth, and the digest in it names a key that
// is not the one being installed.
func TestARefreshThatMovedTheTimesIsPublished(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.echAnswer = answerWithECH(echFixture(t), 300)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	first := readECHState(t, h.echStatePath)
	if first.Generation != 1 {
		t.Fatalf("the first document carries generation %d, want 1", first.Generation)
	}

	// Past the published lifetime, so the next query refreshes.
	h.now = h.now.Add(301 * time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	second := readECHState(t, h.echStatePath)
	if want := time.Date(2026, 9, 25, 12, 5, 1, 0, time.UTC); !second.FetchedAt.Equal(want) {
		t.Fatalf("fetched_at = %s, want the second fetch's own clock reading %s", second.FetchedAt, want)
	}
	if want := time.Date(2026, 9, 25, 12, 10, 1, 0, time.UTC); !second.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %s, want the second fetch plus its 300 second lifetime, %s", second.ExpiresAt, want)
	}
	if second.Generation != 2 {
		t.Fatalf("generation = %d, want 2: the document on disk has to be the second fetch's", second.Generation)
	}
	if second.Status != "fresh" {
		t.Fatalf("status = %q, want fresh", second.Status)
	}
}

// The other half of what has to be published: a refresh that changed the KEY, not
// only the clock. An operator comparing two digests is how they tell a rotated key
// from a re-fetch of the same one, and a document that keeps the first digest after
// a rotation says the key has not changed when it has.
//
// It is also the only case in this package where a source publishing a DIFFERENT
// public name is right, because an upstream rotation moves the name with the key and
// a client authenticates the name inside the config. So it holds both halves of the
// rule, and the seam between them is the grace. Inside it the held key is worth
// keeping and the rotation is refused, because a client is being served that key.
// Past it there is nothing left to keep, and refusing would leave this router
// refusing forever against a source that is answering perfectly well -- every
// force-ECH name failing closed on a rotation it could have survived.
func TestARefreshThatChangedTheKeyIsPublished(t *testing.T) {
	const grace = 600
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.StaleGraceSeconds = grace }
		c.echAnswer = answerWithECH(echFixture(t), 300)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	first := readECHState(t, h.echStatePath)

	// The source rotates its key. The public name moves with it, because a client
	// authenticates the name inside the config.
	rotated := echFixtureFor(t, "rotated-ech.example.com")
	rotatedDigest := sha256.Sum256(rotated)
	h.upstream.setAnswer(answerWithECH(rotated, 300))
	h.now = h.now.Add(echCadence)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	// Inside the grace the held key still serves, so the replacement is refused and
	// the document keeps describing the key that is actually in service.
	during := readECHState(t, h.echStatePath)
	if during.ConfigSHA256 != first.ConfigSHA256 {
		t.Fatalf("config_sha256 = %q while the held key is still inside its grace, want the held key's own %q: that is the key clients are being served",
			during.ConfigSHA256, first.ConfigSHA256)
	}

	// Past the grace the held key is worth nothing, and the rotation is taken.
	h.now = h.now.Add(grace * time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	second := readECHState(t, h.echStatePath)
	if second.ConfigSHA256 != hex.EncodeToString(rotatedDigest[:]) {
		t.Fatalf("config_sha256 = %q after the held key's grace ended, want the digest of the rotated key %q: refusing it from here on would leave this router refusing forever against a source that is working",
			second.ConfigSHA256, hex.EncodeToString(rotatedDigest[:]))
	}
	if second.ConfigSHA256 == first.ConfigSHA256 {
		t.Fatal("the document still carries the first key's digest after the source rotated it and the held key expired")
	}
	if second.PublicName != "rotated-ech.example.com" {
		t.Fatalf("public_name = %q, want the rotated key's own public name", second.PublicName)
	}
	if second.Generation <= during.Generation {
		t.Fatalf("generation = %d, want more than the %d the refused window left behind: the rotation was stored, not merely tolerated", second.Generation, during.Generation)
	}
}

// Two callers can be inside the write with different snapshots, and only the newer
// one may be what is on disk. The race itself is not reproducible on demand, so
// this pins the rule rather than the interleaving: publish an older snapshot over a
// newer one and assert the document still describes the key in service. It is a
// white-box test for that reason, and it is worth one: without the rule the loser is
// saved only by the state writer refusing a rollback, which logs a warning rather
// than deciding anything.
func TestAnOlderSnapshotIsNotPublishedOverANewerOne(t *testing.T) {
	h := newHarness(t)
	newer := echConfig{
		raw:        echFixture(t),
		source:     "cloudflare-ech.com",
		publicName: "cloudflare-ech.com",
		digest:     digestOf(echFixture(t)),
		fetchedAt:  h.now,
		expiresAt:  h.now.Add(300 * time.Second),
		staleUntil: h.now.Add(300*time.Second + 900*time.Second),
		generation: 2,
	}
	older := newer
	older.generation = 1
	older.digest = digestOf(echFixtureFor(t, "an-older-key.example.com"))

	h.plugin.ech.publish(echStatusFresh, newer)
	h.plugin.ech.publish(echStatusFresh, older)

	document := readECHState(t, h.echStatePath)
	if document.Generation != 2 {
		t.Fatalf("generation on disk = %d, want 2: an older snapshot replaced the key in service", document.Generation)
	}
	if document.ConfigSHA256 != newer.digest {
		t.Fatalf("config_sha256 on disk = %q, want the newer key's digest %q", document.ConfigSHA256, newer.digest)
	}
	// And the decision was MADE here rather than left to the state writer, which
	// refuses a generation rollback and would leave the right bytes on disk while
	// logging a warning about a write that should never have been attempted. The
	// document being right is not enough to tell the two apart; the silence is.
	if got := h.countLogged("could not be written"); got != 0 {
		t.Fatalf("the older snapshot was attempted and refused %d times, want the rule to have dropped it before the write", got)
	}
}

// --- Fix wave 1: the status on disk may not go backwards ---

// The status word is not a label but a claim about how much life a key has left, and
// within one generation that claim can only shrink: fresh, then stale, then invalid,
// as the key passes its published lifetime and then its grace, and never back. Nothing
// within one generation lengthens a key's life, so a publish that claims MORE life
// than the document on disk already claims is a caller's older reading of a key that
// has since aged.
//
// The file this is about is the one an operator reads, and `mosdns-cdnctl status`
// prints, when a force-ECH domain will not connect. A document that says stale
// while strict mode is already failing closed with ErrECHExpired is not a
// cosmetic error: it names a key as usable when the router has stopped using it,
// and the operator's next move is to go and look at the ECH source, which is
// working perfectly.
//
// All four phases are in this one test, because any one of them alone is satisfiable
// the wrong way. The first three are a key ageing normally and all of it published: a
// rule that refused every claim of less life would pass a regression-only test and
// bring back the document that froze after the first fetch, the defect the last fix
// round closed. The fourth is the regression -- a caller that read the key while it
// was inside its grace, arriving after the caller that watched its grace end -- and
// the fifth is that same caller one step further out of date, reading the key as
// fresh, which no amount of waiting can be right about: a key past its grace cannot
// become fresh again, so the only way to see it that way is to have looked earlier.
func TestTheStatusOnDiskNeverGoesBackwardsWithinOneGeneration(t *testing.T) {
	h := newHarness(t)
	key := echConfig{
		raw:        echFixture(t),
		source:     "cloudflare-ech.com",
		publicName: "cloudflare-ech.com",
		digest:     digestOf(echFixture(t)),
		fetchedAt:  h.now,
		expiresAt:  h.now.Add(300 * time.Second),
		staleUntil: h.now.Add(300*time.Second + 900*time.Second),
		generation: 1,
	}

	// A key ageing normally, all of it published.
	for _, status := range []string{echStatusFresh, echStatusStale, echStatusInvalid} {
		h.plugin.ech.publish(status, key)
		if got := readECHState(t, h.echStatePath).Status; got != status {
			t.Fatalf("after the %s snapshot the document on disk says %q: a key that has aged has to be described as it is now", status, got)
		}
	}

	// The caller that read this key while it was still inside its grace, arriving
	// now that the grace has ended and the strict arm has already failed closed.
	h.plugin.ech.publish(echStatusStale, key)

	document := readECHState(t, h.echStatePath)
	if document.Status != echStatusInvalid {
		t.Fatalf("status on disk = %q, want %q: an older reading of the same key replaced a later one, so the file an operator reads says a key is usable while the router is failing closed over it", document.Status, echStatusInvalid)
	}
	// The decision was made here rather than left to the state writer. The document
	// being right is not enough to tell the two apart; the silence is.
	if got := h.countLogged("could not be written"); got != 0 {
		t.Fatalf("the backwards snapshot was attempted and refused %d times, want the rule to have dropped it before the write", got)
	}

	// And the same caller, having read the key even earlier, when it was fresh.
	h.plugin.ech.publish(echStatusFresh, key)
	if got := readECHState(t, h.echStatePath).Status; got != echStatusInvalid {
		t.Fatalf("status on disk = %q, want %q: nothing within one generation lengthens a key's life, so a reading that claims a fresh key after its grace ended is a reading taken before it ended", got, echStatusInvalid)
	}
	if got := h.countLogged("could not be written"); got != 0 {
		t.Fatalf("the fresh snapshot was attempted and refused %d times, want the rule to have dropped it before the write", got)
	}
}

// digestOf is the digest of a list as the provider records it, so the fixtures
// above and the provider agree without either of them re-deriving the other's rule.
func digestOf(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// readECHState reads the document this plugin publishes, through the same reader
// the rest of the project uses.
func readECHState(t *testing.T, path string) state.ECHState {
	t.Helper()
	var document state.ECHState
	if err := state.ReadJSON(path, &document); err != nil {
		t.Fatalf("read the ECH state document: %v", err)
	}
	return document
}
