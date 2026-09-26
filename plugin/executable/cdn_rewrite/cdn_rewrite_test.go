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
	"strings"
	"sync"
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
	logs         *observer.ObservedLogs
	plugin       *Plugin
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
	// blankArg names one argument to leave empty, which is how the construction
	// refusals are presented: every one of the six paths is required, and the test
	// says which one it took away.
	blankArg string
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
	}
	policyContents := policyDocument(t, settings.mutatePolicy)
	if settings.ownPolicy != nil {
		policyContents = settings.ownPolicy(t)
	}
	writeFile(t, h.policyPath, policyContents)
	writeFile(t, h.selectorPath, selectorDocument(t, settings.selector))
	writeFile(t, h.forcePath, []byte(settings.forceList))
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
		logger:    zap.New(core),
		now:       func() time.Time { return h.now },
		pollEvery: testPollInterval,
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
		"  persistent_dump: false\n"
	return []byte(document)
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

// --- Step 1: the strict force-ECH short circuit ---

func TestStrictForcedAIsAnsweredWithoutAskingDownstream(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(forceECHName, dns.TypeA, aRecord(forceECHName, cloudflareAddress, 300))

	response, err := h.exec(t, forceECHName, dns.TypeA)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if response == nil {
		t.Fatal("the plugin left no response, which mosdns answers as REFUSED rather than as the empty answer strict mode promises")
	}
	if h.next.calls != 0 {
		t.Fatalf("the downstream sequence ran %d times, want 0: a strict force-ECH A query must cost no lookup", h.next.calls)
	}
	if asked := h.upstream.asked(); len(asked) != 0 {
		t.Fatalf("the ECH client was asked %d queries, want 0: an A query needs no key", len(asked))
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 0 {
		t.Fatalf("answer = %v, want no records at all", addressesIn(t, response.Answer))
	}
	if len(response.Ns) != 0 {
		t.Fatalf("authority = %v, want nothing: an SOA would claim a negative caching TTL this router cannot honour", response.Ns)
	}
	if response.AuthenticatedData {
		t.Fatal("AD is set on an answer this router wrote itself")
	}
	if got := response.Question[0]; got.Name != forceECHName || got.Qtype != dns.TypeA {
		t.Fatalf("question = %+v, want the query echoed back", got)
	}
}

func TestStrictForcedAAAAIsAnsweredWithoutAskingDownstream(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(forceECHName, dns.TypeAAAA, aaaaRecord(forceECHName, "2606:4700::1111", 300))

	response, err := h.exec(t, forceECHName, dns.TypeAAAA)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if response == nil {
		t.Fatal("the plugin left no response, which mosdns answers as REFUSED rather than as the empty answer strict mode promises")
	}
	if h.next.calls != 0 {
		t.Fatalf("the downstream sequence ran %d times, want 0: a strict force-ECH AAAA query must cost no lookup", h.next.calls)
	}
	if asked := h.upstream.asked(); len(asked) != 0 {
		t.Fatalf("the ECH client was asked %d queries, want 0: an AAAA query needs no key", len(asked))
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 0 {
		t.Fatalf("answer = %v, want no records at all", addressesIn(t, response.Answer))
	}
	if len(response.Ns) != 0 {
		t.Fatalf("authority = %v, want nothing: an SOA would claim a negative caching TTL this router cannot honour", response.Ns)
	}
}

// A name the operator did not list is an ordinary query, and a strict policy
// changes nothing about it: the short circuit is a property of the allowlist.
func TestStrictPolicyStillAsksDownstreamForANameItDoesNotForce(t *testing.T) {
	h := newHarness(t)
	h.next.response = answerWith(cloudflareName, dns.TypeA, aRecord(cloudflareName, cloudflareAddress, 300))

	h.mustExec(t, cloudflareName, dns.TypeA)

	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want 1: only a listed domain is short circuited", h.next.calls)
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

// The address a rewrite installs is the one the health check last proved, and a
// window that has closed is not proved any more. Under strict that is fatal,
// because a record with no hint sends the client to resolve a name whose
// resolution this router has emptied.
func TestStrictForcedHTTPSFailsClosedWhenTheProofWindowIsClosed(t *testing.T) {
	h := newHarness(t)
	h.now = time.Date(2026, 9, 25, 12, 5, 0, 0, time.UTC)
	h.next.response = theHTTPSIn(t, forceECHName)

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err == nil {
		t.Fatal("Exec returned no error, so a strict force-ECH name was answered from a selector nothing has proved")
	}
	if !errors.Is(err, dnsrewrite.ErrNoSelectedAddress) {
		t.Fatalf("error = %v, want one wrapping ErrNoSelectedAddress, so the log line says the address is what failed", err)
	}
	if response != nil {
		t.Fatalf("a failing strict answer was set on the context: %v", response.Answer)
	}
}

// The fallback arm is the one a caller gets wrong by returning as soon as it sees
// an error: the rewrite package hands the upstream's own record back WITH the
// refusal, and a caller that discards the record turns a working fallback domain
// into a SERVFAIL through this router's own health gate.
func TestFallbackForcedHTTPSWithAClosedProofWindowKeepsTheUpstreamRecord(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) { p.ECH.FailurePolicy = "fallback" }
	})
	h.now = time.Date(2026, 9, 25, 12, 5, 0, 0, time.UTC)
	upstream := theHTTPSIn(t, forceECHName)
	before := mustPack(t, upstream)
	h.next.response = upstream

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err != nil {
		t.Fatalf("Exec: %v: a fallback name whose selector is down must keep the answer the upstream published", err)
	}
	if h.next.calls != 1 {
		t.Fatalf("the downstream sequence ran %d times, want exactly 1", h.next.calls)
	}
	if response == nil {
		t.Fatal("the plugin left no response, which mosdns answers as REFUSED")
	}
	if got := mustPack(t, response); string(got) != string(before) {
		t.Fatalf("the upstream's own record was not kept:\n before %s\n after  %s", before, got)
	}
	if got := theSynthesized(t, response); len(got.Value) == 0 {
		t.Fatal("the kept record carries no parameters at all")
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

// A source that publishes a lifetime shorter than the floor is not asked once per
// client query: the floor is the whole reason it exists.
func TestAShortPublishedTTLIsRaisedToTheSixtySecondMinimum(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.echAnswer = answerWithECH(echFixture(t), 5)
		c.selector = provenFor(time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC))
	})
	h.next.response = theHTTPSIn(t, forceECHName)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)

	h.now = h.now.Add(30 * time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	if asked := h.upstream.asked(); len(asked) != 1 {
		t.Fatalf("a source publishing a 5 second TTL was asked %d times inside 30 seconds, want 1", len(asked))
	}

	h.now = h.now.Add(31 * time.Second)
	h.mustExec(t, forceECHName, dns.TypeHTTPS)
	if asked := h.upstream.asked(); len(asked) != 2 {
		t.Fatalf("the ECH client was asked %d times a minute after the fetch, want 2", len(asked))
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

// A list two sources disagree about is not forwarded: a client that picks a config
// out of it has two different answers to which name it is talking to, and choosing
// between them is a decision no component of this router is placed to make. Every
// source is read, because the agreement is only real if every source is asked.
func TestTwoSourcesNamingDifferentPublicNamesAreRefused(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.mutatePolicy = func(p *config.Policy) {
			p.ECH.Sources = []string{"cloudflare-ech.com", "other-ech.example.com"}
		}
		c.echAnswer = func(question dns.Question) (*dns.Msg, error) {
			// The public name is a name, so it is the source's name as a person
			// writes one: without the dot the wire carries.
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

	response, err := h.exec(t, forceECHName, dns.TypeHTTPS)

	if err == nil {
		t.Fatal("Exec returned no error, so a key two sources disagreed about was installed")
	}
	if !errors.Is(err, dnsrewrite.ErrNoECHConfig) {
		t.Fatalf("error = %v, want one wrapping ErrNoECHConfig", err)
	}
	if response != nil {
		t.Fatalf("a refused key was installed anyway: %v", response.Answer)
	}
	if asked := h.upstream.asked(); len(asked) != 2 {
		t.Fatalf("the ECH client was asked %d queries, want 2", len(asked))
	}
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
		t.Fatalf("expires_at = %s, want the fetch plus the published 300 second TTL, %s", document.ExpiresAt, want)
	}
	if want := time.Date(2026, 9, 25, 12, 20, 0, 0, time.UTC); !document.StaleUntil.Equal(want) {
		t.Fatalf("stale_until = %s, want the expiry plus the policy's 900 second grace, %s", document.StaleUntil, want)
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

// A new allowlist is served to the next query: the new domain is short circuited
// and the domain that came off the list is not.
func TestANewForceECHListIsServedToTheNextQuery(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.forcePath, []byte("# the operator replaced the list\nsecure2.example.com\n"))
	h.waitFor(t, "the new allowlist to be served", func() bool {
		return len(h.plugin.force.Snapshot()) == 1 && h.plugin.force.Snapshot()[0] == "secure2.example.com"
	})

	listed := h.mustExec(t, "secure2.example.com.", dns.TypeA)
	if len(listed.Answer) != 0 {
		t.Fatalf("the newly listed domain was answered with %v", addressesIn(t, listed.Answer))
	}
	h.next.response = answerWith(forceECHName, dns.TypeA, aRecord(forceECHName, foreignAddress, 300))
	if removed := h.mustExec(t, forceECHName, dns.TypeA); len(removed.Answer) != 1 {
		t.Fatalf("a domain that came off the list was still short circuited: %v", addressesIn(t, removed.Answer))
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

	listed := h.mustExec(t, forceECHName, dns.TypeA)
	if len(listed.Answer) != 0 {
		t.Fatalf("the last valid list stopped being honoured: %v", addressesIn(t, listed.Answer))
	}
	h.next.response = answerWith("secure3.example.com.", dns.TypeA, aRecord("secure3.example.com.", foreignAddress, 300))
	if added := h.mustExec(t, "secure3.example.com.", dns.TypeA); len(added.Answer) != 1 {
		t.Fatal("a domain from a list that was refused whole was short circuited anyway")
	}
}

// A file of no bytes is what an operator's interrupted in-place write leaves
// there, and accepting it would drop every forced domain in the router without a
// word. The last valid list survives it.
func TestAZeroByteForceECHListKeepsTheLastValidList(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.forcePath, nil)
	h.waitFor(t, "the empty allowlist to be reported", func() bool { return h.loggedRefusal() })

	listed := h.mustExec(t, forceECHName, dns.TypeA)
	if len(listed.Answer) != 0 {
		t.Fatalf("a zero-byte allowlist dropped every forced domain: %v", addressesIn(t, listed.Answer))
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
			name:  "a strict force-ECH A query",
			qname: forceECHName,
			qtype: dns.TypeA,
			answer: func(t *testing.T) *dns.Msg {
				return answerWith(forceECHName, dns.TypeA, aRecord(forceECHName, cloudflareAddress, 300))
			},
			wantNext: 0,
		},
		{
			name:  "a strict force-ECH AAAA query",
			qname: forceECHName,
			qtype: dns.TypeAAAA,
			answer: func(t *testing.T) *dns.Msg {
				return answerWith(forceECHName, dns.TypeAAAA, aaaaRecord(forceECHName, "2606:4700::1111", 300))
			},
			wantNext: 0,
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
