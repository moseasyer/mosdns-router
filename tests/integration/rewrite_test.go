// The response rewriter, on the wire.
//
// The cases in this file are about the one thing the renderer's structural tests
// cannot say: what a client actually receives. They run the real binary against
// real sockets, with the rendered document exactly as the committed file has it,
// and they read the answers, the query counts on both resolvers, and the router's
// own output.
//
// What the harness supplies is everything the plugin reads, in the case's own
// directory: the policy, the published selector, the operator's allowlist, the
// published Cloudflare ranges, and the path the ECH metadata is written to. None of
// them is at its production path, so a case can publish a selection, break an ECH
// source, or force a domain without touching /etc or /var/lib -- and every path in
// the rendered document is one a test chose, so a mistyped argument shows up as an
// unstartable router rather than as a feature quietly doing nothing.
//
// The fixtures are hand-derived. Every expected record below is written out as the
// literal the client should receive, and every address is one the published ranges
// or the state package's own rules make possible: the selector cannot publish a
// documentation address at all, so the winners are real public addresses, and the
// mock's Cloudflare address is inside the one range the prefix list holds.
package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"mosdns-router/internal/candidate"
	"mosdns-router/internal/config"
	"mosdns-router/internal/mosdnsconfig"
	"mosdns-router/internal/state"
	"mosdns-router/internal/testdns"
)

// The names the rewrite cases are about. They are under .test, which RFC 6761
// reserves for testing, so no pinned China list can match one of them by accident
// and every answer in this file is the foreign branch's. The harness proves that
// with the router's own matcher before it starts anything, because a name that
// matched would send the case down the domestic branch and every assertion here
// would be about a resolver this file never asks.
const (
	// cloudflareName is served entirely from inside the published range, so the
	// classifier accepts it and the rewrite is authorized.
	cloudflareName = "cdn.example.test."
	// mixedName names a Cloudflare address and one outside every published range,
	// which is the response this router must not rewrite.
	mixedName = "mixed.example.test."
	// plainName is served from outside every published range and is not mapped, so
	// nothing in the document authorises touching it.
	plainName = "plain.example.test."
	// frontName and frontTarget are the two ends of one per-hostname CloudFront
	// mapping: a distribution reached through an alias, which is the ordinary
	// shape of such a mapping.
	frontName   = "front.example.test."
	frontTarget = "d111111abcdef8.cloudfront.net."
	// siblingName shares a parent with frontName and is not mapped, so it is the
	// control for the mapping's exactness.
	siblingName = "sibling.example.test."
	// forcedName is the domain the operator put on the allowlist. Its A answer is
	// Cloudflare-served, so this router rewrites it before the forcing begins --
	// which is what gives the case a cache entry holding a real answer to a strict
	// query later on.
	forcedName = "ech.example.test."
	// forcedMixedName is the second forced domain, and it is mixed on purpose. Its
	// A answer is refused by the classifier, so no IPv6 suppression is ever entered
	// for it, which is what makes its empty answers attributable to the strict short
	// circuit alone: nothing else in this router can produce an empty answer for a
	// name it has no verdict about.
	forcedMixedName = "forced-mixed.example.test."
	// echSourceName is the ECH source the policy names, and the name the router
	// asks for its key under. It is the same host as the key's public name, which
	// is what a real ECH provider looks like.
	echSourceName = "cloudflare-ech.com"
)

// The published Cloudflare range, and the addresses inside and outside it. The
// prefix list in these cases holds exactly one range, so a fixture address is
// either unambiguously inside a published range or unambiguously outside every one.
const (
	publishedRange      = "104.16.0.0/13"
	cloudflareAddress   = "104.16.0.10"  // inside the published range
	selectedAddress     = "104.16.32.7"  // generation one's winner, also inside it
	fallbackAddress     = "104.16.98.98" // the selector's fallback, which no rule here reads
	successorAddress    = "45.45.45.45"  // generation two's winner, OUTSIDE the range
	offRangeAddress     = "198.51.100.7" // outside every published range
	upstreamHint        = "198.51.100.50"
	distributionAddress = "198.51.100.20" // what the distribution publishes
	siblingAddress      = "198.51.100.21"
	plainAddress        = "198.51.100.30"
	cloudFrontAddress   = "13.35.0.1" // the per-hostname mapping's address
	cloudflareIPv6      = "2606:4700:4700::1111"
)

// answerTTL is the TTL every fixture record carries, so the TTL in an answer is a
// value the case can state rather than one it has to read back and compare to
// itself. The rewrite takes the minimum over the records it replaces, so a
// single-record answer keeps exactly this.
const answerTTL = 300

// echFixtureBase64 is the ECHConfigList the fixture ECH source publishes: the same
// non-secret bytes internal/echconfig and internal/dnsrewrite are tested against,
// so the parameter a client would receive here is one a real browser has received.
// It decodes to 71 bytes, the outer uint16 length 0x0045, and one ECHConfig of
// version 0xfe0d whose public name is cloudflare-ech.com.
//
// The expectation in the case below is this string and not the fixture's decode:
// a client receives bytes, and a case that compared the answer against the same
// helper the answer was built with would agree with it whatever it said.
const echFixtureBase64 = "AEX+DQBBuAAgACBeWfLyd08MrrxQgz3O0ws1h/j6yhgH1+4jTfFQ5Y6qawAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

// The lines the router's own output must carry where a case is about a refusal.
// The second is mosdns reporting that a plugin returned an error, which is what
// turns into SERVFAIL; the rest are this project's plugin naming what it did.
const (
	noECHKeyLog      = "cdn_rewrite: there is no usable ECH key to install"
	keptOriginalLog  = "cdn_rewrite: the force-ECH answer was left as the upstream published it"
	fetchedECHKeyLog = "cdn_rewrite: fetched an ECH key"
)

// selectorReloadDeadline bounds how long a case waits for the plugin's poll to
// pick up a document it published. The plugin's interval is half a second, so this
// is generous; it is here because a case that published a document and asked
// immediately would be racing the poll rather than testing it.
const selectorReloadDeadline = 10 * time.Second

// rewriteFixture is everything the rewriter reads, as a case chooses it. A case
// names only the field it is about, and every other field has a value that makes
// the plugin start and change nothing beyond what the case is looking at.
type rewriteFixture struct {
	// policy is applied to the defaults before the file is written.
	policy func(*config.Policy)
	// selector is written as it stands, through the state package's own writer.
	selector state.Selector
	// allowlist is the operator's file, written verbatim.
	allowlist string
	// prefixes is the published range list, written verbatim.
	prefixes string
	// publishECHKey decides what the ECH source answers: a service mode carrying
	// the key, or a service mode without one.
	publishECHKey bool
}

// inactiveRewriteFixture is what the routing cases start the router with. The
// plugin is installed and nothing is selected and nothing is forced, so a routing
// case is proving the routing of the document this project actually ships rather
// than of a shape with the rewriter removed.
func inactiveRewriteFixture() rewriteFixture {
	return rewriteFixture{
		selector:  disabledSelector(),
		allowlist: "# no domain is forced in this configuration\n",
		prefixes:  publishedRange + "\n",
	}
}

// strictECHFixture is the working router: a selection proved a moment ago, the
// published ranges, and an ECH source that publishes a key.
func strictECHFixture() rewriteFixture {
	return rewriteFixture{
		selector:      liveSelector(1, selectedAddress),
		allowlist:     "# no domain is forced in this configuration\n",
		prefixes:      publishedRange + "\n",
		publishECHKey: true,
	}
}

// write publishes the fixture's documents into a directory and returns the paths a
// rendered configuration has to name for them. The ECH state document is the one
// path nothing writes here: it is the plugin's to publish, and a case that wanted
// to see it written would have to read it rather than seed it.
func (f rewriteFixture) write(t *testing.T, directory string) mosdnsconfig.Paths {
	t.Helper()
	policy := config.Defaults()
	policy.ECH.Sources = []string{echSourceName}
	if f.policy != nil {
		f.policy(&policy)
	}
	document, err := config.Marshal(policy)
	if err != nil {
		t.Fatalf("encode the policy for the rewriter: %v", err)
	}
	if err := f.selector.Validate(); err != nil {
		t.Fatalf("the fixture selector is not one the state package accepts: %v", err)
	}
	return mosdnsconfig.Paths{
		Policy:             publishFile(t, filepath.Join(directory, "policy.yaml"), document),
		Selector:           publishSelector(t, filepath.Join(directory, "cdn-selector.json"), f.selector),
		ForceECH:           publishFile(t, filepath.Join(directory, "force-ech-domains.txt"), []byte(f.allowlist)),
		CloudflarePrefixes: publishFile(t, filepath.Join(directory, "cloudflare-prefixes.txt"), []byte(f.prefixes)),
		ECHState:           filepath.Join(directory, "ech-state.json"),
	}
}

// withRewriteFiles returns paths carrying the rewriter's five documents, so a
// caller names the rest and cannot leave one of them out by forgetting it.
func withRewriteFiles(paths, files mosdnsconfig.Paths) mosdnsconfig.Paths {
	paths.Policy = files.Policy
	paths.Selector = files.Selector
	paths.ForceECH = files.ForceECH
	paths.ECHState = files.ECHState
	paths.CloudflarePrefixes = files.CloudflarePrefixes
	return paths
}

// disabledSelector is a selector that selects nothing: the state a router serves
// before the optimizer has ever run, and the one a routing case wants so that a
// foreign answer comes back exactly as the resolver published it.
func disabledSelector() state.Selector {
	return disabledSelectorAt(0)
}

// disabledSelectorAt is the same document at a named generation, for a case that has
// already published a later one. The state writer refuses a rollback -- a selector
// that moved backwards is a writer that lost a race, and serving it would be serving
// a decision the optimizer has taken back -- so withdrawing a selection has to be a
// new generation and not the document a router booted with.
func disabledSelectorAt(generation uint64) state.Selector {
	return state.NewSelector(generation, "disabled", string(candidate.ProviderCloudflare), time.Unix(0, 0).UTC())
}

// liveSelector is a selector whose winner was proved a moment ago and whose window
// is two minutes ahead, which is the shape a health check that has just passed
// publishes. Two minutes is the real health interval, so the window is the short
// one on purpose: a fixture with a generous window would not be exercising a gate.
func liveSelector(generation uint64, winner string) state.Selector {
	proved := time.Now().UTC()
	published := state.NewSelector(generation, "auto", string(candidate.ProviderCloudflare), proved)
	published.WinnerIP = winner
	published.FallbackIP = fallbackAddress
	published.WinnerProofUntil = proved.Add(2 * time.Minute)
	published.ConfigSHA256 = strings.Repeat("a", 64)
	return published
}

// publishFile writes a file the way every writer in this project does: a temporary
// name in the same directory, then a rename, so a reader never sees half of it.
func publishFile(t *testing.T, path string, contents []byte) string {
	t.Helper()
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		t.Fatalf("write %s: %v", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatalf("replace %s: %v", path, err)
	}
	return path
}

// publishSelector writes a state document with this repository's own writer, so the
// plugin reads what the optimizer would have written rather than a literal this
// file has to keep in step with the schema.
func publishSelector(t *testing.T, path string, published state.Selector) string {
	t.Helper()
	if err := state.WriteJSONAtomic(path, published); err != nil {
		t.Fatalf("publish the selector: %v", err)
	}
	return path
}

// rewriteHarness is the routing harness with the rewriter's documents behind it.
// It is the same process, the same two resolvers and the same readiness poll, so a
// case here is asking the question in a document that really is the shipped one.
type rewriteHarness struct {
	*harness

	// The five documents, kept so a case can replace one of them the way the
	// component that owns it would.
	selectorPath string
	allowlist    string
	echStatePath string
	prefixPath   string
	policyPath   string
}

func newRewriteHarness(t *testing.T, fixture rewriteFixture) *rewriteHarness {
	t.Helper()
	// The domestic mock is on a real local address because the production state
	// decoder refuses a loopback upstream, and the plugin reads the state through
	// that decoder. A host that has no such address is a skip on a plain run and a
	// failure in a gate, which is the same rule the routing cases use.
	address, interfaceName := localUnicastAddress(t)
	t.Logf("the domestic resolver answers on %s (%s), and the published state names that address and interface", address, interfaceName)

	rw := &rewriteHarness{harness: &harness{upstreamAddress: address, interfaceName: interfaceName}}
	// The foreign resolver is on loopback: nothing about it is validated, and
	// loopback cannot be reached from off this host.
	rw.foreign = startRewriteResolver(t, fixture)
	t.Cleanup(func() { _ = rw.foreign.Close() })
	rw.domestic = startDomesticResolver(t, address, &rw.answered)
	t.Cleanup(func() { _ = rw.domestic.Close() })

	directory := t.TempDir()
	rw.cnList = writeChinaList(t, directory, committedChinaList)
	// Every name in this file has to take the foreign branch, or the cases are
	// asking the domestic resolver questions they never meant to ask. The matcher
	// is the one the rendered document builds, so this is the router's own
	// classification and not a guess about the list.
	for _, name := range []string{cloudflareName, mixedName, plainName, frontName, frontTarget, siblingName, forcedName} {
		if inCommittedChinaList(t, rw.cnList, name) {
			t.Fatalf("the committed China list matches %s, so this case would be answered by the domestic resolver", name)
		}
	}
	rw.stateFile = filepath.Join(directory, "dhcp-upstreams.json")
	rw.publishState(t, firstGeneration)

	files := fixture.write(t, directory)
	rw.selectorPath = files.Selector
	rw.allowlist = files.ForceECH
	rw.echStatePath = files.ECHState
	rw.prefixPath = files.CloudflarePrefixes
	rw.policyPath = files.Policy

	rw.listen = reserveLoopbackAddress(t)
	_, upstreamPort, err := net.SplitHostPort(rw.domestic.Address())
	if err != nil {
		t.Fatalf("split the domestic address %q: %v", rw.domestic.Address(), err)
	}
	document, err := mosdnsconfig.Render(config.Defaults(), withRewriteFiles(mosdnsconfig.Paths{
		CNDomains:       rw.cnList,
		DHCPState:       rw.stateFile,
		ForeignListener: "tcp://" + rw.foreign.Address(),
		Listen:          rw.listen,
		// A published state carries a bare address, so the port it is dialled on
		// is the document's to state.
		DHCPUpstreamPort: atoi(t, upstreamPort),
	}, files))
	if err != nil {
		t.Fatalf("render a configuration with the rewriter: %v", err)
	}
	configPath := filepath.Join(directory, "mosdns.yaml")
	if err := os.WriteFile(configPath, document, 0o600); err != nil {
		t.Fatalf("write the rendered configuration: %v", err)
	}
	t.Logf("the router answers on %s; the policy is %s, the selector %s, the allowlist %s, the ranges %s and the ECH document %s",
		rw.listen, rw.policyPath, rw.selectorPath, rw.allowlist, rw.prefixPath, rw.echStatePath)

	rw.router = startRouter(t, configPath)
	return rw
}

// selectWith publishes a new selector generation and waits until the plugin is
// serving it, so a case can say what a generation change did without racing the
// plugin's half-second poll. The wait is on the observable effect, not on a sleep:
// it asks until the answer changes, which is the only thing a client could have
// observed anyway. The name and type are arguments because a per-hostname mapping
// changes one name's answer and leaves the global one alone.
func (rw *rewriteHarness) selectWith(t *testing.T, published state.Selector, name string, want string) {
	t.Helper()
	if err := published.Validate(); err != nil {
		t.Fatalf("the published selector is not one the state package accepts: %v", err)
	}
	publishSelector(t, rw.selectorPath, published)
	deadline := time.Now().Add(selectorReloadDeadline)
	for attempt := 0; ; attempt++ {
		response := rw.ask(t, testdns.ProtocolTCP, name, dns.TypeA)
		if got := publishedAddresses(t, response); equalStrings(got, []string{want}) {
			t.Logf("the plugin serves selector generation %d after %d attempt(s)", published.Generation, attempt+1)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the plugin was still serving the previous selector generation after %s, want the published one (generation %d, winner %s)",
				time.Since(deadline.Add(-selectorReloadDeadline)).Round(time.Millisecond), published.Generation, want)
		}
		time.Sleep(readinessPollWait)
	}
}

// forceECH publishes an allowlist naming domains and waits until the plugin is
// serving the new list.
//
// What says the list is in force depends on the policy the case runs under, so the
// caller names the effect it is waiting for rather than the harness guessing: under
// strict it is the empty answer a forced A query gets, and under fallback there is
// no such answer at all -- every answer for a forced name is the one the resolver
// published, before and after -- so the effect there is the plugin's own report that
// it kept what the upstream published. Waiting on the wrong one of those is how a
// case ends up asserting the policy it is not running.
func (rw *rewriteHarness) forceECH(t *testing.T, domains []string, inForce func() bool) {
	t.Helper()
	contents := "# forced by this case\n" + strings.Join(domains, "\n") + "\n"
	publishFile(t, rw.allowlist, []byte(contents))
	deadline := time.Now().Add(selectorReloadDeadline)
	for attempt := 0; ; attempt++ {
		if inForce() {
			t.Logf("the plugin serves an allowlist naming %v after %d attempt(s)", domains, attempt+1)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the plugin was not serving an allowlist naming %v after %s, so every question below would be answered as though the operator had listed nothing",
				domains, selectorReloadDeadline)
		}
		time.Sleep(readinessPollWait)
	}
}

// strictForced reports whether every named domain is answered with the strict empty
// answer, which is what an allowlist entry in force looks like from outside under the
// strict policy.
func (rw *rewriteHarness) strictForced(t *testing.T, domains ...string) bool {
	t.Helper()
	for _, domain := range domains {
		question := dns.Fqdn(domain)
		response := rw.ask(t, testdns.ProtocolTCP, question, dns.TypeA)
		if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 0 {
			return false
		}
	}
	return true
}

// publishedAddresses is every address in an answer, skipping the signatures beside
// them. A rewritten answer has none, so this only matters for the answers that came
// back untouched, and it is the reason a case can state which addresses a name
// resolves to without caring how many proofs travelled with them.
func publishedAddresses(t *testing.T, response *dns.Msg) []string {
	t.Helper()
	addresses := make([]string, 0, len(response.Answer))
	for _, record := range response.Answer {
		switch typed := record.(type) {
		case *dns.A:
			addresses = append(addresses, typed.A.String())
		case *dns.AAAA:
			addresses = append(addresses, typed.AAAA.String())
		case *dns.CNAME:
			// A chain is not an address. The cases that care about one assert it
			// against a literal of their own, because a mapping's whole shape is
			// which name in the answer holds the addresses.
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3:
		default:
			t.Fatalf("the answer carries %v, which is neither an address nor a proof: %v", record, record)
		}
	}
	return addresses
}

// startRewriteResolver is the resolver the foreign branch is pointed at, answering
// one record shape per name. Every response it publishes is a positive one with the
// AD bit set and an RRSIG beside the RRset it signed, because the cases are about
// what survives a rewrite and only a response that carried the proof can show it.
//
// A name it does not know gets no record rather than a plausible one: a case that
// asked for something unexpected should see SERVFAIL, not a wrong answer.
func startRewriteResolver(t *testing.T, fixture rewriteFixture) *testdns.Server {
	t.Helper()
	server, err := testdns.StartOn("127.0.0.1:0", func(_ context.Context, request *dns.Msg) *dns.Msg {
		return rewriteResponse(t, request, fixture)
	})
	if err != nil {
		t.Fatalf("start the foreign resolver: %v", err)
	}
	return server
}

// rewriteResponse is the whole answer table, as the records a zone would publish.
func rewriteResponse(t *testing.T, request *dns.Msg, fixture rewriteFixture) *dns.Msg {
	t.Helper()
	question := request.Question[0]
	response := new(dns.Msg)
	response.SetReply(request)
	// Every answer this resolver gives claims to have been validated. The break a
	// case looks for is a modified answer that stops claiming it, and a control
	// that shows an unmodified one still does.
	response.AuthenticatedData = true

	// The owner of a directly published record is the name that was asked for. A
	// fixture that answered under a neighbour's name would be refused by the
	// classifier for a reason that has nothing to do with what a case is testing.
	header := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: question.Name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: answerTTL}
	}
	// A record this resolver publishes under a name other than the one asked for is
	// only ever a chain's end, and a chain's end is named rather than derived.
	other := func(name string, rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: answerTTL}
	}
	switch question.Name {
	case cloudflareName, forcedName, forcedMixedName:
		switch question.Qtype {
		case dns.TypeA:
			if question.Name == forcedMixedName {
				response.Answer = []dns.RR{
					&dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(cloudflareAddress)},
					&dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(offRangeAddress)},
					rrsigOver(forcedMixedName, dns.TypeA),
				}
				break
			}
			response.Answer = []dns.RR{
				&dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(cloudflareAddress)},
				rrsigOver(cloudflareName, dns.TypeA),
			}
		case dns.TypeAAAA:
			response.Answer = []dns.RR{
				&dns.AAAA{Hdr: header(dns.TypeAAAA), AAAA: net.ParseIP(cloudflareIPv6)},
				rrsigOver(question.Name, dns.TypeAAAA),
			}
		case dns.TypeHTTPS:
			if question.Name == forcedName {
				response.Answer = []dns.RR{serviceBinding(forcedName), rrsigOver(forcedName, dns.TypeHTTPS)}
			}
		}
	case mixedName:
		if question.Qtype == dns.TypeA {
			response.Answer = []dns.RR{
				&dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(cloudflareAddress)},
				&dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(offRangeAddress)},
				rrsigOver(mixedName, dns.TypeA),
			}
		}
	case plainName:
		if question.Qtype == dns.TypeA {
			response.Answer = []dns.RR{
				&dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(plainAddress)},
				rrsigOver(plainName, dns.TypeA),
			}
		}
	case frontName:
		if question.Qtype == dns.TypeA {
			response.Answer = []dns.RR{
				&dns.CNAME{Hdr: header(dns.TypeCNAME), Target: frontTarget},
				&dns.A{Hdr: other(frontTarget, dns.TypeA), A: net.ParseIP(distributionAddress)},
				rrsigOver(frontTarget, dns.TypeA),
			}
		}
	case siblingName:
		if question.Qtype == dns.TypeA {
			response.Answer = []dns.RR{
				&dns.A{Hdr: header(dns.TypeA), A: net.ParseIP(siblingAddress)},
				rrsigOver(siblingName, dns.TypeA),
			}
		}
	case dns.Fqdn(echSourceName):
		if question.Qtype == dns.TypeHTTPS {
			// The key, or a service mode without one. The second shape is what a
			// source that has withdrawn its key looks like, and it is a different
			// refusal from an unreachable source.
			source := &dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      other(question.Name, dns.TypeHTTPS),
				Priority: 1,
				Target:   ".",
				Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}}},
			}}
			if fixture.publishECHKey {
				raw, err := base64.StdEncoding.DecodeString(echFixtureBase64)
				if err != nil {
					// This runs on the resolver's handler goroutine, so a Fatalf here
					// runs runtime.Goexit on the wrong goroutine: no reply is ever
					// written, the client waits out its own timeout, and the case
					// fails as a timeout that says nothing about the ECH path or
					// about the fixture that caused it. Report and answer SERVFAIL,
					// which is what a handler returning nil does, so the case fails
					// where the fixture is wrong.
					t.Errorf("decode the ECH fixture: %v", err)
					return nil
				}
				source.Value = append(source.Value, &dns.SVCBECHConfig{ECH: raw})
			}
			response.Answer = []dns.RR{source}
		}
	}
	if len(response.Answer) == 0 {
		return nil
	}
	// A validating resolver states the denial of existence that goes with a name it
	// has nothing signed for, and the cases assert that it goes with the rewrite
	// rather than staying beside it.
	if question.Qtype == dns.TypeA {
		response.Ns = []dns.RR{&dns.NSEC{
			Hdr:        dns.RR_Header{Name: question.Name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: answerTTL},
			NextDomain: "next.example.test.",
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
		}}
	}
	return response
}

// serviceBinding is the HTTPS record the force-ECH name publishes: a service mode
// with the protocols and the port a TLS edge serves, and an IPv4 hint of its own.
// The hint is the one thing the synthesized record must not inherit, because a
// hint of the upstream's would send the client to the address the health check
// never proved.
func serviceBinding(name string) *dns.HTTPS {
	return &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: answerTTL},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}},
			&dns.SVCBPort{Port: 443},
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(upstreamHint)}},
		},
	}}
}

// rrsigOver is one RRSIG over the RRset of a name, which is what a validating
// upstream puts beside an answer this router is about to change. The library packs a
// signature as base64, so the fixture is written the way a zone file carries it.
func rrsigOver(name string, covered uint16) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: answerTTL},
		TypeCovered: covered,
		Algorithm:   dns.ECDSAP256SHA256,
		Labels:      3,
		OrigTtl:     answerTTL,
		Expiration:  1788000000,
		Inception:   1787000000,
		KeyTag:      1234,
		SignerName:  "example.test.",
		Signature:   "AQIDBA==",
	}
}

// --- assertions ---

// onlyRecord asserts an answer carries exactly the records given and nothing else,
// comparing them in packed form: the record that came back and the record the case
// wrote down are each re-packed by the same encoder, so a field the router rebuilt
// differently fails here and a difference the wire format does not distinguish does
// not. It is packed-form equality and the name says so.
func onlyRecord(t *testing.T, response *dns.Msg, want ...dns.RR) {
	t.Helper()
	if len(response.Answer) != len(want) {
		t.Fatalf("the answer carries %d record(s), want %d: %v", len(response.Answer), len(want), response.Answer)
	}
	for index := range want {
		if got, expected := recordPacked(t, response.Answer[index]), recordPacked(t, want[index]); !bytes.Equal(got, expected) {
			t.Errorf("record %d is\n got  %v\n want %v", index, response.Answer[index], want[index])
		}
	}
}

// recordKinds names every record in a response by type, so a case can say what
// survived rather than counting a section.
func recordKinds(msg *dns.Msg) []string {
	var kinds []string
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, record := range section {
			kinds = append(kinds, dns.TypeToString[record.Header().Rrtype])
		}
	}
	return kinds
}

// proofsIn counts the records a modified answer may not keep: a signature over
// records that are no longer there, and a denial of existence beside them.
func proofsIn(msg *dns.Msg) int {
	count := 0
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, record := range section {
			switch record.Header().Rrtype {
			case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				count++
			}
		}
	}
	return count
}

// carriesNoProofs asserts the message no longer claims to be validated, and says
// what it does carry so a failure shows the whole answer.
func carriesNoProofs(t *testing.T, response *dns.Msg) {
	t.Helper()
	if response.AuthenticatedData {
		t.Errorf("the answer still claims DNSSEC validation (AD=1) although this router changed it: %v", recordKinds(response))
	}
	if proofs := proofsIn(response); proofs != 0 {
		t.Errorf("the answer still carries %d DNSSEC record(s) over data this router replaced: %v", proofs, recordKinds(response))
	}
}

// keepsItsProofs is the control for the assertion above, and it is the reason the
// cases cannot pass by a plugin that strips DNSSEC from everything: an answer this
// router did not change has to come back with the validation the upstream claimed
// and the signature beside it.
func keepsItsProofs(t *testing.T, response *dns.Msg) {
	t.Helper()
	if !response.AuthenticatedData {
		t.Errorf("the answer lost its AD bit although this router changed nothing: %v", recordKinds(response))
	}
	if proofs := proofsIn(response); proofs == 0 {
		t.Errorf("the answer lost every DNSSEC record although this router changed nothing: %v", recordKinds(response))
	}
}

// httpRecord returns the one HTTPS record an answer must carry, and fails when it
// carries two of them: two service descriptions for one name is a choice this router
// does not get to make, and a case that read the first would pass on an answer a
// client cannot use. The signature beside the record is not a second one.
func httpRecord(t *testing.T, response *dns.Msg) *dns.HTTPS {
	t.Helper()
	var found *dns.HTTPS
	for _, record := range response.Answer {
		typed, ok := record.(*dns.HTTPS)
		if !ok {
			continue
		}
		if found != nil {
			t.Fatalf("the %s answer carries two HTTPS records: %v", dns.TypeToString[dns.TypeHTTPS], recordKinds(response))
		}
		found = typed
	}
	if found == nil {
		t.Fatalf("the answer carries no %s record: %v", dns.TypeToString[dns.TypeHTTPS], recordKinds(response))
	}
	return found
}

// parameter returns the one value a record carries for a key.
func parameter(t *testing.T, record *dns.HTTPS, key dns.SVCBKey) dns.SVCBKeyValue {
	t.Helper()
	var found dns.SVCBKeyValue
	for _, pair := range record.Value {
		if pair.Key() == key {
			if found != nil {
				t.Fatalf("the record carries key %d twice, which RFC 9460 makes a record a client may reject", key)
			}
			found = pair
		}
	}
	if found == nil {
		t.Fatalf("the record carries no key %d: %v", key, record.Value)
	}
	return found
}

// hasParameter reports whether a record carries a key at all, so a case can say a
// hint is ABSENT rather than only that a value is right.
func hasParameter(record *dns.HTTPS, key dns.SVCBKey) bool {
	for _, pair := range record.Value {
		if pair.Key() == key {
			return true
		}
	}
	return false
}

// parameterNames names every key a record carries, in the order the wire carried
// them. The names are the RFC 9460 key numbers, because the ORDER is part of what
// the client receives and a case that compared against the order this router built
// the record in would agree with it whatever it built.
func parameterNames(record *dns.HTTPS) []string {
	names := make([]string, 0, len(record.Value))
	for _, pair := range record.Value {
		names = append(names, fmt.Sprintf("%d:%s", pair.Key(), serviceParameterName(pair.Key())))
	}
	return names
}

// serviceParameterName spells out the key numbers this project installs or inherits,
// and falls back to the number for anything else so a case failure names a key even
// when this file has no opinion about it.
func serviceParameterName(key dns.SVCBKey) string {
	switch key {
	case dns.SVCB_MANDATORY:
		return "mandatory"
	case dns.SVCB_ALPN:
		return "alpn"
	case dns.SVCB_PORT:
		return "port"
	case dns.SVCB_IPV4HINT:
		return "ipv4hint"
	case dns.SVCB_IPV6HINT:
		return "ipv6hint"
	case dns.SVCB_ECHCONFIG:
		return "ech"
	default:
		return "unknown"
	}
}

// --- the cases ---

// TestARewrittenCloudflareAnswerCarriesTheSelectedAddressAndNoProof is the whole
// point of the plugin on one query: a response every terminal address of which is
// inside a published range is answered with the one address the selector proved,
// and everything that made the old answer look trustworthy goes with it.
//
// The record is compared in packed form against a literal written here, so a
// different owner, a different class, a different TTL or a different address all
// fail here rather than passing as "some record came back".
func TestARewrittenCloudflareAnswerCarriesTheSelectedAddressAndNoProof(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)
	before := rw.counts()

	response := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s A over the router = %s, want an answer", cloudflareName, dns.RcodeToString[response.Rcode])
	}
	onlyRecord(t, response, &dns.A{
		Hdr: dns.RR_Header{Name: cloudflareName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL},
		A:   net.ParseIP(selectedAddress),
	})
	// The signature covered the addresses the resolver published and the denial of
	// existence described the RRset that was there; neither describes this answer, so
	// neither may travel with it, and the AD bit cannot survive a change like this.
	carriesNoProofs(t, response)
	if got := response.Question; len(got) != 1 || got[0].Name != cloudflareName || got[0].Qtype != dns.TypeA {
		t.Errorf("the answer echoes %v, want the one A question that was sent", got)
	}
	// The address the anycast resolver published is nowhere in the answer, so a
	// rewrite cannot be a copy that also kept the original.
	if bytes.Contains(mustPack(t, response), net.ParseIP(cloudflareAddress).To4()) {
		t.Errorf("the answer still carries the anycast address %s this router replaced:\n%s", cloudflareAddress, mustPack(t, response))
	}

	// One query reached the resolver and nothing reached the domestic branch: the
	// rewrite is a post-processing step, not a second lookup.
	if got := rw.foreign.Count("", cloudflareName); got != 1 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 1", got, cloudflareName)
	}
	if after := rw.counts().since(before); after.foreign != 1 || after.domestic != 0 {
		t.Errorf("resolvers were asked %+d since this case began, want one foreign query and nothing domestic", after)
	}
}

// mustPack is a message on the wire, for a case that wants to say a value is absent
// from the bytes rather than from the decoded structure.
func mustPack(t *testing.T, msg *dns.Msg) []byte {
	t.Helper()
	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack the answer: %v", err)
	}
	return wire
}

// TestTheIPv6AnswerOfARewrittenNameIsEmptied covers the other half of the same
// decision, and the order is the contract: the A answer is asked first, and only an
// A answer this router actually rewrote gives the IPv6 answer permission to be
// emptied. A name whose A answer was refused keeps every IPv6 address it arrived
// with, which is what the mixed case in the same fixture shows.
//
// The empty answer has to be an empty ANSWER and not a negative one: a record in the
// authority section is a caching claim about a TTL this router did not choose, and a
// strict name is recomputed for free.
func TestTheIPv6AnswerOfARewrittenNameIsEmptied(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)

	// The A answer first, and it has to be a rewrite: that is what earns the IPv6
	// answer the right to be emptied.
	first := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if got, want := publishedAddresses(t, first), []string{selectedAddress}; !equalStrings(got, want) {
		t.Fatalf("%s A = %v, want the selected address %v, so the IPv6 answer below is testing a rewritten name",
			cloudflareName, got, want)
	}

	response := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeAAAA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s AAAA over the router = %s, want NOERROR with an empty answer: the client is sent to the selected IPv4",
			cloudflareName, dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 0 {
		t.Errorf("%s AAAA carried %d record(s) (%v), want none: the answer the client would have had without this router is the one that gets suppressed",
			cloudflareName, len(response.Answer), recordKinds(response))
	}
	if len(response.Ns) != 0 {
		t.Errorf("%s AAAA carried %d authority record(s) (%v), want none: an SOA beside an empty answer is a negative caching claim about a TTL this router did not choose",
			cloudflareName, len(response.Ns), recordKinds(response))
	}
	carriesNoProofs(t, response)
	if got := response.Question; len(got) != 1 || got[0].Name != cloudflareName || got[0].Qtype != dns.TypeAAAA {
		t.Errorf("the answer echoes %v, want the one AAAA question that was sent", got)
	}
	// The IPv6 answer really was fetched, and really was emptied rather than
	// refused: a name that reached no upstream at all would also be empty, and this
	// case is about what happens to an answer that arrives.
	if got := rw.foreign.Count("", cloudflareName); got != 2 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 2: the A answer and the IPv6 answer that was emptied", got, cloudflareName)
	}
}

// TestAMixedCDNAnswerIsLeftExactlyAsPublished is the case the classifier exists for,
// and it is the control the whole file rests on: a response naming a Cloudflare
// address AND one outside every published range is not rewritten, not partly
// rewritten, and not stripped of what it arrived with.
//
// The DNSSEC half is the part that cannot pass by accident. A plugin that removed
// the signature and the AD bit from every response would satisfy every other case in
// this file; only this one can tell the difference, because here nothing was changed
// and so everything has to survive.
func TestAMixedCDNAnswerIsLeftExactlyAsPublished(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)

	response := rw.ask(t, testdns.ProtocolTCP, mixedName, dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s A over the router = %s, want an answer", mixedName, dns.RcodeToString[response.Rcode])
	}
	onlyRecord(t, response,
		&dns.A{Hdr: dns.RR_Header{Name: mixedName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL}, A: net.ParseIP(cloudflareAddress)},
		&dns.A{Hdr: dns.RR_Header{Name: mixedName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL}, A: net.ParseIP(offRangeAddress)},
		rrsigOver(mixedName, dns.TypeA),
	)
	keepsItsProofs(t, response)
	if got := rw.foreign.Count("", mixedName); got != 1 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 1", got, mixedName)
	}

	// And the name this router has no verdict about at all is left alone the same
	// way, which is the other half of "only validated CDN responses change".
	plain := rw.ask(t, testdns.ProtocolTCP, plainName, dns.TypeA)
	onlyRecord(t, plain,
		&dns.A{Hdr: dns.RR_Header{Name: plainName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL}, A: net.ParseIP(plainAddress)},
		rrsigOver(plainName, dns.TypeA),
	)
	keepsItsProofs(t, plain)
	if bytes.Contains(mustPack(t, plain), net.ParseIP(selectedAddress).To4()) {
		t.Errorf("the answer for %s carries the selected address %s, which the document authorises for nobody", plainName, selectedAddress)
	}
}

// TestAPerHostnameMappingRewritesThatNameAndNoOther covers the exact-hostname arm,
// and its shape is the one a real per-hostname mapping has: the queried name is an
// alias, and the addresses a client would connect to are the ones at the end of the
// chain. Requiring the two to be the same name would refuse every setup this feature
// is for.
//
// The sibling is the control. It shares a parent with the mapped name, so a suffix
// match, a parent match or a wildcard would catch it, and it is not Cloudflare-served
// either, so the global arm has nothing to say about it.
func TestAPerHostnameMappingRewritesThatNameAndNoOther(t *testing.T) {
	fixture := strictECHFixture()
	mapped := liveSelector(1, selectedAddress)
	// The key carries no trailing dot: a published profile names a host, not a
	// question, and a query arrives fully qualified.
	mapped.CloudFront = map[string]string{"front.example.test": cloudFrontAddress}

	rw := newRewriteHarness(t, fixture)
	rw.waitUntilAnswering(t)
	// The wait is on the mapped name's own answer, because that is the answer the
	// mapping changes: the global name keeps the global winner, so waiting on it would
	// wait for an event that is not supposed to happen.
	rw.selectWith(t, mapped, frontName, cloudFrontAddress)

	// The wait above asked for the global name, so ask the mapped one now: its chain
	// is preserved and the addresses at the END of it are replaced.
	response := rw.ask(t, testdns.ProtocolTCP, frontName, dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s A over the router = %s, want an answer", frontName, dns.RcodeToString[response.Rcode])
	}
	onlyRecord(t, response,
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: frontName, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: answerTTL},
			Target: frontTarget,
		},
		&dns.A{Hdr: dns.RR_Header{Name: frontTarget, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL}, A: net.ParseIP(cloudFrontAddress)},
	)
	carriesNoProofs(t, response)

	sibling := rw.ask(t, testdns.ProtocolTCP, siblingName, dns.TypeA)
	onlyRecord(t, sibling,
		&dns.A{Hdr: dns.RR_Header{Name: siblingName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: answerTTL}, A: net.ParseIP(siblingAddress)},
		rrsigOver(siblingName, dns.TypeA),
	)
	keepsItsProofs(t, sibling)
	if got := rw.foreign.Count("", siblingName); got != 1 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 1", got, siblingName)
	}
}

// TestAChinaAnswerIsByteIdenticalWithTheRewritePluginInstalled is the promise the
// domestic branch exists to keep, and it can only be stated in one process: the same
// router, the same configuration, the same run in which a foreign CDN answer IS
// rewritten. The rewrite happening first is what makes the comparison mean something --
// it rules out a router whose rewriter is simply inert.
func TestAChinaAnswerIsByteIdenticalWithTheRewritePluginInstalled(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)
	if !inCommittedChinaList(t, rw.cnList, chinaName) {
		t.Fatalf("the committed China list does not match %s, so this case would be asking the foreign resolver", chinaName)
	}

	// The rewrite is live in this very process.
	rewritten := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if got, want := publishedAddresses(t, rewritten), []string{selectedAddress}; !equalStrings(got, want) {
		t.Fatalf("%s A = %v, want the selected address %v: the rewriter has to be running for this case to mean anything", cloudflareName, got, want)
	}

	before := rw.counts()
	domestic := rw.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)
	if domestic.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s A over the router = %s, want an answer from the DHCP resolver", chinaName, dns.RcodeToString[domestic.Rcode])
	}
	// Byte for byte, against the record the domestic resolver published. A published
	// state names a bare address, so the record's owner is the queried name, its
	// address is the resolver's first numbered answer and its TTL is the resolver's.
	onlyRecord(t, domestic, &dns.A{
		Hdr: dns.RR_Header{Name: chinaName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("198.51.100.1"),
	})
	if got := rw.foreign.Count("", chinaName); got != 0 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 0: a China name must never be forwarded abroad", got, chinaName)
	}
	if after := rw.counts().since(before); after.domestic != 1 || after.foreign != 0 {
		t.Errorf("resolvers were asked %+d since this case asked about %s, want one domestic query and nothing foreign", after, chinaName)
	}
	// And a second China name, which is a real exchange rather than the domestic
	// plugin's own generation cache: a plugin that rewrote a domestic answer could
	// still leave something behind for the next reader, and only a fresh upstream
	// answer would show it.
	if !inCommittedChinaList(t, rw.cnList, secondChinaName) {
		t.Fatalf("the committed China list does not match %s, so this case would be asking the foreign resolver", secondChinaName)
	}
	again := rw.ask(t, testdns.ProtocolTCP, secondChinaName, dns.TypeA)
	onlyRecord(t, again, &dns.A{
		Hdr: dns.RR_Header{Name: secondChinaName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("198.51.100.2"),
	})
	if got := rw.foreign.Count("", secondChinaName); got != 0 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 0", got, secondChinaName)
	}
	if after := rw.counts().since(before); after.domestic != 2 || after.foreign != 0 {
		t.Errorf("resolvers were asked %+d after two domestic queries, want two domestic queries and nothing foreign", after)
	}
}

// TestARewriteAcrossASelectorGenerationLeavesTheCachedObjectAlone is the reason the
// plugin is in front of the cache rather than behind it, and it is a wire property
// rather than a document property.
//
// Four generations, and each one is a different thing that could go wrong:
//
//	generation 1: the answer is the winner, and the resolver is asked once.
//	generation 2: a different winner, on a new generation, and the answer CHANGES.
//	              This is the load-bearing step: the object the cache still holds is
//	              the upstream's answer, so the new generation is applied to it. A
//	              cache holding a rewritten message would keep answering the old
//	              address for as long as the entry lived, and the resolver's own
//	              count -- still one -- would say nothing was wrong.
//	disabled:      with the selection withdrawn, the answer is the address the
//	              resolver published. THIS is the proof that nothing was corrupted:
//	              the cached object is still the upstream's message, and a cache
//	              holding a rewrite would answer with a winner that no longer exists.
//	generation 4:  selection returns, and the address comes back, still from the one
//	              cached object -- the resolver is still asked exactly once in total.
func TestARewriteAcrossASelectorGenerationLeavesTheCachedObjectAlone(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)

	first := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if got, want := publishedAddresses(t, first), []string{selectedAddress}; !equalStrings(got, want) {
		t.Fatalf("generation 1: %s A = %v, want the selected address %v", cloudflareName, got, want)
	}
	if got := rw.foreign.Count("", cloudflareName); got != 1 {
		t.Fatalf("the foreign resolver was asked %d times for %s, want 1", got, cloudflareName)
	}

	// A new generation with a different winner. The successor is a public address
	// OUTSIDE the published range, so an answer carrying it cannot be mistaken for
	// anything the resolver published.
	rw.selectWith(t, liveSelector(2, successorAddress), cloudflareName, successorAddress)
	second := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if got, want := publishedAddresses(t, second), []string{successorAddress}; !equalStrings(got, want) {
		t.Fatalf("generation 2: %s A = %v, want the new winner %v: the cache holds the upstream's answer, not a rewrite of it", cloudflareName, got, want)
	}

	// And a third query, still on the new generation, is a cache hit and still right.
	third := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if got, want := publishedAddresses(t, third), []string{successorAddress}; !equalStrings(got, want) {
		t.Errorf("generation 2, second query: %s A = %v, want the new winner %v", cloudflareName, got, want)
	}
	if got := rw.foreign.Count("", cloudflareName); got != 1 {
		t.Errorf("the foreign resolver was asked %d times for %s across three queries, want 1: the later two came from the cache", got, cloudflareName)
	}

	// The selection is withdrawn, so the answer is whatever the cache still holds.
	// This is the step that can fail if the rewrite was ever stored rather than
	// applied to a copy.
	rw.selectWith(t, disabledSelectorAt(3), cloudflareName, cloudflareAddress)
	undone := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if got, want := publishedAddresses(t, undone), []string{cloudflareAddress}; !equalStrings(got, want) {
		t.Fatalf("with the selection withdrawn: %s A = %v, want the address the resolver published %v: the cached object is the upstream's message and nothing was written over it",
			cloudflareName, got, want)
	}

	// And it comes back, from that same object, with the resolver still asked once.
	rw.selectWith(t, liveSelector(4, selectedAddress), cloudflareName, selectedAddress)
	restored := rw.ask(t, testdns.ProtocolTCP, cloudflareName, dns.TypeA)
	if got, want := publishedAddresses(t, restored), []string{selectedAddress}; !equalStrings(got, want) {
		t.Errorf("generation 4: %s A = %v, want the selected address %v", cloudflareName, got, want)
	}
	if got := rw.foreign.Count("", cloudflareName); got != 1 {
		t.Errorf("the foreign resolver was asked %d times for %s across the whole case, want 1: nothing in this case may re-fetch", got, cloudflareName)
	}
}

// TestAStrictForcedNameIsRefusedWithoutReachingTheCacheOrTheUpstream is the case
// strict mode exists for, and the whole of it is that the answer costs nothing.
//
// Both names are asked for BEFORE they are forced, so the cache holds a real,
// unexpired answer for both of them and for both types: the Cloudflare one holds a
// rewritten address, the mixed one holds the resolver's two addresses and its IPv6
// answer. A strict query that came back with either of those would be a client
// connecting in the clear.
//
// The mixed name is what makes the IPv6 half attributable. Its A answer was refused
// by the classifier, so no IPv6 suppression is ever entered for it, so the only rule
// in this router that can produce an empty answer for it is the strict short circuit.
//
// Every count is asserted: per name and type on the resolver, the resolver's total,
// and the domestic resolver's total. The total is the strongest of them, because it
// also covers an ECH fetch -- which goes to the same listener and would move it.
func TestAStrictForcedNameIsRefusedWithoutReachingTheCacheOrTheUpstream(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)

	// Priming, with both names unforced. The answers are asserted so the case cannot
	// pass by caching nothing: an empty cache would satisfy the strict assertions
	// below without proving anything.
	// The A query for the Cloudflare name is primed too, and its cache entry is the
	// SELECTED address rather than the resolver's: a rewrite is applied to a copy, so
	// what the cache holds is the upstream's answer, and what the client saw was not.
	// Its IPv6 half is not primed, because the A rewrite above already earns the IPv6
	// answer the right to be emptied, so its cached answer would be an empty one and
	// could not tell a strict refusal from a suppression. The mixed name is the name
	// that can.
	primed := []struct {
		name  string
		qtype uint16
		want  []string
	}{
		{forcedName, dns.TypeA, []string{selectedAddress}},
		{forcedMixedName, dns.TypeA, []string{cloudflareAddress, offRangeAddress}},
		{forcedMixedName, dns.TypeAAAA, []string{cloudflareIPv6}},
	}
	for _, step := range primed {
		response := rw.ask(t, testdns.ProtocolTCP, step.name, step.qtype)
		if got := publishedAddresses(t, response); !equalStrings(got, step.want) {
			t.Fatalf("%s %s before forcing = %v, want %v: the case is about a cache that holds a real answer",
				step.name, dns.TypeToString[step.qtype], got, step.want)
		}
	}

	rw.forceECH(t, []string{"ech.example.test", "forced-mixed.example.test"}, func() bool {
		return rw.strictForced(t, "ech.example.test", "forced-mixed.example.test")
	})
	before := rw.counts()
	// The wait above asks each name once per attempt, so the count this case compares
	// is taken here: from here on, one more query for a name and type is one lookup
	// this router should not have made.
	primedCounts := map[string]int{}
	for _, step := range primed {
		primedCounts[step.name+"/"+dns.TypeToString[step.qtype]] = countType(rw, step.name, step.qtype)
	}

	for _, step := range primed {
		response := rw.ask(t, testdns.ProtocolTCP, step.name, step.qtype)
		if response.Rcode != dns.RcodeSuccess {
			t.Errorf("%s %s while forced = %s, want NOERROR with an empty answer",
				step.name, dns.TypeToString[step.qtype], dns.RcodeToString[response.Rcode])
		}
		if len(response.Answer) != 0 {
			t.Errorf("%s %s while forced carried %d record(s) (%v), want none: a client that resolved the name could connect in the clear",
				step.name, dns.TypeToString[step.qtype], len(response.Answer), recordKinds(response))
		}
		if len(response.Ns) != 0 {
			t.Errorf("%s %s while forced carried %d authority record(s), want none: an empty answer claims no negative caching TTL",
				step.name, dns.TypeToString[step.qtype], len(response.Ns))
		}
		if got := response.Question; len(got) != 1 || got[0].Name != step.name || got[0].Qtype != step.qtype {
			t.Errorf("the answer echoes %v, want the one %s question that was sent", got, dns.TypeToString[step.qtype])
		}
	}

	// Not one query left the router. The per-name counts say the cache was not asked
	// and the upstream was not asked, the grand total says nothing at all was fetched
	// -- including the ECH key, which is fetched over the same listener -- and the
	// domestic count says the answer did not come from the other branch either.
	for _, step := range primed {
		key := step.name + "/" + dns.TypeToString[step.qtype]
		if got, was := countType(rw, step.name, step.qtype), primedCounts[key]; got != was {
			t.Errorf("the foreign resolver was asked %d times for %s %s, want %d: a strict query must cost no lookup, and the cache held a real answer for it",
				got, step.name, dns.TypeToString[step.qtype], was)
		}
	}
	if after := rw.counts().since(before); after.foreign != 0 {
		t.Errorf("the foreign resolver was asked %d times while a strict name was queried, want 0: the cache and the upstream were both supposed to go untouched", after.foreign)
	}
	if after := rw.counts().since(before); after.domestic != 0 {
		t.Errorf("the domestic resolver was asked %d times while a strict name was queried, want 0", after.domestic)
	}
}

// countType is how many queries a name was asked for under one type, which is what
// separates "the A cache was used" from "the AAAA one was": the two are separate
// cache entries and separate upstream questions, and a case that counted them
// together could not tell which of the two was reached.
func countType(rw *rewriteHarness, name string, qtype uint16) int {
	count := 0
	for _, query := range rw.foreign.Queries() {
		if query.QName == name && query.QType == qtype {
			count++
		}
	}
	return count
}

// TestAForcedHTTPSQueryCarriesThePublishedKeyAndTheProvedAddress is the ECH half,
// end to end: the key is fetched from the source over the transport that cannot lose
// a query, and the record the client receives carries those exact bytes, a mandatory
// list naming the key, the proved address as its only hint, and no address of the
// name itself anywhere in the message.
//
// The record is also compared against a literal in full, so the parameters this case
// does not name by hand -- a port, a protocol set, a TTL -- are pinned too.
func TestAForcedHTTPSQueryCarriesThePublishedKeyAndTheProvedAddress(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)
	rw.forceECH(t, []string{"ech.example.test"}, func() bool { return rw.strictForced(t, "ech.example.test") })
	// The wait above asks the forced name on every attempt, so its count is taken
	// here rather than before it: the claim is about the client's own query.
	forcedBefore := rw.foreign.Count("", forcedName)
	before := rw.counts()

	response := rw.ask(t, testdns.ProtocolTCP, forcedName, dns.TypeHTTPS)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s HTTPS while forced = %s, want an answer: the key is published and the address is proved",
			forcedName, dns.RcodeToString[response.Rcode])
	}
	raw, err := base64.StdEncoding.DecodeString(echFixtureBase64)
	if err != nil {
		t.Fatalf("decode the ECH fixture: %v", err)
	}
	onlyRecord(t, response, &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: forcedName, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: answerTTL},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ECHCONFIG}},
			&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}},
			&dns.SVCBPort{Port: 443},
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(selectedAddress)}},
			&dns.SVCBECHConfig{ECH: raw},
		},
	}})
	carriesNoProofs(t, response)

	// The three properties a client acts on, named one at a time so a failure says
	// which of them is wrong.
	record := httpRecord(t, response)
	if got := base64.StdEncoding.EncodeToString(parameter(t, record, dns.SVCB_ECHCONFIG).(*dns.SVCBECHConfig).ECH); got != echFixtureBase64 {
		t.Errorf("the ech parameter is %s, want the %d bytes the source published", got, len(echFixtureBase64))
	}
	if got, want := parameter(t, record, dns.SVCB_MANDATORY).(*dns.SVCBMandatory).Code, []dns.SVCBKey{dns.SVCB_ECHCONFIG}; !equalKeys(got, want) {
		t.Errorf("the mandatory list is %v, want exactly %v: a record naming a key it does not carry, or naming one twice, is one a client may reject",
			got, want)
	}
	hints := parameter(t, record, dns.SVCB_IPV4HINT).(*dns.SVCBIPv4Hint).Hint
	if len(hints) != 1 || hints[0].String() != selectedAddress {
		t.Errorf("the ipv4 hint is %v, want the one proved address %s: a hint of the upstream's would send the client to an address nothing proved", hints, selectedAddress)
	}
	if hasParameter(record, dns.SVCB_IPV6HINT) {
		t.Error("the record carries an ipv6 hint, and this release installs no IPv6 address")
	}
	// RFC 9460 Section 7.3: a client ignores the hints when it already holds an
	// address for the name the record points at, so an address for the queried name
	// anywhere in the message beats the proved one.
	if bytes.Contains(mustPack(t, response), net.ParseIP(upstreamHint).To4()) {
		t.Errorf("the answer still carries %s, the address the upstream published: it would beat the proved hint\n%s", upstreamHint, mustPack(t, response))
	}
	if got, want := parameterNames(record), []string{"0:mandatory", "1:alpn", "3:port", "4:ipv4hint", "5:ech"}; !equalStrings(got, want) {
		t.Errorf("the record's parameters are %v, want %v in the order the wire carries them", got, want)
	}

	// Two exchanges, and both of them over TCP: the client's own question, and the
	// key fetch, which is a client of the plugin's own pointed at the same listener
	// rather than a re-entry into the sequence this plugin sits in.
	after := rw.counts().since(before)
	if after.foreign != 2 {
		t.Errorf("the foreign resolver was asked %d times, want 2: the forced name's own question and one fetch of %s", after.foreign, dns.Fqdn(echSourceName))
	}
	source := dns.Fqdn(echSourceName)
	if got := rw.foreign.Count(testdns.ProtocolTCP, source); got != 1 {
		t.Errorf("the ECH key was fetched %d times over tcp, want 1", got)
	}
	if got := rw.foreign.Count(testdns.ProtocolUDP, source); got != 0 {
		t.Errorf("the ECH key was fetched %d times over udp, want 0: that transport re-sends and drops answers", got)
	}
	if got, was := rw.foreign.Count("", forcedName), forcedBefore; got != was+1 {
		t.Errorf("the forced name was asked for %d times, want %d: one question of the client's own, and the key fetch is a query about the source rather than about the name", got, was+1)
	}

	// The router says what it did, so an operator can see the key is in service.
	if !rw.router.reported(t, fetchedECHKeyLog) {
		t.Errorf("the router did not report %q, so the fetch that produced this record is invisible\n%s", fetchedECHKeyLog, rw.router.diagnostics())
	}
	// And it published the metadata document at the path the rendered configuration
	// named, which is the only proof that the argument reached the plugin.
	assertECHStatePublished(t, rw.echStatePath)
}

// TestAForcedHTTPSQueryDoesNotRefetchTheKeyEveryTime covers the cost side of the
// same feature. The key is fetched once and held; a second query for the same name
// is answered from the same held key with no further query to the source, because a
// fetch per client query would be a query per client query on the listener this
// router forwards everything else through.
func TestAForcedHTTPSQueryDoesNotRefetchTheKeyEveryTime(t *testing.T) {
	rw := newRewriteHarness(t, strictECHFixture())
	rw.waitUntilAnswering(t)
	rw.forceECH(t, []string{"ech.example.test"}, func() bool { return rw.strictForced(t, "ech.example.test") })

	source := dns.Fqdn(echSourceName)
	if first := rw.ask(t, testdns.ProtocolTCP, forcedName, dns.TypeHTTPS); len(first.Answer) != 1 {
		t.Fatalf("the first forced HTTPS answer carried %d records, want 1", len(first.Answer))
	}
	afterFirst := rw.foreign.Count("", source)
	if afterFirst != 1 {
		t.Fatalf("the ECH key was fetched %d times for the first query, want 1", afterFirst)
	}
	for round := range 2 {
		response := rw.ask(t, testdns.ProtocolTCP, forcedName, dns.TypeHTTPS)
		if len(response.Answer) != 1 {
			t.Fatalf("round %d: the forced HTTPS answer carried %d records, want 1", round+2, len(response.Answer))
		}
		record := httpRecord(t, response)
		if got := base64.StdEncoding.EncodeToString(parameter(t, record, dns.SVCB_ECHCONFIG).(*dns.SVCBECHConfig).ECH); got != echFixtureBase64 {
			t.Errorf("round %d: the ech parameter is not the published key", round+2)
		}
	}
	if got := rw.foreign.Count("", source); got != afterFirst {
		t.Errorf("the ECH key was fetched %d times across three queries, want %d: a held key is not refetched per query", got, afterFirst)
	}
}

// TestAStrictForcedHTTPSQueryFailsClosedWhenTheSourcePublishesNoKey is what strict
// means when the key cannot be had. The client gets DNS failure -- not the upstream's
// record, not an empty record, and above all not an A answer it could connect in the
// clear with -- and the router says why, twice over: the plugin names the reason and
// mosdns reports the entry that failed.
func TestAStrictForcedHTTPSQueryFailsClosedWhenTheSourcePublishesNoKey(t *testing.T) {
	fixture := strictECHFixture()
	// A source that answers with a service mode and no key: the key was withdrawn,
	// which is a different fault from an unreachable source and one the plugin
	// refuses rather than forwards.
	fixture.publishECHKey = false
	rw := newRewriteHarness(t, fixture)
	rw.waitUntilAnswering(t)
	rw.forceECH(t, []string{"ech.example.test"}, func() bool { return rw.strictForced(t, "ech.example.test") })
	// The wait above asks the forced name on every attempt, so its count is taken
	// here rather than before it: the claim is about the client's own query.
	forcedBefore := rw.foreign.Count("", forcedName)
	before := rw.counts()

	response := rw.ask(t, testdns.ProtocolTCP, forcedName, dns.TypeHTTPS)
	if response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("%s HTTPS with no usable key = %s, want SERVFAIL: a strict name is given nothing rather than something in the clear",
			forcedName, dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 0 {
		t.Errorf("the answer carried %d record(s) (%v), want none: the upstream's own record is the one thing strict mode must not forward",
			len(response.Answer), recordKinds(response))
	}
	// The client's own question was asked downstream and the source was asked once.
	// A strict HTTPS query is not short-circuited: the service parameters are what
	// the synthesis inherits, so the question has to be asked.
	if got, was := rw.foreign.Count("", forcedName), forcedBefore; got != was+1 {
		t.Errorf("the forced name was asked for %d times, want %d: one question of the client's own", got, was+1)
	}
	if got := rw.foreign.Count("", dns.Fqdn(echSourceName)); got != 1 {
		t.Errorf("the ECH source was asked %d times, want 1", got)
	}
	if after := rw.counts().since(before); after.domestic != 0 {
		t.Errorf("the domestic resolver was asked %d times, want 0", after.domestic)
	}

	for _, fragment := range []string{noECHKeyLog, entryFailedLog, forcedName} {
		if !rw.router.reported(t, fragment) {
			t.Errorf("the router did not report %q, so the refusal is silent\n%s", fragment, rw.router.diagnostics())
		}
	}
}

// TestAFallbackForcedDomainKeepsTheUpstreamsAnswerAndItsAddress is the other policy,
// and the two halves of it are opposites on purpose. The address is still rewritten,
// because the selection is proved and has nothing to do with the key; the HTTPS
// record is the upstream's own, unchanged, because removing a working service
// description would be a downgrade this router has no standing to impose.
//
// The DNSSEC half is what separates this from a rewrite: nothing was changed here, so
// the validation claim and the signature the upstream published both survive.
func TestAFallbackForcedDomainKeepsTheUpstreamsAnswerAndItsAddress(t *testing.T) {
	fixture := strictECHFixture()
	fixture.publishECHKey = false
	fixture.policy = func(policy *config.Policy) { policy.ECH.FailurePolicy = "fallback" }
	rw := newRewriteHarness(t, fixture)
	rw.waitUntilAnswering(t)
	// Under the fallback policy no answer for a forced name differs from an answer for
	// an unforced one -- that is what the policy means -- so the only thing that says
	// the list is in force is the plugin's own report, which is also one of the things
	// this case asserts.
	rw.forceECH(t, []string{"ech.example.test"}, func() bool {
		rw.ask(t, testdns.ProtocolTCP, forcedName, dns.TypeHTTPS)
		return strings.Contains(rw.router.output.String(), keptOriginalLog)
	})

	// The address, rewritten as usual.
	address := rw.ask(t, testdns.ProtocolTCP, forcedName, dns.TypeA)
	if got, want := publishedAddresses(t, address), []string{selectedAddress}; !equalStrings(got, want) {
		t.Fatalf("%s A under the fallback policy = %v, want the selected address %v: the address and the key are fetched independently",
			forcedName, got, want)
	}

	// The record, exactly as the resolver published it: no key, no mandatory list,
	// no proved hint, and the upstream's own hint in place of it.
	response := rw.ask(t, testdns.ProtocolTCP, forcedName, dns.TypeHTTPS)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s HTTPS under the fallback policy = %s, want the upstream's own record", forcedName, dns.RcodeToString[response.Rcode])
	}
	onlyRecord(t, response, serviceBinding(forcedName), rrsigOver(forcedName, dns.TypeHTTPS))
	keepsItsProofs(t, response)
	record := httpRecord(t, response)
	for _, key := range []dns.SVCBKey{dns.SVCB_ECHCONFIG, dns.SVCB_MANDATORY} {
		if hasParameter(record, key) {
			t.Errorf("the fallback record carries key %d, want the upstream's own record untouched", key)
		}
	}
	if got := parameter(t, record, dns.SVCB_IPV4HINT).(*dns.SVCBIPv4Hint).Hint; len(got) != 1 || got[0].String() != upstreamHint {
		t.Errorf("the fallback record's ipv4 hint is %v, want the upstream's own %s", got, upstreamHint)
	}

	// The degradation is reported, because an answer that could not be upgraded is
	// something an operator has to be able to see.
	if !rw.router.reported(t, keptOriginalLog) {
		t.Errorf("the router did not report %q, so a fallback answer looks like a successful one\n%s", keptOriginalLog, rw.router.diagnostics())
	}
}

// assertECHStatePublished reads the metadata document the plugin wrote and holds it
// to the state package's own rules, so a path that reached the plugin is proved by
// its output rather than by the absence of a complaint.
func assertECHStatePublished(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(selectorReloadDeadline)
	for {
		var published state.ECHState
		err := state.ReadJSON(path, &published)
		if err == nil {
			if published.Status != "fresh" {
				t.Errorf("the published ECH state says %q, want %q for a key that was just fetched", published.Status, "fresh")
			}
			if published.Source != echSourceName {
				t.Errorf("the published ECH state names the source %q, want %q", published.Source, echSourceName)
			}
			if published.PublicName != "cloudflare-ech.com" {
				t.Errorf("the published ECH state names the public name %q, want the key's own %q", published.PublicName, "cloudflare-ech.com")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the plugin published no ECH state document at %s after %s: %v", path, selectorReloadDeadline, err)
		}
		time.Sleep(readinessPollWait)
	}
}

// equalKeys compares two SvcParamKey lists, so a failure can show both.
func equalKeys(got, want []dns.SVCBKey) bool {
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

// guardTheNamesInThisFileAreForeign is a fixture check, not a case: the names are
// only meaningful if the committed China list does not match them, and the harness
// checks that per case. This states the dependency in one place so a future reader
// knows why the harness bothers.
func TestTheNamesTheseFixturesUseTakeTheForeignBranch(t *testing.T) {
	directory := t.TempDir()
	list := copyChinaList(t, directory)
	for _, name := range []string{
		cloudflareName, mixedName, plainName, frontName, frontTarget, siblingName,
		forcedName, forcedMixedName, readinessName,
	} {
		if inCommittedChinaList(t, list, name) {
			t.Errorf("the committed China list matches %s, so every case in this file would be answered by the domestic resolver", name)
		}
	}
}
