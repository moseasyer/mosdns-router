package mosdnsconfig

// The domestic branch, driven through the router's OWN plugin and the SHIPPED
// sequences, with the only thing faked being where the DHCP resolvers are.
//
// This file exists because of a measured gap. Until now the only end-to-end
// routing tests in this package swapped `dhcp_forward` for a `forward`, and the
// comment on `TestASuccessfulDomesticAnswerIsNeverReplacedByTheForeignCache` gave
// the reason: "The router's own plugin cannot be driven from a test, because the
// production state decoder refuses the loopback address a mock listens on." So the
// plugin that decides where a domestic query goes — the whole of the domestic
// branch — was never exercised through the document the router ships, and a cell
// in a container had to stand in for it. **That cell refused a China-set name
// with `REFUSED` while the published state named a usable upstream, and the two
// halves of that could not be told apart from a test.** They can now: the
// decoder's rule is about *loopback*, not about *local*, so a mock on the
// machine's own non-loopback address is a legal upstream and needs no injected
// reader.
//
// What is NOT faked: the rendered document is the one this project ships, the
// `dhcp_forward` plugin is this project's, the China list is the committed one,
// the state file is written by `state.NewDHCPState` exactly as the bridge writes
// it, and the query goes over a real socket to a real mosdns.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mosdns-router/internal/state"
	"mosdns-router/internal/testdns"
)

// routableAddress returns this machine's own non-loopback IPv4 address.
//
// **Non-loopback on purpose, and the reason is the product's.** The published
// state is decoded by `state.ReadJSON`, which refuses an upstream that is local —
// loopback, unspecified, multicast — because a resolver publishing itself as its
// own upstream is a loop. That rule is correct and it is not negotiable for a
// test: a case that injected a reader past it would be asserting against a
// document no installed router could read. The machine's own routable address is
// not local, so the document a test writes is one a real router accepts.
func routableAddress(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("cannot list interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			parsed, _, err := net.ParseCIDR(address.String())
			if err != nil || parsed.To4() == nil || !parsed.IsGlobalUnicast() {
				continue
			}
			return parsed.String()
		}
	}
	t.Skip("this machine has no non-loopback IPv4 address, so a mock cannot be given an upstream the production state decoder accepts")
	return ""
}

// freeRoutablePort returns a UDP and TCP port that are both free on `address`
// right now. The servers bind it inside this process, so it has to be given up
// first — the same dance `freeLoopbackPort` does, on the caller's address.
func freeRoutablePort(t *testing.T, address string) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Skipf("cannot reserve a udp port on %s: %v", address, err)
	}
	host, port, err := net.SplitHostPort(packetConn.LocalAddr().String())
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("split %q: %v", packetConn.LocalAddr(), err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		_ = packetConn.Close()
		t.Skipf("cannot reserve a matching tcp port on %s: %v", address, err)
	}
	_ = listener.Close()
	_ = packetConn.Close()
	return port
}

// publishedStatePaths renders the shipped document for a state file the CALLER
// wrote, so a test can publish a real upstream rather than the empty one
// `temporaryPaths` publishes. Everything else is `temporaryPaths`, because the
// point is that only the state file differs.
func publishedStatePaths(t *testing.T, foreignListener string, published []byte) (Paths, string) {
	t.Helper()
	paths, _ := temporaryPaths(t, foreignListener)
	if err := os.WriteFile(paths.DHCPState, published, 0o600); err != nil {
		t.Fatalf("write the state document: %v", err)
	}
	return paths, paths.Listen
}

// stateDocument encodes the state the bridge publishes, through the same
// constructor the bridge uses — `lastGood` true, because a state that named an
// upstream without vouching for it is refused by the plugin on purpose.
func stateDocument(t *testing.T, generation uint64, upstream string, observedAt time.Time) []byte {
	t.Helper()
	var upstreams []string
	if upstream != "" {
		upstreams = []string{upstream}
	}
	document, err := json.Marshal(
		state.NewDHCPState(generation, "eth0", "2f9cc17e-8a25-4043-ac0c-9d3278e06c34",
			upstreams, observedAt, "nm-dhcp4", upstream != ""),
	)
	if err != nil {
		t.Fatalf("encode the state document: %v", err)
	}
	return document
}

// TestAChinaSetNameReachesTheUpstreamTheBridgePublished is the case this whole
// task turned on: a China-set name, the real plugin, a state the production
// decoder accepts, and an upstream that answers.
//
// It fails if the domestic branch does not forward, whatever the reason — and the
// refusal it produces says which. Before this case the only evidence available
// was a container answering `REFUSED`, which does not distinguish a plugin that
// held no generation from a chain that never reached the plugin.
func TestAChinaSetNameReachesTheUpstreamTheBridgePublished(t *testing.T) {
	address := routableAddress(t)
	port := freeRoutablePort(t, address)

	domestic, err := testdns.StartOn(net.JoinHostPort(address, port), func(_ context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(198, 51, 100, 7).To4(),
		})
		return response
	})
	if err != nil {
		t.Fatalf("start the domestic upstream: %v", err)
	}
	t.Cleanup(func() { _ = domestic.Close() })

	foreign := startForeignMock(t)
	paths, listenAddress := temporaryPaths(t, "tcp://"+foreign.Address())
	paths.DHCPUpstreamPort = mustPort(t, port)
	if err := os.WriteFile(paths.DHCPState, stateDocument(t, 1, address, time.Unix(1750000000, 0).UTC()), 0o600); err != nil {
		t.Fatalf("write the state document: %v", err)
	}

	instance := loadMosdns(t, decodeMosdnsConfig(t, mustRender(t, paths)))

	response := ask(t, listenAddress, chinaDomain)
	if got := addressesIn(t, response); !equalStrings(got, []string{"198.51.100.7"}) {
		t.Fatalf("a China-set name came back as %v (rcode %s), want the domestic upstream's own "+
			"address 198.51.100.7: the published state names %s and the plugin should have dialled "+
			"it on port %d", got, dns.RcodeToString[response.Rcode], address, paths.DHCPUpstreamPort)
	}
	if got := domestic.Count("", chinaDomain); got != 1 {
		t.Errorf("the domestic upstream received %d queries for %s, want 1", got, chinaDomain)
	}
	if got := foreign.Count("", ""); got != 0 {
		t.Errorf("the foreign resolver received %d queries in total, want none", got)
	}
	_ = instance
}

// publishGeneration writes one published state document the way the bridge
// writes it: a temporary file in the state file's own directory, then a rename
// over the target.
//
// **The rename is the load-bearing part and not an incidental detail of the
// fixture.** `publish_if_changed` commits through `os.replace`
// (`bridge/mosdns_dhcp_bridge/publish.py:458`), so a new generation is a *new
// file* rather than a rewrite of the old one, which is why the plugin's own
// reload criterion can include file identity and still see every generation. A
// case that published in place would be testing a writer this project does not
// ship, and would pass for a reason that says nothing about the cell.
func publishGeneration(t *testing.T, path string, generation uint64, upstream string, observedAt time.Time) {
	t.Helper()
	temporary := path + ".next"
	if err := os.WriteFile(temporary, stateDocument(t, generation, upstream, observedAt), 0o600); err != nil {
		t.Fatalf("write the temporary state document: %v", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatalf("rename the temporary state document over %s: %v", path, err)
	}
}

// stateFileFacts describes a published state file the way the plugin's reload
// criterion looks at it, so a failure can name what did and did not change. It
// is a reporting helper, not the rule: the rule is `fileSignature.sameAs`, and it
// is held by `TestStateFileSignatureTracksFileIdentity` in the plugin's own
// package, where the unexported type is reachable.
func stateFileFacts(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the state file %s: %v", path, err)
	}
	return fmt.Sprintf("%d bytes, mtime %s, dev %d ino %d",
		info.Size(), info.ModTime().UTC().Format(time.RFC3339Nano), info.Sys().(*syscall.Stat_t).Dev, info.Sys().(*syscall.Stat_t).Ino)
}

// TestASecondGenerationIsAdoptedOverOneThatNamedNoUpstream is the sequence a
// live cell runs and no test ran: a generation that names **no** upstream, and
// then a generation that names a real one, published over it while mosdns keeps
// running.
//
// **Why the first generation has no upstream.** That is what the install's own
// hand-over produces. `postinst` captures the current state through the same
// publisher the bridge uses, and the installer then points NetworkManager at the
// loopback — so a capture taken after the hand-over reads `127.0.0.1` as the
// effective DNS, the collector filters local addresses out, and what is
// published is a valid document that disables the branch. The bridge's own DHCP
// event then publishes the lease's real resolver as a later generation. So
// "disabled, then enabled, without a restart" is not a hypothetical ordering; it
// is the ordinary install ordering, and this is the only test that walks it
// through the real plugin and the shipped document.
//
// **What it decides.** Two candidate causes were on the record for a live cell
// that would not forward a China-set name: `reloadGeneration` keeping the
// current generation when `published.Generation <= current.generation`, and the
// `signature.sameAs(r.observed)` short-circuit skipping the read. Neither can
// survive this case, and the case says so by reaching a state the disabled
// generation cannot serve.
func TestASecondGenerationIsAdoptedOverOneThatNamedNoUpstream(t *testing.T) {
	address := routableAddress(t)
	port := freeRoutablePort(t, address)

	domestic, err := testdns.StartOn(net.JoinHostPort(address, port), func(_ context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(198, 51, 100, 7).To4(),
		})
		return response
	})
	if err != nil {
		t.Fatalf("start the domestic upstream: %v", err)
	}
	t.Cleanup(func() { _ = domestic.Close() })

	foreign := startForeignMock(t)
	observed := time.Unix(1750000000, 0).UTC()
	paths, listenAddress := publishedStatePaths(t, "tcp://"+foreign.Address(), stateDocument(t, 1, "", observed))
	paths.DHCPUpstreamPort = mustPort(t, port)
	instance := loadMosdns(t, decodeMosdnsConfig(t, mustRender(t, paths)))

	// The disabled generation must fail the branch closed. Two things are
	// asserted, and the second is the one a "REFUSED" reading mistakes: the name
	// is a China-set name, so anything the foreign resolver answered would mean
	// the domestic branch's failure leaked a query into the network the user is
	// leaving.
	disabled := ask(t, listenAddress, chinaDomain)
	if disabled.Rcode == dns.RcodeSuccess || len(disabled.Answer) > 0 {
		t.Fatalf("a China-set name came back as %v (rcode %s) from the generation that named no "+
			"upstream: an empty upstream list is the documented way to disable the branch, and it "+
			"must fail closed rather than answer", addressesIn(t, disabled), dns.RcodeToString[disabled.Rcode])
	}
	// errDisabled is returned as an error, and mosdns's entry handler answers an
	// entry error with SERVFAIL. So the code this case observes is a measurement
	// of which mechanism refused, and it is not REFUSED: `resp == nil` with no
	// error is the only path to REFUSED, and `exchange` cannot take it — every
	// branch of `runtime.race` returns either a message or an error.
	if disabled.Rcode != dns.RcodeServerFailure {
		t.Errorf("the disabled generation answered rcode %s, want SERVFAIL: dhcp_forward returns "+
			"errDisabled as an error, and an entry error is SERVFAIL. A different code names a "+
			"different mechanism, and this case exists to name it",
			dns.RcodeToString[disabled.Rcode])
	}
	if got := foreign.Count("", ""); got != 0 {
		t.Errorf("the foreign resolver received %d queries, want none: the domestic branch's "+
			"disabled state must not leak a China-set name into the network the user is leaving", got)
	}
	if got := domestic.Count("", chinaDomain); got != 0 {
		t.Errorf("the domestic upstream received %d queries for %s, want none: the generation named "+
			"no upstream, so nothing may be dialled", got, chinaDomain)
	}
	disabledFacts := stateFileFacts(t, paths.DHCPState)

	// Generation 2, published over generation 1 by the mechanism the bridge uses.
	publishGeneration(t, paths.DHCPState, 2, address, observed.Add(time.Minute))
	enabledFacts := stateFileFacts(t, paths.DHCPState)

	answered := ask(t, listenAddress, chinaDomain)
	if got := addressesIn(t, answered); !equalStrings(got, []string{"198.51.100.7"}) {
		t.Fatalf("after generation 2 was published a China-set name came back as %v (rcode %s), "+
			"want the domestic upstream's own address 198.51.100.7: generation 1 named no upstream and "+
			"generation 2 named %s on port %d, so the plugin must have adopted it. Generation 1 was %s; "+
			"generation 2 is %s",
			got, dns.RcodeToString[answered.Rcode], address, paths.DHCPUpstreamPort, disabledFacts, enabledFacts)
	}
	if got := domestic.Count("", chinaDomain); got != 1 {
		t.Errorf("the domestic upstream received %d queries for %s, want 1: only the second generation "+
			"can forward, so exactly one query can have been forwarded", got, chinaDomain)
	}
	if got := foreign.Count("", ""); got != 0 {
		t.Errorf("the foreign resolver received %d queries in total, want none", got)
	}
	_ = instance
}

// TestASameLengthSecondGenerationIsStillAdopted covers the exact shape the
// `signature.sameAs` candidate needed: a document that is **the same length** as
// the one it replaces, published over it by rename with the modification time
// forced to the value the file it replaces carries.
//
// Only the generation digit differs, so the size is identical, and
// `os.Chtimes` makes the modification time identical too. What is left to tell
// the two apart is file identity, which is why the rename is what the assertion
// rests on. It is asserted on the length and the time as controls: a fixture
// that failed to produce equal lengths would make this case pass without
// testing the thing it names, which is the defect this project has now paid for
// four times.
//
// **The evidence is a COUNT and not the answer, and that is the whole design of
// this case.** Two generations naming the same upstream produce the same address
// from the same mock, so an answer cannot tell generation 1 from generation 2 —
// and a case whose evidence cannot tell the two states apart is a green gate that
// walks through the defect it is named for, which is what this project has now
// paid for four times over. The count can: a replaced generation takes its cache
// with it, so a query answered by generation 2 is a query that was forwarded
// again, while a query answered by generation 1 is a cache hit and costs the
// upstream nothing. The middle query is what makes that difference attributable:
// it shows an unchanged file does not re-forward, so the count moving afterwards
// is the reload and not the passage of time.
func TestASameLengthSecondGenerationIsStillAdopted(t *testing.T) {
	address := routableAddress(t)
	port := freeRoutablePort(t, address)

	domestic, err := testdns.StartOn(net.JoinHostPort(address, port), func(_ context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(198, 51, 100, 8).To4(),
		})
		return response
	})
	if err != nil {
		t.Fatalf("start the domestic upstream: %v", err)
	}
	t.Cleanup(func() { _ = domestic.Close() })

	foreign := startForeignMock(t)
	observed := time.Unix(1750000000, 0).UTC()
	first := stateDocument(t, 1, address, observed)
	paths, listenAddress := publishedStatePaths(t, "tcp://"+foreign.Address(), first)
	paths.DHCPUpstreamPort = mustPort(t, port)
	loadMosdns(t, decodeMosdnsConfig(t, mustRender(t, paths)))

	if got := domestic.Count("", chinaDomain); got != 0 {
		t.Fatalf("the domestic upstream received %d queries before any was asked, want 0", got)
	}
	first1 := addressesIn(t, ask(t, listenAddress, chinaDomain))
	first2 := addressesIn(t, ask(t, listenAddress, chinaDomain))
	if !equalStrings(first1, []string{"198.51.100.8"}) || !equalStrings(first2, []string{"198.51.100.8"}) {
		t.Fatalf("the first generation answered %v then %v, want 198.51.100.8 from both", first1, first2)
	}
	if got := domestic.Count("", chinaDomain); got != 1 {
		t.Fatalf("the domestic upstream received %d queries for two identical questions, want 1: the "+
			"second must have been a cache hit, or the count below cannot tell a reload from a re-forward",
			got)
	}

	before, err := os.Stat(paths.DHCPState)
	if err != nil {
		t.Fatalf("stat the published state file: %v", err)
	}
	second := stateDocument(t, 2, address, observed.Add(time.Minute))
	if len(second) != len(first) {
		t.Fatalf("the two generations are %d and %d bytes, want them equal: this case is named for the "+
			"same-length rewrite, and a longer document would be adopted by the size alone", len(first), len(second))
	}
	temporary := paths.DHCPState + ".next"
	if err := os.WriteFile(temporary, second, 0o600); err != nil {
		t.Fatalf("write the temporary state document: %v", err)
	}
	if err := os.Chtimes(temporary, before.ModTime(), before.ModTime()); err != nil {
		t.Fatalf("set the replacement times: %v", err)
	}
	if err := os.Rename(temporary, paths.DHCPState); err != nil {
		t.Fatalf("rename the temporary state document: %v", err)
	}
	after, err := os.Stat(paths.DHCPState)
	if err != nil {
		t.Fatalf("stat the renamed state file: %v", err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the setup did not reproduce the shape it names: %d bytes and mtime %s became %d "+
			"bytes and mtime %s, want the same length and the same modification time",
			before.Size(), before.ModTime().UTC().Format(time.RFC3339Nano),
			after.Size(), after.ModTime().UTC().Format(time.RFC3339Nano))
	}
	if os.SameFile(before, after) {
		t.Fatal("the setup renamed nothing: the replacement kept the replaced file's identity, so this " +
			"case would pass without the rename it is about")
	}

	third := addressesIn(t, ask(t, listenAddress, chinaDomain))
	if !equalStrings(third, []string{"198.51.100.8"}) {
		t.Fatalf("after the same-length replacement a China-set name came back as %v, want 198.51.100.8", third)
	}
	if got := domestic.Count("", chinaDomain); got != 2 {
		t.Fatalf("the domestic upstream received %d queries for %s, want 2: one from generation 1 and one "+
			"from generation 2. The published document is byte-for-byte the length of the one it replaced and "+
			"carries its modification time, so only the rename distinguishes them, and a count that stayed at 1 "+
			"is generation 1's cache answering — the replacement was never read",
			got, chinaDomain)
	}
	if got := foreign.Count("", ""); got != 0 {
		t.Errorf("the foreign resolver received %d queries in total, want none", got)
	}
}

func mustPort(t *testing.T, port string) int {
	t.Helper()
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse the port %q: %v", port, err)
	}
	return value
}
