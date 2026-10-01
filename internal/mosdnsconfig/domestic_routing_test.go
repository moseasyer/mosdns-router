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
	"net"
	"os"
	"strconv"
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

func mustPort(t *testing.T, port string) int {
	t.Helper()
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse the port %q: %v", port, err)
	}
	return value
}
