// Package integration drives the real mosdns-router binary over real sockets.
//
// Every other test in this project reads bytes: a rendered document, a committed
// file, a plugin's own return value. This package runs the binary those bytes are
// for, points it at two controlled resolvers, and follows the queries it sends.
// It is the only place the promises the project makes as a whole can be checked
// together: a name the China list matches reaches only the DHCP upstream, every
// other name reaches only the foreign resolver, the foreign one is entered over
// TCP, and neither branch answers for the other when its own upstream is gone or
// was never published.
//
// Nothing here touches the host. The router is a child process with a
// configuration in a temporary directory, the two resolvers are test servers
// this package starts, and no service, resolver, or /etc/resolv.conf is read or
// written. Port 53 is never bound: the router listens on an ephemeral loopback
// port, the foreign resolver on another, and the domestic one on an ephemeral
// port of a real local address.
package integration

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/domain_set"
	"github.com/miekg/dns"
	"mosdns-router/internal/config"
	"mosdns-router/internal/mosdnsconfig"
	"mosdns-router/internal/state"
	"mosdns-router/internal/testdns"
)

// chinaName and foreignName are the two names the routing cases turn on, one
// from each branch. They are fully qualified, because that is the form a name
// has when it arrives over the wire. The list-membership assertion in
// TestRoutingSplitSendsEachNameToOnlyItsOwnBranch runs the pinned MOSDNS matcher
// over the committed list, so a list that stopped matching one of them fails the
// case that is supposed to be proving the split rather than quietly
// reclassifying it.
const (
	chinaName = "baidu.com."
	// secondChinaName is a second name the committed list matches, used where a
	// case needs a domestic query that the plugin's own generation cache cannot
	// already hold. That cache is scoped to a generation and has a long TTL, so
	// asking the same name twice in one case would be answered from it rather
	// than from the published upstream.
	secondChinaName = "baidu.cn."
	foreignName     = "www.google.com."
)

// foreignAddress is the A record the foreign resolver answers with, from the
// documentation range 203.0.113.0/24. The domestic answers are
// 198.51.100.1, .2, .3 and so on, one per call, from a different range. An answer
// therefore always says which resolver produced it, and a domestic answer that
// came from an earlier call cannot be mistaken for a fresh one.
const foreignAddress = "203.0.113.10"

// readinessName is the name the readiness poll asks for. No case asserts on it,
// so the two queries the poll costs cannot be mistaken for a routing
// observation.
const readinessName = "readiness-probe.example."

// The published state document's own fields, other than the generation and the
// upstream address. The interface is the real device that owns the address the
// domestic resolver is bound to, and the source is the token the bridge
// publishes a NetworkManager DHCP4 DNS set under.
const (
	stateSource      = "nm-dhcp4"
	stateConnection  = "6d1f0f4c-2a7b-4c3d-9e5a-0b6c8d2e1f30"
	firstGeneration  = 1
	corruptDocument  = `{"schema_version": 1, "generation": 1, "interface": `
	noUpstreamReport = "dhcp_forward: no valid DHCP state is available"
	entryFailedLog   = "entry err"
	unusableStateLog = "the published state is unusable"
	noUpstreamLog    = "all upstream servers failed"
)

// The bounds and cadence of the child process lifecycle. The readiness deadline
// is generous because it covers the process start and the first page-in of a
// freshly built binary; the shutdown grace is shorter because a router that has
// not answered SIGTERM by then has to be told.
const (
	readinessTimeout  = 30 * time.Second
	readinessPollWait = 50 * time.Millisecond
	readinessDialWait = 500 * time.Millisecond
	reportDeadline    = 5 * time.Second
	shutdownGrace     = 10 * time.Second
	queryTimeout      = 10 * time.Second
)

// minimumUDPPayload is the size of a DNS message that fits in a datagram without
// EDNS0, and the point at which a real resolver truncates. The domestic mock
// reproduces that, because it is the only way the plugin's own TCP retry is
// reachable at all.
const minimumUDPPayload = 512

// committedCNList is the pinned list the router is configured with. It is copied
// into a case's own directory rather than read in place, so a case cannot change
// what the repository holds.
const committedCNList = "../../configs/cn-domains.txt"

// --- the binary under test ---

// routerBinary is the binary every case in this package starts. It is built once
// by TestMain, because `go test ./...` runs this package and must not depend on
// a `make build` that may never have run.
var routerBinary string

func TestMain(m *testing.M) {
	// testing.Short reads the parsed flags, and the flags are only parsed before
	// m.Run.
	flag.Parse()

	// The harness builds and starts a process per case, so it is not something a
	// quick unit run should pay for. The Makefile's unit-test entry point passes
	// -short and reaches this suite through `make test-integration`.
	if testing.Short() {
		fmt.Fprintln(os.Stderr, "tests/integration: skipped under -short; run `make test-integration`")
		os.Exit(0)
	}

	binary, discard, err := buildRouter()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		discard()
		os.Exit(1)
	}
	routerBinary = binary
	code := m.Run()
	discard()
	os.Exit(code)
}

// buildRouter compiles ./cmd/mosdns-router into a temporary directory and returns
// its path with the function that removes that directory again. The build is
// readonly, so a stale module file fails the suite instead of being quietly
// rewritten, and the toolchain is the one the Makefile's version guard accepted
// when that is how the suite was started.
func buildRouter() (string, func(), error) {
	directory, err := os.MkdirTemp("", "mosdns-router-integration.")
	discard := func() { _ = os.RemoveAll(directory) }
	if err != nil {
		return "", discard, fmt.Errorf("integration: create a build directory: %w", err)
	}

	binary := filepath.Join(directory, "mosdns-router")
	build := exec.Command(goToolchain(), "build", "-mod=readonly", "-o", binary, "./cmd/mosdns-router")
	// A test binary's working directory is its own package directory, and the
	// command to build lives two levels above it.
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		return "", discard, fmt.Errorf("integration: go build ./cmd/mosdns-router: %w\n%s", err, output)
	}
	return binary, discard, nil
}

// goToolchain is the go command the child build uses. The Makefile passes the
// toolchain its version guard accepted, so the binary a case runs is built by the
// same release `make test-integration` checked. A plain
// `go test ./tests/integration` uses the one on PATH, which the module's own go
// directive pins to the same release.
func goToolchain() string {
	if toolchain := strings.TrimSpace(os.Getenv("MOSDNS_ROUTER_GO")); toolchain != "" {
		return toolchain
	}
	return "go"
}

// --- the child process ---

// router is a running mosdns-router. It is stopped in the test's cleanup:
// SIGTERM first, because that is how a unit stops it and a router that ignores it
// is a defect this harness would be hiding, and a kill only if the grace passes,
// so a case can never leave a stray process behind. Its standard error is kept
// whole and printed into every failure that happens after it started, because the
// reasons this router does anything are all reported there and nowhere else.
type router struct {
	command *exec.Cmd
	output  *lockedBuffer
	exited  chan struct{}
	err     error
}

func startRouter(t *testing.T, configPath string) *router {
	t.Helper()
	if routerBinary == "" {
		t.Fatal("the router binary was never built: TestMain did not run")
	}

	// The context is the backstop for a shutdown that never arrives. The explicit
	// signal below is what a unit sends; this is what a hung case would otherwise
	// leave behind.
	ctx, cancel := context.WithCancel(context.Background())
	child := &router{output: &lockedBuffer{}, exited: make(chan struct{})}
	child.command = exec.CommandContext(ctx, routerBinary, "start", "-c", configPath)
	child.command.Stdout = child.output
	child.command.Stderr = child.output

	if err := child.command.Start(); err != nil {
		cancel()
		t.Fatalf("start mosdns-router: %v", err)
	}
	go func() {
		child.err = child.command.Wait()
		close(child.exited)
	}()
	// Cleanups run last in, first out, so the process is stopped before the
	// resolvers it talks to are closed.
	t.Cleanup(func() {
		child.stop(t)
		cancel()
	})
	return child
}

// stop ends the child. A router that answered SIGTERM exits zero; anything else
// is reported, because a shutdown failure here is a failure a service unit would
// see as well.
func (r *router) stop(t *testing.T) {
	t.Helper()
	select {
	case <-r.exited:
		r.reportExit(t)
		return
	default:
	}

	if err := r.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("the router did not accept SIGTERM: %v\n%s", err, r.diagnostics())
	}
	select {
	case <-r.exited:
	case <-time.After(shutdownGrace):
		_ = r.command.Process.Kill()
		<-r.exited
		t.Errorf("the router was still running %s after SIGTERM and had to be killed:\n%s", shutdownGrace, r.diagnostics())
	}
	r.reportExit(t)
}

func (r *router) reportExit(t *testing.T) {
	t.Helper()
	if r.err != nil {
		t.Errorf("mosdns-router did not exit cleanly: %v\n%s", r.err, r.diagnostics())
	}
}

// running reports whether the child is still alive, for a case that wants to say
// so in a failure message.
func (r *router) running() bool {
	select {
	case <-r.exited:
		return false
	default:
		return true
	}
}

// diagnosticsTail is how much of the child's output a failure carries. The whole
// of it is a per-query log at the level the rendered document states, so the tail
// is where the reason for the last few exchanges is.
const diagnosticsTail = 40

func (r *router) diagnostics() string {
	output := strings.TrimRight(r.output.String(), "\n")
	if output == "" {
		return "--- mosdns-router wrote nothing to its standard error ---"
	}
	lines := strings.Split(output, "\n")
	if len(lines) > diagnosticsTail {
		lines = lines[len(lines)-diagnosticsTail:]
	}
	return fmt.Sprintf("--- mosdns-router output, last %d lines ---\n%s", len(lines), strings.Join(lines, "\n"))
}

// reported tells whether the child said something, waiting briefly for it. The
// line that explains a failure is written before the answer the case is reading
// comes back, so a case holding an answer already holds the line; the wait is for
// the scheduler, not for the router.
func (r *router) reported(t *testing.T, fragment string) bool {
	t.Helper()
	deadline := time.Now().Add(reportDeadline)
	for {
		if strings.Contains(r.output.String(), fragment) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// lockedBuffer collects a child's output. The copier goroutine exec.Cmd installs
// and the test itself both write to it, so every access is guarded.
type lockedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(payload []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(payload)
}

func (b *lockedBuffer) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.String()
}

// --- the harness ---

// stateFixture is what the DHCP bridge had published before the router started.
// It is the one thing the fail-closed cases turn: a router that started without a
// state document, or with one it cannot read, has to still answer foreign names
// and refuse domestic ones.
type stateFixture int

const (
	// publishedState is a valid schema-1 document naming the domestic resolver.
	publishedState stateFixture = iota
	// noStateDocument is no file at all, which is what a router sees before the
	// bridge has ever published.
	noStateDocument
	// corruptStateDocument is a file the strict decoder cannot read. It is
	// truncated rather than merely wrong, so the failure is the decode itself
	// rather than a validation refusal that a later change might reorder.
	corruptStateDocument
)

// harness is a router process with the two resolvers it talks to, a
// configuration rendered for all three, and the state document the bridge
// published.
type harness struct {
	foreign  *testdns.Server
	domestic *testdns.Server
	router   *router

	listen string
	// upstreamAddress is the real local address the domestic resolver is bound
	// to, and interfaceName is the device that owns it. Both are what the state
	// document names, so a case can say which address it published.
	upstreamAddress netip.Addr
	interfaceName   string
	cnList          string
	stateFile       string
	answered        counter
}

// newHarness starts both resolvers, publishes the state the fixture calls for,
// renders a configuration that points at all three, and starts the router on it.
func newHarness(t *testing.T, fixture stateFixture) *harness {
	t.Helper()
	address, interfaceName := localUnicastAddress(t)
	t.Logf("the domestic resolver answers on %s (%s), and the published state names that address and interface",
		address, interfaceName)

	// The foreign resolver is on loopback: nothing about it is validated, and
	// loopback cannot be reached from off this host. The domestic one cannot be,
	// because the production state decoder refuses a loopback upstream and the
	// plugin reads the state through that decoder.
	h := &harness{upstreamAddress: address, interfaceName: interfaceName}
	h.foreign = startForeignResolver(t)
	t.Cleanup(func() { _ = h.foreign.Close() })
	h.domestic = startDomesticResolver(t, address, &h.answered)
	t.Cleanup(func() { _ = h.domestic.Close() })

	directory := t.TempDir()
	h.cnList = copyChinaList(t, directory)
	h.stateFile = filepath.Join(directory, "dhcp-upstreams.json")
	switch fixture {
	case publishedState:
		h.publishState(t, firstGeneration)
	case noStateDocument:
		// Nothing is written: this is the state of a router that started before
		// the bridge has ever published.
	case corruptStateDocument:
		if err := os.WriteFile(h.stateFile, []byte(corruptDocument), 0o600); err != nil {
			t.Fatalf("write the corrupt state document: %v", err)
		}
	default:
		t.Fatalf("unknown state fixture %d", fixture)
	}

	// The listen port is the one address the router cannot be asked to pick, so
	// it is reserved and released rather than guessed.
	h.listen = reserveLoopbackAddress(t)
	_, upstreamPort, err := net.SplitHostPort(h.domestic.Address())
	if err != nil {
		t.Fatalf("split the domestic address %q: %v", h.domestic.Address(), err)
	}
	document, err := mosdnsconfig.Render(config.Defaults(), mosdnsconfig.Paths{
		Policy:    filepath.Join(directory, "policy.yaml"),
		CNDomains: h.cnList,
		DHCPState: h.stateFile,
		// The foreign branch is entered over TCP, so the resolver is a tcp://
		// listener. The renderer refuses the system resolver's port, so an
		// ephemeral one is what it can be pointed at.
		ForeignListener: "tcp://" + h.foreign.Address(),
		Listen:          h.listen,
		// A published state carries a bare address, so the port it is dialled on
		// is this document's to state. Without it the plugin would dial 53, and
		// the domestic branch would answer nothing at all.
		DHCPUpstreamPort: atoi(t, upstreamPort),
	})
	if err != nil {
		t.Fatalf("render a configuration for the harness: %v", err)
	}
	configPath := filepath.Join(directory, "mosdns.yaml")
	if err := os.WriteFile(configPath, document, 0o600); err != nil {
		t.Fatalf("write the rendered configuration: %v", err)
	}

	h.router = startRouter(t, configPath)
	return h
}

// publishState writes a valid schema-1 document with this repository's own
// writer, so the plugin reads what the bridge would have written and a document
// that is only valid to this test cannot reach it. A later generation is a DHCP
// renewal: a new generation owns a new cache, which is what
// TestTheForeignCacheNeverChangesWhatTheDomesticPathReturns uses to make every
// domestic query a real upstream exchange.
func (h *harness) publishState(t *testing.T, generation uint64) {
	t.Helper()
	published := state.NewDHCPState(
		generation,
		h.interfaceName,
		stateConnection,
		[]string{h.upstreamAddress.String()},
		time.Now().UTC(),
		stateSource,
		true,
	)
	if err := state.WriteJSONAtomic(h.stateFile, published); err != nil {
		t.Fatalf("publish DHCP state generation %d with this repository's own writer: %v", generation, err)
	}
}

// ask sends one query to the router and returns the answer. The transport is the
// hop from this process to the router, which is a choice a case makes; the
// router's own hop to the foreign resolver is always TCP.
func (h *harness) ask(t *testing.T, transport, name string, qtype uint16) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), qtype)
	query.Id = dns.Id()

	client := &dns.Client{Net: transport, Timeout: queryTimeout}
	response, _, err := client.Exchange(query, h.listen)
	if err != nil {
		t.Fatalf("the %s query %s %s to the router on %s did not come back: %v\n%s",
			transport, dns.Fqdn(name), dns.TypeToString[qtype], h.listen, err, h.router.diagnostics())
	}
	if response.Id != query.Id {
		t.Fatalf("the router answered transaction %d with transaction %d, so this is not an answer to the query that was sent", query.Id, response.Id)
	}
	return response
}

// counts is how many queries each resolver had been asked. A case that has
// already waited for the router to answer takes one of these and compares against
// it: the readiness poll is a real query, and a count taken before the poll
// would be off by however many the poll cost.
type counts struct {
	foreign  int
	domestic int
}

func (h *harness) counts() counts {
	return counts{foreign: h.foreign.Count("", ""), domestic: h.domestic.Count("", "")}
}

// since is the number of queries each resolver took in between, which is what a
// case asserts on: a per-name count and the grand total have to move together, or
// a query reached a resolver under a name no case asked about.
func (c counts) since(earlier counts) counts {
	return counts{foreign: c.foreign - earlier.foreign, domestic: c.domestic - earlier.domestic}
}

// waitUntilAnswering is the readiness check, and it is a real query rather than a
// sleep: a query that arrives before the read loop starts is dropped by the
// socket rather than answered, so only a reply proves the listener is up. Both
// transports are checked because the router binds two, and a case that only ever
// used one would never notice the other missing.
//
// The two probes are the same question, so the second may well be answered from
// the foreign cache rather than from the resolver. That is why no case asserts
// on a grand total taken from before this point: each takes its own snapshot
// afterwards, and every count it makes is either for its own names or a change
// since that snapshot.
func (h *harness) waitUntilAnswering(t *testing.T) {
	t.Helper()
	for _, transport := range []string{testdns.ProtocolUDP, testdns.ProtocolTCP} {
		h.pollUntilAnswering(t, transport)
	}
	t.Logf("the router answers on %s; it enters the foreign resolver at %s and reads its DHCP upstreams from %s",
		h.listen, h.foreign.Address(), h.stateFile)
}

func (h *harness) pollUntilAnswering(t *testing.T, transport string) {
	t.Helper()
	client := &dns.Client{Net: transport, Timeout: readinessDialWait}
	query := new(dns.Msg)
	query.SetQuestion(readinessName, dns.TypeA)
	query.Id = dns.Id()

	deadline := time.Now().Add(readinessTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		response, _, err := client.Exchange(query, h.listen)
		switch {
		case err != nil:
			lastErr = err
		case response.Id != query.Id || len(response.Question) != 1 || response.Question[0].Name != readinessName:
			t.Fatalf("the router answered the readiness query with a message for a different transaction or question: %v", response)
		default:
			// Any rcode will do. What is proved here is that the listener answers,
			// not which branch a probe name belongs to.
			return
		}
		time.Sleep(readinessPollWait)
	}
	if h.router.running() {
		lastErr = fmt.Errorf("the child process is running but not answering (%w)", lastErr)
	}
	t.Fatalf("the router answered no %s query on %s within %s: %v\n%s",
		transport, h.listen, readinessTimeout, lastErr, h.router.diagnostics())
}

// --- the resolvers ---

// startForeignResolver is the resolver the foreign branch is pointed at. It
// answers every type the cases ask for, so a case never has to tell a
// deliberately unanswered question from a lost one.
func startForeignResolver(t *testing.T) *testdns.Server {
	t.Helper()
	server, err := testdns.StartOn("127.0.0.1:0", func(_ context.Context, request *dns.Msg) *dns.Msg {
		question := request.Question[0]
		record := foreignRecord(question)
		if record == nil {
			return nil
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{record}
		return response
	})
	if err != nil {
		t.Fatalf("start the foreign resolver: %v", err)
	}
	return server
}

// startDomesticResolver is the resolver DHCP published, bound to a real local
// address rather than to loopback. Two things about its answers are deliberate.
//
// Every A answer is a different address, so an answer that came from an earlier
// call cannot be mistaken for a fresh one. And a small answer is never retried
// over TCP, because a truncated answer is the only thing that makes the plugin
// spend its TCP retry: a resolver that truncated everything would hide that the
// small ones are not retried at all.
func startDomesticResolver(t *testing.T, address netip.Addr, answered *counter) *testdns.Server {
	t.Helper()
	server, err := testdns.StartOn(net.JoinHostPort(address.String(), "0"), func(ctx context.Context, request *dns.Msg) *dns.Msg {
		question := request.Question[0]
		response := new(dns.Msg)
		response.SetReply(request)
		switch question.Qtype {
		case dns.TypeA:
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(198, 51, 100, answered.next()).To4(),
			}}
		case dns.TypeTXT:
			response.Answer = []dns.RR{largeTXT(question.Name)}
		default:
			// Nothing else is answered, so a type the router must not be sending
			// here shows up as a SERVFAIL rather than as a plausible answer.
			return nil
		}
		// A real resolver truncates an answer that will not fit the datagram the
		// query arrived on. Reproducing that is the only way the plugin's own TCP
		// retry is reachable, and reaching it is the point of the large-answer
		// case.
		if testdns.Protocol(ctx) == testdns.ProtocolUDP && packedLength(response) > minimumUDPPayload {
			truncated := new(dns.Msg)
			truncated.SetReply(request)
			truncated.Truncated = true
			return truncated
		}
		return response
	})
	if err != nil {
		t.Fatalf("start the domestic resolver on %s: %v", address, err)
	}
	return server
}

// foreignRecord is the answer the foreign resolver gives, whatever the type asked
// for. Type 65 is a record shape nothing in this project knows how to build, so
// asking for it is what proves the router carries a record it cannot interpret
// through unchanged.
func foreignRecord(question dns.Question) dns.RR {
	header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: 300}
	switch question.Qtype {
	case dns.TypeA:
		header.Rrtype = dns.TypeA
		return &dns.A{Hdr: header, A: net.ParseIP(foreignAddress).To4()}
	case dns.TypeHTTPS:
		header.Rrtype = dns.TypeHTTPS
		return &dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      header,
			Priority: 1,
			Target:   ".",
			Value:    []dns.SVCBKeyValue{&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}}},
		}}
	case dns.TypeTXT:
		header.Rrtype = dns.TypeTXT
		return largeTXT(question.Name)
	default:
		// No record rather than a plausible one: a case that asked for something
		// unexpected should see SERVFAIL, not a wrong answer.
		return nil
	}
}

// largeTXT is a TXT answer that cannot fit in a datagram. One character-string is
// limited to 255 bytes, so a long TXT is a sequence of them: four 200-byte
// strings are 800 bytes of payload, and with the name, the type, the class, the
// TTL and the four length octets the record is over 830 bytes on the wire. That
// is what makes it the answer a resolver has to truncate.
func largeTXT(name string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{
			strings.Repeat("a", 200),
			strings.Repeat("b", 200),
			strings.Repeat("c", 200),
			strings.Repeat("d", 200),
		},
	}
}

func packedLength(message *dns.Msg) int {
	wire, err := message.Pack()
	if err != nil {
		return 0
	}
	return len(wire)
}

// recordWire is the packed form of one record, so an answer can be compared
// against the record that was supposed to produce it byte for byte instead of
// field by field: a byte that changed in transit has to fail here too. A message
// whose only content is that record has an all-zero header, so comparing two of
// them compares the record and nothing else.
func recordWire(t *testing.T, record dns.RR) []byte {
	t.Helper()
	message := new(dns.Msg)
	message.Answer = []dns.RR{record}
	wire, err := message.Pack()
	if err != nil {
		t.Fatalf("pack %v: %v", record, err)
	}
	return wire
}

// answeredAddresses is the A records of an answer, so a case can say which
// resolver produced it.
func answeredAddresses(t *testing.T, response *dns.Msg) []string {
	t.Helper()
	addresses := make([]string, 0, len(response.Answer))
	for _, record := range response.Answer {
		address, ok := record.(*dns.A)
		if !ok {
			t.Fatalf("the answer carries %v, which is not an A record: %v", dns.TypeToString[record.Header().Rrtype], record)
		}
		addresses = append(addresses, address.A.String())
	}
	return addresses
}

// equalStrings compares two lists of answers, so a failure can show both.
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

// --- the address a published state may name ---

// localUnicastAddress finds a real, routable, unicast IPv4 address on a
// non-loopback interface of this host.
//
// The domestic resolver cannot be on loopback. The production state decoder
// refuses a loopback upstream -- correctly, because a resolver the user is
// leaving is never on this machine -- and the plugin reads the published state
// through that decoder, so a loopback mock would never be dialled. The address
// has to be a real one for the same reason, and binding it keeps the exchange on
// this host: the kernel routes a packet addressed to one of its own addresses
// internally, and nothing is sent anywhere.
//
// The interface that owns the default route is preferred, because it is the one
// an online machine always has, and whichever address is taken is logged so a
// case can say what it published. A host with no such address cannot run these
// cases and says so rather than reporting a failure: a container with only
// loopback has no address the state decoder will accept, and working around that
// would need a bypass of the very validation these cases exist to hold to. The
// network-namespace variant of this suite is where such a host is covered.
func localUnicastAddress(t *testing.T) (netip.Addr, string) {
	t.Helper()
	preferred := defaultRouteInterface()

	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("this host's interfaces cannot be read, so no address a published DHCP state may name is known: %v", err)
	}
	var fallback netip.Addr
	var fallbackName string
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagUp == 0 || candidate.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := candidate.Addrs()
		if err != nil {
			continue
		}
		for _, assigned := range addresses {
			network, ok := assigned.(*net.IPNet)
			if !ok {
				continue
			}
			// The kernel reports an IPv4 address as a 16-byte IPv4-in-IPv6 value, so
			// it is unmapped before it is judged: the state decoder refuses a
			// 4-in-6 upstream, and an address it would refuse cannot be published
			// under it.
			address, ok := netip.AddrFromSlice(network.IP)
			if !ok {
				continue
			}
			address = address.Unmap()
			// The same conditions the state decoder applies, written out rather
			// than borrowed from it: a check taken from the code under test would
			// agree with that code whatever it said.
			if !address.Is4() || address.IsLoopback() ||
				address.IsUnspecified() || address.IsMulticast() ||
				!address.IsGlobalUnicast() || address.IsLinkLocalUnicast() {
				continue
			}
			if candidate.Name == preferred {
				return address, candidate.Name
			}
			if !fallback.IsValid() {
				fallback, fallbackName = address, candidate.Name
			}
		}
	}
	if !fallback.IsValid() {
		t.Skip("this host has no global-unicast IPv4 address on a non-loopback interface, and the " +
			"production DHCP state decoder refuses a loopback upstream, so no published state can " +
			"name a domestic resolver here; the network-namespace variant of this suite is what covers " +
			"such a host")
	}
	return fallback, fallbackName
}

// defaultRouteInterface is the device the kernel's default route uses, read from
// the routing table the kernel publishes. An empty result is not a failure: it
// only means the choice falls back to the first usable address, which the caller
// logs.
func defaultRouteInterface() string {
	table, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(table), "\n")
	for _, line := range lines[1:] {
		// The first column is the device and the second the destination, which is
		// 0.0.0.0 for the default route.
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "00000000" || fields[0] == "lo" {
			continue
		}
		return fields[0]
	}
	return ""
}

// --- the files the router is given ---

// copyChinaList copies the committed list into the case's own directory. A list
// that did not load would fail the router, and an empty one would send every name
// abroad, so the copy is the committed bytes rather than a fixture.
func copyChinaList(t *testing.T, directory string) string {
	t.Helper()
	committed, err := os.ReadFile(filepath.Clean(committedCNList))
	if err != nil {
		t.Fatalf("read the committed %s: %v", committedCNList, err)
	}
	path := filepath.Join(directory, "cn-domains.txt")
	if err := os.WriteFile(path, committed, 0o600); err != nil {
		t.Fatalf("copy the China list: %v", err)
	}
	return path
}

// inCommittedChinaList reports whether the pinned MOSDNS matcher would send a
// name down the domestic branch. It is the same domain_set the rendered document
// builds and the same matcher the `qname $cn_domains` condition uses, so the two
// names a routing case is about are classified the way the router classifies
// them.
func inCommittedChinaList(t *testing.T, listPath, name string) bool {
	t.Helper()
	matcher := domain.NewDomainMixMatcher()
	if err := domain_set.LoadFile(listPath, matcher); err != nil {
		t.Fatalf("load %s: %v", listPath, err)
	}
	_, matched := matcher.Match(dns.Fqdn(name))
	return matched
}

// reserveLoopbackAddress returns an address whose port is free on both transports
// right now. The router has to bind it, so the sockets that chose the port are
// given up first; nothing else in this process holds it, and a port that is free
// stays free for the moment between the release and the bind.
func reserveLoopbackAddress(t *testing.T) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a udp port for the router to listen on: %v", err)
	}
	address := packetConn.LocalAddr().String()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("reserve a tcp port for the router to listen on: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved tcp port: %v", err)
	}
	if err := packetConn.Close(); err != nil {
		t.Fatalf("release the reserved udp port: %v", err)
	}
	return address
}

// counter is the domestic resolver's per-call counter. It is guarded because the
// resolver serves both transports on their own goroutines.
type counter struct {
	mutex sync.Mutex
	last  byte
}

func (c *counter) next() byte {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.last++
	return c.last
}

func atoi(t *testing.T, value string) int {
	t.Helper()
	number, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("%q is not a port number: %v", value, err)
	}
	return number
}

// --- the cases ---

// TestRoutingSplitSendsEachNameToOnlyItsOwnBranch is the promise the whole
// project turns on, followed through a real process: a name the China list
// matches reaches the DHCP-configured resolver and nothing else, every other name
// reaches the foreign resolver and nothing else.
//
// Every query is counted by name on both resolvers, and both resolvers' totals
// are counted as well. The per-name counts say where each question went; the
// totals say nothing else did. A name that reached both resolvers passes a
// per-name check on either one alone, and a query that arrived under some other
// name is invisible to per-name counts entirely, so both are needed.
func TestRoutingSplitSendsEachNameToOnlyItsOwnBranch(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)

	// The names are classified by the matcher the router itself uses. Without
	// this, a committed list that stopped matching one of them would leave the
	// case below passing while proving something other than the split.
	if !inCommittedChinaList(t, h.cnList, chinaName) || !inCommittedChinaList(t, h.cnList, secondChinaName) {
		t.Fatalf("the committed China list does not match %s and %s, so the router would send them abroad and this case would prove the wrong split",
			chinaName, secondChinaName)
	}
	if inCommittedChinaList(t, h.cnList, foreignName) {
		t.Fatalf("the committed China list matches %s, so the router would send it to the DHCP upstream", foreignName)
	}

	before := h.counts()

	domestic := h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)
	if got, want := answeredAddresses(t, domestic), []string{"198.51.100.1"}; !equalStrings(got, want) {
		t.Errorf("%s = %v, want the domestic resolver's first answer %v", chinaName, got, want)
	}
	foreign := h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeA)
	if got, want := answeredAddresses(t, foreign), []string{foreignAddress}; !equalStrings(got, want) {
		t.Errorf("%s = %v, want the foreign resolver's answer %v", foreignName, got, want)
	}

	// Each name reached one resolver and only that one.
	if got := h.domestic.Count("", chinaName); got != 1 {
		t.Errorf("the domestic resolver was asked for %s %d times, want 1", chinaName, got)
	}
	if got := h.foreign.Count("", chinaName); got != 0 {
		t.Errorf("the foreign resolver was asked for %s %d times, want 0: a China name must never be forwarded abroad", chinaName, got)
	}
	if got := h.foreign.Count("", foreignName); got != 1 {
		t.Errorf("the foreign resolver was asked for %s %d times, want 1", foreignName, got)
	}
	if got := h.domestic.Count("", foreignName); got != 0 {
		t.Errorf("the domestic resolver was asked for %s %d times, want 0: a foreign name must never be re-asked inside the network the user is leaving", foreignName, got)
	}

	// And nothing else reached either of them: a query under a third name would
	// not be caught by any of the counts above.
	after := h.counts().since(before)
	if after.domestic != 1 {
		t.Errorf("the domestic resolver was asked %d times in total, want 1: the only query that should have reached it was for %s", after.domestic, chinaName)
	}
	if after.foreign != 1 {
		t.Errorf("the foreign resolver was asked %d times in total, want 1: the only query that should have reached it was for %s", after.foreign, foreignName)
	}
}

// TestAForeignQueryReachesTheResolverOnlyOverTCP covers the transport the
// foreign branch is entered with, and it is the reason the rendered document
// names a tcp:// URL rather than an address. MOSDNS's stock UDP upstream re-sends
// a query that has gone unanswered for a second and can drop an answer that
// arrived before its exchange began waiting for it, and the foreign branch has no
// client of its own to own that exchange. A foreign forward left on udp:// would
// show up here as a query the resolver received over udp, so the count of zero is
// the assertion, and the tcp count beside it says the query was not simply lost.
func TestAForeignQueryReachesTheResolverOnlyOverTCP(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)
	before := h.counts()

	// Asked over udp, so the client's transport is not what decides the upstream's.
	h.ask(t, testdns.ProtocolUDP, foreignName, dns.TypeA)

	if got := h.foreign.Count(testdns.ProtocolTCP, foreignName); got != 1 {
		t.Errorf("the foreign resolver received %d queries for %s over tcp, want 1", got, foreignName)
	}
	if got := h.foreign.Count(testdns.ProtocolUDP, foreignName); got != 0 {
		t.Errorf("the foreign resolver received %d queries for %s over udp, want 0: the foreign forward is a tcp:// upstream", got, foreignName)
	}
	after := h.counts().since(before)
	if after.foreign != 1 {
		t.Errorf("the foreign resolver was asked %d times in total, want 1", after.foreign)
	}
	if after.domestic != 0 {
		t.Errorf("the domestic resolver was asked %d times, want 0", after.domestic)
	}
}

// TestASmallDomesticQueryReachesTheUpstreamOnlyOverUDP covers the other side of
// the transport decision. The plugin keeps its own UDP exchange rather than
// mosdns's pipelined one, and it retries over TCP only when a UDP answer comes
// back truncated. A small A answer is not truncated, so the domestic resolver
// must have seen one query, over udp, and no query over tcp at all: a plugin that
// retried every exchange over TCP would satisfy a udp count of one and double
// every query on the wire.
func TestASmallDomesticQueryReachesTheUpstreamOnlyOverUDP(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)
	before := h.counts()

	h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)

	if got := h.domestic.Count(testdns.ProtocolUDP, chinaName); got != 1 {
		t.Errorf("the domestic resolver received %d queries for %s over udp, want 1", got, chinaName)
	}
	if got := h.domestic.Count(testdns.ProtocolTCP, chinaName); got != 0 {
		t.Errorf("the domestic resolver received %d queries for %s over tcp, want 0: a small answer is not truncated, so the plugin must not retry it", got, chinaName)
	}
	after := h.counts().since(before)
	if after.domestic != 1 {
		t.Errorf("the domestic resolver was asked %d times in total, want 1", after.domestic)
	}
	if after.foreign != 0 {
		t.Errorf("the foreign resolver was asked %d times, want 0", after.foreign)
	}
}

// TestAForeignFailureNeverFallsBackToTheDomesticBranch is the isolation the
// project exists for, from the other end: with the foreign resolver gone, the
// foreign name has to fail, and it has to fail rather than be answered from
// inside the network the user is leaving.
//
// The failure mode is asserted three ways because SERVFAIL alone does not say
// why. It must be SERVFAIL and not REFUSED, which is what an entry that returned
// no response at all produces, so a branch that fell through unanswered would be
// told apart from a branch that failed. It must carry no answer, so a domestic
// answer that leaked in could not pass as a failure. And the router's own report
// must name the foreign forward, so a SERVFAIL from some other cause cannot stand
// in for this one. The domestic resolver's total is then compared with what it
// was before the foreign one was stopped: unchanged is the whole claim.
func TestAForeignFailureNeverFallsBackToTheDomesticBranch(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)
	before := h.counts()

	// The China name is answered first, so the domestic path is known to work
	// before anything is taken away, and so its resolver has a total to keep.
	h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)
	domesticBefore := h.domestic.Count("", "")

	if err := h.foreign.Close(); err != nil {
		t.Fatalf("stop the foreign resolver: %v", err)
	}

	response := h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeA)
	if response.Rcode != dns.RcodeServerFailure {
		t.Errorf("%s with the foreign resolver stopped = %s, want SERVFAIL", foreignName, dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 0 {
		t.Errorf("%s with the foreign resolver stopped carried %d answer records, want none: a failed foreign query must not be answered from anywhere", foreignName, len(response.Answer))
	}
	if !h.router.reported(t, noUpstreamLog) {
		t.Errorf("the router did not report %q, so this SERVFAIL came from something other than the foreign forward failing\n%s",
			noUpstreamLog, h.router.diagnostics())
	}

	// Nothing reached the domestic branch. Its total is exactly what it was: a
	// foreign failure that fell back would have added at least one query.
	if got := h.domestic.Count("", ""); got != domesticBefore {
		t.Errorf("the domestic resolver was asked %d times while the foreign one was stopped, want %d: the foreign failure reached the domestic path",
			got, domesticBefore)
	}

	// And the branches do not share an upstream, so the dead one says nothing
	// about the other. The second name is a different one, so the plugin's own
	// generation cache cannot answer it and the exchange really does go out to the
	// published resolver.
	domestic := h.ask(t, testdns.ProtocolTCP, secondChinaName, dns.TypeA)
	if got, want := answeredAddresses(t, domestic), []string{"198.51.100.2"}; !equalStrings(got, want) {
		t.Errorf("%s while the foreign resolver is stopped = %v, want a fresh domestic answer %v", secondChinaName, got, want)
	}
	if got := h.domestic.Count("", secondChinaName); got != 1 {
		t.Errorf("the domestic resolver was asked %d times for %s, want 1", got, secondChinaName)
	}
	if after := h.counts().since(before); after.domestic != 2 || after.foreign != 0 {
		t.Errorf("resolvers were asked %+d since this case began, want the two domestic queries and nothing from the stopped foreign resolver", after)
	}
}

// TestArbitraryQTypesRoundTripByteForByte asks for a record shape nothing in
// this project knows how to build. Type 65 is not a type the router interprets:
// it is a type it has to carry, and a router that rebuilt, filtered or dropped an
// answer it did not recognise would show up here as a SERVFAIL or as a record
// that came back different. The comparison is the packed bytes of the whole
// record, so a byte that changed in transit fails this too.
func TestArbitraryQTypesRoundTripByteForByte(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)

	response := h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeHTTPS)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s over the router = %s, want an answer: type 65 has to be carried through the router untouched",
			dns.TypeToString[dns.TypeHTTPS], dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 1 {
		t.Fatalf("%s over the router carried %d answer records, want 1: %+v", dns.TypeToString[dns.TypeHTTPS], len(response.Answer), response.Answer)
	}
	if got := response.Question[0]; got.Qtype != dns.TypeHTTPS {
		t.Errorf("the answer echoes type %s, want %s: the query that was sent was a different type", dns.TypeToString[got.Qtype], dns.TypeToString[dns.TypeHTTPS])
	}

	// The expectation is the record the resolver was configured to answer with,
	// rebuilt here rather than read back out of the answer.
	want := foreignRecord(dns.Question{Name: foreignName, Qtype: dns.TypeHTTPS, Qclass: dns.ClassINET})
	if got := recordWire(t, response.Answer[0]); !bytes.Equal(got, recordWire(t, want)) {
		t.Errorf("the %s answer came back as\n %s\nwant\n %s",
			dns.TypeToString[dns.TypeHTTPS], got, recordWire(t, want))
	}
}

// TestALargeAnswerRoundTripsOverTheForeignTransport asks for an answer that will
// not fit in a datagram. The foreign branch is a tcp:// upstream and the client
// is on the router's TCP listener, so the whole path is sized for a large answer
// and the record has to arrive as the resolver built it. A foreign forward left
// on udp:// would truncate here, which is the loss the transport exists to
// prevent.
func TestALargeAnswerRoundTripsOverTheForeignTransport(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)

	response := h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeTXT)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("a large %s over the router = %s, want an answer: the foreign transport is sized for one",
			dns.TypeToString[dns.TypeTXT], dns.RcodeToString[response.Rcode])
	}
	if response.Truncated {
		t.Error("the router truncated a large answer on a TCP listener, want the whole record")
	}
	if len(response.Answer) != 1 {
		t.Fatalf("the large answer carried %d records, want 1: %+v", len(response.Answer), response.Answer)
	}

	// The claim that the answer was too large for a datagram is checked against
	// the record itself, so the case cannot pass on an answer that happens to be
	// small today.
	want := largeTXT(foreignName)
	if size := dns.Len(want); size <= minimumUDPPayload {
		t.Fatalf("the fixture TXT record is %d bytes, which fits a %d-byte datagram, so this case would not be testing a large answer", size, minimumUDPPayload)
	}
	if got := recordWire(t, response.Answer[0]); !bytes.Equal(got, recordWire(t, want)) {
		t.Errorf("the large TXT came back as\n %s\nwant\n %s", got, recordWire(t, want))
	}
	if got := h.foreign.Count(testdns.ProtocolUDP, foreignName); got != 0 {
		t.Errorf("the foreign resolver received %d queries for the large %s over udp, want 0", got, dns.TypeToString[dns.TypeTXT])
	}
}

// TestATruncatedDomesticAnswerIsRetriedOverTCPByThePlugin covers the one case
// where the plugin does spend its TCP retry. The mock truncates a UDP answer that
// will not fit the datagram, exactly as a resolver does, and answers the retry in
// full. The large record has to arrive, and both halves of the exchange have to
// be visible: the plugin asked over udp, saw the truncated answer, and asked
// again over tcp. A plugin that gave up on a truncated answer would fail the
// record, and one that started on tcp would fail the counts.
func TestATruncatedDomesticAnswerIsRetriedOverTCPByThePlugin(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)

	response := h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeTXT)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("a large %s for %s over the router = %s, want an answer: the plugin must retry a truncated domestic answer over tcp",
			dns.TypeToString[dns.TypeTXT], chinaName, dns.RcodeToString[response.Rcode])
	}
	if len(response.Answer) != 1 {
		t.Fatalf("the large answer carried %d records, want 1: %+v", len(response.Answer), response.Answer)
	}
	want := largeTXT(chinaName)
	if got := recordWire(t, response.Answer[0]); !bytes.Equal(got, recordWire(t, want)) {
		t.Errorf("the large domestic TXT came back as\n %s\nwant\n %s", got, recordWire(t, want))
	}

	if got := h.domestic.Count(testdns.ProtocolUDP, chinaName); got != 1 {
		t.Errorf("the domestic resolver received %d queries for %s over udp, want 1: the plugin's own exchange is a UDP one", got, chinaName)
	}
	if got := h.domestic.Count(testdns.ProtocolTCP, chinaName); got != 1 {
		t.Errorf("the domestic resolver received %d queries for %s over tcp, want 1: the truncated UDP answer has to be retried", got, chinaName)
	}
}

// TestStartupFailsClosedWithoutAPublishableState is the startup guard. A router
// whose state document is missing or unreadable must still start, must still
// answer foreign names, and must refuse domestic ones. The third half is the one
// that matters: a domestic branch that fell through to the foreign branch would
// answer the China name from the resolver the user is leaving, which is the whole
// thing this project refuses to build.
//
// The two sub-cases are separate because they fail in different places, and each
// says so. With no file at all the plugin has nothing to read and reports no
// usable state. With a file it cannot decode, the plugin read the file, rejected
// it, and still has no usable state -- a warning that only appears for the second
// is what tells the two apart.
func TestStartupFailsClosedWithoutAPublishableState(t *testing.T) {
	for name, testCase := range map[string]struct {
		fixture stateFixture
		// wantReport is what the router must have said about the state document
		// for this fixture. It is empty where there is nothing to report.
		wantReport string
	}{
		"no state document at all":          {fixture: noStateDocument},
		"a state document that is not JSON": {fixture: corruptStateDocument, wantReport: unusableStateLog},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, testCase.fixture)
			h.waitUntilAnswering(t)
			before := h.counts()

			// The router started. A guard that refused to start would satisfy
			// "fails closed" for entirely the wrong reason, so the foreign path is
			// asked first and has to answer.
			foreign := h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeA)
			if got, want := answeredAddresses(t, foreign), []string{foreignAddress}; !equalStrings(got, want) {
				t.Fatalf("%s = %v, want the foreign resolver's answer %v: the router has to keep working with no usable state",
					foreignName, got, want)
			}
			// A count for this name, not a change in the grand total: the readiness
			// poll used a different name, so only this case's own query can be
			// carrying it.
			if got := h.foreign.Count("", foreignName); got != 1 {
				t.Errorf("the foreign resolver was asked %d times for %s, want 1", got, foreignName)
			}

			// The domestic branch fails closed, and the rcode says it failed rather
			// than fell through: an entry that returns an error is SERVFAIL, an
			// entry that returns no response at all is REFUSED.
			domestic := h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)
			if domestic.Rcode != dns.RcodeServerFailure {
				t.Errorf("%s = %s, want SERVFAIL: there is no usable upstream, so the branch fails closed", chinaName, dns.RcodeToString[domestic.Rcode])
			}
			if len(domestic.Answer) != 0 {
				t.Errorf("%s carried %d answer records, want none: a China name must not be answered from the foreign resolver", chinaName, len(domestic.Answer))
			}
			if !h.router.reported(t, entryFailedLog) {
				t.Errorf("the router did not report an entry failure, so this SERVFAIL was not the plugin refusing to answer\n%s", h.router.diagnostics())
			}
			if !h.router.reported(t, noUpstreamReport) {
				t.Errorf("the router did not report %q, so the domestic branch failed for some other reason\n%s", noUpstreamReport, h.router.diagnostics())
			}
			if testCase.wantReport != "" && !h.router.reported(t, testCase.wantReport) {
				t.Errorf("the router did not report %q, so the state document was not read and rejected\n%s", testCase.wantReport, h.router.diagnostics())
			}

			// The foreign resolver saw the foreign name and nothing else, and the
			// domestic resolver -- which has no published upstream here at all --
			// was asked nothing.
			if got := h.foreign.Count("", chinaName); got != 0 {
				t.Errorf("the foreign resolver was asked %d times for %s, want 0", got, chinaName)
			}
			if after := h.counts().since(before); after.domestic != 0 {
				t.Errorf("the domestic resolver was asked %d times, want 0: no upstream was published", after.domestic)
			}
		})
	}
}

// TestTheForeignCacheNeverChangesWhatTheDomesticPathReturns is the regression
// guard for the jump out of the dispatch. `exec: $cn_path` would *call* the
// domestic sequence and then resume the main chain at its next rule, so a
// successful domestic answer would be carried into the foreign branch and stored
// in a cache that is not generation-scoped. The second query would then be
// answered with the first one's answer while the fresh one was fetched and
// discarded, and that answer would outlive the DHCP DNS set it came from.
//
// Detecting it needs every domestic query to be a real upstream exchange, which a
// new generation is what buys: a DHCP renewal gives the plugin a cache of its
// own, and the foreign cache is not scoped to one. The three answers must
// therefore be the resolver's first, second and third, in that order, and the
// foreign resolver must never have been asked about the name at all.
//
// The foreign branch is stable in the other direction and is checked here too,
// because the same fix is what makes it so: the same question asked three times
// is answered from the resolver once and from the cache twice, so the answer set
// is one answer rather than three.
func TestTheForeignCacheNeverChangesWhatTheDomesticPathReturns(t *testing.T) {
	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)

	answers := make([]string, 0, 3)
	for round := range 3 {
		if round > 0 {
			// A renewal, which is the only way a second China question is
			// guaranteed to be a real exchange rather than the plugin's own
			// cached answer.
			h.publishState(t, uint64(firstGeneration+round))
		}
		response := h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)
		if response.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s on round %d = %s, want an answer from the domestic resolver", chinaName, round+1, dns.RcodeToString[response.Rcode])
		}
		answers = append(answers, answeredAddresses(t, response)...)
	}
	want := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	if !equalStrings(answers, want) {
		t.Fatalf("three %s answers across three DHCP generations = %v, want %v: a later answer has to be the fresh one",
			chinaName, answers, want)
	}
	if got := h.domestic.Count("", chinaName); got != 3 {
		t.Errorf("the domestic resolver was asked %d times for %s, want 3: one real exchange per generation", got, chinaName)
	}
	if got := h.foreign.Count("", chinaName); got != 0 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 0: a China name must never reach the foreign branch", got, chinaName)
	}

	foreignAnswers := make([]string, 0, 3)
	for round := range 3 {
		response := h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeA)
		if response.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s on round %d = %s, want an answer from the foreign resolver", foreignName, round+1, dns.RcodeToString[response.Rcode])
		}
		foreignAnswers = append(foreignAnswers, answeredAddresses(t, response)...)
	}
	if want := []string{foreignAddress, foreignAddress, foreignAddress}; !equalStrings(foreignAnswers, want) {
		t.Errorf("three %s answers = %v, want %v: the answer set has to be stable", foreignName, foreignAnswers, want)
	}
	if got := h.foreign.Count("", foreignName); got != 1 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 1: the second and third queries must be answered from the cache", got, foreignName)
	}
}
