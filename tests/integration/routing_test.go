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
	// expectsFailure marks a child this harness started knowing would not run. A
	// case about a configuration the router refuses has to be able to hold the
	// non-zero exit without the stop-time report turning it into a second failure
	// of the same thing; the case still asserts on the exit itself.
	expectsFailure bool
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
	if r.err == nil || r.expectsFailure {
		return
	}
	t.Errorf("mosdns-router did not exit cleanly: %v\n%s", r.err, r.diagnostics())
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

// chinaListFixture is the China rule list a case renders with. The default is the
// committed list, because a case that is not about the list must be proving
// something about the routing and not about a fixture. A zero-rule list is the
// other state the list can be in, and it is the only fail-open one: the list loads,
// every name is unmatched, and every query therefore takes the foreign branch.
type chinaListFixture int

const (
	// committedChinaList is a copy of configs/cn-domains.txt.
	committedChinaList chinaListFixture = iota
	// noChinaRules is a list file that resolves to no rule at all. MOSDNS loads
	// it without complaint, so the router starts and serves, and it answers
	// nothing to the domestic branch because nothing matches. The empty file is
	// the shape a wiped or truncated /var/lib leaves behind, and the converter
	// refuses to publish one -- this is the only way to get here.
	noChinaRules
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
	return newHarnessWithList(t, fixture, committedChinaList)
}

// newHarnessWithList is newHarness with the China rule list chosen by the case.
// Splitting it out keeps every existing call site unchanged, so the cases that are
// not about the list cannot accidentally stop using the committed bytes.
func newHarnessWithList(t *testing.T, fixture stateFixture, list chinaListFixture) *harness {
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
	h.cnList = writeChinaList(t, directory, list)
	// The readiness probe's name must not be in the China list, or the poll's
	// query is a domestic one: it would be answered by the domestic resolver, so
	// the counter the cases compare -- which expects the domestic resolver's first
	// answer to be 198.51.100.1 -- would be one along before the case asked
	// anything, and every assertion about a numbered answer would be off. True of
	// the committed list today, and asserted here so a list that started matching
	// it fails the harness rather than every case's arithmetic.
	if inCommittedChinaList(t, h.cnList, readinessName) {
		t.Fatalf("the China list matches the readiness probe name %s, so the poll's own query would be answered by the domestic resolver and the numbered answers every case compares would be one along",
			readinessName)
	}
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

// unstartableConfiguration is a configuration the pinned mosdns refuses to load.
// It is what a case uses to make the child exit at startup: a plugin type that is
// not registered is a load failure rather than a runtime one, so the process is
// gone within milliseconds and the reason is in its output rather than in a
// timeout.
const unstartableConfiguration = `log:
  level: info
plugins:
  - tag: broken
    type: no_such_plugin_type
    args: {}
`

// TestTheReadinessPollGivesUpOnAChildThatHasExited covers the cost of a
// configuration mistake. The poll is a loop with a deadline, and a child that has
// already exited will never answer it, so without a liveness check a case waits
// out the whole readiness timeout for each transport before it says anything --
// two full waits for a failure whose reason was in the child's output all along,
// and a report that says "not answering" about a process that is not running. The
// check must cost nothing when the child is alive, so the bound below is tight
// against the timeout rather than against the poll interval.
func TestTheReadinessPollGivesUpOnAChildThatHasExited(t *testing.T) {
	address, _, reason := discoverUnicastAddress()
	if !address.IsValid() {
		// This case never publishes a state document, so it does not need the
		// address the routing cases need; it only has to be asked of a host that
		// can run it at all.
		t.Skipf("this host cannot run the end-to-end cases (%s)", reason)
	}

	directory := t.TempDir()
	configPath := filepath.Join(directory, "mosdns.yaml")
	if err := os.WriteFile(configPath, []byte(unstartableConfiguration), 0o600); err != nil {
		t.Fatal(err)
	}
	listen := reserveLoopbackAddress(t)
	child := startRouter(t, configPath)
	child.expectsFailure = true

	started := time.Now()
	// The poll is given a harness that carries only what it reads -- the address
	// it probes and the child it is waiting on -- so the case is about the poll and
	// not about a router that never came up.
	h := &harness{listen: listen, router: child}
	verdict := h.pollUntilAnswering(testdns.ProtocolUDP)
	waited := time.Since(started)

	if verdict == nil {
		t.Fatal("the poll reported a router that never started as answering")
	}
	// The verdict has to name the exit and carry the child's own reason, because
	// that is what a person reads: "not answering" about a process that is not
	// running is the report the check exists to replace.
	if !strings.Contains(verdict.Error(), "no_such_plugin_type") {
		t.Errorf("the poll's verdict does not carry the child's own reason:\n%v", verdict)
	}
	if !strings.Contains(verdict.Error(), "exited") {
		t.Errorf("the poll's verdict does not say the child exited rather than that it was silent:\n%v", verdict)
	}
	if waited > readinessTimeout/2 {
		t.Errorf("the poll spent %s reporting a child that had already exited, want well under the %s readiness timeout",
			waited.Round(time.Millisecond), readinessTimeout)
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
		if err := h.pollUntilAnswering(transport); err != nil {
			t.Fatalf("%v", err)
		}
	}
	t.Logf("the router answers on %s; it enters the foreign resolver at %s and reads its DHCP upstreams from %s",
		h.listen, h.foreign.Address(), h.stateFile)
}

// pollUntilAnswering returns why the router is not answering on one transport, and
// nil once it is. It is a value rather than a fatal call so a case can drive the
// poll against a child that is never coming up and observe what it concluded --
// which is the only way the liveness check below is testable.
func (h *harness) pollUntilAnswering(transport string) error {
	client := &dns.Client{Net: transport, Timeout: readinessDialWait}
	query := new(dns.Msg)
	query.SetQuestion(readinessName, dns.TypeA)
	query.Id = dns.Id()

	deadline := time.Now().Add(readinessTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		// A child that has already exited will never answer, so the deadline is
		// the wrong thing to wait for: the whole readiness timeout would be spent
		// polling a socket nobody holds, once per transport, and the reason the
		// child is gone is in the output it wrote on its way out. The liveness
		// check is the first thing the loop does, so a configuration mistake costs
		// one poll interval rather than a timeout -- and it costs nothing at all
		// while the child is alive, which is the case every other test is in.
		if !h.router.running() {
			return fmt.Errorf("mosdns-router exited (%v) before it answered a %s query on %s, so waiting cannot succeed:\n%s",
				h.router.err, transport, h.listen, h.router.diagnostics())
		}
		response, _, err := client.Exchange(query, h.listen)
		switch {
		case err != nil:
			lastErr = err
		case response.Id != query.Id || len(response.Question) != 1 || response.Question[0].Name != readinessName:
			return fmt.Errorf("the router answered the readiness query with a message for a different transaction or question: %v", response)
		default:
			// Any rcode will do. What is proved here is that the listener answers,
			// not which branch a probe name belongs to.
			return nil
		}
		time.Sleep(readinessPollWait)
	}
	return fmt.Errorf("the router answered no %s query on %s within %s: the child process is running but not answering (%v)\n%s",
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

// recordPacked is one record re-packed into a DNS message, so an answer can be
// compared against the record that was supposed to produce it without comparing it
// field by field: a field the router rebuilt differently has to fail here too. A
// message whose only content is that record has an all-zero header, so comparing
// two of them compares the record and nothing else.
//
// It is packed-form equality, not wire-byte equality, and the distinction is worth
// keeping in the name. The record that came back was decoded off the socket and
// re-packed here, and so was the expectation, so both sides go through the same
// encoder: a difference the DNS wire format does not distinguish -- a differently
// compressed name that decodes to the same labels, say -- is invisible to this
// comparison, and so is any encoder bug shared by both sides. What it does catch
// is a router that changed the record's content or its TTL or its type, which is
// what these cases are about. A wire-byte comparison would have to keep the
// received bytes and the sent bytes, which this harness does not do.
func recordPacked(t *testing.T, record dns.RR) []byte {
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

// publishableUpstream reports whether the production DHCP state decoder would
// accept an address as an upstream: a global-unicast IPv4 with no zone, on a
// device rather than on this machine.
//
// The conditions are the decoder's own, written out rather than borrowed from
// it, because a check taken from the code under test would agree with that code
// whatever it said. The one addition is the unmapping, because the kernel
// reports an IPv4 interface address as a 16-byte IPv4-in-IPv6 value and the
// decoder refuses a 4-in-6 upstream -- an address it would refuse cannot be
// published under it.
//
// This is the single list. Discovery filters with it and so does the reporter,
// so the two cannot disagree about what a published state may name.
func publishableUpstream(address netip.Addr) bool {
	return address.IsValid() &&
		address.Unmap() == address &&
		address.Is4() &&
		!address.IsLoopback() &&
		!address.IsUnspecified() &&
		!address.IsMulticast() &&
		address.IsGlobalUnicast() &&
		!address.IsLinkLocalUnicast() &&
		address.Zone() == ""
}

// discoverUnicastAddress looks for an address a published DHCP state may name,
// preferring the device that owns the default route because it is the one an
// online machine always has. Binding such an address keeps the exchange on this
// host: the kernel routes a packet addressed to one of its own addresses
// internally, so nothing is sent anywhere and no route is needed.
//
// It returns the zero address, an empty device and the reason when there is none,
// so the caller can report a host rather than guess at one.
func discoverUnicastAddress() (netip.Addr, string, string) {
	preferred := defaultRouteInterface()

	interfaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, "", fmt.Sprintf("this host's interfaces cannot be read, so no address is known: %v", err)
	}
	var fallback netip.Addr
	var fallbackDevice string
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
			address, ok := netip.AddrFromSlice(network.IP)
			if !ok {
				continue
			}
			// The kernel's IPv4-in-IPv6 form is unmapped first, so the value that
			// is judged, logged and published is the one the decoder accepts.
			address = address.Unmap()
			if !publishableUpstream(address) {
				continue
			}
			// The device that owns the default route is preferred, because it is
			// the one an online machine always has.
			if candidate.Name == preferred {
				return address, candidate.Name, ""
			}
			if !fallback.IsValid() {
				fallback, fallbackDevice = address, candidate.Name
			}
		}
	}
	if !fallback.IsValid() {
		return netip.Addr{}, "", "no interface on this host carries a global-unicast IPv4 address on a non-loopback interface"
	}
	return fallback, fallbackDevice, ""
}

// addressVerdict is what a case may do about the address a published DHCP state
// would have to name.
type addressVerdict int

const (
	// runWithAddress is the only verdict that lets a case proceed.
	runWithAddress addressVerdict = iota
	// skipThisHost is a plain run on a host that cannot be asked.
	skipThisHost
	// failThisHost is a strict run on the same host.
	failThisHost
)

func (v addressVerdict) String() string {
	switch v {
	case runWithAddress:
		return "run"
	case skipThisHost:
		return "skip"
	case failThisHost:
		return "fail"
	default:
		return fmt.Sprintf("unknown verdict %d", int(v))
	}
}

// addressRequirement is the whole decision in one place. A host with an address a
// published state may name runs whatever the environment says; a host without one
// skips on a plain run and fails on a strict one; and nothing else varies.
func addressRequirement(address netip.Addr, strict bool) addressVerdict {
	if publishableUpstream(address) {
		return runWithAddress
	}
	if strict {
		return failThisHost
	}
	return skipThisHost
}

// strictnessVariable is the switch that turns "this host cannot run these cases"
// from a skip into a failure.
//
// It exists because the trade is otherwise invisible. The production DHCP state
// decoder refuses a loopback upstream, so a loopback-only host cannot be given a
// state document naming a domestic resolver, and the only way to make one would
// be a bypass of the validation these cases exist to hold to. Skipping is the
// right answer for a developer on a laptop or in a loopback-only container, and a
// silent skip is the wrong answer for an acceptance gate: it would be green with
// no end-to-end coverage at all. So a CI job sets this and the gate can say "I
// did not run".
const strictnessVariable = "MOSDNS_REQUIRE_INTEGRATION"

// requireIntegration reads the switch out of the environment.
func requireIntegration() bool {
	return requireIntegrationValue(os.Getenv(strictnessVariable))
}

// requireIntegrationValue is requireIntegration's whole decision, given the
// value, so every value can be driven without an environment.
//
// Only an empty value, 0 and false are a "no". Everything else insists, on
// purpose: a value nobody thought about, or a typo in one, must not be the thing
// that quietly turns the gate off. Case is folded and surrounding space is
// dropped, because a variable that reads as a boolean should be read as one and
// FALSE meaning "insist" would be the worst possible surprise.
func requireIntegrationValue(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "0", "false":
		return false
	default:
		return true
	}
}

// unusableAddressMessage is the report a host that cannot be asked receives. It
// has to name what the host lacks, why a loopback address is not a substitute,
// the plan that covers a host without the capability, and the switch that turns
// the failure back into a skip. A report that said only "skipped" is what let
// this gap through in the first place.
func unusableAddressMessage(reason string) string {
	return fmt.Sprintf(
		"this host has no non-loopback IPv4 address a published DHCP state may name, and the end-to-end "+
			"routing cases cannot be asked of it: %s; the production DHCP state decoder refuses a loopback "+
			"upstream, so a loopback domestic resolver is not a substitute and working around that would "+
			"need a bypass of the validation these cases exist to hold to; the netns variant of this suite, "+
			"from the Podman plan, is what covers a host like this; unset %s to skip here instead of failing",
		reason, strictnessVariable,
	)
}

// caseOutcome is the two terminal calls a case can be given, as an interface so
// the failure path is drivable on a host that has an address: a real Fatalf ends
// the test and a real Skipf stops it, so neither branch could otherwise be
// observed.
type caseOutcome interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// A case is the outcome a real case gets, so the double that drives the two
// branches is a stand-in for what a case actually receives rather than a shape
// chosen to suit the test.
var _ caseOutcome = (*testing.T)(nil)

// requireUnicastAddress ends the case the way addressRequirement says, or lets
// it proceed when this host has an address a published state may name.
func requireUnicastAddress(outcome caseOutcome, address netip.Addr, reason string) {
	outcome.Helper()
	switch addressRequirement(address, requireIntegration()) {
	case runWithAddress:
		return
	case skipThisHost:
		outcome.Skipf("%s", unusableAddressMessage(reason))
	case failThisHost:
		outcome.Fatalf("%s", unusableAddressMessage(reason))
	}
}

// localUnicastAddress is the address a case publishes, and it is where a host
// that cannot be asked is reported rather than worked around: a loopback domestic
// resolver is refused by the state decoder, and the only way past that would be a
// bypass of the validation these cases exist to hold to.
func localUnicastAddress(t *testing.T) (netip.Addr, string) {
	t.Helper()
	address, interfaceName, reason := discoverUnicastAddress()
	requireUnicastAddress(t, address, reason)
	return address, interfaceName
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

// writeChinaList writes the China rule list the fixture calls for into the case's
// own directory and returns its path. The committed fixture is the committed
// bytes rather than a hand-written list, because a list that did not load would
// fail the router and a list that loaded but held the wrong names would change what
// the case was about.
func writeChinaList(t *testing.T, directory string, fixture chinaListFixture) string {
	t.Helper()
	path := filepath.Join(directory, "cn-domains.txt")
	var contents []byte
	switch fixture {
	case committedChinaList:
		committed, err := os.ReadFile(filepath.Clean(committedCNList))
		if err != nil {
			t.Fatalf("read the committed %s: %v", committedCNList, err)
		}
		contents = committed
	case noChinaRules:
		// Only a comment, so the file is a list that parses and resolves to
		// nothing rather than a file that is not a list at all -- the difference
		// between "the list has no rules" and "the list would not load".
		contents = []byte("# no rules at all\n")
	default:
		t.Fatalf("unknown China list fixture %d", fixture)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write the China list: %v", err)
	}
	return path
}

// copyChinaList writes the committed list into the case's own directory. A list
// that did not load would fail the router, and an empty one would send every name
// abroad, so the copy is the committed bytes rather than a fixture.
func copyChinaList(t *testing.T, directory string) string {
	t.Helper()
	return writeChinaList(t, directory, committedChinaList)
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

// TestTheReadinessProbeNameIsNotInTheChinaList is the guard the harness relies on
// and states on itself. The poll asks for a name; if the list matched it, that
// query is a domestic one, the domestic resolver's answer counter moves before any
// case asks anything, and every assertion comparing an answer against a numbered
// address is one along -- and would look like a routing defect rather than a list
// that grew a rule.
//
// The control is the other half: a name the list does match has to come back as
// matched, so this is not a case that passes because the matcher is broken.
func TestTheReadinessProbeNameIsNotInTheChinaList(t *testing.T) {
	directory := t.TempDir()
	list := copyChinaList(t, directory)

	if inCommittedChinaList(t, list, readinessName) {
		t.Errorf("the committed China list matches the readiness probe name %s, so the poll's query is a domestic one", readinessName)
	}
	if !inCommittedChinaList(t, list, chinaName) {
		t.Errorf("the committed China list does not match %s, so the classification this harness relies on is not working at all", chinaName)
	}
}

// reserveAttempts is how often a free port is chosen again when the transport
// beside it cannot be bound. A port that is free for UDP can still be taken for
// TCP by a socket that has not finished closing -- the router of the case before
// this one is a plausible owner -- so one refusal is a reason to ask again
// rather than a failure.
const reserveAttempts = 16

// reserveLoopbackAddress returns an address whose port is free on both transports
// right now. The router has to bind it, so the sockets that chose the port are
// given up first; nothing else in this process holds it, and a port that is free
// stays free for the moment between the release and the bind.
func reserveLoopbackAddress(t *testing.T) string {
	t.Helper()
	var refusal error
	for range reserveAttempts {
		address, err := reserveLoopbackAddressOnce()
		if err == nil {
			return address
		}
		refusal = err
	}
	t.Fatalf("no port was free on both transports after %d attempts: %v", reserveAttempts, refusal)
	return ""
}

// reserveLoopbackAddressOnce takes one candidate port, checks that both
// transports accept it, and gives both up again.
func reserveLoopbackAddressOnce() (string, error) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("reserve a udp port for the router to listen on: %w", err)
	}
	address := packetConn.LocalAddr().String()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		_ = packetConn.Close()
		return "", fmt.Errorf("reserve the tcp port beside %s: %w", address, err)
	}
	if err := listener.Close(); err != nil {
		_ = packetConn.Close()
		return "", fmt.Errorf("release the reserved tcp port: %w", err)
	}
	if err := packetConn.Close(); err != nil {
		return "", fmt.Errorf("release the reserved udp port: %w", err)
	}
	return address, nil
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

// TestAnArbitraryQTypeSurvivesTheRouterInPackedForm asks for a record shape
// nothing in this project knows how to build. Type 65 is not a type the router
// interprets: it is a type it has to carry, and a router that rebuilt, filtered or
// dropped an answer it did not recognise would show up here as a SERVFAIL or as a
// record that came back different.
//
// The comparison is packed-form equality of the whole record -- the record that
// came back and the record that was supposed to produce it are each re-packed by
// the same encoder and compared byte for byte. That is not the same as the wire
// bytes being identical, and the name says so: both sides went through a pack, so
// a difference the wire format does not distinguish is invisible here. What it does
// catch is a router that changed the record's own content, which is the claim.
func TestAnArbitraryQTypeSurvivesTheRouterInPackedForm(t *testing.T) {
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
	if got := recordPacked(t, response.Answer[0]); !bytes.Equal(got, recordPacked(t, want)) {
		t.Errorf("the %s answer came back as\n %s\nwant\n %s",
			dns.TypeToString[dns.TypeHTTPS], got, recordPacked(t, want))
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
	if got := recordPacked(t, response.Answer[0]); !bytes.Equal(got, recordPacked(t, want)) {
		t.Errorf("the large TXT came back as\n %s\nwant\n %s", got, recordPacked(t, want))
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
	if got := recordPacked(t, response.Answer[0]); !bytes.Equal(got, recordPacked(t, want)) {
		t.Errorf("the large domestic TXT came back as\n %s\nwant\n %s", got, recordPacked(t, want))
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

// TestAChinaListWithNoRulesSendsEveryNameAbroad covers the one fail-open state
// the China list can be in. The converter refuses to publish an empty list and a
// pin never writes one, so this state is unreachable through this project's own
// writers -- but it is reachable through a wiped or truncated /var/lib, and it does
// not stop the router: domain_set loads a rule-less file without complaint, the
// `qname $cn_domains` condition matches nothing, and the dispatch falls through to
// the foreign branch for every name including the China ones.
//
// The consequences are what this case holds to. A China name reaches the foreign
// resolver, which is the network the user is leaving: the domestic branch stops
// being used without anything saying so, and the operator's China DNS set is
// silently bypassed. The domestic resolver is asked nothing at all, so this is not a
// misroute within the country, it is the whole domestic branch gone. And the router
// says nothing about the list's contents, so an operator reading the log has no
// signal that the list is the reason. That silence is the reason the list is a
// packaging obligation -- provision it, verify its digest, never re-pin it at
// install -- rather than a file the service can be expected to survive without.
func TestAChinaListWithNoRulesSendsEveryNameAbroad(t *testing.T) {
	h := newHarnessWithList(t, publishedState, noChinaRules)
	h.waitUntilAnswering(t)
	before := h.counts()

	// The China name, the one the committed list matches, now goes abroad.
	abroad := h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)
	if got, want := answeredAddresses(t, abroad), []string{foreignAddress}; !equalStrings(got, want) {
		t.Errorf("%s with a rule-less China list = %v, want the foreign resolver's answer %v: with no rule to match, every name takes the foreign branch",
			chinaName, got, want)
	}
	if got := h.foreign.Count("", chinaName); got != 1 {
		t.Errorf("the foreign resolver was asked %d times for %s, want 1", got, chinaName)
	}

	// The domestic resolver saw nothing: not the China name, and nothing else
	// either, so the whole branch is bypassed rather than partly fed.
	if got := h.domestic.Count("", ""); got != 0 {
		t.Errorf("the domestic resolver was asked %d times with a rule-less China list, want 0: the branch is unreachable, not merely unused", got)
	}

	// And the foreign name is unaffected, which is what makes the state hard to
	// notice: a working foreign path is exactly what an operator sees.
	foreign := h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeA)
	if got, want := answeredAddresses(t, foreign), []string{foreignAddress}; !equalStrings(got, want) {
		t.Errorf("%s with a rule-less China list = %v, want %v", foreignName, got, want)
	}
	if after := h.counts().since(before); after.foreign != 2 || after.domestic != 0 {
		t.Errorf("resolvers were asked %+d since this case began, want both names abroad and nothing domestic", after)
	}

	// The silence is part of the claim, and it is a narrow one: what the router
	// must not say is anything about the list's contents. The fragments are the
	// list's own file -- the only way a report could name the thing that is empty
	// -- and phrasings a load of a rule-less file would produce.
	//
	// The control is in the test above: a router started on the same configuration
	// with the committed list logs the same plugin-load lines this one does, so
	// "cn_domains" and "domain_set" appearing here would be ordinary startup and
	// not a report. That is why they are not in this list, and why the list's path
	// is: no line in an ordinary run carries it.
	for _, fragment := range []string{
		h.cnList,
		"cn-domains.txt",
		"no rules",
		"empty list",
		"rule-less",
		"0 rules",
	} {
		// Read the output directly rather than through reported, which waits out a
		// deadline for a fragment it does not find: a silence the case is asserting
		// would otherwise cost five seconds per fragment. The two queries above have
		// already come back, so anything the router had to say about the list it has
		// said by now.
		if strings.Contains(h.router.output.String(), fragment) {
			t.Errorf("the router reported %q about a rule-less China list, so this case is not the silent state it is about:\n%s",
				fragment, h.router.diagnostics())
		}
	}
	// The ordinary startup lines are still there, so the case is not passing
	// because the router logged nothing at all.
	if !h.router.reported(t, "all plugins are loaded") {
		t.Errorf("the router logged no startup of its own, so the silence asserted above is not the router's:\n%s", h.router.diagnostics())
	}
}

// --- whether this host can be asked to run at all ---

// TestStrictnessIsReadFromTheEnvironmentValue covers the one switch that decides
// whether a host without a usable address is a skip or a failure. The values are
// the ones a CI job or a developer would plausibly write, and the rule is that
// anything a person could read as "no" is a no and everything else insists.
//
// The break it catches is the one that matters most for an acceptance gate: a
// value that reads as "off" being treated as "on" would turn an offline laptop
// red, and a value that reads as "on" being treated as "off" would let a loopback
// container pass the gate with nothing having run. Case is folded because a
// variable that reads as a boolean should be read as one, and `FALSE` meaning
// "insist" would be the worst possible surprise.
func TestStrictnessIsReadFromTheEnvironmentValue(t *testing.T) {
	for name, testCase := range map[string]struct {
		value string
		want  bool
	}{
		"unset":              {value: "", want: false},
		"zero":               {value: "0", want: false},
		"zero with a space":  {value: " 0 ", want: false},
		"false":              {value: "false", want: false},
		"false in capitals":  {value: "FALSE", want: false},
		"false mixed case":   {value: "False", want: false},
		"false with a space": {value: " false ", want: false},
		"one":                {value: "1", want: true},
		"one with a space":   {value: " 1 ", want: true},
		"true":               {value: "true", want: true},
		"true in capitals":   {value: "TRUE", want: true},
		"no is not a value":  {value: "no", want: true},
		"off is not a value": {value: "off", want: true},
		"anything else asks": {value: "please", want: true},
		// A value that is only whitespace is unset once trimmed, so it is the
		// same "no" as an unset variable rather than a typo that insists.
		"a blank value is unset": {value: "\t", want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := requireIntegrationValue(testCase.value); got != testCase.want {
				t.Errorf("%s=%q reads as strict=%t, want %t", strictnessVariable, testCase.value, got, testCase.want)
			}
		})
	}
}

// TestTheAddressRequirementDecidesWhetherACaseCanRun is the whole decision in one
// table: a host with a usable address runs whatever the environment says, a host
// without one skips on a plain run and fails on a strict one, and nothing else
// varies. The break is a verdict that ignores the environment, which would make a
// loopback container either red for every developer or green for CI.
func TestTheAddressRequirementDecidesWhetherACaseCanRun(t *testing.T) {
	usable := netip.MustParseAddr("192.168.81.153")
	missing := netip.Addr{}

	for name, testCase := range map[string]struct {
		address netip.Addr
		strict  bool
		want    addressVerdict
	}{
		"a host with an address runs on a plain run":  {address: usable, strict: false, want: runWithAddress},
		"a host with an address runs on a strict run": {address: usable, strict: true, want: runWithAddress},
		"a host without one skips on a plain run":     {address: missing, strict: false, want: skipThisHost},
		"a host without one fails on a strict run":    {address: missing, strict: true, want: failThisHost},
		"the unspecified address is no address":       {address: netip.AddrFrom4([4]byte{0, 0, 0, 0}), strict: false, want: skipThisHost},
		"a host with a zone is not a publishable address": {
			address: netip.MustParseAddr("fe80::1%ens33"), strict: false, want: skipThisHost,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := addressRequirement(testCase.address, testCase.strict); got != testCase.want {
				t.Errorf("address %q on a strict=%t run = %v, want %v", testCase.address, testCase.strict, got, testCase.want)
			}
		})
	}
}

// TestAnUnusableAddressIsSkippedOrFailedAsTheEnvironmentSays is the reporter
// itself, which is where "fails rather than skips" actually lives: a verdict that
// is never consulted, or a reporter that always skips, would leave every table
// above green while the gate stayed dishonest.
//
// The two terminal calls are recorded rather than made, because a real Fatalf
// ends the test and a real Skipf stops it: there is no way to observe both
// branches of one test otherwise. What is asserted is which of the two was
// called and that exactly one was.
func TestAnUnusableAddressIsSkippedOrFailedAsTheEnvironmentSays(t *testing.T) {
	reason := "no interface carried a global-unicast IPv4"
	for name, testCase := range map[string]struct {
		// value is written into the real environment, so the reporter under test
		// reads the switch the way a case reads it rather than through a seam
		// only this test knows about.
		value    string
		wantCall string
	}{
		"a plain run skips":  {value: "", wantCall: "skip"},
		"a strict run fails": {value: "1", wantCall: "fail"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(strictnessVariable, testCase.value)
			recorded := &recordedOutcome{}
			requireUnicastAddress(recorded, netip.Addr{}, reason)

			if recorded.calls != 1 {
				t.Fatalf("a host with no address was told %d times what to do, want exactly 1", recorded.calls)
			}
			if recorded.last != testCase.wantCall {
				t.Errorf("a host with no address was told to %s, want it told to %s", recorded.last, testCase.wantCall)
			}
			if recorded.message == "" {
				t.Error("the report carried no message, so a reader would not know what was missing")
			}
		})
	}
}

// TestAUsableAddressIsNeverReportedAtAll is the control for the case above: a
// reporter that reported something for a host that has an address would stop
// every case in this suite on a machine that can run them.
func TestAUsableAddressIsNeverReportedAtAll(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Setenv(strictnessVariable, strictnessValue(strict))
		recorded := &recordedOutcome{}
		requireUnicastAddress(recorded, netip.MustParseAddr("192.168.81.153"), "unused")
		if recorded.calls != 0 {
			t.Errorf("a host with an address was told %d times what to do on a strict=%t run, want 0", recorded.calls, strict)
		}
	}
}

// TestAnUnusableAddressMessageNamesWhatIsMissingAndWhoCoversIt pins the text of
// the report, because a report that only says "skipped" is what let the original
// gap through. It has to name the capability the host lacks, why a loopback
// address is not a substitute, the plan that covers a host without the
// capability, and the switch that turns the failure back into a skip.
func TestAnUnusableAddressMessageNamesWhatIsMissingAndWhoCoversIt(t *testing.T) {
	message := unusableAddressMessage("no interface carried a global-unicast IPv4")

	for name, wantMention := range map[string]string{
		"the missing capability":     "non-loopback",
		"why loopback will not do":   "refuses a loopback upstream",
		"the reason it happened":     "no interface carried a global-unicast IPv4",
		"the plan that covers it":    "netns",
		"the switch that relaxes it": strictnessVariable,
	} {
		if !strings.Contains(message, wantMention) {
			t.Errorf("the report does not mention %s (%q):\n%s", name, wantMention, message)
		}
	}
}

// TestAStrictRunStillExercisesTheCasesOnAHostThatHasAnAddress is the end-to-end
// half: the switch must not cost a host that can run anything, so this asks for
// the environment to insist and then drives a real router through a real China
// name and a real foreign one.
//
// It skips, rather than fails, on a host with no usable address, and says which
// host that is. The strict behaviour there is the reporter's, and the table above
// covers it; a test that ran a case here on such a host would be reporting a
// property of the machine rather than of the code.
func TestAStrictRunStillExercisesTheCasesOnAHostThatHasAnAddress(t *testing.T) {
	address, interfaceName, reason := discoverUnicastAddress()
	if !address.IsValid() {
		t.Skipf("this host has no address a published DHCP state may name (%s), so a strict end-to-end run cannot be asked of it here; the netns variant of this suite covers such a host", reason)
	}
	t.Logf("the strict run will use %s (%s)", address, interfaceName)

	t.Setenv(strictnessVariable, "1")
	if !requireIntegration() {
		t.Fatalf("%s=1 does not read as strict, so the switch this case is about is not wired to the environment", strictnessVariable)
	}

	h := newHarness(t, publishedState)
	h.waitUntilAnswering(t)

	if got, want := answeredAddresses(t, h.ask(t, testdns.ProtocolTCP, chinaName, dns.TypeA)), []string{"198.51.100.1"}; !equalStrings(got, want) {
		t.Errorf("%s on a strict run = %v, want the domestic resolver's first answer %v", chinaName, got, want)
	}
	if got, want := answeredAddresses(t, h.ask(t, testdns.ProtocolTCP, foreignName, dns.TypeA)), []string{foreignAddress}; !equalStrings(got, want) {
		t.Errorf("%s on a strict run = %v, want the foreign resolver's answer %v", foreignName, got, want)
	}
}

// strictnessValue is the environment text that means what a bool means here.
func strictnessValue(strict bool) string {
	if strict {
		return "1"
	}
	return "0"
}

// recordedOutcome is the double the reporter test drives. It answers both
// questions -- which terminal call was made, and with what -- without making
// either, because a real Skipf or Fatalf would end the test that is asking.
type recordedOutcome struct {
	calls   int
	last    string
	message string
}

func (o *recordedOutcome) Helper() {}

func (o *recordedOutcome) Skipf(format string, args ...any) {
	o.calls++
	o.last = "skip"
	o.message = fmt.Sprintf(format, args...)
}

func (o *recordedOutcome) Fatalf(format string, args ...any) {
	o.calls++
	o.last = "fail"
	o.message = fmt.Sprintf(format, args...)
}
