package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/miekg/dns"

	"mosdns-router/internal/config"
)

// One line per ENABLED entry, in policy order, whether it answered or not -- so a
// report that names four entries and describes two is visibly incomplete rather
// than quietly shorter.
func TestTheReportNamesEveryEnabledEntryInPolicyOrder(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{
		"tcp://127.0.0.1:15353":    {rcode: "NOERROR"},
		"quic://dns.quad9.net:853": {rcode: "NOERROR"},
	})
	var stdout, stderr bytes.Buffer
	code := runCheckUpstream([]string{"--all"}, &stdout, &stderr, services)

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("the report has %d lines, want one per enabled entry:\n%s", len(lines), stdout.String())
	}
	if !strings.HasPrefix(lines[0], "quad9-dnscrypt:") || !strings.HasPrefix(lines[1], "quad9-doq:") {
		t.Fatalf("the report is not in policy order:\n%s", stdout.String())
	}
	if !strings.Contains(lines[0], "tcp://127.0.0.1:15353") {
		t.Fatalf("the dnscrypt line does not name the address it checked:\n%s", lines[0])
	}
	if code != exitSuccess {
		t.Fatalf("exit %d with every entry reachable, want 0\n%s", code, stderr.String())
	}
}

// The exit code is about REACHABILITY, so an operator scripting it can tell
// "everything is up" from "something is down" without parsing the report.
func TestAnUnreachableEntryIsNamedAndChangesTheExitCode(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{
		"tcp://127.0.0.1:15353":    {rcode: "NOERROR"},
		"quic://dns.quad9.net:853": {err: errors.New("dial udp: connection refused")},
	})
	var stdout, stderr bytes.Buffer
	code := runCheckUpstream([]string{"--all"}, &stdout, &stderr, services)

	if code != exitStateUnavailable {
		t.Fatalf("exit %d with one entry unreachable, want %d", code, exitStateUnavailable)
	}
	if !strings.Contains(stdout.String(), "quad9-doq") {
		t.Fatalf("the failing entry is not named:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "connection refused") {
		t.Fatalf("the failure reason is not carried:\n%s", stdout.String())
	}
	// And the reachable one is still reported: a report that stops at the first
	// failure tells the operator nothing about the rest.
	if !strings.Contains(stdout.String(), "quad9-dnscrypt") {
		t.Fatalf("the reachable entry is missing from a report that hit a failure:\n%s", stdout.String())
	}
}

// A DISABLED entry is not checked, because "is this reachable" for something the
// router does not use is a question with no consequence.
func TestADisabledEntryIsNotChecked(t *testing.T) {
	policy := config.Defaults()
	off := false
	policy.Foreign.Upstreams = append(policy.Foreign.Upstreams, config.ForeignUpstream{
		Kind: config.UpstreamKindUpstream, Name: "spare", Addr: "tls://1.1.1.1:853", Enabled: &off,
	})
	services := checkServices(t, map[string]checkAnswer{})
	services.loadPolicy = func(string) (config.Policy, error) { return policy, nil }
	var built []string
	services.newUpstream = func(addr string, _ upstream.Opt) (upstream.Upstream, error) {
		built = append(built, addr)
		return &checkFake{rcode: "NOERROR"}, nil
	}
	var stdout, stderr bytes.Buffer
	runCheckUpstream([]string{"--all"}, &stdout, &stderr, services)
	for _, addr := range built {
		if strings.Contains(addr, "1.1.1.1") {
			t.Fatalf("a disabled entry was dialled (%v)", built)
		}
	}
}

// One unresolvable name must produce ONE named failure, not a whole-run failure and
// not a whole-run success. A domain upstream whose bootstrap is wrong cannot be
// dialled at all, and that shows up here and nowhere else.
func TestOneUnresolvableNameFailsOnlyItsOwnEntry(t *testing.T) {
	policy := config.Defaults()
	policy.Foreign.Upstreams = []config.ForeignUpstream{
		{Kind: config.UpstreamKindDNSCrypt, Name: "packaged"},
		{Kind: config.UpstreamKindUpstream, Name: "doq", Addr: "quic://dns.quad9.net:853"},
	}
	services := checkServices(t, map[string]checkAnswer{})
	services.loadPolicy = func(string) (config.Policy, error) { return policy, nil }
	services.newUpstream = func(addr string, _ upstream.Opt) (upstream.Upstream, error) {
		if strings.Contains(addr, "dns.quad9.net") {
			return nil, errors.New("bootstrap: no resolver answered for dns.quad9.net")
		}
		return &checkFake{rcode: "NOERROR"}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runCheckUpstream([]string{"--all"}, &stdout, &stderr, services)
	if code != exitStateUnavailable {
		t.Fatalf("exit %d, want non-zero: an entry that cannot be dialled is not reachable", code)
	}
	if !strings.Contains(stdout.String(), "doq") || !strings.Contains(stdout.String(), "packaged") {
		t.Fatalf("both entries should be reported:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "bootstrap") {
		t.Fatalf("the reason is not carried, so an operator cannot tell a bad bootstrap "+
			"from a dead network:\n%s", stdout.String())
	}
}

// The probe name is IANA's, and that is a decision this test holds: it is the name
// that must resolve everywhere, so a failure is the transport and not a provider's
// filtering policy.
func TestTheProbeNameIsTheOneReservedForThis(t *testing.T) {
	if checkUpstreamProbeName != "example.com" {
		t.Fatalf("the probe name is %q; it must be a name every resolver answers, so that a "+
			"failure is the transport rather than one provider's filtering", checkUpstreamProbeName)
	}
}

func TestNamingOneEntryChecksOnlyThatOne(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{
		"tcp://127.0.0.1:15353": {rcode: "NOERROR"},
	})
	var stdout, stderr bytes.Buffer
	code := runCheckUpstream([]string{"quad9-dnscrypt"}, &stdout, &stderr, services)
	if code != exitSuccess {
		t.Fatalf("exit %d checking one reachable entry: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "quad9-doq") {
		t.Fatalf("naming one entry checked another:\n%s", stdout.String())
	}
}

func TestNamingAnEntryThatIsNotThereIsAUsageError(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{})
	var stdout, stderr bytes.Buffer
	if code := runCheckUpstream([]string{"nope"}, &stdout, &stderr, services); code != exitInvalidCLI {
		t.Fatalf("exit %d naming an entry that does not exist, want %d", code, exitInvalidCLI)
	}
	if !strings.Contains(stderr.String(), "nope") {
		t.Fatalf("the refusal does not name what was asked for: %s", stderr.String())
	}
	// And it names what IS there, so the operator is not left guessing the right
	// spelling and running the command again to find it.
	for _, name := range []string{"quad9-dnscrypt", "quad9-doq"} {
		if !strings.Contains(stderr.String(), name) {
			t.Errorf("the refusal does not list the enabled entries, so %q is not in it:\n%s",
				name, stderr.String())
		}
	}
}

// --all and a name are two different questions, and answering both at once is a
// usage error rather than a silent preference for one.
func TestAskingForEverythingAndNamingOneIsAUsageError(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{})
	var stdout, stderr bytes.Buffer
	if code := runCheckUpstream([]string{"--all", "quad9-doq"}, &stdout, &stderr, services); code != exitInvalidCLI {
		t.Fatalf("exit %d, want %d", code, exitInvalidCLI)
	}
}

// Asking for nothing is a usage error too: an operator who runs the command with no
// arguments wants to know something, and printing an empty successful report is the
// one answer that tells them nothing.
func TestAskingForNothingIsAUsageError(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{})
	var stdout, stderr bytes.Buffer
	if code := runCheckUpstream(nil, &stdout, &stderr, services); code != exitInvalidCLI {
		t.Fatalf("exit %d, want %d", code, exitInvalidCLI)
	}
	if stdout.Len() != 0 {
		t.Fatalf("a usage error wrote a report anyway:\n%s", stdout.String())
	}
}

// A reachable resolver that REFUSES is not an unreachable one, and the two need
// different operator answers: one needs a route, the other needs a policy.
func TestARefusingResolverIsReportedAsRefusingNotAsUnreachable(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{
		"tcp://127.0.0.1:15353": {rcode: "REFUSED"},
	})
	var stdout, stderr bytes.Buffer
	runCheckUpstream([]string{"--all"}, &stdout, &stderr, services)
	line := strings.TrimSpace(stdout.String())
	if !strings.Contains(line, "REFUSED") {
		t.Fatalf("the line does not carry the rcode the resolver answered with:\n%s", line)
	}
	if !strings.Contains(line, "answered") {
		t.Fatalf("a resolver that ANSWERED is reported as if it were unreachable, and the "+
			"two need different operator answers:\n%s", line)
	}
}

// The dnscrypt entry is checked over TCP against the packaged listener, which is the
// same road the ECH key is fetched through -- so this line also answers "can this
// machine still fetch an ECH key", which is the question that matters when a
// force-ECH name stops working.
func TestThePackagedEntryIsCheckedOverTheAddressTheECHKeyUses(t *testing.T) {
	services := checkServices(t, map[string]checkAnswer{
		"tcp://127.0.0.1:15353": {rcode: "NOERROR"},
	})
	var dialled []string
	inner := services.newUpstream
	services.newUpstream = func(addr string, opt upstream.Opt) (upstream.Upstream, error) {
		dialled = append(dialled, addr)
		return inner(addr, opt)
	}
	var stdout, stderr bytes.Buffer
	runCheckUpstream([]string{"quad9-dnscrypt"}, &stdout, &stderr, services)
	if len(dialled) != 1 || !strings.HasPrefix(dialled[0], "tcp://") {
		t.Fatalf("the packaged entry was dialled at %v; it has no addr of its own, so the "+
			"listener is the only thing it can be, and it is the ECH fetch's road", dialled)
	}
}

type checkAnswer struct {
	rcode string
	err   error
}

// checkFake is an upstream that answers what the fixture said, and records the
// questions it was asked so a case can assert the probe's TYPE as well as its name.
type checkFake struct {
	mu     sync.Mutex
	rcode  string
	err    error
	asked  []dns.Question
	closed bool
}

func (f *checkFake) ExchangeContext(_ context.Context, payload []byte) (*[]byte, error) {
	var query dns.Msg
	if err := query.Unpack(payload); err != nil {
		return nil, err
	}
	if len(query.Question) == 0 {
		return nil, errors.New("a query with no question")
	}
	f.mu.Lock()
	f.asked = append(f.asked, query.Question[0])
	failure := f.err
	f.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	response := new(dns.Msg)
	response.SetReply(&query)
	response.Rcode = dns.StringToRcode[f.rcode]
	// pool.PackBuffer (pkg/pool/msg_buf.go:37) is mosdns's OWN get-a-buffer, pack,
	// copy-into-a-right-sized-buffer helper, and the interface hands back a pooled
	// *[]byte. Writing that sequence by hand in a fixture is four lines of buffer
	// lifetime to get wrong for no reason.
	return pool.PackBuffer(response)
}

func (f *checkFake) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func checkServices(t *testing.T, answers map[string]checkAnswer) services {
	t.Helper()
	return services{
		loadPolicy: func(string) (config.Policy, error) { return config.Defaults(), nil },
		documents:  productionDocumentPaths(),
		now:        func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) },
		newUpstream: func(addr string, _ upstream.Opt) (upstream.Upstream, error) {
			answer, ok := answers[addr]
			if !ok {
				return nil, fmt.Errorf("%s was dialled and the fixture has no answer for it", addr)
			}
			if answer.err != nil {
				return nil, answer.err
			}
			return &checkFake{rcode: answer.rcode}, nil
		},
	}
}
