package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/measure"
	"mosdns-router/internal/optimizer"
	"mosdns-router/internal/prober"
	"mosdns-router/internal/state"
)

const (
	// testSHA256 is the lowercase hex SHA-256 digest of "test", the shape state
	// validation requires for a recorded config or ECHConfig digest.
	testSHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

const validPolicyYAML = `schema_version: 1
schedule: "03:00"
foreign:
  default_provider: Quad9 Secure DNSCrypt v2
  ecs: false
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
  stale_grace: 900
  sources:
    - cloudflare-ech.com
dhcp:
  failure_policy: disable-current
cache:
  persistent_dump: false
`

func TestRunValidateSucceedsWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(validPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	// The document directory is named explicitly, so the case says what it is
	// about -- validate writes nothing -- rather than also depending on whether
	// this host has a /etc/mosdns to report a stale document from.
	documents := filepath.Join(dir, "documents")
	if err := os.Mkdir(documents, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := os.ReadDir(documents)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"validate", "--policy", policyPath, "--documents", documents}, &stdout, &stderr); got != exitSuccess {
		t.Fatalf("validate exit = %d, want %d (stderr: %s)", got, exitSuccess, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("successful validate wrote output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	after, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	afterEntries, err := os.ReadDir(documents)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("validate changed policy contents: got %q, want %q", after, before)
	}
	if !reflect.DeepEqual(entryNames(beforeEntries), entryNames(afterEntries)) {
		t.Fatalf("validate changed the document directory: got %v, want %v", entryNames(afterEntries), entryNames(beforeEntries))
	}
}

func TestRunValidateRejectsInvalidPolicyWithConfigExit(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	invalid := strings.Replace(validPolicyYAML, "failure_policy: strict", "failure_policy: permissive", 1)
	if err := os.WriteFile(policyPath, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"validate", "--policy", policyPath}, &stdout, &stderr); got != exitInvalidCLI {
		t.Fatalf("invalid policy exit = %d, want %d", got, exitInvalidCLI)
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid policy wrote stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), policyPath) || !strings.Contains(stderr.String(), "failure_policy") {
		t.Fatalf("invalid policy error lacks useful context: %q", stderr.String())
	}
}

func TestRunStatusRendersOnlyExplicitlySuppliedState(t *testing.T) {
	dir := t.TempDir()
	selectorPath := filepath.Join(dir, "selector.json")
	writeSelectorFixture(t, selectorPath, state.Selector{
		SchemaVersion: 1,
		Generation:    2,
		Mode:          "auto",
		Provider:      "cloudflare",
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"status", "--selector", selectorPath}, &stdout, &stderr); got != exitSuccess {
		t.Fatalf("status exit = %d, want %d (stderr: %s)", got, exitSuccess, stderr.String())
	}

	want := "selector.generation=2\nselector.mode=auto\nselector.provider=cloudflare\nselector.schema_version=1\n"
	if got := stdout.String(); got != want {
		t.Fatalf("status output = %q, want %q", got, want)
	}
	if strings.Contains(stdout.String(), "dhcp.") || strings.Contains(stdout.String(), "ech.") {
		t.Fatalf("status rendered an unsupplied state: %q", stdout.String())
	}
}

func TestRunStatusOrderIsIndependentOfOptionOrder(t *testing.T) {
	dir := t.TempDir()
	selectorPath := filepath.Join(dir, "selector.json")
	dhcpPath := filepath.Join(dir, "dhcp.json")
	echPath := filepath.Join(dir, "ech.json")
	writeSelectorFixture(t, selectorPath, state.Selector{SchemaVersion: 1, Generation: 2, Mode: "manual", Provider: "cloudflare", WinnerIP: "192.0.2.10", LastSuccess: time.Date(2026, time.September, 25, 19, 0, 0, 0, time.UTC)})
	writeDHCPFixture(t, dhcpPath, state.DHCPState{SchemaVersion: 1, Generation: 3, Interface: "enp3s0", ConnectionUUID: "uuid", Upstreams: []string{"192.0.2.53"}, ObservedAt: time.Date(2026, time.September, 25, 18, 0, 0, 0, time.UTC), Source: "dhcp4", LastGood: true})
	writeECHFixture(t, echPath, state.ECHState{SchemaVersion: 1, Generation: 4, Source: "cloudflare-ech.com", FetchedAt: time.Date(2026, time.September, 25, 19, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, time.September, 25, 20, 0, 0, 0, time.UTC), StaleUntil: time.Date(2026, time.September, 25, 21, 0, 0, 0, time.UTC), ConfigSHA256: testSHA256, PublicName: "public.example", Status: "fresh"})

	var firstOut, firstErr, secondOut, secondErr bytes.Buffer
	first := run([]string{"status", "--ech", echPath, "--selector", selectorPath, "--dhcp", dhcpPath}, &firstOut, &firstErr)
	second := run([]string{"status", "--dhcp", dhcpPath, "--ech", echPath, "--selector", selectorPath}, &secondOut, &secondErr)
	if first != exitSuccess || second != exitSuccess {
		t.Fatalf("status exits = %d/%d, stderr = %q / %q", first, second, firstErr.String(), secondErr.String())
	}
	if firstOut.String() != secondOut.String() {
		t.Fatalf("option order changed status output:\nfirst:  %q\nsecond: %q", firstOut.String(), secondOut.String())
	}

	want := "selector.generation=2\nselector.last_success=2026-09-25T19:00:00Z\nselector.mode=manual\nselector.provider=cloudflare\nselector.schema_version=1\nselector.winner_ip=192.0.2.10\n" +
		"dhcp.connection_uuid=uuid\ndhcp.generation=3\ndhcp.interface=enp3s0\ndhcp.last_good=true\ndhcp.observed_at=2026-09-25T18:00:00Z\ndhcp.schema_version=1\ndhcp.source=dhcp4\ndhcp.upstreams=192.0.2.53\n" +
		"ech.config_sha256=" + testSHA256 + "\n" +
		"ech.expires_at=2026-09-25T20:00:00Z\n" +
		"ech.fetched_at=2026-09-25T19:00:00Z\n" +
		"ech.generation=4\n" +
		"ech.public_name=public.example\n" +
		"ech.schema_version=1\n" +
		"ech.source=cloudflare-ech.com\n" +
		"ech.stale_until=2026-09-25T21:00:00Z\n" +
		"ech.status=fresh\n"
	if got := firstOut.String(); got != want {
		t.Fatalf("combined status output:\n got: %q\nwant: %q", got, want)
	}
}

func TestRunStatusReturnsStateExitForMissingState(t *testing.T) {
	dir := t.TempDir()
	selectorPath := filepath.Join(dir, "selector.json")
	missingPath := filepath.Join(dir, "missing.json")
	writeSelectorFixture(t, selectorPath, state.Selector{SchemaVersion: 1, Generation: 1, Mode: "disabled", Provider: "cloudflare"})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"status", "--selector", selectorPath, "--dhcp", missingPath}, &stdout, &stderr); got != exitStateUnavailable {
		t.Fatalf("missing state exit = %d, want %d", got, exitStateUnavailable)
	}
	if stdout.Len() != 0 {
		t.Fatalf("missing state emitted partial stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), missingPath) {
		t.Fatalf("missing state error lacks path: %q", stderr.String())
	}
}

func TestRunStatusRejectsFutureStateFieldWithoutLeakingItsValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selector.json")
	const futureSecret = "future-private-value-must-not-leak"
	data := `{"schema_version":1,"generation":1,"mode":"auto","provider":"cloudflare","future_private":"` + futureSecret + `"}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{"status", "--selector", path}, &stdout, &stderr); got != exitStateUnavailable {
		t.Fatalf("future field exit = %d, want %d", got, exitStateUnavailable)
	}
	if stdout.Len() != 0 {
		t.Fatalf("future field emitted status output: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), futureSecret) || strings.Contains(stderr.String(), "future_private") {
		t.Fatalf("future field leaked through stderr: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), path) {
		t.Fatalf("future field error lacks path: %q", stderr.String())
	}
}

func TestRunRejectsInvalidCLIWithExitTwo(t *testing.T) {
	// Every row here is refused during ARGUMENT PARSING, and that is a requirement
	// rather than a convenience: a row that got past the parser would read the
	// policy and the document directory this command defaults to, which are the
	// installed ones under /etc, so its verdict would depend on whether the host
	// has the package installed -- and run as root it would publish over the
	// installed configuration. `render` with no arguments at all is therefore absent
	// from this list because it is VALID, not because it is untested: the two flags
	// default to the installed layout on purpose, TestRenderDefaultsAreTheInstalledPaths
	// holds those defaults, and TestRenderPublishesTheReviewedDocumentPair is
	// deliberately the no-argument invocation so the coverage cannot be lost by
	// somebody tidying the call into an explicit one.
	tests := [][]string{
		nil,
		{"unknown"},
		{"validate"},
		{"validate", "--policy"},
		{"validate", "--documents"},
		{"validate", "--policy", "policy.yaml", "--documents", ""},
		{"render", "--out"},
		{"render", "--policy"},
		{"render", "--out", ""},
		{"render", "--policy", ""},
		{"render", "--policy", "policy.yaml", "extra"},
		{"render", "--force", "documents"},
		{"status"},
		{"status", "--unknown", "value"},
		{"status", "--selector", ""},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != exitInvalidCLI {
				t.Fatalf("args %v exit = %d, want %d", args, got, exitInvalidCLI)
			}
			if stdout.Len() != 0 {
				t.Fatalf("args %v wrote stdout: %q", args, stdout.String())
			}
			if stderr.Len() == 0 {
				t.Fatalf("args %v wrote no diagnostic", args)
			}
		})
	}
}

func TestExitCodeContract(t *testing.T) {
	if exitSuccess != 0 || exitInvalidCLI != 2 || exitStateUnavailable != 3 || exitLockHeld != 4 {
		t.Fatalf("unexpected exit code contract: success=%d invalid=%d state=%d lock=%d", exitSuccess, exitInvalidCLI, exitStateUnavailable, exitLockHeld)
	}
}

func writeSelectorFixture(t *testing.T, path string, value state.Selector) {
	t.Helper()
	writeJSONFixture(t, path, value)
}

func writeDHCPFixture(t *testing.T, path string, value state.DHCPState) {
	t.Helper()
	writeJSONFixture(t, path, value)
}

func writeECHFixture(t *testing.T, path string, value state.ECHState) {
	t.Helper()
	writeJSONFixture(t, path, value)
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// ---------------------------------------------------------------------------
// test, apply, pin and unpin
// ---------------------------------------------------------------------------

// stubProber answers every probe from a table so a command can be exercised
// without a socket. It is deliberately minimal: what is under test here is the
// command boundary, not the prober, and the prober has its own suite.
//
// It satisfies the optimizer's Prober, which is the interface a runner measures
// through and therefore the one a command's prober has to be - the mirror of
// countingProber below, which stands in for the prober package's own narrower
// interface on the far side of the adapter.
type stubProber struct {
	mutex sync.Mutex
	// httpsCalls counts the identity proofs, which is how a case tells a run's
	// proof of every candidate from the second proof an apply runs on the winner.
	httpsCalls int
	// identityErr refuses every identity proof, as an address that is not serving
	// any of the hostnames does.
	identityErr error
	// identityRefusedFor refuses the identity proof for named hostnames and answers
	// the rest, which is the shape a real refusal has: a Cloudflare anycast address
	// serves the provider's domains and cannot present a chain for a CloudFront one.
	identityRefusedFor map[string]error
	// identityRefusedForAddress refuses the identity proof for named addresses and
	// answers the rest, which is the shape one dead address has: it stops serving its
	// hostnames while the anycast address beside it keeps serving the same ones.
	identityRefusedForAddress map[string]error
	// finalProofRefused refuses the second and later identity proofs of the named
	// addresses and answers the first, which is the shape of a host that served the
	// run and then stopped serving: the run finds a winner and the apply's final
	// proof does not confirm it. The keys are addresses because that is what the
	// apply re-proves - the run's winner - and not the whole profile set.
	finalProofRefused map[string]error
	// httpsByAddress counts the identity proofs of each address, which is what
	// finalProofRefused is counted against.
	httpsByAddress map[string]int
	// transferred is what each transfer delivers.
	transferred int64
}

func (p *stubProber) TCP(context.Context, netip.Addr, uint16, int) (prober.TCPMetrics, error) {
	return prober.TCPMetrics{Samples: 10, P50MS: 10, P95MS: 20, JitterMS: 1, Loss: 0}, nil
}

func (p *stubProber) HTTPS(_ context.Context, subject candidate.Candidate, profile candidate.ProbeProfile) (prober.HTTPMetrics, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.httpsCalls++
	address := subject.IP.String()
	if p.httpsByAddress == nil {
		p.httpsByAddress = make(map[string]int)
	}
	p.httpsByAddress[address]++
	if refused, is := p.finalProofRefused[address]; is && p.httpsByAddress[address] > 1 {
		return prober.HTTPMetrics{BodyBytes: 512}, refused
	}
	if refused, is := p.identityRefusedForAddress[address]; is {
		return prober.HTTPMetrics{BodyBytes: 512}, refused
	}
	if refused, is := p.identityRefusedFor[profile.Hostname]; is {
		return prober.HTTPMetrics{BodyBytes: 512}, refused
	}
	if p.identityErr != nil {
		return prober.HTTPMetrics{BodyBytes: 512}, p.identityErr
	}
	return prober.HTTPMetrics{Status: 200, BodyBytes: 512, Colocation: "TEST"}, nil
}

func (p *stubProber) Download(_ context.Context, _ candidate.Candidate, _ candidate.ProbeProfile, maxBytes int64, _ time.Duration, budget optimizer.ByteBudget) (measure.DownloadMetrics, error) {
	reserved, err := budget.Reserve(maxBytes)
	if err != nil {
		return measure.DownloadMetrics{}, err
	}
	elapsed := 500 * time.Millisecond
	budget.Consume(reserved, p.transferred)
	return measure.DownloadMetrics{
		Bytes:          p.transferred,
		Elapsed:        elapsed,
		BytesPerSecond: float64(p.transferred) / elapsed.Seconds(),
	}, nil
}

// newStubProber is a stub that transfers 1 MiB per candidate, so a case that reads
// the budget document has a number to read.
func newStubProber() *stubProber {
	return &stubProber{transferred: 1 << 20, httpsByAddress: make(map[string]int)}
}

func (p *stubProber) proofs() int {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.httpsCalls
}

// fixedMoment is the clock every case runs at, so a report's date and the age an
// apply measures are literals.
var fixedMoment = time.Date(2026, 9, 26, 3, 0, 0, 0, time.UTC)

// selectorProfileYAML is the operator's CloudFront profile document: one hostname
// and no address of its own, so it names a hostname to be proved without adding a
// candidate. Its hostname is deliberately not the representative domain's, though
// the two kinds of profile are never used for the same subject, so a collision
// would be harmless: keeping them distinguishable by name is what lets any case
// assert which kind of profile a proof was made against by reading the name alone.
const selectorProfileYAML = `schema_version: 1
profiles:
  - hostname: assets.example.test
    url: https://assets.example.test/
    method: GET
    port: 443
    expected_status:
      - 200
`

// cdnFixture is one command's world: a policy, a selector at a known generation, a
// profile document, and the paths the command is pointed at. Everything is inside
// a temporary directory, so no case here can reach /var/lib or /etc.
type cdnFixture struct {
	directory    string
	policyPath   string
	selectorPath string
	budgetPath   string
	healthPath   string
	lockPath     string
	profilesPath string
	identities   string
	reportPath   string
}

func newCDNFixture(t *testing.T, generation uint64, winner string) *cdnFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := &cdnFixture{
		directory:    directory,
		policyPath:   filepath.Join(directory, "policy.yaml"),
		selectorPath: filepath.Join(directory, "cdn-selector.json"),
		budgetPath:   filepath.Join(directory, "bandwidth-budget.json"),
		healthPath:   filepath.Join(directory, "health.json"),
		lockPath:     filepath.Join(directory, "control.lock"),
		profilesPath: filepath.Join(directory, "cloudfront-domains.yaml"),
		identities:   filepath.Join(directory, "force-ech-domains.txt"),
		reportPath:   filepath.Join(directory, "report.json"),
	}
	if err := os.WriteFile(fixture.policyPath, []byte(validPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.profilesPath, []byte(selectorProfileYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.identities, []byte("# a comment is not a hostname\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if winner != "" {
		selector := state.Selector{
			SchemaVersion: state.SchemaVersion,
			Generation:    generation,
			Mode:          "auto",
			Provider:      "cloudflare",
			WinnerIP:      winner,
			LastSuccess:   fixedMoment.Add(-time.Hour),
		}
		if err := state.WriteJSONAtomic(fixture.selectorPath, selector); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

// flags is the command line every case shares, so a case that changes one thing
// says so by leaving the rest out of its own argument list.
func (f *cdnFixture) flags() []string {
	return []string{
		"--policy", f.policyPath,
		"--selector", f.selectorPath,
		"--budget", f.budgetPath,
		"--control-lock", f.lockPath,
		"--profiles", f.profilesPath,
		"--identity-domains", f.identities,
		"--candidates", f.candidatesPath(),
		"--health", f.healthPath,
	}
}

func (f *cdnFixture) candidatesPath() string { return filepath.Join(f.directory, "cloudflare.txt") }

func (f *cdnFixture) writeCandidates(t *testing.T, addresses ...string) {
	t.Helper()
	if err := os.WriteFile(f.candidatesPath(), []byte(strings.Join(addresses, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// servicesFor is a services value whose prober, official range source and clock are
// the case's own. Everything else stays the real implementation, so the lock, the
// publication and the conversion are exercised rather than replaced.
func servicesFor(prober optimizer.Prober, set candidate.CandidateSet, moment time.Time) services {
	return services{
		newHTTPClient: func() *http.Client { return &http.Client{Timeout: time.Second} },
		acquireLock: func(path string) (func() error, error) {
			lock, err := filelock.Acquire(path)
			if err != nil {
				return nil, err
			}
			return lock.Close, nil
		},
		documents:   productionDocumentPaths(),
		documentOps: defaultDocumentOps(),
		newProber:   func() optimizer.Prober { return prober },
		readCandidates: func(context.Context, candidateSource) (candidate.CandidateSet, error) {
			return set, nil
		},
		now:          func() time.Time { return moment },
		effectiveUID: productionServices().effectiveUID,
		runInstaller: productionServices().runInstaller,
	}
}

// threeCloudflareCandidates is the official range source's answer, as three global
// addresses with the two slowest ones slower than the fastest.
func threeCloudflareCandidates() candidate.CandidateSet {
	return candidate.CandidateSet{Candidates: []candidate.Candidate{
		{Provider: candidate.ProviderCloudflare, IP: netip.MustParseAddr("104.16.0.1"), Source: candidate.SourceCloudflare},
		{Provider: candidate.ProviderCloudflare, IP: netip.MustParseAddr("104.16.1.1"), Source: candidate.SourceCloudflare},
		{Provider: candidate.ProviderCloudflare, IP: netip.MustParseAddr("104.16.2.1"), Source: candidate.SourceCloudflare},
	}}
}

// A run that names only what it spent cannot answer the question an operator has
// before spending it: the day is 100 MiB, a full shortlist of ten candidates at
// 10 MiB each is exactly that, and a report-only run spends it just as an
// applying one does. So the output carries the limit and the room left.
//
// Three candidates transfer 1 MiB each here, so the day stands at 3 MiB of
// 104857600 and 101711872 bytes are left: 104857600 - 3145728 = 101711872.
func TestTestCommandSaysHowMuchOfTheDayIsLeft(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")

	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test"}, fixture.flags()...), &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "budget-limit-bytes: 104857600") {
		t.Errorf("the report does not name the day's limit:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "budget-remaining-bytes: 101711872") {
		t.Errorf("the report does not say what is left of the day:\n%s", stdout.String())
	}
}

// The collection phase of `test` is the one part of a run that fetches over the
// network, so the command's own context has to reach it: a cancelled `test` that
// spent its client's full timeout collecting candidates would ignore the operator's
// Ctrl-C and keep going. This drives the real reader against a local origin that
// never answers, with the context already cancelled, so the only thing that can end
// the request is the context.
func TestCandidateCollectionIsCancellable(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(30 * time.Second)
	}))
	defer origin.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := readOfficialAndUserCandidates(ctx, candidateSource{
		// The origin is TLS because the source refuses anything else, and the
		// server's own client is the one that trusts its certificate.
		Client:    origin.Client(),
		BaseURL:   origin.URL,
		CachePath: filepath.Join(t.TempDir(), "cloudflare-ips.json"),
		UserList:  filepath.Join(t.TempDir(), "cloudflare.txt"),
		Limit:     512,
		Moment:    fixedMoment,
	})
	if err == nil {
		t.Fatal("a cancelled collection returned candidates, want the context's error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("the collection returned %v, want an error that is context.Canceled", err)
	}
}

func TestTestCommandReportsWithoutPublishing(t *testing.T) {
	// The default of `test` is a report and nothing else. A run that changed the
	// address in service would rewrite every user's DNS answers on the strength of
	// a measurement nobody looked at, so the selector has to come out of this
	// command byte for byte identical.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	stub := newStubProber()

	var stdout, stderr bytes.Buffer
	code := runWithContext(t.Context(), append([]string{"test"}, fixture.flags()...), &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment))
	if code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	after, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a report-only test changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !strings.Contains(stdout.String(), "winner: 104.16.0.1") {
		t.Errorf("the report does not name the winner it measured:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "stale-candidates: false") {
		t.Errorf("the report does not say whether the candidate set was stale:\n%s", stdout.String())
	}
	// Three candidates were proved and nothing was proved again: a report-only run
	// does not publish, so it does not need the second proof.
	if got := stub.proofs(); got != 3 {
		t.Errorf("the prober was asked for %d identity proofs, want 3: a report-only run proves each candidate once", got)
	}
	// The day is charged for the transfers, and the report says so.
	record := state.BandwidthBudgetState{}
	if err := state.ReadJSON(fixture.budgetPath, &record); err != nil {
		t.Fatalf("read the budget: %v", err)
	}
	if record.UsedBytes != 3*(1<<20) {
		t.Errorf("the budget stands at %d bytes, want %d: three transfers of 1 MiB", record.UsedBytes, 3*(1<<20))
	}
}

func TestTestCommandRunsWhileTheControlLockIsHeldByAnotherProcess(t *testing.T) {
	// The control lock is held for the write of the selector and for the proof in
	// front of it, and a measurement run needs it for neither: a report-only run an
	// operator started before a timer fired has to be able to finish.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	lock, err := filelock.Acquire(fixture.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()

	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test"}, fixture.flags()...), &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test with the control lock held exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "winner: 104.16.0.1") {
		t.Errorf("the report does not name the winner:\n%s", stdout.String())
	}
}

func TestTestCommandAppliesInTheSameInvocationWhenAsked(t *testing.T) {
	// `--apply` is the whole measurement and the publication in one invocation, and
	// the second identity proof happens inside it: a report generated earlier is
	// never what gets applied.
	//
	// Three candidates are proved once each by the run, against the one global
	// identity profile this configuration names. The apply proves the winner again
	// against that same global profile: four proofs. The CloudFront rule's hostname
	// is not asked about a global address - a Cloudflare anycast address cannot
	// serve it, and the CloudFront mapping is per-hostname, so the global winner is
	// never published there.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	stub := newStubProber()

	args := append([]string{"test", "--apply"}, fixture.flags()...)
	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), args, &stdout, &stderr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test --apply exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if got := stub.proofs(); got != 4 {
		t.Errorf("the prober was asked for %d identity proofs, want 4: three candidates once each, then the winner against the global profile again", got)
	}
	selector := state.Selector{}
	if err := state.ReadJSON(fixture.selectorPath, &selector); err != nil {
		t.Fatal(err)
	}
	if selector.Generation != 5 {
		t.Errorf("the published selector is generation %d, want 5", selector.Generation)
	}
	if selector.WinnerIP != "104.16.0.1" {
		t.Errorf("the published winner is %q, want 104.16.0.1", selector.WinnerIP)
	}
	if selector.FallbackIP != "104.16.1.1" {
		t.Errorf("the published fallback is %q, want the address that was in service", selector.FallbackIP)
	}
	if string(before) == string(mustReadFile(t, fixture.selectorPath)) {
		t.Error("test --apply left the selector exactly as it was")
	}
	if !strings.Contains(stdout.String(), "applied: 104.16.0.1") {
		t.Errorf("the output does not say what was published:\n%s", stdout.String())
	}
}

func TestTestCommandWithApplyIgnoresAReportLeftOnDisk(t *testing.T) {
	// The report on disk is somebody else's evidence. A `test --apply` has to
	// publish what it just measured, so a report file from an earlier run - here one
	// that is not even valid - cannot be what it applies.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	if err := os.WriteFile(fixture.reportPath, []byte("{\"schema_version\": 99}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"test", "--apply", "--report", fixture.reportPath}, fixture.flags()...)
	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test --apply exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	report, err := optimizer.ReadReport(fixture.reportPath)
	if err != nil {
		t.Fatalf("the report this invocation wrote is not one it can read: %v", err)
	}
	if report.SchemaVersion != optimizer.ReportSchemaVersion {
		t.Errorf("the report on disk is schema %d, want %d", report.SchemaVersion, optimizer.ReportSchemaVersion)
	}
	if len(report.Groups) == 0 || report.Groups[0].Winner == nil || report.Groups[0].Winner.IP != "104.16.0.1" {
		t.Errorf("the report on disk does not carry the winner this run measured: %+v", report.Groups)
	}
	if !report.FinalProofPassed {
		t.Error("the report on disk does not record the final proof, though --apply ran one in this invocation")
	}
}

func TestTestCommandWritesAReportThatTheApplyCommandCanRead(t *testing.T) {
	// The two commands have to meet at a file, so the report `test` writes is read
	// back with the same reader `apply` uses and is applied.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	args := append([]string{"test", "--report", fixture.reportPath}, fixture.flags()...)
	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	report, err := optimizer.ReadReport(fixture.reportPath)
	if err != nil {
		t.Fatalf("read the report the command wrote: %v", err)
	}
	if report.GeneratedAt.IsZero() {
		t.Error("the report records no time")
	}
}

func TestApplyCommandRefusesAReportFromAnotherConfiguration(t *testing.T) {
	// The digest is the whole of the "is this report about this router" question,
	// and a report measured under another policy is refused before anything is
	// proved or written.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	stub := newStubProber()
	var measureOut, measureErr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test", "--report", fixture.reportPath}, fixture.flags()...),
		&measureOut, &measureErr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, measureErr.String())
	}
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	// The policy is edited after the report was written, so its digest is no longer
	// the one the report carries.
	edited := strings.Replace(validPolicyYAML, "latency_candidate_count: 10", "latency_candidate_count: 9", 1)
	if err := os.WriteFile(fixture.policyPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	probes := stub.proofs()

	var stdout, stderr bytes.Buffer
	args := append([]string{"apply", fixture.reportPath}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
		t.Fatal("apply of a report from another configuration succeeded, want a refusal")
	}
	if !strings.Contains(stderr.String(), "configuration") {
		t.Errorf("the refusal does not name the configuration: %s", stderr.String())
	}
	if got := stub.proofs(); got != probes {
		t.Errorf("the refused apply proved %d addresses, want 0 more than the run did", got-probes)
	}
	after, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused apply changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestApplyCommandRefusesAReportItCannotDecode(t *testing.T) {
	// A document this build does not fully understand is not a report it may
	// publish from, and the refusal has to be the command's own exit code rather
	// than a panic or a half-applied write.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.reportPath, []byte("{\"schema_version\": 1, \"surprise\": true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := append([]string{"apply", fixture.reportPath}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
		t.Fatal("apply of an undecodable report succeeded, want a refusal")
	}
	after, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused apply changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestApplyCommandSaysTheLockIsHeldWithoutChangingTheFile(t *testing.T) {
	// The conflict has its own exit code, so a timer and an operator can tell "the
	// other one got there first" from "this one is broken".
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	stub := newStubProber()
	var measureOut, measureErr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test", "--report", fixture.reportPath}, fixture.flags()...),
		&measureOut, &measureErr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d (stderr: %s)", code, measureErr.String())
	}
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := filelock.Acquire(fixture.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()

	var stdout, stderr bytes.Buffer
	args := append([]string{"apply", fixture.reportPath}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitLockHeld {
		t.Fatalf("apply with the control lock held exit = %d, want %d (stderr: %s)", code, exitLockHeld, stderr.String())
	}
	after, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused apply changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestPinCommandStoresAManualWinnerAndUnpinRestoresAutomaticSelection(t *testing.T) {
	// The manual path end to end: an address that passes the identity proof is
	// stored as a manual winner, and unpinning puts the selector back into automatic
	// mode with that address as the fallback rather than discarding it.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	stub := newStubProber()
	services := servicesFor(stub, threeCloudflareCandidates(), fixedMoment)

	var stdout, stderr bytes.Buffer
	pinArgs := append([]string{"pin", "104.16.9.9"}, fixture.flags()...)
	if code := runWithContext(t.Context(), pinArgs, &stdout, &stderr, services); code != exitSuccess {
		t.Fatalf("pin exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	pinned := state.Selector{}
	if err := state.ReadJSON(fixture.selectorPath, &pinned); err != nil {
		t.Fatal(err)
	}
	if pinned.Mode != "manual" || pinned.WinnerIP != "104.16.9.9" {
		t.Errorf("the pinned selector holds mode %q and winner %q, want manual and 104.16.9.9", pinned.Mode, pinned.WinnerIP)
	}
	if pinned.Generation != 5 {
		t.Errorf("the pinned selector is generation %d, want 5", pinned.Generation)
	}
	if pinned.FallbackIP != "104.16.1.1" {
		t.Errorf("the pinned fallback is %q, want the address that was in service", pinned.FallbackIP)
	}

	stdout.Reset()
	stderr.Reset()
	unpinArgs := append([]string{"unpin"}, fixture.flags()...)
	if code := runWithContext(t.Context(), unpinArgs, &stdout, &stderr, services); code != exitSuccess {
		t.Fatalf("unpin exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	unpinned := state.Selector{}
	if err := state.ReadJSON(fixture.selectorPath, &unpinned); err != nil {
		t.Fatal(err)
	}
	if unpinned.Mode != "auto" {
		t.Errorf("the unpinned selector's mode is %q, want auto", unpinned.Mode)
	}
	if unpinned.WinnerIP != "" {
		t.Errorf("the unpinned selector still names the winner %q", unpinned.WinnerIP)
	}
	if unpinned.FallbackIP != "104.16.9.9" {
		t.Errorf("the unpinned fallback is %q, want the address that was pinned", unpinned.FallbackIP)
	}
	if unpinned.Generation != 6 {
		t.Errorf("the unpinned selector is generation %d, want 6", unpinned.Generation)
	}
}

// A pin's identity proofs are outside the daily bandwidth budget, so the bytes
// they read are the operator's data allowance and nothing on disk accounts for
// them. `health-check` already prints its total; `pin` now prints its own, on a
// successful pin and on a refused one alike, because a refused proof is exactly the
// case where bytes were spent and no address was stored.
func TestPinCommandReportsTheUnchargedIdentityBytesItSpent(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")

	var stdout, stderr bytes.Buffer
	args := append([]string{"pin", "104.16.9.9"}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("pin exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "identity-body-bytes: 512") {
		t.Errorf("the pin does not account for the uncharged body bytes:\n%s", stdout.String())
	}

	// And on the refused path, where the bytes were spent and nothing was stored.
	fixture = newCDNFixture(t, 4, "104.16.1.1")
	refusing := newStubProber()
	refusing.identityErr = errors.New("104.16.9.9 does not serve speed.cloudflare.com: connection refused")
	stdout.Reset()
	stderr.Reset()
	args = append([]string{"pin", "104.16.9.9"}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(refusing, threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
		t.Fatal("a pin whose proof was refused reported success")
	}
	if !strings.Contains(stdout.String(), "identity-body-bytes: 512") {
		t.Errorf("a refused pin does not account for the bytes it spent:\n%s", stdout.String())
	}
}

func TestPinCommandRefusesAnAddressTheRulesDoNotAllowWithoutChangingTheFile(t *testing.T) {
	// The same rule a candidate is held to, reached through the command an operator
	// would use to get it wrong, and the file does not move.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.168.1.1", "127.0.0.1", "not-an-address", "104.16.9.9:443"} {
		t.Run(address, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"pin", address}, fixture.flags()...)
			if code := runWithContext(t.Context(), args, &stdout, &stderr,
				servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
				t.Fatalf("pin of %s succeeded, want a refusal", address)
			}
			after, err := os.ReadFile(fixture.selectorPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Errorf("a refused pin of %s changed the selector:\nbefore:\n%s\nafter:\n%s", address, before, after)
			}
		})
	}
}

func TestNetworkProberForwardsTheRunnersBudgetThroughToTheRealProber(t *testing.T) {
	// The composition between the two packages is one forwarding method and one
	// budget shim, and it is the only place the runner's settle-once budget meets
	// the prober's own narrower interface. A shim that dropped the reservation
	// would charge the day nothing, so this charges a real budget and reads it
	// back.
	directory := t.TempDir()
	budget := optimizer.NewBudget(10 << 20)
	inner := &countingProber{transferred: 1 << 20}
	adapter := networkProber{inner: inner}
	subject := candidate.Candidate{Provider: candidate.ProviderCloudflare, IP: netip.MustParseAddr("104.16.0.1"), Source: candidate.SourceCloudflare}
	profile := candidate.ProbeProfile{
		Hostname:       "speed.example.test",
		URL:            "https://speed.example.test/",
		Method:         http.MethodGet,
		Port:           443,
		ExpectedStatus: []int{200},
	}
	metrics, err := adapter.Download(t.Context(), subject, profile, 10<<20, time.Second, budget)
	if err != nil {
		t.Fatalf("Download through the adapter: %v", err)
	}
	if metrics.Bytes != 1<<20 {
		t.Errorf("the adapter reports %d bytes, want the %d the prober read", metrics.Bytes, 1<<20)
	}
	if used := budget.Used(); used != 1<<20 {
		t.Errorf("the day stands at %d bytes, want the %d that was transferred", used, 1<<20)
	}
	if inner.reserved != 10<<20 {
		t.Errorf("the prober was asked to reserve %d bytes, want the run's own 10 MiB limit", inner.reserved)
	}
	_ = directory
}

// countingProber is a prober that reserves through whatever budget it is given and
// settles what it was told it read, which is the prober's own contract.
type countingProber struct {
	reserved    int64
	transferred int64
}

func (p *countingProber) TCP(context.Context, netip.Addr, uint16, int) (prober.TCPMetrics, error) {
	return prober.TCPMetrics{Samples: 1}, nil
}

func (p *countingProber) HTTPS(context.Context, candidate.Candidate, candidate.ProbeProfile) (prober.HTTPMetrics, error) {
	return prober.HTTPMetrics{Status: 200}, nil
}

func (p *countingProber) Download(_ context.Context, _ candidate.Candidate, _ candidate.ProbeProfile, maxBytes int64, _ time.Duration, budget prober.ByteBudget) (prober.DownloadMetrics, error) {
	reserved, err := budget.Reserve(maxBytes)
	if err != nil {
		return prober.DownloadMetrics{}, err
	}
	p.reserved = reserved
	budget.Consume(reserved, p.transferred)
	return prober.DownloadMetrics{Bytes: p.transferred, Elapsed: time.Second, BytesPerSecond: float64(p.transferred)}, nil
}

func TestTestCommandProvesAGlobalCandidateAgainstEveryIdentityDomain(t *testing.T) {
	// The design holds a Cloudflare address to the provider's representative domain
	// and every forced-ECH domain, so the hostnames in the identity list are proved
	// alongside it: three candidates against three profiles is nine proofs, and a
	// domain left out of the list is a domain a user on it would have every query
	// rewritten to an address that may not serve it.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	if err := os.WriteFile(fixture.identities, []byte("# forced ECH domains\nstrict.example.test\nsecure.example.test\nstrict.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := newStubProber()
	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test"}, fixture.flags()...), &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	// Three hostnames: the representative domain and the two distinct names from the
	// list, the repeat collapsed. Three candidates against three profiles each.
	if got := stub.proofs(); got != 9 {
		t.Errorf("the prober was asked for %d identity proofs, want 9: three candidates against three profiles", got)
	}
}

func TestTestCommandSaysNothingQualifiedAndPublishesNothing(t *testing.T) {
	// A run where the identity proof refuses every candidate is not a successful
	// run, and a timer that recorded it as one would have a day of measurements
	// nobody looked at. The reason is in the report and the exit code says so.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	stub := newStubProber()
	stub.identityErr = errors.New("the response is a 521, which the profile does not expect")

	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test"}, fixture.flags()...), &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitStateUnavailable {
		t.Fatalf("test with nothing qualified exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no-winner: "+optimizer.ReasonNoProvedCandidate) {
		t.Errorf("the report does not say why nothing qualified:\n%s", stdout.String())
	}
	after, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a run that proved nothing changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// A final proof that ran and was refused is the one line in a report that says the
// address stopped serving, so it must not be printed as "not run" - which is what
// the report used to say for every proof that did not pass, and which reads as
// "nothing was proved and nothing was at stake".
func TestTheReportSaysAFinalProofThatRanAndWasRefusedWasRefused(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	stub := newStubProber()
	// The run proves the winner; the apply's second proof of the same address is
	// refused, which is an address that stopped serving between the two moments.
	stub.finalProofRefused = map[string]error{
		"104.16.0.1": errors.New("104.16.0.1 does not serve speed.cloudflare.com: connection refused"),
	}

	var stdout, stderr bytes.Buffer
	args := append([]string{"test", "--apply"}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
		t.Fatalf("test --apply whose final proof was refused reported success:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "final-proof: refused") {
		t.Errorf("the report does not say the final proof was refused:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "final-proof: not run") {
		t.Errorf("a final proof that ran is reported as never having run:\n%s", stdout.String())
	}
}

// A report-only run never proves the winner again, so "not run" is the truth for it
// and has to stay reachable.
func TestTheReportSaysTheFinalProofDidNotRunOnAReportOnlyRun(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test"}, fixture.flags()...), &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "final-proof: not run") {
		t.Errorf("a report-only run does not say the final proof did not run:\n%s", stdout.String())
	}
}

func TestTestCommandPublishesNothingWhenTheRunIsCancelled(t *testing.T) {
	// A cancelled run returns what it measured and publishes nothing, whichever way
	// the cancellation arrived. The partial report is on stdout, the error on
	// stderr, and the selector is exactly as it was.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var stdout, stderr bytes.Buffer
	args := append([]string{"test", "--apply"}, fixture.flags()...)
	if code := runWithContext(ctx, args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
		t.Fatal("a cancelled test --apply reported success, want a failure")
	}
	after, err := os.ReadFile(fixture.selectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a cancelled run changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !strings.Contains(stdout.String(), "applied: nothing") {
		t.Errorf("the output does not say that nothing was published:\n%s", stdout.String())
	}
}

// A run that did not finish cannot produce a document this build will write: the
// phases that never ran have no boundaries, so the partial report is refused by
// the writer's own validation. That is the right refusal - a partial report is not
// an applyable one - but the error must say what happened and where the document
// is, rather than surfacing a field the operator never sees and leaving the --report
// path empty with no explanation.
func TestACancelledRunWithAReportPathSaysWhereThePartialReportIs(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before := string(mustReadFile(t, fixture.selectorPath))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var stdout, stderr bytes.Buffer
	args := append([]string{"test", "--report", fixture.reportPath}, fixture.flags()...)
	code := runWithContext(ctx, args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment))
	if code == exitSuccess {
		t.Fatal("a cancelled test reported success")
	}
	if _, err := os.Stat(fixture.reportPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a partial report was written to %s (stat error %v): it is not a document an apply can read", fixture.reportPath, err)
	}
	if !strings.Contains(stderr.String(), "did not finish") {
		t.Errorf("the error does not say the run did not finish: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "stdout") {
		t.Errorf("the error does not say the partial report is on stdout: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "final-proof") && !strings.Contains(stderr.String(), "phase") {
		t.Errorf("the error is a bare validation complaint with no shape the operator can act on: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "generated-at:") {
		t.Errorf("the partial report is not on stdout:\n%s", stdout.String())
	}
	if after := string(mustReadFile(t, fixture.selectorPath)); after != before {
		t.Errorf("a cancelled run changed the selector:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestReadUserCandidatesReadsTheOperatorsOwnList(t *testing.T) {
	// The user list is the one channel a person writes by hand, so the reader is
	// held to the same rules the official source is: comments and blank lines are
	// nothing, a /32 and a bare address are one candidate each, the same address
	// twice is one candidate, and a private address is refused rather than measured.
	directory := t.TempDir()
	path := filepath.Join(directory, "cloudflare.txt")
	contents := `# the addresses I trust
104.16.5.5
104.16.6.6/32

104.16.5.5
192.168.1.1
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	listed, err := readUserCandidates(path)
	if err == nil {
		t.Fatalf("a list naming %s was accepted, want a refusal", "192.168.1.1")
	}
	if !strings.Contains(err.Error(), "public") {
		t.Errorf("the refusal %q does not say the address is not a public one", err)
	}
	// The whole list is refused rather than half of it measured, because a list a
	// person wrote and this build could not read is a list to correct, not to
	// partially believe.
	if len(listed) != 0 {
		t.Errorf("a refused list still returned %d candidates: %v", len(listed), listed)
	}

	good := filepath.Join(directory, "good.txt")
	if err := os.WriteFile(good, []byte("# trusted\n104.16.5.5\n104.16.6.6/32\n104.16.5.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listed, err = readUserCandidates(good)
	if err != nil {
		t.Fatalf("read a valid list: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("the list produced %d candidates (%v), want 2", len(listed), listed)
	}
	if listed[0].IP.String() != "104.16.5.5" || listed[1].IP.String() != "104.16.6.6" {
		t.Errorf("the list produced %v, want 104.16.5.5 and 104.16.6.6 in address order", listed)
	}
	for _, subject := range listed {
		if subject.Source != candidate.SourceUser {
			t.Errorf("candidate %s records source %q, want %q: a list a user wrote keeps the user's label", subject.IP, subject.Source, candidate.SourceUser)
		}
		if subject.Provider != candidate.ProviderCloudflare {
			t.Errorf("candidate %s records provider %q, want %q", subject.IP, subject.Provider, candidate.ProviderCloudflare)
		}
	}
}

func TestCommandsRefuseAnEmptyRequiredFlag(t *testing.T) {
	// A mistyped path is an operator measuring the wrong thing or publishing to the
	// wrong file, and an empty flag is what a mistyped path looks like after a shell
	// has eaten it. The refusal is at the command line, where it costs nothing.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	for _, name := range []string{"test", "unpin"} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{name}, fixture.flags()...)
			for index := 0; index < len(args)-1; index++ {
				if args[index] == "--selector" {
					args[index+1] = "  "
				}
			}
			var stdout, stderr bytes.Buffer
			if code := runWithContext(t.Context(), args, &stdout, &stderr,
				servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitInvalidCLI {
				t.Fatalf("%s with an empty --selector exit = %d, want %d (stderr: %s)", name, code, exitInvalidCLI, stderr.String())
			}
			if !strings.Contains(stderr.String(), "--selector") {
				t.Errorf("the refusal does not name the empty flag: %s", stderr.String())
			}
		})
	}
}

// TestTestCommandSaysWhichGroupKeptItsMapping covers the one night shape that is
// ordinary rather than exceptional: one group found an address that clears the
// switch gate and another did not. The overall outcome is "published" and the
// second group's own outcome is "kept", and the output has to say both - an
// overall answer alone hides whichever group did nothing.
func TestTestCommandSaysWhichGroupKeptItsMapping(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	// The operator's CloudFront rule names an address of its own, so the run measures
	// a second group.
	if err := os.WriteFile(fixture.profilesPath, []byte(`schema_version: 1
profiles:
  - hostname: assets.example.test
    url: https://assets.example.test/
    method: GET
    port: 443
    expected_status:
      - 200
    ip: 205.251.192.1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := newStubProber()
	// The address cannot serve the hostname it is named for, so that group measures
	// nothing publishable while the global group measures cleanly.
	stub.identityRefusedFor = map[string]error{
		"assets.example.test": errors.New("the certificate presented is for speed.example.test, not assets.example.test"),
	}

	var stdout, stderr bytes.Buffer
	args := append([]string{"test", "--apply"}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test --apply exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "outcome: published") {
		t.Errorf("the output does not say the apply published something:\n%s", output)
	}
	if !strings.Contains(output, "group: cloudfront/assets.example.test") {
		t.Errorf("the output does not mention the CloudFront group:\n%s", output)
	}
	if !strings.Contains(output, "outcome: kept") {
		t.Errorf("the output does not say the CloudFront group kept its mapping:\n%s", output)
	}
	if !strings.Contains(output, "outcome-reason: "+optimizer.ReasonNoProvedCandidate) {
		t.Errorf("the output does not say why the CloudFront group was kept:\n%s", output)
	}
	// The global winner moved and the per-hostname mapping did not.
	selector := state.Selector{}
	if err := state.ReadJSON(fixture.selectorPath, &selector); err != nil {
		t.Fatal(err)
	}
	if selector.WinnerIP != "104.16.0.1" {
		t.Errorf("the published global winner is %q, want 104.16.0.1", selector.WinnerIP)
	}
}

func TestCommandsRefuseAReportPathThatIsSomethingTheRunAlsoUses(t *testing.T) {
	// `--report PATH` is a path a command writes, and every other path a command
	// names is a file it reads or a state file it publishes. Naming the same file
	// twice means a run overwrites the policy it just read, the selector it is about
	// to publish into, or the budget document it is charging, with a report document
	// - so the collision is refused where the other flags are parsed, before any
	// network I/O and before the control lock is taken.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	collisions := map[string]string{
		"the selector":         fixture.selectorPath,
		"the policy":           fixture.policyPath,
		"the budget":           fixture.budgetPath,
		"the control lock":     fixture.lockPath,
		"the profile document": fixture.profilesPath,
		"the identity domains": fixture.identities,
		"the candidate list":   fixture.candidatesPath(),
	}
	for name, path := range collisions {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"test", "--report", path}, fixture.flags()...)
			if code := runWithContext(t.Context(), args, &stdout, &stderr,
				servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitInvalidCLI {
				t.Fatalf("test --report %s exit = %d, want %d (stderr: %s)", name, code, exitInvalidCLI, stderr.String())
			}
			if !strings.Contains(stderr.String(), path) {
				t.Errorf("the refusal does not name the colliding path: %s", stderr.String())
			}
		})
	}
	// A path that resolves to the same file by another spelling is the same
	// collision: a report written to "<dir>/./cdn-selector.json" overwrites the
	// selector beside it.
	t.Run("another spelling of the same path", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		spelling := filepath.Join(fixture.directory, ".", filepath.Base(fixture.selectorPath))
		args := append([]string{"test", "--report", spelling}, fixture.flags()...)
		if code := runWithContext(t.Context(), args, &stdout, &stderr,
			servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitInvalidCLI {
			t.Fatalf("test --report %s exit = %d, want %d (stderr: %s)", spelling, code, exitInvalidCLI, stderr.String())
		}
	})
	// A report beside the selector is fine, which is what the other cases have to be
	// measured against.
	t.Run("a report of its own", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := append([]string{"test", "--report", fixture.reportPath}, fixture.flags()...)
		if code := runWithContext(t.Context(), args, &stdout, &stderr,
			servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
			t.Fatalf("test --report of its own exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
		}
	})
}

func TestTestCommandProvesAGlobalAddressOnceWhenTheIdentityListNamesTheRepresentativeDomain(t *testing.T) {
	// The representative domain leads the global profile set and the forced-ECH list
	// follows it, so an operator who lists the same name in both gets one profile.
	// Two would be the same proof run twice, and the final gate runs under the
	// control lock.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	if err := os.WriteFile(fixture.identities, []byte(defaultRepresentativeDomain+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := newStubProber()
	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test"}, fixture.flags()...), &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	// Three candidates against one profile: the name appears once, so it is proved
	// once.
	if got := stub.proofs(); got != 3 {
		t.Errorf("the prober was asked for %d identity proofs, want 3: the representative domain listed twice is one profile", got)
	}
}

// A night on which every group kept its mapping is a night the file was not
// touched. The output has to say that, because a timer or a script reading
// "applied: <ip>" would otherwise record a publication that never happened - and it
// would do so on the one night the run said the address in service was still the
// right one, which is exactly the night nobody looks at the output of.
func assertNoPublicationClaimed(t *testing.T, output string) {
	t.Helper()
	if !strings.Contains(output, "applied: nothing") {
		t.Errorf("the output does not say that nothing was applied:\n%s", output)
	}
	if !strings.Contains(output, "outcome: kept") {
		t.Errorf("the output does not carry the kept outcome:\n%s", output)
	}
	for _, claimed := range []string{"applied: 104.16.1.1", "generation: 4", "fallback: "} {
		if strings.Contains(output, claimed) {
			t.Errorf("the output claims %q for a run that wrote nothing:\n%s", claimed, output)
		}
	}
}

func TestTestCommandClaimsNoPublicationWhenEveryGroupKeptItsMapping(t *testing.T) {
	// `test --apply` measures and applies in one invocation, and the apply is what
	// prints. With nothing publishable in any group the apply keeps everything, and
	// the report it hands back describes a selector nobody wrote.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	// The selector as it is before the run, so the case can show that nothing wrote
	// it and, separately, that nothing claimed to.
	before := string(mustReadFile(t, fixture.selectorPath))
	stub := newStubProber()
	// Nothing in the run can be proved, so the group produces no winner at all and
	// the apply has nothing to publish.
	stub.identityErr = errors.New("the response is a 521, which the profile does not expect")

	var stdout, stderr bytes.Buffer
	args := append([]string{"test", "--apply"}, fixture.flags()...)
	code := runWithContext(t.Context(), args, &stdout, &stderr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment))
	// The run measured nothing, which the command reports as such; the question this
	// case asks is what it printed on the way out.
	if code != exitStateUnavailable {
		t.Fatalf("test --apply of an unprovable run exit = %d, want %d (stdout: %s)", code, exitStateUnavailable, stdout.String())
	}
	assertNoPublicationClaimed(t, stdout.String())
	if got := string(mustReadFile(t, fixture.selectorPath)); got != before {
		t.Errorf("the selector changed on a run that published nothing:\n%s", got)
	}
}

func TestApplyCommandClaimsNoPublicationWhenEveryGroupKeptItsMapping(t *testing.T) {
	// The same night seen through `apply`: a report written earlier whose every group
	// kept its mapping. The apply succeeds, because keeping the address in service is
	// an outcome and not a failure - and it must not print the address as one it
	// applied.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before := string(mustReadFile(t, fixture.selectorPath))
	// The report is written by a run that could prove nothing, which exits 3 after
	// writing the report: the document exists and says there was no winner.
	measuring := newStubProber()
	measuring.identityErr = errors.New("the response is a 521, which the profile does not expect")
	var measureOut, measureErr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test", "--report", fixture.reportPath}, fixture.flags()...),
		&measureOut, &measureErr, servicesFor(measuring, threeCloudflareCandidates(), fixedMoment)); code != exitStateUnavailable {
		t.Fatalf("test of an unprovable run exit = %d, want %d (stdout: %s)", code, exitStateUnavailable, measureOut.String())
	}

	applied := filepath.Join(fixture.directory, "applied.json")
	var stdout, stderr bytes.Buffer
	args := append([]string{"apply", fixture.reportPath, "--report", applied}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("apply of an all-kept report exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	assertNoPublicationClaimed(t, stdout.String())
	if got := string(mustReadFile(t, fixture.selectorPath)); got != before {
		t.Errorf("the selector changed on an apply that published nothing:\n%s", got)
	}
}

// assertRefusedNotPublished is the shape every refusing command's output has to
// have: the outcome says the apply was refused, the applied line says nothing was
// applied, and no line names an address as one this run published.
//
// The pair is what matters. `applied: nothing` alone was what round 2 checked for
// the all-kept path, and a refusal printed `applied: nothing` correctly while
// saying `outcome: published` next to it - so a script keying on the outcome line
// instead of the applied line recorded a publication that never happened.
func assertRefusedNotPublished(t *testing.T, output string) {
	t.Helper()
	if !strings.Contains(output, "applied: nothing") {
		t.Errorf("the output does not say that nothing was applied:\n%s", output)
	}
	if got := reportOutcome(output); got != "refused" {
		t.Errorf("the report's own outcome is %q, want %q: a refusal is not a publication, and a script keying on this line is exactly the reader that was misled:\n%s", got, "refused", output)
	}
	// A group that was about to be published is downgraded rather than left claiming
	// a publication, and it says why - so the record an operator reads names both
	// the address the run had chosen and the fact that nothing was written.
	if !strings.Contains(output, optimizer.ReasonApplyRefused) {
		t.Errorf("the output does not say why the group was not published:\n%s", output)
	}
	for _, claimed := range []string{"outcome: published", "applied: 104.16.1.1", "generation: 5", "fallback: "} {
		if strings.Contains(output, claimed) {
			t.Errorf("the output claims %q for an apply that refused:\n%s", claimed, output)
		}
	}
}

// reportOutcome is the outcome of the report as a whole, which is the one a script
// reads. The per-group outcomes are printed indented, so this returns the top-level
// line and only the top-level line.
func reportOutcome(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if rest, is := strings.CutPrefix(line, "outcome: "); is {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func TestApplyCommandReportsARefusalRatherThanAPublication(t *testing.T) {
	// The control lock is the refusal this router is most likely to meet, because a
	// health check and an update both take it. The report the apply was handed says
	// the run would publish; the apply did not, and its output has to say so.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before := string(mustReadFile(t, fixture.selectorPath))
	// A report a run really wrote, so the apply has a decision to refuse.
	measuring := newStubProber()
	var measureOut, measureErr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"test", "--report", fixture.reportPath}, fixture.flags()...),
		&measureOut, &measureErr, servicesFor(measuring, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("test exit = %d, want %d (stderr: %s)", code, exitSuccess, measureErr.String())
	}

	// Another process holds the control lock for the whole apply.
	held, err := filelock.Acquire(fixture.lockPath)
	if err != nil {
		t.Fatalf("take the control lock: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })

	var stdout, stderr bytes.Buffer
	args := append([]string{"apply", fixture.reportPath, "--report", filepath.Join(fixture.directory, "applied.json")}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
		t.Fatal("apply with the control lock held succeeded, want a refusal")
	}
	// The refusal reason goes to stderr where every CLI error does; the report goes
	// to stdout, and the report is what this case is about.
	if !strings.Contains(stderr.String(), "control lock") {
		t.Errorf("stderr does not name the lock as the reason: %s", stderr.String())
	}
	assertRefusedNotPublished(t, stdout.String())
	if got := string(mustReadFile(t, fixture.selectorPath)); got != before {
		t.Errorf("the selector changed on a refused apply:\n%s", got)
	}
}

func TestTestCommandWithApplyReportsARefusalRatherThanAPublication(t *testing.T) {
	// The same mislabel through `test --apply`, where the report is printed from the
	// failed apply rather than read from a file - so a single invocation shows both
	// the decision the run reached and the fact that the apply refused it.
	//
	// The host serves the run and then stops, which is the one shape where the run
	// finds a winner and the final proof does not confirm it.
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before := string(mustReadFile(t, fixture.selectorPath))
	stub := newStubProber()
	stub.finalProofRefused = map[string]error{
		"104.16.0.1": errors.New("the response is a 521, which the profile does not expect"),
	}

	var stdout, stderr bytes.Buffer
	args := append([]string{"test", "--apply"}, fixture.flags()...)
	if code := runWithContext(t.Context(), args, &stdout, &stderr,
		servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code == exitSuccess {
		t.Fatal("test --apply with a refused final proof succeeded, want a refusal")
	}
	if !strings.Contains(stderr.String(), "identity proof was refused") {
		t.Errorf("stderr does not name the proof as the reason: %s", stderr.String())
	}
	assertRefusedNotPublished(t, stdout.String())
	// The report is still printed with the group it had decided on, because that is
	// what an operator needs to see: which address was about to be published.
	if !strings.Contains(stdout.String(), "104.16.0.1") {
		t.Errorf("the report does not name the address that was about to be published:\n%s", stdout.String())
	}
	if got := string(mustReadFile(t, fixture.selectorPath)); got != before {
		t.Errorf("the selector changed on a refused apply:\n%s", got)
	}
}

// ---------------------------------------------------------------------------
// health-check
// ---------------------------------------------------------------------------

// A health check that finds the published winner serving writes the health
// document and refreshes the published winner's proof window, and publishes
// nothing else. The timer runs this every two minutes, so what it must not do is
// change the selection: no address, no mapping, no mode and no generation move on
// a healthy pass.
//
// The window is the one thing that does move, because the check's own probe is a
// proof of the address in service and the rewriter gates on it. The clock is fixed
// at 03:00, so the window closes at 03:05 - five minutes, written out rather than
// computed from the package's constant.
func TestHealthCheckReportsAHealthyWinnerAndRefreshesItsProofWindow(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")

	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"health-check"}, fixture.flags()...),
		&stdout, &stderr, servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("health-check exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "winner: 104.16.1.1 healthy") {
		t.Errorf("the report does not say the winner is healthy:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "healthy: true") || !strings.Contains(stdout.String(), "consecutive-failures: 0") {
		t.Errorf("the report does not show the health document it wrote:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "transition:") {
		t.Errorf("a healthy check reported a transition:\n%s", stdout.String())
	}
	// The report says whether the window was refreshed, and which window: the
	// rewriter gates on it, so a report that stayed silent would leave an operator
	// unable to tell an open window from an expired one.
	want := "winner-proof: refreshed, until 2026-09-26T03:05:00Z"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("the report does not say %q:\n%s", want, stdout.String())
	}
	// The uncharged identity bytes are reported whether or not anything was
	// published, because nothing on disk accounts for them.
	if !strings.Contains(stdout.String(), "identity-body-bytes: 512") {
		t.Errorf("the report does not account for the uncharged body bytes:\n%s", stdout.String())
	}

	published := state.Selector{}
	if err := state.ReadJSON(fixture.selectorPath, &published); err != nil {
		t.Fatal(err)
	}
	if !published.LastSuccess.Equal(fixedMoment) {
		t.Errorf("the refreshed selector records its last success at %s, want the check's own %s", published.LastSuccess, fixedMoment)
	}
	if !published.WinnerProofUntil.Equal(fixedMoment.Add(5 * time.Minute)) {
		t.Errorf("the refreshed selector's proof expires at %s, want %s", published.WinnerProofUntil, fixedMoment.Add(5*time.Minute))
	}
	if published.Generation != 4 || published.WinnerIP != "104.16.1.1" || published.Mode != "auto" {
		t.Errorf("a healthy check changed the selection: generation %d, winner %q, mode %q", published.Generation, published.WinnerIP, published.Mode)
	}
	if err := published.Validate(); err != nil {
		t.Errorf("the refreshed selector is not one the state package accepts: %v", err)
	}
	documented := state.HealthState{}
	if err := state.ReadJSON(fixture.healthPath, &documented); err != nil {
		t.Fatalf("the health document was not written where --health names: %v", err)
	}
	if !documented.Healthy {
		t.Errorf("the written document does not report a healthy winner: %+v", documented)
	}
}

// A check that found the winner failing says so about the window too, because a
// report that only said "refreshed" or nothing at all would leave a reader unable
// to tell an expired window from one nobody refreshed.
func TestHealthCheckSaysWhenItRefreshedNoProof(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before := string(mustReadFile(t, fixture.selectorPath))
	stub := newStubProber()
	stub.identityRefusedForAddress = map[string]error{
		"104.16.1.1": errors.New("104.16.1.1 does not serve speed.cloudflare.com: connection refused"),
	}

	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"health-check"}, fixture.flags()...),
		&stdout, &stderr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("health-check exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "winner-proof: not refreshed") {
		t.Errorf("a failing check does not say it refreshed no proof:\n%s", stdout.String())
	}
	if got := string(mustReadFile(t, fixture.selectorPath)); got != before {
		t.Errorf("a failing check changed the selector:\nbefore:\n%s\nafter:\n%s", before, got)
	}
}

// The policy's threshold is three, and the third check is the one that moves the
// resolver. The output names the address the command actually wrote, which is the
// one the file now holds.
func TestHealthCheckMovesTheSelectorToItsFallbackAfterThreeFailures(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	writeSelectorFixture(t, fixture.selectorPath, state.Selector{
		SchemaVersion: state.SchemaVersion,
		Generation:    4,
		Mode:          "auto",
		Provider:      "cloudflare",
		WinnerIP:      "104.16.1.1",
		FallbackIP:    "104.16.0.1",
		LastSuccess:   fixedMoment.Add(-time.Hour),
	})
	// The winner has stopped serving and the address beside it still does, which is
	// the incident the rollback exists for. The refusal is keyed by address, because
	// the winner and the fallback are proved against the same hostname and only one
	// of them has stopped answering.
	stub := newStubProber()
	stub.identityRefusedForAddress = map[string]error{
		"104.16.1.1": errors.New("104.16.1.1 does not serve speed.cloudflare.com: connection refused"),
	}

	for attempt := 1; attempt <= 3; attempt++ {
		var stdout, stderr bytes.Buffer
		if code := runWithContext(t.Context(), append([]string{"health-check"}, fixture.flags()...),
			&stdout, &stderr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
			t.Fatalf("health-check %d exit = %d, want %d (stderr: %s)", attempt, code, exitSuccess, stderr.String())
		}
		if attempt < 3 {
			if strings.Contains(stdout.String(), "transition:") {
				t.Fatalf("health-check %d reported a transition below the threshold:\n%s", attempt, stdout.String())
			}
			want := fmt.Sprintf("consecutive-failures: %d", attempt)
			if !strings.Contains(stdout.String(), want) {
				t.Fatalf("health-check %d does not report %q:\n%s", attempt, want, stdout.String())
			}
		}
	}

	published := state.Selector{}
	if err := state.ReadJSON(fixture.selectorPath, &published); err != nil {
		t.Fatal(err)
	}
	if published.WinnerIP != "104.16.0.1" || published.FallbackIP != "104.16.1.1" {
		t.Errorf("published selector = %+v, want the fallback in service", published)
	}
	if published.Generation != 5 {
		t.Errorf("generation = %d, want 5", published.Generation)
	}
	if err := published.Validate(); err != nil {
		t.Errorf("the published selector is not one the state package accepts: %v", err)
	}
}

// A transition that was not written must not be reported. The winner has failed at
// the threshold and the selector names no fallback, so the command reports the
// count it recorded and the refusal - and no transition.
func TestHealthCheckReportsNoTransitionWhenTheFallbackCannotBePublished(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before := string(mustReadFile(t, fixture.selectorPath))
	stub := newStubProber()
	stub.identityErr = errors.New("104.16.1.1 does not serve speed.cloudflare.com: connection refused")

	var stdout, stderr bytes.Buffer
	for attempt := 1; attempt <= 3; attempt++ {
		stdout.Reset()
		stderr.Reset()
		code := runWithContext(t.Context(), append([]string{"health-check"}, fixture.flags()...),
			&stdout, &stderr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment))
		if attempt < 3 && code != exitSuccess {
			t.Fatalf("health-check %d exit = %d, want %d (stderr: %s)", attempt, code, exitSuccess, stderr.String())
		}
		if attempt == 3 {
			if code != exitStateUnavailable {
				t.Fatalf("a refused transition exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr.String())
			}
			if !strings.Contains(stderr.String(), "fallback") {
				t.Errorf("stderr does not name the missing fallback as the reason: %s", stderr.String())
			}
		}
	}
	if strings.Contains(stdout.String(), "transition:") {
		t.Errorf("a refused transition was reported as published:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "consecutive-failures: 3") {
		t.Errorf("the report does not show the count that was recorded:\n%s", stdout.String())
	}
	if got := string(mustReadFile(t, fixture.selectorPath)); got != before {
		t.Errorf("a refused transition changed the selector:\nbefore:\n%s\nafter:\n%s", before, got)
	}
}

// A health check spends no bandwidth budget, so it must work on a router whose
// budget document does not exist and must not create one. A check that opened the
// budget would create the file, and the daily allowance would start being spent by
// a timer that runs every two minutes.
func TestHealthCheckSpendsNoBandwidthBudget(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	if _, err := os.Stat(fixture.budgetPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the fixture already has a budget document: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := runWithContext(t.Context(), append([]string{"health-check"}, fixture.flags()...),
		&stdout, &stderr, servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitSuccess {
		t.Fatalf("health-check exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr.String())
	}
	if _, err := os.Stat(fixture.budgetPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("health-check created or charged the budget document: %v", err)
	}
}

// A health document that cannot be read is reported as such, because the count that
// follows starts at the policy's threshold. This check's own failure is then added
// to it, so the threshold is reached on the first check rather than the third - the
// lost history and this failure are two separate facts, and the report has to show
// both. The selector names no fallback, so that threshold is a refused transition
// and the exit code says so.
func TestHealthCheckReportsAHealthDocumentItCouldNotRead(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	if err := os.WriteFile(fixture.healthPath, []byte(`{"schema_version": 1, "healthy": true,`), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := newStubProber()
	stub.identityErr = errors.New("104.16.1.1 does not serve speed.cloudflare.com: connection refused")

	var stdout, stderr bytes.Buffer
	code := runWithContext(t.Context(), append([]string{"health-check"}, fixture.flags()...),
		&stdout, &stderr, servicesFor(stub, threeCloudflareCandidates(), fixedMoment))
	if code != exitStateUnavailable {
		t.Fatalf("a failed-closed threshold with no fallback exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr.String())
	}
	if !strings.Contains(stdout.String(), "failed-closed:") {
		t.Errorf("the report does not say the health document could not be read:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "consecutive-failures: 4") {
		t.Errorf("the report does not show the threshold the lost history started at:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "transition:") {
		t.Errorf("a refused transition was reported as published:\n%s", stdout.String())
	}
}

// The flags that measure something or write a report have no meaning here, and
// accepting them silently would be a command that appears to have done something it
// did not.
func TestHealthCheckRefusesFlagsThatDoNotApply(t *testing.T) {
	for _, refused := range [][]string{{"--report", filepath.Join(t.TempDir(), "report.json")}, {"--apply"}} {
		fixture := newCDNFixture(t, 4, "104.16.1.1")
		var stdout, stderr bytes.Buffer
		args := append([]string{"health-check", refused[0]}, fixture.flags()...)
		if len(refused) == 2 {
			args = append(args, refused[1])
		}
		if code := runWithContext(t.Context(), args, &stdout, &stderr,
			servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment)); code != exitInvalidCLI {
			t.Errorf("health-check %v exit = %d, want %d (stderr: %s)", refused, code, exitInvalidCLI, stderr.String())
		}
		// The refusal has to name the flag, or it is indistinguishable from any other
		// command-line refusal - including the command not existing at all.
		if !strings.Contains(stderr.String(), strings.TrimPrefix(refused[0], "--")) {
			t.Errorf("health-check %v did not name the flag it refuses: %s", refused, stderr.String())
		}
	}
}

// A health check that finds the control lock held reports the conflict and writes
// nothing. The lock is what a pin, an apply and an unpin hold while they publish,
// so this is the two-minute timer meeting an operator's pin: its own exit code, no
// document written, and the next tick in two minutes.
func TestHealthCheckReportsTheControlLockConflictAndWritesNothing(t *testing.T) {
	fixture := newCDNFixture(t, 4, "104.16.1.1")
	before := string(mustReadFile(t, fixture.selectorPath))
	held, err := filelock.Acquire(fixture.lockPath)
	if err != nil {
		t.Fatalf("take the control lock: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })

	var stdout, stderr bytes.Buffer
	code := runWithContext(t.Context(), append([]string{"health-check"}, fixture.flags()...),
		&stdout, &stderr, servicesFor(newStubProber(), threeCloudflareCandidates(), fixedMoment))
	if code != exitLockHeld {
		t.Fatalf("health-check with the control lock held exit = %d, want %d (stderr: %s)", code, exitLockHeld, stderr.String())
	}
	if !strings.Contains(stderr.String(), "control lock") {
		t.Errorf("stderr does not name the lock as the reason: %s", stderr.String())
	}
	if _, err := os.Stat(fixture.healthPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a check that could not take the lock wrote a health document: %v", err)
	}
	if got := string(mustReadFile(t, fixture.selectorPath)); got != before {
		t.Errorf("a check that could not take the lock changed the selector:\n%s", got)
	}
	// The verdict it did reach is still reported, because the proof ran on the
	// network before the lock was needed.
	if !strings.Contains(stdout.String(), "winner: 104.16.1.1 healthy") {
		t.Errorf("the report does not carry the verdict the check reached:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "consecutive-failures:") {
		t.Errorf("a check that wrote no document reported a count:\n%s", stdout.String())
	}
}
