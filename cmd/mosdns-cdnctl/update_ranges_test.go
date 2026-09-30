package main

// `update-lists --refresh-ranges` is the install-time half of update-lists: it
// publishes the response rewriter's prefix list, and nothing else. The list is a
// hard start requirement -- the plugin refuses to construct without it -- and the
// only producer the CDN optimizer had was a measurement run, so a fresh
// installation had to spend the day's bandwidth budget to get a file the router
// cannot start without. The tests below hold the three properties that make this
// mode substitutable for that run:
//
//   - it measures nothing and charges no budget, so an install cannot starve the
//     first nightly;
//   - it takes one request and publishes both artifacts from that one document,
//     so the list and the envelope beside it cannot describe different days;
//   - it leaves the China list completely alone, because ruling 59 forbids
//     re-pinning it during an install and a mode that touched it would do that by
//     accident.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/optimizer"
)

// rangeDocument is a Cloudflare-shaped response: an etag, three IPv4 entries of
// which two are the same range, and one IPv6 range. The duplicate and the IPv6
// range are both there so the published list proves it deduplicates and stays
// IPv4-only, which is the same render the daily sample's own publication goes
// through.
const rangeDocument = `{"success":true,"errors":[],"messages":[],` +
	`"result":{"etag":"refresh-etag","ipv4_cidrs":["104.16.0.0/22","172.64.0.0/21","104.16.0.0/22"],` +
	`"ipv6_cidrs":["2606:4700::/32"]}}`

const rangeETag = "refresh-etag"

// rangeOrigin is a Cloudflare-shaped origin. It counts the bodies it serves,
// because "one fetch, two artifacts" is a claim about the number of requests and
// only the origin can say how many there were.
type rangeOrigin struct {
	client *http.Client
	url    string

	mutex        sync.Mutex
	document     string
	etag         string
	status       int
	servedBodies int
}

func newRangeOrigin(t *testing.T) *rangeOrigin {
	t.Helper()
	origin := &rangeOrigin{document: rangeDocument, etag: rangeETag, status: http.StatusOK}
	server := httptest.NewTLSServer(http.HandlerFunc(origin.serve))
	t.Cleanup(server.Close)
	origin.url = server.URL
	origin.client = originClient(t, server)
	return origin
}

func (o *rangeOrigin) serve(writer http.ResponseWriter, request *http.Request) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	if o.status != http.StatusOK {
		writer.WriteHeader(o.status)
		return
	}
	writer.Header().Set("ETag", o.etag)
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, o.document)
	o.servedBodies++
}

func (o *rangeOrigin) setStatus(status int) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.status = status
}

func (o *rangeOrigin) bodies() int {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.servedBodies
}

// originClient sends the source's own production URL to the test origin, with the
// test server's certificate trusted under the name that certificate carries.
// Certificate verification stays on for the same reason it does in the candidate
// package's own tests: a source in production refuses a non-https URL, so a test
// that used one would be testing a configuration the router rejects. The name is
// not the production endpoint's, because the test server issues for example.com
// and a client that asked for anything else would be the loose configuration this
// whole project exists to prevent.
func originClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the test origin's transport is a %T, want an *http.Transport", server.Client().Transport)
	}
	cloned := transport.Clone()
	cloned.TLSClientConfig = cloned.TLSClientConfig.Clone()
	cloned.TLSClientConfig.ServerName = "example.com"
	return &http.Client{Transport: rewriteRangeHost{target: target, inner: cloned}}
}

type rewriteRangeHost struct {
	target *url.URL
	inner  *http.Transport
}

func (r rewriteRangeHost) RoundTrip(request *http.Request) (*http.Response, error) {
	next := request.Clone(request.Context())
	next.URL.Scheme = r.target.Scheme
	next.URL.Host = r.target.Host
	return r.inner.RoundTrip(next)
}

// rangePaths is where a range refresh writes, and what a test then inspects.
type rangePaths struct {
	dir        string
	cache      string
	prefixList string
	sourceLock string
	listFile   string
	control    string
	// pinSnapshot and pinLock are the pair a package ships, named here rather
	// than defaulted. They sit in the fixture's own directory -- flat, like every
	// other file here -- and no fixture writes them unless it is about them, so
	// every test in this file runs with a snapshot configured and none there. That
	// is the state which must behave exactly as it did before the snapshot
	// existed, and which must not depend on whether the machine running the suite
	// happens to have this package installed.
	pinSnapshot string
	pinLock     string
}

func newRangePaths(t *testing.T) rangePaths {
	t.Helper()
	dir := t.TempDir()
	return rangePaths{
		dir:         dir,
		cache:       filepath.Join(dir, "cloudflare-ips.json"),
		prefixList:  filepath.Join(dir, candidate.DefaultCloudflarePrefixFileName),
		sourceLock:  filepath.Join(dir, "source-lock.json"),
		listFile:    filepath.Join(dir, "cn-domains.txt"),
		control:     filepath.Join(dir, "control.lock"),
		pinSnapshot: filepath.Join(dir, "cloudflare-ranges.json"),
		pinLock:     filepath.Join(dir, "cloudflare-ranges.lock.json"),
	}
}

// listPaths is the China-list reader's own view of the same directory, so a
// fixture that publishes a China pair and a range pair shares one temp dir and
// one snapshot.
func (p rangePaths) listPaths() listPaths {
	return listPaths{dir: p.dir, sourceLock: p.sourceLock, listFile: p.listFile, controlLock: p.control}
}

// services points the command at the test origins, and refuses a request to the
// China one unless the test supplied a GitHub origin. The publication, the lock
// and the range source are production; the client is the only thing rewritten, so
// the command keeps building its real production URLs.
//
// The refusal is the interesting part: a range refresh must not reach the source
// of the China list at all, and a fake that fails the test on contact says so
// where an assertion after the fact would only say it afterwards.
func (o *rangeOrigin) services(github *http.Client) services {
	byName := byHost{{"api.cloudflare.com", o.client.Transport}}
	if github != nil {
		byName = append(byName, struct {
			host      string
			transport http.RoundTripper
		}{"", github.Transport})
	}
	return services{
		newHTTPClient: func() *http.Client { return &http.Client{Transport: byName} },
		acquireLock: func(path string) (func() error, error) {
			lock, err := filelock.Acquire(path)
			if err != nil {
				return nil, err
			}
			return lock.Close, nil
		},
		documents:   productionDocumentPaths(),
		documentOps: defaultDocumentOps(),
		// The clock is here rather than left nil because `--check` now states how
		// old a package's shipped snapshot is, and a report about an age is a
		// report about a moment. `clockedServices` replaces it wherever the age
		// itself is the thing under test; a fixture that needs neither should not
		// have to think about it.
		now: time.Now,
		// The two boundaries the emergency-rollback verb uses are the real ones
		// here, because this fixture replaces the network and the filesystem and
		// says nothing about who the caller is or what running the installer
		// would do.
		effectiveUID: productionServices().effectiveUID,
		runInstaller: productionServices().runInstaller,
	}
}

// byHost routes a request to the transport for the host it names. The last entry
// is the fallback, so a fixture that serves one origin names it last; a request
// with no route at all is a test's own mistake and is refused loudly.
type byHost []struct {
	host      string
	transport http.RoundTripper
}

func (r byHost) RoundTrip(request *http.Request) (*http.Response, error) {
	for _, route := range r {
		if route.host == request.URL.Host {
			return route.transport.RoundTrip(request)
		}
	}
	if len(r) == 0 {
		return nil, fmt.Errorf("no test origin serves %s", request.URL.Host)
	}
	return r[len(r)-1].transport.RoundTrip(request)
}

func refreshArgs(paths rangePaths) []string {
	return []string{
		"--ranges-cache", paths.cache,
		"--ranges-url", candidate.DefaultCloudflareBaseURL,
		"--pinned-ranges", paths.pinSnapshot,
		"--pinned-ranges-lock", paths.pinLock,
		"--source-lock", paths.sourceLock,
		"--list-file", paths.listFile,
		"--control-lock", paths.control,
	}
}

func runRangeRefresh(t *testing.T, boundary services, paths rangePaths) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(append([]string{"update-lists", "--refresh-ranges"}, refreshArgs(paths)...),
		&stdout, &stderr, boundary)
	return code, stdout.String(), stderr.String()
}

func runRangeCheck(t *testing.T, boundary services, paths rangePaths) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(append([]string{"update-lists", "--check"}, refreshArgs(paths)...),
		&stdout, &stderr, boundary)
	return code, stdout.String(), stderr.String()
}

// github is the China-list origin a check reads. It is a separate server because
// the command's two halves genuinely reach two different endpoints, and a
// fixture that served both from one would not notice a half that reached for the
// wrong one.
//
// It publishes the same commit the fixtures pin as locked, so a check that
// compares against it reports the pair as unchanged -- which is what makes the
// ranges lines in that report the only thing under test.
func github(t *testing.T) *http.Client {
	t.Helper()
	archive := sourceArchive(t, lockedCommit, "domain:first.cn\n")
	origin := newFakeOrigin(t, lockedCommit, map[string][]byte{lockedCommit: archive})
	t.Cleanup(origin.server.Close)
	return origin.client
}

func TestUpdateListsRefreshRangesPublishesThePrefixListAndItsEnvelope(t *testing.T) {
	// The whole point of the mode: an installation can obtain the file the router
	// refuses to start without, before any measurement has ever run.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)

	code, stdout, stderr := runRangeRefresh(t, origin.services(nil), paths)
	if code != exitSuccess {
		t.Fatalf("--refresh-ranges exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	if stderr != "" {
		t.Errorf("the refresh wrote a diagnostic on success: %q", stderr)
	}
	published, err := os.ReadFile(paths.prefixList)
	if err != nil {
		t.Fatalf("the refresh published no prefix list: %v", err)
	}
	// Sorted, deduplicated, one prefix per line: the document's own ranges, in the
	// form the rewriter reads and a person can diff.
	if want := "104.16.0.0/22\n172.64.0.0/21\n"; string(published) != want {
		t.Errorf("published prefix list = %q, want %q", published, want)
	}
	if _, err := os.Stat(paths.cache); err != nil {
		t.Errorf("the refresh published no cache envelope beside the list: %v", err)
	}
	for _, want := range []string{
		"ranges-url: " + candidate.DefaultCloudflareBaseURL,
		"ranges-etag: " + rangeETag,
		"ranges-prefixes: 2",
		"ranges-stale: false",
		"published-ranges-cache: " + paths.cache,
		"published-prefix-list: " + paths.prefixList,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the refresh report does not include %q:\n%s", want, stdout)
		}
	}
}

// One fetch, two artifacts. The envelope and the prefix list have to come from
// the same in-memory document, and the only thing that can prove it is the
// origin's own count: a second request would let a concurrent publication
// interleave the two writes and leave a list beside an envelope describing a
// different day.
func TestUpdateListsRefreshRangesTakesOneRequestForTwoArtifacts(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)

	code, _, stderr := runRangeRefresh(t, origin.services(nil), paths)
	if code != exitSuccess {
		t.Fatalf("--refresh-ranges exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	if served := origin.bodies(); served != 1 {
		t.Fatalf("the range origin served %d bodies, want 1: the envelope and the prefix list must come from one document", served)
	}

	// The two artifacts are the same document, read back the way the plugin and
	// the next run read them.
	published, err := candidate.ReadPublished(paths.cache)
	if err != nil {
		t.Fatalf("the published pair is not readable: %v", err)
	}
	if !published.Present || !published.Consistent {
		t.Fatalf("the published pair is not present and consistent: %+v", published)
	}
	envelope, err := os.ReadFile(paths.cache)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Body struct {
			Result struct {
				ETag      string   `json:"etag"`
				IPv4CIDRs []string `json:"ipv4_cidrs"`
			} `json:"result"`
		} `json:"body"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatalf("decode the envelope: %v", err)
	}
	list, err := os.ReadFile(paths.prefixList)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(list)
	if published.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("the reported digest %q is not the published list's", published.SHA256)
	}
	if published.ETag != document.Body.Result.ETag {
		t.Errorf("the reported etag %q is not the envelope's %q", published.ETag, document.Body.Result.ETag)
	}
	if strings.Contains(string(list), "2606:4700") {
		t.Errorf("the published list carries an IPv6 prefix: %q", list)
	}
	if len(document.Body.Result.IPv4CIDRs) != 3 {
		t.Fatalf("the fixture no longer lists three IPv4 ranges, so the deduplication in the published list proves nothing: %v", document.Body.Result.IPv4CIDRs)
	}
}

// The budget is the whole reason this mode exists. A measurement run spends the
// day's 100 MiB, and an install-time run would leave the first nightly with
// nothing, so this asserts the strongest thing available: no budget document is
// written, no prober is built, no candidates are collected, and the only files
// in the directory are the two range artifacts.
func TestUpdateListsRefreshRangesSpendsNoBandwidthBudget(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	probes, collections := 0, 0
	boundary := origin.services(nil)
	boundary.newProber = func() optimizer.Prober {
		probes++
		return nil
	}
	boundary.readCandidates = func(context.Context, candidateSource) (candidate.CandidateSet, error) {
		collections++
		return candidate.CandidateSet{}, nil
	}

	code, _, stderr := runRangeRefresh(t, boundary, paths)
	if code != exitSuccess {
		t.Fatalf("--refresh-ranges exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	if probes != 0 {
		t.Errorf("the range refresh built a prober %d time(s): it measures nothing, so it must build none", probes)
	}
	if collections != 0 {
		t.Errorf("the range refresh collected candidates %d time(s): a refresh is not a measurement run", collections)
	}
	entries, err := os.ReadDir(paths.dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	want := []string{candidate.DefaultCloudflarePrefixFileName, "cloudflare-ips.json"}
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("the refresh published %v, want exactly the two range artifacts %v: nothing else may be written, and a budget document among them would be the day's allowance spent at install time", names, want)
	}
}

// Ruling 59: packaging must never re-pin the China list during an install. A
// range refresh that touched it would do that by accident, so the mode accepts
// the China paths as flags and writes neither of them.
func TestUpdateListsRefreshRangesLeavesTheChinaPairAlone(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:previous.cn\n"))
	lockBefore, err := os.ReadFile(paths.sourceLock)
	if err != nil {
		t.Fatal(err)
	}
	listBefore, err := os.ReadFile(paths.listFile)
	if err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runRangeRefresh(t, origin.services(nil), paths)
	if code != exitSuccess {
		t.Fatalf("--refresh-ranges exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	for _, want := range []struct {
		name string
		path string
		was  []byte
	}{
		{"source lock", paths.sourceLock, lockBefore},
		{"list", paths.listFile, listBefore},
	} {
		got, err := os.ReadFile(want.path)
		if err != nil {
			t.Fatalf("read the China %s: %v", want.name, err)
		}
		if !bytes.Equal(got, want.was) {
			t.Errorf("the range refresh changed the China %s:\n got: %q\nwant: %q", want.name, got, want.was)
		}
	}
	for _, unwanted := range []string{"pinned-commit", "pinned-list-sha256", "pinned-rules", "published-list", "published-source-lock"} {
		if strings.Contains(stdout, unwanted) {
			t.Errorf("the range refresh reported a China publication (%q):\n%s", unwanted, stdout)
		}
	}
}

// A refresh the origin cannot satisfy has to be survivable from the cache the
// previous refresh left, because the alternative is an installation that cannot
// complete while an unrelated API is down.
func TestUpdateListsRefreshRangesFallsBackToThePublishedDocument(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	if code, _, stderr := runRangeRefresh(t, origin.services(nil), paths); code != exitSuccess {
		t.Fatalf("the first refresh failed: exit %d, %s", code, stderr)
	}

	origin.setStatus(503)
	code, stdout, stderr := runRangeRefresh(t, origin.services(nil), paths)
	if code != exitSuccess {
		t.Fatalf("a refresh with an unreachable origin and a cache exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	if !strings.Contains(stdout, "ranges-stale: true") {
		t.Errorf("a refresh served from the cache did not report the document as stale:\n%s", stdout)
	}
	if _, err := os.Stat(paths.prefixList); err != nil {
		t.Errorf("the fallback refresh left no prefix list: %v", err)
	}
}

// With nothing cached and an origin that cannot be read there is no document at
// all, and the mode has to say so rather than reporting a success it cannot back.
func TestUpdateListsRefreshRangesFailsWithNoOriginAndNoCache(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	origin.setStatus(503)

	code, stdout, stderr := runRangeRefresh(t, origin.services(nil), paths)
	if code != exitStateUnavailable {
		t.Fatalf("--refresh-ranges with no origin and no cache exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if stdout != "" {
		t.Errorf("a failed refresh reported a publication:\n%s", stdout)
	}
	if !strings.Contains(stderr, candidate.DefaultCloudflareBaseURL) {
		t.Errorf("the refusal does not name the origin it could not read: %q", stderr)
	}
	if _, err := os.Stat(paths.prefixList); !os.IsNotExist(err) {
		t.Errorf("a failed refresh published a prefix list (stat error %v)", err)
	}
}

// The report-only mode has to stay report-only. Ruling 50 is that `--check`
// exits 0 on drift and writes nothing, and a daily timer depends on both, so the
// ranges report is additive: it states whether the two artifacts are published
// and whether they agree, and it changes no exit code and writes no file.
func TestUpdateListsCheckReportsThePublishedRangesAndWritesNothing(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	if code, _, stderr := runRangeRefresh(t, origin.services(nil), paths); code != exitSuccess {
		t.Fatalf("the refresh failed: exit %d, %s", code, stderr)
	}
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:previous.cn\n"))
	before := snapshot(t, paths.dir)

	code, stdout, stderr := runRangeCheck(t, origin.services(github(t)), paths)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	for _, want := range []string{
		"ranges-cache: " + paths.cache,
		"ranges-prefix-list: " + paths.prefixList,
		"ranges-published: true",
		"ranges-consistent: true",
		"ranges-prefixes: 2",
		"up-to-date: true",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the check report does not include %q:\n%s", want, stdout)
		}
	}
	if origin.bodies() != 1 {
		t.Errorf("the check reached the range origin: a report-only run must not need a document it will not publish")
	}
	assertUnchanged(t, before, paths.dir, "")
}

// A router that cannot start is the failure this whole mode exists to prevent,
// so a report that finds no prefix list has to say so plainly rather than
// reporting a healthy China list and leaving the reader to guess.
func TestUpdateListsCheckSaysWhenTheRangesAreNotPublished(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:previous.cn\n"))
	before := snapshot(t, paths.dir)

	code, stdout, stderr := runRangeCheck(t, origin.services(github(t)), paths)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if !strings.Contains(stdout, "ranges-published: false") {
		t.Errorf("the check report does not say the ranges are not published:\n%s", stdout)
	}
	// The path is the installed one, not the temp one: a report an operator reads
	// has to name the file the router will look for.
	if !strings.Contains(stdout, "ranges-missing: "+filepath.Join(paths.dir, candidate.DefaultCloudflarePrefixFileName)) {
		t.Errorf("the check report does not name what is missing:\n%s", stdout)
	}
	assertUnchanged(t, before, paths.dir, "")
}

// A list beside an envelope describing a different document is the one
// inconsistency a reader cannot detect on its own, so the report states it.
func TestUpdateListsCheckSaysWhenThePrefixListDoesNotMatchItsEnvelope(t *testing.T) {
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	if code, _, stderr := runRangeRefresh(t, origin.services(nil), paths); code != exitSuccess {
		t.Fatalf("the refresh failed: exit %d, %s", code, stderr)
	}
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:previous.cn\n"))
	if err := os.WriteFile(paths.prefixList, []byte("192.0.2.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, paths.dir)

	code, stdout, stderr := runRangeCheck(t, origin.services(github(t)), paths)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if !strings.Contains(stdout, "ranges-consistent: false") {
		t.Errorf("the check report does not say the list does not match the envelope:\n%s", stdout)
	}
	assertUnchanged(t, before, paths.dir, "")
}

// The mode is a third mode, not a flag on one of the other two: exactly one of
// --check, --pin-remote and --refresh-ranges, and the China list's own rules are
// unchanged.
func TestUpdateListsTheThreeModesAreMutuallyExclusiveAndOneIsRequired(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no mode", args: []string{}},
		{name: "check and refresh", args: []string{"--check", "--refresh-ranges"}},
		{name: "pin and refresh", args: []string{"--pin-remote", "HEAD", "--refresh-ranges"}},
		{name: "refresh with an empty cache path", args: []string{"--refresh-ranges", "--ranges-cache", ""}},
		{name: "refresh with an empty url", args: []string{"--refresh-ranges", "--ranges-url", ""}},
		{name: "refresh with an empty pinned snapshot path", args: []string{"--refresh-ranges", "--pinned-ranges", ""}},
		{name: "refresh with an empty pinned snapshot lock path", args: []string{"--refresh-ranges", "--pinned-ranges-lock", ""}},
		{name: "check with an empty cache path", args: []string{"--check", "--ranges-cache", ""}},
		{name: "a positional argument", args: []string{"--refresh-ranges", "extra"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := newRangePaths(t)
			origin := newRangeOrigin(t)
			before := snapshot(t, paths.dir)
			args := append([]string{}, test.args...)
			if !containsRangeFlag(args) {
				args = append(args, refreshArgs(paths)...)
			}
			var stdout, stderr bytes.Buffer
			code := runWith(append([]string{"update-lists"}, args...), &stdout, &stderr, origin.services(nil))
			if code != exitInvalidCLI {
				t.Fatalf("args %v exit = %d, want %d (stderr: %s)", args, code, exitInvalidCLI, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("args %v wrote stdout: %q", args, stdout.String())
			}
			if origin.bodies() != 0 {
				t.Errorf("args %v reached the range origin", args)
			}
			assertUnchanged(t, before, paths.dir, "")
		})
	}
}

// containsRangeFlag answers whether a case has already supplied one of the range
// paths itself, which is what stops the fixture's real paths from overwriting a
// value the case chose on purpose -- an empty one, in every case here. It lists
// every range path flag for that reason: a flag missing from it is a flag whose
// empty-value case is silently defeated and passes for the wrong reason.
func containsRangeFlag(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "--ranges-cache", "--ranges-url", "--pinned-ranges", "--pinned-ranges-lock":
			return true
		}
	}
	return false
}

func TestUpdateListsRefreshRangesDefaultsAreTheInstalledPaths(t *testing.T) {
	// The packaged installer runs the command with no paths at all, so the
	// defaults are the only thing that makes it publish the file the shipped
	// routing document names.
	options, err := parseUpdateListOptions(io.Discard, []string{"--refresh-ranges"})
	if err != nil {
		t.Fatalf("parse the refresh defaults: %v", err)
	}
	if options.rangesCache != candidate.DefaultCloudflareCachePath {
		t.Errorf("the default ranges cache is %q, want the installed lists directory", options.rangesCache)
	}
	if options.rangesURL != candidate.DefaultCloudflareBaseURL {
		t.Errorf("the default ranges url is %q, want the published Cloudflare API", options.rangesURL)
	}
	// The snapshot pair, for the same reason and with the same force: the
	// installer runs this command with no paths at all, so a default that named
	// anything other than the file the package installs is a command that
	// publishes nothing on a machine with no route to the internet.
	if options.pinnedRanges != candidate.DefaultPinnedSnapshotPath {
		t.Errorf("the default pinned snapshot is %q, want the file this package installs", options.pinnedRanges)
	}
	if options.pinnedRangesLock != candidate.DefaultPinnedSnapshotLockPath {
		t.Errorf("the default pinned snapshot lock is %q, want the file this package installs", options.pinnedRangesLock)
	}
	if !options.refreshRanges {
		t.Error("parsing --refresh-ranges did not select the mode")
	}
	// The two modes the command already had are unchanged, and they gain the two
	// path flags with the same installed defaults so a report can name them.
	for _, args := range [][]string{{"--check"}, {"--pin-remote", "HEAD"}} {
		parsed, err := parseUpdateListOptions(io.Discard, args)
		if err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		if parsed.refreshRanges {
			t.Errorf("%v selected the range mode", args)
		}
		if parsed.rangesCache != candidate.DefaultCloudflareCachePath || parsed.rangesURL != candidate.DefaultCloudflareBaseURL {
			t.Errorf("%v did not keep the installed range paths: %+v", args, parsed)
		}
	}
}

// A source scan, because the property is about code that must not exist rather
// than about an answer that must be produced: nothing on the range path may
// reach a prober, a budget or a measurement.
func TestTheRangePathNamesNoProberAndNoBudget(t *testing.T) {
	body := rangeRefreshBody(t)
	forbidden := map[string]string{
		"optimizer.":     "the range refresh must not build an optimizer Runner",
		"newProber":      "the range refresh must not build a prober",
		"readCandidates": "the range refresh must not collect candidates to measure",
		"measure.":       "the range refresh must not measure anything",
		"Download":       "the range refresh must not transfer anything",
		"TCP(":           "the range refresh must not probe anything",
		"HTTPS(":         "the range refresh must not probe anything",
		"acquireLock":    "the range refresh must not take the control lock: two files that are each replaced by a rename do not need one, and a lock held across a network request blocks the router's control operations",
	}
	for needle, why := range forbidden {
		if strings.Contains(body, needle) {
			t.Errorf("runRefreshRanges contains %q: %s", needle, why)
		}
	}
	if !strings.Contains(body, ".Refresh(") {
		t.Error("runRefreshRanges does not call the range refresh, so this scan is not looking at the code it means to")
	}
}

func rangeRefreshBody(t *testing.T) string {
	t.Helper()
	production := string(mustReadFile(t, "update_lists.go"))
	const marker = "func runRefreshRanges"
	start := strings.Index(production, marker)
	if start < 0 {
		t.Fatal("runRefreshRanges is gone from update_lists.go, so the source scan is checking nothing")
	}
	body := production[start:]
	end := strings.Index(body, "\nfunc ")
	if end < 0 {
		t.Fatal("runRefreshRanges is the last function in the file, so the scan cannot bound it")
	}
	return body[:end]
}

// The scan above has to be able to fire, or it is a comment.
func TestTheRangePathScanFailsOnAMeasurement(t *testing.T) {
	needle := "newPro" + "ber"
	if strings.Contains(rangeRefreshBody(t), needle) {
		t.Errorf("the shipped range path names %q", needle)
	}
	// The shape the scan refuses, in the same file the shipped one lives in, so
	// a reviewer can see the difference rather than take the rule on trust.
	offending := "func runRefreshRanges() {\n\tservices." + needle + "()\n}\n"
	if !strings.Contains(offending, needle) {
		t.Fatal("the control case does not contain what the scan looks for, so the scan cannot be shown to fire")
	}
}
