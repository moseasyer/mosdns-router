package main

// The install-time half of `update-lists`, and the flag a package's own pinned
// snapshot arrives through. What these tests hold is the property the whole
// install transaction is waiting on -- a machine with no route to the range
// origin still gets the prefix list the response rewriter refuses to construct
// without -- and the three things that must not be given up to get it: the
// refusal on a snapshot this project cannot account for, the machine's own
// published document ahead of the package's, and a report that states how old
// the pin is and whether what is published has drifted from it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mosdns-router/internal/candidate"
)

// noRoute is a transport with nowhere to send a request, which is what a machine
// with no route to the internet looks like to an HTTP client. It is here rather
// than a status the fake origin serves, because "no route" is the failure the
// whole of this step is about and a 503 is a different one.
type noRoute struct{}

func (noRoute) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: network is unreachable")
}

// The pair a package ships, written into a fixture. The lock's two digests are
// computed over the bytes written here, which is the only way they can be right,
// and the prefix list is a literal so the reader is checked against a hand-written
// expectation rather than against its own renderer.
const (
	// pinFetchedAt is when the fixture's snapshot was taken, and pinClockOffset
	// how far after it the fixture's clock reads. The age is derived from these
	// two so a report line asserting an age is a number this file chose rather
	// than a number the code under test produced.
	pinFetchedAt   = "2026-09-30T00:03:59Z"
	pinClockOffset = 96 * time.Hour // pinPrefixList is what `rangeDocument` renders to: two ranges, the second
	// masked, the duplicate written once, in ascending order.
	pinPrefixList = "104.16.0.0/22\n172.64.0.0/21\n"
)

// writeRangePin writes the snapshot and lock a package ships into the paths the
// fixture's ranges directory names, and returns the two digests so a test can
// assert the report states the snapshot's own and not some other one.
func writeRangePin(t *testing.T, paths rangePaths, document, validator, source, fetchedAt string) (string, string) {
	t.Helper()
	body := []byte(document)
	snapshot, err := json.Marshal(struct {
		SchemaVersion int             `json:"schema_version"`
		URL           string          `json:"url"`
		ETag          string          `json:"etag"`
		Body          json.RawMessage `json:"body"`
	}{1, source, validator, json.RawMessage(body)})
	if err != nil {
		t.Fatalf("encode the pinned snapshot: %v", err)
	}
	snapshot = append(snapshot, '\n')
	lock, err := json.Marshal(struct {
		SchemaVersion    int    `json:"schema_version"`
		Source           string `json:"source"`
		Revision         string `json:"revision"`
		FetchedAt        string `json:"fetched_at"`
		SHA256           string `json:"sha256"`
		PrefixListSHA256 string `json:"prefix_list_sha256"`
	}{1, source, "refresh-etag", fetchedAt, sum(t, snapshot), sum(t, []byte(pinPrefixList))})
	if err != nil {
		t.Fatalf("encode the pin's lock: %v", err)
	}
	lock = append(lock, '\n')
	if err := os.MkdirAll(filepath.Dir(paths.pinSnapshot), 0o755); err != nil {
		t.Fatalf("create the pin's directory: %v", err)
	}
	if err := os.WriteFile(paths.pinSnapshot, snapshot, 0o644); err != nil {
		t.Fatalf("write the pinned snapshot: %v", err)
	}
	if err := os.WriteFile(paths.pinLock, lock, 0o644); err != nil {
		t.Fatalf("write the pin's lock: %v", err)
	}
	return sum(t, snapshot), sum(t, []byte(pinPrefixList))
}

func sum(t *testing.T, contents []byte) string {
	t.Helper()
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

// clockAt reads as a fixed moment pinAge after the pin was taken, so a report
// line about the pin's age is a number this file decided.
func clockAt() func() time.Time {
	taken, err := time.Parse(time.RFC3339, pinFetchedAt)
	if err != nil {
		panic(err)
	}
	moment := taken.Add(pinClockOffset)
	return func() time.Time { return moment }
}

// clockedServices is the fixture's boundary with its clock replaced, which is the
// one service a report's age comes from.
func (o *rangeOrigin) clockedServices(now func() time.Time, githubClient *http.Client) services {
	boundary := o.services(githubClient)
	boundary.now = now
	return boundary
}

func TestUpdateListsRefreshRangesPublishesFromTheSnapshotWithNoRoute(t *testing.T) {
	// The property: no route to the origin, nothing published on this machine,
	// and the snapshot the package ships -- so the router starts, the install
	// transaction continues, and everything downstream of the refusal runs for
	// the first time.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	snapshotDigest, listDigest := writeRangePin(t, paths, rangeDocument, rangeETag,
		candidate.DefaultCloudflareBaseURL, pinFetchedAt)
	origin.setStatus(503)

	code, stdout, stderr := runRangeRefresh(t, origin.clockedServices(clockAt(), nil), paths)
	if code != exitSuccess {
		t.Fatalf("--refresh-ranges with no route and a pinned snapshot exit = %d, want %d (stderr: %s)",
			code, exitSuccess, stderr)
	}
	published, err := os.ReadFile(paths.prefixList)
	if err != nil {
		t.Fatalf("read the published prefix list: %v", err)
	}
	if string(published) != pinPrefixList {
		t.Errorf("the published prefix list is %q, want the snapshot's own ranges %q", published, pinPrefixList)
	}
	// The report has to say three separate things, because a reader who saw only
	// one of them could be misled: where the ranges came from, that they are not
	// today's, and when the pin was taken.
	for _, want := range []string{
		"ranges-source: pinned-snapshot",
		"ranges-stale: true",
		"ranges-prefixes: 2",
		"ranges-pinned-snapshot: " + paths.pinSnapshot,
		"ranges-pinned-lock: " + paths.pinLock,
		"ranges-pinned-sha256: " + snapshotDigest,
		"ranges-pinned-revision: refresh-etag",
		"ranges-pinned-at: " + pinFetchedAt,
		"ranges-pinned-age: 96h0m0s",
		"ranges-pinned-prefix-list-sha256: " + listDigest,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the refresh report does not include %q:\n%s", want, stdout)
		}
	}
}

func TestUpdateListsRefreshRangesKeepsTheMachineOwnDocumentAheadOfTheSnapshot(t *testing.T) {
	// A carried-forward document survives an upgrade. The package's snapshot is
	// months old by construction, so a refresh that preferred it would rewrite
	// the range list a selector was built against on every dpkg upgrade of every
	// offline machine -- which is the re-pinning the China list's own rule
	// forbids, done to a file nobody asked to change.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	// The machine's own document is a different one from the pin's, so a
	// refresh that preferred the pin would publish visibly different ranges.
	own := `{"success":true,"errors":[],"messages":[],"result":{"etag":"own-etag",` +
		`"ipv4_cidrs":["198.41.128.0/17"],"ipv6_cidrs":["2606:4700::/32"]}}`
	if err := os.MkdirAll(paths.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(struct {
		SchemaVersion int             `json:"schema_version"`
		URL           string          `json:"url"`
		ETag          string          `json:"etag"`
		Body          json.RawMessage `json:"body"`
	}{1, candidate.DefaultCloudflareBaseURL, "own-validator", json.RawMessage([]byte(own))})
	if err != nil {
		t.Fatalf("encode the machine's own document: %v", err)
	}
	if err := os.WriteFile(paths.cache, append(envelope, '\n'), 0o644); err != nil {
		t.Fatalf("write the machine's own document: %v", err)
	}
	if err := os.WriteFile(paths.prefixList, []byte("198.41.128.0/17\n"), 0o644); err != nil {
		t.Fatalf("write the machine's own prefix list: %v", err)
	}
	writeRangePin(t, paths, rangeDocument, rangeETag, candidate.DefaultCloudflareBaseURL, pinFetchedAt)
	origin.setStatus(503)
	before := snapshot(t, paths.dir)

	code, stdout, stderr := runRangeRefresh(t, origin.clockedServices(clockAt(), nil), paths)
	if code != exitSuccess {
		t.Fatalf("--refresh-ranges exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	if !strings.Contains(stdout, "ranges-source: cache") {
		t.Errorf("the refresh did not say the published document stood in:\n%s", stdout)
	}
	if strings.Contains(stdout, "ranges-pinned-at") {
		t.Errorf("the refresh reported a pin it did not use:\n%s", stdout)
	}
	assertUnchanged(t, before, paths.dir, "")
}

func TestUpdateListsRefreshRangesRefusesASnapshotItCannotAccountFor(t *testing.T) {
	// The refusal that has protected every machine so far, with the third thing
	// that was tried added to it. A machine that ships a snapshot and cannot use
	// it is not a machine with no ranges: it is a machine whose package cannot
	// account for its own data, and the message has to distinguish the two.
	cases := map[string]func(t *testing.T, paths rangePaths){
		"a snapshot whose bytes the lock does not record": func(t *testing.T, paths rangePaths) {
			writeRangePin(t, paths, rangeDocument, rangeETag, candidate.DefaultCloudflareBaseURL, pinFetchedAt)
			contents, err := os.ReadFile(paths.pinSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			corrupt := bytes.Replace(contents, []byte("104.16.0.0/22"), []byte("104.16.0.0/21"), 1)
			if bytes.Equal(contents, corrupt) {
				t.Fatal("the fixture's document does not carry the range the case corrupts")
			}
			if err := os.WriteFile(paths.pinSnapshot, corrupt, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a snapshot that is not there": func(t *testing.T, paths rangePaths) {
			writeRangePin(t, paths, rangeDocument, rangeETag, candidate.DefaultCloudflareBaseURL, pinFetchedAt)
			if err := os.Remove(paths.pinSnapshot); err != nil {
				t.Fatal(err)
			}
		},
		"a lock that is not there": func(t *testing.T, paths rangePaths) {
			writeRangePin(t, paths, rangeDocument, rangeETag, candidate.DefaultCloudflareBaseURL, pinFetchedAt)
			if err := os.Remove(paths.pinLock); err != nil {
				t.Fatal(err)
			}
		},
		"a snapshot of another endpoint": func(t *testing.T, paths rangePaths) {
			writeRangePin(t, paths, rangeDocument, rangeETag, "https://127.0.0.1:1/ips", pinFetchedAt)
		},
		"no pair at all": func(t *testing.T, paths rangePaths) {},
	}
	for label, arrange := range cases {
		t.Run(label, func(t *testing.T) {
			paths := newRangePaths(t)
			arrange(t, paths)
			origin := newRangeOrigin(t)
			origin.setStatus(503)

			code, stdout, stderr := runRangeRefresh(t, origin.clockedServices(clockAt(), nil), paths)
			if code == exitSuccess {
				t.Fatalf("--refresh-ranges succeeded with %s:\n%s", label, stdout)
			}
			if stdout != "" {
				t.Errorf("a refused refresh reported a publication:\n%s", stdout)
			}
			for _, want := range []string{
				candidate.DefaultCloudflareBaseURL,
				paths.pinSnapshot,
				paths.pinLock,
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("the refusal does not mention %s: %q", want, stderr)
				}
			}
			// Nothing published: a refusal that left a prefix list behind would
			// satisfy the next install's start requirement with ranges nothing
			// accounts for.
			if _, err := os.Stat(paths.prefixList); !os.IsNotExist(err) {
				t.Errorf("a refused refresh published a prefix list (stat error %v)", err)
			}
			if _, err := os.Stat(paths.cache); !os.IsNotExist(err) {
				t.Errorf("a refused refresh published a cache envelope (stat error %v)", err)
			}
		})
	}
}

func TestUpdateListsRefreshRangesReportsWhereTheRangesCameFrom(t *testing.T) {
	// Three sources, three answers, because a report that only said "stale" left
	// a reader unable to tell a machine three days old from a machine that has
	// been installing from the same package copy for a year.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)

	code, stdout, stderr := runRangeRefresh(t, origin.clockedServices(clockAt(), nil), paths)
	if code != exitSuccess {
		t.Fatalf("the first refresh failed: exit %d, %s", code, stderr)
	}
	if !strings.Contains(stdout, "ranges-source: origin") {
		t.Errorf("a refresh that read the origin did not say so:\n%s", stdout)
	}
	if strings.Contains(stdout, "ranges-stale: true") {
		t.Errorf("a refresh that read the origin reported a stale document:\n%s", stdout)
	}

	// The second refresh is answered by the machine's own document, because the
	// origin is refused and the published one is what stands in.
	origin.setStatus(503)
	code, stdout, stderr = runRangeRefresh(t, origin.clockedServices(clockAt(), nil), paths)
	if code != exitSuccess {
		t.Fatalf("the second refresh failed: exit %d, %s", code, stderr)
	}
	if !strings.Contains(stdout, "ranges-source: cache") || !strings.Contains(stdout, "ranges-stale: true") {
		t.Errorf("a refresh served from the machine's own document did not say so:\n%s", stdout)
	}
}

func TestUpdateListsCheckReportsTheSnapshotItShipsAndHowOldItIs(t *testing.T) {
	// The drift measurement. A three-month-old pin is fine for a selector; a pin
	// nobody measures the age of is not, and a check that only reported the China
	// list left the one artefact this package ships unmeasured.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	snapshotDigest, listDigest := writeRangePin(t, paths, rangeDocument, rangeETag,
		candidate.DefaultCloudflareBaseURL, pinFetchedAt)
	if code, _, stderr := runRangeRefresh(t, origin.clockedServices(clockAt(), nil), paths); code != exitSuccess {
		t.Fatalf("the refresh failed: exit %d, %s", code, stderr)
	}
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:first.cn\n"))
	before := snapshot(t, paths.dir)

	code, stdout, stderr := runRangeCheck(t, origin.clockedServices(clockAt(), github(t)), paths)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	for _, want := range []string{
		"ranges-pin: " + paths.pinSnapshot,
		"ranges-pin-lock: " + paths.pinLock,
		"ranges-pin-verified: true",
		"ranges-pin-sha256: " + snapshotDigest,
		"ranges-pin-revision: refresh-etag",
		"ranges-pin-pinned-at: " + pinFetchedAt,
		"ranges-pin-age: 96h0m0s",
		"ranges-pin-prefixes: 2",
		"ranges-pin-prefix-list-sha256: " + listDigest,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the check report does not include %q:\n%s", want, stdout)
		}
	}
	assertUnchanged(t, before, paths.dir, "")
}

func TestUpdateListsCheckSaysWhenWhatIsPublishedHasDriftedFromTheSnapshot(t *testing.T) {
	// Drift in the direction that matters most: a machine that published a
	// document the package does not ship, which is every machine that ever
	// refreshed its ranges online. Reporting it as the same as the shipped pin
	// would be the false claim that a re-pin had happened, so the two digests are
	// both stated and the reader can see which is which.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	own := `{"success":true,"errors":[],"messages":[],"result":{"etag":"own-etag",` +
		`"ipv4_cidrs":["198.41.128.0/17"],"ipv6_cidrs":["2606:4700::/32"]}}`
	envelope, err := json.Marshal(struct {
		SchemaVersion int             `json:"schema_version"`
		URL           string          `json:"url"`
		ETag          string          `json:"etag"`
		Body          json.RawMessage `json:"body"`
	}{1, candidate.DefaultCloudflareBaseURL, "own-validator", json.RawMessage([]byte(own))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.cache, append(envelope, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.prefixList, []byte("198.41.128.0/17\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeRangePin(t, paths, rangeDocument, rangeETag, candidate.DefaultCloudflareBaseURL, pinFetchedAt)
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:first.cn\n"))
	origin.setStatus(503)

	code, stdout, stderr := runRangeCheck(t, origin.clockedServices(clockAt(), github(t)), paths)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if !strings.Contains(stdout, "ranges-pin-drift: published-differs") {
		t.Errorf("the check report does not say the published document is not the shipped pin:\n%s", stdout)
	}
	// Both digests, so "differs" is a measurement and not an assertion.
	if !strings.Contains(stdout, "ranges-pin-document-sha256: "+sum(t, []byte(rangeDocument))) {
		t.Errorf("the check report does not state the digest of the document the pin holds:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ranges-published-document-sha256: "+sum(t, []byte(own))) {
		t.Errorf("the check report does not state the digest of the document that is published:\n%s", stdout)
	}
	// Ruling 50: drift is not a failure, and a daily timer depends on that.
	if code != exitSuccess {
		t.Errorf("--check exit = %d for a drifted pin, want %d", code, exitSuccess)
	}
}

func TestUpdateListsCheckSaysWhenTheShippedSnapshotCannotBeVerified(t *testing.T) {
	// The unreadable case is an answer, not a question the report cannot answer.
	// A check that said nothing about a corrupt snapshot would leave an operator
	// believing the next install would work.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	writeRangePin(t, paths, rangeDocument, rangeETag, candidate.DefaultCloudflareBaseURL, pinFetchedAt)
	if err := os.Remove(paths.pinLock); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runRangeRefresh(t, origin.clockedServices(clockAt(), nil), paths); code != exitSuccess {
		t.Fatalf("the refresh failed: exit %d, %s", code, stderr)
	}
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:first.cn\n"))

	code, stdout, stderr := runRangeCheck(t, origin.clockedServices(clockAt(), github(t)), paths)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if !strings.Contains(stdout, "ranges-pin-verified: false") {
		t.Errorf("the check report does not say the shipped snapshot is unusable:\n%s", stdout)
	}
	if strings.Contains(stdout, "ranges-pin-drift:") {
		t.Errorf("the check report claims a drift measurement it could not make:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ranges-pin-unusable:") {
		t.Errorf("the check report does not say why the snapshot is unusable:\n%s", stdout)
	}
}

func TestUpdateListsCheckReportsTheRangesHalfWhenTheChinaSourceCannotBeRead(t *testing.T) {
	// A machine with no route to the internet is exactly the machine this
	// project's offline install creates, and on it the China half of the check
	// cannot run. The ranges half costs no request and answers a question about
	// the disk, so it is reported on the failure path too: a daily timer acting
	// on this report would otherwise say only "the China source could not be
	// read" on every machine this step makes installable, and the one artefact
	// the package ships would never be measured at all.
	//
	// It goes to stderr and stdout stays empty, because the property the check
	// already holds -- stdout carries a complete answer or nothing -- is what
	// stops a reader treating half a report as a verdict.
	paths := newRangePaths(t)
	origin := newRangeOrigin(t)
	writeRangePin(t, paths, rangeDocument, rangeETag, candidate.DefaultCloudflareBaseURL, pinFetchedAt)
	publishPair(t, paths.listPaths(), lockedCommit, []byte("domain:first.cn\n"))
	before := snapshot(t, paths.dir)
	// No GitHub origin at all: the check's request to the China source has
	// nowhere to go, which is the failure this case is about.
	boundary := origin.clockedServices(clockAt(), nil)
	boundary.newHTTPClient = func() *http.Client { return &http.Client{Transport: noRoute{}} }

	code, stdout, stderr := runRangeCheck(t, boundary, paths)
	if code != exitStateUnavailable {
		t.Fatalf("--check with no China source exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if stdout != "" {
		t.Errorf("a failed check wrote a partial report to stdout: %q", stdout)
	}
	for _, want := range []string{
		"ranges-pin-verified: true",
		"ranges-pin-pinned-at: " + pinFetchedAt,
		"ranges-pin-age: 96h0m0s",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the failed check's stderr does not include %q:\n%s", want, stderr)
		}
	}
	assertUnchanged(t, before, paths.dir, "")
}
