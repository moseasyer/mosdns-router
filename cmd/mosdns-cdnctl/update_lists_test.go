package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"mosdns-router/internal/config"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/rules"
)

// Every test here runs the real command against a fake GitHub origin: the
// command builds its real api.github.com and codeload.github.com URLs and the
// injected client only rewrites where they are sent. Nothing reaches the network,
// and the files it publishes are the ones a real pin would publish.

const (
	// lockedCommit is the commit a published pair in these fixtures claims.
	lockedCommit = "1111111111111111111111111111111111111111"
	// remoteCommit is the commit the fake origin publishes for HEAD.
	remoteCommit = "2222222222222222222222222222222222222222"
	// firstInstallArchive is the archive served for a first pin.
	firstInstallArchive = "domain:first.cn\nfull:exact.cn\ninclude:shared\n"
	// shared is the list the archive's China list includes.
	sharedList = "regexp:^static[0-9]+\\.example\\.cn$\n"
)

// fakeOrigin is a GitHub-shaped test origin: it publishes one commit for HEAD,
// and serves a source archive only for the commits it holds one for.
type fakeOrigin struct {
	server *httptest.Server
	client *http.Client
	head   string
	// archives is what the origin can serve, keyed by commit.
	archives map[string][]byte
	status   int
	requests []string
	// onServe runs before each answer, so a case can make the origin answer
	// differently the second time it is asked. Upstream moving during a run is not
	// something a static fixture can otherwise express, and it is exactly the race the
	// automatic refresh has to be immune to. It gets the request because "the third
	// time it is asked for HEAD" is the only way to say WHEN upstream moved, and a
	// hook that could only flip on the first request would move it before the run had
	// measured anything -- which is a different scenario that passes either way.
	onServe func(*fakeOrigin, *http.Request)
}

func newFakeOrigin(t *testing.T, head string, archives map[string][]byte) *fakeOrigin {
	t.Helper()
	origin := &fakeOrigin{head: head, archives: archives, status: http.StatusOK}
	origin.server = httptest.NewServer(http.HandlerFunc(origin.serve))
	t.Cleanup(origin.server.Close)
	origin.client = rewritingClient(t, origin.server.URL)
	return origin
}

func (o *fakeOrigin) serve(writer http.ResponseWriter, request *http.Request) {
	o.requests = append(o.requests, request.URL.Path)
	if o.onServe != nil {
		o.onServe(o, request)
	}
	if o.status != http.StatusOK {
		writer.WriteHeader(o.status)
		return
	}
	if commit, ok := strings.CutPrefix(request.URL.Path, "/v2fly/domain-list-community/tar.gz/"); ok {
		archive, known := o.archives[commit]
		if !known {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/gzip")
		writer.Header().Set("Content-Length", strconv.Itoa(len(archive)))
		_, _ = writer.Write(archive)
		return
	}
	if !strings.HasSuffix(request.URL.Path, "/commits/HEAD") {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, fmt.Sprintf(`{"sha":%q,"node_id":"C_1","parents":[]}`, o.head))
}

func (o *fakeOrigin) fetched(path string) bool {
	for _, requested := range o.requests {
		if requested == path {
			return true
		}
	}
	return false
}

func (o *fakeOrigin) archivePath(commit string) string {
	return "/v2fly/domain-list-community/tar.gz/" + commit
}

func (o *fakeOrigin) commitPath() string {
	return "/repos/" + rules.Repository + "/commits/HEAD"
}

// rewritingClient sends every request to the test origin, so the command under
// test keeps building its real GitHub URLs.
func rewritingClient(t *testing.T, serverURL string) *http.Client {
	t.Helper()
	target, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: rewriteTo{target: target, inner: &http.Transport{}}}
}

type rewriteTo struct {
	target *url.URL
	inner  *http.Transport
}

func (r rewriteTo) RoundTrip(request *http.Request) (*http.Response, error) {
	next := request.Clone(request.Context())
	next.URL.Scheme = r.target.Scheme
	next.URL.Host = r.target.Host
	return r.inner.RoundTrip(next)
}

// sourceArchive builds a source archive for a commit, carrying the lists it is
// given under the single top-level directory GitHub names them with.
func sourceArchive(t *testing.T, commit, cnList string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	files := map[string]string{
		"data/cn":     cnList,
		"data/shared": sharedList,
		"README.md":   "# fixture\n",
	}
	for name, body := range files {
		header := &tar.Header{
			Name:     "domain-list-community-" + commit + "/" + name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tarWriter, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// listPaths is where a test's command writes, and what it then inspects.
type listPaths struct {
	dir         string
	sourceLock  string
	listFile    string
	controlLock string
	// previousLock is the archive a pin writes the outgoing pin to. It is a field of
	// the fixture because the production default is /var/lib/mosdns/lists, and a test
	// that ran a pin without overriding it tried to write there -- which is the same
	// mistake render's fixtures made with /usr/lib/systemd/system, and the reason this
	// fixture hands every path to the command rather than letting it pick one.
	previousLock string
	lockContents func() []byte
	listContents func() []byte
}

func newListPaths(t *testing.T) listPaths {
	t.Helper()
	dir := t.TempDir()
	return listPaths{
		dir:          dir,
		sourceLock:   filepath.Join(dir, "source-lock.json"),
		listFile:     filepath.Join(dir, "cn-domains.txt"),
		controlLock:  filepath.Join(dir, "control.lock"),
		previousLock: filepath.Join(dir, "source-lock.previous.json"),
		lockContents: func() []byte { return mustReadFile(t, filepath.Join(dir, "source-lock.json")) },
		listContents: func() []byte { return mustReadFile(t, filepath.Join(dir, "cn-domains.txt")) },
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return contents
}

// publishPair writes a valid lock and list, so a test starts from an installed
// state rather than a first install.
func publishPair(t *testing.T, paths listPaths, commit string, list []byte) {
	t.Helper()
	lock := rules.SourceLock{
		SchemaVersion: 1,
		Repository:    rules.Repository,
		Commit:        commit,
		SHA256:        sha256Hex([]byte("the archive " + commit)),
		ListSHA256:    sha256Hex(list),
		Entry:         rules.Entry,
	}
	encoded, err := lock.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.sourceLock, encoded, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.listFile, list, 0o640); err != nil {
		t.Fatal(err)
	}
}

// services points the command at a fake origin and nothing else: the control
// lock, the publication and the conversion are the real ones.
func (o *fakeOrigin) services() services {
	services := productionServices()
	services.newHTTPClient = func() *http.Client { return o.client }
	return services
}

// snapshot records the directory so a test can prove a command wrote nothing.
func snapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	return snapshotWithout(t, dir, "")
}

// snapshotWithout records the directory, leaving out one file. A pin creates the
// control lock file even when it publishes nothing, so the failure cases look at
// the published pair and ignore that file.
func snapshotWithout(t *testing.T, dir, except string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	state := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.Name() == except {
			continue
		}
		// Directories are walked rather than read. The render fixture publishes a
		// systemd unit now, so the tree it snapshots has a subdirectory in it, and
		// os.ReadFile on one is "is a directory" -- a failure that reads as the
		// snapshot being broken when it is the tree that grew a level.
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			for name, contents := range snapshotTree(t, path) {
				state[entry.Name()+"/"+name] = contents
			}
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		state[entry.Name()] = contents
	}
	return state
}

func assertUnchanged(t *testing.T, before map[string][]byte, dir, except string) {
	t.Helper()
	after := snapshotWithout(t, dir, except)
	if len(after) != len(before) {
		t.Fatalf("directory changed: %v, want %v", names(after), names(before))
	}
	for name, contents := range before {
		if !bytes.Equal(after[name], contents) {
			t.Fatalf("%s changed:\n got: %q\nwant: %q", name, after[name], contents)
		}
	}
}

func names(state map[string][]byte) []string {
	list := make([]string, 0, len(state))
	for name := range state {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func runCLI(t *testing.T, services services, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(append([]string{"update-lists"}, args...), &stdout, &stderr, services)
	return code, stdout.String(), stderr.String()
}

func TestUpdateListsCheckReportsAnUnchangedSourceWithoutFetchingTheArchive(t *testing.T) {
	// A daily check must be cheap and silent about files: when the remote still
	// publishes the locked commit, the report is made from the commit document
	// alone. Fetching an archive here would make every check download one, and
	// writing anything would turn a check into an update.
	paths := newListPaths(t)
	published := []byte("domain:previous.cn\n")
	publishPair(t, paths, lockedCommit, published)
	before := snapshot(t, paths.dir)
	origin := newFakeOrigin(t, lockedCommit, map[string][]byte{lockedCommit: sourceArchive(t, lockedCommit, firstInstallArchive)})

	code, stdout, stderr := runCLI(t, origin.services(), "--check",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	for _, want := range []string{lockedCommit, "up-to-date: true", "repository: " + rules.Repository, "entry: " + rules.Entry} {
		if !strings.Contains(stdout, want) {
			t.Errorf("check output does not report %q:\n%s", want, stdout)
		}
	}
	if origin.fetched(origin.archivePath(lockedCommit)) {
		t.Error("check downloaded the archive although the locked commit is unchanged")
	}
	if stderr != "" {
		t.Errorf("check wrote a diagnostic: %q", stderr)
	}
	assertUnchanged(t, before, paths.dir, "")
}

func TestUpdateListsCheckReportsDriftWithTheRemoteArchiveDigest(t *testing.T) {
	// The remote has moved on. The report has to name the commit the gateway
	// runs on and the commit the remote publishes, plus the remote archive's
	// digest, and it still has to write nothing: accepting a new source is an
	// explicit pin.
	paths := newListPaths(t)
	published := []byte("domain:previous.cn\n")
	publishPair(t, paths, lockedCommit, published)
	before := snapshot(t, paths.dir)
	archive := sourceArchive(t, remoteCommit, firstInstallArchive)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: archive})

	code, stdout, stderr := runCLI(t, origin.services(), "--check",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	for _, want := range []string{
		"locked-commit: " + lockedCommit,
		"remote-commit: " + remoteCommit,
		"remote-archive-sha256: " + sha256Hex(archive),
		"up-to-date: false",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("drift report does not include %q:\n%s", want, stdout)
		}
	}
	if !origin.fetched(origin.archivePath(remoteCommit)) {
		t.Errorf("drift report did not read the remote archive: %v", origin.requests)
	}
	assertUnchanged(t, before, paths.dir, "")
}

func TestUpdateListsCheckRefusesToRunWithoutAValidPinnedPair(t *testing.T) {
	// A check that cannot see what it is comparing against is useless, and
	// inventing a comparison from an invalid pair would report drift against
	// something nobody pinned.
	tampered := []byte("domain:tampered.cn\n")
	invalidLock := []byte(`{"schema_version":1,"repository":"v2fly/domain-list-community","commit":"` + lockedCommit + `","sha256":"x","list_sha256":"y","entry":"data/cn"}`)
	tests := []struct {
		name    string
		arrange func(t *testing.T, paths listPaths)
	}{
		{
			name:    "nothing published",
			arrange: func(t *testing.T, paths listPaths) {},
		},
		{
			name: "list does not match its lock",
			arrange: func(t *testing.T, paths listPaths) {
				publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
				if err := os.WriteFile(paths.listFile, tampered, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "lock is not a valid pin",
			arrange: func(t *testing.T, paths listPaths) {
				if err := os.WriteFile(paths.sourceLock, invalidLock, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(paths.listFile, tampered, 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "lock without a list",
			arrange: func(t *testing.T, paths listPaths) {
				publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
				if err := os.Remove(paths.listFile); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := newListPaths(t)
			test.arrange(t, paths)
			before := snapshot(t, paths.dir)
			origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})

			code, stdout, stderr := runCLI(t, origin.services(), "--check",
				"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
			if code != exitStateUnavailable {
				t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
			}
			if stdout != "" {
				t.Errorf("refused check wrote a report: %q", stdout)
			}
			if !strings.Contains(stderr, paths.sourceLock) {
				t.Errorf("refusal does not name the source lock path: %q", stderr)
			}
			if len(origin.requests) != 0 {
				t.Errorf("refused check still reached the remote: %v", origin.requests)
			}
			assertUnchanged(t, before, paths.dir, "")
		})
	}
}

func TestUpdateListsPinRemotePublishesTheListAndItsLock(t *testing.T) {
	// A pin is the only way a new source reaches the router, so it has to leave a
	// pair that agrees with itself and a report that names exactly what was
	// published.
	paths := newListPaths(t)
	archive := sourceArchive(t, remoteCommit, firstInstallArchive)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: archive})

	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("--pin-remote exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}

	lock, list, found, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatalf("published pair: %v", err)
	}
	if !found {
		t.Fatal("pin published no pair")
	}
	if lock.Commit != remoteCommit || lock.SHA256 != sha256Hex(archive) {
		t.Fatalf("published lock does not name the resolved source: %+v", lock)
	}
	if lock.ListSHA256 != sha256Hex(list) {
		t.Fatalf("published lock does not describe the published list: %+v", lock)
	}
	wantList := "domain:first.cn\nfull:exact.cn\nregexp:^static[0-9]+\\.example\\.cn$\n"
	if string(list) != wantList {
		t.Fatalf("published list = %q, want %q", list, wantList)
	}
	for _, want := range []string{
		"pinned-commit: " + remoteCommit,
		"pinned-archive-sha256: " + sha256Hex(archive),
		"pinned-list-sha256: " + sha256Hex([]byte(wantList)),
		"pinned-rules: 3",
		"published-source-lock: " + paths.sourceLock,
		"published-list: " + paths.listFile,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("pin report does not include %q:\n%s", want, stdout)
		}
	}
	if stderr != "" {
		t.Errorf("pin wrote a diagnostic: %q", stderr)
	}
	if _, err := os.Stat(paths.controlLock); err != nil {
		t.Errorf("pin did not take the control lock: %v", err)
	}
}

func TestUpdateListsPinRemoteReplacesAnInstalledPair(t *testing.T) {
	// The second pin of an installation is the one that has to leave no trace of
	// the old list: a router reading a mixture of two sources would route against
	// rules nobody pinned together.
	paths := newListPaths(t)
	previous := []byte("domain:previous.cn\n")
	publishPair(t, paths, lockedCommit, previous)
	archive := sourceArchive(t, remoteCommit, firstInstallArchive)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: archive})

	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("--pin-remote exit = %d, want %d (stderr: %s)", code, exitSuccess, stderr)
	}
	lock, list, found, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil || !found {
		t.Fatalf("published pair: %v found=%t", err, found)
	}
	if lock.Commit != remoteCommit {
		t.Fatalf("published lock still names %s, want %s", lock.Commit, remoteCommit)
	}
	if bytes.Equal(list, previous) {
		t.Fatal("the previous list is still published")
	}
	// Four files, not three: the archive is written by every pin and is named in the
	// gate rather than excluded from it, because a pin that stopped writing it would
	// otherwise still satisfy "the pair and the control lock" and the rollback would
	// quietly stop existing.
	if state := snapshot(t, paths.dir); len(state) != 4 {
		t.Fatalf("published directory holds %v, want the pair, the control lock and the archive",
			names(state))
	}
	archived, err := rules.ReadPrevious(paths.previousLock)
	if err != nil {
		t.Fatalf("the pin wrote no readable archive: %v", err)
	}
	if archived.Commit == remoteCommit {
		t.Error("the archive names the commit this run just published, which is not a rollback target")
	}
	if !strings.Contains(stdout, "pinned-commit: "+remoteCommit) {
		t.Errorf("pin report does not name the accepted commit:\n%s", stdout)
	}
}

func TestUpdateListsPinRemoteKeepsTheInstalledPairOnEveryFailure(t *testing.T) {
	// Every way a pin can fail has to leave the router's list and the lock that
	// describes it exactly as they were, and has to say so on stderr instead of
	// reporting a commit. The last case covers a pair the command cannot even
	// read: it must refuse rather than replace it.
	tests := []struct {
		name    string
		arrange func(t *testing.T, paths listPaths, origin *fakeOrigin)
	}{
		{
			name: "the remote refuses to name a commit",
			arrange: func(t *testing.T, paths listPaths, origin *fakeOrigin) {
				origin.status = http.StatusInternalServerError
			},
		},
		{
			name: "the remote has no such archive",
			arrange: func(t *testing.T, paths listPaths, origin *fakeOrigin) {
				// The origin publishes a commit it cannot serve an archive for.
				origin.archives = map[string][]byte{lockedCommit: sourceArchive(t, lockedCommit, firstInstallArchive)}
			},
		},
		{
			name: "the archive is not the list the gateway understands",
			arrange: func(t *testing.T, paths listPaths, origin *fakeOrigin) {
				origin.archives = map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, "ip4:1.2.3.4\n")}
			},
		},
		{
			name: "the archive does not carry the pinned entry",
			arrange: func(t *testing.T, paths listPaths, origin *fakeOrigin) {
				origin.archives = map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, "# nothing here\n")}
			},
		},
		{
			name: "the published pair cannot be read",
			arrange: func(t *testing.T, paths listPaths, origin *fakeOrigin) {
				publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
				if err := os.Remove(paths.listFile); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "the published list does not match its lock",
			arrange: func(t *testing.T, paths listPaths, origin *fakeOrigin) {
				publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
				// Somebody edited the list the router is running without re-pinning.
				if err := os.WriteFile(paths.listFile, []byte("domain:edited-by-hand.cn\n"), 0o640); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := newListPaths(t)
			published := []byte("domain:previous.cn\n")
			publishPair(t, paths, lockedCommit, published)
			origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})
			test.arrange(t, paths, origin)
			before := snapshotWithout(t, paths.dir, filepath.Base(paths.controlLock))

			code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
				"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
			if code == exitSuccess {
				t.Fatalf("pin reported success although it could not publish:\n%s", stdout)
			}
			if code != exitStateUnavailable {
				t.Errorf("pin exit = %d, want %d for a failing pin (stderr: %s)", code, exitStateUnavailable, stderr)
			}
			if strings.Contains(stdout, "pinned-commit") {
				t.Errorf("failed pin reported an accepted commit:\n%s", stdout)
			}
			if stderr == "" {
				t.Error("failed pin wrote no diagnostic")
			}
			assertUnchanged(t, before, paths.dir, filepath.Base(paths.controlLock))
		})
	}
}

// The reason this change exists: --pin-remote could only name upstream's current
// HEAD, so once a commit nobody reviewed was accepted there was no way back to the
// one this machine was on yesterday.
func TestPinRemoteNamesTheCommitItWillPublish(t *testing.T) {
	options, err := parseUpdateListOptions(io.Discard, []string{"--pin-remote", lockedCommit})
	if err != nil {
		t.Fatalf("--pin-remote %s was refused: %v", lockedCommit, err)
	}
	if options.pinRemote != lockedCommit {
		t.Errorf("--pin-remote did not keep the commit: %q", options.pinRemote)
	}
}

// HEAD still means HEAD, and it is normalized to the empty string so there is one
// place in the code that asks "which commit?" rather than two that disagree about
// what the empty value means.
func TestPinRemoteStillAcceptsTheLiteralHEAD(t *testing.T) {
	options, err := parseUpdateListOptions(io.Discard, []string{"--pin-remote", "HEAD"})
	if err != nil {
		t.Fatalf("the documented --pin-remote HEAD was refused: %v", err)
	}
	if options.pinRemote != "" {
		t.Errorf("--pin-remote HEAD left %q in the options, want the empty value that means HEAD", options.pinRemote)
	}
}

// Anything that is neither HEAD nor a full commit is refused on the command line,
// before a request is made: a branch, a tag, an abbreviated commit and HEAD~1 all
// name a moving target or a form this package does not verify, and accepting any of
// them would put a ref where the lock records a commit.
func TestPinRemoteRefusesSomethingThatIsNeitherHEADNorACommit(t *testing.T) {
	for _, ref := range []string{"main", "master", "v0.2.0", "HEAD~1", "zzzzzzzz", "1111111111"} {
		t.Run(ref, func(t *testing.T) {
			options, err := parseUpdateListOptions(io.Discard, []string{"--pin-remote", ref})
			if err == nil {
				t.Fatalf("--pin-remote %q was accepted as %q", ref, options.pinRemote)
			}
			if !strings.Contains(err.Error(), "--pin-remote") {
				t.Errorf("the refusal does not name the flag: %v", err)
			}
		})
	}
	// The empty value is refused too, and by a different rule: it selects no mode at
	// all, so the diagnostic is about the missing mode rather than about the ref. It
	// is listed here because both are refusals and an operator should not be able to
	// tell from the exit code that one of them was a mistake about the value.
	if options, err := parseUpdateListOptions(io.Discard, []string{"--pin-remote", ""}); err == nil {
		t.Errorf("--pin-remote with an empty value selected the mode %+v", options)
	}
}

// Naming a commit publishes THAT commit even when it is not the remote's HEAD. The
// rollback path is the whole use, and a rollback that published the current HEAD
// would move the machine forward instead of back.
func TestPinRemotePublishesTheNamedCommitRatherThanTheRemoteHead(t *testing.T) {
	paths := newListPaths(t)
	olderArchive := sourceArchive(t, lockedCommit, "domain:older.cn\n")
	newerArchive := sourceArchive(t, remoteCommit, firstInstallArchive)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		lockedCommit: olderArchive,
		remoteCommit: newerArchive,
	})

	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", lockedCommit,
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock, "--previous-lock", filepath.Join(paths.dir, "previous.json"))
	if code != exitSuccess {
		t.Fatalf("pinning a named commit exited %d (stderr: %s)", code, stderr)
	}
	lock, _, found, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil || !found {
		t.Fatalf("published pair: found=%v err=%v", found, err)
	}
	if lock.Commit != lockedCommit {
		t.Fatalf("published %s, want the named %s -- a rollback that moved forward is not a rollback",
			lock.Commit, lockedCommit)
	}
	if lock.SHA256 != sha256Hex(olderArchive) {
		t.Errorf("the lock records archive %s, which is the other commit's", lock.SHA256)
	}
	if !strings.Contains(stdout, "pinned-commit: "+lockedCommit) {
		t.Errorf("the report does not name the commit it published:\n%s", stdout)
	}
	// And it did not ask the API where HEAD is. A named commit needs no resolution
	// round trip, and one that needed it would fail on a machine that can reach the
	// archive host but not the API -- which is the situation an operator doing this
	// is most likely to be in.
	if origin.fetched(origin.commitPath()) {
		t.Errorf("pinning a named commit asked the API for HEAD: %v", origin.requests)
	}
}

// Review Focus, class 2: the archive must name the pin that was CURRENT when this run
// started, not one an earlier run left behind. A stale archive is worse than none,
// because the operator believes they are rolling back to a commit they chose and
// lands on a different one.
func TestPublishingArchivesThePinThatWasCurrent(t *testing.T) {
	paths := newListPaths(t)
	installed := []byte("domain:previous.cn\n")
	publishPair(t, paths, lockedCommit, installed)
	previous := filepath.Join(paths.dir, "previous.json")
	stale := rules.SourceLock{
		SchemaVersion: 1,
		Repository:    rules.Repository,
		Commit:        "3333333333333333333333333333333333333333",
		SHA256:        sha256Hex([]byte("an archive from a run nobody remembers")),
		ListSHA256:    sha256Hex([]byte("domain:stale.cn\n")),
		Entry:         rules.Entry,
	}
	encoded, err := stale.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previous, encoded, 0o640); err != nil {
		t.Fatal(err)
	}

	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive),
	})
	code, _, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock, "--previous-lock", previous)
	if code != exitSuccess {
		t.Fatalf("pin exited %d (stderr: %s)", code, stderr)
	}

	archived, err := rules.ReadPrevious(previous)
	if err != nil {
		t.Fatalf("no readable archive after a successful publish: %v", err)
	}
	if archived.Commit != lockedCommit {
		t.Errorf("the archive names %s, want the pin that was current (%s); a rollback would "+
			"land on a commit the operator did not choose", archived.Commit, lockedCommit)
	}
	if archived.ListSHA256 != sha256Hex(installed) {
		t.Errorf("the archive records list %s, which is not the list that was installed",
			archived.ListSHA256)
	}
}

// The archive is written BEFORE the publish, so a publish that fails leaves an
// archive naming a commit that really was current -- which is exactly what an
// operator rolling back after a failed unattended refresh needs. Archived after, a
// failed publish would leave the archive naming the pin that was about to be replaced
// by a change that never landed.
func TestAFailedPublishLeavesThePinAndTheArchiveIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this case makes a directory unwritable to fail the publication, which " +
			"does not stop root")
	}
	paths := newListPaths(t)
	installed := []byte("domain:previous.cn\n")
	publishPair(t, paths, lockedCommit, installed)
	// The list lives in a directory of its own, because a read-only directory is how
	// this case fails the publication and only the publication: a missing directory
	// would fail the pair check first and never reach a publish.
	listDir := filepath.Join(paths.dir, "readonly")
	if err := os.Mkdir(listDir, 0o755); err != nil {
		t.Fatal(err)
	}
	listFile := filepath.Join(listDir, "cn-domains.txt")
	if err := os.WriteFile(listFile, installed, 0o640); err != nil {
		t.Fatal(err)
	}

	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive),
	})
	// Taken away BEFORE the run. ReadPublishedPair has to succeed -- it is what proves
	// there is an outgoing pair worth protecting -- and only the publication may fail,
	// so the directory is made unwritable once the files are already in it. Chmod after
	// the run would test nothing: it was the first attempt at this case and it passed
	// a pin that had published successfully.
	if err := os.Chmod(listDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(listDir, 0o755) })

	previous := paths.previousLock
	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", listFile,
		"--control-lock", paths.controlLock, "--previous-lock", previous)
	if code == exitSuccess {
		t.Fatalf("pin reported success with the publication failing: %s", stdout)
	}
	// It is the PUBLICATION that failed here, not the archive, so the refusal names
	// the list. The case where the archive is what fails is the next one, and it
	// asserts the same thing about the other file: a refusal an operator cannot map
	// to a file is a refusal they cannot act on.
	if !strings.Contains(stderr, listFile) {
		t.Errorf("the refusal does not name the file it could not write: %q", stderr)
	}
	// The archive was written before the publish, so it exists and names the pin that
	// really was current. That is the whole claim: after a failed publish, an operator
	// can still get back to where they were.
	archived, err := rules.ReadPrevious(previous)
	if err != nil {
		t.Fatalf("a failed publish left no readable archive: %v", err)
	}
	if archived.Commit != lockedCommit {
		t.Errorf("the archive names %s, want the pin that was current (%s)", archived.Commit, lockedCommit)
	}
	after, _, found, err := rules.ReadPublishedPair(paths.sourceLock, listFile)
	if err != nil || !found {
		t.Fatalf("the pair is unreadable after a failed publish: found=%v err=%v", found, err)
	}
	if after.Commit != lockedCommit {
		t.Errorf("a failed publish moved the pin from %s to %s", lockedCommit, after.Commit)
	}
	if got := string(mustReadFile(t, listFile)); got != string(installed) {
		t.Errorf("a failed publish changed the list:\n%s", got)
	}
}

// An archive that cannot be written stops the pin rather than being skipped. The
// alternative -- publish, and lose the rollback target -- is the one outcome this
// whole mechanism exists to prevent, and it is unrecoverable afterwards: once the
// old lock is replaced there is no record of it anywhere.
func TestAFailedArchiveRefusesRatherThanPublishing(t *testing.T) {
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
	// A directory where the archive file goes: the rename onto it cannot succeed, and
	// it fails the same way whatever uid the suite runs as.
	previous := filepath.Join(paths.dir, "previous.json")
	if err := os.Mkdir(previous, 0o755); err != nil {
		t.Fatal(err)
	}

	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive),
	})
	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock, "--previous-lock", previous)
	if code == exitSuccess {
		t.Fatalf("pin reported success although it kept no rollback target: %s", stdout)
	}
	if !strings.Contains(stderr, previous) {
		t.Errorf("the refusal does not name the archive it could not write: %q", stderr)
	}
	lock, _, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit != lockedCommit {
		t.Errorf("the pin moved to %s although the archive failed, so the previous pin is gone", lock.Commit)
	}
}

func TestUpdateListsPinRemoteReportsAPublicationFailureInsteadOfSuccess(t *testing.T) {
	// A pin that verified its source and then could not write the pair has to say
	// so. Reporting an accepted commit for a list that was never published is the
	// one outcome an operator cannot recover from, because the next check would
	// compare a lock nobody wrote against a list nobody installed.
	paths := newListPaths(t)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})
	listFile := filepath.Join(paths.dir, "not-installed", "cn-domains.txt")

	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitStateUnavailable {
		t.Fatalf("pin with an unwritable list exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if strings.Contains(stdout, "pinned-commit") {
		t.Errorf("pin reported an accepted commit although it published nothing:\n%s", stdout)
	}
	if !strings.Contains(stderr, listFile) {
		t.Errorf("refusal does not name the list path: %q", stderr)
	}
	if _, err := os.Stat(filepath.Dir(listFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pin created the missing list directory: %v", err)
	}
	if _, err := os.Stat(paths.sourceLock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pin published a lock without a list: %v", err)
	}
}

func TestUpdateListsPinRemoteFailsWithExitFourWhileTheControlLockIsHeld(t *testing.T) {
	// The control lock is what keeps a pin from publishing a pair while the
	// router is being reconfigured. A pin that cannot take it has to stop with
	// the lock exit code, not with a generic failure, so an operator can tell a
	// busy gateway from a broken source.
	paths := newListPaths(t)
	published := []byte("domain:previous.cn\n")
	publishPair(t, paths, lockedCommit, published)
	held, err := filelock.Acquire(paths.controlLock)
	if err != nil {
		t.Fatalf("take the control lock: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })
	before := snapshot(t, paths.dir)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})

	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitLockHeld {
		t.Fatalf("pin under a held lock exit = %d, want %d (stderr: %s)", code, exitLockHeld, stderr)
	}
	if !strings.Contains(stderr, paths.controlLock) {
		t.Errorf("refusal does not name the control lock path: %q", stderr)
	}
	if strings.Contains(stdout, "pinned-commit") {
		t.Errorf("pin under a held lock reported an accepted commit:\n%s", stdout)
	}
	assertUnchanged(t, before, paths.dir, "")
}

func TestUpdateListsTakesTheControlLockOnlyAfterTheSourceIsVerified(t *testing.T) {
	// The control lock is not a download lock: a check runs daily and must not
	// exclude a running gateway, and a pin that grabbed it before reading the
	// remote would block the router for the length of a download. A failing
	// conversion under a held lock therefore has to report the conversion, which
	// also proves the lock is taken after the conversion.
	paths := newListPaths(t)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, "ip4:1.2.3.4\n")})

	held, err := filelock.Acquire(paths.controlLock)
	if err != nil {
		t.Fatalf("take the control lock: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })

	code, _, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code == exitLockHeld {
		t.Fatalf("pin reported the held lock although it never reached publication: %s", stderr)
	}
	if code != exitStateUnavailable {
		t.Fatalf("pin exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if !strings.Contains(stderr, "ip4") {
		t.Errorf("failure is not the conversion failure: %q", stderr)
	}
}

func TestUpdateListsCheckWritesNoPartialReportWhenTheDriftedArchiveCannotBeRead(t *testing.T) {
	// The remote has moved on, so the check has to read its archive to report the
	// digest a pin would record, and the origin has no archive for the commit it
	// just published. A report cut in half, with no verdict in it, is worse than
	// no report: stdout either carries a complete answer or nothing.
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
	before := snapshot(t, paths.dir)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{lockedCommit: sourceArchive(t, lockedCommit, firstInstallArchive)})

	code, stdout, stderr := runCLI(t, origin.services(), "--check",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitStateUnavailable {
		t.Fatalf("--check exit = %d, want %d (stderr: %s)", code, exitStateUnavailable, stderr)
	}
	if stdout != "" {
		t.Fatalf("failed check wrote a partial report: %q", stdout)
	}
	if !strings.Contains(stderr, remoteCommit) {
		t.Errorf("refusal does not name the commit it could not read an archive for: %q", stderr)
	}
	assertUnchanged(t, before, paths.dir, "")
}

// --- unattended refresh -------------------------------------------------

// automaticPolicy writes a policy with the two switches set as asked, and the rest of
// the reviewed defaults, so a case is about the switches and not about a policy it
// had to invent.
func automaticPolicy(t *testing.T, china, cloudflare bool) string {
	t.Helper()
	policy := config.Defaults()
	policy.Lists.China.Automatic = china
	policy.Lists.Cloudflare.Automatic = cloudflare
	encoded, err := config.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// rulesOf builds a China list with n expressions in it, for the cases about how many
// rules an incoming list has.
func rulesOf(n int) []byte {
	var list bytes.Buffer
	for index := 0; index < n; index++ {
		fmt.Fprintf(&list, "domain:host%05d.example.cn\n", index)
	}
	return list.Bytes()
}

// With both switches off, --automatic must do exactly what --check did. The shipped
// default has to behave identically to the mode it replaces, or turning the feature
// on and off changes the machine's behaviour rather than its configuration.
func TestAutomaticWithBothSwitchesOffIsTheCheck(t *testing.T) {
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, rulesOf(200))
	origin := newFakeOrigin(t, lockedCommit, map[string][]byte{
		lockedCommit: sourceArchive(t, lockedCommit, "domain:first.cn\n"),
	})

	code, stdout, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", automaticPolicy(t, false, false),
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("--automatic with both switches off exited %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "up-to-date:") {
		t.Errorf("the daily report lost its drift line:\n%s", stdout)
	}
	// Nothing was written. Not the pair, not the archive -- an archive taken on a run
	// that refreshed nothing is a rollback target that was never about to be replaced.
	if _, err := rules.ReadPrevious(paths.previousLock); err == nil {
		t.Error("a run that refreshed nothing left an archive")
	}
	lock, _, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit != lockedCommit {
		t.Errorf("the pin moved to %s with both switches off", lock.Commit)
	}
}

// The report is produced either way. A machine that has the switches on should not
// stop being told what its pin is, because that report is the only place the answer
// is written down at all.
func TestAutomaticStillReportsDriftWhenItRefreshes(t *testing.T) {
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, rulesOf(200))
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, string(rulesOf(200))),
	})

	code, stdout, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", automaticPolicy(t, true, false),
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("--automatic with lists.china.automatic on exited %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "up-to-date:") {
		t.Errorf("the drift line is gone once the switch is on:\n%s", stdout)
	}
	lock, _, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit != remoteCommit {
		t.Errorf("lists.china.automatic was on and the pin stayed at %s", lock.Commit)
	}
	archived, err := rules.ReadPrevious(paths.previousLock)
	if err != nil {
		t.Fatalf("the refresh left no rollback target: %v", err)
	}
	if archived.Commit != lockedCommit {
		t.Errorf("the archive names %s, want the pin that was current (%s)", archived.Commit, lockedCommit)
	}
}

// The two switches are two switches. Cloudflare's ranges choose an edge; data/cn
// chooses which names take the foreign branch. Turning on the cheap one must not
// open the expensive one.
func TestAutomaticHonoursEachSwitchSeparately(t *testing.T) {
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, rulesOf(200))
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, string(rulesOf(200))),
	})

	code, stdout, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", automaticPolicy(t, false, true),
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock,
		"--ranges-cache", filepath.Join(paths.dir, "ranges"))
	if code != exitSuccess {
		t.Fatalf("--automatic with lists.cloudflare.automatic on exited %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "published-prefix-list:") {
		t.Errorf("the ranges were not published:\n%s", stdout)
	}
	lock, _, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit != lockedCommit {
		t.Errorf("the China list was re-pinned to %s with lists.china.automatic off", lock.Commit)
	}
	if _, err := rules.ReadPrevious(paths.previousLock); err == nil {
		t.Error("refreshing only the ranges left an archive of the China pin")
	}
}

// Review Focus, class 1. An upstream commit whose data/cn is a fraction of its former
// size VERIFIES -- it really is the upstream document -- and would send far more names
// down the foreign branch than anybody reviewed. The guard refuses and says so; the
// operator can then publish that commit deliberately, having read the diff.
func TestAListThatShrinksSharplyIsRefused(t *testing.T) {
	paths := newListPaths(t)
	published := rulesOf(200)
	publishPair(t, paths, lockedCommit, published)
	// Upstream now publishes one rule where this machine has two hundred.
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, "domain:first.cn\n"),
	})

	code, _, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", automaticPolicy(t, true, false),
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code == exitSuccess {
		t.Fatal("a list that fell from 200 rules to 1 was published")
	}
	if !strings.Contains(stderr, "fewer rules") {
		t.Errorf("the refusal does not say what it noticed: %q", stderr)
	}
	lock, list, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit != lockedCommit {
		t.Errorf("the refused list was published anyway, moving the pin to %s", lock.Commit)
	}
	if !bytes.Equal(list, published) {
		t.Error("the refused list replaced the published one")
	}
	// And no archive: the refusal happened before anything was written, so there is
	// no rollback target to be had and none is claimed.
	if _, err := rules.ReadPrevious(paths.previousLock); err == nil {
		t.Error("a refused refresh left an archive")
	}
}

// A real curation commit removes a few rules and must NOT trip the guard, or the
// guard is just a way of never updating -- which is the same as being off with more
// machinery attached.
func TestASmallReductionIsPublished(t *testing.T) {
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, rulesOf(1000))
	// 980 of 1000: a 2% reduction, comfortably clear of the threshold, because a case
	// balanced exactly on a boundary passes for the wrong reason when the boundary
	// moves by one.
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, string(rulesOf(980))),
	})

	code, _, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", automaticPolicy(t, true, false),
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("a 2%% reduction was refused: %s", stderr)
	}
	lock, _, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit != remoteCommit {
		t.Errorf("the reduced list was not published, the pin is still %s", lock.Commit)
	}
}

// Review Focus, class 5. A machine with no route out runs this daily. It must fail,
// it must say so, and it must leave the pin and the archive exactly as they were.
func TestAFailedAutomaticRunTouchesNothing(t *testing.T) {
	paths := newListPaths(t)
	published := rulesOf(200)
	publishPair(t, paths, lockedCommit, published)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, string(rulesOf(200))),
	})
	origin.status = http.StatusInternalServerError

	code, stdout, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", automaticPolicy(t, true, false),
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code == exitSuccess {
		t.Fatalf("a run that could not reach upstream reported success:\n%s", stdout)
	}
	if !strings.Contains(stderr, "unexpected status") {
		t.Errorf("the failure is not in the report: %q", stderr)
	}
	lock, list, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit != lockedCommit {
		t.Errorf("the pin changed on a failed run: %s -> %s", lockedCommit, lock.Commit)
	}
	if !bytes.Equal(list, published) {
		t.Error("the list changed on a failed run")
	}
	if _, err := rules.ReadPrevious(paths.previousLock); err == nil {
		t.Error("a failed run left an archive, so a rollback would land on a commit that " +
			"was only ever about to be replaced")
	}
}

// The guard measured one commit, so the publication has to be that commit.
//
// Upstream publishes a healthy list, and then -- while this run is working -- moves
// to a commit whose list has collapsed. If the refresh re-resolved HEAD after
// measuring, the size check would have applied to one commit and the publication to
// another, so upstream moving during the run would publish an unmeasured list through
// the very mechanism built to prevent that. The run therefore has to end up on the
// commit it measured, and on nothing else.
func TestTheAutomaticRefreshPublishesTheCommitItMeasured(t *testing.T) {
	paths := newListPaths(t)
	published := rulesOf(200)
	publishPair(t, paths, lockedCommit, published)
	measured := remoteCommit
	collapsed := "3333333333333333333333333333333333333333"
	origin := newFakeOrigin(t, measured, map[string][]byte{
		measured:  sourceArchive(t, measured, string(rulesOf(200))),
		collapsed: sourceArchive(t, collapsed, "domain:only.cn\n"),
	})
	// Upstream answers `measured` for its first three resolutions of HEAD and
	// `collapsed` from the fourth on. Three is the drift report's two plus the
	// refresh's one, so `measured` is what this run measures; the fourth answer only
	// reaches a caller that resolves AGAIN after having decided what to publish.
	//
	// The count is anchored to the code and that is stated rather than hidden. Two
	// earlier anchors were tried and both failed the same way -- they fired during the
	// drift report, so the thing that got measured was already the collapsed commit and
	// both implementations refused. A case whose scenario depends on this number
	// staying 3 says so in a comment; if the report's resolution count changes, this
	// gate fails loudly rather than quietly testing nothing.
	//
	// The flip takes effect on the request that sets it, because the origin answers
	// from the field after the hook runs. Getting that backwards makes the FIRST
	// resolution the collapsed one, which is how the first attempt at this case
	// refused a run that was doing exactly the right thing.
	resolutions := 0
	origin.onServe = func(o *fakeOrigin, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/commits/HEAD") {
			return
		}
		resolutions++
		if resolutions >= 4 {
			o.head = collapsed
		}
	}
	code, _, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", automaticPolicy(t, true, false),
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitSuccess {
		t.Fatalf("--automatic exited %d (stderr: %s)", code, stderr)
	}
	lock, list, _, err := rules.ReadPublishedPair(paths.sourceLock, paths.listFile)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Commit == collapsed {
		t.Fatalf("published %s, which nothing measured: its list has 1 rule where %d were published",
			collapsed, countListRules(published))
	}
	if lock.Commit != measured {
		t.Errorf("published %s, want the commit that was measured (%s)", lock.Commit, measured)
	}
	// And the list that is published is the measured commit's, not the collapsed one.
	if got := countListRules(list); got != countListRules(published) {
		t.Errorf("the published list holds %d rules, want the measured commit's %d",
			got, countListRules(published))
	}
}

// A policy that cannot be loaded stops the run before anything is fetched. The
// policy is what says whether to refresh, so a run that could not read it has no
// business resolving a commit.
func TestAutomaticRefusesAPolicyItCannotLoad(t *testing.T) {
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, rulesOf(200))
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{
		remoteCommit: sourceArchive(t, remoteCommit, string(rulesOf(200))),
	})
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte("schema_version: 1\nschedule: \"5pm\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runCLI(t, origin.services(), "--automatic",
		"--policy", policy,
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile,
		"--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
	if code != exitInvalidCLI {
		t.Fatalf("--automatic with an invalid policy exited %d, want %d (stderr: %s)",
			code, exitInvalidCLI, stderr)
	}
	if len(origin.requests) != 0 {
		t.Errorf("a run that could not read the policy still reached the remote: %v", origin.requests)
	}
}

// --automatic is a mode, not a modifier: it cannot be combined with another one.
func TestAutomaticRefusesToBeCombinedWithAnotherMode(t *testing.T) {
	for _, args := range [][]string{
		{"--automatic", "--check"},
		{"--automatic", "--pin-remote", "HEAD"},
		{"--automatic", "--refresh-ranges"},
	} {
		if _, err := parseUpdateListOptions(io.Discard, append(args, "--policy", "/etc/mosdns/policy.yaml")); err == nil {
			t.Errorf("%v was accepted, and two modes at once is two publishers", args)
		}
	}
	if options, err := parseUpdateListOptions(io.Discard, []string{"--automatic"}); err != nil {
		t.Fatalf("--automatic alone was refused: %v", err)
	} else if !options.automatic {
		t.Error("--automatic did not select its mode")
	}
}

func TestUpdateListsRejectsInvalidCommandLinesWithoutTouchingAnything(t *testing.T) {
	// The command takes no repository, no ref other than the literal HEAD, and
	// no output path it was not told. Every one of those mistakes is an exit two
	// with a diagnostic and no effect, including no request to the remote.
	tests := []struct {
		name string
		args []string
	}{
		{name: "no mode", args: []string{}},
		{name: "both modes", args: []string{"--check", "--pin-remote", "HEAD"}},
		// A full commit is NOT in this table: it is accepted, because publishing a
		// named commit is how a pin accepted by mistake is undone. See
		// TestPinRemotePublishesTheNamedCommitRatherThanTheRemoteHead. What stays
		// refused is every REF that is not HEAD, because a ref names a moving target
		// and the lock records a commit.
		{name: "ref instead of HEAD", args: []string{"--pin-remote", "refs/heads/master"}},
		{name: "branch instead of HEAD", args: []string{"--pin-remote", "master"}},
		{name: "tag instead of HEAD", args: []string{"--pin-remote", "v1.0.0"}},
		{name: "empty ref", args: []string{"--pin-remote", ""}},
		{name: "unknown flag", args: []string{"--check", "--force"}},
		{name: "unknown flag with a value", args: []string{"--check", "--repository", rules.Repository}},
		{name: "positional argument", args: []string{"--check", "extra"}},
		{name: "positional ref", args: []string{"--pin-remote", "HEAD", "extra"}},
		{name: "missing flag value", args: []string{"--check", "--source-lock"}},
		{name: "empty source lock path", args: []string{"--check", "--source-lock", ""}},
		{name: "empty list path", args: []string{"--check", "--list-file", ""}},
		{name: "empty control lock path", args: []string{"--check", "--control-lock", ""}},
		{name: "empty paths with a pin", args: []string{"--pin-remote", "HEAD", "--source-lock", "", "--list-file", ""}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := newListPaths(t)
			publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
			before := snapshot(t, paths.dir)
			origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})

			args := append([]string{}, test.args...)
			if !containsPathFlag(args) {
				args = append(args, "--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock)
			}
			code, stdout, stderr := runCLI(t, origin.services(), args...)
			if code != exitInvalidCLI {
				t.Fatalf("args %v exit = %d, want %d (stderr: %s)", args, code, exitInvalidCLI, stderr)
			}
			if stdout != "" {
				t.Errorf("args %v wrote stdout: %q", args, stdout)
			}
			if stderr == "" {
				t.Errorf("args %v wrote no diagnostic", args)
			}
			if len(origin.requests) != 0 {
				t.Errorf("args %v reached the remote: %v", args, origin.requests)
			}
			assertUnchanged(t, before, paths.dir, "")
		})
	}
}

// containsPathFlag reports whether the arguments already supply an output path,
// so the invalid-command-line cases do not silently get a usable path appended.
func containsPathFlag(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "--source-lock", "--list-file", "--control-lock", "--previous-lock", "--repository", "--force":
			return true
		}
	}
	return false
}

func TestUpdateListsHelpIsPrintedRatherThanDiscarded(t *testing.T) {
	// `--help` used to parse, print the usage into io.Discard, and exit two with a
	// diagnostic that said nothing about the flags. An operator who typed it got
	// a line of prose and no way to learn that `--check` also reports the ranges
	// or that `--refresh-ranges` is the mode that publishes them.
	//
	// The usage now goes to the command's own stderr, names every flag, and
	// carries the flag descriptions -- so the manual page Task 6 writes inherits
	// the same text this asserts on, rather than a second copy of it.
	for _, flag := range []string{"-h", "--help"} {
		t.Run(flag, func(t *testing.T) {
			paths := newListPaths(t)
			origin := newFakeOrigin(t, remoteCommit, nil)
			code, stdout, stderr := runCLI(t, origin.services(), flag,
				"--source-lock", paths.sourceLock, "--list-file", paths.listFile)
			if code != exitInvalidCLI {
				t.Fatalf("`%s` exit = %d, want %d", flag, code, exitInvalidCLI)
			}
			if stdout != "" {
				t.Errorf("`%s` wrote stdout: %q", flag, stdout)
			}
			for _, want := range []string{
				"update-lists",
				"-check",
				"-pin-remote",
				"-refresh-ranges",
				"-ranges-cache",
				"-control-lock",
			} {
				if !strings.Contains(stderr, want) {
					t.Errorf("`%s` usage does not mention %s:\n%s", flag, want, stderr)
				}
			}
			if len(origin.requests) != 0 {
				t.Errorf("`%s` reached the remote: %v", flag, origin.requests)
			}
		})
	}
}

func TestTheCheckFlagSaysWhatItNowReports(t *testing.T) {
	// The reviewer's finding: the brief asked the command to "state explicitly
	// what --check now means for the ranges", and the only place that meaning
	// existed was a doc comment and a report. Task 6 owns the manual page, so the
	// flag's own description is where the page inherits it from.
	paths := newListPaths(t)
	origin := newFakeOrigin(t, remoteCommit, nil)
	_, _, usage := runCLI(t, origin.services(), "--help",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile)
	for _, want := range []string{
		"ranges",
		"writes nothing",
		"--refresh-ranges",
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("the usage does not say %q about --check:\n%s", want, usage)
		}
	}
}

func TestUpdateListsDefaultsAreTheInstalledPaths(t *testing.T) {
	// The packaged timer runs the command with no paths at all, so the defaults
	// are the only thing that makes it update the list the router reads. A
	// default that pointed anywhere else would leave the router on a list no
	// pin ever replaced.
	options, err := parseUpdateListOptions(io.Discard, []string{"--check"})
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	pinned, err := parseUpdateListOptions(io.Discard, []string{"--pin-remote", "HEAD"})
	if err != nil {
		t.Fatalf("parse pin defaults: %v", err)
	}
	for name, options := range map[string]updateListOptions{"check": options, "pin-remote": pinned} {
		if options.sourceLock != "/var/lib/mosdns/lists/source-lock.json" {
			t.Errorf("%s default source lock = %q, want the installed list directory", name, options.sourceLock)
		}
		if options.listFile != "/var/lib/mosdns/lists/cn-domains.txt" {
			t.Errorf("%s default list file = %q, want the installed list directory", name, options.listFile)
		}
		if options.controlLock != "/var/lib/mosdns/runtime/control.lock" {
			t.Errorf("%s default control lock = %q, want the installed runtime directory", name, options.controlLock)
		}
	}
}

func TestUpdateListsCheckNamesTheInstalledSourceLockPathWhenNothingIsPinned(t *testing.T) {
	// With the default paths and nothing published, the refusal has to name the
	// file that is missing, or an operator cannot tell an un-installed gateway
	// from a broken one. This run reads paths only: it never reaches the remote.
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})

	code, stdout, stderr := runCLI(t, origin.services(), "--check")
	if code != exitStateUnavailable {
		t.Skipf("the installed list directory exists on this host (exit %d, stderr %q), so the default-path refusal cannot be observed", code, stderr)
	}
	if stdout != "" {
		t.Errorf("refused check wrote a report: %q", stdout)
	}
	if !strings.Contains(stderr, "/var/lib/mosdns/lists/source-lock.json") {
		t.Errorf("refusal does not name the installed source lock: %q", stderr)
	}
	if len(origin.requests) != 0 {
		t.Errorf("refused check reached the remote: %v", origin.requests)
	}
}

func TestProductionListClientUsesTheSystemResolver(t *testing.T) {
	// The gateway's own updates must resolve GitHub the way the host resolves
	// every other foreign name, through MOSDNS. A client with its own transport
	// or its own dialer could quietly point the pin at a resolver of somebody
	// else's choosing, and a client without a timeout could hang a timer run
	// forever.
	client := productionServices().newHTTPClient()
	if client == nil {
		t.Fatal("production services build no HTTP client")
	}
	if client.Transport != nil {
		t.Error("production HTTP client installs its own transport, so its name resolution is not the system one")
	}
	if client.Timeout <= 0 {
		t.Error("production HTTP client has no timeout")
	}
}

func TestUpdateListsContextIsCancelledWhenTheCommandIsGivenACancelledContext(t *testing.T) {
	// The command boundary takes its context, so a caller that stops waiting
	// stops the update instead of leaving a download running.
	paths := newListPaths(t)
	publishPair(t, paths, lockedCommit, []byte("domain:previous.cn\n"))
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	code := runWithContext(ctx, []string{"update-lists", "--check",
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock, "--previous-lock", paths.previousLock}, &stdout, &stderr, origin.services())
	if code == exitSuccess {
		t.Fatalf("check reported success for a cancelled update:\n%s", stdout.String())
	}
	if len(origin.requests) != 0 {
		t.Errorf("cancelled check reached the remote: %v", origin.requests)
	}
}

// snapshotTree is snapshotWithout for a subtree, keyed by the path below dir. It
// exists because the fixture directories now contain a systemd subdirectory, and a
// snapshot helper that cannot read one is a helper that reports every "validate
// wrote nothing" case as a crash instead of as an answer.
func snapshotTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	state := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || path == dir {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		state[relative] = contents
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}
