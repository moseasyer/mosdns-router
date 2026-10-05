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
	dir          string
	sourceLock   string
	listFile     string
	controlLock  string
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
				"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
	if state := snapshot(t, paths.dir); len(state) != 3 {
		t.Fatalf("published directory holds %v, want the pair and the control lock", names(state))
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
				"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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

func TestUpdateListsPinRemoteReportsAPublicationFailureInsteadOfSuccess(t *testing.T) {
	// A pin that verified its source and then could not write the pair has to say
	// so. Reporting an accepted commit for a list that was never published is the
	// one outcome an operator cannot recover from, because the next check would
	// compare a lock nobody wrote against a list nobody installed.
	paths := newListPaths(t)
	origin := newFakeOrigin(t, remoteCommit, map[string][]byte{remoteCommit: sourceArchive(t, remoteCommit, firstInstallArchive)})
	listFile := filepath.Join(paths.dir, "not-installed", "cn-domains.txt")

	code, stdout, stderr := runCLI(t, origin.services(), "--pin-remote", "HEAD",
		"--source-lock", paths.sourceLock, "--list-file", listFile, "--control-lock", paths.controlLock)
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
		{name: "ref instead of HEAD", args: []string{"--pin-remote", "refs/heads/master"}},
		{name: "branch instead of HEAD", args: []string{"--pin-remote", "master"}},
		{name: "tag instead of HEAD", args: []string{"--pin-remote", "v1.0.0"}},
		{name: "commit instead of HEAD", args: []string{"--pin-remote", lockedCommit}},
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
				args = append(args, "--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock)
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
		case "--source-lock", "--list-file", "--control-lock", "--repository", "--force":
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
		"--source-lock", paths.sourceLock, "--list-file", paths.listFile, "--control-lock", paths.controlLock}, &stdout, &stderr, origin.services())
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
