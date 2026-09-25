package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The archive fixtures below are built in memory, byte for byte, so no test in
// this file reads GitHub. The API fixture is the one field this package reads
// from a commit document, wrapped in the surrounding keys GitHub sends, so a
// decoder that reached for anything else would fail here rather than in
// production.

const (
	// fixtureCommit is the 40-hex commit the fake remote serves. It is a made-up
	// but well-formed commit id, not a real one.
	fixtureCommit = "0123456789abcdef0123456789abcdef01234567"
	// fixtureArchiveTop is the single top-level directory a GitHub source
	// archive carries.
	fixtureArchiveTop = "domain-list-community-" + fixtureCommit
	// fixtureList is the China list the fixture archive carries. It states one
	// rule per supported form, a bare domain, an include, an attribute that is
	// kept, and the attribute upstream casts out of the cn lists.
	fixtureList = "domain:example.cn @cn\nfull:exact.cn\ninclude:shared\ncast-out.cn @!cn\nads.cn @ads\n"
	// fixtureShared is the list the fixture archive's China list includes. Its
	// plain copy of example.cn is the same MOSDNS expression as the attributed
	// one in the China list, and must collapse onto it.
	fixtureShared = "regexp:^static[0-9]+\\.example\\.cn$\nexample.cn\nkeyword:测试\n"
)

// wantFixtureExpressions is the converted fixture list, sorted and with the
// `@!cn` rule cast out, derived by hand from the two fixture files above.
var wantFixtureExpressions = []string{
	"domain:ads.cn",
	"domain:example.cn",
	"full:exact.cn",
	"keyword:测试",
	"regexp:^static[0-9]+\\.example\\.cn$",
}

// archiveEntry is one entry of a test archive.
type archiveEntry struct {
	name       string
	body       string
	typeflag   byte
	linkname   string
	size       int64 // overrides the body length when non-zero
	paxRecords map[string]string
}

// buildArchive returns a gzipped tar archive holding the given entries.
func buildArchive(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		size := entry.size
		if size == 0 {
			size = int64(len(entry.body))
		}
		if entry.typeflag == tar.TypeXGlobalHeader {
			// A PAX global header may carry nothing but its records.
			if err := tarWriter.WriteHeader(&tar.Header{
				Name:       entry.name,
				Typeflag:   tar.TypeXGlobalHeader,
				PAXRecords: entry.paxRecords,
			}); err != nil {
				t.Fatalf("write archive global header %q: %v", entry.name, err)
			}
			continue
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Size:     size,
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
		}
		if header.Typeflag == 0 {
			header.Typeflag = tar.TypeReg
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write archive header %q: %v", entry.name, err)
		}
		if header.Typeflag == tar.TypeDir || header.Typeflag == tar.TypeXGlobalHeader {
			// A directory and a PAX global header carry no list, but they are real
			// entries: a global header names itself and is not a list file, and a
			// directory names its contents.
			continue
		}
		// The declared size may exceed the body, which is how a fixture claims a
		// file larger than the bound the converter enforces.
		source := io.Reader(bytes.NewReader([]byte(entry.body)))
		if int64(len(entry.body)) < size {
			source = io.LimitReader(zeroReader{}, size)
		}
		if _, err := io.CopyN(tarWriter, source, size); err != nil {
			t.Fatalf("write archive body %q: %v", entry.name, err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return compressed.Bytes()
}

// fixtureArchive is the archive every happy-path test in this file pins.
func fixtureArchive(t *testing.T) []byte {
	t.Helper()
	return buildArchive(t, []archiveEntry{
		{name: fixtureArchiveTop + "/data/cn", body: fixtureList},
		{name: fixtureArchiveTop + "/data/shared", body: fixtureShared},
		{name: fixtureArchiveTop + "/README.md", body: "# fixture\n"},
	})
}

// fakeRemote is a GitHub-shaped HTTP origin: a commit endpoint and a source
// archive endpoint, both served from one test server. Every request is
// recorded so a test can assert that a path was never fetched.
type fakeRemote struct {
	server  *httptest.Server
	client  *http.Client
	commit  string
	archive []byte

	// commitBody, when set (rawBody true), is served verbatim by the commit
	// endpoint instead of a commit document.
	commitBody string
	rawBody    bool
	// declaredLength overrides the Content-Length the archive endpoint sends.
	declaredLength int64
	// streamBytes, when non-zero, makes the archive endpoint stream that many
	// zero bytes instead of the archive, so a test can exercise the read bound.
	streamBytes int64
	status      int
	requests    []string
}

func newFakeRemote(t *testing.T, commit string, archive []byte) *fakeRemote {
	t.Helper()
	remote := &fakeRemote{commit: commit, archive: archive, status: http.StatusOK}
	remote.server = httptest.NewServer(http.HandlerFunc(remote.serve))
	t.Cleanup(remote.server.Close)
	remote.client = hostRewritingClient(t, remote.server.URL)
	return remote
}

func (r *fakeRemote) serve(writer http.ResponseWriter, request *http.Request) {
	r.requests = append(r.requests, request.URL.Path)
	if r.status != 0 && r.status != http.StatusOK {
		writer.WriteHeader(r.status)
		return
	}
	switch {
	case strings.HasSuffix(request.URL.Path, "/commits/HEAD"):
		writer.Header().Set("Content-Type", "application/json")
		if r.rawBody {
			_, _ = io.WriteString(writer, r.commitBody)
			return
		}
		// The surrounding keys are the ones GitHub sends around the single field
		// this package reads.
		_, _ = io.WriteString(writer, fmt.Sprintf(`{"sha":%q,"node_id":"C_1","commit":{"committer":{"date":"2026-09-25T01:39:17Z"}},"parents":[]}`, r.commit))
	case strings.HasPrefix(request.URL.Path, "/v2fly/domain-list-community/tar.gz/"):
		writer.Header().Set("Content-Type", "application/gzip")
		if r.streamBytes != 0 && r.declaredLength == 0 {
			// No declared length, so only the reader bound can stop this body.
			_, _ = io.CopyN(writer, zeroReader{}, r.streamBytes)
			return
		}
		length := int64(len(r.archive))
		if r.declaredLength != 0 {
			length = r.declaredLength
		}
		writer.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		if r.streamBytes != 0 {
			_, _ = io.CopyN(writer, zeroReader{}, r.streamBytes)
			return
		}
		_, _ = writer.Write(r.archive)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

// served reports whether path was requested from this origin.
func (r *fakeRemote) served(path string) bool {
	return slices.Contains(r.requests, path)
}

// hostRewritingClient returns a client that sends every request to the test
// server, so production code under test keeps building and using its real
// api.github.com and codeload.github.com URLs.
func hostRewritingClient(t *testing.T, serverURL string) *http.Client {
	t.Helper()
	target, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	transport := &http.Transport{}
	return &http.Client{Transport: rewriteHostTransport{base: target, inner: transport}}
}

type rewriteHostTransport struct {
	base  *url.URL
	inner *http.Transport
}

func (r rewriteHostTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	next := request.Clone(request.Context())
	next.URL.Scheme = r.base.Scheme
	next.URL.Host = r.base.Host
	return r.inner.RoundTrip(next)
}

// digest returns the lowercase hex SHA-256 of b, which is the shape a lock
// records and a pinned download requires.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pinnedLock is a complete lock for the fixture archive: the digest is computed
// here from the archive the fake remote serves, exactly as a pin does.
func pinnedLock(t *testing.T, archive []byte) SourceLock {
	t.Helper()
	return SourceLock{
		SchemaVersion: schemaVersion,
		Repository:    Repository,
		Commit:        fixtureCommit,
		SHA256:        digest(archive),
		Entry:         Entry,
	}
}

func TestDownloadRecordsThePinnedSourceAndConvertsTheEntry(t *testing.T) {
	// The lock a pin writes is the audit record: which reviewed commit, which
	// archive digest, which entry, and the digest of the exact list the router
	// then reads. A Download that returned a lock missing or reordering those
	// would publish a list nothing can be checked against later.
	archive := fixtureArchive(t)
	remote := newFakeRemote(t, fixtureCommit, archive)

	got, list, err := Download(context.Background(), remote.client, pinnedLock(t, archive))
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	wantLock := pinnedLock(t, archive)
	wantLock.ListSHA256 = digest(list)
	if got != wantLock {
		t.Fatalf("Download lock = %+v, want %+v", got, wantLock)
	}
	if got.SchemaVersion != schemaVersion || got.Repository != Repository || got.Entry != Entry {
		t.Fatalf("Download lock lost its pinned identity: %+v", got)
	}

	wantList := ""
	for _, expression := range wantFixtureExpressions {
		wantList += expression + "\n"
	}
	if string(list) != wantList {
		t.Fatalf("Download list =\n%q\nwant\n%q", list, wantList)
	}
	if got.ListSHA256 != digest([]byte(wantList)) {
		t.Fatalf("ListSHA256 = %q, want the digest of the returned list %q", got.ListSHA256, digest([]byte(wantList)))
	}
	if want := "/v2fly/domain-list-community/tar.gz/" + fixtureCommit; !remote.served(want) {
		t.Fatalf("Download fetched %v, want the archive at %q", remote.requests, want)
	}
}

func TestDownloadAcceptsTheShapeAGitHubSourceArchiveActuallyHas(t *testing.T) {
	// A GitHub source archive opens with a PAX global header that names itself,
	// carries explicit directory entries with a trailing slash, and then the
	// files. An extractor that insisted every entry was a list file would refuse
	// every real archive, which is what the one-time pin against the reviewed
	// commit ran into.
	archive := buildArchive(t, []archiveEntry{
		{name: "pax_global_header", typeflag: tar.TypeXGlobalHeader, paxRecords: map[string]string{"comment": "fixture"}},
		{name: fixtureArchiveTop + "/", typeflag: tar.TypeDir},
		{name: fixtureArchiveTop + "/data/", typeflag: tar.TypeDir},
		{name: fixtureArchiveTop + "/data/cn", body: fixtureList},
		{name: fixtureArchiveTop + "/data/shared", body: fixtureShared},
		{name: fixtureArchiveTop + "/LICENSE", body: "MIT\n"},
	})
	remote := newFakeRemote(t, fixtureCommit, archive)

	_, list, err := Download(context.Background(), remote.client, pinnedLock(t, archive))
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := ""
	for _, expression := range wantFixtureExpressions {
		want += expression + "\n"
	}
	if string(list) != want {
		t.Fatalf("Download list =\n%q\nwant\n%q", list, want)
	}
}

func TestDownloadRejectsAChecksumMismatchBeforeConversion(t *testing.T) {
	// The archive in the fixture would fail conversion if it were read at all,
	// so the reported error proves the digest is checked first: a Download that
	// extracted before verifying would report the unknown directive instead.
	archive := buildArchive(t, []archiveEntry{
		{name: fixtureArchiveTop + "/data/cn", body: "ip4:1.2.3.4\n"},
	})
	remote := newFakeRemote(t, fixtureCommit, archive)

	lock := pinnedLock(t, archive)
	lock.SHA256 = digest([]byte("a different archive"))
	lockReturned, list, err := Download(context.Background(), remote.client, lock)
	if err == nil {
		t.Fatalf("Download accepted a mismatched archive and returned %d bytes", len(list))
	}
	if list != nil {
		t.Fatalf("Download returned list bytes on failure: %q", list)
	}
	if lockReturned != (SourceLock{}) {
		t.Fatalf("Download returned a lock on failure: %+v", lockReturned)
	}
	if !strings.Contains(err.Error(), "archive sha256") || !strings.Contains(err.Error(), lock.SHA256) {
		t.Fatalf("error = %v, want it to name the expected archive digest", err)
	}
	if strings.Contains(err.Error(), "ip4") {
		t.Fatalf("error came from conversion, so the digest was not checked first: %v", err)
	}
}

func TestDownloadRefusesALockThatIsNotFullyPinned(t *testing.T) {
	// Every field of a lock is a security decision, not metadata. A lock that
	// names another repository, another list, a short commit, an upper-case
	// digest or a schema version this build does not know must be refused
	// before a byte is fetched, or the gateway would convert someone else's
	// list and record it as reviewed.
	archive := fixtureArchive(t)
	remote := newFakeRemote(t, fixtureCommit, archive)
	valid := pinnedLock(t, archive)
	tests := []struct {
		name   string
		mutate func(*SourceLock)
	}{
		{name: "empty commit", mutate: func(l *SourceLock) { l.Commit = "" }},
		{name: "short commit", mutate: func(l *SourceLock) { l.Commit = "0123456789abcdef" }},
		{name: "non hex commit", mutate: func(l *SourceLock) { l.Commit = strings.Repeat("z", 40) }},
		{name: "upper case commit", mutate: func(l *SourceLock) { l.Commit = strings.ToUpper(fixtureCommit) }},
		{name: "commit with a ref", mutate: func(l *SourceLock) { l.Commit = fixtureCommit + "/data/cn" }},
		{name: "empty archive digest", mutate: func(l *SourceLock) { l.SHA256 = "" }},
		{name: "short archive digest", mutate: func(l *SourceLock) { l.SHA256 = valid.SHA256[:63] }},
		{name: "upper case archive digest", mutate: func(l *SourceLock) { l.SHA256 = strings.ToUpper(valid.SHA256) }},
		{name: "other repository", mutate: func(l *SourceLock) { l.Repository = "attacker/domain-list" }},
		{name: "empty repository", mutate: func(l *SourceLock) { l.Repository = "" }},
		{name: "other entry", mutate: func(l *SourceLock) { l.Entry = "data/geolocation-!cn" }},
		{name: "absolute entry", mutate: func(l *SourceLock) { l.Entry = "/data/cn" }},
		{name: "empty entry", mutate: func(l *SourceLock) { l.Entry = "" }},
		{name: "unknown schema", mutate: func(l *SourceLock) { l.SchemaVersion = schemaVersion + 1 }},
		{name: "missing schema", mutate: func(l *SourceLock) { l.SchemaVersion = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lock := valid
			test.mutate(&lock)
			if _, _, err := Download(context.Background(), remote.client, lock); err == nil {
				t.Fatal("Download accepted a lock that is not fully pinned")
			}
			if len(remote.requests) != 0 {
				t.Fatalf("Download fetched %v before refusing the lock", remote.requests)
			}
		})
	}
}

func TestDownloadRejectsAnArchiveThatCouldEscapeOrFlood(t *testing.T) {
	// A source archive is untrusted input. Anything that would write outside the
	// archive root, present a link instead of a list, or make the converter do
	// unbounded work is refused. The last case streams more than the download
	// bound, so it is the one test in this file that moves real bytes.
	tests := []struct {
		name    string
		entries []archiveEntry
		wantSub string
	}{
		{
			name:    "parent traversal",
			entries: []archiveEntry{{name: "../escape", body: "domain:escape.cn\n"}},
			wantSub: "unsafe archive path",
		},
		{
			name:    "absolute path",
			entries: []archiveEntry{{name: "/etc/passwd", body: "root\n"}},
			wantSub: "unsafe archive path",
		},
		{
			name:    "nested traversal",
			entries: []archiveEntry{{name: fixtureArchiveTop + "/data/../../escape", body: "domain:escape.cn\n"}},
			wantSub: "unsafe archive path",
		},
		{
			name:    "symlink",
			entries: []archiveEntry{{name: fixtureArchiveTop + "/data/cn", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
			wantSub: "unsupported archive entry type",
		},
		{
			name:    "hard link",
			entries: []archiveEntry{{name: fixtureArchiveTop + "/data/cn", typeflag: tar.TypeLink, linkname: fixtureArchiveTop + "/data/shared"}},
			wantSub: "unsupported archive entry type",
		},
		{
			name:    "character device",
			entries: []archiveEntry{{name: fixtureArchiveTop + "/data/cn", typeflag: tar.TypeChar}},
			wantSub: "unsupported archive entry type",
		},
		{
			name:    "fifo",
			entries: []archiveEntry{{name: fixtureArchiveTop + "/data/cn", typeflag: tar.TypeFifo}},
			wantSub: "unsupported archive entry type",
		},
		{
			name: "file above the size bound",
			entries: []archiveEntry{
				{name: fixtureArchiveTop + "/data/cn", body: fixtureList},
				{name: fixtureArchiveTop + "/data/big", size: 4<<20 + 1},
			},
			wantSub: "larger than the 4194304 byte",
		},
		{
			name: "entry count above the bound",
			entries: func() []archiveEntry {
				entries := []archiveEntry{{name: fixtureArchiveTop + "/data/cn", body: fixtureList}}
				for i := 0; i <= maxArchiveFiles; i++ {
					entries = append(entries, archiveEntry{name: fmt.Sprintf("%s/data/pad%d", fixtureArchiveTop, i)})
				}
				return entries
			}(),
			wantSub: "more than 32768 entries",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := buildArchive(t, test.entries)
			remote := newFakeRemote(t, fixtureCommit, archive)
			_, list, err := Download(context.Background(), remote.client, pinnedLock(t, archive))
			if err == nil {
				t.Fatalf("Download accepted the archive and returned %q", list)
			}
			if !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("error = %v, want it to mention %q", err, test.wantSub)
			}
		})
	}
}

func TestDownloadRejectsAnArchiveWithoutExactlyOneTopLevelDirectory(t *testing.T) {
	// The entry path is resolved inside the archive, so the conversion is only
	// meaningful if every file sits under the one directory the source archive is
	// named after. An archive that mixes roots, or that is bare, is refused
	// rather than partially converted.
	tests := []struct {
		name    string
		entries []archiveEntry
	}{
		{
			name: "no top level directory",
			entries: []archiveEntry{
				{name: "data/cn", body: fixtureList},
				{name: "data/shared", body: fixtureShared},
			},
		},
		{
			name: "two top level directories",
			entries: []archiveEntry{
				{name: fixtureArchiveTop + "/data/cn", body: fixtureList},
				{name: "other-root/data/shared", body: fixtureShared},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := buildArchive(t, test.entries)
			remote := newFakeRemote(t, fixtureCommit, archive)
			_, list, err := Download(context.Background(), remote.client, pinnedLock(t, archive))
			if err == nil {
				t.Fatalf("Download accepted the archive and returned %q", list)
			}
			if !strings.Contains(err.Error(), "top-level directory") {
				t.Fatalf("error = %v, want it to mention the top-level directory", err)
			}
		})
	}
}

func TestDownloadReportsAMissingEntryInsteadOfAnEmptyList(t *testing.T) {
	// A pinned commit that no longer carries the entry would otherwise convert to
	// an empty China set, which the router would read as "nothing is Chinese".
	archive := buildArchive(t, []archiveEntry{{name: fixtureArchiveTop + "/README.md", body: "# fixture\n"}})
	remote := newFakeRemote(t, fixtureCommit, archive)

	_, list, err := Download(context.Background(), remote.client, pinnedLock(t, archive))
	if err == nil {
		t.Fatalf("Download accepted an archive without the entry and returned %q", list)
	}
	if !strings.Contains(err.Error(), Entry) {
		t.Fatalf("error = %v, want it to name the entry %q", err, Entry)
	}
}

func TestResolveCommitReturnsTheReviewedDefaultBranchCommit(t *testing.T) {
	// A pin starts from the commit the repository publishes for its default
	// branch, so the request path and the 40-hex requirement are the contract.
	archive := fixtureArchive(t)
	remote := newFakeRemote(t, fixtureCommit, archive)

	lock, err := ResolveCommit(context.Background(), remote.client, Repository)
	if err != nil {
		t.Fatalf("ResolveCommit: %v", err)
	}
	if lock.Commit != fixtureCommit {
		t.Fatalf("Commit = %q, want %q", lock.Commit, fixtureCommit)
	}
	if lock.Repository != Repository || lock.Entry != Entry || lock.SchemaVersion != schemaVersion {
		t.Fatalf("resolved lock lost its pinned identity: %+v", lock)
	}
	if lock.SHA256 != "" || lock.ListSHA256 != "" {
		t.Fatalf("ResolveCommit claimed digests it has not computed: %+v", lock)
	}
	if want := "/repos/v2fly/domain-list-community/commits/HEAD"; !remote.served(want) {
		t.Fatalf("ResolveCommit fetched %v, want %q", remote.requests, want)
	}
	if len(remote.requests) != 1 {
		t.Fatalf("ResolveCommit fetched %v, want only the commit document", remote.requests)
	}
}

func TestResolveCommitRefusesAResponseThatIsNotAFortyHexCommit(t *testing.T) {
	// A commit that is not a full 40-hex id cannot address a source archive, so
	// accepting one would either fail later or, worse, be recorded in a lock as
	// if it had been reviewed.
	archive := fixtureArchive(t)
	tests := []struct {
		name   string
		commit string
	}{
		{name: "empty", commit: ""},
		{name: "abbreviated", commit: "0123456"},
		{name: "39 hex", commit: fixtureCommit[:39]},
		{name: "41 hex", commit: fixtureCommit + "0"},
		{name: "not hex", commit: strings.Repeat("z", 40)},
		{name: "upper case hex", commit: strings.ToUpper(fixtureCommit)},
		{name: "a ref", commit: "refs/heads/master"},
		{name: "a tag", commit: "v1.0.0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remote := newFakeRemote(t, test.commit, archive)
			lock, err := ResolveCommit(context.Background(), remote.client, Repository)
			if err == nil {
				t.Fatalf("ResolveCommit accepted %q and returned %+v", test.commit, lock)
			}
			if len(remote.requests) != 1 {
				t.Fatalf("ResolveCommit fetched %v, want only the commit document", remote.requests)
			}
		})
	}
}

func TestResolveCommitRefusesARemoteFailure(t *testing.T) {
	// An outage, a rate limit and a body that is not a commit document are all
	// ways the remote can fail to name a commit. Each must be an error, and none
	// may be turned into a pin.
	archive := fixtureArchive(t)
	tests := []struct {
		name       string
		commit     string
		commitBody string
		rawBody    bool
		status     int
		wantSub    string
	}{
		{name: "server error", commit: fixtureCommit, status: http.StatusInternalServerError, wantSub: "unexpected status 500"},
		{name: "not found", commit: fixtureCommit, status: http.StatusNotFound, wantSub: "unexpected status 404"},
		{name: "rate limited", commit: fixtureCommit, status: http.StatusForbidden, wantSub: "unexpected status 403"},
		{name: "empty body", commit: fixtureCommit, rawBody: true, wantSub: "decode commit"},
		{name: "not a document", commit: fixtureCommit, commitBody: "not json at all", rawBody: true, wantSub: "decode commit"},
		{name: "no sha field", commit: fixtureCommit, commitBody: `{"node_id":"C_1"}`, rawBody: true, wantSub: "has no 40 character lower-case hex sha"},
		{name: "an html error page", commit: fixtureCommit, commitBody: "<html>rate limited</html>", rawBody: true, wantSub: "decode commit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remote := newFakeRemote(t, test.commit, archive)
			remote.status = test.status
			remote.commitBody = test.commitBody
			remote.rawBody = test.rawBody
			if _, err := ResolveCommit(context.Background(), remote.client, Repository); err == nil {
				t.Fatal("ResolveCommit accepted a failing remote")
			} else if !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("error = %v, want it to mention %q", err, test.wantSub)
			}
			if len(remote.requests) != 1 {
				t.Fatalf("ResolveCommit fetched %v, want only the commit document", remote.requests)
			}
		})
	}
}

func TestResolveHEADRecordsTheArchiveDigestOfTheResolvedCommit(t *testing.T) {
	// A pin cannot record a digest it has not read, so ResolveHEAD resolves the
	// commit and then downloads that commit's archive to compute the digest that
	// the written lock carries. The lock it returns must not claim a list digest
	// it has not produced either.
	archive := fixtureArchive(t)
	remote := newFakeRemote(t, fixtureCommit, archive)

	lock, err := ResolveHEAD(context.Background(), remote.client, Repository)
	if err != nil {
		t.Fatalf("ResolveHEAD: %v", err)
	}
	want := pinnedLock(t, archive)
	if lock != want {
		t.Fatalf("ResolveHEAD = %+v, want %+v", lock, want)
	}
	if wantArchivePath := "/v2fly/domain-list-community/tar.gz/" + fixtureCommit; !remote.served(wantArchivePath) {
		t.Fatalf("ResolveHEAD fetched %v, want the archive at %q", remote.requests, wantArchivePath)
	}
}

func TestResolveHEADRefusesAnotherRepository(t *testing.T) {
	// There is one reviewed source for this gateway. Accepting a caller-supplied
	// repository would let a pin record a list nobody reviewed as if it had been.
	remote := newFakeRemote(t, fixtureCommit, fixtureArchive(t))

	for _, repository := range []string{"attacker/domain-list", "v2fly/domain-list-community/data", "../v2fly/domain-list-community", "V2Fly/domain-list-community", " "} {
		if _, err := ResolveHEAD(context.Background(), remote.client, repository); err == nil {
			t.Errorf("ResolveHEAD accepted repository %q", repository)
		}
		if _, err := ResolveCommit(context.Background(), remote.client, repository); err == nil {
			t.Errorf("ResolveCommit accepted repository %q", repository)
		}
	}
	if len(remote.requests) != 0 {
		t.Fatalf("an unsupported repository was fetched before being refused: %v", remote.requests)
	}
}

func TestDownloadRefusesADownloadLargerThanTheArchiveBound(t *testing.T) {
	// The archive bound exists so a hostile or broken origin cannot make the pin
	// buffer an unbounded body. The first case is refused on the declared length
	// alone; the second is an origin that understates its length and has to be
	// stopped by the reader.
	tests := []struct {
		name           string
		declaredLength int64
		streamBytes    int64
	}{
		{name: "declared length above the bound", declaredLength: maxArchiveBytes + 1, streamBytes: 1024},
		{name: "undeclared length above the bound", streamBytes: maxArchiveBytes + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remote := newFakeRemote(t, fixtureCommit, nil)
			remote.declaredLength = test.declaredLength
			remote.streamBytes = test.streamBytes

			lock := pinnedLock(t, []byte("unused"))
			_, list, err := Download(context.Background(), remote.client, lock)
			if err == nil {
				t.Fatalf("Download accepted an oversized archive and returned %q", list)
			}
			if !strings.Contains(err.Error(), "67108864") {
				t.Fatalf("error = %v, want it to name the 67108864 byte bound", err)
			}
		})
	}
}

func TestDownloadRefusesACancelledRequest(t *testing.T) {
	// A cancelled update has to stop, not to convert a partial archive into a
	// list. A pin that ignored cancellation would also keep a stale pin running
	// after the operator asked for it to stop.
	archive := fixtureArchive(t)
	remote := newFakeRemote(t, fixtureCommit, archive)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := Download(ctx, remote.client, pinnedLock(t, archive)); err == nil {
		t.Fatal("Download ignored a cancelled context")
	}
	if _, err := ResolveCommit(ctx, remote.client, Repository); err == nil {
		t.Fatal("ResolveCommit ignored a cancelled context")
	}
	if _, err := ResolveHEAD(ctx, remote.client, Repository); err == nil {
		t.Fatal("ResolveHEAD ignored a cancelled context")
	}
}

func TestSourceLockJSONIsDeterministicAndStrict(t *testing.T) {
	// The lock file is the audit record, so the same lock must always render the
	// same bytes, and a lock that carries an unknown field must be refused rather
	// than partially read: a future field this build does not understand could
	// otherwise be dropped while the lock still claims to pin the source.
	archive := fixtureArchive(t)
	lock := pinnedLock(t, archive)
	lock.ListSHA256 = digest([]byte("domain:example.cn\n"))

	first, err := lock.Encode()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	second, err := lock.Encode()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("MarshalJSON is not deterministic:\n%s\n%s", first, second)
	}
	if !bytes.HasSuffix(first, []byte("\n")) {
		t.Fatalf("lock JSON does not end in a newline: %q", first)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(first, &fields); err != nil {
		t.Fatalf("decode lock JSON: %v", err)
	}
	want := []string{"schema_version", "repository", "commit", "sha256", "list_sha256", "entry"}
	if len(fields) != len(want) {
		t.Fatalf("lock JSON has fields %v, want exactly %v", fields, want)
	}
	for _, name := range want {
		if _, ok := fields[name]; !ok {
			t.Errorf("lock JSON is missing %q: %s", name, first)
		}
	}
	// The field order is fixed by the struct, so a reader sees the same shape.
	if bytes.Index(first, []byte(`"repository"`)) > bytes.Index(first, []byte(`"commit"`)) {
		t.Errorf("lock JSON is not in its documented order: %s", first)
	}

	decoded, err := ParseSourceLock(first)
	if err != nil {
		t.Fatalf("ParseSourceLock: %v", err)
	}
	if decoded != lock {
		t.Fatalf("ParseSourceLock = %+v, want %+v", decoded, lock)
	}
	if _, err := ParseSourceLock([]byte(string(first) + "\n{}")); err == nil {
		t.Error("ParseSourceLock accepted a second document")
	}
	if _, err := ParseSourceLock([]byte(`{"schema_version":1,"repository":"v2fly/domain-list-community","commit":"` + fixtureCommit + `","sha256":"` + digest([]byte("x")) + `","list_sha256":"` + digest([]byte("x")) + `","entry":"data/cn","future":"value"}`)); err == nil {
		t.Error("ParseSourceLock accepted an unknown field")
	}
	if _, err := ParseSourceLock([]byte("not json")); err == nil {
		t.Error("ParseSourceLock accepted a non-JSON document")
	}
	if _, err := ParseSourceLock(nil); err == nil {
		t.Error("ParseSourceLock accepted an empty document")
	}
}

// zeroReader streams count zero bytes without allocating them.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
