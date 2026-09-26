package candidate

// A measurement run publishes the response rewriter's prefix list as a side
// effect of the fetch it already makes, and that has been the only way the list
// has ever appeared. It is the wrong way to produce a hard start requirement: the
// fetch that produces it belongs to a run that measures candidates, so anything
// that needs the list before the first measurement -- a fresh installation, a
// router that has to start before a timer has ever fired -- has to spend a whole
// measurement run to get it. The refresh below is that fetch with the sampling
// removed, and the tests here hold it to the two properties that make it
// substitutable: it produces the same two artifacts from the same one document,
// and it produces them from a document the sampler would also have accepted.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func refreshed(t *testing.T, origin *fakeOrigin, cachePath string) RangeRefresh {
	t.Helper()
	result, err := newTestSource(t, origin, cachePath).Refresh(t.Context())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return result
}

func TestRefreshPublishesBothArtifactsFromOneRequest(t *testing.T) {
	// One fetch, two artifacts, from one in-memory document. The envelope holds
	// the bytes exactly as they arrived and the prefix list holds the ranges
	// parsed out of those same bytes, so the two cannot describe different days.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cloudflare-ips.json")

	result := refreshed(t, origin, cachePath)

	if served := origin.bodiesServed(); served != 1 {
		t.Fatalf("the origin served %d bodies, want 1: a second fetch would let the envelope and the prefix list describe different documents", served)
	}
	envelope, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read the cache envelope: %v", err)
	}
	if !strings.Contains(string(envelope), `"104.16.0.0/22"`) {
		t.Errorf("the envelope does not carry the document the origin served: %s", envelope)
	}
	published, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the published prefix list: %v", err)
	}
	if want := "104.16.0.0/22\n172.64.0.0/21\n"; string(published) != want {
		t.Errorf("published prefix list = %q, want %q", published, want)
	}
	if result.Prefixes != 2 {
		t.Errorf("Refresh reported %d prefixes, want the document's two distinct ranges", result.Prefixes)
	}
	if result.Stale {
		t.Error("Refresh marked a document it read from the origin as stale")
	}
	if result.ETag != fixtureETag {
		t.Errorf("Refresh reported etag %q, want the origin's %q", result.ETag, fixtureETag)
	}
	if result.URL != origin.server.URL {
		t.Errorf("Refresh reported url %q, want the origin's %q", result.URL, origin.server.URL)
	}
	if result.CachePath != cachePath {
		t.Errorf("Refresh reported cache path %q, want %q", result.CachePath, cachePath)
	}
	if result.PrefixPath != filepath.Join(dir, DefaultCloudflarePrefixFileName) {
		t.Errorf("Refresh reported prefix path %q, want the list beside the cache", result.PrefixPath)
	}
	if result.Prefixes != countPrefixLines(published) {
		t.Errorf("Refresh reported %d prefixes and published a list with %d lines", result.Prefixes, countPrefixLines(published))
	}
}

// The substitutability property, stated as a test: a refresh and a sample of one
// document publish byte-identical lists. If the two paths ever parse or render
// differently, the list an installation publishes is not the list the optimizer
// would have published, and the plugin's classification depends on which one the
// operator happened to get.
func TestRefreshAndTheDailySamplePublishTheSameList(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	first := t.TempDir()
	second := t.TempDir()

	refreshed(t, origin, filepath.Join(first, "cloudflare-ips.json"))
	cloudflareCandidates(t, newTestSource(t, origin, filepath.Join(second, "cloudflare-ips.json")), 8, testDate(2026, time.September, 25))

	fromRefresh, err := os.ReadFile(filepath.Join(first, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the refreshed list: %v", err)
	}
	fromSample, err := os.ReadFile(filepath.Join(second, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the sampled list: %v", err)
	}
	if string(fromRefresh) != string(fromSample) {
		t.Errorf("a refresh published %q and a sample published %q: the two paths render the same document differently", fromRefresh, fromSample)
	}
}

// The whole reason the refresh exists is that it must work before any optimizer
// run has ever happened, so a network failure has to be survivable from a cache
// the previous refresh left. An origin outage that refuses the install would
// leave a machine whose router cannot start.
func TestRefreshStandsInForAnUnreachableOriginWithTheCachedDocument(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cloudflare-ips.json")
	refreshed(t, origin, cachePath)
	before, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the first list: %v", err)
	}

	origin.setStatus(503)
	result := refreshed(t, origin, cachePath)

	if !result.Stale {
		t.Error("a refresh served from the cache did not report the document as stale")
	}
	after, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the republished list: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("the republished list = %q, want the last accepted document's ranges %q", after, before)
	}
}

// A refresh that accepted what a sample would refuse would publish a prefix list
// no measurement run would have produced, which is how a router ends up
// classifying against ranges this build does not understand. Every refusal is
// checked here because each one is a different gate, and one of them -- the
// empty range list -- only fires after the body has been read.
func TestRefreshRefusesExactlyWhatTheDailySampleRefuses(t *testing.T) {
	empty := `{"success":true,"errors":[],"messages":[],` +
		`"result":{"etag":"empty-lists","ipv4_cidrs":[],"ipv6_cidrs":[]}}`
	tests := []struct {
		name    string
		arrange func(t *testing.T, origin *fakeOrigin)
	}{
		{
			name: "a response with no validator",
			arrange: func(t *testing.T, origin *fakeOrigin) {
				origin.mutex.Lock()
				origin.etag = ""
				origin.mutex.Unlock()
			},
		},
		{
			name: "a document the origin reported as failed",
			arrange: func(t *testing.T, origin *fakeOrigin) {
				origin.mutex.Lock()
				origin.document = `{"success":false,"errors":[{"code":1000,"message":"nope"}]}`
				origin.etag = `W/"refused"`
				origin.mutex.Unlock()
			},
		},
		{
			name: "a document that is not JSON",
			arrange: func(t *testing.T, origin *fakeOrigin) {
				origin.mutex.Lock()
				origin.document = "not a document"
				origin.mutex.Unlock()
			},
		},
		{
			name: "a document naming no IPv4 range",
			arrange: func(t *testing.T, origin *fakeOrigin) {
				origin.mutex.Lock()
				origin.document = empty
				origin.mutex.Unlock()
			},
		},
		{
			name: "a range no rewrite target may use",
			arrange: func(t *testing.T, origin *fakeOrigin) {
				origin.mutex.Lock()
				origin.document = cloudflareDocument("10.0.0.0/8", fixtureIPv6CIDRs, fixtureETag)
				origin.mutex.Unlock()
			},
		},
		{
			name: "a response the origin could not answer",
			arrange: func(t *testing.T, origin *fakeOrigin) {
				origin.setStatus(503)
			},
		},
		{
			name: "a not-modified response with nothing cached",
			arrange: func(t *testing.T, origin *fakeOrigin) {
				origin.setNotModified(true)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cachePath := filepath.Join(dir, "cloudflare-ips.json")
			origin := newFakeOrigin(t, standardDocument(), fixtureETag)
			test.arrange(t, origin)
			source := newTestSource(t, origin, cachePath)

			if _, err := source.Refresh(context.Background()); err == nil {
				t.Fatal("Refresh accepted a document the daily sample refuses")
			}
			if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
				t.Errorf("a refused document reached the cache (stat error %v)", err)
			}
			if _, err := os.Stat(filepath.Join(dir, DefaultCloudflarePrefixFileName)); !os.IsNotExist(err) {
				t.Errorf("a refused document published a prefix list (stat error %v)", err)
			}
		})
	}
}

// A refusal must not destroy what is already published. The plugin refuses to
// construct without the list, so a refresh that emptied the directory on a bad
// day would take a running router's next restart with it.
func TestARefusedDocumentLeavesThePublishedListAlone(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	refreshed(t, origin, filepath.Join(dir, "cloudflare-ips.json"))
	before, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the first list: %v", err)
	}

	origin.mutex.Lock()
	origin.document = "not a document"
	origin.mutex.Unlock()
	if _, err := newTestSource(t, origin, filepath.Join(dir, "cloudflare-ips.json")).Refresh(t.Context()); err == nil {
		t.Fatal("Refresh accepted a document that is not JSON")
	}

	after, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the list after the refusal: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("the published list = %q after a refused refresh, want the previous one %q", after, before)
	}
}

// ReadPublished is how the report-only mode answers the one question that
// matters about the two artifacts: is there a prefix list, and does it describe
// the document the envelope beside it records. A report that said "present" for
// a list the envelope does not describe would be reporting the wrong file.
func TestReadPublishedReportsWhatTheTwoArtifactsHold(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cloudflare-ips.json")
	refreshed(t, origin, cachePath)

	published, err := ReadPublished(cachePath)
	if err != nil {
		t.Fatalf("ReadPublished: %v", err)
	}
	if !published.Present {
		t.Error("ReadPublished reported a missing pair after a refresh published both artifacts")
	}
	if !published.Consistent {
		t.Error("ReadPublished reported a list that does not match the envelope beside it")
	}
	contents, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the published list: %v", err)
	}
	sum := sha256.Sum256(contents)
	if published.Prefixes != countPrefixLines(contents) {
		t.Errorf("ReadPublished reported %d prefixes, want the published list's %d", published.Prefixes, countPrefixLines(contents))
	}
	if published.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("ReadPublished digest = %q, want the published list's %q", published.SHA256, hex.EncodeToString(sum[:]))
	}
	if published.ETag != fixtureETag {
		t.Errorf("ReadPublished etag = %q, want %q", published.ETag, fixtureETag)
	}
	if published.URL != origin.server.URL {
		t.Errorf("ReadPublished url = %q, want %q", published.URL, origin.server.URL)
	}
	if published.PrefixPath != filepath.Join(dir, DefaultCloudflarePrefixFileName) {
		t.Errorf("ReadPublished prefix path = %q, want the list beside the cache", published.PrefixPath)
	}
}

// The two refusals a report has to be able to state, and the inconsistency it has
// to be able to name. A missing artifact is a fact the report prints; an
// artifact that is there but says something else is a fact it also prints, and
// neither is a reason for the reader to invent a verdict.
func TestReadPublishedReportsAMissingOrInconsistentPair(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	tests := []struct {
		name    string
		arrange func(t *testing.T, dir string) string
		want    string
	}{
		{
			name: "nothing published at all",
			arrange: func(t *testing.T, dir string) string {
				return filepath.Join(dir, "cloudflare-ips.json")
			},
			want: DefaultCloudflarePrefixFileName,
		},
		{
			name: "an envelope with no prefix list beside it",
			arrange: func(t *testing.T, dir string) string {
				cachePath := filepath.Join(dir, "cloudflare-ips.json")
				refreshed(t, origin, cachePath)
				if err := os.Remove(filepath.Join(dir, DefaultCloudflarePrefixFileName)); err != nil {
					t.Fatal(err)
				}
				return cachePath
			},
			want: DefaultCloudflarePrefixFileName,
		},
		{
			name: "a prefix list with no envelope beside it",
			arrange: func(t *testing.T, dir string) string {
				cachePath := filepath.Join(dir, "cloudflare-ips.json")
				refreshed(t, origin, cachePath)
				if err := os.Remove(cachePath); err != nil {
					t.Fatal(err)
				}
				return cachePath
			},
			want: "cloudflare-ips.json",
		},
		{
			name: "a prefix list that does not describe the envelope's document",
			arrange: func(t *testing.T, dir string) string {
				cachePath := filepath.Join(dir, "cloudflare-ips.json")
				refreshed(t, origin, cachePath)
				if err := os.WriteFile(filepath.Join(dir, DefaultCloudflarePrefixFileName), []byte("192.0.2.0/24\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return cachePath
			},
			want: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			published, err := ReadPublished(test.arrange(t, dir))
			if err != nil {
				t.Fatalf("ReadPublished: %v", err)
			}
			if test.want == "" {
				// Both files are there, so they are present; what is wrong is that
				// the one the rewriter reads does not describe the one beside it,
				// and that is the flag that has to say so.
				if !published.Present {
					t.Error("a pair whose files disagree was reported as absent rather than inconsistent")
				}
				if published.Consistent {
					t.Error("a prefix list describing a different document was reported as consistent")
				}
				return
			}
			if published.Present {
				t.Error("a missing artifact was reported as present")
			}
			if published.Missing == "" {
				t.Error("a missing artifact was reported without naming it")
			}
			if !strings.Contains(published.Missing, test.want) {
				t.Errorf("the report names %q, want it to name %q", published.Missing, test.want)
			}
		})
	}
}

// A cache this build cannot read is not a cache, and a report that counted its
// prefix list as published would be reporting a document nothing can use. The
// envelope's own gates are therefore the report's gates.
func TestReadPublishedReportsACacheItCannotRead(t *testing.T) {
	// Two answers, and the difference is the point. A cache the reader refuses
	// outright is not a published pair, because the next run would refuse to
	// revalidate against it and the envelope is worthless. A cache that reads but
	// holds a body this build does not understand is a pair of files that are
	// both there and cannot be shown to agree, and the only honest report for
	// that is "not consistent" rather than a refusal: the prefix list exists, and
	// the rewriter will read it whether or not this build can vouch for the
	// envelope beside it.
	unusable := map[string]string{
		"not JSON":       "not a cache",
		"another schema": `{"schema_version":99,"url":"https://api.cloudflare.com/client/v4/ips","etag":"x","body":{"a":1}}`,
		"no validator":   `{"schema_version":1,"url":"https://api.cloudflare.com/client/v4/ips","body":{"a":1}}`,
		"an unknown field": `{"schema_version":1,"url":"https://api.cloudflare.com/client/v4/ips","etag":"x",` +
			`"body":{"a":1},"extra":true}`,
		"trailing content": `{"schema_version":1,"url":"https://api.cloudflare.com/client/v4/ips","etag":"x",` +
			`"body":{"a":1}} {"another":1}`,
	}
	for name, contents := range unusable {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cachePath := filepath.Join(dir, "cloudflare-ips.json")
			if err := os.WriteFile(cachePath, []byte(contents), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, DefaultCloudflarePrefixFileName), []byte("104.16.0.0/22\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			published, err := ReadPublished(cachePath)
			if err != nil {
				return // a refusal is a valid answer
			}
			if published.Present {
				t.Errorf("a cache this build cannot read was reported as a published pair: %+v", published)
			}
			if published.Missing != cachePath {
				t.Errorf("the report names %q as missing, want the envelope %q", published.Missing, cachePath)
			}
		})
	}

	t.Run("a body this build does not understand", func(t *testing.T) {
		dir := t.TempDir()
		cachePath := filepath.Join(dir, "cloudflare-ips.json")
		contents := `{"schema_version":1,"url":"https://api.cloudflare.com/client/v4/ips","etag":"x","body":{"result":{}}}`
		if err := os.WriteFile(cachePath, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, DefaultCloudflarePrefixFileName), []byte("104.16.0.0/22\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		published, err := ReadPublished(cachePath)
		if err != nil {
			t.Fatalf("ReadPublished: %v", err)
		}
		if !published.Present {
			t.Fatalf("both files are there, so the pair is present: %+v", published)
		}
		if published.Consistent {
			t.Error("a document this build cannot parse was reported as a list that matches its envelope: nothing checked that")
		}
	})
}
