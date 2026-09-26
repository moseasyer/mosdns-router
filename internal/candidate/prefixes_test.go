package candidate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The response rewriter's `cloudflare_cidr_file` names a plain prefix list, and
// this is the only thing in the project that produces one. The cached envelope
// beside it is not a prefix list: it is the API's own JSON wrapped in the schema,
// URL and validator the cache keeps, so a plugin pointed at it has nothing to
// parse. The list therefore has to be published by the same fetch that caches the
// envelope -- one network request, two artifacts -- and these tests are what hold
// that to publishing a list a resolver can read.

func TestTheRangeFetchPublishesAParsedPrefixListBesideItsEnvelope(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cloudflare-ips.json")
	source := newTestSource(t, origin, cachePath)

	cloudflareCandidates(t, source, 8, testDate(2026, 9, 25))

	// The envelope is still written, because the revalidation depends on it.
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("the cache envelope is not beside the prefix list: %v", err)
	}
	published := filepath.Join(dir, DefaultCloudflarePrefixFileName)
	contents, err := os.ReadFile(published)
	if err != nil {
		t.Fatalf("read %s: %v", published, err)
	}
	// The document's own ranges, one per line, in the order the resolver's
	// comparison does not care about: the plugin reads them into a set, and a
	// sorted file is one a human can diff between two days.
	want := "104.16.0.0/22\n172.64.0.0/21\n"
	if string(contents) != want {
		t.Fatalf("%s = %q, want %q", DefaultCloudflarePrefixFileName, contents, want)
	}
	// One fetch, two artifacts. A second request would mean the list was produced
	// by a different code path from the cache, and the two would drift.
	if served := origin.bodiesServed(); served != 1 {
		t.Fatalf("the origin served %d bodies, want 1: the prefix list must come from the same fetch as the envelope", served)
	}
}

// A range the origin lists twice is one range, and a range it lists inside another
// is still one line: a prefix list is read into a set, and a file that repeats
// itself is a file two runs can disagree about the length of.
func TestThePublishedPrefixListHasNoDuplicates(t *testing.T) {
	document := cloudflareDocument("104.16.0.0/22,104.16.0.0/22,172.64.0.0/21", fixtureIPv6CIDRs, fixtureETag)
	origin := newFakeOrigin(t, document, fixtureETag)
	dir := t.TempDir()
	source := newTestSource(t, origin, filepath.Join(dir, "cloudflare-ips.json"))

	cloudflareCandidates(t, source, 8, testDate(2026, 9, 25))

	contents, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the published prefix list: %v", err)
	}
	if want := "104.16.0.0/22\n172.64.0.0/21\n"; string(contents) != want {
		t.Fatalf("published list = %q, want %q", contents, want)
	}
}

// A stale document is still the last one this build accepted, so its ranges are
// still what the router should classify with. An origin that cannot be read must
// not leave the rewriter with no list at all: the failure it would cause is a
// router that classifies every response as somebody else's and rewrites nothing,
// while looking perfectly healthy.
func TestThePrefixListIsPublishedFromAStaleDocumentToo(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	source := newTestSource(t, origin, filepath.Join(dir, "cloudflare-ips.json"))
	cloudflareCandidates(t, source, 8, testDate(2026, 9, 25))

	origin.mutex.Lock()
	origin.status = 500
	origin.mutex.Unlock()
	set := cloudflareSet(t, source, 8, testDate(2026, 9, 25))
	if !set.Stale {
		t.Fatal("the second run did not report a stale document, so this test is not exercising the stale path")
	}
	contents, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the published prefix list: %v", err)
	}
	if want := "104.16.0.0/22\n172.64.0.0/21\n"; string(contents) != want {
		t.Fatalf("published list = %q, want the last accepted document's ranges %q", contents, want)
	}
}

// A document this build refuses publishes no list, and never leaves a previous one
// looking like it came from the refused document.
func TestARefusedDocumentPublishesNoPrefixList(t *testing.T) {
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	source := newTestSource(t, origin, filepath.Join(dir, "cloudflare-ips.json"))
	cloudflareCandidates(t, source, 8, testDate(2026, 9, 25))

	origin.mutex.Lock()
	origin.document = `{"success":false,"errors":[{"code":1000,"message":"nope"}]}`
	origin.etag = `W/"refused"`
	origin.mutex.Unlock()
	if _, err := source.Candidates(t.Context(), 8, testDate(2026, 9, 25)); err == nil {
		t.Fatal("a document the origin reported as failed was accepted")
	}

	contents, err := os.ReadFile(filepath.Join(dir, DefaultCloudflarePrefixFileName))
	if err != nil {
		t.Fatalf("read the published prefix list: %v", err)
	}
	if strings.Contains(string(contents), "refused") {
		t.Fatalf("the published list mentions the refused document: %q", contents)
	}
}
