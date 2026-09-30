package candidate

// The fallback the offline installation depends on, and the three things that
// must still win over it. A refresh with a pinned snapshot available and an
// origin it could not read publishes the snapshot; a refresh with a published
// document of its own keeps publishing that one, because replacing it with a
// package's older snapshot is re-pinning a pin this project did not make; and a
// refresh with an origin it could read takes the origin, because a pin is a
// fallback and not a floor.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pinnedSourceWith builds a source for a fake origin with the snapshot pair a
// package ships. The pair is written for the fake's own URL, which is what
// production has -- the pin's recorded source and the source reading it are the
// same endpoint -- and the mismatch case takes that away on purpose.
func pinnedSourceWith(t *testing.T, origin *fakeOrigin, cachePath string, paths PinnedSnapshotPaths) *HTTPCloudflareSource {
	t.Helper()
	source, err := NewCloudflareSourceWithPin(origin.client, origin.server.URL, cachePath, paths)
	if err != nil {
		t.Fatalf("NewCloudflareSourceWithPin: %v", err)
	}
	return source
}

func TestRefreshPublishesThePinnedSnapshotWhenTheOriginCannotBeRead(t *testing.T) {
	// The property the whole install transaction is waiting on: a machine with
	// no route to the origin, no document of its own, and the snapshot the
	// package ships still ends up with the prefix list the response rewriter
	// refuses to construct without.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cloudflare-ips.json")
	paths := writePinnedPair(t, filepath.Join(dir, "share"), origin.server.URL, standardDocument(), pinnedValidator)
	origin.setStatus(503)

	result, err := pinnedSourceWith(t, origin, cachePath, paths).Refresh(t.Context())
	if err != nil {
		t.Fatalf("a refresh with an unreadable origin and a verified snapshot refused: %v", err)
	}
	if !result.Pinned {
		t.Error("a refresh served from the snapshot did not report the document as the package's pin")
	}
	// Stale as well as pinned, because the origin was not read and these are not
	// today's ranges. A report that said only `pinned` would leave a reader
	// guessing whether the origin had been reached.
	if !result.Stale {
		t.Error("a refresh served from the snapshot did not report the document as stale")
	}
	if got := readFile(t, filepath.Join(dir, DefaultCloudflarePrefixFileName)); got != "104.16.0.0/22\n172.64.0.0/21\n" {
		t.Errorf("the published prefix list is %q, want the snapshot's own two ranges", got)
	}
	// The envelope is published too, and it is the snapshot's own bytes, so the
	// next run revalidates against the pin's validator rather than starting over
	// and so `--check` can compare the two.
	if got := readFile(t, cachePath); got != readFile(t, paths.Snapshot) {
		t.Errorf("the published envelope is not the snapshot's own bytes:\n%s", got)
	}
	if result.Pin.Source != origin.server.URL || result.Pin.FetchedAt.IsZero() {
		t.Errorf("the refresh did not report which pin it published: %+v", result.Pin)
	}
	if result.PrefixPath != filepath.Join(dir, DefaultCloudflarePrefixFileName) {
		t.Errorf("the refresh reported %q as the prefix list path", result.PrefixPath)
	}
}

func TestRefreshKeepsAPublishedDocumentAheadOfThePinnedSnapshot(t *testing.T) {
	// The never-re-pin property, at the only place it can be decided. A machine
	// that has published a document of its own -- because an online refresh read
	// one -- must keep it when the origin goes away, even though the package
	// ships a snapshot. Replacing it is the same act as re-pinning: a range list
	// a selector was built against, changed by an install.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cloudflare-ips.json")
	if _, err := newTestSource(t, origin, cachePath).Refresh(t.Context()); err != nil {
		t.Fatalf("the first refresh failed: %v", err)
	}
	published := readFile(t, filepath.Join(dir, DefaultCloudflarePrefixFileName))
	envelopeBefore := readFile(t, cachePath)
	// A snapshot of a DIFFERENT document, so a refresh that preferred it would
	// publish a list that is not the one on disk.
	other := cloudflareDocument("198.41.128.0/17", fixtureIPv6CIDRs, fixtureETag)
	paths := writePinnedPair(t, filepath.Join(dir, "share"), origin.server.URL, other, pinnedValidator)

	origin.setStatus(503)
	result, err := pinnedSourceWith(t, origin, cachePath, paths).Refresh(t.Context())
	if err != nil {
		t.Fatalf("a refresh with an unreadable origin and a published document refused: %v", err)
	}
	if result.Pinned {
		t.Error("the package's snapshot replaced a document this machine had already published")
	}
	if got := readFile(t, filepath.Join(dir, DefaultCloudflarePrefixFileName)); got != published {
		t.Errorf("the published prefix list is now %q, want the machine's own %q", got, published)
	}
	if got := readFile(t, cachePath); got != envelopeBefore {
		t.Errorf("the published envelope was rewritten:\n%s", got)
	}
}

func TestRefreshPrefersTheOriginOverThePinnedSnapshot(t *testing.T) {
	// A pin is a fallback, not a floor. With the origin readable its document is
	// today's and the shipped snapshot is not, so a refresh that reached for the
	// pin first would freeze every machine on the ranges the package happened to
	// be built with.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cloudflare-ips.json")
	other := cloudflareDocument("198.41.128.0/17", fixtureIPv6CIDRs, fixtureETag)
	paths := writePinnedPair(t, filepath.Join(dir, "share"), origin.server.URL, other, pinnedValidator)

	result, err := pinnedSourceWith(t, origin, cachePath, paths).Refresh(t.Context())
	if err != nil {
		t.Fatalf("a refresh with a readable origin refused: %v", err)
	}
	if result.Pinned {
		t.Error("the package's snapshot was published while the origin was readable")
	}
	if result.Stale {
		t.Error("a document read from the origin was reported as stale")
	}
	if got := readFile(t, filepath.Join(dir, DefaultCloudflarePrefixFileName)); got != "104.16.0.0/22\n172.64.0.0/21\n" {
		t.Errorf("the published prefix list is %q, want the origin document's two ranges", got)
	}
}

func TestRefreshRefusesWhenThePinnedSnapshotCannotStandIn(t *testing.T) {
	// The refusal that has protected every machine so far, unchanged: no
	// reachable origin, no usable published document, and a snapshot this
	// project cannot account for is a machine with no document at all. What is
	// added to the message is the third thing that was tried, because an
	// operator reading "the origin could not be read" on a machine that ships a
	// snapshot has to be told the snapshot was refused too, and why.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	cases := map[string]func(t *testing.T, dir string) PinnedSnapshotPaths{
		"a snapshot whose digest the lock does not record": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, origin.server.URL, standardDocument(), pinnedValidator)
			writeFile(t, paths.Snapshot, []byte(strings.Replace(readFile(t, paths.Snapshot), "104.16.0.0/22", "104.16.0.0/21", 1)))
			return paths
		},
		"a snapshot that is not there at all": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, origin.server.URL, standardDocument(), pinnedValidator)
			if err := os.Remove(paths.Snapshot); err != nil {
				t.Fatalf("remove the snapshot: %v", err)
			}
			return paths
		},
		"a lock that is not there at all": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, origin.server.URL, standardDocument(), pinnedValidator)
			if err := os.Remove(paths.Lock); err != nil {
				t.Fatalf("remove the lock: %v", err)
			}
			return paths
		},
		"a snapshot of an endpoint this source is not": func(t *testing.T, dir string) PinnedSnapshotPaths {
			// The pair is perfectly valid; it is a document from somewhere else,
			// and publishing it as this source's would make the envelope's URL
			// name an endpoint whose ranges are not the ones beside it.
			return writePinnedPair(t, dir, pinnedSource, standardDocument(), pinnedValidator)
		},
	}
	for label, build := range cases {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			cachePath := filepath.Join(dir, "cloudflare-ips.json")
			paths := build(t, filepath.Join(dir, "share"))
			origin.setStatus(503)

			result, err := pinnedSourceWith(t, origin, cachePath, paths).Refresh(t.Context())
			if err == nil {
				t.Fatalf("a refresh published %d prefixes from %s with no document to publish", result.Prefixes, label)
			}
			message := err.Error()
			// All three of the things that were tried, because each one is the
			// question an operator will ask first.
			for _, want := range []string{origin.server.URL, paths.Snapshot, paths.Lock} {
				if !strings.Contains(message, want) {
					t.Errorf("the refusal does not mention %s: %v", want, err)
				}
			}
			// And nothing published: a refusal that left a prefix list behind
			// would satisfy the next install's start requirement with ranges
			// nothing accounts for.
			if _, err := os.Stat(filepath.Join(dir, DefaultCloudflarePrefixFileName)); !os.IsNotExist(err) {
				t.Errorf("a refused refresh published a prefix list (stat error %v)", err)
			}
			if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
				t.Errorf("a refused refresh published a cache envelope (stat error %v)", err)
			}
		})
	}
}

func TestRefreshWithoutAPinnedSnapshotRefusesAsItAlwaysHas(t *testing.T) {
	// The control. A source built without one behaves exactly as it did before
	// the pin existed, so the fallback above cannot be what is holding an
	// installation up on an origin that answers.
	origin := newFakeOrigin(t, standardDocument(), fixtureETag)
	dir := t.TempDir()
	origin.setStatus(503)

	_, err := newTestSource(t, origin, filepath.Join(dir, "cloudflare-ips.json")).Refresh(t.Context())
	if err == nil {
		t.Fatal("a refresh with an unreadable origin, no cache and no snapshot published something")
	}
	if strings.Contains(err.Error(), "pinned") {
		t.Errorf("a source with no snapshot configured refused as though it had one: %v", err)
	}
}
