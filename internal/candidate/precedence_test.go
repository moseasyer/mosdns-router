package candidate

// The order three places state, held against the order the code does.
//
// The code reads the origin first, falls back to this machine's own published
// document, and only then to the snapshot the package ships. Three documents say
// so, and all three said it BACKWARDS for a while -- the operator-facing manual
// first, and it was wrong in the one case that matters most to an operator: with
// a readable origin the published document is replaced by today's, so "this
// machine's own published document, then the origin" is false precisely where a
// machine is online.
//
// A docstring is prose, and prose drifts. This file is what makes the two
// comparable: it MEASURES the order by making the three cells happen -- origin
// readable, origin unreadable with a document of this machine's own, origin
// unreadable with nothing of its own -- and then requires each of the three
// documents to state that same order, in one named line whose parse is a
// comparison rather than a reading.
//
// The measured order and the stated order are both written out as the same
// three tokens, so a change to either is a visible change to both.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three sources, as this package's own report names them, in the order the
// code tries them. A token per source, and the test's whole method is: where
// these three appear in a stated order, and do they appear in this one.
const (
	orderOrigin = "the origin"
	orderOwn    = "this machine's own published document"
	orderPin    = "the package's snapshot"
	// The words the three documents open the sentence with, and the reason they
	// are the same three in all three: a parse that had to find each document's
	// own phrasing would be a parse each document could phrase its way out of.
	orderSentencePrefix = "The order is"
)

// measuredOrder is the order `Refresh` actually uses, established by making each
// cell happen and recording which document the refresh published.
func measuredOrder(t *testing.T) []string {
	t.Helper()
	order := []string{orderOrigin, orderOwn, orderPin}

	// One: the origin, readable. The pin beside it is of a DIFFERENT document,
	// so a refresh that reached for the pin first would publish the wrong list
	// and this would say so.
	t.Run("a readable origin publishes the origin's document", func(t *testing.T) {
		origin := newFakeOrigin(t, standardDocument(), fixtureETag)
		dir := t.TempDir()
		other := cloudflareDocument("198.41.128.0/17", fixtureIPv6CIDRs, fixtureETag)
		paths := writePinnedPair(t, filepath.Join(dir, "share"), origin.server.URL, other, pinnedValidator)

		result, err := pinnedSourceWith(t, origin, filepath.Join(dir, "cloudflare-ips.json"), paths).Refresh(t.Context())
		if err != nil {
			t.Fatalf("a refresh with a readable origin refused: %v", err)
		}
		if result.Pinned {
			t.Fatalf("the package's snapshot was published while the origin was readable")
		}
		if result.Stale {
			t.Errorf("a document read from the origin was reported as stale")
		}
	})

	// Two: the origin unreadable and a document of this machine's own already on
	// disk. The pin beside it is of a different document again, so a refresh that
	// preferred it would be visible in the published list.
	t.Run("an unreadable origin keeps this machine's own document", func(t *testing.T) {
		origin := newFakeOrigin(t, standardDocument(), fixtureETag)
		dir := t.TempDir()
		cachePath := filepath.Join(dir, "cloudflare-ips.json")
		if _, err := newTestSource(t, origin, cachePath).Refresh(t.Context()); err != nil {
			t.Fatalf("the first refresh failed: %v", err)
		}
		published := readFile(t, filepath.Join(dir, DefaultCloudflarePrefixFileName))
		other := cloudflareDocument("198.41.128.0/17", fixtureIPv6CIDRs, fixtureETag)
		paths := writePinnedPair(t, filepath.Join(dir, "share"), origin.server.URL, other, pinnedValidator)

		origin.setStatus(503)
		result, err := pinnedSourceWith(t, origin, cachePath, paths).Refresh(t.Context())
		if err != nil {
			t.Fatalf("a refresh with an unreadable origin and a document of its own refused: %v", err)
		}
		if result.Pinned {
			t.Errorf("the package's snapshot replaced a document this machine had already published")
		}
		if got := readFile(t, filepath.Join(dir, DefaultCloudflarePrefixFileName)); got != published {
			t.Errorf("the published prefix list is now %q, want the machine's own %q", got, published)
		}
	})

	// Three: the origin unreadable and nothing of this machine's own to keep --
	// which is every fresh installation with no route, and the only cell in
	// which the snapshot is the source.
	t.Run("an unreadable origin with nothing of its own publishes the package's snapshot", func(t *testing.T) {
		origin := newFakeOrigin(t, standardDocument(), fixtureETag)
		dir := t.TempDir()
		paths := writePinnedPair(t, filepath.Join(dir, "share"), origin.server.URL, standardDocument(), pinnedValidator)
		origin.setStatus(503)

		result, err := pinnedSourceWith(t, origin, filepath.Join(dir, "cloudflare-ips.json"), paths).Refresh(t.Context())
		if err != nil {
			t.Fatalf("a refresh with an unreadable origin and nothing of its own refused: %v", err)
		}
		if !result.Pinned {
			t.Errorf("the package's snapshot was not published, so the order is not the one measured")
		}
	})
	return order
}

// statedOrder reads one document's statement of the order out of the ONE SENTENCE
// that carries it, and requires the sentence to exist.
//
// The sentence names the three sources in order. Parsing by position rather than
// by sense means a document that names all three and puts them in the wrong
// sequence fails here, which is the whole point: the manual said "this machine's
// own published document, then the origin, then the package's snapshot", which
// names all three and is false.
//
// The unit is the SENTENCE and not the line, because prose wraps: a document that
// states its order in one sentence split across three lines has stated it once.
func statedOrder(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// One line, so a sentence split across three of them is one sentence. The
	// emphasis markers a roff document and a Go comment use are kept: they are
	// part of the writing and the sentence ends after them.
	flat := strings.Join(strings.Fields(string(raw)), " ")
	_, after, found := strings.Cut(flat, orderSentencePrefix)
	if !found {
		t.Fatalf("%s has no sentence beginning %q, so nothing states the order an operator reads", path, orderSentencePrefix)
	}
	sentence := after
	// The sentence ends at the first FULL STOP: a period followed by a space, or
	// by an emphasis marker and then a space, or by nothing at all. A period
	// inside a word is not one -- `a.b` is not a sentence boundary, and neither
	// is the `.(4)` of a file name.
	for at := 0; at < len(after); at++ {
		if after[at] != '.' {
			continue
		}
		rest := strings.TrimLeft(after[at+1:], "*")
		if rest == "" || rest[0] == ' ' {
			sentence = after[:at+1]
			break
		}
	}
	tokens := []string{orderOrigin, orderOwn, orderPin}
	got := make([]string, 0, len(tokens))
	rest := sentence
	for {
		best, at := -1, -1
		for index, token := range tokens {
			if found := strings.Index(rest, token); found >= 0 && (at < 0 || found < at) {
				best, at = index, found
			}
		}
		if best < 0 {
			break
		}
		got = append(got, tokens[best])
		rest = rest[at+1:]
	}
	if len(got) != len(tokens) {
		t.Fatalf("%s states the order in a sentence that does not name all three sources: %q", path, sentence)
	}
	return got
}

func TestTheThreeDocumentsStateTheOrderTheCodeUses(t *testing.T) {
	want := measuredOrder(t)
	// The three places that state it, and the reason each one is here: the
	// operator-facing manual, and the two doc comments a reader of the fallback
	// is most likely to reach for. `packaging/man/mosdns-cdnctl.1` is prose for
	// a person, and the manual is where a wrong order is worst -- it is the one
	// that says a machine never re-pins its ranges.
	for _, path := range []string{
		filepath.Join("..", "..", "packaging", "man", "mosdns-cdnctl.1"),
		"refresh.go",
		"pinned.go",
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			got := statedOrder(t, path)
			for index := range want {
				if got[index] != want[index] {
					t.Errorf("%s states the order as %v, and the code uses %v.\n"+
						"The origin is read first: with a reachable origin the published document is "+
						"replaced by today's ranges, which is what `ranges-source: origin` reports and "+
						"what keeps a machine online from being frozen on the ranges its package was "+
						"built with. A machine's own published document comes second -- it is what an "+
						"unreachable origin falls back to, so an offline upgrade keeps the ranges its "+
						"selector was built against -- and the package's snapshot is last, because it "+
						"is the only one of the three that is months old by construction.",
						path, got, want)
					return
				}
			}
		})
	}
}

func TestTheOrderIsNotStatedAnywhereElseInTheManual(t *testing.T) {
	// A second statement of the order in the same document is a second thing
	// that can be wrong, and the wrong one is the one a reader skims to. So the
	// manual says it once, and this case is what says so.
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "man", "mosdns-cdnctl.1"))
	if err != nil {
		t.Fatalf("read the manual: %v", err)
	}
	flat := strings.Join(strings.Fields(string(raw)), " ")
	if seen := strings.Count(flat, orderSentencePrefix); seen != 1 {
		t.Errorf("mosdns-cdnctl.1 states the order %d time(s) with %q; it should state it once, on a "+
			"line a reader skims to being the one that is wrong", seen, orderSentencePrefix)
	}
}
