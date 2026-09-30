package candidate

// A machine with no route to `api.cloudflare.com` cannot produce the prefix list
// the response rewriter refuses to construct without, so every installation with
// no route to the internet has refused, and nothing downstream of that refusal
// has ever run. The replacement is a snapshot the package ships and a lock that
// accounts for it, and these tests hold the two halves of that: a reader that
// refuses a snapshot nothing accounts for, and a report that can say how old the
// pin it read is.
//
// The refusals come first and they are the point. A reader that fell back to a
// snapshot it could not verify would install a selector over ranges that are
// not Cloudflare's, which is worse than refusing, because the machine would
// resolve and nothing would say the ranges were wrong.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	// pinnedSource is the endpoint a snapshot names. It is a literal rather than
	// `DefaultCloudflareBaseURL` so a change to that constant cannot silently
	// make a fixture agree with it.
	pinnedSource = "https://api.cloudflare.com/client/v4/ips"
	// pinnedValidator is the HTTP validator the same response carried. It is a
	// different string from the revision -- Cloudflare's `result.etag` is the
	// revision and the `ETag` header is a validator derived from it, in the weak
	// form the real API uses -- and the reader holds the pair to both, because a
	// document whose revision and whose validator disagree is a document two
	// origins could be described by.
	pinnedValidator = `W/"8d1f0b3c2a1e"`
	// pinnedFetchedAt is when the snapshot was taken, in the RFC 3339 form the
	// lock records. Every expectation about it is that literal read back out of
	// the pin, so a reader that reported the current time instead of the pinned
	// one would fail.
	pinnedFetchedAt = "2026-09-30T00:03:59Z"
)

// pinnedLockFixture is the lock a package ships, in the shape the reader holds
// it to. The reader's own type is not used here, so a field the reader does not
// know about cannot be filled in by accident and a field it does know about
// cannot be filled in twice.
type pinnedLockFixture struct {
	SchemaVersion    int    `json:"schema_version"`
	Source           string `json:"source"`
	Revision         string `json:"revision"`
	FetchedAt        string `json:"fetched_at"`
	SHA256           string `json:"sha256"`
	PrefixListSHA256 string `json:"prefix_list_sha256"`
}

// envelopeFixture is the snapshot file in the shape a fetch stores, written by
// this fixture rather than by `writeCache` so a reader that loosened its own
// gates would still be tested against bytes it did not produce.
type envelopeFixture struct {
	SchemaVersion int             `json:"schema_version"`
	URL           string          `json:"url"`
	ETag          string          `json:"etag"`
	Body          json.RawMessage `json:"body"`
}

func sha256Of(t *testing.T, contents []byte) string {
	t.Helper()
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

// writePinnedPair writes the pair a package ships -- the snapshot, in the same
// envelope shape a fetch stores, and the lock beside it -- and returns where
// they are. `source` is the endpoint the document came from, `document` the
// origin's body and `validator` the ETag header it carried; the lock's two
// digests are computed over the bytes this fixture wrote, which is the only way
// they can be right.
func writePinnedPair(t *testing.T, dir, source, document, validator string) PinnedSnapshotPaths {
	t.Helper()
	paths := PinnedSnapshotPaths{
		Snapshot: filepath.Join(dir, "cloudflare-ranges.json"),
		Lock:     filepath.Join(dir, "cloudflare-ranges.lock.json"),
	}
	snapshotBytes, err := json.Marshal(envelopeFixture{
		SchemaVersion: 1,
		URL:           source,
		ETag:          validator,
		Body:          json.RawMessage(document),
	})
	if err != nil {
		t.Fatalf("encode the snapshot fixture: %v", err)
	}
	snapshotBytes = append(snapshotBytes, '\n')
	ranges, err := parseCloudflareDocument(source, []byte(document))
	if err != nil {
		t.Fatalf("the fixture's own document does not parse: %v", err)
	}
	var rendered strings.Builder
	for _, cidr := range ranges.Result.IPv4CIDRs {
		prefix, err := parseIPv4Prefix(cidr)
		if err != nil {
			t.Fatalf("parse the fixture's own range %q: %v", cidr, err)
		}
		fmt.Fprintf(&rendered, "%s\n", prefix)
	}
	writeFile(t, paths.Snapshot, snapshotBytes)
	writeFile(t, paths.Lock, mustJSON(t, pinnedLockFixture{
		SchemaVersion: 1,
		Source:        source,
		// The revision the document's own body carries, read out of the body by
		// this fixture rather than written beside it, so the pair a fixture
		// writes is consistent by construction and a refusal in a test is a
		// refusal the test meant to provoke.
		Revision:         ranges.Result.ETag,
		FetchedAt:        pinnedFetchedAt,
		SHA256:           sha256Of(t, snapshotBytes),
		PrefixListSHA256: sha256Of(t, []byte(rendered.String())),
	}))
	return paths
}

func writeFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode the lock fixture: %v", err)
	}
	return append(encoded, '\n')
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func rewriteLock(t *testing.T, paths PinnedSnapshotPaths, change func(pinnedLockFixture) pinnedLockFixture) {
	t.Helper()
	var lock pinnedLockFixture
	if err := json.Unmarshal([]byte(readFile(t, paths.Lock)), &lock); err != nil {
		t.Fatalf("decode the lock fixture: %v", err)
	}
	writeFile(t, paths.Lock, mustJSON(t, change(lock)))
}

func TestReadPinnedSnapshotReportsTheProvenanceItCanAccountFor(t *testing.T) {
	// The facts a report states about a pin, all of them read out of the lock
	// rather than assumed, and all of them literals here so a reader that
	// reported the wrong file's own values would fail rather than agree.
	paths := writePinnedPair(t, t.TempDir(), pinnedSource, standardDocument(), pinnedValidator)

	pin, err := ReadPinnedSnapshot(paths)
	if err != nil {
		t.Fatalf("ReadPinnedSnapshot: %v", err)
	}
	if pin.Source != pinnedSource {
		t.Errorf("the pin's source is %q, want %q", pin.Source, pinnedSource)
	}
	if pin.Revision != fixtureETag {
		t.Errorf("the pin's revision is %q, want the %q its own document records", pin.Revision, fixtureETag)
	}
	if pin.FetchedAt.UTC().Format(time.RFC3339) != pinnedFetchedAt {
		t.Errorf("the pin's fetched_at is %q, want %q", pin.FetchedAt.UTC().Format(time.RFC3339), pinnedFetchedAt)
	}
	if pin.SnapshotPath != paths.Snapshot || pin.LockPath != paths.Lock {
		t.Errorf("the pin names %q and %q, want %q and %q", pin.SnapshotPath, pin.LockPath, paths.Snapshot, paths.Lock)
	}
	if pin.SHA256 != sha256Of(t, []byte(readFile(t, paths.Snapshot))) {
		t.Errorf("the pin's own digest is %q, which is not the digest of the snapshot it read", pin.SHA256)
	}
	// The ranges the pin stands for are the ones in its own body, masked and in
	// order, and the count is that list's -- which is what an operator's report
	// will say the selector is classifying against.
	if pin.Prefixes != 2 {
		t.Errorf("the pin renders %d prefixes, want the 2 its document names", pin.Prefixes)
	}
	if pin.PrefixList != "104.16.0.0/22\n172.64.0.0/21\n" {
		t.Errorf("the pin's prefix list is %q, want the two ranges of its own document, masked and in order", pin.PrefixList)
	}
}

func TestReadPinnedSnapshotRefusesAPairItCannotVerify(t *testing.T) {
	// Every one of these is a machine that would install a selector over ranges
	// this project cannot account for, and every one has to be a refusal rather
	// than a warning: the router cannot start without a prefix list, so a reader
	// that accepted any of them would have published something.
	document := standardDocument()
	corrupt := func(t *testing.T, dir string) PinnedSnapshotPaths {
		paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
		// One range of the body changed, which is what a truncated download or a
		// hand edit looks like. The document still parses and still names two
		// prefixes, so only a digest can tell -- which is the whole reason there
		// is one.
		writeFile(t, paths.Snapshot, []byte(strings.Replace(readFile(t, paths.Snapshot), "104.16.0.0/22", "104.16.0.0/21", 1)))
		return paths
	}
	cases := map[string]func(t *testing.T, dir string) PinnedSnapshotPaths{
		"a snapshot whose bytes are not the ones the lock records": corrupt,
		"a snapshot that is not a document at all": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			writeFile(t, paths.Snapshot, []byte("{\"schema_version\":1,\"url\":\"\",\"etag\":\"\",\"body\":null}\n"))
			return paths
		},
		"a lock that records no digest of the snapshot": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				lock.SHA256 = ""
				return lock
			})
			return paths
		},
		"a lock that records no digest of the prefix list": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				lock.PrefixListSHA256 = ""
				return lock
			})
			return paths
		},
		"a lock that records a digest of a prefix list this document does not render": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				lock.PrefixListSHA256 = sha256Of(t, []byte("10.0.0.0/8\n"))
				return lock
			})
			return paths
		},
		"a lock that dates the pin nowhere": func(t *testing.T, dir string) PinnedSnapshotPaths {
			// A snapshot nobody can measure the age of is the one failure this
			// reader adds to the ones the China list's digest check already
			// refuses, and it is refused for its own reason: a three-month-old
			// pin is fine for a selector, a pin whose age is written down nowhere
			// is not.
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				lock.FetchedAt = ""
				return lock
			})
			return paths
		},
		"a lock that names no source": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				lock.Source = ""
				return lock
			})
			return paths
		},
		"a lock that records a revision the document does not carry": func(t *testing.T, dir string) PinnedSnapshotPaths {
			// The revision is the one field in the lock that can be checked
			// against the snapshot, so a lock that named another document's
			// revision while carrying this document's bytes would otherwise pass
			// every digest check there is.
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				lock.Revision = "c0ffee"
				return lock
			})
			return paths
		},
		"a lock that carries a field this build does not know": func(t *testing.T, dir string) PinnedSnapshotPaths {
			// The strictness `readAnyCache` applies to a cache, applied to the
			// lock beside it: a lock of another shape is not a lock this build
			// knows how to hold to, and holding it to the fields it happens to
			// recognise is how a pin becomes a pin nobody read.
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				return pinnedLockFixture{
					SchemaVersion: 2, Source: pinnedSource, Revision: fixtureETag,
					FetchedAt: pinnedFetchedAt, SHA256: strings.Repeat("0", 64),
					PrefixListSHA256: strings.Repeat("0", 64),
				}
			})
			return paths
		},
		"a pair that names two different endpoints": func(t *testing.T, dir string) PinnedSnapshotPaths {
			// Both digests are right, and both files are readable, and the two of
			// them are about different documents: the snapshot was taken from a
			// mirror and the lock names the real API. Publishing it would leave an
			// envelope whose URL is not the endpoint its ranges came from.
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			other := writePinnedPair(t, dir, "https://127.0.0.1:1/ips", document, pinnedValidator)
			contents := readFile(t, other.Snapshot)
			contents = strings.Replace(contents, "https://127.0.0.1:1/ips", pinnedSource, 1)
			writeFile(t, paths.Snapshot, []byte(contents))
			rewriteLock(t, paths, func(lock pinnedLockFixture) pinnedLockFixture {
				lock.SHA256 = sha256Of(t, []byte(contents))
				return lock
			})
			return paths
		},
		"a snapshot that is not there": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			if err := os.Remove(paths.Snapshot); err != nil {
				t.Fatalf("remove the snapshot: %v", err)
			}
			return paths
		},
		"a lock that is not there": func(t *testing.T, dir string) PinnedSnapshotPaths {
			paths := writePinnedPair(t, dir, pinnedSource, document, pinnedValidator)
			if err := os.Remove(paths.Lock); err != nil {
				t.Fatalf("remove the lock: %v", err)
			}
			return paths
		},
		"no pair at all": func(t *testing.T, dir string) PinnedSnapshotPaths {
			return PinnedSnapshotPaths{
				Snapshot: filepath.Join(dir, "absent-ranges.json"),
				Lock:     filepath.Join(dir, "absent-ranges.lock.json"),
			}
		},
	}
	for label, build := range cases {
		t.Run(label, func(t *testing.T) {
			paths := build(t, t.TempDir())
			pin, err := ReadPinnedSnapshot(paths)
			if err == nil {
				t.Fatalf("ReadPinnedSnapshot accepted %s and reported %d prefixes from %q",
					label, pin.Prefixes, pin.PrefixList)
			}
			// The refusal names the file, because a message that does not is a
			// message an operator cannot act on, and this refusal is what decides
			// whether the machine installs at all.
			if !strings.Contains(err.Error(), filepath.Base(paths.Snapshot)) &&
				!strings.Contains(err.Error(), filepath.Base(paths.Lock)) {
				t.Errorf("the refusal %q names neither of the two files it is about", err)
			}
		})
	}
}
