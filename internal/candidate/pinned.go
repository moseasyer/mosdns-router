package candidate

// A package that installs this router has to be able to start it on a machine
// with no route to the internet, and the prefix list the response rewriter
// refuses to construct without comes from exactly one endpoint. Every
// installation with no route has therefore refused, which is correct -- a
// selector over ranges nobody can account for is worse -- and has left nothing
// downstream of the refusal ever running.
//
// This file is the other half of that: a snapshot of the document the package
// was built against, shipped in the package, beside a lock that records where it
// came from, when it was taken and both of its digests. It is the China list's
// mechanism applied to the ranges, deliberately: a reviewed pin the package
// carries, a recorded digest, a refusal when the digest does not match, and no
// re-pinning at any point.
//
// Three properties are load-bearing and each is refused rather than tolerated:
//
//   - the snapshot is a *cache envelope*, byte for byte what a fetch stores, so
//     publishing it puts a document this build can revalidate into place rather
//     than a file of somebody's making that nothing else can vouch for;
//   - both digests are checked -- the snapshot's own bytes and the prefix list
//     that body renders -- because the file the router reads is the second one
//     and a pin nobody can account for in either is not a pin;
//   - the recorded source must be the source asking, because a mirror's URL over
//     Cloudflare's ranges is an envelope that will revalidate against the wrong
//     origin on the next run.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// DefaultPinnedSnapshotPath and DefaultPinnedSnapshotLockPath are where this
	// package installs the pair. They are constants for the same reason
	// DefaultCloudflareCachePath is: the tool that publishes has to default to
	// the file the package carries, because the installer runs it with no paths
	// at all and a default that named anything else would silently publish from
	// nothing.
	DefaultPinnedSnapshotPath     = "/usr/share/mosdns-router/cloudflare-ranges.json"
	DefaultPinnedSnapshotLockPath = "/usr/share/mosdns-router/cloudflare-ranges.lock.json"

	// pinnedLockSchemaVersion is the shape of a written lock. A lock carrying any
	// other version is not read, for the reason a cache of another version is
	// not: this build cannot know what a record of another version accounts for.
	pinnedLockSchemaVersion = 1
)

// PinnedSnapshotPaths is the pair a package ships: the snapshot itself and the
// lock beside it. Both are parameters, so nothing in this package reads a
// shipped file unless a caller named it, and a test never reads the repository's
// own copy by accident.
type PinnedSnapshotPaths struct {
	// Snapshot is the document, in the envelope shape a fetch stores.
	Snapshot string
	// Lock is what accounts for it. It is not optional and it is not derived: a
	// snapshot with no lock beside it is a file of ranges this project cannot
	// account for, and the pair is the unit for the same reason the China list's
	// pair is.
	Lock string
}

// PinnedSnapshot is a snapshot that has been verified against the lock beside it,
// and everything a report can state about it without reading either file again.
type PinnedSnapshot struct {
	// SnapshotPath and LockPath are the two files this was read from, as the
	// caller named them, so a refusal or a report can name them.
	SnapshotPath string
	LockPath     string
	// Source is the endpoint the document came from, as the lock records it. A
	// reader compares it with its own endpoint before using the pin, and a
	// mismatch is a refusal.
	Source string
	// Revision is the document's own revision marker, and Prefixes the number of
	// prefixes that document renders to. Both are what a report states, and the
	// second is the count of the list the router is about to classify against
	// rather than the count of the entries in the body, which is the count after
	// masking and deduplication.
	Revision string
	// FetchedAt is when the snapshot was taken, and it is the reason the lock is
	// read at all rather than only the digests: a three-month-old pin is fine
	// for a selector, and a pin nobody measures the age of is not.
	FetchedAt time.Time
	// SHA256 is the digest of the snapshot file as it was read, and
	// PrefixListSHA256 the digest of the rendered list. Both were compared
	// against the lock before this was returned.
	SHA256           string
	PrefixListSHA256 string
	// PrefixList is the rendered list itself, one masked prefix per line in
	// ascending order. It is what the refresh publishes, and holding it here is
	// what lets the reader verify the second digest with the same renderer that
	// writes the file rather than with a second one free to drift from it.
	PrefixList string
	// Prefixes is how many lines that list holds.
	Prefixes int
	// Body is the document's bytes exactly as the snapshot stored them, and
	// Validator the ETag the same response carried, so a published envelope
	// describes the same document the pin does and the next run revalidates
	// against the pin's own validator.
	Body      []byte
	Validator string
}

// pinnedLock is what a package writes beside a snapshot. Every field is
// required, and a lock missing one is refused rather than defaulted: a lock that
// names no date, or no digest, or no source is a record of nothing, and a
// missing field is how a record becomes one without anybody noticing.
type pinnedLock struct {
	SchemaVersion int    `json:"schema_version"`
	Source        string `json:"source"`
	Revision      string `json:"revision"`
	FetchedAt     string `json:"fetched_at"`
	// SHA256 is the digest of the snapshot file beside the lock, and
	// PrefixListSHA256 the digest of the prefix list that snapshot renders to.
	// Two digests rather than one because the two files are the two artifacts a
	// published document consists of, and the second is the one a router reads.
	SHA256           string `json:"sha256"`
	PrefixListSHA256 string `json:"prefix_list_sha256"`
}

// ReadPinnedSnapshot reads the pair a package ships and refuses anything it
// cannot account for.
//
// It reads both files and writes nothing, so a report may call it and a refusal
// leaves the machine exactly as it found it. Every refusal names the file it is
// about, because this refusal is what decides whether an installation completes
// and an operator has to be able to act on it.
//
// The order of the checks is the order of what each one is evidence about. The
// snapshot's own bytes are digested first, because until the lock says which
// bytes it accounts for there is nothing to compare them to; the lock's shape and
// its required fields come next, because a lock of another version, or one
// missing its date, is a record this build cannot read at all; and the two digest
// comparisons and the document's own parse come last, so a refusal names the
// check that failed rather than the first thing that happened to differ.
func ReadPinnedSnapshot(paths PinnedSnapshotPaths) (PinnedSnapshot, error) {
	if paths.Snapshot == "" || paths.Lock == "" {
		return PinnedSnapshot{}, fmt.Errorf(
			"a pinned snapshot is two files, and %q and %q are not both of them",
			paths.Snapshot, paths.Lock)
	}
	contents, err := os.ReadFile(paths.Snapshot)
	if err != nil {
		return PinnedSnapshot{}, fmt.Errorf("%s: read the pinned snapshot: %w", paths.Snapshot, err)
	}
	digest := digestOf(contents)
	lock, err := readPinnedLock(paths.Lock)
	if err != nil {
		return PinnedSnapshot{}, err
	}
	if digest != lock.SHA256 {
		return PinnedSnapshot{}, fmt.Errorf(
			"%s is %s and %s records %s for it, so this package cannot account for the ranges in it",
			paths.Snapshot, digest, paths.Lock, lock.SHA256)
	}
	document, err := readEnvelopeFile(paths.Snapshot)
	if err != nil {
		return PinnedSnapshot{}, fmt.Errorf("%s: it is not a document this build can publish: %w", paths.Snapshot, err)
	}
	if document.URL != lock.Source {
		return PinnedSnapshot{}, fmt.Errorf(
			"%s records the endpoint %s and %s records %s, so the pair does not describe one document",
			paths.Snapshot, document.URL, paths.Lock, lock.Source)
	}
	ranges, err := parseCloudflareDocument(document.URL, document.Body)
	if err != nil {
		return PinnedSnapshot{}, fmt.Errorf("%s: the ranges in it are not ones this build can use: %w", paths.Snapshot, err)
	}
	if ranges.Result.ETag != lock.Revision {
		return PinnedSnapshot{}, fmt.Errorf(
			"%s records the revision %s and %s records %s, so the pair does not describe one document",
			paths.Snapshot, ranges.Result.ETag, paths.Lock, lock.Revision)
	}
	rendered, err := renderPrefixList(ranges)
	if err != nil {
		return PinnedSnapshot{}, fmt.Errorf("%s: its ranges do not render: %w", paths.Snapshot, err)
	}
	if listDigest := digestOf(rendered); listDigest != lock.PrefixListSHA256 {
		return PinnedSnapshot{}, fmt.Errorf(
			"%s renders the prefix list %s and %s records %s for it, so the file a router would read is not one this project can account for",
			paths.Snapshot, listDigest, paths.Lock, lock.PrefixListSHA256)
	}
	fetched, err := time.Parse(time.RFC3339, lock.FetchedAt)
	if err != nil {
		// The lock's own gate already refused a value that is not a time; this
		// parse is the second half of the same refusal, so a future change to
		// that gate cannot leave this one to be the only thing holding it.
		return PinnedSnapshot{}, fmt.Errorf("%s: fetched_at %q is not an RFC 3339 time: %w",
			paths.Lock, lock.FetchedAt, err)
	}
	return PinnedSnapshot{
		SnapshotPath:     paths.Snapshot,
		LockPath:         paths.Lock,
		Source:           lock.Source,
		Revision:         ranges.Result.ETag,
		FetchedAt:        fetched.UTC(),
		SHA256:           digest,
		PrefixListSHA256: lock.PrefixListSHA256,
		PrefixList:       string(rendered),
		Prefixes:         countPrefixLines(rendered),
		Body:             document.Body,
		Validator:        document.ETag,
	}, nil
}

// readPinnedLock reads the lock beside a snapshot and refuses every shape this
// build cannot hold to.
//
// Strict decoding and a version check, for the reason readAnyCache applies the
// same two gates to a cache: a record of a shape this build does not know is not
// a record it can account for, and reading the fields it happens to recognise out
// of one is how a pin becomes a pin nobody read. Every field is required for the
// same reason -- a lock with no digest, no date or no source records nothing, and
// the whole of what shipping the pair is worth is the record.
func readPinnedLock(path string) (pinnedLock, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return pinnedLock{}, fmt.Errorf("%s: read the lock for the pinned snapshot: %w", path, err)
	}
	lock := pinnedLock{}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return pinnedLock{}, fmt.Errorf("%s: it is not a lock this build can read: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return pinnedLock{}, fmt.Errorf("%s: it carries trailing content", path)
	}
	if lock.SchemaVersion != pinnedLockSchemaVersion {
		return pinnedLock{}, fmt.Errorf("%s is schema version %d, and this build reads version %d",
			path, lock.SchemaVersion, pinnedLockSchemaVersion)
	}
	for _, field := range []struct{ name, value string }{
		{"source", lock.Source},
		{"revision", lock.Revision},
		{"fetched_at", lock.FetchedAt},
		{"sha256", lock.SHA256},
		{"prefix_list_sha256", lock.PrefixListSHA256},
	} {
		if strings.TrimSpace(field.value) == "" {
			return pinnedLock{}, fmt.Errorf(
				"%s records no %s, so the snapshot beside it is a file of ranges with nothing accounting for it",
				path, field.name)
		}
	}
	if _, err := time.Parse(time.RFC3339, lock.FetchedAt); err != nil {
		return pinnedLock{}, fmt.Errorf("%s records fetched_at %q, which is not an RFC 3339 time: %w",
			path, lock.FetchedAt, err)
	}
	return lock, nil
}

// NewCloudflareSourceWithPin returns a source that will publish the snapshot a
// package ships when, and only when, the origin cannot be read and there is no
// published document of this machine's own to stand in for it.
//
// The order is the whole of the design, and it is the China list's order because
// that is the only precedent this project has for a reviewed pin: what the
// machine published of its own wins, then a request to the origin, and the
// package's snapshot last. An offline upgrade therefore keeps the document the
// machine already classified against, and a machine that has published nothing at
// all -- which is every fresh installation with no route to the internet -- gets
// the ranges the package was built against instead of a refusal.
func NewCloudflareSourceWithPin(client *http.Client, baseURL, cachePath string, paths PinnedSnapshotPaths) (*HTTPCloudflareSource, error) {
	source, err := NewCloudflareSource(client, baseURL, cachePath)
	if err != nil {
		return nil, err
	}
	source.pin = paths
	return source, nil
}
