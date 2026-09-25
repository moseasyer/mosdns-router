package rules

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The publication contract is the operator's last line of defence: a failed
// update has to leave the list and the lock that describes it exactly as they
// were, because the router reads the list and a lock that disagrees with it is
// not a record of anything.

const (
	// oldList is the last known good list a rollback has to restore byte for
	// byte, and oldLock its lock.
	oldList = "domain:previous.cn\n"
	oldLock = `{
  "schema_version": 1,
  "repository": "v2fly/domain-list-community",
  "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "list_sha256": "9de01e827107e3574e096a1cf5b72f675bf30af19f86520697b1a6a4726cf3da",
  "entry": "data/cn"
}
`
	// newList is the candidate list, and newLock the lock that describes it.
	newList = "domain:current.cn\ndomain:previous.cn\n"
)

var newLock = SourceLock{
	SchemaVersion: schemaVersion,
	Repository:    Repository,
	Commit:        fixtureCommit,
	SHA256:        digest([]byte("current archive")),
	ListSHA256:    digest([]byte(newList)),
	Entry:         Entry,
}

// publishedPair is a directory holding the last known good lock and list.
type publishedPair struct {
	dir       string
	lockPath  string
	listPath  string
	lockBytes []byte
	listBytes []byte
}

func writePublishedPair(t *testing.T) publishedPair {
	t.Helper()
	dir := t.TempDir()
	pair := publishedPair{
		dir:       dir,
		lockPath:  filepath.Join(dir, "source-lock.json"),
		listPath:  filepath.Join(dir, "cn-domains.txt"),
		lockBytes: []byte(oldLock),
		listBytes: []byte(oldList),
	}
	if err := os.WriteFile(pair.lockPath, pair.lockBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pair.listPath, pair.listBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return pair
}

// recordingOps returns the real operations with the rename order recorded, so a
// test can see which file was published first.
func recordingOps(order *[]string) fileOps {
	ops := defaultFileOps()
	rename := ops.rename
	ops.rename = func(from, to string) error {
		*order = append(*order, filepath.Base(to))
		return rename(from, to)
	}
	return ops
}

func TestPublishWritesTheListAndTheLockThatDescribesIt(t *testing.T) {
	// A published pair has to be readable, self-consistent and free of leftovers:
	// the router reads the list while the lock records what produced it, and a
	// temporary file left in the directory is a copy of runtime state nobody
	// manages. The list is published first so a crash between the two renames
	// leaves the old lock, which the next pin refuses to overwrite.
	pair := writePublishedPair(t)
	var order []string
	if err := publishWithOps(pair.lockPath, pair.listPath, newLock, []byte(newList), recordingOps(&order)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	written, err := os.ReadFile(pair.listPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != newList {
		t.Fatalf("published list = %q, want %q", written, newList)
	}
	encoded, err := newLock.Encode()
	if err != nil {
		t.Fatal(err)
	}
	writtenLock, err := os.ReadFile(pair.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writtenLock, encoded) {
		t.Fatalf("published lock =\n%s\nwant\n%s", writtenLock, encoded)
	}
	if strings.Join(order, ",") != "cn-domains.txt,source-lock.json" {
		t.Fatalf("publication order = %v, want the list before the lock", order)
	}

	lock, list, found, err := ReadPublishedPair(pair.lockPath, pair.listPath)
	if err != nil {
		t.Fatalf("ReadPublishedPair: %v", err)
	}
	if !found || lock != newLock || string(list) != newList {
		t.Fatalf("ReadPublishedPair = %+v, %q, %t", lock, list, found)
	}

	entries, err := os.ReadDir(pair.dir)
	if err != nil {
		t.Fatal(err)
	}
	names := entryNames(entries)
	if strings.Join(names, ",") != "cn-domains.txt,source-lock.json" {
		t.Fatalf("publication left files behind: %v", names)
	}
	for _, path := range []string{pair.listPath, pair.lockPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Errorf("%s mode = %v, want 0640", filepath.Base(path), info.Mode().Perm())
		}
	}
}

func TestPublishRestoresTheListWhenTheLockCannotBePublished(t *testing.T) {
	// A half-published pair is worse than a failed update: the router would read
	// a new list that no lock describes. So every failure after the list rename
	// has to undo it, whether the lock rename failed or the directory could not
	// be flushed, and both files are left exactly as they were.
	tests := []struct {
		name    string
		breakIt func(*fileOps, *int)
	}{
		{
			name: "the lock rename fails",
			breakIt: func(ops *fileOps, calls *int) {
				rename := ops.rename
				ops.rename = func(from, to string) error {
					*calls++
					if *calls == 2 {
						return errors.New("injected rename failure")
					}
					return rename(from, to)
				}
			},
		},
		{
			name: "the list directory cannot be flushed",
			breakIt: func(ops *fileOps, calls *int) {
				syncDir := ops.syncDir
				ops.syncDir = func(path string) error {
					*calls++
					if *calls == 1 {
						return errors.New("injected directory sync failure")
					}
					return syncDir(path)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pair := writePublishedPair(t)
			calls := 0
			ops := recordingOps(&[]string{})
			test.breakIt(&ops, &calls)

			err := publishWithOps(pair.lockPath, pair.listPath, newLock, []byte(newList), ops)
			if err == nil {
				t.Fatal("publish reported success although the lock could not be published")
			}
			if !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error = %v, want it to carry the injected failure", err)
			}

			list, err := os.ReadFile(pair.listPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(list) != oldList {
				t.Fatalf("list after the failed publish = %q, want the previous %q", list, oldList)
			}
			lock, err := os.ReadFile(pair.lockPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(lock) != oldLock {
				t.Fatalf("lock after the failed publish =\n%s\nwant\n%s", lock, oldLock)
			}
			entries, err := os.ReadDir(pair.dir)
			if err != nil {
				t.Fatal(err)
			}
			if names := entryNames(entries); strings.Join(names, ",") != "cn-domains.txt,source-lock.json" {
				t.Fatalf("failed publication left files behind: %v", names)
			}
		})
	}
}

func TestPublishRemovesTheNewListWhenTheLockCannotBePublished(t *testing.T) {
	// A first pin has no previous pair, so there is nothing to restore: the list
	// the failed pin created has to go, or the router would read a list no lock
	// describes.
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "source-lock.json")
	listPath := filepath.Join(dir, "cn-domains.txt")
	ops := recordingOps(&[]string{})
	rename := ops.rename
	failures := 0
	ops.rename = func(from, to string) error {
		failures++
		if failures == 2 {
			return errors.New("injected rename failure")
		}
		return rename(from, to)
	}

	if err := publishWithOps(lockPath, listPath, newLock, []byte(newList), ops); err == nil {
		t.Fatal("publish reported success although the lock could not be written")
	}
	if _, err := os.Stat(listPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("list after the failed first pin: %v, want it removed", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if names := entryNames(entries); len(names) != 0 {
		t.Fatalf("failed first pin left files behind: %v", names)
	}
}

func TestPublishRefusesBeforeTouchingAnything(t *testing.T) {
	// A lock that does not describe the bytes being published, a lock that is
	// not a complete pin, and two targets that are the same file are all caller
	// errors. Each must be refused with the previous pair untouched, because the
	// alternative is publishing a pair that disagrees with itself.
	pair := writePublishedPair(t)
	wrongDigest := newLock
	wrongDigest.ListSHA256 = digest([]byte("something else"))
	unpinned := newLock
	unpinned.SHA256 = ""
	tests := []struct {
		name  string
		lock  SourceLock
		list  []byte
		paths func(publishedPair) (string, string)
	}{
		{name: "list is not the one the lock describes", lock: wrongDigest, list: []byte(newList)},
		{name: "lock is not fully pinned", lock: unpinned, list: []byte(newList)},
		{
			name: "same path for both files",
			lock: newLock, list: []byte(newList),
			paths: func(pair publishedPair) (string, string) { return pair.listPath, pair.listPath },
		},
		{
			name: "empty list path",
			lock: newLock, list: []byte(newList),
			paths: func(pair publishedPair) (string, string) { return pair.lockPath, "" },
		},
		{
			name: "empty lock path",
			lock: newLock, list: []byte(newList),
			paths: func(pair publishedPair) (string, string) { return "", pair.listPath },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lockPath, listPath := pair.lockPath, pair.listPath
			if test.paths != nil {
				lockPath, listPath = test.paths(pair)
			}
			if err := Publish(lockPath, listPath, test.lock, test.list); err == nil {
				t.Fatal("Publish accepted a pair it must refuse")
			}
			list, err := os.ReadFile(pair.listPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(list) != oldList {
				t.Fatalf("refused publish changed the list to %q", list)
			}
			lock, err := os.ReadFile(pair.lockPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(lock) != oldLock {
				t.Fatalf("refused publish changed the lock to %s", lock)
			}
		})
	}
}

func TestPublishRefusesAMissingDirectoryInsteadOfCreatingIt(t *testing.T) {
	// Installing the service provisions the list directory, and a mistyped path
	// must be visible rather than turned into a new empty directory tree.
	dir := filepath.Join(t.TempDir(), "not-installed")
	if err := Publish(filepath.Join(dir, "source-lock.json"), filepath.Join(dir, "cn-domains.txt"), newLock, []byte(newList)); err == nil {
		t.Fatal("Publish accepted a path whose directory does not exist")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Publish created the missing directory: %v", err)
	}
}

func TestReadPublishedPairReportsWhatItFound(t *testing.T) {
	// The CLI has to tell three situations apart before it may overwrite
	// anything: nothing has been published yet, a valid pair is published, and
	// what is on disk does not describe itself. The last case must be an error
	// rather than a pair to be silently replaced.
	pair := writePublishedPair(t)
	mismatched := writePublishedPair(t)
	if err := os.WriteFile(mismatched.listPath, []byte("domain:tampered.cn\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	invalidLock := writePublishedPair(t)
	if err := os.WriteFile(invalidLock.lockPath, []byte(`{"schema_version":1,"repository":"v2fly/domain-list-community","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","entry":"data/cn"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	futureLock := writePublishedPair(t)
	if err := os.WriteFile(futureLock.lockPath, []byte(strings.Replace(oldLock, `"schema_version": 1`, `"schema_version": 99`, 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		dir     string
		lock    string
		list    string
		wantSet bool
		wantErr string
	}{
		{name: "nothing published yet", dir: t.TempDir(), lock: "source-lock.json", list: "cn-domains.txt"},
		{name: "a valid pair", dir: pair.dir, lock: "source-lock.json", list: "cn-domains.txt", wantSet: true},
		{name: "list does not match its lock", dir: mismatched.dir, lock: "source-lock.json", list: "cn-domains.txt", wantErr: "does not match the list_sha256 the source lock"},
		{name: "lock is incomplete", dir: invalidLock.dir, lock: "source-lock.json", list: "cn-domains.txt", wantErr: "list_sha256"},
		{name: "lock is a newer shape", dir: futureLock.dir, lock: "source-lock.json", list: "cn-domains.txt", wantErr: "schema_version"},
		{name: "lock without a list", dir: pair.dir, lock: "source-lock.json", list: "other.txt", wantErr: "without a list file"},
		{name: "list without a lock", dir: pair.dir, lock: "other.json", list: "cn-domains.txt", wantErr: "without a source lock"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lock, list, found, err := ReadPublishedPair(filepath.Join(test.dir, test.lock), filepath.Join(test.dir, test.list))
			switch {
			case test.wantErr != "":
				if err == nil {
					t.Fatalf("ReadPublishedPair accepted the pair and returned %+v, %q, %t", lock, list, found)
				}
				if !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want it to mention %q", err, test.wantErr)
				}
				if found {
					t.Fatal("ReadPublishedPair reported a usable pair alongside an error")
				}
			case err != nil:
				t.Fatalf("ReadPublishedPair: %v", err)
			case found != test.wantSet:
				t.Fatalf("ReadPublishedPair found = %t, want %t", found, test.wantSet)
			case test.wantSet && (string(list) != oldList || lock.ListSHA256 != digest([]byte(oldList))):
				t.Fatalf("ReadPublishedPair = %+v, %q", lock, list)
			case test.wantSet == false && (len(list) != 0 || lock != (SourceLock{})):
				t.Fatalf("ReadPublishedPair returned %+v, %q for an unpublished pair", lock, list)
			}
		})
	}
}

func TestReadPublishedPairRefusesTheSamePathTwice(t *testing.T) {
	pair := writePublishedPair(t)
	if _, _, _, err := ReadPublishedPair(pair.listPath, pair.listPath); err == nil {
		t.Fatal("ReadPublishedPair accepted one file as both the lock and the list")
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}
