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

// mustReadDirectory returns a directory's entries, failing the test if it cannot
// be read.
func mustReadDirectory(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	return entries
}

// snapshotDirectory records every file in a directory with its contents, so a
// test can prove a failed publication left it exactly as it was, leftovers
// included.
func snapshotDirectory(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	state := make(map[string][]byte)
	for _, entry := range mustReadDirectory(t, dir) {
		contents, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		state[entry.Name()] = contents
	}
	return state
}

// assertDirectoryMatches requires a directory to hold exactly the recorded files.
func assertDirectoryMatches(t *testing.T, want map[string][]byte, dir string) {
	t.Helper()
	got := snapshotDirectory(t, dir)
	if len(got) != len(want) {
		t.Fatalf("%s holds %v, want exactly %v", dir, entryNames(mustReadDirectory(t, dir)), namesOf(want))
	}
	for name, contents := range want {
		existing, ok := got[name]
		if !ok {
			t.Errorf("%s: %s is missing", dir, name)
			continue
		}
		if !bytes.Equal(existing, contents) {
			t.Errorf("%s: %s =\n%s\nwant\n%s", dir, name, existing, contents)
		}
	}
}

// keptBackups returns the backup files left in a directory, in name order.
func keptBackups(t *testing.T, dir string) []string {
	t.Helper()
	var backups []string
	for _, entry := range mustReadDirectory(t, dir) {
		if strings.HasSuffix(entry.Name(), ".bak") {
			backups = append(backups, entry.Name())
		}
	}
	sort.Strings(backups)
	return backups
}

func namesOf(state map[string][]byte) []string {
	names := make([]string, 0, len(state))
	for name := range state {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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

func TestPublishLeavesThePairAloneWhenItFailsBeforeAnyRename(t *testing.T) {
	// A failure while staging a file or taking a backup, and a failed list rename,
	// all happen before a single published file has been replaced. There is
	// nothing to restore then, and a rollback that ran anyway would be reporting a
	// repair it never made. The published pair has to come out untouched, with no
	// leftovers, and the number of renames attempted says whether any restore ran.
	tests := []struct {
		name       string
		breakIt    func(t *testing.T, ops *fileOps, renames *int)
		paths      func(t *testing.T) (lockPath, listPath string)
		wantRenmes int
		wantStep   string
	}{
		{
			name: "the first backup cannot be written",
			breakIt: func(t *testing.T, ops *fileOps, renames *int) {
				flushes := 0
				syncFile := ops.syncFile
				ops.syncFile = func(file *os.File) error {
					flushes++
					// The two staged files are flushed first, then the backups.
					if flushes == 3 {
						return errors.New("injected file flush failure")
					}
					return syncFile(file)
				}
			},
			wantRenmes: 0,
			wantStep:   "sync backup",
		},
		{
			name: "the list rename fails",
			breakIt: func(t *testing.T, ops *fileOps, renames *int) {
				rename := ops.rename
				ops.rename = func(from, to string) error {
					*renames++
					if *renames == 1 {
						return errors.New("injected list rename failure")
					}
					return rename(from, to)
				}
			},
			wantRenmes: 1,
			wantStep:   "publish list",
		},
		{
			name:       "the lock cannot be staged where its directory is missing",
			breakIt:    func(t *testing.T, ops *fileOps, renames *int) {},
			wantRenmes: 0,
			wantStep:   "create temporary file",
			paths: func(t *testing.T) (lockPath, listPath string) {
				pair := writePublishedPair(t)
				// The list's directory exists, so the list is staged and flushed
				// first; the lock's does not, so staging it fails.
				return filepath.Join(t.TempDir(), "missing", "source-lock.json"), pair.listPath
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pair := writePublishedPair(t)
			lockPath, listPath := pair.lockPath, pair.listPath
			if test.paths != nil {
				lockPath, listPath = test.paths(t)
			}
			before := snapshotDirectory(t, filepath.Dir(listPath))
			renames := 0
			ops := defaultFileOps()
			test.breakIt(t, &ops, &renames)

			err := publishWithOps(lockPath, listPath, newLock, []byte(newList), ops)
			if err == nil {
				t.Fatal("publish reported success although it failed before renaming anything")
			}
			if !strings.Contains(err.Error(), test.wantStep) {
				t.Errorf("error = %v, want it to name the %q step", err, test.wantStep)
			}
			if renames != test.wantRenmes {
				t.Errorf("publish attempted %d renames, want %d: a failure before a rename owes no restore", renames, test.wantRenmes)
			}
			assertDirectoryMatches(t, before, filepath.Dir(listPath))
		})
	}
}

func TestPublishRestoresBothFilesWhenTheLockDirectoryCannotBeFlushed(t *testing.T) {
	// The last step of publication is flushing the directory the lock was renamed
	// into, and both renames have already happened by then. Restoring only the list
	// would leave the previous list beside the new lock: a pair
	// ReadPublishedPair refuses forever, with the previous lock thrown away. So a
	// failure here has to put both files back, byte for byte.
	tests := []struct {
		name    string
		arrange func(t *testing.T) (lockPath, listPath string)
	}{
		{
			// One directory: the second flush is the lock's.
			name: "one directory, second flush fails",
			arrange: func(t *testing.T) (string, string) {
				pair := writePublishedPair(t)
				return pair.lockPath, pair.listPath
			},
		},
		{
			// Two directories, as the CLI allows: the failure is the lock
			// directory's flush, which cannot be mistaken for the list's.
			name: "two directories, the lock directory flush fails",
			arrange: func(t *testing.T) (string, string) {
				pair := writePublishedPair(t)
				lockPath := filepath.Join(t.TempDir(), "source-lock.json")
				if err := os.WriteFile(lockPath, pair.lockBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				return lockPath, pair.listPath
			},
		},
		{
			// A first pin has no previous pair, so a rollback has to remove what
			// the failed publication created.
			name: "a first pin with nothing published",
			arrange: func(t *testing.T) (string, string) {
				dir := t.TempDir()
				return filepath.Join(dir, "source-lock.json"), filepath.Join(dir, "cn-domains.txt")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lockPath, listPath := test.arrange(t)
			listDir := snapshotDirectory(t, filepath.Dir(listPath))
			lockDirectory := snapshotDirectory(t, filepath.Dir(lockPath))

			flushes := 0
			ops := defaultFileOps()
			syncDir := ops.syncDir
			ops.syncDir = func(path string) error {
				flushes++
				if flushes == 2 {
					return errors.New("injected directory flush failure")
				}
				return syncDir(path)
			}

			err := publishWithOps(lockPath, listPath, newLock, []byte(newList), ops)
			if err == nil {
				t.Fatal("publish reported success although the lock directory could not be flushed")
			}
			if !strings.Contains(err.Error(), "injected directory flush failure") {
				t.Errorf("error = %v, want it to carry the flush failure", err)
			}
			if !strings.Contains(err.Error(), "sync lock directory") {
				t.Errorf("error = %v, want it to name the step that failed", err)
			}
			assertDirectoryMatches(t, listDir, filepath.Dir(listPath))
			assertDirectoryMatches(t, lockDirectory, filepath.Dir(lockPath))
		})
	}
}

func TestPublishKeepsBothBackupsWhenNeitherRestoreWorks(t *testing.T) {
	// The flush of the lock directory fails and so does every restore that would
	// follow. Both backups are then the only copies of what the gateway was
	// running, and neither may be cleaned up: one failing restore must not stop
	// the other from being attempted, and every backup that survives has to be
	// named so the operator can find it.
	pair := writePublishedPair(t)
	flushes, renames := 0, 0
	ops := defaultFileOps()
	syncDir := ops.syncDir
	ops.syncDir = func(path string) error {
		flushes++
		if flushes == 2 {
			return errors.New("injected directory flush failure")
		}
		return syncDir(path)
	}
	rename := ops.rename
	ops.rename = func(from, to string) error {
		renames++
		if renames > 2 {
			return errors.New("injected restore failure")
		}
		return rename(from, to)
	}

	err := publishWithOps(pair.lockPath, pair.listPath, newLock, []byte(newList), ops)
	if err == nil {
		t.Fatal("publish reported success although nothing after the renames worked")
	}
	kept := keptBackups(t, pair.dir)
	if len(kept) != 2 {
		t.Fatalf("directory holds %v, want a kept backup of both the list and the lock", entryNames(mustReadDirectory(t, pair.dir)))
	}
	for _, backup := range kept {
		if !strings.Contains(err.Error(), backup) {
			t.Errorf("error = %v, want it to name the kept backup %s", err, backup)
		}
	}
	if !strings.Contains(err.Error(), "injected restore failure") {
		t.Errorf("error = %v, want it to carry the restore failure", err)
	}
}

func TestPublishRestoresTheListEvenWhenTheLockCannotBeRestored(t *testing.T) {
	// The lock's restore fails first. The list is still owed a restore, and taking
	// it leaves the gateway on the list it was running, which is recoverable from
	// the named lock backup alone.
	pair := writePublishedPair(t)
	flushes, renames := 0, 0
	ops := defaultFileOps()
	syncDir := ops.syncDir
	ops.syncDir = func(path string) error {
		flushes++
		if flushes == 2 {
			return errors.New("injected directory flush failure")
		}
		return syncDir(path)
	}
	rename := ops.rename
	ops.rename = func(from, to string) error {
		renames++
		// Renames 1 and 2 publish the pair; rename 3 restores the lock and fails.
		if renames == 3 {
			return errors.New("injected lock restore failure")
		}
		return rename(from, to)
	}

	if err := publishWithOps(pair.lockPath, pair.listPath, newLock, []byte(newList), ops); err == nil {
		t.Fatal("publish reported success although the lock directory could not be flushed")
	}
	list, err := os.ReadFile(pair.listPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(list) != oldList {
		t.Fatalf("list = %q, want the previous %q even though the lock restore failed", list, oldList)
	}
	kept := keptBackups(t, pair.dir)
	if len(kept) != 1 {
		t.Fatalf("directory holds %v, want only the lock backup to survive", entryNames(mustReadDirectory(t, pair.dir)))
	}
	keptLock, err := os.ReadFile(filepath.Join(pair.dir, kept[0]))
	if err != nil {
		t.Fatal(err)
	}
	if string(keptLock) != oldLock {
		t.Fatalf("kept backup = %q, want the previous lock %q", keptLock, oldLock)
	}
}

func TestPublishKeepsTheOnlyCopyOfThePreviousListWhenTheRollbackItselfFails(t *testing.T) {
	// Two failures in a row leave the backup as the only copy of the list the
	// router was running. Cleaning it up would destroy the last thing that can
	// put the gateway back on its previous rules, so it is named in the failure
	// and left where the operator can find it.
	pair := writePublishedPair(t)
	calls := 0
	ops := recordingOps(&[]string{})
	rename := ops.rename
	ops.rename = func(from, to string) error {
		calls++
		if calls >= 2 {
			return errors.New("injected rename failure")
		}
		return rename(from, to)
	}

	err := publishWithOps(pair.lockPath, pair.listPath, newLock, []byte(newList), ops)
	if err == nil {
		t.Fatal("publish reported success although neither the lock nor the rollback worked")
	}
	if !strings.Contains(err.Error(), "the previous list is kept at") {
		t.Fatalf("error = %v, want it to name the kept backup", err)
	}
	entries, readErr := os.ReadDir(pair.dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var backups []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".bak") {
			backups = append(backups, entry.Name())
		}
	}
	if len(backups) != 1 {
		t.Fatalf("directory holds %v, want exactly one kept backup", entryNames(entries))
	}
	kept, readErr := os.ReadFile(filepath.Join(pair.dir, backups[0]))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(kept) != oldList {
		t.Fatalf("kept backup = %q, want the previous list %q", kept, oldList)
	}
	if !strings.Contains(err.Error(), backups[0]) {
		t.Errorf("error = %v, want it to name the kept backup file %s", err, backups[0])
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
