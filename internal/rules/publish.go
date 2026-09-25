package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// publishedFileMode is the exact mode every published list and lock file
	// carries, whatever the caller's umask or the file's previous mode.
	publishedFileMode = 0640
)

// fileOps are the file operations publication is built from. They are a field
// set rather than direct calls so a test can make one of them fail and observe
// what the caller is left with.
type fileOps struct {
	syncFile func(*os.File) error
	syncDir  func(string) error
	rename   func(string, string) error
	remove   func(string) error
}

func defaultFileOps() fileOps {
	return fileOps{
		syncFile: func(file *os.File) error { return file.Sync() },
		syncDir:  syncDirectory,
		rename:   os.Rename,
		remove:   os.Remove,
	}
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// Publish writes the published list and the lock that describes it.
//
// The two files cannot be renamed into place as one operation, so the list is
// published first and the lock second: a crash between the two renames leaves
// the previous lock beside a new list, which the next reader refuses because the
// two no longer describe each other. A failure to publish the lock instead rolls
// the list back, so a failed update leaves the previous pair byte for byte and
// the operator is never left with a half-published source.
func Publish(lockPath, listPath string, lock SourceLock, list []byte) error {
	return publishWithOps(lockPath, listPath, lock, list, defaultFileOps())
}

func publishWithOps(lockPath, listPath string, lock SourceLock, list []byte, ops fileOps) (err error) {
	if lockPath == "" || listPath == "" {
		return errors.New("a source lock path and a list path are both required")
	}
	if lockPath == listPath {
		return fmt.Errorf("%s: the source lock and the list must be different files", lockPath)
	}
	if err := lock.Validate(); err != nil {
		return fmt.Errorf("source lock: %w", err)
	}
	if actual := digestHex(list); actual != lock.ListSHA256 {
		return fmt.Errorf("list sha256 %s does not match the lock's list_sha256 %s", actual, lock.ListSHA256)
	}
	encoded, err := lock.Encode()
	if err != nil {
		return fmt.Errorf("%s: %w", lockPath, err)
	}
	// A missing directory is the operator's to create: provisioning the list
	// directory is part of installing the service, and publication refusing a
	// mistyped path is better than it quietly creating one.

	// Both files are staged and flushed before either is published, so a failure
	// to write either one happens before the pair starts to change.
	listStage, err := stageFile(listPath, list, ops)
	if err != nil {
		return err
	}
	defer listStage.discard(&err, ops)
	lockStage, err := stageFile(lockPath, encoded, ops)
	if err != nil {
		return err
	}
	defer lockStage.discard(&err, ops)

	listBackup, err := takeBackup(listPath, ops)
	if err != nil {
		return err
	}
	defer listBackup.discard(&err, ops)
	lockBackup, err := takeBackup(lockPath, ops)
	if err != nil {
		return err
	}
	defer lockBackup.discard(&err, ops)

	if err := ops.rename(listStage.path, listPath); err != nil {
		return fmt.Errorf("%s: publish list: %w", listPath, err)
	}
	listStage.path = ""
	if err := ops.syncDir(filepath.Dir(listPath)); err != nil {
		return fmt.Errorf("%s: sync list directory: %w", listPath, err)
	}

	if err := ops.rename(lockStage.path, lockPath); err != nil {
		// The lock is the record of the list, so a list published without it is a
		// list nobody can account for. Put the previous list back before
		// reporting the failure.
		if rollbackErr := listBackup.restore(listPath, ops); rollbackErr != nil {
			// The backup is then the only copy of the previous list, so it is kept
			// for the operator instead of being cleaned up.
			listBackup.keep = true
			return fmt.Errorf("%s: publish lock: %w (and restoring the previous list failed: %v, the previous list is kept at %s)", lockPath, err, rollbackErr, listBackup.path)
		}
		listBackup.restored = true
		return fmt.Errorf("%s: publish lock: %w (the previous list was restored)", lockPath, err)
	}
	lockStage.path = ""
	if err := ops.syncDir(filepath.Dir(lockPath)); err != nil {
		return fmt.Errorf("%s: sync lock directory: %w", lockPath, err)
	}
	return nil
}

// stagedFile is a file written next to its target and waiting to be renamed over
// it. A staged file that is never published is removed; one that cannot be
// removed is reported, because a leftover copy of a published source is state
// nothing manages.
type stagedFile struct {
	path string
}

func stageFile(target string, contents []byte, ops fileOps) (stagedFile, error) {
	staged, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return stagedFile{}, fmt.Errorf("%s: create temporary file: %w", target, err)
	}
	path := staged.Name()
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		_ = staged.Close()
		_ = os.Remove(path)
	}()
	if err := staged.Chmod(publishedFileMode); err != nil {
		return stagedFile{}, fmt.Errorf("%s: set temporary file mode: %w", target, err)
	}
	if _, err := staged.Write(contents); err != nil {
		return stagedFile{}, fmt.Errorf("%s: write temporary file: %w", target, err)
	}
	if err := ops.syncFile(staged); err != nil {
		return stagedFile{}, fmt.Errorf("%s: sync temporary file: %w", target, err)
	}
	if err := staged.Close(); err != nil {
		return stagedFile{}, fmt.Errorf("%s: close temporary file: %w", target, err)
	}
	cleanup = false
	return stagedFile{path: path}, nil
}

// discard removes a staged file that was never published. A leftover is joined
// onto the caller's error rather than dropped.
func (s stagedFile) discard(err *error, ops fileOps) {
	if s.path == "" {
		return
	}
	if removeErr := ops.remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		*err = errors.Join(*err, fmt.Errorf("remove %s: %w", s.path, removeErr))
	}
}

// backupFile is a copy of a published file, taken before publication so a failed
// publication can put it back. A target that did not exist has nothing to copy,
// and a rollback for it removes the file the failed publication created.
type backupFile struct {
	path     string
	existed  bool
	restored bool
	keep     bool
}

func takeBackup(target string, ops fileOps) (backupFile, error) {
	backup := backupFile{}
	contents, err := os.ReadFile(target)
	if errors.Is(err, os.ErrNotExist) {
		return backup, nil
	}
	if err != nil {
		return backup, fmt.Errorf("%s: read the published file: %w", target, err)
	}
	copied, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*.bak")
	if err != nil {
		return backup, fmt.Errorf("%s: create backup: %w", target, err)
	}
	backup.path = copied.Name()
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		_ = copied.Close()
		_ = os.Remove(backup.path)
	}()
	if err := copied.Chmod(publishedFileMode); err != nil {
		return backup, fmt.Errorf("%s: set backup mode: %w", target, err)
	}
	if _, err := copied.Write(contents); err != nil {
		return backup, fmt.Errorf("%s: write backup: %w", target, err)
	}
	if err := ops.syncFile(copied); err != nil {
		return backup, fmt.Errorf("%s: sync backup: %w", target, err)
	}
	if err := copied.Close(); err != nil {
		return backup, fmt.Errorf("%s: close backup: %w", target, err)
	}
	cleanup = false
	backup.existed = true
	return backup, nil
}

// restore puts the previous contents of a target back after a failed
// publication: by renaming the backup over a file that existed before, and by
// removing a file the failed publication created when there was none.
func (b backupFile) restore(target string, ops fileOps) error {
	if !b.existed {
		if err := ops.remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := ops.rename(b.path, target); err != nil {
		return err
	}
	b.restored = true
	return ops.syncDir(filepath.Dir(target))
}

// discard removes a backup that is no longer needed: either because the
// publication succeeded, or because a rollback already renamed it back. A backup
// that is still the only copy of the previous contents is kept and named in the
// failure instead.
func (b backupFile) discard(err *error, ops fileOps) {
	if b.path == "" || b.restored || b.keep {
		return
	}
	if removeErr := ops.remove(b.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		*err = errors.Join(*err, fmt.Errorf("remove backup %s: %w", b.path, removeErr))
	}
}

// ReadPublishedPair reads the published list and the lock that describes it.
//
// A directory with neither file is a first install, reported as not found rather
// than as an error. A directory with only one of them, a lock that does not
// validate, and a list whose digest the lock does not record are all errors: a
// pair that disagrees with itself is not something a caller may overwrite on the
// strength of its own new content.
func ReadPublishedPair(lockPath, listPath string) (SourceLock, []byte, bool, error) {
	if lockPath == "" || listPath == "" {
		return SourceLock{}, nil, false, errors.New("a source lock path and a list path are both required")
	}
	if lockPath == listPath {
		return SourceLock{}, nil, false, fmt.Errorf("%s: the source lock and the list must be different files", lockPath)
	}
	lockBytes, lockErr := os.ReadFile(lockPath)
	list, listErr := os.ReadFile(listPath)
	lockMissing := errors.Is(lockErr, os.ErrNotExist)
	listMissing := errors.Is(listErr, os.ErrNotExist)
	if lockErr != nil && !lockMissing {
		return SourceLock{}, nil, false, fmt.Errorf("%s: read the source lock: %w", lockPath, lockErr)
	}
	if listErr != nil && !listMissing {
		return SourceLock{}, nil, false, fmt.Errorf("%s: read the list: %w", listPath, listErr)
	}
	if lockMissing && listMissing {
		return SourceLock{}, nil, false, nil
	}
	if lockMissing {
		return SourceLock{}, nil, false, fmt.Errorf("%s: a list is published without a source lock at %s", listPath, lockPath)
	}
	if listMissing {
		return SourceLock{}, nil, false, fmt.Errorf("%s: a source lock is published without a list file at %s", lockPath, listPath)
	}
	lock, err := ParseSourceLock(lockBytes)
	if err != nil {
		return SourceLock{}, nil, false, fmt.Errorf("%s: %w", lockPath, err)
	}
	if err := lock.Validate(); err != nil {
		return SourceLock{}, nil, false, fmt.Errorf("%s: validate the source lock: %w", lockPath, err)
	}
	if actual := digestHex(list); actual != lock.ListSHA256 {
		return SourceLock{}, nil, false, fmt.Errorf("%s: list sha256 %s does not match the list_sha256 the source lock at %s records", listPath, actual, lockPath)
	}
	return lock, list, true, nil
}
