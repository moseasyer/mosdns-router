package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Publishing the two generated documents has the same obligation internal/rules
// has when it publishes a list and the lock that describes it: the two files
// cannot be renamed into place as one operation, so a failure between the two
// renames has to put the first one back, or the gateway comes up reading a
// routing document from one policy and a resolver document from another. The
// obligations are the same ones, spelled the same way:
//
//   - both documents are staged, flushed and closed before either is published,
//     so a failure to write either happens before the pair starts to change;
//   - both are backed up before either is published, so a rollback has something
//     to put back;
//   - a step that fails after a document was replaced owes that document's
//     restore, and a step that fails before any was replaced owes none;
//   - a restore that fails itself keeps its backup, because that backup is then
//     the only copy of what the gateway was running, and names it in the error
//     rather than cleaning it up;
//   - a missing directory is the operator's to create: provisioning the document
//     directory is part of installing the service, and a mistyped --out is
//     better refused than quietly created.
//
// The discipline is implemented here rather than shared with internal/rules
// because the machinery that carries it -- the staged-file, backup and file-operations
// types -- is unexported there, and moving it would reshape a publisher whose
// rollback tests drive those internals by name. The duplication is deliberate and
// the two files have to be read together.

// documentFileOps are the file operations a document publication is built from.
// They are a field set rather than direct calls so a test can make one of them
// fail and observe what the caller is left with.
type documentFileOps struct {
	syncFile func(*os.File) error
	syncDir  func(string) error
	rename   func(string, string) error
	remove   func(string) error
}

func defaultDocumentOps() documentFileOps {
	return documentFileOps{
		syncFile: func(file *os.File) error { return file.Sync() },
		syncDir:  syncDocumentDirectory,
		rename:   os.Rename,
		remove:   os.Remove,
	}
}

func syncDocumentDirectory(path string) error {
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

// publishPairWithOps publishes the rendered documents into dir. The routing
// document is published first and the resolver document second: a crash between
// the two renames leaves a new routing document beside the previous resolver
// document, which is a gateway whose foreign branch reaches a provider the policy
// no longer names. The reverse order would leave a routing document that still
// routes the way the previous resolver document expects.
func publishPairWithOps(dir string, documents documentPair, ops documentFileOps) (err error) {
	if strings.TrimSpace(dir) == "" {
		return errors.New("an output directory is required")
	}
	if len(documents) == 0 {
		return errors.New("there is nothing to publish")
	}
	seen := make(map[string]bool, len(documents))
	for _, document := range documents {
		if document.Name == "" || document.Name != filepath.Base(document.Name) {
			return fmt.Errorf("%q is not a document name, want the name of a file inside the output directory", document.Name)
		}
		if seen[document.Name] {
			return fmt.Errorf("%s: the same document name is published twice", document.Name)
		}
		seen[document.Name] = true
		if document.Err != nil {
			return document.Err
		}
	}

	// Every document is staged and flushed before any of them is published, so a
	// failure to write one happens before the pair starts to change.
	staged := make([]stagedDocument, len(documents))
	for index, document := range documents {
		published, err := stageDocument(filepath.Join(dir, document.Name), document.Contents, ops)
		if err != nil {
			return err
		}
		staged[index] = published
		defer staged[index].discard(&err, ops)
	}

	backups := make([]documentBackup, len(documents))
	for index, document := range documents {
		taken, err := takeDocumentBackup(filepath.Join(dir, document.Name), ops)
		if err != nil {
			return err
		}
		backups[index] = taken
		defer backups[index].discard(&err, ops)
	}

	// What each step below owes a rollback, step by step, so no branch can return
	// without one:
	//
	//   a document's rename fails      -> nothing was replaced: no restore is owed
	//   a document's flush fails       -> every document before it was replaced
	//   no failure                      -> nothing is owed
	//
	// Every replaced document is restored, in the reverse of the order it was
	// replaced, and each on its own, so one that cannot be restored does not stop
	// the others from being attempted.
	var replaced []int
	defer func() {
		if err == nil {
			return
		}
		var failures []error
		for index := len(replaced) - 1; index >= 0; index-- {
			document := documents[replaced[index]]
			if rollbackErr := rollbackOneDocument(document.Name, filepath.Join(dir, document.Name), &backups[replaced[index]], ops); rollbackErr != nil {
				failures = append(failures, rollbackErr)
			}
		}
		err = errors.Join(err, errors.Join(failures...))
	}()

	for index, document := range documents {
		path := filepath.Join(dir, document.Name)
		if err = ops.rename(staged[index].path, path); err != nil {
			return fmt.Errorf("%s: publish %s: %w", path, document.Name, err)
		}
		staged[index].path = ""
		replaced = append(replaced, index)
		if err = ops.syncDir(dir); err != nil {
			return fmt.Errorf("%s: sync the %s directory: %w", path, document.Name, err)
		}
	}
	return nil
}

// stagedDocument is a document written next to its target and waiting to be
// renamed over it. A staged document that is never published is removed; one that
// cannot be removed is reported, because a leftover copy of a generated document
// is state nothing manages.
type stagedDocument struct {
	path string
}

func stageDocument(target string, contents []byte, ops documentFileOps) (stagedDocument, error) {
	staged, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		return stagedDocument{}, fmt.Errorf("%s: create temporary file: %w", target, err)
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
	if err := staged.Chmod(documentFileMode); err != nil {
		return stagedDocument{}, fmt.Errorf("%s: set temporary file mode: %w", target, err)
	}
	if _, err := staged.Write(contents); err != nil {
		return stagedDocument{}, fmt.Errorf("%s: write temporary file: %w", target, err)
	}
	if err := ops.syncFile(staged); err != nil {
		return stagedDocument{}, fmt.Errorf("%s: sync temporary file: %w", target, err)
	}
	if err := staged.Close(); err != nil {
		return stagedDocument{}, fmt.Errorf("%s: close temporary file: %w", target, err)
	}
	cleanup = false
	return stagedDocument{path: path}, nil
}

// discard removes a staged document that was never published. A leftover is joined
// onto the caller's error rather than dropped.
func (s stagedDocument) discard(err *error, ops documentFileOps) {
	if s.path == "" {
		return
	}
	if removeErr := ops.remove(s.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		*err = errors.Join(*err, fmt.Errorf("remove %s: %w", s.path, removeErr))
	}
}

// documentBackup is a copy of a published document, taken before publication so a
// failed publication can put it back. A target that did not exist has nothing to
// copy, and a rollback for it removes the file the failed publication created.
type documentBackup struct {
	path    string
	existed bool
	keep    bool
}

func takeDocumentBackup(target string, ops documentFileOps) (documentBackup, error) {
	backup := documentBackup{}
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
	if err := copied.Chmod(documentFileMode); err != nil {
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
// removing a file the failed publication created when there was none. The receiver
// is a pointer because a rollback that succeeds has to be visible to the deferred
// cleanup that runs after it.
func (b *documentBackup) restore(target string, ops documentFileOps) error {
	if !b.existed {
		if err := ops.remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := ops.rename(b.path, target); err != nil {
		return err
	}
	return ops.syncDir(filepath.Dir(target))
}

// discard removes a backup that is no longer needed: either because the
// publication succeeded, or because a rollback already renamed it back, in which
// case the path is simply gone. A backup that is still the only copy of the
// previous contents is kept and named in the failure instead.
func (b *documentBackup) discard(err *error, ops documentFileOps) {
	if b.path == "" || b.keep {
		return
	}
	if removeErr := ops.remove(b.path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		*err = errors.Join(*err, fmt.Errorf("remove backup %s: %w", b.path, removeErr))
	}
}

// rollbackOneDocument puts one published document back, and reports where the
// previous contents survive when it could not.
func rollbackOneDocument(name, target string, backup *documentBackup, ops documentFileOps) error {
	err := backup.restore(target, ops)
	if err == nil {
		return nil
	}
	// Nothing may delete a backup that is now the only copy of what the gateway
	// was running, so it is kept and the failure names it.
	backup.keep = true
	if backup.existed {
		return fmt.Errorf("restore the previous %s: %w (the previous %s is kept at %s)", name, err, name, backup.path)
	}
	return fmt.Errorf("remove the %s this publication created: %w", name, err)
}
