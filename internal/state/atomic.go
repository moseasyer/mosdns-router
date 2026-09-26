package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type stateKind uint8

const (
	stateKindDHCP stateKind = iota + 1
	stateKindSelector
	stateKindECH
	stateKindBandwidthBudget
	stateKindHealth
)

type atomicFileOps struct {
	syncFile func(*os.File) error
	syncDir  func(string) error
	rename   func(string, string) error
	remove   func(string) error
}

type readFileOps struct {
	open func(string) (io.ReadCloser, error)
}

func defaultAtomicFileOps() atomicFileOps {
	return atomicFileOps{
		syncFile: func(file *os.File) error { return file.Sync() },
		syncDir:  syncDirectory,
		rename:   os.Rename,
		remove:   os.Remove,
	}
}

func defaultReadFileOps() readFileOps {
	return readFileOps{
		open: func(path string) (io.ReadCloser, error) {
			return os.Open(path)
		},
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

func createStateBackup(path, parent string, syncFile func(*os.File) error) (backupPath string, err error) {
	if syncFile == nil {
		syncFile = func(file *os.File) error { return file.Sync() }
	}
	source, err := os.Open(path)
	if err != nil {
		return "", err
	}
	sourceClosed := false
	defer func() {
		if !sourceClosed {
			if closeErr := source.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
	}()

	info, err := source.Stat()
	if err != nil {
		return "", err
	}
	backup, err := os.CreateTemp(parent, "."+filepath.Base(path)+".*.bak")
	if err != nil {
		return "", err
	}
	backupPath = backup.Name()
	backupClosed := false
	cleanup := true
	defer func() {
		if !backupClosed {
			_ = backup.Close()
		}
		if cleanup {
			_ = os.Remove(backupPath)
		}
	}()

	if err := backup.Chmod(info.Mode().Perm()); err != nil {
		return "", err
	}
	if _, err := io.Copy(backup, source); err != nil {
		return "", err
	}
	if err := syncFile(backup); err != nil {
		return "", err
	}
	if err := backup.Close(); err != nil {
		backupClosed = true
		return "", err
	}
	backupClosed = true
	if err := source.Close(); err != nil {
		sourceClosed = true
		return "", err
	}
	sourceClosed = true
	cleanup = false
	return backupPath, nil
}

// WriteJSONAtomic writes value to path, and refuses a target it cannot read.
//
// The refusal is the safety property of every document this package owns except
// one. A selector is the address the router is serving from right now, a DHCP
// record is the upstream set, an ECH record is a fetched key: overwriting any of
// them because this build cannot parse them would destroy the last thing a broken
// router still has, in exchange for a document this build believes in. Health
// state is the exception, and the exception has its own writer.
func WriteJSONAtomic(path string, value any) error {
	return writeJSONAtomicWithOps(path, value, defaultAtomicFileOps(), false)
}

// WriteReplacementJSONAtomic writes value to path as WriteJSONAtomic does, and may
// replace a target this build cannot read.
//
// It exists for one kind of state, and only that kind is allowed to use it: the
// health document, which is a count of what the checks have concluded so far. A
// history this build cannot read is not a history that vouches for an address - it
// is the opposite - so refusing to replace it would leave every future check failing
// closed to a count that no real verdict could ever clear. The correction is written
// over it, and every other guarantee of the strict writer is kept: the document is
// validated first, the target is backed up before the rename, a rename that succeeds
// and a flush that then fails puts the previous bytes back, and a failure at any step
// leaves the target as it was found.
//
// Asking for the replacement policy on any other kind is refused, so the asymmetry is
// a property of the document rather than a convention every caller has to remember.
// A caller that wants the address in service to survive an unreadable document keeps
// using WriteJSONAtomic and keeps its refusal.
func WriteReplacementJSONAtomic(path string, value any) error {
	return writeJSONAtomicWithOps(path, value, defaultAtomicFileOps(), true)
}

// replaceUnreadableAllowed reports whether this kind of state may be written over a
// target that cannot be read. Only health state may.
//
// The rule is about what the document is for. A selector, a DHCP record and an ECH
// record are what the router is running; a health document is an observation about
// them, and an observation nobody can read is not evidence that the address is
// working. So the observation may be replaced by a real one, and the three documents
// the router depends on may not be replaced by anything at all.
func replaceUnreadableAllowed(kind stateKind) bool {
	return kind == stateKindHealth
}

// writeJSONAtomicWithOps validates the value, writes a same-directory
// temporary file, and renames it over the target. Cleanup failures are reported
// to the caller: a temporary file or a backup that survives in the state
// directory leaves a stale copy of runtime state behind, which is exactly the
// kind of leftover the atomic write exists to prevent.
//
// replaceUnreadable is the caller's request, and the kind decides whether it is
// honoured - see WriteReplacementJSONAtomic and replaceUnreadableAllowed.
func writeJSONAtomicWithOps(path string, value any, ops atomicFileOps, replaceUnreadable bool) (err error) {
	kind, err := validateValue(value)
	if err != nil {
		return fmt.Errorf("%s: validate state: %w", path, err)
	}
	if path == "" {
		return fmt.Errorf("state path must not be empty")
	}
	if replaceUnreadable && !replaceUnreadableAllowed(kind) {
		return fmt.Errorf("%s: a %s may not be written over a target this build cannot read; use WriteJSONAtomic", path, kindName(kind))
	}

	oldGeneration, exists, readable, err := inspectExistingState(path, kind, replaceUnreadable)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if exists && readable && hasGeneration(kind) {
		newGeneration, _ := generationFor(value)
		if newGeneration < oldGeneration {
			return fmt.Errorf("%s: generation rollback from %d to %d", path, oldGeneration, newGeneration)
		}
	}

	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0750); err != nil {
		return fmt.Errorf("%s: create parent directory: %w", path, err)
	}

	temporary, err := os.CreateTemp(parent, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("%s: create temporary file: %w", path, err)
	}
	temporaryPath := temporary.Name()
	temporaryClosed := false
	defer func() {
		if temporaryPath == "" {
			return
		}
		if !temporaryClosed {
			_ = temporary.Close()
		}
		if removeErr := ops.remove(temporaryPath); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("%s: remove temporary file: %w", path, removeErr))
		}
	}()

	if err := temporary.Chmod(0640); err != nil {
		return fmt.Errorf("%s: set temporary file mode: %w", path, err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("%s: encode state: %w", path, err)
	}
	if err := ops.syncFile(temporary); err != nil {
		return fmt.Errorf("%s: sync temporary file: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		temporaryClosed = true
		return fmt.Errorf("%s: close temporary file: %w", path, err)
	}
	temporaryClosed = true

	backupPath := ""
	keepBackup := false
	defer func() {
		if backupPath == "" || keepBackup {
			return
		}
		if removeErr := ops.remove(backupPath); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("%s: remove state backup: %w", path, removeErr))
		}
	}()
	if exists {
		backupPath, err = createStateBackup(path, parent, ops.syncFile)
		if err != nil {
			return fmt.Errorf("%s: create state backup: %w", path, err)
		}
	}
	if err := ops.rename(temporaryPath, path); err != nil {
		return fmt.Errorf("%s: rename temporary file: %w", path, err)
	}
	temporaryPath = ""
	if err := ops.syncDir(parent); err != nil {
		syncErr := err
		if backupPath != "" {
			if rollbackErr := ops.rename(backupPath, path); rollbackErr != nil {
				keepBackup = true
				return fmt.Errorf("%s: atomic commit failed: %w", path, errors.Join(
					fmt.Errorf("sync parent directory: %w", syncErr),
					fmt.Errorf("restore previous state: %w", rollbackErr),
				))
			}
			backupPath = ""
			if rollbackSyncErr := ops.syncDir(parent); rollbackSyncErr != nil {
				return fmt.Errorf("%s: atomic commit failed: %w", path, errors.Join(
					fmt.Errorf("sync parent directory: %w", syncErr),
					fmt.Errorf("sync restored state: %w", rollbackSyncErr),
				))
			}
		}
		return fmt.Errorf("%s: sync parent directory: %w", path, syncErr)
	}
	if backupPath != "" {
		if err := ops.remove(backupPath); err != nil {
			return fmt.Errorf("%s: remove state backup: %w", path, err)
		}
		backupPath = ""
	}
	return nil
}

func ReadJSON(path string, destination any) error {
	return readJSONWithOps(path, destination, defaultReadFileOps())
}

func readJSONWithOps(path string, destination any, ops readFileOps) error {
	kind, err := destinationKind(destination)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	reader, err := ops.open(path)
	if err != nil {
		return fmt.Errorf("%s: open state: %w", path, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = reader.Close()
		}
	}()

	decoded := newState(kind)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(decoded); err != nil {
		return invalidJSONError(path, "decode state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s: trailing data after state document", path)
		}
		return invalidJSONError(path, "decode trailing data")
	}
	if err := validateState(decoded); err != nil {
		return fmt.Errorf("%s: validate state: %w", path, err)
	}
	if err := reader.Close(); err != nil {
		closed = true
		return fmt.Errorf("%s: close state: %w", path, err)
	}
	closed = true
	assignState(destination, decoded)
	return nil
}

func invalidJSONError(path, operation string) error {
	return fmt.Errorf("%s: %s: invalid JSON", path, operation)
}

func validateValue(value any) (stateKind, error) {
	kind, err := kindForValue(value)
	if err != nil {
		return 0, err
	}
	if err := validateState(value); err != nil {
		return 0, err
	}
	return kind, nil
}

func validateState(value any) error {
	switch state := value.(type) {
	case DHCPState:
		return state.Validate()
	case *DHCPState:
		if state == nil {
			return errors.New("DHCP state must not be nil")
		}
		return state.Validate()
	case Selector:
		return state.Validate()
	case *Selector:
		if state == nil {
			return errors.New("selector must not be nil")
		}
		return state.Validate()
	case ECHState:
		return state.Validate()
	case *ECHState:
		if state == nil {
			return errors.New("ECH state must not be nil")
		}
		return state.Validate()
	case BandwidthBudgetState:
		return state.Validate()
	case *BandwidthBudgetState:
		if state == nil {
			return errors.New("bandwidth budget state must not be nil")
		}
		return state.Validate()
	case HealthState:
		return state.Validate()
	case *HealthState:
		if state == nil {
			return errors.New("health state must not be nil")
		}
		return state.Validate()
	default:
		return fmt.Errorf("unsupported state type %T", value)
	}
}

func kindForValue(value any) (stateKind, error) {
	switch value.(type) {
	case DHCPState, *DHCPState:
		return stateKindDHCP, nil
	case Selector, *Selector:
		return stateKindSelector, nil
	case ECHState, *ECHState:
		return stateKindECH, nil
	case BandwidthBudgetState, *BandwidthBudgetState:
		return stateKindBandwidthBudget, nil
	case HealthState, *HealthState:
		return stateKindHealth, nil
	default:
		return 0, fmt.Errorf("unsupported state type %T", value)
	}
}

func destinationKind(destination any) (stateKind, error) {
	switch value := destination.(type) {
	case *DHCPState:
		if value == nil {
			return 0, errors.New("DHCP destination must not be nil")
		}
		return stateKindDHCP, nil
	case *Selector:
		if value == nil {
			return 0, errors.New("selector destination must not be nil")
		}
		return stateKindSelector, nil
	case *ECHState:
		if value == nil {
			return 0, errors.New("ECH destination must not be nil")
		}
		return stateKindECH, nil
	case *BandwidthBudgetState:
		if value == nil {
			return 0, errors.New("bandwidth budget destination must not be nil")
		}
		return stateKindBandwidthBudget, nil
	case *HealthState:
		if value == nil {
			return 0, errors.New("health destination must not be nil")
		}
		return stateKindHealth, nil
	default:
		return 0, fmt.Errorf("destination must be a pointer to a supported state type, got %T", destination)
	}
}

func newState(kind stateKind) any {
	switch kind {
	case stateKindDHCP:
		return &DHCPState{}
	case stateKindSelector:
		return &Selector{}
	case stateKindECH:
		return &ECHState{}
	case stateKindBandwidthBudget:
		return &BandwidthBudgetState{}
	case stateKindHealth:
		return &HealthState{}
	default:
		return nil
	}
}

func assignState(destination, source any) {
	switch target := destination.(type) {
	case *DHCPState:
		*target = *(source.(*DHCPState))
	case *Selector:
		*target = *(source.(*Selector))
	case *ECHState:
		*target = *(source.(*ECHState))
	case *BandwidthBudgetState:
		*target = *(source.(*BandwidthBudgetState))
	case *HealthState:
		*target = *(source.(*HealthState))
	}
}

// inspectExistingState reports what is at path, as three facts: whether a target is
// there at all, whether this build can read it, and the generation it carries. The
// generation is zero for a target that is not there or cannot be read, and the caller
// only ever consults it for a target that is both.
//
// A target that exists and cannot be read is an error unless the caller asked for the
// replacement policy, in which case it is reported as existing and unreadable so the
// write can go ahead - still taking a backup of the bytes first, because a rollback
// that has nothing to restore is not a rollback.
func inspectExistingState(path string, kind stateKind, replaceUnreadable bool) (uint64, bool, bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, false, nil
	}
	if err != nil {
		return 0, false, false, fmt.Errorf("inspect existing state: %w", err)
	}
	destination := newState(kind)
	if err := ReadJSON(path, destination); err != nil {
		if replaceUnreadable {
			return 0, true, false, nil
		}
		return 0, true, false, fmt.Errorf("existing state is not a valid %s: %w", kindName(kind), err)
	}
	generation, _ := generationFor(destination)
	return generation, true, true, nil
}

func hasGeneration(kind stateKind) bool {
	return kind == stateKindDHCP || kind == stateKindSelector || kind == stateKindECH
}

func generationFor(value any) (uint64, bool) {
	switch state := value.(type) {
	case DHCPState:
		return state.Generation, true
	case *DHCPState:
		if state != nil {
			return state.Generation, true
		}
	case Selector:
		return state.Generation, true
	case *Selector:
		if state != nil {
			return state.Generation, true
		}
	case ECHState:
		return state.Generation, true
	case *ECHState:
		if state != nil {
			return state.Generation, true
		}
	}
	return 0, false
}

func kindName(kind stateKind) string {
	switch kind {
	case stateKindDHCP:
		return "DHCP state"
	case stateKindSelector:
		return "selector state"
	case stateKindECH:
		return "ECH state"
	case stateKindBandwidthBudget:
		return "bandwidth budget state"
	case stateKindHealth:
		return "health state"
	default:
		return "unknown state"
	}
}
