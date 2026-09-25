// Package filelock provides the control lock that serialises runtime state
// mutations between the router, its CLI, and timer-driven control operations.
// The lock is a kernel advisory lock on a shared file, so a check-then-write
// sequence cannot interleave with another process. It is a mutual-exclusion
// device only: a crashed holder releases it when its descriptor closes, and no
// holder identity is recorded in the lock file.
package filelock

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// ErrLocked reports that the control lock is already held by another open file
// description, which for this package always means another holder exists.
var ErrLocked = errors.New("control lock is already held")

// lockFileMode is the exact mode every control lock file must carry, whatever
// the caller's umask or the file's previous mode.
const lockFileMode = 0640

// Lock holds an exclusive advisory lock on a control lock file. The lock is
// released by Close, which is safe to call more than once.
type Lock struct {
	file *os.File
	once sync.Once
	err  error
}

// Acquire takes the control lock at path without blocking, creating the lock
// file when it is absent and enforcing mode 0640 on it. It returns ErrLocked
// when the lock is already held.
func Acquire(path string) (*Lock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, lockFileMode)
	if err != nil {
		return nil, fmt.Errorf("%s: open control lock: %w", path, err)
	}
	// OpenFile applies the mode only when it creates the file, and the umask
	// can narrow what it creates, so pin the exact mode on every acquire.
	if err := file.Chmod(lockFileMode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%s: set control lock mode: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// EWOULDBLOCK is EAGAIN on every platform this package builds for, and
		// it is the only flock failure that means "somebody else holds it".
		if errors.Is(err, unix.EWOULDBLOCK) {
			_ = file.Close()
			return nil, fmt.Errorf("%s: %w", path, ErrLocked)
		}
		_ = file.Close()
		return nil, fmt.Errorf("%s: lock control lock: %w", path, err)
	}
	return &Lock{file: file}, nil
}

// Close releases the control lock by closing the lock file. Closing an already
// closed lock is a no-op that reports the result of the first call.
func (l *Lock) Close() error {
	l.once.Do(func() { l.err = l.file.Close() })
	return l.err
}
