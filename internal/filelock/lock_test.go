package filelock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	helperPathEnv = "MOSDNS_ROUTER_FILELOCK_HELPER_PATH"
	helperHoldEnv = "MOSDNS_ROUTER_FILELOCK_HELPER_HOLD"

	helperAcquired = "acquired"
	helperLocked   = "locked"
	helperFailed   = "failed"

	helperTimeout = 60 * time.Second
)

// A second handle in the same process is a separate open file description, so
// an exclusive non-blocking lock must already be visible to it.
func TestSecondAcquireFailsWhileHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Acquire(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

// A process-local mutex cannot be seen by another process, so this only passes
// while the lock is enforced by the kernel on a shared open file description.
func TestAcquireInSeparateProcessFailsWhileHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	held, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	helper := startHelperProcess(t, path, false)
	if got := helper.readResult(t); got != helperLocked {
		t.Fatalf("helper acquire result = %q, want %q", got, helperLocked)
	}
	helper.wait(t)
}

// Mutual exclusion must work in both directions: while the helper process holds
// the lock this process is refused, and the lock is acquirable again once the
// helper releases it through Close.
func TestAcquireFailsWhileSeparateProcessHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	helper := startHelperProcess(t, path, true)
	if got := helper.readResult(t); got != helperAcquired {
		helper.wait(t)
		t.Fatalf("helper acquire result = %q, want %q", got, helperAcquired)
	}

	blocked, err := Acquire(path)
	if err == nil {
		blocked.Close()
		helper.stop(t)
		t.Fatal("expected ErrLocked while the helper process holds the lock")
	}
	if !errors.Is(err, ErrLocked) {
		helper.stop(t)
		t.Fatalf("error while the helper holds the lock = %v, want ErrLocked", err)
	}

	helper.stop(t)
	reacquired, err := Acquire(path)
	if err != nil {
		t.Fatalf("acquire after the helper released the lock: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatalf("close reacquired lock: %v", err)
	}
}

func TestCloseReleasesTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	next, err := Acquire(path)
	if err != nil {
		t.Fatalf("acquire after close: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatalf("close second lock: %v", err)
	}
}

func TestRepeatedCloseReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestAcquireCreatesLockFileWithRequiredMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	assertFileMode(t, path, 0640)
}

// The mode must be exact rather than "whatever the caller's umask leaves
// behind", so a restrictive umask cannot silently narrow the control lock file.
func TestAcquireCreatesExactModeUnderRestrictiveUmask(t *testing.T) {
	setUmask(t, 0o077)
	path := filepath.Join(t.TempDir(), "control.lock")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	assertFileMode(t, path, 0640)
}

// A refused acquirer must still leave the lock file at the required mode. The
// permissions of the file that guards runtime state must not depend on which
// process won the lock race, so the mode is enforced before the lock is taken
// rather than only on the success path.
func TestRefusedAcquireStillRepairsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	held, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	// Simulate an operator or installer loosening the file while it is held.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	blocked, err := Acquire(path)
	if err == nil {
		blocked.Close()
		t.Fatal("expected ErrLocked while the lock is held")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
	assertFileMode(t, path, 0640)
}

// A lock file left behind by an earlier version, an installer, or an operator
// must be repaired on acquire, because the lock guards runtime state that is
// never meant to be world accessible.
func TestAcquireRepairsPreExistingMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	assertFileMode(t, path, 0640)
}

// Only a lock conflict means "another holder exists"; a failure to open the
// lock file must keep its own identity and say which path failed, otherwise a
// caller cannot tell a missing runtime directory from a busy lock.
func TestAcquireWrapsNonLockFailureWithPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "control.lock")
	lock, err := Acquire(path)
	if err == nil {
		lock.Close()
		t.Fatal("expected acquire on a missing directory to fail")
	}
	if errors.Is(err, ErrLocked) {
		t.Fatalf("non-conflict failure reported as ErrLocked: %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want it to wrap fs.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not include path %q", err, path)
	}
}

// TestFilelockHelperProcess is not a test on its own: it is the child half of
// the cross-process tests above. It acquires the control lock named by
// MOSDNS_ROUTER_FILELOCK_HELPER_PATH, reports the outcome as the first line of
// stdout, and waits on stdin when it is asked to hold the lock.
func TestFilelockHelperProcess(t *testing.T) {
	path := os.Getenv(helperPathEnv)
	if path == "" {
		t.Skip("helper process; only runs when spawned by a cross-process test")
	}
	lock, err := Acquire(path)
	switch {
	case errors.Is(err, ErrLocked):
		fmt.Fprintln(os.Stdout, helperLocked)
		return
	case err != nil:
		fmt.Fprintln(os.Stdout, helperFailed+": "+err.Error())
		return
	}
	fmt.Fprintln(os.Stdout, helperAcquired)
	if os.Getenv(helperHoldEnv) != "1" {
		if err := lock.Close(); err != nil {
			fmt.Fprintln(os.Stdout, helperFailed+": "+err.Error())
		}
		return
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		fmt.Fprintln(os.Stdout, helperFailed+": "+err.Error())
	}
	if err := lock.Close(); err != nil {
		fmt.Fprintln(os.Stdout, helperFailed+": "+err.Error())
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("lock file mode = %04o, want %04o", got, want)
	}
}

// setUmask changes the process-wide umask for one test and restores it during
// cleanup. The umask is process-global state, so no test in this package uses
// t.Parallel and the umask is always restored before the next test starts.
func setUmask(t *testing.T, mask int) {
	t.Helper()
	previous := unix.Umask(mask)
	t.Cleanup(func() { unix.Umask(previous) })
}

type helperProcess struct {
	cmd    *exec.Cmd
	stdout *bufio.Reader
	stdin  io.WriteCloser
	stderr *strings.Builder
}

// startHelperProcess runs the test binary again as an independent process so
// the lock is exercised across a process boundary.
func startHelperProcess(t *testing.T, path string, hold bool) *helperProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFilelockHelperProcess$", "-test.timeout=2m")
	cmd.Env = append(os.Environ(), helperPathEnv+"="+path)
	if hold {
		cmd.Env = append(cmd.Env, helperHoldEnv+"=1")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	helper := &helperProcess{cmd: cmd, stdout: bufio.NewReader(stdout), stdin: stdin, stderr: stderr}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return helper
}

// readResult returns the helper's first stdout line, failing the test if the
// helper dies or stays silent instead of reporting an outcome.
func (h *helperProcess) readResult(t *testing.T) string {
	t.Helper()
	type readResult struct {
		line string
		err  error
	}
	results := make(chan readResult, 1)
	go func() {
		line, err := h.stdout.ReadString('\n')
		results <- readResult{line: strings.TrimSpace(line), err: err}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("read helper result: %v (stderr: %s)", result.err, h.stderr.String())
		}
		return result.line
	case <-time.After(helperTimeout):
		t.Fatalf("helper process did not report a result within %s", helperTimeout)
		return ""
	}
}

// stop signals a helper process to release the lock and waits for it to exit,
// so the lock is provably released once it returns.
func (h *helperProcess) stop(t *testing.T) {
	t.Helper()
	if err := h.stdin.Close(); err != nil {
		t.Fatalf("signal helper to release: %v", err)
	}
	h.wait(t)
}

func (h *helperProcess) wait(t *testing.T) {
	t.Helper()
	if err := h.cmd.Wait(); err != nil {
		t.Fatalf("helper process: %v (stderr: %s)", err, h.stderr.String())
	}
}
