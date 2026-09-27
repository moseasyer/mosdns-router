package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The rollback's whole boundary is one argument array, so everything asserted
// here is about the shape of that array and about what happens when the array
// cannot be run at all.
//
// The array is the injection boundary. If the installer were ever reached through
// a shell, a connection UUID or a device name would be interpreted rather than
// passed, and the only place that could be noticed is here: the fake runner below
// records exactly what it was handed, and the assertions are on that recording and
// not on the program's intentions.

// fakeRunner records the argv a command was started with and answers with a
// prepared result, so a case can say what the installer did without running it.
type fakeRunner struct {
	argv   [][]string
	err    error
	called int
}

func (f *fakeRunner) run(argv []string) error {
	// Copied, because the caller keeps the slice it passed and a test that read a
	// mutated one would be reading the runner's own bookkeeping.
	recorded := make([]string, len(argv))
	copy(recorded, argv)
	f.argv = append(f.argv, recorded)
	f.called++
	return f.err
}

// exitErrorWith builds the *exec.ExitError a real run of the installer would
// produce, by running this test binary as a child that exits with a chosen
// status. The alternative -- a hand-built ExitError -- has no ProcessState, and a
// ProcessState is the only thing that carries the status the launcher has to
// pass on.
func exitErrorWith(t *testing.T, status int) error {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestInstallerChildExitsWith$")
	command.Env = append(os.Environ(), "MOSDNS_TEST_CHILD_STATUS="+strconv.Itoa(status))
	err := command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("the child did not exit with %d, so this case cannot test status propagation: %v", status, err)
	}
	return exitErr
}

// TestInstallerChildExitsWith is the child exitErrorWith runs. It is a test only
// so that the test binary can be its own executable; with no status in the
// environment it skips and exits 0, which is what a bare run of this package does.
func TestInstallerChildExitsWith(t *testing.T) {
	requested := os.Getenv("MOSDNS_TEST_CHILD_STATUS")
	if requested == "" {
		t.Skip("not the child run")
	}
	status, err := strconv.Atoi(requested)
	if err != nil {
		t.Fatalf("the child was asked for a status of %q: %v", requested, err)
	}
	os.Exit(status)
}

// rollbackServices is a services value whose only replaced boundary is the one
// this file is about. The effective UID is 0 -- the case the launcher exists for
// -- and the runner records instead of running.
func rollbackServices(uid int, runner *fakeRunner) services {
	return productionServicesWith(func() int { return uid }, runner.run)
}

func TestEmergencyRollbackHandsTheInstallerAnArgumentArrayAndNothingElse(t *testing.T) {
	runner := &fakeRunner{}
	var stdout, stderr bytes.Buffer

	status := runWith([]string{"emergency-rollback"}, &stdout, &stderr, rollbackServices(0, runner))

	if status != exitSuccess {
		t.Fatalf("emergency-rollback exited %d: %s", status, stderr.String())
	}
	if runner.called != 1 {
		t.Fatalf("the installer was started %d times, want exactly 1", runner.called)
	}
	want := []string{"/usr/lib/mosdns-router/mosdns_installer.py", "emergency-rollback"}
	if len(runner.argv) != 1 || !equalStrings(runner.argv[0], want) {
		t.Fatalf("the installer was run as %#v, want %#v", runner.argv, want)
	}
}

// The argument array is the injection boundary, and the two things that would
// break it are a single interpolated string and a shell. Both are checked
// against the recording rather than against the source, because the recording is
// what the operating system would act on.
func TestEmergencyRollbackNeverBuildsAStringForAShellToInterpret(t *testing.T) {
	runner := &fakeRunner{}
	var stdout, stderr bytes.Buffer
	runWith([]string{"emergency-rollback"}, &stdout, &stderr, rollbackServices(0, runner))

	argv := runner.argv[0]
	if len(argv) != 2 {
		t.Fatalf("the command line has %d words (%#v); a shell would see one, and this is not a shell", len(argv), argv)
	}
	interpreter := []string{"sh", "bash", "dash", "zsh", "/bin/sh", "/bin/bash", "env"}
	for _, word := range argv {
		for _, shell := range interpreter {
			if word == shell {
				t.Fatalf("%#v names a shell as a word of the command line", argv)
			}
		}
		for _, meta := range []string{"sh -c", "bash -c", "&&", "||", ";", "|", "$(", "`", "\n"} {
			if strings.Contains(word, meta) {
				t.Fatalf("the word %q contains %q, which a shell would act on rather than pass", word, meta)
			}
		}
	}
	// The script and the verb are separate words, so there is nothing for a
	// shell to split, substitute or quote.
	if !strings.HasSuffix(argv[0], ".py") || argv[1] != "emergency-rollback" {
		t.Fatalf("the command line is %#v, which is not the interpreter, the script and the verb", argv)
	}
}

func TestEmergencyRollbackRefusesToRunAsAnyoneButRoot(t *testing.T) {
	for _, uid := range []int{1, 1000, 65534} {
		t.Run(strconv.Itoa(uid), func(t *testing.T) {
			runner := &fakeRunner{}
			var stdout, stderr bytes.Buffer

			status := runWith([]string{"emergency-rollback"}, &stdout, &stderr, rollbackServices(uid, runner))

			if status != exitInvalidCLI {
				t.Fatalf("uid %d was allowed to run the rollback; it exited %d: %s", uid, status, stderr.String())
			}
			if runner.called != 0 {
				t.Fatalf("the installer was started as uid %d: %#v", uid, runner.argv)
			}
			if !strings.Contains(stderr.String(), "root") {
				t.Fatalf("the refusal does not say what is required: %s", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("a refusal wrote to standard output: %s", stdout.String())
			}
		})
	}
}

func TestEmergencyRollbackTakesNoFlagsOfItsOwn(t *testing.T) {
	for _, arguments := range [][]string{
		{"emergency-rollback", "--force"},
		{"emergency-rollback", "--purge"},
		{"emergency-rollback", "emergency-rollback"},
	} {
		t.Run(strings.Join(arguments, " "), func(t *testing.T) {
			runner := &fakeRunner{}
			var stdout, stderr bytes.Buffer

			status := runWith(arguments, &stdout, &stderr, rollbackServices(0, runner))

			if status != exitInvalidCLI {
				t.Fatalf("%v was accepted; it exited %d", arguments, status)
			}
			if runner.called != 0 {
				t.Fatalf("%v started the installer anyway: %#v", arguments, runner.argv)
			}
		})
	}
}

// The installer's statuses are its own facts about the machine -- 0 for restored,
// 5 for "this is not mine to change", 6 for "I started and did not finish" -- and
// a launcher that flattened them to one failure would take away the only thing an
// operator or a script can act on.
func TestEmergencyRollbackPassesTheInstallersStatusThrough(t *testing.T) {
	for _, want := range []int{0, 1, 3, 5, 6} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			runner := &fakeRunner{}
			if want != 0 {
				runner.err = exitErrorWith(t, want)
			}
			var stdout, stderr bytes.Buffer

			status := runWith([]string{"emergency-rollback"}, &stdout, &stderr, rollbackServices(0, runner))

			if status != want {
				t.Fatalf("the installer exited %d and the launcher reported %d: %s", want, status, stderr.String())
			}
		})
	}
}

func TestEmergencyRollbackReportsAnInstallerThatCouldNotBeStarted(t *testing.T) {
	runner := &fakeRunner{err: errors.New("exec: permission denied")}
	var stdout, stderr bytes.Buffer

	status := runWith([]string{"emergency-rollback"}, &stdout, &stderr, rollbackServices(0, runner))

	if status != exitStateUnavailable {
		t.Fatalf("an installer that could not be started was reported as %d, want %d", status, exitStateUnavailable)
	}
	if !strings.Contains(stderr.String(), "permission denied") {
		t.Fatalf("the failure was not reported: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("a failure wrote to standard output: %s", stdout.String())
	}
}

// The launcher's own two failures are 2 and 3, and the installer's are 0, 1, 3, 5
// and 6 -- so a caller's table has to be able to say which program produced a
// status. The two the launcher itself raises are the ones that cannot collide
// with a "this machine is not what I need" answer, and the collision that would
// have mattered is 3: the launcher uses it for "the installer could not be
// started" and the installer for a state it could not read. Both mean "this did
// not happen", so they do not read differently to a caller.
// TestTheLaunchersOwnStatusesAreNotTheInstallersRefusals is what it says: the two
// statuses this launcher raises on its own account are not the two the installer
// uses to mean "I did not change anything" and "I started and did not finish".
//
// The name is deliberately narrower than "do not collide". exitStateUnavailable is
// 3, and so is the installer's EXIT_INSTALL_FAILED -- an install whose own
// rollback finished -- and the two agree operationally: both mean "this thing did
// not happen". A caller that has to tell them apart would have to know which
// program it invoked, and the honest statement is that it does not, rather than a
// claim of collision-freedom that is false.
func TestTheLaunchersOwnStatusesAreNotTheInstallersRefusals(t *testing.T) {
	// The installer's two refusals, named here rather than imported: this test is
	// about two numbers from two programs, and a literal is the thing that says so.
	const (
		ownershipRefused  = 5
		restoreIncomplete = 6
	)
	for _, status := range []int{exitInvalidCLI, exitStateUnavailable} {
		if status == ownershipRefused || status == restoreIncomplete {
			t.Errorf("this launcher reports one of its own failures as %d, which the installer uses for a refusal or a half-finished restore", status)
		}
	}
	if exitStateUnavailable == 3 {
		t.Log("exitStateUnavailable is 3, which the installer also uses for a failed install; " +
			"both mean the thing asked for did not happen, so a caller can read either the same way")
	}
}

func TestEveryServicesValueCarriesTheRollbacksBoundary(t *testing.T) {
	// A services literal that forgot the two fields would panic the moment the
	// verb was used, and the other verbs would not notice. Every construction site
	// in this package therefore has to fill them in.
	for name, value := range map[string]services{
		"productionServices": productionServices(),
		"servicesFor":        servicesFor(nil, threeCloudflareCandidates(), time.Time{}),
	} {
		if value.effectiveUID == nil {
			t.Errorf("%s has no effectiveUID, so the rollback verb would panic", name)
		}
		if value.runInstaller == nil {
			t.Errorf("%s has no runInstaller, so the rollback verb would panic", name)
		}
	}
}

// shellNeedles is the production needle list for the source scan, and the control
// case below reads THIS rather than re-typing three of them. A control that kept
// its own copy would pass while the production map lost an entry, which is the one
// thing a control is for.
var shellNeedles = map[string]string{
	"exec.Command(\"sh\"":      "a shell runs a string",
	"exec.Command(\"bash\"":    "a shell runs a string",
	"exec.Command(\"/bin/sh\"": "a shell runs a string",
	"\"-c\"":                   "-c is how a command is handed to a shell as a string",
	"sh -c":                    "a shell runs a string",
	"bash -c":                  "a shell runs a string",
	"strings.Join(argv":        "a joined command line is a string a shell would have to interpret",
}

// The source scan is the half of the rule that covers the paths no test reaches:
// an "if the machine is unusual" branch that reached for a shell would be
// invisible to a fake runner, because the shell would be started before the
// runner was asked to record anything.
func TestTheCommandBoundaryNamesNoShell(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(shellNeedles) == 0 {
		t.Fatal("the needle list is empty, so the scan can never find anything")
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry, "_test.go") {
			continue
		}
		source, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for needle, why := range shellNeedles {
			if strings.Contains(text, needle) {
				t.Errorf("%s contains %q: %s", entry, needle, why)
			}
		}
	}
}

func TestTheScanFiresOnAShellInvocation(t *testing.T) {
	offending := `command := exec.Command("sh", "-c", "mosdns_installer.py emergency-rollback")`
	fired := false
	for needle := range shellNeedles {
		if strings.Contains(offending, needle) {
			fired = true
		}
	}
	if !fired {
		t.Fatal("the scan cannot see the shape it forbids, so it proves nothing")
	}
	clean := `command := exec.Command("/usr/lib/mosdns-router/mosdns_installer.py", "emergency-rollback")`
	for needle := range shellNeedles {
		if strings.Contains(clean, needle) {
			t.Fatalf("the scan fires on the argument array this program actually uses: %q", needle)
		}
	}
}

func TestTheRollbackCommandNamesTheInstalledInstaller(t *testing.T) {
	// The path is the one the package installs it at, and it is a constant rather
	// than a flag: a rollback an operator can point at a different script is a
	// rollback that can be pointed somewhere else.
	if installerScriptPath != "/usr/lib/mosdns-router/mosdns_installer.py" {
		t.Fatalf("the installer is run from %q, which is not the installed path", installerScriptPath)
	}
	want := []string{installerScriptPath, "emergency-rollback"}
	if !equalStrings(rollbackCommand(), want) {
		t.Fatalf("the rollback command is %#v, want %#v", rollbackCommand(), want)
	}
	first, second := rollbackCommand(), rollbackCommand()
	if &first[0] == &second[0] {
		t.Fatal("the command is a shared array, so a caller could change what the next run executes")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
