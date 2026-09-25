package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mosdns-router/internal/filelock"
	"mosdns-router/internal/rules"
)

// The paths the packaged service installs its list into. They are the defaults
// so the daily check timer and an operator's pin both act on the list the router
// reads, and they are overridable so a test or a second installation can use its
// own directory.
const (
	defaultSourceLockPath  = "/var/lib/mosdns/lists/source-lock.json"
	defaultListFilePath    = "/var/lib/mosdns/lists/cn-domains.txt"
	defaultControlLockPath = "/var/lib/mosdns/runtime/control.lock"
)

// pinRef is the only ref `--pin-remote` accepts. The reviewed commit comes from
// the repository's default branch, so there is no ref for an operator to name.
const pinRef = "HEAD"

// updateListTimeout bounds one update, so a timer run or a pin cannot hang on a
// slow or unresponsive origin.
const updateListTimeout = 60 * time.Second

// listServices is the boundary the update-lists command uses for everything
// outside itself: the HTTP client that reaches the source, and the control lock
// that keeps a publication from colliding with the rest of the control
// operations. Everything else, conversion and publication included, is the real
// implementation.
type listServices struct {
	newHTTPClient func() *http.Client
	acquireLock   func(path string) (release func() error, err error)
}

// productionServices is what the executable runs with: a plain client that
// resolves names through the system resolver, and the shared control lock.
func productionServices() listServices {
	return listServices{
		newHTTPClient: func() *http.Client { return &http.Client{Timeout: updateListTimeout} },
		acquireLock: func(path string) (func() error, error) {
			lock, err := filelock.Acquire(path)
			if err != nil {
				return nil, err
			}
			return lock.Close, nil
		},
	}
}

// updateListOptions are the parsed command line of update-lists.
type updateListOptions struct {
	check       bool
	pinRemote   string
	sourceLock  string
	listFile    string
	controlLock string
}

// parseUpdateListOptions parses and validates the command line. One of --check
// and --pin-remote is required, they are mutually exclusive, and the only
// accepted ref is the literal HEAD: a pin names no branch, tag or commit, so the
// reviewed source is always the repository's default branch.
func parseUpdateListOptions(args []string) (updateListOptions, error) {
	flags := flag.NewFlagSet("update-lists", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check", false, "report whether the pinned source has changed, writing nothing")
	pinRemote := flags.String("pin-remote", "", "accept the current reviewed default-branch commit and publish it")
	sourceLock := flags.String("source-lock", defaultSourceLockPath, "path to the source lock")
	listFile := flags.String("list-file", defaultListFilePath, "path to the converted list")
	controlLock := flags.String("control-lock", defaultControlLockPath, "path to the shared control lock")
	if err := flags.Parse(args); err != nil {
		return updateListOptions{}, err
	}
	if flags.NArg() != 0 {
		return updateListOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	switch {
	case *check && *pinRemote != "":
		return updateListOptions{}, errors.New("--check and --pin-remote are mutually exclusive")
	case !*check && *pinRemote == "":
		return updateListOptions{}, errors.New("one of --check or --pin-remote HEAD is required")
	case *pinRemote != "" && *pinRemote != pinRef:
		return updateListOptions{}, fmt.Errorf("--pin-remote accepts only %s, not %q", pinRef, *pinRemote)
	}
	for _, path := range []struct{ name, value string }{
		{"--source-lock", *sourceLock},
		{"--list-file", *listFile},
		{"--control-lock", *controlLock},
	} {
		if strings.TrimSpace(path.value) == "" {
			return updateListOptions{}, fmt.Errorf("%s must not be empty", path.name)
		}
	}
	return updateListOptions{
		check:       *check,
		pinRemote:   *pinRemote,
		sourceLock:  *sourceLock,
		listFile:    *listFile,
		controlLock: *controlLock,
	}, nil
}

func runUpdateLists(ctx context.Context, args []string, stdout, stderr io.Writer, services listServices) int {
	options, err := parseUpdateListOptions(args)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitInvalidCLI
	}
	if options.check {
		return runCheckLists(ctx, options, stdout, stderr, services)
	}
	return runPinRemote(ctx, options, stdout, stderr, services)
}

// runCheckLists reports whether the source the gateway runs on is still the one
// the remote publishes. It writes nothing and takes no lock, so a daily check
// never disturbs a running gateway. The report is assembled first and written
// only once it is complete, so a check that fails half way through says so
// instead of leaving a partial report behind.
func runCheckLists(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services listServices) int {
	published, _, found, err := rules.ReadPublishedPair(options.sourceLock, options.listFile)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	if !found {
		writeCLIError(stderr, "update-lists: no pinned China domain list at %s, nothing to compare against; pin one with update-lists --pin-remote HEAD", options.sourceLock)
		return exitStateUnavailable
	}

	client := services.newHTTPClient()
	remote, err := rules.ResolveCommit(ctx, client, rules.Repository)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	var report bytes.Buffer
	writeReportLine(&report, "repository: %s\n", published.Repository)
	writeReportLine(&report, "entry: %s\n", published.Entry)
	writeReportLine(&report, "locked-commit: %s\n", published.Commit)
	writeReportLine(&report, "locked-archive-sha256: %s\n", published.SHA256)
	writeReportLine(&report, "locked-list-sha256: %s\n", published.ListSHA256)
	writeReportLine(&report, "remote-commit: %s\n", remote.Commit)

	if remote.Commit == published.Commit {
		// The remote still publishes the commit the list was converted from, so
		// the archive is not fetched at all.
		writeReportLine(&report, "up-to-date: true\n")
		return writeReport(stdout, stderr, report.Bytes())
	}
	// The remote has moved on. The archive is read in memory only to report the
	// digest the new pin would record; nothing is accepted here.
	drifted, err := rules.ResolveHEAD(ctx, client, rules.Repository)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	writeReportLine(&report, "remote-archive-sha256: %s\n", drifted.SHA256)
	writeReportLine(&report, "up-to-date: false\n")
	return writeReport(stdout, stderr, report.Bytes())
}

// runPinRemote accepts the current reviewed default-branch commit and publishes
// the list and the lock that describes it.
//
// The download and the conversion happen before the control lock is taken, so a
// slow origin never keeps the router's control operations out. Under the lock
// the published pair is read again, so a pair that changed or was broken while
// the download was in flight is refused rather than overwritten, and only then is
// the new pair written.
func runPinRemote(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services listServices) int {
	client := services.newHTTPClient()
	resolved, err := rules.ResolveHEAD(ctx, client, rules.Repository)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	pinned, list, err := rules.Download(ctx, client, resolved)
	if err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}

	release, err := services.acquireLock(options.controlLock)
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			writeCLIError(stderr, "update-lists: %s: the control lock is held, not publishing %s", options.controlLock, resolved.Commit)
			return exitLockHeld
		}
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	defer func() { _ = release() }()

	if _, _, _, err := rules.ReadPublishedPair(options.sourceLock, options.listFile); err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}
	if err := rules.Publish(options.sourceLock, options.listFile, pinned, list); err != nil {
		writeCLIError(stderr, "update-lists: %v", err)
		return exitStateUnavailable
	}

	writeReportLine(stdout, "pinned-commit: %s\n", pinned.Commit)
	writeReportLine(stdout, "pinned-archive-sha256: %s\n", pinned.SHA256)
	writeReportLine(stdout, "pinned-list-sha256: %s\n", pinned.ListSHA256)
	writeReportLine(stdout, "pinned-rules: %d\n", countListRules(list))
	writeReportLine(stdout, "published-source-lock: %s\n", options.sourceLock)
	writeReportLine(stdout, "published-list: %s\n", options.listFile)
	return exitSuccess
}

// countListRules counts the expressions of a published list, which is the number
// of rules a pin added to the router's China set.
func countListRules(list []byte) int {
	if len(list) == 0 {
		return 0
	}
	lines := strings.Split(strings.TrimSuffix(string(list), "\n"), "\n")
	return len(lines)
}

// writeReportLine appends one line of a report.
func writeReportLine(output io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(output, format, args...)
}

// writeReport hands a complete report to the caller's output.
func writeReport(stdout, stderr io.Writer, report []byte) int {
	if _, err := stdout.Write(report); err != nil {
		writeCLIError(stderr, "update-lists: write report: %v", err)
		return exitStateUnavailable
	}
	return exitSuccess
}
