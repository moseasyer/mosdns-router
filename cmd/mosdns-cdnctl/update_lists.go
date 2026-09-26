package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"mosdns-router/internal/candidate"
	"mosdns-router/internal/filelock"
	"mosdns-router/internal/optimizer"
	"mosdns-router/internal/prober"
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

// services is the boundary the commands in this binary use for everything outside
// themselves: the HTTP client that reaches the source, the control lock that keeps
// a publication from colliding with the rest of the control operations, where the
// generated documents live, and the file operations a document publication is
// built from. Everything else, conversion, rendering and publication included, is
// the real implementation.
//
// The three fields the CDN commands need are here for the same reason. The prober
// is the only thing that opens a socket, the candidate source is the only thing
// that reaches the network for addresses, and the clock is what dates a report and
// measures the age of one an apply is reading - so a test that wants any of the
// three to be something else has to be able to say so here.
type services struct {
	newHTTPClient func() *http.Client
	acquireLock   func(path string) (release func() error, err error)
	// documents is where the generated documents are published and which policy
	// they are rendered from, so no test has to write to /etc.
	documents documentPaths
	// documentOps are the file operations a document publication is built from.
	// They are a field so a test can make one of them fail and observe what the
	// operator is left with; production uses the real ones.
	documentOps documentFileOps
	// newProber builds the prober a measurement run measures with.
	newProber func() optimizer.Prober
	// readCandidates reads the official range document and the user's own list, and
	// is the only thing that puts an address a run will measure into existence. It
	// takes the caller's context because it is the one part of a measurement that
	// fetches over the network, and a fetch that ignored the context would make the
	// collection phase of `test` uncancellable.
	readCandidates func(context.Context, candidateSource) (candidate.CandidateSet, error)
	// now is the clock. Every timestamp a report and a selector carry comes from
	// it, so all of them are one reading in production.
	now func() time.Time
}

// productionServices is what the executable runs with: a plain client that
// resolves names through the system resolver, the shared control lock, the
// installed document layout, the real file operations, the real prober, the real
// published range source and the real clock.
func productionServices() services {
	return services{
		newHTTPClient: func() *http.Client { return &http.Client{Timeout: updateListTimeout} },
		acquireLock: func(path string) (func() error, error) {
			lock, err := filelock.Acquire(path)
			if err != nil {
				return nil, err
			}
			return lock.Close, nil
		},
		documents:      productionDocumentPaths(),
		documentOps:    defaultDocumentOps(),
		newProber:      func() optimizer.Prober { return networkProber{inner: prober.New(prober.Options{})} },
		readCandidates: readOfficialAndUserCandidates,
		now:            time.Now,
	}
}

// readOfficialAndUserCandidates is where a run's addresses come from: the
// published Cloudflare ranges, sampled under the policy's cap, and the operator's
// own list, which is never capped.
//
// The two are returned as one set carrying the official set's stale marker, because
// that is the fact a report has to show: an operator reading "12 candidates" needs
// to know whether they are today's or the last ones this build accepted.
//
// The context is the caller's, and it is the whole of the cancellation story for
// this phase: the range fetch is the only network I/O a measurement run does
// outside the prober, so a `test` whose operator pressed Ctrl-C would otherwise
// wait out the HTTP client's own timeout before it noticed.
func readOfficialAndUserCandidates(ctx context.Context, source candidateSource) (candidate.CandidateSet, error) {
	if source.Client == nil {
		return candidate.CandidateSet{}, errors.New("a candidate source needs an HTTP client")
	}
	official, err := candidate.NewCloudflareSource(source.Client, source.BaseURL, source.CachePath)
	if err != nil {
		return candidate.CandidateSet{}, err
	}
	set, err := official.Candidates(ctx, source.Limit, source.Moment)
	if err != nil {
		return candidate.CandidateSet{}, err
	}
	user, err := readUserCandidates(source.UserList)
	if err != nil {
		return candidate.CandidateSet{}, err
	}
	set.Candidates = append(set.Candidates, user...)
	return set, nil
}

// readUserCandidates reads the operator's own list. A file that is not there is
// simply no candidates of its own, which is the state of a fresh installation.
func readUserCandidates(path string) ([]candidate.Candidate, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the candidate list: %w", err)
	}
	defer func() { _ = file.Close() }()
	listed, err := candidate.ParseUserList(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return listed, nil
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

func runUpdateLists(ctx context.Context, args []string, stdout, stderr io.Writer, services services) int {
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
//
// The published pair is read without the control lock, deliberately. Holding the
// lock is what a pin does, and a pin on the same host is a handful of writes; a
// daily check that took the lock would have to either block that pin or be
// skipped whenever anything else was publishing, so it would stop being the
// check an operator can run at any time. The consequence of reading unlocked is
// that a check can observe a half-applied pair, and it is fail-closed about
// that: ReadPublishedPair refuses a pair whose list and lock do not describe each
// other, the check reports the refusal on stderr and exits 3, and it never
// concludes "up-to-date" from a pair it could not verify. A transient exit 3 is
// the correct answer for a check that caught a publication in flight.
func runCheckLists(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
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
func runPinRemote(ctx context.Context, options updateListOptions, stdout, stderr io.Writer, services services) int {
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
