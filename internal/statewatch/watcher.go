// Package statewatch keeps a router serving while the state files it serves
// from are being replaced underneath it.
//
// It watches two kinds of file. The first is a schema version 1 state document
// -- a selector, a DHCP record, an ECH record, a bandwidth budget, a health
// record -- replaced by the atomic rename every writer in this project already
// uses. The second is a plain list of domain names, one per line, the file an
// operator edits by hand. The API is the same for both, and it is deliberately
// small: a snapshot to read, a forced reload, and a Close.
//
// Two guarantees are the reason this package exists rather than a call to
// os.Stat in the plugin.
//
// The first is that a file the watcher cannot read changes nothing. Every
// document is read whole, validated, and only then stored, so a truncated
// editor buffer, a half-finished write, a document declaring a schema version
// this build does not know, and a file that is not there at all all leave the
// last valid snapshot exactly where it was. The alternative is a rewrite plugin
// that has quietly stopped knowing which address the router is serving, and an
// operator with nothing to look at.
//
// The second is that a value handed to a caller shares no mutable reference with
// the watcher's own copy. A selector carries a map of CloudFront mappings and a
// DHCP record carries a slice of upstreams, and a caller is going to sort,
// re-slice or write to whatever it is given. Snapshot returns a value that
// carries its own copies, so the worst a caller can do is corrupt its own copy
// of a value that was already correct.
//
// Nothing here compares modification times. A watcher that stats a file to
// decide whether to look at it has a window between the stat and the open in
// which the file it measured is not the file it reads, and a worse one if it
// records the file as seen when the read is then refused: a repair that lands in
// the same modification time and the same size -- which is what a producer's
// retry looks like -- is never looked at again. So there is no stat, and no
// record of what has been seen. Every tick opens the path and validates
// whatever the open yields, and a refusal is simply a tick that changed nothing.
//
// The read itself is state.ReadJSON, the same authoritative decode-and-validate
// the rest of the project uses, so a document this package publishes is a
// document the router would accept anywhere else. A caller's own check is
// applied after that, and may only add a refusal.
package statewatch

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"mosdns-router/internal/state"
)

// DefaultPollInterval is how often a watcher looks at its file when the caller
// asks for nothing else. It is the rate at which a rewritten answer starts
// tracking a new selector generation, so it is a floor on how quickly the router
// notices the optimizer's decision, and a ceiling on how often it reads a small
// JSON document or a short list of names.
const DefaultPollInterval = 500 * time.Millisecond

// Document is a state document this package can hold: the set state.ReadJSON
// accepts as a destination, and no other. The constraint is the delegation
// rule. A watcher decodes with state.ReadJSON, so a type outside this set has
// nowhere to be decoded into, and a caller that could name one would be asking
// for a watcher with a second opinion about what a valid document is.
type Document interface {
	state.DHCPState | state.Selector | state.ECHState | state.BandwidthBudgetState | state.HealthState
}

// Options is the one optional argument both constructors take. A production
// caller passes none and gets DefaultPollInterval and no reporting; the fields
// exist so a test can watch at a rate a test can observe, and so a caller with a
// log of its own can be told about a refusal where it happens rather than
// having to ask.
type Options struct {
	// PollInterval is how often the background poll looks at the file. Zero
	// means DefaultPollInterval. A negative interval is refused rather than
	// rounded: time.NewTicker panics on one, and a panic in the poll goroutine
	// arrives after the router has already started serving.
	PollInterval time.Duration
	// ReloadError is called once for each episode of failed reloads, with the
	// refusal. An episode is one run of the same failure: a file that stays
	// corrupt is one problem, not two hundred a second, and a file that is
	// repaired and breaks again is a new one. A reload the caller asked for
	// through ReloadNow is not reported here, because the caller has its
	// return value.
	ReloadError func(error)
}

// withDefaults fills in the values the caller left at zero and refuses the one
// value that cannot be defaulted.
func (o Options) withDefaults() (Options, error) {
	if o.PollInterval < 0 {
		return Options{}, fmt.Errorf("poll interval must not be negative, got %s", o.PollInterval)
	}
	if o.PollInterval == 0 {
		o.PollInterval = DefaultPollInterval
	}
	return o, nil
}

// oneOptions is the one optional argument both constructors take, resolved. A
// caller that passes two is a mistake, and honouring the first of them or the
// last would leave it with a poll rate it did not ask for and never hear about.
func oneOptions(path string, options []Options) (Options, error) {
	switch len(options) {
	case 0:
		return Options{}, nil
	case 1:
		return options[0], nil
	default:
		return Options{}, fmt.Errorf("%s: a watcher takes at most one Options value, got %d", path, len(options))
	}
}

// poller is the background half both watchers share: a ticker, a stop signal,
// and the rule for reporting a refusal. The poll loop and the shutdown are
// written once here rather than once per file, so the two cannot drift apart;
// Close and ReloadNow stay on the two types themselves, where godoc can name
// the type a caller is holding.
//
// A read and a store are one sequence per goroutine, and a poll tick and a
// caller's own ReloadNow may run at the same time. Two properties of that are
// pinned by tests: a reload the caller asked for is stored even while a poll read
// is in flight, and the caller's document is what the watcher ends up serving
// once that read has finished. One is not, and it is stated here rather than left
// for the next reader to assume.
//
// Between a tick that read the file before the caller published, and the next
// tick, the watcher can serve the document that tick read: the older one, for up
// to one poll interval. The window is bounded by the interval, the value in it is
// always a document this build accepted, and the alternative -- refusing to store
// a document older than the one in hand -- is a policy this package is not given,
// since a restored state directory would then be ignored for ever. No test
// asserts the window, and one cannot without racing the tick that closes it: at a
// poll interval of a few milliseconds the window is a few milliseconds wide, so
// observing it is a coin toss against the very tick that ends it. A plugin that
// writes a state file and needs it served before the next query should therefore
// not treat a ReloadNow as an ordering barrier against a tick already in flight.
type poller struct {
	path     string
	interval time.Duration
	report   func(error)
	reload   func() error
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once

	// reporting guards reported, which three goroutines can write: the
	// constructor, the poll goroutine, and a caller running ReloadNow. It is
	// held only to decide whether to report, never while the handler runs, so a
	// handler that calls back into the watcher cannot deadlock on it.
	reporting sync.Mutex
	reported  error
}

// init validates the construction a caller asked for and prepares the half a
// watcher shares, in place: the poller carries a sync.Once, so it is filled in
// rather than built and assigned. It does not start anything, because the first
// read goes through the watcher's own fields and the poller is part of them.
func (p *poller) init(path string, options Options) error {
	if path == "" {
		return fmt.Errorf("watched path must not be empty")
	}
	resolved, err := options.withDefaults()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	p.path = path
	p.interval = resolved.PollInterval
	p.report = resolved.ReloadError
	p.stop = make(chan struct{})
	p.done = make(chan struct{})
	return nil
}

// start reads the file once, synchronously, and then begins the background
// poll. The first read is synchronous on purpose: a router that boots while the
// optimizer has already published a selector serves that selector from its first
// query, and not one poll interval later.
func (p *poller) start() {
	p.reportRefusal(p.reload())
	go p.run()
}

func (p *poller) run() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	defer close(p.done)
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.reportRefusal(p.reload())
		}
	}
}

// reportRefusal tells the caller's handler about a failed reload, once per
// episode. A reload that succeeds clears the episode, so the next failure is
// reported whatever it is.
func (p *poller) reportRefusal(err error) {
	p.reporting.Lock()
	if err == nil {
		p.reported = nil
		p.reporting.Unlock()
		return
	}
	if p.reported != nil && p.reported.Error() == err.Error() {
		p.reporting.Unlock()
		return
	}
	p.reported = err
	report := p.report
	p.reporting.Unlock()
	if report != nil {
		report(err)
	}
}

// endEpisode forgets the failure the handler was last given. A reload the caller
// asked for does not report -- the caller has the refusal as a return value -- but
// a successful one is still a repair, and a file that breaks again after a repair
// has to be reported as the new problem it is. Without this, a caller who fixes a
// file and then breaks it again gets silence.
func (p *poller) endEpisode() {
	p.reporting.Lock()
	defer p.reporting.Unlock()
	p.reported = nil
}

// stopPolling ends the background poll and waits for the goroutine to finish.
// It is safe from several goroutines and safe to call twice: the second caller
// waits on a channel the first one is already waiting on. There is nothing that
// can fail here, which is why the error is always nil -- the signature is the
// shape a MOSDNS plugin's Close wants.
func (p *poller) stopPolling() error {
	p.once.Do(func() { close(p.stop) })
	<-p.done
	return nil
}

// Watcher is the last valid snapshot of one JSON state document, kept current
// by a background poll. It is safe for concurrent use: a query reading a
// snapshot while the poll stores a new generation is the case it exists for.
type Watcher[T Document] struct {
	poller

	validate func(T) error
	clone    func(T) T

	mu    sync.RWMutex
	value T
}

// NewJSON returns a watcher for the document at path.
//
// The document is read with state.ReadJSON, which decodes it, refuses fields
// this build does not know, and runs the state package's own validation. Only
// then is validate called, if it is not nil, and a refusal from either keeps
// the last valid snapshot in place -- so a caller's check can add a refusal and
// can never remove one the state package would have made.
//
// initial is what the watcher serves until it has read a document this build
// accepts. A plugin passes the value it would serve anyway: a disabled selector,
// or a document with no upstream set. It is copied, so a caller that keeps
// using its own value does not find it edited.
func NewJSON[T Document](path string, validate func(T) error, initial T, options ...Options) (*Watcher[T], error) {
	settings, err := oneOptions(path, options)
	if err != nil {
		return nil, err
	}
	watcher := &Watcher[T]{
		validate: validate,
		clone:    documentCloner[T](),
	}
	watcher.value = watcher.clone(initial)
	if err := watcher.poller.init(path, settings); err != nil {
		return nil, err
	}
	watcher.poller.reload = watcher.reload
	watcher.poller.start()
	return watcher, nil
}

// Snapshot returns the last document this build was able to read, as a value
// carrying its own copy of every map and slice in it. It answers with the last
// valid document whether the file is current, stale, or unreadable, and it
// keeps answering with it after Close: closing a plugin stops the poll, it does
// not blank the value the router was serving.
func (w *Watcher[T]) Snapshot() T {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.clone(w.value)
}

// ReloadNow reads the file, validates it, and stores it if both doors open. It
// is the synchronous form of what the poll does, for a caller that has just
// written the file itself, and it returns the refusal rather than reporting it.
// A refusal leaves the last valid snapshot in place.
//
// Close does not prevent it: closing stops the background poll, and a caller's
// own read of the file it is holding is still the caller's to make.
func (w *Watcher[T]) ReloadNow() error {
	if err := w.reload(); err != nil {
		return err
	}
	w.poller.endEpisode()
	return nil
}

// Close stops the background poll and waits for it to finish. It is idempotent
// and safe from several goroutines. It is not the end of the value: Snapshot
// keeps answering with the last document this build accepted.
//
// Two things it does not do. It does not wait for a ReloadNow the CALLER started
// -- that read belongs to the caller's goroutine, and the only one Close waits
// for is the poll goroutine's. And calling Close from inside the caller's own
// validate deadlocks: validate runs on the poll goroutine, and Close waits for
// that goroutine, so a handler that closes the watcher it is being called by
// waits for itself. Neither is a mistake a plugin can make by accident, and both
// are mistakes worth naming.
func (w *Watcher[T]) Close() error { return w.stopPolling() }

// reload is one read of the document. The order is the rule: the state's own
// read first, so a document the rest of the router would refuse can never reach
// the caller's check or the stored value, and the caller's own check second, so
// a refusal it adds is a refusal like any other.
func (w *Watcher[T]) reload() error {
	var decoded T
	if err := state.ReadJSON(w.path, &decoded); err != nil {
		return err
	}
	if w.validate != nil {
		if err := w.validate(decoded); err != nil {
			return fmt.Errorf("%s: caller refused the document: %w", w.path, err)
		}
	}
	w.store(decoded)
	return nil
}

// store takes the write lock for the whole of the change, so a query reading a
// snapshot sees either the previous generation or this one and never a document
// with half of each.
func (w *Watcher[T]) store(value T) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.value = w.clone(value)
}

// documentName is the name of a state document, and is how a document type
// becomes the key documentCloners is written in. It returns the empty string for
// a type that is not one of the documents, which is a program that put something
// other than a state document into Document.
func documentName(value any) string {
	switch value.(type) {
	case state.DHCPState:
		return "DHCPState"
	case state.Selector:
		return "Selector"
	case state.ECHState:
		return "ECHState"
	case state.BandwidthBudgetState:
		return "BandwidthBudgetState"
	case state.HealthState:
		return "HealthState"
	}
	return ""
}

// documentCloners is every document the watcher can copy, one entry per document
// and the only list of them there is: the count of its keys is the number of
// documents a caller can hand to a watcher, and the snapshot-isolation test
// requires a subtest for each.
//
// The copies are the fields a caller could reach through the value it was
// handed: a DHCP record's upstream slice and a selector's CloudFront map. The
// other three hold only strings, times, numbers and booleans, and need no
// copying, because a struct assignment already copied everything there is to copy
// -- a time.Time does carry a shared *time.Location, and no method on it writes
// through that pointer. They are here anyway, because a document with a map or a
// slice in it has to be found here rather than at the query that first hands one
// out.
var documentCloners = map[string]func(any) any{
	"DHCPState": func(value any) any {
		cloned := value.(state.DHCPState)
		cloned.Upstreams = slices.Clone(cloned.Upstreams)
		return cloned
	},
	"Selector": func(value any) any {
		cloned := value.(state.Selector)
		cloned.CloudFront = maps.Clone(cloned.CloudFront)
		return cloned
	},
	"ECHState": func(value any) any {
		// No map and no slice: a struct assignment copies all of it.
		return value
	},
	"BandwidthBudgetState": func(value any) any {
		// No map and no slice: a struct assignment copies all of it.
		return value
	},
	"HealthState": func(value any) any {
		// No map and no slice: a struct assignment copies all of it.
		return value
	},
}

// documentCloner returns the copy function for one document type, resolved once
// at construction so that neither Snapshot nor a reload pays for the lookup on
// every query.
//
// A document type with no entry here is refused loudly. Go cannot check that a
// type switch over a type set is exhaustive, so a state document added to
// Document without an entry here would otherwise fall through to a copy that
// shares everything, and the first sign of it would be a plugin editing the
// router's live state from inside a query. Failing at construction is the
// direction to fail in: the router does not start, rather than starting and
// answering from a value a caller can edit.
func documentCloner[T Document]() func(T) T {
	name := documentName(*new(T))
	copier, known := documentCloners[name]
	if !known {
		panic(fmt.Sprintf("statewatch: no snapshot copy for %T; give it an entry in documentCloners and a subtest in the isolation test", *new(T)))
	}
	return func(value T) T {
		return any(copier(any(value))).(T)
	}
}
