// Package optimizer selects a CDN address from measured candidates. This file
// holds the half of it that bounds what measuring may cost: the daily
// bandwidth budget.
//
// The budget is a reserve-then-settle account. A caller asks for the most bytes
// it might read, the request is persisted before a single byte is transferred,
// and the caller settles afterwards with what it really read. Every clause here
// exists because the other one is unsafe: the reservation is written before any
// I/O so a crash costs one candidate's limit and not a whole day's, a reservation
// is settled exactly once so the same bytes can never be handed back twice, and
// the total is never negative, so Used() can never report more room than the
// limit allows.
package optimizer

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"mosdns-router/internal/filelock"
	"mosdns-router/internal/state"
)

const (
	// DefaultBudgetName is the document a run keeps the day's total in. It is a
	// name rather than a full path so the runtime directory stays a parameter
	// and no test can be tempted to write to the production one.
	DefaultBudgetName = "bandwidth-budget.json"

	// DefaultBudgetPath is where the production router keeps the day's total,
	// beside the selector state and under the same runtime directory. Every
	// caller passes its own path: this one is the production default and is
	// never a default, because a test that wrote here would write /var/lib.
	DefaultBudgetPath = "/var/lib/mosdns/runtime/" + DefaultBudgetName

	// BudgetLockSuffix names the dedicated lock file that follows the budget's
	// own path. The lock is not the control lock: a measurement run holds the
	// budget for minutes, and holding the control lock for that would block
	// apply, pin and health-check behind a download.
	BudgetLockSuffix = ".lock"

	// localDateLayout is the calendar date the document records, in the
	// location the caller gave. It is the layout state.BandwidthBudgetState
	// validates, repeated so the two cannot drift.
	localDateLayout = "2006-01-02"

	// defaultLockWait bounds how long a persist waits for another holder of the
	// budget lock. It is long enough for a peer to finish one small atomic
	// write, and short enough that a stuck peer fails a run instead of hanging
	// it: a reservation that cannot be persisted must not be handed out.
	defaultLockWait = 5 * time.Second

	// lockRetryDelay is the pause between attempts at the budget lock. The wait
	// is a poll because filelock.Acquire refuses to block, deliberately: a
	// caller of the control lock must be told at once that it is held.
	lockRetryDelay = 2 * time.Millisecond
)

// ErrBudgetExhausted reports that a reservation is larger than what is left of
// the day's budget. The error names what remains and what was asked for, so a
// report can say which request was refused and against how much; a caller that
// only needs the verdict matches it with errors.Is.
var ErrBudgetExhausted = errors.New("bandwidth budget exhausted")

// ErrNoReservation reports that a settle or a release names a reservation this
// budget never handed out, or already settled. It is the refusal that keeps a
// repeated settle from handing back the same bytes twice, and it refuses the
// call without moving the total.
var ErrNoReservation = errors.New("there is no outstanding reservation of that size")

// ErrNotATransfer reports that a settle named a negative number of transferred
// bytes. No reservation is claimed and no total moves, because a caller that
// miscounted may still have a real transfer to report.
var ErrNotATransfer = errors.New("a transfer is not a negative number of bytes")

// errLockTimeout reports that the budget lock stayed held by another process
// for longer than a persist is willing to wait. It is not ErrBudgetExhausted:
// the day may well have room, and the caller must not conclude otherwise.
var errLockTimeout = errors.New("the bandwidth budget lock is held by another process")

// counter is where a Budget's byte total lives. The in-memory counter and the
// file-backed one below share every rule about what a total may be, and differ
// only in where the number survives. Neither refund can take a total below zero
// or above the day's limit: a settle is matched to an outstanding reservation, so
// a refund is always smaller than the charge it came from, and the two clamps
// are there for a document somebody else wrote.
type counter interface {
	// reserve adds requested bytes to the total when that many are still
	// available, persists the new total, and returns it.
	reserve(day string, limit, requested int64) (int64, error)
	// refund takes back up to amount bytes, never taking the total below zero,
	// persists what is left, and returns it.
	refund(day string, limit, amount int64) (int64, error)
	// total reports the current total without writing.
	total(day string, limit int64) (int64, error)
}

// Budget is a daily byte allowance a download probe reserves from. It is safe
// to call from more than one goroutine, and the zero value is not usable: build
// one with NewBudget for an in-process account, or NewPersistentBudget for the
// one the router and its CLI share.
//
// Every reservation this budget hands out is remembered until it is settled or
// released, and it is remembered once: a second settle of the same reservation is
// refused rather than allowed to hand back the same bytes again. The remembered
// set belongs to this value alone, so a run must spend through one Budget for a
// document rather than opening a second one to settle the first one's work.
type Budget struct {
	mutex   sync.Mutex
	counter counter
	limit   int64
	// location and moment decide which local date a reservation belongs to.
	location *time.Location
	moment   time.Time
	// outstanding counts the reservations handed out and not yet settled, by the
	// amount each one reserved. The amount is the only identity the plan's
	// interface carries, so two reservations of the same size are two entries.
	outstanding map[int64]int
	// lastKnown is the most recent total this budget could establish. A total it
	// can no longer read is reported from here rather than as an unverified
	// zero, so a reader that lost the file does not learn there is budget left.
	lastKnown int64
}

// NewBudget returns an in-process budget of limit bytes. It bounds one process's
// own transfers; the router's daily budget is NewPersistentBudget, because a
// total that lives only in memory forgets every reservation a previous run
// made, and a forgotten reservation is a day the cap does not hold.
func NewBudget(limit int64) *Budget {
	return &Budget{
		counter:     &memoryCounter{},
		limit:       limit,
		location:    time.Local,
		moment:      time.Now(),
		outstanding: make(map[int64]int),
	}
}

// NewPersistentBudget opens the day's budget kept in the document at path, with
// limit bytes allowed per local date.
//
// location and moment decide which day a reservation belongs to: the moment is
// formatted in the location, and because it is fixed for the life of this value
// a run cannot straddle two days and split its spending between them. A zero
// moment means the current one.
//
// Opening is a read and nothing else: no document is created until a byte is
// actually reserved. A document that exists but cannot be read is refused here
// rather than later, because a total this build cannot establish is not a total
// of zero.
func NewPersistentBudget(path string, limit int64, location *time.Location, moment time.Time) (*Budget, error) {
	return newPersistentBudget(path, path+BudgetLockSuffix, limit, location, moment, defaultLockWait)
}

// NewPersistentBudgetWithLock is NewPersistentBudget with the lock file named by
// the caller rather than derived from the document path. The derived name is the
// production default, and it is a default because the lock belongs to this budget
// alone: a deployment that keeps the lock somewhere else must still give every
// budget on the document the same one, or two budgets would each take a lock the
// other never takes.
func NewPersistentBudgetWithLock(path, lockPath string, limit int64, location *time.Location, moment time.Time) (*Budget, error) {
	return newPersistentBudget(path, lockPath, limit, location, moment, defaultLockWait)
}

// newPersistentBudget is NewPersistentBudget with the lock file and the wait
// named, which is how the constructor and a caller that keeps its lock
// elsewhere, or a test that cannot wait five seconds, share one path.
func newPersistentBudget(path, lockPath string, limit int64, location *time.Location, moment time.Time, wait time.Duration) (*Budget, error) {
	switch {
	case path == "":
		return nil, errors.New("the bandwidth budget needs a document path")
	case lockPath == "":
		return nil, errors.New("the bandwidth budget needs a lock file path of its own")
	case limit <= 0:
		// A budget that allows nothing is refused here rather than left to
		// refuse every request later: a run told its limit is unusable is a
		// configuration error, and a silently starved budget looks like a
		// network fault.
		return nil, fmt.Errorf("the daily bandwidth budget must be greater than zero, got %d", limit)
	}
	if location == nil {
		location = time.Local
	}
	if moment.IsZero() {
		moment = time.Now()
	}
	budget := &Budget{
		counter:     &fileCounter{path: path, lockPath: lockPath, wait: wait},
		limit:       limit,
		location:    location,
		moment:      moment,
		outstanding: make(map[int64]int),
	}
	// Read once here so a document that is not usable is reported by the caller
	// that opened the budget, not by the first probe that happened to spend.
	if _, err := budget.counter.total(budget.day(), limit); err != nil {
		return nil, err
	}
	return budget, nil
}

// Reserve persists a request for requested bytes and returns the amount
// reserved, which is exactly what was asked for. The order is the whole point:
// the bytes are charged before the caller reads anything, so a caller that dies
// mid-transfer is billed its reservation rather than nothing.
//
// A request of zero or less is refused, because there is nothing to reserve and
// a caller that asks for one is a caller that has not measured anything. A
// request larger than what remains is refused with ErrBudgetExhausted and
// changes nothing. A document that cannot be read or written is also a refusal:
// the cap is only worth having if it is actually on the books.
func (b *Budget) Reserve(requested int64) (int64, error) {
	if requested <= 0 {
		return 0, fmt.Errorf("a reservation must cover at least one byte, got %d", requested)
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	used, err := b.counter.reserve(b.day(), b.limit, requested)
	if err != nil {
		return 0, err
	}
	b.lastKnown = used
	// The reservation is remembered before the caller is handed the number, so
	// the one settle that may follow it can be matched to it.
	b.outstanding[requested]++
	return requested, nil
}

// Settle closes a reservation with what was really transferred and hands the
// difference back. It is the honest form of the prober's Consume: it reports
// which reservation it settled and refuses the two calls that could otherwise
// hand back bytes that were never handed out.
//
// The rules, in the order they are applied:
//
//   - A negative actual is not a transfer at all (ErrNotATransfer). Nothing
//     changes, including the reservation, because the caller that miscounted may
//     still have a real transfer to report.
//   - An amount with no outstanding reservation is refused (ErrNoReservation).
//     This is the one that matters: a second settle of the same reservation
//     would otherwise hand back the difference a second time, turning real
//     spending into free budget.
//   - An actual above the reservation is charged as the reservation. A reader
//     cannot be believed past what it was given, and the reader can never hand
//     back more than it took.
//   - Anything else in [0, reserved] settles the reservation and hands back
//     reserved - actual.
//
// The reservation is claimed before the document is written, so two settles of
// one reservation racing in two goroutines produce one settle and one refusal
// whatever the interleaving. A write that fails leaves the reservation claimed
// and its bytes charged: over-counting costs the user budget and under-counting
// costs the user money, and the first is the smaller mistake.
func (b *Budget) Settle(reserved, actual int64) error {
	if actual < 0 {
		return fmt.Errorf("%w: got %d for a reservation of %d", ErrNotATransfer, actual, reserved)
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.outstanding[reserved] == 0 {
		return fmt.Errorf("%w of %d bytes, with %d still reserved", ErrNoReservation, reserved, b.reserved())
	}
	b.claim(reserved)
	// The reader cannot be believed past the reservation, so the charge is capped
	// there rather than growing to whatever it claimed.
	charge := min(actual, reserved)
	refund := reserved - charge
	if refund == 0 {
		// The document already records the whole charge, so there is nothing to
		// persist and no reason to take the lock.
		return nil
	}
	used, err := b.counter.refund(b.day(), b.limit, refund)
	if err != nil {
		return err
	}
	b.lastKnown = used
	return nil
}

// Release hands back a whole reservation that the caller will not use, because a
// reservation it never read against has cost nothing. It is one-shot for the same
// reason a settle is: a release is exactly as able as a settle to hand back the
// same bytes twice, and settling a released reservation is refused.
func (b *Budget) Release(reserved int64) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.outstanding[reserved] == 0 {
		return fmt.Errorf("%w of %d bytes, with %d still reserved", ErrNoReservation, reserved, b.reserved())
	}
	b.claim(reserved)
	used, err := b.counter.refund(b.day(), b.limit, reserved)
	if err != nil {
		return err
	}
	b.lastKnown = used
	return nil
}

// Consume settles a reservation, and cannot report a refusal because the prober's
// budget interface gives it no way to. It is Settle for a caller with nowhere to
// put an error; a caller that has one should call Settle, because a refused
// settle is a real outcome a run may want to see rather than swallow.
//
// The one-shot rule does not depend on which of the two is called: a repeated
// Consume of one reservation hands back nothing the second time, exactly as a
// repeated Settle is refused.
func (b *Budget) Consume(reserved, actual int64) {
	_ = b.Settle(reserved, actual)
}

// claim removes one outstanding reservation of the given size. The caller holds
// the lock and has already established that there is one.
func (b *Budget) claim(reserved int64) {
	if b.outstanding[reserved] <= 1 {
		delete(b.outstanding, reserved)
		return
	}
	b.outstanding[reserved]--
}

// reserved reports how many bytes are still reserved and unsettled, which is what
// a refusal names so that a caller can see what it should have settled instead.
func (b *Budget) reserved() int64 {
	var total int64
	for amount, count := range b.outstanding {
		total += amount * int64(count)
	}
	return total
}

// Used reports how many bytes of the day's limit are already spent. It reads the
// persisted total rather than a cached field, so two Budget values on one
// document, and two processes on one document, see each other's spending. A
// total that cannot be read is reported as the last one this budget established.
func (b *Budget) Used() int64 {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	used, err := b.counter.total(b.day(), b.limit)
	if err != nil {
		return b.lastKnown
	}
	b.lastKnown = used
	return used
}

// Path is where this budget's document lives, and is empty for a budget that
// has no document.
func (b *Budget) Path() string {
	if file, ok := b.counter.(*fileCounter); ok {
		return file.path
	}
	return ""
}

// LockPath is the lock file this budget takes around each persist, and is empty
// for a budget that has none.
func (b *Budget) LockPath() string {
	if file, ok := b.counter.(*fileCounter); ok {
		return file.lockPath
	}
	return ""
}

// day is the local date every reservation of this budget belongs to.
func (b *Budget) day() string {
	return b.moment.In(b.location).Format(localDateLayout)
}

// dayRule decides what a recorded document means for the caller's day. It
// returns the total to charge and the limit the day is held to.
//
// A record for another day starts at nothing, with the caller's own limit: the
// local date is the whole reset mechanism, and there is no midnight job to miss.
// A record for this day is held to the smaller of the caller's limit and the one
// the record already carries, so a day can be tightened by an operator and never
// loosened by a process that has forgotten the tighter number. A total above the
// day's limit describes a day already overspent, and is reported as fully spent
// rather than as negative room.
func dayRule(recorded state.BandwidthBudgetState, limit int64, day string) (used, effective int64) {
	if recorded.LocalDate != day {
		return 0, limit
	}
	effective = limit
	if recorded.LimitBytes < effective {
		effective = recorded.LimitBytes
	}
	if recorded.UsedBytes > effective {
		return effective, effective
	}
	return recorded.UsedBytes, effective
}

// memoryCounter is a budget total that lives only in this process. It is
// serialised by the Budget that owns it.
type memoryCounter struct {
	day  string
	used int64
}

var _ counter = (*memoryCounter)(nil)

func (m *memoryCounter) reserve(day string, limit, requested int64) (int64, error) {
	used, effective := dayRule(m.record(limit), limit, day)
	if effective-used < requested {
		return 0, exhausted(effective-used, requested, effective)
	}
	m.day, m.used = day, used+requested
	return m.used, nil
}

func (m *memoryCounter) refund(day string, limit, amount int64) (int64, error) {
	used, effective := dayRule(m.record(limit), limit, day)
	used -= amount
	if used < 0 {
		used = 0
	}
	if used > effective {
		used = effective
	}
	m.day, m.used = day, used
	return used, nil
}

func (m *memoryCounter) total(day string, limit int64) (int64, error) {
	used, _ := dayRule(m.record(limit), limit, day)
	return used, nil
}

func (m *memoryCounter) record(limit int64) state.BandwidthBudgetState {
	return state.BandwidthBudgetState{SchemaVersion: state.SchemaVersion, LocalDate: m.day, LimitBytes: limit, UsedBytes: m.used}
}

// fileCounter is a budget total in a state document, shared by every process that
// opens the same path. Each persist takes the document's own lock, reads,
// changes one number, and writes it back through state.WriteJSONAtomic, so a
// reader that opens the document at any moment sees one of the two totals and
// never half of one.
type fileCounter struct {
	path     string
	lockPath string
	wait     time.Duration
}

var _ counter = (*fileCounter)(nil)

func (f *fileCounter) reserve(day string, limit, requested int64) (int64, error) {
	release, err := f.acquire()
	if err != nil {
		return 0, err
	}
	defer release()
	record, err := f.read()
	if err != nil {
		return 0, err
	}
	used, effective := dayRule(record, limit, day)
	if remaining := effective - used; remaining < requested {
		return 0, exhausted(remaining, requested, effective)
	}
	used += requested
	if err := f.write(day, effective, used); err != nil {
		return 0, err
	}
	return used, nil
}

func (f *fileCounter) refund(day string, limit, amount int64) (int64, error) {
	release, err := f.acquire()
	if err != nil {
		return 0, err
	}
	defer release()
	record, err := f.read()
	if err != nil {
		return 0, err
	}
	used, effective := dayRule(record, limit, day)
	used -= amount
	if used < 0 {
		used = 0
	}
	if used > effective {
		used = effective
	}
	if err := f.write(day, effective, used); err != nil {
		return 0, err
	}
	return used, nil
}

// total reads without taking the lock. The document is replaced by a rename
// rather than rewritten, so a reader is never looking at a half-written number,
// and a total is a number nothing is still holding.
func (f *fileCounter) total(day string, limit int64) (int64, error) {
	record, err := f.read()
	if err != nil {
		return 0, err
	}
	used, _ := dayRule(record, limit, day)
	return used, nil
}

func (f *fileCounter) read() (state.BandwidthBudgetState, error) {
	record := state.BandwidthBudgetState{}
	if err := state.ReadJSON(f.path, &record); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No document is no spending, and the caller is free to create one.
			return record, nil
		}
		return record, fmt.Errorf("%s: read the bandwidth budget: %w", f.path, err)
	}
	return record, nil
}

func (f *fileCounter) write(day string, limit, used int64) error {
	record := state.BandwidthBudgetState{
		SchemaVersion: state.SchemaVersion,
		LocalDate:     day,
		LimitBytes:    limit,
		UsedBytes:     used,
	}
	if err := state.WriteJSONAtomic(f.path, record); err != nil {
		return fmt.Errorf("%s: write the bandwidth budget: %w", f.path, err)
	}
	return nil
}

// acquire takes the budget's own lock and returns the function that releases it.
//
// It polls rather than blocks, because filelock.Acquire refuses to block on
// purpose: a caller of the control lock must be told at once that the lock is
// held. Waiting is right here and only here, because the holders of this lock
// are spends that last as long as one small atomic write, and refusing a
// reservation because a peer was halfway through persisting its own would turn a
// measurement run into a failure. A lock that stays held past the wait is a lock
// this run refuses to write around.
func (f *fileCounter) acquire() (func(), error) {
	deadline := time.Now().Add(f.wait)
	for {
		held, err := filelock.Acquire(f.lockPath)
		if err == nil {
			// The advisory lock is released by closing the descriptor, whether
			// or not Close reports an error, so there is nothing to say about it.
			return func() { _ = held.Close() }, nil
		}
		if !errors.Is(err, filelock.ErrLocked) {
			return nil, fmt.Errorf("%s: take the bandwidth budget lock: %w", f.lockPath, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s: %w after %s", f.lockPath, errLockTimeout, f.wait)
		}
		time.Sleep(lockRetryDelay)
	}
}

// exhausted names both numbers a caller needs to act on the refusal: what is
// left of the day, what was asked for, and what the day allows at all.
func exhausted(remaining, requested, limit int64) error {
	return fmt.Errorf("%w: %d bytes remain of the %d requested and %d allowed today", ErrBudgetExhausted, remaining, requested, limit)
}
