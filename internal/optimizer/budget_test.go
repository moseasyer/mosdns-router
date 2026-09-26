package optimizer

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"mosdns-router/internal/filelock"
	"mosdns-router/internal/prober"
	"mosdns-router/internal/state"
)

// The budget is the hard daily cap the whole project exists to keep: this
// router is a domestic-egress router, and a measurement run that spends the
// user's traffic is worse than a run that measures nothing. The numbers below
// are the policy defaults this repository ships (cdn.bandwidth.daily_budget and
// cdn.bandwidth.per_candidate_limit), so a test that proves the eleventh 10 MiB
// request is refused is proving the documented behaviour and not a constant.

const (
	mib = 1 << 20

	dailyBudgetBytes  = 100 * mib
	perCandidateBytes = 10 * mib
)

// The optimizer reserves from a budget through the prober's own interface, so
// a signature drift between the two packages is a compile error rather than a
// run that charges nothing.
var _ prober.ByteBudget = (*Budget)(nil)

func TestBudgetRejectsRequestOverRemaining(t *testing.T) {
	// A reservation larger than what is left is refused with an error that names
	// both numbers, because the refusal is what a report has to explain: which
	// request was refused and against how much.
	budget := NewBudget(dailyBudgetBytes)
	for attempt := 1; attempt <= 10; attempt++ {
		reserved, err := budget.Reserve(perCandidateBytes)
		if err != nil {
			t.Fatalf("reservation %d of 10 MiB: %v", attempt, err)
		}
		if reserved != perCandidateBytes {
			t.Fatalf("reservation %d returned %d bytes, want the %d it asked for", attempt, reserved, perCandidateBytes)
		}
	}
	if used := budget.Used(); used != dailyBudgetBytes {
		t.Fatalf("Used() = %d after ten 10 MiB reservations, want %d", used, dailyBudgetBytes)
	}

	reserved, err := budget.Reserve(perCandidateBytes)
	if err == nil {
		t.Fatalf("the eleventh 10 MiB request was accepted, Used() = %d", budget.Used())
	}
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("the eleventh request failed with %v, want ErrBudgetExhausted", err)
	}
	if reserved != 0 {
		t.Errorf("a refused request returned %d bytes, want 0", reserved)
	}
	if used := budget.Used(); used != dailyBudgetBytes {
		t.Errorf("Used() = %d after a refused request, want the unchanged %d", used, dailyBudgetBytes)
	}
	// Both numbers are named: 0 bytes remain, and 10485760 were asked for.
	if !strings.Contains(err.Error(), "0 bytes remain") {
		t.Errorf("the refusal does not name what remains: %v", err)
	}
	if !strings.Contains(err.Error(), "10485760") {
		t.Errorf("the refusal does not name the requested size: %v", err)
	}
}

func TestBudgetReturnsUnusedReservation(t *testing.T) {
	// A download that stops early must hand the difference back, or a run that
	// measured ten candidates would spend a hundred megabytes of the user's
	// traffic on ten small responses.
	budget := NewBudget(dailyBudgetBytes)
	reserved, err := budget.Reserve(perCandidateBytes)
	if err != nil {
		t.Fatalf("reserve 10 MiB: %v", err)
	}
	if used := budget.Used(); used != perCandidateBytes {
		t.Fatalf("Used() = %d after reserving 10 MiB, want %d", used, perCandidateBytes)
	}

	budget.Consume(reserved, 3*mib)

	if used := budget.Used(); used != 3*mib {
		t.Fatalf("Used() = %d after consuming 3 MiB of a 10 MiB reservation, want %d", used, 3*mib)
	}
	// The returned bytes are spendable again, which is what makes a short
	// download cost what it transferred.
	again, err := budget.Reserve(perCandidateBytes)
	if err != nil {
		t.Fatalf("reserve 10 MiB again after a 7 MiB return: %v", err)
	}
	if again != perCandidateBytes {
		t.Fatalf("the second reservation returned %d bytes, want %d", again, perCandidateBytes)
	}
	if used := budget.Used(); used != 13*mib {
		t.Fatalf("Used() = %d, want %d", used, 13*mib)
	}
}

// TestBudgetNeverNegative is about the direction of every refusal, because a
// total that dips below the real spend is free traffic and a total that dips
// below zero is a budget with more than its limit left in it. Every case states
// the exact total, not only its sign, and the settle cases go through Settle so
// that the refusal is visible to the caller as well as to the total.
func TestBudgetNeverNegative(t *testing.T) {
	for name, table := range map[string]struct {
		setup    func(*testing.T, *Budget) (int64, error)
		wantUsed int64
		wantErr  error
	}{
		"a settle inside the reservation hands back the difference": {
			setup: func(_ *testing.T, budget *Budget) (int64, error) {
				reserved := mustReserve(t, budget, perCandidateBytes)
				return reserved, budget.Settle(reserved, 2*mib)
			},
			wantUsed: 2 * mib,
		},
		"a byte count above the reservation is charged as the reservation": {
			setup: func(_ *testing.T, budget *Budget) (int64, error) {
				reserved := mustReserve(t, budget, 4*mib)
				return reserved, budget.Settle(reserved, 9*mib)
			},
			wantUsed: 4 * mib,
		},
		"a second settle of one reservation is refused and hands nothing back": {
			setup: func(_ *testing.T, budget *Budget) (int64, error) {
				reserved := mustReserve(t, budget, perCandidateBytes)
				if err := budget.Settle(reserved, 2*mib); err != nil {
					t.Fatalf("the first settle: %v", err)
				}
				return reserved, budget.Settle(reserved, 2*mib)
			},
			wantUsed: 2 * mib,
			wantErr:  ErrNoReservation,
		},
		"a settle of a reservation that was never made is refused": {
			setup: func(_ *testing.T, budget *Budget) (int64, error) {
				return perCandidateBytes, budget.Settle(perCandidateBytes, 1*mib)
			},
			wantUsed: 0,
			wantErr:  ErrNoReservation,
		},
		"a negative byte count is refused and leaves the reservation outstanding": {
			setup: func(_ *testing.T, budget *Budget) (int64, error) {
				reserved := mustReserve(t, budget, perCandidateBytes)
				return reserved, budget.Settle(reserved, -1)
			},
			wantUsed: perCandidateBytes,
			wantErr:  ErrNotATransfer,
		},
		"a settle of no bytes at all is refused": {
			setup: func(_ *testing.T, budget *Budget) (int64, error) {
				return 0, budget.Settle(0, 0)
			},
			wantUsed: 0,
			wantErr:  ErrNoReservation,
		},
		"a refused settle between two good ones leaves the rest alone": {
			setup: func(_ *testing.T, budget *Budget) (int64, error) {
				first := mustReserve(t, budget, 4*mib)
				if err := budget.Settle(first, 1*mib); err != nil {
					t.Fatalf("the first settle: %v", err)
				}
				second := mustReserve(t, budget, 2*mib)
				return second, budget.Settle(second, -1)
			},
			wantUsed: 3 * mib,
			wantErr:  ErrNotATransfer,
		},
	} {
		t.Run(name, func(t *testing.T) {
			budget := NewBudget(perCandidateBytes)
			_, err := table.setup(t, budget)
			switch {
			case table.wantErr == nil && err != nil:
				t.Fatalf("the settle failed: %v", err)
			case table.wantErr != nil && !errors.Is(err, table.wantErr):
				t.Fatalf("the settle failed with %v, want %v", err, table.wantErr)
			}
			if used := budget.Used(); used != table.wantUsed {
				t.Fatalf("Used() = %d, want %d", used, table.wantUsed)
			}
			if used := budget.Used(); used < 0 {
				t.Fatalf("Used() = %d, which is a budget with more than its limit left in it", used)
			}
		})
	}
}

func TestBudgetSettlesAReservationOnlyOnce(t *testing.T) {
	// The one-shot rule on its own, with the reserved amount as the only identity
	// the plan's interface carries. A settle is matched to an outstanding
	// reservation and removes it, so the same bytes can never be handed back
	// twice, whatever the caller does with the value it was given.
	budget := NewBudget(dailyBudgetBytes)
	reserved := mustReserve(t, budget, perCandidateBytes)
	half := mustReserve(t, budget, perCandidateBytes)

	if err := budget.Settle(reserved, 2*mib); err != nil {
		t.Fatalf("settle the first reservation with 2 MiB: %v", err)
	}
	if err := budget.Settle(half, 2*mib); err != nil {
		t.Fatalf("settle the second reservation with 2 MiB: %v", err)
	}
	if used := budget.Used(); used != 4*mib {
		t.Fatalf("Used() = %d, want the %d really spent by two reservations", used, 4*mib)
	}
	for _, exhausted := range []int64{reserved, half} {
		if err := budget.Settle(exhausted, 2*mib); !errors.Is(err, ErrNoReservation) {
			t.Errorf("settling the already settled %d bytes again failed with %v, want %v", exhausted, err, ErrNoReservation)
		}
	}
	if used := budget.Used(); used != 4*mib {
		t.Fatalf("Used() = %d after settling exhausted reservations, want the unchanged %d", used, 4*mib)
	}
}

func TestBudgetKeepsAReservationOutstandingAfterARefusedSettle(t *testing.T) {
	// A refused settle changes nothing at all, including the reservation: a
	// negative count is not a transfer, and the caller that sent it may still have
	// a real one to report.
	budget := NewBudget(perCandidateBytes)
	reserved := mustReserve(t, budget, perCandidateBytes)

	if err := budget.Settle(reserved, -1); !errors.Is(err, ErrNotATransfer) {
		t.Fatalf("a negative count failed with %v, want %v", err, ErrNotATransfer)
	}
	if used := budget.Used(); used != perCandidateBytes {
		t.Fatalf("Used() = %d after a refused settle, want the %d still reserved", used, perCandidateBytes)
	}
	if err := budget.Settle(reserved, 1*mib); err != nil {
		t.Fatalf("the real transfer after a refused one: %v", err)
	}
	if used := budget.Used(); used != 1*mib {
		t.Fatalf("Used() = %d, want the %d really spent", used, 1*mib)
	}
}

func TestBudgetRefusesTwoSettlesOfOneReservationAtOnce(t *testing.T) {
	// Two callers settling the same reservation at the same time is the race the
	// one-shot rule exists for. Exactly one may succeed, and the total must be
	// what the one real transfer cost, however the two interleave.
	budget := NewBudget(perCandidateBytes)
	reserved := mustReserve(t, budget, perCandidateBytes)

	results := make(chan error, 2)
	release := make(chan struct{})
	for attempt := 0; attempt < 2; attempt++ {
		go func() {
			<-release
			results <- budget.Settle(reserved, 2*mib)
		}()
	}
	close(release)

	var accepted, refused int
	for attempt := 0; attempt < 2; attempt++ {
		err := <-results
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrNoReservation):
			refused++
		default:
			t.Fatalf("a concurrent settle failed with %v, want a refusal or success", err)
		}
	}
	if accepted != 1 || refused != 1 {
		t.Fatalf("%d settles were accepted and %d refused, want exactly one of each", accepted, refused)
	}
	if used := budget.Used(); used != 2*mib {
		t.Fatalf("Used() = %d after a contended settle, want the %d one real transfer cost", used, 2*mib)
	}
}

func TestBudgetSettlesConcurrentReservationsWithoutLosingASpend(t *testing.T) {
	// Every reservation in a concurrent run is settled once and the run's total
	// is the sum of what the transfers really moved. This is the case a refund
	// that fires twice, or not at all, would break, and it is the one a run of ten
	// candidates actually looks like.
	const candidates = 20
	reserved := int64(perCandidateBytes / 10)
	transferred := reserved / 2
	budget := NewBudget(dailyBudgetBytes)

	var group sync.WaitGroup
	for candidate := 0; candidate < candidates; candidate++ {
		group.Add(1)
		go func() {
			defer group.Done()
			settled, err := budget.Reserve(reserved)
			if err != nil {
				t.Errorf("reserve %d bytes: %v", reserved, err)
				return
			}
			if err := budget.Settle(settled, transferred); err != nil {
				t.Errorf("settle %d of %d bytes: %v", transferred, reserved, err)
			}
		}()
	}
	group.Wait()

	if used := budget.Used(); used != candidates*transferred {
		t.Fatalf("Used() = %d after %d concurrent transfers of %d bytes, want %d", used, candidates, transferred, candidates*transferred)
	}
}

func TestBudgetReleaseHandsBackAWholeReservation(t *testing.T) {
	// A caller that abandons a reservation before it reads anything has spent
	// nothing, and saying so is one call. It is one-shot like a settle, because a
	// release is exactly as capable of handing back the same bytes twice.
	budget := NewBudget(dailyBudgetBytes)
	reserved := mustReserve(t, budget, perCandidateBytes)

	if err := budget.Release(reserved); err != nil {
		t.Fatalf("release a reservation that was never used: %v", err)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("Used() = %d after releasing an unused reservation, want 0", used)
	}
	if err := budget.Release(reserved); !errors.Is(err, ErrNoReservation) {
		t.Errorf("releasing the same reservation again failed with %v, want %v", err, ErrNoReservation)
	}
	if err := budget.Settle(reserved, 0); !errors.Is(err, ErrNoReservation) {
		t.Errorf("settling a released reservation failed with %v, want %v", err, ErrNoReservation)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("Used() = %d, want 0", used)
	}
}

func TestBudgetReleaseIsNotATransfer(t *testing.T) {
	// A caller that reads bytes and then releases the reservation would be handed
	// money it spent, so a reservation that was already settled is not released
	// either.
	budget := NewBudget(dailyBudgetBytes)
	reserved := mustReserve(t, budget, perCandidateBytes)
	if err := budget.Settle(reserved, 4*mib); err != nil {
		t.Fatalf("settle 4 MiB of a 10 MiB reservation: %v", err)
	}

	if err := budget.Release(reserved); !errors.Is(err, ErrNoReservation) {
		t.Errorf("releasing a settled reservation failed with %v, want %v", err, ErrNoReservation)
	}
	if used := budget.Used(); used != 4*mib {
		t.Errorf("Used() = %d, want the %d really spent", used, 4*mib)
	}
}

func TestBudgetReleaseLeavesTheChargeGoneForTheNextRun(t *testing.T) {
	// A released reservation is not a crash: the next run opens a document that
	// says nothing was spent, because nothing was.
	directory := t.TempDir()
	run := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	reserved := mustReserve(t, run, perCandidateBytes)
	if err := run.Release(reserved); err != nil {
		t.Fatalf("release the reservation: %v", err)
	}

	restarted := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	if used := restarted.Used(); used != 0 {
		t.Fatalf("Used() = %d after a released reservation, want 0", used)
	}
	if reserved := mustReserve(t, restarted, perCandidateBytes); reserved != perCandidateBytes {
		t.Fatalf("the new run reserved %d bytes, want %d", reserved, perCandidateBytes)
	}
}

func TestBudgetSettlesThroughTheProberInterfaceOnlyOnceToo(t *testing.T) {
	// The prober's interface has no way to report a refusal, so the guarantee has
	// to live in the budget: a caller that settles twice through the interface
	// still gets one settle and one refusal, and the total is the real spend.
	var budget ByteBudgetUnderTest = NewBudget(perCandidateBytes)
	reserved, err := budget.Reserve(perCandidateBytes)
	if err != nil {
		t.Fatalf("reserve 10 MiB: %v", err)
	}
	budget.Consume(reserved, 3*mib)
	budget.Consume(reserved, 3*mib)

	if used := budget.Used(); used != 3*mib {
		t.Fatalf("Used() = %d after settling one reservation twice through the interface, want the %d really spent", used, 3*mib)
	}
}

// ByteBudgetUnderTest is the prober's budget interface with the reporting Used
// attached, so this test can hold the budget to the one-shot rule from outside
// the package that defines it.
type ByteBudgetUnderTest interface {
	prober.ByteBudget
	Used() int64
}

func TestBudgetRefusesANonPositiveReservation(t *testing.T) {
	// A zero or negative request is a caller that has nothing to measure, and
	// accepting it would let a bug in the runner spend nothing while looking
	// like a measurement.
	for _, requested := range []int64{0, -1, -perCandidateBytes} {
		budget := NewBudget(perCandidateBytes)
		reserved, err := budget.Reserve(requested)
		if err == nil {
			t.Fatalf("Reserve(%d) was accepted and returned %d bytes", requested, reserved)
		}
		if errors.Is(err, ErrBudgetExhausted) {
			t.Errorf("Reserve(%d) failed with ErrBudgetExhausted, want a complaint about the request itself", requested)
		}
		if reserved != 0 {
			t.Errorf("Reserve(%d) returned %d bytes, want 0", requested, reserved)
		}
		if used := budget.Used(); used != 0 {
			t.Errorf("Used() = %d after refusing Reserve(%d), want 0", used, requested)
		}
	}
}

// TestBudgetConsumeNeverRefundsTheSameReservationTwice is the behaviour the
// review found inverted. Consume only knows how many bytes were reserved, so it
// cannot by itself tell a second settle from a first one, and the floor that
// keeps the total from going negative turns that confusion into free traffic:
// settling one 10 MiB reservation with 2 MiB twice took the day from 10 MiB to
// 2 MiB to 0, and 2 MiB really had crossed the wire. The total after a repeated
// settle must be what was really spent.
func TestBudgetConsumeNeverRefundsTheSameReservationTwice(t *testing.T) {
	budget := NewBudget(perCandidateBytes)
	reserved, err := budget.Reserve(perCandidateBytes)
	if err != nil {
		t.Fatalf("reserve 10 MiB: %v", err)
	}
	budget.Consume(reserved, 2*mib)
	if used := budget.Used(); used != 2*mib {
		t.Fatalf("Used() = %d after the first settle, want the %d really spent", used, 2*mib)
	}

	budget.Consume(reserved, 2*mib)

	if used := budget.Used(); used != 2*mib {
		t.Fatalf("Used() = %d after settling one reservation twice, want the %d really spent: the second settle handed back bytes that were never handed out", used, 2*mib)
	}
}

func mustReserve(t *testing.T, budget *Budget, requested int64) int64 {
	t.Helper()
	reserved, err := budget.Reserve(requested)
	if err != nil {
		t.Fatalf("reserve %d bytes: %v", requested, err)
	}
	return reserved
}

// The persistent budget is charged to a local date, and every date below is
// stated in UTC and then read in the location the budgets are given, so a
// calendar rule is visible in the assertions rather than in a timestamp
// comparison. The location is a fixed offset rather than a named zone, so the
// suite needs no zoneinfo files to say anything about time zones.
var (
	testLocation = time.FixedZone("UTC+8", 8*60*60)

	// testNoon is 2026-09-26 in UTC and in UTC+8 alike, so a date assertion
	// cannot pass because of the offset.
	testNoon = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	// testNextNoon is the next UTC day at the same wall-clock hour.
	testNextNoon = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	// testLateOnTheTwentySixth is 23:00 UTC: still the 26th in UTC, already the
	// 27th eight hours east.
	testLateOnTheTwentySixth = time.Date(2026, 9, 26, 23, 0, 0, 0, time.UTC)
)

func TestHundredMiBBoundary(t *testing.T) {
	// The hard daily cap. Ten candidates at the per-candidate limit is exactly
	// the day's budget, and the eleventh request is refused: the cap is enforced
	// by the code that spends the bytes, not by the policy that declares it.
	directory := t.TempDir()
	budget := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	for attempt := 1; attempt <= 10; attempt++ {
		if reserved := mustReserve(t, budget, perCandidateBytes); reserved != perCandidateBytes {
			t.Fatalf("reservation %d returned %d bytes, want %d", attempt, reserved, perCandidateBytes)
		}
	}
	if used := budget.Used(); used != dailyBudgetBytes {
		t.Fatalf("Used() = %d after ten 10 MiB reservations, want %d", used, dailyBudgetBytes)
	}

	reserved, err := budget.Reserve(perCandidateBytes)
	if err == nil {
		t.Fatalf("the eleventh 10 MiB request was accepted, Used() = %d", budget.Used())
	}
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("the eleventh request failed with %v, want ErrBudgetExhausted", err)
	}
	if reserved != 0 {
		t.Errorf("the eleventh request returned %d bytes, want 0", reserved)
	}
	// One byte is still one byte too many, so the boundary is the same refusal.
	if _, err := budget.Reserve(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("Reserve(1) after the cap failed with %v, want ErrBudgetExhausted", err)
	}
	record := mustReadBudget(t, budget.Path())
	if record.UsedBytes != dailyBudgetBytes {
		t.Errorf("the document records used_bytes = %d, want %d", record.UsedBytes, dailyBudgetBytes)
	}
	if record.LimitBytes != dailyBudgetBytes {
		t.Errorf("the document records limit_bytes = %d, want %d", record.LimitBytes, dailyBudgetBytes)
	}
}

func TestBudgetIsSharedByTwoValuesOnOneFile(t *testing.T) {
	// The router and its CLI are separate processes with separate memories, so a
	// total that only one of them can see is a total that stops meaning anything
	// as soon as two things spend from it. Two Budget values on one file must see
	// each other's spending, in both directions.
	directory := t.TempDir()
	first := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	second := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)

	mustReserve(t, first, perCandidateBytes)
	if used := second.Used(); used != perCandidateBytes {
		t.Fatalf("the second budget sees %d bytes spent, want the %d the first reserved", used, perCandidateBytes)
	}
	mustReserve(t, second, perCandidateBytes)
	if used := first.Used(); used != 2*perCandidateBytes {
		t.Fatalf("the first budget sees %d bytes spent, want %d", used, 2*perCandidateBytes)
	}
	// Settling through one value is visible through the other, so a run that
	// spends and then returns its unused reservation does not leave the other
	// process believing the day is fuller than it is.
	first.Consume(perCandidateBytes, 2*mib)
	if used := second.Used(); used != perCandidateBytes+2*mib {
		t.Fatalf("the second budget sees %d bytes spent, want %d", used, perCandidateBytes+2*mib)
	}
}

func TestBudgetPersistsTheReservationBeforeItReturns(t *testing.T) {
	// The reservation is written before the caller is handed a number, because
	// the caller is about to transfer bytes against it. A budget that charged on
	// settle would lose the whole transfer of a process that died mid-download.
	directory := t.TempDir()
	budget := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)

	mustReserve(t, budget, perCandidateBytes)

	record := mustReadBudget(t, budget.Path())
	if record.UsedBytes != perCandidateBytes {
		t.Fatalf("the document records used_bytes = %d immediately after Reserve returned, want %d", record.UsedBytes, perCandidateBytes)
	}
}

func TestBudgetKeepsACrashedReservationCharged(t *testing.T) {
	// A process that reserved 10 MiB and then died never settles. The bytes it
	// may have transferred are unknown, so the reservation stays charged: the
	// conservative cost is one candidate's limit, and the alternative is a
	// budget that forgets transfers it cannot account for.
	directory := t.TempDir()
	crashed := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	mustReserve(t, crashed, perCandidateBytes)
	// The crashed budget is abandoned here on purpose: there is no settle and no
	// cleanup, which is what a crash looks like to the next run.

	restarted := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	if used := restarted.Used(); used != perCandidateBytes {
		t.Fatalf("Used() = %d after a crashed reservation, want the %d it left charged", used, perCandidateBytes)
	}
	// The day still allows the rest of its budget, and the crashed reservation is
	// part of it: nine more fit and the eleventh does not.
	for attempt := 2; attempt <= 10; attempt++ {
		mustReserve(t, restarted, perCandidateBytes)
	}
	if _, err := restarted.Reserve(perCandidateBytes); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("a crashed reservation was not left charged: Reserve failed with %v", err)
	}
}

func TestBudgetRefusesASecondProcessOnceTheDayIsFull(t *testing.T) {
	// The real case: the router daemon and a `mosdns-cdnctl test` run are
	// separate processes. A child process that shares only the file must be
	// refused once the day is full, and allowed when it is not, which is what
	// makes the refusal above about the file and not about the child's setup.
	full := t.TempDir()
	parent := mustNewPersistentBudget(t, full, dailyBudgetBytes, testNoon)
	for attempt := 1; attempt <= 10; attempt++ {
		mustReserve(t, parent, perCandidateBytes)
	}
	if outcome := runBudgetHelperProcess(t, filepath.Join(full, DefaultBudgetName), testNoon, 1); outcome != helperRefused {
		t.Fatalf("a second process reserving 1 byte of a full day: %s, want %s", outcome, helperRefused)
	}

	empty := t.TempDir()
	if outcome := runBudgetHelperProcess(t, filepath.Join(empty, DefaultBudgetName), testNoon, perCandidateBytes); outcome != helperReserved {
		t.Fatalf("a second process reserving 10 MiB of an empty day: %s, want %s", outcome, helperReserved)
	}
	// The child's reservation is on the books for this process too, which is the
	// same agreement read from the other side.
	fresh := mustNewPersistentBudget(t, empty, dailyBudgetBytes, testNoon)
	if used := fresh.Used(); used != perCandidateBytes {
		t.Errorf("Used() = %d, want the %d the child reserved", used, perCandidateBytes)
	}
}

func TestBudgetResetsOnTheNextLocalDate(t *testing.T) {
	// The counter is per local date, so yesterday's spending does not refuse
	// today's measurement. Nothing is written until the new day's first byte is
	// reserved, so the reset is a rule about what the number means rather than a
	// midnight job.
	directory := t.TempDir()
	yesterday := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	for attempt := 1; attempt <= 10; attempt++ {
		mustReserve(t, yesterday, perCandidateBytes)
	}

	today := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNextNoon)
	if used := today.Used(); used != 0 {
		t.Fatalf("Used() = %d on the next local date, want 0", used)
	}
	if reserved := mustReserve(t, today, dailyBudgetBytes); reserved != dailyBudgetBytes {
		t.Fatalf("the new day reserved %d bytes, want %d", reserved, dailyBudgetBytes)
	}
	record := mustReadBudget(t, today.Path())
	if record.LocalDate != "2026-09-27" {
		t.Errorf("the document records local_date = %q, want %q", record.LocalDate, "2026-09-27")
	}
	// The old day's value was replaced, not added to.
	if record.UsedBytes != dailyBudgetBytes {
		t.Errorf("the document records used_bytes = %d, want %d", record.UsedBytes, dailyBudgetBytes)
	}
}

func TestBudgetUsesTheCallersLocationForTheLocalDate(t *testing.T) {
	// "Today" is the caller's local date, not a UTC date and not the date the
	// document was written in: 23:00 UTC is the 26th in UTC and the 27th eight
	// hours east, and the two must be different days for the budgets they open.
	directory := t.TempDir()
	east := mustNewPersistentBudgetIn(t, directory, dailyBudgetBytes, testLocation, testLateOnTheTwentySixth)
	mustReserve(t, east, perCandidateBytes)
	record := mustReadBudget(t, east.Path())
	if record.LocalDate != "2026-09-27" {
		t.Fatalf("in UTC+8 at 23:00 UTC on the 26th the document records local_date = %q, want %q", record.LocalDate, "2026-09-27")
	}

	west := mustNewPersistentBudgetIn(t, directory, dailyBudgetBytes, time.UTC, testLateOnTheTwentySixth)
	if used := west.Used(); used != 0 {
		t.Fatalf("the same instant in UTC sees %d bytes spent, want 0 because the recorded date is the 27th", used)
	}
	if record := mustReadBudget(t, west.Path()); record.LocalDate != "2026-09-27" {
		t.Errorf("a write in UTC recorded local_date = %q, want the caller's %q", record.LocalDate, "2026-09-27")
	}
}

func TestNewPersistentBudgetWithoutAClockChargesTodaysDate(t *testing.T) {
	// A caller that has no moment to pass gets the current one, not the zero
	// time: a budget with no date would charge every request to year one and
	// never reset.
	directory := t.TempDir()
	budget, err := NewPersistentBudget(filepath.Join(directory, DefaultBudgetName), dailyBudgetBytes, testLocation, time.Time{})
	if err != nil {
		t.Fatalf("open a budget with no clock: %v", err)
	}
	mustReserve(t, budget, 1)
	want := time.Now().In(testLocation).Format(localDateLayout)
	if record := mustReadBudget(t, budget.Path()); record.LocalDate != want {
		t.Fatalf("the document records local_date = %q, want today's date in the caller's location %q", record.LocalDate, want)
	}
}

func TestNewPersistentBudgetWritesNothingUntilItSpends(t *testing.T) {
	// Opening a budget is a read. A run that finds the budget full, or that is
	// only inspecting the state, must not leave a document behind.
	directory := t.TempDir()
	budget := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	if used := budget.Used(); used != 0 {
		t.Fatalf("Used() = %d on an untouched day, want 0", used)
	}
	if names := mustReadDirectory(t, directory); len(names) != 0 {
		t.Fatalf("opening a budget wrote %v, want nothing", names)
	}

	mustReserve(t, budget, 1)

	want := []string{DefaultBudgetName, DefaultBudgetName + BudgetLockSuffix}
	if names := mustReadDirectory(t, directory); !slices.Equal(names, want) {
		t.Fatalf("the runtime directory holds %v, want %v", names, want)
	}
}

func TestNewPersistentBudgetRefusesADocumentItCannotRead(t *testing.T) {
	// A truncated or corrupt document is not an empty one. Reading it as zero
	// would turn a damaged file into a hundred megabytes of free traffic, so it
	// is refused where it is found.
	for name, contents := range map[string]string{
		"a truncated document":             `{"schema_version": 1, "local_date": "2026-09-26", "limit_by`,
		"a document of another schema":     `{"schema_version": 2, "local_date": "2026-09-26", "limit_bytes": 1, "used_bytes": 0}`,
		"a document that is not JSON":      "used_bytes: 0\n",
		"a document with an unknown field": `{"schema_version": 1, "local_date": "2026-09-26", "limit_bytes": 1, "used_bytes": 0, "note": "free bytes"}`,
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, DefaultBudgetName)
			if err := os.WriteFile(path, []byte(contents), 0o640); err != nil {
				t.Fatalf("write the document: %v", err)
			}
			if _, err := NewPersistentBudget(path, dailyBudgetBytes, testLocation, testNoon); err == nil {
				t.Fatalf("a budget was opened on %s", name)
			}
		})
	}
}

func TestBudgetUsedSurvivesADocumentItCannotRead(t *testing.T) {
	// Used() cannot return an error, so a document that has become unreadable
	// must not be reported as an empty budget: the last total this budget
	// established is the only number it can still stand behind.
	directory := t.TempDir()
	budget := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	mustReserve(t, budget, 4*mib)

	if err := os.WriteFile(budget.Path(), []byte("{"), 0o640); err != nil {
		t.Fatalf("damage the document: %v", err)
	}

	if used := budget.Used(); used != 4*mib {
		t.Fatalf("Used() = %d after the document was damaged, want the last known %d", used, 4*mib)
	}
}

func TestTheDaysLimitOnlyTightens(t *testing.T) {
	// Two writers that disagree about the daily limit must not add up to more
	// than the day allows: the smaller limit is the day's limit for as long as
	// the day lasts, and a run cannot raise it by writing a bigger number.
	directory := t.TempDir()
	tight := mustNewPersistentBudget(t, directory, 50*mib, testNoon)
	mustReserve(t, tight, 50*mib)

	loose := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	if used := loose.Used(); used != 50*mib {
		t.Fatalf("Used() = %d, want the %d the stricter writer charged", used, 50*mib)
	}
	if _, err := loose.Reserve(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("a writer allowing 100 MiB spent from a day capped at 50 MiB: %v", err)
	}
	if record := mustReadBudget(t, loose.Path()); record.LimitBytes != 50*mib {
		t.Errorf("the document records limit_bytes = %d, want the stricter %d", record.LimitBytes, 50*mib)
	}

	// The tightening is the day's, not the budget file's: tomorrow the larger
	// limit applies again.
	tomorrow := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNextNoon)
	if reserved := mustReserve(t, tomorrow, dailyBudgetBytes); reserved != dailyBudgetBytes {
		t.Fatalf("the new day reserved %d bytes of %d, want the whole budget", reserved, dailyBudgetBytes)
	}
}

func TestBudgetChargesAHandWrittenTotalAsFullySpent(t *testing.T) {
	// A document whose total is above its own limit describes a day that has
	// already been overspent. It is reported as fully spent rather than as
	// negative room, so a hand-edited or truncated file cannot buy free traffic.
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultBudgetName)
	mustWriteBudget(t, path, state.BandwidthBudgetState{
		SchemaVersion: state.SchemaVersion,
		LocalDate:     "2026-09-26",
		LimitBytes:    dailyBudgetBytes,
		UsedBytes:     2 * dailyBudgetBytes,
	})
	budget, err := NewPersistentBudget(path, dailyBudgetBytes, testLocation, testNoon)
	if err != nil {
		t.Fatalf("open the budget on the hand-written document: %v", err)
	}

	if used := budget.Used(); used != dailyBudgetBytes {
		t.Fatalf("Used() = %d for a document claiming %d bytes of a %d limit, want the limit", used, 2*dailyBudgetBytes, dailyBudgetBytes)
	}
	if _, err := budget.Reserve(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Reserve(1) on an overspent day failed with %v, want ErrBudgetExhausted", err)
	}
}

func TestBudgetTakesOnlyItsOwnLockFile(t *testing.T) {
	// A measurement run holds this budget for minutes at a time. Taking the
	// shared control lock for that would block `apply`, `pin` and `health-check`,
	// so the budget has a lock of its own and never waits on the control lock
	// even when the control lock is held.
	directory := t.TempDir()
	control, err := filelock.Acquire(filepath.Join(directory, "control.lock"))
	if err != nil {
		t.Fatalf("take the control lock: %v", err)
	}
	defer func() { _ = control.Close() }()

	budget := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	reserved := mustReserve(t, budget, perCandidateBytes)
	budget.Consume(reserved, mib)

	want := []string{DefaultBudgetName, DefaultBudgetName + BudgetLockSuffix, "control.lock"}
	if names := mustReadDirectory(t, directory); !slices.Equal(names, want) {
		t.Fatalf("the runtime directory holds %v, want %v", names, want)
	}
	if used := budget.Used(); used != mib {
		t.Fatalf("Used() = %d, want %d", used, mib)
	}
}

func TestBudgetWaitsForTheLockItShares(t *testing.T) {
	// Two processes reserving at once must serialise, and the loser must wait
	// rather than fail: a busy router must not lose a run to a lock held for the
	// millisecond it takes to write one small document.
	directory := t.TempDir()
	budget := mustNewPersistentBudget(t, directory, dailyBudgetBytes, testNoon)
	held, err := filelock.Acquire(budget.LockPath())
	if err != nil {
		t.Fatalf("take the budget lock: %v", err)
	}

	settled := make(chan error, 1)
	go func() {
		_, reserveErr := budget.Reserve(perCandidateBytes)
		settled <- reserveErr
	}()
	select {
	case reserveErr := <-settled:
		t.Fatalf("a reservation finished while another holder had the budget lock: %v", reserveErr)
	case <-time.After(100 * time.Millisecond):
	}

	if err := held.Close(); err != nil {
		t.Fatalf("release the budget lock: %v", err)
	}
	select {
	case reserveErr := <-settled:
		if reserveErr != nil {
			t.Fatalf("a reservation after the lock was released failed: %v", reserveErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a reservation never finished after the lock was released")
	}
	if used := budget.Used(); used != perCandidateBytes {
		t.Fatalf("Used() = %d, want %d", used, perCandidateBytes)
	}
}

func TestBudgetRefusesToSpendWhileTheLockStaysHeld(t *testing.T) {
	// A lock it cannot take in time is a lock it must not write around, and a
	// budget it cannot persist is a budget that must not hand out reservations.
	// The wait is a parameter so the test does not have to sit through the
	// production one.
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultBudgetName)
	budget, err := newPersistentBudget(path, path+BudgetLockSuffix, dailyBudgetBytes, testLocation, testNoon, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("open the budget: %v", err)
	}
	held, err := filelock.Acquire(budget.LockPath())
	if err != nil {
		t.Fatalf("take the budget lock: %v", err)
	}
	defer func() { _ = held.Close() }()

	reserved, err := budget.Reserve(perCandidateBytes)
	if err == nil {
		t.Fatalf("a reservation succeeded while the budget lock was held by another process")
	}
	if errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("the refusal blamed the day's bytes rather than the lock: %v", err)
	}
	if reserved != 0 {
		t.Errorf("the refusal returned %d bytes, want 0", reserved)
	}
	if used := budget.Used(); used != 0 {
		t.Errorf("Used() = %d, want 0", used)
	}
	if names := mustReadDirectory(t, directory); !slices.Equal(names, []string{DefaultBudgetName + BudgetLockSuffix}) {
		t.Errorf("the runtime directory holds %v, want only the lock file", names)
	}
}

func TestBudgetSaysWhyItCouldNotTakeItsLock(t *testing.T) {
	// A lock file that cannot be opened at all is not a lock somebody else is
	// holding, and telling those two apart is the difference between a run that
	// reports the lock file is broken and a run that waited for its whole budget
	// of patience and then blamed a holder that was never there.
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultBudgetName)
	lockPath := path + BudgetLockSuffix
	if err := os.Mkdir(lockPath, 0o750); err != nil {
		t.Fatalf("put a directory where the lock file belongs: %v", err)
	}
	budget, err := newPersistentBudget(path, lockPath, dailyBudgetBytes, testLocation, testNoon, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("open the budget: %v", err)
	}

	reserved, err := budget.Reserve(perCandidateBytes)
	if err == nil {
		t.Fatalf("a reservation succeeded with a lock file that cannot be opened")
	}
	if errors.Is(err, errLockTimeout) {
		t.Errorf("an unusable lock file was reported as a lock held by another process: %v", err)
	}
	if !strings.Contains(err.Error(), lockPath) {
		t.Errorf("the refusal does not name the lock file: %v", err)
	}
	if reserved != 0 {
		t.Errorf("the refusal returned %d bytes, want 0", reserved)
	}
}

func TestPersistentBudgetTakesTheLockFileItWasGiven(t *testing.T) {
	// The lock path is a parameter, so a deployment can keep the lock out of the
	// directory the document is written to. What it may not do is take the
	// control lock, so the test names a lock of its own and checks that the
	// budget writes the document and takes that one.
	directory := t.TempDir()
	lockDirectory := t.TempDir()
	lockPath := filepath.Join(lockDirectory, "measurement.lock")
	budget, err := NewPersistentBudgetWithLock(filepath.Join(directory, DefaultBudgetName), lockPath, dailyBudgetBytes, testLocation, testNoon)
	if err != nil {
		t.Fatalf("open the budget with its own lock: %v", err)
	}
	mustReserve(t, budget, mib)

	if budget.LockPath() != lockPath {
		t.Errorf("LockPath() = %q, want %q", budget.LockPath(), lockPath)
	}
	if names := mustReadDirectory(t, directory); !slices.Equal(names, []string{DefaultBudgetName}) {
		t.Errorf("the document directory holds %v, want only the document", names)
	}
	if names := mustReadDirectory(t, lockDirectory); !slices.Equal(names, []string{"measurement.lock"}) {
		t.Errorf("the lock directory holds %v, want only the lock", names)
	}
}

func TestNewPersistentBudgetRefusesAnImpossibleConfiguration(t *testing.T) {
	// A budget with no path has nowhere to persist, a budget with no limit can
	// never refuse anything, and two budgets must not share one lock file: the
	// whole point of the dedicated lock is that it is dedicated.
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultBudgetName)
	for name, build := range map[string]func() (*Budget, error){
		"no path": func() (*Budget, error) {
			return NewPersistentBudget("", dailyBudgetBytes, testLocation, testNoon)
		},
		"no lock file": func() (*Budget, error) {
			return newPersistentBudget(path, "", dailyBudgetBytes, testLocation, testNoon, defaultLockWait)
		},
		"a limit of zero": func() (*Budget, error) {
			return NewPersistentBudget(path, 0, testLocation, testNoon)
		},
		"a negative limit": func() (*Budget, error) {
			return NewPersistentBudget(path, -1, testLocation, testNoon)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if budget, err := build(); err == nil {
				t.Fatalf("a budget was opened with %s, at %s", name, budget.Path())
			}
		})
	}
}

// mustNewPersistentBudget opens a budget in a fresh directory with the test's
// date rules, and fails the test if it cannot be opened.
func mustNewPersistentBudget(t *testing.T, directory string, limit int64, now time.Time) *Budget {
	t.Helper()
	return mustNewPersistentBudgetIn(t, directory, limit, testLocation, now)
}

func mustNewPersistentBudgetIn(t *testing.T, directory string, limit int64, location *time.Location, now time.Time) *Budget {
	t.Helper()
	budget, err := NewPersistentBudget(filepath.Join(directory, DefaultBudgetName), limit, location, now)
	if err != nil {
		t.Fatalf("open the budget: %v", err)
	}
	return budget
}

func mustReadBudget(t *testing.T, path string) state.BandwidthBudgetState {
	t.Helper()
	record := state.BandwidthBudgetState{}
	if err := state.ReadJSON(path, &record); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return record
}

func mustWriteBudget(t *testing.T, path string, record state.BandwidthBudgetState) {
	t.Helper()
	if err := state.WriteJSONAtomic(path, record); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustReadDirectory(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", directory, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names
}

// The child process of TestBudgetRefusesASecondProcessOnceTheDayIsFull. It
// shares nothing with its parent but the budget file, so it is the only way to
// show that the file and its lock really are the whole of the agreement between
// two spenders.
const (
	helperEnvironmentPath    = "MOSDNS_TEST_BUDGET_PATH"
	helperEnvironmentRequest = "MOSDNS_TEST_BUDGET_REQUEST"
	helperEnvironmentNow     = "MOSDNS_TEST_BUDGET_NOW"

	helperReserved = "reserved"
	helperRefused  = "refused"
)

func TestBudgetHelperProcessOnlyRunsAsASeparateProcess(t *testing.T) {
	if os.Getenv(helperEnvironmentPath) == "" {
		t.Skip("this test is the body of a separate process; see runBudgetHelperProcess")
	}
	requested, err := strconv.ParseInt(os.Getenv(helperEnvironmentRequest), 10, 64)
	if err != nil {
		t.Fatalf("the requested size %q is not a byte count: %v", os.Getenv(helperEnvironmentRequest), err)
	}
	moment, err := time.Parse(time.RFC3339, os.Getenv(helperEnvironmentNow))
	if err != nil {
		t.Fatalf("the moment %q is not a timestamp: %v", os.Getenv(helperEnvironmentNow), err)
	}
	budget, err := NewPersistentBudget(os.Getenv(helperEnvironmentPath), dailyBudgetBytes, testLocation, moment)
	if err != nil {
		t.Fatalf("open the budget: %v", err)
	}
	if _, err := budget.Reserve(requested); err != nil {
		if errors.Is(err, ErrBudgetExhausted) {
			os.Exit(3)
		}
		t.Fatalf("reserve %d bytes: %v", requested, err)
	}
	os.Exit(0)
}

// runBudgetHelperProcess starts a second process that reserves requested bytes
// from the budget at path, and reports what happened to it. The outcome is the
// process exit status, because stdout also carries the test harness's own
// output.
func runBudgetHelperProcess(t *testing.T, path string, now time.Time, requested int64) string {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestBudgetHelperProcessOnlyRunsAsASeparateProcess$", "-test.v")
	command.Env = append(os.Environ(),
		helperEnvironmentPath+"="+path,
		helperEnvironmentRequest+"="+strconv.FormatInt(requested, 10),
		helperEnvironmentNow+"="+now.Format(time.RFC3339),
	)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return helperReserved
	case errors.As(err, &exit) && exit.ExitCode() == 3:
		return helperRefused
	default:
		t.Fatalf("the second process neither reserved nor refused: %v\n%s", err, output)
		return ""
	}
}
