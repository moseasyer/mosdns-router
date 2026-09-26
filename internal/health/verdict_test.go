package health

import (
	"testing"
	"time"

	"mosdns-router/internal/state"
)

// This is the one in-package test file in this package, and it is here for one
// function: applyVerdict is the counter, and one of its four verdicts - the one that
// learned nothing - has no path to it from Check, which returns before the counter is
// applied whenever a check learned nothing. That is the right shape for the caller and
// the wrong shape for a defensive branch: the branch exists so that a future edit to
// Check cannot republish a healthy claim the check never made, and a branch nothing
// reaches is a branch nothing tests. Reaching it directly is the only way to hold it.

// A verdict of "we do not know" is not a verdict, and the one thing it must not do is
// leave a healthy claim standing: the healthy flag belongs to a completed proof, and
// this check completed none.
func TestApplyVerdictOfAnUnknownVerdictClaimsNothing(t *testing.T) {
	moment := time.Date(2026, 9, 26, 4, 0, 0, 0, time.UTC)
	proved := moment.Add(-time.Minute)
	previous := state.HealthState{
		SchemaVersion: state.SchemaVersion,
		Healthy:       true,
		LastSuccess:   proved,
	}

	updated := applyVerdict(previous, VerdictUnknown, moment, 3, proved.Add(-time.Hour), "")

	if updated.Healthy {
		t.Errorf("an unknown verdict republished a healthy claim: %+v", updated)
	}
	if updated.ConsecutiveFailures != 0 {
		t.Errorf("consecutive failures = %d, want 0: an unknown verdict is not a failure", updated.ConsecutiveFailures)
	}
	if !updated.LastSuccess.Equal(proved) {
		t.Errorf("last success = %s, want the earlier proof's own %s", updated.LastSuccess, proved)
	}
	if updated.SchemaVersion != state.SchemaVersion {
		t.Errorf("schema version = %d, want %d", updated.SchemaVersion, state.SchemaVersion)
	}
	if err := updated.Validate(); err != nil {
		t.Errorf("the updated document is not one the state package accepts: %v", err)
	}
}
