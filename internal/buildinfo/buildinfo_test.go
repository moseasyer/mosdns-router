package buildinfo

import "testing"

func TestSnapshotUsesLinkerValues(t *testing.T) {
	oldVersion, oldRevision, oldBuildTime := Version, Revision, BuildTime
	t.Cleanup(func() { Version, Revision, BuildTime = oldVersion, oldRevision, oldBuildTime })
	Version, Revision, BuildTime = "test-version", "test-revision", "2026-09-25T00:00:00Z"

	got := Snapshot()
	if got.Version != "test-version" || got.Revision != "test-revision" || got.BuildTime != "2026-09-25T00:00:00Z" {
		t.Fatalf("unexpected build info: %#v", got)
	}
}
