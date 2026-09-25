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

// A release build is only attributable when all three fields were injected, so
// the compiled-in placeholders and any empty or multi-line value must be
// refused.
func TestCheckRejectsPlaceholderAndMalformedMetadata(t *testing.T) {
	valid := Info{Version: "0.1.0", Revision: "1c3a9b0d2f4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b", BuildTime: "2026-09-25T21:15:00Z"}
	if err := Check(valid); err != nil {
		t.Fatalf("complete build info rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Info)
	}{
		{name: "placeholder version", mutate: func(i *Info) { i.Version = placeholderVersion }},
		{name: "placeholder revision", mutate: func(i *Info) { i.Revision = placeholderRevision }},
		{name: "placeholder build time", mutate: func(i *Info) { i.BuildTime = placeholderBuildTime }},
		{name: "empty version", mutate: func(i *Info) { i.Version = "" }},
		{name: "empty revision", mutate: func(i *Info) { i.Revision = "" }},
		{name: "empty build time", mutate: func(i *Info) { i.BuildTime = "" }},
		{name: "version with a space", mutate: func(i *Info) { i.Version = "0.1.0 candidate" }},
		{name: "revision with a newline", mutate: func(i *Info) { i.Revision = "abc\ndef" }},
		{name: "build time with a control character", mutate: func(i *Info) { i.BuildTime = "2026-09-25T21:15:00Z\x07" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := valid
			tt.mutate(&info)
			if err := Check(info); err == nil {
				t.Fatalf("expected check error for %#v", info)
			}
		})
	}
}

// The compiled-in defaults are what an uninjected build reports, so the check
// has to reject the real Snapshot of an untouched package.
func TestCheckRejectsSnapshotWithoutLinkerInjection(t *testing.T) {
	oldVersion, oldRevision, oldBuildTime := Version, Revision, BuildTime
	t.Cleanup(func() { Version, Revision, BuildTime = oldVersion, oldRevision, oldBuildTime })
	Version, Revision, BuildTime = "dev", "unknown", "unknown"

	if err := Check(Snapshot()); err == nil {
		t.Fatal("expected check error for the compiled-in placeholders")
	}
}
