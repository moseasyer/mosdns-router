package buildinfo

import (
	"fmt"
	"strings"
)

// placeholderVersion, placeholderRevision, and placeholderBuildTime are the
// compiled-in defaults. A binary that still reports them was built without the
// linker's metadata, so it cannot be attributed to a source revision.
const (
	placeholderVersion   = "dev"
	placeholderRevision  = "unknown"
	placeholderBuildTime = "unknown"
)

// Check reports why a build-info record cannot identify a build, so a release
// build can never ship with the compiled-in placeholders. An empty field, a
// placeholder, or any embedded whitespace or control character is rejected.
func Check(info Info) error {
	fields := []struct {
		name        string
		value       string
		placeholder string
	}{
		{name: "version", value: info.Version, placeholder: placeholderVersion},
		{name: "revision", value: info.Revision, placeholder: placeholderRevision},
		{name: "build_time", value: info.BuildTime, placeholder: placeholderBuildTime},
	}
	for _, current := range fields {
		if current.value == "" {
			return fmt.Errorf("%s is empty", current.name)
		}
		if current.value == current.placeholder {
			return fmt.Errorf("%s is the placeholder %q; build with the Make metadata injection", current.name, current.placeholder)
		}
		if strings.ContainsFunc(current.value, isControl) {
			return fmt.Errorf("%s contains a control or whitespace character", current.name)
		}
	}
	return nil
}

func isControl(character rune) bool {
	return character <= ' ' || character == 0x7f
}
