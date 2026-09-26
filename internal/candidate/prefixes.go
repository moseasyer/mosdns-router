package candidate

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
)

// DefaultCloudflarePrefixFileName is the plain prefix list this package publishes
// beside the document it cached, and it is what the response rewriter's
// cloudflare_cidr_file names.
//
// The list exists because the cached envelope cannot serve as one. What a run
// caches is the API's own JSON under a schema, a URL and a validator, so a reader
// pointed at that file has to parse a document whose shape is this package's cache
// rather than a range list, and the ranges inside it are quoted strings in a
// nested object rather than lines. The response rewriter needs the opposite: a
// file it can read a prefix per line out of, with no knowledge of the API and none
// of this package's cache format. So the same fetch that caches the envelope also
// publishes the parsed list next to it -- one request, two artifacts -- and the
// two cannot disagree because there is only one document they both come from.
const DefaultCloudflarePrefixFileName = "cloudflare-prefixes.txt"

// publishPrefixList writes the document's IPv4 ranges beside the cache envelope, in
// the form the rewriter reads: one prefix per line, masked, deduplicated, and in
// ascending order so two days of the file can be diffed by a person.
//
// Every prefix goes through the same parse the sample uses, so a range this
// package would not sample from is a range this package will not publish: the two
// lists then describe the same published space, which is the property a
// classification depends on. A range the document lists more than once is written
// once.
//
// The write is a temporary file in the same directory and a rename, with the same
// mode discipline the cache uses, because this file is replaced while a router is
// reading it and a reader must never see half of it. A stale document publishes
// too: it is the last document this build accepted, so its ranges are the ones a
// classification should be made against, and refusing to publish them would leave
// the rewriter with whatever it had before, which may be nothing at all.
func publishPrefixList(cachePath string, document cloudflareRanges) error {
	prefixes := make([]netip.Prefix, 0, len(document.Result.IPv4CIDRs))
	seen := make(map[netip.Prefix]struct{}, len(document.Result.IPv4CIDRs))
	for index, cidr := range document.Result.IPv4CIDRs {
		prefix, err := parseIPv4Prefix(cidr)
		if err != nil {
			return fmt.Errorf("ipv4_cidrs[%d]: %w", index, err)
		}
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	// Sorted so the file is a document a person can read: a rewriter's only use of
	// it is a membership test, but an operator comparing two days of it is a real
	// use, and an unstable order would make every diff noise.
	slices.SortFunc(prefixes, comparePrefixes)

	contents := make([]byte, 0, len(prefixes)*16)
	for _, prefix := range prefixes {
		contents = append(contents, prefix.String()...)
		contents = append(contents, '\n')
	}
	return writeTextFile(prefixPathFor(cachePath), contents)
}

// prefixPathFor is where the parsed list lives for a given cache path, which is
// beside it: the two are published by one fetch, read by two different processes,
// and a directory an operator can look at is worth more than one this package
// would have to be told about twice.
func prefixPathFor(cachePath string) string {
	return filepath.Join(filepath.Dir(cachePath), DefaultCloudflarePrefixFileName)
}

// comparePrefixes orders prefixes by network address and then by length, so a
// shorter and a longer prefix of the same network have a defined order rather than
// whichever the map produced.
func comparePrefixes(first, second netip.Prefix) int {
	if result := first.Addr().Compare(second.Addr()); result != 0 {
		return result
	}
	return first.Bits() - second.Bits()
}

// writeTextFile publishes one file through a same-directory temporary and a
// rename, with the same mode the cache uses: the prefix list is published
// reference data read by an unprivileged process in another service, not router
// state.
func writeTextFile(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("%s: create %s: %w", path, directory, err)
	}
	handle, err := os.CreateTemp(directory, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("%s: create a temporary file in %s: %w", path, directory, err)
	}
	temporary := handle.Name()
	if _, err := handle.Write(contents); err != nil {
		_ = handle.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("%s: write %s: %w", path, temporary, err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		_ = os.Remove(temporary)
		return fmt.Errorf("%s: sync %s: %w", path, temporary, err)
	}
	if err := handle.Close(); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("%s: close %s: %w", path, temporary, err)
	}
	if err := os.Chmod(temporary, 0o644); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("%s: set the mode of %s: %w", path, temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("%s: replace the prefix list: %w", path, err)
	}
	return nil
}
