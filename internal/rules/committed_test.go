package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	mosdnsdomain "github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

// configs/source-lock.json and configs/cn-domains.txt are the output of one
// `mosdns-cdnctl update-lists --pin-remote HEAD` run against the reviewed
// upstream commit the lock records. They are committed so the repository is
// reviewable and so an installation ships a list whose source is known without
// any network access, and the tests below are what hold the committed pair to the
// promise the lock makes. No test here reads the network: it checks the committed
// bytes against the lock, and the lock against the shape this build understands.

const (
	committedLockPath = "../../configs/source-lock.json"
	committedListPath = "../../configs/cn-domains.txt"

	// chinaDomain and foreignDomain are the routing outcome the committed list
	// has to produce: a well-known China domain has to match, and a well-known
	// foreign domain has not to. Both are stated literally so a converter that
	// published something unusable could not satisfy the test with its own
	// output.
	chinaDomain   = "baidu.com"
	foreignDomain = "www.google.com"
)

func TestCommittedSourceLockIsAFullyPinnedReviewedSource(t *testing.T) {
	// The lock is the record of what was reviewed. A lock that is incomplete, or
	// that names a repository, an entry or a shape this build does not
	// understand, would leave an installation claiming a pin it cannot verify.
	lockBytes, err := os.ReadFile(committedLockPath)
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", committedLockPath, err)
	}
	lock, err := ParseSourceLock(lockBytes)
	if err != nil {
		t.Fatalf("parse the committed source lock: %v", err)
	}
	if err := lock.Validate(); err != nil {
		t.Fatalf("the committed source lock is not a complete pin: %v", err)
	}
	if lock.Repository != Repository {
		t.Errorf("committed repository = %q, want %q", lock.Repository, Repository)
	}
	if lock.Entry != Entry {
		t.Errorf("committed entry = %q, want %q", lock.Entry, Entry)
	}
	if lock.Commit == strings.Repeat("0", 40) {
		t.Error("the committed commit is all zeroes, which is not a reviewed commit")
	}
}

func TestCommittedListIsExactlyWhatTheCommittedLockDescribes(t *testing.T) {
	// The digest in the lock is only worth anything if it is checked against the
	// committed bytes: an edited list beside an untouched lock would otherwise
	// read as a reviewed source.
	lock, err := ParseSourceLock(mustReadCommitted(t, committedLockPath))
	if err != nil {
		t.Fatal(err)
	}
	list := mustReadCommitted(t, committedListPath)
	if actual := digestHex(list); actual != lock.ListSHA256 {
		t.Fatalf("committed list sha256 = %s, the lock records %s", actual, lock.ListSHA256)
	}
}

func TestCommittedListIsSortedDeduplicatedAndReadableByMOSDNS(t *testing.T) {
	// The list is read by MOSDNS v5.3.4, so it is checked there: a duplicate, an
	// out-of-order line, an expression the loader would refuse, or a China domain
	// the loader would not match all fail here rather than at the router's first
	// query.
	list := mustReadCommitted(t, committedListPath)
	if len(list) == 0 {
		t.Fatal("the committed list is empty, so nothing would route to the domestic branch")
	}
	text := strings.TrimSuffix(string(list), "\n")
	lines := strings.Split(text, "\n")
	forms := make(map[string]int)
	for number, line := range lines {
		if err := validateRenderedRule(line); err != nil {
			t.Fatalf("committed list line %d is not a MOSDNS expression: %v", number+1, err)
		}
		forms[strings.SplitN(line, ":", 2)[0]]++
	}
	if !sort.StringsAreSorted(lines) {
		t.Errorf("the committed list is not sorted:\nfirst out of order: %s", firstUnsorted(lines))
	}
	if duplicate := firstDuplicate(lines); duplicate != "" {
		t.Errorf("the committed list repeats %q", duplicate)
	}
	for _, form := range []string{"domain", "full", "regexp"} {
		if forms[form] == 0 {
			t.Errorf("the committed list carries no %s: rule, which the pinned data does", form)
		}
	}

	matcher := mosdnsdomain.NewDomainMixMatcher()
	if err := mosdnsdomain.LoadFromTextReader(matcher, strings.NewReader(text+"\n"), nil); err != nil {
		t.Fatalf("MOSDNS refused the committed list of %d rules: %v", len(lines), err)
	}
	if matcher.Len() == 0 {
		t.Fatal("MOSDNS loaded no rule from the committed list")
	}
	if _, ok := matcher.Match(chinaDomain); !ok {
		t.Errorf("the committed list does not match the China domain %q", chinaDomain)
	}
	if _, ok := matcher.Match(foreignDomain); ok {
		t.Errorf("the committed list matches the foreign domain %q", foreignDomain)
	}
}

func mustReadCommitted(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("cannot read the committed %s: %v", path, err)
	}
	return contents
}

func firstUnsorted(lines []string) string {
	for i := 1; i < len(lines); i++ {
		if lines[i-1] > lines[i] {
			return lines[i-1] + " then " + lines[i]
		}
	}
	return ""
}

func firstDuplicate(lines []string) string {
	for i := 1; i < len(lines); i++ {
		if lines[i-1] == lines[i] {
			return lines[i]
		}
	}
	return ""
}
