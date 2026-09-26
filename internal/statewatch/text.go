package statewatch

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
)

// The file this file watches is a list of domain names, one per line, written by
// an operator and not by a program. Everything here follows from that: the file
// carries prose, so a comment and a blank line are not entries; the same name is
// often written twice, so it is one entry; a name is matched against a query
// that may be capitalised, so it is stored in lower case; and the operator will
// eventually make a mistake in it, so a mistake is a refusal of the whole file
// rather than a line nobody notices.
//
// The whole-file refusal is the part that matters most, and it is deliberate. A
// list that skipped what it could not parse would leave the operator with a
// list they did not write, holding domains they have removed, and they would
// have no way to see it. A list that refuses the whole file keeps the last one
// it could read and says which line stopped it. Losing strict ECH silently is a
// censorship-resistance regression; a loud refusal that keeps the last good list
// is an operator's problem for ten seconds.
const (
	// maximumDomainLength and maximumDomainLabelLength are the limits a DNS name
	// has to live within: 253 characters for the name as written and 63 for one
	// label. The state package holds the same rule for the hostnames it
	// validates, unexported, and a name that would not pass there is not one
	// this list should accept either.
	maximumDomainLength      = 253
	maximumDomainLabelLength = 63
	// minimumDomainLabels is stricter than a DNS name strictly has to be. A name
	// with one label is what a truncated paste, a stray word in prose or a
	// missing suffix looks like, and nothing a browser queries can ever be one,
	// so accepting it would add an entry that silently matches nothing.
	minimumDomainLabels = 2
	// commentPrefix introduces a line that is prose rather than an entry. It
	// counts at the start of a trimmed line, so an operator can indent their
	// comments to match their list, and a # anywhere else makes the line a
	// malformed entry rather than a comment -- a list that guessed which lines
	// were annotated would be guessing about a censorship-resistance setting.
	commentPrefix = "#"
)

// LineError is a refusal naming the line that caused it. It is a value rather
// than a pointer so that a caller holding one cannot edit what the watcher
// recorded, and its fields are exported so a caller can point at the line
// itself rather than at a message: in a file of thousands of names, "line 4 of
// /etc/mosdns/force-ech-domains.txt" is what the operator needs.
type LineError struct {
	// Path is the file the line is in.
	Path string
	// Line is the one-based number of the line in the file, counting the
	// comments and blank lines, so it is the number an editor shows.
	Line int
	// Text is the line as it was read, with the surrounding whitespace removed.
	Text string
	// Reason is what is wrong with it.
	Reason string
}

func (e LineError) Error() string {
	return fmt.Sprintf("%s: line %d: %q is not a domain: %s", e.Path, e.Line, e.Text, e.Reason)
}

// TextWatcher is the last valid list of domain names read from one file, kept
// current by a background poll. It is safe for concurrent use.
type TextWatcher struct {
	poller

	mu      sync.RWMutex
	entries []string
}

// NewTrimmedLines returns a watcher for the list of domain names at path.
//
// The file is read whole and validated whole: comments and blank lines are
// dropped, every remaining name is trimmed and lowercased, duplicates are
// removed keeping the first occurrence, and a line that is not a domain refuses
// the entire file with a LineError naming it. A refusal of any kind leaves the
// last valid list in place, including the list the caller passed as initial,
// which is copied so a caller that keeps using its own slice does not find it
// edited.
func NewTrimmedLines(path string, initial []string, options ...Options) (*TextWatcher, error) {
	settings, err := oneOptions(path, options)
	if err != nil {
		return nil, err
	}
	watcher := &TextWatcher{entries: slices.Clone(initial)}
	if err := watcher.poller.init(path, settings); err != nil {
		return nil, err
	}
	watcher.poller.reload = watcher.reload
	watcher.poller.start()
	return watcher, nil
}

// Snapshot returns the last valid list, as a slice the caller owns: a name in
// it can be written to without reaching the watcher's own list. It keeps
// answering after Close, and a list the operator emptied is an empty list, not
// no list at all.
func (w *TextWatcher) Snapshot() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return slices.Clone(w.entries)
}

// ReloadNow reads the file, validates it whole, and stores it if it is valid. It
// returns the refusal rather than reporting it, and a refusal leaves the last
// valid list in place.
//
// Close does not prevent it: closing stops the background poll, and a caller's
// own read of the file it is holding is still the caller's to make.
func (w *TextWatcher) ReloadNow() error {
	return w.reload()
}

// Close stops the background poll and waits for it to finish. It is idempotent
// and safe from several goroutines, and it leaves the list in place.
func (w *TextWatcher) Close() error { return w.stopPolling() }

func (w *TextWatcher) reload() error {
	entries, err := readDomainList(w.path)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = entries
	return nil
}

// readDomainList reads and validates the whole file. The read is the file as
// the path names it: there is no stat first, so a file replaced between a
// check and a read is not a case this code has to get right.
func readDomainList(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: read domain list: %w", path, err)
	}
	return parseDomainList(path, string(content))
}

// parseDomainList turns the file's text into the list, or refuses it. A file
// with no entries in it is a file the operator emptied and is not a failure, so
// it parses to an empty list rather than to no list at all.
func parseDomainList(path, content string) ([]string, error) {
	lines := strings.Split(content, "\n")
	entries := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for index, raw := range lines {
		text := strings.TrimSpace(raw)
		if text == "" || strings.HasPrefix(text, commentPrefix) {
			continue
		}
		domain := strings.ToLower(text)
		if reason := domainRefusal(domain); reason != "" {
			return nil, LineError{
				Path:   path,
				Line:   index + 1,
				Text:   text,
				Reason: reason,
			}
		}
		if _, duplicate := seen[domain]; duplicate {
			continue
		}
		seen[domain] = struct{}{}
		entries = append(entries, domain)
	}
	return entries, nil
}

// domainRefusal returns why value is not a domain name the router can force ECH
// for, and the empty string when it is one. It is one function rather than a
// predicate beside a diagnostic, because a second place to describe the same
// rule is a second place for the two to disagree about what a name is.
//
// A DNS name and nothing else is accepted: a URL, a wildcard, an address, a
// single word, a name with a space in it and a name longer than the DNS allows
// are all refusals. The checks run in the order the reasons are listed, so the
// reason reported is the first rule the name broke.
func domainRefusal(value string) string {
	if value == "" {
		return "a line has no name on it"
	}
	if len(value) > maximumDomainLength {
		return fmt.Sprintf("a domain name is at most %d characters", maximumDomainLength)
	}
	if strings.HasSuffix(value, ".") {
		return "a domain name must not carry a trailing dot"
	}
	if strings.Contains(value, "://") {
		return "a domain name is a name, not a URL"
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "a domain name must not be an IP address"
	}
	labels := strings.Split(value, ".")
	if len(labels) < minimumDomainLabels {
		return fmt.Sprintf("a domain name has at least %d dot-separated labels, so a bare word is not one", minimumDomainLabels)
	}
	for _, label := range labels {
		if reason := domainLabelRefusal(label); reason != "" {
			return reason
		}
	}
	return ""
}

// domainLabelRefusal returns why one label of a name is not a label, and the
// empty string when it is one. Letters, digits and interior dashes are the whole
// of it: a dash at either end is a name that cannot be encoded, and anything
// else -- an underscore, a wildcard, a space, a character outside ASCII -- is not
// a character a hostname may hold.
func domainLabelRefusal(label string) string {
	switch {
	case label == "":
		return "a domain name has no empty label"
	case len(label) > maximumDomainLabelLength:
		return fmt.Sprintf("a label is at most %d characters", maximumDomainLabelLength)
	case strings.HasPrefix(label, "-"), strings.HasSuffix(label, "-"):
		return "a label does not start or end with a dash"
	}
	for index := 0; index < len(label); index++ {
		character := label[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if character == '-' && index > 0 && index < len(label)-1 {
			continue
		}
		return "a label holds only letters, digits and interior dashes"
	}
	return ""
}
