// Package rules converts the pinned upstream China domain list into MOSDNS
// domain expressions, and pins the upstream source those expressions came from.
//
// The upstream format is the one v2fly/domain-list-community documents and
// implements in its own generator: an inline `#` comment may begin anywhere,
// a rule is either a bare domain (equivalent to `domain:`) or one of
// `domain:`, `full:`, `keyword:` and `regexp:`, a domain rule may carry any
// number of `@attribute` tokens and any number of `&affiliation` tokens, and
// `include:name` may carry `@attribute` (required) and `@-attribute` (forbidden)
// filters that are applied conjunctively to the included list's fully resolved
// rules.
//
// Nothing here guesses. A directive the pinned grammar does not define, a
// malformed attribute, a missing or cyclic inclusion, a domain that could never
// match a query, a regular expression the Go regexp package refuses, and an
// expression MOSDNS would misread are all conversion failures: the caller keeps
// its last known good list instead of publishing a China set with a hole in it.
package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	// maxIncludeDepth bounds how many inclusions one chain of lists may
	// traverse. The pinned entry resolves five levels deep; the bound is a
	// reviewed envelope, not a description of the current data.
	maxIncludeDepth = 32

	// maxVisitedFiles bounds the unique list files a single conversion opens, so
	// a hostile archive cannot make the converter do unbounded work.
	maxVisitedFiles = 2048

	// maxDomainLen and maxLabelLen are the limits the upstream generator applies
	// before it accepts a domain.
	maxDomainLen = 253
	maxLabelLen  = 63

	// notCNAttribute is the attribute upstream casts out of the cn lists: it
	// marks a domain that originates outside China mainland.
	notCNAttribute = "!cn"
)

// supportedRuleKinds are the domain rule types this converter can express as a
// MOSDNS domain_set expression. Any other type is a conversion failure.
var supportedRuleKinds = map[string]bool{
	"domain":  true,
	"full":    true,
	"keyword": true,
	"regexp":  true,
}

// rule is one resolved upstream domain rule, carrying the attribute set its
// inclusions were filtered with.
type rule struct {
	kind  string
	value string
	attrs []string
}

// key identifies a rule by its type, value and complete attribute set. Two
// rules that differ only by attribute are separate keys, because that is what
// `include:x @ads` selects between; two rules with the same key are the same
// rule however many files state it.
func (r rule) key() string {
	return r.kind + "\x00" + r.value + "\x00" + strings.Join(r.attrs, "\x00")
}

// hasAttribute reports whether the rule carries the named attribute.
func (r rule) hasAttribute(name string) bool {
	return slices.Contains(r.attrs, name)
}

// expression renders the rule as the MOSDNS domain_set expression that carries
// its type. Attributes are not rendered: MOSDNS has no attribute concept, and
// they have already done their work in resolution.
func (r rule) expression() string {
	return r.kind + ":" + r.value
}

// inclusion is one `include:` line: the target list, the attributes a child
// rule must have (must) and must not have (ban), and the line that asked for it.
type inclusion struct {
	target string
	must   []string
	ban    []string
	line   int
}

// resolver converts one entry list and everything it reaches.
type resolver struct {
	fsys     fs.FS
	visited  map[string]bool
	resolved map[string]map[string]rule
	active   map[string]bool
	stack    []string
}

// ConvertFS converts the list at entry in fsys into sorted, deduplicated
// MOSDNS domain expressions.
//
// The entry is a path inside the filesystem (the pinned archive after its
// single top-level directory has been stripped), inclusions resolve relative to
// the directory of the list that states them, and every resolved rule marked
// `@!cn` is cast out, matching the upstream notice about the cn lists. An entry
// that resolves to no rule is an error rather than an empty result, because an
// empty China set would silently send every query to the foreign branch.
func ConvertFS(fsys fs.FS, entry string) ([]string, error) {
	if !fs.ValidPath(entry) {
		return nil, fmt.Errorf("entry %q is not a path inside the source archive", entry)
	}
	if fsys == nil {
		return nil, errors.New("a source filesystem is required")
	}

	r := &resolver{
		fsys:     fsys,
		visited:  make(map[string]bool),
		resolved: make(map[string]map[string]rule),
		active:   make(map[string]bool),
	}
	rules, err := r.resolve(entry, 0)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(rules))
	expressions := make([]string, 0, len(rules))
	for _, current := range rules {
		if current.hasAttribute(notCNAttribute) {
			continue
		}
		expression := current.expression()
		// Two rules that differ only by attribute collapse onto one MOSDNS
		// expression, so uniqueness is decided on the rendered form.
		if seen[expression] {
			continue
		}
		if err := validateRenderedRule(expression); err != nil {
			return nil, fmt.Errorf("%s: %w", entry, err)
		}
		seen[expression] = true
		expressions = append(expressions, expression)
	}
	if len(expressions) == 0 {
		return nil, fmt.Errorf("%s: entry resolved to no rules", entry)
	}
	sort.Strings(expressions)
	return expressions, nil
}

// resolve returns the complete rule set of one list: its own rules plus, for
// every inclusion, the included list's resolved rules that pass the inclusion's
// attribute filters.
func (r *resolver) resolve(name string, depth int) (map[string]rule, error) {
	if depth > maxIncludeDepth {
		return nil, fmt.Errorf("%s: include depth exceeds the bound of %d", name, maxIncludeDepth)
	}
	if cached, ok := r.resolved[name]; ok {
		return cached, nil
	}

	r.visited[name] = true
	if len(r.visited) > maxVisitedFiles {
		return nil, fmt.Errorf("%s: more than %d unique list files are reachable", name, maxVisitedFiles)
	}
	r.active[name] = true
	defer delete(r.active, name)

	contents, err := fs.ReadFile(r.fsys, name)
	if err != nil {
		return nil, fmt.Errorf("%s: read list: %w", name, err)
	}

	resolved := make(map[string]rule)
	var inclusions []inclusion
	for index, line := range strings.Split(string(contents), "\n") {
		number := index + 1
		// A comment may begin anywhere in a line, so the line is truncated
		// before anything else is parsed.
		text, _, _ := strings.Cut(line, "#")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		kind, rest, typed := strings.Cut(text, ":")
		if !typed {
			// A rule without a type is a subdomain rule.
			kind, rest = "domain", text
		} else {
			kind = strings.ToLower(kind)
		}
		if kind == "include" {
			parsed, err := parseInclusion(rest)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, number, err)
			}
			parsed.line = number
			inclusions = append(inclusions, parsed)
			continue
		}
		if !supportedRuleKinds[kind] {
			return nil, fmt.Errorf("%s:%d: unsupported rule type %q", name, number, kind)
		}
		parsed, err := parseRule(kind, rest)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, number, err)
		}
		resolved[parsed.key()] = parsed
	}

	for _, include := range inclusions {
		target := path.Join(path.Dir(name), include.target)
		r.stack = append(r.stack, fmt.Sprintf("%s:%d", name, include.line))
		included, err := r.resolveIncluded(name, target, include, depth)
		r.stack = r.stack[:len(r.stack)-1]
		if err != nil {
			return nil, err
		}
		for _, child := range included {
			if matchesAttributeFilters(child, include) {
				resolved[child.key()] = child
			}
		}
	}

	r.resolved[name] = resolved
	return resolved, nil
}

// resolveIncluded resolves one inclusion with the include site already pushed
// onto the visiting stack, so a cycle, a missing list and any other failure name
// the line that asked for it.
func (r *resolver) resolveIncluded(from, target string, include inclusion, depth int) (map[string]rule, error) {
	if r.active[target] {
		return nil, fmt.Errorf("%s:%d: include cycle at %q: %s", from, include.line, include.target, strings.Join(r.stack, " -> "))
	}
	if _, err := fs.Stat(r.fsys, target); err != nil {
		return nil, fmt.Errorf("%s:%d: missing include %q: %w", from, include.line, include.target, err)
	}
	included, err := r.resolve(target, depth+1)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %w", from, include.line, err)
	}
	return included, nil
}

// matchesAttributeFilters reports whether a child rule satisfies an inclusion's
// conjunctive attribute filters. A rule with no attributes passes only an
// inclusion that demands none.
func matchesAttributeFilters(child rule, include inclusion) bool {
	for _, want := range include.must {
		if !child.hasAttribute(want) {
			return false
		}
	}
	for _, forbidden := range include.ban {
		if child.hasAttribute(forbidden) {
			return false
		}
	}
	return true
}

// parseRule parses the part of a domain rule that follows its type.
func parseRule(kind, rest string) (rule, error) {
	parsed := rule{kind: kind}
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return parsed, errors.New("empty domain rule")
	}
	switch kind {
	case "regexp":
		// The pattern is used verbatim; upstream does not fold its case either.
		expression, err := regexp.Compile(parts[0])
		if err != nil {
			return parsed, fmt.Errorf("invalid regexp %q: %w", parts[0], err)
		}
		parsed.value = expression.String()
	case "keyword":
		// A keyword is a substring of a domain name, so it is folded like every
		// other value and then checked for what MOSDNS can hold in one section.
		parsed.value = strings.ToLower(parts[0])
		if !validKeyword(parsed.value) {
			return parsed, fmt.Errorf("invalid keyword %q", parts[0])
		}
	default:
		parsed.value = strings.ToLower(parts[0])
		if !validDomainName(parsed.value) {
			return parsed, fmt.Errorf("invalid domain %q", parts[0])
		}
	}

	for _, part := range parts[1:] {
		switch part[0] {
		case '@':
			attribute := strings.ToLower(part[1:])
			if !validAttributeName(attribute) {
				return parsed, fmt.Errorf("invalid attribute %q", attribute)
			}
			parsed.attrs = append(parsed.attrs, attribute)
		case '&':
			// An affiliation adds the rule to another list; it never changes the
			// list that states it, and this converter publishes one list, so the
			// name is validated and then dropped.
			affiliation := strings.ToUpper(part[1:])
			if !validSiteName(affiliation) {
				return parsed, fmt.Errorf("invalid affiliation %q", part[1:])
			}
		default:
			return parsed, fmt.Errorf("unknown field %q", part)
		}
	}
	sort.Strings(parsed.attrs)
	parsed.attrs = slices.Compact(parsed.attrs)
	return parsed, nil
}

// parseInclusion parses the part of an `include:` line that follows the type.
// The include name charset accepts no dot and no slash, so an inclusion can
// neither traverse out of the archive root nor name an absolute path; a name
// outside that charset is refused instead of guessed at.
func parseInclusion(rest string) (inclusion, error) {
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return inclusion{}, errors.New("empty inclusion")
	}
	parsed := inclusion{target: parts[0]}
	if !validSiteName(parsed.target) {
		return parsed, fmt.Errorf("invalid list name %q", parsed.target)
	}
	for _, part := range parts[1:] {
		switch part[0] {
		case '@':
			attribute := strings.ToLower(part[1:])
			if forbidden, banned := strings.CutPrefix(attribute, "-"); banned {
				if !validAttributeName(forbidden) {
					return parsed, fmt.Errorf("invalid attribute %q", forbidden)
				}
				parsed.ban = append(parsed.ban, forbidden)
				continue
			}
			if !validAttributeName(attribute) {
				return parsed, fmt.Errorf("invalid attribute %q", attribute)
			}
			parsed.must = append(parsed.must, attribute)
		case '&':
			return parsed, errors.New("affiliation is not allowed on an inclusion")
		default:
			return parsed, fmt.Errorf("unknown field %q", part)
		}
	}
	return parsed, nil
}

// validDomainName accepts a domain name in the ASCII form the pinned data uses
// (IDN top-level domains appear as their `xn--` labels), applying the label
// rules the upstream generator applies before a rule is ever built.
func validDomainName(name string) bool {
	if name == "" || len(name) > maxDomainLen {
		return false
	}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			continue
		}
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// validKeyword accepts a keyword rule's value. Unlike a domain name, a keyword
// is a substring of a name rather than a name, so it is only required to be one
// space-free, control-free section that fits in a domain name's length.
func validKeyword(value string) bool {
	if value == "" || len(value) > maxDomainLen {
		return false
	}
	for _, c := range value {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// validAttributeName accepts the attribute charset upstream accepts, after
// folding the name to lower case.
func validAttributeName(attribute string) bool {
	if attribute == "" {
		return false
	}
	for _, c := range attribute {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '!' {
			continue
		}
		return false
	}
	return true
}

// validSiteName accepts the list-name charset upstream accepts: the letters and
// digits of a list name plus `!` and `-`. It contains no dot and no slash, which
// is what keeps an inclusion inside the archive.
func validSiteName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '!' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// validateRenderedRule checks an expression against the way MOSDNS v5.3.4 reads
// a domain_set file: the line is truncated at the first `#`, the remainder must
// be a single section with no whitespace, and the part before the first `:` must
// be a type the gateway is allowed to publish. An expression MOSDNS would read
// as a different rule is refused here rather than published.
func validateRenderedRule(expression string) error {
	if expression == "" {
		return errors.New("empty domain expression")
	}
	for _, c := range expression {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f' || c == '#' || c == 0x7f {
			return fmt.Errorf("domain expression %q is not a single space-free section", expression)
		}
		if c < ' ' {
			return fmt.Errorf("domain expression %q contains a control character", expression)
		}
	}
	kind, value, typed := strings.Cut(expression, ":")
	if !typed || !supportedRuleKinds[kind] || value == "" {
		return fmt.Errorf("domain expression %q is not a supported MOSDNS rule", expression)
	}
	return nil
}
