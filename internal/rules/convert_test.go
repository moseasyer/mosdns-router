package rules

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	mosdnsdomain "github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
)

// The fixtures below are hand-built from the grammar the pinned upstream
// repository documents in its README and implements in its own generator
// (v2fly/domain-list-community, read at the pinned commit). No expectation is
// computed with ConvertFS or any of its helpers, and no test here reads the
// network.

// convertFixture is a small helper for the common shape of a two-file fixture.
func convertFixture(files map[string]string) fstest.MapFS {
	fsys := make(fstest.MapFS, len(files))
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func TestConvertFSExpandsIncludesAndKeepsEverySupportedForm(t *testing.T) {
	// A change that dropped includes, reordered the output, or rewrote a
	// supported form would change this list; a change that only renames an
	// internal helper would not.
	fsys := convertFixture(map[string]string{
		"data/cn": strings.Join([]string{
			"domain:example.cn",
			"full:exact.cn",
			"keyword:测试",
			"include:shared",
			"# a comment",
			"",
		}, "\n"),
		"data/shared": "regexp:^static[0-9]+\\.example\\.cn$\n",
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{
		"domain:example.cn",
		"full:exact.cn",
		"keyword:测试",
		"regexp:^static[0-9]+\\.example\\.cn$",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS =\n%q\nwant\n%q", got, want)
	}
}

func TestConvertFSSortsAndDeduplicates(t *testing.T) {
	// A converter that appended rules in file order, or kept the same domain
	// once per attribute set, would produce a different list. The output is the
	// artifact the router reads, so its order and uniqueness are the contract.
	fsys := convertFixture(map[string]string{
		"data/cn": strings.Join([]string{
			"zeta.cn",
			"alpha.cn @ads",
			"include:shared",
			"alpha.cn",
		}, "\n"),
		"data/shared": strings.Join([]string{
			"alpha.cn @ads",
			"beta.cn",
			"alpha.cn",
		}, "\n"),
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{"domain:alpha.cn", "domain:beta.cn", "domain:zeta.cn"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSConvertsBareDomainsToExplicitDomainForm(t *testing.T) {
	// The pinned data states most rules as bare domains. Passing them through
	// would leave them dependent on whatever default matcher the consumer sets,
	// so every bare domain has to become an explicit `domain:` expression.
	fsys := convertFixture(map[string]string{"data/cn": "example.cn\nxn--fiqs8s\n"})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{"domain:example.cn", "domain:xn--fiqs8s"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSLowercasesDomainAndFullValues(t *testing.T) {
	// The pinned generator lowercases and then validates, so an upper-case rule
	// is valid upstream. A converter that validated before folding would refuse
	// a rule the pinned source actually contains, and one that kept the case
	// would emit a rule MOSDNS normalizes differently.
	fsys := convertFixture(map[string]string{"data/cn": "domain:EXAMPLE.CN\nfull:Exact.CN\n"})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{"domain:example.cn", "full:exact.cn"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSSortsByBytesNotByCase(t *testing.T) {
	// A regular expression is used verbatim, so a list can hold values that
	// differ only in case. The order of the published file has to be decided by
	// the bytes, so the same commit always produces the same file whatever the
	// locale: `^B` sorts before `^a`, because 0x42 is below 0x61.
	fsys := convertFixture(map[string]string{
		"data/cn": "regexp:^a$\nregexp:^B$\nregexp:^A$\nregexp:^b$\n",
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{"regexp:^A$", "regexp:^B$", "regexp:^a$", "regexp:^b$"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSAppliesConjunctiveIncludeAttributeFilters(t *testing.T) {
	// `include:x @a @-b` includes child rules that have @a and lack @b. An
	// implementation that ignored the filters, ORed them, or matched a
	// substring would leak ads-only or @cn-marked rules into the China set and
	// drop the rules that must be there.
	fsys := convertFixture(map[string]string{
		"data/cn": strings.Join([]string{
			"include:ads-only @ads",
			"include:not-cn @-cn",
			"include:cn-and-ads @cn @ads",
			"include:everything",
		}, "\n"),
		"data/ads-only":   "domain:ads.cn @ads\ndomain:plain.cn\n",
		"data/not-cn":     "domain:with-cn.cn @cn\ndomain:clean.cn\n",
		"data/cn-and-ads": "domain:both.cn @ads @cn\ndomain:ads-only.cn @ads\ndomain:cn-only.cn @cn\n",
		"data/everything": "domain:all.cn\n",
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{"domain:ads.cn", "domain:all.cn", "domain:both.cn", "domain:clean.cn"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSCarriesAttributesThroughNestedInclusions(t *testing.T) {
	// Filters are applied to a child's fully resolved rules, not only to the
	// child's own lines. An implementation that filtered before resolving would
	// let a grandchild's @ads rule through an unfiltered intermediate include.
	fsys := convertFixture(map[string]string{
		"data/cn":     "include:middle\n",
		"data/middle": "include:leaf\ndomain:middle.cn @ads\n",
		"data/leaf":   "domain:leaf.cn @ads\ndomain:leaf-clean.cn\n",
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{"domain:leaf-clean.cn", "domain:leaf.cn", "domain:middle.cn"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSDropsNotCNRulesFromTheResolvedList(t *testing.T) {
	// Upstream publishes that rules marked `@!cn` are cast out of the cn lists.
	// A converter that kept them would route a documented non-China domain into
	// the domestic branch; a converter that dropped the whole file, or the plain
	// copy of a domain that also appears as `@!cn`, would lose China rules.
	fsys := convertFixture(map[string]string{
		"data/cn": strings.Join([]string{
			"domain:kept.cn @cn",
			"domain:cast-out.cn @!cn",
			"domain:both.cn @!cn",
			"domain:both.cn",
			"include:child",
		}, "\n"),
		"data/child": "domain:from-child.cn @!cn\ndomain:from-child-clean.cn\n",
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	want := []string{"domain:both.cn", "domain:from-child-clean.cn", "domain:kept.cn"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSValidatesAffiliationsWithoutExpandingThem(t *testing.T) {
	// `&affiliation` is upstream data management: it adds the rule to another
	// list, and never changes the list that states it. The gateway only converts
	// the China list, so the affiliation is validated and then dropped; a
	// malformed one is refused rather than skipped.
	fsys := convertFixture(map[string]string{"data/cn": "domain:example.cn &other-list\n"})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	if want := []string{"domain:example.cn"}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}

	for _, line := range []string{"domain:example.cn &bad_name", "domain:example.cn &"} {
		broken := convertFixture(map[string]string{"data/cn": line + "\n"})
		_, err := ConvertFS(broken, "data/cn")
		if err == nil {
			t.Fatalf("ConvertFS accepted a malformed affiliation: %q", line)
		}
		if !strings.Contains(err.Error(), "data/cn:1:") {
			t.Fatalf("affiliation error lacks file and line: %v", err)
		}
	}
}

func TestConvertFSRejectsUnsupportedOrMalformedRules(t *testing.T) {
	// Every line here is one a converter could plausibly mishandle. Silently
	// dropping any of them would publish a China list that is missing a rule
	// the operator reviewed, so each one has to fail the whole conversion.
	tests := []struct {
		name    string
		line    string
		wantSub string
	}{
		{name: "unknown directive", line: "ip4:1.2.3.4", wantSub: `unsupported rule type "ip4"`},
		{name: "geosite directive", line: "geosite:cn", wantSub: `unsupported rule type "geosite"`},
		{name: "empty domain", line: "domain:", wantSub: "empty domain rule"},
		{name: "unknown field", line: "domain:example.cn nonsense", wantSub: `unknown field "nonsense"`},
		{name: "empty regexp", line: "regexp:", wantSub: "empty domain rule"},
		{name: "empty keyword", line: "keyword:", wantSub: "empty domain rule"},
		{name: "invalid regexp", line: "regexp:^static[0-9+\\.cn$", wantSub: `invalid regexp "^static[0-9+\\.cn$"`},
		// A keyword is the one rule form whose normalisation can silently
		// broaden it: MOSDNS's KeywordMatcher.Add applies NormalizeDomain, so
		// `a.` is published as `a` and matches every name containing the letter
		// a. The validator below has its own case; this one is here so the
		// refusal is a whole-conversion failure and not something a caller can
		// route around.
		{name: "keyword that normalisation would change", line: "keyword:a.", wantSub: `invalid keyword "a."`},
		{name: "empty include", line: "include:", wantSub: "empty inclusion"},
		{name: "affiliation on include", line: "include:child &other", wantSub: "affiliation is not allowed on an inclusion"},
		{name: "unknown include field", line: "include:child @ads nonsense", wantSub: `unknown field "nonsense"`},
		{name: "bad must attribute", line: "include:child @bad_attr", wantSub: `invalid attribute "bad_attr"`},
		{name: "bad ban attribute", line: "include:child @-bad_attr", wantSub: `invalid attribute "bad_attr"`},
	}
	fsys := convertFixture(map[string]string{
		"data/cn":    strings.Join([]string{"include:child", "domain:example.cn", "domain:second.cn"}, "\n") + "\n",
		"data/child": "domain:child.cn\n",
	})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broken := fstest.MapFS{}
			for name, file := range fsys {
				broken[name] = file
			}
			broken["data/broken"] = &fstest.MapFile{Data: []byte(test.line + "\n")}

			got, err := ConvertFS(broken, "data/broken")
			if err == nil {
				t.Fatalf("ConvertFS accepted %q and returned %q", test.line, got)
			}
			if !strings.Contains(err.Error(), "data/broken:1:") {
				t.Errorf("error lacks file and line: %v", err)
			}
			if !strings.Contains(err.Error(), test.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, test.wantSub)
			}
		})
	}
}

func TestConvertFSRejectsInvalidDomainNames(t *testing.T) {
	// The pinned generator refuses these before a rule is ever built, so
	// accepting them would publish a rule that can never match a real query.
	longLabel := strings.Repeat("a", 64) + ".cn"
	longName := strings.Repeat("a.", 127) + "cn"
	for _, line := range []string{
		"domain:-example.cn",
		"domain:example-.cn",
		"domain:example..cn",
		"domain:example.cn.",
		"domain:example_cn",
		"domain:" + longLabel,
		"domain:" + longName,
		"full:-example.cn",
	} {
		t.Run(line, func(t *testing.T) {
			fsys := convertFixture(map[string]string{"data/cn": line + "\n"})
			got, err := ConvertFS(fsys, "data/cn")
			if err == nil {
				t.Fatalf("ConvertFS accepted %q and returned %q", line, got)
			}
			if !strings.Contains(err.Error(), `invalid domain`) {
				t.Errorf("error = %v, want it to mention an invalid domain", err)
			}
		})
	}
}

func TestConvertFSRejectsMissingInclude(t *testing.T) {
	// A missing include means the China set would silently be short. The
	// conversion has to fail so the last known good list stays in place.
	fsys := convertFixture(map[string]string{"data/cn": "domain:kept.cn\ninclude:absent\n"})

	got, err := ConvertFS(fsys, "data/cn")
	if err == nil {
		t.Fatalf("ConvertFS accepted a missing include and returned %q", got)
	}
	if !strings.Contains(err.Error(), "data/cn:2:") || !strings.Contains(err.Error(), `missing include "absent"`) {
		t.Fatalf("error = %v, want the file, line and missing list name", err)
	}
}

func TestConvertFSRejectsIncludeCycle(t *testing.T) {
	// Upstream refuses circular inclusion. A converter that recursed until the
	// stack overflowed, or that silently stopped at the repeated file, would
	// publish a list whose contents depend on where the cycle started.
	fsys := convertFixture(map[string]string{
		"data/cn": "include:a\n",
		"data/a":  "include:b\n",
		"data/b":  "include:c\n",
		"data/c":  "include:a\n",
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err == nil {
		t.Fatalf("ConvertFS accepted an include cycle and returned %q", got)
	}
	if want := "include cycle at \"a\": data/cn:1 -> data/a:1 -> data/b:1 -> data/c:1"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want it to report the cycle as %q", err, want)
	}
}

func TestConvertFSRejectsIncludeNamesThatCannotStayInsideTheListDirectory(t *testing.T) {
	// The include charset upstream accepts contains no dot and no slash, so a
	// traversal or an absolute path can never name a file. If that ever changed,
	// the converter would read a file outside the pinned archive.
	for _, line := range []string{"include:../cn", "include:/etc/passwd", "include:./cn", "include:..", "include:sub/cn"} {
		fsys := convertFixture(map[string]string{"data/cn": line + "\n"})
		got, err := ConvertFS(fsys, "data/cn")
		if err == nil {
			t.Fatalf("ConvertFS accepted %q and returned %q", line, got)
		}
	}
}

func TestConvertFSBoundsIncludeDepth(t *testing.T) {
	// A chain at the bound still converts; one past it is refused. A converter
	// with no bound would depend on the pinned data staying shallow, and one
	// with a bound off by one would refuse a legitimate archive.
	chain := func(files int) fstest.MapFS {
		fsys := fstest.MapFS{}
		for i := 0; i < files-1; i++ {
			fsys[fmt.Sprintf("data/list%d", i)] = &fstest.MapFile{Data: []byte(fmt.Sprintf("include:list%d\n", i+1))}
		}
		fsys[fmt.Sprintf("data/list%d", files-1)] = &fstest.MapFile{Data: []byte("domain:deep.cn\n")}
		return fsys
	}

	got, err := ConvertFS(chain(33), "data/list0")
	if err != nil {
		t.Fatalf("ConvertFS refused a chain at the include-depth bound: %v", err)
	}
	if want := []string{"domain:deep.cn"}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}

	_, err = ConvertFS(chain(34), "data/list0")
	if err == nil {
		t.Fatal("ConvertFS accepted a chain past the include-depth bound")
	}
	if !strings.Contains(err.Error(), "include depth") {
		t.Fatalf("error = %v, want it to name the include depth bound", err)
	}
}

func TestConvertFSBoundsTheNumberOfVisitedFiles(t *testing.T) {
	// A pinned archive is expected to reference a few hundred files, so the
	// bound is a reviewed envelope rather than a guess at the current data. A
	// converter without one would let a hostile archive consume unbounded work.
	star := func(includes int) fstest.MapFS {
		lines := make([]string, 0, includes)
		for i := 0; i < includes; i++ {
			lines = append(lines, fmt.Sprintf("include:leaf%d", i))
		}
		fsys := fstest.MapFS{"data/cn": &fstest.MapFile{Data: []byte(strings.Join(lines, "\n") + "\n")}}
		for i := 0; i < includes; i++ {
			fsys[fmt.Sprintf("data/leaf%d", i)] = &fstest.MapFile{Data: []byte("domain:leaf.cn\n")}
		}
		return fsys
	}

	if _, err := ConvertFS(star(2047), "data/cn"); err != nil {
		t.Fatalf("ConvertFS refused 2048 unique lists: %v", err)
	}
	_, err := ConvertFS(star(2048), "data/cn")
	if err == nil {
		t.Fatal("ConvertFS accepted more than 2048 unique lists")
	}
	if !strings.Contains(err.Error(), "2048") {
		t.Fatalf("error = %v, want it to name the file bound", err)
	}
}

// TestConvertFSRefusesAKeywordMOSDNSWouldNormalize covers the one rule form whose
// value can change between review and use. A domain, a full and a regexp rule are
// all folded to lower case here and then read as written; a keyword is
// additionally run through NormalizeDomain by MOSDNS's own KeywordMatcher.Add, so
// a value normalisation would alter is published as something else.
//
// The broadening is not a theory. This proves it against the pinned matcher, in
// the router's own code path: the same matcher that loads the published list is
// given `keyword:a.`, and a name nobody listed comes back matched. A China set
// holding that rule sends most of the internet to the DHCP branch while the file
// reads exactly as it was reviewed, so the rule has to be refused at conversion
// rather than published and discovered.
func TestConvertFSRefusesAKeywordMOSDNSWouldNormalize(t *testing.T) {
	// The harm, shown first: the pinned matcher, loaded the way the router loads
	// the list, broadens the rule the upstream wrote.
	published := "keyword:a.\n"
	matcher := mosdnsdomain.NewDomainMixMatcher()
	if err := mosdnsdomain.LoadFromTextReader(matcher, strings.NewReader(published), nil); err != nil {
		t.Fatalf("the pinned matcher refused %q: %v", published, err)
	}
	if _, matched := matcher.Match("a-name-nobody-listed.example."); !matched {
		t.Fatalf("the pinned matcher did not broaden %q, so this case is not about the rule it is about", published)
	}

	// So the converter refuses it, and the refusal names the offending value.
	fsys := convertFixture(map[string]string{"data/cn": "domain:kept.cn\nkeyword:a.\n"})
	got, err := ConvertFS(fsys, "data/cn")
	if err == nil {
		t.Fatalf("ConvertFS published a keyword MOSDNS would normalise, as %q", got)
	}
	if !strings.Contains(err.Error(), "data/cn:2:") || !strings.Contains(err.Error(), `invalid keyword "a."`) {
		t.Errorf("refusal = %v, want the line and the offending keyword", err)
	}

	// The control: keywords normalisation leaves alone are still published, so the
	// guard refuses the values that change and not the keyword form. A bare dot is
	// the second half of the same case -- NormalizeDomain reduces it to nothing,
	// which would match every name there is.
	survivable := convertFixture(map[string]string{"data/cn": "keyword:测试\nkeyword:cdn\nkeyword:co\n"})
	if got, err := ConvertFS(survivable, "data/cn"); err != nil {
		t.Fatalf("ConvertFS refused a keyword MOSDNS normalises to itself: %v", err)
	} else if want := []string{"keyword:cdn", "keyword:co", "keyword:测试"}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
	if got, err := ConvertFS(convertFixture(map[string]string{"data/cn": "keyword:.\n"}), "data/cn"); err == nil {
		t.Errorf("ConvertFS published a keyword that normalises to nothing, as %q", got)
	}
}

// TestConvertFSLowercasesAKeywordBecauseMOSDNSDoes is why the guard compares
// against the normalised value rather than refusing every keyword that differs from
// its input: case is a change normalisation makes, folding it here is what keeps
// the published rule and the reviewed one the same rule, and an upper-case
// keyword is valid upstream.
func TestConvertFSLowercasesAKeywordBecauseMOSDNSDoes(t *testing.T) {
	fsys := convertFixture(map[string]string{"data/cn": "keyword:CDN\n"})

	got, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS refused an upper-case keyword: %v", err)
	}
	if want := []string{"keyword:cdn"}; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("ConvertFS = %q, want %q", got, want)
	}
}

func TestConvertFSRefusesAnEntryThatResolvesToNoRules(t *testing.T) {
	// An empty China set sends every query to the foreign branch while the
	// operator believes the list is installed. Failing keeps the previous list.
	fsys := convertFixture(map[string]string{
		"data/cn": "# only a comment\n\n",
	})

	got, err := ConvertFS(fsys, "data/cn")
	if err == nil {
		t.Fatalf("ConvertFS accepted an empty list and returned %q", got)
	}
	if !strings.Contains(err.Error(), "no rules") {
		t.Fatalf("error = %v, want it to say the entry resolved to no rules", err)
	}
}

func TestConvertFSRefusesAnEntryOutsideThePinnedArchive(t *testing.T) {
	// The entry path reaches ConvertFS from a lock file, so it is refused with a
	// diagnostic that says what was wrong with it, before the filesystem is asked
	// to open anything.
	fsys := convertFixture(map[string]string{"data/cn": "domain:example.cn\n"})
	for _, entry := range []string{"", "/data/cn", "../data/cn", "data/../data/cn", "./data/cn"} {
		_, err := ConvertFS(fsys, entry)
		if err == nil {
			t.Errorf("ConvertFS accepted entry %q", entry)
			continue
		}
		if !strings.Contains(err.Error(), "is not a path inside the source archive") {
			t.Errorf("ConvertFS refused entry %q without saying why: %v", entry, err)
		}
	}
	if _, err := ConvertFS(nil, "data/cn"); err == nil {
		t.Error("ConvertFS accepted a nil filesystem")
	}
}

func TestValidateRenderedRuleRejectsExpressionsMOSDNSCannotRead(t *testing.T) {
	// MOSDNS strips `#` to the end of the line and refuses a rule that is not a
	// single space-free section, so an expression that reaches the router with
	// either would silently become a different rule. This is the boundary the
	// router reads, so the validator is exercised directly.
	for _, line := range []string{
		"",
		"example.cn",
		"domain:",
		"domain:example.cn extra",
		"domain:example.cn\t",
		"domain:example.cn#suffix",
		"ip4:1.2.3.4",
		"domain:example.cn\x00",
		"domain:exam\x7fple.cn",
	} {
		if err := validateRenderedRule(line); err == nil {
			t.Errorf("validateRenderedRule accepted %q", line)
		}
	}
	for _, line := range []string{
		"domain:example.cn",
		"full:exact.cn",
		"keyword:测试",
		"regexp:^static[0-9]+\\.example\\.cn$",
	} {
		if err := validateRenderedRule(line); err != nil {
			t.Errorf("validateRenderedRule rejected %q: %v", line, err)
		}
	}
}

func TestConvertedListLoadsInMOSDNSAndMatchesTheIntendedQueries(t *testing.T) {
	// The output is consumed by MOSDNS v5.3.4's own domain_set loader, so the
	// contract is proved there: every converted rule is accepted, a China domain
	// matches, and a domain nobody listed does not. A rule the router would
	// reject, or a domain rule that only matched exactly, would fail here.
	fsys := convertFixture(map[string]string{
		"data/cn": "example.cn @cn\ninclude:shared\nforeign-not-listed.com\n",
		"data/shared": strings.Join([]string{
			"full:exact.cn",
			"keyword:cdn",
			"regexp:^static[0-9]+\\.example\\.cn$",
		}, "\n"),
	})

	lines, err := ConvertFS(fsys, "data/cn")
	if err != nil {
		t.Fatalf("ConvertFS: %v", err)
	}
	matcher := mosdnsdomain.NewDomainMixMatcher()
	if err := mosdnsdomain.LoadFromTextReader(matcher, strings.NewReader(strings.Join(lines, "\n")+"\n"), nil); err != nil {
		t.Fatalf("MOSDNS refused the converted list %q: %v", lines, err)
	}
	if got := matcher.Len(); got != 5 {
		t.Fatalf("MOSDNS loaded %d rules from %q, want 5", got, lines)
	}
	for _, domain := range []string{
		"example.cn",
		"sub.example.cn",
		"exact.cn",
		"deep.sub.example.cn",
		"static1.example.cn",
		"img.cdn.example.org",
	} {
		if _, ok := matcher.Match(domain); !ok {
			t.Errorf("MOSDNS did not match %q against the converted list %q", domain, lines)
		}
	}
	for _, domain := range []string{"example.com", "exact.com", "static1.example.org", "cn"} {
		if _, ok := matcher.Match(domain); ok {
			t.Errorf("MOSDNS matched %q, which the converted list %q does not list", domain, lines)
		}
	}
}
