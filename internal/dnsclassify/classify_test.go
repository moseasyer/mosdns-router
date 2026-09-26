package dnsclassify

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The prefixes in this file are the IPv4 ranges Cloudflare publishes, written out
// here rather than read from a file or fetched from a URL, so every test runs
// without the network and a wrong answer is a wrong answer in this list rather
// than in a cached document. They are also the argument of every classification
// below: the package consults no list of its own, and TestCloudflareReadsThe
// PrefixesItIsGiven is the test that says so.
func publishedPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("104.16.0.0/13"),
		netip.MustParsePrefix("172.64.0.0/13"),
		netip.MustParsePrefix("103.21.244.0/22"),
		netip.MustParsePrefix("103.22.200.0/22"),
		netip.MustParsePrefix("162.158.0.0/15"),
		netip.MustParsePrefix("141.101.64.0/18"),
		netip.MustParsePrefix("108.162.192.0/18"),
		netip.MustParsePrefix("190.93.240.0/20"),
		netip.MustParsePrefix("188.114.96.0/20"),
		netip.MustParsePrefix("197.234.240.0/22"),
		netip.MustParsePrefix("198.41.128.0/17"),
		netip.MustParsePrefix("162.159.128.0/17"),
		netip.MustParsePrefix("104.24.0.0/14"),
		netip.MustParsePrefix("172.104.0.0/14"),
		netip.MustParsePrefix("131.0.72.0/22"),
	}
}

// documentationPrefix is a range no CDN serves from. It is what the
// "the prefixes are an argument" cases classify against, so a verdict that
// depends on a list inside this package instead of on the argument fails here.
func documentationPrefix() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
}

func answerA(name, address string, ttl uint32) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(address),
	}
}

func answerAAAA(name, address string, ttl uint32) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(address),
	}
}

func answerCNAME(from, to string, ttl uint32) *dns.CNAME {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: from, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
		Target: to,
	}
}

// response builds the answer section a recursive resolver would receive for one
// question, with the header a real server sets.
func response(qname string, qtype uint16, answers ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Answer = answers
	return msg
}

// TestCloudflare is the verdict matrix: one literal Result per case, so a change
// in any branch of the walk or the prefix comparison moves exactly the row that
// describes it.
func TestCloudflare(t *testing.T) {
	tests := []struct {
		name     string
		msg      *dns.Msg
		prefixes []netip.Prefix
		want     Result
	}{
		{
			name:     "a direct address inside a published range",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300)),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "cdn.example.",
				AllMatch:     true,
			},
		},
		{
			name:     "a direct address inside the second published range",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "198.41.128.7", 300)),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "cdn.example.",
				AllMatch:     true,
			},
		},
		{
			name: "one CNAME then a published address",
			msg: response("cdn.example.", dns.TypeA,
				answerCNAME("cdn.example.", "edge.example.net.", 300),
				answerA("edge.example.net.", "104.16.1.1", 200),
			),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "edge.example.net.",
				AllMatch:     true,
			},
		},
		{
			name: "three CNAMEs then a published address",
			msg: response("cdn.example.", dns.TypeA,
				answerCNAME("cdn.example.", "one.example.net.", 300),
				answerCNAME("one.example.net.", "two.example.net.", 300),
				answerCNAME("two.example.net.", "three.example.net.", 300),
				answerA("three.example.net.", "104.16.1.1", 60),
			),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "three.example.net.",
				AllMatch:     true,
			},
		},
		{
			name: "every terminal address inside a published range",
			msg: response("cdn.example.", dns.TypeA,
				answerA("cdn.example.", "104.16.1.1", 300),
				answerA("cdn.example.", "172.64.5.5", 300),
				answerA("cdn.example.", "131.0.72.1", 300),
			),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "cdn.example.",
				AllMatch:     true,
			},
		},
		{
			name:     "one published address and one foreign address",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300), answerA("cdn.example.", "198.51.100.5", 300)),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "cdn.example.",
				Mixed:        true,
				Refusal:      RefusalMixed,
			},
		},
		{
			name:     "a foreign address behind a chain of CNAMEs",
			msg:      response("cdn.example.", dns.TypeA, answerCNAME("cdn.example.", "origin.example.", 300), answerA("origin.example.", "192.0.2.10", 300)),
			prefixes: publishedPrefixes(),
			want: Result{
				TerminalName: "origin.example.",
				Refusal:      RefusalForeignAddress,
			},
		},
		{
			name:     "every address foreign",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "198.51.100.5", 300), answerA("cdn.example.", "203.0.113.9", 300)),
			prefixes: publishedPrefixes(),
			want: Result{
				TerminalName: "cdn.example.",
				Refusal:      RefusalForeignAddress,
			},
		},
		{
			name:     "a chain that ends at a name with no records at all",
			msg:      response("cdn.example.", dns.TypeA, answerCNAME("cdn.example.", "nowhere.example.", 300)),
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalNoAddress},
		},
		{
			name:     "an empty answer section",
			msg:      response("cdn.example.", dns.TypeA),
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalNoAddress},
		},
		{
			name:     "a terminal name that holds only IPv6",
			msg:      response("cdn.example.", dns.TypeAAAA, answerAAAA("cdn.example.", "2606:4700::1111", 300)),
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalNoAddress},
		},
		{
			name:     "no published prefixes at all",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300)),
			prefixes: nil,
			want:     Result{Refusal: RefusalNoPrefixes},
		},
		{
			name:     "a prefix set that names the answer",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "203.0.113.9", 300)),
			prefixes: documentationPrefix(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "cdn.example.",
				AllMatch:     true,
			},
		},
		{
			name:     "a real published address the given prefixes omit",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300)),
			prefixes: documentationPrefix(),
			want: Result{
				TerminalName: "cdn.example.",
				Refusal:      RefusalForeignAddress,
			},
		},
		{
			name:     "a prefix set of IPv6 ranges",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300)),
			prefixes: []netip.Prefix{netip.MustParsePrefix("2606:4700::/32")},
			want: Result{
				TerminalName: "cdn.example.",
				Refusal:      RefusalForeignAddress,
			},
		},
		{
			name:     "a prefix set written as IPv4-mapped IPv6",
			msg:      response("cdn.example.", dns.TypeA, answerA("cdn.example.", "104.16.1.1", 300)),
			prefixes: []netip.Prefix{netip.MustParsePrefix("::ffff:104.16.0.0/108")},
			want: Result{
				TerminalName: "cdn.example.",
				Refusal:      RefusalForeignAddress,
			},
		},
		{
			name:     "no response at all",
			msg:      nil,
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalNoResponse},
		},
		{
			name: "no question to walk from",
			msg: func() *dns.Msg {
				msg := new(dns.Msg)
				msg.Response = true
				msg.Answer = []dns.RR{answerA("cdn.example.", "104.16.1.1", 300)}
				return msg
			}(),
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalNoQuestion},
		},
		{
			name: "two questions in one response",
			msg: &dns.Msg{
				Question: []dns.Question{
					{Name: "cdn.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
					{Name: "other.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
				Answer: []dns.RR{answerA("cdn.example.", "104.16.1.1", 300)},
			},
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalNoQuestion},
		},
		{
			name: "a chain name that also carries an address",
			msg: response("cdn.example.", dns.TypeA,
				answerCNAME("cdn.example.", "edge.example.net.", 300),
				answerA("cdn.example.", "198.51.100.5", 300),
				answerA("edge.example.net.", "104.16.1.1", 300),
			),
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalAddressInChain},
		},
		{
			name: "two CNAMEs at the same name",
			msg: response("cdn.example.", dns.TypeA,
				answerCNAME("cdn.example.", "one.example.net.", 300),
				answerCNAME("cdn.example.", "two.example.net.", 300),
				answerA("one.example.net.", "104.16.1.1", 300),
				answerA("two.example.net.", "104.16.2.2", 300),
			),
			prefixes: publishedPrefixes(),
			want:     Result{Refusal: RefusalAmbiguousChain},
		},
		{
			name: "a chain spelled in a different case and without the final dot",
			msg: response("T.Example.COM.", dns.TypeA,
				answerCNAME("t.example.com", "Final.Example.NET", 300),
				answerA("final.example.net", "104.16.1.1", 300),
			),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "final.example.net.",
				AllMatch:     true,
			},
		},
		{
			name: "an address at a name this question never reaches",
			msg: response("cdn.example.", dns.TypeA,
				answerCNAME("cdn.example.", "edge.example.net.", 300),
				answerA("edge.example.net.", "104.16.1.1", 300),
				answerA("somewhere.else.", "198.51.100.5", 300),
			),
			prefixes: publishedPrefixes(),
			want: Result{
				Provider:     "cloudflare",
				TerminalName: "edge.example.net.",
				AllMatch:     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Cloudflare(tt.msg, tt.prefixes); got != tt.want {
				t.Fatalf("Cloudflare(...) = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestCloudflareRefusesANameAliasedToItself is the case a walk with no memory
// cannot pass: `cdn.example. CNAME cdn.example.` is a single edge back to the
// name the walk started at, and following it forever is the failure this whole
// package exists to avoid. The classification runs in its own goroutine so that a
// walk which never returns is a failing test in one second rather than a suite
// that hangs until the package timeout kills it.
func TestCloudflareRefusesANameAliasedToItself(t *testing.T) {
	msg := response("cdn.example.", dns.TypeA,
		answerCNAME("cdn.example.", "cdn.example.", 300),
		answerA("cdn.example.", "104.16.1.1", 300),
	)

	got := withinSecond(t, "the self-aliased name", func() Result {
		return Cloudflare(msg, publishedPrefixes())
	})

	want := Result{Refusal: RefusalCNAMELoop}
	if got != want {
		t.Fatalf("Cloudflare(self-alias) = %+v, want %+v", got, want)
	}
}

// TestCloudflareRefusesAnAliasCycle walks a ring of names back to the start. A
// visited set keyed on the name makes this terminate for any length, which is
// what the 64-name ring below pins: an implementation that compared only the
// previous name, or that gave up after a fixed number of hops, refuses the
// two-name ring in the case above and answers something else here. The address
// belongs to a name the ring never reaches, because an address on a link of the
// ring is a different defect that this package reports first; putting it there
// would have left the loop untested.
func TestCloudflareRefusesAnAliasCycle(t *testing.T) {
	const hops = 64
	answers := make([]dns.RR, 0, hops+2)
	for i := range hops {
		answers = append(answers, answerCNAME(nameAt(i), nameAt(i+1), 300))
	}
	answers = append(answers, answerCNAME(nameAt(hops), nameAt(0), 300))
	answers = append(answers, answerA("elsewhere.example.", "104.16.1.1", 300))
	msg := response(nameAt(0), dns.TypeA, answers...)

	got := withinSecond(t, "the 64-name alias cycle", func() Result {
		return Cloudflare(msg, publishedPrefixes())
	})

	want := Result{Refusal: RefusalCNAMELoop}
	if got != want {
		t.Fatalf("Cloudflare(64-name cycle) = %+v, want %+v", got, want)
	}
}

// nameAt names one link of the cycle, and the index is written out rather than
// turned into a letter so that 64 hops are 64 distinct names and the ring is the
// 64-name one the test names.
func nameAt(i int) string {
	return "hop" + strconv.Itoa(i) + ".alias.example."
}

// TestChainReportsTheOwnersInOrder is the contract dnsrewrite depends on: the
// walk starts at the question name, follows one CNAME per name, and stops at the
// name that owns no CNAME. The names it reports are canonical, because that is
// the form dnsrewrite compares against.
func TestChainReportsTheOwnersInOrder(t *testing.T) {
	msg := response("CDN.Example.", dns.TypeA,
		answerCNAME("cdn.example.", "One.Example.NET.", 300),
		answerCNAME("one.example.net.", "two.example.net.", 300),
		answerA("two.example.net.", "104.16.1.1", 300),
	)

	got, refusal := Chain(msg)
	want := []string{"cdn.example.", "one.example.net.", "two.example.net."}
	if refusal != RefusalNone {
		t.Fatalf("Chain refusal = %q, want none", refusal)
	}
	if len(got) != len(want) {
		t.Fatalf("Chain owners = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Chain owners = %v, want %v", got, want)
		}
	}
}

// TestChainRefusesACycle is the same refusal the classification reports, pinned
// on the exported walk itself so the two cannot drift.
func TestChainRefusesACycle(t *testing.T) {
	msg := response("one.example.", dns.TypeA,
		answerCNAME("one.example.", "two.example.", 300),
		answerCNAME("two.example.", "one.example.", 300),
	)

	got, refusal := withinSecondChain(t, "the two-name alias cycle", msg)

	if len(got) != 0 {
		t.Fatalf("Chain owners = %v, want none for a cycle", got)
	}
	if refusal != RefusalCNAMELoop {
		t.Fatalf("Chain refusal = %q, want %q", refusal, RefusalCNAMELoop)
	}
}

// withinSecond runs one classification and fails the test if it has not returned
// in time, so an unbounded walk is a red test with a readable message instead of
// a stack dump from the package timeout.
func withinSecond(t *testing.T, what string, classify func() Result) Result {
	t.Helper()
	done := make(chan Result, 1)
	go func() { done <- classify() }()
	select {
	case got := <-done:
		return got
	case <-time.After(2 * time.Second):
		t.Fatalf("Cloudflare did not return within 2s for %s: the CNAME walk is not bounded", what)
		return Result{}
	}
}

func withinSecondChain(t *testing.T, what string, msg *dns.Msg) ([]string, Refusal) {
	t.Helper()
	type walked struct {
		owners  []string
		refusal Refusal
	}
	done := make(chan walked, 1)
	go func() {
		owners, refusal := Chain(msg)
		done <- walked{owners: owners, refusal: refusal}
	}()
	select {
	case got := <-done:
		return got.owners, got.refusal
	case <-time.After(2 * time.Second):
		t.Fatalf("Chain did not return within 2s for %s: the CNAME walk is not bounded", what)
		return nil, RefusalNone
	}
}
