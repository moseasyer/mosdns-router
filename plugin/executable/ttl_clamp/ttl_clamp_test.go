package ttlclamp

import (
	"context"
	"strings"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func message(ttl uint32) *dns.Msg {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl,
		},
		A: []byte{203, 0, 113, 10},
	}}
	return response
}

func run(t *testing.T, args Args, response *dns.Msg) *dns.Msg {
	t.Helper()
	plugin, err := Init(nil, &args)
	if err != nil {
		t.Fatalf("Init(%+v): %v", args, err)
	}
	qCtx := query_context.NewContext(new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	qCtx.SetResponse(response)
	if err := plugin.(*Clamp).Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	return qCtx.R()
}

func TestAMaximumIsAppliedToEveryRecord(t *testing.T) {
	got := run(t, Args{Max: 120}, message(3600))
	if ttl := got.Answer[0].Header().Ttl; ttl != 120 {
		t.Fatalf("a record with TTL 3600 came back at %d, want the policy's 120", ttl)
	}
}

// **A bound of 0 is not "no bound" to mosdns**, and this is the case that keeps the
// renderer from ever writing one: `ApplyMaximumTTL(m, 0)` sets EVERY record's TTL
// to 0, which is "expire immediately" rather than "no limit". Init refuses the
// zero/zero configuration for exactly this reason.
func TestAMaximumDoesNotRaiseARecordBelowIt(t *testing.T) {
	// **A clamp, not a setter.** A maximum bounds from above and does nothing to a
	// record already below it. The first version of this case asserted the record
	// came back at 30 -- which is what a MINIMUM does -- so the name, the
	// expectation and the plugin all disagreed, and the plugin was right.
	//
	// This is also what mosdns's own quick-setup cannot do: its "300" form sets every
	// record to exactly 300, so there is no mosdns-reachable way to bound from above
	// without also raising what is below.
	got := run(t, Args{Max: 30}, message(1))
	if ttl := got.Answer[0].Header().Ttl; ttl != 1 {
		t.Fatalf("a record with TTL 1 under a maximum of 30 came back at %d, want 1: a "+
			"maximum bounds from above and does not raise what is already below it", ttl)
	}
}

func TestAMinimumRaisesEveryRecord(t *testing.T) {
	got := run(t, Args{Min: 60}, message(5))
	if ttl := got.Answer[0].Header().Ttl; ttl != 60 {
		t.Fatalf("a record with TTL 5 came back at %d, want the policy's 60", ttl)
	}
}

// Both bounds at once, and the ORDER matters: min is applied first and max second,
// which is mosdns's own order (plugin/executable/ttl/ttl.go:88-93). So min > max
// yields max for every record rather than a result that depends on which ran last.
func TestBothBoundsApplyMinimumFirstAndMaximumSecond(t *testing.T) {
	got := run(t, Args{Min: 60, Max: 300}, message(5))
	if ttl := got.Answer[0].Header().Ttl; ttl != 60 {
		t.Fatalf("a record at TTL 5 came back at %d, want 60: the minimum applies first", ttl)
	}
	got = run(t, Args{Min: 60, Max: 300}, message(3600))
	if ttl := got.Answer[0].Header().Ttl; ttl != 300 {
		t.Fatalf("a record at TTL 3600 came back at %d, want the maximum", ttl)
	}
	got = run(t, Args{Min: 60, Max: 300}, message(120))
	if ttl := got.Answer[0].Header().Ttl; ttl != 120 {
		t.Fatalf("a record between the bounds came back at %d, want it untouched", ttl)
	}
}

// min > max is a predictable configuration rather than a fault: every record ends
// at max. The plugin does not refuse it, and this case holds that it does not.
func TestAMinimumAboveTheMaximumEndsAtTheMaximum(t *testing.T) {
	got := run(t, Args{Min: 900, Max: 300}, message(30))
	if ttl := got.Answer[0].Header().Ttl; ttl != 300 {
		t.Fatalf("min 900 and max 300 gave %d, want 300: the maximum is applied last and "+
			"so decides", ttl)
	}
}

// A record already inside the bounds is not touched, which is the difference between
// a clamp and a setter. mosdns's own quick-setup form ("300") cannot express this.
func TestARecordInsideTheBoundsIsUntouched(t *testing.T) {
	got := run(t, Args{Min: 60, Max: 300}, message(120))
	if ttl := got.Answer[0].Header().Ttl; ttl != 120 {
		t.Fatalf("a record at TTL 120 came back at %d, want 120", ttl)
	}
}

// No answer is left alone rather than manufactured: a clamp that produced an empty
// answer would turn "the upstream did not answer" into something that looks like an
// answer, and hide the failure this project refuses to hide.
func TestNoResponseIsLeftAlone(t *testing.T) {
	plugin, err := Init(nil, &Args{Max: 120})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	qCtx := query_context.NewContext(new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	if err := plugin.(*Clamp).Exec(context.Background(), qCtx); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if qCtx.R() != nil {
		t.Fatalf("the clamp produced a response (%v) where there was none", qCtx.R())
	}
}

// A clamp with neither bound would load, sit in the document and do nothing. That
// is refused here as well as in the renderer, because the two are different
// documents and only one of them goes through this code.
func TestAClampWithNeitherBoundIsRefused(t *testing.T) {
	_, err := Init(nil, &Args{})
	if err == nil {
		t.Fatal("a clamp with neither max nor min was accepted, so it would load and do " +
			"nothing while making the routing document harder to read for it")
	}
	for _, want := range []string{"neither max nor min", "every record's TTL to 0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// The plugin has to be REGISTERED, or the loader refuses the document with
// `plugin type ttl_clamp not defined` -- which is the defect this package's own
// existence is about, reproduced here so it cannot come back.
func TestThePluginTypeIsTheOneTheDocumentRenders(t *testing.T) {
	if PluginType != "ttl_clamp" {
		t.Fatalf("PluginType is %q; the routing document renders %q, and a rename that "+
			"missed one of them produces a document the loader refuses", PluginType, "ttl_clamp")
	}
	// And it must be reachable BY THE LOADER, which is what registration means. A
	// package that is imported but never registered behaves exactly like one that
	// does not exist -- and this is the defect the package exists to fix, so it is
	// checked against the loader's own registry rather than against this file.
	if _, ok := coremain.GetPluginType(PluginType); !ok {
		t.Fatalf("the loader does not know %q, so a document rendering it is refused with "+
			"'plugin type %s not defined' -- which is the defect this package exists to fix",
			PluginType, PluginType)
	}
}
