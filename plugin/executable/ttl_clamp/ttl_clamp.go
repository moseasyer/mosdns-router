// Package ttlclamp bounds the TTL of every record in an answer.
//
// **It exists because mosdns v5.3.4's own `ttl` plugin cannot express what this
// package's policy asks for, and the two facts are separate.** Measured against the
// pinned release:
//
//   - `plugin/executable/ttl/ttl.go:37` registers ONLY
//     `sequence.MustRegExecQuickSetup(PluginType, QuickSetup)`. There is no
//     `coremain.RegNewPluginFunc` call anywhere in that package -- unlike `cache`
//     (cache.go:55) and `forward` (forward.go:45) -- so a standalone
//     `- tag: … type: ttl` entry is refused by the loader with
//     `plugin type ttl not defined`. The quick-setup form is the only way in.
//
//   - That quick setup reads `FIX` or `MIN-MAX` (ttl.go:60-77): "300" sets every
//     record's TTL to exactly 300, and "300-600" clamps between the two. So
//     max-only and min-only, which are the two things `foreign_cache.ttl_max` and
//     `foreign_cache.ttl_min` ask for independently, are not expressible in it.
//
// So a policy that set `ttl_max: 300` and left `ttl_min: 0` had no rendering that
// both loads and means what it says. This package is the fix, and it is small
// because the semantics are already measured in `pkg/dnsutils`: `ApplyMaximumTTL`
// and `ApplyMinimalTTL` are the same two functions mosdns's own plugin calls.
package ttlclamp

import (
	"context"
	"fmt"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
)

// PluginType is the name this package registers under and the name the generated
// routing document carries.
const PluginType = "ttl_clamp"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

// Args is the clamp's configuration.
//
// **Both bounds are omitempty and that is load-bearing in the document as well as
// here.** A rendered `max: 0` would not be "no maximum" -- `dnsutils.ApplyMaximumTTL`
// sets every record whose TTL is above the bound DOWN TO IT, so a bound of 0 sets
// every record's TTL to 0 and every answer expires immediately (measured:
// pkg/dnsutils/msg.go:65-67 -> :94-112, the clamp at :101-104). The zero value here
// means "no bound", and the renderer omits the key so the two cannot be confused.
type Args struct {
	// Max bounds every record's TTL from above. 0 means no bound.
	Max uint32 `yaml:"max,omitempty"`
	// Min raises every record's TTL to at least this. 0 means no bound.
	//
	// A record that would be raised above Max keeps Max: the plugin applies Min
	// first and Max second, which is the order mosdns's own clamp uses
	// (plugin/executable/ttl/ttl.go:88-93), so `min > max` yields max for every
	// record rather than a bound that depends on which ran last. config does not
	// refuse min > max -- the result is predictable and an operator may want it --
	// and this comment is what a reader of such a policy is owed.
	Min uint32 `yaml:"min,omitempty"`
}

// Clamp is the built plugin.
type Clamp struct {
	max uint32
	min uint32
}

// Exec bounds the TTL of the response already in the context.
//
// **It reads `qCtx.R()` and never sets it**, which is what makes it usable at the
// end of a chain: the forward has already produced the answer, and the clamp only
// shapes what the answer carries. An answer that is not there is left alone rather
// than manufactured -- a clamp that produced an empty answer would turn "no
// response" into "SERVFAIL-shaped response" and hide the upstream's failure.
//
// It is a plain `sequence.Executable`, so a sequence that names it must do so with
// `exec: $tag` AFTER the forward in the same sequence. Being present in the plugin
// table is not enough: nothing runs a plugin nobody execs, and a clamp that is
// registered, rendered and never called is the failure this package's own test
// exists to catch.
func (c *Clamp) Exec(_ context.Context, qCtx *query_context.Context) error {
	if response := qCtx.R(); response != nil {
		if c.min > 0 {
			dnsutils.ApplyMinimalTTL(response, c.min)
		}
		if c.max > 0 {
			dnsutils.ApplyMaximumTTL(response, c.max)
		}
	}
	return nil
}

// Init builds the clamp, and refuses a configuration that would expire everything.
//
// A clamp with neither bound is not a clamp: it is a plugin entry that loads, does
// nothing, and makes the routing document harder to read for it. The renderer does
// not emit one, so reaching this is a fault in something that wrote the document by
// hand -- and it is refused here as well as there, because the two are different
// documents and only one of them goes through this code.
func Init(_ *coremain.BP, args any) (any, error) {
	values, ok := args.(*Args)
	if !ok {
		return nil, fmt.Errorf("%s: wrong argument type %T", PluginType, args)
	}
	if values.Max == 0 && values.Min == 0 {
		return nil, fmt.Errorf(
			"%s: neither max nor min is set, so this entry would load and do nothing. "+
				"A bound of 0 does NOT mean 'no bound' to mosdns -- ApplyMaximumTTL(m, 0) sets "+
				"every record's TTL to 0 (pkg/dnsutils/msg.go:65-67), so the renderer omits "+
				"the key rather than writing a zero, and this refuses a document that wrote one",
			PluginType,
		)
	}
	return &Clamp{max: values.Max, min: values.Min}, nil
}
