// Package dhcpstate verifies the DHCP state documents the NetworkManager bridge
// publishes, so packaging, the container image, and a cross-language test can
// refuse a document the router would refuse at runtime instead of shipping it.
package dhcpstate

import (
	"fmt"

	"mosdns-router/internal/state"
)

// VerifyFixture reports whether the state document at path is one the router can
// use: the same strict decoder the dhcp_forward plugin reads it with, plus the
// one rule the state schema leaves to the consumer.
//
// The decoder is the authority. state.ReadJSON refuses a field it does not know, a
// schema version it does not speak, a document with anything after it, and any
// upstream a domestic query could not be forwarded to, so none of that is restated
// here: a second copy of those rules is how a writer and a reader drift apart.
//
// The added rule is the last-known-good marker. A document that records resolvers
// while saying they were never vouched for describes a set the reader may not
// forward to, and the dhcp_forward runtime already refuses it before it builds a
// socket. Verifying it here means the refusal happens where the file is checked,
// before a query can be aimed at it.
func VerifyFixture(path string) error {
	var published state.DHCPState
	if err := state.ReadJSON(path, &published); err != nil {
		return fmt.Errorf("dhcp state at %s is not usable: %w", path, err)
	}
	if !published.LastGood && len(published.Upstreams) > 0 {
		return fmt.Errorf(
			"dhcp state at %s is not usable: it is not last known good but names %d upstream(s)",
			path, len(published.Upstreams),
		)
	}
	return nil
}
