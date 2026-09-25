// Package status renders the small, non-sensitive subset of runtime state
// exposed by mosdns-cdnctl.
package status

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"mosdns-router/internal/state"
)

type field struct {
	key   string
	value string
}

// RenderSelector writes the approved selector status fields as sorted
// key=value lines. Optional values that are empty are omitted so an absent
// fallback or winner cannot be mistaken for a configured address.
func RenderSelector(w io.Writer, value state.Selector) error {
	fields := []field{
		{key: "generation", value: strconv.FormatUint(value.Generation, 10)},
		{key: "mode", value: value.Mode},
		{key: "provider", value: value.Provider},
		{key: "schema_version", value: strconv.Itoa(value.SchemaVersion)},
	}
	if value.WinnerIP != "" {
		fields = append(fields, field{key: "winner_ip", value: value.WinnerIP})
	}
	if value.FallbackIP != "" {
		fields = append(fields, field{key: "fallback_ip", value: value.FallbackIP})
	}
	if !value.WinnerProofUntil.IsZero() {
		fields = append(fields, timestampField("winner_proof_until", value.WinnerProofUntil))
	}
	if !value.LastSuccess.IsZero() {
		fields = append(fields, timestampField("last_success", value.LastSuccess))
	}
	return writeSortedFields(w, fields)
}

// RenderDHCP writes the non-sensitive DHCP state fields as sorted key=value
// lines. The upstream set is rendered in its state order; only the field names
// are sorted, not the addresses, because their order is part of the observed
// state.
func RenderDHCP(w io.Writer, value state.DHCPState) error {
	fields := []field{
		{key: "connection_uuid", value: value.ConnectionUUID},
		{key: "generation", value: strconv.FormatUint(value.Generation, 10)},
		{key: "interface", value: value.Interface},
		{key: "last_good", value: strconv.FormatBool(value.LastGood)},
		{key: "schema_version", value: strconv.Itoa(value.SchemaVersion)},
		{key: "source", value: value.Source},
		{key: "upstreams", value: strings.Join(value.Upstreams, ",")},
	}
	if !value.ObservedAt.IsZero() {
		fields = append(fields, timestampField("observed_at", value.ObservedAt))
	}
	return writeSortedFields(w, fields)
}

// RenderECH writes only the approved ECH status metadata. In particular, it
// does not attempt to render an ECHConfig value or any future state field.
func RenderECH(w io.Writer, value state.ECHState) error {
	fields := []field{
		{key: "config_sha256", value: value.ConfigSHA256},
		{key: "generation", value: strconv.FormatUint(value.Generation, 10)},
		{key: "public_name", value: value.PublicName},
		{key: "schema_version", value: strconv.Itoa(value.SchemaVersion)},
		{key: "source", value: value.Source},
		{key: "status", value: value.Status},
	}
	if !value.FetchedAt.IsZero() {
		fields = append(fields, timestampField("fetched_at", value.FetchedAt))
	}
	if !value.ExpiresAt.IsZero() {
		fields = append(fields, timestampField("expires_at", value.ExpiresAt))
	}
	if !value.StaleUntil.IsZero() {
		fields = append(fields, timestampField("stale_until", value.StaleUntil))
	}
	return writeSortedFields(w, fields)
}

func timestampField(key string, value time.Time) field {
	return field{key: key, value: value.UTC().Format(time.RFC3339Nano)}
}

// writeSortedFields is a private formatting primitive shared by the three
// typed renderers. The state-to-field allowlists remain in the typed functions
// above; this helper never receives a runtime state through an untyped API.
//
// Every value is checked before anything is written. A value carrying a newline
// or any other control character would otherwise forge extra `key=value` lines
// in the status report, and a report that fails halfway through is as
// misleading as a forged one, so a rejected value produces no output at all.
func writeSortedFields(w io.Writer, fields []field) error {
	for _, current := range fields {
		if err := checkRenderedValue(current); err != nil {
			return err
		}
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].key < fields[j].key
	})
	for _, current := range fields {
		if _, err := fmt.Fprintf(w, "%s=%s\n", current.key, current.value); err != nil {
			return err
		}
	}
	return nil
}

func checkRenderedValue(current field) error {
	if strings.ContainsFunc(current.value, isControlCharacter) {
		return fmt.Errorf("field %s contains a control character", current.key)
	}
	return nil
}

// isControlCharacter reports the bytes that can forge a `key=value` line or
// corrupt a terminal. Only the C0 range and DEL qualify: every state value the
// renderers accept is ASCII, so a higher code point is a real character and not
// a control sequence.
func isControlCharacter(character rune) bool {
	return character < ' ' || character == 0x7f
}
