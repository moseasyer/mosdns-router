package state

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const SchemaVersion = 1

type DHCPState struct {
	SchemaVersion  int       `json:"schema_version"`
	Generation     uint64    `json:"generation"`
	Interface      string    `json:"interface"`
	ConnectionUUID string    `json:"connection_uuid"`
	Upstreams      []string  `json:"upstreams"`
	ObservedAt     time.Time `json:"observed_at"`
	Source         string    `json:"source"`
	LastGood       bool      `json:"last_good"`
}

type Selector struct {
	SchemaVersion    int               `json:"schema_version"`
	Generation       uint64            `json:"generation"`
	Mode             string            `json:"mode"`
	Provider         string            `json:"provider"`
	WinnerIP         string            `json:"winner_ip,omitempty"`
	WinnerProofUntil time.Time         `json:"winner_proof_until,omitempty"`
	FallbackIP       string            `json:"fallback_ip,omitempty"`
	CloudFront       map[string]string `json:"cloudfront,omitempty"`
	LastSuccess      time.Time         `json:"last_success,omitempty"`
	LastFailure      string            `json:"last_failure,omitempty"`
	ConfigSHA256     string            `json:"config_sha256"`
}

type ECHState struct {
	SchemaVersion int       `json:"schema_version"`
	Generation    uint64    `json:"generation"`
	Source        string    `json:"source"`
	FetchedAt     time.Time `json:"fetched_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	StaleUntil    time.Time `json:"stale_until"`
	ConfigSHA256  string    `json:"config_sha256"`
	PublicName    string    `json:"public_name"`
	Status        string    `json:"status"`
}

type BandwidthBudgetState struct {
	SchemaVersion int    `json:"schema_version"`
	LocalDate     string `json:"local_date"`
	LimitBytes    int64  `json:"limit_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
}

type HealthState struct {
	SchemaVersion       int       `json:"schema_version"`
	Healthy             bool      `json:"healthy"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	LastFailure         time.Time `json:"last_failure,omitempty"`
}

func NewDHCPState(generation uint64, interfaceName, connectionUUID string, upstreams []string, observedAt time.Time, source string, lastGood bool) DHCPState {
	return DHCPState{
		SchemaVersion:  SchemaVersion,
		Generation:     generation,
		Interface:      interfaceName,
		ConnectionUUID: connectionUUID,
		Upstreams:      cloneStrings(upstreams),
		ObservedAt:     observedAt.UTC(),
		Source:         source,
		LastGood:       lastGood,
	}
}

func NewSelector(generation uint64, mode, provider string, now time.Time) Selector {
	return Selector{
		SchemaVersion: SchemaVersion,
		Generation:    generation,
		Mode:          mode,
		Provider:      provider,
		LastSuccess:   now.UTC(),
	}
}

func NewECHState(generation uint64, source string, fetchedAt, expiresAt, staleUntil time.Time, configSHA256, publicName, status string) ECHState {
	return ECHState{
		SchemaVersion: SchemaVersion,
		Generation:    generation,
		Source:        source,
		FetchedAt:     fetchedAt.UTC(),
		ExpiresAt:     expiresAt.UTC(),
		StaleUntil:    staleUntil.UTC(),
		ConfigSHA256:  configSHA256,
		PublicName:    publicName,
		Status:        status,
	}
}

func (s DHCPState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	for index, upstream := range s.Upstreams {
		if !validIPAddress(upstream) {
			return fmt.Errorf("upstreams[%d] must be a valid IP address", index)
		}
	}
	return nil
}

func (s Selector) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if s.Mode != "auto" && s.Mode != "manual" && s.Mode != "disabled" {
		return fmt.Errorf("mode must be auto, manual, or disabled")
	}
	if strings.TrimSpace(s.Provider) == "" {
		return fmt.Errorf("provider must not be empty")
	}
	if s.WinnerIP != "" && !validIPv4Address(s.WinnerIP) {
		return fmt.Errorf("winner_ip must be a valid IPv4 address")
	}
	if s.FallbackIP != "" && !validIPv4Address(s.FallbackIP) {
		return fmt.Errorf("fallback_ip must be a valid IPv4 address")
	}
	return nil
}

func (s ECHState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if s.Status != "fresh" && s.Status != "stale" && s.Status != "invalid" {
		return fmt.Errorf("status must be fresh, stale, or invalid")
	}
	return nil
}

func (s BandwidthBudgetState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if !validLocalDate(s.LocalDate) {
		return fmt.Errorf("local_date must be a valid YYYY-MM-DD calendar date")
	}
	if s.LimitBytes < 0 {
		return fmt.Errorf("limit_bytes must be non-negative")
	}
	if s.UsedBytes < 0 {
		return fmt.Errorf("used_bytes must be non-negative")
	}
	return nil
}

func (s HealthState) Validate() error {
	if err := validateSchema(s.SchemaVersion); err != nil {
		return err
	}
	if s.ConsecutiveFailures < 0 {
		return fmt.Errorf("consecutive_failures must be non-negative")
	}
	return nil
}

func validateSchema(version int) error {
	if version != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	return nil
}

func validIPAddress(value string) bool {
	_, err := netip.ParseAddr(value)
	return err == nil
}

func validIPv4Address(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Unmap().Is4()
}

func validLocalDate(value string) bool {
	if len(value) != len("2006-01-02") || value[4] != '-' || value[7] != '-' {
		return false
	}
	date, err := time.Parse("2006-01-02", value)
	if err != nil || date.Year() < 1 || date.Format("2006-01-02") != value {
		return false
	}
	return true
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}
