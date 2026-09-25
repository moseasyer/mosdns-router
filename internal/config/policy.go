package config

import (
	"fmt"
	"math"
)

type Policy struct {
	SchemaVersion int           `yaml:"schema_version"`
	Schedule      string        `yaml:"schedule"`
	Foreign       ForeignPolicy `yaml:"foreign"`
	CDN           CDNPolicy     `yaml:"cdn"`
	ECH           ECHPolicy     `yaml:"ech"`
	DHCP          DHCPPolicy    `yaml:"dhcp"`
	Cache         CachePolicy   `yaml:"cache"`
}

type ForeignPolicy struct {
	DefaultProvider string `yaml:"default_provider"`
	ECS             bool   `yaml:"ecs"`
}

type CDNPolicy struct {
	IPVersion                string           `yaml:"ip_version"`
	SuppressAAAA             bool             `yaml:"suppress_aaaa"`
	Cloudflare               CloudflarePolicy `yaml:"cloudflare"`
	LatencyCandidateCount    int              `yaml:"latency_candidate_count"`
	Combined                 CombinedPolicy   `yaml:"combined"`
	SwitchImprovementPercent float64          `yaml:"switch_improvement_percent"`
	Health                   HealthPolicy     `yaml:"health"`
	Bandwidth                BandwidthPolicy  `yaml:"bandwidth"`
}

type CloudflarePolicy struct {
	MaxCandidates int `yaml:"max_candidates"`
}

type CombinedPolicy struct {
	LatencyTop   int `yaml:"latency_top"`
	BandwidthTop int `yaml:"bandwidth_top"`
}

type HealthPolicy struct {
	IntervalSeconds  int `yaml:"interval"`
	FailureThreshold int `yaml:"failure_threshold"`
}

type BandwidthPolicy struct {
	DailyBytes          int64 `yaml:"daily_budget"`
	PerCandidateBytes   int64 `yaml:"per_candidate_limit"`
	PerCandidateSeconds int   `yaml:"per_candidate_seconds"`
}

type ECHPolicy struct {
	Enabled           bool     `yaml:"enabled"`
	FailurePolicy     string   `yaml:"failure_policy"`
	StaleGraceSeconds int      `yaml:"stale_grace"`
	Sources           []string `yaml:"sources"`
}

type DHCPPolicy struct {
	FailurePolicy string `yaml:"failure_policy"`
}

type CachePolicy struct {
	PersistentDump bool `yaml:"persistent_dump"`
}

func (p Policy) Validate() error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1")
	}
	if !validSchedule(p.Schedule) {
		return fmt.Errorf("schedule must be a valid HH:MM time")
	}
	if p.Foreign.DefaultProvider == "" {
		return fmt.Errorf("foreign.default_provider must not be empty")
	}
	if p.CDN.IPVersion == "" {
		return fmt.Errorf("cdn.ip_version must not be empty")
	}
	if p.CDN.Cloudflare.MaxCandidates <= 0 {
		return fmt.Errorf("cdn.cloudflare.max_candidates must be greater than zero")
	}
	if p.CDN.LatencyCandidateCount <= 0 {
		return fmt.Errorf("cdn.latency_candidate_count must be greater than zero")
	}
	if p.CDN.Combined.LatencyTop <= 0 {
		return fmt.Errorf("cdn.combined.latency_top must be greater than zero")
	}
	if p.CDN.Combined.BandwidthTop <= 0 {
		return fmt.Errorf("cdn.combined.bandwidth_top must be greater than zero")
	}
	if math.IsNaN(p.CDN.SwitchImprovementPercent) || math.IsInf(p.CDN.SwitchImprovementPercent, 0) || p.CDN.SwitchImprovementPercent < 0 {
		return fmt.Errorf("cdn.switch_improvement_percent must be non-negative and finite")
	}
	if p.CDN.Health.IntervalSeconds <= 0 {
		return fmt.Errorf("cdn.health.interval must be greater than zero")
	}
	if p.CDN.Health.FailureThreshold <= 0 {
		return fmt.Errorf("cdn.health.failure_threshold must be greater than zero")
	}
	if p.CDN.Bandwidth.DailyBytes <= 0 {
		return fmt.Errorf("cdn.bandwidth.daily_budget must be greater than zero")
	}
	if p.CDN.Bandwidth.PerCandidateBytes <= 0 {
		return fmt.Errorf("cdn.bandwidth.per_candidate_limit must be greater than zero")
	}
	if p.CDN.Bandwidth.PerCandidateSeconds <= 0 {
		return fmt.Errorf("cdn.bandwidth.per_candidate_seconds must be greater than zero")
	}
	if p.ECH.StaleGraceSeconds < 0 {
		return fmt.Errorf("ech.stale_grace must be non-negative")
	}
	if p.ECH.FailurePolicy != "strict" && p.ECH.FailurePolicy != "fallback" {
		return fmt.Errorf("ech.failure_policy must be strict or fallback")
	}
	if p.DHCP.FailurePolicy != "disable-current" && p.DHCP.FailurePolicy != "use-last-good" {
		return fmt.Errorf("dhcp.failure_policy must be disable-current or use-last-good")
	}
	return nil
}

func validSchedule(value string) bool {
	if len(value) != len("HH:MM") || value[2] != ':' {
		return false
	}
	for _, index := range []int{0, 1, 3, 4} {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	hour := int(value[0]-'0')*10 + int(value[1]-'0')
	minute := int(value[3]-'0')*10 + int(value[4]-'0')
	return hour <= 23 && minute <= 59
}
