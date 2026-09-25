package config

func Defaults() Policy {
	return Policy{
		SchemaVersion: 1,
		Schedule:      "03:00",
		Foreign: ForeignPolicy{
			DefaultProvider: "Quad9 Secure DNSCrypt v2",
			ECS:             false,
		},
		CDN: CDNPolicy{
			IPVersion:                "IPv4",
			SuppressAAAA:             true,
			Cloudflare:               CloudflarePolicy{MaxCandidates: 512},
			LatencyCandidateCount:    10,
			Combined:                 CombinedPolicy{LatencyTop: 3, BandwidthTop: 3},
			SwitchImprovementPercent: 10,
			Health: HealthPolicy{
				IntervalSeconds:  120,
				FailureThreshold: 3,
			},
			Bandwidth: BandwidthPolicy{
				DailyBytes:          100 * 1024 * 1024,
				PerCandidateBytes:   10 * 1024 * 1024,
				PerCandidateSeconds: 3,
			},
		},
		ECH: ECHPolicy{
			Enabled:           true,
			FailurePolicy:     "strict",
			StaleGraceSeconds: 900,
			Sources:           []string{"cloudflare-ech.com"},
		},
		DHCP: DHCPPolicy{
			FailurePolicy: "disable-current",
		},
		Cache: CachePolicy{
			PersistentDump: false,
		},
	}
}
