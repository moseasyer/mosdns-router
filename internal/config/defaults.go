package config

// The ECH defaults below are the measured ones, and the derivation is written down
// because the constant they replace had none, which is the only reason it was wrong.
const (
	// echStaleGraceSeconds is how long a key past its own lifetime still serves, and
	// it is TWO refresh intervals: one failed fetch, and the retry after it. The
	// plugin refreshes every five minutes (echRotationInterval in
	// plugin/executable/cdn_rewrite/ech_provider.go), so ten minutes covers the one
	// fetch that fails and the one that replaces it.
	//
	// It was 900 seconds, and nothing in the repository said why. Measured against
	// the two references: Total-ECH's README says Cloudflare ROTATES HOURLY with the
	// config valid for more than three hours, and cloudflare-ech.com's HTTPS TTL
	// measured 295-300s. So fifteen minutes was twelve times tighter than the
	// validity window it sat inside, and a fifteen-minute source outage killed every
	// force-ECH domain at once while the key it was refusing was still good for two
	// hours and forty minutes more.
	//
	// The rotation makes this grace nearly unnecessary, and that is the better
	// argument for it: with three sources and a five-minute cadence, one failed
	// fetch is survived by the next interval landing on a DIFFERENT source. The
	// grace only has to cover the round-robin period, not the upstream's whole
	// validity window -- which is why it is two intervals and not a number anyone
	// has to look up.
	echStaleGraceSeconds = 600
)

// echDefaultSources are the three domains the ECH key is fetched from, and they are
// the three MEASURED on 2026-10-02 to publish a byte-identical ECHConfigList, all
// carrying public_name cloudflare-ech.com. That is what makes rotating between them
// safe: the key does not change, so which domain answered last week is not a fact a
// client can observe, and three sources instead of one means one of them going quiet
// costs one third of the key's freshness.
//
// Two domains measured to publish an ECHConfigList are NOT here and must not be
// added. `defo.ie` publishes one whose public_name is cover.defo.ie, which is not
// interchangeable: it would become the inner SNI of every ClientHello this router
// rewrites, and no other site's edge accepts it. `cf.ech`, which Total-ECH
// recommends, does not resolve.
var echDefaultSources = []string{
	"cloudflare-ech.com",
	"cdn.discordapp.com",
	"discordapp.com",
}

func Defaults() Policy {
	return Policy{
		SchemaVersion: 1,
		Schedule:      "03:00",
		Foreign: ForeignPolicy{
			DefaultProvider: "Quad9 Secure DNSCrypt v2",
			ECS:             false,
		},
		CDN: CDNPolicy{
			IPVersion:                requiredIPVersion,
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
				DailyBytes:          maximumDailyBudgetBytes,
				PerCandidateBytes:   maximumPerCandidateBytes,
				PerCandidateSeconds: maximumPerCandidateSeconds,
			},
		},
		ECH: ECHPolicy{
			Enabled:           true,
			FailurePolicy:     "strict",
			StaleGraceSeconds: echStaleGraceSeconds,
			Sources:           append([]string(nil), echDefaultSources...),
		},
		DHCP: DHCPPolicy{
			FailurePolicy: "disable-current",
		},
		Cache: CachePolicy{
			PersistentDump: false,
		},
	}
}
