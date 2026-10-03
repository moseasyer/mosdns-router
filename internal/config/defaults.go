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

// echDefaultSources are the nine domains the ECH key is fetched from.
//
// **All nine were MEASURED on 2026-10-03 to publish a byte-identical
// ECHConfigList** -- sha256 of the base64 payload 336cc2eb9ee1f248..., public_name
// cloudflare-ech.com for every one of them -- and that is what makes rotating
// between them safe: the key does not change, so which domain answered is not a fact
// a client can observe, and the public_name refusal in ech_provider never fires.
//
// **The list is spread over FIVE DISTINCT DNS ZONES, and the spread is the point
// rather than a decoration.** ECH is enabled per zone, not per platform: a zone
// dropping it is one edit, and a list made of nine hostnames inside one zone would
// lose all nine at the same instant. So the five zones here are
// cloudflare-ech.com, crypto.cloudflare.com, discordapp.com, cdn.discordapp.com
// and encryptedsni.com, and the remaining four entries are additional paths inside
// the zone that was measured to have it enabled throughout (every subdomain of
// encryptedsni.com tried returned an ech parameter).
//
// **A source that stops publishing an ech parameter costs nothing, and the reason
// is in ech_provider.refreshTick.** A tick asks successive sources until one of
// them ANSWERS rather than asking one and waiting for the next tick, because the
// rotation position advances once per attempt and the grace is fifteen to twenty
// minutes: a refresher that asked exactly one source per tick would walk nine
// sources in 45 minutes and the key would die before the rotation reached a source
// that answers. That is what makes a list this long survivable, and it is also why
// the number of sources does not change how often a source is asked.
//
// Two domains measured to publish an ECHConfigList are NOT here and must not be
// added. `defo.ie` publishes one whose public_name is cover.defo.ie, which is not
// interchangeable: it would become the inner SNI of every ClientHello this router
// rewrites, and no other site's edge accepts it. `cf.ech`, which Total-ECH
// recommends, does not resolve.
//
// **And a domain measured NOT to publish one must not be added either**, which is
// most of Cloudflare: cloudflare.com, www, developers, cdnjs, blog, dash, support,
// cloudflare-dns and cdn.cloudflare.com all return a NOERROR HTTPS record with no
// ech parameter. About ninety hostnames were probed on 2026-10-03 and only the five
// zones above answer with one.
var echDefaultSources = []string{
	// zone 1 of 5
	"cloudflare-ech.com",
	// zone 2 of 5
	"crypto.cloudflare.com",
	// zone 3 of 5
	"discordapp.com",
	// zone 4 of 5
	"cdn.discordapp.com",
	// zone 5 of 5, and the zone measured to have ECH enabled throughout, so the
	// remaining four entries are additional independent paths rather than four more
	// names for one zone's single outage.
	"encryptedsni.com",
	"www.encryptedsni.com",
	"ech.encryptedsni.com",
	"api.encryptedsni.com",
	"mail.encryptedsni.com",
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
