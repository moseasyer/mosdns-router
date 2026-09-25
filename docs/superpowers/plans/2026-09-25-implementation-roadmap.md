# MOSDNS Router Implementation Roadmap

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

This roadmap decomposes the approved design into seven independently reviewable implementation plans. Execute them in order; later plans depend on interfaces produced by earlier plans.

| Order | Plan | Independently testable deliverable |
|---:|---|---|
| 1 | `2026-09-25-mosdns-router-foundation.md` | Reproducible Go workspace, strict policy loading, atomic state schema, lock, build/test entry points |
| 2 | `2026-09-25-dynamic-dhcp-routing.md` | NetworkManager-compatible DHCP bridge and hot-reload `dhcp_forward` MOSDNS plugin |
| 3 | `2026-09-25-dnscrypt-domain-routing.md` | Quad9 DNSCrypt configuration, China rule conversion, domestic/foreign MOSDNS sequence |
| 4 | `2026-09-25-cdn-selector-optimizer.md` | Candidate collection, 100 MiB optimizer, scoring, pin/unpin, health checks |
| 5 | `2026-09-25-dns-response-rewrite-ech.md` | Cloudflare/CloudFront A/AAAA rewrite and strict/fallback ECH response plugin |
| 6 | `2026-09-25-native-system-packaging.md` | Hardened systemd units, transactional installer/uninstaller, Ubuntu `.deb` artifacts |
| 7 | `2026-09-25-podman-integration-matrix.md` | Disposable Podman VM test harness and Ubuntu 22.04/24.04/26.04 matrix |

## Cross-plan rules

- Every task uses TDD and ends with a focused commit.
- No plan may modify the development host's NetworkManager, resolved, Firefox, `/etc/resolv.conf`, or installed DNS services.
- Real-network checks are opt-in; deterministic mock checks are mandatory.
- No default Chinese public DNS may appear in generated configuration.
- All runtime state writes use same-directory temporary files, `fsync`, validation, and atomic rename.
- No implementation may add a local DoH listener, a custom CA, TLS interception, SNI DPI, ClearDNS, or Docker runtime dependencies.
- ECH force-mode domains come only from the user-maintained allowlist.
- CloudFront mappings are per-domain and never inferred solely from an AWS CIDR match.
- The 100 MiB daily bandwidth budget is enforced in code, not only in the scheduler.
- System-level verification runs only in the Podman plan.
