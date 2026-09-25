# DNSCrypt and Domain Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route China-set domains through the dynamic DHCP plugin and every other domain through a loopback dnscrypt-proxy configured by default with authenticated Quad9 Secure DNSCrypt v2 stamps.

**Architecture:** `internal/dnscrypt` renders a deterministic `dnscrypt-proxy.toml`; `internal/rules` downloads and converts a pinned `v2fly/domain-list-community` snapshot; `internal/mosdnsconfig` renders the routing sequence. Integration tests run the custom MOSDNS binary against local DHCP and foreign DNS mocks and prove there is no fallback path.

**Tech Stack:** Go 1.25, YAML v3, dnscrypt-proxy 2.1.18 configuration format, MOSDNS v5.3.4, `miekg/dns`, local UDP/TCP DNS servers.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- No generated domestic upstream may contain a Chinese public DNS address.
- Foreign user queries must enter `127.0.0.1:15353` over TCP and must never fall back to the DHCP plugin.
- The local DNSCrypt listener must serve TCP as well as UDP, because the foreign forward uses TCP.
- DNSCrypt configuration must use complete DNS stamps, not bare resolver IPs.
- Default DNSCrypt endpoints are Quad9 Secure DNSCrypt v2, IPv4, no ECS, with authenticated provider certificates.
- Plain bootstrap is used only for DNSCrypt provider-name resolution and must not receive ordinary user queries.
- DNS rules are pinned by source commit and SHA-256; failed downloads keep last-known-good.
- System services are not installed in this plan.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- `server_names` must contain resolver names, while each `[static]` entry's `stamp` contains a complete stamp.
- `ignore_system_dns=true` and a non-53 loopback listener are mandatory to prevent bootstrap loops.
- A SERVFAIL from the foreign resolver must not trigger the domestic branch.
- Unsupported or cyclic `include:` entries in domain-rule data must fail without replacing the last valid list.
- The generated MOSDNS sequence must preserve DNSSEC/EDNS behavior apart from the later explicitly synthetic response paths.

---

## File Map

```text
internal/dnscrypt/config.go
internal/dnscrypt/config_test.go
internal/rules/convert.go
internal/rules/download.go
internal/rules/convert_test.go
internal/rules/download_test.go
internal/mosdnsconfig/render.go
internal/mosdnsconfig/render_test.go
cmd/mosdns-cdnctl/main.go
cmd/mosdns-cdnctl/main_test.go
configs/policy.yaml
configs/dnscrypt-proxy.toml
configs/mosdns.yaml
tests/integration/routing_test.go
Makefile
```

### Interfaces produced by this plan

```go
package dnscrypt

type Stamp struct { Name string; Value string }
func Defaults() []Stamp
func Render(policy config.Policy, stamps []Stamp) ([]byte, error)

package rules
type SourceLock struct {
    Repository string `json:"repository"`
    Commit     string `json:"commit"`
    SHA256     string `json:"sha256"`
    Entry      string `json:"entry"`
}
func ConvertFS(fs.FS, entry string) ([]string, error)
func Download(ctx context.Context, client *http.Client, lock SourceLock) (SourceLock, []byte, error)

package mosdnsconfig
type Paths struct { Policy, CNDomains, DHCPState, ForeignListener, Listen string }
func ProductionPaths() Paths
func Render(p config.Policy, paths Paths) ([]byte, error)

package config
func Marshal(policy Policy) ([]byte, error)
```

---

### Task 1: Render authenticated Quad9 DNSCrypt configuration

**Files:**
- Create: `internal/dnscrypt/config.go`
- Create: `internal/dnscrypt/config_test.go`
- Create: `configs/dnscrypt-proxy.toml`

**Interfaces:**
- Consumes: `config.ForeignPolicy` and complete static stamps.
- Produces: a deterministic TOML document for dnscrypt-proxy 2.1.18.

- [ ] **Step 1: Write failing default-stamp tests**

```go
func TestDefaultsAreQuad9SecureV4WithoutECS(t *testing.T) {
    got := Defaults()
    if len(got) != 3 { t.Fatalf("got %d stamps", len(got)) }
    for _, s := range got {
        if !strings.HasPrefix(s.Value, "sdns://AQMAAAAAAAAA") {
            t.Fatalf("not a Secure IPv4 DNSCrypt stamp: %s", s.Value)
        }
    }
}
```

- [ ] **Step 2: Write failing rendered-config tests**

Decode the output with a TOML parser and assert:

- `listen_addresses` contains only `127.0.0.1:15353`;
- the listener serves TCP as well as UDP, which dnscrypt-proxy does for every listen address, so the configuration must not narrow it and the rendered `dnscrypt-proxy.toml` must carry no protocol restriction on that address;
- `server_names` exactly matches the three static names;
- `ignore_system_dns = true`;
- `cache = false`;
- `ipv4_servers = true`, `ipv6_servers = false`, `dnscrypt_servers = true`, `doh_servers = false`, `odoh_servers = false`;
- `require_dnssec = true`, `require_nolog = true`, `require_nofilter = false`;
- no ECS stamp is present;
- no Chinese DNS address is present.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./internal/dnscrypt -v
```

Expected: compile failure.

- [ ] **Step 4: Implement the exact default stamps**

Use these current Quad9 Secure DNSCrypt v2 IPv4 endpoints:

```go
{Name: "quad9-dnscrypt-ip4-filter-1", Value: "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"},
{Name: "quad9-dnscrypt-ip4-filter-2", Value: "sdns://AQMAAAAAAAAAEjE0OS4xMTIuMTEyLjk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"},
{Name: "quad9-dnscrypt-ip4-filter-3", Value: "sdns://AQMAAAAAAAAAFDE0OS4xMTIuMTEyLjExMjo4NDQzIGfIR7jIdYzRICRVQ751Z0bfNN8dhMALjEcDaN-CHYY-GTIuZG5zY3J5cHQtY2VydC5xdWFkOS5uZXQ"},
```

The third value is not a local correction. It is byte-for-byte what
`https://quad9.net/dnscrypt/quad9-resolvers.md` serves for
`dnscrypt-ip4-filter-alt2` as of 2026-09-26, as are the first two, and a diff
against that list must come back empty.

An earlier copy of the list, and this plan's first draft, carried a corrupt string
for that endpoint. Both forms declare the same 25-byte provider name, but the stale
one fills those 25 bytes with `2.dnscrypt.dnscrypt-cert.` instead of
`2.dnscrypt-cert.quad9.net` and then appends nine leftover bytes (`quad9.net`). The
stale string therefore differs in 15 contiguous bytes at offsets 74-88 and is nine
bytes longer, while its protocol byte, property word, every length byte, its
address `149.112.112.112:8443` and its 32-byte provider public key are
byte-for-byte identical to the live value's and to the other two endpoints'. The
pinned decoder reads the declared name, finds the leftovers, and refuses the stale
stamp with `Invalid stamp (garbage after end)`; dnscrypt-proxy 2.1.18 then exits
255 with `Stamp error for the static [quad9-dnscrypt-ip4-filter-3] definition`,
checked against a real 2.1.18 build. The stale string is retained only as a test
fixture, because a stamp that does not decode is a mistake the renderer has to
refuse.

- [ ] **Step 5: Implement deterministic TOML rendering**

Use ordered sections, single-quoted stamp values, and a trailing newline. Reject empty or duplicate names and values that do not begin with `sdns://`. Permit custom stamps only when the user explicitly supplies them; defaults are not merged with custom policy. Set `bootstrap_resolvers = ['9.9.9.9:53', '149.112.112.9:53']` only for DNSCrypt provider-name resolution, with an adjacent generated comment stating that ordinary user queries never use this path.

- [ ] **Step 6: Generate the default config and test it**

```bash
go test ./internal/dnscrypt -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/dnscrypt configs/dnscrypt-proxy.toml
git commit -m "feat: configure Quad9 DNSCrypt v2"
```

---

### Task 2: Convert pinned China domain rules

**Files:**
- Create: `internal/rules/convert.go`
- Create: `internal/rules/download.go`
- Create: `internal/rules/convert_test.go`
- Create: `internal/rules/download_test.go`
- Modify: `cmd/mosdns-cdnctl/main.go`
- Create: `cmd/mosdns-cdnctl/main_test.go`

**Interfaces:**
- Consumes: a pinned repository archive and entry path `data/cn`.
- Produces: sorted MOSDNS domain expressions and `source-lock.json` metadata.

- [ ] **Step 1: Write failing conversion tests**

Use an in-memory FS containing:

```text
data/cn                 domain:example.cn
                         full:exact.cn
                         keyword:测试
                         include:shared
                         # comment
data/shared             regexp:^static[0-9]+\.example\.cn$
```

Assert recursive include expansion, stable sorting, deduplication, and preservation of supported MOSDNS forms. Add tests for missing include, include cycle, unsupported directive, and empty output.

- [ ] **Step 2: Write failing download tests**

Use `httptest.Server` to return a deterministic GitHub-like archive and commit metadata. Assert the downloader records repository, resolved commit, archive SHA-256, and entry path; rejects a checksum mismatch before extraction; and never overwrites the caller-provided last-known-good output on failure. Add CLI tests with an injected rules service: `--check` reports drift without writes, while `--pin-remote` writes both lock and converted list only after success.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./internal/rules -v
```

Expected: compile failure.

- [ ] **Step 4: Implement bounded recursive conversion**

Support `include:`, `domain:`, `full:`, `keyword:`, and `regexp:`. Ignore blank lines and comments. Reject unknown non-comment directives rather than silently dropping security-sensitive rules. Detect include cycles using a visiting stack and cap recursion at 32 files.

- [ ] **Step 5: Implement archive download and pinning**

Use `archive/tar` plus `gzip`, reject absolute paths, `..`, symlinks, devices, and files above 4 MiB. The initial update command may resolve the current reviewed upstream commit and archive digest, but subsequent runtime reads only the committed `SourceLock`.

- [ ] **Step 6: Add explicit list-management commands**

Implement:

```text
mosdns-cdnctl update-lists --check
mosdns-cdnctl update-lists --pin-remote HEAD
```

`--check` downloads metadata into memory and reports whether the locked commit/archive differs without writing files. `--pin-remote` resolves the remote commit once, verifies and converts the archive, writes `source-lock.json` and `cn-domains.txt` atomically, and prints the accepted commit and digest. Neither mode may use the system resolver to fetch rule files.

- [ ] **Step 7: Run tests**

```bash
go test ./internal/rules ./cmd/mosdns-cdnctl -v
go test -race ./internal/rules ./cmd/mosdns-cdnctl -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/rules cmd/mosdns-cdnctl/main.go cmd/mosdns-cdnctl/main_test.go
git commit -m "feat: add pinned China domain conversion"
```

---

### Task 3: Render the MOSDNS domestic/foreign sequence

**Files:**
- Create: `internal/mosdnsconfig/render.go`
- Create: `internal/mosdnsconfig/render_test.go`
- Create: `configs/policy.yaml`
- Create: `configs/mosdns.yaml`

**Interfaces:**
- Consumes: `config.Policy`, fixed system paths, and the CN rule file.
- Produces: a v5 YAML sequence that can be loaded by `mosdns-router start`.

- [ ] **Step 1: Write failing renderer tests**

Parse the rendered YAML into a generic node and assert these tags exist exactly once:

```text
cn_domains
dhcp_forward
foreign_forward
foreign_cache
cn_path
foreign_path
main
udp_server
tcp_server
```

Assert both servers listen on `127.0.0.1:53`, foreign forward points only to `tcp://127.0.0.1:15353`, and CN dispatch checks `qname $cn_domains` before default foreign dispatch. The foreign upstream is TCP because MOSDNS v5.3.4's stock UDP transport was measured re-sending unanswered queries and dropping answers that arrived before its exchange waited for them -- the same behavior the domestic branch stopped accepting by owning its own one-write UDP exchange, and the foreign branch has no such client, so it is given the transport that does not lose a query.

- [ ] **Step 2: Write failing safety tests**

Reject empty paths, a foreign listener on port 53, a domestic state path under `/etc`, and a generated configuration containing known Chinese public DNS strings. The last check is a defense-in-depth scan, not a substitute for the data-flow tests.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./internal/mosdnsconfig -v
```

Expected: compile failure.

- [ ] **Step 4: Implement the renderer**

Render this behavior:

```text
main:
  if qname matches cn_domains -> goto cn_path
  otherwise                    -> goto foreign_path
cn_path:
  dhcp_forward (generation-scoped domestic cache is internal to this plugin)
  accept
foreign_path:
  foreign_cache
  if has_resp -> accept
  foreign_forward
  accept
```

Render `dhcp_forward` with `cache_entries: 4096`, `upstream_port: 53` and the policy's own `dhcp.failure_policy`; its cache is generation-scoped and therefore cannot return an answer from the previous DHCP DNS set. A published DHCP state carries bare addresses, so the port is a property of this configuration and is written out rather than left to the plugin's default. Later plans insert `cdn_rewrite` around the foreign cache/forward path.

The rendered document is built from typed values and marshalled once, never concatenated out of strings, and the finished bytes are scanned for the known Chinese public resolvers. A `cache.persistent_dump: true` policy is refused rather than rendered as a cache with nowhere to dump to.

- [ ] **Step 5: Add default policy and config files**

`configs/policy.yaml` must be byte-for-byte the output of `config.Marshal(config.Defaults())`. `configs/mosdns.yaml` must be byte-for-byte the output of `mosdnsconfig.Render(config.Defaults(), mosdnsconfig.ProductionPaths())`, and must use:

```text
/var/lib/mosdns/lists/cn-domains.txt
/run/mosdns/dhcp-upstreams.json
tcp://127.0.0.1:15353
127.0.0.1:53
```

The China list lives under `/var/lib`, not `/etc`, because the list updater
rewrites it while the router runs and `/etc` stays read-only root-owned
configuration that a package upgrade owns; the renderer refuses a China list or
state document path under `/etc` for the same reason.

The listener entry is the foreign upstream `tcp://127.0.0.1:15353`, never a `udp://` URL, and it has to agree with the `listen_addresses` of `configs/dnscrypt-proxy.toml`. No user-specific DHCP address appears in the file. Both files are generated by the code (`MOSDNS_ROUTER_UPDATE=1 go test ./internal/config ./internal/mosdnsconfig`) and are never hand-edited.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/mosdnsconfig ./internal/config -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/mosdnsconfig configs/policy.yaml configs/mosdns.yaml
git commit -m "feat: render domestic and foreign routing"
```

---

### Task 4: Prove routing and fail-closed behavior end to end

**Files:**
- Create: `tests/integration/routing_test.go`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `mosdns-router`, `internal/testdns`, rendered temporary config, and controlled DHCP state.
- Produces: deterministic proof of query destination and failure isolation.

- [ ] **Step 1: Write the failing routing integration test**

Start one domestic mock and one foreign mock on loopback high ports. Render a config whose foreign listener points to the foreign mock and whose DHCP state points to the domestic mock. Start the built router and query:

```text
example.cn A       -> domestic mock only
example.com A      -> foreign mock only
```

- [ ] **Step 2: Add leak and truncation cases**

Stop the foreign mock and assert `example.com` returns SERVFAIL while its query count at the domestic mock does not increase. Assert the foreign query reached the mock over TCP, because a foreign forward left on `udp://` is the transport that drops and duplicates answers. Query HTTPS type 65 and a >512-byte TXT response to exercise arbitrary type and large-answer behavior over TCP.

- [ ] **Step 3: Add a startup guard test**

Start the router with a missing or corrupt DHCP state file. Assert it still starts and the foreign path works, while the domestic path fails closed.

- [ ] **Step 4: Run the test and verify initial failure**

```bash
make build
go test ./tests/integration -run TestRouting -v
```

Expected: fail until the test harness and required config behavior are complete.

- [ ] **Step 5: Complete only the integration wiring**

Build a temporary executable path from `build/mosdns-router`, allocate free ports, wait for the UDP/TCP listener, use context timeouts, and always terminate the child process. Do not install services or modify `/etc/resolv.conf`.

- [ ] **Step 6: Run integration and full tests**

```bash
go test ./tests/integration -v
go test ./...
```

Expected: PASS with zero foreign-to-domestic fallback.

- [ ] **Step 7: Commit**

```bash
git add tests/integration/routing_test.go Makefile
git commit -m "test: prove domestic and foreign isolation"
```

---

## Plan Acceptance

Run:

```bash
go test ./internal/dnscrypt ./internal/rules ./internal/mosdnsconfig -v
go test ./tests/integration -run TestRouting -v
go test ./...
```

Expected:

- Quad9 static stamps render correctly and contain no ECS endpoint.
- China rules convert reproducibly from a pinned archive.
- China queries reach only the DHCP mock.
- Other queries reach only the foreign mock.
- Foreign failure never leaks to the domestic path.
- No host service or resolver configuration is changed.
