# Dynamic DHCP Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture router-provided DHCP DNS from NetworkManager on Ubuntu 22.04/24.04/26.04 and hot-swap a custom MOSDNS `dhcp_forward` plugin without restarting MOSDNS or creating a DNS loop.

**Architecture:** A Python 3 standard-library dispatcher collects raw DHCP DNS through `nmcli`/NetworkManager D-Bus-backed output and publishes versioned JSON under `/run/mosdns`. A Go MOSDNS plugin lazily reloads that file, keeps old upstream generations alive long enough for in-flight queries, races at most two domestic upstreams, and retries truncated UDP answers over TCP.

**Tech Stack:** Python 3.10+ standard library, Go 1.25, MOSDNS v5.3.4 plugin APIs, `miekg/dns`, `fcntl.flock`, local UDP/TCP DNS mocks.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- Never hardcode a Chinese public DNS; the only domestic addresses come from the active DHCP configuration.
- Do not use `127.0.0.53` or `127.0.0.54` as an upstream.
- Preserve IPv6 link-local scope when the router supplies a scoped DNS address.
- Do not restart MOSDNS for a DHCP DNS change.
- Do not interrupt already-issued queries when swapping upstream generations.
- Support the common NetworkManager dispatcher events on all three Ubuntu releases; `dns-change` is optional.
- Python bridge code must remain compatible with Python 3.10 and use only the standard library.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- `ignore-auto-dns` must not erase access to the original DHCP DNS values.
- Empty, duplicated, loopback, resolved, and link-local addresses must be handled differently.
- DHCP lease renewal with unchanged DNS must not rewrite the state file or flush caches.
- A truncated UDP response must retry over TCP without sending the original query twice to the same protocol.
- A corrupt state file must not replace the last valid in-memory upstream generation.
- A DHCP generation change must invalidate the plugin's domestic cache before any new query can receive an old-generation answer.

---

## File Map

```text
bridge/mosdns_dhcp_bridge/__init__.py
bridge/mosdns_dhcp_bridge/cli.py
bridge/mosdns_dhcp_bridge/collect.py
bridge/mosdns_dhcp_bridge/publish.py
bridge/tests/test_collect.py
bridge/tests/test_publish.py
plugin/executable/dhcp_forward/dhcp_forward.go
plugin/executable/dhcp_forward/runtime.go
plugin/executable/dhcp_forward/dhcp_forward_test.go
internal/testdns/server.go
cmd/mosdns-router/main.go
```

### Interfaces produced by this plan

Python interfaces:

- `collect_dns(env: Mapping[str, str], interface: str, run: CommandRunner) -> list[str]`
- `publish_if_changed(path: str, *, interface: str, connection_uuid: str, upstreams: Sequence[str], source: str, now: datetime.datetime) -> bool`
- `CommandRunner` is `Callable[[Sequence[str]], str]`.

```go
// plugin/executable/dhcp_forward/dhcp_forward.go
const PluginType = "dhcp_forward"

type Args struct {
    StateFile          string `yaml:"state_file"`
    UpstreamTimeoutMS  int    `yaml:"upstream_timeout_ms"`
    Concurrency        int    `yaml:"concurrency"`
    RetireAfterSeconds int    `yaml:"retire_after_seconds"`
    CacheEntries       int    `yaml:"cache_entries"`
    UpstreamPort       int    `yaml:"upstream_port"`
    FailurePolicy      string `yaml:"failure_policy"`
}

func New(args Args, bp *coremain.BP) (sequence.Executable, error)
```

`upstream_port` and `failure_policy` were added by the DNSCrypt and domain
routing plan, which renders them: a published state carries bare addresses, and
the policy's `dhcp.failure_policy` decides whether a generation that names no
resolver is adopted (the default, `disable-current`) or refused in favour of the
last generation that could answer (`use-last-good`).

The JSON written by Python must validate as `state.DHCPState` from the foundation plan.

---

### Task 1: Collect and normalize NetworkManager DHCP DNS

**Files:**
- Create: `bridge/mosdns_dhcp_bridge/__init__.py`
- Create: `bridge/mosdns_dhcp_bridge/collect.py`
- Create: `bridge/tests/test_collect.py`

**Interfaces:**
- Consumes: dispatcher environment and an injected command runner.
- Produces: `collect_dns(env, interface, run)`.

- [ ] **Step 1: Write failing source-priority tests**

Create fixtures for an `up` event and a `dhcp4-change` event. Assert that `collect_dns` uses values in this order:

1. `DHCP4_DOMAIN_NAME_SERVERS` or `DHCP6_DOMAIN_NAME_SERVERS`;
2. `nmcli -g DHCP4.OPTION_DOMAIN_NAME_SERVERS,DHCP6.OPTION_DOMAIN_NAME_SERVERS device show INTERFACE`;
3. `nmcli -g IP4.DNS,IP6.DNS device show INTERFACE`;
4. `resolvectl dns INTERFACE`, always filtering local addresses.

Use a fake runner that records exact argument arrays; do not execute NetworkManager in unit tests.

- [ ] **Step 2: Write failing normalization tests**

Cover:

Create table-driven tests with concrete inputs and expected values:

```python
def test_deduplicates_and_filters_local_addresses(self):
    got = collect_dns({}, "enp3s0", lambda args: "192.168.1.1 127.0.0.53 192.168.1.1")
    self.assertEqual(got, ["192.168.1.1"])

def test_keeps_ipv6_link_local(self):
    got = collect_dns({"DHCP6_DOMAIN_NAME_SERVERS": "fe80::1"}, "enp3s0", lambda args: "")
    self.assertEqual(got, ["fe80::1"])

def test_rejects_invalid_value_without_dropping_valid_value(self):
    got = collect_dns({"DHCP4_DOMAIN_NAME_SERVERS": "not-an-ip 192.168.1.53"}, "enp3s0", lambda args: "")
    self.assertEqual(got, ["192.168.1.53"])

def test_empty_result_is_valid(self):
    got = collect_dns({"DHCP4_DOMAIN_NAME_SERVERS": "127.0.0.54"}, "enp3s0", lambda args: "")
    self.assertEqual(got, [])
```

Expected normalized values are bare addresses such as `192.168.1.1` and `fe80::1`; the bridge stores the interface separately and the Go plugin adds the zone when building a scoped endpoint.

- [ ] **Step 3: Run tests and verify failure**

```bash
python3 -m unittest discover -s bridge/tests -v
```

Expected: import failure for `mosdns_dhcp_bridge.collect`.

- [ ] **Step 4: Implement the source adapter**

Use `ipaddress.ip_address`. Split on whitespace, commas, and semicolons; trim brackets. Reject unspecified, multicast, loopback, link-local IPv4, `127.0.0.0/8`, `127.0.0.53`, and `127.0.0.54`. Preserve IPv6 link-local addresses and stable IPv4-before-IPv6 ordering.

Run `nmcli` with argument arrays, never a shell string:

```python
["nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS,DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", interface]
```

- [ ] **Step 5: Implement environment parsing**

Only accept the event interface from `NM_DISPLAY_NAME`/`DEVICE` after verifying it against a conservative interface-name regex. Reject values containing whitespace, `/`, or shell metacharacters.

- [ ] **Step 6: Run bridge tests**

```bash
python3 -m unittest discover -s bridge/tests -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add bridge/mosdns_dhcp_bridge bridge/tests/test_collect.py
git commit -m "feat: collect NetworkManager DHCP DNS"
```

---

### Task 2: Publish versioned DHCP state atomically

**Files:**
- Create: `bridge/mosdns_dhcp_bridge/publish.py`
- Create: `bridge/mosdns_dhcp_bridge/cli.py`
- Create: `bridge/tests/test_publish.py`

**Interfaces:**
- Consumes: normalized addresses and current UTC time.
- Produces: `/run/mosdns/dhcp-upstreams.json`, compatible with `state.DHCPState`, and CLI exit code 0 for unchanged/no-DNS events.

- [ ] **Step 1: Write failing publication tests**

Test that:

Create tests with a temporary state file and fixed UTC time:

```python
NOW = datetime.datetime(2026, 9, 25, 0, 0, tzinfo=datetime.timezone.utc)

def publish(self, upstreams, path=None, now=NOW):
    target = path or self.state_path
    return publish_if_changed(
        target,
        interface="enp3s0",
        connection_uuid="11111111-1111-1111-1111-111111111111",
        upstreams=upstreams,
        source="dhcp4",
        now=now,
    )

def test_first_publish_writes_generation_one(self):
    self.assertTrue(self.publish(["192.168.1.1"]))
    data = json.loads(self.state_path.read_text())
    self.assertEqual(data["generation"], 1)
    self.assertEqual(data["upstreams"], ["192.168.1.1"])

def test_unchanged_dns_does_not_rewrite_file(self):
    self.publish(["192.168.1.1"])
    before = self.state_path.stat().st_mtime_ns
    self.assertFalse(self.publish(["192.168.1.1"], now=NOW + datetime.timedelta(hours=1)))
    self.assertEqual(self.state_path.stat().st_mtime_ns, before)

def test_changed_dns_increments_generation(self):
    self.publish(["192.168.1.1"])
    self.assertTrue(self.publish(["192.168.1.53"]))
    self.assertEqual(json.loads(self.state_path.read_text())["generation"], 2)

def test_empty_dns_disables_current_interface(self):
    self.publish(["192.168.1.1"])
    self.assertTrue(self.publish([]))
    data = json.loads(self.state_path.read_text())
    self.assertEqual(data["upstreams"], [])
    self.assertFalse(data["last_good"])

def test_corrupt_existing_state_keeps_file_and_fails(self):
    self.state_path.write_text("{")
    with self.assertRaises(ValueError):
        self.publish(["192.168.1.1"])
    self.assertEqual(self.state_path.read_text(), "{")
```

Capture inode/mtime to prove unchanged events do not write.

- [ ] **Step 2: Run tests and verify failure**

```bash
python3 -m unittest bridge.tests.test_publish -v
```

Expected: import failure.

- [ ] **Step 3: Implement locking and comparison**

Use a separate `/run/mosdns/dhcp-bridge.lock`, `fcntl.flock(LOCK_EX|LOCK_NB)`, JSON schema version 1, and RFC 3339 UTC timestamps. If interface, connection UUID, sorted upstream list, and source are unchanged, return `False` without opening the target for writing.

- [ ] **Step 4: Implement atomic publication**

Write `dhcp-upstreams.json.tmp` in `/run/mosdns`, `flush`, `os.fsync`, chmod `0640`, `os.replace`, and fsync the directory. Never write a partial target file.

- [ ] **Step 5: Implement the CLI**

Accept only:

```text
mosdns-dhcp-bridge --state-file PATH --lock-file PATH
```

Read dispatcher variables from `os.environ`. Exit 0 on success/no change, 2 for invalid input, 3 for a lock conflict, and 4 for an invalid existing state. Do not invoke `resolvectl reconfig` or edit NetworkManager here.

- [ ] **Step 6: Run tests**

```bash
python3 -m unittest discover -s bridge/tests -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add bridge/mosdns_dhcp_bridge/publish.py bridge/mosdns_dhcp_bridge/cli.py bridge/tests/test_publish.py
git commit -m "feat: publish atomic DHCP DNS state"
```

---

### Task 3: Build the hot-reload MOSDNS upstream plugin

**Files:**
- Create: `plugin/executable/dhcp_forward/runtime.go`
- Create: `plugin/executable/dhcp_forward/dhcp_forward.go`
- Create: `internal/testdns/server.go`
- Create: `plugin/executable/dhcp_forward/dhcp_forward_test.go`
- Modify: `cmd/mosdns-router/main.go`

**Interfaces:**
- Consumes: `state.DHCPState`, MOSDNS `sequence.Executable`, and `upstream.NewUpstream`.
- Produces: plugin tag `dhcp_forward` and the runtime interface used later by the full sequence.

- [ ] **Step 1: Write a local DNS test server**

`internal/testdns/server.go` must provide a controllable UDP/TCP server:

```go
type Handler func(context.Context, *dns.Msg) *dns.Msg
type Server struct { /* private */ }
func Start(handler Handler) (*Server, error)
func (s *Server) Address() string
func (s *Server) Close() error
```

It must record query protocol, QNAME, and QTYPE and support forcing UDP truncation.

- [ ] **Step 2: Write failing plugin tests**

Cover:

```go
func TestForwardsToCurrentDHCPGeneration(t *testing.T)
func TestCachesSuccessfulResponseWithinGeneration(t *testing.T)
func TestGenerationChangeClearsDomesticCacheBeforeLookup(t *testing.T)
func TestDoesNotCacheSERVFAILOrEmptyState(t *testing.T)
func TestEmptyStateReturnsErrorWithoutResponse(t *testing.T)
func TestHotSwapDoesNotCloseOldGenerationBeforeRetirement(t *testing.T)
func TestRacesAtMostTwoDistinctUpstreams(t *testing.T)
func TestTruncatedUDPRetriesOverTCP(t *testing.T)
func TestCorruptReloadKeepsCurrentGeneration(t *testing.T)
func TestPluginCloseClosesAllUDPAndTCPClients(t *testing.T)
```

Use `query_context.NewContext` with one-question messages and call `Exec` directly.

- [ ] **Step 3: Run tests and verify failure**

```bash
go test ./plugin/executable/dhcp_forward -v
```

Expected: compile failure for missing plugin/runtime.

- [ ] **Step 4: Implement runtime generations**

Represent each generation with UDP and TCP `upstream.Upstream` pairs. Check the state file's modtime/generation before each query; load and validate it while holding an RLock. Swap an `atomic.Pointer[runtimeGeneration]`, create a fresh bounded domestic cache for that generation, and retire the previous cache before serving a new-generation lookup. Cache keys include qname, qtype, DO/CD flags, and the DHCP generation; successful NOERROR/NXDOMAIN entries expire at their minimum TTL, while SERVFAIL/REFUSED and empty-state errors are never cached. Retain replaced upstream generations for 60 seconds, then close them, guaranteeing the five-second query timeout cannot lose an in-flight client.

- [ ] **Step 5: Implement upstream exchange**

For each query, first look up the generation-scoped domestic cache. On a miss, copy the wire-format message, choose at most `min(2, len(upstreams))` distinct endpoints, apply the configured per-upstream timeout, and return the first valid response. On UDP `TC=1`, send the same question to that endpoint's TCP client. Store only a copy belonging to the still-current generation. Do not treat an empty generation as a successful empty response.

- [ ] **Step 6: Register the plugin**

Register with:

```go
const PluginType = "dhcp_forward"
coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
```

Validate defaults: 5000 ms timeout, concurrency 2, retirement 60 seconds, 4096 cache entries, non-empty state file. Add a blank import of the package to `cmd/mosdns-router/main.go`.

- [ ] **Step 7: Run plugin and race tests**

```bash
go test ./plugin/executable/dhcp_forward -v
go test -race ./plugin/executable/dhcp_forward -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/mosdns-router/main.go internal/testdns plugin/executable/dhcp_forward
git commit -m "feat: add hot reload DHCP forwarding plugin"
```

---

### Task 4: Verify bridge/plugin JSON compatibility and routing behavior

**Files:**
- Create: `bridge/tests/fixtures/dhcp-upstreams.json`
- Create: `internal/dhcpstate/verify.go`
- Create: `internal/dhcpstate/verify_test.go`

**Interfaces:**
- Consumes: a Python-produced fixture.
- Produces: `dhcpstate.VerifyFixture(path string) error`, used by packaging and Podman tests.

- [ ] **Step 1: Add a Python-generated fixture**

The fixture must contain schema version 1, generation 7, interface `enp3s0`, a UUID, two upstreams, a UTC `observed_at`, source `dhcp4`, and `last_good: true`.

- [ ] **Step 2: Write the failing Go verification test**

```go
func TestVerifyFixtureAcceptsBridgeState(t *testing.T) {
    if err := VerifyFixture("bridge/tests/fixtures/dhcp-upstreams.json"); err != nil {
        t.Fatal(err)
    }
}
```

- [ ] **Step 3: Implement strict fixture verification**

Call `state.ReadJSON` into `state.DHCPState`; reject unknown fields, schema mismatch, invalid addresses, local addresses, and inconsistent `last_good=false` with non-empty upstreams.

- [ ] **Step 4: Run cross-language checks**

```bash
python3 -m unittest discover -s bridge/tests -v
go test ./internal/dhcpstate -v
go test ./...
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bridge/tests/fixtures/dhcp-upstreams.json internal/dhcpstate
git commit -m "test: verify DHCP state across languages"
```

---

## Plan Acceptance

Run:

```bash
python3 -m unittest discover -s bridge/tests -v
go test -race ./plugin/executable/dhcp_forward ./internal/dhcpstate
go test ./...
```

Expected:

- Python and Go agree on state schema version 1.
- Unchanged DHCP renewals do not rewrite state.
- Hot swaps affect new queries without restarting MOSDNS.
- Truncated UDP answers use TCP.
- No test contacts or modifies host DNS services.
