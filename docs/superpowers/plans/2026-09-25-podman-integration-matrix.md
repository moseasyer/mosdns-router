# Podman Integration Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove installation, NetworkManager integration, DNS routing, CDN/ECH behavior, failure isolation, upgrade, uninstall, and rollback for Ubuntu 22.04/24.04/26.04 entirely inside disposable Podman machines and containers.

**Architecture:** A Python harness owns a rootful Podman machine, a private network, a mock DHCP/DNS router, target Ubuntu systemd containers, and a mock CDN. The development host is only used to build artifacts and read before/after snapshots; no project installer runs directly on it. amd64 uses an x86_64 Podman machine; arm64 acceptance requires a native arm64 Podman connection and is never mislabeled when skipped.

**Tech Stack:** Python 3 standard library, Podman machine/container/network, Ubuntu official images, systemd, NetworkManager, systemd-resolved, dnsmasq mock router, local TLS server, Mozilla Firefox headless for live ECH verification.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- The current development host is never a target; do not run installer/uninstaller there.
- Do not mount host `/etc`, `/run`, `/var`, `/sys`, or `/home` into target containers.
- Source is mounted read-only; artifacts and mutable test data use VM/container volumes.
- All target containers run systemd as PID 1 and use fixed Ubuntu image digests.
- Deterministic mock tests are mandatory; real-network tests are explicit opt-in.
- Do not mark a skipped architecture or live ECH test as passed.
- Default test data must not include a real force-ECH production domain.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- A failed scenario must still tear down the VM/container and publish logs.
- Host before/after snapshots must be byte-stable except documented build/Podman tool data.
- DHCP DNS changes must be driven through the mock router and observed by NetworkManager.
- Killing dnscrypt-proxy must produce foreign SERVFAIL without a domestic fallback.
- A live ECH pass must verify encrypted ClientHello behavior without installing a CA or modifying Firefox DoH.

---

## File Map

```text
tests/podman/run.py
tests/podman/lib/podman.py
tests/podman/lib/snapshot.py
tests/podman/lib/report.py
tests/podman/images/target.Containerfile
tests/podman/images/mock-router.Containerfile
tests/podman/images/mock-cdn.Containerfile
tests/podman/images.lock.json
tests/podman/mock-router/dnsmasq.conf
tests/podman/mock-cdn/server.go
tests/podman/scenarios/install_test.py
tests/podman/scenarios/dhcp_test.py
tests/podman/scenarios/routing_test.py
tests/podman/scenarios/failure_test.py
tests/podman/scenarios/cdn_ech_test.py
tests/podman/scenarios/upgrade_uninstall_test.py
tests/podman/scenarios/firefox_live.py
tests/podman/tests/test_command.py
tests/podman/tests/test_report.py
docs/testing.md
Makefile
```

### Command-line interfaces produced by this plan

```text
python3 tests/podman/run.py preflight
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04
python3 tests/podman/run.py live-ech --connection NAME --domain HOSTNAME
python3 tests/podman/run.py cleanup
```

Exit codes: 0 all requested tests passed; 1 test failure; 2 harness/configuration error; 3 incomplete matrix or skipped required architecture.

---

### Task 1: Build a testable Podman command wrapper and lifecycle guard

**Files:**
- Create: `tests/podman/lib/podman.py`
- Create: `tests/podman/lib/report.py`
- Create: `tests/podman/tests/test_command.py`
- Create: `tests/podman/tests/test_report.py`
- Create: `tests/podman/run.py`

**Interfaces:**
- Consumes: Podman executable, machine name, connection socket, and test version list.
- Produces: typed command results, lifecycle cleanup, and machine-readable reports.

- [ ] **Step 1: Write failing subprocess tests**

Use a fake executable to assert exact argument arrays for:

```text
podman machine inspect NAME --format {{.ConnectionInfo.PodmanSocket.Path}}
podman machine init --rootful --cpus 4 --memory 4096 --disk-size 30 --volume SOURCE:/workspace:ro,security_model=none NAME
podman machine start NAME
podman --remote --url unix://SOCKET ps --format json
podman machine stop NAME
podman machine rm -f NAME
```

- [ ] **Step 2: Write failing report tests**

Assert per-version status is `passed|failed|skipped|incomplete`; required skips make overall status `incomplete`; logs are attached; JSON output is stable; secrets and full command environments are not recorded.

- [ ] **Step 3: Run tests and verify failure**

```bash
python3 -m unittest discover -s tests/podman/tests -v
```

Expected: import failure.

- [ ] **Step 4: Implement safe subprocess execution**

Use argument arrays, `check=True`, explicit timeouts, captured stdout/stderr, and a redacted environment. Never invoke `shell=True`. A remote Podman URL is obtained from machine inspect rather than guessed.

- [ ] **Step 5: Implement machine lifecycle**

Refuse to reuse a machine with a different provider/rootful mode. `cleanup` removes containers, network, volume, then machine; it continues after individual teardown errors and returns a consolidated failure only if the machine remains.

- [ ] **Step 6: Run unit tests**

```bash
python3 -m unittest discover -s tests/podman/tests -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add tests/podman/run.py tests/podman/lib tests/podman/tests
git commit -m "test: add isolated Podman harness"
```

---

### Task 2: Add host snapshots and fixed Ubuntu images

**Files:**
- Create: `tests/podman/lib/snapshot.py`
- Create: `tests/podman/images/target.Containerfile`
- Create: `tests/podman/images/mock-router.Containerfile`
- Create: `tests/podman/images/mock-cdn.Containerfile`
- Create: `tests/podman/images.lock.json`
- Create: `docs/testing.md`

**Interfaces:**
- Consumes: read-only host state and Ubuntu image references.
- Produces: before/after snapshots and fixed-digest base image parameters.

- [ ] **Step 1: Write failing snapshot tests**

With a fake command runner, assert collection of:

```text
/etc/os-release
/etc/resolv.conf symlink target
NetworkManager active connection summary
resolvectl DNS/status summary
systemd project unit list
listening sockets
Firefox profile path names, mtimes, and sizes only
```

No file contents from Firefox profiles may be read.

- [ ] **Step 2: Implement snapshot normalization**

Sort output, redact environment-specific UUIDs only when they are not relevant to the test, and hash structured records. Create a UTC run ID and write snapshots under `build/test-results/RUN_ID/host-before.json` and `host-after.json`.

- [ ] **Step 3: Create Containerfiles**

Target image installs `systemd-sysv`, `dbus`, `NetworkManager`, `systemd-resolved`, `python3`, `iproute2`, `dnsutils`, `curl`, `ca-certificates`, and test tools, but does not install the project package at build time. Mock router installs `dnsmasq`; mock CDN is built from the repository's Go module.

- [ ] **Step 4: Resolve and lock image digests**

Run inside the disposable machine:

```bash
podman pull docker.io/library/ubuntu:22.04
podman pull docker.io/library/ubuntu:24.04
podman pull docker.io/library/ubuntu:26.04
```

Use `podman image inspect --format '{{.Digest}}'` and write the resulting full OCI reference strings to `images.lock.json` with version keys `22.04`, `24.04`, and `26.04`. Build commands construct `docker.io/library/ubuntu:VERSION@` plus the inspected digest at runtime and reject a lock entry without the `sha256:` prefix.

- [ ] **Step 5: Document environment prerequisites**

State that Podman must already exist, the harness never installs it automatically, arm64 requires a native arm64 Podman connection, and all test output lives under `build/test-results`.

- [ ] **Step 6: Run static tests**

```bash
python3 -m unittest discover -s tests/podman/tests -v
python3 -m json.tool tests/podman/images.lock.json >/dev/null
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add tests/podman/lib/snapshot.py tests/podman/images tests/podman/images.lock.json docs/testing.md
git commit -m "test: lock isolated Ubuntu images"
```

---

### Task 3: Create the private network and mock DHCP/DNS router

**Files:**
- Create: `tests/podman/mock-router/dnsmasq.conf`
- Create: `tests/podman/scenarios/dhcp_test.py`
- Modify: `tests/podman/run.py`

**Interfaces:**
- Consumes: target interface name and desired DNS address.
- Produces: real DHCP lease/DNS events for NetworkManager inside the target container.

- [ ] **Step 1: Write scenario assertions**

The scenario must prove NetworkManager obtains IPv4 by DHCP, publishes the mock DNS, then receives a new DNS address after mock-router reload. It records DHCP events and `/run/mosdns/dhcp-upstreams.json` without touching the host.

- [ ] **Step 2: Create a fixed private network**

Use subnet `10.89.0.0/24` and fixed addresses:

```text
mock-router 10.89.0.2
target       10.89.0.10
mock-cdn     10.89.0.20
client       10.89.0.30
```

Enable DNS only for the private network. Do not publish ports to the host.

- [ ] **Step 3: Implement mock-router control**

Run dnsmasq with DHCP range `10.89.0.100-10.89.0.199`, router option `10.89.0.2`, and configurable DNS addresses. A control command rewrites only the container-private dnsmasq config, sends HUP, and waits for target NM `dns-change`/lease evidence.

- [ ] **Step 4: Make target use NetworkManager**

Inside the target container, create an Ethernet connection for `eth0` with `ipv4.method auto`, `ipv4.never-default yes`, and initially automatic DNS. Confirm `IP4.DNS` contains the mock address before running the package installer.

- [ ] **Step 5: Run the scenario in the VM**

```bash
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04 --scenario dhcp
```

Expected: PASS; host snapshot unchanged.

- [ ] **Step 6: Commit**

```bash
git add tests/podman/mock-router tests/podman/scenarios/dhcp_test.py tests/podman/run.py
git commit -m "test: drive NetworkManager DHCP in Podman"
```

---

### Task 4: Install the package and test systemd/systemd-resolved routing

**Files:**
- Create: `tests/podman/scenarios/install_test.py`
- Create: `tests/podman/scenarios/routing_test.py`
- Modify: `tests/podman/run.py`

**Interfaces:**
- Consumes: built `.deb`, mock router, and a test-only foreign DNS listener.
- Produces: evidence that native units and NetworkManager integration work across Ubuntu versions.

- [ ] **Step 1: Start the target systemd container**

Use the locked image, `--systemd=always`, `--cgroupns=host`, `--privileged` only inside the disposable VM, and the private network fixed IP. Do not mount host system directories. Copy the `.deb` with `podman cp`, then install it inside the container.

- [ ] **Step 2: Validate packaged units**

Run `systemd-analyze verify`, `systemctl is-enabled/is-active`, and `ss -lntup`. Assert only loopback listeners for project services and successful `journalctl -b` service startup.

- [ ] **Step 3: Validate NetworkManager handoff**

Assert preinstall DNS equals the mock router, postinstall active NM DNS equals `127.0.0.1`, `/etc/resolv.conf` still targets resolved stub, and the bridge state retains the original mock DNS.

- [ ] **Step 4: Add a test-only foreign override**

For deterministic offline routing, copy a modified `/etc/mosdns/config.yaml` inside the container so only the foreign forward address points to a private mock listener. Production shipped config and packaged DNSCrypt config remain unchanged and are asserted separately.

- [ ] **Step 5: Query routing paths**

From a separate client container and from inside the target, query China-set and foreign test names. Assert query counters at mock domestic and foreign listeners. Repeat over UDP and TCP.

- [ ] **Step 6: Run all three amd64 versions**

```bash
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04 --scenario install,routing
```

Expected: PASS for each version.

- [ ] **Step 7: Commit**

```bash
git add tests/podman/scenarios/install_test.py tests/podman/scenarios/routing_test.py tests/podman/run.py
git commit -m "test: install package in Ubuntu matrix"
```

---

### Task 5: Add failure, CDN/ECH, upgrade, and uninstall scenarios

**Files:**
- Create: `tests/podman/mock-cdn/server.go`
- Create: `tests/podman/scenarios/failure_test.py`
- Create: `tests/podman/scenarios/cdn_ech_test.py`
- Create: `tests/podman/scenarios/upgrade_uninstall_test.py`
- Modify: `tests/podman/run.py`

**Interfaces:**
- Consumes: running target, selector test fixtures, and mock CDN.
- Produces: system-level failure and lifecycle evidence.

- [ ] **Step 1: Implement the mock CDN server**

Serve certificate-authenticated `cloudflare.test` and `distribution.test` names, Cloudflare-style and CloudFront-style headers, expected body markers, a small file, and a large throttled file. Never use `InsecureSkipVerify` in the client scenario.

- [ ] **Step 2: Add deterministic failure injections**

Cover DNSCrypt process stopped, DHCP DNS stopped, state corruption, ECH source timeout, bad selector, disk-full simulation, and simultaneous manual/automatic lock attempts. Assert fail-closed/no-leak behavior and last-known-good preservation.

- [ ] **Step 3: Add CDN/ECH system assertions**

Use test-only force-ECH `cloudflare.test`. Assert strict A/AAAA are empty, HTTPS RR has ECH/mandatory/ipv4hint, non-ECH client cannot connect, and a fallback-policy run can connect. Use private test addresses and mock certificates; this is not a live ECH claim.

- [ ] **Step 4: Add upgrade/uninstall scenario**

Install version 0.1.0, create selector/ECH/user candidate state, rebuild/install the next test package version with preserved state, then uninstall. Assert state survives upgrade, ordinary uninstall preserves it, purge removes it, and NM settings restore only when ownership marker/current values match.

- [ ] **Step 5: Add emergency rollback scenario**

Change DNS to local, stop MOSDNS, run emergency rollback, and assert the original mock DHCP DNS is restored and the machine remains usable.

- [ ] **Step 6: Run deterministic matrix**

```bash
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04 --scenario failure,cdn-ech,upgrade-uninstall
```

Expected: PASS for each version.

- [ ] **Step 7: Commit**

```bash
git add tests/podman/mock-cdn tests/podman/scenarios tests/podman/run.py
git commit -m "test: cover DNS failure and lifecycle matrix"
```

---

### Task 6: Add opt-in live Firefox ECH verification

**Files:**
- Create: `tests/podman/scenarios/firefox_live.py`
- Modify: `tests/podman/run.py`
- Modify: `docs/testing.md`

**Interfaces:**
- Consumes: an explicit native Podman connection and user-supplied live Cloudflare test hostname.
- Produces: Firefox/packet evidence without changing Firefox DoH or trusting a custom CA.

- [ ] **Step 1: Require explicit live-test inputs**

Refuse to run unless both a Podman connection name and a hostname are supplied. Record only hostname, Firefox version, and pass/fail evidence. Do not query browsing history.

- [ ] **Step 2: Install official Firefox inside the VM**

Download the official Linux tarball inside the target container, record the actual version, and run headless under Xvfb. Do not enable snap, DoH, a local CA, or a proxy.

- [ ] **Step 3: Configure only the test allowlist**

Resolve the current Cloudflare address through the foreign path, validate it with Host/SNI, pin it manually, add the hostname to the test force-ECH file, and restart only the router service if required.

- [ ] **Step 4: Verify ECH without MITM**

Capture packets on the VM private interface and assert the target hostname does not appear in plaintext TLS ClientHello SNI while the expected outer SNI may appear. Also record Firefox `about:networking` diagnostic evidence where accessible. Packet capture is read-only and must not modify traffic.

- [ ] **Step 5: Classify live results honestly**

Return `passed`, `failed`, or `skipped` for network unavailability. A skip cannot satisfy the ECH completion criterion and must be reported as incomplete.

- [ ] **Step 6: Document the exact command**

```bash
python3 tests/podman/run.py live-ech --connection mosdns-arm64-live --domain hostname-provided-by-operator
```

The hostname is a runtime input, not a source placeholder.

- [ ] **Step 7: Commit**

```bash
git add tests/podman/scenarios/firefox_live.py tests/podman/run.py docs/testing.md
git commit -m "test: add opt-in live Firefox ECH check"
```

---

### Task 7: Add arm64 gating, host-isolation comparison, and cleanup

**Files:**
- Create: `tests/podman/tests/test_matrix.py`
- Modify: `tests/podman/run.py`
- Modify: `Makefile`
- Modify: `docs/testing.md`

**Interfaces:**
- Consumes: completed version reports, host snapshots, and optional arm64 connection.
- Produces: release gate with explicit incomplete states.

- [ ] **Step 1: Write failing matrix-gate tests**

Assert all three amd64 versions pass, any required version failure fails the run, missing arm64 makes overall status `incomplete`, and an arm64 pass changes it to pass only when live ECH is separately passed or explicitly reported incomplete per policy.

- [ ] **Step 2: Write failing host-isolation comparison**

Ignore only documented build caches and Podman machine data. Any difference in NM summary, resolved state, resolv.conf link, project units, listeners, or Firefox profile metadata fails the run.

- [ ] **Step 3: Implement arm64 execution**

Accept `MOSDNS_ARM64_PODMAN_CONNECTION` pointing to a native arm64 Podman service. Reject user-mode QEMU reports as native acceptance. Run the same version/scenario list and collect a separate report.

- [ ] **Step 4: Add Make targets**

```make
.PHONY: test-system test-system-amd64 test-system-arm64 test-system-clean
test-system:
	python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04
test-system-amd64: test-system
test-system-arm64:
	python3 tests/podman/run.py matrix --connection "$${MOSDNS_ARM64_PODMAN_CONNECTION}" --arch arm64 --versions 22.04,24.04,26.04
test-system-clean:
	python3 tests/podman/run.py cleanup
```

- [ ] **Step 5: Run harness unit tests and preflight**

```bash
python3 -m unittest discover -s tests/podman/tests -v
python3 tests/podman/run.py preflight
```

Expected: unit tests pass; preflight reports missing Podman clearly on the current host rather than installing it.

- [ ] **Step 6: Commit**

```bash
git add tests/podman/tests/test_matrix.py tests/podman/run.py Makefile docs/testing.md
git commit -m "test: gate cross-version host isolation"
```

---

## Plan Acceptance

Run:

```bash
python3 -m unittest discover -s tests/podman/tests -v
python3 tests/podman/run.py preflight
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04
python3 tests/podman/run.py cleanup
```

Then run the same matrix on a native arm64 Podman connection and the explicit live Firefox ECH command when available.

Expected:

- all deterministic scenarios pass on each Ubuntu version;
- no host network, resolver, service, or Firefox metadata changes;
- arm64 and live ECH are reported honestly as pass/fail/incomplete;
- teardown removes the disposable machine, containers, network, and volumes.
