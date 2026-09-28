# Podman Integration Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove installation, NetworkManager integration, DNS routing, CDN/ECH behavior, failure isolation, upgrade, uninstall, and rollback for Ubuntu 22.04/24.04/26.04 entirely inside disposable Podman containers.

**Architecture:** A Python harness owns a private Podman network, a mock DHCP/DNS router, target Ubuntu systemd containers, and a mock CDN. **There is no Podman machine and no virtual machine of any kind.** The development host runs rootless Podman directly; each target container has its own network namespace, so a test run that changes DNS changes only the container's DNS. The host is used to build artifacts and to read before/after snapshots; no project installer runs directly on it.

> **Why no Podman machine, and why it was not merely parked.** Podman machine requires `qemu-img` to create its disk image. On this host that binary, `qemu-system-x86_64`, `/dev/kvm` and any `vmx`/`svm` CPU flag are all absent, so `podman machine init` cannot create an image at all. It was built once, found to be unstartable, and removed together with the qemu packages; the user's decision is that no virtual machine is used. Rootless Podman containers are sufficient and are proven to work here.

> **How NetworkManager is made to manage a device — measured, not assumed.** A container's default rootless network hands it a **tun/tap** device, and NetworkManager refuses that device type by design (`GENERAL.TYPE: tun`, activation fails with *device is strictly unmanaged*). Use a **netavark bridge network**, which gives the container a real `eth0` of type `ethernet`. Even then, `nmcli device set eth0 managed yes` returns success and does **not** take effect until NetworkManager is restarted: the override is written persistently under `/run/NetworkManager/devices/`, and only a restart re-reads it. The target image's entrypoint must therefore do **`nmcli device set eth0 managed yes` and then `systemctl restart NetworkManager`**, after which profiles activate and NM runs a real DHCP client on the device. This corrects a conclusion reached in the previous plan, where the container was believed to be incapable of this.

**Tech Stack:** Python 3 standard library, rootless Podman container/network, Ubuntu official images, systemd, NetworkManager, systemd-resolved, dnsmasq mock router, local TLS server, Mozilla Firefox headless for live ECH verification.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- The current development host is never a target; do not run installer/uninstaller there.
- **No virtual machine, and no `podman machine`.** Containers only.
- A requirement a container cannot close is recorded **SKIPPED with its exact wording**. It is never closed by substituting a different kind of test, and a skip is never reported as a pass.
- Do not mount host `/etc`, `/run`, `/var`, `/sys`, or `/home` into target containers.
- Source is mounted read-only; artifacts and mutable test data use container volumes.
- All target containers run systemd as PID 1 and use fixed Ubuntu image digests.
- Deterministic mock tests are mandatory; real-network tests are explicit opt-in.
- Do not mark a skipped architecture or live ECH test as passed.
- Default test data must not include a real force-ECH production domain.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- A failed scenario must still tear down the containers and network and publish logs.
- Every SKIPPED item names the container's specific limitation, and a skip is never reported as a pass.
- **The previous plan's central SKIPPED list came from a wrong conclusion** — that a container cannot make NetworkManager manage a device. It can; see the architecture note. Do not inherit that conclusion without re-measuring it.
- Host before/after snapshots must be byte-stable except documented build/Podman tool data.
- DHCP DNS changes must be driven through the mock router and observed by NetworkManager.
- Killing dnscrypt-proxy must produce foreign SERVFAIL without a domestic fallback.
- **The NetworkManager device sequence is asserted, not assumed** — the previous plan's largest SKIPPED list came from concluding a container could not do this, and it can.
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
tests/podman/tests/test_target_entrypoint.py
docs/testing.md
Makefile
```

### Command-line interfaces produced by this plan

```text
python3 tests/podman/run.py preflight
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04
python3 tests/podman/run.py live-ech --domain HOSTNAME
python3 tests/podman/run.py cleanup
```

`--connection` is **not** a machine name. It is an optional Podman connection URI for a remote or native (e.g. arm64) service; omitted means the local rootless Podman, which is the acceptance path on this host.

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
- Consumes: Podman executable, an optional connection URI, the source tree path, and a test version list.
- Produces: typed command results, resource lifecycle/cleanup, and machine-readable reports.

- [ ] **Step 1: Write failing subprocess tests**

Use a fake executable to assert exact argument arrays for:

```text
podman version --format {{.Client.Version}}
podman info --format {{.Store.GraphDriverName}}
podman network create --subnet 10.89.0.0/24 mosdns-testnet
podman network inspect mosdns-testnet --format {{.Name}}
podman run -d --name NAME --network mosdns-testnet --systemd=always --cgroupns=private --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=SYS_PTRACE -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v SOURCE:/workspace:ro IMAGE
podman exec NAME sh -c ...
podman cp ARTIFACT NAME:/tmp/ARTIFACT
podman stop --time 30 NAME
podman rm -f NAME
podman network rm mosdns-testnet
```

Assert that **no** `podman machine` subcommand appears anywhere in the harness, and that the source tree is mounted **read-only** and never at `/etc`, `/run`, `/var`, `/sys` or `/home`. A test must fail if a host path outside the allowed set is ever mounted.

- [ ] **Step 2: Write failing report tests**

Assert per-version status is `passed|failed|skipped|incomplete`; required skips make overall status `incomplete`; logs are attached; JSON output is stable; secrets and full command environments are not recorded.

- [ ] **Step 3: Write a failing test for the NetworkManager device sequence**

The harness asserts, on a running target, that `nmcli -g GENERAL.NM-MANAGED device show eth0` is `yes` before any scenario runs, and fails with a message naming the two steps if it is not. This is the fact the previous plan got wrong, so it is checked at run time rather than assumed.

- [ ] **Step 4: Run tests and verify failure**

```bash
python3 -m unittest discover -s tests/podman/tests -v
```

Expected: import failure.

- [ ] **Step 5: Implement safe subprocess execution**

Use argument arrays, `check=True`, explicit timeouts, captured stdout/stderr, and a redacted environment. Never invoke `shell=True`. When a connection URI is supplied, pass it as `--connection` on every invocation rather than mutating global state.

- [ ] **Step 6: Implement resource lifecycle**

Name every container with a run-specific prefix. `cleanup` removes containers, then the network, then volumes; it continues after individual teardown errors, reports each, and returns a consolidated failure only if something of this run's remains. A failed scenario must still reach `cleanup` — hold that with a test where the scenario raises.

- [ ] **Step 7: Run unit tests**

```bash
python3 -m unittest discover -s tests/podman/tests -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add tests/podman/run.py tests/podman/lib tests/podman/tests
git commit -m "test: add isolated Podman container harness"
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

**The target's entrypoint must perform the NetworkManager device sequence** described in the Architecture note — `nmcli device set eth0 managed yes` followed by `systemctl restart NetworkManager` — and must **fail loudly** if `nmcli -g GENERAL.NM-MANAGED device show eth0` is not `yes` afterwards. A target that boots with an unmanaged device produces a scenario failure that looks like an installer bug, so this is checked at boot and the check is part of the image, not of each scenario. Do **not** add a `NetworkManager.conf.d` entry to force this; the override-and-restart path is the measured one.

- [ ] **Step 4: Resolve and lock image digests**

Run against the local rootless Podman:

```bash
podman pull docker.io/library/ubuntu:22.04
podman pull docker.io/library/ubuntu:24.04
podman pull docker.io/library/ubuntu:26.04
```

Use `podman image inspect --format '{{.Digest}}'` and write the resulting full OCI reference strings to `images.lock.json` with version keys `22.04`, `24.04`, and `26.04`. Build commands construct `docker.io/library/ubuntu:VERSION@` plus the inspected digest at runtime and reject a lock entry without the `sha256:` prefix.

- [ ] **Step 5: Document environment prerequisites**

State that Podman must already exist, the harness never installs it automatically, that **no virtual machine is used or required**, that a target must be on a netavark bridge network so NetworkManager can manage its device, and that all test output lives under `build/test-results`.

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

- [ ] **Step 5: Run the scenario in the target container**

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

Use the locked image, `--systemd=always`, `--cgroupns=private`, `--cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=SYS_PTRACE`, `-v /sys/fs/cgroup:/sys/fs/cgroup:rw`, and the private network's fixed IP. These are the exact flags measured to work on this host; `--cgroupns=host` and `--privileged` are **not** used — they were written for the machine architecture this plan no longer has, and the measured set is narrower. Do not mount host system directories. Copy the `.deb` with `podman cp`, then install it inside the container.

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
- Create: `tests/podman/scenarios/two_user_lock_test.py`
- Create: `tests/podman/scenarios/cdn_ech_test.py`
- Create: `tests/podman/scenarios/upgrade_uninstall_test.py`
- Modify: `tests/podman/run.py`

**Interfaces:**
- Consumes: running target, selector test fixtures, and mock CDN.
- Produces: system-level failure, multi-user lock, and lifecycle evidence.

- [ ] **Step 1: Implement the mock CDN server**

Serve certificate-authenticated `cloudflare.test` and `distribution.test` names, Cloudflare-style and CloudFront-style headers, expected body markers, a small file, and a large throttled file. Never use `InsecureSkipVerify` in the client scenario.

- [ ] **Step 2: Add deterministic failure injections**

Cover DNSCrypt process stopped, DHCP DNS stopped, state corruption, ECH source timeout, bad selector, disk-full simulation, and simultaneous manual/automatic lock attempts. Assert fail-closed/no-leak behavior and last-known-good preservation.

- [ ] **Step 3: Add the two-user control-lock and state test**

This scenario runs the real units as two different unprivileged identities, because
the control lock is acquired through a read-only descriptor and shared state
files are created at mode 0640 inside setgid directories. Run
`mosdns-router.service` as `mosdns` and `mosdns-cdn-optimizer.service` as a second
`mosdns-optimizer` user in the same group, and assert:

- while the optimizer holds `/var/lib/mosdns/runtime/control.lock`, a router-side
  write is refused with the lock-held exit code and no partial state file
  appears, and the reverse direction behaves the same way;
- after the holder exits, the other identity acquires the lock, and the lock
  file is still mode `0640` owned by the shared group;
- a state file written by one identity is read, validated, and replaced by the
  other identity without any additional privilege, and its mode stays `0640`;
- neither identity can read `/etc/mosdns/`-owned secrets through the shared
  runtime directory, and the shared directory is not world accessible;
- a run that changes the runtime directory mode to `0755` or removes the setgid
  bit makes the next systemd start fail closed with a preflight error naming the
  directory, instead of silently creating a world-readable state file.

Collect the evidence with `stat`, `systemctl show`, and the two units' journal
entries, and record the resolved group of the created files.

- [ ] **Step 3: Add CDN/ECH system assertions**

Use test-only force-ECH `cloudflare.test`. Assert strict A/AAAA are empty, HTTPS RR has ECH/mandatory/ipv4hint, non-ECH client cannot connect, and a fallback-policy run can connect. Use private test addresses and mock certificates; this is not a live ECH claim.

- [ ] **Step 4: Add upgrade/uninstall scenario**

Install version 0.1.0, create selector/ECH/user candidate state, rebuild/install the next test package version with preserved state, then uninstall. Assert state survives upgrade, ordinary uninstall preserves it, purge removes it, and NM settings restore only when ownership marker/current values match.

**This scenario is the direct regression test for the previous plan's Critical.** The install must not overwrite the record of the machine's original DNS, so an upgrade followed by a removal must restore the **first** install's recorded values and must refuse to stop the resolver; and a `dpkg --configure` retry after a failed rollback must not rewrite that record either. Assert the recorded values before the upgrade, after the upgrade, and after the removal, and assert that the removal's exit status is not a success in the case where the device check refuses.

- [ ] **Step 5: Add emergency rollback scenario**

Change DNS to local, stop MOSDNS, run emergency rollback, and assert the original mock DHCP DNS is restored and the machine remains usable.

- [ ] **Step 6: Run deterministic matrix**

```bash
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04 --scenario failure,two-user-lock,cdn-ech,upgrade-uninstall
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
- Consumes: an explicit Podman connection (a native arm64 one, when arm64 is the point) and a user-supplied live Cloudflare test hostname.
- Produces: Firefox/packet evidence without changing Firefox DoH or trusting a custom CA.

- [ ] **Step 1: Require explicit live-test inputs**

Refuse to run unless a hostname is supplied. `--connection` is optional and means a Podman service URI, not a machine. Record only hostname, Firefox version, and pass/fail evidence. Do not query browsing history.

- [ ] **Step 2: Install official Firefox inside the target container**

Download the official Linux tarball inside the target container, record the actual version, and run headless under Xvfb. Do not enable snap, DoH, a local CA, or a proxy.

- [ ] **Step 3: Configure only the test allowlist**

Resolve the current Cloudflare address through the foreign path, validate it with Host/SNI, pin it manually, add the hostname to the test force-ECH file, and restart only the router service if required.

- [ ] **Step 4: Verify ECH without MITM**

Capture packets on the target's private interface inside the container and assert the target hostname does not appear in plaintext TLS ClientHello SNI while the expected outer SNI may appear. Also record Firefox `about:networking` diagnostic evidence where accessible. Packet capture is read-only and must not modify traffic.

- [ ] **Step 5: Classify live results honestly**

Return `passed`, `failed`, or `skipped` for network unavailability. A skip cannot satisfy the ECH completion criterion and must be reported as incomplete.

- [ ] **Step 6: Document the exact command**

```bash
python3 tests/podman/run.py live-ech --domain hostname-provided-by-operator
# with a native arm64 service, additionally:
python3 tests/podman/run.py live-ech --connection "$MOSDNS_ARM64_PODMAN_CONNECTION" --domain hostname-provided-by-operator
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

Ignore only documented build caches and this harness's own Podman data (its network, volumes, and container names). Any difference in NM summary, resolved state, resolv.conf link, project units, listeners, or Firefox profile metadata fails the run. A host that ends a run with a different DNS configuration is a failed run, never a passed one.

- [ ] **Step 3: Implement arm64 execution**

Accept `MOSDNS_ARM64_PODMAN_CONNECTION` as a **native arm64 Podman service URI**. Reject an emulated service as native acceptance. On this host there is no `/dev/kvm` and no `vmx`/`svm` flag and no qemu is installed, so arm64 cannot run here; it is reported `skipped`, the run is `incomplete`, and exit code is 3. **Never** substitute a cross-built amd64 result for arm64, and never label a skip a pass.

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

`test-system` requires the built `.deb` and must **not** be wired into `make verify`, which stays fast and hermetic; a system-level run belongs to a release gate, not to a unit gate.

- [ ] **Step 5: Run harness unit tests and preflight**

```bash
python3 -m unittest discover -s tests/podman/tests -v
python3 tests/podman/run.py preflight
```

Expected: unit tests pass; preflight reports a missing Podman clearly rather than installing it. `preflight` must also report, as its first line, the NetworkManager device fact it depends on — that the local Podman exists, that a bridge network is required rather than the default tun/tap one, and whether a target container would come up with `GENERAL.NM-MANAGED: yes`. A preflight that cannot check that must say so rather than assume it.

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

Then, when the operator supplies them, the same matrix on a native arm64 Podman connection and the explicit live Firefox ECH command.

Expected:

- all deterministic scenarios pass on each Ubuntu version;
- no host network, resolver, service, or Firefox metadata changes;
- arm64 and live ECH are reported honestly as pass/fail/incomplete;
- teardown removes this run's containers, network, and volumes.

**On this host, two items are expected to be `skipped` rather than passed, and that is the correct outcome:**

- **arm64** — no `/dev/kvm`, no `vmx`/`svm` flag, and qemu is not installed and must not be. Reported `skipped`; the run is `incomplete` with exit code 3. The cross-built arm64 `.deb` builds and is content-verified, which is not the same claim.
- **live Firefox ECH** — requires a real network path and an operator-supplied production hostname. Not attempted unless both are given.

Everything else on Ubuntu 22.04, 24.04 and 26.04 amd64 is expected to be closed in a container. The previous plan's SKIPPED list — every NetworkManager-managed-connection claim, the install and uninstall transaction, `resolvectl` layout on all three releases, `nmcli` field names and idempotency — is expected to be **closed here**, because the container limitation that produced it was measured and is false.
