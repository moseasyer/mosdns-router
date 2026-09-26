# Native System Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package and transactionally install the router, dnscrypt-proxy, timers, configuration, and NetworkManager integration on supported Ubuntu releases without contaminating the development host or losing rollback state.

**Architecture:** Hardened systemd units and read-only default configs ship in a Debian package. A Python installer performs preflight, captures current DHCP DNS, backs up the active NetworkManager connection, installs local DNS routing, and rolls back on any failure. Uninstall and emergency commands restore only project-owned unchanged settings.

**Tech Stack:** Debian package format, `dpkg-deb`, Python 3 standard library, systemd hardening, NetworkManager CLI, Go release binaries for amd64/arm64.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- Never run install/uninstall against the development host during this plan; tests use a fake root and command runner.
- Support Ubuntu 22.04, 24.04, and 26.04 only; reject other releases before mutation.
- Never hardcode a domestic upstream in shipped configuration.
- All listeners remain on loopback.
- NetworkManager changes are backed up before mutation and restored transactionally on failure.
- Package upgrades never overwrite `/var/lib/mosdns` runtime state or user candidate/ECH files.
- Do not install or configure Firefox, DoH, a CA, ClearDNS, Docker, SNI DPI, or TLS interception.
- TDD is mandatory; every task ends with a focused commit.

## Review Focus

- A preflight failure must occur before any package maintainer script or NetworkManager mutation.
- If MOSDNS fails to start after NM is switched to `127.0.0.1`, the installer must restore the original DNS automatically.
- Uninstall must not overwrite a connection that the user changed after installation.
- Package upgrade must preserve selector, ECH state, health state, and user candidate files.
- Services must fail closed and must not listen on LAN interfaces.

---

## File Map

```text
packaging/systemd/mosdns-router.service
packaging/systemd/dnscrypt-proxy.service
packaging/systemd/mosdns-cdn-optimizer.service
packaging/systemd/mosdns-cdn-optimizer.timer
packaging/systemd/mosdns-cdn-health.service
packaging/systemd/mosdns-cdn-health.timer
packaging/systemd/mosdns-list-check.service
packaging/systemd/mosdns-list-check.timer
packaging/config/config.yaml
packaging/config/dnscrypt-proxy.toml
packaging/config/force-ech-domains.txt
packaging/config/cloudflare.txt
packaging/config/cloudfront-domains.yaml
packaging/debian/control
packaging/debian/conffiles
packaging/debian/postinst
packaging/debian/prerm
packaging/debian/postrm
packaging/mosdns-router.install
packaging/mosdns-router.postinst
installer/mosdns_installer.py
installer/tests/test_units.py
installer/tests/test_preflight.py
installer/tests/test_transaction.py
installer/tests/test_uninstall.py
scripts/build-deb.sh
Makefile
bridge/mosdns_dhcp_bridge/cli.py
bridge/tests/test_capture_current.py
cmd/mosdns-cdnctl/main.go
```

### Interfaces produced by this plan

Python interfaces:

- `CommandRunner.run(args: Sequence[str], check: bool = True) -> CompletedProcess`
- `preflight(root: Path, run: CommandRunner) -> Preflight`
- `install(root: Path, run: CommandRunner, clock: Callable[[], datetime]) -> InstallResult`
- `uninstall(root: Path, run: CommandRunner, purge: bool) -> UninstallResult`
- `emergency_rollback(root: Path, run: CommandRunner) -> None`

```
mosdns-dhcp-bridge --capture-current INTERFACE --state-file PATH --lock-file PATH
```

The dispatcher script is installed as
`/etc/NetworkManager/dispatcher.d/no-wait.d/10-mosdns-dhcp-bridge` with mode `0755`
and invokes `python3 -m mosdns_dhcp_bridge.cli --state-file /run/mosdns/dhcp-upstreams.json --lock-file /run/mosdns/dhcp-bridge.lock INTERFACE ACTION`, or an installed wrapper that runs that exact module invocation. `no-wait.d` is the directory for a script that must not block the event, because the bridge only reads NetworkManager state and rewrites one runtime file; a blocking hook would hold a DHCP event open for the length of an `nmcli` call. Pinning the module invocation keeps the package's Python path explicit, and the dispatcher runs it as root with NetworkManager's own `script INTERFACE ACTION` arguments.

---

### Task 1: Add current-DHCP capture mode for first installation

**Files:**
- Modify: `bridge/mosdns_dhcp_bridge/cli.py`
- Create: `bridge/tests/test_capture_current.py`

**Interfaces:**
- Consumes: an explicit active interface when no dispatcher event exists.
- Produces: the same schema version 1 state as dispatcher mode.

- [ ] **Step 1: Write failing capture-current tests**

Use a fake runner and assert exact `nmcli` calls for raw DHCP4/DHCP6 fields, interface validation, unchanged-file behavior, and empty-DNS publication. A capture must also record the source the collector reports, and an event whose resolvers were already published must not advance the generation.

- [ ] **Step 2: Run tests and verify failure**

```bash
python3 -m unittest bridge.tests.test_capture_current -v
```

Expected: CLI rejects `--capture-current`.

- [ ] **Step 3: Implement mutually exclusive modes**

Support either dispatcher environment mode or `--capture-current INTERFACE`; reject both and neither.

Capture-current is the dispatcher's publication path with an explicit interface, not a second writer: it calls `collect_dns_with_source(env, interface, run)` and `publish_if_changed(...)` with the addresses and the source that answered, so an install that captures the current lease and the first `up` event that follows it record one state instead of two generations. It never invents a source of its own: `installer-current` is not a token any collector can produce, and a state naming it would be a document the router's source vocabulary does not cover.

`CONNECTION_UUID` comes from the environment when the caller has it, and otherwise from `nmcli -g GENERAL.CONNECTION device show INTERFACE`, because a state with upstreams must record the connection the lease belongs to and an empty one would be refused as invalid. The result must pass `internal/dhcpstate.VerifyFixture` in integration tests.

- [ ] **Step 4: Run tests**

```bash
python3 -m unittest discover -s bridge/tests -v
go test ./internal/dhcpstate -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bridge/mosdns_dhcp_bridge/cli.py bridge/tests/test_capture_current.py
git commit -m "feat: capture current DHCP DNS during install"
```

---

### Task 2: Write and statically test hardened systemd units

**Files:**
- Create: all `packaging/systemd/*.service` and `*.timer` files.

**Interfaces:**
- Consumes: installed binary/config paths and policy schedule.
- Produces: native service/timer units.

- [ ] **Step 1: Write a unit-policy test script**

Create a temporary test in `installer/tests/test_units.py` that parses unit text and asserts executable paths, users, loopback config references, `After=dnscrypt-proxy.service`, capabilities, sandbox properties, and timer `Persistent=true`.

- [ ] **Step 2: Run the test and verify failure**

```bash
python3 -m unittest installer.tests.test_units -v
```

Expected: missing unit files.

- [ ] **Step 3: Create MOSDNS and DNSCrypt service units**

Use:

```ini
User=mosdns
Group=mosdns
ExecStart=/usr/lib/mosdns-router/mosdns-router start -c /etc/mosdns/config.yaml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/mosdns /run/mosdns
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

DNSCrypt runs as `dnscrypt-proxy`, uses `/etc/mosdns/dnscrypt-proxy.toml`, needs no capability, and starts before MOSDNS.

- [ ] **Step 4: Create timer/service units**

- Optimizer: initial `OnCalendar=*-*-* 03:00:00`, generated from `policy.yaml`, `Persistent=true`, service runs `mosdns-cdnctl test --apply`. A later schedule change is made with a systemd drop-in and the same value in `policy.yaml`, followed by `systemctl daemon-reload` and `systemctl restart mosdns-cdn-optimizer.timer`.
- Health: every 2 minutes, runs `mosdns-cdnctl health-check`.
- List check: daily after 03:00, runs `mosdns-cdnctl update-lists --check` and is report-only.
- Router and DNSCrypt must not use `network-online.target` as a hard start requirement.

- [ ] **Step 5: Run static tests**

```bash
python3 -m unittest installer.tests.test_units -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packaging/systemd installer/tests/test_units.py
git commit -m "packaging: add hardened systemd units"
```

---

### Task 3: Implement preflight without mutation

**Files:**
- Create: `installer/mosdns_installer.py`
- Create: `installer/tests/test_preflight.py`

**Interfaces:**
- Consumes: target root and injected command runner.
- Produces: validated OS, dependencies, paths, NetworkManager connection, resolved mode, port availability, and optional Firefox version.

- [ ] **Step 1: Write failing OS/dependency tests**

Accept `22.04`, `24.04`, and `26.04`; reject missing/malformed `/etc/os-release`, unknown versions, missing NetworkManager/resolved/systemd, and non-amd64/arm64 architectures.

- [ ] **Step 2: Write failing network preflight tests**

Cover:

- `/etc/resolv.conf` not pointing to the resolved stub;
- missing active NetworkManager connection;
- occupied 53, 15353, or timer conflict;
- `mosdns` or `dnscrypt-proxy` service already active outside this package;
- Firefox below 129: ECH disabled/reported, but basic routing preflight passes;
- user-provided forced ECH domain on a system that cannot meet Firefox 129: reject only when ECH strict is enabled.

Also cover the runtime directory prerequisites, because the control lock is
acquired through a read-only descriptor and a state file is created at mode
0640 by whichever of the two service identities wins the race:

- `/var/lib/mosdns` and `/var/lib/mosdns/runtime` exist, are owned by
  `root:mosdns`, are setgid directories (`2750`), and carry a default ACL
  granting the service group `rwx` so a file created by one identity stays
  group-owned and group-writable for the other;
- `/run/mosdns` is provisioned the same way for the DHCP bridge and the service
  group, and its group ownership survives a reboot;
- a pre-existing directory that is world-readable, group-writable by an
  unrelated group, or missing its setgid bit is a preflight failure reported
  before any mutation, with the exact `stat` values in the message;
- a pre-existing control lock file whose mode is not `0640`, or which is not
  owned by `root:mosdns`, is reported rather than silently repaired by an
  installer running as an unrelated user.

- [ ] **Step 3: Run tests and verify failure**

```bash
python3 -m unittest installer.tests.test_preflight -v
```

Expected: import failure.

- [ ] **Step 4: Implement `--check-only`**

Use subprocess argument arrays only. Parse `nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active`, identify the primary wired/wireless connection, and verify systemd-resolved controls DNS. Do not write files or call mutating `nmcli` commands in preflight.

- [ ] **Step 5: Run tests**

```bash
python3 -m unittest installer.tests.test_preflight -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add installer/mosdns_installer.py installer/tests/test_preflight.py
git commit -m "feat: add safe installation preflight"
```

---

### Task 4: Implement transactional NetworkManager integration

**Files:**
- Modify: `installer/mosdns_installer.py`
- Create: `installer/tests/test_transaction.py`

**Interfaces:**
- Consumes: successful preflight and current DHCP capture.
- Produces: root-only backup plus `ignore-auto-dns` and loopback DNS settings.

- [ ] **Step 1: Write failing transaction-order tests**

Record fake commands and assert this order:

```text
preflight
capture current DHCP DNS
write and validate root-only backup
enable dnscrypt-proxy
start dnscrypt-proxy and wait for 127.0.0.1:15353
start mosdns-router and wait for 127.0.0.1:53
health-check local 127.0.0.1:53
set ipv4.ignore-auto-dns=yes
set ipv6.ignore-auto-dns=yes
set ipv4.dns=127.0.0.1
reconnect only the active NetworkManager connection
verify resolved stub and local DNS
commit marker
```

- [ ] **Step 2: Write failure-injection tests**

For failure after each mutation, assert original NM properties are restored, temporary services are stopped if not previously active, backup remains root-only, and exit code identifies rollback success/failure.

- [ ] **Step 3: Write backup compatibility tests**

Assert backup includes project version, timestamp, connection UUID/name, original ignore-auto-dns values, original DNS list, DHCP DNS state, and a config SHA-256. File mode is 0600 under `/var/lib/mosdns/installer`.

- [ ] **Step 4: Run tests and verify failure**

```bash
python3 -m unittest installer.tests.test_transaction -v
```

Expected: install transaction missing.

- [ ] **Step 5: Implement backup and marker**

Use the package version and schema version. Write a `managed-by: mosdns-router` marker and only mark ownership after the local DNS health check passes.

- [ ] **Step 6: Implement rollback stack**

Keep a list of applied mutating actions. On exception, execute reverse-order restoration; never stop a unit that was active before installation. Return separate errors for original operation and rollback.

- [ ] **Step 7: Implement NM mutation**

Use three exact mutation calls: `nmcli connection modify UUID ipv4.ignore-auto-dns yes`, `nmcli connection modify UUID ipv6.ignore-auto-dns yes`, and `nmcli connection modify UUID ipv4.dns 127.0.0.1`, passing UUID as a separate argument. Do not set a public DNS. Reapply the connection without rebooting NetworkManager globally; use `nmcli connection up UUID` only after dnscrypt/MOSDNS units are installed, enabled, and locally healthy.

- [ ] **Step 8: Run tests**

```bash
python3 -m unittest installer.tests.test_transaction -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add installer/mosdns_installer.py installer/tests/test_transaction.py
git commit -m "feat: install NetworkManager DNS transactionally"
```

---

### Task 5: Implement uninstall and emergency rollback

**Files:**
- Modify: `installer/mosdns_installer.py`
- Create: `installer/tests/test_uninstall.py`
- Modify: `cmd/mosdns-cdnctl/main.go`

**Interfaces:**
- Consumes: installer backup/marker and current NM state.
- Produces: restored original DNS and optional state purge.

- [ ] **Step 1: Write failing ownership tests**

Refuse automatic restoration when marker is absent, schema is unknown, UUID is missing, or current DNS/ignore-auto-dns values differ from the values owned by this installation. Emit a clear manual-recovery report.

- [ ] **Step 2: Write failing purge tests**

Default uninstall preserves `/var/lib/mosdns`. `--purge` removes it only after successful NM restoration. Test both paths and file-lock release.

- [ ] **Step 3: Implement uninstall ordering**

```text
stop timers/health/optimizer
restore NetworkManager original DNS
stop router/dnscrypt if package-owned
remove dispatcher symlink
reload systemd
optionally purge state
```

The installed hook is the `no-wait.d` dispatcher script this plan installs, and
uninstall removes exactly that file.

- [ ] **Step 4: Implement `emergency-rollback`**

Restore only the last valid backup, verify the connection has a usable DNS path, and leave binaries/config installed for diagnosis. This command must work even if normal preflight fails.

- [ ] **Step 5: Wire the root-only CLI entry point**

Add `mosdns-cdnctl emergency-rollback` to `cmd/mosdns-cdnctl/main.go`. It requires UID 0 and executes `/usr/lib/mosdns-router/mosdns_installer.py emergency-rollback` with an argument array and inherited stdio. Add a Go test with a fake `exec.Command` runner proving there is no shell interpolation.

- [ ] **Step 6: Run tests**

```bash
python3 -m unittest installer.tests.test_uninstall -v
go test ./cmd/mosdns-cdnctl ./internal/... -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add installer/mosdns_installer.py installer/tests/test_uninstall.py cmd/mosdns-cdnctl/main.go
git commit -m "feat: add safe uninstall and rollback"
```

---

### Task 6: Assemble default configs and Debian package

**Files:**
- Create: `packaging/config/*`
- Create: `packaging/debian/*`
- Create: `packaging/mosdns-router.install`
- Create: `packaging/mosdns-router.postinst`
- Create: `scripts/build-deb.sh`
- Modify: `Makefile`

**Interfaces:**
- Consumes: built router/cdnctl/dnscrypt-proxy binaries and generated configs.
- Produces: architecture-specific `.deb` files.

- [ ] **Step 1: Write package-content tests**

Add a test that builds a staging root and asserts binaries, units, configs, installer, and dispatcher script are present with correct modes; `/var/lib/mosdns` is an empty state directory, not a shipped state file. The dispatcher script is the one named in this plan's interfaces -- `/etc/NetworkManager/dispatcher.d/no-wait.d/10-mosdns-dhcp-bridge`, mode `0755`, invoking `python3 -m mosdns_dhcp_bridge.cli` with the state and lock paths -- and the test reads its `Exec` line to prove the installed hook runs that invocation rather than a bare script name that depends on `$PATH` and on an interactive login shell's environment.

- [ ] **Step 2: Add shipped configs**

Use:

- `/etc/mosdns/config.yaml`
- `/etc/mosdns/dnscrypt-proxy.toml`
- `/etc/mosdns/policy.yaml`
- empty `/etc/mosdns/force-ech-domains.txt`
- documented empty Cloudflare candidate/CloudFront profile files

Do not ship `114.114.114.114`, `119.29.29.29`, AliDNS, DNSPod, or any other domestic public DNS.

After editing `policy.yaml`, run `sudo mosdns-cdnctl validate --policy /etc/mosdns/policy.yaml` and restart `mosdns-router` so the ECH/AAAA policy is reloaded. Timer and optimizer invocations read the validated file on every run. Custom DNSCrypt stamps are edited in `dnscrypt-proxy.toml` and require a dnscrypt-proxy restart.

- [ ] **Step 3: Add Debian metadata**

Package name `mosdns-router`, version `0.1.0`, architectures `amd64 arm64`, dependencies `python3 (>=3.10), systemd, network-manager, systemd-resolved, libc6`. Mark shipped configs as conffiles. `postinst` calls installer `install`; `prerm` calls `uninstall`; `postrm purge` calls `uninstall --purge` only when requested.

`postinst` must provision the state directories before any unit starts, and the
package-content test asserts the provisioned identity:

```text
/var/lib/mosdns              root:mosdns  2750  (setgid, default ACL rwx for mosdns)
/var/lib/mosdns/runtime      root:mosdns  2750  (setgid, default ACL rwx for mosdns)
/var/lib/mosdns/lists        root:mosdns  2750  (setgid, default ACL rwx for mosdns)
/var/lib/mosdns/runtime/control.lock  created on first acquire at 0640
/run/mosdns                  root:mosdns  2750  (setgid, default ACL rwx for mosdns)
```

`/var/lib/mosdns/lists` is here because the CDN selector plan's range cache lives
at `/var/lib/mosdns/lists/cloudflare-ips.json` and the China list at
`/var/lib/mosdns/lists/cn-domains.txt`: both are read and renamed over by the same
two service identities, and the range cache's own writer creates the directory only
when it is absent. The cache *file* is deliberately not in the 0640 set — it is
published reference data, written 0644 by `internal/candidate` — so the directory
has to be the thing that lets both identities read and replace it.

The setgid bit and the group are what let the router service (user `mosdns`) and
the DHCP bridge or optimizer (a second identity) share one control lock and one
set of state files: whichever process creates a file does so at mode 0640 inside
a group-writable setgid directory, so the other identity can read it, rename
over it, and acquire the lock without any additional privilege. Do not grant
world access and do not rely on a per-file `chown` from an unprivileged unit.

- [ ] **Step 4: Build pinned dnscrypt-proxy**

`build-deb.sh` sets `CGO_ENABLED=0` and builds dnscrypt-proxy v2.1.18 from the pinned module/source into the staging root. It must use the same Go 1.25.8 toolchain and record source SHA-256 in `/usr/share/doc/mosdns-router/BUILD-MANIFEST`.

- [ ] **Step 5: Implement atomic package build**

Use `dpkg-deb --root-owner-group --build staging build/mosdns-router_VERSION_ARCH.deb`. Do not install the package on the development host.

- [ ] **Step 6: Run package tests**

```bash
make package
dpkg-deb --info build/mosdns-router_0.1.0_amd64.deb
dpkg-deb --contents build/mosdns-router_0.1.0_amd64.deb
```

Expected: package metadata and paths match the test; no state files or host service changes exist.

- [ ] **Step 7: Commit**

```bash
git add packaging scripts/build-deb.sh Makefile
git commit -m "build: add Ubuntu native package"
```

---

## Plan Acceptance

Run:

```bash
python3 -m unittest discover -s installer/tests -v
python3 -m unittest discover -s bridge/tests -v
go test ./...
make package
```

Expected:

- installer and bridge unit tests pass with fake roots;
- no target-network command executed on the host;
- both amd64 and arm64 packages can be built;
- package content contains no state, public Chinese DNS, DoH/CA, or LAN listener;
- install/uninstall transaction tests prove rollback and ownership safety.
