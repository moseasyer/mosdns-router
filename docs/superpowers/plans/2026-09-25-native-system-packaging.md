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
- An upgrade must not destroy the record of the machine's ORIGINAL DNS settings, and must not re-pin an operator's published China list. Both were defects found in review, both are now carried-forward properties with their own tests, and both are the reason a re-install is now a distinguishable thing rather than a second first-install.
- A failed install must leave a package that dpkg can still remove, and a failed removal must say what dpkg WILL do rather than what it would do.
- **OPEN DECISION, and it is the user's: should anything run `emergency-rollback` unattended when the local resolver stops answering?** The health unit now fails within two minutes when `127.0.0.1:53` does not resolve resolvably, which is the signal. Whether a watchdog should act on that signal — which means mutating a machine's DNS with nobody watching — is NOT decided here and is NOT built. What an operator does today: `systemctl status mosdns-cdn-health.service` failing is the signal, and `sudo mosdns-cdnctl emergency-rollback` is the action. The same question is open in the Podman plan's ledger, and the two must be answered together.

---

## File Map

`packaging/config/mosdns.yaml` and `packaging/config/dnscrypt-proxy.toml` are named
here as the files the package installs; per the preflight ruling they are produced
by `mosdns-cdnctl render` at build time and held to a byte comparison against a
fresh production render, so they are outputs of Task 6's build rather than
hand-maintained copies in this repository. `packaging/config/policy.yaml` is not a
file at all: `configs/policy.yaml` is the committed output of
`config.Marshal(config.Defaults())` and is what the build copies.

Every shipped file, in the three places it can be. The list is the whole of "the
package installs nothing it should not", and `installer/tests/test_package.py`
compares it with the staged tree in BOTH directions.

```text
--- the eight units, into the merged-/usr unit directory
packaging/systemd/mosdns-router.service
packaging/systemd/dnscrypt-proxy.service
packaging/systemd/mosdns-cdn-optimizer.service
packaging/systemd/mosdns-cdn-optimizer.timer
packaging/systemd/mosdns-cdn-health.service
packaging/systemd/mosdns-cdn-health.timer
packaging/systemd/mosdns-list-check.service
packaging/systemd/mosdns-list-check.timer

--- the documents an operator edits, as conffiles
packaging/config/force-ech-domains.txt   -> /etc/mosdns/force-ech-domains.txt
packaging/config/cloudflare.txt          -> /etc/mosdns/cloudflare.txt
packaging/config/cloudfront-domains.yaml -> /etc/mosdns/cloudfront-domains.yaml
configs/policy.yaml                      -> /etc/mosdns/policy.yaml
configs/cn-domains.txt                   -> /usr/share/mosdns-router/cn-domains.txt
configs/source-lock.json                 -> /usr/share/mosdns-router/source-lock.json
packaging/config/mosdns.yaml             -> GENERATED by `mosdns-cdnctl render`
packaging/config/dnscrypt-proxy.toml     -> GENERATED by `mosdns-cdnctl render`

--- the Debian metadata and the maintainer scripts
packaging/debian/control
packaging/debian/conffiles
packaging/debian/changelog
packaging/debian/postinst
packaging/debian/prerm
packaging/debian/postrm
packaging/debian/dnscrypt-proxy.sha256   -> /usr/share/doc/mosdns-router/ (the recorded source digest)
packaging/mosdns-router.install          -> the package's whole file list
packaging/mosdns-router.postinst         -> a symlink to packaging/debian/postinst
packaging/copyright                      -> /usr/share/doc/mosdns-router/copyright

--- the hook, the tmpfiles entry and the manual pages
packaging/networkmanager/10-mosdns-dhcp-bridge -> /etc/NetworkManager/dispatcher.d/no-wait.d/
packaging/tmpfiles.d/mosdns-router.conf        -> /usr/lib/tmpfiles.d/
packaging/man/mosdns-router.8                  -> /usr/share/man/man8/
packaging/man/mosdns-cdnctl.1                  -> /usr/share/man/man1/
packaging/man/dnscrypt-proxy.8                 -> /usr/share/man/man8/

--- the programs
build/mosdns-router, build/mosdns-cdnctl, build/mosdns-router.dnscrypt-proxy
installer/mosdns_installer.py
bridge/mosdns_dhcp_bridge/{__init__,cli,collect,publish}.py

--- the tests, which are the gate and are as much a part of the plan
installer/tests/test_units.py
installer/tests/test_preflight.py
installer/tests/test_transaction.py
installer/tests/test_uninstall.py
installer/tests/test_package.py
bridge/tests/test_capture_current.py
bridge/tests/test_fixture.py
tests/system/Dockerfile, tests/system/entrypoint.sh, tests/system/*.py
tests/vm/ (the parked machine's scripts; nothing here runs them)

--- the build
scripts/build-deb.sh
scripts/test-make-entrypoints.sh
Makefile
```

`tests/system/` and `tests/vm/` are named because they exist and because the
SKIPPED claims in the ledger name them: the container is what closed the `ss`
parser defect and the "empty `NM_DISPATCHER_ACTION`" measurement, and the VM is
the owner of every claim that cannot be closed in a container. `bridge/` and
`cmd/` hold the Go and Python the plan calls rather than creating — the capture
mode, the render, the classifier the units are tested against — and are listed by
the one file each of them contributes.

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

Capture-current is the dispatcher's publication path with an explicit interface, not a second writer: it calls `collect_dns_with_source(env, interface, run)` and `publish_if_changed(...)` with the addresses and the source that answered, so an install that captures the current lease and the first `up` event that follows it record one state instead of two generations. It never invents a source of its own: `installer-current` is not a token any collector can produce, and the recorded source is the one thing besides the resolvers that the publisher compares when it decides whether an event changed anything, so a token naming the caller instead of the answer would make every later event a new generation for resolvers that never moved. A source no writer of this project emits is also a document nothing here produced, and neither side can catch it by shape — `publish._is_source_token` and `state.validSourceToken` both check a token's form, not the vocabulary — which is why the guarantee is structural: the capture can only pass the collector's own result.

`CONNECTION_UUID` comes from the environment when the caller has it, and otherwise from `nmcli -g GENERAL.CON-UUID device show INTERFACE`, because a state with upstreams must record the connection the lease belongs to and an empty one would be refused as invalid. The field is `GENERAL.CON-UUID` and not the `GENERAL.CONNECTION` this plan first named: `GENERAL.CONNECTION` holds the connection's *name* (`netplan-ens33` on a machine whose profile is called that) and `device show` does not offer `GENERAL.CONNECTION-UUID` at all, so the original token returns a value the publisher refuses and every install-time capture would exit 2.

The result must pass `internal/dhcpstate.VerifyFixture`, and that check lives in the Go suite rather than in the packaging integration tests: `TestVerifyFixtureAcceptsACapture` verifies the bytes a real capture published — both the dual-stack lease and the readable-but-empty one — and `TestCaptureBytesAreTheStateWriterEmits` holds those bytes against `state.DHCPState` marshalled by the Go writer, so a hand-edited or stale literal fails instead of passing as a document the reader happens to like. The Python suite holds the other half: `bridge/tests/test_fixture.py` pins the publisher's bytes to the committed fixture and `test_capture_current.py` pins what a capture records. The field has no runtime consumer — `dhcp_forward` reads `LastGood`, `Generation`, `Upstreams` and `Interface`, and `DHCPState.Validate` does not check the connection — so the mandatory lookup rests on the publisher refusing a state with resolvers and no connection, and on `connection_uuid` being part of the identity the publisher compares: omitting it from a capture that found no resolvers would force a generation advance when the first event arrives.

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

Create a test in `installer/tests/test_units.py` that parses unit text and asserts
executable paths, users and groups, loopback config references, the loopback form
of every address the units and the shipped configs name, `After=` and `Wants=`
against `dnscrypt-proxy.service`, capabilities, sandbox properties, the three
pinned schedules, and the writable paths of each unit against the table of what
that identity writes.

Every property is also checked for teeth: a unit with a hardening directive
removed, a capability added, a bounding set widened, a non-loopback address named
or a writable directory granted that the identity does not write has to make the
check fail, because a check that accepts any of those is not a check. The test
runs `systemd-analyze verify` on each unit file individually, against a fake root
holding the units, a copy of the host's own systemd unit directory and a stub
executable for every path the ExecStart lines name, so no test needs a running
systemd or a live bus; the harness is itself run against deliberately broken units
so a gate that cannot fail is visible.

- [ ] **Step 2: Run the test and verify failure**

```bash
python3 -m unittest installer.tests.test_units -v
```

Expected: missing unit files.

- [ ] **Step 3: Create MOSDNS and DNSCrypt service units**

The router's config path is `/etc/mosdns/mosdns.yaml` -- the renderer's own output
file name, not `config.yaml`, which this plan first wrote. Use:

```ini
User=mosdns
Group=mosdns
ExecStart=/usr/lib/mosdns-router/mosdns-router start -c /etc/mosdns/mosdns.yaml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/mosdns/runtime
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

`ReadWritePaths` is per identity and is not one list repeated, and the table it
comes from is the code's write set rather than a decision: the router writes the
ECH state, the optimizer writes the selector, the budget, the control lock and the
published range cache, the health check writes the health document, the selector it
may transition and the control lock, the bridge publishes the DHCP state, and the
list check and the resolver write nothing at all. The test derives each row from
the writer that produces it -- the write call sites in the two plugins, the options
`runCDNHealthCheck` hands the checker, the paths the optimizer is configured with
-- and compares it for equality, so a unit granting a directory its identity does
not write fails, and a writer that starts using a new directory fails the other
way.

Two consequences of that table are load-bearing rather than tidy:

- **The router does not make `/run/mosdns` writable.** Its only write is the ECH
  state; `dhcp_forward` only reads the state the bridge publishes, and the plugin
  treats its absence as "keep the current generation". An unprefixed
  `ReadWritePaths=` entry naming a directory that is not there fails the unit's
  mount-namespace setup, and `/run` is a tmpfs, so on a host where the dispatcher
  has not fired -- a static address, a link NetworkManager does not manage, no
  dispatcher installed -- that failure is retried on every `RestartSec` forever and
  the machine has no DNS. A `ReadWritePaths` entry naming a volatile path must
  carry the `-` prefix, and there is nothing here to grant anyway.
- **The health check does not make `/var/lib/mosdns/lists` writable.** Its three
  options are all in the runtime directory, and the identity already reads the
  published China list through its DAC permissions as a member of the shared group;
  a mount grant for a directory it does not write in would add no access it lacks.

DNSCrypt runs as `dnscrypt-proxy`, uses `/etc/mosdns/dnscrypt-proxy.toml`, needs
no capability -- 15353 is unprivileged, so its bounding set is emptied rather than
inherited -- and names no writable directory because it creates no file. Its
address-family list is `AF_UNIX AF_INET AF_INET6 AF_NETLINK`: dnscrypt-proxy
2.1.18 enumerates interfaces in its network-change monitor, and Go's
`net.Interfaces` opens a netlink socket, so without the family a change of network
is missed silently. It starts before MOSDNS, which wants and is ordered after it
with `Wants` rather than `Requires`, so a resolver that failed to start does not
take the machine's only DNS path down with it.

- [ ] **Step 4: Create timer/service units**

- Optimizer: initial `OnCalendar=*-*-* 03:00:00`, generated from `policy.yaml`, `Persistent=true`, service runs `mosdns-cdnctl test --apply`. A later schedule change is a drop-in over the TIMER -- `/etc/systemd/system/mosdns-cdn-optimizer.timer.d/schedule.conf` holding the new `[Timer] OnCalendar=` -- together with the same value in `policy.yaml`, applied by `systemctl daemon-reload` (which makes systemd read the drop-in) followed by `systemctl restart mosdns-cdn-optimizer.timer` (which makes the new calendar take effect, because a reloaded timer that is already running keeps the elapse it had). Editing `policy.yaml` alone changes nothing about when this runs.
- Health: every 2 minutes (`OnBootSec=2min` and `OnUnitActiveSec=2min`), runs `mosdns-cdnctl health-check`, and is deliberately NOT `Persistent=true`: a two-minute cadence with persistence replays a backlog of every check the machine missed, and a check two minutes late is still a check.
- List check: daily at `OnCalendar=*-*-* 03:30:00` with `Persistent=true` -- half an hour after the optimizer's window, and persistent for the opposite reason the health timer is not, because a report nobody will ever be shown is not a report. It runs `mosdns-cdnctl update-lists --check` and is report-only.
- The optimizer, health and list-check services are `Type=oneshot` and are not enabled; their timers start them. Each service sets a `TimeoutStartSec` above what its command can legitimately spend, because the 90-second default for a oneshot would kill the nightly run and cut a slow origin off before it could report that it was slow.
- The exit-code policy is one decision, and the test holds it: `SuccessExitStatus=4` on the optimizer and the health check, because 4 is the CLI's own answer for the shared control lock ("the other one got there first") and a race with an operator's own pin or apply is not a broken unit. Every other non-zero exit fails the unit, including a refusal to publish. A budget-exhausted run needs no exception: a full day still names a winner in every group and keeps every mapping, so the command exits 0 by construction. The list check excuses nothing, because it takes no lock, so 4 is unreachable, and its exit 3 is a run that produced no report at all.
- Router and DNSCrypt must not use `network-online.target` as a hard start requirement, and no unit may pull in `network.target` with `Wants=` or `Requires=`. `network.target` appears as an ordering edge only.
- Every unit carries `Documentation=man:…` naming the page it is documented by, and that directive is pinned by the text table. `systemd-analyze verify` shells out to `man(1)` for each one and fails the unit with code 16 when the page is not installed, and there is no option to decline the check, so the verify harness puts a stub `man` on `PATH`. That is deliberate: whether the pages exist is a package-completeness question for Task 6, and it must not decide whether a unit is valid. The pages themselves are Task 6's obligation, listed there.
- Every unit states its systemd version floor in a comment: 249, the oldest supported release, with `ProtectProc=` and `ProcSubset=` (247) the newest directives used. `systemd-analyze verify` runs against the build host's systemd (259 while this was written), so it cannot catch a 250+ directive that Ubuntu 22.04 would refuse at boot; proving the floor is a container run under the spec's isolation testing.

- [ ] **Step 5: Run static tests**

```bash
python3 -m unittest installer.tests.test_units -v
```

Expected: PASS, with `systemd-analyze verify` at exit 0 and no diagnostic about
any of the eight units for each of them. The harness resolves each unit's default
dependencies against a copy of the host's own `/usr/lib/systemd` with its `*.wants`
symlinks preserved, and a test asserts the copy kept them: a copy that dereferences
them silently drops all of them, because following a relative link resolves it
against the process's working directory rather than the link's own directory, and a
harness that drops the closure is clean because of what it dropped. Diagnostics
about the host's own units -- a dracut unit enabled by a symlink out of the copied
tree -- are the host's, and the gate is "nothing systemd said is about this
package" rather than "stderr is empty".

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
- **53 held by systemd-resolved's own stub listener, which every stock Ubuntu has
  and which this install keeps** — resolved stays in front of the router and
  forwards to it, so the stub is the machine working, not a conflict to clear
  first. The exemption is matched on the *owning process* (its pid, resolved to
  `systemd-resolved.service`'s `MainPID`) **and** on the address being loopback; a
  foreign process that has taken `127.0.0.53` is still two answers for one query
  and is refused. A holder this user cannot name is refused too, because that is
  what an unprivileged run sees for every other user's socket. `ss -p` is asked
  for, and the local-address column is found by shape rather than by index — the
  count is not stable, and a hand-written fixture that omits the `Netid` column
  agrees with an off-by-one parser. The suite pins an `ss` answer captured from
  the system-level test machine for exactly that reason.
- 53 or 15353 held by anything else, including a `mosdns-router` process when
  nothing claims it: the ownership marker is the same claim `check_foreign_services`
  makes, and a second installation is not excused by the port check;
- `mosdns` or `dnscrypt-proxy` service already active outside this package;
- Firefox below 129: ECH disabled/reported, but basic routing preflight passes;
- user-provided forced ECH domain on a system that cannot meet Firefox 129: reject only when ECH strict is enabled. **Recorded fail-open: an absent, section-less or unparseable `/etc/mosdns/policy.yaml` is treated as not strict, so on a fresh installation — where the install has not yet rendered the policy — this refusal cannot fire. That is deliberate (refusing would stop an install because a file has not been written yet) and it is reported as a note when a forced domain exists, not passed in silence. Narrowing it to "unparseable is a refusal, absent is the fresh-install state" is a ruling, not a fix.**

Also cover the runtime directory prerequisites, because the control lock is
acquired through a read-only descriptor and a state file is created at mode
0640 by whichever of the two service identities wins the race:

- `/var/lib/mosdns` and `/var/lib/mosdns/runtime` exist, are owned by
  `root:mosdns`, are setgid directories (`2770`, not the `2750` this plan first
  named -- see the correction below), and carry a default ACL
  granting the service group `rwx` so a file created by one identity stays
  group-owned and group-writable for the other;
- `/run/mosdns` is provisioned the same way for the DHCP bridge and the service
  group, and its group ownership survives a reboot;
- a pre-existing directory that is world-readable, group-writable by an
  unrelated group, or missing its setgid bit is a preflight failure reported
  before any mutation, with the exact `stat` values in the message;
- a pre-existing directory whose **access** ACL group class does not grant the
  group `rwx` after the mask is applied, even when the mode and the default ACL
  both read correctly. A named ACL entry creates a mask and a later `chmod 2750`
  sets that mask to `r-x`; the mode then reports the mask as its group field, so
  the two agree and the directory is unusable. This is the case the default-ACL
  check cannot see, and the check reads the whole ACL for it;
- a pre-existing directory whose **owner** cannot write, which the mode bits show
  and no other check was reading;
- a pre-existing control lock file whose mode is not `0640`, or which is not
  owned by `root:mosdns`, is reported rather than silently repaired by an
  installer running as an unrelated user. The lock path is asked with `lstat`,
  not `Path.exists()`: a dangling symlink, a path under a non-directory and a
  path under an unsearchable parent all read as "no lock here" to `exists()`, and
  all three are a refusal — a symlink in particular, because the control
  operations open this path and open follows it.

- [ ] **Step 3: Run tests and verify failure**

```bash
python3 -m unittest installer.tests.test_preflight -v
```

Expected: import failure.

- [ ] **Step 4: Implement `--check-only`**

Use subprocess argument arrays only. Parse `nmcli -t -f NAME,UUID,TYPE,DEVICE connection show --active`, identify the primary wired/wireless connection, and verify systemd-resolved controls DNS. Do not write files or call mutating `nmcli` commands in preflight.

The process boundary is guarded three ways rather than one, because `os` is
imported at module scope for `readlink` and `lstat` and a needle list could not
therefore refuse the module: a named list of process-creating attributes across
`os`/`pty` (the earlier list missed `os.fork` and `os.posix_spawn`, both of which
start a process the injected runner never sees), an allowlist of the `os`
attributes this module may use, and the existing needle list for the ways it
argues about shells. All three read the code with comments and string literals
blanked out, so a docstring explaining why there is no shell does not fail the
scan that says there is none. Each has a control case proving it fires, and the
documented limit is that a call spelled through `getattr` passes all three — the
layer below is the `FakeRunner`, which refuses a string.

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

Record fake commands and assert this order. This list was wrong in two ways when
it was written and is corrected here against the code: it interleaved
enable/start per unit where the code enables BOTH units first, and it omitted the
prefix-list publication entirely.

```text
preflight
refuse a probe the router would answer locally        (no command; reads two files)
capture current DHCP DNS
write and validate root-only backup
enable dnscrypt-proxy
enable mosdns-router
publish the Cloudflare prefix list                    (mosdns-cdnctl update-lists --refresh-ranges)
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

Both enables come before the publication and both starts, and the publication is
between them: `cdn_rewrite` refuses to CONSTRUCT without
`/var/lib/mosdns/lists/cloudflare-prefixes.txt`, so starting the router before
anything has published that file fails the unit at start on a machine whose only
resolver is the one that just failed. `update-lists --refresh-ranges` is the
command that publishes it, with every path at its default; it measures nothing
and spends no bandwidth budget, and its own help text calls it "the mode an
installation runs before the router starts". A first install therefore needs
either a reachable origin or a seeded cache envelope, and no network and no cache
refuses -- which is the correct direction for a hard start requirement and the
reason the step is a refusal rather than a warning. On a RE-install the step runs
identically, because the list is republished idempotently from whatever envelope
is there.

A unit that was already running before this transaction is `try-restart`ed rather
than `start`ed, so an upgrade's verification describes the binaries this package
just installed; the sequence above is the FIRST-install shape, and a unit whose
prior state could not be read is still only `start`ed.

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

- [ ] **Step 7: Implement the capture call and the NM mutation**

Invoke the capture as an argument array, never a shell string:

```text
python3 -m mosdns_dhcp_bridge.cli --capture-current INTERFACE --state-file /run/mosdns/dhcp-upstreams.json --lock-file /run/mosdns/dhcp-bridge.lock
```

with an environment scrubbed of exactly four names: `NM_DISPATCHER_ACTION`, `DHCP4_DOMAIN_NAME_SERVERS`, `DHCP6_DOMAIN_NAME_SERVERS` and `CONNECTION_UUID`. `CommandRunner.run(args, check=True)` has no `env=` parameter, so the caller's environment is inherited by default and each of the four changes what the capture records:

- `NM_DISPATCHER_ACTION`: any exported value, empty included, makes `--capture-current` a usage error and exits 2 before a single command runs.
- `DHCP4_DOMAIN_NAME_SERVERS` and `DHCP6_DOMAIN_NAME_SERVERS`: the collector ranks them below the raw NetworkManager fields but above the effective device DNS and resolved, so a stale exported value is recorded as the source `dispatcher-env`. NetworkManager builds the real event's own environment and never puts those names in it, so no later event can reproduce that state — a guaranteed generation advance, and a cache flush, at the moment there must be none.
- `CONNECTION_UUID`: the environment wins over the authoritative `nmcli -g GENERAL.CON-UUID` lookup, so a stale exported value makes the capture name the *wrong* connection and skip the query while the first real `up` event names the true one. That is a certain second generation over a state which briefly claims a lease the router is not following.

`DEVICE_IP_IFACE`, `INTERFACE` and `DEVICE` need no scrubbing: `_capture` never reads them.

The connection lookup is mandatory even when the lease named no resolver, so a first-install capture that cannot read the connection exits 4 and publishes nothing: the state file keeps the generation it had, and the resolvers the collector had already read are discarded. That is the fail-closed choice — a state carrying resolvers and no connection is refused by the publisher anyway — but exit 4 is a defined outcome of this step rather than an unexpected one, and the discarded addresses are real: the machine had a lease and the capture could not record which connection it belonged to. The failure-injection test in Step 2 has to treat that outcome as a rollback point like any other.

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

- `/etc/mosdns/mosdns.yaml`
- `/etc/mosdns/dnscrypt-proxy.toml`
- `/etc/mosdns/policy.yaml`
- `/etc/mosdns/force-ech-domains.txt` — carrying at least one comment line, NOT empty
- documented empty `/etc/mosdns/cloudflare.txt` and `/etc/mosdns/cloudfront-domains.yaml`

The forced-ECH list is the one line above that changed, and it changed because
the first version of this plan was wrong in a way that would have failed the
build. `cdn_rewrite` REFUSES a zero-byte forced-ECH list by design (ruling 127):
an empty list and a missing list are the same document, and "forcing ECH off"
has to be said rather than implied by a zero byte count. So the shipped file
carries a comment line and no entries, which is the documented way to ship
"off" — and the test holds the comment line, not the emptiness.

The candidate and profile documents are genuinely empty of CONTENT and are not
refused: `cloudflare.txt` is a list of extra addresses to measure and
`cloudfront-domains.yaml` is a map of hostname profiles, both with an empty
document as a valid and documented value.

Do not ship `114.114.114.114`, `119.29.29.29`, AliDNS, DNSPod, or any other domestic public DNS.

After editing `policy.yaml`, run `sudo mosdns-cdnctl validate --policy /etc/mosdns/policy.yaml` and restart `mosdns-router` so the ECH/AAAA policy is reloaded. Timer and optimizer invocations read the validated file on every run. Custom DNSCrypt stamps are edited in `dnscrypt-proxy.toml` and require a dnscrypt-proxy restart.

- [ ] **Step 3: Add Debian metadata**

Package name `mosdns-router`, version `0.1.0`, architectures `amd64 arm64`, dependencies `python3 (>=3.10), systemd, network-manager, systemd-resolved, libc6`. Mark shipped configs as conffiles. `postinst` calls installer `install`; `prerm` calls `uninstall`; and `postrm purge` does the data removal ITSELF, not by calling `uninstall --purge`.

**Recorded deviation on `postrm purge`, and the reason it is a deviation rather
than an oversight.** This plan first asked `postrm purge` to call the installer's
`uninstall --purge`, and that verb cannot exist in that script: dpkg removes this
package's files BETWEEN `prerm remove` and `postrm purge`, so by the time
`postrm purge` runs there is no `/usr/lib/mosdns-router/mosdns_installer.py` to
call. The shipped `postrm` says so in its own header, checks the three conditions
the installer applies (not a symbolic link, a directory, absent is not an error),
removes `/var/lib/mosdns` and the dispatcher hook directly, and points at the
operator's own `uninstall --purge` for the path that does both halves in one
place.

What that loses is nothing, and the reason is an ordering rather than a
behaviour: `uninstall --purge` guarantees that the state directory goes only
after the NetworkManager restore has SUCCEEDED, and that guarantee is already
established, because `prerm` has run the restore and exited non-zero if it did
not finish — and dpkg does not reach `postrm` at all in that case.

`postinst` must provision the state directories before any unit starts, and the
package-content test asserts the provisioned identity:

```text
/var/lib/mosdns              root:mosdns  2770  (setgid, default ACL rwx for mosdns)
/var/lib/mosdns/runtime      root:mosdns  2770  (setgid, default ACL rwx for mosdns)
/var/lib/mosdns/lists        root:mosdns  2770  (setgid, default ACL rwx for mosdns)
/var/lib/mosdns/runtime/control.lock  created on first acquire at 0640
/run/mosdns                  root:mosdns  2770  (setgid, default ACL rwx for mosdns)
```

**Correction (Task 3, measured on the system-level test machine): the mode is
`2770`, not `2750`.** The table above first said `2750` while the prose below
asked for "a group-writable setgid directory", and only one of those is
possible. A directory's group permission is what a member of the owning group
gets on the *directory*, and it has to include `w`: creating a state file,
renaming one over another and taking the control lock all need write on the
directory. On a real `root:mosdns` directory at `2750`, a member of the `mosdns`
group cannot create a file in it at all -- measured, not assumed -- while at
`2770` the same member can. `postinst` runs as root and would not notice either
way; the first thing that would notice is a service identity, and the first
thing it would fail to do is create a state file.

No mode reads `2750` while granting the group write, because when a directory
carries an extended ACL the mode's group field **is** the group-class mask. So
the default ACL granting `rwx` for new files and a group that can write the
directory are the same permission in two places, and the check reads both: the
mode for the directory, the default entries for what a new file inherits, and
the access mask for what the kernel actually applies when a named ACL entry has
narrowed it.

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

**The group and the setgid bit are not sufficient, and the mode table above first
said `2750` because it looked sufficient.** A default ACL grants the *new file*
its permissions; it does not grant the *directory* anything. Creating a file,
renaming one over another and taking the control lock all need write on the
directory, and at `2750` a member of the `mosdns` group has `r-x` on it. This was
measured on the system-level test machine rather than reasoned about: a member of
a `root:mosdns` directory's own group cannot create a file in it at `2750`, and
can at `2770`. There is no third option — when a directory carries an extended
ACL, the mode's group field *is* the group-class mask, so no mode reads `2750`
while granting the group write.

**What preflight checks, and therefore what postinst must produce:** for each of
the four directories, the type, the owner (`root`), the group (`mosdns`), the mode
bits the package provisions (owner `rwx`, group `rwx`, world none, setgid), the
group's *effective access* permission after the mask is applied, and the group's
effective *default* permission for a new file. The access half and the default
half are separate checks because they fail separately: a named ACL entry creates
a mask, and a later `chmod 2750` sets that mask to `r-x` while the default ACL
still reads `rwx` — a directory that passes every default-ACL check and that
neither service identity can write.

`postinst` therefore provisions with `install -d -o root -g mosdns -m 2770`
followed by `setfacl -d -m g::rwx`, in that order — the mode first, then the ACL.
The order is load-bearing and the reverse is wrong: `install -d -m 2770` writes the
mode with no ACL present, so it leaves no mask behind, and the `setfacl` that follows
creates the default ACL with the mask its own entries imply. Running them the other
way round leaves `default:other::r-x`, because `install`'s `chmod` sets the mask a
previously created ACL had narrowed. Measured in the test container, both ways. The
`tmpfiles.d` entry provisions `/run/mosdns` the same way, since it is the same
directory on a different boot.

`/run/mosdns` is the one directory on that list that `postinst` cannot keep: `/run`
is a tmpfs, so the group, the setgid bit and the default ACL are all gone after a
reboot. **A `tmpfiles.d` entry creates it with the same properties on every boot,
and reaps `*.tmp` and `*.bak` from both `/var/lib/mosdns/runtime` and
`/etc/mosdns`** -- the second producer being `cmd/mosdns-cdnctl/publish.go`. The
package-content test asserts the entry is installed and names `/run/mosdns`.

The DHCP state file `/run/mosdns/dhcp-upstreams.json` has no producer unit and no
ordering edge, and no unit directive can say that honestly: the NM dispatcher
creates it asynchronously, the router treats its absence as "keep the current
generation" and starts green, and `ConditionPathExists` would make the router
refuse to start before the first dispatch, which is the worse outage. So the
obligation is entirely in the packaging: the dispatcher script, the `tmpfiles.d`
entry, and a package-content test that both are installed.

`Documentation=man:mosdns-router(8)`, `man:mosdns-cdnctl(1)` and
`man:dnscrypt-proxy(8)` are named by all eight units and the package must ship
those three manual pages, so a directive does not point at nothing. The unit
tests do not check this -- their `systemd-analyze verify` harness stubs `man(1)` on
purpose, so that a package which has not shipped its pages yet is not a package
whose units cannot be verified -- so the package-content test is where the pages
are asserted.

- [ ] **Step 4: Build pinned dnscrypt-proxy**

`build-deb.sh` sets `CGO_ENABLED=0` and builds dnscrypt-proxy v2.1.18 from the pinned module/source into the staging root. It must use the same Go 1.25.8 toolchain and record source SHA-256 in `/usr/share/doc/mosdns-router/BUILD-MANIFEST`.

The three binaries are installed at the exact paths the units' `ExecStart` lines
name -- `/usr/lib/mosdns-router/mosdns-router`,
`/usr/lib/mosdns-router/mosdns-cdnctl` and
`/usr/lib/mosdns-router/dnscrypt-proxy` -- and the package-content test reads
those `ExecStart` lines and asserts a file at each path, so a build that puts a
binary anywhere else fails the build rather than the first boot.

- [ ] **Step 5: Put the unit policy in the acceptance gate**

`make test-python` discovers `bridge/tests` only, so the 37 unit-policy tests do
not run in `make verify` until this is done. Add a `test-installer` target running

```make
	@$(PYTHON) -m unittest discover -s installer/tests
```

make `verify` depend on it, and add the assertion to
`scripts/test-make-entrypoints.sh` that it depends on the target and that the
target names the installer suite -- the same way that script holds the other
entry points, so a later edit cannot drop it quietly.

- [ ] **Step 6: Implement atomic package build**

Use `dpkg-deb --root-owner-group --build staging build/mosdns-router_VERSION_ARCH.deb`. Do not install the package on the development host.

- [ ] **Step 7: Run package tests**

```bash
make package
dpkg-deb --info build/mosdns-router_0.1.0_amd64.deb
dpkg-deb --contents build/mosdns-router_0.1.0_amd64.deb
```

Expected: package metadata and paths match the test; no state files or host service changes exist.

- [ ] **Step 8: Commit**

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
