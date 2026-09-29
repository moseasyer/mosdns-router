# Podman Integration Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove installation, NetworkManager integration, DNS routing, CDN/ECH behavior, failure isolation, upgrade, uninstall, and rollback for Ubuntu 22.04/24.04/26.04 entirely inside disposable Podman containers.

**Architecture:** A Python harness owns a private Podman network, a mock DHCP/DNS router, target Ubuntu systemd containers, and a mock CDN. **There is no Podman machine and no virtual machine of any kind.** The development host runs rootless Podman directly; each target container has its own network namespace, so a test run that changes DNS changes only the container's DNS. The host is used to build artifacts and to read before/after snapshots; no project installer runs directly on it.

> **Why no Podman machine, and why it was not merely parked.** Podman machine requires `qemu-img` to create its disk image. On this host that binary, `qemu-system-x86_64`, `/dev/kvm` and any `vmx`/`svm` CPU flag are all absent, so `podman machine init` cannot create an image at all. It was built once, found to be unstartable, and removed together with the qemu packages; the user's decision is that no virtual machine is used. Rootless Podman containers are sufficient and are proven to work here.

> **How NetworkManager is made to manage a device — measured, and the mechanism is version-dependent.** A container's default rootless network hands it a **tun/tap** device, and NetworkManager refuses that device type by design (`GENERAL.TYPE: tun`, activation fails with *device is strictly unmanaged*). Use a **netavark bridge network**, which gives the container a real `eth0` of type `ethernet`. Beyond that the answer is not one mechanism but **two**, and which one works depends on the release's NetworkManager.

> **The declaration is the baseline: `/etc/NetworkManager/conf.d/10-mosdns-target.conf`, shipped by the target image on every release.** NetworkManager's own `/usr/lib/NetworkManager/conf.d/10-globally-managed-devices.conf` ships `unmanaged-devices=*,except:type:wifi,except:type:gsm,except:type:cdma` — byte-identical on 22.04 and 26.04 — so every non-radio device is unmanaged unless something says otherwise. The target image's snippet **narrows that list with `except:interface-name:eth0`**, which is NetworkManager's own documented key for "this device is handled by NetworkManager even when it would not otherwise be". Measured: on 22.04 with the sequence skipped entirely, that one line takes `GENERAL.NM-MANAGED` to `yes` and the device to `100 (connected)`. It needs nothing else: `[ifupdown] managed=true` was also measured and does **not** work on 22.04, so the `[keyfile]` `except:` is the whole mechanism.

> **The previous note's prohibition on a `conf.d` entry is withdrawn; it was reasoned from the 24.04 measurement and does not survive the 22.04 one.** It said *do not add a `NetworkManager.conf.d` entry to force this; the override-and-restart path is the measured one* — which was true on 24.04, where the path exists, and false on 22.04, where it cannot be made to exist. The prohibition is replaced by the distinction it was reaching for: the declaration is the *baseline*, and the boot check is what keeps the baseline honest.

> **The `nmcli device set … managed yes` + `systemctl restart NetworkManager` sequence works only from NetworkManager 1.44, and below that it is a measured no-op.** With a connection profile present, measured on this host across five releases: **nmcli 1.36.6 (22.04) → `no`**; **1.42.4 (23.04) → `no`**; **1.44.2 (23.10) → `yes`**; **1.46.0 (24.04) → `yes`**; **1.54.3 (26.04) → `yes`**. So the boundary is **1.44**, and the two sides are adjacent releases with nothing in between to be excused. Below it the command is *accepted*, the audit log records `op="device-managed" … result="success"`, the field stays `no` after the restart, and no restart can re-read what was never written. The discriminator is **the field, not the file**: on 22.04 `/run/NetworkManager/devices/<ifindex>` *does* grow a `managed=true` key once something else has made the device managed, which is NetworkManager recording state it already has. With the declaration removed, the command is accepted, the restart happens, the field stays `no`, and no key appears at all. The target image therefore **runs those two commands only where the override exists** and skips them below 1.44, saying which version it found and why; the gate's failure direction is the safe one, because skipping costs nothing the declaration does not already provide. `tests/podman/lib/podman.py` carries this as `NM_OVERRIDE_MINIMUM` and `NM_OVERRIDE_MEASUREMENTS`, and both are asserted against the image's own script.

> **A unit that restarts NetworkManager must order itself `After=` it and must NOT `Requires=` it, and this is a ruling rather than a preference.** `Requires=NetworkManager.service` reads like the obvious way to say "NetworkManager must be up first", and it is the correct spelling of that sentence — which is what makes it dangerous here. `Requires=` *also* means a deactivating required unit deactivates the requiring one, and a restart is a stop followed by a start. So NetworkManager's own restart SIGTERMed the setup unit, systemd restarted it, it created another profile and restarted NetworkManager again, and the target came up with **NetworkManager not running at all** (`Main process exited, code=killed, status=15/TERM` on every pass; `Warning: There are 4 other connections with the name 'eth0-managed'`). `Requires=` is therefore *wrong*, not merely insufficient: a missing `After=` would be a race, and a race is fixed by waiting, whereas this is a cycle and no amount of ordering fixes a cycle. The correct ordering is `After=NetworkManager.service` plus the script's own bounded wait for `nmcli general status` — and never `Requires=`, `BindsTo=`, `PartOf=`, `PropagatesStopTo=` or `Upholds=`, which propagate a stop the same way.

> **The active connection is NetworkManager's own, not the harness's.** On 24.04 and 26.04 the device comes up on a profile NetworkManager creates for itself, named `eth0`, in state `100 (connected (externally))` — the bridge gave the interface its address outside NetworkManager, and NM's own profile is what it activated. `eth0-managed` exists but is **not** the active connection. **Task 3 step 4's `nmcli connection up eth0-managed` is therefore what hands the device to the harness's profile**, and a DHCP scenario that reads the active connection before that will report a lease belonging to a different profile and conclude the mock router is broken.

> **A connection profile must exist for the device first — measured on this host, and not in the note above.** The two steps are necessary and, on their own, not sufficient: with **no** connection profile for `eth0`, both steps are accepted, `journalctl` records `op="device-managed" … result="success"`, the override is never written to `/run/NetworkManager/devices/`, and `GENERAL.NM-MANAGED` stays `no` — verified on every container tried. With a profile for `eth0` present, the same two steps take the field to `yes` and the device to `100 (connected)` — verified on three consecutive fresh containers. So the order is: **create the `eth0` connection profile, then `nmcli device set eth0 managed yes`, then `systemctl restart NetworkManager`** — and the profile therefore belongs to **Task 2, not to Task 3**. Within Task 2 it belongs to `tests/podman/images/target-nm-setup.service` and **not** to the image entrypoint: `nmcli` reaches NetworkManager over D-Bus, and there is no bus before `/sbin/init`, so an entrypoint that ran any of the three measured on this host as `Error: Could not create NMClient object: Could not connect: No such file or directory`. That was the first version's error and it is corrected here — the profile was to be created at scenario time in Task 3 step 4, which runs *after* the target has booted, so Task 2's image would have run the two steps with no profile at all, failed its own boot check, and left every cell of the matrix `incomplete` with exit 3 forever. Task 3 step 4 now **modifies** the profile the setup unit created, and says so. `tests/podman/lib/podman.py` carries this as `NM_PROFILE_STEP` and its runtime device check names it in the refusal, because a message that named only the two steps would send an operator to run them, watch them succeed, and conclude the harness was wrong.

> **A fourth capability, and it is the one DHCP needs: `NET_RAW`.** The three flags above are this plan's original list and they start a target and make NetworkManager manage its device, but a target with only those three **cannot obtain a DHCP lease**: podman's default bounding set for a rootless container does not carry `NET_RAW` (bit 13, absent from `CapEff: 00000000802c15fb`), NetworkManager's built-in DHCP client opens an `AF_PACKET` socket to send and receive DORA, and without it every transaction fails with `dhcp4 (eth0): error -1 dispatching events` while `nmcli connection up` reports *IP configuration could not be reserved (no available address, timeout)*. Measured on this host against a real dnsmasq on a netavark bridge, on 24.04; adding `--cap-add=NET_RAW` to the same container against the same router produces a full `DHCPDISCOVER`/`DHCPOFFER`/`DHCPREQUEST`/`DHCPACK` and a published DNS address. It is in the harness's cap ceiling and in the emitted array rather than in a scenario's `extra_args`, because the target is one container for the whole cell and a capability one scenario needs and another does not is a property of the run.

> **A readiness wait on a field is not a readiness wait on the process that owns the field — and `GENERAL.NM-MANAGED` is a field.** This is the same class of error as the `conf.d` note above, one level up, and it is a **ruling** rather than an observation. The cell's only readiness gate was a bounded wait for `GENERAL.NM-MANAGED: yes`. That field is produced *by* `target-nm-setup.service`, which is `Type=oneshot` with `RemainAfterExit=yes`, and on 24.04 and 26.04 the script's third step is `systemctl restart NetworkManager`. So the field reads `yes` — from the `conf.d` declaration, during the daemon's own activation — while the unit is still running and about to restart that daemon underneath it. A scenario's `nmcli connection up eth0-managed` landing in that window fails with `Error: NetworkManager is not running` (exit 8), which reads as a network fault three steps from the cause.
>
> **Measured, and the window is not a corner case — it is every boot.** Polling 12 target boots per release and recording the unit's state *at the poll where the field first read `yes`*:
>
> ```text
> release  boots  unit state when the field first read 'yes'   NetworkManager   eth0-managed profile
> 24.04       12   'inactive' or 'activating', never 'active'   activating 12/12  does NOT exist in 8/12
> 22.04       12   'inactive' or 'activating', never 'active'   active 12/12      present in 12/12
> ```
>
> The `activating` counts, which is where the harm is, are 5 of 12 on 24.04 and 8 of 12 on 22.04; the remainder were `inactive`, i.e. the unit had not started yet. **The profile column was measured over a second, 10-boot pass per release** and reads 5×`inactive`/no-profile, 3×`activating`/no-profile, 2×`inactive`/profile-present on 24.04 and 9×`activating`/profile-present, 1×`inactive`/profile-present on 22.04 -- the same conclusion, from a smaller sample.
>
> So the gate was wrong on **24 of 24 boots, 100%**, and the *visible* failure rate is a separate and much smaller number, because it depends only on whether the scenario happens to reach `nmcli` inside the window. Measured, on 24.04: **3 failures in 9 runs under load**, and **0 in 12 on a quiet machine**. An earlier version of this note attributed a 1-in-6 figure to "this commit's parent"; that measurement was taken at `4867d8d`, seven commits before the ruling, and **the parent of the ruling is itself the fixed tree** -- so the attribution was wrong and the number was not a property of the parent at all. The load-dependent figure is the reason this survived a whole task: a flaky-looking number over an underlying certainty, and no case that could have seen it.
>
> **The ruling, and it is about ordering rather than about either check alone.** The cell waits for `target-nm-setup.service` to reach a terminal state and *then* for `GENERAL.NM-MANAGED`, and the order is the fix. Neither check substitutes for the other: a unit that has finished with the device unmanaged is a target every scenario would fail on without ever having been managed, and a field that reads `yes` mid-restart is a target whose daemon is about to go away. The terminal state is `active` (`SubState=exited`, `Result=success`) — **measured, and identical on all three releases**, including 22.04 where the script skips the override sequence and so is the obvious release to expect something different. `failed` is the other terminal state and is reported **at once**, because the script's exit status is the unit's verdict and it exits non-zero naming which of the three things went wrong. `activating` is neither: it is the state a healthy target is in for the first seconds of its life, and it is the state the race lives in.
>
> The general form, because it will recur: **a field is a projection of a process's state, and it is sampled at an instant. Gate on the process when the process is the thing that must have finished.** The plan already has two instances of the same shape — a bridge network's `eth0` is a projection of podman's choice, and a DHCP lease is a projection of a DORA — and this is the first one where a *test harness* was the thing that had to finish.

**Tech Stack:** Python 3 standard library, rootless Podman container/network, Ubuntu official images, systemd, NetworkManager, systemd-resolved, dnsmasq mock router, local TLS server, Mozilla Firefox headless for live ECH verification.

**Spec:** `docs/superpowers/specs/2026-09-25-mosdns-dnscrypt-cdn-ech-design.md`

## Global Constraints

- The current development host is never a target; do not run installer/uninstaller there.
- **No virtual machine, and no `podman machine`.** Containers only.
- A requirement a container cannot close is recorded **SKIPPED with its exact wording**. It is never closed by substituting a different kind of test, and a skip is never reported as a pass.
- **A read-only source bind is allowed anywhere except `/etc`, `/run`, `/var` and `/sys`; anything that could let a container influence host state is refused everywhere.** The two cases are distinguished deliberately, and so is the reason each is policed.
  - **Read-only source bind.** The source tree is mounted at `/workspace` `:ro`. A `:ro` bind of a source directory exposes that directory's bytes to a container and nothing more: a target that reads source it was given has not changed anything on the host. So a checkout is permitted wherever the operator keeps it, **including under `/home`** — and it is permitted precisely because the mount is read-only, not because `/home` is safe in general. `Podman(...)` refuses `/etc`, `/run`, `/var`, `/sys` and `/` at construction rather than mounting them, because those four hold the host's resolver and its systemd state, and `/` contains all four. A checkout under `/home` is the normal case, not an edge case: the previous five-root rule left **no legal value at all** for `--source-tree` on a host whose checkout is under `/home`, so the harness could not run from a checkout at all, and the rule that gave way is the one whose rationale does not reach a read-only bind.
  - **What makes `:ro` actually read-only — the premise this rests on, and it is a kernel one.** The measured target runs `systemd` and therefore needs `SYS_ADMIN`, so "a target cannot write to the host checkout" is *not* a consequence of the capability policy. It is a consequence of **rootless**: a target container's mounts are created inside a **user namespace owned by an unprivileged user**, which makes its mount namespace *less privileged* than the host's, and in a less privileged mount namespace `MS_RDONLY` is **locked** — the kernel forbids clearing it. `mount_namespaces(7)` §"Restrictions on mount namespaces" [5] states it and gives the case: *"For security reasons, it should not be possible to make the mount writable in a less privileged mount namespace, and indeed the kernel prevents this"*, with `mount -o remount,rw` answering `permission denied`. Measured on this host, in a rootless container holding `SYS_ADMIN`:

    ```text
    $ podman run --rm --network none --cgroupns=private --cap-add=SYS_ADMIN \
        -v <throwaway-dir>:/mnt/probe:ro docker.io/library/ubuntu:24.04 \
        sh -c 'mount -o remount,rw /mnt/probe; echo rc=$?; echo x > /mnt/probe/marker'
    mount: /mnt/probe: permission denied.
    rc=32
    sh: 1: cannot create /mnt/probe/marker: Read-only file system
    ```

    (Measured with whatever image the machine already had; the fixed digests are Task 2's, and the reference above is illustrative. The *mount* is what the measurement is about, and it is the same one the harness emits.)

    **So the dependency is on the rootless user namespace, and therefore on the whole "no machine, rootless Podman" architecture above** — a *rootful* `podman run` creates the mount in the initial user namespace, where `SYS_ADMIN` is `SYS_ADMIN` and the remount would succeed. Nothing else in this plan substitutes for it: a container root with `SYS_ADMIN` in a rootless user namespace is exactly the case the kernel refuses, and that is not a coincidence, it is the same mechanism that makes rootless containers safe at all. Anyone considering a rootful fallback has to re-open this constraint, not just the capability one.
  - **Anything that can influence host state** is refused **everywhere**, with no path exception: a **writable** bind (the workspace mount is always `:ro`, and `:rw` on a permitted source is refused), **`--volumes-from`** (another container's filesystems), a **host device** (`--device`), plus the existing refusals for host namespaces, `--privileged`, seccomp/apparmor overrides, and a `--cap-add` beyond the measured ceiling. `/home` gets no exemption here. Two keyed `--mount` options were found reaching the host through the option the guard was not reading, and both are now refused by key: **`relabel=`** (the `--mount` spelling of `:z`, which relabels host files) and **`chown=`/`U=`** (a recursive ownership change on the host); **`bind-propagation=`** is refused too, because a *shared* bind makes a submount the target creates propagate back into the host's own filesystem or cgroup hierarchy. The rule is an allowlist of keys, so an option nobody has thought of is refused as well.
  - **The host-isolation snapshot's rules about `/home` and Firefox metadata are unchanged.** `/home` is in the mount list for a different reason than resolver state — the snapshot compares Firefox profile metadata and a run must not perturb what it compares — and that is a rule about what the harness **writes** and what it **reads back**, not about read-only source visibility. It is enforced by the snapshot, not by a path allowlist, so nothing above weakens it.
  - **Why, so a later reviewer does not restore the five-root list:** a read-only bind cannot write to the host, and the mount policy is an *allowlist compared by exact path*, not a prefix test — widening the read-only source-tree exemption to `/home` therefore adds no writable path and does not weaken any host-state check. A reviewer who disagrees must argue with that, not with the old list.
- **Every resource this harness creates carries the `mosdns-` prefix followed by the run id.** `cleanup` sweeps by that prefix and `RunResources` anchors the filter with `^`, so a container, network or volume named by hand outside the prefix is invisible to the teardown: it is not removed, it is not reported, and the next run inherits it. A task that needs a name of its own composes it from `RunResources` (`container_name`, `volume_name`, `network_name`) rather than writing one out. This is a constraint on the tasks, not a note for the reader, because the failure it prevents is silent.
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
- **The watchdog is judged on what it says as much as what it does** — a default-on mechanism that restores basic connectivity while leaving the project's actual problem in place must say so, and a switch nobody has observed in the off position is not a switch.
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
tests/podman/tests/test_matrix_cell.py
tests/podman/tests/test_dhcp_scenario.py
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

`--connection` is **not** a machine name. It is an optional Podman connection URI for a remote or native (e.g. arm64) service; omitted means the local rootless Podman, which is the acceptance path on this host. A bare word is **refused**, not documented: a name is how a machine is spelled, and podman would resolve it through a shared `connections.conf`.

Every option above is accepted **on either side of the subcommand** — `run.py --arch arm64 matrix` and `run.py matrix --arch arm64` are the same run — because a Make target and a CI variable each produce one of them.

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
podman run -d --name NAME --network mosdns-testnet --systemd=always --cgroupns=private --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=SYS_PTRACE --cap-add=NET_RAW -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v SOURCE:/workspace:ro IMAGE
podman exec NAME sh -c ...
podman cp ARTIFACT NAME:/tmp/ARTIFACT
podman stop --time 30 NAME
podman rm -f NAME
podman network rm mosdns-testnet
```

Assert that **no** `podman machine` subcommand appears anywhere in the harness, and that the source tree is mounted **read-only** and never at `/etc`, `/run`, `/var` or `/sys`. A source tree **under `/home` is accepted and emitted `:ro`** — that is the amended constraint, and a case must hold it, because the checkout is normally under `/home` and a refusal there leaves the harness unusable. A test must fail if a host path outside the allowed set is ever mounted, and a writable bind must fail even for a permitted source. The `podman run -d … --systemd=always …` array above is asserted **as a whole, as literals** — not as a subset — because it is the only place the measured flag set appears; and the suite carries a guard that fails on any two cases in the harness's own test files sharing a name, since `unittest` silently keeps the last of them and a shadowed case is invisible in its output.

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

Target image installs `systemd-sysv`, `dbus`, `NetworkManager`, `libnss-resolve`, `python3`, `iproute2`, `dnsutils`, `curl`, `ca-certificates`, and test tools, but does not install the project package at build time. Mock router installs `dnsmasq-base`; mock CDN is built from the repository's Go module and installs no server package at all.

**`libnss-resolve`, and not the package named `systemd-resolved`.** The latter is a binary package on 24.04 and 26.04 and does not exist on 22.04 at all, where the daemon is part of `systemd` — so naming it fails the 22.04 build with `E: Unable to locate package systemd-resolved` (measured, in this task). `libnss-resolve` exists on all three, brings the daemon with it where it is a **hard `Depends`**, and is the NSS module without which a lookup in a target reads `/etc/hosts` and then the network and never asks 127.0.0.53.

> **But on 26.04 the daemon is a `Recommends`, so the target image installed the module and no daemon.** Measured in the 26.04 target image this task's first cell built: `dpkg -s libnss-resolve` reads `Depends: libc6 (>= 2.39)` and `Recommends: systemd-resolved`, and `command -v resolvectl` answers nothing — against 24.04, where the same package says `Depends: … systemd-resolved (= 255.4-1ubuntu8.17)`. The image builds with `--no-install-recommends`, for a good reason stated in the Containerfile, so on 26.04 a target had `libnss_resolve.so.2` and **nothing behind it**: every lookup went to a stub nobody was listening on, and the DHCP scenario's own `resolvectl dns eth0` exited 127. Found by running the third release, not by reading the manifest. The Containerfile therefore installs `systemd-resolved` **where the release has it as a package**, guarded by `if apt-cache show systemd-resolved >/dev/null 2>&1; then apt-get install …; fi` — the guard and the install name the same package on purpose, and `tests/podman/tests/test_images.py` holds the two names equal, holds the package against the availability table, and counts every `apt-get install` in the file so a third spelling is neither refused nor recorded but *noticed*.


**The mock CDN installs nothing in its serving stage, and that is a measurement too.** `caddy` does not exist on 22.04 — not in `main`, not in `universe` — so an image that installed it could not be built on a third of the matrix, and the plan's own answer is the Go module's own TLS server. Every package any of the three images installs is checked against all three locked releases, and **the set of images is discovered by glob**, so a Containerfile added in a later task is covered without anybody editing the check.

**The sequence runs from `tests/podman/images/target-nm-setup.service`, a systemd unit the target image installs and enables — and *not* from the entrypoint.** `nmcli` reaches NetworkManager over D-Bus, and before `/sbin/init` there is no bus to connect to, so an entrypoint that ran these commands itself would fail its first one with `Error: Could not create NMClient object: Could not connect: No such file or directory` (measured) and leave every target unmanaged. The unit runs the sequence in this exact order, and the profile comes first:

```sh
nmcli connection add type ethernet ifname eth0 con-name eth0-managed ipv4.method auto
nmcli device set eth0 managed yes
systemctl restart NetworkManager
```

The target's **entrypoint** has its own job and does not touch NetworkManager: it points `/etc/resolv.conf` at the resolved stub — Podman bind-mounts a generated one over that path in every container *and* every build step, so the image cannot own it and the entrypoint unmounts it inside the container's own mount namespace — and then `exec`s `/sbin/init` so systemd is PID 1.

**The declaration is the baseline, the sequence is the second mechanism, and on 24.04 and 26.04 the declaration is inert.** `/etc/NetworkManager/conf.d/10-mosdns-target.conf` narrows NetworkManager's shipped `unmanaged-devices=*` with `except:interface-name:eth0` and works on all three releases; on 22.04 it is the *only* mechanism that does, because the sequence is skipped there (no persistent device override below nmcli 1.44). But measured on a fresh 24.04 and 26.04 target with the declaration removed and `/run/NetworkManager/devices` cleared, the device still comes up `yes` — so a rename of the file is caught **only on 22.04**, and the boot check cannot fail because of it on the other two. The image gates the sequence on the measured nmcli boundary, and the boot check asserts the field on every release.

The first line is the same command as `NM_PROFILE_STEP` in `tests/podman/lib/podman.py`, which was measured on this host: with **no** profile for `eth0`, the two steps are accepted, the audit log records `op="device-managed" … result="success"`, the override is never written to `/run/NetworkManager/devices/`, and `GENERAL.NM-MANAGED` stays `no`. **`target-nm-setup.service` creates the profile**, before the two steps, and nothing creates it at scenario time: a profile created later leaves the window where the target is unmanaged open to the first scenario, and the plan's whole correction — that the profile must exist *before* the steps — only holds if the three commands run once, at boot, in order. A profile created from the image's entrypoint would not merely be in the wrong place, it would be uncreatable there: `nmcli` has no D-Bus to connect to before `/sbin/init` (measured, above), so the creation would fail and the target would boot unmanaged. Task 3 step 4 works on the profile this line creates.

The unit must then **fail loudly** if `nmcli -g GENERAL.NM-MANAGED device show eth0` is not `yes` afterwards. The check asserts the **ordering**, not just the final value: the profile must exist (`nmcli -g 802-3-ethernet.device connection show eth0-managed`, or `nmcli connection show eth0-managed`) *and* the field must be `yes`, so a setup script that reorders or drops the profile fails with the two facts it needs rather than a bare "unmanaged". A target that boots with an unmanaged device produces a scenario failure that looks like an installer bug, so this is checked at boot and the check is part of the image, not of each scenario — and it has to be **in the unit rather than the entrypoint** for the same D-Bus reason: `nmcli` cannot answer in the entrypoint, so a check there would pass vacuously and the boot would go unchecked. **The target image also declares the device managed by configuration, in `/etc/NetworkManager/conf.d/10-mosdns-target.conf`, and the boot check is what keeps that declaration honest.** This replaces the earlier instruction not to add a `NetworkManager.conf.d` entry, which was reasoned from the 24.04 measurement and does not survive the 22.04 one — see the architecture note, which carries the five-point version table. The check must still *assert* `GENERAL.NM-MANAGED: yes` and fail loudly with the observed value and the `nmcli --version` when it is not, so a declaration that is written, read and does not take effect still fails the boot.

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

> **`--conf-file` is the wrong file to rewrite, and this step's original sentence was wrong about HUP.** Measured, in `dnsmasq(8)`'s own NOTES section on this host: *"SIGHUP does NOT re-read the configuration file."* It re-reads `/etc/hosts`, `/etc/ethers` and **the files named by `--dhcp-hostsfile`, `--dhcp-optsfile`, `--addn-hosts` and friends** — and an option found in `--dhcp-optsfile` takes precedence over `dhcp-option`. So the control command rewrites `/etc/dnsmasq-dhcp-opts` (a path declared in the shipped config and absent from the checkout, so the write is inside the container), sends HUP, and the new DNS address reaches the next DHCP transaction. Rewriting `/etc/dnsmasq.conf` and sending HUP would change nothing, and the scenario would then report a *stale* baseline as a pass. **The shipped config does *not* carry `dhcp-option=option:dns-server,10.89.0.2`, and it must not.** (An earlier draft of this note said it did; that was wrong, and the reason it is wrong is the interesting part.) The baseline option 6 lives in the option *file*, which the mock-router image creates with `6,10.89.0.2` in it, so there is exactly one written-down source for the DNS the router hands out. Two sources make dnsmasq say so — measured on the first live 22.04 cell:

```text
dnsmasq-dhcp[1]: Ignoring duplicate dhcp-option 6
```

beside the option it actually sent, and **the line does not say which of the two it ignored.** That log is the document the DHCP scenario records as the attribution for a DNS address, so a reader has to resolve the ambiguity before they can read the rest of it. dnsmasq's own default for option 6 is "the address of the machine running dnsmasq", which here *is* `10.89.0.2` — so the baseline is right either way, and what changes is that a value a test asserts is one the harness wrote down rather than one a future dnsmasq release decides.

`tests/podman/tests/test_dhcp_scenario.py` holds the absence, and `PlanAgreesWithTheShippedRouterConfigTest` holds *this sentence*, so the plan cannot drift back to describing a config line the image does not have.

- [ ] **Step 4: Make target use NetworkManager**

The Ethernet connection for `eth0` **already exists**: `tests/podman/images/target-nm-setup.service`, which Task 2's image installs and enables, creates it (see Task 2's Step 3) because the measured device sequence does not take effect without it. So this step **modifies the profile the setup unit created**, and must not create a second profile and must not race the unit — by the time a scenario runs, the unit has finished and the device is managed.

```sh
nmcli connection modify eth0-managed ipv4.never-default yes
nmcli connection up eth0-managed
```

`ipv4.never-default yes` is a **post-boot scenario change**, not a boot precondition: it is set here, after the target's boot has already made the device managed, and re-activating the profile re-runs DHCP. The boot profile is created with `ipv4.method auto` and automatic DNS; the `never-default` change belongs to the DHCP scenario, which confirms `IP4.DNS` contains the mock address after the change and before running the package installer.

- [ ] **Step 5: Run the scenario in the target container**

```bash
python3 tests/podman/run.py matrix --arch amd64 --versions 22.04 --scenario dhcp
```

Expected: PASS; host snapshot unchanged. Until the `dhcp` scenario is registered, this command is **refused** with exit 2 and the name in the message — `--scenario` is either run or refused, never parsed and ignored, because a silent no-op on the flag the plan's own acceptance command passes reads as "the harness looked and did not find it".

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

Use the locked image, `--systemd=always`, `--cgroupns=private`, `--cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=SYS_PTRACE --cap-add=NET_RAW`, `-v /sys/fs/cgroup:/sys/fs/cgroup:rw`, and the private network's fixed IP. These are the exact flags measured to work on this host; `--cgroupns=host` and `--privileged` are **not** used — they were written for the machine architecture this plan no longer has, and the measured set is narrower. **`NET_RAW` is the fourth flag and Task 3 measured it necessary**: a target with only the three above cannot obtain a DHCP lease, because NetworkManager's built-in DHCP client opens an `AF_PACKET` socket (see the architecture note). Anything a scenario adds goes through the wrapper's `extra_args`, which refuses a privilege flag, a host namespace, a capability outside the four above, a device, a seccomp/apparmor override and `--volumes-from`, in both spellings pflag accepts. Do not mount host system directories. Copy the `.deb` with `podman cp`, then install it inside the container.

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

### Task 8: Add the resolver watchdog, on by default and switchable off

**This task exists because the previous plan left a decision open and the user has now
made it.** It is a product feature inside a testing plan, which is a deliberate
placement and not an accident: the `emergency-rollback` action is the previous plan's,
the health unit that detects the condition is this plan's image, and **this** plan's
harness is the only place the behaviour can be observed at all — kill the router inside
a container and watch what happens is not something a fake command runner can answer.
There is no plan 8, and re-opening a closed plan to add a feature would be worse.

**Interfaces:**
- Consumes: the health unit's resolvability probe, `mosdns-cdnctl emergency-rollback`,
  and an operator setting.
- Produces: a watchdog that restores the machine's own resolvers when the local one has
  stopped answering, and a documented way to turn that off.

- [ ] **Step 1: Write the decision down before the code, in the plan and in the docs**

The user's decision, verbatim in substance: **automatic rollback is the default, and it
must be possible to switch it off.** Record also what automatic rollback actually
restores and what it does not: it restores the machine's own (DHCP-provided) resolvers,
so basic connectivity returns while **foreign-name resolution through DNSCrypt does
not** — the condition this project exists to fix is unfixed, only no longer in the way.
An operator reading the log at 3am must be able to learn that from the message itself.

- [ ] **Step 2: Write the setting, its default, and its shape**

An operator-authored file under `/etc/mosdns/` — the same directory and the same
ownership rules as the other user inputs, so an unprivileged read cannot change it.
`automatic: true` is the shipped default. Also settable: the **consecutive-failure
count** and the **minimum elapsed time** before anything is touched.

**Why the window exists, stated as a decision and not as a caveat.** A single failed
probe is not evidence that the router is down: an upstream that is slow, a cold boot
before NTP has synchronised, and a loaded machine all produce one. With automatic
rollback as the *default*, a single-probe trigger is a mechanism that can tear down a
working configuration while the operator is using it, and a self-inflicted outage is
worse than a false alarm. The window is therefore part of the default behaviour rather
than an opt-in hardening — and the two numbers are **settings**, because the false-
positive rate has not been measured and a number nobody measured should not be baked in.

- [ ] **Step 3: Write the watchdog**

A systemd timer alongside the health timer, so it inherits the packaged unit's
hardening rather than inventing its own. Each run: probe resolvability through the
**same predicate the health unit and the installer already use** — a second definition
of "resolvable" is exactly the defect this project has been correcting. On failure,
record it and stop; on the Nth consecutive failure, or once M minutes have elapsed
since the first, run `emergency-rollback` **exactly as the operator would**, so the
watchdog cannot take a path a human would not. On a successful probe, reset the counter
and log that it did.

- [ ] **Step 4: Make every refusal and every action say what it did**

- Not enough failures yet: name the count, the threshold, the elapsed time and the
  first-failure timestamp, so the operator can tell "working" from "about to act".
- The action failed: name the action's exit status and what the operator should run by
  hand. **Never claim the machine is back when it is not** — that is the defect class
  this project has hit repeatedly, and the `postinst` fix-round history is the
  precedent.
- The action succeeded: name what was restored, and repeat the limitation in
  production, not only in the docs.

A test that reads these messages and would fail if a claim were removed.

- [ ] **Step 5: Prove the switch works, in a container, and prove the action is the real one**

A scenario that: points the machine at the local resolver, stops the router, and
records what the watchdog does across the window — nothing before the threshold, the
real `emergency-rollback` after it, the recorded DNS restored, the machine still
usable. Then the same scenario with `automatic: false` must observe **no** action at
all across a window longer than the default, and the operator's manual
`emergency-rollback` must still work afterwards. A switch that has never been observed
in the off position is not a switch.

- [ ] **Step 6: Document it where an operator will actually read it**

The man page, the README or `docs/testing.md`'s troubleshooting section, and the
setting file's own comments. State the default, the two numbers, what is restored and
what is not, and how to disable it.

- [ ] **Step 7: Commit**

```bash
git add packaging/systemd tests/podman/scenarios docs
git commit -m "feat: roll the machine's resolvers back when the local one stops answering"
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
