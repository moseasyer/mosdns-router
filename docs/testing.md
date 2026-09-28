# Testing

Two kinds of tests live in this repository, and the difference between them is
not how thorough they are — it is **where they run**.

| | Unit / integration | System-level matrix |
|---|---|---|
| Where | this machine | disposable Podman containers on this machine |
| Command | `make verify` | `python3 tests/podman/run.py …` |
| Touches the host's DNS? | no | no |

`make verify` is fast, hermetic, and **never** a test target: it builds a fake
root, injects a command runner, and uses loopback high ports. Nothing in it
reads or writes `/etc/resolv.conf`, `systemd-resolved`, or NetworkManager
state.

The system-level matrix exists to close the claims the unit suite cannot,
which is almost everything about what actually happens when the installer
takes over DNS. It runs the real installer, the real NetworkManager
integration and the real resolver — inside containers that have their own
`/etc`, their own `systemd-resolved`, and their own network namespace.

## The system-level harness

`tests/podman/run.py` is the entry point.

```bash
python3 tests/podman/run.py preflight   # can this host run the matrix?
python3 tests/podman/run.py matrix      # run the scenarios
python3 tests/podman/run.py cleanup     # remove anything a run left behind
```

Start with `preflight`. It reports the Podman client version, the store
driver, the source tree it would mount, and the NetworkManager fact below.
It changes nothing.

**`matrix` exits 3 today**, with every version reported `incomplete` and the
reason `no scenario is registered in this build of the harness`. That is the
honest answer: the target image, the mock router and the scenarios are built
by later tasks, and until one is registered nothing ran. Exit 3 means
*incomplete*, which is deliberately not a pass. Exit codes are the interface:

- `0` — everything requested passed
- `1` — a test failed
- `2` — a harness or configuration error
- `3` — an incomplete matrix (nothing ran, or a required architecture was skipped)

Every run writes `build/test-results/<run-id>/report.json`. A requirement the
containers could not close is recorded there as **SKIPPED with its exact
wording**. It is never reported as a pass, and never closed by substituting a
different kind of test.

## The images, and the digests they are built from

The matrix runs three target images, one per Ubuntu release, and every one of
them is pinned by digest.

```text
tests/podman/images/target.Containerfile        the target: systemd, NetworkManager, resolved
tests/podman/images/target-entrypoint.sh        its PID 1: the resolver, then systemd
tests/podman/images/target-nm-setup.sh          the NetworkManager sequence and its boot check
tests/podman/images/target-nm-setup.service     the unit that runs it once, at boot
tests/podman/images/10-mosdns-target.conf        declares eth0 managed, on every release
tests/podman/images/mock-router.Containerfile   dnsmasq, serving DHCP and DNS
tests/podman/images/mock-cdn.Containerfile      the CDN server, built from this module
tests/podman/images.lock.json                   the three digests, and how each was read
```

**A tag is not a pin.** `ubuntu:24.04` is whatever the registry serves that day,
and Ubuntu ships a point release under the same tag without the tag changing. So
the base image is a build argument with no default:

```bash
BASE=$(python3 - <<'PY'
import sys; sys.path.insert(0, "tests/podman/lib")
import images; print(images.reference_for_version("24.04"))
PY
)
podman build -f tests/podman/images/target.Containerfile \
    -t mosdns-target:24.04 --build-arg BASE_IMAGE="$BASE" .
```

`images.reference_for_version` refuses rather than falling back to a tag, and it
refuses three ways: a digest without the `sha256:` prefix, a version the lock has
no entry for, and a version recorded `unavailable`. **Falling back to a tag would
be the worst of the three answers available** — the build would succeed against a
floating image and the lock would be doing nothing.

Each entry in `images.lock.json` carries the command its digest was read with, so
a reader who doubts one can re-run that command. A digest with no provenance is a
claim, not a pin, and the two are indistinguishable by inspection: both match
`sha256:` and both are 64 hex characters. The suite asks the registry to serve
each digest again rather than trusting the file.

**No image installs this project's package.** The `.deb` is copied in at scenario
time. An image that installed it would make its own packaging the thing under
test before a single scenario ran, and the install transaction — the claim this
whole plan exists to close — would have been exercised by the image build instead
of by the install scenario.

## The host snapshot: what it is for

A run writes `build/test-results/<run-id>/host-before.json` and `host-after.json`
before and after, and the comparison is the plan's evidence that the run changed
nothing on this machine.

Seven fields, and they are the ones that would change if a run reached the host's
resolver:

| field | read from |
|---|---|
| `os_release` | `/etc/os-release` |
| `resolv_conf_link` | the **symlink target** of `/etc/resolv.conf`, not the file |
| `networkmanager_connections` | `nmcli connection show` |
| `resolvectl_status` | `resolvectl status` |
| `project_units` | `systemctl list-unit-files`, filtered to this project's units |
| `listening_sockets` | `ss -lntup` |
| `firefox_profiles` | path names, mtimes and sizes under the Firefox roots |

Three properties make the record worth anything, and each is a way it could have
been written wrongly:

- **It only runs read-only commands, as argument arrays.** Six of the seven fields
  come from one command each. The six arrays are asserted as literals against the
  ones the suite names, so a seventh — a mutating one — fails that case.
- **The resolver is recorded as its *link*.** This host's `/etc/resolv.conf` is a
  systemd stub symlink. Reading the file it points at would record resolved's
  *generated* content, which changes whenever a network does, and every run would
  report a host change for something it always does.
- **A Firefox profile is metadata, never content.** The field is gathered with
  `lstat` and `scandir`, and **no profile file is opened** — which is checked by
  auditing every `open` on the Python surface while a real directory of real files
  is walked, because "no content is used" would also be true of a module that read
  the bytes and threw them away. It is name, mtime and size precisely because a
  listing cannot change those; recording access time would give the field a value
  that differs between two snapshots of an unchanged machine, because taking the
  snapshot is itself a read.

Each field is normalised (lines sorted; connection UUIDs and process ids replaced)
and hashed. The normalisation drops what identifies an *instance* rather than
describing the machine, because a machine's pids and profile UUIDs differ on every
boot and a snapshot that carried them would report a change constantly. Everything
that describes what the machine is *doing* is kept — nameservers, ports, device
names, unit names. A field whose command this host does not have is recorded as an
error rather than raised: a host without NetworkManager has a before/after pair to
give, and no snapshot at all is indistinguishable from no change.

## The measured fact the whole plan turns on, on all three releases

**A target's `eth0` is managed on 22.04, 24.04 and 26.04, on a netavark bridge
network, out of the locked images in this repository.** Measured by building
`target.Containerfile` at each locked digest and running it with the flag set the
wrapper emits:

| release | nmcli | `GENERAL.NM-MANAGED` | `GENERAL.TYPE` | `GENERAL.STATE` | active connection | profile | unit | failed units |
|---|---|---|---|---|---|---|---|---|
| 22.04 | 1.36.6 | **`yes`** | `ethernet` | `100 (connected (externally))` | `eth0` | `eth0-managed` present | active | 0 |
| 24.04 | 1.46.0 | **`yes`** | `ethernet` | `100 (connected (externally))` | `eth0` | `eth0-managed` present | active | 0 |
| 26.04 | 1.54.3 | **`yes`** | `ethernet` | `100 (connected (externally))` | `eth0` | `eth0-managed` present | active | 0 |

### Two mechanisms, and which one applies

**1. The declaration, which is the baseline on every release.** NetworkManager
ships `/usr/lib/NetworkManager/conf.d/10-globally-managed-devices.conf` containing

```ini
[keyfile]
unmanaged-devices=*,except:type:wifi,except:type:gsm,except:type:cdma
```

so every non-radio device is unmanaged unless something says otherwise. The
target image ships one file,
`/etc/NetworkManager/conf.d/10-mosdns-target.conf`, which **narrows that list**
with `except:interface-name:eth0` — NetworkManager's own documented key for "this
device is handled by NetworkManager even when it would not otherwise be". It works
on all three releases, and on 22.04 it is the only mechanism that does.
`[ifupdown] managed=true` was also measured and does **not** work on 22.04.

**2. The sequence, which works only from NetworkManager 1.44.** With a connection
profile present, measured across five releases:

| release | nmcli | `nmcli device set … managed yes` + restart |
|---|---|---|
| 22.04 | 1.36.6 | `no` — accepted, and changes nothing |
| 23.04 | 1.42.4 | `no` — same |
| 23.10 | 1.44.2 | `yes` |
| 24.04 | 1.46.0 | `yes` |
| 26.04 | 1.54.3 | `yes` |

The boundary is **1.44**, and the two sides are adjacent releases, so nothing is
excused in between. The target image therefore **runs the sequence only where the
override exists** and skips it below 1.44, naming the version it found. On 22.04
the journal says so:

```text
target-nm-setup: this NetworkManager (nmcli tool, version 1.36.6) has no
target-nm-setup: persistent device override, so 'nmcli device set eth0 managed
target-nm-setup: yes' would be accepted and would change nothing, and no restart could
target-nm-setup: re-read it. Skipping both; the managed state comes from the conf.d
target-nm-setup: declaration, and the check below is what decides whether it took effect.
```

The discriminator is **the field, not the file**. On 22.04
`/run/NetworkManager/devices/<ifindex>` *does* grow a `managed=true` key once the
device is managed — but that is NetworkManager recording state it already has. With
the declaration removed, the command is accepted, the restart happens, the field
stays `no`, and no key appears at all. A check that read the file would have been
reading a consequence.

### The boot check is what keeps the declaration honest

The declaration is a file, and a file can be written, read, and not take effect. So
the setup script **asserts** `GENERAL.NM-MANAGED: yes` after the sequence and
refuses to boot when it is not — with the observed value, the declaration's path,
and the `nmcli --version` it found. A case runs the script with a declaration that
is present and *ignored* and requires a non-zero exit, with a control that a
managed device passes on the observed field alone.

### The active connection is NetworkManager's own

**`eth0`, not `eth0-managed`, on all three releases.** The bridge gave the
interface its address outside NetworkManager, so NM activated a profile it created
for itself. `eth0-managed` exists and is the profile the plan's Task 3 modifies,
but it is *not* the active connection until something activates it. A DHCP
scenario that reads the active connection before that will report a lease
belonging to a different profile.

## Prerequisites

**There is no virtual machine and no `podman machine`.** This is deliberate:
`podman machine` needs qemu, this host has none, will not get any, and rootless
Podman containers are proven to work here. If you find yourself reading about
`podman machine init`, you are reading a superseded document.

**Podman must already exist, and the harness will never install it.** There is
no install path, no `dnf`/`apt` call, no `systemctl enable`. A missing binary
is reported:

```
harness error: podman was not found at 'podman'. It is a prerequisite that the
operator provides: this harness does not install Podman …
```

Install Podman yourself with your package manager and re-run. That refusal is
not a limitation to work around; a test harness that installs packages on
somebody's working machine is a different tool from this one.

A target must be on a **netavark bridge network**, and this is not a
preference — it is the fact the previous plan got wrong.

## Why a target needs a bridge network, and the `managed yes` sequence

Podman's default rootless network hands a container a **tun/tap** device.
NetworkManager refuses that device type by design, so
`GENERAL.NM-MANAGED` stays `no` and every scenario fails for a reason that has
nothing to do with the installer. Use a bridge network; the container then gets
a real `eth0` of type `ethernet`.

Even then, it depends on the release. The target image's setup unit runs these
three, in this order, once at boot:

```bash
# 1. a connection profile must exist for eth0 first, or nothing below sticks
nmcli connection add type ethernet ifname eth0 con-name eth0-managed ipv4.method auto

# 2. then the override
nmcli device set eth0 managed yes

# 3. then the restart — the override is written under
#    /run/NetworkManager/devices/ and only a restart re-reads it
systemctl restart NetworkManager
```

Step 3 is not optional: without the restart step 2 returns success, writes
nothing that is re-read, and you conclude the harness is broken. Step 1 is not
optional either: with no profile, both later steps are accepted, the audit log
records `op="device-managed" … result="success"`, and the field stays `no`.

They run from a **systemd unit the image installs and enables**
(`target-nm-setup.service`), not from the entrypoint. `nmcli` talks to
NetworkManager over D-Bus, and before `/sbin/init` there is no bus to connect to
— measured, with an entrypoint that tried: `Error: Could not create NMClient
object: Could not connect: No such file or directory`.

**On 22.04 these three do not work**, because NetworkManager 1.36 has no
persistent device override: step 2 is accepted, the audit log records success, and
the field stays `no` after the restart. The image therefore **skips them there**
and gets `yes` from the `conf.d` declaration instead, which is why the table above
shows 22.04 coming up managed. See "Two mechanisms, and which one applies".

The harness **asserts** `nmcli -g GENERAL.NM-MANAGED device show eth0` is
`yes` on a running target before the first scenario runs, and refuses with a
message naming these steps if it is not. A target that booted wrong is then an
`incomplete` cell, not a failing scenario and not a pass.

## What a run does and does not change

- **A target container's DNS changes are the container's own.** Each target has
  its own network namespace and its own `/etc`, so a scenario that reconfigures
  DNS reconfigures the container's DNS. The host's resolver is not involved.
- **The target's own resolver is its own too, and this is a measurement.** Podman
  mounts a generated resolv.conf over `/etc/resolv.conf` in every container *and*
  in every build step, so an image cannot own that path — `ln -sf` there fails
  with `Device or resource busy`. The target's entrypoint unmounts it **inside the
  container's own mount namespace** and points it at the resolved stub. The host
  is not involved: the mount is created by the runtime inside the container, and
  the harness refuses to bind any host path under `/etc`, `/run`, `/var` or
  `/sys` at all. Verified after a real run: this host's `/etc/resolv.conf` was
  unchanged, same symlink and same mtime.
- **Two binds, and only two.** The source tree at `/workspace` **read-only**,
  and `/sys/fs/cgroup` writable (a systemd container will not start without
  it). Nothing else is ever bound in.
- **Host resolver and systemd state are refused everywhere:** `/etc`, `/run`,
  `/var` and `/sys` cannot be a mount source, and `/` cannot be a source tree.
- **A read-only source bind under `/home` is permitted.** The distinction is
  deliberate and worth knowing about, because the checkout usually lives there.
  See below.

If a source tree the policy refuses: the refusal names the root it broke and
tells you what to pass instead. `--source-tree` is the knob — point it at the
checkout directory, or omit it to use this repository. You do **not** need to
move a checkout out of `/home` to satisfy the policy; only out of `/etc`,
`/run`, `/var` and `/sys`, which no checkout belongs in anyway.

Note the difference between the two rules, because it is the thing that made
this harness unusable and is easy to get backwards:

- A **read-only** source bind is allowed anywhere except the four roots holding
  resolver and systemd state. A `:ro` bind of a source directory exposes that
  directory's bytes to the container and nothing a target could change on the
  host.
- A **writable** bind, `--volumes-from`, or a host **device** is refused
  **everywhere**, including under `/home`. The exemption is for the read-only
  workspace, not for the path.

## Cleaning up

Every resource this harness creates is named `mosdns-<run-id>-…`, and `cleanup`
sweeps by that prefix.

```bash
python3 tests/podman/run.py cleanup                  # sweep every run of this harness
python3 tests/podman/run.py cleanup --run-id <id>    # sweep one run
```

Teardown runs on the way out of a scenario even when the scenario raises, and
it continues past individual errors rather than stopping at the first. A
leftover container or network makes the *next* run fail for the wrong reason,
so a failed teardown is reported as a failure, not a warning.

## Adding a scenario

Scenarios are registered, not discovered. A scenario that is asked for by name
and is not registered is a **configuration error** (exit 2), not a silently
ignored flag: the run must not report a pass for something it never looked for.
`tests/podman/scenarios/` is where they go; `run.py` is where the registry is.
