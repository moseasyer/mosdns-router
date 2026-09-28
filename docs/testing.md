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

Even then, the device does not become managed on its own. In the target's own
init, in this order:

```bash
# 1. a connection profile must exist for eth0 first, or nothing below sticks
nmcli connection add type ethernet ifname eth0 con-name eth0-managed ipv4.method auto

# 2. then the override
nmcli device set eth0 managed yes

# 3. then the restart — the override is written under
#    /run/NetworkManager/devices/ and only a restart re-reads it
systemctl restart NetworkManager
```

Step 3 is not optional and step 2 on its own does nothing: without the restart
it returns success, does not take effect, and you conclude the harness is
broken. With all three, the field goes to `yes` and the device to
`100 (connected)`, measured on three consecutive fresh containers.

The harness **asserts** `nmcli -g GENERAL.NM-MANAGED device show eth0` is
`yes` on a running target before the first scenario runs, and refuses with a
message naming these steps if it is not. A target that booted wrong is then an
`incomplete` cell, not a failing scenario and not a pass.

## What a run does and does not change

- **A target container's DNS changes are the container's own.** Each target has
  its own network namespace and its own `/etc`, so a scenario that reconfigures
  DNS reconfigures the container's DNS. The host's resolver is not involved.
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
