# Measured facts about this development environment

This file records things that were **established by running something** on this
development host or inside its containers, because re-establishing them costs
far more than looking them up. It is documentation, not a work note: every
number here is a property of a *version of a tool* or of *this host*, and both
of those change.

It is not a record of decisions. Where a choice was made, the trade-off behind
it and the reasons for it stay in the plan
(`docs/superpowers/plans/2026-09-25-podman-integration-matrix.md`) and in the
gitignored process ledger under `.superpowers/`. What follows is the
re-derivable part only.

Two rules shape every entry:

- **Provenance.** Each fact names the command, the log line, or the value that
  was read. A number nobody can re-derive is a number nobody should act on.
- **An invalidation condition.** Every measurement says what would make it
  wrong. A stale measurement is worse than a missing one unless it is marked.

Unless stated otherwise the measurements were taken between 2026-09-25 and
2026-09-29, in the three locked Ubuntu container images and on the host, and
their transcripts are in the gitignored
`.superpowers/sdd/2026-09-25-podman-integration-matrix/` task reports. Those
transcripts are the record; this file is the index into them.

---

## When to re-measure

Re-measure a section when any of these happens. They are the actual triggers,
not a generic "if in doubt".

| Trigger | What to re-derive |
|---|---|
| **Podman is upgraded** — any change to the major or minor version | [Podman](#podman-570-on-this-host) in full: the rootless capability bounding set, `run -d` start-up timing, the long-flag alias set, the device type a given network kind hands a container, and the `system df` accounting. These are the most likely to move and the least likely to announce it. |
| **NetworkManager changes version on a target release** — a point release bump on 22.04, 24.04 or 26.04, or a new release entering the matrix | The [NetworkManager override boundary](#networkmanager) table, the two `conf.d`/`[ifupdown]` facts, and the bridge-managed-by-default fact. Re-derive the whole table; do not interpolate, and do not re-use 23.04/23.10 without reading the warning below. |
| **A new Ubuntu release enters the matrix** | Its `nmcli --version` and its place relative to the 1.44 boundary; whether a bridge device is managed by NetworkManager's default with the declaration removed; where it packages the `systemd-resolved` daemon (`Depends` or `Recommends` or absent); and its base image digest, which belongs in `tests/podman/images.lock.json`. |
| **dnsmasq is upgraded** | [The SIGHUP fact](#dnsmasq) — re-read `dnsmasq(8)` NOTES and re-measure. It is a documentation claim first and a behaviour claim second. |
| **A test fails with a message that points at one of these facts** | That section, and only that section, before the fix. A failure naming `dispatching events`, `IP configuration could not be reserved`, `GENERAL.NM-MANAGED`, `strictly unmanaged`, `resolvectl` exit 127, or an unexplained `is-active` refusal is one of these facts being wrong or out of date, not an installer defect. |

Two things are *not* triggers and will mislead you if treated as ones:

- A stale `podman images` SIZE is not a NetworkManager or dnsmasq fact. See
  [the image cost measurement](#the-figure-for-image-cost-is-podman-system-df-not-podman-images).
- A target container's resolver failing is a packaging fact, not a NetworkManager
  fact, unless the failure names `GENERAL.NM-MANAGED`.

---

## NetworkManager

Versions referenced below: **nmcli 1.36.6** (22.04), **1.46.0** (24.04),
**1.54.3** (26.04). These are the versions **inside the three locked target
images**, not the host's.

### The persistent device override exists from 1.44 upward

**The fact.** `nmcli device set <if> managed yes` followed by
`systemctl restart NetworkManager` takes `GENERAL.NM-MANAGED` to `yes` from
NetworkManager **1.44** upward. Below 1.44 the command is accepted and changes
nothing.

| release | nmcli | override works? |
|---|---|---|
| 22.04 | 1.36.6 | `no` |
| 23.04 | 1.42.4 | `no` |
| 23.10 | 1.44.2 | **`yes`** |
| 24.04 | 1.46.0 | `yes` |
| 26.04 | 1.54.3 | `yes` |

**Provenance.** Bisected, not inferred. 1.42.4 fails and 1.44.2 works, and they
are adjacent releases, so there is nothing between them to be excused. The
measurement was taken with a connection profile present, which is a
precondition in its own right (below). The threshold lives in the harness as
`NM_OVERRIDE_MINIMUM = (1, 44)` and the table as `NM_OVERRIDE_MEASUREMENTS` in
`tests/podman/lib/podman.py`, and a case parses the threshold out of
`tests/podman/images/target-nm-setup.sh`'s own comparison and requires every
measured `no` to sit below it and every measured `yes` at or above it, so the
refusal an operator reads and the gate the shell acts on cannot drift apart.
Reproduce with: pull 22.04/23.04/23.10/24.04/26.04, build the target image,
run it on a netavark bridge, and read the field after the two commands.

**Invalidated by** any NetworkManager version change on a release in the table,
and **the boundary bisect is the awkward one to redo**: 23.04 and 23.10 are
end-of-life and are no longer on `archive.ubuntu.com`. They were pulled from
`old-releases.ubuntu.com` for that bisect only, are not in
`tests/podman/images.lock.json`, and are not proposed for the matrix. If the
1.44 boundary ever needs re-establishing, budget for the fact that two of the
five points may no longer be obtainable from the normal archive.

### On 1.36 the override has no effect at all, and the file lies about it

**The fact.** On 22.04 (nmcli 1.36.6) `nmcli device set eth0 managed yes` returns
`result="success"` in the audit log, and `/run/NetworkManager/devices/<ifindex>`
**never gains a `managed=true` key**. The only mechanism that manages the device
there is a `NetworkManager.conf.d` declaration using
`except:interface-name:eth0`. `[ifupdown] managed=true` was measured and does
**not** work.

**Provenance.** A controlled experiment on a fresh 22.04 container with the
setup unit masked, one step at a time:

```text
nmcli device set eth0 managed yes (no profile yet)  audit log op="device-managed" … result="success", field still no
create the profile, device set again                 still no
systemctl restart NetworkManager                     still no
cat /run/NetworkManager/devices/2                    [device] perm-hw-addr-fake=… nm-owned=false   <- no managed=true key
```

The declaration's own measurement on the same release, with the sequence skipped
entirely: `NM-MANAGED=yes`, `STATE=100 (connected (externally))`,
`TYPE=ethernet`.

**The discriminator is the field, not the file.** `GENERAL.NM-MANAGED`, read
with `nmcli -g GENERAL.NM-MANAGED device show <if>`. On 24.04 the same
`/run/NetworkManager/devices/2` file *does* gain `managed=true` — NetworkManager
writes it as a **consequence** of a device already being managed, so a check that
read the file would be reading the effect backwards. The harness's check and
`wait_for_networkmanager_device` in `tests/podman/lib/podman.py` read the field.

**Invalidated by** a NetworkManager change on 22.04, or by a change in the
shipped `unmanaged-devices` default (see below), which would move what the
declaration has to counteract. The declaration's exact spelling is also
load-bearing in a way that is easy to break silently: the image ships it as
`10-mosdns-target.conf` to sort **after** `10-globally-managed-devices.conf`,
because within a merged list the administrator directory is appended after the
`lib/` ones. A filename that sorts earlier is merged first and the shipped
`unmanaged-devices=*` wins — no error, the device simply stops being managed.

### A bridge device is managed by default on 24.04 and 26.04, so the declaration is inert there

**The fact.** On 24.04 (1.46.0) and 26.04 (1.54.3), a device on a bridge network
is managed by NetworkManager's own default. With the setup unit masked and no
sequence run at all, and with `/run/NetworkManager/devices` cleared:

| release | nmcli | bridge network, setup unit masked, no sequence | with the declaration removed and the devices directory cleared |
|---|---|---|---|
| 22.04 | 1.36.6 | `NM-MANAGED=no`, `STATE=10 (unmanaged)` | `no` |
| 24.04 | 1.46.0 | `NM-MANAGED=yes`, `STATE=100 (connected (externally))` | `yes` |
| 26.04 | 1.54.3 | `NM-MANAGED=yes`, `STATE=100 (connected (externally))` | `yes` |

**Why this is recorded.** A `conf.d` declaration is therefore **inert** on 24.04
and 26.04, and a mistake in it — masking, misspelling, renaming — is **not
detectable there**. Only 22.04 catches a rename. If you rename the file and
watch 24.04 pass, you have learned nothing about 22.04.

**Invalidated by** a change in NetworkManager's shipped
`unmanaged-devices` default, or by a version change on any of the three
releases. A release that changed its default back to "unmanaged" would make the
declaration load-bearing everywhere and remove the trap.

### NetworkManager refuses tun/tap, and does not refuse ethernet

**The fact.** A container on Podman's **default rootless** network gets a
tun/tap device: `GENERAL.TYPE: tun`, `NM-MANAGED: no`, and
`nmcli device connect eth0` answers `Error: Device 'eth0' not found.` A
**netavark bridge** network gives the container a real `eth0` of type
`ethernet`. NetworkManager refuses the tun/tap device type by design; activation
fails with *device is strictly unmanaged*. This is why the harness uses a bridge
network and why the target's device is checked for type `ethernet`.

**Provenance.** Both observed on the same host, same session, by starting
containers on each network kind and reading `nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status`.

**Invalidated by** a NetworkManager change to which device types it will manage
(unlikely — the refusal is by design), or by a change in what Podman's default
rootless network hands a container, which would be a
[Podman](#podman-570-on-this-host) change.

> The error string recorded here is *device is strictly unmanaged*. A fuller
> form, *device lo not available because device is strictly unmanaged*, is what
> the underlying dispatcher condition amounts to, but no transcript in the
> records contains that exact text. Treat the exact wording as unverified; the
> device-type facts above are measured and are not in doubt.

### `managed yes` returns success and needs the restart

**The fact.** `nmcli device set <if> managed yes` returns success and does not
take effect until NetworkManager restarts. The override is written persistently
and only a restart re-reads it. **Exception: on 1.36 there is no override at
all**, so the restart re-reads nothing and the field stays `no` — see above.

**Provenance.** Measured on a real 24.04 target, and named in the harness's own
refusal message, which lists the two steps in order and explains why each is
needed.

**A connection profile must exist first, and this is load-bearing in both
directions.** With a profile for `eth0` present, the two steps take the field to
`yes` and the device to `100 (connected)` — three consecutive fresh containers.
With **no** profile, both steps are accepted, the audit log records
`op="device-managed" … result="success"`, the override is never written to
`/run/NetworkManager/devices/`, and `GENERAL.NM-MANAGED` stays `no` — every
container tried.

**Invalidated by** a NetworkManager change to the persistence of the override,
or to whether a connection profile is still a precondition for it.

**The three steps, in order, and where they run.** Create the `eth0` connection
profile, then `nmcli device set eth0 managed yes`, then
`systemctl restart NetworkManager`. They run from
`tests/podman/images/target-nm-setup.service`, a systemd unit the image
installs, **not** from the image entrypoint: `nmcli` reaches NetworkManager
over D-Bus and there is no bus before `/sbin/init`, so an entrypoint running any
of the three fails its first one with `Error: Could not create NMClient object:
Could not connect: No such file or directory`. That was the first version's
error and is recorded here because the failure is identical to "NetworkManager is
not running", which makes it easy to misread.

**The active connection on arrival is NetworkManager's own**, named `eth0`, in
state `100 (connected (externally))` on 24.04 and 26.04 — the bridge gave the
interface its address outside NetworkManager, so NM activated a profile it
created for itself. `eth0-managed` exists and is **not** the active connection
until something activates it. A DHCP scenario that reads the active connection
before that hand-off reports a lease belonging to a different profile and
concludes the mock router is broken.

---

## Podman (5.7.0 on this host)

Host facts, read live: `podman --version` → `podman version 5.7.0`;
`podman info --format '{{.Store.GraphDriverName}}'` → `overlay`;
`podman network ls` connection `none` — the local rootless Podman, which is the
supported path. `tests/podman/images.lock.json` records `podman_version:
"5.7.0"` alongside the pinned digests.

### The rootless bounding set does not carry `NET_RAW`, and DHCP needs it

**The fact.** Podman's default bounding set for a rootless container does not
carry `NET_RAW` (bit 13). A container without it cannot open an `AF_PACKET`
socket, so NetworkManager's DHCP client fails. With the capability added and
nothing else changed, a full DORA exchange completes.

**Provenance.** Measured on a netavark bridge `10.89.0.0/24` with a real dnsmasq
at `10.89.0.2` and a 24.04 target at `10.89.0.10`, started with only the three
`--cap-add` values the plan originally listed. The failure:

```text
Error: Connection activation failed: IP configuration could not be reserved (no available address, timeout, etc.)
NetworkManager: <error> dhcp4 (eth0): error -1 dispatching events
NetworkManager: <info>  dhcp4 (eth0): state changed no lease
```

```console
$ podman exec … grep Cap /proc/self/status
CapEff:	00000000802c15fb          # bit 13, NET_RAW, absent
```

Decoded: bits 0,1,3,4,5,6,7 (CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL,
SETGID, SETUID), 8 (SETPCAP), 10 (NET_BIND_SERVICE), 12 (NET_ADMIN), 18
(SYS_CHROOT), 19 (SYS_PTRACE), 21 (SYS_ADMIN), 31 (SETFCAP). Bit 13 is not
there. With one flag added and nothing else changed:

```console
$ podman run -d … --cap-add=NET_RAW …
$ podman exec … grep CapEff /proc/self/status
CapEff:	00000000802c35fb          # bit 13 now set
```

and the router's own log records the complete exchange:

```text
dnsmasq-dhcp[1]: DHCPDISCOVER(eth0) c2:c6:42:81:9d:6d
dnsmasq-dhcp[1]: DHCPOFFER(eth0) 10.89.0.191 c2:c6:42:81:9d:6d
dnsmasq-dhcp[1]: DHCPREQUEST(eth0) 10.89.0.191 c2:c6:42:81:9d:6d
dnsmasq-dhcp[1]: DHCPACK(eth0) 10.89.0.191 c2:c6:42:81:9d:6d
dnsmasq-dhcp[1]: sent size:  4 option:  6 dns-server  10.89.0.2
```

**Why no client-level workaround exists is structural: NetworkManager's DHCP has
no UDP mode, and every client it offers uses a raw socket.** This is the reason
the capability is the answer rather than a different DHCP client.

The capability belongs in the harness's **ceiling and the emitted target array**
(`ALLOWED_CAPABILITIES` in `tests/podman/lib/podman.py`), not in a scenario's
`extra_args`, because the target is one container for the whole cell and a
capability one scenario needs and another does not is a property of the run.

**The mock router needs `NET_ADMIN` and `NET_RAW` — both, measured one flag at a
time** against dnsmasq 2.91:

```text
--cap-add=NET_RAW            -> dnsmasq: process is missing required capability NET_ADMIN
--cap-add=NET_ADMIN          -> dnsmasq: process is missing required capability NET_RAW
--cap-add=NET_ADMIN NET_RAW  -> dnsmasq[1]: started, version 2.91 cachesize 150
```

A DHCP *server* opens the same `AF_PACKET` socket a DHCP *client* does, because
it must receive the broadcast DISCOVER before it has an address to reply from.
`NET_BIND_SERVICE` is needed by neither: a container started with no
`--cap-add` at all reports `CapEff: 00000000800405fb`, which already carries
bit 10, so `port=53` binds below 1024 without it.

**Invalidated by** a Podman change to the rootless bounding set — the most
plausible way this breaks, and one that would announce itself only as "DHCP
stopped working". Also invalidated by a NetworkManager change to how its DHCP
client opens sockets, or by a NetworkManager release that gains a UDP DHCP mode
(this one would make the capability unnecessary, not wrong).

### Broadcast DHCP crosses the bridge, and `bind-interfaces` is not the cause

**The fact.** Broadcast DHCP **does** cross a podman bridge, and dnsmasq's
`bind-interfaces` is **not** the cause of a failed lease. The DISCOVER arrives
in the router's log.

**Provenance.** The DISCOVER/OFFER/REQUEST/ACK excerpt above is the evidence:
the DISCOVER is a broadcast and it arrives, and OFFER/REQUEST/ACK are ordinary
unicast. Separately, `bind-dynamic` and `bind-interfaces` were observed to
behave identically here — both log `DHCP, sockets bound exclusively to interface
eth0` — because a container's `eth0` is created *before* its init runs, so there
is no window in which the interface is missing. The shipped mock-router config
uses `bind-dynamic` anyway, because it is the answer that does not depend on that
ordering being true.

**This is recorded because it is the hypothesis people reach for first**, and
reaching for it twice costs more than reading this line. The real cause was the
missing `NET_RAW`.

**Not established:** the comparison of `bind-interfaces` against `bind-dynamic`
*under a starting race* — the argument that `bind-dynamic` is more robust comes
from the man page, not from a measurement. The measurement only shows they
behaved identically here, for the reason above.

**Invalidated by** a change in how the netavark bridge handles L2 broadcast, or
in dnsmasq's socket binding.

### `podman run -d` returns before the container exists

**The fact.** `podman run -d` returns **before the container exists**, so the
first `podman exec` after it can be a query that never ran.

**Provenance.** Measured, both ways, on a healthy 24.04 image:

| case | exit | stdout |
|---|---|---|
| the unit is active | 0 | `active` |
| the unit is in some state | 3 | that state |
| the image has no such unit | 4 | `inactive` |
| the container is not running | **255 through a shell, 1 through the wrapper** | `''` (empty) |

**There is no exit code to match on.** The not-running case's exit status
depends on the layer it is observed through, so it cannot be distinguished by a
number. The invariant across every row is **whether a command printed a state
word at all**: a missing unit names a unit and says there is none, and a query
that never ran says nothing. That is the discriminator the harness uses —
no word is a plain `PodmanError`, transient, retried; a word with an exit
systemd does not use for a state is terminal and reported on the first read.

**This bit two live cells before it was found.** Both failed `incomplete` on a
healthy image, with a message sending the reader to the image.

**Invalidated by** a Podman change to when `run -d` returns. Nothing depends on
it being early; everything depends on it being handled, and the handling is
correct for either.

### The figure for image cost is `podman system df`, not `podman images`

**The fact.** Six stale harness images whose `podman images` SIZE totals
**1,116,992,936 bytes (≈1.12 GB)** reclaimed **3,851,100 bytes** — `podman
system df` went **728 MB → 723.6 MB**, a 4.4 MB delta. The gap is that
`podman images` counts shared layers once per image, while every harness image's
`UNIQUE SIZE` in `podman system df -v` is *a few kilobytes* and its `SHARED SIZE`
equals its `SIZE`: the expensive layers are the Ubuntu base image and the
`apt-get install`, which the stale and current images share.

**Two figures here do not agree with each other, and both are recorded as
measured.** The byte count (3,851,100) and the `podman system df` delta
(4.4 MB) come from two different tools and differ by about half a megabyte;
3,851,100 bytes is 3.85 MB decimal or 3.67 MiB. The prose figure used
everywhere — including in `docs/testing.md` — is **4.4 MB**, taken from
`podman system df`, because that is the tool whose number is being argued for.
Similarly, the stale images' summed size is **1.12 GB**, though `docs/testing.md`
rounds it to "~1.2 GB" in prose. Prefer the exact byte counts and name the tool.

**Per-Containerfile-edit cost**, measured by building probe images against the
real Containerfiles and diffing the store:

| edit | cost |
|---|---|
| comment-only, mock-router | **0 bytes** (the tag does not even change) |
| comment-only, target | **0 bytes** |
| a late `RUN` producing one small layer, target | **480 bytes** |
| a late `RUN`, mock-router | **219 bytes** |
| **worst case**: adding a real package, invalidating the big `apt-get` layer | **160 MB** |

So a stale tag costs only the *delta* from whichever layer the edit changed. The
222–248 MB figure attached to harness images in earlier review commentary is
**not** what a removal reclaims, and the claim that every Containerfile edit
left a full image behind does not hold: nothing duplicates the base layers.

**Invalidated by** a Podman change to its storage accounting, or to how it
shares layers. A store driver other than `overlay` would change this
entirely — this host's driver is `overlay` and it is recorded in
`tests/podman/images.lock.json` as `podman_version` alongside the digests.

### Default rootless network versus netavark bridge

**The fact.** Podman's default rootless network gives a container a **tun/tap**
device; a **netavark bridge** network gives it `eth0` of type `ethernet`.
NetworkManager refuses the first and not the second — see
[the NetworkManager section](#networkmanager-refuses-tuntap-and-does-not-refuse-ethernet).

**Invalidated by** a change in what Podman's default network hands a container.
It would also change the meaning of every harness cell, so it is a re-measure
trigger rather than a footnote.

### Long-flag aliases: exactly two pairs, in 5.7.0

**The fact.** In podman 5.7.0's whole documentation set there are exactly **two**
long-flag alias pairs:

```text
--network, --net     <- the one that matters; --network is policed
--namespace, --ns    <- podman ps's "Display namespace information"
```

Only the first matters for a flag guard: `--net` is the only alias of a policed
name. The harness normalises it before the policed-name lookup, in
`PODMAN_FLAG_ALIASES` / `canonical_flag_name` in `tests/podman/lib/podman.py`.

**Provenance.** Derived, not sampled, by reading every `podman-*.1.gz` on the
machine and extracting the long flags from every `.SS` heading that names more
than one:

```console
podman-*.1.gz pages read : 229
'.SS' headings read     : 2285
multi-name headings     : 15
```

Fifteen headings, two pairs: the pages are per-subcommand, so the same heading
is written out fifteen times.

**A second finding, recorded because it is a trap rather than a hole.**
`--namespace` and `--ns` are accepted by `podman run` and documented **nowhere**
in `podman-run(1)`:

```console
$ podman run --ns=x --help >/dev/null 2>&1 ; echo $?          # 0
$ podman run --namespace=x --help >/dev/null 2>&1 ; echo $?   # 0
$ zcat /usr/share/man/man1/podman-run.1.gz | grep -c -- 'SS .*--ns'   # 0
$ zcat /usr/share/man/man1/podman-ps.1.gz   | grep -A1 -- 'SS .*--namespace'
.SS --namespace, --ns
Display namespace information
```

They grant a target nothing and a value on a boolean is a no-op, so they are
recorded, not policed. Their value is that **`podman run --help` is neither a
superset nor a subset of the real vocabulary**: `--net` is documented and
*absent* from the help text, and `--ns` is accepted and absent from both. A
guard built on the help output would find nothing; one built on the man pages is
necessary and not sufficient. That is why the harness reads both.

**Short forms are a separate matter.** `-p` and `-P` are in the harness's alias
table because pflag registers a short form as a *separate name* for the flag, and
`podman-run(1)` declares `--publish, -p` and `--publish-all, -P` in their own
headings. The invariant the suite holds is therefore **"every short form is
resolved"**, not "no short form exists" — the second is a claim about podman and
is false.

**Invalidated by** any Podman version that adds, removes or renames a long-flag
alias, or changes the man page set. Re-derive by re-running the extraction over
`/usr/share/man/man1/podman-*.1.gz` (and `/usr/local/share/man/man1`).

---

## dnsmasq

### SIGHUP does not re-read the configuration file

**The fact.** **SIGHUP does not re-read `dnsmasq.conf`.** It re-reads
`--dhcp-optsfile` (and the other files named below). A control command that
rewrites `dnsmasq.conf` and sends SIGHUP changes nothing — a silent no-op that
reads exactly like a successful reload.

**Provenance, in two independent forms.**

*The documentation.* `dnsmasq(8)` NOTES, read on this host and quoted in full in
`docs/testing.md` and in the mock-router Containerfile's comment:

```text
When it receives a SIGHUP, dnsmasq clears its cache and then re-loads
/etc/hosts and /etc/ethers and any file given by --dhcp-hostsfile,
--dhcp-hostsdir, --dhcp-optsfile, --dhcp-optsdir, --addn-hosts or --hostsdir.
The DHCP lease change script is called for all existing DHCP leases. If
--no-poll is set SIGHUP also re-reads /etc/resolv.conf.
SIGHUP does NOT re-read the configuration file.
```

*The behaviour, measured with the plan's mechanism exactly as written* —
`sed -i` on `/etc/dnsmasq.conf`, then `podman kill --signal HUP`:

```console
$ podman exec …-router sh -c 'sed -i "s/^dhcp-option=option:dns-server,10.89.0.2$/dhcp-option=option:dns-server,10.89.0.20/" /etc/dnsmasq.conf && cat /etc/dnsmasq.conf'
interface=eth0
…
dhcp-option=option:dns-server,10.89.0.20
$ podman kill --signal HUP mosdns-20260929T000000Z-router
$ podman exec …-target sh -c 'nmcli connection up eth0-managed; nmcli -g IP4.ADDRESS,IP4.DNS device show eth0'
10.89.0.191/24
10.89.0.2                                   # unchanged
$ podman exec …-target resolvectl dns eth0
Link 2 (eth0): 10.89.0.2                    # unchanged
```

The reload changed nothing. The same page documents the answer: an option found
in `--dhcp-optsfile` takes precedence over `dhcp-option`, so writing *that* file
and signalling does work:

```console
$ podman exec …-router sh -c 'printf "6,10.89.0.20\n" > /etc/dnsmasq-dhcp-opts'
$ podman kill --signal HUP mosdns-20260929T000000Z-router
$ podman exec …-target sh -c 'nmcli connection up eth0-managed'
$ podman exec …-target sh -c 'nmcli -g IP4.DNS device show eth0; resolvectl dns eth0'
10.89.0.20
Link 2 (eth0): 10.89.0.20
$ podman logs …-router | tail -4
dnsmasq[1]: cleared cache
dnsmasq-dhcp[1]: read /etc/dnsmasq-dhcp-opts
dnsmasq-dhcp[1]: DHCPREQUEST(eth0) 10.89.0.191 32:83:9e:e1:11:3c
dnsmasq-dhcp[1]: DHCPACK(eth0) 10.89.0.191 32:83:9e:e1:11:3c
dnsmasq-dhcp[1]: sent size:  4 option:  6 dns-server  10.89.0.20
```

**Version note.** The container measurement is against **dnsmasq 2.91**. This
**host** has **dnsmasq-base 2.92**, and its `dnsmasq(8)` carries the same NOTES
text. The fact therefore holds on two dnsmasq versions, but the transcripts are
all from 2.91.

**Invalidated by** a dnsmasq upgrade. Re-read the NOTES section first — it is a
documentation claim before it is a behaviour claim — then re-measure with the
`sed`/`SIGHUP` sequence above. A dnsmasq that began re-reading its config on
SIGHUP would make the mock router's option file mechanism unnecessary rather
than wrong.

**One consequence worth carrying.** A lease is not renegotiated on a timer the
harness controls, and NetworkManager does not re-DHCP because a packet arrived
somewhere on the network, so after the signal the scenario must **re-activate
the profile** to produce a second transaction. The evidence for the change is
the router's log, not the target.

---

## systemd-resolved packaging, across the three locked releases

**The facts.** Where the `systemd-resolved` **daemon** is packaged differs per
release, and this is why the target image installs it conditionally:

| release | `libnss-resolve` declares | the daemon |
|---|---|---|
| 22.04 | `Depends: libc6 (>= 2.34), systemd (= 249.11-0ubuntu3.22)` | **no `systemd-resolved` package at all**; the daemon is in `systemd`, which `systemd-sysv` brings |
| 24.04 | `Depends: libc6 (>= 2.39), libcap2 (>= 1:2.10), systemd-resolved (= 255.4-1ubuntu8.17)` | a hard **`Depends`** |
| 26.04 | `Depends: libc6 (>= 2.39)` only, with `Recommends: systemd-resolved` | a **`Recommends`** only |

**The consequence, and the reason this is written down.** The target image builds
with `apt-get install --no-install-recommends`, for a reason recorded in
`tests/podman/images/target.Containerfile`. On **26.04** that leaves the release
with `libnss_resolve.so.2` and **nothing behind it**: every lookup goes to
127.0.0.53, nothing is listening, `resolvectl` is exit 127, and the target
cannot resolve anything.

**Provenance.** Re-measured with `dpkg -s` and `dpkg -S` in the three images
this checkout builds:

```text
22.04  Depends: libc6 (>= 2.34), systemd (= 249.11-0ubuntu3.22)
       systemd: /lib/systemd/systemd-resolved            -- no systemd-resolved package
24.04  Depends: libc6 (>= 2.39), libcap2 (>= 1:2.10), systemd-resolved (= 255.4-1ubuntu8.17)
       systemd-resolved: /usr/lib/systemd/systemd-resolved
26.04  Depends: libc6 (>= 2.39)
       Recommends: systemd-resolved                       -- NOT a hard Depends
       systemd-resolved: /usr/lib/systemd/systemd-resolved
```

and the 26.04 failure it explains:

```console
$ podman run --rm --network none --entrypoint sh localhost/mosdns-target:26.04-… -c \
    'command -v resolvectl || echo NO_RESOLVECTL; dpkg -s libnss-resolve | grep -E "^(Depends|Recommends)"'
NO_RESOLVECTL
Depends: libc6 (>= 2.39)
Recommends: systemd-resolved
```

**A recorded table in this repository carried the wrong 26.04 row for a while** —
it read `(Depends: libc6 >= 2.39; the daemon is in systemd)`, which is false, and
was corrected by re-measurement. The rule reads only presence/absence, so
nothing failed while it was wrong; that is the limit of a recorded table, and it
is why a case now holds the prose against the table's own rows: a release whose
`systemd-resolved` row says `ABSENT` must place the daemon in `systemd`, and a
release whose row says `present` must not.

**Invalidated by** any release changing `libnss-resolve`'s relationship to the
daemon, or by the image dropping `--no-install-recommends` (which would make
26.04 work by accident and hide the difference). A new release entering the
matrix must be asked directly — `podman run --rm IMAGE apt-cache show
libnss-resolve` — rather than assumed to match 24.04.

---

## systemd unit ordering

**The fact.** A unit that restarts NetworkManager must be
`After=NetworkManager.service` and must **not** carry `Requires=`, `BindsTo=`,
`PartOf=`, `PropagatesStopTo=` or `Upholds=` on it.

**Why, and why the distinction matters.** `Requires=NetworkManager.service` is
the correct spelling of "NetworkManager must be up first", which is what makes
it dangerous. It *also* means a deactivating required unit deactivates the
requiring one, and a restart is a stop followed by a start. So NetworkManager's
own restart SIGTERM'd the setup unit, systemd restarted it, it created a second
profile and restarted NetworkManager again, and the target came up with
**NetworkManager not running at all** — `Main process exited, code=killed,
status=15/TERM` on every pass, plus `Warning: There are 4 other connections with
the name 'eth0-managed'`.

`Requires=` is therefore **wrong, not merely insufficient**, and the difference is
the useful part: a missing `After=` would be a **race**, and a race is fixed by
waiting; this is a **cycle**, and no amount of ordering fixes a cycle. The
ordering that was meant to guarantee the daemon is up is what took it down.
**If you see this symptom, waiting longer will not fix it.**

**Provenance.** Observed on live target containers, quoted above. The shipped
`tests/podman/images/target-nm-setup.service` carries the reasoning in its own
header, and a case in `tests/podman/tests/test_images.py` checks the whole
family of five directives rather than the one that bit, because a later task
reaching for `PartOf=` is reaching for the same cycle. A second case holds the
ruling live: the version gate skips the restart on 1.36, so on a 1.36 target the
hazard is unreachable — but the ordering directives are **per unit** and the
version is **per release**, and the next release to cross the gate is a 1.44+
one, so the hazard returns with the same file.

**The correct shape** is `After=NetworkManager.service` plus the script's own
bounded wait for `nmcli general status` as the readiness gate, and
`Type=oneshot` with `RemainAfterExit=yes` and no `Restart=`.

**Invalidated by** a change in systemd's propagation semantics for the five
directives. That would be a kernel/`systemd` version change, not a
NetworkManager one, and the symptom would be a target that never boots — check
this section before the images.

### `systemctl is-active` exits 3 for every state that is not `active`

**The fact.** `systemctl is-active` exits **3** for every state other than
`active`, so a caller that wants to read the *state* rather than the *success*
must not use `check=True`. Measured on a real 24.04 target:

```text
target-nm-setup.service   exit=0  stdout=active
a unit that is not active  exit=3  stdout=<the state word>
a unit that does not exist exit=4  stdout=inactive
```

All three of `activating`, `inactive` and `failed` are **answers**, not failures.
`activating` is what a healthy target reads for the first seconds of its life,
`inactive` is what a target reads before the unit starts, and `failed` is the
verdict the setup script itself returned. A read that raised on them would answer
a different question — *did a command fail?* — and report a target that is
merely not ready yet as a target whose query could not be made.

This is not hypothetical: the read shipped with `check=True` while its own
docstring said the states came back as words, so `activating`, `inactive` and
`failed` all raised, the `failed` branch was unreachable against a real target,
and the budget message said "the last query failed" for a target that had merely
not finished starting. A refusal also burned the full 120 s naming a *failed
query* rather than a failed unit. The fix is `check=False` and
`setup_unit_state` in `tests/podman/lib/podman.py`, which is the only caller
that uses it.

The last row of the table is the one that matters for the not-running case: a
**missing** unit prints a word, and a query that never ran prints none. See
[`podman run -d`](#podman-run--d-returns-before-the-container-exists).

**A related measurement, for anyone tempted to gate on the field instead of the
unit.** `GENERAL.NM-MANAGED` is a *projection* of `target-nm-setup.service`'s
state, sampled at an instant. Polling 12 boots per release and recording the
unit's state at the poll where the field first read `yes`, the gate was wrong on
**24 of 24 boots (100%)** — the unit was `inactive` or `activating` and never
`active`. The *visible* failure rate is a separate and much smaller number,
because it depends only on whether the scenario happens to reach `nmcli` inside
the window: **3 in 9** under load, **1 in 6** on commit `4867d8d` with none of
the fixing code checked out, and **0 in 12 on a quiet machine**. That gap is why
it survived a whole task. An earlier version of the plan's own note attributed
the 1-in-6 figure to "`4867d8d`'s parent"; that attribution was wrong and has
been withdrawn — the parent of the ruling is itself the fixed tree, so the number
was never a property of a parent at all. The terminal state is
`active` (`SubState=exited`, `Result=success`), measured identical on all three
releases including 22.04, where the script skips the override sequence and is
therefore the obvious release to expect something different — it is not
different.

**Invalidated by** a systemd change to `is-active`'s exit codes, or by a
NetworkManager/setup-script change that alters the unit's terminal states. The
24-of-24 figure is a 12-boot-per-release sample on one host's boot timing —
enough to separate 100% from 1-in-4, not enough to bound a rare case, and
nothing has re-measured it.

---

## The host

| fact | value | how it was read |
|---|---|---|
| Podman | **5.7.0** | `podman --version`; also recorded as `podman_version` in `tests/podman/images.lock.json` |
| Podman storage driver | **`overlay`** | `podman info --format '{{.Store.GraphDriverName}}'`; also printed by `tests/podman/run.py preflight` |
| Podman connection | **rootless, `none`** | `preflight` prints it: the local rootless Podman is the supported path |
| Hardware virtualisation | **none** | `/dev/kvm` does not exist; `grep -cE 'vmx\|svm' /proc/cpuinfo` → `0` |
| qemu | **not installed** | `qemu-system-x86_64` and `qemu-img` are both absent |
| Virtual machines used | **none** | by decision, and enforced by the absence of the above: `podman machine` cannot create an image without `qemu-img` |
| Base image digests (22.04, 24.04, 26.04) | — | **`tests/podman/images.lock.json`** holds them, each with the `resolved_by` command that read it. Referenced here rather than duplicated, so there is one source. |
| `nmcli` in the target images | **1.36.6 / 1.46.0 / 1.54.3** | read inside each container; 22.04 / 24.04 / 26.04 respectively. This is *not* the host's nmcli. |

**The host's own `nmcli` is 1.54.3** and the host runs **Ubuntu 26.04.1 LTS
("Resolute Raccoon")**, which is why the host and the 26.04 target image report
the same NetworkManager version. Nothing in this document is a measurement of
the host's NetworkManager behaviour; every NetworkManager fact above was measured
inside a container.

**The 26.04 release exists**, which the plan and the brief both doubted. Verified
by reading `/etc/os-release` out of a container of the pinned digest, which
reports `VERSION_ID=26.04.1`. The brief's doubt is recorded here because a
reader meeting the lock file will reasonably wonder.

**Invalidated by** any of: a Podman upgrade, a change of storage driver, qemu
being installed, or a release's `nmcli --version` moving. Nothing on this host
is expected to move on its own, which is why these were cheap to establish
once and are recorded once.

---

## Facts not established by the records

Named rather than asserted, because the brief for this file asked for
provenance on every number and a number nobody can re-derive is a number nobody
should act on.

- **The full error string for a strictly-unmanaged tun device.** The records
  carry *device is strictly unmanaged* and, separately,
  `Error: Device 'eth0' not found.` from `nmcli device connect eth0` on the
  default rootless network. A fuller form, *device lo not available because
  device is strictly unmanaged*, is plausible but appears in no transcript. The
  device-type facts are measured; this exact wording is not. To establish it:
  start a container on Podman's default rootless network and attempt an
  activation, keeping the full stderr.
- **The list of DHCP clients NetworkManager offers.** The structural claim is
  measured and recorded above — no UDP mode, every client it offers uses a raw
  socket — but the enumeration `internal`, `dhclient`, `udhcpc`, `pump`,
  `dhcpcd` is **not** in any record and is therefore not asserted here. This
  host's own `NetworkManager.conf(5)` says the allowed values depend on build
  configuration and lists only `internal` for this build, which is a statement
  about one build, not about NetworkManager in general. To establish the
  enumeration: read `NetworkManager.conf(5)`'s `dhcp` key in each target image,
  or the NetworkManager source for the release.
- **`bind-interfaces` versus `bind-dynamic` under a starting race.** Measured
  identical here, and *not* measured where the interface appears after the
  daemon starts. Recorded as an open item above rather than as a fact.
- **A `UNIQUE SIZE` in kilobytes per image.** The records say "a few kilobytes"
  for every harness image; no per-image figure was kept, so none is quoted.
- **arm64 and live Firefox ECH.** Both are recorded as SKIPPED with exact
  wording, both for reasons that are facts about this host (no `/dev/kvm`, no
  `vmx`/`svm`, no qemu) plus an operator-supplied production hostname. They are
  reported as `skipped`, with the run `incomplete` and exit code 3, and a skip is
  never reported as a pass. Their wording lives in the plan's Plan Acceptance
  section, not here.
