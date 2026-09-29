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
python3 tests/podman/run.py matrix      # run every registered scenario
python3 tests/podman/run.py matrix --versions 24.04 --scenario dhcp
python3 tests/podman/run.py cleanup     # remove anything a run left behind
```

Start with `preflight`. It reports the Podman client version, the store
driver, the source tree it would mount, and the NetworkManager fact below.
It changes nothing.

**`matrix` runs the scenarios and exits 0 or 1.** The first scenario to exist
is `dhcp`: a cell creates the private network, starts a mock DHCP/DNS router and
a target on it, and proves NetworkManager obtained an address **by DHCP**,
published the router's DNS, and then received a **new** DNS address after the
router was reconfigured. Naming no scenario runs every registered one, which is
what the plan's own acceptance command does. Exit codes are the interface:

- `0` — everything requested passed
- `1` — a test failed
- `2` — a harness or configuration error (including asking for a scenario that
  is not registered, which is refused with its name rather than ignored)
- `3` — an incomplete matrix (a target that could not be brought up, or a
  required architecture was skipped)

A scenario that fails is a `failed` row in the report with the reason beside
it; a scenario the registry does not hold is exit 2. They are different claims:
one means something was tried and did not work, the other means nothing was
tried.

Every run writes `build/test-results/<run-id>/report.json`, and every scenario
writes its own evidence document under `build/test-results/<run-id>/logs/`. A
requirement the containers could not close is recorded there as **SKIPPED with
its exact wording**. It is never reported as a pass, and never closed by
substituting a different kind of test.

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
tests/podman/mock-router/dnsmasq.conf           the router's configuration
tests/podman/scenarios/dhcp_test.py             the DHCP/DNS scenario
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

`matrix` builds what it needs itself, and the tag it uses is
`mosdns-<role>:<version>-<12 hex>` where the hex is a hash of **the Containerfile,
the base reference, and the contents of every file the Containerfile copies in**.
That makes the tag a cache key: edit an input and the tag changes and the image
is rebuilt; change nothing and the tag is identical and the build is skipped.
Without the Containerfile in the key a stale image is what the matrix runs, and a
stale image here is a mock router whose dnsmasq has no configuration file to read.

**The copied files are in the key because a config file is not the Containerfile.**
`mock-router.Containerfile` copies `tests/podman/mock-router/dnsmasq.conf` in, and
that file is the whole of the router's configuration. Measured in Task 8: the
config was given an `address=` line, the file changed, the tag did not, and the
run kept reporting a rollback that could not resolve — which reads as a defect in
the thing under test and is a stale image. The copies are read out of the `COPY`
lines rather than by globbing the directory, so a file the build does not read
cannot move the tag either.

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

A `matrix` run writes `build/test-results/<run-id>/host-before.json` **before** it
does anything and `host-after.json` on the way out, whatever happened in between,
and the comparison is the plan's evidence that the run changed nothing on this
machine. Until that wiring existed the two files could not exist at all, and the
collector being able to do it in isolation was not evidence of anything.

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

**1. The declaration, which is the baseline on every release — and is only
*load-bearing* on 22.04.** On 24.04 and 26.04 the shipped snippet is **inert**:
measured on a fresh 24.04 (nmcli 1.46.0) and 26.04 (nmcli 1.54.3) target with the
file removed *and* `/run/NetworkManager/devices` cleared, the device still comes up
`GENERAL.NM-MANAGED: yes`, `STATE: 100 (connected)`, because a bridge device on
those releases is managed by NetworkManager by default. So on those two, masking,
misspelling or renaming the file changes nothing and **the boot check still
passes**. **22.04 is where a rename is caught**, because there the snippet is the
only mechanism that manages the device. If you rename it and watch 24.04 pass, you
have learned nothing about 22.04.

The override wins for a reason worth knowing before you rename anything:
NetworkManager merges `conf.d` over the main file, and within a merged *list* the
administrator directory is appended after the `lib/` ones — which is why the file is
named `10-mosdns-target.conf`, to sort after
`10-globally-managed-devices.conf`. A name that sorted earlier would be merged
first and the shipped `unmanaged-devices=*` would win. Nothing errors.

NetworkManager
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

### And the hand-off is a wait, not a query

`podman run -d` returns long before the target has finished booting, so the
managed-device check is a **bounded wait**: the entrypoint has to `exec
/sbin/init`, systemd has to reach multi-user, and `target-nm-setup.service` runs
*after* NetworkManager — and on 22.04 the managed state comes from the `conf.d`
declaration, which NetworkManager reads when it starts. A single query about two
seconds after `podman run -d` returned answered

```text
Error: Could not create NMClient object: Could not connect: No such file or directory
```

which is *no NetworkManager yet*, and the single-shot check reported it with the
same message it uses for "NetworkManager is running and refuses this device" —
with the two `nmcli` steps printed under it, which fix neither. The wait's
failure names the value it read, the budget and the number of reads, and says
plainly that a target which has not booted answers the same way.

## The DHCP/DNS scenario

`python3 tests/podman/run.py matrix --arch amd64 --versions 22.04 --scenario dhcp`

One cell creates the private bridge network and starts **two** containers on it —
a mock DHCP/DNS router and a target — because a lease has to cross a network for
the claim to be a DHCP claim:

| role | address | who gives it |
|---|---|---|
| mock router | `10.89.0.2` | `--ip`, because podman hands out the first free address otherwise |
| target | `10.89.0.10` | `--ip`, for the same reason |
| *lease* | `10.89.0.100`–`10.89.0.199` | **dnsmasq**, and this is the evidence |

The gap between the fixed addresses and the pool is the mechanism, not a
detail: the target has an IPv4 address before a single DHCP packet crosses, so
"the target has an address" proves nothing on its own. What makes it a lease is
that the address is one the pool could have handed out, and the DNS it published
is one **the lease carried** (`nmcli -g DHCP4.OPTION connection show
eth0-managed`, `domain_name_servers = …`).

The scenario then

1. records the active connection, which is NM's own `eth0`;
2. sets `ipv4.never-default yes` on the image's `eth0-managed` profile and
   activates it — the hand-off, and the step that re-runs DHCP;
3. waits for NetworkManager to *report* the lease, the DNS, and `resolvectl
   dns eth0`;
4. checks the route table for a default route through the router — dnsmasq
   offers `option:router 10.89.0.2` and the target must not take it;
5. reads the **router's own log** for the four DORA messages, because that log
   is the process that owns the pool saying what it did;
6. reloads the router (below), re-activates the profile, and waits again for a
   **new** DNS address;
7. records `/run/mosdns/dhcp-upstreams.json`, which is the *package's* state
   document and is absent here — recorded as absence, with the reason, and never
   as an empty document, which would read as "the bridge published nothing".

### The reload is a SIGHUP of the *option file*, and the plan's sentence was wrong

The plan said a control command "rewrites only the container-private dnsmasq
config, sends HUP". **`dnsmasq(8)` says otherwise** (NOTES, measured here):

```text
When it receives a SIGHUP, dnsmasq clears its cache and then re-loads
/etc/hosts and /etc/ethers and any file given by --dhcp-hostsfile,
--dhcp-hostsdir, --dhcp-optsfile, --dhcp-optsdir, --addn-hosts or --hostsdir.
…
SIGHUP does NOT re-read the configuration file.
```

So the control command writes `/etc/dnsmasq-dhcp-opts` — the file the shipped
config names with `dhcp-optsfile`, inside the container, absent from the
checkout — and signals the daemon. An option found there takes precedence over
`dhcp-option`, which is what makes a second DNS address possible without a
restart. **Rewriting `/etc/dnsmasq.conf` and sending SIGHUP changes nothing**, and
a scenario built that way reports the stale baseline it already had as a pass.

Two things make the reload *observable* rather than asserted: the router's log
records `read /etc/dnsmasq-dhcp-opts` after the signal, and the option it then
sent is the new address. And the scenario **waits** for NetworkManager to report
the new address with a bounded retry whose failure names the value it kept
reading — a scenario that sends a signal and sleeps cannot fail.

### DHCP needs `NET_RAW`, and it is not a bridge problem

**A real DORA exchange crosses the podman bridge.** The original measurement said
otherwise, and the cause was the container's capabilities, not the network. A
target started with the plan's three `--cap-add` values reaches "getting IP
configuration" and then:

```text
Error: Connection activation failed: IP configuration could not be reserved
(no available address, timeout, etc.)
…
NetworkManager: dhcp4 (eth0): error -1 dispatching events
```

with, from `/proc/self/status` inside the container,

```text
CapEff: 00000000802c15fb
```

— bit 13, `NET_RAW`, absent, because podman's default bounding set for a
rootless container does not carry it. NetworkManager's built-in DHCP client opens
an `AF_PACKET` socket to send and receive DORA and cannot without the capability.
With `--cap-add=NET_RAW` the same container against the same router leases
`10.89.0.1xx` out of the pool and publishes the router's DNS. `NET_RAW` is in the
harness's cap ceiling and in the emitted target array for that reason, and the
plan's flag listing has been amended.

The bridge was never the problem: the router's log records the DISCOVER
(broadcast) arriving, so L2 broadcast crosses the netavark bridge, and the OFFER,
REQUEST and ACK are ordinary unicast.

## The resolver watchdog scenario

`python3 tests/podman/run.py matrix --arch amd64 --versions 24.04 --scenario watchdog`

This is the only scenario that **installs the package**, because the mechanism it
observes is four files inside the `.deb` — the unit, the timer, the setting and
the verb — and a scenario that hand-copied those would be testing a constructed
approximation of the package. It needs `make package` to have run; a missing
`.deb` is a harness error (exit 2) naming the command, not a failed cell.

It is also the only scenario that can be described as a *product* test rather
than a claim about files, because the watchdog is the first thing this project
does to a machine with nobody watching. Three things are observed, and each is
evidence of something a unit test cannot reach:

1. **The window.** The device is handed to the image's own connection profile
   (so the link has a resolver at all), the machine is pointed at `127.0.0.1`,
   the router is stopped, and `mosdns-watchdog.service` is started by hand. The
   *first* probe must do nothing and the record must read `consecutive_failures: 1`
   — the count is checked at each step, not only at the end, because a watchdog
   that acts on the first probe passes a test that only looks at the final state.
2. **The action is the real one.** The evidence is the machine: the recorded DNS
   is back on the connection, the connection no longer carries the loopback
   address, the device's resolver is the DHCP one again, and a name resolves
   through the machine's own stub (`getent hosts install-probe.example`). The
   journal is the *explanation*; the machine is the claim.
3. **The switch.** `automatic: false` is written, the machine is put back into
   the broken condition, and `shipped_threshold + 1` probes are run. Nothing may
   happen, and then the operator's own
   `mosdns-cdnctl emergency-rollback` must still work. A switch implemented by
   removing the action would leave a machine with no way back, and every other
   assertion in the scenario would be green.

### What the cell does not prove, and says so in its evidence document

**The install transaction is refused in a container**, measured on 24.04:

```text
install: publishing the Cloudflare prefix list, which the router refuses to start
without failed: ... update-lists: https://api.cloudflare.com/client/v4/ips: dial
tcp: lookup api.cloudflare.com on 127.0.0.53:53: server misbehaving
```

A container on this bridge has no route off it, so the publish cannot happen. The
refusal happens *after* the record is written and read back and *before* any DNS
setting is changed, which is why the scenario has a record to restore — and it
rolls itself back cleanly, so the machine is exactly the one the watchdog is for.
The evidence document says all of this, and says explicitly that the router was
not successfully started by the cell. A cell that claimed a working install here
would be claiming something it did not achieve.

### The journal is read through a cursor, and that is not a detail

`journalctl -n 40` returns the cell's last forty lines, so the switch-off
position would read the *armed* run's success message and report that the
mechanism had acted with the switch off — a false failure on a mechanism that had
done exactly the right thing, which is the worst direction for a false positive
because the tempting fix is to weaken the assertion. The scenario takes a
`--show-cursor` position before each run and reads `--after-cursor` from it, and
the cursor is taken from the **whole** journal because a unit that has never run
has no entries and prints `-- No entries --` and no cursor.

### The mock router answers for one name, and `no-resolv` is why

dnsmasq with `no-resolv` and no upstream SERVFAILs everything, and a SERVFAIL for
`install-probe.example` is a *correct* answer from a resolver that reached nobody —
which is exactly what the rollback checks for when it decides whether the machine
came back. The first live run found this: the restore was faithful and the
machine was still dead, and the watchdog reported exit 6 with the reason. The
watchdog was right; the fixture could not answer. The router now carries

```text
address=/install-probe.example/10.89.0.2
```

— one name, `address=` rather than `server=`, and a case holds that there is no
`server=` line anywhere in the config, so the mock cannot become a forwarder.

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

### `resolvectl` exists on all three releases, and only because of a conditional

`libnss-resolve` is what makes a lookup in a target go to 127.0.0.53. The
**daemon** behind that stub is packaged differently on each release: part of
`systemd` on 22.04, a hard `Depends` of `libnss-resolve` on 24.04, and on
**26.04 a plain `Recommends`** — measured in the image the first version built:

```text
$ dpkg -s libnss-resolve | grep -E '^(Depends|Recommends)'
Depends: libc6 (>= 2.39)
Recommends: systemd-resolved
$ command -v resolvectl
NO_RESOLVECTL
```

The target image builds with `--no-install-recommends`, for a good reason
written in the Containerfile, so 26.04 came out with the module and nothing
behind it. The Containerfile therefore installs the daemon package where the
release has it:

```dockerfile
RUN apt-get update \
    && if apt-cache show systemd-resolved >/dev/null 2>&1; then \
         apt-get install -y --no-install-recommends systemd-resolved; \
       else \
         echo "systemd-resolved is not a package on this release; the resolved daemon is part of systemd here"; \
       fi \
    && rm -rf /var/lib/apt/lists/*
```

The guard and the install name the same package deliberately, and the suite holds
that, holds the package against the availability table, and counts every
`apt-get install` in every Containerfile so a third spelling is a failure rather
than a package no rule sees.

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

The harness **waits for** `nmcli -g GENERAL.NM-MANAGED device show eth0` to be
`yes` on a running target before the first scenario runs, and refuses with a
message naming these steps if it is not. It waits rather than asks, because
`podman run -d` returns before the target has booted — see "And the hand-off is a
wait, not a query" above. A target that booted wrong is then an `incomplete`
cell, not a failing scenario and not a pass.

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

**`cleanup` does not remove images, and the cost is small — measured on this
host, September 2026.** Images are podman's content-addressed store, tagged by a
hash of the Containerfile and the base reference, so an edited Containerfile gets
a *new* tag and the old image stays under its old one. Six stale harness images
were sitting on this machine alongside the six current ones. Removing all six
reclaimed **4.4 MB**, not the ~1.2 GB their reported sizes sum to
(`podman system df`: 728 MB → 723.6 MB), because the layers they share with the
current set are the large ones — each image's `UNIQUE SIZE` in
`podman system df -v` was a few kilobytes. A stale tag costs the *deltas* from
whichever layer the edit changed; a comment-only edit cost 0 bytes, a late
`RUN` cost 480 bytes, and an edit invalidating the big `apt-get` layer cost
160 MB. No names leak: a stale tag is content-derived, so it cannot be mistaken
for a current one, and the only way to tell them apart is
`podman images --filter reference=localhost/mosdns-*` against the tags
`tests/podman/lib/images.py` would compute. To reclaim them:

```bash
podman image prune -f                                  # unused images, harness tags included
podman rmi localhost/mosdns-target:24.04-<old-hash>    # or name them one at a time
```

Leave the six current tags and the three `docker.io/library/ubuntu` base images
alone — the next run needs them, and a rebuild is minutes.

**So: do not go looking for a gigabyte.** The number to believe is the one
`podman rmi` gives you, not the one `podman images` prints. Adding up a stale
image's reported size double-counts every layer it shares with the images you
kept, and a harness image is almost entirely shared layers — the Ubuntu base and
the `apt-get install` are the bulk of it, and both are identical across a stale
and a current image of the same release.

## Adding a scenario

Scenarios are registered, not discovered. A scenario that is asked for by name
and is not registered is a **configuration error** (exit 2), not a silently
ignored flag: the run must not report a pass for something it never looked for.
`tests/podman/scenarios/` is where they go; `run.py` is where the registry is,
in `build_scenarios()`.

**A scenario that installs the package is named in `PACKAGE_SCENARIOS`**, and
that set is what makes `run.py` copy the `.deb` in. It is a literal rather than
something derived from the builder's signature for the same reason the registry
is: a derived property is a property a reader cannot check, and a scenario that
gained a `deb` parameter without being added to the set would be handed no
artifact and fail with a `TypeError` at cell construction. The set is also why
`matrix` with no `--scenario` cannot be exercised against a fake podman — it would
try to install a package a fake cannot unpack — and the case that proves the
flag-free path names the scenario it covers rather than letting the set decide.



A scenario module gets:

- `build_scenario(...)` — a builder the runner calls with the cell's `podman`
  client, its two container names, the version, the run id and the results
  directory, returning a **zero-argument** callable the runner invokes. Bound
  rather than global, because a cell has its own containers and a global name
  would measure whichever container happened to be running.
- a `ScenarioResult` with `status="passed"` or `status="failed"`, and a `log`
  path **relative** to the run's own result directory.
- its own exception type for a failed assertion. `PodmanError` means a harness
  fault (exit 2); a scenario that raises it for "the DNS did not change" is
  reporting a broken matrix as a broken harness.
- a **bounded** wait for anything NetworkManager has to report, with the
  failure naming what it saw. `nmcli connection up` returns before the device
  has an address.
- the two clocks, `now` and `sleep`, as parameters defaulting to
  `time.monotonic` and `time.sleep`. `run.scenario_clock()` is the seam that
  supplies them, so a case can run the whole scenario without sitting out a real
  ninety-second bound.

Put the cases in `tests/podman/tests/`, not in the scenario file: discovery is
pointed at `tests/podman/tests`, so a `TestCase` in `scenarios/` would be read by
everybody and collected by nothing. `tests/podman/tests/test_suite_shape.py`
fails on a case that ends up there.
