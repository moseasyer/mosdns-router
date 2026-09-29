"""The only place in this repository that builds a Podman argument array.

Every container, network and volume this harness creates goes through the
:class:`Podman` object here. That is not tidiness, it is the boundary: the
harness runs on somebody's working system, and the properties that keep it off
that system's resolver are all properties of how a command line is built.

* **No shell, ever.** A scenario's command is an argument array, so a test name,
  a hostname or a version string can never become a second command.
* **No machine.** ``podman machine`` needs qemu. This host has none, is not
  going to get any, and the previous architecture of the Podman plan was built
  on it. Rootless Podman is the architecture now, and the refusal is here
  because this is the only module that builds an argument array.
* **A hatch with a ceiling.** ``extra_args`` is the escape every later task
  reaches for when something will not start, so the policy is enforced there
  and not merely documented: a cap ceiling, no device, no seccomp or apparmor
  override, no ``--volumes-from``, no privilege flag, and no host namespace --
  in both spellings pflag accepts, in any position, without returning early.
* **A redacted environment.** The child gets a named set of variables and
  nothing else, so a token in the operator's shell cannot reach a command line
  and then a report.
* **A connection is an argument.** ``--connection`` is a Podman *service* URI
  for a remote or native service, never a machine name, and it is passed on
  every invocation rather than written to a configuration file that would change
  every other podman user on the machine. Omitted -- the default -- is the local
  rootless Podman, which is the acceptance path here. The shape is checked at
  construction, not documented: a bare word is refused.

* **Two binds, and the source tree may be anywhere.** The workspace is ``:ro``
  and the cgroup filesystem is the one writable mount, because a systemd
  container will not start without its cgroup hierarchy. **A source inside
  ``/etc``, ``/run``, ``/var``, ``/sys`` or ``/home`` is never bound writable**,
  and that check is by path, in ``_check_mount``, after the allowlist -- so a
  later task that adds a mount to the allowlist cannot widen it by writing one
  line into a table. The *read-only* case is where ``/home`` is permitted,
  because this host's checkout is under ``/home`` and refusing it left no legal
  ``--source-tree`` at all; the read-only source tree is still refused under
  ``/etc``, ``/run``, ``/var`` and ``/sys``, which hold the host's resolver and
  its systemd state. See ``FORBIDDEN_SOURCE_TREE_ROOTS`` for the argument and
  ``FORBIDDEN_HOST_ROOTS`` for the writable rule.

Nothing in this module installs, enables or starts anything on the host, reads
the host's resolver, or mutates NetworkManager. The commands it builds are the
commands a disposable container run needs.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

# Every command gets a deadline. A harness that blocks forever on a Podman
# service that has wedged reports nothing, and a wedged service is exactly what
# a broken run looks like from the outside.
DEFAULT_TIMEOUT = 120.0

# The separate deadline for an image build. A target image installs a systemd
# and a NetworkManager through apt on every release this matrix runs, which is
# minutes rather than seconds, and a deadline the build cannot meet turns a
# working machine into a harness error -- the one failure mode a shorter
# deadline creates rather than prevents.
DEFAULT_BUILD_TIMEOUT = 1800.0

# The grace period given to a container's init to shut down. systemd inside the
# target needs a moment to stop the units it started; the plan measures 30.
STOP_TIME_SECONDS = 30

# The variables a child may inherit. The list is an allowlist rather than a
# subtraction because the set of variables that carry a secret is open-ended
# and the set that rootless Podman needs is not.
FORWARDED_ENV_NAMES = (
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
)

# The first non-flag token of an argument array is the Podman subcommand. A
# refusal is keyed on it so that a *value* that happens to spell a forbidden
# word -- an image named `machine`, a path -- is not a false positive, while a
# real subcommand is caught wherever it appears in the array.
MACHINE_SUBCOMMAND = "machine"

# The source tree, read-only, and the cgroup filesystem. These two are the whole
# of what this harness may bind into a target container, and the second is the
# only mount that is allowed to live under one of the five forbidden roots --
# a systemd container will not start without its cgroup hierarchy, and the
# exception is the cgroup *filesystem* rather than the whole of /sys, which is
# where the host's NetworkManager state and interfaces live.
WORKSPACE_MOUNT_POINT = "/workspace"
CGROUP_HOST_PATH = "/sys/fs/cgroup"
CGROUP_MOUNT_POINT = "/sys/fs/cgroup"

# The repository the harness lives in, named in a source-tree refusal so the
# operator has a value to pass rather than only a flag to read about.
REPO_ROOT = str(Path(__file__).resolve().parents[3])

# The host roots this harness will not put in front of a target container, and
# -- this is the second of the two sets, not a copy of the first -- the one that
# governs **writable** binds everywhere, with no path exception.
#
# `_check_mount` refuses a source inside any of these whose mode is not `ro`,
# and it does so *after* every comparison against the mount allowlist, on
# purpose. Every allowlist comparison agrees with the allowlist by construction,
# so a later task that adds a third mount to `allowed_mounts()` widens all of
# them at the same time; the refusal that is not a comparison is the one that
# survives that edit. This is the second instance of the defect Fix Round 1 called
# Critical 2, and it is closed the same way: the subject of the check is named
# here and the caller cannot choose it.
#
# The list is also kept because a refusal that names the root it broke is a
# diagnosis and a refusal that says "refused" is a shrug.
#
# `Podman` emits exactly two mounts, and this set is what governs them:
# `/sys/fs/cgroup` read-write, which is the one measured exception, and the
# source tree read-only, which is the read-only case the argument below covers.
FORBIDDEN_HOST_ROOTS = ("/etc", "/run", "/var", "/sys", "/home")

# The narrower set that governs the *source tree*, and the reason the two differ
# is the whole content of this amendment rather than a convenience.
#
# `/etc`, `/run`, `/var` and `/sys` hold the host's resolver and its systemd
# state, so a bind of any of them is how a container comes to influence the
# host's DNS. That rationale reaches a *writable* bind everywhere and a
# read-only bind of those four roots, and nothing else.
#
# `/home` is in the list above for a different reason: the host-isolation
# snapshot compares Firefox profile metadata, and a run must not perturb what it
# compares. That is a rule about what the harness *writes* and what it *reads
# back*, not about read-only visibility of a checkout — and this host's checkout
# is under `/home`, so refusing it left no legal value at all for
# `--source-tree` here and `run.py` could not run from a checkout at all.
#
# The security argument, so a later reviewer does not restore the old list: a
# read-only bind of a directory under `/home` exposes exactly that directory's
# bytes to a container, and a container that reads source it was given is not a
# container that changed anything. Nothing a target does to a `:ro` mount
# reaches the host. The `/home` entry protects the host by governing what the
# harness *does* — the writable binds, the volumes, the artifacts copied in —
# and every one of those is refused by the mount allowlist, which compares a
# mount's source against its own entries and never consults a prefix. Widening
# the read-only source-tree exemption to `/home` therefore adds no writable
# path, and the host-isolation snapshot's rules about `/home` and Firefox
# metadata are unchanged by this: they are enforced where they were, by the
# snapshot, not by a path allowlist.
#
# `FORBIDDEN_HOST_ROOTS` above is deliberately *not* shortened, and the reason is
# no longer a comment's promise: it is the set `_check_mount` refuses a writable
# source against, so the writable case is closed there by a path check rather
# than by whatever the mount allowlist happens to say.
FORBIDDEN_SOURCE_TREE_ROOTS = ("/etc", "/run", "/var", "/sys")

# Flags that would hand a target the host it runs on, and the value each one
# is refused *with*. `--privileged` is the obvious one and takes no value;
# `--cgroupns=host` was written for the machine architecture this plan no longer
# has, is measured not to start systemd here, and puts a container's cgroup
# changes on the host's hierarchy; the namespace-sharing flags are the same
# escape in five spellings. `extra_args` is the hatch every later task reaches
# for when something will not start, so the hatch is where the refusal lives.
#
# Keyed on the flag's **canonical** NAME and the value it carries, because pflag
# accepts both `--flag value` and `--flag=value` for a string flag, and because
# `run_container` emits its own `--network <net>` before `extra_args` -- so the
# last occurrence of a repeated flag is the one podman reads. A list of
# `--flag=value` strings checked with `token == flag or token.startswith(flag +
# "=")` refuses the equals form only, which is a check on a spelling rather than
# on a policy.
#
# Canonical, because podman has *aliases*: `podman-run(1)` declares
# `--network=mode, --net` in a single heading and pflag accepts either name, so
# a table keyed on the name the documentation happens to lead with is a table
# with a hole in it. The second spelling is in `PODMAN_FLAG_ALIASES` below and is
# resolved by `canonical_flag_name` before this table is consulted, rather than
# by a second key here -- see the note at that constant for why.
FORBIDDEN_CONTAINER_FLAGS = {
    "--privileged": None,
    "--cgroupns": "host",
    "--network": "host",
    "--pid": "host",
    "--ipc": "host",
    "--uts": "host",
    "--userns": "host",
}

# The other names podman has for a policed flag, as alias -> canonical name.
#
# **Keyed the other way round from the policy on purpose.** A second entry here
# (`"--net": "host"`, beside `"--network": "host"`) would work, and it is the
# change a reviewer would expect -- but it makes the policy table a mixture of
# policies and vocabulary, and a later task that adds a policed flag has to know
# that aliases exist and go and look for them. Keyed as alias -> canonical, the
# policed table stays a statement of policy, the aliases stay a statement about
# podman's spelling, and a flag added to the policy needs no second thought. The
# table is closed against the policy in both directions by the suite, so an
# entry pointing at a name nothing polices -- an entry that would refuse nothing
# -- is a test failure rather than a silent no-op.
#
# **Short forms are here, and they are here because the reasoning that excluded
# them was the defect.** The first version of this comment said that pflag's
# short form "is a different token shape, and the guard reads the flag's name
# and the value that flag carries, so both value spellings are already covered by
# construction". Both halves of that are true and neither of them helps: a
# *different token shape* is exactly why the name lookup misses it, and the guard
# reads the **name**. `podman-run(1)` declares the pairs in their own headings --
#
#     .SS \fB--publish\fP, \fB-p\fP=\fI[[ip:][hostPort]:]containerPort[/protocol]\fP
#     .SS \fB--publish-all\fP, \fB-P\fP
#
# -- and pflag registers each of those as a separate name for its flag, so
# `extra_args=["-p", "53:53/udp"]` is a port published to the host through a name
# the policed table did not contain. It is the same defect `--net` was, arrived
# at by a different route, and the route is now closed for both: the
# `test_no_policed_flag_has_a_short_form_the_name_lookup_would_miss` case in
# `test_podman_flags.py` reads the run page's own headings and requires every
# short form it finds for a policed flag to be in this table, so the next
# short form is a case failure rather than a review.
PODMAN_FLAG_ALIASES = {
    "--net": "--network",
    "-p": "--publish",
    "-P": "--publish-all",
}

# The flag names a caller can see are policed *by the table above*: the canonical
# names and every alias of one. Used, in `ContainerPolicyError`'s message, so the
# person who has just been refused is told the whole set rather than only the one
# token they typed -- `extra_args` is the hatch every later task reaches for, so
# the refusal is the documentation.
#
# Scoped to that table deliberately, and `POLICED_CONTAINER_FLAGS` below is the
# whole policed surface. This set is what the value-keyed refusal prints, and the
# other two policies print their own reasons (a family is refused whatever its
# value; `--cap-add` is refused unless the value is one of the measured
# capabilities), so mixing the families in here would print a set that is not what
# was checked against.
#
# Long names first and short forms after, rather than `sorted()`, because the
# whole list is a single line an operator reads after a refusal: `-P, -p,
# --cap-add, --cgroupns, …` puts the two short forms where they look like
# typos.
def _policed_flag_names() -> tuple[str, ...]:
    names = set(FORBIDDEN_CONTAINER_FLAGS) | set(PODMAN_FLAG_ALIASES)
    return tuple(
        sorted(name for name in names if name.startswith("--"))
        + sorted(name for name in names if not name.startswith("--"))
    )


FORBIDDEN_CONTAINER_FLAG_NAMES = _policed_flag_names()

# Families refused outright, in both spellings, whatever the value. A device is
# host hardware; a seccomp or apparmor override removes a layer of the boundary
# the caps are inside; `--volumes-from` is another container's filesystems, and
# the name would have to be one this harness created for the boundary to mean
# anything, which is a property of the caller rather than of the flag.
#
# **`--publish` and `--publish-all` are here for the plan's "do not publish ports
# to the host", and they are here rather than in the value-keyed table because no
# value of either is safe.** Every port value is a port on the operator's
# machine: a mock router published on 53 collides with `systemd-resolved` on the
# host, and a mock CDN published on 443 answers for a name the operator is
# visiting. The plan states the rule, and a rule with no flag behind it is a
# sentence, so it is a refusal here -- with the two short forms resolved through
# `PODMAN_FLAG_ALIASES`, which is where `-p` and `-P` are.
FORBIDDEN_CONTAINER_FLAG_FAMILIES = (
    "--device",
    "--security-opt",
    "--volumes-from",
    "--publish",
    "--publish-all",
)

# The one flag policed by a value check against a ceiling rather than by a table
# of forbidden values. Named, rather than written as a literal at the one place
# that consults it, so the derived set below and the guard cannot disagree about
# which name the cap policy is spelled with -- the shape of drift that left the
# alias sweep covering seven names when the policy policed eleven.
CAPABILITY_ADD_FLAG = "--cap-add"

# **The whole policed surface, derived.** Every long flag name the container
# guard refuses, from all three of the mechanisms that refuse one: the
# value-keyed table, the families refused whatever their value, and the cap
# ceiling. A case that checks one of those three and not the others is a case
# that checked a policy rather than the policy -- which is how the alias and
# no-short-form sweeps in `tests/podman/tests/test_podman_flags.py` came to
# cover seven names while eleven were policed, and how a future alias of
# `--device` would have reached the same position `--net` did.
#
# Derived here, once, so that a name added to any of the three is in this set
# without anybody editing a second list. It is the set the vocabulary cases
# iterate, and `test_policed_container_flags_covers_every_name_the_guard_refuses`
# is what holds it to the guard's own body rather than to this comment.
POLICED_CONTAINER_FLAGS = tuple(
    sorted(
        set(FORBIDDEN_CONTAINER_FLAGS)
        | set(FORBIDDEN_CONTAINER_FLAG_FAMILIES)
        | {CAPABILITY_ADD_FLAG}
    )
)

# The cap ceiling. The measured target needs exactly these, and
# `--cap-add=ALL` is a one-word route to every capability including `SYS_ADMIN`
# for a target that does not need it. The ceiling is the measured values rather
# than a denylist of the dangerous ones, so a capability nobody has thought of
# yet is refused too.
#
# **Four values, and `NET_RAW` is the one that was not on the plan's list until
# it was measured to be necessary.** A target started with only the plan's three
# capabilities reaches NetworkManager's "getting IP configuration" and then fails:
#
#     Error: Connection activation failed: IP configuration could not be reserved
#     (no available address, timeout, etc.)
#
# and the journal says
#
#     dhcp4 (eth0): error -1 dispatching events
#
# which reads like a DHCP server that is not answering. `/proc/self/status` in
# that container reads `CapEff: 00000000802c15fb` -- bit 13, `NET_RAW`, absent,
# because podman's default bounding set for a rootless container does not carry
# it. NetworkManager's built-in DHCP client opens an `AF_PACKET` socket to send
# and receive DORA and cannot without the capability. With `NET_RAW` the same
# container against the same dnsmasq leases an address out of the configured
# range and publishes the router's DNS. (Measured on this host; see the DHCP
# scenario's report.)
#
# `NET_RAW` is inside the container's own network namespace, which is the same
# containment `NET_ADMIN` and `SYS_ADMIN` are already inside, and the ceiling's
# subject is *widening* a container's privilege -- so the bar is that a value
# earns its place by having been measured, not by looking harmless.
#
# `--cap-drop` is deliberately outside this ceiling, and the asymmetry is the
# design, not an oversight -- so a later task that reaches for `--cap-add` and
# finds it policed while `--cap-drop` is not is not looking at an inconsistency.
# The ceiling's subject is **widening** a container's privilege, and only
# `--cap-add` widens it. `--cap-drop` can only take privilege away, so a guard
# that policed it would be removed the first time a scenario wanted a narrower
# container -- and would have bought nothing while it stood, because a drop cannot
# reach the host. The escape that *would* matter is a drop combined with a wide
# add, and that is refused on the add side, where the ceiling is
# (`--cap-drop=ALL --cap-add=ALL` is refused for the `--cap-add`). If a future
# task finds a way to make a drop reach host state, that is a case to add here --
# not an argument for having policed the word.
ALLOWED_CAPABILITIES = ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW")

# **The ceiling is not the policy.** `ALLOWED_CAPABILITIES` above is the widest
# set any container this harness starts may hold -- it is what a `--cap-add` in a
# scenario's `extra_args` is checked against. This is the narrower question: which
# container holds which of them.
#
# | role | capabilities | measured why |
# |---|---|---|
# | `target` | all four | `SYS_ADMIN` and `NET_ADMIN` for systemd and a netavark bridge, `SYS_PTRACE` for `journalctl` inside the target, and `NET_RAW` for NetworkManager's `AF_PACKET` DHCP client (see `ALLOWED_CAPABILITIES`). |
# | `mock-router` | `NET_ADMIN`, `NET_RAW` | **measured, and the measurement contradicted the obvious answer.** dnsmasq refuses to start without both, in its own words: `dnsmasq: process is missing required capability NET_ADMIN`, and `… NET_RAW` for the other. It opens the *same* `AF_PACKET` socket NetworkManager does, because a DHCP server must receive the broadcast DISCOVER before it has an address to reply from. `SYS_ADMIN` and `SYS_PTRACE` are not needed: the router runs no init and is not traced. |
#
# **`NET_BIND_SERVICE` is not in either row, and that is measured too.** `port=53`
# binds below 1024, so it looks like it should be. A container started with no
# `--cap-add` at all reports `CapEff: 00000000800405fb` on this host, which carries
# bit 10 -- podman's default rootless bounding set already has it.
#
# **An empty set is what this table said before a live run, and it was wrong.**
# dnsmasq does not look like something that needs capabilities: it is a
# foreground daemon answering on one interface, and the argument for "none" --
# `NET_BIND_SERVICE` is already present -- is true and beside the point. The
# scenario then failed with
#
# ```text
# Error: Connection activation failed: IP configuration could not be reserved
# ```
#
# and the router's own log carried `dnsmasq: process is missing required
# capability NET_ADMIN`. A capability *removed* is as loud as one added, and
# louder in this direction: the failure surfaces on the **target**, three steps
# from the container that was under-privileged, and reads exactly like a network
# fault. It is the mirror image of the defect this table exists to fix -- too much
# privilege is invisible, too little is a DHCP timeout on the other container.
#
# So each row here is a measurement, and a row that cannot name one will be wrong.
#
# The cost of the table is one line per container, which is the cost of any
# per-container policy and is why a shared array is tempting. The alternative --
# one array for every container -- is free until the first container that does not
# need what the others do, and then it is wrong in a way nothing reports, because
# a capability granted and not needed is not an error podman or the kernel will
# ever mention.
CONTAINER_CAPABILITIES = {
    "target": ALLOWED_CAPABILITIES,
    "mock-router": ("NET_ADMIN", "NET_RAW"),
}


class PodmanError(RuntimeError):
    """A Podman command failed, was refused, or could not be built."""


def canonical_flag_name(name: str) -> str:
    """The policed name a flag spelling stands for, or the name unchanged.

    Podman has aliases -- `podman-run(1)` declares `--network=mode, --net` in one
    heading, and pflag accepts either name in either value spelling. The guard
    below is keyed on the flag's *name*, so an alias that is not resolved first is
    a policed flag under a name the table does not contain: `extra_args=["--net",
    "host"]` lands after the wrapper's own `--network <net>`, `--network` is a
    `stringArray`, and the target would end up on the bridge *and* on the host
    network. Resolving here, once, is what makes the policed table a statement
    about flags rather than about spellings.

    Idempotent, so a caller may normalise defensively without a loop, and total on
    the names this harness emits: anything podman does not alias -- `--ip`,
    `--hostname`, a short form, a value -- is returned unchanged, which is what
    keeps the ordinary `extra_args` of a real scenario passing.
    """
    return PODMAN_FLAG_ALIASES.get(name, name)


class PodmanTimeout(PodmanError):
    """A Podman command ran past its deadline and was abandoned."""


class MountPolicyError(PodmanError):
    """A bind mount was refused: it is not one of the two allowed mounts."""


class ContainerPolicyError(PodmanError):
    """A container flag was refused: it would give the target the host."""


class NetworkManagerDeviceError(PodmanError):
    """A running target is not the machine these scenarios need.

    Raised only for the device state, and its message always names the two
    steps that fix it, because this failure is not the project's bug.
    """


class PodmanUnitStateUnavailable(PodmanError):
    """`systemctl is-active` answered something that is not a unit state.

    **A distinct type, and it is a terminal condition rather than a transient
    one.** `is-active` exits 0 for `active` and 3 for every state it knows; any
    other exit means the query itself did not work -- most importantly exit 4,
    which is what a target whose image has **no such unit** answers, while
    printing the same `inactive` a unit that has not started yet prints.

    It is its own type because a caller has to treat it differently from a
    transport failure. A `PodmanError` from a container that is still starting is
    "not yet" and worth retrying; this one will never become ready, so retrying
    it spends the whole budget and then reports a broken image as a slow target.
    That is the misdirection `wait_for_networkmanager_setup` avoids by letting
    this through on the first read.
    """


class NetworkManagerSetupError(NetworkManagerDeviceError):
    """The target's own NetworkManager setup has not finished, or refused.

    **A subclass, and that is load-bearing twice.** `run_target` already reports
    a `NetworkManagerDeviceError` as an *incomplete cell* with a reason, which is
    exactly right for this -- a target whose setup unit is mid-restart is not a
    failed test, it is a target that is not ready -- so subclassing means one
    `except` covers both readiness gates and neither can be raised without the
    cell reporting it as incomplete. And it keeps the narrower type available:
    `except NetworkManagerSetupError` before `except NetworkManagerDeviceError`
    is how the cell names the *unit's* requirement in the skip rather than the
    device's, so the requirement recorded in the report is the one that was
    actually not met.

    The boundary it draws is the same one the parent draws: this is the state of
    the machine before a scenario runs, never a scenario's own failure. A
    scenario that raises this would be reporting a broken matrix as a broken
    harness, and `DhcpScenarioError` is the type for that.
    """

# The device a target gets on a netavark bridge network, and the two steps that
# make NetworkManager manage it. Both are measured facts and both are stated
# wherever the check is, because the previous plan's SKIPPED list came from
# believing the sequence was impossible.
NM_DEVICE = "eth0"
NM_MANAGED_FIELD = "GENERAL.NM-MANAGED"
NM_MANAGED_YES = "yes"

# The unit that makes the device managed, and the one state of it that means the
# job is done.
#
# **The terminal state is `active`, measured on all three releases** -- not
# assumed. The unit is `Type=oneshot` with `RemainAfterExit=yes`, so after its
# script exits it stays `active` with `SubState=exited`, and that is the state
# the cell must reach before any scenario runs. Measured, per release, on a
# freshly started target:
#
# ```text
# release  nmcli     ActiveState  SubState  Result   is-enabled
# 22.04    1.36.6    active       exited    success  enabled
# 24.04    1.46.0    active       exited    success  enabled
# 26.04    1.54.3    active       exited    success  enabled
# ```
#
# **It is the same on all three, and that is worth saying rather than
# discovering per release.** 22.04 is where the setup script *skips* the override
# sequence, so it is the obvious release to expect a different unit state -- and
# it is not different: the script still runs, still creates the profile, still
# makes its own check and still exits 0. Only two commands inside it are skipped.
# So a per-release special case here would be a rule about a difference that does
# not exist, and it would be one more thing to keep true.
#
# `failed` is the other terminal state, and it is the one a reader most needs to
# be told about: the script's exit status *is* the unit's verdict (`Type=oneshot`,
# no `Restart=`), and it exits non-zero with a message naming which of the three
# things went wrong -- no profile, not an ethernet device, or the `conf.d`
# declaration did not take effect. So the gate accepts `active`, refuses
# `failed` *immediately* rather than waiting out its budget, and its refusal
# points at `journalctl -u target-nm-setup.service` in that target.
#
# `activating` is not terminal and is not a failure: it is what a healthy target
# reads for the first second or two, and it is the state the race lives in.
NM_SETUP_UNIT = "target-nm-setup.service"
NM_SETUP_ACTIVE = "active"
NM_SETUP_FAILED = "failed"
# The two states the wait acts on, and the one it waits through. **These are
# load-bearing, not documentation** -- `wait_for_networkmanager_setup` branches on
# them -- and a case in `test_command.py` holds that each is one of the words
# `systemctl is-active` can actually print, because a constant that names a state
# systemd does not have is a gate that cannot fire.
NM_SETUP_TERMINAL = (NM_SETUP_ACTIVE, NM_SETUP_FAILED)
NM_SETUP_IN_FLIGHT = "activating"
# What an answer with no state word in it looks like. Also load-bearing: it is
# what `setup_unit_state` returns when the command succeeded and printed nothing,
# and the wait treats it as "not terminal" rather than as `active`.
NM_SETUP_UNKNOWN = ""
# `systemctl is-active`'s exit codes, measured on a real 24.04 target rather than
# assumed -- and the last line is the reason this is a table and not a boolean:
#
# ```text
# target-nm-setup.service     exit=0  stdout=active
# a unit in any other state   exit=3  stdout=<that state>
# a unit that does not exist  exit=4  stdout=inactive
# ```
#
# A missing unit prints the *same word* a unit that has not started yet prints, so
# stdout cannot tell them apart and the exit code is the only discriminator. That
# is what lets `setup_unit_state` return the three interesting states as words
# while still refusing to call a broken image a slow target.
NM_IS_ACTIVE_EXIT_ACTIVE = 0
NM_IS_ACTIVE_EXIT_STATE = 3
NM_MANAGE_STEPS = (
    "nmcli device set eth0 managed yes",
    "systemctl restart NetworkManager",
)
# A connection profile has to exist on the device before the override sticks.
# Measured here, not assumed: with a profile for eth0 present, the two steps
# above take the device to `yes` on three consecutive fresh containers, and
# without one the two steps leave the field at `no` on every container tried.
#
# The profile is created by the target image's ENTRYPOINT, as its first step
# (the plan's Task 2, Step 3), and not at scenario time: the entrypoint's two
# steps are what need it, so creating it later would leave every target booting
# unmanaged and every cell of the matrix incomplete with exit 3. The plan's
# Task 3 step 4 modifies the profile the entrypoint created, post-boot, for
# `ipv4.never-default yes`. This comment is the harness's copy of that
# ordering, and the refusal below is where a reader learns it.
NM_PROFILE_STEP = (
    "a connection profile must already exist for the device, e.g. "
    "'nmcli connection add type ethernet ifname eth0 con-name eth0-managed "
    "ipv4.method auto' -- with no profile the override is accepted and the "
    "field stays 'no'"
)
# **The name of that profile, as a separate constant, and the reason is a bug this
# file had.** `NM_PROFILE_STEP` is a *sentence* for a message, and an earlier
# version of the setup-failure message tried to name the profile by splicing
# `NM_PROFILE_STEP.split('--')[0]`, which rendered as
#
#     The unit creates the 'a connection profile must already exist for the device,
#     e.g. 'nmcli connection add … auto'' connection profile
#
# -- ungrammatical, self-contradictory, and a sentence spliced out of a sentence
# that was written for a different reader. So the name lives here and the sentence
# stays a sentence; a message that needs both uses both.
NM_PROFILE_NAME = "eth0-managed"
# The measured NetworkManager version boundary for the persistent device
# override, and the five measurements that establish it. The target image's
# setup script gates the same two commands on it, and the suite asserts both
# against this list, so the two records cannot drift apart.
#
# The shape of this fact is why it is a constant rather than a sentence: below
# 1.44 the `device set` + restart sequence **cannot** make a device managed --
# the command is accepted, the audit log records `op="device-managed" ...
# result="success"`, and the field stays `no` after the restart -- so an operator
# told to run the sequence on 22.04 runs it, watches it succeed, and concludes
# the harness is wrong. Measured on this host, with a connection profile present:
#
#     nmcli 1.36.6  22.04  -> no       nmcli 1.44.2  23.10  -> yes
#     nmcli 1.42.4  23.04  -> no       nmcli 1.46.0  24.04  -> yes
#                                   nmcli 1.54.3  26.04  -> yes
NM_OVERRIDE_MINIMUM = (1, 44)
NM_OVERRIDE_MEASUREMENTS = {
    "1.36.6": False,  # Ubuntu 22.04
    "1.42.4": False,  # Ubuntu 23.04
    "1.44.2": True,   # Ubuntu 23.10
    "1.46.0": True,   # Ubuntu 24.04
    "1.54.3": True,   # Ubuntu 26.04
}
NM_UNMANAGED_EXPLANATION = (
    "A target's device is managed by two mechanisms, and which one applies "
    "depends on its NetworkManager version.\n"
    "  1. the declaration the target image ships in "
    "/etc/NetworkManager/conf.d/10-mosdns-target.conf, which narrows "
    "NetworkManager's own shipped unmanaged-devices list with "
    "'except:interface-name:eth0'. This is the baseline: it works on every "
    "release this matrix runs, and on 22.04 it is the only one that does.\n"
    "  2. 'nmcli device set eth0 managed yes' followed by "
    "'systemctl restart NetworkManager', which work only where "
    "NetworkManager has a "
    f"persistent device override -- measured present from "
    f"{NM_OVERRIDE_MINIMUM[0]}.{NM_OVERRIDE_MINIMUM[1]} and absent below it. On "
    "nmcli 1.36.6 (22.04) and 1.42.4 (23.04), 'nmcli device set eth0 managed "
    "yes' is accepted with result=\"success\" and changes nothing, and the field "
    "stays 'no' after the restart.\n"
    "The device must also be a bridge network's eth0 of type ethernet -- "
    "Podman's default rootless network hands a container a tun/tap device, "
    f"which NetworkManager refuses by design. Note also that {NM_PROFILE_STEP}."
)


def _forbidden_root(
    path: str,
    exempt_cgroup: bool = True,
    roots: Sequence[str] = FORBIDDEN_HOST_ROOTS,
) -> str | None:
    """The forbidden host root `path` is inside, if any.

    `/sys/fs/cgroup` is inside `/sys`, and it is the measured exception, so a
    path that is inside a forbidden root and is not the cgroup filesystem is
    what this names. The exception belongs to that one *mount*, so a caller
    deciding whether a path may be the source tree passes
    `exempt_cgroup=False`: allowing `/sys/fs/cgroup` as the workspace would
    bind the host's cgroup hierarchy at `/workspace` instead of a checkout.

    `roots` defaults to the full five because that is the set that governs
    binds, and the source-tree caller passes the narrower four-root set: it is
    a different question (may this be the read-only workspace) rather than a
    loosened one.
    """
    if exempt_cgroup and (path == CGROUP_HOST_PATH or path.startswith(CGROUP_HOST_PATH + "/")):
        return None
    resolved = os.path.normpath(path) if path else ""
    for root in roots:
        if resolved == root or resolved.startswith(root + "/"):
            return root
    return None


# The schemes a Podman *service* URI can carry. A connection is a URI or it is
# nothing: the harness refuses a machine, and this is where the refusal is
# structural rather than a sentence in a docstring.
CONNECTION_SCHEMES = ("ssh://", "unix://", "tcp://", "npipe://")


def _checked_connection(connection: str | None) -> str | None:
    """The connection URI, or a refusal naming the shapes that are not one.

    A bare word is refused because that is how a machine is spelled: `podman
    --connection podman-machine-default` is a valid invocation, and this
    harness's whole architecture is that there is no machine. A name of any
    other kind is still ambiguous -- podman resolves it through a shared
    configuration file, which is a second piece of state this plan refuses to
    write -- so a connection is either a URI or it is absent.

    The check is the shape, not a list of known machines: an unknown scheme is
    refused too, because a scheme this harness cannot read is a connection it
    cannot vouch for, the same rule the mount options are held to.
    """
    if connection is None or connection == "":
        return None
    if not any(connection.startswith(scheme) for scheme in CONNECTION_SCHEMES):
        raise PodmanError(
            f"refusing --connection {connection!r}: a connection is a Podman service URI, "
            f"never a name. It must start with one of "
            f"{', '.join(CONNECTION_SCHEMES)} -- a bare word would name a podman machine, and "
            f"this harness uses rootless containers on the local host and has no machine at all. "
            f"Omit the option for the local rootless Podman, which is the acceptance path"
        )
    return connection


def _checked_source_tree(source_tree: str | None) -> str | None:
    """The source tree, resolved, or a refusal when it is not a legal parameter.

    The mount allowlist is an allowlist of two, and the second entry is
    parameterized: a checkout is wherever the operator's checkout is, and
    pinning it would make the harness unusable. But the parameter *decides what
    /workspace contains*, so a source tree of `/etc` or of `/` made the policy
    `run.py --source-tree /etc matrix` bind the host's `/etc` -- including its
    `/etc/resolv.conf` -- into a target that holds SYS_ADMIN and runs systemd.
    Every later check compares the source against the allowlist's own entry, so
    a parameter that is itself forbidden makes them agree and the check passes.
    That is the defect this function exists to close: the parameter must be
    legal, not only the destinations.

    The set consulted is `FORBIDDEN_SOURCE_TREE_ROOTS` -- the four roots that
    hold the host's resolver and its systemd state -- and not the five that
    govern binds generally. A checkout under `/home` is therefore accepted and
    emitted `:ro`, because a read-only bind of a source directory exposes that
    directory's bytes and nothing a target can change on the host, and because
    `/home`'s place in the bind list is about what the harness writes and what
    the host-isolation snapshot compares, neither of which a read-only mount
    does. The security argument is written out at the constant, so a reviewer
    inclined to restore the old list has to argue with it.

    Every writable mount stays refused, and that is not this function: a caller
    asking for `:rw` at `WORKSPACE_MOUNT_POINT` is refused by `_check_mount`,
    which requires the source to equal the allowlist's own entry *and* the mode
    to be `ro`. The exemption is for the read-only workspace, not for the path.

    Checked after resolution, so `/etc/../etc` and `//etc` are refused too --
    a check on the raw string is defeated by a relative component, and a
    relative component is what an operator types out of habit. `/` is refused
    explicitly: it is not under any of the four roots in the sense the prefix
    test uses, and it contains all four.
    """
    if not source_tree:
        return None
    resolved = str(Path(source_tree).resolve())
    remedy = (
        "Point --source-tree at the checkout directory -- e.g. "
        f"--source-tree /home/$(whoami)/mosdns-router -- or omit it to use this "
        f"repository ({REPO_ROOT})"
    )
    if resolved == "/":
        raise MountPolicyError(
            f"refusing source tree {resolved!r}: it is the whole filesystem, which contains "
            f"every forbidden host root ({', '.join(FORBIDDEN_SOURCE_TREE_ROOTS)}) and all of "
            f"/home. The source tree is mounted read-only at {WORKSPACE_MOUNT_POINT}, and a "
            f"mount of '/' would put the host's resolver and systemd state there instead of a "
            f"checkout. {remedy}"
        )
    root = _forbidden_root(resolved, exempt_cgroup=False, roots=FORBIDDEN_SOURCE_TREE_ROOTS)
    if root:
        raise MountPolicyError(
            f"refusing source tree {resolved!r}: it would be bound at "
            f"{WORKSPACE_MOUNT_POINT} read-only, and it is under {root}, which holds the "
            f"host's resolver and its systemd state -- the four roots a source tree may not be "
            f"under are {', '.join(FORBIDDEN_SOURCE_TREE_ROOTS)}. A checkout under /home, or "
            f"anywhere else, is fine and is still mounted read-only. {remedy}"
        )
    return resolved


# The keyed `--mount` options this harness will accept, and the keys that name
# the two directions of a mode. An allowlist, because a keyed option is usually
# `key=value` and the value is where the hazard is: `relabel=shared` is the
# `--mount` spelling of the `:z` this module already refuses, `chown=true` is a
# recursive ownership change on the **host**, and `bind-propagation=rshared` on
# the cgroup filesystem makes a submount the target creates propagate back into
# the host's own hierarchy. All three were accepted, because a parser that
# collected only the *valueless* keys dropped every one of them before the policy
# saw them.
#
# So the rule is the same as for the valueless options, and the same as the
# capability ceiling: an option this harness does not recognise is refused, which
# means an option nobody has thought of yet is refused too. `type`, the source
# and destination spellings, and the two mode keys are all it needs -- the
# wrapper emits the colon-separated `-v` form itself and never writes a `--mount`.
ALLOWED_MOUNT_KEYS = frozenset(
    {
        "type",
        "src",
        "source",
        "dst",
        "dest",
        "destination",
        "target",
        "ro",
        "readonly",
        "rw",
        "readwrite",
    }
)
READ_ONLY_MOUNT_KEYS = ("ro", "readonly")
WRITABLE_MOUNT_KEYS = ("rw", "readwrite")

# The keyed options whose *effect* is a change to this machine, refused with the
# reason rather than with "unrecognised option", because they are recognisable
# and an operator who wrote one deserves to be told what it does. Each is a
# refusal the wrapper would have to make anyway -- `:Z` and `:z` are already
# refused above, in the colon form, for the same reason.
HOST_MUTATING_MOUNT_KEYS = {
    "relabel": "relabels the files on the host, which is a change to this machine made by a "
    "command whose job is to change nothing here -- it is `:z` under the keyed spelling",
    "chown": "recursively changes the owner and group of the source **on the host**, which is "
    "the same thing `:Z`/`:z` is refused for",
    "U": "recursively changes the owner and group of the source **on the host**; it is podman's "
    "abbreviation of chown",
    "context": "applies an SELinux label to the source on the host, which relabels it by another "
    "name",
    "idmap": "creates an id-mapped mount, which rewrites how ownership is interpreted for the "
    "host's own files",
    "bind-propagation": "makes the mount shared, so a submount the target creates under it "
    "propagates back into the host's own filesystem or cgroup hierarchy",
}


def _is_true(value: str) -> bool:
    """Whether a keyed option's value means "yes", the way podman reads it."""
    return value.strip().lower() in ("", "true", "1", "yes", "on")


def _parse_mount_spec(spec: str) -> tuple[str | None, str | None, list[str]]:
    """Read one mount specification as (source, destination, options).

    Podman accepts a colon-separated `-v` value and a keyed `--mount` value, and
    a policy that read only one of them would be a policy on a spelling.

    An option in the returned list is either a bare key (`ro`, `Z`) or a
    `key=value` pair, and **both are returned**. A parser that kept only the
    bare keys -- which is what this one used to do, because that is how the colon
    form spells an option -- silently discarded every valued key of a `--mount`,
    and in the keyed form nearly every option has a value.
    """
    if "," in spec and "=" in spec.split(",")[0]:
        fields: dict[str, str] = {}
        for part in spec.split(","):
            key, separator, value = part.partition("=")
            fields[key.strip()] = value.strip() if separator else ""
        source = fields.get("src") or fields.get("source")
        destination = fields.get("dst") or fields.get("destination") or fields.get("target")
        options = sorted(
            key if key == "type" else (key if not value else f"{key}={value}")
            for key, value in fields.items()
        )
        return source, destination, options
    parts = spec.split(":")
    if len(parts) == 1:
        # A bare token is an anonymous volume: a resource the harness would
        # create without recording it, which cleanup then cannot remove.
        return parts[0], None, []
    options_text = ",".join(parts[2:])
    options = [option for option in options_text.split(",") if option]
    return parts[0], parts[1], options


@dataclass(frozen=True)
class CommandResult:
    """What a Podman command returned.

    The environment is deliberately absent. A result is the thing a scenario
    attaches to a report, and a whole environment is the one thing that can put
    a secret into a file that gets archived.
    """

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self):
        """stdout with the trailing newline Podman adds removed."""
        return self.stdout.strip()


def _subcommand_of(args: Sequence[str]) -> str:
    """The first token of `args` that is not a flag or a flag's value."""
    expect_value = False
    for token in args:
        if expect_value:
            expect_value = False
            continue
        if token.startswith("-"):
            # A `--flag=value` carries its value; a bare `--flag` may or may
            # not, and podman's global flags are all of the first shape.
            expect_value = "=" not in token
            continue
        return token
    return ""


class Podman:
    """A Podman client that builds argument arrays and holds the policy."""

    def __init__(
        self,
        executable: str = "podman",
        connection: str | None = None,
        source_tree: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        build_timeout: float = DEFAULT_BUILD_TIMEOUT,
        extra_env: Mapping[str, str] | None = None,
    ):
        self.executable = executable
        # A Podman service URI -- `ssh://…`, `unix://…`, `tcp://…`. It is never
        # a machine name: there is no machine, and a bare word is refused here
        # rather than documented in prose.
        self.connection = _checked_connection(connection)
        self.source_tree = _checked_source_tree(source_tree)
        self.timeout = timeout
        # An image build installs packages, and a target image installs
        # NetworkManager and a systemd; that is minutes rather than seconds, and
        # a deadline the build cannot meet is a deadline that turns a working
        # machine into a harness error. It is a separate attribute rather than a
        # per-call argument because a caller shortening the command deadline
        # (`network_exists` below does) is not asking to shorten a build.
        self.build_timeout = build_timeout
        self._extra_env = dict(extra_env or {})

    # -- the command line ---------------------------------------------------

    def build_argv(self, args: Sequence[str]) -> list[str]:
        """The full argument array for one Podman invocation.

        Both policies are applied here rather than where the arrays are built,
        because this is the last point every array passes through. Raises rather
        than returning an array the harness must not run, so a policy failure
        cannot be ignored by a caller that forgot to check.
        """
        args = [str(a) for a in args]
        if not args:
            raise PodmanError("a podman invocation needs a subcommand")
        if _subcommand_of(args) == MACHINE_SUBCOMMAND:
            raise PodmanError(
                f"refusing to run 'podman {MACHINE_SUBCOMMAND}': this harness uses rootless "
                f"Podman containers only, and there is no virtual machine in it"
            )
        self._check_container_flags(args)
        self._check_mount_arguments(args)
        argv = [self.executable]
        if self.connection:
            argv += ["--connection", self.connection]
        return argv + args

    # -- the policies -------------------------------------------------------

    def allowed_mounts(self) -> dict[str, tuple[str, str]]:
        """The mounts this wrapper permits, as destination -> (source, mode)."""
        allowed = {CGROUP_MOUNT_POINT: (CGROUP_HOST_PATH, "rw")}
        if self.source_tree:
            allowed[WORKSPACE_MOUNT_POINT] = (self.source_tree, "ro")
        return allowed

    def mount_arguments(self) -> list[str]:
        """The `-v` arguments a target container is started with."""
        spec = f"{CGROUP_HOST_PATH}:{CGROUP_MOUNT_POINT}:rw"
        if self.source_tree:
            spec += f",{self.source_tree}:{WORKSPACE_MOUNT_POINT}:ro"
        return sum((["-v", part] for part in spec.split(",")), [])

    def _check_container_flags(self, args: Sequence[str]) -> None:
        """Refuse any flag that would hand the target the host, in any spelling.

        pflag accepts `--flag value` and `--flag=value` for the same string
        flag, and `run_container` appends `extra_args` after its own
        `--network <net>`, so a repeated flag's last occurrence is the one podman
        reads. Both facts are why this walks tokens, reads a flag's name and
        the value that flag carries, and compares those -- rather than matching
        a list of `--flag=value` strings, which is a check on a spelling.

        Every violation in the array is collected and reported together, and the
        scan does not stop at the first: a guard that named one and returned
        would make a caller fix them one at a time for a defect that was
        visible from the start.

        It examines the whole array, not only `extra_args`, so the wrapper's own
        flags are inside the policy rather than beside it. A wrapper that grew a
        `--cap-add=ALL` of its own would be caught by this case, and the flag
        set it is allowed to emit is asserted as literals in `ArgumentArrayTest`.

        A flag's *name* is canonicalised before **any** of the three policies is
        consulted, so an alias pflag accepts reaches the policy it belongs to.
        That is a statement about all three, and it was not true of all three:
        the canonicalisation used to happen after the family and cap branches,
        which compared the raw name, so those two were a check on a spelling
        again -- and `--net` is exactly that defect, one table over. `--net` is
        the alias podman documents (`podman-run(1)`: `.SS --network=mode, --net`)
        and it is the shape of the hazard: it lands after the wrapper's own
        `--network <net>`, `--network` is a `stringArray`, and the target would
        end up on the bridge *and* on the host network. `tests/podman/tests/
        test_podman_flags.py` derives the set of aliases from podman's own
        documentation, and it derives it over `POLICED_CONTAINER_FLAGS` -- all
        eleven names, not the seven the value-keyed table holds -- so the next
        alias is a case failure rather than a review.

        It also examines every token rather than skipping each flag's value, and
        that is the safe direction. Skipping a value means trusting that the
        token after `--privileged` is a value; not skipping it means a token
        that *is* `--privileged` is caught wherever it sits, including where the
        caller meant it as a value. The cost is a false positive on an array
        that puts a policed flag name in a value position, which no real podman
        invocation does -- and a false positive here is a refusal with a readable
        message, while the false negative is the host.
        """
        violations: list[str] = []
        index = 0
        while index < len(args):
            token = args[index]
            index += 1
            if not token.startswith("-"):
                continue
            name, separator, inline = token.partition("=")
            # The space-separated form's value is the next token. A token that
            # is not a flag is skipped by the loop's own test, so the only extra
            # cost of reading it here is for a value that itself looks like a
            # flag -- the safe direction, as the docstring says.
            value = inline if separator else (args[index] if index < len(args) else None)

            # Canonicalised once, before **any** of the three policies is
            # consulted -- not just before the table lookup. The family and cap
            # branches used to compare the raw name, which meant an alias of
            # `--device`, `--security-opt`, `--volumes-from` or `--cap-add` would
            # have reached a name-keyed check those branches could not see. There
            # is no such alias in podman 5.7.0 (the vocabulary case proves it
            # from the documentation), so this closes a future podman rather than
            # a live hole; the difference between the two is recorded rather than
            # left to be rediscovered.
            policed = canonical_flag_name(name)
            alias_note = (
                f" {name} is podman's alias for {policed}, so this is the same flag under the "
                f"other name pflag accepts -- refusing it here is not a quirk of this harness."
                if policed != name
                else ""
            )

            if policed in FORBIDDEN_CONTAINER_FLAG_FAMILIES:
                violations.append(
                    f"{token!r} (this harness has no opt-in for it: a device is host hardware, "
                    f"a seccomp or apparmor override removes a layer of the boundary, "
                    f"--volumes-from is another container's filesystems, and publishing a port "
                    f"would put a mock router or a mock CDN on the operator's own machine -- the "
                    f"plan's bridge network is private to the run and a published port is the one "
                    f"way past it.{alias_note})"
                )
                continue
            if policed == CAPABILITY_ADD_FLAG:
                if value not in ALLOWED_CAPABILITIES:
                    violations.append(
                        f"{token!r} (the cap ceiling is "
                        f"{', '.join(ALLOWED_CAPABILITIES)}; --cap-add=ALL is a one-word route "
                        f"to every capability.{alias_note})"
                    )
                continue
            # Both value spellings are already covered -- `value` is the inline
            # one or the next token -- and this is the part that covers the
            # *other name* for the same flag.
            if policed in FORBIDDEN_CONTAINER_FLAGS:
                forbidden_value = FORBIDDEN_CONTAINER_FLAGS[policed]
                if forbidden_value is None or value == forbidden_value:
                    violations.append(
                        f"{token!r} (a target container may not be given the host it runs on."
                        f"{alias_note} The measured flag set is --systemd=always "
                        f"--cgroupns=private with {', '.join(ALLOWED_CAPABILITIES)}, and no "
                        f"privilege or host-namespace flag. The policed names are "
                        f"{', '.join(FORBIDDEN_CONTAINER_FLAG_NAMES)})"
                    )
        if violations:
            raise ContainerPolicyError(
                "refusing to start the target:\n"
                + "\n".join(f"  - {violation}" for violation in violations)
            )

    @staticmethod
    def _mount_mode(options: Sequence[str]) -> str:
        """The mode a mount's options ask for: `ro`, `rw`, or `both`.

        Read from the *value* where the option has one, because a keyed
        `ro=false` asks for the opposite of a bare `ro` and a guard that only
        looked at the key would judge a writable workspace from the mode it was
        meant to be denied -- and because a keyed `rw=false` is how the keyed form
        spells *read-only*, which a default-to-`rw` reading gets backwards. So
        each direction is read as what it says and the two are reconciled: an
        explicit statement in one direction is the other one's negation, and no
        statement at all is podman's default, which is `rw`.
        """
        read_only: bool | None = None
        writable: bool | None = None
        for option in options:
            key, _, value = option.partition("=")
            if key in READ_ONLY_MOUNT_KEYS:
                read_only = _is_true(value)
            elif key in WRITABLE_MOUNT_KEYS:
                writable = _is_true(value)
        if read_only is None and writable is None:
            return "rw"
        wants_read_only = read_only if read_only is not None else not writable
        wants_writable = writable if writable is not None else not read_only
        if wants_read_only and wants_writable:
            return "both"
        return "ro" if wants_read_only else "rw"

    def _check_mount_arguments(self, args: Sequence[str]) -> None:
        index = 0
        while index < len(args):
            token = args[index]
            if token in ("-v", "--volume", "--mount"):
                if index + 1 >= len(args):
                    raise MountPolicyError(
                        f"'{token}' is the last argument in the array and carries no mount"
                    )
                self._check_mount(args[index + 1])
                index += 2
                continue
            if token.startswith("--volume=") or token.startswith("--mount="):
                self._check_mount(token.split("=", 1)[1])
            index += 1

    def _check_mount(self, spec: str) -> None:
        source, destination, options = _parse_mount_spec(spec)
        if destination is None:
            raise MountPolicyError(
                f"refusing mount '{spec}': a bare token is an anonymous volume, and a volume "
                f"this harness did not record is one cleanup cannot remove"
            )
        # Every option is read, whether it was spelled bare (`ro`, `:Z`) or
        # keyed (`ro=true`, `relabel=shared`). The two spellings are the same
        # option and were once policed differently, which is how a keyed
        # `relabel=shared` reached the host's resolver files while the colon
        # `:z` in front of it was refused.
        for option in options:
            key, separator, value = option.partition("=")
            if key in ("Z", "z"):
                raise MountPolicyError(
                    f"refusing mount '{spec}': '{option}' relabels the file on the host, which "
                    f"is a change to this machine made by a command whose job is to change "
                    f"nothing here"
                )
            if key in HOST_MUTATING_MOUNT_KEYS:
                raise MountPolicyError(
                    f"refusing mount '{spec}': '{key}{'=' + value if separator else ''}' "
                    f"{HOST_MUTATING_MOUNT_KEYS[key]}"
                )
            if key not in ALLOWED_MOUNT_KEYS:
                raise MountPolicyError(
                    f"refusing mount '{spec}': '{key}' is not a mount option this harness uses, "
                    f"and an option it does not recognise is one it cannot vouch for"
                )
        if self._mount_mode(options) == "both":
            raise MountPolicyError(f"refusing mount '{spec}': it is both read-only and writable")
        if not source.startswith("/"):
            raise MountPolicyError(
                f"refusing mount '{spec}': '{source}' is a relative path, so it resolves "
                f"against a working directory rather than naming a host path"
            )
        allowed = self.allowed_mounts()
        if destination not in allowed:
            root = _forbidden_root(destination)
            detail = (
                f", and {destination} is under the host root {root} this plan forbids mounting"
                if root
                else ""
            )
            raise MountPolicyError(
                f"refusing mount '{spec}': the only destinations this harness mounts are "
                f"{', '.join(sorted(allowed))}{detail}"
            )
        want_source, want_mode = allowed[destination]
        if source != want_source:
            root = _forbidden_root(source)
            detail = (
                f" -- {source} is under the host root {root}, which this plan forbids mounting"
                if root
                else ""
            )
            raise MountPolicyError(
                f"refusing mount '{spec}': {destination} may only be bound to {want_source}{detail}"
            )
        effective_mode = self._mount_mode(options)  # podman's default is rw
        if effective_mode != want_mode:
            wanted = "read-only" if want_mode == "ro" else "writable"
            raise MountPolicyError(
                f"refusing mount '{spec}': {destination} must be mounted {wanted} and this one "
                f"is {effective_mode}"
            )
        # The last refusal, and the only one that is not a comparison against the
        # allowlist. Everything above checks a mount against `allowed_mounts()`,
        # which means every one of them agrees with the allowlist by
        # construction -- so a later task that adds an entry to the allowlist
        # widens every one of those checks at once. A source inside one of the
        # five forbidden roots is therefore refused here, by path and regardless
        # of what the allowlist says, so the widening is a decision somebody has
        # to make in this function rather than a side effect of a table edit.
        #
        # The rule is *writable*, not *any*: a read-only bind of a directory under
        # a forbidden root exposes that directory's bytes and nothing a target
        # can change on the host, which is the whole argument for permitting this
        # host's checkout under `/home` (see `FORBIDDEN_SOURCE_TREE_ROOTS`), and
        # a blanket refusal here would leave no legal `--source-tree` on this
        # machine. `/sys/fs/cgroup` is exempt because it is the one measured
        # writable mount of a forbidden root that a systemd target cannot start
        # without.
        writable_root = _forbidden_root(source)
        if writable_root and effective_mode != "ro":
            raise MountPolicyError(
                f"refusing mount '{spec}': {source} is inside the host root {writable_root}, "
                f"which this plan forbids binding writable -- a mount of any of "
                f"{', '.join(FORBIDDEN_HOST_ROOTS)} must be read-only, whatever the allowlist "
                f"says, because a writable bind is a route to the host's resolver and its "
                f"systemd state. (The one exception is {CGROUP_HOST_PATH}, which a systemd "
                f"container cannot start without.) Read the source tree at {WORKSPACE_MOUNT_POINT} "
                f"':ro' instead"
            )

    def run(
        self,
        args: Sequence[str],
        timeout: float | None = None,
        check: bool = True,
    ) -> CommandResult:
        """Run one Podman command and return what it produced.

        Streams are captured, the status is checked, and the deadline is
        explicit. A caller that wanted the status instead of an exception wants
        a different method.

        **`check` exists for one command, and it defaults to `True`.**
        `systemctl is-active` exits **3** for every state that is not `active`, and
        those states are the *answer* rather than a failure: `activating` is what a
        healthy target reads for the first seconds of its life, and `failed` is the
        verdict the target's own setup script returned. So the one read whose
        answer is a non-zero exit asks for it by name, rather than being handed an
        exception that says only that a command failed.

        The default is the load-bearing half. A permissive default would stop
        every `nmcli` refusal in this harness from raising, and those refusals are
        what keep a scenario from reading the output of a failure;
        `SetupUnitStateTest.test_the_read_is_the_only_one_that_opts_out_of_checking`
        holds the default so a later task cannot widen the exception by accident.
        """
        argv = self.build_argv(args)
        try:
            completed = subprocess.run(
                argv,
                cwd=self.working_directory,
                env=self.child_environment(),
                capture_output=True,
                text=True,
                timeout=self.timeout if timeout is None else timeout,
                check=check,
            )
        except subprocess.TimeoutExpired as expired:
            raise PodmanTimeout(
                f"'{' '.join(argv)}' ran longer than "
                f"{expired.timeout}s and was abandoned"
            ) from expired
        except subprocess.CalledProcessError as failed:
            raise PodmanError(
                f"'{' '.join(self.build_argv(args))}' exited {failed.returncode}"
                + (f":\n{failed.stderr.strip()}" if failed.stderr.strip() else "")
            ) from failed
        return CommandResult(
            argv=tuple(argv),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    # -- the child's environment --------------------------------------------

    def child_environment(self) -> dict[str, str]:
        """The environment a Podman command is started with.

        A named set of variables from the operator's environment, plus whatever
        the harness passes explicitly. Nothing else, so a variable this machine
        happens to export cannot reach a command line.
        """
        env = {name: os.environ[name] for name in FORWARDED_ENV_NAMES if name in os.environ}
        env.update(self._extra_env)
        return env

    def forwarded_env_names(self) -> tuple[str, ...]:
        """The names the wrapper forwards from the operator's environment."""
        return FORWARDED_ENV_NAMES

    @property
    def working_directory(self) -> str:
        return self.source_tree or os.getcwd()

    # -- the operations the harness needs ------------------------------------

    def client_version(self) -> str:
        return self.run(["version", "--format", "{{.Client.Version}}"]).output

    def store_graph_driver(self) -> str:
        return self.run(["info", "--format", "{{.Store.GraphDriverName}}"]).output

    def create_network(self, name: str, subnet: str) -> CommandResult:
        return self.run(["network", "create", "--subnet", subnet, name])

    def inspect_network(self, name: str) -> str:
        return self.run(["network", "inspect", name, "--format", "{{.Name}}"]).output

    def remove_network(self, name: str) -> CommandResult:
        return self.run(["network", "rm", name])

    def network_exists(self, name: str, timeout: float | None = None) -> bool:
        """Whether a network is still there, asked the way podman answers it.

        `network exists` exits 0 for present and 1 for absent, and says nothing
        on stderr in the absent case. A non-zero status that *does* carry a
        diagnostic is a service that could not be asked, which is a different
        answer and is raised rather than reported as absence -- a teardown that
        read it as absence would claim a clean sweep it never performed.

        The deadline is a parameter for the same reason `run`'s is: this is the
        question at the end of a run, and a caller with a shorter budget than
        the default has to be able to say so rather than wait out the full one.
        """
        argv = self.build_argv(["network", "exists", name])
        try:
            completed = subprocess.run(
                argv,
                cwd=self.working_directory,
                env=self.child_environment(),
                capture_output=True,
                text=True,
                timeout=self.timeout if timeout is None else timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as expired:
            raise PodmanTimeout(
                f"'{' '.join(argv)}' ran longer than {expired.timeout}s and was abandoned"
            ) from expired
        if completed.returncode == 0:
            return True
        if completed.returncode == 1 and not completed.stderr.strip():
            return False
        raise PodmanError(
            f"'{' '.join(argv)}' exited {completed.returncode}"
            + (f":\n{completed.stderr.strip()}" if completed.stderr.strip() else "")
        )

    def run_container(
        self,
        image: str,
        name: str,
        network: str,
        extra_args: Sequence[str] = (),
        capabilities: Sequence[str] = ALLOWED_CAPABILITIES,
    ) -> str:
        """Start a container and return its id.

        The flags are the ones measured to work on this host: systemd as the
        init, a private cgroup namespace, the capabilities this container was
        measured to need, and the cgroup filesystem bound in. `--cgroupns=host`
        and `--privileged` are not here and must not be added -- the first does
        not start, the second reaches the host this harness is required not to
        touch.

        **The capabilities are a per-container argument, and the default is the
        target's four.** `ALLOWED_CAPABILITIES` is the *ceiling* -- the widest set
        any container here may hold -- and `CONTAINER_CAPABILITIES` is the policy
        that says which container holds how much of it. They are different
        questions, and one answer for both is how the mock router came to be given
        `SYS_ADMIN` and `SYS_PTRACE`: `run_container` is shared, so before this was
        a parameter every container got whatever the target needed. A capability
        the target needed and was measured to need is defensible; one handed to a
        container that did not is only defensible if the code says why, and it did
        not.

        **The router's row was written as an empty set and a live run proved it
        wrong.** dnsmasq needs `NET_ADMIN` and `NET_RAW` -- it opens an
        `AF_PACKET` socket to receive the broadcast DISCOVER, exactly as
        NetworkManager does to send one -- and it exits 5 with
        `dnsmasq: process is missing required capability NET_ADMIN` rather than
        starting. The symptom appears on the *target* as an unresolvable lease, so
        the measurement belongs here and not to whoever reads the failure first.
        Both facts are in `CONTAINER_CAPABILITIES`.

        The cost of the shared array was a ceiling that read as a policy: a
        reader of `ALLOWED_CAPABILITIES` would conclude the router needs
        `SYS_ADMIN` and `SYS_PTRACE` for a daemon that runs no init, and would
        carry that belief into the next container the plan adds. So the
        per-container answer is in the code, next to the flags -- and it is
        narrower than the target's by exactly the two the router does not need,
        which is the only part of this that is an argument rather than a
        measurement. `CONTAINER_CAPABILITIES` carries the measurement.

        **`--cap-add=NET_RAW` is in the *target's* set because a DHCP lease needs
        it, and the plan's three flags are not enough.** The measurement is written
        out at `ALLOWED_CAPABILITIES`; the short version is that NetworkManager's
        built-in DHCP client opens an `AF_PACKET` socket, podman's default bounding
        set does not carry `NET_RAW`, and without it every DHCP transaction in the
        target fails with `dhcp4 (eth0): error -1 dispatching events` while the
        mock router sits on the other side of the bridge with an empty pool. It is
        a parameter rather than a scenario's `extra_args` because the target is
        *one* container for the whole cell: a capability a later scenario needs and
        an earlier one does not is a property of the run, not of the scenario that
        happens to be looking.
        """
        args = [
            "run",
            "-d",
            "--name", name,
            "--network", network,
            "--systemd=always",
            "--cgroupns=private",
        ]
        args += [f"--cap-add={capability}" for capability in capabilities]
        args += self.mount_arguments()
        args += list(extra_args)
        args.append(image)
        return self.run(args).output

    def exec_container(
        self, container: str, *command: str, check: bool = True
    ) -> CommandResult:
        """Run one command inside a container, raising unless it is told not to.

        `check=False` is for a command whose *answer* is a non-zero exit -- see
        `Podman.run` and `setup_unit_state`, which is the only caller that uses it.
        """
        return self.run(["exec", container, *[str(c) for c in command]], check=check)

    def exec_status(self, container: str, *command: str) -> int:
        """The exit status of one command inside a container, asked without raising.

        **`check=True` is the policy everywhere else here, and it is right there:**
        a scenario that read stdout from a command that failed would be reading
        the output of a failure. This is the one question that is *about* the
        status -- "is this file there?" is `test -e`, and its whole answer is a
        number -- so a method that raised would turn a question into an error and
        force the caller to catch an exception to ask whether a file exists.

        It is deliberately narrow: a caller that wanted the output of a command
        that might fail gets an exception from `exec_container`, because a status
        a scenario did not look at is a failure a scenario cannot see.
        """
        argv = self.build_argv(["exec", container, *[str(c) for c in command]])
        completed = subprocess.run(
            argv,
            cwd=self.working_directory,
            env=self.child_environment(),
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        return completed.returncode

    def exec_script(self, container: str, script: str) -> CommandResult:
        """Run a shell script inside a container.

        The script is one argument. It is never given to a shell on this side
        of the boundary, so nothing in a scenario name or a path can be
        interpreted here.
        """
        return self.run(["exec", container, "sh", "-c", script])

    def copy_to(self, container: str, host_path: str, container_path: str) -> CommandResult:
        return self.run(["cp", str(host_path), f"{container}:{container_path}"])

    def stop(self, container: str) -> CommandResult:
        return self.run(["stop", "--time", str(STOP_TIME_SECONDS), container])

    def remove_container(self, name: str) -> CommandResult:
        return self.run(["rm", "-f", name])

    def create_volume(self, name: str) -> CommandResult:
        return self.run(["volume", "create", name])

    def remove_volume(self, name: str) -> CommandResult:
        return self.run(["volume", "rm", "-f", name])

    # -- the image and process operations a scenario needs ---------------------

    def image_exists(self, tag: str) -> bool:
        """Whether `tag` is in the local store, asked the way podman answers it.

        `image exists` exits 0 for present and 1 for absent, the same shape as
        `network exists` above, and for the same reason: a build is expensive and
        a scenario should not pay for one it already has. The digest behind a
        reusable tag is a property of what was built, which is why the tag
        itself carries a hash of the Containerfile and the base reference --
        `images.image_tag` is what makes this question safe to ask.

        A non-zero status that carries a diagnostic is a store that could not be
        asked, and is raised rather than read as absence, for the reason the
        network case gives: a teardown that read it as absence would claim a
        clean sweep it never performed.
        """
        argv = self.build_argv(["image", "exists", tag])
        try:
            completed = subprocess.run(
                argv,
                cwd=self.working_directory,
                env=self.child_environment(),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as expired:
            raise PodmanTimeout(
                f"'{' '.join(argv)}' ran longer than {expired.timeout}s and was abandoned"
            ) from expired
        if completed.returncode == 0:
            return True
        if completed.returncode == 1 and not completed.stderr.strip():
            return False
        raise PodmanError(
            f"'{' '.join(argv)}' exited {completed.returncode}"
            + (f":\n{completed.stderr.strip()}" if completed.stderr.strip() else "")
        )

    def build_image(
        self,
        tag: str,
        containerfile: str,
        build_args: Sequence[tuple[str, str]] = (),
        context: str = ".",
    ) -> str:
        """Build `tag` from `containerfile` and return the image id.

        **The base image arrives as a build argument and never as a `FROM` in the
        file.** That is what `images.lock.json` is for: `docker.io/library/ubuntu:
        24.04@sha256:…` names the release for a reader and the bytes for the
        machine, and it has to be resolved at run time from the lock rather than
        written into a Containerfile, where a point release would land under the
        same tag without it changing.

        `--pull` is left at podman's default on purpose. `never` would make a
        build against a base that is not in the store fail with a manifest
        error, and `always` would re-resolve the tag of a digest-pinned
        reference on every run for no gain -- the digest is the pin.
        """
        args = ["build", "--file", str(containerfile)]
        for name, value in build_args:
            args += ["--build-arg", f"{name}={value}"]
        args += ["--tag", tag, str(context)]
        return self.run(args, timeout=self.build_timeout).output

    def container_logs(self, container: str) -> str:
        """Everything a container has written to its stdout and stderr.

        **Both of podman's own streams, because podman puts them on different
        ones.** Measured on this host:

        ```text
        $ podman logs probe-router
        dnsmasq[1]: started, version 2.91 cachesize 150      # on a shell's stdout
        $ python3 -c '…; print(podman.container_logs("probe-router"))'
        ''
        ```

        `podman logs` gives a container's stdout to podman's stdout and the
        container's stderr to podman's stderr, the same split `docker logs`
        makes. dnsmasq with `log-facility=-` logs to **stderr** -- it is the only
        facility a container has, there being no syslog in one -- so a reader that
        read only stdout would see an empty log for a daemon logging perfectly
        well. The DHCP scenario reads this log as the *attribution* for the
        address and the resolver the target was given, so a reader that found
        nothing here would report a DORA exchange that plainly happened as a
        missing one. That is not hypothetical: it is what the first live 22.04
        cell did, and it is the reason this method joins the two streams.

        They are joined stdout-first rather than one being preferred, so a
        container that writes to both is recorded whole and the document reads in
        the order the streams were written. The result is stripped, as
        `CommandResult.output` is, so a log's trailing newline is not a
        difference between two runs of the same thing.
        """
        result = self.run(["logs", container])
        return "".join(part for part in (result.stdout, result.stderr) if part).strip()

    def signal_container(self, container: str, signal: str = "HUP") -> CommandResult:
        """Send a signal to a container's **init**.

        `podman kill --signal` reaches PID 1 inside the container, which for the
        mock router is dnsmasq itself: the image runs it with
        `--keep-in-foreground` for exactly this reason. An entrypoint that
        started it in the background and waited would have a shell as PID 1, the
        signal would go to the shell, and the scenario would wait for a DNS change
        that no process had been asked to make.
        """
        return self.run(["kill", "--signal", signal, container])

    def all_container_names(self, prefix: str) -> tuple[str, ...]:
        """Every container whose name starts with `prefix`, running or not.

        The filter is anchored with a leading `^` because Podman's `name=`
        filter is a substring match. An unanchored `mosdns-` finds another run's
        containers as well, and a teardown that sweeps by prefix would remove
        them -- which matters because two runs on one machine is the normal
        case, not an edge case.
        """
        result = self.run(
            ["ps", "-a", "--filter", f"name=^{prefix}", "--format", "{{.Names}}"]
        )
        return tuple(line for line in result.output.splitlines() if line)

    def all_volume_names(self, prefix: str) -> tuple[str, ...]:
        result = self.run(
            ["volume", "ls", "--filter", f"name=^{prefix}", "--format", "{{.Name}}"]
        )
        return tuple(line for line in result.output.splitlines() if line)

    def network_names(self, prefix: str) -> tuple[str, ...]:
        """Every network whose name starts with `prefix`.

        Anchored for the same reason as the container and volume listings, and
        read back rather than reconstructed: a cleanup that removed a network
        by a name it had invented would report an error for a network that
        never existed.
        """
        result = self.run(["network", "ls", "--format", "{{.Name}}"])
        return tuple(line for line in result.output.splitlines() if line.startswith(prefix))

    def available(self) -> bool:
        """True when the executable exists on this machine.

        A preflight uses it to report a missing Podman rather than to install
        one: the harness never installs its own prerequisites.
        """
        return shutil.which(self.executable) is not None or Path(self.executable).exists()

    def nm_managed(self, container: str, device: str = NM_DEVICE) -> str:
        """Ask a running target whether NetworkManager manages its device.

        The query is a fixed read built as an argument array, not a script, so
        it is the same bytes on every run. `check=True` means a target where the
        device does not exist raises rather than answering.
        """
        return self.exec_container(
            container, "nmcli", "-g", NM_MANAGED_FIELD, "device", "show", device
        ).output

    def setup_unit_state(self, container: str, unit: str = NM_SETUP_UNIT) -> str:
        """The state of the target image's NetworkManager setup unit.

        **Asked with `check=False`, and that is not a convenience -- it is the whole
        point of the read.** `systemctl is-active` exits **3** for every state that
        is not `active`, and all three of those are answers rather than failures:
        `activating` is what a healthy target reads for the first seconds of its
        life, `inactive` is what a target reads before the unit starts, and
        `failed` is the verdict the setup script itself returned. A read that
        raised on them would answer a different question -- *did a command fail?* --
        and the wait that uses this read would then report a target that is simply
        not ready yet as a target whose query could not be made.

        That is not hypothetical. This method shipped a `check=True` call whose
        docstring claimed the states came back as words, so `activating`, `inactive`
        and `failed` all raised, the `failed` branch in `wait_for_networkmanager_setup`
        was unreachable against a real target, and the budget message said "the last
        query failed" for a target that had merely not finished starting. The race
        itself was still closed -- a raised state is not `active`, so the wait kept
        going -- but the second terminal state and both refusal messages were not
        delivered. `SetupUnitStateTest` drives the real class against a fake that
        models the exit code, which is the only way that class of bug is visible in
        a suite: a fake that always exits 0 agrees with a wrapper that cannot read
        the state at all.

        Only the states systemd *means* are returned as words, and the
        discriminator is the **exit code**, not the output. Measured on a real
        24.04 target:

        ```text
        target-nm-setup.service   exit=0  stdout=active
        a unit that is not active  exit=3  stdout=<the state word>
        a unit that does not exist exit=4  stdout=inactive
        ```

        The last line is the one that matters: a **missing** unit prints
        `inactive`, the same word a unit that has not started yet prints, and only
        the exit code separates them. So exit 4 -- a target whose image has no such
        unit -- raises `PodmanUnitStateUnavailable`, which the wait treats as
        terminal rather than retrying: it will never become ready, and retrying it
        would spend the whole budget and then report a broken image as a slow
        target.
        """
        result = self.exec_container(container, "systemctl", "is-active", unit, check=False)
        word = (result.output or "").strip().splitlines()[-1].strip() if result.output.strip() else NM_SETUP_UNKNOWN
        if result.returncode not in (NM_IS_ACTIVE_EXIT_ACTIVE, NM_IS_ACTIVE_EXIT_STATE):
            raise PodmanUnitStateUnavailable(
                f"'systemctl is-active {unit}' in {container} exited {result.returncode}, which is "
                f"neither {NM_IS_ACTIVE_EXIT_ACTIVE} (the unit is active) nor "
                f"{NM_IS_ACTIVE_EXIT_STATE} (the unit is in a state systemd reports). It printed "
                f"{word!r}, and the most likely reason is that the target's image has no such "
                f"unit -- which is a broken image, not a target that is slow"
            )
        return word


def assert_networkmanager_manages_device(
    podman: Podman, container: str, device: str = NM_DEVICE
) -> str:
    """Fail unless NetworkManager manages `device` in a running target.

    This is the check the previous plan's largest SKIPPED list was built on the
    absence of. A target that boots with an unmanaged `eth0` produces a
    scenario failure that reads like an installer bug -- every DNS assertion
    downstream fails at once, and for a reason that has nothing to do with the
    package. So the harness asserts it before any scenario runs, and the
    refusal names the two steps that produce a managed device rather than
    saying "unmanaged" and leaving the reader to work it out.

    Returns the value the field held, which is `yes` on the only path that does
    not raise.
    """
    try:
        value = podman.nm_managed(container, device)
    except PodmanError as error:
        raise NetworkManagerDeviceError(
            f"NetworkManager device check failed in {container}: {error}\n"
            + _NM_MANAGE_STEPS_TEXT
            + NM_UNMANAGED_EXPLANATION
        ) from error
    if value != NM_MANAGED_YES:
        raise NetworkManagerDeviceError(
            f"NetworkManager does not manage {device} in {container}: "
            f"'nmcli -g {NM_MANAGED_FIELD} device show {device}' answered {value!r}, "
            f"not {NM_MANAGED_YES!r}\n"
            + _NM_MANAGE_STEPS_TEXT
            + NM_UNMANAGED_EXPLANATION
        )
    return value


# The two steps, formatted for a message. One place, because the wait below and
# the single-shot check above have to print the same thing: a reader who has
# been told one set of steps by the wait and a different one by a later check is
# being handed two claims about the same fix.
_NM_MANAGE_STEPS_TEXT = (
    f"Make the target manage {NM_DEVICE} before any scenario runs:\n"
    f"  1. {NM_MANAGE_STEPS[0]}\n"
    f"  2. {NM_MANAGE_STEPS[1]}\n"
)

# How long a target gets to finish booting before the managed-device check gives
# up, and how long to sit still between reads. A target's entrypoint has to
# `exec /sbin/init`, systemd has to reach multi-user, and
# `target-nm-setup.service` runs *after* NetworkManager -- and on 22.04 the
# managed state comes from the conf.d declaration, which NetworkManager reads
# when it starts. So the device is managed *after* the container is running, not
# when it is started, and the budget is for the boot rather than for DHCP.
NM_DEVICE_BOOT_TIMEOUT = 120.0
NM_DEVICE_POLL_INTERVAL = 5.0


def wait_for_networkmanager_device(
    podman: Podman,
    container: str,
    device: str = NM_DEVICE,
    *,
    timeout: float = NM_DEVICE_BOOT_TIMEOUT,
    interval: float = NM_DEVICE_POLL_INTERVAL,
    now=time.monotonic,
    sleep=time.sleep,
) -> str:
    """Wait for a booting target to bring NetworkManager up on `device`.

    **`podman run -d` returns long before the device is managed**, and a
    single-shot check is therefore a race that reports its own loss as a fact
    about the target. Measured on this host on the first live cell: the check
    ran about two seconds after `podman run -d` returned and `nmcli` answered

    ```text
    Error: Could not create NMClient object: Could not connect: No such file or directory
    ```

    which is *no NetworkManager yet*, and which the single-shot check reported
    with the same message it uses for "NetworkManager is running and refuses
    this device" -- the one message a reader must not be sent for a timing
    problem, because the two steps printed with it do not fix a container that
    has not booted.

    Bounded, and the failure carries the last value, the budget and the number of
    reads: a reader who sees `answered 'no'` and a reader who sees `answered
    'no' on 25 reads over 120s` know different things, and only the second knows
    the answer was not a race.

    **Do not give this the `check=False` treatment `setup_unit_state` needed.**
    The two look like the same shape -- "a read whose answer is not what we want"
    -- and they are opposites. `nmcli` exits non-zero when the *device is not
    there yet*, and for this wait that **is** "not yet": the field's whole
    contract is that the target is not ready, and an exception saying
    `Error: Could not create NMClient object: Could not connect` is the single most
    informative thing it can report about a target that has not finished booting.
    `setup_unit_state` is the opposite because `is-active`'s non-zero exits are
    *states* rather than failures, and it is the only read here where that is true.
    If you add a second `check=False`, check this first.
    """
    deadline = now() + timeout
    last_value: str | None = None
    last_error: str | None = None
    reads = 0
    while True:
        reads += 1
        try:
            last_value = podman.nm_managed(container, device)
            last_error = None
            if last_value == NM_MANAGED_YES:
                return last_value
        except PodmanError as error:
            last_error = str(error)
        if now() >= deadline:
            break
        sleep(interval)
    if last_error:
        seen = f"the last query failed: {last_error.splitlines()[-1]}"
    else:
        seen = (
            f"'nmcli -g {NM_MANAGED_FIELD} device show {device}' answered {last_value!r}, "
            f"not {NM_MANAGED_YES!r}"
        )
    raise NetworkManagerDeviceError(
        f"NetworkManager did not come up managing {device} in {container} after {timeout:g}s and "
        f"{reads} reads {interval:g}s apart: {seen}. A target that has not finished booting answers "
        f"the same way, and the steps below fix a device NetworkManager has *refused* -- so read "
        f"this as 'the target never managed its device' only after 'the target never booted' is "
        f"ruled out ('journalctl -b' and 'systemctl is-active NetworkManager' inside {container}).\n"
        + _NM_MANAGE_STEPS_TEXT
        + NM_UNMANAGED_EXPLANATION
    )


# The target's own setup budget. A healthy target reaches `active` in **two to
# three seconds** on every release measured (22.04 2s, 24.04 3s, 26.04 2s), so
# this is not a tight bound -- it is a bound. It matches the device wait's budget
# deliberately, so the two gates cannot disagree about how long a target is
# allowed to take, and a reader who reads one of the two messages is not left
# wondering whether the other is more patient.
NM_SETUP_BOOT_TIMEOUT = NM_DEVICE_BOOT_TIMEOUT
# **The same 5s as the device wait, and the argument is consistency rather than
# latency.** A 1s interval would notice a unit that finished at t=2s about three
# seconds sooner, which on a ~40s cell is not worth a second set of constants to
# explain; and the interval is not free, because each read is a `podman exec`
# subprocess. On a *virtual* clock -- which is how every case in `test_command.py`
# runs a cell -- a wait that can never succeed does not stop early: it runs the
# whole budget, so 120s/1s means 121 subprocess spawns in one case, and 120s/5s
# means 25. The interval is therefore also the suite's cost for exercising this
# gate's failure path, and 5s is the cheaper of the two by a factor of five.
NM_SETUP_POLL_INTERVAL = NM_DEVICE_POLL_INTERVAL


def wait_for_networkmanager_setup(
    podman: Podman,
    container: str,
    unit: str = NM_SETUP_UNIT,
    *,
    timeout: float = NM_SETUP_BOOT_TIMEOUT,
    interval: float = NM_SETUP_POLL_INTERVAL,
    now=time.monotonic,
    sleep=time.sleep,
) -> str:
    """Wait for the target image's NetworkManager setup unit to reach a terminal state.

    **This is a gate, not a check, and it is the first of two.** The cell waits
    here and *then* waits for `GENERAL.NM-MANAGED`, and the order is the whole
    point -- see `TargetReadinessTest` for the measurement. In one sentence: the
    field this harness used to gate on is produced by the unit this waits for, and
    the unit is still running when the field first reads `yes`.

    Two behaviours that are not decoration:

    * **`failed` stops the wait immediately.** It is a terminal state and it
      carries the setup script's own verdict, so waiting out the budget would
      report a target that has already said what was wrong as one that is merely
      slow. The message points at the unit's log rather than at the two
      NetworkManager steps, because the script's message is the specific one --
      it names whether the profile was missing, the device was not an ethernet
      one, or the `conf.d` declaration did not take effect.

    * **The failure names the last state it saw, and the budget.** A reader who
      sees `answered 'inactive'` and a reader who sees `answered 'inactive' on
      120 reads over 120.0s` know different things, and only the second knows the
      answer was not a race.

    Returns the terminal state, which is `NM_SETUP_ACTIVE` on the only path that
    does not raise.
    """
    deadline = now() + timeout
    last_state: str | None = None
    last_error: str | None = None
    reads = 0
    while True:
        reads += 1
        try:
            last_state = podman.setup_unit_state(container, unit)
            last_error = None
            if last_state == NM_SETUP_ACTIVE:
                return last_state
            if last_state == NM_SETUP_FAILED:
                raise NetworkManagerSetupError(
                    f"{unit} FAILED in {container} after {reads} reads {interval:g}s apart. The "
                    f"unit is Type=oneshot with the setup script's exit status as its verdict, so "
                    f"it has already said what went wrong and the harness is not going to wait "
                    f"for a second opinion: read its own log, which names which of the three it "
                    f"was.\n"
                    f"  journalctl -u {unit} -b            # inside {container}\n"
                    f"  systemctl show {unit}             # Result, and the exit code\n"
                    f"The unit creates the {NM_PROFILE_NAME} connection profile, and on releases "
                    f"with a persistent device override (measured boundary "
                    f"{'.'.join(str(part) for part in NM_OVERRIDE_MINIMUM)}; measured "
                    f"{', '.join(f'{v} -> {r}' for v, r in sorted(NM_OVERRIDE_MEASUREMENTS.items()))}) "
                    f"it also runs 'nmcli device set {NM_DEVICE} managed yes' and restarts "
                    f"NetworkManager -- which is why a scenario must not start before this unit is "
                    f"finished."
                )
        except NetworkManagerSetupError:
            raise
        except PodmanUnitStateUnavailable as unavailable:
            # **Terminal, on the first read.** A target whose image has no such
            # unit will not grow one, so retrying spends the budget and then
            # reports a broken image as a slow target. The `PodmanError` below
            # this one is the opposite case: a container that has not started yet
            # answers with a transport failure, and that *is* worth retrying.
            raise NetworkManagerSetupError(
                f"the setup unit could not be read in {container} after {reads} "
                f"read{'s' if reads != 1 else ''} {interval:g}s apart: {unavailable}. The gate is "
                f"not waiting for a slow target, it is reporting that there is no such unit to "
                f"wait for, so there is no budget to spend.\n"
                f"  podman exec {container} systemctl list-unit-files | grep nm-setup\n"
                f"  podman exec {container} ls -l /etc/systemd/system/{unit}\n"
            ) from unavailable
        except PodmanError as error:
            last_error = str(error)
        if now() >= deadline:
            break
        sleep(interval)
    if last_error:
        seen = f"the last query failed: {last_error.splitlines()[-1]}"
    else:
        seen = f"'systemctl is-active {unit}' answered {last_state!r}"
    raise NetworkManagerSetupError(
        f"{unit} did not reach {NM_SETUP_ACTIVE!r} in {container} after {timeout:g}s and {reads} "
        f"reads {interval:g}s apart: {seen}. That is the gate a target has to pass before any "
        f"scenario runs, and it is a *different* question from whether NetworkManager manages "
        f"{NM_DEVICE} -- the unit owns that field and is still holding it. A target that has not "
        f"finished booting answers the same way, and a target whose script refused exits "
        f"'failed' and is reported at once rather than after this budget.\n"
        f"  journalctl -u {unit} -b            # inside {container}: the script's own verdict\n"
        f"  systemctl is-active NetworkManager # the unit restarts it on 24.04 and 26.04\n"
        f"  nmcli -g {NM_MANAGED_FIELD} device show {NM_DEVICE}\n"
    )


# -- the lifecycle ------------------------------------------------------------

# Every resource this harness creates carries this prefix, and the run id that
# follows it. The prefix is what makes a sweep safe: it is a namespace, so a
# teardown can find what a run left behind without finding anything else.
RESOURCE_PREFIX = "mosdns"

# The plan's fixed private network. A bridge network, not Podman's default
# rootless one, because the default hands a container a tun/tap device that
# NetworkManager refuses by design.
DEFAULT_NETWORK_SUBNET = "10.89.0.0/24"


class CleanupFailed(PodmanError):
    """Teardown left something of this run behind.

    Carries the result so a caller can say which resource, rather than only
    that something did.
    """

    def __init__(self, result: "CleanupResult"):
        self.result = result
        super().__init__(
            "teardown left resources of this run behind: "
            + ", ".join(f"{kind} {name}" for kind, name in result.survivors)
            + "\nrun 'python3 tests/podman/run.py cleanup --run-id "
            + result.run_id
            + "' once the cause is cleared"
        )


@dataclass(frozen=True)
class TeardownError:
    """One teardown step that failed, kept even when nothing survived.

    Recorded rather than raised, because a step that failed and left nothing
    behind has done its job and a run that reports it as a failure teaches
    everybody to ignore leaks.
    """

    kind: str
    name: str
    message: str


@dataclass(frozen=True)
class CleanupResult:
    """What teardown did, what it could not do, and what is still there.

    `survivors` is a (kind, name) pair per resource rather than a bare name, so
    "a network survived" and "a container survived" are different problems and
    a reader of a failure is told which one they have.
    """

    run_id: str
    removed: tuple[str, ...] = ()
    errors: tuple[TeardownError, ...] = ()
    survivors: tuple[tuple[str, str], ...] = ()

    @property
    def ok(self) -> bool:
        """True when nothing of this run survives.

        Not "when nothing failed". The question a teardown has to answer is
        whether the machine is clean, and podman is asked directly rather than
        inferred from the harness's own bookkeeping.
        """
        return not self.survivors


def new_run_id(when: datetime | None = None) -> str:
    """A UTC run id, compact enough for a container name and sortable as text.

    The timestamp is UTC because the run id is also the result directory's name
    and the two have to agree in a log from a machine in another timezone.
    """
    moment = when or datetime.now(timezone.utc)
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y%m%dT%H%M%SZ")


class RunResources:
    """The resources one run owns, and their teardown.

    Naming is the whole mechanism: every container, network and volume carries
    this run's prefix, so `cleanup` can be both precise -- it removes what this
    run created and nothing else -- and complete, because it can also find a
    resource a scenario created without recording it.
    """

    def __init__(
        self,
        podman: Podman,
        run_id: str,
        network: str | None = None,
        scope: str | None = None,
    ):
        self.podman = podman
        self.run_id = run_id
        self.network = network
        # A run makes one network, but `run.py cleanup` sweeps the namespace
        # across every run this harness has made, so teardown takes a list.
        self.networks: list[str] = [network] if network else []
        # What this teardown is responsible for. It is this run's own prefix
        # for a run, and the whole `mosdns-` namespace for a sweep, so a bare
        # `run.py cleanup` clears every run and a session's teardown never
        # reaches a parallel one.
        self.scope = scope if scope is not None else (f"{RESOURCE_PREFIX}-{run_id}" if run_id else RESOURCE_PREFIX)
        self.containers: list[str] = []
        self.volumes: list[str] = []
        self.cleanup_result: CleanupResult | None = None

    @property
    def prefix(self) -> str:
        return f"{RESOURCE_PREFIX}-{self.run_id}"

    def container_name(self, role: str, version: str) -> str:
        return f"{self.prefix}-{role}-{version}"

    def volume_name(self, role: str) -> str:
        return f"{self.prefix}-{role}"

    def network_name(self, name: str) -> str:
        return f"{self.prefix}-{name}"

    def track_container(self, name: str) -> str:
        self.containers.append(name)
        return name

    def track_volume(self, name: str) -> str:
        self.volumes.append(name)
        return name

    def _attempt(self, kind: str, name: str, action) -> tuple[str | None, str | None]:
        """Run one teardown step, reporting rather than raising.

        A teardown that returns on the first failure strands everything after
        it: one stuck container would leave the network and the volumes behind
        too, and the next run would find a network it did not create.
        """
        try:
            action()
        except PodmanError as error:
            return None, f"{kind} {name}: {error}"
        return name, None

    def cleanup(self) -> CleanupResult:
        """Remove this run's resources and report what is still there.

        Containers, then the network, then volumes -- the order is required,
        not chosen: a container attached to a network cannot be removed after
        the network is gone.

        Each container is **stopped** before it is removed, and this is the
        correction of a claim the first report made: `podman rm -f` does not
        stop a container gracefully, it SIGKILLs it. A systemd target's units
        are then never shut down, its journal is truncated at the kill rather
        than closed, and `systemd-resolved`'s state is whatever the kernel left
        -- which is exactly the state the later tasks read out to decide
        whether the package's units behaved. `stop --time 30` gives the init the
        grace period to stop what it started, and it happens before the
        removal, which is the only order in which it means anything.
        """
        removed: list[str] = []
        errors: list[TeardownError] = []

        def shut_down(n: str) -> tuple[str | None, str | None]:
            """Stop a container, then remove it, reporting rather than raising."""
            self.podman.stop(n)
            return self.podman.remove_container(n)

        for name in list(self.containers):
            done, message = self._attempt("container", name, lambda n=name: shut_down(n))
            (removed.append(done) if done else errors.append(TeardownError("container", name, message)))
        # The sweep catches a container a scenario created without recording it.
        for name in self.podman.all_container_names(self.scope):
            if name in removed:
                continue
            done, message = self._attempt("container", name, lambda n=name: shut_down(n))
            (removed.append(done) if done else errors.append(TeardownError("container", name, message)))

        for name in list(self.networks):
            done, message = self._attempt("network", name, lambda n=name: self.podman.remove_network(n))
            (removed.append(done) if done else errors.append(TeardownError("network", name, message)))
        # And the same sweep for the networks. A network this run created and
        # did not record was previously *reported* and left behind, which is
        # the one thing a teardown must not do: the next run finds a network it
        # did not create, and `run.py cleanup` is the documented recovery for
        # exactly that situation. The containers and the volumes were swept
        # here already; a network was the odd one out.
        for name in self.podman.network_names(self.scope):
            if name in removed:
                continue
            done, message = self._attempt("network", name, lambda n=name: self.podman.remove_network(n))
            (removed.append(done) if done else errors.append(TeardownError("network", name, message)))

        for name in list(self.volumes):
            done, message = self._attempt("volume", name, lambda n=name: self.podman.remove_volume(n))
            (removed.append(done) if done else errors.append(TeardownError("volume", name, message)))
        for name in self.podman.all_volume_names(self.scope):
            if name in removed:
                continue
            done, message = self._attempt("volume", name, lambda n=name: self.podman.remove_volume(n))
            (removed.append(done) if done else errors.append(TeardownError("volume", name, message)))

        # The survivorship question, asked of podman rather than of this
        # bookkeeping: the harness may have forgotten a name, and podman cannot.
        # The prefix is the namespace this teardown is responsible for, which is
        # this run's own prefix for a run and the harness namespace for a sweep
        # across every run -- so a network or container from a parallel run is
        # not this teardown's business, and one from an earlier run is.
        survivors: list[tuple[str, str]] = [
            ("container", name) for name in self.podman.all_container_names(self.scope)
        ]
        survivors += [("volume", name) for name in self.podman.all_volume_names(self.scope)]
        survivors += [("network", name) for name in self.podman.network_names(self.scope)]
        for name in self.networks:
            if self.podman.network_exists(name):
                survivors.append(("network", name))

        result = CleanupResult(
            run_id=self.run_id,
            removed=tuple(removed),
            errors=tuple(errors),
            survivors=tuple(survivors),
        )
        self.cleanup_result = result
        return result


@contextlib.contextmanager
def podman_session(podman: Podman, run_id: str, network: str | None = None):
    """Run a body of scenarios, then tear the run down however the body ended.

    The teardown is in a `finally` because the shape that leaks is the obvious
    one: do the work, then remove the resources on the next line, which the
    exception skips. And a teardown failure is raised *only* when nothing else
    is propagating -- raising it over a scenario's own exception would replace
    the installer's error with "a container survived" and destroy the evidence
    for why the run failed. The result is attached to the run either way, so
    the leak is reported beside the failure rather than instead of it.
    """
    resources = RunResources(podman, run_id, network)
    try:
        yield resources
    finally:
        result = resources.cleanup()
        if not result.ok and sys.exc_info()[0] is None:
            raise CleanupFailed(result)
