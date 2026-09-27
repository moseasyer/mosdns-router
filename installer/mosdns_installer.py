#!/usr/bin/env python3
"""Check that this machine can have this router installed on it, and then do it.

The module has two halves and the line between them is the one that matters on a
router. Everything above :func:`install` reads and reports; everything in
:func:`install` changes a machine's DNS, in one fixed order, with a record of what
it found and a rollback for every step it takes. ``preflight`` is the half that
runs before the package owns anything, so it has exactly two jobs and the whole of
its design follows from them:

* **It reads, and it says.** Every check either establishes a fact or names a
  refusal, and a refusal carries the values it refused on. A preflight that
  printed a check name without the numbers behind it would leave an operator
  guessing, and one that quietly normalised the machine would turn a wrong machine
  into a right-looking install.

* **It never repairs.** A state directory in an unexpected shape belongs to
  whoever made it that way. Only ``postinst`` -- running as the package owner,
  inside the package's own lifecycle -- provisions, and it is the only thing that
  does. An installer that chowned a directory it had just refused is how a user's
  own state gets re-permissioned by a program that was only asked to look, and the
  two failures look identical from the outside.

Every command is an argument array handed to an injected runner, and never a
string. The runner is the whole injection boundary for this program, which is why
it is a parameter of :func:`preflight` rather than something the module builds: a
test can then see every command this module would run, and a string would be a
string a shell would have interpreted. There is no second code path -- no
``subprocess`` import, no ``os.system``, no backticks -- and a source scan in the
test suite holds that, because the FakeRunner refusing a string only covers the
paths a test happens to reach.

Nothing in that half is a network, a service or a file write. ``--check-only``
reads ``/etc/os-release``, asks four read-only questions of systemd and
NetworkManager, reads the state directories' metadata, and reports. If it cannot
answer a question it says so; it never answers "fine" from a failed read, because
the installer's next step binds a privileged port and a second answer that does
not exist is how two resolvers end up fighting over port 53.

:func:`install` is the other half, and its design is one sentence: **the
NetworkManager is touched last, after the machine's own resolver has answered a
real query.** Everything before that point is undone by stopping two units;
everything after it is undone from a record written before any of it, and a
failure anywhere leaves either a machine that is as it was found or a loud report
that says which of this package's changes are still applied. Read the numbered
order at the head of the transaction section before changing anything in it.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Callable, List, NamedTuple, Optional, Sequence

__all__ = [
    "Answer",
    "BACKUP_PATH",
    "BACKUP_SCHEMA_VERSION",
    "CommandRunner",
    "Completed",
    "Connection",
    "DISPATCHER_SCRIPT",
    "EXIT_INSTALL_FAILED",
    "EXIT_OK",
    "EXIT_OWNERSHIP_REFUSED",
    "EXIT_REFUSED",
    "EXIT_RESTORE_INCOMPLETE",
    "EXIT_ROLLBACK_FAILED",
    "EXIT_USAGE",
    "Holder",
    "InstallRefused",
    "InstallResult",
    "MANAGED_BY",
    "Owner",
    "Preflight",
    "RealCommandRunner",
    "RollbackFailure",
    "RollbackResult",
    "SCRUBBED_ENVIRONMENT_NAMES",
    "STATE_DIRECTORY",
    "Transaction",
    "UninstallResult",
    "build_dns_query",
    "capture_command",
    "check_architecture",
    "check_connection",
    "check_control_lock",
    "check_dependencies",
    "check_ech",
    "check_foreign_services",
    "check_ports",
    "check_release",
    "check_resolv_conf",
    "check_state_directories",
    "emergency_rollback",
    "install",
    "manual_recovery_report",
    "preflight",
    "prepare_backup",
    "probe_dns",
    "response_is_an_answer",
    "response_resolves",
    "uninstall",
    "validate_backup",
    "wait_for_dns",
    "write_backup",
    "main",
]


# The releases this package is built and reviewed for, and the only two
# architectures it ships. The version decides the systemd floor, the
# NetworkManager fields and the shipped unit syntax, and all three differ across
# the set, so an unrecognised one is refused before anything is provisioned
# rather than discovered at the first boot.
SUPPORTED_RELEASES = ("22.04", "24.04", "26.04")
SUPPORTED_ARCHITECTURES = ("amd64", "arm64")

# The state directories the package provisions, and what each has to hold.
#
# Three separate mechanisms, and none of them is visible in the mode alone.
#
# A file's group comes from the directory's setgid bit. A file's group
# *permissions* come from the directory's default ACL. And the group's ability to
# write the *directory* -- which it needs before it can create or replace
# anything in it -- comes from the access ACL, and that is the group's own field
# of the mode. So all three are read, and none is inferred: a directory at 2770
# with no default ACL passes every mode check and still produces a state file one
# identity creates that the other cannot write, and a directory whose *access*
# mask is r-x produces the same failure while the mode still reads 2770, because
# when an access ACL has a named entry the mode's group field is the mask.
#
# The mode is 2770 and not 2750 because the group has to be able to write. That
# was measured on the system-level test machine rather than assumed: a member of
# a root:mosdns directory's own group cannot create a file in it at 2750, at all,
# and can at 2770. 2750 was in the plan's table and in ruling 142, while the same
# plan's prose asked for "a group-writable setgid directory"; 2770 is that, and
# no mode reads 2750 while granting the group write, because the group field *is*
# the mask.
#
# The first entry is named on its own because it is the one an operator's data
# lives in and the one a `purge` removes; every other check here is about the
# whole set and this one is about a single path.
STATE_DIRECTORY = "/var/lib/mosdns"
STATE_DIRECTORIES = (
    STATE_DIRECTORY,
    STATE_DIRECTORY + "/runtime",
    STATE_DIRECTORY + "/lists",
    "/run/mosdns",
)
STATE_OWNER = "root"
STATE_GROUP = "mosdns"
# The one mode a state directory may have: the owner writes, the group writes --
# both service identities are in it and both write here -- the world gets
# nothing, and setgid is set so a new file takes this group rather than its
# creator's. The four are checked separately and reported separately, because an
# operator fixing one of them has to know which one is wrong.
STATE_MODE = "2770"
SETGID_BIT = 0o2000
# The permission the group needs, on the directory and in the default ACL a new
# file inherits. rwx rather than rw because the second identity has to be able to
# *replace* a state file and to acquire the lock, and both need to create and
# rename; the x on a file is a no-op, and on the directory it is what lets the
# group reach the names inside it.
STATE_GROUP_PERMISSIONS = "rwx"

# The control lock is created on first acquire by whichever of the two identities
# wins the race, at this mode. Its absence on a fresh machine is the normal state;
# its presence at any other mode or with any other ownership is a file this
# package did not create, and preflight reports it rather than re-creating it.
CONTROL_LOCK = "/var/lib/mosdns/runtime/control.lock"
LOCK_MODE = 0o640
LOCK_MODE_OCTAL = "640"

# The marker an installation of this package leaves. It is what tells a
# re-install -- an upgrade, where an already-active router is the expected state
# rather than a conflict -- apart from a foreign installation whose resolver is
# holding this machine's ports.
MANAGED_BY = "/var/lib/mosdns/installer/managed-by"
MANAGED_BY_VALUE = "mosdns-router"

# The two ports the router and the resolver will bind, and the ones a
# conflicting installation would already hold.
DNS_PORT = 53
RESOLVER_PORT = 15353
RESOLVER_UNIT = "dnscrypt-proxy.service"
ROUTER_UNIT = "mosdns-router.service"
# The three timers, named on their own because an uninstall stops them first and
# on their own: they are the only units that WRITE, so they are the reason a
# purge can be safe without taking the control lock. One list rather than two,
# because two lists of the same three names is one more thing to get out of step.
PROJECT_TIMERS = (
    "mosdns-cdn-optimizer.timer",
    "mosdns-cdn-health.timer",
    "mosdns-list-check.timer",
)
PROJECT_UNITS = (ROUTER_UNIT, RESOLVER_UNIT) + PROJECT_TIMERS
# The unit whose stub listener already holds port 53 on a stock Ubuntu, and the
# one the install keeps: resolved stays in front and forwards to the router, so
# its socket is not a conflict to be cleared first. It is named here because the
# port check has to be able to exempt it, and an exemption that cannot name the
# process holding the port is an exemption of the port.
RESOLVED_UNIT = "systemd-resolved.service"

# Firefox reads HTTPS RRs, and with them ECH, from 129. Below that a domain on
# the forced list is unreachable in it, which is a loss of protection in one
# browser rather than a broken install -- so it is reported and the install
# continues. The refusal is reserved for the case the operator asked for in a way
# this machine cannot deliver: strict ECH on a forced domain.
MINIMUM_ECH_FIREFOX = 129
FIREFOX_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
# The v4-mapped IPv6 spelling, anchored: `::ffff:` is the whole of the prefix and
# what follows has to be a dotted quad. Not a prefix test on the IPv6 side -- that
# is the bug this exists to be the opposite of -- because `::ffff:10.0.0.1` and
# `::ffff:127.0.0.1` are both mapped, and only one of them is loopback.
IPV4_MAPPED = re.compile(r"::ffff:((?:[0-9]{1,3}\.){3}[0-9]{1,3})\Z")

# The connection types that carry a machine's DNS. A VPN or a bridge with no
# device is neither the primary uplink this install rewrites nor a source of the
# lease the router follows, and a loopback device is never one.
PRIMARY_CONNECTION_TYPES = ("802-3-ethernet", "802-11-wireless", "ethernet", "wifi")

# The path systemd-resolved's stub is reached at, and the address that stub
# answers on. The installer replaces the stub, so a resolv.conf pointing anywhere
# else means something other than resolved is in charge of DNS today.
RESOLVED_STUB_PATH = "run/systemd/resolve/stub-resolv.conf"
RESOLVED_STUB_ADDRESS = "127.0.0.53"

# The operator's force-ECH list, and the one line in it that is prose. Both readers
# of this file are in the preflight half and both are here rather than down with
# the transaction: `check_ech` decides whether a forced domain under strict ECH can
# be delivered by the browser on this machine, and the install transaction's guard
# decides whether its own health check would be answered by the router instead of
# by a resolver. Two spellings of the path, or two readers of it, in a path that
# decides whether strict ECH is forced for a name, is the last place that should
# be able to drift.
FORCE_ECH_DOMAINS = "/etc/mosdns/force-ech-domains.txt"
FORCE_ECH_COMMENT = "#"

# The timeout for one read-only command. Every question here is a local query
# against a running manager, so a slow answer means a machine that is not in a
# state worth installing onto rather than a slow network.
COMMAND_TIMEOUT_SECONDS = 30


class Connection(NamedTuple):
    """The active connection the installer is about to rewrite.

    The uuid is the device's own, read from ``GENERAL.CON-UUID``, because that is
    the only field that carries one: ``GENERAL.CONNECTION`` holds the profile's
    *name*, and ``device show`` does not offer ``GENERAL.CONNECTION-UUID`` at all.
    A lookup naming either would record a name where the DHCP state wants a
    canonical UUID, which the publisher then refuses -- so every install would
    exit 2 on its first capture.
    """

    name: str
    uuid: str
    kind: str
    device: str


class Preflight:
    """What the checks found: the facts, the refusals, and the notes.

    ``problems`` are the refusals that stop an install. ``notes`` are facts an
    operator needs and that do not stop anything -- a browser too old for ECH, a
    port free at the moment it was looked at. They are separate because a preflight
    that reported a working install and a broken one in the same list would be a
    list nobody reads.
    """

    def __init__(self) -> None:
        self.release: Optional[str] = None
        self.architecture: Optional[str] = None
        self.connection: Optional[Connection] = None
        self.firefox: Optional[str] = None
        self._problems: List[str] = []
        self._notes: List[str] = []
        self._occupied_ports: List[int] = []
        self._ech_available = False

    def problems(self) -> List[str]:
        """The refusals, in the order the checks ran."""
        return list(self._problems)

    def notes(self) -> List[str]:
        """The facts that do not stop an install."""
        return list(self._notes)

    def occupied_ports(self) -> List[int]:
        """The ports something was listening on when the check looked."""
        return list(self._occupied_ports)

    def ech_available(self) -> bool:
        """Whether a browser on this machine can use ECH at all."""
        return self._ech_available

    @property
    def ok(self) -> bool:
        return not self._problems

    def refuse(self, message: str) -> None:
        self._problems.append(message)

    def note(self, message: str) -> None:
        self._notes.append(message)

    def mark_occupied(self, port: int) -> None:
        """Record a port the port check found bound, for the report to quote.

        The check records rather than only refusing, because "port 53 is taken"
        is a fact an operator will ask about again after fixing whatever held it,
        and a refusal that has to be re-derived from a second run of the program
        is one more run of the program.
        """
        self._occupied_ports.append(port)

    def mark_ech_available(self) -> None:
        """Record that the browser on this machine can read an HTTPS RR."""
        self._ech_available = True


class CommandRunner:
    """The boundary every command in this module crosses.

    A real one runs an argument array; a test's records it and answers what it
    prepared. The interface is a class rather than a Protocol so the production
    runner is here to be read, and so the type of ``run`` is a name somebody
    looked at.
    """

    def run(self, args: Sequence[str], check: bool = True) -> "Completed":
        raise NotImplementedError


class Completed(NamedTuple):
    """What a command produced: its status, its standard output, its errors."""

    returncode: int
    stdout: str
    stderr: str


class RealCommandRunner(CommandRunner):
    """Runs one read-only command and returns what it printed.

    This is the one place in the module that starts a process, and it is the whole
    of what "reaching a real host command" means. The command is an argument array
    passed through ``list(args)`` and never a string, and there is no ``shell=``
    anywhere, so a connection name, an interface or a path that reaches here cannot
    be reinterpreted as anything else. That matters more here than anywhere else in
    the project: this program runs as root on somebody's machine, so an
    interpolated path in a command would be a shell injection rather than a test
    failure, and the test suite's source scan holds the rule for the paths no test
    reaches.

    ``import subprocess`` is inside the method rather than at module scope so that
    importing this module starts nothing and reads nothing. A module that
    imported its process boundary at load time would make every test that imports
    it a test of that import.
    """

    def run(self, args: Sequence[str], check: bool = True) -> Completed:
        import subprocess

        command = list(args)
        try:
            completed = subprocess.run(
                command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            # A command that did not answer is a failed read, not a crash. Every
            # caller here turns a failed read into a refusal, which is the right
            # answer to a question that could not be asked -- and nmcli and
            # systemctl both block on D-Bus, so a manager that has stopped
            # answering is one of the states this program exists to report. Left
            # unhandled it would be worse than a traceback: an uncaught exception
            # exits 1, the same status as a refusal, so a script would read a
            # failure to give a verdict as the verdict itself.
            return Completed(
                124,
                "",
                f"{command[0]} did not answer within {COMMAND_TIMEOUT_SECONDS}s",
            )
        if check and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode, command, completed.stdout, completed.stderr
            )
        return Completed(completed.returncode, completed.stdout, completed.stderr)


def _ok(runner: CommandRunner, args: Sequence[str]) -> Optional[Completed]:
    """Run a read-only command, answering ``None`` when it could not be read.

    A failed read is never an empty answer. Every caller distinguishes the two,
    because a check that concluded "nothing is wrong" from a command that did not
    run would send the install on to bind a port it has not established is free.
    """
    try:
        completed = runner.run(list(args), check=False)
    except (OSError, ValueError):
        return None
    if completed.returncode != 0:
        return None
    return completed


def parse_os_release(contents: str) -> dict:
    """Parse an ``/etc/os-release`` document into its keys.

    The format is shell-like ``KEY=VALUE`` with optional quoting, and this reads
    it rather than guessing at the two keys it needs with a regular expression: a
    file this cannot parse is a machine whose identity is unknown, and the right
    answer to that is a refusal rather than a best effort.
    """
    fields = {}
    for line in contents.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, value = stripped.partition("=")
        if not separator or not key.strip():
            raise ValueError(f"a line of /etc/os-release is not KEY=VALUE: {line!r}")
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"/etc/os-release has a key that is not a shell identifier: {key!r}")
        fields[key] = _unquote(value.strip(), key)
    return fields


def _unquote(value: str, key: str) -> str:
    """Remove the quoting ``/etc/os-release`` allows, refusing anything else."""
    if len(value) >= 2 and value[0] == value[-1] == "'":
        # Single quotes are literal in the format; nothing inside is an escape.
        return value[1:-1]
    if len(value) >= 2 and value[0] == value[-1] == '"':
        body = value[1:-1]
        for escape in ('\\"', "\\\\", "\\$", "\\`"):
            body = body.replace(escape, escape[1])
        if "\\" in body:
            raise ValueError(f"/etc/os-release has an unsupported escape in {key}")
        return body
    if '"' in value or "'" in value:
        raise ValueError(f"/etc/os-release has a mismatched quote in {key}: {value!r}")
    return value


def check_release(root: Path, run: CommandRunner, report: Preflight) -> None:
    """Accept the three supported Ubuntu releases and refuse everything else."""
    path = root / "etc" / "os-release"
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        report.refuse(
            f"{path} could not be read ({error}); this package is only supported on Ubuntu "
            f"{', '.join(SUPPORTED_RELEASES)} and the machine's identity cannot be established"
        )
        return
    try:
        fields = parse_os_release(contents)
    except ValueError as error:
        report.refuse(f"{path} is not a readable os-release document: {error}")
        return
    identifier = fields.get("ID", "")
    version = fields.get("VERSION_ID", "")
    if identifier != "ubuntu":
        report.refuse(
            f"{path} names ID={identifier or '(none)'!r}; this package is only supported on "
            f"Ubuntu {', '.join(SUPPORTED_RELEASES)}, and a derivative shares the resolver "
            "stack without sharing the stub layout or the support commitment"
        )
        return
    if version not in SUPPORTED_RELEASES:
        report.refuse(
            f"{path} names VERSION_ID={version or '(none)'!r}; this package is supported on "
            f"Ubuntu {', '.join(SUPPORTED_RELEASES)}, and the version decides the systemd "
            "floor, the NetworkManager fields and the shipped unit syntax"
        )
        return
    report.release = version


def check_architecture(run: CommandRunner, report: Preflight) -> None:
    """Accept the two architectures this package ships, and no others."""
    completed = _ok(run, ("dpkg", "--print-architecture"))
    if completed is None:
        report.refuse(
            "the machine's architecture could not be read with `dpkg --print-architecture`; "
            f"this package ships {', '.join(SUPPORTED_ARCHITECTURES)} and an unreadable "
            "architecture is not one of them"
        )
        return
    architecture = completed.stdout.strip()
    report.architecture = architecture
    if architecture not in SUPPORTED_ARCHITECTURES:
        report.refuse(
            f"the machine's architecture is {architecture or '(none)'!r}; this package ships "
            f"{', '.join(SUPPORTED_ARCHITECTURES)} and no package is built for anything else"
        )


def check_dependencies(run: CommandRunner, report: Preflight) -> None:
    """Require systemd, NetworkManager and a running systemd-resolved.

    Each is named on its own refusal. They have different remedies -- install a
    package, enable a service, look at a failed unit -- and "a dependency is
    missing" tells an operator none of them.

    systemd-resolved has to be *running*, not merely installed. An installed and
    stopped resolved is the state where ``/etc/resolv.conf`` names a stub nothing
    is listening on, and rewriting DNS on top of it leaves the machine with no
    resolver at all.
    """
    version = _ok(run, ("systemctl", "--version"))
    if version is None:
        report.refuse(
            "systemd is not present or not runnable (`systemctl --version` failed); this "
            "package installs systemd units, so a machine without systemd cannot run it"
        )
    for unit, name in (
        ("NetworkManager.service", "NetworkManager"),
        ("systemd-resolved.service", "systemd-resolved"),
    ):
        state = _ok(run, ("systemctl", "is-active", unit))
        if state is None:
            report.refuse(
                f"{name} could not be asked about (`systemctl is-active {unit}` failed); this "
                "package rewrites NetworkManager's DNS and installs a resolved stub, so a "
                "machine whose managers cannot be read is not one to install onto"
            )
            continue
        if state.stdout.strip() != "active":
            report.refuse(
                f"{name} is {state.stdout.strip() or 'not active'!r}, not active; this package "
                "rewrites the DNS NetworkManager hands the resolver and replaces the "
                "systemd-resolved stub, and neither is in place while it is stopped"
            )


def check_resolv_conf(root: Path, report: Preflight) -> None:
    """Require ``/etc/resolv.conf`` to name systemd-resolved's stub.

    The installer takes DNS over from whatever is answering, so it has to know
    what is answering today. A ``resolv.conf`` pointing at a DHCP nameserver, a
    public resolver or a hand-written file means something other than resolved is in
    charge, and taking over from it is not what this package was written to do --
    which is why the refusal says so rather than only naming the address.
    """
    path = root / "etc" / "resolv.conf"
    if path.is_symlink():
        target = os.readlink(path)
        if RESOLVED_STUB_PATH in target.replace("\\", "/"):
            return
        report.refuse(
            f"{path} is a symlink to {target!r}, not to resolved's stub "
            "(/run/systemd/resolve/stub-resolv.conf); something other than "
            f"systemd-resolved is in charge of DNS on this machine, and this package "
            f"replaces the {RESOLVED_STUB_ADDRESS} stub rather than whatever is there"
        )
        return
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        report.refuse(
            f"{path} could not be read ({error}); this package needs to know what is "
            "answering DNS before it replaces it"
        )
        return
    nameservers = [
        line.split("#", 1)[0].split()[1]
        for line in contents.splitlines()
        if line.split("#", 1)[0].split()[:1] == ["nameserver"]
    ]
    if not nameservers:
        report.refuse(
            f"{path} names no nameserver at all; a machine with nothing answering DNS is "
            "not one this package can take over from"
        )
        return
    if nameservers != [RESOLVED_STUB_ADDRESS]:
        report.refuse(
            f"{path} names {', '.join(nameservers)} rather than the "
            f"{RESOLVED_STUB_ADDRESS} systemd-resolved stub; something other than "
            "systemd-resolved is in charge of DNS on this machine, and this package "
            "replaces the stub rather than whatever is there"
        )


def _unescape_terminfo(field: str) -> str:
    """Undo nmcli's terse escaping, where a colon inside a value is backslashed."""
    return re.sub(r"\\(.)", r"\1", field)


def _parse_terminfo_row(line: str) -> Optional[Connection]:
    """One row of ``nmcli -t`` output, or ``None`` for a line that is not one."""
    if not line.strip():
        return None
    fields = [_unescape_terminfo(field) for field in line.split(":")]
    if len(fields) < 4:
        return None
    name, uuid, kind, device = fields[0], fields[1], fields[2], fields[3]
    if not device or device == "lo":
        return None
    if kind not in PRIMARY_CONNECTION_TYPES:
        return None
    return Connection(name=name, uuid=uuid, kind=kind, device=device)


def check_connection(run: CommandRunner, report: Preflight) -> None:
    """Find the active wired or wireless connection and its device's UUID.

    Two questions, two argument arrays, and the second is the one with teeth:
    ``GENERAL.CONNECTION`` holds the connection's *name*, and ``device show`` does
    not offer ``GENERAL.CONNECTION-UUID`` at all. The UUID therefore comes from
    ``GENERAL.CON-UUID``, which is the only field that carries one, and the
    device's own answer is compared with the connection table's rather than
    trusted -- a disagreement means the machine changed under the read, and
    modifying a UUID from one of them would be modifying a connection the other
    does not name.
    """
    table = _ok(run, ("nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active"))
    if table is None:
        report.refuse(
            "the active NetworkManager connections could not be read (`nmcli -t -f "
            "NAME,UUID,TYPE,DEVICE connection show --active` failed); this package rewrites "
            "one connection's DNS and cannot choose which without the list"
        )
        return
    primary: Optional[Connection] = None
    for line in table.stdout.splitlines():
        connection = _parse_terminfo_row(line)
        if connection is not None and (primary is None or connection.device < primary.device):
            # Lowest device name, so a machine with two uplinks gets a
            # deterministic answer rather than whatever order nmcli happened to
            # print them in.
            primary = connection
    if primary is None:
        report.refuse(
            "no active wired or wireless connection with a device was found; this package "
            "rewrites a connection's DNS and captures the lease on its device, and a machine "
            "with neither has nothing to route through"
        )
        return
    device_uuid = _ok(run, ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", primary.device))
    if device_uuid is None:
        report.refuse(
            f"the connection UUID of {primary.device} could not be read (`nmcli -g "
            f"GENERAL.CON-UUID device show {primary.device}` failed); this package modifies a "
            "connection by UUID and the DHCP state records one, so a UUID it cannot read is a "
            "UUID it cannot safely use"
        )
        return
    found = device_uuid.stdout.strip()
    if not found:
        report.refuse(
            f"{primary.device} reports no connection UUID, so it is not attached to a "
            f"connection this package could rewrite (the table named {primary.name!r})"
        )
        return
    if found != primary.uuid:
        report.refuse(
            f"{primary.device} reports connection UUID {found} while the connection table "
            f"names {primary.uuid} for it; the machine changed under the read, and modifying "
            "one of them would be modifying a connection the other does not name"
        )
        return
    report.connection = Connection(name=primary.name, uuid=found, kind=primary.kind, device=primary.device)


class Owner(NamedTuple):
    """One process holding a socket, as `ss` reports it."""

    name: str
    pid: Optional[int]


class Holder(NamedTuple):
    """One listening socket, and whoever `ss` says is holding it."""

    protocol: str
    address: str
    port: int
    owners: List[Owner]


def _holders(listeners: str) -> List[Holder]:
    """The listening sockets in `ss -H -lntup` output, one Holder per line.

    The local address is found by looking for the first field that ends in a
    numeric port rather than by counting columns, because the count is not stable:
    `ss` prints Netid, State, Recv-Q, Send-Q, Local, Peer and -- only with -p --
    the process, and a version that adds or drops a column moves every index after
    it. Counting is also how the last version of this check ended up reading the
    send-queue length as an address: `ss` pads its columns to the terminal width,
    so a hand-written fixture can agree with an off-by-one parser and both look
    right.

    A scope suffix is stripped (`127.0.0.53%lo:53`) because which interface a
    loopback socket is bound to is not what this check decides. `ss` names every
    process sharing a socket, so all of them are kept: a socket that resolved holds
    alongside a foreign process is not resolved's alone. A line with no process
    column at all keeps no owners, which is what `ss` prints for a socket this user
    may not read -- a holder nobody can name is a holder nobody can clear.
    """
    holders = []
    for line in listeners.splitlines():
        fields = line.split()
        address = None
        port_number = 0
        for field in fields:
            head, separator, port = field.rpartition(":")
            if separator and port.isdigit() and head:
                address, port_number = head, int(port)
                break
        if address is None:
            continue
        owners = []
        for field in fields:
            if not field.startswith("users:(("):
                continue
            owners = [
                Owner(name, int(number))
                for name, number in re.findall(r'\("([^"]+)",pid=(\d+)', field)
            ]
            break
        holders.append(
            Holder(
                protocol=fields[0] if fields else "",
                address=address.split("%", 1)[0],
                port=port_number,
                owners=owners,
            )
        )
    return holders


def _is_loopback(address: str) -> bool:
    """Whether an address is one of the loopback range, in either family.

    Two spellings of the same question: `127.0.0.1` and `[::1]`. Anything that is
    not loopback is not resolved's stub, whatever the owning process is.

    The IPv6 answer is an equality and not a prefix, because `::1` is the whole of
    IPv6 loopback -- `::2` and up are reserved, not loopback. A prefix test says
    `yes` to `::10.0.0.1` and to `::1abc`, and the direction it is wrong in is the
    permissive one: the address exists so that a listener on something routable is
    refused, so a test that admits a global address waves through the case the
    address was added to catch.

    A v4-mapped address is the IPv4 address in the other spelling, so it is asked
    the same question: `::ffff:127.0.0.1` is the loopback address and is exempt,
    and `::ffff:10.0.0.1` is a global address and is not, which falls out of
    unwrapping it rather than out of a rule of its own.
    """
    bare = address.strip("[]")
    if bare == "::1":
        return True
    mapped = IPV4_MAPPED.match(bare)
    if mapped is not None:
        bare = mapped.group(1)
    parts = bare.split(".")
    return len(parts) == 4 and parts[0] == "127" and all(part.isdigit() for part in parts)


def _main_pid_of(run: CommandRunner, unit: str) -> Optional[int]:
    """The main process id of a unit, or ``None`` when it has none.

    `systemctl show -p MainPID --value` answers 0 for a unit that is not running
    and for one that does not exist, both with status 0, so 0 is the answer that
    matches no process at all and a unit that could not be asked about is treated
    the same way: a holder this check cannot attribute to a unit is a holder it
    does not exempt.
    """
    completed = _ok(run, ("systemctl", "show", "-p", "MainPID", "--value", unit))
    if completed is None:
        return None
    value = completed.stdout.strip()
    if not value.isdigit() or int(value) == 0:
        return None
    return int(value)


def _owner_is_exempt(owner: Owner, address: str, resolved_pid: Optional[int], own_pids: dict) -> bool:
    """Whether this one process is one of the two the install expects to find.

    A pid `ss` could not read is not exempt: the question could not be asked, and
    preflight's rule is that an unanswered question is a refusal.
    """
    if owner.pid is None:
        return False
    if resolved_pid is not None and owner.pid == resolved_pid and _is_loopback(address):
        return True
    return owner.pid in own_pids


def _is_exempt(holder: Holder, resolved_pid: Optional[int], own_pids: dict) -> bool:
    """Whether a holder is one this install expects to find already there.

    Two exemptions and nothing else. systemd-resolved's stub, because the design
    keeps resolved in front of the router and its socket on port 53 is the machine
    working; and a unit of this package's own, because the port check must not be
    the thing that fails an upgrade.

    Both are matched on the owning process and not on the port, and the resolved
    one is matched on the address as well: a foreign process that has taken
    127.0.0.53 is two answers for one query, and the port being the right number
    is not a reason to let it stand. The second exemption is gated on the ownership
    marker, which is the same claim check_foreign_services makes -- a
    mosdns-router process this install did not start is a foreign installation
    whatever it is called.

    EVERY owner has to be exempt, and that is the whole of the rule. `ss` prints
    one line per socket and names every process holding it in a single
    `users:((...),(...))` field, so a socket this install may bind can arrive with
    a foreign process on it beside resolved -- or beside this package's own router
    -- and answering for its share of the queries on the way in. A guard that asked
    "is any owner exempt" would wave that through, and the answer it gives is
    indistinguishable from the answer for a socket nobody else holds. This package's
    own router sharing a descriptor with a foreign process is the same shape, and
    the same refusal: the exemption is about who holds the socket, not about
    whether one of them is familiar. It needs no cooperation from the foreign
    process to arise -- a child that inherits a listening fd is named on the same
    line as its parent -- and unlike two sockets on 127.0.0.53 it is not something
    the operator had to ask for.

    A socket with no identifiable owner is not exempt either: that is a holder
    nobody can name, and so nobody can clear.
    """
    if not holder.owners:
        return False
    return all(
        _owner_is_exempt(owner, holder.address, resolved_pid, own_pids) for owner in holder.owners
    )


def _describe_owners(holder: Holder) -> str:
    """The processes holding a socket, in a form an operator can act on."""
    if not holder.owners:
        return "a process this user is not allowed to name"
    return " and ".join(
        f"{owner.name} (pid {owner.pid})" if owner.pid is not None else owner.name
        for owner in holder.owners
    )


def check_ports(root: Path, run: CommandRunner, report: Preflight) -> None:
    """Refuse a DNS or resolver port held by anything this install does not own.

    The refusal is not a reservation and the note says so. Between this check and
    the bind, anything may take either port, and the installer's own service will
    hold 53 afterwards by design -- so an operator reading "free" is reading a
    fact about the moment it was looked at, not a claim the install holds it.

    A stock Ubuntu already holds port 53: resolved's stub listener, which this
    install keeps and which is exempted by owning process rather than by port.
    Every other holder of either port is refused, and the refusal names the
    process, because "port 53 is taken" sends an operator hunting when the answer
    is one `ss` away.
    """
    completed = _ok(run, ("ss", "-H", "-lntup"))
    if completed is None:
        report.refuse(
            "the machine's listening sockets could not be read (`ss -H -lntup` failed); an "
            "unreadable answer is not an empty one, and binding a port whose state is "
            "unknown is how two resolvers end up fighting over it"
        )
        return
    interesting = {DNS_PORT, RESOLVER_PORT}
    claimed = [holder for holder in _holders(completed.stdout) if holder.port in interesting]
    resolved_pid = _main_pid_of(run, RESOLVED_UNIT)
    own_pids = {}
    if _installation_is_ours(root):
        for unit in (ROUTER_UNIT, RESOLVER_UNIT):
            pid = _main_pid_of(run, unit)
            if pid is not None:
                own_pids[pid] = unit
    occupied = set()
    for holder in claimed:
        if _is_exempt(holder, resolved_pid, own_pids):
            continue
        holder_of = "the router" if holder.port == DNS_PORT else "the resolver"
        report.refuse(
            f"{holder.protocol} port {holder.port} is already held on {holder.address} by "
            f"{_describe_owners(holder)}, and it is the port {holder_of} needs; this package "
            "keeps only resolved's own stub listener and its own units on these ports, and it "
            "will not take DNS over from a service it did not install"
        )
        occupied.add(holder.port)
    for port in sorted(occupied):
        report.mark_occupied(port)
    report.note(
        f"the port check is a reading of this moment, not a reservation: {DNS_PORT} and "
        f"{RESOLVER_PORT} were checked when it ran, anything may take either before the bind, "
        "and this package's own router holds 53 afterwards"
    )


def _installation_is_ours(root: Path) -> bool:
    """Whether the ownership marker names this package.

    One function for two checks that must agree. The foreign-service check and
    the port check both decide "is this process one of ours", and if they read the
    marker differently -- one on the unit's state and one on the file's
    contents -- then a machine can pass one and fail the other, and the operator
    is left with a refusal that no fact on the machine supports.
    """
    try:
        return (root / MANAGED_BY.lstrip("/")).read_text(encoding="utf-8").strip() == MANAGED_BY_VALUE
    except (OSError, UnicodeDecodeError):
        return False


def check_foreign_services(run: CommandRunner, root: Path, report: Preflight) -> None:
    """Refuse a resolver or a router this package did not install, already active.

    The ownership marker is what tells an upgrade from a conflict. Re-running the
    installer on a machine this package already installed finds a router already
    active, and that is the expected state; a unit that is active with no marker
    is a different installation, and only its owner can say whether it is safe to
    take DNS over from. A timer counts the same way: a second optimizer would
    measure and publish against a selector this install is about to replace.
    """
    owned = _installation_is_ours(root)
    for unit in PROJECT_UNITS:
        state = _ok(run, ("systemctl", "is-active", unit))
        if state is None or state.stdout.strip() != "active":
            continue
        if owned:
            report.note(
                f"{unit} is active and {MANAGED_BY} names this package, so this is a "
                "re-install of a machine this package already runs on"
            )
            continue
        report.refuse(
            f"{unit} is already active and {MANAGED_BY} does not name this package, so it "
            "belongs to an installation this one did not make; two resolvers or two routers "
            "holding the same ports produce two answers rather than one"
        )


def _firefox_major(version: str) -> Optional[int]:
    """The major version in ``firefox --version`` output, or ``None``."""
    match = FIREFOX_VERSION.search(version)
    if match is None:
        return None
    return int(match.group(1))


def _forced_ech_domains(root: Path) -> List[str]:
    """The names on the operator's force-ECH list, as the router's own reader sees them.

    ONE definition for TWO callers, and the reason is that they must not be able to
    drift. `check_ech` reads this list to decide whether a forced domain under
    strict ECH can be delivered by the browser on this machine, and the install
    transaction's guard reads it to decide whether its own health check would be
    answered by the router instead of by a resolver. A second copy of this read
    would mean a change to one silently changes the other, in a path that decides
    whether strict ECH is forced for a name -- a censorship-resistance path, which
    is the last place two readings of one operator file should be able to disagree.

    What it mirrors, and what re-deriving it would cost:

    * the file, `FORCE_ECH_DOMAINS` above, which is the path the router's unit and
      `cmd/mosdns-cdnctl`'s default both use;
    * the rule, `internal/statewatch.NewTrimmedLines` (see `text.go:31-56`): a
      trimmed line that starts with a comment marker is prose, a blank line is
      nothing, and everything else is an entry kept verbatim. A `#` anywhere but
      the start is a malformed entry rather than a comment, because a list that
      guessed which lines were annotated would be guessing about a
      censorship-resistance setting;
    * the match, `cdn_rewrite.forcesECH` (`cdn_rewrite.go:799-810`), which
      compares each entry to the canonical name with `strings.EqualFold` -- see
      :func:`_forces_ech`.

    A list that cannot be read is an empty one, and that is the direction this
    guess is made in on purpose: the router's own watcher refuses a list it cannot
    parse and keeps the LAST GOOD one, which this installer cannot see from here.

    Two places this mirror is not faithful, named here because the report is the
    slower reader and because both fail in the direction that lets an install
    proceed:

    * an entry written with a trailing dot (`install-probe.example.`) is treated
      here as a match and refuses, while `text.go:230` refuses the WHOLE file for a
      trailing dot -- so the router would keep its last good list and not force
      anything. The mirror is stricter than the router, which costs a needless
      refusal and not a false pass;
    * a malformed line makes the watcher keep its last good list, which could still
      contain the probe name, while this reader keeps the malformed line as an
      entry and finds no match in it. The precondition is that the operator
      previously listed the probe's name by hand and has since broken the file, so
      the router is still forcing and this guard is silent.

    Neither is fixed here. Both would need this installer to reproduce the
    watcher's whole validation -- length, label count, punycode, trailing dot,
    address-shaped lines -- and a partial reproduction is the failure mode that
    produced both of them.
    """
    try:
        contents = (root / FORCE_ECH_DOMAINS.lstrip("/")).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    entries = []
    for line in contents.splitlines():
        entry = line.strip()
        if not entry or entry.startswith(FORCE_ECH_COMMENT):
            continue
        entries.append(entry)
    return entries


def _ech_is_strict(root: Path) -> Optional[bool]:
    """Whether the installed policy asks for strict ECH, or ``None`` if it cannot say.

    A policy that cannot be read is not a strict one. The install renders the
    document itself, and refusing here would stop an install because a file has
    not been written yet -- which is the normal state before the first run.

    **This is the module's one documented fail-open, and it makes the strict-ECH
    refusal below unreachable on a fresh installation.** A policy file that is
    absent, that has no ``ech:`` section, or whose ``ech:`` block this cannot parse
    all answer the same way: not strict. The install renders ``policy.yaml`` itself
    from a template, so on a machine this package has not run on yet there is no
    policy to read, and the browser-too-old refusal that exists to stop an operator
    installing a configuration this machine cannot deliver will not fire. An
    operator who has written a strict policy with a forced domain, on a machine
    with Firefox below 129, is refused; an operator who has written the same
    policy and then had a typo in it is not.

    It is a fail-open on purpose, for the reason in the first paragraph, and it is
    recorded here and in the plan rather than left as an omission. The narrow fix
    would be to treat an unparseable policy as a refusal while still treating an
    absent one as the fresh-install state, which is a different rule from this one
    and a ruling rather than a fix; and the whole check is better than nothing for
    the case that matters, which is the operator who configured strict ECH on a
    machine that cannot deliver it.
    """
    try:
        contents = (root / "etc/mosdns/policy.yaml").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    section = re.search(r"^ech:\s*$(.*?)(?=^\S|\Z)", contents, flags=re.MULTILINE | re.DOTALL)
    if section is None:
        return None
    enabled = re.search(r"^\s+enabled:\s*(\S+)\s*$", section.group(1), flags=re.MULTILINE)
    policy = re.search(r"^\s+failure_policy:\s*(\S+)\s*$", section.group(1), flags=re.MULTILINE)
    if enabled is not None and enabled.group(1) == "false":
        return False
    if policy is None:
        return None
    return policy.group(1).strip('"') == "strict"


def check_ech(run: CommandRunner, root: Path, report: Preflight) -> None:
    """Report what ECH this machine can do, and refuse only what it cannot deliver.

    Firefox reads HTTPS RRs, and with them ECH, from 129. Below that, a domain on
    the operator's forced list is unreachable *in that browser* -- a loss of
    protection in one program, not a broken install, so it is a note.

    The refusal is the case where the operator asked for something this machine
    cannot provide: strict ECH on a forced domain, with a browser that cannot do
    ECH. Under strict the router synthesizes an empty A/AAAA and an HTTPS RR
    carrying ECH, and a client that cannot read it gets nothing at all, so the
    domain is unreachable rather than merely unprotected. Fallback is the same
    request with a working answer for such a client, and a policy with ECH off
    does not ask for anything, so neither is refused.

    Read :func:`_ech_is_strict` for why that refusal does not fire on a fresh
    installation, where there is no policy file yet.
    """
    domains = _forced_ech_domains(root)
    strict = _ech_is_strict(root)

    # The browser is read BEFORE the fail-open note is written, and the order is
    # the fix rather than a style. That note used to carry the clause "a browser
    # below 129 cannot deliver ECH" and was written first, so it described a
    # browser nobody had asked about yet: on a machine with Firefox 130 the report
    # asserted that a browser below 129 could not deliver ECH, when the only
    # browser it has is not below 129. A note whose whole job is to say what was
    # not checked cannot assert a fact about the machine it did not read. So the
    # version comes first and the clause is derived from it.
    completed = _ok(run, ("firefox", "--version"))
    if completed is None:
        version, major = None, None
        report.note(
            "no Firefox was found on this machine, so nothing here can use ECH; the router "
            "still serves every other query, and a client on another machine is unaffected"
        )
    else:
        version = completed.stdout.strip()
        major = _firefox_major(version)
        report.firefox = version
        if major is None:
            report.note(
                f"Firefox reported {version!r}, whose version could not be read, so ECH "
                "availability is unknown"
            )
        elif major >= MINIMUM_ECH_FIREFOX:
            report.mark_ech_available()

    if strict is None and domains:
        # The one fail-open in this module, named in the report rather than left
        # to be discovered. It is a note and not a refusal because an absent policy
        # is the normal state before the first run -- but an operator who HAS
        # written a forced-domain list deserves to know that the strict-ECH
        # refusal below did not get a chance to consider their machine, because
        # the policy it would have read is missing or unparseable.
        #
        # The browser clause is the version's own, and each of its three forms is
        # what this machine can be shown to be: a browser below the minimum cannot
        # deliver ECH, one at or above it can, and a machine with no Firefox at all
        # has no browser to be below anything. The last of those is the case the
        # unconditional "a browser below 129" was wrong about most plainly.
        if version is None:
            client = "this machine has no browser whose version could be read, so it is not known"
        elif major is None:
            client = f"Firefox reported {version!r}, so what it can do is not known"
        elif major >= MINIMUM_ECH_FIREFOX:
            client = f"Firefox is {version}, at or above {MINIMUM_ECH_FIREFOX}, and can deliver ECH"
        else:
            client = f"Firefox is {version}, below {MINIMUM_ECH_FIREFOX}, and cannot deliver ECH"
        report.note(
            f"{len(domains)} domain(s) are forced for ECH and {client}, but "
            "/etc/mosdns/policy.yaml could not be read as a policy, so whether ECH is strict is "
            "unknown and this preflight is not refusing on that basis; if the policy is meant to "
            "be strict, check that it parses"
        )

    # Above this line the only case left is a browser that is too old, and the
    # cases that already reported what they know -- no browser, an unreadable
    # version, and one that can do ECH -- have returned or marked themselves.
    if version is None or major is None or major >= MINIMUM_ECH_FIREFOX:
        return

    report.note(
        f"Firefox is {version}, below {MINIMUM_ECH_FIREFOX}, so it does not read HTTPS RRs and "
        "cannot use ECH: a domain on the forced list is unreachable in this browser, and "
        "everything else the router does is unaffected"
    )
    if strict and domains:
        report.refuse(
            f"the policy asks for strict ECH on {', '.join(domains)}, and Firefox is {version}, "
            f"below {MINIMUM_ECH_FIREFOX}: under strict the router answers those names with an "
            "HTTPS record only a client that reads ECH can use, so they would be unreachable "
            "rather than merely unprotected. Upgrade Firefox, or set ech.failure_policy to "
            "fallback, or remove the forced domains"
        )


def _stat_of(root: Path, run: CommandRunner, path: str) -> Optional[Sequence[str]]:
    """The mode, owner, group and kind of a path, or ``None`` if it is not there."""
    absolute = root / path.lstrip("/")
    completed = _ok(run, ("stat", "-c", "%a %U %G %f", str(absolute)))
    if completed is None:
        return None
    fields = completed.stdout.split()
    if len(fields) < 4:
        return None
    return fields


def _file_type(stat_fields: Sequence[str]) -> Optional[str]:
    """What the raw mode in a stat answer says the path is, or ``None``.

    ``%F`` would spell the type out as a word, and the word is not a fixed
    string: coreutils prints "regular empty file" for a zero-length one and
    "regular file" for the rest, so a refusal that turned on which of the two it
    saw would be a refusal that depended on how big the file was. ``%f`` is the
    same fact as a number, in a fixed form on every machine that has a ``stat``.

    ``stat`` follows a symbolic link rather than describing it, so the answer is
    about whatever the link resolves to. That is the right question here: a state
    directory that is a link to a real directory is a directory the package can
    use, and a link to a file is refused by the same answer either way.
    """
    try:
        bits = int(stat_fields[3], 16)
    except (IndexError, ValueError):
        return None
    if stat.S_ISDIR(bits):
        return "directory"
    if stat.S_ISREG(bits):
        return "regular file"
    return f"neither a directory nor a regular file (raw mode {bits:x})"


def _acl_of(root: Path, run: CommandRunner, path: str) -> Optional[str]:
    """A directory's whole ACL, read with getfacl rather than inferred.

    This is the read that the ACL check rests on, and it is the whole ACL, not
    the default half. Two of the three permissions this check needs live in the
    access entries and one lives in the default entries, and the two halves
    disagree in exactly the way that matters: a directory whose default ACL
    grants the group rwx and whose access mask is r-x produces a state file one
    identity creates that the other cannot write, and its mode reads the same as
    a directory that works. A check that read only the default entries passes it.
    """
    absolute = root / path.lstrip("/")
    completed = _ok(run, ("getfacl", "-c", "-p", str(absolute)))
    if completed is None:
        return None
    return completed.stdout


def _acl_entry(line: str):
    """One getfacl entry as ``(is_default, kind, qualifier, effective)``, or ``None``.

    The compact form getfacl prints is ``[default:]kind:qualifier:permissions``, so
    an access entry is three colon-separated fields (``group::rwx``) and a default
    entry is four (``default:group::rwx``). Both are one whitespace-delimited
    token, so the split is on the colon and not on the space.

    A trailing ``#effective:r-x`` replaces the permissions the kernel actually
    applies, which is why it is read rather than discarded: a named entry with rwx
    and a mask of r-x grants r-x, and a check that read the nominal permission
    would pass a directory whose files the other identity still cannot replace.
    """
    body, _, note = line.partition("#")
    fields = body.split()
    if not fields:
        return None
    parts = fields[0].split(":")
    if len(parts) == 3:
        is_default, kind, qualifier, permissions = False, parts[0], parts[1], parts[2]
    elif len(parts) == 4:
        is_default, kind, qualifier, permissions = True, parts[1], parts[2], parts[3]
    else:
        return None
    effective = permissions
    if "effective:" in note:
        effective = note.split("effective:", 1)[1].strip()
    return is_default, kind, qualifier, effective


def _acl_group_class(acl: str, default: bool):
    """The mask and the effective group permissions of one half of an ACL.

    Returns ``(mask, permissions)``, where ``mask`` is the group-class mask or
    ``None`` when the half has none, and ``permissions`` is the list of effective
    permissions this package's group gets from the entries that apply to it.

    Two entries can apply to that group: the owning-group entry, which is this
    package's group because the directory is owned by it, and a named entry for
    it, which Linux permits even when the qualifier names the owning group. A
    process in the group gets the union of the entries that match it, so the
    answer is a list and "can it write" is "can any of them write".

    The mask is applied first, and that is the point of reading it. POSIX
    requires a mask on the group class as soon as an access ACL carries a named
    entry, and the mask -- not the entry -- is what the kernel applies. So an
    access ACL of ``group::rwx / group:someone:rwx / mask::r-x`` grants the group
    nothing beyond r-x, ``stat -c %a`` reports the mask as the mode's group field
    (so the directory still reads 2770 if it was chmodded there afterwards), and a
    check that read the entries rather than the mask would call it writable.

    The mask is therefore collected in a pass of its own: getfacl prints it
    *after* the group entries it applies to, so masking as the lines arrive would
    mask nothing.
    """
    entries = []
    mask = None
    for line in acl.splitlines():
        entry = _acl_entry(line)
        if entry is None:
            continue
        is_default, kind, qualifier, effective = entry
        if is_default != default:
            continue
        if kind == "mask":
            mask = effective
        elif kind == "group" and qualifier in ("", STATE_GROUP):
            entries.append(effective)
    return mask, [entry if mask is None else _masked(entry, mask) for entry in entries]


def _masked(permissions: str, mask: str) -> str:
    """The permissions a mask actually grants, in the letters getfacl would print."""
    if len(permissions) != 3 or len(mask) != 3:
        return permissions
    return "".join(letter if mask[index] == letter else "-" for index, letter in enumerate("rwx"))


def check_state_directories(root: Path, run: CommandRunner, report: Preflight) -> None:
    """Require each state directory to hold what two service identities need.

    Kind, existence, ownership, and then the four mode properties and the two
    halves of the ACL, checked separately and reported together for one
    directory, because an operator fixing one has to know all of it at once.
    Every refusal names the path and quotes the values found: "a state directory
    is wrong" is not actionable across four directories that are not
    interchangeable, one of which is on a tmpfs and is recreated by a tmpfiles.d
    entry rather than by a postinst.
    """
    for path in STATE_DIRECTORIES:
        stat_fields = _stat_of(root, run, path)
        if stat_fields is None:
            report.refuse(
                f"{path} does not exist or could not be stat'd; the package provisions it, and "
                "preflight only reports what it found -- if this is a fresh install, run the "
                "package's own configure step before installing"
            )
            continue
        mode, owner, group = stat_fields[0], stat_fields[1], stat_fields[2]
        problems = []
        kind = _file_type(stat_fields)
        if kind is None:
            problems.append(
                f"its type could not be read from the raw mode stat reported beside {mode}, so "
                "whether it is a directory at all is unknown"
            )
        elif kind != "directory":
            problems.append(
                f"it is a {kind}, not a directory: the package creates state files inside it, and "
                "a path of another kind is a refusal rather than something preflight replaces"
            )
        if owner != STATE_OWNER:
            problems.append(
                f"it is owned by {owner!r}, not {STATE_OWNER!r}, so the package's own units "
                f"run as {STATE_GROUP!r} members and cannot be sure what they will find"
            )
        if group != STATE_GROUP:
            problems.append(
                f"its group is {group!r}, not {STATE_GROUP!r}"
                + (
                    f", so that group can read and replace the state files this package writes"
                    if group
                    else ""
                )
            )
        try:
            mode_bits = int(mode, 8)
        except ValueError:
            mode_bits = -1
        if mode_bits < 0:
            problems.append(f"its mode {mode!r} is not an octal number")
        else:
            if not mode_bits & SETGID_BIT:
                problems.append(
                    f"its mode is {mode}, without the setgid bit (2000): a file created in it "
                    "takes its creator's group rather than this package's, so the other service "
                    "identity cannot read it however the ACL is set"
                )
            if mode_bits & 0o070 != 0o070:
                problems.append(
                    f"its mode is {mode}, so the group permission is {mode_bits & 0o070:03o} "
                    f"rather than 070: this package's two identities share {STATE_GROUP!r} and "
                    "both create and replace what is created in here, and a group that cannot "
                    "write this directory cannot create a state file in it at all"
                )
            if mode_bits & 0o700 != 0o700:
                problems.append(
                    f"its mode is {mode}, so the owner permission is {mode_bits & 0o700:03o} "
                    "rather than 700: the package provisions it for root to maintain, and an "
                    "owner that cannot write it is a shape nobody chose"
                )
            if mode_bits & 0o007:
                problems.append(
                    f"its mode is {mode}, which is readable by every local user; the state a "
                    "router keeps is readable through the group, and a world bit under it is a "
                    "widening nobody chose"
                )
        acl = _acl_of(root, run, path)
        if acl is None:
            problems.append(
                "its ACL could not be read with getfacl, so what the group may create and "
                "replace in it, and what a file created in it will be, are both unknown"
            )
        else:
            access_mask, access_group = _acl_group_class(acl, default=False)
            if STATE_GROUP_PERMISSIONS not in access_group:
                problems.append(
                    f"its access ACL gives the group {access_group or 'nothing'} "
                    f"(mask {access_mask or 'none'}) rather than {STATE_GROUP_PERMISSIONS!r}: "
                    "this is the permission that decides whether a service identity can create, "
                    "replace and lock anything in this directory, and when the ACL carries a "
                    "named entry the mask is what the kernel applies -- so the mode above can "
                    "read rwx for the group while the group still cannot write here"
                )
            default_mask, default_group = _acl_group_class(acl, default=True)
            if STATE_GROUP_PERMISSIONS not in default_group:
                problems.append(
                    f"its default ACL does not grant the group {STATE_GROUP_PERMISSIONS!r} "
                    f"(grants {default_group or 'nothing'}, mask {default_mask or 'none'}, "
                    f"{acl.split()!r}): the mode says what the directory permits today and says "
                    "nothing about what a file created in it will get, and without the ACL a "
                    "file one identity creates comes out group-unwritable for the other"
                )
        if problems:
            # The stat values go in the message whether or not they are the
            # problem. An operator fixing one of these has to confirm the others
            # are what they should be, and quoting only the value that failed
            # makes them stat the directory themselves to find out. The shape the
            # package provisions goes in the same breath, because a refusal that
            # names what is wrong but not what is right leaves the operator
            # guessing at a mode -- and it is named rather than applied, since
            # applying it is postinst's work inside its own lifecycle.
            report.refuse(
                f"{path} is not the state directory this package can use: it is {mode} "
                f"{owner}:{group}, and "
                + "; ".join(problems)
                + f". The package provisions it at {STATE_MODE} {STATE_OWNER}:{STATE_GROUP} with "
                f"a default ACL granting the group {STATE_GROUP_PERMISSIONS!r}, and preflight "
                "reports that rather than applying it: it changes nothing it was asked to look at"
            )


def _path_state(path: Path) -> str:
    """Whether a path is absent, and what is there if it is not.

    ``Path.exists()`` cannot answer this question, and its two failures are the
    two that matter here. It follows a symbolic link, so a dangling link reads as
    absent; and it swallows ``OSError``, so a path whose parent is not a directory
    or whose parent this user may not search reads as absent too. All three are
    "there is something at this path and this program cannot see what", and this
    check is the one place where "absent" is the answer that lets an install
    proceed to create a file.

    The link is not followed: a symbolic link at the control lock's path is a
    redirect the control operations would follow when they open it, and naming it
    is more use to an operator than "could not be stat'd".
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    except NotADirectoryError:
        return "under something that is not a directory"
    except OSError as error:
        return f"unreadable ({error.strerror or error})"
    if stat.S_ISLNK(info.st_mode):
        return "a symbolic link"
    if stat.S_ISDIR(info.st_mode):
        return "a directory"
    if stat.S_ISREG(info.st_mode):
        return "a regular file"
    return "neither a regular file nor a directory"


def check_control_lock(root: Path, run: CommandRunner, report: Preflight) -> None:
    """Report a control lock that already exists and is not this package's.

    The lock is created on first acquire by whichever of the two identities wins
    the race, at 0640, so its absence is the normal state on a fresh machine and
    is not a problem. Its *presence* at another mode, or owned by anybody but
    root and this package's group, means a file this package did not create: a
    world-writable lock is a lock any local user can take, and a lock in another
    group's hands is a lock this package's own control operations would contend
    with. Re-creating it would be a repair, and postinst owns repairs.

    Presence is asked with lstat rather than with ``Path.exists()``, so a path
    that exists and cannot be read is a refusal and not the normal state.
    """
    path = root / CONTROL_LOCK.lstrip("/")
    state = _path_state(path)
    if state == "absent":
        return
    if state != "a regular file":
        report.refuse(
            f"{CONTROL_LOCK} is {state}, not a regular file: the control operations open this "
            "path, and open follows a symbolic link, so whatever is here would be written "
            "through or refused -- either way the install cannot treat the lock as free. It is "
            "reported rather than replaced, because replacing it is a change to something this "
            "package did not create"
        )
        return
    stat_fields = _stat_of(root, run, CONTROL_LOCK)
    if stat_fields is None:
        report.refuse(
            f"{CONTROL_LOCK} exists but could not be stat'd, so whether it is a lock this "
            "package can share is unknown"
        )
        return
    mode, owner, group = stat_fields[0], stat_fields[1], stat_fields[2]
    problems = []
    kind = _file_type(stat_fields)
    if kind is None:
        problems.append(
            f"its type could not be read from the raw mode stat reported beside {mode}, so "
            "whether it is a file at all is unknown"
        )
    elif kind != "regular file":
        problems.append(
            f"it is a {kind}, not a regular file: the lock is taken through a file descriptor, so "
            "a directory at this path is one this package's own control operations cannot use"
        )
    try:
        mode_bits = int(mode, 8)
    except ValueError:
        mode_bits = -1
    if mode_bits < 0:
        problems.append(f"its mode {mode!r} is not an octal number")
    elif mode_bits != LOCK_MODE:
        problems.append(
            f"its mode is {mode}, not {LOCK_MODE_OCTAL}"
            + (
                "; a world-writable lock is a lock any local user can take, and every control "
                "operation then races with them"
                if mode_bits & 0o007
                else ""
            )
        )
    if owner != STATE_OWNER:
        problems.append(f"it is owned by {owner!r}, not {STATE_OWNER!r}")
    if group != STATE_GROUP:
        problems.append(
            f"its group is {group!r}, not {STATE_GROUP!r}, so the two service identities "
            "would not both be able to take it"
        )
    if problems:
        report.refuse(
            f"{CONTROL_LOCK} already exists and is not the lock this package writes: it is "
            f"{mode} {owner}:{group}, and "
            + "; ".join(problems)
            + ". It is reported rather than replaced, because replacing it is a change to a "
            "file this package did not create"
        )


def preflight(root: Path, run: CommandRunner) -> Preflight:
    """Check that this machine can have this router installed on it, changing nothing.

    Every check runs and every result is reported, because an operator fixing a
    refused install should learn about the second problem while they are at it
    rather than after the next run. A check that cannot be answered -- a command
    that would not run, a file that would not read -- is a refusal and never a
    pass: the next thing this program does is bind a privileged port, and a
    question that could not be asked is not a question that came back clear.

    ``root`` is the filesystem to read, which is the real ``/`` in production and a
    temporary directory in a test, and ``run`` is the only way this module reaches
    a command.
    """
    root = Path(root)
    report = Preflight()
    check_release(root, run, report)
    check_architecture(run, report)
    check_dependencies(run, report)
    check_resolv_conf(root, report)
    check_connection(run, report)
    check_ports(root, run, report)
    check_foreign_services(run, root, report)
    check_ech(run, root, report)
    check_state_directories(root, run, report)
    check_control_lock(root, run, report)
    return report


# ---------------------------------------------------------------------------
# The install transaction
# ---------------------------------------------------------------------------
#
# The preflight above reads and reports. Everything below changes, and the order
# it changes things in is the whole of its safety argument:
#
#   1. preflight -- a refusal here means nothing has been touched at all;
#   2. capture the lease this machine is following RIGHT NOW, through the
#      bridge's own capture, with four environment names scrubbed;
#   3. read every value the transaction will change, and write AND read back the
#      root-only backup that records them;
#   4. enable the two units, start each, and prove each answers before the next;
#   5. health-check 127.0.0.1:53 with a real query;
#   6. only then point NetworkManager at the loopback, reactivate the one
#      connection, and check that resolved forwards to it;
#   7. write the ownership marker, last, so an install that failed anywhere above
#      leaves nothing claiming the machine's DNS.
#
# Step 6 is last on purpose. Everything before it is reversible by stopping two
# units; the three properties in step 6 are the ones that can leave a machine
# with no resolver at all, and they are only written once a local query has come
# back. The whole transaction hangs on that, and the test suite holds the two
# steps apart by asserting the whole argument-and-probe sequence as one literal.

# The package this installer belongs to. The version is not a constant here: an
# operator reading a backup has to know which release wrote it, and a literal in
# this file would be the version the source was last edited at rather than the
# one that ran.
PACKAGE_NAME = "mosdns-router"

# Where this installer's own record lives, and what is in it. Both files are
# root-only and so is the directory: the backup names the machine's resolvers and
# the connection they belong to, and the marker is the claim an uninstall reads
# to decide whether the DNS on this machine is ours to change back.
INSTALLER_DIRECTORY = "/var/lib/mosdns/installer"
BACKUP_PATH = INSTALLER_DIRECTORY + "/network-manager-backup.json"
BACKUP_MODE = 0o600
BACKUP_MODE_OCTAL = "0600"
INSTALLER_DIRECTORY_MODE = 0o700
MARKER_MODE = 0o600

# The one file under /etc this package installs, and the only one an uninstall
# removes. Everything else under /etc belongs to dpkg's conffile machinery or to
# the operator, and an operator who has edited /etc/mosdns/policy.yaml has edited
# a file this program must not delete on the way out.
#
# `no-wait.d` is the directory for a hook that must not block a NetworkManager
# event, which is the right one for the bridge: it reads NetworkManager's state
# and rewrites one runtime file, and a blocking hook would hold a DHCP event open
# for the length of an `nmcli` call. The name is this plan's and it is named once
# so that "which hook did we install" has one answer.
DISPATCHER_SCRIPT = "/etc/NetworkManager/dispatcher.d/no-wait.d/10-mosdns-dhcp-bridge"

# The schema version of the backup. It is written into the document and checked
# on the way back in, so a future release that cannot read this shape says so
# instead of restoring a guess.
BACKUP_SCHEMA_VERSION = 1

# How much of a failing command's own output a refusal quotes, and in which
# direction: the last `FAILURE_DETAIL_LINES` non-blank lines, truncated to
# `FAILURE_DETAIL_CHARACTERS` from the left so the end of the explanation -- the
# part that says why the tool gave up -- always survives. Bounded because the
# text is read by a person on a machine that has just lost its resolver, in a
# `prerm` output, and a pasted log is not a message.
FAILURE_DETAIL_LINES = 4
FAILURE_DETAIL_CHARACTERS = 600

# The fields a SECOND install of this package refreshes, and -- by naming the
# complement rather than the list -- the fields it must carry forward untouched.
#
# A re-install happens on every upgrade: `postinst configure` runs the whole
# transaction whatever dpkg passed as its second argument. By then this package
# has already pointed the machine at 127.0.0.1, so the three properties the
# backup records read `yes`/`yes`/`127.0.0.1` -- this package's own values -- and a
# re-install that records them as "what the machine had" has destroyed the only
# copy of the machine's real DNS settings. The next removal then writes the
# loopback back, stops both units, and reports success. This tuple is the rule
# that stops it, and the complement is the safer way to state it: a field added to
# the document later is carried forward by default, because forgetting to record
# that a new field is volatile is the mistake that destroys a machine's record.
#
#   * `created_at` and `package_version` are about THIS run, not about the machine.
#   * `dhcp` is the lease as it is now, re-read by the capture on every install.
#   * `connection` is a live observation, and its `device` in particular is: a
#     machine whose interface was renamed carries the OLD name in the record, and
#     an uninstall asks `resolvectl dns <device>` to prove the device took the
#     restored values back. Carrying a stale name forward would leave a renamed
#     machine refusing its own uninstall with a message about a rename. The UUID
#     is not volatile and is not refreshed: the record is only ever about one
#     connection, and a re-install naming a different one is refused rather than
#     given a second record's worth of values.
#
# Everything else -- `original` above all, and with it the connection's own
# properties, the configuration digest, the schema version and the project name --
# describes the machine, and a re-install observes none of it anew.
VOLATILE_BACKUP_FIELDS = ("created_at", "package_version", "dhcp", "connection")

# The document the backup digests. It is the POLICY rather than the rendered
# routing config because that is what this project already means by a
# configuration digest: `internal/optimizer`'s PolicyDigest is the SHA-256 of the
# policy's own bytes, and a second meaning for the same field name in the same
# repository is a trap for whoever reads both.
POLICY_CONFIG = "/etc/mosdns/policy.yaml"

# Where the DHCP bridge publishes, and how a first-install capture is asked for.
# These are the same three values bridge/mosdns_dhcp_bridge documents and the
# same ones the package's dispatcher script uses, so a capture and the first
# `up` event after it record one state rather than two generations.
DHCP_STATE_FILE = "/run/mosdns/dhcp-upstreams.json"
DHCP_LOCK_FILE = "/run/mosdns/dhcp-bridge.lock"
DHCP_BRIDGE = ("python3", "-m", "mosdns_dhcp_bridge.cli")
DHCP_CAPTURE = "--capture-current"

# The four environment names the capture must not inherit, and no others.
#
# `CommandRunner.run` takes no `env=`, so the environment the capture would
# inherit is changed by the COMMAND rather than by the caller: `env -u NAME` for
# each of the four, inside the argument array. That is a real answer to a real
# constraint rather than a workaround -- it needs no `os.environ` surgery, it is
# visible in the array a test records, and `env -u` on a name that is not set is
# not an error, so the scrub does not depend on what the installer's own
# environment happened to carry.
#
# Each of the four changes what the capture records, which is why none of them
# can be left to chance:
#
#   * the action makes `--capture-current` a usage error, and exits 2 before a
#     single command runs;
#   * the two DHCP variables are ranked below NetworkManager's raw fields but
#     above the effective device DNS, so a stale value is recorded as the
#     `dispatcher-env` source -- a source no real event can reproduce, and so a
#     generation advance and a cache flush at the moment there must be none;
#   * the connection UUID outranks the authoritative `nmcli -g GENERAL.CON-UUID`
#     lookup, so a stale value makes the capture name the WRONG connection and
#     skip the query, and the first real event then names the true one.
#
# `DEVICE_IP_IFACE`, `INTERFACE` and `DEVICE` are deliberately left alone: a
# capture never reads them, because the caller names the interface on the
# command line instead.
SCRUBBED_ENVIRONMENT_NAMES = (
    "NM_DISPATCHER_ACTION",
    "DHCP4_DOMAIN_NAME_SERVERS",
    "DHCP6_DOMAIN_NAME_SERVERS",
    "CONNECTION_UUID",
)

# The address the machine's own resolver listens on. It is loopback, and nothing
# here may name a resolver that is not this machine: after the three properties
# below, the machine's only path to DNS is a process on the other end of a
# loopback socket.
LOCAL_DNS = "127.0.0.1"

# The two properties that tell NetworkManager to stop following the lease, and
# the one that points it at the loopback instead. Named as constants because they
# appear in three places -- the read, the set and the restore -- and a typo in one
# of the three would be a property this package sets and cannot undo.
IPV4_IGNORE_AUTO_DNS = "ipv4.ignore-auto-dns"
IPV6_IGNORE_AUTO_DNS = "ipv6.ignore-auto-dns"
IPV4_DNS = "ipv4.dns"
IPV6_DNS = "ipv6.dns"

# The three mutations, in the order they are made, and the only three.
#
# The order is not incidental. Both ignore-auto-dns properties are set before any
# address is, so the window in which the lease's resolvers are being ignored is a
# window in which the loopback address has already been given. The reverse order
# would leave a moment where the connection follows nothing at all and before it
# is asked to use an address the machine cannot yet resolve through.
NM_MUTATIONS = (
    (IPV4_IGNORE_AUTO_DNS, "yes"),
    (IPV6_IGNORE_AUTO_DNS, "yes"),
    (IPV4_DNS, LOCAL_DNS),
)

# The four properties the backup records: the three above and the IPv6 address
# list, which this install never changes and an operator restoring by hand does.
# Recording a property nothing restores costs two reads; failing to record one
# somebody may have to restore costs a machine with no DNS.
IGNORED_AUTOMATICALLY = (IPV4_IGNORE_AUTO_DNS, IPV6_IGNORE_AUTO_DNS)
ADDRESS_LISTS = (IPV4_DNS, IPV6_DNS)
RECORDED_PROPERTIES = IGNORED_AUTOMATICALLY + ADDRESS_LISTS

# The command that publishes the Cloudflare prefix list, on the installed binary
# and with every path at its default, which is what makes it the production one.
#
# It is here and not merely noted because the router cannot start without it. The
# response rewriter builds its prefix watcher before anything else and returns the
# error, so a plugin with no published ranges never constructs -- which means
# `systemctl start mosdns-router` binds nothing on port 53, the wait for the
# resolver port burns its whole deadline, and the install rolls itself back. A
# router that cannot start is not a state an install may leave a machine waiting
# in, and the producer of the list is not a later task: `update-lists
# --refresh-ranges` exists, it measures nothing, it spends no bandwidth budget,
# and its own flag description calls it the mode an installation runs before the
# router starts. The other two modes are the wrong carriers: `--check` documents
# that it writes nothing and cannot publish a missing prefix list, and
# `--pin-remote` re-pins the China list.
#
# It is run unconditionally, and it is run with no origin named, because a
# publisher that decided for itself whether to run would be a second thing that can
# be wrong: it would have to re-derive the cache envelope's validity, and an origin
# that is unreachable is exactly the case where the cached envelope is the answer.
# Left to the publisher, the same array republishes from the cache with no network
# at all.
PUBLISH_PREFIXES = ("/usr/lib/mosdns-router/mosdns-cdnctl", "update-lists", "--refresh-ranges")

# The launcher an operator runs to put a machine's DNS back by hand. Named as a
# constant because three places print it -- the health verb's failure message and
# the rollback's recovery line -- and a hand-rolled path in two of three would be
# wrong on a build where the prefix is not the one above.
CDNCTL = "/usr/lib/mosdns-router/mosdns-cdnctl"

# The operator's force-ECH list -- read by :func:`_forced_ech_domains` above, which
# is shared with the preflight on purpose -- and the one entry in it that would
# make this install's own health check meaningless.
#
# The rewriter's strict short circuit is the FIRST thing its Exec does: for a name
# on this list, with the policy's failure policy fail-closed, an A or AAAA query is
# answered by the router itself with a NOERROR carrying no records and no SOA, and
# nothing is asked downstream. The probe above is an A query, so an operator with
# the probe's name on this list would get a NOERROR out of the router with no
# upstream ever consulted -- and the wait, the barrier and the router half of the
# verification would all be satisfied by a local answer.
#
# That short circuit is load-bearing ECH behaviour and it is correct: forcing ECH
# for a censored name must not cost a DNS lookup, which is the entire point of the
# feature. This install does not weaken it and cannot. What it can do is refuse to
# run while its own probe would be answered that way, because a barrier that
# cannot be lied to is the only kind worth having, and the refusal names the file,
# the entry and the remedy.
# The path. Named once and used by BOTH readers of this file -- the preflight's
# `check_ech` and the transaction's guard below -- because two spellings of the
# path would be two chances to look at different files.
# The policy's ECH failure policy value the plugin maps to its fail-closed
# behaviour. `failurePolicyOf` in the plugin returns FailClosed for anything that
# is not "fallback", and `internal/config`'s default is "strict", so both the
# default and a typo land on the short circuit.
ECH_FALLBACK = "fallback"
# The two units this transaction owns, in the order it enables them. The router
# is enabled as well as started: a machine whose NetworkManager points DNS at the
# loopback and whose router is not enabled comes back from a reboot with no
# resolver at all, which is a worse outcome than one extra idempotent call.
OWNED_UNITS = (RESOLVER_UNIT, ROUTER_UNIT)

# The answers that mean "this unit was not running" and "this unit is not
# enabled". Anything else -- including an answer this program could not read --
# is treated as "it was", because stopping or disabling something that was
# already running is the harm the rollback rule exists to prevent, and leaving one
# running is a smaller and reversible one.
NOT_ACTIVE = ("inactive", "failed")
NOT_ENABLED = ("disabled", "not-found")
# The two keys of a unit's recorded state, named for the same reason the two
# tuples above are: they are looked up in a mapping this module builds, and a
# misspelled key there is a question that never gets asked.
UNIT_ACTIVE = "active"
UNIT_ENABLED = "enabled"

# The name the probes ask for, and the RFC plus the measurement that chose it.
#
# The barrier's real dependency is a fact about the machine the install runs on:
# that the operator's resolver FORWARDS this name rather than answering it without
# asking anybody. No assertion in this file can observe that, so the choice below
# is made from what can be -- what the RFC tells a conforming caching resolver to
# do with each candidate -- and the measurement on 24.04 says whether the resolver
# this project ships agrees.
#
# RFC 6761 gives every special-use TLD a "caching servers" category, and the three
# candidates are recommended in three DIFFERENT directions. That partition is the
# whole of the choice:
#
#   * `.invalid` (§6.4 category 4) -- caching servers SHOULD generate immediate
#     NXDOMAIN responses. systemd-resolved 24.04 does exactly that: with an
#     unreachable upstream configured, a question is answered in microseconds with
#     a bare NXDOMAIN carrying no records at all (28 bytes: a header and the
#     question). So `.invalid` is CONFORMING and deterministically blind -- a dead
#     chain states a confident denial, and any check that accepts a denial passes
#     a machine that cannot resolve anything. Disqualifying, and not a judgement
#     call.
#   * `.test` (§6.2 category 4) -- caching servers SHOULD generate immediate
#     negative responses. resolved forwarding it is a measured DEVIATION from a
#     SHOULD, so a resolver that followed the RFC would put the blind spot back.
#     Better than `.invalid` and still resting on a resolver behaving against the
#     RFC's recommendation.
#   * `.example` (§6.5 category 4) -- caching servers SHOULD NOT recognise these
#     names as special and SHOULD resolve them normally. resolved forwards it, and
#     that is the RECOMMENDED behaviour, so a conforming caching server cannot
#     answer it locally. Measured on 24.04 with an unreachable upstream: forwarded,
#     and therefore silent, which the wait already reads as a failure.
#
# `.test` was the choice in the previous round, on the evidence that `.test` is
# forwarded and `.invalid` is not. That evidence did not separate them, and this
# comment is the correction: the RFC does, and it is on the side of `.example`.
#
# WHAT THIS COSTS, stated rather than glossed: a question for this name is
# forwarded, so 1-3 of them per install reach the operator's own recursive resolver
# and the public root, where the root has no delegation for `.example` and answers
# NXDOMAIN. Under `.invalid` nothing left the machine. The name is meaningless to
# the public root either way -- nothing delegates any of the three -- so what
# changed is a handful of queries to the operator's own resolver, not a disclosure
# of anything about the machine.
#
# UNVERIFIED, and it is the one thing this rests on beyond the RFC: whether a
# systemd-resolved on 22.04 or 26.04 forwards a `.example` question the way 24.04
# does. A resolved that synthesised `.example` as well would pass a dead chain
# again. Closing that needs a per-release measurement; the failure is a check that
# accepts a machine that cannot resolve, so the residual is recorded rather than
# designed away.
INSTALL_PROBE_NAME = "install-probe.example"
PROBE_TIMEOUT_SECONDS = 2.0
# How long a unit gets to start answering. It fails the install rather than
# hanging, because a resolver that is not up is exactly the state this
# transaction must not point a machine at.
WAIT_DEADLINE_SECONDS = 60.0
WAIT_POLL_SECONDS = 0.25

# The DNS message the prober builds and reads, spelled out rather than borrowed
# from a library: this is the one place the transaction opens a socket, it is the
# only network code in the installer, and the Python standard library has no DNS
# client. 12 header bytes, one question, an A record, class IN.
DNS_HEADER_LENGTH = 12
DNS_RECURSION_DESIRED = 0x0100
DNS_RESPONSE_BIT = 0x8000
DNS_RESPONSE_CODE_MASK = 0x000F
DNS_QUESTION_COUNT = 1
DNS_TYPE_A = 1
DNS_CLASS_IN = 1
DNS_LABEL_LIMIT = 63
DNS_NAME_LIMIT = 255
# The only two response codes that mean a resolver reached somebody and was told
# the answer. A SERVFAIL or a REFUSED means it did not, and silence means the same
# thing more slowly.
DNS_RCODE_NO_ERROR = 0
DNS_RCODE_NAME_ERROR = 3
RESOLVING_RCODES = (DNS_RCODE_NO_ERROR, DNS_RCODE_NAME_ERROR)


class InstallRefused(Exception):
    """A step of the transaction could not be completed, and the machine says why.

    It is raised for every failure the transaction has, and the transaction
    catches nothing itself: one exception type means there is exactly one path
    from "a step failed" to "roll back", and a second one would be a step that
    could fail without a rollback.
    """


class InstallResult(NamedTuple):
    """What the transaction did, what it could not put back, and what a person owes.

    ``error`` and ``rollback_error`` are separate because they are separate facts
    about a machine: the first says the install did not finish, and the second
    says whether the machine is now as it was found. A script -- or an operator --
    has to be able to tell those apart without reading prose, so ``main`` gives
    them different exit statuses.

    ``recovery`` is the third fact, and it is the one only a person can act on. A
    rollback that failed at the reactivation leaves the profile carrying its
    recorded values and the device not reactivated, so the machine's DNS may not
    be in use; a rollback that failed at a property restore leaves the connection
    handing resolved the loopback address. Those are different states of the
    machine with different single actions, and collapsing them into "the rollback
    did not finish" is how an operator ends up rebooting a machine that needed one
    `nmcli connection up`.

    ``left_running`` names the units this run started and then declined to stop,
    because their prior state could not be read. It is what keeps the exit-3
    message from claiming a machine is unchanged when it is not.
    """

    ok: bool
    backup: Optional[str]
    report: Optional[Preflight]
    notes: List[str]
    error: Optional[str]
    rollback_error: Optional[str]
    recovery: Optional[str]
    left_running: List[str]


class AppliedStep(NamedTuple):
    """One mutating action this transaction took, and the action that undoes it.

    The undo is a callable rather than a command array because a step is not always
    a command: putting back a marker that was not there before is an unlink, and a
    step whose undo were a command the transaction never recorded would be a value
    it invented.

    ``was_running`` is the fact the recovery message cannot be reconstructed
    without. A step whose unit was NOT running before this run and whose undo did
    not run leaves a unit this program STARTED still running, and the operator's
    action is `systemctl stop <unit>`. A step whose unit WAS running before this
    run and whose undo did not run leaves a unit this program RESTARTED down, and
    the operator's action is not a stop at all -- the machine may have no resolver,
    and `emergency-rollback` is what puts the recorded settings back. One sentence
    cannot be true of both, and the wrong one sends an operator to stop a resolver
    on a machine that has nothing left listening.
    """

    description: str
    undo: Callable[[], None]
    # The unit this step changed, or None for a step that is not a unit's. Carried
    # rather than recovered from the description, because the recovery message has
    # to print a command an operator can run and `systemctl stop <unit>` with an
    # unsubstituted placeholder is not one.
    unit: Optional[str] = None
    was_running: bool = False


class RollbackFailure(NamedTuple):
    """One undo that did not run, and which kind of step it belonged to.

    The group is carried rather than left in prose because the three kinds leave
    the machine in three different states, and the operator's next action differs
    for each. ``main`` keys its message off it. ``was_running`` says which way the
    unit group went wrong, and :class:`AppliedStep` is where that is explained.
    """

    group: str
    description: str
    error: str
    unit: Optional[str] = None
    was_running: bool = False


class Transaction:
    """The applied mutations, and the restoration of them in the order that works.

    Three groups, each undone newest-first, taken back in this order:

      1. the connection's profile,
      2. the reactivation,
      3. the units.

    Groups 1 and 3 are the reverse of the order they were applied in, and group 2
    is the whole reason there are three groups rather than one stack. A profile
    change reaches the live device only when the connection is brought up again,
    so a rollback that reactivated FIRST would hand the device the values it is in
    the middle of removing -- both `ignore-auto-dns` set and the loopback address
    -- and would then write the recorded values to the profile, where nothing reads
    them again. The machine would come out of a failed install with no resolver in
    use and a correct profile on disk, and the profile being correct is exactly
    what makes that state hard to notice. So the reactivation is a group of its
    own, between the profile and the units: restore the values, let the device pick
    them up, and only then take the resolver away.

    A plain reverse-order stack cannot express that, and a stack that tries ends up
    with this order by accident and looks right until a failure proves otherwise.

    A failure in one undo does not stop the others. Every failure is collected and
    the transaction reports all of them, because stopping at the first would leave
    more of this package's changes applied than restoring past it would, and the
    operator's only information would be about whichever one happened to fail
    first.
    """

    # The three groups, named because the recovery message keys off them.
    PROFILE = "the connection profile"
    REACTIVATING = "the reactivation"
    UNITS = "the units"

    def __init__(self) -> None:
        self._groups: dict = {self.PROFILE: [], self.REACTIVATING: [], self.UNITS: []}
        self.backup: Optional[str] = None
        # Units this run started and then declined to stop, because their prior
        # state could not be read. Reported so the exit-3 message can except them.
        self.uncertain_units: List[str] = []

    def apply_profile(self, description: str, undo) -> None:
        """Record a change to the connection's own properties."""
        self._groups[self.PROFILE].append(AppliedStep(description, undo))

    def apply_reactivating(self, description: str, undo) -> None:
        """Record the reactivation, whose undo runs after every profile restore."""
        self._groups[self.REACTIVATING].append(AppliedStep(description, undo))

    def apply_unit(
        self, description: str, undo, unit: Optional[str] = None, was_running: bool = False
    ) -> None:
        """Record a change to a unit, undone after the profile and the reactivation.

        ``was_running`` says the unit was already running before this run, so the
        undo is a restart rather than a stop and the recovery message has to talk
        about a machine that may have no resolver. See :class:`AppliedStep`.
        """
        self._groups[self.UNITS].append(AppliedStep(description, undo, unit, was_running))

    def note_uncertain_unit(self, unit: str) -> None:
        """Record that ``unit``'s prior state could not be read.

        The unit is therefore left as the rollback found it, whatever the rollback
        did to it, and the caller has to be able to say so rather than claim the
        machine is unchanged.
        """
        self.uncertain_units.append(unit)

    def rollback(self) -> List[RollbackFailure]:
        """Undo every applied step, group by group, and report what would not undo."""
        failures = []
        for group in (self.PROFILE, self.REACTIVATING, self.UNITS):
            for step in reversed(self._groups[group]):
                try:
                    step.undo()
                except Exception as error:  # noqa: BLE001 - see this method's docstring
                    failures.append(
                        RollbackFailure(group, step.description, str(error), step.unit, step.was_running)
                    )
            self._groups[group] = []
        return failures


def build_dns_query(name: str, identifier: int) -> bytes:
    """The bytes of one A/IN question for ``name``.

    Built by hand because the standard library has no DNS client and this program
    may not add a dependency: it runs from a Debian package as root on a router,
    and a resolver probe is not worth a library.

    The name is refused rather than mangled. A label over 63 octets, an empty
    label, or a name over 255 octets is not a question any resolver will answer,
    and a probe that built one would be waiting for a timeout instead of getting a
    refusal.
    """
    if not name:
        raise ValueError("a DNS question needs a name")
    labels = []
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii", "strict")
        if not encoded:
            raise ValueError(f"{name!r} has an empty label")
        if len(encoded) > DNS_LABEL_LIMIT:
            raise ValueError(f"{name!r} has a label over {DNS_LABEL_LIMIT} octets")
        labels.append(bytes([len(encoded)]) + encoded)
    question = b"".join(labels) + b"\x00"
    if len(question) > DNS_NAME_LIMIT:
        raise ValueError(f"{name!r} is over {DNS_NAME_LIMIT} octets encoded")
    header = (
        identifier.to_bytes(2, "big")
        + DNS_RECURSION_DESIRED.to_bytes(2, "big")
        + DNS_QUESTION_COUNT.to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x00\x00"
    )
    return header + question + DNS_TYPE_A.to_bytes(2, "big") + DNS_CLASS_IN.to_bytes(2, "big")


class Answer(NamedTuple):
    """What one DNS question found, as the two questions the transaction asks.

    ``answered`` is "is something listening on that port and speaking DNS", and
    ``resolves`` is "did that something reach a resolver and get an answer". One
    question produces both, because a second question would double the wait's
    deadline and ask a second question of a machine that is already in trouble.

    They are separate because they come apart in exactly the case this check
    exists for. A resolver whose upstream is unreachable answers SERVFAIL: it has
    answered, and it has not resolved. Reading that as "up" is how a transaction
    points a machine at a chain that cannot resolve anything.
    """

    answered: bool
    resolves: bool


def response_is_an_answer(datagram: bytes, identifier: int) -> bool:
    """Whether ``datagram`` is a DNS response to the question ``identifier`` asked.

    Three facts, and no more: it is long enough to hold a header, its transaction
    id is the one this program chose, and its QR bit says it is a response rather
    than a query. The response code is deliberately not looked at, because this is
    the question the two WAITS ask -- is a socket listening and speaking DNS -- and
    any answer at all proves that, including the SERVFAIL a resolver sends while
    its own upstream is still coming up. The question the BARRIER asks is
    :func:`response_resolves`, and it gets a different answer from the same
    datagram.

    A datagram from something that is not a resolver at all -- a proxy answering
    on the same port, say -- has the QR bit clear, so it does not pass.
    """
    if len(datagram) < DNS_HEADER_LENGTH:
        return False
    if int.from_bytes(datagram[:2], "big") != identifier:
        return False
    return bool(int.from_bytes(datagram[2:4], "big") & DNS_RESPONSE_BIT)


def response_resolves(datagram: bytes, identifier: int) -> bool:
    """Whether ``datagram`` is an answer a resolver that reached somebody gives.

    :func:`response_is_an_answer` plus the response code, and the code is the whole
    of the difference. NOERROR and NXDOMAIN both mean the resolver got an answer:
    one is an answer with a name in it, the other is an answer that the name does
    not exist, and for a name under a TLD nothing delegates the second is what a
    working chain says. SERVFAIL and REFUSED mean the resolver did not get one --
    the former is what this project's own tests hand a rewriter when an upstream
    is unreachable, and the latter is a resolver declining rather than failing.

    A bare NXDOMAIN with no records is still accepted, and that is deliberate: a
    synthesised denial and a real one are the same twelve bytes of header and
    nothing else, and telling them apart would mean requiring records a healthy
    resolver may strip. The measurement that makes this safe is not on the rcode
    but on the NAME -- see :data:`INSTALL_PROBE_NAME`, where the reason a dead
    chain cannot synthesise a denial is that this build asks a TLD resolved
    forwards rather than one it answers itself.
    """
    if not response_is_an_answer(datagram, identifier):
        return False
    flags = int.from_bytes(datagram[2:4], "big")
    return (flags & DNS_RESPONSE_CODE_MASK) in RESOLVING_RCODES


def probe_dns(
    address: str,
    port: int,
    timeout: float = PROBE_TIMEOUT_SECONDS,
    name: str = INSTALL_PROBE_NAME,
) -> Answer:
    """Ask ``address:port`` one question and report both answers it gave.

    This is the one place in the installer that opens a socket, and it opens a UDP
    socket to a loopback address and sends a few dozen bytes. It binds nothing:
    the machine's resolver ports belong to the resolver, and a probe that took one
    of them to find out whether it was free would be the thing it was measuring.

    Every failure is an all-`False` :class:`Answer` rather than an exception.
    "Nothing answered" is an answer this function exists to give, and a caller that
    had to tell a refused socket from a silent one could only do it by reading the
    error, which is a worse contract than the fact.
    """
    identifier = 0x4D4F
    query = build_dns_query(name, identifier)
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return Answer(answered=False, resolves=False)
    try:
        connection.settimeout(timeout)
        connection.sendto(query, (address, port))
        datagram, _ = connection.recvfrom(4096)
    except OSError:
        return Answer(answered=False, resolves=False)
    finally:
        connection.close()
    return Answer(
        answered=response_is_an_answer(datagram, identifier),
        resolves=response_resolves(datagram, identifier),
    )


def wait_for_dns(address: str, port: int, probe, deadline_seconds: float, poll_seconds: float) -> bool:
    """Poll ``probe`` until it answers or the deadline passes.

    A query, not a sleep: preflight's port check established that a free port is a
    fact about one moment and not a reservation, and this is the other half of
    that. Waiting a fixed interval and asking once would pass a machine whose
    router took four seconds to bind; polling a real question is the only way to
    know a resolver is up rather than merely scheduled.

    The question asked here is the LISTENING one -- any answer at all -- and not
    the resolving one, because a resolver that is up and whose upstream is still
    coming up answers SERVFAIL and a wait that rejected that would fail a machine
    that is about to work. Whether the chain resolves is the barrier's question,
    and it is asked after both units are up.

    The deadline is what keeps a broken machine from hanging the install, and it is
    reported as a failure rather than a warning: the next step would point the
    machine at an address nothing is answering on.
    """
    deadline = time.monotonic() + deadline_seconds
    while True:
        if probe(address, port).answered:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_seconds)


def _utcnow() -> datetime.datetime:
    """The time the backup is stamped with."""
    return datetime.datetime.now(datetime.timezone.utc)


def _stamp(moment: datetime.datetime) -> str:
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_text(path: Path, what: str) -> str:
    """Read a file the transaction cannot go on without, or refuse."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise InstallRefused(f"{what} ({path}) could not be read: {error}") from error


def _text(runner: CommandRunner, args: Sequence[str]) -> Optional[str]:
    """What a query printed, or `None` when the query could not be run at all.

    The text and not the status, because that is the shape of the answers that
    matter here: `systemctl is-active` answers 3 for a stopped unit and
    `is-enabled` answers 1 for a disabled one, both with the answer on standard
    output. A reader that looked at the status instead would conclude that every
    unit on a healthy machine is stopped.

    `None` means only that the call itself failed -- a missing binary, a runner
    that raised -- and an empty string is a real answer that happened to be empty.
    The two are kept apart because a property with no value set is one of the
    values this transaction has to record and put back, and a reader that called
    silence "no answer" would refuse every connection that has no manual DNS.
    """
    try:
        completed = runner.run(list(args), check=False)
    except Exception:  # noqa: BLE001 - the boundary is arbitrary injected code
        return None
    return (completed.stdout or "").strip()


def _answer(runner: CommandRunner, args: Sequence[str]) -> Optional[str]:
    """:func:`_text`, with a blank answer folded into "this program cannot say".

    Used only for the two unit-state queries, where silence and a missing unit
    are the same fact and `None` is what makes the caller fall back to the safe
    reading instead of treating silence as a state.
    """
    return _text(runner, args) or None


def _quoted(text: Optional[str]) -> str:
    """A bounded ``; it said: ...`` for text a command already returned.

    The same bound and the same direction as :func:`_failure_detail`, factored out
    because the capture does not raise -- it reads a non-zero status off a
    `Completed` -- and would otherwise be the one place in this module where a
    tool's explanation is dropped on the floor.
    """
    if not isinstance(text, str):
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    omitted = len(lines) - FAILURE_DETAIL_LINES
    kept = lines[-FAILURE_DETAIL_LINES:]
    if omitted > 0:
        kept = [f"{omitted} earlier line(s) omitted"] + kept
    detail = " | ".join(kept)
    if len(detail) > FAILURE_DETAIL_CHARACTERS:
        detail = "..." + detail[-FAILURE_DETAIL_CHARACTERS:]
    return f"; it said: {detail}"


def _failure_detail(error: BaseException) -> str:
    """What a failing command printed, trimmed to something a person can read.

    Standard error first and standard output second, because a refusal is
    conventionally written to standard error and a tool that wrote its reason
    somewhere else has still said it. `getattr` rather than an `isinstance` check
    because the boundary is an injected runner: a fake may raise
    `CalledProcessError`, which carries both streams, and anything else -- a
    `TypeError` from a string argument, an `OSError` from a binary that is not
    there -- carries neither. This function runs inside the handler that is trying
    to explain the failure, so raising here would replace a message with a
    traceback.

    The last few lines rather than the first, because the line that says why a
    tool gave up is at the end of what it printed; the count of omitted lines is
    stated rather than hidden, so a reader can tell a truncated quote from a
    complete one. The bounding itself is `_quoted`'s, which the capture shares.
    """
    for name in ("stderr", "stdout"):
        text = getattr(error, name, None)
        if not isinstance(text, str):
            continue
        quoted = _quoted(text)
        if quoted:
            return quoted
    return ""


def _checked(runner: CommandRunner, args: Sequence[str], what: str) -> None:
    """Run a command that has to succeed, and name the step AND what it said if it did not.

    The broad `except` is forced and not lazy: the module's one process boundary is
    the only place allowed to name `subprocess`, because naming it here would be a
    second reference the preflight's boundary scan would have to allow -- and this
    program runs as root, so a scan weakened to accommodate it is a scan that no
    longer holds. Every failure of the injected boundary means the same thing to
    this step anyway: the command did not do what it was asked to do.

    The reason is quoted because the exception's own text does not carry it.
    `CalledProcessError.__str__` is `Command '[...]' returned non-zero exit
    status N`, so the most likely install-time failure in the field reaches the
    operator as a sentence about this program's step and a number, with the tool's
    own explanation -- the only part that says what to do next -- discarded. The
    quote is bounded (see :func:`_quoted`) because this text ends up in a `prerm`
    output on a machine that may have no DNS, where a thousand-line log is not a
    message.
    """
    try:
        runner.run(list(args), check=True)
    except Exception as error:  # noqa: BLE001 - see above
        detail = _failure_detail(error)
        raise InstallRefused(
            f"{what} failed: {error}" + (f"; {detail}" if detail else "")
        ) from error


def capture_command(interface: str) -> List[str]:
    """The capture, as an argument array, with the four names scrubbed in it.

    `env -u` four times and then the bridge's own documented module invocation. It
    is an array and never a string, so an interface name cannot be reinterpreted,
    and the scrub is part of the command rather than a property of the process that
    runs it -- which is what makes it visible to a test and independent of what the
    installer's own environment happened to carry.
    """
    command = ["env"]
    for name in SCRUBBED_ENVIRONMENT_NAMES:
        command += ["-u", name]
    command += list(DHCP_BRIDGE)
    command += [
        DHCP_CAPTURE,
        interface,
        "--state-file",
        DHCP_STATE_FILE,
        "--lock-file",
        DHCP_LOCK_FILE,
    ]
    return command


def _capture_dhcp(runner: CommandRunner, device: str) -> None:
    """Publish the lease in use right now, before anything is pointed anywhere.

    The capture is the bridge's own publication path with an interface this
    installer named, so the first real `up` event after this install records one
    state rather than a second generation for resolvers that never moved.

    Each of the bridge's own statuses is named rather than lumped together,
    because they are three different facts about the machine:

      * 4 is a defined outcome and not an accident. The collector read the lease
        and the connection it belonged to could not be read, so the capture
        published nothing and discarded the addresses it had read. The state file
        keeps the generation it had, which is the fail-closed answer: a state
        carrying resolvers and no connection is one the publisher refuses, and the
        machine really did have a lease.
      * 2 is a refusal of the command line, which after a scrubbed environment
        means this installer and the bridge disagree about how a capture is
        invoked -- a bug, not a machine.
      * anything else failed for a reason the bridge has already logged.
    """
    command = capture_command(device)
    try:
        completed = runner.run(command, check=False)
    except Exception as error:  # noqa: BLE001 - see _checked
        raise InstallRefused(
            f"the DHCP capture could not be run at all ({error}); this install records the lease "
            "the machine is following before it changes anything, and a capture that did not run "
            "says nothing about that lease"
        ) from error
    if completed.returncode == 0:
        return
    if completed.returncode == 4:
        raise InstallRefused(
            f"the DHCP capture read the lease on {device} and could not name the connection it "
            "belongs to, so it published nothing and discarded the resolvers it had read; the "
            "state file keeps the generation it had. This is a failure and not a success, because "
            "the machine does have a lease and this install cannot say which connection it belongs "
            "to"
        )
    if completed.returncode == 2:
        raise InstallRefused(
            "the DHCP capture refused its command line, which with a scrubbed environment means "
            "this installer and mosdns_dhcp_bridge disagree about how a capture is invoked; "
            "nothing has been changed"
        )
    raise InstallRefused(
        f"the DHCP capture failed with status {completed.returncode}; nothing has been changed"
        + _quoted(getattr(completed, "stderr", None) or getattr(completed, "stdout", None))
    )


def _package_version(runner: CommandRunner) -> str:
    """The version of the package that is doing the installing.

    Read from dpkg rather than from a literal in this file, because the point of
    recording it is that an operator reading a backup months later can tell which
    release wrote it. A version this installer cannot read is a refusal rather than
    a blank field, because a backup with no version cannot be matched against the
    release being removed.
    """
    args = ("dpkg-query", "--show", "--showformat=${Version}", PACKAGE_NAME)
    answer = _answer(runner, args)
    if answer is None:
        raise InstallRefused(
            f"the installed version of {PACKAGE_NAME} could not be read (`dpkg-query --show "
            f"--showformat=${{Version}} {PACKAGE_NAME}`); the backup records which release wrote "
            "it, so an unknown version is a backup nobody can match against the release they are "
            "trying to remove"
        )
    return answer


def _original_property(runner: CommandRunner, uuid: str, prop: str) -> str:
    """One property of one connection, as NetworkManager reports it now.

    `-g` with a single field, and a single field because of what an empty value
    does to the answer: asked for four properties at once, nmcli prints four lines
    and an unset last one has no line of its own to count, so which line is which
    becomes a guess. Asked one at a time there is exactly one answer and no way to
    misattribute it.

    The answer is validated against what the property can be. An ignore-auto-dns
    this module cannot read as `yes` or `no` is refused rather than stored, because
    a restore writes back a value it recorded and a value it could not parse is
    one it would write back as nonsense.

    THE ASYMMETRY, which is the module's one and it is deliberate.

    This is the module's SECOND statement of "a blank `yes`/`no` is not a value",
    and the other one is the shared classifier `_classify`, which
    :func:`_ownership` and :func:`manual_recovery_report` use. They are not
    interchangeable, and pretending they were is what let an earlier round ship two
    functions that disagreed about a blank read and then print both answers about
    the same property twelve lines apart in one report.

    The two answer DIFFERENT questions, which is why there are two:

      * `_classify` answers WHOSE value is this -- is it what we set, what was
        recorded, what somebody else changed, or is it unreadable -- and it must
        keep working for a value that is legitimately blank. An `ipv6.dns` nobody
        has set is a real value, and a report that called it unreadable would print
        a row about a machine that is fine. So it reads blank as a value, compares
        it, and only says UNREADABLE when a read produced nothing at all.

      * THIS function answers MAY I RECORD THIS -- and a blank ignore-auto-dns is
        not something to record, because `nmcli` prints nothing for an unset
        boolean and "unset" and "NetworkManager could not be read" are the same
        empty string. A restore that wrote the empty string back would write a
        malformed value onto a live connection.

    So the two are not duplicates to be collapsed and one is not a bug in the
    other. The shape is the same because the VALUE SPACE is the same; the verdict
    differs because the question does. The rule both sides point at, and the
    reason this comment exists rather than a refactor: any change to one that is
    not also a change to the other has to be a change to the QUESTION, not to the
    answer.
    """
    answer = _text(runner, ("nmcli", "-g", prop, "connection", "show", uuid))
    if answer is None:
        raise InstallRefused(
            f"{prop} of connection {uuid} could not be read (`nmcli -g {prop} connection show "
            f"{uuid}` failed); this install changes that property, and a property it cannot read "
            "is one it could not put back"
        )
    if prop in IGNORED_AUTOMATICALLY and answer not in ("yes", "no"):
        raise InstallRefused(
            f"{prop} of connection {uuid} is {answer!r}, which is neither 'yes' nor 'no'; this "
            "install refuses to change a property whose current value it cannot record, because a "
            "restore can only put back what was written down"
        )
    return answer


def _address_list(uuid: str, prop: str, answer: str) -> List[str]:
    """The addresses in one of the DNS list properties, or a refusal.

    Split on every separator NetworkManager has been seen to use for an array,
    because this module cannot measure which one a given release prints and guessing
    wrong is not a cosmetic error: an un-split list restores as ONE malformed
    address, and a machine whose DNS is a single malformed address has no DNS at
    all.

    Each address is then checked with `ipaddress`, and anything that is not one
    refuses the install. That is the fail-closed direction and the only safe one: a
    value the module cannot parse is a value its restore could not reproduce, and a
    backup that cannot be restored is worse than an install that declined to start.
    """
    tokens = [token for token in re.split(r"[,;\s]+", answer.strip()) if token]
    for token in tokens:
        try:
            ipaddress.ip_address(token)
        except ValueError as error:
            raise InstallRefused(
                f"{prop} of connection {uuid} is {answer!r}, and {token!r} in it is not an IP "
                f"address ({error}); this install refuses to change a connection whose manual DNS "
                "it cannot parse, because a restore can only put back what was written down"
            ) from error
    return tokens


def _config_digest(root: Path) -> str:
    """The SHA-256 of the configuration document, as this project already means it.

    The policy's own bytes, matching the digest `mosdns-cdnctl` stamps into the
    selector and the ECH state. An uninstall compares it to decide whether the
    operator has edited the configuration since the install, so a document that
    cannot be read is an install that cannot be accounted for later -- which is why
    this refuses rather than recording nothing.
    """
    import hashlib

    path = root / POLICY_CONFIG.lstrip("/")
    try:
        contents = path.read_bytes()
    except OSError as error:
        raise InstallRefused(
            f"{path} could not be read ({error}); the backup records the digest of the "
            "configuration this install ran under, so an uninstall can tell an operator's edits "
            "from ours, and a configuration it cannot digest is a change it cannot account for"
        ) from error
    return hashlib.sha256(contents).hexdigest()


def _dhcp_state(root: Path) -> dict:
    """The lease the capture just published, or a refusal.

    The backup records the lease this machine was following, because the whole
    reason the capture runs first is that a resolver pointed at the loopback makes
    the original resolvers un-followable: after the switch, nothing on the machine
    can read them back out of NetworkManager. A state file that cannot be read now
    is a lease this install will not be able to describe afterwards.
    """
    path = root / DHCP_STATE_FILE.lstrip("/")
    text = _read_text(path, "the published DHCP state")
    try:
        document = json.loads(text)
    except ValueError as error:
        raise InstallRefused(
            f"{path} is not the state document the bridge publishes ({error}); the backup records "
            "the lease this machine is following, and a document it cannot read is a lease it "
            "cannot describe"
        ) from error
    if not isinstance(document, dict):
        raise InstallRefused(f"{path} is not a JSON object; nothing has been changed")
    _check_dhcp_document(path, document)
    return document


def _check_dhcp_document(path: Path, document: dict) -> None:
    """Refuse a state whose resolvers or generation are not what the publisher writes.

    This is the one place the transaction reads a document written by ANOTHER
    program, and every other such document in this repository is refused rather
    than parsed loosely. Without the check a state whose `upstreams` is the string
    "192.0.2.53" is copied into the backup by `list()` as nine characters, and the
    backup then names a resolvers list of one character at a time -- which is worse
    than no backup, because it is one an operator cannot tell is wrong.

    The generation has to be a whole number for the same reason in miniature: it is
    the other half of what identifies this state, and a string in it means the file
    is not the document the bridge's publisher writes.
    """
    if "upstreams" not in document:
        raise InstallRefused(
            f"{path} names no `upstreams`, which every state the bridge's publisher writes carries; "
            "nothing has been changed"
        )
    upstreams = document["upstreams"]
    if not isinstance(upstreams, list):
        raise InstallRefused(
            f"{path} has `upstreams` as a {type(upstreams).__name__}, not a list of addresses; "
            f"{upstreams!r} would be copied into the backup one element at a time, and a backup "
            "naming a resolvers list of characters is one an operator cannot tell is wrong. Nothing "
            "has been changed"
        )
    for upstream in upstreams:
        try:
            ipaddress.ip_address(str(upstream))
        except ValueError as error:
            raise InstallRefused(
                f"{path} lists {upstream!r} among its resolvers, which is not an IP address "
                f"({error}); the backup records the resolvers this machine is following, and it "
                "cannot record one it cannot recognise. Nothing has been changed"
            ) from error
    generation = document.get("generation")
    if generation is not None and (type(generation) is not int or generation < 0):
        raise InstallRefused(
            f"{path} has a generation of {generation!r}, which is not a whole number of "
            "generations; nothing has been changed"
        )


def _ech_may_answer_locally(root: Path) -> bool:
    """Whether the router could answer the probe itself, under the policy as written.

    This mirrors two facts and refuses when they combine:

    * the plugin's `forcesECH` returns false when the policy has ECH turned OFF,
      whatever the list says -- there is no ECH to force, so there is no short
      circuit (`ECHPolicy.Enabled` is the model, `internal/config/policy.go:71`,
      and it is a plain bool, so the document's spelling of "off" is YAML's); and
    * the plugin's `failurePolicyOf` maps every failure policy except "fallback"
      onto `dnsrewrite.FailClosed`, and `internal/config`'s default is "strict".

    So the risky combination is: ECH not explicitly disabled, and the failure
    policy not "fallback". A policy with no `ech:` section at all is the risky
    one, because the config defaults fill both fields in -- reading a silent
    policy as the safe one would be exactly backwards, because silence is the
    default configuration.

    An unreadable policy answers True. The plugin would fail to load a policy it
    cannot parse, and the direction that leaves the check quiet is the direction
    that could wave a machine through, so the uncertain answer is the one that
    keeps looking.
    """
    body = _ech_section(root)
    if body is None:
        return True
    enabled = re.search(r"^\s+enabled:\s*(\S+)\s*$", body, flags=re.MULTILINE)
    if enabled is not None and enabled.group(1).strip('"').lower() in ("false", "no", "off"):
        return False
    policy = re.search(r"^\s+failure_policy:\s*(\S+)\s*$", body, flags=re.MULTILINE)
    if policy is not None and policy.group(1).strip('"').lower() == ECH_FALLBACK:
        return False
    return True


def _ech_section(root: Path) -> Optional[str]:
    """The policy's ``ech:`` block, or ``None`` when there is not one to read."""
    try:
        contents = (root / POLICY_CONFIG.lstrip("/")).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    section = re.search(r"^ech:\s*$(.*?)(?=^\S|\Z)", contents, flags=re.MULTILINE | re.DOTALL)
    return None if section is None else section.group(1)


def _forces_ech(entries: Sequence[str], name: str) -> bool:
    """The plugin's own match: EXACT, case-insensitive, trailing dot trimmed.

    Deliberately exact rather than suffix-based, because that is what
    `cdn_rewrite.forcesECH` does: it compares each entry to the canonical name with
    `strings.EqualFold`. A mirror that matched a suffix would refuse installations
    the plugin would answer downstream like any other name, and one that matched
    loosely in the other direction would claim a cover it does not have.
    """
    bare = name.rstrip(".").lower()
    return any(entry.strip().rstrip(".").lower() == bare for entry in entries)


def _refuse_a_locally_answered_probe(root: Path) -> None:
    """Refuse the install when the router would answer the health check itself.

    Read before the first mutation, and it costs no command: the policy is a file
    and the list is a file, so the sequence of argument arrays every order
    assertion is written against is unchanged by this check existing.

    A refusal, rather than a note, because the alternative is worse than a failed
    install: proceeding means the wait, the barrier and the verification are all
    satisfied by a NOERROR the router fabricated, NetworkManager is pointed at the
    loopback, and the machine loses resolution with every check reporting success.
    That is the one outcome this whole transaction exists to prevent, and it is
    reachable through a single line in a file the operator is invited to edit.
    """
    if not _ech_may_answer_locally(root):
        return
    entry = next(
        (name for name in _forced_ech_domains(root) if _forces_ech((name,), INSTALL_PROBE_NAME)),
        None,
    )
    if entry is None:
        return
    raise InstallRefused(
        f"{FORCE_ECH_DOMAINS} lists {entry!r}, and the policy asks for strict ECH, so the router "
        f"answers A queries for that name itself without asking anything upstream. This install "
        f"checks that {LOCAL_DNS} can actually resolve by asking it for {INSTALL_PROBE_NAME}, and "
        "a name on that list would be answered locally whatever the upstream is doing, so the "
        f"check would pass on a machine that cannot resolve anything. Remove the {entry!r} line from "
        f"{FORCE_ECH_DOMAINS}, or set ech.failure_policy to fallback in {POLICY_CONFIG}, and run the "
        "install again. Nothing has been changed"
    )


def prepare_backup(root: Path, runner: CommandRunner, connection: Connection, now) -> dict:
    """Read every value the transaction will change, and return the backup document.

    Nothing is written here. The document is built from reads only, so a step that
    cannot read is a refusal before any mutation, and the document that comes out
    of this function is the only source of an original value anywhere in the
    transaction -- which is what makes "restore only what was recorded" a property
    of the code rather than a promise in a review.
    """
    version = _package_version(runner)
    original: dict = {}
    for prop in RECORDED_PROPERTIES:
        answer = _original_property(runner, connection.uuid, prop)
        if prop in ADDRESS_LISTS:
            original[prop] = {"raw": answer, "value": _address_list(connection.uuid, prop, answer)}
        else:
            original[prop] = {"raw": answer, "value": answer}
    dhcp = _dhcp_state(root)
    return {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "managed_by": MANAGED_BY_VALUE,
        "package": PACKAGE_NAME,
        "package_version": version,
        "created_at": _stamp(now()),
        "config_path": POLICY_CONFIG,
        "config_sha256": _config_digest(root),
        "connection": {
            "uuid": connection.uuid,
            "name": connection.name,
            "type": connection.kind,
            "device": connection.device,
        },
        "original": original,
        "dhcp": {
            "state_file": DHCP_STATE_FILE,
            "interface": dhcp.get("interface", connection.device),
            "connection_uuid": dhcp.get("connection_uuid", connection.uuid),
            "upstreams": list(dhcp.get("upstreams") or []),
            "source": dhcp.get("source", ""),
            "generation": dhcp.get("generation", 0),
            "observed_at": dhcp.get("observed_at", ""),
        },
    }


def _carried_forward(root: Path, document: dict) -> dict:
    """The document a RE-install writes: the previous record kept, the rest fresh.

    A first install reads the machine's DNS properties and records them; that is
    the one moment the values mean what the backup says they mean. On a machine
    this package has already installed, the same three properties hold
    `yes`/`yes`/`127.0.0.1` -- this package's own values -- so the only correct
    `original` block on a re-install is the one the FIRST install wrote. Carrying
    it forward is what makes a re-install a re-install rather than a second
    installation: refusing it outright would push an operator who wants to
    re-run the install into hand-editing `/etc`, and silently re-recording the
    loopback as the machine's own resolver is the one outcome this whole program
    exists to prevent -- the next removal would then take the machine's resolver
    with it while reporting that everything was fine.

    Two things it will not do, and both are refusals rather than guesses. The
    third case -- a first install, with nothing to carry forward -- is not one of
    them and must never become one:

      * **Carry a record it cannot read.** The record is the only thing that knows
        what the machine's DNS was, so a record that is absent with the marker
        claiming this machine, or a record that is present and unusable, both
        leave the only values available being this package's own -- and writing
        those would manufacture a record rather than keep one.
      * **Keep a record that is about a different connection.** The record is
        what `uninstall` and `emergency-rollback` restore from, and they restore
        the one connection it names. A re-install working on a second connection
        cannot have one record for both, and replacing the first would leave that
        connection pointed at the loopback with nothing to put back.

    The reader is `_read_backup`, the same one the uninstall uses and the same
    standard of what a usable record is -- so a document carried forward here is
    one an uninstall would act on rather than one that merely parsed.

    THE GATE IS THE RECORD, not the marker, and getting that backwards is the
    whole of the second version of this bug.

    An earlier version asked `_installation_is_ours` -- the MARKER -- whether to
    carry anything forward, and that is the wrong question by one state. The
    marker is a claim about the INSTALL: it is written last, after the health
    check and the verification, so it is absent on every machine whose install did
    not run to completion -- and the machine that matters most here is exactly
    that one. An install that changed the connection and then failed with a
    rollback that did not finish leaves a RECORD of the machine's original DNS,
    NO marker, and a connection still handing resolved the loopback address. The
    routine repair for that is `dpkg --configure mosdns-router`, which dpkg itself
    offers after a failed configure: it re-reads the connection -- which now holds
    `yes`/`yes`/`127.0.0.1`, this package's own values -- wrote them over the
    record, and SUCCEEDED. The next removal then restored the loopback, stopped
    both units and reported `ok=True`.

    So the record is what knows the machine's original, and the marker is a claim
    about the install that is missing precisely where the record matters most. A
    record is a fact about the MACHINE; a marker is a fact about a RUN. This
    function is about the machine, and it is gated on the record.

    What that leaves, and all three are refusals or a first install rather than a
    guess:

      * **A record that is present and not usable.** The machine's original is
        unknown, and the values this run would write down are this package's own.
        It refuses, and it names which field of the record is missing, because
        "the backup is not usable" is not something an operator can act on and
        "the record has no `ipv4.dns`" is.
      * **No record at all, with the marker claiming this machine.** The marker
        says the DNS is ours and the record of what it was is gone, so the only
        values left to write are ours. Same refusal, same reason, reached from the
        other side -- and `_never_applied` treats the mirror image of it
        (no marker, no record) as provably-never-applied, which is the complement
        of this arm rather than a contradiction of it.
      * **A first install.** No record, no claim, nothing to keep, so the fresh
        document is written. This is the ordinary case and it must not be refused.

    THE COST, stated rather than discovered later: a release that changes the
    schema cannot re-install over a machine an older release installed, because
    `_read_backup` refuses a version it does not know and this arm then refuses
    the install. The operator's route is the refusal's own advice. The alternative
    is writing a fresh document over the only record of the machine's original
    DNS, which is the outcome this function exists to prevent, so the refusal is
    the right side of that trade.
    """
    recorded, refusals = _read_backup(root)
    if recorded is None:
        # Three states and the difference between them is the whole of the gate.
        # `_path_state` rather than "did the file open" because a record that is
        # ABSENT and a record that is present-but-damaged are different machines:
        # the first is a first install (or a refused one), and the second is a
        # machine whose original this program can no longer say.
        if _path_state(root / BACKUP_PATH.lstrip("/")) == "absent" and not _installation_is_ours(root):
            return document
        claim = (
            f"{MANAGED_BY} says this machine is already running this package's DNS, and "
            if _installation_is_ours(root)
            else ""
        )
        raise InstallRefused(
            f"{claim}{BACKUP_PATH} is not a record this program can read, and it is the only "
            "thing that knows what this machine's DNS was set to before this package touched it ("
            + "; ".join(refusals)
            + "), so this install cannot record what the machine had: the values it would "
            f"write down are the ones this package itself set -- {_set_values_now(document)} -- and "
            "recording those would destroy the record of the machine's real settings rather than "
            "keep it. Nothing on this machine's DNS configuration has been changed; the DHCP lease "
            "this run published under /run/mosdns before it got here is this package's own state "
            f"and says nothing about the connection. Restore the record, or remove this package "
            f"with `dpkg --force-remove-reinstreq` once the connection is back on the machine's own "
            "resolvers"
        )
    recorded_uuid = str(recorded["connection"]["uuid"])
    fresh_uuid = str(document["connection"]["uuid"])
    if recorded_uuid != fresh_uuid:
        raise InstallRefused(
            f"{BACKUP_PATH} records what connection {recorded_uuid} was set to, and this install "
            f"is working on connection {fresh_uuid}; one record cannot describe two connections, "
            "and replacing the first would leave it pointed at the loopback address with nothing to "
            "put back. Nothing on this machine's DNS configuration has been changed; the DHCP lease "
            "this run published under /run/mosdns before it got here is this package's own state "
            "and says nothing about the connection. Remove this package (which restores "
            f"{recorded_uuid} through the record that is already there) and install it again to "
            f"work on {fresh_uuid}"
        )
    carried = dict(recorded)
    for field in VOLATILE_BACKUP_FIELDS:
        carried[field] = document[field]
    return carried


def _set_values_now(document: dict) -> str:
    """The three values a re-install would record, spelled out for a refusal.

    Only ever used to say what this program is NOT going to write down, so an
    operator reading the refusal can see the machine's record and the package's
    own values side by side and tell which is which.
    """
    return ", ".join(
        f"{prop}={document['original'][prop]['raw']!r}" for prop, _value in NM_MUTATIONS
    )


def write_backup(root: Path, document: dict) -> tuple:
    """Write the backup at mode 0600 under the installer directory, and return it.

    Returns ``(path, document)``, and the document is the one as WRITTEN, which on
    a machine this package has already installed is not the one that was passed
    in: :func:`_carried_forward` keeps the first install's record of the machine
    and refreshes only the fields that are about this run. `validate_backup` is
    handed the written document rather than the intended one, so a carry-forward
    that did not survive the round trip is still caught here.

    The directory is created at 0700 when it is not there and is NOT
    re-permissioned when it is, for the reason preflight never repairs anything: a
    directory the package already made belongs to the package, and the install
    writes into it rather than deciding what it should be.

    The mode is set after the write rather than through the open, because the
    standard library's own file-opening call is the one `os` attribute this
    module's allowlist refuses -- and the window that would close is inside a
    directory this function has just made root-only, so nothing else can reach the
    file while it is briefly at the umask's mode.
    """
    document = _carried_forward(root, document)
    directory = root / INSTALLER_DIRECTORY.lstrip("/")
    if _path_state(directory) == "absent":
        try:
            directory.mkdir(parents=True, mode=INSTALLER_DIRECTORY_MODE)
            directory.chmod(INSTALLER_DIRECTORY_MODE)
        except OSError as error:
            raise InstallRefused(
                f"{INSTALLER_DIRECTORY} could not be created ({error}); it is where the record of "
                "this machine's original DNS settings lives, so an install that cannot write it "
                "must not change anything"
            ) from error
    path = root / BACKUP_PATH.lstrip("/")
    try:
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(BACKUP_MODE)
    except OSError as error:
        raise InstallRefused(
            f"{path} could not be written ({error}); this install changes NetworkManager's DNS and "
            "the record of what it was has to be readable before it does"
        ) from error
    return path, document


def validate_backup(root: Path, document: dict) -> None:
    """Read the backup back and check it against what was meant to be written.

    "Wrote a file" is not the same claim as "there is a file that can be read back
    and says the right thing", and the difference is the whole of what a rollback
    and a manual recovery depend on. So the file is asked about with `lstat` (a
    path that exists and cannot be read is a failure, not an absence), its mode is
    read from the inode rather than trusted, and the decoded document is compared to
    the one in hand -- so the message can name the field that disagrees rather than
    only saying that they differ.

    The schema version and the marker are checked on their own after the
    comparison, because they are the two fields a future release has to refuse
    rather than guess at, and a message that only said "the documents differ" would
    not tell an operator which of the two it was.
    """
    path = root / BACKUP_PATH.lstrip("/")
    state = _path_state(path)
    if state != "a regular file":
        raise InstallRefused(
            f"{BACKUP_PATH} is {state} after being written, so the record of this machine's "
            "original DNS settings cannot be read back; nothing has been changed, and a backup "
            "that cannot be read is not a backup"
        )
    try:
        mode = stat.S_IMODE(path.lstat().st_mode)
    except OSError as error:
        raise InstallRefused(
            f"{BACKUP_PATH} could not be stat'd after being written: {error}"
        ) from error
    if mode != BACKUP_MODE:
        raise InstallRefused(
            f"{BACKUP_PATH} is at mode {mode:04o} rather than {BACKUP_MODE_OCTAL}; it names this "
            "machine's resolvers and its connection, so it is readable by root and by nobody else, "
            "and an install that cannot make it so must not change anything"
        )
    text = _read_text(path, "the backup")
    try:
        written = json.loads(text)
    except ValueError as error:
        raise InstallRefused(
            f"{BACKUP_PATH} is not a JSON document after being written ({error}); nothing has been "
            "changed"
        ) from error
    if written != document:
        differences = sorted(
            key for key in set(written) | set(document) if written.get(key) != document.get(key)
        )
        raise InstallRefused(
            f"{BACKUP_PATH} does not read back as the document that was written; "
            f"{', '.join(differences) if differences else 'the documents differ'} disagree(s). "
            "Nothing has been changed: a rollback and a manual recovery both work from this file, "
            "and one whose contents are not the ones that were recorded is worse than none"
        )
    if written.get("schema_version") != BACKUP_SCHEMA_VERSION:
        raise InstallRefused(
            f"{BACKUP_PATH} names schema version {written.get('schema_version')!r} rather than "
            f"{BACKUP_SCHEMA_VERSION}; nothing has been changed"
        )
    if written.get("managed_by") != MANAGED_BY_VALUE:
        raise InstallRefused(
            f"{BACKUP_PATH} names {written.get('managed_by')!r} rather than {MANAGED_BY_VALUE!r}, "
            "so it is not a record of this project's changes; nothing has been changed"
        )


def _unit_states(runner: CommandRunner) -> dict:
    """Whether each owned unit was running and enabled before this transaction.

    Read once, before anything is enabled, and read conservatively: only a definite
    `inactive`/`failed` and a definite `disabled`/`not-found` mean the transaction
    may undo the corresponding change afterwards. Anything else -- including a
    query that could not be answered -- is read as "it was already that way",
    because a rollback that stops or disables a unit somebody else was running is
    the harm this rule exists to prevent, and leaving one running is a smaller,
    reversible, reportable one.

    Returns the states and the units whose active state could not be read at all.
    The second is not a detail: such a unit is one this run may start and then
    decline to stop, and a caller that then claims the machine is unchanged has to
    except it by name rather than assert the opposite.
    """
    states = {}
    unreadable = []
    for unit in OWNED_UNITS:
        # A blank answer is unreadable as well as a missing one, and for the same
        # reason: `is-active` on a unit that does not exist prints nothing at all,
        # so "" and "the call failed" are one fact -- this program cannot say --
        # and both have to become "was already running".
        active = _text(runner, ("systemctl", "is-active", unit))
        enabled = _text(runner, ("systemctl", "is-enabled", unit))
        if not active:
            unreadable.append(unit)
        states[unit] = {
            UNIT_ACTIVE: active is None or active not in NOT_ACTIVE,
            UNIT_ENABLED: enabled is None or enabled not in NOT_ENABLED,
        }
    return states, unreadable


def _enable(runner: CommandRunner, transaction: Transaction, unit: str, states: dict) -> None:
    """Enable a unit, and record how to take that back if this was not its state."""
    _checked(runner, ("systemctl", "enable", unit), f"enabling {unit}")
    if states[unit][UNIT_ENABLED]:
        return
    transaction.apply_unit(
        f"enabling {unit}",
        lambda unit=unit: _checked(runner, ("systemctl", "disable", unit), f"disabling {unit}"),
        unit,
    )


def _start(
    runner: CommandRunner,
    transaction: Transaction,
    unit: str,
    states: dict,
    unreadable: Sequence[str],
) -> None:
    """Put the unit into the state this run needs, and record how to undo that.

    Three cases, and the middle one is the reason this function is not one line.

    **Not running before** -- `start`, and a stop is registered, because this run
    is what made it run.

    **Running before** -- `try-restart`, and a RESTART is registered as the undo,
    because it was already running and the only way to put a unit back the way it
    was found is to have it running again. `try-restart` rather than `start`
    because `start` on an active unit is a no-op: this is the ordinary path of an
    UPGRADE, where dpkg has just unpacked a new binary and a new generated
    `/etc/mosdns/mosdns.yaml` over a machine that is already running the old
    ones. Starting nothing would leave every check that follows -- the two waits,
    the barrier, the device's verification, the exit-0 message about ports 53 and
    15353 -- describing the processes that were there before the upgrade, and the
    caller would be told it verified this release. The wait the caller does next
    is what makes the restart observable rather than merely issued.

    **State unreadable** -- `start` only, never `try-restart`, and no stop, and
    the transaction is told. `try-restart` STOPS the unit first, and the only
    reason this case exists is that this program does not know whether the unit
    was already running; stopping somebody else's unit is the harm the prior
    state rule exists to prevent. Leaving one running is recorded rather than
    hidden, so the report can name the unit it left as it found it instead of
    claiming the machine is unchanged.

    WHY THE RESTART'S UNDO GOES ON THE STACK FIRST, which is the whole of the
    middle case and the reason it is not symmetric with the first.

    `try-restart` STOPS the unit on its way to restarting it, so a `try-restart`
    that fails may well have left a unit that WAS running down -- and on an upgrade
    the connection is already `127.0.0.1` by the time this runs, so that is a
    machine with no resolver at all. An undo registered after the attempt is not
    on the stack when the rollback runs, so exit 3 says "every change this run
    made has been rolled back, and nothing else is different about this machine"
    about a machine whose resolver this run took down. The same argument, and the
    same shape, as `_reconnect`'s; the two are now the only two places in the
    transaction where the undo is registered first.

    The price is recorded rather than hidden: a `try-restart` that fails twice --
    the attempt and the rollback's own -- is a rollback FAILURE (exit 4), because
    on that machine the unit really is down and no undo in this program can put
    it back. :func:`_failed` says so in those words and names `emergency-rollback`
    as the action, and the decision is recorded in the fix report.

    Nothing about the FIRST case is asymmetric in the same way, and it is worth
    being explicit about why, because the two look identical in the command list.
    `start` on a unit that was not running cannot have stopped anything: if it
    fails, the unit is where it was, so there is nothing to undo and the stop
    registered afterwards is the undo of a success rather than of an attempt.
    """
    uncertain = unit in unreadable
    if states[unit][UNIT_ACTIVE] and not uncertain:
        # Registered BEFORE the attempt, for the reason in the docstring. The
        # undo is the same command because putting a running unit back the way it
        # was IS restarting it, and it is idempotent in the way that matters: a
        # rollback reaches the same state whether the restart succeeded or failed.
        transaction.apply_unit(
            f"restarting {unit}, which was already running",
            lambda unit=unit: _checked(
                runner,
                ("systemctl", "try-restart", unit),
                f"restarting {unit} again, because it was already running before this run and a "
                "restart that failed may have left it down",
            ),
            unit,
            was_running=True,
        )
        _checked(
            runner,
            ("systemctl", "try-restart", unit),
            f"restarting {unit}, which was already running, so the version this package just "
            f"installed is the one that serves {LOCAL_DNS}",
        )
        return
    _checked(runner, ("systemctl", "start", unit), f"starting {unit}")
    # The unreadable case is asked here, after the `start` and before the stop is
    # registered, because an unreadable state reads as "was already running" and
    # the early return above would swallow it: the transaction would push no stop,
    # correctly, and record nothing, so the report would claim a machine is
    # unchanged while a unit this run started is still running.
    if uncertain:
        transaction.note_uncertain_unit(unit)
        return
    transaction.apply_unit(
        f"starting {unit}",
        lambda unit=unit: _checked(runner, ("systemctl", "stop", unit), f"stopping {unit}"),
        unit,
    )


def _restore_value(prop: str, recorded: dict) -> str:
    """The single argument that puts one property back the way it was.

    An address list is joined with commas, which is the separator nmcli's own
    property parser accepts, and an ignore-auto-dns is the `yes` or `no` that was
    recorded. Nothing else is ever written: a value this function did not get from
    the backup is a value nothing read, and the whole point of recording before
    mutating is that no restore has to guess.
    """
    value = recorded[prop]["value"]
    return ",".join(value) if isinstance(value, list) else value


def _apply_nm(
    runner: CommandRunner, transaction: Transaction, connection: Connection, document: dict
) -> None:
    """Make the three property changes, each with its own recorded undo.

    The UUID is a separate argument throughout, and never the connection's name:
    `GENERAL.CONNECTION` holds a profile's name, a name is not a UUID, and a modify
    aimed at a name is a modify aimed at the wrong thing with no error.

    Each undo is pushed immediately after its own mutation succeeded, so a failure
    halfway through the three leaves exactly the ones that happened on the stack
    and nothing else.
    """
    recorded = document["original"]
    for prop, value in NM_MUTATIONS:
        _checked(
            runner,
            ("nmcli", "connection", "modify", connection.uuid, prop, value),
            f"setting {prop} to {value} on {connection.uuid}",
        )
        put_back = _restore_value(prop, recorded)
        transaction.apply_profile(
            f"setting {prop} to {value} on {connection.uuid}",
            lambda prop=prop, put_back=put_back: _checked(
                runner,
                ("nmcli", "connection", "modify", connection.uuid, prop, put_back),
                f"putting {prop} back to {put_back!r} on {connection.uuid}",
            ),
        )


def _reconnect(runner: CommandRunner, transaction: Transaction, connection: Connection) -> None:
    """Reactivate the one connection, and record that the undo is to reactivate it.

    Reactivating this connection is the design; reloading or restarting
    NetworkManager would take every other connection on the machine with it,
    including a VPN and a second uplink, so nothing here does that.

    The undo is the same command, and that is not a placeholder. The properties
    above are written to the connection's *profile*, and a profile change reaches
    the live device only when the connection is brought up again -- so a rollback
    that restored the properties and stopped here would leave a machine whose
    NetworkManager was still handing resolved the loopback address, with the
    recorded values sitting unused on disk. Reactivating is what makes the restore
    take effect, and it is idempotent, so a rollback reaches the same state whether
    the reconnection succeeded or failed.

    The undo is registered BEFORE the attempt, which is the one place in the
    transaction where that order is load-bearing rather than tidy. `nmcli
    connection up` takes a connection DOWN on its way up, so a run in which it
    fails may well have left the machine with no uplink -- and an undo registered
    afterwards is not on the stack when the rollback runs, so exit 3 says "every
    change this run made has been rolled back and nothing else is different about
    this machine" about a machine whose connection this run deactivated. The price
    is that a reactivation which fails twice is a rollback FAILURE (exit 4) rather
    than a clean refusal, which is the truth about that machine.
    """
    transaction.apply_reactivating(
        f"reactivating {connection.uuid}",
        lambda: _checked(
            runner,
            ("nmcli", "connection", "up", connection.uuid),
            f"reactivating {connection.uuid} again to apply what was put back",
        ),
    )
    _checked(
        runner,
        ("nmcli", "connection", "up", connection.uuid),
        f"reactivating {connection.uuid}",
    )


def _verify(runner: CommandRunner, ask, connection: Connection) -> None:
    """Check that the machine is really using the loopback, and that it answers.

    Three questions, and each of them can fail the install. `resolvectl` has to
    name the loopback for this device, which is the observable consequence of the
    three properties and of nothing else; the router has to answer a real query
    again, in case it died between the health check and the reconnection; and
    resolved's own stub has to answer, because a stub that has stopped speaking is
    a machine with no resolver at all however correct the properties are.

    This is the step that catches a NetworkManager which accepted the change and
    did not apply it -- the failure mode a successful `nmcli` and a correct backup
    both miss.
    """
    forwarding = _text(runner, ("resolvectl", "dns", connection.device))
    if forwarding is None:
        raise InstallRefused(
            f"resolvectl could not be asked what {connection.device} is using for DNS; the "
            "properties were set to use the loopback and nothing has confirmed that resolved took "
            "them, so the transaction is being undone rather than claimed as installed"
        )
    if LOCAL_DNS not in forwarding.split():
        raise InstallRefused(
            f"resolvectl reports {connection.device} using {forwarding!r} rather than the loopback "
            f"address {LOCAL_DNS}, so NetworkManager accepted the properties and did not apply "
            "them; the transaction is being undone rather than leaving a machine that resolves "
            "nothing"
        )
    if not ask(LOCAL_DNS, DNS_PORT).resolves:
        raise InstallRefused(
            f"the router did not resolve {INSTALL_PROBE_NAME} at {LOCAL_DNS}:{DNS_PORT} after the "
            "reconnection, though it resolved before NetworkManager was pointed at it; the "
            "transaction is being undone rather than leaving the machine's DNS pointing at a chain "
            "that cannot resolve"
        )
    if not ask(RESOLVED_STUB_ADDRESS, DNS_PORT).resolves:
        raise InstallRefused(
            f"systemd-resolved's stub at {RESOLVED_STUB_ADDRESS}:{DNS_PORT} did not resolve "
            f"{INSTALL_PROBE_NAME} after the reconnection, so /etc/resolv.conf points at a chain "
            "that cannot resolve; the transaction is being undone"
        )


def _undo_marker(path: Path, previous: Optional[str]) -> None:
    """Put the ownership marker back the way it was, byte for byte.

    A marker that was not there is removed, and one that was is written back
    exactly, because on a re-install the marker that was there belongs to a router
    that is still installed and still running.
    """
    if previous is None:
        try:
            path.unlink()
        except FileNotFoundError:
            return
    else:
        path.write_text(previous, encoding="utf-8")
        path.chmod(MARKER_MODE)


def _commit_marker(root: Path, transaction: Transaction) -> None:
    """Write the ownership marker, last, and record what has to happen if it cannot stay.

    The marker is the claim an uninstall reads to decide whether the DNS on this
    machine is this package's to change back, so it is written after the health check
    and after the verification, and an install that failed anywhere above leaves
    none. A machine with this package's DNS on it and no marker is a machine an
    uninstall will refuse to restore automatically, which is the correct answer and
    the reason the write is the last step rather than an early one.

    The marker that was already there is read first and put back byte for byte if
    anything later fails, so a failed re-install cannot make a later uninstall refuse
    to restore a machine it should have restored.
    """
    path = root / MANAGED_BY.lstrip("/")
    previous: Optional[str] = None
    if _path_state(path) == "a regular file":
        previous = _read_text(path, "the existing ownership marker")
    try:
        path.write_text(MANAGED_BY_VALUE + "\n", encoding="utf-8")
        path.chmod(MARKER_MODE)
    except OSError as error:
        raise InstallRefused(
            f"{MANAGED_BY} could not be written ({error}); the marker is what tells an uninstall "
            "that the DNS on this machine is this package's, so an install that cannot record that "
            "is being undone rather than claimed as installed"
        ) from error
    transaction.apply_unit(f"writing {MANAGED_BY}", lambda: _undo_marker(path, previous))


def _run_transaction(
    root: Path,
    runner: CommandRunner,
    connection: Connection,
    ask,
    transaction: Transaction,
    now,
    deadline_seconds: float,
    poll_seconds: float,
    notes: List[str],
) -> None:
    """Every step, in the only order this program runs them in.

    The numbered order at the head of this section is the design; this function is
    that order written out, and the barrier comment below is the one line of it
    that a future edit must not move.
    """
    # Before the capture, and that order is the point rather than an accident.
    # The capture PUBLISHES: it writes the DHCP state and a new generation, so a
    # guard that ran after it could not honestly say "nothing has been changed".
    # This one has no dependency on the capture -- it reads the policy and the
    # operator's list, two files, and issues no command -- so it costs nothing to
    # put first, and putting it first makes the refusal's claim literally true.
    _refuse_a_locally_answered_probe(root)
    _capture_dhcp(runner, connection.device)
    document = prepare_backup(root, runner, connection, now)
    path, document = write_backup(root, document)
    validate_backup(root, document)
    transaction.backup = str(path)

    states, unreadable = _unit_states(runner)
    for unit in OWNED_UNITS:
        _enable(runner, transaction, unit, states)

    # Between the enables and the first start, which is where the ledger put it and
    # where it has to be: the router is the unit that refuses to start without the
    # list, so publishing it after the router has been started would be too late to
    # matter. A non-zero status is a refusal and never a warning, because there is
    # no later moment at which anything else will publish it: the nightly timer is
    # hours away, and the install is the only moment at which nothing has.
    #
    # No undo is registered. Republishing an already-published list is idempotent,
    # and a rollback that un-published it would leave a router that will not start,
    # which is a worse state than the list it was published from.
    _checked(
        runner,
        PUBLISH_PREFIXES,
        "publishing the Cloudflare prefix list, which the router refuses to start without",
    )

    restarted = [
        unit
        for unit, _port in ((RESOLVER_UNIT, RESOLVER_PORT), (ROUTER_UNIT, DNS_PORT))
        if unit not in unreadable and states[unit][UNIT_ACTIVE]
    ]
    for unit, port in ((RESOLVER_UNIT, RESOLVER_PORT), (ROUTER_UNIT, DNS_PORT)):
        _start(runner, transaction, unit, states, unreadable)
        if not wait_for_dns(LOCAL_DNS, port, ask, deadline_seconds, poll_seconds):
            raise InstallRefused(
                f"{unit} was started but nothing answered a DNS query at {LOCAL_DNS}:{port} within "
                f"{deadline_seconds:g}s, so the machine has no local resolver to point "
                "NetworkManager at; nothing has been pointed at anything and the transaction is "
                "being undone"
            )
    if restarted:
        notes.append(
            " and ".join(restarted)
            + " were already running, so they were RESTARTED rather than started: everything "
            "verified below describes the binaries and the configuration this package just "
            "installed, and not the ones that were running before it"
        )

    # The barrier. Everything above is reversible by stopping two units; the three
    # properties below are the ones that can leave a machine with no resolver at all,
    # and they are not touched until a real query has come back from the machine's own
    # resolver AND that query came back resolved rather than as a SERVFAIL from a
    # chain whose upstream is unreachable. The second half is what the waits cannot
    # do: a SERVFAIL is an answer, and reading it as proof the machine can resolve
    # is how this check would hand a machine to a chain that cannot.
    if not ask(LOCAL_DNS, DNS_PORT).resolves:
        raise InstallRefused(
            f"the router answered at {LOCAL_DNS}:{DNS_PORT} but did not resolve "
            f"{INSTALL_PROBE_NAME} -- a SERVFAIL, a REFUSED or silence all mean the chain cannot "
            "reach a resolver, and this install will not point a working machine at a chain it has "
            "seen fail; nothing has been changed on the machine's connection"
        )

    _apply_nm(runner, transaction, connection, document)
    _reconnect(runner, transaction, connection)
    _verify(runner, ask, connection)
    _commit_marker(root, transaction)
    notes.append(
        f"{connection.name} ({connection.device}, {connection.uuid}) now uses the loopback address "
        f"{LOCAL_DNS}; the original settings are recorded in {BACKUP_PATH}"
    )


def install(
    root: Path,
    run: CommandRunner,
    clock=None,
    probe=None,
    deadline_seconds: float = WAIT_DEADLINE_SECONDS,
    poll_seconds: float = WAIT_POLL_SECONDS,
) -> InstallResult:
    """Take this machine's DNS over, transactionally, and report what happened.

    ``root`` is the filesystem to read and write, which is the real ``/`` in
    production and a temporary directory in a test; ``run`` is the only way this
    module reaches a command, exactly as in :func:`preflight`; ``clock`` is the time
    the backup is stamped with.

    ``probe`` and the two intervals are the second seam, and they exist because a
    socket is the one thing an injected runner cannot stand in for. The default is
    the real prober, and the transaction's tests pass a scripted one -- so a test
    never opens a socket to the machine's own resolver ports, and a test that wanted
    the real thing would have to ask for it by name.

    Nothing here raises. The result carries the failure and the rollback failure as
    two separate fields, because "the install did not finish" and "the machine is not
    as it was found" are two different facts, and an operator deciding whether to
    reach for the backup needs both.
    """
    root = Path(root)
    now = clock or _utcnow
    ask = probe or (lambda address, port: probe_dns(address, port))
    notes: List[str] = []

    report = preflight(root, run)
    if not report.ok:
        return InstallResult(
            ok=False,
            backup=None,
            report=report,
            notes=list(report.notes()),
            error="preflight refused this machine, so nothing was captured, backed up or changed: "
            + "; ".join(report.problems()),
            rollback_error=None,
            recovery=None,
            left_running=[],
        )
    notes.extend(report.notes())
    connection = report.connection
    if connection is None:  # pragma: no cover - a passing preflight always sets it
        return InstallResult(
            ok=False,
            backup=None,
            report=report,
            notes=notes,
            error="preflight accepted this machine without naming a connection, so there is "
            "nothing to back up and nothing to change",
            rollback_error=None,
            recovery=None,
            left_running=[],
        )

    transaction = Transaction()
    try:
        _run_transaction(
            root, run, connection, ask, transaction, now, deadline_seconds, poll_seconds, notes
        )
    except InstallRefused as error:
        failures = transaction.rollback()
        return _failed(transaction, report, notes, str(error), failures)
    except Exception as error:  # noqa: BLE001 - see below
        # A step that fails in a way this program did not predict -- a bug here, a
        # runner that raises something exotic, a filesystem that answers in an
        # unforeseen way -- is rolled back exactly like a predicted one. That is
        # the whole reason this catch is broad: the alternative is a traceback out
        # of a transaction that has already pointed a machine's DNS at a
        # loopback address, which is the single worst outcome available here, and
        # the exit status of an uncaught exception is the same 1 a refusal uses,
        # so a script would read a half-applied install as a clean refusal.
        failures = transaction.rollback()
        return _failed(
            transaction,
            report,
            notes,
            f"the install failed in a way this program does not recognise, which is a bug in it: "
            f"{type(error).__name__}: {error}",
            failures,
        )
    return InstallResult(
        ok=True,
        backup=transaction.backup,
        report=report,
        notes=notes,
        error=None,
        rollback_error=None,
        recovery=None,
        left_running=[],
    )


def _failed(transaction: Transaction, report: Preflight, notes: List[str], error: str, failures) -> InstallResult:
    """The result of an install that did not finish, with what a person still owes.

    ``recovery`` is built from WHICH group of undo failed, because the three leave
    the machine in three different states:

      * the reactivation -- every value on disk is back to what it was, and the
        device simply never picked them up, so the machine's DNS may not be in use
        and one ``nmcli connection up`` finishes it;
      * the profile -- the connection is still handing resolved the loopback
        address, and the recorded values have to be written back by hand before the
        reactivation means anything;
      * the units -- a unit this run started is still running, and one
        ``systemctl stop`` finishes it.

    And the one arm that is not a housekeeping matter. A unit that was ALREADY
    running when this run began is restarted, not started, and its undo is another
    restart; a restart that fails twice leaves it DOWN, on a machine whose
    connection this run may already have pointed at the loopback. That is not "a
    unit is still running" and telling an operator to ``systemctl stop`` a resolver
    that is already stopped would be the wrong instruction twice over. So it gets
    its own sentence: the machine may have NO RESOLVER, and the action is
    ``emergency-rollback`` -- the one condition in this program where pointing at
    it matters most, because there is no unit left to start and no profile value
    left to write.
    """
    groups = {failure.group for failure in failures}
    steps = []
    uuid = connection_of(report)
    if Transaction.PROFILE in groups:
        steps.append(
            f"{Transaction.PROFILE} was not put back, so the connection may still be handing "
            f"resolved the loopback address {LOCAL_DNS}; {BACKUP_PATH} lists the values it had"
        )
    if Transaction.REACTIVATING in groups:
        steps.append(
            f"the recorded values are back on the profile of {uuid} but the connection was never "
            f"reactivated, so the machine's DNS may not be in use; `nmcli connection up {uuid}`, or "
            "a reboot, is what finishes it"
        )
    unit_failures = [failure for failure in failures if failure.group == Transaction.UNITS]
    # The two halves of the unit group, and they are opposites. `stop` is the undo
    # of a start, so a start whose stop did not run leaves a unit this program
    # STARTED running. A restart's undo is a restart, so a restart whose undo did
    # not run leaves a unit that was ALREADY running down. The second is the
    # dangerous one and it is a different sentence with a different action.
    stuck = sorted({failure.unit for failure in unit_failures if failure.unit and not failure.was_running})
    down = sorted({failure.unit for failure in unit_failures if failure.unit and failure.was_running})
    if down:
        # Written with the number's grammar spelled out rather than with a
        # placeholder, because this is a message an operator reads once, on a
        # machine with no resolver, and "they/them" in a sentence about one unit
        # is the sort of thing that makes a reader doubt the rest of it.
        subject = down[0] if len(down) == 1 else " and ".join(down)
        verb = "was" if len(down) == 1 else "were"
        pronoun = "it" if len(down) == 1 else "them"
        plural = len(down) > 1
        steps.append(
            f"THIS MACHINE MAY HAVE NO RESOLVER. {subject} {verb} running before this run began, "
            f"and the rollback could not put {pronoun} back up: this run RESTARTED {pronoun} rather "
            f"than starting {pronoun}, because the unit{'s' if plural else ''} "
            f"{'were' if plural else 'was'} already serving, and a restart that fails STOPS the "
            f"unit first -- so there may now be nothing at all listening on {LOCAL_DNS}. `systemctl "
            f"restart {subject}` is the first thing to try, and `sudo {CDNCTL} emergency-rollback` "
            f"puts the recorded DNS settings back from {BACKUP_PATH} whether or not the unit comes "
            "up"
        )
    if len(stuck) == 1:
        steps.append(
            f"this run started {stuck[0]}, which is still running, and `systemctl stop "
            f"{stuck[0]}` stops it"
        )
    elif stuck:
        # Both units' undos failing is reachable -- a systemd wedged partway
        # through a rollback is the ordinary way -- so this arm is not a formality
        # and it names every unit rather than printing a placeholder. The two
        # branches are worded differently on purpose, so a message that got the
        # count wrong is visible rather than merely wrong.
        commands = " and ".join(f"`systemctl stop {unit}`" for unit in stuck)
        steps.append(
            f"this run started {len(stuck)} units, which are still running: "
            + " and ".join(stuck)
            + f", and {commands} stop them"
        )
    return InstallResult(
        ok=False,
        backup=transaction.backup,
        report=report,
        notes=notes,
        error=error,
        rollback_error="; ".join(
            f"{failure.description} could not be undone: {failure.error}" for failure in failures
        )
        if failures
        else None,
        recovery=" ".join(steps) if steps else None,
        left_running=list(transaction.uncertain_units),
    )


def connection_of(report: Optional[Preflight]) -> str:
    """The connection the install was working on, for a message about its state."""
    if report is None or report.connection is None:
        return "the connection"
    return report.connection.uuid


# ---------------------------------------------------------------------------
# The uninstall, and the emergency rollback
# ---------------------------------------------------------------------------
#
# Two verbs that put a machine's DNS back, and the difference between them is
# which record they are allowed to act on:
#
#   * `uninstall` acts on a claim. The marker has to be there and the connection
#     has to hold what the installation set, because this runs on a working
#     machine and an operator may have changed the connection since. Anything it
#     cannot prove it owns, it refuses, and the refusal's deliverable is a report
#     a person can act on.
#   * `emergency_rollback` acts on a record alone. It exists for the machine
#     where the install died partway -- killed, or rolled back with a rollback
#     that did not finish -- and on that machine the marker is precisely what is
#     MISSING, because Task 4 writes it last. So it reads the backup and nothing
#     else, which is why the backup is written and read back before the first
#     mutation rather than after the last one.
#
# Neither consults preflight. An uninstall has to work on the machine preflight
# refuses -- wrongly-moded state directories are the ordinary reason -- and the
# operator removing the package is exactly the person who needs it to.
#
# The order, and it is the order rather than a preference:
#
#   1. stop the three timers. They are the only units that write, so nothing is
#      writing state while the machine is being pointed elsewhere.
#   2. put the profile back and reactivate the connection, then CHECK that the
#      device picked the values up.
#   3. stop the two units this package installs, and only those whose state this
#      program could read.
#   4. remove the one file under /etc this package installed.
#   5. reload systemd.
#   6. purge the state directory, if asked, and never before.
#
# Steps 2 and 3 are the load-bearing pair. The machine's NetworkManager is handing
# resolved the loopback address until step 2 finishes, so stopping the router
# first would open a window in which the machine points at 127.0.0.1 with nothing
# listening on it. And because the restore comes first, the check in step 2 can be
# FATAL -- if the device is still on the loopback, the units are not stopped, which
# is why a unit whose state cannot be read may be left running without the
# operator losing their resolver. That is the same reasoning as the install's
# barrier, pointed the other way.

# The property comparison's three outcomes, and only the third is a refusal. The
# first two are the only states this program is entitled to act on.
#
# Recorded in a comment rather than as an enum because there is no third
# enumerator to define: the states are "what we set", "what the backup recorded",
# and everything else, and the everything-else case is a refusal rather than a
# value to write.
NOTHING_RECORDED = "(no record)"
COULD_NOT_BE_READ = "(could not be read)"
# An address list that is empty is a real value -- a connection with no manual DNS
# -- and a report that printed it as nothing would read as a column that failed to
# be filled in. This is the same fact as the "''" in the command below it, said in
# the table's own language.
UNSET = "(unset)"

# A word that needs no quoting in a shell command line. Anything outside it is
# single-quoted by :func:`_render_command`, which matters for exactly one value
# this program ever renders: the empty address list, which has to be written as
# '' or it is a command with a missing argument.
_COMMAND_WORD = re.compile(r"\A[A-Za-z0-9._:@%+=,/-]+\Z")


class UninstallResult(NamedTuple):
    """What an uninstall did, what it refused, and what a person still owes.

    ``ok`` is a fact about the MACHINE and only about the machine: this machine's
    DNS is back on the resolvers the backup recorded, and the device took the
    values. It is False in exactly two situations, and both of them are the ones
    where removing the package would take a resolver away from a machine that is
    still using one:

      * ``refusals`` is not empty -- nothing was changed, because ownership could
        not be proven. The connection is as the operator left it and the
        deliverable is ``manual_recovery``;
      * ``error`` is not None -- the restoration began and did not finish, so some
        of this package's changes are still applied, and the deliverable is again
        ``manual_recovery``, this time to finish the job.

    Everything AFTER a successful restoration -- a unit that could not be stopped,
    a hook that could not be unlinked, a systemd cache one removal out of date, a
    purge that was refused -- is in ``notes`` and does not clear ``ok``. Those are
    things an operator should be told about and none of them is a reason to tell
    dpkg that this machine's DNS is not where it should be.

    ``left_running`` names the units this program would not stop because it could
    not read whether they were running, which is the one case where a successful
    uninstall leaves a unit of this package's still up.

    ``purged`` is a fact about the filesystem rather than a step that succeeded:
    the state directory is gone, or it is not.
    """

    ok: bool
    notes: List[str]
    refusals: List[str]
    error: Optional[str]
    manual_recovery: Optional[str]
    left_running: List[str]
    purged: bool


class RollbackResult(NamedTuple):
    """What an emergency rollback did, and whether the machine can resolve now.

    ``restored`` and ``ok`` are separate because they answer two different
    questions. ``restored`` is "the recorded values are back on the profile" and
    ``ok`` is "this machine can resolve". A rollback whose reactivation failed has
    restored nothing that is live; a rollback whose reactivation worked on a chain
    that cannot reach a resolver has restored something and has not fixed the
    machine. Both are worth telling apart, and neither is the other's success.

    ``resolves`` is the answer the rollback actually got, or `None` when it never
    asked -- an unasked question is not a passing one.
    """

    ok: bool
    restored: bool
    notes: List[str]
    error: Optional[str]
    manual_recovery: Optional[str]
    resolves: Optional[bool]


class Ownership(NamedTuple):
    """What the marker, the backup and the connection say about who owns the DNS.

    ``restores`` is the list of properties to write back, in the order they are
    written, and it is EMPTY for a connection that already holds the recorded
    values everywhere. A machine that is already back where the backup says needs
    no `connection modify` -- and still needs the reactivation, because a profile
    that is right on disk and a device that has not picked it up are two states.
    """

    uuid: str
    device: str
    original: dict
    observed: dict
    restores: List[tuple]
    refusals: List[str]
    notes: List[str]


def _render_command(args: Sequence[str]) -> str:
    """One argument array, rendered as a line a person can paste into a root shell.

    The report this produces is a deliverable, and a deliverable an operator
    cannot run is not one. So the array is rendered, not printed as a Python
    tuple, and anything that is not a bare word is single-quoted: the empty
    address list is the case that matters, and `nmcli connection modify UUID
    ipv6.dns` with no value after it clears a property by accident rather than by
    the argument the report meant to pass.
    """
    words = []
    for word in args:
        if word and _COMMAND_WORD.match(word):
            words.append(word)
        else:
            words.append("'" + word.replace("'", "'\\''") + "'")
    return " ".join(words)


# The four verdicts one property's current value can have. They are named rather
# than derived, because "could not be read" is a QUESTION ABOUT THIS PROGRAM and
# every other verdict is a question about the machine, and the two must never be
# confused: this module's whole argument is that a value it did not read is not
# evidence of anything, and a report that calls one "changed" has made a claim
# about a machine on the strength of a failed read.
#
# One classifier and three consumers. The three are the refusal reasons, the
# report's "now" column and the report's command block, and they were three
# functions in the round before this one -- two of which were written the same day
# and disagreed about the unreadable case, which is how a report came to say
# "changed after the install" about a value nobody read. :func:`_classify` is the
# single answer and the three read it.
OURS = "ours"
RECORDED = "recorded"
SOMEONE_ELSE = "somebody_else"
UNREADABLE = "unreadable"


def _classify(prop: str, current: Optional[str], recorded: str) -> str:
    """What one property's current value is, as one of the four verdicts.

    The order of the questions is the order of the trust: what this program can
    say about its own reading, then what the machine is using, then what the
    record says.

    ``UNREADABLE`` has two shapes and both are the same fact. ``None`` is a call
    that raised. A BLANK answer is a call that ran and printed nothing, and for a
    ``yes``/no`` that is the second unreadable shape rather than a value: `nmcli
    -g` prints nothing at all for a connection it cannot find, and a `yes`/`no`
    has no empty value. For an ADDRESS LIST the blank is the opposite -- the empty
    list, a real answer, a link with no manual DNS -- and it goes on to the other
    questions. That asymmetry is measured and it is the one the two functions this
    replaces got wrong differently.

    THE OTHER STATEMENT OF "A BLANK `yes`/`no` IS NOT A VALUE" is in
    :func:`_original_property`, on the install side, and the comment there says
    what is said here and why the two are not one function: this one answers
    WHOSE value is this and must keep treating a blank ADDRESS LIST as a real
    value, and that one answers MAY I RECORD THIS and must refuse a blank
    `yes`/`no` because nmcli prints nothing for an unset boolean. Same value
    space, different questions, and the asymmetry is the design rather than a
    leftover.

    ``SOMEONE_ELSE`` is strict equality against both the value this installation
    set and the recorded original, which means a list that CONTAINS what this
    install set and one more address is somebody else's: a user who added a
    resolver did not leave a leftover.
    """
    if current is None:
        return UNREADABLE
    if not current and prop in IGNORED_AUTOMATICALLY:
        return UNREADABLE
    found = _as_current(prop, current)
    ours = dict(NM_MUTATIONS).get(prop)
    if ours is not None and found == _as_current(prop, ours):
        return OURS
    if found == _as_current(prop, recorded):
        return RECORDED
    return SOMEONE_ELSE


def _shown_now(prop: str, current: Optional[str], recorded: str) -> str:
    """How a report shows what one property holds at this moment.

    One question, and :func:`_classify` answers it: the row is unreadable or it
    is not. A column that says ``(unset)`` when it means "I could not look" is a
    column that misleads in the direction that matters, because it looks like a
    machine this run examined.
    """
    if _classify(prop, current, recorded) == UNREADABLE:
        return COULD_NOT_BE_READ
    return current or UNSET


def manual_recovery_report(
    uuid: str,
    original: Optional[dict],
    observed: dict,
    reasons: Sequence[str],
    device: str = "",
    summary: Optional[str] = None,
    written: Sequence[str] = (),
) -> str:
    """The report a person acts on, and the only thing a refusal really produces.

    It carries three things and nothing else does: **what this program found**,
    **what was expected**, and **the commands to run**. A refusal whose only
    output is a sentence is a refusal that leaves the work to the reader, and the
    reader is standing in front of a machine that cannot resolve.

    The commands are offered only when the record behind them is one this program
    read and understood in full. A backup of an unknown schema version may not
    even hold these four properties in this shape, and a partial set of commands
    is worse than none: an operator who runs three of four believes the connection
    is back.

    And a property this program did not write, whose current value is one this
    package never put there, gets a LEAVE line instead of a modify. The reasons
    above this block exist to say that this program will not write over such a
    value, and a block twelve lines below handing over the command that writes
    over it makes the whole report a thing nobody can act on. Two values are never
    left alone: a value this program could not READ, which is a fact about the
    program and not about the machine (:func:`_classify`), and a property
    ``written`` names, because this run put the recorded value there and the value
    in the table no longer exists.

    ``written`` is a parameter and not an inference because a report cannot know
    what a profile holds after an UNCONDITIONAL overwrite. The emergency rollback
    writes every recorded value whatever it found -- that is the killed-install
    case, and gating it would refuse the machine the command exists for -- and then
    hands this function the observation it took BEFORE those writes. A report built
    from that without being told what was written would name a value that has been
    overwritten and claim a refusal that did not happen. So the caller says which
    properties it wrote, the table is labelled as the state before that, and the
    overwrite is stated rather than hidden.
    """
    lines = [f"MANUAL RECOVERY REPORT for connection {uuid}" if uuid else "MANUAL RECOVERY REPORT", ""]
    if reasons:
        lines.append("why this program stopped where it did:")
        lines.extend(f"  - {reason}" for reason in reasons)
        lines.append("")
    quoted = False
    if original:
        when = "held before this run wrote to it" if written else "holds now"
        lines.append(f"what {BACKUP_PATH} recorded, and what the connection {when}:")
        for prop in RECORDED_PROPERTIES:
            entry = original.get(prop)
            if not isinstance(entry, dict):
                recorded_raw = NOTHING_RECORDED
            else:
                raw = str(entry.get("raw", ""))
                recorded_raw = raw if raw else UNSET
            if observed:
                lines.append(
                    f"  {prop:<20}    recorded {recorded_raw}    now "
                    f"{_shown_now(prop, observed.get(prop), original[prop]['raw'])}"
                )
            else:
                lines.append(f"  {prop:<20}    recorded {recorded_raw}")
        lines.append("")
    if uuid and original:
        lines.append(
            "to put the connection back by hand, run these as root: the recorded values, then the "
            "reconnection. The recorded order is the order they are read in here; the order matters "
            "only in that all of them come before the reconnection, which is what makes them live"
        )
        for prop in RECORDED_PROPERTIES:
            current = observed.get(prop) if observed else None
            if prop not in written and _classify(prop, current, original[prop]["raw"]) == SOMEONE_ELSE:
                lines.append(
                    f"  leave {prop} at {current or UNSET} -- changed after the install, not the "
                    f"recorded value, and overwriting somebody else's change is what this program "
                    "refused to do"
                )
                continue
            value = _restore_value(prop, original)
            rendered = _render_command(("nmcli", "connection", "modify", uuid, prop, value))
            quoted = quoted or "''" in rendered
            lines.append(f"  {rendered}")
        lines.append(f"  {_render_command(('nmcli', 'connection', 'up', uuid))}")
        if quoted:
            lines.append("")
            lines.append(
                "an empty value is written as '', which asks NetworkManager to clear that property "
                "rather than to set it to something"
            )
        if written:
            # After the block and its notes, never inside them: the block has to
            # stay a run of command lines, because the one thing an operator does
            # with it is select it and paste it.
            #
            # The second half is scoped to the properties just named, and that
            # scoping is the whole point of the paragraph. A partial write set --
            # the first modify landed and the second did not -- made this sentence
            # claim about all four properties that the profile holds what every
            # modify line says, three lines below a reason saying one of those
            # writes failed. That is Finding A's shape with the polarity flipped:
            # a claim about the machine on the strength of a write that did not
            # happen. The properties this run did not write are still what the
            # table shows, and the report says so rather than leaving it implied.
            lines.append("")
            lines.append(
                "this run already wrote the recorded value for "
                + ", ".join(written)
                + ", so the table above is what the connection held BEFORE it did and the modify "
                "lines above are what the profile holds now for those properties; the others are "
                "still what the table above shows"
            )
        lines.append("")
        lines.append("then check that the device picked them up:")
        for prop in (IPV4_DNS, IPV6_IGNORE_AUTO_DNS, IPV4_IGNORE_AUTO_DNS):
            lines.append(
                "  " + _render_command(("nmcli", "-g", prop, "connection", "show", uuid))
            )
        if device:
            lines.append("  " + _render_command(("resolvectl", "dns", device)))
            lines.append(
                f"  that should name the machine's own resolvers and not {LOCAL_DNS}, which is the "
                "address this package pointed it at"
            )
        lines.append("")
    elif not uuid:
        lines.append(
            f"there is no connection to name, because {BACKUP_PATH} is not a record this program "
            "can read, and this program will not invent a connection UUID. The commands that put "
            "a connection back are `nmcli connection modify <uuid> <property> <value>`, once for "
            "each of "
            + ", ".join(RECORDED_PROPERTIES)
            + ", followed by `nmcli connection up <uuid>`; the values are in that file"
        )
        lines.append("")
    lines.append(
        summary
        or (
            f"nothing on this machine has been changed by this run, and {BACKUP_PATH} is the record "
            "of what the connection was set to before anything was changed"
        )
    )
    return "\n".join(lines)


def _as_current(prop: str, text: str):
    """One property's value in the shape two values are compared in.

    An address list is compared as a list and a `yes`/`no` as a string, so that a
    release printing `192.0.2.53;192.0.2.54` and a release printing
    `192.0.2.53,192.0.2.54` are the same value rather than a difference this
    program would refuse over.

    Nothing here validates an address. A value that is not a list of addresses is
    simply a value that is neither what this installation set nor what the backup
    recorded, and a refusal that names it is more use than a refusal that parses
    it and fails on the parsing.
    """
    if prop in ADDRESS_LISTS:
        return [token for token in re.split(r"[,;\s]+", (text or "").strip()) if token]
    return text


def _read_marker(root: Path) -> List[str]:
    """The ownership claim, or the reasons there is not one to act on.

    The marker is the second of two independent proofs, not the only one: the
    connection's own values are the first, and either alone is a reason to stop.
    Both have to agree, because each can be present without the other -- a marker
    is left behind by an install whose rollback undid its changes, and correct
    values are left behind by an install that was killed before it wrote one.
    """
    path = root / MANAGED_BY.lstrip("/")
    state = _path_state(path)
    if state != "a regular file":
        return [
            f"there is no ownership marker at {MANAGED_BY} (there is {state}); a marker says "
            f"{MANAGED_BY_VALUE!r} and an install writes it only after it has finished, so nothing "
            "on this machine claims the DNS is this package's"
        ]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return [f"the ownership marker at {MANAGED_BY} could not be read ({error})"]
    said = text.strip()
    if said != MANAGED_BY_VALUE:
        return [
            f"the ownership marker at {MANAGED_BY} says {said!r} rather than {MANAGED_BY_VALUE!r}, "
            "so it is not this package's claim to this machine"
        ]
    return []


def _read_backup(root: Path) -> tuple:
    """The record, and the reasons there is not one this program will act on.

    Returns ``(document, refusals)``. The document is `None` whenever anything
    about it is wrong, INCLUDING a field it did not have: a record that is
    missing one of the four properties is a record this program cannot offer
    commands from, because a command block that restores three of four is one an
    operator will believe is complete.

    The schema version and the project name are checked first and on their own,
    because those are the two fields a future release has to refuse rather than
    guess at, and a message that only said "the backup is not usable" would not
    tell an operator which of the two it was.
    """
    path = root / BACKUP_PATH.lstrip("/")
    state = _path_state(path)
    if state != "a regular file":
        return None, [
            f"there is no backup at {BACKUP_PATH} (there is {state}), and without it there is "
            "nothing to put the connection back to: this program will not invent a value it did "
            "not record"
        ]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return None, [f"{BACKUP_PATH} could not be read ({error})"]
    try:
        document = json.loads(text)
    except ValueError as error:
        return None, [f"{BACKUP_PATH} is not a JSON document ({error})"]
    if not isinstance(document, dict):
        return None, [f"{BACKUP_PATH} is a {type(document).__name__} rather than a record"]
    if document.get("managed_by") != MANAGED_BY_VALUE:
        return None, [
            f"{BACKUP_PATH} names {document.get('managed_by')!r} rather than {MANAGED_BY_VALUE!r}, "
            "so it is not a record of this project's changes to this machine"
        ]
    if document.get("schema_version") != BACKUP_SCHEMA_VERSION:
        return None, [
            f"{BACKUP_PATH} is at schema version {document.get('schema_version')!r} and this "
            f"release reads version {BACKUP_SCHEMA_VERSION}, so this program cannot know what its "
            "fields mean and will not write any of them"
        ]
    refusals = []
    connection = document.get("connection")
    if not isinstance(connection, dict):
        refusals.append(f"{BACKUP_PATH} names no connection at all")
    else:
        if not str(connection.get("uuid") or "").strip():
            refusals.append(
                f"{BACKUP_PATH} names no connection UUID, and a modify aimed at anything but a "
                "UUID is a modify aimed at the wrong thing with no error"
            )
        if not str(connection.get("device") or "").strip():
            refusals.append(
                f"{BACKUP_PATH} names no device, so there is nothing to ask which resolvers the "
                "machine ended up using"
            )
    original = document.get("original")
    if not isinstance(original, dict):
        refusals.append(f"{BACKUP_PATH} records no original properties at all")
    else:
        for prop in RECORDED_PROPERTIES:
            entry = original.get(prop)
            if not isinstance(entry, dict) or not isinstance(entry.get("raw"), str) or "value" not in entry:
                refusals.append(
                    f"{BACKUP_PATH} does not record {prop}, or records it without the raw text an "
                    "operator would read, and a restore can only put back what was written down"
                )
                continue
            value = entry["value"]
            if prop in ADDRESS_LISTS:
                shape = "a list of addresses"
            else:
                shape = "a yes or a no"
            readable = (
                isinstance(value, list) and all(isinstance(item, str) for item in value)
                if prop in ADDRESS_LISTS
                else isinstance(value, str)
            )
            if not readable:
                # Checked here rather than at the point of use, because the point
                # of use is a refusal's own report: a `value` of the wrong shape
                # has to be a refusal with a sentence in it, not a TypeError from
                # a function that was rendering a command for a person to run.
                refusals.append(
                    f"{BACKUP_PATH} records {prop} as {value!r}, which is not {shape}, so this "
                    "release cannot put it back and will not guess at what it meant"
                )
    if refusals:
        return None, refusals
    return document, []


def _as_restored(original: dict, ours: Optional[Sequence[str]] = None) -> List[tuple]:
    """The three properties, newest change first, with the value each goes back to.

    The same order and the same values as the install's own rollback, because
    there is one story for how this package undoes its profile changes and two
    would be one more thing to get wrong. The address list this install never
    changed is not in it: writing it would be writing a value nothing changed.

    ``ours`` restricts the answer to the properties the caller found still holding
    this installation's value, and restricting it does not disturb the order --
    which is the reason the order lives here and not in the caller.
    """
    return [
        (prop, _restore_value(prop, original))
        for prop, _value in reversed(NM_MUTATIONS)
        if ours is None or prop in ours
    ]


def _ownership(root: Path, run: CommandRunner) -> Ownership:
    """Everything this program has to establish before it writes to a connection.

    Four independent questions, and any of them being unanswerable is a refusal:

      1. does the marker say this package owns this machine's DNS;
      2. is there a record this release can read, naming a connection and a device;
      3. does every property hold the value this installation set, or the value
         the backup recorded;
      4. and the two address lists, are they values this program can read at all.

    Question 3 is the plan's own review focus -- an uninstall must not overwrite a
    connection the user changed after the installation -- and it is asked as a
    three-way comparison rather than as "is it what we set", because a property
    that already holds the recorded original is a machine that has been restored
    already and is not a machine somebody edited.
    """
    refusals = _read_marker(root)
    document, backup_refusals = _read_backup(root)
    refusals.extend(backup_refusals)
    if document is None:
        return Ownership("", "", {}, {}, [], refusals, [])
    connection = document["connection"]
    uuid = str(connection["uuid"])
    device = str(connection["device"])
    original = document["original"]
    notes = []

    observed: dict = {}
    ours: List[str] = []
    for prop in RECORDED_PROPERTIES:
        answer = _text(run, ("nmcli", "-g", prop, "connection", "show", uuid))
        observed[prop] = answer
        recorded_raw = original[prop]["raw"]
        # One classifier, and this is consumer one of three. The verdict is
        # UNREADABLE for both unreadable shapes -- a call that raised and a call
        # that printed nothing -- because this program has no account of this
        # property either way and the report is told the same thing, which is the
        # whole of Finding A: one definition, so the refusal reason and the
        # report's row and the report's command block cannot disagree.
        verdict = _classify(prop, answer, recorded_raw)
        if verdict == UNREADABLE:
            refusals.append(
                f"{prop} of connection {uuid} could not be read: it came back "
                + (
                    "empty, which is not a value it can hold, and `nmcli -g "
                    f"{prop} connection show {uuid}` prints nothing at all for a connection it "
                    "cannot find"
                    if answer is not None
                    else f"nothing at all (`nmcli -g {prop} connection show {uuid}` did not run)"
                )
                + ", so this program cannot say whether the machine still holds what this "
                "installation set and will not write to a connection it cannot see"
            )
            continue
        if verdict == OURS:
            ours.append(prop)
            continue
        if verdict == RECORDED:
            # Only for a property this installation SET. For one it never touched
            # -- the IPv6 address list -- "already holds the recorded value" is a
            # tautology about something no change of ours could have altered, and
            # a refactor must not add a line to every normal uninstall's output
            # without a reason. The note is about this installation's changes.
            if prop in dict(NM_MUTATIONS):
                notes.append(
                    f"{prop} of {uuid} already holds the value {BACKUP_PATH} recorded, so it is "
                    "left as it is"
                )
            continue
        set_by_us = dict(NM_MUTATIONS).get(prop)
        refusals.append(
            f"{prop} of connection {uuid} is {answer!r}, which is neither the value this "
            f"installation set ({set_by_us!r}) nor the value {BACKUP_PATH} recorded "
            f"({recorded_raw!r})"
            + (
                ", so somebody changed this connection after the install and this program will "
                "not overwrite their change"
                if set_by_us is not None
                else ", and this installation never changed this property, so it was changed by "
                "something other than this package and this program will not write over it"
            )
        )
    restores = _as_restored(original, ours)
    if not restores and not refusals:
        notes.append(
            f"every property of {uuid} already holds the value {BACKUP_PATH} recorded, so there is "
            "nothing to put back and only the reactivation is needed"
        )
    try:
        digest = _config_digest(root)
    except InstallRefused:
        digest = ""
    if digest and digest != document.get("config_sha256"):
        notes.append(
            f"{POLICY_CONFIG} no longer has the digest {BACKUP_PATH} recorded, so it has been "
            "edited since the install; that says nothing about the connection, and the connection "
            "is what is being restored"
        )
    return Ownership(uuid, device, original, observed, restores, refusals, notes)


def _device_follows_the_backup(run: CommandRunner, ownership: Ownership) -> None:
    """Whether the live device took the restored values, which is the step that matters.

    The properties are written to the connection's PROFILE, and a profile reaches
    the device when the connection is brought up. A `connection modify` and a
    `connection up` that both succeed are not proof that the second one applied
    the first, and on this program that is not a cosmetic gap: the router is
    stopped two steps later, and stopping it on a machine that is still handing
    resolved the loopback address is the one outcome this whole section exists to
    prevent.

    A loopback address is only a failure when the backup did not record one. A
    machine that was already using a local resolver before this package was
    installed is restored TO the loopback, and calling that a leftover would
    refuse the correct result.

    And a read that PRODUCED NOTHING is a refusal, which is the one case this
    check had wrong. `_text` returns `None` only when the call raises, so a
    `resolvectl` that exits non-zero having printed nothing comes back as the
    empty string -- and the loopback is not in `"".split()`, so the check passed
    and the units were stopped on a machine whose state nobody had read. Measured
    on real resolved 24.04: a device that does not exist exits 1 with nothing on
    standard output. Real resolved always prints the `Link N (<dev>):` line for a
    link that exists, even one with no DNS on it, so an empty answer is never a
    real one and the reading that decides it is a blank line rather than a missing
    loopback.
    """
    forwarding = _text(run, ("resolvectl", "dns", ownership.device))
    if forwarding is None:
        raise InstallRefused(
            f"resolvectl could not be asked what {ownership.device} is using for DNS, so nothing "
            "has confirmed that the connection picked the values that were just put back"
        )
    if not forwarding.strip():
        raise InstallRefused(
            f"resolvectl was asked what {ownership.device} is using for DNS and printed nothing at "
            f"all. A link that exists is always printed as `Link N (<dev>):` even when it has no "
            f"resolvers, so this is a read that did not happen, and the only two reasons are that "
            f"{ownership.device} -- the name {BACKUP_PATH} recorded -- may have been renamed or "
            f"removed since the install, or that resolvectl itself failed. If the interface was "
            f"renamed, `resolvectl dns <its new name>` will answer and the values in {BACKUP_PATH} "
            f"are still the ones to put back. Either way nothing has confirmed that the connection "
            f"picked the values that were just put back, so the units this package installs are "
            f"still running and the hook is still installed"
        )
    recorded = _as_current(IPV4_DNS, ownership.original[IPV4_DNS]["raw"])
    if LOCAL_DNS in forwarding.split() and LOCAL_DNS not in recorded:
        raise InstallRefused(
            f"resolvectl reports {ownership.device} using {forwarding!r}, which still includes the "
            f"loopback address {LOCAL_DNS} that this package pointed it at, and {BACKUP_PATH} "
            f"recorded {ownership.original[IPV4_DNS]['raw']!r}; NetworkManager accepted the change "
            "and did not apply it, so this program will not go on to stop the resolver that "
            "address is pointing at"
        )


def _stop_units(run: CommandRunner, units: Sequence[str], notes: List[str]) -> List[str]:
    """Stop the units this package installs, and name the ones it will not touch.

    A unit whose state could not be read is LEFT RUNNING and named, which is
    Task 4's rule and it is inherited rather than re-derived: `is-active` on a
    unit that does not exist prints nothing, so a blank answer and a call that
    failed are one fact -- this program cannot say -- and stopping a resolver whose
    state it cannot read is the harm the rule exists to prevent. Leaving one
    running is smaller, and reversible, and is reported.

    The reads come first and the stops second, for both groups. Reading each unit
    and stopping it before reading the next would make "which units did this
    program decide it could not read" depend on where the run stopped.

    A stop that FAILS is reported and the rest of the uninstall goes on. That is
    the difference between this step and the restoration above it: the machine is
    already back on its own resolvers, so a resolver of this package's that is
    still running is a process nobody is using rather than a machine with nowhere
    to send a query -- and stopping the run at the first failure would leave the
    hook installed and systemd's copy of the unit files stale, which are two more
    things wrong for no benefit.

    Every step after the restoration is reported this way rather than raised, and
    none of them changes `ok`. The exit status is a fact about the MACHINE: not
    ours, not back, or back. A stale hook, a unit that is still up, and a systemd
    cache that is one removal out of date are all things an operator should be
    told about and none of them is a reason to tell dpkg that this machine's DNS
    is not where it should be.
    """
    readable = [unit for unit in units if _text(run, ("systemctl", "is-active", unit))]
    unreadable = [unit for unit in units if unit not in readable]
    for unit in readable:
        try:
            _checked(run, ("systemctl", "stop", unit), f"stopping {unit}")
        except InstallRefused as error:
            notes.append(
                f"{str(error)}, so {unit} is still running; `systemctl stop {unit}` stops it, and "
                "nothing on this machine's DNS depends on it any more"
            )
    for unit in unreadable:
        notes.append(
            f"{unit} could not be asked about, so this program would not stop a unit whose state "
            f"it could not read and left it as it found it; `systemctl stop {unit}` stops it"
        )
    return unreadable


def _remove_dispatcher(root: Path, notes: List[str]) -> None:
    """Remove the one file under /etc this package installed, and only that one.

    A symbolic link is unlinked rather than followed: the link is the package's
    file and whatever it points at is not. Anything else at that path -- a
    directory, a socket -- is not a hook and is reported rather than removed,
    because a path this program did not create is the one thing it must not
    destroy on its way out.

    Nothing else under /etc is touched. The conffiles are dpkg's business, and an
    operator who has edited /etc/mosdns/policy.yaml owns it: the package's answer
    to that is to leave it for `dpkg` to ask about, not to delete it.
    """
    path = root / DISPATCHER_SCRIPT.lstrip("/")
    state = _path_state(path)
    if state == "absent":
        return
    if state not in ("a regular file", "a symbolic link"):
        notes.append(
            f"{DISPATCHER_SCRIPT} is {state} rather than a file this package installed, so it was "
            "left alone"
        )
        return
    try:
        path.unlink()
    except OSError as error:
        notes.append(
            f"{DISPATCHER_SCRIPT} could not be removed ({error}), so the DHCP bridge is still "
            "installed and will still run on the next NetworkManager event"
        )
        return
    notes.append(f"removed {DISPATCHER_SCRIPT}, the only file under /etc this package installs")


def _purge_state(root: Path) -> None:
    """Remove the state directory, which is the operator's data, and only on request.

    Three refusals, all in the same direction. A symbolic link is not followed:
    the tree behind it was not created by this program and is not its to delete.
    Anything that is not a directory is not a state directory. And an absent
    directory is not a failure of its own -- it is what a purge finds when
    something else has already removed it -- so this step says nothing and the
    caller reports ``purged`` as false, which is the fact.

    `shutil.rmtree` does not follow a symbolic link inside the tree either, so a
    link an operator dropped into the state directory is unlinked and what it
    pointed at is untouched. That is the property this step is allowed to have,
    and it is asserted rather than assumed.
    """
    path = root / STATE_DIRECTORY.lstrip("/")
    if path.is_symlink():
        raise InstallRefused(
            f"{STATE_DIRECTORY} is a symbolic link to {os.readlink(path)} rather than a directory "
            "this package created, so this program will not remove a tree it did not make"
        )
    state = _path_state(path)
    if state == "absent":
        return
    if state != "a directory":
        raise InstallRefused(f"{STATE_DIRECTORY} is {state} rather than a directory to remove")
    try:
        shutil.rmtree(path)
    except OSError as error:
        raise InstallRefused(
            f"{STATE_DIRECTORY} could not be removed ({error}); everything above it is already "
            "back the way it was, and the state directory is the operator's to remove by hand"
        ) from error


def _restore_unfinished(
    ownership: Ownership, error: str, notes: List[str], written: Sequence[str] = ()
) -> UninstallResult:
    """The result of an uninstall that started and could not finish.

    ``refusals`` is empty on purpose. A refusal means nothing was changed and the
    caller can say so; this is the other machine, where the values this package
    set are still on the profile, so the sentence has to be a different one and
    the exit status has to be a different one. Everything below the restoration is
    left alone: the units keep running, the hook stays installed, and the state
    directory stays exactly where the record of it is.

    ``written`` names the properties whose recorded value REACHED the profile, and
    it is passed on for the same reason the rollback passes it: this report is
    built from an observation taken before those writes, so without them its table
    reads as the current state of a machine it has already changed.
    """
    return UninstallResult(
        ok=False,
        notes=list(notes),
        refusals=[],
        error=(
            f"the restoration did not finish, so the values this installation set are still on "
            f"connection {ownership.uuid}: {error}"
        ),
        manual_recovery=manual_recovery_report(
            ownership.uuid,
            ownership.original,
            ownership.observed,
            [error],
            device=ownership.device,
            summary=(
                f"{BACKUP_PATH} still records what connection {ownership.uuid} was set to, and the "
                "values written before the failure are in place. The units this package installs "
                f"have NOT been stopped, because the machine may still be using {LOCAL_DNS}, so "
                "removing the package now would take away a resolver this machine is still "
                "pointing at; the commands above are what finishes the job"
            ),
            written=list(written),
        ),
        left_running=[],
        purged=False,
    )


def _never_applied(root: Path) -> bool:
    """Whether no transaction of THIS PACKAGE ever reached a mutation here.

    Two absences, and the second one is the whole of the argument:
      * **no record.** The install writes the record of the machine's original DNS
        settings, reads it back, compares it field by field and checks its mode
        BEFORE the first mutation, and refuses if it cannot. So a machine with no
        record at all is a machine on which no transaction of this package ever
        got as far as changing anything -- which is a fact about the ORDER the
        transaction runs in, not a hope. There is nothing to put back, because
        nothing was ever taken.

      * **no claim.** The marker is the other proof, and it is checked FIRST and
        for the opposite reason: it is written last, so every install that failed
        anywhere above it left none, and its absence on its own says nothing. A
        marker that is present and readable says the opposite -- this package
        claims the machine's DNS -- and a marker that is present and unreadable, or
        present and not this package's, also fails this check, because a machine
        whose DNS somebody else claims is not a machine this program may tidy up.
        The two conditions together are one fact: nothing of this package ever ran
        to completion on this machine, and nothing of it ever got as far as
        changing anything.

    What the claim does NOT cover: a record deleted by hand after a successful
    install. That is not a state this program produces, and a package that removed
    the resolver of such a machine would be the harm this whole section exists to
    prevent. The absence it does cover is the one a refused install leaves.
    """
    if not _read_marker(root):
        return False
    return _path_state(root / BACKUP_PATH.lstrip("/")) == "absent"


def _remove_what_was_never_applied(
    root: Path, run: CommandRunner, notes: List[str], purge: bool
) -> UninstallResult:
    """Finish a removal of a package that never changed this machine.

    The one place in this program that takes a machine's resolver away without a
    record saying where the machine's own resolvers are, so the sentence is the
    deliverable as much as the commands are: it says plainly what was established,
    that no connection was written to, and that the removal may go ahead.

    No `resolvectl` is asked and no connection is named, because there is no
    connection to name and nothing on any connection is ours to read or change.
    The units are stopped in the same two groups and under the same
    read-the-state-first rule as a restoration, the hook is removed, systemd is
    reloaded, and a `--purge` removes the state directory -- which here holds no
    record, only a prefix list and a range cache.
    """
    left = _stop_units(run, PROJECT_TIMERS, notes)
    left += _stop_units(run, (ROUTER_UNIT, RESOLVER_UNIT), notes)
    _remove_dispatcher(root, notes)
    try:
        _checked(
            run,
            ("systemctl", "daemon-reload"),
            "reloading systemd (systemctl daemon-reload) so its copy of the unit files is current",
        )
    except InstallRefused as error:
        notes.append(str(error))
    purged = False
    if purge:
        try:
            _purge_state(root)
        except InstallRefused as error:
            notes.append(str(error))
        else:
            purged = True
    # Two sentences and not one, because the two states are different facts. A
    # machine whose installer directory is empty never had this package applied to
    # it; a machine that still carries the directory had it, and the absence of
    # the record is a refused install that rolled itself back. Both end in the
    # same place -- no connection was written to, and the removal may proceed --
    # and neither may say "never applied" about a machine that was.
    if _path_state(root / INSTALLER_DIRECTORY.lstrip("/")) == "absent":
        notes.append(
            f"there is nothing of this package left on this machine: no ownership marker at "
            f"{MANAGED_BY}, no record at {BACKUP_PATH}, and not even the directory they live in, "
            f"which is where they are after a purge. No connection was touched; the units this "
            "package installs have been stopped, the dispatcher hook has been removed, and the "
            "removal may proceed"
        )
    else:
        notes.append(
            f"nothing of this package was ever applied to this machine: there is no ownership "
            f"marker at {MANAGED_BY} and no record at {BACKUP_PATH}, and the install writes that "
            "record -- then reads it back and compares it -- before it changes anything, so a "
            "machine with neither had no DNS setting of its own changed by this package. No "
            "connection was touched: the units this package installs have been stopped, the "
            "dispatcher hook has been removed, and the removal may proceed"
        )
    return UninstallResult(
        ok=True,
        notes=notes,
        refusals=[],
        error=None,
        manual_recovery=None,
        left_running=left,
        purged=purged,
    )


def uninstall(root: Path, run: CommandRunner, purge: bool = False, probe=None) -> UninstallResult:
    """Put this machine's DNS back the way the backup says it was, and stop.

    ``root`` and ``run`` are the same two seams :func:`preflight` and
    :func:`install` have. ``probe`` is the third: after the restore the machine's
    path is through its own resolvers, and whether that path works is a fact the
    operator is entitled to be told -- so it is asked once, through resolved's
    stub, with the RESOLVING half of the prober's two answers. A SERVFAIL is not
    a resolution, and an uninstall that reported one as a working machine would be
    reporting the one thing an operator removing this package cannot afford to be
    told wrongly.

    It is a note and not a failure. Whether the operator's own upstream can
    resolve is not this package's business, and failing the uninstall over it
    would make `dpkg` complain about a machine whose resolver is somebody else's
    problem. The restore's OWN check -- did the device pick the values up -- is a
    failure, and it is fatal, because on that machine stopping the resolver is the
    one thing that must not happen.
    """
    root = Path(root)
    ask = probe or (lambda address, port: probe_dns(address, port))
    ownership = _ownership(root, run)
    notes = list(ownership.notes)
    if ownership.refusals:
        # The absence of the RECORD has its own verdict, and it is not a refusal.
        # See `_never_applied`: the install writes and verifies the record before
        # its first mutation, so a machine with no record is a machine this package
        # never changed -- and refusing it is what leaves a failed install
        # permanently unremovable, because dpkg aborts a removal whose
        # pre-removal script exits non-zero.
        if _never_applied(root):
            return _remove_what_was_never_applied(root, run, notes, purge)
        # Two summaries, because there are two reports. When the record could not
        # be read there is no connection to name and no command block to point
        # at -- the report printed a template -- and a summary that interpolated
        # the empty UUID and said "the commands above" would be a sentence about
        # a machine and a set of commands that are not there.
        if ownership.uuid:
            summary = (
                f"nothing on this machine has been changed by this run, and {BACKUP_PATH} is the "
                f"record of what connection {ownership.uuid} was set to before anything was "
                f"changed. The units this package installs are still here and the machine may still "
                f"be using {LOCAL_DNS}, so REMOVING THE PACKAGE NOW would take away a resolver "
                "this machine is still pointing at; put the connection back with the commands "
                "above first, or reboot, and then remove the package"
            )
        else:
            summary = (
                f"nothing on this machine has been changed by this run, and there is no record of "
                f"what any connection here was set to: {BACKUP_PATH} is where it would be, and it "
                f"is not a record this program can read. The units this package installs are still "
                f"here and the machine may still be using {LOCAL_DNS}, so REMOVING THE PACKAGE NOW "
                "would take away a resolver this machine is still pointing at; put the connection "
                "back by hand, or reboot, and then remove the package"
            )
        return UninstallResult(
            ok=False,
            notes=notes,
            refusals=ownership.refusals,
            error=(
                "this program will not change a connection it cannot prove this package set, so "
                "nothing was changed"
            ),
            manual_recovery=manual_recovery_report(
                ownership.uuid,
                ownership.original,
                ownership.observed,
                ownership.refusals,
                device=ownership.device,
                summary=summary,
            ),
            left_running=[],
            purged=False,
        )

    # 1. the timers, which are the only units that write anything.
    left = _stop_units(run, PROJECT_TIMERS, notes)
    # 2. the profile, newest change first, and then the reactivation, which is
    #    what makes the restored values live. What reached the profile is tracked
    #    per write rather than taken from the list of intended ones, because a
    #    second modify failing must leave the report saying one value is back and
    #    two are not.
    written: List[str] = []
    for prop, value in ownership.restores:
        try:
            _checked(
                run,
                ("nmcli", "connection", "modify", ownership.uuid, prop, value),
                f"putting {prop} back to {value!r} on {ownership.uuid}",
            )
        except InstallRefused as error:
            return _restore_unfinished(ownership, str(error), notes, written)
        written.append(prop)
    try:
        _checked(
            run,
            ("nmcli", "connection", "up", ownership.uuid),
            f"reactivating {ownership.uuid} to apply what was put back",
        )
    except InstallRefused as error:
        return _restore_unfinished(ownership, str(error), notes, written)
    #    and the read that proves the device took them. Fatal, and the reason the
    #    units below are not stopped when it fails.
    try:
        _device_follows_the_backup(run, ownership)
    except InstallRefused as error:
        return _restore_unfinished(ownership, str(error), notes, written)
    # 3. the two units, and only the ones whose state could be read.
    left += _stop_units(run, (ROUTER_UNIT, RESOLVER_UNIT), notes)
    # 4. the one file under /etc this package installed.
    _remove_dispatcher(root, notes)
    # 5. systemd's cached copy of the unit files this uninstall has just stopped,
    #    which the package removal that follows is about to make wrong. It is
    #    harmless while the files are still there, which at `prerm` time they are:
    #    it is here because a plain `uninstall` with no package removal is also a
    #    thing an operator does, and a reload is the only step that makes a
    #    removed unit's cache entry go away. NetworkManager reads its dispatcher
    #    directory itself, so the hook's removal needs no reload -- this one is
    #    about the unit files.
    try:
        _checked(
            run,
            ("systemctl", "daemon-reload"),
            "reloading systemd (systemctl daemon-reload) so its copy of the unit files is current",
        )
    except InstallRefused as error:
        notes.append(str(error))
    # 6. the state directory, last, and never before the restoration above.
    purged = False
    if purge:
        try:
            _purge_state(root)
        except InstallRefused as error:
            notes.append(str(error))
        else:
            purged = True
    # The verdict on the machine is LAST, and it is the only sentence in this
    # whole section that is about whether the machine works rather than about
    # what this program did to it. An operator who reads the last line of the
    # output has to be reading that, and a run whose last line is about a
    # directory is a run whose last line can be mistaken for "all fine".
    if ask(RESOLVED_STUB_ADDRESS, DNS_PORT).resolves:
        notes.append(
            f"connection {ownership.uuid} is back on the machine's own resolvers, and "
            f"{RESOLVED_STUB_ADDRESS} resolved {INSTALL_PROBE_NAME}, so this machine can resolve"
        )
    else:
        notes.append(
            f"connection {ownership.uuid} is back on the machine's own resolvers, but a query for "
            f"{INSTALL_PROBE_NAME} through {RESOLVED_STUB_ADDRESS} did not resolve, so THIS MACHINE "
            f"CANNOT RESOLVE: that is the resolver it was following before this package was "
            "installed, it is not something this uninstall did, and nothing above will change it"
        )
    return UninstallResult(
        ok=True,
        notes=notes,
        refusals=[],
        error=None,
        manual_recovery=None,
        left_running=left,
        purged=purged,
    )


def _read_current_properties(run: CommandRunner, uuid: str) -> dict:
    """What the four properties hold now, for a report to show beside the record.

    Read-only, and read for the REPORT rather than for a decision: every write
    below is unconditional, because the machine this verb exists for is one whose
    install died partway and whose connection may hold any mixture of this
    package's values and the recorded originals. Asking for a gate here would
    refuse the case the command is for.

    But a rollback that overwrites a connection without having read it can tell an
    operator nothing about what it just replaced, and on a fully installed machine
    whose owner has since hand-edited the connection that overwrite is silent and
    exits 0. So the four reads happen first, the values go into the report's
    "now" column, and the report is the thing that makes the overwrite visible.

    A read that fails is `None` in the report's own words -- it could not be read
    -- and changes nothing about what is written. The direction of that failure is
    deliberate and is stated in :func:`emergency_rollback`: the report gets less
    complete, the rollback does not get less effective.
    """
    return {prop: _text(run, ("nmcli", "-g", prop, "connection", "show", uuid)) for prop in RECORDED_PROPERTIES}


def emergency_rollback(root: Path, run: CommandRunner, probe=None) -> RollbackResult:
    """Put the recorded DNS back on a machine whose install died, and say whether it works.

    The record is the only input. No marker -- a machine whose install was killed
    has no marker, because Task 4 writes it last, and requiring one would make
    this command useless for exactly the machine it exists for. No preflight --
    the machine is broken, and a broken machine is the one that fails preflight.
    No ownership check -- the connection is expected to hold some mixture of this
    package's values and the recorded originals, and requiring it to hold exactly
    the former would refuse the case the command is for.

    What it does read is the connection itself, before it writes to it, and only so
    that the report can show both value sets. That is not a gate and nothing turns
    on the answer: a hand-edited connection is overwritten exactly as before, and
    the only difference is that an operator is now told what it was holding. A
    read that fails costs the report a column and nothing else.

    It restores ONLY the connection. It does not stop a unit, remove a file,
    disable anything or reload systemd, and the binaries and the configuration
    stay installed: an operator who has just watched their DNS die needs to be
    able to read the logs, and a rollback that tidied up would take the evidence
    with it.

    The verification asks whether this machine can RESOLVE, through resolved's
    stub, with the resolving half of the prober's two answers. Not whether
    something is listening: a SERVFAIL is a confident answer from a chain that
    reached nobody, and a rollback that called that success would hand the
    operator a machine with no DNS and a reassuring message. The profile being
    right is reported separately from the machine working, because on a machine
    where the upstream is down those are two different facts and only the first
    is this package's doing.
    """
    root = Path(root)
    ask = probe or (lambda address, port: probe_dns(address, port))
    document, refusals = _read_backup(root)
    if document is None:
        reasons = list(refusals) + [
            "an emergency rollback restores the last valid backup and there is not one here; it "
            "will not guess at a value, because a guessed resolver is a machine with no DNS",
            f"the connection on this machine may still be handing resolved the loopback address "
            f"{LOCAL_DNS}, and this program will not stop the router that answers it, because "
            "without a record of the original settings it could not put them back",
        ]
        return RollbackResult(
            ok=False,
            restored=False,
            notes=[],
            error="there is no valid backup to roll back to, so nothing was changed",
            manual_recovery=manual_recovery_report(
                "",
                None,
                {},
                reasons,
                summary=(
                    f"nothing on this machine has been changed, and {BACKUP_PATH} is where the "
                    "record of what this connection was set to would be if one had survived"
                ),
            ),
            resolves=None,
        )
    connection = document["connection"]
    uuid = str(connection["uuid"])
    device = str(connection["device"])
    original = document["original"]
    observed = _read_current_properties(run, uuid)
    unread = [
        prop
        for prop, value in observed.items()
        if _classify(prop, value, original[prop]["raw"]) == UNREADABLE
    ]
    notes = [
        f"{prop} of {uuid} is {COULD_NOT_BE_READ} in this report, so it cannot say what that "
        "property held; the values in the backup were written back regardless"
        for prop in unread
    ]
    ownership = Ownership(uuid, device, original, observed, _as_restored(original), [], [])
    # What REACHED the profile, appended as each write succeeds rather than taken
    # from what was intended. A first-modify failure means the second and third
    # were never written, so a hand-edited one of those has survived this run and
    # the report's leave line for it is the truth.
    written: List[str] = []
    for prop, value in ownership.restores:
        try:
            _checked(
                run,
                ("nmcli", "connection", "modify", uuid, prop, value),
                f"putting {prop} back to {value!r} on {uuid}",
            )
        except InstallRefused as error:
            return _rollback_stopped(ownership, str(error), False, None, notes, written)
        written.append(prop)
    try:
        _checked(
            run,
            ("nmcli", "connection", "up", uuid),
            f"reactivating {uuid} to apply what was put back",
        )
    except InstallRefused as error:
        return _rollback_stopped(ownership, str(error), True, None, notes, written)
    try:
        _device_follows_the_backup(run, ownership)
    except InstallRefused as error:
        return _rollback_stopped(ownership, str(error), True, None, notes, written)
    resolves = ask(RESOLVED_STUB_ADDRESS, DNS_PORT).resolves
    # The read failures collected before the first write stay on the notes: they
    # are still true of this run, and a report that lost them is a report that
    # looks complete.
    notes.append(
        f"connection {uuid} was put back on the resolvers {BACKUP_PATH} recorded, and the "
        "binaries and the configuration were left installed for diagnosis"
    )
    if not resolves:
        return RollbackResult(
            ok=False,
            restored=True,
            notes=notes,
            error=(
                f"the recorded values are restored on {uuid} and the connection was reactivated, "
                f"but a query for {INSTALL_PROBE_NAME} through {RESOLVED_STUB_ADDRESS} did not "
                f"resolve, so this machine still cannot resolve: check what {device} is using for "
                "DNS, and whether the resolvers it is using answer"
            ),
            manual_recovery=manual_recovery_report(
                uuid,
                original,
                observed,
                [
                    f"a query for {INSTALL_PROBE_NAME} through {RESOLVED_STUB_ADDRESS} did not "
                    "resolve after the restore, so the values this backup recorded are in place and "
                    "the machine still does not work"
                ],
                device=device,
                summary=(
                    f"the values in {BACKUP_PATH} are on connection {uuid} and it has been "
                    "reactivated; what is left is the resolver that connection is now using"
                ),
                written=written,
            ),
            resolves=False,
        )
    notes.append(
        f"{RESOLVED_STUB_ADDRESS} resolved {INSTALL_PROBE_NAME}, so this machine can resolve"
    )
    return RollbackResult(ok=True, restored=True, notes=notes, error=None, manual_recovery=None, resolves=True)



def _rollback_stopped(
    ownership: Ownership,
    error: str,
    restored: bool,
    resolves: Optional[bool],
    notes: Optional[List[str]] = None,
    written: Optional[Sequence[str]] = None,
) -> RollbackResult:
    """A rollback that put some of the recorded values back and then stopped.

    ``notes`` carries the read failures collected before the first write, because
    a report that cannot name the property it could not read is a report that
    looks like a report about a machine this run never looked at. ``written``
    names the properties that REACHED the profile, and the report needs it for the
    same reason it needs ``observed``: without it the report would tell an operator
    to leave a value at a number this run has already replaced, and claim a refusal
    that did not happen.
    """
    return RollbackResult(
        ok=False,
        restored=restored,
        notes=list(notes or []),
        error=(
            f"the rollback did not finish, so the connection is still partly as this package left "
            f"it: {error}"
        ),
        manual_recovery=manual_recovery_report(
            ownership.uuid,
            ownership.original,
            ownership.observed,
            [error],
            device=ownership.device,
            summary=(
                f"{BACKUP_PATH} records what connection {ownership.uuid} was set to, and the "
                "commands above are what puts the rest of it back"
            ),
            written=list(written or ()),
        ),
        resolves=resolves,
    )


# The exit statuses the command boundary uses. They are the CLI's own: 0 is a machine
# this can install onto, 1 is one it cannot, and 2 is a usage error.
#
# 3 and 4 are the two halves of a failed install, and they are separate statuses
# because an operator's next action differs. After 3 the machine is as it was found
# and the install can simply be repeated. After 4 it is not: something this package
# changed is still in place, no marker claims it, and the backup is the only record
# of what the connection was set to -- so that is a manual recovery, and a script
# that cannot tell the two apart will report "the install failed" about a machine
# that has lost its resolver.
#
# 5 and 6 are the same two machines reached from the other end, by the verbs that
# put a machine back rather than take it. 4 is about the INSTALL's own rollback
# failing while the install was running; 6 is about a restore this program was
# asked to perform and did not finish. Both mean "still applied", both carry a
# recovery line, and a caller that has to tell them apart can, because the
# situations are different: after 4 nobody asked for a restore, and after 6
# somebody did.
EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_INSTALL_FAILED = 3
EXIT_ROLLBACK_FAILED = 4
# Nothing was changed, because this program could not prove the DNS on this
# machine is its own to change. Distinct from 1 because 1 is about a machine's
# shape and this is about a claim on a machine, and the deliverable is a manual
# recovery report rather than a list of problems.
EXIT_OWNERSHIP_REFUSED = 5
# A restore was attempted and did not finish: some of this package's changes are
# still applied, and the manual recovery report is what finishes them.
EXIT_RESTORE_INCOMPLETE = 6


def _usage() -> str:
    return (
        "usage: mosdns_installer.py preflight [--check-only]\n"
        "       mosdns_installer.py install\n"
        "       mosdns_installer.py uninstall [--purge]\n"
        "       mosdns_installer.py emergency-rollback\n"
        "       mosdns_installer.py verify-local\n"
    )


def _run_verify_local(root: Path, probe) -> int:
    """Ask the machine's own resolver one question, and fail if it cannot answer it.

    This is the SECOND command of `mosdns-cdn-health.service`, and it exists
    because `health-check` proves the CDN address in service -- not
    `127.0.0.1:53`, which is the machine's whole path to DNS. With only the former,
    a router that had stopped passed a health check every two minutes for ever.

    The question is the installer's own, asked with the installer's own
    `probe_dns`, so "resolvable" has one definition in this package: a NOERROR or
    an NXDOMAIN, and not a SERVFAIL, a REFUSED or silence. That is the same
    predicate the install's barrier and its verification use, and re-implementing
    it here -- or, worse, in the health command's own Go -- is how two programs end
    up disagreeing about whether a machine has DNS.

    It changes nothing, and takes a `run` it does not need: the only thing it
    DOES is open a UDP socket to a loopback address and wait two seconds, plus the
    two file reads below.

    WHAT IT READS, and why the reads are the point rather than an exception. The
    install REFUSES to run its own checks when the router would answer
    `install-probe.example` itself from the operator's force-ECH list -- see
    `_refuse_a_locally_answered_probe`, which is the same two predicates this verb
    now uses. An operator who adds that name to `/etc/mosdns/force-ech-domains.txt`
    AFTER the install gets no such refusal, because there is no install to refuse:
    they get a health check that reports a working local resolver for ever,
    whatever the router is doing, because the answer it is reading was fabricated
    in-process by the thing it is supposed to be checking. That is the blind spot
    the install's guard was written for, inherited by the verb without the guard.

    So the verb refuses the verdict rather than reporting it. It FAILS rather than
    warning, and that is the fail-closed direction for a health check: a machine
    whose resolver cannot be proved is not a machine to call healthy, and the
    alternative -- a passing check that proves nothing -- is the exact failure this
    verb exists to remove. The message is explicit that this is NOT evidence the
    router is down, because the health unit failing is the signal for
    `emergency-rollback` and an operator who read this as "the resolver is dead"
    would roll back a working machine over a line in a text file.

    What a failed unit otherwise means is a DECISION this package does not make.
    Putting `emergency-rollback` on a timer would mutate a machine's DNS
    unattended, and an operator who has watched their DNS die is better served by a
    signal and a person: the health unit failing is the signal, `sudo mosdns-cdnctl
    emergency-rollback` is the action.
    """
    blind = next(
        (
            name
            for name in _forced_ech_domains(root)
            if _forces_ech((name,), INSTALL_PROBE_NAME)
        ),
        None,
    )
    if blind is not None and _ech_may_answer_locally(root):
        sys.stderr.write(
            f"verify-local: {FORCE_ECH_DOMAINS} lists {blind!r} and the policy asks for strict "
            f"ECH, so the router answers A queries for {INSTALL_PROBE_NAME} itself without asking "
            f"anything upstream. A resolved answer from {LOCAL_DNS}:{DNS_PORT} for that name is "
            "therefore evidence of nothing, so this verb cannot report a verdict at all rather "
            "than report a healthy one. THIS IS NOT A SIGN THE ROUTER IS DOWN: nothing was "
            f"probed and nothing was changed. An install refuses this machine for the same "
            f"reason, so the entry is out of step with what this package will install. Either "
            f"remove {blind!r} from {FORCE_ECH_DOMAINS} so this check can see the router, or "
            "accept that nothing on this machine can prove the local resolver is answering.\n"
        )
        return EXIT_REFUSED
    ask = probe or (lambda address, port: probe_dns(address, port))
    answer = ask(LOCAL_DNS, DNS_PORT)
    if answer.resolves:
        sys.stdout.write(
            f"verify-local: {LOCAL_DNS}:{DNS_PORT} resolved {INSTALL_PROBE_NAME}, so this machine's "
            "resolver is answering and the health check's verdict is about a working machine\n"
        )
        return EXIT_OK
    if answer.answered:
        sys.stderr.write(
            f"verify-local: {LOCAL_DNS}:{DNS_PORT} ANSWERED a query for {INSTALL_PROBE_NAME} and did "
            "not resolve it -- a SERVFAIL is a confident answer from a chain that reached nobody, "
            "and reading it as health is how a machine with no DNS is called healthy. The router or "
            "the resolver it forwards to is not working.\n"
        )
        sys.stderr.write(
            "verify-local: nothing has been changed by this command. The action is yours: "
            "`sudo mosdns-cdnctl emergency-rollback` puts the recorded DNS settings back.\n"
        )
        return EXIT_REFUSED
    sys.stderr.write(
        f"verify-local: nothing at all answered a query for {INSTALL_PROBE_NAME} at "
        f"{LOCAL_DNS}:{DNS_PORT} within {PROBE_TIMEOUT_SECONDS:g}s, so the machine's own resolver is "
        "not answering. Nothing has been changed by this command. The action is yours: "
        "`sudo mosdns-cdnctl emergency-rollback` puts the recorded DNS settings back.\n"
    )
    return EXIT_REFUSED


def _run_preflight(root: Path, run: CommandRunner) -> int:
    report = preflight(root, run)
    for note in report.notes():
        sys.stdout.write(f"note: {note}\n")
    for problem in report.problems():
        sys.stderr.write(f"preflight: {problem}\n")
    if not report.ok:
        sys.stderr.write(
            f"preflight: {len(report.problems())} problem(s); nothing has been changed, and "
            "the package's own provisioning is what creates the directories above\n"
        )
        return EXIT_REFUSED
    sys.stdout.write(
        "preflight: this machine can have this router installed on it; nothing has been changed\n"
    )
    return EXIT_OK


def _run_install(root: Path, run: CommandRunner, probe) -> int:
    result = install(root, run, probe=probe)
    for note in result.notes:
        sys.stdout.write(f"note: {note}\n")
    if result.ok:
        sys.stdout.write(
            f"install: {DNS_PORT} and {RESOLVER_PORT} are served on loopback and NetworkManager has "
            f"been pointed at {LOCAL_DNS}; the ownership marker at {MANAGED_BY} has been written, so "
            "an uninstall will restore exactly what was changed\n"
        )
        return EXIT_OK
    if result.report is not None and not result.report.ok:
        for problem in result.report.problems():
            sys.stderr.write(f"preflight: {problem}\n")
        sys.stderr.write(f"install: {result.error}\n")
        return EXIT_REFUSED
    sys.stderr.write(f"install: {result.error}\n")
    if result.rollback_error:
        sys.stderr.write(
            "install: the rollback did not finish, so these changes are still applied on this "
            f"machine: {result.rollback_error}\n"
        )
        if result.recovery:
            sys.stderr.write(f"install: what is left is this: {result.recovery}\n")
        sys.stderr.write(
            f"install: {result.backup or BACKUP_PATH} records what connection "
            f"{connection_of(result.report)} was set to before this run, and {MANAGED_BY} was NOT "
            "written, so an uninstall will refuse to restore automatically and this machine needs "
            "the manual recovery report\n"
        )
        return EXIT_ROLLBACK_FAILED
    # "Nothing is different" is a claim, and there is one case where this module
    # makes it deliberately false: a unit whose prior state could not be read is
    # started and then left running, because stopping somebody else's unit is the
    # harm the rollback rule exists to prevent. So the claim is qualified by name
    # rather than made unconditionally, which would be the kind of sentence an
    # operator stops reading after the first time it was wrong.
    exception = ""
    if result.left_running:
        exception = (
            " except "
            + " and ".join(result.left_running)
            + ", which this run started and then left as it found them, because it could not "
            "read whether they were already running and will not stop a unit it did not know to "
            "own"
        )
    sys.stderr.write(
        f"install: every change this run made has been rolled back, and "
        f"{result.backup or BACKUP_PATH} records what the connection was set to; nothing else is "
        f"different about this machine{exception}\n"
    )
    return EXIT_INSTALL_FAILED


def _run_uninstall(root: Path, run: CommandRunner, purge: bool, probe) -> int:
    result = uninstall(root, run, purge=purge, probe=probe)
    if result.refusals:
        # Nothing was changed, so the whole of the output is the refusal and the
        # report. The reasons appear in both because the report has to stand alone
        # -- it is the thing an operator pastes into a ticket, and a report that
        # pointed at the lines above it would be useless there -- and the prefixed
        # lines are what a script greps for.
        for refusal in result.refusals:
            sys.stderr.write(f"uninstall: {refusal}\n")
        sys.stderr.write(f"{result.manual_recovery}\n")
        return EXIT_OWNERSHIP_REFUSED
    # What happened to the state directory is printed FIRST, and the notes after
    # it, so the last line of the output is the verdict on the machine rather than
    # a note about a directory. The two facts are equally true and only one of
    # them is what an operator who reads only the last line needs to know.
    if result.purged:
        sys.stdout.write(
            f"uninstall: {STATE_DIRECTORY} and everything in it has been removed, and nothing "
            f"else under /etc was touched; the backup that was in it said what this connection was "
            "set to, and it is now gone\n"
        )
    else:
        sys.stdout.write(
            f"uninstall: {STATE_DIRECTORY} was kept, including {BACKUP_PATH} and the marker, "
            "because --purge was not asked for; a machine with no marker is a machine a later "
            "install will treat as somebody else's\n"
        )
    for note in result.notes:
        sys.stdout.write(f"uninstall: {note}\n")
    if result.error:
        sys.stderr.write(f"uninstall: {result.error}\n")
    if not result.ok:
        sys.stderr.write(f"{result.manual_recovery}\n")
        return EXIT_RESTORE_INCOMPLETE
    return EXIT_OK


def _run_emergency_rollback(root: Path, run: CommandRunner, probe) -> int:
    result = emergency_rollback(root, run, probe=probe)
    for note in result.notes:
        sys.stdout.write(f"rollback: {note}\n")
    if not result.ok:
        sys.stderr.write(f"rollback: {result.error}\n")
        sys.stderr.write(f"{result.manual_recovery}\n")
        return EXIT_RESTORE_INCOMPLETE if result.restored else EXIT_OWNERSHIP_REFUSED
    return EXIT_OK


def main(
    argv: Sequence[str],
    run: Optional[CommandRunner] = None,
    root: Path = Path("/"),
    probe=None,
) -> int:
    """Run ``preflight`` to report, or one of the verbs that change the machine.

    Three verbs change a machine and two do not, and the difference between
    reporting a problem and changing the machine is the difference this program
    exists to keep, so it is a verb and not a flag. ``preflight`` changes nothing by
    construction; ``install`` changes a machine's DNS and puts it back if anything
    goes wrong. ``verify-local`` is the odd one: it is a verb because it is a
    QUESTION with an exit status rather than a mode of another verb, it is
    read-only, and a `mosdns-cdn-health.service` ExecStart line needs a program to
    run.

    ``--check-only`` is accepted for ``preflight`` and is not a flag in disguise: it
    names the only mode that verb has. ``--purge`` is the only flag ``uninstall``
    takes and it is a separate verb's worth of decision -- whether the operator's
    data goes -- rather than a detail, so a repeated ``--purge`` is a usage error
    rather than a second permission.

    ``run``, ``root`` and ``probe`` are the three seams :func:`preflight`,
    :func:`install`, :func:`uninstall` and :func:`emergency_rollback` have, and they
    are named here in the other order from :func:`preflight`, which takes
    ``(root, run)``. A command whose root could not be pointed elsewhere could only
    be tested against the machine it ran on, and a test here that read the host's
    NetworkManager, ports and ``/etc/resolv.conf`` would be a test of the host
    wearing a test's name. ``probe`` is here for the same reason and one more: a
    DNS query is a real request to a real resolver, and the last three verbs ask
    one. ``verify-local`` needs no runner -- it issues no command at all -- but it
    does read the policy and the operator's force-ECH list through ``root``, so
    that a test can point it at a fake root and a test that could not inject the
    probe into it would still be a test that queried a real resolver.
    """
    arguments = list(argv)
    if arguments[:1] == ["preflight"]:
        if arguments[1:] not in ([], ["--check-only"]):
            sys.stderr.write(f"{_usage()}\n")
            return EXIT_USAGE
        return _run_preflight(root, run or RealCommandRunner())
    if arguments == ["install"]:
        return _run_install(root, run or RealCommandRunner(), probe)
    if arguments[:1] == ["uninstall"]:
        purge = False
        for argument in arguments[1:]:
            if argument != "--purge" or purge:
                sys.stderr.write(f"{_usage()}\n")
                return EXIT_USAGE
            purge = True
        return _run_uninstall(root, run or RealCommandRunner(), purge, probe)
    if arguments == ["emergency-rollback"]:
        return _run_emergency_rollback(root, run or RealCommandRunner(), probe)
    if arguments == ["verify-local"]:
        return _run_verify_local(root, probe)
    sys.stderr.write(f"{_usage()}\n")
    return EXIT_USAGE


# The process entry point, and the reason this file is shipped as an executable
# program rather than imported by something else.
#
# Two callers exec this exact path and both need it to be a program: the package's
# postinst and prerm run it, and `mosdns-cdnctl emergency-rollback` executes
# `/usr/lib/mosdns-router/mosdns_installer.py` with an argument array. A module with
# no `__main__` guard is neither of those things -- exec'ing it starts a Python
# process that defines everything and exits 0, so a postinst that called it would
# report a successful installation of a machine on which nothing had been installed.
#
# It holds nothing but the translation of a verb into an exit status, which is the
# whole of what an entry point is allowed to decide. `main` itself raises nothing,
# and every status it returns is its own.
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
