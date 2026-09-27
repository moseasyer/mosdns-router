"""Check that this machine can have this router installed on it, and change nothing.

This module is the only part of the installer that runs before the package owns
anything, so it has exactly two jobs and the whole design follows from them:

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

Nothing here is a network, a service or a file write. ``--check-only`` reads
``/etc/os-release``, asks four read-only questions of systemd and NetworkManager,
reads the state directories' metadata, and reports. If it cannot answer a
question it says so; it never answers "fine" from a failed read, because the
installer's next step binds a privileged port and a second answer that does not
exist is how two resolvers end up fighting over port 53.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional, Sequence

__all__ = [
    "CommandRunner",
    "Completed",
    "Connection",
    "Preflight",
    "RealCommandRunner",
    "check_connection",
    "check_control_lock",
    "check_dependencies",
    "check_ech",
    "check_foreign_services",
    "check_ports",
    "check_release",
    "check_resolv_conf",
    "check_state_directories",
    "preflight",
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
STATE_DIRECTORIES = (
    "/var/lib/mosdns",
    "/var/lib/mosdns/runtime",
    "/var/lib/mosdns/lists",
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
PROJECT_UNITS = (
    ROUTER_UNIT,
    RESOLVER_UNIT,
    "mosdns-cdn-optimizer.timer",
    "mosdns-cdn-health.timer",
    "mosdns-list-check.timer",
)
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

# The connection types that carry a machine's DNS. A VPN or a bridge with no
# device is neither the primary uplink this install rewrites nor a source of the
# lease the router follows, and a loopback device is never one.
PRIMARY_CONNECTION_TYPES = ("802-3-ethernet", "802-11-wireless", "ethernet", "wifi")

# The path systemd-resolved's stub is reached at, and the address that stub
# answers on. The installer replaces the stub, so a resolv.conf pointing anywhere
# else means something other than resolved is in charge of DNS today.
RESOLVED_STUB_PATH = "run/systemd/resolve/stub-resolv.conf"
RESOLVED_STUB_ADDRESS = "127.0.0.53"

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
    """
    bare = address.strip("[]")
    if bare.startswith("::1") or bare == "::1":
        return True
    if bare.startswith("::ffff:127."):
        return True
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


def _is_exempt(holder: Holder, resolved_pid: Optional[int], own_pids: dict) -> bool:
    """Whether a holder is one this install expects to find already there.

    Two exemptions and nothing else. systemd-resolved's stub, because the design
    keeps resolved in front of the router and its socket on port 53 is the machine
    working; and a unit of this package's own, because the port check must not be
    the thing that fails an upgrade.

    Both are matched on the owning process and not on the port, and the resolved
    one is matched on the address as well: a foreign process that has taken
    127.0.0.53 is two answers for one query, and the port being the right number
    is not a reason to let it stand. A socket with no identifiable owner is not
    exempt, and neither is one whose only match is a different address from the
    stub's. The second exemption is gated on the ownership marker, which is the
    same claim check_foreign_services makes -- a mosdns-router process this install
    did not start is a foreign installation whatever it is called.
    """
    if not holder.owners:
        return False
    for owner in holder.owners:
        if owner.pid is None:
            continue
        if resolved_pid is not None and owner.pid == resolved_pid and _is_loopback(holder.address):
            return True
        if owner.pid in own_pids:
            return True
    return False


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
    """The domains the operator forces ECH for, ignoring blanks and comments."""
    try:
        contents = (root / "etc/mosdns/force-ech-domains.txt").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    domains = []
    for line in contents.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            domains.append(stripped)
    return domains


def _ech_is_strict(root: Path) -> Optional[bool]:
    """Whether the installed policy asks for strict ECH, or ``None`` if it cannot say.

    A policy that cannot be read is not a strict one. The install renders the
    document itself, and refusing here would stop an install because a file has
    not been written yet -- which is the normal state before the first run.
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
    """
    domains = _forced_ech_domains(root)
    strict = _ech_is_strict(root)

    completed = _ok(run, ("firefox", "--version"))
    if completed is None:
        report.note(
            "no Firefox was found on this machine, so nothing here can use ECH; the router "
            "still serves every other query, and a client on another machine is unaffected"
        )
        return
    version = completed.stdout.strip()
    report.firefox = version
    major = _firefox_major(version)
    if major is None:
        report.note(f"Firefox reported {version!r}, whose version could not be read, so ECH availability is unknown")
        return
    if major >= MINIMUM_ECH_FIREFOX:
        report.mark_ech_available()
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


def check_control_lock(root: Path, run: CommandRunner, report: Preflight) -> None:
    """Report a control lock that already exists and is not this package's.

    The lock is created on first acquire by whichever of the two identities wins
    the race, at 0640, so its absence is the normal state on a fresh machine and
    is not a problem. Its *presence* at another mode, or owned by anybody but
    root and this package's group, means a file this package did not create: a
    world-writable lock is a lock any local user can take, and a lock in another
    group's hands is a lock this package's own control operations would contend
    with. Re-creating it would be a repair, and postinst owns repairs.
    """
    path = root / CONTROL_LOCK.lstrip("/")
    if not path.exists():
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


# The exit statuses the command boundary uses. They are the CLI's own: 0 is a
# machine this can install onto, 1 is one it cannot, and 2 is a usage error.
EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2


def _usage() -> str:
    return "usage: mosdns_installer.py preflight [--check-only]"


def main(argv: Sequence[str], run: Optional[CommandRunner] = None, root: Path = Path("/")) -> int:
    """Run ``preflight`` and report what it found.

    ``--check-only`` is the only mode and it is not a flag in disguise: it names
    what the command does, which is check and nothing else. A later mode that
    provisions would be a different verb rather than a flag on this one, because
    the distinction between reporting a problem and fixing it is the distinction
    this program exists to keep.

    ``run`` and ``root`` are the same two seams :func:`preflight` has, in the same
    order. A command whose root could not be pointed elsewhere could only be
    tested against the machine it ran on, and a test here that read the host's
    NetworkManager, ports and ``/etc/resolv.conf`` would be a test of the host
    wearing a test's name.
    """
    arguments = list(argv)
    if not arguments or arguments[0] != "preflight":
        sys.stderr.write(f"{_usage()}\n")
        return EXIT_USAGE
    if arguments[1:] not in ([], ["--check-only"]):
        sys.stderr.write(f"{_usage()}\n")
        return EXIT_USAGE
    report = preflight(root, run or RealCommandRunner())
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


if __name__ == "__main__":  # pragma: no cover - the process boundary
    raise SystemExit(main(sys.argv[1:]))
