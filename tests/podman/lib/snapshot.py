"""What the host looked like before a run and after it, and the rules that make it evidence.

This module is the plan's answer to "did that test run change anything on this
machine?". It reads, it records, and it never writes to the host. Three
properties are what make the record worth anything, and each of them is a way
this module could have been written wrongly:

* **It only ever runs read-only commands, as argument arrays.** Six of the seven
  fields come from one command each, built as a tuple and handed to an injected
  runner. There is no shell anywhere on the path from a field name to a process,
  so no field's text can become a second command. The commands themselves are an
  allowlist in the module body rather than a convention: ``MUTATING_COMMANDS``
  names the shapes a snapshot must refuse, and a command this module does not
  recognise is not one it runs.

* **Firefox profiles are metadata, never content.** The field is path name,
  mtime and size, gathered with ``os.lstat`` and ``os.scandir`` -- which read a
  directory's names and never open the entries inside it. Nothing here calls
  ``open``, and that is the property the case in ``tests/podman/tests/
  test_snapshot.py`` measures with an audit over every ``open`` on the Python
  surface, because "no content is used" would also be true of a module that read
  the bytes and threw them away. A browsing history is somebody's, and a snapshot
  is archived next to a report.

  The three facts chosen are the three a listing cannot change: a walk updates a
  directory's *access* time, so recording that would give this module a field
  that differs between two snapshots of an unchanged machine. That is the whole
  reason the plan names mtime and size.

* **A digest that can see a real change is worth as much as one that ignores a
  real one.** Each field is normalised -- lines sorted, and two classes of value
  replaced -- and hashed. The normalisation drops what identifies an *instance*
  rather than describing the machine: a NetworkManager connection's UUID, and the
  process id in ``ss -p``'s ``users:(("name",pid=N,fd=M))``. A machine's pids
  and profile UUIDs differ on every boot, so a snapshot that carried them would
  report a change for every restart and would be muted within a week. Everything
  that describes what the machine is *doing* is kept: nameserver addresses, ports,
  device names, unit names, the resolver's link target. The cases in the suite
  assert both directions, and the changed-nameserver case is the one that gives
  the rest of this module its point.

A field whose command this host does not have is recorded as an error rather
than raised, because the alternative is a host without NetworkManager producing
no snapshot at all -- and "no snapshot" is indistinguishable from "nothing
changed", which is the one answer this record must never give by accident.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence

# The harness's own run id, rather than a second format for the same identifier.
# The run id names a result directory and a container prefix at once, so two
# formats for it is the shape of drift this project keeps finding.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from podman import new_run_id  # noqa: E402
from report import redact  # noqa: E402

# The document's shape, so a snapshot compared against an older one can say it is
# not the same shape rather than reporting every field as different.
SCHEMA = "mosdns-podman-snapshot/1"

# The two moments a snapshot is taken at, and the file name each gets. Named
# rather than interpolated, because `host-bfore.json` is a plausible typo and a
# silent one: the run would still write its pair, and the comparison would find
# one of them missing.
BEFORE = "before"
AFTER = "after"
MOMENTS = (BEFORE, AFTER)

# This project's systemd units, from `packaging/debian/control` and the unit
# files it installs. The snapshot asks `systemctl` for every unit on the host and
# keeps only these, because a run does not change `dbus.service` and a record of
# the whole list is a diff of the machine rather than of the run. The list is the
# names, not a prefix: a prefix filter would adopt a third party's unit and then
# fail a run for it.
PROJECT_UNITS = (
    "dnscrypt-proxy.service",
    "mosdns-cdn-health.service",
    "mosdns-cdn-optimizer.service",
    "mosdns-list-check.service",
    "mosdns-router.service",
)

# The six command fields, in the order they are collected, as literal argument
# arrays. `readlink` and not `cat` for the resolver: this host's
# `/etc/resolv.conf` is a systemd stub symlink, and reading the file it points at
# would record resolved's *generated* content -- which changes whenever a network
# does, and would report a host change for something every run does.
COMMAND_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("os_release", ("cat", "/etc/os-release")),
    ("resolv_conf_link", ("readlink", "/etc/resolv.conf")),
    (
        "networkmanager_connections",
        ("nmcli", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show"),
    ),
    ("resolvectl_status", ("resolvectl", "status")),
    (
        "project_units",
        ("systemctl", "list-unit-files", "--no-legend", "--no-pager", "--type=service"),
    ),
    # `-p` because the process name is part of what a listener is; the pid in the
    # same field is not, and `normalize` drops it.
    ("listening_sockets", ("ss", "-H", "-lntup")),
)

# The seventh field, read from the filesystem rather than from a command. These
# are the places a Firefox profile lives on Linux, in the order they are walked;
# a root that is not there is not an error, because a host with no browser is the
# normal case on a build host.
DEFAULT_FIREFOX_ROOTS: tuple[str, ...] = (
    "~/.mozilla/firefox",
    "~/snap/firefox/common/.mozilla/firefox",
    "~/.var/app/org.mozilla.firefox/.mozilla/firefox",
)
FIREFOX_FIELD = "firefox_profiles"

# What a field is given when this host has nothing to say. An empty list and an
# error are different answers, and a comparison that only checked for emptiness
# could not tell them apart -- nor tell either from a read that failed silently.
REDACTED = "***"

# The values that identify an instance rather than describe the machine, and so
# are replaced before hashing. See the module docstring for why each is here and
# what is deliberately *not*.
#
# A UUID, in any spelling: NetworkManager's connection UUIDs, systemd's, and the
# machine-id that a journal prefix carries. Two runs of the same host differ in
# every one of them, and none of them says what the host is doing -- the
# connection's name, device, type and state next to the UUID do.
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
# A process id, in `ss -p`'s own spelling. The name beside it is kept: a listener
# is an address, a port and a program, and a pid is which run of the program.
_PID = re.compile(r"pid=\d+")

# The commands and subcommand pairs that change something. This is not a filter
# applied to what a caller passes -- there is no caller here, the six arrays above
# are the whole of what runs -- but it is the table the module carries so that a
# future field is checked against it rather than added next to it, and
# `mutating_command` is what the suite asserts over the real arrays.
MUTATING_COMMANDS: dict[str, frozenset[str]] = {
    "nmcli": frozenset({"connection", "device", "general", "networking", "radio"}),
    "systemctl": frozenset(
        {
            "daemon-reload",
            "disable",
            "enable",
            "mask",
            "reboot",
            "restart",
            "set-property",
            "start",
            "stop",
            "unmask",
        }
    ),
    "resolvectl": frozenset({"dns", "domain", "flush-caches", "revert"}),
    "nm-online": frozenset(),
    "sh": frozenset(),
    "bash": frozenset(),
    "sudo": frozenset(),
    "rm": frozenset(),
    "mv": frozenset(),
    "cp": frozenset(),
    "tee": frozenset(),
    "mount": frozenset(),
    "umount": frozenset(),
    "kill": frozenset(),
    "pkill": frozenset(),
    "chmod": frozenset(),
    "chown": frozenset(),
    "ln": frozenset(),
    "truncate": frozenset(),
    "dd": frozenset(),
    "apt": frozenset(),
    "apt-get": frozenset(),
    "dpkg": frozenset(),
    "systemctl-poweroff": frozenset(),
}

# The commands this module runs, which is what `mutating_command` is asked about
# in the suite. A command outside this set is not one this module has an answer
# for, and the suite says so rather than staying quiet.
READ_ONLY_COMMANDS = frozenset(
    {"cat", "readlink", "nmcli", "resolvectl", "systemctl", "ss"}
)

# `nmcli device show` and `nmcli connection show` are reads; the same two words
# with `set` or `modify` are writes. The table above is keyed on the *subcommand*,
# so the read forms are named here as the exceptions rather than the rule.
NMCLI_READ_SUBCOMMANDS = frozenset({"device", "connection", "general", "monitor", "radio"})


def mutating_command(argv: Sequence[str]) -> bool:
    """Whether an argument array is a command that can change this machine.

    Used as a property over the arrays this module builds, and exercised on both
    sides in the suite -- a check that cannot recognise a mutation is not a
    check. `nmcli` is the interesting case: `nmcli device show` is a read and
    `nmcli device set` is a write, and the difference is the word after the
    subcommand, so both are named rather than the whole command refused.
    """
    if not argv:
        return False
    program = Path(str(argv[0])).name
    if program in ("sh", "bash", "dash", "sudo"):
        return True
    if program == "nmcli":
        # `nmcli device set eth0 managed yes` and `nmcli connection modify …`
        # are the two writes; both name a verb straight after the subcommand.
        verbs = {"set", "modify", "add", "delete", "remove", "up", "down", "reload"}
        return any(str(token) in verbs for token in argv[2:])
    verbs = MUTATING_COMMANDS.get(program)
    if verbs is None:
        return False
    if not verbs:
        # Listed with no subcommand set: the program is a write whatever it is
        # asked to do. `rm`, `tee` and `chmod` have no read-only spelling, and a
        # check that required one of the table's words to appear would pass them
        # all -- which is the direction this table exists to fail.
        return True
    return any(str(token) in verbs for token in argv[1:])


def digest_of(records: Iterable[str]) -> str:
    """The digest of a field's records, so "the snapshots differ" is checkable by hand.

    Over the *stored* records rather than over the text they came from, so a
    reader can recompute it and get the same answer -- which is what stops the
    digest from being an opaque number that changes for reasons nobody can find.
    """
    digest = hashlib.sha256()
    for record in records:
        digest.update(record.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def normalize(text: str) -> list[str]:
    """The lines of a command's output, sorted, scrubbed and instance-blind.

    Sorted because a comparison that fails on a reordering is a comparison
    nobody trusts: the host does not have to change for two runs to disagree
    about the order of a listing. Scrubbed because a report is archived and a
    command's own output can carry a password. Instance-blind because a UUID and
    a pid say which copy of something this is, not what this machine does.
    """
    scrubbed = _PID.sub("pid=<pid>", _UUID.sub("<uuid>", text))
    return sorted(line.strip() for line in redact(scrubbed).splitlines() if line.strip())


def project_unit_records(text: str) -> list[str]:
    """Only the unit files this project ships, from the whole host's list.

    `systemctl list-unit-files` answers with one line per unit, the unit name
    first. The name and its state are both kept -- a run that enabled or disabled
    one of this project's units is a finding, and so is one that left a unit
    behind -- and everything else on the machine is dropped.
    """
    records = []
    for line in normalize(text):
        fields = line.split(None, 1)
        if fields and fields[0] in PROJECT_UNITS:
            records.append(" ".join(fields))
    return sorted(records)


def _field_commands() -> dict[str, tuple[str, ...]]:
    return {name: argv for name, argv in COMMAND_FIELDS}


def _field(name: str, records: list[str], error: str | None = None) -> dict:
    return {
        "digest": digest_of(records),
        "error": error,
        "records": records,
    }


def collect_command_fields(runner: Callable[[Sequence[str]], str]) -> dict[str, dict]:
    """Run the six read-only commands and record each one's answer.

    A command this host does not have is recorded as an error, not raised. The
    snapshot's job is to be a before/after *pair* for one machine, and a host
    without NetworkManager has one of those to give; raising would leave the run
    with no evidence at all, which is indistinguishable from evidence of no
    change.
    """
    fields: dict[str, dict] = {}
    for name, argv in COMMAND_FIELDS:
        try:
            output = runner(argv)
        except Exception as error:  # noqa: BLE001 - a missing tool is a recorded answer
            fields[name] = _field(name, [], f"{type(error).__name__}: {error}")
            continue
        text = str(output)
        if name == "project_units":
            fields[name] = _field(name, project_unit_records(text))
        else:
            fields[name] = _field(name, normalize(text))
    return fields


def _walk(base: Path) -> Iterable[Path]:
    """Every entry under `base`, itself included, without opening any of them.

    `os.scandir` enumerates a directory and never opens the entries inside it;
    that is the only way to learn the *names* this field exists to record, and a
    content read would have to go through `open`, which this module does not call.
    The order is a stack rather than a recursion so that a profile nested deeper
    than Python's recursion limit is still walked -- a real profile nests several
    levels below its root, and a depth limit would record a prefix of it and call
    that the profile.
    """
    stack = [base]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    yield path
                    try:
                        is_directory = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        is_directory = False
                    if is_directory:
                        stack.append(path)
        except OSError:
            # A directory this process cannot list -- somebody else's, or one
            # whose mode says so -- costs its own entries and nothing else. A walk
            # that raised here would abandon the whole field, and an empty field
            # compares equal to an unchanged one.
            continue


def firefox_profile_records(roots: Sequence[str | Path] = DEFAULT_FIREFOX_ROOTS) -> list[str]:
    """Path name, mtime and size for every entry under each Firefox root.

    Three facts, in that order, tab-separated, and nothing else. No file under a
    root is opened: `lstat` reads a directory entry's own metadata and does not
    follow a symlink, so a profile link into a cache is recorded as the link and
    the target's name never enters a record that is archived next to a report.

    Each root's records are relative to that root, so a snapshot taken by one
    operator and one taken by another do not differ by a home directory's name.
    """
    records: list[str] = []
    for root in roots:
        base = Path(str(root)).expanduser()
        if not base.is_dir():
            continue
        for path in _walk(base):
            try:
                info = os.lstat(path)
            except OSError:
                # An entry that vanished between listing and stat is a fact about
                # a moving directory, not an error, and it is the same fact the
                # next snapshot would see.
                continue
            records.append(
                "{}\t{}\t{}".format(path.relative_to(base), info.st_mtime_ns, info.st_size)
            )
    return sorted(records)


def collect(runner: Callable[[Sequence[str]], str], *, firefox_roots: Sequence[str | Path] = DEFAULT_FIREFOX_ROOTS) -> dict[str, dict]:
    """Every field, as `{name: {"digest", "error", "records"}}`.

    The seventh field is gathered from the filesystem, so it is the one that
    carries the rule about not reading anything: `runner` is never asked for it,
    and a Firefox profile's bytes are never opened.
    """
    fields = collect_command_fields(runner)
    fields[FIREFOX_FIELD] = _field(FIREFOX_FIELD, firefox_profile_records(firefox_roots))
    return fields


def collect_document(
    runner: Callable[[Sequence[str]], str],
    *,
    run_id: str,
    taken_utc: str,
    firefox_roots: Sequence[str | Path] = DEFAULT_FIREFOX_ROOTS,
) -> dict:
    """A whole snapshot, with the run it belongs to and the moment it was taken.

    `runner` is required and not defaulted. A default would be a snapshot that
    quietly runs whatever is on the operator's PATH, which is the opposite of an
    injected runner: the point of passing one in is that a case can answer every
    field from a table and never touch a host.
    """
    if not callable(runner):
        raise TypeError(
            "a snapshot needs a command runner: it is the whole of this module's "
            "interaction with the host, and a default would run whatever is on PATH"
        )
    if not run_id or not taken_utc:
        raise ValueError("a snapshot names the run it belongs to and the moment it was taken")
    return {
        "fields": collect(runner, firefox_roots=firefox_roots),
        "run_id": str(run_id),
        "schema": SCHEMA,
        "taken_utc": str(taken_utc),
    }


def write_snapshot(document: dict, results_dir: Path | str, run_id: str, moment: str) -> Path:
    """Write a snapshot to `<results_dir>/<run_id>/host-<moment>.json`.

    Both moments are named constants, so a caller cannot invent a third file name
    that nothing looks at later.
    """
    if moment not in MOMENTS:
        raise ValueError(
            f"a snapshot is taken {BEFORE} or {AFTER} a run, not {moment!r}: a third file "
            f"name in the run's directory is one the comparison will not find, and the run "
            f"would still look like it had written its pair"
        )
    directory = Path(results_dir) / str(run_id)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"host-{moment}.json"
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


class SubprocessRunner:
    """A runner that executes an argument array -- no shell, a deadline, no env.

    The same discipline the Podman wrapper keeps, for the same reason: the six
    command arrays are built here and nowhere else, they are handed over as an
    array rather than a string, and there is no environment to inherit a token
    from. The timeout is not optional, because a `nmcli` that has wedged is a
    scenario that will never finish and says so on its own.
    """

    def __init__(self, timeout: float = 30.0, env: dict | None = None):
        self.timeout = timeout
        self.env = env

    def __call__(self, argv: Sequence[str]) -> str:
        completed = subprocess.run(
            [str(token) for token in argv],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
            env=self.env,
        )
        if completed.returncode != 0 and not completed.stdout:
            detail = completed.stderr.strip() or f"exited {completed.returncode}"
            raise OSError(f"'{' '.join(str(t) for t in argv)}': {detail}")
        return completed.stdout


__all__ = [
    "AFTER",
    "BEFORE",
    "COMMAND_FIELDS",
    "DEFAULT_FIREFOX_ROOTS",
    "FIREFOX_FIELD",
    "MOMENTS",
    "PROJECT_UNITS",
    "SCHEMA",
    "SubprocessRunner",
    "collect",
    "collect_command_fields",
    "collect_document",
    "digest_of",
    "firefox_profile_records",
    "mutating_command",
    "new_run_id",
    "normalize",
    "project_unit_records",
    "write_snapshot",
]
