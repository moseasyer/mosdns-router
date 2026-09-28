"""What the host looked like before a run and after it, and the rules that make it evidence.

This module is the plan's answer to "did that test run change anything on this
machine?". It reads, it records, and it never writes to the host. Three
properties are what make the record worth anything, and each of them is a way
this module could have been written wrongly:

* **It only ever runs read-only commands, as argument arrays.** Six of the seven
  fields come from one command each, built as a tuple and handed to an injected
  runner. There is no shell anywhere on the path from a field name to a process,
  so no field's text can become a second command. The commands themselves are an
  allowlist in the module body rather than a convention: ``READ_ONLY_PROGRAMS``
  names the six, ``WRITE_VERBS`` and ``NMCLI_WRITE_PAIRS`` say which invocations of
  them write, and a program the module does not recognise is refused rather than
  assumed a read.

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
# `Mapping` is here because `SubprocessRunner.__init__` annotates `extra_env` with
# it, and this module defers annotation evaluation, so the name is not resolved at
# import time and its absence was invisible to every case in the suite -- and to
# `make verify`, which runs no Python linter. It is not invisible to anything that
# *does* resolve hints: `typing.get_type_hints` raised `NameError`, which is what
# `PublicSurfaceTypeHintsTest` in `tests/podman/tests/test_snapshot.py` holds.
from typing import Callable, Iterable, Mapping, Sequence

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

# The directory the package's systemd units live in, and the one thing the
# derivation below cannot do.
#
# **Derived, not listed.** A literal tuple of five names was here, with a test's
# docstring claiming "the names come from the package" -- and a sixth unit shipped
# by the package would have been absent from the `project_units` field, which is
# one of the seven the host-isolation comparison reads. So the unit a run left
# behind would not be in the record that exists to catch it, and nothing would say
# so. Reading the directory is the difference between a list and an inventory.
#
# **The limit, stated rather than implied:** this follows one directory. A unit
# the package installed from anywhere else would be missed, and no case here can
# tell that from the outside without becoming a second inventory of the package --
# which is the thing that drifts. A unit installed from elsewhere is a change to
# this function, and the case in the suite holds the record of that.
PACKAGING_UNIT_DIRECTORY = "packaging/systemd"


def project_units() -> tuple:
    """The unit files the package ships, as `*.service` names.

    Read from the package's own directory on every call rather than computed at
    import, so a unit added to the package is in the next snapshot without this
    module being reloaded -- and so a checkout without the directory fails at the
    point of use with a message saying why, rather than at import with a
    `NameError`.

    **What it does not do:** a unit the package installed from somewhere other
    than `packaging/systemd` is not found. No case here can tell that from the
    outside without becoming a second inventory of the package, which is the thing
    that drifts. A unit installed from elsewhere is a change to
    `PACKAGING_UNIT_DIRECTORY`, and `ProjectUnitDerivationTest` holds this
    paragraph so the limit stays written down.
    """
    directory = Path(__file__).resolve().parents[3] / PACKAGING_UNIT_DIRECTORY
    if not directory.is_dir():
        raise RuntimeError(
            f"cannot tell which units this project ships: {directory} does not exist, so the "
            f"project_units field would be empty and an empty field compares equal to a host "
            f"that changed nothing. The harness runs from a source checkout, so this is a "
            f"checkout that is not one"
        )
    return tuple(sorted(path.name for path in directory.glob("*.service")))

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

# The six programs a snapshot runs, and the fact that all six are reads **at the
# program level** -- the question then becomes which *invocation* of them is a
# read, which is answered per program below.
#
# Named explicitly, and the enumeration is held by a case over `COMMAND_FIELDS`:
# the alternative is a table of programs that can write, and a program missing
# from it is then a read by default. That default is the wrong direction for a
# module whose whole purpose is to prove a run changed nothing.
READ_ONLY_PROGRAMS = frozenset(
    {"cat", "readlink", "nmcli", "resolvectl", "ss", "systemctl"}
)

# Programs that run a command through a shell, or with privileges this module never
# wants. Not used by any field -- they are here because the rule "no shell, ever"
# is a property of `mutating_command` and a caller reading a field's array should
# find the table closed rather than discover the gap by running it.
SHELL_WRAPPERS = frozenset({"bash", "dash", "sh", "sudo"})

# The subcommand verbs that write, per program. `cat`, `readlink` and `ss` have no
# such verb -- every invocation of them is a read -- and their absence from this
# table is the point.
#
# `nmcli` is the awkward one and gets its own handling below: `nmcli device show`
# is a read and `nmcli device set` is a write, and the difference is the word after
# the subcommand. Three of the pairs are mutations with **no** verb in
# `NMCLI_WRITE_VERBS` at all -- `nmcli radio wifi on` turns the interface up,
# `nmcli general logging level trace` changes the daemon's logging, and
# `nmcli general reset` reloads its configuration. The first version of this
# module listed `radio` as a read subcommand, which classified the first of those
# as safe.
WRITE_VERBS = {
    "resolvectl": frozenset({"dns", "domain", "flush-caches", "revert"}),
    "systemctl": frozenset(
        {
            "daemon-reload",
            "disable",
            "enable",
            "halt",
            "isolate",
            "mask",
            "poweroff",
            "reboot",
            "restart",
            "set-property",
            "start",
            "stop",
            "suspend",
            "unmask",
        }
    ),
}
NMCLI_WRITE_VERBS = frozenset(
    {"add", "delete", "down", "modify", "reload", "remove", "set", "up"}
)
# (subcommand, any-of-these) pairs. A pair is a write whatever else the array
# contains, so `nmcli general reset` is caught by its subcommand and
# `nmcli radio wifi on` by its verb.
NMCLI_WRITE_PAIRS = (
    ("general", frozenset({"logging", "permissions", "reset"})),
    ("radio", frozenset({"all", "gsm", "off", "on", "wifi", "wimax"})),
    ("connectivity", frozenset({"check"})),
    ("networking", frozenset({"off", "on"})),
)


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
    rest = [str(token) for token in argv[1:]]
    if program in SHELL_WRAPPERS:
        return True
    if program == "nmcli":
        if any(token in NMCLI_WRITE_VERBS for token in rest):
            return True
        for subcommand, triggers in NMCLI_WRITE_PAIRS:
            if subcommand in rest and triggers & set(rest):
                return True
        return False
    verbs = WRITE_VERBS.get(program)
    if program in READ_ONLY_PROGRAMS:
        # `cat`, `readlink` and `ss` are not in `WRITE_VERBS`, and that is the
        # whole of their classification: every invocation of them reads.
        return any(token in verbs for token in rest) if verbs else False
    # **A program nobody thought of is refused, not assumed a read.** This
    # function's job is to tell a reader whether a command can change the machine,
    # and a command it cannot classify is a command whose effect is unknown -- so
    # the answer is "yes, treat it as a write" and the caller stops. Returning
    # False made a new program silently a read, which is the one direction that
    # weakens the claim a snapshot exists to support without anything saying so.
    return True


def digest_of(records: Iterable[str], error: str | None = None) -> str:
    """The digest of a field, so "the snapshots differ" is checkable by hand.

    Over the *stored* records rather than over the text they came from, so a
    reader can recompute it and get the same answer -- which is what stops the
    digest from being an opaque number that changes for reasons nobody can find.

    **The error is folded in as a string, and it has to be.** A field whose command
    failed has an empty `records` list, and so does a field that succeeded and read
    nothing -- so hashing the records alone made "the resolver is not a symlink"
    and "the resolver is missing" the same digest, and made a field that could not
    be collected equal to one that was genuinely empty. The second of those is the
    answer an unchanged host gives, so a field that failed would have been read as
    proof that nothing changed. A field's error is part of what it observed.
    """
    digest = hashlib.sha256()
    for record in records:
        digest.update(record.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
    digest.update(b"\0error=")
    digest.update((error or "").encode("utf-8", "surrogateescape"))
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
        if fields and fields[0] in project_units():
            records.append(" ".join(fields))
    return sorted(records)


def _field_commands() -> dict[str, tuple[str, ...]]:
    return {name: argv for name, argv in COMMAND_FIELDS}


def _field(name: str, records: list[str], error: str | None = None) -> dict:
    return {
        "digest": digest_of(records, error=error),
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


# The variables a snapshot's commands may inherit. An allowlist, for the same
# reason the Podman wrapper has one: a token in the operator's shell must not
# reach a command a harness runs, and then a report.
SNAPSHOT_ENV_NAMES = ("HOME", "LANG", "LC_ALL", "PATH", "TZ")


class SubprocessRunner:
    """A runner that executes an argument array -- no shell, a deadline, no env.

    The same discipline the Podman wrapper keeps, for the same reason: the six
    command arrays are built here and nowhere else, they are handed over as an
    array rather than a string, and there is no environment to inherit a token
    from. The timeout is not optional, because a `nmcli` that has wedged is a
    scenario that will never finish and says so on its own.

    **The environment is an allowlist and not an inheritance.** This used to pass
    `env=None`, which is `subprocess.run` for *use the caller's environment* -- so
    the docstring's claim and the code disagreed, in the direction that hands every
    variable the operator exported to six commands. `nmcli`, `resolvectl` and
    `systemctl` do not need a token, and a command's environment is exactly what
    this repository's Podman wrapper goes out of its way not to record. So the
    child gets `SNAPSHOT_ENV_NAMES` and `extra_env`, and nothing else.
    """

    def __init__(self, timeout: float = 30.0, extra_env: Mapping[str, str] | None = None):
        self.timeout = timeout
        self.extra_env = dict(extra_env or {})

    def child_environment(self) -> dict:
        """The variables a snapshot's commands run with.

        The allowlist from this process, plus whatever the caller added on top.
        The merge is here rather than at the call to `subprocess.run` so that
        "what does a snapshot's command inherit" has one answer to read.
        """
        inherited = {name: os.environ[name] for name in SNAPSHOT_ENV_NAMES if name in os.environ}
        return inherited | self.extra_env

    def __call__(self, argv: Sequence[str]) -> str:
        completed = subprocess.run(
            [str(token) for token in argv],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
            env=self.child_environment(),
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
    "PACKAGING_UNIT_DIRECTORY",
    "SNAPSHOT_ENV_NAMES",
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
    "project_units",
    "project_unit_records",
    "write_snapshot",
]
