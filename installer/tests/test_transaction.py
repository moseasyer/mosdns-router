"""Hold the install transaction to the order and the rollback that make it safe.

This is the only code in the project that changes a machine's DNS, and the whole
of its safety argument is one sentence: **the NetworkManager is touched last,
after the local resolver has answered a real query.** A transaction that pointed
a working machine at ``127.0.0.1`` and then found the router was not answering
has taken the machine's DNS away, and nothing else in this repository can put it
back. So the properties asserted here are the order, the rollback and the
record:

* **The order is the design.** The full argument array of every command, and
  every DNS probe, is asserted as one literal sequence. "A modify call happened"
  is not a test; a test that passes for a transaction which modifies
  NetworkManager *before* the router is up is worse than no test.
* **Every failure restores what it found.** A failure is injected after each
  mutation in turn, and each case asserts the exact restoring commands, the units
  that stay running because they were already running, the backup that survives as
  the record, and which of the two exit statuses came back.
* **Nothing is restored that was not recorded.** The backup is the only source of
  an original value, so it is written, read back, compared field by field, and
  checked for its mode before the first mutation -- and a backup that cannot be
  read back aborts rather than proceeding.
* **The capture's environment is scrubbed by argument.** ``CommandRunner.run``
  takes no ``env=``, so the four names are removed with ``env -u`` inside the
  argument array itself, and one case runs that prefix as a real child process
  with a deliberately polluted parent to prove the names really are absent.

Nothing here reads or writes the host. The root is a temporary directory, every
command goes through a fake runner that records the array it was given, and the
DNS probe is an injected callable -- with one exception, the probe's own packet
builder and socket client, which are exercised against a UDP socket on a
loopback *ephemeral* port. Ports 53, 15353 and 127.0.0.53 are never bound and
never queried; the real network path stays the one thing this container cannot
check, and it is reported as such rather than pretended at.
"""

import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import tokenize
import unittest
from pathlib import Path
from typing import NamedTuple

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "installer"))
sys.path.insert(0, str(REPO))

import mosdns_installer as installer  # noqa: E402
from installer.tests.test_units import toml_scalar  # noqa: E402

MODULE = REPO / "installer" / "mosdns_installer.py"
SOURCE = MODULE.read_text(encoding="utf-8")

# Token types that carry prose rather than code. Python 3.12 and later tokenize an
# f-string into FSTRING_START/MIDDLE/END, so the middle -- the literal text
# between the braces -- is prose inside code and has to be named too.
PROSE_TOKENS = tuple(
    kind
    for kind in (tokenize.COMMENT, tokenize.STRING, getattr(tokenize, "FSTRING_MIDDLE", None))
    if kind is not None
)


def code_only(source):
    """The module's code tokens, with every comment and string literal dropped.

    A source scan has to be able to tell code from the prose that argues *about*
    code, and this module's docstrings explain at length exactly which commands
    it refuses to build -- so a scan over the raw text fails hardest on the file
    that best obeys the rule.

    This is a smaller thing than the identical helper in ``test_preflight`` and
    it is deliberately not imported from there: the brief's own acceptance
    command is ``python3 -m unittest installer.tests.test_transaction``, which
    does not put ``installer/tests`` on ``sys.path``, so an import of a sibling
    test module would make the documented way to run this file fail. This
    version also does not preserve line layout, because nothing here parses the
    result -- it is searched with patterns, and dropping a multi-line string's
    newlines can merge two code lines but cannot hide either of them, which is
    the only failure direction a scan has to worry about.
    """
    kept = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in PROSE_TOKENS:
            continue
        kept.append(token.string)
    return " ".join(kept)


CODE = code_only(SOURCE)

# The constants the transaction is built from, restated here rather than read
# from the module. A test that asserted `installer.BACKUP_PATH` proved that the
# module agrees with itself.
PACKAGE_NAME = "mosdns-router"
PACKAGE_VERSION = "1.4.2"
BACKUP_PATH = "/var/lib/mosdns/installer/network-manager-backup.json"
MANAGED_BY = "/var/lib/mosdns/installer/managed-by"
MANAGED_BY_VALUE = "mosdns-router"
POLICY_CONFIG = "/etc/mosdns/policy.yaml"
DHCP_STATE_FILE = "/run/mosdns/dhcp-upstreams.json"
DHCP_LOCK_FILE = "/run/mosdns/dhcp-bridge.lock"
BACKUP_MODE = 0o600
BACKUP_SCHEMA_VERSION = 1
RESOLVER_UNIT = "dnscrypt-proxy.service"
ROUTER_UNIT = "mosdns-router.service"
RESOLVED_UNIT = "systemd-resolved.service"
DNS_PORT = 53
RESOLVER_PORT = 15353
LOCAL_DNS = "127.0.0.1"
RESOLVED_STUB = "127.0.0.53"

# The four names the capture must not inherit, and nothing else. Each one changes
# what the capture records: the action makes `--capture-current` a usage error,
# the two DHCP variables outrank the effective device DNS, and the connection
# UUID outranks the authoritative `nmcli -g GENERAL.CON-UUID` lookup.
SCRUBBED = (
    "NM_DISPATCHER_ACTION",
    "DHCP4_DOMAIN_NAME_SERVERS",
    "DHCP6_DOMAIN_NAME_SERVERS",
    "CONNECTION_UUID",
)

# The connection the fixture machine has, and its device.
UUID = "11111111-1111-1111-1111-111111111111"
CONNECTION_NAME = "Wired connection 1"
DEVICE = "ens33"
OTHER_UUID = "99999999-9999-9999-9999-999999999999"


class Injection(NamedTuple):
    """One row of the failure-injection table: a command, and the machine it is on.

    A bare command is not enough, because two of the transaction's commands are
    reachable on only one of its two machines. `systemctl try-restart` is issued
    when a unit was ALREADY running, so a first install never issues it -- a row
    naming it with nothing else would assert nothing, because the command it names
    would never appear in the run it injects into. The flag is the machine, and the
    machine is a fact about the program rather than a convenience for the test.
    """

    failing: tuple
    already_running: bool = False


# The three mutations, and only these three. A test below reads them out of the
# recorded command list, so a fourth property fails without anybody editing this
# table -- and a second test reads every ipv4/ipv6 property the module names,
# which is the one that covers the paths a test does not reach.
MUTATIONS = (
    ("ipv4.ignore-auto-dns", "yes"),
    ("ipv6.ignore-auto-dns", "yes"),
    ("ipv4.dns", LOCAL_DNS),
)
# The four properties the backup records, which is the three above plus the IPv6
# address list this install never changes and an operator restoring by hand does.
RECORDED_PROPERTIES = (
    "ipv4.ignore-auto-dns",
    "ipv6.ignore-auto-dns",
    "ipv4.dns",
    "ipv6.dns",
)

# The preflight's own commands, in the order its checks run. It is the first
# step of the sequence, and the sequence test below spells it out rather than
# summarising it, so a reordering inside preflight is visible here too.
STATE_DIRECTORIES = (
    "/var/lib/mosdns",
    "/var/lib/mosdns/runtime",
    "/var/lib/mosdns/lists",
    "/run/mosdns",
)
# The shared control lock, its mode, and the owner and group preflight requires
# it to have. The transaction now TAKES this lock -- it is the exclusion that
# stops the resolver watchdog firing an emergency rollback underneath a running
# install -- so a test that runs a transaction leaves a real lock file in the
# fake root and the next run's preflight stats it.
CONTROL_LOCK = "/var/lib/mosdns/runtime/control.lock"
LOCK_MODE_OCTAL = "640"
STATE_OWNER = "root"
STATE_GROUP = "mosdns"
# The units whose states the preflight reads, and the fixture's own list rather
# than the module's: this suite asserts the exact sequence of commands a
# transaction issues, and a sequence derived from the constant under test would
# be a sequence that cannot fail. The watchdog's timer is here for the same
# reason the other three are -- preflight reads whether a unit this package
# installed is running, because one that is already running changes what the
# transaction must undo -- and its ABSENCE from this list is what the case below
# would have caught.
PROJECT_UNITS = (
    ROUTER_UNIT,
    RESOLVER_UNIT,
    "mosdns-cdn-optimizer.timer",
    "mosdns-cdn-health.timer",
    "mosdns-list-check.timer",
    "mosdns-watchdog.timer",
)
# The command that publishes the Cloudflare prefix list, which the response
# rewriter refuses to CONSTRUCT without (plugin/executable/cdn_rewrite calls
# newPrefixList first and returns the error). It is `mosdns-cdnctl update-lists
# --refresh-ranges` on the installed binary, with every path at its default, and
# it measures nothing and spends no bandwidth budget -- its own help text calls it
# "the mode an installation runs before the router starts".
CDNCTL = "/usr/lib/mosdns-router/mosdns-cdnctl"
PUBLISH_PREFIXES = (CDNCTL, "update-lists", "--refresh-ranges")

# The names a scripted probe can report, which is what a real resolver's answer
# looks like to the prober. "healthy" is what a working chain returns for a
# reserved name; the other three are the three ways a chain that cannot resolve
# answers instead -- an immediate synthesised denial, an explicit failure, and
# silence. Measured against real systemd-resolved; see the report.
SERVFAIL = "servfail"
REFUSED = "refused"
SILENT = "silent"
HEALTHY = "healthy"

# The prober's answer, as the two questions the transaction asks of it. The
# answering is spelled out here rather than read from the module -- a fixture that
# asked the module what its own answer is would agree with it whatever it did --
# but the type is the module's, because the prober's return type IS the interface
# a scripted probe has to stand in for.
def answer(answered, resolves):
    return installer.Answer(answered=answered, resolves=resolves)


ANSWER_SHAPES = {
    HEALTHY: answer(True, True),
    SERVFAIL: answer(True, False),
    REFUSED: answer(True, False),
    SILENT: answer(False, False),
}
# RFC 6761 reserves these for testing and documentation, so a resolver is
# expected to answer a name under one of them without any public delegation. The
# set is restated here because the probe name's being under it is a property
# this suite holds, not one it reads.
SPECIAL_USE_TLDS = ("test", "example", "invalid", "localhost", "local")
# RFC 6761's "caching servers" category, which is the only one that decides whether a
# resolver forwards a name or answers it without asking anybody. The partition is
# from the RFC, restated here so the test asserts the RFC rather than an
# observation.
#
#   §6.2 `.test`     category 4: SHOULD generate immediate negative responses.
#   §6.4 `.invalid`  category 4: SHOULD generate immediate NXDOMAIN responses.
#   §6.3 `.localhost` category 4: SHOULD generate an immediate positive response.
#   §6.5 `.example`  category 4: SHOULD NOT recognise these names as special and
#                              SHOULD resolve them normally.
LOCALLY_ANSWERED_TLDS = ("test", "invalid", "localhost", "local")
FORWARDED_TLD = "example"
# The name the transaction probes with, restated from the RFC and the measurement
# that chose it: `.example` is the one special-use TLD whose category 4 tells a
# caching server to resolve it NORMALLY, so a resolver that follows the RFC cannot
# answer it locally, and a dead chain is silent rather than confidently wrong.
INSTALL_PROBE_NAME = "install-probe.example"
FORCE_ECH = "/etc/mosdns/force-ech-domains.txt"

NMCLI_CONNECTIONS = ("nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active")
NMCLI_DEVICE_UUID = ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", DEVICE)
SS_LISTENERS = ("ss", "-H", "-lntup")
MAIN_PID = ("systemctl", "show", "-p", "MainPID", "--value")
STAT_FIELDS = ("stat", "-c", "%a %U %G %f")
GETFACL = "getfacl"
DNS_UUID_PREFIX = ("nmcli", "-g")
MODIFY = ("nmcli", "connection", "modify")
CONNECTION_UP = ("nmcli", "connection", "up")
# The UPGRADE's verb, and it is a different command from `start` rather than a
# different spelling of it: on an already-active unit `start` is a no-op, which is
# what an upgrade must not rely on. So the two are separate keys in `UNDO_OF` and
# separate rows in the failure-injection table, and a table row that named `start`
# for a machine that is already running would name a command the transaction never
# issues there.
TRY_RESTART = ("systemctl", "try-restart")
START = ("systemctl", "start")
# The verb the two `start` rows' undo is, and the one `FakeUnitModelTests` holds the
# fake to in both directions. Named here because `UNDO_OF` writes it out twice
# otherwise and a test that spelled it itself would be a test that could pass on a
# typo in the table it is meant to be reading.
STOP = ("systemctl", "stop")

# The three states of a unit that decide what `systemctl try-restart` does with it,
# named here because the finding is ABOUT the difference between them. `try-restart`
# acts on `active` and on nothing else: on `failed`, on `activating` and on
# `inactive` it does nothing and exits zero. `failed` is the state a `try-restart`
# leaves behind when the start half fails, so it is the one this suite's cases are
# about.
UNIT_RUNNING = "active"
UNIT_STOPPED = "inactive"
UNIT_FAILED = "failed"

# What the four recorded properties hold on a machine THIS package has already
# taken over. It is the state a second install reads, and the reason the value of
# the `original` block is visible at all: after an upgrade the connection holds
# these, so anything that records "what the machine had" from a second install
# records this package's own values instead of the machine's.
ALREADY_OURS = {
    "ipv4.ignore-auto-dns": "yes",
    "ipv6.ignore-auto-dns": "yes",
    "ipv4.dns": LOCAL_DNS,
    "ipv6.dns": "",
}

# The verbs that change something, as distinct from the verbs that ask. The
# assertion "nothing was mutated" is about these and not about the program that
# carries them, because the preflight asks systemd read-only questions before the
# transaction starts.
CHANGE_VERBS = frozenset(
    {
        "add",
        "clone",
        "daemon-reload",
        "delete",
        "disable",
        "down",
        "enable",
        "mask",
        "modify",
        "reload",
        "reload-or-restart",
        "restart",
        "start",
        "stop",
        "unmask",
        "up",
    }
)
# `dpkg --print-architecture` is the preflight's own read; the version of the
# package that is doing the installing is a different question and a different
# binary, and the backup records the answer because an operator reading a backup
# has to know which release wrote it.
PACKAGE_VERSION_COMMAND = ("dpkg-query", "--show", "--showformat=${Version}", PACKAGE_NAME)

# The DHCP state the capture publishes, in the publisher's own field order. The
# upstream addresses are documentation-reserved, so nothing in this suite can
# accidentally query a real resolver.
DHCP_UPSTREAM = "192.0.2.53"
DHCP_SECOND_UPSTREAM = "192.0.2.54"
OBSERVED_AT = "2026-09-27T09:15:00Z"
CREATED_AT = "2026-09-27T09:20:00Z"
POLICY_BODY = "schema_version: 1\ncdn:\n  provider: cloudflare\nech:\n  enabled: true\n"


def capture_command(interface=DEVICE):
    """The capture, as the transaction has to build it.

    The four ``-u`` pairs are the scrub, and they are in the array rather than in
    a parameter: :meth:`CommandRunner.run` has no ``env=``, so the environment
    the capture would inherit is changed by the command itself.

    ``PYTHONPATH`` is here for the reason the live run established, and it is a
    **measured** addition rather than a tidy one. ``DHCP_BRIDGE`` runs
    ``python3 -m mosdns_dhcp_bridge.cli``, and the package installs that module at
    ``/usr/lib/mosdns-router/mosdns_dhcp_bridge/`` -- which is not on the system
    path, and never was: the dispatcher hook sets ``PYTHONPATH`` for exactly this
    reason and the installer's own capture did not. On a real 24.04 target
    (measured, in Task 8's container run) the transaction refused with:

        install: the DHCP capture failed with status 1; nothing has been changed;
        it said: /usr/bin/python3: Error while finding module specification for
        'mosdns_dhcp_bridge.cli' (ModuleNotFoundError: No module named
        'mosdns_dhcp_bridge')

    which is a refused install on every machine, and a silent one in the sense
    that matters: the transaction rolls itself back cleanly and dpkg reports a
    normal failure. The bridge's own path is the one the package's dispatcher
    already uses, so the two callers of the same module now agree on where it
    lives.
    """
    return (
        ("env",)
        + tuple(word for name in SCRUBBED for word in ("-u", name))
        + (
            "PYTHONPATH=/usr/lib/mosdns-router",
            "python3",
            "-m",
            "mosdns_dhcp_bridge.cli",
            "--capture-current",
            interface,
            "--state-file",
            DHCP_STATE_FILE,
            "--lock-file",
            DHCP_LOCK_FILE,
        )
    )


def responder(answer):
    """A one-packet UDP server on 127.0.0.1:0, answering ``answer``.

    Port 0, so the suite can never collide with a resolver and can never be
    mistaken for one; the address is loopback, so nothing leaves the machine.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(0.5)

    def serve():
        try:
            query, peer = server.recvfrom(4096)
            if answer is not None:
                server.sendto(answer(query), peer)
        except (socket.timeout, OSError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server, server.getsockname()[1], thread


class FakeRunner:
    """A CommandRunner that records argument arrays and answers prepared ones.

    Only an array the test prepared produces output, so a command the transaction
    must not run answers empty and is visible in ``events``. A string is refused
    outright rather than recorded, which is the same boundary ``test_preflight``
    holds: in production a string reaching the runner is a string a shell would
    have interpreted.

    ``fail`` holds full argument arrays that raise, matched exactly. Exactness is
    the point: a restore of ``ipv4.dns`` and the install's own
    ``ipv4.dns 127.0.0.1`` share their first five arguments and differ only in the
    value, so a prefix matcher could not fail one without failing the other, and
    the case that needs a *failing restore* needs exactly that distinction.

    ``child_environment`` is read at call time, which is what lets a test see the
    environment the scrubbed command would actually hand its child.

    ``fail_after`` is how a command is failed only on its SECOND run. The
    transaction's reactivation and the rollback's reactivation are the same
    argument array, so a case that needs the first to succeed and the second to
    fail cannot say so by naming a command; it says how many times the command may
    succeed first, which is a fact about the machine rather than about the array.

    ``fail_first`` is the same problem the other way round, and it is the shape
    the reactivation's own undo needs: that undo is registered BEFORE the attempt,
    so the rollback runs the same command again, and a case about "the first
    ``connection up`` failed" wants the second one to succeed. ``fail`` would fail
    both, which is a different machine and has its own test.

    ``unit_state`` is the model of a unit's state, and it exists because
    ``systemctl --help`` says of ``try-restart``: "try-restart UNIT... Restart one
    or more units **if active**". On a unit that is not running it does NOTHING and
    exits ZERO. Every state a failed start leaves -- ``failed``, ``activating``,
    ``inactive`` -- is outside the set it acts on, and a silent no-op that returns
    success is the worst shape a rollback's undo can have: the command count goes
    up, the record says the undo ran, and the unit is still down.

    A runner that recorded argument arrays and returned success for everything
    modelled that as a helpful tool, so a rollback whose undo was another
    ``try-restart`` reported a unit restored on a machine where nothing had been
    started at all. Every transition in ``_transition`` below is that manual's
    sentence, and there are four of them -- ``start``, ``stop``, ``try-restart`` and
    ``restart`` -- so the list here is a list of what is tested rather than a list of
    what is intended: ``FakeUnitModelTests`` holds ``start`` and ``stop`` succeeding
    AND failing, and ``try-restart`` and ``restart`` succeeding. ``unit_state`` is
    what a test reads to ask what the machine ended up as rather than how many
    commands it was sent.

    Only a unit the test NAMED is modelled, and ``is-active`` on a modelled unit
    answers from the model rather than from the canned output, so a test that
    arranges a unit's state arranges what the transaction READS. A unit nobody
    named keeps this runner's canned answers, so a test that does not care about
    unit state is unchanged by this model existing.

    THE RETURNCODE of ``is-active`` is deliberately NOT derived from the model, and
    the incoherence is recorded rather than quietly fixed. The canned table gives
    every project unit 3 -- "not active" -- including the two an upgrade's machine
    has running, and ``check_foreign_services`` reads the STATUS to decide whether
    the read succeeded, so those two are read as unreadable and the foreign-service
    refusal is skipped. That is how the upgrade fixture reaches the transaction at
    all: it models units running with no ownership marker, which on a real machine
    is an installation this one did not make and would be REFUSED. Deriving the
    status from the model turns that fiction into a real refusal and is a change to
    what the upgrade machine is, not to the undo this model exists for.
    """

    def __init__(self, outputs=None, returncodes=None, stderr="", fail=(), fail_after=None, fail_first=(), child_environment=None, record=None, unit_state=None):
        self.outputs = {tuple(key): value for key, value in (outputs or {}).items()}
        self.returncodes = {tuple(key): value for key, value in (returncodes or {}).items()}
        self.stderr = stderr
        self.fail = {tuple(command) for command in fail}
        self.fail_after = {tuple(key): value for key, value in (fail_after or {}).items()}
        self.fail_first = {tuple(command) for command in fail_first}
        self.succeeded = {}
        self.child_environment = child_environment
        self.record = record
        # SHARED, not copied: the fixture seeds it and the test reads the state the
        # run ended in, and a copy would leave the test reading the machine as it
        # was arranged rather than as it ended up -- which is the whole distinction
        # the model exists for.
        self.unit_state = {} if unit_state is None else unit_state
        self.calls = []

    def running(self, unit):
        """Whether ``unit`` is modelled AND modelled as running.

        ``None`` for a unit this runner does not model, so a caller can tell "the
        model says stopped" from "there is no model here" -- the same distinction
        the module's own ``_unit_states`` draws with its ``unreadable`` list, and
        the one a test that forgets to arrange a state has to be able to see.
        """
        state = self.unit_state.get(unit)
        if state is None:
            return None
        return state == UNIT_RUNNING

    def _transition(self, command, ok):
        """One `systemctl` unit verb's effect on the modelled state, if any.

        Three verbs, and the asymmetry between them IS the finding. `start` and
        `stop` act on a unit whatever state it is in -- a `start` on a stopped unit
        brings it up, and a `start` on a running one is a no-op that succeeds, so
        `start` is both a correct undo and a loud one: it fails if the unit cannot
        be brought up. `try-restart` acts only on an active unit, silently and
        successfully, so it is the right word for the FORWARD action of a unit that
        is known to be running and the wrong word for its UNDO.
        """
        if len(command) < 3 or command[0] != "systemctl":
            return
        action, unit = command[1], command[2]
        if unit not in self.unit_state:
            return
        if action == "try-restart" and self.unit_state[unit] != UNIT_RUNNING:
            return
        if action in ("start", "try-restart", "restart"):
            self.unit_state[unit] = UNIT_RUNNING if ok else UNIT_FAILED
        elif action == "stop":
            self.unit_state[unit] = UNIT_STOPPED if ok else UNIT_RUNNING

    def run(self, args, check=True):
        if isinstance(args, (str, bytes)):
            raise TypeError(
                "a command must be an argument array, never a string the shell would "
                f"have to interpret: {args!r}"
            )
        command = tuple(args)
        self.calls.append(command)
        if self.record is not None:
            self.record(command)
        if self.child_environment is not None:
            self.child_environment(command)
        if command in self.fail:
            self._transition(command, ok=False)
            raise subprocess.CalledProcessError(
                1, list(command), "", self.stderr or "injected failure"
            )
        if command in self.fail_first and not self.succeeded.get(command, 0):
            self.succeeded[command] = self.succeeded.get(command, 0) + 1
            self._transition(command, ok=False)
            raise subprocess.CalledProcessError(
                1, list(command), "", self.stderr or "injected failure"
            )
        allowed = self.fail_after.get(command)
        if allowed is not None and self.succeeded.get(command, 0) >= allowed:
            self._transition(command, ok=False)
            raise subprocess.CalledProcessError(
                1, list(command), "", self.stderr or "injected failure"
            )
        self.succeeded[command] = self.succeeded.get(command, 0) + 1
        self._transition(command, ok=True)
        code = self.returncodes.get(command, 0)
        if code != 0 and check:
            # The prepared answer goes on BOTH sides, because a tool that reports
            # a refusal on standard output is a real thing and the module's
            # message quotes standard output when standard error is empty.
            raise subprocess.CalledProcessError(
                code, list(command), self.answer(command), self.stderr
            )
        return subprocess.CompletedProcess(
            args=list(command), returncode=code, stdout=self.answer(command), stderr=self.stderr
        )

    def answer(self, command):
        if command[:2] == ("systemctl", "is-active") and command[2:] and command[2] in self.unit_state:
            return self.unit_state[command[2]] + "\n"
        if command in self.outputs:
            return self.outputs[command]
        if command[:2] == (GETFACL, "-c"):
            return acl_of(command[-1])
        return ""


def acl_of(path):
    """The real ACL of a path, from the real ``getfacl``.

    The preflight's directory check reads an extended ACL, and it is checked
    against what the tool actually prints. A canned string here would let a
    transaction pass a preflight the real machine would have refused.
    """
    return subprocess.run(
        [GETFACL, "-c", "-p", str(path)], check=False, capture_output=True, text=True
    ).stdout


def setfacl(path, entry, default=True):
    """Give a fake-root directory a real ACL, with the real tool."""
    command = ["setfacl"]
    if default:
        command.append("-d")
    command += ["-m", entry, str(path)]
    subprocess.run(command, check=True)


class TransactionFixture(unittest.TestCase):
    """A fake root, a runner that records, and a probe that answers on cue.

    Both the runner and the probe append to one ordered event list. That is what
    makes the order assertable as a single sequence: the health check is a
    socket, not a command, so a list of commands alone would place the barrier
    the whole design rests on somewhere invisible.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.events = []
        self.answers = {}
        self.failing = set()
        self.returncodes = {}
        # The machine's unit states, as a MODEL rather than as canned answers. Seeded
        # by `already_running` and mutated by the runner as the transaction issues
        # `start`/`try-restart`/`stop`, so a test can ask what the machine ended up
        # as. See `FakeRunner.unit_state` for why `try-restart` needs one.
        self.unit_state = {}
        self.captured_environment = []
        self.write("/etc/os-release", 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n')
        self.stub_resolv_conf()
        self.build_state_directories()
        self.write(POLICY_CONFIG, POLICY_BODY)
        self.dhcp_state()
        self.runner = None

    # -- the fake root ----------------------------------------------------

    def rooted(self, absolute):
        return self.root / absolute.lstrip("/")

    def write(self, relative, contents, mode=0o644):
        path = self.rooted(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        path.write_text(contents, encoding="utf-8")
        path.chmod(mode)
        return path

    def stub_resolv_conf(self):
        link = self.rooted("/etc/resolv.conf")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        return link

    def build_state_directories(self, mode="2770"):
        for relative in STATE_DIRECTORIES:
            path = self.rooted(relative)
            path.mkdir(parents=True, exist_ok=True)
            setfacl(path, "g::rwx")
            path.chmod(int(mode, 8))

    def force_ech(self, *domains):
        """Write the operator's force-ECH list, comment lines and all."""
        body = "# domains this router forces ECH for\n"
        for domain in domains:
            body += f"{domain}\n"
        return self.write(FORCE_ECH, body, mode=0o644)

    def policy(self, enabled="true", failure="strict"):
        return self.write(
            POLICY_CONFIG,
            "schema_version: 1\n"
            "cdn:\n"
            "  provider: cloudflare\n"
            "ech:\n"
            f"  enabled: {enabled}\n"
            f"  failure_policy: {failure}\n"
            "  stale_grace: 900\n",
        )

    def dhcp_state(self, upstreams=(DHCP_UPSTREAM,), source="dhcp4", uuid=UUID):
        """The state the capture has already published under the fake root.

        The transaction reads this file to put the lease in the backup, so the
        fixture has to hold a real one: the bytes are the publisher's own field
        order, because a document the publisher would refuse is not a state.
        """
        document = {
            "schema_version": 1,
            "generation": 1,
            "interface": DEVICE,
            "connection_uuid": uuid,
            "upstreams": list(upstreams),
            "observed_at": OBSERVED_AT,
            "source": source,
            "last_good": bool(upstreams),
        }
        return self.write(DHCP_STATE_FILE, json.dumps(document, indent=2) + "\n", mode=0o640)

    # -- the runner and the probe ----------------------------------------

    # The eight mutating steps, in the order the transaction applies them, and the
    # command that undoes each. Written out here so a test can compute the tail a
    # failure must be followed by, rather than only checking that "a stop
    # happened" -- which a rollback that also re-ran a mutation would satisfy.
    # The mutating steps in the order they are applied, and the command that undoes
    # each. The three property changes come first, then the reactivation, then the
    # units: that is the order a rollback has to take them back in, and it is NOT
    # the reverse of this list. The reactivation has to happen after the profile
    # carries its recorded values again and before the units are stopped, so this
    # is a table with two orders in it and both of them are the contract.
    #
    # The two `try-restart` rows are the UPGRADE's alternatives to the two `start`
    # rows and never appear in the same run as them; see UNIT_STEPS. They are here
    # because `expected_rollback` reads this table for the commands a run actually
    # issued, and a run that issued a restart would otherwise have no undo to name.
    STEPS = (
        ("systemctl", "enable", RESOLVER_UNIT),
        ("systemctl", "enable", ROUTER_UNIT),
        PUBLISH_PREFIXES,
        ("systemctl", "start", RESOLVER_UNIT),
        TRY_RESTART + (RESOLVER_UNIT,),
        ("systemctl", "start", ROUTER_UNIT),
        TRY_RESTART + (ROUTER_UNIT,),
        MODIFY + (UUID, "ipv4.ignore-auto-dns", "yes"),
        MODIFY + (UUID, "ipv6.ignore-auto-dns", "yes"),
        MODIFY + (UUID, "ipv4.dns", LOCAL_DNS),
        CONNECTION_UP + (UUID,),
    )
    UNDO_OF = {
        ("systemctl", "enable", RESOLVER_UNIT): ("systemctl", "disable", RESOLVER_UNIT),
        ("systemctl", "enable", ROUTER_UNIT): ("systemctl", "disable", ROUTER_UNIT),
        ("systemctl", "start", RESOLVER_UNIT): ("systemctl", "stop", RESOLVER_UNIT),
        ("systemctl", "start", ROUTER_UNIT): ("systemctl", "stop", ROUTER_UNIT),
        # The undo of a restart is a `start`, not another `try-restart`, and the
        # reason is `FakeRunner.unit_state`: `try-restart` acts on an active unit
        # and does nothing, successfully, to a stopped one, so it cannot be the
        # undo of a forward action that STOPS the unit it issues. `restart` is the
        # other correct word and `start` is chosen over it because `restart` stops a
        # unit that is already up, so an undo built from it can take away the
        # resolver it is repairing -- and that is the half of the property that is
        # still true here, read against the two `start` rows ABOVE rather than
        # against this table as a whole: a `stop` in one of THOSE would be an undo
        # that takes away a resolver the machine had before this run began, and the
        # table does contain two such undos.
        TRY_RESTART + (RESOLVER_UNIT,): START + (RESOLVER_UNIT,),
        TRY_RESTART + (ROUTER_UNIT,): START + (ROUTER_UNIT,),
        MODIFY + (UUID, "ipv4.ignore-auto-dns", "yes"): MODIFY + (UUID, "ipv4.ignore-auto-dns", "no"),
        MODIFY + (UUID, "ipv6.ignore-auto-dns", "yes"): MODIFY + (UUID, "ipv6.ignore-auto-dns", "no"),
        MODIFY + (UUID, "ipv4.dns", LOCAL_DNS): MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM),
        CONNECTION_UP + (UUID,): CONNECTION_UP + (UUID,),
    }
    # Which group each step's undo belongs to, which is what decides when it runs.
    PROFILE_STEPS = (
        MODIFY + (UUID, "ipv4.ignore-auto-dns", "yes"),
        MODIFY + (UUID, "ipv6.ignore-auto-dns", "yes"),
        MODIFY + (UUID, "ipv4.dns", LOCAL_DNS),
    )
    REACTIVATING_STEP = CONNECTION_UP + (UUID,)
    # The steps whose undo is registered BEFORE the attempt rather than after it,
    # and the only places `expected_rollback` therefore has to treat a FAILING
    # command as one whose undo is already on the stack. Every other step
    # registers its undo because it succeeded.
    #
    # Two kinds, and the reason is the same for both: the attempt can leave the
    # machine in the state the undo is about even when the attempt itself fails.
    # `nmcli connection up` takes a connection DOWN on its way up, and
    # `systemctl try-restart` STOPS a unit on its way to restarting it -- so a
    # failed `try-restart` on a unit that was running is a unit that is DOWN, and
    # on an upgrade the connection is already 127.0.0.1 at that point in the
    # order, so the machine has no resolver at all.
    UNDO_REGISTERED_FIRST = (
        CONNECTION_UP + (UUID,),
        TRY_RESTART + (RESOLVER_UNIT,),
        TRY_RESTART + (ROUTER_UNIT,),
    )
    # In APPLICATION order, like STEPS, because expected_rollback reverses each
    # group: newest first within a group. So the unit group's rollback is
    # stop-router, stop-resolver, disable-router, disable-resolver -- the stops
    # before the disables, and the two units in the reverse of how they were
    # started.
    #
    # `start` and `try-restart` are both listed for each unit, and only ever ONE of
    # the pair appears in a run: they are alternatives chosen by the unit's prior
    # state, not two steps. The order is still the application order for either
    # machine, because each pair's two entries are adjacent and only one is
    # present, so filtering by what actually ran leaves the right sequence.
    UNIT_STEPS = (
        ("systemctl", "enable", RESOLVER_UNIT),
        ("systemctl", "enable", ROUTER_UNIT),
        ("systemctl", "start", RESOLVER_UNIT),
        TRY_RESTART + (RESOLVER_UNIT,),
        ("systemctl", "start", ROUTER_UNIT),
        TRY_RESTART + (ROUTER_UNIT,),
    )
    # The steps an UPGRADE's machine issues but whose undo the transaction does
    # NOT register, because the state they would undo is the state it found. The
    # command still runs -- `systemctl enable` on an enabled unit is harmless and
    # cheap -- so a rollback tail computed without this would name a `disable` the
    # rollback must not issue.
    ALREADY_SATISFIED = (
        ("systemctl", "enable", RESOLVER_UNIT),
        ("systemctl", "enable", ROUTER_UNIT),
    )

    @property
    def commands(self):
        """Every command array the transaction built, in order."""
        return [event[1] for event in self.events if event[0] == "run"]

    def changing(self, command):
        """Whether one command changes the machine's configuration, as against asking.

        "No `systemctl` ran" is the wrong shape for this assertion: the preflight
        asks `systemctl` four read-only questions before anything else happens, so a
        check written that way passes a transaction that started a unit and fails a
        transaction that read one. What has to be absent is the set of commands that
        change something, and that is a verb, not a program.

        The capture is not in that set, and its own tests hold it separately: it
        publishes a lease into a state file under `/run`, which is this project's
        data rather than the machine's configuration, and every case here also
        asserts that no backup and no marker was written.
        """
        if command[:1] == ("systemctl",) and len(command) > 1:
            return command[1] in CHANGE_VERBS
        if command[:2] == ("nmcli", "connection") and len(command) > 2:
            return command[2] in CHANGE_VERBS | {"modify", "up", "down", "delete", "add", "clone"}
        return False

    def assertNothingChanged(self, why):
        """No command that changes anything ran, and name the one that did."""
        changed = [command for command in self.commands if self.changing(command)]
        self.assertEqual(changed, [], f"{why}: {changed}")

    def undo_of(self, command):
        """The command that undoes one of the transaction's own steps."""
        return self.UNDO_OF[command]

    def expected_rollback(self, failing, already_running=False):
        """The commands a failure at ``failing`` must be followed by, in order.

        The three groups, each undone newest first, in the order the design
        requires: the profile, then the reactivation, then the units. Asserting
        the whole tail rather than "an undo for each completed step ran" is what
        catches a rollback that repeats a mutation it never reached, and writing
        the reactivation into its own group is what catches a rollback that
        reactivates the device while the profile is still wrong.

        ``already_running`` is the machine, and it is a parameter rather than
        something read off `self` because the expected tail genuinely depends on
        the prior state and guessing it would be guessing the code's own rule. On
        a unit that was ALREADY enabled, `systemctl enable` is still issued and
        still registers NO `disable` undo, so naming the disable for it would be
        naming a command the rollback must not run. On a unit that was already
        running, the undo of the start is never reached at all and the row's
        command is the restart instead.
        """
        reached = self.commands.index(failing)
        done = [
            command
            for command in self.STEPS
            if command in self.commands
            and (
                self.commands.index(command) < reached
                # A step whose undo went on the stack BEFORE the attempt is undone
                # even when the attempt failed, because the machine may already be
                # in the state the undo is about. `_reconnect` and the already-
                # running `_start` are those steps, and this is the one place the
                # rule differs.
                or (command == failing and command in self.UNDO_REGISTERED_FIRST)
            )
        ]
        if already_running:
            done = [command for command in done if command not in self.ALREADY_SATISFIED]
        tail = []
        for group in (self.PROFILE_STEPS, (self.REACTIVATING_STEP,), self.UNIT_STEPS):
            completed = [command for command in group if command in done]
            tail += [self.undo_of(command) for command in reversed(completed)]
        return tail

    def good_runner(
        self,
        outputs=None,
        returncodes=None,
        fail=(),
        fail_after=None,
        fail_first=(),
        child_environment=None,
        already_installed=False,
        stderr="",
    ):
        """A runner answering exactly what an installable machine answers.

        ``already_installed`` answers the four properties with the values a machine
        this package has already taken over holds -- `yes`/`yes`/`127.0.0.1` and an
        empty IPv6 list -- which is what the SECOND install of an upgrade reads. A
        runner that kept answering the machine's original values would make every
        re-install look like a first install, and the bug this fixture exists to
        catch is invisible from a first install.
        """
        answers = {
            ("dpkg", "--print-architecture"): "amd64\n",
            ("systemctl", "--version"): "systemd 255 (255.1-1ubuntu1)\n",
            ("systemctl", "is-active", "NetworkManager.service"): "active\n",
            ("systemctl", "is-active", RESOLVED_UNIT): "active\n",
            NMCLI_CONNECTIONS: f"{CONNECTION_NAME}:{UUID}:802-3-ethernet:{DEVICE}\n",
            NMCLI_DEVICE_UUID: f"{UUID}\n",
            SS_LISTENERS: "",
            MAIN_PID + (RESOLVED_UNIT,): "39\n",
            ("firefox", "--version"): "Mozilla Firefox 129.0\n",
            PACKAGE_VERSION_COMMAND: f"{PACKAGE_VERSION}\n",
            ("resolvectl", "dns", DEVICE): f"Link 2 ({DEVICE}): {LOCAL_DNS}\n",
        }
        for unit in PROJECT_UNITS:
            answers[("systemctl", "is-active", unit)] = "inactive\n"
        # The four properties the backup records. The manual address list is NOT
        # empty by default: a machine with one is the case where a restore has a
        # real value to put back, and a case whose restore is "put back nothing"
        # would pass a transaction that quietly dropped the list on the floor.
        for prop, value in (
            ("ipv4.ignore-auto-dns", "no"),
            ("ipv6.ignore-auto-dns", "no"),
            ("ipv4.dns", DHCP_UPSTREAM),
            ("ipv6.dns", ""),
        ):
            answers[DNS_UUID_PREFIX + (prop, "connection", "show", UUID)] = value + "\n"
        if already_installed:
            for prop, value in ALREADY_OURS.items():
                answers[DNS_UUID_PREFIX + (prop, "connection", "show", UUID)] = value + "\n"
        for unit in (RESOLVER_UNIT, ROUTER_UNIT):
            answers[("systemctl", "is-active", unit)] = "inactive\n"
            answers[("systemctl", "is-enabled", unit)] = "disabled\n"
            # `systemctl is-active` answers 3 for a stopped unit and
            # `is-enabled` answers 1 for a disabled one, both with a useful
            # answer on standard output, so the transaction has to read the
            # stream rather than the status.
            answers[("systemctl", "is-active", unit)] = "inactive\n"
            self.returncodes[("systemctl", "is-active", unit)] = 3
            self.returncodes[("systemctl", "is-enabled", unit)] = 1
        for unit in PROJECT_UNITS:
            self.returncodes[("systemctl", "is-active", unit)] = 3
        for relative in STATE_DIRECTORIES:
            answers[STAT_FIELDS + (str(self.rooted(relative)),)] = f"2770 root mosdns {stat.S_IFDIR | 0o2770:x}"
        # The control lock, stat-able. The transaction now TAKES this lock (it is
        # the exclusion that stops the resolver watchdog acting underneath an
        # install), so a test that runs the transaction twice leaves a real lock
        # file in the fake root, and the second run's preflight stats it. Without
        # an answer here the fake runner reports "could not be stat'd" and
        # preflight refuses a machine it should accept -- which is a fixture that
        # does not know about a file the program now creates, not a product
        # defect. `LOCK_MODE` and not the directory's 2770: the lock is a regular
        # file, and preflight checks its mode, owner and group.
        answers[STAT_FIELDS + (str(self.rooted(CONTROL_LOCK)),)] = (
            f"{LOCK_MODE_OCTAL} {STATE_OWNER} {STATE_GROUP} "
            f"{stat.S_IFREG | int(LOCK_MODE_OCTAL, 8):x}"
        )
        answers.update(self.answers)
        answers.update(outputs or {})
        codes = dict(self.returncodes)
        codes.update(returncodes or {})
        runner = FakeRunner(
            outputs=answers,
            returncodes=codes,
            stderr=stderr,
            fail=fail or self.failing,
            fail_after=fail_after,
            fail_first=fail_first,
            child_environment=child_environment or self.record_child,
            record=lambda command: self.events.append(("run", command)),
            unit_state=self.unit_state,
        )
        self.runner = runner
        return runner

    def already_running(self, *units):
        """The machine an UPGRADE runs on: these units are active and enabled.

        One definition for every case that needs it, because the two halves matter
        together. `active` is what makes the transaction issue `try-restart`
        rather than `start`, and `enabled` is what makes it register no `disable`
        undo -- a unit that was enabled before this run began must be enabled
        after a rollback too. A case that set only the first would compute a
        rollback tail with a `disable` in it and prove nothing about the restart.

        It also seeds the runner's UNIT MODEL for the same units, and that is not a
        convenience: `try-restart` acts on an active unit and does nothing to a
        stopped one, so a case that arranges "this unit was running" only in a
        canned string has not arranged the state the verb looks at. The model's
        transitions then make the unit's state at the END of the run a thing a test
        can read, which is the only way to tell a rollback that put a resolver back
        from one that issued the right command twice.
        """
        for unit in units:
            self.answers[("systemctl", "is-active", unit)] = "active\n"
            self.answers[("systemctl", "is-enabled", unit)] = "enabled\n"
            self.returncodes[("systemctl", "is-active", unit)] = 0
            self.returncodes[("systemctl", "is-enabled", unit)] = 0
            self.unit_state[unit] = UNIT_RUNNING
        return self

    def record_child(self, command):
        """What a child of this command would see in the four scrubbed names."""
        if command and command[0] == "env":
            self.captured_environment.append(dict(os.environ))
        else:
            self.captured_environment.append(None)

    def probe_for(self, answers=None):
        """A DNS probe that answers from a script and records what it was asked.

        ``answers`` maps ``(address, port)`` to one of the four answer shapes a
        resolver can have -- ``HEALTHY`` (a working chain's denial for a reserved
        name), ``SERVFAIL``, ``REFUSED`` or ``SILENT`` -- or to a callable, so a
        case can make a resolver answer on the first poll, on the third, or never.

        The shapes are the whole of the two questions the transaction asks, and
        they are separate on purpose: "is something listening and speaking DNS" and
        "does this chain resolve" have different answers on a machine whose
        upstream is unreachable, and a single predicate cannot serve both.
        """

        def probe(address, port):
            self.events.append(("probe", address, port))
            answer = (answers or {}).get((address, port), HEALTHY)
            if callable(answer):
                answer = answer()
            return ANSWER_SHAPES[answer]

        return probe

    def clock(self):
        import datetime

        return datetime.datetime(2026, 9, 27, 9, 20, tzinfo=datetime.timezone.utc)

    def run_install(self, runner=None, probe=None, deadline=0.0, poll=0.0, clock=None, **kwargs):
        """Run the transaction against the fake root, with no real command."""
        self.events = []
        if runner is None:
            runner = self.good_runner(**kwargs)
        return installer.install(
            self.root,
            runner,
            clock=clock or self.clock,
            probe=probe or self.probe_for(),
            deadline_seconds=deadline,
            poll_seconds=poll,
        )

    def install_succeeds(self, **kwargs):
        result = self.run_install(**kwargs)
        self.assertEqual(result.error, None, f"the transaction failed: {result.error}")
        self.assertEqual(result.rollback_error, None)
        self.assertTrue(result.ok)
        return result

    def install_cli(self, runner=None):
        """``main`` with the injected probe, which ``main`` does not take.

        The probe is a seam of the functions and not of ``main``, so the one way to
        run the command as a person runs it is to put the fixture's probe back for
        the length of the call. The substitution is in memory and restored in a
        ``finally``, so a case that fails leaves the module as it found it.
        """
        out, err = io.StringIO(), io.StringIO()
        import contextlib

        original = installer.install

        def install(root, run, clock=None, probe=None, **kwargs):
            return original(root, run, clock=clock or self.clock, probe=probe or self.probe_for(), **kwargs)

        installer.install = install
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = installer.main(["install"], runner or self.good_runner(), root=self.root)
        finally:
            installer.install = original
        return status, out.getvalue(), err.getvalue()

    def preflight_commands(self):
        """Preflight's own read-only commands, as a literal.

        Separate from :meth:`full_sequence` because one assertion needs to say
        "the transaction stopped at the check, so nothing after preflight's reads
        ran at all" -- and an assertion like that is only worth anything if the
        thing it compares against is a literal rather than a list built from the
        run being tested.
        """
        rooted = lambda relative: str(self.rooted(relative))  # noqa: E731
        commands = [
            ("dpkg", "--print-architecture"),
            ("systemctl", "--version"),
            ("systemctl", "is-active", "NetworkManager.service"),
            ("systemctl", "is-active", RESOLVED_UNIT),
            NMCLI_CONNECTIONS,
            NMCLI_DEVICE_UUID,
            SS_LISTENERS,
            MAIN_PID + (RESOLVED_UNIT,),
        ]
        commands += [("systemctl", "is-active", unit) for unit in PROJECT_UNITS]
        commands.append(("firefox", "--version"))
        for relative in STATE_DIRECTORIES:
            commands.append(STAT_FIELDS + (rooted(relative),))
            commands.append((GETFACL, "-c", "-p", rooted(relative)))
        return commands

    def full_sequence(self):
        """The commands and probes of a successful install, in order.

        Written out rather than summarised: this is the literal the order test
        compares against, and every entry is a value a reader can check against
        the plan without running anything.
        """
        preflight = self.preflight_commands()
        transaction = [
            capture_command(),
            PACKAGE_VERSION_COMMAND,
            DNS_UUID_PREFIX + ("ipv4.ignore-auto-dns", "connection", "show", UUID),
            DNS_UUID_PREFIX + ("ipv6.ignore-auto-dns", "connection", "show", UUID),
            DNS_UUID_PREFIX + ("ipv4.dns", "connection", "show", UUID),
            DNS_UUID_PREFIX + ("ipv6.dns", "connection", "show", UUID),
            ("systemctl", "is-active", RESOLVER_UNIT),
            ("systemctl", "is-enabled", RESOLVER_UNIT),
            ("systemctl", "is-active", ROUTER_UNIT),
            ("systemctl", "is-enabled", ROUTER_UNIT),
            ("systemctl", "enable", RESOLVER_UNIT),
            ("systemctl", "enable", ROUTER_UNIT),
            PUBLISH_PREFIXES,
            ("systemctl", "start", RESOLVER_UNIT),
            ("systemctl", "start", ROUTER_UNIT),
        ]
        transaction += [MODIFY + (UUID, prop, value) for prop, value in MUTATIONS]
        transaction += [
            CONNECTION_UP + (UUID,),
            ("resolvectl", "dns", DEVICE),
        ]
        return preflight + transaction

    def expected_events(self):
        """``full_sequence`` with the DNS probes interleaved where they belong."""
        probes = {
            ("systemctl", "start", RESOLVER_UNIT): [("probe", LOCAL_DNS, RESOLVER_PORT)],
            ("systemctl", "start", ROUTER_UNIT): [
                ("probe", LOCAL_DNS, DNS_PORT),
                ("probe", LOCAL_DNS, DNS_PORT),
            ],
            MODIFY + (UUID, "ipv4.ignore-auto-dns", "yes"): [],
            ("resolvectl", "dns", DEVICE): [
                ("probe", LOCAL_DNS, DNS_PORT),
                ("probe", RESOLVED_STUB, DNS_PORT),
            ],
        }
        events = []
        for command in self.full_sequence():
            events.append(("run", command))
            events.extend(probes.get(command, []))
        return events


class ModuleSurfaceTests(unittest.TestCase):
    """The interface exists at all, before anything is asserted about it."""

    def test_the_module_offers_an_install(self):
        self.assertTrue(
            hasattr(installer, "install"),
            "mosdns_installer.py has no install(): the whole of this task is missing",
        )

    def test_the_two_install_failure_statuses_are_distinct(self):
        self.assertTrue(
            hasattr(installer, "EXIT_INSTALL_FAILED") and hasattr(installer, "EXIT_ROLLBACK_FAILED"),
            "the transaction has to exit differently when a rollback succeeded and when it did not",
        )
        self.assertNotEqual(installer.EXIT_INSTALL_FAILED, installer.EXIT_ROLLBACK_FAILED)


class TransactionOrderTests(TransactionFixture):
    """The order, asserted as one literal sequence of commands and probes."""

    def test_the_wait_and_the_health_check_are_two_separate_queries(self):
        # They are the same query against the same port, so the sequence test is
        # what tells them apart; this holds the property that makes them different
        # steps rather than one, and that the verification after the reconnection
        # is a third.
        self.install_succeeds()
        local = [event for event in self.events if event == ("probe", LOCAL_DNS, DNS_PORT)]
        self.assertEqual(
            len(local),
            3,
            "the transaction queried the local resolver three times: once to wait for the port, "
            "once to health-check it before the mutation, and once to verify it after the "
            "reconnection",
        )

    def test_a_successful_install_runs_exactly_this_sequence(self):
        self.install_succeeds()
        self.assertEqual(
            self.events,
            self.expected_events(),
            "the transaction ran a different sequence than the one the design fixes",
        )

    def test_no_nm_mutation_comes_before_the_local_resolver_answers(self):
        # The one property the whole design exists to hold, asserted on its own
        # so a failure names it rather than reporting two sequences that differ.
        self.install_succeeds()
        events = self.events
        mutations = [
            index
            for index, event in enumerate(events)
            if event[0] == "run" and event[1][:2] in (MODIFY[:2], CONNECTION_UP[:2])
        ]
        self.assertTrue(mutations, "the transaction has to mutate NetworkManager at all")
        first = mutations[0]
        self.assertGreater(
            len(mutations),
            1,
            "the health check has to be its own step, separate from waiting for the port",
        )
        self.assertEqual(
            events[first - 1],
            ("probe", LOCAL_DNS, DNS_PORT),
            "something other than a DNS query at 127.0.0.1:53 happened immediately before the "
            "first NetworkManager mutation, so nothing proved the local resolver healthy before "
            "the machine was pointed at it",
        )

    def test_the_barrier_check_fires_on_a_reordered_sequence(self):
        # The assertion above is only worth anything if it can fail, so the same
        # check is run over a sequence that modified NetworkManager first and
        # queried afterwards.
        first_mutation = lambda events: next(  # noqa: E731
            index
            for index, event in enumerate(events)
            if event[0] == "run" and event[1][:2] in (MODIFY[:2], CONNECTION_UP[:2])
        )
        barrier = lambda events: events[first_mutation(events) - 1]  # noqa: E731

        correct = self.expected_events()
        self.assertEqual(barrier(correct), ("probe", LOCAL_DNS, DNS_PORT))

        mutations = [event for event in correct if event[0] == "run" and event[1][:2] in (MODIFY[:2], CONNECTION_UP[:2])]
        reordered = mutations + [event for event in correct if event not in mutations]
        self.assertEqual(len(reordered), len(correct), "the control case lost an event")
        self.assertNotEqual(
            barrier(reordered),
            ("probe", LOCAL_DNS, DNS_PORT),
            "a sequence that mutated NetworkManager before the health check passed the barrier",
        )

    def test_it_mutates_exactly_three_properties_and_never_a_public_resolver(self):
        self.install_succeeds()
        modifies = [command for command in self.commands if command[:3] == MODIFY]
        self.assertEqual(
            modifies,
            [MODIFY + (UUID, prop, value) for prop, value in MUTATIONS],
            "the transaction modified something other than the three properties, or set them in "
            "another order, or named another connection",
        )
        for command in modifies:
            self.assertIn(
                command[3],
                (UUID,),
                f"{command!r} modified a connection other than the active one; the UUID is a "
                "separate argument, so a name could not have been passed by accident here",
            )
        for command in modifies:
            if command[4] == "ipv4.dns":
                self.assertTrue(
                    ipaddress.ip_address(command[5]).is_loopback,
                    f"{command!r} points the machine at a resolver that is not this machine",
                )

    def test_the_module_names_no_other_networkmanager_property(self):
        # The recorded list above can only see the properties the test happens
        # to reach. This reads the whole file for every ipv4/ipv6 property it
        # names, so a fifth one fails whether or not a case runs the path that
        # sets it -- and it reads the *text*, prose included, because the names
        # live in string literals and a scan with the literals blanked out can
        # only ever find nothing. That is the price of the rule: this file may
        # not mention a property the transaction does not record and restore.
        named = set(re.findall(r"\bipv[46]\.[A-Za-z0-9_.-]+", SOURCE))
        self.assertEqual(
            named,
            set(RECORDED_PROPERTIES),
            f"the module names NetworkManager properties it does not read and restore: "
            f"{sorted(named - set(RECORDED_PROPERTIES))}",
        )

    def test_the_property_scan_fires_on_a_fifth_property(self):
        scan = lambda text: set(re.findall(r"\bipv[46]\.[A-Za-z0-9_.-]+", text))  # noqa: E731
        self.assertEqual(scan('PROP = "ipv4.dns"'), {"ipv4.dns"})
        self.assertEqual(
            scan('PROP = "ipv4.dns"\nOTHER = "ipv4.dns-priority"'),
            {"ipv4.dns", "ipv4.dns-priority"},
            "the scan cannot see a fifth property, so the assertion above proves nothing",
        )
        self.assertEqual(
            scan('PROP = "ipv6.dns-search"'),
            {"ipv6.dns-search"},
            "a property whose name is a prefix of a recorded one would slip past",
        )

    def test_it_never_restarts_networkmanager_globally(self):
        # Reapplying one connection is the design; reloading or restarting
        # NetworkManager takes every other connection on the machine with it,
        # including a VPN and a second uplink.
        self.install_succeeds()
        for command in self.commands:
            if command[0] == "nmcli" and len(command) > 1:
                self.assertNotIn(command[1], ("general", "reload"), f"{command!r} reloads NetworkManager")
        for command in self.commands:
            if command[:2] == ("systemctl", "reload-or-restart"):
                self.fail(f"{command!r} restarts more than this connection")
        self.assertNotIn(("systemctl", "restart", "NetworkManager.service"), self.commands)

    def test_the_capture_can_import_the_bridge_the_package_installs(self):
        # **Measured on a real 24.04 target, in Task 8's container run.** The
        # bridge is installed as a package at /usr/lib/mosdns-router, which is
        # not on the system path, so `python3 -m mosdns_dhcp_bridge.cli` could not
        # find it and the transaction refused with:
        #
        #   install: the DHCP capture failed with status 1; nothing has been
        #   changed; it said: /usr/bin/python3: Error while finding module
        #   specification for 'mosdns_dhcp_bridge.cli' (ModuleNotFoundError: No
        #   module named 'mosdns_dhcp_bridge')
        #
        # A clean rollback and a message about a module: an install that fails on
        # every machine, and a reader sent to Python rather than to DNS. The
        # package's own dispatcher hook already set PYTHONPATH for this reason;
        # the second caller of the same module did not, so the two disagreed about
        # where the bridge lives.
        #
        # Held against the HOOK's value rather than against a literal, because
        # the disagreement this fixes is between two callers of one module and a
        # case that compared both to a constant would still be green if the
        # constant and both call sites moved together.
        hook = (
            REPO / "packaging" / "networkmanager" / "10-mosdns-dhcp-bridge"
        ).read_text(encoding="utf-8")
        self.assertIn("PYTHONPATH=/usr/lib/mosdns-router", hook)
        self.assertIn(
            "PYTHONPATH=/usr/lib/mosdns-router",
            capture_command(),
            "the installer's capture does not put the bridge package on the path, so the module "
            "it runs cannot be imported and every install refuses",
        )

    def test_the_capture_runs_before_anything_is_changed(self):
        # The capture is the only way this machine's original resolvers can be
        # recorded, and after the properties below are set nothing on the machine
        # can read them back out of NetworkManager. So it is first.
        self.install_succeeds()
        capture = capture_command()
        self.assertIn(capture, self.commands)
        before = self.commands[: self.commands.index(capture)]
        self.assertEqual(
            [command for command in before if self.changing(command)],
            [],
            "something changed the machine before the lease had been captured",
        )

    def test_a_refused_machine_is_never_mutated(self):
        # Preflight's refusals are reused rather than re-derived, so a machine it
        # refuses never reaches the capture, the backup or any unit.
        self.build_state_directories(mode="2777")
        answers = {
            STAT_FIELDS + (str(self.rooted(relative)),): f"2777 root mosdns {stat.S_IFDIR | 0o2777:x}"
            for relative in STATE_DIRECTORIES
        }
        runner = self.good_runner(outputs=answers)
        result = installer.install(self.root, runner, clock=self.clock, probe=self.probe_for())
        self.assertFalse(result.ok)
        self.assertIsNone(result.backup)
        self.assertIn("preflight", (result.error or "").lower())
        self.assertEqual(result.rollback_error, None)
        self.assertNothingChanged("a refused machine was changed")
        self.assertFalse(self.rooted(BACKUP_PATH).exists())


class ScrubbedEnvironmentTests(TransactionFixture):
    """The capture's four names, in the argument array and in a real child."""

    def test_the_capture_unsets_exactly_the_four_names(self):
        self.install_succeeds()
        capture = capture_command()
        self.assertIn(capture, self.commands)
        unsets = [capture[index + 1] for index, word in enumerate(capture) if word == "-u"]
        self.assertEqual(unsets, list(SCRUBBED), "the capture scrubs a different set of names")
        self.assertEqual(
            [capture[index] for index, word in enumerate(capture) if word == "-u"],
            ["-u"] * len(SCRUBBED),
            "a scrubbed name has to follow its -u",
        )

    def test_the_capture_is_an_argument_array_naming_the_state_and_lock(self):
        capture = capture_command()
        self.assertEqual(
            capture[-9:],
            (
                "python3",
                "-m",
                "mosdns_dhcp_bridge.cli",
                "--capture-current",
                DEVICE,
                "--state-file",
                DHCP_STATE_FILE,
                "--lock-file",
                DHCP_LOCK_FILE,
            ),
            "the capture is not the module invocation the bridge documents; in particular the "
            "interface is one argument, so a device name could not be split by anything",
        )
        self.assertNotIsInstance(capture, str)

    def test_the_names_are_absent_in_a_real_child_of_this_prefix(self):
        # The one place a real process is started, and it starts the interpreter
        # on an ephemeral loopback-free path: it prints its own environment and
        # touches nothing. The parent is deliberately polluted with all four
        # names, so a scrub that only worked on a clean environment passes
        # nothing here.
        polluted = {
            "NM_DISPATCHER_ACTION": "up",
            "DHCP4_DOMAIN_NAME_SERVERS": "192.0.2.1",
            "DHCP6_DOMAIN_NAME_SERVERS": "2001:db8::1",
            "CONNECTION_UUID": OTHER_UUID,
        }
        for name, value in polluted.items():
            previous = os.environ.get(name)
            os.environ[name] = value
            self.addCleanup(os.environ.pop, name, None)
            if previous is not None:
                self.addCleanup(os.environ.__setitem__, name, previous)
        prefix = list(capture_command()[:9]) + [sys.executable, "-c"]
        program = "import os,sys;sys.stdout.write('|'.join(n for n in sys.argv[1:] if n in os.environ))"
        completed = subprocess.run(
            prefix + [program, *SCRUBBED],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(
            completed.returncode, 0, f"the scrubbed child did not run: {completed.stderr!r}"
        )
        self.assertEqual(
            completed.stdout,
            "",
            f"the child still sees {completed.stdout!r}; a name the installer's own environment "
            "carries changes what the capture records",
        )
        for name, value in polluted.items():
            self.assertEqual(
                os.environ.get(name), value, "the test's own pollution did not survive the child"
            )

    def test_the_command_keeps_the_rest_of_the_environment(self):
        # A scrub that emptied the environment would break the child's import
        # path and is not what the ruling asks for: four names, and no others.
        os.environ["MOSDNS_TEST_KEEP_ME"] = "kept"
        self.addCleanup(os.environ.pop, "MOSDNS_TEST_KEEP_ME", None)
        completed = subprocess.run(
            list(capture_command()[:9])
            + [sys.executable, "-c", "import os;print(os.environ.get('MOSDNS_TEST_KEEP_ME',''))"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "kept", "the scrub emptied the environment")

    def test_the_transaction_leaves_the_process_environment_alone(self):
        before = dict(os.environ)
        self.install_succeeds()
        self.assertEqual(
            dict(os.environ), before, "the transaction exported or unset a variable in its own process"
        )

    def test_a_capture_that_published_nothing_aborts_before_anything_is_mutated(self):
        # Exit 4 is a defined outcome of this step, not an accident: the capture
        # read the lease and could not name the connection it belonged to, so it
        # published nothing and the addresses it had read are gone.
        for status, expected in ((4, "connection"), (2, "command line"), (1, "failed")):
            with self.subTest(status=status):
                self.setUp()
                self.returncodes[capture_command()] = status
                result = self.run_install()
                self.assertFalse(result.ok)
                self.assertIsNone(result.rollback_error, "nothing had been changed to roll back")
                self.assertIn(expected, (result.error or "").lower())
                self.assertNothingChanged(f"a capture that exited {status} was followed by a change")
                self.assertFalse(self.rooted(BACKUP_PATH).exists())


class BackupTests(TransactionFixture):
    """The record: what is in it, who may read it, and that it was read back."""

    def backup(self):
        self.install_succeeds()
        return self.rooted(BACKUP_PATH)

    def test_the_backup_records_everything_a_restore_needs(self):
        path = self.backup()
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            document,
            {
                "schema_version": BACKUP_SCHEMA_VERSION,
                "managed_by": MANAGED_BY_VALUE,
                "package": PACKAGE_NAME,
                "package_version": PACKAGE_VERSION,
                "created_at": CREATED_AT,
                "config_path": POLICY_CONFIG,
                "config_sha256": hashlib.sha256(POLICY_BODY.encode("utf-8")).hexdigest(),
                "connection": {
                    "uuid": UUID,
                    "name": CONNECTION_NAME,
                    "type": "802-3-ethernet",
                    "device": DEVICE,
                },
                "original": {
                    "ipv4.ignore-auto-dns": {"raw": "no", "value": "no"},
                    "ipv6.ignore-auto-dns": {"raw": "no", "value": "no"},
                    "ipv4.dns": {"raw": DHCP_UPSTREAM, "value": [DHCP_UPSTREAM]},
                    "ipv6.dns": {"raw": "", "value": []},
                },
                "dhcp": {
                    "state_file": DHCP_STATE_FILE,
                    "interface": DEVICE,
                    "connection_uuid": UUID,
                    "upstreams": [DHCP_UPSTREAM],
                    "source": "dhcp4",
                    "generation": 1,
                    "observed_at": OBSERVED_AT,
                },
            },
            "the backup does not say everything a restore and an operator need",
        )

    def test_the_backup_names_the_property_values_it_actually_read(self):
        outputs = {
            DNS_UUID_PREFIX + ("ipv4.ignore-auto-dns", "connection", "show", UUID): "yes\n",
            DNS_UUID_PREFIX + ("ipv6.ignore-auto-dns", "connection", "show", UUID): "no\n",
            DNS_UUID_PREFIX + ("ipv4.dns", "connection", "show", UUID): f"{DHCP_UPSTREAM},{DHCP_SECOND_UPSTREAM}\n",
            DNS_UUID_PREFIX + ("ipv6.dns", "connection", "show", UUID): "2001:db8::1\n",
        }
        self.install_succeeds(outputs=outputs)
        document = json.loads(self.rooted(BACKUP_PATH).read_text(encoding="utf-8"))
        self.assertEqual(
            document["original"],
            {
                "ipv4.ignore-auto-dns": {"raw": "yes", "value": "yes"},
                "ipv6.ignore-auto-dns": {"raw": "no", "value": "no"},
                "ipv4.dns": {
                    "raw": f"{DHCP_UPSTREAM},{DHCP_SECOND_UPSTREAM}",
                    "value": [DHCP_UPSTREAM, DHCP_SECOND_UPSTREAM],
                },
                "ipv6.dns": {"raw": "2001:db8::1", "value": ["2001:db8::1"]},
            },
            "the backup recorded a value the transaction did not read",
        )

    def test_the_dns_list_is_split_whatever_separator_nmcli_prints(self):
        # `nmcli -g` is asked for one property at a time, and this module has no
        # way to measure what separator a given NetworkManager uses for an array.
        # The three spellings below are the ones the man page and the wild use,
        # and all three have to yield the same list, because a wrong split would
        # restore a single malformed address.
        for raw, expected in (
            (f"{DHCP_UPSTREAM},{DHCP_SECOND_UPSTREAM}", [DHCP_UPSTREAM, DHCP_SECOND_UPSTREAM]),
            (f"{DHCP_UPSTREAM};{DHCP_SECOND_UPSTREAM}", [DHCP_UPSTREAM, DHCP_SECOND_UPSTREAM]),
            (f"{DHCP_UPSTREAM} {DHCP_SECOND_UPSTREAM}", [DHCP_UPSTREAM, DHCP_SECOND_UPSTREAM]),
            (DHCP_UPSTREAM, [DHCP_UPSTREAM]),
            ("", []),
        ):
            with self.subTest(raw=raw):
                self.setUp()
                outputs = {DNS_UUID_PREFIX + ("ipv4.dns", "connection", "show", UUID): raw + "\n"}
                self.install_succeeds(outputs=outputs)
                document = json.loads(self.rooted(BACKUP_PATH).read_text(encoding="utf-8"))
                self.assertEqual(document["original"]["ipv4.dns"]["value"], expected)
                self.assertEqual(document["original"]["ipv4.dns"]["raw"], raw)

    def test_a_dns_value_that_is_not_an_address_is_refused_before_anything_is_mutated(self):
        # A value the module cannot re-parse is a value the restore could not
        # reproduce, and a backup that cannot be restored is worse than a refusal
        # that has changed nothing.
        self.answers[DNS_UUID_PREFIX + ("ipv4.dns", "connection", "show", UUID)] = "not-an-address\n"
        result = self.run_install()
        self.assertFalse(result.ok)
        self.assertIn("not-an-address", result.error or "")
        self.assertFalse(self.rooted(BACKUP_PATH).exists())
        self.assertNothingChanged("an unreadable DNS list was followed by a change")

    def test_an_ignore_auto_dns_value_that_is_not_yes_or_no_is_refused(self):
        for raw in ("maybe", "true", "1", ""):
            with self.subTest(raw=raw):
                self.setUp()
                self.answers[DNS_UUID_PREFIX + ("ipv4.ignore-auto-dns", "connection", "show", UUID)] = raw + "\n"
                result = self.run_install()
                self.assertFalse(result.ok, f"{raw!r} was accepted as an ignore-auto-dns value")
                self.assertFalse(self.rooted(BACKUP_PATH).exists())

    def test_the_backup_is_written_before_the_first_mutation(self):
        self.install_succeeds()
        last_read = self.commands.index(DNS_UUID_PREFIX + ("ipv6.dns", "connection", "show", UUID))
        first_mutation = next(
            index
            for index, command in enumerate(self.commands)
            if command[:1] == ("systemctl",) and command[1] in ("enable", "start")
        )
        self.assertLess(
            last_read,
            first_mutation,
            "a unit was enabled or started before the original property values had been read",
        )
        self.assertTrue(self.rooted(BACKUP_PATH).exists())

    def test_the_backup_is_root_only(self):
        path = self.backup()
        info = path.lstat()
        self.assertEqual(stat.S_IMODE(info.st_mode), BACKUP_MODE, "the backup is readable by somebody else")
        self.assertTrue(stat.S_ISREG(info.st_mode))
        # The contents name the machine's resolvers and its connection, so a
        # world-readable backup is a map of the network.
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8"))["dhcp"]["upstreams"],
            [DHCP_UPSTREAM],
        )

    def test_the_backup_directory_is_created_root_only_and_not_re_permissioned(self):
        self.assertFalse(self.rooted("/var/lib/mosdns/installer").exists())
        self.install_succeeds()
        directory = self.rooted("/var/lib/mosdns/installer")
        self.assertEqual(stat.S_IMODE(directory.lstat().st_mode), 0o700)
        # A directory the package already made belongs to the package; the
        # transaction writes into it and does not change what it finds, which is
        # the rule preflight keeps for everything it inspects.
        self.setUp()
        directory = self.rooted("/var/lib/mosdns/installer")
        directory.mkdir(parents=True)
        directory.chmod(0o755)
        self.install_succeeds()
        self.assertEqual(
            stat.S_IMODE(directory.lstat().st_mode),
            0o755,
            "the transaction re-permissioned a directory it did not create",
        )

    def test_a_backup_that_cannot_be_written_aborts_before_anything_is_mutated(self):
        # A directory where the file has to be is a real filesystem condition,
        # not a mock: the write cannot succeed, so the transaction must stop
        # before it has enabled a unit.
        path = self.rooted(BACKUP_PATH)
        path.parent.mkdir(parents=True)
        path.mkdir()
        result = self.run_install()
        self.assertFalse(result.ok)
        self.assertIsNone(result.rollback_error, "nothing had been mutated to roll back")
        self.assertNothingChanged("the transaction changed the machine without a backup")

    def test_a_backup_that_cannot_be_read_back_aborts_before_anything_is_mutated(self):
        # The validation is a read-back and a comparison, so it is the second
        # half of the write that has to pass. Corrupting the payload between the
        # write and the comparison is exactly what the check exists for, and it
        # is the only way a write that reported success can still be wrong.
        original = installer.validate_backup
        self.addCleanup(setattr, installer, "validate_backup", original)

        def poison(root, document):
            path = root / BACKUP_PATH.lstrip("/")
            path.write_text(json.dumps({**document, "package_version": "0.0.0-lies"}) + "\n")
            path.chmod(BACKUP_MODE)
            return original(root, document)

        installer.validate_backup = poison
        try:
            result = self.run_install()
        finally:
            installer.validate_backup = original
        self.assertFalse(result.ok)
        self.assertIn("backup", (result.error or "").lower())
        self.assertNothingChanged("the transaction changed the machine on an unvalidated backup")

    def test_a_backup_written_at_the_wrong_mode_is_refused(self):
        self.setUp()
        path = self.rooted(BACKUP_PATH)
        document = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "managed_by": MANAGED_BY_VALUE,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o644)
        with self.assertRaises(installer.InstallRefused) as caught:
            installer.validate_backup(self.root, document)
        self.assertIn("0600", str(caught.exception))

    def test_validate_backup_refuses_a_document_that_differs(self):
        self.setUp()
        path = self.rooted(BACKUP_PATH)
        document = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "managed_by": MANAGED_BY_VALUE,
            "connection": {"uuid": UUID},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        for mutation, because in (
            ({"connection": {"uuid": OTHER_UUID}}, "a different connection"),
            ({"schema_version": 99}, "a schema this version cannot read"),
            ({"managed_by": "something-else"}, "a marker naming another installation"),
            ({"extra": True}, "a field the writer did not mean to write"),
        ):
            with self.subTest(mutation=because):
                path.write_text(json.dumps({**document, **mutation}), encoding="utf-8")
                path.chmod(BACKUP_MODE)
                with self.assertRaises(installer.InstallRefused):
                    installer.validate_backup(self.root, document)
        path.write_text("{not json", encoding="utf-8")
        path.chmod(BACKUP_MODE)
        with self.assertRaises(installer.InstallRefused):
            installer.validate_backup(self.root, document)

    def test_a_config_it_cannot_digest_aborts_before_anything_is_mutated(self):
        self.rooted(POLICY_CONFIG).unlink()
        result = self.run_install()
        self.assertFalse(result.ok)
        self.assertIn(POLICY_CONFIG, result.error or "")
        self.assertFalse(self.rooted(BACKUP_PATH).exists())
        self.assertNothingChanged("the transaction changed the machine with no configuration digest")

    def test_a_dhcp_state_that_is_not_a_state_document_is_refused(self):
        # Everywhere else this module refuses a document it cannot parse, and this
        # one was the exception: a JSON object of any shape was accepted and copied
        # with defaults, so a state whose `upstreams` is the STRING "192.0.2.53"
        # produced a backup listing every character of it as a resolver. A backup
        # that names a resolvers list of one character at a time is worse than no
        # backup, because it is one an operator cannot tell is wrong.
        for name, document, because in (
            ("upstreams as a string", {"upstreams": "192.0.2.53"}, "a resolvers list of characters"),
            ("upstreams as a mapping", {"upstreams": {"0": "192.0.2.53"}}, "a resolvers list of keys"),
            ("upstreams with a non-address", {"upstreams": ["resolver.example"]}, "a hostname where an address belongs"),
            ("generation as a string", {"generation": "1"}, "a generation that is not a number"),
            ("generation as a float", {"generation": 1.5}, "a generation that is not a whole number"),
            ("upstreams missing", {}, "no resolvers field at all when the publisher writes one"),
        ):
            with self.subTest(because=because):
                self.setUp()
                path = self.rooted(DHCP_STATE_FILE)
                complete = json.loads(path.read_text(encoding="utf-8"))
                complete.update(document)
                if "upstreams" not in document and "upstreams" in complete:
                    del complete["upstreams"]
                path.write_text(json.dumps(complete), encoding="utf-8")
                result = self.run_install()
                self.assertFalse(result.ok, f"a state with {because} was accepted")
                self.assertIn(DHCP_STATE_FILE, result.error or "")
                self.assertNothingChanged(f"the transaction read {because} into a backup")

    def test_an_empty_resolver_list_is_still_a_state_document(self):
        # The publisher writes `upstreams: []` for a lease that named no resolver
        # and that is a legitimate state, not a missing field.
        self.dhcp_state(upstreams=())
        self.install_succeeds()
        document = json.loads(self.rooted(BACKUP_PATH).read_text(encoding="utf-8"))
        self.assertEqual(document["dhcp"]["upstreams"], [])
        self.assertEqual(document["dhcp"]["source"], "dhcp4")

    def test_a_package_version_it_cannot_read_aborts_before_anything_is_mutated(self):
        result = self.run_install(
            outputs={PACKAGE_VERSION_COMMAND: ""}, returncodes={PACKAGE_VERSION_COMMAND: 1}
        )
        self.assertFalse(result.ok)
        self.assertIn(PACKAGE_NAME, result.error or "")
        self.assertFalse(self.rooted(BACKUP_PATH).exists())

    def test_a_dhcp_state_it_cannot_read_aborts_before_anything_is_mutated(self):
        # The lease the capture just published is what the backup records, so a
        # state file that cannot be read is a backup that cannot describe what
        # this machine was following.
        self.rooted(DHCP_STATE_FILE).unlink()
        result = self.run_install()
        self.assertFalse(result.ok)
        self.assertIn(DHCP_STATE_FILE, result.error or "")
        self.assertNothingChanged("the transaction changed the machine with no lease recorded")


class PrefixListTests(TransactionFixture):
    """The router cannot start without a published prefix list, so it is published.

    The response rewriter calls ``newPrefixList`` before anything else and
    returns the error, so a plugin with no published Cloudflare ranges never
    constructs -- which means ``systemctl start mosdns-router`` binds nothing on
    port 53, the wait for the resolver port burns its whole deadline, and the
    install rolls itself back. A router that cannot start is not a state an
    install may leave a machine waiting in, and the producer of the list
    (``mosdns-cdnctl update-lists --refresh-ranges``, which measures nothing and
    spends no bandwidth budget) already exists and documents itself as the
    install-time mode.
    """

    def test_the_prefix_list_is_published_between_the_enables_and_the_first_start(self):
        self.install_succeeds()
        self.assertIn(PUBLISH_PREFIXES, self.commands)
        enables = [
            index
            for index, command in enumerate(self.commands)
            if command[:2] == ("systemctl", "enable")
        ]
        starts = [index for index, command in enumerate(self.commands) if command[:2] == ("systemctl", "start")]
        published = self.commands.index(PUBLISH_PREFIXES)
        self.assertEqual(len(enables), 2, "both units are enabled before the list is published")
        self.assertEqual(len(starts), 2)
        self.assertLess(max(enables), published, "the list was published before a unit was enabled")
        self.assertLess(published, min(starts), "a unit was started before the list was published")

    def test_the_publisher_is_the_mode_that_publishes_and_takes_no_measurement(self):
        # `--check` writes nothing and cannot publish; `--pin-remote` re-pins the
        # China list, which an install must not do. `--refresh-ranges` is the only
        # one of the three that publishes the prefix list, and its own flag
        # description calls it the mode an installation runs before the router
        # starts. The array is pinned whole, so a mode that measures, or one that
        # touches the China list, cannot be substituted for it quietly.
        self.install_succeeds()
        published = self.commands[self.commands.index(PUBLISH_PREFIXES)]
        self.assertEqual(published[0], CDNCTL)
        self.assertEqual(published[1:], ("update-lists", "--refresh-ranges"))
        for wrong in ("test", "pin-remote", "measure", "apply"):
            self.assertNotIn(wrong, published[2:], f"{wrong!r} is a mode that may not be substituted here")

    def test_a_prefix_list_that_cannot_be_published_refuses_the_install(self):
        # Never a warning, and never "the optimizer's timer will get there". The
        # install is the only moment at which nothing else has published the list,
        # and the router cannot start without it, so continuing would mean waiting
        # out a 60-second deadline and rolling back having learned nothing.
        result = self.run_install(fail=[PUBLISH_PREFIXES])
        self.assertFalse(result.ok, "a prefix list that could not be published was not a refusal")
        self.assertIn("prefix", (result.error or "").lower())
        self.assertIsNone(result.rollback_error, "the rollback of that refusal did not complete")
        self.assertFalse(self.rooted(MANAGED_BY).exists(), "the marker was written after a refused publish")
        # Nothing NetworkManager-facing ever ran, and neither unit was started.
        for command in self.commands:
            self.assertNotIn(command[:2], (MODIFY[:2], CONNECTION_UP[:2]), f"{command!r} ran")
            self.assertNotEqual(command[:2], ("systemctl", "start"), f"{command!r} ran")
        # Both units were enabled and are put back; neither was started, so there
        # is nothing to stop and a stop would be the transaction acting on a unit
        # it never reached.
        self.assertEqual(
            self.commands[self.commands.index(PUBLISH_PREFIXES) + 1 :],
            [
                ("systemctl", "disable", ROUTER_UNIT),
                ("systemctl", "disable", RESOLVER_UNIT),
            ],
        )

    def test_the_list_is_published_the_same_way_with_and_without_a_cached_envelope(self):
        # A machine with a valid cached envelope must still be sent through the
        # publisher, because a publisher that decides for itself whether to run
        # is a publisher whose decision is a second thing that can be wrong: it
        # would have to re-derive the cache's validity, and an origin that is
        # unreachable is exactly when the cached envelope is the answer. So the
        # command is the same array either way, and it names no origin at all.
        self.install_succeeds()
        published = self.commands[self.commands.index(PUBLISH_PREFIXES)]
        self.setUp()
        self.write(
            "/var/lib/mosdns/lists/cloudflare-ips.json",
            json.dumps({"schema_version": 1, "url": "https://example.invalid/ranges", "prefixes": []}),
            mode=0o644,
        )
        self.install_succeeds()
        self.assertEqual(
            self.commands[self.commands.index(PUBLISH_PREFIXES)],
            published,
            "the command differs when a cached envelope is present, so the decision to publish is "
            "the installer's rather than the publisher's",
        )
        for word in ("--ranges-url", "--ranges-cache", "http://", "https://"):
            self.assertNotIn(word, " ".join(published), f"{word!r} in the command would make the publish reach the network on its own terms")

    def test_the_resolver_binds_inside_the_budget_the_transaction_waits_in(self):
        """The one number that had to change before any install could complete.

        MEASURED, in a container cell, on the first install that ever got this far:
        ``dnscrypt-proxy`` logged

            Network not available yet -- waiting...
            Timeout while waiting for network connectivity
            Now listening to 127.0.0.1:15353 [UDP]

        sixty seconds after it was started, and the transaction gave up at the
        same second -- because the resolver's own reachability probe is configured
        for 60 seconds and ``WAIT_DEADLINE_SECONDS`` is 60 seconds. On a machine
        with a route both are satisfied instantly; on a machine with NO route the
        probe has to run out before the listener exists, so the two budgets
        collided exactly and the install refused at this step, on every machine
        this step exists to make installable.

        The probe is kept, because a blackholed network should still be reported,
        and the budget is what has to exceed it. Disabling the probe outright would
        take the report with it; raising the wait would make every offline install
        spend a minute discovering there is no internet.

        So the invariant is the relationship, and both sides of it are read from
        the files that carry them: a number here could be changed in step with the
        number there and leave this test as the only thing that notices.
        """
        text = (REPO / "configs" / "dnscrypt-proxy.toml").read_text(encoding="utf-8")
        rendered = toml_scalar(text, "netprobe_timeout")
        self.assertIsNotNone(
            rendered,
            "the shipped resolver document sets no netprobe_timeout, so the resolver uses "
            "dnscrypt-proxy's own default of 60 seconds and the transaction waits exactly as long",
        )
        self.assertGreater(
            rendered, 0,
            "netprobe_timeout is 0, which switches the probe off; a blackholed network would then "
            "be reported by nothing at all",
        )
        self.assertLess(
            rendered, installer.WAIT_DEADLINE_SECONDS,
            f"the resolver's own start-up budget is {rendered}s and the transaction waits "
            f"{installer.WAIT_DEADLINE_SECONDS}s, so on a machine that cannot reach the probe "
            "address the listener appears at the moment the transaction has given up waiting "
            "for it",
        )
        # And the wait itself is bounded, because a test that only said "the probe
        # is shorter" would pass with a probe of a microsecond and no deadline at
        # all, which is the opposite of what the collision was.
        self.assertGreater(
            installer.WAIT_DEADLINE_SECONDS, rendered,
            "the transaction's own wait was lowered to fit under the resolver's probe rather than "
            "the probe being bounded -- a resolver that cannot start at all would then be waited "
            "for less than the time a healthy one needs",
        )

    def test_no_undo_is_registered_for_the_publication(self):
        # Republishing an already-published list is idempotent, and a rollback
        # that un-published it would leave a router that will not start -- which is
        # worse than the list it was published from. So the step has no undo, and
        # the tail after a failure at the FIRST start is the units only.
        self.run_install(fail=[CONNECTION_UP + (UUID,)])
        tail = self.commands[self.commands.index(CONNECTION_UP + (UUID,)) + 1 :]
        self.assertIn(PUBLISH_PREFIXES, self.commands, "the publisher has to have run for this to mean anything")
        self.assertNotIn(PUBLISH_PREFIXES, tail, "a rollback tried to un-publish the prefix list")
        # And the units ARE put back, so the absence is the publisher's and not a
        # rollback that stopped working.
        self.assertIn(("systemctl", "stop", ROUTER_UNIT), tail)
        self.assertIn(("systemctl", "stop", RESOLVER_UNIT), tail)
        self.assertIn(("systemctl", "disable", ROUTER_UNIT), tail)
        self.assertIn(("systemctl", "disable", RESOLVER_UNIT), tail)


class ResolvingChainTests(TransactionFixture):
    """Two questions, and one predicate cannot answer both.

    "Is something listening and speaking DNS" and "does this chain resolve" have
    different answers on a machine whose upstream is unreachable, and the second
    one is the question the barrier exists to ask. Measured against real
    systemd-resolved 24.04 with an unreachable upstream configured: a request for
    a name under ``.invalid`` is answered immediately with a bare NXDOMAIN that
    carries no records at all, while a request for a name under ``.test`` is
    forwarded and comes back as silence. A barrier that accepts any answer would
    have passed that machine; a barrier that accepts NOERROR and NXDOMAIN but
    probes ``.invalid`` still would.
    """

    def test_a_servfail_answers_the_wait_but_not_the_barrier(self):
        result = self.run_install(probe=self.probe_for({(LOCAL_DNS, DNS_PORT): SERVFAIL}))
        self.assertFalse(result.ok, "a resolver answering SERVFAIL passed the health check")
        self.assertIn("SERVFAIL", (result.error or ""), "the refusal has to name what the resolver said")
        for command in self.commands:
            self.assertNotIn(
                command[:2], (MODIFY[:2], CONNECTION_UP[:2]), f"{command!r} ran after a SERVFAIL chain"
            )
        self.assertFalse(self.rooted(MANAGED_BY).exists())

    def test_a_refused_answers_the_wait_but_not_the_barrier(self):
        result = self.run_install(probe=self.probe_for({(LOCAL_DNS, DNS_PORT): REFUSED}))
        self.assertFalse(result.ok, "a resolver answering REFUSED passed the health check")
        for command in self.commands:
            self.assertNotIn(command[:2], (MODIFY[:2], CONNECTION_UP[:2]), f"{command!r} ran")

    def test_a_denial_from_a_working_chain_passes_both(self):
        # A reserved name has no delegation, so a chain that works answers
        # NXDOMAIN. That is a resolver that resolved: it reached somebody who told
        # it the name does not exist. The barrier must accept it, or the install
        # would be impossible on every healthy machine.
        self.install_succeeds(probe=self.probe_for({(LOCAL_DNS, DNS_PORT): HEALTHY}))

    def test_a_silent_resolver_still_fails_the_waits(self):
        # The waits are the rcode-agnostic half and must stay that way: a socket
        # that is listening and speaking DNS is proved by any answer at all, and
        # a resolver that is up but has not finished binding its own children is
        # not a failure of the install.
        for port in (RESOLVER_PORT, DNS_PORT):
            with self.subTest(port=port):
                self.setUp()
                result = self.run_install(probe=self.probe_for({(LOCAL_DNS, port): SILENT}))
                self.assertFalse(result.ok, f"nothing answered on {port} and the install proceeded")
                self.assertIn(str(port), result.error or "")

    def test_a_servfail_after_the_reconnection_fails_the_verification(self):
        # The same question again at the end: resolved forwards to the router, and
        # if the router has started answering SERVFAIL the machine is pointed at a
        # chain that cannot resolve. The verification is the last chance to notice.
        def answering_servfail_late(address, port):
            self.events.append(("probe", address, port))
            local = [event for event in self.events if event[:3] == ("probe", LOCAL_DNS, DNS_PORT)]
            return answer(True, len(local) < 3)

        result = self.run_install(probe=answering_servfail_late)
        self.assertFalse(result.ok, "a chain that started SERVFAILING passed the verification")
        self.assertIn(MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM), self.commands)
        self.assertFalse(self.rooted(MANAGED_BY).exists())

    def test_the_probe_name_is_one_the_rfc_tells_a_resolver_to_forward(self):
        """The name, and an honest account of what this test can and cannot hold.

        THE REAL DEPENDENCY is a property of the machine the install runs on: that
        the operator's resolver FORWARDS this name instead of answering it locally.
        A fake root cannot observe that, a container cannot host the router, and no
        assertion in this file can stand in for it. Everything below is a PROXY for
        it, and the proxy is only as good as the observation behind it.

        The observation: on real systemd-resolved 24.04 with an unreachable
        upstream, `.invalid` is answered with an immediate bare NXDOMAIN and
        `.example` is forwarded into silence. The RFC explains why those differ,
        and the difference is the whole of the choice -- RFC 6761 gives every
        special-use TLD a "caching servers" category, and the three candidates are
        recommended in three different directions:

          * `.invalid`  (§6.4 category 4): caching servers SHOULD generate immediate
            NXDOMAIN. resolved does exactly that, so `.invalid` is CONFORMING and
            deterministically blind -- a dead chain states a confident denial.
          * `.test`     (§6.2 category 4): caching servers SHOULD generate immediate
            negative responses. resolved forwarding it is a measured DEVIATION
            from a SHOULD, so a resolver that follows the RFC would reintroduce the
            blind spot.
          * `.example`  (§6.5 category 4): caching servers SHOULD NOT recognise
            these names as special and SHOULD resolve them normally. resolved
            forwarding it is the RECOMMENDED behaviour, so the name cannot be
            answered locally by a conforming caching server.

        So the assertion is the RFC's own partition, not a list of names that
        happen to work today: the probe's TLD must be one whose category 4 asks
        for normal resolution. 22.04 and 26.04 are unmeasured and the residual
        says so.
        """
        labels = INSTALL_PROBE_NAME.split(".")
        self.assertEqual(
            labels[-1],
            FORWARDED_TLD,
            "the probe's TLD must be the one RFC 6761 tells a caching server to resolve normally "
            "(§6.5 category 4); a TLD whose category 4 asks for an immediate local response makes "
            "a dead chain look like a resolver",
        )
        self.assertIn(
            labels[-1],
            SPECIAL_USE_TLDS,
            "the probe name must be under a special-use TLD, so it is meaningless to the public "
            "root and the 1-3 queries an install sends cannot resolve to anything real",
        )
        self.assertNotIn(labels[-1], LOCALLY_ANSWERED_TLDS, "see the RFC partition in this docstring")
        for label in labels[:-1]:
            self.assertTrue(label, "the probe name has an empty label")
            self.assertLessEqual(len(label), 63)
        self.assertGreaterEqual(
            len(labels),
            2,
            "the force-ECH list's own rule is that an entry needs at least two labels, so a "
            "one-label probe name could not even be refused by the check that guards this one",
        )

    def test_response_resolves_is_the_question_the_barrier_asks(self):
        query = installer.build_dns_query(INSTALL_PROBE_NAME, 0x0042)
        question = query[12:]

        def reply(flags):
            return query[:2] + flags.to_bytes(2, "big") + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question

        for flags, listening, resolving, why in (
            (0x8180, True, True, "NOERROR"),
            (0x8183, True, True, "NXDOMAIN"),
            (0x8182, True, False, "SERVFAIL"),
            (0x8185, True, False, "REFUSED"),
            (0x8181, True, False, "FORMERR"),
            (0x8184, True, False, "NOTIMP"),
        ):
            with self.subTest(why=why):
                self.assertTrue(installer.response_is_an_answer(reply(flags), 0x0042), f"{why} is not an answer")
                self.assertEqual(
                    installer.response_resolves(reply(flags), 0x0042),
                    resolving,
                    f"{why} was read as {'resolving' if resolving else 'not resolving'}",
                )
        self.assertFalse(installer.response_is_an_answer(query, 0x0042), "a query is not an answer")
        self.assertFalse(installer.response_resolves(query, 0x0042), "a query resolves nothing")
        self.assertFalse(installer.response_resolves(reply(0x8183), 0x0043), "another question's denial")
        self.assertFalse(installer.response_resolves(b"", 0x0042), "nothing at all")

    def test_the_two_answers_come_from_one_query(self):
        # One question, two facts, because a second query would double the
        # deadline and ask a second question of a machine that is already in
        # trouble. A resolver that answers SERVFAIL has answered; it has not
        # resolved. Both come from the one datagram.
        server, port, thread = responder(lambda query: query[:2] + b"\x81\x82" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:])
        try:
            answer = installer.probe_dns("127.0.0.1", port, timeout=2.0)
            self.assertTrue(answer.answered, "a SERVFAIL is an answer")
            self.assertFalse(answer.resolves, "a SERVFAIL does not resolve")
        finally:
            server.close()
            thread.join(timeout=5)
        server, port, thread = responder(lambda query: query[:2] + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:])
        try:
            answer = installer.probe_dns("127.0.0.1", port, timeout=2.0)
            self.assertTrue(answer.answered)
            self.assertTrue(answer.resolves, "an NXDOMAIN from a working chain resolves")
        finally:
            server.close()
            thread.join(timeout=5)


class LocallyAnsweredProbeTests(TransactionFixture):
    """A force-ECH entry can make the router answer the probe itself, and nothing else.

    The rewriter's strict short circuit is the first thing its Exec does: for a name
    on the operator's force-ECH list, with the policy's failure policy fail-closed,
    an **A** or AAAA query is answered with `emptyAnswer(query)` -- NOERROR, the
    question echoed, no records, no SOA -- and `next.ExecNext` is never called. The
    install's probe is an A query, so an operator with the probe's name on that list
    gets a NOERROR out of the router without one thing being asked downstream: the
    wait, the barrier and `_verify`'s router probe are all satisfied by a local lie.

    That is load-bearing ECH behaviour and it is correct. This install cannot
    weaken it, and it does not. What it can do is refuse to run at all when its own
    probe would be answered that way, which is the only outcome in which "the
    barrier passed" means "the machine can resolve" -- so that is what it does.
    """

    def test_the_install_is_refused_when_the_router_would_answer_the_probe_itself(self):
        self.force_ech("cdn.example.net", INSTALL_PROBE_NAME)
        result = self.run_install()
        self.assertFalse(result.ok, "the install proceeded with a probe the router answers itself")
        message = result.error or ""
        self.assertIn(FORCE_ECH, message, "the refusal has to name the file that causes it")
        self.assertIn(INSTALL_PROBE_NAME, message, "and the entry in it")
        self.assertIn("force", message.lower())
        self.assertIn("ECH", message, "and say that the entry is a force-ECH entry")
        self.assertTrue(
            any(word in message.lower() for word in ("remove", "delete")),
            "and name the remedy; a refusal that only names the cause leaves the operator guessing",
        )
        self.assertIsNone(result.rollback_error, "nothing had been mutated to roll back")
        self.assertNothingChanged("the machine was changed despite a locally-answered probe")
        self.assertFalse(self.rooted(BACKUP_PATH).exists())
        self.assertFalse(self.rooted(MANAGED_BY).exists())

    def test_the_refusal_matches_the_plugins_rule_exactly(self):
        # cdn_rewrite's forcesECH is an EXACT case-insensitive match on the
        # canonical name with the trailing dot trimmed -- no suffix, no wildcard --
        # so a mirror that matched loosely would either refuse installs that are
        # fine or, worse, think it had covered a name the plugin does not match.
        for entry, refused in (
            (INSTALL_PROBE_NAME, True),
            (INSTALL_PROBE_NAME.upper(), True),
            (f"  {INSTALL_PROBE_NAME}  ", True),
            (f"{INSTALL_PROBE_NAME}.", True),
            # Neither of these is a match for an exact comparison, and treating
            # either as one would refuse a machine the plugin would answer
            # downstream like any other name.
            ("example", False),
            (f"cdn.{INSTALL_PROBE_NAME}", False),
            (INSTALL_PROBE_NAME.replace("install-", "x"), False),
        ):
            with self.subTest(entry=entry, refused=refused):
                self.setUp()
                self.force_ech(entry)
                result = self.run_install()
                self.assertEqual(
                    not result.ok,
                    refused,
                    f"an entry of {entry!r} should {'refuse' if refused else 'not refuse'}, and the "
                    "plugin matches the canonical name exactly and case-insensitively",
                )

    def test_a_comment_only_list_is_the_normal_case_and_changes_nothing(self):
        # The shipped list is comments, and a list whose every line is a comment is
        # the state a fresh installation is in. The check must be quiet there, or
        # it would refuse every install.
        self.force_ech()
        self.install_succeeds()

    def test_an_absent_list_changes_nothing(self):
        self.install_succeeds()

    def test_a_name_on_the_list_under_fallback_is_not_refused(self):
        # failure_policy: fallback means the plugin does not short circuit, so
        # the same list is harmless. A check that ignored the policy would refuse
        # a machine the plugin answers downstream.
        self.force_ech(INSTALL_PROBE_NAME)
        self.policy(failure="fallback")
        self.install_succeeds()

    def test_a_name_on_the_list_with_ech_disabled_is_not_refused(self):
        self.force_ech(INSTALL_PROBE_NAME)
        self.policy(enabled="false")
        self.install_succeeds()

    def test_a_policy_with_no_ech_section_is_the_risky_default(self):
        # internal/config's defaults are Enabled true and FailurePolicy strict, and
        # the plugin's failurePolicyOf maps anything but "fallback" to FailClosed.
        # So a policy that says nothing is the case the check must catch, not skip.
        self.force_ech(INSTALL_PROBE_NAME)
        self.write(POLICY_CONFIG, "schema_version: 1\ncdn:\n  provider: cloudflare\n")
        result = self.run_install()
        self.assertFalse(result.ok, "a silent policy was read as the safe one rather than the default")

    def test_the_check_costs_no_command_and_runs_before_the_capture(self):
        # The first version of this case compared `full_sequence()` with itself,
        # which is a literal compared with a literal: it would have passed with the
        # guard issuing a command per file it read. So the comparison is against
        # what the runner ACTUALLY recorded, and against the literal half of it
        # that a refused transaction can legitimately reach.
        #
        # Two properties, and they are separate. "Costs no command" is that the
        # guard added nothing to the sequence a successful install runs, which is
        # checked against the full literal. "Runs before the capture" is that the
        # refusal is literal about changing nothing -- the capture publishes a
        # state and a generation, so a guard after it could not say so -- and it is
        # checked against the recorded commands being preflight's reads and no
        # more.
        before = self.full_sequence()
        self.force_ech(INSTALL_PROBE_NAME)
        result = self.run_install()
        self.assertFalse(result.ok)
        self.assertEqual(
            self.full_sequence(),
            before,
            "the refusal added a step to the sequence, so every order assertion in this file is "
            "written against a sequence that no longer exists",
        )
        self.assertEqual(
            self.commands,
            self.preflight_commands(),
            "a refused run issued commands beyond preflight's own reads, so the refusal's "
            "'nothing has been changed' is not literally true -- the capture publishes a state and "
            "a generation, so a check that runs after it has changed something",
        )
        self.assertNotIn(capture_command(), self.commands, "the capture ran before the guard refused")


class MarkerTests(TransactionFixture):
    """The marker is the claim uninstall reads, so it is written last or not at all."""

    def test_the_marker_is_written_only_after_everything_else(self):
        self.install_succeeds()
        marker = self.rooted(MANAGED_BY)
        self.assertEqual(marker.read_text(encoding="utf-8"), MANAGED_BY_VALUE + "\n")
        self.assertEqual(stat.S_IMODE(marker.lstat().st_mode), 0o600)
        # Nothing is left to do after the marker, so a transaction that wrote it
        # and then mutated something would have left a claim it had not finished
        # earning.
        self.assertEqual(
            self.commands[-1],
            ("resolvectl", "dns", DEVICE),
            "a command ran after the ownership marker was written",
        )

    def test_no_failure_before_the_health_check_leaves_a_marker(self):
        for failing in (
            ("systemctl", "enable", RESOLVER_UNIT),
            ("systemctl", "start", RESOLVER_UNIT),
            ("systemctl", "start", ROUTER_UNIT),
            MODIFY + (UUID, "ipv6.ignore-auto-dns", "yes"),
            ("resolvectl", "dns", DEVICE),
        ):
            with self.subTest(failing=failing):
                self.setUp()
                result = self.run_install(fail=[failing])
                self.assertFalse(result.ok, f"a failure at {failing!r} did not fail the install")
                self.assertFalse(
                    self.rooted(MANAGED_BY).exists(),
                    f"a failed install left an ownership marker behind ({failing!r}); an uninstall "
                    "would then believe the changes on this machine are ours",
                )

    def test_a_marker_that_cannot_be_written_undoes_the_whole_install(self):
        # The marker is the last thing the transaction does, so a failure to write
        # it is the worst-timed failure there is: everything is applied, and the
        # one step that would have claimed it is refused. A directory at the
        # marker's path is a real condition the write cannot survive, and the
        # rollback has to take the whole transaction back down.
        self.setUp()
        marker = self.rooted(MANAGED_BY)
        marker.mkdir(parents=True)
        result = self.run_install()
        self.assertFalse(result.ok, "a marker that could not be written was reported as installed")
        self.assertIn(MANAGED_BY, result.error or "")
        self.assertIsNone(result.rollback_error, "the rollback did not complete")
        self.assertFalse(marker.is_file(), "the marker was written over a path that is not a file")
        self.assertEqual(
            self.commands[self.commands.index(("resolvectl", "dns", DEVICE)) + 1 :],
            self.expected_rollback(("resolvectl", "dns", DEVICE)),
            "a failed marker write left the machine pointed at the loopback",
        )
        self.assertIn(("systemctl", "stop", ROUTER_UNIT), self.commands)
        self.assertIn(MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM), self.commands)

    def test_the_marker_step_has_an_undo_that_puts_back_what_was_there(self):
        # The marker's undo is the one rollback action the transaction of today can
        # never reach, because the marker is the last step and nothing follows it.
        # It exists for the step that will be added after it, so it is exercised
        # here directly: a future edit that drops it removes the only thing that
        # would un-claim the machine, and no other case here would notice.
        self.setUp()
        path = self.rooted(MANAGED_BY)
        self.write(MANAGED_BY, MANAGED_BY_VALUE + "\n", mode=0o600)
        transaction = installer.Transaction()
        installer._commit_marker(self.root, transaction)
        self.assertEqual(path.read_text(encoding="utf-8"), MANAGED_BY_VALUE + "\n")
        self.assertEqual(transaction.rollback(), [])
        self.assertEqual(
            path.read_text(encoding="utf-8"),
            MANAGED_BY_VALUE + "\n",
            "the undo of the marker removed a marker belonging to a router that is still installed",
        )

        path.unlink()
        transaction = installer.Transaction()
        installer._commit_marker(self.root, transaction)
        self.assertTrue(path.exists())
        self.assertEqual(transaction.rollback(), [])
        self.assertFalse(path.exists(), "the undo of a marker that was not there left it behind")

    def test_a_rollback_restores_the_marker_that_was_there_before(self):
        # A re-install finds the previous installation's marker. Failing the new
        # one has to put that marker back, not remove it: the router it claims is
        # still installed and still running.
        self.setUp()
        marker = self.write(MANAGED_BY, MANAGED_BY_VALUE + "\n", mode=0o600)
        result = self.run_install(fail=[("systemctl", "start", ROUTER_UNIT)])
        self.assertFalse(result.ok)
        self.assertEqual(
            marker.read_text(encoding="utf-8"),
            MANAGED_BY_VALUE + "\n",
            "the previous installation's marker was removed by a failed re-install",
        )

    def test_a_preflight_never_writes_the_marker(self):
        self.build_state_directories(mode="2777")
        answers = {
            STAT_FIELDS + (str(self.rooted(relative)),): f"2777 root mosdns {stat.S_IFDIR | 0o2777:x}"
            for relative in STATE_DIRECTORIES
        }
        installer.install(self.root, self.good_runner(outputs=answers), clock=self.clock, probe=self.probe_for())
        self.assertFalse(self.rooted(MANAGED_BY).exists())


class ReinstallTests(TransactionFixture):
    """What a SECOND install must not forget: the first install's recorded values.

    This is the whole of a re-install, and it is one property: the ``original``
    block is a record of the machine, not of a run. Once this package has taken
    the machine's DNS over, the connection's three properties hold ``yes``/``yes``/
    ``127.0.0.1`` -- THIS package's values -- so a second install that re-reads
    them and writes them over the record has destroyed the only copy of what the
    machine actually had. The removal that follows then writes the loopback back,
    reactivates, stops both units, and reports that the connection is back on the
    machine's own resolvers.

    The three cases are the same property seen from the three places the record is
    read, because one of them fixing it is not the property:

      * the backup file itself, after the second install;
      * ``uninstall``, which is what ``prerm remove`` runs;
      * ``emergency-rollback``, on the same re-installed machine.
    """

    # The device the fake machine reports. It is the LOOPBACK for the whole of
    # these cases, including after a restore, and that is deliberate: it models
    # the real failure `_device_follows_the_backup` exists to catch -- a
    # NetworkManager that accepted the profile writes and did not apply them to
    # the device. The interesting consequence is the direction the two versions
    # differ in, and it is asserted below rather than assumed.
    def later_clock(self):
        import datetime

        return datetime.datetime(2026, 10, 4, 11, 5, tzinfo=datetime.timezone.utc)

    def upgrade(self, **kwargs):
        """Run a second install on a machine this package has already installed.

        A LATER clock and a DIFFERENT package version, because the two are the
        volatile half of the carry-forward and a test that kept them identical
        could not tell a carry-forward from a refusal to re-run.
        """
        kwargs.setdefault("clock", self.later_clock)
        kwargs.setdefault("outputs", {PACKAGE_VERSION_COMMAND: "1.5.0\n"})
        return self.run_install(already_installed=True, **kwargs)

    def recorded(self):
        return json.loads(self.rooted(BACKUP_PATH).read_text(encoding="utf-8"))

    def test_a_reinstall_refuses_to_replace_a_record_it_cannot_read(self):
        # The marker says this machine is already ours and the record cannot be
        # read. The only values left to write down are this package's own, so the
        # one thing the install must not do is manufacture a record out of them.
        self.install_succeeds()
        self.rooted(BACKUP_PATH).unlink()
        result = self.upgrade()
        self.assertFalse(result.ok, "a re-install with no record to keep reported success")
        self.assertIn(BACKUP_PATH, result.error or "")
        self.assertIn("127.0.0.1", result.error or "")
        self.assertFalse(
            self.rooted(BACKUP_PATH).exists(),
            "the refused re-install wrote a record built from this package's own values",
        )
        self.assertNothingChanged("a refused re-install")

    def test_a_reinstall_refuses_when_the_record_belongs_to_another_connection(self):
        # One record describes one connection, and both the uninstall and the
        # emergency rollback restore the connection it names. A re-install working
        # on a second one has to say so rather than replace the first record and
        # leave that connection pointed at the loopback with nothing to put back.
        self.install_succeeds()
        before = self.recorded()
        self.write(POLICY_CONFIG, POLICY_BODY + "# an operator edit\n")
        second = {
            NMCLI_CONNECTIONS: f"{CONNECTION_NAME}:{OTHER_UUID}:802-3-ethernet:{DEVICE}\n",
            NMCLI_DEVICE_UUID: f"{OTHER_UUID}\n",
        }
        for prop, value in (
            ("ipv4.ignore-auto-dns", "no"),
            ("ipv6.ignore-auto-dns", "no"),
            ("ipv4.dns", DHCP_UPSTREAM),
            ("ipv6.dns", ""),
        ):
            second[DNS_UUID_PREFIX + (prop, "connection", "show", OTHER_UUID)] = value + "\n"
        result = self.run_install(already_installed=True, outputs=second)
        self.assertFalse(result.ok, "a re-install replaced a record about a different connection")
        self.assertIn(OTHER_UUID, result.error or "")
        self.assertIn(UUID, result.error or "")
        self.assertEqual(self.recorded(), before, "the record about the first connection was replaced")
        self.assertNothingChanged("a refused re-install onto a second connection")

    def test_the_second_connection_refusal_offers_a_removal_that_can_actually_be_run(self):
        """The advice this arm used to give could not be carried out in the state the arm
        routes to.

        It said "Remove this package (which restores … through the record that is
        already there) and install it again". A record PRESENT with no MARKER is
        exactly where `uninstall` refuses -- exit 5, `EXIT_OWNERSHIP_REFUSED` -- and
        `prerm` turns a non-zero uninstall into a dpkg abort, so the removal the arm
        names is the one operation that cannot happen. It is the state an install
        that failed after `_apply_nm` leaves behind, which is why the sibling
        refusal (a record that cannot be read) already offers
        `dpkg --force-remove-reinstreq`: the forced removal skips the refusal and
        takes the package's own advice about the connection with it.

        Asserted as the command being NAMED rather than as prose around it, because
        the command is the deliverable and the sentence is only how it is carried.
        """
        self.install_succeeds()
        self.write(POLICY_CONFIG, POLICY_BODY + "# an operator edit\n")
        second = {
            NMCLI_CONNECTIONS: f"{CONNECTION_NAME}:{OTHER_UUID}:802-3-ethernet:{DEVICE}\n",
            NMCLI_DEVICE_UUID: f"{OTHER_UUID}\n",
        }
        for prop, value in (
            ("ipv4.ignore-auto-dns", "no"),
            ("ipv6.ignore-auto-dns", "no"),
            ("ipv4.dns", DHCP_UPSTREAM),
            ("ipv6.dns", ""),
        ):
            second[DNS_UUID_PREFIX + (prop, "connection", "show", OTHER_UUID)] = value + "\n"
        result = self.run_install(already_installed=True, outputs=second)
        error = result.error or ""
        self.assertIn("dpkg --force-remove-reinstreq", error)
        # The plain removal it used to name is what this state cannot do, so saying
        # "remove this package" without saying WHICH removal is the false advice.
        self.assertNotIn(
            "Remove this package (which restores", error,
            "the refusal still tells the operator to remove the package, without naming the "
            "forced removal the state requires",
        )
        # And the sibling refusal offers the same escape hatch, so an operator who
        # has read one has read the other's remedy. It is reached by making the
        # record present and the marker absent, which is what a failed install
        # leaves behind; `RecordWithoutMarkerTests` builds that state for real and
        # this only asks whether the two refusals agree about the way out.
        self.install_succeeds()
        self.setUp()
        self.write(BACKUP_PATH, "{ not json")
        self.write(MANAGED_BY, f"installed-by={MANAGED_BY_VALUE}\n", mode=0o644)
        result = self.run_install(already_installed=True)
        self.assertFalse(result.ok)
        self.assertIn("not a record this program can read", result.error or "")
        self.assertIn("dpkg --force-remove-reinstreq", result.error or "")

    def test_the_second_install_keeps_the_first_installs_recorded_values(self):
        first = self.install_succeeds()
        self.assertIsNotNone(first.backup)
        before = self.recorded()

        self.events = []
        result = self.upgrade()
        self.assertTrue(result.ok, f"a re-install on an installed machine failed: {result.error}")
        after = self.recorded()

        self.assertEqual(
            after["original"],
            before["original"],
            "the second install rewrote the record of what the machine had, from the values "
            "this package itself had just set",
        )
        # And the volatile half DID move, so this is a carry-forward and not a
        # refusal to re-run: a backup that still claims the first release wrote
        # it is a backup an operator cannot match against the release they are
        # removing.
        self.assertNotEqual(after["created_at"], before["created_at"])
        self.assertNotEqual(after["package_version"], before["package_version"])
        self.assertEqual(after["dhcp"], before["dhcp"], "the lease is re-read on every install")

    def test_the_uninstall_after_a_reinstall_restores_the_first_installs_values(self):
        self.install_succeeds()
        before = self.recorded()
        self.assertTrue(self.upgrade().ok)

        self.events = []
        result = installer.uninstall(self.root, self.good_runner(already_installed=True), probe=self.probe_for())
        restored = [command[4:] for command in self.commands if command[:3] == MODIFY]
        self.assertEqual(
            sorted(restored),
            sorted(
                (
                    (prop, before["original"][prop]["raw"] or "''")
                    for prop in ("ipv4.dns", "ipv4.ignore-auto-dns", "ipv6.ignore-auto-dns")
                ),
            ),
            "the uninstall after a re-install did not put the FIRST install's recorded values back",
        )
        # The device still reports the loopback this run took away from it -- the
        # failure mode above -- and the recorded original does not contain it, so
        # the check that guards the machine's resolver must refuse and the units
        # must still be running. On the broken version the re-install had recorded
        # the loopback as the machine's own, so the check passed and both units
        # were stopped on a machine whose DNS pointed at a process that had gone.
        self.assertFalse(result.ok, "the device check did not refuse a machine still on the loopback")
        self.assertIn(LOCAL_DNS, (result.error or "") + (result.manual_recovery or ""))
        for unit in (ROUTER_UNIT, RESOLVER_UNIT):
            with self.subTest(unit=unit):
                self.assertNotIn(
                    ("systemctl", "stop", unit),
                    self.commands,
                    f"{unit} was stopped while the device was still using {LOCAL_DNS}",
                )

    def test_the_emergency_rollback_after_a_reinstall_restores_the_first_installs_values(self):
        self.install_succeeds()
        before = self.recorded()
        self.assertTrue(self.upgrade().ok)

        self.events = []
        result = installer.emergency_rollback(
            self.root, self.good_runner(already_installed=True), probe=self.probe_for()
        )
        restored = [command[4:] for command in self.commands if command[:3] == MODIFY]
        self.assertEqual(
            sorted(restored),
            sorted(
                (
                    (prop, before["original"][prop]["raw"] or "''")
                    for prop in ("ipv4.dns", "ipv4.ignore-auto-dns", "ipv6.ignore-auto-dns")
                )
            ),
            "the emergency rollback on a re-installed machine did not put the FIRST install's "
            "recorded values back",
        )
        self.assertIn(LOCAL_DNS, (result.error or "") + (result.manual_recovery or ""))
        self.assertFalse(result.ok, "the rollback reported success on a device still on the loopback")


class RecordWithoutMarkerTests(TransactionFixture):
    """A record and NO marker: the state the carry-forward must be gated on.

    `ReinstallTests` reaches its state by installing twice, which leaves a marker,
    and the carry-forward is gated on that marker. The marker is a claim about the
    INSTALL -- it is written last, after the health check and the verification --
    and it is absent in exactly one state that matters more than the upgrade: a
    machine whose install got as far as recording, changed the connection, and
    then failed with a rollback that did not finish. That machine has a RECORD
    saying what it had, NO marker, and a connection still handing resolved the
    loopback address, because the restore is one of the undos that failed.

    The routine retry from there is `dpkg --configure mosdns-router`, which dpkg
    offers on its own after a failed configure. It re-reads the connection --
    which holds `yes`/`yes`/`127.0.0.1`, this package's own values -- and, on the
    version before the fix, wrote them over the record and succeeded. The next
    removal then restored the loopback, stopped both units and printed `ok=True`.
    That is the Critical from `final-review-findings.md` reached by the ordinary
    retry path, and gating on the marker is what let it through.

    The state is produced HONESTLY here -- by a real install whose rollback fails
    -- rather than by deleting the marker, because the marker being absent is
    supposed to be a fact about the ORDER and a test that arranges it by hand
    cannot tell whether the order still produces it.
    """

    # The two commands that fail. The first is the ROLLBACK's own restore of
    # `ipv4.dns`, which is a different argument array from the install's
    # `ipv4.dns 127.0.0.1` -- the forward write succeeds, the restore does not,
    # and the profile is left pointing at the loopback. The second is the
    # reactivation, so the device never picks the recorded values up either.
    UNRESTORABLE = (MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM), CONNECTION_UP + (UUID,))

    def failed_rollback(self):
        """Get this machine into record-without-marker and the connection on the loopback."""
        result = self.run_install(fail=list(self.UNRESTORABLE))
        self.assertFalse(result.ok, "an install with two failing undos reported success")
        self.assertIsNotNone(
            result.rollback_error,
            "the install was supposed to fail its ROLLBACK, and a clean refusal would leave the "
            "connection restored and the case testing nothing",
        )
        self.assertTrue(
            self.rooted(BACKUP_PATH).exists(),
            "a failed rollback removed the record of what the machine had, which is the whole "
            "thing the next install would have to keep",
        )
        self.assertFalse(
            self.rooted(MANAGED_BY).exists(),
            "this case is about a machine with a record and NO marker, and the install left a "
            "marker behind",
        )
        return self.recorded()

    def later_clock(self):
        import datetime

        return datetime.datetime(2026, 10, 4, 11, 5, tzinfo=datetime.timezone.utc)

    def recorded(self):
        return json.loads(self.rooted(BACKUP_PATH).read_text(encoding="utf-8"))

    def retry(self, **kwargs):
        """The routine retry: a second install on a machine now reading `ALREADY_OURS`."""
        kwargs.setdefault("clock", self.later_clock)
        kwargs.setdefault("outputs", {PACKAGE_VERSION_COMMAND: "1.5.0\n"})
        return self.run_install(already_installed=True, **kwargs)

    def test_a_reinstall_keeps_the_record_of_a_machine_that_has_no_marker(self):
        before = self.failed_rollback()
        self.assertEqual(
            before["original"]["ipv4.dns"]["raw"],
            DHCP_UPSTREAM,
            "the record this case builds its argument from does not hold the machine's own resolver",
        )
        result = self.retry()
        self.assertTrue(result.ok, f"the routine retry failed: {result.error}")
        after = self.recorded()
        self.assertEqual(
            after["original"],
            before["original"],
            "the retry rewrote the record of what the machine had, from the values this package "
            "itself had just set",
        )
        for prop in ("ipv4.ignore-auto-dns", "ipv6.ignore-auto-dns", "ipv4.dns"):
            with self.subTest(prop=prop):
                self.assertNotIn(
                    LOCAL_DNS,
                    str(after["original"][prop]["value"]),
                    f"the loopback is in the record of the machine's own {prop}, so the next "
                    "removal would put it back and stop the resolver",
                )
        # And the volatile half moved, so this is a carry-forward and not a refusal:
        # a refusal would be a different (also correct) answer, and the two must not
        # be able to stand in for each other in a test.
        self.assertNotEqual(after["created_at"], before["created_at"])
        self.assertNotEqual(after["package_version"], before["package_version"])

    def test_the_uninstall_after_that_retry_restores_the_machine_and_the_device_check_refuses(self):
        before = self.failed_rollback()
        self.assertTrue(self.retry().ok)

        self.events = []
        result = installer.uninstall(
            self.root, self.good_runner(already_installed=True), probe=self.probe_for()
        )
        restored = [command[4:] for command in self.commands if command[:3] == MODIFY]
        self.assertEqual(
            sorted(restored),
            sorted(
                (
                    (prop, before["original"][prop]["raw"] or "''")
                    for prop in ("ipv4.dns", "ipv4.ignore-auto-dns", "ipv6.ignore-auto-dns")
                )
            ),
            "the uninstall did not put the machine's OWN recorded values back",
        )
        # The fake device still reports the loopback this run took away from it, so
        # the check that guards the machine's resolver has to REFUSE and the units
        # have to still be running. On the version before the fix the record held
        # the loopback, so the check passed and both units were stopped on a
        # machine whose DNS pointed at a process that had gone.
        self.assertFalse(result.ok, "the device check did not refuse a machine still on the loopback")
        self.assertIn(LOCAL_DNS, (result.error or "") + (result.manual_recovery or ""))
        for unit in (ROUTER_UNIT, RESOLVER_UNIT):
            with self.subTest(unit=unit):
                self.assertNotIn(
                    ("systemctl", "stop", unit),
                    self.commands,
                    f"{unit} was stopped while the device was still using {LOCAL_DNS}",
                )

    def test_the_uninstall_refuses_a_record_without_a_marker_before_the_retry(self):
        # The same machine one step earlier, and it is a separate assertion because
        # it is a different fact: with no marker there is no claim, so the restore
        # is refused outright and nothing at all is written. The retry is what makes
        # the case above reachable, and a reader who only saw the case above would
        # not know this one had to give way.
        self.failed_rollback()
        self.events = []
        result = installer.uninstall(
            self.root, self.good_runner(already_installed=True), probe=self.probe_for()
        )
        self.assertFalse(result.ok, "a machine with a record and no marker reported a clean removal")
        self.assertFalse(
            [command for command in self.commands if command[:3] == MODIFY],
            "a refused uninstall wrote to the connection anyway",
        )
        self.assertIn(MANAGED_BY, " ".join(result.refusals))

    def test_a_reinstall_refuses_a_record_it_can_read_the_file_of_but_not_the_fields(self):
        # Present but damaged is not absent. A record whose file is there and whose
        # contents are not usable is a machine whose original is UNKNOWN, and writing
        # a fresh document would replace an unknown with this package's own values --
        # so it refuses, and it says which part of the record is missing rather
        # than only that the record is not usable.
        before = self.failed_rollback()
        damaged = self.recorded()
        del damaged["original"]["ipv4.dns"]
        self.rooted(BACKUP_PATH).write_text(
            json.dumps(damaged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        result = self.retry()
        self.assertFalse(result.ok, "a re-install over a damaged record reported success")
        self.assertIn(
            "ipv4.dns",
            result.error or "",
            f"the refusal does not name what is missing from the record: {result.error!r}",
        )
        self.assertEqual(
            self.recorded()["original"],
            damaged["original"],
            "the refused re-install overwrote a record it had just said it could not read",
        )
        self.assertNotEqual(
            self.recorded()["original"],
            before["original"],
            "the damaged record is the one under test, and this says the test did not set it up",
        )
        self.assertNothingChanged("a re-install refused over a damaged record")


class FailureMessageTests(TransactionFixture):
    """What a failing command says, as opposed to what it exits with.

    `subprocess.CalledProcessError`'s own `str()` is
    ``Command '[...]' returned non-zero exit status N``, which names the array and
    the number and nothing else. The reason is on standard error, and the most
    likely install-time failure in the field is a tool explaining itself there --
    `update-lists --refresh-ranges` refusing because the origin is unreachable and
    no cache envelope is seeded reaches the operator as
    "publishing the Cloudflare prefix list ... failed: Command '[...]' returned
    non-zero exit status 3", which says what this program was doing and gives the
    operator nothing to act on.

    The detail is BOUNDED, because the alternative to a bounded message is a
    thousand-line log pasted into a `prerm` output an operator has to read on a
    machine with no DNS.
    """

    REFUSAL = (
        "mosdns-cdnctl: refusing to publish the prefix list: the origin is unreachable and no "
        "cache envelope is seeded (origin https://example.invalid/list.txt)"
    )

    def test_a_failing_command_says_what_it_printed(self):
        result = self.run_install(
            fail=[PUBLISH_PREFIXES],
            stderr=self.REFUSAL + "\n",
        )
        self.assertFalse(result.ok)
        self.assertIn(self.REFUSAL, result.error or "", "the command's own words were dropped")

    def test_the_operator_sees_it_and_not_only_the_transaction(self):
        # `main` prints `result.error` to standard error, and `prerm` reads THAT.
        # A detail that reached the result but not the process's output would help
        # a test and not a person.
        self.setUp()
        status, _out, err = self.install_cli(
            runner=self.good_runner(fail=[PUBLISH_PREFIXES], stderr=self.REFUSAL + "\n")
        )
        self.assertEqual(status, installer.EXIT_INSTALL_FAILED, err)
        self.assertIn(self.REFUSAL, err)

    def test_a_command_that_only_printed_on_standard_output_still_says_something(self):
        # Some tools report a refusal on stdout. Bounded output is the fallback,
        # and it is a fallback rather than a silence because a message that names
        # nothing is what this whole item is about.
        result = self.run_install(
            outputs={PUBLISH_PREFIXES: "refusing: no envelope and no network\n"},
            returncodes={PUBLISH_PREFIXES: 3},
        )
        self.assertFalse(result.ok)
        self.assertIn("refusing: no envelope and no network", result.error or "")

    def test_the_detail_is_bounded(self):
        noise = "\n".join(f"line {index} of a very long explanation" for index in range(200))
        result = self.run_install(fail=[PUBLISH_PREFIXES], stderr=noise + "\n")
        message = result.error or ""
        self.assertIn("line 199 of a very long explanation", message, "the LAST line is the one that says why")
        self.assertNotIn("line 0 of a very long explanation", message, "an unbounded paste is not a message")
        self.assertLess(len(message), 2000, f"the message grew to {len(message)} characters")

    def test_a_failure_with_nothing_to_say_still_names_the_step(self):
        result = self.run_install(fail=[("systemctl", "start", ROUTER_UNIT)])
        self.assertFalse(result.ok)
        self.assertIn("starting " + ROUTER_UNIT, result.error or "")


class FakeUnitModelTests(unittest.TestCase):
    """The FAKE's own fidelity, held against `systemctl`'s own description.

    The whole of the Important is one sentence in `systemctl --help`: "try-restart
    UNIT... Restart one or more units if active". A test that asserts the state a
    rollback achieves is only as good as the fake's answer to that sentence, and
    this fake had no state at all until this round -- so a suite that now depends
    on the state has to hold the fake to the manual it is standing in for. A gate
    on a fake that could not model the defect is a gate that could not have
    failed.

    WHAT IS HELD, so this class is a list of what it covers rather than a list of
    what it intends: `try-restart` on an active unit, and on each of the three
    states a failed start leaves; `start` succeeding from a stopped or failed unit
    and failing from any of them; `stop` succeeding and failing; `start` on a
    running unit not stopping it; `is-active` answering from the model and the
    canned answer for a unit nobody modelled; and a string command still refused.
    The four verbs `FakeRunner._transition` models -- `try-restart`, `start`,
    `restart` and `stop` -- are therefore each covered, but not each in both
    directions: `start` and `stop` have a succeeding and a failing case, and
    `try-restart` and `restart` are covered succeeding only, because a case that
    injects a failing `try-restart` or a failing `restart` does not exist here.
    """

    def runner(self, **kwargs):
        return FakeRunner(**kwargs)

    def modelled(self, state, **kwargs):
        return FakeRunner(unit_state={ROUTER_UNIT: state}, **kwargs)

    def test_try_restart_stops_and_starts_a_unit_that_is_active(self):
        runner = self.modelled(UNIT_RUNNING)
        runner.run(list(TRY_RESTART + (ROUTER_UNIT,)))
        self.assertEqual(runner.unit_state[ROUTER_UNIT], UNIT_RUNNING)
        self.assertTrue(runner.running(ROUTER_UNIT))

    def test_try_restart_on_a_unit_that_is_not_running_does_nothing_and_succeeds(self):
        """The three states a failed start leaves, and the trap is in all three."""
        for state in (UNIT_FAILED, UNIT_STOPPED, "activating"):
            with self.subTest(state=state):
                runner = self.modelled(state)
                completed = runner.run(list(TRY_RESTART + (ROUTER_UNIT,)))
                self.assertEqual(
                    completed.returncode, 0,
                    "try-restart on a unit that is not running exits non-zero, and the undo of a "
                    "failed restart would then be a rollback FAILURE rather than a silent no-op",
                )
                self.assertEqual(
                    runner.unit_state[ROUTER_UNIT], state,
                    "try-restart did something to a unit that is not running, which is the one "
                    "thing the manual says it does not do",
                )

    def test_start_brings_a_stopped_unit_up_and_its_failure_leaves_it_failed(self):
        for state in (UNIT_FAILED, UNIT_STOPPED):
            with self.subTest(state=state, action="succeeds"):
                runner = self.modelled(state)
                runner.run(list(START + (ROUTER_UNIT,)))
                self.assertEqual(runner.unit_state[ROUTER_UNIT], UNIT_RUNNING)
        for state in (UNIT_FAILED, UNIT_STOPPED, UNIT_RUNNING):
            with self.subTest(state=state, action="fails"):
                runner = self.modelled(state, fail=[START + (ROUTER_UNIT,)])
                with self.assertRaises(subprocess.CalledProcessError):
                    runner.run(list(START + (ROUTER_UNIT,)))
                self.assertEqual(
                    runner.unit_state[ROUTER_UNIT], UNIT_FAILED,
                    "a start that failed did not leave the unit failed, so a rollback that could "
                    "not bring it back would be reported as one that did",
                )

    def test_stop_takes_a_running_unit_down_and_a_failure_leaves_it_running(self):
        """`stop` is in this model's vocabulary and in `UNDO_OF`, and until now
        nothing here held the fake to it.

        The report and this class's own class-docstring both listed `stop` among the
        `systemctl` semantics the class holds, and neither said so was true: the
        other four verbs had a case each and this one did not. So the claim was
        either true and unheld or false, and a class whose docstring is a list of
        what it holds needs the list to be what it holds.

        Both directions, because a `stop` that succeeded while leaving the unit
        running would make the rollback of a `start` -- the two rows in `UNDO_OF` that
        use it -- a rollback that put nothing back and said it had.
        """
        for state in (UNIT_RUNNING, UNIT_FAILED, UNIT_STOPPED):
            with self.subTest(state=state, action="succeeds"):
                runner = self.modelled(state)
                runner.run(list(STOP + (ROUTER_UNIT,)))
                self.assertEqual(
                    runner.unit_state[ROUTER_UNIT], UNIT_STOPPED,
                    "a `stop` that succeeded did not take a unit down, so a rollback that stops a "
                    "unit this run started is reported as having put the machine back",
                )
        for state in (UNIT_RUNNING, UNIT_STOPPED):
            with self.subTest(state=state, action="fails"):
                runner = self.modelled(state, fail=[STOP + (ROUTER_UNIT,)])
                with self.assertRaises(subprocess.CalledProcessError):
                    runner.run(list(STOP + (ROUTER_UNIT,)))
                self.assertEqual(
                    runner.unit_state[ROUTER_UNIT], UNIT_RUNNING,
                    "a `stop` that failed left the unit stopped, so a rollback that could not "
                    "stop a unit is indistinguishable from one that did",
                )

    def test_start_on_a_running_unit_is_a_no_op_that_does_not_stop_it(self):
        """The reason `start` and not `restart`: an undo built from `restart` can stop
        the very resolver it is repairing."""
        runner = self.modelled(UNIT_RUNNING)
        runner.run(list(START + (ROUTER_UNIT,)))
        self.assertEqual(runner.unit_state[ROUTER_UNIT], UNIT_RUNNING)
        restarted = self.modelled(UNIT_RUNNING)
        restarted.run(list(("systemctl", "restart", ROUTER_UNIT)))
        # `restart` also ends with the unit running, so the two are indistinguishable
        # from the FINAL state. Nothing here injects a FAILING `restart` -- a failure
        # is injected for `start` and for `stop` only, and this class's docstring
        # says which of the four verbs have both directions rather than a comment
        # here claiming a case that is not below it.
        self.assertEqual(restarted.unit_state[ROUTER_UNIT], UNIT_RUNNING)

    def test_is_active_answers_from_the_model_and_a_unit_nobody_named_keeps_its_answer(self):
        canned = ("systemctl", "is-active", ROUTER_UNIT)
        modelled = self.runner(
            outputs={canned: "inactive\n"}, unit_state={ROUTER_UNIT: UNIT_RUNNING}
        )
        self.assertEqual(
            modelled.run(list(("systemctl", "is-active", ROUTER_UNIT))).stdout, "active\n",
            "a modelled unit's state does not answer `is-active`, so a test that arranges a "
            "state has not arranged what the transaction READS",
        )
        unmodelled = self.runner(outputs={canned: "inactive\n"})
        self.assertEqual(
            unmodelled.run(list(("systemctl", "is-active", ROUTER_UNIT))).stdout, "inactive\n",
            "a unit nobody modelled stopped answering its canned answer",
        )
        self.assertIsNone(unmodelled.running(ROUTER_UNIT))

    def test_a_string_is_still_refused(self):
        with self.assertRaises(TypeError):
            self.runner().run("systemctl start x")


class FailureInjectionTests(TransactionFixture):
    """A failure after each mutation, and what the rollback put back."""

    def run_install_failing_at(self, row, **kwargs):
        """Run the install with ``row``'s command failing, the way that command fails.

        The steps whose undo is registered BEFORE the attempt are failed with
        `fail_first` -- the first call fails, the rollback's retry succeeds -- and
        `fail` would fail both, which is a different machine and has its own test.
        The machine is whichever one ``row`` asks for, because two of the commands
        in the table are only reachable on one of them.
        """
        if row.already_running:
            self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
        if row.failing in self.UNDO_REGISTERED_FIRST:
            return self.run_install(fail_first=[row.failing], **kwargs)
        return self.run_install(fail=[row.failing], **kwargs)

    def injection_points(self):
        """Every command after which something can go wrong, in order.

        Each entry names a command whose failure the transaction has to survive and
        the machine it is reachable on, and the cases below assert the whole
        rollback for it. The list is the sequence's own commands, so a new step in
        the transaction shows up here.

        The two `try-restart` rows are why a row is a row and not a bare command:
        a first install never issues them, because the units are not running yet, so
        a row naming one without saying which machine it is on would be a row whose
        command never ran and whose assertions nothing.
        """
        return [
            Injection(("systemctl", "enable", RESOLVER_UNIT)),
            Injection(("systemctl", "enable", ROUTER_UNIT)),
            Injection(PUBLISH_PREFIXES),
            Injection(("systemctl", "start", RESOLVER_UNIT)),
            Injection(("systemctl", "start", ROUTER_UNIT)),
            Injection(TRY_RESTART + (RESOLVER_UNIT,), already_running=True),
            Injection(TRY_RESTART + (ROUTER_UNIT,), already_running=True),
            Injection(MODIFY + (UUID, "ipv4.ignore-auto-dns", "yes")),
            Injection(MODIFY + (UUID, "ipv6.ignore-auto-dns", "yes")),
            Injection(MODIFY + (UUID, "ipv4.dns", LOCAL_DNS)),
            Injection(CONNECTION_UP + (UUID,)),
            Injection(("resolvectl", "dns", DEVICE)),
        ]

    def test_it_survives_a_failure_after_every_mutation(self):
        for row in self.injection_points():
            with self.subTest(failing=row.failing):
                self.setUp()
                result = self.run_install_failing_at(row)
                self.assertFalse(result.ok, f"a failure at {row.failing!r} was not a failure")
                self.assertIsNone(
                    result.rollback_error,
                    f"the rollback of a failure at {row.failing!r} did not complete",
                )
                self.assertIn(row.failing, self.commands, "the failing command never ran")

    def test_a_failure_after_every_mutation_is_followed_by_exactly_its_rollback(self):
        # The whole tail, compared as a list rather than as membership. A rollback
        # that skipped an undo, ran one twice, or -- the failure this shape exists
        # to catch -- also repeated a mutation it never reached all produce a tail
        # that no membership check would notice.
        for row in self.injection_points():
            with self.subTest(failing=row.failing):
                self.setUp()
                self.run_install_failing_at(row)
                reached = self.commands.index(row.failing)
                self.assertEqual(
                    self.commands[reached + 1 :],
                    self.expected_rollback(row.failing, already_running=row.already_running),
                    f"a failure at {row.failing!r} was not followed by exactly its own rollback",
                )

    def test_a_failed_reactivation_is_still_reactivated_by_the_rollback(self):
        # The one mutation whose undo has to be on the stack BEFORE the attempt.
        # `nmcli connection up` takes a connection DOWN on its way up, so a run in
        # which it fails may have left the machine's connection deactivated -- and
        # the exit-3 message says every change this run made has been rolled back
        # and nothing else is different about this machine. Before the fix the undo
        # was registered after the attempt, so it was not on the stack at all, the
        # retry never ran, and that sentence was false on exactly the machine it
        # was written for.
        self.setUp()
        result = self.run_install(fail_first=[CONNECTION_UP + (UUID,)])
        self.assertFalse(result.ok)
        reactivations = [
            index for index, command in enumerate(self.commands) if command == CONNECTION_UP + (UUID,)
        ]
        self.assertEqual(
            len(reactivations), 2,
            f"the reactivation was attempted {len(reactivations)} time(s); a connection that was "
            "taken down and not brought back up is a machine with no uplink",
        )
        self.assertEqual(
            self.commands[reactivations[0] + 1 :],
            self.expected_rollback(CONNECTION_UP + (UUID,)),
            "a failed reactivation was not followed by the profile restore and then the retry",
        )
        self.assertIsNone(result.rollback_error, "the rollback of a failed reactivation did not finish")

    def test_a_reactivation_that_fails_every_time_is_a_rollback_failure_not_a_clean_refusal(self):
        # The other machine: the attempt fails and so does the retry, so the
        # reactivation is genuinely still applied. The exit status has to say so --
        # exit 3 claims the machine is as it was found, and this one is not.
        self.setUp()
        result = self.run_install(fail=[CONNECTION_UP + (UUID,)])
        self.assertFalse(result.ok)
        self.assertIsNotNone(
            result.rollback_error,
            "a reactivation that failed both times was reported as a clean refusal, so exit 3 "
            "would claim the machine is as it was found",
        )
        self.assertIn("reactivating", result.rollback_error)
        self.assertIn(
            "never reactivated",
            result.recovery or "",
            f"the recovery message does not tell the operator the connection was not brought back "
            f"up: {result.recovery!r}",
        )
        self.assertIn(f"nmcli connection up {UUID}", result.recovery or "")
        for unit in (RESOLVER_UNIT, ROUTER_UNIT):
            with self.subTest(unit=unit):
                self.assertIn(("systemctl", "stop", unit), self.commands)
        self.assertIn(MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM), self.commands)

    def test_the_exit_four_status_is_what_a_failed_reactivation_gets(self):
        # The status, because "the rollback did not finish" and "the rollback
        # finished" are two different machines and one status for both would tell
        # a script to simply repeat an install on a machine with no uplink.
        self.setUp()
        status, _out, err = self.install_cli(runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)]))
        self.assertEqual(status, installer.EXIT_ROLLBACK_FAILED, err)
        self.assertIn("these changes are still applied", err)

    # -- The upgrade's restart, which is the same hazard as the reactivation and
    # was found by looking for the other one -----------------------------------

    def test_a_failed_restart_of_a_unit_that_was_running_is_restarted_again(self):
        # `systemctl try-restart` STOPS the unit on its way to restarting it, so a
        # run in which it fails may have left a unit that WAS running down -- and
        # the exit-3 message says every change this run made has been rolled back
        # and nothing else is different about this machine. Before the fix the
        # already-active branch returned before `apply_unit`, so it registered NO
        # undo at all, the retry never ran, and a unit that was serving a machine
        # whose connection had already been pointed at 127.0.0.1 stayed down.
        #
        # This is the state item 8's fix created and did not carry the safety
        # property across: before it, `start` on an active unit was a no-op, so a
        # bad new release left the OLD binary serving and the machine resolving.
        #
        # WHAT IS ASSERTED IS THE STATE, not the command count. The first version
        # of this test counted the restarts, and a count is exactly what cannot
        # tell a `try-restart` on a running unit from the same command on a stopped
        # one -- `systemctl --help` says try-restart restarts a unit "if active",
        # and on a unit a failed start has just left in `failed` it does nothing
        # and exits ZERO. So the count went up, the record said the undo had run,
        # and the resolver stayed down on any real machine. See
        # `test_the_rollback_of_a_failed_restart_leaves_the_unit_running`.
        self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
        self.run_install(fail_first=[TRY_RESTART + (ROUTER_UNIT,)])
        self.assertTrue(
            self.runner.running(ROUTER_UNIT),
            f"{ROUTER_UNIT} was running before this run and the rollback left it "
            f"{self.unit_state[ROUTER_UNIT]!r}, so the machine has a resolver this run took "
            "down and an exit status that says every change was rolled back",
        )
        # The forward action is still `try-restart`, because that is right for a
        # unit that IS running: restarting it is the whole point of an upgrade.
        self.assertIn(TRY_RESTART + (ROUTER_UNIT,), self.commands)
        self.assertIn(
            "every change this run made has been rolled back",
            self.stderr_of_install(fail_first=[TRY_RESTART + (ROUTER_UNIT,)]),
            "the exit-3 sentence is the one this property is about, so it is asserted where it "
            "is printed rather than reconstructed -- and with the unit back up, it is now true",
        )
        self.assertIsNone(
            self.run_install(fail_first=[TRY_RESTART + (ROUTER_UNIT,)]).rollback_error,
            "a failed restart whose unit was put back is not a rollback failure, so it cannot be "
            "reported as one",
        )

    def test_the_rollback_of_a_failed_restart_leaves_the_unit_running(self):
        """The undo of a restart must be a verb that WORKS on a unit a failed restart
        left stopped, and must FAIL LOUDLY when it cannot.

        `try-restart` is the wrong word for an undo, and the asymmetry is the whole
        trap: it is the RIGHT word for the forward action, because a unit that is
        running should be restarted rather than left alone, and it is exactly wrong
        for putting that unit back, because the unit the forward action leaves
        behind after a failure is not running. The same word, chosen for its
        forward-action sense, silently undoes nothing on the machine it is supposed
        to be repairing.

        The undo is `systemctl start`: a no-op that succeeds when the unit is
        already running, a real start when it is not, and a FAILURE when the unit
        cannot be brought up -- which is the only thing that can route this machine
        to exit 4 and the `MAY HAVE NO RESOLVER` line. `systemctl restart` is the
        other correct word; `start` is chosen because it does not stop a unit that
        is already up, so an undo can never take away the resolver it is repairing.
        """
        for unit in (RESOLVER_UNIT, ROUTER_UNIT):
            with self.subTest(unit=unit):
                self.setUp()
                self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
                self.run_install(fail_first=[TRY_RESTART + (unit,)])
                self.assertTrue(
                    self.runner.running(unit),
                    f"the undo of a failed restart left {unit} "
                    f"{self.unit_state[unit]!r}; a `try-restart` on a unit a failed start "
                    "left in `failed` does nothing and exits zero, so the rollback reported a "
                    "unit it had not started",
                )
                self.assertIn(
                    ("systemctl", "start", unit), self.commands,
                    f"the undo issued no `start` for {unit}, so the only way it could have "
                    "restored the unit is a `try-restart`, which is a silent no-op on a "
                    "stopped one",
                )
                # The SIBLING, and what this loop is really about. Both units are
                # already running, so the transaction restarts both; this sub-test
                # failed the restart of one, and the rollback had to put BOTH back --
                # the failed one, which it down, and the one whose restart succeeded,
                # which was never down and had to be left alone. The assertion that was
                # here before asked about `unit` a second time under a comment about a
                # unit the run did not touch, which is the same fact twice and the
                # wrong fact once; the fact it meant to ask is about the other unit.
                sibling = RESOLVER_UNIT if unit == ROUTER_UNIT else ROUTER_UNIT
                self.assertTrue(
                    self.runner.running(sibling),
                    f"the rollback that put {unit} back took {sibling} down as well "
                    f"({self.unit_state[sibling]!r}); {sibling} was running before this run and "
                    "its own restart had succeeded, so nothing about it needed undoing",
                )

    def test_a_unit_that_could_not_be_brought_back_is_a_rollback_failure(self):
        # The other machine, and the one the decision this round records is about.
        # The unit was running, the restart failed, and the rollback's own attempt
        # to bring it back failed too -- so the unit is DOWN, it was UP before this
        # run, and no undo in the program can put it back. That has to be a rollback
        # FAILURE (exit 4) and not a clean refusal, and the recovery line has to say
        # the machine may have NO RESOLVER rather than "a unit this run started is
        # still running", which is the opposite fact and would send an operator to
        # `systemctl stop` on a machine that has nothing left listening.
        #
        # BOTH verbs are injected, and both have to be: the forward `try-restart` and
        # the rollback's `start`. Before the undo was a `start`, this case injected
        # only the restart and "passed" for the wrong reason -- the retry was a
        # no-op, not a success, and nothing could tell the difference.
        self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
        result = self.run_install(
            fail=[TRY_RESTART + (RESOLVER_UNIT,), START + (RESOLVER_UNIT,)]
        )
        self.assertFalse(result.ok)
        self.assertEqual(self.runner.running(RESOLVER_UNIT), False)
        self.assertIsNotNone(
            result.rollback_error,
            "a unit that was running and could not be restarted was reported as a clean "
            "refusal, so exit 3 would claim a machine is as it was found with a resolver down",
        )
        recovery = result.recovery or ""
        self.assertIn(
            "MAY HAVE NO RESOLVER",
            recovery,
            f"the recovery message does not tell the operator the machine may have no resolver: "
            f"{recovery!r}",
        )
        self.assertIn(RESOLVER_UNIT, recovery)
        self.assertIn("emergency-rollback", recovery, "the recovery message does not name the action")
        self.assertNotIn(
            f"this run started {RESOLVER_UNIT}",
            recovery,
            "the message still says this run STARTED the unit, which is the opposite of what "
            "happened: it was running before and the restart is what took it down",
        )
        # And a unit this run DID start, whose own stop failed, is still described as
        # running -- the two are different facts and one sentence cannot be true of
        # both, so this half is what stops the fix from fixing the message by
        # deleting the older arm.
        self.setUp()
        result = self.run_install(
            fail=[CONNECTION_UP + (UUID,), ("systemctl", "stop", ROUTER_UNIT)]
        )
        self.assertIn(f"this run started {ROUTER_UNIT}", result.recovery or "")
        self.assertNotIn("MAY HAVE NO RESOLVER", result.recovery or "")

    def test_the_recovery_line_prints_one_runnable_command_per_unit_it_names(self):
        """`systemctl restart A and B` is not a command. It is copy-pasteable text
        whose whole purpose is to be copied, and an operator who pastes it gets
        `Failed to restart ...: Unit a and b not found` -- or worse, a partial
        success that looks like the whole of it.

        The plural branch is reachable: both units were running, the transaction
        got past both of them, and a later step failed so the rollback ran -- and
        then both of the rollback's own `start`s failed, which is what a wedged
        systemd looks like. The message then names both units, and the ONE command
        it printed for them named both.
        """
        self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
        result = self.run_install(
            fail=[
                MODIFY + (UUID, "ipv4.dns", LOCAL_DNS),
                START + (RESOLVER_UNIT,),
                START + (ROUTER_UNIT,),
            ]
        )
        recovery = result.recovery or ""
        self.assertIn("MAY HAVE NO RESOLVER", recovery)
        for unit in (RESOLVER_UNIT, ROUTER_UNIT):
            with self.subTest(unit=unit):
                self.assertIn(f"`systemctl restart {unit}`", recovery)
        self.assertNotIn(
            f"`systemctl restart {RESOLVER_UNIT} and {ROUTER_UNIT}`", recovery,
            "the message still prints one command naming two units, which is not a command",
        )
        # Nothing that is not a command is offered. The conjunction is fine in a
        # sentence; it is not fine inside a command an operator is meant to paste.
        for command in re.findall(r"`([^`]+)`", recovery):
            if command.startswith("sudo ") or command.endswith(".json"):
                continue
            with self.subTest(command=command):
                self.assertIsNone(
                    re.search(r"^systemctl (\S+) .*\band\b", command),
                    f"{command!r} names more than one unit in a single command",
                )

    def test_the_exit_four_status_is_what_an_unrestartable_unit_gets(self):
        self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
        status, _out, err = self.install_cli(
            runner=self.good_runner(
                fail=[TRY_RESTART + (RESOLVER_UNIT,), START + (RESOLVER_UNIT,)]
            )
        )
        self.assertEqual(status, installer.EXIT_ROLLBACK_FAILED, err)
        self.assertIn("these changes are still applied", err)
        self.assertIn(
            "MAY HAVE NO RESOLVER", err, "the operator is not told the machine may have no resolver"
        )

    def test_a_unit_that_was_running_is_never_stopped_by_any_rollback(self):
        # The other half of the pair, and the property the undo must not trade
        # away: the undo of a restart is a RESTART, so the rollback cannot take a
        # resolver away that was there before this run began -- whichever step it
        # fails at.
        for row in self.injection_points():
            if not row.already_running:
                continue
            with self.subTest(failing=row.failing):
                self.setUp()
                self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
                if row.failing in self.UNDO_REGISTERED_FIRST:
                    self.run_install(fail=[row.failing])
                else:
                    self.run_install(fail_first=[row.failing])
                for unit in (RESOLVER_UNIT, ROUTER_UNIT):
                    with self.subTest(unit=unit):
                        self.assertNotIn(
                            ("systemctl", "stop", unit),
                            self.commands,
                            f"a failure at {row.failing!r} stopped {unit}, which was running before "
                            "this run began",
                        )

    def stderr_of_install(self, **kwargs):
        """The install's own standard error, through `main` and the injected probe."""
        _status, _out, err = self.install_cli(runner=self.good_runner(**kwargs))
        return err

    def test_a_failure_stops_the_services_it_started_and_leaves_the_rest_running(self):
        for row in self.injection_points():
            with self.subTest(failing=row.failing):
                self.setUp()
                self.run_install_failing_at(row)
                reached = self.commands.index(row.failing)
                for unit in (RESOLVER_UNIT, ROUTER_UNIT):
                    started = ("systemctl", "start", unit)
                    with self.subTest(unit=unit):
                        if started in self.commands and self.commands.index(started) < reached:
                            self.assertIn(
                                ("systemctl", "stop", unit),
                                self.commands,
                                f"a failure at {row.failing!r} left {unit} running; this install started it",
                            )
                        else:
                            self.assertNotIn(
                                ("systemctl", "stop", unit),
                                self.commands,
                                f"a failure at {row.failing!r} stopped {unit}, which this install had not started",
                            )

    def test_a_failure_at_a_property_restores_the_values_it_recorded(self):
        # The machine is pointed at the loopback by the third mutation, so the
        # cases that matter are the two failures after it: nothing may be left
        # pointing at 127.0.0.1, and the properties that were already set have to
        # carry the values the backup read rather than defaults.
        for failing in (MODIFY + (UUID, "ipv4.dns", LOCAL_DNS), CONNECTION_UP + (UUID,)):
            with self.subTest(failing=failing):
                self.setUp()
                self.run_install(fail=[failing])
                self.assertIn(MODIFY + (UUID, "ipv4.ignore-auto-dns", "no"), self.commands)
                self.assertIn(MODIFY + (UUID, "ipv6.ignore-auto-dns", "no"), self.commands)
                if self.commands.index(failing) > self.commands.index(MODIFY + (UUID, "ipv4.dns", LOCAL_DNS)):
                    self.assertIn(
                        MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM),
                        self.commands,
                        f"a failure at {failing!r} left the machine pointed at 127.0.0.1",
                    )

    def test_a_failure_restores_the_values_it_read_not_the_ones_it_set(self):
        # The original values are the backup's, so a connection that already
        # ignored automatic DNS comes back ignoring it, and one that already had
        # manual DNS comes back with the same addresses in the same order.
        outputs = {
            DNS_UUID_PREFIX + ("ipv4.ignore-auto-dns", "connection", "show", UUID): "yes\n",
            DNS_UUID_PREFIX + ("ipv4.dns", "connection", "show", UUID): f"{DHCP_SECOND_UPSTREAM},{DHCP_UPSTREAM}\n",
        }
        self.run_install(fail=[CONNECTION_UP + (UUID,)], outputs=outputs)
        self.assertIn(MODIFY + (UUID, "ipv4.ignore-auto-dns", "yes"), self.commands)
        self.assertIn(
            MODIFY + (UUID, "ipv4.dns", f"{DHCP_SECOND_UPSTREAM},{DHCP_UPSTREAM}"),
            self.commands,
            "the restore did not put the recorded addresses back, in the recorded order",
        )

    def test_it_never_stops_a_unit_that_was_already_running(self):
        outputs = {
            ("systemctl", "is-active", RESOLVER_UNIT): "active\n",
            ("systemctl", "is-enabled", RESOLVER_UNIT): "enabled\n",
        }
        self.returncodes[("systemctl", "is-active", RESOLVER_UNIT)] = 0
        self.returncodes[("systemctl", "is-enabled", RESOLVER_UNIT)] = 0
        self.run_install(fail=[("systemctl", "start", ROUTER_UNIT)], outputs=outputs)
        self.assertNotIn(
            ("systemctl", "stop", RESOLVER_UNIT),
            self.commands,
            "the transaction stopped a resolver that was running before it began",
        )
        self.assertNotIn(
            ("systemctl", "disable", RESOLVER_UNIT),
            self.commands,
            "the transaction disabled a resolver that was enabled before it began",
        )

    def test_an_unreadable_unit_state_is_treated_as_already_running(self):
        # The question could not be asked, and the safe reading of "was this unit
        # active before" is yes: stopping a unit somebody else was running is the
        # harm this rule exists to prevent, and leaving one running is a lesser
        # and reversible one.
        self.returncodes[("systemctl", "is-active", RESOLVER_UNIT)] = 1
        self.returncodes[("systemctl", "is-enabled", RESOLVER_UNIT)] = 1
        self.answers[("systemctl", "is-active", RESOLVER_UNIT)] = ""
        self.answers[("systemctl", "is-enabled", RESOLVER_UNIT)] = ""
        self.run_install(fail=[("systemctl", "start", ROUTER_UNIT)])
        self.assertNotIn(("systemctl", "stop", RESOLVER_UNIT), self.commands)
        self.assertNotIn(("systemctl", "disable", RESOLVER_UNIT), self.commands)

    def test_the_backup_survives_every_rollback_as_the_record(self):
        for row in self.injection_points():
            with self.subTest(failing=row.failing):
                self.setUp()
                self.run_install_failing_at(row)
                path = self.rooted(BACKUP_PATH)
                self.assertTrue(path.exists(), f"a failure at {row.failing!r} removed the backup")
                self.assertEqual(stat.S_IMODE(path.lstat().st_mode), BACKUP_MODE)
                self.assertEqual(
                    json.loads(path.read_text(encoding="utf-8"))["connection"]["uuid"],
                    UUID,
                )

    def test_the_rollback_restores_the_profile_and_only_then_reactivates(self):
        # The order that matters, spelled out. A rollback that reactivated the
        # device FIRST would hand it the profile as it stands mid-restore -- both
        # ignore-auto-dns set and the loopback address -- and would then write the
        # recorded values to the profile, where the live device never reads them
        # again. The machine would come out of a failed install with no resolver in
        # use and a correct profile, which is the state this rollback exists to
        # prevent, and the profile being correct is exactly what makes it hard to
        # notice.
        self.run_install(fail=[("resolvectl", "dns", DEVICE)])
        reached = self.commands.index(("resolvectl", "dns", DEVICE))
        tail = self.commands[reached + 1 :]
        self.assertEqual(
            tail,
            [
                MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM),
                MODIFY + (UUID, "ipv6.ignore-auto-dns", "no"),
                MODIFY + (UUID, "ipv4.ignore-auto-dns", "no"),
                CONNECTION_UP + (UUID,),
                ("systemctl", "stop", ROUTER_UNIT),
                ("systemctl", "stop", RESOLVER_UNIT),
                ("systemctl", "disable", ROUTER_UNIT),
                ("systemctl", "disable", RESOLVER_UNIT),
            ],
            "the rollback put the machine in the order the design requires: profile, then "
            "reactivation, then units",
        )

    def test_the_reactivation_is_after_every_property_restore_at_every_injection_point(self):
        # The property above is not a property of one failure. It has to hold
        # wherever the rollback gets far enough to have a reactivation to order.
        for failing in (MODIFY + (UUID, "ipv4.dns", LOCAL_DNS), CONNECTION_UP + (UUID,), ("resolvectl", "dns", DEVICE)):
            with self.subTest(failing=failing):
                self.setUp()
                self.run_install(fail=[failing])
                tail = self.commands[self.commands.index(failing) + 1 :]
                restores = [command for command in tail if command[:3] == MODIFY]
                reactivating = [index for index, command in enumerate(tail) if command == CONNECTION_UP + (UUID,)]
                done = [command for command in self.STEPS if command in self.commands and self.commands.index(command) < self.commands.index(failing)]
                if not restores:
                    continue
                if self.REACTIVATING_STEP not in done:
                    # The reconnection was never reached, so there is nothing to
                    # order; the property restores still have to be in order among
                    # themselves.
                    self.assertEqual(
                        restores,
                        [
                            self.undo_of(step)
                            for step in reversed(self.PROFILE_STEPS)
                            if self.undo_of(step) in tail
                        ],
                    )
                    continue
                self.assertEqual(len(reactivating), 1, f"a failure at {failing!r} did not reactivation at all")
                self.assertGreater(
                    reactivating[0],
                    len(restores) - 1,
                    f"a failure at {failing!r} reactivated the device before the profile carried its "
                    "recorded values again, so the device was handed the values being taken away",
                )
                stops = [index for index, command in enumerate(tail) if command[:2] == ("systemctl", "stop")]
                if stops:
                    self.assertGreater(reactivating[0], len(restores) - 1)
                    self.assertLess(reactivating[0], min(stops), "a unit was stopped before the reactivation")

    def test_a_wait_that_never_answers_fails_the_install_rather_than_hanging(self):
        for port, unit in ((RESOLVER_PORT, RESOLVER_UNIT), (DNS_PORT, ROUTER_UNIT)):
            with self.subTest(port=port):
                self.setUp()
                result = self.run_install(
                    probe=self.probe_for({("127.0.0.1", port): SILENT}), deadline=0.0
                )
                self.assertFalse(result.ok, f"a resolver that never answered on {port} passed")
                self.assertIn(str(port), result.error or "")
                self.assertIsNone(result.rollback_error)
                self.assertIn(("systemctl", "stop", unit), self.commands)
                self.assertNotIn(MODIFY + (UUID, "ipv4.ignore-auto-dns", "yes"), self.commands)
                self.assertFalse(self.rooted(MANAGED_BY).exists())

    def test_a_health_check_that_fails_never_reaches_networkmanager(self):
        # The wait for the router's port succeeds, then the health check -- the
        # query that decides whether the machine may be pointed at 127.0.0.1 --
        # goes silent. Nothing may have touched NetworkManager by then.
        queries = []

        def probe(address, port):
            self.events.append(("probe", address, port))
            queries.append((address, port))
            listening = (address, port) != (LOCAL_DNS, DNS_PORT) or len(queries) == 1
            return answer(listening, listening)

        result = self.run_install(probe=probe, deadline=0.0)
        self.assertFalse(result.ok, "a health check that never answered passed the install")
        self.assertIn("127.0.0.1:53", result.error or "")
        for command in self.commands:
            self.assertNotIn(
                command[:2],
                (MODIFY[:2], CONNECTION_UP[:2]),
                f"{command!r} ran after a failed health check",
            )
        self.assertFalse(self.rooted(MANAGED_BY).exists())

    def test_a_stub_that_stops_answering_fails_the_install_and_rolls_back(self):
        def probe(address, port):
            self.events.append(("probe", address, port))
            listening = (address, port) != (RESOLVED_STUB, DNS_PORT)
            return answer(listening, listening)

        result = self.run_install(probe=probe, deadline=0.0)
        self.assertFalse(result.ok)
        self.assertIn(RESOLVED_STUB, result.error or "")
        self.assertIn(MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM), self.commands)
        self.assertFalse(self.rooted(MANAGED_BY).exists())

    def test_a_resolved_that_is_not_forwarding_to_us_fails_the_install(self):
        result = self.run_install(
            outputs={("resolvectl", "dns", DEVICE): "Link 2 (ens33): 192.0.2.1\n"}
        )
        self.assertFalse(result.ok, "resolved forwarding somewhere else passed the verification")
        self.assertIn(LOCAL_DNS, result.error or "")
        self.assertIn(MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM), self.commands)


class RollbackFailureTests(TransactionFixture):
    """The two failure statuses are different facts about the machine."""

    def test_a_step_that_fails_in_a_way_this_program_did_not_expect_still_rolls_back(self):
        # A traceback out of a transaction that has already pointed a machine's DNS
        # at a loopback address is the worst outcome available here, and the exit
        # status of an uncaught exception is the same 1 a refusal uses -- so a bug
        # in a step must roll back like a predicted failure and must say so.
        original = installer._reconnect
        self.addCleanup(setattr, installer, "_reconnect", original)

        def explode(*arguments, **keywords):
            raise KeyError("a bug in a step nobody predicted")

        installer._reconnect = explode
        try:
            result = self.run_install()
        finally:
            installer._reconnect = original
        self.assertFalse(result.ok)
        self.assertIn("bug", (result.error or "").lower())
        self.assertIsNone(result.rollback_error, "the rollback of an unexpected failure did not complete")
        self.assertIn(MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM), self.commands)
        self.assertIn(("systemctl", "stop", ROUTER_UNIT), self.commands)
        self.assertFalse(self.rooted(MANAGED_BY).exists())

    def test_a_rollback_that_worked_and_one_that_did_not_are_different_statuses(self):
        # `fail_first` for the reactivation, not `fail`: its undo is the SAME
        # argument array and is on the stack before the attempt, so failing every
        # call is a different machine -- one whose reactivation could not be
        # undone either -- and is the subject of the case above.
        worked = self.run_install(fail_first=[CONNECTION_UP + (UUID,)])
        self.assertIsNone(worked.rollback_error, "a completed rollback reported a failure")
        self.assertTrue(worked.error)
        self.setUp()
        broken = self.run_install(
            fail=[
                CONNECTION_UP + (UUID,),
                MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM),
            ]
        )
        self.assertTrue(broken.error)
        self.assertIsNotNone(
            broken.rollback_error, "a restore that failed was reported as a clean rollback"
        )
        self.assertIn("ipv4.dns", broken.rollback_error)

    def test_a_rollback_that_could_not_restore_still_restores_everything_else(self):
        # Stopping at the first failure would leave the machine with more applied
        # than restoring past it would.
        self.run_install(
            fail=[
                CONNECTION_UP + (UUID,),
                MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM),
            ]
        )
        for command in (
            CONNECTION_UP + (UUID,),
            MODIFY + (UUID, "ipv6.ignore-auto-dns", "no"),
            MODIFY + (UUID, "ipv4.ignore-auto-dns", "no"),
            ("systemctl", "stop", ROUTER_UNIT),
            ("systemctl", "stop", RESOLVER_UNIT),
            ("systemctl", "disable", ROUTER_UNIT),
            ("systemctl", "disable", RESOLVER_UNIT),
        ):
            self.assertIn(command, self.commands, f"{command!r} was skipped after an earlier failure")

    def test_the_two_reasons_are_reported_separately(self):
        result = self.run_install(
            fail=[CONNECTION_UP + (UUID,), MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM)]
        )
        self.assertIn(
            UUID, result.error or "", "the original failure has to name the step that failed"
        )
        self.assertNotIn("ipv4.dns", result.error or "", "the rollback's own failure leaked into the first")
        self.assertIn("ipv4.dns", result.rollback_error or "", "the rollback failure has to name what it could not undo")
        self.assertNotEqual(result.error, result.rollback_error)

    def test_a_restored_value_is_never_invented(self):
        # Every restoring command names a value the backup recorded. A restore
        # that wrote a default instead would be a value nothing read.
        outputs = {
            DNS_UUID_PREFIX + ("ipv6.ignore-auto-dns", "connection", "show", UUID): "yes\n",
            DNS_UUID_PREFIX + ("ipv4.dns", "connection", "show", UUID): f"{DHCP_SECOND_UPSTREAM}\n",
        }
        self.run_install(fail=[("resolvectl", "dns", DEVICE)], outputs=outputs)
        document = json.loads(self.rooted(BACKUP_PATH).read_text(encoding="utf-8"))
        recorded = {
            key: ",".join(value["value"]) if isinstance(value["value"], list) else value["value"]
            for key, value in document["original"].items()
        }
        restores = [
            command
            for command in self.commands
            if command[:3] == MODIFY and command not in self.STEPS
        ]
        self.assertTrue(restores, "the test has to see at least one restoring command")
        for command in restores:
            if command[4] == "ipv4.dns":
                self.assertEqual(command[5], recorded["ipv4.dns"])
            else:
                self.assertEqual(command[5], recorded[command[4]])


class LocalVerdictBlindSpotTests(TransactionFixture):
    """`verify-local` must not report a verdict the router fabricated for it.

    The install REFUSES to run when the operator's force-ECH list makes the router
    answer `install-probe.example` itself: with such an entry the router short
    circuits A queries for that name, never forwards, and answers NOERROR. Every
    check the install makes would then be satisfied by the thing it is checking.

    An operator who adds the name AFTER the install gets no such refusal, because
    there is no install left to refuse -- and the two-minute health check then
    reports a working local resolver for ever, whatever the router is doing. That
    is the blind spot this verb inherited from the barrier and did not carry the
    guard for, and the two predicates that close it already exist here:
    `_forced_ech_domains` and `_ech_may_answer_locally`.
    """

    def run_verify(self, shape=HEALTHY, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        import contextlib

        self.events = []
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = installer.main(
                ["verify-local"],
                self.good_runner(),
                root=self.root,
                probe=self.probe_for({(LOCAL_DNS, DNS_PORT): shape}),
            )
        return status, out.getvalue(), err.getvalue()

    def blind(self, *domains):
        self.write(FORCE_ECH, "\n".join(domains) + "\n")

    def test_a_probe_name_the_router_answers_locally_gets_no_verdict_at_all(self):
        self.blind("install-probe.example.")
        status, out, err = self.run_verify()
        self.assertNotEqual(status, installer.EXIT_OK, f"a fabricated answer was called healthy: {out!r}")
        self.assertEqual(status, installer.EXIT_REFUSED, err)
        self.assertEqual(
            [event for event in self.events if event[0] == "probe"],
            [],
            "the verb probed after it had already decided the answer proves nothing",
        )
        self.assertIn("NOT A SIGN THE ROUTER IS DOWN", err)
        self.assertIn(FORCE_ECH, err)

    def test_a_list_that_does_not_name_the_probe_leaves_the_verdict_alone(self):
        # The negative control, and it is what makes the case above a statement
        # about the probe name rather than about the file existing: a list with
        # other entries in it is the common case and must not cost the check
        # anything.
        self.blind("example.com.", "example.org.")
        status, out, err = self.run_verify()
        self.assertEqual(status, installer.EXIT_OK, err)
        self.assertIn("resolved", out)

    def test_the_same_entry_is_not_a_blind_spot_when_the_policy_turns_ech_off(self):
        # `_ech_may_answer_locally` is the second half and it is not decoration:
        # `forcesECH` returns false when ECH is explicitly disabled, whatever the
        # list says, so the router forwards the name and the answer means
        # something. A guard that ignored the policy would refuse a machine whose
        # check is perfectly able to see the router.
        self.blind("install-probe.example.")
        self.write(
            POLICY_CONFIG,
            "schema_version: 1\ncdn:\n  provider: cloudflare\nech:\n  enabled: false\n",
        )
        status, out, err = self.run_verify()
        self.assertEqual(status, installer.EXIT_OK, err)
        self.assertIn("resolved", out)


class ProbeTests(unittest.TestCase):
    """The prober, against a UDP socket on a loopback ephemeral port.

    Ports 53, 15353 and 127.0.0.53 are never bound or queried here, and the
    socket is bound to port 0, so the test cannot collide with a resolver and
    cannot be mistaken for one.
    """

    def test_it_builds_a_well_formed_query(self):
        query = installer.build_dns_query("example.test", 0x1234)
        self.assertEqual(query[:2], b"\x12\x34", "the transaction id is not the one it chose")
        self.assertEqual(int.from_bytes(query[2:4], "big"), 0x0100, "the query is not a standard recursion request")
        self.assertEqual(int.from_bytes(query[4:6], "big"), 1, "the query does not ask one question")
        self.assertEqual(int.from_bytes(query[6:8], "big"), 0)
        self.assertEqual(int.from_bytes(query[8:10], "big"), 0)
        self.assertEqual(int.from_bytes(query[10:12], "big"), 0)
        self.assertEqual(
            query[12 : 12 + 14],
            b"\x07example\x04test\x00",
            "the name is not encoded as length-prefixed labels ending in a root label",
        )
        self.assertEqual(query[-4:], b"\x00\x01\x00\x01", "the question is not A/IN")

    def test_a_name_that_is_not_a_dotted_name_is_refused(self):
        for name in ("", "a..b", "x" * 64):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    installer.build_dns_query(name, 1)

    def test_it_accepts_a_response_and_ignores_everything_else(self):
        query = installer.build_dns_query("example.test", 0x0042)
        header = query[:2] + b"\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:]
        self.assertTrue(installer.response_is_an_answer(header, 0x0042))
        self.assertFalse(
            installer.response_is_an_answer(header, 0x0043), "a response for another query was accepted"
        )
        self.assertFalse(
            installer.response_is_an_answer(query, 0x0042), "the query itself was accepted as a response"
        )
        for short in (b"", b"\x00", query[:11]):
            with self.subTest(length=len(short)):
                self.assertFalse(installer.response_is_an_answer(short, 0x0042))

    def test_it_answers_a_real_socket_and_gives_up_on_a_silent_one(self):
        def answer(query):
            return query[:2] + b"\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:]

        server, port, thread = responder(answer)
        try:
            seen = installer.probe_dns("127.0.0.1", port, timeout=2.0)
            self.assertTrue(seen.answered, "a DNS answer on the socket was not seen")
            self.assertTrue(seen.resolves, "a NOERROR response does not resolve")
        finally:
            server.close()
            thread.join(timeout=5)
        silent = installer.probe_dns("127.0.0.1", port, timeout=0.2)
        self.assertFalse(
            silent.answered,
            "a closed port answered, so the prober would wait for a resolver that is not there",
        )
        self.assertFalse(silent.resolves)

    def test_it_refuses_a_socket_that_answers_with_something_else(self):
        def answer(query):
            return b"HTTP/1.1 400 Bad Request\r\n\r\n"

        server, port, thread = responder(answer)
        try:
            seen = installer.probe_dns("127.0.0.1", port, timeout=2.0)
            self.assertFalse(seen.answered, "something that is not DNS was accepted as an answer")
            self.assertFalse(seen.resolves, "and therefore not as a working resolver either")
        finally:
            server.close()
            thread.join(timeout=5)

    def test_a_wait_polls_until_the_deadline_and_then_gives_up(self):
        attempts = []

        def late(address, port):
            attempts.append((address, port))
            return answer(len(attempts) >= 3, len(attempts) >= 3)

        self.assertTrue(
            installer.wait_for_dns(LOCAL_DNS, DNS_PORT, late, 10.0, 0.0),
            "a resolver that answered on the third poll was not waited for",
        )
        self.assertEqual(attempts, [(LOCAL_DNS, DNS_PORT)] * 3)

        attempts.clear()
        self.assertFalse(
            installer.wait_for_dns(
                LOCAL_DNS,
                DNS_PORT,
                lambda a, p: (attempts.append((a, p)), answer(False, False))[1],
                0.0,
                0.0,
            ),
            "a wait with no deadline left succeeded",
        )
        self.assertEqual(len(attempts), 1, "the wait did not try even once")


class UpgradeRestartTests(TransactionFixture):
    """A unit that was already running is RESTARTED, so the upgrade is what is verified.

    `systemctl start` on an already-active unit is a no-op, so an upgrade of a
    running machine installs a new `mosdns-router`, a new `dnscrypt-proxy`, a new
    `mosdns-cdnctl` and a new generated `/etc/mosdns/mosdns.yaml`, and then
    verifies the OLD processes against the NEW document. Everything the
    transaction reports after the start -- the two waits, the barrier, the
    verification of the device and the machine's own resolvers -- describes the
    binaries that were running before dpkg unpacked the new ones, and the exit-0
    message claims ports 53 and 15353 are served by what this package just
    installed.

    `try-restart` is the verb that fixes it and it is conditional on the state
    being READ. A unit whose state could not be read is only `start`ed, because
    `try-restart` stops it first and stopping a unit this install may not own is
    the harm the whole prior-state rule exists to prevent. That second half is a
    judgement rather than an oversight and it is argued in `_start`'s own
    docstring; `FailureInjectionTests` holds both halves, because the restart's own
    undo is a property that only the injection table reaches.
    """

    def test_a_unit_that_was_already_running_is_restarted_rather_than_started(self):
        self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
        result = self.install_succeeds()
        for unit in (RESOLVER_UNIT, ROUTER_UNIT):
            with self.subTest(unit=unit):
                self.assertIn(("systemctl", "try-restart", unit), self.commands)
                self.assertNotIn(
                    ("systemctl", "start", unit),
                    self.commands,
                    f"{unit} was already running and was only started, so the running process is "
                    "still the one this package had before the upgrade",
                )
        # And the wait is asked again afterwards, so the verification describes the
        # process that is now running rather than the one that was.
        for unit, port in ((RESOLVER_UNIT, RESOLVER_PORT), (ROUTER_UNIT, DNS_PORT)):
            with self.subTest(unit=unit):
                after = self.commands.index(("systemctl", "try-restart", unit))
                self.assertIn(
                    ("probe", LOCAL_DNS, port),
                    self.events[after:],
                    f"nothing asked {LOCAL_DNS}:{port} after {unit} was restarted, so the "
                    "verification describes the process that was there before the upgrade",
                )
        self.assertIn(
            f"{RESOLVER_UNIT} and {ROUTER_UNIT} were already running",
            " ".join(result.notes),
            "an operator reading the report cannot tell that the daemons were restarted",
        )

    def test_a_unit_that_was_already_running_is_never_stopped_by_the_rollback(self):
        self.already_running(RESOLVER_UNIT, ROUTER_UNIT)
        self.run_install(fail=[MODIFY + (UUID, "ipv4.dns", LOCAL_DNS)])
        for unit in (RESOLVER_UNIT, ROUTER_UNIT):
            with self.subTest(unit=unit):
                self.assertNotIn(("systemctl", "stop", unit), self.commands)
                self.assertNotIn(("systemctl", "disable", unit), self.commands)

    def test_a_unit_whose_state_could_not_be_read_is_only_started(self):
        # The unreadable state reads as "was already running", so the two cases are
        # one branch in the code and must not be one branch in what the code DOES.
        self.answers[("systemctl", "is-active", RESOLVER_UNIT)] = ""
        self.returncodes[("systemctl", "is-active", RESOLVER_UNIT)] = 1
        self.install_succeeds()
        self.assertNotIn(
            ("systemctl", "try-restart", RESOLVER_UNIT),
            self.commands,
            "a unit whose prior state could not be read was try-restarted, which stops it first",
        )
        self.assertIn(("systemctl", "start", RESOLVER_UNIT), self.commands)
        # The router's state WAS readable, so the other half of the pair is
        # restarted; a fix that stopped restarting anything would pass the case above.
        self.setUp()
        self.already_running(ROUTER_UNIT)
        self.install_succeeds()
        self.assertIn(("systemctl", "try-restart", ROUTER_UNIT), self.commands)


class LocalResolverVerbTests(TransactionFixture):
    """`verify-local`: the question the health unit's second command asks.

    The two-minute health check proves the CDN address in service and nothing
    else, so a machine whose local resolver had stopped was called healthy every
    two minutes for ever. This verb is the second ExecStart of
    `mosdns-cdn-health.service` and it asks the one question that was missing,
    with the installer's own probe so that "resolvable" has one definition in this
    package rather than two.
    """

    def run_verify(self, shape):
        out, err = io.StringIO(), io.StringIO()
        import contextlib

        self.events = []
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = installer.main(
                ["verify-local"],
                self.good_runner(),
                root=self.root,
                probe=self.probe_for({(LOCAL_DNS, DNS_PORT): shape}),
            )
        return status, out.getvalue(), err.getvalue()

    def test_a_resolvable_local_resolver_exits_zero(self):
        status, out, err = self.run_verify(HEALTHY)
        self.assertEqual(status, installer.EXIT_OK, err)
        self.assertIn(f"{LOCAL_DNS}:{DNS_PORT}", out)
        self.assertIn(INSTALL_PROBE_NAME, out)

    def test_it_asks_the_local_resolver_and_nothing_else(self):
        self.run_verify(HEALTHY)
        asked = [event for event in self.events if event[0] == "probe"]
        self.assertEqual(asked, [("probe", LOCAL_DNS, DNS_PORT)])

    def test_a_servfail_is_a_failure_and_says_why_it_is_not_health(self):
        # The predicate's whole point: something answered, confidently, from a
        # chain that reached nobody. Calling that healthy is the failure mode.
        for shape in (SERVFAIL, REFUSED):
            with self.subTest(shape=shape):
                self.setUp()
                status, out, err = self.run_verify(shape)
                self.assertEqual(status, installer.EXIT_REFUSED, out)
                self.assertIn("did not resolve", err)
                self.assertIn("SERVFAIL", err)
                self.assertEqual(out, "", "a failure reported a result on standard output")

    def test_silence_is_a_failure_and_is_told_apart_from_a_servfail(self):
        status, _out, err = self.run_verify(SILENT)
        self.assertEqual(status, installer.EXIT_REFUSED)
        self.assertIn("nothing at all answered", err)
        self.assertNotIn("SERVFAIL", err)

    def test_it_names_the_action_and_changes_nothing(self):
        status, _out, err = self.run_verify(SILENT)
        self.assertEqual(status, installer.EXIT_REFUSED)
        self.assertIn("emergency-rollback", err)
        self.assertIn("Nothing has been changed", err)
        self.assertEqual(
            self.commands, [], "the verb issued a command, and it is documented as read-only"
        )
        self.assertFalse(self.rooted(BACKUP_PATH).exists())


class CliTransactionTests(TransactionFixture):
    """The command as a person runs it, and the two statuses that mean things."""

    def run_cli(self, *arguments, runner=None, probe=None):
        out, err = io.StringIO(), io.StringIO()
        import contextlib

        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = installer.main(
                list(arguments),
                runner or self.good_runner(),
                root=self.root,
            )
        return status, out.getvalue(), err.getvalue()

    def test_a_successful_install_exits_zero_and_says_what_it_did(self):
        status, out, err = self.install_cli()
        self.assertEqual(status, installer.EXIT_OK, err)
        self.assertIn(DEVICE, out)
        self.assertIn(str(DNS_PORT), out)
        self.assertIn("marker", out.lower())

    def test_a_refused_machine_exits_one(self):
        self.build_state_directories(mode="2777")
        answers = {
            STAT_FIELDS + (str(self.rooted(relative)),): f"2777 root mosdns {stat.S_IFDIR | 0o2777:x}"
            for relative in STATE_DIRECTORIES
        }
        status, out, err = self.install_cli(self.good_runner(outputs=answers))
        self.assertEqual(status, installer.EXIT_REFUSED)
        self.assertNotIn("install:", out, "a refused install reported a result")
        self.assertIn("preflight", err.lower())
        self.assertIn("nothing", err.lower(), "a refusal has to say it changed nothing")

    def test_a_failed_install_that_rolled_back_exits_three(self):
        # `fail_first`, not `fail`: the reactivation's undo is the same argument
        # array and is on the stack before the attempt, so a run in which BOTH
        # calls fail is a machine with an undone reactivation -- which is exit 4,
        # and is what the case in FailureInjectionTests is about.
        status, out, err = self.install_cli(self.good_runner(fail_first=[CONNECTION_UP + (UUID,)]))
        self.assertEqual(status, installer.EXIT_INSTALL_FAILED, err)
        self.assertIn("rolled back", err.lower(), "the operator has to be told the machine is as it was")
        self.assertNotIn("still applied", err.lower())

    def test_a_failed_install_that_did_not_roll_back_exits_four(self):
        status, out, err = self.install_cli(
            self.good_runner(fail=[CONNECTION_UP + (UUID,), MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM)])
        )
        self.assertEqual(status, installer.EXIT_ROLLBACK_FAILED, err)
        self.assertIn("still applied", err.lower(), "an operator has to be told the machine is half-changed")
        self.assertIn("ipv4.dns", err)

    def test_the_exit_four_message_says_the_uplink_may_be_down(self):
        # After the corrected rollback order, a failure of the REACTIVATION alone
        # leaves the profile carrying its recorded values and the device not
        # reactivated -- so the machine's DNS may not be in use even though every
        # value on disk is right. That is the one fact the operator needs and the
        # message has to carry it, with the one action that finishes the job.
        status, out, err = self.install_cli(
            self.good_runner(
                fail=[("resolvectl", "dns", DEVICE)],
                fail_after={CONNECTION_UP + (UUID,): 1},
            )
        )
        self.assertEqual(status, installer.EXIT_ROLLBACK_FAILED, err)
        self.assertIn("still applied", err.lower())
        self.assertIn("reactivated", err.lower(), "the message has to name the reactivation as what is missing")
        self.assertIn("nmcli connection up", err, "the message has to name the one command that finishes it")
        self.assertIn(UUID, err, "the message has to name the connection it applies to")
        self.assertIn("profile", err.lower(), "the message has to say the recorded values ARE back")

    def test_the_exit_four_message_says_when_the_profile_itself_is_still_wrong(self):
        # A different failed undo is a different state of the machine, and the
        # message must not tell the operator the profile is fine when it is not:
        # the connection would still be handing resolved the loopback address.
        status, out, err = self.install_cli(
            self.good_runner(fail=[CONNECTION_UP + (UUID,), MODIFY + (UUID, "ipv4.dns", DHCP_UPSTREAM)])
        )
        self.assertEqual(status, installer.EXIT_ROLLBACK_FAILED, err)
        self.assertIn("ipv4.dns", err)
        self.assertIn("still applied", err.lower())
        self.assertIn("127.0.0.1", err, "the operator has to be told the machine may still point at the loopback")

    def test_the_exit_four_message_names_the_unit_in_the_command_it_prints(self):
        # The first version of this case asserted only that the unit appeared
        # somewhere in stderr, which the failing step's own description satisfies
        # whether or not the recovery line names anything. So it asserted that
        # `systemctl stop <unit>` was printed: the unit has to be SUBSTITUTED into
        # the command, which is the only way that string can appear.
        status, out, err = self.install_cli(
            self.good_runner(fail=[CONNECTION_UP + (UUID,), ("systemctl", "stop", ROUTER_UNIT)])
        )
        self.assertEqual(status, installer.EXIT_ROLLBACK_FAILED, err)
        self.assertIn(
            f"systemctl stop {ROUTER_UNIT}",
            err,
            "the recovery line has to print the command with the unit's name in it, because "
            "'systemctl stop <unit>' with an unsubstituted placeholder is not a command an "
            "operator can run",
        )
        self.assertNotIn("<unit>", err, "a placeholder reached the operator")
        self.assertNotIn(
            RESOLVER_UNIT,
            err,
            "only the unit whose undo failed may be named: the resolver was stopped successfully, "
            "so naming it would send the operator after a unit that is already down",
        )

    def test_the_exit_four_message_names_every_stuck_unit_in_the_plural_branch(self):
        # Both units' undos failing is reachable -- a systemd wedged partway
        # through a rollback is the ordinary way -- and the plural arm of the
        # message used to print the literal `systemctl stop <unit>`, which is not
        # a command. The singular arm was fixed in round 2 and its test cannot
        # pass by accident; this is the same property on the other arm, and the
        # two have to stay distinguishable in the output.
        status, out, err = self.install_cli(
            self.good_runner(
                fail=[
                    ("resolvectl", "dns", DEVICE),
                    ("systemctl", "stop", ROUTER_UNIT),
                    ("systemctl", "stop", RESOLVER_UNIT),
                ]
            )
        )
        self.assertEqual(status, installer.EXIT_ROLLBACK_FAILED, err)
        for unit in (ROUTER_UNIT, RESOLVER_UNIT):
            self.assertIn(
                f"systemctl stop {unit}",
                err,
                f"the recovery line has to print the command with {unit} in it, because an "
                "unsubstituted placeholder is not a command an operator can run",
            )
        self.assertNotIn("<unit>", err, "a placeholder reached the operator")
        self.assertIn("which are still running", err, "the two units have to be distinguishable from the one-unit case")
        self.assertNotIn("which is still running", err, "two units are not one unit")

    def test_the_exit_four_message_distinguishes_one_stuck_unit_from_two(self):
        one, _, one_err = self.install_cli(
            self.good_runner(fail=[("resolvectl", "dns", DEVICE), ("systemctl", "stop", ROUTER_UNIT)])
        )
        two, _, two_err = self.install_cli(
            self.good_runner(
                fail=[
                    ("resolvectl", "dns", DEVICE),
                    ("systemctl", "stop", ROUTER_UNIT),
                    ("systemctl", "stop", RESOLVER_UNIT),
                ]
            )
        )
        self.assertEqual(one, installer.EXIT_ROLLBACK_FAILED)
        self.assertEqual(two, installer.EXIT_ROLLBACK_FAILED)
        self.assertIn("which is still running", one_err)
        self.assertIn("which are still running", two_err)

    def test_the_exit_three_message_excepts_a_unit_it_could_not_ask_about(self):
        # "Nothing is different about this machine" is a claim, and there is one
        # case where this module makes it deliberately false: a unit whose prior
        # state could not be read is started and then left running, because
        # stopping somebody else's unit is the harm the rule exists to prevent. The
        # message has to name that exception rather than assert the opposite.
        self.setUp()
        self.answers[("systemctl", "is-active", RESOLVER_UNIT)] = ""
        self.returncodes[("systemctl", "is-active", RESOLVER_UNIT)] = 1
        status, out, err = self.install_cli(self.good_runner(fail=[("systemctl", "start", ROUTER_UNIT)]))
        self.assertEqual(status, installer.EXIT_INSTALL_FAILED, err)
        self.assertIn("rolled back", err.lower())
        self.assertIn(RESOLVER_UNIT, err, "the message has to name the unit it left as it found it")
        self.assertIn("could not", err.lower(), "and say that it could not ask about it")
        self.assertNotIn(
            "nothing is different",
            err.lower(),
            "the message claims the machine is unchanged while a unit it started is still running",
        )

    def test_the_exit_three_message_makes_no_exception_when_every_state_was_read(self):
        status, out, err = self.install_cli(self.good_runner(fail=[("systemctl", "start", ROUTER_UNIT)]))
        self.assertEqual(status, installer.EXIT_INSTALL_FAILED, err)
        self.assertIn("nothing else is different", err.lower())
        self.assertNotIn("except", err.lower(), "no exception is due when every unit state was read")

    def test_a_usage_error_runs_nothing_at_all(self):
        # `uninstall` was one of these cases until Task 5 made it a verb, and the
        # case that replaced it is one its own test file holds: `uninstall` with
        # a flag it does not take, and with the flag given twice. A repeated
        # `--purge` is a usage error rather than a second permission, because
        # whether the operator's data goes is a decision and not a modifier.
        for arguments in ((), ("install", "--force"), ("preflight", "install"), ("uninstall", "--force")):
            with self.subTest(arguments=arguments):
                self.setUp()
                runner = self.good_runner()
                status, out, err = self.run_cli(*arguments, runner=runner)
                self.assertEqual(status, installer.EXIT_USAGE, f"{arguments} was accepted")
                self.assertEqual(runner.calls, [], f"{arguments} read the machine it was given")
                self.assertEqual(out, "")

    def test_the_usage_names_both_verbs(self):
        for arguments in ((), ("install", "--force")):
            with self.subTest(arguments=arguments):
                _, _, err = self.run_cli(*arguments)
                self.assertIn("preflight", err)
                self.assertIn("install", err)
                self.assertNotIn("--fix", err)


if __name__ == "__main__":
    unittest.main()
