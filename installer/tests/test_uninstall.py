"""Hold the uninstall and the emergency rollback to the refusals they have to make.

The install is the half of this program that takes a machine's DNS. This file is
about the half that gives it back, and the direction of its failure matters more
than anything it can do: **an uninstall that restores the wrong thing is worse
than one that refuses.** So what is asserted here is mostly what does *not* happen.

* **Nothing is restored that this installation cannot prove it owns.** The marker
  has to be there, the backup has to be a record this project wrote at a schema
  version this release understands, the connection has to be named, and every
  property has to hold either the value this installation set or the value the
  backup recorded -- nothing else. A property in a third state means somebody
  edited the connection after the install, and the answer is a refusal plus a
  report a person can act on, never an overwrite.
* **A refusal changes nothing.** Every refusal case asserts the refusal *and*
  that no command that changes anything ran and no file under the fake root
  changed. A refusal that changed something is a bug, and a test that only reads
  the exit status would not notice.
* **The restoration happens before the resolver is taken away.** The machine is
  put back on its own resolvers, and the device is *checked* to have picked them
  up, before ``mosdns-router.service`` is stopped. That order is why a unit whose
  state cannot be read may safely be left running.
* **The default keeps ``/var/lib/mosdns``; ``--purge`` removes it only after the
  restoration finished.** A failed restoration is never followed by a purge.
* **The emergency rollback asks the *resolving* question.** "Something is
  listening" is not "this machine can resolve", and a rollback that declares
  success on a dead chain hands the operator a machine with no DNS. So its
  verification is the resolved predicate, and a SERVFAIL is a failure.

Nothing here reads or writes the host. The root is a temporary directory, every
command goes through a fake runner that records the exact argument array, and the
DNS probe is an injected callable. The fake root is walked before and after every
case that removes anything, so "it removed only the dispatcher script and the
state directory" is a claim about the whole tree rather than about two paths a
test remembered to check.
"""

import ast
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "installer"))

import mosdns_installer as installer  # noqa: E402

MODULE = REPO / "installer" / "mosdns_installer.py"
SOURCE = MODULE.read_text(encoding="utf-8")

# The paths and values this task is about, restated rather than read from the
# module: a test that asserted `installer.DISPATCHER_SCRIPT` proved that the
# module agrees with itself.
PACKAGE_NAME = "mosdns-router"
MANAGED_BY_VALUE = "mosdns-router"
STATE_DIRECTORY = "/var/lib/mosdns"
INSTALLER_DIRECTORY = "/var/lib/mosdns/installer"
BACKUP_PATH = INSTALLER_DIRECTORY + "/network-manager-backup.json"
MANAGED_BY = INSTALLER_DIRECTORY + "/managed-by"
BACKUP_SCHEMA_VERSION = 1
BACKUP_MODE = 0o600
MARKER_MODE = 0o600
CONTROL_LOCK = "/var/lib/mosdns/runtime/control.lock"
LOCK_MODE = 0o640
DISPATCHER_SCRIPT = "/etc/NetworkManager/dispatcher.d/no-wait.d/10-mosdns-dhcp-bridge"
DISPATCHER_MODE = 0o755
POLICY_CONFIG = "/etc/mosdns/policy.yaml"
CONFFILE = "/etc/mosdns/cloudflare.txt"
FORCE_ECH = "/etc/mosdns/force-ech-domains.txt"
DNS_RECORD_FILE = "/etc/mosdns/cloudfront-domains.yaml"
DHCP_STATE_FILE = "/run/mosdns/dhcp-upstreams.json"
PREFIX_LIST = "/var/lib/mosdns/lists/cloudflare-prefixes.txt"
RUNTIME_STATE = "/var/lib/mosdns/runtime/optimizer-state.json"
SIBLING_DISPATCHER = "/etc/NetworkManager/dispatcher.d/no-wait.d/10-somebody-elses-hook"
SIBLING_DISPATCHER_BLOCKING = "/etc/NetworkManager/dispatcher.d/20-somebody-elses-hook"

UUID = "11111111-1111-1111-1111-111111111111"
CONNECTION_NAME = "Wired connection 1"
DEVICE = "ens33"

RESOLVER_UNIT = "dnscrypt-proxy.service"
ROUTER_UNIT = "mosdns-router.service"
OPTIMIZER_TIMER = "mosdns-cdn-optimizer.timer"
HEALTH_TIMER = "mosdns-cdn-health.timer"
LIST_TIMER = "mosdns-list-check.timer"
# The watchdog's timer is here for a reason the other three do not share, and the
# cases below exercise it as one of the four: it is the only unit in this package
# that CHANGES the machine by itself, so an uninstall that stopped three timers
# and left it running would leave an unattended `emergency-rollback` on a machine
# whose connection no longer carries the record it restores. It is stopped first
# for the same reason `emergency_rollback` refuses to guess at a value.
WATCHDOG_TIMER = "mosdns-watchdog.timer"
PROJECT_TIMERS = (OPTIMIZER_TIMER, HEALTH_TIMER, LIST_TIMER, WATCHDOG_TIMER)
# The watchdog's SERVICE, stopped with the timers and for the same reason plus
# one. A timer only STARTS a unit, so stopping the timer does not stop a run the
# timer has already started -- and an uninstall landing inside a watchdog run
# (up to `WATCHDOG_ACTION_TIMEOUT_SECONDS`, because the action reactivates a
# NetworkManager connection) would restore the connection underneath that run.
# The window is narrow and the consequences honest, and one line in the sequence
# is the whole of the fix.
WATCHDOG_SERVICE = "mosdns-watchdog.service"
STOPPED_ONESHOT = (WATCHDOG_SERVICE,)
# The two units are stopped router first. At this point in an uninstall the
# machine's DNS is not ours any more, so neither order opens a window; the reason
# to name one is that it is the order the install's own rollback uses, and two
# orders for the same decision is one more thing to get wrong.
STOPPED_UNITS = (ROUTER_UNIT, RESOLVER_UNIT)

DNS_PORT = 53
RESOLVER_PORT = 15353
LOCAL_DNS = "127.0.0.1"
RESOLVED_STUB = "127.0.0.53"
INSTALL_PROBE_NAME = "install-probe.example"

IPV4_IGNORE = "ipv4.ignore-auto-dns"
IPV6_IGNORE = "ipv6.ignore-auto-dns"
IPV4_DNS = "ipv4.dns"
IPV6_DNS = "ipv6.dns"
RECORDED_PROPERTIES = (IPV4_IGNORE, IPV6_IGNORE, IPV4_DNS, IPV6_DNS)
# The three properties this install sets, and the three values it owns on a
# machine it has just installed onto.
OUR_VALUES = {IPV4_IGNORE: "yes", IPV6_IGNORE: "yes", IPV4_DNS: LOCAL_DNS}
# What the backup recorded on the fixture machine. `ipv4.dns` is a real address
# rather than an empty list because a restore that has to put a real value back is
# the case; the empty list is the case for the quoting in the report.
DHCP_UPSTREAM = "192.0.2.53"
RECORDED_RAW = {
    IPV4_IGNORE: "no",
    IPV6_IGNORE: "no",
    IPV4_DNS: DHCP_UPSTREAM,
    IPV6_DNS: "",
}
# The order the profile is put back in: newest change first, which is the order
# the install's own rollback uses, and then the reactivation, which is what makes
# the restored values live.
RESTORE_ORDER = ((IPV4_DNS, DHCP_UPSTREAM), (IPV6_IGNORE, "no"), (IPV4_IGNORE, "no"))

MODIFY = ("nmcli", "connection", "modify")
CONNECTION_UP = ("nmcli", "connection", "up")
PROPERTY_READ = ("nmcli", "-g")
RESOLVECTL_DNS = ("resolvectl", "dns", DEVICE)
DAEMON_RELOAD = ("systemctl", "daemon-reload")

POLICY_BODY = "schema_version: 1\ncdn:\n  provider: cloudflare\nech:\n  enabled: true\n"
# The words the report uses for a value it could not read, and for a list that is
# empty. Both are restated rather than imported: the report is a thing an
# operator reads, and its wording is part of what these tests hold.
COULD_NOT_BE_READ = "(could not be read)"
UNSET = "(unset)"
POLICY_DIGEST = hashlib.sha256(POLICY_BODY.encode("utf-8")).hexdigest()
CREATED_AT = "2026-09-27T09:20:00Z"
OBSERVED_AT = "2026-09-27T09:15:00Z"

# The prober's two answers, spelled out rather than read from the module -- a
# fixture that asked the module what its own answer is would agree with it
# whatever it did. The type is the module's, because the return type IS the
# interface a scripted probe has to stand in for.
SERVFAIL = "servfail"
REFUSED = "refused"
SILENT = "silent"
HEALTHY = "healthy"


def answer(answered, resolves):
    return installer.Answer(answered=answered, resolves=resolves)


ANSWER_SHAPES = {
    HEALTHY: answer(True, True),
    SERVFAIL: answer(True, False),
    REFUSED: answer(True, False),
    SILENT: answer(False, False),
}

# The verbs that change something, as against the verbs that ask. "No systemctl
# ran" is the wrong shape for a refusal: the ownership check asks systemd
# read-only questions, so what has to be absent is a set of verbs, not a program.
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


def restore_commands(uuid=UUID, recorded=None):
    """The four commands that put a connection back by hand, in order.

    Restated here rather than taken from the module, because this is the string
    an operator is told to copy and a test that compared the module's own
    rendering with itself would prove nothing.
    """
    recorded = recorded or RECORDED_RAW
    commands = [
        " ".join([*MODIFY, uuid, prop, recorded[prop]]) if recorded[prop] else
        " ".join([*MODIFY, uuid, prop, "''"])
        for prop in RECORDED_PROPERTIES
    ]
    commands.append(" ".join([*CONNECTION_UP, uuid]))
    return commands


def backup_document(
    uuid=UUID,
    device=DEVICE,
    original=None,
    schema=BACKUP_SCHEMA_VERSION,
    managed_by=MANAGED_BY_VALUE,
    digest=POLICY_DIGEST,
    version="1.4.2",
):
    """The document the install writes, in the shape it writes it."""
    raw = original or dict(RECORDED_RAW)
    # An address list is recorded as a list and a `yes`/`no` as the string, which
    # is the shape the install writes and the shape a restore can put back.
    value = {
        prop: (
            [token for token in re.split(r"[,;\s]+", raw[prop]) if token]
            if prop in (IPV4_DNS, IPV6_DNS)
            else raw[prop]
        )
        for prop in RECORDED_PROPERTIES
    }
    return {
        "schema_version": schema,
        "managed_by": managed_by,
        "package": PACKAGE_NAME,
        "package_version": version,
        "created_at": CREATED_AT,
        "config_path": POLICY_CONFIG,
        "config_sha256": digest,
        "connection": {
            "uuid": uuid,
            "name": CONNECTION_NAME,
            "type": "802-3-ethernet",
            "device": device,
        },
        "original": {prop: {"raw": raw[prop], "value": value[prop]} for prop in RECORDED_PROPERTIES},
        "dhcp": {
            "state_file": DHCP_STATE_FILE,
            "interface": device,
            "connection_uuid": uuid,
            "upstreams": [DHCP_UPSTREAM],
            "source": "dhcp4",
            "generation": 1,
            "observed_at": OBSERVED_AT,
        },
    }


def row_for(report, prop):
    """The one line of a manual recovery report that is about ``prop``.

    Read back out of the report rather than rebuilt, so the assertion is about
    the report an operator receives. The column width is the only thing a test
    that rebuilt the line would be able to fake, and it is the one thing in the
    row that carries no information.
    """
    rows = [line for line in report.splitlines() if line.strip().startswith(prop)]
    assert len(rows) == 1, f"the report has {len(rows)} rows about {prop}: {rows}"
    return rows[0]


def purges(path):
    """Whether one snapshot entry is the state directory or something inside it.

    The directory itself counts as well as its contents, because `rglob` stops
    descending once the directory is gone and the assertion is about the set of
    paths that disappeared, not about the leaves it happened to reach.
    """
    state = STATE_DIRECTORY.lstrip("/")
    return path == state or path.startswith(state + "/")


def function_source(name):
    """One function's own text out of the module, comments and docstring included.

    Read with `ast` rather than by scanning for the name, so a docstring that
    happens to mention another function's name cannot make the reader believe the
    function under test says something it does not. And the DOCSTRING is kept,
    because that is the text this assertion is about.
    """
    tree = ast.parse(SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(SOURCE, node) or ""
    raise AssertionError(f"{MODULE} has no function named {name}")


def snapshot(root):
    """Every path under ``root``, and what it is.

    A claim about "what an uninstall removed" has to be a claim about the whole
    tree, or it is a claim about the paths a test remembered to check. Symlinks
    are recorded with their target so that removing one, rather than what it
    points at, is visible.
    """
    entries = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            entries[relative] = "link " + os.readlink(path)
        elif path.is_dir():
            entries[relative] = "dir"
        else:
            entries[relative] = "file"
    return entries


class FakeRunner:
    """A CommandRunner that records argument arrays and answers prepared ones.

    Only an array the test prepared produces output, so a command that must not
    run answers empty and is visible in ``commands``. A string is refused
    outright rather than recorded: in production a string reaching the runner is
    a string a shell would have interpreted, and the report this file's tests
    check is full of text an operator will paste, so a program that built one
    would be one paste away from running it.
    """

    def __init__(self, outputs=None, returncodes=None, stderr="", fail=(), record=None):
        self.outputs = {tuple(key): value for key, value in (outputs or {}).items()}
        self.returncodes = {tuple(key): value for key, value in (returncodes or {}).items()}
        self.stderr = stderr
        self.fail = {tuple(command) for command in fail}
        self.record = record
        self.calls = []

    def run(self, args, check=True):
        if isinstance(args, (str, bytes)):
            raise TypeError(
                "a command must be an argument array, never a string a shell would "
                f"have to interpret: {args!r}"
            )
        command = tuple(args)
        self.calls.append(command)
        if self.record is not None:
            self.record(command)
        if command in self.fail:
            raise subprocess.CalledProcessError(1, list(command), "", "injected failure")
        code = self.returncodes.get(command, 0)
        if code != 0 and check:
            raise subprocess.CalledProcessError(code, list(command), "", self.stderr)
        return subprocess.CompletedProcess(args=list(command), returncode=code, stdout=self.answer(command), stderr=self.stderr)

    def answer(self, command):
        return self.outputs.get(command, "")


class UninstallFixture(unittest.TestCase):
    """A fake root holding an installed machine, and a runner that answers it.

    The machine starts out in the state a successful install leaves: the
    ownership marker, the root-only backup, the dispatcher hook, a control lock
    in the state directory, the operator's own configuration, and a connection
    whose properties hold exactly the three values this package set.
    """

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.probes = []
        self.overrides = {}
        self.failing = set()
        self.codes = {}
        # The recording list is created here rather than lazily by the property
        # that reads it. `record` appends to `self.commands`, and a getter that
        # returned a fresh `[]` for a list that does not exist yet would throw
        # every recorded command away -- so a case that runs the module without
        # going through `run_uninstall` (which resets it) recorded nothing and
        # asserted nothing.
        self._commands = []
        self.installed()
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

    def installed(self):
        """Put the fake root into the state a successful install leaves."""
        self.write(POLICY_CONFIG, POLICY_BODY, mode=0o644)
        self.write(CONFFILE, "# the operator's own candidate list\nexample.test\n", mode=0o644)
        self.write(FORCE_ECH, "# domains this router forces ECH for\n", mode=0o644)
        self.write(DNS_RECORD_FILE, "profiles: {}\n", mode=0o644)
        self.write(DISPATCHER_SCRIPT, "#!/bin/sh\nexec python3 -m mosdns_dhcp_bridge.cli \"$@\"\n", mode=DISPATCHER_MODE)
        self.write(SIBLING_DISPATCHER, "#!/bin/sh\nexit 0\n", mode=DISPATCHER_MODE)
        self.write(SIBLING_DISPATCHER_BLOCKING, "#!/bin/sh\nexit 0\n", mode=DISPATCHER_MODE)
        self.write(CONTROL_LOCK, "", mode=LOCK_MODE)
        self.write(PREFIX_LIST, "173.245.48.0/20\n", mode=0o640)
        self.write(RUNTIME_STATE, "{}\n", mode=0o640)
        self.write(
            DHCP_STATE_FILE,
            json.dumps(
                {
                    "schema_version": 1,
                    "generation": 1,
                    "interface": DEVICE,
                    "connection_uuid": UUID,
                    "upstreams": [DHCP_UPSTREAM],
                    "observed_at": OBSERVED_AT,
                    "source": "dhcp4",
                    "last_good": True,
                },
                indent=2,
            )
            + "\n",
            mode=0o640,
        )
        self.write(MANAGED_BY, MANAGED_BY_VALUE + "\n", mode=MARKER_MODE)
        self.write_backup()

    def write_backup(self, document=None, mode=BACKUP_MODE):
        document = document if document is not None else backup_document()
        return self.write(BACKUP_PATH, json.dumps(document, indent=2, sort_keys=True) + "\n", mode=mode)

    def remove_marker(self):
        self.rooted(MANAGED_BY).unlink()

    def snapshot(self):
        return snapshot(self.root)

    # -- the runner and the probe ----------------------------------------

    def good_runner(self, outputs=None, returncodes=None, fail=()):
        """A runner answering exactly what an installed machine answers."""
        answers = {}
        for prop, value in OUR_VALUES.items():
            answers[PROPERTY_READ + (prop, "connection", "show", UUID)] = value + "\n"
        answers[PROPERTY_READ + (IPV6_DNS, "connection", "show", UUID)] = "\n"
        for unit in (*PROJECT_TIMERS, *STOPPED_ONESHOT, *STOPPED_UNITS):
            answers[("systemctl", "is-active", unit)] = "active\n"
        answers[RESOLVECTL_DNS] = f"Link 2 ({DEVICE}): {DHCP_UPSTREAM}\n"
        answers.update(self.overrides)
        answers.update(outputs or {})
        codes = dict(self.codes)
        codes.update(returncodes or {})
        runner = FakeRunner(
            outputs=answers,
            returncodes=codes,
            fail=list(fail) + list(self.failing),
            record=self.record,
        )
        self.runner = runner
        return runner

    def record(self, command):
        self.commands.append(command)

    def property_value(self, prop, value):
        """Make the connection report ``value`` for ``prop``."""
        self.overrides[PROPERTY_READ + (prop, "connection", "show", UUID)] = value

    def unit_answers(self, answer="active\n"):
        for unit in (*PROJECT_TIMERS, *STOPPED_ONESHOT, *STOPPED_UNITS):
            self.overrides[("systemctl", "is-active", unit)] = answer

    def resolvectl_fails(self, code=1, output=""):
        """Make the read that proves the device took the restored values fail.

        A status and no output is the shape of a read that did not happen, and
        `nmcli` and `resolvectl` both answer a question they cannot answer with a
        status rather than with a sentence. Measured on real resolved 24.04: a
        device that does not exist exits 1 with nothing on standard output.
        """
        self.codes[RESOLVECTL_DNS] = code
        self.overrides[RESOLVECTL_DNS] = output

    def probe_for(self, stub=HEALTHY, local=HEALTHY):
        """A DNS probe that answers from a script and records what it was asked.

        The stub and the local resolver are separate keys because they are
        separate questions: after a restore the machine's path is through
        resolved's stub, and a rollback that reported success on a local resolver
        answering while the stub was silent would be reporting the wrong thing.
        """

        def probe(address, port):
            self.probes.append((address, port))
            shape = stub if (address, port) == (RESOLVED_STUB, DNS_PORT) else local
            return ANSWER_SHAPES[shape]

        return probe

    @property
    def commands(self):
        return getattr(self, "_commands", [])

    @commands.setter
    def commands(self, value):
        self._commands = value

    def run_uninstall(self, purge=False, runner=None, probe=None):
        self._commands = []
        runner = runner or self.good_runner()
        return installer.uninstall(self.root, runner, purge=purge, probe=probe or self.probe_for())

    def run_rollback(self, runner=None, probe=None):
        self._commands = []
        runner = runner or self.good_runner()
        return installer.emergency_rollback(self.root, runner, probe=probe or self.probe_for())

    def run_cli(self, *arguments, runner=None, probe=None):
        """The command as a person runs it, with the runner and the probe injected.

        On the base fixture rather than on the CLI's own class, because the
        ordering and the refusals are properties of the output and a case that
        needs the output should not have to reach into another class for it.
        """
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = installer.main(
                list(arguments),
                runner or self.good_runner(),
                root=self.root,
                probe=probe or self.probe_for(),
            )
        return status, out.getvalue(), err.getvalue()

    # -- assertions -------------------------------------------------------

    def changing(self, command):
        """Whether one command changes the machine's configuration."""
        if command[:1] == ("systemctl",) and len(command) > 1:
            return command[1] in CHANGE_VERBS
        if command[:2] == ("nmcli", "connection") and len(command) > 2:
            return command[2] in CHANGE_VERBS
        return False

    def assertNothingChanged(self, why):
        changed = [command for command in self.commands if self.changing(command)]
        self.assertEqual(changed, [], f"{why}: {changed}")

    def assertNothingTouched(self, before, why):
        after = self.snapshot()
        self.assertEqual(
            sorted(set(before) - set(after)),
            [],
            f"{why}: these paths were removed: {sorted(set(before) - set(after))}",
        )

    def removed_paths(self, before):
        return sorted(set(before) - set(self.snapshot()))

    def restored(self):
        self.assertTrue(self.result.ok, f"the uninstall did not finish: {self.result.error}")
        self.assertEqual(self.result.refusals, [])
        return self.result

    def refused(self):
        self.assertFalse(self.result.ok, "a refusal the fixture did not provoke reported success")
        self.assertNotEqual(self.result.refusals, [], "a refusal with nothing named in it")
        return self.result

    def refuse_with(self, **kwargs):
        """Run the uninstall expecting a refusal, and assert it changed nothing.

        Both halves, every time: a refusal that changed something is a bug, and a
        test that only reads the exit status would not notice.
        """
        before = self.snapshot()
        self.result = self.run_uninstall(**kwargs)
        self.assertNothingChanged(f"a refusal changed the machine: {self.result.refusals}")
        self.assertNothingTouched(before, f"a refusal wrote to the filesystem: {self.result.refusals}")
        return self.refused()

    # -- the sequence -----------------------------------------------------

    def property_reads(self):
        return [PROPERTY_READ + (prop, "connection", "show", UUID) for prop in RECORDED_PROPERTIES]

    def full_sequence(self, restore=None):
        """Every command array a successful plain uninstall runs, in order."""
        restore = RESTORE_ORDER if restore is None else restore
        return (
            self.property_reads()
            + [("systemctl", "is-active", timer) for timer in PROJECT_TIMERS]
            + [("systemctl", "stop", timer) for timer in PROJECT_TIMERS]
            + [("systemctl", "is-active", unit) for unit in STOPPED_ONESHOT]
            + [("systemctl", "stop", unit) for unit in STOPPED_ONESHOT]
            + [MODIFY + (UUID, prop, value) for prop, value in restore]
            + [CONNECTION_UP + (UUID,), RESOLVECTL_DNS]
            + [("systemctl", "is-active", unit) for unit in STOPPED_UNITS]
            + [("systemctl", "stop", unit) for unit in STOPPED_UNITS]
            + [DAEMON_RELOAD]
        )


class UnreadableValueTests(UninstallFixture):
    """A value this program could not read is UNREADABLE, not SOMEONE_ELSE.

    The two consumers of that question -- the refusal reasons and the report's
    command block -- were written in the same round and did not agree about it.
    `_shown_now` read a blank `yes`/`no` as "could not be read"; the command
    block's `_changed_after_the_install` knew only `None`. So on the refusal path
    one property got three accounts of itself in one report:

      * the refusal said "could not be read: it came back empty",
      * the table's row said `now (could not be read)`,
      * and the block said `leave ipv4.ignore-auto-dns at (unset) -- changed after
        the install, ... this program refused to do`.

    The last is the false one. "Changed after the install" is a claim about the
    MACHINE, and it is asserted about a value nobody read.
    """

    def test_a_blank_read_on_the_refusal_path_makes_no_claim_about_the_machine(self):
        self.property_value(IPV4_IGNORE, "")
        before = self.snapshot()
        self.result = self.run_uninstall()
        self.assertNothingChanged("a refusal over an unreadable property")
        self.assertNothingTouched(before, "a refusal over an unreadable property")
        self.refused()
        report = self.result.manual_recovery or ""
        self.assertNotIn(
            f"leave {IPV4_IGNORE}",
            report,
            "the report claims somebody changed a property this program could not read",
        )
        self.assertNotIn(
            "changed after the install",
            report,
            "the report asserts a change after the install about a value it could not read",
        )

    def test_the_report_does_not_contradict_its_own_refusal_reason(self):
        self.property_value(IPV4_IGNORE, "")
        result = self.refuse_with()
        report = result.manual_recovery or ""
        reasons = " ".join(result.refusals)
        self.assertIn("could not be read", reasons, "the refusal reason has to say what happened")
        self.assertIn(
            f"{IPV4_IGNORE}    recorded {RECORDED_RAW[IPV4_IGNORE]}    now {COULD_NOT_BE_READ}",
            report,
            "the row has to agree with the refusal reason about the same property",
        )

    def test_an_unreadable_property_is_handed_the_recorded_value_not_a_leave(self):
        # The instruction for a value nobody read is "put it back to what the
        # record says", not "leave it". It is a guess in neither direction: the
        # refusal above it says the read failed, and the record is the only
        # account of the machine there is.
        self.property_value(IPV4_IGNORE, "")
        report = self.refuse_with().manual_recovery or ""
        self.assertIn(
            f"nmcli connection modify {UUID} {IPV4_IGNORE} {RECORDED_RAW[IPV4_IGNORE]}",
            report,
            "an unreadable property has no value to leave, so the record is what the operator needs",
        )

    def test_a_property_read_that_could_not_run_says_so(self):
        # The other unreadable shape, and the one half of the merged refusal
        # message that had no coverage at all: the call RAISED rather than
        # printing nothing. The verdict is the same either way -- the table pins
        # both -- so this is about the wording, and about the report agreeing with
        # it.
        before = self.snapshot()
        self.result = self.run_uninstall(
            runner=self.good_runner(fail=[PROPERTY_READ + (IPV6_IGNORE, "connection", "show", UUID)])
        )
        self.assertNothingChanged("a refusal over a read that could not run")
        self.assertNothingTouched(before, "a refusal over a read that could not run")
        result = self.refused()
        reason = " ".join(result.refusals)
        self.assertIn(
            "did not run",
            reason,
            "the refusal has to say the call never happened, which is a different fact from one "
            "that printed nothing",
        )
        report = result.manual_recovery or ""
        self.assertIn(
            f"{IPV6_IGNORE}    recorded {RECORDED_RAW[IPV6_IGNORE]}    now {COULD_NOT_BE_READ}",
            report,
            "the row has to agree with the refusal reason about the same property",
        )
        self.assertNotIn(
            f"leave {IPV6_IGNORE}",
            report,
            "the report claims somebody changed a property whose read never ran",
        )
        self.assertNotIn("changed after the install", report)


class ValueSpaceTests(unittest.TestCase):
    """The whole value space, one table, all three consumers read from it.

    The two control tests that shipped in round 1 pinned the two ENDS: a machine
    nobody touched, and a value somebody deliberately changed. The unreadable
    middle is what went wrong, and a table over all four verdicts is what stops the
    next middle from being invented.

    Each row is `(property, value nmcli printed, our value, recorded value,
    verdict, the row's "now" text, whether the block leaves it)`. Every row feeds
    all three consumers: :func:`mosdns_installer._classify` for the verdict, the
    table's row for the "now" column, and the command block for the leave-or-write
    decision. A value one consumer classifies and another does not fails here.
    """

    # (prop, what nmcli printed, the value this install sets, the recorded value,
    #  verdict, the row's "now" text, whether the block leaves it)
    ROWS = (
        # -- a yes/no holding what this installation set: the commonest row on an
        #    installed machine, and the one a two-way rule got wrong.
        (IPV4_IGNORE, "yes", "yes", "no", "ours", "yes", False),
        (IPV6_IGNORE, "yes", "yes", "no", "ours", "yes", False),
        (IPV4_IGNORE, "yes", "yes", "yes", "ours", "yes", False),
        # -- a yes/no where the value this installation set IS the recorded one.
        #    The only row that can see the order of the classifier's first two
        #    questions, because it is the only one where the two answers differ.
        #    A machine that already ignored auto-DNS before the install lands
        #    here, and asking RECORDED first would call it untouched.
        # -- a yes/no already back where the record says.
        (IPV4_IGNORE, "no", "yes", "no", "recorded", "no", False),
        (IPV6_IGNORE, "no", "yes", "no", "recorded", "no", False),
        # -- a yes/no somebody set by hand.
        (IPV4_IGNORE, "maybe", "yes", "no", "somebody_else", "maybe", True),
        # -- a yes/no this program could not read. BOTH unreadable shapes: the
        #    call raised, and the call ran and printed nothing.
        (IPV4_IGNORE, None, "yes", "no", "unreadable", COULD_NOT_BE_READ, False),
        (IPV4_IGNORE, "", "yes", "no", "unreadable", COULD_NOT_BE_READ, False),
        (IPV6_IGNORE, "", "yes", "no", "unreadable", COULD_NOT_BE_READ, False),
        # -- an address list holding what this installation set.
        (IPV4_DNS, LOCAL_DNS, LOCAL_DNS, DHCP_UPSTREAM, "ours", LOCAL_DNS, False),
        # -- an address list already back, with an empty recorded list. This is
        #    the row that separates "the list is empty" from "the read produced
        #    nothing": the first is a value and the second is not.
        (IPV6_DNS, "", None, "", "recorded", UNSET, False),
        # -- an address list somebody set by hand.
        (IPV4_DNS, "192.0.2.99", LOCAL_DNS, DHCP_UPSTREAM, "somebody_else", "192.0.2.99", True),
        (IPV6_DNS, "2001:db8::1", None, "", "somebody_else", "2001:db8::1", True),
        # -- the same property, a list this install never set and cannot be read
        #    from. The third value of a property is what the two ends of the table
        #    do not reach.
        (IPV6_DNS, None, None, "", "unreadable", COULD_NOT_BE_READ, False),
        # -- a list that CONTAINS what this install set and one more address,
        #    which is a user adding a resolver and not a leftover.
        (IPV4_DNS, f"{LOCAL_DNS},203.0.113.9", LOCAL_DNS, DHCP_UPSTREAM, "somebody_else",
         f"{LOCAL_DNS},203.0.113.9", True),
        # -- an address list the call raised on. A blank one is a real value --
        #    the empty list -- and here the recorded list is NOT empty, so the
        #    empty one is somebody's edit rather than a leftover. That is the row
        #    that separates "the list is empty" from "the read produced nothing",
        #    and both from "the list is empty because this install never had one"
        #    (the ipv6 row above).
        (IPV4_DNS, None, LOCAL_DNS, DHCP_UPSTREAM, "unreadable", COULD_NOT_BE_READ, False),
        (IPV4_DNS, "", LOCAL_DNS, DHCP_UPSTREAM, "somebody_else", UNSET, True),
    )

    def original_for(self, recorded):
        """The backup's ``original`` with one property's recorded value replaced.

        Built from the row's own recorded value, so a row is a complete statement
        about one value rather than half a statement about the default fixture.
        """
        recorded_for = {
            IPV4_IGNORE: "no",
            IPV6_IGNORE: "no",
            IPV4_DNS: DHCP_UPSTREAM,
            IPV6_DNS: "",
        }
        recorded_for[recorded[0]] = recorded[3]
        return {
            prop: {
                "raw": value,
                "value": value if prop in (IPV4_IGNORE, IPV6_IGNORE) else [
                    token for token in value.split(",") if token
                ],
            }
            for prop, value in recorded_for.items()
        }

    def test_the_three_consumers_agree_about_every_value(self):
        for row in self.ROWS:
            prop, printed, _ours, _recorded, verdict, shown, _leaves = row
            with self.subTest(prop=prop, printed=printed, recorded=row[3]):
                original = self.original_for(row)
                classified = installer._classify(prop, printed, original[prop]["raw"])
                self.assertEqual(
                    classified,
                    verdict,
                    f"{prop} printed {printed!r} against a recorded {original[prop]['raw']!r} was "
                    f"classified as {classified!r}",
                )
                self.assertEqual(
                    installer._shown_now(prop, printed, original[prop]["raw"]),
                    shown,
                    f"{prop} printed {printed!r} is shown as something other than {shown!r}",
                )

    def test_the_report_row_and_the_command_block_come_from_the_same_rows(self):
        for row in self.ROWS:
            prop, printed, _ours, _recorded, _verdict, shown, leaves = row
            with self.subTest(prop=prop, printed=printed, recorded=row[3]):
                original = self.original_for(row)
                observed = {
                    other: ("" if other in (IPV4_DNS, IPV6_DNS) else "yes")
                    for other in RECORDED_PROPERTIES
                }
                observed[prop] = printed
                report = installer.manual_recovery_report(
                    UUID, original, observed, ["a test drove this report"]
                )
                rows = [line for line in report.splitlines() if line.strip().startswith(prop)]
                self.assertEqual(len(rows), 1, f"the report has {len(rows)} rows about {prop}: {rows}")
                self.assertTrue(
                    rows[0].endswith(shown),
                    f"the row for {prop} printed {printed!r} ends {rows[0]!r}, not with {shown!r}",
                )
                self.assertEqual(
                    f"leave {prop} " in report,
                    leaves,
                    f"the block's decision for {prop} printed {printed!r} is the wrong one",
                )

    def test_the_two_statements_about_a_blank_value_point_at_each_other(self):
        """The module's one classifier and its one second statement, said once each.

        The ledger has carried this as a deferred minor for two rounds: the module
        has three ways of asking whether a blank `yes`/`no` is a value, and a
        reviewer has to read both docstrings to learn that the difference is
        deliberate. The fix is not a refactor -- merging them would be wrong, and
        the two docstrings now say why -- it is that each one says it, and this
        holds them to it in both directions so neither can be edited into silence.
        """
        classify = function_source("_classify")
        record = function_source("_original_property")
        for name, body in (("_classify", classify), ("_original_property", record)):
            with self.subTest(function=name):
                self.assertIn(
                    "_original_property" if name == "_classify" else "_classify",
                    body,
                    f"{name} does not name the other statement, so the asymmetry is stated in one "
                    "place only",
                )
                self.assertIn(
                    "question", body.lower(),
                    f"{name} states an asymmetry without saying the two answer different questions, "
                    "which is the only reason for having two",
                )
                # And it must say WHY each side differs, not merely that they do:
                # a comment that says "these differ" without saying how is the note
                # this minor was filed about.
                self.assertIn("nmcli", body.lower())

    def test_the_table_covers_every_verdict_and_both_unreadable_shapes(self):
        verdicts = {row[4] for row in self.ROWS}
        self.assertEqual(
            verdicts,
            {"ours", "recorded", "somebody_else", "unreadable"},
            f"the value-space table does not exercise every verdict: {sorted(verdicts)}",
        )
        self.assertTrue(
            any(row[2] == row[3] for row in self.ROWS),
            "the table has no row where the value this install sets equals the recorded one, so it "
            "cannot see which of the first two questions is asked first",
        )
        # The one row that can see the order of the first two questions: a value
        # this install set that IS the recorded one. Without it, asking RECORDED
        # before OURS passes every other row, because on all of them only one of
        # the two can be true.
        yes_no = (IPV4_IGNORE, IPV6_IGNORE)
        unreadable_yes_no = {
            row[1] for row in self.ROWS if row[0] in yes_no and row[4] == "unreadable"
        }
        self.assertEqual(
            unreadable_yes_no,
            {None, ""},
            "the table has to cover BOTH shapes of an unreadable value, because a blank answer "
            "and a call that raised are the two the drift was about",
        )
        # The same pair, for an address list, where the two shapes mean DIFFERENT
        # things: a raised call is unreadable and a blank answer is the empty list.
        blank_lists = {
            row[1]: row[4]
            for row in self.ROWS
            if row[0] in (IPV4_DNS, IPV6_DNS) and row[1] in (None, "")
        }
        self.assertEqual(
            blank_lists.get(None),
            "unreadable",
            "a list whose call raised is unreadable",
        )
        self.assertIn(
            blank_lists.get(""),
            ("recorded", "somebody_else"),
            "a blank list is a value -- an empty one -- and never a failed read",
        )

    def test_the_table_is_still_a_whole_value_space(self):
        # A table that can be cut for brevity is a table that stops being the
        # space. The two shapes that drifted are named here rather than left to
        # the row count, because a count can be met by adding duplicates.
        self.assertGreaterEqual(
            len(self.ROWS),
            12,
            "the value-space table has shrunk below the whole space it enumerates",
        )
        self.assertEqual(
            len({(row[0], row[1], row[3]) for row in self.ROWS}),
            len(self.ROWS),
            "the table has duplicate rows, so it is shorter than it looks",
        )
        for prop in (IPV4_IGNORE, IPV6_IGNORE, IPV4_DNS, IPV6_DNS):
            with self.subTest(prop=prop):
                self.assertGreaterEqual(
                    len([row for row in self.ROWS if row[0] == prop]),
                    3,
                    f"{prop} is in the table with fewer than three values, so the space it spans "
                    "is not the space",
                )


class ModuleSurfaceTests(unittest.TestCase):
    """The interface exists at all, before anything is asserted about it."""

    def test_the_module_offers_an_uninstall_and_an_emergency_rollback(self):
        for name in ("uninstall", "emergency_rollback"):
            self.assertTrue(
                hasattr(installer, name),
                f"mosdns_installer.py has no {name}(): the whole of this task is missing",
            )

    def test_the_two_new_statuses_are_distinct_from_each_other_and_from_the_install(self):
        for name in ("EXIT_OWNERSHIP_REFUSED", "EXIT_RESTORE_INCOMPLETE"):
            self.assertTrue(
                hasattr(installer, name),
                f"the module has no {name}: an operator cannot tell a refusal from a "
                "half-finished restore, and those are different machines",
            )
        statuses = [
            installer.EXIT_OK,
            installer.EXIT_REFUSED,
            installer.EXIT_USAGE,
            installer.EXIT_INSTALL_FAILED,
            installer.EXIT_ROLLBACK_FAILED,
            installer.EXIT_OWNERSHIP_REFUSED,
            installer.EXIT_RESTORE_INCOMPLETE,
        ]
        self.assertEqual(
            len(set(statuses)),
            len(statuses),
            f"two statuses share a number, so a script cannot tell them apart: {statuses}",
        )

    def test_the_results_carry_the_manual_recovery_report(self):
        # The report is the deliverable of a refusal, so it has to be somewhere a
        # caller can reach: a field, not a line somebody has to scrape out of a
        # message and re-parse.
        for name in ("UninstallResult", "RollbackResult"):
            self.assertIn(
                "manual_recovery",
                getattr(installer, name)._fields,
                f"{name} has nowhere to put the report, so a caller would have to parse prose",
            )


class OwnershipRefusalTests(UninstallFixture):
    """Nothing is restored that this installation cannot prove it owns."""

    def test_it_refuses_when_the_marker_is_absent(self):
        self.remove_marker()
        result = self.refuse_with()
        reason = " ".join(result.refusals)
        self.assertIn(MANAGED_BY, reason)
        self.assertIn(
            MANAGED_BY_VALUE,
            reason,
            "the refusal has to say what a marker would have said, or an operator cannot tell "
            "which of the two files it should look at",
        )

    def test_it_refuses_a_marker_that_names_another_program(self):
        self.write(MANAGED_BY, "unbound\n", mode=MARKER_MODE)
        result = self.refuse_with()
        self.assertIn("unbound", " ".join(result.refusals))
        self.assertIn(MANAGED_BY_VALUE, " ".join(result.refusals))

    def test_it_refuses_a_marker_that_is_not_a_file(self):
        self.rooted(MANAGED_BY).unlink()
        self.rooted(MANAGED_BY).mkdir()
        self.refuse_with()

    def test_it_refuses_when_the_backup_is_absent(self):
        # The record is gone but the CLAIM is not, and that is the half that
        # matters: this machine says the DNS is ours, so it may still be using
        # 127.0.0.1 and there is nothing to put back. (Both absent is a different
        # machine, and a different verdict -- see NeverAppliedRemovalTests.)
        self.rooted(BACKUP_PATH).unlink()
        result = self.refuse_with()
        self.assertIn(BACKUP_PATH, " ".join(result.refusals))
        self.assertIn("no", " ".join(result.refusals).lower())

    def test_it_refuses_a_backup_that_is_not_a_document(self):
        self.write(BACKUP_PATH, "this is not json\n", mode=BACKUP_MODE)
        result = self.refuse_with()
        self.assertIn(BACKUP_PATH, " ".join(result.refusals))

    def test_it_refuses_a_backup_of_an_unknown_schema(self):
        self.write_backup(backup_document(schema=2))
        result = self.refuse_with()
        self.assertIn("2", " ".join(result.refusals))
        self.assertIn(str(BACKUP_SCHEMA_VERSION), " ".join(result.refusals))

    def test_it_refuses_a_backup_of_another_project(self):
        self.write_backup(backup_document(managed_by="something-else"))
        result = self.refuse_with()
        self.assertIn("something-else", " ".join(result.refusals))

    def test_it_refuses_a_backup_that_names_no_connection(self):
        self.write_backup(backup_document(uuid=""))
        result = self.refuse_with()
        self.assertIn("connection", " ".join(result.refusals).lower())

    def test_it_refuses_a_backup_that_names_no_device(self):
        self.write_backup(backup_document(device=""))
        result = self.refuse_with()
        self.assertIn("device", " ".join(result.refusals).lower())

    def test_it_refuses_a_backup_that_did_not_record_the_property_it_would_restore(self):
        document = backup_document()
        del document["original"][IPV4_DNS]
        self.write_backup(document)
        result = self.refuse_with()
        self.assertIn(IPV4_DNS, " ".join(result.refusals))

    def test_it_refuses_a_recorded_value_of_a_shape_it_cannot_put_back(self):
        # A refusal's own report renders commands out of these values, so a value
        # of the wrong shape has to be a refusal with a sentence in it and not a
        # crash in the middle of telling an operator what to run.
        cases = {
            IPV4_DNS: "192.0.2.53",
            IPV4_IGNORE: ["no"],
            IPV6_IGNORE: None,
            IPV6_DNS: {"raw": "", "value": 3},
        }
        for prop, value in cases.items():
            with self.subTest(prop=prop, value=value):
                self.setUp()
                document = backup_document()
                document["original"][prop]["value"] = value
                self.write_backup(document)
                before = self.snapshot()
                self.result = self.run_uninstall()
                self.assertFalse(self.result.ok, f"a {prop} recorded as {value!r} was restored from")
                self.assertIn(prop, " ".join(self.result.refusals))
                self.assertNothingChanged(f"a backup with a {prop} of {value!r} was acted on")
                self.assertNothingTouched(before, "a refused backup was written over")
                self.assertNotEqual(self.result.manual_recovery, "", "the refusal has no report")

    def test_it_refuses_a_connection_it_cannot_read(self):
        # `nmcli -g` on a connection that does not exist exits non-zero and prints
        # nothing, and one of the two properties it is asked for here has no empty
        # value at all. So a blank answer for it is a read that produced nothing --
        # the connection is gone, or nmcli failed -- and neither is a value to
        # restore over.
        self.property_value(IPV4_IGNORE, "")
        result = self.refuse_with()
        self.assertIn("could not be read", " ".join(result.refusals))

    def test_an_empty_recorded_address_list_is_a_value_and_not_a_failed_read(self):
        # The other half of the unreadable-connection case, and the reason the two
        # are separated. A machine with no manual DNS at all has an empty
        # `ipv4.dns`, and putting that back is a command whose value is the empty
        # string -- which is a real restoration, not a read that produced nothing.
        self.write_backup(backup_document(original={**RECORDED_RAW, IPV4_DNS: ""}))
        self.result = self.run_uninstall()
        self.assertTrue(
            self.result.ok, f"a lease-only machine could not be uninstalled: {self.result.error}"
        )
        self.assertIn(
            MODIFY + (UUID, IPV4_DNS, ""),
            self.commands,
            "the empty manual list was not put back, so a lease-only machine keeps 127.0.0.1",
        )

    def test_it_refuses_a_property_a_person_changed_after_the_install(self):
        # The properties with more than two values are the ones where a person
        # can leave the connection in a state that is neither what this package
        # set nor what the backup recorded. That third state is the only one this
        # program must refuse, and it is the case the plan's own review focus
        # names: an uninstall must not overwrite a connection the user changed
        # after the installation.
        changed = {IPV4_DNS: "192.0.2.99", IPV6_DNS: "2001:db8::1"}
        for prop, value in changed.items():
            with self.subTest(prop=prop):
                self.setUp()
                self.property_value(prop, value)
                result = self.refuse_with()
                self.assertIn(
                    prop,
                    " ".join(result.refusals),
                    f"a change to {prop} after the install is the one case this program must "
                    "refuse rather than undo, and the refusal did not name it",
                )
                self.assertIn(value, " ".join(result.refusals))

    def test_a_two_valued_property_holding_the_recorded_value_is_not_a_refusal(self):
        # `ignore-auto-dns` has two values, so a person who "changed" it has
        # necessarily put it back to what the backup recorded. There is no third
        # state to refuse, and none is needed: writing the recorded original over
        # the recorded original changes nothing, and the address property is what
        # catches a connection somebody actually re-pointed.
        for prop in (IPV4_IGNORE, IPV6_IGNORE):
            with self.subTest(prop=prop):
                self.setUp()
                self.property_value(prop, RECORDED_RAW[prop])
                self.result = self.run_uninstall()
                self.restored()
                self.assertNotIn(
                    MODIFY + (UUID, prop, RECORDED_RAW[prop]),
                    self.commands,
                    f"{prop} was written to even though it already held the recorded value",
                )

    def test_the_refusal_names_what_was_found_and_what_was_expected(self):
        self.property_value(IPV4_DNS, "192.0.2.99")
        result = self.refuse_with()
        reason = " ".join(result.refusals)
        self.assertIn("192.0.2.99", reason, "the value found on the machine")
        self.assertIn(LOCAL_DNS, reason, "the value this installation set")
        self.assertIn(DHCP_UPSTREAM, reason, "the value the backup recorded")

    def test_the_manual_recovery_report_carries_the_recorded_and_the_observed_values(self):
        self.property_value(IPV4_DNS, "192.0.2.99")
        result = self.refuse_with()
        report = result.manual_recovery or ""
        self.assertNotEqual(report, "", "a refusal with no report is a refusal with no next step")
        for prop in RECORDED_PROPERTIES:
            self.assertIn(prop, report, f"the report does not mention {prop}")
        # The changed property: the recorded value AND the value found now, on the
        # same line. A report that printed the two in different places would be a
        # report about two different machines.
        changed = row_for(report, IPV4_DNS)
        self.assertIn("recorded", changed)
        self.assertIn(DHCP_UPSTREAM, changed)
        self.assertIn("192.0.2.99", changed)
        # An untouched property, so the table is not just the interesting row.
        untouched = row_for(report, IPV4_IGNORE)
        self.assertIn("recorded no", untouched)
        self.assertIn("now yes", untouched)
        # And the one the install never changed, whose recorded value is empty.
        never = row_for(report, IPV6_DNS)
        self.assertIn("recorded", never)
        self.assertNotIn(DHCP_UPSTREAM, never, "the IPv6 list is carrying the IPv4 address")

    def test_the_manual_recovery_report_carries_the_commands_a_person_can_run(self):
        # Provoked by the missing marker rather than by a changed property, so
        # every property still holds what this installation set and the whole
        # command block is the one an operator would be handed on the commonest
        # refusal there is.
        self.remove_marker()
        report = self.refuse_with().manual_recovery or ""
        for command in restore_commands():
            self.assertIn(
                command,
                report,
                f"the report does not carry {command!r}, and an operator cannot restore a "
                "connection from a description of it",
            )
        self.assertIn(f"resolvectl dns {DEVICE}", report, "the operator has to be told how to check")

    def test_a_property_a_person_changed_gets_a_leave_line_and_no_modify(self):
        # The refusal above is the report's own contract in one place: it says
        # "this program will not write over it", and then the command block twelve
        # lines below hands over the command that writes over it. The report has
        # both value sets, so it can tell the two cases apart, and for a property
        # somebody deliberately set the right instruction is to LEAVE IT.
        self.property_value(IPV6_DNS, "2001:db8::1")
        report = self.refuse_with().manual_recovery or ""
        self.assertNotIn(
            f"nmcli connection modify {UUID} {IPV6_DNS}",
            report,
            "the report hands over a modify for the property whose refusal is that nobody may "
            "write to it",
        )
        self.assertIn(f"leave {IPV6_DNS} at 2001:db8::1", report)
        self.assertIn("changed after the install", report)

    def test_a_property_a_person_changed_is_leaved_in_the_report_that_refuses_about_it(self):
        # The same property as the refusal it belongs to. A refusal whose whole
        # subject is "somebody changed ipv4.dns" and whose command block then says
        # "set ipv4.dns to the recorded value" is a report that undoes its own
        # sentence.
        self.property_value(IPV4_DNS, "192.0.2.99")
        report = self.refuse_with().manual_recovery or ""
        self.assertIn("leave ipv4.dns at 192.0.2.99", report)
        self.assertNotIn(f"nmcli connection modify {UUID} {IPV4_DNS}", report)

    def test_a_property_this_program_wrote_still_gets_its_modify(self):
        # The other half, and the case a too-broad rule would get wrong. On an
        # installed machine `ipv4.ignore-auto-dns` holds `yes` and the backup
        # recorded `no`, so "the value found is not the recorded value" is true --
        # and it is exactly the property most in need of the recorded value, since
        # leaving it at `yes` leaves the machine ignoring its own lease.
        self.remove_marker()
        report = self.refuse_with().manual_recovery or ""
        for prop, value in ((IPV4_IGNORE, "no"), (IPV6_IGNORE, "no"), (IPV4_DNS, DHCP_UPSTREAM)):
            self.assertIn(
                f"nmcli connection modify {UUID} {prop} {value}",
                report,
                f"{prop} is a property this installation set, so the report has to hand over the "
                "command that puts it back",
            )
        self.assertNotIn("leave ", report, "no property on this machine was changed by anybody else")

    def test_the_report_says_which_order_and_why(self):
        self.remove_marker()
        report = self.refuse_with().manual_recovery or ""
        self.assertIn(
            "the recorded values, then the reconnection",
            report,
            "the block says 'in this order' without saying which order, and the recorded order is "
            "not the order the program itself uses",
        )

    def test_the_refusal_summary_is_accurate_when_there_is_no_backup(self):
        # The summary interpolated the UUID unconditionally, so a machine whose
        # backup could not be read was told "of what connection  was set to" and
        # pointed at "the commands above" when the report had printed no commands
        # at all -- only a template with <uuid> in it.
        self.rooted(BACKUP_PATH).unlink()
        self.assertTrue(
            self.rooted(MANAGED_BY).exists(),
            "this case is about a machine that CLAIMS the DNS is ours with no record of it, so "
            "it still refuses; both absent is the other verdict",
        )
        before = self.snapshot()
        self.result = self.run_uninstall()
        self.assertNothingChanged("a refusal with no backup")
        self.assertNothingTouched(before, "a refusal with no backup")
        self.refused()
        report = self.result.manual_recovery or ""
        self.assertNotIn(
            "connection  was set to",
            report,
            "the summary names a connection with an empty UUID, which is not a sentence",
        )
        self.assertNotIn(
            "the commands above",
            report,
            "the summary points an operator at commands the report did not print",
        )
        self.assertIn(BACKUP_PATH, report, "and it still has to name the file the record would be in")

    def test_the_manual_recovery_report_says_why_and_what_it_did_not_do(self):
        self.remove_marker()
        result = self.refuse_with()
        report = result.manual_recovery or ""
        self.assertTrue(report.startswith("MANUAL RECOVERY REPORT"), report[:60])
        self.assertIn("nothing on this machine has been changed by this run", report)
        self.assertIn(
            "REMOVING THE PACKAGE NOW would take away a resolver this machine is still pointing at",
            report,
            "a refusal has to say what removing the package would do, because that is the decision "
            "the operator is about to make",
        )

        for refusal in result.refusals:
            self.assertIn(
                refusal,
                report,
                "the report is the deliverable of a refusal, so it has to carry the reason rather "
                "than point at it",
            )

    def test_the_manual_recovery_report_quotes_a_value_that_needs_it(self):
        # The recorded IPv6 list is empty, and restoring an empty list is a
        # command with an empty argument. Printed bare it is a command with a
        # missing argument, which is a different command.
        self.remove_marker()
        report = self.refuse_with().manual_recovery or ""
        self.assertIn(f"nmcli connection modify {UUID} {IPV6_DNS} ''", report)
        self.assertIn(f"nmcli connection modify {UUID} {IPV4_DNS} {DHCP_UPSTREAM}", report)

    def test_the_report_of_a_machine_with_no_backup_names_the_file_instead_of_commands(self):
        self.rooted(BACKUP_PATH).unlink()
        self.assertTrue(
            self.rooted(MANAGED_BY).exists(),
            "this case is about a machine that CLAIMS the DNS is ours with no record of it, so "
            "it still refuses; both absent is the other verdict",
        )
        report = self.refuse_with().manual_recovery or ""
        self.assertIn(BACKUP_PATH, report)
        self.assertIn("nmcli", report, "an operator still has to be told the shape of the command")
        self.assertNotIn(f"nmcli connection modify {UUID}", report, "there is no UUID to name")

    def test_it_notes_an_edited_configuration_and_does_not_refuse_for_it(self):
        # Editing the policy is the normal thing an operator does after an
        # install. It says nothing about whether the connection is still ours, and
        # refusing the restore for it would be refusing the most common uninstall
        # there is, over a file the package does not own.
        self.write(POLICY_CONFIG, POLICY_BODY + "cdn:\n  cap_mbps: 900\n", mode=0o644)
        result = self.run_uninstall()
        self.assertTrue(result.ok, f"an edited policy refused the uninstall: {result.error}")
        self.assertIn(
            POLICY_CONFIG,
            " ".join(result.notes),
            "the backup records the configuration's digest, and the operator has to be told it "
            "no longer matches",
        )
        self.assertEqual(
            self.rooted(POLICY_CONFIG).read_text(encoding="utf-8"),
            POLICY_BODY + "cdn:\n  cap_mbps: 900\n",
            "the uninstall edited the operator's configuration",
        )

    def test_it_does_not_note_a_configuration_that_has_not_been_edited(self):
        result = self.run_uninstall()
        self.assertTrue(result.ok, result.error)
        self.assertNotIn(POLICY_CONFIG, " ".join(result.notes))

    def test_it_never_asks_preflight(self):
        # An uninstall has to work on the machine that preflight refuses --
        # wrongly-moded state directories are the ordinary reason, and an operator
        # removing the package is exactly the person who needs it to.
        for relative in ("/var/lib/mosdns", "/var/lib/mosdns/runtime", "/var/lib/mosdns/lists", "/run/mosdns"):
            path = self.rooted(relative)
            path.chmod(0o777)
        result = self.run_uninstall()
        self.assertTrue(result.ok, f"a machine preflight refuses could not be uninstalled: {result.error}")
        self.assertNotIn(
            ("dpkg", "--print-architecture"),
            self.commands,
            "the uninstall ran a preflight check, so it works only where preflight works",
        )


class UninstallOrderTests(UninstallFixture):
    """The order, asserted as one literal sequence of commands and probes."""

    def test_a_plain_uninstall_runs_exactly_this_sequence(self):
        self.result = self.run_uninstall()
        self.restored()
        self.assertEqual(
            self.commands,
            self.full_sequence(),
            "the uninstall ran a different sequence than the one the plan fixes",
        )

    def test_the_restore_happens_before_the_resolver_is_stopped(self):
        # The one property that makes this ordering safe rather than tidy. If the
        # router is stopped first, there is a window in which the machine's
        # NetworkManager is still handing resolved the loopback address and
        # nothing is listening on it. So the order is not a preference, and the
        # test above the one is its negative control.
        self.result = self.run_uninstall()
        self.restored()
        self.assertLess(
            self.commands.index(MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM)),
            self.commands.index(("systemctl", "stop", ROUTER_UNIT)),
        )
        reordered = self.full_sequence()
        wrong = [c for c in reordered if c != ("systemctl", "stop", ROUTER_UNIT)]
        wrong.insert(2, ("systemctl", "stop", ROUTER_UNIT))
        self.assertLess(
            wrong.index(("systemctl", "stop", ROUTER_UNIT)),
            wrong.index(MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM)),
            "the control case did not reorder, so the assertion above cannot fail",
        )

    def test_the_timers_are_stopped_before_anything_else_is_touched(self):
        self.result = self.run_uninstall()
        self.restored()
        first_mutation = next(
            index for index, command in enumerate(self.commands) if self.changing(command)
        )
        self.assertEqual(
            self.commands[first_mutation],
            ("systemctl", "stop", OPTIMIZER_TIMER),
            "the first thing the uninstall changes is not a timer",
        )

    def test_the_reactivation_is_after_every_property_restore(self):
        self.result = self.run_uninstall()
        self.restored()
        up = self.commands.index(CONNECTION_UP + (UUID,))
        for prop, value in RESTORE_ORDER:
            self.assertLess(
                self.commands.index(MODIFY + (UUID, prop, value)),
                up,
                f"{prop} was put back after the reactivation, so the device never picked it up",
            )

    def test_it_restores_in_the_same_order_the_installs_rollback_does(self):
        # One story for "how this package undoes its own profile changes". The
        # install's rollback writes the newest change back first, and an uninstall
        # that used a different order would be a second order to reason about.
        self.result = self.run_uninstall()
        self.restored()
        modifies = [command for command in self.commands if command[:3] == MODIFY]
        self.assertEqual(modifies, [MODIFY + (UUID, prop, value) for prop, value in RESTORE_ORDER])

    def test_it_never_restores_the_address_list_this_install_never_changed(self):
        self.result = self.run_uninstall()
        self.restored()
        for command in self.commands:
            if command[:3] == MODIFY:
                self.assertNotEqual(command[-2], IPV6_DNS, "the install never set the IPv6 list, so restoring it writes a value nothing changed")

    def test_it_does_not_reload_or_restart_networkmanager(self):
        self.result = self.run_uninstall()
        self.restored()
        for command in self.commands:
            if command[:1] == ("nmcli",) and len(command) > 1:
                self.assertNotIn(command[1], ("general", "reload"), f"{command!r} reloads NetworkManager")
        for command in self.commands:
            self.assertNotEqual(
                command[:2],
                ("systemctl", "reload-or-restart"),
                f"{command!r} restarts more than this connection",
            )

    def test_it_removes_exactly_the_dispatcher_file_this_plan_installs(self):
        before = self.snapshot()
        self.result = self.run_uninstall()
        self.restored()
        self.assertEqual(
            self.removed_paths(before),
            [DISPATCHER_SCRIPT.lstrip("/")],
            "the uninstall removed something other than the hook this plan installs",
        )
        self.assertFalse(self.rooted(DISPATCHER_SCRIPT).exists())
        self.assertTrue(self.rooted(SIBLING_DISPATCHER).exists(), "somebody else's no-wait hook was removed")
        self.assertTrue(self.rooted(SIBLING_DISPATCHER_BLOCKING).exists(), "somebody else's blocking hook was removed")

    def test_the_dispatcher_file_is_removed_before_systemd_is_reloaded(self):
        self.result = self.run_uninstall()
        self.restored()
        # The removal is not a command, so the order is asserted by what the
        # sequence looks like: the reload is the last command, and the file is
        # gone by the end of the run.
        self.assertEqual(
            self.commands[-1],
            DAEMON_RELOAD,
            "systemd was reloaded before the files it was told about were removed",
        )
        self.assertFalse(self.rooted(DISPATCHER_SCRIPT).exists())

    def test_a_dispatcher_path_that_is_a_directory_is_reported_and_not_removed(self):
        # A directory at the hook's path is not this package's file, and removing
        # it would be destroying something that belongs to somebody else.
        self.rooted(DISPATCHER_SCRIPT).unlink()
        self.rooted(DISPATCHER_SCRIPT).mkdir()
        before = self.snapshot()
        self.result = self.run_uninstall()
        self.assertTrue(self.rooted(DISPATCHER_SCRIPT).is_dir(), "a directory at the hook's path was removed")
        self.assertNothingTouched(before, "a directory at the hook's path was emptied")
        self.assertIn(DISPATCHER_SCRIPT, " ".join(self.result.notes) + " ".join(self.result.refusals) + (self.result.error or ""))

    def test_a_dispatcher_file_that_cannot_be_removed_is_reported(self):
        # The unlink needs write permission on the hook's DIRECTORY, so that is
        # what is taken away. Skipped as root, where the permission does not stop
        # it and the case would pass without exercising the branch.
        if os.geteuid() == 0:
            self.skipTest("root ignores the directory mode this case removes")
        directory = self.rooted(DISPATCHER_SCRIPT).parent
        directory.chmod(0o500)
        self.addCleanup(directory.chmod, 0o755)
        self.result = self.run_uninstall()
        self.assertTrue(
            self.result.ok, "a hook that could not be unlinked does not stop the package coming out"
        )
        self.assertIn(
            DISPATCHER_SCRIPT,
            " ".join(self.result.notes) + (self.result.error or ""),
            "a hook that is still on the machine has to be named",
        )
        self.assertTrue(self.rooted(DISPATCHER_SCRIPT).exists())

    def test_it_takes_no_lock_and_releases_none(self):
        # The lock lives in the state directory, and this program never acquires
        # it: stopping the three timers first is what removes the writer that
        # would contend for it. So the lock file is left exactly as it was, and
        # the sequence contains nothing that opens one.
        self.result = self.run_uninstall()
        self.restored()
        self.assertTrue(self.rooted(CONTROL_LOCK).exists(), "the control lock was removed by a plain uninstall")
        for command in self.commands:
            self.assertNotIn("flock", command, f"{command!r} takes a lock this program never asked for")
            self.assertNotIn("lock", " ".join(command), f"{command!r} mentions the lock file")

    def test_a_running_watchdog_run_is_stopped_before_the_connection_is_restored(self):
        # The review's minor, held. A timer only STARTS a unit, so stopping
        # `mosdns-watchdog.timer` does not stop a run that timer already started
        # -- and that run can be up to `WATCHDOG_ACTION_TIMEOUT_SECONDS` long,
        # because its action reactivates a NetworkManager connection. An
        # uninstall landing inside that window would restore the connection
        # underneath a rollback that is rewriting the same properties.
        self.result = self.run_uninstall()
        self.restored()
        # The connection on this fixture already carries the recorded values, so
        # there are no modifies; the reactivation is the first thing that
        # changes anything, and it is the thing a watchdog run would collide
        # with. Asserted against the whole sequence rather than one write so the
        # case does not depend on which values the fixture starts from.
        writes = [
            index
            for index, command in enumerate(self.commands)
            if command[:2] in (("nmcli", "connection"), ("resolvectl", "dns"))
        ]
        self.assertTrue(writes, "the uninstall changed nothing on the connection at all")
        stop = self.commands.index(("systemctl", "stop", WATCHDOG_SERVICE))
        self.assertLess(
            stop,
            min(writes),
            f"{WATCHDOG_SERVICE} is stopped after the connection is rewritten, so a watchdog run "
            "in progress would be restoring the same properties underneath this uninstall",
        )
        self.assertLess(
            self.commands.index(("systemctl", "stop", WATCHDOG_TIMER)),
            stop,
            "the timer is stopped after the service it starts, so a run can start between the two",
        )

    def test_an_already_restored_connection_is_restored_nothing_and_still_reactivated(self):
        for prop, raw in RECORDED_RAW.items():
            self.property_value(prop, raw)
        self.result = self.run_uninstall()
        self.restored()
        self.assertEqual(
            self.commands,
            self.full_sequence(restore=()),
            "a machine that is already back where the backup says was written to anyway",
        )

    def test_a_connection_already_back_on_one_property_gets_only_the_two_that_are_ours(self):
        # One of the three properties this install sets already holds the recorded
        # original. Nothing a person did is true of that one, so the other two are
        # put back and the restored one is left exactly as it is found.
        self.property_value(IPV6_IGNORE, RECORDED_RAW[IPV6_IGNORE])
        self.result = self.run_uninstall()
        self.restored()
        self.assertEqual(
            [command for command in self.commands if command[:3] == MODIFY],
            [MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM), MODIFY + (UUID, IPV4_IGNORE, "no")],
            "a property that already held the recorded value was written to, or one that did not "
            "was left",
        )

    def test_it_probes_resolveds_stub_and_not_the_local_resolver(self):
        self.result = self.run_uninstall()
        self.restored()
        self.assertEqual(
            self.probes,
            [(RESOLVED_STUB, DNS_PORT)],
            "after a restore the machine's path is through resolved's stub, and a check of "
            f"{LOCAL_DNS} is a check of a resolver this package is about to remove",
        )

    def test_it_does_not_claim_the_machine_can_resolve_on_a_servfail(self):
        # The install's whole barrier exists because a SERVFAIL is an answer from
        # a chain that reached nobody. An uninstall that reported "the machine can
        # resolve" on one would be reporting the one thing an operator who is
        # removing this package cannot afford to be told wrongly.
        self.result = self.run_uninstall(probe=self.probe_for(stub=SERVFAIL))
        self.assertTrue(self.result.ok, "the restoration finished, so this is not a failure")
        self.assertIn("CANNOT RESOLVE", " ".join(self.result.notes))
        self.assertNotIn("so this machine can resolve", " ".join(self.result.notes))

    def test_it_says_the_machine_can_resolve_only_when_it_can(self):
        self.result = self.run_uninstall(probe=self.probe_for(stub=HEALTHY))
        self.restored()
        self.assertIn("so this machine can resolve", " ".join(self.result.notes))

    def test_a_silent_stub_is_not_reported_as_resolving(self):
        self.result = self.run_uninstall(probe=self.probe_for(stub=SILENT))
        self.assertIn("CANNOT RESOLVE", " ".join(self.result.notes))

    def test_the_verdict_on_the_machine_is_the_last_thing_the_uninstall_says(self):
        # Every other line is about something this program did. The only line
        # about whether the machine works has to be the last one, because a reader
        # who reads the last line of the output is reading it.
        status, out, _err = self.run_cli("uninstall", probe=self.probe_for(stub=SERVFAIL))
        self.assertEqual(status, installer.EXIT_OK)
        self.assertTrue(
            out.strip().splitlines()[-1].startswith(f"uninstall: connection {UUID} is back"),
            f"the last line of a run that left a machine unable to resolve is: {out!r}",
        )
        self.assertIn("CANNOT RESOLVE", out)

    def test_it_leaves_the_operators_conffiles_byte_for_byte(self):
        edited = "# my own candidates\nexample.test\n"
        self.write(CONFFILE, edited, mode=0o644)
        before = self.snapshot()
        self.result = self.run_uninstall()
        self.restored()
        self.assertEqual(
            self.rooted(CONFFILE).read_text(encoding="utf-8"),
            edited,
            "an uninstall rewrote a conffile the operator may have edited",
        )
        self.assertEqual(
            [path for path in self.removed_paths(before)],
            [DISPATCHER_SCRIPT.lstrip("/")],
            "an uninstall removed something under /etc besides the hook it installed",
        )
        for relative in (POLICY_CONFIG, FORCE_ECH, DNS_RECORD_FILE):
            self.assertTrue(self.rooted(relative).exists(), f"{relative} is dpkg's and the operator's, not ours")

    def test_no_restore_writes_anything_the_backup_did_not_record(self):
        # The whole of "a restore may only put back what was written down", asked
        # of both verbs: every value either of them writes has to be a value in
        # the backup document, and the document on disk is the one they read.
        document = backup_document()
        for verb, run in (
            ("uninstall", lambda: self.run_uninstall()),
            ("emergency-rollback", lambda: self.run_rollback()),
        ):
            with self.subTest(verb=verb):
                self.setUp()
                self.write_backup(document)
                run()
                recorded = set()
                for prop in RECORDED_PROPERTIES:
                    value = document["original"][prop]["value"]
                    recorded.add(value if isinstance(value, str) else ",".join(value))
                for command in self.commands:
                    if command[:3] == MODIFY:
                        self.assertIn(
                            command[-1],
                            recorded,
                            f"{verb} wrote {command[-1]!r} to {command[-2]}, which the backup does "
                            "not record",
                        )


class FailedRestorationTests(UninstallFixture):
    """A restoration that did not finish stops there, and says what is left."""

    def test_a_property_that_could_not_be_put_back_stops_the_uninstall_there(self):
        before = self.snapshot()
        self.result = self.run_uninstall(
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM)])
        )
        self.assertFalse(self.result.ok)
        self.assertNotEqual(self.result.error, None)
        self.assertEqual(
            self.removed_paths(before),
            [],
            "a failed restoration still removed the hook, so the machine has neither the "
            "router nor the bridge",
        )
        self.assertTrue(self.rooted(DISPATCHER_SCRIPT).exists())
        self.assertTrue(self.rooted(STATE_DIRECTORY).is_dir())
        for unit in STOPPED_UNITS:
            self.assertNotIn(
                ("systemctl", "stop", unit),
                self.commands,
                "the resolver was stopped even though the restore failed, which leaves the "
                "machine pointing at the loopback with nothing on it",
            )

    def test_a_failed_restoration_still_names_the_commands_to_finish_it(self):
        self.result = self.run_uninstall(
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM)])
        )
        report = self.result.manual_recovery or ""
        for command in restore_commands():
            self.assertIn(command, report)
        self.assertIn("still", " ".join(self.result.refusals + [self.result.error or ""]).lower())

    def test_a_reconnection_that_fails_is_reported_with_the_command_that_finishes_it(self):
        self.result = self.run_uninstall(runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)]))
        self.assertFalse(self.result.ok)
        self.assertIn(
            f"nmcli connection up {UUID}",
            " ".join(self.result.refusals) + (self.result.error or "") + (self.result.manual_recovery or ""),
            "the profile is back and only the reactivation is missing, and that one command is "
            "what finishes it",
        )
        self.assertNotIn(("systemctl", "stop", ROUTER_UNIT), self.commands)

    def test_a_device_still_on_the_loopback_is_a_failure_and_the_router_keeps_running(self):
        # NetworkManager accepted the change and did not apply it, which is the
        # failure mode a successful `nmcli` and a correct backup both miss. The
        # answer is not "carry on and stop the router": the machine would be
        # pointing at a loopback address with nothing listening on it.
        self.overrides[RESOLVECTL_DNS] = f"Link 2 ({DEVICE}): {LOCAL_DNS}\n"
        self.result = self.run_uninstall()
        self.assertFalse(self.result.ok, "a machine still on the loopback was reported as restored")
        self.assertIn(LOCAL_DNS, " ".join(self.result.refusals) + (self.result.error or ""))
        self.assertNotIn(
            ("systemctl", "stop", ROUTER_UNIT),
            self.commands,
            "the router was stopped on a machine that is still using it",
        )
        self.assertTrue(self.rooted(STATE_DIRECTORY).is_dir())

    def test_a_loopback_the_backup_recorded_is_not_a_failure(self):
        # A machine that was already using a local resolver before this package
        # was installed is restored TO the loopback, and that is the recorded
        # original rather than a leftover. The recorded list here also carries a
        # second address, because the test is "the recorded original mentions the
        # loopback", not "the recorded original is the loopback".
        self.write_backup(
            backup_document(original={**RECORDED_RAW, IPV4_DNS: f"{LOCAL_DNS},{DHCP_UPSTREAM}"})
        )
        self.property_value(IPV6_DNS, RECORDED_RAW[IPV6_DNS])
        self.overrides[RESOLVECTL_DNS] = f"Link 2 ({DEVICE}): {LOCAL_DNS} {DHCP_UPSTREAM}\n"
        self.result = self.run_uninstall()
        self.assertTrue(self.result.ok, f"a recorded loopback was treated as a failure: {self.result.error}")

    def test_the_report_of_a_failed_restore_says_which_values_it_had_already_written(self):
        # The THIRD report path, and the one that was never told. `_restore_unfinished`
        # hands the report its PRE-WRITE observation too, so its table reads
        # "what the connection holds now" while it has already written -- and the
        # second modify failing renders `ipv4.dns now 127.0.0.1` for a profile
        # that already holds 192.0.2.53.
        self.result = self.run_uninstall(
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV6_IGNORE, "no")])
        )
        self.assertFalse(self.result.ok)
        report = self.result.manual_recovery or ""
        self.assertIn(
            "what the connection held before this run wrote to it",
            report,
            "the table is the state before the writes and does not say so",
        )
        self.assertIn(
            "this run already wrote the recorded value for ipv4.dns",
            report,
            "the report does not name what it wrote, so an operator cannot tell which of the "
            "modify lines is already true of the profile",
        )

    def test_a_failed_restore_that_wrote_nothing_claims_nothing(self):
        self.result = self.run_uninstall(
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM)])
        )
        self.assertFalse(self.result.ok)
        report = self.result.manual_recovery or ""
        self.assertNotIn("already wrote", report, "the report claims a write that never happened")
        self.assertIn(
            "what the connection holds now",
            report,
            "and with nothing written the table is the current state, so it should say so",
        )

    def test_a_stop_that_fails_is_reported_and_the_rest_of_the_uninstall_happens(self):
        self.result = self.run_uninstall(runner=self.good_runner(fail=[("systemctl", "stop", ROUTER_UNIT)]))
        self.assertTrue(self.result.ok, "the restoration finished, so the uninstall itself did")
        self.assertIn(ROUTER_UNIT, " ".join(self.result.notes) + (self.result.error or ""))
        self.assertIn(("systemctl", "stop", RESOLVER_UNIT), self.commands)
        self.assertIn(DAEMON_RELOAD, self.commands)
        self.assertFalse(self.rooted(DISPATCHER_SCRIPT).exists())

    def test_a_reload_that_fails_is_reported(self):
        self.result = self.run_uninstall(runner=self.good_runner(fail=[DAEMON_RELOAD]))
        self.assertTrue(self.result.ok)
        self.assertIn("daemon-reload", " ".join(self.result.notes) + (self.result.error or ""))


class UnreadableDeviceCheckTests(UninstallFixture):
    """The read that proves the device took the values has to have happened.

    This is the one check in the section that stands between a restore and
    stopping the resolver, so the case where it cannot be performed is a case
    where the router must not be stopped. It was not, and the reason is an
    asymmetry: `_text` returns `None` only when the call RAISES, so a
    `resolvectl` that exits non-zero with nothing on standard output comes back
    as the empty string, and the loopback is not in `"".split()`.
    """

    def assertTheRouterKeptRunning(self, why):
        self.assertFalse(self.result.ok, why)
        self.assertNotIn(
            ("systemctl", "stop", ROUTER_UNIT),
            self.commands,
            why + ": the router was stopped on a machine whose state nobody could read",
        )
        self.assertNotIn(("systemctl", "stop", RESOLVER_UNIT), self.commands, why)
        self.assertTrue(self.rooted(STATE_DIRECTORY).is_dir(), why + ": the state was purged anyway")
        self.assertTrue(self.rooted(DISPATCHER_SCRIPT).exists(), why + ": the hook was removed anyway")

    def test_a_resolvectl_that_exits_non_zero_with_no_output_refuses(self):
        # Measured on real systemd-resolved 24.04: `resolvectl dns <dev>` for a
        # device that does not exist exits 1, prints nothing on standard output,
        # and puts `Failed to resolve interface "<dev>": No such device` on
        # standard error. That is the machine this case is about.
        self.resolvectl_fails()
        self.result = self.run_uninstall()
        self.assertTheRouterKeptRunning("a failed device check")
        self.assertIn("resolvectl", (self.result.error or ""))

    def test_a_resolvectl_that_succeeds_with_no_output_at_all_refuses(self):
        # Real resolved always prints the `Link N (<dev>):` line for a link that
        # exists, even a link with no DNS on it, so a run of nothing at all is
        # not a link with no resolvers -- it is a run this program cannot read.
        self.resolvectl_fails(code=0)
        self.result = self.run_uninstall()
        self.assertTheRouterKeptRunning("a device check that printed nothing")
        self.assertIn("resolvectl", (self.result.error or ""))

    def test_a_resolvectl_that_could_not_be_run_at_all_refuses(self):
        # The other failure shape, kept distinct: the call raised, so there is no
        # output and no status, only the absence of a runner answer.
        before = self.snapshot()
        self.result = self.run_uninstall(runner=self.good_runner(fail=[RESOLVECTL_DNS]))
        self.assertTheRouterKeptRunning("a device check that could not run")
        self.assertIn("resolvectl", (self.result.error or ""))
        self.assertNothingTouched(before, "a machine nobody could read lost its dispatcher hook")

    def test_a_link_with_no_dns_at_all_is_not_a_failed_read(self):
        # The measured case that a too-broad check would get wrong. Real resolved
        # exits 0 and prints `Link 2 (ens33):` with nothing after the colon, so
        # the answer is a real one that happens to say there are no resolvers,
        # and this program is about to put the recorded ones there.
        self.overrides[RESOLVECTL_DNS] = f"Link 2 ({DEVICE}):\n"
        self.result = self.run_uninstall()
        self.assertTrue(self.result.ok, f"a link with no DNS was read as a failure: {self.result.error}")
        self.assertIn(("systemctl", "stop", ROUTER_UNIT), self.commands)

    def test_the_report_says_a_device_check_that_could_not_be_done(self):
        self.resolvectl_fails()
        self.result = self.run_uninstall()
        report = self.result.manual_recovery or ""
        self.assertIn("resolvectl", report, "the report has to name the check that could not be made")
        self.assertIn(
            "the commands above",
            report,
            "the report's own summary tells an operator the commands above are the way to finish, so "
            "it is still the deliverable after a failed check",
        )

    def test_a_property_this_install_never_changed_is_not_announced_as_untouched(self):
        # A refactor changed this output silently, so the test says what it is.
        # `ipv6.dns` is a property the install never sets, so on a machine it
        # installed "already holds the value the backup recorded" is a tautology
        # about a property nothing ever touched -- and it appeared in every
        # normal uninstall's notes. The note is about THIS INSTALL's changes, and
        # a property it never made cannot be one.
        self.result = self.run_uninstall()
        self.restored()
        notes = " ".join(self.result.notes)
        self.assertNotIn(
            f"{IPV6_DNS} of {UUID} already holds",
            notes,
            "the note is about this installation's own changes, and it never changed the IPv6 list",
        )
        for prop in (IPV4_DNS, IPV4_IGNORE, IPV6_IGNORE):
            self.assertNotIn(
                f"{prop} of {UUID} already holds",
                notes,
                f"{prop} holds what this installation set, so it is not 'already back'",
            )
        self.assertNotIn("already holds", notes, "nothing on this machine is already back")

    def test_a_machine_that_is_already_back_keeps_the_note_for_the_properties_it_set(self):
        # The other half: when a property this install DID set is already holding
        # the recorded original, that is worth saying -- it is the difference
        # between "I put it back" and "it was already there".
        for prop, raw in RECORDED_RAW.items():
            self.property_value(prop, raw)
        self.result = self.run_uninstall()
        self.restored()
        for prop in (IPV4_DNS, IPV4_IGNORE, IPV6_IGNORE):
            self.assertIn(f"{prop} of {UUID} already holds", " ".join(self.result.notes))

    def test_the_check_runs_before_the_units_it_gates(self):
        # The ordering, asserted on its own: a gate that runs after the thing it
        # gates is not a gate.
        self.result = self.run_uninstall()
        self.restored()
        self.assertLess(
            self.commands.index(RESOLVECTL_DNS),
            self.commands.index(("systemctl", "stop", ROUTER_UNIT)),
        )


class PurgeTests(UninstallFixture):
    """``/var/lib/mosdns`` is the operator's, and a purge is a last step."""

    def test_the_default_uninstall_preserves_the_state_directory(self):
        before = self.snapshot()
        self.result = self.run_uninstall()
        self.restored()
        self.assertEqual(
            self.removed_paths(before),
            [DISPATCHER_SCRIPT.lstrip("/")],
            "a plain uninstall removed state it was not asked to remove",
        )
        for relative in (CONTROL_LOCK, PREFIX_LIST, RUNTIME_STATE, BACKUP_PATH, MANAGED_BY):
            self.assertTrue(self.rooted(relative).exists(), f"{relative} was removed by a plain uninstall")

    def test_a_purge_removes_the_state_directory(self):
        self.result = self.run_uninstall(purge=True)
        self.restored()
        self.assertFalse(self.rooted(STATE_DIRECTORY).exists(), "--purge left the state directory behind")

    def test_a_purge_removes_the_control_lock_with_the_rest(self):
        self.result = self.run_uninstall(purge=True)
        self.restored()
        self.assertFalse(self.rooted(CONTROL_LOCK).exists(), "the control lock outlived the state directory it lives in")

    def test_a_purge_runs_after_the_restoration(self):
        self.result = self.run_uninstall(purge=True)
        self.restored()
        self.assertEqual(
            self.commands[-1],
            DAEMON_RELOAD,
            "a purge is not the last step, so a failure after it would leave nothing to read",
        )
        self.assertLess(
            self.commands.index(CONNECTION_UP + (UUID,)),
            len(self.commands) - 1,
            "the state directory was removed before the machine was pointed back at its own "
            "resolvers",
        )

    def test_a_restoration_that_did_not_finish_is_not_followed_by_a_purge(self):
        self.result = self.run_uninstall(
            purge=True,
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM)]),
        )
        self.assertFalse(self.result.ok)
        self.assertTrue(
            self.rooted(STATE_DIRECTORY).is_dir(),
            "the record of what the connection was set to was deleted while it was still wrong",
        )
        self.assertTrue(self.rooted(BACKUP_PATH).exists(), "the backup was deleted by a failed restore")

    def test_a_machine_still_on_the_loopback_is_not_purged(self):
        self.overrides[RESOLVECTL_DNS] = f"Link 2 ({DEVICE}): {LOCAL_DNS}\n"
        self.result = self.run_uninstall(purge=True)
        self.assertFalse(self.result.ok)
        self.assertTrue(self.rooted(BACKUP_PATH).exists())

    def test_a_purge_removes_the_hook_and_the_state_directory_and_nothing_else(self):
        before = self.snapshot()
        self.result = self.run_uninstall(purge=True)
        self.restored()
        self.assertEqual(
            self.removed_paths(before),
            sorted(
                path
                for path in before
                if path == DISPATCHER_SCRIPT.lstrip("/") or purges(path)
            ),
            "a purge removed a path outside the state directory and the hook",
        )
        for relative in (POLICY_CONFIG, CONFFILE, DHCP_STATE_FILE, SIBLING_DISPATCHER):
            self.assertTrue(self.rooted(relative).exists(), f"{relative} is not this package's to delete")

    def test_a_purge_does_not_follow_a_symlink_out_of_the_state_directory(self):
        outside = self.write("/home/ubuntu/keep-me", "the operator's own data\n")
        self.rooted(PREFIX_LIST).unlink()
        self.rooted(PREFIX_LIST).symlink_to(outside)
        self.result = self.run_uninstall(purge=True)
        self.restored()
        self.assertTrue(
            outside.exists() and outside.read_text(encoding="utf-8") == "the operator's own data\n",
            "a purge followed a symlink out of the state directory and deleted the file behind it",
        )

    def test_a_state_directory_that_is_a_symlink_is_not_purged(self):
        # A link at the state directory's path is a redirect this program did not
        # write, and whatever it points at is not its to delete. The uninstall
        # itself still finishes -- the machine's DNS is back either way -- and the
        # refusal is a note about the state directory, which is the fact it is a
        # fact about.
        outside = self.rooted("/var/lib/somebody-elses")
        self.rooted(STATE_DIRECTORY).rename(outside)
        self.rooted(STATE_DIRECTORY).symlink_to(outside)
        before = self.snapshot()
        self.result = self.run_uninstall(purge=True)
        self.restored()
        self.assertFalse(self.result.purged, "a symlinked state directory was reported as purged")
        self.assertIn(STATE_DIRECTORY, " ".join(self.result.notes))
        self.assertTrue(
            (outside / "runtime" / "control.lock").exists(),
            "the tree behind the symlink was removed",
        )
        self.assertEqual(
            self.removed_paths(before),
            [DISPATCHER_SCRIPT.lstrip("/")],
            "a refused purge removed a path the uninstall did not already remove",
        )

    def test_a_second_purge_removes_nothing_more(self):
        # The purge takes the marker with it, because the marker lives inside the
        # state directory -- so the second run has no claim to act on and no record
        # to restore from, and it says so and removes nothing rather than refusing.
        # The refusal is what this used to do, and it is what left a package that
        # no documented means could remove: dpkg aborts a removal whose
        # pre-removal script exits non-zero, so an operator whose machine ended up
        # here could not get rid of it. What the refusal was protecting against --
        # this verb deleting something it had no business deleting -- is still
        # held, and by a stronger assertion than the exit status: nothing at all
        # disappeared.
        self.result = self.run_uninstall(purge=True)
        self.assertTrue(self.result.ok, result_error(self.result))
        before = self.snapshot()
        self.result = self.run_uninstall(purge=True)
        self.assertTrue(self.result.ok, result_error(self.result))
        self.assertEqual(self.result.refusals, [])
        self.assertIn(
            "nothing of this package left on this machine",
            " ".join(self.result.notes),
            "the second purge reported success without saying that there was nothing left to do",
        )
        self.assertEqual(self.removed_paths(before), [], "a second purge removed something")

    def test_a_purge_leaves_the_run_directory_alone(self):
        # `/run` is a tmpfs the init system rebuilds, and the plan names
        # `/var/lib/mosdns` as the state to purge. Removing the DHCP state would
        # be tidy and would also throw away the record of the lease.
        self.result = self.run_uninstall(purge=True)
        self.restored()
        self.assertTrue(self.rooted(DHCP_STATE_FILE).exists())

    def test_a_purge_keeps_the_backup_until_the_last_step(self):
        seen = []

        def watch(command):
            seen.append((command, self.rooted(BACKUP_PATH).exists()))

        self._commands = []
        runner = self.good_runner()
        runner.record = lambda command: (self.commands.append(command), watch(command))
        result = installer.uninstall(self.root, runner, purge=True, probe=self.probe_for())
        self.assertTrue(result.ok, result.error)
        self.assertTrue(
            all(exists for _, exists in seen),
            "the backup was gone before the commands finished, so a later step could not have "
            "used it to finish a restore",
        )


class UnitOwnershipTests(UninstallFixture):
    """A unit whose state cannot be read is left running, and named."""

    def test_a_unit_whose_state_cannot_be_read_is_left_running_and_reported(self):
        self.unit_answers(answer="")
        before = self.snapshot()
        self.result = self.run_uninstall()
        self.assertTrue(self.result.ok, "an unreadable unit state is not a failed uninstall")
        for unit in (*PROJECT_TIMERS, *STOPPED_ONESHOT, *STOPPED_UNITS):
            self.assertNotIn(
                ("systemctl", "stop", unit),
                self.commands,
                f"{unit} was stopped by a program that could not read whether it was running",
            )
            self.assertIn(unit, " ".join(self.result.notes) + (self.result.error or ""))
        self.assertEqual(
            sorted(self.result.left_running),
            sorted((*PROJECT_TIMERS, *STOPPED_ONESHOT, *STOPPED_UNITS)),
            "the units this program would not touch are not reported",
        )
        self.assertEqual(
            self.removed_paths(before),
            [DISPATCHER_SCRIPT.lstrip("/")],
            "a unit this program would not stop stopped the uninstall short, and the hook is "
            "still there",
        )

    def test_a_unit_that_answers_is_stopped(self):
        self.result = self.run_uninstall()
        self.restored()
        for unit in (*PROJECT_TIMERS, *STOPPED_ONESHOT, *STOPPED_UNITS):
            self.assertIn(("systemctl", "stop", unit), self.commands)
        self.assertEqual(self.result.left_running, [])

    def test_a_query_that_fails_is_the_same_as_an_answer_of_nothing(self):
        self.result = self.run_uninstall(
            runner=self.good_runner(
                fail=[("systemctl", "is-active", ROUTER_UNIT), ("systemctl", "is-active", RESOLVER_UNIT)]
            )
        )
        self.assertTrue(self.result.ok, result_error(self.result))
        self.assertNotIn(("systemctl", "stop", ROUTER_UNIT), self.commands)
        self.assertNotIn(("systemctl", "stop", RESOLVER_UNIT), self.commands)
        self.assertIn(ROUTER_UNIT, " ".join(self.result.notes) + (self.result.error or ""))

    def test_the_two_units_are_stopped_router_first(self):
        self.result = self.run_uninstall()
        self.restored()
        self.assertLess(
            self.commands.index(("systemctl", "stop", ROUTER_UNIT)),
            self.commands.index(("systemctl", "stop", RESOLVER_UNIT)),
        )

    def test_an_unreadable_state_does_not_stop_a_purge(self):
        # The timers were stopped first, which is what makes the purge safe
        # without taking the control lock, and a unit this program could not ask
        # about is not a reason to leave the operator's data behind.
        self.unit_answers(answer="")
        self.result = self.run_uninstall(purge=True)
        self.assertTrue(self.result.ok, result_error(self.result))
        self.assertFalse(self.rooted(STATE_DIRECTORY).exists())

    def test_the_units_stopped_are_only_this_packages(self):
        self.result = self.run_uninstall()
        self.restored()
        stopped = {command[-1] for command in self.commands if command[:2] == ("systemctl", "stop")}
        self.assertEqual(
            stopped,
            {*PROJECT_TIMERS, *STOPPED_ONESHOT, *STOPPED_UNITS},
            "the uninstall stopped a unit this package does not install",
        )

    def test_it_never_disables_or_enables_anything(self):
        # The backup records no unit state, so there is nothing to put back, and
        # writing a value the backup did not record is the one thing this program
        # must never do. The plan's list has no disable step either.
        self.result = self.run_uninstall()
        self.restored()
        for command in self.commands:
            self.assertNotIn(
                command[1] if command[:1] == ("systemctl",) else None,
                ("disable", "enable", "mask", "unmask"),
                f"{command!r} writes a unit's enablement, and no record of it exists",
            )


def result_error(result):
    return f"the uninstall did not finish: {result.error}"


class EmergencyRollbackTests(UninstallFixture):
    """The command that exists for the machine preflight refuses."""

    def test_it_needs_no_marker(self):
        self.remove_marker()
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"a rollback that needs the marker cannot help: {self.result.error}")
        self.assertEqual(
            [command for command in self.commands if command[:3] == MODIFY],
            [MODIFY + (UUID, prop, value) for prop, value in RESTORE_ORDER],
        )
        self.assertIn(CONNECTION_UP + (UUID,), self.commands)

    def test_it_runs_exactly_the_restore_and_nothing_else(self):
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"the rollback did not finish: {self.result.error}")
        self.assertEqual(
            self.commands,
            self.rollback_reads()
            + [MODIFY + (UUID, prop, value) for prop, value in RESTORE_ORDER]
            + [CONNECTION_UP + (UUID,), RESOLVECTL_DNS],
            "a rollback ran something other than reading the connection and restoring it, and an "
            "emergency command that stops a unit or removes a file is one more thing that can be "
            "wrong",
        )

    def rollback_reads(self):
        """The four read-only property reads a rollback makes before it writes.

        They are here so the verb is visible in the report it hands over: a
        rollback that overwrites a connection without having read it can tell an
        operator nothing about what it just replaced.
        """
        return [PROPERTY_READ + (prop, "connection", "show", UUID) for prop in RECORDED_PROPERTIES]

    def test_it_reads_the_connection_before_it_overwrites_it(self):
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"the rollback did not finish: {self.result.error}")
        for command in self.rollback_reads():
            self.assertIn(
                command,
                self.commands,
                f"{command!r} never ran, so the report cannot show what the connection held",
            )
        first_write = next(
            index for index, command in enumerate(self.commands) if self.changing(command)
        )
        self.assertLess(
            self.commands.index(self.rollback_reads()[-1]),
            first_write,
            "the first write happened before the last read, so the report describes a connection "
            "this run had already changed",
        )

    def test_its_reads_change_nothing(self):
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"the rollback did not finish: {self.result.error}")
        for command in self.rollback_reads():
            self.assertFalse(
                self.changing(command), f"{command!r} is recorded as a read and is a mutation"
            )

    def test_the_set_of_commands_it_writes_is_exactly_the_recorded_ones(self):
        # The reads are new; the WRITES must not be. Compared as a set against
        # the recorded values, so a rollback that grew a fourth property or lost a
        # reactivation fails here.
        document = backup_document()
        self.write_backup(document)
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"the rollback did not finish: {self.result.error}")
        written = [command for command in self.commands if self.changing(command)]
        self.assertEqual(
            written,
            [MODIFY + (UUID, prop, value) for prop, value in RESTORE_ORDER]
            + [CONNECTION_UP + (UUID,)],
            "the rollback's writes are not the three recorded properties and one reconnection",
        )

    def test_its_report_shows_what_the_connection_held(self):
        # A property this program is about to overwrite, read rather than assumed.
        # The report exists on the paths that need one, so this is the failing
        # reactivation, and the read of the property is what makes its row differ.
        self.property_value(IPV6_DNS, "2001:db8::1")
        self.result = self.run_rollback(
            runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)])
        )
        self.assertFalse(self.result.ok)
        report = self.result.manual_recovery or ""
        self.assertIn("now 2001:db8::1", report, "the report has no column for what was there")
        self.assertIn("recorded", report, "and the column it has is not the recorded one")
        for prop in RECORDED_PROPERTIES:
            self.assertIn(prop, report, f"the report says nothing about {prop}")

    def test_a_read_it_could_not_do_says_so_and_does_not_change_what_is_written(self):
        # Which way this fails: the READING is for the report, so a read that
        # fails makes the report less complete and the rollback no less
        # effective. The writes are unconditional by design -- the machine this
        # verb exists for is one whose install died partway.
        #
        # The read that fails is a `yes`/`no`, because that is the half of the
        # asymmetry that matters: `nmcli -g` exits non-zero with nothing on
        # standard output for a connection it cannot find, and that arrives as the
        # empty string, which for a `yes`/`no` is not a value it can hold.
        self.resolve_property_read_fails(prop=IPV4_IGNORE)
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"a failed read stopped the rollback: {self.result.error}")
        self.assertEqual(
            [command for command in self.commands if self.changing(command)],
            [MODIFY + (UUID, prop, value) for prop, value in RESTORE_ORDER]
            + [CONNECTION_UP + (UUID,)],
            "a read that failed changed what the rollback wrote",
        )
        self.assertIn(
            COULD_NOT_BE_READ,
            (self.result.manual_recovery or "") + " ".join(self.result.notes),
            "a read that failed is reported as a read that failed",
        )

    def test_a_read_of_an_address_list_that_came_back_empty_is_a_value_not_a_failure(self):
        # The other half of the same asymmetry. An empty address list is a link
        # with no manual DNS, which is a real answer, and reading it as a failed
        # read would put "I could not look" in a column that has an answer in it.
        self.resolve_property_read_fails(prop=IPV6_DNS)
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"a failed read stopped the rollback: {self.result.error}")
        self.assertNotIn(COULD_NOT_BE_READ, " ".join(self.result.notes))
        self.result = self.run_rollback(runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)]))
        report = self.result.manual_recovery or ""
        self.assertIn(f"now {UNSET}", report, "an empty list is a value and the report says so")
        self.assertNotIn(COULD_NOT_BE_READ, report)

    def test_a_read_it_could_not_do_says_so_in_the_report_it_hands_over(self):
        self.resolve_property_read_fails(prop=IPV6_IGNORE)
        self.result = self.run_rollback(runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)]))
        self.assertFalse(self.result.ok)
        self.assertIn(COULD_NOT_BE_READ, self.result.manual_recovery or "")
        self.assertIn(
            COULD_NOT_BE_READ,
            " ".join(self.result.notes),
            "the operator has to be told which property the report cannot speak for",
        )

    def test_the_report_of_a_write_that_did_not_finish_never_names_a_written_value(self):
        # `_rollback_stopped` is one of the two report paths on this verb, and it
        # hands the PRE-WRITE observation to the report while the run has already
        # written to the profile. A leave line there names a value that no longer
        # exists and claims a refusal that did not happen.
        self.property_value(IPV4_DNS, "192.0.2.99")
        self.result = self.run_rollback(
            runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)])
        )
        self.assertFalse(self.result.ok)
        report = self.result.manual_recovery or ""
        self.assertIn(
            MODIFY[0], report, "the report of a failed rollback has no command block at all"
        )
        self.assertNotIn(
            f"leave {IPV4_DNS}",
            report,
            "the report tells an operator to leave a value at 192.0.2.99 that this run has already "
            "overwritten with the recorded 192.0.2.53",
        )
        self.assertIn(
            f"nmcli connection modify {UUID} {IPV4_DNS} {DHCP_UPSTREAM}",
            report,
            "a property this run wrote is the recorded value now, so the report says so",
        )
        self.assertIn(
            "already wrote",
            report,
            "the report has to say which properties it changed, or the table reads as the state of "
            "a machine nobody touched",
        )

    def test_the_report_of_a_chain_that_does_not_resolve_never_names_a_written_value(self):
        # The other report path, and the one an operator is most likely to be
        # looking at: the restore worked and the machine still cannot resolve.
        self.property_value(IPV4_DNS, "192.0.2.99")
        self.result = self.run_rollback(probe=self.probe_for(stub=SERVFAIL))
        self.assertFalse(self.result.ok)
        self.assertTrue(self.result.restored)
        report = self.result.manual_recovery or ""
        self.assertNotIn(
            f"leave {IPV4_DNS}",
            report,
            "this run put ipv4.dns back and the report claims it refused to",
        )
        self.assertIn("already wrote", report)

    def test_the_command_block_is_a_contiguous_run_of_command_lines(self):
        # The one thing an operator does with the block is select it and paste it,
        # so prose inside it is a defect -- and the "already wrote" paragraph is
        # prose. The first version of it landed between the modify lines and the
        # note about `''`, which put two paragraphs inside the block.
        self.property_value(IPV4_DNS, "192.0.2.99")
        self.result = self.run_rollback(probe=self.probe_for(stub=SERVFAIL))
        report = self.result.manual_recovery or ""
        after = report.split("  nmcli connection modify", 1)[1]
        block = "  nmcli connection modify" + after.split("\n\n")[0]
        for line in block.splitlines():
            self.assertTrue(
                line.strip().startswith("nmcli "),
                f"the command block has a line in it that is not a command: {line!r}",
            )
        self.assertIn("already wrote", report)
        self.assertNotIn("already wrote", block, "the overwrite note is inside the block an operator pastes")

    def test_a_property_this_run_did_not_write_still_gets_its_leave_line(self):
        # The other half: the rollback never writes `ipv6.dns`, so a hand-edited
        # one survives it and the report's leave line is the truth.
        self.property_value(IPV6_DNS, "2001:db8::1")
        self.result = self.run_rollback(
            runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)])
        )
        report = self.result.manual_recovery or ""
        self.assertIn(f"leave {IPV6_DNS} at 2001:db8::1", report)

    def test_a_write_that_never_happened_is_not_claimed_as_written(self):
        # The write set is what REACHED the profile, not what was intended. The
        # rollback writes `ipv4.dns` first, so failing that one means a
        # hand-edited `ipv4.dns` survived this run entirely -- and the report's
        # leave line for it is the truth, which is the case a set of intended
        # writes would get wrong.
        self.property_value(IPV4_DNS, "192.0.2.99")
        self.result = self.run_rollback(
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM)])
        )
        self.assertFalse(self.result.ok)
        report = self.result.manual_recovery or ""
        self.assertIn(
            f"leave {IPV4_DNS} at 192.0.2.99",
            report,
            "the report claims a refusal over a property whose write never ran",
        )
        self.assertNotIn("already wrote", report, "and it claims a write that did not happen")

    def test_a_write_that_failed_after_an_earlier_one_claimed_exactly_that_one(self):
        # The partial case, and the one that needs the set to be tracked rather
        # than reconstructed: the first write reached the profile and the second
        # did not, so the report may claim the first and must not claim the second.
        self.property_value(IPV4_DNS, "192.0.2.99")
        self.result = self.run_rollback(
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV6_IGNORE, "no")])
        )
        self.assertFalse(self.result.ok)
        report = self.result.manual_recovery or ""
        self.assertIn("already wrote the recorded value for ipv4.dns,", report)
        self.assertNotIn("ipv6.ignore-auto-dns,", report.split("already wrote the recorded value for")[1])
        self.assertNotIn(f"leave {IPV4_DNS}", report, "the first write happened, so nothing to leave")

    def test_a_partial_write_set_does_not_claim_the_profile_holds_the_others(self):
        # Two accounts of one property, three lines apart, is Finding A's shape
        # with the polarity flipped. The reason says the second write FAILED and
        # the paragraph said every modify line is what the profile holds now --
        # which is false for the two properties whose write never happened. The
        # claim has to be scoped to the properties it just named.
        self.property_value(IPV4_DNS, "192.0.2.99")
        self.result = self.run_rollback(
            runner=self.good_runner(fail=[MODIFY + (UUID, IPV6_IGNORE, "no")])
        )
        self.assertFalse(self.result.ok)
        report = self.result.manual_recovery or ""
        # Every occurrence of the claim has to be scoped. The unscoped sentence
        # ends there, so its remainder starts with a full stop or a newline; the
        # scoped one continues with "for those properties".
        for occurrence in report.split("the modify lines above are what the profile holds now")[1:]:
            self.assertTrue(
                occurrence.startswith(" for those properties"),
                f"the report makes an unscoped claim about the profile: {occurrence[:40]!r}",
            )
        self.assertIn(
            "the others are still what the table above shows",
            report,
            "and the report has to say what is true of the properties it did not write",
        )
        # And the first half must survive the narrowing, or the fix has hidden
        # the overwrite instead of scoping it.
        self.assertIn("this run already wrote the recorded value for ipv4.dns", report)

    def test_a_blank_device_check_on_the_rollback_path_is_reported(self):
        # The same read that now refuses on the uninstall path, on the other one.
        # It ends as `restored=True, ok=False`: the values are back and the
        # machine's DNS is not accounted for, which is the machine a caller has to
        # be told about rather than the machine a rollback can claim.
        self.resolvectl_fails()
        self.result = self.run_rollback()
        self.assertFalse(self.result.ok, "a device check that failed was reported as a good rollback")
        self.assertTrue(self.result.restored, "the values were put back and the result says otherwise")
        self.assertIsNone(self.result.resolves, "the machine was never asked whether it resolves")
        self.assertIn("resolvectl", self.result.error or "")
        self.assertIn(
            ("nmcli", "connection", "up", UUID),
            self.commands,
            "the reactivation is what the report's commands are for, so it has to have run",
        )

    def test_a_stale_recorded_device_is_named_so_the_operator_recognises_it(self):
        # A new way for a healthy uninstall to refuse: the interface was renamed
        # since the install, so the recorded device is not the device. Fail-closed
        # and recoverable, and the only thing that makes it recoverable is the
        # operator recognising which name the record holds.
        self.resolvectl_fails()
        self.result = self.run_uninstall()
        self.assertFalse(self.result.ok)
        message = self.result.error or ""
        self.assertIn(
            DEVICE,
            message,
            "the failure does not name the device the record holds, so an operator cannot tell a "
            "renamed interface from a missing one",
        )
        self.assertIn(
            "rename",
            message.lower(),
            "the failure does not say that a renamed interface is the likely cause",
        )
        # And it has to name CAUSES, not enumerate the device as one of them. The
        # sentence it replaced read "Two things make that so: ens33 is the name
        # the backup recorded, and the interface has been renamed or removed" --
        # in which the first "thing" is the subject restated, not a reason.
        self.assertNotIn(
            "Two things make that so",
            message,
            "the sentence that was supposed to name the causes names the device as one of them",
        )
        self.assertIn(
            "may have been renamed or removed",
            message,
            "the message has to say the two things that can make a recorded name unresolvable",
        )

    def resolve_property_read_fails(self, prop=IPV4_IGNORE):
        self.codes[PROPERTY_READ + (prop, "connection", "show", UUID)] = 1
        self.overrides[PROPERTY_READ + (prop, "connection", "show", UUID)] = ""

    def test_it_never_consults_preflight(self):
        for relative in ("/var/lib/mosdns", "/var/lib/mosdns/runtime", "/var/lib/mosdns/lists", "/run/mosdns"):
            self.rooted(relative).chmod(0o777)
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"a machine preflight refuses could not be rolled back: {self.result.error}")
        for command in self.commands:
            self.assertNotEqual(command[:1], ("dpkg",), "the rollback ran a preflight check")
            self.assertNotEqual(command[:2], ("systemctl", "--version"))

    def test_it_leaves_the_units_the_configuration_and_the_hook_in_place(self):
        before = self.snapshot()
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"the rollback did not finish: {self.result.error}")
        self.assertNothingTouched(
            before, "an emergency rollback removed a file; the binaries and the configuration are "
            "left installed for diagnosis"
        )
        for command in self.commands:
            self.assertFalse(self.changing(command) and command[:1] == ("systemctl",), f"{command!r} touches a unit")

    def test_it_restores_the_backup_written_by_the_last_install(self):
        # One backup file, written by the most recent install attempt, so "the
        # last valid backup" is the file as it is at the moment of the rollback
        # and not anything a run cached.
        second = backup_document(original={**RECORDED_RAW, IPV4_DNS: "192.0.2.77", IPV6_DNS: "2001:db8::53"})
        self.write_backup(second)
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"the rollback did not finish: {self.result.error}")
        self.assertIn(MODIFY + (UUID, IPV4_DNS, "192.0.2.77"), self.commands)
        self.assertNotIn(MODIFY + (UUID, IPV4_DNS, DHCP_UPSTREAM), self.commands)
        self.assertNotIn(
            MODIFY + (UUID, IPV6_DNS, "2001:db8::53"),
            self.commands,
            "the rollback restored a property the install never changed",
        )

    def test_it_verifies_the_machine_resolves_with_the_resolving_predicate(self):
        self.result = self.run_rollback()
        self.assertTrue(self.result.ok, f"the rollback did not finish: {self.result.error}")
        self.assertEqual(
            self.probes,
            [(RESOLVED_STUB, DNS_PORT)],
            "the rollback asked a question about something other than whether this machine can "
            "resolve",
        )
        self.assertTrue(self.result.resolves, "a healthy chain was not reported as resolving")

    def test_a_servfail_after_the_rollback_is_not_reported_as_resolving(self):
        # The whole of the previous round's finding: a SERVFAIL is an answer from
        # a chain that reached nobody, and a rollback that calls that success hands
        # the operator a machine with no DNS and a reassuring message.
        self.result = self.run_rollback(probe=self.probe_for(stub=SERVFAIL))
        self.assertFalse(self.result.ok, "a SERVFAIL was reported as a successful rollback")
        self.assertIs(self.result.resolves, False)
        self.assertIn("still cannot resolve", (self.result.error or "") + " ".join(self.result.notes))
        self.assertIn("restored", (self.result.error or "").lower(), "the operator has to know the profile is back")

    def test_a_refused_answer_is_not_resolving_either(self):
        self.result = self.run_rollback(probe=self.probe_for(stub=REFUSED))
        self.assertFalse(self.result.ok)

    def test_silence_is_not_resolving_either(self):
        self.result = self.run_rollback(probe=self.probe_for(stub=SILENT))
        self.assertFalse(self.result.ok)

    def test_a_device_still_on_the_loopback_is_reported(self):
        self.overrides[RESOLVECTL_DNS] = f"Link 2 ({DEVICE}): {LOCAL_DNS}\n"
        self.result = self.run_rollback()
        self.assertFalse(self.result.ok, "a machine still on the loopback was reported as rolled back")
        self.assertIn(LOCAL_DNS, (self.result.error or ""))

    def test_a_backup_that_does_not_validate_is_refused_and_nothing_is_changed(self):
        for document in (
            backup_document(schema=7),
            backup_document(managed_by="another-project"),
            backup_document(uuid=""),
            backup_document(device=""),
            None,
        ):
            with self.subTest(document="absent" if document is None else document["schema_version"]):
                self.setUp()
                if document is None:
                    self.rooted(BACKUP_PATH).unlink()
                else:
                    self.write_backup(document)
                before = self.snapshot()
                self.result = self.run_rollback()
                self.assertNothingChanged(f"a rollback refused over {document} changed the machine")
                self.assertNothingTouched(before, "a refused rollback wrote to the filesystem")
                self.assertFalse(self.result.ok, "a backup that does not validate was restored from")
                self.assertEqual(self.commands, [], "a refused rollback ran a command")

    def test_a_backup_that_is_not_a_document_is_refused(self):
        self.write(BACKUP_PATH, "{}\n", mode=BACKUP_MODE)
        self.result = self.run_rollback()
        self.assertFalse(self.result.ok)
        self.assertEqual(self.commands, [])

    def test_a_refused_rollback_still_hands_over_the_commands(self):
        self.rooted(BACKUP_PATH).unlink()
        self.result = self.run_rollback()
        report = self.result.manual_recovery or ""
        self.assertIn(BACKUP_PATH, report)
        self.assertIn("still", report.lower())

    def test_a_rollback_whose_restore_fails_reports_the_command_that_finishes_it(self):
        self.result = self.run_rollback(runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)]))
        self.assertFalse(self.result.ok)
        self.assertIn(
            f"nmcli connection up {UUID}",
            (self.result.error or "") + (self.result.manual_recovery or ""),
            "the profile is back and only the reactivation is missing",
        )
        self.assertEqual(
            self.probes,
            [],
            "a rollback that could not reactivate has nothing to verify, and asking anyway would "
            "report on a machine it did not restore",
        )


class CliTests(UninstallFixture):
    """The command as a person runs it, and the statuses that mean things."""

    def test_a_successful_uninstall_exits_zero_and_says_what_it_did(self):
        status, out, err = self.run_cli("uninstall")
        self.assertEqual(status, installer.EXIT_OK, err)
        self.assertIn(UUID, out)
        self.assertIn(STATE_DIRECTORY, out)
        self.assertIn("kept", out, "an operator has to be told the state directory is still there")

    def test_a_purge_says_the_state_is_gone(self):
        status, out, err = self.run_cli("uninstall", "--purge")
        self.assertEqual(status, installer.EXIT_OK, err)
        self.assertIn(STATE_DIRECTORY, out)
        self.assertIn("removed", out)
        self.assertFalse(self.rooted(STATE_DIRECTORY).exists())

    def test_a_refused_ownership_exits_five_and_prints_the_report(self):
        # Two refusals with two different reports, because they have two
        # different next steps: one where nothing was changed by anybody and the
        # report is the whole command block, and one where a property was changed
        # after the install and the report must tell the operator to leave it.
        self.remove_marker()
        status, out, err = self.run_cli("uninstall")
        self.assertEqual(status, installer.EXIT_OWNERSHIP_REFUSED, err)
        self.assertEqual(out, "", "a refusal reported a result on standard output")
        for command in restore_commands():
            self.assertIn(command, err, "the report did not reach the operator")

        self.setUp()
        self.property_value(IPV4_DNS, "192.0.2.99")
        status, out, err = self.run_cli("uninstall")
        self.assertEqual(status, installer.EXIT_OWNERSHIP_REFUSED, err)
        self.assertIn("leave ipv4.dns at 192.0.2.99", err)
        self.assertNotIn(f"nmcli connection modify {UUID} {IPV4_DNS} {DHCP_UPSTREAM}", err)

    def test_an_incomplete_restore_exits_six(self):
        status, out, err = self.run_cli(
            "uninstall", runner=self.good_runner(fail=[CONNECTION_UP + (UUID,)])
        )
        self.assertEqual(status, installer.EXIT_RESTORE_INCOMPLETE, err)
        self.assertIn("still", err.lower())
        self.assertIn(f"nmcli connection up {UUID}", err)

    def test_a_refused_rollback_exits_five_and_a_rollback_that_finished_exits_zero(self):
        self.rooted(BACKUP_PATH).unlink()
        status, out, err = self.run_cli("emergency-rollback")
        self.assertEqual(status, installer.EXIT_OWNERSHIP_REFUSED, err)
        self.assertIn(BACKUP_PATH, err)

        self.setUp()
        status, out, err = self.run_cli("emergency-rollback")
        self.assertEqual(status, installer.EXIT_OK, err)
        self.assertIn(UUID, out)

    def test_a_rollback_that_could_not_verify_exits_six(self):
        status, out, err = self.run_cli("emergency-rollback", probe=self.probe_for(stub=SERVFAIL))
        self.assertEqual(status, installer.EXIT_RESTORE_INCOMPLETE, err)
        self.assertIn("cannot resolve", err)

    def test_a_usage_error_runs_nothing_at_all(self):
        for arguments in (
            (),
            ("uninstall", "--purge-everything"),
            ("uninstall", "purge"),
            ("uninstall", "--purge", "--purge"),
            ("emergency-rollback", "--force"),
            ("preflight", "uninstall"),
        ):
            with self.subTest(arguments=arguments):
                self.setUp()
                self._commands = []
                runner = self.good_runner()
                status, out, err = self.run_cli(*arguments, runner=runner)
                self.assertEqual(status, installer.EXIT_USAGE, f"{arguments} was accepted")
                self.assertEqual(runner.calls, [], f"{arguments} read the machine it was given")
                self.assertEqual(out, "")

    def test_the_usage_names_every_verb(self):
        for arguments in ((), ("install", "--force")):
            with self.subTest(arguments=arguments):
                _, _, err = self.run_cli(*arguments)
                for verb in ("preflight", "install", "uninstall", "emergency-rollback"):
                    self.assertIn(verb, err, f"the usage line does not name {verb}")
                self.assertIn("--purge", err)
                self.assertNotIn("--fix", err)


class NeverAppliedRemovalTests(UninstallFixture):
    """A machine this package provably never changed has to be removable.

    The marker is written LAST, so every install that failed anywhere above it
    left none, and `uninstall` refused on that alone -- which means a failed
    install leaves a package that no documented means can remove. `prerm` turns
    the refusal into `exit 1`, dpkg aborts a removal whose pre-removal script
    fails, and the refusal's own advice ("put the connection back by hand, or
    reboot, and then remove the package") does not work, because rebooting does
    not create a marker.

    The refinement is provable rather than hopeful, and it is the ORDER the
    transaction runs in: the record of the machine's original DNS settings is
    written, read back, compared field by field and mode-checked BEFORE the first
    mutation, and a transaction that cannot do that refuses. So **no record at
    all** means no transaction of this package ever reached a mutation -- there is
    nothing to put back, because nothing was ever taken. In that state stopping
    the units and removing the hook is safe, and only the connection restore
    needed the record.

    The other half matters as much: a machine with a record and no marker is a
    DIFFERENT machine, and it still refuses. That is the case where an install
    got far enough to record and then failed, and it is the case the connection
    restore is for.
    """

    def refused_at_the_barrier(self):
        """This package's own install, refused before it recorded anything.

        The fake root has no `/etc/os-release`, so preflight refuses the machine
        at its first gate -- before the capture, before the record, before any
        mutation. The two absences this test then asserts are the ones the whole
        refinement rests on, so they are produced by the real install rather than
        arranged by hand.
        """
        self.remove_marker()
        self.rooted(BACKUP_PATH).unlink()
        result = installer.install(self.root, self.good_runner(), probe=self.probe_for())
        self.assertFalse(result.ok, "a machine with no /etc/os-release was installable")
        self.assertFalse(
            self.rooted(MANAGED_BY).exists(),
            "an install refused at preflight left an ownership marker behind",
        )
        self.assertFalse(
            self.rooted(BACKUP_PATH).exists(),
            "an install refused at preflight left a record behind, and a record is what makes "
            "'nothing was ever applied' unprovable",
        )
        return result

    def test_an_install_refused_at_the_barrier_leaves_no_marker_and_no_record(self):
        self.refused_at_the_barrier()

    def test_such_a_package_is_removable_and_dpkg_is_told_so(self):
        self.refused_at_the_barrier()
        before = self.snapshot()
        status, out, err = self.run_cli("uninstall")
        self.assertEqual(
            status,
            installer.EXIT_OK,
            f"the uninstall refused a machine this package never changed, and prerm turns that "
            f"into exit 1, which aborts the removal and leaves the operator with a package they "
            f"cannot remove: {err}",
        )
        self.assertEqual(err, "", "a removal that succeeded complained about something")
        for unit in (*PROJECT_TIMERS, *STOPPED_ONESHOT, *STOPPED_UNITS):
            with self.subTest(unit=unit):
                self.assertIn(("systemctl", "stop", unit), self.commands)
        self.assertFalse(
            [command for command in self.commands if command[:2] == MODIFY],
            "a removal with nothing to restore wrote to the connection anyway",
        )
        self.assertNotIn(DISPATCHER_SCRIPT, self.snapshot())
        self.assertEqual(
            sorted(set(before) - set(self.snapshot())),
            [DISPATCHER_SCRIPT.lstrip("/")],
            "the removal removed something other than the one file under /etc this package installs",
        )
        # And the sentence that matters, because this is the one place in the
        # program that removes a machine's resolver WITHOUT the record that says
        # where the machine's own resolvers are.
        self.assertIn("nothing of this package was ever applied", out)

    def test_prerm_passes_this_status_through_so_dpkg_removes_the_package(self):
        # The composition of two things this file does not own: the status the
        # installer returns, and what `prerm` does with it. dpkg aborts a removal
        # whose pre-removal script exits non-zero, so the one non-zero exit in the
        # remove arm has to be the branch where the uninstall failed -- and the
        # script's last word has to be success, or a status of zero would still
        # not let the removal happen.
        self.refused_at_the_barrier()
        status, _out, _err = self.run_cli("uninstall")
        self.assertEqual(status, installer.EXIT_OK)
        text = (REPO / "packaging" / "debian" / "prerm").read_text(encoding="utf-8")
        # The whole arm, cut at the NEXT outer label. Cutting at the first `;;`
        # would stop inside the nested `case` on the installer's status, whose
        # arms also end in `;;` -- and would then report an arm with no exit in it
        # for a script that has one.
        arm = text.split("remove|deconfigure)", 1)[1].split("upgrade | failed-upgrade)", 1)[0]
        self.assertIn('"$INSTALLER" uninstall', arm)
        self.assertEqual(
            [line.strip() for line in arm.splitlines() if line.strip().startswith("exit ")],
            ["exit 1"],
            "prerm's remove arm exits somewhere other than the branch where the uninstall failed, "
            "so a status of 0 would not remove the package",
        )
        self.assertTrue(
            text.rstrip().endswith("exit 0"),
            "prerm does not end in success, so a status of 0 would still abort the removal",
        )

    def test_a_record_without_a_marker_still_refuses(self):
        # The other half of the refinement, and the case the refinement must not
        # swallow: an install that got as far as recording and then failed leaves a
        # record and no marker, and there the connection restore is exactly what
        # is needed.
        self.remove_marker()
        result = self.run_uninstall()
        self.assertFalse(result.ok, "a machine with a record and no marker reported a clean removal")
        self.assertNotIn(
            ("systemctl", "stop", ROUTER_UNIT),
            self.commands,
            "the router was stopped on a machine whose record says the connection may still be "
            "using 127.0.0.1",
        )
        self.assertIn(MANAGED_BY, " ".join(result.refusals))


class SourceScanTests(unittest.TestCase):
    """What the module is allowed to name, read from its own source."""

    def test_the_module_names_only_this_plans_dispatcher_file(self):
        named = set(re.findall(r"/etc/NetworkManager/dispatcher\.d/[A-Za-z0-9._/-]+", SOURCE))
        self.assertEqual(
            named,
            {DISPATCHER_SCRIPT},
            f"the module names a dispatcher file this plan does not install: {sorted(named - {DISPATCHER_SCRIPT})}",
        )

    def test_the_dispatcher_scan_fires_on_another_hook(self):
        scan = lambda text: set(  # noqa: E731
            re.findall(r"/etc/NetworkManager/dispatcher\.d/[A-Za-z0-9._/-]+", text)
        )
        self.assertEqual(
            scan("/etc/NetworkManager/dispatcher.d/no-wait.d/10-other\n"),
            {"/etc/NetworkManager/dispatcher.d/no-wait.d/10-other"},
            "the scan cannot see a second hook, so the rule above proves nothing",
        )
        self.assertEqual(scan("no hook here\n"), set(), "the control case is not clean")

    def test_the_module_names_only_the_networkmanager_properties_it_records(self):
        # Task 4's rule, restated here because this task is the one that WRITES
        # properties rather than reading them: a restore may only put back a value
        # the backup recorded, and a property the backup does not record is one
        # this program must not name.
        named = set(re.findall(r"\bipv[46]\.[A-Za-z0-9_.-]+", SOURCE))
        self.assertEqual(
            named,
            set(RECORDED_PROPERTIES),
            f"the module names NetworkManager properties it does not record: {sorted(named - set(RECORDED_PROPERTIES))}",
        )

    def test_the_property_scan_fires_on_a_property_it_does_not_record(self):
        scan = lambda text: set(re.findall(r"\bipv[46]\.[A-Za-z0-9_.-]+", text))  # noqa: E731
        self.assertEqual(
            scan('PROP = "ipv4.dns-priority"\n'),
            {"ipv4.dns-priority"},
            "the scan cannot see a fifth property, so the rule above proves nothing",
        )
