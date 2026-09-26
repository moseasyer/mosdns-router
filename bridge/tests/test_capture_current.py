"""Tests for capturing the DHCP DNS a machine is using right now, before any event.

The installer rewrites NetworkManager's DNS, so it has to know the resolvers that
are in use *before* it touches anything, and it has to write them somewhere the
router already reads. That is the whole job of ``--capture-current INTERFACE``,
and the one thing that could go wrong quietly is publishing a document the router
would not accept, or one that disagrees with what the first ``up`` event records
a moment later. These tests hold to the parts that matter:

* **The mode is exclusive.** A dispatcher environment and ``--capture-current``
  are the two ways this program is run, and either one alone is a mode. A
  command line carrying both, or neither, is refused before any command runs,
  and a refused argument is not the same thing as an unknown one.
* **The commands are exact.** ``nmcli`` is asked for specific fields in a
  specific order, and the argument array *is* the injection boundary for the
  whole installer, so every case asserts the arrays rather than the answers.
* **The document is one the router can use.** A capture records the source the
  collector reported, records the connection the lease belongs to, and produces
  a document whose fields are the ones the Go verifier proved acceptable. It
  never records a source token of its own.
* **It is the same writer, not a second one.** A capture and the first event
  after it are one state, so neither advances the generation on its own.

The runner double is local to this file: the other bridge tests each keep their
own, and this suite is also run as ``bridge.tests.test_capture_current``, where
a sibling test module is not importable.
"""

import contextlib
import fcntl
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# The bridge package is used from a source checkout, not from an installed
# distribution, so the repository's bridge directory is the import root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mosdns_dhcp_bridge import cli

INTERFACE = "enp3s0"
UUID = "11111111-1111-1111-1111-111111111111"

# The exact argument arrays a capture may build for one interface. DHCP4 and DHCP6
# are read separately because a colon is both nmcli's field separator and part of
# every IPv6 address.
RAW_DHCP4 = ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE)
RAW_DHCP6 = ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE)
EFFECTIVE_IP4 = ("nmcli", "-g", "IP4.DNS", "device", "show", INTERFACE)
EFFECTIVE_IP6 = ("nmcli", "-g", "IP6.DNS", "device", "show", INTERFACE)
RESOLVECTL = ("resolvectl", "dns", INTERFACE)
COLLECTOR_COMMANDS = (RAW_DHCP4, RAW_DHCP6, EFFECTIVE_IP4, EFFECTIVE_IP6, RESOLVECTL)

# The field that carries the UUID of the connection a device is using. Its
# sibling GENERAL.CONNECTION holds the connection's NAME -- "netplan-ens33" on a
# machine whose connection is called that -- and a name is not something the
# state may record, so a lookup that asked for it would leave every capture
# without a connection.
CONNECTION = ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", INTERFACE)

# Every source token the collector can report, spelled out because this is the
# vocabulary a published state may draw from. A capture adds no token of its own,
# and the plan names the one it must not add.
COLLECTOR_SOURCES = (
    "nm-dhcp4",
    "nm-dhcp6",
    "nm-dhcp",
    "dispatcher-env",
    "nm-effective",
    "resolved",
)

# The cross-language fixture the Go verifier reads. A capture has to produce a
# document with exactly these fields, or the router would be reading a shape
# nothing proved acceptable.
VERIFIED_FIELDS = sorted(
    json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "dhcp-upstreams.json").read_text()
    )
)


class RecordingRunner:
    """A command runner double that answers exact argument arrays.

    A command the test did not prepare answers empty, so a command built with a
    wrong flag, a wrong field, or the wrong arguments is visible in ``calls``
    instead of being answered by accident, and anything that is not an argument
    array is refused outright.
    """

    def __init__(self, answers=None, failures=None):
        self._answers = dict(answers or {})
        self._failures = dict(failures or {})
        self.calls = []

    def __call__(self, argv):
        if not isinstance(argv, (list, tuple)):
            raise TypeError("a command must be an argument array, not a shell string")
        command = tuple(argv)
        self.calls.append(command)
        if command in self._failures:
            raise self._failures[command]
        return self._answers.get(command, "")


class BrokenRunner(RecordingRunner):
    """A runner whose every command fails, the way a wedged D-Bus does."""

    def __call__(self, argv):
        if not isinstance(argv, (list, tuple)):
            raise TypeError("a command must be an argument array, not a shell string")
        self.calls.append(tuple(argv))
        raise OSError("Could not connect to the system bus")


class CaptureCase(unittest.TestCase):
    """One capture against a real state file, a real lock, and a real clock."""

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.state_path = self.directory / "dhcp-upstreams.json"
        self.lock_path = self.directory / "dhcp-bridge.lock"

    def argv(self, interface=INTERFACE, *rest):
        """The installation's invocation, exactly as the plan writes it."""
        return [
            "--capture-current",
            interface,
            "--state-file",
            str(self.state_path),
            "--lock-file",
            str(self.lock_path),
            *rest,
        ]

    def call(self, env=None, argv=None, runner=None):
        """Run the CLI and return its exit code, its stderr, and the runner."""
        runner = RecordingRunner() if runner is None else runner
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = cli.main(self.argv() if argv is None else argv, env or {}, runner)
        return code, stderr.getvalue(), runner

    def capture(self, answers=None, failures=None, env=None, argv=None, runner=None):
        """Run one capture and return its exit code, its stderr, and the runner."""
        if runner is None:
            runner = RecordingRunner(answers, failures)
        return self.call(env, argv, runner)

    def event(self, action, **variables):
        """Return a dispatcher environment for ``action``."""
        environment = {"NM_DISPATCHER_ACTION": action}
        environment.update(variables)
        return environment

    def dispatch(self, env, answers=None, failures=None, argv=None):
        """Run one dispatcher event against the same files a capture uses."""
        dispatcher_argv = argv or [
            "--state-file",
            str(self.state_path),
            "--lock-file",
            str(self.lock_path),
        ]
        return self.call(env, dispatcher_argv, RecordingRunner(answers, failures))

    def published(self):
        """Return the state file exactly as the router would find it."""
        return json.loads(self.state_path.read_text())

    def bytes_on_disk(self):
        return self.state_path.read_bytes()

    @contextlib.contextmanager
    def held_lock(self):
        """Hold the publication lock the way another bridge process would."""
        descriptor = os.open(str(self.lock_path), os.O_CREAT | os.O_RDONLY, 0o640)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


class CaptureModeTests(CaptureCase):
    """Which invocation the program is being run as.

    An installation runs this program with no event behind it and names the
    interface itself; NetworkManager runs it with an event in the environment
    and no such option. Treating them as one program with two inputs is what
    keeps a capture from being a second writer with a second idea of what the
    state means.
    """

    def test_a_capture_publishes_the_lease_the_raw_dhcp_field_carries(self):
        code, _, _ = self.capture(
            {RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            self.published(),
            {
                "schema_version": 1,
                "generation": 1,
                "interface": "enp3s0",
                "connection_uuid": UUID,
                "upstreams": ["192.168.1.1"],
                "observed_at": self.published()["observed_at"],
                "source": "nm-dhcp4",
                "last_good": True,
            },
        )
        self.assertRegex(self.published()["observed_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_a_capture_runs_the_collector_calls_and_one_connection_lookup(self):
        code, _, runner = self.capture({CONNECTION: UUID + "\n"})
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [*COLLECTOR_COMMANDS, CONNECTION])

    def test_a_capture_that_falls_through_to_the_device_dns_asks_for_both_families(self):
        code, _, runner = self.capture(
            {EFFECTIVE_IP4: "192.168.1.9", CONNECTION: UUID + "\n"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(
            runner.calls,
            [RAW_DHCP4, RAW_DHCP6, EFFECTIVE_IP4, EFFECTIVE_IP6, CONNECTION],
        )
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("nm-effective", ["192.168.1.9"]))

    def test_a_capture_that_falls_through_to_resolved_asks_resolvectl_last(self):
        code, _, runner = self.capture(
            {
                RESOLVECTL: f"Link 2 ({INTERFACE}): 192.168.1.1",
                CONNECTION: UUID + "\n",
            },
            failures={command: OSError("nmcli") for command in COLLECTOR_COMMANDS if command != RESOLVECTL},
        )
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [*COLLECTOR_COMMANDS, CONNECTION])
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("resolved", ["192.168.1.1"]))

    def test_a_capture_that_falls_through_to_the_environment_records_that_source(self):
        code, _, runner = self.capture(
            {CONNECTION: UUID + "\n"},
            env={"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1"},
        )
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6, CONNECTION])
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("dispatcher-env", ["192.168.1.1"]))

    def test_the_dhcp6_field_alone_is_recorded_as_nm_dhcp6(self):
        code, _, _ = self.capture({RAW_DHCP6: "fd00::1", CONNECTION: UUID + "\n"})
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("nm-dhcp6", ["fd00::1"]))

    def test_both_raw_dhcp_families_are_recorded_as_one_source(self):
        code, _, _ = self.capture(
            {RAW_DHCP4: "192.168.1.1", RAW_DHCP6: "fd00::1", CONNECTION: UUID + "\n"}
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("nm-dhcp", ["192.168.1.1", "fd00::1"]))

    def test_the_source_comes_from_the_collector_and_is_never_one_of_its_own(self):
        """A source no collector can produce describes nothing about the lease.

        The published token is compared when the plugin decides whether anything
        changed, so a token that named the caller rather than the source would
        turn every later event into a new generation, and a token the router's
        vocabulary does not carry would be a document nothing proved usable.
        """
        answers = [
            {RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"},
            {RAW_DHCP6: "fd00::1", CONNECTION: UUID + "\n"},
            {RAW_DHCP4: "192.168.1.1", RAW_DHCP6: "fd00::1", CONNECTION: UUID + "\n"},
            {CONNECTION: UUID + "\n"},
            {EFFECTIVE_IP4: "192.168.1.9", CONNECTION: UUID + "\n"},
            {RESOLVECTL: f"Link 2 ({INTERFACE}): 192.168.1.1", CONNECTION: UUID + "\n"},
        ]
        recorded = set()
        for case, values in enumerate(answers):
            with self.subTest(case=case):
                if self.state_path.exists():
                    self.state_path.unlink()
                self.assertEqual(self.capture(values)[0], 0)
                recorded.add(self.published()["source"])
        self.assertTrue(recorded, "no capture published a source")
        self.assertEqual(
            sorted(recorded - set(COLLECTOR_SOURCES)), [], "a capture recorded a source of its own"
        )
        self.assertNotIn("installer-current", recorded)

    def test_the_connection_the_caller_exports_is_used_without_asking_networkmanager(self):
        code, _, runner = self.capture(
            {RAW_DHCP4: "192.168.1.1", CONNECTION: "22222222-2222-2222-2222-222222222222\n"},
            env={"CONNECTION_UUID": UUID},
        )
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])
        self.assertEqual(self.published()["connection_uuid"], UUID)

    def test_a_capture_writes_nothing_to_the_dispatcher_streams(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        runner = RecordingRunner({CONNECTION: UUID + "\n"})
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(self.argv(), {}, runner)
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_the_capture_document_carries_exactly_the_verified_state_fields(self):
        self.assertEqual(self.capture({CONNECTION: UUID + "\n"})[0], 0)
        self.assertEqual(sorted(self.published()), VERIFIED_FIELDS)


class ModeExclusivityTests(CaptureCase):
    """The two invocations are mutually exclusive, and one of them is required.

    A program that acted on both would publish twice from one command line, and a
    program that accepted neither would guess at an event that never happened.
    """

    def test_a_capture_beside_a_dispatcher_event_is_refused(self):
        for action in ["up", "dhcp4-change", "dhcp6-change", "down", "dns-change"]:
            with self.subTest(action=action):
                code, stderr, runner = self.capture(
                    {CONNECTION: UUID + "\n"},
                    env={"NM_DISPATCHER_ACTION": action, "DEVICE_IP_IFACE": INTERFACE},
                )
                self.assertEqual(code, 2)
                self.assertIn("NM_DISPATCHER_ACTION", stderr)
                self.assertIn("--capture-current", stderr)
                # A known option in a combination this program refuses is not an
                # option it has never heard of, and saying so is the difference
                # between an installer typo and a misconfigured call.
                self.assertNotIn("unknown argument", stderr)
                self.assertEqual(runner.calls, [])
                self.assertFalse(self.state_path.exists())

    def test_a_capture_beside_an_event_this_bridge_ignores_is_refused_too(self):
        """Ignoring an event is not the same as not having one.

        An event the collector would never read is still a dispatcher
        invocation, and a capture run beside it would publish a state the
        dispatcher is about to publish again.
        """
        code, stderr, runner = self.capture(
            {CONNECTION: UUID + "\n"}, env={"NM_DISPATCHER_ACTION": "connectivity-change"}
        )
        self.assertEqual(code, 2)
        self.assertIn("NM_DISPATCHER_ACTION", stderr)
        self.assertIn("--capture-current", stderr)
        self.assertEqual(runner.calls, [])
        self.assertFalse(self.state_path.exists())

    def test_neither_a_capture_nor_a_dispatcher_event_is_refused(self):
        code, stderr, runner = self.dispatch({})
        self.assertEqual(code, 2)
        self.assertIn("NM_DISPATCHER_ACTION", stderr)
        self.assertIn("--capture-current", stderr)
        self.assertEqual(runner.calls, [])
        self.assertFalse(self.state_path.exists())

    def test_an_empty_dispatcher_action_is_not_an_event_a_capture_may_join(self):
        """An exported but empty action names no event, so the capture stands.

        NetworkManager always exports a real action of its own; an empty value is
        an environment that happens to hold the variable, and refusing a capture
        beside it would fail an installation run from a shell that had exported
        it earlier.
        """
        code, _, _ = self.capture({CONNECTION: UUID + "\n"}, env={"NM_DISPATCHER_ACTION": ""})
        self.assertEqual(code, 0)
        self.assertEqual(self.published()["interface"], INTERFACE)

    def test_a_capture_needs_one_interface(self):
        for tail in [
            ["--state-file", str(self.state_path), "--lock-file", str(self.lock_path)],
            ["--state-file", str(self.state_path), "--lock-file", str(self.lock_path), ""],
            [
                "--capture-current",
                INTERFACE,
                "--capture-current",
                "br-lan",
                "--state-file",
                str(self.state_path),
                "--lock-file",
                str(self.lock_path),
            ],
        ]:
            with self.subTest(argv=tail):
                runner = RecordingRunner({CONNECTION: UUID + "\n"})
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    code = cli.main(tail, {}, runner)
                self.assertEqual(code, 2)
                self.assertIn("--capture-current", stderr.getvalue())
                self.assertEqual(runner.calls, [])
                self.assertFalse(self.state_path.exists())

    def test_a_capture_beside_the_dispatchers_positional_arguments_is_refused(self):
        """The dispatcher names its interface positionally; a capture names its own.

        Both on one command line is a line whose interface is ambiguous, and the
        answer an operator needs is which of the two arguments the program read.
        """
        code, stderr, runner = self.capture({CONNECTION: UUID + "\n"}, argv=self.argv(INTERFACE, "br-lan"))
        self.assertEqual(code, 2)
        self.assertIn("--capture-current", stderr)
        self.assertIn("br-lan", stderr)
        self.assertEqual(runner.calls, [])
        self.assertFalse(self.state_path.exists())

    def test_the_capture_option_is_accepted_in_either_order(self):
        """The plan writes the option first and an operator may write it last."""
        for argv in [
            self.argv(INTERFACE),
            [
                "--state-file",
                str(self.state_path),
                "--lock-file",
                str(self.lock_path),
                "--capture-current",
                INTERFACE,
            ],
        ]:
            with self.subTest(argv=argv[:1]):
                self.assertEqual(self.capture({CONNECTION: UUID + "\n"}, argv=argv)[0], 0)
                self.assertEqual(self.published()["interface"], INTERFACE)

    def test_an_option_this_program_does_not_know_is_still_unknown(self):
        runner = RecordingRunner({CONNECTION: UUID + "\n"})
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = cli.main(self.argv(INTERFACE) + ["--verbose"], {}, runner)
        self.assertEqual(code, 2)
        self.assertIn("unknown argument", stderr.getvalue())
        self.assertEqual(runner.calls, [])

    def test_a_dispatcher_event_without_the_option_still_publishes(self):
        code, _, runner = self.dispatch(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("dispatcher-env", ["192.168.1.1"]))


class CaptureInterfaceTests(CaptureCase):
    """The interface a capture names is checked before anything is asked of it.

    The name reaches fixed argument arrays and the published document, and the
    publisher holds it to the same rule, so a value the state could not carry is
    refused while refusing it is still free.
    """

    def test_an_interface_no_device_could_own_is_refused_before_any_command(self):
        for interface in [
            "enp3s0:1",
            "enp3s0 eth0",
            "enp3s0;id",
            "enp3s0|id",
            "enp3s0$(id)",
            "enp3s0\n",
            "-enp3s0",
            ".enp3s0",
            "_enp3s0",
            "../etc/passwd",
            "/dev/null",
            "abcdefghijklmnop",
            # The value after the option is the interface, whatever it looks like:
            # an option-shaped value is a bad interface, not a second option.
            "--verbose",
        ]:
            with self.subTest(interface=interface):
                code, stderr, runner = self.capture(
                    {CONNECTION: UUID + "\n"}, argv=self.argv(interface)
                )
                self.assertEqual(code, 2)
                self.assertIn("--capture-current", stderr)
                self.assertIn("interface name", stderr)
                # The value is rendered repr-style, so an interface carrying a
                # newline cannot break the one line the dispatcher's log holds.
                self.assertIn(repr(interface), stderr)
                self.assertEqual(stderr.count("\n"), 1)
                self.assertEqual(runner.calls, [])
                self.assertFalse(self.state_path.exists())
                self.assertFalse(self.lock_path.exists())

    def test_every_command_asks_about_the_interface_the_capture_named(self):
        code, _, runner = self.capture(
            {CONNECTION: UUID + "\n"}, argv=self.argv("br-lan")
        )
        self.assertEqual(code, 0)
        for field in [
            "DHCP4.OPTION_DOMAIN_NAME_SERVERS",
            "DHCP6.OPTION_DOMAIN_NAME_SERVERS",
            "IP4.DNS",
            "IP6.DNS",
            "GENERAL.CON-UUID",
        ]:
            with self.subTest(field=field):
                self.assertIn(
                    ("nmcli", "-g", field, "device", "show", "br-lan"), runner.calls
                )
        self.assertIn(("resolvectl", "dns", "br-lan"), runner.calls)
        self.assertEqual(self.published()["interface"], "br-lan")

    def test_an_interface_the_kernel_could_own_is_accepted(self):
        for interface in ["enp3s0", "eth0.100", "vlan_2", "2eth0", "abcdefghijklmno"]:
            with self.subTest(interface=interface):
                if self.state_path.exists():
                    self.state_path.unlink()
                code, _, _ = self.capture(
                    {CONNECTION: UUID + "\n"}, argv=self.argv(interface)
                )
                self.assertEqual(code, 0)
                self.assertEqual(self.published()["interface"], interface)


class CaptureConnectionTests(CaptureCase):
    """The connection a capture's resolvers belong to, and what happens without it.

    A state that names resolvers has to name the connection they came from: the
    router reads that field to decide whether a lease is the one it is following,
    and the publisher refuses a state with upstreams and no connection at all.
    The lookup is therefore part of the capture rather than a convenience, and a
    machine that cannot answer it publishes nothing.
    """

    def test_a_connection_that_could_not_be_read_publishes_nothing(self):
        self.assertEqual(
            self.capture({RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"})[0], 0
        )
        original = self.bytes_on_disk()
        before = self.state_path.stat()
        code, stderr, _ = self.capture(
            {RESOLVECTL: f"Link 2 ({INTERFACE}): 192.168.1.53"},
            failures={
                command: OSError("nmcli")
                for command in [*COLLECTOR_COMMANDS, CONNECTION]
                if command != RESOLVECTL
            },
        )
        self.assertEqual(code, 4)
        self.assertEqual(self.bytes_on_disk(), original)
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)
        for secret in [INTERFACE, UUID, "192.168.1.53", "Could not connect to the system bus"]:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, stderr)

    def test_a_lookup_that_answers_something_other_than_a_string_is_not_an_answer(self):
        code, _, _ = self.capture({RAW_DHCP4: "192.168.1.1", CONNECTION: None})
        self.assertEqual(code, 4)
        self.assertFalse(self.state_path.exists())
        self.assertFalse(self.lock_path.exists())

    def test_an_empty_connection_beside_resolvers_is_invalid_input(self):
        code, stderr, runner = self.capture({RAW_DHCP4: "192.168.1.1", CONNECTION: ""})
        self.assertEqual(code, 2)
        self.assertIn("connection_uuid", stderr)
        self.assertEqual(runner.calls[-1], CONNECTION)
        self.assertFalse(self.state_path.exists())

    def test_a_connection_that_is_not_a_uuid_is_invalid_input(self):
        """A connection name is what GENERAL.CONNECTION holds, and it is not a UUID."""
        code, stderr, _ = self.capture(
            {RAW_DHCP4: "192.168.1.1", CONNECTION: "Wired connection 1\n"}
        )
        self.assertEqual(code, 2)
        self.assertIn("connection_uuid", stderr)
        self.assertFalse(self.state_path.exists())

    def test_a_device_with_no_connection_publishes_a_disabled_state(self):
        code, _, _ = self.capture({CONNECTION: ""})
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual(
            (data["upstreams"], data["last_good"], data["connection_uuid"]), ([], False, "")
        )

    def test_a_disabled_capture_names_the_connection_so_the_next_event_agrees(self):
        """An empty lease still records which connection stopped answering.

        A state with no resolvers may leave the connection empty, but a capture
        and the first event after it are the same observation, and one of them
        recording a connection the other omits is two generations for a lease
        that never changed.
        """
        self.assertEqual(self.capture({CONNECTION: UUID + "\n"})[0], 0)
        original = self.bytes_on_disk()
        code, _, _ = self.dispatch(
            self.event("up", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID)
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.bytes_on_disk(), original)
        self.assertEqual(self.published()["generation"], 1)


class CaptureGenerationTests(CaptureCase):
    """A capture is one state, not a generation the next event has to advance.

    The installer's capture and the first dispatcher event after it read the
    same lease through the same source. Two generations for that pair would
    reload the plugin and drop its cache for resolvers that never moved, and it
    is the one place where a second writer would be visible from the outside.
    """

    def test_the_capture_and_the_first_up_event_after_it_record_one_state(self):
        answers = {RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"}
        self.assertEqual(self.capture(answers)[0], 0)
        original = self.bytes_on_disk()
        before = self.state_path.stat()
        code, stderr, runner = self.dispatch(
            self.event("up", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID), answers
        )
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])
        self.assertEqual(self.bytes_on_disk(), original)
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(self.published()["generation"], 1)
        self.assertEqual(
            (self.published()["source"], self.published()["upstreams"]),
            ("nm-dhcp4", ["192.168.1.1"]),
        )

    def test_two_captures_of_the_same_lease_record_one_state(self):
        answers = {RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"}
        self.assertEqual(self.capture(answers)[0], 0)
        original = self.bytes_on_disk()
        before = self.state_path.stat()
        self.assertEqual(self.capture(answers)[0], 0)
        self.assertEqual(self.bytes_on_disk(), original)
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(self.published()["generation"], 1)

    def test_a_capture_of_a_lease_the_router_already_knows_does_not_advance_it(self):
        """The install may run on a machine the dispatcher has been watching."""
        answers = {RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"}
        self.assertEqual(
            self.dispatch(
                self.event(
                    "dhcp4-change", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID
                ),
                answers,
            )[0],
            0,
        )
        original = self.bytes_on_disk()
        before = self.state_path.stat()
        code, _, _ = self.capture(answers)
        self.assertEqual(code, 0)
        self.assertEqual(self.bytes_on_disk(), original)
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(self.published()["generation"], 1)

    def test_a_capture_of_a_changed_lease_advances_the_generation(self):
        self.assertEqual(
            self.capture({RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"})[0], 0
        )
        self.assertEqual(
            self.capture({RAW_DHCP4: "192.168.1.53", CONNECTION: UUID + "\n"})[0], 0
        )
        data = self.published()
        self.assertEqual((data["generation"], data["upstreams"]), (2, ["192.168.1.53"]))

    def test_a_capture_of_a_readable_empty_lease_disables_the_branch(self):
        code, _, _ = self.capture({CONNECTION: UUID + "\n"})
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["upstreams"], data["last_good"]), ([], False))
        self.assertEqual(data["source"], "nm-dhcp")
        self.assertEqual(data["generation"], 1)


class CaptureFailureTests(CaptureCase):
    """What a capture leaves standing when the machine does not answer.

    A capture runs before an installer has changed anything, so a failure here
    has to be visible to the installer through the exit status and must never
    replace a state the router is already serving.
    """

    def test_a_total_source_failure_preserves_the_published_state(self):
        self.assertEqual(
            self.capture({RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"})[0], 0
        )
        original = self.bytes_on_disk()
        before = self.state_path.stat()
        code, stderr, runner = self.capture(runner=BrokenRunner())
        self.assertEqual(code, 4)
        # The connection is never asked for: a NetworkManager that cannot be
        # queried says nothing about the lease, so there is nothing to publish.
        self.assertEqual(runner.calls, list(COLLECTOR_COMMANDS))
        self.assertEqual(self.bytes_on_disk(), original)
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertIn("source", stderr)

    def test_a_total_source_failure_on_a_first_capture_publishes_nothing(self):
        code, _, runner = self.capture(runner=BrokenRunner())
        self.assertEqual(code, 4)
        self.assertEqual(runner.calls, list(COLLECTOR_COMMANDS))
        self.assertFalse(self.state_path.exists())
        self.assertFalse(self.lock_path.exists())

    def test_a_corrupt_state_exits_four_and_keeps_the_file(self):
        self.state_path.write_text("{")
        code, stderr, _ = self.capture({CONNECTION: UUID + "\n"})
        self.assertEqual(code, 4)
        self.assertIn("dhcp-upstreams.json", stderr)
        self.assertEqual(self.state_path.read_text(), "{")

    def test_a_held_lock_exits_three_and_keeps_the_state(self):
        self.assertEqual(
            self.capture({RAW_DHCP4: "192.168.1.1", CONNECTION: UUID + "\n"})[0], 0
        )
        original = self.bytes_on_disk()
        with self.held_lock():
            code, stderr, _ = self.capture(
                {RAW_DHCP4: "192.168.1.53", CONNECTION: UUID + "\n"}
            )
        self.assertEqual(code, 3)
        self.assertIn("lock", stderr)
        self.assertEqual(self.bytes_on_disk(), original)


if __name__ == "__main__":
    unittest.main()
