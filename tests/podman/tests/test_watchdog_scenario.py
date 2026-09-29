"""The watchdog scenario's assertions, driven against a fake podman.

The watchdog is the first thing this project does to a machine with nobody
watching, and **a fake root and an injected runner cannot answer the question
that matters about it**: does the window hold, is the action the real one, and
is the switch a switch. Only a live target can, and `scenarios/watchdog_test.py`
is what runs there. This file is the half that can be checked here, and it is
worth having for the same reason the DHCP scenario's is: the scenario is a
program, and a program whose *failure path* nobody exercises is a program whose
failure path will be discovered on a live run.

Four properties, each of which is a defect this project's own record says a
green suite has shipped before:

* **The window is checked at each step, not only at the end.** A scenario that
  only looked at the final state would pass against a watchdog that acts on the
  first probe -- which is the single most dangerous thing this mechanism could
  do, and the one the plan's whole window argument exists to prevent. So there is
  a case that plants exactly that defect in the fake's answers and requires the
  scenario to fail on it.

* **The action is proved by the MACHINE.** The recorded DNS being back on the
  connection is the claim; the journal is the claim's *explanation*. A scenario
  that asserted only the journal would pass against a watchdog that printed a
  convincing message and changed nothing.

* **The off position is observed on a machine that NEEDED watching.** A switch
  tested on a healthy machine produces the same "no action" as a switch that
  does nothing at all, so the scenario re-establishes the broken condition
  before it observes the off position, and a case holds that it does.

* **The operator's own action still works afterwards.** A switch implemented by
  removing the action, or by a setting the action reads, would leave a machine
  with a dead resolver and no way back -- and every other case here would be
  green.

The fake is `test_command.py`'s, at the subprocess seam, so the production
`Podman` wrapper is exercised for real. It is the same fixture
`test_dhcp_scenario.py` uses, and the rule table below is built the same way.
"""

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "tests" / "podman"
SCENARIOS = HARNESS / "scenarios"

sys.path.insert(0, str(HARNESS / "lib"))
sys.path.insert(0, str(HARNESS / "tests"))

import test_command  # noqa: E402
from test_dhcp_scenario import cell_rules, is_active_answer  # noqa: E402

PodmanTestCase = test_command.PodmanTestCase


def _load_scenario(name: str = "watchdog_test"):
    """The scenario module, loaded from its path rather than by name.

    The same reason `test_dhcp_scenario.py` gives: a case file and a scenario
    file that share a name would shadow one another in `sys.modules`, which is
    the defect `test_suite_shape.py` exists to keep out of this suite.
    """
    path = SCENARIOS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"mosdns_scenario_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


watchdog = _load_scenario()

RUN_ID = "20260929T000000Z"
VERSION = "24.04"
ROUTER = f"mosdns-{RUN_ID}-mock-router-{VERSION}"
TARGET = f"mosdns-{RUN_ID}-target-{VERSION}"
PROFILE = "eth0-managed"
RECORDED_DNS = "10.89.0.2"
LOCAL_DNS = "127.0.0.1"
MOCK_ROUTER_ADDRESS = "10.89.0.2"
# The installed paths, restated rather than imported from the scenario: a case
# that read them out of the module would agree with whatever the module said, and
# these are the paths the package installs.
CDNCTL = "/usr/lib/mosdns-router/mosdns-cdnctl"

BACKUP = json.dumps(
    {
        "schema_version": 1,
        "connection": {"uuid": "11111111-1111-1111-1111-111111111111", "device": "eth0"},
        "original": {
            "ipv4.dns": {"raw": RECORDED_DNS, "value": [RECORDED_DNS]},
            "ipv4.ignore-auto-dns": {"raw": "no", "value": False},
            "ipv6.dns": {"raw": "", "value": []},
            "ipv6.ignore-auto-dns": {"raw": "no", "value": False},
        },
    }
)

# The journal the watchdog writes when it acts, as the scenario requires it.
#
# Every clause of this text is one the scenario asserts, so removing any of them
# from the production message would fail a case here. The three the plan names
# are marked: the action ran, the exit status, and the limitation.
JOURNAL_ACTED = (
    "mosdns-watchdog.service: watchdog: nothing at all answered a query for "
    "install-probe.example at 127.0.0.1:53 within 2s, so the machine's own resolver is not "
    "answering.\n"
    "mosdns-watchdog.service: watchdog: the window was reached: 2 consecutive failures, and the "
    "threshold is 2. This run performed the emergency rollback unattended and it exited 0.\n"
    "mosdns-watchdog.service: watchdog: WHAT IS BACK: the DNS settings recorded in "
    "/var/lib/mosdns/installer/network-manager-backup.json are on this machine's connection "
    "again.\n"
    "mosdns-watchdog.service: watchdog: WHAT IS NOT BACK: foreign-name resolution through DNSCrypt "
    "does not work, and that is the condition this package was installed to fix.\n"
)

JOURNAL_BELOW = (
    "mosdns-watchdog.service: watchdog: this is consecutive failure 1 of the 2 this machine is "
    "configured to act on; 0s of the 5m window has passed since the first failure at "
    "2026-09-29T03:00:00Z. Nothing has been changed by this run.\n"
)

JOURNAL_OFF = (
    "mosdns-watchdog.service: watchdog: /etc/mosdns/watchdog.yaml says automatic: false, so this "
    "run took no action and advanced no count. The probe found: the machine's own resolver did not "
    "resolve. Nothing has been changed by this run.\n"
)


def _record(count: int, action: bool = False, status: int | None = None) -> dict:
    document = {
        "schema_version": 1,
        "consecutive_failures": count,
        "first_failure_utc": "2026-09-29T03:00:00Z",
        "last_failure_utc": "2026-09-29T03:00:00Z",
        "action_utc": "2026-09-29T03:00:00Z" if action else None,
        "action_status": status,
    }
    return document


def watchdog_rules(
    *,
    journals: list[str] | None = None,
    record_reads: list[str] | None = None,
    connection_dns: list[str] | None = None,
    backup: str | None = BACKUP,
    operator_exit: int = 0,
    probe_status: int = 0,
) -> list[dict]:
    """Every answer a cell that passes the watchdog scenario needs.

    `journals`, `record_reads` and `connection_dns` are sequences, so a case can
    say "the first probe does nothing and the second acts" and mean it -- the
    sequence IS the window, and a table that answered the same thing every time
    would make the scenario's central assertion unobservable.

    **The record is read through TWO commands with separate counters**, and
    counting them is the difference between a fixture that models the machine and
    one that quietly repeats its last answer. The scenario asks `test -e` three
    times -- once per probe it inspects -- and then `cat`s the file for the first
    two and once more for the evidence document, because recording the file
    after the rollback does not ask whether it is there first. So:

      test -e  x3 : present, present, ABSENT (the switch cleared it)
      cat      x3 : the count below the window, the count at the window, and the
                    same document again as the post-rollback evidence

    A `cat` list shorter than three repeats its last entry for ever, which is how
    a fixture written without counting made the switch-off position look like a
    streak that had survived the switch -- and the case that caught it is
    `test_the_off_position_is_observed_with_the_machine_broken`'s sibling
    `ScenarioPassesTest.test_the_scenario_passes_and_records_both_switch_positions`.
    """
    answers = journals or [
        JOURNAL_BELOW,   # below the window
        JOURNAL_ACTED,   # at the window
        JOURNAL_OFF,     # switch off, probe 1
        JOURNAL_OFF,     # probe 2
        JOURNAL_OFF,     # probe 3
        JOURNAL_OFF,     # probe 4 -- one past the shipped threshold
        JOURNAL_ACTED,   # the operator's own rollback prints its own words
    ]
    states = record_reads or [
        json.dumps(_record(1)),                        # probe 1, below the window
        json.dumps(_record(2, action=True, status=0)),  # probe 2, at the window
        json.dumps(_record(2, action=True, status=0)),  # the file as the rollback left it
    ]
    dns = connection_dns or [
        f"{LOCAL_DNS}\n",          # before the scenario points it at the local resolver
        f"{LOCAL_DNS}\n",          # pointed
        f"{RECORDED_DNS}\n",       # after the watchdog's rollback
        f"{LOCAL_DNS}\n",          # re-armed for the off position
        f"{LOCAL_DNS}\n",
        f"{RECORDED_DNS}\n",       # after the operator's own rollback
    ]
    return cell_rules() + [
        # -- the hand-off, before the package -------------------------------
        # The mock router's address on the DEVICE, which is what the wait for
        # the lease reads. `cell_rules()` answers the same command with a lease
        # for the `dhcp` scenario, and this rule is narrower and comes first, so
        # the two suites agree about what a device with a DHCP lease publishes.
        {"match": ["nmcli", "-g", "IP4.DNS", "device", "show", "eth0"],
         "stdout": f"{MOCK_ROUTER_ADDRESS}\n"},
        {"match": ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "eth0"],
         "answers": [{"stdout": "eth0\n"}, {"stdout": f"{PROFILE}\n"}]},
        # -- the package ----------------------------------------------------
        {"match": ["dpkg", "-i"], "returncode": 0, "stdout": "Setting up mosdns-router ...\n"},
        {"match": ["stat", "-c", "%s"], "stdout": "16167412\n"},
        {"match": ["dpkg-query"], "stdout": "install ok installed\n"},
        {"match": ["dpkg-reconfigure"], "stdout": "postinst: nothing to do\n"},
        {"match": ["stat", "-c", "%a %U %G"], "stdout": "644 root root\n"},
        # -- the units ------------------------------------------------------
        # `ActiveState` through `show`, which exits 0 for every state, because
        # that is what the scenario reads: `is-active` exits 3 for anything that
        # is not `active`, and the wrapper's `check=True` turns a stopped router
        # into an exception rather than into the word `inactive`. The router in
        # this cell is stopped BY the scenario, so its state is an expected
        # answer and not a failure.
        # NOT enabled, read through `show --property=UnitFileState` for the
        # reason `unit_enabled`'s own docstring gives: `is-enabled` exits 1 for
        # `disabled`, which is this cell's answer, and the wrapper's `check=True`
        # would turn it into an exception. The transaction refused here, so
        # postinst never reached the enable step -- answering `enabled` would
        # make the placement its own comment argues for look right in a cell
        # where it never ran.
        {"match": ["systemctl", "show", "mosdns-watchdog.timer", "--property=UnitFileState"],
         "stdout": "UnitFileState=disabled\n"},
        {"match": ["systemctl", "show", "mosdns-router.service", "--property=UnitFileState"],
         "stdout": "UnitFileState=enabled\n"},
        {"match": ["systemctl", "show", "mosdns-watchdog.service", "--property=UnitFileState"],
         "stdout": "UnitFileState=static\n"},
        {"match": ["systemctl", "show", "mosdns-router.service", "--property=ActiveState"],
         "stdout": "ActiveState=inactive\n"},
        {"match": ["systemctl", "show", "mosdns-watchdog.service", "--property=ActiveState"],
         "stdout": "ActiveState=inactive\n"},
        {"match": ["systemctl", "show", "mosdns-watchdog.timer", "--property=ActiveState"],
         "stdout": "ActiveState=inactive\n"},
        # -- the connection, read from the device ---------------------------
        {"match": ["nmcli", "-g", "ipv4.dns", "connection", "show", PROFILE],
         "answers": [{"stdout": value} for value in dns]},
        # -- the record, the backup and the marker ---------------------------
        # `test -e` as an ARGUMENT ARRAY and not as a `sh -c` script, because
        # that is how the scenario asks: `exec_status(target, "test", "-e",
        # path)`. A rule written as `["sh", "-c", "test -e …"]` matches nothing
        # here, and the fake's default answer is success -- so the fixture would
        # have said "the record is there" on every read and the switch-off
        # position would have looked like a streak that survived the switch. The
        # same applies to the backup's read below, for the same reason.
        #
        # Three reads against a three-entry `cat` list, for the reason this
        # function's docstring gives. The third `test -e` answers ABSENT: with
        # the switch off the watchdog clears the record, and a record that still
        # named an action after four no-action runs is exactly the property the
        # switch has to have.
        {"match": ["test", "-e", "/run/mosdns/watchdog.json"],
         "answers": [{"returncode": 0}, {"returncode": 0}, {"returncode": 1}]},
        {"match": ["cat", "/run/mosdns/watchdog.json"],
         "answers": [{"stdout": state} for state in states]},
        {"match": ["test", "-e", "/var/lib/mosdns/installer/network-manager-backup.json"],
         "returncode": 0 if backup else 1},
        {"match": ["cat", "/var/lib/mosdns/installer/network-manager-backup.json"],
         "stdout": backup or ""},
        {"match": ["cat", "/var/lib/mosdns/installer/managed-by"],
         "stdout": "mosdns-router\n"},
        {"match": ["stat", "-c", "%a %U %G", "/run/mosdns/watchdog.json"],
         "stdout": "640 root root\n"},
        # -- the four watchdog runs ------------------------------------------
        # The journal is read through a CURSOR, so each read is one run's output
        # and nothing else. `--show-cursor` is the position and `--after-cursor`
        # the read forward from it; without them every read is the cell's last
        # forty lines, which is how the switch-off position once "failed" on the
        # armed run's success message.
        {"match": ["systemctl", "start", "mosdns-watchdog.service"], "returncode": 0},
        {"match": ["systemctl", "show", "mosdns-watchdog.service"], "stdout": "Result=success\n"},
        {"match": ["journalctl", "--no-pager", "-n", "0", "--show-cursor"],
         "answers": [{"stdout": f"-- cursor: s={index}b311b2743f4965\n"}
                     for index in range(len(answers))]},
        {"match": ["journalctl", "-u", "mosdns-watchdog.service"],
         "answers": [{"stdout": text} for text in answers]},
        # -- the operator's own action ---------------------------------------
        # The command array carries the exit status as a token, because that is
        # how the scenario asks: it interpolates `echo EXIT=$?` so the status and
        # the output arrive together, and a rule matched on the *interpolated*
        # status would be a different rule per case. Matching the two leading
        # tokens answers every case with the same rule and puts the status in
        # the answer, which is where the case under test changes it.
        {"match": ["sh", "-c", f"{CDNCTL} emergency-rollback 2>&1; echo EXIT=$?"],
         "stdout": f"rollback: the recorded values are back\nEXIT={operator_exit}\n"},
        # -- resolved and resolv.conf, kept as evidence ---------------------
        {"match": ["resolvectl", "dns"],
         "stdout": f"Link 2 (eth0): {MOCK_ROUTER_ADDRESS}\n"},
        # The machine's own resolver answering the installer's probe name, asked
        # through `getent` -- the same path every program on the machine takes,
        # and the one `emergency_rollback`'s own final check uses. `probe_status`
        # is what a case changes to model a resolver that is not there.
        {"match": ["getent", "hosts", "install-probe.example"],
         "returncode": probe_status,
         "stdout": f"{MOCK_ROUTER_ADDRESS} install-probe.example\n" if probe_status == 0 else ""},
        {"match": ["sh", "-c", "readlink -f /etc/resolv.conf; cat /etc/resolv.conf"],
         "stdout": f"/run/systemd/resolve/stub-resolv.conf\nnameserver {RECORDED_DNS}\n"},
        {"match": ["cat", "/etc/mosdns/watchdog.yaml"],
         "stdout": "automatic: true\nconsecutive_failures: 3\nminimum_minutes: 10\n"},
    ]


class WatchdogScenarioHarness(PodmanTestCase):
    """A fake podman, and the scenario wired to it."""

    def run_scenario(self, *, rules=None, **overrides):
        fake = self.fake(watchdog_rules(**overrides) if rules is None else rules)
        clock = {"now": 0.0}
        self.elapsed = clock

        def advance(seconds):
            clock["now"] += seconds

        package = self.directory / "mosdns-router_0.1.0_amd64.deb"
        package.write_bytes(b"not a real deb; the fake never reads it")
        builder = watchdog.build_scenario(
            podman=self.client(fake),
            version=VERSION,
            arch="amd64",
            run_id=RUN_ID,
            router=ROUTER,
            target=TARGET,
            network=f"mosdns-{RUN_ID}-testnet",
            results_dir=self.directory / "results",
            deb=package,
            now=lambda: clock["now"],
            sleep=advance,
        )
        return fake, builder()

    def record(self, result):
        return json.loads(
            (self.directory / "results" / RUN_ID / result.log).read_text(encoding="utf-8")
        )

    def asked(self, fake):
        return [
            " ".join(argv[2:])
            for argv in fake.invocations()
            if argv[:2] == ["exec", TARGET]
        ]


class ScenarioPassesTest(WatchdogScenarioHarness):
    """The scenario end to end, and what it records when it passes."""

    def test_the_scenario_passes_and_records_both_switch_positions(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(result.log, f"logs/{VERSION}-watchdog.json")
        record = self.record(result)
        # Both positions, in one document, because "a switch nobody has observed
        # in the off position is not a switch" and a document that kept only the
        # on position would be the same absence one file over.
        self.assertIn("watchdog: the window was reached", record["journal_at_window"])
        self.assertEqual(len(record["journal_with_the_switch_off"]), 4)
        for journal in record["journal_with_the_switch_off"]:
            self.assertIn("automatic: false", journal)
            self.assertNotIn("performed the emergency rollback unattended", journal)
        self.assertEqual(record["operator_rollback_exit"], 0)
        # Stripped, because every one of these values comes back through
        # `wait_for`, which strips. A case comparing against a raw read's
        # trailing newline would be asserting about the harness's reader rather
        # than about the machine.
        self.assertEqual(record["connection_dns_after_rollback"], RECORDED_DNS)
        self.assertEqual(record["connection_dns_with_the_switch_off"], LOCAL_DNS)
        self.assertEqual(record["recorded_dns"], RECORDED_DNS)

    def test_it_copies_the_built_package_in_rather_than_hand_making_the_files(self):
        fake, _result = self.run_scenario()
        copied = [
            argv for argv in fake.invocations() if argv[:1] == ["cp"]
        ]
        self.assertTrue(
            copied, "the scenario never copied the package in, so it tested a target that already "
                    "had it"
        )
        for argv in copied:
            self.assertRegex(argv[-1], rf"^{TARGET}:/tmp/mosdns-router\.deb$")
        self.assertIn(
            ["dpkg", "-i", "/tmp/mosdns-router.deb"],
            [argv[2:] for argv in fake.invocations() if argv[:2] == ["exec", TARGET]],
            "the package was copied and not installed, so nothing in the package was exercised",
        )

    def test_the_record_is_read_after_the_first_probe_and_its_count_asserted(self):
        record = self.record(self.run_scenario()[1])
        self.assertEqual(record["record_below_window"]["consecutive_failures"], 1)
        self.assertIsNone(record["record_below_window"]["action_utc"])
        self.assertEqual(record["record_at_window"]["action_status"], 0)

    def test_the_machine_is_observed_after_the_rollback_not_just_the_journal(self):
        # The evidence is the machine, and the journal is the explanation. A
        # scenario that asserted only the journal would pass against a watchdog
        # that printed a convincing message and changed nothing.
        #
        # "The machine is usable again" is a claim about a RESOLVER, so it is
        # checked as one: a name answered through the machine's own stub. A
        # profile property would not be that claim -- and asserting one is the
        # exact confusion the watchdog's own success message exists to avoid.
        record = self.record(self.run_scenario()[1])
        self.assertNotIn(LOCAL_DNS, record["connection_dns_after_rollback"])
        self.assertIn(MOCK_ROUTER_ADDRESS, record["resolvectl_after_rollback"])
        self.assertTrue(
            record["probe_after_rollback"],
            "the machine's own resolver did not answer the probe name after the rollback, so "
            "'the machine is usable again' is not something this run showed",
        )

    def test_a_rollback_that_restores_a_dead_resolver_is_a_failure(self):
        # The connection property is right and the machine still cannot resolve:
        # the profile was restored, the resolver behind it is not there. This is
        # the case the first live run found -- the mock router answered nothing,
        # the restore was faithful, and the machine was still dead.
        _fake, result = self.run_scenario(probe_status=2)
        self.assertEqual(result.status, "failed")
        self.assertIn("still cannot resolve", result.detail)

    def test_each_run_reads_its_own_journal_and_not_the_cell_s(self):
        # **Measured, and it is the reason the journal is read through a cursor.**
        # Without one, every read is the last forty lines of the cell, and the
        # switch-off position read the *armed* run's success message and reported
        # that the mechanism had acted with the switch off -- a false failure on a
        # mechanism that had done exactly the right thing, which is the worst
        # direction for one: the tempting fix is to weaken the assertion.
        record = self.record(self.run_scenario()[1])
        armed = record["journal_at_window"]
        self.assertIn(watchdog.CLAIM_ACTION_RAN, armed)
        for index, journal in enumerate(record["journal_with_the_switch_off"], start=1):
            with self.subTest(probe=index):
                self.assertNotIn(
                    "WHAT IS BACK",
                    journal,
                    "the off position's journal contains an earlier run's success message, so the "
                    "read is the cell's last forty lines rather than this run's output",
                )
                self.assertIn("automatic: false", journal)
        # And the armed run's own journal is its own: it does not contain the off
        # position's message, which is written later.
        self.assertNotIn("automatic: false", armed)

    def test_the_cursor_is_taken_from_the_whole_journal_and_the_read_is_filtered(self):
        # A unit that has never run has no entries, so `--show-cursor` on the
        # UNIT prints `-- No entries --` and no cursor -- measured, on the first
        # run of the first cell. The cursor therefore comes from the whole
        # journal, which always has boot output, and the read is filtered to the
        # unit afterwards.
        fake, _result = self.run_scenario()
        cursors = [
            " ".join(argv[2:])
            for argv in fake.invocations()
            if argv[:2] == ["exec", TARGET] and "--show-cursor" in argv
        ]
        self.assertTrue(cursors, "no cursor was taken before the run")
        for argv in cursors:
            self.assertNotIn("-u mosdns-watchdog.service", argv)
        reads = [
            " ".join(argv[2:])
            for argv in fake.invocations()
            if argv[:2] == ["exec", TARGET] and "--after-cursor" in argv
        ]
        self.assertTrue(reads, "no read used a cursor")
        for argv in reads:
            self.assertIn("-u mosdns-watchdog.service", argv)
            # The VALUE, not the `-- cursor: …` line: journalctl refuses the
            # marker and the refusal is a PodmanError rather than a diagnosis.
            self.assertNotIn("-- cursor:", argv)

    def test_the_success_message_must_carry_the_limitation_into_the_cell(self):
        # A cell that passed on the action alone would not have noticed a
        # watchdog whose success message claimed the machine was fixed -- and that
        # claim is the defect this whole task exists to prevent.
        record = self.record(self.run_scenario()[1])
        self.assertIn("WHAT IS NOT BACK", record["journal_at_window"])
        self.assertIn(
            "foreign-name resolution through DNSCrypt does not work",
            record["journal_at_window"],
        )
        for lie in ("the machine is back", "fully restored", "everything is back to normal"):
            self.assertNotIn(lie, record["journal_at_window"].lower())


class WindowIsCheckedTest(WatchdogScenarioHarness):
    """The window, as a property of the scenario rather than of the fake.

    Each case here plants a defect in the fake's answers and requires the
    scenario to fail. A control that cannot manufacture the defect it is written
    for is not evidence, and this project's own record names four of them.
    """

    def test_a_watchdog_that_acts_on_the_first_probe_fails_the_scenario(self):
        # The single most dangerous thing this mechanism could do, and the one
        # the plan's whole window argument exists to prevent. The fake is made to
        # act on probe 1, and the scenario must notice at step 6 rather than
        # sailing through to a pass at step 7.
        _fake, result = self.run_scenario(
            journals=[JOURNAL_ACTED] + [JOURNAL_OFF] * 6,
            record_reads=[json.dumps(_record(1, action=True, status=0))] * 3,
        )
        self.assertEqual(result.status, "failed", "a first-probe rollback was reported as a pass")
        self.assertIn("FIRST probe", result.detail)
        self.assertIn("window", result.detail)

    def test_a_watchdog_that_never_counts_fails_the_scenario(self):
        # The record stays at zero, so the window cannot be reached and the
        # action never runs -- and a scenario that only watched for the action
        # would have waited out its budget and reported a timeout instead of the
        # real defect.
        _fake, result = self.run_scenario(record_reads=[json.dumps(_record(0))] * 3)
        self.assertEqual(result.status, "failed")
        self.assertIn("was not counted", result.detail)

    def test_a_rollback_that_changed_nothing_fails_the_scenario(self):
        # The journal claims success and the connection still carries the
        # loopback. A scenario that trusted the message would pass. The answer
        # list is the loopback for every read, so the wait for the restore times
        # out and the failure names the value it kept reading -- which is the
        # honest report of a machine that did not come back.
        _fake, result = self.run_scenario(connection_dns=[f"{LOCAL_DNS}\n"] * 6)
        self.assertEqual(result.status, "failed")
        self.assertIn(f"read '{LOCAL_DNS}'", result.detail)
        self.assertIn("carry the recorded DNS again", result.detail)

    def test_a_restore_that_put_the_wrong_thing_back_fails_the_scenario(self):
        # The connection carries an address, the loopback is gone, and it is not
        # the one the record named. A zero exit status from the action does not
        # make that a restore.
        _fake, result = self.run_scenario(
            connection_dns=[f"{LOCAL_DNS}\n", f"{LOCAL_DNS}\n", "203.0.113.9\n"] + [
                f"{LOCAL_DNS}\n", f"{LOCAL_DNS}\n", f"{RECORDED_DNS}\n"
            ],
        )
        self.assertEqual(result.status, "failed")
        self.assertIn(RECORDED_DNS, result.detail)


class SwitchIsASwitchTest(WatchdogScenarioHarness):
    """The off position, observed where it means something."""

    def test_a_watchdog_that_ignores_the_switch_fails_the_scenario(self):
        _fake, result = self.run_scenario(
            journals=[JOURNAL_BELOW, JOURNAL_ACTED] + [JOURNAL_ACTED] * 5,
            record_reads=[json.dumps(_record(1)), json.dumps(_record(2, action=True, status=0))]
                         + [json.dumps(_record(3, action=True, status=0))],
        )
        self.assertEqual(result.status, "failed", "a switch that does nothing was reported as one")
        self.assertIn("automatic: false", result.detail)

    def test_the_off_position_is_observed_with_the_machine_broken(self):
        # Re-establishing the condition before observing the switch is the whole
        # of what makes the observation evidence: a no-action result on a healthy
        # machine is also what a switch that does nothing at all produces.
        fake, _result = self.run_scenario()
        joined = "\n".join(self.asked(fake))
        switches = [
            index for index, line in enumerate(joined.splitlines()) if "automatic: false" in line
        ]
        self.assertTrue(
            switches,
            "the scenario never wrote a setting file with the switch off, so the off position was "
            "not observed at all",
        )
        # The re-arming commands come before the off setting is written.
        first_off = switches[0]
        before = joined.splitlines()[:first_off]
        self.assertTrue(
            any("ipv4.dns 127.0.0.1" in line for line in before),
            "the machine was not pointed at the local resolver before the off position",
        )
        self.assertTrue(
            any("systemctl stop mosdns-router.service" in line for line in before),
            "the router was not stopped before the off position, so there was no condition to "
            "watch for",
        )

    def test_a_switch_that_also_disabled_the_operator_is_failed(self):
        _fake, result = self.run_scenario(operator_exit=1)
        self.assertEqual(result.status, "failed", "an operator left with no way back was a pass")
        self.assertIn("no way back", result.detail)
        self.assertIn("exited 1", result.detail)

    def test_more_probes_than_the_shipped_threshold_are_run_with_the_switch_off(self):
        # The plan's requirement is "no action at all across a window longer than
        # the default", and one more probe than the default's count is the
        # cheapest reading of that which a container run can afford.
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertEqual(
            len(record["journal_with_the_switch_off"]),
            watchdog.SHIPPED_FAILURES + 1,
            f"the off position was observed over {len(record['journal_with_the_switch_off'])} "
            f"probes, which is not more than the shipped threshold of {watchdog.SHIPPED_FAILURES}",
        )
        self.assertEqual(result.status, "passed", result.detail)


class WithoutARecordTest(WatchdogScenarioHarness):
    """A target the package was not successfully installed on.

    This is the *expected* result in a container with no reachable foreign
    resolver, and the scenario's answer to it matters more than its passing
    cases: a watchdog whose action cannot run would otherwise be reported as a
    watchdog whose window did not work.
    """

    def test_a_target_with_no_record_fails_rather_than_proving_anything(self):
        # The transaction's LATER refusal still leaves a record -- it is written
        # and read back before the first mutation -- so this case models the
        # earlier one, where the transaction refused before it got that far. The
        # distinction is the point: a container that cannot reach
        # api.cloudflare.com refuses the transaction and still gives the watchdog
        # a record to restore, and this case is the other machine entirely.
        _fake, result = self.run_scenario(backup=None)
        self.assertEqual(result.status, "failed")
        self.assertIn("no record", result.detail)
        self.assertIn("Nothing about the watchdog's own behaviour is proved", result.detail)

    def test_the_refusal_names_the_record_and_the_way_out(self):
        _fake, result = self.run_scenario(backup=None)
        self.assertIn("/var/lib/mosdns/installer/network-manager-backup.json", result.detail)
        self.assertIn("dpkg exit", result.detail)

    def test_a_refused_transaction_is_recorded_rather_than_asserted_away(self):
        # The cell's install transaction refuses in a container, and that is a
        # fact about the cell rather than something to hide: the scenario's
        # document says so, says WHY, and says explicitly that the router was not
        # successfully started. A document that recorded only successes is a
        # document nobody can read after a failure.
        record = self.record(self.run_scenario()[1])
        self.assertIn("refused this target", record["transaction_refused"])
        self.assertIn("api.cloudflare.com", record["transaction_refused"])
        self.assertIn("NOT successfully started", record["transaction_refused"])

    def test_the_scenario_does_not_claim_the_router_works(self):
        # The router is stopped BY the scenario, deliberately, and the document
        # says the transaction did not start it. A reader who took the stop for
        # evidence of a working install would be reading a stopped unit as a
        # healthy one -- which is exactly what the health check's own verdict
        # must never be confused with.
        record = self.record(self.run_scenario()[1])
        self.assertEqual(record["router_state_after_stop"], "inactive")
        self.assertIn("deliberately", record["transaction_refused"])

    def test_the_watchdog_timer_is_enabled_by_the_install_that_succeeded(self):
        # `postinst` enables it only after the transaction succeeds, and in this
        # cell the transaction refused -- so the timer is NOT enabled, and the
        # scenario must not read that as "the switch is off". It arms the
        # mechanism by starting the service by hand, which is the same command
        # the timer would issue.
        record = self.record(self.run_scenario()[1])
        self.assertNotEqual(
            record[f"is-enabled:{watchdog.WATCHDOG_TIMER}"],
            "enabled",
            "the transaction refused in this cell, so postinst never reached the enable step; if "
            "this reads enabled then the postinst enables timers on a refused install, which is "
            "the defect the placement of that step exists to prevent",
        )
        # And the mechanism still runs, because the scenario arms it by hand with
        # the same command the timer would issue. A watchdog that only worked when
        # its timer was enabled would be untested here, and this is the answer.
        self.assertEqual(record["record_at_window"]["action_status"], 0)


class SettingDocumentTest(unittest.TestCase):
    """The document the scenario writes, which the watchdog's parser must accept."""

    def setUp(self):
        sys.path.insert(0, str(REPO / "installer"))
        import mosdns_installer as installer

        self.installer = installer

    def test_the_document_parses_to_the_numbers_the_scenario_armed(self):
        for automatic, failures, minutes in (
            (True, 2, 5), (False, 3, 10), (True, 1, 1), (False, 99, 120),
        ):
            with self.subTest(automatic=automatic, failures=failures, minutes=minutes):
                setting, refusal = self.installer.parse_watchdog_setting(
                    watchdog.setting_document(automatic, failures, minutes), "harness"
                )
                self.assertEqual(refusal, "")
                self.assertEqual(setting.automatic, automatic)
                self.assertEqual(setting.consecutive_failures, failures)
                self.assertEqual(setting.minimum_minutes, minutes)

    def test_the_document_would_be_refused_by_a_shell_that_could_not_see_it(self):
        # Every value is quoted the way the shipped file documents itself, so a
        # failure here is never a formatting accident dressed up as a defect in
        # the parser.
        body = watchdog.setting_document(False, 3, 10)
        self.assertIn("automatic: false\n", body)
        self.assertNotIn("automatic: False", body)
        self.assertNotIn("automatic: 0", body)


class SourceShapeTest(unittest.TestCase):
    """What the scenario file may and may not do, read out of its own source."""

    def setUp(self):
        self.source = (SCENARIOS / "watchdog_test.py").read_text(encoding="utf-8")

    def test_the_plan_and_the_review_focus_both_demand_the_two_observations(self):
        # The plan's Task 8 step 5 and its Review Focus bullet, held against the
        # scenario so the two cannot drift: the brief for this task is that a
        # default-on mechanism is judged on what it says and that a switch
        # nobody has seen in the off position is not a switch.
        self.assertIn("CLAIM_WHAT_IS_NOT_BACK", self.source)
        self.assertIn("journal_with_the_switch_off", self.source)
        self.assertIn("operator_rollback", self.source)

    def test_the_scenario_reaches_the_container_and_never_the_host(self):
        # Everything it touches is inside `target`, and the two ways a scenario
        # could reach a host are a `podman exec` against another container and a
        # direct read of a host path. There is no host read here, and the one
        # path the harness gives it (`deb`) is the file it copies IN.
        self.assertNotIn("os.unlink", self.source)
        self.assertNotIn("shutil", self.source)
        self.assertIn("podman.copy_to", self.source)


if __name__ == "__main__":
    unittest.main()
