"""The resolver watchdog: what it decides, and what it says when it decides it.

**This is the first mechanism in this project that changes a machine with nobody
watching**, so the cases here are about two things in roughly equal measure, and
the second one is the reason the mechanism is judged at all:

* **The decision.** A single failed probe is not evidence that the router is
  down -- a slow upstream, a cold boot before NTP has synchronised and a loaded
  machine all produce one -- so the default acts on the Nth *consecutive* failure
  or once M minutes have passed since the first, whichever comes first, and both
  numbers are settings rather than constants because the false-positive rate has
  never been measured. The boundaries are asserted at exactly N, at exactly M and
  with both met at once, because "roughly" is how a window becomes no window.
* **What it says.** A watchdog that reports "the machine is back" is lying about
  the one thing the operator cares about: `emergency-rollback` restores the
  machine's own DHCP-provided resolvers, so basic connectivity returns and
  **foreign-name resolution through DNSCrypt does not**, which is the condition
  this project exists to fix. Every message below is read by a case that would go
  red if a claim were deleted, and the negative list in
  :meth:`ActionMessagesTests.test_a_success_never_claims_the_machine_is_back`
  exists because a message can also lie by omission.

Three further properties are load-bearing and are asserted rather than assumed:

* **One definition of "resolvable".** The health unit's second command already
  asks this question through the installer's own probe and predicate. The
  watchdog asks it through the same function, and a source-level case holds the
  two verbs to that, because a watchdog that disagrees with the health check
  about whether the resolver is down is a machine that gets two opposite answers
  to the same question.
* **The action is the real one.** It is the argument array an operator types,
  run as a process, and the cases that hold it also hold that no shell is
  involved -- a watchdog with its own rollback path would be a second
  implementation of the previous plan's most delicate code.
* **The record cannot say "healthy" by being absent.** A reboot, a restarted
  timer, a deleted file and a record that cannot be parsed are all ways a
  stateful counter can reset itself into a clean bill of health, and every run
  probes first, so none of them is a path to a conclusion without one.

Nothing here touches the host. The root is a temporary directory, the runner
records the arrays it was given, the probe is an injected callable and the clock
is a parameter.
"""

import contextlib
import io
import json
import re
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "installer"))

import mosdns_installer as installer  # noqa: E402

MODULE = REPO / "installer" / "mosdns_installer.py"
SOURCE = MODULE.read_text(encoding="utf-8")
UNIT_DIR = REPO / "packaging" / "systemd"
CONFIG_DIR = REPO / "packaging" / "config"
SHIPPED_SETTING = CONFIG_DIR / "watchdog.yaml"
CONFFILES = REPO / "packaging" / "debian" / "conffiles"
INSTALL_LIST = REPO / "packaging" / "mosdns-router.install"
VERB = "watchdog"

# The paths and numbers the tests here assert are the ones the package installs,
# restated rather than read from the module. A test that asserted
# `installer.WATCHDOG_RECORD` proved that the module agrees with itself; these
# are the strings an operator reads in a journal and in a message.
SETTING_PATH = "/etc/mosdns/watchdog.yaml"
RECORD_PATH = "/run/mosdns/watchdog.json"
RECORD_DIR = "/run/mosdns"
CDNCTL = "/usr/lib/mosdns-router/mosdns-cdnctl"
INSTALLER = "/usr/lib/mosdns-router/mosdns_installer.py"
BACKUP_PATH = "/var/lib/mosdns/installer/network-manager-backup.json"
ACTION = (CDNCTL, "emergency-rollback")
LOCAL_DNS = "127.0.0.1"
DNS_PORT = 53
PROBE_NAME = "install-probe.example"
RECORD_MODE = 0o640
RECORD_KEYS = {
    "schema_version",
    "consecutive_failures",
    "first_failure_utc",
    "last_failure_utc",
    "action_utc",
    "action_status",
}
WATCHDOG_UNIT = "mosdns-watchdog.service"
WATCHDOG_TIMER = "mosdns-watchdog.timer"
# The three keys and the two numbers, restated: this is the file's whole schema
# and both halves of the package have to agree on it (see
# `SettingFileTests.test_the_shipped_setting_file_says_what_the_code_defaults_to`).
SETTING_KEYS = ("automatic", "consecutive_failures", "minimum_minutes")
SHIPPED_AUTOMATIC = True
SHIPPED_FAILURES = 3
SHIPPED_MINUTES = 10

# The three answer shapes a resolver has, as (answered, resolves). The pair is
# the installer's `Answer` and the middle shape is the one this whole mechanism
# exists for: something answered, confidently, from a chain that reached nobody.
HEALTHY = (True, True)
SERVFAIL = (True, False)
SILENT = (False, False)

NOW = datetime(2026, 9, 29, 3, 0, 0, tzinfo=timezone.utc)


def at(**seconds) -> datetime:
    return NOW + timedelta(**seconds)


class RecordingRunner:
    """A runner that records every array, answers the action on cue, and can look.

    It is written out rather than imported from a sibling test module: the
    documented way to run this file (`python3 -m unittest
    installer.tests.test_watchdog`) does not put `installer/tests` on the path, so
    an import of one would make the documented command fail.
    """

    def __init__(self, status: int = 0, stdout: str = "", stderr: str = "", hook=None):
        self.commands: list[tuple] = []
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        # `hook(command, runner)` runs while the command is being issued, so a
        # case can inspect the machine at that instant -- which is the only way to
        # see what the watchdog had already written when it handed the machine
        # over to the action.
        self.hook = hook

    def run(self, args, check: bool = True):
        command = tuple(args)
        self.commands.append(command)
        if self.hook is not None:
            answer = self.hook(command, self)
            if answer is not None:
                return answer
        return installer.Completed(self.status, self.stdout, self.stderr)


class WatchdogFixture(unittest.TestCase):
    """A fake root, an injected probe and a clock, and nothing that is the host."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.shapes = {(LOCAL_DNS, DNS_PORT): SILENT}
        self.asked: list[tuple] = []
        self.runner = RecordingRunner()
        self.now = NOW
        # A policy and an operator list with no entries, so the force-ECH blind
        # spot is absent unless a case writes one in. The watchdog inherits that
        # guard from `verify-local`, and a case below holds it.
        self.write("/etc/mosdns/policy.yaml", "schema_version: 1\nech:\n  failure_policy: strict\n")
        self.write("/etc/mosdns/force-ech-domains.txt", "# none\n")

    # -- the fake root ----------------------------------------------------

    def rooted(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")

    def write(self, relative: str, contents: str, mode: int = 0o644) -> Path:
        path = self.rooted(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        path.write_text(contents, encoding="utf-8")
        path.chmod(mode)
        return path

    def setting(self, **values) -> Path:
        return self.write(SETTING_PATH, "".join(f"{key}: {value}\n" for key, value in values.items()))

    def record(self) -> dict | None:
        try:
            return json.loads(self.rooted(RECORD_PATH).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def record_mode(self) -> int | None:
        try:
            return stat.S_IMODE(self.rooted(RECORD_PATH).stat().st_mode)
        except OSError:
            return None

    # -- the probe and the clock -------------------------------------------

    def probe(self):
        def ask(address, port):
            self.asked.append((address, port))
            shape = self.shapes.get((address, port), HEALTHY)
            return installer.Answer(answered=shape[0], resolves=shape[1])

        return ask

    def run_watchdog(self, now: datetime | None = None):
        """One watchdog run, as the verb itself computes it.

        The outcome carries both streams verbatim, so a case reads the product's
        own text rather than a restatement of it, and
        `test_the_verb_writes_exactly_what_the_outcome_carries` holds that the
        command line writes these and nothing else.
        """
        return installer.watchdog(self.root, self.runner, probe=self.probe(), now=now or self.now)

    def run_cli(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = installer.main(
                [VERB], self.runner, root=self.root, probe=self.probe(), now=self.now
            )
        return status, out.getvalue(), err.getvalue()

    def actions(self) -> list[tuple]:
        return [command for command in self.runner.commands if command[:1] == ACTION[:1]]


class WindowTests(WatchdogFixture):
    """The window: N consecutive failures, or M minutes, whichever comes first.

    The boundaries are the whole content of this class. `>=` against a count and
    against an elapsed time is a decision, and each of its sides is a different
    behaviour: at exactly N the action runs, one short of N it does not, at
    exactly M it runs, and with both met it runs **once** and names both.
    """

    def arm(self, failures: int = 3, minutes: int = 10, automatic: bool = True):
        self.setUp()
        self.setting(
            automatic=str(automatic).lower(),
            consecutive_failures=failures,
            minimum_minutes=minutes,
        )
        return self

    def test_one_failure_short_of_the_threshold_takes_no_action(self):
        self.arm()
        self.run_watchdog()
        self.run_watchdog()
        self.assertEqual(
            self.actions(), [], "two failures of a configured three acted, so the window is not one"
        )
        self.assertEqual(self.record()["consecutive_failures"], 2)

    def test_the_threshold_itself_acts(self):
        self.arm()
        for _ in range(2):
            self.run_watchdog()
        self.assertEqual(self.actions(), [], "the action ran before the threshold")
        outcome = self.run_watchdog()
        self.assertEqual(
            self.actions(), [ACTION], "the third consecutive failure is the threshold and did not act"
        )
        self.assertEqual(outcome.status, installer.EXIT_OK)

    def test_the_elapsed_window_acts_with_the_count_still_below_the_threshold(self):
        # The case the count alone cannot cover: a machine that was suspended, or
        # whose timer was stopped, comes back with ONE recorded failure and ten
        # minutes of unavailability behind it. Consecutive counting cannot see
        # that, and this is what the elapsed half of the window is for. It takes
        # two runs to set up, because the run that records the first failure is
        # the run that stamps its time -- elapsed time on that run is zero by
        # construction, which is the honest answer and not an omission.
        self.arm()
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(minutes=10))
        self.assertEqual(self.actions(), [ACTION], "ten minutes passed and the count never reached 3")
        self.assertIn("10m", outcome.stdout)
        self.assertIn("the window is 10m", outcome.stdout)

    def test_a_minute_short_of_the_elapsed_window_does_not_act(self):
        self.arm()
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(minutes=9, seconds=59))
        self.assertEqual(self.actions(), [])
        self.assertIn("9m59s", outcome.stderr)

    def test_both_conditions_met_are_both_named_and_the_action_runs_once(self):
        self.arm(failures=2, minutes=5)
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(minutes=5))
        self.assertEqual(
            self.actions(), [ACTION], "both conditions were met and the action ran twice"
        )
        self.assertIn("2 consecutive failures", outcome.stdout)
        self.assertIn("5m", outcome.stdout)

    def test_a_clock_that_moved_backwards_reports_no_elapsed_time_and_does_not_act(self):
        # Every message must be true, and "10m have passed since the first
        # failure" is false when the recorded first failure is later than now.
        self.arm()
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(minutes=-30))
        self.assertEqual(self.actions(), [])
        self.assertIn("clock", (outcome.stdout + outcome.stderr).lower())

    def test_a_successful_probe_resets_the_count_and_says_that_it_did(self):
        self.arm(failures=2)
        self.run_watchdog()
        self.assertEqual(self.record()["consecutive_failures"], 1)
        self.shapes[(LOCAL_DNS, DNS_PORT)] = HEALTHY
        outcome = self.run_watchdog()
        self.assertIn("cleared", outcome.stdout)
        self.assertIsNone(
            self.record(), "the count was not reset, so a later failure resumes a streak that ended"
        )

    def test_a_failure_after_a_reset_starts_from_one_again(self):
        self.arm(failures=2)
        self.run_watchdog()
        self.shapes[(LOCAL_DNS, DNS_PORT)] = HEALTHY
        self.run_watchdog()
        self.shapes[(LOCAL_DNS, DNS_PORT)] = SILENT
        self.run_watchdog()
        self.assertEqual(self.record()["consecutive_failures"], 1)
        self.assertEqual(self.actions(), [], "a reset streak reached the threshold in one failure")


class ActionMessagesTests(WatchdogFixture):
    """The three messages the plan requires, read off a real run.

    These are the product. An operator reading a journal at 3am learns from these
    strings whether they are looking at a working machine, a machine about to be
    changed, or a machine that has been changed and is still not what it was.
    """

    def reached(self, status: int = 0, stdout: str = "", stderr: str = "", shape=SILENT, **window):
        """Arm a one-failure window, point the resolver at nothing, and act."""
        self.setUp()
        self.shapes[(LOCAL_DNS, DNS_PORT)] = shape
        self.runner = RecordingRunner(status=status, stdout=stdout, stderr=stderr)
        self.setting(
            automatic="true",
            consecutive_failures=window.get("failures", 1),
            minimum_minutes=window.get("minutes", 10),
        )
        return self.run_watchdog()

    def test_not_enough_failures_names_the_count_the_threshold_the_elapsed_time_and_the_first(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=3, minimum_minutes=10)
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(seconds=72))
        self.assertEqual(outcome.status, installer.EXIT_REFUSED)
        self.assertEqual(self.actions(), [], "the action ran below the threshold")
        for claim in (
            "consecutive failure 2 of the 3",
            "1m12s",
            "10m",
            "2026-09-29T03:00:00Z",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, outcome.stderr)

    def test_not_enough_failures_says_nothing_was_changed_and_what_will_be(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=3, minimum_minutes=10)
        outcome = self.run_watchdog()
        self.assertIn("Nothing has been changed", outcome.stderr)
        self.assertIn("emergency-rollback", outcome.stderr)
        self.assertIn(SETTING_PATH, outcome.stderr)

    def test_a_success_names_what_was_restored(self):
        outcome = self.reached()
        self.assertEqual(outcome.status, installer.EXIT_OK)
        self.assertIn("WHAT IS BACK", outcome.stdout)
        self.assertIn(BACKUP_PATH, outcome.stdout)
        self.assertIn("DHCP", outcome.stdout)

    def test_a_success_repeats_the_limitation_in_production_not_only_in_the_docs(self):
        # The whole reason this task exists: the rollback restores basic
        # connectivity and leaves the actual fault in place. A message that said
        # only what was restored would be true and useless.
        outcome = self.reached()
        self.assertIn("WHAT IS NOT BACK", outcome.stdout)
        self.assertIn("foreign-name resolution through DNSCrypt does not work", outcome.stdout)
        self.assertIn("still installed", outcome.stdout)
        self.assertIn("verify-local", outcome.stdout)

    def test_a_success_never_claims_the_machine_is_back(self):
        outcome = self.reached()
        for lie in (
            "the machine is back",
            "everything is back to normal",
            "fully restored",
            "this machine's dns is restored",
            "the fault is fixed",
        ):
            with self.subTest(lie=lie):
                self.assertNotIn(lie, (outcome.stdout + outcome.stderr).lower())

    def test_a_success_names_the_command_that_puts_the_router_back(self):
        outcome = self.reached()
        self.assertIn(f"{INSTALLER} install", outcome.stdout)

    def test_a_failure_names_the_exit_status_and_what_to_run_by_hand(self):
        outcome = self.reached(status=installer.EXIT_ROLLBACK_FAILED)
        self.assertEqual(outcome.status, installer.EXIT_ROLLBACK_FAILED)
        self.assertIn("exited 4", outcome.stderr)
        self.assertIn(f"sudo {CDNCTL} emergency-rollback", outcome.stderr)
        self.assertIn("did not finish", outcome.stderr)

    def test_a_failure_repeats_the_actions_own_words(self):
        outcome = self.reached(
            status=installer.EXIT_ROLLBACK_FAILED,
            stderr="rollback: connection activation failed\n",
        )
        self.assertIn("connection activation failed", outcome.stderr)

    def test_a_failure_claims_nothing_about_the_machine(self):
        outcome = self.reached(status=installer.EXIT_OWNERSHIP_REFUSED)
        self.assertIn("Nothing about this machine's DNS can be promised", outcome.stderr)
        for lie in ("the machine is back", "has been rolled back", "is restored"):
            with self.subTest(lie=lie):
                self.assertNotIn(lie, (outcome.stdout + outcome.stderr).lower())

    def test_a_failure_says_the_watchdog_will_not_try_again(self):
        outcome = self.reached(status=installer.EXIT_ROLLBACK_FAILED)
        self.assertIn("will not try again", outcome.stderr)
        self.assertIn("worse than it found it", outcome.stderr)

    def test_a_servfail_and_silence_are_told_apart_in_the_watchdogs_own_message(self):
        # The predicate's whole point, inherited rather than re-decided: something
        # answered confidently from a chain that reached nobody is not the same
        # fact as nothing answering, and the operator is the one who has to act.
        answered = self.reached(failures=2, shape=SERVFAIL)
        self.assertIn("SERVFAIL", answered.stderr)
        silent = self.reached(failures=2, shape=SILENT)
        self.assertNotIn("SERVFAIL", silent.stderr)
        self.assertIn("nothing at all answered", silent.stderr)

    def test_every_status_this_program_defines_has_a_sentence_the_watchdog_can_print(self):
        # The action is a process, so its status is a number this program did not
        # choose. A status with no sentence would print a bare number at 3am.
        defined = {
            value
            for name, value in vars(installer).items()
            if name.startswith("EXIT_") and isinstance(value, int)
        }
        self.assertTrue(defined, "no exit statuses were found, so this case is not holding anything")
        for status in sorted(defined):
            with self.subTest(status=status):
                self.assertIn(status, installer.WATCHDOG_ACTION_STATUSES)
        outcome = self.reached(status=199)
        self.assertIn("199", outcome.stderr)
        self.assertIn("not a status this package defines", outcome.stderr)

    def test_the_verb_writes_exactly_what_the_outcome_carries(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        status, out, err = self.run_cli()
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        outcome = self.run_watchdog()
        self.assertEqual(status, outcome.status)
        self.assertEqual(out, outcome.stdout)
        self.assertEqual(err, outcome.stderr)

    def test_the_two_verbs_ask_the_same_question_through_one_function(self):
        # One definition of "resolvable" in this package, held structurally: both
        # verbs call `local_resolvability`, and neither reaches for the probe or
        # the predicate itself. A watchdog with its own answer to this question is
        # how a machine gets two opposite verdicts on it.
        for verb in ("_run_verify_local", "watchdog"):
            body = _function_body(SOURCE, verb)
            with self.subTest(verb=verb):
                self.assertIn("local_resolvability(", body)
                for own in ("probe_dns(", "response_resolves(", "response_is_an_answer("):
                    self.assertNotIn(
                        own,
                        body,
                        f"{verb} answers the question for itself with {own}, which is a second "
                        "definition of 'resolvable'",
                    )

    def test_the_watchdog_asks_the_local_resolver_and_nothing_else(self):
        self.reached()
        self.assertEqual(self.asked, [(LOCAL_DNS, DNS_PORT)])


class ActionTests(WatchdogFixture):
    """The action is the operator's command, run as a process, once per streak."""

    def test_the_action_is_exactly_the_command_an_operator_types(self):
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        self.assertEqual(
            self.actions(),
            [ACTION],
            "the watchdog did not run the command an operator runs, so it has a rollback path of "
            "its own, and that is a second implementation of the previous plan's most deliberate "
            "code",
        )

    def test_the_action_is_not_run_through_a_shell(self):
        self.assertNotIn("shell=True", SOURCE)
        self.assertIn("WATCHDOG_ACTION", _function_body(SOURCE, "watchdog"))

    def test_the_action_runs_at_most_once_per_failure_streak(self):
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        for _ in range(5):
            self.run_watchdog()
        self.assertEqual(
            len(self.actions()),
            1,
            "the action ran more than once in one failure streak, which is a mutating action on a "
            "timer repeating itself",
        )

    def test_a_failure_is_reported_rather_than_retried(self):
        self.setUp()
        self.runner = RecordingRunner(status=installer.EXIT_ROLLBACK_FAILED)
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        outcome = self.run_watchdog()
        self.assertEqual(len(self.actions()), 1)
        self.assertIn("already", outcome.stderr)
        self.assertIn("exited 4", outcome.stderr)

    def test_the_attempt_is_recorded_before_the_action_runs_not_after_it(self):
        # Write-ahead, and it is the only thing that makes the latch above
        # survive an action whose outcome could not be written down. Read from
        # inside the action, because the moment that matters is the moment the
        # machine was handed over: a watchdog that recorded afterwards would have
        # nothing on disk here.
        seen = {}

        def watch_the_handover(command, runner):
            if command[:1] != ACTION[:1]:
                return None
            document = self.record()
            seen.update(document or {})
            return None

        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.runner.hook = watch_the_handover
        self.run_watchdog()
        self.assertEqual(
            seen.get("action_utc"),
            "2026-09-29T03:00:00Z",
            "the attempt was not on disk while the action was running, so an action that ran and "
            "could not be recorded afterwards would be run again, for ever",
        )
        self.assertIsNone(seen.get("action_status"), "the status was written before the action ran")

    def test_an_action_whose_status_could_not_be_recorded_is_not_run_again(self):
        def read_only_after(command, runner):
            if command[:1] != ACTION[:1]:
                return None
            # The rename into place fails; the record written before the action is
            # still readable, so the latch holds.
            self.rooted(RECORD_DIR).chmod(0o500)
            return None

        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.runner.hook = read_only_after
        first = self.run_watchdog()
        self.addCleanup(self.rooted(RECORD_DIR).chmod, 0o755)
        self.assertEqual(len(self.actions()), 1)
        self.assertIn("could not be written", first.stdout + first.stderr)
        self.runner.hook = None
        second = self.run_watchdog()
        self.assertEqual(len(self.actions()), 1, "a second action ran after an unrecorded outcome")
        self.assertIn("not recorded", second.stderr)

    def test_the_action_gets_a_budget_of_its_own_and_the_unit_bounds_the_rest(self):
        # `COMMAND_TIMEOUT_SECONDS` is 30, and `nmcli connection up` inside the
        # rollback re-runs DHCP; killing the rollback half way through a restore
        # is the worst thing this mechanism could do. So the action gets its own
        # budget, and the unit's `TimeoutStartSec` is above it so that the
        # watchdog prints its own report rather than being killed mid-restore.
        self.assertGreater(
            installer.WATCHDOG_ACTION_TIMEOUT_SECONDS, installer.COMMAND_TIMEOUT_SECONDS
        )
        unit = (UNIT_DIR / WATCHDOG_UNIT).read_text(encoding="utf-8")
        seconds = int(re.search(r"^TimeoutStartSec=(\d+)$", unit, re.M).group(1))
        self.assertGreater(
            seconds,
            installer.WATCHDOG_ACTION_TIMEOUT_SECONDS,
            f"{WATCHDOG_UNIT} allows {seconds}s, which is not above the action's own "
            f"{installer.WATCHDOG_ACTION_TIMEOUT_SECONDS}s budget, so systemd kills the restore "
            "instead of letting the watchdog report it",
        )

    def test_the_action_runs_as_the_verb_an_operator_runs_not_through_a_helper(self):
        # `mosdns-cdnctl emergency-rollback` is the boundary: it refuses to run
        # as a non-root uid and it execs the installer. Going around it would be
        # a path a human would not take.
        source = (REPO / "cmd" / "mosdns-cdnctl" / "main.go").read_text(encoding="utf-8")
        self.assertIn('"emergency-rollback"', source)
        self.assertIn("effectiveUID", source)


class RecordTests(WatchdogFixture):
    """Where the failure record lives, and what an absent one is allowed to mean."""

    def test_the_record_is_written_under_the_run_directory_and_nowhere_else(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        self.assertIsNotNone(self.record(), "no record was written, so nothing can be counted")
        self.assertEqual(RECORD_PATH, "/run/mosdns/watchdog.json")
        written = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*.json"))
        self.assertEqual(written, [RECORD_PATH.lstrip("/")])

    def test_a_missing_record_is_never_read_as_a_healthy_machine(self):
        # The property the whole design turns on. A record's absence means "no
        # failure has been recorded", never "the last probe succeeded": the count
        # starts at one, the first failure is this run, and the record carries no
        # field that could be read as a verdict.
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        outcome = self.run_watchdog()
        document = self.record()
        self.assertEqual(document["consecutive_failures"], 1)
        self.assertEqual(document["first_failure_utc"], "2026-09-29T03:00:00Z")
        self.assertEqual(set(document), RECORD_KEYS, "the record carries a field nothing measured")
        self.assertEqual(outcome.status, installer.EXIT_OK)

    def test_a_record_that_cannot_be_parsed_starts_the_count_again_and_says_so(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=2, minimum_minutes=10)
        self.run_watchdog()
        self.write(RECORD_PATH, "{not json", mode=RECORD_MODE)
        outcome = self.run_watchdog()
        self.assertEqual(self.actions(), [], "an unreadable record was treated as a met window")
        self.assertIn("could not be read", outcome.stderr)
        self.assertEqual(self.record()["consecutive_failures"], 1)

    def test_the_record_is_not_world_readable_and_is_not_writable_by_others(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        mode = self.record_mode()
        self.assertEqual(mode, RECORD_MODE)
        self.assertEqual(mode & 0o007, 0, "the failure record is readable by every account")
        self.assertEqual(mode & 0o022, 0, "the record is writable by its group or by the world")

    def test_the_record_names_the_streak_and_the_action_in_utc(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=2, minimum_minutes=10)
        self.run_watchdog()
        self.run_watchdog(now=at(minutes=1))
        document = self.record()
        self.assertEqual(document["first_failure_utc"], "2026-09-29T03:00:00Z")
        self.assertEqual(document["last_failure_utc"], "2026-09-29T03:01:00Z")
        self.assertEqual(document["action_utc"], "2026-09-29T03:01:00Z")
        self.assertEqual(document["action_status"], 0)

    def test_a_record_that_cannot_be_written_is_refused_rather_than_counted(self):
        # An unwritable record means every run would read as the first failure,
        # so acting on that is a mechanism with no window in it. It must refuse,
        # and it must say that nothing is watching this machine.
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.rooted(RECORD_PATH).parent.mkdir(parents=True, exist_ok=True)
        self.rooted(RECORD_PATH).mkdir()
        outcome = self.run_watchdog()
        self.assertEqual(outcome.status, installer.EXIT_REFUSED)
        self.assertEqual(self.actions(), [])
        self.assertIn("could not be recorded", outcome.stderr)
        self.assertIn("not being watched", outcome.stderr)


class SwitchTests(WatchdogFixture):
    """The switch, in both positions, and the off position is the one nobody runs."""

    def test_the_shipped_default_is_automatic_rollback_on(self):
        self.assertTrue(SHIPPED_AUTOMATIC)
        self.assertTrue(
            installer.WATCHDOG_DEFAULT_AUTOMATIC,
            "the default in the code is not the default in the file, and the file is what an "
            "operator reads",
        )

    def test_off_takes_no_action_however_many_failures_accumulate(self):
        self.setUp()
        self.setting(automatic="false", consecutive_failures=1, minimum_minutes=10)
        for _ in range(4):
            outcome = self.run_watchdog(now=at(minutes=10))
        self.assertEqual(
            self.actions(), [], "the mechanism acted with the switch off, and a switch is a switch"
        )
        self.assertEqual(outcome.status, installer.EXIT_OK)

    def test_off_still_probes_and_says_what_it_found(self):
        # Switching the mechanism off does not switch off the health check, and an
        # operator who disabled the watchdog still wants to know the machine's own
        # resolver is not answering.
        self.setUp()
        self.setting(automatic="false", consecutive_failures=1, minimum_minutes=10)
        outcome = self.run_watchdog()
        self.assertIn("automatic: false", outcome.stdout)
        self.assertIn("Nothing has been changed", outcome.stdout)
        self.assertIn("did not resolve", outcome.stdout)
        self.assertEqual(self.asked, [(LOCAL_DNS, DNS_PORT)], "the switch turned the probe off too")

    def test_off_clears_a_record_an_armed_run_left_behind(self):
        # Otherwise re-enabling the mechanism resumes a streak the operator
        # interrupted on purpose, and the first failure after they switch it back
        # on is a rollback with no window in front of it.
        self.setUp()
        self.setting(automatic="true", consecutive_failures=3, minimum_minutes=10)
        self.run_watchdog()
        self.run_watchdog()
        self.assertEqual(self.record()["consecutive_failures"], 2)
        self.setting(automatic="false", consecutive_failures=3, minimum_minutes=10)
        outcome = self.run_watchdog()
        self.assertIsNone(self.record())
        self.assertIn("cleared", outcome.stdout)

    def test_the_setting_lives_in_etc_mosdns_with_the_other_operator_inputs(self):
        # Same directory, same mode, and a conffile: a document an operator edits
        # is one an upgrade must ask about, and one a service identity cannot
        # rewrite. The mode is 0644 exactly as the other six documents are, and
        # the package's own mode table is the gate that says so.
        listing = INSTALL_LIST.read_text(encoding="utf-8")
        self.assertRegex(listing, rf"(?m)^\S+\s+{re.escape(SETTING_PATH)}$")
        self.assertIn(f"{SETTING_PATH}\n", CONFFILES.read_text(encoding="utf-8"))
        self.assertEqual(installer.WATCHDOG_SETTING, SETTING_PATH)


class SettingFileTests(WatchdogFixture):
    """The schema, the shipped values, and what an unreadable setting does.

    An unreadable setting is the one case where this package's usual fail-open is
    the wrong answer, and the asymmetry is deliberate: `_ech_is_strict` treats an
    unparseable policy as "not strict" because the alternative refuses an
    install, while here the alternative tears down a working machine. So a
    setting this program cannot read means it does nothing, and it says loudly
    that nothing is watching the machine.
    """

    def parse_shipped(self):
        return installer.parse_watchdog_setting(
            SHIPPED_SETTING.read_text(encoding="utf-8"), str(SHIPPED_SETTING)
        )

    def test_the_shipped_setting_file_says_what_the_code_defaults_to(self):
        setting, refusal = self.parse_shipped()
        self.assertEqual(refusal, "")
        self.assertTrue(setting.automatic, "the shipped file is not automatic: true")
        self.assertEqual(setting.consecutive_failures, SHIPPED_FAILURES)
        self.assertEqual(setting.minimum_minutes, SHIPPED_MINUTES)
        self.assertEqual(setting, installer.default_watchdog_setting())

    def test_the_shipped_file_says_what_is_restored_and_what_is_not(self):
        # Step 6 of the plan is the file's own comments, and an operator who has
        # only ever read this file has to be able to learn that the rollback does
        # not fix the condition the router was installed for.
        body = SHIPPED_SETTING.read_text(encoding="utf-8").lower()
        for claim in ("dnscrypt", "dhcp", "does not", "automatic: true", "emergency-rollback"):
            with self.subTest(claim=claim):
                self.assertIn(claim, body)

    def test_every_key_the_schema_has_is_a_key_the_shipped_file_sets(self):
        body = SHIPPED_SETTING.read_text(encoding="utf-8")
        for key in SETTING_KEYS:
            with self.subTest(key=key):
                self.assertRegex(body, rf"(?m)^{key}: \S+$")

    def test_a_missing_setting_file_leaves_the_shipped_defaults_in_force(self):
        # Absence must not quietly switch the mechanism off: the shipped default
        # is `automatic: true`, and a file somebody deleted is not a decision.
        self.setUp()
        setting, refusal = installer.read_watchdog_setting(self.root)
        self.assertEqual(refusal, "")
        self.assertEqual(setting, installer.default_watchdog_setting())

    def test_an_unknown_key_is_refused_by_name(self):
        self.write(SETTING_PATH, "automatic: true\nautomatic_rollback: false\n")
        setting, refusal = installer.read_watchdog_setting(self.root)
        self.assertIsNone(setting)
        self.assertIn("automatic_rollback", refusal)
        for key in SETTING_KEYS:
            self.assertIn(key, refusal)

    def test_a_value_that_is_not_a_boolean_is_refused(self):
        for value in ("yes", "1", "True", "on", ""):
            with self.subTest(value=value):
                self.write(SETTING_PATH, f"automatic: {value}\n")
                setting, refusal = installer.read_watchdog_setting(self.root)
                self.assertIsNone(setting)
                self.assertIn("automatic", refusal)

    def test_a_count_that_is_not_a_positive_integer_is_refused(self):
        for value in ("0", "-1", "3.5", "three", ""):
            with self.subTest(value=value):
                self.write(SETTING_PATH, f"consecutive_failures: {value}\n")
                setting, refusal = installer.read_watchdog_setting(self.root)
                self.assertIsNone(setting)
                self.assertIn("consecutive_failures", refusal)

    def test_a_minutes_value_that_is_not_a_positive_integer_is_refused(self):
        self.write(SETTING_PATH, "minimum_minutes: soon\n")
        setting, refusal = installer.read_watchdog_setting(self.root)
        self.assertIsNone(setting)
        self.assertIn("minimum_minutes", refusal)

    def test_the_same_key_twice_is_refused(self):
        self.write(SETTING_PATH, "automatic: true\nautomatic: false\n")
        setting, refusal = installer.read_watchdog_setting(self.root)
        self.assertIsNone(setting)
        self.assertIn("automatic", refusal)

    def test_an_indented_key_is_refused(self):
        # The file is a flat table. An indented key is a section header somebody
        # invented, and guessing which section it belongs to is how a setting
        # that says one thing is acted on as another.
        self.write(SETTING_PATH, "window:\n  automatic: false\n")
        setting, refusal = installer.read_watchdog_setting(self.root)
        self.assertIsNone(setting)
        self.assertIn("window", refusal)

    def test_comments_and_blank_lines_are_not_keys(self):
        self.write(
            SETTING_PATH,
            "# the watchdog's setting\n\nautomatic: false\n\n  # indented comment\nminimum_minutes: 1\n",
        )
        setting, refusal = installer.read_watchdog_setting(self.root)
        self.assertEqual(refusal, "")
        self.assertFalse(setting.automatic)
        self.assertEqual(setting.minimum_minutes, 1)

    def test_a_setting_that_cannot_be_read_takes_no_action_and_says_the_machine_is_unwatched(self):
        self.write(SETTING_PATH, "automatic: perhaps\n")
        outcome = self.run_watchdog()
        self.assertEqual(self.actions(), [], "a setting this program cannot read still acted")
        self.assertIsNone(self.record(), "a run that cannot read its setting recorded a failure")
        self.assertEqual(outcome.status, installer.EXIT_REFUSED)
        self.assertIn("not being watched", outcome.stderr)
        self.assertIn(SETTING_PATH, outcome.stderr)


class BlindSpotTests(WatchdogFixture):
    """The force-ECH blind spot, which must never become a reason to tear down.

    `verify-local` refuses to give a verdict at all when the operator's force-ECH
    list makes the router answer the probe name itself, and says in as many words
    that this is not a sign the router is down. A watchdog that counted that
    refusal as a failure would undo a working installation over a line in a text
    file -- which is the self-inflicted outage the window exists to prevent,
    arriving through a different door.
    """

    def blind(self, *domains: str):
        self.write("/etc/mosdns/force-ech-domains.txt", "\n".join(domains) + "\n")

    def test_a_probe_name_the_router_answers_locally_is_not_counted_as_a_failure(self):
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.blind("install-probe.example.")
        outcome = self.run_watchdog()
        self.assertEqual(self.actions(), [])
        self.assertIsNone(
            self.record(), "a verdict the verb refused to give was recorded as a failure"
        )
        self.assertIn("NOT A SIGN THE ROUTER IS DOWN", outcome.stdout)
        self.assertEqual(outcome.status, installer.EXIT_OK)

    def test_a_list_that_does_not_name_the_probe_changes_nothing(self):
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.blind("example.com.", "example.org.")
        self.run_watchdog()
        self.assertEqual(len(self.actions()), 1, "an ordinary list stopped the mechanism")

    def test_ech_turned_off_in_the_policy_is_not_a_blind_spot(self):
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.blind("install-probe.example.")
        self.write(
            "/etc/mosdns/policy.yaml",
            "schema_version: 1\nech:\n  enabled: false\n  failure_policy: strict\n",
        )
        self.run_watchdog()
        self.assertEqual(len(self.actions()), 1)


class UnitAgreementTests(unittest.TestCase):
    """The units this feature ships, held to the shape the plan's ruling names."""

    def service(self) -> dict:
        return _unit_sections((UNIT_DIR / WATCHDOG_UNIT).read_text(encoding="utf-8"))

    def timer(self) -> dict:
        return _unit_sections((UNIT_DIR / WATCHDOG_TIMER).read_text(encoding="utf-8"))

    def test_the_units_ship_in_the_package(self):
        listing = INSTALL_LIST.read_text(encoding="utf-8")
        for unit in (WATCHDOG_UNIT, WATCHDOG_TIMER):
            with self.subTest(unit=unit):
                self.assertRegex(
                    listing, rf"(?m)^\S+\s+/usr/lib/systemd/system/{re.escape(unit)}$"
                )

    def test_the_service_runs_this_verb(self):
        self.assertEqual(
            self.service()["Service"].get("ExecStart"),
            f"{INSTALLER} {VERB}",
            "the unit does not run the watchdog verb, so the timer runs something else",
        )

    def test_it_runs_as_root_because_the_action_demands_it(self):
        # `mosdns-cdnctl emergency-rollback` refuses a non-root uid, so a unit
        # that ran the verb as `mosdns-cdn` would fail at the action every time
        # with a message about privileges rather than about DNS.
        self.assertEqual(self.service()["Service"].get("User"), "root")
        self.assertEqual(self.service()["Service"].get("Group"), "root")

    def test_it_orders_itself_after_networkmanager_and_requires_nothing_from_it(self):
        # Ruling 167, the cycle: a unit that talks to a service through D-Bus must
        # be `After=` it and must not carry any of the five directives that
        # propagate a stop. The family is checked whole because a later edit
        # reaching for `PartOf=` would be reaching for the same cycle.
        unit = self.service()
        self.assertIn("NetworkManager.service", unit["Unit"].get("After", ""))
        for directive in (
            "Requires",
            "BindsTo",
            "PartOf",
            "PropagatesStopTo",
            "Upholds",
            "UpheldBy",
        ):
            with self.subTest(directive=directive):
                self.assertNotIn(
                    directive,
                    unit["Unit"],
                    f"{WATCHDOG_UNIT} carries {directive}= on a unit it only talks to through "
                    "D-Bus, and every one of these propagates a stop",
                )

    def test_the_timer_is_not_persistent_and_starts_after_boot(self):
        # The health timer's measured reason: at a one-minute cadence a laptop
        # closed for a day comes back and replays every elapse it missed. And the
        # first run is three minutes after boot because at boot the router is
        # still coming up, so a probe before then fails by construction.
        self.assertNotIn("Persistent", self.timer()["Timer"])
        self.assertEqual(self.timer()["Timer"].get("OnUnitActiveSec"), "1min")
        self.assertEqual(self.timer()["Timer"].get("OnBootSec"), "3min")
        self.assertEqual(self.timer()["Timer"].get("Unit"), WATCHDOG_UNIT)

    def test_it_carries_the_packaged_sandbox_rather_than_a_new_shape(self):
        # Reuse, not invention: the whole argument for putting this beside the
        # health timer is that it inherits the hardening this package already
        # decided on. A per-unit subset is a privilege decision nobody can review
        # at a glance.
        health = _unit_sections(
            (UNIT_DIR / "mosdns-cdn-health.service").read_text(encoding="utf-8")
        )
        service = self.service()["Service"]
        for key, value in health["Service"].items():
            if key in (
                "User",
                "Group",
                "ExecStart",
                "TimeoutStartSec",
                "ReadWritePaths",
                "UMask",
                # The health unit's exit 4 is the shared control lock, and this
                # unit takes no lock: the watchdog's own non-zero statuses are the
                # ones an operator has to read, so inheriting an excuse here
                # would silence the signal this mechanism exists to raise. Its
                # ABSENCE is asserted in the case below rather than left to this
                # one skipping it.
                "SuccessExitStatus",
            ):
                continue
            with self.subTest(directive=key):
                self.assertEqual(
                    service.get(key),
                    value,
                    f"{WATCHDOG_UNIT} does not carry the health unit's {key}, so it has a "
                    "hardening shape of its own",
                )

    def test_it_carries_no_exit_status_excuse_at_all(self):
        # The health unit's `SuccessExitStatus=4` is the shared control lock: a
        # pin, an apply or an update-lists an operator is running by hand, which
        # is a race and not a fault. The watchdog takes no lock and has no such
        # race, so every non-zero exit it returns is something an operator has to
        # read -- and inheriting an excuse would be silencing the only signal
        # this mechanism produces.
        self.assertNotIn("SuccessExitStatus", self.service()["Service"])

    def test_its_only_writable_directory_is_the_one_its_record_lives_in(self):
        entries = self.service()["Service"]["ReadWritePaths"].split()
        self.assertEqual(
            entries,
            [f"-{RECORD_DIR}"],
            "the watchdog writes exactly one file and it is the failure record",
        )

    def test_the_paths_it_reads_and_writes_are_named_in_its_own_header(self):
        # A unit whose header does not name the files it touches is a unit whose
        # answer to "why is this happening" is a search.
        body = (UNIT_DIR / WATCHDOG_UNIT).read_text(encoding="utf-8")
        self.assertIn(SETTING_PATH, body)
        self.assertIn(RECORD_PATH, body)


def _function_body(source: str, name: str) -> str:
    """One top-level function's source text, by its `def` and its indentation.

    Deliberately not an `ast` walk: this gate is about the text a reader greps
    for, and a walk that reassembled a body would make it about a shape instead
    of about the two spellings it is holding apart. The body starts after the
    line that closes the `def`, because this module is formatted with a closing
    parenthesis on its own column when the signature is long.
    """
    lines = source.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith(f"def {name}("):
            start = index
            break
    if start is None:
        raise AssertionError(f"{name} is not in the module, so the gate is not holding anything")
    while not lines[start].rstrip().endswith(":"):
        start += 1
    body = []
    for line in lines[start + 1:]:
        if line and not line[0].isspace():
            break
        body.append(line)
    return "\n".join(body)


def _unit_sections(text: str) -> dict:
    """A unit's `Section -> {directive: value}`, for the small reads above."""
    sections: dict[str, dict[str, str]] = {}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
            sections[current] = {}
            continue
        if current is None or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        sections[current][key.strip()] = value.strip()
    return sections


if __name__ == "__main__":
    unittest.main()
