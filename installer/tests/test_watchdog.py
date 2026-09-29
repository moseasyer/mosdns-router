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
import fcntl
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
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
# The record's own directory, and why it is not simply `/run/mosdns`. That
# directory is 2770 root:mosdns on purpose (ruling 142, measured: the DHCP bridge
# publishes `dhcp-upstreams.json` there as `mosdns-cdn` and needs directory `w`),
# and a `0600` file inside a group-WRITABLE directory is still deletable and
# replaceable, because unlink and rename are the containing directory's decision
# and not the file's. So the record gets a root-owned subdirectory with no
# default ACL, and the only identity that can reach it is the one that writes it.
RECORD_PATH = "/run/mosdns/watchdog/watchdog.json"
RECORD_DIR = "/run/mosdns/watchdog"
CDNCTL = "/usr/lib/mosdns-router/mosdns-cdnctl"
INSTALLER = "/usr/lib/mosdns-router/mosdns_installer.py"
BACKUP_PATH = "/var/lib/mosdns/installer/network-manager-backup.json"
# The package's shared control lock, the mechanism that answers "is somebody else
# mutating this machine's DNS right now" for the optimizer, the health check and
# `update-lists` -- and now for the install transaction and the watchdog.
CONTROL_LOCK = "/var/lib/mosdns/runtime/control.lock"
ACTION = (CDNCTL, "emergency-rollback")
LOCAL_DNS = "127.0.0.1"
DNS_PORT = 53
PROBE_NAME = "install-probe.example"
# The record is 0600 root:root, and the reason is a privilege, not tidiness:
# `/run/mosdns` is a directory a group member can traverse, and the ONLY
# identity in this package that reads the record is the root watchdog. A 0640
# record in a group-*writable* directory is a file `mosdns-cdn` -- the identity
# the Go health check runs as -- can delete to disable the mechanism for ever,
# or replace with a threshold of 99 and a first failure in the past, so the very
# next run tears the machine down with no window in front of it. See
# `RecordOwnershipTests` and `DirectoryModeTests`.
RECORD_MODE = 0o600
RECORD_KEYS = {
    "schema_version",
    "consecutive_failures",
    "first_failure_utc",
    "first_failure_boot_seconds",
    "first_failure_boot_id",
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

    def run_watchdog(self, now: datetime | None = None, boot: datetime | None = None):
        """One watchdog run, as the verb itself computes it.

        The outcome carries both streams verbatim, so a case reads the product's
        own text rather than a restatement of it, and
        `test_the_verb_writes_exactly_what_the_outcome_carries` holds that the
        command line writes these and nothing else.

        `boot` is the boot-relative clock, as a datetime, because a datetime is
        what a case can state exactly: the module converts it to boot seconds and
        the elapsed arm is computed entirely in that unit.

        **`boot` defaults to `now`**, and that default is load-bearing. A case
        that moved the wall clock but not the boot clock is describing a machine
        whose wall clock was stepped, which is a case in its own right
        (`WallClockStepTests`) and not something a case should do by accident --
        and when it happened by accident it looked like a mechanism failure: two
        runs ten minutes apart on the wall clock and microseconds apart on the
        real boot clock is an enormous forward step, which the new code correctly
        reads as a clock nobody can step disagreeing with one that can. Passing
        both together by default means a case that only cares about the count says
        nothing about either clock.
        """
        moment = now or self.now
        return installer.watchdog(
            self.root,
            self.runner,
            probe=self.probe(),
            now=moment,
            boot_seconds=(boot or moment).timestamp(),
        )

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
        #
        # **Both clocks move together here**, and that is the point: the elapsed
        # arm is measured on a clock an operator cannot step, so a case that
        # moves only the wall clock would be testing nothing.
        self.arm()
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(minutes=10), boot=at(minutes=10))
        self.assertEqual(self.actions(), [ACTION], "ten minutes passed and the count never reached 3")
        self.assertIn("10m", outcome.stdout)
        self.assertIn("the window is 10m", outcome.stdout)

    def test_a_minute_short_of_the_elapsed_window_does_not_act(self):
        self.arm()
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(minutes=9, seconds=59), boot=at(minutes=9, seconds=59))
        self.assertEqual(self.actions(), [])
        self.assertIn("9m59s", outcome.stderr)

    def test_both_conditions_met_are_both_named_and_the_action_runs_once(self):
        self.arm(failures=2, minutes=5)
        self.run_watchdog()
        outcome = self.run_watchdog(now=at(minutes=5), boot=at(minutes=5))
        self.assertEqual(
            self.actions(), [ACTION], "both conditions were met and the action ran twice"
        )
        self.assertIn("2 consecutive failures", outcome.stdout)
        self.assertIn("5m", outcome.stdout)


class WallClockStepTests(WatchdogFixture):
    """A wall clock an operator can step must not decide whether a machine is torn down.

    **The first version of the elapsed arm subtracted the recorded UTC
    first-failure from the current UTC now**, guarded only in the *backwards*
    direction, and a forward step satisfied the window on a single failed probe.
    Measured in-process against the shipped defaults, both of these acted:

      * a record stamped ``1970-01-01T00:03:00Z`` and one run at the current
        time -- "29844177m0s have passed since the first failure";
      * a plain +20 minute step with one failure.

    That is reachable on a machine whose boot clock is wrong past the three-minute
    mark, on a host whose clock is adjusted, and on a manual ``hwclock`` step. It
    is the sharpest form of the failure this whole mechanism exists to prevent,
    and this package's own text names the condition: the unit's header and the
    shipped setting both say **"a cold boot before NTP has synchronised"** is
    precisely why the window exists. A cold boot is a forward clock step. The two
    facts combine into a guaranteed unattended teardown.

    So the elapsed arm no longer reads the wall clock at all. It reads a
    **boot-relative** clock (``CLOCK_BOOTTIME``), which an operator cannot step,
    which survives a suspend -- which is the case the arm exists for -- and which
    is gone at a reboot, which is exactly the lifetime the record has.
    """

    def arm(self, failures: int = 3, minutes: int = 10):
        self.setUp()
        self.setting(
            automatic="true",
            consecutive_failures=failures,
            minimum_minutes=minutes,
        )
        return self

    def test_a_record_stamped_at_the_epoch_does_not_tear_a_machine_down(self):
        # The review's own measurement, as a case. One failed probe, a first
        # failure recorded in 1970, and a run now: the count is 1 of 3 and the
        # elapsed arm must say nothing.
        self.arm()
        first = at(minutes=-60 * 24 * 365 * 56)
        self.run_watchdog(now=first, boot=at(minutes=0))
        outcome = self.run_watchdog(now=at(minutes=1), boot=at(minutes=1))
        self.assertEqual(
            self.actions(),
            [],
            "a first failure stamped in 1970 satisfied the elapsed window, so a wall clock that "
            "steps forward is a single-probe teardown",
        )
        self.assertIn("consecutive failure 2 of the 3", outcome.stderr)

    def test_a_twenty_minute_forward_step_does_not_satisfy_the_window_either(self):
        self.arm()
        self.run_watchdog(now=at(), boot=at())
        outcome = self.run_watchdog(now=at(minutes=20), boot=at(seconds=60))
        self.assertEqual(
            self.actions(),
            [],
            "a twenty-minute forward wall-clock step satisfied the ten-minute window on a boot "
            "clock that has advanced one minute",
        )
        self.assertIn("1m0s", outcome.stderr)

    def test_the_decision_is_the_same_however_wrong_the_wall_clock_is(self):
        # The property the fix is for, stated as an equality rather than as two
        # examples: the elapsed arm is not a function of the wall clock at all.
        # A wildly wrong clock and the right one must reach the same decision.
        self.arm(failures=3, minutes=10)
        self.run_watchdog(now=at(), boot=at())
        honest = self.run_watchdog(now=at(minutes=3), boot=at(minutes=3))
        self.arm(failures=3, minutes=10)
        self.run_watchdog(now=at(), boot=at())
        wrong = self.run_watchdog(now=at(days=400), boot=at(minutes=3))
        self.assertEqual(self.actions(), [], "a 400-day-old clock tore the machine down")
        self.assertEqual(
            [line for line in honest.stderr.splitlines() if "consecutive failure" in line],
            [line for line in wrong.stderr.splitlines() if "consecutive failure" in line],
            "the two runs disagree about the count, so the wall clock reaches the decision "
            "somewhere",
        )

    def test_a_clock_that_moved_backwards_no_longer_changes_the_decision(self):
        # The previous version's backwards guard is gone, and deliberately: with
        # the elapsed arm on a boot-relative clock there is nothing to guard, and
        # a guard that clamped a *decision* input to zero was the shape of the
        # forward hole. The wall clock still appears in the message, so a reader
        # is not misled by a timestamp that moved -- and the case below holds the
        # DECISION is unaffected either way.
        self.arm()
        self.run_watchdog(now=at(), boot=at())
        backwards = self.run_watchdog(now=at(minutes=-30), boot=at(minutes=30))
        self.assertEqual(
            self.actions(),
            [ACTION],
            "thirty minutes of boot clock passed and the arm did not fire, so the M arm is dead "
            "or the count reached its threshold",
        )
        self.assertIn("clock", (backwards.stdout + backwards.stderr).lower())

    def test_the_elapsed_arm_fires_on_a_real_advance_with_only_one_failure(self):
        # The review's second requirement: the fix must not make the M arm dead.
        # One failure, ten minutes of BOOT clock, the count still at 1 of 3, and
        # the action runs.
        self.arm(failures=3, minutes=10)
        self.run_watchdog(now=at(), boot=at())
        self.assertEqual(self.record()["consecutive_failures"], 1)
        self.run_watchdog(now=at(minutes=10), boot=at(minutes=10))
        self.assertEqual(self.actions(), [ACTION], "ten minutes on a clock nobody can step did not act")

    def test_a_record_with_no_boot_stamp_does_not_satisfy_the_elapsed_arm(self):
        # A record written before the boot stamp existed, or truncated. The
        # patient answer: the elapsed arm does not fire for it and this run
        # re-stamps it, so the arm is available again from the next failure. What
        # it must never do is fall back to the wall clock, which is the hole.
        self.arm()
        self.run_watchdog()
        document = self.record()
        document["first_failure_boot_seconds"] = None
        self.write(RECORD_PATH, json.dumps(document) + "\n", mode=RECORD_MODE)
        outcome = self.run_watchdog(now=at(days=400), boot=at(seconds=61))
        self.assertEqual(self.actions(), [], "a record with no boot stamp fell back to the wall clock")
        self.assertIn("boot", (outcome.stdout + outcome.stderr).lower())
        self.assertIsNotNone(
            self.record().get("first_failure_boot_seconds"),
            "the record was not re-stamped, so the elapsed arm stays dead for ever on this machine",
        )

    def test_the_boot_stamp_is_stamped_by_the_run_that_observed_the_failure(self):
        self.arm()
        self.run_watchdog(now=at(), boot=at(minutes=2))
        document = self.record()
        self.assertIsNotNone(document.get("first_failure_boot_seconds"))
        self.assertEqual(
            document["first_failure_boot_seconds"],
            at(minutes=2).timestamp(),
            "the boot stamp is not the one this run was given, so the elapsed arm is measuring "
            "something other than the gap between the two runs",
        )
        self.assertIn("first_failure_boot_seconds", RECORD_KEYS)


class AnotherBootTests(WatchdogFixture):
    """A record is about one boot, and a clock nobody can step is still only one boot deep.

    The record lives on the tmpfs at ``/run/mosdns``, and the whole of the design
    rests on that: a reboot takes the streak with it, because the first minutes
    after a boot are exactly when a machine produces a failure that is not a fault.
    **That rests on ``/run`` being a tmpfs**, which is the Linux default and not a
    guarantee -- a host with ``/run`` on a disk carries the record across, and then
    a boot-relative stamp from the PREVIOUS boot is a huge positive number of
    seconds ago on this one, so the elapsed arm fires on the first failed probe of
    a freshly booted machine. The count arm carries over for the same reason.

    So the record names the boot it was written in, and a record from another boot
    -- or from before this field existed -- is re-seeded at one and says so, which
    is the same treatment an unreadable record already gets and the patient
    direction. ``first_failure_boot_id`` is the kernel's own per-boot UUID at
    ``/proc/sys/kernel/random/boot_id``: it is the only identifier of a boot that
    needs no state from this package, and reading it cannot fail in a way that
    matters (a machine that cannot read it gets a record with no boot id, which is
    re-seeded, which is safe).
    """

    def arm(self, failures: int = 3, minutes: int = 10):
        self.setUp()
        self.setting(
            automatic="true",
            consecutive_failures=failures,
            minimum_minutes=minutes,
        )
        return self

    def rewrite(self, **fields):
        document = self.record()
        document.update(fields)
        self.write(RECORD_PATH, json.dumps(document) + "\n", mode=RECORD_MODE)

    def test_a_record_from_another_boot_never_satisfies_the_elapsed_arm(self):
        self.arm()
        self.run_watchdog(now=at(), boot=at())
        self.rewrite(first_failure_boot_id="00000000-0000-0000-0000-000000000000")
        outcome = self.run_watchdog(now=at(minutes=30), boot=at(minutes=30))
        self.assertEqual(
            self.actions(),
            [],
            "a streak from another boot satisfied this boot's elapsed window, so a machine with "
            "/run on a disk tears itself down on its first failure after every reboot",
        )
        self.assertIn("another boot", (outcome.stdout + outcome.stderr).lower())
        self.assertEqual(self.record()["consecutive_failures"], 1, "the streak was carried over")

    def test_a_record_from_another_boot_does_not_carry_the_count_either(self):
        self.arm(failures=3, minutes=10)
        for _ in range(2):
            self.run_watchdog(now=at(), boot=at())
        self.assertEqual(self.record()["consecutive_failures"], 2)
        self.rewrite(first_failure_boot_id="00000000-0000-0000-0000-000000000000")
        self.run_watchdog(now=at(seconds=60), boot=at(seconds=60))
        self.assertEqual(
            self.record()["consecutive_failures"],
            1,
            "two failures from a boot that has been gone for hours still counted, so the third "
            "probe after a reboot performs a rollback with two failures of this boot behind it",
        )

    def test_a_record_with_no_boot_id_is_re_seeded_rather_than_trusted(self):
        # The forward-compatible reading of a record written by an older version
        # of this file. It is the same question as the one above -- is this record
        # about this boot? -- and it has to be asked before the record is used, not
        # afterwards.
        self.arm()
        self.run_watchdog(now=at(), boot=at())
        self.rewrite(first_failure_boot_id=None)
        outcome = self.run_watchdog(now=at(minutes=30), boot=at(minutes=30))
        self.assertEqual(self.actions(), [])
        self.assertIn("boot", (outcome.stdout + outcome.stderr).lower())
        self.assertEqual(self.record()["consecutive_failures"], 1)

    def test_the_record_names_the_boot_this_run_is_in(self):
        self.arm()
        self.run_watchdog(now=at(), boot=at())
        self.assertEqual(
            self.record()["first_failure_boot_id"],
            installer._boot_id(),
            "the record does not name the boot it was written in, so nothing can tell a record "
            "from this boot from one from another",
        )
        self.assertIn("first_failure_boot_id", RECORD_KEYS)

    def test_the_boot_id_is_this_machines_own_and_not_a_constant(self):
        identifier = installer._boot_id()
        self.assertIsInstance(identifier, str)
        self.assertRegex(
            identifier,
            r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
            "the boot id is not the kernel's UUID format, so a placeholder has been substituted "
            "for a value that identifies a boot",
        )


class ResetTests(WatchdogFixture):
    """A success ends a streak rather than pausing it."""

    def arm(self, failures: int = 3, minutes: int = 10):
        self.setUp()
        self.setting(
            automatic="true",
            consecutive_failures=failures,
            minimum_minutes=minutes,
        )
        return self

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

    def test_an_action_killed_at_its_budget_is_told_from_a_failed_restore(self):
        # 124 is what the runner returns for a command that outran its budget,
        # and it is NOT a status this package's verbs return -- so before this
        # fix the journal said "exited 124, which is not a status this package
        # defines", which is exactly backwards: the honest reading is that the
        # launcher was killed at a budget and the restore may never have run at
        # all. The distinction matters because the two need different things from
        # the operator: a failed restore leaves a machine to inspect, and a killed
        # one leaves a question about whether a restore is still in progress.
        self.assertIn(
            124,
            installer.WATCHDOG_ACTION_STATUSES,
            "a command killed at its budget has no sentence, so the most confusing status this "
            "mechanism can produce is the one it prints a bare number for",
        )
        outcome = self.reached(status=124, stderr="")
        self.assertIn("124", outcome.stderr)
        self.assertIn("killed", outcome.stderr.lower())
        self.assertNotIn("not a status this package defines", outcome.stderr)

    def test_a_killed_action_does_not_claim_to_know_the_machines_state(self):
        # A launcher killed at its budget has observed nothing. Whatever sentence
        # this prints must not assert that the machine was left half-restored,
        # because that is exactly the claim it cannot make -- and it must not
        # claim the opposite either.
        outcome = self.reached(status=124)
        for claim in (
            "some of this package's settings may still be on this machine's connection",
            "was restored",
            "was not restored",
            "the restore completed",
        ):
            with self.subTest(claim=claim):
                self.assertNotIn(claim, outcome.stderr)

    def test_a_killed_action_tells_the_operator_how_to_find_out(self):
        # "May still be in progress" is only useful if it comes with the thing to
        # look at. `pgrep` is the answer, and the message has to name it,
        # because an operator told that something may be running and given no way
        # to check has been told nothing.
        outcome = self.reached(status=124)
        self.assertIn("pgrep", outcome.stderr)
        self.assertIn("emergency-rollback", outcome.stderr)

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


def RealCommandRunnerDefault():
    """A runner built the way every verb but the watchdog builds one."""
    return installer.RealCommandRunner()


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

    def test_the_action_budget_is_derived_from_the_work_the_action_does(self):
        # `COMMAND_TIMEOUT_SECONDS` is 30 and `nmcli connection up` inside the
        # rollback re-runs DHCP; killing the rollback half way through a restore
        # is the worst thing this mechanism could do. So the action gets its own
        # budget -- and the budget is **computed from the work**, not chosen:
        #
        #   the work is `emergency_rollback`, which issues at most
        #   `ROLLBACK_COMMAND_BUDGET` commands, each on a runner built with the
        #   default `COMMAND_TIMEOUT_SECONDS`, plus one 2-second probe;
        #   the watchdog's budget is that, plus slack for the Go launcher and the
        #   process-group teardown.
        #
        # The previous version of this gate compared two constants -- the action's
        # budget against `COMMAND_TIMEOUT_SECONDS` -- so raising the budget, or
        # adding a sixth command to the rollback, left it green while the unit's
        # `TimeoutStartSec` became a lie. That is ruling 151's shape: the worst
        # outcome in the package, guarded by a check that cannot fail.
        budget = installer.ROLLBACK_COMMAND_BUDGET
        self.assertEqual(
            budget,
            len(installer.RECORDED_PROPERTIES)
            + len(installer.NM_MUTATIONS)
            + 1  # `nmcli connection up`
            + 1,  # `resolvectl dns`
            "the declared worst-case command count no longer describes the rollback, so the "
            "budget is derived from a number that is not the work",
        )
        self.assertEqual(
            installer.WATCHDOG_ACTION_TIMEOUT_SECONDS,
            budget * installer.COMMAND_TIMEOUT_SECONDS
            + int(installer.PROBE_TIMEOUT_SECONDS)
            + installer.WATCHDOG_ACTION_SLACK_SECONDS,
            "the action's budget is not the work's bound plus slack, so a command that hangs "
            "takes the restore past the budget that exists to protect it",
        )
        self.assertGreater(
            installer.WATCHDOG_ACTION_SLACK_SECONDS, 0, "there is no room for the launcher itself"
        )

    def test_the_rollback_issues_no_more_commands_than_its_declared_budget(self):
        # The measurement the derivation rests on, and the reason it is a test
        # rather than a comment: this RUNS the rollback, against a runner that
        # counts, over a backup in which every recorded property needs putting
        # back. If a sixth command is added -- one more `nmcli connection modify`,
        # another probe, a re-read -- the count here rises above the declared
        # budget and the budget gate above goes red, which is the point.
        issued = []

        class Counting:
            def run(self, args, check=True):
                issued.append(tuple(args))
                if args[:2] == ("nmcli", "-g"):
                    return installer.Completed(0, f"{uuid}.example\n", "")
                if args[:3] == ("nmcli", "connection", "modify"):
                    return installer.Completed(0, "", "")
                if args[:3] == ("nmcli", "connection", "up"):
                    return installer.Completed(0, "", "")
                if args[:2] == ("resolvectl", "dns"):
                    return installer.Completed(0, f"{device}.example: 1.1.1.1\n", "")
                return installer.Completed(0, "", "")

        uuid, device = "11111111-2222-3333-4444-555555555555", "eth0"
        # The record the install itself writes: every recorded property, with the
        # shape `_read_backup` requires of each -- a list for the two address
        # lists and a yes-or-no for the two ignore flags. A hand-written document
        # that skipped that shape would be refused before a single command was
        # issued, and this case would then be measuring zero and passing.
        original = {}
        for prop in installer.RECORDED_PROPERTIES:
            if prop in installer.ADDRESS_LISTS:
                original[prop] = {"raw": "", "value": ["1.1.1.1"], "set_by": "dhcp"}
            else:
                original[prop] = {"raw": "no", "value": "no", "set_by": "manual"}
        document = {
            "schema_version": installer.BACKUP_SCHEMA_VERSION,
            "managed_by": installer.MANAGED_BY_VALUE,
            "package_version": "0.0.0",
            "created_at": "2026-09-29T03:00:00Z",
            "connection": {"uuid": uuid, "device": device, "name": "wired"},
            "original": original,
        }
        self.write(BACKUP_PATH, json.dumps(document) + "\n")
        result = installer.emergency_rollback(self.root, Counting(), probe=self.probe())
        self.assertTrue(
            (result.ok, result.restored),
            f"the rollback under test issued no commands at all, so this case is measuring "
            f"nothing: {result.error}",
        )
        self.assertEqual(
            len(issued),
            installer.ROLLBACK_COMMAND_BUDGET,
            f"the rollback issued {len(issued)} commands but the budget declares "
            f"{installer.ROLLBACK_COMMAND_BUDGET}, so the watchdog's budget is derived from a "
            f"count that is no longer the work's: {issued}",
        )

    def test_the_units_budget_is_above_the_work_derived_one(self):
        unit = (UNIT_DIR / WATCHDOG_UNIT).read_text(encoding="utf-8")
        seconds = int(re.search(r"^TimeoutStartSec=(\d+)$", unit, re.M).group(1))
        self.assertGreater(
            seconds,
            installer.WATCHDOG_ACTION_TIMEOUT_SECONDS,
            f"{WATCHDOG_UNIT} allows {seconds}s, which is not above the action's own "
            f"{installer.WATCHDOG_ACTION_TIMEOUT_SECONDS}s budget, so systemd kills the restore "
            "instead of letting the watchdog report it",
        )

    def test_the_group_kill_works_and_is_not_only_written_down(self):
        # The mechanism, exercised. A real `sleep`, started through the real
        # runner with `kill_group=True` and a budget of a fraction of a second,
        # with a child of its own that writes a file after a delay -- so the case
        # can tell the difference between "the launcher was killed" and "nothing
        # it started is still running". The second is the whole claim.
        self.assertEqual(
            installer.KILLED_AT_BUDGET,
            installer.RealCommandRunner(timeout=0.4, kill_group=True)
            .run(["/bin/sleep", "30"])
            .returncode,
            "a command that outran its budget was not reported as killed",
        )

    def test_a_group_killed_at_its_budget_leaves_nothing_of_its_own_running(self):
        # The same mechanism, with a grandchild, which is the shape the action
        # actually has: `mosdns-cdnctl` is a launcher and the work is below it.
        # A shell that spawns a child and then sleeps is the closest thing to it
        # this host can run, and if the group is not killed the child outlives
        # the call and writes its marker -- which is exactly the unsupervised
        # restore the fix is for.
        marker = self.root / "grandchild-ran"
        script = f"/bin/sh -c 'sleep 2; touch {marker}; sleep 30'"
        outcome = installer.RealCommandRunner(timeout=0.5, kill_group=True).run(
            ["/bin/sh", "-c", script]
        )
        self.assertEqual(outcome.returncode, installer.KILLED_AT_BUDGET)
        # Long enough for the grandchild to have written the marker if it were
        # going to, and short enough not to make the suite slow.
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.1)
        self.assertFalse(
            marker.exists(),
            "the grandchild outlived the budget and ran to completion, so a restore killed at its "
            "budget would keep mutating this machine with nobody watching",
        )

    def test_a_runner_without_the_group_flag_leaves_the_default_alone(self):
        # The flag is opt-in and only the watchdog opts in. Asserted rather than
        # assumed, because the default is the other kind of wrong: a read-only
        # question in a new session cannot be interrupted by the terminal an
        # operator is holding.
        self.assertFalse(installer.RealCommandRunner().kill_group)

    def test_the_action_runs_in_its_own_process_group_so_the_budget_kills_the_restore(self):
        # The launcher is not the work. `mosdns-cdnctl emergency-rollback` execs
        # this program's own `emergency-rollback` verb, and THAT is what rewrites
        # the connection, so killing the launcher at its budget would leave a
        # restore running unsupervised on a machine whose latch says the action
        # has already been performed: nobody would ever report its outcome, and
        # nobody would ever run it again. So the action is started in a new session
        # and the timeout kills the whole group.
        body = _function_body(SOURCE, "_run_a_group")
        self.assertIn("start_new_session", body, "the action does not get a process group of its own")
        self.assertIn("killpg", body, "the budget kills the launcher and leaves the restore running")
        self.assertIn("SIGKILL", body, "the budget does not actually kill the process group")
        # `killpg` on the child's own group, and nothing else. A `kill` of a pid
        # that came from anywhere but `Popen` is a way for this program to kill
        # something it did not start, and this one runs as root.
        self.assertIn("os.getpgid(process.pid)", body)

    def test_the_watchdogs_own_runner_is_the_one_asked_to_kill_the_group(self):
        # The runner takes the flag; the verb has to pass it. A budget with no
        # group behind it is the state this whole fix exists to remove, and it is
        # a default argument away.
        self.assertIn("kill_group=True", _function_body(SOURCE, "main"))
        self.assertFalse(
            RealCommandRunnerDefault().kill_group,
            "the default runner kills its group, so every read-only question this program asks a "
            "running manager is now a process that cannot be interrupted by a terminal",
        )

    def test_the_latch_names_both_ways_a_status_can_go_unrecorded(self):
        # The previous version said an unrecorded status means the record could
        # not be written after the action ran -- as if that were the only cause.
        # A unit SIGKILLed by systemd is the other one, and it is the more
        # alarming: the machine is not known to be in any particular state AND
        # this program was killed rather than having finished. A message that
        # misdiagnoses that sends the operator to look at a filesystem permission
        # instead of at a process that may still be restoring.
        self.setUp()
        self.runner = RecordingRunner(status=0)
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        document = self.record()
        document["action_status"] = None
        self.write(RECORD_PATH, json.dumps(document) + "\n", mode=RECORD_MODE)
        outcome = self.run_watchdog()
        self.assertIn("not recorded", outcome.stderr)
        self.assertIn(
            "killed",
            outcome.stderr.lower(),
            "an unrecorded status is read as a failed write, and a unit systemd killed is not that",
        )
        self.assertIn("pgrep", outcome.stderr)

    def test_a_killed_action_still_does_not_run_again(self):
        # The write-ahead latch, held against the new status. A unit SIGKILLed
        # mid-restore is precisely the case where a second attempt would be a
        # second mutation on a machine whose first one may still be running, and
        # the latch is the only thing preventing it.
        self.setUp()
        self.runner = RecordingRunner(status=124)
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        for _ in range(3):
            self.run_watchdog()
        self.assertEqual(
            len(self.actions()),
            1,
            "an action killed at its budget was attempted again, which on a machine whose restore "
            "may still be running is a second mutation",
        )

    def test_the_action_runs_as_the_verb_an_operator_runs_not_through_a_helper(self):
        # `mosdns-cdnctl emergency-rollback` is the boundary: it refuses to run
        # as a non-root uid and it execs the installer. Going around it would be
        # a path a human would not take.
        source = (REPO / "cmd" / "mosdns-cdnctl" / "main.go").read_text(encoding="utf-8")
        self.assertIn('"emergency-rollback"', source)
        self.assertIn("effectiveUID", source)


class RecordOwnershipTests(WatchdogFixture):
    """Nothing that is not the root watchdog may be able to reach the record.

    The file mode alone is not the question, and the previous version of this
    suite asked only that. `/run/mosdns` is `2770 root:mosdns` with
    `default:group::rwx` -- deliberately, per ruling 142, because the DHCP bridge
    publishes `dhcp-upstreams.json` there as `mosdns-cdn` and needs directory
    `w`. So a `0640 root:mosdns` record sits in a directory whose GROUP can
    create, delete and rename anything in it, and `mosdns-cdn` -- the identity the
    Go health check runs as -- could therefore:

      * **delete** `/run/mosdns/watchdog.json` and switch this mechanism off for
        as long as it liked, with no trace; or
      * **replace** it with a document saying `consecutive_failures: 99` and a
        first failure long past, so that the very next run tears the machine down
        with no window in front of it.

    Both are one filesystem primitive away from a 0640 record, and no test that
    reads `stat` on the file can see either. So the cases here are at the level of
    the DIRECTORY, and the one that matters is measured rather than read: an
    actual unprivileged uid, in a real directory with the shipped mode and ACL,
    attempting the two operations.
    """

    TMPFILES = REPO / "packaging" / "tmpfiles.d" / "mosdns-router.conf"
    POSTINST = REPO / "packaging" / "debian" / "postinst"

    def test_the_record_is_not_readable_by_any_other_identity(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        mode = self.record_mode()
        self.assertEqual(mode, RECORD_MODE)
        self.assertEqual(
            mode & 0o077,
            0,
            "the record is reachable by the group or the world, and nothing in this package but "
            "the root watchdog reads it",
        )

    def test_the_record_is_not_writable_by_its_own_group_either(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        self.assertEqual(
            self.record_mode() & 0o022,
            0,
            "a group-writable record is a record `mosdns-cdn` can rewrite into a threshold of 99 "
            "and a first failure in the past",
        )

    def test_an_unprivileged_member_of_the_group_cannot_delete_the_record(self):
        # The measured version, and the one a mode check cannot make. It builds
        # the directory the package actually ships -- mode and default ACL, in
        # the order the tmpfiles entry and `postinst` apply them -- drops to the
        # real `mosdns-cdn` uid, and tries the unlink.
        if os.geteuid() != 0:
            self.skipTest("changing uid needs root, and this suite must not require it")
        record = self._shipped_directory_with_a_record()
        self._as_mosdns_cdn(lambda: os.unlink(record))
        self.assertTrue(
            record.exists(),
            "a member of the record's own group deleted it, so the mechanism's only automatic "
            "protection can be switched off by the unprivileged identity in this package with no "
            "trace and no journal entry",
        )

    def test_an_unprivileged_member_of_the_group_cannot_replace_the_record(self):
        if os.geteuid() != 0:
            self.skipTest("changing uid needs root, and this suite must not require it")
        record = self._shipped_directory_with_a_record()
        # Staged in the SAME directory, because that is the only place a group
        # member could stage it: a rename across directories needs write on both.
        replacement = record.with_name("watchdog.json.replacement")
        replacement.write_text('{"consecutive_failures": 99}\n')
        replacement.chmod(0o600)
        self._as_mosdns_cdn(lambda: os.replace(replacement, record))
        self.assertEqual(
            json.loads(record.read_text())["consecutive_failures"],
            1,
            "a member of the record's own group replaced it, so the next run reads a threshold of "
            "99 and tears this machine down with no window in front of it",
        )

    def test_the_record_lives_in_a_directory_no_group_member_can_write(self):
        # The structural half, and the one that can be observed without root. A
        # `0600` file inside a group-WRITABLE directory is still deletable and
        # still replaceable, because unlink and rename are governed by the
        # containing directory and not by the file's own mode. So the record gets
        # a root-owned subdirectory of its own, and this case reads the shipped
        # tmpfiles entry and the shipped `postinst` for the mode they give it.
        #
        # It is a SUBdirectory rather than a change to `/run/mosdns` itself,
        # because that directory is 2770 on purpose: ruling 142 measured that the
        # DHCP bridge publishes `dhcp-upstreams.json` there as `mosdns-cdn` and
        # needs directory `w`, and no argument here is better than that
        # measurement. The bridge's file and the watchdog's record are two
        # different things that happen to share a parent, and only one of them
        # has an unprivileged writer.
        for path, needle in ((self.TMPFILES, "d "), (self.POSTINST, None)):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIn(
                    RECORD_DIR,
                    text,
                    f"nothing in {path.name} creates the record's own directory, so after a "
                    "reboot -- when /run is empty -- the watchdog has nowhere to write and "
                    "refuses to count anything",
                )
                self.assertNotRegex(
                    text,
                    rf"a {re.escape(RECORD_DIR)} .*d:g::rwx",
                    f"{path.name} gives the record's directory a default group ACL, which hands a "
                    "group member the ability to replace a 0600 root file inside it",
                )
        entry = next(
            line
            for line in self.TMPFILES.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"d {RECORD_DIR} ")
        ).split()
        mode, owner, group = entry[2], entry[3], entry[4]
        self.assertEqual(mode, "0700", f"the record's directory is {mode}, not 0700")
        self.assertEqual(owner, "root")
        self.assertEqual(group, "root", "the record's directory is group-owned, so it is reachable")
        self.assertEqual(int(mode, 8) & 0o077, 0, "the record's directory is reachable by others")

    def test_the_units_writable_path_is_the_records_own_directory(self):
        # The unit can only write where it is told it may, so the path in
        # `ReadWritePaths` is the enforcement, not a description of it. A unit
        # granted `/run/mosdns` would be granted the bridge's directory -- and
        # with it the ability to remove the DHCP generation the router reads.
        entries = _unit_sections(
            (UNIT_DIR / WATCHDOG_UNIT).read_text(encoding="utf-8")
        )["Service"]["ReadWritePaths"].split()
        self.assertEqual(entries, [f"-{RECORD_DIR}"])

    def test_the_control_stands_up_and_reports_nothing_when_it_is_held(self):
        # A guard that cannot fail is a comment. The same two operations, as
        # root, in the same shipped directory: both succeed, so the two cases
        # above are reading the ownership and not a typo in a path.
        if os.geteuid() != 0:
            self.skipTest("changing uid needs root, and this suite must not require it")
        record = self._shipped_directory_with_a_record()
        os.unlink(record)
        self.assertFalse(record.exists(), "root could not unlink the record in its own directory")

    def _shipped_directory_with_a_record(self) -> Path:
        """A `/run/mosdns` built the way the package builds it, with a record in it.

        The mode and the ACL come from the shipped tmpfiles entry and the shipped
        `postinst` rather than from constants here, so a change to either of them
        is a change to what this case exercises -- and so that the case fails if
        the packaging and the record's mode ever stop agreeing.
        """
        directory = self.root / "run" / "mosdns"
        directory.mkdir(parents=True)
        os.chown(directory, 0, self._mosdns_gid())
        os.chmod(directory, self._shipped_directory_mode())
        self._apply_shipped_default_acl(directory)
        record = directory / "watchdog.json"
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        return record

    def _shipped_directory_mode(self) -> int:
        line = next(
            line
            for line in self.TMPFILES.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"d {RECORD_DIR} ")
        )
        return int(line.split()[2], 8)

    def _apply_shipped_default_acl(self, directory: Path) -> None:
        entry = next(
            line
            for line in self.TMPFILES.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"a {RECORD_DIR} ")
        )
        fields = entry.split()[6:]
        if not any(field.startswith("d:g:") for field in fields):
            return
        setfacl = shutil.which("setfacl")
        if setfacl is None:
            self.skipTest("setfacl is not installed, so the shipped ACL cannot be reproduced")
        subprocess.run(
            [setfacl, "-d", "-m", ",".join(fields), str(directory)],
            check=True,
            capture_output=True,
        )

    def _entry(self, name: str):
        """The passwd entry for a packaged identity, or None where there is none.

        None rather than a made-up uid: a case that cannot find `mosdns-cdn` has
        no business running as some other account and reporting what it did.
        """
        import pwd

        try:
            return pwd.getpwnam(name)
        except KeyError:
            return None

    def _mosdns_gid(self) -> int:
        """The gid of the `mosdns` group, or a fallback for a build host without it."""
        import grp

        try:
            return grp.getgrnam("mosdns").gr_gid
        except KeyError:
            return self._entry("mosdns-cdn").pw_gid if self._entry("mosdns-cdn") else 4242

    def _as_mosdns_cdn(self, work) -> None:
        """Run one callable as `mosdns-cdn`, and put this process back afterwards.

        Both halves of the id are restored even if the callable raises, because a
        test that leaves the suite running as another uid turns every later case
        into a mystery. The order is setgid last, since dropping the privilege is
        the direction that cannot be undone.
        """
        account = self._entry("mosdns-cdn")
        if account is None:
            self.skipTest("this host has no mosdns-cdn account, so there is nothing to be")
        euid, egid = os.geteuid(), os.getegid()
        try:
            os.setegid(account.pw_gid)
            os.seteuid(account.pw_uid)
            work()
        finally:
            os.seteuid(euid)
            os.setegid(egid)


class TransactionExclusionTests(WatchdogFixture):
    """The watchdog must not tear a machine down underneath a running install.

    On an upgrade the watchdog's timer is already enabled -- `postinst`'s own arm
    says so and defers to the transaction -- and the transaction then
    `try-restart`s the two units that serve `127.0.0.1:53`. While they are
    restarting, `127.0.0.1:53` is not answering **by construction**, and the
    watchdog reads that as a failure. At the shipped defaults three failed probes
    are two minutes, and the transaction's own wait deadline is 60 s plus a 30 s
    command budget per unit, so the threshold is reachable inside the window the
    transaction deliberately creates.

    Nothing stopped it: the watchdog takes no lock -- it deliberately does not
    inherit the health unit's `SuccessExitStatus=4`, because a declined run is
    information -- and nothing stops the timer before the transaction. The
    consequence is bounded, because `emergency_rollback` only restores recorded
    values, but a rollback underneath an install is a double mutation nobody asked
    for and a latch burned on a streak that was never a fault.

    **The mechanism is the control lock this package already has.**
    `/var/lib/mosdns/runtime/control.lock` is what the optimizer, the health
    check and `update-lists` all take, and "somebody else is mutating this
    machine right now" is precisely what it means. So the transaction takes it
    across the windows in which the machine's DNS is moving, and the watchdog
    takes it before it acts and declines when it cannot.

    Two things about that shape are load-bearing and are asserted below:

    * **The lock is taken WITHOUT waiting.** A watchdog that blocked on it would
      sit for the length of a transaction, and a transaction that blocked on it
      would hang `dpkg`. Both callers decline, loudly, and the caller that has
      already changed the machine says so in terms of what it is doing.
    * **The publish step is outside the lock**, because `update-lists
      --refresh-ranges` takes the lock itself. A transaction that held it across
      that step would deadlock against its own child, which is why the critical
      section is two sections and not one around everything.
    """

    def arm(self, failures: int = 3, minutes: int = 10):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=failures, minimum_minutes=minutes)
        return self

    def hold_the_lock(self):
        """Take the shared control lock, as another process would."""
        self.holder = self._open_lock()
        fcntl.flock(self.holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(self._release)
        return self.holder

    def _open_lock(self):
        path = self.rooted(CONTROL_LOCK)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(mode=0o640)
        return os.open(path, os.O_CREAT | os.O_RDONLY, 0o640)

    def test_the_watchdog_takes_no_action_while_a_transaction_holds_the_lock(self):
        self.arm()
        outcome = None
        for _ in range(4):
            self.hold_the_lock()
            outcome = self.run_watchdog()
            self._unlock_only()
        self.assertEqual(
            self.actions(),
            [],
            "the watchdog performed an emergency rollback underneath something else that was "
            "mutating this machine's DNS, which is a double mutation and a burned latch on a "
            "failure streak that was never a fault",
        )
        self.assertEqual(outcome.status, installer.EXIT_REFUSED)

    def test_it_says_the_lock_is_held_rather_than_just_not_acting(self):
        # A watchdog that declines SILENTLY is indistinguishable from one that is
        # broken, and the operator reading the journal has to be able to tell the
        # difference between "nothing was wrong" and "something else was in the
        # middle of changing this machine".
        self.arm()
        self.hold_the_lock()
        outcome = self.run_watchdog()
        self.assertIn(CONTROL_LOCK, outcome.stderr)
        self.assertIn("held", outcome.stderr)
        self.assertIn("did nothing at all", outcome.stderr)

    def test_it_does_not_count_the_failure_while_the_lock_is_held(self):
        # Counting is not acting, and the argument for counting is that the
        # streak is a property of the MACHINE. It is not, while a transaction is
        # deliberately making the local resolver stop answering: those failures
        # are the transaction's, and carrying them means the FIRST probe after an
        # upgrade can reach a threshold that the upgrade manufactured.
        self.arm()
        self.hold_the_lock()
        for _ in range(3):
            self.run_watchdog()
        self.assertIsNone(
            self.record(),
            "a transaction's own restarts were counted as this machine's resolver failing, so the "
            "streak that survives the upgrade is the upgrade's",
        )

    def test_the_streak_resumes_from_nothing_once_the_transaction_is_over(self):
        # The other direction: the exclusion must not leave the machine unwatched
        # for ever. After the lock is released the counting starts again at one,
        # which is the patient direction -- one failure of delay, not a machine
        # that stopped being watched.
        self.arm()
        self.hold_the_lock()
        for _ in range(3):
            self.run_watchdog()
        self.assertEqual(self.record(), None)
        self._release()
        self.run_watchdog()
        self.assertEqual(self.record()["consecutive_failures"], 1)
        self.assertEqual(self.actions(), [], "a first failure acted with the lock free")

    def test_it_acts_normally_when_the_lock_is_free(self):
        # The control. A guard that cannot be distinguished from a mechanism that
        # never acts is not a guard.
        self.arm(failures=1, minutes=10)
        self._open_lock()
        outcome = self.run_watchdog()
        self.assertEqual(self.actions(), [ACTION], "a free control lock stopped the action")
        self.assertEqual(outcome.status, installer.EXIT_OK)

    def test_a_lock_it_cannot_open_declines_rather_than_acting_without_one(self):
        # The lock is a guarantee only while it can be taken. A machine whose
        # control lock cannot be opened -- a directory that is not there, a lock
        # that is a directory, a filesystem that will not let it be created -- is
        # a machine where "nobody else is mutating this" cannot be established,
        # and the patient answer is to do nothing and say so.
        self.arm(failures=1, minutes=10)
        self.rooted(CONTROL_LOCK).mkdir(parents=True)
        outcome = self.run_watchdog()
        self.assertEqual(
            self.actions(),
            [],
            "the action ran with no way to know whether a transaction was in flight",
        )
        self.assertIn(CONTROL_LOCK, outcome.stderr)

    def test_the_lock_is_taken_without_waiting(self):
        # Asserted on the source, and it matters in both directions: a watchdog
        # that waited would sit for the length of a transaction, and a transaction
        # that waited would hang dpkg. `LOCK_NB` is the whole of it.
        self.assertIn("LOCK_EX | fcntl.LOCK_NB", _function_body(SOURCE, "_try_control_lock"))

    def test_the_transaction_holds_the_same_lock_while_it_moves_the_machines_dns(self):
        # The other half, and without it the watchdog's half excludes nothing.
        # Read from the source because the transaction is the most delicate code
        # in the project and a case that ran it would be asserting the order of
        # forty commands rather than this one fact about it.
        body = _function_body(SOURCE, "_run_transaction")
        self.assertIn("with _hold_control_lock(root):", body)
        # The window has to CONTAIN the restart of the units that serve
        # 127.0.0.1:53, or it excludes nothing that matters.
        critical = body[body.index("with _hold_control_lock(root):") :]
        for step in ("_start(", "_apply_nm(", "_reconnect(", "_verify(", "_commit_marker("):
            with self.subTest(step=step):
                self.assertIn(step, critical, f"{step} runs outside the control lock")

    def test_the_publish_step_is_outside_the_lock_or_the_transaction_deadlocks(self):
        # `PUBLISH_PREFIXES` is `mosdns-cdnctl update-lists --refresh-ranges`,
        # and `update-lists` takes the control lock itself. A transaction holding
        # that lock across this step would be refusing its own child, and the
        # install would fail at a step that has nothing to do with DNS. So there
        # are two critical sections and this is the seam between them.
        body = _function_body(SOURCE, "_run_transaction")
        publish = body.index("PUBLISH_PREFIXES,")
        first = body.index("with _hold_control_lock(root):")
        self.assertLess(
            publish,
            first,
            "the prefix publication is inside the control lock, so the transaction refuses its own "
            "`update-lists --refresh-ranges`, which takes that lock",
        )

    def test_the_rollback_holds_the_lock_too(self):
        # A rollback stops the same two units, so it makes `127.0.0.1:53` stop
        # answering in exactly the way the install does, and a watchdog that acted
        # during one would be doing to a machine being put RIGHT what it does to a
        # machine being left broken.
        self.assertIn("_roll_back_under_the_lock(root, transaction, notes)", _function_body(SOURCE, "install"))
        self.assertIn("with _try_control_lock(root):", _function_body(SOURCE, "_roll_back_under_the_lock"))

    def test_a_rollback_that_cannot_take_the_lock_still_rolls_back(self):
        # The one place the discipline is deliberately broken, and it is worth
        # being explicit about why. A rollback is the response to a half-applied
        # install; making it wait for a lock would be the worst possible answer,
        # because the machine is already in the state the rollback exists to leave.
        # So it proceeds unlocked, and says so in a note beside the failure it is
        # already reporting.
        self.assertIn("LockUnavailable", _function_body(SOURCE, "_roll_back_under_the_lock"))
        self.assertIn(
            "WITHOUT the control lock",
            _function_body(SOURCE, "_roll_back_under_the_lock"),
            "a rollback that ran without the lock did not say so",
        )

    def _unlock_only(self):
        fcntl.flock(self.holder, fcntl.LOCK_UN)

    def _release(self):
        """Drop the lock and close the descriptor, tolerating being called twice.

        The cases release it mid-test and the cleanup releases it again, so this
        has to be idempotent rather than raising out of a cleanup and burying the
        assertion that failed.
        """
        try:
            fcntl.flock(self.holder, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(self.holder)
        except OSError:
            pass


class RecordTests(WatchdogFixture):
    """Where the failure record lives, and what an absent one is allowed to mean."""

    def test_the_record_is_written_under_its_own_directory_and_nowhere_else(self):
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        self.assertIsNotNone(self.record(), "no record was written, so nothing can be counted")
        self.assertEqual(RECORD_PATH, "/run/mosdns/watchdog/watchdog.json")
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
    # Both spellings, because the module has a module-level function and a
    # method of the same shape and a gate that could only see one of them would
    # be a gate that quietly stopped holding.
    starts = [
        f"def {name}(",
        f"    def {name}(",
    ]
    start = None
    for index, line in enumerate(lines):
        if any(line.startswith(prefix) for prefix in starts):
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
        # A method ends where the next `def` at the SAME indentation begins,
        # which is one level in from the `def` that opened it -- not at the next
        # unindented line, which for a method is the end of the whole class and
        # would hand every method in it the body of every method after it.
        if line.startswith("    def ") or line.startswith("    @"):
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
