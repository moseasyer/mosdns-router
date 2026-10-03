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
# Where the uid-dropping cases build their fake root, and why it is named rather
# than left to `TMPDIR`. A dropped uid must be able to traverse to the directory
# under test, and on this host `TMPDIR` is inside `/home/ubuntu/.cache` at 0700 --
# so every operation would fail on the path, above anything the case made, and
# the permissions being measured would never be reached. `/tmp` is 1777.
#
# The case that would catch that is
# `RecordOwnershipTests.test_the_control_proves_the_dropped_identity_really_could_reach_the_parent`:
# it asserts the same dropped identity, in the same tree, at the PARENT's shipped
# mode, **succeeds**. A harness that blocks the operation makes the control red
# rather than the two protection cases quietly green.
_UID_TEST_ROOT = "/tmp"
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

    # -- the shared control lock, as another process holds it ----------------
    # On the base fixture rather than on one subclass, because two subclasses
    # need it: the exclusion cases, and the negative-list table's deferred-by-lock
    # path. A helper copied into the second one would be a second thing to keep
    # in step with the first.

    def _open_lock(self) -> int:
        path = self.rooted(CONTROL_LOCK)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(mode=0o640)
        return os.open(path, os.O_CREAT | os.O_RDONLY, 0o640)

    def hold_the_lock(self) -> int:
        """Take the shared control lock, as another process would."""
        self.holder = self._open_lock()
        fcntl.flock(self.holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(self._release)
        return self.holder

    def _unlock_only(self) -> None:
        fcntl.flock(self.holder, fcntl.LOCK_UN)

    def _release(self) -> None:
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

    def test_a_record_whose_boot_cannot_be_confirmed_is_used_and_says_so(self):
        # **Measured, and it changed the design.** The live cell's record reads
        # `first_failure_boot_id: null` with a perfectly good
        # `first_failure_boot_seconds`, because `mosdns-watchdog.service` carries
        # the packaged `ProcSubset=pid` and that hides `/proc/sys` -- so
        # `/proc/sys/kernel/random/boot_id` is not there to read. The guard
        # above therefore does not fire in the shipped unit at all, and a guard
        # that cannot fire while looking armed is worse than none.
        #
        # The two ways to close that are both wrong. Refusing the elapsed arm
        # whenever the boot cannot be confirmed would disable the M arm on every
        # machine this package ships -- and the M arm exists for the suspend case,
        # which is the one place waiting is the wrong answer. And dropping
        # `ProcSubset=pid` would give this unit a hardening shape of its own, which
        # is the thing the plan's reuse ruling exists to prevent.
        #
        # So the guard degrades in the open: the record is used, its boot id stays
        # null, and the run says once that the boot could not be confirmed, why,
        # and which guard IS in force -- the record on a tmpfs, which is the
        # design's primary answer to exactly this question.
        self.arm()
        self.run_watchdog(now=at(), boot=at())
        self.rewrite(first_failure_boot_id=None)
        outcome = self.run_watchdog(now=at(minutes=30), boot=at(minutes=30))
        said = (outcome.stdout + outcome.stderr).lower()
        self.assertEqual(
            self.record()["consecutive_failures"],
            2,
            "a run whose boot could not be confirmed threw the streak away, so the mechanism "
            "counts from one on every run and never reaches its threshold",
        )
        self.assertIn("could not be confirmed", said)
        self.assertIn("tmpfs", said)
        self.assertIn(
            "/proc/sys/kernel/random/boot_id",
            said,
            "the message does not say WHY the boot could not be confirmed, and the reason is a "
            "directive in the unit's own sandbox",
        )
        # And the elapsed arm is still alive for it, because that is the whole
        # of the trade this case is documenting.
        self.assertEqual(self.actions(), [ACTION])

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

    #: The phrases a message must not contain, as a table rather than a literal
    #: at the two call sites. The review's minor: the list was five literals
    #: inside one case, so adding a claim of health to a DIFFERENT message was
    #: invisible, and the failure path -- which has its own wording and its own
    #: sentences -- was never checked at all.
    FALSE_CLAIMS = (
        "the machine is back",
        "everything is back to normal",
        "the machine is working again",
        "everything is fine",
        "fully restored",
        "this machine's dns is restored",
        "the fault is fixed",
        "is working again",
        "the machine is healthy",
        "back to normal",
    )

    #: The paths whose messages must not claim the machine is back, named. The
    #: names are what the assertions report and what the docstring and the report
    #: enumerate, so "how many paths are checked" has one answer rather than three.
    NEGATIVE_LIST_PATHS = (
        "success",
        "below the window",
        "switch off",
        "no verdict",
        "deferred by the lock",
        "latch",
        "action failed",
        "action killed at its budget",
        "setting unreadable",
    )

    def _assert_no_false_claim(self, outcome, where: str):
        said = (outcome.stdout + outcome.stderr).lower()
        for lie in self.FALSE_CLAIMS:
            with self.subTest(where=where, lie=lie):
                self.assertNotIn(
                    lie, said, f"the {where} message claims {lie!r}, which is the one claim this "
                    "mechanism must never make"
                )

    def test_no_message_on_any_path_claims_the_machine_is_back(self):
        # Every path, not just the success one. Each of these is a distinct set of
        # sentences written by a distinct branch, and a branch nobody read is a
        # branch nobody checked: the success path, the refusal below the window,
        # the switch off, the blind spot, the deferred-by-lock path, the latch, a
        # failed action, an action killed at its budget, and a setting that cannot
        # be read.
        #
        # **Nine, and the table is the thing the docstring and the report
        # describe.** An earlier version of this case listed seven in the table
        # while its own comment and the report both said eight or nine, so the
        # coverage claim was not true of the coverage: two real branches -- the
        # deferred-by-lock path and the latch -- were never checked at all, and a
        # future message is checked against a table whose size is a guess.
        # `test_every_watchdog_path_is_in_the_negative_list_table` holds the count.
        outcomes = {
            "success": self.reached(),
            "below the window": self.run_watchdog(),
            "switch off": self._switched_off(),
            "no verdict": self._blind(),
            "deferred by the lock": self._deferred_by_lock(),
            "latch": self._latched(),
            "action failed": self.reached(status=installer.EXIT_ROLLBACK_FAILED),
            "action killed at its budget": self.reached(status=installer.KILLED_AT_BUDGET),
            "setting unreadable": self._unreadable_setting(),
        }
        for where, outcome in outcomes.items():
            self._assert_no_false_claim(outcome, where)

    def test_every_watchdog_path_is_in_the_negative_list_table(self):
        # The table is not allowed to shrink, because nothing else would notice.
        # Each of the nine is reachable and each prints a different set of
        # sentences, and the two that were missing from the first version are the
        # two an operator reads while an upgrade is running.
        self.assertEqual(
            len(self.NEGATIVE_LIST_PATHS),
            9,
            "the negative-list table is the thing a future message is checked against, so its "
            "size has to be a fact rather than whatever the dict happens to contain",
        )
        for name in (
            "success",
            "below the window",
            "switch off",
            "no verdict",
            "deferred by the lock",
            "latch",
            "action failed",
            "action killed at its budget",
            "setting unreadable",
        ):
            with self.subTest(path=name):
                self.assertIn(name, self.NEGATIVE_LIST_PATHS)

    def _deferred_by_lock(self):
        self.setUp()
        self.shapes[(LOCAL_DNS, DNS_PORT)] = SILENT
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.hold_the_lock()
        try:
            return self.run_watchdog()
        finally:
            self._release()

    def _latched(self):
        # A streak that has already acted, probed again. The latch's own words.
        self.setUp()
        self.shapes[(LOCAL_DNS, DNS_PORT)] = SILENT
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.run_watchdog()
        return self.run_watchdog()

    def _switched_off(self):
        self.setUp()
        self.shapes[(LOCAL_DNS, DNS_PORT)] = SILENT
        self.setting(automatic="false", consecutive_failures=1, minimum_minutes=10)
        return self.run_watchdog()

    def _blind(self):
        self.setUp()
        self.shapes[(LOCAL_DNS, DNS_PORT)] = SILENT
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.write("/etc/mosdns/force-ech-domains.txt", "install-probe.example.\n")
        return self.run_watchdog()

    def _unreadable_setting(self):
        self.setUp()
        self.setting(automatic="perhaps")
        return self.run_watchdog()

    def test_the_actions_own_words_are_checked_for_the_same_lies(self):
        # The review's minor, second half: the failure message deliberately ECHOES
        # the action's output -- "the action's own words follow, because they are
        # the report" -- and the negative list never saw that output, so a
        # rollback that printed "the machine is back" would have been repeated
        # verbatim into a watchdog message that is the only thing an operator
        # reads at three in the morning.
        #
        # This cannot be fixed in the product: the watchdog is not going to
        # rewrite what the operator's own command said, and a message that
        # paraphrased it would be worse than one that quotes it. So the claim is
        # the opposite one -- the echo is labelled as the action's words and not
        # as the watchdog's verdict, and the watchdog's OWN sentences around it
        # make no claim. A case that failed the whole run on a lying action would
        # be a case that had decided the watchdog should lie less than the command
        # an operator ran by hand.
        outcome = self.reached(
            status=installer.EXIT_ROLLBACK_FAILED,
            stderr="emergency-rollback: the machine is back and everything is fine\n",
        )
        self.assertIn("the action's own words follow", outcome.stderr)
        self.assertIn("the machine is back", outcome.stderr, "the action's words were not echoed")
        # And the watchdog's own sentences around the echo claim nothing.
        for line in outcome.stderr.splitlines():
            if "the machine is back" in line:
                with self.subTest(line=line):
                    self.assertIn("the action's own words", line)

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

    def test_no_verdict_and_verify_local_disagree_on_the_status_and_that_is_stated(self):
        # The review's minor, and it is a real inconsistency that was left to be
        # discovered: on the IDENTICAL condition -- the force-ECH blind spot --
        # `verify-local` exits 1 and the watchdog exits 0. The verdicts agree, and
        # the substantive requirement is met on both sides: nothing was counted,
        # nothing was acted on, and the message is explicit that this is not a
        # sign the router is down. Only the STATUS differs, and it differs in the
        # patient direction, which is a choice worth writing down.
        #
        # It is the right direction for each unit separately. `verify-local` is
        # the second command of the health unit, and a health unit that failed is
        # the signal an operator acts on -- a check that cannot be made is not a
        # check that passed. The watchdog's unit carries no `SuccessExitStatus`
        # at all, so every non-zero it returns is something to read; a blind spot
        # is a configuration the operator has to know about and not a fault, and
        # a unit failing every minute over a line in a text file would be noise
        # that trains an operator to ignore this unit.
        self.setUp()
        self.setting(automatic="true", consecutive_failures=1, minimum_minutes=10)
        self.write("/etc/mosdns/force-ech-domains.txt", "install-probe.example.\n")
        outcome = self.run_watchdog()
        self.assertEqual(outcome.status, installer.EXIT_OK)
        self.assertEqual(outcome.verdict, installer.NO_VERDICT)
        self.assertIn("NOT A SIGN THE ROUTER IS DOWN", outcome.stdout)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            verify = installer._run_verify_local(self.root, self.probe())
        self.assertEqual(verify, installer.EXIT_REFUSED, "the two verbs no longer disagree, so the")
        self.assertIn("NOT A SIGN THE ROUTER IS DOWN", err.getvalue())
        # The disagreement is the point, so it is asserted as a disagreement
        # rather than left for a reader to work out from two different numbers.
        self.assertNotEqual(
            outcome.status,
            verify,
            "this case exists to hold the two statuses apart; if they now agree, the reasoning "
            "above is out of date and this case is asserting a difference that is not there",
        )
        # And the reason is in the shipped text, not only in this file.
        self.assertIn("exit", _function_body(SOURCE, "_deferred"))
        body = _function_body(SOURCE, "watchdog")
        self.assertIn("NO_VERDICT", body)

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
        # **This case is permission-dependent too, and it is the fifth in this
        # suite.** It makes the record's directory `0500` during the action so the
        # post-action status write fails while the pre-action record stays
        # readable -- and that state is only reachable for an identity the mode
        # binds, which root is not. Run as root the write SUCCEEDS, the
        # "could not be written" text never appears, and the case fails on an
        # assertion about a message rather than about the latch.

        # So it says so and skips, with the reason, rather than passing on a
        # suite-wide false. The latch it is here for is demonstrated two ways that
        # need no permission at all: this file's
        # `test_a_killed_action_still_does_not_run_again`, and the plain streak
        # cases in `ActionTests.test_the_action_runs_at_most_once_per_failure_streak`.
        # What is NOT demonstrated anywhere is a *readable but unwritable* record
        # still latching, and that is recorded in the report's residual list.
        if os.geteuid() == 0:
            self.skipTest(
                "this case's evidence is a permission, and root is not bound by the mode bits it "
                "sets: run it as an unprivileged uid, and note that the readable-but-unwritable "
                "case has no non-root evidence elsewhere in this suite"
            )

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


def shipped_prose(path: Path) -> str:
    return shipped_prose_from(path.read_text(encoding="utf-8"))


def shipped_prose_from(source: str) -> str:
    """A shipped document's words, with troff and YAML structure removed.

    **The same reader as `shipped_prose`, over text already in hand.** It is split
    out rather than reimplemented so that "what words does this roff say" stays one
    function: a second implementation would be a second thing that could be wrong
    about the same file.

    **It exists because a gate that must be sure a claim is written in ONE PLACE
    cannot ask a reader that reads the whole file.** `test_package.py`'s
    foreign-route gates match keywords, and a keyword that also occurs four hundred
    lines away satisfies them -- two mutations proved exactly that. Rewriting "picks
    ONE upstream at random" as "picks ONE upstream by some rule" left a gate green
    because `random` occurred elsewhere in the manual, and deleting the sentence
    saying the cost is not latency was matched by a stray `.B not` far from it. A
    gate that cannot be sure WHERE a word is written is not a gate about where the
    claim lives.

    **Necessary, and the failure it fixes is the case being false for the
    wrong reason.** `mosdns-router(8)` writes the correction as

        it does
        .B not
        fire in this package's own unit

    so a regex over the raw source sees `.B` between `not` and `fire` and
    reports a man page that says the right thing as one that does not. A gate
    that cannot read the sentence it is checking is a gate whose failures
    send a reader to the wrong file.

    **Only the macro NAME is removed, never its argument** -- `.BR
    ProcSubset=pid ,` must keep `ProcSubset=pid`, and a whole-line strip
    would take it. The first version of this helper dropped every line
    beginning with `.` and failed all three documents for exactly that
    reason: a gate that cannot see the word it is looking for.

    **Module-level, and shared with `test_package.py`**, for the reason this
    project's fakes are shared rather than copied: a second implementation of
    "what words does this roff file say" is a second thing that can be wrong
    about the same file, and the two would disagree about the documents they
    both read.
    """
    lines = []
    for line in source.splitlines():
        if line.startswith("."):
            line = re.sub(r"^\.[A-Za-z]+\*?\s?", " ", line)
        lines.append(line.replace("\\-", "-").replace("\\&", ""))
    # Emphasis markers go too, for the same reason: `mosdns-cdnctl(1)` writes
    # `it does **not** fire`, and an assertion about the WORDS must not care
    # how they are marked up.
    return re.sub(r"\s+", " ", " ".join(lines)).replace("*", "").lower()



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
