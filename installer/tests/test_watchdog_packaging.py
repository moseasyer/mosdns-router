"""What a machine that has this package installed actually gets for the watchdog.

Three files, one decision, and the checks that keep them from disagreeing:

* **the setting** at ``/etc/mosdns/watchdog.yaml`` -- root, 0644, a conffile, and
  its three keys parsed to exactly the values the program defaults to;
* **the two units** -- enabled by ``postinst`` after the transaction succeeds,
  disabled by ``prerm`` with the other three timers, and stopped first by the
  uninstaller;
* **the one thing this package does by itself**, which is why the enable step is
  checked for being *last*: reaching it means the machine's DNS was taken over
  and the daemons are serving, which is the only state in which a mechanism that
  can restore the machine's resolvers has something to protect.

The last of those is a placement claim rather than a content one, and it is the
kind this project has been wrong about before -- the misplaced ``fi`` that made
the enable step unreachable on every install shipped in a green suite, so the
gate here runs ``postinst`` rather than reading it.
"""

import importlib.util
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "installer"))

import mosdns_installer as installer  # noqa: E402


def _package_tests():
    """`test_package` as a module, loaded from its path rather than imported.

    A plain `from test_package import ...` works under
    `python3 -m unittest discover -s installer/tests` and fails under
    `python3 -m unittest installer.tests.test_watchdog_packaging`, because only
    the first puts this directory on the path -- and the brief's own acceptance
    command is the second. `test_transaction` makes the same point for the same
    reason, and the answer there (do not import a sibling) is why this one loads
    it by path instead: this module needs two helpers that are only correct
    because they run the real `postinst`, and re-implementing them here would be
    the exact defect this project's ledger names.
    """
    path = Path(__file__).resolve().parent / "test_package.py"
    spec = importlib.util.spec_from_file_location("_mosdns_test_package", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_package = _package_tests()
CONFFILES = _package.CONFFILES
INSTALL_LIST = _package.MANIFEST
POSTINST = _package.POSTINST
PRERM = _package.PRERM
postinst_transaction_run = _package.postinst_transaction_run
postinst_steps = _package.postinst_steps

WATCHDOG_UNIT = "mosdns-watchdog.service"
WATCHDOG_TIMER = "mosdns-watchdog.timer"
SETTING = "/etc/mosdns/watchdog.yaml"
SHIPPED = REPO / "packaging" / "config" / "watchdog.yaml"


class SettingInstallsTests(unittest.TestCase):
    """The setting reaches a machine, at the mode and with the ownership the
    other operator-authored documents have."""

    def test_the_package_installs_the_setting_where_the_program_reads_it(self):
        listing = [
            line.split()
            for line in INSTALL_LIST.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        rows = {row[1]: row[0] for row in listing if len(row) == 2}
        self.assertEqual(
            rows.get(SETTING),
            "packaging/config/watchdog.yaml",
            "the setting is not installed at the path the program reads, or it is installed from a "
            "different source than the file in the repository",
        )
        self.assertEqual(installer.WATCHDOG_SETTING, SETTING)

    def test_it_is_a_conffile(self):
        listed = [
            line.strip()
            for line in CONFFILES.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertIn(
            SETTING,
            listed,
            "the setting is not a conffile, so an upgrade replaces an operator's `automatic: false` "
            "with the shipped `true` without asking",
        )

    def test_the_whole_table_parses_to_the_programs_defaults(self):
        setting, refusal = installer.parse_watchdog_setting(
            SHIPPED.read_text(encoding="utf-8"), str(SHIPPED)
        )
        self.assertEqual(refusal, "", "the file this package ships does not parse")
        self.assertEqual(setting, installer.default_watchdog_setting())
        self.assertTrue(
            setting.automatic,
            "the shipped default is not automatic rollback, and the user's decision was that it is",
        )

    def test_the_file_states_the_limitation_in_its_own_comments(self):
        # Step 6 of the plan is the file's own comments, and an operator who has
        # only read this file has to be able to learn that the rollback does not
        # fix the condition the router was installed for.
        # Lowercased, because the file is a comment block and this is about the
        # claim rather than about capitalisation. Each phrase is one operator has
        # to be able to find by reading only this file.
        body = SHIPPED.read_text(encoding="utf-8").lower()
        for claim in (
            "basic connectivity only",
            "what the rollback does not fix",
            "does not work after a rollback",
            "it is not fixed",
            "dnscrypt",
            "automatic: true",
            "emergency-rollback",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, body)


class TimerEnableTests(unittest.TestCase):
    """`postinst` enables it, `prerm` disables it, and the uninstaller stops it."""

    def test_postinst_enables_the_watchdog_timer(self):
        self.assertIn(WATCHDOG_TIMER, POSTINST.read_text(encoding="utf-8"))

    def test_prerm_disables_the_watchdog_timer(self):
        text = PRERM.read_text(encoding="utf-8")
        self.assertIn(WATCHDOG_TIMER, text)

    def test_the_uninstaller_stops_it_with_the_other_timers_and_before_the_daemons(self):
        # The order that matters is timers-then-daemons, and it is the one the
        # uninstaller already had: every timer is stopped before either unit this
        # package owns, so nothing is still writing while the machine is being
        # pointed elsewhere. A watchdog timer left running through that would be
        # the one writer that can rewrite the machine's DNS while the rollback is
        # in flight.
        self.assertIn(WATCHDOG_TIMER, installer.PROJECT_TIMERS)
        source = (REPO / "installer" / "mosdns_installer.py").read_text(encoding="utf-8")
        for function in ("uninstall", "_remove_what_was_never_applied"):
            with self.subTest(function=function):
                body = _function_body(source, function)
                self.assertIn("_stop_units(run, PROJECT_TIMERS, notes)", body)
                self.assertLess(
                    body.index("_stop_units(run, PROJECT_TIMERS, notes)"),
                    body.index("_stop_units(run, (ROUTER_UNIT, RESOLVER_UNIT), notes)"),
                    f"{function} stops the daemons before the timers, so a watchdog timer can fire "
                    "against a machine that is being taken apart",
                )

    def test_the_enable_step_is_after_the_transaction_and_only_reached_on_success(self):
        # Run the script, do not read it. The misplaced-`fi` defect shipped inside
        # a green suite, and the reason three substring checks could not see it is
        # that a substring cannot see control flow.
        for status, expected in (
            (0, WATCHDOG_TIMER),
            (1, None),
            (3, None),
            (4, None),
        ):
            with self.subTest(status=status):
                completed, calls = postinst_transaction_run(status)
                enabled = [
                    call for call in calls if call[:1] == ["enable"] and WATCHDOG_TIMER in call
                ]
                if expected is None:
                    self.assertEqual(
                        enabled,
                        [],
                        f"a transaction that exited {status} still enabled the watchdog timer, so "
                        "a machine whose install was refused is running a mechanism that can "
                        "rewrite its DNS unattended",
                    )
                    continue
                self.assertEqual(
                    enabled,
                    [["enable", "mosdns-cdn-optimizer.timer", "mosdns-cdn-health.timer",
                      "mosdns-list-check.timer", WATCHDOG_TIMER]],
                    f"the enable did not carry the watchdog timer: {calls}",
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_the_enable_is_below_the_transaction_in_the_script_itself(self):
        # `postinst_steps` is the reader `test_package` uses for the same claim, so
        # a second implementation of "where does this step happen" would be a
        # second answer to the question the shipped one already answers. Read its
        # own positions rather than re-deriving them.
        steps = postinst_steps(POSTINST.read_text(encoding="utf-8"))
        self.assertGreater(
            steps["enable-timers"],
            steps["install-transaction"],
            "postinst enables the watchdog timer before the transaction, so a machine whose install "
            "is refused is running the mechanism that restores the machine's resolvers",
        )


class WatchdogUnitInstallTests(unittest.TestCase):
    """The two unit files are shipped, and the service is the one the timer names."""

    def test_both_units_are_installed(self):
        listing = INSTALL_LIST.read_text(encoding="utf-8")
        for unit in (WATCHDOG_UNIT, WATCHDOG_TIMER):
            with self.subTest(unit=unit):
                self.assertRegex(
                    listing, rf"(?m)^\S+\s+/usr/lib/systemd/system/{re.escape(unit)}$"
                )

    def test_the_action_the_unit_runs_is_the_verb_that_runs_it(self):
        service = (REPO / "packaging" / "systemd" / WATCHDOG_UNIT).read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/lib/mosdns-router/mosdns_installer.py watchdog", service)
        self.assertEqual(installer.WATCHDOG_ACTION, (installer.CDNCTL, "emergency-rollback"))


def _function_body(source: str, name: str) -> str:
    """One top-level function's source text, by its `def` and its indentation.

    The body starts after the line that closes the `def`, not after the `def`
    line: this module is formatted with a closing parenthesis on its own column
    when the signature is long, and a helper that stopped at the first
    unindented line would hand back a signature and pass a gate that was looking
    at nothing.
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


if __name__ == "__main__":
    unittest.main()
