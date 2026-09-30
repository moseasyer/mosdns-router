"""The matrix cell: the private network, the mock router, the target, and the registry.

Task 3 is the first task in this plan with a **scenario in it**, and three things
change because of that. Each is a case here rather than a sentence, because each
of the three is a way for a run to report something it did not do.

* **A cell starts more than one container.** The plan's private network carries
  four fixed addresses, and the DHCP scenario needs two of them -- the mock router
  and the target -- on the same bridge, because a lease has to cross a network
  for the claim to be a DHCP claim. So the cell starts the router, tracks it, and
  gives it the plan's address; a router started by hand and not tracked is a
  container `cleanup` cannot sweep and the next run inherits.

* **A target is built from the locked reference, not named.** `images.lock.json`
  is the only source of base images, and the plan's Task 2 step 4 says the build
  constructs `docker.io/library/ubuntu:VERSION@digest` at run time. A harness that
  started a container from `localhost/mosdns-target:24.04` would be testing an
  image nothing in the repository accounts for, and the digest in the lock would
  be a comment. The build command is asserted here, and so is the *tag*: it has to
  change when the Containerfile or the base reference changes, or a stale image
  is what the matrix runs.

* **`--scenario` is run or refused, never parsed and dropped.** A scenario that
  is not registered is a configuration error naming it; a scenario that *is*
  registered runs, and a run that named none runs every registered one -- which is
  the shape the plan's own acceptance command and its Task 7 Make target use.
"""

import importlib.util
import inspect
import json
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "tests" / "podman"

sys.path.insert(0, str(HARNESS / "lib"))
sys.path.insert(0, str(HARNESS / "tests"))

import images  # noqa: E402
import test_command  # noqa: E402
import test_dhcp_scenario  # noqa: E402
from podman import CONTAINER_CAPABILITIES as CONTAINER_CAPS  # noqa: E402
from podman import RunResources  # noqa: E402
from report import Report, ScenarioResult, Skip  # noqa: E402

_spec = importlib.util.spec_from_file_location("mosdns_matrix_cell_run", HARNESS / "run.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

PodmanTestCase = test_command.PodmanTestCase

RUN_ID = test_dhcp_scenario.RUN_ID
ROUTER = test_dhcp_scenario.ROUTER
TARGET = test_dhcp_scenario.TARGET
PROFILE = test_dhcp_scenario.PROFILE
# The unit the target image installs and enables, named here rather than spelled
# in each case: a case that typed the name would be a case that still passes if
# the unit is renamed, which is the one edit that would silently un-gate the cell.
NM_SETUP_UNIT = "target-nm-setup.service"
MOCK_ROUTER_ADDRESS = test_dhcp_scenario.MOCK_ROUTER_ADDRESS
SUBNET = "10.89.0.0/24"
TARGET_ADDRESS = "10.89.0.10"


class EntryPoint(PodmanTestCase):
    """`run.py`'s own entry point, driven against a fake podman."""

    def invoke(self, argv):
        return test_command.EntryPointTestCase.invoke(self, argv)

    def base(self, fake, *extra):
        return ["--podman", str(fake.path), "--source-tree", str(self.source_tree), *extra]

    def passing_fake(self, rules=None):
        """A fake that answers everything the harness asks on a *passing* cell.

        The scenario's half of the table is `test_dhcp_scenario.cell_rules`, so a
        matrix case and a scenario case are answered by the same answers: a second
        copy would be a second thing that can be wrong about what a passing run
        looks like, and a case that stopped agreeing with the run it describes
        would still be green. What is added here is the handful the *runner*
        needs and the scenario never asks for.
        """
        return self.fake(
            (rules if rules is not None else []) + self.passing_fake_rules()
        )

    def passing_fake_rules(self):
        """`passing_fake`'s table, without the fake.

        Split out so a case that wants to change *one* rule -- a build that fails,
        an image that is already in the store -- edits the table the passing cases
        use instead of spelling a second version of it out. A table copied in
        order to be modified is the copy that goes stale, and it goes stale
        silently: the case stays green, and green about a run that no longer
        resembles the one its neighbours describe.
        """
        return [
            {"match": ["version"], "stdout": "5.7.0\n"},
            {"match": ["info"], "stdout": "overlay\n"},
            # Not in the store, so the build is asked for rather than skipped
            # -- a rule that said the image was there would make the build
            # argument invisible to every case below.
            {"match": ["image", "exists"], "returncode": 1},
            {"match": ["build"], "stdout": "sha256:" + "a" * 64 + "\n"},
            {"match": ["run"], "stdout": "9f3c1d0e2b\n"},
            {"match": ["cat", test_dhcp_scenario.ROUTER_LEASE_FILE], "stdout": ""},
            {"match": ["network", "exists"], "returncode": 1},
            # The cell's first readiness gate: the target image's setup unit
            # finished. `active` is measured on all three releases (`SubState`
            # `exited`, `Result` `success`), and a case that wants another state
            # says so in its own rules -- see `TargetReadinessTest`. An
            # unanswered `is-active` is an empty string, which is not `active`, so
            # leaving this out would make every cell here incomplete rather than
            # passing, which is a loud failure rather than a silent one.
            {"match": ["systemctl", "is-active", NM_SETUP_UNIT],
             **test_dhcp_scenario.is_active_answer("active")},
        ] + test_dhcp_scenario.cell_rules()


class ScenarioRegistryTest(EntryPoint):
    """`--scenario` is run or refused."""

    def test_a_registered_scenario_runs_the_cell_and_the_run_passes(self):
        fake = self.passing_fake()
        results = self.directory / "results"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04", "--scenario", "dhcp")
        )
        self.assertEqual(code, run.EXIT_OK, output)
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        self.assertEqual(document["status"], "passed")
        self.assertEqual([s["name"] for s in document["results"][0]["scenarios"]], ["dhcp"])
        self.assertEqual(document["results"][0]["scenarios"][0]["status"], "passed")

    def test_a_registered_scenario_runs_even_with_no_scenario_flag(self):
        """The plan's own acceptance command, and its Task 7 Make target, pass no flag.

        `python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04`
        is the whole matrix. A harness where naming nothing means running nothing
        would report that command incomplete forever, which is what the Task 2
        build did -- honestly, and for a state that has now changed.

        **A scenario that needs the built package is not in this case.** The fake
        podman cannot install a `.deb`, so a run of the whole matrix here reaches
        the watchdog scenario and its cell fails -- correctly, and for a reason
        that has nothing to do with what this case is about. The flag-free run is
        proved over the scenarios a fake can answer, and the package-backed one is
        in `test_the_package_backed_scenarios_are_the_ones_that_need_the_package`
        plus a live run. Listing the scenario explicitly is what the plan's own
        acceptance command does from Task 3 on, and that path is the case above.
        """
        fake = self.passing_fake()
        results = self.directory / "results"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04",
                      "--scenario", "dhcp")
        )
        self.assertEqual(code, run.EXIT_OK, output)
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        self.assertEqual(
            [s["name"] for s in document["results"][0]["scenarios"]],
            ["dhcp"],
            "naming no scenario must not run a package-backed one a fake podman cannot satisfy; "
            f"the scenarios a flag-free run covers are {run.SCENARIO_NAMES} and the one it skipped "
            f"is {sorted(set(run.PACKAGE_SCENARIOS))}",
        )

    def test_the_declared_extra_arguments_are_the_builders_own_parameters(self):
        """**The map and the signatures, held to each other.**

        `run.py` hands every builder the keyword arguments `MOCK_SCENARIO_EXTRA`
        names for it, and every one of them is keyword-only, so a name the
        builder does not accept is a `TypeError` at cell construction: exit 2, a
        report that says nothing was proved about any release, and a reader sent
        to look for a broken harness rather than a cell that never ran. That is
        exactly what the first version of this did -- one set, every argument to
        every member of it, so `install` was handed a `client` and `routing` an
        `override_path`, neither of which either of them accepts.

        So this is checked from both directions, by `inspect.signature` on the
        builders themselves rather than by reading the map's comments: a name in
        the map that no builder takes, and a builder that takes a name the map
        does not give it. The second is the one a comment cannot catch.
        """
        declared = run.MOCK_SCENARIO_EXTRA
        self.assertEqual(
            set(declared) - set(run.SCENARIO_NAMES),
            set(),
            "a scenario is listed as needing an extra container and is not registered, so the "
            "harness would start a container for a scenario that never runs",
        )
        for name in run.SCENARIO_NAMES:
            with self.subTest(scenario=name):
                parameters = inspect.signature(
                    run._resolve_builder(name)
                ).parameters
                wanted = set(declared.get(name, ()))
                missing = wanted - set(parameters)
                self.assertEqual(
                    missing, set(),
                    f"the harness hands {name} {sorted(missing)} and its builder does not take "
                    f"it, so the cell dies with a TypeError before a scenario runs",
                )
                # `deb` is the other conditional, and it is held by the same rule
                # from the other end: a builder that takes it and is not in
                # `PACKAGE_SCENARIOS` is handed nothing, and one in the set that
                # does not take it is a `TypeError`. The case above already covers
                # the set, so here it is only subtracted.
                passed = set(declared.get(name, ()))
                if name in run.PACKAGE_SCENARIOS:
                    passed.add("deb")
                # The parameters every builder takes, so what is left is a
                # parameter the cell's own composition forgot -- a builder that grew
                # one the declarations do not name would be handed nothing for it
                # and would say so, which is the property being held here.
                common = {
                    "podman", "version", "arch", "run_id", "router", "target",
                    "network", "results_dir", "wait_seconds", "interval", "now", "sleep",
                }
                undeclared = set(parameters) - common - passed
                self.assertEqual(
                    undeclared, set(),
                    f"{name}'s builder takes {sorted(undeclared)}, which the harness does not "
                    f"pass it, so it can only ever see the default",
                )

    def test_every_extra_parameter_names_a_role_the_cell_builds_a_name_for(self):
        # `EXTRA_PARAMETER_ROLES` is what turns a builder's parameter name into the
        # container role the name comes from, and `foreign` -> `mock-foreign` is a
        # mapping somebody has to have written down. A role the cell does not build
        # a name for is a `KeyError` at cell construction, and a parameter with no
        # entry at all is one too -- so both are refusals here.
        built = {
            "mock-router", "target", "mock-foreign", "client",
        }
        self.assertEqual(
            set(run.EXTRA_PARAMETER_ROLES.values()) - built, set(),
            "an extra parameter names a role the cell does not build a container name for",
        )
        for scenario, parameters in run.MOCK_SCENARIO_EXTRA.items():
            for parameter in parameters:
                if parameter == "override_path":
                    continue
                self.assertIn(
                    parameter, run.EXTRA_PARAMETER_ROLES,
                    f"{scenario} is handed {parameter!r} and the role map has no entry for it, "
                    f"so the cell looks the name up under a key that is not there",
                )
        # And the two flags the cell starts containers from are the same map, so a
        # scenario that needs the client cannot be served a cell without one.
        self.assertEqual(
            {name for name, extra in run.MOCK_SCENARIO_EXTRA.items() if "client" in extra},
            {"routing"},
        )
        self.assertEqual(
            {name for name, extra in run.MOCK_SCENARIO_EXTRA.items() if "foreign" in extra},
            {"install", "routing"},
        )

    def test_the_package_backed_scenarios_are_the_ones_that_need_the_package(self):
        """The registry, the package set, and the two disagreeing would be a silent skip.

        `run.py` copies the `.deb` in for exactly the scenarios in
        `PACKAGE_SCENARIOS`. A scenario added to the registry that is not in that
        set would be handed no `deb` argument and fail with a `TypeError` at cell
        construction; one in the set that is not registered would be a name the
        harness resolves a package for and then never runs. Both are refusals here
        rather than a live run that discovers them.
        """
        registered = set(run.SCENARIO_NAMES)
        self.assertEqual(
            set(run.PACKAGE_SCENARIOS) - registered,
            set(),
            "a scenario is listed as needing the package and is not registered, so the harness "
            "resolves a `.deb` for a cell that never runs",
        )
        self.assertEqual(
            registered - set(run.SCENARIO_NAMES),
            set(),
            "the registered names and the package set have drifted apart",
        )
        # And the property that makes the flag-free run above possible: every
        # scenario a fake podman can answer is NOT package-backed.
        self.assertNotIn("dhcp", run.PACKAGE_SCENARIOS)
        self.assertIn("watchdog", run.PACKAGE_SCENARIOS)

    def test_a_missing_package_is_a_harness_error_naming_the_command_that_makes_one(self):
        """`make package`, and exit 2 rather than a failed cell.

        A cell that failed because an artifact was not built would be reported as
        a failure of the release, and a reader would go looking for an installer
        bug. Nothing was proved about 24.04 either way, which is what exit 2 says.
        """
        code, output = self.invoke(
            self.base(
                self.passing_fake(),
                "--results-dir", str(self.directory / "results"),
                "--run-id", RUN_ID, "--arch", "mips64",
                "matrix", "--versions", "24.04", "--scenario", "watchdog",
            )
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("make package", output)

    def test_a_scenario_that_is_not_registered_is_refused_with_its_name(self):
        """Exit 2, the name, and the names that would have worked.

        The refusal is a configuration error rather than a cell that did not run:
        `--scenario` is the flag the plan's own acceptance command passes, and
        silently ignoring it made that command report "no scenario is registered"
        -- which reads as though the harness looked for `dhcp` and did not find
        it, when in fact it never looked.

        The name asked for is `routin`, a near-miss rather than a name that was
        never plausible. It used to be `routing`, which was an unregistered
        scenario at the time and became one when Task 4 Step 6 registered it -- so
        this case silently stopped testing the refusal and started testing a cell,
        which is the failure mode the file's own docstring warns about and which
        nothing reported. A name nobody would write is what keeps this case
        exercising the refusal after the registry grows.
        """
        self.assertNotIn(
            "routin", run.SCENARIO_NAMES,
            "this case asks for `routin`, which must not be registered, or it is no longer "
            "testing the refusal",
        )
        fake = self.passing_fake()
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04", "--scenario", "routin")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("routin", output)
        self.assertIn("dhcp", output)
        self.assertEqual(
            [argv for argv in fake.invocations() if argv[:1] == ["run"]], [],
            "a refused scenario still started a container",
        )

    def test_a_comma_separated_scenario_list_is_accepted(self):
        """**The plan's own acceptance command, and it did not work.**

        Task 4 Step 7's command is

        ```text
        python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04 \\
            --scenario install,routing
        ```

        and `--scenario` was `action="append"`, so the whole string was one
        argument, the name `install,routing` matched nothing, and the run refused
        with exit 2 and a message about `install,routing`:

        ```text
        harness error: refusing --scenario install,routing: no such scenario is
        registered in this build of the harness, so the requested one cannot be run.
        The registered scenarios are dhcp, install, routing, and …
        ```

        Every one of those words is correct and the run is useless, because a
        reader who then ran `--scenario install --scenario routing` -- which the
        refusal's own message invites -- would conclude the plan's command was
        wrong rather than the flag. `--versions` already takes a comma-separated
        list for the same reason, and a caller writing both options in the same
        style is being reasonable.

        So a comma-separated `--scenario` is **split**, and the repeatable spelling
        keeps working: both are how a Make target, a CI variable and a person each
        spell the same request, and a flag that accepts only one of the three is
        the flag that gets worked around.
        """
        for spelling in (
            ["--scenario", "install,routing"],
            ["--scenario", "install", "--scenario", "routing"],
        ):
            with self.subTest(spelling=" ".join(spelling)):
                fake = self.passing_fake()
                code, output = self.invoke(
                    self.base(fake, "--results-dir", str(self.directory / "results"),
                              "--run-id", RUN_ID, "matrix", "--arch", "amd64",
                              "--versions", "24.04", *spelling)
                )
                # Not EXIT_OK: this suite's fake answers the *dhcp* scenario, so
                # a cell that installs the package fails for want of an install
                # fixture. What is being checked is that both scenarios RAN and in
                # the load-bearing order, so the status is not the subject -- and
                # asserting it would be asserting a fact about the fixture rather
                # than about the flag.
                self.assertNotEqual(
                    code, run.EXIT_HARNESS_ERROR,
                    f"a run naming two scenarios the way {spelling} spells them refused as a "
                    f"configuration error:\n{output}",
                )
                document = json.loads(
                    next((self.directory / "results").rglob("report.json")).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    [scenario["name"] for scenario in document["results"][0]["scenarios"]],
                    ["install", "routing"],
                    f"a scenario list spelled {' '.join(spelling)} did not run both, or ran "
                    "them in the wrong order -- and the order is load-bearing: routing asks "
                    "the router install put there",
                )

    def test_a_comma_separated_scenario_list_still_refuses_an_unknown_name(self):
        """Splitting is not a way to smuggle a bad name past the refusal.

        A split that dropped the check would let `--scenario install,nonsense` run
        `install` and quietly ignore the half nobody could run -- which is the exact
        defect `--scenario` being run-or-refused exists to prevent, arrived at from
        the other direction.
        """
        fake = self.passing_fake()
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04",
                      "--scenario", "install,nonsens")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        self.assertIn("nonsens", output)
        self.assertEqual(
            [argv for argv in fake.invocations() if argv[:1] == ["run"]], [],
            "a refused scenario list still started a container",
        )

    def test_an_empty_element_in_a_comma_separated_list_is_refused(self):
        """`install,` is a typo, and dropping it would be a run nobody asked for.

        A split that filtered empties would accept `--scenario install,` and run
        one scenario, reporting nothing about the empty element -- so a trailing
        comma in a Make variable would look like a working command. The name it
        would have to report is the one an operator can see, which is the whole
        element as written.
        """
        fake = self.passing_fake()
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04",
                      "--scenario", "install,")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        self.assertIn("empty", output.lower())
        self.assertEqual(
            [argv for argv in fake.invocations() if argv[:1] == ["run"]], [],
            "a refused scenario list still started a container",
        )

    def test_a_refusal_names_every_requested_scenario_not_only_the_first(self):
        """`--scenario` is repeatable, and a caller who mistyped one of three is told so.

        One of the three is a real registered scenario and two are near-misses,
        so the case cannot pass by reporting only the first name: the first is one
        nobody would have mistyped, and a refusal that named only what it
        recognised would satisfy the "it is in the output" assertion for it.
        """
        for near_miss in ("routin", "instal"):
            self.assertNotIn(
                near_miss, run.SCENARIO_NAMES,
                f"this case asks for {near_miss!r}, which must not be registered",
            )
        fake = self.passing_fake()
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04",
                      "--scenario", "dhcp", "--scenario", "routin", "--scenario", "instal")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        for name in ("routin", "instal"):
            self.assertIn(name, output)

    def test_the_registry_is_the_one_the_refusal_and_the_runner_agree_on(self):
        """Two lists would drift, and the drift is invisible: a name in one and not the other.

        The refusal prints what would have worked and the runner looks up what
        was asked for, so a name registered in one and not the other is either a
        scenario nobody can ask for or a refusal that lies about it.
        """
        self.assertTrue(run.SCENARIO_NAMES)
        self.assertIn("dhcp", run.SCENARIO_NAMES)
        self.assertEqual(
            sorted(run.SCENARIO_NAMES), sorted(set(run.SCENARIO_NAMES)),
            "a scenario name is registered twice",
        )
        for name in run.SCENARIO_NAMES:
            with self.subTest(scenario=name):
                self.assertIn(
                    name, run.build_scenarios(),
                    "a registered scenario has no builder, so asking for it is refused and asking "
                    "for nothing does not run it",
                )


class BuildFailureTest(EntryPoint):
    """A `podman build` that fails is a **harness error**, and it is exit 2.

    **The asymmetry is the point, and it is one-directional.** A build that fails
    is `PodmanError` from `_build_images`, which `main` reports as exit 2 and
    which happens *before* any cell exists -- so no report is written, no cell is
    recorded `failed`, and nothing in the artifact says a release was tested. The
    reverse is not reachable: there is no path by which a build failure becomes a
    `failed` row, because the build is not inside the cell.

    Why it matters: a regression here is reported as a **broken image**, and the
    consequence runs the wrong way. A cell that could not start proves nothing
    about the package, so a `failed` row sends a reader after an installer bug
    that is not there -- and the image is a harness artefact, not the thing the
    plan is about. That is the misdirection the docstring warns about, and it is
    why the refusal lives in `_build_images` rather than being left to the report.

    So the case is: the build fails, the run exits 2, **and no row anywhere claims
    a release was tested.** The last part is what a reader would check, and it is
    the part that fails if somebody moves the build inside the cell.
    """

    def failing_build_fake(self):
        """A fake whose answer is `passing_fake` except the build, which fails.

        The passing table with its one `build` rule swapped for one that fails, so
        every other answer a cell needs is still there: a fake that answered
        nothing else would fail for a second reason too, and the case would not
        say which of the two it was about. The stderr is a real `podman build`
        failure -- an `apt-get` step that could not find a package -- so the
        refusal is exercised against the message an operator would actually read,
        and the role in the refusal can be checked against the image that failed.
        """
        return self.fake([
            {
                "match": ["build"],
                "returncode": 1,
                "stderr": (
                    'Error: building at STEP "RUN apt-get install": exit status 100: '
                    "E: Unable to locate package dnsmasq-base\n"
                ),
            },
        ] + [
            rule for rule in self.passing_fake_rules() if rule["match"] != ["build"]
        ])

    def test_a_build_that_fails_is_a_harness_error_and_not_a_failed_cell(self):
        fake = self.failing_build_fake()
        results = self.directory / "results"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04", "--scenario", "dhcp")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        # The message names the role, the version, the tag and why it is not a
        # result. A reader who sees "build failed" alone looks in the wrong place.
        for needle in ("mock-router", "24.04", "mosdns-mock-router:24.04-", "harness error"):
            with self.subTest(needle=needle):
                self.assertIn(needle, output)
        # Nothing was started, so nothing was tested.
        self.assertEqual(
            [argv for argv in fake.invocations() if argv[:1] == ["run"]], [],
            "a run whose image could not be built still started a container",
        )
        self.assertEqual(
            [argv for argv in fake.invocations() if argv[:1] == ["network"] and argv[1:2] == ["create"]], [],
            "a run whose image could not be built still created the network",
        )

    def test_a_build_failure_leaves_no_row_claiming_a_release_was_tested(self):
        """**The half a reader actually reads.** Nothing says 24.04 was tested.

        The failure is one-directional, and this is the direction that matters. If
        a build failure were ever recorded as a cell, the report would carry
        `24.04: failed` for a release no container ever ran on -- a row that reads
        as a result and is not one, which is the shape this project keeps meeting.
        So the case asserts the *absence* of any such row, and says why the
        absence is the assertion rather than a side effect.
        """
        fake = self.failing_build_fake()
        results = self.directory / "results"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04", "--scenario", "dhcp")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        reports = sorted(results.rglob("report.json")) if results.exists() else []
        for path in reports:
            document = json.loads(path.read_text(encoding="utf-8"))
            for result in document.get("results", []):
                self.assertNotEqual(
                    result.get("status"), "failed",
                    f"{path} carries a failed row for {result.get('version')}, but no container "
                    f"was ever started, so that row is not a result",
                )
        # And the before/after snapshots *were* written: the teardown is in a
        # `finally`, and a harness error that skipped it would leave a run whose
        # host state is unrecorded -- which is the case where a reader wants it
        # most.
        self.assertTrue(
            list(results.rglob("host-before.json")) and list(results.rglob("host-after.json")),
            "the run failed on its image and still did not snapshot the host, so there is no "
            "record of what this machine looked like either side of it",
        )


class TargetReadinessTest(EntryPoint):
    """**A readiness wait on a field is not a readiness wait on the process that
    owns the field.**

    The cell's only readiness gate was `wait_for_networkmanager_device`, which
    polls `GENERAL.NM-MANAGED` for `yes`. That field is produced by the target
    image's `target-nm-setup.service` -- and the service is `Type=oneshot` with
    `RemainAfterExit=yes`, so between NetworkManager answering `yes` (from the
    `conf.d` declaration, during the daemon's own activation) and the unit
    *finishing*, the unit is still running. On 24.04 and 26.04 its third step is
    `systemctl restart NetworkManager`, so in that window the field reads `yes`
    and NetworkManager is about to go away.

    Measured, polling a starting 24.04 target once a second:

    ```text
    t=1s NM-MANAGED='Error: Could not create NMClient object…'  NM='inactive'   unit='inactive'
    t=2s NM-MANAGED='yes'                                         NM='activating' unit='inactive'
    ```

    and the unit's own restart, from its journal:

    ```text
    NetworkManager[55]: caught SIGTERM, shutting down normally.
    ```

    So the gate returned, the scenario ran `nmcli connection up eth0-managed`, and
    that landed inside the restart: `Error: NetworkManager is not running` (exit 8).

    **Two rates, and the one that is easy to quote is the one that means least.**
    The *visible* failure was 3 in 9 runs on a loaded machine and 1 in 6 at
    `4867d8d` with none of the later code checked out -- so it predates the fix
    round -- but it is also **0 in 12 on a quiet machine**, measured at the parent
    commit. A number that depends on what else the host is doing is a property of
    the host.

    The defect is the gate, and it was wrong on **24 of 24 boots measured** (12 per
    release, recording the unit's state at the poll where the field first read
    `yes`): `inactive` or `activating` every time, never `active`. That is the
    figure to act on, and it is the one a reader of the diff alone can check.
    After the fix, 24 runs -- 12 on 24.04, 12 on 22.04 -- all passed.

    The two facts are separate and neither substitutes for the other: the **unit**
    is what must be finished first, the **field** is what the scenarios need. The
    cases below hold the *ordering*, not merely that two waits exist -- a harness
    that waited on the field and the unit in either order, or on only one, fails
    one of them.
    """

    def rules_for(self, *, unit_answers, managed_answers=("yes",)):
        """The passing table with the two readiness reads made controllable.

        `unit_answers` and `managed_answers` are *sequences*, so a case can say
        "activating for the first three reads, then active" -- which is what a
        target that is still booting looks like -- as well as "activating for
        ever", which is what a target whose unit is wedged looks like. The two are
        different failures and the failure message has to tell them apart, so the
        cases need both.
        """
        rules = [
            rule for rule in self.passing_fake_rules()
            if rule["match"][:1] != ["systemctl"] and rule["match"][:2] != ["nmcli", "-g"]
        ]
        return rules + [
            {"match": ["systemctl", "is-active", "NetworkManager"], "stdout": "active\n"},
            {"match": ["systemctl", "is-active", NM_SETUP_UNIT],
             "answers": [test_dhcp_scenario.is_active_answer(state) for state in unit_answers]},
            {"match": ["nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", "eth0"],
             "answers": [{"stdout": f"{value}\n"} for value in managed_answers]},
            {"match": ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "eth0"],
             "stdout": f"{PROFILE}\n"},
        ] + test_dhcp_scenario.target_rules()

    def cell(self, fake):
        results = self.directory / "results"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04", "--scenario", "dhcp")
        )
        return code, output, results

    def managed_reads(self, fake):
        return [argv for argv in fake.invocations()
                if argv[:2] == ["exec", TARGET] and argv[2:5] == ["nmcli", "-g", "GENERAL.NM-MANAGED"]]

    def test_a_still_running_setup_unit_stops_the_cell_even_when_the_field_says_yes(self):
        """**The race, exactly.** The field is `yes`; the unit is still running.

        This is the one that matters, and the shape of it is the whole defect:
        the field is what the field-based wait looks at, it reads `yes` from the
        first read, and a harness with only that wait proceeds into a unit that
        is about to restart NetworkManager. So the case is not "the wait exists"
        -- it is "the cell refuses *while* the field is already satisfied", which
        a field-only gate cannot do.

        Two assertions, and the second is the sharp one:

        * the cell is **incomplete**, with a reason naming the unit; and
        * `GENERAL.NM-MANAGED` was **never read as a gate at all** -- the field
          check is downstream of the unit check, so a cell that stopped on the
          unit did not consult the field, and an implementation that read the
          field first and treated it as sufficient would leave a read behind.

        The second is what makes this an ordering case rather than a presence
        case. `assertIsNone`-shaped absence assertions are easy to satisfy by
        accident; this one is satisfied only by doing the checks in the right
        order.
        """
        fake = self.fake(self.rules_for(unit_answers=["activating"], managed_answers=["yes"]))
        code, output, results = self.cell(fake)
        self.assertEqual(code, run.EXIT_INCOMPLETE, output)
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        result = document["results"][0]
        self.assertEqual(result["status"], "incomplete", output)
        self.assertTrue(result["skips"], "an incomplete cell with no reason to act on")
        reason = " ".join(skip["reason"] for skip in result["skips"])
        self.assertIn(NM_SETUP_UNIT, reason,
                      f"the reason does not name the unit, so the reader is not told what to "
                      f"look at: {reason}")
        self.assertEqual(
            self.managed_reads(fake), [],
            "the cell stopped on the setup unit but still consulted GENERAL.NM-MANAGED, so the "
            "field check is not downstream of the unit check -- the ordering is what keeps a "
            "field that reads 'yes' from standing in for a finished setup",
        )

    def test_a_setup_unit_that_reports_its_verdict_as_a_failure_stops_the_cell(self):
        """`failed` is a terminal state too, and the one that matters most.

        The unit is `Type=oneshot` with the script's exit status as its verdict, so
        `failed` means the target refused to continue -- the profile is missing, or
        the device is not an ethernet one, or the declaration did not take effect.
        A wait that only recognised `active` would spin until its budget and then
        report the same message as a target that is merely slow, which sends the
        reader to wait rather than to read the unit's own log where the script
        said which of the three it was.
        """
        fake = self.fake(self.rules_for(unit_answers=["failed"], managed_answers=["yes"]))
        code, output, results = self.cell(fake)
        self.assertEqual(code, run.EXIT_INCOMPLETE, output)
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        reason = " ".join(skip["reason"] for skip in document["results"][0]["skips"])
        self.assertIn(NM_SETUP_UNIT, reason)
        self.assertIn(
            "failed", reason.lower(),
            f"the reason does not carry the state the unit reported, so a reader cannot tell a "
            f"target that refused from one that is still starting: {reason}",
        )
        # **And it stops at once.** This is the behaviour that distinguishes a
        # terminal state from a state the wait is still watching for, and it is
        # the whole reason `failed` is not treated as "not yet": a wait that
        # burned its 120s budget here would report a target that already said
        # what was wrong as one that is merely slow, and a reader would go and
        # wait instead of reading the unit's log.
        self.assertIn(
            "1 reads", reason,
            f"the wait kept reading after the unit had reached a terminal state, so a target that "
            f"refused is reported as one that is slow: {reason}",
        )
        # The read count is one because the very first read already said `failed`.
        self.assertEqual(
            len([argv for argv in fake.invocations()
                 if argv[:4] == ["exec", TARGET, "systemctl", "is-active"]
                 and NM_SETUP_UNIT in argv]),
            1,
            "the setup unit was read more than once despite reporting a terminal failure",
        )

    def test_a_unit_that_never_becomes_terminal_names_its_budget_and_read_count(self):
        """The other bounded path: `inactive` for ever, so the budget runs out.

        Separate from the `failed` case because it is a different reader. `failed`
        is a target that told us what was wrong; `inactive` is a target whose
        setup unit has not started at all, which is what a target still booting
        looks like and what a target with a broken image looks like. The two must
        not print the same message, and the message for this one has to carry the
        numbers -- budget, read count, interval -- because "the unit never ran" and
        "the unit is slow" are different findings and only the read count tells
        them apart.
        """
        fake = self.fake(self.rules_for(unit_answers=["inactive"], managed_answers=["yes"]))
        code, output, results = self.cell(fake)
        self.assertEqual(code, run.EXIT_INCOMPLETE, output)
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        reason = " ".join(skip["reason"] for skip in document["results"][0]["skips"])
        self.assertIn(NM_SETUP_UNIT, reason)
        for needle in ("did not reach", "120s", "reads", "s apart"):
            with self.subTest(needle=needle):
                self.assertIn(
                    needle, reason,
                    f"the budget failure does not carry {needle!r}, so a reader cannot tell a "
                    f"target that never started from one that is merely slow: {reason}",
                )
        # And it must have read more than once, or "never became active" is a
        # claim about one reading.
        self.assertGreater(
            len([argv for argv in fake.invocations()
                 if argv[:4] == ["exec", TARGET, "systemctl", "is-active"]
                 and NM_SETUP_UNIT in argv]),
            1,
            "the wait gave up after a single read, so the budget in the message is not a "
            "measurement of anything",
        )

    def test_a_finished_unit_with_an_unmanaged_device_still_stops_the_cell(self):
        """The other direction, and it is why there are two waits.

        The unit has run and the field is not `yes`. A gate on the *unit* alone
        would wave this target through, and every scenario would then fail on a
        lease it never had -- which is the misdirection the device wait's own
        message was written to avoid. So the field check is not redundant with the
        unit check, and this case is what says so.
        """
        fake = self.fake(self.rules_for(unit_answers=["active"], managed_answers=["no"]))
        code, output, results = self.cell(fake)
        self.assertEqual(code, run.EXIT_INCOMPLETE, output)
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        result = document["results"][0]
        reason = " ".join(skip["reason"] for skip in result["skips"])
        self.assertIn("GENERAL.NM-MANAGED", reason,
                      f"the reason does not name the field, so it cannot be told from a target "
                      f"that is merely still setting up: {reason}")
        self.assertTrue(
            any("GENERAL.NM-MANAGED" in " ".join(argv) for argv in fake.invocations()),
            "the cell stopped without ever reading the managed field, so the second check is "
            "not being made",
        )

    def test_a_container_that_is_not_running_yet_is_waited_for_not_called_a_broken_image(self):
        """**The opposite of the case below, and the one a live run found first.**

        `podman run -d` returns before the container exists, so the cell's *first*
        read of the setup unit is a `podman exec` against a container that has not
        started. Measured, that answers with **no state word at all**:

        ```text
        $ podman exec <not-running> sh -c 'systemctl is-active x'
        Error: can only create exec sessions on running containers: container state improper
        ```

        which is a *transient* and must be retried. A first version of the read
        discriminated on the exit code alone and called it a missing unit instead,
        and the consequence was not subtle: **two consecutive live 24.04 cells
        both went `incomplete` with the gate refusing on its first read**, on a
        perfectly healthy image, before any scenario ran.

        So this case is the control for the discrimination: a query that produced
        no word is retried, and a cell that gets one is still waiting rather than
        already refusing. A gate that refused here would make every run fail, and
        the fake could not have shown it -- a fake whose `exec` always succeeds is
        exactly the fake that hides it.
        """
        # Two answers: the first read finds the container not running yet, and the
        # second finds it up. The `is-active` rule is built here rather than
        # through `is_active_answer`, because "no word" is not a state.
        rules = [
            {"match": ["systemctl", "is-active", NM_SETUP_UNIT],
             "answers": [
                 {"stdout": "", "returncode": 255,
                  "stderr": "Error: can only create exec sessions on running containers\n"},
                 {"returncode": 0, "stdout": "active\n"},
             ]},
        ] + [
            rule for rule in self.rules_for(unit_answers=["active"], managed_answers=["yes"])
            if rule["match"] != ["systemctl", "is-active", NM_SETUP_UNIT]
        ]
        fake = self.fake(rules)
        code, output, _ = self.cell(fake)
        self.assertEqual(code, run.EXIT_OK, output)
        self.assertGreaterEqual(
            len([argv for argv in fake.invocations()
                 if argv[:4] == ["exec", TARGET, "systemctl", "is-active"]
                 and NM_SETUP_UNIT in argv]),
            2,
            "the cell did not read the unit again after the container refused an exec, so a "
            "container that had not started yet would be called a broken image",
        )

    def test_a_unit_that_does_not_exist_is_reported_as_a_broken_image_not_a_slow_target(self):
        """**Why the fake has to model the exit code at all.**

        `systemctl is-active` on a unit the image does not have prints
        `inactive` and exits **4**; a unit that merely has not started prints the
        same word and exits **3**. Measured on a real target. So the two are
        indistinguishable from stdout, and only the exit code separates them --
        and they mean opposite things to a reader: one is a target that is slow,
        the other is an image that is wrong.

        A fake that answers every state with `returncode: 0` cannot tell them
        apart either, so it cannot hold this case, and a wrapper that could not
        read the state at all would have agreed with that fake.

        So the reason must name the image, and the cell must stop on the first
        read. `inactive` on its own is the correct answer for a target that is
        booting, and a reader who is told that of a broken image goes and waits --
        which is what a budget exists to make them do.

        **This case, with `test_a_setup_unit_that_reports_its_verdict_as_a_failure_stops_the_cell`,
        is what catches the wrapper regression this round fixed.** With
        `setup_unit_state` reading through `check=True` again -- the state it
        shipped with, and the state its docstring claimed the opposite of -- and
        the exit codes modelled, both go red: the `failed` case reports 25 reads
        against a 120s budget, and this one reports a slow target. Verified.
        """
        fake = self.fake([
            # The unit file is not in the image: `is-active` says so on the exit
            # code, and prints the same word a unit that has not started prints.
            {"match": ["systemctl", "is-active", NM_SETUP_UNIT],
             "stdout": "inactive\n", "returncode": 4},
        ] + [
            rule for rule in self.rules_for(unit_answers=["active"], managed_answers=["yes"])
            if rule["match"] != ["systemctl", "is-active", NM_SETUP_UNIT]
        ])
        code, output, results = self.cell(fake)
        self.assertEqual(code, run.EXIT_INCOMPLETE, output)
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        reason = " ".join(skip["reason"] for skip in document["results"][0]["skips"])
        self.assertIn(
            "no such unit", reason,
            f"a target whose image has no {NM_SETUP_UNIT} is reported as though the unit were "
            f"merely not running yet, so a reader is sent to wait instead of to the image: "
            f"{reason}",
        )
        self.assertNotIn(
            "did not reach", reason,
            f"the reason is the budget-exhausted message, which is for a target that is slow -- "
            f"and this target is not slow, its image is wrong: {reason}",
        )
        # And terminal, not merely reported differently: one read. A wait that
        # spent its budget here would cost 120 seconds to say something it knew
        # on the first read.
        self.assertEqual(
            len([argv for argv in fake.invocations()
                 if argv[:4] == ["exec", TARGET, "systemctl", "is-active"]
                 and NM_SETUP_UNIT in argv]),
            1,
            "the wait kept reading after learning the target has no such unit, which will never "
            "become true",
        )

    def test_a_unit_that_finishes_late_is_waited_for_rather_than_refused(self):
        """The control for the case above: `activating` then `active` must pass.

        A gate that refused the *first* non-`inactive` reading would turn this
        case green by being a race-detector rather than a wait -- and would then
        fail every healthy target, because a healthy target's unit is `activating`
        for the first second or two of its life. So the sequence is the one the
        cases above omit: still activating, then active, and the cell proceeds.
        """
        fake = self.fake(self.rules_for(
            unit_answers=["activating", "activating", "active"], managed_answers=["yes"]))
        code, output, _ = self.cell(fake)
        self.assertEqual(code, run.EXIT_OK, output)

    def test_the_unit_wait_and_the_field_wait_are_both_ordered_unit_first(self):
        """The ordering, read off the invocation log rather than inferred.

        Every other case here asserts an outcome. This one asserts the sequence
        itself, so a future edit that hoists the field check back above the unit
        check fails here even if the outcomes still happen to come out right --
        which is exactly the regression that produced the flake, and the reason
        the flake was invisible for a whole task.
        """
        fake = self.fake(self.rules_for(unit_answers=["active"], managed_answers=["yes"]))
        self.cell(fake)
        first_unit = next(
            index for index, argv in enumerate(fake.invocations())
            if argv[:4] == ["exec", TARGET, "systemctl", "is-active"]
            and NM_SETUP_UNIT in argv
        )
        first_field = next(
            index for index, argv in enumerate(fake.invocations())
            if argv[2:5] == ["nmcli", "-g", "GENERAL.NM-MANAGED"]
        )
        self.assertLess(
            first_unit, first_field,
            "the managed-device field is consulted before the setup unit that owns it has "
            "finished; a target can read 'yes' mid-restart, which is the race this gate exists "
            "to close",
        )


class CellCompositionTest(EntryPoint):
    """The network, the router and the target, with the plan's addresses."""

    def cell(self, fake, *, version="24.04", scenario="dhcp"):
        results = self.directory / "results"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", version,
                      *([ "--scenario", scenario] if scenario else []))
        )
        return code, output, results

    def test_the_private_network_is_the_plans_subnet(self):
        fake = self.passing_fake()
        self.cell(fake)
        created = [argv for argv in fake.invocations() if argv[:2] == ["network", "create"]]
        self.assertEqual(created, [["network", "create", "--subnet", SUBNET, f"mosdns-{RUN_ID}-testnet"]])

    def test_the_router_and_the_target_take_the_plans_fixed_addresses(self):
        """Both `--ip` values, because podman would otherwise hand out `.2` twice.

        The mock router is created first and takes the first free address in the
        pool, so a target left to its own devices would be given the router's
        address and the DHCP exchange would be a target talking to itself. The
        plan names all four addresses and the cell uses the two it starts.
        """
        fake = self.passing_fake()
        self.cell(fake)
        started = {
            argv[argv.index("--name") + 1]: argv[argv.index("--ip") + 1]
            for argv in fake.invocations()
            if argv[:2] == ["run", "-d"] and "--ip" in argv
        }
        self.assertEqual(started, {
            f"mosdns-{RUN_ID}-mock-router-24.04": MOCK_ROUTER_ADDRESS,
            f"mosdns-{RUN_ID}-target-24.04": TARGET_ADDRESS,
        })

    def test_the_router_is_started_with_the_two_capabilities_dnsmasq_measures_as_necessary(self):
        """**A shared array handed dnsmasq two capabilities it cannot run without,
        and two it has never used.**

        `run_container` builds one argument array and both containers went through
        it, so the router was started with the target's whole set: `SYS_ADMIN`,
        `NET_ADMIN`, `SYS_PTRACE`, `NET_RAW`. dnsmasq runs no init and is not
        traced, so the first and third are not its business. The second and fourth
        are, and this case says which -- because the answer is not guessable from
        the outside, and getting it wrong fails **on the other container**:

        * with all four (the old shared array) the router ran, DHCP worked, and two
          of the four were never used;
        * with **none**, the router exits 5 with `dnsmasq: process is missing
          required capability NET_ADMIN`, and the *target* then fails with `IP
          configuration could not be reserved` -- a message three steps from the
          container that was under-privileged, reading exactly like a network
          fault. That is measured: the first version of this case asserted an empty
          set, on the argument that dnsmasq "opens no raw socket", and the live
          24.04 cell refuted it.

        So the assertion is the exact two-flag list -- not "not all four", which the
        old defect would pass, and not "none", which only shows up as a DHCP
        timeout. The target's four are asserted in the same breath, so a fix that
        emptied both containers would not pass a case about the router alone.
        """
        fake = self.passing_fake()
        self.cell(fake)
        granted = {
            argv[argv.index("--name") + 1]: [
                token for token in argv if token.startswith("--cap-add=")
            ]
            for argv in fake.invocations() if argv[:2] == ["run", "-d"]
        }
        self.assertEqual(
            granted.get(f"mosdns-{RUN_ID}-mock-router-24.04"),
            ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"],
            "the mock router's capabilities are not the measured two. dnsmasq opens an "
            "AF_PACKET socket to receive the broadcast DISCOVER and exits 5 with 'process is "
            "missing required capability NET_ADMIN' without NET_ADMIN; it runs no init and is "
            "not traced, so SYS_ADMIN and SYS_PTRACE are not its business either",
        )
        self.assertEqual(
            granted.get(f"mosdns-{RUN_ID}-target-24.04"),
            ["--cap-add=SYS_ADMIN", "--cap-add=NET_ADMIN", "--cap-add=SYS_PTRACE", "--cap-add=NET_RAW"],
            "the target lost a capability it was measured to need, so a DHCP lease would fail "
            "with 'IP configuration could not be reserved'",
        )

    def test_the_router_and_the_target_do_not_share_one_capability_set(self):
        """The structural half, and the one that cannot go stale.

        The exact list in the case above is a measurement, so it is right until a
        release changes it. This is the property that made the measurement
        necessary in the first place: both containers are started through the
        *same* function, and before the capabilities became a parameter they
        necessarily got the same answer. So this asserts the two sets differ --
        which holds for any two containers with different needs, and fails the
        moment somebody collapses them back into one array.
        """
        self.assertNotEqual(
            CONTAINER_CAPS["mock-router"], CONTAINER_CAPS["target"],
            "both roles resolve to the same set again, so the per-container policy has been "
            "collapsed back into the shared array this was written to stop",
        )
        self.assertLess(
            set(CONTAINER_CAPS["mock-router"]), set(CONTAINER_CAPS["target"]),
            "the router is not granted strictly less than the target, so the shared array is "
            "back in force",
        )

    def test_every_container_the_cell_starts_is_named_from_this_runs_prefix(self):
        fake = self.passing_fake()
        self.cell(fake)
        started = [
            argv[argv.index("--name") + 1]
            for argv in fake.invocations() if argv[:2] == ["run", "-d"]
        ]
        self.assertTrue(started)
        for name in started:
            with self.subTest(container=name):
                # The version is part of the name -- three versions run at once
                # and a name has to say which -- so the character class allows the
                # dot of `24.04` while still refusing anything with a path in it.
                self.assertRegex(name, rf"^mosdns-{RUN_ID}-[a-z0-9.-]+$")

    def test_the_router_is_removed_on_the_way_out_like_the_target_is(self):
        """A router the cell does not tear down is a router the next run inherits.

        `cleanup` sweeps by prefix, so a container the cell started and did not
        record *is* swept -- but only if it carries the prefix, and only if the
        cell's own teardown reaches it. The target's teardown is asserted
        elsewhere; this is the same claim for the second container.
        """
        fake = self.passing_fake()
        self.cell(fake)
        removed = [argv[-1] for argv in fake.invocations() if argv[:2] == ["rm", "-f"]]
        self.assertIn(f"mosdns-{RUN_ID}-mock-router-24.04", removed)
        self.assertIn(f"mosdns-{RUN_ID}-target-24.04", removed)
        stopped = [argv[-1] for argv in fake.invocations() if argv[:1] == ["stop"]]
        self.assertIn(f"mosdns-{RUN_ID}-mock-router-24.04", stopped)

    def test_the_router_runs_on_the_private_bridge_and_not_on_a_published_port(self):
        """`--network <the run's net>` and no `-p`/`--publish`, which the guard refuses anyway.

        The two are the same claim from two sides: the router is reachable only
        on the run's own bridge, and there is no flag that could make it
        reachable from the host -- where port 53 belongs to the operator's
        resolved.
        """
        fake = self.passing_fake()
        self.cell(fake)
        for argv in fake.invocations():
            if argv[:2] != ["run", "-d"]:
                continue
            name = argv[argv.index("--name") + 1]
            if "mock-router" not in name:
                continue
            self.assertEqual(argv[argv.index("--network") + 1], f"mosdns-{RUN_ID}-testnet")
            for flag in ("-p", "--publish", "-P", "--publish-all"):
                self.assertNotIn(flag, argv)

    def test_the_target_image_is_built_from_the_locked_reference(self):
        """The digest in the lock reaches the build, and it reaches it as an argument.

        `images.lock.json` exists so that two runs of the matrix are the same
        three images. A build given `ubuntu:24.04` would be a floating tag, and
        a build given `localhost/mosdns-target:24.04` would be an image nothing
        in the repository accounts for -- the lock would be a comment. Both
        images are checked, and each build names the Containerfile it came from.
        """
        fake = self.passing_fake()
        self.cell(fake)
        builds = [argv for argv in fake.invocations() if argv[:1] == ["build"]]
        self.assertEqual(len(builds), len(images.IMAGE_ROLES), f"one build per image expected: {builds}")
        reference = images.reference_for_version("24.04")
        for build in builds:
            with self.subTest(build=build[build.index("--tag") + 1]):
                self.assertIn(f"BASE_IMAGE={reference}", build)
                self.assertIn("--build-arg", build)
                self.assertIn("--file", build)
                self.assertTrue(
                    any(
                        str(images.containerfile(role)) == build[build.index("--file") + 1]
                        for role in images.IMAGE_ROLES
                    ),
                    f"a build was asked for a Containerfile that is not one of the plan's: {build!r}",
                )
        # And the context is the checkout, because the Containerfiles COPY paths
        # from the repository root -- a build whose context was the image
        # directory would fail on the last step, after installing a systemd.
        for build in builds:
            self.assertEqual(build[-1], str(REPO))


class ImageTagTest(unittest.TestCase):
    """The tag is the cache key, so it has to change when the build would."""

    def test_the_tag_carries_the_version_and_a_hash_of_what_it_built(self):
        reference = images.reference_for_version("24.04")
        tag = images.image_tag("target", "24.04", reference)
        self.assertTrue(tag.startswith("mosdns-target:24.04-"))
        self.assertRegex(tag, r"^mosdns-target:24\.04-[0-9a-f]{12}$")

    def test_the_tag_changes_when_the_base_reference_changes(self):
        """A different digest is a different image, and the tag has to say so.

        Without this, a run against a rebuilt base would silently reuse the image
        built from the previous one -- which is the exact failure the lock
        exists to prevent, reintroduced through the cache. The digest is edited
        where it actually is rather than by a `replace` that would quietly match
        nothing and make the case green on a tag that cannot change.
        """
        reference = images.reference_for_version("24.04")
        first = images.image_tag("target", "24.04", reference)
        head, _, tail = reference.partition("sha256:")
        flipped = tail[0] + ("0" if tail[0] != "0" else "1") + tail[1:]
        second = images.image_tag("target", "24.04", f"{head}sha256:{flipped}")
        self.assertNotEqual(reference, f"{head}sha256:{flipped}")
        self.assertNotEqual(first, second)

    def test_the_tag_changes_when_the_containerfile_changes(self):
        """The build's own input is part of the key, or a stale image is what runs.

        A contributor who edits `mock-router.Containerfile` has changed what
        `podman build` would produce, and a tag derived from the version alone
        would make the next run use the image built from the previous file.
        """
        containerfile = images.containerfile("mock-router")
        original = containerfile.read_bytes()
        self.addCleanup(containerfile.write_bytes, original)
        before = images.image_tag("mock-router", "24.04", images.reference_for_version("24.04"))
        containerfile.write_bytes(original + b"\n# an edit the tag has to notice\n")
        after = images.image_tag("mock-router", "24.04", images.reference_for_version("24.04"))
        self.assertNotEqual(before, after)

    def test_the_tag_changes_when_a_copied_file_changes(self):
        """The `COPY` case, and it is the one that bit a live run.

        `mock-router.Containerfile` copies `tests/podman/mock-router/dnsmasq.conf`
        in, and that file is the whole of the router's configuration. A tag
        derived from the Containerfile alone does not move when the config does,
        so a run after an edit to the config reuses the image built before it.

        **Measured, in Task 8's container run.** The mock router was given an
        `address=` line so a machine whose resolvers had been restored could
        actually resolve, the config changed, the tag did not, and the live run
        kept reporting `a query for install-probe.example through 127.0.0.53 did
        not resolve` -- which reads as a defect in the watchdog under test and is
        a stale image. A guard that only watched the Containerfile would have
        stayed green through it, exactly as the previous version of this class
        did.
        """
        config = REPO / "tests" / "podman" / "mock-router" / "dnsmasq.conf"
        original = config.read_bytes()
        self.addCleanup(config.write_bytes, original)
        before = images.image_tag("mock-router", "24.04", images.reference_for_version("24.04"))
        config.write_bytes(original + b"\n# an edit the tag has to notice\n")
        after = images.image_tag("mock-router", "24.04", images.reference_for_version("24.04"))
        self.assertNotEqual(
            before, after,
            "a file the Containerfile copies in is not in the tag, so editing it reuses the image "
            "built from the previous contents",
        )

    def test_every_copied_file_is_read_out_of_the_containerfile_and_not_a_glob(self):
        """The copies are the `COPY` lines, and a file nothing copies cannot move the tag.

        Two directions, and both are mistakes. A tag that moved for a file the
        build does not read would rebuild the image for nothing, on every edit to
        anything in the directory; a tag that missed a file the build DOES read is
        the stale-image defect the case above is about.

        **Two kinds of `COPY` are not build-context sources, and reading them as
        ones is this case's own defect rather than a Containerfile's.** It was
        found by the foreign mock's Containerfile, which is the first of these
        images with a second stage:

        * `COPY --from=build /out/mock-foreign /usr/local/bin/mock-foreign` names a
          path inside a *previous stage*, not a file the context supplies, and a
          tag cannot hash it. `images.copied_sources` skips such a line; if this
          case did not, the two would disagree by construction and the case would
          be asserting that the tag carries something the context does not contain.
        * `COPY . .` names the context ROOT, which is a directory. The tag hashes
          the *files* the build copies, and the whole checkout arriving in one
          `COPY` is exactly the case `copied_sources` returns no file for -- so the
          honest statement about that line is the next case's, not this one's.

        So the assertion here is over the sources the function under test reports,
        and what it checks is the direction that matters: every source it reports
        really is named in a `COPY` line. The other direction -- a file a `COPY`
        names and the tag omits -- is checked by the mutation in
        `test_the_tag_changes_when_a_copied_file_changes`, which moves the tag when
        a copied file's bytes change and so cannot pass if the file is not in the
        key.
        """
        for role in images.IMAGE_ROLES:
            with self.subTest(role=role):
                containerfile = images.containerfile(role)
                copied = [
                    str(path.relative_to(REPO))
                    for path in images.copied_sources(containerfile)
                ]
                text = containerfile.read_text(encoding="utf-8")
                for source in copied:
                    with self.subTest(source=source):
                        self.assertRegex(
                            text,
                            rf"(?mi)^\s*COPY\s+[^\n]*\b{re.escape(source)}\b",
                            f"{role} reports {source} as a copied source and the Containerfile "
                            f"has no COPY line naming it, so `copied_sources` and the file it "
                            f"reads have drifted apart",
                        )
                # And the control, which is the half that catches a glob: a file
                # that is in the checkout and named in no `COPY` line is NOT in
                # the list. `Makefile` is the right subject because it exists in the
                # repository root, beside every one of these Containerfiles, and
                # none of them copies it -- so a reader that walked the directory
                # would report it, and this one does not.
                self.assertTrue(
                    (REPO / "Makefile").is_file(),
                    "the control subject is not in the checkout, so the control proves nothing",
                )
                self.assertNotIn(
                    "Makefile", copied,
                    f"{role}'s copied sources include the Makefile, and the Makefile is in the "
                    f"context but named in no COPY line -- so this is reading the directory rather "
                    f"than the Containerfile, which is the defect this case exists to catch",
                )

    def test_every_copied_file_is_inside_the_build_context(self):
        """A `COPY` from outside the repository cannot be in the tag, and is not.

        The context is the repository root, so a path above it or a URL is a
        source the tag cannot hash. None of the three Containerfiles has one, and
        a case that held it is cheaper than a stale image nobody can explain --
        so the check is here rather than in a comment that says "don't".
        """
        for role in images.IMAGE_ROLES:
            with self.subTest(role=role):
                for path in images.copied_sources(images.containerfile(role)):
                    self.assertTrue(
                        str(path).startswith(str(REPO) + "/"),
                        f"{role} copies {path}, which is outside the build context, so its "
                        "contents cannot be part of the tag and an edit to it reuses a stale image",
                    )
                    self.assertTrue(
                        path.is_file(),
                        f"{role} copies {path}, which is not a file, so the build would fail and "
                        "the tag would name an image that cannot be built",
                    )

    def test_the_tag_is_the_same_for_the_same_inputs(self):
        reference = images.reference_for_version("24.04")
        self.assertEqual(
            images.image_tag("target", "24.04", reference),
            images.image_tag("target", "24.04", reference),
            "the tag is not reproducible, so every run would rebuild the same image",
        )

    def test_a_tag_refuses_a_role_with_no_containerfile(self):
        for role in ("", "cdn", "router", "target "):
            with self.subTest(role=role):
                with self.assertRaises(images.LockError):
                    images.image_tag(role, "24.04", images.reference_for_version("24.04"))


class ScenarioSkipTest(EntryPoint):
    """A scenario that could not close a requirement makes the cell incomplete.

    The `install` scenario is the case this is about, and it is why the field
    exists. It proves the property Task 4 Step 1 delivered and it cannot prove
    the one the plan first wrote -- the transaction reaching `install ok
    configured` -- because the foreign chain is a DNSCrypt server on the
    internet. Three dispositions were available and two of them are wrong:

    * `failed`, which is a red run for a reason that is not a defect, and it is
      what the scenario used to do on every cell;
    * `passed` with the open requirement written into `detail`, which is a skip
      reported as a pass -- the thing the plan's constraints forbid twice;
    * `passed` with a **required skip**, which is the honest one: the scenario
      did what it was written to do, the cell is `incomplete`, and the run is
      exit 3.
    """

    SKIP = Skip(
        requirement="with no route to the internet the transaction reaches `install ok configured`",
        reason="the foreign chain is a DNSCrypt server on the internet",
    )

    def cell(self, *, skip=None, status="passed", second=None):
        """One cell whose `install` scenario records `skip` and passes."""
        fake = self.passing_fake()
        outcomes = [("install", lambda: ScenarioResult("install", status, detail="d", skips=(skip,) if skip else ()))]
        if second is not None:
            outcomes.append((second[0], lambda: second[1]))
        built = run.run_target(
            self.client(fake),
            RUN_ID,
            "amd64",
            "24.04",
            "localhost/mosdns-target:24.04",
            outcomes,
        )
        return built, [line.splitlines()[0] for line in self.invoke_output(built)]

    def invoke_output(self, built):
        # The terminal lines `command_matrix` prints, produced here from the
        # result so the case reads the same shape the operator reads.
        lines = [f"  amd64/24.04: {built.status}"]
        for scenario_result in built.scenarios:
            if scenario_result.status != "passed" and scenario_result.detail:
                lines.append(f"      {scenario_result.name}: {scenario_result.detail.splitlines()[0]}")
        for skip in built.skips:
            lines.append(f"      not closed: {skip.reason}")
        return lines

    def test_a_scenario_skip_lands_on_the_version(self):
        built, _lines = self.cell(skip=self.SKIP)
        self.assertEqual([s.requirement for s in built.skips], [self.SKIP.requirement])
        self.assertTrue(built.skips[0].required, "an optional skip is a nicety, and this is not one")

    def test_a_scenario_skip_leaves_the_cell_incomplete_and_the_run_at_three(self):
        built, _lines = self.cell(skip=self.SKIP)
        self.assertEqual(built.status, "incomplete")
        self.assertEqual(
            Report(
                run_id=RUN_ID,
                arch="amd64",
                started_utc="2026-09-30T00:00:00Z",
                finished_utc="2026-09-30T00:01:00Z",
                podman_version="5.7.0",
                store_driver="overlay",
                results=(built,),
            ).exit_code,
            3,
        )

    def test_a_scenario_skip_is_printed_as_not_closed(self):
        _built, lines = self.cell(skip=self.SKIP)
        self.assertIn(f"      not closed: {self.SKIP.reason}", lines)

    def test_a_scenario_with_no_skip_passes_the_cell(self):
        built, lines = self.cell()
        self.assertEqual(built.status, "passed")
        self.assertEqual(built.skips, ())
        self.assertNotIn("not closed:", "\n".join(lines))

    def test_a_skip_from_a_failed_scenario_is_hoisted_too(self):
        # The evidence is still evidence: a scenario that recorded a requirement
        # it could not close and then failed on a later assertion has not closed
        # it, and dropping the record on the strength of the failure would make
        # the failure hide the skip.
        built, _lines = self.cell(skip=self.SKIP, status="failed")
        self.assertEqual([s.requirement for s in built.skips], [self.SKIP.requirement])
        self.assertEqual(built.status, "failed")

    def test_a_scenario_that_raises_records_no_skip(self):
        # The exception path builds its own ScenarioResult, and a cell whose
        # first scenario crashed is `failed` on that alone -- there is nothing
        # from that scenario to hoist.
        fake = self.passing_fake()

        def boom():
            raise RuntimeError("the scenario crashed")

        built = run.run_target(
            self.client(fake), RUN_ID, "amd64", "24.04",
            "localhost/mosdns-target:24.04", [("install", boom)],
        )
        self.assertEqual(built.skips, ())
        self.assertEqual(built.status, "failed")


class ContributorPageAgreesWithTheRun(unittest.TestCase):
    """`docs/testing.md` is tracked, and it is the page a contributor reads.

    Four sentences on it described a harness this tree no longer has, and all four
    failed the same way: a reader who believed one of them went looking for a
    thing that is not there. That is the defect the project's own convention
    already holds this file for once -- `test_images.py` requires the page to
    carry a specific claim about the NM declaration -- so this is the same shape,
    for the four sentences that were stale.

    * **The watchdog section gave a stale reason as a measurement.** It printed
      dpkg's output refusing at the Cloudflare prefix list and concluded "a
      container on this bridge has no route off it, so the publish cannot happen".
      Task 4 Step 1 ended that: the transaction publishes the package's pinned
      snapshot with no network at all (`ranges-source: pinned-snapshot`, exit 0),
      and what refuses in a cell with no route is the **resolver's own start-up
      barrier**. A reader sent to the range origin goes hunting for a network
      fault this cell does not have.
    * **The same section called `watchdog` the only scenario that installs the
      package.** `install` installs it too, and `install` is in the *default* set,
      so a flag-free `matrix` runs two package-installing scenarios.
    * **The harness section said `matrix` "exits 0 or 1"** -- contradicted by the
      four-code list two lines under it -- and gave exit 3 exactly two causes,
      neither of which is a scenario's required skip. A contributor who runs the
      documented default command, gets 3, and finds no listed cause is in exactly
      the position to file a required requirement as a nicety.
    * **The "Adding a scenario" contract listed `status` and `log`** and not
      `skips`, which is the instrument the third of those is made of: a scenario
      that proves what it can and cannot prove the rest reports the open
      requirement as a skip, and a scenario author reading this page would have
      put it in `detail` -- a skip reported as prose.

    **Checked against the code, not against a paraphrase of the page.** The
    package set, the default set and `ScenarioResult`'s fields are read here, so
    the case fails if either side moves: a page that is right about a registry
    that has changed is still a page that is wrong, and a code change that
    invalidates the page's claim has to be a failing case rather than a sentence
    nobody re-reads. Deferring prose is defensible; a tracked page held by a test
    is what this project has already decided on.
    """

    PAGE = REPO / "docs/testing.md"
    HARNESS = "## The system-level harness"
    WATCHDOG = "## The resolver watchdog scenario"
    REFUSAL = "### What the cell does not prove"
    ADDING = "## Adding a scenario"

    def setUp(self):
        self.page = self.PAGE.read_text(encoding="utf-8")

    def section(self, heading: str) -> str:
        """The one section of the page a claim is about, cut at the next heading.

        A substring of the whole page would let a sentence in a *different*
        section satisfy a claim about this one, which is the same defect as a
        refusal that names a sequence the code does not run.
        """
        self.assertIn(heading, self.page, f"the page has no {heading!r} section to check")
        body = self.page[self.page.index(heading) + len(heading):]
        ends = [body.index(line) for line in ("\n## ", "\n### ") if line in body]
        return body[: min(ends)] if ends else body

    def test_the_page_names_the_barrier_that_refused_and_not_the_range_origin(self):
        # -- the refusal's reason, which was a stale measurement ---------------
        refusal = self.section(self.REFUSAL)
        self.assertIn(
            "nothing answered a DNS query at", refusal,
            "the page does not give the barrier the transaction actually refused at. The cell's "
            "own words are 'dnscrypt-proxy.service was started but nothing answered a DNS query "
            "at 127.0.0.1:15353 within 60s', and that is the measurement",
        )
        self.assertIn(
            "127.0.0.1:15353", refusal,
            "the resolver's own port is not named, so a reader cannot tell the resolver's "
            "start-up barrier from any other refusal",
        )
        # **And the range origin is not the reason it gives.** This is the
        # assertion that makes the sentence load-bearing: the pinned snapshot
        # publishes with no route, so a page that names the origin sends the
        # reader to a fault the cell does not have.
        self.assertNotIn(
            "api.cloudflare.com", refusal,
            "the page still states, as the measured reason a cell's transaction refuses, that "
            "the Cloudflare prefix list cannot be published. Task 4 Step 1 ended that: the "
            "transaction publishes the package's pinned snapshot with no route at all",
        )
        self.assertIn(
            "ranges-source: pinned-snapshot", refusal,
            "the page does not say the cell publishes the pin from the shipped snapshot, which "
            "is the half of the claim that makes the resolver the barrier",
        )

        # -- the set of scenarios that install the package ---------------------
        self.assertIn(
            "install", run.SCENARIO_NAMES,
            "the `install` scenario is no longer registered, so the watchdog section's account "
            "of the package set has to be written again",
        )
        self.assertIn(
            "install", run.PACKAGE_SCENARIOS,
            "`install` installs the package, so it belongs in the set the page names; without "
            "it a flag-free `matrix` would run exactly one package-installing scenario",
        )
        # The falsifiable consequence: the default set really does install the
        # package, so "the only scenario that installs the package" cannot be
        # true of a run with no `--scenario`.
        self.assertTrue(
            set(run.SCENARIO_NAMES) & set(run.PACKAGE_SCENARIOS),
            f"the default set is {run.SCENARIO_NAMES} and the package set is "
            f"{run.PACKAGE_SCENARIOS}; a flag-free run installs the package only while the two "
            "overlap, and the page claims a flag-free run installs it twice",
        )
        watchdog = self.section(self.WATCHDOG)
        self.assertNotIn(
            "the only scenario that **installs the package**", watchdog,
            "the watchdog section still calls itself the only scenario that installs the "
            f"package, while {sorted(set(run.SCENARIO_NAMES) & set(run.PACKAGE_SCENARIOS))} are "
            "in the default set and in the package set",
        )
        for name in run.PACKAGE_SCENARIOS:
            self.assertIn(
                f"`{name}`", watchdog,
                f"the watchdog section does not name `{name}`, which is one of the scenarios that "
                "install the package, so a contributor reading it cannot see the whole set",
            )

        # -- exit 3's causes, and the number a flag-free run returns -----------
        harness = self.section(self.HARNESS)
        self.assertNotIn(
            "exits 0 or 1", harness,
            "the page still says `matrix` exits 0 or 1, which its own four-code list two lines "
            "under it contradicts",
        )
        third = re.search(r"^- `3` — (.+?)(?=\n- `|\n\n)", harness, re.M | re.S)
        self.assertIsNotNone(third, "the page does not list what exit 3 means")
        self.assertIn(
            "required skip", third.group(1),
            "exit 3's causes do not include a scenario's required skip, which is the cause the "
            "default set produces on every cell: `install` proves the property and records the "
            "one requirement it cannot close",
        )
        self.assertIn(
            "flag-free `matrix`", harness,
            "the page does not say what a run with no `--scenario` returns, and 3 is what it "
            "returns -- a reader who is not told so looks for a failure that is not there",
        )
        self.assertIn(
            "Task 4 Step 5", harness,
            "the page does not say which step makes 3 go away, so the number reads as permanent",
        )

        # -- the contract a scenario module is handed -------------------------
        adding = self.section(self.ADDING)
        self.assertIn(
            "skips=", adding,
            "the contract for a returned `ScenarioResult` names `status` and `log` and not "
            "`skips`, so a scenario author has no way to learn that an unclosed requirement "
            "belongs on the result rather than in `detail`",
        )
        # And the field is really there, and really optional.
        self.assertEqual(
            ScenarioResult("install", "passed").skips, (),
            "`ScenarioResult` no longer defaults `skips` to empty, so the page's contract is not "
            "just incomplete -- a scenario that returns none of it cannot be constructed",
        )


class NamespaceAndGateTest(unittest.TestCase):
    """Two things that are not this task's to add, and are held anyway.

    * **Every resource carries the prefix.** A container named by hand is one
      `cleanup` does not find, and the next run inherits it.
    * **`test-system` is not wired into `make verify`.** The plan says a
      system-level run belongs to a release gate rather than to a hermetic unit
      gate, and Task 7 is the task that adds the target. Nothing in this task
      touches the Makefile, so these cases are what stop Task 7 from closing the
      loop by accident.
    """

    def test_the_naming_helper_produces_a_name_cleanup_can_sweep(self):
        run_resources = RunResources(run.Podman(executable="/bin/true"), RUN_ID)
        for name in (
            run_resources.container_name("mock-router", "24.04"),
            run_resources.container_name("target", "24.04"),
            run_resources.network_name("testnet"),
            run_resources.volume_name("state"),
        ):
            with self.subTest(name=name):
                self.assertTrue(name.startswith(f"mosdns-{RUN_ID}-"))

    def test_verify_does_not_run_the_podman_matrix(self):
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        verify = re.search(r"^verify:(.*)$", makefile, re.MULTILINE)
        self.assertIsNotNone(verify, "the Makefile has no verify target")
        prerequisites = verify.group(1).split()
        self.assertNotIn(
            "test-system", prerequisites,
            "the system-level Podman matrix is wired into `make verify`, which the plan forbids: it "
            "is a release gate, and verify is meant to stay fast and hermetic",
        )

    def test_no_make_recipe_runs_the_podman_harness(self):
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn(
            "tests/podman/run.py", makefile,
            "a Makefile recipe runs the Podman harness; nothing in this task adds one, and the one "
            "that will (`test-system`) belongs to Task 7 and not to `verify`",
        )

    def test_the_harness_refuses_a_resource_name_outside_its_namespace(self):
        """The prefix is the mechanism, so a name that lacks it is a name nobody can sweep.

        `RunResources.container_name` composes from the run id rather than
        accepting a name, and these are the two spellings a later task would
        reach for instead.
        """
        run_resources = RunResources(run.Podman(executable="/bin/true"), RUN_ID)
        self.assertFalse(run_resources.container_name("target", "24.04").startswith("mosdns--"))
        self.assertNotEqual(
            RunResources(run.Podman(executable="/bin/true"), "other-run").container_name("target", "24.04"),
            run_resources.container_name("target", "24.04"),
        )


if __name__ == "__main__":
    unittest.main()
