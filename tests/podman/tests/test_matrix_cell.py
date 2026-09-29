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
from podman import RunResources  # noqa: E402

_spec = importlib.util.spec_from_file_location("mosdns_matrix_cell_run", HARNESS / "run.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

PodmanTestCase = test_command.PodmanTestCase

RUN_ID = test_dhcp_scenario.RUN_ID
ROUTER = test_dhcp_scenario.ROUTER
TARGET = test_dhcp_scenario.TARGET
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
            (rules if rules is not None else [])
            + [
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
            ]
            + test_dhcp_scenario.cell_rules()
        )


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
        """
        fake = self.passing_fake()
        results = self.directory / "results"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04")
        )
        self.assertEqual(code, run.EXIT_OK, output)

    def test_a_scenario_that_is_not_registered_is_refused_with_its_name(self):
        """Exit 2, the name, and the names that would have worked.

        The refusal is a configuration error rather than a cell that did not run:
        `--scenario` is the flag the plan's own acceptance command passes, and
        silently ignoring it made that command report "no scenario is registered"
        -- which reads as though the harness looked for `dhcp` and did not find
        it, when in fact it never looked.
        """
        fake = self.passing_fake()
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04", "--scenario", "routing")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("routing", output)
        self.assertIn("dhcp", output)
        self.assertEqual(
            [argv for argv in fake.invocations() if argv[:1] == ["run"]], [],
            "a refused scenario still started a container",
        )

    def test_a_refusal_names_every_requested_scenario_not_only_the_first(self):
        """`--scenario` is repeatable, and a caller who mistyped one of three is told so."""
        fake = self.passing_fake()
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"), "--run-id", RUN_ID,
                      "matrix", "--arch", "amd64", "--versions", "24.04",
                      "--scenario", "dhcp", "--scenario", "routing", "--scenario", "install")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        for name in ("routing", "install"):
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
