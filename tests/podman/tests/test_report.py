"""Hold the harness's report to what a report is for.

The report is the artifact a release decision is read from, and the plan's
review focus names the two ways it can lie:

* **A skip must not read as a pass.** The plan's own words are that a skip is
  never reported as a pass, a required skip makes the matrix `incomplete`, and
  a skipped architecture is exit 3. A version that ran every scenario and also
  recorded a requirement it could not close is the exact case where a report
  that only looked at the scenario list would say `passed`.
* **The document must be stable and must not carry a secret.** A report is
  compared against the previous one and archived, so the same run twice has to
  produce the same bytes, and a field that did not exist last month must be a
  visible change rather than a silent addition. A report is also the one file
  that leaves this machine, so a whole command environment or a password in a
  connection URI cannot be in it.

The status vocabulary is the plan's: `passed`, `failed`, `skipped`,
`incomplete`, and the exit codes are 0, 1, 2 and 3. Nothing here starts
anything, and nothing here reads this machine.
"""

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tests" / "podman" / "lib"))

from report import (  # noqa: E402
    EXIT_HARNESS_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
    EXIT_TEST_FAILURE,
    SCHEMA,
    ScenarioResult,
    Skip,
    VersionResult,
    Report,
    redact,
)

# A minimal report, written out in full so the serialised bytes can be compared
# against a golden document. Everything volatile -- the run id, the two
# timestamps -- is supplied rather than read from a clock, so the comparison is
# a comparison of the document and not of the run.
MINIMAL = Report(
    run_id="20260928T101010Z",
    arch="amd64",
    started_utc="2026-09-28T10:10:10Z",
    finished_utc="2026-09-28T10:11:40Z",
    podman_version="5.7.0",
    store_driver="overlay",
    results=(VersionResult(version="24.04", arch="amd64", recorded="passed"),),
)

MINIMAL_GOLDEN = """\
{
  "arch": "amd64",
  "finished_utc": "2026-09-28T10:11:40Z",
  "harness_error": null,
  "podman": {
    "connection": null,
    "store_driver": "overlay",
    "version": "5.7.0"
  },
  "results": [
    {
      "arch": "amd64",
      "detail": null,
      "scenarios": [],
      "skips": [],
      "status": "passed",
      "version": "24.04"
    }
  ],
  "run_id": "20260928T101010Z",
  "schema": "mosdns-podman-report/1",
  "started_utc": "2026-09-28T10:10:10Z",
  "status": "passed"
}
"""


def version(name, recorded=None, scenarios=(), skips=(), detail=None, arch="amd64"):
    return VersionResult(
        version=name,
        arch=arch,
        scenarios=tuple(scenarios),
        skips=tuple(skips),
        detail=detail,
        recorded=recorded,
    )


def scenario(name, status, detail=None, log=None):
    return ScenarioResult(name=name, status=status, detail=detail, log=log)


def report(results, **kwargs):
    fields = {
        "run_id": "20260928T101010Z",
        "arch": "amd64",
        "started_utc": "2026-09-28T10:10:10Z",
        "finished_utc": "2026-09-28T10:11:40Z",
        "podman_version": "5.7.0",
        "store_driver": "overlay",
        "results": tuple(results),
    }
    fields.update(kwargs)
    return Report(**fields)


class StatusVocabularyTest(unittest.TestCase):
    """Four statuses, and no fifth."""

    def test_each_status_in_the_plan_is_accepted_for_a_version_and_a_scenario(self):
        for status in ("passed", "failed", "skipped", "incomplete"):
            with self.subTest(status=status):
                built = version("24.04", recorded=status)
                self.assertEqual(built.status, status)
                self.assertEqual(scenario("dhcp", status).status, status)

    def test_a_status_outside_the_vocabulary_is_refused(self):
        """`flaky` and `mostly-passed` are how a skip becomes a pass.

        A vocabulary that grows a word outside the plan's four is the mechanism
        by which an unclosed requirement gets a comfortable label, so the
        constructor refuses rather than passing it through.
        """
        for status in ("flaky", "mostly-passed", "PASSED", "", "pass"):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    version("24.04", recorded=status)
                with self.assertRaises(ValueError):
                    scenario("dhcp", status)

    def test_a_version_status_is_always_readable_even_when_nothing_ran(self):
        """`status` is derived, so there is no state where it is unset.

        A stored optional status that reads back as `None` is a value a caller
        can compare against `passed` and get a wrong answer from a version
        where nothing ran at all.
        """
        self.assertIn(version("24.04").status, ("passed", "failed", "skipped", "incomplete"))
        self.assertIsNotNone(version("24.04").status)


class DerivedStatusTest(unittest.TestCase):
    """A version's status follows from what happened, or it is not a pass.

    A version that ran no scenario has proved nothing. That is the whole
    argument for deriving the status rather than letting a caller supply
    `passed`, and it is the case a report most needs to get right because it
    looks like success.
    """

    def test_a_version_with_no_scenarios_is_incomplete_not_passed(self):
        self.assertEqual(version("24.04").status, "incomplete")

    def test_every_scenario_passing_passes_the_version(self):
        built = version("24.04", scenarios=[scenario("dhcp", "passed"), scenario("routing", "passed")])
        self.assertEqual(built.status, "passed")

    def test_one_failing_scenario_fails_the_version(self):
        built = version("24.04", scenarios=[scenario("dhcp", "passed"), scenario("routing", "failed")])
        self.assertEqual(built.status, "failed")

    def test_a_skipped_scenario_leaves_the_version_incomplete(self):
        built = version("24.04", scenarios=[scenario("dhcp", "passed"), scenario("ech", "skipped")])
        self.assertEqual(built.status, "incomplete")

    def test_a_recorded_status_overrides_the_derivation(self):
        """A target that never started has a reason, and the reason is the status.

        `skipped` with a detail is the honest shape for "this host cannot run
        that architecture", and forcing it through the scenario list would mean
        inventing a scenario that did not run.
        """
        built = version("26.04", recorded="skipped", detail="no digest is locked for 26.04")
        self.assertEqual(built.status, "skipped")
        self.assertEqual(built.detail, "no digest is locked for 26.04")

    def test_a_required_skip_keeps_an_otherwise_passing_version_incomplete(self):
        """The case the plan names: a skip attached to a green version.

        Everything the version could run did run and pass, and one requirement
        it could not close was recorded. Reading only the scenario list makes
        this a pass, which is precisely the reporting failure the plan forbids.
        """
        built = version(
            "24.04",
            scenarios=[scenario("dhcp", "passed")],
            skips=[Skip(requirement="nmcli field names on 24.04", reason="device unmanaged", required=True)],
        )
        self.assertEqual(built.status, "incomplete")

    def test_an_optional_skip_does_not_change_a_passing_version(self):
        built = version(
            "24.04",
            scenarios=[scenario("dhcp", "passed")],
            skips=[Skip(requirement="a nicety", reason="not attempted", required=False)],
        )
        self.assertEqual(built.status, "passed")


class OverallStatusTest(unittest.TestCase):
    """The run's status and its exit code.

    These are the numbers a release gate reads, so they are pinned here rather
    than only through a command line: 0 all requested passed, 1 a test failure,
    2 a harness or configuration error, 3 an incomplete matrix.
    """

    def test_all_versions_passing_gives_zero(self):
        built = report([version("22.04", scenarios=[scenario("dhcp", "passed")]),
                        version("24.04", scenarios=[scenario("dhcp", "passed")])])
        self.assertEqual(built.status, "passed")
        self.assertEqual(built.exit_code, EXIT_OK)

    def test_any_failing_version_gives_one(self):
        built = report([version("22.04", scenarios=[scenario("dhcp", "passed")]),
                        version("24.04", scenarios=[scenario("dhcp", "failed")])])
        self.assertEqual(built.status, "failed")
        self.assertEqual(built.exit_code, EXIT_TEST_FAILURE)

    def test_a_failure_outranks_an_incomplete_version(self):
        """A red run is reported as red, not softened into "incomplete".

        The order matters because the two are not the same claim: incomplete
        says some of the work did not happen, failed says some of it went
        wrong. Collapsing them would let a red run be filed as an unfinished
        one.
        """
        built = report([version("22.04", scenarios=[scenario("dhcp", "failed")]),
                        version("24.04", recorded="skipped")])
        self.assertEqual(built.status, "failed")
        self.assertEqual(built.exit_code, EXIT_TEST_FAILURE)

    def test_a_skipped_architecture_gives_three_and_never_zero(self):
        """The ruling: a skipped arm64 is exit 3, never 0."""
        built = report(
            [version("22.04", arch="amd64", scenarios=[scenario("dhcp", "passed")]),
             version("22.04", arch="arm64", recorded="skipped",
                     detail="no native arm64 Podman service on this host")]
        )
        self.assertEqual(built.status, "incomplete")
        self.assertEqual(built.exit_code, EXIT_INCOMPLETE)

    def test_a_required_skip_anywhere_gives_three(self):
        built = report(
            [version("22.04", scenarios=[scenario("dhcp", "passed")]),
             version("24.04", scenarios=[scenario("dhcp", "passed")],
                     skips=[Skip(requirement="live ECH", reason="no operator hostname", required=True)])]
        )
        self.assertEqual(built.status, "incomplete")
        self.assertEqual(built.exit_code, EXIT_INCOMPLETE)

    def test_a_run_with_no_versions_at_all_is_incomplete(self):
        built = report([])
        self.assertEqual(built.status, "incomplete")
        self.assertEqual(built.exit_code, EXIT_INCOMPLETE)

    def test_a_harness_error_gives_two_and_outranks_everything(self):
        """Exit 2 is "this was not a result", which is not the same as a red one.

        A run that could not find Podman, or could not read a locked digest,
        produced no evidence at all. Reporting it as `failed` would say the
        package is broken; reporting it as `passed` would say it works.
        """
        built = report([], harness_error="podman is not installed")
        self.assertEqual(built.exit_code, EXIT_HARNESS_ERROR)

    def test_a_harness_error_beside_a_failing_version_is_still_two(self):
        built = report([version("22.04", scenarios=[scenario("dhcp", "failed")])],
                       harness_error="could not write the result directory")
        self.assertEqual(built.exit_code, EXIT_HARNESS_ERROR)

    def test_the_exit_codes_are_the_plan_s_four_numbers(self):
        self.assertEqual(
            (EXIT_OK, EXIT_TEST_FAILURE, EXIT_HARNESS_ERROR, EXIT_INCOMPLETE),
            (0, 1, 2, 3),
        )


class SkipRecordingTest(unittest.TestCase):
    """A skip names the requirement in its exact wording and why it is open.

    The plan's constraint is that a requirement a container cannot close is
    recorded SKIPPED with its exact wording, and never closed by substituting a
    different kind of test. A skip that does not carry the requirement's own
    text cannot be checked against the requirement later.
    """

    def test_a_skip_records_the_requirement_and_the_reason(self):
        built = version("22.04", recorded="skipped", skips=[
            Skip(requirement="nmcli -g GENERAL.NM-MANAGED device show eth0 is yes", reason="measured unmanaged")
        ])
        self.assertEqual(built.skips[0].requirement, "nmcli -g GENERAL.NM-MANAGED device show eth0 is yes")
        self.assertEqual(built.skips[0].reason, "measured unmanaged")

    def test_a_skip_with_no_requirement_wording_is_refused(self):
        with self.assertRaises(ValueError):
            Skip(requirement="", reason="something")

    def test_a_skip_with_no_reason_is_refused(self):
        with self.assertRaises(ValueError):
            Skip(requirement="a real requirement", reason="")

    def test_the_skip_reaches_the_document(self):
        built = report([version("22.04", recorded="skipped", skips=[
            Skip(requirement="arm64 systemd-resolved layout", reason="no native arm64 service")
        ])])
        document = built.to_dict()
        self.assertEqual(
            document["results"][0]["skips"],
            [{"reason": "no native arm64 service", "required": True, "requirement": "arm64 systemd-resolved layout"}],
        )


class LogAttachmentTest(unittest.TestCase):
    """Every scenario that ran has a log, and the path is relative.

    The plan's review focus: a failed scenario must still publish its logs.
    So the log is a field on the scenario rather than something a caller has to
    remember to attach, and it is a path relative to the run's result
    directory -- an absolute path would make the archived report useless on any
    other machine and would leak the operator's directory layout.
    """

    def test_a_scenario_carries_its_log_path(self):
        built = report([version("24.04", scenarios=[
            scenario("dhcp", "failed", detail="IP4.DNS never contained the mock address", log="logs/24.04-dhcp.log")
        ])])
        self.assertEqual(built.to_dict()["results"][0]["scenarios"][0]["log"], "logs/24.04-dhcp.log")

    def test_an_absolute_log_path_is_refused(self):
        with self.assertRaises(ValueError):
            scenario("dhcp", "failed", log="/home/ubuntu/build/test-results/x/logs/dhcp.log")

    def test_a_log_path_that_climbs_out_of_the_run_directory_is_refused(self):
        with self.assertRaises(ValueError):
            scenario("dhcp", "failed", log="../../../etc/shadow")

    def test_the_document_records_every_scenario_in_the_order_it_ran(self):
        built = report([version("24.04", scenarios=[
            scenario("install", "passed", log="logs/24.04-install.log"),
            scenario("routing", "failed", log="logs/24.04-routing.log"),
            scenario("failure", "passed", log="logs/24.04-failure.log"),
        ])])
        names = [entry["name"] for entry in built.to_dict()["results"][0]["scenarios"]]
        self.assertEqual(names, ["install", "routing", "failure"])


class DocumentStabilityTest(unittest.TestCase):
    """The serialised document is a stable artifact, not a debug dump."""

    def test_a_minimal_report_matches_its_golden_bytes(self):
        self.assertEqual(MINIMAL.to_json(), MINIMAL_GOLDEN)

    def test_the_schema_identifier_is_in_the_document(self):
        """A report compared against an older one has to say which it is."""
        self.assertEqual(json.loads(MINIMAL.to_json())["schema"], SCHEMA)
        self.assertEqual(SCHEMA, "mosdns-podman-report/1")

    def test_two_builds_of_the_same_run_produce_the_same_bytes(self):
        first = report([version("22.04", scenarios=[scenario("dhcp", "passed")]),
                        version("24.04", scenarios=[scenario("dhcp", "failed")])])
        second = report([version("22.04", scenarios=[scenario("dhcp", "passed")]),
                         version("24.04", scenarios=[scenario("dhcp", "failed")])])
        self.assertEqual(first.to_json(), second.to_json())

    def test_the_order_versions_were_recorded_in_does_not_reach_the_document(self):
        """A scenario order is the run's; a version order is the matrix's.

        Two runs that recorded 24.04 before 22.04 for their own reasons produce
        the same matrix, and a byte comparison of the two documents has to
        agree or every comparison needs a normaliser nobody applies.
        """
        forwards = report([version("22.04", scenarios=[scenario("dhcp", "passed")]),
                           version("24.04", scenarios=[scenario("dhcp", "passed")])])
        backwards = report([version("24.04", scenarios=[scenario("dhcp", "passed")]),
                            version("22.04", scenarios=[scenario("dhcp", "passed")])])
        self.assertEqual(forwards.to_json(), backwards.to_json())
        self.assertEqual([r["version"] for r in json.loads(forwards.to_json())["results"]], ["22.04", "24.04"])

    def test_two_architectures_of_the_same_version_keep_a_stable_order(self):
        built = report([version("22.04", arch="arm64", scenarios=[scenario("dhcp", "passed")]),
                        version("22.04", arch="amd64", scenarios=[scenario("dhcp", "passed")])])
        self.assertEqual(
            [(r["arch"], r["version"]) for r in json.loads(built.to_json())["results"]],
            [("amd64", "22.04"), ("arm64", "22.04")],
        )

    def test_the_document_has_exactly_these_top_level_keys(self):
        self.assertEqual(
            sorted(MINIMAL.to_dict()),
            ["arch", "finished_utc", "harness_error", "podman", "results", "run_id", "schema", "started_utc", "status"],
        )

    def test_the_document_has_exactly_these_keys_per_version(self):
        self.assertEqual(
            sorted(MINIMAL.to_dict()["results"][0]),
            ["arch", "detail", "scenarios", "skips", "status", "version"],
        )

    def test_the_document_has_exactly_these_keys_per_scenario(self):
        built = report([version("24.04", scenarios=[
            scenario("dhcp", "passed", detail="eth0 was managed and DHCP supplied 10.89.0.2", log="logs/dhcp.log")
        ])])
        self.assertEqual(
            sorted(built.to_dict()["results"][0]["scenarios"][0]),
            ["detail", "log", "name", "status"],
        )

    def test_the_document_has_exactly_these_keys_for_podman(self):
        self.assertEqual(sorted(MINIMAL.to_dict()["podman"]), ["connection", "store_driver", "version"])

    def test_every_value_survives_the_round_trip(self):
        built = report([
            version("22.04", scenarios=[scenario("dhcp", "failed", detail="nmcli said no", log="logs/a.log")],
                    skips=[Skip(requirement="a requirement", reason="a reason")]),
            version("26.04", recorded="skipped", detail="no image"),
        ], connection="ssh://builder@arm64.example/run/user/1000/podman/podman.sock")
        self.assertEqual(json.loads(built.to_json()), built.to_dict())

    def test_the_document_is_parsed_back_with_no_extra_or_missing_values(self):
        document = json.loads(MINIMAL.to_json())
        self.assertEqual(document["podman"], {"connection": None, "store_driver": "overlay", "version": "5.7.0"})
        self.assertIsNone(document["harness_error"])


class SecretRedactionTest(unittest.TestCase):
    """A report is the one file that leaves this machine.

    Two mechanisms hold that, and both are needed. The schema has no field for
    a command environment at all, so a whole environment cannot be recorded
    even by accident. And text that arrives from a command -- a log line, a
    failure detail, a connection URI -- is scrubbed, because a Podman service
    URI can carry a password and a command's own diagnostics can carry one too.
    """

    def test_the_document_has_nowhere_to_put_a_command_environment(self):
        """A field that does not exist is the strongest guarantee there is."""
        self.assertNotIn("env", MINIMAL.to_json())
        self.assertNotIn("environment", MINIMAL.to_json())
        self.assertNotIn("command_env", MINIMAL.to_json())

    def test_a_password_in_a_connection_uri_is_scrubbed(self):
        built = report([], connection="ssh://builder:hunter2@arm64.example/run/podman/podman.sock")
        self.assertNotIn("hunter2", built.to_json())
        self.assertIn("ssh://builder:***@arm64.example", built.to_json())

    def test_a_connection_uri_without_a_password_is_left_alone(self):
        built = report([], connection="ssh://builder@arm64.example/run/podman/podman.sock")
        self.assertIn("ssh://builder@arm64.example/run/podman/podman.sock", built.to_json())

    def test_a_password_named_in_a_failure_detail_is_scrubbed(self):
        built = report([version("24.04", scenarios=[
            scenario("install", "failed", detail="dpkg failed: PASSWORD=hunter2 for the mock router")
        ])])
        self.assertNotIn("hunter2", built.to_json())
        self.assertIn("PASSWORD=***", built.to_json())

    def test_a_bearer_token_in_a_detail_is_scrubbed(self):
        built = report([version("24.04", scenarios=[
            scenario("cdn-ech", "failed", detail="Authorization: Bearer ya29.a0AfH6SMBxxxx rejected")
        ])])
        self.assertNotIn("ya29.a0AfH6SMBxxxx", built.to_json())

    def test_a_run_id_or_version_is_not_mistaken_for_a_secret(self):
        """Redaction that eats ordinary text makes a report unreadable.

        `22.04`, `24.04` and a run id all look like opaque tokens, and a
        document whose versions had been replaced by `***` would be a document
        nobody can read.
        """
        built = report([version("22.04", scenarios=[scenario("dhcp", "passed")])], run_id="20260928T101010Z")
        self.assertIn('"version": "22.04"', built.to_json())
        self.assertIn('"run_id": "20260928T101010Z"', built.to_json())

    def test_the_scrubber_leaves_an_ordinary_sentence_alone(self):
        self.assertEqual(
            redact("the mock router answered 10.89.0.2 and eth0 came up as ethernet"),
            "the mock router answered 10.89.0.2 and eth0 came up as ethernet",
        )

    def test_a_detail_that_merely_names_a_key_word_is_not_scrubbed(self):
        """`secret` in prose is not a secret, and blanking it loses the reason."""
        self.assertEqual(
            redact("the ECH source timeout is a known upstream secret-store outage"),
            "the ECH source timeout is a known upstream secret-store outage",
        )

    def test_the_scrubbed_value_is_the_same_one_everywhere(self):
        built = report([
            version("22.04", scenarios=[scenario("a", "failed", detail="token=abc123")]),
            version("24.04", scenarios=[scenario("b", "failed", detail="token=abc123")]),
        ])
        self.assertEqual(built.to_json().count("token=***"), 2)
