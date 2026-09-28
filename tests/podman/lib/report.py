"""The machine-readable record of a matrix run.

A report is read two ways: by a person deciding whether a release may ship, and
by a comparison against the last one. Both readings are why the rules in here
are what they are.

* **A skip is never a pass.** The plan's constraints say it three times -- a
  requirement a container cannot close is recorded SKIPPED with its exact
  wording, a skip is never reported as a pass, and a skipped architecture is
  exit 3. So a version's status is *derived* from what happened inside it, a
  version with no scenarios is `incomplete` rather than `passed`, and a version
  that recorded a required skip cannot be `passed` however green its scenarios
  are.
* **The document is stable.** A fixed key set, sorted results, and a schema
  identifier, so two runs of the same thing are byte-comparable and a field that
  appears is a visible change rather than a silent one.
* **Nothing secret is recorded.** There is no field for a command environment,
  so a whole environment cannot leak even by accident, and text that arrives
  from a command is scrubbed on the way in -- a Podman service URI can carry a
  password and a command's own diagnostics can carry one.

The four statuses and the four exit codes are the plan's, not this module's:
``passed``, ``failed``, ``skipped``, ``incomplete`` and 0, 1, 2, 3.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# The identifier that says which shape this document is. A report compared
# against an older one has to be able to say it is not the same shape.
SCHEMA = "mosdns-podman-report/1"

STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_INCOMPLETE = "incomplete"
STATUSES = frozenset({STATUS_PASSED, STATUS_FAILED, STATUS_SKIPPED, STATUS_INCOMPLETE})

# 0 all requested tests passed; 1 a test failure; 2 a harness or configuration
# error; 3 an incomplete matrix or a skipped required architecture.
EXIT_OK = 0
EXIT_TEST_FAILURE = 1
EXIT_HARNESS_ERROR = 2
EXIT_INCOMPLETE = 3

REDACTED = "***"

# The words that make a following value a secret. Matched case-insensitively as
# a whole word so that prose mentioning "secret" is not blanked out -- a report
# whose reasons have been replaced by asterisks cannot be acted on.
_SECRET_WORD = (
    r"pass(?:word|wd)|secret|token|api[-_]?key|private[-_]?key|credential|authorization|bearer"
)
# `NAME=value` and `NAME: value`, where NAME is a secret word followed by any
# word characters. The separator must be `=` or `:` and the value stops at
# whitespace and at the punctuation that ends a log line, so a sentence keeps
# its sentence -- "a known upstream secret-store outage" is prose, not a value.
_ASSIGNMENT = re.compile(
    r"\b((?:" + _SECRET_WORD + r")[-_]?\w*)\s*([:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s;,)\]}]+)",
    re.IGNORECASE,
)
# A command line's own spelling: the value follows the option by whitespace, so
# it needs its own rule rather than a whitespace separator in the rule above.
_OPTION_VALUE = re.compile(
    r"(--(?:password|passwd|secret|token|api[-_]?key|private[-_]?key|credential))(\s+)(\S+)",
    re.IGNORECASE,
)
# A URL's own password, in `scheme://user:password@host`. The connection URI is
# the one field in a run that routinely carries a credential, and it is
# operator-supplied, so it is exactly the kind of value a report must not keep.
_USERINFO = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^/@\s:]+):(?P<password>[^/@\s]+)@")
_AUTHORIZATION = re.compile(r"\b(Authorization\s*:\s*)(?P<value>Bearer\s+\S+|\S+)", re.IGNORECASE)


def redact(text: str) -> str:
    """Remove credential-shaped values from text that came from a command.

    Deliberately narrow. A scrubber that ate ordinary prose would replace the
    reasons a run was skipped with asterisks, and a report nobody can read is
    not a safer report.
    """
    if not text:
        return text
    scrubbed = _USERINFO.sub(lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}@", text)
    scrubbed = _OPTION_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", scrubbed)
    # The whole `Bearer <token>` is consumed here, before the assignment rule
    # gets a chance to stop at the space after `Bearer` and leave the token.
    scrubbed = _AUTHORIZATION.sub(lambda m: f"{m.group(1)}{REDACTED}", scrubbed)
    scrubbed = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", scrubbed)
    return scrubbed


def _check_status(status: str, what: str) -> str:
    if status not in STATUSES:
        raise ValueError(
            f"{what} status must be one of {sorted(STATUSES)}, not {status!r}: a status "
            f"outside that set is how an unclosed requirement gets a comfortable label"
        )
    return status


def _check_relative_log(log: str) -> str:
    """A log path is relative to the run's own result directory.

    An absolute path makes an archived report useless on any other machine and
    publishes the operator's directory layout; a `..` makes it point at
    something outside the run entirely, which is where a secret would be.
    """
    if not log or log.startswith("/"):
        raise ValueError(f"a log path is relative to the run's result directory, not absolute: {log!r}")
    parts = log.replace("\\", "/").split("/")
    if ".." in parts:
        raise ValueError(f"a log path may not climb out of the run's result directory: {log!r}")
    return log


@dataclass(frozen=True)
class Skip:
    """A requirement this run did not close, in the requirement's own words.

    The wording is not decoration. The plan requires a skip to carry the exact
    text of what was not closed so that a later reader can check the claim
    against the requirement rather than against a summary of it.
    """

    requirement: str
    reason: str
    required: bool = True

    def __post_init__(self):
        if not self.requirement.strip():
            raise ValueError("a skip must carry the exact wording of the requirement it did not close")
        if not self.reason.strip():
            raise ValueError(f"a skip of {self.requirement!r} must say why it is open")

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": redact(self.reason),
            "required": self.required,
            "requirement": self.requirement,
        }


@dataclass(frozen=True)
class ScenarioResult:
    """One scenario's outcome, and the log that explains it."""

    name: str
    status: str
    detail: str | None = None
    log: str | None = None

    def __post_init__(self):
        _check_status(self.status, "scenario")
        if self.log is not None:
            _check_relative_log(self.log)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detail": redact(self.detail) if self.detail is not None else None,
            "log": self.log,
            "name": self.name,
            "status": self.status,
        }


@dataclass(frozen=True)
class VersionResult:
    """One (architecture, version) cell of the matrix.

    `status` is a property and is always derived. A caller that is handed a
    field to fill in will fill it in with `passed`; deriving it is the only
    thing that notices a version where nothing ran, or where a required skip
    sat under a green scenario list. `recorded` is the escape hatch for the
    cases the derivation cannot express -- a target whose image would not
    build, an architecture this host cannot run natively -- and it has a
    different name so that reading `status` can never return a missing value.
    """

    version: str
    arch: str
    scenarios: tuple[ScenarioResult, ...] = ()
    skips: tuple[Skip, ...] = ()
    detail: str | None = None
    recorded: str | None = None

    def __post_init__(self):
        if self.recorded is not None:
            _check_status(self.recorded, "version")
        for scenario in self.scenarios:
            if not isinstance(scenario, ScenarioResult):
                raise TypeError(f"a scenario must be a ScenarioResult, not {scenario!r}")
        for skip in self.skips:
            if not isinstance(skip, Skip):
                raise TypeError(f"a skip must be a Skip, not {skip!r}")
        object.__setattr__(self, "scenarios", tuple(self.scenarios))
        object.__setattr__(self, "skips", tuple(self.skips))

    @property
    def status(self) -> str:
        if self.recorded is not None:
            return self.recorded
        if any(s.status == STATUS_FAILED for s in self.scenarios):
            return STATUS_FAILED
        if any(s.status != STATUS_PASSED for s in self.scenarios):
            return STATUS_INCOMPLETE
        if self.scenarios and not any(skip.required for skip in self.skips):
            return STATUS_PASSED
        return STATUS_INCOMPLETE

    def to_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "detail": redact(self.detail) if self.detail is not None else None,
            "scenarios": [scenario.to_dict() for scenario in self.scenarios],
            "skips": [skip.to_dict() for skip in self.skips],
            "status": self.status,
            "version": self.version,
        }


@dataclass(frozen=True)
class Report:
    """A whole run, and the number a release gate reads off it."""

    run_id: str
    arch: str
    started_utc: str
    finished_utc: str
    podman_version: str
    store_driver: str
    results: tuple[VersionResult, ...] = ()
    connection: str | None = None
    harness_error: str | None = None

    def __post_init__(self):
        for result in self.results:
            if not isinstance(result, VersionResult):
                raise TypeError(f"a result must be a VersionResult, not {result!r}")
        object.__setattr__(self, "results", tuple(self.results))

    @property
    def status(self) -> str:
        """The run's own status.

        A failure outranks an incomplete cell, because the two are different
        claims: incomplete says some of the work did not happen, failed says
        some of it went wrong. Collapsing them lets a red run be filed as an
        unfinished one.
        """
        statuses = [result.status for result in self.results]
        if STATUS_FAILED in statuses:
            return STATUS_FAILED
        if not statuses or any(status != STATUS_PASSED for status in statuses):
            return STATUS_INCOMPLETE
        return STATUS_PASSED

    @property
    def exit_code(self) -> int:
        """0, 1, 2 or 3 -- and never 0 for a skipped architecture."""
        if self.harness_error is not None:
            return EXIT_HARNESS_ERROR
        status = self.status
        if status == STATUS_PASSED:
            return EXIT_OK
        if status == STATUS_FAILED:
            return EXIT_TEST_FAILURE
        return EXIT_INCOMPLETE

    def to_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "finished_utc": self.finished_utc,
            "harness_error": redact(self.harness_error) if self.harness_error is not None else None,
            "podman": {
                "connection": redact(self.connection) if self.connection is not None else None,
                "store_driver": self.store_driver,
                "version": self.podman_version,
            },
            "results": [
                result.to_dict()
                for result in sorted(self.results, key=lambda r: (r.arch, _version_sort_key(r.version)))
            ],
            "run_id": self.run_id,
            "schema": SCHEMA,
            "started_utc": self.started_utc,
            "status": self.status,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _version_sort_key(version: str) -> tuple:
    """Sort a version numerically where it looks numeric.

    `sorted()` on the string would put `26.04` before `9.10`, and the matrix is
    read in release order.
    """
    match = re.match(r"^(\d+)\.(\d+)$", version)
    if match:
        return (0, int(match.group(1)), int(match.group(2)), "")
    return (1, 0, 0, version)
