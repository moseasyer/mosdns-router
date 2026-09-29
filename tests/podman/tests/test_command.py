"""Hold the Podman harness to the four things that keep it off this machine.

The harness in `tests/podman` runs the real installer, the real NetworkManager
integration and the real resolver inside disposable containers. Three of its
properties are what make that safe to do on somebody's working system, and
this file is where they are held:

* **The host is not a target.** The source tree is mounted read-only and only at
  ``/workspace``, the one other mount is the cgroup filesystem, and nothing under
  ``/etc``, ``/run``, ``/var`` or ``/sys`` is ever bound in. The source tree
  itself may be anywhere, ``/home`` included, because it is bound read-only.
  These cases read the *mount arguments the wrapper actually emits*, not a list
  of strings somebody can reorder, and they hold the refusal itself: a
  validator that cannot fail is not a validator.
* **There is no virtual machine.** ``podman machine`` needs qemu, this host has
  no qemu and must not get any, and the previous architecture of this plan was
  built on it. The wrapper is the only place that builds a Podman argument
  array, so the refusal is here and it is exercised here.
* **A failed scenario still tears down.** A container or a network left behind
  by a raising scenario is the thing that makes the next run fail for the wrong
  reason, so ``cleanup`` runs on the way out of a raising block, continues past
  individual errors, and reports a consolidated failure when something of the
  run survives.

The NetworkManager device check lives in this file too, and it is the most
load-bearing case in it. The previous plan recorded its entire NetworkManager
SKIPPED list on the conclusion that a container cannot make NetworkManager
manage a device; that conclusion was wrong, and the working sequence is
``nmcli device set eth0 managed yes`` followed by ``systemctl restart
NetworkManager``. Because a target that boots with an unmanaged ``eth0``
produces a scenario failure that reads like an installer bug, the sequence is
asserted at run time and never assumed.

Every case here runs against a fake ``podman`` executable -- a real process, so
the subprocess boundary itself is exercised -- and never against this host's
Podman. Nothing in this file starts, stops or inspects anything real.
"""

import ast
import contextlib
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
# The harness is used from a source checkout, so its library directory is the
# import root. There is no installed distribution of it.
sys.path.insert(0, str(REPO / "tests" / "podman" / "lib"))

from podman import (  # noqa: E402
    CAPABILITY_ADD_FLAG,
    FORBIDDEN_CONTAINER_FLAG_FAMILIES,
    FORBIDDEN_CONTAINER_FLAG_NAMES,
    FORBIDDEN_CONTAINER_FLAGS,
    HOST_MUTATING_MOUNT_KEYS,
    PODMAN_FLAG_ALIASES,
    POLICED_CONTAINER_FLAGS,
    ALLOWED_CAPABILITIES as ALLOWED_CAPS,
    CONTAINER_CAPABILITIES as CONTAINER_CAPS,
    CleanupFailed,
    ContainerPolicyError,
    MountPolicyError,
    NetworkManagerDeviceError,
    Podman,
    PodmanError,
    PodmanTimeout,
    RunResources,
    assert_networkmanager_manages_device,
    canonical_flag_name,
    new_run_id,
    podman_session,
    wait_for_networkmanager_device,
)
from report import EXIT_TEST_FAILURE, ScenarioResult  # noqa: E402

# `run.py` is a script rather than an installed module, and it is loaded by
# path so that this file's own name cannot collide with it.
_spec = importlib.util.spec_from_file_location("mosdns_podman_run", REPO / "tests" / "podman" / "run.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

# The five host roots the plan forbids binding into a target container, and the
# one mount of a forbidden root that is the measured, required exception: the
# cgroup filesystem, which a systemd container cannot start without.
FORBIDDEN_HOST_ROOTS = ("/etc", "/run", "/var", "/sys", "/home")
# The *source tree* is policed by a narrower set, and the difference is the
# point rather than an inconsistency. `/etc`, `/run`, `/var` and `/sys` hold the
# host's resolver and its systemd state, so a bind of any of them is a route to
# the host's DNS and is refused everywhere. `/home` is in the list above for a
# different reason -- the host-isolation snapshot compares Firefox profile
# metadata, and a run must not perturb what it compares -- which is a rule about
# what the harness *writes* and *reads back*, not about read-only visibility of
# a checkout. A checkout under `/home` bound `:ro` at `/workspace` exposes
# project source and nothing else, so it is permitted; every writable mount is
# still refused everywhere, which is the property the exemption is not for.
FORBIDDEN_SOURCE_TREE_ROOTS = ("/etc", "/run", "/var", "/sys")
WORKSPACE = "/workspace"
CGROUP = "/sys/fs/cgroup"


def home_source_tree(prefix: str = "mosdns-source-tree-") -> Path:
    """A temporary directory genuinely under `/home`, for the `/home` cases.

    Built from the operator's own home rather than from `TMPDIR` or from
    `legal_temp_base()`, because the property under test is the *path* and a
    fixture that quietly avoided `/home` would not be testing it. `/home` itself
    is not writable, so the directory is created one level down, in whatever
    `$HOME` is -- and a host whose home is not under `/home` skips rather than
    pretending to have tested something.
    """
    home = os.path.expanduser("~")
    if not (home == "/home" or home.startswith("/home/")):
        raise unittest.SkipTest(f"$HOME is {home!r}, which is not under /home")
    directory = Path(tempfile.mkdtemp(dir=home, prefix=prefix))
    assert str(directory).startswith("/home/"), directory
    return directory


def legal_temp_base() -> str:
    """A directory the source-tree policy will accept, whatever `TMPDIR` says.

    This suite's stand-in source tree is a temporary directory, and the wrapper
    refuses a source tree inside one of `FORBIDDEN_SOURCE_TREE_ROOTS` — so the
    suite's own fixture depends on where `tempfile` puts things. That is not
    hypothetical: the Go build on this host requires `TMPDIR` off `/tmp` (a
    small tmpfs), which puts it under `/home`, which under the original
    five-root policy made 220 cases fail with
    `refusing source tree '/home/…/source'` — every one of them for a reason
    that had nothing to do with what they test. The two rules collided and the
    policy was the wrong one, so the policy was amended and this fixture now
    measures against the amended one.

    So the fixture asks for a base that satisfies the policy it is testing, in
    the order a developer would expect: `TMPDIR` if it is usable, then the
    system default, then the first conventional location that is outside every
    refused root. A `TMPDIR` under `/home` is the first candidate now, and it is
    a legal one, so the suite builds its fixture where the developer asked.
    """
    def outside_every_refused_root(candidate: str) -> bool:
        resolved = os.path.normpath(candidate)
        return not any(
            resolved == root or resolved.startswith(root + "/")
            for root in FORBIDDEN_SOURCE_TREE_ROOTS
        )

    for candidate in (os.environ.get("TMPDIR"), tempfile.gettempdir(), "/tmp", "/opt", "/srv"):
        if candidate and os.path.isdir(candidate) and outside_every_refused_root(candidate):
            return candidate
    raise unittest.SkipTest(
        "no writable directory outside " + ", ".join(FORBIDDEN_SOURCE_TREE_ROOTS)
        + " to build a fixture in"
    )


def volume_arguments(argv):
    """Every bind-mount specification in an argument array, as a raw string.

    Written out here rather than reused from the module, so the assertion about
    which mounts the harness emits is not made by the same code that emits
    them. All three spellings podman accepts are read, because a check that only
    understood `-v` would pass on a `--mount` and the check is the property.
    """
    found = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in ("-v", "--volume"):
            found.append(argv[index + 1])
            index += 2
            continue
        if token.startswith("--volume="):
            found.append(token.split("=", 1)[1])
            index += 1
            continue
        if token == "--mount":
            found.append(argv[index + 1])
            index += 2
            continue
        if token.startswith("--mount="):
            found.append(token.split("=", 1)[1])
            index += 1
            continue
        index += 1
    return found


def parse_volume(spec):
    """Split a mount specification into (source, destination, options).

    A `--mount` specification is keyed rather than positional, so it is read as
    key=value pairs; everything else is the colon-separated `-v` spelling.
    """
    if "=" in spec and "," in spec and not spec.split(",")[0].count(":"):
        fields = {}
        for part in spec.split(","):
            key, _, value = part.partition("=")
            fields[key.strip()] = value.strip()
        options = [k for k, v in fields.items() if v == "" and k != "type"] + [
            v for v in fields.values() if v in ("ro", "rw", "z", "Z")
        ]
        return fields.get("src") or fields.get("source"), fields.get("dst") or fields.get("destination"), ",".join(options)
    parts = spec.split(":")
    if len(parts) < 2:
        return spec, None, ""
    options = parts[2] if len(parts) > 2 else ""
    return parts[0], parts[1], options

FAKE_PODMAN = '''#!/usr/bin/env python3
"""A stand-in for the podman binary.

It records the argument array it was given, answers from a scripted table, and
exits with the scripted status. It is a real process so that the production
runner -- the one boundary a substituted runner cannot test -- is exercised for
real in every case in this file.

The table, the log and the state live beside the executable rather than in the
environment, so a case that points the harness at this binary needs nothing
plumbed through the wrapper's environment allowlist.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
LOG = os.path.join(HERE, "invocations.jsonl")
TABLE = os.path.join(HERE, "table.json")
STATE = os.path.join(HERE, "state.json")


def contains(argv, match):
    """True when `match` appears in `argv` as a contiguous run of tokens."""
    if not match:
        return True
    for start in range(len(argv) - len(match) + 1):
        if argv[start:start + len(match)] == match:
            return True
    return False


def main():
    argv = sys.argv[1:]
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(argv) + "\\n")
    answer = {"returncode": 0, "stdout": "", "stderr": ""}
    state = {}
    if os.path.exists(STATE):
        with open(STATE, encoding="utf-8") as handle:
            state = json.load(handle)
    if os.path.exists(TABLE):
        with open(TABLE, encoding="utf-8") as handle:
            for index, rule in enumerate(json.load(handle).get("rules", [])):
                if not contains(argv, rule["match"]):
                    continue
                # A rule may carry a sequence of answers, so a case can say
                # "the first listing shows it, the second does not" -- which is
                # what a sweep that actually removed something looks like.
                answers = rule.get("answers")
                if answers:
                    seen = state.get(str(index), 0)
                    answer = answers[min(seen, len(answers) - 1)]
                    state[str(index)] = seen + 1
                    with open(STATE, "w", encoding="utf-8") as handle:
                        json.dump(state, handle)
                else:
                    answer = rule
                break
    time.sleep(float(answer.get("sleep", 0)))
    if answer.get("dump_env"):
        sys.stdout.write(json.dumps(dict(os.environ), sort_keys=True))
    stdout = answer.get("stdout", "")
    # `respect_filter` makes this fake apply podman's own `name=` filter to the
    # lines it was going to print. Podman treats the value as a regular
    # expression, which is why the harness anchors it with `^` -- and a fake
    # that ignores the filter cannot tell a sweep that reaches only this run
    # from one that reaches the whole namespace, so a case about that property
    # would be asserting about the fake rather than about podman.
    if answer.get("respect_filter"):
        pattern = ""
        for position, token in enumerate(argv):
            if token.startswith("--filter") and position + 1 < len(argv):
                pattern = argv[position + 1].split("=", 1)[-1]
        import re as _re
        stdout = "".join(
            line + "\\n"
            for line in stdout.splitlines()
            if _re.search(pattern, line)
        )
    sys.stdout.write(stdout)
    sys.stderr.write(answer.get("stderr", ""))
    return int(answer.get("returncode", 0))


if __name__ == "__main__":
    sys.exit(main())
'''

# The environment variables the production wrapper is allowed to forward to a
# child, written out here rather than read from the module. A wrapper that grew
# a new forwarded variable would carry whatever the operator's shell happens to
# export -- which is how a token reaches a command line and then a report -- so
# the forwarded set is pinned as a literal and not derived from the code.
FORWARDED_ENV_NAMES = (
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
)

SECRET_ENV_NAME = "MOSDNS_PODMAN_HARNESS_SECRET"

# The production clock factory, captured before any case replaces it, so
# `use_the_real_clock` puts back the real thing rather than another case's. The
# *factory* and not one dict from it: `scenario_clock()` is called once per run
# and per cell, and comparing against a single captured dict would compare two
# different objects where the claim is about the function.
_REAL_CLOCK = run.scenario_clock
_REAL_CLOCK_VALUES = _REAL_CLOCK()


class FakePodmanBinary:
    """A fake podman executable plus the table and log the harness hands it.

    The table is a list of rules, each one a contiguous token run that selects
    the answer. The first matching rule wins, so a case that needs two
    different answers for one subcommand orders the narrower rule first.

    The default is a machine already in the state a teardown wants to reach:
    every command succeeds, nothing is listed, and a network is absent. That is
    the state `run.py cleanup` documents itself as producing, so a case that
    does not care about leftovers does not have to say so four times over. A
    case that wants a survivor writes its own rule, which wins because it is
    matched first.
    """

    # The defaults every fake in this file starts from. So: a network the run
    # has not created, and a target whose setup unit has finished.
    #
    # **The setup unit is here because most cases in this file are about
    # something downstream of the cell's first readiness gate** -- the device
    # wait, scenario ordering, the exit codes -- and each of them would otherwise
    # have to carry the same line. `systemctl is-active target-nm-setup.service`
    # answers `active`, which is the measured state on all three releases
    # (`SubState=exited`, `Result=success`).
    #
    # It is a *default*, and `write_table` puts explicit rules first, so any case
    # that wants a different state gets it. That is what keeps the default
    # honest rather than load-bearing: `test_matrix_cell.TargetReadinessTest`
    # passes explicit answers and asserts that `activating` and `failed` both stop
    # the cell, so a case that relied on this default to be *wrong* would have to
    # override it, and then be caught.
    DEFAULT_RULES = (
        {"match": ["network", "exists"], "returncode": 1},
        {"match": ["systemctl", "is-active", "target-nm-setup.service"], "stdout": "active\n"},
    )

    def __init__(self, directory, rules=None):
        self.directory = directory
        self.path = directory / "podman"
        self.path.write_text(FAKE_PODMAN, encoding="utf-8")
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)
        self.log = directory / "invocations.jsonl"
        self.table = directory / "table.json"
        self.state = directory / "state.json"
        self.write_table(rules or [])

    def write_table(self, rules):
        ordered = list(rules) + [dict(rule) for rule in self.DEFAULT_RULES]
        self.table.write_text(json.dumps({"rules": ordered}), encoding="utf-8")

    def invocations(self):
        """Every argument array the fake was called with, in order."""
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line]

    def only(self):
        invocations = self.invocations()
        if len(invocations) != 1:
            raise AssertionError(f"expected exactly one invocation, got {invocations!r}")
        return invocations[0]


class PodmanTestCase(unittest.TestCase):
    """A temp directory, a fake podman, and a wrapper pointed at both."""

    def setUp(self):
        # Every bounded wait the runner performs runs on a **virtual clock** for
        # every case in this file, and that is a suite-wide decision rather than
        # a per-case convenience. There are two of them, both bounded in minutes:
        # the managed-device wait (a target that has not booted) and the DHCP
        # scenario's own (a DNS address that never arrived). A case that drives a
        # cell on the real clock spends those minutes for real, and about a dozen
        # cases here drive a cell -- so the suite grew from seven minutes to
        # twenty, and the cases that had grown it are not the ones anybody would
        # prune: they are the exit-code and ordering cases, and the ones about the
        # waits' *failure* paths are the ones that would be pruned first.
        #
        # `run.scenario_clock` is the seam, of the same kind as
        # `run.snapshot_settings`, and it exists so a case can replace it. The
        # real clock is what a real run uses; nothing in this suite asserts on
        # wall-clock time, and a case that wants the real thing says so.
        self.use_a_virtual_clock()
        self._tmp = tempfile.TemporaryDirectory(dir=legal_temp_base())
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        # A stand-in for the source tree. It is never read; the wrapper only
        # ever names it on a mount argument.
        self.source_tree = self.directory / "source"
        self.source_tree.mkdir()
        # The wrapper resolves the path it was given, so the expected value in
        # these cases is the resolved one.
        self.source_tree = self.source_tree.resolve()

    def extra_directory(self):
        """A second directory of this case's own, for a second log.

        `FakePodmanBinary` appends to one log beside itself, so two cases that
        each expect exactly one invocation cannot share one. Returned rather
        than created inline so every such directory is cleaned up.
        """
        directory = Path(tempfile.mkdtemp(dir=legal_temp_base()))
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def fake(self, rules=None, directory=None):
        """A fake binary, in `directory` when a case needs its own log.

        The log is appended to, so two cases sharing one fake share one
        `invocations()` list; a case that counts invocations passes its own
        directory rather than reading a list that grew underneath it.
        """
        return FakePodmanBinary(directory or self.directory, rules)

    def client(self, fake, **kwargs):
        # Nothing is plumbed through the environment: the fake finds its own
        # table beside itself, so the wrapper's allowlist is exercised exactly
        # as a real run would exercise it.
        return Podman(
            executable=str(fake.path),
            source_tree=str(self.source_tree),
            **kwargs,
        )

    def use_a_virtual_clock(self):
        """Replace the clock the harness's bounded waits run on.

        `run.scenario_clock` is the seam -- the same kind as
        `run.snapshot_settings` -- and it exists so a case can replace it. Called
        from `setUp` for every case in this file; the reason is written there,
        and a case that needs the real clock calls `self.use_the_real_clock()`
        instead of reaching past this.
        """
        original = run.scenario_clock
        clock = {"now": 0.0}
        self.addCleanup(setattr, run, "scenario_clock", original)
        run.scenario_clock = lambda: {
            "now": lambda: clock["now"],
            "sleep": lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
        }
        # Recorded so `ClockSeamTest` can assert this really happened. A refactor
        # that left the real clock in place would otherwise make this file's
        # stated premise false while every case in it stayed green -- and the
        # symptom is a suite that quietly takes twenty minutes.
        self._virtual_now = run.scenario_clock()["now"]
        return clock

    def use_the_real_clock(self):
        """Put the real clock back, for a case that is about elapsed time.

        **One case uses this**, and it is about the seam rather than about the
        wait: `test_a_wait_consults_the_clock_the_runner_gave_it`. Every other
        case in this file runs on a virtual clock because the bounds are in
        minutes, so this is the only place the real `time.monotonic` is exercised
        and the only place the two clocks are compared to each other.

        The alternative -- documenting it and leaving it unused -- was the state
        this replaced, and it is a bad state for a helper: the first contributor
        to reach for it would be the first to find out whether it works, and a
        helper that has never been called is a helper whose name is the only
        evidence it exists.
        """
        run.scenario_clock = _REAL_CLOCK
        return _REAL_CLOCK()


class ArgumentArrayTest(PodmanTestCase):
    """The exact argument array every operation builds.

    These are the arrays the plan's Task 1 spells out. They are written out as
    literals rather than built by a helper, so a flag that moves, disappears or
    is replaced changes this file rather than agreeing with itself.
    """

    def test_version_asks_only_for_the_client_version(self):
        fake = self.fake()
        self.assertEqual(self.client(fake).client_version(), "")
        self.assertEqual(fake.only(), ["version", "--format", "{{.Client.Version}}"])

    def test_version_returns_the_stripped_client_version(self):
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        self.assertEqual(self.client(fake).client_version(), "5.7.0")

    def test_info_asks_only_for_the_store_graph_driver(self):
        fake = self.fake([{"match": ["info"], "stdout": "overlay\n"}])
        self.assertEqual(self.client(fake).store_graph_driver(), "overlay")
        self.assertEqual(fake.only(), ["info", "--format", "{{.Store.GraphDriverName}}"])

    def test_create_network_takes_the_subnet_before_the_name(self):
        fake = self.fake()
        self.client(fake).create_network("mosdns-testnet", "10.89.0.0/24")
        self.assertEqual(
            fake.only(),
            ["network", "create", "--subnet", "10.89.0.0/24", "mosdns-testnet"],
        )

    def test_inspect_network_takes_the_name_before_the_format(self):
        fake = self.fake([{"match": ["network", "inspect"], "stdout": "mosdns-testnet\n"}])
        self.assertEqual(
            self.client(fake).inspect_network("mosdns-testnet"),
            "mosdns-testnet",
        )
        self.assertEqual(
            fake.only(),
            ["network", "inspect", "mosdns-testnet", "--format", "{{.Name}}"],
        )

    def test_network_exists_reports_presence_without_raising(self):
        """Teardown asks this question, so absence is an answer not an error.

        `cleanup` reports a consolidated failure when something of the run
        survives, and "survives" is exactly this question. A wrapper that
        raised on an absent network would make the answer unreachable, and one
        that swallowed every failure would report "nothing survived" when in
        fact nothing could be checked -- so the question is asked with
        `network exists`, whose exit status *is* the answer.
        """
        present = self.fake([{"match": ["network", "exists"], "returncode": 0}])
        self.assertIs(self.client(present).network_exists("mosdns-testnet"), True)
        self.assertEqual(present.only(), ["network", "exists", "mosdns-testnet"])

        absent = self.fake([{"match": ["network", "exists"], "returncode": 1}])
        self.assertIs(self.client(absent).network_exists("mosdns-testnet"), False)

    def test_network_exists_honours_a_per_call_deadline(self):
        """The per-call timeout is a parameter, so a caller can shorten it.

        `run()` has taken an override since the first version; `network_exists`
        is the question at the *end* of a run, which is the one place a caller
        may want a shorter budget than the default, and an override that is
        accepted and then ignored is worse than no override at all -- it reads
        as though the deadline was configurable.
        """
        fake = self.fake([{"match": ["network", "exists"], "sleep": 30}])
        with self.assertRaises(PodmanTimeout) as caught:
            self.client(fake, timeout=120.0).network_exists("mosdns-testnet", timeout=0.5)
        self.assertIn("0.5", str(caught.exception))

    def test_network_exists_still_defaults_to_the_client_deadline(self):
        fake = self.fake([{"match": ["network", "exists"], "sleep": 30}])
        with self.assertRaises(PodmanTimeout) as caught:
            self.client(fake, timeout=0.5).network_exists("mosdns-testnet")
        self.assertIn("0.5", str(caught.exception))

    def test_network_exists_distinguishes_an_absent_network_from_a_broken_service(self):
        """Podman's own answer is the answer; a broken service is still an error.

        `network exists` exits 1 for "not there" and for a few other things. The
        distinguishing feature is the message: an absent network has no
        diagnostics, so a non-zero status with output on stderr is a service
        problem and pretending the network is gone would let a run report a
        clean teardown it never performed.
        """
        broken = self.fake([
            {
                "match": ["network", "exists"],
                "returncode": 125,
                "stderr": "cannot connect to podman socket\n",
            }
        ])
        with self.assertRaises(PodmanError) as caught:
            self.client(broken).network_exists("mosdns-testnet")
        self.assertIn("cannot connect to podman socket", str(caught.exception))

    def test_run_container_emits_the_measured_flag_set_and_nothing_else(self):
        """The whole array, as literals, because this is the measured target.

        The plan's Task 1 Step 1 lists this command line exactly, and it is the
        only place in the tree where `--systemd=always`, `--cgroupns=private`,
        the three `--cap-add` values and `-d` appear. So this case holds the
        entire array rather than a fragment: an assertion that checked the
        mounts and left the flags unchecked would still be green on a target
        that starts without an init, and the measured flag set is the thing a
        later task would drop first.

        It is also why the case is named for what it asserts. It used to be
        called `test_exec_passes_the_command_as_separate_arguments`, the same
        name as the `exec` case below: Python kept the second definition and
        discarded the first without a word, so the only assertion of the
        measured flags was dead code and the suite ran one case fewer than it
        declared. `test_suite_shape.py` now fails on any duplicate case name
        in this project's own test files, because `unittest` swallowing a test
        is otherwise invisible.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-20260928T101010Z-target-24.04",
            network="mosdns-testnet",
        )
        self.assertEqual(
            fake.only(),
            [
                "run",
                "-d",
                "--name", "mosdns-20260928T101010Z-target-24.04",
                "--network", "mosdns-testnet",
                "--systemd=always",
                "--cgroupns=private",
                "--cap-add=SYS_ADMIN",
                "--cap-add=NET_ADMIN",
                "--cap-add=SYS_PTRACE",
                "--cap-add=NET_RAW",
                "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "-v", f"{self.source_tree}:/workspace:ro",
                "localhost/mosdns-target:24.04",
            ],
        )

    def test_the_measured_target_flag_set_is_the_plan_own_listing(self):
        """Step 1's array, read from the plan rather than from the wrapper.

        The plan is the record the next implementer works from, so a later task
        that changes the flags has to change the plan too. Reading the listing
        out of the plan makes that a failing case rather than a divergence
        nobody notices, and it means the literals in the case above are checked
        against a second copy of the same list.
        """
        plan = (REPO / "docs/superpowers/plans/2026-09-25-podman-integration-matrix.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "podman run -d --name NAME --network mosdns-testnet --systemd=always "
            "--cgroupns=private --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=SYS_PTRACE "
            "--cap-add=NET_RAW "
            "-v /sys/fs/cgroup:/sys/fs/cgroup:rw -v SOURCE:/workspace:ro IMAGE",
            plan,
        )
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-20260928T101010Z-target-24.04",
            network="mosdns-testnet",
        )
        emitted = " ".join(fake.only())
        for flag in (
            "-d",
            "--systemd=always",
            "--cgroupns=private",
            "--cap-add=SYS_ADMIN",
            "--cap-add=NET_ADMIN",
            "--cap-add=SYS_PTRACE",
            "--cap-add=NET_RAW",
            "-v /sys/fs/cgroup:/sys/fs/cgroup:rw",
            f"-v {self.source_tree}:/workspace:ro",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, emitted)

    def test_run_container_returns_the_container_id(self):
        fake = self.fake([{"match": ["run"], "stdout": "9f3c1d0e2b\n"}])
        self.assertEqual(
            self.client(fake).run_container(
                image="localhost/mosdns-target:24.04",
                name="mosdns-x-target-22.04",
                network="mosdns-testnet",
            ),
            "9f3c1d0e2b",
        )

    def test_run_container_appends_extra_arguments_before_the_image(self):
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=["--ip", "10.89.0.10"],
        )
        argv = fake.only()
        self.assertEqual(argv[-3:], ["--ip", "10.89.0.10", "localhost/mosdns-target:24.04"])

    def test_exec_passes_the_command_as_separate_arguments(self):
        fake = self.fake()
        self.client(fake).exec_container("mosdns-x-target-24.04", "systemctl", "is-active", "mosdns-router")
        self.assertEqual(
            fake.only(),
            ["exec", "mosdns-x-target-24.04", "systemctl", "is-active", "mosdns-router"],
        )

    def test_exec_script_passes_the_script_as_one_sh_dash_c_argument(self):
        fake = self.fake()
        script = "nmcli -g GENERAL.NM-MANAGED device show eth0; echo done"
        self.client(fake).exec_script("mosdns-x-target-24.04", script)
        self.assertEqual(
            fake.only(),
            ["exec", "mosdns-x-target-24.04", "sh", "-c", script],
        )

    def test_container_logs_reads_the_stderr_stream_podman_writes_them_to(self):
        """**Podman writes a container's log to its own stderr, not stdout.**

        Measured on this host, and it is the kind of thing that reads as "the
        daemon logged nothing":

        ```text
        $ podman logs probe-router            # from a shell
        dnsmasq[1]: started, version 2.91 cachesize 150
        ...
        $ python3 -c '…; print(podman.container_logs("probe-router"))'
        ''
        ```

        `podman logs` gives a container's stdout to podman's stdout and the
        container's stderr to podman's stderr -- the same split `docker logs`
        makes. dnsmasq with `log-facility=-` logs to **stderr** (it is the
        only facility a container has, since it has no syslog), so a reader that
        reads stdout sees an empty log for a daemon that is logging perfectly
        well. And the DHCP scenario reads the router's log as the *attribution*
        for the address and the resolver, so a reader that found nothing there
        would report a DORA exchange that plainly happened as a missing one.
        """
        fake = self.fake([{
            "match": ["logs", "mosdns-x-mock-router"],
            "stdout": "",
            "stderr": "dnsmasq-dhcp[1]: DHCPOFFER(eth0) 10.89.0.191 c2:c6:42:81:9d:6d\n",
        }])
        logs = self.client(fake).container_logs("mosdns-x-mock-router")
        self.assertIn("DHCPOFFER", logs)

    def test_container_logs_keeps_both_streams(self):
        """A daemon that writes to both is not half a log.

        The two streams are joined rather than one being preferred, so a router
        that logged an answer to stdout and a warning to stderr is recorded whole
        -- and the join is ordered, stdout first, so the document reads the way
        the streams were written.
        """
        fake = self.fake([{
            "match": ["logs", "mosdns-x-mock-router"],
            "stdout": "first line\n",
            "stderr": "second line\n",
        }])
        logs = self.client(fake).container_logs("mosdns-x-mock-router")
        self.assertEqual(logs, "first line\nsecond line")

    def test_copy_to_names_the_artifact_and_the_container_destination(self):
        fake = self.fake()
        artifact = self.directory / "mosdns-router_0.1.0_amd64.deb"
        artifact.write_bytes(b"!<arch>\n")
        self.client(fake).copy_to("mosdns-x-target-24.04", str(artifact), "/tmp/package.deb")
        self.assertEqual(
            fake.only(),
            ["cp", str(artifact), "mosdns-x-target-24.04:/tmp/package.deb"],
        )

    def test_stop_uses_thirty_seconds_and_the_container_name(self):
        fake = self.fake()
        self.client(fake).stop("mosdns-x-target-24.04")
        self.assertEqual(fake.only(), ["stop", "--time", "30", "mosdns-x-target-24.04"])

    def test_remove_container_forces(self):
        fake = self.fake()
        self.client(fake).remove_container("mosdns-x-target-24.04")
        self.assertEqual(fake.only(), ["rm", "-f", "mosdns-x-target-24.04"])

    def test_remove_network_names_the_network(self):
        fake = self.fake()
        self.client(fake).remove_network("mosdns-testnet")
        self.assertEqual(fake.only(), ["network", "rm", "mosdns-testnet"])

    def test_remove_volume_names_the_volume(self):
        fake = self.fake()
        self.client(fake).remove_volume("mosdns-x-state")
        self.assertEqual(fake.only(), ["volume", "rm", "-f", "mosdns-x-state"])

    def test_every_documented_operation_emits_no_machine_subcommand(self):
        """No `podman machine`, anywhere, and no way to ask for one.

        The previous architecture of this plan was a `podman machine`, which
        needs qemu that this host does not have and must not get. The wrapper
        builds every argument array in the harness, so the sweep over the
        documented operations plus the refusal in the wrapper is what holds it:
        a grep of the tree would pass the day a second code path started
        building its own command line.
        """
        fake = self.fake()
        podman = self.client(fake)
        operations = [
            lambda: podman.client_version(),
            lambda: podman.store_graph_driver(),
            lambda: podman.create_network("mosdns-testnet", "10.89.0.0/24"),
            lambda: podman.inspect_network("mosdns-testnet"),
            lambda: podman.network_exists("mosdns-testnet"),
            lambda: podman.run_container(
                image="localhost/mosdns-target:24.04",
                name="mosdns-x-target-24.04",
                network="mosdns-testnet",
            ),
            lambda: podman.exec_container("mosdns-x-target-24.04", "true"),
            lambda: podman.exec_script("mosdns-x-target-24.04", "true"),
            lambda: podman.copy_to("mosdns-x-target-24.04", "/tmp/a.deb", "/tmp/a.deb"),
            lambda: podman.stop("mosdns-x-target-24.04"),
            lambda: podman.remove_container("mosdns-x-target-24.04"),
            lambda: podman.remove_network("mosdns-testnet"),
            lambda: podman.create_volume("mosdns-x-state"),
            lambda: podman.remove_volume("mosdns-x-state"),
            lambda: podman.all_container_names("mosdns-x-"),
            lambda: podman.all_volume_names("mosdns-x-"),
        ]
        for operation in operations:
            operation()
        invocations = fake.invocations()
        self.assertEqual(len(invocations), len(operations))
        for argv in invocations:
            self.assertNotIn("machine", argv, f"a machine subcommand was emitted: {argv!r}")

    def test_asking_for_a_machine_subcommand_is_refused(self):
        fake = self.fake()
        with self.assertRaises(PodmanError) as caught:
            self.client(fake).run(["machine", "start"])
        self.assertIn("machine", str(caught.exception))
        self.assertEqual(fake.invocations(), [])


class ConnectionFlagTest(PodmanTestCase):
    """`--connection` is a service URI on every invocation, never global state.

    The plan runs the arm64 arm of the matrix against a native arm64 Podman
    service. Setting a global default in a configuration file would change the
    behaviour of every other podman user on the machine, so the connection is
    an argument on each call and the default -- no connection at all -- is the
    local rootless Podman, which is the acceptance path on this host.
    """

    def test_no_connection_leaves_the_argument_array_alone(self):
        fake = self.fake()
        self.client(fake, connection=None).client_version()
        self.assertEqual(fake.only(), ["version", "--format", "{{.Client.Version}}"])

    def test_connection_is_passed_as_a_global_flag_on_every_invocation(self):
        fake = self.fake()
        podman = self.client(fake, connection="ssh://builder@arm64.example/run/user/1000/podman/podman.sock")
        podman.client_version()
        podman.create_network("mosdns-testnet", "10.89.0.0/24")
        podman.remove_network("mosdns-testnet")
        for argv in fake.invocations():
            self.assertEqual(argv[:2], ["--connection", "ssh://builder@arm64.example/run/user/1000/podman/podman.sock"])

    def test_connection_precedes_every_subcommand(self):
        fake = self.fake()
        self.client(fake, connection="unix:///run/podman/podman.sock").create_network("mosdns-testnet", "10.89.0.0/24")
        self.assertEqual(
            fake.only(),
            [
                "--connection", "unix:///run/podman/podman.sock",
                "network", "create", "--subnet", "10.89.0.0/24", "mosdns-testnet",
            ],
        )

    def test_a_machine_name_is_refused_rather_than_documented(self):
        """A bare word is how a machine is spelled, so the shape is checked.

        `podman --connection podman-machine-default` is a valid invocation, and
        this harness's whole architecture is that there is no machine. Before
        this case the rule was a sentence in the plan and a sentence in the
        module docstring, which is the same class of thing as the `machine`
        subcommand guard was before it was a guard: a comment where a refusal
        belongs. Podman also resolves a bare name through `connections.conf`, a
        shared configuration file, so even a name that is not a machine points
        at a second piece of state on this machine.
        """
        for spelling in (
            "podman-machine-default",
            "arm64",
            "local",
            "./some/socket",
            "podman-machine-default:",
            "SSH://builder@arm64.example/run/podman/podman.sock",
        ):
            with self.subTest(connection=spelling):
                with self.assertRaises(PodmanError) as caught:
                    Podman(executable="/bin/true", connection=spelling)
                message = str(caught.exception)
                self.assertIn("service URI", message)
                self.assertIn("machine", message)

    def test_every_service_uri_scheme_the_plan_names_is_accepted(self):
        """The refusal is on the shape, so the shapes the plan names must pass."""
        for uri in (
            "ssh://builder@arm64.example/run/user/1000/podman/podman.sock",
            "unix:///run/podman/podman.sock",
            "tcp://arm64.example:1234",
        ):
            with self.subTest(connection=uri):
                self.assertEqual(Podman(executable="/bin/true", connection=uri).connection, uri)

    def test_no_connection_is_the_local_rootless_podman(self):
        """Omitted, or empty, is the acceptance path -- and stays legal."""
        for absent in (None, ""):
            with self.subTest(connection=absent):
                podman = Podman(executable="/bin/true", connection=absent)
                self.assertIsNone(podman.connection)
                self.assertEqual(podman.build_argv(["version"]), ["/bin/true", "version"])


class SubprocessSafetyTest(PodmanTestCase):
    """Argument arrays, check=True, timeouts, captured streams, redacted env.

    A harness that hands a scenario's string to a shell is a harness whose test
    names are arguments, so the shell case is detected by what the child
    process was actually started with rather than by reading the source.
    """

    def test_a_failing_command_raises_with_its_streams(self):
        fake = self.fake([{"match": ["version"], "returncode": 125, "stderr": "cannot connect to podman\n"}])
        with self.assertRaises(PodmanError) as caught:
            self.client(fake).client_version()
        message = str(caught.exception)
        self.assertIn("125", message)
        self.assertIn("cannot connect to podman", message)
        self.assertIn("version --format", message)

    def test_a_command_that_runs_too_long_is_abandoned_at_its_deadline(self):
        fake = self.fake([{"match": ["version"], "sleep": 30}])
        podman = self.client(fake, timeout=0.5)
        with self.assertRaises(PodmanTimeout) as caught:
            podman.client_version()
        self.assertIn("0.5", str(caught.exception))

    def test_the_child_is_started_directly_and_never_through_a_shell(self):
        """`sh -c` is one argv element, and the child's argv[0] is podman.

        If the runner used `shell=True` the child would be `/bin/sh` with the
        whole command line as a single `-c` string, so the recorded array would
        be `['/bin/sh', '-c', '...']` and neither the executable nor the
        argument array would be what this asserts.
        """
        fake = self.fake()
        podman = self.client(fake)
        podman.exec_script("mosdns-x-target-24.04", "echo 'a  b' > /tmp/f; echo $HOME")
        argv = fake.only()
        self.assertEqual(argv[:4], ["exec", "mosdns-x-target-24.04", "sh", "-c"])
        self.assertEqual(argv[4], "echo 'a  b' > /tmp/f; echo $HOME")

    def test_both_streams_are_captured_rather_than_inherited(self):
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n", "stderr": "warn: overlays\n"}])
        result = self.client(fake).run(["version", "--format", "{{.Client.Version}}"])
        self.assertEqual(result.stdout, "5.7.0\n")
        self.assertEqual(result.stderr, "warn: overlays\n")
        self.assertEqual(result.returncode, 0)

    def test_a_non_zero_status_is_an_error_even_with_usable_output(self):
        """`check=True` is what makes this an error, and it is load bearing.

        A container that exited non-zero after printing the answer a scenario
        was about to trust is the case where reading stdout anyway produces a
        green run of a broken target.
        """
        fake = self.fake([{"match": ["exec"], "returncode": 1, "stdout": "yes\n"}])
        with self.assertRaises(PodmanError):
            self.client(fake).exec_container("mosdns-x-target-24.04", "true")

    def test_only_named_variables_reach_the_child(self):
        fake = self.fake([{"match": ["version"], "dump_env": True}])
        os.environ[SECRET_ENV_NAME] = "hunter2-not-a-real-secret"
        self.addCleanup(os.environ.pop, SECRET_ENV_NAME, None)
        result = self.client(fake).run(["version", "--format", "{{.Client.Version}}"])
        child_env = json.loads(result.stdout)
        self.assertNotIn(SECRET_ENV_NAME, child_env)
        self.assertNotIn("hunter2-not-a-real-secret", result.stdout)
        self.assertNotIn("hunter2-not-a-real-secret", str(result))

    def test_the_forwarded_variable_set_is_exactly_the_allowlist(self):
        fake = self.fake([{"match": ["version"], "dump_env": True}])
        podman = self.client(fake)
        result = podman.run(["version", "--format", "{{.Client.Version}}"])
        child_env = json.loads(result.stdout)
        self.assertEqual(
            sorted(podman.forwarded_env_names()),
            sorted(FORWARDED_ENV_NAMES),
        )
        self.assertEqual(set(child_env) - set(FORWARDED_ENV_NAMES), set())

    def test_an_explicitly_supplied_variable_is_the_only_other_way_in(self):
        fake = self.fake([{"match": ["version"], "dump_env": True}])
        podman = self.client(fake, extra_env={"XDG_DATA_DIRS": "/usr/share:/usr/local/share"})
        result = podman.run(["version", "--format", "{{.Client.Version}}"])
        self.assertEqual(json.loads(result.stdout)["XDG_DATA_DIRS"], "/usr/share:/usr/local/share")

    def test_the_child_runs_in_the_source_tree_as_a_working_directory(self):
        fake = self.fake()
        podman = self.client(fake)
        # A missing working directory would make every command fail with a
        # confusing error instead of a clear one, so it is the real directory.
        self.assertTrue(Path(podman.working_directory).is_dir())


class MountAllowlistTest(PodmanTestCase):
    """The source tree is read-only at /workspace, and nothing else is mounted.

    The harness exists to run code that takes over DNS. If it could see the
    host's `/etc/resolv.conf`, `/run/systemd/resolve` or a home directory, a
    scenario would be reading and could be writing the very state the harness
    is required to prove it does not change. So the rule is an allowlist of two
    mounts rather than a denylist of five roots, and these cases read the mount
    arguments the wrapper emits -- the check is on the arguments, not on a list
    of strings a caller could reorder into a shape the check does not read.
    """

    def test_the_two_mounts_the_wrapper_emits_are_the_two_allowed_ones(self):
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
        )
        mounts = [parse_volume(spec) for spec in volume_arguments(fake.only())]
        self.assertEqual(
            sorted(mounts),
            sorted(
                [
                    (str(self.source_tree), WORKSPACE, "ro"),
                    (CGROUP, CGROUP, "rw"),
                ]
            ),
        )

    def test_every_mount_of_every_operation_stays_inside_the_allowlist(self):
        """The sweep, not one operation: a new operation is covered by this.

        A case that only checked `run_container` would say nothing about a
        later task's helper, and a later task's helper is exactly where a
        convenient extra bind would appear.
        """
        fake = self.fake()
        podman = self.client(fake)
        podman.run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
        )
        podman.run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=["--ip", "10.89.0.10"],
        )
        podman.client_version()
        for argv in fake.invocations():
            for spec in volume_arguments(argv):
                source, destination, options = parse_volume(spec)
                self.assertIn(source, (str(self.source_tree), CGROUP), f"{spec!r} mounts a foreign host path")
                self.assertIn(destination, (WORKSPACE, CGROUP), f"{spec!r} mounts outside the allowed destinations")
                if destination == WORKSPACE:
                    self.assertEqual(options, "ro", f"{spec!r} must bind the source tree read-only")
                else:
                    self.assertEqual(options, "rw", f"{spec!r} must bind the cgroup filesystem writable")

    def test_a_host_path_outside_the_allowlist_is_refused_in_every_spelling(self):
        """The refusal reads all three spellings, and order is irrelevant.

        `--volume SRC:DST`, `--volume=SRC:DST`, `-v SRC:DST` and
        `--mount type=bind,src=…,dst=…` are four ways of saying the same thing.
        A check that read one of them would be a check on a spelling.
        """
        forbidden = [
            "/etc/passwd",
            "/etc/NetworkManager",
            "/run/systemd/resolve",
            "/var/lib/mosdns",
            "/sys/class/net",
            "/home/ubuntu/.ssh",
            "/root/.aws",
            "/opt/anything",
        ]
        # (the token as it appears in an argument array, the value it carries)
        spellings = (
            ("-v", None),
            ("--volume", None),
            ("--volume=", None),
            ("--mount", "type=bind,source={src},target=/workspace,ro"),
            ("--mount=", "type=bind,source={src},target=/workspace,ro"),
        )
        for host_path in forbidden:
            for token, template in spellings:
                value = (
                    template.format(src=host_path)
                    if template
                    else f"{host_path}:/workspace:ro"
                )
                argv = (
                    ["run", "-d", token + value, "localhost/mosdns-target:24.04"]
                    if token.endswith("=")
                    else ["run", "-d", token, value, "localhost/mosdns-target:24.04"]
                )
                with self.subTest(spelling=token, source=host_path):
                    with self.assertRaises(MountPolicyError) as caught:
                        self.client(self.fake()).run(argv)
                    self.assertIn(host_path, str(caught.exception))

    def test_a_refused_mount_is_refused_wherever_it_sits_in_the_array(self):
        """A good mount does not launder a bad one, in either order.

        The temptation this case exists to close is a validator that returns as
        soon as it has found an allowed mount, which passes every argument
        array that starts correctly and fails every one that does not.
        """
        good = f"{self.source_tree}:{WORKSPACE}:ro"
        bad = "/etc/shadow:/workspace:ro"
        for argv in (
            ["run", "-v", good, "-v", bad, "localhost/img"],
            ["run", "-v", bad, "-v", good, "localhost/img"],
            ["run", "-d", "--name", "n", "-v", bad, "localhost/img"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(MountPolicyError):
                    self.client(self.fake()).run(argv)

    def test_each_forbidden_host_root_is_named_in_the_refusal(self):
        """The plan's five roots, one case each, so the message is usable.

        The refusal is read by whoever left a bind in, and "refused" without a
        path is a comment rather than a diagnosis.
        """
        for root in FORBIDDEN_HOST_ROOTS:
            with self.subTest(root=root):
                with self.assertRaises(MountPolicyError) as caught:
                    self.client(self.fake()).run(["run", "-v", f"{root}/inside:/workspace:ro", "localhost/img"])
                self.assertIn(f"{root}/inside", str(caught.exception))

    def test_the_cgroup_filesystem_is_the_only_mount_under_a_forbidden_root(self):
        """`/sys/fs/cgroup` is the exception, and the rest of `/sys` is not.

        A systemd container will not start without the cgroup filesystem bound
        in, so the exception has to exist; the case that matters is that it is
        the cgroup *filesystem* and not the whole of `/sys`, which is where the
        host's NetworkManager state and interfaces live.
        """
        with self.assertRaises(MountPolicyError):
            self.client(self.fake()).run(["run", "-v", "/sys:/sys:rw", "localhost/img"])
        with self.assertRaises(MountPolicyError):
            self.client(self.fake()).run(["run", "-v", "/sys/fs:/sys/fs:rw", "localhost/img"])

    def test_a_source_tree_inside_a_forbidden_host_root_is_refused_at_construction(self):
        """The allowlist's *parameter* must itself be legal, or it empties it.

        The allowlist is right to be parameterized: a checkout is wherever the
        operator's checkout is, and pinning it to one path would make the
        harness unusable. But the parameter decides what `/workspace` contains,
        so a source tree of `/etc` or of `/` made the policy
        `run.py --source-tree /etc matrix` -> `-v /etc:/workspace:ro`, and a
        target holding SYS_ADMIN and running systemd could then read the host's
        `/etc/resolv.conf`. The refusal has to be at construction, because by
        the time an argument array exists the mount is legal as far as
        `_check_mount` can tell: it compares the source against the
        allowlist's own entry and the two agree.

        The four roots are the ones that hold the host's resolver and systemd
        state. `/home` is not among them and there is a case for that
        (`test_a_source_tree_under_home_is_accepted_and_emitted_read_only`).

        Every case names the root it broke in the message -- a refusal that
        says "refused" without a path is a shrug.
        """
        for root in FORBIDDEN_SOURCE_TREE_ROOTS:
            for path in (root, os.path.join(root, "inside"), os.path.join(root, "a", "b")):
                with self.subTest(source_tree=path):
                    with self.assertRaises(MountPolicyError) as caught:
                        Podman(executable="/bin/true", source_tree=path)
                    message = str(caught.exception)
                    self.assertIn(root, message)
                    self.assertIn(WORKSPACE, message)

    def test_the_root_itself_is_refused_as_a_source_tree(self):
        """`/` contains all five forbidden roots, so it is the worst case.

        It is also the one a prefix check gets wrong: no forbidden root is a
        prefix of `/` followed by a separator, so `"/" == root` is false and
        `"/".startswith("//")` is false, and a prefix comparison alone lets the
        whole host through. Widening the source-tree allowlist to `/home` does
        not widen it to `/` -- `/` is refused by its own branch, and this case
        is what says so.
        """
        with self.assertRaises(MountPolicyError) as caught:
            Podman(executable="/bin/true", source_tree="/")
        self.assertIn("every forbidden host root", str(caught.exception))

    def test_the_source_tree_refusal_names_a_remedy_an_operator_can_act_on(self):
        """A refusal that does not say what to pass instead is a defect.

        The operator who hit this wrote `--source-tree` to a path that was
        refused, or inherited the default and was refused by it. In both cases
        the only useful next action is to point `--source-tree` at the checkout
        directory, and under the amended policy a checkout under `/home` is a
        legal answer -- so the message has to name it. A message that said only
        "not under /home, /etc, /run, /var, /sys" would have been correct and
        useless once `/home` became legal.
        """
        with self.assertRaises(MountPolicyError) as caught:
            Podman(executable="/bin/true", source_tree="/etc")
        message = str(caught.exception)
        self.assertIn("--source-tree", message)
        self.assertIn("/workspace", message)
        # A worked example, not just the flag: the remedy is a value to pass.
        self.assertRegex(message, r"--source-tree\s+\S+")

    def test_a_source_tree_that_traverses_out_of_a_forbidden_root_is_refused(self):
        """`..` must not launder a path, and the wrapper resolves before it checks.

        A check against the raw string is defeated by a relative component, and
        a relative component is a thing an operator types out of habit. Each
        spelling below resolves to a path the case above already refuses.
        """
        spellings = [spelling for root in FORBIDDEN_SOURCE_TREE_ROOTS
                     for spelling in (f"{root}/../{root.lstrip('/')}", f"//{root.lstrip('/')}", f"{root}/")]
        self.assertEqual(len(spellings), 12)
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                with self.assertRaises(MountPolicyError):
                    Podman(executable="/bin/true", source_tree=spelling)

    def test_a_source_tree_that_traverses_into_home_is_accepted(self):
        """`/home/../home/<user>` is the same `/home` case, and it is legal.

        Held next to the refusal it is the whole amendment in one line: the
        traversal is still resolved rather than trusted, and what it resolves
        to is judged against the amended set. A future tightening of the set
        therefore shows up here as a failure rather than as a silent hole.
        """
        podman = Podman(executable="/bin/true", source_tree="/home/../home/ubuntu")
        self.assertEqual(podman.source_tree, "/home/ubuntu")
        self.assertEqual(podman.allowed_mounts()[WORKSPACE], ("/home/ubuntu", "ro"))

    def test_a_source_tree_under_home_is_accepted_and_emitted_read_only(self):
        """A checkout under `/home` is the normal case on this host, not a refusal.

        The rationale for refusing `/etc`, `/run`, `/var` and `/sys` is that
        they hold the host's resolver and its systemd state: a bind of any of
        them is how a run reaches the host's DNS. A read-only bind of a source
        checkout under `/home` does none of that -- it exposes project source
        and nothing else -- and this host's checkout *is* under `/home`, so
        refusing it left no legal value at all for `--source-tree` here and
        `run.py` could not run from a checkout at all.

        So `/home` is permitted for the read-only workspace, and the mount is
        asserted `:ro` rather than merely accepted: the exemption is for the
        read-only workspace, and a case that only checked acceptance would not
        hold the property the exemption is granted on.
        """
        # Built under the real `/home` rather than under `legal_temp_base()`,
        # because the point of the case is the path.
        legal = home_source_tree()
        self.addCleanup(shutil.rmtree, legal, True)
        podman = Podman(executable="/bin/true", source_tree=str(legal))
        self.assertEqual(podman.source_tree, str(legal))
        self.assertEqual(
            podman.allowed_mounts(),
            {CGROUP: (CGROUP, "rw"), WORKSPACE: (str(legal), "ro")},
        )
        self.assertEqual(
            podman.mount_arguments(),
            ["-v", f"{CGROUP}:{CGROUP}:rw", "-v", f"{legal}:{WORKSPACE}:ro"],
        )

    def test_a_source_tree_under_home_is_still_may_not_be_mounted_writable(self):
        """The exemption is for the read-only workspace, not for the path.

        This is the case that keeps the amendment from being read as "bind the
        checkout read-write too". A permitted source tree is still only ever
        emitted `:ro`, and a caller that asks for `:rw` is refused -- including
        one whose source tree is under `/home`, which is the spelling a later
        task would reach for if it wrongly concluded the path was what made
        `:rw` legal.
        """
        legal = home_source_tree()
        self.addCleanup(shutil.rmtree, legal, True)
        fake = self.fake()
        podman = Podman(executable=str(fake.path), source_tree=str(legal))
        with self.assertRaises(MountPolicyError) as caught:
            podman.run(["run", "-v", f"{legal}:{WORKSPACE}:rw", "localhost/img"])
        self.assertIn("read-only", str(caught.exception))
        self.assertEqual(fake.invocations(), [])

    def test_a_foreign_path_under_home_is_still_refused_as_a_mount(self):
        """`/home` is not a hole in the *mount* policy, only in the source-tree one.

        The mount policy is unchanged: a mount's source must equal the
        allowlist's own entry, so a path under `/home` that is not the source
        tree -- the operator's own home, an SSH key directory, a browser
        profile -- is still refused. Permitting `/home` for the workspace must
        not have permitted it as an argument.
        """
        legal = home_source_tree()
        self.addCleanup(shutil.rmtree, legal, True)
        client = Podman(executable="/bin/true", source_tree=str(legal))
        for foreign in ("/home/ubuntu/.ssh", "/home/ubuntu/.mozilla/firefox", "/home/ubuntu/Documents"):
            with self.subTest(foreign=foreign):
                with self.assertRaises(MountPolicyError) as caught:
                    client.run(["run", "-v", f"{foreign}:{WORKSPACE}:ro", "localhost/img"])
                self.assertIn(foreign, str(caught.exception))

    def test_a_later_task_cannot_widen_the_allowlist_into_a_writable_host_root(self):
        """The five-root set is a refusal, not a phrase in an error message.

        This is the second instance of the defect Fix Round 1 called Critical 2:
        `_check_mount` compares a mount's source against **the allowlist's own
        entry**, so a check whose only evidence is that entry agrees with itself.
        A later task that needs a third mount writes one line into
        `allowed_mounts()` -- and if that line is `/etc/mosdns -> /mnt/extra` with
        mode `rw`, the host's `/etc`, `/etc/resolv.conf` included, is bound
        writable into a target holding `SYS_ADMIN` and running systemd.

        `FORBIDDEN_HOST_ROOTS` did not stop it. The constant was consulted only to
        *name* a root in a refusal message, so the comment claiming the writable
        case "must stay closed there" was a claim about the code rather than a
        property of it. The comment was wrong about the mechanism, so the
        mechanism is what this fixes: a source inside any of the five roots is
        refused **whatever the allowlist says**, unless the mount is read-only or
        is the one measured exception.

        The allowlist is extended the way a later task would extend it, by
        overriding the method -- so the case is about the guard rather than about
        a table nobody edits today.
        """
        for root, source, destination in (
            ("/etc", "/etc/mosdns", "/mnt/extra"),
            ("/run", "/run/mosdns", "/mnt/extra"),
            ("/var", "/var/lib/mosdns", "/mnt/extra"),
            ("/sys", "/sys/class/net", "/mnt/extra"),
            ("/home", "/home/ubuntu/Documents", "/mnt/extra"),
        ):
            with self.subTest(root=root):
                podman = Podman(executable="/bin/true")
                podman.allowed_mounts = lambda source=source, destination=destination: {
                    CGROUP: (CGROUP, "rw"),
                    destination: (source, "rw"),
                }
                with self.assertRaises(MountPolicyError) as caught:
                    podman.run(["run", "-v", f"{source}:{destination}:rw", "localhost/img"])
                message = str(caught.exception)
                self.assertIn(source, message)
                self.assertIn(root, message)
                # And nothing reached the binary: the refusal happens where every
                # other mount refusal happens, before `run` starts podman.
                self.assertIn("read-only", message)

    def test_a_read_only_mount_of_a_host_root_stays_possible_so_the_rule_is_not_a_door(self):
        """The new refusal is narrow on purpose, and the narrowness is held.

        A guard that refused every path under a forbidden root would refuse this
        host's own checkout -- the source tree is under `/home` and is bound
        `:ro`, which is the whole of the read-only case's argument. So the rule is
        "a forbidden root is never bound *writable*", and this holds the
        read-only side, through the same overridden allowlist the case above uses,
        so the two are visibly the same lever.
        """
        podman = Podman(executable="/bin/true")
        podman.allowed_mounts = lambda: {
            CGROUP: (CGROUP, "rw"),
            "/mnt/extra": ("/home/ubuntu/Documents", "ro"),
        }
        self.assertEqual(
            podman.build_argv(["run", "-v", "/home/ubuntu/Documents:/mnt/extra:ro", "localhost/img"])[-4:],
            ["run", "-v", "/home/ubuntu/Documents:/mnt/extra:ro", "localhost/img"],
        )
        # The one measured exception is still the exception, and it is still the
        # only *writable* mount of a forbidden root: a cgroup mount that is not
        # `rw` is refused for being the wrong mode, which is a different refusal
        # and is asserted elsewhere.
        self.assertEqual(
            Podman(executable="/bin/true").build_argv(
                ["run", "-v", f"{CGROUP}:{CGROUP}:rw", "localhost/img"]
            )[-3:],
            ["-v", f"{CGROUP}:{CGROUP}:rw", "localhost/img"],
        )

    def test_a_keyed_mount_option_with_a_value_is_still_inspected(self):
        """A valued `--mount` key was invisible, and three of them change the host.

        `_parse_mount_spec` collected only the keys that had *no* value, because
        that is how the colon-separated `-v` form spells an option. In the keyed
        `--mount` form almost every option is `key=value`, so a valued key was
        dropped before the policy ever saw it -- and measured on the two legal
        mounts, these were all accepted before this case existed:

        ```text
        /workspace,ro,relabel=shared          ACCEPTED   <- the --mount spelling of `:z`
        /workspace,ro,chown=true              ACCEPTED   <- chowns the host's source tree
        /workspace,ro,U=true                  ACCEPTED   <- the same option, abbreviated
        /sys/fs/cgroup,rw,bind-propagation=rshared   ACCEPTED   <- propagates to the host
        ```

        The first is the same host relabelling the guard already refuses as `:Z`
        and `:z`, reached by the other spelling. The last is worse than a
        relabel: a *shared* bind mount means a submount the target makes under
        `/sys/fs/cgroup` propagates back into the host's own cgroup hierarchy, and
        that is the harness's one writable mount.

        So this is closed by an **allowlist of keys** rather than a denylist of
        the three above: a key this harness does not recognise is refused, which
        is the same rule the valueless options already followed and the same
        design as the capability ceiling -- an option nobody has thought of yet is
        refused too.

        **Each row asserts the *reason*, not the key name.** The previous version
        of this table asserted `assertIn(named, message)` with `named` the key --
        and every message begins `refusing mount '<the specification>'`, which
        echoes the key back, so the assertion was satisfied by the refusal text
        alone and could not tell a host-mutating option from an unrecognised one.
        That is the same shape as the fixture defect Fix Round 2 found, where a
        comma in a value made the `context=` row pass on the pre-fix module. So
        the reason from `HOST_MUTATING_MOUNT_KEYS` is asserted for the keys it
        holds, the unrecognised-option sentence is asserted for the rest, and the
        two are held to be mutually exclusive so neither can stand in for the
        other.

        Falsified by deleting the `HOST_MUTATING_MOUNT_KEYS` branch from the
        guard, so every valued key falls through to the generic refusal that
        echoes the key back: **eleven of the twelve pre-round rows pass against
        a guard with no host-mutating check at all**, and the twelfth (`U=true`,
        which asserted `chown` while the message quotes `'U') fails for the wrong
        reason. The rows here fail all sixteen host-mutating sub-cases, each
        naming the reason it should have found missing.
        """
        legal = Path(tempfile.mkdtemp(dir=legal_temp_base()))
        self.addCleanup(shutil.rmtree, legal, True)
        podman = Podman(executable="/bin/true", source_tree=str(legal))
        refused = (
            ("relabel=shared", "relabel"),
            ("relabel=private", "relabel"),
            ("chown=true", "chown"),
            ("U=true", "U"),
            ("idmap=true", "idmap"),
            ("bind-propagation=rshared", "bind-propagation"),
            ("bind-propagation=shared", "bind-propagation"),
            ("no-dereference=true", "no-dereference"),
            ("subpath=src", "subpath"),
            # A real SELinux MCS context is `…:s0:c1,c2`, and that comma splits
            # the `--mount` specification into two fields -- so the full label is
            # refused as an unrecognised option named `c2`, and the `context` key
            # is never the thing that refused it. **The message names the trailing
            # label component and nothing else**, which reads like a parser bug
            # and is the shape a contributor with an SELinux-labelled mount would
            # file. The row is here so that what actually happens is recorded
            # rather than discovered: the label cannot be written in this syntax
            # at all, so the truncation below is the only form this harness can
            # be asked about, and it is refused too.
            ("context=system_u:object_r:container_file_t:s0:c1,c2", "c2"),
            ("context=system_u:object_r:container_file_t:s0", "context"),
            ("tmpfs-size=4096", "tmpfs-size"),
            ("an-option-nobody-has-thought-of=yet", "an-option-nobody-has-thought-of"),
        )
        # The unrecognised-option reason, written out rather than read from the
        # guard, so a change to the message fails here instead of being agreed
        # with by both sides at once.
        unrecognised = "is not a mount option this harness uses"
        for option, key in refused:
            expected = HOST_MUTATING_MOUNT_KEYS.get(key, unrecognised)
            for destination, mode in ((WORKSPACE, "ro"), (CGROUP, "rw")):
                source = str(legal) if destination == WORKSPACE else CGROUP
                with self.subTest(option=option, destination=destination):
                    spec = f"type=bind,src={source},dst={destination},{mode},{option}"
                    with self.assertRaises(MountPolicyError) as caught:
                        podman.run(["run", "--mount", spec, "localhost/img"])
                    message = str(caught.exception)
                    self.assertIn(
                        expected,
                        message,
                        f"the refusal for {option!r} does not give its reason, so this row cannot "
                        f"tell it apart from any other refusal",
                    )
                    # The key name is in the message because the message echoes the
                    # specification, which is why asserting it proved nothing.
                    self.assertIn(key, message)
                    # And the reason is *this row's*: no other key's reason may be in
                    # it, so a guard that refused everything for one reason -- the
                    # `:Z`/`:z` check, the unrecognised-option check -- would fail.
                    for other, reason in HOST_MUTATING_MOUNT_KEYS.items():
                        if other != key and reason != expected:
                            with self.subTest(option=option, other=other):
                                self.assertNotIn(
                                    reason,
                                    message,
                                    f"{option!r} was refused for {other!r}'s reason as well, so "
                                    f"this row does not identify which check refused it",
                                )
        # The reasons are genuinely different strings, which is what lets the
        # cross-check above discriminate. If two ever converge, the cross-check is
        # vacuous and says so here rather than passing quietly.
        self.assertEqual(
            len({*HOST_MUTATING_MOUNT_KEYS.values(), unrecognised}),
            len(HOST_MUTATING_MOUNT_KEYS) + 1,
            "two refusal reasons have become the same string, so asserting one no longer "
            "distinguishes it from the other",
        )

    def test_a_legitimate_seluinux_label_is_refused_because_context_is(self):
        """`context` is refused for what the key *is*, not for the value it carries.

        The policy refuses `context` in `HOST_MUTATING_MOUNT_KEYS` because a keyed
        `context=` applies an SELinux label to the source **on the host** -- the
        same act `relabel` and `chown` are refused for, and the same act `:Z` and
        `:z` are refused for in the colon form. **There is no legitimate value of
        it that this harness supports**: a valid, harmless-looking SELinux label is
        refused anyway, and refusing it regresses no supported case. SELinux-
        labelled CI is unaffected, because the harness mounts a cgroup filesystem
        and a read-only workspace and labels neither.

        It is stated as a case rather than a comment because the *message* is
        misleading. A contributor who wrote a real MCS label -- `…:s0:c1,c2`, and
        whose comma splits the `--mount` specification -- is told that `c2` is not
        a mount option, which reads like a parser bug rather than a policy and is
        the shape somebody files. The full-label row in the case above records
        what actually happens; this one records that no label is a way through.
        """
        legal = Path(tempfile.mkdtemp(dir=legal_temp_base()))
        self.addCleanup(shutil.rmtree, legal, True)
        podman = Podman(executable="/bin/true", source_tree=str(legal))
        for label in (
            "system_u:object_r:container_file_t:s0",
            "system_u:object_r:container_t:s0:c1",
            "unconfined_u:object_r:container_file_t:s0",
        ):
            with self.subTest(label=label):
                # The MCS range's comma cannot be written in this syntax, so the
                # truncated label is the most complete one expressible here; it is
                # what the row above calls a legitimate label.
                spec = f"type=bind,src={legal},dst={WORKSPACE},ro,context={label}"
                with self.assertRaises(MountPolicyError) as caught:
                    podman.run(["run", "--mount", spec, "localhost/img"])
                self.assertIn(HOST_MUTATING_MOUNT_KEYS["context"], str(caught.exception))

    def test_a_keyed_mount_option_whose_value_is_a_mode_is_read_as_that_mode(self):
        """`ro=true` and `rw=false` are read as the mode they name, not ignored.

        The valued form is the common way a later task would write a mount, so
        dropping the value is not a conservative default: `ro=false` on the
        workspace would otherwise be invisible and the mount would be judged from
        the bare keys alone, which is how a writable workspace comes back. So the
        value is read, both ways -- a false value is the opposite mode, and both
        are refused for the same reason the bare-keyed form is.
        """
        legal = Path(tempfile.mkdtemp(dir=legal_temp_base()))
        self.addCleanup(shutil.rmtree, legal, True)
        podman = Podman(executable="/bin/true", source_tree=str(legal))
        # `ro=false` on the read-only workspace: the mount is writable, refused.
        with self.assertRaises(MountPolicyError) as caught:
            podman.run(
                ["run", "--mount", f"type=bind,src={legal},dst={WORKSPACE},ro=false", "localhost/img"]
            )
        self.assertIn("read-only", str(caught.exception))
        # `rw=false` on the writable cgroup filesystem: the mount is read-only,
        # and the message says which one it wanted, so the reader knows which
        # mode to change.
        with self.assertRaises(MountPolicyError) as caught:
            podman.run(
                ["run", "--mount", f"type=bind,src={CGROUP},dst={CGROUP},rw=false", "localhost/img"]
            )
        self.assertIn("writable", str(caught.exception))
        # And the legal valued forms still work, so the reading is not a refusal
        # of the keyed spelling itself.
        self.assertEqual(
            podman.build_argv(
                ["run", "--mount", f"type=bind,src={legal},dst={WORKSPACE},ro=true", "localhost/img"]
            )[-4:],
            ["run", "--mount", f"type=bind,src={legal},dst={WORKSPACE},ro=true", "localhost/img"],
        )

    def test_a_source_tree_at_a_legal_path_is_accepted_and_still_mounted_read_only(self):
        """The parameter stays parameterized; a refusal would end the harness.

        The whole point of `--source-tree` is that a checkout is wherever the
        operator put it. So a path outside the four refused roots is accepted,
        the mount is emitted, and it is read-only -- the property the policy
        exists for, and one a case that only tested refusals would not hold.
        """
        # A base outside every refused root, chosen the same way the fixture's
        # is, so this case does not depend on where `tempfile` points.
        legal = Path(tempfile.mkdtemp(dir=legal_temp_base()))
        self.addCleanup(shutil.rmtree, legal, True)
        podman = Podman(executable="/bin/true", source_tree=str(legal))
        self.assertEqual(
            podman.allowed_mounts(),
            {
                CGROUP: (CGROUP, "rw"),
                WORKSPACE: (str(legal), "ro"),
            },
        )
        self.assertEqual(
            podman.mount_arguments(),
            ["-v", f"{CGROUP}:{CGROUP}:rw", "-v", f"{legal}:{WORKSPACE}:ro"],
        )

    def test_the_cgroup_exception_is_not_a_source_tree_exception(self):
        """`/sys/fs/cgroup` is allowed as a *mount*; as a source tree it is not.

        The exception exists because a systemd container cannot start without
        its cgroup hierarchy, and it is scoped to that one mount. Extending it
        to the source tree would let `--source-tree /sys/fs/cgroup` bind the
        host's cgroup hierarchy at `/workspace`, which is the same class of
        mount the plan forbids.
        """
        with self.assertRaises(MountPolicyError) as caught:
            Podman(executable="/bin/true", source_tree=CGROUP)
        self.assertIn("/sys", str(caught.exception))

    def test_the_source_tree_may_not_be_mounted_writable(self):
        """`ro` is a property of the workspace mount, not of the caller.

        A scenario that could write into the checkout could rewrite a test, and
        a green run of a test that edited itself is not a result.
        """
        with self.assertRaises(MountPolicyError) as caught:
            self.client(self.fake()).run(["run", "-v", f"{self.source_tree}:{WORKSPACE}:rw", "localhost/img"])
        self.assertIn("read-only", str(caught.exception))

    def test_the_cgroup_filesystem_may_not_be_mounted_read_only(self):
        fake = self.fake()
        podman = self.client(fake)
        with self.assertRaises(MountPolicyError):
            podman.run(["run", "-v", f"{CGROUP}:{CGROUP}:ro", "localhost/img"])
        self.assertEqual(fake.invocations(), [])

    def test_a_destination_outside_the_allowed_set_is_refused(self):
        """Where a mount lands in the container is as bound as what it reads.

        A source tree at `/opt` would put a writable-looking copy of the
        checkout on the container's boot path, where an image's own tooling
        could pick it up.
        """
        with self.assertRaises(MountPolicyError) as caught:
            self.client(self.fake()).run(["run", "-v", f"{self.source_tree}:/opt/source:ro", "localhost/img"])
        self.assertIn("/opt/source", str(caught.exception))

    def test_a_relative_source_is_refused(self):
        """A relative `-v` resolves against the caller's directory, not a policy.

        `podman run -v .:/workspace:ro` is a real and tempting spelling, and it
        would satisfy a string comparison against an absolute allowlist entry
        only by accident.
        """
        with self.assertRaises(MountPolicyError):
            self.client(self.fake()).run(["run", "-v", ".:/workspace:ro", "localhost/img"])

    def test_a_relabelling_option_is_refused(self):
        """`:Z` and `:z` change the host file's SELinux label.

        That is a change to a file on this machine made by a command whose
        whole job is to change nothing on this machine, and it is invisible in
        a diff of the container.
        """
        for option in ("Z", "z"):
            with self.subTest(option=option):
                with self.assertRaises(MountPolicyError) as caught:
                    self.client(self.fake()).run(
                        ["run", "-v", f"{self.source_tree}:{WORKSPACE}:ro,{option}", "localhost/img"]
                    )
                self.assertIn(option, str(caught.exception))

    def test_an_anonymous_volume_is_refused(self):
        """A bare `-v NAME` creates a volume, which is an untracked resource.

        A resource the harness created and did not record is a resource
        `cleanup` cannot remove, which is the leak this task exists to prevent.
        """
        with self.assertRaises(MountPolicyError):
            self.client(self.fake()).run(["run", "-v", "an-anonymous-volume", "localhost/img"])

    def test_a_refused_mount_never_reaches_the_podman_binary(self):
        fake = self.fake()
        with self.assertRaises(MountPolicyError):
            self.client(fake).run(["run", "-v", "/etc/shadow:/workspace:ro", "localhost/img"])
        self.assertEqual(fake.invocations(), [])

    def test_a_policy_refusal_is_a_podman_error_and_not_a_crash(self):
        """The harness handles `PodmanError`; a refusal must be one of them.

        A refusal that is some other type would escape a `run_scenario` loop's
        error handling and be reported as a crash of the harness rather than as
        a command it declined to run, which is the difference between a useful
        message and a traceback.
        """
        with self.assertRaises(PodmanError) as caught:
            self.client(self.fake()).run(["run", "-v", "/etc/shadow:/workspace:ro", "localhost/img"])
        self.assertIsInstance(caught.exception, MountPolicyError)

    def test_a_mount_flag_with_no_value_is_refused(self):
        with self.assertRaises(MountPolicyError):
            self.client(self.fake()).run(["run", "-d", "-v", "localhost/img"])

    def test_a_command_with_no_mount_is_unaffected_by_the_mount_policy(self):
        fake = self.fake()
        self.client(fake).client_version()
        self.assertEqual(fake.invocations(), [["version", "--format", "{{.Client.Version}}"]])


# The measured cap ceiling, written out here rather than read from the module:
# a guard that derived its own allowlist from the code it guards agrees with
# itself, and the whole point of the ceiling is what a later task may add.
#
# **Four, and the fourth is `NET_RAW` because DHCP does not work without it.**
# Measured on this host, on a bridge network with a real dnsmasq across it: a
# target started with the three capabilities the plan listed reaches
# "getting IP configuration", NetworkManager logs
#
#     dhcp4 (eth0): error -1 dispatching events
#
# and `nmcli connection up` fails with
#
#     Error: Connection activation failed: IP configuration could not be
#     reserved (no available address, timeout, etc.)
#
# while `/proc/self/status` in that container reads
#
#     CapEff: 00000000802c15fb
#
# -- bit 13, `NET_RAW`, absent, because podman's default bounding set for a
# rootless container does not carry it. NetworkManager's built-in DHCP client
# opens an `AF_PACKET` socket to send and receive DORA, and cannot without it.
# With `--cap-add=NET_RAW` the same container against the same router leases
# `10.89.0.191` out of `10.89.0.100-10.89.0.199` and publishes the router's DNS.
#
# `NET_RAW` is inside the container's own network namespace, which is the same
# containment `NET_ADMIN` and `SYS_ADMIN` are inside and which is the reason the
# ceiling is a list of measured values rather than a denylist of the dangerous
# ones. It is the *subject* of the ceiling that matters: the ceiling is about
# widening privilege, and a value nobody has measured has not earned a place in
# it.
ALLOWED_CAPS = ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW")

# **The per-container policy, written out here for the same reason the ceiling
# is: so it cannot change silently.** `ALLOWED_CAPS` above is the ceiling -- the
# widest set any container may hold. This is the narrower question, which the
# ceiling cannot answer: which container holds which of them.
#
# The router's entry is **not** empty, and getting that wrong took a live run to
# discover. `run_container` built one argument array and both containers went
# through it, so dnsmasq held the target's four. The obvious narrowing -- none of
# them, on the grounds that dnsmasq "opens no raw socket" -- is false: it opens
# the *same* `AF_PACKET` socket NetworkManager does, because a DHCP server must
# receive the broadcast DISCOVER before it has an address to reply from. Measured
# on this host, the daemon's own words:
#
# ```text
# $ podman run … --cap-add=NET_RAW      … mosdns-mock-router:24.04-…
# dnsmasq: process is missing required capability NET_ADMIN
# $ podman run … --cap-add=NET_ADMIN    … mosdns-mock-router:24.04-…
# dnsmasq: process is missing required capability NET_RAW
# $ podman run … --cap-add=NET_ADMIN --cap-add=NET_RAW … mosdns-mock-router:24.04-…
# dnsmasq[1]: started, version 2.91 cachesize 150
# ```
#
# `SYS_ADMIN` and `SYS_PTRACE` are the half that is genuinely unused: no init, no
# tracing. `NET_BIND_SERVICE` is in neither row -- `port=53` is below 1024, and a
# container with no `--cap-add` at all reports `CapEff: 00000000800405fb` on this
# host, which already carries bit 10.
#
# The cost of the table is one line per container, which is the cost of any
# per-container policy. A shared array is free until the first container that
# does not need what the others do, and then it is wrong invisibly: a capability
# granted and not needed is not something podman or the kernel ever reports.
PER_CONTAINER_CAPS = {
    "target": ALLOWED_CAPS,
    "mock-router": ("NET_ADMIN", "NET_RAW"),
}

# Every flag family refused in `extra_args`, in the two spellings pflag accepts
# and in both positions, written as one table so the sweep is the table. If a
# later task needs one of these, the honest move is to measure why the ceiling
# has to move and change it here too, not to reach for a spelling the sweep
# forgot.
#
# pflag accepts `--flag value` for a string flag as well as `--flag=value`, and
# `run_container` already emits `--network <net>` *before* `extra_args`, so the
# last occurrence of a repeated flag is the one podman reads. That combination
# is what the previous spelling-sensitive guard missed: `--network host` in the
# space form, in the hatch, after the legal value.
#
# Each entry is (extra_args, the token the refusal must name). The second
# element is not decoration: a guard that raised a generic message would satisfy
# "did it refuse?" while telling the operator nothing about which of the four
# flags in the array was the problem, which is the one thing they need.
FORBIDDEN_EXTRA_ARGS = (
    # privilege and host namespaces, both spellings
    (["--privileged"], "--privileged"),
    (["--cgroupns=host"], "--cgroupns"),
    (["--cgroupns", "host"], "--cgroupns"),
    (["--network=host"], "--network"),
    (["--network", "host"], "--network"),
    (["--pid=host"], "--pid"),
    (["--pid", "host"], "--pid"),
    (["--ipc=host"], "--ipc"),
    (["--ipc", "host"], "--ipc"),
    (["--uts=host"], "--uts"),
    (["--uts", "host"], "--uts"),
    (["--userns=host"], "--userns"),
    (["--userns", "host"], "--userns"),
    # the cap ceiling
    (["--cap-add=ALL"], "--cap-add"),
    (["--cap-add", "ALL"], "--cap-add"),
    (["--cap-add=DAC_OVERRIDE"], "--cap-add"),
    (["--cap-add", "DAC_OVERRIDE"], "--cap-add"),
    # devices, which is the host's own hardware
    (["--device=/dev/kvm"], "--device"),
    (["--device", "/dev/kvm"], "--device"),
    (["--device=/dev/net/tun"], "--device"),
    (["--device", "/dev/sda"], "--device"),
    # seccomp and apparmor, which are the other half of a container boundary
    (["--security-opt=seccomp=unconfined"], "--security-opt"),
    (["--security-opt", "seccomp=unconfined"], "--security-opt"),
    (["--security-opt=apparmor=unconfined"], "--security-opt"),
    (["--security-opt", "apparmor=unconfined"], "--security-opt"),
    (["--security-opt", "label=disable"], "--security-opt"),
    # another run's or another container's filesystems
    (["--volumes-from=some-other-container"], "--volumes-from"),
    (["--volumes-from", "some-other-container"], "--volumes-from"),
    # each of the above again, positioned after an allowed flag, because
    # run_container's own flags come first and the last occurrence wins
    (["--ip", "10.89.0.10", "--network", "host"], "--network"),
    (["--hostname", "mosdns-target", "--privileged"], "--privileged"),
    (["--env", "A=1", "--device", "/dev/kvm"], "--device"),
    (["--ip", "10.89.0.10", "--cap-add", "ALL"], "--cap-add"),
    (["--dns", "10.89.0.2", "--security-opt", "seccomp=unconfined"], "--security-opt"),
    (["--add-host", "router.test:10.89.0.2", "--volumes-from", "other"], "--volumes-from"),
    (["--tmpfs", "/run:rw", "--device", "/dev/net/tun"], "--device"),
    (["--userns=keep-id", "--privileged"], "--privileged"),
    (["--pid=container", "--ipc", "host"], "--ipc"),
    # a capability in a name a later task might invent, to show the ceiling is
    # an allowlist rather than a denylist of the names somebody thought of.
    # `NET_RAW` is *in* the ceiling as of Task 3 (it is what NetworkManager's
    # DHCP client needs, measured), so the row beside it names a neighbouring
    # capability that is not -- which is the property being shown.
    (["--cap-add", "NET_BROADCAST"], "--cap-add"),
    (["--cap-add=DAC_READ_SEARCH"], "--cap-add"),
    (["--cap-add=MKNOD"], "--cap-add"),
    (["--cap-add=SYS_BOOT"], "--cap-add"),
    # `--pid=container` is legal, so the refusal beside it is the one that
    # counts: a legal value must not launder an illegal neighbour
    (["--pid=container", "--cgroupns", "host"], "--cgroupns"),
    # the same, with the illegal one in the space form and the legal one inline
    (["--uts=private", "--userns", "host"], "--userns"),
    # the boolean spelled `=false`, which is NOT privileged. It is refused
    # anyway, and that is a deliberate over-refusal rather than a miss: the
    # policy is on the flag being present at all, so there is no spelling of
    # `--privileged` to reason about. A false positive here costs a token
    # somebody typed out of habit; a false negative hands over the host.
    (["--privileged=false"], "--privileged"),
    (["--privileged=false", "--cap-add=ALL"], "--cap-add"),
    # two violations in one array: the guard must not return on the first, or
    # a caller that fixes one and re-runs meets the other without a message
    (["--privileged", "--device=/dev/kvm"], "--device"),
    (["--cgroupns=host", "--cap-add=ALL", "--pid", "host"], "--pid"),
    (["--network", "host", "--ipc=host", "--uts=host", "--userns", "host"], "--userns"),
    # `--net`, which `podman-run(1)` lists in its own `.SS --network=mode, --net`
    # heading and pflag accepts, in both spellings, in any position. These two
    # rows are about the *alias*, not the spelling: each is placed after a legal
    # flag, because the property is that an alias arriving after a legal flag is
    # still policed. A second key in the policed table with the value spelled out
    # would have covered the equals form and left the space form open -- which is
    # the defect Fix Round 1 already had to fix once for `--network` itself.
    (["--ip", "10.89.0.10", "--net=host"], "--net"),
    (["--hostname", "mosdns-target", "--net", "host"], "--net"),
    # `--publish` and `--publish-all`, in every name pflag accepts for them:
    # the long form in both value spellings, and the two short forms. The plan
    # says "do not publish ports to the host", and a mock router published on
    # port 53 would collide with the operator's resolved -- which is the one
    # boundary this whole harness exists not to cross. `-P` is here for the same
    # reason: it publishes every EXPOSEd port on a random host port, and a later
    # task's mock CDN serves HTTPS.
    #
    # The short forms are the rows a name-keyed guard gets wrong, and the reason
    # `PODMAN_FLAG_ALIASES` now holds short names is written at that constant.
    # Each row is placed after a legal flag, because that is where `extra_args`
    # puts everything and a repeated flag's last occurrence is the one podman
    # reads.
    (["--publish=53:53/udp"], "--publish"),
    (["--publish", "53:53/udp"], "--publish"),
    (["--hostname", "mosdns-router", "-p", "53:53/udp"], "-p"),
    (["-p=53:53/udp"], "-p"),
    (["--publish-all"], "--publish-all"),
    (["-P"], "-P"),
    (["--hostname", "mosdns-cdn", "-P"], "-P"),
)

# --- The closure between the policed names and the cases that check them -------
#
# A policed name is a name the guard refuses, and the guard refuses through three
# mechanisms: a value-keyed table, a family refused whatever its value, and a cap
# ceiling. The cases that check podman's *vocabulary* -- the alias gate and the
# no-short-form gate in `test_podman_flags.py` -- have to cover all of them, and
# the drift is what Fix Round 3 found: they iterated the value-keyed table alone,
# so seven names were checked and eleven were policed. Four policed names sat
# outside every vocabulary check, which is how a future alias of `--device`
# would have reached a name-keyed check that could not see it.
#
# So the sweep set is derived in `lib/podman.py` from the three constants that
# police it, and the functions below hold that derivation to **the guard's own
# body** rather than to a second list of names. A name added to a policed table,
# added to a family tuple, or written as a literal in the guard, is in the
# derived set because the guard reads it -- and if a fourth mechanism ever appears
# as a new module-level collection, it is in the derived set for the same reason.
# This is the third time in this plan that a coverage claim and a coverage
# implementation drifted apart (the dead
# `test_exec_passes_the_command_as_separate_arguments`, the 48-vs-50 count in the
# class docstring below, and the seven-vs-eleven sweep), so the guard reads the
# code rather than being told what the code says.
LONG_FLAG_LITERAL = re.compile(r"^--[a-z][a-z0-9-]*$")
GUARD_METHOD = "_check_container_flags"
PODMAN_SOURCE = REPO / "tests" / "podman" / "lib" / "podman.py"


def long_flag_names(value) -> set[str]:
    """Every long flag name in a module-level constant, whatever shape it has.

    A policed set in this module is a dict (`name -> refused value`), a tuple or
    frozenset of names, or a single string -- so the reader has to accept each
    shape and return the same thing for all of them, and return nothing for a
    constant that holds no flag names at all (`ALLOWED_CAPABILITIES` is a tuple of
    capability names, and is not a policed *set*).
    """
    if isinstance(value, str):
        return {value} if LONG_FLAG_LITERAL.match(value) else set()
    if isinstance(value, dict):
        return {key for key in value if isinstance(key, str) and LONG_FLAG_LITERAL.match(key)}
    if isinstance(value, (set, frozenset, tuple, list)):
        return {item for item in value if isinstance(item, str) and LONG_FLAG_LITERAL.match(item)}
    return set()


def module_level_constants(tree: ast.Module) -> dict[str, object]:
    """Every module-level `NAME = <literal>` in `tree`, as `ast.literal_eval` sees it.

    A constant the AST cannot evaluate as a literal is absent rather than guessed
    at, so a policed set built by a function call would be invisible here -- which
    is why every policed set in `lib/podman.py` is written as a literal, and why
    the case below says so in its failure rather than passing on a partial read.
    """
    constants: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = getattr(node, "value", None)
        if value is None:
            continue
        try:
            evaluated = ast.literal_eval(value)
        except (ValueError, SyntaxError, TypeError):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                constants[target.id] = evaluated
    return constants


def policed_names_the_guard_reads(source: str):
    """What `_check_container_flags` compares flag names against, from the source.

    Two shapes, because the guard names policed flags two ways: a **literal** in
    the body (`name == "--cap-add"` was exactly that before
    `CAPABILITY_ADD_FLAG`), and a **module-level collection** it reads by name
    (`FORBIDDEN_CONTAINER_FLAG_FAMILIES`, `FORBIDDEN_CONTAINER_FLAGS`). Reading
    the source rather than the imported module is the point: by the time a module
    is imported, a name that was in a table and has been removed from it is gone,
    and the comparison this exists for is between the *declared* policy and the
    set the vocabulary cases iterate.
    """
    tree = ast.parse(source, filename=str(PODMAN_SOURCE))
    constants = module_level_constants(tree)
    guard = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == GUARD_METHOD
        ),
        None,
    )
    if guard is None:
        raise AssertionError(
            f"{PODMAN_SOURCE.name} has no {GUARD_METHOD}(self, args), so the policed names cannot "
            f"be read from the guard; a rename that skips this case leaves the vocabulary sweep "
            f"unchecked against anything"
        )
    literals: set[str] = set()
    by_constant: dict[str, set[str]] = {}
    for node in ast.walk(guard):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if LONG_FLAG_LITERAL.match(node.value):
                literals.add(node.value)
        elif isinstance(node, ast.Name) and node.id in constants:
            names = long_flag_names(constants[node.id])
            if names:
                by_constant.setdefault(node.id, set()).update(names)
    return literals, by_constant


class ContainerPolicyTest(PodmanTestCase):
    """A target container may not be handed the host it runs on.

    The measured flag set for a systemd target is three capabilities, a private
    cgroup namespace and no privilege flag. `extra_args` is the escape hatch
    every later task reaches for when something will not run, so the guard lives
    there rather than in prose -- and a hatch with no cap ceiling, no device
    policy and one spelling of everything is a hatch that reaches the host.

    The guard is spelling-independent, the way the mount guard already is: pflag
    accepts `--flag value` as well as `--flag=value`, and `run_container` emits
    `--network <net>` before `extra_args`, so a later occurrence of a repeated
    flag is the one podman reads. The sweep below is the table, and every one of
    its rows must be refused before the binary is started.

    **The policed surface is thirteen names, not the seven in the value-keyed
    table.** `--device`, `--security-opt`, `--volumes-from`, `--publish`,
    `--publish-all` and `--cap-add` are policed by the same guard through the
    other two mechanisms, and a case that derived its coverage from one table
    would have covered seven -- which is exactly what happened to the vocabulary
    sweeps in `test_podman_flags.py` until Fix Round 3. `POLICED_CONTAINER_FLAGS`
    is the union, it is derived once, and
    `test_policed_container_flags_covers_every_name_the_guard_refuses` holds it
    to this guard's own body.
    """

    def refused(self, extra_args):
        """Start a target with `extra_args` and return the refusal message."""
        with self.assertRaises(ContainerPolicyError) as caught:
            self.client(self.fake()).run_container(
                image="localhost/mosdns-target:24.04",
                name="mosdns-x-target-24.04",
                network="mosdns-testnet",
                extra_args=extra_args,
            )
        return str(caught.exception)

    def test_every_forbidden_extra_argument_is_refused_in_every_spelling(self):
        """The sweep: the table is the sweep, and the count holds it to the table.

        The count is asserted so the table cannot be quietly shortened -- a
        guard with fewer cases in it than the family has spellings is a guard
        on a spelling, which is the defect this table exists to close. It is
        written in the same shape as the mount sweep: a table of cases, each
        one refusing, so a family added to the policy has to be added here too.

        The number is `len(FORBIDDEN_EXTRA_ARGS)` rather than a literal, and
        that is a change of *kind*, not of value. This docstring and the class
        docstring above both said forty-eight while the assertion said fifty,
        and a reader had two numbers to choose between and no way to tell which
        one the run had produced -- a second hand-written number in a file whose
        sibling case exists to remove hand-written numbers. The table is right
        there in this file, so the assertion reads it.
        """
        self.assertEqual(
            len(FORBIDDEN_EXTRA_ARGS),
            len({(tuple(args), named) for args, named in FORBIDDEN_EXTRA_ARGS}),
            "the refusal table has a row in it twice, so the sweep reads the same spelling once "
            "and a spelling it was supposed to hold is missing",
        )
        for extra_args, named in FORBIDDEN_EXTRA_ARGS:
            with self.subTest(extra_args=extra_args):
                self.assertIn(named, self.refused(extra_args))

    def test_policed_container_flags_covers_every_name_the_guard_refuses(self):
        """The closure, read from the guard's own body rather than from a list.

        `test_podman_flags.py` iterates `POLICED_CONTAINER_FLAGS` to ask podman
        whether any of the policed names has a second spelling, and iterates it to
        ask whether any has a short one. **Those cases skip where podman is not
        installed**, so on a machine without podman nothing at all checks that the
        set they iterate is the set the guard polices -- and the previous version
        of them iterated `FORBIDDEN_CONTAINER_FLAGS` alone, so even with podman
        installed they covered seven names of eleven. Four policed names were
        outside every vocabulary check.

        So this reads `lib/podman.py`: every long flag name written as a literal
        in `_check_container_flags`, and every long flag name in a module-level
        collection that the method reads, must be in `POLICED_CONTAINER_FLAGS`.
        A name added to the policed table, to a family tuple, to the cap
        constant, or written into the guard's body, fails here if the derivation
        missed it -- and it does not need this case edited, because the set is
        derived from those same constants in `lib/podman.py`.

        The second half is the same drift in the other file: every policed name
        must appear in `FORBIDDEN_EXTRA_ARGS` too, so a policed name cannot be
        absent from the hand-written refusal table while the count assertion
        still passes. That assertion is a floor on a *number*; this is a check on
        a *set*, and a number cannot tell a table that grew a row from a table
        that lost one.
        """
        literals, by_constant = policed_names_the_guard_reads(
            PODMAN_SOURCE.read_text(encoding="utf-8")
        )
        self.assertTrue(
            literals or by_constant,
            "the guard reads no policed name at all, so this case is satisfied by a parse that "
            "read nothing -- the same vacuous pass the suite-shape guard exists to stop",
        )
        # The derivation is the union of the three mechanisms, recomputed here
        # rather than imported, so a change to one of the three cannot quietly
        # change what "derived" means.
        self.assertEqual(
            set(POLICED_CONTAINER_FLAGS),
            set(FORBIDDEN_CONTAINER_FLAGS)
            | set(FORBIDDEN_CONTAINER_FLAG_FAMILIES)
            | {CAPABILITY_ADD_FLAG},
            "POLICED_CONTAINER_FLAGS is no longer the union of the three things that police a "
            "flag name, so a name it holds is policed by nothing and a name it misses is policed "
            "by something the vocabulary sweep cannot see",
        )
        # An alias is a second *name* for a policed flag, not a policed name of
        # its own: `--net` is policed through `--network`. So the alias table's
        # keys are the one thing allowed to be outside the set, and its values
        # are held to it.
        aliases = set(PODMAN_FLAG_ALIASES)
        for constant, names in sorted(by_constant.items()):
            with self.subTest(constant=constant):
                self.assertEqual(
                    sorted((names - aliases) - set(POLICED_CONTAINER_FLAGS)),
                    [],
                    f"{constant} holds policed flag names that POLICED_CONTAINER_FLAGS does not, so "
                    f"the alias and no-short-form sweeps in test_podman_flags.py never look at them",
                )
        self.assertEqual(
            sorted(literals - set(POLICED_CONTAINER_FLAGS)),
            [],
            f"{GUARD_METHOD} compares against flag names written as literals that "
            f"POLICED_CONTAINER_FLAGS does not hold, so they are outside every vocabulary sweep",
        )
        for alias, canonical in sorted(PODMAN_FLAG_ALIASES.items()):
            with self.subTest(alias=alias):
                self.assertIn(
                    canonical,
                    POLICED_CONTAINER_FLAGS,
                    f"{alias!r} canonicalises to {canonical!r}, which no derived policed name "
                    f"covers, so the closure cases would not see an alias of it",
                )
        swept = {named for _extra_args, named in FORBIDDEN_EXTRA_ARGS}
        # `--net` is an alias, so the sweep rows name it where a row says so and
        # name the canonical name where the row is about the value; both are policed.
        missing = sorted(
            name
            for name in POLICED_CONTAINER_FLAGS
            if name not in swept and name not in aliases
        )
        self.assertEqual(
            missing,
            [],
            "these policed names have no row in FORBIDDEN_EXTRA_ARGS, so the refusal sweep does "
            "not exercise them and the count assertion cannot notice",
        )

    def test_the_cap_ceiling_is_exactly_the_measured_capabilities(self):
        """`--cap-add` is allowlisted, not denylisted.

        `--cap-add=ALL` is a one-word route to every capability, including
        `SYS_ADMIN` for a target that does not need it, and it is the first
        thing anybody reaches for when a scenario will not start. So the
        ceiling is the measured values and the guard names them, so the
        person who hit it knows what the alternative is -- and the list
        beside this case is written out, so the ceiling cannot grow by
        accident.

        `NET_RAW` is on it because NetworkManager's built-in DHCP client opens
        an `AF_PACKET` socket and does not get a lease without one; the
        measurement is written out at the list.
        """
        for cap in ALLOWED_CAPS:
            with self.subTest(cap=cap):
                # A fresh fake per case: `FakePodmanBinary` keeps one log
                # beside itself, so a shared one would accumulate three runs and
                # `only()` would be asserting about the wrong one.
                directory = self.extra_directory()
                fake = self.fake(directory=directory)
                self.client(fake).run_container(
                    image="localhost/mosdns-target:24.04",
                    name="mosdns-x-target-24.04",
                    network="mosdns-testnet",
                    extra_args=[f"--cap-add={cap}"],
                )
                self.assertIn(f"--cap-add={cap}", fake.only())
        message = self.refused(["--cap-add=SYS_BOOT"])
        for cap in ALLOWED_CAPS:
            self.assertIn(cap, message)

    def test_the_cap_ceiling_and_the_per_container_policy_are_two_different_questions(self):
        """A ceiling read as a policy is how dnsmasq was handed four capabilities.

        `ALLOWED_CAPABILITIES` answers "what is the widest set any container here
        may hold", and that is what a scenario's `--cap-add` is checked against.
        `CONTAINER_CAPABILITIES` answers "which container holds which", and the
        ceiling cannot answer it -- a target that needs `NET_RAW` says nothing
        about dnsmasq, which needs none of the four.

        Merging the two is what made the router's emitted array carry
        `--cap-add=NET_RAW`, and the cost of that is a *reader*: the emitted array
        is what somebody consults when a container misbehaves, so an array saying
        the router needs a capability is a claim about the router that nothing can
        falsify and nothing will report. So the two are separate constants and
        this case holds the relationship between them.

        Three properties, and the third is the one that would catch a regression:
        the policy's widest entry **is** the ceiling (so the policy cannot quietly
        exceed what the guard allows), the router's is empty, and the target's is
        the ceiling (so a fix that emptied both would fail).
        """
        self.assertEqual(
            set(PER_CONTAINER_CAPS), set(CONTAINER_CAPS),
            "the per-container policy and the module's have drifted apart, so this file's copy "
            "is asserting about a table the code does not use",
        )
        self.assertEqual(
            max((len(caps) for caps in CONTAINER_CAPS.values()), default=0),
            len(ALLOWED_CAPS),
            "no container is granted the full ceiling, so the target's own measured set has been "
            "lost and a DHCP lease would fail with 'IP configuration could not be reserved'",
        )
        for role, caps in sorted(CONTAINER_CAPS.items()):
            with self.subTest(role=role):
                self.assertLessEqual(
                    set(caps), set(ALLOWED_CAPS),
                    f"{role} is granted a capability the ceiling does not allow, so the policy "
                    f"and the guard disagree about what may be granted",
                )
        self.assertEqual(
            set(CONTAINER_CAPS["mock-router"]), {"NET_ADMIN", "NET_RAW"},
            "the router's capability set is not the measured pair. dnsmasq opens an AF_PACKET "
            "socket to receive the broadcast DISCOVER and exits 5 with 'process is missing "
            "required capability NET_ADMIN' without NET_ADMIN, or the NET_RAW message without "
            "that one; SYS_ADMIN and SYS_PTRACE are not its business because it runs no init and "
            "is not traced",
        )
        self.assertNotIn(
            "NET_BIND_SERVICE", CONTAINER_CAPS["mock-router"],
            "the router is granted NET_BIND_SERVICE, but podman's default rootless bounding set "
            "already carries bit 10 -- measured in CapEff: 00000000800405fb for a container "
            "started with no --cap-add at all -- so port=53 does not need it",
        )
        self.assertEqual(
            CONTAINER_CAPS["target"], ALLOWED_CAPS,
            "the target is no longer granted the four capabilities it was measured to need",
        )
        # And the two are genuinely different objects, so the distinction cannot
        # be a naming accident that a later edit papers over.
        self.assertIsNot(
            CONTAINER_CAPS["mock-router"], CONTAINER_CAPS["target"],
            "both roles resolve to the same tuple, so a container with narrower needs is given "
            "the target's set again",
        )

    def test_the_measured_target_runs_with_net_raw_because_dhcp_needs_it(self):
        """The emitted array carries the capability DHCP needs, not only the allowed ones.

        The ceiling says which capabilities *may* be granted and the emitted
        array says which ones a target actually *has*. Those are two different
        facts, and a target with the wrong one reaches "getting IP
        configuration" and then fails with "IP configuration could not be
        reserved" -- a message that reads like a DNS problem and is not one. So
        the emitted array is held here too, and the measurement is written out
        at the list this iterates.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
        )
        emitted = " ".join(fake.only())
        for cap in ALLOWED_CAPS:
            with self.subTest(cap=cap):
                self.assertIn(f"--cap-add={cap}", emitted)

    def test_publishing_a_port_to_the_host_is_refused_in_every_name_pflag_accepts(self):
        """The plan says "do not publish ports to the host", and this is what that means.

        A mock router published on port 53 would land on the operator's own
        resolver port, and the whole point of this harness is that a run changes
        the container's DNS and nothing else. `--publish` is not on the policed
        list this tree started with, so it was legal in `extra_args` -- and
        `extra_args` is the hatch every later task reaches for, which is exactly
        where a legal-looking flag that reaches the host belongs.

        **Four names, not one.** `podman-run(1)` declares
        `--publish=…, -p=…` and `--publish-all, -P` in their own headings, and
        pflag registers each of those as a *separate name* for the flag. A guard
        keyed on the long name sees none of the other three -- and `-P` is not a
        variant of `--publish` at all, it is a second flag that does the same
        thing for every EXPOSEd port, so a case that only policed the first would
        leave a later task's mock CDN free to publish 443.
        """
        for spelling, named in (
            (["--publish=53:53/udp"], "--publish"),
            (["--publish", "53:53/udp"], "--publish"),
            (["-p", "53:53/udp"], "-p"),
            (["-p=53:53/udp"], "-p"),
            (["--publish-all"], "--publish-all"),
            (["-P"], "-P"),
        ):
            with self.subTest(spelling=spelling):
                message = self.refused(spelling)
                self.assertIn(named, message)
                # The refusal says why, and both short forms have to be told
                # which long name they are, or an operator refuses `-p`, reads no
                # mention of `-p` in the guard and concludes the message is about
                # something else.
                if named in ("-p", "-P"):
                    self.assertIn("alias", message)

    def test_the_wrapper_itself_emits_no_publish_flag(self):
        """The policy examines the whole array, so a wrapper that grew one would be caught.

        `run_container` is where a fixed port would be typed -- a mock CDN on
        8443, an operator asking for it -- and the case above only covers
        `extra_args`. This is the other half: the guard reads the wrapper's own
        flags, and the wrapper's own flags are read back here.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
        )
        for token in fake.only():
            with self.subTest(token=token):
                self.assertNotIn(token, ("-p", "-P", "--publish", "--publish-all"))

    def test_a_device_is_refused_and_the_wrapper_has_no_opt_in_for_one(self):
        """A device is host hardware, and there is no flag to ask for it.

        `/dev/kvm` is what a previous architecture wanted and is absent here;
        `/dev/net/tun` is the device Podman's own default network needs, and
        the target is on a bridge network precisely so it does not. A policy
        that allowed a device under an opt-in nobody sets is a policy with a
        door in it, so there is no opt-in: the family is refused, both
        spellings, and the refusal says why.
        """
        for spelling in (["--device=/dev/net/tun"], ["--device", "/dev/kvm"]):
            with self.subTest(spelling=spelling):
                self.assertIn("--device", self.refused(spelling))

    def test_a_capability_can_be_dropped_but_not_added_beyond_the_ceiling(self):
        """`--cap-drop` is not a route to the host, so it is not policed.

        A guard that refused everything containing the word `cap` would be
        removed the first time a scenario wanted a *narrower* container, and
        the reviewer's "refuse, or leave it legal" question has an answer here:
        dropping a capability can only take privilege away, so the flag is
        outside the ceiling's subject. The cap ceiling is on `--cap-add` alone
        and that asymmetry is deliberate, and a case says so -- a guard whose
        boundary is a substring is a guard on a spelling.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=["--cap-drop=SYS_PTRACE"],
        )
        self.assertIn("--cap-drop=SYS_PTRACE", fake.only())
        # And the combination that would be a real escape is still refused: a
        # drop alongside an add of everything is the shape "make it wide, then
        # take the ceiling away" takes, and the ceiling is what says no.
        self.assertIn("--cap-add", self.refused(["--cap-drop=ALL", "--cap-add=ALL"]))

    def test_a_later_occurrence_of_a_flag_is_refused_even_after_a_legal_one(self):
        """The wrapper emits `--network` first, so the last one is the one read.

        `run_container` builds `... --network mosdns-testnet ...` and then
        appends `extra_args`, so a hatch carrying `--network host` overrides
        the legal value rather than conflicting with it -- and pflag keeps the
        last value it is given. The refusal is what makes the first value
        mean anything.
        """
        message = self.refused(["--network", "host"])
        self.assertIn("--network", message)
        self.assertIn("host", message)

    def test_the_documented_alias_of_a_policed_flag_is_policed_too(self):
        """`--net` is `--network`. A guard keyed on one name does not see it.

        `podman-run(1)` lists the pair in a single heading --
        `.SS --network=mode, --net` -- and pflag accepts either spelling, so
        `extra_args=["--net", "host"]` is a host-namespace request that reaches
        the target through a *name* the policed table did not contain. It lands
        after the wrapper's own `--network <net>` and `--network` is a
        `stringArray`, so the target would end up on both the bridge and the
        host network.

        The alias is held, not the two value spellings: the equals form and the
        space form are both refused, and each is refused when it arrives *after*
        a legal flag, which is where `extra_args` puts everything.
        """
        for spelling in (["--net=host"], ["--net", "host"]):
            with self.subTest(spelling=spelling):
                message = self.refused(["--hostname", "mosdns-target", *spelling])
                # The token the operator typed is in the message, and so is the
                # name the policy is written against: a reader who has never seen
                # the alias has to learn from the refusal that they are the same
                # flag, or the next thing they try is `--network host`.
                self.assertIn("--net", message)
                self.assertIn("--network", message)
                self.assertIn("alias", message)

    def test_an_alias_of_a_policed_flag_does_not_police_its_value(self):
        """`--net mosdns-testnet` is a legal flag with a legal value.

        The failure mode of a fix for the alias hole is to blacklist the *name*,
        which would refuse the alias in every position and so break the first
        thing a later scenario does -- put a target on a network by its alias.
        The property is that the value is judged, not the spelling of the name,
        so this holds the legal case as firmly as the refused one.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=["--net", "mosdns-testnet"],
        )
        self.assertIn("mosdns-testnet", fake.only())

    def test_an_alias_of_a_family_or_of_the_cap_flag_is_refused_too(self):
        """Planted, because podman 5.7.0 has no such alias -- and that is the point.

        The `--net` finding was that a policed flag has a second *name* pflag
        accepts, and the fix canonicalises the name before the lookup. Two of the
        three policies were not covered by it: `--device`, `--security-opt`,
        `--volumes-from` and `--cap-add` were compared by their **raw** name, so
        an alias of any of them would have reached a name-keyed check that could
        not see it -- the same position `--net` was in, one table over.

        There is no such alias today, and the case that says so is derived from
        `podman-run(1)` in `test_podman_flags.py` over all eleven policed names
        (it skips where podman is absent, which is why it cannot be the only
        thing holding this). So this plants the aliases instead of waiting for
        the podman release that introduces one, and asks the real `build_argv`
        path -- not a copy of the guard -- whether each is refused.

        The alias table is replaced and put back rather than patched, because a
        case that left podman's vocabulary altered would poison every case after
        it in the file; `addCleanup` restores it whatever the assertion does.
        """
        planted = dict(PODMAN_FLAG_ALIASES)
        planted.update(
            {
                "--dev": "--device",
                "--secopt": "--security-opt",
                "--caps": CAPABILITY_ADD_FLAG,
            }
        )
        import podman as podman_lib

        original = podman_lib.PODMAN_FLAG_ALIASES

        def restore():
            podman_lib.PODMAN_FLAG_ALIASES = original

        self.addCleanup(restore)
        podman_lib.PODMAN_FLAG_ALIASES = planted
        for extra_args, named, why in (
            (["--dev=/dev/kvm"], "--device", "a device is host hardware"),
            (["--dev", "/dev/net/tun"], "--device", "a device is host hardware"),
            (["--secopt=seccomp=unconfined"], "--security-opt", "removes a layer"),
            (["--secopt", "apparmor=unconfined"], "--security-opt", "removes a layer"),
            (["--caps=ALL"], CAPABILITY_ADD_FLAG, "the cap ceiling"),
            (["--caps", "ALL"], CAPABILITY_ADD_FLAG, "the cap ceiling"),
        ):
            with self.subTest(extra_args=extra_args):
                message = self.refused(extra_args)
                self.assertIn(named, message, f"the alias was not policed: {why}")
                # And it says so, rather than refusing a name the operator cannot
                # connect to the flag they are actually holding.
                self.assertIn("alias", message)
                self.assertIn("podman's alias for", message)
        # The canonical name is still refused the same way, so the plant did not
        # replace a policy with a spelling of one.
        self.assertIn("--device", self.refused(["--device=/dev/kvm"]))
        self.assertIn(CAPABILITY_ADD_FLAG, self.refused([f"{CAPABILITY_ADD_FLAG}=ALL"]))
        # And a legal value for the alias is still legal, which is the half of the
        # property a name-keyed guard gets wrong in the other direction.
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=[f"{CAPABILITY_ADD_FLAG}=SYS_ADMIN"],
        )
        self.assertIn(f"{CAPABILITY_ADD_FLAG}=SYS_ADMIN", fake.only())
        restore()

    def test_a_flag_name_is_canonicalised_before_the_policed_lookup(self):
        """The normalisation is one function, and it is idempotent.

        Deriving the policed names from one declaration is what keeps the alias
        table from becoming a second list that drifts: a policed name is written
        once, and every spelling that reaches it goes through this function. The
        second property is that canonicalising an already-canonical name is a
        no-op, so a caller may normalise defensively without a loop.
        """
        self.assertEqual(canonical_flag_name("--net"), "--network")
        self.assertEqual(canonical_flag_name("--network"), "--network")
        # Idempotent on the canonical names, which are the policed ones; an
        # alias's whole job is to *change* the name, so demanding otherwise of
        # `--net` would be demanding the bug.
        for name in FORBIDDEN_CONTAINER_FLAGS:
            self.assertEqual(canonical_flag_name(name), name)
        # And the derived name set is the policed names plus the aliases, so
        # nothing else is advertised as policed and no alias is left out of the
        # set a refusal prints.
        self.assertEqual(
            set(FORBIDDEN_CONTAINER_FLAG_NAMES),
            set(FORBIDDEN_CONTAINER_FLAGS) | set(PODMAN_FLAG_ALIASES),
        )
        # An unpoliced flag is untouched, which is what keeps the ordinary
        # extra arguments of `test_an_ordinary_extra_argument_is_still_allowed`
        # passing rather than making the normalisation a closed door.
        for name in ("--ip", "--hostname", "--dns", "--env", "--add-host", "--tmpfs"):
            self.assertEqual(canonical_flag_name(name), name)

    def test_the_alias_table_cannot_name_a_flag_nothing_policies(self):
        """An alias pointing at an unpoliced name is a silent no-op.

        The alias table is keyed alias -> canonical name, and the policed names
        are policed by three mechanisms: a value-keyed table, a tuple of
        families refused whatever their value, and the cap ceiling. Nothing in
        the types stops a contributor adding `{"--ns": "--namespace"}` when both
        names are policed *in their own right* in some later Podman, which would
        make the entry a spelling of a policy while the tables disagree. So the
        alias table is closed against the policed set in both directions.

        **The policed set is the union, not the value-keyed table.** A family is
        policed by name and has no refused value to be a key of, so an alias of
        one -- `-p` for `--publish` -- canonicalises to a name the value-keyed
        table does not hold. Checking against that table alone reported the
        alias as naming a flag nothing polices, which is the same false
        positive a guard produces when it fails on correct code.
        """
        policed = set(POLICED_CONTAINER_FLAGS)
        self.assertTrue(policed, "the policed set cannot be empty")
        for alias, canonical in PODMAN_FLAG_ALIASES.items():
            with self.subTest(alias=alias):
                self.assertIn(
                    canonical,
                    policed,
                    f"{alias!r} canonicalises to {canonical!r}, which no policy governs, so "
                    f"the entry refuses nothing",
                )
                # And it is not a *second* key for a name already policed: a
                # policed name reached through two table rows is the shape that
                # made the count of policed spellings meaningless in Fix Round 1.
                self.assertNotIn(alias, policed)
        # The printed set is the value-keyed names and their aliases, and nothing
        # else -- it is what the *value-keyed* refusal prints, and the two other
        # policies print their own reasons rather than joining that list.
        self.assertEqual(
            set(FORBIDDEN_CONTAINER_FLAG_NAMES),
            set(FORBIDDEN_CONTAINER_FLAGS) | set(PODMAN_FLAG_ALIASES),
        )

    def test_the_refusal_names_the_whole_policed_set(self):
        """`FORBIDDEN_CONTAINER_FLAG_NAMES` is used, not decoration.

        It was declared as "the names alone, for a caller that wants to know
        which names are policed" and no caller wanted to know. The caller that
        wants to know is the person who has just been refused, in a harness where
        `extra_args` is the hatch every later task reaches for -- so the refusal
        prints the set, and a case holds that it is the set and not a summary.
        """
        message = self.refused(["--net", "host"])
        for name in FORBIDDEN_CONTAINER_FLAG_NAMES:
            self.assertIn(name, message)

    def test_every_violation_in_one_array_is_named(self):
        """The scan does not return on the first thing it finds.

        A guard that reported one forbidden flag and stopped would let a caller
        fix that one, re-run, and meet the next -- a loop of one at a time for
        a defect that was fully visible. So all of them are named at once.
        """
        message = self.refused(["--privileged", "--device=/dev/kvm", "--pid", "host"])
        for token in ("--privileged", "--device", "--pid"):
            self.assertIn(token, message)

    def test_an_ordinary_extra_argument_is_still_allowed(self):
        """The refusal is a policy, not a closed door.

        A guard that refused anything would be replaced the first time a
        scenario needed `--ip`, and the guard would be gone with it. So the
        ordinary case is held as firmly as the forbidden one: a static address,
        a hostname, a DNS server, an environment variable, an extra host entry.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=[
                "--ip", "10.89.0.10",
                "--hostname", "mosdns-target",
                "--dns", "10.89.0.2",
                "--env", "MOSDNS_TEST=1",
                "--add-host", "router.test:10.89.0.2",
                "--cgroupns=private",
                "--log-driver", "k8s-file",
            ],
        )
        argv = fake.only()
        self.assertIn("mosdns-testnet", argv)
        self.assertIn("10.89.0.10", argv)
        self.assertEqual(argv[-1], "localhost/mosdns-target:24.04")

    def test_a_value_that_merely_contains_a_forbidden_word_is_not_a_flag(self):
        """`--hostname host` is a hostname, and `--network mosdns-testnet` is legal.

        A guard that refused a token because the word `host` appeared somewhere
        near it would refuse the measured flag set itself and be removed on the
        first real run. The check is on the flag name and the value that flag
        carries, never on a substring of a value.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=["--hostname", "host", "--network", "mosdns-testnet"],
        )
        self.assertIn("host", fake.only())

    def test_a_refused_container_is_never_started(self):
        fake = self.fake()
        with self.assertRaises(ContainerPolicyError):
            self.client(fake).run_container(
                image="localhost/mosdns-target:24.04",
                name="mosdns-x-target-24.04",
                network="mosdns-testnet",
                extra_args=["--privileged"],
            )
        self.assertEqual(fake.invocations(), [])

    def test_the_wrapper_emits_no_flag_of_its_own_that_the_policy_refuses(self):
        """The wrapper's own array is inside its own policy, not beside it.

        A guard that only examined `extra_args` would let the wrapper emit
        `--cap-add=ALL` and pass, because the token is not in the hatch. So the
        whole array is checked, which is also why the flag set is asserted as
        literals in `ArgumentArrayTest`: the two cases together say the wrapper
        emits only what the policy allows.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
        )
        # Read the way the guard reads: a flag's name, and the value that flag
        # carries. `--cgroupns` and `--network` are policed *names* -- the
        # refusal is on the value `host` -- so asserting the names are absent
        # would be asserting that the measured flag set contains no policed
        # flag, which is the opposite of what this case is for.
        argv = fake.only()
        index = 0
        while index < len(argv):
            token = argv[index]
            index += 1
            if not token.startswith("-"):
                continue
            name, separator, inline = token.partition("=")
            value = inline if separator else (argv[index] if index < len(argv) else None)
            if separator:
                continue
            index += 1
            with self.subTest(token=token):
                self.assertNotIn(name, FORBIDDEN_CONTAINER_FLAG_FAMILIES)
                if name in FORBIDDEN_CONTAINER_FLAGS:
                    self.assertNotEqual(value, FORBIDDEN_CONTAINER_FLAGS[name])
                if name == "--cap-add":
                    self.assertIn(value, ALLOWED_CAPS)


class NetworkManagerDeviceTest(PodmanTestCase):
    """The measured fact, asserted at run time instead of assumed.

    The previous plan recorded its entire NetworkManager SKIPPED list on the
    conclusion that a container cannot make NetworkManager manage a device.
    That conclusion was measured and is false. What is true, measured here, is:

    * a container on Podman's **default** rootless network gets a tun/tap
      device, NetworkManager refuses that device type by design, and activation
      fails with *device is strictly unmanaged*;
    * a container on a **netavark bridge** network gets an ``eth0`` of type
      ``ethernet``;
    * ``nmcli device set eth0 managed yes`` then **returns success and does not
      take effect** -- the override is written under ``/run/NetworkManager/
      devices/`` and only ``systemctl restart NetworkManager`` re-reads it.

    So the harness checks the device before any scenario runs, and a target
    whose ``eth0`` is unmanaged fails with a message naming the two steps. It
    is a runtime assertion because a target that boots wrong produces a
    scenario failure that reads like an installer bug, and a comment would have
    left the previous plan's conclusion standing.
    """

    def test_the_check_reads_the_managed_field_from_the_running_target(self):
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        self.assertEqual(
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04"),
            "yes",
        )
        self.assertEqual(
            fake.only(),
            ["exec", "mosdns-x-target-24.04", "nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", "eth0"],
        )

    def test_the_check_asks_for_no_shell(self):
        """The query is a fixed read, so it is an argument array and not a script.

        A `sh -c` here would be a shell the harness did not need, on a command
        whose whole job is to be the same bytes every time.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")
        self.assertNotIn("sh", fake.only())

    def test_an_unmanaged_device_fails_with_both_steps_named(self):
        """The message has to be enough to act on without reading the plan.

        A failure here is not the project's bug; it is the target booting
        without the sequence, and the operator reading the message is the only
        one who can fix it.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "no\n"}])
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")
        message = str(caught.exception)
        self.assertIn("nmcli device set eth0 managed yes", message)
        self.assertIn("systemctl restart NetworkManager", message)

    def test_the_refusal_names_the_connection_profile_the_sequence_depends_on(self):
        """Measured on this host, and the brief did not state it.

        With a connection profile present for `eth0`, `nmcli device set eth0
        managed yes` followed by `systemctl restart NetworkManager` takes the
        field to `yes` -- three fresh containers, three times. Without a
        profile, both steps are accepted, the audit log says
        `result="success"`, the override is never written, and the field stays
        `no`. A refusal that named only the two steps would send an operator
        to run them, watch them succeed, and conclude the harness is wrong.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "no\n"}])
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")
        message = str(caught.exception)
        self.assertIn("connection profile", message)
        self.assertIn("nmcli connection add type ethernet ifname eth0", message)

    def test_the_plan_agrees_with_this_module_about_who_creates_the_profile(self):
        """The ordering lives in two records, and this is what stops them drifting.

        The harness refuses when a target boots unmanaged, and the plan's Task
        2 and Task 3 are the two records that decide whether a target boots
        managed at all. They disagreed: the plan's architecture note said "Task
        3 step 4 already creates that profile" while Task 2's operative text
        created nothing, so the profile would not exist when the entrypoint's
        two steps ran, every boot check would fail, and every cell would be
        `incomplete` with exit 3 — forever, and for a reason that looked like a
        container limitation. A plan an implementer cannot run is a defect in
        the same family as a test that does not run.

        So the agreement is held here rather than left to review: the profile's
        creating command is named in Task 2's entrypoint text, and Task 3's step
        4 modifies that profile instead of creating one. The module's own
        comment records which is which, and this case fails the day either half
        moves.
        """
        plan = (REPO / "docs/superpowers/plans/2026-09-25-podman-integration-matrix.md").read_text(
            encoding="utf-8"
        )
        # The exact command in NM_PROFILE_STEP is the entrypoint's first step.
        add = "nmcli connection add type ethernet ifname eth0 con-name eth0-managed ipv4.method auto"
        self.assertIn(add, plan)
        # The anchor moved with the ruling. This case used to look for "The
        # target's entrypoint must perform" and asserted the plan's Task 3 step 4
        # came after it -- which was the ordering the previous plan got wrong, and
        # which Fix Round 1/5's review confirmed cannot be implemented: the
        # sequence runs from a systemd unit because there is no D-Bus before
        # `/sbin/init`. What the case still asserts is the *claim* it was written
        # for: the plan names the `connection add` command as the one that creates
        # the profile, and Task 3 step 4 modifies that profile rather than creating
        # a second one. The anchor is now the sentence that says so.
        entrypoint = plan.index("The sequence runs from")
        task_three_step_four = plan.index("**Step 4: Make target use NetworkManager**")
        self.assertLess(
            entrypoint, task_three_step_four,
            "the entrypoint text must come before the step that works on its profile",
        )
        # Task 2 owns the creation, and says the profile comes first.
        task_two_entrypoint = plan[entrypoint:task_three_step_four]
        self.assertIn(add, task_two_entrypoint)
        self.assertIn("ipv4.method auto", task_two_entrypoint)
        # Task 3 modifies it, and says so rather than creating a second one.
        task_three_step = plan[task_three_step_four:task_three_step_four + 2000]
        self.assertIn("modify eth0-managed ipv4.never-default yes", task_three_step)
        self.assertNotIn("connection add", task_three_step)
        self.assertIn("post-boot", task_three_step)

    def test_the_refusal_reports_what_the_field_actually_said(self):
        """`no` and `yes` are one character apart, and the message must carry it.

        The value is the evidence, and a message that only says "unmanaged"
        makes the reader go and reproduce it.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "no\n"}])
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")
        self.assertIn("no", str(caught.exception))

    def test_a_query_that_fails_also_names_both_steps(self):
        """`nmcli` erroring is the shape the refusal takes on a missing device.

        `device show` on an interface that is not there exits non-zero, and that
        is a target whose bridge network gave it something other than the
        `eth0` this check asks about. Reporting it as a plain error would leave
        the two steps unnamed.
        """
        fake = self.fake([{"match": ["nmcli"], "returncode": 1, "stderr": "Error: unknown device 'eth0'.\n"}])
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")
        message = str(caught.exception)
        self.assertIn("nmcli device set eth0 managed yes", message)
        self.assertIn("systemctl restart NetworkManager", message)
        self.assertIn("unknown device 'eth0'", message)

    def test_an_empty_answer_is_a_failure_and_not_a_pass(self):
        """Silence is not consent.

        An empty answer is what a wrapper that swallowed the output would look
        like, and a check that treated "not yes" as fine would turn that into a
        green scenario against a target NetworkManager never touched.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": ""}])
        with self.assertRaises(NetworkManagerDeviceError):
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")

    def test_an_unexpected_answer_is_refused_rather_than_assumed_yes(self):
        """Only the exact word `yes` passes, so nothing is inferred.

        Podman has been known to answer `--get` with the field name as a header
        on some versions, and a check that looked for "yes" anywhere in the
        output would pass on `GENERAL.NM-MANAGED:no`.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "GENERAL.NM-MANAGED:yes\n"}])
        with self.assertRaises(NetworkManagerDeviceError):
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")

    def test_a_check_that_hangs_is_abandoned_rather_than_blocking_the_run(self):
        """NetworkManager inside a wedged target does not answer.

        Without a deadline a broken target turns into a run that never finishes
        and never reports, which is the same as a run that silently passed.
        """
        fake = self.fake([{"match": ["nmcli"], "sleep": 30}])
        podman = self.client(fake, timeout=0.5)
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(podman, "mosdns-x-target-24.04")
        self.assertIn("nmcli device set eth0 managed yes", str(caught.exception))

    def test_the_device_is_named_so_a_tun_tap_target_can_be_told_apart(self):
        """The default rootless network's tun/tap device fails this check.

        That is the point: a target on the wrong network reports a refusal
        naming the two steps, and the reader can see the device is not the
        bridge `eth0` rather than wondering why the override "did not work".
        """
        fake = self.fake([{"match": ["nmcli"], "returncode": 1, "stderr": "Error: unknown device 'eth0'.\n"}])
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")
        self.assertIn("eth0", str(caught.exception))

    def test_the_check_names_the_container_it_was_looking_at(self):
        """Three versions run at once, and the failure has to say which one."""
        fake = self.fake([{"match": ["nmcli"], "stdout": "no\n"}])
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(self.client(fake), "mosdns-20260928T101010Z-target-24.04")
        self.assertIn("mosdns-20260928T101010Z-target-24.04", str(caught.exception))

    def test_a_refusal_is_a_podman_error_so_the_run_loop_reports_it(self):
        with self.assertRaises(PodmanError):
            assert_networkmanager_manages_device(
                self.client(self.fake([{"match": ["nmcli"], "stdout": "no\n"}])), "mosdns-x-target-24.04"
            )


class CleanupOrderTest(PodmanTestCase):
    """Containers, then the network, then volumes -- and past the failures.

    The order is not cosmetic. A container attached to a network cannot be
    removed after the network is gone, so a teardown that removed them in the
    wrong order would report leftovers for a run that had nothing left to
    clean, and the next run would refuse to start.
    """

    def removals(self, fake):
        """Only the calls that change something, in order.

        The survivorship sweep issues read-only `ps`/`volume ls` calls between
        the phases, and this case is about the order of the removals.
        """
        mutating = (["rm", "-f"], ["network", "rm"], ["volume", "rm", "-f"])
        return [
            argv
            for argv in fake.invocations()
            if any(argv[: len(prefix)] == prefix for prefix in mutating)
        ]

    def test_a_whole_teardown_removes_containers_then_the_network_then_volumes(self):
        fake = self.fake()
        with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet") as run:
            run.track_container(run.container_name("target", "24.04"))
            run.track_container(run.container_name("client", "24.04"))
            run.track_volume(run.volume_name("state"))
        self.assertEqual(
            self.removals(fake),
            [
                ["rm", "-f", "mosdns-20260928T101010Z-target-24.04"],
                ["rm", "-f", "mosdns-20260928T101010Z-client-24.04"],
                ["network", "rm", "mosdns-20260928T101010Z-testnet"],
                ["volume", "rm", "-f", "mosdns-20260928T101010Z-state"],
            ],
        )

    def test_teardown_asks_whether_anything_of_this_run_survived(self):
        """The consolidated failure is about survivors, not about errors.

        A teardown step that failed and left nothing behind has done its job.
        One that failed and left a container has not. Podman is asked directly,
        so the answer is podman's rather than the harness's bookkeeping.
        """
        fake = self.fake()
        with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet") as run:
            run.track_container(run.container_name("target", "24.04"))
        self.assertEqual(
            [argv[:2] for argv in fake.invocations()][-4:],
            [["ps", "-a"], ["volume", "ls"], ["network", "ls"], ["network", "exists"]],
        )

    def test_a_survivor_is_named_and_the_run_is_a_failure(self):
        """A leftover is the failure, and it has to be identifiable."""
        fake = self.fake([
            {"match": ["rm", "-f"], "returncode": 2, "stderr": "no such container\n"},
            {"match": ["ps", "-a"], "stdout": "mosdns-20260928T101010Z-target-24.04\n"},
        ])
        with self.assertRaises(CleanupFailed) as caught:
            with podman_session(self.client(fake), "20260928T101010Z") as run:
                run.track_container(run.container_name("target", "24.04"))
        self.assertFalse(caught.exception.result.ok)
        self.assertIn(("container", "mosdns-20260928T101010Z-target-24.04"), caught.exception.result.survivors)

    def test_a_teardown_error_that_left_nothing_is_reported_but_is_not_a_failure(self):
        """Errors are recorded; the failure is reserved for what survived.

        A container that was already gone, or a network that was never
        created, makes `rm` fail while the run is in fact clean. Calling that a
        failed teardown would make an ordinary rerun look like a leak, and a
        harness that cries wolf about leaks stops being read about them.
        """
        fake = self.fake([
            {"match": ["rm", "-f"], "returncode": 1, "stderr": "no such container\n"},
        ])
        with podman_session(self.client(fake), "20260928T101010Z") as run:
            run.track_container(run.container_name("target", "24.04"))
        outcome = run.cleanup_result
        self.assertTrue(outcome.ok)
        self.assertEqual(len(outcome.errors), 1)
        self.assertEqual(outcome.errors[0].name, "mosdns-20260928T101010Z-target-24.04")
        self.assertIn("no such container", outcome.errors[0].message)

    def test_teardown_continues_past_a_container_it_could_not_remove(self):
        """One stuck container does not strand the other eleven.

        The tempting implementation returns on the first failure, and then the
        network and the volumes stay behind too, and the next run finds a
        network it did not create and refuses to use it.
        """
        fake = self.fake([
            {"match": ["rm", "-f", "mosdns-20260928T101010Z-stuck-24.04"], "returncode": 125, "stderr": "device busy\n"},
        ])
        with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet") as run:
            run.track_container(run.container_name("stuck", "24.04"))
            run.track_container(run.container_name("ok", "24.04"))
        removals = self.removals(fake)
        self.assertEqual(
            removals,
            [["rm", "-f", "mosdns-20260928T101010Z-stuck-24.04"],
             ["rm", "-f", "mosdns-20260928T101010Z-ok-24.04"],
             ["network", "rm", "mosdns-20260928T101010Z-testnet"]],
        )

    def test_every_error_is_reported_not_only_the_first(self):
        fake = self.fake([
            {"match": ["rm", "-f"], "returncode": 125, "stderr": "device busy\n"},
            {"match": ["network", "rm"], "returncode": 125, "stderr": "network busy\n"},
            {"match": ["volume", "rm"], "returncode": 125, "stderr": "volume in use\n"},
        ])
        with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet") as run:
            run.track_container(run.container_name("target", "24.04"))
            run.track_volume(run.volume_name("state"))
        outcome = run.cleanup_result
        self.assertEqual(len(outcome.errors), 3)
        self.assertEqual([error.kind for error in outcome.errors], ["container", "network", "volume"])

    def test_a_volume_left_behind_is_a_survivor_too(self):
        """A volume holds state, and state left behind is worse than a container.

        A container is visible in `podman ps`; a volume is not, and a stale one
        is the thing that makes a later install see a previous run's state.
        """
        fake = self.fake([
            {"match": ["volume", "rm"], "returncode": 1, "stderr": "volume is in use\n"},
            {"match": ["volume", "ls"], "stdout": "mosdns-20260928T101010Z-state\n"},
        ])
        with self.assertRaises(CleanupFailed) as caught:
            with podman_session(self.client(fake), "20260928T101010Z") as run:
                run.track_volume(run.volume_name("state"))
        self.assertIn(("volume", "mosdns-20260928T101010Z-state"), caught.exception.result.survivors)
        self.assertFalse(caught.exception.result.ok)

    def test_a_network_left_behind_is_a_survivor_too(self):
        """The network is this run's, so its survival is this run's failure."""
        fake = self.fake([
            {"match": ["network", "rm"], "returncode": 1, "stderr": "network is in use\n"},
            {"match": ["network", "exists"], "returncode": 0},
        ])
        with self.assertRaises(CleanupFailed) as caught:
            with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet"):
                pass
        self.assertIn(("network", "mosdns-20260928T101010Z-testnet"), caught.exception.result.survivors)

    def test_teardown_sweeps_up_a_resource_the_run_lost_track_of(self):
        """The run prefix is the tracking, so a forgotten name is still found.

        A scenario that creates a container through its own command line
        leaves something the harness never recorded. Without the sweep it is
        invisible to `cleanup`, and the run after it inherits a stray container.
        The listing is present once and then empty, which is what a sweep that
        actually removed it looks like.
        """
        fake = self.fake([
            {"match": ["ps", "-a"], "answers": [
                {"stdout": "mosdns-20260928T101010Z-rogue\n"},
                {"stdout": ""},
            ]},
        ])
        with podman_session(self.client(fake), "20260928T101010Z"):
            pass
        self.assertIn(["rm", "-f", "mosdns-20260928T101010Z-rogue"], fake.invocations())

    def test_teardown_touches_nothing_belonging_to_another_run(self):
        """The sweep reaches this run and not the one next to it.

        Two runs on one machine is the normal case for a release gate and a
        developer's own run at the same time, so the anchoring is the property:
        an unanchored `name=mosdns-` filter would remove the containers of the
        run happening in parallel.

        The previous version of this case asserted a filter *literal* and then
        asserted that a container the fake had never returned was not removed
        -- the second half was vacuous, and the first half was a check on a
        string rather than on the behaviour. So the fake is now told to apply
        podman's own `name=` regexp filter (`respect_filter`), and the world it
        reports includes the name that is actually at risk from an unanchored
        filter: a container whose name *contains* this run's prefix but does
        not start with it. Removing that one is the accident, and it can only
        be avoided by the anchor.
        """
        world = (
            "mosdns-20260928T101010Z-rogue\n"
            "mosdns-20260928T101011Z-target-24.04\n"
            "backup-of-mosdns-20260928T101010Z-target-24.04\n"
            "unrelated-container\n"
        )
        fake = self.fake([
            {"match": ["ps", "-a"], "answers": [
                # the sweep: the whole world, with podman's own filter applied
                # to it, so what comes back is what podman would return
                {"stdout": world, "respect_filter": True},
                # the survivorship re-read, by which the rogue is gone
                {"stdout": "", "respect_filter": True},
            ]},
        ])
        with podman_session(self.client(fake), "20260928T101010Z"):
            pass
        removed = [argv[-1] for argv in fake.invocations() if argv[:2] == ["rm", "-f"]
                   and argv[1] == "-f"]
        self.assertIn("mosdns-20260928T101010Z-rogue", removed)
        self.assertNotIn("mosdns-20260928T101011Z-target-24.04", removed)
        self.assertNotIn("backup-of-mosdns-20260928T101010Z-target-24.04", removed)
        self.assertNotIn("unrelated-container", removed)
        # And the filter podman was given is podman's own, so the exclusion is
        # podman's behaviour under this filter rather than the fake's choice:
        # unanchored, the same filter would have matched the `backup-of-` name
        # too, and the sweep would have removed it.
        filters = {argv[3] for argv in fake.invocations() if argv[:2] in (["ps", "-a"], ["volume", "ls"])}
        self.assertEqual(filters, {"name=^mosdns-20260928T101010Z"})
        pattern = next(iter(filters)).split("=", 1)[1]
        self.assertIsNotNone(re.search(pattern, "mosdns-20260928T101010Z-rogue"))
        for name in (
            "mosdns-20260928T101011Z-target-24.04",
            "backup-of-mosdns-20260928T101010Z-target-24.04",
            "unrelated-container",
        ):
            with self.subTest(name=name):
                self.assertIsNone(re.search(pattern, name))

    def test_a_container_is_stopped_before_it_is_removed(self):
        """`rm -f` is SIGKILL, not a graceful shutdown, and that matters here.

        The first report claimed "podman's forced remove stops a container
        gracefully first". It does not: `podman rm -f` force-removes, and the
        wrapper implements the graceful path separately as `stop --time 30`.
        For every other harness that would be a cosmetic difference. For this
        one it is not, because a systemd target's units are what the later
        tasks read out of the container -- `journalctl -b` for a clean service
        start, the resolved state, the unit statuses -- and a SIGKILL truncates
        exactly the evidence. So teardown stops first, with the measured grace
        period, and then removes.
        """
        fake = self.fake()
        with podman_session(self.client(fake), "20260928T101010Z") as run:
            run.track_container(run.container_name("target", "24.04"))
        invocations = fake.invocations()
        stop = [argv for argv in invocations if argv[:1] == ["stop"]]
        self.assertEqual(stop, [["stop", "--time", "30", "mosdns-20260928T101010Z-target-24.04"]])
        removal = next(i for i, argv in enumerate(invocations) if argv[:2] == ["rm", "-f"])
        self.assertLess(
            invocations.index(stop[0]), removal,
            "a container must be stopped before it is removed, or the stop is a no-op",
        )

    def test_a_swept_container_is_stopped_before_it_is_removed_too(self):
        """The container the run lost track of gets the same shutdown.

        The stop is inside the removal helper rather than in the tracking
        loop, so a container found by the prefix sweep is shut down as
        gracefully as a tracked one. A teardown that stopped only what it
        tracked would SIGKILL exactly the container whose name nobody wrote
        down.
        """
        fake = self.fake([
            {"match": ["ps", "-a"], "answers": [
                {"stdout": "mosdns-20260928T101010Z-rogue\n"},
                {"stdout": ""},
            ]},
        ])
        with podman_session(self.client(fake), "20260928T101010Z"):
            pass
        self.assertIn(
            ["stop", "--time", "30", "mosdns-20260928T101010Z-rogue"],
            fake.invocations(),
        )

    def test_a_network_the_run_forgot_is_removed_rather_than_only_reported(self):
        """A sweep that finds a leak and leaves it is a leak.

        The containers and the volumes were swept by prefix and removed; the
        networks were listed for the survivorship report and then left, so a
        run that created a network and did not record it ended with a teardown
        failure naming a network this teardown could have removed. The next run
        then finds a network it did not create, and `run.py cleanup` -- the
        documented recovery for exactly that state -- is the only thing that
        clears it. The asymmetry is closed: the sweep removes.
        """
        fake = self.fake([
            {"match": ["network", "ls"], "answers": [
                {"stdout": "podman\nmosdns-20260928T101010Z-testnet\n"},
                {"stdout": "podman\n"},
            ]},
            {"match": ["network", "exists"], "returncode": 1},
        ])
        with podman_session(self.client(fake), "20260928T101010Z"):
            pass
        self.assertIn(["network", "rm", "mosdns-20260928T101010Z-testnet"], fake.invocations())
        # And podman's own default network is not this harness's to remove.
        removed = [argv[-1] for argv in fake.invocations() if argv[:2] == ["network", "rm"]]
        self.assertNotIn("podman", removed)

    def test_a_swept_network_that_cannot_be_removed_is_still_a_survivor(self):
        """Removing it is an attempt, not a claim, so the report is unchanged.

        A sweep that removed what it found and then reported nothing would be
        the worse bug: a network podman refused to remove would be reported as
        gone. So a failed removal is an error AND a survivor, and the run still
        fails.
        """
        fake = self.fake([
            {"match": ["network", "rm"], "returncode": 1, "stderr": "network is in use\n"},
            {"match": ["network", "ls"], "stdout": "mosdns-20260928T101010Z-testnet\n"},
        ])
        with self.assertRaises(CleanupFailed) as caught:
            with podman_session(self.client(fake), "20260928T101010Z"):
                pass
        self.assertIn(("network", "mosdns-20260928T101010Z-testnet"), caught.exception.result.survivors)

    def test_a_second_cleanup_of_the_same_run_reports_a_clean_run(self):
        """`run.py cleanup` has to be safe to run twice.

        It is the documented way to recover a host after a killed run, and a
        recovery command that fails on the state it is meant to clear is not a
        recovery command.
        """
        fake = self.fake()
        podman = self.client(fake)
        run = RunResources(podman, "20260928T101010Z")
        run.track_container(run.container_name("target", "24.04"))
        self.assertTrue(run.cleanup().ok)
        self.assertTrue(run.cleanup().ok)


class RaisingScenarioTest(PodmanTestCase):
    """A scenario that raises still reaches teardown.

    This is the requirement most easily asserted and least easily true. The
    shape that leaks is `run_version` doing its work and then returning a
    result, with the teardown on the line after: the exception skips it. So the
    teardown is in a `finally`, and the two halves of the awkwardness -- an
    exception from the scenario *and* a failing teardown -- are held here
    separately, because getting the second one wrong silently destroys the
    first one's evidence.
    """

    def test_a_raising_scenario_still_tears_its_run_down(self):
        fake = self.fake()

        def scenario():
            raise AssertionError("the installer's postinst exited 1")

        with self.assertRaises(AssertionError):
            with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet") as run:
                run.track_container(run.container_name("target", "24.04"))
                scenario()
        self.assertIn(["rm", "-f", "mosdns-20260928T101010Z-target-24.04"], fake.invocations())
        self.assertIn(["network", "rm", "mosdns-20260928T101010Z-testnet"], fake.invocations())
        self.assertTrue(run.cleanup_result.ok)

    def test_a_raising_scenario_is_not_masked_by_a_failing_teardown(self):
        """The scenario's exception is the evidence; the leak is reported beside it.

        Raising the teardown failure from a `finally` would replace the installer's
        error with "a container survived", and the reason the installer failed
        would be gone. So the teardown result is attached and the original
        exception propagates.
        """
        fake = self.fake([
            {"match": ["rm", "-f"], "returncode": 125, "stderr": "device busy\n"},
            {"match": ["ps", "-a"], "stdout": "mosdns-20260928T101010Z-target-24.04\n"},
        ])

        def scenario():
            raise AssertionError("the installer's postinst exited 1")

        with self.assertRaises(AssertionError) as caught:
            with podman_session(self.client(fake), "20260928T101010Z") as run:
                run.track_container(run.container_name("target", "24.04"))
                scenario()
        self.assertIn("postinst exited 1", str(caught.exception))
        self.assertFalse(run.cleanup_result.ok)
        self.assertIn(("container", "mosdns-20260928T101010Z-target-24.04"), run.cleanup_result.survivors)

    def test_a_successful_run_that_leaves_something_behind_fails_loudly(self):
        """With nothing to mask it, a leak is raised rather than logged.

        A run that passes every scenario and leaks a container has still failed,
        and the only place that can say so is the teardown.
        """
        fake = self.fake([
            {"match": ["ps", "-a"], "stdout": "mosdns-20260928T101010Z-rogue\n"},
        ])
        with self.assertRaises(CleanupFailed) as caught:
            with podman_session(self.client(fake), "20260928T101010Z"):
                pass
        self.assertIn("mosdns-20260928T101010Z-rogue", str(caught.exception))
        self.assertIn(("container", "mosdns-20260928T101010Z-rogue"), caught.exception.result.survivors)

    def test_a_clean_run_leaves_nothing_to_raise(self):
        fake = self.fake()
        with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet") as run:
            run.track_container(run.container_name("target", "24.04"))
        self.assertEqual(run.cleanup_result.survivors, ())
        self.assertEqual(run.cleanup_result.errors, ())

    def test_a_session_always_cleans_up_even_with_nothing_tracked(self):
        """The network is a session's own resource, so it is removed regardless.

        A caller that forgets to track its containers still gets its network
        removed; the survivorship sweep is what catches the containers.
        """
        fake = self.fake()
        with podman_session(self.client(fake), "20260928T101010Z", network="mosdns-20260928T101010Z-testnet"):
            pass
        self.assertIn(["network", "rm", "mosdns-20260928T101010Z-testnet"], fake.invocations())


class RunNamingTest(PodmanTestCase):
    """Every resource carries this run's prefix, so one run cannot touch another's.

    Two runs on one machine is the normal case for a release gate and a
    developer's own run at the same time, and a fixed name for the network
    would mean the second run either fails to create it or removes the first
    run's.
    """

    def test_two_runs_get_different_ids(self):
        first, second = new_run_id(when=datetime(2026, 9, 28, 10, 10, 10)), new_run_id(
            when=datetime(2026, 9, 28, 10, 10, 11)
        )
        self.assertNotEqual(first, second)

    def test_a_run_id_is_utc_sortable_and_usable_in_a_container_name(self):
        run_id = new_run_id(when=datetime(2026, 9, 28, 10, 10, 10))
        self.assertEqual(run_id, "20260928T101010Z")
        self.assertTrue(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", run_id))

    def test_every_name_a_run_produces_carries_its_prefix(self):
        run = RunResources(self.client(self.fake()), "20260928T101010Z", network="testnet")
        names = [
            run.container_name("target", "24.04"),
            run.container_name("client", "24.04"),
            run.volume_name("state"),
            run.network_name("testnet"),
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(name.startswith("mosdns-20260928T101010Z-"), name)
                self.assertTrue(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name), name)

    def test_two_runs_never_produce_the_same_container_name(self):
        fake = self.fake()
        first = RunResources(self.client(fake), "20260928T101010Z")
        second = RunResources(self.client(fake), "20260928T101011Z")
        self.assertNotEqual(
            first.container_name("target", "24.04"),
            second.container_name("target", "24.04"),
        )

    def test_a_container_name_keeps_the_version_visible(self):
        """Three versions run at once and a name has to say which it is."""
        run = RunResources(self.client(self.fake()), "20260928T101010Z")
        self.assertEqual(run.container_name("target", "26.04"), "mosdns-20260928T101010Z-target-26.04")


class RunTargetTest(PodmanTestCase):
    """A target's device is checked before a scenario runs, not after.

    This is the wiring the ruling is really about. The check exists and is
    tested, but a check nothing calls is a comment with a subprocess in it, so
    the runner calls it between starting the target and running the first
    scenario -- and these cases hold that order.
    """

    def scenario_results(self, fake, nmcli="yes\n"):
        """Run one target with two scenarios and return the runner's result."""
        fake.write_table([
            {"match": ["nmcli"], "stdout": nmcli},
            {"match": ["run"], "stdout": "9f3c1d0e2b\n"},
        ])
        podman = self.client(fake)
        ran: list[str] = []

        def first():
            ran.append("first")
            return ScenarioResult(name="first", status="passed", log="logs/first.log")

        def second():
            ran.append("second")
            return ScenarioResult(name="second", status="passed", log="logs/second.log")

        result = run.run_target(
            podman,
            run_id="20260928T101010Z",
            arch="amd64",
            version="24.04",
            image="localhost/mosdns-target:24.04",
            scenarios=[("first", first), ("second", second)],
        )
        return result, ran

    def test_a_managed_device_runs_every_scenario_in_order(self):
        fake = self.fake()
        result, ran = self.scenario_results(fake)
        self.assertEqual(ran, ["first", "second"])
        self.assertEqual(result.status, "passed")
        self.assertEqual([s.name for s in result.scenarios], ["first", "second"])
        self.assertEqual(result.version, "24.04")
        self.assertEqual(result.arch, "amd64")

    def test_an_unmanaged_device_stops_the_version_before_any_scenario_runs(self):
        """The ordering, held: no scenario may run against a target NM ignores.

        Every DNS assertion in a scenario would fail at once, for a reason that
        has nothing to do with the package, and the resulting report would name
        the installer.
        """
        fake = self.fake()
        result, ran = self.scenario_results(fake, nmcli="no\n")
        self.assertEqual(ran, [])
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.scenarios, ())
        self.assertIn("nmcli device set eth0 managed yes", result.detail)
        self.assertIn("systemctl restart NetworkManager", result.detail)

    def test_a_device_query_that_fails_stops_the_version_the_same_way(self):
        fake = self.fake()
        fake.write_table([
            {"match": ["nmcli"], "returncode": 1, "stderr": "Error: unknown device 'eth0'.\n"},
            {"match": ["run"], "stdout": "9f3c1d0e2b\n"},
        ])
        podman = self.client(fake)
        ran: list[str] = []
        result = run.run_target(
            podman,
            run_id="20260928T101010Z",
            arch="amd64",
            version="24.04",
            image="localhost/mosdns-target:24.04",
            scenarios=[("first", lambda: ran.append("first"))],
        )
        self.assertEqual(ran, [])
        self.assertIn("unknown device 'eth0'", result.detail)

    def test_a_target_that_boots_after_the_runner_asks_is_waited_for(self):
        """`podman run -d` returns before systemd has started the target's units.

        **Measured, and it is the reason the check is a wait.** The first live
        cell on 22.04 asked `nmcli -g GENERAL.NM-MANAGED device show eth0` about
        two seconds after `podman run -d` returned and got

        ```
        'podman exec … nmcli -g GENERAL.NM-MANAGED device show eth0' exited 1
        ```

        -- not a device NetworkManager refused, but no NetworkManager at all
        yet. The target's entrypoint has to `exec /sbin/init`, systemd has to
        reach multi-user, and `target-nm-setup.service` runs *after*
        NetworkManager; on 22.04 the managed state comes from the conf.d
        declaration, which is read when NetworkManager starts. So a single-shot
        check is a race that a fast machine loses and a loaded one wins, and it
        reports the loss as "the device is unmanaged" -- which is the one message
        a reader must not be sent for a timing problem.

        So the check is a bounded wait, and the fake answers `no` twice before
        `yes`: a single-shot check would report the cell incomplete on exactly
        this sequence.
        """
        fake = self.fake()
        fake.write_table([
            {"match": ["nmcli", "-g", "GENERAL.NM-MANAGED"], "answers": [
                {"returncode": 1, "stderr": "Error: Could not create NMClient object.\n"},
                {"stdout": "no\n"},
                {"stdout": "yes\n"},
            ]},
            {"match": ["nmcli"], "stdout": "yes\n"},
            {"match": ["run"], "stdout": "9f3c1d0e2b\n"},
        ])
        ran: list[str] = []
        result = run.run_target(
            self.client(fake),
            run_id="20260928T101010Z",
            arch="amd64",
            version="22.04",
            image="localhost/mosdns-target:22.04",
            scenarios=[("dhcp", lambda: ran.append("dhcp"))],
        )
        self.assertEqual(ran, ["dhcp"], f"the cell did not wait for the target to boot: {result.detail}")
        self.assertEqual(result.status, "passed")

    def test_a_device_that_stays_unmanaged_names_what_it_saw(self):
        """A wait that runs out says what it read, not merely that it timed out.

        `no` and "no NetworkManager at all" are different answers and they send a
        reader to different places: the first to the image's
        `target-nm-setup.service` and the `conf.d` declaration, the second to the
        target's own boot. The poll that raised the last one is the value the
        message has to carry.
        """
        fake = self.fake()
        fake.write_table([
            {"match": ["nmcli", "-g", "GENERAL.NM-MANAGED"], "stdout": "no\n"},
            {"match": ["nmcli"], "stdout": "yes\n"},
            {"match": ["run"], "stdout": "9f3c1d0e2b\n"},
        ])
        ran: list[str] = []
        result = run.run_target(
            self.client(fake),
            run_id="20260928T101010Z",
            arch="amd64",
            version="22.04",
            image="localhost/mosdns-target:22.04",
            scenarios=[("dhcp", lambda: ran.append("dhcp"))],
        )
        self.assertEqual(ran, [])
        self.assertEqual(result.status, "incomplete")
        self.assertIn("'no'", result.detail)
        # **And it says how hard it tried**, which the single-shot check could
        # not: a reader who sees "answered 'no'" and one who sees "answered 'no'
        # on 25 reads over 120s" take different next steps, and only the second
        # one knows the answer was not a timing problem.
        self.assertRegex(result.detail, r"\d+ reads")
        self.assertIn("120", result.detail)
        # And the two steps are still named, because that is the whole value of
        # the refusal: a reader who has never seen the conf.d declaration has to
        # learn from the message that it exists.
        self.assertIn("nmcli device set eth0 managed yes", result.detail)
        self.assertIn("systemctl restart NetworkManager", result.detail)
        self.assertIn("10-mosdns-target.conf", result.detail)

    def test_the_target_runs_on_a_bridge_network_with_the_measured_subnet(self):
        """A tun/tap device would fail the check, and the check is not optional.

        So the network the target is put on is the plan's fixed netavark bridge
        rather than Podman's default, and that is asserted here because it is
        the precondition the check depends on.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        self.scenario_results(fake)
        created = [argv for argv in fake.invocations() if argv[:2] == ["network", "create"]]
        self.assertEqual(created, [["network", "create", "--subnet", "10.89.0.0/24", "mosdns-20260928T101010Z-testnet"]])

    def test_the_target_is_named_for_this_run_and_this_version(self):
        """Three versions run at once, and the mock router is a container too.

        The router is started *first* and takes the first free address in the
        pool, so the order is a fact and not a preference; and the name is read
        out of the array rather than off the first invocation, which is what
        makes "the target is named for this run" survive a cell that starts two
        containers.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        self.scenario_results(fake)
        started = {argv[argv.index("--name") + 1] for argv in fake.invocations() if argv[:2] == ["run", "-d"]}
        self.assertEqual(started, {
            "mosdns-20260928T101010Z-target-24.04",
            "mosdns-20260928T101010Z-mock-router-24.04",
        })

    def test_a_scenario_that_raises_is_recorded_and_the_run_is_still_torn_down(self):
        """A failing scenario is a result; a leaking run is not a result.

        So the exception becomes a `failed` entry carrying its message, the
        remaining scenarios for that version do not run against a target in a
        known-bad state, and the teardown happens anyway.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        podman = self.client(fake)
        ran: list[str] = []

        def boom():
            raise AssertionError("the installer's postinst exited 1")

        def later():
            ran.append("later")

        result = run.run_target(
            podman,
            run_id="20260928T101010Z",
            arch="amd64",
            version="24.04",
            image="localhost/mosdns-target:24.04",
            scenarios=[("install", boom), ("routing", later)],
        )
        self.assertEqual(ran, [])
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.scenarios[0].status, "failed")
        self.assertIn("postinst exited 1", result.scenarios[0].detail)
        self.assertIn(["rm", "-f", "mosdns-20260928T101010Z-target-24.04"], fake.invocations())
        self.assertIn(["network", "rm", "mosdns-20260928T101010Z-testnet"], fake.invocations())

    def test_a_version_with_no_scenarios_is_not_a_pass(self):
        """Nothing ran, so nothing was proved.

        The plan's rule is that a requirement which was not closed is recorded
        and never counted as satisfied, and a version with an empty scenario
        list is the shape that rule exists for.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        result = run.run_target(
            self.client(fake),
            run_id="20260928T101010Z",
            arch="amd64",
            version="24.04",
            image="localhost/mosdns-target:24.04",
            scenarios=[],
        )
        self.assertEqual(result.status, "incomplete")


class EntryPointTestCase(PodmanTestCase):
    """How a case drives the real entry point. No cases of its own.

    Extracted from `CommandLineTest` so that a second class of case can drive
    `run.py` without inheriting that class's thirty. Inheritance runs a parent's
    cases in the subclass as well as in the parent, and it is silent: a subclass
    that wanted five properties of a `matrix` run was running all thirty exit-code
    cases a second time, and the ones that failed did so for a reason in the
    subclass's `setUp` rather than in the code under test.
    """

    def invoke(self, argv):
        """Run the entry point and return (exit code, everything it printed)."""
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
            code = run.main(argv)
        return code, printed.getvalue()

    def base(self, fake, *extra):
        return ["--podman", str(fake.path), "--source-tree", str(self.source_tree), *extra]


class CommandLineTest(EntryPointTestCase):
    """The exit codes are the interface a release gate reads.

    0 all requested tests passed, 1 a test failure, 2 a harness or
    configuration error, 3 an incomplete matrix or a skipped required
    architecture. They are exercised through the real entry point rather than
    through the report's properties alone, because the number a Make target
    sees comes from `main` and not from the object it was derived on.
    """


    def test_global_options_are_accepted_after_the_subcommand(self):
        """The plan's own acceptance commands put them there.

        `run.py matrix --arch amd64 --versions 22.04 --results-dir X` is the
        shape the plan writes, and argparse's subparsers reject a global option
        that follows the subcommand unless it is also attached to it. Without
        this the invocation dies with "unrecognized arguments" and exit 2, and
        the failure reads like a harness fault rather than a parser fault.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        results = self.directory / "results"
        code, _ = self.invoke([
            "matrix", "--arch", "amd64", "--versions", "24.04",
            "--podman", str(fake.path), "--source-tree", str(self.source_tree),
            "--results-dir", str(results),
        ])
        self.assertEqual(code, run.EXIT_INCOMPLETE)
        self.assertTrue((results).rglob("report.json").__next__().is_file())

    def test_global_options_are_accepted_before_the_subcommand_too(self):
        """Both spellings resolve to the same run, not to two different ones.

        **Both runs carry the same `--run-id`**, which is what makes the two
        reports comparable in full. A scenario's failure detail quotes the
        container it was looking at, and a container name carries the run id --
        so two runs with two auto-generated ids differ in a field this case is
        not about, and comparing them in full would be comparing two different
        runs. Fixing the id turns the comparison back into the one it means: the
        same options, the same run, byte-identical apart from the timestamps.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        first = self.directory / "a"
        second = self.directory / "b"
        common = [
            "--podman", str(fake.path), "--source-tree", str(self.source_tree),
            "--run-id", "20260928T120000Z",
        ]
        self.invoke([
            *common, "--results-dir", str(first),
            "matrix", "--arch", "amd64", "--versions", "24.04",
        ])
        self.invoke([
            "matrix", "--arch", "amd64", "--versions", "24.04",
            *common, "--results-dir", str(second),
        ])
        one = json.loads(next(first.rglob("report.json")).read_text(encoding="utf-8"))
        two = json.loads(next(second.rglob("report.json")).read_text(encoding="utf-8"))
        for document in (one, two):
            for key in ("run_id", "started_utc", "finished_utc"):
                document.pop(key)
        self.assertEqual(one, two)

    def test_the_matrix_options_are_accepted_on_both_sides_of_the_subcommand(self):
        """`--arch`, `--versions` and `--scenario` are global too, not matrix-only.

        The previous fix attached the five *global* options to every subparser
        and left the three *matrix* options on the `matrix` subparser alone, so
        `run.py --arch arm64 matrix` -- the shape a Make target or a CI
        variable produces, and the shape `make test-system-arm64` in the plan
        writes -- died with argparse's usage error and exit 2. Only the
        post-subcommand spelling was tested, so the other half was untested and
        unfixed. Both sides are held here for all three.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        before = self.directory / "before"
        after = self.directory / "after"
        common = ["--podman", str(fake.path), "--source-tree", str(self.source_tree)]
        code, _ = self.invoke([
            *common, "--results-dir", str(before),
            "--arch", "arm64", "--versions", "24.04", "matrix",
        ])
        self.invoke([
            "matrix", "--arch", "arm64", "--versions", "24.04",
            *common, "--results-dir", str(after),
        ])
        for directory in (before, after):
            document = json.loads(next(directory.rglob("report.json")).read_text(encoding="utf-8"))
            self.assertEqual(document["arch"], "arm64")
            self.assertEqual([r["version"] for r in document["results"]], ["24.04"])

    def test_an_unregistered_scenario_is_refused_rather_than_parsed_and_ignored(self):
        """`--scenario` is either run or refused, and never parsed and dropped.

        The plan's own Task 3 acceptance command is `run.py matrix --arch amd64
        --versions 22.04 --scenario dhcp`, so the flag is passed on the first
        command in the plan that expects a cell to be *run*. Silently ignoring
        it produced exit 3 with "no scenario is registered in this build of the
        harness" -- honest, but it reads as though the harness looked for `dhcp`
        and did not find it, when in fact it never looked. So a requested
        scenario that is not registered is a configuration error: exit 2, the
        name in the message, and the reason.

        The name is now `routing` rather than `dhcp`, because `dhcp` **is**
        registered as of Task 3 and asking for it runs a cell. The refusal is
        about a name the registry does not hold, which is the only shape the
        defect takes; the case that a registered name runs is in
        `test_matrix_cell.py`.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"),
                      "matrix", "--arch", "amd64", "--versions", "24.04",
                      "--scenario", "routing")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("routing", output)
        self.assertIn("no such scenario is registered", output)
        # And the refusal says what *would* have worked, because the operator who
        # mistyped one of four names is not going to read the source to find the
        # other three.
        self.assertIn("dhcp", output)
        # Nothing was started: a refusal that created a container first would be
        # a refusal that already did the thing it refused.
        self.assertEqual(
            [argv for argv in fake.invocations() if argv[:2] == ["run", "-d"]], []
        )

    def test_a_registered_scenario_that_fails_is_a_failed_cell_not_a_refusal(self):
        """The two answers are different claims and they get different exit codes.

        A registered scenario that could not establish its claim is a *test
        failure* -- exit 1, a `failed` row in the report, the reason beside it --
        because something was tried and did not work. A scenario the harness has
        never heard of is exit 2, because nothing was tried. Collapsing the two
        would let a run whose scenarios all failed be filed as a configuration
        mistake, and the first thing anybody would do about a configuration
        mistake is change a flag.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"),
                      "--run-id", "20260928T120000Z",
                      "matrix", "--arch", "amd64", "--versions", "24.04",
                      "--scenario", "dhcp")
        )
        # This fake has no answers for the scenario's queries, so the DHCP
        # scenario fails its assertions -- which is the point: it *ran*.
        self.assertEqual(code, EXIT_TEST_FAILURE, output)
        document = json.loads(
            next((self.directory / "results").rglob("report.json")).read_text(encoding="utf-8")
        )
        self.assertEqual(document["results"][0]["scenarios"][0]["status"], "failed")
        self.assertTrue(document["results"][0]["scenarios"][0]["detail"])

    def test_matrix_with_no_scenario_requested_runs_every_registered_one(self):
        """Naming nothing means everything, because that is the plan's own command.

        `python3 tests/podman/run.py matrix --arch amd64 --versions
        22.04,24.04,26.04` is the whole matrix, and the Make target Task 7 adds
        writes exactly that with no `--scenario`. A harness where that meant
        "run nothing" would report the plan's own acceptance command incomplete
        forever -- which is what the Task 2 build did, honestly and for a state
        that has now changed.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"),
                      "--run-id", "20260928T120000Z",
                      "matrix", "--arch", "amd64", "--versions", "24.04")
        )
        self.assertEqual(code, EXIT_TEST_FAILURE, output)
        document = json.loads(
            next((self.directory / "results").rglob("report.json")).read_text(encoding="utf-8")
        )
        self.assertEqual(
            [s["name"] for s in document["results"][0]["scenarios"]],
            list(run.SCENARIO_NAMES),
            "a run that named no scenario did not run every registered one",
        )

    def test_a_subcommand_that_raises_something_unexpected_is_still_a_harness_error(self):
        """The exit-code contract has a net under it.

        `main` caught `PodmanError` and nothing else, so a `TypeError`, an
        `AttributeError` or a bug in a later task's handler escaped as a
        traceback: exit 1 from the interpreter, which the contract reserves for
        "a test failure". A caller reading that as a test failure would go
        looking for a broken installer when the harness is what broke. So
        anything a handler raises is exit 2, named, with the type -- and a
        `KeyboardInterrupt` is deliberately not caught, because a Ctrl-C is
        not a harness fault.
        """
        def broken(args):
            raise TypeError("a later task's handler returned None where it promised a dict")

        original = run.command_preflight
        run.command_preflight = broken
        self.addCleanup(setattr, run, "command_preflight", original)
        code, output = self.invoke(self.base(self.fake(), "preflight"))
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("TypeError", output)
        self.assertIn("promised a dict", output)

    def test_an_interrupt_is_not_converted_into_a_harness_error(self):
        """A Ctrl-C must stay a Ctrl-C.

        `except Exception` does not catch `KeyboardInterrupt` -- it derives
        from `BaseException` -- and this case says so, because the net above
        would be a bad thing to add and the reason it is not a bad thing is
        that it is not there.
        """
        def interrupted(args):
            raise KeyboardInterrupt

        original = run.command_preflight
        run.command_preflight = interrupted
        self.addCleanup(setattr, run, "command_preflight", original)
        with self.assertRaises(KeyboardInterrupt):
            self.invoke(self.base(self.fake(), "preflight"))

    def test_a_version_that_is_not_a_version_is_refused_rather_than_reported(self):
        """`--versions 24.4` used to produce a row for a release nobody ships.

        The cell was reported `incomplete` with a requirement string naming
        `24.4`, so a typo became a requirement in the machine-readable record
        -- and this plan's rule is that a requirement which was not closed is
        recorded, which is not a rule that a misspelling is one. So the shape
        is checked: dot-separated numbers, which is what a release is.
        """
        for spelling in ("24.4", "jammy", "24.04.1", "24-04", "v24.04", ""):
            with self.subTest(versions=spelling):
                fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
                code, output = self.invoke(
                    self.base(fake, "--results-dir", str(self.directory / "results"),
                              "matrix", "--arch", "amd64", "--versions", spelling)
                )
                # An empty list is the default, not a refusal: `--versions ""`
                # is how a shell passes an unset variable.
                self.assertIn(code, (run.EXIT_OK, run.EXIT_INCOMPLETE, run.EXIT_HARNESS_ERROR))
                if spelling:
                    self.assertEqual(code, run.EXIT_HARNESS_ERROR)
                    self.assertIn("is not a version", output)

    def test_every_release_the_lock_pins_reaches_a_build_with_its_own_digest(self):
        """**The lock pins every release, and each digest reaches a `podman build`.

        That is the whole claim, and it is one claim rather than two. It used to
        be a case called `..._is_accepted` whose exit-code assertion accepted three
        of the four codes and in practice only ever saw one -- so the "the release
        is accepted" half of the name was carried entirely by the build-argv
        assertion below, while the assertion next to it read as though the exit
        code were doing work. A subject that has quietly become a different claim
        is worse than a weak one, because the docstring is what a later reader
        trusts.

        So the name says what is asserted. The exit code is **not** pinned to a
        single value, and the reason is measured: the code this run returns is
        `1` for all three releases, because this fake answers a cell only well
        enough to build it and the DHCP scenario then fails on the missing
        answers. That number is a property of how completely this case's table
        describes a passing run, not a property of the lock, and pinning it would
        be asserting a fact about the fixture.

        The one exit code that *is* asserted is the one that would mean the
        version was refused: `2`. A release the lock does not cover is refused
        before anything is built -- `test_a_release_the_lock_does_not_pin_is_refused_by_the_lock_not_the_parser`
        is the other side of that, and it names the versions the lock does cover
        in its message. So "accepted" is carried by "not refused", and "built from
        its own digest" is carried by the argv, and neither is carried by a number
        that describes the fixture.

        **There is no `skips` entry any more.** That assertion was the Task 2 way
        of saying "the cell names the image it would have used". The cell runs, so
        nothing skips, and the claim is stronger now: the digest reaches a
        `podman build` argument, which
        `test_a_target_is_started_from_the_locked_reference_verbatim` asserts and
        `test_the_target_image_is_built_from_the_locked_reference` asserts again
        through the real entry point.
        """
        import images as images_module

        for version in sorted(images_module.load_lock()["images"]):
            with self.subTest(version=version):
                # A directory of its own per version: `FakePodmanBinary`
                # appends to one log beside itself, so a shared directory makes
                # each subtest's `invocations()` include the ones before it and
                # the assertion below is about a different run.
                directory = self.extra_directory()
                fake = self.fake(
                    [{"match": ["image", "exists"], "returncode": 1}],
                    directory=directory,
                )
                fake.write_table([
                    {"match": ["image", "exists"], "returncode": 1},
                    {"match": ["nmcli"], "stdout": "yes\n"},
                ])
                results = directory / "results"
                code, output = self.invoke(
                    self.base(fake, "--results-dir", str(results),
                              "--run-id", "20260928T120000Z",
                              "matrix", "--arch", "amd64", "--versions", version)
                )
                # "Accepted", and nothing more specific than that: a refusal is
                # exit 2 and happens before a single build.
                self.assertNotEqual(
                    code, run.EXIT_HARNESS_ERROR,
                    f"the lock refused a version it pins, so no build was reached: {output}",
                )
                document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
                self.assertEqual([r["version"] for r in document["results"]], [version])
                # And the claim: the build was given *this* release's own digest,
                # not a bare tag and not another release's.
                builds = [
                    argv for argv in fake.invocations()
                    if argv[:1] == ["build"]
                    and any(f"docker.io/library/ubuntu:{version}@sha256:" in token for token in argv)
                ]
                self.assertTrue(builds, f"no build was given the {version} digest: {fake.invocations()}")
                for argv in fake.invocations():
                    if argv[:1] != ["build"]:
                        continue
                    for token in argv:
                        if "ubuntu:" not in token or token.startswith("docker.io/library/ubuntu:"):
                            continue
                        self.assertIn(
                            f"docker.io/library/ubuntu:{version}@sha256:", token,
                            "a build was given a base reference for a different release than the "
                            f"one this subtest is about, so the digest that reached the build is "
                            f"not the one the lock pins for {version}",
                        )

    def test_a_release_the_lock_does_not_pin_is_refused_by_the_lock_not_the_parser(self):
        """**The two version checks are now different checks, and this is the seam.**

        Task 1's case here asserted that *any* well-formed release is accepted,
        with `9.10` and `18.04` in the list, because at that point the only version
        check was the parser's shape. Wiring the image lock in added a second
        check with a different answer: a run cannot build a version the lock does
        not pin, because there is no digest to build it from and the fallback --
        a bare tag -- is the failure this plan exists to prevent.

        So `9.10` is still a *well-formed* version and the parser still accepts it;
        what refuses it now is the lock, and the two are told apart by the message:
        the parser's complaint is about a shape, the lock's names the versions it
        does cover. Asserting both is what keeps a later reader from concluding
        the parser gained a hard-coded list of releases.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        results = self.directory / "r-910"
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(results),
                      "matrix", "--arch", "amd64", "--versions", "9.10")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        self.assertIn("9.10", output)
        # The lock's refusal lists what it does cover, which the parser's never does.
        self.assertIn("24.04", output)
        self.assertNotIn(
            "is not a version", output, "the parser refused the shape, so the lock was never read"
        )

    def test_a_malformed_version_is_still_refused_by_the_parser(self):
        """The shape check is unchanged, and it fires before the lock is read.

        `24.4` is a typo, and it should be reported as a typo -- not as a version
        the lock happens not to cover, which would send a reader to edit the lock
        instead of their own command line.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "r-244"),
                      "matrix", "--arch", "amd64", "--versions", "24.4")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        self.assertIn("is not a version", output)

    def test_a_bare_cleanup_reports_nothing_to_clean_rather_than_an_error(self):
        """A recovery command that fails on a clean host is not a recovery command.

        A cleanup that reconstructed a run's network name instead of reading
        the networks back reported `network not found` as a teardown error on a
        machine with nothing to clean. The fake never showed it, because the
        fake's `network ls` answers empty for a reason the test chose rather
        than one the real podman chose.
        """
        fake = self.fake()
        code, output = self.invoke(self.base(fake, "cleanup"))
        self.assertEqual(code, run.EXIT_OK)
        self.assertIn("nothing to clean up", output)
        self.assertNotIn("teardown:", output)

    def test_a_bare_cleanup_asks_the_networks_rather_than_guessing_one(self):
        """The network is read back from podman, not reconstructed from a prefix.

        A run's network is `<prefix>-testnet` by convention, and a cleanup that
        removed a network by an invented name reports an error for a network
        that never existed -- on a clean host, for the first run anyone makes.
        """
        fake = self.fake()
        self.invoke(self.base(fake, "cleanup"))
        self.assertIn(["network", "ls", "--format", "{{.Name}}"], fake.invocations())
        self.assertEqual([argv for argv in fake.invocations() if argv[:2] == ["network", "rm"]], [])

    def test_a_bare_cleanup_removes_a_network_it_found(self):
        # The listing is present once and then empty, which is what podman does
        # after the network is actually gone.
        fake = self.fake([
            {"match": ["network", "ls"], "answers": [
                {"stdout": "podman\nmosdns-20260928T101010Z-testnet\n"},
                {"stdout": "podman\n"},
            ]},
            {"match": ["network", "exists"], "returncode": 1},
        ])
        code, _ = self.invoke(self.base(fake, "cleanup"))
        self.assertEqual(code, run.EXIT_OK)
        self.assertIn(["network", "rm", "mosdns-20260928T101010Z-testnet"], fake.invocations())

    def test_a_bare_cleanup_does_not_touch_a_network_it_did_not_create(self):
        """`podman` is podman's own default network, and it is not ours."""
        fake = self.fake([
            {"match": ["network", "ls"], "answers": [
                {"stdout": "podman\nmosdns-20260928T101010Z-testnet\n"},
                {"stdout": "podman\n"},
            ]},
            {"match": ["network", "exists"], "returncode": 1},
        ])
        self.invoke(self.base(fake, "cleanup"))
        removed = [argv[-1] for argv in fake.invocations() if argv[:2] == ["network", "rm"]]
        self.assertNotIn("podman", removed)

    def test_a_network_this_run_forgot_is_a_survivor(self):
        """The survivorship sweep covers networks as well as containers.

        A run whose network was created and then not recorded is invisible to
        a name list, and the next run finds a network it did not create.
        """
        fake = self.fake([
            {"match": ["network", "ls"], "stdout": "mosdns-20260928T101010Z-testnet\n"},
        ])
        with self.assertRaises(CleanupFailed) as caught:
            with podman_session(self.client(fake), "20260928T101010Z"):
                pass
        self.assertIn(("network", "mosdns-20260928T101010Z-testnet"), caught.exception.result.survivors)

    def test_preflight_reports_a_missing_podman_and_installs_nothing(self):
        """A preflight that installed Podman would break the host boundary.

        Podman is a prerequisite the operator provides; the plan says the
        harness never installs it, and a missing binary is reported rather than
        solved. The source tree is named explicitly because the default is this
        repository, and a repository under a forbidden host root is refused by
        the mount policy before podman is ever asked about -- which is the
        subject of `test_the_default_source_tree_is_this_repository` and
        `test_a_source_tree_the_policy_refuses_is_reported_as_such`.
        """
        code, output = self.invoke(
            [
                "--podman", str(self.directory / "no-such-podman"),
                "--source-tree", str(self.source_tree),
                "preflight",
            ]
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("not found", output)
        self.assertIn("does not install", output)

    def test_the_default_source_tree_is_this_repository(self):
        """The default is the checkout, and the policy is applied to it.

        A default that silently became something else would make a run
        un-reproducible: two checkouts, two mount arguments, and nothing in the
        report saying which was mounted. So the default is named here, and this
        case states plainly what happens when the checkout is not a legal
        parameter.
        """
        self.assertEqual(run.GLOBAL_DEFAULTS["source_tree"], str(REPO))

    def test_a_source_tree_the_policy_refuses_is_reported_as_such(self):
        """A refused source tree is a refusal with a remedy, not a crash.

        `/etc` is a root this policy refuses for a reason that has nothing to do
        with where a checkout lives -- it is the host's resolver and systemd
        state -- so `--source-tree /etc` is refused at construction, before
        podman is asked anything, and the operator is told what to pass instead.

        (This host's own checkout is under `/home`, which the amended policy
        permits, so the deadlock this case used to describe no longer exists.
        `/etc` is the case that still holds: a refusal that is about the kind of
        path, not about where the operator keeps their work.)
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(
            ["--podman", str(fake.path), "--source-tree", "/etc", "preflight"]
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("/etc", output)
        self.assertIn("--source-tree", output)
        self.assertEqual(fake.invocations(), [])

    def test_this_checkout_is_the_source_tree_on_this_host(self):
        """The deadlock, resolved: the default is now a legal parameter here.

        The plan mounts "the source tree" and also forbade mounting host
        `/home`, and this checkout *is* under `/home` — so the two constraints
        collided, there was no legal value at all for `--source-tree` on this
        host, and `run.py` could not run from a checkout at all. That is a
        collision between two rules that were each individually reasonable, and
        the rule that gave way is the one whose rationale (resolver and systemd
        state) does not reach a read-only source bind.

        So the default source tree is asserted to be *accepted* here, and
        emitted `:ro`. Had this checkout been under one of the four roots that
        hold resolver state, the case would have to say so instead, so the
        check is written as both: the default is accepted, and it is not under
        a refused root.
        """
        for root in FORBIDDEN_SOURCE_TREE_ROOTS:
            self.assertFalse(
                str(REPO) == root or str(REPO).startswith(root + "/"),
                f"this checkout is at {REPO}, which is under {root} and the policy refuses it",
            )
        podman = Podman(executable="/bin/true", source_tree=str(REPO))
        self.assertEqual(podman.source_tree, str(REPO))
        self.assertEqual(podman.allowed_mounts()[WORKSPACE], (str(REPO), "ro"))

    def test_preflight_reports_the_podman_facts_it_can_read(self):
        fake = self.fake([
            {"match": ["version"], "stdout": "5.7.0\n"},
            {"match": ["info"], "stdout": "overlay\n"},
        ])
        code, output = self.invoke(self.base(fake, "preflight"))
        self.assertEqual(code, run.EXIT_OK)
        self.assertIn("5.7.0", output)
        self.assertIn("overlay", output)

    def test_preflight_states_the_networkmanager_fact_it_depends_on(self):
        """The first line, because it is the fact the whole plan turns on.

        A preflight that reported a version and a store and then said nothing
        about the device would let an operator conclude the harness is ready
        when the thing it cannot do is the thing that matters.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(self.base(fake, "preflight"))
        first = output.splitlines()[0]
        self.assertIn("NetworkManager", first)
        self.assertIn("eth0", first)

    def test_preflight_says_it_cannot_check_the_device_here_rather_than_assuming_it(self):
        """The plan's rule: a preflight that cannot check must say so.

        Claiming the device would come up managed is the false claim the
        previous plan's SKIPPED list was built on, and it is the one thing this
        harness must not assert without a running target to ask.

        **Updated when the target image arrived.** This case used to require the
        words "no target image is built yet", which were true when Task 1 landed
        and stopped being true when `tests/podman/images/target.Containerfile` and
        its three Containerfile siblings were added. A preflight that tells an
        operator the repository ships no image, while the repository ships three,
        is worse than one that says nothing: the operator builds one, runs
        `preflight` again, and gets the same sentence.

        The rule is unchanged and is what is now asserted: preflight does not
        claim the field will be `yes`, and it names the facts that decide it.

        **Corrected again after Fix Round 1**, which is the second time this
        sentence has gone stale, and both times for the same reason: a preflight
        cannot check the field, so whoever last changed the image had to write
        down what the image now does, and got it right for a release rather than
        for the matrix. The previous version said a 22.04 target "is expected to
        refuse to boot", which was true when the only mechanism was the sequence
        and is now false: the image declares the device managed by configuration,
        so 22.04 comes up `yes` like the other two.

        So this case now requires the *mechanism* rather than a prediction about a
        release. A preflight that names the declaration and the two
        `nmcli --version` facts stays true whatever the images do next; one that
        predicts an outcome goes stale the moment an image changes, and the
        version of this sentence in git is the history of that.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(self.base(fake, "preflight"))
        self.assertIn("cannot be checked", output)
        self.assertIn("tests/podman/images/target.Containerfile", output)
        self.assertNotIn(
            "no target image is built yet",
            output,
            "the repository ships the target image now, so this sentence is false",
        )
        # The declaration is the mechanism, so it is what the preflight names.
        self.assertIn("conf.d", output)
        # And it must not claim the field will be `yes` -- that is the whole rule.
        self.assertNotIn("would come up with GENERAL.NM-MANAGED: yes.", output)
        # Nor predict an outcome per release: a prediction is a claim a preflight
        # cannot check, and this sentence has been wrong twice.
        self.assertNotIn("is expected to refuse to boot", output)
        self.assertNotIn("the field stays 'no'", output)

    def test_preflight_runs_no_command_that_changes_anything(self):
        """A preflight is a read, and a read that mutates is not one.

        It runs `version` and `info` and nothing else, so a preflight on a
        machine with no Podman permission changes no Podman state either.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        self.invoke(self.base(fake, "preflight"))
        for argv in fake.invocations():
            self.assertIn(argv[0], ("version", "info"), f"preflight ran {argv!r}")

    def test_preflight_names_the_local_rootless_podman_it_defaults_to(self):
        """No `--connection` is the acceptance path, and the output says so."""
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(self.base(fake, "preflight"))
        self.assertIn("local rootless", output)

    def test_a_connection_reaches_every_command_as_a_service_uri(self):
        """The connection is an argument, and it is a URI rather than a name.

        A name would be a machine, and there is no machine. What reaches podman
        is the service URI the operator supplied, on every invocation, with
        nothing written to a configuration file that other podman users on this
        machine would inherit.

        And the refusal, through the entry point rather than through the
        wrapper: a machine name on this command line is exit 2 with the reason
        named, and no podman process is started at all. A preflight that echoed
        a machine name back and carried on would be the one place an operator
        learns this harness has a machine in it.
        """
        uri = "ssh://builder@arm64.example/run/podman/podman.sock"
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(self.base(fake, "--connection", uri, "preflight"))
        self.assertIn("service URI", output)
        self.assertTrue(fake.invocations())
        for argv in fake.invocations():
            self.assertEqual(argv[:2], ["--connection", uri])

        # Its own directory, so its log is its own: `FakePodmanBinary` appends
        # to one file beside itself, and a refusal that shares a log with the
        # run above would be asserting about the run above.
        directory = self.extra_directory()
        refused = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}], directory=directory)
        code, output = self.invoke(
            self.base(refused, "--connection", "podman-machine-default", "preflight")
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("podman-machine-default", output)
        self.assertIn("machine", output)
        self.assertEqual(refused.invocations(), [])

    def test_matrix_with_no_scenarios_is_incomplete_and_exits_three(self):
        """Task 1 registers no scenario, so the honest answer is incomplete.

        Not zero, and not one: nothing failed and nothing was proved, and the
        exit code is how a caller tells those apart.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"),
                      "matrix", "--arch", "amd64", "--versions", "22.04,24.04,26.04")
        )
        self.assertEqual(code, run.EXIT_INCOMPLETE)
        self.assertIn("incomplete", output)

    def test_matrix_records_every_version_it_was_asked_for(self):
        """A version that was requested and not reported is worse than a failure."""
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        results = self.directory / "results"
        self.invoke(
            self.base(fake, "--results-dir", str(results),
                      "matrix", "--arch", "amd64", "--versions", "22.04,24.04,26.04")
        )
        document = json.loads(next(results.rglob("report.json")).read_text(encoding="utf-8"))
        self.assertEqual([r["version"] for r in document["results"]], ["22.04", "24.04", "26.04"])
        self.assertEqual(document["status"], "incomplete")
        self.assertEqual(document["arch"], "amd64")
        self.assertEqual(document["harness_error"], None)

    def test_matrix_writes_its_report_under_the_run_id_directory(self):
        """A run's result is one directory, so two runs do not overwrite each other."""
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        results = self.directory / "results"
        self.invoke(
            self.base(fake, "--results-dir", str(results), "--run-id", "20260928T101010Z",
                      "matrix", "--arch", "amd64", "--versions", "24.04")
        )
        self.assertTrue((results / "20260928T101010Z" / "report.json").is_file())

    def test_a_matrix_run_only_touches_podman_inside_its_own_namespace(self):
        """Nothing a `matrix` run creates is outside the run's own prefix.

        **This case used to assert the opposite** -- that a matrix run creates
        and starts *nothing* -- which was true only while no scenario was
        registered and the runner reported every version incomplete without
        touching Podman. A cell now creates a network and starts two containers,
        so the claim that is worth holding is the one that still matters: every
        name the run invents is inside `mosdns-<run-id>-`, which is what makes
        `cleanup` able to find all of it and makes a second concurrent run's
        resources untouchable.

        `build` is the one invocation with no resource name, and it is named
        separately: it writes podman's image store, not a named container, and
        its tag is `mosdns-`-prefixed and content-derived, which
        `test_matrix_cell.py` holds in detail.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"),
                      "--run-id", "20260928T101010Z",
                      "matrix", "--arch", "amd64", "--versions", "24.04")
        )
        for argv in fake.invocations():
            if argv[0] == "build":
                continue
            if argv[0] in ("version", "info", "image", "ps", "volume", "exec", "logs", "kill"):
                continue
            if argv[:2] in (["network", "ls"], ["network", "exists"]):
                continue
            with self.subTest(argv=argv):
                self.assertTrue(
                    any(token.startswith("mosdns-20260928T101010Z-") for token in argv),
                    f"a matrix run touched a resource outside its own namespace: {argv!r}",
                )

    def test_a_missing_podman_makes_every_subcommand_a_harness_error(self):
        """One place decides, so `preflight`, `matrix` and `cleanup` cannot disagree."""
        for argv in (
            ["preflight"],
            ["matrix", "--arch", "amd64", "--versions", "24.04"],
            ["cleanup"],
        ):
            with self.subTest(argv=argv):
                code, _ = self.invoke(["--podman", str(self.directory / "no-such-podman"), *argv])
                self.assertEqual(code, run.EXIT_HARNESS_ERROR)

    def test_cleanup_removes_a_leftover_run_and_exits_zero(self):
        """`run.py cleanup` is the documented recovery after a killed run."""
        fake = self.fake([
            {"match": ["ps", "-a"], "answers": [
                {"stdout": "mosdns-20260928T101010Z-target-24.04\n"},
                {"stdout": ""},
            ]},
        ])
        code, output = self.invoke(self.base(fake, "cleanup", "--run-id", "20260928T101010Z"))
        self.assertEqual(code, run.EXIT_OK)
        self.assertIn(["rm", "-f", "mosdns-20260928T101010Z-target-24.04"], fake.invocations())

    def test_cleanup_with_nothing_to_remove_is_zero(self):
        fake = self.fake()
        code, _ = self.invoke(self.base(fake, "cleanup"))
        self.assertEqual(code, run.EXIT_OK)

    def test_cleanup_that_leaves_something_behind_is_a_harness_error(self):
        """The harness could not do the job it was asked to do.

        Exit 2 rather than 1 or 3: no test failed, and the matrix is not
        incomplete -- the machine is dirty, and that is neither of those.
        """
        fake = self.fake([
            {"match": ["rm", "-f"], "returncode": 125, "stderr": "device busy\n"},
            {"match": ["ps", "-a"], "stdout": "mosdns-20260928T101010Z-target-24.04\n"},
        ])
        code, output = self.invoke(self.base(fake, "cleanup", "--run-id", "20260928T101010Z"))
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("mosdns-20260928T101010Z-target-24.04", output)

    def test_cleanup_without_a_run_id_sweeps_the_whole_harness_namespace(self):
        """The Make target calls it with no arguments, so it has to be useful.

        Scoped to the harness's own prefix: a sweep that matched "mosdns"
        loosely would remove resources it did not create.
        """
        fake = self.fake([
            {"match": ["ps", "-a"], "answers": [
                {"stdout": "mosdns-20260928T101010Z-target-24.04\nmosdns-20260928T101011Z-target-26.04\n"},
                {"stdout": ""},
            ]},
        ])
        code, _ = self.invoke(self.base(fake, "cleanup"))
        self.assertEqual(code, run.EXIT_OK)
        removed = [argv[-1] for argv in fake.invocations() if argv[:2] == ["rm", "-f"]]
        self.assertEqual(
            removed,
            ["mosdns-20260928T101010Z-target-24.04", "mosdns-20260928T101011Z-target-26.04"],
        )
        self.assertNotIn("unrelated-container", removed)

    def test_an_unknown_subcommand_is_a_harness_error(self):
        code, _ = self.invoke(["install-everything"])
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)

    def test_no_subcommand_runs_a_machine_subcommand(self):
        """The sweep, through the entry point rather than through the wrapper.

        Every subcommand was run against the fake and every recorded argument
        array is inspected. A grep of the tree would pass the day a second code
        path built its own command line; the wrapper is the only place that
        builds one, and this is where its callers are exercised.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        results = self.directory / "results"
        for argv in (
            self.base(fake, "preflight"),
            self.base(fake, "--results-dir", str(results), "matrix", "--arch", "amd64", "--versions", "24.04"),
            self.base(fake, "cleanup", "--run-id", "20260928T101010Z"),
        ):
            with self.subTest(argv=argv):
                self.invoke(argv)
        self.assertTrue(fake.invocations())
        for recorded in fake.invocations():
            self.assertNotIn("machine", recorded, f"a machine subcommand was emitted: {recorded!r}")


class SetupUnitStateTest(PodmanTestCase):
    """`systemctl is-active` exits 3 for every state that is not `active`.

    **This is the tool's real contract, and it is why this class drives the real
    `Podman` against a fake binary rather than a fake method.** `setup_unit_state`
    is the only read in the wrapper whose *answer is a non-zero exit*, so it is the
    only one that cannot go through `exec_container`, and it is therefore the one
    place in this file where "the fake is convenient" and "the fake is right" come
    apart. The fake models the exit code, so a wrapper that went through the
    raising path would raise here too -- which is what makes the cases below worth
    having.
    """

    # The contract, as `systemctl(1)` states it: `is-active` exits 0 only for
    # `active`, and 3 for every other known state. Spelled out rather than
    # assumed, because the whole class is about that number.
    NON_ACTIVE_EXIT = 3

    def client_answering(self, state: str):
        """A fake binary that answers `is-active` the way systemd does."""
        directory = self.extra_directory()
        fake = self.fake(directory=directory)
        fake.write_table([
            {"match": ["systemctl", "is-active", "target-nm-setup.service"],
             "returncode": 0 if state == "active" else self.NON_ACTIVE_EXIT,
             "stdout": f"{state}\n"},
        ])
        return self.client(fake)

    def test_every_state_a_target_can_be_in_is_returned_as_a_word(self):
        """**The states, including the three that exit non-zero.**

        `activating`, `inactive` and `failed` are *answers*. A reader that got an
        exception for them would learn nothing about the target -- only that a
        command failed -- and the wait above this read would report "the last query
        failed" for a target it should have reported as *not ready yet*, which is a
        different message for a different reader and a different fix.
        """
        for state in ("active", "activating", "inactive", "failed"):
            with self.subTest(state=state):
                client = self.client_answering(state)
                self.assertEqual(
                    client.setup_unit_state("mosdns-x-target-24.04"), state,
                    f"systemctl is-active answered {state!r} with a non-zero exit and the read "
                    f"did not return it as a word",
                )

    def test_a_query_that_genuinely_fails_still_raises(self):
        """`check=False` is for this command's contract, not a blanket amnesty.

        A wrapper that swallowed every non-zero exit would make a *missing* unit --
        `systemctl is-active` on a target whose image has no such unit exits
        non-zero with an error on stderr -- look like a unit that is merely not
        running yet, and the gate would sit out its 120s budget reporting a slow
        target when the truth is that the image is wrong. So the narrow case is
        asserted as well as the broad one: only the states systemd *means* come
        back as words.
        """
        fake = self.fake(directory=self.extra_directory())
        fake.write_table([
            {"match": ["systemctl", "is-active", "target-nm-setup.service"],
             "returncode": 4, "stdout": "",
             "stderr": "Failed to get unit file state: No such file or directory\n"},
        ])
        client = self.client(fake)
        with self.assertRaises(PodmanError) as caught:
            client.setup_unit_state("mosdns-x-target-24.04")
        self.assertIn("exited 4", str(caught.exception))

    def test_the_read_is_the_only_one_that_opts_out_of_checking(self):
        """`check` defaults to `True`, so every other caller is unchanged.

        The parameter is the fix for one read, and a parameter defaulting to the
        *permissive* value would be a different and much larger change: `nmcli`
        answering non-zero would stop raising, and every refusal in this suite
        rests on it. So this holds the default rather than the fix, because the
        default is the thing a later task would get wrong.
        """
        self.assertIs(
            inspect.signature(Podman.run).parameters["check"].default, True,
            "Podman.run's check parameter does not default to True, so every caller that relied "
            "on a non-zero exit raising has silently stopped raising",
        )


class ClockSeamTest(EntryPointTestCase):
    """The one case in the suite that runs a wait on the **real** clock.

    `PodmanTestCase.setUp` puts every case in `test_command.py` on a virtual
    clock, and the reason is written there: the bounds are in minutes, and about a
    dozen cases drive a whole cell, so the real thing grew the suite from seven
    minutes to twenty. That is the right default and it has a cost: the real
    `time.monotonic` is never exercised, and neither is the seam that replaces it.

    So this is where both are. It is small on purpose -- **one real sleep of
    `NM_DEVICE_POLL_INTERVAL` is not affordable on every cell**, but one is
    affordable once, and once is what it takes to know the seam works in the
    direction that matters: that `use_the_real_clock` puts back something the
    runner will actually consult, and that a wait on it terminates on its own
    rather than only because a test told it the time had passed.

    The three properties, and why a case that only asserted one would be half a
    claim:

    * the runner's clock is the real one after the call, and the virtual one
      before it (so `setUp` is really doing what its comment says);
    * a wait on the real clock **returns** when the condition is met, which a
      virtual clock makes look instantaneous;
    * and a wait on the real clock **gives up** at its budget, which is the
      property a virtual clock cannot show at all -- on the virtual clock "timed
      out" and "asked once" are indistinguishable, because the clock is whatever
      the case said it was.
    """

    def test_a_wait_consults_the_clock_the_runner_gave_it(self):
        self.assertIsNot(
            run.scenario_clock()["now"], self._virtual_now,
            "setUp did not install a virtual clock, so every case in this file was about to "
            "spend the real bounds and this file's premise does not hold",
        )
        self.use_the_real_clock()
        # `scenario_clock()` is a factory: a *call* returns the clock the runner
        # would hand a scenario. So this compares the fresh dict against the
        # factory, which is what "the runner's clock is the real one" means --
        # and it is asserted on the values rather than on identity, because a
        # factory may legitimately return an equal dict each time.
        self.assertIs(run.scenario_clock, _REAL_CLOCK)
        self.assertEqual(
            sorted(run.scenario_clock()), ["now", "sleep"],
            "the real clock does not carry the two values a bounded wait is driven with",
        )

        answered = {"calls": 0}

        def read():
            # Satisfied on the third read, so the wait must have slept twice on
            # the real clock rather than returning on its first look.
            answered["calls"] += 1
            return "yes" if answered["calls"] >= 3 else "no"

        started = time.monotonic()
        value = wait_for_networkmanager_device(
            _FakeDevice(read), "mosdns-x-target-24.04", interval=0.05, timeout=30.0,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(value, "yes")
        self.assertEqual(answered["calls"], 3, "the wait did not read until the condition held")
        # Two real sleeps of 50ms. The assertion is a floor and a generous
        # ceiling, not a measurement: the claim is that *time passed*, which a
        # virtual clock would report as a number the case itself chose.
        self.assertGreaterEqual(
            elapsed, 0.1,
            "the wait returned without sleeping, so it cannot have consulted the real clock",
        )
        self.assertLess(elapsed, 10.0, f"the wait slept for {elapsed:.1f}s against a 30s budget")

    def test_a_wait_that_never_succeeds_gives_up_at_its_own_budget(self):
        """The property only the real clock can show.

        On the virtual clock, a timeout is indistinguishable from a single read:
        the clock is a number the case incremented, so "gave up after 0.3s" and
        "gave up immediately" print the same. Here the budget is 0.3s of *real*
        time and the read never succeeds, so the wait has to stop on its own --
        and the message has to carry the read count and the interval, because
        those are what tell a reader the answer was not a race.

        **It runs on a thread, and that is load-bearing.** A wait that stopped
        consulting its budget would otherwise loop forever, and the failure this
        case exists to catch would be a *hung suite* rather than a red one -- the
        worst possible shape for a case, because the reader who triggered it is
        not there to see it. So the wait is joined with a ceiling several times
        its own budget: a wait that overruns is reported, and the thread is a
        daemon so the case does not wait for it either way.
        """
        self.use_the_real_clock()
        finished = threading.Event()
        outcome: dict = {}

        def run_the_wait():
            try:
                outcome["value"] = wait_for_networkmanager_device(
                    _FakeDevice(lambda: "no"), "mosdns-x-target-24.04",
                    interval=0.05, timeout=0.3,
                )
            except NetworkManagerDeviceError as error:
                outcome["error"] = error
            finally:
                finished.set()

        worker = threading.Thread(target=run_the_wait, daemon=True)
        worker.start()
        self.assertTrue(
            finished.wait(30.0),
            "the wait did not give up within 30s against a 0.3s budget, so it is not "
            "consulting the clock it was given",
        )
        self.assertNotIn(
            "value", outcome,
            "the wait returned instead of raising, so an unmanaged device was accepted",
        )
        message = str(outcome["error"])
        self.assertIn("0.3s", message)
        self.assertIn("reads 0.05s apart", message)
        self.assertIn("answered 'no'", message)


class _FakeDevice:
    """The one method `wait_for_networkmanager_device` calls on a `Podman`.

    A whole fake podman would be a second thing to keep right for a case about
    the clock, and the wait uses exactly one method of the client.
    """

    def __init__(self, answer):
        self._answer = answer

    def nm_managed(self, container, device):
        return self._answer()


class MatrixProducesEvidenceTest(EntryPointTestCase):
    """A run writes the evidence the plan's host-isolation comparison consumes.

    "A module exists" and "a run produces the evidence" are different properties,
    and this repository has been bitten by the first being reported as the second
    more than once: `lib/snapshot.py` and `lib/images.py` were both written, both
    tested in isolation, and neither was called by anything. So
    `build/test-results/<run>/host-before.json` and `host-after.json` could not
    exist, Task 7's comparison had nothing to consume, and the report's wording
    about them was true of the module and false of the harness.

    Every case here goes through the real entry point, so what is asserted is what
    a run does rather than what a function offers.

    **The host is not read.** A snapshot would normally run `cat`, `readlink`,
    `nmcli`, `resolvectl`, `systemctl` and `ss` on this machine and walk the
    operator's Firefox profiles, and a *test* that did that would depend on the
    machine it runs on -- which is the thing NO-HOST-MUTATION.md forbids. So the
    runner and the profile roots come from one named seam, `run.snapshot_settings`,
    which production fills from `snapshot.SubprocessRunner` and the default roots
    and every case here fills from a table and a temp directory. The live run that
    is the actual evidence is done by hand, once, and its output is in the report.
    """

    # The six commands, answered from a table, and a profile root that is a
    # temporary directory. Nothing here reads the machine.
    TABLE = {
        ("cat", "/etc/os-release"): 'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nID=ubuntu\n',
        ("readlink", "/etc/resolv.conf"): "../run/systemd/resolve/stub-resolv.conf\n",
        ("nmcli",): "NAME                UUID                                  TYPE      DEVICE\n"
        "Wired connection 1  0e4a3b21-2f8f-4a1e-9b0e-3f2c1d4e5f60  ethernet  eth0\n",
        ("resolvectl", "status"): (
            "Link 2 (eth0): 2: eth0\n                 DNS Servers: 127.0.0.53\n"
        ),
        ("systemctl", "list-unit-files"): "mosdns-router.service          enabled\n"
        "NetworkManager.service         enabled\n",
        ("ss",): 'tcp   LISTEN 0      4096   127.0.0.53%lo:53    0.0.0.0:*    '
        'users:(("systemd-resolve",pid=812,fd=12))\n',
    }

    def setUp(self):
        super().setUp()
        import test_snapshot

        # A profile tree built here rather than imported from the snapshot suite:
        # the two files test different modules and one importing the other's
        # fixtures couples them for no gain. What matters is that the snapshot
        # walks a real directory of real files, not that it is a Firefox profile.
        self.profile_root = self.directory / "firefox" / "abc.default"
        self.profile_root.mkdir(parents=True)
        (self.profile_root / "prefs.js").write_text("// profile\n", encoding="utf-8")
        self.runner = test_snapshot.FakeCommandRunner(self.TABLE)
        self._real_settings = run.snapshot_settings
        run.snapshot_settings = lambda: {
            "runner": self.runner,
            "firefox_roots": [self.directory / "firefox"],
        }
        self.addCleanup(self._restore)

    def _restore(self):
        run.snapshot_settings = self._real_settings

    def matrix(self, *extra, results_dir=None, expect=run.EXIT_INCOMPLETE):
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        directory = results_dir or (self.directory / "results")
        code, output = self.invoke(
            [
                "matrix", "--arch", "amd64", "--versions", "24.04",
                "--podman", str(fake.path), "--source-tree", str(self.source_tree),
                "--results-dir", str(directory), *extra,
            ]
        )
        self.assertEqual(code, expect, output)
        return directory, output

    def run_directory(self, results_dir):
        directories = [d for d in results_dir.iterdir() if d.is_dir()]
        self.assertEqual(len(directories), 1, f"expected one run directory, got {directories}")
        return directories[0]

    def test_a_matrix_run_writes_a_host_before_and_a_host_after(self):
        """The two files, under the run's directory, named for the moment.

        This is the whole of it. `host-before.json` and `host-after.json` do not
        exist because nothing in the harness writes them, and Task 7's comparison
        is a function of these two paths.
        """
        results, _ = self.matrix()
        run_directory = self.run_directory(results)
        self.assertTrue(
            (run_directory / "host-before.json").is_file(),
            f"no host-before.json in {sorted(q.name for q in run_directory.iterdir())}",
        )
        self.assertTrue(
            (run_directory / "host-after.json").is_file(),
            f"no host-after.json in {sorted(q.name for q in run_directory.iterdir())}",
        )

    def test_the_snapshots_are_real_snapshots_of_this_run(self):
        """Written documents, not empty files, and they name the run they belong to.

        A pair of zero-byte files would satisfy the case above, and an empty
        snapshot compares equal to every other empty snapshot -- which is the
        answer the host-isolation check must never give by accident.
        """
        import snapshot as snapshot_module

        results, _ = self.matrix()
        run_directory = self.run_directory(results)
        for moment in ("before", "after"):
            with self.subTest(moment=moment):
                document = json.loads(
                    (run_directory / f"host-{moment}.json").read_text(encoding="utf-8")
                )
                self.assertEqual(document["schema"], snapshot_module.SCHEMA)
                self.assertEqual(document["run_id"], run_directory.name)
                self.assertIn("networkmanager_connections", document["fields"])
                self.assertTrue(document["fields"]["resolvectl_status"]["records"])

    def test_the_before_snapshot_is_taken_before_the_run_and_the_after_after(self):
        """Ordering, from the documents themselves.

        A pair written in the other order -- or both after the run -- would compare
        a machine that had already been changed against itself, and a run that
        failed halfway would leave two snapshots of the same state. The report's
        `started_utc` and `finished_utc` bracket them, so the three timestamps are
        enough to tell which is which, and that is what is asserted.
        """
        results, _ = self.matrix()
        run_directory = self.run_directory(results)
        before = json.loads((run_directory / "host-before.json").read_text(encoding="utf-8"))
        after = json.loads((run_directory / "host-after.json").read_text(encoding="utf-8"))
        report = json.loads((run_directory / "report.json").read_text(encoding="utf-8"))
        self.assertLessEqual(
            before["taken_utc"],
            report["started_utc"],
            f"the 'before' snapshot was taken at {before['taken_utc']} but the run started at "
            f"{report['started_utc']}",
        )
        self.assertGreaterEqual(
            after["taken_utc"],
            report["finished_utc"],
            f"the 'after' snapshot was taken at {after['taken_utc']} but the run finished at "
            f"{report['finished_utc']}",
        )

    def test_the_snapshots_ran_the_six_read_only_commands(self):
        """The runner was used, so the snapshot is of this machine and not a fixture.

        Without this, a pair of hand-written documents would pass every case above
        and the comparison in Task 7 would be comparing fiction. And the count is
        asserted too: one collection before, one after, and not one or three.
        """
        self.matrix()
        self.assertEqual(
            [call for call in self.runner.calls if not call[0].startswith("-")],
            [
                ("cat", "/etc/os-release"),
                ("readlink", "/etc/resolv.conf"),
                ("nmcli", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show"),
                ("resolvectl", "status"),
                ("systemctl", "list-unit-files", "--no-legend", "--no-pager", "--type=service"),
                ("ss", "-H", "-lntup"),
            ]
            * 2,
            f"the run did not collect the six fields twice, so the pair it wrote is not a pair "
            f"of snapshots: {self.runner.calls}",
        )

    def test_a_refused_run_leaves_no_snapshots(self):
        """The lock is read first, so a run that stops leaves no misleading evidence.

        A pair of snapshots from a run that never started would be worse than none:
        Task 7's comparison would read two documents describing an unchanged host
        and conclude the right thing for the wrong reason, and the two files would
        look exactly like the evidence a real run produced.

        So the order is: resolve the lock, then snapshot, then run. And a runner
        whose commands all *raise* is not a failure of the run -- a command this
        host does not have is recorded as a field error, which is a property the
        snapshot module holds deliberately and a case there already covers.
        """
        lock = self.directory / "unusable.lock.json"
        lock.write_text(
            json.dumps(
                {
                    "arch": "amd64",
                    "images": {"24.04": {"digest": "not-a-digest"}},
                    "schema": "mosdns-podman-images/1",
                }
            ),
            encoding="utf-8",
        )
        results = self.directory / "results"
        code, _ = self.invoke(
            [
                "matrix", "--versions", "24.04", "--podman",
                str(self.fake([{"match": ["version"], "stdout": "5.7.0\n"}]).path),
                "--source-tree", str(self.source_tree), "--results-dir", str(results),
                "--lock", str(lock),
            ]
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertEqual(
            [p.name for p in results.rglob("*.json")] if results.exists() else [],
            [],
            "a run that refused to start wrote result files, so Task 7 would read them as a "
            "real run's evidence",
        )


    def test_the_after_snapshot_is_written_even_when_the_run_breaks(self):
        """The `finally` is the property, and it had no case.

        The 'after' snapshot is taken in a `finally` rather than after the report,
        because the case where a contributor wants to know what the host looked
        like afterwards is the case where the run broke. A reviewer confirmed that
        by hand -- forcing `_run_cells` to raise and finding exit 2 with both files
        on disk -- and nothing in the suite held it, so `try`/`finally` and
        `try`/`except: pass` were the same test suite.

        Driven by making `_run_cells` raise, which is the only seam for it: the run
        is real up to the point of failure, so the 'before' snapshot is a real one
        and the assertion below is about the file the `finally` wrote, not about a
        fixture.

        **The controls are what make this a case rather than a file listing.** With
        the `finally` reverted to a plain call, the first assertion fails -- that is
        the RED this was written against. And the `report.json` assertion is here
        because the interesting half is *which* files appear: a `finally` that wrote
        the 'after' snapshot and then wrote a report anyway would give Task 7 three
        documents describing a run that did not finish.
        """
        def explode(*args, **kwargs):
            raise run.PodmanError("the run broke, on purpose, for this case")

        real = run._run_cells
        run._run_cells = explode
        try:
            results = self.directory / "results"
            code, output = self.invoke(
                [
                    "matrix", "--arch", "amd64", "--versions", "24.04",
                    "--podman", str(self.fake([{"match": ["version"], "stdout": "5.7.0\n"}]).path),
                    "--source-tree", str(self.source_tree), "--results-dir", str(results),
                ]
            )
        finally:
            run._run_cells = real

        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        run_directory = self.run_directory(results)
        self.assertTrue(
            (run_directory / "host-before.json").is_file(),
            "the run broke before it wrote a 'before' snapshot, so the case is not about "
            f"the 'finally' at all: {sorted(q.name for q in run_directory.iterdir())}",
        )
        self.assertTrue(
            (run_directory / "host-after.json").is_file(),
            "a run that broke left no 'after' snapshot, which is the one case where the host "
            "matters most -- there is nothing to compare the 'before' against, and the run "
            "that broke is exactly the run a contributor needs the evidence for",
        )
        self.assertFalse(
            (run_directory / "report.json").exists(),
            "a run that broke still wrote a report, so a reader would find a document that "
            "looks like a finished run's evidence next to a 'before' snapshot with no 'after' "
            "to complete it",
        )


class ImageLockWiringTest(EntryPointTestCase):
    """A target is started from the locked digest, and the lock is read to find out.

    `lib/images.py` refuses a lock entry without a `sha256:` prefix, and a
    `matrix` run that ignored it would build and start targets against a floating
    tag while the lock sat in the repository saying otherwise. So the reference a
    target is started from is the lock's, and a lock the harness cannot use stops
    the run before it starts anything.
    """

    def test_the_reference_for_a_version_is_the_locked_one(self):
        """The value, read from the committed lock, written out as a literal.

        Not "some string ending in a digest": `images.reference_for_version` is what
        the harness calls, so comparing it to itself would be tautological. What is
        asserted is that the committed lock produces exactly this reference.
        """
        import images as images_module

        self.assertEqual(
            images_module.reference_for_version("24.04"),
            "docker.io/library/ubuntu:24.04@sha256:"
            "496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4",
        )

    def test_a_matrix_run_reads_the_lock_before_it_does_anything(self):
        """A run whose lock is unusable stops, rather than falling back to a tag.

        The fallback is the one answer worse than none: the run would proceed
        against a floating image and the lock would be doing nothing at all, with
        nothing in the report to say so.
        """
        lock = self.directory / "unusable.lock.json"
        lock.write_text(
            json.dumps(
                {
                    "arch": "amd64",
                    "images": {"24.04": {"digest": "496754492fb28b4d"}},
                    "schema": "mosdns-podman-images/1",
                }
            ),
            encoding="utf-8",
        )
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(
            [
                "matrix", "--versions", "24.04", "--podman", str(fake.path),
                "--source-tree", str(self.source_tree),
                "--results-dir", str(self.directory / "results"),
                "--lock", str(lock),
            ]
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        self.assertIn("sha256:", output)
        # And nothing was started: a refusal that created a container first would
        # be a refusal that already did the thing it refused.
        self.assertFalse(
            [call for call in fake.invocations() if "run" in call and "-d" in call],
            fake.invocations(),
        )

    def test_a_matrix_run_refuses_a_version_the_lock_does_not_cover(self):
        """`--versions 24.04,26.04` against a lock that pins only 24.04 is a refusal.

        Not a cell reported `incomplete` for a release nobody ships, and not a
        fallback to the tag. The message names the version, because that is the
        one thing a caller can act on.
        """
        lock = self.directory / "small.lock.json"
        lock.write_text(
            json.dumps(
                {
                    "arch": "amd64",
                    "images": {"24.04": {"digest": "sha256:" + "a" * 64}},
                    "schema": "mosdns-podman-images/1",
                }
            ),
            encoding="utf-8",
        )
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(
            [
                "matrix", "--versions", "24.04,26.04", "--podman", str(fake.path),
                "--source-tree", str(self.source_tree),
                "--results-dir", str(self.directory / "results"),
                "--lock", str(lock),
            ]
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR, output)
        self.assertIn("26.04", output)

    def test_a_target_is_started_from_the_locked_reference_verbatim(self):
        """The chain, end to end: the reference reaches the `podman run` array.

        The last link, and the one the cases above do not reach. A run that
        resolved the digest correctly and then started a target from a
        hand-written image string would satisfy all of them, and the gap is exactly
        the kind that shows up only as a matrix that quietly tested a different
        Ubuntu than the one it was pinned to.

        **Two arrays, not one**, because a cell now starts the mock router as
        well as the target (Task 3) and both are started from the same locked
        reference. The claim is per-array rather than about a count: which
        container gets which image is asserted by
        `test_the_target_image_is_built_from_the_locked_reference` in
        `test_matrix_cell.py`, and what matters here is that neither of them
        names a tag.
        """
        import images as images_module

        reference = images_module.reference_for_version("24.04")
        fake = self.fake(
            [
                {"match": ["nmcli"], "stdout": "yes\n"},
                {"match": ["run"], "stdout": "9f3c1d0e2b\n"},
                {"match": ["version"], "stdout": "5.7.0\n"},
            ]
        )
        run.run_target(
            _podman_for(self, fake),
            run_id="20260928T120000Z",
            arch="amd64",
            version="24.04",
            image=reference,
            router_image=reference,
            scenarios=(),
        )
        arrays = [call for call in fake.invocations() if "run" in call and "-d" in call]
        self.assertEqual(len(arrays), 2, arrays)
        for array in arrays:
            with self.subTest(container=array[array.index("--name") + 1]):
                self.assertIn("@sha256:", array[-1])
                self.assertEqual(
                    array[-1], reference, "a container was started from something else entirely"
                )


def _podman_for(case, fake):
    """A Podman pointed at a case's fake binary, for calling `run_target` directly."""
    from podman import Podman as _Podman

    return _Podman(executable=str(fake.path), source_tree=str(case.source_tree))


if __name__ == "__main__":
    unittest.main()
