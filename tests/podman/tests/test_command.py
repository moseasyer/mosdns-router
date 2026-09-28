"""Hold the Podman harness to the four things that keep it off this machine.

The harness in `tests/podman` runs the real installer, the real NetworkManager
integration and the real resolver inside disposable containers. Three of its
properties are what make that safe to do on somebody's working system, and
this file is where they are held:

* **The host is not a target.** The source tree is mounted read-only and only at
  ``/workspace``, the one other mount is the cgroup filesystem, and nothing under
  ``/etc``, ``/run``, ``/var``, ``/sys`` or ``/home`` is ever bound in. These
  cases read the *mount arguments the wrapper actually emits*, not a list of
  strings somebody can reorder, and they hold the refusal itself: a validator
  that cannot fail is not a validator.
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

import contextlib
import importlib.util
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
# The harness is used from a source checkout, so its library directory is the
# import root. There is no installed distribution of it.
sys.path.insert(0, str(REPO / "tests" / "podman" / "lib"))

from podman import (  # noqa: E402
    CleanupFailed,
    ContainerPolicyError,
    MountPolicyError,
    NetworkManagerDeviceError,
    Podman,
    PodmanError,
    PodmanTimeout,
    RunResources,
    assert_networkmanager_manages_device,
    new_run_id,
    podman_session,
)
from report import ScenarioResult  # noqa: E402

# `run.py` is a script rather than an installed module, and it is loaded by
# path so that this file's own name cannot collide with it.
_spec = importlib.util.spec_from_file_location("mosdns_podman_run", REPO / "tests" / "podman" / "run.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

# The five host roots the plan forbids binding into a target container, and the
# one mount of a forbidden root that is the measured, required exception: the
# cgroup filesystem, which a systemd container cannot start without.
FORBIDDEN_HOST_ROOTS = ("/etc", "/run", "/var", "/sys", "/home")
WORKSPACE = "/workspace"
CGROUP = "/sys/fs/cgroup"


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
    sys.stdout.write(answer.get("stdout", ""))
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

    DEFAULT_RULES = ({"match": ["network", "exists"], "returncode": 1},)

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
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        # A stand-in for the source tree. It is never read; the wrapper only
        # ever names it on a mount argument.
        self.source_tree = self.directory / "source"
        self.source_tree.mkdir()
        # The wrapper resolves the path it was given, so the expected value in
        # these cases is the resolved one.
        self.source_tree = self.source_tree.resolve()

    def fake(self, rules=None):
        return FakePodmanBinary(self.directory, rules)

    def client(self, fake, **kwargs):
        # Nothing is plumbed through the environment: the fake finds its own
        # table beside itself, so the wrapper's allowlist is exercised exactly
        # as a real run would exercise it.
        return Podman(
            executable=str(fake.path),
            source_tree=str(self.source_tree),
            **kwargs,
        )


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

    def test_exec_passes_the_command_as_separate_arguments(self):
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
                "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "-v", f"{self.source_tree}:/workspace:ro",
                "localhost/mosdns-target:24.04",
            ],
        )

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


class ContainerPolicyTest(PodmanTestCase):
    """A target container may not be handed the host it runs on.

    The measured flag set for a systemd target is three capabilities, a private
    cgroup namespace and no privilege flag. `extra_args` is the escape hatch
    every later task reaches for when something will not run, so the three
    flags that would defeat the isolation are refused there rather than trusted
    to the caller.
    """

    def test_privileged_is_refused(self):
        with self.assertRaises(ContainerPolicyError) as caught:
            self.client(self.fake()).run_container(
                image="localhost/mosdns-target:24.04",
                name="mosdns-x-target-24.04",
                network="mosdns-testnet",
                extra_args=["--privileged"],
            )
        self.assertIn("--privileged", str(caught.exception))

    def test_the_host_cgroup_namespace_is_refused(self):
        """`--cgroupns=host` was written for the architecture this plan dropped.

        It is also the flag that makes a container's cgroup changes land on the
        host's hierarchy, and it is measured not to start systemd here.
        """
        with self.assertRaises(ContainerPolicyError) as caught:
            self.client(self.fake()).run_container(
                image="localhost/mosdns-target:24.04",
                name="mosdns-x-target-24.04",
                network="mosdns-testnet",
                extra_args=["--cgroupns=host"],
            )
        self.assertIn("--cgroupns=host", str(caught.exception))

    def test_sharing_a_host_namespace_is_refused(self):
        for flag in ("--pid=host", "--ipc=host", "--userns=host", "--network=host"):
            with self.subTest(flag=flag):
                with self.assertRaises(ContainerPolicyError) as caught:
                    self.client(self.fake()).run_container(
                        image="localhost/mosdns-target:24.04",
                        name="mosdns-x-target-24.04",
                        network="mosdns-testnet",
                        extra_args=[flag],
                    )
                self.assertIn(flag, str(caught.exception))

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

    def test_an_ordinary_extra_argument_is_still_allowed(self):
        """The refusal is three flags, not a closed door.

        A guard that refused anything would be replaced the first time a
        scenario needed `--ip`, and the guard would be gone with it.
        """
        fake = self.fake()
        self.client(fake).run_container(
            image="localhost/mosdns-target:24.04",
            name="mosdns-x-target-24.04",
            network="mosdns-testnet",
            extra_args=["--ip", "10.89.0.10", "--hostname", "mosdns-target"],
        )
        argv = fake.only()
        self.assertEqual(argv[-5:], ["--ip", "10.89.0.10", "--hostname", "mosdns-target", "localhost/mosdns-target:24.04"])


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
        without the two-step sequence, and the operator reading the message is
        the only one who can fix it.
        """
        fake = self.fake([{"match": ["nmcli"], "stdout": "no\n"}])
        with self.assertRaises(NetworkManagerDeviceError) as caught:
            assert_networkmanager_manages_device(self.client(fake), "mosdns-x-target-24.04")
        message = str(caught.exception)
        self.assertIn("nmcli device set eth0 managed yes", message)
        self.assertIn("systemctl restart NetworkManager", message)

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
            [argv[:2] for argv in fake.invocations()][-3:],
            [["ps", "-a"], ["volume", "ls"], ["network", "exists"]],
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
        """The sweep is anchored on this run's prefix, not on the word `mosdns`.

        An unanchored filter would remove the containers of a run happening in
        parallel, and two runs on one machine is the normal case rather than an
        edge case.
        """
        fake = self.fake([
            {"match": ["ps", "-a"], "answers": [
                {"stdout": "mosdns-20260928T101010Z-rogue\n"},
                {"stdout": ""},
            ]},
        ])
        with podman_session(self.client(fake), "20260928T101010Z"):
            pass
        filters = [argv[3] for argv in fake.invocations() if argv[:2] in (["ps", "-a"], ["volume", "ls"])]
        self.assertEqual(
            filters,
            ["name=^mosdns-20260928T101010Z"] * 4,
        )
        removed = [argv[-1] for argv in fake.invocations() if argv[:2] == ["rm", "-f"]]
        self.assertNotIn("mosdns-20260928T101011Z-target-24.04", removed)

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
        fake = self.fake([{"match": ["nmcli"], "stdout": "yes\n"}])
        self.scenario_results(fake)
        started = [argv for argv in fake.invocations() if argv[:2] == ["run", "-d"]]
        self.assertEqual(started[0][3], "mosdns-20260928T101010Z-target-24.04")

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


class CommandLineTest(PodmanTestCase):
    """The exit codes are the interface a release gate reads.

    0 all requested tests passed, 1 a test failure, 2 a harness or
    configuration error, 3 an incomplete matrix or a skipped required
    architecture. They are exercised through the real entry point rather than
    through the report's properties alone, because the number a Make target
    sees comes from `main` and not from the object it was derived on.
    """

    def invoke(self, argv):
        """Run the entry point and return (exit code, everything it printed)."""
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(printed):
            code = run.main(argv)
        return code, printed.getvalue()

    def base(self, fake, *extra):
        return ["--podman", str(fake.path), "--source-tree", str(self.source_tree), *extra]

    def test_preflight_reports_a_missing_podman_and_installs_nothing(self):
        """A preflight that installed Podman would break the host boundary.

        Podman is a prerequisite the operator provides; the plan says the
        harness never installs it, and a missing binary is reported rather than
        solved.
        """
        code, output = self.invoke(
            ["--podman", str(self.directory / "no-such-podman"), "preflight"]
        )
        self.assertEqual(code, run.EXIT_HARNESS_ERROR)
        self.assertIn("not found", output)
        self.assertIn("does not install", output)

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
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(self.base(fake, "preflight"))
        self.assertIn("cannot be checked", output)
        self.assertIn("no target image is built yet", output)

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
        """
        uri = "ssh://builder@arm64.example/run/podman/podman.sock"
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        code, output = self.invoke(self.base(fake, "--connection", uri, "preflight"))
        self.assertIn("service URI", output)
        self.assertTrue(fake.invocations())
        for argv in fake.invocations():
            self.assertEqual(argv[:2], ["--connection", uri])

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

    def test_matrix_creates_nothing_and_starts_nothing(self):
        """With no scenario and no image, a matrix run must not touch Podman.

        This case is what makes it safe to wire the command into a target later
        without discovering that it was already mutating this machine.
        """
        fake = self.fake([{"match": ["version"], "stdout": "5.7.0\n"}])
        self.invoke(
            self.base(fake, "--results-dir", str(self.directory / "results"),
                      "matrix", "--arch", "amd64", "--versions", "24.04")
        )
        for argv in fake.invocations():
            self.assertNotIn(argv[0], ("run", "rm", "stop", "create", "cp"), f"matrix ran {argv!r}")

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


if __name__ == "__main__":
    unittest.main()
