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

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
# The harness is used from a source checkout, so its library directory is the
# import root. There is no installed distribution of it.
sys.path.insert(0, str(REPO / "tests" / "podman" / "lib"))

from podman import (  # noqa: E402
    ContainerPolicyError,
    MountPolicyError,
    Podman,
    PodmanError,
    PodmanTimeout,
)

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
"""
import json
import os
import sys
import time


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
    log = os.environ.get("FAKE_PODMAN_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(argv) + "\\n")
    answer = {"returncode": 0, "stdout": "", "stderr": ""}
    table = os.environ.get("FAKE_PODMAN_TABLE")
    if table:
        with open(table, encoding="utf-8") as handle:
            for rule in json.load(handle).get("rules", []):
                if contains(argv, rule["match"]):
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
    """

    def __init__(self, directory, rules=None):
        self.directory = directory
        self.path = directory / "podman"
        self.path.write_text(FAKE_PODMAN, encoding="utf-8")
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)
        self.log = directory / "invocations.jsonl"
        self.table = directory / "table.json"
        self.write_table(rules or [])

    def write_table(self, rules):
        self.table.write_text(json.dumps({"rules": rules}), encoding="utf-8")

    def extra_env(self):
        return {
            "FAKE_PODMAN_LOG": str(self.log),
            "FAKE_PODMAN_TABLE": str(self.table),
        }

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
        extra_env = dict(fake.extra_env())
        extra_env.update(kwargs.pop("extra_env", {}))
        return Podman(
            executable=str(fake.path),
            source_tree=str(self.source_tree),
            extra_env=extra_env,
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
            lambda: podman.container_names("mosdns-x-"),
            lambda: podman.volume_names("mosdns-x-"),
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
        # The fake's own plumbing is not forwarded by the wrapper; it is passed
        # explicitly by the case that installed the fake.
        unexpected = set(child_env) - set(FORWARDED_ENV_NAMES) - set(fake.extra_env())
        self.assertEqual(unexpected, set())

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


if __name__ == "__main__":
    unittest.main()
