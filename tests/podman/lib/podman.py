"""The only place in this repository that builds a Podman argument array.

Every container, network and volume this harness creates goes through the
:class:`Podman` object here. That is not tidiness, it is the boundary: the
harness runs on somebody's working system, and the properties that keep it off
that system's resolver are all properties of how a command line is built.

* **No shell, ever.** A scenario's command is an argument array, so a test name,
  a hostname or a version string can never become a second command.
* **No machine.** ``podman machine`` needs qemu. This host has none, is not
  going to get any, and the previous architecture of the Podman plan was built
  on it. Rootless Podman is the architecture now, and the refusal is here
  because this is the only module that builds an argument array.
* **A hatch with a ceiling.** ``extra_args`` is the escape every later task
  reaches for when something will not start, so the policy is enforced there
  and not merely documented: a cap ceiling, no device, no seccomp or apparmor
  override, no ``--volumes-from``, no privilege flag, and no host namespace --
  in both spellings pflag accepts, in any position, without returning early.
* **A redacted environment.** The child gets a named set of variables and
  nothing else, so a token in the operator's shell cannot reach a command line
  and then a report.
* **A connection is an argument.** ``--connection`` is a Podman *service* URI
  for a remote or native service, never a machine name, and it is passed on
  every invocation rather than written to a configuration file that would change
  every other podman user on the machine. Omitted -- the default -- is the local
  rootless Podman, which is the acceptance path here. The shape is checked at
  construction, not documented: a bare word is refused.

Nothing in this module installs, enables or starts anything on the host, reads
the host's resolver, or mutates NetworkManager. The commands it builds are the
commands a disposable container run needs.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

# Every command gets a deadline. A harness that blocks forever on a Podman
# service that has wedged reports nothing, and a wedged service is exactly what
# a broken run looks like from the outside.
DEFAULT_TIMEOUT = 120.0

# The grace period given to a container's init to shut down. systemd inside the
# target needs a moment to stop the units it started; the plan measures 30.
STOP_TIME_SECONDS = 30

# The variables a child may inherit. The list is an allowlist rather than a
# subtraction because the set of variables that carry a secret is open-ended
# and the set that rootless Podman needs is not.
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

# The first non-flag token of an argument array is the Podman subcommand. A
# refusal is keyed on it so that a *value* that happens to spell a forbidden
# word -- an image named `machine`, a path -- is not a false positive, while a
# real subcommand is caught wherever it appears in the array.
MACHINE_SUBCOMMAND = "machine"

# The source tree, read-only, and the cgroup filesystem. These two are the whole
# of what this harness may bind into a target container, and the second is the
# only mount that is allowed to live under one of the five forbidden roots --
# a systemd container will not start without its cgroup hierarchy, and the
# exception is the cgroup *filesystem* rather than the whole of /sys, which is
# where the host's NetworkManager state and interfaces live.
WORKSPACE_MOUNT_POINT = "/workspace"
CGROUP_HOST_PATH = "/sys/fs/cgroup"
CGROUP_MOUNT_POINT = "/sys/fs/cgroup"

# The host roots the plan forbids binding into a target container. The allowlist
# above is what enforces this; the list is kept because a refusal that names the
# root it broke is a diagnosis and a refusal that says "refused" is a shrug.
FORBIDDEN_HOST_ROOTS = ("/etc", "/run", "/var", "/sys", "/home")

# Flags that would hand a target the host it runs on, and the value each one
# is refused *with*. `--privileged` is the obvious one and takes no value;
# `--cgroupns=host` was written for the machine architecture this plan no longer
# has, is measured not to start systemd here, and puts a container's cgroup
# changes on the host's hierarchy; the namespace-sharing flags are the same
# escape in five spellings. `extra_args` is the hatch every later task reaches
# for when something will not start, so the hatch is where the refusal lives.
#
# Keyed on the flag's NAME and the value it carries, because pflag accepts both
# `--flag value` and `--flag=value` for a string flag, and because
# `run_container` emits its own `--network <net>` before `extra_args` -- so the
# last occurrence of a repeated flag is the one podman reads. A list of
# `--flag=value` strings checked with `token == flag or token.startswith(flag +
# "=")` refuses the equals form only, which is a check on a spelling rather than
# on a policy.
FORBIDDEN_CONTAINER_FLAGS = {
    "--privileged": None,
    "--cgroupns": "host",
    "--network": "host",
    "--pid": "host",
    "--ipc": "host",
    "--uts": "host",
    "--userns": "host",
}

# The flag names alone, for a caller that wants to know which names are policed
# without repeating the value table.
FORBIDDEN_CONTAINER_FLAG_NAMES = tuple(sorted(FORBIDDEN_CONTAINER_FLAGS))

# Families refused outright, in both spellings, whatever the value. A device is
# host hardware; a seccomp or apparmor override removes a layer of the boundary
# the caps are inside; `--volumes-from` is another container's filesystems, and
# the name would have to be one this harness created for the boundary to mean
# anything, which is a property of the caller rather than of the flag.
FORBIDDEN_CONTAINER_FLAG_FAMILIES = (
    "--device",
    "--security-opt",
    "--volumes-from",
)

# The cap ceiling. The measured target needs exactly these three, and
# `--cap-add=ALL` is a one-word route to every capability including `SYS_ADMIN`
# for a target that does not need it. The ceiling is the three measured values
# rather than a denylist of the dangerous ones, so a capability nobody has
# thought of yet is refused too.
ALLOWED_CAPABILITIES = ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE")


class PodmanError(RuntimeError):
    """A Podman command failed, was refused, or could not be built."""


class PodmanTimeout(PodmanError):
    """A Podman command ran past its deadline and was abandoned."""


class MountPolicyError(PodmanError):
    """A bind mount was refused: it is not one of the two allowed mounts."""


class ContainerPolicyError(PodmanError):
    """A container flag was refused: it would give the target the host."""


class NetworkManagerDeviceError(PodmanError):
    """A running target is not the machine these scenarios need.

    Raised only for the device state, and its message always names the two
    steps that fix it, because this failure is not the project's bug.
    """


# The device a target gets on a netavark bridge network, and the two steps that
# make NetworkManager manage it. Both are measured facts and both are stated
# wherever the check is, because the previous plan's SKIPPED list came from
# believing the sequence was impossible.
NM_DEVICE = "eth0"
NM_MANAGED_FIELD = "GENERAL.NM-MANAGED"
NM_MANAGED_YES = "yes"
NM_MANAGE_STEPS = (
    "nmcli device set eth0 managed yes",
    "systemctl restart NetworkManager",
)
# A connection profile has to exist on the device before the override sticks.
# Measured here, not assumed: with a profile for eth0 present, the two steps
# above take the device to `yes` on three consecutive fresh containers, and
# without one the two steps leave the field at `no` on every container tried.
#
# The profile is created by the target image's ENTRYPOINT, as its first step
# (the plan's Task 2, Step 3), and not at scenario time: the entrypoint's two
# steps are what need it, so creating it later would leave every target booting
# unmanaged and every cell of the matrix incomplete with exit 3. The plan's
# Task 3 step 4 modifies the profile the entrypoint created, post-boot, for
# `ipv4.never-default yes`. This comment is the harness's copy of that
# ordering, and the refusal below is where a reader learns it.
NM_PROFILE_STEP = (
    "a connection profile must already exist for the device, e.g. "
    "'nmcli connection add type ethernet ifname eth0 con-name eth0-managed "
    "ipv4.method auto' -- with no profile the override is accepted and the "
    "field stays 'no'"
)
NM_UNMANAGED_EXPLANATION = (
    "A target's device is only managed after a connection profile exists for "
    "it and then both steps, in that order, in the target container's own "
    "init: the override is written under /run/NetworkManager/devices/ and "
    "only the restart re-reads it, so the first command on its own returns "
    "success and does not take effect. The device must also be a bridge "
    "network's eth0 of type ethernet -- Podman's default rootless network "
    "hands a container a tun/tap device, which NetworkManager refuses by "
    f"design. Note also that {NM_PROFILE_STEP}."
)


def _forbidden_root(path: str, exempt_cgroup: bool = True) -> str | None:
    """The forbidden host root `path` is inside, if any.

    `/sys/fs/cgroup` is inside `/sys`, and it is the measured exception, so a
    path that is inside a forbidden root and is not the cgroup filesystem is
    what this names. The exception belongs to that one *mount*, so a caller
    deciding whether a path may be the source tree passes
    `exempt_cgroup=False`: allowing `/sys/fs/cgroup` as the workspace would
    bind the host's cgroup hierarchy at `/workspace` instead of a checkout.
    """
    if exempt_cgroup and (path == CGROUP_HOST_PATH or path.startswith(CGROUP_HOST_PATH + "/")):
        return None
    resolved = os.path.normpath(path) if path else ""
    for root in FORBIDDEN_HOST_ROOTS:
        if resolved == root or resolved.startswith(root + "/"):
            return root
    return None


# The schemes a Podman *service* URI can carry. A connection is a URI or it is
# nothing: the harness refuses a machine, and this is where the refusal is
# structural rather than a sentence in a docstring.
CONNECTION_SCHEMES = ("ssh://", "unix://", "tcp://", "npipe://")


def _checked_connection(connection: str | None) -> str | None:
    """The connection URI, or a refusal naming the shapes that are not one.

    A bare word is refused because that is how a machine is spelled: `podman
    --connection podman-machine-default` is a valid invocation, and this
    harness's whole architecture is that there is no machine. A name of any
    other kind is still ambiguous -- podman resolves it through a shared
    configuration file, which is a second piece of state this plan refuses to
    write -- so a connection is either a URI or it is absent.

    The check is the shape, not a list of known machines: an unknown scheme is
    refused too, because a scheme this harness cannot read is a connection it
    cannot vouch for, the same rule the mount options are held to.
    """
    if connection is None or connection == "":
        return None
    if not any(connection.startswith(scheme) for scheme in CONNECTION_SCHEMES):
        raise PodmanError(
            f"refusing --connection {connection!r}: a connection is a Podman service URI, "
            f"never a name. It must start with one of "
            f"{', '.join(CONNECTION_SCHEMES)} -- a bare word would name a podman machine, and "
            f"this harness uses rootless containers on the local host and has no machine at all. "
            f"Omit the option for the local rootless Podman, which is the acceptance path"
        )
    return connection


def _checked_source_tree(source_tree: str | None) -> str | None:
    """The source tree, resolved, or a refusal when it is not a legal parameter.

    The mount allowlist is an allowlist of two, and the second entry is
    parameterized: a checkout is wherever the operator's checkout is, and
    pinning it would make the harness unusable. But the parameter *decides what
    /workspace contains*, so a source tree of `/etc` or of `/` made the policy
    `run.py --source-tree /etc matrix` bind the host's `/etc` -- including its
    `/etc/resolv.conf` -- into a target that holds SYS_ADMIN and runs systemd.
    Every later check compares the source against the allowlist's own entry, so
    a parameter that is itself forbidden makes them agree and the check passes.
    That is the defect this function exists to close: the parameter must be
    legal, not only the destinations.

    Checked after resolution, so `/etc/../etc` and `//etc` are refused too --
    a check on the raw string is defeated by a relative component, and a
    relative component is what an operator types out of habit. `/` is refused
    explicitly: it is not under any of the five roots in the sense the prefix
    test uses, and it contains all five.
    """
    if not source_tree:
        return None
    resolved = str(Path(source_tree).resolve())
    if resolved == "/":
        raise MountPolicyError(
            f"refusing source tree {resolved!r}: it is the whole filesystem, which contains "
            f"every forbidden host root ({', '.join(FORBIDDEN_HOST_ROOTS)}). The source tree is "
            f"mounted read-only at {WORKSPACE_MOUNT_POINT}, and a mount of '/' would put the "
            f"host's /etc, /run, /var, /sys and /home there instead of a checkout"
        )
    root = _forbidden_root(resolved, exempt_cgroup=False)
    if root:
        raise MountPolicyError(
            f"refusing source tree {resolved!r}: it would be bound at {WORKSPACE_MOUNT_POINT} "
            f"read-only, and it is under the forbidden host root {root}, which this plan does "
            f"not mount into a target container. Point --source-tree at a checkout outside "
            f"{', '.join(FORBIDDEN_HOST_ROOTS)}"
        )
    return resolved


def _parse_mount_spec(spec: str) -> tuple[str | None, str | None, list[str]]:
    """Read one mount specification as (source, destination, options).

    Podman accepts a colon-separated `-v` value and a keyed `--mount` value, and
    a policy that read only one of them would be a policy on a spelling.
    """
    if "," in spec and "=" in spec.split(",")[0]:
        fields: dict[str, str] = {}
        for part in spec.split(","):
            key, separator, value = part.partition("=")
            fields[key.strip()] = value.strip() if separator else ""
        source = fields.get("src") or fields.get("source")
        destination = fields.get("dst") or fields.get("destination") or fields.get("target")
        options = sorted(key for key, value in fields.items() if not value and key != "type")
        return source, destination, options
    parts = spec.split(":")
    if len(parts) == 1:
        # A bare token is an anonymous volume: a resource the harness would
        # create without recording it, which cleanup then cannot remove.
        return parts[0], None, []
    options_text = ",".join(parts[2:])
    options = [option for option in options_text.split(",") if option]
    return parts[0], parts[1], options


@dataclass(frozen=True)
class CommandResult:
    """What a Podman command returned.

    The environment is deliberately absent. A result is the thing a scenario
    attaches to a report, and a whole environment is the one thing that can put
    a secret into a file that gets archived.
    """

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def output(self):
        """stdout with the trailing newline Podman adds removed."""
        return self.stdout.strip()


def _subcommand_of(args: Sequence[str]) -> str:
    """The first token of `args` that is not a flag or a flag's value."""
    expect_value = False
    for token in args:
        if expect_value:
            expect_value = False
            continue
        if token.startswith("-"):
            # A `--flag=value` carries its value; a bare `--flag` may or may
            # not, and podman's global flags are all of the first shape.
            expect_value = "=" not in token
            continue
        return token
    return ""


class Podman:
    """A Podman client that builds argument arrays and holds the policy."""

    def __init__(
        self,
        executable: str = "podman",
        connection: str | None = None,
        source_tree: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        extra_env: Mapping[str, str] | None = None,
    ):
        self.executable = executable
        # A Podman service URI -- `ssh://…`, `unix://…`, `tcp://…`. It is never
        # a machine name: there is no machine, and a bare word is refused here
        # rather than documented in prose.
        self.connection = _checked_connection(connection)
        self.source_tree = _checked_source_tree(source_tree)
        self.timeout = timeout
        self._extra_env = dict(extra_env or {})

    # -- the command line ---------------------------------------------------

    def build_argv(self, args: Sequence[str]) -> list[str]:
        """The full argument array for one Podman invocation.

        Both policies are applied here rather than where the arrays are built,
        because this is the last point every array passes through. Raises rather
        than returning an array the harness must not run, so a policy failure
        cannot be ignored by a caller that forgot to check.
        """
        args = [str(a) for a in args]
        if not args:
            raise PodmanError("a podman invocation needs a subcommand")
        if _subcommand_of(args) == MACHINE_SUBCOMMAND:
            raise PodmanError(
                f"refusing to run 'podman {MACHINE_SUBCOMMAND}': this harness uses rootless "
                f"Podman containers only, and there is no virtual machine in it"
            )
        self._check_container_flags(args)
        self._check_mount_arguments(args)
        argv = [self.executable]
        if self.connection:
            argv += ["--connection", self.connection]
        return argv + args

    # -- the policies -------------------------------------------------------

    def allowed_mounts(self) -> dict[str, tuple[str, str]]:
        """The mounts this wrapper permits, as destination -> (source, mode)."""
        allowed = {CGROUP_MOUNT_POINT: (CGROUP_HOST_PATH, "rw")}
        if self.source_tree:
            allowed[WORKSPACE_MOUNT_POINT] = (self.source_tree, "ro")
        return allowed

    def mount_arguments(self) -> list[str]:
        """The `-v` arguments a target container is started with."""
        spec = f"{CGROUP_HOST_PATH}:{CGROUP_MOUNT_POINT}:rw"
        if self.source_tree:
            spec += f",{self.source_tree}:{WORKSPACE_MOUNT_POINT}:ro"
        return sum((["-v", part] for part in spec.split(",")), [])

    def _check_container_flags(self, args: Sequence[str]) -> None:
        """Refuse any flag that would hand the target the host, in any spelling.

        pflag accepts `--flag value` and `--flag=value` for the same string
        flag, and `run_container` appends `extra_args` after its own
        `--network <net>`, so a repeated flag's last occurrence is the one podman
        reads. Both facts are why this walks tokens, reads a flag's name and
        the value that flag carries, and compares those -- rather than matching
        a list of `--flag=value` strings, which is a check on a spelling.

        Every violation in the array is collected and reported together, and the
        scan does not stop at the first: a guard that named one and returned
        would make a caller fix them one at a time for a defect that was
        visible from the start.

        It examines the whole array, not only `extra_args`, so the wrapper's own
        flags are inside the policy rather than beside it. A wrapper that grew a
        `--cap-add=ALL` of its own would be caught by this case, and the flag
        set it is allowed to emit is asserted as literals in `ArgumentArrayTest`.

        It also examines every token rather than skipping each flag's value, and
        that is the safe direction. Skipping a value means trusting that the
        token after `--privileged` is a value; not skipping it means a token
        that *is* `--privileged` is caught wherever it sits, including where the
        caller meant it as a value. The cost is a false positive on an array
        that puts a policed flag name in a value position, which no real podman
        invocation does -- and a false positive here is a refusal with a readable
        message, while the false negative is the host.
        """
        violations: list[str] = []
        index = 0
        while index < len(args):
            token = args[index]
            index += 1
            if not token.startswith("-"):
                continue
            name, separator, inline = token.partition("=")
            # The space-separated form's value is the next token. A token that
            # is not a flag is skipped by the loop's own test, so the only extra
            # cost of reading it here is for a value that itself looks like a
            # flag -- the safe direction, as the docstring says.
            value = inline if separator else (args[index] if index < len(args) else None)

            if name in FORBIDDEN_CONTAINER_FLAG_FAMILIES:
                violations.append(
                    f"{token!r} (this harness has no opt-in for it: a device is host hardware, "
                    f"a seccomp or apparmor override removes a layer of the boundary, and "
                    f"--volumes-from is another container's filesystems)"
                )
                continue
            if name == "--cap-add":
                if value not in ALLOWED_CAPABILITIES:
                    violations.append(
                        f"{token!r} (the cap ceiling is "
                        f"{', '.join(ALLOWED_CAPABILITIES)}; --cap-add=ALL is a one-word route "
                        f"to every capability)"
                    )
                continue
            if name in FORBIDDEN_CONTAINER_FLAGS:
                forbidden_value = FORBIDDEN_CONTAINER_FLAGS[name]
                if forbidden_value is None or value == forbidden_value:
                    violations.append(
                        f"{token!r} (a target container may not be given the host it runs on. "
                        f"The measured flag set is --systemd=always --cgroupns=private with "
                        f"{', '.join(ALLOWED_CAPABILITIES)}, and no privilege or host-namespace "
                        f"flag)"
                    )
        if violations:
            raise ContainerPolicyError(
                "refusing to start the target:\n"
                + "\n".join(f"  - {violation}" for violation in violations)
            )

    def _check_mount_arguments(self, args: Sequence[str]) -> None:
        index = 0
        while index < len(args):
            token = args[index]
            if token in ("-v", "--volume", "--mount"):
                if index + 1 >= len(args):
                    raise MountPolicyError(
                        f"'{token}' is the last argument in the array and carries no mount"
                    )
                self._check_mount(args[index + 1])
                index += 2
                continue
            if token.startswith("--volume=") or token.startswith("--mount="):
                self._check_mount(token.split("=", 1)[1])
            index += 1

    def _check_mount(self, spec: str) -> None:
        source, destination, options = _parse_mount_spec(spec)
        if destination is None:
            raise MountPolicyError(
                f"refusing mount '{spec}': a bare token is an anonymous volume, and a volume "
                f"this harness did not record is one cleanup cannot remove"
            )
        for option in options:
            if option in ("Z", "z"):
                raise MountPolicyError(
                    f"refusing mount '{spec}': ':{option}' relabels the file on the host, which "
                    f"is a change to this machine made by a command whose job is to change "
                    f"nothing here"
                )
            if option not in ("ro", "rw"):
                raise MountPolicyError(
                    f"refusing mount '{spec}': '{option}' is not a mount option this harness "
                    f"uses, and an option it does not recognise is one it cannot vouch for"
                )
        if "ro" in options and "rw" in options:
            raise MountPolicyError(f"refusing mount '{spec}': it is both read-only and writable")
        if not source.startswith("/"):
            raise MountPolicyError(
                f"refusing mount '{spec}': '{source}' is a relative path, so it resolves "
                f"against a working directory rather than naming a host path"
            )
        allowed = self.allowed_mounts()
        if destination not in allowed:
            root = _forbidden_root(destination)
            detail = (
                f", and {destination} is under the host root {root} this plan forbids mounting"
                if root
                else ""
            )
            raise MountPolicyError(
                f"refusing mount '{spec}': the only destinations this harness mounts are "
                f"{', '.join(sorted(allowed))}{detail}"
            )
        want_source, want_mode = allowed[destination]
        if source != want_source:
            root = _forbidden_root(source)
            detail = (
                f" -- {source} is under the host root {root}, which this plan forbids mounting"
                if root
                else ""
            )
            raise MountPolicyError(
                f"refusing mount '{spec}': {destination} may only be bound to {want_source}{detail}"
            )
        effective_mode = "ro" if "ro" in options else "rw"  # podman's default is rw
        if effective_mode != want_mode:
            wanted = "read-only" if want_mode == "ro" else "writable"
            raise MountPolicyError(
                f"refusing mount '{spec}': {destination} must be mounted {wanted} and this one "
                f"is {effective_mode}"
            )

    def run(self, args: Sequence[str], timeout: float | None = None) -> CommandResult:
        """Run one Podman command and return what it produced.

        Streams are captured, the status is checked, and the deadline is
        explicit. A caller that wanted the status instead of an exception wants
        a different method.
        """
        argv = self.build_argv(args)
        try:
            completed = subprocess.run(
                argv,
                cwd=self.working_directory,
                env=self.child_environment(),
                capture_output=True,
                text=True,
                timeout=self.timeout if timeout is None else timeout,
                check=True,
            )
        except subprocess.TimeoutExpired as expired:
            raise PodmanTimeout(
                f"'{' '.join(argv)}' ran longer than "
                f"{expired.timeout}s and was abandoned"
            ) from expired
        except subprocess.CalledProcessError as failed:
            raise PodmanError(
                f"'{' '.join(self.build_argv(args))}' exited {failed.returncode}"
                + (f":\n{failed.stderr.strip()}" if failed.stderr.strip() else "")
            ) from failed
        return CommandResult(
            argv=tuple(argv),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    # -- the child's environment --------------------------------------------

    def child_environment(self) -> dict[str, str]:
        """The environment a Podman command is started with.

        A named set of variables from the operator's environment, plus whatever
        the harness passes explicitly. Nothing else, so a variable this machine
        happens to export cannot reach a command line.
        """
        env = {name: os.environ[name] for name in FORWARDED_ENV_NAMES if name in os.environ}
        env.update(self._extra_env)
        return env

    def forwarded_env_names(self) -> tuple[str, ...]:
        """The names the wrapper forwards from the operator's environment."""
        return FORWARDED_ENV_NAMES

    @property
    def working_directory(self) -> str:
        return self.source_tree or os.getcwd()

    # -- the operations the harness needs ------------------------------------

    def client_version(self) -> str:
        return self.run(["version", "--format", "{{.Client.Version}}"]).output

    def store_graph_driver(self) -> str:
        return self.run(["info", "--format", "{{.Store.GraphDriverName}}"]).output

    def create_network(self, name: str, subnet: str) -> CommandResult:
        return self.run(["network", "create", "--subnet", subnet, name])

    def inspect_network(self, name: str) -> str:
        return self.run(["network", "inspect", name, "--format", "{{.Name}}"]).output

    def remove_network(self, name: str) -> CommandResult:
        return self.run(["network", "rm", name])

    def network_exists(self, name: str, timeout: float | None = None) -> bool:
        """Whether a network is still there, asked the way podman answers it.

        `network exists` exits 0 for present and 1 for absent, and says nothing
        on stderr in the absent case. A non-zero status that *does* carry a
        diagnostic is a service that could not be asked, which is a different
        answer and is raised rather than reported as absence -- a teardown that
        read it as absence would claim a clean sweep it never performed.

        The deadline is a parameter for the same reason `run`'s is: this is the
        question at the end of a run, and a caller with a shorter budget than
        the default has to be able to say so rather than wait out the full one.
        """
        argv = self.build_argv(["network", "exists", name])
        try:
            completed = subprocess.run(
                argv,
                cwd=self.working_directory,
                env=self.child_environment(),
                capture_output=True,
                text=True,
                timeout=self.timeout if timeout is None else timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as expired:
            raise PodmanTimeout(
                f"'{' '.join(argv)}' ran longer than {expired.timeout}s and was abandoned"
            ) from expired
        if completed.returncode == 0:
            return True
        if completed.returncode == 1 and not completed.stderr.strip():
            return False
        raise PodmanError(
            f"'{' '.join(argv)}' exited {completed.returncode}"
            + (f":\n{completed.stderr.strip()}" if completed.stderr.strip() else "")
        )

    def run_container(
        self,
        image: str,
        name: str,
        network: str,
        extra_args: Sequence[str] = (),
    ) -> str:
        """Start a target container and return its id.

        The flags are the ones measured to work on this host: systemd as the
        init, a private cgroup namespace, three capabilities, and the cgroup
        filesystem bound in. `--cgroupns=host` and `--privileged` are not here
        and must not be added -- the first does not start, the second reaches
        the host this harness is required not to touch.
        """
        args = [
            "run",
            "-d",
            "--name", name,
            "--network", network,
            "--systemd=always",
            "--cgroupns=private",
            "--cap-add=SYS_ADMIN",
            "--cap-add=NET_ADMIN",
            "--cap-add=SYS_PTRACE",
        ]
        args += self.mount_arguments()
        args += list(extra_args)
        args.append(image)
        return self.run(args).output

    def exec_container(self, container: str, *command: str) -> CommandResult:
        return self.run(["exec", container, *[str(c) for c in command]])

    def exec_script(self, container: str, script: str) -> CommandResult:
        """Run a shell script inside a container.

        The script is one argument. It is never given to a shell on this side
        of the boundary, so nothing in a scenario name or a path can be
        interpreted here.
        """
        return self.run(["exec", container, "sh", "-c", script])

    def copy_to(self, container: str, host_path: str, container_path: str) -> CommandResult:
        return self.run(["cp", str(host_path), f"{container}:{container_path}"])

    def stop(self, container: str) -> CommandResult:
        return self.run(["stop", "--time", str(STOP_TIME_SECONDS), container])

    def remove_container(self, name: str) -> CommandResult:
        return self.run(["rm", "-f", name])

    def create_volume(self, name: str) -> CommandResult:
        return self.run(["volume", "create", name])

    def remove_volume(self, name: str) -> CommandResult:
        return self.run(["volume", "rm", "-f", name])

    def all_container_names(self, prefix: str) -> tuple[str, ...]:
        """Every container whose name starts with `prefix`, running or not.

        The filter is anchored with a leading `^` because Podman's `name=`
        filter is a substring match. An unanchored `mosdns-` finds another run's
        containers as well, and a teardown that sweeps by prefix would remove
        them -- which matters because two runs on one machine is the normal
        case, not an edge case.
        """
        result = self.run(
            ["ps", "-a", "--filter", f"name=^{prefix}", "--format", "{{.Names}}"]
        )
        return tuple(line for line in result.output.splitlines() if line)

    def all_volume_names(self, prefix: str) -> tuple[str, ...]:
        result = self.run(
            ["volume", "ls", "--filter", f"name=^{prefix}", "--format", "{{.Name}}"]
        )
        return tuple(line for line in result.output.splitlines() if line)

    def network_names(self, prefix: str) -> tuple[str, ...]:
        """Every network whose name starts with `prefix`.

        Anchored for the same reason as the container and volume listings, and
        read back rather than reconstructed: a cleanup that removed a network
        by a name it had invented would report an error for a network that
        never existed.
        """
        result = self.run(["network", "ls", "--format", "{{.Name}}"])
        return tuple(line for line in result.output.splitlines() if line.startswith(prefix))

    def available(self) -> bool:
        """True when the executable exists on this machine.

        A preflight uses it to report a missing Podman rather than to install
        one: the harness never installs its own prerequisites.
        """
        return shutil.which(self.executable) is not None or Path(self.executable).exists()

    def nm_managed(self, container: str, device: str = NM_DEVICE) -> str:
        """Ask a running target whether NetworkManager manages its device.

        The query is a fixed read built as an argument array, not a script, so
        it is the same bytes on every run. `check=True` means a target where the
        device does not exist raises rather than answering.
        """
        return self.exec_container(
            container, "nmcli", "-g", NM_MANAGED_FIELD, "device", "show", device
        ).output


def assert_networkmanager_manages_device(
    podman: Podman, container: str, device: str = NM_DEVICE
) -> str:
    """Fail unless NetworkManager manages `device` in a running target.

    This is the check the previous plan's largest SKIPPED list was built on the
    absence of. A target that boots with an unmanaged `eth0` produces a
    scenario failure that reads like an installer bug -- every DNS assertion
    downstream fails at once, and for a reason that has nothing to do with the
    package. So the harness asserts it before any scenario runs, and the
    refusal names the two steps that produce a managed device rather than
    saying "unmanaged" and leaving the reader to work it out.

    Returns the value the field held, which is `yes` on the only path that does
    not raise.
    """
    try:
        value = podman.nm_managed(container, device)
    except PodmanError as error:
        raise NetworkManagerDeviceError(
            f"NetworkManager device check failed in {container}: {error}\n"
            f"Make the target manage {device} before any scenario runs:\n"
            f"  1. {NM_MANAGE_STEPS[0]}\n"
            f"  2. {NM_MANAGE_STEPS[1]}\n"
            f"{NM_UNMANAGED_EXPLANATION}"
        ) from error
    if value != NM_MANAGED_YES:
        raise NetworkManagerDeviceError(
            f"NetworkManager does not manage {device} in {container}: "
            f"'nmcli -g {NM_MANAGED_FIELD} device show {device}' answered {value!r}, "
            f"not {NM_MANAGED_YES!r}\n"
            f"Make the target manage {device} before any scenario runs:\n"
            f"  1. {NM_MANAGE_STEPS[0]}\n"
            f"  2. {NM_MANAGE_STEPS[1]}\n"
            f"{NM_UNMANAGED_EXPLANATION}"
        )
    return value


# -- the lifecycle ------------------------------------------------------------

# Every resource this harness creates carries this prefix, and the run id that
# follows it. The prefix is what makes a sweep safe: it is a namespace, so a
# teardown can find what a run left behind without finding anything else.
RESOURCE_PREFIX = "mosdns"

# The plan's fixed private network. A bridge network, not Podman's default
# rootless one, because the default hands a container a tun/tap device that
# NetworkManager refuses by design.
DEFAULT_NETWORK_SUBNET = "10.89.0.0/24"


class CleanupFailed(PodmanError):
    """Teardown left something of this run behind.

    Carries the result so a caller can say which resource, rather than only
    that something did.
    """

    def __init__(self, result: "CleanupResult"):
        self.result = result
        super().__init__(
            "teardown left resources of this run behind: "
            + ", ".join(f"{kind} {name}" for kind, name in result.survivors)
            + "\nrun 'python3 tests/podman/run.py cleanup --run-id "
            + result.run_id
            + "' once the cause is cleared"
        )


@dataclass(frozen=True)
class TeardownError:
    """One teardown step that failed, kept even when nothing survived.

    Recorded rather than raised, because a step that failed and left nothing
    behind has done its job and a run that reports it as a failure teaches
    everybody to ignore leaks.
    """

    kind: str
    name: str
    message: str


@dataclass(frozen=True)
class CleanupResult:
    """What teardown did, what it could not do, and what is still there.

    `survivors` is a (kind, name) pair per resource rather than a bare name, so
    "a network survived" and "a container survived" are different problems and
    a reader of a failure is told which one they have.
    """

    run_id: str
    removed: tuple[str, ...] = ()
    errors: tuple[TeardownError, ...] = ()
    survivors: tuple[tuple[str, str], ...] = ()

    @property
    def ok(self) -> bool:
        """True when nothing of this run survives.

        Not "when nothing failed". The question a teardown has to answer is
        whether the machine is clean, and podman is asked directly rather than
        inferred from the harness's own bookkeeping.
        """
        return not self.survivors


def new_run_id(when: datetime | None = None) -> str:
    """A UTC run id, compact enough for a container name and sortable as text.

    The timestamp is UTC because the run id is also the result directory's name
    and the two have to agree in a log from a machine in another timezone.
    """
    moment = when or datetime.now(timezone.utc)
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y%m%dT%H%M%SZ")


class RunResources:
    """The resources one run owns, and their teardown.

    Naming is the whole mechanism: every container, network and volume carries
    this run's prefix, so `cleanup` can be both precise -- it removes what this
    run created and nothing else -- and complete, because it can also find a
    resource a scenario created without recording it.
    """

    def __init__(
        self,
        podman: Podman,
        run_id: str,
        network: str | None = None,
        scope: str | None = None,
    ):
        self.podman = podman
        self.run_id = run_id
        self.network = network
        # A run makes one network, but `run.py cleanup` sweeps the namespace
        # across every run this harness has made, so teardown takes a list.
        self.networks: list[str] = [network] if network else []
        # What this teardown is responsible for. It is this run's own prefix
        # for a run, and the whole `mosdns-` namespace for a sweep, so a bare
        # `run.py cleanup` clears every run and a session's teardown never
        # reaches a parallel one.
        self.scope = scope if scope is not None else (f"{RESOURCE_PREFIX}-{run_id}" if run_id else RESOURCE_PREFIX)
        self.containers: list[str] = []
        self.volumes: list[str] = []
        self.cleanup_result: CleanupResult | None = None

    @property
    def prefix(self) -> str:
        return f"{RESOURCE_PREFIX}-{self.run_id}"

    def container_name(self, role: str, version: str) -> str:
        return f"{self.prefix}-{role}-{version}"

    def volume_name(self, role: str) -> str:
        return f"{self.prefix}-{role}"

    def network_name(self, name: str) -> str:
        return f"{self.prefix}-{name}"

    def track_container(self, name: str) -> str:
        self.containers.append(name)
        return name

    def track_volume(self, name: str) -> str:
        self.volumes.append(name)
        return name

    def _attempt(self, kind: str, name: str, action) -> tuple[str | None, str | None]:
        """Run one teardown step, reporting rather than raising.

        A teardown that returns on the first failure strands everything after
        it: one stuck container would leave the network and the volumes behind
        too, and the next run would find a network it did not create.
        """
        try:
            action()
        except PodmanError as error:
            return None, f"{kind} {name}: {error}"
        return name, None

    def cleanup(self) -> CleanupResult:
        """Remove this run's resources and report what is still there.

        Containers, then the network, then volumes -- the order is required,
        not chosen: a container attached to a network cannot be removed after
        the network is gone.

        Each container is **stopped** before it is removed, and this is the
        correction of a claim the first report made: `podman rm -f` does not
        stop a container gracefully, it SIGKILLs it. A systemd target's units
        are then never shut down, its journal is truncated at the kill rather
        than closed, and `systemd-resolved`'s state is whatever the kernel left
        -- which is exactly the state the later tasks read out to decide
        whether the package's units behaved. `stop --time 30` gives the init the
        grace period to stop what it started, and it happens before the
        removal, which is the only order in which it means anything.
        """
        removed: list[str] = []
        errors: list[TeardownError] = []

        def shut_down(n: str) -> tuple[str | None, str | None]:
            """Stop a container, then remove it, reporting rather than raising."""
            self.podman.stop(n)
            return self.podman.remove_container(n)

        for name in list(self.containers):
            done, message = self._attempt("container", name, lambda n=name: shut_down(n))
            (removed.append(done) if done else errors.append(TeardownError("container", name, message)))
        # The sweep catches a container a scenario created without recording it.
        for name in self.podman.all_container_names(self.scope):
            if name in removed:
                continue
            done, message = self._attempt("container", name, lambda n=name: shut_down(n))
            (removed.append(done) if done else errors.append(TeardownError("container", name, message)))

        for name in list(self.networks):
            done, message = self._attempt("network", name, lambda n=name: self.podman.remove_network(n))
            (removed.append(done) if done else errors.append(TeardownError("network", name, message)))
        # And the same sweep for the networks. A network this run created and
        # did not record was previously *reported* and left behind, which is
        # the one thing a teardown must not do: the next run finds a network it
        # did not create, and `run.py cleanup` is the documented recovery for
        # exactly that situation. The containers and the volumes were swept
        # here already; a network was the odd one out.
        for name in self.podman.network_names(self.scope):
            if name in removed:
                continue
            done, message = self._attempt("network", name, lambda n=name: self.podman.remove_network(n))
            (removed.append(done) if done else errors.append(TeardownError("network", name, message)))

        for name in list(self.volumes):
            done, message = self._attempt("volume", name, lambda n=name: self.podman.remove_volume(n))
            (removed.append(done) if done else errors.append(TeardownError("volume", name, message)))
        for name in self.podman.all_volume_names(self.scope):
            if name in removed:
                continue
            done, message = self._attempt("volume", name, lambda n=name: self.podman.remove_volume(n))
            (removed.append(done) if done else errors.append(TeardownError("volume", name, message)))

        # The survivorship question, asked of podman rather than of this
        # bookkeeping: the harness may have forgotten a name, and podman cannot.
        # The prefix is the namespace this teardown is responsible for, which is
        # this run's own prefix for a run and the harness namespace for a sweep
        # across every run -- so a network or container from a parallel run is
        # not this teardown's business, and one from an earlier run is.
        survivors: list[tuple[str, str]] = [
            ("container", name) for name in self.podman.all_container_names(self.scope)
        ]
        survivors += [("volume", name) for name in self.podman.all_volume_names(self.scope)]
        survivors += [("network", name) for name in self.podman.network_names(self.scope)]
        for name in self.networks:
            if self.podman.network_exists(name):
                survivors.append(("network", name))

        result = CleanupResult(
            run_id=self.run_id,
            removed=tuple(removed),
            errors=tuple(errors),
            survivors=tuple(survivors),
        )
        self.cleanup_result = result
        return result


@contextlib.contextmanager
def podman_session(podman: Podman, run_id: str, network: str | None = None):
    """Run a body of scenarios, then tear the run down however the body ended.

    The teardown is in a `finally` because the shape that leaks is the obvious
    one: do the work, then remove the resources on the next line, which the
    exception skips. And a teardown failure is raised *only* when nothing else
    is propagating -- raising it over a scenario's own exception would replace
    the installer's error with "a container survived" and destroy the evidence
    for why the run failed. The result is attached to the run either way, so
    the leak is reported beside the failure rather than instead of it.
    """
    resources = RunResources(podman, run_id, network)
    try:
        yield resources
    finally:
        result = resources.cleanup()
        if not result.ok and sys.exc_info()[0] is None:
            raise CleanupFailed(result)
