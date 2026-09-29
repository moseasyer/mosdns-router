"""Hold the installer's preflight to the properties that make it safe to run.

A preflight runs on somebody's working machine before the router that takes over
their DNS is installed, and it is the one part of the installer that runs with no
guarantee that anything has been provisioned yet. So there are exactly two things
it may do, and this file is mostly about the second one:

* **It reads, and it says.** Every check reports a fact or a refusal, and a
  refusal carries the values it refused on. A preflight that quietly normalised the
  machine, or that printed a check name without the numbers behind it, would be a
  place where a wrong machine becomes a right-looking install.
* **It never repairs, and never reaches a real command.** Preflight runs before
  this package owns any of the state it inspects, so a directory in an unexpected
  shape belongs to the operator: only ``postinst``, running as the package owner
  with the package's own lifecycle, provisions. The command boundary is the
  injected runner, so a test sees every argument array the module builds, and a
  source scan holds the rule that none of them is a string a shell would interpret.

The fake root is a temporary directory and the fake runner records argument
arrays. Nothing here reads the host's NetworkManager, ``resolved``,
``/etc/resolv.conf``, ports, or packages; the ACL cases build real extended ACLs
with ``setfacl`` inside the temporary directory rather than describing them in
prose, because the check under test is a check on a real ACL. Two cases do start
real processes -- this interpreter, printing an argument back and sleeping -- and
they touch nothing on the machine: the production runner is the one boundary a
substituted runner cannot test, and a boundary nobody has run is one nobody has
read.
"""

import contextlib
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import tokenize
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "installer"))

import mosdns_installer as installer  # noqa: E402

MODULE = REPO / "installer" / "mosdns_installer.py"
SOURCE = MODULE.read_text(encoding="utf-8")
# The class whose body is the one process boundary, named once so the scan and
# the test that bounds it cannot disagree about where it starts.
RUNNER_CLASS = "class RealCommandRunner(CommandRunner):"

# Token types that carry text rather than an operation. Python 3.12 and later
# tokenize an f-string into FSTRING_START/MIDDLE/END, so the middle -- the literal
# text between the braces, which is prose inside code -- has to be named too.
PROSE_TOKENS = tuple(
    kind
    for kind in (tokenize.COMMENT, tokenize.STRING, getattr(tokenize, "FSTRING_MIDDLE", None))
    if kind is not None
)


def code_only(source):
    """The module's code, with every comment and string literal blanked out.

    The rules a source scan holds here are about code, and a scan that cannot
    tell code from prose has to be weakened until it means nothing: this
    module's docstrings explain at length why it never builds a command string,
    so a scan over the raw text fails hardest on the file that best obeys it.

    Blanking the prose leaves the code and leaves the file readable for a human,
    which is the trade worth making: a docstring saying *why* there is no shell
    is worth more than a scan that can be satisfied by deleting the reason. The
    gap this opens is a forbidden call spelled inside a string, which is a word
    somebody wrote rather than something the module does -- and the call itself
    would still have to reach a command, which the FakeRunner refuses unless it
    is an array.
    """
    rows = source.splitlines()
    hidden = [[False] * len(row) for row in rows]
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type not in PROSE_TOKENS:
            continue
        # A token's end is a column *on its last line*, so a token spanning lines
        # has to be blanked to the end of every line but its first and its last.
        first_row, first_column = token.start
        last_row, last_column = token.end
        last_index = min(last_row, len(rows))
        for index in range(first_row - 1, last_index):
            if index == first_row - 1 and index == last_index - 1:
                columns = range(first_column, last_column)
            elif index == first_row - 1:
                columns = range(first_column, len(rows[index]))
            elif index == last_index - 1:
                columns = range(last_column)
            else:
                columns = range(len(rows[index]))
            for column in columns:
                if column < len(hidden[index]):
                    hidden[index][column] = True
    return "\n".join(
        "".join(character for column, character in enumerate(row) if not hidden[index][column])
        for index, row in enumerate(rows)
    )


CODE = code_only(SOURCE)

# The releases this package is built and reviewed for, and the only two
# architectures it ships. Both come from the plan's support matrix; a version
# outside the set is a machine whose resolver stack nobody here has read.
SUPPORTED_RELEASES = ("22.04", "24.04", "26.04")
SUPPORTED_ARCHITECTURES = ("amd64", "arm64")

# The four directories the package provisions, and the properties each has to
# hold. The list and the values are the plan's postinst table and ruling 142.
STATE_DIRECTORIES = (
    "/var/lib/mosdns",
    "/var/lib/mosdns/runtime",
    "/var/lib/mosdns/lists",
    "/run/mosdns",
)
STATE_OWNER = "root"
STATE_GROUP = "mosdns"
# A gid that is nobody's here, used to build a named ACL entry for a group that is
# not the directory's own. That is what creates a mask: an entry for the owning
# group is redundant, and one for the owning group would leave the mask wide.
ANOTHER_GID = 4242
STATE_MODE = "2770"
# The control lock is a file, created on first acquire by whichever of the two
# identities wins the race, at this mode. A pre-existing one at any other mode is
# a file this package did not create.
LOCK_MODE = "640"
CONTROL_LOCK = "/var/lib/mosdns/runtime/control.lock"
# The marker an installation of this package leaves, which is what tells a
# re-install (an upgrade, where an active service is expected) apart from a
# foreign installation.
MANAGED_BY = "/var/lib/mosdns/installer/managed-by"
MANAGED_BY_VALUE = "mosdns-router"

# The exact argument arrays the preflight builds. They are the injection boundary
# for the whole installer, so a case asserts the array rather than the answer: a
# field name that does not exist on a real nmcli then fails here rather than on
# somebody's machine.
NMCLI_CONNECTIONS = ("nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active")
# GENERAL.CONNECTION holds the connection's NAME, and `device show` does not offer
# GENERAL.CONNECTION-UUID at all. The UUID comes from this field; a lookup naming
# either of the others would leave every install recording a profile name where a
# canonical UUID belongs.
NMCLI_DEVICE_UUID = ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show")
GETFACL = "getfacl"
# The raw mode rather than `%F`: coreutils spells the type out as a word, and the
# word is "regular empty file" for a zero-length file and "regular file" for the
# rest, so a fixture answering a word would be answering a string the module could
# only compare against by luck. `%f` is the same fact as a number.
STAT_FIELDS = ("stat", "-c", "%a %U %G %f")
# `ss` with -p, so the process column is present and a holder can be attributed
# to a unit. Without -p there is no way to tell resolved's own stub from a
# foreign resolver on port 53, so the check asks for it.
SS_LISTENERS = ("ss", "-H", "-lntup")
# The unit whose main pid a port holder is compared against. `systemctl show -p
# MainPID --value` answers 0 for a unit that is not running and for one that does
# not exist, both with status 0, so "0" is the answer that matches nothing.
MAIN_PID = ("systemctl", "show", "-p", "MainPID", "--value")
RESOLVED_UNIT = "systemd-resolved.service"
ROUTER_UNIT = "mosdns-router.service"
RESOLVER_UNIT = "dnscrypt-proxy.service"

# `ss` output as it actually arrives, captured from the system-level test machine
# (`tests/system/Dockerfile`, Ubuntu 24.04, a real systemd-resolved holding its
# stub) rather than written by hand. This block is the reason the parser finds the
# local address by shape: the column count is not a property of the tool, it is a
# property of the flags.
#
# `ss -H -lntup` prints Netid, State, Recv-Q, Send-Q, Local, Peer, Process -- seven
# fields, the local address fifth. `ss -H -lntp` omits the Netid column entirely
# because only one protocol family was asked for, and the local address is fourth.
# The version of this check that read a fixed index read the fourth, which is right
# for the second invocation and wrong for the first -- and the fixture it was tested
# against was hand-written in the *second* shape, so the parser and its fixture
# agreed with each other and both disagreed with the command. That is the whole
# mechanism of the bug, and it is why both real shapes are pinned here.
RESOLVED_STUB_LISTENERS = """\
udp UNCONN 0      0         127.0.0.54:53        0.0.0.0:*          users:(("systemd-resolve",pid=39,fd=16))
udp UNCONN 0      0         127.0.0.53%lo:53     0.0.0.0:*          users:(("systemd-resolve",pid=39,fd=14))
tcp LISTEN 0      4096      127.0.0.54:53        0.0.0.0:*          users:(("systemd-resolve",pid=39,fd=17))
tcp LISTEN 0      4096      127.0.0.53%lo:53     0.0.0.0:*          users:(("systemd-resolve",pid=39,fd=15))
"""
# The same machine with `-u` dropped, captured the same way. Four fields fewer is
# not hypothetical: `ss` drops the Netid column when one protocol family is asked
# for, so the same socket is the fifth field in one invocation and the fourth in
# the other.
RESOLVED_STUB_LISTENERS_TCP_ONLY = """\
LISTEN 0      4096   127.0.0.53%lo:53   0.0.0.0:* users:(("systemd-resolve",pid=39,fd=15))
LISTEN 0      4096   127.0.0.54:53      0.0.0.0:* users:(("systemd-resolve",pid=39,fd=17))
"""
# A listening socket on an unrelated port whose Send-Q is 53, captured the same
# way. This is the line a fixed-index parser reads a port out of, and it is why
# the suite pins the queue-length case rather than only the happy one.
UNRELATED_PORT_WITH_QUEUE_53 = """\
tcp LISTEN 0      53     127.0.0.1:8080  0.0.0.0:* users:(("python3",pid=310,fd=3))
"""
UNRELATED_PORT_WITH_QUEUE_53_TCP_ONLY = """\
LISTEN 0      53         127.0.0.1:8080  0.0.0.0:* users:(("python3",pid=310,fd=3))
"""
# ONE socket, TWO processes, ONE line -- captured the same way, from a python
# process on the test machine that forked and left the child holding the
# listening descriptor it was born with (`tests/system/shared_listener.py`). No
# SO_REUSEPORT and no cooperation of any kind: a process that inherits a listening
# fd holds the same socket, and `ss` names every holder of a socket in a single
# `users:((...),(...))` field rather than one line per holder.
#
# This is the shape the port check's exemption has to be reasoned about, and the
# one a two-line fixture cannot represent: a fixture that prints a line per
# process describes two sockets, and a guard that exempts on the first owner it
# sees passes a socket resolved shares with a foreign process while every test
# built that way still agreed with it.
SHARED_LISTENER_LINE = (
    "tcp LISTEN 0      5          127.0.0.1:18081 0.0.0.0:*"
    ' users:(("python3",pid=110,fd=3),("python3",pid=108,fd=3))\n'
)
# The same demonstration on the IPv6 loopback, captured the same way. It pins two
# spellings rather than one behaviour: `ss` BRACKETS an IPv6 local address
# (`[::1]:15399`), and the peer column of an IPv6 socket is `[::]:*` rather than
# `0.0.0.0:*`. The brackets are why an address is stripped before it is compared,
# and a fixture written without them would be describing a line `ss` does not
# print -- which is the same class of mistake as the two-line shared socket above.
SHARED_IPV6_LISTENER_LINE = (
    "tcp LISTEN 0      5              [::1]:15399    [::]:*"
    ' users:(("python3",pid=136,fd=3),("python3",pid=134,fd=3))\n'
)
# The pids those lines name, and the two this package's own units would use.
RESOLVED_PID = "39"
ROUTER_PID = "41"
RESOLVER_PID = "42"

# The subcommands that change something. A --check-only run reaching any of them
# would have mutated the machine it was asked to inspect, and a test that only
# asserted "no exception" would not have noticed.
MUTATING_VERBS = frozenset(
    {
        "add", "authtoggle", "change", "connect", "con", "daemon-reload", "disable",
        "down", "edit", "enable", "general", "install", "modify", "move", "purge",
        "reapply", "reboot", "reload", "reload-or-restart", "remove", "restart",
        "revert", "set", "start", "stop", "unmask", "up",
    }
)
# Programs that can write. A preflight has no reason to run one, and a shell is
# the specific thing the argument-array discipline exists to rule out.
FILE_WRITERS = frozenset(
    {"tee", "sh", "bash", "zsh", "dash", "env", "su", "sudo", "chmod", "chown", "setfacl", "install", "dd"}
)

# The units whose active state decides whether something else already owns this
# machine's DNS.
PROJECT_SERVICES = ("mosdns-router.service", "dnscrypt-proxy.service")
PROJECT_TIMERS = (
    "mosdns-cdn-optimizer.timer",
    "mosdns-cdn-health.timer",
    "mosdns-list-check.timer",
)


def setfacl(path, entry, default=True):
    """Give ``path`` an ACL entry, with the real tool.

    The ACL check is worth nothing if the ACL it reads is a description. The two
    cases it exists for are both invisible in the mode: a directory with mode
    2770 and no extended ACL produces a state file one identity creates that the
    other cannot write, and a directory whose *access* mask is r-x produces one
    the other cannot write either -- the mode reads the same either way, because
    when an extended ACL exists the mode's group field IS the mask.

    ``default=False`` sets an access entry, which is what creates the mask.
    """
    command = ["setfacl"]
    if default:
        command.append("-d")
    command += ["-m", entry, str(path)]
    subprocess.run(command, check=True)


def fingerprint(root):
    """Every path under a root with the metadata a permission change would move.

    Mode, owner, group, size, the bytes of every file, and the extended
    attributes. A repair that wrote, re-owned or re-moded anything shows up here,
    and one that only touched an ACL shows up in the xattr half -- which is the
    repair this module must never make.
    """
    state = {}
    for directory, subdirectories, files in os.walk(root):
        for name in sorted(subdirectories) + sorted(files):
            path = Path(directory) / name
            info = path.lstat()
            entry = [
                str(path.relative_to(root)),
                stat.S_IMODE(info.st_mode),
                info.st_uid,
                info.st_gid,
                info.st_size,
            ]
            if path.is_file() and not path.is_symlink():
                entry.append(path.read_bytes())
            try:
                entry.append(sorted((key, os.getxattr(path, key)) for key in os.listxattr(path)))
            except OSError as error:
                entry.append(("xattr-error", str(error)))
            state[str(path.relative_to(root))] = entry
    return state


class FakeRunner:
    """A CommandRunner that answers prepared argument arrays and records them.

    Only an array the test prepared produces output, so a command the preflight
    must not run answers empty and is visible in ``calls``. A string argument is
    refused outright rather than recorded, which is the boundary the whole
    argument-array discipline is about: a string here is a string a shell would
    have interpreted in production.

    ``acl_reader`` is a callable rather than a canned answer because the ACL a
    directory carries is not something a test should be able to assert into
    existence: the fixture builds a real one with ``setfacl`` and the reader runs
    the real ``getfacl`` over it, so the module is checked against what the tool
    actually prints.
    """

    def __init__(self, outputs=None, returncodes=None, stderr="", acl_reader=None):
        self.outputs = {tuple(key): value for key, value in (outputs or {}).items()}
        self.returncodes = {tuple(key): value for key, value in (returncodes or {}).items()}
        self.stderr = stderr
        self.acl_reader = acl_reader
        self.calls = []

    def run(self, args, check=True):
        if isinstance(args, (str, bytes)):
            raise TypeError(
                "a command must be an argument array, never a string the shell would "
                f"have to interpret: {args!r}"
            )
        command = tuple(args)
        self.calls.append(command)
        code = self.returncodes.get(command, 0)
        if code != 0 and check:
            raise subprocess.CalledProcessError(code, command)
        stdout = self.answer(command)
        return subprocess.CompletedProcess(args=list(command), returncode=code, stdout=stdout, stderr=self.stderr)

    def answer(self, command):
        """The output for one recorded command."""
        if command in self.outputs:
            return self.outputs[command]
        if self.acl_reader is not None and command[:2] == (GETFACL, "-c"):
            return self.acl_reader(command[-1])
        return ""


class PreflightFixture(unittest.TestCase):
    """A fake root shaped like the paths preflight reads, and a runner for it."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.release("24.04")
        self.stub_resolv_conf()
        self.build_state_directories()
        self.mark_owned()

    def stub_resolv_conf(self):
        """A ``resolv.conf`` in the shape the install expects to find.

        A real machine has this as a symlink into resolved's tmpfs. A temporary
        directory cannot have a real one -- the target would have to exist under
        the fake root -- so the symlink is made to a path the check recognises by
        name without following it, which is also what the check does: it decides
        from the link's own text, because a link to a document nothing has written
        yet is still the layout the install is written for.
        """
        link = self.rooted("/etc/resolv.conf")
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to("/run/systemd/resolve/stub-resolv.conf")
        return link

    def rooted(self, absolute):
        return self.root / absolute.lstrip("/")

    def write(self, relative, contents, mode=0o644):
        path = self.rooted(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        # A path the fixture already made a symlink has to be unlinked first, or
        # writing through it would land in whatever it points at. That is a
        # property of the fixture rather than of the module, and it is why
        # `symlink_resolv` does the same.
        if path.is_symlink():
            path.unlink()
        path.write_text(contents, encoding="utf-8")
        path.chmod(mode)
        return path

    def release(self, version="24.04", ident="ubuntu"):
        return self.write(
            "/etc/os-release",
            f'NAME="Ubuntu"\nID={ident}\nVERSION_ID="{version}"\nPRETTY_NAME="Ubuntu {version}"\n',
        )

    def policy(self, enabled="true", failure="strict"):
        return self.write(
            "/etc/mosdns/policy.yaml",
            "schema_version: 1\n"
            "ech:\n"
            f"  enabled: {enabled}\n"
            f"  failure_policy: {failure}\n"
            "  stale_grace: 900\n",
        )

    def force_list(self, *domains):
        body = "# domains this router forces ECH for\n"
        for domain in domains:
            body += f"{domain}\n"
        return self.write("/etc/mosdns/force-ech-domains.txt", body)

    def mark_owned(self):
        return self.write(MANAGED_BY, f"{MANAGED_BY_VALUE}\n", mode=0o600)

    def unmark(self):
        self.rooted(MANAGED_BY).unlink()

    def build_state_directories(self, mode=STATE_MODE, acl="g::rwx", access=None):
        """Create the four state directories with real modes and real ACLs.

        The mode is applied *last*, because that is the order the interesting
        cases happen in: a named access entry creates a mask, and a chmod after it
        sets that mask, which is the whole of the access-mask case. A chmod does
        not touch a default ACL, so the default half is unaffected by the order.

        ``acl=None`` means *no extended ACL at all*, and it has to take one away
        rather than add nothing. setUp already gave these directories a default
        ACL, so a case that wanted "the right mode and no ACL" would otherwise be
        handed the very ACL it is asserting the absence of.

        ``access`` is an optional *access* ACL entry, which is what creates the
        mask.
        """
        for relative in STATE_DIRECTORIES:
            path = self.rooted(relative)
            path.mkdir(parents=True, exist_ok=True)
            if acl is None:
                # -k drops the default ACL, -b the extended access entries.
                subprocess.run(["setfacl", "-b", "-k", str(path)], check=True)
            else:
                setfacl(path, acl)
            if access is not None:
                setfacl(path, access, default=False)
            path.chmod(int(mode, 8))

    @staticmethod
    def stat_answer(mode, owner=STATE_OWNER, group=STATE_GROUP, kind=stat.S_IFDIR):
        """What ``stat -c "%a %U %G %f"`` prints for a path of this shape.

        The fourth field is the whole raw mode, type and permissions, so the
        answer is the one a real ``stat`` would give: 2770 on a directory is
        ``45f0``, not ``40000``, and a fixture that answered only the type would
        be answering something no tool produces.
        """
        return f"{mode} {owner} {group} {kind | int(mode, 8):x}"

    def state_stat_answers(self, mode=STATE_MODE, owner=STATE_OWNER, group=STATE_GROUP):
        return {
            STAT_FIELDS + (str(self.rooted(relative)),): self.stat_answer(mode, owner, group)
            for relative in STATE_DIRECTORIES
        }

    @staticmethod
    def ss_line(protocol, state, local, queue, process=None, pid=None, fd=7, netid=True):
        """One `ss -H -lntu` line, in the column order `ss` really prints.

        Netid, State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port, and
        the process column only when one is known. Single-spaced on purpose: the
        captured blocks above keep `ss`'s own padding, and a parser that needed the
        padding to find a column would be a parser that breaks on a terminal width
        change.

        ``netid=False`` drops the Netid column, which is what `ss` prints when only
        one protocol family is asked for -- so a line built here can be in the shape
        a different set of flags would produce, and a parser that reads a fixed
        index passes one of the two shapes and fails the other.
        """
        columns = [protocol] if netid else []
        columns += [state, "0", str(queue), local, "0.0.0.0:*"]
        if process is not None:
            columns.append(f'users:(("{process}",pid={pid},fd={fd}))')
        return " ".join(columns) + "\n"

    @staticmethod
    def shared_line(protocol, state, local, queue, owners, netid=True, peer=None):
        """One `ss -H -lntu` line whose single ``users:`` field names SEVERAL processes.

        ``owners`` is a sequence of ``(process, pid, fd)`` triples, and they all
        land in ONE ``users:(("a",pid=1,fd=3),("b",pid=2,fd=3))`` field, because
        that is what `ss` prints for a socket more than one process holds -- see
        :data:`SHARED_LISTENER_LINE` for the captured line and the fork that
        produced it. :meth:`ss_line` builds the one-owner shape, which is what
        `ss` prints when a socket has one holder, and the two shapes have to stay
        distinguishable: a fixture written as one line per process describes two
        sockets, and a check that only ever sees that shape cannot tell an
        exemption that reads "this socket is resolved's" from one that reads
        "this socket is resolved's *and nobody else's*".
        """
        named = ",".join(f'("{process}",pid={pid},fd={fd})' for process, pid, fd in owners)
        columns = [protocol] if netid else []
        columns += [state, "0", str(queue), local, peer if peer is not None else "0.0.0.0:*", f"users:(({named}))"]
        return " ".join(columns) + "\n"

    def listener(self, port, address="127.0.0.1", process="dnsmask", pid="1234", protocol="tcp", netid=True):
        """A listening socket on ``port`` held by a process that is not ours.

        The default is a foreign resolver on purpose: the port check's whole job
        is to refuse a port something else holds, so a fixture that defaulted to
        this package's own process would let a broken check pass.
        """
        if protocol == "tcp":
            return self.ss_line("tcp", "LISTEN", f"{address}:{port}", 4096, process, pid, netid=netid)
        return self.ss_line("udp", "UNCONN", f"{address}:{port}", 0, process, pid, netid=netid)

    def good_runner(self, answers=None, returncodes=None, stderr=""):
        """A runner answering exactly what a passing preflight asks for.

        ``answers`` is a mapping from an argument *array* to its output, and
        ``returncodes`` from an array to a status. They are positional mappings
        rather than ``**`` because the keys here are tuples and ``**`` only carries
        string keys -- and every command in this suite is named by an array, which
        is the whole point of the boundary.

        The ``getfacl`` answer is produced by running the real tool on the fake
        root's real directory rather than by a canned string. That is the only way
        this suite can hold the claim that the ACL check reads an extended ACL: a
        fixture written out by hand proves nothing about what the module does with
        what the tool prints, and the directory really does carry the ACL the
        fixture claims.
        """
        outputs = self.state_stat_answers()
        outputs.update(
            {
                ("dpkg", "--print-architecture"): "amd64",
                ("systemctl", "--version"): "systemd 255 (255.1-1ubuntu1)\n",
                NMCLI_CONNECTIONS: "Wired connection 1:11111111-1111-1111-1111-111111111111:802-3-ethernet:ens33\n",
                NMCLI_DEVICE_UUID + ("ens33",): "11111111-1111-1111-1111-111111111111\n",
                SS_LISTENERS: "",
                ("firefox", "--version"): "Mozilla Firefox 129.0\n",
                ("systemctl", "is-active", "NetworkManager.service"): "active\n",
                ("systemctl", "is-active", "systemd-resolved.service"): "active\n",
            }
        )
        for unit in PROJECT_SERVICES + PROJECT_TIMERS:
            outputs[("systemctl", "is-active", unit)] = "inactive\n"
        # resolved is running, because the fixture's resolv.conf names its stub
        # and the dependency check requires it; this package's own two services
        # are not running, so 0 -- which matches no process at all.
        for unit in PROJECT_SERVICES:
            outputs[MAIN_PID + (unit,)] = "0\n"
        outputs[MAIN_PID + (RESOLVED_UNIT,)] = f"{RESOLVED_PID}\n"
        outputs.update(answers or {})
        return FakeRunner(outputs=outputs, returncodes=returncodes, stderr=stderr, acl_reader=self._real_acl)

    def _real_acl(self, path):
        """The ACL of a fake-root path, from the real getfacl.

        A path with no extended ACL gets getfacl's real answer, which is the
        access entries and no ``default:`` line at all. That is the case the check
        exists for, and a fixture that returned something else for it would be
        hiding the very case under test.
        """
        completed = subprocess.run(
            [GETFACL, "-c", "-p", str(path)], check=False, capture_output=True, text=True
        )
        return completed.stdout

    def preflight(self, runner=None):
        return installer.preflight(self.root, runner or self.good_runner())

    def answered(self, answers):
        """The preflight with some commands answered differently."""
        return self.preflight(self.good_runner(answers))

    def assertPasses(self, runner=None, message=""):
        report = self.preflight(runner)
        self.assertEqual(
            report.problems(),
            [],
            message or "a machine this install can proceed on reported a problem",
        )
        return report


class OsReleaseTests(PreflightFixture):
    """The release: the three Ubuntu versions this package is built and reviewed for."""

    def test_accepts_every_supported_release(self):
        for version in SUPPORTED_RELEASES:
            with self.subTest(release=version):
                self.setUp()
                self.release(version)
                report = self.assertPasses()
                self.assertEqual(report.release, version)

    def test_rejects_a_missing_release_file(self):
        # An image with no /etc/os-release is a machine nothing here can reason
        # about: the version decides the systemd floor, the NetworkManager fields
        # and the unit syntax, and all three differ across the supported set.
        self.rooted("/etc/os-release").unlink()
        problems = " ".join(self.preflight().problems())
        self.assertIn("os-release", problems, "the refusal has to name the file it could not read")

    def test_rejects_a_release_file_that_is_not_a_key_value_document(self):
        for name, contents in {
            "no key/value lines at all": "Ubuntu 24.04 LTS\n",
            "a value that is empty": "ID=ubuntu\nVERSION_ID=\n",
            "no VERSION_ID": 'ID=ubuntu\nPRETTY_NAME="Ubuntu"\n',
            "a version that is not a number": "ID=ubuntu\nVERSION_ID=twentyfour\n",
            "no ID": 'VERSION_ID="24.04"\n',
            "binary": "\x00\x01\x02",
        }.items():
            with self.subTest(contents=name):
                self.setUp()
                self.write("/etc/os-release", contents)
                self.assertTrue(
                    self.preflight().problems(), f"a malformed /etc/os-release ({name}) was accepted"
                )

    def test_rejects_an_unsupported_version(self):
        for version in ("20.04", "23.10", "25.04", "27.04", "1.0"):
            with self.subTest(release=version):
                self.setUp()
                self.release(version)
                self.assertTrue(
                    self.preflight().problems(), f"Ubuntu {version} is not supported and was accepted"
                )

    def test_rejects_a_derivative_that_is_not_ubuntu(self):
        # Debian shares the resolver stack and nothing else here: no
        # systemd-resolved stub layout this package checks for, and no support
        # commitment in the plan.
        self.release(ident="debian")
        self.assertTrue(self.preflight().problems(), "a non-Ubuntu release was accepted")


class ArchitectureTests(PreflightFixture):
    """The architecture: the two this package is built for, and no others."""

    def test_accepts_every_supported_architecture(self):
        for architecture in SUPPORTED_ARCHITECTURES:
            with self.subTest(architecture=architecture):
                self.setUp()
                report = self.assertPasses(self.good_runner({("dpkg", "--print-architecture"): architecture}))
                self.assertEqual(report.architecture, architecture)

    def test_rejects_an_architecture_this_package_is_not_built_for(self):
        for architecture in ("i386", "armhf", "ppc64el", "s390x", "riscv64", ""):
            with self.subTest(architecture=architecture):
                self.setUp()
                self.assertTrue(
                    self.answered({("dpkg", "--print-architecture"): architecture}).problems(),
                    f"architecture {architecture!r} is not built and was accepted",
                )

    def test_rejects_a_machine_whose_architecture_cannot_be_read(self):
        self.assertTrue(
            self.preflight(self.good_runner(returncodes={("dpkg", "--print-architecture"): 1})).problems(),
            "a machine whose architecture cannot be read was accepted",
        )


class DependencyTests(PreflightFixture):
    """The three things this machine has to be running before its DNS is rewritten."""

    def test_reports_a_missing_dependency_by_name(self):
        for unit, name in (
            ("NetworkManager.service", "NetworkManager"),
            ("systemd-resolved.service", "systemd-resolved"),
        ):
            with self.subTest(dependency=name):
                self.setUp()
                problems = " ".join(
                    self.answered({("systemctl", "is-active", unit): "inactive\n"}).problems()
                )
                self.assertIn(
                    name,
                    problems,
                    f"a host without {name} has to be refused by name: the two have different "
                    "remedies and 'a dependency is missing' tells an operator nothing they "
                    "can act on",
                )

    def test_rejects_a_machine_without_systemd(self):
        self.assertTrue(
            self.preflight(self.good_runner(returncodes={("systemctl", "--version"): 127})).problems(),
            "a machine with no systemd was accepted",
        )

    def test_rejects_a_resolved_that_is_installed_but_not_running(self):
        # systemd-resolved installed and stopped is the state where
        # /etc/resolv.conf names a stub nothing is listening on. Rewriting DNS on
        # top of that leaves the machine with no resolver at all.
        self.assertTrue(
            self.answered({("systemctl", "is-active", "systemd-resolved.service"): "failed\n"}).problems(),
            "an installed but stopped systemd-resolved was accepted",
        )


class ResolvConfTests(PreflightFixture):
    """/etc/resolv.conf: the one file whose content decides where DNS goes."""

    def symlink_resolv(self, target):
        link = self.rooted("/etc/resolv.conf")
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target)
        return link

    def test_accepts_the_resolved_stub_symlink(self):
        self.symlink_resolv("../run/systemd/resolve/stub-resolv.conf")
        self.assertPasses()

    def test_rejects_a_resolv_conf_naming_something_other_than_the_stub(self):
        # The installer replaces what NetworkManager hands the resolver, so it has
        # to know what is answering today. A resolv.conf pointing anywhere else --
        # a DHCP nameserver, a public resolver, a hand-written file -- means
        # something other than resolved is in charge, and taking DNS over from it
        # is not what the package was written to do.
        #
        # A file that names the stub is not in this table however much else it
        # holds: the address is the fact that matters, and a search list or an
        # option beside it is resolved's own handwriting, not another resolver.
        for name, contents in {
            "a DHCP nameserver": "nameserver 192.168.1.1\n",
            "a public resolver": "nameserver 1.1.1.1\n",
            "a loopback resolver": "nameserver 127.0.0.1\n",
            "an empty file": "",
            "comments only": "# managed by something\n",
            "the stub beside a DHCP nameserver": "nameserver 127.0.0.53\nnameserver 192.168.1.1\n",
            "a search list and no nameserver": "search example.com\noptions edns0\n",
        }.items():
            with self.subTest(resolv_conf=name):
                self.setUp()
                self.write("/etc/resolv.conf", contents)
                self.assertTrue(
                    self.preflight().problems(), f"a resolv.conf holding {name} was accepted"
                )

    def test_accepts_a_resolv_conf_naming_the_stub_inline(self):
        # The stub is an address, and a file naming it points at it just as a
        # symlink does. The two layouts are the same fact about the machine, and a
        # check that accepted only the symlink would refuse a supported machine
        # for how its administrator wrote the file. The search list and the option
        # are there because a real stub-resolv.conf carries both, and a check that
        # parsed the document as a whole rather than for the address would refuse
        # the very file it is written to replace.
        self.write(
            "/etc/resolv.conf",
            "search example.com\nnameserver 127.0.0.53\noptions edns0 timeout:2\n",
        )
        self.assertPasses()

    def test_rejects_a_missing_resolv_conf(self):
        # The fixture creates the stub symlink, so this case has to take it away
        # first. A machine with no resolv.conf at all is a container or a rescue
        # shell, and there is nothing there to take DNS over from.
        self.rooted("/etc/resolv.conf").unlink()
        self.assertTrue(self.preflight().problems(), "a machine with no /etc/resolv.conf was accepted")

    def test_rejects_a_resolv_conf_pointing_at_a_symlink_that_is_not_the_stub(self):
        self.symlink_resolv("../run/systemd/resolve/resolv.conf")
        self.assertTrue(
            self.preflight().problems(),
            "a resolv.conf pointing at resolved's non-stub document was accepted: the install "
            "needs the stub, because that is the address the router replaces",
        )


class NetworkManagerConnectionTests(PreflightFixture):
    """The active connection: the one the installer is going to rewrite."""

    def test_reports_the_primary_connection_from_the_terminfo_table(self):
        runner = self.good_runner(
            {
                NMCLI_CONNECTIONS: (
                    "Wired connection 1:11111111-1111-1111-1111-111111111111:802-3-ethernet:ens33\n"
                    "lo:00000000-0000-0000-0000-000000000000:loopback:lo\n"
                )
            }
        )
        report = self.assertPasses(runner)
        self.assertIsNotNone(report.connection, "a machine with an active wired connection names none")
        self.assertEqual(report.connection.name, "Wired connection 1")
        self.assertEqual(report.connection.uuid, "11111111-1111-1111-1111-111111111111")
        self.assertEqual(report.connection.device, "ens33")
        self.assertIn(NMCLI_CONNECTIONS, runner.calls)

    def test_asks_for_the_uuid_by_the_field_that_carries_one(self):
        # GENERAL.CONNECTION is the profile's NAME, and `device show` does not
        # offer GENERAL.CONNECTION-UUID at all. A lookup naming either would give
        # every install a name where the DHCP state's UUID belongs, which the
        # publisher then refuses -- so every install would exit 2.
        runner = self.good_runner()
        self.assertPasses(runner)
        self.assertIn(
            NMCLI_DEVICE_UUID + ("ens33",),
            runner.calls,
            "the device's connection UUID is read from GENERAL.CON-UUID, the only field that "
            "carries one",
        )
        for call in runner.calls:
            joined = " ".join(call)
            self.assertNotIn(
                "GENERAL.CONNECTION-UUID", joined, f"{call} names a field `device show` does not have"
            )
            self.assertNotIn(
                "GENERAL.CONNECTION", joined, f"{call} reads a UUID from GENERAL.CONNECTION, which holds a name"
            )

    def test_a_device_uuid_that_disagrees_with_the_table_is_refused(self):
        # The two answers come from different nmcli views of the same connection.
        # A disagreement means the machine changed under the read, and an install
        # that modified a UUID from one of them would be modifying a connection the
        # other does not name.
        runner = self.good_runner(
            {NMCLI_DEVICE_UUID + ("ens33",): "99999999-9999-9999-9999-999999999999\n"}
        )
        self.assertTrue(
            self.preflight(runner).problems(),
            "a device whose connection UUID disagrees with the connection table was accepted",
        )

    def test_rejects_a_machine_with_no_active_connection(self):
        # Nothing to rewrite means nothing to route through. An install that
        # proceeded would capture a DHCP lease from an interface it cannot name,
        # and the capture is the step that publishes the state the router reads.
        for name, answer in {
            "only loopback": "lo:00000000-0000-0000-0000-000000000000:loopback:lo\n",
            "nothing at all": "",
            "only a VPN": "vpn0:22222222-2222-2222-2222-222222222222:vpn:vpn0\n",
            "a bridge with no device": "br0:33333333-3333-3333-3333-333333333333:bridge:\n",
        }.items():
            with self.subTest(connections=name):
                self.setUp()
                self.assertTrue(
                    self.answered({NMCLI_CONNECTIONS: answer}).problems(),
                    f"a machine with {name} was accepted",
                )

    def test_rejects_a_machine_whose_connections_cannot_be_read(self):
        self.assertTrue(
            self.preflight(self.good_runner(returncodes={NMCLI_CONNECTIONS: 1})).problems(),
            "a machine whose connections could not be read was accepted",
        )


class PortTests(PreflightFixture):
    """Ports 53 and 15353: the two the router and the resolver will bind.

    A stock Ubuntu already holds port 53. systemd-resolved's stub listener answers
    on 127.0.0.53 there, and the install keeps resolved in the chain -- it forwards
    to the router on 127.0.0.1 -- so the stub is not a transient state to clear
    first, it is the machine working. A check that refuses it refuses every real
    machine, and one that exempts the port without asking who holds it lets a
    second resolver answer beside the first. So the exemption is matched on the
    owning process, resolved by pid to the unit that owns it, and it is the
    *address* too: a foreign process that has taken 127.0.0.53 is refused even
    though the address is the stub's own.
    """

    def test_accepts_the_stub_listener_a_stock_machine_already_has(self):
        # The captured `ss` answer from a real machine, byte for byte. A fixture
        # written by hand is how the last version of this check came to read the
        # send-queue column as the local address: a hand-written line that omits
        # Netid agrees with a parser that is off by one field, and both are wrong
        # in the same direction, so the suite could not see it.
        #
        # The second assertion is the one that gives the first its teeth: a parser
        # that finds no ports at all also reports no problem, so "nothing was
        # refused" is only evidence if the module demonstrably read the lines and
        # asked who owns the processes on them.
        runner = self.good_runner({SS_LISTENERS: RESOLVED_STUB_LISTENERS})
        self.assertPasses(runner)
        self.assertIn(
            MAIN_PID + (RESOLVED_UNIT,),
            runner.calls,
            "the stub is exempt because resolved is the process holding it, which is a question "
            "the check has to have asked; a pass that came from reading nothing is not a pass",
        )

    def test_reports_a_foreign_process_on_the_dns_port(self):
        problems = " ".join(self.answered({SS_LISTENERS: self.listener(53)}).problems())
        self.assertIn("53", problems, "an occupied DNS port has to be named")
        self.assertIn(
            "dnsmask", problems, "the refusal has to name the process holding the port: 'port 53 "
            "is taken' sends an operator hunting, and the answer is one `ss` away",
        )

    def test_reports_a_foreign_process_on_an_address_that_looks_like_the_stub(self):
        # 127.0.0.53 is the stub's own address, so an exemption keyed on the
        # address would pass this. It is keyed on the owning process, so it does
        # not: a second resolver on the stub's address is two answers for one
        # query, and it is the exact case a port check exists to catch.
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                self.setUp()
                problems = " ".join(
                    self.answered(
                        {SS_LISTENERS: self.listener(53, address="127.0.0.53", protocol=protocol)}
                    ).problems()
                )
                self.assertIn(
                    "dnsmask", problems, f"a foreign {protocol} listener on 127.0.0.53 was accepted"
                )

    def test_accepts_this_packages_own_router_on_53_when_the_marker_claims_it(self):
        # The upgrade case. The router holds 53 by design once this package is
        # installed, and the marker is what says so -- which is the same marker
        # check_foreign_services uses, so a second installation is not excused by
        # the port check on the strength of the port check alone.
        answers = {
            SS_LISTENERS: self.listener(53, process="mosdns-router", pid=ROUTER_PID),
            MAIN_PID + (ROUTER_UNIT,): f"{ROUTER_PID}\n",
        }
        self.assertPasses(self.good_runner(answers))

    def test_reports_this_packages_own_router_on_53_without_the_marker(self):
        # The same listener, with nothing claiming it. A mosdns-router process
        # this install did not start is a foreign installation by the marker's
        # own rule, and it must not be excused here on the strength of its name.
        self.unmark()
        answers = {
            SS_LISTENERS: self.listener(53, process="mosdns-router", pid=ROUTER_PID),
            MAIN_PID + (ROUTER_UNIT,): f"{ROUTER_PID}\n",
        }
        problems = " ".join(self.preflight(self.good_runner(answers)).problems())
        self.assertIn(
            "mosdns-router", problems, "an unclaimed router on 53 has to be refused and named"
        )

    def test_accepts_this_packages_own_resolver_on_15353_when_the_marker_claims_it(self):
        answers = {
            SS_LISTENERS: self.listener(15353, process="dnscrypt-proxy", pid=RESOLVER_PID),
            MAIN_PID + (RESOLVER_UNIT,): f"{RESOLVER_PID}\n",
        }
        self.assertPasses(self.good_runner(answers))

    def test_reports_a_foreign_holder_of_the_resolver_port(self):
        for port in (53, 15353):
            with self.subTest(port=port):
                self.setUp()
                problems = " ".join(
                    self.answered({SS_LISTENERS: self.listener(port)}).problems()
                )
                self.assertIn(
                    str(port), problems, f"an occupied port {port} has to be named in the refusal"
                )

    def test_reports_a_foreign_process_sharing_the_stub_socket(self):
        # ONE line, TWO owners, one `users:((...),(...))` field -- the shape `ss`
        # prints for a socket two processes hold, captured in SHARED_LISTENER_LINE.
        # A socket resolved holds alongside a foreign process is not resolved's
        # alone: the foreign one answers for a share of the queries that arrive on
        # 53, which is the two-answers problem this check exists for, and `ss` names
        # both of them in the same breath.
        #
        # So the exemption has to be "every owner of this socket is one of ours",
        # not "some owner of this socket is one of ours". The previous version of
        # this test built two lines -- one per process -- and passed a guard that
        # only ever looked for the first owner that matched: a shape `ss` does not
        # print for one shared socket, so the guard was never exercised. Each
        # half was a socket with a single owner, and each half is decided on its
        # own.
        line = self.shared_line(
            "tcp",
            "LISTEN",
            "127.0.0.53%lo:53",
            4096,
            [("systemd-resolve", RESOLVED_PID, 15), ("snatch", "777", 9)],
        )
        problems = " ".join(self.answered({SS_LISTENERS: line}).problems())
        self.assertIn(
            "snatch", problems, "a foreign process on a socket resolved also holds was accepted"
        )

    def test_a_shared_socket_is_exempt_only_when_every_owner_is(self):
        # The whole truth table for one socket in one place, because the guard it
        # exercises is one boolean and the two ways to get that boolean wrong --
        # "any owner" and "no owners" -- both come out as an install that binds a
        # port it does not own. Every row is a single `ss` line, and the owners
        # are named in the field `ss` actually names them in.
        resolved = ("systemd-resolve", RESOLVED_PID, 15)
        router = ("mosdns-router", ROUTER_PID, 3)
        snatch = ("snatch", "777", 9)
        for owners, accepted, why in (
            ((resolved,), True, "resolved alone on the stub is the machine working"),
            ((router,), True, "this package's own router on 53 is the state after an install"),
            ((resolved, router), True, "every owner is ours, so nothing foreign can answer here"),
            ((resolved, snatch), False, "one foreign owner is enough to refuse: it answers too"),
            ((snatch, resolved), False, "and it does not matter which owner comes first"),
            ((router, snatch), False, "an exempt owner does not excuse a foreign one beside it"),
            ((snatch,), False, "a single foreign owner was always refused"),
            ((), False, "no owner at all is a holder nobody can name, so nobody can clear it"),
        ):
            with self.subTest(owners=[name for name, _, _ in owners], accepted=accepted):
                self.setUp()
                line = self.shared_line("tcp", "LISTEN", "127.0.0.53%lo:53", 4096, owners)
                answers = {
                    SS_LISTENERS: line,
                    MAIN_PID + (ROUTER_UNIT,): f"{ROUTER_PID}\n",
                }
                if accepted:
                    self.assertPasses(
                        self.good_runner(answers),
                        f"{why}, but the socket was refused",
                    )
                else:
                    problems = " ".join(self.answered(answers).problems())
                    self.assertIn("53", problems, f"{why}, but the socket was accepted")

    def test_the_stub_exemption_is_loopback_and_not_merely_an_ipv6_prefix(self):
        # The exemption is "resolved on a loopback address", and the IPv6 half of
        # that question is an equality. `::1` is the whole of IPv6 loopback: `::2`
        # and up are reserved, and a global address beginning `::1` is a global
        # address. A prefix test answers "yes" to `::10.0.0.1` and `::1abc`, and
        # the direction it is wrong in is the permissive one -- this is the check
        # that refuses a listener on something routable, so a prefix that admits a
        # global address waves through the case the address exists to catch.
        #
        # The 4-in-6 rows are here for the same reason and in both directions: a
        # v4-mapped loopback is the same loopback in the other spelling and is
        # exempt, and a v4-mapped *global* address is not, which falls out of the
        # same equality rather than out of a special case.
        for address, accepted in (
            ("127.0.0.1", True),
            ("127.0.0.53", True),
            ("[::1]", True),
            ("[::ffff:127.0.0.1]", True),
            ("[::10.0.0.1]", False),
            ("[::ffff:10.0.0.1]", False),
            ("[::2]", False),
            ("[2001:db8::1]", False),
            ("[fe80::1]", False),
        ):
            with self.subTest(address=address, accepted=accepted):
                self.setUp()
                peer = "[::]:*" if ":" in address else "0.0.0.0:*"
                line = self.shared_line(
                    "tcp",
                    "LISTEN",
                    f"{address}:53",
                    4096,
                    [("systemd-resolve", RESOLVED_PID, 15)],
                    peer=peer,
                )
                if accepted:
                    self.assertPasses(
                        self.good_runner({SS_LISTENERS: line}),
                        f"resolved on {address}, which is loopback, was refused",
                    )
                else:
                    problems = " ".join(self.answered({SS_LISTENERS: line}).problems())
                    self.assertIn(
                        "53", problems, f"resolved on {address} is not the stub this install keeps"
                    )

    def test_a_socket_with_no_process_column_is_refused_on_a_shared_address(self):
        # `ss` prints no process column for a socket this user may not read, and
        # that is what an unprivileged run sees for every other user's process.
        # A holder nobody can name is a holder nobody can clear, so it is refused --
        # including on the stub's own address, where the address alone is the thing
        # the last version of this check keyed on.
        line = self.ss_line("tcp", "LISTEN", "127.0.0.53%lo:53", 4096)
        problems = " ".join(self.answered({SS_LISTENERS: line}).problems())
        self.assertIn(
            "53", problems, "a port 53 with no nameable holder was accepted on the stub's address"
        )

    def test_reports_two_processes_on_one_socket_when_named_separately(self):
        # The shape the old fixture used, kept because it is a shape `ss` can
        # print: two DISTINCT sockets that happen to be on the same address and
        # port, which two processes get with SO_REUSEPORT. It is two holders and
        # the foreign one is refused, and it is a different situation from the
        # shared-descriptor one above -- two sockets, rather than one socket with
        # two holders -- so the refusal has to be reached for the right reason.
        two_lines = self.ss_line(
            "tcp", "LISTEN", "127.0.0.53%lo:53", 4096, "systemd-resolve", RESOLVED_PID, fd=15
        ) + self.ss_line("tcp", "LISTEN", "127.0.0.53%lo:53", 4096, "snatch", "777", fd=9)
        problems = " ".join(self.answered({SS_LISTENERS: two_lines}).problems())
        self.assertIn("snatch", problems, "a foreign socket on the stub's port was accepted")

    def test_reports_resolved_holding_the_dns_port_off_loopback(self):
        # The exemption is the stub on a loopback address, not resolved's process
        # on any address. A resolved process listening on a routable address is
        # not the stub this install replaces, and treating it as one would skip
        # the very check the address exists to make.
        problems = " ".join(
            self.answered(
                {
                    SS_LISTENERS: self.ss_line(
                        "tcp", "LISTEN", "192.0.2.53:53", 4096, "systemd-resolve", RESOLVED_PID
                    )
                }
            ).problems()
        )
        self.assertIn(
            "192.0.2.53", problems, "resolved on a non-loopback address is not the stub this install keeps"
        )

    def test_reports_a_holder_it_cannot_identify(self):
        # `ss` prints no process column for a socket it may not read, which is
        # what an unprivileged run sees for every other user's process. A holder
        # that cannot be named cannot be cleared either, and preflight's rule is
        # that a question it could not ask is a refusal -- reporting "free" here
        # would be the one answer the install cannot act on.
        problems = " ".join(
            self.answered(
                {SS_LISTENERS: self.ss_line("tcp", "LISTEN", "127.0.0.1:53", 4096)}
            ).problems()
        )
        self.assertIn("53", problems, "a port 53 nobody can be named on has to be refused")

    def test_reads_the_same_socket_in_both_of_ss_column_layouts(self):
        # The captured answer twice, in the two shapes `ss` really prints, and a
        # foreign listener in each. The column count is a property of the flags and
        # not of the tool: `-lntup` prints Netid and puts the local address fifth,
        # `-lntp` omits Netid and puts it fourth. A parser reading a fixed index is
        # right for one of those and wrong for the other, and which one it was
        # tested against is the only thing that decides whether the suite sees it --
        # which is how the version before this one shipped a parser that read the
        # Send-Q length as a port, and a fixture, hand-written, that agreed with it.
        for netid in (True, False):
            shape = "with -u" if netid else "without -u"
            stub = RESOLVED_STUB_LISTENERS if netid else RESOLVED_STUB_LISTENERS_TCP_ONLY
            queue = UNRELATED_PORT_WITH_QUEUE_53 if netid else UNRELATED_PORT_WITH_QUEUE_53_TCP_ONLY
            with self.subTest(shape=shape):
                self.setUp()
                self.assertPasses(
                    self.good_runner({SS_LISTENERS: stub}),
                    f"resolved's stub in the shape `ss` prints {shape} was refused",
                )
            with self.subTest(shape=shape, case="queue"):
                self.setUp()
                self.assertPasses(
                    self.good_runner({SS_LISTENERS: queue}),
                    "a Send-Q of 53 on port 8080 is not a conflict on 53, and a parser that cannot "
                    "see the difference refuses a machine with both ports free",
                )
            with self.subTest(shape=shape, case="foreign"):
                self.setUp()
                problems = " ".join(
                    self.answered({SS_LISTENERS: self.listener(53, netid=netid)}).problems()
                )
                self.assertIn(
                    "53", problems, f"a foreign listener on 53 was accepted in the {shape} shape"
                )

    def test_the_captured_lines_are_the_shapes_they_claim_to_be(self):
        # The two constants above are the evidence for the claim in their comment,
        # so the claim is asserted rather than left to a reader's counting: seven
        # fields with a Netid when both families are asked for, six without one when
        # they are not, and a local address in the fifth position in both cases once
        # the Netid is accounted for.
        for name, listeners, with_netid in (
            ("with -u", RESOLVED_STUB_LISTENERS, True),
            ("without -u", RESOLVED_STUB_LISTENERS_TCP_ONLY, False),
        ):
            with self.subTest(shape=name):
                self.setUp()
                line = next(one for one in listeners.splitlines() if "127.0.0.53" in one)
                fields = line.split()
                self.assertEqual(
                    len(fields), 7 if with_netid else 6, f"{name}: the captured line's field count"
                )
                if with_netid:
                    self.assertIn(fields[0], ("tcp", "udp"), f"{name}: the Netid column")
                else:
                    self.assertEqual(
                        fields[0], "LISTEN", f"{name}: without -u the first column is the state"
                    )
                self.assertEqual(
                    fields[4 if with_netid else 3],
                    "127.0.0.53%lo:53",
                    f"{name}: the local address is not where this comment says it is",
                )
                self.assertTrue(
                    fields[3 if with_netid else 2].isdigit(),
                    f"{name}: the column before the address is the queue, and it is a number",
                )
        queue = UNRELATED_PORT_WITH_QUEUE_53_TCP_ONLY.split()
        self.assertEqual(
            queue[2], "53", "the captured Send-Q line does not carry 53 in the queue column"
        )
        self.assertEqual(queue[3], "127.0.0.1:8080", "and the socket is not on port 53")

    def test_the_captured_shared_lines_carry_two_owners_on_one_line(self):
        # The evidence for the every-owner rule, asserted rather than left to a
        # reader's counting. What matters is that the claim "one socket, two
        # holders" is expressed the way `ss` expresses it: a single `users:` field
        # naming two processes, on a single line. A capture that put them on two
        # lines would be describing two sockets, and it is the difference between
        # the case the rule exists for and the case that was already refused.
        for name, captured, local, peer in (
            ("IPv4", SHARED_LISTENER_LINE, "127.0.0.1:18081", "0.0.0.0:*"),
            ("IPv6", SHARED_IPV6_LISTENER_LINE, "[::1]:15399", "[::]:*"),
        ):
            with self.subTest(family=name):
                self.setUp()
                lines = captured.splitlines()
                self.assertEqual(
                    len(lines), 1, f"{name}: a socket with two holders is ONE line to `ss`"
                )
                fields = lines[0].split()
                self.assertEqual(len(fields), 7, f"{name}: the captured line's field count")
                self.assertEqual(
                    fields[4], local, f"{name}: the local address is not where this comment says"
                )
                self.assertEqual(fields[5], peer, f"{name}: and neither is the peer column")
                owners = re.findall(r'\("([^"]+)",pid=(\d+)', fields[6])
                self.assertEqual(
                    len(owners),
                    2,
                    f"{name}: the process field names both holders, and this capture names "
                    f"{len(owners)}",
                )
                self.assertNotEqual(
                    owners[0], owners[1], f"{name}: and they are two processes, not one twice"
                )

    def test_says_that_a_port_check_is_a_moment_and_not_a_reservation(self):
        # Between this check and the bind, anything may take the port, and the
        # installer's own service will hold it afterwards by design. A report that
        # read as a reservation would have an operator either distrusting a correct
        # install or trusting a racy one.
        report = self.answered({SS_LISTENERS: self.listener(53)})
        self.assertTrue(report.occupied_ports(), "an occupied port 53 was not reported as occupied")
        self.assertRegex(
            " ".join(report.notes()),
            r"(?i)(moment|not a reservation|race|between|afterwards)",
            "a port report has to say it describes one moment, because the check cannot hold "
            "the port afterwards and anything may take it in between",
        )

    def test_rejects_a_machine_whose_listeners_cannot_be_read(self):
        # An unreadable answer is not an empty answer. Reporting the ports free
        # because `ss` failed would send the install into a bind that cannot win.
        self.assertTrue(
            self.preflight(self.good_runner(returncodes={SS_LISTENERS: 1})).problems(),
            "a machine whose listeners could not be read was accepted",
        )


class ForeignServiceTests(PreflightFixture):
    """A resolver or a router this package did not install, already running.

    The installer takes DNS over from whatever is answering. A `mosdns` or
    `dnscrypt-proxy` unit that is active before this package installed anything is
    a different installation, and binding the same ports underneath it produces two
    answers rather than one -- or a silent fight over who owns port 53.
    """

    def test_accepts_a_machine_with_no_foreign_resolver_running(self):
        self.assertPasses()

    def test_rejects_a_machine_where_this_projects_services_are_already_active(self):
        # The marker says this package is installed, so this is an upgrade and an
        # active service is the expected state rather than a conflict. The
        # unmarked case is the one that is refused.
        for unit in PROJECT_SERVICES:
            with self.subTest(unit=unit):
                self.setUp()
                self.unmark()
                problems = " ".join(
                    self.answered({("systemctl", "is-active", unit): "active\n"}).problems()
                )
                self.assertIn(
                    unit,
                    problems,
                    f"an already-active {unit} from an installation this package did not make "
                    "has to be named in the refusal: only its owner can say whether it is safe "
                    "to take DNS over from it",
                )

    def test_rejects_a_machine_where_one_of_this_projects_timers_is_already_active(self):
        # A timer from another installation is the same conflict wearing a timer:
        # a second optimizer will start measuring and publishing against a selector
        # this install is about to replace.
        for unit in PROJECT_TIMERS:
            with self.subTest(unit=unit):
                self.setUp()
                self.unmark()
                problems = " ".join(
                    self.answered({("systemctl", "is-active", unit): "active\n"}).problems()
                )
                self.assertIn(unit, problems)

    def test_does_not_refuse_a_service_this_package_owns(self):
        # Re-running the installer on a machine this package already installed is
        # an upgrade, and a router that is already active is what an upgrade finds.
        # The ownership marker is what tells the two apart, so it is the whole of
        # this case.
        report = self.answered({("systemctl", "is-active", "mosdns-router.service"): "active\n"})
        self.assertEqual(
            [problem for problem in report.problems() if "mosdns-router.service" in problem],
            [],
            "a service this package's own marker claims is not a foreign installation",
        )

    def test_a_marker_naming_something_else_does_not_excuse_the_conflict(self):
        # The marker is a claim, and a claim this package did not make is not one.
        self.write(MANAGED_BY, "some-other-tool\n", mode=0o600)
        problems = " ".join(
            self.answered({("systemctl", "is-active", "dnscrypt-proxy.service"): "active\n"}).problems()
        )
        self.assertIn("dnscrypt-proxy.service", problems)


class ECHTests(PreflightFixture):
    """Firefox and the forced-ECH list: what the router can and cannot protect.

    A Firefox below 129 does not read HTTPS RRs, so strict ECH cannot work in it
    and a domain on the forced list is unreachable there. That is a loss of
    protection in one browser, not a broken install: everything else the router
    does still works, so it is reported and the install continues. The one case
    that is refused is the one where the operator asked for strict ECH on a domain
    this machine cannot deliver it for.
    """

    def test_reports_a_firefox_below_129_and_continues(self):
        # Fallback, because a forced domain under fallback is reachable in a
        # browser that cannot do ECH: the router answers such a client with the
        # origin's own record. The strict half of this pair is the one refusal
        # below, and asserting the continuation here is what keeps the note from
        # being a refusal the moment somebody configures strict.
        self.policy(enabled="true", failure="fallback")
        self.force_list("example.com")
        report = self.answered({("firefox", "--version"): "Mozilla Firefox 128.0.3\n"})
        self.assertEqual(
            [problem for problem in report.problems() if "firefox" in problem.lower()],
            [],
            "a Firefox below 129 is a loss of ECH in that browser, not a broken install: "
            "refusing here would stop an operator installing a working router over a "
            "preference in one program",
        )
        self.assertFalse(report.ech_available(), "a Firefox below 129 cannot use ECH")
        self.assertRegex(
            " ".join(report.notes()),
            r"128",
            "the report has to name the version it found, or the operator cannot tell "
            "whether their browser is why a domain fails",
        )

    def test_reports_a_firefox_at_or_above_129_as_capable(self):
        self.policy()
        self.force_list("example.com")
        for version in ("129.0", "130.0.1", "140.0"):
            with self.subTest(version=version):
                self.setUp()
                report = self.answered({("firefox", "--version"): f"Mozilla Firefox {version}\n"})
                self.assertTrue(report.ech_available(), f"Firefox {version} can use ECH")

    def test_reports_a_machine_with_no_firefox_at_all(self):
        # A server with no browser runs this router perfectly well. The absence is
        # a fact about the machine, not a fault in it.
        self.policy()
        self.force_list("example.com")
        report = self.preflight(self.good_runner(returncodes={("firefox", "--version"): 127}))
        self.assertEqual(
            [problem for problem in report.problems() if "firefox" in problem.lower()], []
        )
        self.assertFalse(report.ech_available(), "there is no Firefox here to use ECH")

    def test_refuses_a_forced_ech_domain_that_strict_ech_cannot_deliver_here(self):
        self.policy(enabled="true", failure="strict")
        self.force_list("example.com")
        problems = " ".join(
            self.answered({("firefox", "--version"): "Mozilla Firefox 128.0.3\n"}).problems()
        )
        self.assertIn(
            "example.com",
            problems,
            "the refused domain has to be named: strict ECH would make it unreachable in this "
            "browser, and an operator who did not know which domain would have no way to find out",
        )
        self.assertRegex(problems, r"(?i)(strict|ech)", "the refusal has to say which policy made it one")

    def test_does_not_refuse_a_forced_domain_when_ech_is_not_strict(self):
        # Fallback is a policy that works in a browser without HTTPS RRs: the
        # client falls back to the origin's own record. Refusing here would stop
        # an install over a configuration that delivers what it promises.
        self.policy(enabled="true", failure="fallback")
        self.force_list("example.com")
        report = self.answered({("firefox", "--version"): "Mozilla Firefox 128.0.3\n"})
        self.assertEqual(
            [problem for problem in report.problems() if "example.com" in problem],
            [],
            "a forced domain under fallback ECH works in a browser that cannot do ECH",
        )

    def test_does_not_refuse_when_no_domain_is_forced(self):
        # The shipped force-ech list is comments only (ruling 135), so a fresh
        # install on a machine with an old browser has nothing to be refused for.
        self.policy()
        self.force_list()
        report = self.answered({("firefox", "--version"): "Mozilla Firefox 128.0.3\n"})
        self.assertEqual([problem for problem in report.problems() if "example.com" in problem], [])

    def test_does_not_refuse_when_ech_is_disabled_outright(self):
        self.policy(enabled="false", failure="strict")
        self.force_list("example.com")
        report = self.answered({("firefox", "--version"): "Mozilla Firefox 128.0.3\n"})
        self.assertEqual([problem for problem in report.problems() if "example.com" in problem], [])

    def test_does_not_refuse_when_the_policy_cannot_be_read(self):
        # An absent policy is not a strict one. The install will render the
        # document itself, and refusing here would stop an install because a file
        # has not been written yet -- which is the normal state before the first
        # run.
        self.force_list("example.com")
        report = self.answered({("firefox", "--version"): "Mozilla Firefox 128.0.3\n"})
        self.assertEqual([problem for problem in report.problems() if "example.com" in problem], [])

    @staticmethod
    def fail_open_note(report, case):
        """The one note that says the strict-ECH refusal was never considered."""
        for note in report.notes():
            if "policy.yaml" in note:
                return note
        raise AssertionError(f"the fail-open note is missing for {case}; the notes are {report.notes()}")

    def test_the_unreadable_policy_note_does_not_predate_the_version_it_reports(self):
        # The fail-open note carried the clause "a browser below 129 cannot deliver
        # ECH" -- a claim about a browser -- and it was written before anything had
        # run `firefox --version`. So on a machine with Firefox 130 the report
        # asserted that a browser below 129 could not deliver ECH, when the browser
        # it had is not below 129: a sentence about a machine that does not exist,
        # in the one note whose whole job is to be honest about what was not
        # checked.
        #
        # The note has to be written after the version is known and in the
        # version's own terms, so all three states of the browser are asserted: too
        # old, new enough, and no browser at all -- which is not a browser below
        # the minimum either, and still has to produce the note.
        for version, below in (("128.0.3", True), ("129.0", False), ("130.0.1", False)):
            with self.subTest(firefox=version):
                self.setUp()
                self.force_list("example.com")
                report = self.answered({("firefox", "--version"): f"Mozilla Firefox {version}\n"})
                note = self.fail_open_note(report, f"Firefox {version}")
                self.assertEqual(
                    "below" in note,
                    below,
                    f"with Firefox {version} the fail-open note must not describe a browser "
                    f"below the minimum that this machine does not have: {note}",
                )
                self.assertIn(
                    version, note, f"the note has to name the version it actually read: {note}"
                )
        with self.subTest(firefox="none installed"):
            self.setUp()
            self.force_list("example.com")
            report = self.preflight(self.good_runner(returncodes={("firefox", "--version"): 127}))
            note = self.fail_open_note(report, "no Firefox")
            self.assertNotIn(
                "below",
                note,
                f"there is no browser on this machine, so none of them is below anything: {note}",
            )
            self.assertRegex(
                note,
                r"(?i)(no firefox|browser|version)",
                f"the note has to say what it could not find out: {note}",
            )

    def test_says_that_an_unreadable_policy_left_the_strict_ech_refusal_unconsidered(self):
        # The module's one fail-open, and the note that names it. An operator who
        # has written a forced-domain list and has a strict policy they intended
        # is refused; one whose policy will not parse is not, and the difference is
        # between "this machine cannot do what you asked" and "preflight could not
        # read what you asked for". The second is worth a line of its own, because
        # the install renders the policy itself and the file an operator edited is
        # not necessarily the one that will be in force.
        for name, write_policy in {
            "the policy is absent": lambda: None,
            "the policy has no ech section": lambda: self.write(
                "/etc/mosdns/policy.yaml", "schema_version: 1\n"
            ),
        }.items():
            with self.subTest(policy=name):
                self.setUp()
                write_policy()
                self.force_list("example.com")
                report = self.answered({("firefox", "--version"): "Mozilla Firefox 128.0.3\n"})
                self.assertEqual(
                    [problem for problem in report.problems() if "example.com" in problem],
                    [],
                    f"{name} must not refuse, because an absent policy is the fresh-install state",
                )
                self.assertRegex(
                    " ".join(report.notes()),
                    r"(?i)(policy\.yaml|policy)",
                    f"with {name} and a forced domain, the report has to say that the strict-ECH "
                    "refusal could not be considered rather than passing in silence",
                )


class StateDirectoryTests(PreflightFixture):
    """The four state directories, and the properties each one has to hold.

    Three of the properties are invisible in the mode, and they are the reason
    this check reads the extended ACL rather than reasoning about the bits.

    A file's group comes from the directory's setgid bit. A file's group
    *permissions* come from the directory's default ACL, so a directory with mode
    2770 and no default ACL produces a state file one identity creates that the
    other cannot write. And the group's ability to write *the directory* -- which
    it needs before it can create or rename anything in it -- comes from the
    access ACL, so a restrictive access mask produces the same failure while the
    mode still reads 2770: when an extended ACL exists, the mode's group field IS
    the mask. Both were confirmed on the system-level test machine, where a
    member of the directory's own group cannot create a file in a 2750 directory
    at all, which is why the provisioned mode is 2770 and not 2750.
    """

    def test_accepts_directories_provisioned_the_way_the_plan_says(self):
        self.assertPasses()

    def test_the_group_can_actually_write_to_the_directory(self):
        # What this suite cannot prove, and where the proof is instead.
        #
        # The fake root's directories are owned by the user running the suite, so
        # a write here succeeds on the *owner* bits and says nothing about the
        # group. The group case needs a second identity, which means either root
        # or a real user, and the suite has neither by design. So the suite proves
        # the check refuses a directory the group cannot write to -- 2750, and a
        # restrictive access mask -- and the fact itself is proved on the
        # system-level test machine, where a member of the directory's own group
        # cannot create a file in a 2750 directory and can in a 2770 one. Both
        # numbers are in the task report.
        self.assertEqual(STATE_MODE, "2770", "the provisioned mode is the group-writable one")
        self.assertPasses()

    def test_reports_a_directory_the_group_cannot_write_to(self):
        # The reviewer's case, built with the real tools: a named access entry
        # creates a mask, and a later chmod to 2750 sets that mask to r-x. The
        # default ACL still grants the group rwx, so a check that read only the
        # default entries would call this directory correct.
        #
        # The mode's group field and the access mask are the same number -- POSIX
        # makes the mode report the mask whenever an access ACL has a named entry
        # -- so the mode check refuses this too, and no directory exists whose
        # mode says 2770 while the mask says r-x. What the access half adds is the
        # *reason*: the refusal has to say the mask is what denies the group, or
        # an operator reads a mode, chmods the same number back, and is refused
        # again with no new information. That is asserted below.
        self.build_state_directories(mode="2750", access=f"g:{ANOTHER_GID}:rwx")
        before = fingerprint(self.root)
        acl = subprocess.run(
            ["getfacl", "-c", "-p", str(self.rooted("/var/lib/mosdns"))],
            capture_output=True,
            text=True,
        ).stdout
        self.assertIn("mask::r-x", acl, "the fixture did not produce the mask the case is about")
        problems = " ".join(self.preflight().problems())
        self.assertRegex(
            problems,
            r"(?i)mask",
            "a restrictive access mask has to be reported as a mask: it is not the default ACL, "
            "and an operator who was told only the mode would change the wrong thing",
        )
        self.assertEqual(fingerprint(self.root), before, "preflight changed the ACL it was refusing")

    def test_accepts_an_access_mask_that_grants_the_group(self):
        # The control: the same named access entry with the mode the package
        # provisions, so the mask is rwx and the group can write. Without this, a
        # scan that reported every mask as a problem would satisfy the test above.
        self.build_state_directories(mode=STATE_MODE, access=f"g:{ANOTHER_GID}:rwx")
        for relative in STATE_DIRECTORIES:
            acl = subprocess.run(
                ["getfacl", "-c", "-p", str(self.rooted(relative))], capture_output=True, text=True
            ).stdout
            self.assertIn(
                "mask::rwx", acl, f"{relative} does not have the permissive mask the control needs"
            )
        self.assertPasses(self.good_runner(self.state_stat_answers(mode=STATE_MODE)))

    def test_reports_a_directory_with_the_right_mode_and_no_acl(self):
        # The case the design exists for, and the one a mode check passes.
        self.build_state_directories(acl=None)
        before = fingerprint(self.root)
        problems = " ".join(self.preflight().problems())
        self.assertIn(
            STATE_MODE,
            problems,
            "the refusal has to quote the mode the directory actually has, because the "
            "operator's next question is what to change it to",
        )
        self.assertRegex(problems, r"(?i)acl", "a missing default ACL has to be named as such")
        self.assertEqual(
            fingerprint(self.root), before, "preflight changed the directory it was refusing"
        )

    def test_reports_a_directory_whose_acl_does_not_grant_the_group_write(self):
        # A group entry of r-x is a group that can list and traverse but not
        # replace. The lock is acquired through a read-only descriptor and a state
        # file is replaced by rename, so r-x is the mode at which the second
        # identity stops working.
        self.build_state_directories(acl="g::r-x")
        problems = " ".join(self.preflight().problems())
        self.assertRegex(problems, r"(?i)acl", "a group ACL without rwx has to be reported")

    def test_reports_a_directory_that_is_world_readable(self):
        # 2775 hands every local user a listing of the state a router keeps, and
        # the group ACL the directory is supposed to carry is the narrower
        # mechanism; a world bit under it is a widening nobody chose.
        self.build_state_directories(mode="2775", acl=None)
        before = fingerprint(self.root)
        # The stat answers have to move with the fixture's mode. `stat` is asked
        # through the runner, so a fixture that chmodded the directory and left
        # the runner answering the provisioned mode would be testing the runner.
        problems = " ".join(
            self.preflight(self.good_runner(self.state_stat_answers(mode="2775"))).problems()
        )
        self.assertIn(
            "2775", problems, "a world-readable directory has to be refused with the mode it has"
        )
        self.assertEqual(fingerprint(self.root), before, "preflight changed the directory it was refusing")

    def test_reports_a_directory_group_writable_by_an_unrelated_group(self):
        # 2770 with a group this package does not use is the failure where somebody
        # else's group can replace the control lock and the selector.
        self.build_state_directories(mode=STATE_MODE)
        outputs = self.state_stat_answers(group="staff")
        before = fingerprint(self.root)
        problems = " ".join(self.preflight(self.good_runner(outputs)).problems())
        self.assertIn(
            "staff", problems, "the group that holds the directory has to be named in the refusal"
        )
        self.assertIn(STATE_GROUP, problems, "the group it has to be has to be named beside it")
        self.assertEqual(fingerprint(self.root), before, "preflight changed the directory it was refusing")

    def test_reports_a_directory_without_its_setgid_bit(self):
        # Without setgid a file created in it takes the *creator's* primary group,
        # not this package's, and the other identity cannot read it however good
        # the ACL is. This is the one property a group-writable mode does not give.
        self.build_state_directories(mode="0770")
        outputs = self.state_stat_answers(mode="0770")
        before = fingerprint(self.root)
        problems = " ".join(self.preflight(self.good_runner(outputs)).problems())
        self.assertIn("0770", problems, "the refusal has to quote the mode without the setgid bit")
        self.assertRegex(
            problems, r"(?i)(setgid|sgid)", "a missing setgid bit has to be named as such"
        )
        self.assertEqual(fingerprint(self.root), before)

    def test_reports_a_directory_whose_owner_cannot_write(self):
        # 2570: setgid is set, the group is fine, and the owner has r-x only.
        # postinst runs as root and does not care, but a directory the owner
        # cannot write is a directory whose shape nobody chose -- and the refusal
        # used to quote a provisioned mode it had not actually verified.
        self.build_state_directories(mode="2570")
        before = fingerprint(self.root)
        problems = " ".join(
            self.preflight(self.good_runner(self.state_stat_answers(mode="2570"))).problems()
        )
        self.assertIn("2570", problems, "the refusal has to quote the mode it found")
        self.assertRegex(
            problems, r"(?i)owner", "an owner without write has to be named as the owner, not the group"
        )
        self.assertEqual(fingerprint(self.root), before)

    def test_reports_every_mode_the_check_cannot_accept(self):
        # One case per bit, so a check that stopped looking at a bit is a failure
        # here rather than a permission nobody noticed. The owner, group and other
        # fields are each wrong in exactly one case with the other two right, so a
        # check reading the wrong field cannot pass by accident, and the
        # provisioned mode is in the table as the case that must be accepted. The
        # default ACL the package provisions is in place throughout, so what is
        # under test is the mode.
        for mode, why in (
            ("1770", "no setgid"),
            ("4770", "setuid, and no setgid"),
            ("2750", "the group cannot write"),
            ("2700", "the group can neither write nor list"),
            ("2570", "the owner cannot write"),
            ("2775", "readable by every local user"),
            ("2777", "writable by every local user"),
            (STATE_MODE, "the mode the package provisions"),
        ):
            with self.subTest(mode=mode, why=why):
                self.setUp()
                self.build_state_directories(mode=mode, acl="g::rwx")
                report = self.preflight(self.good_runner(self.state_stat_answers(mode=mode)))
                accepted = report.problems() == []
                self.assertEqual(
                    accepted,
                    mode == STATE_MODE,
                    f"a directory at {mode} ({why}) "
                    + ("should have been accepted" if mode == STATE_MODE else "was accepted"),
                )

    def test_reports_a_state_path_that_is_not_a_directory(self):
        # A regular file at the provisioned mode with a group ACL would pass every
        # mode check, and a file is not somewhere the package can put a state
        # file. The type comes from the raw mode rather than from stat's `%F`,
        # because that word is "regular empty file" for an empty file and "regular
        # file" for a full one -- a check keyed on it would be a check on how big
        # the file was.
        path = self.rooted("/var/lib/mosdns/lists")
        path.rmdir()
        path.write_text("", encoding="utf-8")
        path.chmod(int(STATE_MODE, 8))
        outputs = self.state_stat_answers()
        outputs[STAT_FIELDS + (str(path),)] = self.stat_answer(
            STATE_MODE, kind=stat.S_IFREG
        )
        before = fingerprint(self.root)
        problems = " ".join(self.preflight(self.good_runner(outputs)).problems())
        self.assertIn(
            "/var/lib/mosdns/lists", problems, "the path that is not a directory has to be named"
        )
        self.assertIn(
            "regular file", problems, "a refusal has to say what the path is rather than only "
            "which mode it has"
        )
        self.assertEqual(
            fingerprint(self.root), before, "preflight replaced a path it was refusing"
        )

    def test_reports_a_missing_state_directory(self):
        self.rooted("/var/lib/mosdns/runtime").rmdir()
        before = fingerprint(self.root)
        problems = " ".join(self.preflight().problems())
        self.assertIn("/var/lib/mosdns/runtime", problems, "a missing directory has to be named")
        self.assertEqual(
            fingerprint(self.root), before, "preflight created the directory it reported missing"
        )

    def test_it_checks_exactly_the_four_directories_the_package_provisions(self):
        # /run/mosdns is on a tmpfs, is recreated by a tmpfiles.d entry after every
        # reboot, and is where the DHCP bridge writes, so it is checked exactly as
        # the three under /var/lib are. None of the four is interchangeable with
        # another and none is optional, so the list is asserted rather than
        # trusted: a check that quietly dropped one would leave the directory the
        # router needs first unexamined, and the units' own -/run/mosdns tolerance
        # would hide the consequence until the first lease capture.
        self.assertEqual(installer.STATE_DIRECTORIES, STATE_DIRECTORIES)

    def test_names_the_offending_directory_and_not_only_the_check(self):
        # "a state directory is wrong" is not actionable: there are four of them
        # and they are not interchangeable -- one is on a tmpfs and is recreated by
        # a tmpfiles.d entry, three are on disk and are not. So each is broken in
        # turn, and each refusal has to name its own path.
        for relative in STATE_DIRECTORIES:
            with self.subTest(directory=relative):
                self.setUp()
                setfacl(self.rooted(relative), "g::r-x")
                report = self.preflight()
                self.assertTrue(report.problems(), f"a {relative} with a group ACL of r-x was accepted")
                # Each refusal opens with the path it is about, so the set of paths
                # named is exact -- a substring would not do, because three of the
                # four are prefixes of the fourth's parent.
                named = {problem.split(" ", 1)[0] for problem in report.problems()}
                self.assertEqual(
                    named,
                    {relative},
                    f"only {relative} is wrong here, and a refusal that also named another would "
                    "send an operator to fix a directory that is fine",
                )

    def test_reads_the_real_extended_acl_rather_than_inferring_it_from_the_mode(self):
        # Each case breaks one property while satisfying the other, so a check
        # reading the wrong one would pass.
        self.build_state_directories(acl="g::r-x")
        self.assertRegex(
            " ".join(self.preflight().problems()),
            r"(?i)acl",
            "a directory at the provisioned mode with a group default ACL of r-x is the case a "
            "mode check cannot see",
        )

        self.setUp()
        self.build_state_directories(mode="0750", acl="g::rwx")
        self.assertRegex(
            " ".join(self.preflight(self.good_runner(self.state_stat_answers(mode="0750"))).problems()),
            r"(?i)(setgid|sgid)",
            "a correct ACL does not make up for a missing setgid bit: a file created here "
            "takes the creator's group, not the directory's",
        )

    def test_asks_getfacl_rather_than_asking_for_a_symbolic_mode(self):
        runner = self.good_runner()
        self.assertPasses(runner)
        self.assertTrue(
            any(call[0] == GETFACL for call in runner.calls),
            "the ACL check has to read the extended ACL; inferring it from the directory "
            "mode is the mistake this check exists to prevent",
        )
        for call in runner.calls:
            self.assertNotIn(
                "+", " ".join(call), f"{call} asked for a symbolic ACL mode instead of reading the ACL"
            )


class ControlLockTests(PreflightFixture):
    """A control lock that already exists, and is not this package's."""

    def write_lock(self, mode=LOCK_MODE):
        path = self.rooted(CONTROL_LOCK)
        path.write_text("", encoding="utf-8")
        path.chmod(int(mode, 8))
        return path

    def lock_stat(self, path, mode=LOCK_MODE, owner=STATE_OWNER, group=STATE_GROUP):
        return self.stat_answer(mode, owner, group, kind=stat.S_IFREG)

    def test_accepts_a_lock_this_package_would_have_created(self):
        lock = self.write_lock()
        runner = self.good_runner(
            {STAT_FIELDS + (str(lock),): self.lock_stat(lock)}
        )
        self.assertPasses(runner)

    def test_reports_a_lock_whose_mode_is_not_the_documented_one(self):
        # 0666 is the one that matters: a world-writable lock is a lock any local
        # user can take, which turns every control operation into a race with them.
        for mode, why in (("666", "world writable"), ("600", "not group readable"), ("644", "world readable")):
            with self.subTest(mode=mode, why=why):
                self.setUp()
                lock = self.write_lock(mode=mode)
                before = fingerprint(self.root)
                runner = self.good_runner(
                    {STAT_FIELDS + (str(lock),): self.lock_stat(lock, mode=mode)}
                )
                problems = " ".join(self.preflight(runner).problems())
                self.assertIn(
                    mode, problems, f"a lock that is {why} has to be refused with the mode it has"
                )
                self.assertIn(LOCK_MODE, problems, "the mode it should be has to be named beside it")
                self.assertEqual(
                    fingerprint(self.root), before, "preflight repaired a lock file it was refusing"
                )

    def test_reports_a_lock_this_package_does_not_own(self):
        for owner, group in (("mosdns", "mosdns"), (STATE_OWNER, "www-data"), ("ubuntu", "ubuntu")):
            with self.subTest(owner=owner, group=group):
                self.setUp()
                lock = self.write_lock()
                before = fingerprint(self.root)
                runner = self.good_runner(
                    {STAT_FIELDS + (str(lock),): self.lock_stat(lock, owner=owner, group=group)}
                )
                problems = " ".join(self.preflight(runner).problems())
                self.assertIn(owner, problems, f"a lock owned by {owner} has to say so")
                self.assertEqual(fingerprint(self.root), before, "preflight re-owned a lock it was refusing")

    def test_reports_a_lock_that_is_not_a_regular_file(self):
        # A directory at 0640 passes every mode and ownership check, and it is
        # exactly what it is not: the lock is taken through a file descriptor, so
        # the control operations would fail at the first acquire rather than at
        # the install.
        lock = self.rooted(CONTROL_LOCK)
        lock.mkdir(parents=True)
        lock.chmod(int(LOCK_MODE, 8))
        before = fingerprint(self.root)
        runner = self.good_runner(
            {STAT_FIELDS + (str(lock),): self.stat_answer(LOCK_MODE, kind=stat.S_IFDIR)}
        )
        problems = " ".join(self.preflight(runner).problems())
        self.assertIn(
            "directory", problems, "a directory where the lock belongs has to be named as one"
        )
        self.assertEqual(
            fingerprint(self.root), before, "preflight replaced a lock path it was refusing"
        )

    def test_reports_a_dangling_symlink_at_the_lock_path(self):
        # A link to nothing is not a lock, and it is not the absence of one either.
        # The control operations open this path, and open follows a symbolic link,
        # so a link at this path is a redirect the install must not walk: it is
        # reported by kind, which is more use to an operator than "could not be
        # stat'd".
        path = self.rooted(CONTROL_LOCK)
        path.symlink_to(self.rooted("/gone/elsewhere.lock"))
        before = fingerprint(self.root)
        problems = " ".join(self.preflight().problems())
        self.assertIn(CONTROL_LOCK, problems, "a dangling symlink at the lock path was passed")
        self.assertRegex(
            problems,
            r"(?i)(symbolic link|symlink)",
            "a symlink at the lock path has to be named as one: open follows it, so the "
            "refusal has to say the path is a redirect",
        )
        self.assertEqual(fingerprint(self.root), before, "preflight removed the link it was refusing")

    def test_reports_a_lock_path_under_something_that_is_not_a_directory(self):
        # The lookup itself fails with ENOTDIR, which `Path.exists()` turns into
        # "no lock here". A file at the runtime directory is something the operator
        # did, and the install is not free to proceed past it.
        self._replace_runtime_directory_with_a_file()
        before = fingerprint(self.root)
        problems = " ".join(self.preflight().problems())
        self.assertIn(
            CONTROL_LOCK, problems, "a lock path under a file was reported as no lock at all"
        )
        self.assertEqual(fingerprint(self.root), before)

    @unittest.skipIf(os.geteuid() == 0, "root may search a 0600 directory, so this case cannot be built here")
    def test_reports_a_lock_path_whose_parent_cannot_be_searched(self):
        # A parent this user cannot search is unreadable, not empty. Preflight runs
        # as root in production, where this cannot happen -- which is exactly why
        # the answer has to be a refusal rather than an exception or a pass: the
        # same code path runs wherever it is invoked from.
        parent = self.rooted(CONTROL_LOCK).parent
        parent.chmod(0o600)
        self.addCleanup(parent.chmod, 0o700)
        before = fingerprint(self.root)
        problems = " ".join(self.preflight().problems())
        self.assertIn(
            CONTROL_LOCK, problems, "an unsearchable parent was reported as no lock at all"
        )
        self.assertEqual(fingerprint(self.root), before)

    def _replace_runtime_directory_with_a_file(self):
        """Turn the runtime directory into a regular file, lock path and all."""
        parent = self.rooted(CONTROL_LOCK).parent
        lock = self.rooted(CONTROL_LOCK)
        if lock.is_symlink() or lock.exists():
            lock.unlink()
        subprocess.run(["setfacl", "-b", "-k", str(parent)], check=True)
        parent.rmdir()
        parent.write_text("not a directory", encoding="utf-8")
        parent.chmod(0o644)

    def test_a_missing_lock_is_not_a_problem(self):
        # The lock is created on first acquire by whichever of the two identities
        # wins the race, so its absence on a fresh machine is the normal state.
        self.assertPasses()


class NoMutationTests(PreflightFixture):
    """`--check-only` writes nothing and calls nothing that changes anything.

    This is the property the module's design rests on, asserted the only way it can
    be: the fake runner records every argument array, and the test fails if any of
    them names a verb that changes something. Asserting "no exception was raised"
    instead would pass against an installer that had reconfigured NetworkManager
    and then reported success.
    """

    def test_reaches_no_mutating_verb(self):
        runner = self.good_runner()
        before = fingerprint(self.root)
        installer.preflight(self.root, runner)
        self.assertTrue(
            runner.calls, "the fake root has to produce at least one command, or this proves nothing"
        )
        for call in runner.calls:
            self.assertGreater(len(call), 0, "an empty argument array is not a command")
            for word in call[1:]:
                self.assertNotIn(
                    word,
                    MUTATING_VERBS,
                    f"preflight ran {call!r}, and {word!r} changes the machine it was asked to inspect",
                )
            self.assertNotIn(
                call[0],
                FILE_WRITERS,
                f"preflight ran {call[0]!r}, which can write to files; preflight is read-only",
            )
        self.assertEqual(fingerprint(self.root), before, "preflight wrote something")

    def test_runs_nmcli_only_in_its_read_only_forms(self):
        # The two nmcli forms here are the whole injection boundary for the
        # installer. A third, in a mutating form, is how a preflight becomes the
        # thing the plan's rollback exists to undo.
        runner = self.good_runner()
        installer.preflight(self.root, runner)
        nmcli_calls = [call for call in runner.calls if call[0] == "nmcli"]
        self.assertTrue(nmcli_calls, "the connection check has to ask nmcli something")
        for call in nmcli_calls:
            self.assertIn(
                tuple(call[:2]),
                (("nmcli", "-t"), ("nmcli", "-g")),
                f"{call!r} uses a form this preflight does not: the two read-only forms are -t "
                "and -g, and any other shape is one a later edit could make mutating",
            )
            for verb in ("modify", "up", "down", "delete", "add", "reload"):
                self.assertNotIn(verb, call, f"{call!r} changes a connection")

    def test_a_refusal_leaves_the_machine_exactly_as_it_was_found(self):
        # The whole point of "report, do not repair": a host in a shape this
        # install cannot proceed from gets a refusal, and the host is unchanged.
        # postinst provisions; nothing here does.
        self.build_state_directories(mode="2777")
        outputs = self.state_stat_answers(mode="2777", group="wheel")
        lock = self.rooted(CONTROL_LOCK)
        lock.write_text("", encoding="utf-8")
        lock.chmod(0o666)
        outputs[STAT_FIELDS + (str(lock),)] = self.stat_answer("666", kind=stat.S_IFREG)
        before = fingerprint(self.root)
        runner = self.good_runner(outputs)

        report = installer.preflight(self.root, runner)

        self.assertTrue(report.problems(), "a world-writable state directory was accepted")
        self.assertEqual(fingerprint(self.root), before, "preflight repaired what it refused")
        for call in runner.calls:
            for verb in ("chmod", "chown", "setfacl", "install", "rm", "mv", "cp"):
                self.assertNotIn(verb, call, f"preflight ran {call!r}, which repairs")

    def test_the_environment_is_not_modified(self):
        # The bridge's capture is invoked with an inherited environment and four
        # names have to be scrubbed before it runs (ruling 145). A preflight that
        # exported or unset a variable would reintroduce that leak into whatever
        # the transaction invokes next, so the whole environment is compared.
        before = dict(os.environ)
        self.preflight()
        self.assertEqual(dict(os.environ), before, "preflight changed the process environment")


class CliTests(PreflightFixture):
    """The command as a person runs it: the verb, the flag, and three statuses.

    Every other class here calls :func:`preflight` directly, which is the right
    level to test the checks at. This one calls :func:`main`, because the contract
    a person depends on is not a return value but three things at once: what the
    program writes to each stream, what it exits with, and what it did not touch
    while doing either. A wrapper that reported a refusal on stdout and exited 0
    would pass every test above it.
    """

    def run_cli(self, *arguments, runner=None):
        """Run ``main`` against the fake root, returning its status and streams."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = installer.main(list(arguments), runner or self.good_runner(), root=self.root)
        return status, out.getvalue(), err.getvalue()

    def test_exits_zero_and_says_so_on_a_machine_it_can_install_onto(self):
        # The flag is accepted rather than required, because naming the mode is
        # what makes the mode impossible to forget: `preflight` alone is still
        # check-only, and `--check-only` is accepted as a person would type it.
        for arguments in (("preflight",), ("preflight", "--check-only")):
            with self.subTest(arguments=arguments):
                self.setUp()
                status, out, err = self.run_cli(*arguments)
                self.assertEqual(status, installer.EXIT_OK, f"{arguments} was not accepted")
                self.assertIn("nothing has been changed", out)
                self.assertEqual(err, "", "a machine with no problem has no complaint")

    def test_a_problem_exits_one_and_is_named_on_stderr(self):
        # The two streams are the report's two halves: notes are facts on stdout,
        # refusals are complaints on stderr, so a script reading either one alone
        # gets a coherent half rather than a mixture.
        self.build_state_directories(acl=None)
        before = fingerprint(self.root)
        status, out, err = self.run_cli("preflight", "--check-only")
        self.assertEqual(status, installer.EXIT_REFUSED)
        self.assertIn("acl", err.lower(), "the refusal has to name what it refused on")
        self.assertNotIn("preflight:", out, "a refusal is not a note")
        self.assertIn("nothing has been changed", err, "a refusal has to say it changed nothing")
        self.assertEqual(fingerprint(self.root), before, "the command changed the machine it inspected")

    def test_a_usage_error_runs_nothing_at_all(self):
        # A verb this program does not have, or a flag it does not have, is
        # answered from the arguments alone. Nothing is read, because a command
        # that guessed what an operator meant would go on to bind a port.
        for arguments in (
            (),
            ("check",),
            ("check-only",),
            ("preflight", "--fix"),
            ("preflight", "--check-only", "--force"),
            ("preflight", "install"),
        ):
            with self.subTest(arguments=arguments):
                self.setUp()
                runner = self.good_runner()
                before = fingerprint(self.root)
                status, out, err = self.run_cli(*arguments, runner=runner)
                self.assertEqual(status, installer.EXIT_USAGE, f"{arguments} was not a usage error")
                self.assertIn("usage", err.lower(), "a usage error has to say what the usage is")
                self.assertEqual(out, "", "a usage error reported a result rather than refusing to")
                self.assertEqual(runner.calls, [], "a usage error read the machine it was given")
                self.assertEqual(fingerprint(self.root), before)

    def test_the_usage_names_the_mode_that_exists(self):
        # An operator who types --help has to be able to find out what this
        # command does from the message alone, and the message must not offer a
        # mode this program refuses: offering `--fix` in the usage would be the
        # one repair-shaped string in the file.
        for arguments in ((), ("preflight", "--fix")):
            with self.subTest(arguments=arguments):
                _, _, err = self.run_cli(*arguments)
                self.assertIn("preflight", err)
                self.assertIn("--check-only", err)
                self.assertNotIn("--fix", err)


class RealRunnerTests(unittest.TestCase):
    """The production runner, on the two things only it can be asked about.

    Every other class here substitutes the runner, which is the whole point of
    it. These two are about the substitution's other side: that a command which
    does not answer becomes a failed read rather than a traceback, and that the
    boundary takes the array it is handed rather than a string something would
    reinterpret. They start real processes -- this interpreter and nothing else,
    sleeping and printing -- because a boundary nobody has run is a boundary
    nobody has read.
    """

    def test_a_command_that_does_not_answer_is_a_failed_read(self):
        # A preflight that raised here would exit 1, which is the same status as a
        # refusal, so a script would read a failure to give a verdict as the
        # verdict. The callers turn a non-zero status into "this could not be
        # read", and that is the answer a hung D-Bus deserves.
        self.addCleanup(
            setattr, installer, "COMMAND_TIMEOUT_SECONDS", installer.COMMAND_TIMEOUT_SECONDS
        )
        installer.COMMAND_TIMEOUT_SECONDS = 0.05
        completed = installer.RealCommandRunner().run(
            [sys.executable, "-c", "import time; time.sleep(30)"], check=False
        )
        self.assertNotEqual(completed.returncode, 0, "a command that did not answer reported success")
        self.assertIn("did not answer", completed.stderr, "a timeout has to say it was one")
        self.assertEqual(completed.stdout, "", "a command that did not answer produced output")

    def test_the_runner_hands_the_array_to_the_process_unchanged(self):
        # The property the argument-array discipline is for, on the one runner
        # that starts something. The argument is read back out of what the child
        # printed, so a shell in the middle would have to reproduce it exactly to
        # pass -- and a string command would have failed to start at all.
        awkward = "an argument with spaces; and a ; and $(echo x)"
        completed = installer.RealCommandRunner().run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", awkward]
        )
        self.assertEqual(completed.stdout.strip(), awkward)


class ModuleSurfaceTests(unittest.TestCase):
    """The module's public face, asserted without any machine at all."""

    def test_every_name_in_all_is_something_the_module_defines(self):
        # `from mosdns_installer import *` is not something this program does, but
        # `__all__` is a list of promises and a name in it that does not exist is
        # an AttributeError for whoever acts on the promise. This module listed
        # an exception class it never defined, and nothing else here would have
        # found it: no check reaches this list and no test imports a star.
        for name in installer.__all__:
            self.assertTrue(
                hasattr(installer, name),
                f"__all__ names {name!r}, which this module does not define",
            )

    def test_the_public_names_are_the_ones_a_caller_needs(self):
        for name in ("preflight", "main", "CommandRunner", "RealCommandRunner", "Preflight"):
            self.assertIn(name, installer.__all__, f"{name} is part of the interface and is not exported")


class ArgumentArrayDisciplineTests(unittest.TestCase):
    """The scan that holds "argument arrays only" across the whole module.

    The FakeRunner refuses a string, which is a good check for every path a test
    happens to reach. It cannot see one no test reaches, and this installer runs
    on somebody's machine as root: an interpolation bug in a path built from a
    connection name is a shell injection, not a test failure. So the rule is also a
    source scan -- and, like every scan in this project, the scan has its own test,
    because a guard that cannot fail is a comment.

    The scan reads :data:`CODE`, not the raw source. The forbidden tokens are
    things this module argues *about*, and an argument that cannot tell the
    argument from the code is an argument that has to be dropped.

    Three scans, because one list of needles was not enough. The needle list
    rules out the ways this module has talked about reaching a shell. A named
    list of process-creating attributes rules out the ones it had not named,
    across `os` and `pty` -- `os` is imported at module scope, so `os.fork` and
    `os.posix_spawn` are one attribute away and were invisible to the needles.
    And an allowlist of `os` attributes says positively which ones this program
    is allowed to touch, so the next attribute somebody reaches for is a test
    failure rather than a review question.

    All three are needle-shaped and so are a floor, not a proof: a call reached
    through ``getattr`` would pass them. That is stated rather than papered over,
    because the layer that does not have the hole is one level down -- whatever
    such a call produced would have to reach :class:`CommandRunner` as a command,
    and the runner this suite injects refuses a string outright.
    """

    FORBIDDEN = {
        "shell=True": "a shell runs a string, and a string is what this module must never build",
        "shell = True": "a shell runs a string, and a string is what this module must never build",
        "os.system": "os.system hands its argument to a shell",
        "os.popen": "os.popen hands its argument to a shell",
        "os.spawn": "os.spawn takes a shell argument in its mode",
        "subprocess.getoutput": "it runs a string through a shell",
        "subprocess.getstatusoutput": "it runs a string through a shell",
        "shlex.split": "splitting a string is what a caller does before a shell runs it",
        "eval(": "eval evaluates a string as code",
        "exec(": "exec evaluates a string as code",
        "`": "a backtick is a shell command substitution",
    }

    # `os` is imported at module scope for `readlink` and `lstat`, which is why
    # the earlier FORBIDDEN list could not simply refuse the module: a whole-module
    # refusal would have forbidden the two reads the program is made of. An
    # allowlist of attributes is the other half of that decision. It is short
    # because the module reads files and nothing else -- no environment, no
    # process, no signals, no paths beyond the ones it is handed.
    #
    # **The four write-side attributes are the watchdog's, and each is here for a
    # reason a reviewer can check rather than because the program needed it.**
    # The watchdog publishes a failure record at a mode, and the three attributes
    # are the only way to do that safely:
    #
    #   * `chmod` -- the record is 0640 and that is its mode, not the umask's. A
    #     file whose mode is left to the process umask is a file an operator has
    #     to reason about, and this package pins the mode of every document it
    #     writes (the backup is 0600 and its case says so).
    #   * `fsync` -- the record is read by a timer, on a machine that may lose
    #     power between this write and the next probe, and a half-written
    #     document is a document whose absence the next run would read as "no
    #     failures recorded" -- which is the direction that acts.
    #   * `getpid` -- the staged name, and nothing else. `internal/state` and every
    #     other publisher in this repository stage into a name derived from the
    #     pid, and the tmpfiles entry reaps `/run/mosdns/.*.tmp` precisely because
    #     of that convention.
    #   * `replace` -- the rename that makes the record atomic. This is the one
    #     that carries the argument: `Path.rename` is not atomic over a tmpfs the
    #     way `os.replace` is, and a reader that caught a partially renamed record
    #     would start counting from nothing.
    #
    # None of the four can start a process, reach the environment, or act on a
    # path the program was not handed, which is the property this allowlist
    # exists to keep.
    #   * `getpid`/`killpg` -- the staged name, and the process group the
    #     watchdog's action is started in. `killpg` is the reason that group
    #     exists: the action is a launcher for `emergency-rollback`, so a budget
    #     that killed only the launcher would leave the restore running on a
    #     machine whose record already says the action was performed, and
    #     nothing would ever report its outcome. It signals a group, never a
    #     single pid, and the group is one this program created with
    #     `start_new_session` a few lines earlier.
    #   * `open`/`close`/`O_CREAT`/`O_RDONLY`/`fchmod` -- the control lock.
    #     `flock` is taken through a descriptor, so a lock is an open file; the
    #     flags are the bridge's own (`O_CREAT | O_RDONLY`, never `O_WRONLY`,
    #     so a process holding this lock has no way to modify the state it
    #     protects), and `fchmod` pins the mode on every acquire because the
    #     umask narrows the creation mode and a lock at 0600 would be a lock the
    #     other service identity could never take. None of the five can start a
    #     process, reach the environment, or name a path of its own: the path is
    #     `CONTROL_LOCK` under the `root` a caller was handed, exactly as every
    #     other path in this module is.
    OS_ALLOWED = {
        "readlink",
        "lstat",
        "stat",
        "chmod",
        "fsync",
        "getpid",
        "getpgid",
        "killpg",
        "replace",
        "open",
        "close",
        "O_CREAT",
        "O_RDONLY",
        "fchmod",
    }
    # Every attribute of `os` and `pty` that starts a process, named rather than
    # inferred. The needle list above missed all of them: `os` is imported at
    # module scope, so `os.posix_spawn`, `os.fork` and `pty.spawn` would have
    # passed every scan in this class, and each of them starts something the
    # injected runner never sees.
    PROCESS_SPAWNERS = (
        "system",
        "popen",
        "spawn",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "posix_spawn",
        "posix_spawnp",
        "fork",
        "forkpty",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execlp",
    )
    SPAWNING_MODULES = ("os", "pty", "ptyprocess", "multiprocessing", "commands")

    @staticmethod
    def process_boundary():
        """The span of ``RealCommandRunner``'s own code within the module's code.

        Bounded by the next top-level ``def``, ``class`` or decorator rather than
        by the next class, because this class is followed by module-level
        functions. A boundary that ran on past them would be scanning the whole
        module while claiming to scan the runner, and a reviewer reading the
        failure would be sent to look at the wrong code.
        """
        start = CODE.index(RUNNER_CLASS)
        rest = CODE[start + len(RUNNER_CLASS) :]
        following = re.search(r"^(?:def |class |@)", rest, flags=re.MULTILINE)
        return start, start + len(RUNNER_CLASS) + (following.start() if following else len(rest))

    def test_the_module_contains_no_shell_invocation(self):
        for needle, why in self.FORBIDDEN.items():
            self.assertNotIn(
                needle, CODE, f"mosdns_installer.py runs {needle!r} in code: {why}"
            )

    def test_the_one_process_boundary_is_a_real_runner_and_nothing_else(self):
        # There is exactly one place in this module that starts a process, and it
        # is the class a caller substitutes. A second one -- even for a read-only
        # command -- is a path the fake runner cannot see, and the boundary is the
        # only thing making these tests hermetic. The count is the property: it is
        # not that subprocess is absent, it is that it appears once, in the runner,
        # and passes an argument array.
        starts = re.findall(r"subprocess\.run\(", CODE)
        self.assertEqual(
            len(starts), 1, f"the module starts a process in {len(starts)} places, want exactly one: "
            "every other one would be invisible to the injected runner"
        )
        self.assertIn(
            RUNNER_CLASS,
            CODE,
            "the one process boundary has to be the runner a caller substitutes, so a test's "
            "runner is what production's is",
        )
        start, end = self.process_boundary()
        boundary = CODE[start:end]
        self.assertIn(
            "list(args)",
            boundary,
            "the one process boundary has to pass an argument array, or a string reaching it "
            "would be a string the shell interprets",
        )
        for forbidden in ("shell", "os.system", "os.popen"):
            self.assertNotIn(forbidden, boundary, f"the process boundary contains {forbidden!r}")
        # Counting `subprocess.run` once is not enough on its own: an alias
        # imported above the runner would start a process the count never sees.
        # Every mention of the module has to be inside the boundary, which is
        # what makes "one boundary" true rather than merely plausible.
        self.assertNotIn(
            "subprocess",
            CODE[:start] + CODE[end:],
            "a reference to subprocess outside the runner is a second process boundary, "
            "however it is spelled",
        )

    @classmethod
    def spawners_used(cls, code):
        """The process-creating attribute uses in a block of code.

        Whitespace between the module and the dot is allowed, because ``os\n
        .fork()`` parses and a scan that only matched ``os.fork`` would miss it.
        """
        return {
            f"{module}.{name}"
            for module in cls.SPAWNING_MODULES
            for name in cls.PROCESS_SPAWNERS
            if re.search(rf"\b{module}\s*\.\s*{name}\b", code)
        }

    def test_the_module_uses_no_process_creating_attribute(self):
        # The hole the earlier needle list left. `os` is imported at module scope,
        # so every process-creating attribute of it was one attribute away from a
        # second process boundary that the injected runner cannot see -- and this
        # program runs as root on somebody's machine, where the difference between
        # a read and a spawn is the difference between a report and an incident.
        self.assertEqual(
            self.spawners_used(CODE),
            set(),
            f"mosdns_installer.py uses {sorted(self.spawners_used(CODE))}, which start processes "
            "the injected runner would never see",
        )

    def test_every_os_attribute_the_module_uses_is_one_it_is_allowed(self):
        # An allowlist rather than a needle list, because the module legitimately
        # uses `os` for two reads and a needle list could only answer "no" by
        # forbidding the module. `stat` is here for the same reason: it is the
        # module's `stat`, and the attributes it uses are `S_ISDIR` and friends
        # rather than anything that starts a process.
        used = set(re.findall(r"\bos\.(\w+)", CODE))
        self.assertTrue(used, "the module uses os, so this allowlist is doing work")
        self.assertEqual(
            used - self.OS_ALLOWED,
            set(),
            f"mosdns_installer.py uses os attributes outside the allowlist: "
            f"{sorted(used - self.OS_ALLOWED)}. Add a name to OS_ALLOWED only if it cannot "
            "start a process, change the environment, or write",
        )

    def test_the_spawn_scan_fires_on_a_spawn_and_stays_quiet_on_the_reads(self):
        # The scan's own test, so a guard that cannot fail is not a comment. Each
        # control is run through the same helper the real assertion uses, so what
        # is shown to fire is exactly what fires on the module.
        for spawner in ("os.posix_spawn", "os.fork", "pty.spawn", "os.execv", "os.system"):
            with self.subTest(spawner=spawner):
                code = f"import os\n{spawner}('ls', ['ls'])\n"
                self.assertEqual(
                    self.spawners_used(code),
                    {spawner},
                    f"the scan does not see {spawner!r}, so it cannot be shown to fire on it",
                )
        for read in ("os.readlink(path)", "os.lstat(path)", "os.getcwd()", "stat.S_ISREG(mode)"):
            with self.subTest(read=read):
                self.assertEqual(
                    self.spawners_used(read),
                    set(),
                    f"the control case {read!r} is not clean, so a passing scan would prove nothing",
                )

    def test_every_subprocess_use_passes_no_shell_and_no_string_command(self):
        for match in re.finditer(r"subprocess\.\w+\(([^)]*)\)", CODE):
            arguments = match.group(1)
            self.assertNotIn(
                "shell", arguments, f"a subprocess call passes a shell argument: {match.group(0)!r}"
            )
            self.assertNotIn(
                '"', arguments.split(",")[0],
                f"a subprocess call may be building a string command: {match.group(0)!r}",
            )

    def test_the_scan_fires_on_a_shell_invocation(self):
        # The scan's own test, run over the shape it refuses and the shape it
        # allows, so a reviewer sees the difference rather than taking the rule on
        # trust.
        offending = "subprocess.run('ls -l', shell=True)\n"
        self.assertTrue(
            any(needle in offending for needle in self.FORBIDDEN),
            "the control case does not contain what the scan looks for, so the scan cannot be "
            "shown to fire",
        )
        self.assertFalse(
            any(needle in "subprocess.run(['ls', '-l'], check=True)\n" for needle in self.FORBIDDEN),
            "the control case is not clean, so a passing scan would prove nothing",
        )

    def test_the_scan_sees_code_and_leaves_the_prose_about_code_alone(self):
        # The scan reads code, so it has to be able to tell code from a docstring
        # that says "os.system", a comment naming a forbidden call, and the
        # literal text inside an f-string. Each of those is in this module's own
        # source today, and a scan that could not see past them would have had to
        # be deleted -- which is how the rule would have ended up as a comment.
        for prose in (
            '"""Never os.system, and never shell=True."""\n',
            "# os.system is a shell; the runner takes an array.\n",
            'message = f"the answer is os.system"\n',
        ):
            with self.subTest(prose=prose.strip()):
                clean = code_only(prose)
                self.assertFalse(
                    any(needle in clean for needle in self.FORBIDDEN),
                    f"the scan read prose as code: {prose.strip()!r}",
                )
        for code in ("os.system('ls -l')\n", "subprocess.run('ls', shell=True)\n"):
            with self.subTest(code=code.strip()):
                self.assertTrue(
                    any(needle in code_only(code) for needle in self.FORBIDDEN),
                    f"the scan missed a call in code: {code.strip()!r}",
                )
        self.assertIn(
            "subprocess.run(",
            CODE,
            "blanking the prose has to leave the module's one process boundary intact, or the "
            "scan is passing because it can see nothing",
        )

    def test_the_module_does_no_work_at_import_time(self):
        # A module that touched the filesystem at import would make every test in
        # this file a system test, and the fake root a fiction. The check is that
        # nothing but a constant is assigned at module level.
        for match in re.finditer(r"^([a-z_][a-z0-9_]*)\s*=\s*(.+)$", CODE, flags=re.MULTILINE):
            name, value = match.group(1), match.group(2)
            self.assertNotIn("preflight(", value, f"module-level {name!r} runs a check at import time")
            self.assertNotIn("subprocess", value, f"module-level {name!r} runs a command at import time")
            self.assertNotIn("open(", value, f"module-level {name!r} opens a file at import time")


class FakeRunnerBoundaryTests(unittest.TestCase):
    """The boundary itself, asserted without any machine at all."""

    def test_the_fake_runner_refuses_a_string_command(self):
        with self.assertRaises(TypeError):
            FakeRunner().run("nmcli connection show --active")

    def test_the_fake_runner_refuses_a_bytes_command(self):
        with self.assertRaises(TypeError):
            FakeRunner().run(b"nmcli")

    def test_the_fake_runner_records_only_prepared_answers(self):
        runner = FakeRunner(outputs={("id",): "root\n"})
        self.assertEqual(runner.run(["id"]).stdout, "root\n")
        self.assertEqual(runner.run(["whoami"]).stdout, "", "an unprepared command answered something")
        self.assertEqual(runner.calls, [("id",), ("whoami",)])

    def test_the_fake_runner_raises_for_a_failing_checked_command(self):
        runner = FakeRunner(returncodes={("systemctl", "--version"): 1})
        with self.assertRaises(subprocess.CalledProcessError):
            runner.run(["systemctl", "--version"])
        self.assertEqual(runner.run(["systemctl", "--version"], check=False).returncode, 1)


if __name__ == "__main__":
    unittest.main()
