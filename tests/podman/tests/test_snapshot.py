"""The host before/after snapshot, and the one thing it is not allowed to read.

The snapshot is this plan's **evidence that a test run changed nothing on the
host**. That claim is only worth what the snapshot can see, so the fields are
the ones the plan names -- the release, the resolver's *link*, NetworkManager's
connections, resolved's status, this project's units, the listening sockets, and
Firefox profile metadata -- and they are collected as read-only command arrays
against an injected runner. Nothing here executes a mutating command, and the
case that says so asserts the exact arrays the collector emitted rather than a
list of strings somebody can reorder.

**Firefox is the field with a rule inside it.** The snapshot compares a browser
profile's path names, mtimes and sizes across a run, so it must not perturb
what it compares, and it must not read what it compares. The second is not a
matter of *not using* a value: a harness that opens a profile and then declines
to use the bytes has already done the thing. So the case here is not "no content
appears in the document" but "**no profile file is opened**" -- an audit over
every ``open`` on the Python surface, run against a real directory of real
files. And a control runs the same audit against a function that does open a
profile file, because an audit that cannot notice is a comment.

Every field is normalised and hashed. The hash is what Task 7 compares, so
whether a normalised record *can* see a real change matters as much as whether
it ignores an irrelevant one: a changed nameserver, port or unit name has to
change the digest, and a connection UUID or a process id has not to -- they say
which instance this was, not what this machine is doing.
"""

import builtins
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tests" / "podman" / "lib"))

import snapshot  # noqa: E402

# The seven fields the plan names, as the literal command arrays that collect
# them. Written out rather than derived, so a command that changes is a change
# this file can see. The Firefox field is the seventh and is deliberately not
# here: it is read from the filesystem, not from a command.
EXPECTED_COMMANDS = [
    ("cat", "/etc/os-release"),
    ("readlink", "/etc/resolv.conf"),
    ("nmcli", "-f", "NAME,UUID,DEVICE,TYPE,STATE", "connection", "show"),
    ("resolvectl", "status"),
    ("systemctl", "list-unit-files", "--no-legend", "--no-pager", "--type=service"),
    ("ss", "-H", "-lntup"),
]

# Realistic output, hand-written rather than captured from this machine: a
# snapshot case that ran against the host would be a test that passes or fails
# depending on the machine it runs on, which is exactly what this repository's
# boundary forbids.
OS_RELEASE = (
    'PRETTY_NAME="Ubuntu 24.04.3 LTS"\n'
    'NAME="Ubuntu"\n'
    'VERSION_ID="24.04"\n'
    'VERSION="24.04.3 LTS (Noble Numbat)"\n'
    'ID=ubuntu\n'
)
RESOLV_LINK = "../run/systemd/resolve/stub-resolv.conf\n"
NM_CONNECTIONS = (
    "NAME                UUID                                  TYPE      DEVICE\n"
    "Wired connection 1  0e4a3b21-2f8f-4a1e-9b0e-3f2c1d4e5f60  ethernet  eth0\n"
    "docker0            2a5b6c31-1111-4222-8333-944455556666  bridge   docker0\n"
)
RESOLVECTL_STATUS = (
    "Link 2 (eth0): 2: eth0\n"
    "                 Current Scopes: DNS\n"
    "                 DNS Servers: 10.89.0.2\n"
    "                          DNS Domain: lan\n"
)
UNIT_FILES = (
    "mosdns-router.service          enabled\n"
    "mosdns-cdn-optimizer.service   enabled\n"
    "mosdns-cdn-health.service      disabled\n"
    "mosdns-list-check.service      static\n"
    "dnscrypt-proxy.service         enabled\n"
    "NetworkManager.service         enabled\n"
    "dbus.service                   static\n"
    "systemd-resolved.service       enabled\n"
)
LISTENING = (
    'tcp   LISTEN 0      4096   127.0.0.53%lo:53    0.0.0.0:*    '
    'users:(("systemd-resolve",pid=812,fd=12))\n'
    'tcp   LISTEN 0      4096   127.0.0.1:15353     0.0.0.0:*    '
    'users:(("dnscrypt-proxy",pid=901,fd=5))\n'
    'udp   UNCONN 0      4096   127.0.0.53%lo:53    0.0.0.0:*    '
    'users:(("systemd-resolve",pid=812,fd=13))\n'
)

STANDARD_TABLE = {
    ("cat", "/etc/os-release"): OS_RELEASE,
    ("readlink", "/etc/resolv.conf"): RESOLV_LINK,
    ("nmcli",): NM_CONNECTIONS,
    ("resolvectl", "status"): RESOLVECTL_STATUS,
    ("systemctl", "list-unit-files"): UNIT_FILES,
    ("ss",): LISTENING,
}

# A marker planted in a Firefox file. It must never appear in a snapshot: a
# profile is somebody's browsing data and this harness reads metadata about it,
# not its contents.
PROFILE_SECRET = "SECRET-BROWSING-DATA-must-never-be-read"


class FakeCommandRunner:
    """A command runner that answers a fixed table and records every array.

    A table value may be an exception instance, which is raised instead of
    answered. That is how a host without `nmcli` is reproduced without a host
    without `nmcli`: the case asks what the snapshot records when a command is
    missing, and a runner that could only ever succeed could not answer it.

    An unmatched command answers the empty string rather than raising, so a
    collector that asks for something this fixture does not know about shows up
    as an empty field -- and the case that asserts the exact arrays is what
    notices.
    """

    def __init__(self, table=None):
        self.table = dict(STANDARD_TABLE if table is None else table)
        self.calls = []

    def __call__(self, argv):
        argv = tuple(str(token) for token in argv)
        self.calls.append(argv)
        for pattern, answer in self.table.items():
            if argv[: len(pattern)] == pattern:
                if isinstance(answer, BaseException):
                    raise answer
                return answer
        return ""

    def calls_matching(self, *prefix):
        """Every recorded array whose first tokens are `prefix`."""
        return [call for call in self.calls if call[: len(prefix)] == prefix]


class OpenAudit:
    """Records every path an `open` reaches, and still opens it.

    The three names are the whole Python surface a file's bytes can be read
    through -- `builtins.open` and `io.open` are the same function under two
    names, and `os.open` is the raw one. All three are wrapped, because wrapping
    only `builtins.open` would miss `io.open` and every `Path.read_text()`.

    What it does not intercept is `os.scandir`, which is how the collector learns
    the *names* it is asked to record: scandir enumerates a directory and never
    opens the entries inside it, and the plan asks for names, mtimes and sizes.
    A content read has to go through one of the three names above, so a collector
    that read a profile would be caught here.
    """

    def __init__(self):
        self.paths = []
        self._saved = []

    def _wrap(self, real):
        def opener(*args, **kwargs):
            if args:
                self.paths.append(args[0])
            return real(*args, **kwargs)

        return opener

    def __enter__(self):
        for holder in (builtins, io, os):
            real = holder.open
            self._saved.append((holder, real))
            holder.open = self._wrap(real)
        return self

    def __exit__(self, *exc_info):
        for holder, real in self._saved:
            holder.open = real
        self._saved.clear()
        return False

    def under(self, root):
        """Every recorded path inside `root`, as resolved strings."""
        base = str(Path(root).resolve())
        return [
            str(Path(str(path)).resolve())
            for path in self.paths
            if str(path) and str(Path(str(path)).resolve()).startswith(base)
        ]


def firefox_root(directory: Path, name: str = "firefox") -> Path:
    """A realistic profile tree, with a secret in one file's contents.

    Built as directories and files rather than mocked, because the property under
    test is a property of the filesystem walk: what it records, and what it
    opens.
    """
    root = directory / name
    profile = root / "abc123.default-release"
    (profile / "cache2" / "entries").mkdir(parents=True)
    (profile / "places.sqlite").write_text(f"places,{PROFILE_SECRET}\n", encoding="utf-8")
    (profile / "prefs.js").write_text('user_pref("browser.startup.homepage", "about:blank");\n', encoding="utf-8")
    (profile / "cache2" / "entries" / "0A0B0C0D0E0F").write_bytes(b"\x00" * 4096)
    return root


def record_size(root: Path, relative: str) -> int:
    return os.lstat(root / relative).st_size


def record_mtime(root: Path, relative: str) -> int:
    return os.lstat(root / relative).st_mtime_ns


class SnapshotTestCase(unittest.TestCase):
    """A temp directory, a fake runner, and a Firefox root of real files."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        self.firefox = firefox_root(self.directory)
        self.runner = FakeCommandRunner()

    def collect(self, runner=None, **kwargs):
        kwargs.setdefault("firefox_roots", [self.firefox])
        return snapshot.collect_document(
            runner or self.runner,
            run_id="20260928T120000Z",
            taken_utc="2026-09-28T12:00:00Z",
            **kwargs,
        )


class FieldCollectionTest(SnapshotTestCase):
    """The seven fields, and the six read-only commands that collect six of them."""

    def test_it_collects_every_field_the_plan_names(self):
        document = self.collect()
        self.assertEqual(
            sorted(document["fields"]),
            sorted(
                [
                    "firefox_profiles",
                    "listening_sockets",
                    "networkmanager_connections",
                    "os_release",
                    "project_units",
                    "resolvectl_status",
                    "resolv_conf_link",
                ]
            ),
        )

    def test_the_commands_it_runs_are_the_six_written_out_in_this_file(self):
        """The arrays are the literal ones, so a changed command is a failed case.

        This is the whole of the "the snapshot is read-only" claim, and it is
        asserted as equality against literals rather than as a property of a
        list: a seventh command -- a mutating one -- fails this case, because the
        recorded arrays would no longer be these six.
        """
        self.collect()
        self.assertEqual(self.runner.calls, EXPECTED_COMMANDS)

    def test_every_command_it_runs_is_a_read(self):
        """The same property, named, with a detector that is shown able to fail.

        A guard that cannot fail is a comment, and the previous four rounds in
        this project each found one. So the detector below is exercised on a
        mutating array it must flag before the property is asserted over the
        real ones -- otherwise "no mutating command" is a claim about a regex
        nobody ran.
        """
        mutating = (
            ("nmcli", "connection", "modify", "eth0-managed", "ipv4.never-default", "yes"),
            ("systemctl", "restart", "NetworkManager"),
            ("resolvectl", "dns", "eth0", "10.89.0.2"),
            ("rm", "-f", "/etc/resolv.conf"),
        )
        for argv in mutating:
            with self.subTest(command=argv[0]):
                self.assertTrue(
                    snapshot.mutating_command(argv),
                    f"the detector must flag {argv[0]} -- a read-only check that cannot "
                    f"recognise a mutation is not a read-only check",
                )
        self.collect()
        for argv in self.runner.calls:
            with self.subTest(command=argv[0]):
                self.assertFalse(
                    snapshot.mutating_command(argv),
                    f"the snapshot ran a command that can change the host: {argv}",
                )

    def test_no_command_is_asked_for_a_shell(self):
        """Each command is an argument array, so no field can become a second command.

        A `sh -c` here would make every field's text a shell script, and a field's
        text is data the collector does not control.
        """
        self.collect()
        for argv in self.runner.calls:
            with self.subTest(command=argv[0]):
                self.assertNotIn("sh", argv)
                self.assertNotIn("bash", argv)
                self.assertNotIn("sudo", argv)

    def test_the_resolver_is_recorded_as_its_link_and_never_read(self):
        """The link, not the file: a run must not disturb what the stub link points at.

        This host's `/etc/resolv.conf` is a systemd stub symlink. Reading the
        file it points at records resolved's generated content, which changes
        whenever a network does, and comparing that would report a host change
        for something every run does. So the field is the link target, and the
        case holds both halves: the recorded value is the link, and no command
        read the file.
        """
        document = self.collect()
        self.assertEqual(
            document["fields"]["resolv_conf_link"]["records"],
            ["../run/systemd/resolve/stub-resolv.conf"],
        )
        self.assertEqual(self.runner.calls_matching("cat", "/etc/resolv.conf"), [])
        self.assertEqual(
            self.runner.calls_matching("readlink", "/etc/resolv.conf"),
            [("readlink", "/etc/resolv.conf")],
        )

    def test_a_resolver_that_is_not_a_symlink_is_recorded_as_such(self):
        """Not a link is an answer, and it has to be visible rather than empty.

        A target container's `/etc/resolv.conf` is a regular file, so the field
        cannot be assumed to hold a link. An empty list and an error look the
        same to a comparison that only checks for emptiness, and the first is
        what a broken read looks like -- so the error is kept in the record and
        is part of what the digest covers.
        """
        table = dict(STANDARD_TABLE)
        table[("readlink", "/etc/resolv.conf")] = OSError(
            "readlink: /etc/resolv.conf: Not a symbolic link"
        )
        document = self.collect(FakeCommandRunner(table))
        field = document["fields"]["resolv_conf_link"]
        self.assertIn("Not a symbolic link", field["error"])
        self.assertEqual(field["records"], [])

    def test_a_command_this_host_does_not_have_is_recorded_rather_than_raised(self):
        """A host without NetworkManager must still produce a snapshot.

        The snapshot is the evidence for a run, so a run on a host where one
        command is missing has to be comparable against a later run on the same
        host. Raising would abandon the whole collection and leave the run with
        no before/after pair at all -- the failure this module exists to prevent,
        arriving through the field the host is thinnest in.
        """
        table = dict(STANDARD_TABLE)
        table[("nmcli",)] = FileNotFoundError("nmcli: command not found")
        document = self.collect(FakeCommandRunner(table))
        self.assertIn("command not found", document["fields"]["networkmanager_connections"]["error"])
        # The other fields were still collected, and the field that failed is
        # still present -- not dropped.
        self.assertEqual(sorted(document["fields"]), sorted(self.collect()["fields"]))
        self.assertEqual(
            document["fields"]["os_release"]["records"],
            sorted(OS_RELEASE.splitlines()),
        )

    def test_only_this_projects_units_are_recorded(self):
        """The field is the project's unit list, so it has to be filtered.

        `systemctl list-unit-files` on a real machine returns every unit on it.
        A run does not change `dbus.service`, and a snapshot that recorded the
        whole list would be a diff of the machine rather than of the run.
        """
        document = self.collect()
        self.assertEqual(
            document["fields"]["project_units"]["records"],
            [
                "dnscrypt-proxy.service enabled",
                "mosdns-cdn-health.service disabled",
                "mosdns-cdn-optimizer.service enabled",
                "mosdns-list-check.service static",
                "mosdns-router.service enabled",
            ],
        )

    def test_a_unit_this_project_does_not_ship_is_not_recorded(self):
        """The filter is a list of names, so a unit nobody expected is not adopted.

        A filter written as "anything that looks like one of ours" -- by prefix
        alone, say -- would record a third party's unit and then fail the run for
        it. The names come from the package, and the case holds that a unit that
        merely resembles one of them is left out.
        """
        table = dict(STANDARD_TABLE)
        table[("systemctl", "list-unit-files")] = (
            "mosdns-router.service          enabled\n"
            "mosdns-router-extras.service   enabled\n"
            "not-mosdns-router.service      enabled\n"
            "systemd-networkd.service       enabled\n"
        )
        document = self.collect(FakeCommandRunner(table))
        self.assertEqual(
            document["fields"]["project_units"]["records"],
            ["mosdns-router.service enabled"],
        )


class NormalizationTest(SnapshotTestCase):
    """What a digest is allowed to ignore, and what it is not allowed to."""

    def digests(self, table=None, runner=None):
        document = self.collect(runner or FakeCommandRunner(table))
        return {name: field["digest"] for name, field in document["fields"].items()}

    def test_lines_are_sorted_so_an_irrelevant_ordering_is_not_a_change(self):
        forward = "dns 1.1.1.1\ndns 9.9.9.9\n"
        backward = "dns 9.9.9.9\ndns 1.1.1.1\n"
        self.assertEqual(
            self.digests({("resolvectl", "status"): forward})["resolvectl_status"],
            self.digests({("resolvectl", "status"): backward})["resolvectl_status"],
        )

    def test_a_changed_nameserver_is_a_change(self):
        """The property that makes the digest worth comparing.

        Everything else in this class is about what a digest must *not* notice.
        A check that only knows how to ignore is satisfied by an empty record, so
        the one that matters is that a different resolver answer is a different
        digest -- the whole claim the snapshot makes is that a run that changed
        the host's DNS is visible.
        """
        before = self.digests({("resolvectl", "status"): "DNS Servers: 10.89.0.2\n"})
        after = self.digests({("resolvectl", "status"): "DNS Servers: 127.0.0.1\n"})
        self.assertNotEqual(before["resolvectl_status"], after["resolvectl_status"])

    def test_a_connection_uuid_says_which_instance_and_not_what_the_machine_does(self):
        """NetworkManager mints a UUID per profile; two runs of the same host differ.

        The connection's name, device, type and state are what the comparison is
        about. Its UUID is which copy of the profile this is, and it is not
        stable across a container run or a profile re-creation, so a snapshot
        that carried it would report a change on every run and be ignored.
        """
        first = NM_CONNECTIONS.replace("0e4a3b21-2f8f-4a1e-9b0e-3f2c1d4e5f60", "11111111-2222-3333-4444-555555555555")
        second = NM_CONNECTIONS.replace("0e4a3b21-2f8f-4a1e-9b0e-3f2c1d4e5f60", "99999999-8888-7777-6666-555555555555")
        self.assertEqual(
            self.digests({("nmcli",): first})["networkmanager_connections"],
            self.digests({("nmcli",): second})["networkmanager_connections"],
        )
        # And the record keeps the name, the type and the device, so a comparison
        # can say *what* changed rather than only that something did. Only the
        # UUID is the placeholder.
        records = self.collect(FakeCommandRunner({("nmcli",): first}))["fields"][
            "networkmanager_connections"
        ]["records"]
        self.assertIn(
            "Wired connection 1  <uuid>  ethernet  eth0",
            records,
        )

    def test_a_connection_removed_or_added_is_a_change(self):
        """Redacting a UUID must not flatten the list into one shape.

        A record that hashed only the redacted text would give the same digest
        for one connection and for two if the extra one were a duplicate. The
        name line is kept, so a different count is a different digest.
        """
        two = NM_CONNECTIONS + "docker1            3b6c7d32-2222-4333-8444-555555555555  bridge   docker1\n"
        self.assertNotEqual(
            self.digests({("nmcli",): NM_CONNECTIONS})["networkmanager_connections"],
            self.digests({("nmcli",): two})["networkmanager_connections"],
        )

    def test_a_listener_is_its_address_and_port_and_not_the_process_that_holds_it(self):
        """`ss -p` prints a pid, and a pid is different on every boot.

        A snapshot that hashed it would report a change for every restart of any
        listening process -- which on a machine with a desktop is constantly --
        and would be muted within a week. The address, the port and the process
        *name* are the listener, and those are kept.
        """
        first = LISTENING
        second = LISTENING.replace("pid=901", "pid=1477").replace("pid=812", "pid=1934")
        self.assertEqual(
            self.digests({("ss",): first})["listening_sockets"],
            self.digests({("ss",): second})["listening_sockets"],
        )
        # The process *name* and the address and the port are kept, so a failure
        # can be diagnosed; only the number is dropped, and it is dropped in
        # `ss -p`'s own spelling so the record still reads as a socket line.
        records = self.collect(FakeCommandRunner({("ss",): first}))["fields"]["listening_sockets"]["records"]
        self.assertIn(
            'tcp   LISTEN 0      4096   127.0.0.1:15353     0.0.0.0:*    '
            'users:(("dnscrypt-proxy",pid=<pid>,fd=5))',
            records,
        )

    def test_a_different_port_is_a_change(self):
        """The other half of the listener property, and the one a run could cause.

        This is the check that would catch a harness scenario binding the host's
        port 53 or 15353 -- the failure NO-HOST-MUTATION.md forbids outright, and
        the one a before/after comparison is the last line of defence against.
        """
        listening_elsewhere = LISTENING.replace("127.0.0.1:15353", "127.0.0.1:15354")
        self.assertNotEqual(
            self.digests({("ss",): LISTENING})["listening_sockets"],
            self.digests({("ss",): listening_elsewhere})["listening_sockets"],
        )

    def test_a_credential_shaped_value_in_command_output_is_not_recorded(self):
        """Command output goes into an archived file, and a profile's password is in it.

        `nmcli` prints a 802-1x password for a secured wireless connection, and
        `systemctl list-unit-files` can print an `Environment=` line carrying a
        token. Neither is what the snapshot is for, and the report module already
        knows how to scrub a value that is shaped like one.
        """
        with_secret = NM_CONNECTIONS + "HomeWifi             4d5e6f73-3333-4444-8555-666666666666  wifi     wlan0\n802-1x.password:s3cr3t-value\n"
        document = self.collect(FakeCommandRunner({("nmcli",): with_secret}))
        records = document["fields"]["networkmanager_connections"]["records"]
        self.assertNotIn("s3cr3t-value", json.dumps(document))
        # The line is kept, with the value blanked: the fact that the host has a
        # secured wireless connection is part of the state, and the key is not.
        self.assertIn("802-1x.password:{}".format(snapshot.REDACTED), records)
        # And the control: a value the scrubber is not shaped for is kept whole,
        # so the case is reading the redaction and not a field that is always
        # blanked.
        self.assertIn("HomeWifi             <uuid>  wifi     wlan0", records)

    def test_every_field_carries_a_digest_and_the_records_it_was_made_from(self):
        """A digest with no records is unauditable, and a record with no digest uncmpared.

        Task 7 compares digests; a person diagnosing a failure reads the records.
        Both are in the document for the same reason, and the case holds the shape
        for every field rather than for one of them.
        """
        document = self.collect()
        for name, field in document["fields"].items():
            with self.subTest(field=name):
                self.assertTrue(field["digest"].startswith("sha256:"), field)
                self.assertIsInstance(field["records"], list, name)
                self.assertIsNone(field["error"], name)

    def test_the_digest_is_the_hash_of_the_records(self):
        """Otherwise the digest is a number nobody can reproduce.

        Two runs, the same records, the same digest -- and a digest recomputed
        from the stored records has to equal the stored one, which is what makes
        "the snapshots differ" checkable by hand as well as by a program.
        """
        document = self.collect()
        for name, field in document["fields"].items():
            with self.subTest(field=name):
                self.assertEqual(field["digest"], snapshot.digest_of(field["records"]))

    def test_the_document_is_stable_text(self):
        """Two collections of the same state are the same document.

        A snapshot is compared against a previous run's, so a field that
        reordered itself would read as a change. The whole document, not one
        field, is what has to be byte-identical.
        """
        self.assertEqual(
            json.dumps(self.collect(), sort_keys=True),
            json.dumps(self.collect(), sort_keys=True),
        )


class FirefoxMetadataTest(SnapshotTestCase):
    """The field with a rule inside it: names, mtimes, sizes -- and no contents."""

    def test_it_records_the_path_mtime_and_size_of_every_profile_entry(self):
        """The three facts the plan asks for, and nothing else about them.

        The expected list is written out by hand from the fixture, so a
        collector that recorded a fourth field, or one field's value wrongly, is
        a difference rather than a change nobody reads.
        """
        document = self.collect()
        self.assertEqual(
            document["fields"]["firefox_profiles"]["records"],
            [
                "abc123.default-release\t{}\t{}".format(
                    record_mtime(self.firefox, "abc123.default-release"),
                    record_size(self.firefox, "abc123.default-release"),
                ),
                "abc123.default-release/cache2\t{}\t{}".format(
                    record_mtime(self.firefox, "abc123.default-release/cache2"),
                    record_size(self.firefox, "abc123.default-release/cache2"),
                ),
                "abc123.default-release/cache2/entries\t{}\t{}".format(
                    record_mtime(self.firefox, "abc123.default-release/cache2/entries"),
                    record_size(self.firefox, "abc123.default-release/cache2/entries"),
                ),
                "abc123.default-release/cache2/entries/0A0B0C0D0E0F\t{}\t{}".format(
                    record_mtime(self.firefox, "abc123.default-release/cache2/entries/0A0B0C0D0E0F"),
                    record_size(self.firefox, "abc123.default-release/cache2/entries/0A0B0C0D0E0F"),
                ),
                "abc123.default-release/places.sqlite\t{}\t{}".format(
                    record_mtime(self.firefox, "abc123.default-release/places.sqlite"),
                    record_size(self.firefox, "abc123.default-release/places.sqlite"),
                ),
                "abc123.default-release/prefs.js\t{}\t{}".format(
                    record_mtime(self.firefox, "abc123.default-release/prefs.js"),
                    record_size(self.firefox, "abc123.default-release/prefs.js"),
                ),
            ],
        )

    def test_no_profile_file_is_opened(self):
        """The strong half of "no contents may be read".

        "No content is used" is a claim about this module's discipline, and a
        module that opened the file and then discarded the bytes would satisfy it.
        What has to hold is that the bytes are never reached, and that is only
        visible from outside: the case installs an audit over every `open` on the
        Python surface, collects for real against real files, and requires that
        nothing under the profile root was opened.
        """
        with OpenAudit() as audit:
            self.collect()
        self.assertEqual(
            audit.under(self.firefox),
            [],
            "the snapshot opened a Firefox profile file; the plan allows names, mtimes and "
            "sizes, and the only way to get a fourth thing is to read the file",
        )

    def test_the_audit_would_notice_a_profile_file_being_opened(self):
        """The control. An audit that cannot fail turns the case above into a comment.

        This is the same defect the previous four rounds each found: a check that
        could not fail. So the audit is run against a function that reads a
        profile file with the one call a collector would plausibly use, and it has
        to report it. If this case fails, the case above is passing for a reason
        that has nothing to do with the collector.
        """
        target = self.firefox / "abc123.default-release" / "places.sqlite"
        with OpenAudit() as audit:
            target.read_text(encoding="utf-8")
        self.assertEqual(
            [Path(path).name for path in audit.under(self.firefox)],
            ["places.sqlite"],
            "the audit did not see a read of a profile file, so it cannot see one the "
            "collector does",
        )

    def test_no_profile_content_reaches_the_document(self):
        """The other half, and it is a weaker claim than the one above.

        Worth having on its own because it is the one a reader of the document
        can check: the snapshot is archived next to a report, and a browsing
        history in it would be a disclosure this harness has no business making.
        """
        document = self.collect()
        self.assertNotIn(PROFILE_SECRET, json.dumps(document))

    def test_a_root_that_does_not_exist_is_not_an_error(self):
        """A host with no Firefox is a host whose Firefox metadata did not change.

        Raising here would abandon the whole snapshot over a browser that is not
        installed, and a machine without a profile directory is the normal case
        on a build host.
        """
        document = self.collect(firefox_roots=[self.firefox, self.directory / "absent"])
        self.assertEqual(document["fields"]["firefox_profiles"]["records"], document["fields"]["firefox_profiles"]["records"])
        self.assertIsNone(document["fields"]["firefox_profiles"]["error"])

    def test_it_walks_every_profile_under_a_root_not_only_the_first(self):
        """A Firefox root holds several profiles, and a run that touched one is a change.

        Stopping at the first profile would make the field a sample rather than
        the record the comparison needs, and the miss would be silent: a second
        profile is exactly what a test run's own browser would have created.
        """
        second = self.firefox / "second.default"
        second.mkdir()
        (second / "prefs.js").write_text("// second profile\n", encoding="utf-8")
        records = self.collect()["fields"]["firefox_profiles"]["records"]
        self.assertIn(
            "second.default/prefs.js\t{}\t{}".format(
                record_mtime(self.firefox, "second.default/prefs.js"),
                record_size(self.firefox, "second.default/prefs.js"),
            ),
            records,
        )

    def test_a_symlink_is_recorded_as_the_link_and_not_as_its_target(self):
        """A profile entry that is a symlink points at bytes this harness must not read.

        `lstat` reads the link itself, so a link into a cache or an old backup is
        recorded by its own size -- and the target's name, size and mtime stay out
        of a record that is archived next to a report.
        """
        outside = self.directory / "outside-cache.bin"
        outside.write_bytes(b"x" * 99)
        profile = self.firefox / "abc123.default-release"
        os.symlink(outside, profile / "linked-cache")
        document = self.collect()
        records = document["fields"]["firefox_profiles"]["records"]
        self.assertIn(
            "abc123.default-release/linked-cache\t{}\t{}".format(
                record_mtime(self.firefox, "abc123.default-release/linked-cache"),
                record_size(self.firefox, "abc123.default-release/linked-cache"),
            ),
            records,
        )
        self.assertEqual(
            [record for record in records if "outside-cache" in record],
            [],
            "the record must be the link's own metadata, not the target's name",
        )

    def test_atime_is_not_recorded(self):
        """Listing a directory updates its access time, so recording it would be self-defeating.

        The snapshot has to walk the profile to learn the names it records, and
        that walk is itself a read as far as the filesystem is concerned. The
        three facts the plan names -- name, mtime, size -- are untouched by it, so
        recording atime would give the field a value every snapshot of this
        module changes just by being taken.
        """
        records = self.collect()["fields"]["firefox_profiles"]["records"]
        for record in records:
            with self.subTest(record=record):
                self.assertEqual(len(record.split("\t")), 3, record)


class SnapshotDocumentTest(SnapshotTestCase):
    """The document, the run it belongs to, and where it is written."""

    def test_it_carries_the_run_id_and_the_moment_it_was_taken(self):
        """A snapshot nobody can place is a snapshot nobody can compare."""
        document = self.collect()
        self.assertEqual(document["run_id"], "20260928T120000Z")
        self.assertEqual(document["taken_utc"], "2026-09-28T12:00:00Z")

    def test_it_writes_before_and_after_under_the_run_directory(self):
        """The two paths the plan names, under `build/test-results/RUN_ID`.

        Asserted as literals with a temporary results directory, because the path
        is the contract with the reader: two files in one run's directory, named
        for the moment they were taken.
        """
        results = self.directory / "build" / "test-results"
        document = self.collect()
        before = snapshot.write_snapshot(document, results, "20260928T120000Z", snapshot.BEFORE)
        after = snapshot.write_snapshot(document, results, "20260928T120000Z", snapshot.AFTER)
        self.assertEqual(
            [str(before), str(after)],
            [
                str(results / "20260928T120000Z" / "host-before.json"),
                str(results / "20260928T120000Z" / "host-after.json"),
            ],
        )
        self.assertTrue(before.is_file() and after.is_file())

    def test_the_written_file_is_the_document(self):
        """What is read back is what was collected.

        The comparison in Task 7 reads the files, not the objects, so a writer
        that dropped or reshaped a field on the way out would leave the snapshot
        weaker than the collection and nothing would notice.
        """
        results = self.directory / "results"
        document = self.collect()
        path = snapshot.write_snapshot(document, results, "20260928T120000Z", snapshot.BEFORE)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), document)

    def test_a_moment_that_is_not_before_or_after_is_refused(self):
        """Otherwise a typo writes a third file nobody looks at.

        `host-bfore.json` is a plausible typo and a silent one: the run would
        still write its pair, and the comparison would find one of them missing.
        """
        document = self.collect()
        with self.assertRaises(ValueError):
            snapshot.write_snapshot(document, self.directory, "20260928T120000Z", "bfore")

    def test_a_run_id_is_a_utc_timestamp(self):
        """The run id is a directory name, so a local-time one would sort wrong.

        Reused from the harness's own run id rather than written again here: two
        formats for one identifier is the shape of drift this project keeps
        finding, and the id names a directory and a container prefix at once.
        """
        moment = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(snapshot.new_run_id(moment), "20260928T120000Z")
        self.assertEqual(snapshot.new_run_id(moment), snapshot.new_run_id(moment))
        self.assertEqual(
            snapshot.new_run_id(datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone(timedelta(hours=-5)))),
            "20260928T170000Z",
        )

    def test_it_needs_a_runner_and_says_so(self):
        """The runner is the whole of the host interaction, so it is not optional.

        A default would be a snapshot that quietly runs whatever the operator's
        PATH happens to have, which is the opposite of an injected runner.
        """
        with self.assertRaises(TypeError):
            snapshot.collect_document(run_id="20260928T120000Z", taken_utc="2026-09-28T12:00:00Z")


class MutatingCommandDetectionTest(unittest.TestCase):
    """`mutating_command` has to recognise a write, including the ones a denylist misses.

    The first version of this table listed `nmcli radio` under the *read*
    subcommands, on the reasoning that a radio query is a read. `nmcli radio wifi
    on` is not a read: it turns the interface up. And the two sets the table
    referred to -- `READ_ONLY_COMMANDS` and `NMCLI_READ_SUBCOMMANDS` -- were read
    by nothing at all, while a comment beside them claimed the suite asked about
    them. A comment that describes a guard which is not there is worse than no
    comment, because it is a reader's evidence that the case is covered.
    """

    def test_the_read_only_nmcli_forms_are_not_flagged(self):
        for argv in (
            ("nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", "eth0"),
            ("nmcli", "-f", "NAME,DEVICE", "connection", "show"),
            ("nmcli", "general", "status"),
            ("nmcli", "--version"),
        ):
            with self.subTest(command=" ".join(argv)):
                self.assertFalse(snapshot.mutating_command(argv))

    def test_the_nmcli_forms_that_change_something_are_flagged(self):
        for argv in (
            ("nmcli", "radio", "wifi", "on"),
            ("nmcli", "radio", "all", "off"),
            ("nmcli", "general", "logging", "level", "trace"),
            ("nmcli", "general", "reset"),
            ("nmcli", "connectivity", "check", "now"),
            ("nmcli", "device", "set", "eth0", "managed", "yes"),
            ("nmcli", "connection", "modify", "eth0", "ipv4.never-default", "yes"),
            ("nmcli", "connection", "up", "eth0"),
            ("nmcli", "connection", "delete", "eth0"),
        ):
            with self.subTest(command=" ".join(argv)):
                self.assertTrue(
                    snapshot.mutating_command(argv),
                    f"{' '.join(argv)} changes the machine and was classified as a read",
                )

    def test_the_programs_a_snapshot_could_name_are_all_classified(self):
        """No program is left unclassified, which is what a missing table entry means.

        `mutating_command` returned `False` for anything not in its table, so a
        program nobody thought of was silently a read. The table is now closed over
        the six programs `collect_command_fields` actually runs, and this case holds
        that closure -- so adding a field with a new program forces a decision here
        rather than inheriting a default.
        """
        for argv in snapshot.COMMAND_FIELDS:
            with self.subTest(field=argv[0]):
                program = argv[1][0]
                self.assertIn(
                    program, snapshot.READ_ONLY_PROGRAMS,
                    f"the {argv[0]} field runs {program!r}, which is not in the table, so "
                    f"mutating_command() would classify it as a read by default",
                )

    def test_a_program_nobody_thought_of_is_refused_rather_than_assumed_a_read(self):
        """The control, and the direction of the default.

        An unknown program is refused, not read. The six commands this module runs
        are all named, so the refusal never fires in production -- and the reason it
        is the safe direction is that a snapshot exists to prove a run changed
        nothing, and a command it cannot classify is a command whose effect is
        unknown.
        """
        self.assertTrue(
            snapshot.mutating_command(("some-new-tool", "--read-some-flag")),
            "an unclassifiable program is treated as a read, which is the direction that "
            "silently weakens the claim the snapshot makes",
        )


class RunnerEnvironmentTest(unittest.TestCase):
    """The runner's child environment, and what its docstring claims about it.

    The docstring said "no env to inherit a token from" and the code passed
    `env=None`, which is `subprocess.run` for *inherit the parent's environment*.
    So the claim and the code disagreed, and the direction of the disagreement was
    the bad one: a token in the operator's shell would have been handed to every
    command a snapshot runs, and a command's environment is exactly the kind of
    thing this repository's Podman wrapper goes out of its way not to record.
    """

    def test_the_child_gets_a_named_set_of_variables_and_nothing_else(self):
        import os

        recorded = {}
        real = os.environ
        try:
            os.environ = {
                **real,
                "AWS_SECRET_ACCESS_KEY": "must-not-be-forwarded",
                "MOSDNS_TOKEN": "must-not-be-forwarded",
            }
            runner = snapshot.SubprocessRunner()
            child = runner.child_environment()
        finally:
            os.environ = real
        recorded.update(child)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", recorded)
        self.assertNotIn("MOSDNS_TOKEN", recorded)
        for name in recorded:
            with self.subTest(variable=name):
                self.assertIn(
                    name, snapshot.SNAPSHOT_ENV_NAMES,
                    "the runner forwards a variable its own allowlist does not name, which is "
                    "the same shape of hole as an unredacted environment",
                )

    def test_an_explicit_override_is_merged_and_still_named(self):
        runner = snapshot.SubprocessRunner(extra_env={"LC_ALL": "C"})
        child = runner.child_environment()
        self.assertEqual(child["LC_ALL"], "C")

    def test_the_documented_allowlist_is_the_one_the_runner_docstring_names(self):
        """The docstring and the code, compared.

        A docstring that describes a guard which is not there is a reader's evidence
        that the case is covered, and this pair of claims -- the environment and the
        two dead sets -- is the third time this file has had one.
        """
        import inspect

        source = inspect.getsource(snapshot.SubprocessRunner)
        # Whitespace is collapsed first: the claim is a sentence, and a sentence
        # that happens to be wrapped across a line is not a different claim. A
        # literal search over wrapped prose fails on a reformat and passes on a
        # docstring that says the opposite, which is the worst of both.
        flattened = " ".join(source.split())
        self.assertIn("SNAPSHOT_ENV_NAMES", source)
        self.assertIn(
            "no environment to inherit a token from",
            flattened,
            "the runner's docstring no longer states that it withholds the environment, so a "
            "reader looking for that guarantee in the class is looking for a claim that has "
            "moved -- and the guarantee is the thing this class exists for",
        )



class ProjectUnitDerivationTest(unittest.TestCase):
    """The unit list comes from the package, not from a list that can fall behind it.

    `PROJECT_UNITS` was five literals, and a case's docstring claimed "the names
    come from the package". A sixth unit shipped by the package would then be
    absent from the snapshot's `project_units` field -- and that field is one of the
    seven the host-isolation comparison reads, so the unit a run left behind would
    not be in the record that exists to catch it. Silent, and in the one direction
    that matters.
    """

    def test_the_derived_names_are_the_units_the_package_ships(self):
        derived = snapshot.project_units()
        shipped = sorted(
            path.name for path in (REPO / "packaging" / "systemd").glob("*.service")
        )
        self.assertEqual(
            sorted(derived), shipped,
            "the snapshot's project-unit list and the package's systemd/ directory have "
            "drifted apart, so a unit the package ships is not in the record a run's "
            "leftovers are compared against",
        )

    def test_a_documented_limit_is_stated_where_somebody_would_look(self):
        """The one thing the derivation cannot do, written down rather than implied.

        The package installs a unit from `packaging/systemd/` and the derivation
        follows that directory. A unit shipped from anywhere else would be missed,
        and no case can tell that from here without becoming a second inventory of
        the package -- which is the thing that drifts. So the limit is recorded and
        this case holds the record.
        """
        self.assertIn("packaging/systemd", snapshot.project_units.__doc__)
        self.assertIn("not", snapshot.project_units.__doc__.lower())


class FieldDigestTest(unittest.TestCase):
    """A field's digest covers everything the field records, error included.

    `resolv_conf_link` had a case whose docstring said a command's error "is part of
    what the digest covers" and a `_field` that hashed `records` only. So a
    resolver that was a symlink and a resolver that was a *missing file* produced
    the same digest -- an empty `records` list either way -- and Task 7's
    comparison would have called them equal. The docstring and the code disagreed
    and the code was the weaker of the two.

    Hashing the error as well as the records is the fix, because the error *is* part
    of what the field observed. The alternative -- comparing whole documents
    rather than digests -- is Task 7's choice and does not remove the trap from this
    module's own output.
    """

    def field(self, records, error):
        return snapshot._field("resolv_conf_link", records, error)

    def test_a_missing_file_and_a_link_that_is_not_one_have_different_digests(self):
        absent = self.field([], "FileNotFoundError: /etc/resolv.conf: no such file")
        not_a_link = self.field([], "OSError: readlink: /etc/resolv.conf: Not a symbolic link")
        self.assertEqual(absent["records"], not_a_link["records"])
        self.assertNotEqual(
            absent["digest"], not_a_link["digest"],
            "two different failures both produce an empty record list and the same digest, so "
            "a comparison of digests cannot tell them apart",
        )

    def test_a_field_with_an_error_never_digests_as_a_clean_field(self):
        self.assertNotEqual(
            self.field([], "OSError: something")["digest"],
            self.field([], None)["digest"],
            "a field that failed to be collected digests the same as one that was empty, and an "
            "empty field is what an unchanged host looks like",
        )

    def test_the_digest_is_still_reproducible_from_the_records_alone(self):
        """The recomputation case, and it is why the error is folded in as text.

        A reader who wants to check "the snapshots differ" by hand has to be able to
        recompute a digest from the document. So the error is hashed *as a string*
        alongside the records rather than through a different path, and this case
        holds the two in step.
        """
        document = self.field(["link -> stub"], "OSError: partial read")
        self.assertEqual(
            document["digest"],
            snapshot.digest_of(["link -> stub"], error="OSError: partial read"),
        )


class WalkShapeTest(unittest.TestCase):
    """The walk itself, on paths a fixture did not build for it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)

    def test_a_deep_profile_is_walked_rather_than_truncated(self):
        """A real profile nests several levels below the root.

        A walk with a depth limit would record a prefix of the profile and call
        it the profile, and the run that changed a file four levels down would
        compare equal to one that changed nothing.
        """
        root = self.directory / "firefox"
        deep = root / "abc.default" / "storage" / "default" / "https+++example.com" / "idb"
        deep.mkdir(parents=True)
        (deep / "000003.log").write_bytes(b"z" * 17)
        records = snapshot.firefox_profile_records([root])
        self.assertEqual(
            records,
            [
                "abc.default\t{}\t{}".format(
                    os.lstat(root / "abc.default").st_mtime_ns, os.lstat(root / "abc.default").st_size
                ),
                "abc.default/storage\t{}\t{}".format(
                    os.lstat(root / "abc.default/storage").st_mtime_ns,
                    os.lstat(root / "abc.default/storage").st_size,
                ),
                "abc.default/storage/default\t{}\t{}".format(
                    os.lstat(root / "abc.default/storage/default").st_mtime_ns,
                    os.lstat(root / "abc.default/storage/default").st_size,
                ),
                "abc.default/storage/default/https+++example.com\t{}\t{}".format(
                    os.lstat(root / "abc.default/storage/default/https+++example.com").st_mtime_ns,
                    os.lstat(root / "abc.default/storage/default/https+++example.com").st_size,
                ),
                "abc.default/storage/default/https+++example.com/idb\t{}\t{}".format(
                    os.lstat(root / "abc.default/storage/default/https+++example.com/idb").st_mtime_ns,
                    os.lstat(root / "abc.default/storage/default/https+++example.com/idb").st_size,
                ),
                "abc.default/storage/default/https+++example.com/idb/000003.log\t{}\t{}".format(
                    os.lstat(root / "abc.default/storage/default/https+++example.com/idb/000003.log").st_mtime_ns,
                    os.lstat(root / "abc.default/storage/default/https+++example.com/idb/000003.log").st_size,
                ),
            ],
        )

    def test_an_unreadable_directory_does_not_abandon_the_others(self):
        """A root the operator cannot list must not cost the rest of the snapshot.

        A profile directory can be unreadable for reasons that have nothing to do
        with this run, and a walk that raised would leave the run with no Firefox
        record at all -- which is indistinguishable from "nothing changed", the
        one answer a snapshot must never give by accident.
        """
        readable = self.directory / "readable"
        (readable / "abc.default").mkdir(parents=True)
        (readable / "abc.default" / "prefs.js").write_text("// x\n", encoding="utf-8")
        unreadable = self.directory / "unreadable"
        (unreadable / "def.default").mkdir(parents=True)
        (unreadable / "def.default" / "prefs.js").write_text("// y\n", encoding="utf-8")
        os.chmod(unreadable / "def.default", 0o000)
        self.addCleanup(os.chmod, unreadable / "def.default", stat.S_IRWXU)
        if os.access(unreadable / "def.default", os.R_OK):
            self.skipTest("this process can list a mode 000 directory, so the case is not testing it")
        records = snapshot.firefox_profile_records([unreadable, readable])
        self.assertEqual(
            [record for record in records if record.startswith("abc.default/prefs.js")],
            [
                "abc.default/prefs.js\t{}\t{}".format(
                    os.lstat(readable / "abc.default" / "prefs.js").st_mtime_ns,
                    os.lstat(readable / "abc.default" / "prefs.js").st_size,
                )
            ],
        )

    def test_records_are_sorted_so_two_walks_of_one_tree_agree(self):
        """The walk order of a filesystem is not a promise, and the digest is compared."""
        root = self.directory / "firefox"
        for name in ("zeta.default", "alpha.default", "mu.default"):
            (root / name).mkdir(parents=True)
            (root / name / "prefs.js").write_text(f"// {name}\n", encoding="utf-8")
        self.assertEqual(snapshot.firefox_profile_records([root]), sorted(snapshot.firefox_profile_records([root])))
        self.assertEqual(snapshot.firefox_profile_records([root]), snapshot.firefox_profile_records([root]))


if __name__ == "__main__":
    unittest.main()
