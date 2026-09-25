"""Tests for the DHCP DNS bridge: collection, publication, locking, and the CLI.

The published file is the only channel between a NetworkManager dispatcher event
and the router's ``dhcp_forward`` plugin, and the CLI is the only way a
dispatcher event reaches it, so these tests work on real files, a real advisory
lock, and real timestamps. Each one names the break it catches: a state document
a reader would reject, a generation that skipped or repeated a value, an unchanged
event that still rewrote the file, an event that published the wrong interface or
the wrong source, a source that could not be read being published as an empty
lease, a lock that let two writers through, a failed write that left a partial or
lost target behind, and a command that reached a shell.
"""

import contextlib
import datetime
import errno
import fcntl
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

# The bridge package is used from a source checkout, not from an installed
# distribution, so the repository's bridge directory is the import root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mosdns_dhcp_bridge import cli
from mosdns_dhcp_bridge.publish import (
    InvalidStateError,
    LockUnavailable,
    PublicationError,
    publish_if_changed,
)

INTERFACE = "enp3s0"
UUID = "11111111-1111-1111-1111-111111111111"
NOW = datetime.datetime(2026, 9, 25, 0, 0, tzinfo=datetime.timezone.utc)
LATER = NOW + datetime.timedelta(hours=1)


def state_document(**overrides):
    """Return a hand-written valid state document as JSON text.

    Every field is a literal so a test can corrupt exactly one of them and know
    that the document is otherwise a state file the Go reader accepts.
    """
    fields = {
        "schema_version": 1,
        "generation": 1,
        "interface": "enp3s0",
        "connection_uuid": "11111111-1111-1111-1111-111111111111",
        "upstreams": ["192.168.1.1"],
        "observed_at": "2026-09-25T00:00:00Z",
        "source": "dhcp4",
        "last_good": True,
    }
    fields.update(overrides)
    return json.dumps(fields)


@contextlib.contextmanager
def failing_fsync(directories):
    """Fail os.fsync for the descriptors of the requested kind only.

    ``directories`` selects the file kind: True for directory descriptors, False
    for regular files. The other kind keeps the real syscall, so the injection
    fails the exact step under test and nothing else.
    """
    real_fsync = os.fsync

    def injected(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode) is directories:
            raise OSError(errno.EIO, "injected fsync failure")
        return real_fsync(descriptor)

    with mock.patch("os.fsync", injected):
        yield


class PublicationTests(unittest.TestCase):
    """What a reader of the state file sees after one event."""

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.state_path = self.directory / "dhcp-upstreams.json"
        self.lock_path = self.directory / "dhcp-bridge.lock"

    def publish(
        self,
        upstreams,
        interface=INTERFACE,
        connection_uuid=UUID,
        source="dhcp4",
        now=NOW,
        state_path=None,
        lock_path=None,
    ):
        """Publish one event, defaulting to this test's real state file."""
        return publish_if_changed(
            str(state_path or self.state_path),
            interface=interface,
            connection_uuid=connection_uuid,
            upstreams=upstreams,
            source=source,
            now=now,
            lock_path=str(lock_path) if lock_path is not None else None,
        )

    def published(self, state_path=None):
        """Return the state file exactly as a reader would find it."""
        return json.loads((state_path or self.state_path).read_text())

    def test_first_publish_writes_generation_one(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        data = self.published()
        self.assertEqual(data["generation"], 1)
        self.assertEqual(data["upstreams"], ["192.168.1.1"])

    def test_first_publish_records_the_whole_event_factly(self):
        self.publish(["192.168.1.1", "fd00::1"])
        self.assertEqual(
            self.published(),
            {
                "schema_version": 1,
                "generation": 1,
                "interface": "enp3s0",
                "connection_uuid": "11111111-1111-1111-1111-111111111111",
                "upstreams": ["192.168.1.1", "fd00::1"],
                "observed_at": "2026-09-25T00:00:00Z",
                "source": "dhcp4",
                "last_good": True,
            },
        )

    def test_unchanged_dns_does_not_rewrite_file(self):
        self.publish(["192.168.1.1"])
        original = self.state_path.read_bytes()
        before = self.state_path.stat()
        self.assertFalse(self.publish(["192.168.1.1"], now=LATER))
        after = self.state_path.stat()
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(after.st_ino, before.st_ino)
        self.assertEqual(self.state_path.read_bytes(), original)

    def test_reordered_upstreams_are_the_same_state(self):
        self.publish(["192.168.1.1", "fd00::1"])
        before = self.state_path.stat()
        self.assertFalse(self.publish(["fd00::1", "192.168.1.1"], now=LATER))
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)

    def test_a_lease_renewal_of_the_same_addresses_is_still_unchanged(self):
        self.publish(["192.168.1.1"])
        for hours in [1, 2, 3, 4]:
            self.assertFalse(
                self.publish(["192.168.1.1"], now=NOW + datetime.timedelta(hours=hours))
            )
        self.assertEqual(self.published()["generation"], 1)
        self.assertEqual(self.published()["observed_at"], "2026-09-25T00:00:00Z")

    def test_changed_dns_increments_generation(self):
        self.publish(["192.168.1.1"])
        self.assertTrue(self.publish(["192.168.1.53"], now=LATER))
        self.assertEqual(self.published()["generation"], 2)
        self.assertEqual(self.published()["upstreams"], ["192.168.1.53"])
        self.assertEqual(self.published()["observed_at"], "2026-09-25T01:00:00Z")

    def test_the_published_bytes_are_the_state_a_reader_is_told_to_expect(self):
        self.publish(["192.168.1.1"])
        self.assertEqual(
            self.state_path.read_text(),
            """{
  "schema_version": 1,
  "generation": 1,
  "interface": "enp3s0",
  "connection_uuid": "11111111-1111-1111-1111-111111111111",
  "upstreams": [
    "192.168.1.1"
  ],
  "observed_at": "2026-09-25T00:00:00Z",
  "source": "dhcp4",
  "last_good": true
}
""",
        )

    def test_every_distinct_event_advances_the_generation_by_exactly_one(self):
        for index, upstreams in enumerate(
            [["192.168.1.1"], ["192.168.1.2"], ["192.168.1.2", "fd00::1"], []], start=1
        ):
            self.assertTrue(self.publish(upstreams))
            self.assertEqual(self.published()["generation"], index)

    def test_a_new_interface_is_a_new_generation(self):
        self.publish(["192.168.1.1"], interface="enp3s0")
        self.assertTrue(self.publish(["192.168.1.1"], interface="br-lan"))
        data = self.published()
        self.assertEqual((data["interface"], data["generation"]), ("br-lan", 2))

    def test_a_new_connection_uuid_is_a_new_generation(self):
        self.publish(["192.168.1.1"], connection_uuid=UUID)
        self.assertTrue(
            self.publish(["192.168.1.1"], connection_uuid="22222222-2222-2222-2222-222222222222")
        )
        data = self.published()
        self.assertEqual(
            data["connection_uuid"], "22222222-2222-2222-2222-222222222222"
        )
        self.assertEqual(data["generation"], 2)

    def test_a_new_source_is_a_new_generation(self):
        self.publish(["192.168.1.1"], source="dhcp4")
        self.assertTrue(self.publish(["192.168.1.1"], source="dhcp6"))
        data = self.published()
        self.assertEqual((data["source"], data["generation"]), ("dhcp6", 2))

    def test_empty_dns_disables_current_interface(self):
        self.publish(["192.168.1.1"])
        self.assertTrue(self.publish([]))
        data = self.published()
        self.assertEqual(data["upstreams"], [])
        self.assertFalse(data["last_good"])
        self.assertEqual(data["generation"], 2)

    def test_upstreams_are_deduplicated_and_ordered_ipv4_first(self):
        self.publish(["fd00::1", "192.168.1.1", "fd00::1", "192.168.1.1"])
        self.assertEqual(self.published()["upstreams"], ["192.168.1.1", "fd00::1"])

    def test_a_duplicate_address_alone_is_not_a_new_generation(self):
        self.publish(["192.168.1.1", "fd00::1"])
        self.assertFalse(self.publish(["192.168.1.1", "192.168.1.1", "fd00::1"]))
        self.assertEqual(self.published()["generation"], 1)

    def test_the_observation_time_is_converted_to_utc(self):
        self.publish(
            ["192.168.1.1"],
            now=datetime.datetime(
                2026, 9, 25, 8, 30, tzinfo=datetime.timezone(datetime.timedelta(hours=8))
            ),
        )
        self.assertEqual(self.published()["observed_at"], "2026-09-25T00:30:00Z")

    def test_the_same_event_publishes_the_same_bytes_twice(self):
        first = self.directory / "first.json"
        second = self.directory / "second.json"
        self.publish(["192.168.1.1", "fd00::1"], state_path=first)
        self.publish(["fd00::1", "192.168.1.1"], state_path=second)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_publication_leaves_no_temporary_file_behind(self):
        self.publish(["192.168.1.1"])
        self.assertEqual(
            sorted(os.listdir(self.directory)),
            ["dhcp-bridge.lock", "dhcp-upstreams.json"],
        )

    def test_a_restrictive_umask_does_not_narrow_the_published_modes(self):
        nested = self.directory / "run" / "mosdns"
        with _umask(0o077):
            self.assertTrue(self.publish(["192.168.1.1"], state_path=nested / "dhcp-upstreams.json"))
        self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((nested / "dhcp-upstreams.json").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((nested / "dhcp-bridge.lock").stat().st_mode), 0o640)

    def test_publication_creates_a_missing_parent_directory(self):
        target = self.directory / "run" / "mosdns" / "dhcp-upstreams.json"
        self.assertTrue(self.publish(["192.168.1.1"], state_path=target))
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o750)
        self.assertTrue(target.is_file())

    def test_rejects_an_upstream_a_query_could_not_be_forwarded_to(self):
        for upstream in [
            "127.0.0.53",
            "127.0.0.54",
            "0.0.0.0",
            "169.254.10.1",
            "224.0.0.1",
            "::1",
            "::",
            "ff02::1",
            "fe80::1%enp3s0",
            "::ffff:192.168.1.1",
            "not-an-ip",
            "",
            "192.168.1.1 192.168.1.2",
            "[192.168.1.1]",
        ]:
            with self.subTest(upstream=upstream):
                with self.assertRaises(ValueError):
                    self.publish([upstream])
                self.assertFalse(self.state_path.exists())

    def test_rejects_an_interface_or_source_the_state_validator_would_refuse(self):
        for interface, source in [
            ("enp3s0:1", "dhcp4"),
            ("", "dhcp4"),
            ("eth0 eth1", "dhcp4"),
            ("abcdefghijklmnop", "dhcp4"),
            ("enp3s0", "DHCP4"),
            ("enp3s0", "network manager"),
            ("enp3s0", ""),
            ("enp3s0", "-dhcp4"),
            ("enp3s0", "d" * 33),
        ]:
            with self.subTest(interface=interface, source=source):
                with self.assertRaises(ValueError):
                    self.publish(["192.168.1.1"], interface=interface, source=source)
                self.assertFalse(self.state_path.exists())

    def test_rejects_a_connection_uuid_the_router_never_wrote(self):
        for connection_uuid in ["not-a-uuid", "1111", "11111111-1111-1111-1111-11111111111Z"]:
            with self.subTest(connection_uuid=connection_uuid):
                with self.assertRaises(ValueError):
                    self.publish(["192.168.1.1"], connection_uuid=connection_uuid)
                self.assertFalse(self.state_path.exists())

    def test_a_state_with_upstreams_requires_a_connection_uuid(self):
        with self.assertRaises(ValueError):
            self.publish(["192.168.1.1"], connection_uuid="")
        self.assertFalse(self.state_path.exists())

    def test_a_disabled_state_records_a_missing_connection_uuid(self):
        self.assertTrue(self.publish([], connection_uuid=""))
        data = self.published()
        self.assertEqual(data["connection_uuid"], "")
        self.assertFalse(data["last_good"])


class ExistingStateTests(unittest.TestCase):
    """What the publisher does with the state it finds already there."""

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.state_path = Path(self.workspace.name) / "dhcp-upstreams.json"

    def publish(self, upstreams, now=NOW, source="dhcp4", interface=INTERFACE):
        return publish_if_changed(
            str(self.state_path),
            interface=interface,
            connection_uuid=UUID,
            upstreams=upstreams,
            source=source,
            now=now,
        )

    def test_the_first_publish_after_a_removed_state_starts_at_generation_one(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        self.state_path.unlink()
        self.assertTrue(self.publish(["192.168.1.1"]))
        self.assertEqual(json.loads(self.state_path.read_text())["generation"], 1)

    def test_the_generation_continues_from_the_published_value(self):
        self.state_path.write_text(state_document(generation=7, upstreams=["10.0.0.1"]))
        self.assertTrue(self.publish(["10.0.0.1", "fd00::2"]))
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["generation"], 8)
        self.assertEqual(data["upstreams"], ["10.0.0.1", "fd00::2"])

    def test_an_unchanged_existing_state_is_left_byte_for_byte(self):
        original = state_document() + "\n"
        self.state_path.write_text(original)
        self.assertFalse(self.publish(["192.168.1.1"], now=LATER))
        self.assertEqual(self.state_path.read_text(), original)

    def test_an_existing_state_whose_upstreams_are_out_of_order_is_not_a_change(self):
        self.state_path.write_text(
            state_document(upstreams=["fd00::1", "192.168.1.1"]) + "\n"
        )
        before = self.state_path.stat()
        self.assertFalse(self.publish(["192.168.1.1", "fd00::1"], now=LATER))
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)

    def test_a_valid_state_without_a_uuid_is_replaced_when_the_event_collects_dns(self):
        self.state_path.write_text(
            state_document(upstreams=[], connection_uuid="", last_good=False) + "\n"
        )
        self.assertTrue(self.publish(["192.168.1.1"]))
        data = json.loads(self.state_path.read_text())
        self.assertEqual((data["generation"], data["last_good"]), (2, True))
        self.assertEqual(data["connection_uuid"], UUID)

    def test_an_invalid_existing_state_is_never_overwritten(self):
        cases = {
            "truncated json": "{",
            "empty file": "",
            "not an object": '["192.168.1.1"]',
            "trailing data": state_document() + "{}",
            "wrong schema version": state_document(schema_version=2),
            "boolean schema version": state_document(schema_version=True),
            "zero generation": state_document(generation=0),
            "negative generation": state_document(generation=-1),
            "boolean generation": state_document(generation=True),
            "float generation": state_document(generation=1.5),
            "string generation": state_document(generation="1"),
            "missing key": json.dumps({"schema_version": 1, "generation": 1}),
            "unknown key": state_document(extra="value"),
            "missing upstream key": json.dumps(
                {
                    "schema_version": 1,
                    "generation": 1,
                    "interface": "enp3s0",
                    "connection_uuid": UUID,
                    "observed_at": "2026-09-25T00:00:00Z",
                    "source": "dhcp4",
                    "last_good": False,
                }
            ),
            "colon interface": state_document(interface="enp3s0:1"),
            "long interface": state_document(interface="abcdefghijklmnop"),
            "uppercase source": state_document(source="DHCP4"),
            "source with a space": state_document(source="dhcp 4"),
            "local upstream": state_document(upstreams=["127.0.0.53"]),
            "scoped upstream": state_document(upstreams=["fe80::1%enp3s0"]),
            "non string upstream": state_document(upstreams=[53]),
            "upstream object": state_document(upstreams=[{"address": "10.0.0.1"}]),
            "upstream not a list": state_document(upstreams="10.0.0.1"),
            "unrfc3339 time": state_document(observed_at="2026-09-25 00:00:00"),
            "offset time": state_document(observed_at="2026-09-25T00:00:00+08:00"),
            "fractional time": state_document(observed_at="2026-09-25T00:00:00.5Z"),
            "impossible date": state_document(observed_at="2026-02-30T00:00:00Z"),
            "empty time": state_document(observed_at=""),
            "string last good": state_document(last_good="true"),
            "integer last good": state_document(last_good=1),
            "last good without upstreams": state_document(upstreams=[], last_good=True),
            "disabled with upstreams": state_document(upstreams=["10.0.0.1"], last_good=False),
            "last good with a broken uuid": state_document(connection_uuid="not-a-uuid"),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.state_path.write_text(text)
                with self.assertRaises(InvalidStateError):
                    self.publish(["192.168.1.53"])
                self.assertEqual(self.state_path.read_text(), text)

    def test_a_duplicate_key_makes_an_existing_state_invalid(self):
        text = state_document().replace(
            '"source": "dhcp4"', '"source": "dhcp4", "source": "dhcp6"'
        )
        self.state_path.write_text(text)
        with self.assertRaises(InvalidStateError):
            self.publish(["192.168.1.53"])
        self.assertEqual(self.state_path.read_text(), text)

    def test_a_state_that_is_not_text_is_invalid_state_not_a_bad_request(self):
        for payload in [b"\xff\xfe\x00garbage", b"", b"\x00"]:
            with self.subTest(payload=payload):
                self.state_path.write_bytes(payload)
                with self.assertRaises(InvalidStateError):
                    self.publish(["192.168.1.53"])
                self.assertEqual(self.state_path.read_bytes(), payload)


class LockTests(unittest.TestCase):
    """One bridge process at a time, enforced by a real advisory lock."""

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.state_path = self.directory / "dhcp-upstreams.json"
        self.lock_path = self.directory / "dhcp-bridge.lock"

    def publish(self, upstreams, lock_path=None):
        return publish_if_changed(
            str(self.state_path),
            interface=INTERFACE,
            connection_uuid=UUID,
            upstreams=upstreams,
            source="dhcp4",
            now=NOW,
            lock_path=str(lock_path) if lock_path is not None else None,
        )

    @contextlib.contextmanager
    def held_lock(self, path):
        """Hold the publication lock the way another bridge process would."""
        descriptor = os.open(str(path), os.O_CREAT | os.O_RDONLY, 0o640)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield

    def publish_while_held(self, publish, seconds=10.0):
        """Return the error ``publish`` raises, failing if it does not return.

        A publication lock that waits instead of reporting a conflict would
        otherwise hang the suite rather than fail it, and a hanging suite proves
        nothing about the exit status the dispatcher would have seen.
        """
        outcome = {}

        def attempt():
            try:
                outcome["value"] = publish()
            except BaseException as error:  # noqa: BLE001 - reported verbatim
                outcome["error"] = error

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(seconds)
        if worker.is_alive():
            self.fail(
                f"publication did not finish within {seconds}s while the lock was held: "
                "the lock blocks instead of reporting a conflict"
            )
        if "value" in outcome:
            return None
        return outcome.get("error")

    def test_the_lock_is_a_dedicated_file_next_to_the_state(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        self.assertTrue(self.lock_path.is_file())
        self.assertNotEqual(self.lock_path, self.state_path)
        self.assertEqual(stat.S_IMODE(self.lock_path.stat().st_mode), 0o640)

    def test_a_held_lock_stops_a_second_publication(self):
        with self.held_lock(self.lock_path):
            error = self.publish_while_held(lambda: self.publish(["192.168.1.1"]))
        self.assertIsInstance(error, LockUnavailable)
        self.assertFalse(self.state_path.exists())

    def test_a_held_lock_never_leaves_a_stale_state_behind(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        original = self.state_path.read_bytes()
        with self.held_lock(self.lock_path):
            error = self.publish_while_held(lambda: self.publish(["192.168.1.53"]))
        self.assertIsInstance(error, LockUnavailable)
        self.assertEqual(self.state_path.read_bytes(), original)

    def test_a_held_dedicated_lock_does_not_block_a_state_the_lock_cannot_see(self):
        """The state file is not a lock: a stale state must not block writing."""
        self.assertTrue(self.publish(["192.168.1.1"]))
        with self.held_lock(self.state_path):
            self.assertTrue(self.publish(["192.168.1.53"]))
        self.assertEqual(json.loads(self.state_path.read_text())["upstreams"], ["192.168.1.53"])

    def test_the_lock_is_released_when_publication_fails(self):
        with mock.patch("os.replace", side_effect=OSError(errno.EIO, "injected")):
            with self.assertRaises(PublicationError):
                self.publish(["192.168.1.1"])
        self.assertTrue(self.publish(["192.168.1.1"]))

    def test_an_explicit_lock_path_is_used_instead_of_the_default(self):
        elsewhere = self.directory / "run" / "bridge.lock"
        self.assertTrue(self.publish(["192.168.1.1"], lock_path=elsewhere))
        self.assertTrue(elsewhere.is_file())
        self.assertFalse(self.lock_path.exists())


class AtomicWriteTests(unittest.TestCase):
    """A reader sees the previous state or the next one, never a partial file."""

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.state_path = self.directory / "dhcp-upstreams.json"

    def publish(self, upstreams, now=NOW):
        return publish_if_changed(
            str(self.state_path),
            interface=INTERFACE,
            connection_uuid=UUID,
            upstreams=upstreams,
            source="dhcp4",
            now=now,
        )

    def temporary_names(self):
        """Return the files in the state directory that are not the state."""
        return sorted(
            name
            for name in os.listdir(self.directory)
            if name not in ("dhcp-upstreams.json", "dhcp-bridge.lock")
        )

    def test_a_failed_replace_keeps_the_previous_state(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        original = self.state_path.read_bytes()
        observed = {}

        def failing_replace(source, target):
            observed["entries"] = sorted(os.listdir(self.directory))
            raise OSError(errno.EIO, "injected replace failure")

        with mock.patch("os.replace", failing_replace):
            with self.assertRaises(PublicationError):
                self.publish(["192.168.1.53"])
        self.assertEqual(self.state_path.read_bytes(), original)
        self.assertEqual(self.temporary_names(), [])
        self.assertIn("dhcp-upstreams.json.tmp", observed["entries"])

    def test_a_failed_replace_of_the_first_event_publishes_nothing(self):
        with mock.patch("os.replace", side_effect=OSError(errno.EIO, "injected")):
            with self.assertRaises(PublicationError):
                self.publish(["192.168.1.1"])
        self.assertFalse(self.state_path.exists())
        self.assertEqual(self.temporary_names(), [])

    def test_a_failed_state_sync_keeps_the_previous_state(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        original = self.state_path.read_bytes()
        with failing_fsync(directories=False):
            with self.assertRaises(PublicationError):
                self.publish(["192.168.1.53"], now=LATER)
        self.assertEqual(self.state_path.read_bytes(), original)
        self.assertEqual(self.temporary_names(), [])

    def test_a_failed_state_sync_of_the_first_event_publishes_nothing(self):
        with failing_fsync(directories=False):
            with self.assertRaises(PublicationError):
                self.publish(["192.168.1.1"])
        self.assertFalse(self.state_path.exists())
        self.assertEqual(self.temporary_names(), [])

    def test_a_failed_directory_sync_is_reported_and_leaves_a_complete_state(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        with failing_fsync(directories=True):
            with self.assertRaises(PublicationError):
                self.publish(["192.168.1.53"], now=LATER)
        data = json.loads(self.state_path.read_text())
        self.assertEqual(data["upstreams"], ["192.168.1.53"])
        self.assertEqual(data["generation"], 2)
        self.assertEqual(self.temporary_names(), [])

    def test_the_state_replaces_the_previous_inode_only_after_a_complete_write(self):
        self.assertTrue(self.publish(["192.168.1.1"]))
        self.assertEqual(stat.S_IMODE(self.state_path.stat().st_mode), 0o640)
        self.assertTrue(self.publish(["192.168.1.53"]))
        self.assertEqual(json.loads(self.state_path.read_text())["upstreams"], ["192.168.1.53"])
        self.assertEqual(stat.S_IMODE(self.state_path.stat().st_mode), 0o640)


class RecordingRunner:
    """A command runner that answers argument arrays and records every call.

    A command the test did not prepare answers empty, and an argument that is not
    a sequence is refused outright, so a collector that reached for a shell
    string or built the wrong argument array is visible in ``calls`` rather than
    silently tolerated.
    """

    def __init__(self, answers=None, failures=None):
        self._answers = dict(answers or {})
        self._failures = dict(failures or {})
        self.calls = []

    def __call__(self, argv):
        if not isinstance(argv, (list, tuple)):
            raise TypeError("a command must be an argument array, not a shell string")
        command = tuple(argv)
        self.calls.append(command)
        if command in self._failures:
            raise self._failures[command]
        return self._answers.get(command, "")


class BrokenRunner(RecordingRunner):
    """A runner whose every command fails, the way a wedged D-Bus behaves."""

    def __call__(self, argv):
        if not isinstance(argv, (list, tuple)):
            raise TypeError("a command must be an argument array, not a shell string")
        self.calls.append(tuple(argv))
        raise OSError("Could not connect to the system bus")

class DispatcherCommandLineTests(unittest.TestCase):
    """What one NetworkManager event does to the published state."""

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.state_path = self.directory / "dhcp-upstreams.json"
        self.lock_path = self.directory / "dhcp-bridge.lock"

    def argv(self, state_path=None, lock_path=None):
        return [
            "--state-file",
            str(state_path or self.state_path),
            "--lock-file",
            str(lock_path or self.lock_path),
        ]

    def event(self, action, **variables):
        """Return a dispatcher environment for ``action``."""
        environment = {"NM_DISPATCHER_ACTION": action}
        environment.update(variables)
        return environment

    def call(self, env, argv=None, runner=None):
        """Run the CLI and return its exit code, stderr, and the runner."""
        runner = RecordingRunner() if runner is None else runner
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = cli.main(self.argv() if argv is None else argv, env, runner)
        return code, stderr.getvalue(), runner

    def call_while_held(self, env, seconds=10.0):
        """Return the CLI exit code under a held lock, failing if it blocks.

        A publication lock that waited instead of reporting the conflict would
        hang the suite rather than fail it, and the exit status the dispatcher
        sees is exactly what this test exists to pin.
        """
        outcome = {}

        def attempt():
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    outcome["code"] = cli.main(self.argv(), env, RecordingRunner())
            finally:
                outcome["stderr"] = stderr.getvalue()

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(seconds)
        if worker.is_alive():
            self.fail(
                f"the CLI did not finish within {seconds}s while the lock was held: "
                "the lock blocks instead of reporting a conflict"
            )
        return outcome["code"], outcome["stderr"]

    def published(self):
        return json.loads(self.state_path.read_text())

    def test_a_dhcp4_change_publishes_the_resolvers_the_lease_named(self):
        code, _, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1 192.168.1.2",
            )
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual(data["interface"], "enp3s0")
        self.assertEqual(data["connection_uuid"], UUID)
        self.assertEqual(data["upstreams"], ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(data["source"], "dhcp4")
        self.assertEqual(data["generation"], 1)
        self.assertTrue(data["last_good"])

    def test_a_dhcp6_change_records_the_dhcp6_source(self):
        code, _, _ = self.call(
            self.event(
                "dhcp6-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP6_DOMAIN_NAME_SERVERS="fd00::1",
            )
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("dhcp6", ["fd00::1"]))

    def test_an_up_event_records_the_networkmanager_source(self):
        code, _, _ = self.call(
            self.event(
                "up",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.published()["source"], "networkmanager")

    def test_a_dns_change_event_collects_and_records_the_networkmanager_source(self):
        code, _, _ = self.call(
            self.event(
                "dns-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["source"], data["upstreams"]), ("networkmanager", ["192.168.1.1"]))

    def test_a_down_event_disables_the_interface_without_running_a_command(self):
        code, _, runner = self.call(
            self.event("down", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID)
        )
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [])
        data = self.published()
        self.assertEqual(data["upstreams"], [])
        self.assertFalse(data["last_good"])
        self.assertEqual(data["source"], "down")
        self.assertEqual(data["connection_uuid"], UUID)

    def test_a_down_event_after_a_lease_disables_the_previous_resolvers(self):
        self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        code, _, _ = self.call(self.event("down", DEVICE_IP_IFACE=INTERFACE))
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["upstreams"], data["last_good"], data["generation"]), ([], False, 2))

    def test_an_event_with_no_usable_dns_publishes_a_disabled_state(self):
        code, _, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="127.0.0.53",
            )
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["upstreams"], data["last_good"]), ([], False))

    def test_the_observation_time_is_the_time_of_the_event(self):
        self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        observed = datetime.datetime.strptime(
            self.published()["observed_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=datetime.timezone.utc)
        self.assertLess(
            abs(datetime.datetime.now(datetime.timezone.utc) - observed),
            datetime.timedelta(minutes=1),
        )

    def test_an_unchanged_renewal_exits_zero_without_rewriting_the_state(self):
        environment = self.event(
            "dhcp4-change",
            DEVICE_IP_IFACE=INTERFACE,
            CONNECTION_UUID=UUID,
            DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
        )
        self.assertEqual(self.call(environment)[0], 0)
        original = self.state_path.read_bytes()
        before = self.state_path.stat()
        code, _, _ = self.call(environment)
        self.assertEqual(code, 0)
        self.assertEqual(self.state_path.read_bytes(), original)
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)

    def test_a_changed_lease_advances_the_generation(self):
        self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        code, _, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.53",
            )
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["generation"], data["upstreams"]), (2, ["192.168.1.53"]))

    def test_an_unsupported_action_writes_nothing_and_exits_zero(self):
        for action in ["connectivity-change", "hostname", "vpn-up", "reapply", "device-removed"]:
            with self.subTest(action=action):
                if self.state_path.exists():
                    self.state_path.unlink()
                code, _, runner = self.call(
                    self.event(
                        action,
                        NM_DISPLAY_NAME="Home Wi-Fi",
                        DEVICE_IP_IFACE="enp3s0;id",
                        DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
                    )
                )
                self.assertEqual(code, 0)
                self.assertEqual(runner.calls, [])
                self.assertFalse(self.state_path.exists())

    def test_a_missing_or_empty_dispatcher_action_is_invalid_input(self):
        for env in [{"DEVICE_IP_IFACE": INTERFACE}, self.event("", DEVICE_IP_IFACE=INTERFACE)]:
            with self.subTest(env=env):
                code, stderr, _ = self.call(env)
                self.assertEqual(code, 2)
                self.assertIn("NM_DISPATCHER_ACTION", stderr)
                self.assertFalse(self.state_path.exists())

    def test_the_ip_iface_variable_names_the_interface_in_preference_to_the_others(self):
        code, _, _ = self.call(
            self.event(
                "up",
                DEVICE_IP_IFACE="enp3s0",
                INTERFACE="br-lan",
                DEVICE="eth9",
                NM_DISPLAY_NAME="Home Wi-Fi 5G",
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.published()["interface"], "enp3s0")

    def test_the_interface_falls_back_to_the_dispatcher_interface_then_device(self):
        for variables, expected in [
            ({"DEVICE_IP_IFACE": "", "INTERFACE": "br-lan", "DEVICE": "eth9"}, "br-lan"),
            ({"DEVICE_IP_IFACE": "", "INTERFACE": "", "DEVICE": "eth9"}, "eth9"),
            ({"INTERFACE": "br-lan", "DEVICE": "eth9"}, "br-lan"),
        ]:
            with self.subTest(variables=variables):
                code, _, _ = self.call(
                    self.event(
                        "up",
                        CONNECTION_UUID=UUID,
                        DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
                        **variables,
                    )
                )
                self.assertEqual(code, 0)
                self.assertEqual(self.published()["interface"], expected)

    def test_a_display_name_is_never_used_as_an_interface(self):
        for action in ["up", "down"]:
            with self.subTest(action=action):
                code, stderr, runner = self.call(
                    self.event(action, NM_DISPLAY_NAME="Home Wi-Fi 5G", CONNECTION_UUID=UUID)
                )
                self.assertEqual(code, 2)
                self.assertIn("interface", stderr)
                self.assertEqual(runner.calls, [])
                self.assertFalse(self.state_path.exists())

    def test_an_unusable_interface_is_invalid_input_on_every_collecting_path(self):
        for action, variables in [
            ("up", {}),
            ("dhcp4-change", {"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1"}),
            ("down", {}),
        ]:
            with self.subTest(action=action):
                code, stderr, runner = self.call(
                    self.event(
                        action,
                        DEVICE_IP_IFACE="enp3s0;id",
                        NM_DISPLAY_NAME="Home Wi-Fi 5G",
                        CONNECTION_UUID=UUID,
                        **variables,
                    )
                )
                self.assertEqual(code, 2)
                self.assertIn("enp3s0;id", stderr)
                self.assertEqual(runner.calls, [])
                self.assertFalse(self.state_path.exists())

    def test_a_connection_uuid_the_router_never_wrote_is_invalid_input(self):
        code, stderr, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID="not-a-uuid",
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        self.assertEqual(code, 2)
        self.assertIn("not-a-uuid", stderr)
        self.assertFalse(self.state_path.exists())

    def test_a_corrupt_state_exits_four_and_keeps_the_file(self):
        self.state_path.write_text("{")
        code, stderr, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            )
        )
        self.assertEqual(code, 4)
        self.assertIn("dhcp-upstreams.json", stderr)
        self.assertEqual(self.state_path.read_text(), "{")

    def test_a_lock_conflict_exits_three_and_keeps_the_state(self):
        environment = self.event(
            "dhcp4-change",
            DEVICE_IP_IFACE=INTERFACE,
            CONNECTION_UUID=UUID,
            DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
        )
        self.call(environment)
        original = self.state_path.read_bytes()
        descriptor = os.open(str(self.lock_path), os.O_CREAT | os.O_RDONLY, 0o640)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, stderr = self.call_while_held(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.53",
            )
        )
        self.assertEqual(code, 3)
        self.assertIn("lock", stderr)
        self.assertEqual(self.state_path.read_bytes(), original)

    def test_unusable_command_line_arguments_exit_two(self):
        environment = self.event("up", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID)
        for argv in [
            [],
            ["--state-file", str(self.state_path)],
            ["--lock-file", str(self.lock_path)],
            self.argv() + ["--state-file", str(self.state_path)],
            ["--state-file", str(self.state_path), "--lock-file"],
            ["--state-file", "", "--lock-file", str(self.lock_path)],
            ["--state-file", str(self.state_path), "--lock-file", ""],
            self.argv() + ["--verbose"],
            self.argv() + ["extra"],
            ["-s", str(self.state_path), "-l", str(self.lock_path)],
        ]:
            with self.subTest(argv=argv):
                code, stderr, _ = self.call(environment, argv=argv)
                self.assertEqual(code, 2)
                self.assertNotEqual(stderr, "")
                self.assertFalse(self.state_path.exists())

    def test_a_successful_event_writes_nothing_to_the_dispatcher_streams(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(
                self.argv(),
                self.event(
                    "dhcp4-change",
                    DEVICE_IP_IFACE=INTERFACE,
                    CONNECTION_UUID=UUID,
                    DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
                ),
                RecordingRunner(),
            )
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_a_total_source_failure_preserves_the_published_state(self):
        environment = self.event(
            "dhcp4-change",
            DEVICE_IP_IFACE=INTERFACE,
            CONNECTION_UUID=UUID,
        )
        self.assertEqual(self.call(environment)[0], 0)
        original = self.state_path.read_bytes()
        before = self.state_path.stat()
        code, stderr, runner = self.call(environment, runner=BrokenRunner())
        self.assertEqual(code, 4)
        self.assertEqual(self.state_path.read_bytes(), original)
        self.assertEqual(self.state_path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(self.state_path.stat().st_ino, before.st_ino)
        self.assertEqual(
            runner.calls,
            [
                ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE),
                ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE),
                ("nmcli", "-g", "IP4.DNS", "device", "show", INTERFACE),
                ("nmcli", "-g", "IP6.DNS", "device", "show", INTERFACE),
                ("resolvectl", "dns", INTERFACE),
            ],
        )
        self.assertIn("source", stderr)

    def test_a_total_source_failure_on_a_first_event_writes_nothing(self):
        code, stderr, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
            ),
            runner=BrokenRunner(),
        )
        self.assertEqual(code, 4)
        self.assertFalse(self.state_path.exists())
        self.assertFalse(self.lock_path.exists())

    def test_the_source_failure_diagnostic_leaks_no_address_or_environment_value(self):
        code, stderr, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="127.0.0.53",
            ),
            runner=BrokenRunner(),
        )
        self.assertEqual(code, 4)
        for secret in ["127.0.0.53", UUID, INTERFACE, "Could not connect to the system bus"]:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, stderr)

    def test_a_broken_command_is_not_a_source_failure_when_the_event_names_dns(self):
        """The event's own variables answer without a command, so this is not 4."""
        code, _, runner = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="192.168.1.1",
            ),
            runner=BrokenRunner(),
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.published()["upstreams"], ["192.168.1.1"])
        self.assertEqual(
            runner.calls,
            [
                ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE),
                ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE),
            ],
        )

    def test_a_readable_but_empty_source_publishes_a_disabled_generation(self):
        code, _, _ = self.call(
            self.event(
                "dhcp4-change",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
            )
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["upstreams"], data["last_good"]), ([], False))
        self.assertEqual(data["generation"], 1)

    def test_a_failure_before_a_readable_empty_source_still_publishes_a_disabled_generation(self):
        runner = RecordingRunner(
            failures={
                ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE): OSError(
                    "nmcli"
                ),
                ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE): OSError(
                    "nmcli"
                ),
            }
        )
        code, _, _ = self.call(
            self.event("dhcp4-change", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID),
            runner=runner,
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["upstreams"], data["last_good"]), ([], False))

    def test_a_readable_source_survives_a_later_source_failure(self):
        runner = RecordingRunner(
            failures={
                ("nmcli", "-g", "IP4.DNS", "device", "show", INTERFACE): OSError("nmcli"),
                ("nmcli", "-g", "IP6.DNS", "device", "show", INTERFACE): OSError("nmcli"),
                ("resolvectl", "dns", INTERFACE): OSError("resolvectl"),
            }
        )
        code, _, _ = self.call(
            self.event("dhcp4-change", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID),
            runner=runner,
        )
        self.assertEqual(code, 0)
        data = self.published()
        self.assertEqual((data["upstreams"], data["last_good"]), ([], False))

    def test_a_down_event_never_consults_a_broken_source(self):
        code, _, runner = self.call(
            self.event("down", DEVICE_IP_IFACE=INTERFACE, CONNECTION_UUID=UUID),
            runner=BrokenRunner(),
        )
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [])
        data = self.published()
        self.assertEqual((data["upstreams"], data["last_good"]), ([], False))

    def test_the_collector_is_asked_about_the_event_interface(self):
        _, _, runner = self.call(
            self.event("up", DEVICE_IP_IFACE="br-lan", CONNECTION_UUID=UUID)
        )
        self.assertEqual(
            runner.calls,
            [
                ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", "br-lan"),
                ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", "br-lan"),
                ("nmcli", "-g", "IP4.DNS", "device", "show", "br-lan"),
                ("nmcli", "-g", "IP6.DNS", "device", "show", "br-lan"),
                ("resolvectl", "dns", "br-lan"),
            ],
        )

    def test_the_collector_reads_the_raw_lease_before_the_effective_dns(self):
        runner = RecordingRunner(
            {
                ("nmcli", "-g", "IP4.DNS", "device", "show", INTERFACE): "192.168.1.9",
                ("nmcli", "-g", "IP6.DNS", "device", "show", INTERFACE): "fd00::9",
                ("resolvectl", "dns", INTERFACE): "192.168.1.8",
            }
        )
        code, _, _ = self.call(
            self.event(
                "up",
                DEVICE_IP_IFACE=INTERFACE,
                CONNECTION_UUID=UUID,
                DHCP4_DOMAIN_NAME_SERVERS="127.0.0.53",
            ),
            runner=runner,
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.published()["upstreams"], ["192.168.1.9", "fd00::9"])

    def test_console_entry_runs_with_the_process_environment(self):
        environment = {
            "NM_DISPATCHER_ACTION": "dhcp4-change",
            "DEVICE_IP_IFACE": INTERFACE,
            "CONNECTION_UUID": UUID,
            "DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1",
        }
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            sys, "argv", ["mosdns-dhcp-bridge"] + self.argv()
        ):
            with mock.patch.object(cli, "real_runner", RecordingRunner()):
                code = cli.console_entry()
        self.assertEqual(code, 0)
        self.assertEqual(self.published()["upstreams"], ["192.168.1.1"])


class RealCommandRunnerTests(unittest.TestCase):
    """The process boundary the collector depends on when it is not injected."""

    def python(self, source, *arguments):
        return [sys.executable, "-c", source, *arguments]

    def test_it_returns_the_standard_output_of_an_argument_array(self):
        self.assertEqual(
            cli.real_runner(self.python("print('192.168.1.1')")),
            "192.168.1.1\n",
        )

    def test_a_shell_metacharacter_in_an_argument_reaches_the_command_verbatim(self):
        """A shell would run ``id`` here and print nothing but its own output."""
        self.assertEqual(
            cli.real_runner(self.python("import sys; print(sys.argv[1])", "enp3s0;id")),
            "enp3s0;id\n",
        )

    def test_a_failed_command_is_reported_to_the_caller(self):
        with self.assertRaises(subprocess.CalledProcessError):
            cli.real_runner(self.python("raise SystemExit(4)"))

    def test_a_command_that_hangs_is_abandoned(self):
        with mock.patch.object(cli, "COMMAND_TIMEOUT_SECONDS", 0.25):
            with self.assertRaises(subprocess.TimeoutExpired):
                cli.real_runner(self.python("import time; time.sleep(30)"))

    def test_a_missing_command_is_reported_to_the_caller(self):
        with self.assertRaises(OSError):
            cli.real_runner(["/nonexistent/mosdns-bridge-command"])


@contextlib.contextmanager
def _umask(mask):
    """Run a block with a process-wide umask, restoring it afterwards."""
    previous = os.umask(mask)
    try:
        yield
    finally:
        os.umask(previous)


if __name__ == "__main__":
    unittest.main()
