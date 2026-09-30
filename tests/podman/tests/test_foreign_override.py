"""The foreign override: a substitution, held to being nothing but a substitution.

The plan's Task 4 Step 5 makes a foreign answer reachable by rewriting the
resolver document inside the target, and this file is what stops that rewrite
becoming a second place this project's resolver policy is stated. The property is
narrow and it is the whole of the module's value:

    the override differs from `/etc/mosdns/dnscrypt-proxy.toml` in its stamps and
    in nothing else.

Everything else in the document -- `require_dnssec`, `require_nofilter`,
`listen_addresses`, `netprobe_address` and its timeout, the cache setting, the
bootstrap resolvers, the four clauses of the generated header -- is a decision
this project ships, and Task 5's scenarios are about those decisions. An override
that also relaxed one of them would produce a cell in which the packaged resolver
was configured by the test, and the routing counters in Task 4 Step 6 would be
counting a resolver nobody shipped.

The other half is that the override must be *complete*: every `[static.*]` table
replaced, so the document cannot still carry a Quad9 resolver that a cell with no
route to the internet would fail on for a reason the evidence document would not
describe.
"""

import base64
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCENARIOS = REPO / "tests" / "podman" / "scenarios"
sys.path.insert(0, str(SCENARIOS))

import foreign_override  # noqa: E402

# The repository's own shipped document, read rather than written down here. A
# literal copy would let a re-render and this file disagree while every assertion
# below still passed -- which is the defect the install scenario's own comment
# about reading the shipped pin rather than remembering it names.
SHIPPED = (REPO / "configs" / "dnscrypt-proxy.toml").read_text(encoding="utf-8")

ADDRESS = "10.89.0.40:443"
PROVIDER = "2.dnscrypt-cert." + foreign_override.STATIC_NAME


def dnscrypt_stamp(address: str = ADDRESS, provider: str = PROVIDER,
                   provider_key: bytes = bytes(range(32)), props: int = 0b011) -> str:
    """A real DNSCrypt stamp, built the way go-dnsstamps builds one.

    **Constructed rather than pasted, and that is the point.** The module's job
    includes checking that a stamp carries a provider name, and a pasted literal
    would be a base64 blob the check could only satisfy by accident -- or, worse,
    could fail on, since the provider name is inside the encoding and not visible
    in the text. So the fixture is assembled from the documented layout:

    ```text
    id(0x01) props(8) addrLen(1) addr pkLen(1) pk(32) nameLen(1) name
    ```

    with `props` little endian, and then base64url-encoded without padding. The
    proto byte is 0x01 (DNSCrypt), the key is 32 bytes, and the properties are
    DNSSEC and NoLog -- the two the shipped document requires, so the fixture is a
    stamp the shipped resolver would actually accept.
    """
    blob = b"\x01" + props.to_bytes(8, "little")
    blob += bytes([len(address)]) + address.encode()
    blob += bytes([len(provider_key)]) + provider_key
    blob += bytes([len(provider)]) + provider.encode()
    return "sdns://" + base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")


def decoded_stamp(stamp: str) -> dict:
    """The fields of a stamp, read back the way a client reads it.

    So a case can assert on the provider name as a *name* rather than as a
    substring of base64 that happens to be there.
    """
    blob = base64.urlsafe_b64decode(stamp.removeprefix("sdns://") + "==")
    address_length = blob[9]
    address = blob[10 : 10 + address_length].decode()
    cursor = 10 + address_length
    key_length = blob[cursor]
    key = blob[cursor + 1 : cursor + 1 + key_length]
    cursor += 1 + key_length
    name_length = blob[cursor]
    return {
        "proto": blob[0],
        "props": int.from_bytes(blob[1:9], "little"),
        "address": address,
        "key": key,
        "provider": blob[cursor + 1 : cursor + 1 + name_length].decode(),
        "trailing": blob[cursor + 1 + name_length :],
    }


STAMP = dnscrypt_stamp()


class TheOverrideIsASubstitutionTest(unittest.TestCase):
    def override(self, **kwargs):
        arguments = {"stamp": STAMP, "address": ADDRESS}
        arguments.update(kwargs)
        return foreign_override.build_override(SHIPPED, **arguments)

    def test_the_shipped_document_declares_the_stamps_this_module_replaces(self):
        """The premise, asserted so a re-render that changed it is a loud failure.

        Three Quad9 tables, three stamps, and a `server_names` that selects them.
        A document with none of those is a document the override cannot be
        derived from, and the cases below would be asserting against a fixture
        that is not the shipped thing.
        """
        self.assertEqual(
            foreign_override.static_names(SHIPPED),
            [
                "quad9-dnscrypt-ip4-filter-1",
                "quad9-dnscrypt-ip4-filter-2",
                "quad9-dnscrypt-ip4-filter-3",
            ],
            "the shipped document's static tables changed; every case in this file is "
            "written against this list",
        )
        names = foreign_override.SERVER_NAMES.search(SHIPPED)
        self.assertIsNotNone(names, "the shipped document has no `server_names` line")
        for table in foreign_override.static_names(SHIPPED):
            self.assertIn(table, names.group(1))

    def test_it_changes_the_stamps_and_nothing_else(self):
        """**The property the module exists for.**"""
        foreign_override.assert_only_stamps_changed(SHIPPED, self.override())

    def test_every_stamp_is_replaced_and_none_is_left_behind(self):
        """Completeness, which is a different failure from tidiness.

        One table left naming Quad9 is a document that still has a real foreign
        upstream: `server_names` would name it, the resolver would select it, and
        a cell with no route to the internet would fail its barrier -- for a
        reason the evidence document would not describe, because the document
        looks right.
        """
        override = self.override()
        self.assertEqual(
            foreign_override.static_names(override),
            [foreign_override.STATIC_NAME] * 3,
            "the override did not rename every static table to the mock's",
        )
        # The selection has to move with the tables, and that is the half a
        # substitution that rewrote only the definitions would get wrong: the
        # document would still load, and the resolver would still bind 15353, and
        # it would still answer nothing -- because the names it selects are Quad9's.
        self.assertEqual(
            foreign_override.selected_names(override),
            [foreign_override.STATIC_NAME] * 3,
            "the override's server_names still selects a resolver it does not define",
        )
        # Read on the *lines* rather than the whole text, because the shipped
        # document's own generated header explains what the stamps are and says
        # Quad9 in doing so. A check on the whole text would fail on the prose the
        # project shipped, which is exactly the mistake several of this project's
        # own cases warn about.
        self.assertNotIn(
            "quad9-dnscrypt-ip4-filter",
            " ".join(
                line for line in override.splitlines() if not line.strip().startswith("#")
            ),
            "the override still names a Quad9 resolver in an instruction, so the resolver "
            "it selects is a real one this cell cannot reach",
        )
        stamps = []
        for line in override.splitlines():
            match = foreign_override.STAMP_ASSIGNMENT.match(line.strip())
            if match is not None:
                stamps.append(match.group(2))
        self.assertEqual(
            stamps,
            [STAMP] * 3,
            f"the override's stamps are not all the mock's: {stamps}",
        )

    def test_the_stamp_names_the_provider_the_mock_publishes(self):
        """The stamp and the certificate have to agree, and nothing else enforces it.

        dnscrypt-proxy fetches a DNSCrypt resolver's certificate by querying
        `2.dnscrypt-cert.<the stamp's provider name>`, so a stamp carrying Quad9's
        provider name against a mock that publishes its certificate under a
        different one produces a resolver that never gets a certificate -- and
        answers nothing, silently, which is the shape of the failure the install
        transaction reports as its own foreign-resolver barrier.

        The provider name is *inside* the base64, so the assertion decodes the
        stamp rather than searching its text: a substring check on base64 would be
        satisfied or failed by accident.
        """
        fields = decoded_stamp(STAMP)
        self.assertEqual(
            fields["provider"],
            foreign_override.PROVIDER_PREFIX + foreign_override.STATIC_NAME,
            "the fixture stamp names a provider the mock does not publish a certificate for",
        )
        self.assertEqual(fields["proto"], 0x01, "the fixture is not a DNSCrypt stamp")
        self.assertEqual(fields["address"], ADDRESS)
        self.assertEqual(len(fields["key"]), 32, "a DNSCrypt stamp carries a 32-byte provider key")
        # And a stamp naming a *different* provider is refused, which is the case
        # that would otherwise reach a cell and fail there for a reason nothing in
        # the evidence document would describe. Quad9's real provider name, from
        # the shipped document, so the case is the mistake a cell would actually
        # make: reusing a shipped stamp and changing only its address.
        with self.assertRaises(foreign_override.OverrideError) as raised:
            self.override(stamp=dnscrypt_stamp(provider="2.dnscrypt-cert.quad9-dnscrypt-ip4-filter-1"))
        message = str(raised.exception)
        self.assertIn("provider name", message)
        self.assertIn("foreign-resolver barrier", message)
        self.assertIn("2.dnscrypt-cert.quad9-dnscrypt-ip4-filter-1", message)

    def test_a_stamp_that_is_not_a_dnscrypt_one_is_refused(self):
        """A stamp this module cannot read is a stamp it cannot check, so it refuses.

        The plain-DNS stamp shape go-dnsstamps also parses (proto byte 0x00) is
        the realistic version: it has an address and no provider, so a naive check
        would write it into the document and the resolver would find no
        certificate. `dnscrypt-proxy` 2.1.18 would not even select it -- its
        `fetchServerInfo` handles DNSCrypt, DoH and ODoH -- so the cell would stop
        at the transaction's barrier with a document that looks right.
        """
        for stamp, what in (
            ("sdns://" + base64.urlsafe_b64encode(b"\x00" + bytes(8) + bytes([9]) + b"10.89.0.40:443").decode().rstrip("="),
             "a plain-DNS stamp"),
            ("not a stamp at all", "text that is not a stamp"),
            ("sdns://!!!!", "base64 that is not base64"),
            ("sdns://", "a stamp with no payload at all"),
        ):
            with self.subTest(stamp=what):
                self.assertIsNone(foreign_override.stamp_provider_name(stamp))
                with self.assertRaises(foreign_override.OverrideError) as raised:
                    self.override(stamp=stamp)
                self.assertIn("not a DNSCrypt stamp", str(raised.exception))

    def test_the_shipped_settings_survive_byte_for_byte(self):
        """Named, one by one, because "nothing else changed" is easier to believe
        than to read.

        Each of these is a decision this project ships and a later task's scenario
        is about: which resolvers may be used, whether the resolver binds a port
        at all, how long a machine with no route waits before binding, and whether
        the resolver keeps a cache of the user's names. A list of them in the
        failure message is what a reader needs when one of them goes missing.
        """
        override = self.override()
        for needle, what in (
            ("require_dnssec = true", "which resolvers may be used at all"),
            ("require_nolog = true", "the no-log promise a resolver must make"),
            ("require_nofilter = false", "whether an unfiltered resolver is refused"),
            ("ignore_system_dns = true", "that the bootstrap list is the only one used"),
            ("cache = false", "that the resolver keeps no cache of the user's names"),
            ("netprobe_address", "the address the reachability probe uses"),
            ("netprobe_timeout", "how long that probe may take"),
            (foreign_override.SHIPPED_LISTENER, "the listener the transaction's barrier waits on"),
        ):
            with self.subTest(setting=needle):
                self.assertIn(needle, override, f"the override dropped {needle}, which is {what}")

    def test_the_listener_is_carried_over_unchanged(self):
        """The one line where a change would stop the install for a new reason.

        The transaction's own barrier is `wait_for_dns(127.0.0.1, 15353)`. An
        override that moved the listener would leave the transaction stopping at a
        barrier nobody is measuring, and the evidence document would describe a
        resolver barrier that is not this one.
        """
        shipped = foreign_override.LISTEN_ADDRESSES.search(SHIPPED).group(1)
        override = foreign_override.LISTEN_ADDRESSES.search(self.override()).group(1)
        self.assertEqual(override, shipped)
        self.assertIn(foreign_override.SHIPPED_LISTENER, override)

    def test_the_override_is_a_document_dnscrypt_proxy_would_load(self):
        """Every table has a stamp, and `server_names` selects them all.

        The structural property `dnscrypt-proxy` itself relies on: a `[static.*]`
        entry with no `stamp =` is a refusal at load, and a `server_names` entry
        with no table is a resolver that does not exist. Both produce a resolver
        that binds its listener and answers nothing, which is the failure mode this
        whole file exists to rule out.
        """
        override = self.override()
        blocks = re.split(r"^\[", override, flags=re.MULTILINE)[1:]
        for block in blocks:
            header, _, body = block.partition("\n")
            with self.subTest(table=header.strip()):
                self.assertRegex(
                    body, r"stamp\s*=\s*'sdns://",
                    f"[{header.strip()}] has no stamp, and dnscrypt-proxy refuses the document",
                )
        selected = foreign_override.SERVER_NAMES.search(override).group(1)
        for table in foreign_override.static_names(override):
            self.assertIn(table, selected, f"[static.{table}] is not in server_names")

    def test_a_change_to_any_other_line_is_refused_and_says_which(self):
        """The control, and the reason `assert_only_stamps_changed` is not a comment.

        The same shipped document with one shipped setting altered, and the
        comparison has to catch it. A check that accepted this would be satisfied
        by an override that turned `require_dnssec` off, which is a resolver that
        would use anything it is offered.
        """
        for needle, replacement, why in (
            ("require_dnssec = true", "require_dnssec = false", "an unfiltered resolver set"),
            ("require_nofilter = false", "require_nofilter = true", "a resolver set that refuses Quad9"),
            ("cache = false", "cache = true", "a cache of the user's query names"),
            ("netprobe_timeout = 5", "netprobe_timeout = 60", "a machine with no route waiting 60s to bind"),
        ):
            with self.subTest(setting=needle):
                altered = SHIPPED.replace(needle, replacement)
                self.assertNotEqual(altered, SHIPPED, f"{needle} is not in the shipped document")
                with self.assertRaises(foreign_override.OverrideError) as raised:
                    foreign_override.assert_only_stamps_changed(altered, self.override())
                self.assertIn("not part of the stamp substitution", str(raised.exception))
                self.assertIn(why.split()[0], str(raised.exception).lower() + why.lower())

    def test_a_moved_listener_is_refused_by_its_own_message(self):
        """The listener gets its own refusal, because it has its own consequence.

        A check that folded the listener into "a line that is not a stamp" would
        still refuse it, and the message would not say what the refusal means: that
        the transaction would stop at a port nobody is waiting on.
        """
        altered = SHIPPED.replace(
            foreign_override.SHIPPED_LISTENER, "127.0.0.1:15354"
        )
        with self.assertRaises(foreign_override.OverrideError) as raised:
            foreign_override.assert_only_stamps_changed(altered, self.override())
        self.assertIn("listen_addresses", str(raised.exception))
        self.assertIn("127.0.0.1:15353", str(raised.exception))

    def test_an_added_line_is_refused_as_well_as_a_changed_one(self):
        """The other direction, and it is the one a hand-written document has.

        A hand-written override would almost certainly *add* a line -- a comment
        header, a `[static]` entry for a fourth resolver, a setting nobody
        remembered the shipped document already had. An added line is a setting
        this project did not ship, and it is refused with its own message rather
        than by a length comparison the reader has to interpret.
        """
        with self.assertRaises(foreign_override.OverrideError) as raised:
            foreign_override.assert_only_stamps_changed(
                SHIPPED, self.override() + "\nsomething_the_shipped_document_does_not_say = true\n"
            )
        self.assertIn("added or removed", str(raised.exception))
        self.assertIn("this project did not ship", str(raised.exception))


class TheOverrideIsCompleteOrRefusedTest(unittest.TestCase):
    """The inputs it refuses, because each is a cell that would fail for a reason
    the evidence document would not describe."""

    def override(self, shipped=SHIPPED, **kwargs):
        arguments = {"stamp": STAMP, "address": ADDRESS}
        arguments.update(kwargs)
        return foreign_override.build_override(shipped, **arguments)

    def test_no_stamp_is_refused(self):
        with self.assertRaises(foreign_override.OverrideError) as raised:
            self.override(stamp="")
        self.assertIn("published no stamp", str(raised.exception))

    def test_no_address_is_refused(self):
        with self.assertRaises(foreign_override.OverrideError) as raised:
            self.override(address="")
        self.assertIn("no address", str(raised.exception))

    def test_a_document_with_no_static_table_is_refused(self):
        """Not an empty override -- a refusal, because an empty one is a document
        the resolver loads and then has no upstream, and a cell would spend sixty
        seconds at the transaction's barrier for that."""
        with self.assertRaises(foreign_override.OverrideError) as raised:
            self.override(shipped="listen_addresses = ['127.0.0.1:15353']\n")
        self.assertIn("declares no `[static.*]` table", str(raised.exception))

    def test_a_table_with_no_stamp_is_refused(self):
        # A hand-edited document, which is the realistic way to get here: a table
        # header added without its stamp line, and the selection left alone so the
        # two halves still agree on the count -- otherwise this case would pass
        # for a different reason than the one it is about.
        broken = SHIPPED.replace(
            "server_names = ['quad9-dnscrypt-ip4-filter-1', 'quad9-dnscrypt-ip4-filter-2', 'quad9-dnscrypt-ip4-filter-3']",
            "server_names = ['quad9-dnscrypt-ip4-filter-1', 'quad9-dnscrypt-ip4-filter-2', "
            "'quad9-dnscrypt-ip4-filter-3', 'a-table-with-no-stamp']",
        ) + "\n[static.a-table-with-no-stamp]\n"
        self.assertEqual(len(foreign_override.static_names(broken)), 4, "the fixture is not the shape this case needs")
        with self.assertRaises(foreign_override.OverrideError) as raised:
            self.override(shipped=broken)
        self.assertIn("has no `stamp =` line", str(raised.exception))

    def test_a_selection_that_does_not_match_the_definitions_is_refused(self):
        """The shipped document in a state this project does not render.

        It is here because `build_override` preserves the ratio between the
        selection and the definitions, and preserving a ratio in a document whose
        two halves already disagree produces an override that disagrees in a new
        way. A refusal is better than a document that loads and answers nothing.
        """
        broken = re.sub(
            r"^server_names\s*=\s*\[[^\]]*\]",
            "server_names = ['quad9-dnscrypt-ip4-filter-1']",
            SHIPPED,
            flags=re.MULTILINE,
        )
        self.assertNotEqual(broken, SHIPPED, "the selection could not be rewritten")
        with self.assertRaises(foreign_override.OverrideError) as raised:
            self.override(shipped=broken)
        self.assertIn("does not define every resolver it selects", str(raised.exception))

    def test_the_override_keeps_the_documents_own_trailing_newline(self):
        """Both ways, because the file is a conffile dpkg compares by digest.

        A file that gained or lost its final newline is a different file with a
        different sha256, and dpkg's conffile machinery is byte-oriented -- so a
        rewrite that normalises the ending would look like an operator's edit to
        every later upgrade.
        """
        self.assertTrue(self.override().endswith("\n"))
        self.assertFalse(
            self.override(shipped=SHIPPED.rstrip("\n")).endswith("\n"),
            "a document with no trailing newline produced one that has",
        )


if __name__ == "__main__":
    unittest.main()
