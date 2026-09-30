"""Tests for collecting router-supplied DHCP DNS from NetworkManager.

The collector is the only component allowed to ask NetworkManager and resolved
what DNS the router was told to use, so these tests pin the five things a
domestic query depends on: which source wins, which addresses a source may
contribute, which interface name may be asked about, that a source that could not
be read is reported instead of becoming an empty lease, and that no command is
ever handed a shell string.
"""

import sys
import unittest
from pathlib import Path

# The bridge package is used from a source checkout, not from an installed
# distribution, so the repository's bridge directory is the import root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mosdns_dhcp_bridge.collect import (
    SourcesUnavailable,
    collect_dns,
    collect_dns_with_source,
)

INTERFACE = "enp3s0"

# The exact argument arrays the collector may build for one interface. DHCP4 and
# DHCP6 are read separately because a colon is both nmcli's field separator and
# part of every IPv6 address.
# **The fields are `DHCP4.OPTION` and `DHCP6.OPTION`, and that is MEASURED, not
# chosen.** nmcli 1.42.4 inside a configured 24.04 target answers
#
#     $ nmcli -g DHCP4.OPTION_DOMAIN_NAME_SERVERS device show eth0
#     Error: 'device show': invalid field 'DHCP4.OPTION_DOMAIN_NAME_SERVERS';
#     allowed fields: DHCP4.OPTION
#
# with exit 2 and no output -- and the whole lease is in the `key = value |`
# list the allowed field prints. These two names were the wrong ones, so the
# collector's highest-priority source was unreadable on every release, and the
# fixture in this file asked the same wrong question, which is why 36 green
# cases agreed with the code and neither agreed with nmcli. See
# `NmcliFieldNameTests`, which holds the command.
RAW_DHCP4 = ("nmcli", "-g", "DHCP4.OPTION", "device", "show", INTERFACE)
RAW_DHCP6 = ("nmcli", "-g", "DHCP6.OPTION", "device", "show", INTERFACE)
EFFECTIVE_IP4 = ("nmcli", "-g", "IP4.DNS", "device", "show", INTERFACE)
EFFECTIVE_IP6 = ("nmcli", "-g", "IP6.DNS", "device", "show", INTERFACE)
RESOLVECTL = ("resolvectl", "dns", INTERFACE)
ALL_COMMANDS = (RAW_DHCP4, RAW_DHCP6, EFFECTIVE_IP4, EFFECTIVE_IP6, RESOLVECTL)


def option_line(resolvers, **extra):
    """A `DHCPn.OPTION` answer in the shape nmcli really prints it.

    **The first version of this fixture handed the collector a bare address**,
    which is what the code asked for while it asked for a field nmcli does not
    have -- so the fixture and the code agreed with each other and neither agreed
    with the program. nmcli prints the whole lease as `key = value | key = value`
    and the resolvers are the `domain_name_servers` key inside it, so that is what
    a case supplies now. `extra` adds sibling keys a real lease carries, because
    the parser has to skip them and a fixture with no siblings cannot show that it
    does.
    """
    keys = [f"{key} = {value}" for key, value in extra.items()]
    keys.append(f"domain_name_servers = {resolvers}")
    keys.append("subnet_mask = 255.255.255.0")
    return " | ".join(keys) + "\n"


def quiet_outputs(answers):
    """Return one output per known command, defaulting to an empty answer."""
    outputs = {command: "" for command in ALL_COMMANDS}
    outputs.update(answers)
    return outputs


def silent():
    """Return a runner that reports success with no output for every command."""
    return lambda args: ""


class FakeRunner:
    """A command runner double that answers exact argument arrays.

    Only an argument array the test prepared produces output, so a command the
    collector must not run -- or one it built with the wrong arguments --
    answers empty and is visible in the recorded calls.
    """

    def __init__(self, outputs=None, failures=None):
        self._outputs = dict(outputs or {})
        self._failures = dict(failures or {})
        self.calls = []

    def __call__(self, args):
        if not isinstance(args, (list, tuple)):
            raise TypeError("a command must be an argument array, not a shell string")
        command = tuple(args)
        self.calls.append(command)
        if command in self._failures:
            raise self._failures[command]
        return self._outputs.get(command, "")


class SourcePriorityTests(unittest.TestCase):
    def test_prefers_the_raw_nm_dhcp_fields_over_every_other_source(self):
        runner = FakeRunner(
            quiet_outputs(
                {
                    RAW_DHCP4: option_line("192.168.1.1"),
                    EFFECTIVE_IP4: "127.0.0.53",
                    EFFECTIVE_IP6: "127.0.0.53",
                    RESOLVECTL: "127.0.0.53",
                }
            )
        )
        got = collect_dns(
            {
                "DHCP4_DOMAIN_NAME_SERVERS": "10.0.0.53",
                "DHCP6_DOMAIN_NAME_SERVERS": "fd00::53",
            },
            INTERFACE,
            runner,
        )
        self.assertEqual(got, ["192.168.1.1"])
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])

    def test_reads_the_dhcp6_raw_field_when_dhcp4_offers_nothing(self):
        runner = FakeRunner(
            quiet_outputs(
                {
                    RAW_DHCP6: option_line("fd00::53"),
                    EFFECTIVE_IP4: "192.168.1.9",
                    RESOLVECTL: "192.168.1.8",
                }
            )
        )
        got = collect_dns({}, INTERFACE, runner)
        self.assertEqual(got, ["fd00::53"])
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])

    def test_uses_the_dispatcher_environment_when_the_raw_fields_are_empty(self):
        runner = FakeRunner(
            quiet_outputs({EFFECTIVE_IP4: "192.168.1.9", RESOLVECTL: "192.168.1.8"})
        )
        got = collect_dns(
            {"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.53"}, INTERFACE, runner
        )
        self.assertEqual(got, ["192.168.1.53"])
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])

    def test_uses_the_dhcp6_dispatcher_variable_of_a_dhcp6_change_event(self):
        runner = FakeRunner(quiet_outputs({EFFECTIVE_IP4: "192.168.1.9"}))
        got = collect_dns({"DHCP6_DOMAIN_NAME_SERVERS": "fd00::53"}, INTERFACE, runner)
        self.assertEqual(got, ["fd00::53"])
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])

    def test_uses_the_effective_device_dns_when_every_dhcp_source_is_empty(self):
        runner = FakeRunner(
            quiet_outputs(
                {
                    EFFECTIVE_IP4: "192.168.1.10",
                    EFFECTIVE_IP6: "fd00::10",
                    RESOLVECTL: "192.168.1.8",
                }
            )
        )
        got = collect_dns({}, INTERFACE, runner)
        self.assertEqual(got, ["192.168.1.10", "fd00::10"])
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6, EFFECTIVE_IP4, EFFECTIVE_IP6])

    def test_uses_resolvectl_only_after_every_other_source_is_empty(self):
        runner = FakeRunner(
            quiet_outputs(
                {RESOLVECTL: "Link 2 (enp3s0): 192.168.1.1\n                fd00::1"}
            )
        )
        got = collect_dns({}, INTERFACE, runner)
        self.assertEqual(got, ["192.168.1.1", "fd00::1"])
        self.assertEqual(runner.calls, list(ALL_COMMANDS))

    def test_continues_with_the_next_source_after_a_command_fails(self):
        runner = FakeRunner(
            quiet_outputs({EFFECTIVE_IP4: "192.168.1.1"}),
            failures={RAW_DHCP4: OSError("nmcli"), RAW_DHCP6: OSError("nmcli")},
        )
        got = collect_dns({}, INTERFACE, runner)
        self.assertEqual(got, ["192.168.1.1"])
        self.assertEqual(
            runner.calls, [RAW_DHCP4, RAW_DHCP6, EFFECTIVE_IP4, EFFECTIVE_IP6]
        )

    def test_a_runner_that_answers_no_string_is_not_a_readable_command(self):
        runner = FakeRunner(
            quiet_outputs(
                {
                    RAW_DHCP4: None,
                    RAW_DHCP6: None,
                    EFFECTIVE_IP4: None,
                    EFFECTIVE_IP6: None,
                    RESOLVECTL: "192.168.1.7",
                }
            )
        )
        got = collect_dns({}, INTERFACE, runner)
        self.assertEqual(got, ["192.168.1.7"])
        self.assertEqual(runner.calls, list(ALL_COMMANDS))

    def test_never_merges_a_lower_priority_source_into_a_usable_answer(self):
        runner = FakeRunner(
            quiet_outputs(
                {
                    RAW_DHCP4: option_line("192.168.1.1,192.168.1.2"),
                    EFFECTIVE_IP4: "203.0.113.9",
                    RESOLVECTL: "203.0.113.8",
                }
            )
        )
        got = collect_dns({}, INTERFACE, runner)
        self.assertEqual(got, ["192.168.1.1", "192.168.1.2"])


class SourceTokenTests(unittest.TestCase):
    """The source token names what answered, not what triggered the read.

    The published state records the source beside the addresses, and only the
    source is compared when an event decides whether it changed anything. A token
    that named the dispatcher's action would make every routine event pair a new
    generation and flush the plugin's cache for resolvers that never moved, so
    the token has to describe the source that produced the addresses.
    """

    def test_the_raw_dhcp4_field_alone_is_named_nm_dhcp4(self):
        runner = FakeRunner(quiet_outputs({RAW_DHCP4: option_line("192.168.1.1")}))
        result = collect_dns_with_source({}, INTERFACE, runner)
        self.assertEqual(result.source, "nm-dhcp4")
        self.assertEqual(result.addresses, ["192.168.1.1"])

    def test_the_raw_dhcp6_field_alone_is_named_nm_dhcp6(self):
        runner = FakeRunner(quiet_outputs({RAW_DHCP6: option_line("fd00::1")}))
        result = collect_dns_with_source({}, INTERFACE, runner)
        self.assertEqual(result.source, "nm-dhcp6")
        self.assertEqual(result.addresses, ["fd00::1"])

    def test_both_raw_dhcp_families_are_named_nm_dhcp(self):
        runner = FakeRunner(
            quiet_outputs({RAW_DHCP4: option_line("192.168.1.1"), RAW_DHCP6: option_line("fd00::1")})
        )
        result = collect_dns_with_source({}, INTERFACE, runner)
        self.assertEqual(result.source, "nm-dhcp")
        self.assertEqual(result.addresses, ["192.168.1.1", "fd00::1"])

    def test_the_family_that_answered_is_named_when_its_sibling_could_not_be_read(self):
        """One readable field still carries the lease's resolvers."""
        runner = FakeRunner(
            quiet_outputs({RAW_DHCP6: option_line("fd00::1")}), failures={RAW_DHCP4: OSError("nmcli")}
        )
        result = collect_dns_with_source({}, INTERFACE, runner)
        self.assertEqual(result.source, "nm-dhcp6")
        self.assertEqual(result.addresses, ["fd00::1"])

    def test_the_dispatcher_environment_is_named_dispatcher_env(self):
        runner = FakeRunner()
        result = collect_dns_with_source(
            {"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1"}, INTERFACE, runner
        )
        self.assertEqual(result.source, "dispatcher-env")
        self.assertEqual(result.addresses, ["192.168.1.1"])

    def test_the_effective_device_dns_is_named_nm_effective(self):
        runner = FakeRunner(
            quiet_outputs({EFFECTIVE_IP4: "192.168.1.9", EFFECTIVE_IP6: "fd00::9"})
        )
        result = collect_dns_with_source({}, INTERFACE, runner)
        self.assertEqual(result.source, "nm-effective")
        self.assertEqual(result.addresses, ["192.168.1.9", "fd00::9"])

    def test_resolvectl_is_named_resolved(self):
        runner = FakeRunner(
            quiet_outputs({RESOLVECTL: "Link 2 (enp3s0): 192.168.1.1"})
        )
        result = collect_dns_with_source({}, INTERFACE, runner)
        self.assertEqual(result.source, "resolved")
        self.assertEqual(result.addresses, ["192.168.1.1"])

    def test_an_event_naming_no_usable_resolver_falls_through_to_the_source_that_did(self):
        runner = FakeRunner(quiet_outputs({EFFECTIVE_IP4: "192.168.1.9"}))
        result = collect_dns_with_source(
            {"DHCP4_DOMAIN_NAME_SERVERS": "127.0.0.53"}, INTERFACE, runner
        )
        self.assertEqual(result.source, "nm-effective")
        self.assertEqual(result.addresses, ["192.168.1.9"])

    def test_a_readable_but_empty_lease_names_the_source_that_answered(self):
        result = collect_dns_with_source({}, INTERFACE, FakeRunner())
        self.assertEqual((result.addresses, result.source), ([], "nm-dhcp"))

    def test_a_total_failure_still_raises_and_names_no_source(self):
        with self.assertRaises(SourcesUnavailable):
            collect_dns_with_source({}, INTERFACE, broken())

    def test_the_list_wrapper_still_returns_the_addresses_only(self):
        got = collect_dns({}, INTERFACE, FakeRunner(quiet_outputs({RAW_DHCP4: option_line("192.168.1.1")})))
        self.assertIs(type(got), list)
        self.assertEqual(got, ["192.168.1.1"])


def broken():
    """Return a runner whose every command fails, the way a wedged D-Bus does."""
    return FakeRunner(
        failures={command: OSError("Could not connect to the system bus") for command in ALL_COMMANDS}
    )


class SourceFailureTests(unittest.TestCase):
    """An unreadable source is an operational failure, not an empty lease.

    A lease with no resolvers and a NetworkManager that cannot be read are
    different facts, and only the first one may publish an empty state. These
    tests pin the difference, because a single flaky query behind a five second
    timeout must never disable a working router.
    """

    def test_every_command_failing_is_not_an_empty_lease(self):
        runner = broken()
        with self.assertRaises(SourcesUnavailable):
            collect_dns({}, INTERFACE, runner)
        self.assertEqual(runner.calls, list(ALL_COMMANDS))

    def test_a_total_failure_reports_neither_an_address_nor_an_environment_value(self):
        runner = broken()
        with self.assertRaises(SourcesUnavailable) as caught:
            collect_dns(
                {
                    "DHCP4_DOMAIN_NAME_SERVERS": "127.0.0.53",
                    "DHCP6_DOMAIN_NAME_SERVERS": "127.0.0.54",
                    "CONNECTION_UUID": "11111111-1111-1111-1111-111111111111",
                },
                INTERFACE,
                runner,
            )
        message = str(caught.exception)
        for secret in [
            "127.0.0.53",
            "127.0.0.54",
            "11111111-1111-1111-1111-111111111111",
            INTERFACE,
            "Could not connect to the system bus",
        ]:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, message)

    def test_a_command_that_answers_no_string_is_not_a_readable_command(self):
        for answer in [None, 42, b"192.168.1.1\n", ["192.168.1.1"]]:
            with self.subTest(answer=answer):
                runner = FakeRunner({command: answer for command in ALL_COMMANDS})
                with self.assertRaises(SourcesUnavailable):
                    collect_dns({}, INTERFACE, runner)
                self.assertEqual(runner.calls, list(ALL_COMMANDS))

    def test_a_readable_empty_field_is_an_answer_not_a_failure(self):
        self.assertEqual(collect_dns({}, INTERFACE, FakeRunner()), [])

    def test_a_failure_before_a_readable_empty_source_is_an_empty_lease(self):
        runner = FakeRunner(
            failures={RAW_DHCP4: OSError("nmcli"), RAW_DHCP6: OSError("nmcli")}
        )
        self.assertEqual(collect_dns({}, INTERFACE, runner), [])
        self.assertEqual(runner.calls, list(ALL_COMMANDS))

    def test_a_readable_source_is_not_undone_by_a_later_failure(self):
        """The raw fields answered, so a wedged resolvectl is not a total failure."""
        runner = FakeRunner(
            failures={EFFECTIVE_IP4: OSError("nmcli"), EFFECTIVE_IP6: OSError("nmcli"),
                      RESOLVECTL: OSError("resolvectl")},
        )
        self.assertEqual(collect_dns({}, INTERFACE, runner), [])
        self.assertEqual(runner.calls, list(ALL_COMMANDS))

    def test_a_failure_before_a_readable_source_with_addresses_keeps_them(self):
        runner = FakeRunner(
            quiet_outputs({EFFECTIVE_IP4: "192.168.1.1"}),
            failures={RAW_DHCP4: OSError("nmcli"), RAW_DHCP6: OSError("nmcli")},
        )
        self.assertEqual(collect_dns({}, INTERFACE, runner), ["192.168.1.1"])
        self.assertEqual(
            runner.calls, [RAW_DHCP4, RAW_DHCP6, EFFECTIVE_IP4, EFFECTIVE_IP6]
        )

    def test_the_events_own_variables_answer_without_a_command(self):
        runner = broken()
        self.assertEqual(
            collect_dns({"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.53"}, INTERFACE, runner),
            ["192.168.1.53"],
        )
        self.assertEqual(runner.calls, [RAW_DHCP4, RAW_DHCP6])

    def test_a_resolvectl_fallback_alone_is_a_readable_source(self):
        runner = FakeRunner(
            quiet_outputs({RESOLVECTL: "Link 2 (enp3s0): 192.168.1.1"}),
            failures={command: OSError("nmcli") for command in ALL_COMMANDS if command != RESOLVECTL},
        )
        self.assertEqual(collect_dns({}, INTERFACE, runner), ["192.168.1.1"])


class NormalizationTests(unittest.TestCase):
    def test_keeps_only_addresses_a_domestic_query_can_be_forwarded_to(self):
        cases = [
            ({"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1 127.0.0.53 192.168.1.1"},
             ["192.168.1.1"]),
            ({"DHCP6_DOMAIN_NAME_SERVERS": "fe80::1"}, ["fe80::1"]),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "not-an-ip 192.168.1.53"}, ["192.168.1.53"]),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "127.0.0.54"}, []),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "127.0.0.1 127.1.2.3"}, []),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "169.254.10.1"}, []),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "0.0.0.0 224.0.0.1 239.255.255.250"}, []),
            ({"DHCP6_DOMAIN_NAME_SERVERS": ":: ::1 ff02::1"}, []),
            ({"DHCP6_DOMAIN_NAME_SERVERS": "::ffff:192.168.1.1"}, []),
            ({"DHCP6_DOMAIN_NAME_SERVERS": "fe80::1%enp3s0"}, []),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1:53 192.168.1.999"}, []),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "[192.168.1.1]"}, ["192.168.1.1"]),
            ({"DHCP6_DOMAIN_NAME_SERVERS": "[2001:db8::1]"}, ["2001:db8::1"]),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1,192.168.1.2;192.168.1.3"},
             ["192.168.1.1", "192.168.1.2", "192.168.1.3"]),
            ({"DHCP6_DOMAIN_NAME_SERVERS": "2001:0db8:0000::0001 2001:db8::1"},
             ["2001:db8::1"]),
            ({"DHCP4_DOMAIN_NAME_SERVERS": "   "}, []),
        ]
        for env, want in cases:
            with self.subTest(env=env):
                self.assertEqual(collect_dns(env, INTERFACE, silent()), want)

    def test_orders_addresses_by_family_and_then_numerically(self):
        env = {
            "DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.10 192.168.1.2",
            "DHCP6_DOMAIN_NAME_SERVERS": "fd00::10 fd00::2",
        }
        self.assertEqual(
            collect_dns(env, INTERFACE, silent()),
            ["192.168.1.2", "192.168.1.10", "fd00::2", "fd00::10"],
        )

    def test_order_does_not_depend_on_the_order_a_source_reports(self):
        ascending = {
            "DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.2 192.168.1.10",
            "DHCP6_DOMAIN_NAME_SERVERS": "fd00::2 fd00::10",
        }
        descending = {
            "DHCP6_DOMAIN_NAME_SERVERS": "fd00::10 fd00::2",
            "DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.10 192.168.1.2",
        }
        want = ["192.168.1.2", "192.168.1.10", "fd00::2", "fd00::10"]
        self.assertEqual(collect_dns(ascending, INTERFACE, silent()), want)
        self.assertEqual(collect_dns(descending, INTERFACE, silent()), want)

    def test_deduplicates_an_address_named_by_two_dhcp_variables(self):
        env = {
            "DHCP4_DOMAIN_NAME_SERVERS": "192.168.1.1",
            "DHCP6_DOMAIN_NAME_SERVERS": "192.168.1.1 fe80::1",
        }
        self.assertEqual(collect_dns(env, INTERFACE, silent()), ["192.168.1.1", "fe80::1"])


class InterfaceTests(unittest.TestCase):
    def test_passes_the_event_interface_to_every_command(self):
        runner = FakeRunner()
        got = collect_dns({}, "br-lan.2", runner)
        self.assertEqual(got, [])
        self.assertEqual(
            runner.calls,
            [
                ("nmcli", "-g", "DHCP4.OPTION", "device", "show", "br-lan.2"),
                ("nmcli", "-g", "DHCP6.OPTION", "device", "show", "br-lan.2"),
                ("nmcli", "-g", "IP4.DNS", "device", "show", "br-lan.2"),
                ("nmcli", "-g", "IP6.DNS", "device", "show", "br-lan.2"),
                ("resolvectl", "dns", "br-lan.2"),
            ],
        )

    def test_accepts_interface_names_the_kernel_could_own(self):
        for interface in [
            "enp3s0",
            "eth0",
            "eth0.100",
            "vlan_2",
            "br-lan",
            "2eth0",
            "abcdefghijklmno",
        ]:
            with self.subTest(interface=interface):
                self.assertEqual(collect_dns({}, interface, silent()), [])

    def test_rejects_an_interface_name_that_could_carry_a_second_command(self):
        for interface in [
            "",
            "enp3s0:1",
            "enp3s0 eth0",
            "enp3s0;id",
            "enp3s0|id",
            "enp3s0&",
            "enp3s0$(id)",
            "enp3s0`id`",
            "enp3s0\n",
            "enp3s0>out",
            "enp3s0*",
            "../etc/passwd",
            "/dev/null",
            "enp@3s0",
            "-enp3s0",
            ".enp3s0",
            "_enp3s0",
            "abcdefghijklmnop",
        ]:
            with self.subTest(interface=interface):
                runner = FakeRunner()
                with self.assertRaises(ValueError):
                    collect_dns({}, interface, runner)
                self.assertEqual(runner.calls, [])

class NmcliFieldNameTests(unittest.TestCase):
    """**The field name the collector asked for is not a field nmcli has.**

    MEASURED, in a 24.04 target container after a **successful** install, on
    `mosdns-router` 0.1.0:

        $ nmcli -g DHCP4.OPTION_DOMAIN_NAME_SERVERS device show eth0
        Error: 'device show': invalid field 'DHCP4.OPTION_DOMAIN_NAME_SERVERS';
        allowed fields: DHCP4.OPTION
        rc=2

        $ nmcli -g DHCP4.OPTION device show eth0
        broadcast_address = 10.89.0.255 | dhcp_client_identifier = 01\\:4e\\:b1\\:...
        | domain_name_servers = 10.89.0.2 | ... | routers = 10.89.0.2 | ...
        rc=0

    The lease's resolvers are in the output, under a KEY inside a `key = value |
    key = value` list, and the field that carries the list is `DHCP4.OPTION`. The
    collector's highest-priority source -- the one its own docstring says "is the
    only source that still names the lease's resolvers once `ignore-auto-dns`
    keeps NetworkManager from passing them to resolved" -- has therefore been
    **unreadable on every release**, and the bridge falls through to the
    effective device DNS.

    Which is harmless until the install points NetworkManager at the loopback.
    Then the effective DNS *is* `127.0.0.1`, a local address the collector
    filters out, and the published state becomes:

        { "upstreams": [], "last_good": false, "source": "nm-effective",
          "generation": 2, "interface": "eth0" }

    MEASURED, same cell, same moment. The router's `dhcp_forward` plugin then has
    no upstream, so **every China-set name SERVFAILs after a successful install**
    -- which is the exact condition this project exists to fix, produced by the
    install that fixes the foreign side. The plan's Task 4 Step 4 asks for "the
    bridge state retains the original mock DNS", and it did not.

    **The fixture is why 36 green cases never saw it.** `RAW_DHCP4` in this file
    is the same wrong field name, so the fake runner answered a question nmcli
    cannot be asked and the test agreed with the code. That is the same defect
    class as `install_test.py`'s `ActiveState` rule that matched nothing: a
    fixture and an assertion that agree with each other and neither agrees with
    the program under test.
    """

    # The output `nmcli -g DHCP4.OPTION device show eth0` really prints. Trimmed,
    # and with the escaped colons left exactly as nmcli writes them, because the
    # unescaping is part of what has to work.
    REAL_DHCP4_OPTION = (
        "broadcast_address = 10.89.0.255 | "
        "dhcp_client_identifier = 01\\:4e\\:b1\\:5f\\:bf\\:79\\:e2 | "
        "domain_name_servers = 10.89.0.2 | "
        "routers = 10.89.0.2 | "
        "subnet_mask = 255.255.255.0\n"
    )
    # A CANONICAL v6 address, and that is a constraint rather than a preference:
    # Python 3.14's `ipaddress` rejects a short form like `2001:db8:1:53` outright
    # ("does not appear to be an IPv4 or IPv6 address"), so a fixture using one
    # would be testing nothing. The escaped colons are nmcli's, not the
    # address's, and unescaping them is part of what has to work.
    REAL_DHCP6_OPTION = "domain_name_servers = 2001\\:db8\\:\\:53\n"

    def test_the_lease_resolvers_are_read_out_of_the_option_field_nmcli_has(self):
        result = collect_dns_with_source(
            {},
            INTERFACE,
            FakeRunner({RAW_DHCP4: self.REAL_DHCP4_OPTION}),
        )
        self.assertEqual(result.addresses, ["10.89.0.2"])
        self.assertEqual(result.source, "nm-dhcp4")

    def test_a_v6_lease_is_read_the_same_way_and_keeps_its_escaped_colons(self):
        result = collect_dns_with_source(
            {},
            INTERFACE,
            FakeRunner({RAW_DHCP6: self.REAL_DHCP6_OPTION}),
        )
        # The escaped colons are nmcli's, not the address's, and an address with
        # backslashes in it is not an address.
        self.assertEqual(result.addresses, ["2001:db8::53"])
        self.assertEqual(result.source, "nm-dhcp6")

    def test_both_families_in_one_lease_are_one_answer(self):
        result = collect_dns_with_source(
            {},
            INTERFACE,
            FakeRunner({
                RAW_DHCP4: self.REAL_DHCP4_OPTION,
                RAW_DHCP6: self.REAL_DHCP6_OPTION,
            }),
        )
        self.assertEqual(result.addresses, ["10.89.0.2", "2001:db8::53"])
        self.assertEqual(result.source, "nm-dhcp")

    def test_the_loopback_the_install_configures_never_comes_from_this_source(self):
        """**And the case that is the whole point: a lease whose raw option names
        the router's real upstream, on a machine whose effective DNS is the
        loopback.**

        This is the state a configured target is in, and it is the state the
        install leaves the bridge in. With the field name fixed, the raw lease
        answers and the empty effective list is never consulted; with it wrong,
        the loopback is the only thing left and the published state is empty.
        """
        result = collect_dns_with_source(
            {},
            INTERFACE,
            FakeRunner({
                RAW_DHCP4: self.REAL_DHCP4_OPTION,
                EFFECTIVE_IP4: "127.0.0.1",
            }),
        )
        self.assertEqual(result.addresses, ["10.89.0.2"])
        self.assertEqual(result.source, "nm-dhcp4")

    def test_an_option_line_with_no_resolvers_is_an_empty_answer_not_a_failure(self):
        # A v4-only lease's DHCP6 field prints nothing at all, and a field that
        # answered with nothing is a source that was read -- which is what keeps
        # `SourcesUnavailable` for a NetworkManager that cannot be queried.
        result = collect_dns_with_source(
            {},
            INTERFACE,
            FakeRunner({
                RAW_DHCP4: "routers = 10.89.0.2 | subnet_mask = 255.255.255.0\n",
                EFFECTIVE_IP4: "",
            }),
        )
        self.assertEqual(result.addresses, [])

    def test_the_argument_arrays_name_fields_nmcli_actually_has(self):
        """**The command is asserted, because the command was the defect.**

        A field name is not a formatting choice: nmcli refuses an unknown one with
        exit 2 and no output, which the collector reads as "this source could not
        be read" and skips. So the argument arrays are held to `DHCP4.OPTION` and
        `DHCP6.OPTION` -- the two fields nmcli lists as allowed -- and a case that
        renames them fails here rather than silently making the source unreadable
        on every release.
        """
        runner = FakeRunner()
        collect_dns_with_source({}, INTERFACE, runner)
        for expected in (
            ("nmcli", "-g", "DHCP4.OPTION", "device", "show", INTERFACE),
            ("nmcli", "-g", "DHCP6.OPTION", "device", "show", INTERFACE),
        ):
            self.assertIn(expected, runner.calls, f"the collector did not run {expected!r}")
        self.assertNotIn(
            "OPTION_DOMAIN_NAME_SERVERS", " ".join(" ".join(call) for call in runner.calls),
            "a field name nmcli does not have was asked for again: exit 2 and no output, which "
            "this collector reads as a source it could not read and skips",
        )


if __name__ == "__main__":
    unittest.main()
