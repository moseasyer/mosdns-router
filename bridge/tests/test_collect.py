"""Tests for collecting router-supplied DHCP DNS from NetworkManager.

The collector is the only component allowed to ask NetworkManager and resolved
what DNS the router was told to use, so these tests pin the four things a
domestic query depends on: which source wins, which addresses a source may
contribute, which interface name may be asked about, and that no command is ever
handed a shell string.
"""

import sys
import unittest
from pathlib import Path

# The bridge package is used from a source checkout, not from an installed
# distribution, so the repository's bridge directory is the import root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mosdns_dhcp_bridge.collect import collect_dns

INTERFACE = "enp3s0"

# The exact argument arrays the collector may build for one interface. DHCP4 and
# DHCP6 are read separately because a colon is both nmcli's field separator and
# part of every IPv6 address.
RAW_DHCP4 = ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE)
RAW_DHCP6 = ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", INTERFACE)
EFFECTIVE_IP4 = ("nmcli", "-g", "IP4.DNS", "device", "show", INTERFACE)
EFFECTIVE_IP6 = ("nmcli", "-g", "IP6.DNS", "device", "show", INTERFACE)
RESOLVECTL = ("resolvectl", "dns", INTERFACE)
ALL_COMMANDS = (RAW_DHCP4, RAW_DHCP6, EFFECTIVE_IP4, EFFECTIVE_IP6, RESOLVECTL)


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
                    RAW_DHCP4: "192.168.1.1",
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
                    RAW_DHCP6: "fd00::53",
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

    def test_treats_a_command_without_output_as_unavailable(self):
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
                    RAW_DHCP4: "192.168.1.1,192.168.1.2",
                    EFFECTIVE_IP4: "203.0.113.9",
                    RESOLVECTL: "203.0.113.8",
                }
            )
        )
        got = collect_dns({}, INTERFACE, runner)
        self.assertEqual(got, ["192.168.1.1", "192.168.1.2"])


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
                ("nmcli", "-g", "DHCP4.OPTION_DOMAIN_NAME_SERVERS", "device", "show", "br-lan.2"),
                ("nmcli", "-g", "DHCP6.OPTION_DOMAIN_NAME_SERVERS", "device", "show", "br-lan.2"),
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
            "enp3s0:1",
            "abcdefghijklmno",
        ]:
            with self.subTest(interface=interface):
                self.assertEqual(collect_dns({}, interface, silent()), [])

    def test_rejects_an_interface_name_that_could_carry_a_second_command(self):
        for interface in [
            "",
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


if __name__ == "__main__":
    unittest.main()
