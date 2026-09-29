"""The DHCP scenario's assertions, and the two facts that make them possible.

The plan's Task 3 asks for a scenario that proves NetworkManager obtains IPv4 by
DHCP, publishes the mock router's DNS, and then receives a **new** DNS address
after the mock router is reconfigured. Those are three claims about a running
container and none of them can be checked by reading a file, so this file drives
the real scenario module against a fake `podman` executable -- the same
subprocess-level seam `test_command.py` uses -- and asserts what the scenario
asks the container and what it accepts as an answer.

Four things here are the ones a later task would get wrong, so they are cases
rather than comments.

* **The lease has to be inside the DHCP range.** The target is given a fixed
  address on the bridge by podman (`--ip 10.89.0.10`), so "the target has an
  IPv4 address" is true before a single DHCP packet crosses the network. The
  only evidence that the address came from DHCP is that it is one the pool
  could have handed out, and the only evidence that the *DNS* came from DHCP is
  the option the lease itself carried.

* **The DNS change has to be waited for, not slept for.** `nmcli connection up`
  returns before the device has an address, so a scenario that reads `IP4.DNS` on
  the next line reads a field that is not there yet, and one that sleeps reads
  it at an arbitrary later moment. Both pass on a fast machine and fail on a
  loaded one. The wait is bounded, and its failure names what it saw.

* **A reload has to be observable from the other end.** The mock router is
  reconfigured and the target's NetworkManager is driven to ask again; what
  proves the change arrived is that the router's own log records reading the
  option file after the signal, and that the option it then sent is the new one.
  A scenario that sent the signal and asserted nothing cannot fail.

* **The hand-off is checked before the reload, not after.** Without it, a
  target whose `eth0-managed` profile was never activated fails the *reload*
  assertion, and the failure names the reload -- sending a reader to the mock
  router when the problem is that the device is still on NetworkManager's own
  profile.
"""

import ast
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "tests" / "podman"
SCENARIOS = HARNESS / "scenarios"
DISCOVERED = HARNESS / "tests"

sys.path.insert(0, str(HARNESS / "lib"))
sys.path.insert(0, str(DISCOVERED))

# `test_command.py`'s fake podman, its table format and its `PodmanTestCase`
# base, reused rather than copied. A second fake would be a second thing that
# can be wrong about what a podman invocation looks like, and this suite's record
# is that a duplicated fixture is a duplicated defect.
import test_command  # noqa: E402
from test_images import run_lines  # noqa: E402

from podman import PodmanError  # noqa: E402

PodmanTestCase = test_command.PodmanTestCase


def _load_scenario(name: str = "dhcp_test"):
    """The scenario module, loaded from its path.

    It lives in `scenarios/` rather than in this directory, and it is loaded by
    path rather than by name so a case file and a scenario file can never shadow
    one another in `sys.modules` -- the defect `test_suite_shape.py` exists to
    keep out of the harness's own suite.
    """
    path = SCENARIOS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"mosdns_scenario_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dhcp = _load_scenario()

# The plan's fixed private network, written out here rather than read from the
# module: a case that imported the addresses it is checking would agree with
# whatever the module said, and these four are the plan's.
PLAN_ADDRESSES = {
    "MOCK_ROUTER_ADDRESS": "10.89.0.2",
    "TARGET_ADDRESS": "10.89.0.10",
    "MOCK_CDN_ADDRESS": "10.89.0.20",
    "CLIENT_ADDRESS": "10.89.0.30",
}
SUBNET = "10.89.0.0/24"
POOL_FIRST = "10.89.0.100"
POOL_LAST = "10.89.0.199"
LEASE_ADDRESS = "10.89.0.191"
PROFILE = "eth0-managed"
DNS_OPTION_FILE = "/etc/dnsmasq-dhcp-opts"
DHCP_STATE_FILE = "/run/mosdns/dhcp-upstreams.json"
ROUTER_LEASE_FILE = "/var/lib/mosdns-mock-router/dnsmasq.leases"
RUN_ID = "20260929T000000Z"
# The names the **runner** composes, version suffix and all: `RunResources`
# appends the version because three versions run at once and a name has to say
# which it is. Used here rather than a shorter spelling so this file's rule
# table is the same table `test_matrix_cell.py` drives the real runner with --
# a table written against names nothing produces matches nothing, and every case
# that depends on it fails on an empty reading.
ROUTER = f"mosdns-{RUN_ID}-mock-router-24.04"
TARGET = f"mosdns-{RUN_ID}-target-24.04"

MOCK_ROUTER_ADDRESS = PLAN_ADDRESSES["MOCK_ROUTER_ADDRESS"]
MOCK_CDN_ADDRESS = PLAN_ADDRESSES["MOCK_CDN_ADDRESS"]

# dnsmasq's log, as the scenario reads it: a DORA and the option lines that make
# the DNS attributable to the router rather than to a coincidence, then the
# post-reload read.
#
# **`read <optsfile>` is in the *first* log, not only the second.** dnsmasq opens
# `--dhcp-optsfile` when it starts, so the line is in the log the scenario
# captures *before* it writes the new address and signals -- measured on a live
# 22.04 cell, where the pre-reload `podman logs` already carried it. A fixture
# that put it only in the second log would make a presence test on that line look
# like it proved a reload, which is the defect
# `test_the_startup_read_on_its_own_is_not_a_reload` is written about.
DORA_LOG = "\n".join([
    "dnsmasq[1]: started, version 2.91 cachesize 150",
    f"dnsmasq-dhcp[1]: read {DNS_OPTION_FILE}",
    f"dnsmasq-dhcp[1]: DHCP, IP range {POOL_FIRST} -- {POOL_LAST}, lease time 5m",
    "dnsmasq-dhcp[1]: DHCPDISCOVER(eth0) c2:c6:42:81:9d:6d",
    f"dnsmasq-dhcp[1]: DHCPOFFER(eth0) {LEASE_ADDRESS} c2:c6:42:81:9d:6d",
    f"dnsmasq-dhcp[1]: DHCPREQUEST(eth0) {LEASE_ADDRESS} c2:c6:42:81:9d:6d",
    f"dnsmasq-dhcp[1]: DHCPACK(eth0) {LEASE_ADDRESS} c2:c6:42:81:9d:6d",
    f"dnsmasq-dhcp[1]: sent size:  4 option: 6 dns-server  {MOCK_ROUTER_ADDRESS}",
    f"dnsmasq-dhcp[1]: sent size:  4 option: 3 router  {MOCK_ROUTER_ADDRESS}",
])
# **Cumulative, because `podman logs` is.** The second read of the router's log
# returns everything the first returned *plus* what the reload added -- a
# `podman logs` is a container's whole output since it started, not a delta. The
# first fixture modelled it as a replacement, which is not what podman does, and
# a count across the two reads is wrong against a log that forgets its own
# start-up. So the second answer is the first one and then the reload.
RELOADED_LOG = "\n".join([
    DORA_LOG,
    "dnsmasq[1]: cleared cache",
    f"dnsmasq-dhcp[1]: read {DNS_OPTION_FILE}",
    f"dnsmasq-dhcp[1]: DHCPREQUEST(eth0) {LEASE_ADDRESS} 32:83:9e:e1:11:3c",
    f"dnsmasq-dhcp[1]: DHCPACK(eth0) {LEASE_ADDRESS} 32:83:9e:e1:11:3c",
    f"dnsmasq-dhcp[1]: sent size:  4 option: 6 dns-server  {MOCK_CDN_ADDRESS}",
])


def _contains(argv, match):
    """Whether `match` appears in `argv` as a contiguous run of tokens."""
    return any(argv[index:index + len(match)] == list(match) for index in range(len(argv)))


def _quoted(address) -> bool:
    return bool(re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(address or ""))) and all(
        0 <= int(part) <= 255 for part in str(address).split(".")
    )


def _in_subnet(address, subnet) -> bool:
    network, _, bits = subnet.partition("/")
    if not _quoted(address) or not bits.isdigit():
        return False
    packed = lambda parts: sum(int(part) << shift for part, shift in zip(parts.split("."), (24, 16, 8, 0)))
    mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
    return (packed(address) & mask) == (packed(network) & mask)


def _in_pool(address, first, last) -> bool:
    if not _quoted(address) or not _quoted(first) or not _quoted(last):
        return False
    value = tuple(int(part) for part in address.split("."))
    return tuple(int(p) for p in first.split(".")) <= value <= tuple(int(p) for p in last.split("."))


class NetworkPlanTest(unittest.TestCase):
    """The plan's addresses, and the range that makes a lease attributable."""

    def test_the_four_fixed_addresses_are_the_plans(self):
        for name, planned in sorted(PLAN_ADDRESSES.items()):
            with self.subTest(address=name):
                self.assertEqual(getattr(dhcp, name), planned)

    def test_the_subnet_is_the_plans(self):
        self.assertEqual(dhcp.NETWORK_SUBNET, SUBNET)

    def test_the_dhcp_pool_is_the_plans_and_is_inside_the_subnet(self):
        self.assertEqual((dhcp.DHCP_POOL_FIRST, dhcp.DHCP_POOL_LAST), (POOL_FIRST, POOL_LAST))
        for label, value in (("first", POOL_FIRST), ("last", POOL_LAST)):
            with self.subTest(bound=label):
                self.assertTrue(
                    _in_subnet(value, SUBNET),
                    f"the {label} pool address {value} is not inside {SUBNET}, so a lease would be "
                    f"off the network the bridge was given",
                )

    def test_no_fixed_address_is_inside_the_pool(self):
        """A pool that overlapped a fixed address would make two claims ambiguous.

        The plan gives the target `10.89.0.10` and a pool of
        `10.89.0.100-10.89.0.199`. The gap is the point: it is what lets the
        scenario say "this address is one the pool could have handed out, so
        DHCP gave it" while the address podman handed the container is still
        there to be confused with.
        """
        for name, address in sorted(PLAN_ADDRESSES.items()):
            with self.subTest(address=name):
                self.assertFalse(
                    _in_pool(address, POOL_FIRST, POOL_LAST),
                    f"the {name} {address} is inside the DHCP pool {POOL_FIRST}-{POOL_LAST}, so a "
                    f"lease could not be told apart from a fixed address",
                )

    def test_the_pool_predicate_answers_both_ways(self):
        """The claim rests on this predicate, so it is checked on both sides.

        A case that only checked the in-pool address would pass on a predicate
        that accepted everything, and "the target obtained its address by DHCP"
        would then be indistinguishable from "the target has an address".
        """
        self.assertTrue(_in_pool(LEASE_ADDRESS, POOL_FIRST, POOL_LAST))
        for outside in (
            PLAN_ADDRESSES["TARGET_ADDRESS"],
            PLAN_ADDRESSES["MOCK_ROUTER_ADDRESS"],
            "10.89.0.99",
            "10.89.0.200",
            "10.89.1.150",
            "10.89.0",
            "not-an-address",
            "",
            None,
        ):
            with self.subTest(address=outside):
                self.assertFalse(
                    _in_pool(outside, POOL_FIRST, POOL_LAST),
                    f"{outside!r} is not a lease from {POOL_FIRST}-{POOL_LAST} and was accepted",
                )


class DnsOptionFileTest(unittest.TestCase):
    """The file a reload rewrites, and why it is not the dnsmasq config.

    **Measured, and the plan's step 3 was wrong about it.** `dnsmasq(8)` says,
    in its own NOTES section:

    ```text
    SIGHUP does NOT re-read the configuration file.
    ```

    so a control command that rewrites `/etc/dnsmasq.conf` and sends SIGHUP
    changes nothing, and the DNS a target is given stays the one the config said
    at boot. The same page says `--dhcp-optsfile` *is* re-read on SIGHUP, and
    that an option found there takes precedence over `dhcp-option` -- which is
    what makes a second DNS address possible without restarting the daemon.
    """

    def shipped_config(self) -> str:
        return (HARNESS / "mock-router" / "dnsmasq.conf").read_text(encoding="utf-8")

    def plan(self) -> str:
        """The plan, which is a record the next implementer works from.

        Read by path rather than imported: it is prose, and the claim is about
        what it says, not about what any code does with it.
        """
        return (
            REPO / "docs" / "superpowers" / "plans"
            / "2026-09-25-podman-integration-matrix.md"
        ).read_text(encoding="utf-8")

    def test_the_shipped_config_names_the_option_file_a_reload_rewrites(self):
        self.assertIn(f"dhcp-optsfile={DNS_OPTION_FILE}", self.shipped_config())
        self.assertEqual(dhcp.DNS_OPTION_FILE, DNS_OPTION_FILE)

    def test_the_option_file_lives_inside_the_router_and_not_in_the_checkout(self):
        """A control command must not rewrite the file the image was built from.

        `/etc/dnsmasq-dhcp-opts` does not exist in the checkout, so a scenario
        that wrote it there would be writing the source tree -- which is mounted
        read-only in every container and is the one thing on this host a run must
        not change.
        """
        self.assertTrue(dhcp.DNS_OPTION_FILE.startswith("/etc/"))
        self.assertFalse(
            (REPO / dhcp.DNS_OPTION_FILE.lstrip("/")).exists(),
            f"{dhcp.DNS_OPTION_FILE} exists in the checkout, so a reload would rewrite the source "
            f"tree rather than the container's own configuration",
        )

    def test_the_option_line_is_validated_before_it_reaches_the_router(self):
        """The address is checked here, because the write is a shell command.

        The option file is written with `podman exec … sh -c '…'`, so an address
        that were not a dotted quad would be a second command. The check is on
        the shape and says so, and the rejection is a refusal rather than a
        string that is quietly quoted into something else.
        """
        self.assertEqual(dhcp.dns_option_line(MOCK_CDN_ADDRESS), f"6,{MOCK_CDN_ADDRESS}")
        for bad in ("", "10.89.0.20; rm -rf /", "$(id)", "`id`", "10.89.0", "10.89.0.256", "not an address", None):
            with self.subTest(address=bad):
                with self.assertRaises(dhcp.DhcpScenarioError) as caught:
                    dhcp.dns_option_line(bad)
                self.assertIn("dotted-quad", str(caught.exception))

    def test_the_shipped_config_publishes_the_router_and_ranges_the_pool(self):
        conf = self.shipped_config()
        self.assertIn(f"dhcp-range={POOL_FIRST},{POOL_LAST}", conf)
        self.assertIn(f"dhcp-option=option:router,{MOCK_ROUTER_ADDRESS}", conf)
        # `no-resolv` and `no-hosts`, because a mock router that forwarded to
        # the resolver podman handed it would answer questions off this host.
        self.assertIn("no-resolv", conf)
        self.assertIn("no-hosts", conf)
        # **And the one name it answers for itself, which `no-resolv` made
        # necessary.** With no upstream at all, dnsmasq SERVFAILs every query --
        # and a SERVFAIL for `install-probe.example` is a CORRECT answer from a
        # resolver that reached nobody, which is precisely what the rollback
        # checks for when it decides whether the machine came back. Measured on a
        # real 24.04 target in Task 8's container run: the first unattended
        # rollback restored the machine's own resolvers and then reported exit 6
        # because a query through the stub did not resolve. The watchdog was
        # right; the fixture could not answer. The line is the fix, and it is
        # `address=` rather than `server=` so it is an answer dnsmasq gives
        # without asking anybody.
        self.assertIn("address=/install-probe.example/", conf)
        # And exactly one answer, and NO upstream. A `server=` line would make
        # this mock a forwarder, which is what `no-resolv` above exists to
        # prevent, and the comment explaining the choice names the word -- so the
        # check reads the DIRECTIVE lines rather than the raw text. Scanning the
        # whole file for a substring a comment contains is a check that can only
        # be satisfied by deleting the explanation.
        self.assertEqual(
            [line for line in run_lines(conf) if line.startswith("server=")], [],
            "the mock router has an upstream, so it forwards and a question it answers came from "
            "off this host",
        )
        self.assertEqual(
            [line for line in run_lines(conf) if line.startswith("address=")],
            ["address=/install-probe.example/10.89.0.2"],
            "the mock router answers for more than the one test-only name, so it is a resolver "
            "for the rest of the matrix rather than a fixture for one check",
        )
        # Authoritative, or a DISCOVER is answered with an offer of nothing and
        # the client waits out its own transaction timeout for a server that is
        # standing right there.
        self.assertIn("dhcp-authoritative", conf)

    def test_option_6_comes_from_the_option_file_and_nowhere_else(self):
        """**Two sources for option 6 make dnsmasq say so, in the log we treat as evidence.**

        Measured on the first live 22.04 cell: with both
        `dhcp-option=option:dns-server,10.89.0.2` in the config and `6,10.89.0.20`
        in the option file, the reload worked and the second transaction offered
        `option: 6 dns-server  10.89.0.20` -- and the log also carried

        ```text
        dnsmasq-dhcp[1]: Ignoring duplicate dhcp-option 6
        ```

        which does not say *which* one it ignored. That line sits in the very
        document the scenario records as the attribution for a DNS address, so a
        reader has to work out whether the router sent the new address or the
        old one before they can read the rest of the log. The option file wins,
        so the baseline is the file's own value and the config must not also
        carry one: one source, one line in the log, nothing to work out.
        """
        conf = self.shipped_config()
        self.assertNotIn(
            f"dhcp-option=option:dns-server,{MOCK_ROUTER_ADDRESS}", conf,
            "the config sets option 6 as well as the option file, so dnsmasq logs 'Ignoring "
            "duplicate dhcp-option 6' into the very document this scenario records as evidence, "
            "and the line does not say which one it ignored",
        )
        # And the plan must not describe a line the config does not have. The
        # check above holds the config; nothing held the *plan*, and the plan is
        # the record the next implementer works from -- so a later task reading
        # "the shipped config also carries dhcp-option=option:dns-server,10.89.0.2"
        # would restore the line, and the run would produce
        # `Ignoring duplicate dhcp-option 6` in the evidence document. That
        # sentence was in the plan; this is what keeps it from coming back.
        self.assertNotIn(
            f"carries `dhcp-option=option:dns-server,{MOCK_ROUTER_ADDRESS}`",
            self.plan(),
            "the plan says the shipped config carries a dhcp-option=option:dns-server line, and it "
            "does not: restoring the line the plan describes puts 'Ignoring duplicate "
            "dhcp-option 6' into the document this scenario records as the attribution for a "
            "DNS address",
        )

    def test_the_image_ships_the_option_file_with_the_routers_address(self):
        """The baseline comes from a file the image creates, not from an implicit default.

        dnsmasq's own default for option 6 is "the address of the machine running
        dnsmasq", which here is 10.89.0.2 -- so the baseline would be right even
        with the config saying nothing. Relying on a documented default to
        produce a value a test asserts is one more thing to keep true across
        dnsmasq versions, so the file is written into the image with the
        address in it, and the path it is written to is the one the config
        names.
        """
        containerfile = (HARNESS / "images" / "mock-router.Containerfile").read_text(encoding="utf-8")
        created = re.search(
            rf"printf\s+'([^']+)'\s*>\s*(\S+)", containerfile
        )
        self.assertIsNotNone(
            created, "the mock router's image does not create the option file its config names"
        )
        self.assertEqual(created.group(2), DNS_OPTION_FILE)
        self.assertIn(MOCK_ROUTER_ADDRESS, created.group(1))

    def test_the_shipped_config_binds_only_the_private_interface(self):
        """`interface=eth0`, and a bind mode, because a wildcard would not.

        The router answers on the run's private bridge and nowhere else. A
        dnsmasq listening on every address is a listener on the container's
        loopback too, and the failure the interface line prevents is a DHCP
        server that answers for a network it is not on.
        """
        conf = self.shipped_config()
        self.assertIn("interface=eth0", conf)
        self.assertTrue(
            "bind-dynamic" in conf or "bind-interfaces" in conf,
            "the config neither binds to its interfaces nor binds dynamically, so the server is "
            "listening on addresses the run did not give it",
        )

    def test_the_router_image_ships_the_config_at_the_path_dnsmasq_is_asked_for(self):
        """The CMD's `--conf-file` and the COPY's destination have to be one path.

        Two places name `/etc/dnsmasq.conf` -- the Containerfile's `CMD` and its
        `COPY` -- and a scenario that changed one and not the other would get a
        container whose dnsmasq exits immediately with "can't open ..." and a
        DHCP exchange that never happens. Reading both out of the two files is
        the cheapest way to hold them together.
        """
        containerfile = (HARNESS / "images" / "mock-router.Containerfile").read_text(encoding="utf-8")
        asked = re.search(r"--conf-file=(\S+?)\"", containerfile)
        self.assertIsNotNone(asked, "the mock router's CMD no longer names a --conf-file")
        destination = re.search(
            r"^COPY\s+\S+\s+(\S+)/dnsmasq\.conf$", containerfile, re.MULTILINE
        )
        self.assertIsNotNone(
            destination, "the mock router's config is not COPYed to a dnsmasq.conf path"
        )
        self.assertEqual(f"{destination.group(1)}/dnsmasq.conf", asked.group(1))


class WaitForEvidenceTest(unittest.TestCase):
    """The bounded wait, and what its failure says.

    A scenario that sends the signal and sleeps cannot fail; one that polls
    without a bound hangs until the matrix's own deadline. Both halves are here.
    """

    def wait(self, answers, **kwargs):
        """Run the wait against a `read` that answers from a list.

        The poll count lands in `self.polls` rather than in the return value, so
        a case that is asserting on the *failure* -- the count is what tells a
        bounded wait from a busy loop -- can see it: the tuple is never assigned
        when the wait raises, and a case written as `answer, polls = self.wait(…)`
        inside `assertRaises` reads `polls` before it exists.
        """
        remaining = list(answers)
        self.polls = 0

        def read():
            self.polls += 1
            return remaining[min(self.polls - 1, len(remaining) - 1)]

        clock = {"now": 0.0}
        settings = {
            "timeout": 60.0,
            "interval": 5.0,
            "now": lambda: clock["now"],
            "sleep": lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
        }
        settings.update(kwargs)
        return dhcp.wait_for(read, MOCK_CDN_ADDRESS, what="IP4.DNS", **settings)

    def test_the_wait_returns_the_moment_the_new_dns_is_reported(self):
        """Two stale reads and then the answer: the third poll is enough.

        A *sequence* rather than an immediate match, because the defect is a wait
        that gives up too early, and a case that only ever saw the answer on the
        first poll could not tell a bounded wait from a single read.
        """
        self.assertEqual(
            self.wait([f"{MOCK_ROUTER_ADDRESS}\n", f"{MOCK_ROUTER_ADDRESS}\n", f"{MOCK_CDN_ADDRESS}\n"]),
            MOCK_CDN_ADDRESS,
        )
        self.assertEqual(self.polls, 3)

    def test_a_shorter_address_does_not_satisfy_a_wait_for_a_longer_one(self):
        """`10.89.0.2` is not `10.89.0.20`, and the reload case is exactly that.

        The whole reload claim is "the DNS address is now a *different* address",
        so a wait that matched the old one inside the new one would report a
        reload that never happened as a success -- on a network where the second
        address is the first with a digit appended, which is the plan's.
        """
        with self.assertRaises(dhcp.DhcpScenarioError):
            self.wait([f"{MOCK_ROUTER_ADDRESS}\n"], timeout=1.0, interval=1.0)
        self.assertEqual(self.polls, 2)
        with self.assertRaises(dhcp.DhcpScenarioError):
            dhcp.wait_for(
                lambda: f"Link 2 (eth0): {MOCK_ROUTER_ADDRESS}\n",
                MOCK_CDN_ADDRESS, what="IP4.DNS", timeout=0.0, interval=1.0,
            )

    def test_the_wait_is_bounded_by_its_budget_over_its_interval(self):
        """A busy loop is the other way to be wrong, and this case is what tells them apart.

        Sixty seconds at a five second interval is thirteen reads: one at t=0 and
        one at each of t=5 … t=60. A loop with no sleep would be unbounded, and
        the count is what distinguishes the two.
        """
        with self.assertRaises(dhcp.DhcpScenarioError):
            self.wait([f"{MOCK_ROUTER_ADDRESS}\n"])
        self.assertEqual(self.polls, 13)

    def test_the_failure_names_the_field_the_value_the_expectation_and_the_budget(self):
        """A timeout that says only "timed out" sends a reader to the router.

        One that says `IP4.DNS read '10.89.0.2', waiting for '10.89.0.20'` says
        the reload did not reach the target, which is a different question from
        "the target never came up" and the one a maintainer has to answer first.
        """
        with self.assertRaises(dhcp.DhcpScenarioError) as caught:
            self.wait([f"{MOCK_ROUTER_ADDRESS}\n"])
        message = str(caught.exception)
        self.assertIn("IP4.DNS", message)
        self.assertIn(MOCK_ROUTER_ADDRESS, message)
        self.assertIn(MOCK_CDN_ADDRESS, message)
        self.assertIn("60", message)

    def test_a_read_that_fails_is_treated_as_not_yet_and_its_error_is_kept(self):
        """`nmcli` exits non-zero when the device is not there yet.

        That is "not yet" rather than a crash, so the wait keeps polling. But it
        has to keep the last diagnostic: a wait that swallowed every error would
        report the same "gave up" for a target whose device had gone away and for
        one whose DNS never changed.
        """
        calls = {"count": 0}

        def read():
            calls["count"] += 1
            if calls["count"] < 3:
                raise PodmanError("Error: unknown device 'eth0'.")
            return f"{MOCK_CDN_ADDRESS}\n"

        self.assertEqual(
            dhcp.wait_for(read, MOCK_CDN_ADDRESS, what="IP4.DNS", timeout=30.0, interval=1.0),
            MOCK_CDN_ADDRESS,
        )

    def test_the_wait_reports_the_last_error_when_it_never_succeeds(self):
        calls = {"count": 0}

        def read():
            calls["count"] += 1
            raise PodmanError(f"Error: device {calls['count']} is gone.")

        with self.assertRaises(dhcp.DhcpScenarioError) as caught:
            dhcp.wait_for(read, MOCK_CDN_ADDRESS, what="IP4.DNS", timeout=3.0, interval=1.0)
        self.assertIn("is gone", str(caught.exception))


def router_log_rules() -> list[dict]:
    """Two answers for the router's log: before the reload, then after."""
    return [{"match": ["logs", ROUTER], "answers": [
        {"stdout": DORA_LOG + "\n"},
        {"stdout": RELOADED_LOG + "\n"},
    ]}]


def target_rules(*, dns_answers=None, connection=None, route=None, state_file=None) -> list[dict]:
    """Every query the scenario makes inside the target, in answer order.

    `dns_answers`, `connection`, `route` and `state_file` are the four a failure
    case changes, so each is a parameter rather than a re-spelled table -- a rule
    table a failure case copied would drift from the one the passing case used,
    and the failure would then be about a different run than the one it names.
    """
    return [
        {"match": ["nmcli", "-g", "IP4.DNS", "device", "show", "eth0"],
         "answers": [{"stdout": f"{value}\n"} for value in (
             dns_answers or [MOCK_ROUTER_ADDRESS] * 3 + [MOCK_CDN_ADDRESS])]},
        {"match": ["nmcli", "-g", "IP4.ADDRESS", "device", "show", "eth0"],
         "stdout": f"{LEASE_ADDRESS}/24\n"},
        {"match": ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "eth0"],
         "stdout": f"{connection or PROFILE}\n"},
        {"match": ["nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", "eth0"],
         "stdout": "yes\n"},
        {"match": ["nmcli", "-g", "DHCP4.OPTION", "connection", "show", PROFILE],
         "answers": [
             {"stdout": f"dhcp_server_identifier = {MOCK_ROUTER_ADDRESS} | domain_name_servers = {MOCK_ROUTER_ADDRESS} | ip_address = {LEASE_ADDRESS} | routers = {MOCK_ROUTER_ADDRESS}\n"},
             {"stdout": f"dhcp_server_identifier = {MOCK_ROUTER_ADDRESS} | domain_name_servers = {MOCK_CDN_ADDRESS} | ip_address = {LEASE_ADDRESS} | routers = {MOCK_ROUTER_ADDRESS}\n"},
         ]},
        {"match": ["nmcli", "-g", "ipv4.never-default", "connection", "show", PROFILE],
         "stdout": "yes\n"},
        {"match": ["resolvectl", "dns", "eth0"],
         "answers": [
             {"stdout": f"Link 2 (eth0): {MOCK_ROUTER_ADDRESS}\n"},
             {"stdout": f"Link 2 (eth0): {MOCK_CDN_ADDRESS}\n"},
         ]},
        {"match": ["ip", "route"],
         "stdout": route or f"10.89.0.0/24 dev eth0 proto kernel scope link src {LEASE_ADDRESS}\n"},
        {"match": ["journalctl", "-u", "NetworkManager", "--no-pager"],
         "stdout": f"dhcp4 (eth0): state changed new lease, address={LEASE_ADDRESS}\n"},
        {"match": ["systemctl", "is-active", "NetworkManager"], "stdout": "active\n"},
        # The package's state file is absent in this task, and `test -e` is how
        # the scenario asks without turning absence into a command failure. The
        # match is the whole contiguous run, because the command is one token
        # inside a `sh -c` argument rather than three tokens of the array.
        {"match": ["sh", "-c", f"test -e {DHCP_STATE_FILE}"], "returncode": 0 if state_file else 1},
    ]


# How `systemctl is-active` answers, **including the exit code**.
#
# `is-active` exits 0 only for `active` and 3 for every other state -- measured on
# a real 24.04 target, which also showed that a unit which does **not exist**
# exits 4 while printing `inactive`, the same word a unit that has not started yet
# prints. So the exit code is the discriminator and stdout alone is not.
#
# The previous fixture answered every state with `returncode: 0`, and that was not
# a harmless simplification: with the wrapper reading its state from a command
# that always succeeded, a wrapper that could not read the state at all agreed
# with it. That is how the `failed` branch in `wait_for_networkmanager_setup` went
# unreachable without anything going red -- the read raised on the states that
# exit 3, and the fake never produced one. A fake that cannot fail the way the
# real thing fails is a fake that agrees with a broken wrapper.
_IS_ACTIVE_EXIT = {
    "active": 0, "activating": 3, "deactivating": 3, "inactive": 3, "failed": 3,
}


def is_active_answer(state: str) -> dict:
    """One `systemctl is-active` answer, with the exit code systemd would give.

    An unrecognised word gets 4, which is what systemd answers for a unit that
    does not exist -- so a case that invents a state cannot accidentally make the
    read look successful.
    """
    return {"stdout": f"{state}\n", "returncode": _IS_ACTIVE_EXIT.get(state, 4)}


def cell_rules(**overrides) -> list[dict]:
    """Every answer a cell that passes its scenario needs, in one table.

    Shared with `test_matrix_cell.py` so a matrix case and a scenario case are
    answered by the same table: a second copy would be a second thing that can be
    wrong about what a passing run looks like, and a case that stopped agreeing
    with the run it describes would still be green.
    """
    return router_log_rules() + target_rules(**overrides)


class ScenarioHarness(PodmanTestCase):
    """A fake podman, and the scenario wired to it."""

    def run_scenario(self, *, rules=None, **overrides):
        """Run the DHCP scenario against a fake podman and return (fake, result).

        **On a virtual clock.** The scenario's waits are bounded and their
        *failure* is what most of the cases below are about, so they are driven
        with the `now`/`sleep` the builder takes rather than the real ones: a case
        that waited out a real 90-second bound to prove the bound exists would be
        a suite nobody runs, and a case that skipped the wait would not be
        testing the wait. `self.elapsed` is the clock it ran on, so a case can
        still say how long the scenario gave up after.
        """
        fake = self.fake(cell_rules(**overrides) if rules is None else rules)
        clock = {"now": 0.0}
        self.elapsed = clock

        def advance(seconds):
            clock["now"] = clock["now"] + seconds

        builder = dhcp.build_scenario(
            podman=self.client(fake),
            version="24.04",
            arch="amd64",
            run_id=RUN_ID,
            router=ROUTER,
            target=TARGET,
            network=f"mosdns-{RUN_ID}-testnet",
            results_dir=self.directory / "results",
            now=lambda: clock["now"],
            sleep=advance,
        )
        return fake, builder()

    def record(self, result):
        return json.loads(
            (self.directory / "results" / RUN_ID / result.log).read_text(encoding="utf-8")
        )

    def scripts(self, fake, container=TARGET):
        """Every `exec` into `container`, as one readable string per invocation.

        Not only the `sh -c` ones: the scenario asks most of its questions as
        argument arrays (`nmcli -g IP4.DNS device show eth0`) and only the two
        multi-command steps as scripts, so a helper that looked only at the
        scripts would see a scenario that read nothing.
        """
        return [
            " ".join(argv[2:])
            for argv in fake.invocations()
            if argv[:2] == ["exec", container]
        ]


class ScenarioRunsThePlanTest(ScenarioHarness):
    """The scenario, end to end against a fake podman."""

    def test_the_scenario_passes_and_records_its_evidence(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(result.log, f"logs/24.04-dhcp.json")
        record = self.record(result)
        self.assertEqual(record["lease_address"], LEASE_ADDRESS)
        self.assertEqual(record["dns_before"], MOCK_ROUTER_ADDRESS)
        self.assertEqual(record["dns_after"], MOCK_CDN_ADDRESS)
        self.assertEqual(record["dhcp_events"], ["DISCOVER", "OFFER", "REQUEST", "ACK"])
        # The router's own log is the attribution, and it is kept in the record.
        self.assertIn(f"option: 6 dns-server  {MOCK_CDN_ADDRESS}", record["router_log_after_reload"])
        # The lease's own option, read out of the connection, is the second half
        # of "the DNS came from DHCP": the device field could have been written
        # by something other than the lease.
        self.assertIn(f"domain_name_servers = {MOCK_CDN_ADDRESS}", record["lease_dns_after"])

    def test_it_records_the_bridges_dhcp_state_file_as_absent_rather_than_empty(self):
        """`/run/mosdns/dhcp-upstreams.json` is the *package's* file, and the package is not installed.

        Recording `{}` there would read as "the bridge published nothing", which
        is a different and wrong claim; recording the absence with the reason
        says the thing that is true, and the file's whole point is that the
        installer's rollback restores what it recorded.
        """
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertIsNone(record["dhcp_upstreams_state_file"])
        self.assertIn("not present", record["dhcp_upstreams_state_file_note"])
        self.assertIn("/run/mosdns/dhcp-upstreams.json", record["dhcp_upstreams_state_file_note"])

    def test_the_state_file_is_read_when_the_package_has_published_it(self):
        """The recording is not "absent, always" -- it reads the file when it is there.

        A recording that only ever reported absence would be indistinguishable
        from a recording that never looked, and Task 4 is the task that installs
        the package that writes it.
        """
        rules = cell_rules(state_file=True) + [
            {"match": ["cat", DHCP_STATE_FILE], "stdout": '{"upstreams": ["10.89.0.2"]}\n'},
        ]
        _fake, result = self.run_scenario(rules=rules)
        record = self.record(result)
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(record["dhcp_upstreams_state_file"], {"upstreams": ["10.89.0.2"]})

    def test_it_hands_the_device_to_the_harness_profile_with_never_default(self):
        """The two commands, in the plan's order, and no second profile.

        The image's `target-nm-setup.service` created `eth0-managed` at boot, and
        on 24.04 and 26.04 the active connection is NetworkManager's own `eth0`,
        so this step is what hands the device over. The plan's
        `ipv4.never-default yes` is a *post-boot* change, which is why it is set
        here and not in the image.
        """
        fake, _result = self.run_scenario()
        joined = "\n".join(self.scripts(fake))
        self.assertIn(f"nmcli connection modify {PROFILE} ipv4.never-default yes", joined)
        self.assertIn(f"nmcli connection up {PROFILE}", joined)
        self.assertLess(
            joined.index("ipv4.never-default yes"),
            joined.index(f"connection up {PROFILE}"),
            "never-default has to be set before the activation that re-runs DHCP, or the first "
            "lease can install a default route through the mock router",
        )

    def test_it_never_creates_or_deletes_a_connection_profile(self):
        """A second profile makes `connection up eth0-managed` ambiguous.

        The measured symptom of one is a warning and a duplicate rather than an
        error, and the profile the plan hands the device to is the one the image
        already created.
        """
        fake, _result = self.run_scenario()
        for container in (TARGET, ROUTER):
            for script in self.scripts(fake, container):
                with self.subTest(container=container):
                    self.assertNotIn("connection add", script)
                    self.assertNotIn("connection delete", script)

    def test_it_asks_for_the_address_and_the_lease_s_own_dhcp_options(self):
        """The two reads that make "by DHCP" a claim rather than a hope.

        The target is on the bridge with `--ip 10.89.0.10`, so "the target has
        an address" is true before any DHCP packet crosses. What makes it a lease
        is that the address is one the pool could have handed out *and* that the
        lease itself carried the DNS.
        """
        fake, _result = self.run_scenario()
        joined = "\n".join(self.scripts(fake))
        self.assertIn("IP4.ADDRESS", joined)
        self.assertIn("DHCP4.OPTION", joined)

    def test_a_record_that_cannot_be_read_is_recorded_and_does_not_fail_the_run(self):
        """**A read the scenario only records must not be able to fail the scenario.**

        Measured on a live 24.04 cell: the first read of the active connection --
        the one taken *before* the hand-off, purely so the evidence document says
        what the device was doing on arrival -- answered

        ```text
        'podman exec … nmcli -g GENERAL.CONNECTION device show eth0' exited 8
        ```

        because the device was mid-transition after boot, and the cell was
        reported `failed`. The claim the scenario makes is not "the active
        connection could be read before the hand-off"; it is "the hand-off works
        and the DNS moves". A record that can fail the run is a second assertion
        nobody wrote and nobody can act on.

        So the record is taken through a tolerant read that keeps the error, and
        the assertion reads are unchanged -- the wait below them is what turns
        "not there yet" into "there".
        """
        rules = cell_rules()
        rules = [
            rule for rule in rules
            if rule["match"][:2] != ["nmcli", "-g"]
            or "GENERAL.CONNECTION" not in rule["match"]
        ]
        rules.append({
            "match": ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "eth0"],
            "answers": [
                {"returncode": 8, "stderr": "Error: unknown device 'eth0'.\n"},
                {"stdout": f"{PROFILE}\n"},
                {"stdout": f"{PROFILE}\n"},
            ],
        })
        _fake, result = self.run_scenario(rules=rules)
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertIn("unknown device", str(record["active_connection_before"]))

    def test_a_stale_dns_after_the_reload_fails_and_names_what_it_saw(self):
        """The case that makes the reload observable rather than asserted.

        The fake answers the same DNS forever, so the bounded wait runs out and
        the failure has to name the address it kept reading and the one it was
        waiting for. A scenario that sent the signal and slept reports `passed`
        on exactly this.
        """
        _fake, result = self.run_scenario(dns_answers=[MOCK_ROUTER_ADDRESS])
        self.assertEqual(result.status, "failed")
        self.assertIn(MOCK_CDN_ADDRESS, result.detail)
        self.assertIn(MOCK_ROUTER_ADDRESS, result.detail)

    def test_a_target_that_never_activates_the_profile_fails_before_the_reload(self):
        """The hand-off is checked first, so the failure names the hand-off.

        Without this, a target whose `eth0-managed` profile was never activated
        would fail the *reload* assertion, and the message would send a reader
        to the mock router when the device is still on NetworkManager's own
        profile.
        """
        _fake, result = self.run_scenario(connection="eth0")
        self.assertEqual(result.status, "failed")
        self.assertIn(PROFILE, result.detail)
        self.assertNotIn(MOCK_CDN_ADDRESS, result.detail)

    def test_it_never_lets_the_mock_router_become_the_default_route(self):
        """`ipv4.never-default yes` is the mechanism; the route table is the evidence.

        dnsmasq offers `option:router 10.89.0.2` -- the plan asks for it -- so
        the one thing that must not happen is the target taking the mock router
        as its default gateway. A scenario that asserted only the setting would
        pass on a target where a foreign route had already installed it.
        """
        _fake, result = self.run_scenario(
            route=f"default via {MOCK_ROUTER_ADDRESS} dev eth0\n10.89.0.0/24 dev eth0\n"
        )
        self.assertEqual(result.status, "failed")
        self.assertIn(MOCK_ROUTER_ADDRESS, result.detail)
        self.assertIn("default", result.detail)

    def test_every_resource_the_scenario_names_carries_this_runs_prefix(self):
        """A name written out by hand is a name `cleanup` does not sweep.

        `RunResources.cleanup` finds containers, volumes and networks by the
        `mosdns-<run-id>` prefix, so a scenario that invented a name would leave
        it behind and the next run would inherit it. The names come from
        `RunResources`, and this is what holds that.
        """
        source = (SCENARIOS / "dhcp_test.py").read_text(encoding="utf-8")
        literals = re.findall(r"[\"'](mosdns-[A-Za-z0-9._-]*)[\"']", source)
        self.assertEqual(
            literals, [],
            "the scenario spells a resource name out as a literal, so cleanup cannot find it: "
            f"{literals}",
        )

    def test_the_scenario_only_touches_the_two_containers_the_run_created(self):
        """The evidence comes from the router and the target, and nothing else.

        A scenario that read from a third container, or from one this run did not
        create, would be measuring something the harness does not own -- and the
        `exec` argument is the whole of how it says which.
        """
        fake, _result = self.run_scenario()
        for argv in fake.invocations():
            if argv[:1] != ["exec"]:
                continue
            self.assertIn(argv[1], (TARGET, ROUTER), f"exec into a container this run did not name: {argv!r}")

    def test_the_reload_signals_the_router_and_copies_nothing_in_or_out(self):
        """`podman kill --signal HUP`, and no `cp` in either direction.

        The rewrite is an `exec` of the router, so the file it writes is inside
        that container's own filesystem. A `podman cp` in either direction is how
        a scenario would end up touching the checkout or the host.
        """
        fake, _result = self.run_scenario()
        signals = [argv for argv in fake.invocations() if argv[:1] == ["kill"]]
        self.assertTrue(signals, "the router was never signalled, so nothing was reloaded")
        for argv in signals:
            self.assertIn("--signal", argv)
            self.assertIn("HUP", argv)
            self.assertEqual(argv[-1], ROUTER)
        for argv in fake.invocations():
            self.assertNotEqual(argv[:1], ["cp"], f"the scenario copied a file: {argv!r}")

    def test_a_router_that_never_re_read_the_option_file_fails_the_reload(self):
        """**The reload assertion, made able to fail.**

        The log handed back after the signal is the one dnsmasq wrote at *start*,
        with the new option 6 already in it and **no second `read` line**. So
        every other property of a reloaded router holds -- the router's log names
        the new resolver, the target's `IP4.DNS` and its lease's own option 6
        changed, `resolvectl` reports the new address -- and the one thing missing
        is the only thing a re-read can produce.

        That is the shape the old check could not see. It asked whether the log
        contained `read <optsfile>` **at all**, and dnsmasq logs that line when it
        *starts* -- so a pre-reload log, which is what this fixture's first answer
        is, already satisfied it. The check therefore passed whether or not the
        SIGHUP ever reached dnsmasq, and the evidence document would claim a
        reload the log says did not happen. The count is the difference between the
        two logs, and that difference is the only thing in the log that can tell a
        re-read from a start-up.
        """
        never_re_read = DORA_LOG.replace(
            f"option: 6 dns-server  {MOCK_ROUTER_ADDRESS}",
            f"option: 6 dns-server  {MOCK_CDN_ADDRESS}",
        )
        rules = [
            rule for rule in cell_rules() if rule["match"] != ["logs", ROUTER]
        ] + [{"match": ["logs", ROUTER], "answers": [
            {"stdout": DORA_LOG + "\n"},
            {"stdout": never_re_read + "\n"},
        ]}]
        _fake, result = self.run_scenario(rules=rules)
        self.assertEqual(result.status, "failed", result.detail)
        self.assertIn(DNS_OPTION_FILE, result.detail)
        # The message names both counts, or the reader is back to guessing which
        # half of the comparison says the reload did not happen.
        self.assertIn("re-read", result.detail)
        self.assertIn(
            "1 time(s) before the reload and 1 time(s) after", result.detail,
            "the failure does not carry the two counts, so the reader cannot see which half "
            "of the comparison says the reload did not happen",
        )

    def test_the_reload_is_checked_against_a_log_that_remembers_its_start_up(self):
        """`podman logs` is cumulative, and the check depends on that being so.

        The count is a difference between the log read before the signal and the
        log read after it, and a difference is only meaningful if the second
        reading contains the first. `podman logs` does: it is a container's whole
        output since it started, not a delta since the last call. The fixture
        used to model it as a replacement -- each read a fresh log -- which is not
        what podman does, and against which a count says "dnsmasq re-read the
        file once" for a run where it re-read it twice.

        So the passing fixture carries its own start-up into the second answer, and
        this case holds that. A fixture that forgets its start-up makes the
        re-read assertion pass for the wrong reason: the count would be satisfied
        by the start-up read alone.
        """
        self.assertIn(
            f"read {DNS_OPTION_FILE}", RELOADED_LOG,
            "the post-reload fixture dropped the start-up read, so the re-read count would be "
            "satisfied by start-up alone -- the same defect as a presence test, in a fixture",
        )
        self.assertTrue(
            RELOADED_LOG.startswith(DORA_LOG),
            "the post-reload log is not the pre-reload log plus what the reload added, so it is "
            "not a `podman logs` reading",
        )
        self.assertEqual(
            dhcp._option_file_reads(RELOADED_LOG),
            dhcp._option_file_reads(DORA_LOG) + 1,
            "a genuine reload adds exactly one read of the option file to a cumulative log",
        )

    def test_a_reload_that_happened_is_the_one_that_passes(self):
        """The other side of the check above, and it is the side that has to pass.

        A check that only ever fails is not a check. This is the log a router
        produces when the signal did reach it: the option file is read a *second*
        time, after the line the start-up read wrote. So the case that fails
        without the reload and passes with it is the same assertion read twice,
        and the difference between them is one number.
        """
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertNotEqual(
            record["router_log"], record["router_log_after_reload"],
            "the two logs are identical, so this case is not exercising the "
            "difference the reload assertion is about",
        )

    def test_the_baseline_is_read_before_the_router_is_reloaded(self):
        """The order is the claim: baseline first, then the change, then the re-ask.

        A scenario that reloaded the router before the target had ever been given
        a lease would still see *a* DNS address afterwards, and the report would
        read as though the baseline had been observed. So the whole baseline --
        the address, the lease's own option 6, and the DNS NetworkManager
        published -- is read before the router is signalled, and the option file
        is written before it too.
        """
        fake, _result = self.run_scenario()
        sequence = [argv for argv in fake.invocations() if argv[0] in ("exec", "kill")]
        signalled = next(index for index, argv in enumerate(sequence) if argv[0] == "kill")
        before = sequence[:signalled]
        target_reads = [" ".join(argv[2:]) for argv in before if argv[0] == "exec" and argv[1] == TARGET]
        for needle in ("IP4.ADDRESS", "DHCP4.OPTION", "IP4.DNS"):
            with self.subTest(read=needle):
                self.assertTrue(
                    any(needle in text for text in target_reads),
                    f"the target's {needle} was not read before the router was reloaded, so nothing "
                    f"recorded the baseline the change is measured against",
                )
        self.assertTrue(
            any(DNS_OPTION_FILE in " ".join(argv[2:]) for argv in before if argv[0] == "exec" and argv[1] == ROUTER),
            f"the router's {DNS_OPTION_FILE} was written after the signal rather than before it, so "
            f"dnsmasq re-read a file that did not hold the new address yet",
        )


class ScenarioSourceShapeTest(unittest.TestCase):
    """The scenario module is a harness module, not a test file.

    `unittest` discovery is pointed at `tests/podman/tests`, so a scenario named
    `dhcp_test.py` cannot be collected by accident -- and if it ever were, the
    suite-shape guard would count cases that were never meant to run.
    """

    def test_the_scenario_lives_outside_the_discovered_directory(self):
        self.assertTrue(SCENARIOS.is_dir())
        self.assertNotIn(SCENARIOS, {path.parent for path in DISCOVERED.glob("test_*.py")})

    def test_the_scenario_defines_no_unittest_case(self):
        """A `TestCase` in a scenario file would be collected by nothing and read by everybody.

        It would not fail, it would simply never run, which is the failure mode
        this project's guards exist for.
        """
        tree = ast.parse((SCENARIOS / "dhcp_test.py").read_text(encoding="utf-8"))
        cases = [
            node.name for node in tree.body
            if isinstance(node, ast.ClassDef)
            and any(_is_a_test_case_base(base) for base in node.bases)
        ]
        self.assertEqual(cases, [], f"the scenario file defines unittest cases: {cases}")

    def test_the_scenario_is_imported_by_the_harness_rather_than_by_a_side_path(self):
        """`run.py` is the only importer, so a scenario cannot be run by hand.

        A scenario that had a `__main__` of its own would be a second way to run
        a matrix cell, outside the exit-code contract and the teardown.
        """
        source = (SCENARIOS / "dhcp_test.py").read_text(encoding="utf-8")
        self.assertNotIn('if __name__ == "__main__"', source)


def _is_a_test_case_base(base) -> bool:
    name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
    return name.endswith("TestCase") or name.endswith("Test")


if __name__ == "__main__":
    unittest.main()
