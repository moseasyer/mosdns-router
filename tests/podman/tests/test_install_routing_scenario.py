"""The routing scenario: which branch a name went down, read from the counters.

Task 4 Step 6 asks for China-set and foreign test names queried from a separate
client container and from inside the target, with the **query counters** at the
mock domestic and mock foreign listeners asserted, repeated over UDP and TCP. The
word that matters is *counters*, and this file is why: an answer coming back
proves somebody answered, and a router that sent every name down one branch
satisfies it completely. The two things only the counters can see are

* **which listener** the query reached, and
* **which transport** it reached it over,

and both are load-bearing for the property under test. A China-set name and a
foreign name that both arrive at the foreign listener mean the split is broken
and everything still resolves; a foreign name that only ever arrives over UDP
means the TCP path was never exercised, which is half of what Step 6 asks for.

So the fixture below is built to be *disagreeable*. It answers the two mock
listeners from one table keyed by the name each was asked about, so a case can
change one listener's answer and the other stays as the happy path has it -- and
a case cannot pass by both counters moving together.
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
sys.path.insert(0, str(HARNESS / "lib"))
sys.path.insert(0, str(HARNESS / "tests"))
sys.path.insert(0, str(SCENARIOS))

import test_command  # noqa: E402

from podman import Podman  # noqa: E402

PodmanTestCase = test_command.PodmanTestCase

VERSION = "24.04"
RUN_ID = "20260930T000000Z"
ROUTER = f"mosdns-{RUN_ID}-mock-router-{VERSION}"
TARGET = f"mosdns-{RUN_ID}-target-{VERSION}"
FOREIGN = f"mosdns-{RUN_ID}-mock-foreign-{VERSION}"
CLIENT = f"mosdns-{RUN_ID}-client-{VERSION}"


def _load_scenario(name: str):
    """The scenario module, loaded by path rather than by name.

    Loaded by path so a case file and a scenario file can never shadow one
    another in `sys.modules` -- the defect `test_suite_shape.py` exists to keep
    out of this harness's own suite.
    """
    path = SCENARIOS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"mosdns_scenario_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


routing = _load_scenario("routing_test")

# The four addresses this run's private network hands out, read from the
# scenario rather than written here, and asserted below to be the ones the plan
# fixes. A case that typed them would still pass if the scenario moved the
# foreign listener onto the domestic address -- which is the mistake that would
# make both branches the same listener and every counter agree.
DOMESTIC_LISTENER = routing.MOCK_ROUTER_ADDRESS
FOREIGN_LISTENER = routing.MOCK_FOREIGN_ADDRESS
CLIENT_ADDRESS = routing.CLIENT_ADDRESS
# The target's own address on the private network, and the address a client
# container would have to ask to reach the target's resolver. Read out of the
# scenario rather than typed, so the listener table this file's fixture writes
# cannot be about a different address than the one the scenario asks for.
TARGET_ADDRESS = routing.TARGET_ADDRESS


def counters_document(**counts):
    """A mock foreign resolver's counters document, with the counts given.

    The shape is the one `mock-foreign` writes, so a case that builds one by hand
    and a live run's are the same document -- a second invented shape would let a
    scenario read a field the real program never writes.
    """
    queries = {}
    for key, value in counts.items():
        name, _, transport = key.partition("/")
        queries.setdefault(name, {})[transport] = value
    return json.dumps(
        {
            "stamp": "sdns://AQMAAAAAAAAADzEyNy4wLjAuMToxNTQ0MyAE8jObx8__N7tWgbRyjpRmU57dO1C-Jx9MCVEzwfOB7iMyLmRuc2NyeXB0LWNlcnQubW9zZG5zLW1vY2stZm9yZWlnbg",
            "provider": "2.dnscrypt-cert.mosdns-mock-foreign",
            "address": f"{FOREIGN_LISTENER}:443",
            "total": sum(counts.values()),
            "certificate_fetches": 1,
            "plaintext_probes": 1,
            "dropped": 0,
            "queries": queries,
        },
        indent=2,
    )


# The two names the scenario asks about, and which branch each is meant to reach.
# `routing_test.py` derives the China-set name from the published list rather
# than from a literal, so a case cannot pass by using a name that is in neither
# set -- and a case that wanted to check that would have to change the list, not
# the name.
FOREIGN_NAME = routing.FOREIGN_TEST_NAME

# The China-set name the record will carry: `probe.<entry>` for an entry of the
# published list, which is the shape `routing_test.py` builds once it has read the
# list. The entry is the FIRST name in the repository's own published list, read
# rather than typed, so the fixture and the shipped data cannot drift apart
# silently.
CHINA_ENTRY = next(
    line.strip().removeprefix("domain:")
    for line in (REPO / "configs" / "cn-domains.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
)
CHINA_NAME = f"probe.{CHINA_ENTRY}"

# Every entry of the repository's own published China list, for the shape case: it
# reads the scenario's code and refuses any name that is one of these. Read rather
# than typed, so a re-pin that changed the list changes what is forbidden with it.
_PUBLISHED_ENTRIES = frozenset(
    line.strip().removeprefix("domain:")
    for line in (REPO / "configs" / "cn-domains.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
)


def routing_rules(**overrides):
    """Every answer a cell whose two branches are distinguishable needs.

    Every override replaces one answer, so each case changes exactly the fact it
    is about.
    """
    answers = {
        # The client container's own resolver is the target's loopback -- which
        # is what makes a client's answer evidence about the target rather than
        # about whatever the client's resolv.conf said.
        "client_resolv": "nameserver 10.89.0.10\n",
        "target_resolv": "nameserver 127.0.0.53\n",
        # The published China list, read from the target. The names are real
        # entries of the list this project ships -- read out of the repository's
        # own file rather than typed, so a re-pin that dropped them would fail
        # this fixture loudly rather than quietly ask about a name the router
        # routes down the foreign branch.
        "published_cn": f"domain:{CHINA_ENTRY}\ndomain:example.cn\n",
        # Each mock's counter for each name and transport. The happy path is the
        # split: the China name at the domestic listener only, the foreign name
        # at the foreign one only.
        "domestic": counters_document(),
        "foreign": counters_document(
            **{f"{FOREIGN_NAME}/udp": 1, f"{FOREIGN_NAME}/tcp": 1},
        ),
        # A dnsmasq `log-queries` line, in the shape dnsmasq(1) documents:
        # `<timestamp> <hostname> <client> <name> is <answer>`. The marker between
        # the name and the answer is what makes the line a query, so a DHCP line or
        # a startup line cannot satisfy the domestic count -- and the first version
        # of `router_queries` read the fields positionally, counted nothing, and the
        # only symptom was a cell that waited out its whole budget.
        "router_log": (
            f"Sep 30 20:00:00 mosdns-mock-router {DOMESTIC_LISTENER} {CHINA_NAME} is "
            f"{routing.DOMESTIC_ANSWER}\n"
        ),
        "answer": "198.51.100.7",
    }
    # The domestic mock is the DHCP/DNS router, whose evidence is its own log
    # rather than a counters document -- dnsmasq is a package on the locked
    # release, not this project's code, and the plan's Task 3 built it that way.
    answers["domestic_queries"] = overrides.pop("domestic_queries", 2)
    answers.update(overrides)
    return [
        # -- the target's own listener table ---------------------------------
        # Read before the queries, and the refusal that hangs on it is in
        # `TheClientCannotReachALoopbackOnlyRouterTest`. **The default answer has
        # the target's bridge address bound**, so the table does not turn every
        # case in this file into that one: a case that wants the loopback-only
        # shape says so, and the rest of this suite is about the counters.
        {"match": ["sh", "-c"], "match_contains": "ss -lntup",
         "stdout": (
             "tcp   LISTEN 0      128       127.0.0.1:53        0.0.0.0:*\n"
             "tcp   LISTEN 0      128       127.0.0.1:15353     0.0.0.0:*\n"
             "udp   UNCONN 0      0         127.0.0.1:53        0.0.0.0:*\n"
             "udp   UNCONN 0      0         127.0.0.1:15353     0.0.0.0:*\n"
             f"tcp   LISTEN 0      128       {TARGET_ADDRESS}:53       0.0.0.0:*\n"
         )},
        # -- the client's resolver, which is the whole of "the answer came
        # through the target" for a client on the same bridge --------------
        {"match": ["exec", CLIENT, "cat", "/etc/resolv.conf"],
         "stdout": answers["client_resolv"]},
        {"match": ["exec", TARGET, "cat", "/etc/resolv.conf"],
         "stdout": answers["target_resolv"]},
        # -- the two branches' evidence, one mock each -----------------------
        # The foreign mock's counters document, read the way a live run reads
        # it: `cat` of the file it publishes. Matching on the path rather than
        # on the container is deliberate -- the case below changes this answer
        # and needs the *other* mock's answer to stay as it is.
        {"match": ["exec", FOREIGN, "cat", routing.COUNTERS_PATH],
         "stdout": answers["foreign"]},
        {"match": ["logs", ROUTER], "stdout": answers["router_log"]},
        # -- what the answers were, read from inside the target -------------
        {"match": ["exec", TARGET, "cat", routing.PUBLISHED_CN_LIST],
         "stdout": answers["published_cn"]},
        # Each query's answer, and it is keyed by the NAME in the command so a case
        # can make one branch answer with the other's address. `sh -c` carries the
        # whole script as one argv token, so `match_contains` on the name is what
        # tells two otherwise identical `dig` invocations apart.
        {"match": ["exec", TARGET, "sh", "-c"], "match_contains": CHINA_NAME,
         "stdout": routing.DOMESTIC_ANSWER + "\n"},
        {"match": ["exec", TARGET, "sh", "-c"], "match_contains": FOREIGN_NAME,
         "stdout": routing.FOREIGN_ANSWER + "\n"},
        {"match": ["exec", CLIENT, "sh", "-c"], "match_contains": CHINA_NAME,
         "stdout": routing.DOMESTIC_ANSWER + "\n"},
        {"match": ["exec", CLIENT, "sh", "-c"], "match_contains": FOREIGN_NAME,
         "stdout": routing.FOREIGN_ANSWER + "\n"},
    ]


class RoutingScenarioHarness(PodmanTestCase):
    """Drives the scenario against a fake podman, on a virtual clock."""

    def run_scenario(self, *, rules=None, **overrides):
        if rules is None:
            rules = routing_rules(**overrides)
        fake = self.fake(rules, self.extra_directory())
        clock = {"now": 0.0}
        builder = routing.build_scenario(
            podman=self.client(fake),
            version=VERSION,
            arch="amd64",
            run_id=RUN_ID,
            router=ROUTER,
            target=TARGET,
            foreign=FOREIGN,
            client=CLIENT,
            network=f"mosdns-{RUN_ID}-testnet",
            results_dir=self.directory / "results",
            now=lambda: clock["now"],
            sleep=lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
        )
        return fake, builder()

    def record(self, result):
        return json.loads(
            (self.directory / "results" / RUN_ID / result.log).read_text(encoding="utf-8")
        )

    def asked_in(self, fake, container):
        return [
            " ".join(argv[3:])
            for argv in fake.invocations()
            if argv[:2] == ["exec", container]
        ]


class TheClientCannotReachALoopbackOnlyRouterTest(RoutingScenarioHarness):
    """**The plan's client half cannot be measured, and the reason is the
    package's own headline property.**

    Task 4 Step 6 says "from a separate client container **and** from inside the
    target, query China-set and foreign test names". The second vantage point
    works: a query asked inside the target of 127.0.0.1:53 goes down the domestic
    branch to the mock router and down the foreign branch to the mock foreign
    resolver, and both listeners' counters move.

    The first cannot. `configs/mosdns.yaml` listens on `127.0.0.1:53` and nothing
    else, and the package's own Description says it: "The router binds 127.0.0.1:53
    and the resolver 127.0.0.1:15353, on UDP and TCP, **and nothing else; no
    listener in this package is reachable from another host**". A client container
    on the bridge cannot `dig @10.89.0.10 -p 53` anything, because nothing is
    bound to 10.89.0.10.

    MEASURED, 24.04 and 26.04, Task 4 Step 7:

        answers: {"client/domestic/tcp": "(not readable: 'podman exec
                  mosdns-…-client-24.04 sh -c dig +short +tcp @10.89.0.10 -p 53
                  probe.0033.cn' exited 9)", …}

    `exited 9` is `dig`'s "no reply from server", on all four client queries.

    So the scenario does not wait out its whole budget to report a symptom. It
    reads the target's own listener table first and, when nothing is bound to the
    bridge address, refuses **naming this**: the finding is that Step 6's client
    half and the package's loopback-only property cannot both hold, and a reader
    needs that sentence rather than a 60-second timeout followed by "the mock
    router's query log does not carry a query", which is what the first version
    produced.
    """

    LISTENERS_LOOPBACK_ONLY = (
        "tcp   LISTEN 0      128       127.0.0.1:53        0.0.0.0:*\n"
        "tcp   LISTEN 0      128       127.0.0.1:15353     0.0.0.0:*\n"
        "udp   UNCONN 0      0         127.0.0.1:53        0.0.0.0:*\n"
        "udp   UNCONN 0      0         127.0.0.1:15353     0.0.0.0:*\n"
    )
    LISTENERS_ON_THE_BRIDGE = LISTENERS_LOOPBACK_ONLY + (
        "tcp   LISTEN 0      128       10.89.0.10:53       0.0.0.0:*\n"
    )

    def test_a_router_bound_to_loopback_only_is_refused_and_says_why(self):
        _fake, result = self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup",
                 "stdout": self.LISTENERS_LOOPBACK_ONLY},
            ] + routing_rules(),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("reachable from another host", result.detail)
        self.assertIn("cannot be measured", result.detail)
        self.assertIn(TARGET_ADDRESS, result.detail)
        self.assertIn(f"nothing is bound to {TARGET_ADDRESS}:53", result.detail)
        # And the listener table is in the evidence, because a reader who doubts
        # the refusal needs the reading the refusal is based on.
        record = self.record(result)
        self.assertIn("127.0.0.1:53", record["target_listeners"])
        self.assertNotIn(TARGET_ADDRESS, record["target_listeners"])

    def test_a_router_also_bound_to_the_bridge_address_is_not_refused_for_that(self):
        # The control: the refusal is about the BINDING, not about the client. A
        # cell whose router does listen on the bridge address -- which is a
        # configuration this project does not ship, and which the plan's Task 4
        # Step 3 forbids -- must get past this check and on to the counters, or
        # the case is a statement about the container rather than about the
        # binding.
        _fake, result = self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup",
                 "stdout": self.LISTENERS_ON_THE_BRIDGE},
            ] + routing_rules(),
        )
        self.assertEqual(result.status, "passed", result.detail)
        self.assertIn(TARGET_ADDRESS, self.record(result)["target_listeners"])

    def test_the_listener_table_is_read_from_the_target(self):
        """**The reading the refusal rests on is a reading, not a podman error.**

        MEASURED on the first three-release matrix run: the cell's evidence
        document carried

            "target_listeners": "(not readable: Error: no container with name
             or ID \"sh\" found: no such container)"

        and the refusal that followed it was built on that string. The read had
        no container in it -- `try_read` takes one first and the call did not
        pass one -- so podman was asked for a container called `sh`, and the
        text that does not contain `10.89.0.10:53` satisfied the check. The
        refusal was true and it was unfounded at the same time, which is the
        worst of both: a cell whose router *did* bind the bridge address would
        have been refused for the same reason.

        So the invocation has to name the target, and this is the case that says
        so -- a scenario that went back to reading the wrong thing would fail
        here rather than quietly re-deriving the same unfounded conclusion.
        """
        fake, result = self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup",
                 "stdout": self.LISTENERS_ON_THE_BRIDGE},
            ] + routing_rules(),
        )
        self.assertEqual(result.status, "passed", result.detail)
        asked = [line for line in self.asked_in(fake, TARGET) if "ss -lntup" in line]
        self.assertTrue(
            asked, f"the target's listener table was not read from {TARGET}: {self.asked_in(fake, TARGET)}"
        )
        every = [line for container in (TARGET, CLIENT, ROUTER, FOREIGN)
                 for line in self.asked_in(fake, container)]
        self.assertFalse(
            [line for line in every if line.startswith("sh ")],
            f"a command was run as though it were a container name: {every}",
        )

    def test_a_listener_table_that_cannot_be_read_is_a_fault_and_not_the_finding(self):
        """**A failed read is not evidence.**

        The refusal above is a strong claim -- that this project's own packaging
        forbids the very vantage point the plan asks for -- and a strong claim
        made on a read that did not happen is worse than no claim: it sends a
        reader to the plan with a reason that was never measured. So an
        unreadable table is refused as what it is, a harness fault, and the
        message must not contain the finding.
        """
        _fake, result = self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup",
                 "returncode": 125, "stderr": "no such container"},
            ] + routing_rules(),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("not readable", result.detail)
        self.assertNotIn(
            "reachable from another host", result.detail,
            "a read that failed was reported as a measurement of the shipped configuration",
        )
        self.assertNotIn("cannot be measured", result.detail)
        # And the failed read is recorded verbatim, so the evidence document says
        # what was read rather than leaving a reader to infer it from the refusal.
        self.assertIn(routing.READ_FAILED, self.record(result)["target_listeners"])
        self.assertIn("no such container", result.detail)

    def test_an_empty_listener_table_is_not_evidence_that_nothing_is_bound(self):
        # The same class as the case above and a different symptom: `ss` printed
        # nothing at all, which is not what `ss -lntup` does -- it prints a
        # header whether or not anything is bound. An empty reading is a read
        # that did not happen, and the `|| true` in the command means a missing
        # `ss` looks exactly like this.
        _fake, result = self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup", "stdout": ""},
            ] + routing_rules(),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("printed nothing", result.detail)
        self.assertNotIn("reachable from another host", result.detail)


class RoutingScenarioTest(RoutingScenarioHarness):
    """A cell whose two branches reached two different listeners passes."""

    def test_a_cell_whose_two_branches_reached_two_listeners_passes(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)

    def test_the_record_says_which_name_reached_which_listener(self):
        """**The property under test, read back.**"""
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertTrue(record["branches_distinguished"])
        self.assertEqual(record["domestic_name"], CHINA_NAME)
        self.assertEqual(record["foreign_name"], FOREIGN_NAME)
        self.assertEqual(record["domestic_listener"], DOMESTIC_LISTENER)
        self.assertEqual(record["foreign_listener"], FOREIGN_LISTENER)

    def test_both_transports_reached_the_foreign_listener(self):
        """UDP and TCP, which is half of what Step 6 asks for.

        Read from the mock's own counters and not from a summary the scenario
        wrote, so a scenario that recorded "tcp: yes" without the counter having
        moved would fail here.
        """
        _fake, result = self.run_scenario()
        record = self.record(result)
        for transport in ("udp", "tcp"):
            with self.subTest(transport=transport):
                # Read per name and then per transport, in that order, because the
                # document is nested that way and a flat lookup would report a
                # missing name as a missing transport.
                self.assertGreaterEqual(
                    record["foreign_counters"].get(FOREIGN_NAME, {}).get(transport, 0), 1,
                    f"the foreign listener was not asked for {FOREIGN_NAME} over {transport}; "
                    f"it counted {record['foreign_counters']}",
                )

    def test_the_china_name_never_reached_the_foreign_listener(self):
        """The other half, and the one a total would not see.

        A China-set name that reached the foreign listener means the split is
        broken and the machine still resolves -- so this is an *absence* on the
        foreign mock's counters, keyed by the China name specifically.
        """
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertNotIn(
            CHINA_NAME, record["foreign_counters"],
            f"the China-set name {CHINA_NAME} reached the FOREIGN listener, so the "
            "domestic/foreign split is not what this cell claims to have exercised",
        )

    def test_the_foreign_name_never_reached_the_domestic_listener(self):
        """The mirror, because the two directions have different symptoms.

        A foreign name answered by the domestic branch would produce an answer
        from an address nobody can reach, and a scenario that only checked "an
        answer came back" would read that as a pass.
        """
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertNotIn(FOREIGN_NAME, record["domestic_counters"])

    def test_the_scenario_asked_from_inside_the_target_and_from_the_client(self):
        """Both vantage points, because Step 6 names both."""
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        for container in (TARGET, CLIENT):
            with self.subTest(container=container):
                asked = self.asked_in(fake, container)
                self.assertTrue(
                    any(CHINA_NAME in line for line in asked),
                    f"nothing asked {CHINA_NAME} from {container}: {asked}",
                )
                self.assertTrue(
                    any(FOREIGN_NAME in line for line in asked),
                    f"nothing asked {FOREIGN_NAME} from {container}: {asked}",
                )

    def test_the_clients_own_resolver_is_the_target(self):
        """**How a client's answer is known to have come through the target.**

        A client container on the private network has the mock router as its
        resolver, so an answer it receives could have come from anywhere. The
        answer is that the client's `/etc/resolv.conf` names the *target* -- so
        the only resolver it can ask is the target's -- and the counters on the
        two mocks are what the target's own forwarding reached. The scenario
        reads the client's resolv.conf and records it, so a reader of the
        evidence document sees which resolver was asked rather than trusting that
        the answer came from the right place.
        """
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertIn(routing.TARGET_ADDRESS, record["client_resolver"])
        self.assertNotIn(DOMESTIC_LISTENER, record["client_resolver"])

    def test_a_client_whose_resolver_is_the_mock_router_is_refused(self):
        """The control, and the reason the resolver is read at all.

        Without this case the check above would be satisfied by any resolv.conf
        containing the target's address, including one that also names the mock
        router -- and a client asking the router would get its answer from a
        resolver that is not under test.
        """
        _fake, result = self.run_scenario(
            client_resolv=f"nameserver {DOMESTIC_LISTENER}\nnameserver 10.89.0.10\n"
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("resolver", result.detail)


class TheCountersAreTheMeasurementTest(RoutingScenarioHarness):
    """What makes the counters load-bearing rather than decorative."""

    def test_a_china_name_that_reached_the_foreign_listener_is_refused(self):
        """**The control for the whole scenario.**"""
        _fake, result = self.run_scenario(
            foreign=counters_document(
                **{f"{FOREIGN_NAME}/udp": 1, f"{FOREIGN_NAME}/tcp": 1, f"{CHINA_NAME}/udp": 1},
            ),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn(CHINA_NAME, result.detail)
        self.assertIn("split", result.detail)

    def test_a_foreign_name_that_reached_the_domestic_listener_is_refused(self):
        _fake, result = self.run_scenario(
            router_log=(
                f"Sep 30 20:00:00 mosdns-mock-router {DOMESTIC_LISTENER} {FOREIGN_NAME} is "
                f"{routing.DOMESTIC_ANSWER}\n"
            )
        )
        self.assertEqual(result.status, "failed")
        self.assertIn(FOREIGN_NAME, result.detail)

    def test_a_foreign_name_answered_only_over_udp_is_refused(self):
        """TCP is not a formality in Step 6, and a scenario that dropped it would
        still resolve every name it asked."""
        _fake, result = self.run_scenario(
            foreign=counters_document(**{f"{FOREIGN_NAME}/udp": 2}),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("tcp", result.detail.lower())

    def test_a_foreign_listener_that_answered_nothing_is_refused(self):
        # The refusal comes from the WAIT, not from the count assertion: a mock
        # that was never asked is caught before the split is checked, and the
        # message names the counters document rather than the name. That is the
        # right order -- there is nothing to say about the split until both
        # listeners have been read -- and a case asserting the name here would be
        # asserting a message the scenario does not produce.
        _fake, result = self.run_scenario(foreign=counters_document())
        self.assertEqual(result.status, "failed")
        self.assertIn(routing.COUNTERS_PATH, result.detail)
        self.assertIn(routing.MOCK_FOREIGN_ADDRESS, result.detail)

    def test_a_domestic_listener_that_saw_nothing_is_refused(self):
        _fake, result = self.run_scenario(router_log="")
        self.assertEqual(result.status, "failed")
        self.assertIn("query log", result.detail)

    def test_both_counters_moving_alone_does_not_pass(self):
        """**The self-review question, as a case.**

        "Could this cell pass without the two branches actually being different?"
        The answer has to be no, and the way to show it is to make both listeners
        report the *foreign* name and leave the China name unasked anywhere. A
        scenario that only compared the two totals would see two non-zero numbers
        and pass; one that asks which name reached which listener cannot.
        """
        _fake, result = self.run_scenario(
            foreign=counters_document(
                **{f"{FOREIGN_NAME}/udp": 1, f"{FOREIGN_NAME}/tcp": 1, f"{CHINA_NAME}/tcp": 1},
            ),
            router_log=(
                f"Sep 30 20:00:00 mosdns-mock-router {DOMESTIC_LISTENER} {FOREIGN_NAME} is "
                f"{routing.DOMESTIC_ANSWER}\n"
            ),
        )
        self.assertEqual(result.status, "failed")
        # Both listeners have a non-zero count of the foreign name, and the China
        # name reached the foreign one, so any check keyed on totals alone would be
        # satisfied.
        self.assertIn(FOREIGN_NAME, result.detail)


def _executable_code(source: str) -> str:
    """A module's source with every docstring removed, as `ast.unparse` renders it.

    The docstrings are dropped by *structure* -- the parser knows which expression
    statements are string literals -- rather than by a line filter, which a prose
    line could satisfy by not starting with `#`. Every check in this file that
    looks for code in a scenario reads the code this way, and the reason is the
    same throughout: these scenarios explain at length what they deliberately do
    not do, and a check on the raw text fails on the explanation of the thing it
    forbids.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def _dig_invocations(tree: ast.AST) -> list[tuple[str, str]]:
    """Every `dig` command line the scenario builds, as `(place, text)`.

    Read out of the parsed tree by finding the f-string that names the query tool,
    so a case sees what the *code* would run rather than what this file says it
    runs. `f-string` is a `JoinedStr` whose parts are constants and formatted
    values, and `ast.unparse` of one puts it back together -- which is the join
    this needs and is why the search is for the tool's name rather than for a
    whole literal.
    """
    found: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        rendered = ast.unparse(node)
        if routing.QUERY_TOOL in rendered:
            found.append((f"line {node.lineno}", rendered))
    return found


class RoutingScenarioShapeTest(unittest.TestCase):
    """What the scenario must keep being, checked against its source."""

    def source(self) -> str:
        return (SCENARIOS / "routing_test.py").read_text(encoding="utf-8")

    def test_the_scenario_is_registered_under_this_name(self):
        registry = (HARNESS / "run.py").read_text(encoding="utf-8")
        self.assertIn('"routing": "routing_test:build_scenario"', registry)

    def test_the_image_publishes_the_address_this_scenario_dials(self):
        """**The address the foreign mock's stamp names is the one the client dials.**

        MEASURED, and it cost a matrix run on all three releases. The mock binds
        `0.0.0.0:443` so it answers on whatever address the private network gave
        it, and its first version built the DNSCrypt stamp from that bind address.
        The stamp therefore named `0.0.0.0:443`, which the client resolves to
        *itself*: `dnscrypt-proxy` in the target dialled the target's own port 443,
        got nothing, and the install transaction refused at its own barrier with

            dnscrypt-proxy.service was started but nothing answered a DNS query at
            127.0.0.1:15353 within 60s

        -- a sentence about a resolver that says nothing about an address nobody
        could have dialled.

        So the image names the address separately (`--address`), and this case holds
        that name equal to the address the scenario dials: two spellings of one fact
        in two files, which is exactly the shape that produced the failure.
        """
        text = (SCENARIOS / ".." / "images" / "mock-foreign.Containerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f'"--address={FOREIGN_LISTENER}:443"', text,
            f"the foreign mock's image does not name {FOREIGN_LISTENER}:443 as the address its "
            f"stamp carries, so the stamp names whatever the container binds",
        )
        self.assertIn(
            '"--listen=0.0.0.0:443"', text,
            "and the bind address is the unspecified one on purpose: it is the address the "
            "container listens on, not the one a client dials",
        )

    def test_the_two_listeners_are_different_addresses(self):
        """The premise, held here so a later edit moving them onto one address is
        a visible failure rather than a cell that passes for the wrong reason."""
        self.assertNotEqual(
            routing.MOCK_ROUTER_ADDRESS, routing.MOCK_FOREIGN_ADDRESS,
            "the domestic and foreign listeners are the same address, so no cell can "
            "distinguish the two branches by which listener a query reached",
        )

    def test_the_china_name_comes_from_the_published_list_and_not_a_literal(self):
        """A name the China set does not match is not a China-set name.

        The scenario has to read a name out of the published list rather than
        hard-code one, or a re-pin that dropped it would leave the scenario asking
        about a name the router routes down the *foreign* branch and the counters
        would disagree for a reason the evidence document would not describe.
        """
        # On the executable code, with the prose out, for the reason the IPv6 case
        # gives: this scenario's own docstring explains that the name is read from
        # the published list, and a check over the raw text finds the explanation.
        self.assertIn("cn-domains.txt", self.source())
        code = _executable_code(self.source())
        # **No China-set NAME is written down, and the check is for a name rather
        # than for the string `domain:`** -- because `domain:` is the published
        # list's own line prefix and the parser that reads it has to spell it. A
        # name is a dotted domain; the one this scenario asks about is
        # `probe.<entry>` out of the list, so a literal name here would be a dotted
        # name that is not of that form.
        for name in sorted(set(re.findall(r"[\"']([a-z0-9-]+(?:\.[a-z0-9-]+)+)[\"']", code))):
            with self.subTest(name=name):
                self.assertNotIn(
                    name, _PUBLISHED_ENTRIES,
                    f"routing_test.py's code contains the name {name!r}, which is an entry of "
                    "this project's own published China list -- so the China-set test name is a "
                    "name this file chose rather than one the list carries, and a re-pin that "
                    "dropped it would leave the cell asking about a name the router routes down "
                    "the foreign branch",
                )
        self.assertIn(
            "probe.", code,
            "the name the scenario asks about should be built as `probe.<entry>` out of the "
            "published list rather than written down",
        )
        # And the name it does use comes from the list, read at run time.
        self.assertIn(routing.PUBLISHED_CN_LIST, code)
        self.assertIn("matches_china_set", code)

    def test_the_scenario_asserts_on_counters_and_not_on_answers_alone(self):
        source = self.source()
        self.assertIn("foreign_counters", source)
        self.assertIn("domestic_counters", source)
        self.assertIn("branches_distinguished", source)

    def test_the_scenario_asks_over_both_transports(self):
        source = self.source()
        self.assertIn("TRANSPORTS", source)
        self.assertIn("+tcp", source)

    def test_the_scenario_never_asserts_an_ipv6_absence(self):
        """**`ip -6` is not a claim.**

        22.04, 24.04 and 26.04 differ in what they do with IPv6, and a cell that
        never asked an AAAA question cannot say anything about it. So the scenario
        must not assert that IPv6 is absent -- it must simply not make the claim.

        **Checked on the executable code, not on the whole file**, and that is the
        substance of the case rather than a detail of it. "AAAA" appears in this
        scenario's own docstring -- saying that nothing here asks an AAAA question
        -- and in the list of types a dnsmasq log line may carry, and neither is a
        claim. A check over the raw source fails on the explanation of the thing it
        forbids, which is the mistake `shell_statements` and `instructions` exist
        in this project to prevent, and a check that fails on correct prose is a
        check a reader learns to work around.

        The code is taken by parsing the module and dropping every docstring, so
        the prose -- the module's, its functions' and its classes' -- is excluded
        by *structure* rather than by a line filter, which a prose line could
        satisfy by not starting with `#`.
        """
        code = _executable_code(self.source())
        for pattern, what in (
            (r"ip\s+-6", "an `ip -6` read"),
            (r"inet6", "an inet6 address family"),
            (r"ipv6", "an IPv6 setting"),
        ):
            with self.subTest(pattern=what):
                self.assertNotRegex(
                    code, pattern,
                    f"routing_test.py's code contains {what}, and no cell in this scenario asks "
                    "an IPv6 question, so it would be a claim about a property nothing here "
                    "exercises -- and 22.04, 24.04 and 26.04 differ in it",
                )
        # And the two facts that make the absence honest rather than an omission:
        # both transports ARE asked, and the scenario says what it does not claim.
        self.assertEqual(routing.TRANSPORTS, ("udp", "tcp"))
        self.assertIn("IPv6", self.source())

        # **`AAAA` is a query TYPE, and naming it is not a claim about IPv6.**
        # A dnsmasq log line carries the type that was asked, and a parser that
        # recognised every type but AAAA would mis-read a line this project cannot
        # control -- so the word is allowed to appear in the markers, and what is
        # forbidden is *asking* one. Which is the property the `dig` invocations
        # have, and it is checked directly: every query in the scenario's code
        # asks the same single type, and that type is not AAAA.
        for name, argument in _dig_invocations(ast.parse(self.source())):
            with self.subTest(invocation=name):
                self.assertNotIn(
                    "AAAA", argument,
                    f"the scenario asks an AAAA query ({argument}), and a cell that did would be "
                    "asserting something about IPv6 -- which 22.04, 24.04 and 26.04 differ in "
                    "and which this scenario does not otherwise exercise",
                )


if __name__ == "__main__":
    unittest.main()
