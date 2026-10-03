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

import report  # noqa: E402
from podman import Podman  # noqa: E402

# This repository's root, for the committed document the fixture renders.
REPO = Path(__file__).resolve().parents[3]

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



def dnsmasq_query_line(name, client=None, query_type="A"):
    """One `log-queries` line in the shape dnsmasq 2.91 really prints.

    **The first version of this fixture was a syslog line** --
    `Sep 30 20:00:00 mosdns-mock-router 10.89.0.2 probe.example.cn is 192.168.123.53`
    -- which is the shape `router_queries` used to parse and the shape this dnsmasq
    never prints: a container has no syslog, which is the only reason
    `log-facility=-` is set, so there is no timestamp and no hostname. So the
    fixture and the parser agreed with each other and neither agreed with dnsmasq,
    and the cell counted the word `error` on a live run. MEASURED, run
    `20261001T003319Z`; this helper's output is copied from it.
    """
    return f"dnsmasq[1]: query[{query_type}] {name} from {client or DOMESTIC_LISTENER}"


def rendered_document(upstreams=None):
    """An installed routing document, in the shape the renderer writes.

    **Read from the repository's own `configs/mosdns.yaml`, not typed.** That file is
    the committed output of the Go renderer -- `TestCommittedMosdnsConfigIsExactly`
    TheRenderedDefault` compares it byte for byte and regenerates it from the code --
    so it is what a real install writes, and a hand-written fixture would be a
    document shape no install ever produces. A fixture that typed the document would
    let the section under test pass against a fiction.

    `upstreams` replaces the forward's block, for the case that needs a document
    which does NOT name the second upstream.
    """
    document = (REPO / "configs" / "mosdns.yaml").read_text(encoding="utf-8")
    if upstreams is None:
        return document
    # A case that wants a different upstream list replaces the forward's block,
    # which is the only part of the document the section reads.
    lines = document.splitlines()
    out, inside = [], False
    for line in lines:
        if line.strip().startswith("- tag: foreign_forward"):
            inside = True
        elif inside and line.strip().startswith("- tag:"):
            inside = False
        if not inside:
            out.append(line)
    block = ["  - tag: foreign_forward", "    type: forward", "    args:",
             "      concurrent: 2"]
    for addr in upstreams:
        block.append(f"      - addr: {addr}")
    spliced = "\n".join(out).rstrip("\n")
    return spliced.replace(
        "  - tag: cn_path", "\n".join(block) + "\n  - tag: cn_path", 1
    ) + "\n"


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
        # **TCP ONLY, and that is what the cell measures.** The foreign branch's
        # forward is `tcp://127.0.0.1:15353`, so every arrival the foreign
        # listener sees from this router is TCP -- and this fixture used to claim
        # a UDP count as well, which the scenario then *required*, so the fixture
        # and the assertion agreed with each other and neither agreed with the
        # configuration. MEASURED, run `20261001T003952Z`: `foreign-routing.test`
        # counted `tcp: 1` with both transports asked of the router and both
        # answers carrying the foreign branch's address.
        "foreign": counters_document(
            **{f"{FOREIGN_NAME}/tcp": 1},
        ),
        # A dnsmasq `log-queries` line, in the shape dnsmasq 2.91 prints with
        # `log-facility=-`: `dnsmasq[1]: query[A] <name> from <client>`, with the
        # answer on a SEPARATE line that carries no name. The bracketed token in
        # the second field is what makes the line a query, so a DHCP line or a
        # startup line cannot satisfy the domestic count -- and the first version
        # of `router_queries` read the fields positionally, counted nothing, and the
        # only symptom was a cell that waited out its whole budget.
        # **Two lines, one per transport, in the shape dnsmasq prints.** The
        # answer dnsmasq gives this name is REFUSED (it has no upstream), and it
        # prints that on a SEPARATE line that carries no name -- which is why the
        # old parser read the word `error` and why this parser recognises the
        # `query[...]` line instead.
        "router_log": "\n".join(
            [
                "dnsmasq[1]: started, version 2.91 cachesize 150",
                "dnsmasq[1]: warning: no upstream servers configured",
                dnsmasq_query_line(CHINA_NAME),
                "dnsmasq[1]: config error is REFUSED (EDE: not ready)",
                dnsmasq_query_line(CHINA_NAME),
                "dnsmasq[1]: config error is REFUSED (EDE: not ready)",
            ]
        ) + "\n",
        "answer": "198.51.100.7",
        # The installed routing document, in the shape the renderer writes. The
        # second upstream is the one this cell cannot reach, and the section under
        # test reads it back out of here rather than trusting the policy.
        "rendered_document": rendered_document(),
        # **And the router's log naming that upstream.** This is the only evidence
        # in the cell that the dead upstream was asked at all: nothing receives
        # those queries, so no counter reports them, and mosdns logs a Warn per
        # failure. A log without this line is the `concurrent: 1` configuration,
        # which is the one the section exists to be different from.
    }
    # Read from `overrides`, NOT from `answers`: the flag decides what goes INTO the
    # router log, and the log is built before `answers.update(overrides)` runs. A
    # first version popped it out of `answers`, which held the default, so
    # `dead_upstream_warned=False` was applied after the log had already been written
    # -- and the case that exists to prove the cell refuses a router that never tried
    # the second upstream passed against a fixture that always added the line.
    if overrides.pop("dead_upstream_warned", True):
        answers["router_log"] = answers["router_log"] + (
            "2026-10-04T00:00:00.000+0800\tWARN\tforeign_forward\tupstream error"
            f'\t{{"upstream": "{routing.SECOND_UPSTREAM}", "error": "context deadline exceeded"}}\n'
        )
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
        # -- the installed routing document, and the router's own evidence that
        # it TRIED the upstream this cell cannot reach ------------------------
        # Read from the INSTALLED document rather than from the policy: the
        # document is what the router loaded, so a policy the renderer dropped an
        # entry from would otherwise be measured as a working two-upstream route.
        {"match": ["exec", TARGET, "cat", "/etc/mosdns/mosdns.yaml"],
         "stdout": answers["rendered_document"]},
        {"match": ["logs", ROUTER], "stdout": answers["router_log"]},
        # -- what the answers were, read from inside the target -------------
        {"match": ["exec", TARGET, "cat", routing.PUBLISHED_CN_LIST],
         "stdout": answers["published_cn"]},
        # Each query's answer, keyed by the NAME in the command so a case can make
        # one branch answer with the other's address. `sh -c` carries the whole
        # script as one argv token, so `match_contains` on the name is what tells
        # two otherwise identical `dig` invocations apart.
        #
        # **The domestic answer is EMPTY, because that is what this project's mock
        # router returns.** `dnsmasq.conf` carries `no-resolv` and one hardcoded
        # test-only name, so a China-set name gets SERVFAIL and `dig +short` prints
        # nothing — MEASURED on all three releases. The fixture used to answer
        # `DOMESTIC_ANSWER` here, which asserted against a fiction the mock cannot
        # produce, and the case that holds the answer check could not have caught
        # that.
        {"match": ["exec", TARGET, "sh", "-c"], "match_contains": FOREIGN_NAME,
         "stdout": routing.FOREIGN_ANSWER + "\n"},
        {"match": ["exec", CLIENT, "sh", "-c"], "match_contains": CHINA_NAME,
         "stdout": "\n"},
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
    package's own headline property — so it is a SKIP, and the rest of the step
    still runs.**

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

    **What the first version of this did was refuse the cell before asking
    anything**, so one plan contradiction cost the substance of the whole step:
    the per-name counters, the split, both transports and the answer/branch match
    were all written, all green against the fake, and never measured on a live
    cell on any release. A cell that refuses before it asks anything cannot tell
    a working split from a broken one.

    The plan's Global Constraint is explicit about this case — "A requirement a
    container cannot close is recorded **SKIPPED with its exact wording**. It is
    never closed by substituting a different kind of test, and a skip is never
    reported as a pass" — and this plan's own implementer chose required-skip →
    `incomplete` → exit 3 over `failed` → exit 1 in Task 4 Step 1, on the reasoning
    that a red matrix for something that is not a defect is the wrong disposition.
    The priority is not "how do I reach exit 0": a rule that exists so a run
    cannot reach 0 by declining to file an unclosable requirement must not be used
    as a reason not to file one.

    So: the client half is a **required skip carrying the plan's exact wording**,
    the target half runs for real, and the run is `incomplete` — never a pass.
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

    def loopback_only(self, **overrides):
        return self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup",
                 "stdout": self.LISTENERS_LOOPBACK_ONLY},
            ] + routing_rules(**overrides),
        )

    def test_a_loopback_only_router_files_the_client_vantage_point_as_a_required_skip(self):
        fake, result = self.loopback_only()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(
            len(result.skips), 1,
            f"the client half is unclosable and nothing was filed for it: {result.skips}",
        )
        skip = result.skips[0]
        self.assertTrue(skip.required, "a skip that is not required cannot refuse a pass")
        # **The exact wording, from the plan.** A skip that paraphrases the
        # requirement is a reader checking their memory of it rather than the
        # requirement, and the Global Constraint asks for the exact words so the
        # claim can be checked against the requirement and not against a summary.
        self.assertEqual(skip.requirement, routing.CLIENT_VANTAGE_POINT_REQUIREMENT)
        self.assertEqual(
            skip.requirement,
            "From a separate client container and from inside the target, query "
            "China-set and foreign test names.",
        )
        # And the reason names the measurement, not the symptom.
        self.assertIn(TARGET_ADDRESS, skip.reason)
        self.assertIn("reachable from another host", skip.reason)
        self.assertIn(self.LISTENERS_LOOPBACK_ONLY.splitlines()[0].split()[3], skip.reason)

    def test_the_split_is_measured_even_though_the_client_half_is_not(self):
        """**The substance of Step 6, measured, with the client half filed as a
        skip rather than used as an excuse.**

        This is the case the previous version could not have. A cell that refuses
        at the reachability check records no counters, no answers and no split, so
        on every release the assertions below were green against the fake and
        unmeasured against a container. Here they are exercised end to end with
        the listener table saying the client cannot be asked, and the four
        target-side queries are the ones that ran.
        """
        fake, result = self.loopback_only()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertTrue(
            record["branches_distinguished"],
            f"no split was measured: {sorted(record)}",
        )
        self.assertGreaterEqual(
            record["domestic_counters"].get(CHINA_NAME, 0), 1,
            f"the domestic listener never saw the China name: {record['domestic_counters']}",
        )
        # The foreign branch's forward is TCP, so the arrival is TCP and both
        # transports are checked by their ANSWERS instead -- both of which carry
        # the foreign branch's address. See
        # `test_both_transports_reached_the_foreign_branch_and_arrivals_were_tcp`.
        self.assertEqual(
            record["foreign_counters"].get(FOREIGN_NAME), {routing.FOREIGN_TRANSPORT: 1},
            f"the foreign listener did not count the one TCP arrival a working foreign branch "
            f"produces: {record['foreign_counters']}",
        )
        for transport in ("udp", "tcp"):
            self.assertEqual(
                record["answers"][f"target/foreign/{transport}"], routing.FOREIGN_ANSWER,
                f"the {transport} foreign query did not come back with the foreign branch's own "
                f"address, so that transport did not exercise the branch",
            )
        self.assertNotIn(CHINA_NAME, record["foreign_counters"])
        self.assertNotIn(FOREIGN_NAME, record["domestic_counters"])
        self.assertTrue(record["answers_match_their_branch"])
        # **Four queries, not eight**, and they are the target's: the client half
        # is not recorded as asked and then ignored, it is not asked.
        self.assertEqual(
            sorted(record["answers"]),
            sorted(
                f"target/{name_key}/{transport}"
                for name_key in ("domestic", "foreign")
                for transport in ("udp", "tcp")
            ),
            f"the answers recorded are {sorted(record['answers'])}",
        )
        asked_client = [line for line in self.asked_in(fake, CLIENT) if "dig" in line]
        self.assertEqual(
            asked_client, [],
            f"the client was asked {len(asked_client)} question(s) after the skip was filed: "
            f"{asked_client}",
        )
        asked_target = [line for line in self.asked_in(fake, TARGET) if "dig" in line]
        # **The count is of the SPLIT, not of every query the scenario makes.** The
        # section that measures a dead second upstream asks one more question after
        # the split, and a literal total here would make adding a measurement look
        # like a change to what is being measured.
        #
        # What is held is the shape: one question per name per transport, from the
        # vantage point that can ask, and the extra query after the split.
        split_queries = [line for line in asked_target if FOREIGN_NAME in line or CHINA_NAME in line]
        self.assertGreaterEqual(
            len(split_queries), 4,
            f"the target was asked {asked_target}, which does not contain a question per "
            f"name per transport for the split",
        )
        self.assertEqual(
            asked_target,
            split_queries + [line for line in asked_target if line not in split_queries],
            "the queries must be the split's queries and then the post-split ones",
        )

    def test_the_record_says_which_vantage_points_were_measured(self):
        """A reader of the evidence document has to be able to tell that the client
        half is unmeasured from the document alone, without reading the prose."""
        _fake, result = self.loopback_only()
        record = self.record(result)
        self.assertEqual(record["vantage_points_measured"], ["target"])
        self.assertEqual(record["client_vantage_point_measured"], False)
        self.assertEqual(record["client_vantage_point_reason"], "not bound on the bridge")
        self.assertIn("127.0.0.1:53", record["target_listeners"])
        self.assertNotIn(TARGET_ADDRESS, record["target_listeners"])

    def test_the_detail_does_not_claim_a_container_asked_nothing_was_asked(self):
        """**The sentence a reader is sent to the plan with has to be true of what
        the cell did.**

        The first version's refusal said "The queries asked from INSIDE the target
        do exercise both branches and do move both listeners' counters" — a claim
        about a measurement nobody had taken, one level down from the unfounded
        refusal `fc06e2a` fixed. Now the counters are measured, so the sentence is
        earned; and the *client* is named only as the vantage point that was not
        used, never as one that was.
        """
        _fake, result = self.loopback_only()
        self.assertIn(TARGET, result.detail)
        self.assertIn("skip", result.detail.lower())
        self.assertIn("not bound", result.detail.lower())
        self.assertNotIn(
            f"from the separate client container {CLIENT}", result.detail,
            "the detail says the client was asked when the cell did not ask it",
        )
        # And the measurement it now claims is in the record.
        record = self.record(result)
        self.assertIn(
            str(record["domestic_counters"].get(CHINA_NAME, 0)), result.detail,
            "the detail does not carry the count it claims was moved",
        )

    def test_a_version_with_this_skip_is_incomplete_and_never_passed(self):
        """**The disposition, asserted on the type the gate reads.**

        The plan says a skip is never reported as a pass, and `VersionResult.status`
        is where that is enforced — so a case that only checked the scenario's own
        `status` would leave the one thing a reader of the report sees unheld. This
        drives the real type with the real result.
        """
        _fake, result = self.loopback_only()
        version = report.VersionResult(
            version=VERSION, arch="amd64", scenarios=(result,),
            skips=tuple(result.skips), recorded=None,
        )
        self.assertEqual(version.status, report.STATUS_INCOMPLETE)
        self.assertNotEqual(version.status, report.STATUS_PASSED)
        # And the report's own exit-code mapping is what turns that into 3.
        self.assertEqual(
            report.EXIT_INCOMPLETE, 3,
            "the run's exit code for an incomplete matrix is not 3, so a required skip would "
            "not keep the run off a pass",
        )

    def test_each_vantage_point_asks_the_address_that_vantage_point_can_reach(self):
        """**The in-target queries were addressed to the target's BRIDGE address,
        so from inside the target they asked a socket nothing is bound to.**

        MEASURED, and it is a defect the refusal was hiding: the first
        three-release run of this round's code produced four answers of the shape

            (not readable: 'podman exec …-target-24.04 sh -c dig +short @10.89.0.10
             -p 53 probe.0033.cn' exited 9)

        on all three releases, and the cell then reported "the mock router's query
        log … does not carry a query within 60s". `dig` exits 9 for "no reply from
        server", and the reason there was no reply is that the router binds
        `127.0.0.1:53` — which is the same fact §1b has been reading the target's
        listener table to establish, and the same fact the loopback-only property
        is. The `ask` helper asked one address for both vantage points, so the
        half of the step this round exists to measure was asking a socket that
        does not exist.

        The two addresses are different *addresses of the same router*: the
        client's has to be the bridge address, or the client cannot reach it, and
        the target's has to be the loopback address, or nothing answers. So the
        address is a property of the vantage point, and the record carries which
        one each vantage used.
        """
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertEqual(
            record["vantage_point_addresses"],
            {"target": routing.TARGET_LOCAL_ADDRESS, "client": TARGET_ADDRESS},
        )
        self.assertEqual(routing.TARGET_LOCAL_ADDRESS, "127.0.0.1")
        # And the invocations, because a record field nobody asserted is a
        # sentence (ruling 190).
        fake, _result = self.run_scenario()
        for container, address in (
            (TARGET, routing.TARGET_LOCAL_ADDRESS),
            (CLIENT, TARGET_ADDRESS),
        ):
            asked = [line for line in self.asked_in(fake, container) if "dig" in line]
            # **Every query, not a fixed number of them.** The claim this case makes
            # is about the ADDRESS each question was addressed to, and a literal count
            # made it a claim about how many questions the scenario happens to ask --
            # so adding the measurement of a dead second upstream turned it red for
            # no reason the case was written to catch.
            self.assertGreaterEqual(
                len(asked), 4,
                f"{container} was asked {asked}, which is fewer questions than the split "
                f"needs -- one per name per transport",
            )
            for line in asked:
                self.assertIn(
                    f"@{address} -p 53", line,
                    f"{container} was asked {line!r}, which does not name the address that "
                    f"vantage point can reach",
                )
                self.assertNotIn(
                    f"@{routing.TARGET_LOCAL_ADDRESS} -p 53"
                    if address == TARGET_ADDRESS else f"@{TARGET_ADDRESS} -p 53",
                    line,
                    f"{container} was asked an address it cannot reach: {line!r}",
                )

    def test_a_domestic_name_the_mock_router_cannot_answer_still_measures_the_split(self):
        """**The domestic branch's ANSWER does not exist, and asking for one was
        this scenario asking for a fixture.**

        MEASURED, and it is the second thing the refusal was hiding. With the
        queries finally going to an address that exists, the foreign name comes
        back `198.51.100.7` over both transports and the China name comes back
        **nothing** — on all three releases:

            "answers": {"target/domestic/tcp": "", "target/domestic/udp": "",
                        "target/foreign/tcp": "198.51.100.7",
                        "target/foreign/udp": "198.51.100.7"}

        and the cell reported "at least one of the 4 queries returned nothing, so a
        branch was not exercised end to end". The reason is the mock's own
        configuration and it is deliberate:
        `tests/podman/mock-router/dnsmasq.conf` carries `no-resolv` — *"a mock
        router that forwarded would answer a test's questions from off this host"*
        — and exactly one hardcoded test-only name,

            address=/install-probe.example/10.89.0.2

        so every other name, a China-set one included, gets **SERVFAIL**: a
        resolver that reached nobody, which is a correct answer and is precisely
        what `emergency_rollback` checks for elsewhere in this project.

        So `DOMESTIC_ANSWER` was a fixture this project's own mock cannot produce,
        and requiring a non-empty answer for the domestic branch was the
        **answers-not-counters** mistake this scenario's own docstring is written
        against. The domestic branch's evidence is the mock's QUERY LOG, which is
        what the counters are; the cell measures it, and the answer is recorded
        beside it with the reason it is empty.
        """
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        for transport in ("udp", "tcp"):
            with self.subTest(transport=transport):
                self.assertEqual(
                    record["answers"][f"target/domestic/{transport}"], "",
                    "the fixture is answering the domestic queries and the real mock router "
                    "cannot: `no-resolv` with one test-only name SERVFAILs everything else. A "
                    "fixture that answers here is a fixture asserting against a fiction",
                )
                self.assertEqual(
                    record["answers"][f"target/foreign/{transport}"], routing.FOREIGN_ANSWER,
                )
        # The split is measured, and it is the whole claim.
        self.assertTrue(record["branches_distinguished"])
        self.assertGreaterEqual(record["domestic_counters"].get(CHINA_NAME, 0), 1)
        self.assertNotIn(FOREIGN_NAME, record["domestic_counters"])
        self.assertNotIn(CHINA_NAME, record["foreign_counters"])
        # And the record says why the domestic answers are empty, IN the record.
        self.assertIn("no-resolv", record["domestic_answers_note"])
        self.assertIn("SERVFAIL", record["domestic_answers_note"])
        self.assertIn("query log", record["domestic_answers_note"])

    def test_a_domestic_answer_carrying_the_foreign_branches_address_is_refused(self):
        """**The answer check that IS load-bearing, and the control for it.**

        A domestic query that came back with the FOREIGN branch's address would say
        the name went down the wrong branch even if the counters were read
        generously — so it is refused by answer as well as by counter. The third
        state is the interesting one: a domestic answer that is neither mock's
        address is ACCEPTED, because a SERVFAIL and an unrecognised address are both
        "not the foreign branch's answer", and the counters are what say what
        actually happened.
        """
        for answer, refused in (
            (routing.FOREIGN_ANSWER, True),
            ("", False),
            ("203.0.113.9", False),
        ):
            with self.subTest(answer=answer or "(empty)"):
                _fake, result = self.run_scenario(
                    rules=[
                        {"match": ["exec", TARGET, "sh", "-c"], "match_contains": CHINA_NAME,
                         "stdout": answer + "\n"},
                    ] + routing_rules(),
                )
                if refused:
                    self.assertEqual(result.status, "failed")
                    self.assertIn(routing.FOREIGN_ANSWER, result.detail)
                else:
                    self.assertEqual(result.status, "passed", result.detail)

    def test_a_router_also_bound_to_the_bridge_address_is_not_refused_for_that(self):
        # The control: the refusal is about the BINDING, not about the client. A
        # cell whose router does listen on the bridge address -- which is a
        # configuration this project does not ship, and which the plan's Task 4
        # Step 3 forbids -- must get past this check, ask the client, and file no
        # skip, or the case is a statement about the container rather than about
        # the binding.
        fake, result = self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup",
                 "stdout": self.LISTENERS_ON_THE_BRIDGE},
            ] + routing_rules(),
        )
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(result.skips, (), "a router that is reachable filed a skip")
        record = self.record(result)
        self.assertEqual(record["vantage_points_measured"], ["target", "client"])
        self.assertTrue(record["client_vantage_point_measured"])
        self.assertEqual(len(record["answers"]), 8)
        self.assertEqual(
            sorted(record["answers"]),
            sorted(
                f"{vantage}/{name_key}/{transport}"
                for vantage in ("target", "client")
                for name_key in ("domestic", "foreign")
                for transport in ("udp", "tcp")
            ),
        )
        self.assertIn(TARGET_ADDRESS, record["target_listeners"])

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

    def test_both_transports_reached_the_foreign_branch_and_arrivals_were_tcp(self):
        """**What the plan's "Repeat over UDP and TCP" is at each listener, measured.**

        This case used to assert a UDP count **and** a TCP count at the foreign
        mock, on the reasoning that "TCP is not a formality in Step 6". The
        measurement says that reasoning was inverted: the shipped configuration
        forwards the foreign branch over `tcp://127.0.0.1:15353`, so every arrival
        at the foreign listener is TCP and a UDP count there would mean something
        other than the configured forward got there.

        So the two transports are checked where they *are* observable:

        * at the **domestic** listener, the China-set name is counted **twice** --
          one question per transport, because nothing caches a REFUSED answer in
          front of dnsmasq; and
        * at the **foreign** listener, the arrival is **TCP**, and both foreign
          answers carry the foreign branch's address.

        And the per-transport evidence is required in both directions, because
        the second one is what makes the first meaningful: a count of one would
        pass a cell that asked one transport.
        """
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        counted = record["domestic_counters"].get(CHINA_NAME, 0)
        self.assertGreaterEqual(
            counted, 2,
            f"the China-set name was counted {counted} time(s) at the domestic listener. The cell "
            f"asks it over UDP and over TCP, and nothing in front of dnsmasq caches a REFUSED "
            f"answer, so both questions arrive and a count below two means one transport was not "
            f"exercised end to end",
        )
        self.assertEqual(
            record["foreign_counters"].get(FOREIGN_NAME), {routing.FOREIGN_TRANSPORT: 1},
            "the foreign listener did not count exactly one TCP arrival for the foreign name. The "
            "configured forward is TCP, so that is the shape a working foreign branch produces",
        )
        for transport in ("udp", "tcp"):
            with self.subTest(transport=transport):
                self.assertEqual(
                    record["answers"][f"target/foreign/{transport}"], routing.FOREIGN_ANSWER,
                    f"the {transport} query did not come back with the foreign branch's address, so "
                    f"that transport did not exercise the foreign branch end to end",
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

    def test_a_broken_split_is_a_failure_and_files_no_skip(self):
        """**A skip and a failure are different claims and must not be conflated.**

        A skip says a requirement cannot be closed by this configuration. A failure
        says something went wrong. A cell that measured a broken split AND filed
        the client-vantage-point skip would be reported `incomplete` -- a softer
        reading of the same red, and one where the routing defect is filed as a
        limitation of the environment.

        The shape here is the one the counters exist to catch: both names reached
        the foreign listener, so the split is not there. The listener table says
        the client is unreachable, so the skip WOULD be filed on a passing run --
        and the point is that it is not filed on a failing one.
        """
        rules = [
            {"match": ["sh", "-c"], "match_contains": "ss -lntup",
             "stdout": TheClientCannotReachALoopbackOnlyRouterTest.LISTENERS_LOOPBACK_ONLY},
        ] + routing_rules(
            foreign=counters_document(
                **{f"{FOREIGN_NAME}/udp": 1, f"{FOREIGN_NAME}/tcp": 1, f"{CHINA_NAME}/udp": 1},
            ),
        )
        _fake, result = self.run_scenario(rules=rules)
        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.skips, (),
            "a failed cell filed the unclosable-requirement skip, so a red routing result would "
            "be reported as an incomplete matrix",
        )
        self.assertIn(CHINA_NAME, result.detail)

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
                dnsmasq_query_line(FOREIGN_NAME)
                + "\ndnsmasq[1]: config error is REFUSED (EDE: not ready)\n"
            )
        )
        self.assertEqual(result.status, "failed")
        self.assertIn(FOREIGN_NAME, result.detail)

    def test_a_foreign_name_the_foreign_listener_saw_only_over_udp_is_refused(self):
        """**Same assertion, restated from the measurement, and it is about the
        configured forward rather than about a transport.**

        This case used to hold "a foreign name answered only over UDP is refused",
        with the reasoning "TCP is not a formality in Step 6". That reasoning was
        backwards: the shipped config forwards the foreign branch over
        `tcp://127.0.0.1:15353`, so **every** arrival at the foreign listener from
        this router is TCP, and a UDP arrival means something other than the
        configured forward got there. Refusing it is right; refusing it *as a
        missing TCP count* was not, because the count that mattered is a TCP count
        and a UDP count is a different anomaly with a different cause.
        """
        _fake, result = self.run_scenario(
            foreign=counters_document(**{f"{FOREIGN_NAME}/udp": 2}),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("tcp", result.detail.lower())
        self.assertIn(
            "forward",
            result.detail.lower(),
            "the refusal does not say that the arrival did not come from the configured forward, "
            "which is what a UDP arrival at this listener means",
        )

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
                dnsmasq_query_line(FOREIGN_NAME)
                + "\ndnsmasq[1]: config error is REFUSED (EDE: not ready)\n"
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


class TheForeignCounterIsNotATransportOfTheRouterTest(RoutingScenarioHarness):
    """**The cell required a dnscrypt-proxy cache miss and called it "the repeat
    over UDP and TCP".**

    MEASURED, run `20261001T003952Z`, 24.04, everything else in this round
    working — the domestic counter read `{"api.cloudflare.com": 4,
    "probe.0033.cn": 2}`, so the China-set name reached the mock router **twice**,
    one question per transport — and the cell refused:

    ```text
    routing: the mock foreign resolver counted no UDP query for
    'foreign-routing.test', so the foreign branch was not exercised over UDP.
    It counted ['api.cloudflare.com', 'api.github.com', 'foreign-routing.test',
    'install-probe.example']
    ```

    And the counters say:

    ```json
    "foreign-routing.test": { "tcp": 1 },
    "install-probe.example": { "tcp": 2, "udp": 2 }
    ```

    **The foreign name reached the foreign listener, once, and both of the
    foreign-branch answers carried the foreign mock's address** --
    `answers` records `target/foreign/udp = 198.51.100.7` and
    `target/foreign/tcp = 198.51.100.7`. So the branch worked over both
    transports and the counter still said one of them was never asked. Two
    measured facts explain it, and neither is about a transport:

    * **The router forwards the foreign branch over TCP.** `configs/mosdns.yaml`
      says `foreign_upstream: tcp://127.0.0.1:15353` and
      `addr: tcp://127.0.0.1:15353`. A `dig +short` over UDP and a `dig +short
      +tcp` from a client both arrive at mosdns on their own transport and both
      leave it over **TCP**, so the mock foreign resolver can only ever see TCP
      from this cell's vantage point.
    * **dnscrypt-proxy caches.** It answered the second query itself, so the
      second never arrived. That is what a resolver in front of a mock does, and
      the foreign mock's per-transport counter is a measure of **how many times
      that cache missed** -- which is why `install-probe.example`, asked by the
      installer through the same path, shows both `tcp: 2` and `udp: 2`: something
      in that exchange re-queried, and the cell has no account of what.

    So the assertion `foreign_counters[name]["udp"] >= 1` is asserting a cache
    miss. It would pass or fail with the resolver's cache state and with nothing
    about this project's routing, and the message it produces names the transport
    -- which is the most misleading sentence in this scenario, because a reader
    who believes it would go looking for a router that ignored UDP.

    **What is true and is asserted instead**, all three of it measured above:
    the foreign name reached the foreign listener; both foreign-branch answers
    carried the foreign branch's address; and the China-set name never reached the
    foreign listener at all. The per-transport split at the *domestic* listener is
    the one that does correspond to what the router was asked, and it is a count
    of two rather than a pair.
    """

    def run_with_foreign_counted(self, counted):
        _fake, result = self.run_scenario(
            rules=[
                {"match": ["sh", "-c"], "match_contains": "ss -lntup",
                 "stdout": TheClientCannotReachALoopbackOnlyRouterTest.LISTENERS_LOOPBACK_ONLY},
            ] + routing_rules(foreign=counters_document(**counted)),
        )
        return result

    def test_a_foreign_name_counted_once_over_tcp_is_the_split_being_measured(self):
        """The real cell's shape, verbatim: one TCP arrival, both transports asked."""
        result = self.run_with_foreign_counted({f"{FOREIGN_NAME}/tcp": 1})
        self.assertEqual(
            result.status, "passed",
            "the foreign branch reached the foreign listener and answered both queries with the "
            "foreign address, and the cell refused it for a UDP arrival the router cannot make: "
            f"{result.detail}",
        )
        record = self.record(result)
        self.assertTrue(record["branches_distinguished"])
        self.assertEqual(record["answers"]["target/foreign/udp"], routing.FOREIGN_ANSWER)
        self.assertEqual(record["answers"]["target/foreign/tcp"], routing.FOREIGN_ANSWER)
        # And the domestic listener saw the China name once per transport asked,
        # which is the per-transport evidence this configuration can give.
        self.assertGreaterEqual(record["domestic_counters"].get(CHINA_NAME, 0), 2)

    def test_a_foreign_name_the_foreign_listener_never_saw_is_still_a_failure(self):
        """The control, and it is the one that keeps the loosened requirement honest.

        Requiring an arrival rather than an arrival *per transport* must not
        become requiring nothing: a foreign branch that never reached the foreign
        listener is the defect this counter exists to catch, and it is still
        refused.
        """
        # The document carries a DIFFERENT name, so the read succeeds and the
        # split assertion is what refuses -- rather than the wait for a
        # counters document to carry anything at all, which is a harness refusal
        # about the same fact and would let this case pass for the wrong reason.
        result = self.run_with_foreign_counted({"api.github.com/tcp": 1})
        self.assertEqual(result.status, "failed")
        self.assertIn(FOREIGN_NAME, result.detail)
        self.assertIn(
            "never reached",
            result.detail,
            "the refusal does not say the foreign listener was never reached for that name, which "
            "is the finding",
        )

    def test_the_record_says_the_foreign_split_measures_the_resolvers_cache(self):
        """**And it says so in the record, not only in this file.**

        A reader of the evidence document holds two numbers: the foreign mock's
        `{name: {udp: n, tcp: m}}` and the domestic listener's plain count. The
        first looks like a per-transport split of what the router was asked and is
        not; the second looks like a total and is the per-transport evidence. Both
        readings are wrong unless the document says which is which, and a reader
        has no way to work it out from the numbers.
        """
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        for field in ("domestic_counters_transport", "foreign_counters_transport"):
            with self.subTest(field=field):
                self.assertIn(
                    field, record,
                    "the record does not say how each listener's numbers were produced, so the two "
                    "counters in it cannot be compared by a reader",
                )
        self.assertIn(
            "cache", record["foreign_counters_transport"],
            "the record does not say that the foreign mock's transport split measures dnscrypt-"
            "proxy's cache misses rather than what the router was asked",
        )
        self.assertIn(
            "tcp://127.0.0.1:15353", record["foreign_counters_transport"],
            "the record does not name the configured forward, which is why only one transport "
            "can ever appear at the foreign listener",
        )

class TheDomesticCounterIsCountedFromTheLinesDnsmasqWritesTest(unittest.TestCase):
    """**`router_queries` counted the word `error`, six times, and called it a
    routing result.**

    MEASURED, run `20261001T003319Z`, 24.04, with the two defects of this round's
    first half already fixed (`log-queries` set, and the log read through the
    reader that sees stderr). The mock router's log is now readable, and it says:

    ```text
    dnsmasq[1]: query[A] probe.0033.cn from 10.89.0.168
    dnsmasq[1]: config error is REFUSED (EDE: not ready)
    dnsmasq[1]: query[A] probe.0033.cn from 10.89.0.168
    dnsmasq[1]: config error is REFUSED (EDE: not ready)
    ```

    **The China-set name reached the mock router, twice — one per transport.** The
    domestic branch works. And the cell reported

    ```text
    routing: the mock router's log carries no query for the China-set name
    'probe.0033.cn', so the domestic branch was not exercised. Its counted names
    are: ['error']
    ```

    because `router_queries` recognises a query by a `reply to` marker and reads
    the name as the field before it, and dnsmasq 2.91's `log-queries` **writes the
    answer on a separate line that carries no name at all**:

    ```text
    query[A] probe.0033.cn from 10.89.0.168     <- the query: name and client
    config error is REFUSED (EDE: not ready)    <- the answer: no name, no client
    ```

    So the marker `is REFUSED` matched on the *answer* line and the field before
    it was the word `error`. Six such lines across the cell — four
    `api.cloudflare.com` and two `probe.0033.cn` — and the count came out
    `{"error": 6}`.

    The docstring documents the *wrong* shape, quoting a syslog-with-facility line
    (`Sep 30 20:00:00 hostname 10.89.0.10 probe.example.cn is 10.89.0.2`) that this
    dnsmasq, in a container with `log-facility=-`, never prints. So the parser was
    written against a line a fixture invented -- the same class as the bridge's
    bare-address fixtures and the `ActiveState` rule that matched nothing, and the
    third time in this project that **the harness's own evidence has been a
    fixture agreeing with a parser and neither agreeing with the program**.

    And the failure is the worst kind: it is a **routing result**. The refusal says
    "the domestic branch was not exercised", names the name it looked for, and
    calls what it found "counted names". A reader has no way to know that the
    split was measured correctly two lines above.
    """

    # The lines, verbatim from run 20261001T003319Z's 24.04 cell. Trimmed of the
    # DHCP exchange and dnsmasq's banner, and left otherwise untouched -- the
    # whole defect is in these exact characters.
    REAL_LOG = "\n".join(
        [
            "dnsmasq[1]: started, version 2.91 cachesize 150",
            "dnsmasq[1]: warning: no upstream servers configured",
            "dnsmasq-dhcp[1]: DHCP, IP range 10.89.0.100 -- 10.89.0.199, lease time 5m",
            "dnsmasq-dhcp[1]: 2249392984 DHCPDISCOVER(eth0) b6:68:81:b7:90:a0 ",
            "dnsmasq-dhcp[1]: 2249392984 DHCPACK(eth0) 10.89.0.168 b6:68:81:b7:90:a0 dd64d35d826a",
            "dnsmasq-dhcp[1]: 2249392984 sent size:  4 option:  6 dns-server  10.89.0.2",
            "dnsmasq-dhcp[1]: 2249392984 DHCPACK(eth0) 10.89.0.168 b6:68:81:b7:90:a0 dd64d35d826a",
            "dnsmasq[1]: query[AAAA] api.cloudflare.com from 10.89.0.168",
            "dnsmasq[1]: config error is REFUSED (EDE: not ready)",
            "dnsmasq[1]: query[A] api.cloudflare.com from 10.89.0.168",
            "dnsmasq[1]: config error is REFUSED (EDE: not ready)",
            "dnsmasq[1]: query[A] probe.0033.cn from 10.89.0.168",
            "dnsmasq[1]: config error is REFUSED (EDE: not ready)",
            "dnsmasq[1]: query[A] probe.0033.cn from 10.89.0.168",
            "dnsmasq[1]: config error is REFUSED (EDE: not ready)",
        ]
    )

    def counts(self, log=None):
        return routing.router_queries(self.REAL_LOG if log is None else log)

    def test_the_china_name_is_counted_twice_from_the_lines_dnsmasq_really_writes(self):
        """The whole of it, on the log the cell actually produced.

        Two lines for one name is the shape the plan's "Repeat over UDP and TCP"
        produces at this listener, so the count of two is not a detail: it is the
        evidence that both transports reached the domestic upstream. At this
        listener that evidence is the *count* and not a per-transport split --
        dnsmasq's `log-queries` records the query type and not the transport --
        and `test_the_domestic_counter_says_it_cannot_see_a_transport` holds that
        the record says so rather than implying a split it does not have.
        """
        self.assertEqual(
            self.counts().get("probe.0033.cn"), 2,
            "the China-set name reached the mock router twice in the cell's own log and the "
            "counter does not see it. The measured log is in this case's docstring; the parser "
            "recognises a query by an answer-side marker that this dnsmasq writes on a separate "
            "line carrying no name, so it reads the word before `is REFUSED` as the name",
        )

    def test_a_name_nobody_asked_about_is_absent(self):
        """The other half, and it is the half that makes the count worth having.

        `api.cloudflare.com` is in the log because the install's list refresh asked
        the mock router directly. A parser that counted everything would put it in
        the same document as the routing measurement, and the cell's assertion that
        the **foreign** name is absent from the domestic listener would then be
        asserting against a document that mixes the install's own questions in.
        """
        counts = self.counts()
        self.assertEqual(counts.get("api.cloudflare.com"), 2)
        self.assertNotIn(
            "foreign-routing.test", counts,
            "a name the foreign branch asked for is in the domestic listener's log, so the split "
            "is broken and this parser is counting something other than what reached it",
        )

    def test_no_dhcp_line_and_no_banner_line_is_counted_as_a_query(self):
        """A DHCP exchange is not a DNS query, and the banner is not anything.

        The old parser's `marker < 1` guard was doing this job by accident, on a
        shape that never occurred. On the real shape the recognition is `query[`,
        which cannot match `DHCPDISCOVER(eth0)` or `DHCPACK(eth0)` or
        `sent size: 4 option: 6 dns-server 10.89.0.2` -- and the last of those is
        the dangerous one, because it is a line about a **DNS server address** and
        a positional parser would read `dns-server` as a name.
        """
        counts = self.counts()
        for name in ("dhcpdiscover(eth0)", "dhcpack(eth0)", "dhcp,", "dns-server", "started,", "warning:"):
            with self.subTest(name=name):
                self.assertNotIn(
                    name, counts,
                    "a line that is not a DNS query was counted as one. dnsmasq's `log-dhcp` "
                    "prints `sent size: 4 option: 6 dns-server 10.89.0.2`, which is a line about "
                    "a DNS server ADDRESS and the closest thing in this log to a query line",
                )
        self.assertEqual(sum(counts.values()), 4, "the four DNS query lines are the whole of it")

    def test_the_parser_documents_the_shape_this_dnsmasq_prints(self):
        """**The docstring is what the next reader implements from.**

        The old one quoted
        `Sep 30 20:00:00 hostname 10.89.0.10 probe.example.cn is 10.89.0.2` -- a
        syslog line with a hostname and a client address in front of the name --
        and dnsmasq in a container with `log-facility=-` prints neither. So the
        documented shape and the real shape disagreed, and the parser followed the
        documentation because the documentation was the only shape anyone had
        written down.
        """
        doc = routing.router_queries.__doc__ or ""
        self.assertIn(
            "query[", doc,
            "the parser's docstring does not name the `query[` line this dnsmasq prints, so the "
            "shape it documents is not the shape the mock writes",
        )
        # **The check is on the CLAIM, not on the string**, and for the reason the
        # plan's `dhcp-option` case uses: the correction is allowed to quote the
        # line it is correcting, because a reader who remembers
        # `Sep 30 20:00:00 hostname 10.89.0.10 …` and finds nothing saying it is
        # wrong learns nothing from the absence. What has to be there is the
        # sentence saying a container prints no such line -- and what must NOT be
        # there is a parser that still recognises an answer-side marker, which is
        # the mechanical half of the same claim.
        self.assertIn(
            "never prints",
            doc,
            "the parser's docstring quotes the syslog line it used to be written against but does "
            "not say that a container with `log-facility=-` never prints one, so a reader cannot "
            "tell which of the two quoted shapes this parser implements",
        )


    def test_a_queried_name_is_normalised_so_the_set_can_be_compared_with_it(self):
        """Case and the trailing dot, because the China set is compared with this count.

        `matches_china_set` lowercases and strips a trailing dot from the name it
        is asked about, and the published list carries `domain:0033.cn`. So a
        counter that returned `probe.0033.cn.` would compare unequal to a set
        entry built the other way, and the cell would refuse a split it had
        measured. dnsmasq echoes the name as it arrived, which for a query with a
        trailing dot has one, and for a randomised-case query is mixed.
        """
        for asked in ("probe.0033.cn", "probe.0033.cn.", "PROBE.0033.CN", "Probe.0033.Cn."):
            with self.subTest(asked=asked):
                counts = routing.router_queries(f"dnsmasq[1]: query[A] {asked} from 10.89.0.168")
                self.assertEqual(
                    list(counts), ["probe.0033.cn"],
                    f"the name {asked!r} was counted as something that cannot be compared with "
                    f"the published China set",
                )

    def test_the_count_says_it_cannot_see_a_transport(self):
        """**And the record has to admit the domestic counter is not per-transport.**

        The plan asks for per-name counters at both listeners and for the repeat
        over UDP and TCP. At the foreign listener the mock publishes
        `{name: {udp: n, tcp: m}}` and both are there. At the domestic one
        dnsmasq records `query[<TYPE>] <name> from <client>` and **no transport at
        all** -- the plan's "Repeat over UDP and TCP" is visible here only as a
        count of two. So the record says that, rather than carrying a number that
        reads as a per-transport split it is not, and the foreign side is left as
        the one that has it.
        """
        source = (SCENARIOS / "routing_test.py").read_text(encoding="utf-8")
        self.assertIn(
            "domestic_counters_transport",
            source,
            "the record never says that the domestic counter cannot distinguish UDP from TCP, so a "
            "reader comparing the two listeners' documents would compare a per-name count against "
            "a per-transport one and conclude the domestic side is missing half the measurement",
        )
        self.assertIn(
            "no transport",
            source,
            "the record does not say in words why the domestic side has no per-transport split, so "
            "the field is a name and not an explanation",
        )

class ThePlanAgreesWithTheRoutingCellTest(unittest.TestCase):
    """**The plan is the file a reader of the diff alone sees, so the amendment
    lives there and is held from here.**

    Ruling 184: a claim that was stated and then corrected in place must be
    corrected in the file a reader of the diff alone sees. The three task reports
    live under `.superpowers/`, which `.gitignore` excludes and no commit carries,
    so a correction in one of them is a blockquote appended *after* the sentence
    it corrects. Ruling 178's precedent is the plan itself: Task 3's sentences
    still said the opposite two lines below a corrected one, and a case now holds
    the plan against the code over the WHOLE document rather than a region.

    Two claims are corrected here, and each was a live defect:

    * **Step 6 presented the client vantage point as a thing to do**, and it is
      not one: Step 3 asserts loopback-only listeners, so nothing on this project
      is reachable from another host. The step now says the two cannot both hold,
      that the client vantage point is recorded as a required skip with its exact
      wording, and that the rest of the step runs for real.
    * **Step 5 named `/etc/mosdns/config.yaml`, a file this project does not
      ship.** The two documents it ships are `mosdns.yaml` and
      `dnscrypt-proxy.toml`, and it is the latter that names the foreign resolver.
      A later task reading Step 5 would have looked for a file that has never
      existed.
    """

    @classmethod
    def setUpClass(cls):
        cls.plan = (
            REPO / "docs" / "superpowers" / "plans" / "2026-09-25-podman-integration-matrix.md"
        ).read_text(encoding="utf-8")

    def test_the_requirement_the_scenario_skips_is_the_plans_own_sentence(self):
        """**The skip carries the plan's exact words, so the two cannot drift.**

        A `Skip` whose `requirement` is a transcription of the plan is a claim a
        reader checks against the plan. If the plan's sentence is edited and the
        constant is not, the skip is still a well-formed skip of a requirement
        nobody wrote any more — and the Global Constraint's "with its exact
        wording" becomes a promise about a string. So the constant is a substring
        of the plan, and a case says so.
        """
        self.assertIn(
            routing.CLIENT_VANTAGE_POINT_REQUIREMENT, self.plan,
            "the requirement the routing cell records as a SKIP is not a sentence of the plan, so "
            "'with its exact wording' is a promise about a transcription. Either the plan's Step 6 "
            "was rewritten or the constant was typed from memory",
        )

    def test_the_plan_says_the_two_vantage_points_cannot_both_hold(self):
        """**Step 6 must not present the client half as a thing to do.**

        The defect is a *presentational* one and it is the kind that costs the
        most: a next implementer reads Step 6, sees two vantage points, builds a
        client, watches `dig @10.89.0.10` time out, and either concludes the
        harness is broken or binds a listener the packaging forbids. So the step
        says the contradiction, says which half is recorded as a skip, and says
        the other half runs.
        """
        for needle, what in (
            ("cannot both hold", "the plan does not say the two requirements contradict each other"),
            ("required skip", "the plan does not say the client vantage point is recorded as a skip"),
            ("incomplete", "the plan does not say what the run's disposition becomes"),
            ("reachable from another host", "the plan does not cite the packaging's own reason"),
        ):
            with self.subTest(needle=what):
                self.assertIn(needle, self.plan)

    def test_the_plan_does_not_offer_a_workaround_the_packaging_forbids(self):
        """**The two non-options are named as non-options, and so is why.**

        Exposing the router on the bridge weakens a property
        `packaging/debian/control` states in the package's own Description, and a
        shared network namespace makes the client's `127.0.0.1` the target's own —
        the same socket asked by the same `dig`, which is a second vantage point in
        name only. Both were considered and both are wrong; a plan that records
        only the conclusion leaves the next implementer to re-derive them, and the
        namespace one looks like a solution until you say what it is.
        """
        self.assertIn("network namespace", self.plan)
        self.assertIn("name only", self.plan)
        self.assertIn("packaging/debian/control", self.plan)

    def test_the_plans_step_3_says_why_its_loopback_clause_binds_step_six(self):
        """**Step 3's "only loopback listeners" is a security property, and the
        step says so.**

        Step 3 is where the router's own configuration is validated, and its
        loopback clause is what makes Step 6's client half unclosable. A reader
        arriving at Step 6 has to be able to find the reason where it is written
        down, and a reader arriving at Step 3 has to know that changing the clause
        would change another step's outcome. A case on each sentence is cheap; the
        two steps silently contradicting each other is not.
        """
        self.assertIn("load-bearing for Step 6", self.plan)
        self.assertIn("security property rather than a convenience", self.plan)

    def test_the_plans_step_5_names_a_document_this_project_ships(self):
        """**`/etc/mosdns/config.yaml` is a file that has never existed here.**

        The two documents this project installs are `mosdns.yaml` and
        `dnscrypt-proxy.toml`, and it is the DNSCrypt document that names the
        foreign resolver — the `mosdns.yaml` document is the router's own policy
        and is what Step 6's domestic branch runs on. A later task reading Step 5
        for a file that is not there would have no way to know the name was wrong
        rather than that the step was out of date.

        **The check is on the CLAIM, not on the path**, and that is the precedent
        Task 2 set with the `dhcp-option` line: the amendment is allowed to name
        the wrong path in order to say it is wrong, and a bare search for the
        string would forbid the correction along with the error. So the
        instruction is forbidden and the correction is required.
        """
        self.assertNotIn(
            "copy a modified `/etc/mosdns/config.yaml`", self.plan,
            "the plan still tells the next implementer to copy a document this project does not "
            "ship. The two it installs are /etc/mosdns/mosdns.yaml and "
            "/etc/mosdns/dnscrypt-proxy.toml",
        )
        self.assertIn("/etc/mosdns/dnscrypt-proxy.toml", self.plan)
        # And the amendment says which of the two is the foreign branch's, and
        # that the other is the one that must be left alone.
        self.assertIn(
            "is a file this project does not ship", self.plan,
            "the plan no longer names the wrong document but does not say it was wrong, so the next "
            "reader cannot tell an oversight from a decision",
        )
        self.assertIn("mosdns.yaml", self.plan)
        self.assertIn(
            "what Step 6's domestic branch runs on", self.plan,
            "the plan does not say which of the two documents is the router's own policy, so "
            "'copy a modified <document>' would still be ambiguous",
        )

    def test_the_plans_step_5_names_both_assertions_the_shipped_documents_get(self):
        """**"Asserted separately" has to name the assertions, or it is a promise.**

        The DNSCrypt document is digested three ways and the router document is
        digested in the target and required byte-equal to the repository's — the
        second of which is the assertion that was MISSING when the plan said
        "Production shipped config and packaged DNSCrypt config remain unchanged
        and are asserted separately", and the gap let the domestic branch's policy
        be a file no assertion touched. So the step names both.
        """
        for needle, what in (
            ("byte-equal", "the plan does not say the two digests must be equal"),
            ("configs/mosdns.yaml", "the plan does not name the repository's router document"),
        ):
            with self.subTest(needle=what):
                self.assertIn(needle, self.plan)


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


class ADeadSecondUpstreamStillAnswersTest(RoutingScenarioHarness):
    """The claim `concurrent: 2` exists for, measured where it can only be measured.

    Everything else in this file can be measured on a host with a route to the
    internet. This cannot: the second upstream the shipped policy names is a DoQ
    endpoint on the public internet, and the matrix cell has no route off its own
    bridge. So the cell is the only place where "one upstream is unreachable and the
    query is still answered" can be observed against the shipped configuration.

    **And the unreachable upstream is not measured by a counter, because nothing
    receives its queries.** mosdns logs a Warn naming the upstream it could not
    reach, and that line is the only evidence in this cell that it was asked at all.
    The counter measures the other half -- that the query was still answered by the
    upstream that CAN be reached -- and the two together are the claim.
    """

    def test_the_query_is_answered_even_though_the_second_upstream_is_dead(self):
        _fake, result = self.run_scenario()
        # "passed", not "incomplete": the whole point of the classification above is
        # that the client vantage point is filed as a required skip and the REST still
        # runs. A cell that reported `incomplete` here would be a cell that measured
        # nothing, which is the defect the classification was written to prevent.
        self.assertEqual(
            result.status, "passed",
            f"the routing cell measured the split and the dead upstream and reported "
            f"{result.status}: {result.detail}",
        )
        record = self.record(result)
        self.assertIn(
            routing.FOREIGN_ANSWER, record.get("answer_after_dead_upstream", ""),
            f"after the router tried and failed to reach {routing.SECOND_UPSTREAM} the "
            f"foreign name answered {record.get('answer_after_dead_upstream')!r}, which does "
            f"not carry the foreign branch's answer. Racing two upstreams exists so that one "
            f"unreachable upstream does not stop the query",
        )

    def test_the_dead_upstream_is_recorded_as_having_been_tried(self):
        """The half that makes the case worth anything.

        Asserting only "the query succeeded" would pass against a document with ONE
        upstream -- and one upstream is exactly the configuration this change moves
        away from. So the record has to say the second upstream was dialled, and the
        only thing in this cell that can say it is the router's own log.
        """
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertTrue(
            record.get("dead_upstream_was_tried"),
            "the record does not say the second upstream was tried, so this cell cannot "
            "tell a racing route from a single-upstream one -- which is the only thing it "
            "was added to measure",
        )
        self.assertIn(
            routing.SECOND_UPSTREAM, record.get("router_log_for_upstreams", ""),
            "the record says the upstream was tried but carries no log line naming it",
        )

    def test_the_installed_document_must_name_both_upstreams(self):
        """The precondition, and it is refused rather than passed over.

        A document with one upstream would make every assertion above pass while
        measuring nothing: the query would succeed, and the log would never name the
        second upstream. So the cell first checks the installed document names it --
        read from the INSTALLED file, because that is what the router loaded, and a
        policy the renderer dropped an entry from is the failure this catches.
        """
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertIn(
            routing.SECOND_UPSTREAM, record.get("rendered_upstreams", []),
            f"the installed routing document names {record.get('rendered_upstreams')}, which "
            f"does not include {routing.SECOND_UPSTREAM}. This cell measures a route that "
            f"races two upstreams; a document with one measures something else",
        )

    def test_a_document_without_the_second_upstream_is_refused_not_passed(self):
        """**The mutation, as a case.** This is what makes the section above a
        measurement rather than a comment: the same document minus its second
        upstream must be REFUSED by the cell.

        Without this case the section could pass on a cell whose document never named
        the second upstream, and the reader of a green report would have no way to
        tell which configuration was measured.
        """
        rules = routing_rules()
        rules.insert(
            0,
            {"match": ["exec", TARGET, "cat", "/etc/mosdns/mosdns.yaml"],
             "stdout": rendered_document(upstreams=["tcp://127.0.0.1:15353"])},
        )
        _fake, result = self.run_scenario(rules=rules)
        self.assertEqual(
            result.status, "failed",
            "a cell whose installed document names no second upstream was reported as "
            f"{result.status}, so a green report cannot be told apart from one that "
            f"measured a single-upstream route",
        )
        self.assertIn(
            routing.SECOND_UPSTREAM, result.detail,
            f"the refusal does not name the upstream it wanted: {result.detail}",
        )

    def test_a_router_that_never_tried_the_second_upstream_is_refused(self):
        """**The other mutation, as a case.** This is `concurrent: 1` wearing the
        same document: the router answers, the log never mentions the second
        upstream, and every "the query succeeded" assertion still passes.

        So the cell must refuse, because the thing it is here to measure did not
        happen. Without this case the section would be satisfied by a router that
        asked exactly one upstream -- which is the default mosdns ships and the one
        this change deliberately moved away from.
        """
        _fake, result = self.run_scenario(dead_upstream_warned=False)
        self.assertEqual(
            result.status, "failed",
            "a router that never mentioned the second upstream was reported as "
            f"{result.status}. Asking one upstream and asking two look identical from the "
            f"answer alone, which is why this is refused rather than passed",
        )
        self.assertIn(
            routing.SECOND_UPSTREAM, result.detail,
            f"the refusal does not name the upstream it expected to see tried: {result.detail}",
        )


if __name__ == "__main__":
    unittest.main()
