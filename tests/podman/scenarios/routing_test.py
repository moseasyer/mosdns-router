"""DNS routing, read from the two mock listeners' own counters.

Task 4 Step 6: *from a separate client container and from inside the target,
query China-set and foreign test names. Assert query counters at mock domestic and
mock foreign listeners. Repeat over UDP and TCP.*

Every word of that is load-bearing, and this file is the shape that makes them
so.

**Counters, and why not answers.** An answer coming back proves somebody
answered. A router that sent *every* name down one branch satisfies that
completely, resolves everything, and has no split at all -- which is the property
under test. So what is asserted here is a count per *name* at each of the two
listeners, and the assertions are deliberately asymmetric: the China name is
required at the domestic listener and required **absent** from the foreign one,
and the foreign name the other way round. A total would be satisfied by both
branches being the same branch; a per-name count cannot be.

**Both transports, and the vantage points the configuration can serve.** UDP and
TCP are asked separately, and a name that arrived only over UDP fails the cell: a
scenario that dropped TCP would still resolve every name it asked, and Step 6
asks for the repeat.

The *vantage points* are whatever the target's own listener table says it can
serve, which against the configuration this project ships is **one**: the router
binds `127.0.0.1:53` and nothing else, so a client container on this bridge
cannot ask it anything. The plan's Task 4 Step 3 asks for loopback listeners only,
so Step 6's client half and Step 3 cannot both hold; the plan's own Global
Constraints say what to do with a requirement a container cannot close, and this
is that -- record it as a REQUIRED SKIP carrying the requirement's exact wording,
run the rest of the step for real, and let the run be `incomplete`.

**A cell that refuses before it asks anything cannot tell a working split from a
broken one.** The first version of this file refused at the reachability check, so
one plan contradiction cost the substance of the whole step: the per-name,
per-transport counters below were written, were green against the fake, and had
never been measured on a live cell on any release. So the reachability read is a
*classification* and not a verdict, the rest of the step runs either way, and the
evidence document records which vantage points produced the numbers.

**How a client's answer is known to have come through the target.** A client
container on the private network has the mock router available to it, so an
answer it receives is not by itself evidence about the target. The scenario
therefore puts the *target's* address in the client's `/etc/resolv.conf` -- the
one resolver the client can ask is the target -- and then reads the two mocks'
counters, which are what the target's own forwarding reached. The client's
`resolv.conf` is read and recorded whether or not the client ends up being asked,
so a reader of the evidence document sees which resolver it *could* have asked;
and a client whose resolver is *not* the target is refused rather than measured.

**The two names, and where they come from.** The China-set name is read out of
the *published* `/var/lib/mosdns/lists/cn-domains.txt`, not written down here: a
literal would be a name this project chose rather than a name the router is
configured to route domestically, and a re-pin that dropped it would leave the
cell asking about a name the foreign branch takes -- so the counters would
disagree for a reason the evidence document would not describe. The foreign name
is chosen to be *definitely* outside the China set, and that is asserted rather
than assumed: it is checked against the published list.

**What is deliberately not claimed.** Nothing here says anything about IPv6. No
cell in this scenario asks an AAAA question, and 22.04, 24.04 and 26.04 differ in
what they do with it, so an assertion about its absence would be a claim about a
property nothing here exercises.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

from podman import PodmanError
from report import ScenarioResult, Skip

SCENARIO_NAME = "routing"

# The run's private network, as `dhcp_test.py` fixes it and as the plan's table
# does. The two listener addresses are the whole of what this scenario's split
# rests on, so they are named and compared rather than computed.
MOCK_ROUTER_ADDRESS = "10.89.0.2"
TARGET_ADDRESS = "10.89.0.10"
MOCK_FOREIGN_ADDRESS = "10.89.0.40"
CLIENT_ADDRESS = "10.89.0.30"

# **The router's own loopback address, which is where the TARGET asks it and NOT
# where the client does.** MEASURED, and it is a defect the refusal in section 1b
# was hiding: `ask` used one address for both vantage points, so the queries asked
# from inside the target went to `10.89.0.10` -- the bridge address, which the
# router does not bind -- and all four came back `exited 9` ("no reply from
# server") on all three releases, after which the cell reported that the mock
# router's query log did not carry a query. The half of the step this round exists
# to measure was asking a socket that does not exist.
#
# The two are the same router at two addresses, and which one a vantage point can
# reach is the whole difference: the client has no `127.0.0.1` that is the
# target's, and the target has nothing bound to its own bridge address. So the
# address is a property of the vantage point, and the evidence document carries
# which one each used.
TARGET_LOCAL_ADDRESS = "127.0.0.1"

# The published China list, inside the target. Read for the China-set test name
# and to prove the foreign one is outside it.
PUBLISHED_CN_LIST = "/var/lib/mosdns/lists/cn-domains.txt"

# Where the mock foreign resolver publishes its counters, inside its own
# container. The path is the one `mock-foreign.Containerfile`'s `CMD` passes to
# `--counters`, and it is read with `podman exec cat` rather than by parsing the
# container's log: the document is written atomically on the query path, so a
# reader sees a complete one and never half of a JSON object.
COUNTERS_PATH = "/run/mosdns-mock-foreign/counters.json"

# The mock *domestic* listener's evidence, and the markers that make a line in it
# a query. The domestic mock is dnsmasq -- a package on the locked release, not
# this project's code -- and its attribution is its own query log.
#
# The mock-router image sets `log-queries`, so the log carries a line per query
# and the count of lines naming a test name is a count of queries for it. What
# identifies such a line is the word dnsmasq puts between the name and the rest,
# and it is not one word: `reply to` when there is no answer, `is <address>` when
# there is one, `NXDOMAIN` or `cached ... NODATA-Other` for the refusals. So the
# markers are a set, and the name is the field immediately before whichever one
# appeared -- see `router_queries`.
ROUTER_LOG_QUERY = "log-queries"
# The field dnsmasq's `log-queries` opens a query line with, and the word that
# ends the question on that line. Both are required together, because the log also
# carries `sent size: 4 option: 6 dns-server 10.89.0.2` -- a line about a DNS server
# ADDRESS -- and `log-dhcp`'s `DHCPDISCOVER(eth0)` / `DHCPACK(eth0)`.
QUERY_RECORDING = "query["
QUERY_CLIENT_MARKER = "from"

# The transports Step 6 asks the repeat over, in the order it asks it. Both, and
# not "UDP and then TCP if there is time": a scenario that asked one would satisfy
# every other assertion in this file.
TRANSPORTS = ("udp", "tcp")

# The query tool inside the target and the client. `dig` is in the target image
# (`dnsutils`), and the client runs the same image -- the client is a target
# container that this scenario uses for nothing else, so it needs nothing the
# target does not already have, and a second image would be a second thing that
# could differ from the first.
QUERY_TOOL = "dig"

# The resolver port on the target. The client asks the target's *address* on this
# port, and the port is the one the package serves, so a client's answer can only
# have come from the target.
RESOLVER_PORT = 53

# The TLD used for the two test names. `.test` is reserved by RFC 2606 and
# delegates nowhere, so a name under it cannot be answered by anything off this
# run's private network -- which is what makes "the mock answered" the only
# possible source of an answer.
TEST_SUFFIX = "test"

# The foreign name, and the property it must have: the published China list must
# not match it. Asserted in the scenario rather than trusted, because the whole
# foreign branch's meaning rests on it -- a name the China set matched would go
# down the *domestic* branch, and the cell's two counters would agree for a
# reason nobody could read.
FOREIGN_TEST_NAME = f"foreign-routing.{TEST_SUFFIX}"
# The China name is NOT a literal. It is read out of the published list, so it is
# a name this project's own configuration routes domestically. The placeholder is
# only what the record says before the list has been read.
CHINA_TEST_NAME = "(read from the published China list)"

# **The address the mock foreign resolver answers with, and the one this project's
# own mock router CANNOT answer with.**
#
# The foreign mock is this project's code and it answers every name with one fixed
# test address, so a foreign query's answer is a real measurement and the scenario
# asserts it exactly.
#
# The domestic mock is dnsmasq with `no-resolv` and one hardcoded test-only name,
# so a China-set name gets **SERVFAIL** from it and `dig +short` prints nothing.
# MEASURED on all three releases. So there is no domestic answer to assert, and
# the constant below names the address a query would have to come back with for
# this scenario to be wrong about the branch -- which is the FOREIGN one, and
# section 3 and section 6 both check for its absence from a domestic query.
#
# It is kept as a name rather than deleted because a reader of the evidence document
# needs to know what the domestic side was NOT allowed to answer, and because the
# dnsmasq log line a query produces carries an address column.
# **The only transport the foreign listener can ever see from this cell**, because
# the foreign branch's forward is configured as `tcp://127.0.0.1:15353` in
# `configs/mosdns.yaml`. MEASURED on 24.04 and on the plan's own document: a
# client query over UDP and one over TCP both arrive at mosdns on their own
# transport and both leave it over TCP. So this is not a default -- it is the
# transport the shipped configuration sends, and a scenario that required a UDP
# count here would be requiring something the router cannot do.
FOREIGN_TRANSPORT = "tcp"

FOREIGN_ANSWER = "198.51.100.7"
DOMESTIC_ANSWER = "192.168.123.53"

# The marker `try_read` puts on a read podman could not do, and which is
# therefore not a reading. The reachability classification in section 1b is a
# claim about the configuration this project ships, and a claim made on a read
# that failed is worse than no claim at all: it sends a reader to the plan with a
# reason that was never measured. MEASURED -- the read had no container in it, so
# podman was asked for one named `sh`, and the text that does not contain the
# address being looked for satisfied the check. See the comment at the read.
READ_FAILED = "(not readable:"

# **The requirement this scenario cannot close, in the plan's exact words.**
#
# The Global Constraints say "A requirement a container cannot close is recorded
# SKIPPED with its exact wording", so the wording is a **copy** of the plan's
# Task 4 Step 6 sentence and not a summary of it: a reader checking the claim
# against the requirement is the whole point, and a paraphrase would make them
# check their memory of the requirement instead. The plan's sentence is the one
# below, the first half of which is what the shipped configuration forbids.
#
# **Why the wording stops at "names".** Step 6's sentence is two sentences joined
# by "and", and the second one ("Assert query counters at mock domestic and mock
# foreign listeners. Repeat over UDP and TCP.") IS closed, from inside the
# target. So the requirement recorded as skipped is the vantage point, not the
# step -- a skip of the whole step would be false, and a skip that claimed the
# counters were unmeasured would be false in the other direction.
CLIENT_VANTAGE_POINT_REQUIREMENT = (
    "From a separate client container and from inside the target, query "
    "China-set and foreign test names."
)

# The word the reason carries, and the record's own name for it. Two spellings of
# one fact in two files is how they drift, and this one has already been wrong
# once: the first version of this section's message said the queries asked from
# inside the target "do move both listeners' counters", which was a claim about a
# measurement nobody had taken, one level below the unfounded refusal the read
# above is about. Now the counters ARE measured, so the sentence is earned -- and
# the evidence document says which vantage points produced them.
CLIENT_VANTAGE_POINT_REASON = "not bound on the bridge"

# How long to wait for a counter to move. A bounded poll of a real fact, like every
# other wait in this harness: the mock writes the document on the query path, so
# a counter is there the moment the query has been answered, and a scenario that
# slept would be reading a race.
DEFAULT_WAIT_SECONDS = 60.0
WAIT_INTERVAL_SECONDS = 1.0


class RoutingScenarioError(Exception):
    """A routing claim the run could not establish, with the evidence attached.

    Its own type rather than the harness's `PodmanError`, for the reason
    `dhcp_test.py` gives: a failed assertion inside a scenario is a test failure
    (a `failed` row) and a harness fault is exit 2. A scenario that raised the
    harness's error for "the foreign branch did not ask its listener" would be
    reporting a routing property as a broken harness.
    """


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RoutingScenarioError(message)


def published_cn_domains(text: str) -> set[str]:
    """The China-set names in a published list, as a set of dotted names.

    **Only a `domain:` line is a name, and a line that is not one is not a name
    that happens to be malformed.** The list is one `domain:<name>` line per
    entry, which is the shape `update-lists` publishes and the shape `domain_set`
    reads; a leading `.` is also accepted, because a matcher may record a suffix
    with one and two matchers that mean the same set would then mean different
    keys.

    The first version accepted *any* line, splitting on the first `:`, and that is
    a parser that reads an error message as a routing fact. A cell asked this for
    a list the install had not published, `cat` answered

    ```text
    cat: /var/lib/mosdns/lists/cn-domains.txt: no such file or directory
    ```

    and the parser produced the China-set name `cat: /var/lib/mosdns/lists/
    cn-domains.txt: no such file or directory` -- a name the router cannot match
    and cannot be asked about, carried into the evidence document as though it
    were one of this project's own domains. So a line without a recognised prefix
    is **skipped**, and a list that yields no names at all is refused by the
    caller with the file it read attached, which is the message a reader needs.

    Comments and blank lines are skipped for the same reason: this is evidence
    read out of a machine, and a machine's published list may carry a comment this
    parser does not know.
    """
    names: set[str] = set()
    for line in text.splitlines():
        text_line = line.strip()
        if not text_line or text_line.startswith("#"):
            continue
        for prefix in ("domain:", "domain-set:"):
            if text_line.lower().startswith(prefix):
                name = text_line[len(prefix) :]
                if name.strip():
                    names.add(name.strip().lstrip(".").lower())
                break
    return names


def matches_china_set(name: str, domains: set[str]) -> bool:
    """Whether a name is in the China set, the way `domain_set` decides.

    **A suffix match, at label boundaries, and that is the whole of it.**
    `domain_set` matches a name when the name equals an entry or ends with
    `.` + entry -- so `example.cn` matches an entry `example.cn` and does *not*
    match an entry `ample.cn`, and a name like `notexample.cn` does not match
    either. A scenario that used `in` would classify `notexample.cn` as domestic
    and route its query at the wrong mock, and the counters would then disagree
    for a reason that reads as a routing defect.

    The comparison is case-insensitive, because DNS names are.
    """
    candidate = name.strip().rstrip(".").lower()
    for entry in domains:
        if candidate == entry or candidate.endswith("." + entry):
            return True
    return False


def router_queries(log: str) -> dict[str, int]:
    """The names in a dnsmasq query log, counted.

    Read from the log rather than from a counters document, because the domestic
    mock is dnsmasq: a package on the locked release, not this project's code.
    Its `log-queries` output is one line per query, which is the same per-name
    count the foreign mock publishes in a document -- so the two listeners'
    evidence is comparable without either of them being something this project
    wrote.

    **A query is the `query[<TYPE>] <name> from <client>` line, and that is what
    this function recognises.** MEASURED, dnsmasq 2.91 in this harness's own
    mock-router image with `log-facility=-`, from run `20261001T003319Z`:

    ```text
    dnsmasq[1]: query[AAAA] api.cloudflare.com from 10.89.0.168
    dnsmasq[1]: config error is REFUSED (EDE: not ready)
    dnsmasq[1]: query[A] probe.0033.cn from 10.89.0.168
    dnsmasq[1]: config error is REFUSED (EDE: not ready)
    ```

    **The query line carries the name; the answer line does not.** That is the
    whole reason the previous version of this function counted `{"error": 6}` and
    the cell called it a routing result: it recognised a query by an answer-side
    marker (`reply to`, `is <addr>`, `NXDOMAIN`) and read the name as the field
    before it, and on this dnsmasq the only line carrying `is REFUSED` is
    `config error is REFUSED (EDE: not ready)`, whose field before the marker is
    the word `error`.

    Its docstring made that inevitable, because it documented a different shape
    entirely -- a syslog line with a timestamp and a hostname in front of the name:

    ```text
    Sep 30 20:00:00 hostname 10.89.0.10 probe.example.cn is 10.89.0.2
    ```

    A container has no syslog, which is the only reason `log-facility=-` is set,
    so a container running this project's mock router **never prints** a line
    with a timestamp or a hostname in front of the name. The parser followed the
    documentation because the documentation was the only shape anyone had written
    down. **That is the third time in this project that the harness's own
    evidence has been a fixture agreeing with a parser and neither agreeing with
    the program** -- after the bridge's bare-address fixtures and
    `install_test.py`'s `ActiveState` rule that matched nothing.

    **Why `query[` is a safe recognition and not a substring.** `log-dhcp` prints
    `DHCPDISCOVER(eth0)`, `DHCPACK(eth0)` and
    `sent size: 4 option: 6 dns-server 10.89.0.2`, and that last one is the
    dangerous neighbour: it is a line about a DNS server **address**, and a parser
    reading fields positionally would count `dns-server` as a name. The bracket
    and the ` from ` that follows the name are what no other line in this log
    carries, so both are required rather than one.

    **Names are normalised** -- lowercased, trailing dot stripped -- because
    `matches_china_set` normalises the name it is asked about and the published
    list carries `domain:0033.cn`. A counter that returned `probe.0033.cn.` would
    compare unequal to the set and the cell would refuse a split it had measured,
    and dnsmasq echoes the name exactly as it arrived.

    **And it cannot see a transport, which the record says.** dnsmasq records the
    query *type* and not the transport, so the plan's "Repeat over UDP and TCP" is
    visible here only as a count of two for one name. The foreign mock, which is
    this project's own code, publishes `{name: {udp: n, tcp: m}}` and both are
    there -- so the two listeners' documents are comparable per NAME, and only
    one of them per transport. See `domestic_counters_transport`, which records
    that rather than letting a reader infer a split this log does not carry.
    """
    counts: dict[str, int] = {}
    for line in log.splitlines():
        fields = line.split()
        # `query[A]` is ONE field, so the recognition is on a field that both
        # opens with `query[` and closes with `]`, and it has to be the second
        # field: dnsmasq prefixes every line with `dnsmasq[1]:` or
        # `dnsmasq-dhcp[1]:` and nothing else puts a bracketed token there.
        if len(fields) < 5 or not fields[1].startswith(QUERY_RECORDING):
            continue
        if not fields[1].endswith("]"):
            continue
        # The name is the one field before the literal `from`, which is the only
        # place in a dnsmasq log line where those two meet: `from` appears in
        # `query[TYPE] name from client` and in nothing else this daemon prints.
        # Requiring it at that position rather than merely somewhere on the line
        # is what keeps `sent size: 4 option: 6 dns-server 10.89.0.2` out, which
        # is a line about a DNS server ADDRESS and the nearest neighbour a
        # positional parser has to get wrong.
        if fields[-2] != QUERY_CLIENT_MARKER:
            continue
        name = fields[-3].strip(".").lower()
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
    return counts


def china_name_key(document: dict) -> str:
    """The China-set name this cell asked about, normalised the way the log counts it."""
    return str(document.get("domestic_name", "")).strip(".").lower()


def foreign_counters(document: str) -> dict[str, dict[str, int]]:
    """The foreign mock's counters document, as `{name: {transport: count}}`.

    Read through `json.loads` and then reduced, rather than with a regular
    expression, because the document is written by another program and a
    scenario that pattern-matched it would be reading a *shape* it had invented.
    A document that will not parse is an error naming the path, not an empty
    count: "the foreign listener was asked nothing" and "this scenario could not
    read what it was asked" are different states, and the first is a routing
    result while the second is a harness fault.
    """
    try:
        parsed = json.loads(document)
    except json.JSONDecodeError as broken:
        raise RoutingScenarioError(
            f"the mock foreign resolver's counters document at {COUNTERS_PATH} is not JSON "
            f"({broken}), so this scenario cannot read what the foreign branch asked it. That "
            "is a harness fault rather than a routing result: the document is written "
            "atomically on the query path, so an unreadable one means the file was never "
            f"written or is not the file this scenario asked for. The document was:\n{document}"
        ) from broken
    if not isinstance(parsed, dict) or "queries" not in parsed:
        raise RoutingScenarioError(
            f"the mock foreign resolver's counters document at {COUNTERS_PATH} has no "
            f"'queries' object, so it is not the document this scenario reads. It read:\n{document}"
        )
    reduced: dict[str, dict[str, int]] = {}
    for name, transports in (parsed.get("queries") or {}).items():
        if isinstance(transports, dict):
            reduced[str(name).strip(".").lower()] = {
                str(transport): int(count) for transport, count in transports.items()
            }
    return reduced


def build_scenario(
    *,
    podman,
    version: str,
    arch: str,
    run_id: str,
    router: str,
    target: str,
    foreign: str,
    client: str,
    network: str,
    results_dir,
    wait_seconds: float = DEFAULT_WAIT_SECONDS,
    interval: float = WAIT_INTERVAL_SECONDS,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Callable[[], ScenarioResult]:
    """The `routing` scenario, bound to one matrix cell's four containers.

    Returned as a zero-argument callable because that is what `run.py`'s scenario
    loop calls, and bound rather than global because a cell has its own containers
    and its own run id -- and a scenario that reached for a global container name
    would be measuring whichever container happened to be running.
    """
    log_name = f"logs/{version}-{SCENARIO_NAME}.json"
    log_path = Path(results_dir) / run_id / log_name

    def read(container, *command):
        return podman.exec_container(container, *command).output

    def try_read(container, *command) -> str:
        """One read that cannot fail the run, for evidence rather than a claim."""
        try:
            return read(container, *command)
        except PodmanError as error:
            return f"(not readable: {str(error).splitlines()[-1]})"

    def wait_for(probe, accept, what: str, seen=lambda: "", timeout=wait_seconds):
        """Poll a real fact until it holds, and return what it read.

        A poll rather than a sleep, for the reason the other scenarios give: the
        mock writes its counters document on the query path, and a scenario that
        slept would be reading a moment rather than a fact.
        """
        deadline = now() + timeout
        last = ""
        while True:
            last = probe()
            if accept(last):
                return last
            if now() >= deadline:
                raise RoutingScenarioError(
                    f"{what} within {timeout:g}s; last read: {last!r}{seen()}"
                )
            sleep(interval)

    def evidence(document: dict) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def ask(container, name, transport, address) -> str:
        """One query, from one container, to one address, over one transport.

        `+tcp` is the whole of the transport choice: `dig`'s `+tcp` forces TCP and
        its absence is UDP, and both are asked rather than one being derived from
        the other. `+short` so the output is the address and nothing else, which
        is what makes "the answer was the one belonging to the branch that was
        supposed to answer it" a comparison rather than a reading.

        **The address is an argument, and it is the vantage point's own.** The
        router binds `127.0.0.1:53` and nothing else, so a query asked from inside
        the target has to go to the loopback and a query asked from the client has
        to go to the bridge address -- there is no address both can use, and the
        first version of this asked the bridge one from both. See
        `TARGET_LOCAL_ADDRESS` for the measurement.
        """
        command = (
            f"{QUERY_TOOL} +short {'+tcp ' if transport == 'tcp' else ''}"
            f"@{address} -p {RESOLVER_PORT} {name}"
        )
        return try_read(container, "sh", "-c", command)

    def run_scenario() -> ScenarioResult:
        document = {
            "arch": arch,
            "network": network,
            "router_container": router,
            "target_container": target,
            "foreign_container": foreign,
            "client_container": client,
            "domestic_listener": MOCK_ROUTER_ADDRESS,
            "foreign_listener": MOCK_FOREIGN_ADDRESS,
            "client_address": CLIENT_ADDRESS,
            "transports": list(TRANSPORTS),
        }
        try:
            # -- 1. the client's own resolver ------------------------------
            # Read first, and required, because everything after it is evidence
            # about the target only if the client could ask nobody else. A client
            # on this network has the mock router reachable, so "the client got
            # an answer" is not by itself evidence about the target.
            #
            # **Required whether or not the client is asked**, and the record keeps
            # it either way: the harness points the client at the target before any
            # scenario runs, so a client whose resolver is not the target is a
            # broken cell and not an unmeasurable one. Section 1b decides whether
            # the client can be asked anything; this decides whether it was pointed
            # anywhere useful.
            client_resolver = try_read(client, "cat", "/etc/resolv.conf")
            document["client_resolver"] = client_resolver
            _require(
                TARGET_ADDRESS in client_resolver.split(),
                f"the client container's /etc/resolv.conf is {client_resolver!r}, which does "
                f"not name the target's address {TARGET_ADDRESS}. A client on this run's "
                "private network can reach the mock router directly, so an answer the client "
                "receives is not evidence about the target's routing unless the target is the "
                "only resolver it was asked -- and this scenario's whole claim is about the "
                "target's routing",
            )
            _require(
                MOCK_ROUTER_ADDRESS not in client_resolver.split(),
                f"the client container's /etc/resolv.conf also names the mock router "
                f"({MOCK_ROUTER_ADDRESS}), so the client could have been answered by the "
                "domestic mock directly and this scenario could not tell which resolver "
                "answered",
            )
            document["target_resolver"] = try_read(target, "cat", "/etc/resolv.conf")
            _require(
                "127.0.0.53" in document["target_resolver"],
                f"the target's /etc/resolv.conf is {document['target_resolver']!r} and does "
                "not name resolved's stub. The target is the machine under test and its own "
                "resolver is the project's; a target pointed somewhere else is a cell that "
                "measured a different configuration",
            )

            # -- 1b. WHICH vantage points this configuration can serve --------
            # **This project ships a router that binds `127.0.0.1:53` and nothing
            # else, and its own package Description says so: "no listener in this
            # package is reachable from another host".** So a client container on
            # this bridge cannot ask the target anything -- `dig @10.89.0.10 -p 53`
            # is `exited 9`, "no reply from server", because nothing is bound to
            # that address. MEASURED on 24.04 and 26.04, and the target's own
            # `ss -lntup` is recorded in every cell below.
            #
            # **This is a CLASSIFICATION and not a refusal, and the difference is
            # the whole of the fix.** The plan's Task 4 Step 6 asks for the client
            # vantage point AND the target's, and the first cannot exist against
            # the configuration this project ships. The Global Constraints say
            # what to do with a requirement a container cannot close: record it
            # **SKIPPED with its exact wording**, and never report a skip as a
            # pass. So that is what happens -- and then **the rest of the step
            # runs**, because the counters, the split, both transports and the
            # answer/branch match are all closable from inside the target.
            #
            # The first version of this refused here, before asking anything. So
            # one plan contradiction cost the substance of the whole step: the
            # per-name, per-transport counters were written, were green against
            # the fake, and had never been measured on a live cell on any
            # release. **A cell that refuses before it asks anything cannot tell a
            # working split from a broken one**, and that is a worse defect than
            # the one the refusal was reporting.
            #
            # **The table is a measurement or this classification is nothing, and
            # the two ways it can fail to be one are refused as themselves.**
            # MEASURED on the first three-release run: this read had no container
            # in it, so podman was asked for a container named `sh` and answered
            #
            #     (not readable: Error: no container with name or ID "sh" found:
            #     no such container)
            #
            # -- a string that does not contain `10.89.0.10:53`, which is exactly
            # what the check below looks for. The conclusion that followed was
            # TRUE and UNFOUNDED at the same time, which is the worst of both: a
            # cell whose router did bind the bridge address would have been
            # classified the same way. An empty table is the same defect wearing a
            # different mask -- `ss -lntup` prints a header whether or not
            # anything is bound, and the `|| true` on the command means a missing
            # `ss` looks exactly like an empty one. Neither is a routing result, so
            # neither is allowed to produce one -- and a classification built on
            # either would file a SKIP of a requirement the cell could have closed.
            listeners = try_read(target, "sh", "-c", "ss -lntup 2>/dev/null || true")[:4000]
            document["target_listeners"] = listeners
            _require(
                READ_FAILED not in listeners,
                f"the target's own listener table could not be read in {target} -- podman said "
                f"{listeners!r} -- so this scenario has NOT established whether a client "
                f"container can ask the target's resolver, and the plan's client vantage point "
                f"is therefore UNMEASURED rather than unclosable. That is a harness fault and not "
                f"a routing result, and it is refused as one: a SKIP is a claim about the "
                f"configuration this project ships, and this scenario will not file one on the "
                f"strength of a command that did not run",
            )
            _require(
                bool(listeners.strip()),
                f"`ss -lntup` printed nothing at all in {target}, and it prints a header whether or "
                "not anything is bound -- so an empty table is a read that did not happen rather than "
                "a table with no rows. The `|| true` on the command means a missing `ss` looks "
                "exactly like this, so the cell cannot classify anything about what is bound",
            )
            client_reachable = f"{TARGET_ADDRESS}:{RESOLVER_PORT}" in listeners
            document["client_vantage_point_measured"] = client_reachable
            skips: list[Skip] = []
            if client_reachable:
                document["client_vantage_point_reason"] = "bound on the bridge"
            else:
                document["client_vantage_point_reason"] = CLIENT_VANTAGE_POINT_REASON
                skips.append(
                    Skip(
                        requirement=CLIENT_VANTAGE_POINT_REQUIREMENT,
                        reason=(
                            f"nothing is bound to {TARGET_ADDRESS}:{RESOLVER_PORT} in {target}, and "
                            f"this project's own router does not bind it. `configs/mosdns.yaml` "
                            f"listens on 127.0.0.1:53 and nothing else, and the package's own "
                            f"Description says 'no listener in this package is reachable from "
                            f"another host'. A client container on this bridge therefore cannot ask "
                            f"the target's resolver anything: `dig @{TARGET_ADDRESS} -p "
                            f"{RESOLVER_PORT}` is `exited 9` ('no reply from server'), MEASURED on "
                            f"24.04 and 26.04. The plan's Task 4 Step 3 asks for loopback listeners "
                            f"only, so the two requirements cannot both hold; the vantage point is "
                            f"recorded as skipped rather than substituted with a second network "
                            f"namespace, whose 127.0.0.1 would be the target's own and therefore "
                            f"not a second vantage point at all. The counters, the split, both "
                            f"transports and the answer/branch match ARE closed, from inside "
                            f"{target}. The target's listener table:\n{listeners}"
                        ),
                    )
                )
            # The vantage points that will be asked, in the order they are asked:
            # one or two, and the record says which -- so a reader of the evidence
            # document can tell an unmeasured vantage point from an unrecorded one.
            vantage_points = ("target", "client") if client_reachable else ("target",)
            document["vantage_points_measured"] = list(vantage_points)
            containers = {"target": target, "client": client}
            # **The address each vantage point can actually reach**, and the
            # client's is the bridge address precisely because its `127.0.0.1` is
            # its own. Recorded, because "asked from inside the target" does not
            # say where the target was asked, and a reader of the evidence
            # document should not have to guess.
            addresses = {"target": TARGET_LOCAL_ADDRESS, "client": TARGET_ADDRESS}
            document["vantage_point_addresses"] = {
                vantage: addresses[vantage] for vantage in vantage_points
            }

            # -- 2. the two names, and which branch each must reach ---------
            # The China name is read out of the *published* list, so it is a name
            # this project's own configuration routes domestically. A literal here
            # would be a name the scenario chose, and a re-pin that dropped it
            # would leave the cell asking about a name the foreign branch takes --
            # so the counters would disagree for a reason the evidence document
            # would not describe.
            published = try_read(target, "cat", PUBLISHED_CN_LIST)
            domains = published_cn_domains(published)
            document["published_cn_domains"] = len(domains)
            _require(
                bool(domains),
                f"{PUBLISHED_CN_LIST} yielded no domain names in {target}, so there is no "
                "China-set name to ask about and the domestic branch cannot be exercised. "
                f"The list read:\n{published}",
            )
            china_name = next(
                (entry for entry in sorted(domains) if matches_china_set(f"probe.{entry}", domains)),
                None,
            )
            _require(
                china_name is not None,
                f"none of the {len(domains)} published China-set names matches "
                "`probe.<name>`, which is the shape this scenario asks about. That would "
                "mean the published list is in a form `published_cn_domains` does not "
                f"read, and not that the router has no domestic branch:\n{published}",
            )
            # The foreign name must be OUTSIDE the China set, and that is checked
            # rather than assumed -- the whole foreign branch's meaning rests on it.
            # A name the China set matched would go down the *domestic* branch and
            # the two counters would agree for a reason nobody could read.
            _require(
                not matches_china_set(FOREIGN_TEST_NAME, domains),
                f"the foreign test name {FOREIGN_TEST_NAME} is IN the published China set, "
                f"so the router would route it down the domestic branch and this cell's two "
                "counters would agree for a reason that reads as a routing split. The name "
                f"has to be outside the set; the set has {len(domains)} entries and this one "
                "matched",
            )
            document["domestic_name"] = f"probe.{china_name}"
            document["foreign_name"] = FOREIGN_TEST_NAME
            document["china_set_entry"] = china_name

            # -- 3. the queries, from the measured vantage points, both transports
            # **From the vantage points section 1b established, and not from a
            # fixed pair.** A cell that asked the client unconditionally would be
            # asking a container nothing is listening for and would then report
            # four empty answers as a routing failure; a cell that asked nothing at
            # all because one vantage point was unclosable is what the first
            # version did, and it measured nothing. So the loop is over
            # `vantage_points`, which is one or two, and the record says which.
            #
            # A client is a different resolver stack (glibc, through resolved) from
            # a direct `dig` inside the target, which is why the plan asked for
            # both; over each vantage point, UDP and TCP are asked separately,
            # because a scenario that dropped TCP would still resolve every name it
            # asked.
            answers: dict[str, str] = {}
            for vantage in vantage_points:
                for name_key, name in (("domestic", document["domestic_name"]),
                                       ("foreign", document["foreign_name"])):
                    for transport in TRANSPORTS:
                        key = f"{vantage}/{name_key}/{transport}"
                        answers[key] = ask(
                            containers[vantage], name, transport, addresses[vantage]
                        )
                        document.setdefault("answers", {})[key] = answers[key]
            # **The FOREIGN answers are required; the DOMESTIC ones are recorded
            # and not required, and the reason is the mock's own configuration.**
            # `tests/podman/mock-router/dnsmasq.conf` carries `no-resolv` — "a mock
            # router that forwarded would answer a test's questions from off this
            # host" — and exactly one test-only name,
            #
            #     address=/install-probe.example/10.89.0.2
            #
            # so every other name, a China-set one included, gets SERVFAIL. MEASURED
            # on all three releases with the queries finally going to an address that
            # exists:
            #
            #     "answers": {"target/domestic/tcp": "", "target/domestic/udp": "",
            #                 "target/foreign/tcp": "198.51.100.7",
            #                 "target/foreign/udp": "198.51.100.7"}
            #
            # An empty answer from a resolver that reached nobody is a CORRECT
            # answer — it is what `emergency_rollback` checks for elsewhere in this
            # project — and requiring one was the **answers-not-counters** mistake
            # this file's own docstring is written against. `DOMESTIC_ANSWER` was a
            # fixture this project's mock cannot produce. The domestic branch's
            # evidence is its query log, which is what the counters below are read
            # from, and the answer is recorded beside them with the reason.
            document["domestic_answers_note"] = (
                f"the domestic queries' answers are expected to be EMPTY, and they are not "
                f"checked for a value: the mock router at {MOCK_ROUTER_ADDRESS} is dnsmasq with "
                f"`no-resolv` and one hardcoded test-only name "
                f"(address=/install-probe.example/10.89.0.2), so a China-set name gets SERVFAIL "
                f"from it -- a resolver that reached nobody, which is a correct answer and is not "
                f"a routing result either way. The domestic branch's evidence is the mock's own "
                f"query log, counted per name below."
            )
            for transport in TRANSPORTS:
                key = f"target/domestic/{transport}"
                _require(
                    FOREIGN_ANSWER not in answers[key],
                    f"the {key} query came back with {FOREIGN_ANSWER!r}, the address the FOREIGN "
                    f"mock answers with, so the China-set name went down the foreign branch. That "
                    f"is a routing result and it is refused here as well as by the counters "
                    f"below, because a counter read generously and an answer read exactly are "
                    f"two different strengths of the same claim",
                )
                _require(
                    answers[f"target/foreign/{transport}"].strip() == FOREIGN_ANSWER,
                    f"the target/foreign/{transport} query returned "
                    f"{answers[f'target/foreign/{transport}']!r} and the foreign mock answers "
                    f"{FOREIGN_ANSWER!r}; `+short` prints the address and nothing else, so "
                    f"anything else is a SERVFAIL, a REFUSED, or an answer from somewhere the "
                    f"counters below will not have counted",
                )

            # -- 4. THE MEASUREMENT: both listeners' own counters -----------
            # Read after the queries, and both required. This is the section the
            # whole scenario exists for, and it is read from the two listeners
            # rather than from anything the router said about itself.
            document["router_log"] = wait_for(
                lambda: router_log(podman, router),
                lambda log: bool(router_queries(log)),
                what=f"the mock router's query log in {router} to carry a query",
                seen=lambda: f" the log reads:\n{document.get('router_log', '')}",
            )
            document["foreign_counters_raw"] = wait_for(
                lambda: try_read(foreign, "cat", COUNTERS_PATH),
                lambda raw: bool(foreign_counters(raw)) if raw.lstrip().startswith("{") else False,
                what=f"the mock foreign resolver's counters at {COUNTERS_PATH} in {foreign}",
            )
            document["domestic_counters"] = router_queries(document["router_log"])
            document["foreign_counters"] = foreign_counters(document["foreign_counters_raw"])
            document["domestic_counters_source"] = (
                f"the mock router's own query log in {router}, counted by name"
            )
            # **And the record says the domestic side has NO per-transport split,
            # because that is what it has.** dnsmasq's `log-queries` records
            # `query[<TYPE>] <name> from <client>` and the transport is not in it,
            # so the plan's "Repeat over UDP and TCP" is visible at this listener
            # only as a count of two for one name -- one question per transport,
            # which is the evidence, and it is weaker than the foreign mock's
            # `{name: {udp: n, tcp: m}}`. A record carrying one count and the
            # other's pair would read as though the domestic half were missing,
            # and a reader has to be able to see the difference from the document
            # rather than infer it.
            document["foreign_counters_transport"] = (
                "NOT what the router was asked: the foreign branch is configured to forward "
                "over TCP only (`foreign_upstream: tcp://127.0.0.1:15353` in "
                "configs/mosdns.yaml), so a client query over UDP and one over TCP both leave "
                "this router over TCP and the foreign listener can only ever see TCP from "
                "this cell. The split it publishes is therefore a measure of how many times "
                "dnscrypt-proxy's own cache missed -- and dnscrypt-proxy caches, so a second "
                "identical question is answered without arriving at all. MEASURED, run "
                "20261001T003952Z on 24.04: `foreign-routing.test` counted tcp=1 with BOTH "
                "transports asked and both answers carrying the foreign branch's address."
            )
            document["domestic_counters_transport"] = (
                "not observable: dnsmasq's log-queries records query[<TYPE>] <name> "
                "from <client> and carries no transport, so the repeat over UDP and TCP is "
                f"visible here as a count of {document['domestic_counters'].get(china_name_key(document), 0)} "
                "for the China-set name rather than as one number per transport. The foreign "
                "mock publishes both."
            )
            document["foreign_counters_source"] = (
                f"the mock foreign resolver's counters document at {COUNTERS_PATH} in {foreign}"
            )

            # -- 5. the split, both directions, per name --------------------
            # Four assertions, and each is load-bearing:
            #
            #   * the China name at the domestic listener, because a cell where
            #     it went nowhere exercised no domestic branch;
            #   * the China name ABSENT from the foreign listener, because a China
            #     name the foreign branch answers means the split is broken and
            #     everything still resolves;
            #   * the foreign name at the foreign listener, over BOTH transports,
            #     because UDP alone is half of Step 6; and
            #   * the foreign name ABSENT from the domestic listener, which has
            #     the opposite symptom -- an answer from an address nobody can
            #     reach -- and a scenario that only checked "an answer came back"
            #     would read that as a pass.
            china = document["domestic_name"].strip(".").lower()
            foreign_name = document["foreign_name"].strip(".").lower()
            _require(
                document["domestic_counters"].get(china, 0) >= 1,
                f"the mock router's log carries no query for the China-set name {china!r}, so "
                "the domestic branch was not exercised. Its counted names are: "
                f"{sorted(document['domestic_counters'])}. That is a routing result, not a "
                "harness fault: the query was asked (section 3 recorded the answer) and the "
                "domestic branch did not reach the mock router",
            )
            _require(
                china not in document["foreign_counters"],
                f"the China-set name {china!r} reached the FOREIGN listener "
                f"({MOCK_FOREIGN_ADDRESS}), so the domestic/foreign split this cell claims to "
                f"have exercised is not the split: the name went down the foreign branch. The "
                f"foreign listener counted {sorted(document['foreign_counters'])} and the "
                f"domestic one {sorted(document['domestic_counters'])}. Everything on this "
                "machine still resolves either way, which is why the counters and not the "
                "answers are what this scenario asserts",
            )
            # **The foreign listener is required to have been ASKED, and the
            # requirement is deliberately NOT per transport.** MEASURED, run
            # `20261001T003952Z` on 24.04 with everything else in this round
            # working:
            #
            #     answers        = {"target/foreign/udp": "198.51.100.7",
            #                       "target/foreign/tcp": "198.51.100.7"}
            #     foreign_counters = {"foreign-routing.test": {"tcp": 1}, ...}
            #
            # Both foreign-branch answers carried the foreign branch's address and
            # the mock counted one arrival, over TCP. Two measured facts, and
            # neither is about a transport:
            #
            #   * **the router forwards the foreign branch over TCP** --
            #     `configs/mosdns.yaml` says `foreign_upstream:
            #     tcp://127.0.0.1:15353` and `addr: tcp://127.0.0.1:15353`, so a
            #     `dig` over UDP and a `dig +tcp` from a client both arrive at
            #     mosdns on their own transport and both leave it over TCP, and
            #     the foreign listener can only ever see TCP from here;
            #   * **dnscrypt-proxy caches**, so the second query was answered
            #     without arriving.
            #
            # So requiring a UDP count here was requiring a **cache miss**: it
            # would pass or fail with the resolver's cache state and with nothing
            # about this project's routing, and the sentence it produced named the
            # transport -- so a reader who believed it would go looking for a
            # router that ignored UDP. What is required instead is that the
            # foreign listener was asked about the foreign name at all, and the
            # per-transport split at the DOMESTIC listener is the one that
            # corresponds to what the router was asked: a count of two for one
            # name, one question per transport.
            _require(
                sum(document["foreign_counters"].get(foreign_name, {}).values()) >= 1,
                f"the mock foreign resolver never reached the foreign listener for "
                f"{foreign_name!r}, so the foreign branch never reached it and nothing here was "
                f"measured about that branch. It counted {sorted(document['foreign_counters'])} "
                f"and the foreign answers were "
                f"{ {key: value for key, value in answers.items() if '/foreign/' in key} }",
            )
            # **And the arrivals must be TCP, because the configured forward is
            # TCP.** This is the control the relaxed requirement needs: the point
            # is not "any count will do", it is "the count that corresponds to
            # what this router is configured to send". A UDP arrival here means
            # something other than `tcp://127.0.0.1:15353` reached the listener.
            _require(
                document["foreign_counters"].get(foreign_name, {}).get("udp", 0) == 0,
                f"the mock foreign resolver counted {document['foreign_counters'][foreign_name]} "
                f"for {foreign_name!r}, so it saw a UDP query from this cell. The foreign "
                "branch's forward is configured as `tcp://127.0.0.1:15353` in "
                "`configs/mosdns.yaml`, so every arrival this router causes is TCP and a UDP "
                "arrival came from something else -- a different listener, a different path, or "
                "a resolver that is not the one the router is configured to use",
            )
            _require(
                foreign_name not in document["domestic_counters"],
                f"the foreign test name {foreign_name!r} reached the DOMESTIC listener "
                f"({MOCK_ROUTER_ADDRESS}), so the foreign branch was answered by the mock "
                "router. That has the opposite symptom to the case above and the same cause: "
                "the split is not there. The domestic listener counted "
                f"{sorted(document['domestic_counters'])}",
            )
            document["branches_distinguished"] = True

            # -- 6. the answers belonged to the branch that answered them ---
            # Recorded and checked, which is a different claim from the counters:
            # the counters say which listener was *asked*, and these say the
            # answer that came back is the one that listener answers with. A
            # resolver that asked the right listener and then answered from
            # somewhere else would satisfy the counters alone.
            #
            # **Over the measured vantage points**, for the reason section 3 gives:
            # asking for a `client/...` answer the cell never collected would index
            # a key that does not exist and report a KeyError as a routing failure.
            # **The FOREIGN branch is checked against its answer; the DOMESTIC one
            # is checked against the FOREIGN answer's absence.** The reason is
            # section 3's: this project's own mock router cannot answer a China-set
            # name, so `DOMESTIC_ANSWER` is a fixture rather than a measurement, and
            # asserting that the domestic answer equals it would be asserting a
            # fiction on every cell. What IS load-bearing is that a domestic answer
            # is never the foreign branch's address -- which says the name did not
            # come back down the wrong branch -- and that is checked, at both
            # vantage points, over both transports.
            for vantage in vantage_points:
                for transport in TRANSPORTS:
                    foreign_key = f"{vantage}/foreign/{transport}"
                    _require(
                        FOREIGN_ANSWER in answers[foreign_key],
                        f"the {foreign_key} query returned {answers[foreign_key]!r}, which does "
                        f"not carry the address the foreign mock answers with "
                        f"({FOREIGN_ANSWER}). So the answer did not come from the listener this "
                        f"scenario is counting, and the counters would be evidence about a "
                        f"listener that did not answer it",
                    )
                    domestic_key = f"{vantage}/domestic/{transport}"
                    _require(
                        FOREIGN_ANSWER not in answers[domestic_key],
                        f"the {domestic_key} query returned {answers[domestic_key]!r}, which "
                        f"carries the FOREIGN branch's address ({FOREIGN_ANSWER}). The "
                        f"China-set name came back down the wrong branch, and the counters below "
                        f"would be the only thing saying so",
                    )
            document["answers_match_their_branch"] = True

            evidence(document)
            # **The detail names the vantage points that were asked, and names the
            # one that was not as NOT ASKED.** The first version's sentence here
            # claimed that "the queries asked from INSIDE the target do exercise
            # both branches and do move both listeners' counters" -- on a cell that
            # had asked nothing, which is a claim about a measurement nobody had
            # taken, one level below the unfounded refusal the listener-table read
            # was. Now the counters ARE measured, so the sentence can be said, and
            # it is said with the counts in it.
            asked_from = ", ".join(containers[vantage] for vantage in vantage_points)
            not_asked = (
                ""
                if client_reachable
                else (
                    f" The separate client container {client} was NOT asked anything: nothing is "
                    f"bound to {TARGET_ADDRESS}:{RESOLVER_PORT} in the target "
                    f"({CLIENT_VANTAGE_POINT_REASON}), so that vantage point of the plan's Step 6 "
                    f"is recorded as a required SKIP with its exact wording, and the run is "
                    f"therefore incomplete rather than passed. "
                )
            )
            return ScenarioResult(
                name=SCENARIO_NAME,
                status="passed",
                skips=tuple(skips),
                detail=(
                    f"the two branches reached two different listeners, and the counters say so: "
                    f"the China-set name {china!r} reached the mock router at "
                    f"{MOCK_ROUTER_ADDRESS} "
                    f"{document['domestic_counters'].get(china, 0)} time(s) -- once per transport, "
                    f"and nothing in front of dnsmasq caches a REFUSED answer -- and never the mock "
                    f"foreign resolver at {MOCK_FOREIGN_ADDRESS}. The foreign name "
                    f"{foreign_name!r} reached the foreign listener "
                    f"{sum(document['foreign_counters'].get(foreign_name, {}).values())} time(s) "
                    f"over {FOREIGN_TRANSPORT}, which is the transport this router's foreign "
                    f"forward is configured to use (tcp://127.0.0.1:15353), and never the mock "
                    f"router; both its queries, asked over UDP and over TCP, came back with the "
                    f"foreign branch's own address {FOREIGN_ANSWER}. Asked over UDP and TCP from "
                    f"{asked_from}."
                    f"{not_asked}"
                    " Nothing here says anything about IPv6: no cell in this scenario asks an "
                    "AAAA question"
                ),
                log=f"logs/{version}-{SCENARIO_NAME}.json",
            )
        except RoutingScenarioError as error:
            # **A failure carries no skip.** A skip is a claim that a requirement
            # cannot be closed by this configuration; a failure is a claim that
            # something went wrong. Filing the skip here as well would make a cell
            # that measured a broken split look like a cell that ran out of vantage
            # points -- and would let a *failed* cell be reported as `incomplete`,
            # which is a softer reading of the same red. The two are kept apart so
            # a reader of the report can tell "could not be measured" from "was
            # measured and was wrong".
            evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME, status="failed", detail=str(error),
                log=f"logs/{version}-{SCENARIO_NAME}.json",
            )

    return run_scenario


def router_log(podman, container) -> str:
    """`podman logs <container>`, with a podman failure carried as text.

    dnsmasq is started with `log-facility=-`, so its query log goes to stderr
    because a container has no syslog to write to -- which makes the container's
    own output the only place that log exists, and there is no file inside the
    container to read instead. So the two mock listeners' evidence comes from two
    different places on purpose: the foreign resolver is this project's code and
    publishes a document, and the router is a package on the locked release and
    logs to stderr.

    **`container_logs` and not `logs`, and that is the whole of this round's
    fourth defect.** MEASURED, on this host, against this harness's own image:

        $ podman logs <mock-router> | head              # stdout only -- nothing
        $ podman logs <mock-router> 2>&1 1>/dev/null   # stderr
        dnsmasq[1]: started, version 2.91 cachesize 150
        dnsmasq-dhcp[1]: DHCP, IP range 10.89.0.100 -- 10.89.0.199, lease time 5m

    podman puts a container's stdout on podman's stdout and its **stderr** on
    podman's stderr, and dnsmasq logs to stderr. `Podman.logs` returned `.output`,
    which is stdout only, so **every cell of this scenario on every release read an
    empty log** and then waited out its 60-second budget reporting
    `the mock router's query log … to carry a query within 60s; last read: ''` --
    which is a sentence about the DOMESTIC BRANCH produced by a read of the wrong
    stream. `Podman.container_logs` joins both, its docstring records this trap and
    the measurement that found it on the first live 22.04 cell, and the DHCP
    scenario has always called it. So the trap was found once and re-entered by
    the second caller of the same question. `Podman.logs` now delegates to it, and
    the two cannot disagree again.

    A log read that *raised* would fail the cell as a harness fault, and a
    container whose log cannot be read is not a routing result. So the failure is
    carried as text and the counter check downstream refuses the cell, with a
    message about the routing rather than about podman.
    """
    try:
        return podman.container_logs(container)
    except PodmanError as error:
        return f"(the mock router's log is not readable: {str(error).splitlines()[-1]})"


__all__ = [
    "CHINA_TEST_NAME",
    "CLIENT_ADDRESS",
    "COUNTERS_PATH",
    "DOMESTIC_ANSWER",
    "FOREIGN_ANSWER",
    "FOREIGN_TEST_NAME",
    "FOREIGN_TRANSPORT",
    "MOCK_FOREIGN_ADDRESS",
    "MOCK_ROUTER_ADDRESS",
    "CLIENT_VANTAGE_POINT_REASON",
    "CLIENT_VANTAGE_POINT_REQUIREMENT",
    "PUBLISHED_CN_LIST",
    "READ_FAILED",
    "RoutingScenarioError",
    "SCENARIO_NAME",
    "TARGET_ADDRESS",
    "TARGET_LOCAL_ADDRESS",
    "TRANSPORTS",
    "build_scenario",
    "china_name_key",
    "foreign_counters",
    "matches_china_set",
    "published_cn_domains",
    "router_log",
    "router_queries",
]
