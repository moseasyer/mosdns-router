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

**Both transports, and both vantage points.** UDP and TCP are asked separately
from inside the target and from the client container, and a name that arrived
only over UDP fails the cell -- a scenario that dropped TCP would still resolve
every name it asked, and Step 6 asks for the repeat.

**How a client's answer is known to have come through the target.** A client
container on the private network has the mock router available to it, so an
answer it receives is not by itself evidence about the target. The scenario
therefore puts the *target's* address in the client's `/etc/resolv.conf` -- the
one resolver the client can ask is the target -- and then reads the two mocks'
counters, which are what the target's own forwarding reached. The client's
`resolv.conf` is read and recorded, so a reader of the evidence document sees
which resolver was asked rather than trusting that the answer came from the right
place, and a client whose resolver is *not* the target is refused rather than
measured.

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
from report import ScenarioResult

SCENARIO_NAME = "routing"

# The run's private network, as `dhcp_test.py` fixes it and as the plan's table
# does. The two listener addresses are the whole of what this scenario's split
# rests on, so they are named and compared rather than computed.
MOCK_ROUTER_ADDRESS = "10.89.0.2"
TARGET_ADDRESS = "10.89.0.10"
MOCK_FOREIGN_ADDRESS = "10.89.0.40"
CLIENT_ADDRESS = "10.89.0.30"

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
QUERY_LOG_MARKERS = ("is", "reply", "NXDOMAIN", "cached", "NODATA", "SERVFAIL", "REFUSED")

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

# The address the mock foreign resolver answers with, and the one the mock router
# answers with. Two different addresses, from two different containers, and the
# scenario asserts that the answer a query got is the one belonging to the branch
# that was supposed to answer it -- so an answer from the wrong mock is caught
# even before the counters are read.
FOREIGN_ANSWER = "198.51.100.7"
DOMESTIC_ANSWER = "192.168.123.53"

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

    **A query is recognised by its `reply to` marker, not by the position of a
    field.** dnsmasq(1)'s `log-queries` prints, per query:

    ```text
    Sep 30 20:00:00 hostname 10.89.0.10 probe.example.cn is 10.89.0.2
    Sep 30 20:00:00 hostname 10.89.0.10 probe.example.cn is 1.2.3.4 NXDOMAIN
    ```

    and the two words between the timestamp and the name vary with the log level:
    a query with no answer carries `reply to`, an answered one carries `is <addr>`,
    a refused one carries `NXDOMAIN` or `cached ... NODATA-Other`. So a parser that
    read fields positionally would read the client's address as the name, and the
    first version of this function did exactly that -- it counted nothing at all
    on a real log, and the only symptom was a cell that waited out its whole
    budget and reported a routing failure.

    The marker is therefore the *recognition* and the name is the field before it.
    Everything before the marker is a timestamp, a hostname and a client address,
    none of which is this scenario's business, and a line with no marker is not a
    query -- which is also what keeps a `DHCPDISCOVER` line out of the count.
    """
    counts: dict[str, int] = {}
    for line in log.splitlines():
        fields = line.split()
        marker = next(
            (index for index, field in enumerate(fields) if field in QUERY_LOG_MARKERS), None
        )
        if marker is None or marker < 1:
            continue
        name = fields[marker - 1].strip(".").lower()
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
    return counts


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

    def ask(container, name, transport) -> str:
        """One query, from one container, over one transport, and its output.

        `+tcp` is the whole of the transport choice: `dig`'s `+tcp` forces TCP and
        its absence is UDP, and both are asked rather than one being derived from
        the other. `+short` so the output is the address and nothing else, which
        is what makes "the answer was the one belonging to the branch that was
        supposed to answer it" a comparison rather than a reading.
        """
        command = f"{QUERY_TOOL} +short {'+tcp ' if transport == 'tcp' else ''}@{TARGET_ADDRESS} -p {RESOLVER_PORT} {name}"
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

            # -- 3. the queries, from both vantage points, over both transports
            # Asked from inside the target and from the client container, and over
            # UDP and TCP, with all four combinations asked. A scenario that asked
            # one vantage point would leave the other's path unexercised, and a
            # client is a different resolver stack (glibc, through resolved) from
            # a direct `dig` inside the target.
            answers: dict[str, dict[str, str]] = {}
            for vantage, container in (("target", target), ("client", client)):
                for name_key, name in (("domestic", document["domestic_name"]),
                                       ("foreign", document["foreign_name"])):
                    for transport in TRANSPORTS:
                        key = f"{vantage}/{name_key}/{transport}"
                        answers[key] = ask(container, name, transport)
                        document.setdefault("answers", {})[key] = answers[key]
            _require(
                all(value.strip() for value in answers.values()),
                "at least one of the eight queries returned nothing, so a branch was not "
                "exercised end to end. The answers were:\n"
                + json.dumps(answers, indent=2, sort_keys=True)
                + "\nAn empty answer here is not a routing result: it means a query was asked "
                "and nothing came back, and the counters below are what say which listener "
                "reached",
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
            _require(
                document["foreign_counters"].get(foreign_name, {}).get("udp", 0) >= 1,
                f"the mock foreign resolver counted no UDP query for {foreign_name!r}, so the "
                "foreign branch was not exercised over UDP. It counted "
                f"{sorted(document['foreign_counters'])}",
            )
            _require(
                document["foreign_counters"].get(foreign_name, {}).get("tcp", 0) >= 1,
                f"the mock foreign resolver counted no TCP query for {foreign_name!r}. The "
                "plan's Step 6 asks for the repeat over UDP and TCP, and a cell that asked "
                "only UDP would resolve every name it asked -- so a name that arrived over "
                f"UDP alone fails here. It counted {document['foreign_counters']}",
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
            for vantage in ("target", "client"):
                for name_key, expected in (
                    ("domestic", DOMESTIC_ANSWER),
                    ("foreign", FOREIGN_ANSWER),
                ):
                    for transport in TRANSPORTS:
                        key = f"{vantage}/{name_key}/{transport}"
                        got = answers[key].strip()
                        _require(
                            expected in got,
                            f"the {key} query returned {got!r}, which is not the address the "
                            f"{'domestic' if name_key == 'domestic' else 'foreign'} mock "
                            f"answers with ({expected}). So the answer did not come from the "
                            "listener this scenario is counting, and the counters would be "
                            "evidence about a listener that did not answer it",
                        )
            document["answers_match_their_branch"] = True

            evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME,
                status="passed",
                detail=(
                    f"the two branches reached two different listeners, and the counters say so: "
                    f"the China-set name {china!r} was asked of the mock router at "
                    f"{MOCK_ROUTER_ADDRESS} and never of the mock foreign resolver at "
                    f"{MOCK_FOREIGN_ADDRESS}; the foreign name {foreign_name!r} was asked of the "
                    f"foreign resolver over UDP "
                    f"({document['foreign_counters'].get(foreign_name, {}).get('udp', 0)} time(s)) "
                    f"and over TCP "
                    f"({document['foreign_counters'].get(foreign_name, {}).get('tcp', 0)} time(s)) "
                    f"and never of the mock router. Asked from inside {target} and from the "
                    f"separate client container {client}, whose only resolver is the target. "
                    "Nothing here says anything about IPv6: no cell in this scenario asks an "
                    "AAAA question"
                ),
                log=f"logs/{version}-{SCENARIO_NAME}.json",
            )
        except RoutingScenarioError as error:
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

    A log read that *raised* would fail the cell as a harness fault, and a
    container whose log cannot be read is not a routing result. So the failure is
    carried as text and the counter check downstream refuses the cell, with a
    message about the routing rather than about podman.
    """
    try:
        return podman.logs(container)
    except PodmanError as error:
        return f"(the mock router's log is not readable: {str(error).splitlines()[-1]})"


__all__ = [
    "CHINA_TEST_NAME",
    "CLIENT_ADDRESS",
    "COUNTERS_PATH",
    "DOMESTIC_ANSWER",
    "FOREIGN_ANSWER",
    "FOREIGN_TEST_NAME",
    "MOCK_FOREIGN_ADDRESS",
    "MOCK_ROUTER_ADDRESS",
    "PUBLISHED_CN_LIST",
    "RoutingScenarioError",
    "SCENARIO_NAME",
    "TARGET_ADDRESS",
    "TRANSPORTS",
    "build_scenario",
    "foreign_counters",
    "matches_china_set",
    "published_cn_domains",
    "router_log",
    "router_queries",
]
