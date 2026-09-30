"""The install transaction, run for real, and the barrier that stops it.

Every other scenario in this harness observes a mechanism that already works.
This one observes the property that **the install gets past the range
publication with no route to the internet at all** -- and, because that is where
it stops today, the property that **the refusal it stops at names the foreign
resolver and not the range origin**. Before this step existed both halves were
false: every cell of this matrix ended `half-configured` or `unpacked` with a
refusal that named `api.cloudflare.com`, and the range publication it was
refused at is the one this step made possible.

## What is under test, and what each observation is evidence OF

1. **The transaction got past the CDN step.** `update-lists --refresh-ranges`
   published the package's pinned snapshot in a cell with no route, and the
   document it published is byte-for-byte the snapshot the package ships --
   compared by digest, because a cell that reached the origin would publish a
   *different* document and every other observation would read the same.
2. **postinst verified the pair before the transaction ran.** Its own words are
   in dpkg's output, and the digest it names is the shipped one.
3. **The transaction's refusal is the FOREIGN one.** `dnscrypt-proxy` starts
   and never answers, because the DNSCrypt server it needs is on the internet;
   the transaction's wait for it is the barrier, and the two range refusals that
   would mean the CDN step is what stopped it are required to be ABSENT.
4. **dpkg recorded the state that refusal produces**, and the machine's DNS was
   recorded before the transaction started and never committed to afterwards --
   the backup is there and the ownership marker is not.
5. **The machine has no route to the internet.** Measured in the cell, from the
   route table and a connect to a **literal** address, and asserted.
6. **The refusals are still refusals.** A corrupt shipped snapshot must stop the
   install before the transaction runs, and must publish nothing.

## The requirement this scenario records rather than closes

    with no route to the internet the install transaction completes and the
    package reaches `install ok configured`

The plan wrote that for Task 4 Step 1 and no cell can close it, because the
foreign chain answers from a DNSCrypt server on the internet and the
transaction's barrier needs an answer. It is recorded as a **required skip on
this scenario** -- `Skip(requirement=..., reason=...)` -- which `run.py` hoists
onto the version, so the cell is `incomplete` and the run is exit 3. That is
deliberate and it is the plan's own rule: a skip is never reported as a pass,
so a cell that proved everything it could and could not close the rest must not
read `passed`. It is also the only honest disposition left, because the
alternative -- `failed` -- is a red matrix for something that is not a defect.

**Task 4 Step 5 reads this.** Step 5 adds the test-only foreign override, and
with a foreign answer reachable the transaction completes; at that point this
scenario's expectations are *upgraded* rather than relaxed -- the requiring
assertions on the refusal and on dpkg's state are replaced by the configured
state, and the skip is deleted. The requirement string is the plan's, not a
summary of it, so the report can be read against the plan.
"""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Callable

from podman import PodmanError
from report import ScenarioResult, Skip

SCENARIO_NAME = "install"

# The package's own paths, inside the target. Named here rather than imported from
# the installer, for the reason the other scenarios give: this file runs inside a
# container against the installed package, so the paths it needs are the INSTALLED
# ones -- which is the whole of the difference between a scenario that tests the
# package and one that tests the checkout.
INSTALLER = "/usr/lib/mosdns-router/mosdns_installer.py"
CDNCTL = "/usr/lib/mosdns-router/mosdns-cdnctl"
SHIPPED_PIN = "/usr/share/mosdns-router/cloudflare-ranges.json"
SHIPPED_PIN_LOCK = "/usr/share/mosdns-router/cloudflare-ranges.lock.json"
PUBLISHED_RANGES = "/var/lib/mosdns/lists/cloudflare-ips.json"
PUBLISHED_PREFIX_LIST = "/var/lib/mosdns/lists/cloudflare-prefixes.txt"
PUBLISHED_LIST = "/var/lib/mosdns/lists/cn-domains.txt"
PUBLISHED_LOCK = "/var/lib/mosdns/lists/source-lock.json"
BACKUP_PATH = "/var/lib/mosdns/installer/network-manager-backup.json"
MARKER_PATH = "/var/lib/mosdns/installer/managed-by"

# The origin the range document comes from, and the four timers postinst enables
# after a successful transaction. Both are named here rather than read out of the
# package so a reader can see what the cell is asserting without opening a file.
RANGE_ORIGIN = "https://api.cloudflare.com/client/v4/ips"
TIMERS = (
    "mosdns-cdn-optimizer.timer",
    "mosdns-cdn-health.timer",
    "mosdns-list-check.timer",
    "mosdns-watchdog.timer",
)
# The two daemons the transaction owns, and the ports it must leave served on
# loopback. STEP 3 of the plan asserts only loopback listeners for this project's
# services; this scenario records them and the plan's own step decides what they
# must be.
RESOLVER_UNIT = "dnscrypt-proxy.service"
ROUTER_UNIT = "mosdns-router.service"

DEVICE = "eth0"
MANAGED_PROFILE = "eth0-managed"
MOCK_ROUTER_ADDRESS = "10.89.0.2"
LOCAL_DNS = "127.0.0.1"
DNS_PORT = 53
RESOLVER_PORT = 15353

# **The address the no-route probe asks about, and why it is a literal and not a
# name.** The first version of this probe connected to
# `RANGE_ORIGIN.split('/')[2]` -- `api.cloudflare.com` -- and a UDP `connect()`
# to a NAME resolves it first, through whatever resolver the cell is configured
# with. In this matrix that resolver is the mock router, which is `no-resolv`
# with no upstream and answers exactly one name, so the probe read a
# `socket.gaierror` (`[Errno -2] Name or service not known`) and the assertion --
# which looked for the kernel's `Network is unreachable` or a timeout -- refused
# a cell that had no route, with a message saying the opposite: that the origin
# was reachable and every claim below was true for the wrong reason. MEASURED in
# a 24.04 cell; see the task-4-step1 report.
#
# A literal address measures the route table and nothing else, which is the whole
# claim, and it makes the fake answerable: the rule that answers this command
# matches on `9.9.9.9 443`, so a probe that went back to a name would be a
# command no rule matches and the cell would be refused rather than measured.
# 9.9.9.9 is Quad9's, chosen because it is a well-known public resolver address
# and because the probe is a UDP `connect()`, which sends no packet: it asks the
# routing table and stops.
NO_ROUTE_ADDRESS = "9.9.9.9"
NO_ROUTE_PORT = 443
PROBE_TIMEOUT_SECONDS = 4.0

# The `OSError` numbers that mean "there is no route to that address", and the
# only three this scenario accepts. `ENETUNREACH` is what a container with one
# link-scope route answers; `EHOSTUNREACH` is what a machine with a default
# route and no answer for that host answers; `ETIMEDOUT` is what a blackholed
# route answers once the probe's own timeout runs out. A NAME that does not
# resolve is `EAI_NONAME` (-2) or `EAI_AGAIN` (-3) and is on no list here,
# deliberately: a probe that measured the cell's resolver instead of its route
# table has measured nothing, and accepting its answer is what made the first
# version of this scenario report a routeless cell as a reachable one.
NO_ROUTE_ERRNOS = (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT)

# The two numbers that mean "the NAME did not resolve", named so the refusal can
# say which kind of failure it read rather than only that the number was not in
# the set above. They live in `socket` rather than `errno` because a name is not
# a system call: getaddrinfo reports them itself.
NAME_ERRNOS = (socket.EAI_NONAME, socket.EAI_AGAIN)

# The probe program, run in the cell through `python3 -c`. It classifies the
# failure ITSELF and prints the number, because the number is the fact and a
# message is a sentence somebody can spell differently on a different kernel. The
# traceback the first version relied on is gone with the name.
PROBE_PROGRAM = "\n".join(
    (
        "import errno, socket, sys",
        "address, port = sys.argv[1], int(sys.argv[2])",
        "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
        f"sock.settimeout({PROBE_TIMEOUT_SECONDS:g})",
        "try:",
        "    sock.connect((address, port))",
        "except OSError as error:",
        "    print('mosdns-probe: failed errno=%d text=%s' % (error.errno, error.strerror))",
        "else:",
        "    print('mosdns-probe: connected')",
    )
)
CLAIM_PROBE_CONNECTED = "mosdns-probe: connected"
CLAIM_PROBE_FAILED = re.compile(r"mosdns-probe: failed errno=(-?\d+)")

# The prefix every line of a maintainer script's own output carries --
# `postinst: `, `install: `, `note: `, `dpkg: ` -- stripped before a sentence is
# matched. Named as a module-level thing rather than a nested helper because the
# cases have to apply the SAME rule to the same output, and a second copy of it
# in a test is a second thing that can be wrong about what the program said.
OUTPUT_LINE_PREFIX = re.compile(r"^[a-z][a-z0-9_-]*:[ \t]+")


def flatten_output(text: str) -> str:
    """`text` as one line, with the writers' own per-line prefixes removed.

    postinst and the installer both write one sentence across several `echo`
    lines, each line carrying the program's own name as a prefix -- so
    "It is read" ends one line, "postinst: here and never written" starts the
    next, and a claim that spans the two is not findable in the raw output
    however exactly it is quoted. Collapsing the whitespace keeps the assertion
    on the SENTENCE, which is what the claim is, rather than on where the writer
    happened to wrap it. The raw output is recorded as well, and is what a
    reader reads.
    """
    return " ".join(
        OUTPUT_LINE_PREFIX.sub("", line) for line in (text or "").splitlines()
    )

# How long to wait for the machine to reach a state after a command that should
# cause it. Every one of these is a poll of a real fact, not a sleep.
DEFAULT_WAIT_SECONDS = 120.0
WAIT_INTERVAL_SECONDS = 3.0

# The states dpkg records. `installed` and `install ok installed` are the two
# spellings of the configured state: `${Status}` is the phrase and
# `${db:Status-Status}` is the one-word form, and both are read because a
# scenario that asserted one literal would be asserting dpkg's formatting rather
# than dpkg's decision.
CONFIGURED_STATES = ("installed", "install ok installed")
# And the two words dpkg records when a package's configuration step refused,
# depending on how far its own state machine got before postinst exited
# non-zero. **Measured, both**: `half-configured` on 24.04 and 26.04, `unpacked`
# elsewhere. Requiring either keeps the assertion on the property -- the
# transaction did not finish -- rather than on which of the two dpkg chose.
REFUSING_STATES = ("half-configured", "unpacked")

# The messages that are the product. A scenario that asserted only "the package
# installed" would pass against a transaction that installed a selector over
# ranges nobody can name -- and, in the shape this scenario is written in, one
# that asserted only "the transaction refused" would pass against a cell where
# the refusal is the one this step existed to remove.
CLAIM_PIN_PUBLISHED = "ranges-source: pinned-snapshot"
CLAIM_PIN_VERIFIED = "ranges-pin-verified: true"
CLAIM_PIN_DRIFT_NONE = "ranges-pin-drift: none"
# postinst's STEP 3, verbatim from a measured 24.04 cell: the shipped pair
# verified, and the position it states about not re-pinning.
CLAIM_PIN_CHECKED_BY_POSTINST = "the pinned range document at"
CLAIM_PIN_NEVER_REPINNED = "It is read here and never written"
# The transaction's OWN refusal, verbatim. This is the barrier: `dnscrypt-proxy`
# binds its loopback listener once its own reachability probe runs out and then
# cannot answer, because the DNSCrypt server it needs is on the internet and it
# has no route to one. MEASURED, 24.04, 2026-09-30; the number after `within`
# is `WAIT_DEADLINE_SECONDS` and is deliberately not part of the match, so
# changing the wait does not silently invalidate the claim.
CLAIM_RESOLVER_BARRIER = "was started but nothing answered a DNS query at 127.0.0.1:15353 within"
# What the installer's rollback says, and what postinst's own arms say about it.
CLAIM_ROLLED_BACK = "every change this run made has been rolled back"
CLAIM_POSTINST_SAW_REFUSAL = "the install transaction refused this machine and rolled back"
CLAIM_NOTHING_ENABLED = "Nothing is enabled and nothing was started"
# The two sentences that would mean the RANGE step is what refused, and the two
# this scenario requires to be absent from the same output. `cannot stand in
# for it` is `standInFor`'s own wording -- the pin could not replace an
# unreadable origin -- and `cannot account for` is postinst's -- the shipped pair
# does not match its lock. Either one in the transaction's output is a cell that
# did not get past the CDN step, which is the state this step was written to end,
# and a scenario that only asserted "the transaction refused" could not tell the
# two apart.
CDN_BARRIER_SIGNATURES = ("cannot stand in for it", "cannot account for")

# The requirement this scenario cannot close in a cell with no route, in the
# plan's own words -- the requirement as `docs/superpowers/plans/
# 2026-09-25-podman-integration-matrix.md` Task 4 Step 1 first wrote it, and as
# that step's correction leaves it. It is recorded rather than asserted, and the
# step that closes it is named in the reason.
OFFLINE_CONFIGURED_REQUIREMENT = (
    "with no route to the internet the install transaction completes and the "
    "package reaches `install ok configured`"
)


class InstallScenarioError(Exception):
    """An install claim the run could not establish, with the evidence attached.

    Its own type rather than the harness's `PodmanError`, for the reason
    `dhcp_test.py` gives: a failed assertion inside a scenario is a test failure
    (a `failed` row), and a harness fault is exit 2. A scenario that raised the
    harness's error for "the install refused" would be reporting a broken matrix
    as a broken harness.
    """


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InstallScenarioError(message)


def build_scenario(
    *,
    podman,
    version: str,
    arch: str,
    run_id: str,
    router: str,
    target: str,
    network: str,
    results_dir,
    deb: Path,
    wait_seconds: float = DEFAULT_WAIT_SECONDS,
    interval: float = WAIT_INTERVAL_SECONDS,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Callable[[], ScenarioResult]:
    """The `install` scenario, bound to one matrix cell's target.

    `deb` is the package to install, and it is a parameter rather than a path
    computed here: this scenario installs the package for real, and a scenario
    that reached for a global would be measuring whichever build happened to be
    on disk.
    """
    log_name = f"logs/{version}-{SCENARIO_NAME}.json"
    log_path = Path(results_dir) / run_id / log_name

    def read(*command):
        return podman.exec_container(target, *command).output

    def run(script: str) -> None:
        podman.exec_script(target, script)

    def try_read(*command) -> str:
        """One read that cannot fail the run, for evidence rather than a claim."""
        try:
            return read(*command)
        except PodmanError as error:
            return f"(not readable: {str(error).splitlines()[-1]})"

    def wait_for(probe, accept, what: str, seen=lambda: "", timeout=wait_seconds):
        """Poll a real fact until it holds, and return what it read.

        A poll rather than a sleep, for the reason the harness's own cell gate
        gives: `podman run -d` returns before the target has booted, and a
        scenario that slept would be reading a race.
        """
        deadline = now() + timeout
        last = ""
        while True:
            last = probe()
            if accept(last):
                return last
            if now() >= deadline:
                raise InstallScenarioError(
                    f"{what} within {timeout:g}s in {target}; last read: {last!r}{seen()}"
                )
            sleep(interval)

    def package_status() -> tuple[str, str]:
        """dpkg's own two spellings of this package's state.

        Read as a pair because they answer different questions and a scenario
        that read only one could be satisfied by a package dpkg left unpacked:
        `${Status}` is the phrase, `${db:Status-Status}` the one word. Both are
        recorded whatever they say.
        """
        return (
            try_read(
                "sh", "-c", "dpkg-query -W -f='${db:Status-Status}\\n' mosdns-router 2>&1 || true"
            ).strip(),
            try_read(
                "sh", "-c", "dpkg-query -W -f='${Status}\\n' mosdns-router 2>&1 || true"
            ).strip(),
        )

    def digest_of(path: str) -> str:
        """One file's sha256, or the empty string when it is not readable.

        Empty rather than a fabricated value, because every comparison below is
        an equality between two of these and a placeholder would make an absent
        file look like a file whose digest happens to be nothing.
        """
        try:
            return read("sha256sum", path).split()[0]
        except (PodmanError, IndexError):
            return ""

    def evidence(document: dict) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def run_scenario() -> ScenarioResult:
        document = {
            "arch": arch,
            "target_container": target,
            "router_container": router,
            "package": str(deb),
        }
        try:
            # -- 1. the machine, and its OWN resolver, before anything else ----
            # The hand-off comes first for the measured reason the other two
            # scenarios give: the image's own `target-nm-setup.service` creates the
            # `eth0-managed` profile at boot, and on 24.04 and 26.04 the device is
            # left on NetworkManager's own `eth0`, so the link has no resolver at
            # all until that profile is activated. The install records the ACTIVE
            # connection, so a record naming a profile with no DHCP lease is a
            # record of nothing.
            run(
                "set -eu\n"
                f"nmcli connection modify {MANAGED_PROFILE} ipv4.never-default yes\n"
                f"nmcli connection up {MANAGED_PROFILE}\n"
            )
            document["profile_after_handoff"] = wait_for(
                lambda: read("nmcli", "-g", "GENERAL.CONNECTION", "device", "show", DEVICE),
                lambda value: value.strip() == MANAGED_PROFILE,
                what=f"the device {DEVICE} in {target} to be on {MANAGED_PROFILE}",
                seen=lambda: "; the image's own profile is what carries a DHCP lease, and without "
                             "it the link has no resolver for the install to record",
            ).strip()
            document["dhcp_dns_published"] = wait_for(
                lambda: read("nmcli", "-g", "IP4.DNS", "device", "show", DEVICE),
                lambda value: MOCK_ROUTER_ADDRESS in value,
                what=f"the mock router's address on IP4.DNS of {DEVICE} in {target}",
                seen=lambda: "; the machine's own resolver has to be working before the install "
                             "records what it was",
            ).strip()

            # -- 2. THE PROPERTY: no route to the internet --------------------
            # Measured, not assumed, and ASSERTED. A cell whose bridge NATs
            # outward would install for an entirely different reason -- the origin
            # would be reachable and the shipped snapshot would never be consulted
            # -- and every observation below would read the same while measuring
            # nothing. So the cell's lack of a route is the precondition of this
            # scenario, and a cell that has one is reported rather than passed.
            document["route_table"] = try_read("ip", "route", "show")
            document["probe_address"] = f"{NO_ROUTE_ADDRESS}:{NO_ROUTE_PORT}"
            document["origin_reachable"] = try_read(
                "sh", "-c",
                f'python3 -c "{PROBE_PROGRAM}" {NO_ROUTE_ADDRESS} {NO_ROUTE_PORT} 2>&1 || true',
            ).strip()
            failure = CLAIM_PROBE_FAILED.search(document["origin_reachable"] or "")
            document["origin_probe_errno"] = int(failure.group(1)) if failure else None
            _require(
                CLAIM_PROBE_CONNECTED not in document["origin_reachable"],
                f"a UDP connect to {document['probe_address']} SUCCEEDED in {target}, so this cell has a "
                f"route off its own bridge and the origin would be reachable from it. Every claim below "
                f"would then be true for a different reason -- the snapshot the package ships would never "
                f"be consulted. The probe said:\n{document['origin_reachable']}\n"
                f"and the cell's route table is:\n{document['route_table']}",
            )
            _require(
                document["origin_probe_errno"] is not None,
                f"the probe to {document['probe_address']} reported no errno at all:\n"
                f"{document['origin_reachable']!r}\n"
                f"The probe asks a LITERAL address, so this is not a resolution failure -- it is a probe "
                f"that did not run, or one whose output this scenario cannot read. A cell that answered a "
                f"NAME here instead would be measuring this cell's resolver rather than its route table, "
                f"and the route table is the claim:\n{document['route_table']}",
            )
            _require(
                document["origin_probe_errno"] in NO_ROUTE_ERRNOS,
                f"the probe to {document['probe_address']} failed with errno "
                f"{document['origin_probe_errno']}, which is not one of the {NO_ROUTE_ERRNOS} this "
                f"scenario accepts as 'no route to that address':\n"
                f"{document['origin_reachable']}\n"
                + (
                    f"That is a NAME that did not resolve ({NAME_ERRNOS} are "
                    f"'{os.strerror(socket.EAI_NONAME)}' and '{os.strerror(socket.EAI_AGAIN)}'), and a "
                    f"probe that measured this cell's resolver instead of its route table has measured "
                    f"nothing. The probe asks {NO_ROUTE_ADDRESS} -- a literal -- so this is the shape "
                    f"of the probe, not a property of this cell.\n"
                    if document["origin_probe_errno"] in NAME_ERRNOS
                    else "The probe asks a literal address, so this is a failure of the route to it "
                         "that this scenario does not recognise, and it is not treated as 'no route'.\n"
                )
                + f"The cell's route table is:\n{document['route_table']}",
            )
            document["no_route_established"] = True

            # -- 3. the package, installed with dpkg, ONCE --------------------
            podman.copy_to(target, str(deb), "/tmp/mosdns-router.deb")
            document["package_bytes"] = int(
                try_read("stat", "-c", "%s", "/tmp/mosdns-router.deb").strip() or 0
            )
            # One install, through `sh -c`, with the status out of the SAME
            # invocation: `exec_status` keeps no output, so a status read through
            # it describes an install whose words are in a different string --
            # which is how the previous version of the watchdog scenario ran
            # `dpkg -i` twice and recorded the second run's state.
            document["dpkg_output"] = try_read(
                "sh", "-c",
                "dpkg -i /tmp/mosdns-router.deb 2>&1; printf 'DPKG_EXIT=%s\\n' \"$?\"",
            )[:8000]
            match = re.search(r"DPKG_EXIT=(\d+)", document["dpkg_output"] or "")
            document["dpkg_exit"] = int(match.group(1)) if match else 0
            document["dpkg_runs"] = 1
            one_word, phrase = package_status()
            document["package_state"] = one_word
            document["package_status_phrase"] = phrase
            document["package_configured"] = (
                one_word in CONFIGURED_STATES or phrase in CONFIGURED_STATES
            )
            document["package_state_explained"] = (
                f"dpkg recorded {one_word!r} / {phrase!r}. Both spellings are read because "
                "`${Status}` is the phrase and `${db:Status-Status}` the one word, and a scenario "
                "that asserted one literal would be asserting dpkg's formatting rather than dpkg's "
                "decision. dpkg's own output is in this document, and the barrier that stopped the "
                "transaction is quoted in `transaction_barrier` below."
            )
            _require(
                not document["package_configured"],
                f"the package is {one_word!r} / {phrase!r} -- CONFIGURED -- and this scenario is "
                "written for the cell where the transaction refuses at the resolver's barrier, so "
                "either the cell got further than the scenario expects or the scenario is out of "
                "date. The plan says which: Task 4 Step 5 adds the test-only foreign override, and "
                "THIS scenario is what it upgrades -- the assertions below are replaced by the "
                "configured state and the recorded skip is deleted, rather than relaxed to accept "
                "both. dpkg's output is in this document:\n"
                f"{document['dpkg_output']}",
            )
            _require(
                one_word in REFUSING_STATES,
                f"dpkg recorded {one_word!r}, which is neither a configured state "
                f"({CONFIGURED_STATES}) nor one of the states a refused configuration step leaves "
                f"({REFUSING_STATES}), so what this scenario observed is not what it says it "
                f"observed. dpkg's exit was {document['dpkg_exit']} and its output is in this "
                f"document:\n{document['dpkg_output']}",
            )
            _require(
                "ok " in phrase,
                f"dpkg reports {phrase!r}, which is not one of the unpacked-but-not-configured "
                f"phrases this scenario is written for, so the state above is not the one the rest "
                f"of this document describes",
            )

            # -- 4. WHICH barrier refused, and what the transaction left -------
            # **This is the load-bearing section of the scenario.** A cell that
            # merely refused could have refused at the range step -- the state
            # this step was written to end -- and every other observation in
            # this file would read the same, because postinst verifies the pair
            # and the transaction publishes from it in both cells. So the
            # transaction's own words are required to name the resolver's wait
            # and the two range refusals are required to be absent, and the
            # rollback and postinst's own account of it are required to be
            # present.
            document["transaction_barrier"] = next(
                (line for line in (document["dpkg_output"] or "").splitlines()
                 if CLAIM_RESOLVER_BARRIER in line),
                "",
            )
            flat = flatten_output(document["dpkg_output"])
            for claim, what in (
                (CLAIM_PIN_CHECKED_BY_POSTINST, "postinst verified the shipped pair"),
                (CLAIM_RESOLVER_BARRIER, "the resolver's own start-up barrier refused the transaction"),
                (CLAIM_ROLLED_BACK, "the installer rolled the transaction back"),
                (CLAIM_POSTINST_SAW_REFUSAL, "postinst saw the refusal and rolled back with it"),
                (CLAIM_NOTHING_ENABLED, "postinst said nothing was enabled or started"),
            ):
                _require(
                    claim in flat,
                    f"dpkg's output does not contain {what} ({claim!r}), so this cell's refusal is "
                    "not the one this step delivered -- either it is the range step refusing again, "
                    "or the transaction refused somewhere else entirely, and either way the evidence "
                    f"document would describe a barrier it did not observe. dpkg's output:\n"
                    f"{document['dpkg_output']}",
                )
            _require(
                CLAIM_PIN_NEVER_REPINNED in flat,
                f"postinst verified the pair but did not say {CLAIM_PIN_NEVER_REPINNED!r}, which is the "
                "position that keeps this snapshot from being re-pinned at install time. If that changed "
                "then a package an operator reviewed is not the package that gets installed, and the "
                f"report should say so. dpkg's output:\n{document['dpkg_output']}",
            )
            for signature in CDN_BARRIER_SIGNATURES:
                _require(
                    signature not in flat,
                    f"dpkg's output contains {signature!r}, which is what the RANGE step says when it "
                    "refuses, so the transaction did not get past the CDN step in this cell and every "
                    "claim below would be true of a cell this step did not fix. dpkg's output:\n"
                    f"{document['dpkg_output']}",
                )
            document["barrier_is_the_foreign_resolver"] = True
            # The machine's DNS was recorded before the transaction's first
            # mutation and was never committed to, so the backup is there and
            # the ownership marker is not. Two facts, and the second is the one
            # that says the transaction did not take the machine over: a marker
            # written by a refused transaction would tell the next run's
            # uninstall that this package owns DNS it rolled back.
            document["backup_present"] = podman.exec_status(target, "test", "-e", BACKUP_PATH) == 0
            document["marker_present"] = podman.exec_status(target, "test", "-e", MARKER_PATH) == 0
            _require(
                document["backup_present"],
                f"{BACKUP_PATH} is not in {target} after a transaction that reported rolling itself "
                "back, so this machine's DNS was changed with nothing recording what it was",
            )
            _require(
                not document["marker_present"],
                f"{MARKER_PATH} IS in {target} after a transaction that reported rolling itself back. "
                "The marker is what tells a later uninstall that this package owns the machine's DNS, "
                "and a refused transaction that left one would have a rollback point pointing at DNS "
                "it never changed.",
            )

            # -- 5. WHY it got that far: the shipped snapshot ---------------
            # The load-bearing comparison in this scenario. A cell that published
            # from the origin would hold a *different* document, so equality of
            # the two digests is what says the pin was the source rather than
            # evidence that merely happens to hold.
            document["shipped_pin_sha256"] = digest_of(SHIPPED_PIN)
            document["shipped_pin_lock_sha256"] = digest_of(SHIPPED_PIN_LOCK)
            document["published_ranges_sha256"] = digest_of(PUBLISHED_RANGES)
            document["published_prefix_list_sha256"] = digest_of(PUBLISHED_PREFIX_LIST)
            _require(
                document["shipped_pin_sha256"] != "",
                f"{SHIPPED_PIN} is not readable in {target}, so this package ships no pinned range "
                "document and the install cannot have used one",
            )
            _require(
                document["published_ranges_sha256"] == document["shipped_pin_sha256"],
                f"the published range document is {document['published_ranges_sha256']} and the snapshot "
                f"the package ships is {document['shipped_pin_sha256']}. The transaction got past the "
                f"range step on a machine with no route, so the document it published has to be the "
                f"shipped one, and these are not equal.",
            )
            _require(
                document["published_prefix_list_sha256"] != "",
                f"{PUBLISHED_PREFIX_LIST} is not readable in {target} after a transaction that "
                "published a range document, so the response rewriter would refuse to construct on "
                "this machine",
            )
            document["prefix_list_lines"] = len(
                [line for line in try_read("cat", PUBLISHED_PREFIX_LIST).splitlines() if line.strip()]
            )
            _require(
                document["prefix_list_lines"] > 0,
                f"{PUBLISHED_PREFIX_LIST} is empty in {target}, so the selector has no ranges and a "
                "router that cannot construct is a router that binds nothing on port 53",
            )
            document["china_pair_sha256"] = {
                PUBLISHED_LIST: digest_of(PUBLISHED_LIST),
                PUBLISHED_LOCK: digest_of(PUBLISHED_LOCK),
            }

            # -- 6. the report an operator reads, read in the cell ------------
            # **Both modes, and both are report-only, and BOTH ARE READ FROM ONE
            # INVOCATION EACH.** The publish is asked with the published
            # artifacts REMOVED first, so the machine's own document cannot stand
            # in -- which is the state a fresh install is in and the only state
            # in which the snapshot is the source. And the report is read out of
            # that same invocation, because a second `update-lists
            # --refresh-ranges` asks a different question: the first one
            # published a document, so the second reports `ranges-source: cache`
            # and says nothing about the pin at all.
            #
            # That is MEASURED, and it is what the first version of this section
            # did: the fixture answered both invocations with the pin's report,
            # so twenty cases were asserting the answer the fake was written with
            # rather than the one the cell produced, and the real cell produced
            # `ranges-source: cache`.
            document["refresh_report"] = try_read(
                "sh", "-c",
                f"rm -f {PUBLISHED_RANGES} {PUBLISHED_PREFIX_LIST}\n"
                f"{CDNCTL} update-lists --refresh-ranges 2>&1\n"
                f"printf 'REFRESH_EXIT=%s\\n' \"$?\"",
            )[:4000]
            refresh = re.search(r"REFRESH_EXIT=(\d+)", document["refresh_report"] or "")
            document["refresh_exit"] = int(refresh.group(1)) if refresh else None
            _require(
                document["refresh_exit"] == 0,
                f"the refresh on a machine with no route exited {document['refresh_exit']!r} rather "
                f"than 0, so it published nothing and every claim about the published document is "
                f"about an earlier run:\n{document['refresh_report']}",
            )
            _require(
                CLAIM_PIN_PUBLISHED in document["refresh_report"],
                "a refresh on a machine with no route and no published document did not report the "
                "package's snapshot as its source, so the offline path this step added is not the one "
                f"that ran:\n{document['refresh_report']}",
            )
            document["check_report"] = try_read(
                "sh", "-c", f"{CDNCTL} update-lists --check 2>&1 || true"
            )[:6000]
            for claim, what in (
                (CLAIM_PIN_VERIFIED, "the shipped snapshot verified"),
                (CLAIM_PIN_DRIFT_NONE, "the published document matched the shipped one"),
            ):
                _require(
                    claim in document["check_report"],
                    f"the daily check did not report {what}, so the drift measurement this step added "
                    f"is not reaching an operator on the machine it was written for:\n"
                    f"{document['check_report']}",
                )
            document["pin_age_reported"] = bool(
                re.search(r"^ranges-pin-age: ", document["check_report"], re.MULTILINE)
            )
            _require(
                document["pin_age_reported"],
                "the check reported no `ranges-pin-age`, so a snapshot nobody measures the age of is "
                f"exactly what this machine has:\n{document['check_report']}",
            )

            # -- 7. the timers, recorded rather than asserted -----------------
            # **Both the unit files and the enabled state, and neither is
            # asserted to be enabled.** The transaction refused, so postinst
            # never reached its enable step and its own output says so
            # (`CLAIM_NOTHING_ENABLED`, asserted above). What is asserted is that
            # the four unit files are installed -- a package dpkg refused still
            # unpacked them, and a cell where it did not is a different package
            # -- and the enabled state is recorded because Task 4 Step 5 is the
            # step that changes it, and the report should show both readings
            # rather than this scenario's opinion of one.
            for timer in TIMERS:
                document[f"unit-file:{timer}"] = (
                    "present" if podman.exec_status(target, "test", "-e", f"/usr/lib/systemd/system/{timer}") == 0
                    else "absent"
                )
                _require(
                    document[f"unit-file:{timer}"] == "present",
                    f"{timer} is not installed in {target} after a dpkg run that unpacked this "
                    "package, so the transaction refused over something other than a missing unit and "
                    f"the refusal above is not the whole of it. dpkg's output is in this document:\n"
                    f"{document['dpkg_output']}",
                )
                document[f"enabled:{timer}"] = try_read(
                    "sh", "-c", f"systemctl is-enabled {timer} 2>/dev/null || true"
                ).strip()
            for unit in (RESOLVER_UNIT, ROUTER_UNIT):
                document[f"state:{unit}"] = try_read(
                    "sh", "-c", f"systemctl show --property=ActiveState --value {unit}"
                ).strip()
            document["loopback_listeners"] = try_read(
                "sh", "-c", f"ss -lntup 2>/dev/null | grep -E '127\\.0\\.0\\.1:({DNS_PORT}|{RESOLVER_PORT})\\b' || true"
            )

            # -- 8. the refusal, on the same cell ---------------------------
            # The other half of the property, and the half a happy-path-only
            # scenario leaves unverified. One byte of the SHIPPED snapshot is
            # changed and the install is repeated: postinst must refuse BEFORE the
            # transaction, and must publish nothing. The pair is restored
            # afterwards so the cell is left as it was found, which also means the
            # restore is itself observed rather than assumed.
            #
            # **The bytes come back as base64, and that is not decoration.** The
            # wrapper's `.output` strips trailing whitespace, so a plain
            # `cat`-and-heredoc restore writes the file back with the heredoc's
            # terminator glued to its last line -- a different file with a
            # different digest. MEASURED: the first version of this restore
            # produced
            # `e249206b0e0a5c1f41084ae0b31d4ace48981ffd11b004c40aedc92477d447a1`
            # where the shipped pair is
            # `fa80894eae91ea4b2240e8571048933eeb178f2a7757c5dcfe58c44acd0e5165`,
            # and the assertion below caught it. Base64 has no trailing
            # whitespace to strip and nothing that needs quoting, so the restore
            # writes back exactly the bytes that were read.
            original = try_read("sh", "-c", f"base64 -w0 {SHIPPED_PIN}").strip()
            _require(
                original != "" and not original.startswith("(not readable:"),
                f"{SHIPPED_PIN} could not be read as base64 in {target}, so there is nothing to "
                "restore it to and the refusal case below would leave the cell holding a corrupted "
                "shipped snapshot",
            )
            try:
                run(
                    "set -eu\n"
                    f"sed -i 's#104\\.16\\.0\\.0/13#104.16.0.0/12#' {SHIPPED_PIN}\n"
                    f"rm -f {PUBLISHED_RANGES} {PUBLISHED_PREFIX_LIST}\n"
                    f"dpkg --configure mosdns-router 2>&1 || true\n"
                )
                document["corrupt_pin_output"] = try_read(
                    "sh", "-c", "dpkg --configure mosdns-router 2>&1 || true"
                )[:6000]
                document["corrupt_pin_state"] = package_status()[0]
                document["corrupt_pin_published"] = [
                    path for path in (PUBLISHED_RANGES, PUBLISHED_PREFIX_LIST)
                    if podman.exec_status(target, "test", "-e", path) == 0
                ]
                _require(
                    "cannot account for" in document["corrupt_pin_output"],
                    "a shipped snapshot whose bytes its lock does not record did not stop the install, "
                    "so this package would configure a machine's DNS over a range list it cannot name. "
                    f"postinst said:\n{document['corrupt_pin_output']}",
                )
                # The refusal is in STEP 3, before the transaction: the
                # transaction's own words are absent, which is what says nothing
                # was captured, backed up or changed.
                _require(
                    "Nothing has been changed on this machine's DNS" in document["corrupt_pin_output"],
                    "the corrupt-snapshot refusal did not say that nothing was changed, so an operator "
                    f"reading it cannot tell a refusal from a partial install:\n"
                    f"{document['corrupt_pin_output']}",
                )
                _require(
                    document["corrupt_pin_published"] == [],
                    f"a refused install published {document['corrupt_pin_published']}, so the next "
                    "install's start requirement would be satisfied by ranges nothing accounts for",
                )
                _require(
                    document["corrupt_pin_state"] in REFUSING_STATES,
                    f"a refused install left the package {document['corrupt_pin_state']!r}, which is "
                    f"neither configured ({CONFIGURED_STATES}) nor one of the states a refused "
                    f"configuration step leaves ({REFUSING_STATES}), so the cell both passed and "
                    f"refused and the evidence document would describe whichever it found first",
                )
                document["corrupt_pin_refused"] = True
            finally:
                # The restore, by writing the bytes that were read back rather
                # than re-fetching them: a restore that reached the network would
                # be able to put a DIFFERENT document in place and leave the cell
                # in a state no other cell starts from. The digest is asserted
                # below, so a restore that failed cannot pass quietly either.
                run(
                    "set -eu\n"
                    f"printf '%s' '{original}' | base64 -d > {SHIPPED_PIN}\n"
                )
            document["pin_restored_sha256"] = digest_of(SHIPPED_PIN)
            _require(
                document["pin_restored_sha256"] == document["shipped_pin_sha256"],
                f"the shipped snapshot was restored to {document['pin_restored_sha256']} and not to "
                f"{document['shipped_pin_sha256']}, so the refusal case left the cell in a state no "
                "other cell would start from",
            )

            skip = Skip(
                requirement=OFFLINE_CONFIGURED_REQUIREMENT,
                reason=(
                    f"the transaction got past the range step and refused at the resolver's own "
                    f"start-up barrier instead: dpkg's output says {document['transaction_barrier']!r}. "
                    f"dnscrypt-proxy binds 127.0.0.1:15353 once its own reachability probe runs out and "
                    f"then cannot answer, because the DNSCrypt server it needs is on the internet and "
                    f"this cell has no route to one -- so no pinned data can change it, and the "
                    f"transaction waits for an answer that cannot come. The range document was "
                    f"published and is the snapshot the package ships "
                    f"({document['shipped_pin_sha256'][:16]}...), which is the property this step "
                    f"delivers. Task 4 Step 5 adds the test-only foreign override; that is the step "
                    f"that closes this requirement, and it upgrades this scenario rather than relaxing "
                    f"it."
                ),
            )
            document["unclosed_requirements"] = [skip.to_dict()]
            evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME,
                status="passed",
                detail=(
                    f"with no route to the internet the transaction got past the range step: "
                    f"update-lists --refresh-ranges reported "
                    f"{CLAIM_PIN_PUBLISHED}, the published document is the snapshot the package ships "
                    f"({document['shipped_pin_sha256'][:16]}...), and postinst verified the pair. It "
                    f"then refused at the resolver's start-up barrier -- dnscrypt-proxy answers nothing "
                    f"at 127.0.0.1:15353 without a route to a DNSCrypt server -- so dpkg recorded "
                    f"{document['package_status_phrase'] or document['package_state']}, the machine's "
                    f"original DNS was recorded and rolled back and never committed to, and a snapshot "
                    f"whose bytes its lock does not record still refused the install before the "
                    f"transaction ran and published nothing. The requirement this cell cannot close, "
                    f"'{OFFLINE_CONFIGURED_REQUIREMENT}', is recorded as a required skip, so this cell "
                    f"is incomplete rather than passed."
                ),
                log=f"logs/{version}-{SCENARIO_NAME}.json",
                skips=(skip,),
            )
        except InstallScenarioError as error:
            evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME,
                status="failed",
                detail=str(error),
                log=f"logs/{version}-{SCENARIO_NAME}.json",
            )

    return run_scenario
