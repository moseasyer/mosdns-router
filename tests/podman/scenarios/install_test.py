"""The install transaction, run for real, with **no route to the internet at all**.

Every other scenario in this harness observes a mechanism that already works.
This one observes the property that **the transaction completes and the package
reaches `install ok configured` on a machine that cannot reach anything** -- and
the two things that make that possible, both of which are *test-only* and both of
which are held to being test-only.

## What is under test, and what each observation is evidence OF

1. **The transaction got past the CDN step.** `update-lists --refresh-ranges`
   published the package's pinned snapshot in a cell with no route, and the
   document it published is byte-for-byte the snapshot the package ships --
   compared by digest, because a cell that reached the origin would publish a
   *different* document and every other observation would read the same.
2. **postinst verified the pair before the transaction ran.** Its own words are
   in dpkg's output, and the digest it names is the shipped one.
3. **A foreign answer was reachable, and only because of the override.**
   `dnscrypt-proxy` completed a real DNSCrypt exchange with a mock on the run's
   private network, so the transaction's own barrier -- which is *that listener
   answering* -- passed. The document that made it reachable is
   `/etc/mosdns/dnscrypt-proxy.toml` with **its stamps and nothing else**
   replaced, and the evidence document carries the changed lines so a reader can
   check that claim rather than take it.
4. **The shipped documents are unchanged.** The resolver document in the
   *artifact* is compared, by digest, against the repository's own file, and
   against the override the target is running -- so "the override is test-only"
   is three digests rather than a promise.
5. **The machine has no route to the internet.** Measured in the cell, from the
   route table and a connect to a **literal** address, and asserted. This is the
   precondition of the whole scenario: a cell whose bridge NATs outward would
   install for an entirely different reason.
6. **The machine's DNS was taken over and recorded.** The backup is there *and*
   the ownership marker is there, which is the pair that says the transaction
   committed rather than rolled back.
7. **The refusals are still refusals.** A corrupt shipped snapshot must still
   stop the install before the transaction runs, and must publish nothing --
   which is what makes the success above a fact about a machine that can install
   and not about a package that stopped refusing.

## Why this scenario requires the CONFIGURED state, and not either

The plan's own words, which are the requirement this file asserts and which
`OFFLINE_CONFIGURED_REQUIREMENT` holds verbatim so a reader can check one against
the other: *"with no route to the internet the install transaction completes and
the package reaches `install ok configured`"*.

It did not always. It was written for a cell where the transaction refused at the
resolver's own barrier, and it recorded the requirement it could not close as a
**required skip** on this scenario, which `run.py` hoists onto the version -- so
the cell was `incomplete` and the run exit 3, because a skip is never reported as
a pass. That was the honest disposition then, and it is gone now: the override
makes a foreign answer reachable, so the transaction completes, so the requiring
assertions are **replaced** rather than made optional.

**Replaced, not relaxed.** A scenario that accepted both dispositions would
prove nothing about either: "the transaction completed" and "the transaction
refused" are different worlds, and a check satisfied by both cannot tell a reader
which one a cell was in. So the four requiring assertions about the resolver's
barrier and the two about the range refusals being absent are **dropped** and
replaced by assertions about the configured state, the timers being enabled, the
ownership marker being present, and the two daemons being active.
`test_a_cell_where_the_transaction_completed_is_refused` in
`tests/podman/tests/test_install_scenario.py` is the case that fails if the
replacement is not made.

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

import foreign_override

from podman import PodmanError
from report import ScenarioResult

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
# Where the resolver document is read back out of the .deb after the install, so
# "the package was not modified to make this cell pass" is a digest rather than a
# claim. Inside the target, because that is where the artifact is.
ARTIFACT_DNSCrypt_TMP = "/tmp/mosdns-router-artifact-dnscrypt-proxy.toml"
MARKER_PATH = "/var/lib/mosdns/installer/managed-by"

# **The ROUTER's document, and the one shipped copy of it the cell compares the
# target's against.** The DNSCrypt document is the foreign branch's; this one is
# the DOMESTIC branch's, and until this constant existed the plan's "Production
# shipped config and packaged DNSCrypt config remain unchanged and are asserted
# separately" had an assertion for the second half only -- MEASURED,
# `grep -rn "/etc/mosdns/mosdns" tests/podman/` returned nothing.
#
# The failure that absence permits is not hypothetical. The override's purpose is
# to point a *foreign forward address* at a mock; if the harness ever wrote the
# ROUTER document to do that instead, every counter would still read correctly
# and the split would be an artefact of the test's own configuration. So this is
# digested and required EQUAL, read through the same read-only source mount the
# override is built from.
ROUTER_CONFIG = "/etc/mosdns/mosdns.yaml"

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
# The transaction's OWN success, verbatim, and what replaced the four requiring
# assertions about its refusal. `dnscrypt-proxy` binds 127.0.0.1:15353 once its
# reachability probe runs out, and with the test-only foreign override it then
# ANSWERS -- which is the whole of what Step 5 changed, and the transaction's own
# sentence about handing the loopback over is the fact that it did.
#
# The refusal's wording is still named below, as `CLAIM_RESOLVER_BARRIER`, and it
# is still checked for absence: a cell that both handed the loopback over and
# reported the barrier refused is a cell whose evidence document would describe
# two transactions. It is no longer *required*, because requiring it is what made
# this scenario unable to observe the cell this step produces.
CLAIM_LOOPBACK_HANDED_OVER = (
    "53 and 15353 are served on loopback and NetworkManager has been pointed at 127.0.0.1"
)
CLAIM_MARKER_WRITTEN = "the ownership marker at"
# The barrier's own sentence, kept for the ABSENCE check above and for the
# evidence document's `dpkg_output`, which carries whatever really happened.
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

# The requirement Task 4 Step 1 reassigned to Step 5, in the plan's own words.
# **It is asserted here now, not recorded as a skip**, and it is named rather
# than inlined so a reader can find it in the plan and a case can hold the two
# strings to each other.
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


def stamp_and_address(document: str) -> tuple[str, str] | None:
    """The mock foreign resolver's stamp and the address it names, or `None`.

    Read out of the mock's own counters document with `json.loads`, because the
    document is written by another program and a regular expression over it would
    be a shape this file invented. The stamp is generated per start and the address
    is what that stamp names, so both travel together and are returned as a pair:
    a stamp and an address that disagreed would be an override pointing at a
    resolver nobody is listening on, and the evidence document would report two
    different facts as one.
    """
    try:
        parsed = json.loads(document)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    stamp, address = parsed.get("stamp"), parsed.get("address")
    if not isinstance(stamp, str) or not stamp or not isinstance(address, str) or not address:
        return None
    return stamp, address


def changed_lines(shipped: str, override: str) -> list[str]:
    """The lines that differ, as `'<n>: <shipped line> -> <override line>'`.

    Read out of the two documents and recorded in the evidence, because "the
    override differs from the shipped document in its stamps" is a claim a reader
    of a report cannot check, and the list of changed lines is the smallest
    document that says it. The comparison is on whole lines and in order, so a
    reordering is visible as two changes rather than as one -- which is what a
    line-based check is for.
    """
    left, right = shipped.splitlines(), override.splitlines()
    changes = []
    for index in range(max(len(left), len(right))):
        before = left[index] if index < len(left) else "(absent)"
        after = right[index] if index < len(right) else "(absent)"
        if before != after:
            changes.append(f"{index + 1}: {before.strip()} -> {after.strip()}")
    return changes


def build_scenario(
    *,
    podman,
    version: str,
    arch: str,
    run_id: str,
    router: str,
    target: str,
    foreign: str,
    network: str,
    results_dir,
    deb: Path,
    override_path: Path,
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

    def read_in(container, *command):
        """One read in `container`, which is not the target.

        A separate function rather than a parameter on `read` because **almost
        every read this scenario makes is of the target**, and the one that is
        not -- the mock foreign resolver's own counters document -- has to name
        its container explicitly. The first version of this called
        `try_read(foreign, "cat", ...)` on a helper bound to the target, which
        ran `cat` *inside the target* with the mock's name as an extra argument
        and read nothing at all. Every case in the suite would have failed on it
        and the live cell would have waited out the same 120s.
        """
        return podman.exec_container(container, *command).output

    def try_read_in(container, *command) -> str:
        """`read_in` for evidence rather than for a claim."""
        try:
            return read_in(container, *command)
        except PodmanError as error:
            return f"(not readable: {str(error).splitlines()[-1]})"

    def try_read_logs(container) -> str:
        """A container's own log, or a sentence saying it could not be read.

        **Both streams, because a daemon that logs to stderr is the ordinary case
        here.** `podman logs` gives a container's stdout to podman's stdout and its
        stderr to podman's stderr -- the same split `docker logs` makes -- and
        dnsmasq with `log-facility=-` logs to stderr, which is the only facility a
        container has. A reader that looked at stdout alone would report a
        perfectly healthy mock as a silent one. (`Podman.logs` reads both and
        joins them; this is the one place a scenario asks for a container that is
        not the target, so it is wrapped rather than reached for.)
        """
        try:
            return podman.logs(container)
        except PodmanError as error:
            return f"(log not readable: {str(error).splitlines()[-1]})"

    def run(script: str) -> None:
        """One script into the target, and a failure is a CELL, not a harness fault.

        **Translated, and that is the whole of it.** Every script below is a
        command in a container, and a command that fails is a cell that did not
        work -- `chmod 0644` failing because the `podman cp` before it never
        happened, `dpkg-deb` failing because the artifact is not a package, the
        `nmcli` sequence failing because the profile would not come up. Letting
        `PodmanError` out would have the harness report exit 2, "the matrix is
        broken", with the detail in the report naming a `podman` invocation and
        nothing at all about the override, the document or the cell. The reason
        this scenario has its own exception type is stated on the class; this is
        the second place that reason is acted on.
        """
        try:
            podman.exec_script(target, script)
        except PodmanError as error:
            raise InstallScenarioError(
                f"a command in the cell failed, so this cell is not a result about the "
                f"package:\n{script}\nwhich said:\n{error}"
            ) from error

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

    def apply_foreign_override(document: dict) -> dict:
        """Make a foreign answer reachable, by rewriting one file inside the target.

        **The override is written BEFORE `dpkg -i`, and dpkg is told to keep it.**
        `/etc/mosdns/dnscrypt-proxy.toml` is a conffile this project ships on
        purpose -- `packaging/debian/conffiles` says "an operator is EXPECTED to
        edit one of them -- a custom DNSCrypt stamp set lives in
        dnscrypt-proxy.toml" -- and dpkg asks what to do when the file already
        exists and the package carries a different one. `N` is that answer, and it
        is the *operator's* answer: the file on the system is the machine's, the
        package's copy is installed beside it, and `postinst` -- which starts
        `dnscrypt-proxy` and then waits up to 60s for 127.0.0.1:15353 to answer --
        therefore runs with the override in place.

        **That ordering is the whole mechanism, and it is not incidental.** The
        transaction is *inside* `postinst`, so anything written after `dpkg -i`
        returns is written after the barrier has already refused. Measured on
        24.04 without this: `dnscrypt-proxy.service was started but nothing
        answered a DNS query at 127.0.0.1:15353 within 60s`.

        The document it substitutes into is read from the *read-only source mount*
        at `/workspace/configs/dnscrypt-proxy.toml`, and that is also where the
        evidence that the shipped document is unchanged comes from: the override
        is compared against those bytes line by line, and the `.deb`'s own copy is
        read back out of the artifact and compared against both.

        **The read is stripped and the write therefore has no final newline.** The
        wrapper's `.output` is `stdout.strip()`, and `build_override` reproduces a
        trailing newline only when the shipped text it was given ended in one. So
        `override_sha256` below is not the digest of the repository's file with its
        stamps replaced by hand, and a reader who recomputes it that way will get a
        different number. Nothing downstream cares -- the comparison is over whole
        lines and dnscrypt-proxy's TOML parser does not want a final newline -- and
        the recorded `shipped_sha256` is the real file's digest, taken by
        `sha256sum` inside the target rather than from this read.

        **`OverrideError` is translated into a failed cell rather than being
        allowed to escape.** Every input here is a property of *this* project --
        the document `internal/dnscrypt.Render` writes, and a substitution applied
        to it -- so a refusal from that module means the cell is not the one this
        repository describes. An escaping exception would be caught by the
        harness as a fault in the matrix itself and reported as exit 2, which
        tells a reader to go and fix the harness rather than the cell. It is a
        `failed` row, and it names the document and the reason.
        """
        counters = wait_for(
            lambda: try_read_in(foreign, "cat", foreign_override.COUNTERS_PATH),
            lambda raw: stamp_and_address(raw) is not None,
            what=(
                f"the mock foreign resolver's counters at "
                f"{foreign_override.COUNTERS_PATH} in {foreign}"
            ),
        )
        stamp, address = stamp_and_address(counters)
        # **The mock's own end of the exchange, recorded at the moment its stamp
        # is read.** The stamp is what the override carries, so this is the
        # document that says what was listening and where; without it a cell that
        # fails at the resolver's barrier has nothing in it about the resolver's
        # other end, and "the mock published a stamp naming an address nobody can
        # dial" reads exactly like "the resolver never started".
        document["foreign_counters_at_start"] = counters[:4000]
        document["foreign_log_at_start"] = try_read_logs(foreign)[-2000:]

        shipped_path = foreign_override.SHIPPED_SOURCE
        # **`try_read`, NOT `try_read(target, …)`.** This file's `try_read` is
        # bound to the target; passing the target to it asks the wrapper to exec
        # the container's own NAME inside the container:
        #
        #     podman exec <target> <target> cat /workspace/configs/dnscrypt-proxy.toml
        #
        # and the answer is an error or nothing at all. MEASURED, 24.04: the cell
        # reported `the shipped resolver document at
        # /workspace/configs/dnscrypt-proxy.toml could not be read in
        # mosdns-…-target-24.04 … It read:` and then nothing, on all three
        # releases, and the file is right there and readable inside a target.
        #
        # The reason no case caught it is worth recording, because it is this
        # project's most repeated defect one level down: **the fake's rule table
        # matches a contiguous run of tokens, and `["cat", <path>]` IS a
        # contiguous run of an argv that names the container twice.** So every
        # case in the suite was answered correctly by a command the scenario does
        # not run. `test_every_command_names_the_target_exactly_once` is the case
        # that can see it.
        shipped = try_read("cat", shipped_path)
        _require(
            foreign_override.LISTEN_ADDRESSES.search(shipped) is not None,
            f"the shipped resolver document at {shipped_path} could not be read in {target}, "
            f"so there is nothing to substitute the override into. It read:\n{shipped}",
        )
        try:
            override = foreign_override.build_override(shipped, stamp, address)
            foreign_override.assert_only_stamps_changed(shipped, override)
        except foreign_override.OverrideError as error:
            raise InstallScenarioError(
                f"the shipped resolver document at {shipped_path} in {target} is not one this "
                f"test-only override can be substituted into: {error}\n"
                f"**This cell has no route to the internet**, so the transaction's own barrier -- "
                f"the resolver at 127.0.0.1:15353 answering -- can only be passed by an override "
                f"that makes a foreign answer reachable. Without one the transaction refuses and "
                f"the package is left unpacked, which is the state this step was written to end. "
                f"The document the override read was:\n{shipped}"
            ) from error
        # **The facts are RETURNED, because the refusal case needs them a second
        # time.** `dpkg --unpack` puts the package's own conffile back, so the
        # override is written again from the same text -- and the text has to be
        # the same, or the cell would be measuring a second, differently-built
        # override.
        write_override(
            document,
            {
                "override": override,
                "shipped": shipped,
                "shipped_from": shipped_path,
                "stamp": stamp,
                "address": address,
            },
        )
        return {
            "override": override,
            "shipped": shipped,
            "shipped_from": shipped_path,
            "stamp": stamp,
            "address": address,
        }

    def write_override(document: dict, facts: dict) -> None:
        """Put the override at the path the resolver's unit reads, and record it.

        **A function, because the refusal case needs it a second time.** `dpkg
        --unpack` puts the package's own conffile back -- it has to, that is what
        unpacking a package means -- and this conffile is
        `/etc/mosdns/dnscrypt-proxy.toml`. So the override is written again after
        the unpack, and its digest is asserted to be the override's, which is what
        says the resolver that answers the restore is the one the cell measured.

        **The directory is created every time, and `podman cp` does not create
        it.** MEASURED on this host: `podman cp pkg.deb c:/etc/nosuchdir/pkg.deb` is
        `Error: "/etc/nosuchdir/pkg.deb" could not be found on container c: no such
        file or directory`. `/etc/mosdns` is created by the PACKAGE, and the first
        of these two runs before `dpkg -i`, so on a fresh target the directory is
        not there and the copy would fail on every cell.
        """
        override_path.write_text(facts["override"], encoding="utf-8")
        run(
            "set -eu\n"
            f"mkdir -p {os.path.dirname(foreign_override.DNSCRYPT_CONFIG)}\n"
        )
        podman.copy_to(target, str(override_path), foreign_override.DNSCRYPT_CONFIG)
        run(f"chmod 0644 {foreign_override.DNSCRYPT_CONFIG}")
        document["foreign_override"] = {
            "path": foreign_override.DNSCRYPT_CONFIG,
            "stamp": facts["stamp"],
            "address": facts["address"],
            "static_names": foreign_override.static_names(facts["override"]),
            "selected_names": foreign_override.selected_names(facts["override"]),
            "shipped_sha256": digest_of(facts["shipped_from"]),
            "shipped_from": facts["shipped_from"],
            "override_sha256": digest_of(foreign_override.DNSCRYPT_CONFIG),
            "changed_lines": changed_lines(facts["shipped"], facts["override"]),
            "only_stamps_changed": True,
        }

    def digest_of(path: str) -> str:
        """One file's sha256, or the empty string when it is not readable.

        Empty rather than a fabricated value, because every comparison below is
        an equality between two of these and a placeholder would make an absent
        file look like a file whose digest happens to be nothing.

        **And only a digest.** `sha256sum` prints `<digest>  <path>`, and taking
        the first whitespace-separated field of a line that is *only* a path --
        which is what a wrapper that lost stdout, or an `sha256sum` that failed
        and printed its argument, would give -- returns the path. So the field is
        required to be 64 hex characters, and anything else is the empty string
        for the reason above: a comparison between two malformed answers is not a
        comparison, and the one below this function's callers is the one that says
        whether the router's own policy is the one this repository renders.
        """
        try:
            field = read("sha256sum", path).split()[0]
        except (PodmanError, IndexError):
            return ""
        if len(field) != 64 or any(character not in "0123456789abcdef" for character in field):
            return ""
        return field

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

            # -- 3. the override, then the package, with dpkg, ONCE ----------
            # The override is written FIRST because the transaction is inside
            # `postinst`: anything written after `dpkg -i` returns is written
            # after the barrier has already refused. See `apply_foreign_override`.
            override_facts = apply_foreign_override(document)
            podman.copy_to(target, str(deb), "/tmp/mosdns-router.deb")
            document["package_bytes"] = int(
                try_read("stat", "-c", "%s", "/tmp/mosdns-router.deb").strip() or 0
            )
            # One install, through `sh -c`, with the status out of the SAME
            # invocation: `exec_status` keeps no output, so a status read through
            # it describes an install whose words are in a different string --
            # which is how the previous version of the watchdog scenario ran
            # `dpkg -i` twice and recorded the second run's state.
            # **`N` is the answer to dpkg's conffile question, and it is the
            # operator's answer.** `/etc/mosdns/dnscrypt-proxy.toml` is a conffile
            # this project ships on purpose -- `packaging/debian/conffiles`: "an
            # operator is EXPECTED to edit one of them -- a custom DNSCrypt stamp
            # set lives in dnscrypt-proxy.toml" -- and the override written above
            # IS a custom stamp set, written by an operator. dpkg asks what to do
            # with a file that already exists and differs from the package's, and
            # `N` is "keep the machine's".
            #
            # The override is written BEFORE this line, not after: the transaction
            # is inside `postinst`, and anything written once `dpkg -i` has
            # returned is written after the barrier has already refused.
            document["dpkg_output"] = try_read(
                "sh", "-c",
                "printf 'N\\n' | dpkg -i /tmp/mosdns-router.deb 2>&1; "
                "printf 'DPKG_EXIT=%s\\n' \"$?\"",
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
            # **Both ends of the exchange, read after the install and before
            # anything is asserted about it.** The packaged resolver's own account
            # of itself and the mock's counters, which is the only place in this
            # document that can tell a resolver that never started from a resolver
            # that started and could not reach anybody.
            #
            # MEASURED, twice, at the cost of two full matrix runs: the mock's
            # stamp named `0.0.0.0:443`, which a DNSCrypt client resolves to
            # itself, and the cell reported only
            #
            #     dnscrypt-proxy.service was started but nothing answered a DNS
            #     query at 127.0.0.1:15353 within 60s
            #
            # which is a sentence about a symptom. The address was in the mock's
            # counters document, and the mock's own log was not in the report at
            # all.
            document["resolver_journal"] = try_read(
                "sh", "-c",
                "journalctl -u dnscrypt-proxy.service -b --no-pager -n 80 2>&1 || true",
            )[:8000]
            document["foreign_counters_after_install"] = try_read_in(
                foreign, "cat", foreign_override.COUNTERS_PATH
            )[:4000]
            document["foreign_log_after_install"] = try_read_logs(foreign)[-4000:]
            document["package_state_explained"] = (
                f"dpkg recorded {one_word!r} / {phrase!r}. Both spellings are read because "
                "`${Status}` is the phrase and `${db:Status-Status}` the one word, and a scenario "
                "that asserted one literal would be asserting dpkg's formatting rather than dpkg's "
                "decision. dpkg's own output is in this document, verbatim, and the loopback "
                "hand-over and the marker it wrote are quoted from it below."
            )
            # **The CONFIGURED state is what this scenario requires, and it
            # requires it because the override made it reachable.** This assertion
            # is the inverse of the one this file carried before Task 4 Step 5, and
            # the inversion is the upgrade: the previous one said "not configured"
            # and the required four assertions about the resolver's barrier, so a
            # cell that configured was REFUSED and told the reader which step would
            # change that. Requiring the configured state is what makes the
            # scenario a test of the transaction completing rather than of the
            # barrier existing.
            _require(
                document["package_configured"],
                f"the package is {one_word!r} / {phrase!r} -- NOT configured -- and this scenario "
                "requires the configured state, because the test-only foreign override makes a "
                "foreign answer reachable and the transaction's own barrier is that resolver "
                f"answering. dpkg exited {document['dpkg_exit']} and said:\n"
                f"{document['dpkg_output']}\nThe override that should have made it reachable is "
                f"recorded under `foreign_override` in this document: "
                f"{document.get('foreign_override')}\n"
                f"**The resolver's own account of itself**, which is the half of this the "
                f"sentence above does not say:\n{document['resolver_journal']}\n"
                f"**And the other end of the exchange** -- the mock's counters:\n"
                f"{document['foreign_counters_after_install']}\n"
                f"and the mock's log:\n{document['foreign_log_after_install']}",
            )
            # The resolver document is read back out of the ARTIFACT -- not out of
            # the installed tree, which now holds the override -- and compared
            # against the repository's own copy. This is the whole of "the
            # override is test-only": three digests, one of which is the package
            # as it was built.
            #
            # **Out of the COPY, at the path inside the target.** `deb` is a path
            # on the host, and the only host directory bound into a target is the
            # source tree, read-only, at `/workspace` -- so a `dpkg-deb` naming
            # `deb` is a command no container can run, and it would have failed on
            # every live matrix run while every case here stayed green, because
            # the fake answers it. The file at `/tmp/mosdns-router.deb` is the
            # same bytes, `podman cp`'d in two lines above.
            run(
                "set -eu\n"
                "dpkg-deb --fsys-tarfile /tmp/mosdns-router.deb | tar -xO "
                f"./etc/mosdns/dnscrypt-proxy.toml > {ARTIFACT_DNSCrypt_TMP}\n"
            )
            _require(
                "ok " in phrase,
                f"dpkg reports {phrase!r}, which is not one of the unpacked-but-not-configured "
                f"phrases this scenario is written for, so the state above is not the one the rest "
                f"of this document describes",
            )

            # -- 4. that the transaction COMMITTED, and what it left ---------
            # **This section is the upgrade, and it replaces rather than relaxes.**
            #
            # The previous version required FOUR things here -- the resolver's
            # barrier sentence, the installer's rollback, postinst's own account
            # of that rollback, and postinst saying nothing was enabled -- and
            # required the two range refusals to be ABSENT. A cell where the
            # transaction completed has none of the four, so keeping them would
            # refuse the very cell this step was written to produce; and making
            # them optional would accept both dispositions, which is a scenario
            # that proves nothing about either.
            #
            # What replaces them is evidence of the OTHER disposition: the
            # transaction's own words about handing the loopback over, the
            # ownership marker being written, the four timers being enabled, and
            # both daemons active. `test_a_cell_where_the_transaction_completed_is_
            # not_refused` in `tests/podman/tests/test_install_scenario.py` is the
            # case that fails if the replacement is not made -- it is the same case
            # name as the one it replaced, with the direction of the assertion
            # inverted, because the case is about this decision and not about the
            # cell.
            flat = flatten_output(document["dpkg_output"])
            for claim, what in (
                (CLAIM_PIN_CHECKED_BY_POSTINST, "postinst verified the shipped pair"),
                (CLAIM_LOOPBACK_HANDED_OVER, "the loopback was handed to NetworkManager"),
                (CLAIM_MARKER_WRITTEN, "the ownership marker was written"),
            ):
                _require(
                    claim in flat,
                    f"dpkg's output does not contain {what} ({claim!r}), so this cell's "
                    "transaction did not commit -- either the override did not make a foreign answer "
                    "reachable, or the transaction stopped somewhere this scenario cannot see, and "
                    "either way the evidence document would describe an install that did not finish. "
                    f"dpkg's output:\n{document['dpkg_output']}",
                )
            # **The four sentences a REFUSING transaction prints, as a named
            # tuple** so the list and the loop over it cannot drift apart.
            forbidden = (
                (CLAIM_RESOLVER_BARRIER, "the resolver's start-up barrier refusing"),
                (CLAIM_ROLLED_BACK, "the installer rolling the transaction back"),
                (CLAIM_POSTINST_SAW_REFUSAL, "postinst's own account of that rollback"),
                (CLAIM_NOTHING_ENABLED, "postinst saying nothing was enabled"),
            )
            _require(
                CLAIM_PIN_NEVER_REPINNED in flat,
                f"postinst verified the pair but did not say {CLAIM_PIN_NEVER_REPINNED!r}, which is "
                "the position that keeps this snapshot from being re-pinned at install time. If that "
                "changed then a package an operator reviewed is not the package that gets installed, "
                f"and the report should say so. dpkg's output:\n{document['dpkg_output']}",
            )
            document["transaction_completed"] = True
            # **And the four sentences a REFUSING transaction prints are checked
            # for ABSENCE, which is the half that makes the two requirements
            # above load-bearing.** Before Step 5 these four were the requirements
            # and the hand-over was not required at all; a cell that both handed
            # the loopback over and reported the barrier refused has an evidence
            # document describing two transactions, and a reader of it would have
            # no way to tell which one the cell ran. So:
            #
            #   * the resolver's barrier, which means the resolver bound its
            #     loopback listener and then answered nothing -- the state the
            #     override exists to end;
            #   * the installer's own rollback, which means the machine's DNS is
            #     back the way it was;
            #   * postinst's account of that rollback; and
            #   * postinst's "nothing is enabled", which means the four timers
            #     were never turned on.
            #
            # A cell that printed any of them did not commit, and the assertions
            # further down -- the marker, the enabled timers -- would all read the
            # same.
            for claim, what in forbidden:
                _require(
                    claim not in flat,
                    f"dpkg's output contains {what} ({claim!r}), so this cell describes TWO "
                    "transactions: it handed the loopback over and then reported that the "
                    "transaction was refused. Only one of those can have happened, and the "
                    f"evidence document would report whichever this scenario found first. "
                    f"dpkg's output:\n{document['dpkg_output']}",
                )
            # The machine's DNS was recorded before the transaction's first
            # mutation AND committed to, so the backup is there and so is the
            # ownership marker. The pair is the load-bearing part: the backup
            # alone is what a REFUSED transaction also leaves behind, and the
            # marker is what only a committed one writes.
            document["backup_present"] = podman.exec_status(target, "test", "-e", BACKUP_PATH) == 0
            document["marker_present"] = podman.exec_status(target, "test", "-e", MARKER_PATH) == 0
            _require(
                document["backup_present"],
                f"{BACKUP_PATH} is not in {target} after a transaction that reported handing the "
                "loopback over, so this machine's DNS was changed with nothing recording what it was",
            )
            _require(
                document["marker_present"],
                f"{MARKER_PATH} is NOT in {target} after a transaction that committed. The marker is "
                "what tells a later uninstall that this package owns the machine's DNS, and a "
                "committed install without one would leave an uninstall refusing to restore a machine "
                "it is right to restore",
            )
            # The two range refusals are still checked for ABSENCE -- not as the
            # property this step delivered, which was the resolver's barrier, but
            # because a transaction that *also* carried a range refusal published
            # nothing and the evidence document would then describe an install
            # that did not happen. The check is kept because it is still true, and
            # dropped as a *requirement about which barrier refused* because that
            # is the assertion this step replaced.
            for signature in CDN_BARRIER_SIGNATURES:
                _require(
                    signature not in flat,
                    f"dpkg's output contains {signature!r}, which is what the RANGE step says when it "
                    "refuses, so the transaction did not get past the CDN step in this cell and the "
                    "configured state below would describe an install that published nothing. dpkg's "
                    f"output:\n{document['dpkg_output']}",
                )
            document["published_from_the_pin"] = True

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

            # -- 7. the timers, ASSERTED enabled ----------------------------
            # **The unit files AND the enabled state, and both are now required.**
            # The previous version recorded the enabled state and asserted
            # nothing, because the transaction refused and postinst never reached
            # its enable step -- and said so (`CLAIM_NOTHING_ENABLED`, which the
            # previous version required). A committed transaction enables all
            # four, so "enabled" is now evidence of the other disposition, and a
            # cell that configured the package and left the timers disabled is a
            # machine whose operators get no drift measurement and no watchdog.
            for timer in TIMERS:
                document[f"unit-file:{timer}"] = (
                    "present" if podman.exec_status(target, "test", "-e", f"/usr/lib/systemd/system/{timer}") == 0
                    else "absent"
                )
                _require(
                    document[f"unit-file:{timer}"] == "present",
                    f"{timer} is not installed in {target} after a transaction that committed, so "
                    f"the package is not the one this project builds. dpkg's output is in this "
                    f"document:\n{document['dpkg_output']}",
                )
                document[f"enabled:{timer}"] = try_read(
                    "sh", "-c", f"systemctl is-enabled {timer} 2>/dev/null || true"
                ).strip()
                _require(
                    document[f"enabled:{timer}"] == "enabled",
                    f"{timer} is {document[f'enabled:{timer}']!r} in {target} after a transaction "
                    "that committed, and a timer that is not enabled is a measurement this project "
                    "promises and does not take. postinst enables the four together and only after "
                    "the transaction succeeds, so this says the transaction did not finish rather "
                    f"than that the timer is wrong. dpkg's output:\n{document['dpkg_output']}",
                )
            for unit in (RESOLVER_UNIT, ROUTER_UNIT):
                document[f"state:{unit}"] = try_read(
                    "sh", "-c", f"systemctl show --property=ActiveState --value {unit}"
                ).strip()
                # **Required, and the requirement is what this scenario's
                # upgrade rests on.** The four barrier assertions this scenario
                # used to require said the resolver's own start-up wait had
                # refused the transaction; what replaced them is the configured
                # state, and a configured package whose units are not running is
                # a machine whose DNS is about to stop resolving. So the word is
                # read AND required, rather than recorded as evidence nobody
                # looked at -- a `try_read` whose value is never compared is a
                # sentence in the evidence document that a reader can check
                # themselves, which is not the same as a gate.
                #
                # `active` rather than "not failed": the two units are the
                # project's own and there is nothing else they can usefully be,
                # and `is-active` is the question the plan's Task 4 Step 3 asks.
                _require(
                    document[f"state:{unit}"] == "active",
                    f"{unit} is {document[f'state:{unit}']!r} in {target} and the transaction is "
                    f"supposed to have left it running: the package is {document['package_status_phrase'] or document['package_state']}, "
                    f"and a configured package whose resolver is not active is a machine whose "
                    f"resolution is about to stop, which is the failure the four assertions this "
                    f"scenario replaced used to catch",
                )
            document["loopback_listeners"] = try_read(
                "sh", "-c", f"ss -lntup 2>/dev/null | grep -E '127\\.0\\.0\\.1:({DNS_PORT}|{RESOLVER_PORT})\\b' || true"
            )

            # -- 8. the refusal, on the same cell ---------------------------
            # The other half of the property, and the half a happy-path-only
            # scenario leaves unverified. One byte of the SHIPPED snapshot is
            # changed and the install is repeated: postinst must refuse BEFORE the
            # transaction, and must publish nothing. **Everything it touches is put
            # back afterwards** -- the snapshot by writing the bytes that were
            # read, the package by configuring it again, and the two published
            # documents by publishing them again -- so the cell is left as it was
            # found, which also means each restore is itself observed rather than
            # assumed.
            #
            # **The package is put back too, and that is new with the configured
            # state.** The refused probe leaves it `half-configured`, and the
            # `routing` scenario runs in the SAME cell after this one: a cell
            # handed on with a half-configured package is a cell whose next
            # scenario is measured on a machine the install left half-done. The
            # restore is `dpkg --configure`, so it also says the snapshot was the
            # ONLY thing wrong -- which is a second piece of evidence for the pin
            # rather than a tidy-up.
            #
            # **The published documents matter as much as the snapshot.** They are
            # removed on purpose, so that "a refusal published nothing" is a fact
            # about the machine rather than about the postinst script. What they
            # leave behind is a machine whose response rewriter would refuse to
            # construct, and `install` runs first in `PACKAGE_SCENARIOS` order, so
            # this is not hypothetical.
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
                # **Four commands, and the order is the mechanism.** The pin's
                # digest check lives in postinst's STEP 3 and in NOWHERE ELSE, so
                # the case has to make postinst run over a corrupt snapshot, and
                # two earlier shapes could not:
                #
                #   * `dpkg --configure` on an `installed` package runs no maint
                #     script at all -- "package mosdns-router is already installed
                #     and configured", MEASURED;
                #   * `dpkg -i` re-unpacks, and the unpack RESTORES the shipped
                #     snapshot from the package, so postinst read a whole one --
                #     MEASURED, the cell configured the machine and the case said
                #     the corruption had not stopped the install;
                #   * and the installer's own `preflight --check-only` -- which
                #     postinst's own refusal names as the way to try again -- says
                #     nothing about the pin at all. MEASURED on 24.04 over a
                #     snapshot whose bytes its lock did not record:
                #
                #         preflight: this machine can have this router installed
                #         on it; nothing has been changed
                #
                #     It checks the MACHINE, not the pin.
                #
                # So: `dpkg --unpack` (which runs no maint script and leaves the
                # package `unpacked`), then the override is written again --
                # unpacking a package puts its own conffiles back, and this
                # conffile is the one the resolver reads, so the resolver that
                # answers the restore has to be the one the cell measured -- then
                # the corruption, then `dpkg --configure`, which runs postinst.
                run("set -eu\nprintf 'N\\n' | dpkg --unpack /tmp/mosdns-router.deb\n")
                write_override(document, override_facts)
                _require(
                    digest_of(foreign_override.DNSCRYPT_CONFIG)
                    == document["foreign_override"]["override_sha256"],
                    f"the override did not survive `dpkg --unpack`, so the resolver that answered "
                    f"the restore below would be reading the package's own Quad9 stamps on a cell "
                    f"with no route to the internet -- and the restore would be measured against a "
                    f"resolver this cell never configured",
                )
                run(
                    "set -eu\n"
                    f"sed -i 's#104\\.16\\.0\\.0/13#104.16.0.0/12#' {SHIPPED_PIN}\n"
                    f"rm -f {PUBLISHED_RANGES} {PUBLISHED_PREFIX_LIST}\n"
                )
                # **The pin's digest is read AFTER the corruption and BEFORE the
                # probe**, and asserted to differ from the shipped one. A refusal
                # case that cannot show its own precondition applied is a case
                # about whatever the cell did -- and the order is the whole of the
                # check: the first version of this assertion read the digest BEFORE
                # the `sed`, and produced a cell that failed with "the shipped
                # snapshot still reads <the shipped digest> after the corruption"
                # on a machine where the corruption had worked.
                document["pin_corrupted_sha256"] = digest_of(SHIPPED_PIN)
                _require(
                    document["pin_corrupted_sha256"] != ""
                    and document["pin_corrupted_sha256"] != document["shipped_pin_sha256"],
                    f"the shipped snapshot at {SHIPPED_PIN} still reads "
                    f"{document['pin_corrupted_sha256']!r} after the corruption, so the refusal "
                    f"case below would be probing a machine whose snapshot is whole and would say "
                    f"nothing about a corrupt one",
                )
                document["corrupt_pin_output"] = try_read(
                    "sh", "-c",
                    "dpkg --configure mosdns-router 2>&1; "
                    "printf 'PROBE_EXIT=%s\\n' \"$?\"",
                )[:6000]
                document["corrupt_pin_state"] = package_status()[0]
                document["corrupt_pin_published"] = [
                    path for path in (PUBLISHED_RANGES, PUBLISHED_PREFIX_LIST)
                    if podman.exec_status(target, "test", "-e", path) == 0
                ]
                _require(
                    "cannot account for" in document["corrupt_pin_output"],
                    "a shipped snapshot whose bytes its lock does not record did not stop the "
                    "installer, so this package would configure a machine's DNS over a range list it "
                    f"cannot name. postinst said:\n{document['corrupt_pin_output']}",
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
                # **The refusal is a non-zero EXIT, not only a sentence about one.**
                # dpkg's own status is read out of the same invocation, because a
                # refusal that is only words is a refusal a program can print on its
                # way to succeeding.
                probe_exit = re.search(r"PROBE_EXIT=(\d+)", document["corrupt_pin_output"] or "")
                document["corrupt_pin_exit"] = int(probe_exit.group(1)) if probe_exit else None
                _require(
                    document["corrupt_pin_exit"] not in (0, None),
                    f"a configuration step over a corrupt snapshot exited "
                    f"{document['corrupt_pin_exit']!r} rather than refusing, so this package would "
                    f"have configured a machine's DNS over ranges its own lock does not account "
                    f"for:\n{document['corrupt_pin_output']}",
                )
                # And it left the package in one of the two states a refusing
                # configuration step leaves -- `half-configured` on 24.04 and 26.04,
                # `unpacked` elsewhere, both MEASURED -- which is what says nothing
                # was captured, backed up or changed. Requiring either keeps the
                # assertion on the property rather than on which of the two dpkg
                # chose.
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
            # **And the package is configured AGAIN**, which is the second half of
            # "leave the cell as you found it" and the second piece of evidence for
            # the pin: the whole snapshot was the only thing the refusal case
            # broke. The package is `half-configured` now -- `dpkg --configure` is
            # what put it there -- and `routing` runs after this one in the same
            # cell, so a cell handed on half-configured is a cell whose next
            # scenario is measured on a machine the install left half-done.
            #
            # The transaction runs a second time. It is the same transaction, on a
            # machine this package already runs on, and postinst says so in its own
            # output ("this is a re-install of a machine this package already runs
            # on") -- so the second run is evidence about idempotence rather than a
            # second thing being measured, and the record carries its output.
            document["pin_restore_output"] = try_read(
                "sh", "-c",
                "dpkg --configure mosdns-router 2>&1; "
                "printf 'RESTORE_EXIT=%s\\n' \"$?\"",
            )[:6000]
            restore_exit = re.search(r"RESTORE_EXIT=(\d+)", document["pin_restore_output"] or "")
            document["pin_restore_exit"] = int(restore_exit.group(1)) if restore_exit else None
            restored_one_word, restored_phrase = package_status()
            document["restored_package_state"] = restored_one_word
            document["restored_package_status_phrase"] = restored_phrase
            _require(
                document["pin_restore_exit"] == 0
                and (
                    restored_one_word in CONFIGURED_STATES
                    or restored_phrase in CONFIGURED_STATES
                ),
                f"the package is {restored_one_word!r} / {restored_phrase!r} after the shipped "
                "snapshot was put back and `dpkg --configure` was run again, so the snapshot was "
                "not the only thing the refusal case broke and the cell is handed to the next "
                "scenario half-done. dpkg said:\n"
                f"{document['pin_restore_output']}",
            )
            # **And the two published documents are published again**, from the same
            # pinned snapshot, by the one command on a machine with no route that
            # can do it. Asked with nothing removed -- they are already gone -- and
            # with no report asked for, because a report here would be about the
            # restore rather than about the publish the assertions above are about.
            # The two digests are then RE-READ, so the record's own values are the
            # cell's final state and not the state before the refusal case.
            document["published_restore_report"] = try_read(
                "sh", "-c",
                f"{CDNCTL} update-lists --refresh-ranges 2>&1\n"
                f"printf 'RESTORE_EXIT=%s\\n' \"$?\"",
            )[:4000]
            restore = re.search(r"RESTORE_EXIT=(\d+)", document["published_restore_report"] or "")
            document["published_restore_exit"] = int(restore.group(1)) if restore else None
            _require(
                document["published_restore_exit"] == 0,
                f"putting the published documents back exited "
                f"{document['published_restore_exit']!r} rather than 0, so the cell is left "
                "without the ranges the router classifies against and the next scenario in it "
                f"would be measuring a router that cannot construct:\n"
                f"{document['published_restore_report']}",
            )
            document["published_ranges_sha256"] = digest_of(PUBLISHED_RANGES)
            document["published_prefix_list_sha256"] = digest_of(PUBLISHED_PREFIX_LIST)
            _require(
                document["published_ranges_sha256"] == document["shipped_pin_sha256"]
                and document["published_prefix_list_sha256"] != "",
                "the published documents were not put back the way the refusal case removed "
                f"them: the range document reads {document['published_ranges_sha256']} where the "
                f"snapshot is {document['shipped_pin_sha256']}, and the prefix list reads "
                f"{document['published_prefix_list_sha256'] or '(nothing)'}. The cell is handed "
                "to the next scenario in this run, and a router with no ranges binds nothing on "
                "port 53",
            )
            document["published_restored_after_refusal"] = True

            # -- 9. that the SHIPPED documents are unchanged ----------------
            # **The override is test-only, and this is the evidence rather than
            # the promise.** Three digests:
            #
            #   * the repository's own `configs/dnscrypt-proxy.toml`, read
            #     through the read-only source mount inside the target;
            #   * the `.deb`'s OWN copy of the same document, read back out of
            #     the artifact after the install; and
            #   * the file the target is running, which is the override.
            #
            # The first two must be EQUAL, and the third must differ. A cell
            # where the artifact and the checkout disagreed would mean the package
            # that was installed is not the package this repository builds, and a
            # cell where the third equalled them would mean the override never
            # reached the target -- so the install would have completed for some
            # other reason and the evidence document would say it was the
            # override.
            document["artifact_dnscrypt_sha256"] = digest_of(
                f"{ARTIFACT_DNSCrypt_TMP}"
            )
            _require(
                document["artifact_dnscrypt_sha256"] != "",
                f"the resolver document could not be read back out of {deb} in {target}, so this "
                "scenario cannot show the package was not modified to make the install work",
            )
            _require(
                document["artifact_dnscrypt_sha256"] == document["foreign_override"]["shipped_sha256"],
                f"the resolver document inside the artifact is "
                f"{document['artifact_dnscrypt_sha256']} and the repository's own is "
                f"{document['foreign_override']['shipped_sha256']}. They must be the same bytes: a "
                "package carrying a different document is a package this repository did not build, "
                "and a cell that installed it proved nothing about this one",
            )
            _require(
                document["foreign_override"]["override_sha256"]
                != document["foreign_override"]["shipped_sha256"],
                "the file the target is running at "
                f"{foreign_override.DNSCRYPT_CONFIG} is byte-identical to the shipped document, so "
                "the override never reached the target -- and the transaction completed for some other "
                "reason, which this scenario must not report as the override's doing",
            )
            document["shipped_documents_unchanged"] = True

            # -- 9b. and the ROUTER document, which the override does not touch
            # **The DNSCrypt document is the FOREIGN branch's. The domestic branch
            # runs on `/etc/mosdns/mosdns.yaml`, and until this section existed
            # nothing in this harness read that file at all** -- MEASURED,
            # `grep -rn "/etc/mosdns/mosdns" tests/podman/ --include=*.py` returned
            # nothing, so the plan's "Production shipped config and packaged DNSCrypt
            # config remain unchanged and are asserted separately" had an assertion
            # for the second half of the sentence and none for the first.
            #
            # The failure that absence permits is specific and quiet. This
            # override's whole purpose is to point a *foreign forward address* at a
            # mock; if the harness ever wrote the ROUTER document to do that
            # instead, the foreign branch would keep working, the domestic branch
            # would stop being this project's real policy, and **every counter in
            # Step 6 would still read correctly**. A cell that cannot tell a real
            # split from a manufactured one is worse than no cell, because it is
            # green.
            #
            # So the target's copy is digested and required EQUAL to the
            # repository's, read through the same read-only `/workspace` mount the
            # override is built from -- a mount that cannot be written, which is
            # what `NO-HOST-MUTATION.md`'s premise rests on and what makes the
            # repository's side of the comparison trustworthy.
            document["router_document_path"] = ROUTER_CONFIG
            document["router_document_shipped_from"] = foreign_override.SHIPPED_ROUTER
            document["router_document_sha256"] = digest_of(ROUTER_CONFIG)
            document["router_document_shipped_sha256"] = digest_of(
                foreign_override.SHIPPED_ROUTER
            )
            _require(
                document["router_document_sha256"] != "",
                f"{ROUTER_CONFIG} could not be digested in {target} (sha256sum read "
                f"{document['router_document_sha256']!r}), so this cell has NOT measured whether the "
                f"router's own document is the one this repository renders. An absent digest is not "
                f"an equal digest, and the domestic branch's policy is exactly what a cell that "
                f"cannot read it has nothing to say about",
            )
            _require(
                document["router_document_shipped_sha256"] != "",
                f"the repository's own {foreign_override.SHIPPED_ROUTER} could not be digested through "
                f"the read-only source mount, so there is nothing to compare "
                f"{ROUTER_CONFIG} against and the comparison below would be between two placeholders",
            )
            _require(
                document["router_document_sha256"] == document["router_document_shipped_sha256"],
                f"the router's document {ROUTER_CONFIG} in {target} is "
                f"{document['router_document_sha256'] or '(no digest)'} and the repository's own "
                f"{foreign_override.SHIPPED_ROUTER} is "
                f"{document['router_document_shipped_sha256'] or '(no digest)'}, and they must be "
                f"the same bytes. This is the DOMESTIC branch's policy, and a cell where it was "
                f"changed -- to point a forward at this run's mock, say -- would still resolve every "
                f"test name and every query counter would still read correctly. A split measured "
                f"against a document the test wrote is not a split",
            )
            document["router_document_matches_the_repository"] = True

            evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME,
                status="passed",
                detail=(
                    f"with no route to the internet the transaction COMPLETED: dpkg recorded "
                    f"{document['package_status_phrase'] or document['package_state']}, the loopback "
                    f"was handed to NetworkManager, the ownership marker was written, and all four "
                    f"timers are enabled. A foreign answer was reachable because the resolver "
                    f"document's stamps -- and only its stamps -- pointed at a mock foreign resolver "
                    f"on this run's private network at {document['foreign_override']['address']} "
                    f"({len(document['foreign_override']['changed_lines'])} line(s) of "
                    f"{foreign_override.DNSCRYPT_CONFIG} differ from the shipped document: "
                    f"{'; '.join(document['foreign_override']['changed_lines'])}). The document in "
                    f"the artifact is byte-identical to the repository's own "
                    f"({document['artifact_dnscrypt_sha256'][:16]}...), so the override is "
                    f"test-only. The range document published is the snapshot the package ships "
                    f"({document['shipped_pin_sha256'][:16]}...), and a snapshot whose bytes its lock "
                    "does not record still refused the install before the transaction ran and "
                    f"published nothing. This closes "
                    f"'{OFFLINE_CONFIGURED_REQUIREMENT}'"
                ),
                log=f"logs/{version}-{SCENARIO_NAME}.json",
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
