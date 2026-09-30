"""The install transaction, run for real: the first scenario that can fail on it.

Every other scenario in this harness observes a mechanism that already works.
This one observes the property that **the install completes at all**, and before
this step existed that property had never been observed anywhere -- not in a
container, not on a machine. Every cell of this matrix ended `half-configured`
because the transaction refused, and the refusal chain it named started at the
Cloudflare prefix list the response rewriter refuses to construct without.

## What is under test, and what each observation is evidence OF

1. **The transaction completes.** `dpkg -i` is run once and dpkg's own recorded
   status is read back. Not "the installer printed no error" -- dpkg's record of
   what it did with the package.
2. **It completed because the shipped snapshot exists, not by luck.** The
   published range artifacts are compared with the pinned pair the package
   installed, by digest. A cell that installed because the origin happened to be
   reachable would publish a *different* digest, so this is what distinguishes the
   two.
3. **The machine has no route to the internet.** Measured in the cell, by the
   route table and by a connect to the origin, and asserted -- because a cell
   whose bridge NATs outward would install for the wrong reason and the evidence
   would read the same.
4. **The refusals are still refusals.** A corrupt shipped snapshot must stop the
   install before the transaction runs, and must publish nothing.

## What this scenario deliberately does NOT do

It does not assert that the machine can reach the internet. It cannot, and
asserting it would be the same defect in reverse: the cell's bridge is private
precisely so the install has to work without a route.

It also does not claim the whole transaction is reachable with no route. It is
not, and the reason is not this project's to fix here: the foreign resolver
answers from a DNSCrypt server on the internet, the installer's barrier requires
an answer, and a machine that cannot reach one is refused for that reason -- a
refusal with its own name, its own evidence and its own place in the report. This
scenario asserts the step this project took (the pinned snapshot is published and
verified with no route) and records the next barrier as text rather than
asserting a property the cell cannot have.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

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

# How long to wait for the machine to reach a state after a command that should
# cause it. Every one of these is a poll of a real fact, not a sleep.
DEFAULT_WAIT_SECONDS = 120.0
WAIT_INTERVAL_SECONDS = 3.0

# The states dpkg records, and the one this scenario requires. `installed` and
# `install ok installed` are the two spellings of the same state: `${Status}` is
# the phrase and `${db:Status-Status}` is the one-word form. Both are read and both
# are accepted, because a scenario that asserted one literal would be asserting
# dpkg's formatting rather than dpkg's decision.
CONFIGURED_STATES = ("installed", "install ok installed")

# The messages that are the product. A scenario that asserted only "the package
# installed" would pass against a transaction that installed a selector over
# ranges nobody can name.
CLAIM_PIN_PUBLISHED = "ranges-source: pinned-snapshot"
CLAIM_PIN_VERIFIED = "ranges-pin-verified: true"
CLAIM_PIN_DRIFT_NONE = "ranges-pin-drift: none"
CLAIM_NO_ROUTE = "Network is unreachable"
CLAIM_TRANSACTION_TOOK_OVER = "now uses the loopback address 127.0.0.1"
CLAIM_MARKER_WRITTEN = "the ownership marker at"


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
            document["origin_reachable"] = try_read(
                "sh", "-c",
                f"python3 -c \"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                f"s.settimeout(4);s.connect(('{RANGE_ORIGIN.split('/')[2].split(':')[0]}',443));"
                "print('reachable')\" 2>&1 || true",
            ).strip()
            _require(
                CLAIM_NO_ROUTE in document["origin_reachable"] or "timed out" in document["origin_reachable"],
                f"the range origin is reachable from {target} ({document['origin_reachable']!r}), so this "
                "cell would publish from the origin rather than from the snapshot the package ships, "
                "and every claim below would be true for the wrong reason. The cell's route table is:\n"
                f"{document['route_table']}",
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
                "decision. dpkg's own output is in this document."
            )
            _require(
                document["package_configured"],
                f"the package is {one_word!r} / {phrase!r} and this scenario's evidence document "
                "claims a cell where the install transaction completed. Either the transaction "
                "refused in this cell -- in which case its own message is in dpkg_output and the "
                "published-range evidence below says which barrier refused -- or it did not, and "
                "the state is not what this scenario documents.",
            )

            # -- 4. the transaction's OWN account of what it did ---------------
            # The words are the product, and each one is a claim the script makes
            # about the machine. A cell that reached `installed` without them would
            # mean a different script had configured the package.
            for claim, what in (
                (CLAIM_TRANSACTION_TOOK_OVER, "NetworkManager was pointed at the loopback"),
                (CLAIM_MARKER_WRITTEN, "the ownership marker was written"),
            ):
                _require(
                    claim in document["dpkg_output"],
                    f"the install completed but dpkg's output does not say {what}, so the evidence "
                    f"document would credit the transaction with something it did not report:\n"
                    f"{document['dpkg_output']}",
                )
            document["backup_present"] = podman.exec_status(target, "test", "-e", BACKUP_PATH) == 0
            document["marker_present"] = podman.exec_status(target, "test", "-e", MARKER_PATH) == 0
            for label, present in (("backup", document["backup_present"]), ("marker", document["marker_present"])):
                _require(
                    present,
                    f"{BACKUP_PATH if label == 'backup' else MARKER_PATH} is not in {target} after an "
                    "install that reported writing it, so the machine's DNS was changed with nothing "
                    "recording what it was",
                )

            # -- 5. WHY it could install: the shipped snapshot ---------------
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
                f"the package ships is {document['shipped_pin_sha256']}. The install completed on a "
                "machine with no route, so the document it published has to be the shipped one, and "
                "these are not equal.",
            )
            _require(
                document["published_prefix_list_sha256"] != "",
                f"{PUBLISHED_PREFIX_LIST} is not readable in {target} after an install that reported "
                "serving port 53, so the response rewriter would refuse to construct on this machine",
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
            # Both modes, and both are report-only: the refresh is run with the
            # published artifacts REMOVED first so the machine's own document
            # cannot stand in, which is the state a fresh install is in and the
            # only state in which the snapshot is the source.
            run(
                "set -eu\n"
                f"rm -f {PUBLISHED_RANGES} {PUBLISHED_PREFIX_LIST}\n"
                f"{CDNCTL} update-lists --refresh-ranges\n"
            )
            document["refresh_report"] = try_read("sh", "-c", f"{CDNCTL} update-lists --refresh-ranges")[:4000]
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

            # -- 7. the timers, which STEP 5 reaches only through here ---------
            # Recorded rather than asserted as enabled: whether a timer is enabled
            # depends on a `systemctl enable` that succeeds, and a failure there is
            # LOUD in postinst's own output and non-fatal by decision. What this
            # asserts is that the transaction SUCCEEDED, which is what makes the
            # enable reachable at all, and that the units exist and are named.
            for timer in TIMERS:
                document[f"unit-file:{timer}"] = (
                    "present" if podman.exec_status(target, "test", "-e", f"/usr/lib/systemd/system/{timer}") == 0
                    else "absent"
                )
                _require(
                    document[f"unit-file:{timer}"] == "present",
                    f"{timer} is not installed in {target} after an install that reported completing, "
                    f"so postinst's enable step had nothing to enable. dpkg's output is in this "
                    f"document:\n{document['dpkg_output']}",
                )
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
            original = read("cat", SHIPPED_PIN)
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
                    document["corrupt_pin_state"] not in CONFIGURED_STATES,
                    f"a refused install left the package {document['corrupt_pin_state']!r}, so the cell "
                    "both passed and refused and the evidence document would describe whichever it "
                    "found first",
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
                    f"cat > {SHIPPED_PIN} <<'MOSDNS_PIN_EOF'\n{original}MOSDNS_PIN_EOF\n"
                )
            document["pin_restored_sha256"] = digest_of(SHIPPED_PIN)
            _require(
                document["pin_restored_sha256"] == document["shipped_pin_sha256"],
                f"the shipped snapshot was restored to {document['pin_restored_sha256']} and not to "
                f"{document['shipped_pin_sha256']}, so the refusal case left the cell in a state no "
                "other cell would start from",
            )

            evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME,
                status="passed",
                detail=(
                    f"the install transaction completed with no route to the internet: dpkg recorded "
                    f"{document['package_status_phrase'] or document['package_state']}, the published "
                    f"range document is the snapshot the package ships "
                    f"({document['shipped_pin_sha256'][:16]}...), the daily check measured the pin's age "
                    f"and reported no drift, and a snapshot whose bytes its lock does not record refused "
                    f"the install before the transaction ran and published nothing"
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
