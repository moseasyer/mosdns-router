"""The install scenario's assertions: the property that has never been observed.

`install_test.py` is the first scenario in this harness that can fail on the
install transaction itself, and it observes the property the whole of Task 4 was
waiting for: with no route to the internet, `dpkg -i` of this package completes
and the published Cloudflare range document is the snapshot the package ships.

These cases drive the real scenario module against the fake `podman` the rest of
this suite uses, and there are two halves to them.

**The happy path**, which is three facts rather than one. dpkg recorded the
package installed; the transaction's own words say it pointed NetworkManager at
the loopback and wrote the marker; and the published range document's digest
equals the shipped snapshot's. The third is the one that matters: a cell whose
bridge NATs outward would publish from the origin and hold a *different*
document, so the equality is what distinguishes "the pin made this install
possible" from "the install happened to succeed".

**The refusals**, which a happy-path-only scenario leaves entirely unverified and
which are what has been protecting every machine so far. A cell whose bridge
reaches the origin is refused rather than passed, because every observation would
otherwise read the same while measuring nothing; a shipped snapshot whose bytes
its lock does not record has to stop the install *before* the transaction runs and
publish nothing; and each of those refusals has to leave the cell as it was
found, so one cell's failed case cannot be the next cell's starting state.
"""

import ast
import errno
import importlib.util
import io
import json
import os
import re
import socket
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HARNESS = REPO / "tests" / "podman"
SCENARIOS = HARNESS / "scenarios"
DISCOVERED = HARNESS / "tests"

sys.path.insert(0, str(HARNESS / "lib"))
sys.path.insert(0, str(DISCOVERED))

# The fake podman and its base class, reused rather than copied: a second fake
# would be a second thing that can be wrong about what a podman invocation looks
# like, and this suite's record is that a duplicated fixture is a duplicated
# defect.
import test_command  # noqa: E402

from podman import Podman  # noqa: E402

PodmanTestCase = test_command.PodmanTestCase

VERSION = "24.04"
RUN_ID = "20260930T000000Z"
ROUTER = f"mosdns-{RUN_ID}-mock-router-{VERSION}"
TARGET = f"mosdns-{RUN_ID}-target-{VERSION}"


def _load_scenario(name: str = "install_test"):
    """The scenario module, loaded by path rather than by name.

    Loaded by path so a case file and a scenario file can never shadow one
    another in `sys.modules` -- the defect `test_suite_shape.py` exists to keep
    out of the harness's own suite.
    """
    path = SCENARIOS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"mosdns_scenario_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


install = _load_scenario()

# The digests this file's rules answer with. The shipped snapshot's is the
# repository's own, read rather than written here so a re-pinned package does not
# make every case in this file fail for a reason that has nothing to do with the
# scenario: the property under test is that the PUBLISHED document equals the
# SHIPPED one, and the two are given the same value below, which is what makes
# that comparison a measurement.
SHIPPED_PIN_SHA = "fa80894eae91ea4b2240e8571048933eeb178f2a7757c5dcfe58c44acd0e5165"
PUBLISHED_PIN_SHA = "fa80894eae91ea4b2240e8571048933eeb178f2a7757c5dcfe58c44acd0e5165"
# What the origin would have published instead, so a cell that reached it is
# distinguishable from one that did not.
ORIGIN_DOCUMENT_SHA = "f3d0a35768afd4a9a8307aa1033d50b9fa011b73836c9235c170aa31acac5efd"
PREFIX_LIST = "103.21.244.0/22\n104.16.0.0/13\n198.41.128.0/17\n"

# `dpkg -i`, run once through `sh -c` with the status in the same output, which is
# how the watchdog scenario's own table is written and why: two invocations of
# `dpkg -i` run the transaction twice, and every recorded state then describes
# the second run.
DPKG_INSTALL = "dpkg -i /tmp/mosdns-router.deb 2>&1; printf 'DPKG_EXIT=%s\\n' \"$?\""
DPKG_STATE_QUERY = "dpkg-query -W -f='${db:Status-Status}\\n' mosdns-router 2>&1 || true"
DPKG_STATUS_QUERY = "dpkg-query -W -f='${Status}\\n' mosdns-router 2>&1 || true"

# postinst's own words, for a cell where the transaction completed. Each is a
# claim the script makes about the machine, so a cell that reached `installed`
# without them would mean a different script had configured the package.
COMPLETED_OUTPUT = """\
postinst: /var/lib/mosdns/lists/cn-domains.txt and /var/lib/mosdns/lists/source-lock.json are already published and
postinst: readable, so they are left exactly as they are.
postinst: the pinned range document at /usr/share/mosdns-router/cloudflare-ranges.json is {shipped}, as
postinst: /usr/share/mosdns-router/cloudflare-ranges.lock.json records {shipped} for it, taken at 2026-09-30T00:03:59Z.
note: eth0-managed (eth0, f1480978-e49e-4ed7-953b-748d5d1c512d) now uses the loopback address 127.0.0.1; the original settings are recorded in /var/lib/mosdns/installer/network-manager-backup.json
install: 53 and 15353 are served on loopback and NetworkManager has been pointed at 127.0.0.1; the ownership marker at /var/lib/mosdns/installer/managed-by has been written, so an uninstall will restore exactly what was changed
Created symlink /etc/systemd/system/timers.target.wants/mosdns-cdn-optimizer.timer -> /usr/lib/systemd/system/mosdns-cdn-optimizer.timer.
Created symlink /etc/systemd/system/timers.target.wants/mosdns-watchdog.timer -> /usr/lib/systemd/system/mosdns-watchdog.timer.
""".format(shipped=SHIPPED_PIN_SHA)

# The refusal a corrupt shipped snapshot has to produce, and the sentence that
# says nothing was changed. The second is load-bearing: it is what distinguishes
# a refusal from a partial install, and an operator reading a refusal without it
# cannot tell whether their resolver is up.
CORRUPT_OUTPUT = """\
postinst: /var/lib/mosdns/lists/cn-domains.txt and /var/lib/mosdns/lists/source-lock.json are already published and
postinst: readable, so they are left exactly as they are.
postinst: /usr/share/mosdns-router/cloudflare-ranges.json is d1235dc06af1c770ffee53ec9a53275a3aa7aca1349b95672d74aea06433de5d and /usr/share/mosdns-router/cloudflare-ranges.lock.json records
postinst: {shipped} for it, so this package cannot account for the ranges
postinst: in it. Refusing to install a selector over a range list this project cannot
postinst: name. Nothing has been changed on this machine's DNS.
""".format(shipped=SHIPPED_PIN_SHA)

# The no-route probe, and what a cell that cannot route answers it.
#
# **The answer is DERIVED BY RUNNING THE SCENARIO'S OWN PROGRAM, and that is the
# whole point of this block.** The first version of this file held the literal
# text `OSError: [Errno 101] Network is unreachable` -- the exact substring
# `install_test.py` was looking for -- so the fake asserted the value the code
# wanted rather than what the real command produces, and twenty cases in this
# file could not see that the real command produced a `socket.gaierror` instead.
# A fake that hardcodes the answer is this project's most repeated defect, and it
# had reached a podman fixture.
#
# So the number goes in and the sentence comes out, by executing the program's
# own `except` clause with a real `OSError` in place of the real `connect`:
#
#   * the fake cannot be made to agree with a wrong assertion, because it does
#     not contain an assertion to agree with -- change the scenario to require
#     `EHOSTUNREACH` and this answer still says `ENETUNREACH`;
#   * and if the program stops printing an errno at all, the helper raises here
#     and every case in this file says so, rather than the fake quietly
#     answering "" and a case reading that as a routeless cell.
def probe_failed(number: int = errno.ENETUNREACH) -> str:
    """What the in-cell probe prints when its `connect` fails with `number`.

    Run here, in this process, with the real `socket` module and only
    `socket.socket` replaced -- so `AF_INET`, `SOCK_DGRAM`, `settimeout` and the
    program's own `except` clause are the production ones, and the address and
    port the cell would have received are the arguments that are checked.
    """
    program = install.PROBE_PROGRAM
    saved_socket, saved_argv, saved_out = socket.socket, sys.argv, sys.stdout
    captured = io.StringIO()

    class _Refusing:
        def __init__(self, *_args, **_kwargs):
            pass

        def settimeout(self, _seconds):
            return None

        def connect(self, _address):
            raise OSError(number, os.strerror(number))

    socket.socket = _Refusing
    sys.argv = ["mosdns-probe", install.NO_ROUTE_ADDRESS, str(install.NO_ROUTE_PORT)]
    sys.stdout = captured
    try:
        exec(compile(program, "<mosdns-probe>", "exec"), {"__name__": "__main__"})  # noqa: S102
    except OSError as error:
        raise AssertionError(
            f"install_test.py's route probe lets an OSError escape instead of reporting its "
            f"errno, so a cell that cannot route is reported as a command failure rather than as "
            f"a measurement, and this fixture cannot derive an answer for it. The program is:\n"
            f"{program}\nand it raised {error!r}"
        ) from error
    finally:
        socket.socket, sys.argv, sys.stdout = saved_socket, saved_argv, saved_out
    return captured.getvalue().strip()


# A probe that resolved a NAME and found nothing. `socket.EAI_NONAME` is what a
# real `socket.gaierror` carries when the only resolver in the cell -- the mock
# router, `no-resolv` with no upstream -- cannot answer, and it is MEASURED: a
# 24.04 cell answering the old name-based probe printed
# `socket.gaierror: [Errno -2] Name or service not known`.
#
# The number is reproduced faithfully and the sentence is not, deliberately:
# glibc's `gai_strerror` gave the cell "Name or service not known" where
# `os.strerror(-2)` gives "Unknown error -2", and nothing here asserts on a
# sentence. That gap is the argument for asserting on the number -- and for a
# fixture that produces the sentence rather than copying one run's copy of it.
NAME_UNRESOLVED = probe_failed(socket.EAI_NONAME)

# The probe succeeded, which is the cell this scenario refuses to measure. Named
# from the scenario's own constant so it cannot drift from what is looked for.
PROBE_CONNECTED = install.CLAIM_PROBE_CONNECTED

# The needle the probe's rule matches on: the LITERAL address and port, as they
# appear in the `sh -c` script. A scenario that went back to probing a hostname
# would be a command no rule in this table matches, so the cell would come back
# with no probe output at all and be refused -- which is the failure the first
# version could not have produced, because its rule matched whatever probe ran.
PROBE_NEEDLE = f"{install.NO_ROUTE_ADDRESS} {install.NO_ROUTE_PORT}"

# What `update-lists --refresh-ranges` prints on a machine with no route and no
# published document, and what it prints when the check has measured the pin.
REFRESH_FROM_PIN = """\
ranges-url: https://api.cloudflare.com/client/v4/ips
ranges-etag: W/"38f79d050aa027e3be3865e495dcc9bc"
ranges-prefixes: 15
ranges-stale: true
ranges-source: pinned-snapshot
ranges-pinned-snapshot: /usr/share/mosdns-router/cloudflare-ranges.json
ranges-pinned-lock: /usr/share/mosdns-router/cloudflare-ranges.lock.json
ranges-pinned-sha256: {shipped}
ranges-pinned-revision: 38f79d050aa027e3be3865e495dcc9bc
ranges-pinned-at: 2026-09-30T00:03:59Z
ranges-pinned-age: 1h4m32.555058608s
ranges-pinned-prefixes: 15
ranges-pinned-prefix-list-sha256: db746a8739a51088c27d0b3c48679d21a69aab304d4c92af3ec0e89145b0cadd
published-ranges-cache: /var/lib/mosdns/lists/cloudflare-ips.json
published-prefix-list: /var/lib/mosdns/lists/cloudflare-prefixes.txt
""".format(shipped=SHIPPED_PIN_SHA)

CHECK_REPORT = """\
update-lists: https://api.github.com/repos/v2fly/domain-list-community/commits/HEAD: server misbehaving
update-lists: what was read from the disk, which did not depend on that request:
ranges-published: true
ranges-consistent: true
ranges-prefixes: 15
ranges-prefix-list-sha256: db746a8739a51088c27d0b3c48679d21a69aab304d4c92af3ec0e89145b0cadd
ranges-published-document-sha256: {origin}
ranges-pin: /usr/share/mosdns-router/cloudflare-ranges.json
ranges-pin-lock: /usr/share/mosdns-router/cloudflare-ranges.lock.json
ranges-pin-verified: true
ranges-pin-pinned-at: 2026-09-30T00:03:59Z
ranges-pin-age: 1h4m47.599102241s
ranges-pin-prefixes: 15
ranges-pin-document-sha256: {origin}
ranges-pin-drift: none
""".format(origin=ORIGIN_DOCUMENT_SHA)


def install_rules(**overrides):
    """The rule table a cell where the install completes and the pin is used.

    Every override replaces one answer, so each case changes exactly the fact it
    is about -- which is the property that makes a case here evidence rather
    than a re-run.
    """
    answers = {
        # The route table of a cell on a private bridge, and the route probe that
        # fails. The precondition of the whole scenario.
        "route": "10.89.0.0/24 dev eth0 proto kernel scope link src 10.89.0.190 metric 100",
        "reachable": probe_failed(),
        # The package, installed once.
        "stat": "16205254",
        "install": COMPLETED_OUTPUT,
        "state": "installed",
        "status": "install ok installed",
        # The two digests the property rests on.
        "shipped": SHIPPED_PIN_SHA,
        "published": PUBLISHED_PIN_SHA,
        "prefixes": PREFIX_LIST,
        # The two files the transaction claims to have written.
        "backup": 0,
        "marker": 0,
        "refresh": REFRESH_FROM_PIN,
        "check": CHECK_REPORT,
        # The refusal case, and the state it leaves behind.
        "corrupt": CORRUPT_OUTPUT,
        "corrupt_state": "half-configured",
        "corrupt_present": 1,
        "corrupt_restored": 0,
    }
    answers.update(overrides)
    return [
        {"match": ["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "eth0"],
         "answers": [{"stdout": "eth0\n"}, {"stdout": "eth0-managed\n"}]},
        {"match": ["nmcli", "-g", "IP4.DNS", "device", "show", "eth0"], "stdout": "10.89.0.2\n"},
        {"match": ["ip", "route", "show"], "stdout": answers["route"] + "\n"},
        # The rule that answers the route probe matches on the LITERAL address, so
        # it is the shape of the command that is asserted here rather than a
        # substring of the program: a rule that matched on `SOCK_DGRAM` would
        # answer whatever probe ran, and a rule that matched on a hostname would
        # answer exactly the command that made this fix necessary.
        {"match": ["sh", "-c"], "match_contains": PROBE_NEEDLE, "stdout": answers["reachable"] + "\n"},
        {"match": ["stat", "-c", "%s", "/tmp/mosdns-router.deb"], "stdout": answers["stat"] + "\n"},
        {"match": ["sh", "-c", DPKG_INSTALL], "returncode": 0, "stdout": answers["install"] + "DPKG_EXIT=0\n"},
        {"match": ["sh", "-c", DPKG_STATUS_QUERY], "stdout": answers["status"] + "\n"},
        {"match": ["sha256sum", "/usr/share/mosdns-router/cloudflare-ranges.json"],
         "stdout": f"{answers['shipped']}  /usr/share/mosdns-router/cloudflare-ranges.json\n"},
        {"match": ["sha256sum", "/usr/share/mosdns-router/cloudflare-ranges.lock.json"],
         "stdout": f"{answers['corrupt']and SHIPPED_PIN_SHA}  /usr/share/mosdns-router/cloudflare-ranges.lock.json\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/cloudflare-ips.json"],
         "stdout": f"{answers['published']}  /var/lib/mosdns/lists/cloudflare-ips.json\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/cloudflare-prefixes.txt"],
         "stdout": f"{answers['prefixes']}  /var/lib/mosdns/lists/cloudflare-prefixes.txt\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/cn-domains.txt"],
         "stdout": "a865b7cb15f56edd73e8b2df37f22d0d1fe9ee0f4991c090a62ca11e495dfa9f  /var/lib/mosdns/lists/cn-domains.txt\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/source-lock.json"],
         "stdout": "9c1a1d0dd0eea0f4d2b1c2e5c9a0e1d4b3f2a1c0d9e8f7a6b5c4d3e2f1a0b9c8  /var/lib/mosdns/lists/source-lock.json\n"},
        {"match": ["test", "-e", "/var/lib/mosdns/installer/network-manager-backup.json"],
         "returncode": answers["backup"]},
        {"match": ["test", "-e", "/var/lib/mosdns/installer/managed-by"], "returncode": answers["marker"]},
        # The refresh is asked twice: once to publish (the `sh -c` rule above
        # carries the socket test, and this one carries the `rm` and the run) and
        # once to read the report back.
        {"match": ["sh", "-c"], "match_contains": "update-lists --refresh-ranges",
         "stdout": answers["refresh"]},
        {"match": ["sh", "-c"], "match_contains": "update-lists --check", "stdout": answers["check"]},
        {"match": ["cat", "/var/lib/mosdns/lists/cloudflare-prefixes.txt"], "stdout": answers["prefixes"]},
        {"match": ["cat", "/usr/share/mosdns-router/cloudflare-ranges.json"],
         "stdout": '{"schema_version":1,"url":"https://api.cloudflare.com/client/v4/ips"}\n'},
        # The refusal case, and it is a SEQUENCE rather than one answer: the
        # scenario runs `dpkg --configure` twice, once to plant the refusal's
        # output in the log and once to read it back, and both have to be
        # answered. A single answer here would leave the second read empty, and a
        # case asserting on empty output would pass for the wrong reason.
        {"match": ["sh", "-c"], "match_contains": "dpkg --configure mosdns-router",
         "answers": [
             {"stdout": answers["corrupt"]},
             {"stdout": answers["corrupt"]},
         ]},
        # And the state the refusal leaves, which is a SEQUENCE of its own for
        # the same reason and for the same property: the package was `installed`
        # when the scenario read it after `dpkg -i`, and `half-configured` when it
        # read it after the refusal. Exactly two reads, so exactly two answers --
        # a third would be dead weight and a case reading it would be asserting
        # against an entry nothing consults.
        {"match": ["sh", "-c", DPKG_STATE_QUERY],
         "answers": [
             {"stdout": answers["state"] + "\n"},
             {"stdout": answers["corrupt_state"] + "\n"},
         ]},
        # The published artifacts after the refusal. One answer each and NOT a
        # sequence: the scenario reads these digests with `sha256sum` and asks
        # `test -e` about them exactly once, in the refusal case, so a sequence
        # here would leave its second answer unused and read as coverage that is
        # not there.
        {"match": ["test", "-e", "/var/lib/mosdns/lists/cloudflare-ips.json"],
         "returncode": answers["corrupt_present"]},
        {"match": ["test", "-e", "/var/lib/mosdns/lists/cloudflare-prefixes.txt"],
         "returncode": answers["corrupt_present"]},
        {"match": ["systemctl", "show", "--property=ActiveState", "--value",
                   "dnscrypt-proxy.service"], "stdout": "active\n"},
        {"match": ["systemctl", "show", "--property=ActiveState", "--value",
                   "mosdns-router.service"], "stdout": "active\n"},
        {"match": ["sh", "-c"], "match_contains": "ss -lntup", "stdout": (
            "udp UNCONN 0 0 127.0.0.1:15353 0.0.0.0:* users:((\"dnscrypt-proxy\",pid=1060,fd=5))\n"
            "udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:((\"mosdns-router\",pid=1068,fd=3))\n"
        )},
    ] + [
        {"match": ["test", "-e", f"/usr/lib/systemd/system/{timer}"], "returncode": 0}
        for timer in (
            "mosdns-cdn-optimizer.timer", "mosdns-cdn-health.timer",
            "mosdns-list-check.timer", "mosdns-watchdog.timer",
        )
    ]


class InstallScenarioHarness(PodmanTestCase):
    """Drives the scenario against a fake podman, on a virtual clock."""

    def run_scenario(self, *, rules=None, **overrides):
        """One cell, and the fake that answered it."""
        if rules is None:
            rules = install_rules(**overrides)
        fake = self.fake(rules, self.extra_directory())
        clock = {"now": 0.0}
        package = self.directory / "mosdns-router_0.1.0_amd64.deb"
        package.write_bytes(b"not a real deb; the fake never reads it")
        builder = install.build_scenario(
            podman=self.client(fake),
            version=VERSION,
            arch="amd64",
            run_id=RUN_ID,
            router=ROUTER,
            target=TARGET,
            network=f"mosdns-{RUN_ID}-testnet",
            results_dir=self.directory / "results",
            deb=package,
            now=lambda: clock["now"],
            sleep=lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
        )
        return fake, builder()

    def record(self, result):
        return json.loads(
            (self.directory / "results" / RUN_ID / result.log).read_text(encoding="utf-8")
        )

    def asked(self, fake):
        return [
            " ".join(argv[2:])
            for argv in fake.invocations()
            if argv[:2] == ["exec", TARGET]
        ]


class ScenarioPassesTest(InstallScenarioHarness):
    """The cell this step exists to produce, and what it records when it passes."""

    def test_the_scenario_passes_with_no_route_to_the_internet(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(result.log, f"logs/{VERSION}-install.json")

    def test_the_record_carries_the_three_facts_the_claim_rests_on(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        # One: dpkg's own record. Both spellings, because a scenario that read
        # only one could be satisfied by a package dpkg left half-configured.
        self.assertEqual(record["package_state"], "installed")
        self.assertEqual(record["package_status_phrase"], "install ok installed")
        self.assertTrue(record["package_configured"])
        # Two: the transaction's own account, and the two files it says it wrote.
        self.assertIn("now uses the loopback address 127.0.0.1", record["dpkg_output"])
        self.assertIn("the ownership marker at", record["dpkg_output"])
        self.assertTrue(record["backup_present"])
        self.assertTrue(record["marker_present"])
        # Three: the digest equality, which is the whole of "the pin made this
        # install possible". A cell that reached the origin would hold a
        # different document here and every other observation would read the
        # same.
        self.assertEqual(record["published_ranges_sha256"], record["shipped_pin_sha256"])
        self.assertEqual(record["prefix_list_lines"], 3)

    def test_the_record_says_the_cell_had_no_route_and_why_that_matters(self):
        # The precondition is recorded rather than assumed, so a reader of the
        # evidence can tell that the install was possible BECAUSE the snapshot
        # exists rather than in spite of a reachable origin. The errno is the
        # fact, and it is recorded as the number the kernel gave.
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertTrue(record["no_route_established"])
        self.assertIn("10.89.0.0/24", record["route_table"])
        self.assertEqual(record["origin_probe_errno"], errno.ENETUNREACH)
        self.assertIn(f"errno={errno.ENETUNREACH}", record["origin_reachable"])
        self.assertIn("mosdns-probe: failed", record["origin_reachable"])

    def test_a_blackholed_route_is_accepted_because_the_probe_timed_out(self):
        # A machine with a default route and no answer for the address is a
        # machine with no route to the internet as far as this claim is
        # concerned, and it answers `ETIMEDOUT` rather than `ENETUNREACH`. It is
        # a different kernel message for the same fact, which is the reason the
        # assertion is on the number.
        _fake, result = self.run_scenario(reachable=probe_failed(errno.ETIMEDOUT) + "\n")
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(self.record(result)["origin_probe_errno"], errno.ETIMEDOUT)

    def test_a_probe_that_produced_no_errno_at_all_is_refused(self):
        # Empty output is what the fake answers a command no rule matches, and it
        # is what a `python3` that is not installed answers. Either way the probe
        # did not measure the route table, and a scenario that read an absent
        # measurement as "no route" would be reporting the precondition it was
        # checking.
        _fake, result = self.run_scenario(reachable="\n")
        self.assertEqual(result.status, "failed")
        self.assertIn("reported no errno at all", result.detail)
        self.assertIn("it is a probe that did not run", result.detail)

    def test_the_record_carries_the_reports_an_operator_would_read(self):
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertIn("ranges-source: pinned-snapshot", record["refresh_report"])
        self.assertIn("ranges-pin-verified: true", record["check_report"])
        self.assertIn("ranges-pin-drift: none", record["check_report"])
        # The age is the reason the drift half exists: a three-month-old pin is a
        # fine input for a selector and a pin nobody measures is not.
        self.assertTrue(record["pin_age_reported"])
        self.assertIn("ranges-pin-age: 1h4m47", record["check_report"])

    def test_the_record_says_which_barrier_refused_when_one_does(self):
        # The record is written on the failure path too, and a reader of a failed
        # cell needs dpkg's own words rather than a status.
        _fake, result = self.run_scenario(state="half-configured", status="install ok half-configured")
        self.assertEqual(result.status, "failed")
        record = self.record(result)
        self.assertEqual(record["package_state"], "half-configured")
        self.assertIn("dpkg_output", record)
        self.assertIn("postinst", record["dpkg_output"])

    def test_the_install_runs_exactly_once(self):
        # Two `dpkg -i` invocations run the transaction twice, and every recorded
        # state then describes the second one -- which is how the watchdog
        # scenario's fixture once reported a cell green while its evidence
        # document quietly became a record of two installs.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        installs = [line for line in self.asked(fake) if line.startswith("sh -c dpkg -i")]
        self.assertEqual(len(installs), 1, f"dpkg -i ran {len(installs)} times: {installs}")
        self.assertEqual(self.record(result)["dpkg_runs"], 1)


class TheRefusalsTest(InstallScenarioHarness):
    """Both sides of the property. A scenario that only proves the happy path
    leaves the refusal unverified, and the refusal is what has been protecting
    every machine so far."""

    def test_a_cell_that_can_reach_the_origin_is_refused_not_passed(self):
        # The single most important case in this file. A bridge that NATs outward
        # would let the install succeed for an entirely different reason, the
        # published document would be the origin's, and every other observation
        # would read the same -- so the cell would pass while measuring nothing.
        _fake, result = self.run_scenario(reachable=PROBE_CONNECTED + "\n")
        self.assertEqual(result.status, "failed")
        self.assertIn("SUCCEEDED", result.detail)
        self.assertIn("would then be true for a different reason", result.detail)

    def test_the_no_route_probe_asks_a_literal_address_and_not_a_name(self):
        # **The defect this pair of cases exists for.** A UDP `connect()` to a
        # NAME resolves the name first, through the cell's own resolver -- which
        # here is the mock router, `no-resolv` with no upstream, answering exactly
        # one name -- so the probe read a resolution error and never read the
        # route table at all. MEASURED in a 24.04 cell: the old probe printed
        # `socket.gaierror: [Errno -2] Name or service not known`.
        #
        # So the command is read out of the fake's own log rather than trusted,
        # because a source-level check cannot tell a name from an address and a
        # substring check on the scenario would be the same kind of assertion the
        # first version made.
        fake, result = self.run_scenario()
        probes = [line for line in self.asked(fake) if "mosdns-probe" in line or "SOCK_DGRAM" in line]
        self.assertEqual(len(probes), 1, f"the route probe ran {len(probes)} times: {probes}")
        self.assertIn(f"{install.NO_ROUTE_ADDRESS} {install.NO_ROUTE_PORT}", probes[0])
        for name in ("api.cloudflare.com", "cloudflare.com"):
            self.assertNotIn(
                name, probes[0],
                f"the no-route probe resolves {name} through this cell's own resolver, so it "
                f"measures the mock router rather than the route table: {probes[0]!r}",
            )
        self.assertEqual(result.status, "passed", result.detail)

    def test_a_probe_that_only_failed_to_resolve_a_name_is_refused_and_says_so(self):
        # The fake cannot get this wrong by accident: `NAME_UNRESOLVED` is
        # derived from `EAI_NONAME` and `os.strerror`, and `EAI_NONAME` is not in
        # the scenario's accepted set. Before the fix the scenario looked for a
        # message substring, and the message the real cell produced contained
        # neither the kernel's nor a timeout -- so it refused a routeless cell
        # while saying the origin was REACHABLE, the exact inverse of the truth.
        _fake, result = self.run_scenario(reachable=NAME_UNRESOLVED + "\n")
        self.assertEqual(result.status, "failed")
        self.assertIn(
            "is not one of the", result.detail,
            "the scenario refused a name that did not resolve, which is right, and said so "
            "by the number rather than by a sentence",
        )
        self.assertIn(
            "has measured nothing", result.detail,
            "the refusal does not say that a name-resolving probe measured the cell's resolver "
            "instead of its route table, which is the defect that produced it",
        )
        self.assertNotIn(
            "is reachable from", result.detail,
            "the refusal claims the origin is reachable, which is the inverse of what a cell with "
            "no route is: this is the message the first version produced on the real cell",
        )

    def test_a_published_document_that_is_not_the_shipped_one_is_refused(self):
        # The digest equality is the measurement, so a cell holding the ORIGIN's
        # document has to fail even though everything else about it is healthy.
        _fake, result = self.run_scenario(published=ORIGIN_DOCUMENT_SHA)
        self.assertEqual(result.status, "failed")
        self.assertIn("the published range document is", result.detail)
        self.assertIn("these are not equal", result.detail)

    def test_a_missing_shipped_snapshot_is_refused(self):
        # A package that ships no pinned document cannot have installed from one,
        # and an unreadable file has to be distinguishable from a file whose
        # digest happens to be nothing -- which is why `digest_of` returns the
        # empty string rather than a placeholder.
        rules = [
            rule for rule in install_rules()
            if rule["match"] != ["sha256sum", "/usr/share/mosdns-router/cloudflare-ranges.json"]
        ]
        _fake, result = self.run_scenario(rules=rules)
        self.assertEqual(result.status, "failed")
        self.assertIn("is not readable", result.detail)
        self.assertIn("this package ships no pinned range document", result.detail)

    def test_a_corrupt_shipped_snapshot_refuses_before_the_transaction_runs(self):
        # The refusal is in STEP 3, which is why the transaction's own words are
        # absent from the output: nothing was captured, backed up or changed.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertTrue(record["corrupt_pin_refused"])
        self.assertIn("cannot account for", record["corrupt_pin_output"])
        self.assertIn("Nothing has been changed on this machine's DNS", record["corrupt_pin_output"])
        self.assertNotIn("now uses the loopback address", record["corrupt_pin_output"])
        self.assertNotIn("preflight refused", record["corrupt_pin_output"])

    def test_a_corrupt_shipped_snapshot_publishes_nothing(self):
        # A refusal that left a prefix list behind would satisfy the NEXT
        # install's start requirement with ranges nothing accounts for, which is
        # the failure the whole digest check exists to prevent.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(self.record(result)["corrupt_pin_published"], [])

    def test_a_corrupt_shipped_snapshot_leaves_the_package_unconfigured(self):
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertEqual(record["corrupt_pin_state"], "half-configured")
        self.assertNotIn(record["corrupt_pin_state"], ("installed", "install ok installed"))

    def test_the_refusal_case_restores_the_shipped_snapshot(self):
        # One cell's failed case must not be the next cell's starting state, and
        # the restore is by writing back the bytes that were read rather than by
        # re-fetching them -- a restore that reached the network could put a
        # DIFFERENT document in place and leave the cell unrecognisable.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertEqual(record["pin_restored_sha256"], record["shipped_pin_sha256"])


class FakeSeamTest(InstallScenarioHarness):
    """The fake's `sh -c` matcher, which every case here depends on.

    A seam rather than a detail: every command a scenario runs through `sh -c`
    arrives as ONE argv token holding the whole script, so a rule matching tokens
    would match every `sh -c` at once and hand the first answer to all of them.
    Without this the refusal case and the happy path -- the same command, two
    different answers -- could not be told apart, and the cases above would be
    asserting against a table that cannot express what they claim to.
    """

    def test_two_sh_c_invocations_of_one_command_get_different_answers(self):
        for script in ("update-lists --refresh-ranges", "update-lists --check",
                       "dpkg --configure mosdns-router"):
            with self.subTest(script=script):
                fake = self.fake(
                    [
                        {"match": ["sh", "-c"], "match_contains": script,
                         "answers": [{"stdout": "first"}, {"stdout": "second"}]},
                    ],
                    self.extra_directory(),
                )
                client = self.client(fake)
                self.assertEqual(client.exec_script(TARGET, script).output, "first")
                self.assertEqual(client.exec_script(TARGET, script).output, "second")

    def test_a_rule_without_the_needle_still_matches_its_own_command(self):
        # The other half, and the one that would make the case above pass for the
        # wrong reason: a `match_contains` rule that matched everything would
        # satisfy it too.
        fake = self.fake(
            [{"match": ["sh", "-c"], "match_contains": "update-lists --check",
              "stdout": "checking"}],
            self.extra_directory(),
        )
        client = self.client(fake)
        self.assertEqual(
            client.exec_script(TARGET, "update-lists --refresh-ranges").output, "",
            "a rule for `--check` answered a `--refresh-ranges`",
        )
        self.assertEqual(client.exec_script(TARGET, "update-lists --check").output, "checking")


class ScenarioShapeTest(unittest.TestCase):
    """What the scenario must keep being, checked against its source.

    These are the properties a reader of `install_test.py` would otherwise have
    to take on trust, and each one has been a real defect in a sibling scenario:
    a scenario that stopped waiting, one that ran `dpkg -i` twice, one that
    reported a pass for a cell whose own evidence contradicted it.
    """

    def source(self) -> str:
        return (SCENARIOS / "install_test.py").read_text(encoding="utf-8")

    def test_the_scenario_is_registered_under_this_name(self):
        registry = (HARNESS / "run.py").read_text(encoding="utf-8")
        self.assertIn('"install": "install_test:build_scenario"', registry)
        self.assertIn('PACKAGE_SCENARIOS = ("install", "watchdog")', registry)

    def test_the_scenario_declares_the_claim_constants_it_asserts(self):
        # Every string the scenario requires is a named constant, so a reader can
        # see what the product is without reading the assertions, and a change to
        # what the package says is a change to one line rather than to a dozen
        # literals scattered through the file.
        tree = ast.parse(self.source())
        constants = {
            node.targets[0].id
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        }
        for name in (
            "CLAIM_PIN_PUBLISHED", "CLAIM_PIN_VERIFIED", "CLAIM_PIN_DRIFT_NONE",
            "CLAIM_TRANSACTION_TOOK_OVER", "CLAIM_MARKER_WRITTEN",
        ):
            self.assertIn(name, constants, f"{name} is asserted but not named at module scope")

    def test_the_no_route_assertion_is_a_number_and_not_a_sentence(self):
        # The first version named `CLAIM_NO_ROUTE = "Network is unreachable"` and
        # required that sentence, so the fake had to produce that sentence and
        # the twenty cases here could not tell a real reading from a written
        # one. The accepted set is now built from the `errno` module and the
        # probe program classifies its own failure, so both the claim and the
        # fake's answer are derived from a number.
        source = self.source()
        self.assertNotIn(
            "CLAIM_NO_ROUTE", source,
            "the scenario still asserts a message substring for its no-route precondition",
        )
        self.assertIn("import errno", source)
        self.assertIn("NO_ROUTE_ERRNOS", source)
        self.assertIn(
            "errno.ENETUNREACH", source,
            "the accepted set of 'no route' errors is written out rather than derived from the "
            "`errno` module, so a platform that renumbers one would silently stop matching",
        )
        self.assertEqual(
            install.NO_ROUTE_ERRNOS,
            (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT),
            "the accepted set changed; a case that depends on the exact set has to say so",
        )
        for number in (socket.EAI_NONAME, socket.EAI_AGAIN):
            self.assertNotIn(
                number, install.NO_ROUTE_ERRNOS,
                f"{number} is a name that did not resolve, not a route that does not lead anywhere",
            )
        self.assertEqual(
            install.NAME_ERRNOS, (socket.EAI_NONAME, socket.EAI_AGAIN),
            "the scenario's named set of 'the name did not resolve' errors changed, and the refusal "
            "message above is written against it",
        )

    def test_the_scenario_waits_rather_than_sleeps_for_the_handoff(self):
        # `nmcli connection up` returns before the device has an address, so a
        # scenario that reads IP4.DNS on the next line reads a field that is not
        # there yet, and one that sleeps reads it at an arbitrary later moment.
        # Both pass on a fast machine and fail on a loaded one.
        source = self.source()
        self.assertIn("wait_for(", source)
        self.assertNotRegex(source, r"time\.sleep\(")

    def test_the_scenario_asserts_the_digest_equality_rather_than_a_message(self):
        # "The install succeeded" is not the property. "The document it published
        # is the snapshot the package ships" is, and it is an equality between two
        # digests the cell produced.
        source = self.source()
        self.assertIn("published_ranges_sha256\"] == document[\"shipped_pin_sha256\"]", source)

    def test_the_scenario_covers_both_sides_of_the_property(self):
        # A scenario that only proves the happy path leaves the refusal
        # unverified, and the refusal is what has been protecting every machine
        # so far. Named here because a later edit that drops the second half
        # would otherwise look like a simplification.
        source = self.source()
        self.assertIn("corrupt_pin_refused", source)
        self.assertIn("no_route_established", source)


if __name__ == "__main__":
    unittest.main()
