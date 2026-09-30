"""The install scenario's assertions: the barrier, and the one it cannot pass.

`install_test.py` observes the property Task 4 Step 1 was written to deliver --
with no route to the internet at all, `update-lists --refresh-ranges` publishes
the package's pinned range document, `postinst` verifies the pair, and the
transaction's refusal names the *foreign resolver* rather than the range origin.
And it observes the property it **cannot** deliver: the transaction reaching
`install ok configured` with no route. That one is recorded as a required skip on
the scenario, so the cell is `incomplete` and the run is exit 3 rather than a red
matrix for something that is not a defect.

These cases drive the real scenario module against the fake `podman` the rest of
this suite uses, and there are three halves to them.

**The cell**, which is three facts rather than one: dpkg recorded the state a
refused transaction leaves, the transaction's own words name the resolver's
barrier and not the range step's, and the published range document's digest
equals the snapshot the package ships. The third is the one that matters: a cell
whose bridge NATs outward would publish from the origin and hold a *different*
document, so the equality is what distinguishes "the pin made this install get
that far" from "the install happened to succeed".

**The refusals**, which a happy-path-only scenario leaves entirely unverified and
which are what has been protecting every machine so far. A cell whose bridge
reaches the origin is refused rather than passed, because every observation would
otherwise read the same while measuring nothing; a cell where the *range* step is
what refused is refused, because that is the state this step was written to end
and only the absent-signature checks can tell the two refusals apart; a cell
where the transaction completed is refused, because that is Task 4 Step 5's cell
and a scenario that accepted both would prove nothing about either; a shipped
snapshot whose bytes its lock does not record has to stop the install *before the
transaction runs* and publish nothing; and each of those refusals has to leave the
cell as it was found, so one cell's failed case cannot be the next cell's
starting state.

**The fakes**, which have to be able to disagree with the code. The route probe's
answer is produced by running the scenario's own probe program with a real
`OSError` substituted, so the fixture derives what it answers instead of writing
down the string the assertion is looking for -- the defect this file's first
version had, and the reason it could not see that the real cell answered a
`gaierror` where the assertion wanted an `ENETUNREACH`.
"""

import ast
import base64
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

# dpkg's own output for the cell this scenario is written for: a routeless cell
# in which the transaction got PAST the range publication and refused at the
# resolver's own start-up barrier. **Verbatim from a 24.04 cell built from this
# tree**, so every claim the scenario asserts is a sentence a real cell printed.
#
# The three parts that matter, and what each one would mean if it were absent:
#
#   * postinst's STEP 3 -- the shipped pair verified. Without it the package
#     never got past its own pin, which is the state this step was written to
#     end.
#   * the installer's refusal naming the resolver's wait, and its rollback. This
#     is the barrier: `dnscrypt-proxy` binds its loopback listener once its own
#     reachability probe runs out and then answers nothing, because the DNSCrypt
#     server it needs is on the internet.
#   * postinst's own status-3 arm -- "refused this machine and rolled back" and
#     "Nothing is enabled and nothing was started". The second is why the four
#     timers are recorded rather than asserted enabled.
REFUSED_OUTPUT = """\
Selecting previously unselected package mosdns-router.
Preparing to unpack /tmp/mosdns-router.deb ...
Unpacking mosdns-router (0.1.0) ...
Setting up mosdns-router (0.1.0) ...
postinst: the pinned range document at /usr/share/mosdns-router/cloudflare-ranges.json is {shipped}, as
postinst: /usr/share/mosdns-router/cloudflare-ranges.lock.json records, taken at 2026-09-30T00:03:59Z. It is read
postinst: here and never written: 'mosdns-cdnctl update-lists --refresh-ranges' is what
postinst: publishes it, and it reads this machine's own published document first.
install: dnscrypt-proxy.service was started but nothing answered a DNS query at 127.0.0.1:15353 within 60s, so the machine has no local resolver to point NetworkManager at; nothing has been pointed at anything and the transaction is being undone
install: every change this run made has been rolled back, and /var/lib/mosdns/installer/network-manager-backup.json records what the connection was set to; nothing else is different about this machine
postinst: the install transaction refused this machine and rolled back
postinst: every change it made, so nothing on this machine's DNS
postinst: configuration is different from how this script found it.
postinst: Nothing is enabled and nothing was started: this was a first
postinst: install, and the four timers are enabled only after this step
postinst: succeeds, so there is nothing here for them to run against.
dpkg: error processing package /tmp/mosdns-router.deb (--install):
 installed mosdns-router package post-installation script subprocess returned error exit status 1
Errors were encountered while processing:
 mosdns-router
DPKG_EXIT=1
""".format(shipped=SHIPPED_PIN_SHA)

# A cell where the RANGE step is what refused, which is the state this step was
# written to end and the one a scenario that only asserted "the transaction
# refused" could not tell from `REFUSED_OUTPUT`. Two of the words are required to
# be ABSENT from the transaction's output, so this is the case that makes that
# assertion load-bearing rather than decorative. The wording is `standInFor`'s
# own, and postinst's.
CDN_BARRIER_OUTPUT = """\
postinst: the pinned range document at /usr/share/mosdns-router/cloudflare-ranges.json is {shipped}, as
postinst: /usr/share/mosdns-router/cloudflare-ranges.lock.json records, taken at 2026-09-30T00:03:59Z.
install: update-lists: https://api.cloudflare.com/client/v4/ips: unexpected status 503; the pinned
install: snapshot this package ships, /usr/share/mosdns-router/cloudflare-ranges.json with
install: /usr/share/mosdns-router/cloudflare-ranges.lock.json beside it, cannot stand in for it
install: either: /usr/share/mosdns-router/cloudflare-ranges.json is
install: d1235dc06af1c770ffee53ec9a53275a3aa7aca1349b95672d74aea06433de5d and
install: /usr/share/mosdns-router/cloudflare-ranges.lock.json records {shipped} for it, so this
install: package cannot account for the ranges in it
postinst: the install transaction refused this machine before it changed
postinst: anything. That is the installer's own refusal, and the list of
postinst: what its preflight found is the messages above.
dpkg: error processing package /tmp/mosdns-router.deb (--install):
 installed mosdns-router package post-installation script subprocess returned error exit status 1
DPKG_EXIT=1
""".format(shipped=SHIPPED_PIN_SHA)

# A cell whose transaction refused at the resolver's barrier AND carried a range
# refusal with it. It is not a cell this suite can produce and it is not a cell
# any matrix produced -- it is here because it is the only state in which the
# ABSENT-signature checks are the only thing that can see it. A cell that
# refused at the ranges alone is caught by the positive check; a cell that
# refused at the resolver alone has no range wording in it. A cell carrying both
# means the range step failed *and* the transaction carried on far enough to hit
# the resolver's wait, and an evidence document that called that "the barrier"
# would be describing a run that published nothing and installed nothing.
BOTH_BARRIERS_OUTPUT = REFUSED_OUTPUT + """\
update-lists: https://api.cloudflare.com/client/v4/ips: server misbehaving
install: the pinned snapshot this package ships cannot stand in for it either
"""

# The first version of this file's happy path: a cell where the transaction
# COMPLETED, with both daemons active and the four timers enabled. Kept as a
# fixture value rather than deleted, because it is what the scenario must now
# refuse -- it is Task 4 Step 5's cell, not this step's, and a scenario that
# quietly accepted both would prove nothing about either.
COMPLETED_OUTPUT = """\
postinst: the pinned range document at /usr/share/mosdns-router/cloudflare-ranges.json is {shipped}, as
postinst: /usr/share/mosdns-router/cloudflare-ranges.lock.json records, taken at 2026-09-30T00:03:59Z. It is read
postinst: here and never written: 'mosdns-cdnctl update-lists --refresh-ranges' is what
postinst: publishes it, and it reads this machine's own published document first.
note: eth0-managed (eth0, f1480978-e49e-4ed7-953b-748d5d1c512d) now uses the loopback address 127.0.0.1; the original settings are recorded in /var/lib/mosdns/installer/network-manager-backup.json
install: 53 and 15353 are served on loopback and NetworkManager has been pointed at 127.0.0.1; the ownership marker at /var/lib/mosdns/installer/managed-by has been written, so an uninstall will restore exactly what was changed
Created symlink /etc/systemd/system/timers.target.wants/mosdns-cdn-optimizer.timer -> /usr/lib/systemd/system/mosdns-cdn-optimizer.timer.
DPKG_EXIT=0
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

# What the scenario writes back after the corrupt-snapshot case. Base64, because
# the scenario reads the file that way: the wrapper's `.output` strips trailing
# whitespace, so a text read loses the final newline and the restore would not
# round-trip. **This constant is derived from the repository's own shipped
# snapshot**, so if the pin is ever re-pinned the fixture follows it and the
# restore case is testing a real round trip rather than a remembered string.
SHIPPED_PIN_PATH = install.SHIPPED_PIN
SHIPPED_PIN_BYTES = (
    REPO / "configs" / "cloudflare-ranges.json"
).read_bytes()
SHIPPED_PIN_BASE64 = base64.b64encode(SHIPPED_PIN_BYTES).decode("ascii")

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
    """The rule table for the cell this scenario is written for: a routeless cell
    in which the transaction got past the range step and refused at the resolver.

    Every override replaces one answer, so each case changes exactly the fact it
    is about -- which is the property that makes a case here evidence rather
    than a re-run.
    """
    answers = {
        # The route table of a cell on a private bridge, and the route probe that
        # fails. The precondition of the whole scenario.
        "route": "10.89.0.0/24 dev eth0 proto kernel scope link src 10.89.0.190 metric 100",
        "reachable": probe_failed(),
        # The package, installed once: the transaction refuses, so dpkg's word is
        # one of the two and the exit is 1.
        "stat": "16205254",
        "install": REFUSED_OUTPUT,
        "state": "half-configured",
        "status": "install ok half-configured",
        # The two digests the property rests on.
        "shipped": SHIPPED_PIN_SHA,
        "published": PUBLISHED_PIN_SHA,
        "prefixes": PREFIX_LIST,
        # The lock's own digest. Recorded separately from `shipped` rather than
        # written inline: the first version of this table carried an accidental
        # `answers['corrupt'] and SHIPPED_PIN_SHA` here, which evaluated to the
        # right value for the wrong reason and would have read a boolean to
        # anybody who changed the `corrupt` answer.
        "lock": SHIPPED_PIN_SHA,
        # The record the transaction wrote before its first mutation, and the
        # marker it did not write because it never committed.
        "backup": 0,
        "marker": 1,
        "refresh": REFRESH_FROM_PIN,
        "check": CHECK_REPORT,
        # The four timers: the unit files are there, the enable never ran.
        "timer": "disabled",
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
        {"match": ["sh", "-c", DPKG_INSTALL], "returncode": 0,
         "stdout": answers["install"] + f"DPKG_EXIT={1 if 'DPKG_EXIT=0' not in answers['install'] else 0}\n"},
        {"match": ["sh", "-c", DPKG_STATUS_QUERY], "stdout": answers["status"] + "\n"},
        {"match": ["sha256sum", "/usr/share/mosdns-router/cloudflare-ranges.json"],
         "stdout": f"{answers['shipped']}  /usr/share/mosdns-router/cloudflare-ranges.json\n"},
        {"match": ["sha256sum", "/usr/share/mosdns-router/cloudflare-ranges.lock.json"],
         "stdout": f"{answers['lock']}  /usr/share/mosdns-router/cloudflare-ranges.lock.json\n"},
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
        # The refresh is asked ONCE, and the report is read out of that same
        # invocation: a second `--refresh-ranges` finds the document the first
        # one published and reports `ranges-source: cache`, which says nothing
        # about the pin. The first version of this table answered BOTH
        # invocations with the pin's report, which is how twenty cases were
        # asserting the answer the fake was written with rather than the one a
        # real cell produces. MEASURED, 24.04: the second invocation says
        # `ranges-source: cache`.
        {"match": ["sh", "-c"], "match_contains": "update-lists --refresh-ranges",
         "stdout": answers["refresh"] + "REFRESH_EXIT=0\n"},
        {"match": ["sh", "-c"], "match_contains": "update-lists --check", "stdout": answers["check"]},
        {"match": ["cat", "/var/lib/mosdns/lists/cloudflare-prefixes.txt"], "stdout": answers["prefixes"]},
        # The shipped snapshot is read as base64 for the restore, not as text:
        # the wrapper's `.output` strips trailing whitespace, so a text read
        # loses the file's final newline and a heredoc restore glues its
        # terminator onto the last line. MEASURED -- that restore produced
        # `e249206b…` where the shipped pair is `fa80894e…`. The rule carries
        # the base64 of the same bytes the `cat` rule used to carry, so a case
        # that changes the shipped document changes both.
        {"match": ["sh", "-c"], "match_contains": f"base64 -w0 {SHIPPED_PIN_PATH}",
         "stdout": SHIPPED_PIN_BASE64 + "\n"},
        {"match": ["cat", SHIPPED_PIN_PATH],
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
        # the same reason and for the same property: the package was
        # `half-configured` when the scenario read it after `dpkg -i`, and
        # `half-configured` again when it read it after the corrupt-pin refusal.
        # Exactly two reads, so exactly two answers -- a third would be dead
        # weight and a case reading it would be asserting against an entry
        # nothing consults.
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
        # The two daemons the transaction started and then rolled back, so both
        # are `inactive` in this cell -- a measured reading, and the one that
        # tells a reader the rollback reached the units.
        {"match": ["systemctl", "show", "--property=ActiveState", "--value",
                   "dnscrypt-proxy.service"], "stdout": "inactive\n"},
        {"match": ["systemctl", "show", "--property=ActiveState", "--value",
                   "mosdns-router.service"], "stdout": "inactive\n"},
        # And no listener, because the resolver was stopped again. Recorded, not
        # asserted -- the loopback-listener question is the plan's Task 4 Step 3,
        # and this cell cannot answer it.
        {"match": ["sh", "-c"], "match_contains": "ss -lntup", "stdout": ""},
    ] + [
        {"match": ["test", "-e", f"/usr/lib/systemd/system/{timer}"], "returncode": 0}
        for timer in (
            "mosdns-cdn-optimizer.timer", "mosdns-cdn-health.timer",
            "mosdns-list-check.timer", "mosdns-watchdog.timer",
        )
    ] + [
        {"match": ["sh", "-c"], "match_contains": f"systemctl is-enabled {timer}",
         "stdout": f"{answers['timer']}\n"}
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
    """The cell this step produces, and what it records when it passes.

    **A passing install scenario is a passing cell that is not a passed cell.**
    The scenario proves what Task 4 Step 1 delivered -- the transaction gets past
    the range publication with no route to the internet -- and it cannot prove
    that the transaction then completes, so it records that requirement as a
    required skip. The cases below cover both halves, and the shape case in
    `ScenarioShapeTest` holds the docstring to the same two.
    """

    def test_the_scenario_passes_with_no_route_to_the_internet(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(result.log, f"logs/{VERSION}-install.json")

    def test_the_record_carries_the_facts_the_claim_rests_on(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        # One: dpkg's own record, and it is the REFUSING state. Both spellings,
        # because a scenario that read only one could be satisfied by a package
        # dpkg left unpacked. The two words dpkg uses are both accepted, and
        # which one appeared is recorded rather than assumed.
        self.assertEqual(record["package_state"], "half-configured")
        self.assertEqual(record["package_status_phrase"], "install ok half-configured")
        self.assertFalse(record["package_configured"])
        # Two: postinst verified the pair, and said it is never re-pinned. The
        # second is matched on the flattened output, because postinst writes that
        # sentence across two `echo` lines -- which is exactly why the scenario
        # flattens before it matches.
        flat = install.flatten_output(record["dpkg_output"])
        self.assertIn("the pinned range document at", flat)
        self.assertIn("It is read here and never written", flat)
        # Three: the digest equality, which is the whole of "the pin made this
        # install get that far". A cell that reached the origin would hold a
        # different document here and every other observation would read the
        # same.
        self.assertEqual(record["published_ranges_sha256"], record["shipped_pin_sha256"])
        self.assertEqual(record["prefix_list_lines"], 3)
        self.assertIn("ranges-source: pinned-snapshot", record["refresh_report"])

    def test_the_record_says_the_refusal_is_the_resolver_and_not_the_ranges(self):
        # **The property this step holds.** The transaction refuses in a
        # routeless cell, and the point is WHICH refusal: this step was written
        # to end the one that named the range origin, so a cell that still named
        # it would be a cell this step did not fix. The positive half is the
        # barrier's own sentence; the negative half is the two range refusals,
        # asserted absent, which is the half that makes it load-bearing.
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertTrue(record["barrier_is_the_foreign_resolver"])
        self.assertIn(install.CLAIM_RESOLVER_BARRIER, record["transaction_barrier"])
        self.assertIn("dnscrypt-proxy.service", record["transaction_barrier"])
        flat = install.flatten_output(record["dpkg_output"])
        self.assertIn(install.CLAIM_ROLLED_BACK, flat)
        self.assertIn(install.CLAIM_POSTINST_SAW_REFUSAL, flat)
        self.assertIn(install.CLAIM_NOTHING_ENABLED, flat)
        for signature in install.CDN_BARRIER_SIGNATURES:
            self.assertNotIn(signature, flat)

    def test_the_record_says_the_machines_dns_was_recorded_and_never_taken_over(self):
        # Two facts that are the rollback, read as a pair. The record is written
        # before the transaction's first mutation, so it exists whether or not the
        # transaction gets further; the ownership marker is written only on
        # commit, so its ABSENCE is what says the transaction never took the
        # machine over. A marker left behind by a refused transaction would point
        # a later uninstall at DNS the rollback undid.
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertTrue(record["backup_present"])
        self.assertFalse(record["marker_present"])

    def test_the_unclosed_requirement_is_recorded_as_a_named_required_skip(self):
        # The requirement in the plan's own words, not a summary of it, so a
        # reader can check the report against the plan. And `required=True`, so
        # the cell is `incomplete` and the run is exit 3 -- a skip is never
        # reported as a pass, and a `required=False` here would be filing a
        # required requirement as a nicety.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(len(result.skips), 1)
        recorded = result.skips[0]
        self.assertEqual(recorded.requirement, install.OFFLINE_CONFIGURED_REQUIREMENT)
        self.assertTrue(recorded.required)
        self.assertIn("install ok configured", recorded.requirement)
        # The reason says which barrier refused and which step closes it, so a
        # reader is not left with an open requirement and no road.
        self.assertIn(install.CLAIM_RESOLVER_BARRIER, recorded.reason)
        self.assertIn("Task 4 Step 5", recorded.reason)
        self.assertIn("DNSCrypt server", recorded.reason)

    def test_the_scenario_detail_says_the_state_and_the_barrier(self):
        # The one line an operator reads on the terminal. It has to name the
        # state dpkg recorded, the barrier, and the fact that the requirement is
        # recorded rather than closed -- a detail that said "the install
        # completed" would be the false claim the review found, and it would be
        # the only sentence most readers see.
        _fake, result = self.run_scenario()
        self.assertIn("install ok half-configured", result.detail)
        self.assertIn("got past the range step", result.detail)
        self.assertIn("127.0.0.1:15353", result.detail)
        self.assertIn("recorded as a required skip", result.detail)
        self.assertIn("incomplete rather than passed", result.detail)
        self.assertNotIn("the install transaction completed", result.detail)

    def test_the_record_carries_the_skip_it_could_not_close(self):
        # The evidence document is the one file a reader has, so the open
        # requirement is in it as well as in the result: a report archived
        # without the scenario's `detail` would otherwise be silent about it.
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertEqual(
            [entry["requirement"] for entry in record["unclosed_requirements"]],
            [install.OFFLINE_CONFIGURED_REQUIREMENT],
        )
        self.assertTrue(record["unclosed_requirements"][0]["required"])

    def test_the_record_says_the_cell_had_no_route_and_why_that_matters(self):
        # The precondition is recorded rather than assumed, so a reader of the
        # evidence can tell that the transaction got that far BECAUSE the
        # snapshot exists rather than in spite of a reachable origin. The errno
        # is the fact, and it is recorded as the number the kernel gave.
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

    def test_the_refresh_that_published_is_the_one_whose_report_is_read(self):
        # A second `update-lists --refresh-ranges` on the same machine finds the
        # document the first one published and reports `ranges-source: cache`,
        # so a scenario that asked twice and asserted on the second was
        # asserting on a report about its own first run. MEASURED, 24.04. The
        # rule above matches both invocations with the pin's report, so this is
        # about how many times the scenario asks.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        refreshes = [
            line for line in self.asked(fake)
            if "update-lists --refresh-ranges" in line and "rm -f" in line
        ]
        self.assertEqual(
            len(refreshes), 1,
            f"the publish was asked {len(refreshes)} times: {refreshes}",
        )
        self.assertEqual(self.record(result)["refresh_exit"], 0)

    def test_a_refresh_that_published_nothing_is_refused(self):
        # Exit 0 with `ranges-source: pinned-snapshot` is the whole of the claim.
        # A refresh that failed publishes nothing, and a scenario that read the
        # report of a LATER successful run would report an install that
        # published a document it did not.
        _fake, result = self.run_scenario(refresh=REFRESH_FROM_PIN + "REFRESH_EXIT=3\n")
        self.assertEqual(result.status, "failed")
        self.assertIn("exited 3", result.detail)
        self.assertIn("it published nothing", result.detail)

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

    def test_a_cell_where_the_range_step_is_what_refused_is_refused(self):
        # **The case that makes the "not the CDN one" assertion load-bearing.**
        # This is the cell every matrix cell was before the pinned snapshot
        # existed: postinst verified its pair, and the transaction refused
        # because the origin could not be read and the pin could not stand in
        # for it. Its dpkg output carries BOTH range refusals' signatures and not
        # the resolver's barrier -- so a scenario that only asserted "the
        # transaction refused" would pass against it and report a pass for a cell
        # this step did not fix.
        _fake, result = self.run_scenario(install=CDN_BARRIER_OUTPUT)
        self.assertEqual(result.status, "failed")
        self.assertIn(install.CLAIM_RESOLVER_BARRIER, result.detail)
        self.assertIn("the resolver's own start-up barrier refused the transaction", result.detail)
        self.assertIn("not the one this step delivered", result.detail)

    def test_a_refusal_that_also_carries_a_range_refusal_is_refused(self):
        # **The case the absent-signature checks exist for.** A cell that refused
        # at the ranges alone is already caught by the requirement that the
        # resolver's barrier be present, and a cell that refused at the resolver
        # alone has no range wording in it. This one has both, and it is the only
        # state in which dropping the absent-signature checks changes anything:
        # a document that called it "the resolver's barrier" would be describing
        # a run that published nothing and installed nothing while appearing to
        # have got past the CDN step.
        _fake, result = self.run_scenario(install=BOTH_BARRIERS_OUTPUT)
        self.assertEqual(result.status, "failed")
        self.assertIn("what the RANGE step says when it refuses", result.detail)
        self.assertIn("cannot stand in for it", result.detail)
        self.assertIn("did not get past the CDN step", result.detail)

    def test_a_cell_where_the_transaction_completed_is_refused(self):
        # The mirror, and it is Task 4 Step 5's cell rather than this step's:
        # with the test-only foreign override the transaction completes and
        # dpkg records `install ok installed`. A scenario that accepted both
        # would prove nothing about either, and the refusal says which step
        # upgrades it rather than leaving the next implementer to guess.
        _fake, result = self.run_scenario(
            install=COMPLETED_OUTPUT, state="installed", status="install ok installed",
            marker=0, backup=0, timer="enabled",
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("CONFIGURED", result.detail)
        self.assertIn("Task 4 Step 5 adds the test-only foreign override", result.detail)
        self.assertIn("upgrades", result.detail)

    def test_a_refused_transaction_that_still_left_the_ownership_marker_is_refused(self):
        # The marker is the rollback point a later uninstall reads. A transaction
        # that rolled itself back and left one would have a marker pointing at DNS
        # it never changed -- and the fixture's happy path is the only other place
        # a marker appears, so this case isolates it.
        _fake, result = self.run_scenario(marker=0)
        self.assertEqual(result.status, "failed")
        self.assertIn("IS in", result.detail)
        self.assertIn("owns the machine's DNS", result.detail)

    def test_a_refused_transaction_that_recorded_nothing_is_refused(self):
        _fake, result = self.run_scenario(backup=1)
        self.assertEqual(result.status, "failed")
        self.assertIn("is not in", result.detail)
        self.assertIn("nothing recording what it was", result.detail)

    def test_a_postinst_that_never_reported_verifying_the_pair_is_refused(self):
        # STEP 3's words are what say the package got past its own pin. Without
        # them the cell is not this one, and the transaction's own output would be
        # the only evidence -- which is the case where the interesting question
        # is which step refused, and the answer would be unanswered.
        _fake, result = self.run_scenario(
            install=REFUSED_OUTPUT.replace("the pinned range document at", "no range document here"),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("does not contain", result.detail)
        self.assertIn("postinst verified the shipped pair", result.detail)

    def test_a_refusal_that_did_not_say_it_rolled_back_is_refused(self):
        _fake, result = self.run_scenario(
            install=REFUSED_OUTPUT.replace("every change this run made has been rolled back",
                                           "the transaction is being undone"),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("the installer rolled the transaction back", result.detail)

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

    def test_the_restore_round_trips_the_bytes_it_read(self):
        # **The wrapper's `.output` strips trailing whitespace**, so the first
        # version of this restore -- read the file as text, write it back through
        # a heredoc -- put the heredoc's terminator on the end of the last line
        # and produced `e249206b…` where the shipped pair is `fa80894e…`. The
        # digest assertion above caught it on the first live run; this case
        # holds the mechanism, so the next reader is not left guessing why the
        # read is base64.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        restores = [line for line in self.asked(fake) if "base64 -d" in line]
        self.assertEqual(len(restores), 1, f"the restore ran {len(restores)} times: {restores}")
        self.assertNotIn("MOSDNS_PIN_EOF", restores[0])
        # And the bytes the scenario writes back are the repository's own file,
        # base64-encoded, so a case reading `restores[0]` can decode it and
        # compare -- which is the round trip this case is about.
        quoted = re.search(r"printf '%s' '([A-Za-z0-9+/=]+)'", restores[0])
        self.assertIsNotNone(quoted, f"the restore is not a base64 write: {restores[0]!r}")
        self.assertEqual(base64.b64decode(quoted.group(1)), SHIPPED_PIN_BYTES)


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
            "CLAIM_PIN_CHECKED_BY_POSTINST", "CLAIM_PIN_NEVER_REPINNED",
            "CLAIM_RESOLVER_BARRIER", "CLAIM_ROLLED_BACK",
            "CLAIM_POSTINST_SAW_REFUSAL", "CLAIM_NOTHING_ENABLED",
            "CDN_BARRIER_SIGNATURES", "OFFLINE_CONFIGURED_REQUIREMENT",
            "REFUSING_STATES", "CONFIGURED_STATES",
        ):
            self.assertIn(name, constants, f"{name} is asserted but not named at module scope")

    def test_the_docstring_says_what_the_scenario_asserts_and_not_what_it_cannot(self):
        # **The false claim the review found, held shut.** The first version's
        # docstring said "It also does not claim the whole transaction is
        # reachable with no route" while the file required `package_configured`
        # and reported "the install transaction completed" -- so the file a
        # future implementer reads told them the opposite of what it did, in the
        # one document nobody skips.
        #
        # The requirement it cannot close is now IN the docstring, verbatim,
        # because the docstring is where a reader looks for it, and the claims
        # that were false are gone rather than softened.
        source = self.source()
        # Flattened, because postinst and the installer both write one sentence
        # across several lines and the requirement in the docstring is written
        # as the plan wrote it.
        flat = " ".join(source.split())
        self.assertIn(install.OFFLINE_CONFIGURED_REQUIREMENT, flat)
        for gone in (
            "1. **The transaction completes.**",
            "2. **It completed because the shipped snapshot exists, not by luck.**",
            "It also does not claim the whole transaction is reachable with no route",
            "the property that **the install completes at all**",
        ):
            self.assertNotIn(gone, flat, f"install_test.py still says {gone!r}")
        # And it names the step that closes the requirement, so a reader of the
        # plan and a reader of this file are pointed at the same place.
        self.assertIn("Task 4 Step 5 reads this", source)

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

    def test_the_scenario_asserts_the_range_step_is_not_what_refused(self):
        # A later edit that dropped the two absent-signature checks would look
        # like tidying: the scenario would still require the resolver's barrier,
        # and the cell this step was written to end -- the one whose refusal
        # names the origin -- would be reported as the barrier with the
        # requirement skipped over it.
        source = self.source()
        self.assertIn("CDN_BARRIER_SIGNATURES", source)
        self.assertIn("barrier_is_the_foreign_resolver", source)
        self.assertIn(
            "for signature in CDN_BARRIER_SIGNATURES:", source,
            "the range refusals are no longer required to be ABSENT from the transaction's output, "
            "which is the only thing that can see a cell carrying both refusals",
        )
        self.assertIn("signature not in flat", source)
        self.assertEqual(
            install.CDN_BARRIER_SIGNATURES,
            ("cannot stand in for it", "cannot account for"),
            "the two signatures changed; `Cannot stand in for it` is `standInFor`'s own wording and "
            "`cannot account for` is postinst's, and a case that depends on them has to say so",
        )

    def test_the_scenario_does_not_assert_a_configured_package(self):
        # The single assertion that made this scenario unable to go green in any
        # cell, and it is the one the review found. Held here so that dropping it
        # -- which would look like a simplification -- is a visible change.
        source = self.source()
        self.assertIn(
            "not document[\"package_configured\"]", source,
            "the scenario requires a CONFIGURED package again, which no routeless cell can produce",
        )
        self.assertIn("REFUSING_STATES", source)


if __name__ == "__main__":
    unittest.main()
