"""The install scenario's assertions: the transaction COMPLETING, and the refusals.

**This file was rewritten, and the direction of the rewrite is the upgrade.** It
was written for a cell where the transaction refused at the resolver's own barrier
and recorded the requirement it could not close as a **required skip**, so the cell
was `incomplete` and the run exit 3 -- honest then, and gone now. Task 4 Step 5's
test-only foreign override makes a foreign answer reachable, the transaction
completes, and the scenario's requiring assertions are **replaced** rather than
made optional. The requirement the plan's words spell out is now asserted.

**Replaced, not relaxed**, and that is the whole of what is hard to do here. The
four requiring assertions about the resolver's barrier and the two about the
range refusals being absent are GONE, and what replaces them is evidence of the
other disposition: the loopback hand-over, the ownership marker written, all four
timers enabled, and the shipped documents byte-identical between the artifact and
the repository. A scenario that accepted both dispositions would prove nothing
about either, so there is no "either is fine" here and the cases below say so.

**The cell**, which is four facts rather than one: dpkg recorded the configured
state, the transaction's own words name the loopback hand-over, the published
range document's digest equals the snapshot the package ships, and the resolver
document in the ARTIFACT is byte-identical to the repository's own. The last two
are what make the rest mean anything -- a cell whose bridge NATs outward would
publish from the origin and hold a different document, and a cell whose artifact
had been modified would be measuring a package this repository does not build.

**The override**, which is where the transaction's completion comes from and which
is read the way a cell reads it: the stamp out of the mock's own counters
document, the shipped document out of the read-only source mount, and the
"test-only" claim out of three digests rather than a promise.

**The refusals**, which a happy-path-only scenario leaves entirely unverified and
which are what has been protecting every machine so far. A cell whose bridge
reaches the origin is refused rather than passed; a cell where the *range* step is
what refused is refused; a shipped snapshot whose bytes its lock does not record
has to stop the install *before the transaction runs* and publish nothing; a cell
whose override is NOT what made it work is refused; and each of those refusals has
to leave the cell as it was found, so one cell's failed case cannot be the next
cell's starting state.

And the case that is the reason the rewrite is checked at all:
`test_a_cell_where_the_transaction_completed_is_not_refused` was **inverted** -- it
used to assert that a configured cell is refused, and it now asserts that the
configured cell is accepted. Its mirror, `test_a_refused_transaction_that_the_
override_could_not_reach_is_refused`, runs the real measured refusal, so a
scenario that accepted both would fail one of the two.

**The fakes**, which have to be able to disagree with the code. The route probe's
answer is produced by running the scenario's own probe program with a real
`OSError` substituted; the mock foreign resolver's stamp is produced by building
a DNSCrypt stamp in the layout go-dnsstamps writes, and then decoded back through
the override module's own reader; the override's own text and its three digests
are produced by running the override module's own builder over the repository's
own document. Every one of them could be a hard-coded string, and each would then
be a value that agreed with the code by construction -- which is this project's
most repeated defect, and it had reached a podman fixture three times.
"""

import ast
import base64
import errno
import hashlib
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
# The scenarios directory as well, and **this file is the reason it has to be
# here rather than somewhere else**: `install_test.py` opens with
# `import foreign_override`, and without this line that import is resolved by
# whichever other case file happened to be imported first and put the directory
# on the path. `test_foreign_override.py` and `test_install_routing_scenario.py`
# each do this for themselves for the same reason, and a file that only works
# because a sibling fixed the path for it is a file whose import error is
# somebody else's defect to diagnose.
sys.path.insert(0, str(SCENARIOS))

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
# The mock foreign listener, which is where the test-only override points the
# resolver's stamps. Its name is composed from the same run id and version as the
# others, so a case cannot be reading a different cell's resolver.
FOREIGN = f"mosdns-{RUN_ID}-mock-foreign-{VERSION}"
# The client, which this scenario never execs. It is named here because the case
# that holds every `exec` to the containers this run built has to know the whole
# set, and a set that listed only the containers this scenario uses would pass for
# a command into a container nobody built.
CLIENT = f"mosdns-{RUN_ID}-client-{VERSION}"


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

# The override module, imported BY ITS OWN NAME rather than through the loader
# above. `install_test.py` does `import foreign_override`, so this has to be the
# same module object the scenario holds: two copies would mean two
# `OverrideError` classes, and a case that raised one of them would be raising a
# type the scenario's own handler does not catch -- which is a case that could
# not fail for the reason it exists to check.
import foreign_override  # noqa: E402
from podman import PodmanError  # noqa: E402

# The repository's own pinned snapshot, read rather than written down. The
# comment this block used to carry said "read rather than written here" above a
# hard-coded digest, which is the one kind of lie this file exists to keep out of
# a podman fixture: a re-pinned package would have failed every case in it for a
# reason that had nothing to do with the scenario, and the digest would have been
# a remembered string rather than the file's.
#
# The property under test is that the PUBLISHED document equals the SHIPPED one,
# and the two are given the same value below, which is what makes that comparison
# a measurement rather than a tautology.
SHIPPED_PIN_PATH = install.SHIPPED_PIN
SHIPPED_PIN_BYTES = (REPO / "configs" / "cloudflare-ranges.json").read_bytes()
SHIPPED_PIN_SHA = hashlib.sha256(SHIPPED_PIN_BYTES).hexdigest()
PUBLISHED_PIN_SHA = SHIPPED_PIN_SHA
# What the origin would have published instead, so a cell that reached it is
# distinguishable from one that did not.
ORIGIN_DOCUMENT_SHA = "f3d0a35768afd4a9a8307aa1033d50b9fa011b73836c9235c170aa31acac5efd"
# The shipped snapshot with one byte changed -- the state the refusal case creates
# with a single `sed`. It is a real, different digest and NOT a placeholder: the
# scenario's assertion that the corruption applied is a comparison between this
# and the shipped one, and a fixture that answered the same value for both would
# make that assertion a statement about the fixture.
CORRUPTED_PIN_SHA = "9b810d862ba07c383cc0b8f9f7f1f2ca8f74a02f849d818c4c4d37cc21a7dfa6"
PREFIX_LIST = "103.21.244.0/22\n104.16.0.0/13\n198.41.128.0/17\n"
# The digest of that list, which is a *different* value from the range
# document's: the two are answers to two different `sha256sum` commands, and the
# previous table answered the prefix list's digest with the range document's,
# which is not a wrong fact anybody could have noticed and is exactly the kind of
# fixture answer that makes a case read as coverage it does not have.
PREFIX_LIST_SHA = hashlib.sha256(PREFIX_LIST.encode("utf-8")).hexdigest()

# `dpkg -i`, run once through `sh -c` with the status in the same output, which is
# how the watchdog scenario's own table is written and why: two invocations of
# `dpkg -i` run the transaction twice, and every recorded state then describes
# the second run.
#
# **`printf 'N\n' |` in front, and that is the operator's answer rather than a
# convenience.** `/etc/mosdns/dnscrypt-proxy.toml` is a conffile this project
# ships on purpose, dpkg asks what to do when the file already exists and the
# package carries a different one, and `N` is "keep the machine's" -- which is
# what makes the override the transaction ran with. A table that spelled the
# command without it would answer a command the scenario does not run, and every
# case in this file would then be reading an empty string.
DPKG_INSTALL = (
    "printf 'N\\n' | dpkg -i /tmp/mosdns-router.deb 2>&1; printf 'DPKG_EXIT=%s\\n' \"$?\""
)
DPKG_STATE_QUERY = "dpkg-query -W -f='${db:Status-Status}\\n' mosdns-router 2>&1 || true"
DPKG_STATUS_QUERY = "dpkg-query -W -f='${Status}\\n' mosdns-router 2>&1 || true"

# dpkg's own output for the cell this scenario is written for: a routeless cell
# in which the transaction got past the range publication and refused at the
# resolver's own start-up barrier. **Verbatim from a 24.04 cell built from this
# tree** (measured twice, and the run was `incomplete`, exit 3, with the required
# skip hoisted onto the version), so every claim the scenario asserts is a
# sentence a real cell printed. It is no longer the happy path; it is the mirror
# `test_a_refused_transaction_that_the_override_could_not_reach_is_refused` runs.
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
#     timers were recorded rather than asserted enabled, back when this was the
#     cell the scenario was written for.
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

# A cell where the RANGE step is what refused, which is the state Task 4 Step 1
# was written to end and the one a scenario that only asserted "the transaction
# completed" could not tell from `COMPLETED_OUTPUT`. The two words are required
# to be ABSENT from the transaction's output, so this is the case that makes that
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
# refused at the ranges alone is caught by the required hand-over; a cell that
# refused at the resolver alone has no range wording in it. A cell carrying both
# means the range step failed *and* the transaction carried on far enough to hit
# the resolver's wait, and an evidence document that called that "the barrier"
# would be describing a run that published nothing and installed nothing.

# The cell this scenario is written for NOW: a routeless cell in which the
# test-only foreign override made a foreign answer reachable, so the transaction
# ran to the end. It is the happy path, and it was the first version of this
# file's fixture that a passing cell was *refused* for.
#
# The two sentences the transaction only prints on the committing path are the
# load-bearing pair, and their wording is `installer/mosdns_installer.py`'s:
#
#   * `install: 53 and 15353 are served on loopback and NetworkManager has been
#     pointed at 127.0.0.1; the ownership marker at ... has been written` -- the
#     hand-over, and the marker an uninstall reads.
#   * the absence of the installer's rollback, postinst's "refused this machine
#     and rolled back", and postinst's "Nothing is enabled and nothing was
#     started". A cell that printed the hand-over AND one of those would have
#     described two transactions, and the scenario refuses it.
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

# A cell that committed AND carried a range refusal with it. It is not a cell
# this suite can produce and it is not a cell any matrix produced -- it is here
# because it is the only state in which the ABSENT-signature checks are the only
# thing that can see it. A cell that committed and published from the pin
# published the snapshot; one that also carries the range refusal's wording is a
# cell whose evidence document would say it both got past the CDN step and did
# not, and only the absence check can tell those apart.
COMPLETED_WITH_A_RANGE_REFUSAL = COMPLETED_OUTPUT.replace(
    "Created symlink /etc/systemd/system/timers.target.wants/mosdns-cdn-optimizer.timer",
    "update-lists: https://api.cloudflare.com/client/v4/ips: server misbehaving\n"
    "install: the pinned snapshot this package ships cannot stand in for it either",
)

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

# What the restoring `dpkg --configure` says after the shipped snapshot has been put
# back: the same transaction on a machine this package already runs on, and postinst
# says so in its own words. It is a second piece of evidence for the pin rather than a
# tidy-up -- the whole snapshot was the only thing the refusal case broke.
PIN_RESTORE_OUTPUT = """\
mosdns-router postinst (configure) ...
note: mosdns-router.service is active and /var/lib/mosdns/installer/managed-by names this package, so this is a re-install of a machine this package already runs on
postinst: the pinned range document at /usr/share/mosdns-router/cloudflare-ranges.json is {shipped}, as
postinst: /usr/share/mosdns-router/cloudflare-ranges.lock.json records, taken at 2026-09-30T00:03:59Z. It is read
postinst: here and never written: 'mosdns-cdnctl update-lists --refresh-ranges' is what
postinst: publishes it, and it reads this machine's own published document first.
install: 53 and 15353 are served on loopback and NetworkManager has been pointed at 127.0.0.1; the ownership marker at /var/lib/mosdns/installer/managed-by has been written, so an uninstall will restore exactly what was changed
""".format(shipped=SHIPPED_PIN_SHA)

# What the scenario writes back after the corrupt-snapshot case. Base64, because
# the scenario reads the file that way: the wrapper's `.output` strips trailing
# whitespace, so a text read loses the final newline and the restore would not
# round-trip. **This constant is derived from the repository's own shipped
# snapshot**, so if the pin is ever re-pinned the fixture follows it and the
# restore case is testing a real round trip rather than a remembered string.
# (`SHIPPED_PIN_PATH` and `SHIPPED_PIN_BYTES` are read above, next to the digest
# they are the digest of, so one file is read once and the three facts about it
# cannot disagree.)
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


# The mock foreign resolver's own published facts, and the three resolver
# documents, all of them DERIVED rather than written down. This block is the file's
# own rule applied to the newest part of the scenario: the route probe's answer is
# produced by running the scenario's program, and the stamp the override carries is
# produced by building a stamp in the shape go-dnsstamps writes -- because a
# hard-coded one is a remembered string, and a remembered string is a fixture that
# agrees with the code by construction.
#
# The stamp is not cosmetic. `foreign_override.stamp_provider_name` decodes it, and
# `build_override` REFUSES a stamp naming any provider other than the mock's -- so a
# fixture that carried Quad9's would not fail a case, it would fail every case with
# a message about the wrong resolver, and the suite would read as though the
# override were broken.
def dnscrypt_stamp(address: str, public_key: bytes, provider: str, props: int = 0x03) -> str:
    """A DNSCrypt stamp in the layout go-dnsstamps writes, as a `sdns://` URL.

    `id(0x01) props(8, little-endian) addrLen addr pkLen pk nameLen name`, which is
    the layout `foreign_override.stamp_provider_name` reads back. `props` defaults
    to 3 -- DNSSEC and NoLog -- because `configs/dnscrypt-proxy.toml` says
    `require_dnssec = true` and `require_nolog = true`, and a certificate that did
    not declare them is a resolver this project's own configuration refuses.
    """
    blob = (
        b"\x01"
        + props.to_bytes(8, "little")
        + bytes((len(address),))
        + address.encode("ascii")
        + bytes((len(public_key),))
        + public_key
        + bytes((len(provider),))
        + provider.encode("ascii")
    )
    return "sdns://" + base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")


# The address the mock listens on, with dnscrypt-proxy's own port, and the provider
# name the certificate is published under. Both are the ones the override module
# requires, and the two are read out of it rather than typed so a change to either
# is a failing fixture rather than a cell that installs for the wrong reason.
FOREIGN_PROVIDER = foreign_override.PROVIDER_PREFIX + foreign_override.STATIC_NAME
FOREIGN_ADDRESS = "10.89.0.40:443"
MOCK_STAMP = dnscrypt_stamp(FOREIGN_ADDRESS, bytes(range(32)), FOREIGN_PROVIDER)
assert foreign_override.stamp_provider_name(MOCK_STAMP) == FOREIGN_PROVIDER, (
    "the fixture's stamp does not decode to the provider the override requires, so "
    "this file's answers are about a stamp no cell would ever publish"
)

# The mock's counters document, in the shape `mock-foreign`'s `document` struct
# writes -- read with `json.loads` by the scenario, never by a pattern.
FOREIGN_COUNTERS = json.dumps(
    {
        "stamp": MOCK_STAMP,
        "provider": FOREIGN_PROVIDER,
        "address": FOREIGN_ADDRESS,
        "total": 0,
        "certificate_fetches": 0,
        "plaintext_probes": 0,
        "dropped": 0,
        "queries": {},
    },
    indent=2,
)
# The same document AFTER the install, and it is a different one: the transaction's
# barrier asked the packaged resolver for a real answer, so the mock counted a
# certificate fetch, a plaintext probe and one query. A fixture whose "after" answer
# repeated its "before" one would make the case below pass for a mock that was
# never asked anything, which is the shape of fixture this file has been wrong
# about three times.
FOREIGN_COUNTERS_AFTER_INSTALL = json.dumps(
    {
        "stamp": MOCK_STAMP,
        "provider": FOREIGN_PROVIDER,
        "address": FOREIGN_ADDRESS,
        "total": 1,
        "certificate_fetches": 1,
        "plaintext_probes": 1,
        "dropped": 0,
        "queries": {"install-probe.example": {"udp": 1, "tcp": 1}},
    },
    indent=2,
)
# The mock's own log, in the shape `main.go` writes it: one line per answer, naming
# the name and the transport.
FOREIGN_LOG = (
    "mosdns-mock-foreign: listening on 0.0.0.0:443, reachable at "
    f"{FOREIGN_ADDRESS}, provider {FOREIGN_PROVIDER}, stamp {MOCK_STAMP}\n"
    "mosdns-mock-foreign: answered 2.dnscrypt-cert.mosdns-mock-foreign over udp with "
    "198.51.100.7\n"
    "mosdns-mock-foreign: answered install-probe.example over udp with 198.51.100.7\n"
    "mosdns-mock-foreign: answered install-probe.example over tcp with 198.51.100.7\n"
)
# The packaged resolver's own account of itself, in `journalctl -b` form. A cell
# that fails at the barrier and does not carry this cannot tell a resolver that
# never started from one that started and could not reach anybody.
RESOLVER_JOURNAL = (
    "Jun 01 00:00:01 target systemd[1]: Started dnscrypt-proxy.service.\n"
    "Jun 01 00:00:01 target dnscrypt-proxy[412]: dnscrypt-proxy 2.1.18\n"
    "Jun 01 00:00:01 target dnscrypt-proxy[412]: [network] netprobe failed, continuing\n"
    "Jun 01 00:00:01 target dnscrypt-proxy[412]: [servers] [  0] 10.89.0.40:443\n"
    "Jun 01 00:00:01 target dnscrypt-proxy[412]: [servers] loading the certificate\n"
    "Jun 01 00:00:01 target dnscrypt-proxy[412]: listening on 127.0.0.1:15353\n"
)

# The three resolver documents, and their digests. The first two must be EQUAL --
# that is "the package was not modified to make this cell pass" -- and the third
# must differ from them, which is "the override actually reached the target". All
# three are computed from the repository's own file and the fixture's own stamp, by
# running the override module's own builder, so a case can compare the record's
# digests with a hash of the file the harness actually wrote.
SHIPPED_DNSCRYPT_TEXT = (
    REPO / "configs" / "dnscrypt-proxy.toml"
).read_text(encoding="utf-8")
SHIPPED_DNSCRYPT_SHA = hashlib.sha256(SHIPPED_DNSCRYPT_TEXT.encode("utf-8")).hexdigest()
# **The text as the TARGET sees it, which is not the text on disk.** The
# wrapper's `.output` is `stdout.strip()`, so a `cat` of the document arrives
# without its final newline -- and `build_override` reproduces a trailing newline
# only when the shipped text it was given had one. So the override the harness
# writes is the substitution *plus* one byte the read lost, which is why its
# digest is not the digest of the repository's file with the stamps replaced by
# hand. Nothing downstream cares: the comparison is over whole lines
# (`splitlines`), and dnscrypt-proxy's TOML parser does not require a final
# newline. Stated here because the digest is the load-bearing number and a
# reader comparing it by hand will get a different one.
SHIPPED_DNSCRYPT_AS_READ = SHIPPED_DNSCRYPT_TEXT.strip()
OVERRIDE_DNSCRYPT_TEXT = foreign_override.build_override(
    SHIPPED_DNSCRYPT_AS_READ, MOCK_STAMP, FOREIGN_ADDRESS
)
OVERRIDE_DNSCRYPT_SHA = hashlib.sha256(
    OVERRIDE_DNSCRYPT_TEXT.encode("utf-8")
).hexdigest()

# A shipped document with a listener and a selection and no `[static.*]` table at
# all. This project renders one, so no real cell produces it -- it is here because
# it is the input `build_override` names first in its refusal ("the shipped
# document declares no `[static.*]` table ... or the document this cell installed
# is not the one this repository renders"), and a refusal nothing exercises is a
# refusal nothing can be shown to be load-bearing.
NO_STATIC_TABLES_DOCUMENT = (
    "listen_addresses = ['127.0.0.1:15353']\n"
    "server_names = ['quad9-dnscrypt-ip4-filter-1']\n"
    "require_dnssec = true\n"
)

# Quad9's own stamp, READ OUT of the repository's document rather than typed --
# and checked to decode to Quad9's provider name, so this fixture cannot be a
# stamp that happens to fail the override's provider check for some other reason.
QUAD9_STAMP = next(
    match.group(2)
    for match in (foreign_override.STAMP_ASSIGNMENT.match(line) for line in
                  SHIPPED_DNSCRYPT_TEXT.splitlines())
    if match is not None
)
assert foreign_override.stamp_provider_name(QUAD9_STAMP) == "2.dnscrypt-cert.quad9.net", (
    f"the repository's first stamp does not decode to Quad9's provider name: {QUAD9_STAMP!r}"
)


def install_rules(**overrides):
    """The rule table for the cell this scenario is written for: a routeless cell
    in which the test-only foreign override made a foreign answer reachable and the
    transaction ran to the end.

    Every override replaces one answer, so each case changes exactly the fact it
    is about -- which is the property that makes a case here evidence rather
    than a re-run.
    """
    answers = {
        # The route table of a cell on a private bridge, and the route probe that
        # fails. The precondition of the whole scenario.
        "route": "10.89.0.0/24 dev eth0 proto kernel scope link src 10.89.0.190 metric 100",
        "reachable": probe_failed(),
        # The package, installed once: the transaction ran to the end, so dpkg's
        # word is the configured one and the exit is 0.
        "stat": "16205254",
        "install": COMPLETED_OUTPUT,
        "state": "installed",
        "status": "install ok installed",
        # The two digests the property rests on.
        "shipped": SHIPPED_PIN_SHA,
        "published": PUBLISHED_PIN_SHA,
        # The same file with one byte changed by the refusal case, so the scenario's
        # "did my corruption apply?" assertion is a comparison between two real
        # digests rather than between one digest and itself.
        "corrupt_pin": CORRUPTED_PIN_SHA,
        "prefix_list_sha": PREFIX_LIST_SHA,
        "prefixes": PREFIX_LIST,
        # The lock's own digest. Recorded separately from `shipped` rather than
        # written inline: the first version of this table carried an accidental
        # `answers['corrupt'] and SHIPPED_PIN_SHA` here, which evaluated to the
        # right value for the wrong reason and would have read a boolean to
        # anybody who changed the `corrupt` answer.
        "lock": SHIPPED_PIN_SHA,
        # The record the transaction wrote before its first mutation, and the
        # marker it wrote because it committed. Both are `0` -- the `test -e`
        # exit status, so zero is PRESENT. A transaction that rolled itself back
        # leaves the backup behind too, so the backup alone says nothing; the
        # marker is the half that is only there on the committing path.
        "backup": 0,
        "marker": 0,
        "refresh": REFRESH_FROM_PIN,
        "check": CHECK_REPORT,
        # The four timers: postinst enables them only after the transaction
        # succeeds, so "enabled" is a fourth piece of evidence for the other
        # disposition rather than tidying.
        "timer": "enabled",
        # The mock foreign resolver, and the three resolver documents. The stamp
        # and the address travel together out of the mock's own counters document
        # because the mock generates the stamp per start and the address is what
        # that stamp names.
        "foreign_counters": FOREIGN_COUNTERS,
        # The same document after the install, and the mock's log. A live mock
        # counted the certificate fetch and the queries by then, so the answer
        # says so rather than repeating an empty one: a fixture whose "after"
        # answer is identical to its "before" answer cannot tell a mock that was
        # asked from one that was not.
        "foreign_counters_after_install": FOREIGN_COUNTERS_AFTER_INSTALL,
        "foreign_log": FOREIGN_LOG,
        "resolver_journal": RESOLVER_JOURNAL,
        "shipped_document": SHIPPED_DNSCRYPT_TEXT,
        "shipped_dnscrypt": SHIPPED_DNSCRYPT_SHA,
        "override_dnscrypt": OVERRIDE_DNSCRYPT_SHA,
        # The artifact's own copy, which has to be the repository's own bytes.
        "artifact_dnscrypt": SHIPPED_DNSCRYPT_SHA,
        # The refusal case, and the state it leaves behind.
        "corrupt": CORRUPT_OUTPUT,
        "pin_restore": PIN_RESTORE_OUTPUT,
        # The state the refusal leaves (`half-configured`: dpkg's own word on 24.04
        # and 26.04) and the state the restore puts it back to, which is the
        # configured one again -- and the pair is what says the shipped snapshot was
        # the only thing the refusal case broke.
        "corrupt_state": "half-configured",
        "restored_state": "installed",
        "corrupt_present": 1,
        "corrupt_restored": 0,
        # What the machine looks like after a transaction that committed: both
        # daemons running, and the two loopback listeners the hand-over is about.
        "active": "active",
        "listeners": (
            "tcp   LISTEN 0 4096 127.0.0.1:53 0.0.0.0:*\n"
            "tcp   LISTEN 0 4096 127.0.0.1:15353 0.0.0.0:*\n"
            "udp   UNCONN 0 4096 127.0.0.1:53 0.0.0.0:*\n"
            "udp   UNCONN 0 4096 127.0.0.1:15353 0.0.0.0:*\n"
        ),
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
        # The shipped snapshot's digest is read THREE times and the three are
        # different: as the package ships it, as the refusal case corrupts it, and
        # after the restore puts it back. A single answer here is what made the
        # first live run of this case fail for a reason that had nothing to do with
        # the case -- the scenario asserted "the corruption applied" and the fake
        # answered with the same digest three times, so the assertion could only
        # ever be about the fake.
        {"match": ["sha256sum", "/usr/share/mosdns-router/cloudflare-ranges.json"],
         "answers": [
             {"stdout": f"{answers['shipped']}  /usr/share/mosdns-router/cloudflare-ranges.json\n"},
             {"stdout": f"{answers['corrupt_pin']}  /usr/share/mosdns-router/cloudflare-ranges.json\n"},
             {"stdout": f"{answers['shipped']}  /usr/share/mosdns-router/cloudflare-ranges.json\n"},
         ]},
        {"match": ["sha256sum", "/usr/share/mosdns-router/cloudflare-ranges.lock.json"],
         "stdout": f"{answers['lock']}  /usr/share/mosdns-router/cloudflare-ranges.lock.json\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/cloudflare-ips.json"],
         "stdout": f"{answers['published']}  /var/lib/mosdns/lists/cloudflare-ips.json\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/cloudflare-prefixes.txt"],
         "stdout": f"{answers['prefix_list_sha']}  /var/lib/mosdns/lists/cloudflare-prefixes.txt\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/cn-domains.txt"],
         "stdout": "a865b7cb15f56edd73e8b2df37f22d0d1fe9ee0f4991c090a62ca11e495dfa9f  /var/lib/mosdns/lists/cn-domains.txt\n"},
        {"match": ["sha256sum", "/var/lib/mosdns/lists/source-lock.json"],
         "stdout": "9c1a1d0dd0eea0f4d2b1c2e5c9a0e1d4b3f2a1c0d9e8f7a6b5c4d3e2f1a0b9c8  /var/lib/mosdns/lists/source-lock.json\n"},
        # -- the override, and the three documents it is measured against ----
        # The mock's counters, read out of the MOCK's own container rather than
        # the target's, and the case below changes this answer and needs the
        # target's own reads to stay as they are.
        {"match": ["exec", FOREIGN, "cat", foreign_override.COUNTERS_PATH],
         "answers": [
             {"stdout": answers["foreign_counters"]},
             {"stdout": answers["foreign_counters_after_install"]},
         ]},
        # The mock's own log, which is read on both sides of the install. `logs`
        # is a top-level subcommand rather than an `exec`, so the rule matches the
        # container name as a token.
        {"match": ["logs", FOREIGN], "stdout": answers["foreign_log"]},
        # **The packaged resolver's own account of itself**, read once, after the
        # install. A cell that fails at the resolver's barrier and does not carry
        # this is a cell whose only account of the failure is the sentence that
        # describes the symptom -- and MEASURED twice, that is all there was.
        {"match": ["sh", "-c"], "match_contains": "journalctl -u dnscrypt-proxy.service",
         "stdout": answers["resolver_journal"]},
        # The shipped document, as the target sees it through the read-only source
        # mount. The repository's own file, so the substitution the scenario
        # performs is a real one and `changed_lines` in the record is a real
        # diff. A case can replace it to hand the override something it cannot
        # substitute into.
        {"match": ["cat", foreign_override.SHIPPED_SOURCE], "stdout": answers["shipped_document"]},
        {"match": ["sha256sum", foreign_override.SHIPPED_SOURCE],
         "stdout": f"{answers['shipped_dnscrypt']}  {foreign_override.SHIPPED_SOURCE}\n"},
        # The file the target is RUNNING, which is the override. It has to differ
        # from the shipped one, and a case changes this answer to make it not.
        {"match": ["sha256sum", foreign_override.DNSCRYPT_CONFIG],
         "stdout": f"{answers['override_dnscrypt']}  {foreign_override.DNSCRYPT_CONFIG}\n"},
        # The `chmod` the scenario runs after the `cp`, and the read-back out of
        # the artifact. Both are `sh -c`, so both are matched on the one line that
        # distinguishes them from every other script the scenario runs.
        {"match": ["sh", "-c"], "match_contains": f"chmod 0644 {foreign_override.DNSCRYPT_CONFIG}",
         "returncode": 0},
        {"match": ["sh", "-c"], "match_contains": "dpkg-deb --fsys-tarfile", "returncode": 0},
        {"match": ["sha256sum", install.ARTIFACT_DNSCrypt_TMP],
         "stdout": f"{answers['artifact_dnscrypt']}  {install.ARTIFACT_DNSCrypt_TMP}\n"},
        {"match": ["test", "-e", "/var/lib/mosdns/installer/network-manager-backup.json"],
         "returncode": answers["backup"]},
        {"match": ["test", "-e", "/var/lib/mosdns/installer/managed-by"], "returncode": answers["marker"]},
        # The refresh is asked ONCE to publish, and once more to put back what the
        # refusal case removed -- and the two are told apart by the command, not
        # by the answer. The FIRST one has the published documents REMOVED first,
        # so the machine's own cannot stand in; the second is the restore and asks
        # for no report. The first version of this table answered BOTH
        # invocations with the pin's report, which is how twenty cases were
        # asserting the answer the fake was written with rather than the one a
        # real cell produces. MEASURED, 24.04: a second `--refresh-ranges` on a
        # machine that already published says `ranges-source: cache`.
        {"match": ["sh", "-c"], "match_contains": "update-lists --refresh-ranges",
         "answers": [
             {"stdout": answers["refresh"] + "REFRESH_EXIT=0\n"},
             {"stdout": answers["refresh"] + "RESTORE_EXIT=0\n"},
         ]},
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
        # The refusal case. **Four commands and two state reads, in this order** --
        # `dpkg --unpack` (which runs no maint script), the override written again
        # (unpacking a package puts its own conffiles back), the corruption, and
        # `dpkg --configure` (which runs postinst). The refusal's own output is read
        # with a second invocation of the same script, and the state is read before
        # and after it.
        #
        # The two `sha256sum` answers for the override are also a SEQUENCE: the
        # unpack puts the package's conffile back, so the digest right after the
        # first `cp` and the digest after the second are what tells the scenario
        # whether the override survived.
        {"match": ["sh", "-c"], "match_contains": "dpkg --unpack /tmp/mosdns-router.deb",
         "returncode": 0, "stdout": "Unpacking mosdns-router (0.1.0) over (0.1.0) ...\n"},
        {"match": ["sh", "-c"], "match_contains": "dpkg --configure mosdns-router 2>&1; printf 'PROBE_EXIT",
         "answers": [
             {"stdout": answers["corrupt"] + "PROBE_EXIT=1\n"},
             {"stdout": answers["corrupt"] + "PROBE_EXIT=1\n"},
         ]},
        # The restore's own `dpkg --configure`, which is a SEQUENCE of its own.
        {"match": ["sh", "-c"], "match_contains": "dpkg --configure mosdns-router 2>&1; printf 'RESTORE_EXIT",
         "answers": [
             {"stdout": answers["pin_restore"] + "RESTORE_EXIT=0\n"},
             {"stdout": answers["pin_restore"] + "RESTORE_EXIT=0\n"},
         ]},
        # And the state the refusal leaves, and the state the restore puts it back
        # to -- three reads, three answers: after `dpkg -i`, after the refused
        # `dpkg --configure`, and after the restoring one. The third says the shipped
        # snapshot was the only thing the refusal case broke, and it is what the
        # next scenario in this cell is measured on.
        {"match": ["sh", "-c", DPKG_STATE_QUERY],
         "answers": [
             {"stdout": answers["state"] + "\n"},
             {"stdout": answers["corrupt_state"] + "\n"},
             {"stdout": answers["restored_state"] + "\n"},
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
        # The two daemons the transaction owns, both active because it committed.
        # Recorded rather than asserted -- the scenario's claims about the two
        # units are the loopback hand-over and the enabled timers, and those are
        # things the transaction said about itself; a unit's `ActiveState` read
        # afterwards is evidence about the system rather than about the package.
        {"match": ["systemctl", "show", "--property=ActiveState", "--value",
                   "dnscrypt-proxy.service"], "stdout": answers["active"] + "\n"},
        {"match": ["systemctl", "show", "--property=ActiveState", "--value",
                   "mosdns-router.service"], "stdout": answers["active"] + "\n"},
        # And the loopback listeners, which the transaction's own hand-over is
        # about. Recorded, not asserted: the scenario's claim is that the
        # transaction said it served them, and `ss` output is a reading of the
        # machine rather than of the package.
        {"match": ["sh", "-c"], "match_contains": "ss -lntup", "stdout": answers["listeners"]},
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
            foreign=FOREIGN,
            network=f"mosdns-{RUN_ID}-testnet",
            override_path=self.directory / "foreign-override.toml",
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

    def asked(self, fake, container=TARGET):
        return [
            " ".join(argv[2:])
            for argv in fake.invocations()
            if argv[:2] == ["exec", container]
        ]

    def override_on_disk(self):
        """The file the harness actually built and copied in, read back.

        The record's `override_sha256` is the fake's answer, and a fake's answer
        is only evidence if it is the right answer. So the file the scenario wrote
        is read here and hashed, which is what makes the recorded digest a
        measurement of what the harness did rather than a constant this file
        agreed with.
        """
        path = self.directory / "foreign-override.toml"
        return hashlib.sha256(path.read_bytes()).hexdigest(), path.read_text(encoding="utf-8")


class ScenarioPassesTest(InstallScenarioHarness):
    """The cell this scenario is written for, and what it records when it passes.

    **A passing install scenario is now a cell that reached `install ok
    configured` with no route to the internet at all**, which is the requirement
    Task 4 Step 1 reassigned to Step 5. The cases below cover the four things it
    rests on -- dpkg's own record, the transaction's own words about the
    hand-over and the marker, the override that made a foreign answer reachable,
    and the three digests that say the override is test-only -- and the shape
    cases in `ScenarioShapeTest` hold the docstring to the same set.
    """

    def test_the_scenario_passes_with_no_route_to_the_internet(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(result.log, f"logs/{VERSION}-install.json")

    def test_the_record_carries_the_facts_the_claim_rests_on(self):
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        # One: dpkg's own record, and it is the CONFIGURED state -- the thing the
        # previous version of this scenario required the ABSENCE of. Both
        # spellings, because a scenario that read only one could be satisfied by
        # a package dpkg left unpacked. The two words dpkg uses are both
        # accepted, and which one appeared is recorded rather than assumed.
        self.assertEqual(record["package_state"], "installed")
        self.assertEqual(record["package_status_phrase"], "install ok installed")
        self.assertTrue(record["package_configured"])
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

    def test_the_record_says_the_transaction_committed_and_not_that_it_refused(self):
        # **The replacement, and it is a replacement in both directions.** The
        # previous version required the resolver's barrier, the installer's
        # rollback, postinst's own account of it and postinst saying nothing was
        # enabled. A committed transaction prints none of the four, so requiring
        # them refused the very cell this step was written to produce -- and
        # making them optional would accept both dispositions, which is a
        # scenario that proves nothing about either. So they are now checked for
        # ABSENCE, and that absence is what says which world the cell was in.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        flat = install.flatten_output(self.record(result)["dpkg_output"])
        for gone, what in (
            (install.CLAIM_RESOLVER_BARRIER, "the resolver's start-up barrier"),
            (install.CLAIM_ROLLED_BACK, "the installer's rollback"),
            (install.CLAIM_POSTINST_SAW_REFUSAL, "postinst's own account of the rollback"),
            (install.CLAIM_NOTHING_ENABLED, "postinst saying nothing was enabled"),
        ):
            self.assertNotIn(gone, flat, f"a cell that handed the loopback over also printed {what}")
        for signature in install.CDN_BARRIER_SIGNATURES:
            self.assertNotIn(signature, flat)
        self.assertTrue(self.record(result)["transaction_completed"])
        self.assertTrue(self.record(result)["published_from_the_pin"])

    def test_the_record_says_the_machines_dns_was_recorded_and_taken_over(self):
        # Two facts that are the commit, read as a pair. The backup is written
        # before the transaction's first mutation, so a REFUSED transaction leaves
        # one too; the marker is written only on commit, so its PRESENCE is what
        # says the machine's DNS was really handed over. A marker left behind by a
        # refused transaction would point a later uninstall at DNS the rollback
        # undid, which is the case in `TheRefusalsTest`.
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertTrue(record["backup_present"])
        self.assertTrue(record["marker_present"])

    def test_the_requirement_is_asserted_and_the_scenario_records_no_skip(self):
        # The requirement in the plan's own words, asserted rather than recorded
        # as a required skip. `ScenarioResult.skips` is empty, which is the whole
        # of the upgrade as far as a reader of the report is concerned: a cell
        # that carries a required skip is `incomplete` and the run is exit 3, and
        # this cell carries none.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        self.assertEqual(list(result.skips), [])
        self.assertIn("install ok configured", install.OFFLINE_CONFIGURED_REQUIREMENT)

    def test_the_evidence_document_carries_no_unclosed_requirement(self):
        # The evidence document is the one file a reader has, so a requirement
        # that were still open would have to be in it as well as in the result.
        # The key is gone rather than empty, because an empty list reads as "the
        # scenario considered the question and found nothing" -- and this
        # scenario does not consider it at all; it asserts it.
        _fake, result = self.run_scenario()
        self.assertNotIn("unclosed_requirements", self.record(result))

    def test_the_scenario_detail_says_the_transaction_completed(self):
        # The one line an operator reads on the terminal. It has to name the
        # state dpkg recorded, say the transaction finished, and say WHICH step
        # closed the requirement -- and it has to stop saying it is recorded as a
        # skip, which was the honest sentence then and is a false one now.
        _fake, result = self.run_scenario()
        self.assertIn("install ok installed", result.detail)
        self.assertIn("transaction COMPLETED", result.detail)
        self.assertIn("the loopback was handed to NetworkManager", result.detail)
        self.assertIn("all four timers are enabled", result.detail)
        self.assertIn(install.OFFLINE_CONFIGURED_REQUIREMENT, result.detail)
        for gone in ("recorded as a required skip", "incomplete rather than passed",
                     "127.0.0.1:15353"):
            self.assertNotIn(gone, result.detail)

    def test_the_record_carries_the_override_and_the_lines_it_changed(self):
        # **The stamp and the address travel out of the mock's own counters
        # document, and the changed lines are in the evidence** so a reader can
        # check "only the stamps moved" rather than take it. The digests are the
        # repository's own, computed by this file from the same bytes the
        # substitution ran on, and the changed-lines list has to be exactly the
        # substitution: the three tables, the selection and the three stamps --
        # eight lines, and nothing else.
        _fake, result = self.run_scenario()
        record = self.record(result)
        override = record["foreign_override"]
        self.assertEqual(override["path"], foreign_override.DNSCRYPT_CONFIG)
        self.assertEqual(override["stamp"], MOCK_STAMP)
        self.assertEqual(override["address"], FOREIGN_ADDRESS)
        self.assertEqual(override["shipped_from"], foreign_override.SHIPPED_SOURCE)
        self.assertEqual(override["shipped_sha256"], SHIPPED_DNSCRYPT_SHA)
        self.assertTrue(override["only_stamps_changed"])
        # The selection and the definitions agree, which is what makes the
        # document one dnscrypt-proxy will actually use -- **and the three tables
        # have names of their own**, because TOML refuses a table defined twice and
        # the first version of the override named all three the same. MEASURED on
        # 24.04: `dnscrypt-proxy` exited 255 with `Key
        # 'static.mosdns-mock-foreign' has already been defined`, eleven restarts in
        # sixty seconds, and a cell reporting the transaction's foreign-resolver
        # barrier.
        names = [foreign_override.static_name(n) for n in (1, 2, 3)]
        self.assertEqual(override["selected_names"], names)
        self.assertEqual(override["static_names"], names)
        changed = override["changed_lines"]
        self.assertEqual(len(changed), 7, f"the substitution changed {changed}")
        self.assertEqual(
            [int(line.split(":", 1)[0]) for line in changed],
            [18, 74, 75, 77, 78, 80, 81],
            "the changed lines are not the seven lines of the shipped document this "
            "substitution is defined as: the selection, three table headers and three stamps",
        )
        # And each change's NEW half, checked against the override's own rules
        # rather than against a transcription: every one of them is a line the
        # substitution is allowed to write, and the new half names the mock.
        halves = [line.partition(" -> ")[2] for line in changed]
        for half in halves:
            self.assertTrue(
                foreign_override.is_substitutable(half),
                f"{half!r} is not a line this override is allowed to write",
            )
        self.assertEqual(
            halves[0],
            "server_names = [" + ", ".join(f"'{name}'" for name in names) + "]",
        )
        self.assertEqual(
            halves[1::2], [f"[static.{name}]" for name in names],
            "the three table headers are not the mock's, or two of them are the same name",
        )
        self.assertEqual(
            halves[2::2], [f"stamp = '{MOCK_STAMP}'"] * 3,
            "the three stamps are not the mock's",
        )

    def test_the_digest_the_record_carries_is_the_digest_of_the_file_it_wrote(self):
        # **The fake's answer, measured rather than trusted.** Everything above
        # says the override reached the target on the strength of a digest the
        # rule table supplied, and a fixture that supplies a digest is a fixture
        # that agrees with itself. So the file the harness actually built is read
        # back and hashed here, and the two have to be equal.
        _fake, result = self.run_scenario()
        record = self.record(result)
        on_disk, text = self.override_on_disk()
        self.assertEqual(record["foreign_override"]["override_sha256"], on_disk)
        self.assertEqual(on_disk, OVERRIDE_DNSCRYPT_SHA)
        self.assertNotEqual(on_disk, SHIPPED_DNSCRYPT_SHA)
        # And the listener line is byte-identical, so the transaction's barrier
        # was still the real one: 15353 on loopback, served by this project's own
        # document.
        self.assertIn(
            f"listen_addresses = ['{foreign_override.SHIPPED_LISTENER}']", text
        )
        self.assertIn("require_dnssec = true", text)
        self.assertIn("require_nolog = true", text)
        self.assertIn("netprobe_timeout = 5", text)

    def test_the_shipped_documents_are_unchanged_and_the_override_is_test_only(self):
        # Three digests, and the third is what the word "test-only" means: the
        # artifact the install ran against and the repository's own document are
        # the same bytes, and the file the target is running is not.
        _fake, result = self.run_scenario()
        record = self.record(result)
        self.assertTrue(record["shipped_documents_unchanged"])
        self.assertEqual(record["artifact_dnscrypt_sha256"], SHIPPED_DNSCRYPT_SHA)
        self.assertEqual(
            record["artifact_dnscrypt_sha256"], record["foreign_override"]["shipped_sha256"]
        )

    def test_the_stamp_was_read_out_of_the_mocks_own_container(self):
        # The stamp is generated per start and published by the mock, so a
        # scenario that read it from anywhere else would be writing down a
        # remembered value -- and a remembered value is a stamp no cell would
        # ever serve a certificate for. The commands are read out of the fake's log
        # rather than trusted, because a source-level check cannot tell the mock
        # container from the target.
        #
        # **Twice, and that is the point**: once to learn the stamp and once after
        # the install to carry the exchange's evidence. Both out of the MOCK's
        # container, and both this one path.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        reads = self.asked(fake, FOREIGN)
        self.assertEqual(
            reads,
            [f"cat {foreign_override.COUNTERS_PATH}"] * 2,
            f"the mock's counters were read as {reads!r}",
        )
        logs = [
            argv for argv in fake.invocations()
            if argv[:2] == ["logs", FOREIGN]
        ]
        self.assertEqual(
            len(logs), 2,
            f"the mock's own log was read {len(logs)} times -- once when its stamp was read and "
            f"once after the install -- and it is the half of the exchange a report has no other "
            f"way to see: {logs!r}",
        )

    def test_a_refusal_carries_the_resolvers_own_account_of_itself(self):
        # **The refusal a reader gets is the difference between "the barrier
        # refused" and "the barrier refused and here is why".**
        #
        # The first version's refusal quoted dpkg's output and the override, and
        # nothing at all about either end of the exchange: not the packaged
        # resolver's own log, and not the mock's counters. MEASURED, twice: the
        # mock published a stamp naming `0.0.0.0:443` -- which the client resolves
        # to itself -- and the cell reported `dnscrypt-proxy.service was started
        # but nothing answered a DNS query at 127.0.0.1:15353 within 60s` on all
        # three releases, with nothing in the report that could tell an address
        # nobody could dial from a resolver that never started. Two full matrix
        # runs were spent on it.
        #
        # So the evidence document carries both ends, read on the failing path and
        # read on the passing one, and the refusal quotes the resolver's own
        # account rather than the sentence that describes it.
        _fake, result = self.run_scenario(
            install=REFUSED_OUTPUT,
            state="half-configured",
            status="install ok half-configured",
            backup=0,
            marker=1,
            timer="disabled",
        )
        self.assertEqual(result.status, "failed")
        record = self.record(result)
        self.assertIn("dnscrypt-proxy", record["resolver_journal"])
        self.assertIn("10.89.0.40", record["foreign_counters_after_install"])
        self.assertIn("The resolver's own account of itself", result.detail)
        self.assertIn("dnscrypt-proxy", result.detail)

    def test_the_record_carries_both_ends_of_the_exchange(self):
        # The same two readings on a PASSING cell, because a cell that recorded
        # them only when it failed is a cell whose happy-path evidence says
        # nothing about the exchange it claims to have made -- and Task 4 Step 6's
        # counters are exactly this, read from the same document.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        for key in (
            "foreign_counters_at_start",
            "foreign_counters_after_install",
            "foreign_log_after_install",
            "resolver_journal",
        ):
            self.assertIn(key, record)
        self.assertIn(FOREIGN_PROVIDER, record["foreign_counters_at_start"])
        self.assertIn("mock-foreign", record["foreign_log_after_install"])

    def test_every_command_names_the_target_exactly_once(self):
        # **The case the fake's rule table structurally cannot write.**
        #
        # The fake matches a rule on a contiguous run of tokens, so a rule for
        # `["cat", <path>]` answers an argv that names the container TWICE --
        # `["exec", TARGET, TARGET, "cat", <path>]` -- just as well as one that
        # names it once. So a scenario whose `try_read` is bound to the target and
        # which passes the target to it anyway is answered correctly by every case
        # in this file, while the live cell asks the wrapper to exec the
        # container's own NAME inside the container.
        #
        # MEASURED, and it is what the first live run of the configured cell
        # reported, on all three releases: `the shipped resolver document at
        # /workspace/configs/dnscrypt-proxy.toml could not be read in
        # mosdns-…-target-24.04 … It read:` and then nothing -- a file that is
        # right there and readable inside a target. 45 of this file's cases were
        # green throughout.
        #
        # So the check is on the argv itself: one container name, and never two.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        containers = {TARGET, ROUTER, FOREIGN, CLIENT}
        for argv in fake.invocations():
            if argv[:1] != ["exec"] or len(argv) < 3:
                continue
            with self.subTest(command=" ".join(argv[2:])[:120]):
                self.assertIn(
                    argv[1], containers,
                    f"an exec named a container this run did not build: {argv!r}",
                )
                self.assertNotIn(
                    argv[2], containers,
                    f"a container's name was passed as the COMMAND, so the wrapper execs a "
                    f"binary called {argv[2]!r} inside it -- which is what a helper bound to "
                    f"one container and handed another one does: {argv!r}",
                )

    def test_the_override_is_written_before_dpkg_runs(self):
        # **The ordering is the mechanism, not a detail.** The transaction is
        # inside `postinst`, which starts `dnscrypt-proxy` and then waits up to
        # 60s for 127.0.0.1:15353 to answer -- so anything written after `dpkg -i`
        # returns is written after the barrier has already refused. The commands
        # are read out of the fake's log in order rather than from the source,
        # which is what makes this a measurement of the cell.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        lines = self.asked(fake)
        first_chmod = next(i for i, line in enumerate(lines) if "chmod 0644" in line)
        install_at = next(i for i, line in enumerate(lines) if " dpkg -i " in line)
        self.assertLess(
            first_chmod, install_at,
            f"the override was written after the install: {lines}",
        )
        # And the conffile answer is the operator's, so dpkg is told to keep the
        # file that is already there rather than the one in the package. MEASURED
        # in a 24.04 container with a package that ships one conffile: dpkg
        # prints the question, reads the `N`, keeps the file, and exits 0.
        self.assertIn("printf 'N\\n' | dpkg -i", lines[install_at])

    def test_the_directory_the_override_goes_into_is_created_first(self):
        # **`podman cp` does not create the directory it is writing into.**
        # MEASURED on this host: `podman cp pkg.deb c:/etc/nosuchdir/pkg.deb` is
        # `Error: "/etc/nosuchdir/pkg.deb" could not be found on container c: no
        # such file or directory`, and `/etc/mosdns` is created by the PACKAGE --
        # so on a fresh target the copy fails before the override is written, and
        # the failure is a `PodmanError` the first version of this scenario did
        # not translate, so the cell would have died as a harness fault (exit 2)
        # with nothing said about the override.
        #
        # **Twice, because the refusal case copies it again** -- `dpkg --unpack`
        # puts the package's own conffile back -- and the second copy is the one
        # that could leave a machine whose resolver is reading Quad9's stamps. A
        # `mkdir` for one of the two is a `mkdir` for neither if the second is
        # skipped, and the assertion is over both.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        # `cp` is a top-level `podman` subcommand rather than an `exec`, so it is
        # read out of the whole invocation log and not out of `asked`.
        copies = [
            argv for argv in fake.invocations()
            if argv[:1] == ["cp"] and foreign_override.DNSCRYPT_CONFIG in argv[-1]
        ]
        self.assertEqual(
            len(copies), 2,
            f"the override is copied twice -- once for the install and once after the refusal "
            f"case's `dpkg --unpack` -- and each of them needs the directory to exist: {copies}",
        )
        directory = str(Path(foreign_override.DNSCRYPT_CONFIG).parent)
        mkdirs = [
            index for index, line in enumerate(self.asked(fake))
            if f"mkdir -p {directory}" in line
        ]
        self.assertEqual(len(mkdirs), 2, f"{directory} was created {len(mkdirs)} times")
        # The order that matters is each `mkdir` before the `chmod` that follows
        # its own copy.
        chmods = [
            index for index, line in enumerate(self.asked(fake)) if "chmod 0644" in line
        ]
        self.assertEqual(len(chmods), 2)
        for mkdir, chmod in zip(mkdirs, chmods):
            self.assertLess(mkdir, chmod)

    def test_a_script_that_fails_in_the_cell_is_a_failed_cell_and_not_a_broken_harness(self):
        # Every `set -eu` script in this scenario is a command into a container, and
        # a command that fails is a CELL that did not work. The first version let
        # `PodmanError` out of `run()`, which the harness reports as exit 2 --
        # "the matrix is broken" -- for a `chmod` that failed because the copy
        # before it never happened. A reader sent to look for a broken harness
        # would not find one, and the report would say nothing about the override.
        #
        # The `chmod` is the one to fail: it is the command that touches the file
        # the `cp` put there, so it is the one that fails when the copy did not.
        #
        # The `try` is not decoration. An escaping `PodmanError` is what the first
        # version did, and it would be reported as an ERROR in this file rather
        # than a FAILURE, which reads as a broken case rather than as the broken
        # disposition this is about. So it is caught and failed on by name.
        try:
            _fake, result = self.run_scenario(
                rules=[
                    {"match": ["sh", "-c"], "match_contains": "chmod 0644", "returncode": 1,
                     "stderr": "chmod: cannot access '/etc/mosdns/dnscrypt-proxy.toml': "
                               "No such file or directory\n"},
                ] + install_rules(),
            )
        except PodmanError as error:
            self.fail(
                f"a command that failed inside the cell escaped the scenario as a harness "
                f"error, so the run would report exit 2 -- 'the matrix is broken' -- for a "
                f"cell that did not work:\n{error}"
            )
        self.assertEqual(result.status, "failed")
        self.assertIn("a command in the cell failed", result.detail)
        self.assertIn("chmod 0644", result.detail)
        self.assertIn("No such file or directory", result.detail)

    def test_the_artifact_is_read_out_of_the_copy_inside_the_target(self):
        # "The package was not modified to make this cell pass" is a claim about
        # the ARTIFACT, and the artifact inside a target is the copy the harness
        # made of it. A `dpkg-deb --fsys-tarfile` naming a path on the host is a
        # command no container can run -- the source tree is the only host path
        # inside it, and it is at `/workspace` -- and it would fail on every live
        # run while every case here stayed green, because the fake answers it.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        reads = [line for line in self.asked(fake) if "dpkg-deb --fsys-tarfile" in line]
        self.assertEqual(len(reads), 1, f"the artifact was read {len(reads)} times: {reads}")
        self.assertIn("/tmp/mosdns-router.deb", reads[0])
        for line in self.asked(fake):
            self.assertNotIn(
                str(self.directory), line,
                f"a command names a path on the host, which does not exist inside the "
                f"target: {line!r}",
            )

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
        #
        # **One install, and nothing else that runs it.** The refusal case probes
        # the installer's own preflight rather than dpkg -- a second `dpkg -i`
        # re-unpacks and restores the shipped snapshot, and `dpkg --configure` on an
        # installed package does not run postinst at all -- so the transaction is
        # run once and the record says so.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        installs = [line for line in self.asked(fake) if " dpkg -i " in line]
        self.assertEqual(len(installs), 1, f"dpkg -i ran {len(installs)} times: {installs}")
        self.assertIn("DPKG_EXIT", installs[0])
        self.assertEqual(self.record(result)["dpkg_runs"], 1)


class TheRefusalsTest(InstallScenarioHarness):
    """Both sides of the property, and both of them have to be refusals.

    A scenario that only proves the happy path leaves the refusal unverified, and
    the refusal is what has been protecting every machine so far. The mirror half
    matters more than usual here: the previous version of this scenario
    *required* the refusal, so a cell that configured was refused -- and the case
    that held it there was `test_a_cell_where_the_transaction_completed_is_refused`,
    which is now the case that holds the replacement in place."""

    def test_a_cell_where_the_transaction_completed_is_not_refused(self):
        # **The inversion, and this is the case the upgrade is checked by.**
        #
        # It used to read the other way round: the default fixture was a refused
        # cell, and this case showed that overriding it with a COMPLETED cell
        # still produced `failed` -- i.e. the scenario required the resolver's
        # barrier and nothing could talk it out of it. It now runs the default
        # fixture, which IS the completed cell, and asserts that a passing cell is
        # a passing result. An implementer who dropped the replacement and put the
        # barrier back would fail here, which is the whole of "must fail if the
        # replacement is not made".
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertTrue(record["package_configured"])
        self.assertTrue(record["transaction_completed"])
        self.assertEqual(list(result.skips), [])

    def test_a_refused_transaction_that_the_override_could_not_reach_is_refused(self):
        # The mirror, and it is what a real cell was before Step 5: postinst
        # verified its pair, the transaction started, `dnscrypt-proxy` bound its
        # loopback listener and then answered nothing because the DNSCrypt server
        # it needed was on the internet, and the installer rolled the whole thing
        # back. Measured twice on 24.04.
        #
        # A scenario that accepted this cell would say nothing about either
        # disposition, so it is refused -- and the refusal has to name the
        # CONFIGURED state as the thing that is missing, because that is the
        # requirement the override closes.
        _fake, result = self.run_scenario(
            install=REFUSED_OUTPUT,
            state="half-configured",
            status="install ok half-configured",
            backup=0,
            marker=1,
            timer="disabled",
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("NOT configured", result.detail)
        self.assertIn("half-configured", result.detail)
        self.assertIn("foreign answer reachable", result.detail)
        self.assertIn("The override that should have made it reachable is recorded", result.detail)

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
        # for it. Its dpkg output carries BOTH range refusals' signatures and none
        # of the committing path's own sentences -- so a scenario that only
        # asserted "the transaction configured" would pass against it and report a
        # pass for a cell that published nothing.
        _fake, result = self.run_scenario(install=CDN_BARRIER_OUTPUT)
        self.assertEqual(result.status, "failed")
        self.assertIn("does not contain", result.detail)
        self.assertIn("the loopback was handed to NetworkManager", result.detail)
        self.assertIn("did not commit", result.detail)

    def test_a_committed_transaction_that_also_carries_a_range_refusal_is_refused(self):
        # **The case the absent-signature checks exist for.** A cell that refused
        # at the ranges alone is already caught by the required hand-over, and a
        # cell that committed cleanly has no range wording in it. This one has
        # both, and it is the only state in which dropping the absent-signature
        # checks changes anything: an evidence document that reported a committed
        # transaction would be describing a run that published nothing while
        # appearing to have got past the CDN step.
        _fake, result = self.run_scenario(install=COMPLETED_WITH_A_RANGE_REFUSAL)
        self.assertEqual(result.status, "failed")
        self.assertIn("what the RANGE step says when it refuses", result.detail)
        self.assertIn("cannot stand in for it", result.detail)
        self.assertIn("did not get past the CDN step", result.detail)

    def test_a_transaction_that_handed_the_loopback_over_and_also_refused_is_refused(self):
        # A cell that printed the hand-over AND the installer's rollback would
        # have an evidence document describing two transactions, so the barrier's
        # own sentence is now checked for ABSENCE. It is the half of the
        # replacement that makes the requirement load-bearing in the other
        # direction: before, the sentence was REQUIRED; now it is FORBIDDEN, and
        # a scenario that accepted both would accept a cell that is neither.
        _fake, result = self.run_scenario(
            install=COMPLETED_OUTPUT
            + "install: every change this run made has been rolled back\n"
        )
        self.assertEqual(result.status, "failed")
        self.assertIn(install.CLAIM_ROLLED_BACK, result.detail)
        self.assertIn("the installer rolling the transaction back", result.detail)
        self.assertIn("two transactions", result.detail.lower())

    def test_a_shipped_resolver_document_the_override_cannot_substitute_is_refused(self):
        # `foreign_override` raises `OverrideError` for a document it cannot
        # rewrite, and the scenario's own handler is `InstallScenarioError` -- a
        # scenario that let the other one escape would take the whole run down as
        # a harness fault (exit 2) for what is a cell that did not work, and the
        # reader of the report would be looking at the wrong thing entirely.
        _fake, result = self.run_scenario(shipped_document=NO_STATIC_TABLES_DOCUMENT)
        self.assertEqual(result.status, "failed")
        self.assertIn("the shipped resolver document", result.detail)
        self.assertIn("no route to the internet", result.detail)

    def test_an_override_whose_stamp_names_another_resolver_is_refused(self):
        # The realistic mistake, and the one the override module exists to catch:
        # a shipped Quad9 stamp with only its address changed. dnscrypt-proxy
        # would ask the mock for a certificate under Quad9's provider name, never
        # get one, bind its listener and answer nothing -- and the cell would
        # report that as the resolver's barrier rather than as a stamp pointing at
        # the wrong place.
        _fake, result = self.run_scenario(
            foreign_counters=FOREIGN_COUNTERS.replace(MOCK_STAMP, QUAD9_STAMP)
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("names the provider", result.detail)
        self.assertIn("2.dnscrypt-cert.quad9.net", result.detail)

    def test_a_cell_whose_override_never_reached_the_target_is_refused(self):
        # The override digest is compared against the shipped one, and the
        # inequality is the claim that the transaction completed BECAUSE of the
        # override. A cell where the two are equal installed for some other
        # reason, and an evidence document that said it was the override would be
        # reporting a mechanism it did not observe.
        _fake, result = self.run_scenario(override_dnscrypt=SHIPPED_DNSCRYPT_SHA)
        self.assertEqual(result.status, "failed")
        self.assertIn("byte-identical to the shipped document", result.detail)
        self.assertIn("the override never reached the target", result.detail)

    def test_an_artifact_whose_resolver_document_is_not_the_repositorys_is_refused(self):
        # "The package was not modified to make this cell pass" is a claim about
        # the ARTIFACT, and it is a comparison against the repository's own file.
        # A cell whose `.deb` carried a different document would be measuring a
        # package this repository did not build, and every other observation would
        # read the same.
        _fake, result = self.run_scenario(artifact_dnscrypt=ORIGIN_DOCUMENT_SHA)
        self.assertEqual(result.status, "failed")
        self.assertIn("the resolver document inside the artifact is", result.detail)
        self.assertIn("a package this repository did not build", result.detail)

    def test_a_committed_transaction_that_left_no_ownership_marker_is_refused(self):
        # The marker is the rollback point a later uninstall reads, and it is
        # written only on commit. A transaction that reported handing the loopback
        # over and left no marker would leave an uninstall refusing to restore a
        # machine it is right to restore -- so the marker is required, and its
        # ABSENCE is what a rolled-back transaction looks like from here.
        _fake, result = self.run_scenario(marker=1)
        self.assertEqual(result.status, "failed")
        self.assertIn("is NOT in", result.detail)
        self.assertIn("owns the machine's DNS", result.detail)

    def test_a_committed_transaction_that_recorded_nothing_is_refused(self):
        _fake, result = self.run_scenario(backup=1)
        self.assertEqual(result.status, "failed")
        self.assertIn("is not in", result.detail)
        self.assertIn("nothing recording what it was", result.detail)

    def test_a_timer_left_disabled_by_a_committed_transaction_is_refused(self):
        # **A committed transaction enables all four**, and only after the
        # transaction succeeds -- so a disabled one says the transaction did not
        # finish rather than that the timer is wrong. Back when the transaction
        # refused this was recorded and asserted nothing; that was the honest
        # disposition then.
        _fake, result = self.run_scenario(timer="disabled")
        self.assertEqual(result.status, "failed")
        self.assertIn("mosdns-cdn-optimizer.timer is 'disabled'", result.detail)
        self.assertIn("a timer that is not enabled", result.detail)

    def test_a_postinst_that_never_reported_verifying_the_pair_is_refused(self):
        # STEP 3's words are what say the package got past its own pin. Without
        # them the cell is not this one, and the transaction's own output would be
        # the only evidence -- which is the case where the interesting question
        # is which step refused, and the answer would be unanswered.
        _fake, result = self.run_scenario(
            install=COMPLETED_OUTPUT.replace(
                "the pinned range document at", "no range document here"
            ),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("does not contain", result.detail)
        self.assertIn("postinst verified the shipped pair", result.detail)

    def test_a_postinst_that_did_not_say_it_never_repins_is_refused(self):
        # The pin is a reviewable input, and "it is read here and never written"
        # is what says the package an operator reviewed is the package that gets
        # installed. A re-pin at install time would change that, and the report
        # should say so rather than pass a cell that re-pinned.
        _fake, result = self.run_scenario(
            install=COMPLETED_OUTPUT.replace(
                "here and never written", "here, and refreshed on the way past"
            ),
        )
        self.assertEqual(result.status, "failed")
        self.assertIn("It is read here and never written", result.detail)
        self.assertIn("is not the package that gets installed", result.detail)

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

    def test_a_corrupt_shipped_snapshot_leaves_the_package_half_configured(self):
        # **The refusal is dpkg's, and dpkg's own word is asserted.** `half-configured`
        # on 24.04 and 26.04, `unpacked` elsewhere -- both MEASURED -- so the pair
        # is what the scenario requires and this case is the one that says which of
        # them a 24.04 cell produces.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertEqual(record["corrupt_pin_state"], "half-configured")
        self.assertNotIn(record["corrupt_pin_state"], install.CONFIGURED_STATES)
        self.assertNotEqual(record["corrupt_pin_exit"], 0)

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
        # digest assertion above caught it on the first live run; this case is
        # there to hold the mechanism, so the next reader is not left guessing why
        # the read is base64.
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

    def test_the_refusal_case_leaves_the_published_documents_it_removed(self):
        # **One cell's failed case must not be the next cell's starting state,
        # and the published documents are part of that.** The corrupt-snapshot
        # case removes the range document and the prefix list on purpose, so that
        # "a refusal published nothing" is a fact about the machine rather than
        # about the postinst script. What it leaves behind is a machine whose
        # response rewriter would refuse to construct -- and `routing` runs in
        # the SAME cell after this one, so the cell would be measuring a router
        # whose ranges nobody can name.
        #
        # So they are put back, from the same pinned snapshot, and the restore is
        # observed rather than assumed -- the shipped pin is restored by writing
        # back the bytes that were read, and the published pair by asking the
        # control tool to publish it again, which is the one command on a machine
        # with no route that can do it.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertEqual(record["corrupt_pin_published"], [])
        self.assertTrue(record["published_restored_after_refusal"])
        self.assertEqual(
            record["published_ranges_sha256"], record["shipped_pin_sha256"]
        )
        self.assertNotEqual(
            record["published_ranges_sha256"], "",
            "the restore left the range document unreadable, so the cell it hands to the "
            "next scenario has no ranges at all",
        )
        self.assertNotEqual(record["published_prefix_list_sha256"], "")

    def test_the_refusal_case_puts_the_package_back_too(self):
        # **The refusal leaves the package `half-configured`, and the next scenario
        # in this cell runs on this machine.** `routing` runs after `install` in
        # `PACKAGE_SCENARIOS` order, so a cell handed on with a half-configured
        # package is a cell measured on a machine the install left half-done -- and
        # the record would say `package_configured` and mean the state before its
        # own last section.
        #
        # So the snapshot is restored and `dpkg --configure` is run again, and the
        # second is a second piece of evidence for the pin rather than a tidy-up:
        # the whole snapshot was the only thing the refusal case broke. The
        # transaction runs a second time, on a machine this package already runs on,
        # and postinst says so in its own output.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertIn(record["corrupt_pin_state"], install.REFUSING_STATES)
        self.assertEqual(record["restored_package_state"], "installed")
        self.assertIn("install ok", record["restored_package_status_phrase"])
        self.assertEqual(record["pin_restore_exit"], 0)
        self.assertIn(
            "re-install of a machine this package already runs on",
            record["pin_restore_output"],
        )

    def test_the_refusal_case_unpacks_before_it_corrupts_and_the_override_is_rewritten(self):
        # **Four commands, and the order is the mechanism.** The pin's digest check
        # lives in postinst's STEP 3 and nowhere else, so the case has to make
        # postinst run over a corrupt snapshot. Three earlier shapes could not, and
        # each was MEASURED on 24.04:
        #
        #   * `dpkg --configure` on an `installed` package runs no maint script --
        #     "package mosdns-router is already installed and configured";
        #   * `dpkg -i` re-unpacks and the unpack RESTORES the shipped snapshot
        #     from the package, so postinst read a whole one and the cell
        #     configured the machine;
        #   * and the installer's own `preflight --check-only` -- which postinst's
        #     own refusal names as the way to try again -- says nothing about the
        #     pin: "preflight: this machine can have this router installed on it;
        #     nothing has been changed". It checks the MACHINE.
        #
        # So: `dpkg --unpack`, then the override is written AGAIN (unpacking a
        # package puts its own conffiles back, and this conffile is the one the
        # resolver reads), then the corruption, then `dpkg --configure`.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        lines = self.asked(fake)
        unpack = next(i for i, line in enumerate(lines) if "dpkg --unpack" in line)
        installs = [line for line in self.asked(fake) if " dpkg -i " in line]
        self.assertEqual(len(installs), 1, f"the package is installed once: {installs}")
        # The `cp` is a top-level subcommand, so its position comes from the
        # invocation log rather than from `asked`.
        copies = [
            index for index, argv in enumerate(fake.invocations())
            if argv[:1] == ["cp"] and foreign_override.DNSCRYPT_CONFIG in argv[-1]
        ]
        self.assertEqual(len(copies), 2, f"the override is written twice: {copies}")
        second = next(
            index for index, line in enumerate(lines)
            if "chmod 0644" in line and index > unpack
        )
        self.assertLess(unpack, second, f"the unpack came after the second copy: {lines}")
        probes = [line for line in lines if "dpkg --configure" in line]
        self.assertEqual(
            len(probes), 2,
            f"`dpkg --configure` runs twice: once over the corrupt snapshot and once after the "
            f"restore: {probes}",
        )

    def test_the_refusal_case_says_its_own_precondition_applied(self):
        # **The case the live run was missing, and the reason two runs were spent.**
        #
        # A probe that re-installed the package restored the shipped snapshot from
        # the package before postinst read it, so the cell got a whole pin, a
        # configuration, and a failure whose message was "a shipped snapshot whose
        # bytes its lock does not record did not stop the install" -- a sentence
        # about a corruption that was no longer there. The refusal case asserted
        # the refusal's *text* and never checked that its own precondition held.
        _fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        record = self.record(result)
        self.assertNotEqual(
            record["pin_corrupted_sha256"], record["shipped_pin_sha256"],
            "the corruption did not apply, so the refusal case probed a whole snapshot",
        )
        self.assertNotEqual(record["pin_corrupted_sha256"], record["pin_restored_sha256"])

    def test_the_publish_is_asked_once_to_publish_and_once_to_put_back(self):
        # Two invocations, and the distinction is in the command: the FIRST one
        # removes the published documents first, so the machine's own cannot stand
        # in and the snapshot is necessarily the source; the SECOND is the
        # restore, and it asks for no report. A cell that asked for a report from
        # the second one would be asserting on `ranges-source: cache` -- a report
        # about its own first run, which is the mistake this table's comment above
        # the refresh rule exists to prevent.
        fake, result = self.run_scenario()
        self.assertEqual(result.status, "passed", result.detail)
        refreshes = [
            line for line in self.asked(fake) if "update-lists --refresh-ranges" in line
        ]
        self.assertEqual(
            len(refreshes), 2,
            f"the publish was asked {len(refreshes)} times and one of them has to be the "
            f"restore: {refreshes}",
        )
        self.assertIn("rm -f", refreshes[0])
        self.assertNotIn("rm -f", refreshes[1])
        self.assertNotIn("REFRESH_EXIT", refreshes[1])
        self.assertEqual(self.record(result)["refresh_exit"], 0)


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
            "CLAIM_LOOPBACK_HANDED_OVER", "CLAIM_MARKER_WRITTEN",
            "CLAIM_RESOLVER_BARRIER", "CLAIM_ROLLED_BACK",
            "CLAIM_POSTINST_SAW_REFUSAL", "CLAIM_NOTHING_ENABLED",
            "CDN_BARRIER_SIGNATURES", "OFFLINE_CONFIGURED_REQUIREMENT",
            "CONFIGURED_STATES",
        ):
            self.assertIn(name, constants, f"{name} is asserted but not named at module scope")
        # And `REFUSING_STATES` is back in the list, because the refusal case makes
        # dpkg configure the package over a corrupt snapshot again -- through
        # `dpkg --unpack` first, which is the only way to get postinst to run
        # without the unpack restoring the snapshot it is about to be shown. The
        # pair is asserted, so it is not vocabulary the scenario merely carries.
        for name in ("REFUSING_STATES", "CONFIGURED_STATES"):
            self.assertIn(name, constants, f"{name} is asserted but not named at module scope")
        self.assertEqual(
            install.REFUSING_STATES, ("half-configured", "unpacked"),
            "the refusing pair changed; both were measured, on 24.04/26.04 and elsewhere "
            "respectively, and a case that depends on the exact set has to say so",
        )

    def test_the_docstring_says_what_the_scenario_asserts_and_not_what_it_cannot(self):
        # **The false claim the review found, held shut.** The first version's
        # docstring said "It also does not claim the whole transaction is
        # reachable with no route" while the file required `package_configured`
        # and reported "the install transaction completed" -- so the file a
        # future implementer reads told them the opposite of what it did, in the
        # one document nobody skips.
        #
        # The requirement is in the docstring verbatim, because the docstring is
        # where a reader looks for it, and the claims that were false are gone
        # rather than softened. And the direction has flipped: the docstring now
        # has to say the scenario REQUIRES the configured state, and to name the
        # case that fails if the replacement is not made -- a docstring that said
        # "not either" would be the old lie with the sign changed.
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
        # The two sentences a reader of this file needs and that the previous
        # version did not have: the state is required, and the requirement is
        # replaced rather than relaxed.
        self.assertIn("requires the CONFIGURED state", flat)
        self.assertIn("Replaced, not relaxed.", flat)
        # And it points at the case that holds the replacement in place, so a
        # reader of the plan and a reader of this file are sent to the same place.
        self.assertIn("test_a_cell_where_the_transaction_completed_is_refused", flat)
        # **And it says the disposition it replaced is GONE rather than optional.**
        # "It did not always" is allowed -- the history is the honest part -- but
        # the sentence has to end at "it is gone now", or a reader would be told
        # a skip is still on offer.
        self.assertIn("it is gone now", flat)
        self.assertIn(
            "are **dropped** and", flat,
            "the docstring does not say the requiring assertions were dropped",
        )
        # The word "optional" is NOT banned: the docstring uses it to explain why
        # making the old assertions optional would have been wrong, and a rule
        # against the bare word would forbid the explanation. So the ban is on the
        # phrasings that would actually license a skip.
        for gone in (
            "either disposition is fine",
            "may be a skip",
            "the assertions are optional",
            "recorded rather than closed",
        ):
            self.assertNotIn(gone, flat, f"install_test.py still says {gone!r}")

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
        # like tidying, and the cell this step was written to end -- the one whose
        # refusal names the origin -- would be reported as an install that
        # published from the pin. The check survived the rewrite for that reason
        # and not out of habit: it is the only thing that can see a cell that both
        # committed and carried a range refusal.
        source = self.source()
        self.assertIn("CDN_BARRIER_SIGNATURES", source)
        self.assertIn(
            "for signature in CDN_BARRIER_SIGNATURES:", source,
            "the range refusals are no longer checked for ABSENCE at all, which is the only "
            "thing that can see a cell carrying both a committed transaction and a range refusal",
        )
        self.assertIn("signature not in flat", source)
        self.assertEqual(
            install.CDN_BARRIER_SIGNATURES,
            ("cannot stand in for it", "cannot account for"),
            "the two signatures changed; `Cannot stand in for it` is `standInFor`'s own wording and "
            "`cannot account for` is postinst's, and a case that depends on them has to say so",
        )

    def test_the_scenario_asserts_a_configured_package_and_says_why_it_may(self):
        # **The inversion, held as a shape.** The single assertion that made this
        # scenario unable to go green in any cell was
        # `not document["package_configured"]`; it is now
        # `document["package_configured"]`, and the reason is named next to it
        # rather than left in a commit message. A later edit that flipped it back
        # -- which would look like a restoration of the previous behaviour -- is a
        # failing case.
        source = self.source()
        self.assertNotIn(
            'not document["package_configured"]', source,
            "the scenario requires a CONFIGURED package again, which the override is what makes "
            "possible and what the requirement asks for",
        )
        self.assertIn(
            'document["package_configured"],', source,
            "the configured state is no longer required, so the cell this step produces would be "
            "refused for the reason the previous version of this file was written to remove",
        )
        self.assertIn(
            "# **The CONFIGURED state is what this scenario requires, and it", source,
            "the inversion is one line and the reason is beside it in a comment; a later edit that "
            "flipped it back should not look like a restoration of previous behaviour",
        )
        self.assertIn("CONFIGURED_STATES", source)
        self.assertEqual(
            install.CONFIGURED_STATES, ("installed", "install ok installed"),
            "the configured pair changed; dpkg spells the state two ways and a case that depends on "
            "the exact set has to say so",
        )
        # The refusal is a non-zero exit now, and it is asserted: a refusal that is
        # only a sentence is a refusal a program can print on its way to succeeding.
        # (That the refusing *pair* is gone is held in the constants case above,
        # because that is a statement about the module's vocabulary and not about
        # this assertion.)
        self.assertIn("corrupt_pin_exit", source)
        self.assertIn("PROBE_EXIT", source)

    def test_the_scenario_requires_the_committing_path_and_forbids_the_refusing_one(self):
        # **The replacement itself, read off the source rather than trusted from
        # the record.** Two required sentences and four forbidden ones, and the
        # forbidden four are the previous version's required four. A scenario that
        # kept only the required pair would accept both dispositions, which is a
        # scenario that proves nothing about either -- so the case holds that the
        # loop is over the *committing* claims and that the refusal's own sentences
        # are asserted absent.
        source = self.source()
        self.assertIn(
            "(CLAIM_LOOPBACK_HANDED_OVER, \"the loopback was handed to NetworkManager\")",
            source,
        )
        self.assertIn(
            "(CLAIM_MARKER_WRITTEN, \"the ownership marker was written\")", source,
            "the marker sentence is one of the two halves of the replacement",
        )
        for sentence in (
            "CLAIM_RESOLVER_BARRIER", "CLAIM_ROLLED_BACK",
            "CLAIM_POSTINST_SAW_REFUSAL", "CLAIM_NOTHING_ENABLED",
        ):
            self.assertIn(
                f"({sentence}, ", source,
                f"{sentence} is no longer checked at all, and the only thing that can tell a "
                f"committed cell from one that printed both dispositions is the absence check",
            )
        self.assertIn("in forbidden:", source)
        self.assertIn("not in flat", source)
        # The two are the same loop run twice, and the second is the direction
        # that matters: before, this was the *only* check and it was the wrong
        # way round.
        self.assertEqual(
            source.count("not in flat"), 2,
            "the absence checks are one loop over the two refusing sets; a count other than two "
            "means one of them was dropped or the other was duplicated",
        )

    def test_the_scenario_writes_the_override_before_dpkg_and_says_dpkg_to_keep_it(self):
        # The mechanism, read off the source: the override is written BEFORE
        # `dpkg -i` (the transaction is inside `postinst`, and anything written
        # after `dpkg -i` returns is written after the barrier has refused), and
        # dpkg is told `N` -- the operator's answer to a conffile this project
        # ships on purpose. Both halves, because a cell with the ordering right
        # and the answer wrong leaves dpkg's conffile prompt to decide.
        source = self.source()
        self.assertIn("printf 'N\\\\n' | dpkg -i", source)
        self.assertIn("apply_foreign_override(document)\n            podman.copy_to(", source)
        # And the override is written through a `cp` of a file the harness built,
        # not through a here-doc: the wrapper strips trailing whitespace, so a
        # text round trip would produce a different file with a different digest,
        # and this one is compared by digest twice.
        self.assertIn("podman.copy_to(target, str(override_path)", source)
        self.assertIn("chmod 0644", source)

    def test_the_scenario_turns_an_override_failure_into_a_cell_and_not_a_crash(self):
        # `foreign_override` raises `OverrideError`, and the scenario's own
        # handler is `InstallScenarioError`. Without the translation an escaping
        # `OverrideError` is a harness fault -- exit 2, "the matrix is broken" --
        # for what is a cell whose shipped document the override could not
        # substitute into. Held here because the translation is one clause in a
        # function and dropping it looks like tidying.
        source = self.source()
        self.assertIn("except foreign_override.OverrideError as error:", source)
        self.assertIn("raise InstallScenarioError(", source)

    def test_the_scenario_reads_the_artifact_out_of_the_target_not_a_host_path(self):
        # The host path of the `.deb` is not a path inside the target: the only
        # host directory bound in is the source tree, read-only, at `/workspace`.
        # So a `dpkg-deb --fsys-tarfile` naming the host's own file is a command
        # no cell can run, and the only reason nothing noticed is that the fake
        # answers it. The read-back is about the COPY.
        source = self.source()
        self.assertIn("dpkg-deb --fsys-tarfile", source)
        self.assertIn("ARTIFACT_DNSCrypt_TMP", source)
        self.assertNotIn(
            f"dpkg-deb --fsys-tarfile {{deb}}", source,
            "the artifact is read out of the copy the harness made inside the target, not out of "
            "the host's own path, which does not exist in a container",
        )


if __name__ == "__main__":
    unittest.main()
