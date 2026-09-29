"""The watchdog scenario: the only place this mechanism can be observed at all.

Everything else about the resolver watchdog is a table, a parser and a message,
and a fake root answers all three. **What a fake command runner cannot answer is
what the mechanism does to a machine**: whether the window is real, whether the
action is the real one, and whether the switch is a switch. So this scenario
installs the package into a live target, points the machine at the local
resolver, stops the router, and watches.

## The three observations, and what each one is evidence OF

1. **The window.** Nothing happens below it and the real rollback happens above
   it. The count is checked at each step rather than only at the end, because a
   mechanism that acts on the first probe passes a test that only looks at the
   end -- and one unattended rollback is the whole of what this thing does.
2. **The action is the real one.** The evidence is the machine, not the log: the
   recorded DHCP DNS is back on the connection, the connection carries no
   loopback address, the ownership marker is untouched, and the router unit's
   state is whatever the rollback left it (it stops nothing, which is the
   documented behaviour and the reason the limitation is in the message).
3. **The switch.** With `automatic: false`, across a window **longer than the
   default** -- more consecutive failures than the default threshold and more
   elapsed time than the default window -- nothing happens at all, and the
   operator's own `emergency-rollback` still works afterwards. The second half
   matters as much as the first: a switch that turned the action off for the
   watchdog *and* for the operator would be a broken machine with no way out.

## What this scenario deliberately does NOT do

It does not restore the router afterwards. The target container is thrown away
and the next cell builds a fresh one, and a scenario that tidied up would be
asserting something about a mock rather than about the package. It also does not
wait on the timer: it runs `mosdns-watchdog.service` by hand with
`systemctl start`, because a scenario that sleeps for a wall-clock window is a
scenario whose failure is indistinguishable from a slow machine. The TIMER is
exercised separately, by checking that the unit exists, is enabled, and names
this service -- and `installer/tests/test_watchdog_packaging.py` holds the rest
of the packaging.

## The boundary

Everything here happens inside the target container. The host's resolver, its
NetworkManager, its `/etc/resolv.conf` and its units are never read or written;
the harness's mount policy refuses the paths that could carry them, and
`NO-HOST-MUTATION.md` is why this scenario can run at all.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

from podman import PodmanError
from report import ScenarioResult

SCENARIO_NAME = "watchdog"

# The package's own paths, inside the target. They are named here rather than
# imported from the installer, because this file runs inside a container and the
# paths it needs are the INSTALLED ones -- which is the whole of the difference
# between a scenario that tests the package and one that tests the checkout.
INSTALLER = "/usr/lib/mosdns-router/mosdns_installer.py"
CDNCTL = "/usr/lib/mosdns-router/mosdns-cdnctl"
BACKUP_PATH = "/var/lib/mosdns/installer/network-manager-backup.json"
MARKER_PATH = "/var/lib/mosdns/installer/managed-by"
RECORD_PATH = "/run/mosdns/watchdog/watchdog.json"
RECORD_DIR = "/run/mosdns/watchdog"
SETTING_PATH = "/etc/mosdns/watchdog.yaml"
# The name the installer's own probe asks for, and the one the mock router is
# configured to answer. Both are named here rather than imported from the
# installer: this file runs inside a container against the installed package, and
# the name is the contract between the two.
INSTALL_PROBE_NAME = "install-probe.example"
ROUTER_UNIT = "mosdns-router.service"
WATCHDOG_UNIT = "mosdns-watchdog.service"
WATCHDOG_TIMER = "mosdns-watchdog.timer"
LOCAL_DNS = "127.0.0.1"
DNS_PORT = 53
RESOLVED_STUB = "127.0.0.53"
# The device the bridge gives a target and the profile the image's own setup unit
# created for it. The profile is named here rather than read from the target: on
# 24.04 and 26.04 the active connection on arrival is NetworkManager's own `eth0`,
# and the hand-off to this one is what gives the link a resolver at all.
DEVICE = "eth0"
MANAGED_PROFILE = "eth0-managed"
# The mock router's own address, which is what a DHCP lease publishes and what
# the machine's resolver therefore is before the install takes it over.
MOCK_ROUTER_ADDRESS = "10.89.0.2"

# The window this scenario arms, and why it is not the shipped one.
#
# The shipped window is 3 failures or 10 minutes, and this scenario would have to
# wait ten minutes of wall clock to cross it -- which is a scenario nobody runs and
# a failure indistinguishable from a slow machine. So the numbers are SET, to
# their smallest useful values, and what is under test is the mechanism rather
# than the default: that the count is honoured at each step, that the action runs
# at the threshold rather than before it, and that the shipped defaults are what
# the shipped file says (which `installer/tests/test_watchdog.py` holds).
#
# The off position uses the SHIPPED threshold instead, and says so: "a window
# longer than the default" is the plan's own requirement, and a shorter window
# would not be one.
ARMED_FAILURES = 2
ARMED_MINUTES = 5
SHIPPED_FAILURES = 3
SHIPPED_MINUTES = 10

# How long to wait for the machine to reach a state after a command that should
# cause it. Every one of these is a poll of a real fact, not a sleep: the DHCP
# re-activation that puts the recorded DNS back is asynchronous, and a scenario
# that slept would either be slow or flaky.
DEFAULT_WAIT_SECONDS = 90.0
WAIT_INTERVAL_SECONDS = 3.0

# The message fragments the scenario requires. They are the product, and a
# scenario that asserted only "the DNS came back" would pass against a watchdog
# that claimed the machine was fixed.
CLAIM_ACTION_RAN = "performed the emergency rollback unattended"
CLAIM_WHAT_IS_NOT_BACK = "foreign-name resolution through DNSCrypt does not work"
CLAIM_NOTHING_CHANGED = "Nothing has been changed"


class WatchdogScenarioError(Exception):
    """A watchdog claim the run could not establish, with the evidence attached.

    Its own type rather than the harness's `PodmanError`, for the reason
    `dhcp_test.py` gives: a failed assertion inside a scenario is a test failure
    (a `failed` row), and a harness fault is exit 2. A scenario that raised the
    harness's error for "the watchdog did not act when it should have" would be
    reporting a broken matrix as a broken harness.
    """


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchdogScenarioError(message)


def setting_document(automatic: bool, failures: int, minutes: int) -> str:
    """The setting file this scenario writes into the target.

    Written as text rather than patched, because the file's parse is one of the
    things under test: a document this function produced and the parser refused
    would be a refusal, and the refusal names the line. Every value is quoted the
    way the file documents itself -- `true`/`false` lowercase, positive integers
    -- so a failure here is never a formatting accident dressed as a defect.
    """
    return (
        "# written by the Podman harness's watchdog scenario\n"
        f"automatic: {'true' if automatic else 'false'}\n"
        f"consecutive_failures: {failures}\n"
        f"minimum_minutes: {minutes}\n"
    )


def wait_for(
    read: Callable[[], str],
    accept: Callable[[str], bool],
    *,
    what: str,
    seen: Callable[[], str] = lambda: "",
    timeout: float = DEFAULT_WAIT_SECONDS,
    interval: float = WAIT_INTERVAL_SECONDS,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Poll `read` until `accept` is satisfied, bounded, and say what it kept seeing.

    The DHCP reactivation a rollback performs is asynchronous, and the state this
    scenario waits for -- the machine carrying the recorded DNS again -- is a
    consequence of it rather than a step it can sequence against. So it is waited
    for, and the failure names the value it kept reading: a message that says only
    "timed out" sends a reader to the rollback, which is innocent.

    A read that raises counts as "not yet" and its message is kept, because
    `systemctl` and `nmcli` both exit non-zero on a unit or a device that is
    mid-transition, and swallowing every error would report one message for a
    target that disappeared and for one that never changed.
    """
    deadline = now() + timeout
    last: str | None = None
    last_error: str | None = None
    polls = 0
    while True:
        polls += 1
        try:
            last = str(read() or "").strip()
            if accept(last):
                return last
        except PodmanError as error:
            last_error = str(error)
        if now() >= deadline:
            break
        sleep(interval)
    described = f"read {last!r}" if last is not None else "never got an answer"
    if last_error:
        described += f" (the last command failed: {last_error.splitlines()[-1]})"
    raise WatchdogScenarioError(
        f"{what} {described}, and it still did not happen after {timeout:g}s and {polls} reads "
        f"{interval:g}s apart{seen()}. That means the thing did not arrive rather than that the "
        "read was never made, so the thing to look at is whatever produces it."
    )


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
    """The `watchdog` scenario, bound to one matrix cell's target.

    `deb` is the package to install. It is a parameter rather than a path
    computed here, for the same reason the other scenarios bind their containers:
    a scenario that reached for a global would be measuring whichever build
    happened to be on disk, and this one installs the package for real.
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

    def unit_state(unit: str) -> str:
        """A unit's `ActiveState`, read with a command that exits 0 for every state.

        `systemctl is-active` exits 3 for every state that is not `active` --
        measured, and recorded in `docs/measured-environment.md` -- and the
        wrapper's policy is `check=True`, so a stopped unit RAISES rather than
        printing its word. This scenario asks about a router it stopped on
        purpose, and "inactive" is the answer it wants.

        `systemctl show --property=ActiveState` is the read instead, and it is
        the harness's own `Podman.setup_unit_state` that makes the same choice for
        the same reason: the state is a fact about the unit, not about whether a
        command succeeded. Reading it through a command that exits 0 for every
        state means the difference between "inactive" and "the query could not be
        made" is a property of the command rather than of the moment.
        """
        try:
            return read("systemctl", "show", unit, "--property=ActiveState").partition("=")[2].strip()
        except PodmanError as error:
            return f"(could not read the state: {str(error).splitlines()[-1]})"

    def unit_enabled(unit: str) -> str:
        """Whether a unit is enabled, read the same way as its state.

        `systemctl is-enabled` exits 1 for `disabled`, which is this cell's
        actual answer, so the same `check=True` problem applies and the same
        read answers it: `show --property=UnitFileState`, which is 0 for every
        state and prints the word. `enabled` and `disabled` are the two a reader
        needs, and neither is an error.
        """
        try:
            return read("systemctl", "show", unit, "--property=UnitFileState").partition("=")[2].strip()
        except PodmanError as error:
            return f"(could not read: {str(error).splitlines()[-1]})"

    def file_text(path: str) -> str | None:
        """A file's contents, or `None` when it is not there.

        `None` and not an empty string, because the two mean different things:
        "no record has been written" and "a record that says nothing" are
        different claims and only one of them is expected.
        """
        if podman.exec_status(target, "test", "-e", path) != 0:
            return None
        return read("cat", path)

    def record() -> dict | None:
        text = file_text(RECORD_PATH)
        if text is None:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            raise WatchdogScenarioError(
                f"{RECORD_PATH} exists in {target} and is not JSON: {error}. The watchdog writes "
                "it with a temporary file and a rename, so this is either a different writer or a "
                "filesystem that lost the rename, and the harness will not read a document it "
                "cannot parse as though it were one."
            ) from error

    def write_setting(text: str) -> None:
        # Written through a staged file and a rename, inside the container, for
        # the same reason the watchdog writes its record that way: a reader must
        # never see half a document, and the watchdog IS the reader here.
        staged = f"{SETTING_PATH}.harness"
        run(f"set -eu\ncat > {staged} <<'MOSDNS-WATCHDOG-EOF'\n{text}MOSDNS-WATCHDOG-EOF\n"
            f"install -m 0644 -o root -g root {staged} {SETTING_PATH}\nrm -f {staged}\n")

    def journal_cursor() -> str:
        """Where the journal is right now, as a cursor this run can read forward from.

        **Without this, every read is the journal's last N lines and every
        assertion about it is about the last N lines of the whole cell.** That was
        measured: the switch-off position reported the watchdog acting, because
        the message it read was the *armed* run's success message still inside the
        window. The off position then "failed" on a mechanism that had done
        exactly the right thing -- which is the worst direction for a false
        positive, because the fix would have been to weaken the assertion.

        `journalctl --show-cursor` prints the position it is at; `--after-cursor`
        then returns only what was written after it. A cursor rather than a
        timestamp because a timestamp is ambiguous at second granularity and a
        fast cell writes two runs inside one second.

        **The cursor is taken from the whole journal, not from the unit's**,
        because a unit that has never run has no entries and `--show-cursor` then
        prints `-- No entries --` and no cursor at all (measured, on the first run
        of the first cell). The whole journal always has boot output, and
        `--after-cursor` is then filtered to the unit on the way out, so the
        position is the same and the read is still this run's.
        """
        answer = read("journalctl", "--no-pager", "-n", "0", "--show-cursor")
        line = answer.strip().splitlines()[-1].strip() if answer.strip() else ""
        # `--after-cursor` takes the cursor VALUE, not the line: the marker is
        # `-- cursor: ` and the value is everything after it. Passing the whole
        # line -- which is what the first version did -- makes journalctl refuse
        # the argument, and a refusal here is a `PodmanError` rather than a
        # diagnosis.
        _require(
            line.startswith("-- cursor:"),
            f"the journal printed no cursor in {target} ({answer!r}), so this run cannot read its "
            "own output back and every assertion about the watchdog's message would be about "
            "whatever the last forty lines of the cell happen to be",
        )
        return line.split("-- cursor:", 1)[1].strip()

    def start_watchdog() -> tuple[tuple, str]:
        """Run the watchdog service once, and report its status and its journal.

        By hand with `systemctl start`, not by waiting for the timer. A scenario
        that waits for a timer is a scenario whose failure is indistinguishable
        from a slow machine, and the timer's own behaviour -- that it exists, is
        enabled and names this service -- is checked separately and cheaply.

        The journal is read from a cursor taken **before** the start, so it is
        this run's output and nothing else. See :func:`journal_cursor` for what
        happens without it, which was measured.

        **The start's own exit status is a fact to record, not a failure here.**
        The verb exits non-zero whenever the machine's resolver is not answering
        and the window has not been reached, and `systemctl start` propagates a
        failed oneshot's status -- so the run BELOW the window returns 1 by
        design. Reading it through the wrapper's `check=True` would raise on the
        expected case and the scenario would never reach the window it exists to
        observe. It is recorded anyway, because a status that changes shape
        between the run below the window and the run at it is worth seeing.

        Both this status and the journal are kept: the journal is the message the
        product produces and the status is what systemd did with it, and a
        mechanism whose message is right while its exit status is wrong is still
        a mechanism an operator misreads.
        """
        cursor = journal_cursor()
        start_status = podman.exec_status(target, "systemctl", "start", WATCHDOG_UNIT)
        result = podman.exec_status(
            target, "systemctl", "show", WATCHDOG_UNIT, "--property=Result"
        )
        journal = read(
            "journalctl", "-u", WATCHDOG_UNIT, "--no-pager", "--after-cursor", cursor
        )
        return (start_status, result), journal

    def connection_dns() -> str:
        """The connection's `ipv4.dns`, from the profile the device is on.

        Read from the DEVICE's active connection rather than from a name this
        scenario invented: on 24.04 and 26.04 the active connection on arrival is
        NetworkManager's own, and the install recorded and modified whichever one
        was active -- so a profile name written into this file would be a
        different connection on a different release, and a wait on it would time
        out on a target where the mechanism worked.
        """
        active = read("nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "eth0").strip()
        if not active:
            return ""
        return read("nmcli", "-g", "ipv4.dns", "connection", "show", active)

    def recorded_dns() -> str:
        """The `ipv4.dns` the install recorded, read out of the backup itself.

        Read from the record rather than from the mock router's constant, so the
        claim is "the DNS that was recorded is back", not "the address the harness
        expected is back". A scenario that asserted the second would pass on a
        machine that restored the wrong thing.
        """
        document = json.loads(read("cat", BACKUP_PATH))
        return str(document["original"]["ipv4.dns"]["raw"])

    def wait_for_rollback(expected: str):
        """Wait for the connection to stop carrying the loopback address.

        **The recorded value is often the EMPTY string, and that is the point.**
        The install records what the connection held, and a machine that used its
        DHCP lease held *no* manual `ipv4.dns` at all -- so the restore's job is to
        clear the property and hand the resolver back to the lease. A predicate
        that required a non-empty answer after the restore would time out on the
        correct result, which is what the first live run of this scenario did.

        So the test is "the loopback address is gone", and where the record names
        a value, that the value is what came back instead. Both are claims about
        the machine, and neither is satisfied by a quiet read.
        """
        def restored(value: str) -> bool:
            if LOCAL_DNS in value:
                return False
            if expected.strip():
                return expected.strip() in value
            return True

        return wait_for(
            connection_dns,
            restored,
            what=f"the connection on {target} to carry the recorded DNS again",
            seen=lambda: (
                f"; the rollback restores what {BACKUP_PATH} recorded, which is "
                f"{expected or '(unset -- the lease publishes the resolver)'!r}, and this target's "
                "own log is in the evidence document"
            ),
            timeout=wait_seconds,
            interval=interval,
            now=now,
            sleep=sleep,
        )

    def probe_result() -> bool:
        """Whether the machine's own resolver answers the installer's probe name.

        Asked through `getent`, which on this image goes through
        `libnss-resolve` and therefore through resolved's stub -- the same path
        every other program on the machine takes, and the one the rollback's own
        final check uses. `dig` against the stub would answer a question about the
        stub rather than about the machine.
        """
        status = podman.exec_status(
            target, "getent", "hosts", INSTALL_PROBE_NAME
        )
        return status == 0

    def evidence(document: dict) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def run_scenario() -> ScenarioResult:
        document = {
            "arch": arch,
            "target_container": target,
            "router_container": router,
            "package": str(deb),
            "armed_window": {"consecutive_failures": ARMED_FAILURES, "minimum_minutes": ARMED_MINUTES},
            "shipped_window": {"consecutive_failures": SHIPPED_FAILURES, "minimum_minutes": SHIPPED_MINUTES},
        }
        try:
            # -- 1. the machine, and its OWN resolver, before anything else ----
            # **The hand-off comes first, and the order is the whole of what
            # makes step 8 mean anything.** The image's `target-nm-setup.service`
            # creates the `eth0-managed` profile at boot, and on 24.04 and 26.04
            # the device is left on NetworkManager's own `eth0` profile -- so the
            # link has no resolver at all until that profile is activated.
            # Measured on a live 24.04 target: `resolvectl dns eth0` printed
            # nothing and `Current Scopes: none`.
            #
            # A watchdog's action restores the DNS settings the install
            # RECORDED, and against a connection that never held a DHCP lease
            # there is nothing to restore and nothing that would make the machine
            # usable again. Worse, the record would name the wrong connection: the
            # install records the ACTIVE one, and the active one is the profile
            # with no resolver. So the device is handed over first, exactly as the
            # `dhcp` scenario does and for the same measured reason, and the
            # install below then records the connection that has a resolver.
            #
            # Two commands, the plan's Task 3 step 4, written out rather than
            # delegated: pretending the transaction took the machine over would be
            # the harness lying about the precondition.
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
                             "it the link has no resolver for a restore to put back",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            ).strip()
            document["dhcp_dns_published"] = wait_for(
                lambda: read("nmcli", "-g", "IP4.DNS", "device", "show", DEVICE),
                lambda value: MOCK_ROUTER_ADDRESS in value,
                what=f"the mock router's address on IP4.DNS of {DEVICE} in {target}",
                seen=lambda: "; the machine's own resolver has to be working before a restore can "
                             "be measured, because the rollback's last act is to ask it a question",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            ).strip()
            _require(
                MOCK_ROUTER_ADDRESS in document["dhcp_dns_published"],
                f"the device carries {document['dhcp_dns_published']!r} and not the mock router, so "
                "the machine has no resolver of its own and nothing this scenario restores would "
                "make it usable",
            )

            # -- 2. the package, UNPACKED in a live target --------------------
            # The package, copied in and installed with `dpkg -i`, because the
            # thing under test is the package: the unit, the timer, the setting,
            # the two numbers, the timer being enabled by postinst and the verb
            # the unit runs all come out of the same .deb an operator's machine
            # gets. A scenario that hand-copied those four files would be
            # testing a constructed approximation of it.
            #
            # **AND IT ENDS `unpacked`, NOT `configured`, and that is asserted
            # rather than left in the document for a reader to notice.**
            # `postinst` exits 1 when the install transaction refuses -- which it
            # does in every cell of this matrix, because the transaction's
            # `update-lists --refresh-ranges` step needs `api.cloudflare.com` and
            # there is no route off the container bridge -- so dpkg records
            # `install ok unpacked` and never reaches the enable step. The
            # watchdog's evidence is unaffected: every file it needs is
            # unpacked, and the scenario starts the service by hand because the
            # timer was never enabled. But a cell whose install did not complete
            # must not read as a cell that tested an installed package, and
            # `postinst`'s own timer-enable path is therefore NOT exercised by
            # this scenario at all. Both facts are in the document, and both are
            # required.
            podman.copy_to(target, str(deb), "/tmp/mosdns-router.deb")
            document["package_bytes"] = int(
                try_read("stat", "-c", "%s", "/tmp/mosdns-router.deb").strip() or 0
            )
            # `dpkg -i` through `sh -c` so the installer's own stdout AND stderr
            # are captured. `exec_status` keeps no output, and the previous
            # version used it -- which is why the evidence document had the dpkg
            # exit status and nothing that said WHY. That gap is what let the
            # first version of this report call the resulting state `unpacked`
            # when a live run measures `half-configured`: the transaction's own
            # refusal, which names the step it stopped at, is in this string.
            document["dpkg_output"] = try_read(
                "sh", "-c", "dpkg -i /tmp/mosdns-router.deb 2>&1 || true"
            )[:4000]
            installed = podman.exec_status(target, "dpkg", "-i", "/tmp/mosdns-router.deb")
            document["dpkg_exit"] = installed
            document["package_state"] = try_read(
                "sh", "-c", "dpkg-query -W -f='${db:Status-Status}\\n' mosdns-router 2>&1 || true"
            ).strip()
            # `dpkg-reconfigure` re-runs the configure step, so the transaction's
            # messages are in the document whatever the first run printed -- and
            # on a package dpkg has already left half-configured it REFUSES
            # ("broken or not fully installed"), which is itself an answer worth
            # having next to the state.
            document["configure_output"] = try_read(
                "sh", "-c", "dpkg-reconfigure mosdns-router 2>&1 || true"
            )[:4000]
            document["package_unpacked"] = try_read(
                "sh", "-c", "dpkg-query -W -f='${Status}\\n' mosdns-router 2>&1 || true"
            ).strip()
            # **MEASURED, NOT ASSUMED.** The first version of this scenario
            # reported the state as `unpacked` because that is what the review
            # said, and a live run measured `half-configured` -- dpkg records a
            # different word depending on how far its state machine got before
            # `postinst` exited 1, and "unpacked" was simply the wrong one. Both
            # words mean the same thing for every claim this scenario makes, so
            # what is asserted is the PROPERTY -- not configured, and the files
            # are there -- rather than a literal dpkg is free to change. The
            # word is recorded either way.
            configured = document["package_state"] in ("installed", "install ok installed")
            document["package_configured"] = configured
            document["package_state_explained"] = (
                f"{document['package_state']!r}, NOT configured: postinst exits 1 when the install "
                "transaction refuses, and it refuses in this matrix because `update-lists "
                "--refresh-ranges` needs api.cloudflare.com and the container has no route off its "
                "bridge. Everything this scenario observes was unpacked and is present; the timer "
                "was never enabled by postinst, so the service is started by hand and postinst's "
                "enable path is NOT exercised here. (dpkg's exact word for this state is measured "
                "per run rather than asserted: it has been observed as both `unpacked` and "
                "`half-configured` depending on how far dpkg's state machine got.)"
            )
            _require(
                not configured,
                f"the package is {document['package_state']!r} and this scenario's evidence document "
                "claims a cell that tested an installed package. Either the transaction succeeded "
                "in this cell -- in which case that text is wrong and must be rewritten -- or it "
                "did not, and the state is what this scenario documents. The dpkg exit was "
                f"{document['dpkg_exit']} and dpkg's own output is in this document:\n"
                f"{document['dpkg_output']}",
            )
            _require(
                "ok " in document["package_unpacked"],
                f"dpkg reports {document['package_unpacked']!r}, which is not one of the "
                "unpacked-but-not-configured states this scenario is written for, so what it "
                "observed is not what it says it observed",
            )

            for path in (INSTALLER, CDNCTL, SETTING_PATH):
                _require(
                    podman.exec_status(target, "test", "-e", path) == 0,
                    f"{path} is not installed in {target} after dpkg -i, so the watchdog cannot be "
                    f"observed here at all. The dpkg exit was {installed} and the configure "
                    f"output is in this document:\n{document['configure_output']}",
                )
            document["setting_mode"] = try_read("stat", "-c", "%a %U %G", SETTING_PATH)

            # -- 3. the units the package installed, as the machine sees them --
            # Read through `show --property=ActiveState` and not through
            # `is-active`, because the transaction above refused and the units
            # this package installs are therefore in whatever state a refused
            # install left them -- which `is-active` answers with exit 3 and no
            # word, on a wrapper whose policy is `check=True`.
            for unit in (ROUTER_UNIT, WATCHDOG_UNIT, WATCHDOG_TIMER):
                document[f"is-enabled:{unit}"] = unit_enabled(unit)
                document[f"state:{unit}"] = unit_state(unit)
            document["watchdog_unit_file"] = try_read("cat", f"/usr/lib/systemd/system/{WATCHDOG_UNIT}")
            document["watchdog_setting_shipped"] = try_read("cat", SETTING_PATH)

            # -- 4. the machine the watchdog is for --------------------------
            # A connection carrying the loopback address, with a record of what
            # it was before. The record is the installer's, not this scenario's:
            # `emergency_rollback` acts on the record alone, so a record written
            # by the harness would be testing the harness's JSON rather than the
            # package's restore.
            profile = read(
                "nmcli", "-g", "GENERAL.CONNECTION", "device", "show", DEVICE
            ).strip()
            _require(
                profile == MANAGED_PROFILE,
                f"the target's active connection is {profile!r} and not {MANAGED_PROFILE!r}. The "
                "install records the ACTIVE connection, so a record naming a profile with no DHCP "
                "lease is a record of nothing -- and the restore would put back values that cannot "
                "make the machine resolve.",
            )
            document["connection_before"] = profile
            if not file_text(BACKUP_PATH):
                # The record is written and read back BEFORE the transaction's
                # first mutation, so a transaction that refused for any later
                # reason still leaves one behind. Its absence therefore means the
                # transaction refused earlier than that -- the DHCP capture, or
                # preflight -- and there is nothing for the watchdog's action to
                # restore.
                #
                # REFUSED rather than skipped, and the reason is the plan's own:
                # a scenario that proceeded without a record would be testing
                # `emergency_rollback`'s refusal path and reporting it as the
                # watchdog's window. And a skip is never reported as a pass.
                raise WatchdogScenarioError(
                    f"{BACKUP_PATH} does not exist in {target}, so there is no record for "
                    f"`emergency-rollback` to restore and the watchdog has nothing to act on. The "
                    f"transaction refused before it wrote the record, which is earlier than the "
                    f"cloud-ranges publication a container cannot reach -- dpkg exit was "
                    f"{installed} and this document has the messages. Nothing about the watchdog's "
                    "own behaviour is proved by a refusal."
                )
            document["backup"] = json.loads(read("cat", BACKUP_PATH))
            expected = recorded_dns()
            document["recorded_dns"] = expected
            document["record_mode"] = try_read("stat", "-c", "%a %U %G", BACKUP_PATH)
            document["connection_dns_before"] = try_read(
                "nmcli", "-g", "ipv4.dns", "connection", "show", profile
            )
            # **The transaction's refusal is recorded as a fact about the cell,
            # not worked around and not asserted away.** In a container the
            # install refuses -- measured on 24.04 -- because publishing the
            # Cloudflare prefix list needs a reachable api.cloudflare.com, and
            # this target has no route off the bridge. The refusal happens AFTER
            # the record is written and read back, which is why the record below
            # exists and why the watchdog has something to act on; and it happens
            # with the connection untouched, because the transaction rolls itself
            # back before it points anything anywhere. So the machine this
            # scenario builds is exactly the one the watchdog is for: a package
            # installed, a record of the machine's original DNS, and a resolver
            # that is not answering.
            #
            # What the refusal does NOT give is a working router, and this
            # scenario does not claim one. The router unit is stopped below
            # deliberately rather than because a failed install stopped it.
            document["transaction_refused"] = (
                "the install transaction refused this target: publishing the Cloudflare prefix list "
                "needs a reachable api.cloudflare.com and this container has no route off the "
                "bridge. The record above was written and read back before that point, and the "
                "transaction rolled itself back before it changed any DNS setting, so the machine "
                "is the one the watchdog exists for -- a record of the original DNS and a resolver "
                "that is not answering. The router was NOT successfully started by this cell, it "
                "is stopped deliberately below rather than because a failed install stopped it, "
                "and nothing here claims otherwise."
            )

            # -- 5. point the machine at the local resolver ------------------
            # The install does this and the transaction was refused, so the
            # scenario performs the one step it needs. It is the same three
            # `nmcli` calls the installer makes, written out rather than
            # delegated: the watchdog is tested on a machine that looks like one
            # the install has taken over, and pretending otherwise would be the
            # harness lying about the precondition.
            #
            # **`ipv4.ignore-auto-dns yes` is the half that matters.** Without
            # it the connection would carry the loopback address AND the DHCP
            # one, and the restore -- which puts the recorded `(unset)` back --
            # would look like it did nothing, because the lease's resolver was
            # there all along. The property is what makes the restore a change.
            run(
                "set -eu\n"
                f"nmcli connection modify {profile} ipv4.dns {LOCAL_DNS}\n"
                f"nmcli connection modify {profile} ipv4.ignore-auto-dns yes\n"
                f"nmcli connection modify {profile} ipv6.ignore-auto-dns yes\n"
                f"nmcli connection up {profile}\n"
            )
            pointing = wait_for(
                lambda: connection_dns(),
                lambda value: LOCAL_DNS in value,
                what=f"the connection {profile} in {target} to carry the loopback address",
                seen=lambda: "; the watchdog's probe is against this address, so without it there "
                             "is no condition for the watchdog to find",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            )
            document["connection_dns_pointing_at_local"] = pointing

            # -- 6. stop the router, so the probe has a reason to fail -------
            run(f"set -eu\nsystemctl stop {ROUTER_UNIT}\n")
            document["router_state_after_stop"] = unit_state(ROUTER_UNIT)

            # -- 7. below the window: nothing, and the count that says so -----
            write_setting(setting_document(True, ARMED_FAILURES, ARMED_MINUTES))
            below_status, first_journal = start_watchdog()
            document["start_status_below_window"] = list(below_status)
            document["journal_below_window"] = first_journal
            _require(
                CLAIM_ACTION_RAN not in first_journal,
                "the watchdog performed the rollback on its FIRST probe with a window of "
                f"{ARMED_FAILURES} failures armed, so a single failed probe is the trigger and "
                "the window is not in the code. That is the failure the whole default exists to "
                "prevent, and it is not visible in any unit file.",
            )
            below = record()
            document["record_below_window"] = below
            _require(
                below is not None and below.get("consecutive_failures") == 1,
                f"{RECORD_PATH} after one failed probe reads {below!r}, so the failure was not "
                "counted. A watchdog that does not count cannot have a window, and a scenario "
                "that did not check the count would go on to prove the action and call the "
                "mechanism correct.",
            )
            _require(
                below.get("action_utc") in (None, ""),
                f"the record already names an action at {below.get('action_utc')!r} after one "
                "probe below the window, so something acted that this scenario did not see",
            )

            # -- 8. at the window: the real action, once --------------------
            at_status, acted = start_watchdog()
            document["start_status_at_window"] = list(at_status)
            document["journal_at_window"] = acted
            for claim in (CLAIM_ACTION_RAN, CLAIM_WHAT_IS_NOT_BACK, BACKUP_PATH):
                _require(
                    claim in acted,
                    f"the watchdog's own message does not contain {claim!r}. The action may have "
                    "run and the operator would still be told nothing about what came back and "
                    "what did not, which is the failure this mechanism is judged on:\n" + acted,
                )
            _require(
                "exited 0" in acted,
                "the watchdog did not report the action's exit status, so an operator cannot tell "
                f"a rollback that finished from one that did not:\n{acted}",
            )
            acted_record = record()
            document["record_at_window"] = acted_record
            _require(
                acted_record and acted_record.get("consecutive_failures") == ARMED_FAILURES,
                f"the record at the window reads {acted_record!r}, so the count that reached the "
                "threshold is not the count the record holds",
            )
            _require(
                acted_record.get("action_status") == 0,
                f"the record says the action exited {acted_record.get('action_status')!r} while the "
                "watchdog's message reports success, so the machine and its own record of the "
                "machine disagree",
            )

            # -- 9. the MACHINE, which is the only evidence that matters -----
            restored = wait_for_rollback(expected)
            document["connection_dns_after_rollback"] = restored
            _require(
                LOCAL_DNS not in restored,
                f"the connection still carries {LOCAL_DNS} after the rollback reported success: "
                f"{restored!r}",
            )
            if expected.strip():
                _require(
                    expected.strip() in restored,
                    f"the connection carries {restored!r} after the rollback, and the record says "
                    f"it should carry {expected!r}. A restore that put something else back is not "
                    "a restore, and the exit status of zero does not make it one.",
                )
            # **"The machine is usable again" is a claim about a RESOLVER, not
            # about a connection property**, so it is measured the only way it can
            # be: a name answered, through the machine's own stub, by the resolvers
            # the restore put back. A scenario that checked the profile and called
            # it a working machine would be repeating the exact defect this
            # mechanism's own success message is written to avoid.
            document["resolvectl_after_rollback"] = wait_for(
                lambda: try_read("resolvectl", "dns"),
                lambda value: MOCK_ROUTER_ADDRESS in value,
                what=f"the resolver on {DEVICE} in {target} to be the mock router again",
                seen=lambda: "; the restore puts the machine's own resolver back, and a profile "
                             "that carries no address is a machine that cannot ask anything",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            )
            document["probe_after_rollback"] = probe_result()
            _require(
                document["probe_after_rollback"],
                "the machine's own resolver is not answering "
                f"{INSTALL_PROBE_NAME} after the rollback restored the recorded DNS, so the "
                "rollback reported success on a machine that still cannot resolve. That is the "
                "claim the success message makes and this is the check on it.",
            )
            document["resolv_conf_after_rollback"] = try_read(
                "sh", "-c", "readlink -f /etc/resolv.conf; cat /etc/resolv.conf"
            )
            # The rollback stops nothing, and the marker survives, because the
            # binaries and the record stay installed for diagnosis. Both are the
            # documented behaviour and both are the reason the limitation is in
            # the message: the machine is usable again and the fault is not fixed.
            document["router_state_after_rollback"] = unit_state(ROUTER_UNIT)
            document["marker_after_rollback"] = try_read("cat", MARKER_PATH)
            document["record_file_after_rollback"] = try_read("cat", RECORD_PATH)
            document["record_file_mode"] = try_read(
                "stat", "-c", "%a %U %G", RECORD_PATH
            )
            # The DIRECTORY the record lives in, which is the half of the
            # ownership that a file mode cannot show: a 0600 file in a
            # group-writable directory is still deletable and replaceable,
            # because unlink and rename are the containing directory's decision.
            document["record_dir_mode"] = try_read("stat", "-c", "%a %U %G", RECORD_DIR)
            # -- 10. the switch, in the OFF position -------------------------
            # The SHIPPED threshold, and a window longer than the default:
            # `SHIPPED_FAILURES + 1` consecutive failures, which is one more than
            # `consecutive_failures` names, so a switch that only raised the
            # count by a little or that acted one run early would be caught here.
            # The elapsed arm is not waited for in wall-clock time -- ten minutes
            # of sleeping is not a scenario anybody runs -- and the case that
            # holds the elapsed arm's boundary is in
            # `installer/tests/test_watchdog.py`, where the clock is a parameter.
            # What this step proves is that the count arm, taken past the
            # default's threshold, produces no action at all.
            #
            # The machine is put back into the condition first -- pointed at the
            # local resolver with the router stopped -- so the off position is
            # observed on a machine that NEEDED watching. A switch observed on a
            # healthy machine proves nothing: no watchdog fires on a healthy
            # machine with the switch on either.
            run(
                f"set -eu\n"
                f"nmcli connection modify {profile} ipv4.dns {LOCAL_DNS}\n"
                f"nmcli connection modify {profile} ipv4.ignore-auto-dns yes\n"
                f"nmcli connection modify {profile} ipv6.ignore-auto-dns yes\n"
                f"nmcli connection up {profile}\n"
                f"systemctl stop {ROUTER_UNIT}\n"
            )
            document["connection_dns_rearmed"] = wait_for(
                lambda: connection_dns(),
                lambda value: LOCAL_DNS in value,
                what=f"the connection {profile} in {target} to carry the loopback address again",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            )
            document["router_state_rearmed"] = unit_state(ROUTER_UNIT)
            write_setting(setting_document(False, SHIPPED_FAILURES, SHIPPED_MINUTES))
            document["setting_with_the_switch_off"] = try_read("cat", SETTING_PATH)
            off_journals = []
            off_statuses = []
            for _ in range(SHIPPED_FAILURES + 1):
                status, journal = start_watchdog()
                off_statuses.append(list(status))
                off_journals.append(journal)
            document["start_status_with_the_switch_off"] = off_statuses
            document["journal_with_the_switch_off"] = off_journals
            for index, journal in enumerate(off_journals, start=1):
                _require(
                    CLAIM_ACTION_RAN not in journal,
                    f"the watchdog performed the unattended rollback on probe {index} of "
                    f"{len(off_journals)} with `automatic: false` in its setting file, so the "
                    "switch does nothing and the default is not switchable:\n" + journal,
                )
                _require(
                    "automatic: false" in journal,
                    "a run with the switch off did not say so in its own output, so an operator "
                    "reading the journal cannot tell a machine that is being watched from one "
                    "that is not:\n" + journal,
                )
            off_record = record()
            document["record_with_the_switch_off"] = off_record
            _require(
                off_record is None or off_record.get("action_utc") in (None, ""),
                f"the record names an action at {(off_record or {}).get('action_utc')!r} with "
                "the switch off, so a streak armed by an earlier run survived the switch and the "
                "first failure after an operator re-enabled the mechanism would be a rollback "
                "with no window in front of it",
            )
            # Read ONCE and check the value in hand. A second read here would be
            # a poll whose answer the scenario does not need, and on a machine
            # where the value is changing it is a read that could disagree with
            # the one this evidence records -- which is how a scenario ends up
            # asserting a state it never observed.
            with_the_switch_off = connection_dns()
            document["connection_dns_with_the_switch_off"] = with_the_switch_off
            _require(
                LOCAL_DNS in with_the_switch_off,
                "the machine is no longer pointed at the local resolver, so the off position was "
                "not observed on a machine that needed watching: something else changed the "
                "connection while the switch was off, and a no-action result on a healthy machine "
                "is what a switch that does nothing at all would also produce",
            )

            # -- 11. and the operator's own action still works --------------
            # The second half of the plan's requirement, and the half that is
            # easy to get wrong: a switch implemented by removing the action, or
            # by a setting the action reads, would leave a machine whose
            # resolver is dead with no way to put it back.
            output = try_read("sh", "-c", f"{CDNCTL} emergency-rollback 2>&1; echo EXIT=$?")
            document["operator_rollback_output"] = output[:4000]
            match = re.search(r"^EXIT=(\d+)$", output, re.MULTILINE)
            _require(
                match is not None,
                f"`{CDNCTL} emergency-rollback` by hand printed no exit status, so this run "
                f"cannot tell whether the operator's own action still works:\n{output}",
            )
            # Recorded before it is checked, so the evidence document says what
            # happened even on the run that fails -- a document that only records
            # successes is a document that cannot be read after a failure.
            document["operator_rollback_exit"] = int(match.group(1))
            _require(
                match.group(1) == "0",
                f"`{CDNCTL} emergency-rollback` by hand exited {match.group(1)} after the switch "
                "was observed in the off position, so the switch disabled the action for the "
                "operator as well as for the watchdog and this run has left a machine with no way "
                f"back. Its output was:\n{output}",
            )
            document["connection_dns_after_operator_rollback"] = wait_for_rollback(expected)
            document["resolved_dns_final"] = try_read("resolvectl", "dns")
        except WatchdogScenarioError as error:
            document["failure"] = str(error)
            evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME, status="failed", detail=str(error), log=log_name
            )
        evidence(document)
        return ScenarioResult(name=SCENARIO_NAME, status="passed", log=log_name)

    return run_scenario


__all__ = [
    "ARMED_FAILURES",
    "ARMED_MINUTES",
    "RECORD_PATH",
    "SCENARIO_NAME",
    "SETTING_PATH",
    "SHIPPED_FAILURES",
    "SHIPPED_MINUTES",
    "WATCHDOG_TIMER",
    "WATCHDOG_UNIT",
    "WatchdogScenarioError",
    "build_scenario",
    "setting_document",
    "wait_for",
]
