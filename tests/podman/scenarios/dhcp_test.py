"""The DHCP scenario: NetworkManager obtains an address by DHCP, and the DNS moves.

The plan's Task 3 wants a scenario that proves three things, and all three are
about a running target rather than about a file:

1. NetworkManager obtains IPv4 **by DHCP** and publishes the mock router's DNS;
2. the mock router is reconfigured, and
3. the target's NetworkManager **reports a new** DNS address.

**Every step below is here because of something measured on this host**, and the
measurements are the reason three of the steps look the way they do.

* **The target has to be given `NET_RAW` to get a lease at all.** With the
  capabilities the plan originally listed, NetworkManager reaches "getting IP
  configuration" and then fails with *IP configuration could not be reserved
  (no available address, timeout)* while its journal says
  `dhcp4 (eth0): error -1 dispatching events`. That is the DHCP client being
  unable to open the `AF_PACKET` socket it sends and receives DORA on, and it is
  not a property of the mock router -- the same target leases an address
  immediately once the capability is there. `tests/podman/lib/podman.py` carries
  the measurement and emits the flag for every target.

* **The address the scenario reads is not the evidence; the address being one
  the pool could have handed out is.** Podman gives the target `10.89.0.10` on
  the bridge, so "the target has an IPv4 address" is true before a single DHCP
  packet crosses the network. The pool is `10.89.0.100-10.89.0.199` and the fixed
  addresses sit outside it, deliberately, so a lease and a fixed address cannot
  be confused for one another.

* **SIGHUP does not re-read dnsmasq's configuration file.** `dnsmasq(8)` says so
  in its NOTES section: *"SIGHUP does NOT re-read the configuration file."* It
  re-reads `/etc/hosts`, `/etc/ethers` and the files named by `--dhcp-hostsfile`,
  `--dhcp-optsfile` and friends, and an option in `--dhcp-optsfile` takes
  precedence over `dhcp-option`. So the control command rewrites
  `DNS_OPTION_FILE` -- a path declared in the shipped config, inside the
  container's own filesystem and absent from the checkout -- and sends the
  signal. Rewriting `/etc/dnsmasq.conf` and sending SIGHUP changes nothing at
  all, and a scenario built that way reports a *stale* baseline as a pass.

**And the reload is waited for rather than slept for.** `nmcli connection up`
returns before the device has an address; reading `IP4.DNS` on the next line
reads a field that is not there yet, and sleeping reads it at an arbitrary later
moment. Both pass on a fast machine and fail on a loaded one. `wait_for` is
bounded, and its failure names the field, the value it kept reading, the address
it was waiting for and the budget -- because a message that says only "timed
out" sends a reader to the mock router.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

from podman import PodmanError
from report import ScenarioResult

# -- the plan's private network ------------------------------------------------
#
# All four fixed addresses and the pool, written out rather than computed. These
# are the plan's, they are quoted in the scenario's failure messages, and a
# scenario that derived them would be unable to say what it expected.

NETWORK_SUBNET = "10.89.0.0/24"
MOCK_ROUTER_ADDRESS = "10.89.0.2"
TARGET_ADDRESS = "10.89.0.10"
MOCK_CDN_ADDRESS = "10.89.0.20"
CLIENT_ADDRESS = "10.89.0.30"
DHCP_POOL_FIRST = "10.89.0.100"
DHCP_POOL_LAST = "10.89.0.199"

# The device the bridge gives a target, and the profile the image's
# `target-nm-setup.service` created for it at boot. The scenario *modifies* that
# profile and never creates a second one: on 24.04 and 26.04 the active
# connection on arrival is NetworkManager's own `eth0`, and `connection up` on
# the image's profile is what hands the device over.
DEVICE = "eth0"
CONNECTION_PROFILE = "eth0-managed"

# The file dnsmasq re-reads on SIGHUP, declared by the shipped config. It is
# inside the mock router's own filesystem and does not exist in the checkout, so
# a control command that writes it cannot be writing the source tree.
DNS_OPTION_FILE = "/etc/dnsmasq-dhcp-opts"
# DHCP option 6. The number, not the name, because that is the form the option
# file takes.
DNS_OPTION_NUMBER = 6
# The lease file dnsmasq writes, which is the DHCP server's own record of what
# it leased and to whom. Evidence in its own right, and the one artefact here
# that outlives the process.
ROUTER_LEASE_FILE = "/var/lib/mosdns-mock-router/dnsmasq.leases"
# The file the *package* publishes the lease into, read so a later task that
# installs it records the document rather than having to grow this scenario. It
# is absent in this task, and its absence is recorded as absence.
DHCP_STATE_FILE = "/run/mosdns/dhcp-upstreams.json"

SCENARIO_NAME = "dhcp"

# How long to wait for NetworkManager to *report* something, and how long to sit
# still between attempts. The bounds are generous because a matrix cell shares a
# machine with whatever else is running on it, and generous in the safe
# direction: a scenario that waited too little fails loudly with what it saw, and
# a scenario that waited too long only wastes the run.
DEFAULT_WAIT_SECONDS = 90.0
WAIT_INTERVAL_SECONDS = 5.0
# The profile activation itself is `nmcli`'s own 45-second DHCP transaction, so
# the wait after it is the wait for *NetworkManager* to catch up with it.
ACTIVATION_WAIT_SECONDS = 120.0

_DOTTED_QUAD = re.compile(r"(?<!\d)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d)")
# A value matches an address only as a whole one. `10.89.0.2` must not satisfy a
# wait for `10.89.0.20`, and the dot-adjacent guards are what say so: a wait
# that matched the shorter address inside the longer one would report a reload
# that never happened as a success.
_VALUE_BOUNDARY = r"(?<![\w.])"
_VALUE_END = r"(?![\w.])"

# dnsmasq's own words for the four messages, in the order they arrive. Read out
# of the router's log rather than inferred from the target, because the log is
# the process that owns the pool saying what it did.
_DHCP_EVENTS = (
    ("DHCPDISCOVER", "DISCOVER"),
    ("DHCPOFFER", "OFFER"),
    ("DHCPREQUEST", "REQUEST"),
    ("DHCPACK", "ACK"),
)


class DhcpScenarioError(Exception):
    """A DHCP claim the run could not establish, with the evidence attached.

    Its own type rather than the harness's `PodmanError`, because a failed
    *assertion* inside a scenario is a test failure -- exit 1, a `failed` row in
    the report -- and a harness fault is exit 2. A scenario that raised the
    harness's error for "the DNS did not change" would be reporting a broken
    matrix as a broken harness.
    """


def dns_option_line(address) -> str:
    """The one line that goes in `DNS_OPTION_FILE`, or a refusal.

    **Validated here because the line is written with `sh -c`.** The address is
    interpolated into a script the scenario passes to `podman exec`, so a value
    that were not a dotted quad would be a second command rather than a
    configuration. The check is on the shape and the refusal names the shape, so
    a caller that passed something else is told what it passed.
    """
    text = str(address or "")
    if not _DOTTED_QUAD.fullmatch(text) or not all(
        0 <= int(part) <= 255 for part in text.split(".")
    ):
        raise DhcpScenarioError(
            f"refusing to write {address!r} into {DNS_OPTION_FILE}: a DHCP option value has to be "
            f"a dotted-quad IPv4 address, and this scenario writes it through 'sh -c', so "
            f"anything else would be a second command rather than an option. (The addresses the "
            f"plan fixes are {MOCK_ROUTER_ADDRESS} and {MOCK_CDN_ADDRESS}.)"
        )
    return f"{DNS_OPTION_NUMBER},{text}"


def _holds_value(text: str, expected: str) -> bool:
    """Whether `text` carries `expected` as a whole value.

    `nmcli -g` answers a device field with one address, a connection's
    `DHCP4.OPTION` with a ` | `-separated list, and `resolvectl dns` with
    `Link 2 (eth0): 10.89.0.2`. All three are read by the same predicate so a
    wait does not have to know which of them it is looking at -- and the
    boundary guards are what stop `10.89.0.2` from satisfying a wait for
    `10.89.0.20`.
    """
    return re.search(_VALUE_BOUNDARY + re.escape(expected) + _VALUE_END, text or "") is not None


def wait_for(
    read: Callable[[], str],
    expected: str,
    *,
    what: str,
    timeout: float = DEFAULT_WAIT_SECONDS,
    interval: float = WAIT_INTERVAL_SECONDS,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    accept: Callable[[str], bool] | None = None,
) -> str:
    """Poll `read` until it reports `expected`, and return what it reported.

    Bounded, and the two seams -- `now` and `sleep` -- are parameters so a case
    can drive the whole thing without waiting for it. That is not a convenience:
    a wait whose timing cannot be exercised in a unit test is a wait whose
    *failure path* is untested, and the failure path is the one that runs when
    the harness is wrong.

    `accept` replaces the "does it carry this address" test for a field whose
    *readiness* is what is being waited on -- `IP4.ADDRESS` has no expected
    value, only the moment nmcli stops answering with an empty line -- so the
    bounded loop and the message stay one implementation rather than two.

    A read that raises is treated as "not yet" and its message is kept. `nmcli`
    exits non-zero when the device is not there yet, which after an activation is
    a normal state and not a crash; but a wait that swallowed every error would
    report the same "gave up" for a target whose device had disappeared and for
    one whose DNS never changed, so the last diagnostic is in the failure.
    """
    deadline = now() + timeout
    test = accept or (lambda value: _holds_value(value, expected))
    last_value: str | None = None
    last_error: str | None = None
    polls = 0
    while True:
        polls += 1
        try:
            value = str(read() or "").strip()
            last_value = value
            if test(value):
                return value
        except PodmanError as error:
            last_error = str(error)
        if now() >= deadline:
            break
        sleep(interval)
    seen = f"read {last_value!r}" if last_value is not None else "never got an answer"
    if last_error:
        seen += f" (the last command failed: {last_error.splitlines()[-1]})"
    raise DhcpScenarioError(
        f"{what} {seen}, and it still did not report {expected!r} after {timeout:g}s and {polls} "
        f"reads {interval:g}s apart. That means the value did not arrive rather than that the "
        f"read was never made, so the thing to look at is whatever produces it: for IP4.DNS that "
        f"is the mock router's dnsmasq log and the SIGHUP that was sent to it."
    )


def _address_in_pool(address: str, first: str, last: str) -> bool:
    """Whether `address` is one the DHCP pool could have handed out.

    The whole "by DHCP" claim, reduced to something checkable: podman gave the
    target `10.89.0.10` before any packet crossed, so an address is only evidence
    if the pool could have produced it and the fixed addresses could not have
    been mistaken for it.
    """
    def parts(value):
        match = _DOTTED_QUAD.fullmatch(str(value or ""))
        if not match or not all(0 <= int(part) <= 255 for part in match.groups()):
            return None
        return tuple(int(part) for part in match.groups())

    candidate = parts(address)
    if candidate is None:
        return False
    low, high = parts(first), parts(last)
    return low is not None and high is not None and low <= candidate <= high


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DhcpScenarioError(message)


def _read(podman, container, *command):
    """One command inside a container, as stripped text.

    `check=True` is already the wrapper's policy, so a non-zero status is a
    `PodmanError` and the wait treats it as "not yet".
    """
    return podman.exec_container(container, *command).output


def _record(podman, container, *command):
    """One command inside a container, for a value the scenario only **records**.

    A record must not be able to fail the run. The first read of the active
    connection is the case: it is taken before the hand-off purely so the
    evidence document says what the device was doing on arrival, and a live
    24.04 cell answered `exited 8` to it because the device was mid-transition
    after boot -- so the cell was reported `failed` for a value no assertion was
    made about. The claim the scenario makes is "the hand-off works and the DNS
    moves"; the read is evidence for a reader, not a claim.

    The error is kept as the value, because "the device was not readable yet" is
    itself the honest answer for that field at that moment, and an empty string
    would be indistinguishable from a device that had no connection.
    """
    try:
        return podman.exec_container(container, *command).output
    except PodmanError as error:
        return f"(not readable: {str(error).splitlines()[-1]})"


def _option_value(text: str, name: str) -> str | None:
    """One `DHCP4.OPTION` entry, as the value after its name.

    `nmcli -g DHCP4.OPTION connection show …` answers a single line of
    `name = value` pairs separated by ` | `, with backslash-escaped colons. The
    option the DHCP *lease* carried is the second half of the claim that the DNS
    came from DHCP: `IP4.DNS` is what NetworkManager published, and this is what
    it published it from.
    """
    for entry in (text or "").split("|"):
        key, separator, value = entry.partition("=")
        if separator and key.strip() == name:
            return value.strip()
    return None


def _default_routes_through(routes: str, gateway: str) -> list[str]:
    """Every `default` route in `ip route` output that goes through `gateway`."""
    found = []
    for line in (routes or "").splitlines():
        fields = line.split()
        if not fields or fields[0] != "default":
            continue
        if "via" in fields and gateway in fields[fields.index("via") + 1:fields.index("via") + 2]:
            found.append(line.strip())
    return found


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
    wait_seconds: float = DEFAULT_WAIT_SECONDS,
    interval: float = WAIT_INTERVAL_SECONDS,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Callable[[], ScenarioResult]:
    """The `dhcp` scenario, bound to one matrix cell's two containers.

    Returned as a zero-argument callable because that is what `run.py`'s scenario
    loop calls, and bound rather than global because a cell has its own target,
    its own router and its own run id -- and because a scenario that reached for
    a global container name would be measuring whichever container happened to
    be running.
    """
    log_name = f"logs/{version}-{SCENARIO_NAME}.json"
    log_path = Path(results_dir) / run_id / log_name

    def record() -> dict:
        return {
            "arch": arch,
            "device": DEVICE,
            "profile": CONNECTION_PROFILE,
            "network": network,
            "router_container": router,
            "target_container": target,
            "subnet": NETWORK_SUBNET,
            "pool": f"{DHCP_POOL_FIRST}-{DHCP_POOL_LAST}",
            "mock_router_address": MOCK_ROUTER_ADDRESS,
            "mock_cdn_address": MOCK_CDN_ADDRESS,
        }

    def read_field(container, *command):
        return lambda: _read(podman, container, *command)

    def write_evidence(document: dict) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def run() -> ScenarioResult:
        document = record()
        try:
            # -- 0. what the device was doing before the hand-off ----------
            # Recorded, not asserted. The plan's measured fact is that on 24.04
            # and 26.04 the active connection on arrival is NetworkManager's own
            # `eth0`, because the bridge gave the interface its address outside
            # NetworkManager -- and asserting that here would be a claim about
            # one release, not about the hand-off this scenario performs.
            document["active_connection_before"] = _record(
                podman, target, "nmcli", "-g", "GENERAL.CONNECTION", "device", "show", DEVICE
            )

            # -- 1. hand the device to the image's profile -------------------
            # `ipv4.never-default yes` is set *before* the activation that
            # re-runs DHCP, and not in the image: the plan makes it a post-boot
            # scenario change, and the reason is right here. dnsmasq offers
            # `option:router 10.89.0.2`, so a lease handed to a profile that will
            # install a default gateway would put the mock router on the target's
            # default path for the whole matrix.
            podman.exec_script(
                target,
                "set -eu\n"
                f"nmcli connection modify {CONNECTION_PROFILE} ipv4.never-default yes\n"
                f"nmcli connection up {CONNECTION_PROFILE}\n",
            )

            # -- 2. the hand-off, asserted ----------------------------------
            # Checked *before* the reload, so a target whose profile never took
            # the device fails here and names the hand-off. Left until after the
            # reload, the same target fails the reload assertion and sends a
            # reader to the mock router, which is innocent.
            active = wait_for(
                read_field(target, "nmcli", "-g", "GENERAL.CONNECTION", "device", "show", DEVICE),
                CONNECTION_PROFILE,
                what=f"the active connection on {DEVICE} in {target}",
                timeout=ACTIVATION_WAIT_SECONDS,
                interval=interval,
                now=now,
                sleep=sleep,
            )
            document["active_connection_after"] = active
            managed = _read(podman, target, "nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", DEVICE)
            _require(
                managed == "yes",
                f"NetworkManager does not manage {DEVICE} in {target} after the hand-off: "
                f"'nmcli -g GENERAL.NM-MANAGED device show {DEVICE}' answered {managed!r}, not 'yes'. "
                f"The image's target-nm-setup.service creates {CONNECTION_PROFILE} and asserts this "
                f"at boot, so a 'no' here means the boot check passed and the device was unmanaged "
                f"afterwards.",
            )

            # -- 3. the lease, and the evidence that it is one ---------------
            # Waited for by *emptiness*, not by a value: `nmcli -g IP4.ADDRESS`
            # answers an empty line until NetworkManager has configured the
            # device, and the address itself is checked immediately below
            # against the pool.
            address_field = wait_for(
                read_field(target, "nmcli", "-g", "IP4.ADDRESS", "device", "show", DEVICE),
                "an IPv4 address",
                what=f"IP4.ADDRESS on {DEVICE} in {target}",
                timeout=ACTIVATION_WAIT_SECONDS,
                interval=interval,
                now=now,
                sleep=sleep,
                accept=lambda value: bool(value.strip()),
            )
            lease_address = address_field.split("/")[0].strip()
            _require(
                _address_in_pool(lease_address, DHCP_POOL_FIRST, DHCP_POOL_LAST),
                f"{target} has the address {lease_address!r}, which is not one the mock router's pool "
                f"{DHCP_POOL_FIRST}-{DHCP_POOL_LAST} could have handed out. Podman gave this "
                f"container {TARGET_ADDRESS} on the bridge, so an address outside the pool is the "
                f"bridge's own and not a lease -- which means the target's NetworkManager never "
                f"asked, and the mock router's log will show no DISCOVER for it.",
            )
            document["lease_address"] = lease_address

            # -- 4. the DNS the lease carried, and the DNS NM published -------
            dns_before = wait_for(
                read_field(target, "nmcli", "-g", "IP4.DNS", "device", "show", DEVICE),
                MOCK_ROUTER_ADDRESS,
                what=f"IP4.DNS on {DEVICE} in {target}",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            )
            document["dns_before"] = dns_before
            lease_dns_before = _option_value(
                _read(podman, target, "nmcli", "-g", "DHCP4.OPTION", "connection", "show", CONNECTION_PROFILE),
                "domain_name_servers",
            )
            _require(
                _holds_value(lease_dns_before or "", MOCK_ROUTER_ADDRESS),
                f"the lease on {CONNECTION_PROFILE} does not carry the mock router as a resolver: "
                f"'nmcli -g DHCP4.OPTION connection show {CONNECTION_PROFILE}' answered "
                f"domain_name_servers = {lease_dns_before!r}, and {MOCK_ROUTER_ADDRESS} was "
                f"expected. IP4.DNS says {dns_before!r}, so the address on the device did not come "
                f"from DHCP.",
            )
            document["lease_dns_before"] = lease_dns_before
            document["resolved_dns_before"] = _read(podman, target, "resolvectl", "dns", DEVICE)

            # -- 5. the target is not routed through the mock router ---------
            never_default = _read(
                podman, target, "nmcli", "-g", "ipv4.never-default", "connection", "show", CONNECTION_PROFILE
            )
            document["ipv4_never_default"] = never_default
            routes = _read(podman, target, "ip", "route")
            document["routes"] = routes
            through_router = _default_routes_through(routes, MOCK_ROUTER_ADDRESS)
            _require(
                not through_router,
                f"{target} has a default route through the mock router: "
                f"{'; '.join(through_router)}. dnsmasq offers 'option:router {MOCK_ROUTER_ADDRESS}' "
                f"and the profile carries ipv4.never-default={never_default!r}, so either the "
                f"setting did not take or something outside this scenario installed the route. A "
                f"target routed through the mock router would send every packet a test run makes to "
                f"a dnsmasq that answers nothing, and the failure would look like a DNS problem.",
            )

            # -- 6. the router's own account of the exchange -----------------
            document["router_log"] = podman.container_logs(router)
            document["dhcp_events"] = _dhcp_events(document["router_log"])
            for event, token in _DHCP_EVENTS:
                _require(
                    event in document["router_log"],
                    f"the mock router's own log records no {event} for {target}. Without all four "
                    f"there is no DORA exchange across the bridge, whatever the target's "
                    f"NetworkManager says about its own address. The log is:\n"
                    f"{document['router_log'][-2000:]}",
                )
            _require(
                _holds_value(document["router_log"], MOCK_ROUTER_ADDRESS),
                f"the mock router's log does not mention {MOCK_ROUTER_ADDRESS} at all, so the "
                f"DNS on the target cannot be attributed to it.",
            )
            document["router_lease_file"] = _read(podman, router, "cat", ROUTER_LEASE_FILE)
            document["network_manager_dhcp_events"] = _network_manager_events(
                _read(podman, target, "journalctl", "-u", "NetworkManager", "--no-pager")
            )
            document["dhcp_upstreams_state_file"] = _read_state_file(podman, target)
            document["dhcp_upstreams_state_file_note"] = (
                f"{DHCP_STATE_FILE} is not present in {target}: nothing in this task publishes it. "
                f"It is the *package's* state document -- bridge/mosdns_dhcp_bridge writes it, and "
                f"the installer reads it back to restore the machine's original DNS -- so its "
                f"absence here means the package is not installed, and it is recorded as absence "
                f"rather than as an empty document, which would read as 'the bridge published "
                f"nothing'."
            )

            # -- 7. reload the router ----------------------------------------
            document["dns_reload_to"] = MOCK_CDN_ADDRESS
            podman.exec_script(
                router,
                "set -eu\n" + f"printf '%s\\n' '{dns_option_line(MOCK_CDN_ADDRESS)}' > {DNS_OPTION_FILE}\n",
            )
            # SIGHUP, and the signal reaches dnsmasq itself because the image
            # runs it as PID 1 with `--keep-in-foreground`. SIGHUP does not
            # re-read `/etc/dnsmasq.conf`; it re-reads this file, which is why
            # this is the file the control command writes.
            podman.signal_container(router, "HUP")
            # And the target has to ask again. A lease is not renegotiated on a
            # timer the scenario controls, and NetworkManager will not re-DHCP
            # because a packet arrived somewhere on the network -- so the
            # profile is re-activated, which is what the plan's step 4 does and
            # what produces the second transaction.
            podman.exec_script(
                target,
                "set -eu\n" f"nmcli connection up {CONNECTION_PROFILE}\n",
            )

            # -- 8. the new DNS, waited for ---------------------------------
            document["dns_after"] = wait_for(
                read_field(target, "nmcli", "-g", "IP4.DNS", "device", "show", DEVICE),
                MOCK_CDN_ADDRESS,
                what=f"IP4.DNS on {DEVICE} in {target} after the mock router was reloaded",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            )
            lease_dns_after = _option_value(
                _read(podman, target, "nmcli", "-g", "DHCP4.OPTION", "connection", "show", CONNECTION_PROFILE),
                "domain_name_servers",
            )
            _require(
                _holds_value(lease_dns_after or "", MOCK_CDN_ADDRESS),
                f"the second lease on {CONNECTION_PROFILE} does not carry {MOCK_CDN_ADDRESS} as a "
                f"resolver: 'nmcli -g DHCP4.OPTION connection show {CONNECTION_PROFILE}' answered "
                f"domain_name_servers = {lease_dns_after!r}. IP4.DNS reads "
                f"{document['dns_after']!r}, so the address on the device came from somewhere the "
                f"DHCP exchange did not put it.",
            )
            document["lease_dns_after"] = f"domain_name_servers = {lease_dns_after}"
            resolved_after = wait_for(
                read_field(target, "resolvectl", "dns", DEVICE),
                MOCK_CDN_ADDRESS,
                what=f"resolvectl dns {DEVICE} in {target} after the mock router was reloaded",
                timeout=wait_seconds,
                interval=interval,
                now=now,
                sleep=sleep,
            )
            document["resolved_dns_after"] = resolved_after

            # -- 9. the router's account of the reload -----------------------
            document["router_log_after_reload"] = podman.container_logs(router)
            _require(
                f"read {DNS_OPTION_FILE}" in document["router_log_after_reload"],
                f"dnsmasq did not report re-reading {DNS_OPTION_FILE} after the SIGHUP, so the "
                f"option file the control command wrote was never consulted and any change in the "
                f"target's DNS came from somewhere else. The log is:\n"
                f"{document['router_log_after_reload'][-2000:]}",
            )
            _require(
                re.search(rf"option:\s*\d+\s+dns-server\s+{re.escape(MOCK_CDN_ADDRESS)}\b",
                          document["router_log_after_reload"]) is not None,
                f"dnsmasq's log after the reload records no option 6 of {MOCK_CDN_ADDRESS}, so it "
                f"never offered the new address to any client. The log is:\n"
                f"{document['router_log_after_reload'][-2000:]}",
            )
            document["dhcp_events_after_reload"] = _dhcp_events(
                document["router_log_after_reload"]
            )
            document["routes_after_reload"] = _read(podman, target, "ip", "route")
            through_router = _default_routes_through(
                document["routes_after_reload"], MOCK_ROUTER_ADDRESS
            )
            _require(
                not through_router,
                f"{target} gained a default route through the mock router after the reload: "
                f"{'; '.join(through_router)}.",
            )
        except DhcpScenarioError as error:
            document["failure"] = str(error)
            write_evidence(document)
            return ScenarioResult(
                name=SCENARIO_NAME, status="failed", detail=str(error), log=log_name
            )
        write_evidence(document)
        return ScenarioResult(name=SCENARIO_NAME, status="passed", log=log_name)

    return run


def _dhcp_events(router_log: str) -> list[str]:
    """The DORA messages, in the order the router's log records them.

    Out of the router's own log rather than the target's, because the log is the
    process that owns the pool saying what it did, and a target that reports a
    lease is reporting a *consequence*.
    """
    events: list[str] = []
    for token, name in _DHCP_EVENTS:
        if token in (router_log or "") and name not in events:
            events.append(name)
    return events


def _network_manager_events(journal: str) -> list[str]:
    """The target's own DHCP lines, kept for the record.

    These are what a reader checks first when a later run fails, and they are the
    half of the evidence that lives in the target rather than in the router.
    """
    return [
        line.strip()
        for line in (journal or "").splitlines()
        if "dhcp" in line.lower() and line.strip()
    ]


def _read_state_file(podman, container) -> dict | None:
    """The package's DHCP state document, or `None` when nothing has written one.

    Read with `test -e` first because its absence is the expected answer in this
    task, and a `cat` of a missing file is a non-zero exit rather than a value.
    The return is a parsed document or `None`: an empty object would read as "the
    bridge published nothing", which is a different claim and a wrong one.
    """
    if podman.exec_status(container, "sh", "-c", f"test -e {DHCP_STATE_FILE}") != 0:
        return None
    try:
        return json.loads(_read(podman, container, "cat", DHCP_STATE_FILE))
    except json.JSONDecodeError as error:
        raise DhcpScenarioError(
            f"{DHCP_STATE_FILE} exists in {container} and is not JSON: {error}. The harness will "
            f"not record a document it cannot read as though it were one."
        ) from error


__all__ = [
    "ACTIVATION_WAIT_SECONDS",
    "CLIENT_ADDRESS",
    "CONNECTION_PROFILE",
    "DEFAULT_WAIT_SECONDS",
    "DHCP_POOL_FIRST",
    "DHCP_POOL_LAST",
    "DHCP_STATE_FILE",
    "DNS_OPTION_FILE",
    "DEVICE",
    "MOCK_CDN_ADDRESS",
    "MOCK_ROUTER_ADDRESS",
    "NETWORK_SUBNET",
    "SCENARIO_NAME",
    "TARGET_ADDRESS",
    "DhcpScenarioError",
    "build_scenario",
    "dns_option_line",
    "wait_for",
]
