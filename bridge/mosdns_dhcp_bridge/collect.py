"""Collect the router-supplied DHCP DNS addresses from NetworkManager.

NetworkManager is the only authority for which resolvers the router was told to
use, and the raw DHCP configuration is the only source that still holds those
addresses after ``ignore-auto-dns`` hides them from resolved. The collector is
therefore read-only and fail-closed: it runs fixed argument arrays, never a
shell string, treats an unreadable source as unavailable instead of guessing,
and returns only the addresses a domestic query could actually be sent to.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

__all__ = ["collect_dns", "is_interface_name", "normalize_upstreams", "usable_address"]

# A command runner takes one argument array and returns its standard output.
CommandRunner = Callable[[Sequence[str]], str]

Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# The kernel caps a device name at IFNAMSIZ-1 characters, so nothing longer can
# be a real interface. The accepted shape is deliberately narrow because the
# name reaches the published state file, and ``\Z`` rather than ``$`` keeps a
# trailing newline from ending the match. The character class is the same one
# Linux ``dev_valid_name()`` and ``state.DHCPState.Validate`` accept, so an
# interface this collector can name is an interface the state file can carry:
# a colon is rejected by both, which is why this pattern has none.
MAXIMUM_INTERFACE_NAME_LENGTH = 15
_INTERFACE_NAME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,%d}\Z" % (MAXIMUM_INTERFACE_NAME_LENGTH - 1)
)

# The dispatcher exports the DNS servers of the lease that just arrived, one
# variable per address family.
DISPATCHER_DNS_VARIABLES = ("DHCP4_DOMAIN_NAME_SERVERS", "DHCP6_DOMAIN_NAME_SERVERS")

# The raw DHCP option holds the addresses the router was configured with; the
# effective fields hold whatever NetworkManager is currently using, which is
# empty once ``ignore-auto-dns`` hides the lease. Both families are read one
# field at a time because a colon separates nmcli fields and appears inside
# every IPv6 address.
RAW_DHCP_FIELDS = ("DHCP4.OPTION_DOMAIN_NAME_SERVERS", "DHCP6.OPTION_DOMAIN_NAME_SERVERS")
EFFECTIVE_DNS_FIELDS = ("IP4.DNS", "IP6.DNS")

# A source separates its addresses with whitespace, commas, or semicolons, and
# systemd-resolved reports a scoped address in brackets.
SEPARATORS = re.compile(r"[\s,;]+")
BRACKETS = "[]"


def collect_dns(env: Mapping[str, str], interface: str, run: CommandRunner) -> List[str]:
    """Return the DHCP DNS addresses in use on ``interface``.

    ``env`` is the dispatcher environment of the current event, ``interface``
    the device that event is about, and ``run`` executes one read-only command
    and returns its standard output.

    The sources are consulted in a fixed order and the first one that yields a
    usable address wins outright, because a lower-priority source would
    otherwise contribute addresses the router is not configured to use. A
    source that cannot be read counts as unavailable. An empty list is a valid
    answer: it means no usable address is configured for this interface right
    now, which is not the same as a collection failure.
    """
    if not is_interface_name(interface):
        raise ValueError(
            "interface must be a network interface name of at most "
            f"{MAXIMUM_INTERFACE_NAME_LENGTH} characters, got {interface!r}"
        )

    for source in _sources(env, interface, run):
        addresses = source()
        if addresses:
            return addresses
    return []


def _sources(
    env: Mapping[str, str], interface: str, run: CommandRunner
) -> Iterator[Callable[[], List[str]]]:
    """Return one collector per source, highest priority first.

    The raw NetworkManager DHCP configuration is ranked above the dispatcher
    environment because it is the only source that still names the lease's
    resolvers once ``ignore-auto-dns`` keeps NetworkManager from passing them to
    resolved. The dispatcher environment is next because it is this event's own
    authoritative value, the effective device DNS is what is in use right now,
    and ``resolvectl`` is last because it reports the resolved view of the same
    facts and is filtered for local addresses in any case.
    """
    yield lambda: _nmcli_fields(interface, run, RAW_DHCP_FIELDS)
    yield lambda: _normalized(env.get(name, "") for name in DISPATCHER_DNS_VARIABLES)
    yield lambda: _nmcli_fields(interface, run, EFFECTIVE_DNS_FIELDS)
    yield lambda: _normalized([_read(run, ["resolvectl", "dns", interface])])


def _nmcli_fields(
    interface: str, run: CommandRunner, fields: Iterable[str]
) -> List[str]:
    """Read each nmcli device field with its own argument array."""
    return _normalized(
        _read(run, ["nmcli", "-g", field, "device", "show", interface])
        for field in fields
    )


def _normalized(outputs: Iterable[Optional[str]]) -> List[str]:
    """Return the usable addresses named by ``outputs``, deduplicated and ordered.

    Nothing here may raise: a source can report a value that is not an address
    at all, and a single unusable token must not discard the usable addresses
    reported next to it.
    """
    tokens = []
    for output in outputs:
        if not isinstance(output, str):
            continue
        tokens.extend(token.strip(BRACKETS) for token in SEPARATORS.split(output))
    return normalize_upstreams(tokens)


def normalize_upstreams(values: Iterable[str]) -> List[str]:
    """Return the usable addresses named by ``values``, deduplicated and ordered.

    This is the one definition of what an upstream list looks like, and the
    publisher reuses it so the two writers of an upstream set cannot disagree
    about which addresses survive or in which order they are recorded.
    """
    addresses = {address for address in map(usable_address, values) if address is not None}
    return sorted(addresses, key=_family_then_value)


def usable_address(token: str) -> Optional[str]:
    """Return the bare canonical address ``token`` names, or None if unusable.

    An empty result is not an error: a source may report anything at all, and a
    caller that needs a hard failure validates the returned value itself.
    """
    if not token or not isinstance(token, str):
        return None
    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        return None
    if not _usable_upstream(address):
        return None
    return str(address)


def _usable_upstream(address: Address) -> bool:
    """Report whether a domestic query can be forwarded to ``address``.

    Loopback, which covers the whole of 127/8 and the systemd-resolved stubs at
    127.0.0.53 and 127.0.0.54, the unspecified address, multicast, and IPv4
    link-local space all send the query back to this host. A scoped or
    IPv4-mapped address is ambiguous once the address is stored without the
    interface that gave it meaning. A bare IPv6 link-local address stays: the
    collector returns the interface next to it, and the Go plugin restores the
    scope when it builds an endpoint.
    """
    if address.version == 6 and (address.ipv4_mapped is not None or address.scope_id):
        return False
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        return False
    if address.version == 4 and address.is_link_local:
        return False
    return True


def _family_then_value(value: str) -> Tuple[int, Address]:
    """Order addresses IPv4 first, then numerically inside each family.

    The published state must not change just because a lease renewed its
    addresses in a different order, so the order is derived from the value
    itself and never from the order a source happened to report.
    """
    address = ipaddress.ip_address(value)
    return (address.version, address)


def _read(run: CommandRunner, argv: Sequence[str]) -> Optional[str]:
    """Return a command's standard output, or None when it is unavailable.

    The runner owns process handling, so a missing binary, a non-zero exit
    status, and a timeout all arrive here as an exception, and a runner that
    reports failure with no output is treated the same way. The catch is
    deliberately broad: it is confined to the injected call, and a failure only
    means this source could not be read, never that the interface is unusable.
    """
    command = list(argv)
    try:
        output = run(command)
    except Exception:
        return None
    return output if isinstance(output, str) else None


def is_interface_name(interface: str) -> bool:
    """Report whether ``interface`` is a device name the kernel could own.

    The name is handed to fixed argument arrays, so no shell can reinterpret it;
    the narrow pattern is defense in depth that also keeps whitespace, a path
    separator, and shell metacharacters out of the published state. The
    publisher validates the same name before it is written, and a state file
    whose interface this rejects is one the Go state validator rejects too.
    """
    if not isinstance(interface, str):
        return False
    return _INTERFACE_NAME.match(interface) is not None
