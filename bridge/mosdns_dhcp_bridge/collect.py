"""Collect the router-supplied DHCP DNS addresses from NetworkManager.

NetworkManager is the only authority for which resolvers the router was told to
use, and the raw DHCP configuration is the only source that still holds those
addresses after ``ignore-auto-dns`` hides them from resolved. The collector is
therefore read-only and fail-closed: it runs fixed argument arrays, never a
shell string, returns only the addresses a domestic query could actually be sent
to, and keeps two facts apart that look alike in a list -- a lease that named no
usable resolver, and a NetworkManager that could not be read at all. Only the
first is an empty answer; the second is a failure the caller must not publish as
one.
"""

from __future__ import annotations

import ipaddress
import re
from typing import (
    Callable,
    Iterable,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
)

__all__ = [
    "CollectionResult",
    "SourcesUnavailable",
    "collect_dns",
    "collect_dns_with_source",
    "is_interface_name",
    "normalize_upstreams",
    "usable_address",
]


class SourcesUnavailable(Exception):
    """Every command the collector attempted could not be read.

    Deliberately not a ValueError: a source that could not be read is a failure
    of this machine, not a rejected request, and the caller acts on the two
    differently. The message names no environment value and no command output,
    because it is written to the dispatcher's log.
    """


class CollectionResult(NamedTuple):
    """What the collector found, and the source that found it.

    The source is the token a reader of the published state needs, and it names
    the source that answered rather than the event that asked: a lease renewal,
    an interface coming up, and a DNS change that renews nothing all reach the
    same resolvers through the same source, and recording the event instead would
    publish a new generation for each of them.
    """

    addresses: List[str]
    source: str


class _Outcome(NamedTuple):
    """What one source yielded, whether any command behind it was readable, and its token."""

    addresses: List[str]
    readable: bool
    source: str


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
#
# **`DHCP4.OPTION` and `DHCP6.OPTION` are the field names nmcli HAS, and the first
# version of this asked for `DHCP4.OPTION_DOMAIN_NAME_SERVERS`, which is not one.**
# MEASURED, in a 24.04 target container after a successful install:
#
#     $ nmcli -g DHCP4.OPTION_DOMAIN_NAME_SERVERS device show eth0
#     Error: 'device show': invalid field 'DHCP4.OPTION_DOMAIN_NAME_SERVERS';
#     allowed fields: DHCP4.OPTION
#     rc=2
#
#     $ nmcli -g DHCP4.OPTION device show eth0
#     broadcast_address = 10.89.0.255 | dhcp_client_identifier = 01\:4e\:... |
#     domain_name_servers = 10.89.0.2 | ... | routers = 10.89.0.2 | ...
#     rc=0
#
# So the resolvers are a KEY inside a `key = value | key = value` list, not a
# field of their own, and the whole list is read and the key picked out of it --
# see `option_domain_name_servers`.
#
# **What the wrong name cost, and it was not a fallback.** An unknown field is
# exit 2 with no output, which this module reads as "this source could not be
# read", so the highest-priority source was skipped on every release and the
# bridge fell through to the *effective* device DNS. That is harmless until the
# install points NetworkManager at the loopback -- at which point the effective
# DNS IS the loopback, a local address filtered out here, and the published state
# becomes `{"upstreams": [], "last_good": false, "source": "nm-effective"}`
# (MEASURED, same cell, generation 2). The router's `dhcp_forward` plugin then
# has no upstream and every China-set name SERVFAILs **after a successful
# install** -- the condition this project exists to fix, produced by the install
# that fixes the foreign side.
RAW_DHCP_FIELDS = ("DHCP4.OPTION", "DHCP6.OPTION")

# The key the lease's resolvers are recorded under inside that list, and nmcli's
# separator between the entries of it.
OPTION_DNS_KEY = "domain_name_servers"
OPTION_SEPARATOR = "|"
EFFECTIVE_DNS_FIELDS = ("IP4.DNS", "IP6.DNS")

# The token each source is recorded under. A lease that named its resolvers in
# one family is recorded as that family, a lease that named them in both is one
# answer from one source, and the two remaining sources have one token each.
SOURCE_NM_DHCP = "nm-dhcp"
SOURCE_DISPATCHER_ENV = "dispatcher-env"
SOURCE_NM_EFFECTIVE = "nm-effective"
SOURCE_RESOLVED = "resolved"
RAW_DHCP_SOURCES = (("nm-dhcp4", RAW_DHCP_FIELDS[0]), ("nm-dhcp6", RAW_DHCP_FIELDS[1]))

# A source separates its addresses with whitespace, commas, or semicolons, and
# systemd-resolved reports a scoped address in brackets.
SEPARATORS = re.compile(r"[\s,;]+")
BRACKETS = "[]"


def collect_dns(env: Mapping[str, str], interface: str, run: CommandRunner) -> List[str]:
    """Return the DHCP DNS addresses in use on ``interface``.

    A list-only view of ``collect_dns_with_source``, for a caller that has no use
    for the source. Everything it does, including the SourcesUnavailable rule, is
    that function's.
    """
    return collect_dns_with_source(env, interface, run).addresses


def collect_dns_with_source(
    env: Mapping[str, str], interface: str, run: CommandRunner
) -> CollectionResult:
    """Return the DHCP DNS addresses in use on ``interface`` and where they came from.

    ``env`` is the dispatcher environment of the current event, ``interface``
    the device that event is about, and ``run`` executes one read-only command
    and returns its standard output.

    The sources are consulted in a fixed order and the first one that yields a
    usable address wins outright, because a lower-priority source would
    otherwise contribute addresses the router is not configured to use. A source
    that cannot be read is skipped in favour of the next one. The recorded
    source is the one that answered, so the same resolvers read twice through
    the same source are the same state rather than a new generation.

    An empty list is a valid answer: it means a source answered and named no
    usable address, which is not the same as a collection failure, and the
    source it is recorded under is that first readable source. When every
    command that was attempted could not be read, there is no answer at all and
    SourcesUnavailable is raised instead, because a NetworkManager that cannot
    be queried is not evidence that the lease lost its resolvers. Publishing an
    empty state for that would disable a working router on one flaky query.
    """
    if not is_interface_name(interface):
        raise ValueError(
            "interface must be a network interface name of at most "
            f"{MAXIMUM_INTERFACE_NAME_LENGTH} characters, got {interface!r}"
        )

    readable = False
    answered = ""
    for source in _sources(env, interface, run):
        outcome = source()
        readable = readable or outcome.readable
        if outcome.addresses:
            return CollectionResult(outcome.addresses, outcome.source)
        if outcome.readable and not answered:
            answered = outcome.source
    if not readable:
        raise SourcesUnavailable(
            "no NetworkManager source could be read: every nmcli and resolvectl query failed"
        )
    return CollectionResult([], answered)


def _sources(
    env: Mapping[str, str], interface: str, run: CommandRunner
) -> Iterator[Callable[[], _Outcome]]:
    """Return one collector per source, highest priority first.

    The raw NetworkManager DHCP configuration is ranked above the dispatcher
    environment because it is the only source that still names the lease's
    resolvers once ``ignore-auto-dns`` keeps NetworkManager from passing them to
    resolved. The dispatcher environment is next because it is this event's own
    authoritative value, the effective device DNS is what is in use right now,
    and ``resolvectl`` is last because it reports the resolved view of the same
    facts and is filtered for local addresses in any case.
    """
    yield lambda: _raw_dhcp_fields(interface, run)
    yield lambda: _event_variables(env)
    yield lambda: _device_fields(interface, run, EFFECTIVE_DNS_FIELDS)
    yield lambda: _resolved_dns(interface, run)


def _event_variables(env: Mapping[str, str]) -> _Outcome:
    """Return what this event's own variables name.

    The environment is read in this process, so it can never fail to be read and
    it is never the reason a source is unreadable. It also never stands in for a
    successful command read: a silent environment beside a NetworkManager that
    cannot be queried is still an unreadable machine, not an empty lease.
    """
    return _Outcome(
        _normalized(env.get(name, "") for name in DISPATCHER_DNS_VARIABLES),
        False,
        SOURCE_DISPATCHER_ENV,
    )


def option_domain_name_servers(text: Optional[str]) -> str:
    """The `domain_name_servers` value inside one `nmcli -g DHCPn.OPTION` answer.

    The field nmcli prints is a `key = value | key = value` list, so the
    resolvers are a key inside it rather than the whole answer -- and every
    sibling key has to be skipped, most of which (`broadcast_address`,
    `routers`, `subnet_mask`, and a dozen `requested_*` flags) are not addresses.
    A colon inside a value is written escaped by nmcli (`01\:4e\:b1`) because a
    colon is nmcli's own field separator, so the escaping is undone here: an
    address with backslashes in it is not an address.

    Returns the empty string for a field that named no resolvers, which is a
    source that was read and had nothing to say -- not a failure.
    """
    if not isinstance(text, str):
        return ""
    found = []
    for entry in text.split(OPTION_SEPARATOR):
        key, separator, value = entry.partition("=")
        if separator and key.strip() == OPTION_DNS_KEY and value.strip():
            found.append(value.strip().replace("\\:", ":"))
    return " ".join(found)


def _raw_dhcp_fields(interface: str, run: CommandRunner) -> _Outcome:
    """Read each raw DHCP field with its own argument array and name its family.

    Every field is read even when an earlier one answered, because the DHCP6
    field is the only record of a v6 lease's resolvers, and a field that answered
    with nothing is still a source that was read. The recorded source names the
    family that carried the addresses, so a v4-only lease is not recorded as a
    v6 one and a lease that named both is recorded as the single answer it is.

    **The answer is a key inside the field, not the field.** See
    `option_domain_name_servers` and `RAW_DHCP_FIELDS` -- the second of which
    records what asking for a field nmcli does not have cost.
    """
    answers = [
        (source, _read(run, ["nmcli", "-g", field, "device", "show", interface]))
        for source, field in RAW_DHCP_SOURCES
    ]
    resolvers = {source: option_domain_name_servers(output) for source, output in answers}
    answering = [source for source, value in resolvers.items() if _normalized([value])]
    recorded = answering[0] if len(answering) == 1 else SOURCE_NM_DHCP
    return _Outcome(
        _normalized(resolvers[source] for source, _output in answers),
        any(output is not None for _, output in answers),
        recorded,
    )


def _device_fields(
    interface: str, run: CommandRunner, fields: Iterable[str]
) -> _Outcome:
    """Read each effective device DNS field with its own argument array.

    Both families are one answer here: they are what NetworkManager is using
    right now, and a state records the source that produced the set rather than
    which field of it held each address.
    """
    outputs = [
        _read(run, ["nmcli", "-g", field, "device", "show", interface]) for field in fields
    ]
    return _Outcome(
        _normalized(outputs),
        any(output is not None for output in outputs),
        SOURCE_NM_EFFECTIVE,
    )


def _resolved_dns(interface: str, run: CommandRunner) -> _Outcome:
    """Return what resolved reports for ``interface``."""
    output = _read(run, ["resolvectl", "dns", interface])
    return _Outcome(_normalized([output]), output is not None, SOURCE_RESOLVED)


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
    """Return a command's standard output, or None when it could not be read.

    A returned string means the command answered and the source behind it is
    readable, and an empty string is an answer rather than a failure: a field that
    holds nothing is how NetworkManager reports a lease with no resolvers. Only a
    failure makes a source unreadable.

    The runner owns process handling, so a missing binary, a non-zero exit
    status, and a timeout all arrive here as an exception, and a runner that
    answers with anything other than a string is treated the same way. The catch
    is deliberately broad: it is confined to the injected call, and a failure
    only means this source could not be read, never that the interface is
    unusable. The distinction is what keeps an unreadable NetworkManager from
    being reported as an empty lease.
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
