"""Hold the shipped systemd units to exactly the privilege each service needs.

A unit file is the one part of this package that decides what a compromise gets,
and none of the properties below are visible in the router's behaviour: a dropped
``ProtectSystem=strict``, an extra capability, or a writable directory nobody
writes to produces byte-identical answers from the router and a strictly larger
blast radius. So the properties are read out of the unit text and compared against
a table rather than trusted, and the four ways a unit can be wrong all fail here:

* a hardening directive that is dropped or whose value is loosened;
* a capability that is added, or a bounding set that stops being the limit;
* an address that is not loopback, in a unit or in a shipped config's listener;
* a writable directory the unit's identity never writes to.

Two further properties are held here because they are the difference between a
unit that fails loudly and one that fails silently: every unit that needs a
dependency names it, and every unit is additionally parsed by
``systemd-analyze verify`` against a fake root, so an unknown directive, a
malformed calendar specification or an ExecStart that is not executable fails the
build rather than the first boot.

The tables are the contract. ``UNIT_DIRECTIVES`` is every directive of every
shipped unit except ``Description=`` and ``Documentation=``, which are prose; the
comments in the unit files are prose too, and neither is pinned, because pinning
documentation makes a test fail over a rewording and trains everyone to rewrite
the test instead of the thing it describes. Everything that is a decision is
pinned, and a unit that grows a directive nobody decided on fails.
"""

import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO / "packaging" / "systemd"
CONFIG_DIR = REPO / "configs"
RENDERER = REPO / "cmd" / "mosdns-cdnctl" / "render.go"

ROUTER = "mosdns-router.service"
DNSCRYPT = "dnscrypt-proxy.service"
OPTIMIZER = "mosdns-cdn-optimizer.service"
OPTIMIZER_TIMER = "mosdns-cdn-optimizer.timer"
HEALTH = "mosdns-cdn-health.service"
HEALTH_TIMER = "mosdns-cdn-health.timer"
LIST_CHECK = "mosdns-list-check.service"
LIST_CHECK_TIMER = "mosdns-list-check.timer"

SHIPPED_UNITS = (
    ROUTER,
    DNSCRYPT,
    OPTIMIZER,
    OPTIMIZER_TIMER,
    HEALTH,
    HEALTH_TIMER,
    LIST_CHECK,
    LIST_CHECK_TIMER,
)

SERVICES = (ROUTER, DNSCRYPT, OPTIMIZER, HEALTH, LIST_CHECK)
TIMERS = (OPTIMIZER_TIMER, HEALTH_TIMER, LIST_CHECK_TIMER)

# The installed layout every ExecStart names. The two documents are the renderer's
# own output file names, which is why `test_the_units_name_the_files_the_renderer_publishes`
# reads them back out of render.go rather than trusting this spelling.
ROUTER_BINARY = "/usr/lib/mosdns-router/mosdns-router"
CDNCTL_BINARY = "/usr/lib/mosdns-router/mosdns-cdnctl"
DNSCRYPT_BINARY = "/usr/lib/mosdns-router/dnscrypt-proxy"
ROUTER_CONFIG = "/etc/mosdns/mosdns.yaml"
DNSCRYPT_CONFIG = "/etc/mosdns/dnscrypt-proxy.toml"
POLICY = "/etc/mosdns/policy.yaml"
CANDIDATES = "/etc/mosdns/cloudflare.txt"
FORCE_ECH = "/etc/mosdns/force-ech-domains.txt"
CLOUDFRONT_PROFILES = "/etc/mosdns/cloudfront-domains.yaml"
CONTROL_LOCK = "/var/lib/mosdns/runtime/control.lock"
SELECTOR = "/var/lib/mosdns/runtime/cdn-selector.json"
BANDWIDTH_BUDGET = "/var/lib/mosdns/runtime/bandwidth-budget.json"
HEALTH_STATE = "/var/lib/mosdns/runtime/health.json"
ECH_STATE = "/var/lib/mosdns/runtime/ech-state.json"
RANGES_CACHE = "/var/lib/mosdns/lists/cloudflare-ips.json"
CN_LIST = "/var/lib/mosdns/lists/cn-domains.txt"
SOURCE_LOCK = "/var/lib/mosdns/lists/source-lock.json"
DHCP_STATE = "/run/mosdns/dhcp-upstreams.json"
RUNTIME_DIR = "/var/lib/mosdns/runtime"
LISTS_DIR = "/var/lib/mosdns/lists"
RUN_DIR = "/run/mosdns"

# The sandbox every service in this package gets, as (key, value) pairs. It is one
# list for all five services on purpose: five short-lived or long-lived Go
# programs that read documents, write state and open sockets, with no use for /tmp,
# for devices, for kernel knobs or for anything under /home. A per-service subset
# would be a privilege decision nobody can review at a glance, and the only
# per-identity differences in this package are the ones the tables below name: the
# user, the capability set and the writable paths.
SANDBOX = (
    ("NoNewPrivileges", "true"),
    ("PrivateTmp", "true"),
    ("PrivateDevices", "true"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "true"),
    ("ProtectKernelTunables", "true"),
    ("ProtectKernelModules", "true"),
    ("ProtectKernelLogs", "true"),
    ("ProtectControlGroups", "true"),
    ("ProtectClock", "true"),
    ("ProtectHostname", "true"),
    ("ProtectProc", "invisible"),
    ("ProcSubset", "pid"),
    ("LockPersonality", "true"),
    ("RestrictNamespaces", "true"),
    ("RestrictRealtime", "true"),
    ("RestrictSUIDSGID", "true"),
    ("SystemCallArchitectures", "native"),
)

# The directories each identity writes, and therefore the only directories its unit
# may make writable. One `mosdns` group serves two service users because a default
# ACL grants by group, so `root:mosdns` 2750 with a default ACL for `mosdns` is
# what lets either identity replace the other's files; per-service groups would
# give the ACL to one identity and leave the other unable to write.
#
# The router writes the ECH state (cdn_rewrite) and the health file; the optimizer
# and the health check write the selector, the bandwidth budget, the health
# document and the published range cache; the bridge publishes the DHCP state. The
# list check writes nothing at all -- `update-lists --check` is documented to take
# no lock and write no file -- and dnscrypt-proxy's cache is off, so those two
# units name no writable directory. The bridge has no unit: NetworkManager runs it
# as root from a `no-wait.d` dispatcher script, so it is a row here and nowhere
# else.
WRITE_TABLE = {
    ROUTER: (RUNTIME_DIR, RUN_DIR),
    OPTIMIZER: (RUNTIME_DIR, LISTS_DIR),
    HEALTH: (RUNTIME_DIR, LISTS_DIR),
    LIST_CHECK: (),
    DNSCRYPT: (),
}
BRIDGE_WRITES = (RUN_DIR,)

# The identity each unit runs as, and the group it runs under. Both mosdns service
# users have `mosdns` as their primary group, which is the group the state
# directories' default ACL names; dnscrypt-proxy shares no state with either, so it
# has its own group and its own umask.
IDENTITIES = {
    ROUTER: ("mosdns", "mosdns"),
    OPTIMIZER: ("mosdns-cdn", "mosdns"),
    HEALTH: ("mosdns-cdn", "mosdns"),
    LIST_CHECK: ("mosdns-cdn", "mosdns"),
    DNSCRYPT: ("dnscrypt-proxy", "dnscrypt-proxy"),
}

# Only the router binds a privileged port, and only the router gets a capability.
# 15353 is unprivileged, so dnscrypt-proxy needs none, and a unit that needs none
# clears its bounding set rather than inheriting a full one it will never use.
# CAP_NET_BIND_SERVICE appears in both directives: AmbientCapabilities is what the
# process gets, and CapabilityBoundingSet is what stops anything from ever raising
# it, so the bounding set is the limit and not the grant.
CAPABILITIES = {
    ROUTER: ("CAP_NET_BIND_SERVICE",),
    DNSCRYPT: (),
    OPTIMIZER: (),
    HEALTH: (),
    LIST_CHECK: (),
}

# The three schedules, pinned. The optimizer is 03:00 local time and catches up
# after a machine that was off; the health check is every two minutes and must not
# be persistent, because a two-minute cadence with Persistent=true replays a
# backlog of every check the machine missed; the list check is daily after the
# optimizer's window and is report-only, and it is persistent for the opposite
# reason the health timer is not -- a report nobody will ever be shown is not a
# report.
SCHEDULES = {
    OPTIMIZER_TIMER: (("OnCalendar", "*-*-* 03:00:00"), ("Persistent", "true")),
    HEALTH_TIMER: (("OnBootSec", "2min"), ("OnUnitActiveSec", "2min")),
    LIST_CHECK_TIMER: (("OnCalendar", "*-*-* 03:30:00"), ("Persistent", "true")),
}

# Every directive of every shipped unit, except Description= and Documentation=.
UNIT_DIRECTIVES = {
    ROUTER: {
        "Unit": (
            # Ordered after dnscrypt-proxy so the upstream exists when the router
            # takes its first foreign query, and pulled in with Wants rather than
            # Requires: a resolver that failed to start must not take the router
            # down with it, because the router is the machine's only DNS path and a
            # host with no resolver at all is a worse outage than one whose foreign
            # branch fails closed. network.target is ordering only -- no Wants, no
            # Requires -- and there is no network-online.target anywhere: the router
            # binds loopback and must come up on a machine whose network is not up.
            ("After", "dnscrypt-proxy.service network.target"),
            ("Wants", "dnscrypt-proxy.service"),
        ),
        "Service": (
            ("Type", "simple"),
            ("User", "mosdns"),
            ("Group", "mosdns"),
            ("ExecStart", f"{ROUTER_BINARY} start -c {ROUTER_CONFIG}"),
            ("AmbientCapabilities", "CAP_NET_BIND_SERVICE"),
            ("CapabilityBoundingSet", "CAP_NET_BIND_SERVICE"),
            # Anything this router creates lands in a directory the other service
            # identity has to be able to read, so 0007 and not 0077: the umask must
            # never clear group access and must never open the file to the world.
            ("UMask", "0007"),
            ("Restart", "on-failure"),
            ("RestartSec", "5s"),
        )
        + SANDBOX
        + (
            # No SystemCallFilter: @system-service cannot be proven against these
            # two binaries from a test host, and a filter that stops one syscall
            # mosdns v5.3.4 needs is an outage on the machine's only DNS path. The
            # bounding set, the address-family list and ProtectSystem=strict carry
            # the confinement this package can actually stand behind.
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            ("ReadWritePaths", f"{RUNTIME_DIR} {RUN_DIR}"),
        ),
        "Install": (("WantedBy", "multi-user.target"),),
    },
    DNSCRYPT: {
        "Unit": (("After", "network.target"),),
        "Service": (
            ("Type", "simple"),
            ("User", "dnscrypt-proxy"),
            ("Group", "dnscrypt-proxy"),
            ("ExecStart", f"{DNSCRYPT_BINARY} -config {DNSCRYPT_CONFIG}"),
            # An empty bounding set, not an inherited one: this resolver binds an
            # unprivileged port and runs no privileged operation, so there is
            # nothing for it to hold and nothing for a bug in it to use. It creates
            # no file -- cache is off and the log goes to the journal -- so 0077.
            ("CapabilityBoundingSet", ""),
            ("UMask", "0077"),
            ("Restart", "on-failure"),
            ("RestartSec", "5s"),
        )
        + SANDBOX
        + (
            # AF_NETLINK is here and not in the router's list because
            # dnscrypt-proxy 2.1.18 enumerates interfaces in its network-change
            # monitor (dnscrypt-proxy/netmon.go: snapshotNetworkInterfaces calls
            # net.Interfaces, which opens a netlink socket). Without it the
            # fingerprint loses every interface and a network change is missed.
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6 AF_NETLINK"),
        ),
        "Install": (("WantedBy", "multi-user.target"),),
    },
    OPTIMIZER: {
        "Unit": (("After", "network.target"),),
        "Service": (
            ("Type", "oneshot"),
            ("User", "mosdns-cdn"),
            ("Group", "mosdns"),
            ("ExecStart", f"{CDNCTL_BINARY} test --apply"),
            # 512 candidates at 3 s each is 25 minutes of transfers before the
            # identity and proof phases, and the 90 s default for a oneshot would
            # kill the nightly run a quarter of the way through.
            ("TimeoutStartSec", "3600"),
            # Exit 4 is the control lock, and the CLI documents it as "the other
            # one got there first" -- a different answer from "this one is broken".
            # A pin, an apply or an update-lists the operator is running by hand
            # races this timer, and that race is not a failed unit. Every other
            # non-zero exit fails the unit, including a refusal to publish: a
            # nightly run that measured nothing publishable has recorded no day the
            # router was fine. A budget-exhausted run is not among them, and needs
            # no exception: a full day still names a winner in every group and
            # keeps its mapping, so the command exits 0 by construction.
            ("SuccessExitStatus", "4"),
            ("CapabilityBoundingSet", ""),
            ("UMask", "0007"),
        )
        + SANDBOX
        + (
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            ("ReadWritePaths", f"{RUNTIME_DIR} {LISTS_DIR}"),
        ),
    },
    HEALTH: {
        "Unit": (("After", "network.target"),),
        "Service": (
            ("Type", "oneshot"),
            ("User", "mosdns-cdn"),
            ("Group", "mosdns"),
            ("ExecStart", f"{CDNCTL_BINARY} health-check"),
            # A pass is bounded by 60 s and a transition's proof by 15 s, so 110 s
            # is above everything the command can legitimately spend and below the
            # two-minute cadence: a check that hangs is killed before the next
            # elapse instead of overlapping it.
            ("TimeoutStartSec", "110"),
            # The same control-lock race as the optimizer's, and the same reason.
            ("SuccessExitStatus", "4"),
            ("CapabilityBoundingSet", ""),
            ("UMask", "0007"),
        )
        + SANDBOX
        + (
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            ("ReadWritePaths", f"{RUNTIME_DIR} {LISTS_DIR}"),
        ),
    },
    LIST_CHECK: {
        "Unit": (("After", "network.target"),),
        "Service": (
            ("Type", "oneshot"),
            ("User", "mosdns-cdn"),
            ("Group", "mosdns"),
            ("ExecStart", f"{CDNCTL_BINARY} update-lists --check"),
            # `update-lists --check` makes at most two HTTP requests against a
            # 60 s client timeout each, so 90 s would cut a slow origin off before
            # it could say it was slow.
            ("TimeoutStartSec", "180"),
            # No SuccessExitStatus here. This command takes no lock, so exit 4 is
            # unreachable, and its exit 3 is a run that produced no report at all --
            # including the documented transient, a check that caught a publication
            # in flight. The whole job of this unit is its report, and a daily
            # report-only job that failed is information rather than noise.
            ("CapabilityBoundingSet", ""),
        )
        + SANDBOX
        + (
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
        ),
    },
    OPTIMIZER_TIMER: {
        "Unit": (),
        "Timer": (("Unit", OPTIMIZER),) + SCHEDULES[OPTIMIZER_TIMER],
        "Install": (("WantedBy", "timers.target"),),
    },
    HEALTH_TIMER: {
        "Unit": (),
        "Timer": (("Unit", HEALTH),) + SCHEDULES[HEALTH_TIMER],
        "Install": (("WantedBy", "timers.target"),),
    },
    LIST_CHECK_TIMER: {
        "Unit": (),
        "Timer": (("Unit", LIST_CHECK),) + SCHEDULES[LIST_CHECK_TIMER],
        "Install": (("WantedBy", "timers.target"),),
    },
}

# Prose, and prose only. See the module docstring for why neither is pinned.
PROSE_KEYS = frozenset({"Description", "Documentation"})


class UnitParseError(Exception):
    """A unit file that this parser will not read, with the reason and the line."""


def parse_unit(text, name="<unit>"):
    """Parse unit text into ``{section: [(key, value), ...]}``.

    The parser is deliberately stricter than systemd, because a file this
    repository ships and this test reads has no reason to use anything the strict
    reading of a unit file does not allow. In particular a value carrying ``#`` or
    ``;`` is refused: systemd does not strip a trailing comment, so
    ``User=mosdns # the router`` is a user named "mosdns # the router" and a
    ``ReadWritePaths=/var/lib/mosdns # state`` is a path that does not exist. That
    is not a stylistic rule -- it was checked against systemd-analyze on this host
    -- and a directive that reads as commented out but is not is a privilege
    directive that is set.
    """
    sections = {}
    current = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("["):
            if not line.endswith("]") or len(line) < 3:
                raise UnitParseError(f"{name}:{number}: {line!r} is not a section header")
            current = line[1:-1]
            sections.setdefault(current, [])
            continue
        if current is None:
            raise UnitParseError(f"{name}:{number}: {line!r} is a directive before any section")
        key, separator, value = line.partition("=")
        if not separator:
            raise UnitParseError(f"{name}:{number}: {line!r} is not a key=value directive")
        key = key.strip()
        if not key:
            raise UnitParseError(f"{name}:{number}: {line!r} has an empty key")
        value = value.strip()
        if "#" in value or ";" in value:
            raise UnitParseError(
                f"{name}:{number}: the value of {key}= carries a comment marker. systemd does not "
                f"strip one, so the value systemd would use is {value!r}"
            )
        sections[current].append((key, value))
    return sections


def unit_text(name):
    """The shipped text of one unit.

    A missing unit is a failure and not a skip: every property below is a property
    of a file that has to exist, and a skipped assertion is indistinguishable from a
    passing one in a gate that decides whether a package may be built.
    """
    path = UNIT_DIR / name
    if not path.is_file():
        raise AssertionError(
            f"{path.relative_to(REPO)} is missing. It is one of the "
            f"{len(SHIPPED_UNITS)} unit files this package installs "
            f"({', '.join(sorted(SHIPPED_UNITS))}), and every property below is a property of "
            "a file that has to exist"
        )
    return path.read_text(encoding="utf-8")


def parsed(name):
    """The parsed directives of one shipped unit."""
    return parse_unit(unit_text(name), name)


def directive_value(sections, section, key):
    """Every value of ``key`` in ``section``, in file order."""
    return [value for name, value in sections.get(section, ()) if name == key]


def one_directive(sections, section, key):
    values = directive_value(sections, section, key)
    if len(values) != 1:
        raise AssertionError(
            f"[{section}] {key}= appears {len(values)} time(s), want exactly 1: {values!r}"
        )
    return values[0]


def compare_directives(name, expected, actual):
    """Describe how a unit's directives differ from the table, or return ``""``.

    Both sides are compared as multisets of (key, value) pairs, so an order
    difference is not a difference -- a unit file is read by key, not by position
    -- while a repeated key, a changed value, a dropped key and a key nobody
    decided on are all differences.
    """
    expected_counter = Counter(pair for pair in expected if pair[0] not in PROSE_KEYS)
    actual_counter = Counter(pair for pair in actual if pair[0] not in PROSE_KEYS)
    problems = []
    for (key, value), _count in sorted((expected_counter - actual_counter).items()):
        problems.append(f"missing {key}={value}")
    for (key, value), _count in sorted((actual_counter - expected_counter).items()):
        problems.append(f"unexpected {key}={value}")
    for key in sorted({key for key, _ in expected_counter} & {key for key, _ in actual_counter}):
        want = expected_counter[key]
        got = actual_counter[key]
        if want != got:
            problems.append(
                f"{key}= appears {got} time(s) with value(s) "
                f"{[value for name, value in actual if name == key]!r}, want {want} time(s) with "
                f"{[value for name, value in expected if name == key]!r}"
            )
    return f"{name}: " + "; ".join(problems) if problems else ""


def capability_problems(name, sections, expected):
    """How a unit's capability set differs from what its identity needs.

    Two properties, and they are different properties. ``AmbientCapabilities`` is
    the grant: a capability in it that the service does not use is a capability a
    bug in it can use. ``CapabilityBoundingSet`` is the limit, and a bounding set
    wider than the grant is the difference between a service that holds one
    capability and a service from which anything may be raised.
    """
    ambient = tuple(
        part
        for value in directive_value(sections, "Service", "AmbientCapabilities")
        for part in value.split()
    )
    bounding = tuple(
        part
        for value in directive_value(sections, "Service", "CapabilityBoundingSet")
        for part in value.split()
    )
    problems = []
    if ambient != expected:
        problems.append(
            f"AmbientCapabilities is {ambient!r} and this identity needs exactly {expected!r}"
        )
    if bounding != expected:
        problems.append(
            f"CapabilityBoundingSet is {bounding!r}; the bounding set is the limit, so it has "
            f"to name exactly {expected!r}"
        )
    return problems


def write_path_problems(name, sections, expected):
    """How a unit's writable paths differ from the identity's write set."""
    values = directive_value(sections, "Service", "ReadWritePaths")
    declared = tuple(
        part for value in values for part in value.split() if part
    )
    problems = []
    granted = set(declared)
    for path in expected:
        if path not in granted:
            problems.append(f"{path} is written by this unit but is not writable in it")
    for path in declared:
        if path not in expected:
            problems.append(
                f"{path} is writable but nothing this unit runs writes it: "
                f"{sorted(expected)!r} is the whole write set of {IDENTITIES[name][0]}"
            )
    if len(declared) != len(set(declared)):
        problems.append(f"a directory is granted twice: {declared!r}")
    return problems


# host:port, with the host part possibly empty -- ":53" is a bind on every
# address the host has, which is the thing this project refuses, so it has to be
# recognised as one rather than skipped as unparseable.
HOST_PORT = re.compile(r"^(?P<host>[^:]*):(?P<port>\d+)$")


def named_addresses(text):
    """Every IP address the text names, with the host part of ``host:port`` forms.

    A token only counts when it parses as an address, so a clock time such as
    ``03:00:00`` in an OnCalendar line is not a malformed IPv6 address and is not
    reported as one. ``tcp://host:port`` and ``[v6]:port`` are reduced to the host
    first, because a listener is a binding and a binding is what this project
    refuses to put anywhere but loopback. A host:port with an empty host is
    reported with no address at all, because an unspecified bind is the opposite
    of a loopback one and has to be named rather than skipped.

    The ``None`` in the result is that unspecified bind: a caller asking which
    addresses are not loopback wants it in the answer.
    """
    bracketed = re.compile(r"^\[([^\]]+)\](?::\d+)?$")
    found = []
    for token in re.split(r"[\s,=]+", text):
        token = token.strip("'\"`<>(){}")
        if not token or ("." not in token and ":" not in token):
            continue
        match = bracketed.match(token)
        if match is not None:
            candidate = match.group(1)
        else:
            candidate = token.split("://", 1)[-1]
            port_form = HOST_PORT.match(candidate)
            if port_form is not None:
                candidate = port_form.group("host")
                if not candidate:
                    found.append((token, None))
                    continue
        try:
            found.append((token, ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return found


def non_loopback(text):
    """Every address in the text that is not a loopback address."""
    return [token for token, address in named_addresses(text) if address is None or not address.is_loopback]


def yaml_listen_addresses(text):
    """The ``listen:`` values of a routing document, which is where it binds."""
    return re.findall(r"^\s*listen:\s*(\S+)\s*$", text, flags=re.MULTILINE)


def toml_listen_addresses(text):
    """The listener list of a dnscrypt-proxy document, one entry per address."""
    match = re.search(r"^listen_addresses\s*=\s*\[(.*?)\]", text, flags=re.MULTILINE)
    if match is None:
        return []
    return re.findall(r"'([^']+)'", match.group(1))


class UnitTextTests(unittest.TestCase):
    """The unit text itself: what is shipped, and what every directive says."""

    def test_the_unit_directory_holds_exactly_the_shipped_units(self):
        self.assertTrue(UNIT_DIR.is_dir(), f"{UNIT_DIR} does not exist")
        present = tuple(sorted(path.name for path in UNIT_DIR.iterdir()))
        self.assertEqual(
            present,
            tuple(sorted(SHIPPED_UNITS)),
            f"{UNIT_DIR.relative_to(REPO)} must hold exactly the shipped units: "
            "an extra unit is a service nobody reviewed, and a missing one is a "
            "timer or a service the install cannot enable",
        )

    def test_every_unit_file_parses(self):
        for name in SHIPPED_UNITS:
            with self.subTest(unit=name):
                text = unit_text(name)
                sections = parse_unit(text, name)
                self.assertIn("Unit", sections, f"{name} has no [Unit] section")
                for section in sections:
                    self.assertIn(
                        section,
                        ("Unit", "Service", "Timer", "Install", "Socket"),
                        f"{name} has a [{section}] section this package never writes",
                    )
                self.assertTrue(
                    text.endswith("\n"),
                    f"{name} does not end in a newline, so its last directive is joined to "
                    "whatever is appended to it -- which is how a ReadWritePaths line added "
                    "by an editing tool becomes part of the previous value instead of a "
                    "directive of its own",
                )

    def test_every_directive_is_the_one_that_was_decided(self):
        for name in SHIPPED_UNITS:
            with self.subTest(unit=name):
                sections = parsed(name)
                for section, expected in sorted(UNIT_DIRECTIVES[name].items()):
                    with self.subTest(unit=name, section=section):
                        difference = compare_directives(
                            f"{name} [{section}]", expected, sections.get(section, ())
                        )
                        self.assertEqual(
                            difference,
                            "",
                            f"{difference}. Every directive except "
                            f"{sorted(PROSE_KEYS)} is pinned, so a dropped directive, "
                            "a loosened value and a directive nobody decided on all fail here",
                        )

    def test_each_unit_runs_as_the_identity_that_owns_its_writes(self):
        for name in SERVICES:
            with self.subTest(unit=name):
                sections = parsed(name)
                user, group = IDENTITIES[name]
                self.assertEqual(one_directive(sections, "Service", "User"), user)
                self.assertEqual(one_directive(sections, "Service", "Group"), group)
                self.assertEqual(
                    group,
                    "mosdns" if name != DNSCRYPT else "dnscrypt-proxy",
                    "the two mosdns service users share the group the state directories' default "
                    "ACL names, because an ACL grants by group and per-service groups would let "
                    "only one of them replace the other's files; the resolver shares no state "
                    "with either, so it has a group of its own",
                )

    def test_each_timer_triggers_exactly_its_own_service(self):
        # A timer whose Unit= names another service would run the wrong command on
        # its schedule, and a service two timers trigger would be run twice on two
        # schedules. Neither is visible in the unit it is written in, so the pairing
        # is checked here as a pairing.
        triggered = {}
        for name in TIMERS:
            sections = parsed(name)
            service = one_directive(sections, "Timer", "Unit")
            self.assertEqual(
                service,
                name[: -len(".timer")] + ".service",
                f"{name} triggers {service}, and a timer's schedule belongs to one service",
            )
            self.assertEqual(
                one_directive(sections, "Install", "WantedBy"),
                "timers.target",
                f"{name} is enabled into timers.target, which is what starts a timer at boot",
            )
            self.assertNotIn(
                "Install",
                sections.get("Service", {}),
                f"{name} has no service of its own to enable",
            )
            self.assertNotIn(
                service,
                triggered,
                f"{name} and {triggered.get(service)} both trigger {service}, so one command "
                "would run on two schedules",
            )
            triggered[service] = name
        self.assertEqual(
            set(triggered),
            {name[: -len(".timer")] + ".service" for name in SCHEDULES},
            "every timer with a pinned schedule has a service, and every timer-driven service "
            "has exactly one timer",
        )

    def test_only_the_router_holds_a_capability(self):
        for name in SERVICES:
            with self.subTest(unit=name):
                self.assertEqual(
                    capability_problems(name, parsed(name), CAPABILITIES[name]),
                    [],
                    f"{name} runs as {IDENTITIES[name][0]} and needs exactly "
                    f"{CAPABILITIES[name]!r}: a capability nobody uses is a capability a bug "
                    "can use, and a bounding set wider than the grant is a service anything "
                    "can be raised in",
                )

    def test_each_unit_may_write_only_what_its_identity_writes(self):
        for name in SERVICES:
            with self.subTest(unit=name):
                sections = parsed(name)
                self.assertEqual(
                    write_path_problems(name, sections, WRITE_TABLE[name]),
                    [],
                    "ReadWritePaths is per identity and checked against the write set, not "
                    "repeated from one list: a directory nobody writes is a directory a "
                    "compromise can use",
                )

    def test_a_unit_granting_a_directory_it_does_not_write_fails(self):
        # The property above is only worth anything if the checker has teeth, so it
        # is run against a unit that has been given the extra directory the plan's
        # single shared list would have granted every service.
        sections = parsed(OPTIMIZER)
        sections["Service"].append(("ReadWritePaths", "/var/lib/mosdns"))
        self.assertEqual(
            write_path_problems(OPTIMIZER, sections, WRITE_TABLE[OPTIMIZER]),
            [
                "/var/lib/mosdns is writable but nothing this unit runs writes it: "
                f"{sorted(WRITE_TABLE[OPTIMIZER])!r} is the whole write set of mosdns-cdn"
            ],
            "the write-set check has to reject a broader grant, or it accepts any",
        )

    def test_a_unit_gaining_a_capability_fails(self):
        sections = parsed(LIST_CHECK)
        sections["Service"].append(("AmbientCapabilities", "CAP_NET_BIND_SERVICE"))
        self.assertEqual(
            capability_problems(LIST_CHECK, sections, CAPABILITIES[LIST_CHECK]),
            [
                "AmbientCapabilities is ('CAP_NET_BIND_SERVICE',) and this identity needs "
                "exactly ()"
            ],
            "the capability check has to reject a grant nobody needs, or it accepts any",
        )

    def test_a_unit_widening_its_bounding_set_fails(self):
        # The other half of the capability property: a grant that is right and a
        # limit that is not. This is the change a careless edit makes, because an
        # inherited bounding set looks like it says nothing.
        sections = parsed(ROUTER)
        sections["Service"] = [
            ("CapabilityBoundingSet", "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN")
            if pair[0] == "CapabilityBoundingSet"
            else pair
            for pair in sections["Service"]
        ]
        self.assertEqual(
            capability_problems(ROUTER, sections, CAPABILITIES[ROUTER]),
            [
                "CapabilityBoundingSet is ('CAP_NET_BIND_SERVICE', 'CAP_SYS_ADMIN'); the "
                "bounding set is the limit, so it has to name exactly "
                "('CAP_NET_BIND_SERVICE',)"
            ],
            "a bounding set wider than the grant is the service anything can be raised in",
        )

    def test_a_unit_dropping_a_hardening_directive_fails(self):
        sections = parsed(ROUTER)
        before = len(sections["Service"])
        sections["Service"] = [pair for pair in sections["Service"] if pair[0] != "ProtectSystem"]
        difference = compare_directives(
            f"{ROUTER} [Service]", UNIT_DIRECTIVES[ROUTER]["Service"], sections["Service"]
        )
        self.assertEqual(
            difference,
            f"{ROUTER} [Service]: missing ProtectSystem=strict",
            "dropping a hardening directive has to be a difference the table sees",
        )
        self.assertEqual(len(sections["Service"]), before - 1)

    def test_the_oneshot_services_are_oneshots_that_no_timer_reports_as_failed(self):
        for name in (OPTIMIZER, HEALTH, LIST_CHECK):
            with self.subTest(unit=name):
                sections = parsed(name)
                self.assertEqual(
                    one_directive(sections, "Service", "Type"),
                    "oneshot",
                    f"{name} exits after doing its work; anything else makes systemd wait for a "
                    "process that has already gone",
                )
                self.assertNotIn(
                    "Install",
                    sections,
                    f"{name} is started by its timer, never enabled on its own",
                )
        # The exit-code policy, stated as one property: a held control lock is a race
        # with an operator, not a defect, and it is the only non-zero exit excused.
        self.assertEqual(
            {
                name: tuple(directive_value(parsed(name), "Service", "SuccessExitStatus"))
                for name in (OPTIMIZER, HEALTH, LIST_CHECK)
            },
            {OPTIMIZER: ("4",), HEALTH: ("4",), LIST_CHECK: ()},
            "exit 4 is the control lock the CLI itself reports as 'the other one got there "
            "first'; every other non-zero exit, including a refusal to publish, fails the "
            "unit, and the list check excuses nothing because it takes no lock at all",
        )

    def test_the_router_waits_for_dnscrypt_without_requiring_it(self):
        sections = parsed(ROUTER)
        self.assertIn(
            "dnscrypt-proxy.service",
            one_directive(sections, "Unit", "After"),
            "the router's first foreign query goes to the resolver, so it starts after it",
        )
        self.assertIn(
            "dnscrypt-proxy.service",
            one_directive(sections, "Unit", "Wants"),
            "Wants, not Requires: a Requires would stop the router when the resolver "
            "failed, and a host whose only DNS path is down has no DNS at all",
        )
        for key in ("Requires", "Requisite", "BindsTo"):
            self.assertEqual(
                directive_value(sections, "Unit", key),
                [],
                f"{key} would make the resolver's failure the router's failure",
            )

    def test_no_unit_waits_for_the_network_to_be_online(self):
        for name in SHIPPED_UNITS:
            with self.subTest(unit=name):
                text = unit_text(name)
                self.assertNotIn(
                    "network-online",
                    text,
                    f"{name} names network-online.target. The router binds loopback and has to "
                    "come up on a machine NetworkManager does not call online; the installer's "
                    "ordering, not a target, is what guarantees DNS is ready",
                )
                for key in ("Requires", "Requisite", "Wants"):
                    for value in directive_value(parse_unit(text, name), "Unit", key):
                        self.assertNotIn(
                            "network.target",
                            value.split(),
                            f"{name} pulls in network.target with {key}=, which is the hard "
                            "start requirement this package refuses",
                        )

    def test_no_unit_names_an_address_outside_loopback(self):
        for name in SHIPPED_UNITS:
            with self.subTest(unit=name):
                self.assertEqual(
                    non_loopback(unit_text(name)),
                    [],
                    f"{name} names an address that is not loopback. Nothing in this package "
                    "listens off-host, so any address a unit names is one it hands to "
                    "something that might",
                )

    def test_a_unit_naming_a_lan_address_fails(self):
        for line, address in (
            ("Environment=MOSDNS_LISTEN=0.0.0.0:53", "0.0.0.0:53"),
            ("Environment=UPSTREAM=192.168.1.53:53", "192.168.1.53:53"),
            ("Environment=LISTEN=[::]:53", "[::]:53"),
            ("Environment=LISTEN=:53", ":53"),
            ("Environment=LISTEN=fd00::53", "fd00::53"),
        ):
            self.assertEqual(
                non_loopback(line),
                [address],
                f"{line!r} binds or dials something that is not loopback, and the check has to "
                "say which address it found",
            )
        self.assertEqual(
            non_loopback("OnCalendar=*-*-* 03:00:00"),
            [],
            "a clock time is not an address, and a check that reported one would be a "
            "check nobody could act on",
        )


class ShippedConfigListenerTests(unittest.TestCase):
    """The listeners the units are only half of: the shipped configs' own binds.

    The units name no address of their own, so the listener half of "nothing
    listens on a LAN interface" lives in the documents the units load. Asserting
    that a port appears is not enough -- ``127.0.0.1:53`` and ``0.0.0.0:53`` both
    contain 53 -- so the host part is what is compared, and the whole address with
    its port, which is also what a wildcard bind fails.
    """

    def test_the_routing_document_binds_loopback_53_on_udp_and_tcp(self):
        text = (CONFIG_DIR / "mosdns.yaml").read_text(encoding="utf-8")
        self.assertEqual(
            yaml_listen_addresses(text),
            ["127.0.0.1:53", "127.0.0.1:53"],
            "the routing document's two servers are the machine's only DNS listeners and "
            "both are loopback; a wildcard or a bare port here is a resolver on the LAN",
        )

    def test_the_routing_document_forwards_to_the_loopback_resolver(self):
        text = (CONFIG_DIR / "mosdns.yaml").read_text(encoding="utf-8")
        upstreams = re.findall(r"^\s*-\s*addr:\s*(\S+)\s*$", text, flags=re.MULTILINE)
        self.assertEqual(
            upstreams,
            ["tcp://127.0.0.1:15353"],
            "the foreign branch reaches the resolver this package ships, on loopback",
        )
        self.assertEqual(
            re.findall(r"^\s*foreign_upstream:\s*(\S+)\s*$", text, flags=re.MULTILINE),
            ["tcp://127.0.0.1:15353"],
            "the ECH fetch goes through the same loopback resolver, never a LAN address",
        )

    def test_the_resolver_document_binds_loopback_15353(self):
        text = (CONFIG_DIR / "dnscrypt-proxy.toml").read_text(encoding="utf-8")
        self.assertEqual(
            toml_listen_addresses(text),
            ["127.0.0.1:15353"],
            "the resolver's listener is loopback and is not port 53, so it is neither "
            "reachable from off-host nor mistakable for the system resolver",
        )

    def test_a_listener_that_is_not_loopback_fails(self):
        for listening in ("listen: 0.0.0.0:53", "listen: :53", "listen: 192.168.1.10:53"):
            self.assertEqual(
                non_loopback(listening),
                [listening.split("listen:")[1].strip()],
                f"{listening!r} is a LAN bind and the loopback check has to reject it",
            )

    def test_the_units_and_the_configs_name_loopback_addresses_only(self):
        for path in sorted(CONFIG_DIR.glob("mosdns.yaml")) + sorted(
            CONFIG_DIR.glob("dnscrypt-proxy.toml")
        ):
            with self.subTest(config=path.name):
                for value in yaml_listen_addresses(path.read_text(encoding="utf-8")) + (
                    toml_listen_addresses(path.read_text(encoding="utf-8"))
                ):
                    self.assertEqual(
                        non_loopback(value),
                        [],
                        f"{path.name} binds {value}, which is not loopback",
                    )


class ConfigPathTests(unittest.TestCase):
    """The units name the renderer's own output files, and nothing else."""

    def test_the_units_name_the_files_the_renderer_publishes(self):
        source = RENDERER.read_text(encoding="utf-8")
        published = dict(
            re.findall(r'(Mosdns|DNSCrypt):\s*"([^"]+)"', source)
        )
        self.assertEqual(
            published,
            {"Mosdns": "mosdns.yaml", "DNSCrypt": "dnscrypt-proxy.toml"},
            "the renderer's production layout moved; the units have to be amended with it",
        )
        router = parsed(ROUTER)
        self.assertIn(
            f"/etc/mosdns/{published['Mosdns']}",
            one_directive(router, "Service", "ExecStart"),
            "the router's ExecStart must load the file the renderer writes",
        )
        resolver = parsed(DNSCRYPT)
        self.assertIn(
            f"/etc/mosdns/{published['DNSCrypt']}",
            one_directive(resolver, "Service", "ExecStart"),
            "the resolver's ExecStart must load the file the renderer writes",
        )

    def test_no_unit_names_the_config_yaml_the_plan_first_wrote(self):
        for name in SHIPPED_UNITS:
            with self.subTest(unit=name):
                self.assertNotIn(
                    "config.yaml",
                    unit_text(name),
                    f"{name} names config.yaml. Nothing produces that file: the renderer's "
                    "own output is mosdns.yaml, and a unit loading a path that does not exist "
                    "is a service that cannot start",
                )


class SystemdAnalyzeTests(unittest.TestCase):
    """``systemd-analyze verify`` on every shipped unit, with no systemd running.

    The static text test above says the units say what this package decided. It
    cannot say they are valid: a directive systemd does not know, a calendar
    specification it cannot parse, or an ExecStart that is not executable all pass
    a text comparison and fail on the user's machine at boot.

    ``verify`` is run against a fake root, because it checks that every ExecStart
    names an executable and the package is not installed on the host that runs the
    test. The fake root holds the units, a copy of this host's own systemd unit
    directory (so the default dependencies -- sysinit.target, basic.target, the
    shutdown conflicts -- resolve exactly as they will on a real system), and a
    stub executable for every path the units' ExecStart lines name. Nothing here
    talks to a bus, a journal or a running manager.
    """

    @classmethod
    def setUpClass(cls):
        cls.analyze = shutil.which("systemd-analyze")

    def _require_analyze(self):
        self.assertIsNotNone(
            self.analyze,
            "systemd-analyze is not on PATH, so the units cannot be verified at all. This is a "
            "failure rather than a skip on purpose: a skipped verification is a gate that reports "
            "success while checking nothing",
        )

    def _fake_root(self, directory, units, stub_paths=None):
        """A root that has the units, systemd's own units, and the executables.

        ``stub_paths`` defaults to every path the units' ExecStart lines name, which
        is what the shipped units need and what makes the executability check
        meaningful: a unit whose binary is nowhere else gets one here, and a unit
        naming something this root does not hold is reported as not executable. The
        control case below passes an empty list, because the point there is a unit
        whose ExecStart nothing stubs.
        """
        systemd_units = Path("/usr/lib/systemd")
        self.assertTrue(
            systemd_units.is_dir(),
            "/usr/lib/systemd does not exist, so there is no unit tree to resolve default "
            "dependencies against",
        )
        target = directory / "usr" / "lib"
        target.mkdir(parents=True)
        # Symlinks are dereferenced: a symlinked /usr/lib/systemd/system would send
        # the relative links inside it back into the fake root, and verify would
        # report a loop for every alias instead of a unit property.
        shutil.copytree(
            systemd_units,
            target / "systemd",
            symlinks=False,
            ignore_dangling_symlinks=True,
        )
        installed = directory / "etc" / "systemd" / "system"
        installed.mkdir(parents=True)
        for name, text in units.items():
            (installed / name).write_text(text, encoding="utf-8")
        if stub_paths is None:
            stub_paths = sorted(
                {
                    part
                    for text in units.values()
                    for line in text.splitlines()
                    if line.startswith("ExecStart=")
                    for part in line.partition("=")[2].split()
                }
            )
        for path in stub_paths:
            if not path.startswith("/"):
                continue
            stub = directory / path.lstrip("/")
            stub.parent.mkdir(parents=True, exist_ok=True)
            stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            stub.chmod(0o755)
        return directory

    def _verify(self, units):
        self._require_analyze()
        with tempfile.TemporaryDirectory() as raw:
            self._fake_root(Path(raw), units)
            results = {}
            for name in sorted(units):
                completed = subprocess.run(
                    [self.analyze, "verify", "--root", raw, name],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                results[name] = completed
            return results

    def test_systemd_analyze_verify_accepts_every_shipped_unit(self):
        results = self._verify({name: unit_text(name) for name in SHIPPED_UNITS})
        for name, completed in sorted(results.items()):
            with self.subTest(unit=name):
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"systemd-analyze verify rejected {name}:\n{completed.stdout}{completed.stderr}",
                )
                self.assertEqual(
                    completed.stderr.strip(),
                    "",
                    f"systemd-analyze verify reported diagnostics for {name}, and a diagnostic "
                    "is the whole reason this check exists",
                )

    def test_the_verification_itself_rejects_a_broken_unit(self):
        # A gate that cannot fail is not a gate, so the same harness is run against
        # units broken in the three ways this package most plausibly gets wrong. Two
        # of them systemd refuses outright and one it only reports, which is why the
        # harness asserts both an exit code and an empty stderr rather than either.
        # The shapes are checked against this host's systemd first: a calendar
        # specification that is not one exits non-zero, a directive systemd does not
        # know is reported and ignored, and an ExecStart that names nothing is a
        # non-zero exit too.
        self._require_analyze()
        broken = {
            "broken-calendar.timer": (
                "[Unit]\nDescription=x\n\n[Timer]\nOnCalendar=every other tuesday\n\n"
                "[Install]\nWantedBy=timers.target\n",
                True,
                "Failed to parse calendar specification",
            ),
            "broken-directive.service": (
                "[Unit]\nDescription=x\n\n[Service]\nType=oneshot\nExecStart=/bin/true\n"
                "ProtectEverything=maybe\n",
                False,
                "Unknown key 'ProtectEverything'",
            ),
            "broken-exec.service": (
                "[Unit]\nDescription=x\n\n[Service]\nType=oneshot\n"
                "ExecStart=/usr/lib/mosdns-router/does-not-exist\n",
                True,
                "is not executable",
            ),
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            # Nothing is stubbed here, so an ExecStart naming a missing binary is
            # missing in the root too -- which is the whole point of that case.
            self._fake_root(root, {name: text for name, (text, _, _) in broken.items()}, [])
            for name, (_, refused, message) in broken.items():
                with self.subTest(unit=name):
                    completed = subprocess.run(
                        [self.analyze, "verify", "--root", str(root), name],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    self.assertIn(
                        message,
                        completed.stdout + completed.stderr,
                        f"{name} is broken and the harness did not say why, so the harness is "
                        "not checking what the test above believes it is",
                    )
                    if refused:
                        self.assertNotEqual(
                            completed.returncode,
                            0,
                            f"{name} is refused by systemd and the harness accepted it",
                        )
                    else:
                        self.assertNotEqual(
                            completed.stderr.strip() + completed.stdout.strip(),
                            "",
                            f"{name} produces a diagnostic and the harness reported nothing",
                        )


class WriteSetEvidenceTests(unittest.TestCase):
    """The write table against the code that writes, so it cannot rot silently.

    The table above is a decision; this is the check that the decision still
    describes the code. A writer that starts writing a new directory has to be
    added to both, because a unit that is not writable there fails at runtime with
    a mount-namespace error rather than with anything an operator can read.
    """

    def _writable(self, name):
        sections = parsed(name)
        return [
            path
            for value in directive_value(sections, "Service", "ReadWritePaths")
            for path in value.split()
        ]

    def test_the_state_paths_the_go_code_defaults_to_are_the_ones_this_table_names(self):
        # The constants in this module are read out of the Go source rather than
        # written here from memory: a moved default is then a failure of this test
        # instead of a unit that makes the wrong directory writable. The pattern
        # tolerates gofmt's alignment so a reformat of the const block is not a
        # failure of this test.
        declared = {
            "control lock": (
                REPO / "internal" / "optimizer" / "runner.go",
                r"DefaultControlLockPath\s*=\s*\"%s/\"\s*\+\s*DefaultControlLockPathName"
                % re.escape(RUNTIME_DIR),
            ),
            "selector": (
                REPO / "internal" / "optimizer" / "runner.go",
                r"DefaultSelectorPath\s*=\s*\"%s/\"\s*\+\s*DefaultSelectorPathName"
                % re.escape(RUNTIME_DIR),
            ),
            "bandwidth budget": (
                REPO / "internal" / "optimizer" / "budget.go",
                r"DefaultBudgetPath\s*=\s*\"%s/\"\s*\+\s*DefaultBudgetName"
                % re.escape(RUNTIME_DIR),
            ),
            "health state": (
                REPO / "internal" / "health" / "checker.go",
                r"DefaultHealthPath\s*=\s*\"%s/\"\s*\+\s*DefaultHealthPathName"
                % re.escape(RUNTIME_DIR),
            ),
            "published ranges": (
                REPO / "cmd" / "mosdns-cdnctl" / "main.go",
                r"defaultCloudflareRangesCache\s*=\s*\"%s\"" % re.escape(RANGES_CACHE),
            ),
            "DHCP state": (
                REPO / "internal" / "mosdnsconfig" / "render.go",
                r"DHCPState:\s+\"%s\"" % re.escape(DHCP_STATE),
            ),
            "ECH state": (
                REPO / "internal" / "mosdnsconfig" / "render.go",
                r"ECHState:\s+\"%s\"" % re.escape(ECH_STATE),
            ),
            "pinned China list": (
                REPO / "cmd" / "mosdns-cdnctl" / "update_lists.go",
                r"defaultListFilePath\s*=\s*\"%s\"" % re.escape(CN_LIST),
            ),
            "list source lock": (
                REPO / "cmd" / "mosdns-cdnctl" / "update_lists.go",
                r"defaultSourceLockPath\s*=\s*\"%s\"" % re.escape(SOURCE_LOCK),
            ),
            "policy": (
                REPO / "cmd" / "mosdns-cdnctl" / "main.go",
                r"defaultPolicyPath\s*=\s*\"%s\"" % re.escape(POLICY),
            ),
            "user candidates": (
                REPO / "cmd" / "mosdns-cdnctl" / "main.go",
                r"defaultUserCandidatesPath\s*=\s*\"%s\"" % re.escape(CANDIDATES),
            ),
            "forced ECH domains": (
                REPO / "cmd" / "mosdns-cdnctl" / "main.go",
                r"defaultIdentityDomainsPath\s*=\s*\"%s\"" % re.escape(FORCE_ECH),
            ),
            "CloudFront profiles": (
                REPO / "cmd" / "mosdns-cdnctl" / "main.go",
                r"defaultCloudFrontProfilesPath\s*=\s*\"%s\"" % re.escape(CLOUDFRONT_PROFILES),
            ),
        }
        for what, (path, pattern) in declared.items():
            with self.subTest(path=what):
                self.assertIsNotNone(
                    re.search(pattern, path.read_text(encoding="utf-8")),
                    f"{path.relative_to(REPO)} no longer declares the {what} path this module "
                    f"names ({pattern}); the writable sets checked against it have to move too",
                )
        for path in (CONTROL_LOCK, SELECTOR, BANDWIDTH_BUDGET, HEALTH_STATE):
            self.assertEqual(os.path.dirname(path), RUNTIME_DIR, path)
        self.assertEqual(os.path.dirname(RANGES_CACHE), LISTS_DIR)
        self.assertEqual(os.path.dirname(ECH_STATE), RUNTIME_DIR)
        self.assertEqual(os.path.dirname(DHCP_STATE), RUN_DIR)

    def test_the_list_check_reads_the_pinned_pair_and_writes_nothing(self):
        # The reason this unit names no writable directory at all: the command it
        # runs reads two documents, compares the commit they describe with the one
        # upstream publishes, and writes nothing. A unit that acquired a writable
        # directory for it would be granting write access to buy a report.
        source = (REPO / "cmd" / "mosdns-cdnctl" / "update_lists.go").read_text(encoding="utf-8")
        self.assertEqual(
            self._writable(LIST_CHECK),
            [],
            "update-lists --check writes no file and takes no lock, so this unit grants nothing",
        )
        for path in (CN_LIST, SOURCE_LOCK):
            self.assertEqual(
                os.path.dirname(path),
                LISTS_DIR,
                f"the list check reads {path}, and the lists directory is where the package "
                "provisions it",
            )
        # The one function that implements --check, and what it does with the pair.
        body = source.split("func runCheckLists", 1)[1].split("\nfunc ", 1)[0]
        for absent in ("acquireLock", "WriteReplacement", "WriteJSON", "os.Create", "rules.Publish"):
            self.assertNotIn(
                absent,
                body,
                f"runCheckLists now contains {absent!r}, so it is no longer a check: whatever it "
                "does, this unit's writable-directory table and its exit-code policy are wrong",
            )

    def test_the_bridge_is_a_row_of_the_table_with_no_unit(self):
        # The DHCP bridge is the fourth writer of the project's state and the only
        # one with no unit: NetworkManager runs it as root from a no-wait.d
        # dispatcher script, so its access is whatever the dispatcher gives root
        # and there is nothing to harden. It is a row of the table because /run is
        # a directory with two writers and saying so is what stops a sixth column
        # of "just add /run to the list" from appearing later.
        self.assertEqual(BRIDGE_WRITES, (RUN_DIR,))
        self.assertEqual(os.path.dirname(DHCP_STATE), RUN_DIR)
        present = (
            sorted(path.name for path in UNIT_DIR.iterdir())
            if UNIT_DIR.is_dir()
            else []
        )
        self.assertEqual(
            [name for name in present if "bridge" in name or "dhcp" in name],
            [],
            "the bridge is dispatched by NetworkManager and has no unit; one appearing here "
            "means the dispatcher was replaced, and this table needs a User= row and a "
            "ReadWritePaths row for it before the units can say anything about it",
        )
        publisher = (REPO / "bridge" / "mosdns_dhcp_bridge" / "publish.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("os.replace", publisher, "the publisher replaces the state by rename")

    def test_the_router_writes_only_the_ech_state(self):
        # The router's whole write set is one document the cdn_rewrite plugin
        # publishes; dhcp_forward only reads the state the bridge publishes. That is
        # why the router's writable directory is the one holding it. /run/mosdns is
        # granted beside it by the write table above, and it is where the DHCP state
        # the router reads lives -- a grant nothing in this router writes today, and
        # the one entry in the table this test cannot justify from the code.
        writes = {
            plugin.name: [
                call
                for path in sorted(plugin.glob("*.go"))
                if not path.name.endswith("_test.go")
                for call in re.findall(
                    r"state\.Write\w*\(", path.read_text(encoding="utf-8")
                )
            ]
            for plugin in (
                REPO / "plugin" / "executable" / "cdn_rewrite",
                REPO / "plugin" / "executable" / "dhcp_forward",
            )
        }
        self.assertEqual(
            writes,
            {"cdn_rewrite": ["state.WriteJSONAtomic("], "dhcp_forward": []},
            "a plugin that has started writing a second document has changed the router's write "
            f"set, and the writable directory is {RUNTIME_DIR}",
        )
        self.assertIn(
            f"ech_state_file: {ECH_STATE}",
            (CONFIG_DIR / "mosdns.yaml").read_text(encoding="utf-8"),
            "the shipped routing document is what tells the router which document to publish",
        )
        self.assertIn(
            RUNTIME_DIR,
            self._writable(ROUTER),
            f"the router publishes {ECH_STATE}, so {RUNTIME_DIR} has to be writable in it",
        )

    def test_the_optimizer_and_the_health_check_take_the_control_lock_under_a_writable_directory(self):
        for name in (OPTIMIZER, HEALTH):
            with self.subTest(unit=name):
                writable = self._writable(name)
                self.assertIn(
                    os.path.dirname(CONTROL_LOCK),
                    writable,
                    f"{name} acquires {CONTROL_LOCK} through a read-only descriptor, so the "
                    "directory holding it has to be writable or the command fails at its first "
                    "control operation",
                )
        for name, path in ((OPTIMIZER, SELECTOR), (HEALTH, HEALTH_STATE), (OPTIMIZER, BANDWIDTH_BUDGET)):
            with self.subTest(unit=name, document=path):
                self.assertIn(
                    os.path.dirname(path),
                    self._writable(name),
                    f"{name} writes {path}",
                )
        self.assertIn(
            LISTS_DIR,
            self._writable(OPTIMIZER),
            f"the optimizer caches the published range document at {RANGES_CACHE}",
        )

    def test_every_writable_directory_is_named_by_something_that_writes_there(self):
        for name in SERVICES:
            with self.subTest(unit=name):
                for path in self._writable(name):
                    self.assertIn(
                        path,
                        (RUNTIME_DIR, LISTS_DIR, RUN_DIR),
                        f"{name} makes {path} writable, which is not one of the three state "
                        "directories this package provisions",
                    )
                for path in WRITE_TABLE[name]:
                    self.assertIn(
                        path,
                        self._writable(name),
                        f"{name} writes {path}, so it must be writable in {name}",
                    )


if __name__ == "__main__":
    unittest.main()
