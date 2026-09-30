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
shipped unit except ``Description=``, which is prose; the comments in the unit
files are prose too, and neither is pinned, because pinning documentation makes a
test fail over a rewording and trains everyone to rewrite the test instead of the
thing it describes. Everything that is a decision is pinned -- ``Documentation=``
included, because naming the manual page a unit is documented by is a decision --
and a unit that grows a directive nobody decided on fails.
"""

import ipaddress
import os
import re
import shutil
import subprocess
import sys
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
WATCHDOG = "mosdns-watchdog.service"
WATCHDOG_TIMER = "mosdns-watchdog.timer"

SHIPPED_UNITS = (
    ROUTER,
    DNSCRYPT,
    OPTIMIZER,
    OPTIMIZER_TIMER,
    HEALTH,
    HEALTH_TIMER,
    LIST_CHECK,
    LIST_CHECK_TIMER,
    WATCHDOG,
    WATCHDOG_TIMER,
)

SERVICES = (ROUTER, DNSCRYPT, OPTIMIZER, HEALTH, LIST_CHECK, WATCHDOG)
TIMERS = (OPTIMIZER_TIMER, HEALTH_TIMER, LIST_CHECK_TIMER, WATCHDOG_TIMER)

# The installed layout every ExecStart names. The two documents are the renderer's
# own output file names, which is why `test_the_units_name_the_files_the_renderer_publishes`
# reads them back out of render.go rather than trusting this spelling.
ROUTER_BINARY = "/usr/lib/mosdns-router/mosdns-router"
CDNCTL_BINARY = "/usr/lib/mosdns-router/mosdns-cdnctl"
DNSCRYPT_BINARY = "/usr/lib/mosdns-router/dnscrypt-proxy"
# The installer as a program. It is the only part of this package that already
# knows what "resolvable" means -- one predicate, `response_resolves`, shared by
# the install's barrier, its waits and its verification -- and the health unit's
# second ExecStart is here rather than a Go re-implementation for exactly that
# reason.
INSTALLER = "/usr/lib/mosdns-router/mosdns_installer.py"
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


def _watchdog_record_path() -> str:
    """The watchdog's one written file, read out of the program that writes it.

    Imported rather than restated, and the reason is this project's own subject:
    a table row that repeats a path constant is a second answer to the question
    the constant answers, and the whole defect this plan's rulings keep naming is
    two definitions of one fact. A moved `WATCHDOG_RECORD` has to be a failure
    of the unit's writable set, not a row here that quietly stops matching.
    """
    sys.path.insert(0, str(REPO / "installer"))
    import mosdns_installer

    return mosdns_installer.WATCHDOG_RECORD


WATCHDOG_RECORD = _watchdog_record_path()
# The directory that record lives in, read out of the program the same way, so
# the unit's write permission and the program's own path cannot drift apart. It
# is its own directory and not RUN_DIR because /run/mosdns is group-writable by
# design (ruling 142: the DHCP bridge publishes there as mosdns-cdn), and unlink
# and rename are the containing directory's decision rather than a file's mode --
# so a 0600 record in there could be deleted, or replaced with a streak that has
# already reached its window, by the one unprivileged identity in this package.
WATCHDOG_RECORD_DIR = os.path.dirname(WATCHDOG_RECORD)

# The sandbox every service in this package gets, as (key, value) pairs. It is one
# list for all six services on purpose: short-lived or long-lived programs that
# read documents, write state and open sockets, with no use for /tmp, for devices,
# for kernel knobs or for anything under /home. A per-service subset would be a
# privilege decision nobody can review at a glance, and the only per-identity
# differences in this package are the ones the tables below name: the user, the
# capability set and the writable paths.
#
# The watchdog is in this list on the strength of the ruling that a unit beside
# another one inherits the packaged hardening rather than inventing its own: it
# reads two documents, writes one file and opens one loopback socket, and a
# subset would be a second hardening shape to review. What it does NOT inherit is
# the identity -- `mosdns-cdnctl emergency-rollback` refuses a non-root uid, so
# `mosdns-watchdog.service` runs as root with an empty bounding set, and that is
# the only per-identity difference in the table below.
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
# ACL grants by group, so `root:mosdns` 2770 with a default ACL for `mosdns` is
# what lets either identity replace the other's files; per-service groups would
# give the ACL to one identity and leave the other unable to write. The mode is
# 2770 rather than 2750 because a group member cannot create a file in a 2750
# directory at all -- measured on the system-level test machine, and the reason is
# in the packaging plan's mode table.
#
# The rows are the code's write set, not a decision this module could make: each
# one is derived from the writer that produces it and compared for equality, so a
# unit that grants a directory the writer does not use and a writer that starts
# using a directory the unit does not grant both fail here.
#
# The router writes the ECH state and nothing else -- cdn_rewrite publishes it and
# dhcp_forward only reads the state the bridge publishes. It therefore does not
# make /run/mosdns writable: the DHCP state arrives asynchronously from a
# NetworkManager dispatcher, the plugin tolerates its absence, and an unprefixed
# ReadWritePaths entry naming a directory that is not there fails the only
# resolver on the host. The optimizer and the health check write the selector, the
# budget, the health document and the control lock under the runtime directory,
# and only the optimizer writes the published range cache under the lists
# directory. The list check writes nothing at all -- `update-lists --check` is
# documented to take no lock and write no file -- and dnscrypt-proxy's cache is
# off, so those two units name no writable directory. The bridge has no unit:
# NetworkManager runs it as root from a `no-wait.d` dispatcher script, so it is a
# row below and nowhere else.
WRITE_TABLE = {
    ROUTER: (RUNTIME_DIR,),
    OPTIMIZER: (RUNTIME_DIR, LISTS_DIR),
    HEALTH: (RUNTIME_DIR,),
    LIST_CHECK: (),
    DNSCRYPT: (),
    # One file, on the tmpfs: the consecutive-failure record, in a root-owned
    # subdirectory of its own rather than in /run/mosdns. The row is derived from
    # `WATCHDOG_RECORD` below rather than written out, because a table row that
    # restates a constant is a second answer to the question the constant already
    # answers -- and the derivation is what keeps the unit's write permission and
    # the program's record path from drifting apart.
    WATCHDOG: (WATCHDOG_RECORD_DIR,),
}
# The bridge's row: it has no unit, so it appears in no table above, and the only
# thing a test can say about it is where it writes.
BRIDGE_WRITES = (RUN_DIR,)

# The watchdog's one written file, read out of the program that writes it rather
# than written here: a table that restated the path would be a second place to
# change it, and this is exactly the defect the two-definition ruling is about.
WATCHDOG_RECORD = _watchdog_record_path()

# The directories this package provisions, and so the only ones a ReadWritePaths
# entry may name without the `-` prefix. /var/lib/mosdns/runtime and
# /var/lib/mosdns/lists are created by the package's postinst and survive a
# reboot; /run/mosdns is on a tmpfs and is recreated by a tmpfiles.d entry, so
# it is a volatile path like any other (see VOLATILE_PREFIXES).
PROVISIONED = (RUNTIME_DIR, LISTS_DIR)

# The directories that are gone after a reboot, so a ReadWritePaths entry naming
# one fails the unit at start if the path is absent -- and the unprefixed form is
# fatal. `-` is what makes a missing path tolerated. Nothing in this package
# needs a volatile path: see the router's row above.
VOLATILE_PREFIXES = ("/run/", "/var/run/", "/tmp/", "/dev/shm/")

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
    # root, explicitly and with an empty bounding set. The verb this unit runs
    # execs `mosdns-cdnctl emergency-rollback`, which refuses a non-root uid, so
    # a unit that ran it as a service identity would fail at the action every time
    # with a message about privileges rather than about DNS. It needs no
    # capability: the action reaches NetworkManager over D-Bus and the daemon at
    # the other end does the writing.
    WATCHDOG: ("root", "root"),
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
    WATCHDOG: (),
}

# The four schedules, pinned. The optimizer is 03:00 local time and catches up
# after a machine that was off; the health check is every two minutes and must not
# be persistent, because a two-minute cadence with Persistent=true replays a
# backlog of every check the machine missed; the list check is daily after the
# optimizer's window and is report-only, and it is persistent for the opposite
# reason the health timer is not -- a report nobody will ever be shown is not a
# report; and the watchdog is every minute, NOT persistent for the health timer's
# measured reason at a cadence that is thirty times worse, and three minutes after
# boot rather than immediately, because at boot the router is still coming up and
# a probe before then fails by construction.
SCHEDULES = {
    OPTIMIZER_TIMER: (("OnCalendar", "*-*-* 03:00:00"), ("Persistent", "true")),
    HEALTH_TIMER: (("OnBootSec", "2min"), ("OnUnitActiveSec", "2min")),
    LIST_CHECK_TIMER: (("OnCalendar", "*-*-* 03:30:00"), ("Persistent", "true")),
    WATCHDOG_TIMER: (("OnBootSec", "3min"), ("OnUnitActiveSec", "1min")),
}

# Every directive of every shipped unit, except Description=.
UNIT_DIRECTIVES = {
    ROUTER: {
        "Unit": (
            # The manual page this router is documented by. The verify harness
            # stubs man(1), so this directive is checked here whether or not the
            # package has installed the page yet; Task 6 owns shipping the page.
            ("Documentation", "man:mosdns-router(8)"),
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
            # The start rate limit, stated rather than inherited. The defaults are
            # StartLimitIntervalSec=10s and StartLimitBurst=5, and with this unit's
            # RestartSec=5s the fifth retry is already outside a ten-second window,
            # so the burst is never reached and the unit loops every five seconds
            # for ever. These two make the claim the Restart comment below makes
            # true: a permanently missing prerequisite -- the Cloudflare prefix list
            # is a hard start requirement -- ends in a visible failed unit.
            ("StartLimitIntervalSec", "60s"),
            ("StartLimitBurst", "5"),
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
            ("ReadWritePaths", f"{RUNTIME_DIR}"),
        ),
        "Install": (("WantedBy", "multi-user.target"),),
    },
    DNSCRYPT: {
        "Unit": (
            ("Documentation", "man:dnscrypt-proxy(8)"),
            ("After", "network.target"),
        ),
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
        "Unit": (
            ("Documentation", "man:mosdns-cdnctl(1)"),
            ("After", "network.target"),
        ),
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
        "Unit": (
            ("Documentation", "man:mosdns-cdnctl(1)"),
            ("After", "network.target"),
        ),
        "Service": (
            ("Type", "oneshot"),
            ("User", "mosdns-cdn"),
            ("Group", "mosdns"),
            ("ExecStart", f"{CDNCTL_BINARY} health-check"),
            # The second command, and the whole of the "nothing notices the router
            # stopped" gap: `health-check` proves the CDN address, not the machine's
            # own resolver at 127.0.0.1:53, so a router that is down passed this
            # unit every two minutes for ever. This one asks the LOCAL resolver --
            # with the installer's own resolvable predicate, so "resolvable" has one
            # definition in this package and not two -- and fails the unit when the
            # answer is a SERVFAIL or silence.
            #
            # It is last so the CDN verdict is recorded before the machine's, and it
            # runs as the same identity with the same sandbox: the installer only
            # reads and opens a socket.
            ("ExecStart", f"{INSTALLER} verify-local"),
            # A pass is bounded by 60 s and a transition's proof by 15 s, so 110 s
            # is above everything the command can legitimately spend and below the
            # two-minute cadence: a check that hangs is killed before the next
            # elapse instead of overlapping it. The local probe is a single
            # two-second query, so the budget is still the health check's.
            ("TimeoutStartSec", "110"),
            # The same control-lock race as the optimizer's, and the same reason.
            ("SuccessExitStatus", "4"),
            ("CapabilityBoundingSet", ""),
            ("UMask", "0007"),
        )
        + SANDBOX
        + (
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            # The runtime directory only: the health document, the selector this
            # command may transition and the control lock are everything it writes.
            ("ReadWritePaths", f"{RUNTIME_DIR}"),
        ),
    },
    LIST_CHECK: {
        "Unit": (
            ("Documentation", "man:mosdns-cdnctl(1)"),
            ("After", "network.target"),
        ),
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
        "Unit": (("Documentation", "man:mosdns-cdnctl(1)"),),
        "Timer": (("Unit", OPTIMIZER),) + SCHEDULES[OPTIMIZER_TIMER],
        "Install": (("WantedBy", "timers.target"),),
    },
    HEALTH_TIMER: {
        "Unit": (("Documentation", "man:mosdns-cdnctl(1)"),),
        "Timer": (("Unit", HEALTH),) + SCHEDULES[HEALTH_TIMER],
        "Install": (("WantedBy", "timers.target"),),
    },
    LIST_CHECK_TIMER: {
        "Unit": (("Documentation", "man:mosdns-cdnctl(1)"),),
        "Timer": (("Unit", LIST_CHECK),) + SCHEDULES[LIST_CHECK_TIMER],
        "Install": (("WantedBy", "timers.target"),),
    },
    WATCHDOG: {
        "Unit": (
            # The installer's own page: the watchdog is a verb of the program
            # that also does the install, and the page is where the action it
            # runs and the setting it reads are described.
            ("Documentation", "man:mosdns-router(8)"),
            # `After=` NetworkManager, and none of Requires=, BindsTo=, PartOf=,
            # PropagatesStopTo= or Upholds=. Measured rather than preferred: the
            # watchdog reaches NetworkManager over D-Bus through the action, and
            # `Requires=` on a unit a service only talks to is a cycle, not a
            # race -- NetworkManager's own restart would take this unit down with
            # it, and a machine whose resolver is already dead is the worst place
            # to lose the thing that is watching for it.
            ("After", "network.target NetworkManager.service"),
        ),
        "Service": (
            ("Type", "oneshot"),
            # root, because the verb execs `mosdns-cdnctl emergency-rollback`,
            # which refuses a non-root uid. No capability: the action talks to
            # NetworkManager over D-Bus.
            ("User", "root"),
            ("Group", "root"),
            ("ExecStart", f"{INSTALLER} watchdog"),
            # Above the action's own budget, on purpose: a watchdog killed part
            # way through a restore prints nothing, and a rollback killed
            # mid-restore is the worst thing this package can do unattended.
            #
            # That budget is 302s -- `ROLLBACK_COMMAND_BUDGET` (9) x
            # `COMMAND_TIMEOUT_SECONDS` (30) + a 2s probe + 30s of slack -- and
            # this is 330. It was 180, against a 150s action budget that was
            # itself smaller than the work (9 x 30 = 270s), so the unit's claim
            # and its number disagreed with the program's. The number here is
            # pinned AND re-derived: `test_watchdog.py` measures how many
            # commands the rollback actually issues, recomputes 302 from that and
            # the per-command budget, and requires this to exceed it -- so a
            # sixth command or a longer per-command timeout fails that gate
            # rather than leaving this table quietly stale.
            ("TimeoutStartSec", "330"),
            # No SuccessExitStatus, and that is the difference from the health
            # check's exit 4. Every non-zero exit here is something an operator
            # has to read: this program's own 1 (not resolving and the window not
            # reached, the setting unreadable, or the record unwritable) and the
            # ACTION's own status passed through unchanged, so a caller can tell a
            # rollback that did not finish from one that changed nothing without
            # parsing a sentence.
            ("CapabilityBoundingSet", ""),
            ("UMask", "0007"),
        )
        + SANDBOX
        + (
            # AF_UNIX for the D-Bus connection the action makes to
            # NetworkManager, AF_INET for the probe. The health check's list
            # exactly: no interface is enumerated and no netlink socket is
            # opened.
            ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
            # Exactly one directory, the record's OWN 0700 root:root
            # subdirectory rather than /run/mosdns -- which is group-writable by
            # design, and a 0600 file inside a group-writable directory is still
            # deletable and replaceable. The `-` prefix is load-bearing: /run is
            # a tmpfs, so this directory is gone after a reboot, and an unprefixed
            # entry naming a path that is not there fails the unit's
            # mount-namespace setup -- so the machine's only automatic DNS
            # protection would be the retry loop.
            ("ReadWritePaths", f"-{WATCHDOG_RECORD_DIR}"),
        ),
    },
    WATCHDOG_TIMER: {
        "Unit": (("Documentation", "man:mosdns-router(8)"),),
        "Timer": (("Unit", WATCHDOG),) + SCHEDULES[WATCHDOG_TIMER],
        "Install": (("WantedBy", "timers.target"),),
    },
}

# Prose, and prose only. See the module docstring for why neither is pinned.
# Documentation= is NOT in this set: a unit that documents itself points at a
# manual page, and a package that has not installed its pages yet is a package
# whose content test is missing -- not a reason for the unit to stop saying what it
# documents. The verify harness stubs man(1) for that reason, so the directive is
# checked here and the pages are Task 6's obligation.
PROSE_KEYS = frozenset({"Description"})


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


def unit_comments(name):
    """Every comment line of one shipped unit, as ONE space-joined string.

    A unit file is half prose, and the prose is what a reader -- and a reviewer --
    reasons about when the directives are not enough. So a claim made in a comment is
    a claim this suite can hold, and this reader is what makes that possible.

    Space-joined rather than line-joined, and the reason is a rewrap: a claim that
    happens to straddle a line break is the same claim, and a reader that reported the
    file's line breaks would make every assertion about it a test of where somebody
    pressed return. Empty comment lines are dropped, so the `#` on its own that
    separates paragraphs does not become a run of spaces inside a phrase.
    """
    lines = [
        line[1:].strip()
        for line in unit_text(name).splitlines()
        if line.lstrip().startswith("#")
    ]
    return " ".join(line for line in lines if line)


def duration_seconds(value):
    """A systemd duration in seconds, for the two spellings this package uses.

    Only the forms the units actually carry, and it says so when it meets another:
    a reader that silently read `5min` as five would let a rate-limit check pass on
    a unit whose window is five minutes, which is the direction the check exists to
    catch.
    """
    text = value.strip()
    for suffix, scale in (("ms", 0.001), ("s", 1.0), ("min", 60.0), ("h", 3600.0)):
        if text.endswith(suffix):
            return float(text[: -len(suffix)]) * scale
    raise AssertionError(f"{value!r} is not a duration this reader knows how to read")


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


def tolerant(path: str) -> str:
    """A `ReadWritePaths` entry with systemd's `-` prefix removed, if it carries one.

    The prefix is a **start-time tolerance marker** and not part of the path: it
    tells systemd to ignore the entry when the directory is absent, which is what
    every entry naming a volatile path has to say. So the write set is a table of
    directories and the marker is a property of the unit's spelling, and mixing
    the two would put `-/run/mosdns` in a table whose other rows are plain paths
    -- where it would read as a fourth directory rather than as a flag on the
    third.
    """
    return path[1:] if path.startswith("-") else path


def write_path_problems(name, sections, expected):
    """How a unit's writable paths differ from the identity's write set."""
    values = directive_value(sections, "Service", "ReadWritePaths")
    declared = tuple(
        tolerant(part) for value in values for part in value.split() if part
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


def toml_scalar(text, key):
    """One scalar from a dnscrypt-proxy document, as an int where it reads as one.

    `None` when the key is absent, which is the answer the caller needs: a
    document that does not set a key at all is a document running the program's
    own default for it, and a test that read a default as a value would compare
    two numbers that were never written down.
    """
    match = re.search(rf"^{key}\s*=\s*(\S+)\s*$", text, flags=re.MULTILINE)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return match.group(1).strip("'\"")


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
                        # Unit, Service, Timer and Install are the only sections a
                        # service or a timer in this package has. A [Socket] here
                        # would be socket activation, which is a different way for
                        # the machine to reach a unit than "start it", and no
                        # directive of one would be a decision anybody made.
                        ("Unit", "Service", "Timer", "Install"),
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
                    # root is the third answer, and the reason is a refusal in
                    # another program: `mosdns-cdnctl emergency-rollback` exits
                    # non-zero for a non-root uid, so the watchdog has to be root
                    # to run the action at all. The two mosdns service users share
                    # the group the state directories' default ACL names, because
                    # an ACL grants by group and per-service groups would let only
                    # one of them replace the other's files; the resolver shares no
                    # state with either, so it has a group of its own.
                    "root" if name == WATCHDOG
                    else ("mosdns" if name != DNSCRYPT else "dnscrypt-proxy"),
                    "the identity table is what says which of this package's three "
                    "identities a unit runs as, and each of the three has a reason",
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

    def test_a_writable_path_that_does_not_exist_is_tolerated_or_absent(self):
        # The form of a ReadWritePaths entry is a start-time decision, not a
        # convenience. Unprefixed, the path must exist or the unit fails its
        # mount-namespace setup -- and systemd retries that failure on every
        # RestartSec, so a path that is absent on a host is not a unit that starts
        # late, it is a resolver that never comes up. The `-` prefix is what makes a
        # missing path tolerated.
        #
        # A path under /run, /var/run, /tmp or /dev/shm is a volatile path: it is
        # gone after a reboot whatever an installer did, and only a tmpfiles.d entry
        # brings it back. So an entry naming one has to be `-`-prefixed whether or
        # not this package installs that entry itself, and an unprefixed entry has to
        # name a directory the package provisions.
        for name in SERVICES:
            values = directive_value(parsed(name), "Service", "ReadWritePaths")
            entries = [part for value in values for part in value.split() if part]
            for entry in entries:
                tolerated = entry.startswith("-")
                path = entry[1:] if tolerated else entry
                with self.subTest(unit=name, path=path):
                    if path.startswith(VOLATILE_PREFIXES):
                        self.assertTrue(
                            tolerated,
                            f"{name} names {path} without the `-` prefix. It is a volatile "
                            "path, so a host that has not created it yet fails this unit's "
                            "mount-namespace setup, and the retry that follows is the only DNS "
                            "path on the machine coming up and going down",
                        )
                        continue
                    self.assertIn(
                        path,
                        PROVISIONED,
                        f"{name} names {path} unprefixed, and {path} is not a directory this "
                        f"package provisions ({list(PROVISIONED)}). An unprefixed entry has to "
                        "name a path that exists when the unit starts, because nothing creates "
                        "it at that moment",
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

    def test_the_health_unit_also_asks_whether_the_local_resolver_resolves(self):
        # The gap this closes: `health-check` proves the CDN address in service, so
        # a router that is DOWN passed this unit every two minutes for ever, and
        # there was no other path from a dead router back to the machine's own
        # resolvers. The unit fails; what an operator does with that failure is
        # `emergency-rollback`, and that is a decision this package does not make
        # for them.
        starts = directive_value(parsed(HEALTH), "Service", "ExecStart")
        self.assertEqual(
            starts,
            [f"{CDNCTL_BINARY} health-check", f"{INSTALLER} verify-local"],
            "the health service runs the CDN check and nothing else, so a machine whose local "
            "resolver stopped answering looks healthy to it",
        )
        # The probe must fail the unit, and `SuccessExitStatus=4` must not excuse
        # it: the installer's "it did not resolve" is exit 1, so the two cannot
        # collide by accident -- and this is the assertion that says so.
        self.assertNotIn(
            "1",
            directive_value(parsed(HEALTH), "Service", "SuccessExitStatus"),
            "a local resolver that does not resolve must fail this unit",
        )

    def test_the_local_probe_reuses_the_installers_resolvable_predicate(self):
        # One definition of "resolvable" in this package, not two. The installer's
        # `response_resolves` is the one the barrier, the waits and the
        # verification all use, and a Go re-implementation of it in the health
        # command is a second answer to the same question.
        source = (REPO / "installer" / "mosdns_installer.py").read_text(encoding="utf-8")
        self.assertIn(
            "def response_resolves(", source,
            "the installer's resolvable predicate is gone, so the health unit's second ExecStart "
            "has nothing to reuse",
        )
        command = subprocess.run(
            [sys.executable, str(REPO / "installer" / "mosdns_installer.py")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(command.returncode, 2, "the installer no longer refuses a usage error")
        self.assertIn("verify-local", command.stderr, "the verb the health unit runs is not there")

    def test_the_health_unit_says_what_its_second_command_now_reads(self):
        """The unit's own header was corrected in the round that gave `verify-local` the
        two force-ECH predicates; the verb's `main` docstring was corrected and the
        unit's comment was not.

        It said "It takes no root, reads no file, changes nothing", which became false
        the moment the verb was given `_forced_ech_domains(root)` and
        `_ech_may_answer_locally(root)`: it reads `/etc/mosdns/policy.yaml` and the
        operator's `/etc/mosdns/force-ech-domains.txt` through the root, which is
        what lets a test point it at a fake root. A unit file that says a command
        reads nothing is read by whoever has to reason about its sandbox, and the
        sandbox here is `ProtectSystem=strict` with no `ReadOnlyPaths` for /etc --
        so the claim is the kind that makes a reader stop looking.

        Held as a claim to be true rather than as a phrase to be present: the test
        asserts the unit does NOT carry the old claim, and that it says what it reads
        instead. A comment nobody checks is a comment a later edit deletes.
        """
        comments = unit_comments(HEALTH)
        for stale in ("reads no file", "takes no root"):
            with self.subTest(claim=stale):
                self.assertNotIn(
                    stale, comments,
                    f"the health unit still says its second command {stale}, which stopped being "
                    "true when verify-local was given the two force-ECH predicates and began "
                    "reading the policy and the operator's force-ECH list through the root",
                )
        for said in (FORCE_ECH, POLICY):
            with self.subTest(says=said):
                self.assertIn(
                    said, comments,
                    f"the health unit does not name {said}, which the command it runs reads, so "
                    "a reader reasoning about this unit's sandbox has to find that out elsewhere",
                )

    def test_the_health_unit_says_that_one_of_its_two_failure_modes_is_not_the_signal(self):
        """The unit header still presented "this unit failing is the signal" with nothing
        about the case where it is not one.

        `verify-local` FAILS -- rather than warns -- when the operator's force-ECH list
        makes the router answer the probe name itself, because then a resolved answer
        from `127.0.0.1:53` is evidence of nothing. That is a real failure of this
        unit and it is NOT a sign the router is down, and the health unit failing is
        the signal an operator is told to act on with `emergency-rollback`. A machine
        that was working perfectly would be rolled back over a line in a text file.
        The verb's own message says so in as many words; the unit did not.
        """
        comments = unit_comments(HEALTH)
        self.assertIn("this unit failing is the signal", comments)
        self.assertIn(
            "NOT A SIGN THE ROUTER IS DOWN", comments,
            "the health unit says a failing unit is the signal and nothing about the one case "
            "in which it is not one, so the sentence is false exactly where it is most costly",
        )
        # And the not-a-signal case names the entry, because the fix is a line in a
        # file and an operator who is not told which file cannot act on it.
        self.assertIn(FORCE_ECH, comments)

    def test_the_router_retry_burst_is_reachable_so_a_missing_prerequisite_ends_in_a_failed_unit(self):
        # The router's comment justifies `Restart=on-failure` by claiming the start
        # rate limit "bounds the retries, so a permanently missing prerequisite ...
        # ends in a visible failed unit ... rather than in a loop". With the
        # systemd defaults (StartLimitIntervalSec=10s, StartLimitBurst=5) and this
        # unit's RestartSec=5s, the counter never reaches the burst: every window of
        # ten seconds holds at most three starts, so the unit restarts for ever and
        # the claim is false in the direction that matters.
        sections = parsed(ROUTER)
        interval = duration_seconds(one_directive(sections, "Unit", "StartLimitIntervalSec"))
        burst = int(one_directive(sections, "Unit", "StartLimitBurst"))
        restart = duration_seconds(one_directive(sections, "Service", "RestartSec"))
        self.assertEqual(one_directive(sections, "Service", "Restart"), "on-failure")
        self.assertLessEqual(
            burst * restart, interval,
            f"{burst} restarts {restart:g}s apart span {burst * restart:g}s, which is more than the "
            f"{interval:g}s window, so the burst is never reached and the unit loops for ever "
            "instead of ending in a visible failed unit",
        )
        # And the teeth: the same arithmetic against the defaults this unit used to
        # inherit, so the assertion above is known to be able to fail.
        self.assertGreater(5 * restart, 10.0, "the defaults would not have failed this check")

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

    def test_every_listener_the_configs_name_is_loopback(self):
        # The scoped name is the honest one. This class checks BINDINGS and nothing
        # else, because the broad reading -- every address either document names --
        # is not a property this package can have: the resolver document has to name
        # Quad9's own addresses to bootstrap provider names and to probe
        # reachability, and those are destinations it dials, not interfaces it is
        # reachable on. The units are held to the broad reading in
        # test_no_unit_names_an_address_outside_loopback, where it is satisfiable,
        # because a unit file is not supposed to name an address at all.
        for path in (
            sorted(CONFIG_DIR.glob("mosdns.yaml"))
            + sorted(CONFIG_DIR.glob("dnscrypt-proxy.toml"))
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


# What a diagnostic has to mention to be this package's business. The fake root
# holds the host's own systemd units, and resolving a target's default
# dependencies walks all of them: on a host that ships dracut, a unit in
# /usr/lib/dracut is enabled by a symlink from /usr/lib/systemd/system that points
# outside the copied tree, so it dangles in the fake root and systemd reports it.
# Those are the host's diagnostics, about the host's packages, and they are the
# same on every unit this package ships -- so the gate is not "stderr is empty" but
# "nothing systemd said is about this package".
OUR_SUBJECTS = tuple(SHIPPED_UNITS) + (
    ROUTER_BINARY,
    CDNCTL_BINARY,
    DNSCRYPT_BINARY,
    ROUTER_CONFIG,
    DNSCRYPT_CONFIG,
    POLICY,
    RUNTIME_DIR,
    LISTS_DIR,
    RUN_DIR,
)


def our_diagnostics(name, completed):
    """The lines of a verify run that are about this package rather than the host."""
    lines = (completed.stdout + completed.stderr).splitlines()
    return [
        line
        for line in lines
        if line.strip() and any(subject in line for subject in OUR_SUBJECTS)
    ]


def host_wants_entries(root):
    """The `*.wants/<unit>` entries under a systemd unit tree, as relative paths.

    The `.wants` is a suffix of a path component rather than a component of its
    own -- ``getty.target.wants/getty@tty1.service`` -- so the suffix is what is
    matched.
    """
    return sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if any(part.endswith(".wants") for part in path.parts)
        and not path.name.endswith(".wants")
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
        # Symlinks are PRESERVED, which is the whole reason this is a copy and not
        # a selection. `symlinks=False` follows them, and following a relative link
        # resolves it against the process's working directory rather than against
        # the link's own directory -- so every one of the ~100 `*.wants` entries in
        # a normal /usr/lib/systemd/system resolves to nothing, copytree is asked to
        # ignore a dangling link, and the fake root ends up with no wants entries at
        # all. That failure is silent, the closure is resolved without the target's
        # real dependencies, and the result is a check that is clean because of what
        # it dropped rather than because of what it verified. Preserved links
        # resolve inside the copy, which is what they were pointing at.
        shutil.copytree(
            systemd_units,
            target / "systemd",
            symlinks=True,
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
        # `man` is stubbed so the harness's verdict does not depend on whether this
        # package has installed its manual pages yet. `systemd-analyze verify`
        # shells out to man(1) for every Documentation= entry and fails the unit
        # with code 16 when the page is not there, and there is no --man=no to
        # decline it -- so a package that has not shipped its man pages yet would
        # otherwise be unable to state what it documents. Whether those pages exist
        # is a package-content question for Task 6, recorded in the plan; it is not
        # a unit-validity question and must not decide one.
        man = directory / "stub-bin" / "man"
        man.parent.mkdir(parents=True, exist_ok=True)
        man.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        man.chmod(0o755)
        return directory

    def _verify(self, units):
        self._require_analyze()
        with tempfile.TemporaryDirectory() as raw:
            self._fake_root(Path(raw), units)
            environment = dict(os.environ)
            environment["PATH"] = str(Path(raw) / "stub-bin") + os.pathsep + environment["PATH"]
            results = {}
            for name in sorted(units):
                completed = subprocess.run(
                    [self.analyze, "verify", "--root", raw, name],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    env=environment,
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
                    our_diagnostics(name, completed),
                    [],
                    f"systemd-analyze verify reported something about {name}, and a diagnostic "
                    "about this package's own unit is the whole reason this check exists",
                )

    def test_the_fake_root_keeps_the_wants_entries_it_exists_to_resolve(self):
        # A target's default dependencies are its .wants entries. A harness that
        # drops them resolves the closure without them and reports the result as
        # clean, so the copy is checked for having kept them -- as symlinks, since
        # a dereferenced copy of a relative link is a file at a path nothing points
        # at, which is the failure this test exists to make visible.
        host = Path("/usr/lib/systemd")
        self.assertTrue(
            host.is_dir(),
            "/usr/lib/systemd does not exist, so there is no unit tree to resolve default "
            "dependencies against",
        )
        expected = host_wants_entries(host)
        self.assertTrue(
            expected,
            "the host's systemd tree has no *.wants entries, so this check cannot tell a "
            "preserved link from a dropped one and the harness is not being verified",
        )
        with tempfile.TemporaryDirectory() as raw:
            self._fake_root(Path(raw), {name: unit_text(name) for name in SHIPPED_UNITS})
            copied = Path(raw) / "usr" / "lib" / "systemd"
            present = host_wants_entries(copied)
            missing = sorted(set(expected) - set(present))
            self.assertEqual(
                missing,
                [],
                f"{len(missing)} of the host's {len(expected)} .wants entries are not in the "
                f"fake root ({missing[:5]}), so the default dependencies this check resolves "
                "are not the ones a real system has",
            )
            for relative in expected:
                path = copied / relative
                self.assertTrue(
                    path.is_symlink(),
                    f"{relative} exists in the fake root as "
                    f"{'a regular file' if path.exists() else 'nothing'}, and a dereferenced "
                    "wants entry is an enablement nothing follows",
                )

    def test_a_diagnostic_about_this_package_is_not_mistaken_for_the_hosts(self):
        # The filter above is what replaces "stderr is empty", and a filter that
        # matches nothing is as weak as an empty-stderr assertion that never fires.
        # Both shapes are the real ones: systemd reports a broken property of our own
        # unit by naming it, and it reports the host's dangling dracut link by
        # naming that.
        class Reported:
            def __init__(self, text):
                self.stdout = ""
                self.stderr = text

        self.assertEqual(
            our_diagnostics(ROUTER, Reported(f"{ROUTER}:7: Unknown key 'Nope', ignoring.\n")),
            [f"{ROUTER}:7: Unknown key 'Nope', ignoring."],
            "a diagnostic naming one of this package's units is a failure, not noise",
        )
        self.assertEqual(
            our_diagnostics(
                ROUTER,
                Reported("dracut-pre-udev.service: Failed to open /fake/usr/lib/dracut/x.service\n"),
            ),
            [],
            "a diagnostic about the host's own unit tree is the host's problem, and failing on "
            "it would make this gate depend on which packages the build host has",
        )

    def test_the_man_stub_is_what_keeps_documentation_from_deciding_the_verdict(self):
        # `systemd-analyze verify` runs man(1) for every Documentation= entry and
        # fails the unit with code 16 when the page is not installed, and there is no
        # option to decline the check. Without the stub, a package that has not
        # shipped its manual pages cannot state what its units document, and the
        # only cure would be deleting the directive -- which is a package-completeness
        # question deciding a unit-validity one. This is the proof that the stub is
        # what changes the verdict, in both directions, on the same unit.
        self._require_analyze()
        documented = (
            "[Unit]\nDescription=x\nDocumentation=man:mosdns-router(8)\n\n[Service]\n"
            "Type=oneshot\nExecStart=/bin/true\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self._fake_root(root, {"broken-man.service": documented}, ["/bin/true"])
            stubbed = dict(os.environ)
            stubbed["PATH"] = str(root / "stub-bin") + os.pathsep + stubbed["PATH"]
            without = subprocess.run(
                [self.analyze, "verify", "--root", str(root), "broken-man.service"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            with_man = subprocess.run(
                [self.analyze, "verify", "--root", str(root), "broken-man.service"],
                capture_output=True,
                text=True,
                timeout=120,
                env=stubbed,
            )
        self.assertNotEqual(
            without.returncode,
            0,
            "without the stub this unit fails on its missing man page, so the stub is not "
            "what the shipped units are relying on and the claim in the harness docstring "
            "is wrong",
        )
        self.assertIn("man mosdns-router(8)", without.stdout + without.stderr)
        self.assertEqual(
            with_man.returncode,
            0,
            "with the stub on PATH the same unit verifies, which is the point: "
            f"{with_man.stdout}{with_man.stderr}",
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
            environment = dict(os.environ)
            environment["PATH"] = (
                str(root / "stub-bin") + os.pathsep + environment["PATH"]
            )
            for name, (_, refused, message) in broken.items():
                with self.subTest(unit=name):
                    completed = subprocess.run(
                        [self.analyze, "verify", "--root", str(root), name],
                        capture_output=True,
                        text=True,
                        timeout=120,
                        env=environment,
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


# The message every write-set failure ends with, so a person who has just added a
# writer is told what the row now owes them.
_HINT_NEW_WRITE = (
    "A writer that has appeared or moved has to be resolved to the path it writes, and that "
    "path's directory added to this unit's ReadWritePaths -- or the write has to be shown not to "
    "be this identity's. A unit that does not grant a directory its own writer needs fails at "
    "runtime with a mount-namespace error, which is not what an operator should be reading."
)

# Every way a Go program in this repository writes a file, so a new one cannot slip
# past by not being the state package's helper. This is a guard, not an allowlist:
# a call site that matches and cannot be resolved is a failure, not a pass.
WRITE_CALL = re.compile(
    r"(?P<call>\b(?:state\.\w*Write\w*|(?:os|ioutil)\.(?:WriteFile|Create|OpenFile|MkdirAll"
    r"|Mkdir|Rename|Remove|RemoveAll|Truncate))\s*\()"
)
# The path a write call is given: the first argument, which is a field of some
# receiver. A first argument that is a local variable cannot be followed from
# here, and is reported as unresolved rather than guessed at.
WRITE_TARGET = re.compile(r"^\s*(?:(?P<receiver>[A-Za-z_]\w*)\.)?(?P<field>\w+)\s*,")

PLUGIN_DIRS = (
    REPO / "plugin" / "executable" / "cdn_rewrite",
    REPO / "plugin" / "executable" / "dhcp_forward",
)


def go_sources(directory):
    """The non-test Go files of a directory, in a stable order."""
    return [
        (path.name, path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("*.go"))
        if not path.name.endswith("_test.go")
    ]


def go_text(directory):
    return "".join(body for _name, body in go_sources(directory))


def go_constant(name, directory):
    """The right-hand side of a top-level constant, or ``None``."""
    found = re.search(
        rf"^\s*{re.escape(name)}\s*=\s*(?P<value>.+?)\s*$",
        go_text(directory),
        flags=re.MULTILINE,
    )
    return found.group("value") if found is not None else None


def go_path_pieces(expression, directory, package_aliases, depth=0):
    """The string pieces a Go constant expression is built from, in order.

    A quoted literal is one piece. An identifier is another constant in the same
    package, resolved in turn -- which is how a directory constant and a file-name
    constant compose into one path. A qualified name is a constant in a package
    this file imports, and the import block says which directory that is. Anything
    else is refused, because a path this function cannot name is a path the table
    cannot be derived from and the row has to be resolved by hand.
    """
    if depth > 3:
        raise AssertionError(f"{expression!r} does not resolve within three hops")
    qualified = re.fullmatch(r"(?P<pkg>\w+)\.(?P<name>\w+)", expression.strip())
    if qualified is not None:
        alias = qualified.group("pkg")
        if alias not in package_aliases:
            raise AssertionError(
                f"{expression!r} names the package {alias!r}, which this derivation does not "
                "know the import path of"
            )
        target = REPO / package_aliases[alias]
        value = go_constant(qualified.group("name"), target)
        if value is None:
            raise AssertionError(
                f"{expression!r} names a constant that is not in {target.relative_to(REPO)}"
            )
        return go_path_pieces(value, target, package_aliases, depth + 1)
    pieces = []
    for literal, name in re.findall(r'"([^"]*)"|(\b[A-Za-z_]\w*\b)', expression):
        if literal:
            pieces.append(literal)
            continue
        if not name:
            continue
        value = go_constant(name, directory)
        if value is None:
            raise AssertionError(
                f"{name!r} in {expression!r} is not a top-level constant in "
                f"{directory.relative_to(REPO)}, so the path cannot be named from here"
            )
        pieces.extend(go_path_pieces(value, directory, package_aliases, depth + 1))
    return pieces


def resolve_go_path(expression, directory, package_aliases):
    """Resolve a Go constant expression to the absolute path it names."""
    path = "".join(go_path_pieces(expression, directory, package_aliases))
    if not path.startswith("/"):
        raise AssertionError(
            f"{expression!r} resolves to {path!r}, which is not an absolute path, so the "
            "directory it names cannot be put in a table"
        )
    return path


def router_write_calls():
    """Every write call site in the two plugins the router loads, resolved to a key.

    Each call is followed from the field it writes to the configuration key that
    supplies it: ``state.WriteJSONAtomic(e.statePath, ...)`` -> ``statePath:
    args.ECHStateFile`` -> ``ECHStateFile string `yaml:"ech_state_file"` ``. The
    hops are read out of the source, and a call site that does not resolve comes
    back with an empty key so the caller fails on it.
    """
    resolved = []
    for directory in PLUGIN_DIRS:
        sources = go_sources(directory)
        everything = "".join(body for _name, body in sources)
        for name, text in sources:
            for match in WRITE_CALL.finditer(text):
                line = text[match.start() : text.find("\n", match.start())]
                target = WRITE_TARGET.match(line[match.end("call") - match.start() :])
                key = ""
                if target is not None:
                    field = target.group("field")
                    supplied = re.search(
                        rf"^\s*{re.escape(field)}:\s*(?P<value>[^,\n]+),",
                        everything,
                        flags=re.MULTILINE,
                    )
                    if supplied is not None:
                        named = re.search(
                            r"args\.(?P<field>\w+)", supplied.group("value")
                        )
                        if named is not None:
                            tag = re.search(
                                rf"{named.group('field')}\s+string\s+`yaml:\"(?P<key>[^\"]+)\"`",
                                everything,
                            )
                            key = tag.group("key") if tag is not None else ""
                resolved.append((f"{directory.name}/{name}", match.group("call"), key))
    return resolved


def routing_document_value(key):
    """The value a key has in the shipped routing document, or ``None``."""
    if not key:
        return None
    found = re.search(
        rf"^\s*{re.escape(key)}:\s*(?P<value>\S+)\s*$",
        (CONFIG_DIR / "mosdns.yaml").read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    return found.group("value") if found is not None else None


def router_write_directories():
    """The directories the router's plugins write in, sorted."""
    directories = set()
    for _call_site, _call, key in router_write_calls():
        path = routing_document_value(key)
        if path is not None:
            directories.add(os.path.dirname(path))
    return tuple(sorted(directories))


CDNCTL_DIR = REPO / "cmd" / "mosdns-cdnctl"


def cdnctl_imports():
    """The import aliases of the command, mapped to the directory they name.

    Both spellings count: an import written with an explicit alias and one written
    bare, where the alias is the last element of the path. Go's own compiler
    decides the same thing, so a change to either form moves this map.
    """
    source = go_text(CDNCTL_DIR)
    aliases = {}
    for alias, path in re.findall(
        r'^\s*(\w+)\s+"mosdns-router/internal/(\w+)"', source, flags=re.MULTILINE
    ):
        aliases[alias] = f"internal/{path}"
    for path in re.findall(r'^\s*"mosdns-router/internal/(\w+)"', source, flags=re.MULTILINE):
        aliases[path] = f"internal/{path}"
    return aliases


def command_write_directories(constant_suffix, fields):
    """The directories a command's options hand it, resolved through its defaults.

    ``fields`` are the struct fields the call sets. Each is an ``options.<field>``
    on the parsed command line, each of those has a ``default...`` constant, and
    each of those is either a literal path or a constant in a package this command
    imports. Reading the four hops is what keeps the row equal to the code rather
    than to a comment about the code.
    """
    source = go_text(CDNCTL_DIR)
    aliases = cdnctl_imports()
    directories = set()
    for field in fields:
        option = re.search(
            rf"^\s*{re.escape(field)}:\s*options\.(?P<option>\w+),", source, flags=re.MULTILINE
        )
        if option is None:
            raise AssertionError(
                f"the {field} option is no longer set from the parsed command line, so this "
                "derivation cannot say what path the command writes and the row has to be "
                "resolved by hand"
            )
        named = option.group("option")
        # The constants in this file whose name carries the option's own, matched
        # on the declarations rather than on a naming convention: the option is
        # `budget` and the constant is `defaultBandwidthBudgetPath`, and a
        # convention that had to be guessed would break on the next flag.
        candidates = [
            name
            for name in re.findall(r"^\s*(default\w+)\s*=", source, flags=re.MULTILINE)
            if named.lower() in name.lower()
        ]
        if len(candidates) != 1:
            raise AssertionError(
                f"{len(candidates)} constants in cmd/mosdns-cdnctl carry the {named!r} option's "
                f"name ({candidates!r}), so this derivation cannot say which default the "
                f"{field} path comes from and the row has to be resolved by hand"
            )
        path = resolve_go_path(go_constant(candidates[0], CDNCTL_DIR), CDNCTL_DIR, aliases)
        directories.add(os.path.dirname(path))
    return tuple(sorted(directories))


def health_check_write_directories():
    """The directories `mosdns-cdnctl health-check` writes in, from its own options."""
    return command_write_directories(
        None, ("HealthPath", "SelectorPath", "ControlLockPath")
    )


def optimizer_write_directories():
    """The directories `mosdns-cdnctl test --apply` writes in, from its own paths."""
    runner = command_write_directories(
        None, ("BudgetPath", "SelectorPath", "ControlLockPath")
    )
    # The candidate fetch caches the published range document at --ranges-cache,
    # which the runner does not carry: it is a field of the source the run reads its
    # candidates from, and the constant for it does not follow the default<Option>
    # naming the other four do.
    source = go_text(CDNCTL_DIR)
    if "CachePath:" not in source:
        raise AssertionError(
            "the candidate fetch no longer names a ranges cache, so the optimizer's write set "
            "has to be resolved by hand"
        )
    cache = go_constant("defaultCloudflareRangesCache", CDNCTL_DIR)
    if cache is None:
        raise AssertionError("defaultCloudflareRangesCache is gone")
    return tuple(
        sorted(set(runner) | {os.path.dirname(resolve_go_path(cache, CDNCTL_DIR, cdnctl_imports()))})
    )


class WriteSetEvidenceTests(unittest.TestCase):
    """The write table against the code that writes, so it cannot rot silently.

    The table is not a decision this module could make and then check itself
    against: every row is derived from the writer that produces it -- the plugins
    the router loads, the options the two control commands are handed -- and
    compared for equality. A unit that grants a directory its identity does not
    write in fails, and a writer that starts using a directory its unit does not
    grant fails the other way, which is the direction a table nobody checks
    against the code fails in silently.
    """

    def _writable(self, name):
        sections = parsed(name)
        return [
            tolerant(path)
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

    def test_the_router_writable_set_is_exactly_what_its_plugins_write(self):
        # The router's write set is derived from the code that writes, not asserted
        # as a fact about it. Every write call site in either plugin is resolved
        # through to the configuration key it publishes, and the directories those
        # keys are given in the shipped routing document are compared for EQUALITY
        # with the table's row. So a unit that grants a directory the router does
        # not write in fails, and -- the other direction -- a plugin that starts
        # writing a document the unit does not grant also fails, with the message
        # naming the call site that has to be accounted for.
        self.assertEqual(
            tuple(sorted(self._writable(ROUTER))),
            router_write_directories(),
            "the router's writable set is what its two plugins write, and nothing else. "
            + _HINT_NEW_WRITE,
        )
        self.assertEqual(
            router_write_calls(),
            [
                (
                    "cdn_rewrite/ech_provider.go",
                    "state.WriteJSONAtomic(",
                    "ech_state_file",
                )
            ],
            "a write call site this derivation cannot resolve appeared in the router's plugins. "
            + _HINT_NEW_WRITE,
        )

    def test_the_health_check_writable_set_is_exactly_where_its_checker_is_pointed(self):
        # `health-check` builds its checker from three paths -- the health document,
        # the selector and the control lock -- and every one of them is handed to it
        # by name in runCDNHealthCheck. A fourth write would be a fourth option
        # field, and the derivation reads those options, so the row cannot drift.
        self.assertEqual(
            tuple(sorted(self._writable(HEALTH))),
            health_check_write_directories(),
            "the health check's writable set is the set of paths its checker is handed, and the "
            "DAC permissions of the shared group already grant it every one of them: a mount "
            "grant for a directory this command does not write in is redundant. "
            + _HINT_NEW_WRITE,
        )

    def test_the_optimizer_writable_set_is_exactly_what_its_paths_name(self):
        self.assertEqual(
            tuple(sorted(self._writable(OPTIMIZER))),
            optimizer_write_directories(),
            "the optimizer's writable set is the four paths its command is configured with: the "
            "selector, the budget, the control lock and the published range cache. "
            + _HINT_NEW_WRITE,
        )

    def test_the_optimizer_and_the_health_check_take_the_control_lock_under_a_writable_directory(self):
        for name in (OPTIMIZER, HEALTH):
            with self.subTest(unit=name):
                self.assertIn(
                    os.path.dirname(CONTROL_LOCK),
                    self._writable(name),
                    f"{name} acquires {CONTROL_LOCK} through a read-only descriptor, so the "
                    "directory holding it has to be writable or the command fails at its first "
                    "control operation",
                )

    def test_every_writable_directory_is_named_by_something_that_writes_there(self):
        for name in SERVICES:
            with self.subTest(unit=name):
                for path in self._writable(name):
                    self.assertIn(
                        path,
                        (RUNTIME_DIR, LISTS_DIR, RUN_DIR, WATCHDOG_RECORD_DIR),
                        f"{name} makes {path} writable, which is not one of the state "
                        "directories this package provisions",
                    )
                for path in WRITE_TABLE[name]:
                    self.assertIn(
                        path,
                        self._writable(name),
                        f"{name} writes {path}, so it must be writable in {name}",
                    )

    def test_the_watchdogs_writable_directory_is_the_record_s_own_and_nothing_broader(self):
        # The rule the other six units follow, and the one the watchdog is most
        # able to break: it runs as ROOT, so every directory it is granted is a
        # directory root can write anywhere in. It writes one file, so it is
        # granted one directory -- and that directory is the record's own 0700
        # root:root one rather than /run/mosdns, which is group-writable by
        # design and holds the DHCP generation the router reads.
        self.assertEqual(self._writable(WATCHDOG), [WATCHDOG_RECORD_DIR])
        self.assertNotIn(
            RUN_DIR,
            self._writable(WATCHDOG),
            "the watchdog is granted the bridge's group-writable directory, so a compromise of it "
            "can remove the DHCP generation the router follows as well as the failure record",
        )
        self.assertEqual(
            os.path.dirname(WATCHDOG_RECORD),
            WATCHDOG_RECORD_DIR,
            "the record is not in the directory the unit is granted write access to",
        )


if __name__ == "__main__":
    unittest.main()
