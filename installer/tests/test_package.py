"""Hold the Debian package to the machine it is allowed to make.

A package is the one artifact in this project that can change a machine without
asking a question, and nothing about what it would do is visible in the code that
does it: three compiled binaries, eight unit files, six configuration documents,
a maintainer script, a dispatcher hook, three manual pages and a tmpfiles entry
are all opaque files a reviewer has to trust because they are shipped rather than
read. So this module builds the staging root exactly the way
``scripts/build-deb.sh`` does and asks the questions a text review of those files
would ask, in the only form that can be answered automatically:

* is every file the units' ``ExecStart`` lines name actually installed;
* is every file installed something the plan decided on;
* is every mode the mode table says, in either direction;
* does nothing anywhere name a resolver this project refuses to use.

Each of the four ways a package is wrong has a control in ``ControlTests`` that
mutates a copy of the staged tree and asserts the question changes its answer,
because a check that accepts a missing file, a loose mode or a forbidden address
is not a check.

The build runs once per process and its result is shared, because it compiles
three programs and a suite that rebuilt them per assertion would be unrunnable.
The shared build is a staging root and nothing else: no maintainer script is ever
executed, no service is started, no port is bound, and nothing outside a
temporary directory is written. That is the whole of the boundary this project
works under, and a test that crossed it would be testing the development machine
wearing a test's name.
"""

import atexit
import contextlib
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# The one implementation of "what words does this roff file say", shared with
# `test_watchdog.py` rather than copied: a second one is a second thing that can
# be wrong about the same file, and the two would disagree about the documents
# they both read.
from test_watchdog import shipped_prose  # noqa: E402

BUILD_SCRIPT = REPO / "scripts" / "build-deb.sh"
PACKAGING = REPO / "packaging"
MANIFEST = PACKAGING / "mosdns-router.install"
CONTROL = PACKAGING / "debian" / "control"
CONFFILES = PACKAGING / "debian" / "conffiles"
POSTINST = PACKAGING / "debian" / "postinst"
PRERM = PACKAGING / "debian" / "prerm"
POSTRM = PACKAGING / "debian" / "postrm"
SOURCE_DIGEST = PACKAGING / "debian" / "dnscrypt-proxy.sha256"

sys.path.insert(0, str(REPO))
from installer.tests.test_units import (  # noqa: E402
    SHIPPED_UNITS,
    non_loopback,
    parse_unit,
    toml_listen_addresses,
    yaml_listen_addresses,
)

# --- the installed layout ----------------------------------------------------
#
# Every path here is a path this project decided on. The three binaries and the
# installer script are the paths the units and mosdns-cdnctl name; the rest are
# the installer's own constants. A path that appears in only one of those is a
# disagreement between two parts of the same package, and that is a bug rather
# than a choice this module gets to make.

BINARY_DIRECTORY = "/usr/lib/mosdns-router"
ROUTER_BINARY = BINARY_DIRECTORY + "/mosdns-router"
CDNCTL_BINARY = BINARY_DIRECTORY + "/mosdns-cdnctl"
DNSCRYPT_BINARY = BINARY_DIRECTORY + "/dnscrypt-proxy"
INSTALLER_SCRIPT = BINARY_DIRECTORY + "/mosdns_installer.py"
# The bridge is imported rather than executed, so it is a directory of modules
# rather than a program, and it has to sit on the Python path of every process
# that runs `python3 -m mosdns_dhcp_bridge.cli`.
BRIDGE_PACKAGE = BINARY_DIRECTORY + "/mosdns_dhcp_bridge"
BRIDGE_MODULES = ("__init__.py", "cli.py", "collect.py", "publish.py")
DISPATCHER_SCRIPT = "/etc/NetworkManager/dispatcher.d/no-wait.d/10-mosdns-dhcp-bridge"
UNIT_DIRECTORY = "/usr/lib/systemd/system"
TMPFILES_PATH = "/usr/lib/tmpfiles.d/mosdns-router.conf"
DOC_DIRECTORY = "/usr/share/doc/mosdns-router"
BUILD_MANIFEST = DOC_DIRECTORY + "/BUILD-MANIFEST"
DATA_DIRECTORY = "/usr/share/mosdns-router"
CONFIG_DIRECTORY = "/etc/mosdns"
MAN_ROOT = "/usr/share/man"
DEBIAN = "/DEBIAN"

# The seven documents an operator edits, and the two generated ones among them. All
# seven are conffiles, so an upgrade asks before replacing any of them. The
# seventh is the watchdog's setting, and it is a conffile for that reason twice
# over: an upgrade that silently replaced `automatic: false` with the shipped
# `true` would hand a machine with a working resolver to the one unattended action
# in this package, on the upgrade that was meant to be uneventful.
EDITABLE_DOCUMENTS = (
    CONFIG_DIRECTORY + "/mosdns.yaml",
    CONFIG_DIRECTORY + "/dnscrypt-proxy.toml",
    CONFIG_DIRECTORY + "/policy.yaml",
    CONFIG_DIRECTORY + "/force-ech-domains.txt",
    CONFIG_DIRECTORY + "/cloudflare.txt",
    CONFIG_DIRECTORY + "/cloudfront-domains.yaml",
    CONFIG_DIRECTORY + "/watchdog.yaml",
)
ROUTING_DOCUMENTS = (
    CONFIG_DIRECTORY + "/mosdns.yaml",
    CONFIG_DIRECTORY + "/dnscrypt-proxy.toml",
)

# The three compiled programs. Their bytes are pinned by digest in the build
# manifest and they are deliberately NOT content-scanned: mosdns-cdnctl embeds
# the very list of Chinese public resolvers it REFUSES to render, so a substring
# scan of that binary finds exactly the values the project exists to keep out of
# a routing document, and calling that a failure would be a check satisfiable
# only by deleting the refusal.
COMPILED = (ROUTER_BINARY, CDNCTL_BINARY, DNSCRYPT_BINARY)

# The China domain list, shipped as a reviewed snapshot for the install to place
# and verify, and the lock that describes it. They are shipped under /usr/share
# and copied by postinst, because /var/lib holds generated state and a package
# that ships state there is a package whose upgrade overwrites the operator's
# data.
CHINA_LIST = DATA_DIRECTORY + "/cn-domains.txt"
SOURCE_LOCK = DATA_DIRECTORY + "/source-lock.json"
PUBLISHED_LIST = "/var/lib/mosdns/lists/cn-domains.txt"
PUBLISHED_LOCK = "/var/lib/mosdns/lists/source-lock.json"

# The pinned Cloudflare range document, and the lock that accounts for it. The
# second of the two pairs this package carries, and the one that makes an
# installation with no route to the internet possible: the prefix list the
# response rewriter refuses to construct without comes from exactly one endpoint,
# so without a snapshot of it a machine that cannot reach that endpoint has no way
# to start this router at all.
#
# It is shipped and VERIFIED but never placed: the published artifacts under
# /var/lib are written by `mosdns-cdnctl update-lists --refresh-ranges`, which is
# the one program that knows how to publish them, and postinst writes neither.
RANGES_SNAPSHOT = DATA_DIRECTORY + "/cloudflare-ranges.json"
RANGES_SNAPSHOT_LOCK = DATA_DIRECTORY + "/cloudflare-ranges.lock.json"
PUBLISHED_RANGES_CACHE = "/var/lib/mosdns/lists/cloudflare-ips.json"
PUBLISHED_PREFIX_LIST = "/var/lib/mosdns/lists/cloudflare-prefixes.txt"

# The four directories the package provisions. The mode is 2770 and the reason
# is load-bearing: with an extended ACL present the mode's group field IS the
# group-class mask, so 2750 would cap the group at r-x and no service identity
# could create, replace or lock a state file. The first three survive a reboot
# and are in the package; the fourth is on a tmpfs and belongs to tmpfiles.d.
STATE_DIRECTORIES = (
    "/var/lib/mosdns",
    "/var/lib/mosdns/runtime",
    "/var/lib/mosdns/lists",
    "/run/mosdns",
)
PACKAGED_STATE_DIRECTORIES = STATE_DIRECTORIES[:3]

# The whole mode table. A mode here is the ONLY mode the file may have, so a file
# made too permissive and a file made too restrictive both fail.
MODES = {
    ROUTER_BINARY: 0o755,
    CDNCTL_BINARY: 0o755,
    DNSCRYPT_BINARY: 0o755,
    INSTALLER_SCRIPT: 0o755,
    DISPATCHER_SCRIPT: 0o755,
    TMPFILES_PATH: 0o644,
    BUILD_MANIFEST: 0o644,
    DOC_DIRECTORY + "/copyright": 0o644,
    CHINA_LIST: 0o644,
    SOURCE_LOCK: 0o644,
    RANGES_SNAPSHOT: 0o644,
    RANGES_SNAPSHOT_LOCK: 0o644,
    **{document: 0o644 for document in EDITABLE_DOCUMENTS},
    **{BRIDGE_PACKAGE + "/" + module: 0o644 for module in BRIDGE_MODULES},
    **{UNIT_DIRECTORY + "/" + name: 0o644 for name in SHIPPED_UNITS},
    MAN_ROOT + "/man1/mosdns-cdnctl.1.gz": 0o644,
    MAN_ROOT + "/man8/mosdns-router.8.gz": 0o644,
    MAN_ROOT + "/man8/dnscrypt-proxy.8.gz": 0o644,
}

# The prefixes the package may write to at all. Whether this set is right is the
# whole of "the package installs nothing it should not", so it is a table here
# rather than a judgement inside the build script.
ALLOWED_PREFIXES = (
    BINARY_DIRECTORY + "/",
    UNIT_DIRECTORY + "/",
    CONFIG_DIRECTORY + "/",
    "/etc/NetworkManager/dispatcher.d/no-wait.d/",
    "/usr/lib/tmpfiles.d/",
    DOC_DIRECTORY + "/",
    DATA_DIRECTORY + "/",
    MAN_ROOT + "/",
    "/var/lib/mosdns/",
)

# The paths the build generates rather than copies. A staged path is either a
# manifest destination or one of these, and both lists are here so that a path
# appearing in neither is a failure rather than a surprise.
GENERATED = set(ROUTING_DOCUMENTS) | {
    BUILD_MANIFEST,
    DEBIAN + "/control",
    DEBIAN + "/conffiles",
    DEBIAN + "/postinst",
    DEBIAN + "/prerm",
    DEBIAN + "/postrm",
    DEBIAN + "/md5sums",
    DEBIAN + "/shlibs",
}

# Everything forbidden, in two tables, because there are two questions and they do
# not have the same answer everywhere.
#
# A resolver ADDRESS is refused EVERYWHERE, the China domain list included. An
# address in a document is an upstream somebody would be asked, and the domestic
# branch of the routing document reaches exactly one set of upstreams: the addresses
# the DHCP lease published. Everything else this package names is either loopback or
# a pinned bootstrap resolver.
FORBIDDEN_ADDRESSES = (
    "114.114.114.114",
    "114.114.115.115",
    "119.29.29.29",
    "182.118.125.13",
    "223.5.5.5",
    "223.6.6.6",
    "180.76.76.76",
    "117.50.11.11",
    "1.12.12.12",
    "120.53.53.53",
    "168.95.1.1",
    "202.96.128.86",
)
# A resolver ENDPOINT, a provider's brand, or a tool that moves this machine onto
# somebody else's resolver. Refused in every document EXCEPT the one file that is a
# list of the names to be resolved inside the network the user is not leaving: that
# file's content is a set of NAMES this project routes domestically, so naming the
# provider those names belong to is what the file is FOR, and pointing a query at
# that provider's public resolver is what the address table above refuses.
FORBIDDEN_PROVIDERS = (
    # The domestic public resolvers, by endpoint and by name.
    "dns.alidns.com",
    "doh.360.cn",
    "dot.pub",
    "doh.pub",
    "alidns",
    "dnspod",
    "114dns",
    # A DoH or an ODoH endpoint: a resolver doing DNS over HTTPS on this machine's
    # behalf, where the whole foreign branch is a plain DNSCrypt-over-TCP hop to a
    # loopback socket.
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "dns.adguard.com",
    "doh.opendns.com",
    "doh.mullvad.net",
    "dns.nextdns.io",
    # A local certificate authority, a browser policy file, a TLS-intercepting
    # middlebox and a container runtime: the ways a machine is put on somebody
    # else's resolver without a resolver address ever appearing in a configuration.
    "ClearDNS",
    "cleardns",
    "update-ca-certificates",
    "p11-kit",
    "mkcert",
    "mitmproxy",
    "sslh",
    "tls.intercept",
    "sni_proxy",
    "haproxy",
    "network.trr",
    "policies.json",
    "/etc/docker",
    "docker-ce",
    "wpad",
)

# An ALLOWLIST of the addresses a shipped configuration document may name, applied
# to the shipped documents only.
#
# The two tables above are DENYLISTS, and a denylist of twelve IPv4 literals and
# twenty-five provider strings has two holes this one closes. First, it cannot know
# an address nobody has written down: 1.2.4.8, 210.2.4.8, 211.98.20.20 and
# 221.5.88.88 are all public resolvers inside the network this project routes out of
# and all four would pass. Second, it is IPv4-only by construction, so every domestic
# IPv6 literal -- 2400:3200::1, 2402:4e00::, and the rest -- would pass too.
#
# An allowlist inverts the question: not "is this forbidden?" but "is this one of the
# handful of addresses this package is allowed to name?". The answer is four
# categories and no more:
#
#   * loopback, because the router and the resolver are this machine's own and
#     nothing in this package is reachable from another host;
#   * 127.0.0.53 and 127.0.0.54, which are inside 127/8 and are resolved's own stub,
#     which this install KEEPS and reads;
#   * the two pinned Quad9 bootstrap resolvers, which resolve DNSCrypt provider
#     names and never receive a user query (`ignore_system_dns = true` is asserted
#     separately, and it is what makes the distinction true);
#   * the RFC 5737 and RFC 3849 documentation ranges, which are what an EXAMPLE in a
#     comment has to use. An example with a real address in it is a copy-paste
#     accident waiting to happen.
#
# Anything else in a shipped configuration document is a finding, including an
# address nobody has heard of. The two scans are kept because they catch different
# things: the allowlist cannot see a provider by NAME, and the denylist cannot see an
# address that is not on it.
ALLOWED_ADDRESSES = (
    "127.0.0.1",
    "::1",             # loopback, the IPv6 spelling of the same thing
    "9.9.9.9",
    "149.112.112.9",
)
ALLOWED_NETWORKS = (
    "127.0.0.0/8",       # loopback, including resolved's stub at .53 and .54
    "192.0.2.0/24",      # RFC 5737 TEST-NET-1
    "198.51.100.0/24",   # RFC 5737 TEST-NET-2
    "203.0.113.0/24",    # RFC 5737 TEST-NET-3
    "2001:db8::/32",     # RFC 3849 documentation
)
# The documents an operator's resolver behaviour comes from. The installer, the
# bridge and the manual pages are code and prose: an address in a code comment is
# not something the machine is pointed at, and `mosdns_installer.py` carries the
# 192.0.2.0/24 range in a report-format example on purpose.
CONFIG_VALUE_DOCUMENTS = tuple(EDITABLE_DOCUMENTS)

# One address, in every spelling a document can use: dotted quad, colon-hex, and the
# IPv4-mapped form an IPv6 socket prints. Read with ipaddress rather than with a
# regex, because a regex cannot tell 1.2.3.4 from 1.2.3.4:5 and would either miss the
# port or swallow it.
# Ordered so the IPv4-mapped form is matched as ONE address: the generic IPv6
# alternative would otherwise swallow the `::ffff` prefix and leave a bare `::ffff`
# for `ipaddress` to call a valid address of its own, which is both a false finding
# and a false negative for the address that was actually there.
ADDRESS_TOKEN = re.compile(
    r"(?<![0-9A-Za-z._-])("
    r"::(?:[Ff]{4}:)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    r"|(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    r"|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z._-]+)?"
    r")(?![0-9A-Za-z._-])"
)


def address_findings(root, documents=CONFIG_VALUE_DOCUMENTS, inventory=None):
    """Every address in a shipped configuration document that is not an allowed one.

    Comments and blank lines are skipped, because that is where a documentation-range
    example lives and an example is not configuration. Everything else in a routing
    document or a resolver document IS configuration, which is why the skip is by
    line rather than by anything cleverer: a `#` mid-line is a value in a URL or a
    path, not a comment marker in any format these documents use.
    """
    import ipaddress

    allowed_exact = {ipaddress.ip_address(value) for value in ALLOWED_ADDRESSES}
    allowed_networks = [ipaddress.ip_network(value) for value in ALLOWED_NETWORKS]
    findings = []
    for document in documents:
        path = Path(root) / document.lstrip("/")
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for token in ADDRESS_TOKEN.findall(stripped):
                candidate = token.split("%", 1)[0]
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                # An IPv4-mapped IPv6 address is the IPv4 address it maps, and a
                # socket prints it that way; comparing it as IPv6 would put
                # ::ffff:127.0.0.1 outside 127/8 and call loopback a finding.
                mapped = getattr(address, "ipv4_mapped", None)
                comparable = [address] + ([mapped] if mapped is not None else [])
                if any(value in allowed_exact for value in comparable):
                    continue
                if any(value in network for network in allowed_networks for value in comparable):
                    continue
                findings.append(
                    f"{document}:{number}: {address} is not one of the addresses this package "
                    "is allowed to configure"
                )
    return findings


# The one file the provider scan skips, and why it is not a hole: its bytes are
# pinned by digest against a lock the package also ships, and every line of it is
# checked to be one of the four rule forms the gateway can read, which is what
# keeps it a list of names rather than anything else.
ROUTE_SCAN_EXEMPT = (CHINA_LIST,)

# The metadata that was decided, read back out of packaging/debian/control.
CONTROL_FIELDS = {
    "Package": "mosdns-router",
    "Version": "0.1.0",
    "Section": "net",
    "Priority": "optional",
}
# The SET the package is built for, which the repository's control file declares, and
# the ONE a built package carries. dpkg rejects a space-separated Architecture field,
# so the two cannot be the same string: a package labelled `amd64 arm64` is a parse
# error, and a binary labelled with a name it does not have is worse.
BUILT_ARCHITECTURES = "amd64 arm64"
CONTROL_DEPENDS = (
    "python3",
    "systemd",
    "network-manager",
    # **`libnss-resolve`, and NOT `systemd-resolved`** -- MEASURED, and the reason
    # is a package that does not exist. `systemd-resolved` is a binary package on
    # 24.04 and 26.04 and **there is no such package on 22.04**, where the daemon
    # is part of `systemd` -- so a `Depends: systemd-resolved` is a package dpkg
    # refuses to configure on the oldest release this project supports, with
    #
    #     dpkg: dependency problems prevent configuration of mosdns-router:
    #      mosdns-router depends on systemd-resolved; however:
    #       Package systemd-resolved is not installed.
    #
    # MEASURED on 22.04 in the Podman matrix (Task 4 Step 7), and the failure
    # looks like an install failure rather than like a dependency that cannot be
    # satisfied on this release.
    #
    # `libnss-resolve` exists on all three and brings the daemon with it where the
    # daemon is a package of its own (24.04: `Depends: … systemd-resolved
    # (= 255.4-…)`, measured) and is the NSS module everywhere. It is the same
    # reasoning `tests/podman/images/target.Containerfile` already applies to the
    # image, for the same reason, and the two spellings are the same fact.
    #
    # The preflight still requires `systemd-resolved.service` to be *running*
    # (`check_managers` in `mosdns_installer.py`), which is the property this
    # package actually needs; a package name that exists on every release is how
    # a dependency says it.
    "libnss-resolve",
    "libc6",
)

# The source the packaged resolver is built from, and the digest that archive has
# to carry before anything at all is built from it.
DNSCRYPT_VERSION = "2.1.18"
DNSCRYPT_ARCHIVE = "dnscrypt-proxy-" + DNSCRYPT_VERSION + ".tar.gz"
DNSCRYPT_SOURCE_URL = (
    "https://github.com/DNSCrypt/dnscrypt-proxy/archive/refs/tags/2.1.18.tar.gz"
)


# --- the Debian control file ------------------------------------------------


def control_fields(text):
    """Return a Debian control stanza as a mapping with lowercased field names.

    The three rules that matter, and each of them is a case this repository's own
    files get wrong for a reader that does not have them:

    * a continuation line begins with a space or a tab, and it continues the field
      above it -- a Description that wraps is one field, and a reader that took only
      its first line would compare against a truncated sentence;
    * a BLANK line ends the stanza. This is why an inserted control field may not be
      followed by one: two stanzas where there should be one, and dpkg reports the
      second as a package with no Package field;
    * any other line that is not a field ends the field being read as well.
      `dpkg-deb --info` prints a size header above the stanza, and a reader that did
      not end the previous field there reads the indented ` Package:` line as a
      continuation of the header -- and then reports a package with no Package field
      at all, which is a property of the reader and not of the package.
    """
    fields = {}
    name = None
    for line in text.splitlines():
        if not line.strip():
            name = None
            continue
        if line[:1] in (" ", "\t"):
            if name is not None:
                fields[name] += " " + line.strip()
            continue
        if ":" not in line:
            name = None
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        fields[name] = value.strip()
    return fields


def dependency_names(fields):
    """The Depends field as a list of package names, without their constraints."""
    parts = []
    for clause in fields.get("depends", "").split(","):
        clause = clause.strip()
        if clause:
            parts.append(clause.split("(")[0].split("[")[0].split("|")[0].strip())
    return parts


def _built_architecture():
    """The architecture the shared staging root was built for.

    Read out of the staged control rather than out of `dpkg --print-architecture`, so
    a build for one architecture cannot pass a test that expects the other: the two
    are equal in every run that matters and differ in a cross-build.
    """
    return control_fields(
        (Path(_SHARED.get("root", "")) / "DEBIAN" / "control").read_text()
        if _SHARED.get("root")
        else ""
    ).get("architecture", "")


# --- a staged tree -----------------------------------------------------------


def staged_inventory(root):
    """Every path under ``root`` as ``(absolute, kind, mode, size)``.

    Reducing the staging root to a list of tuples is what lets every question in
    this module be asked of the real build and of a mutated copy by the same code.
    """
    entries = []
    for path in sorted(Path(root).rglob("*")):
        absolute = "/" + str(path.relative_to(root))
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            kind = "symlink"
        elif stat.S_ISDIR(info.st_mode):
            kind = "directory"
        elif stat.S_ISREG(info.st_mode):
            kind = "file"
        else:
            kind = "other"
        entries.append((absolute, kind, stat.S_IMODE(info.st_mode), info.st_size))
    return entries


def inventory_get(inventory, path):
    for entry in inventory:
        if entry[0] == path:
            return entry
    return None


def content_findings(root, inventory, needles, exempt=()):
    """Every ``(path, needle)`` in the staged text files that names a needle.

    A file that is not valid UTF-8, and is not one of the compiled binaries, is a
    finding in its own right: a package whose contents cannot be read is a package
    nobody reviewed, and skipping one silently is how a forbidden value gets in as
    an unreadable blob.
    """
    findings = []
    for path, kind, _mode, _size in inventory:
        if kind != "file" or path in COMPILED or path in exempt:
            continue
        raw = (Path(root) / path.lstrip("/")).read_bytes()
        if path.endswith(".gz"):
            # A manual page ships compressed, as a Debian package's does, and a scan
            # that reported every page as unreadable would be a scan that never read
            # one -- which is exactly where a needle in a page would hide.
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                findings.append((path, "<not readable gzip>"))
                continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            findings.append((path, "<not utf-8 text>"))
            continue
        for needle in needles:
            if needle in text:
                findings.append((path, needle))
    return findings


def mode_findings(inventory, modes):
    """Every path whose mode is not the mode the table says, in either direction."""
    findings = []
    for path, kind, mode, _size in inventory:
        if path in modes and kind == "file" and mode != modes[path]:
            findings.append(f"{path} is {oct(mode)}, want {oct(modes[path])}")
    present = {entry[0] for entry in inventory}
    for path, want in sorted(modes.items()):
        if path not in present:
            findings.append(f"{path} is not installed at all, want mode {oct(want)}")
    return findings


# Debian Policy 6.5, "Summary of ways maintainer scripts are called", Debian Policy
# Manual 4.7.4.1. This is the COMPLETE set of first arguments dpkg may pass each
# script, transcribed once, and every script's `case` arms are compared against it in
# both directions.
#
# It is transcribed from the policy rather than from the scripts, and that is the
# whole point of the test: a list copied out of the scripts is a list that can be
# wrong in the same way twice. This one was wrong exactly once -- `postrm` was given
# six of the seven, `failed-upgrade` was missing, and a test that enumerated the same
# six said so -- which is a failure the table below is designed to make impossible.
# `new-postrm failed-upgrade old-version new-version` is what dpkg calls when
# `old-postrm upgrade` fails, mid-unwind, and Policy 6.2 requires a maintainer script
# to be idempotent across its error paths; a script that exits 1 on it turns a
# recoverable unwind into a half-installed package.
POLICY_VERBS = {
    "postinst": ("abort-deconfigure", "abort-remove", "abort-upgrade", "configure"),
    "prerm": ("deconfigure", "failed-upgrade", "remove", "upgrade"),
    "postrm": (
        "abort-install", "abort-upgrade", "disappear",
        "failed-upgrade", "purge", "remove", "upgrade",
    ),
}
# ON THE SECOND ARGUMENT. A maintainer script may be HANDED a second argument -- a
# version -- and must not break on it: `postinst configure` is called as `postinst
# configure most-recently-configured-version` and Policy 6.5 footnote 7 says that
# argument may be null, `prerm deconfigure` is called with four arguments, and
# `new-postrm abort-upgrade` with three. So the rule is NOT "the scripts may only ever
# look at $1", which is what this table used to say here and which `postinst` itself
# contradicts by reading `${2:-}` to tell a first install from an upgrade. The rule is
# that an argument dpkg may not pass is never read unguarded: every `$N` for N >= 2
# carries a `${N:-}` default, so a null one reads as empty rather than aborting the
# script. Asserted per script, in
# `test_an_argument_dpkg_may_not_pass_is_never_read_unguarded`.
#
# THE THREE SCRIPTS ARE RESOLVED AT CALL TIME, and the reason is load-bearing.
# `SCRIPTS` used to be a dict literal binding three Path objects once, at import; the
# test methods iterated it; and a control that swapped the `POSTINST`/`PRERM`/`POSTRM`
# globals in order to run a method against a MUTATED script left every method reading
# the file on disk. Those controls therefore passed while testing nothing, and the
# report claimed them as evidence. Resolving the names at call time is what makes a
# substitution reach the code under test, and
# `test_a_missing_policy_verb_is_reported` holds that property: it asserts
# `assertMethodFails` on a mutated postrm, which can only raise if the method really
# read the replacement.
SCRIPT_GLOBALS = ("postinst", "prerm", "postrm")


def script_paths():
    """The three maintainer scripts, resolved at CALL time from the globals."""
    return {name: globals()[name.upper()] for name in SCRIPT_GLOBALS}


class _Scripts:
    """``SCRIPTS``, resolving through `script_paths()` on every access.

    Not a dict: a dict is a snapshot, and a snapshot taken at import is exactly the
    bug. Mapping-shaped so the methods can keep saying ``SCRIPTS.items()`` and mean
    the current global rather than whatever the global was when the module loaded.
    """

    def items(self):
        return sorted(script_paths().items())

    def __getitem__(self, name):
        return script_paths()[name]

    def __contains__(self, name):
        return name in script_paths()

    def __iter__(self):
        return iter(sorted(script_paths()))

    def __len__(self):
        return len(script_paths())


SCRIPTS = _Scripts()


def policy_verb_findings(name, text):
    """Every way ``text`` disagrees with Policy 6.5 about what dpkg may pass it.

    Three things, and all three have to hold: every policy verb has an arm, the arm
    set is not larger than the policy's (a script that handles a verb dpkg cannot
    pass it is a script carrying a case nobody reasoned about), and there is a default
    arm that refuses rather than silently succeeding on an argument it was not
    written for.
    """
    findings = []
    labels = shell_alternatives(text)
    wanted = set(POLICY_VERBS[name])
    for verb in sorted(wanted - set(labels)):
        findings.append(
            f"dpkg may call this script with {verb!r} (Policy 6.5) and the script has no "
            f"arm for it, so it falls into the default arm and exits 1"
        )
    for verb in sorted(set(labels) - wanted - {"*"}):
        # `*` is the default arm and is checked by the rule below, not by this one.
        findings.append(f"the script handles {verb!r}, which Policy 6.5 does not list as a way to call it")
    if not re.search(r"(?m)^\s*\*\)", text):
        findings.append(
            "the script has no default arm, so an argument dpkg does pass it that is not in "
            "Policy 6.5's list would be accepted as success"
        )
    return findings


def case_arms(text):
    """A shell script's ``case`` arms as ``[(labels, body)]``, in script order.

    ``labels`` is a list because arms share lines: ``remove|disappear) ... ;;`` is ONE
    arm with two labels, and a reader that cut at a literal ``disappear)`` would call
    the rest of the arm part of ``remove`` and read a statement that really belongs to
    a different situation as belonging to a plain removal. That is the false assurance
    a hand-cut reader produces, and it is why the arms are computed from the label
    set rather than from a delimiter.

    A case label is a line that starts at column zero with one or more ``|``-separated
    words and a ``)``. Column zero is what keeps an indented ``if ... )`` out, and the
    optional trailing command is what keeps a one-line arm from reporting an empty
    body -- which would read as "this arm does nothing" when it does something.
    """
    label = r"[A-Za-z*][A-Za-z0-9*-]*"
    # Whitespace on BOTH sides of the bar: `remove|deconfigure) ;;` and
    # `configure | abort-upgrade) ;;` are the same construct, and a pattern that
    # only allowed one of them would read a spaced list as no list at all.
    label_line = re.compile(
        r"^\s*(" + label + r"(?:\s*\|\s*" + label + r")*)\)(?P<inline>.*)$"
    )
    lines = text.splitlines()
    arms = []
    for index, line in enumerate(lines):
        match = label_line.match(line)
        if match is None:
            continue
        if match.group("inline").strip() in ("", ";;"):
            body = []
            cursor = index + 1
            while cursor < len(lines) and lines[cursor].strip() != ";;":
                body.append(lines[cursor])
                cursor += 1
            arms.append((_labels(match.group(1)), "\n".join(body)))
        else:
            arms.append((_labels(match.group(1)), match.group("inline")))
    return arms


def postinst_step_body(text, number):
    """The body of one `postinst` STEP, as the script's own lines.

    Cut at the two `--- STEP N` headers rather than at a line count, so a step that
    grows does not silently become a different step to the reader. The leading
    header is kept: it carries no logic, and a reader that dropped it would still
    be reading the script.

    **The letter after the number is part of the pattern, and leaving it out cost a
    case.** `STEP 1b` is a step of its own, but `STEP\\s+\\d+\\b` does not match it:
    `\\d+` takes the `1` and then `\\b` asks for a boundary between `1` and `b`, which
    are both word characters, so there is none and the match fails. The consequence
    was that STEP 1's body ran on to STEP 2 -- carrying STEP 1b with it -- so
    anything that RAN step 1 also ran the migration, against a real `chgrp` and a
    group that does not exist on a build machine. `sandboxed_postinst_step` shims
    `install` for exactly this class of reason and shimmed nothing for `chgrp`, so
    the step it thought it was running failed on a tool it had never heard of. It
    went unnoticed because every case in the suite runs STEP 3, whose neighbours are
    numbered.
    """
    header = re.compile(r"^#\s*-{2,}\s*STEP\s+" + str(number) + r"\b", re.MULTILINE)
    any_header = re.compile(r"^#\s*-{2,}\s*STEP\s+\d+[a-z]?\b", re.MULTILINE)
    found = list(header.finditer(text))
    if len(found) != 1:
        raise AssertionError(
            f"postinst has {len(found)} STEP {number} headers, so this step cannot be cut out of it"
        )
    start = found[0].start()
    following = any_header.search(text, found[0].end())
    if following is None:
        raise AssertionError(f"postinst has a STEP {number} with no STEP after it")
    return text[start : following.start()]


class _Purge:
    """One `postrm purge` run: what it printed and what it removed.

    `removed` and `removed_groups` are read out of the STUBS rather than out of the
    script, because "the script contains a deluser" is a sentence about a file and
    this is a question about what happened on a machine. The stubs append the name
    they were asked to remove to a file, so a purge that removed an account and a
    purge that merely said it did are different results.
    """

    def __init__(self, root, result, removed_file, groups_file):
        self.root = root
        self.returncode = result.returncode
        self.stdout = result.stdout
        self.stderr = result.stderr
        self._removed = removed_file
        self._groups = groups_file

    @property
    def removed(self):
        return tuple(_lines(self._removed))

    @property
    def removed_groups(self):
        return tuple(_lines(self._groups))


# Every absolute path the purge touches, longest first so a parent is not replaced
# before a child. A path this script does not name is not rewritten, so the rewrite
# below cannot invent a condition.
_PURGE_PATHS = (
    "/etc/NetworkManager/dispatcher.d",
    "/usr/lib/mosdns-router/mosdns_dhcp_bridge",
    "/usr/lib/mosdns-router",
    "/usr/share/mosdns-router",
    "/var/lib/mosdns",
    "/etc/mosdns",
    "/run/mosdns",
)


def _rooted(text, root):
    """The shipped script with its absolute paths moved under `root`.

    One pass, and the order of the alternatives inside it is longest-first for a
    reason that cost a case to find: replacing the paths one at a time rewrites
    `/usr/lib/mosdns-router/mosdns_dhcp_bridge` first and then finds
    `/usr/lib/mosdns-router` *inside the result*, so the bridge directory came out
    rooted twice and nothing the purge does to it happens in the tree the case then
    inspects. `re.sub` consumes each position once, so a single alternation cannot
    rewrite its own output.

    Nothing else is touched: no conditional is rewritten, no guard dropped and no
    message changed, so what runs is the shipped text pointed at a throwaway tree.
    """
    pattern = re.compile("|".join(re.escape(p) for p in sorted(_PURGE_PATHS, key=len, reverse=True)))
    return pattern.sub(lambda m: root + m.group(0), text)


def _lines(path):
    try:
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line]
    except FileNotFoundError:
        return []


class purged_sandbox:
    """Run the shipped `postrm purge` against a throwaway tree, to completion.

    Every tool that touches the machine's ACCOUNT database is stubbed, because this is
    a build machine and the whole subject of the cases is what the purge DECIDES about
    accounts. `getent` answers from what the fixture says exists, `deluser` and
    `delgroup` record what they were asked to remove, `ps` reports the processes the
    fixture says are running, and `find` reports the foreign files it planted.
    `rm`, `rmdir`, `ls` and `[` are the real ones: the removals under test are those.

    The context manager runs the script on entry, so a case reads a finished run and
    there is no ordering question about when to look at the tree.
    """

    def __init__(self, accounts=(), running=(), foreign=(), symlinked_cache_to=None):
        self.accounts = tuple(accounts)
        # `running` is an iterable of (account, count) pairs, or of accounts that
        # default to one process each -- normalised here so a case can say
        # `running=["mosdns-router"]` and mean one, and `running=[("mosdns-router",
        # 3)]` and mean three.
        self.running = tuple(
            (item, 1) if isinstance(item, str) else item for item in running
        )
        self.foreign = tuple(foreign)
        self.symlinked_cache_to = symlinked_cache_to

    def __enter__(self):
        root = Path(scratch_directory("mosdns-postrm-purge.")) / "root"
        if root.exists():
            subprocess.run(["rm", "-rf", str(root)], check=True)
        binroot = root / "stub-bin"
        binroot.mkdir(parents=True)
        state = root / "stub-state"
        state.mkdir()
        removed = state / "removed-users"
        groups = state / "removed-groups"
        removed.write_text("", encoding="utf-8")
        groups.write_text("", encoding="utf-8")

        # A coherent little account database: `getent passwd NAME`,
        # `getent group NAME`, and the bare `getent passwd` the purge reads to find
        # which users still hold a group. The gids are real rather than constant
        # because the holder check compares a user's primary gid against a group by
        # NUMBER -- a fixture where all three groups were gid 900 would say every
        # user holds every group, and the check would refuse to remove any of them
        # for a reason that is an artefact of the fixture.
        gid = {name: 900 + i for i, name in enumerate(self.accounts)}
        # A user's primary group is the one whose name it shares, except for the
        # control identity, which is in the shared state group -- the same shape the
        # shipped package provisions.
        state_group = next((n for n in self.accounts if n == "mosdns-router"), None)
        primary = {}
        for name in self.accounts:
            primary[name] = state_group if name.endswith("-cdn") and state_group else name
        account_file = state / "passwd"
        account_file.write_text(
            "".join(
                f"{a}:x:900:{gid[primary[a]]}::{a}:/nonexistent:/usr/sbin/nologin\n"
                for a in self.accounts
            ),
            encoding="utf-8",
        )
        (binroot / "getent").write_text(
            '#!/bin/sh\n'
            'database="${1:-}"; name="${2:-}"\n'
            # Bare `getent passwd`: the whole passwd database, which is how the
            # purge asks which users hold a group. Read from the LIVE file, so an
            # account `deluser` removed is not a holder on the next question.
            'if [ -z "$name" ]; then\n'
            '  if [ "$database" = passwd ]; then cat "' + str(account_file) + '"; fi\n'
            '  exit 0\n'
            'fi\n'
            # The key carries a trailing colon so the patterns can end in one, which
            # is what keeps `passwd:mosdns-router` from also matching a longer
            # account name that starts with it.
            'key="$database:$name:"\n'
            'case "$key" in\n'
            + "".join(
                f'passwd:{a}:) printf "{a}:x:900:{gid[primary[a]]}::{a}:/nonexistent:/usr/sbin/nologin\\n"; exit 0;;\n'
                for a in self.accounts
            )
            + "".join(
                f'group:{a}:) printf "{a}:x:{gid[a]}:\\n"; exit 0;;\n'
                for a in self.accounts
            )
            + 'esac\nexit 2\n',
            encoding="utf-8",
        )
        # `deluser --system NAME` / `delgroup --system NAME`: record and succeed. The
        # `--system` is skipped rather than assumed to be first, because the script
        # writes it that way and a stub that only understood one spelling would make
        # a removal silently not happen.
        # `deluser` also DELETES the account from the fixture's database, because a
        # purge that has removed a user must not go on seeing it as a group holder.
        # A stub that only recorded the name made the holder check see a user that no
        # longer existed, and the shared group survived every clean purge.
        (binroot / "deluser").write_text(
            '#!/bin/sh\nname=\n'
            'while [ $# -gt 0 ]; do case "$1" in --system) shift;; *) name="$1"; shift;; esac; done\n'
            f'printf "%s\\n" "$name" >> "{removed}"\n'
            f'grep -v "^$name:" "{account_file}" > "{account_file}.new" 2>/dev/null || true\n'
            f'[ -f "{account_file}.new" ] && mv "{account_file}.new" "{account_file}"\n'
            'exit 0\n',
            encoding="utf-8",
        )
        (binroot / "delgroup").write_text(
            '#!/bin/sh\nname=\n'
            'while [ $# -gt 0 ]; do case "$1" in --system) shift;; *) name="$1"; shift;; esac; done\n'
            f'printf "%s\\n" "$name" >> "{groups}"\n'
            'exit 0\n',
            encoding="utf-8",
        )
        (binroot / "ps").write_text(
            "#!/bin/sh\n"
            + "".join(f'printf "%s\\n" "{a}"\n' * int(n) for a, n in self.running)
            + "exit 0\n",
            encoding="utf-8",
        )
        # `find` answers for the account it was ASKED about and for no other. A stub
        # that printed its whole fixture for every call kept all three accounts the
        # moment one of them had a foreign file, which reads exactly like a purge that
        # refuses to remove anything it was ever asked about.
        (binroot / "find").write_text(
            '#!/bin/sh\nasked=\n'
            'while [ $# -gt 0 ]; do\n'
            '  if [ "$1" = "-user" ]; then asked="$2"; fi\n'
            "  shift\n"
            'done\n'
            + "".join(
                f'if [ "$asked" = "{a}" ]; then printf "%s/foreign/{a}.txt\\n"; exit 0; fi\n'
                for a in self.foreign
            )
            + "exit 0\n",
            encoding="utf-8",
        )

        # Executable. Without this the stub is on PATH but cannot run, the shell
        # falls THROUGH it to the real tool in /usr/bin, and the case reads the real
        # machine's accounts -- which is exactly the thing NO-HOST-MUTATION forbids
        # and, here, silently reported "no accounts exist" for every fixture.
        for stub in binroot.iterdir():
            stub.chmod(0o755)

        # The tree the removals act on.
        (root / "var/lib/mosdns/runtime").mkdir(parents=True)
        (root / "var/lib/mosdns/runtime/ech-state.json").write_text("{}\n", encoding="utf-8")
        (root / "run/mosdns/watchdog").mkdir(parents=True)
        bridge = root / "usr/lib/mosdns-router/mosdns_dhcp_bridge"
        bridge.mkdir(parents=True)
        # The module itself is NOT planted: it is a package file, so dpkg has
        # already removed it by the time postrm runs and the directory holds only
        # what dpkg cannot see. Planting it would leave the directory non-empty for
        # a reason that has nothing to do with the residue under test.
        if self.symlinked_cache_to:
            elsewhere = root / self.symlinked_cache_to
            elsewhere.mkdir(exist_ok=True)
            (elsewhere / "keep.txt").write_text("not this package's\n", encoding="utf-8")
            (bridge / "__pycache__").symlink_to(elsewhere)
        else:
            (bridge / "__pycache__").mkdir()
            (bridge / "__pycache__/publish.cpython-311.pyc").write_bytes(b"\x00pyc")
        hook = root / "etc/NetworkManager/dispatcher.d/no-wait.d"
        hook.mkdir(parents=True)
        (hook / "10-mosdns-dhcp-bridge").write_text("#!/bin/sh\n", encoding="utf-8")

        script = root / "postrm"
        script.write_text(_rooted(SCRIPTS["postrm"].read_text(), str(root)), encoding="utf-8")
        result = subprocess.run(
            ["sh", str(script), "purge"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PATH": f"{binroot}{os.pathsep}{os.environ['PATH']}"},
        )
        return _Purge(root, result, removed, groups)

    def __exit__(self, *exc):
        return False


class _Migration:
    """One `postinst` STEP 1b run: what it printed, and the tree it left."""

    def __init__(self, root, result, names, groups):
        self.root = root
        self.result = result
        self.names = names
        self.groups = groups

    @property
    def stderr(self):
        return self.result.stderr

    def gid_of(self, path):
        """`path`'s GROUP as a number, or `None` when `path` is not there.

        A number rather than a name, and that is the whole point of this helper. A
        migration's job is to move ownership from a group it is about to DELETE to
        the one that is replacing it, so the question a case has to ask is whether
        the files came off the old gid -- and `os.stat(...).st_gid` is the only
        reader that can answer it. `getent group <name>` cannot: a gid nothing
        resolves has no name at all, which is exactly the state the migration is
        supposed to prevent and the one a name-shaped assertion cannot see.
        """
        target = self.root / str(path).lstrip("/")
        if not target.exists():
            return None
        return target.stat().st_gid


class migrated_sandbox:
    """Run the shipped `postinst`'s own migration (STEP 1b) over a throwaway tree
    that a PREVIOUS build left behind, and hand back the tree it produced.

    **Run rather than read, and the reason is a measured defect rather than a
    preference.** The first version of this migration walked four directories with
    `chgrp` and no `-R`. That is correct for the directories and silent about
    everything inside them: `chgrp` on a directory moves the directory's group and
    leaves each child's own group alone. The step then went on to `delgroup` the
    old group, so every published file under `/var/lib/mosdns/lists` was left
    group-owned by a gid that no longer resolved to anything, at mode 0640 -- a file
    only root can read. The router reads the Cloudflare ranges there before it binds
    anything, so it started, failed to build its prefix watcher and bound nothing on
    port 53 while NetworkManager was already pointing the machine at 127.0.0.1.
    MEASURED in a container reproducing a machine the old build had provisioned.

    A test that reads the script cannot see that. `test_an_upgrade_moves_the_state_
    directories_before_it_drops_the_old_group` asserted that a `chgrp` and a
    `setfacl` appear before a `delgroup`, and every one of those three substrings is
    still there -- the shape is right and the effect is wrong, which is the whole
    defect class this project's own gate keeps hitting.

    So the fixture is the machine, and `chgrp` is the real one. What is stubbed is
    everything that touches the account database, because this is a build machine
    and the subject is what the migration DOES to files: `addgroup`/`adduser`
    succeed, `deluser`/`delgroup` record and succeed, `getent` answers from the
    fixture. `chgrp` needs a name-to-gid shim because neither the old nor the new
    group name exists on a build machine -- and the shim rewrites the NAME to the
    fixture's GID and execs the real `chgrp`, so the recursion question the defect
    turns on is answered by the kernel rather than by this file.
    """

    def __init__(self, empty=False):
        # `empty` is a machine that has NEVER run this package: no state tree at
        # all. It is a fixture rather than a second sandbox because the step under
        # test has to run in both worlds, and running it in a tree that is merely
        # empty of FILES would not exercise the `[ -d ]` guard at all.
        self.empty = empty

    def __enter__(self):
        text = POSTINST.read_text()
        variables = shell_assignments(text)
        for name in ("STATE_GROUP", "LEGACY_STATE_GROUP"):
            if name not in variables:
                raise AssertionError(
                    f"postinst does not assign {name}, so the migration cannot be read out of it"
                )
        names = {
            "new_group": variables["STATE_GROUP"],
            "legacy_group": variables["LEGACY_STATE_GROUP"],
        }

        root = Path(scratch_directory("mosdns-postinst-migration.")) / "root"
        if root.exists():
            subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        binroot = root.parent / "bin"
        binroot.mkdir(exist_ok=True)
        state = root.parent / "state"
        state.mkdir(exist_ok=True)
        removed = state / "removed"
        removed.write_text("", encoding="utf-8")

        # Two gids this process is actually a MEMBER of, and the reason is that the
        # question cannot be answered any other way as a normal user. `chgrp` to a
        # gid you are not in fails with EPERM and `os.chown` to one fails too, so a
        # fixture that invented 4101 and 4102 could not build the machine it is
        # describing. Taking two of the caller's own groups makes the fixture
        # portable -- no group NAME is hard-coded, so it runs on a build machine with
        # a different membership -- and it keeps the recursion question in the hands
        # of chgrp(1) rather than of this file.
        #
        # Distinct, and checked: a fixture whose two gids were equal would report
        # every file as correctly migrated whatever the step did, because `chgrp` to
        # the number a file already has is a no-op that succeeds.
        available = sorted({os.getgid(), *os.getgroups()})
        if len(available) < 2:
            raise unittest.SkipTest(
                "this process belongs to fewer than two groups, so it cannot build the two "
                "ownerships a migration has to move a state tree between"
            )
        gids = {names["legacy_group"]: available[0], names["new_group"]: available[-1]}
        (binroot / "chgrp").write_text(
            "#!/usr/bin/env python3\n"
            "# Rewrite the group NAME this script uses to a gid the caller is a member\n"
            "# of, and exec the REAL chgrp -- so whether `chgrp -R` reaches the files\n"
            "# INSIDE a directory is answered by chgrp(1) and not by this shim.\n"
            "import os, sys\n"
            f"GIDS = {gids!r}\n"
            "args = sys.argv[1:]\n"
            "for index, word in enumerate(args):\n"
            "    if word in GIDS:\n"
            "        args[index] = str(GIDS[word])\n"
            "        break\n"
            "else:\n"
            "    sys.stderr.write('chgrp shim: no fixture group in %r\\n' % (args,))\n"
            "    sys.exit(97)\n"
            "os.execv('/usr/bin/chgrp', ['chgrp'] + args)\n",
            encoding="utf-8",
        )
        (binroot / "getent").write_text(
            "#!/bin/sh\n"
            "case \"${1:-}:${2:-}\" in\n"
            # Both groups exist: the step is an UPGRADE off a machine the old build
            # provisioned, so by the time STEP 1b runs the new one is already there.
            + "".join(
                f'group:{name}:) printf "{name}:x:{gid}:\\n"; exit 0;;\n'
                for name, gid in gids.items()
            )
            + f'passwd:{names["legacy_group"]}:*) printf "{names["legacy_group"]}:x:0:'
            f'{gids[names["legacy_group"]]}::x:/nonexistent:/usr/sbin/nologin\\n"; exit 0;;\n'
            'esac\nexit 2\n',
            encoding="utf-8",
        )
        for tool in ("addgroup", "adduser", "setfacl"):
            (binroot / tool).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        for tool in ("deluser", "delgroup"):
            (binroot / tool).write_text(
                "#!/bin/sh\nname=\n"
                "while [ $# -gt 0 ]; do case \"$1\" in --system) shift;; *) name=\"$1\"; shift;; esac; done\n"
                f'printf "%s\\n" "$name" >> "{removed}"\n'
                "exit 0\n",
                encoding="utf-8",
            )
        for stub in binroot.iterdir():
            stub.chmod(0o755)

        # The tree the OLD build left, unless this case asked for a machine that has
        # never run this package at all: four directories at 2770 with a default ACL
        # granting the group rwx, and every file inside them group-owned by the OLD
        # group at the mode this package publishes at. Plus `/var/lib/mosdns/
        # installer`, which the old build created too and which is NOT one of the
        # four -- it holds the ownership marker and the recorded NetworkManager
        # values, so it is the one directory whose group decides whether a later
        # uninstall can prove what this package set.
        #
        # `os.chown(path, -1, gid)` and not `(os.getuid(), gid)`: asking for the uid
        # the file already has is a separate, unnecessary privilege, and a fixture
        # that fails on it would read as a migration failure.
        if not self.empty:
            for directory in STATE_DIRECTORIES:
                target = root / directory.lstrip("/")
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o2770)
                os.chown(target, -1, gids[names["legacy_group"]])
            planted = {
                "var/lib/mosdns/lists/cn-domains.txt": 0o640,
                "var/lib/mosdns/lists/source-lock.json": 0o640,
                "var/lib/mosdns/lists/cloudflare-ips.json": 0o640,
                "var/lib/mosdns/runtime/control.lock": 0o640,
            }
            for relative, mode in planted.items():
                target = root / relative
                target.write_bytes(b"planted\n")
                os.chmod(target, mode)
                os.chown(target, -1, gids[names["legacy_group"]])
            installer = root / "var/lib/mosdns/installer"
            installer.mkdir(parents=True, exist_ok=True)
            os.chmod(installer, 0o2770)
            os.chown(installer, -1, gids[names["legacy_group"]])
            for relative in (
                "var/lib/mosdns/installer/managed-by",
                "var/lib/mosdns/installer/network-manager-backup.json",
            ):
                target = root / relative
                target.write_text("{}\n", encoding="utf-8")
                os.chmod(target, 0o600)
                os.chown(target, -1, gids[names["legacy_group"]])

        body = postinst_step_body(text, "1b")
        script = root.parent / "migration.sh"
        # `_rooted` and not a header of substituted variables: STEP 1b names its
        # four paths as LITERALS, so a header would have to restate them and the
        # case would be reading this file's list rather than the script's. Rooting
        # the shipped text is the same one pass `postrm`'s own sandbox uses, and it
        # is what keeps the step off this machine's `/var/lib/mosdns`.
        script.write_text(
            "set -e\n"
            f'STATE_GROUP={names["new_group"]}\n'
            f'LEGACY_STATE_GROUP={names["legacy_group"]}\n'
            + _rooted(body, str(root))
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            ["sh", str(script)],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PATH": f"{binroot}{os.pathsep}{os.environ['PATH']}"},
        )
        return _Migration(root, result, names, gids)

    def __exit__(self, *exc):
        return False


def collision_report(groups=(), users=()):
    """Run the shipped `postinst`'s own STEP 1 over a fixture account database, and
    return what it printed.

    **Run rather than read, because the thing under test is a sentence's TRUTH and a
    sentence's truth is not a substring.** STEP 1 reports a group that already exists
    and tells the operator it "belongs to another package". Before ruling 191(d)
    that was worth saying: `dnscrypt-proxy` is the upstream package's own group, and
    postinst used to admit that the two were sharing one identity. The rename removed
    anything left to collide with -- and the same lines run against the NEW names,
    so every `dpkg --configure` retry printed four lines saying this package's own
    group was somebody else's. MEASURED on a 24.04 cell: a second `dpkg -i` over
    the first produced

        postinst: the mosdns-router group already exists (mosdns-router:x:102:)
        postinst: and this install is using it rather than creating it. Nothing in
        postinst: this package creates that name, so it belongs to another package,

    for a group this package had created four lines earlier.

    So the distinction the report has to make is not "does the group exist" -- on
    every re-run it does -- but "does the group exist WITHOUT the service identity
    this package's own `adduser` creates", which is the shape of a real collision.
    `groups` and `users` are the names the fixture database answers for; a case
    passes both to describe this package's own accounts and only `groups` to
    describe a bare group left by somebody else.

    `addgroup` and `adduser` are stubs that succeed, because they are idempotent and
    the question is what the surrounding reporting decides. Nothing else is stubbed:
    STEP 1 runs no command that touches this machine.
    """
    text = POSTINST.read_text()
    variables = shell_assignments(text)
    names = identities_from(text)
    root = Path(scratch_directory("mosdns-postinst-step1."))
    if root.exists():
        subprocess.run(["rm", "-rf", str(root)], check=True)
    binroot = root / "bin"
    binroot.mkdir(parents=True)
    (binroot / "getent").write_text(
        "#!/bin/sh\n"
        # The key carries a trailing colon so the patterns can end in one, which is
        # what keeps `group:mosdns-router` from also answering for a longer account
        # name that starts with it. `--system` and the like are not arguments this
        # call makes, but a stub that silently answered for whatever it was given
        # would report a collision where there is none.
        'key="${1:-}:${2:-}:"\n'
        "case \"$key\" in\n"
        + "".join(f'group:{name}:) printf "{name}:x:1:\\n"; exit 0;;\n' for name in groups)
        + "".join(
            f'passwd:{name}:) printf "{name}:x:1:1::x:/nonexistent:/usr/sbin/nologin\\n"; '
            "exit 0;;\n"
            for name in users
        )
        + "esac\nexit 2\n",
        encoding="utf-8",
    )
    for tool in ("addgroup", "adduser"):
        (binroot / tool).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for stub in binroot.iterdir():
        stub.chmod(0o755)
    script = root / "step1.sh"
    script.write_text(
        "set -e\n"
        + f'STATE_GROUP={names["group"]}\n'
        + f'ROUTER_USER={names["router"]}\n'
        + f'CONTROL_USER={names["control"]}\n'
        + f'RESOLVER_USER={names["resolver"]}\n'
        + postinst_step_body(text, 1)
        + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["sh", str(script)],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "PATH": f"{binroot}{os.pathsep}{os.environ['PATH']}"},
    )
    return completed.stderr


def sandboxed_postinst_step(number, published, source_pair, text=None, absent=()):
    """Run one `postinst` step's own lines in a throwaway tree, and return the tree.

    The point of this helper is that the DECISION is the script's own text. The
    paths are the script's own variables -- read out of its own assignments by
    `shell_assignments`, so a renamed variable is a failure here rather than a
    silent divergence -- with the sandbox root in front, and the one tool that
    cannot run on this host replaced by a `PATH` shim.

    The shim is `install`, and the reason is narrow and stated in the shim itself:
    the script asks for group `mosdns`, which does not exist on a build machine,
    and `install -g` on a missing group fails. Ownership is not what this step
    decides, so the shim drops `-o` and `-g` and execs the real `install`. The
    readability test, the `sed`, the `sha256sum` and the comparison are the
    script's own, unrewritten.

    `published` maps an absolute destination path to bytes, or is `{}` to plant
    nothing there; `source_pair` maps each shipped path the step reads to its
    bytes; and `absent` names shipped paths to remove after planting, which is
    how the "the file this package ships is not there" case is run through the
    same path as every other one rather than beside it.
    """
    text = text if text is not None else POSTINST.read_text()
    body = postinst_step_body(text, number)
    root = Path(scratch_directory("mosdns-postinst-step.")) / "root"
    # Only the variables this step NAMES, and only from the script's own
    # assignments. `shell_assignments` reads the whole file, so it also finds the
    # `expected_digest=$(...)` and `actual_digest=$(...)` lines inside the step --
    # and emitting those into the header ran the step's own digest comparison
    # against an empty tree before the step had placed anything, which is a
    # failure of the harness wearing the step's name.
    referenced = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", body))
    variables = {
        name: value
        for name, value in shell_assignments(text).items()
        # Only a LITERAL. `shell_assignments` reads the whole file, so it also
        # finds the `expected_digest=$(sed ...)` and `actual_digest=$(sha256sum
        # ...)` lines inside the step -- and the body references both, so a filter
        # on the name alone would put them in the header and run the step's own
        # digest comparison against an empty tree before the step had placed
        # anything. A harness cannot precompute a value the script computes.
        if name in referenced and "$(" not in value and "`" not in value
    }
    for name in ("SOURCE_LIST", "SOURCE_LOCK", "PUBLISHED_LIST", "PUBLISHED_LOCK"):
        if name not in variables:
            raise AssertionError(f"postinst does not assign {name}, so this step cannot be read")
    for name, value in variables.items():
        if value.startswith("/"):
            variables[name] = str(root) + value
    # **Every** shipped file this step reads is planted, not just the China pair.
    # The set is derived from the step's own variable assignments and the shipped
    # data directory rather than named here, because a name missing from a list is
    # a file the step decides something about without ever seeing it -- and a step
    # that verified nothing at all would pass every assertion in the suite. So a
    # shipped file the step reads and this fixture has no bytes for is a failure
    # of the harness, raised before the step runs.
    for name, value in sorted(variables.items()):
        if not value.startswith(str(root) + DATA_DIRECTORY + "/"):
            continue
        if name not in source_pair:
            raise AssertionError(
                f"postinst reads {name} ({value}) and this test supplies no bytes for it, so the "
                "step would run against a file that is not there"
            )
        path = Path(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source_pair[name], encoding="utf-8")
    for destination, contents in published.items():
        path = root / destination.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    for name in absent:
        Path(variables[name]).unlink()
    for name in ("PUBLISHED_LIST", "PUBLISHED_LOCK"):
        Path(variables[name]).parent.mkdir(parents=True, exist_ok=True)

    shim = root.parent / "shim"
    shim.mkdir(exist_ok=True)
    install = shim / "install"
    install.write_text(
        "#!/usr/bin/env python3\n"
        "# A stand-in for install(1) that drops -o and -g: this build host has no\n"
        "# `mosdns` group and `install -g` on a missing group fails. Ownership is not\n"
        "# what the step being run decides, so the decision runs unrewritten.\n"
        "import os, sys\n"
        "args, skip = [], 0\n"
        "for word in sys.argv[1:]:\n"
        "    if skip:\n"
        "        skip -= 1\n"
        "        continue\n"
        "    if word in ('-o', '-g'):\n"
        "        skip = 1\n"
        "        continue\n"
        "    args.append(word)\n"
        "os.execv('/usr/bin/install', ['install'] + args)\n"
    )
    install.chmod(0o755)
    header = "set -e\n" + "".join(f"{name}={value}\n" for name, value in variables.items())
    script = root.parent / "step.sh"
    script.write_text(header + body + "\n")
    environment = dict(os.environ)
    environment["PATH"] = f"{shim}{os.pathsep}{environment.get('PATH', '')}"
    completed = subprocess.run(
        ["sh", str(script)], capture_output=True, text=True, check=False, env=environment
    )
    return root, variables, completed


def postinst_transaction_tail(text=None):
    """`postinst` from its STEP 4 header to its last line, as the script's own text.

    Cut at the header rather than at a line count, for the reason
    `postinst_step_body` gives. Everything from the transaction onwards is
    included, and that is the whole point: the status capture, the arms, the
    `exit 1` a refusal ends on, the timer enable and the final `exit 0` are ONE
    control-flow unit, and a harness that cut between any two of them is the
    reason a `fi` in the wrong place went unseen -- the three substring tests this
    replaced each asserted something true of a script that failed on every
    install.
    """
    text = text if text is not None else POSTINST.read_text()
    header = re.compile(r"^#\s*-{2,}\s*STEP\s+4\b", re.MULTILINE)
    found = header.search(text)
    if found is None:
        raise AssertionError(
            "postinst has no STEP 4 header, so its transaction cannot be cut out of it"
        )
    return text[found.start():]


# The phase of the machine `postinst`'s own `set -e` is in. A maintainer script
# has one, and whether a bare failing command ends the run is a property of the
# script rather than of the shell that started it, so the harness below copies the
# script's own line instead of assuming one.
POSTINST_SET_OPTION = "set -e"

# Where the tail asks whether systemd is running. Rewritten into the throwaway
# tree by `postinst_transaction_run`, so the answer is the tree's and not the
# build host's: a test that read this host's real answer would pass here and fail
# on a machine without systemd, which is the machine-dependency the boundary
# forbids.
SYSTEMD_RUNTIME_DIRECTORY = "/run/systemd/system"


def postinst_transaction_run(status, second_argument=None, systemd_running=True,
                             failing_systemctl=None, text=None):
    """Run `postinst`'s own transaction, its arms and its timer enable, and look.

    Returns ``(completed, calls)``: the script's own ``CompletedProcess``, and the
    argument arrays the `systemctl` shim was given.

    WHAT IS SUBSTITUTED, and why each substitution is the one that cannot hide the
    defect this exists to catch:

    * ``$INSTALLER`` -- the only substitution that matters, and it is also what
      makes the run safe. The real installer takes a machine's DNS over and
      `NO-HOST-MUTATION.md` forbids running it on this host, so the stub is a
      three-line `sh` program that prints its argument array and exits with the
      status the test names. Its path comes from the script's OWN assignment
      through `shell_assignments`, so a renamed variable fails the harness instead
      of leaving it substituting nothing.
    * ``/run/systemd/system`` -- the two `[ -d … ]` guards, rewritten to a
      directory in the throwaway tree whose presence the test chooses.
    * ``systemctl`` -- a `PATH` shim that appends its argument array to a log and
      exits zero. The shim is first on `PATH`, so the host's systemd is not
      reachable from the generated script and `daemon-reload` and `enable` are lines
      in a file. `failing_systemctl=` names a VERB the shim fails, because a shim
      that can only succeed cannot show what the script does when a command it
      issued did not work.
    * the ``set`` option -- the script's own line, found rather than assumed.

    WHAT IS NOT SUBSTITUTED: the status capture, the arms, every `exit`, the
    `[ -d … ]` tests themselves, the ``${2:-}`` upgrade test and the timer's own
    argument array. Those are the script's lines, cut out of the file on disk, and
    the exit status and the messages this returns are the ones `dpkg` would see.
    """
    text = text if text is not None else POSTINST.read_text()
    tail = postinst_transaction_tail(text)
    variables = shell_assignments(text)
    if "INSTALLER" not in variables:
        raise AssertionError(
            "postinst does not assign INSTALLER, so this run could not put a stub where the "
            "transaction calls the installer"
        )
    if POSTINST_SET_OPTION not in text.splitlines():
        raise AssertionError(
            f"postinst has no {POSTINST_SET_OPTION!r} line, so the harness cannot know which "
            "phase of the machine it is running the control flow in"
        )
    set_option = next(
        line for line in text.splitlines() if line.strip() == POSTINST_SET_OPTION
    )

    root = Path(scratch_directory("mosdns-postinst-transaction."))
    # The stub installer, in the throwaway tree and reachable only through the
    # header below. It is never the real program and the real program's path is
    # not on any PATH this harness builds.
    stub = root / "installer-stub"
    stub.write_text(
        "#!/bin/sh\n"
        "# A stand-in for the installer. It changes nothing and exits with the status the\n"
        "# test names, because what is under test is which arm postinst PRINTS for that\n"
        "# status -- not whether an install can be performed on this machine, which the\n"
        "# boundary in NO-HOST-MUTATION.md forbids here.\n"
        'printf "stub-installer: %s\\n" "$*" >&2\n'
        f"exit {int(status)}\n"
    )
    stub.chmod(0o755)

    log = root / "systemctl.log"
    shim = root / "shim"
    shim.mkdir(parents=True, exist_ok=True)
    systemctl = shim / "systemctl"
    # A failure is asked for BY VERB, matched on the shim's own `$1`, and it fails
    # EVERY call of that verb rather than the first: a `systemctl enable` that fails
    # once and then succeeds is not the machine this exists to model, and a shim
    # that failed only the first call would let a script that retried look working.
    # The call is LOGGED before it fails, because a test asking what the script did
    # with a command that failed needs to see that it issued it.
    fail_line = (
        f'if [ "$1" = {shlex.quote(failing_systemctl)} ]; then\n'
        '  echo "systemctl: stub failure for $1" >&2\n'
        "  exit 1\n"
        "fi\n"
    ) if failing_systemctl else ""
    systemctl.write_text(
        "#!/bin/sh\n"
        "# A stand-in for systemctl that records its argument array and changes nothing.\n"
        "# It is first on PATH, so the build host's systemd cannot be reached from the\n"
        "# generated script: `daemon-reload` and `enable` are lines in a file.\n"
        + f'printf "%s\\n" "$*" >> {log}\n'
        + fail_line
        + "exit 0\n"
    )
    systemctl.chmod(0o755)

    runtime = root / "run-systemd-system"
    runtime.mkdir(parents=True, exist_ok=True)
    if not systemd_running:
        runtime.rmdir()

    # The two guards, and nothing else. Every other line is the script's own.
    body = tail.replace(SYSTEMD_RUNTIME_DIRECTORY, str(runtime))
    script = root / "postinst-tail.sh"
    script.write_text(
        set_option
        + "\nINSTALLER="
        + str(stub)
        + "\n"
        + body
        + "\n"
    )
    environment = dict(os.environ)
    environment["PATH"] = f"{shim}{os.pathsep}{environment.get('PATH', '')}"
    completed = subprocess.run(
        # dpkg's own two arguments: `postinst configure` and, on an upgrade, the
        # version that was configured before. The `${2:-}` arm depends on them.
        ["sh", str(script), "configure"] + ([second_argument] if second_argument else []),
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    calls = [
        line.split()
        for line in log.read_text().splitlines()
    ] if log.exists() else []
    return completed, calls


def postinst_status_arms_findings(text=None):
    """``(arms, findings)`` for `postinst`'s arms on the installer's exit status.

    `numeric_case_arms` reads a `case` and answers `{}` for anything else without
    saying so, so a script whose status arms had been un-nested into an
    `if`/`elif`/`else` chain -- the shape `88bc2af` shipped, and a shape a hand edit
    takes -- left every test that asks for arm 4 to raise `KeyError: '4'`. A
    `KeyError` is an ERROR in a suite and a FAILURE in nothing: a control aimed at
    such a test sees a crash, not a verdict, and a crash is not a gate.

    So the reader reports what it could not read, and a shape it does not understand
    is a FINDING rather than an empty dictionary. The findings are the ones a
    `case` reader genuinely cannot answer, and nothing else is invented here -- the
    bodies themselves are read the same way they always were.
    """
    text = text if text is not None else POSTINST.read_text()
    tail = postinst_transaction_tail(text)
    arms = numeric_case_arms(tail)
    findings = []
    if not arms:
        # Name the shape we can recognise, because "no arms" and "arms of a shape I
        # cannot read" are different situations and only the first is a `case` bug.
        if re.search(r'^\s*(?:el)?if\s+\[?\s*"?\$\{?install_status', tail, re.MULTILINE):
            findings.append(
                "postinst's status arms are an `if`/`elif` chain on the captured status rather "
                "than a `case`, and no reader in this suite understands that shape: the arms are "
                "read as nothing, so a test asking what the arm for a status says would report "
                "an absent arm rather than the un-nesting that caused it"
            )
        else:
            findings.append(
                "postinst has no readable arms on the captured install status, so nothing can "
                "ask what this script says about a status it does not know"
            )
    for status in ("1", "3", "4", "5", "6", "*"):
        if status not in arms and arms:
            findings.append(f"postinst's status arms have no arm for {status}")
    return arms, findings


def postinst_status_arms(text=None):
    """``{status: body}`` for `postinst`'s arms on the installer's exit status.

    A `case` on an exit status, read with `numeric_case_arms` -- the reader built
    for exactly that shape, which is why it refuses a word label. This is what
    lets a test ask "does the arm for the installer's own EXIT_REFUSED stop calling
    it unknown" as a question about a BODY rather than about a paragraph.

    After the fix the arms live inside the `else` of `if "$INSTALLER" install`,
    which is `prerm`'s shape and the only one in which a successful run cannot
    reach them. `numeric_case_arms` does not care where they are, so neither does
    this -- but it does care WHAT SHAPE they are in, and a shape it cannot read is
    raised as an `AssertionError` carrying the finding rather than returned as an
    empty dictionary. `AssertionError` because that is what `assertMethodFails` and
    every other gate in this suite can act on; an empty dictionary is not.
    """
    arms, findings = postinst_status_arms_findings(text)
    if findings:
        raise AssertionError("; ".join(findings))
    return arms


# A line that OPENS a shell block, and a line that CLOSES one, for the walk in
# `matching_closer`. Both are ANCHORED, and that is the whole of the reader: these
# are maintainer scripts written as one command or one block per line, and the
# arms' prose is full of the words a general matcher would take for keywords --
# "…/var/lib/mosdns/installer for what was recorded", "…nothing here for them to
# run against" -- so an unanchored match reads three blocks that are not there and
# then pairs the `fi` with the wrong `if`. What the reader cannot see it says so
# for: command substitution and single-line `if …; then …; fi`, neither of which
# any of the four maintainer scripts contains, and the control below pins the
# answer it gets against a second, independent derivation of the same line.
SHELL_BLOCK_OPENER = re.compile(r"^(?:if|for|while|until|case)\b")
SHELL_BLOCK_CLOSER = re.compile(r"^(?:fi|esac|done|\})\s*$")


def matching_closer(lines, opening):
    """The index of the line that closes the block ``opening`` opens.

    ``opening`` is the index of an opening line and the answer is the index of the
    matching `fi`/`esac`/`done`/`}` -- by MATCHING rather than by position, because
    "the last `fi` below the capture" is a rule that answers a different question
    the moment another block appears below it, and a control that silently starts
    moving a different line is the failure this project has now recorded four times.
    """
    depth = 0
    for index in range(opening, len(lines)):
        body = lines[index].strip()
        if body.startswith("#"):
            continue
        if SHELL_BLOCK_OPENER.match(body):
            depth += 1
        elif SHELL_BLOCK_CLOSER.match(body):
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(
        f"no line closes the block opened at line {opening + 1}, so this reader cannot "
        "answer the question it is here to answer"
    )


def status_capture(text):
    """``(capture, opening, closing, moved)`` for `postinst`'s status capture.

    Four line indices and the line itself, zero-based, so a test can say WHICH `fi`
    was moved rather than only that a `fi` moved. `closing` is the `fi` that closes
    the transaction, found by matching `if "$INSTALLER" install` and nothing else.
    """
    lines = text.splitlines(keepends=True)
    capture = next(
        index for index, line in enumerate(lines) if line.strip() == "install_status=$?"
    )
    opening = max(
        index for index, line in enumerate(lines)
        if line.strip() == f'if "$INSTALLER" install; then'
    )
    if not opening < capture:
        raise AssertionError(
            "postinst does not capture the status INSIDE the if that runs the installer, so "
            "there is no capture to close early"
        )
    closing = matching_closer(lines, opening)
    if closing <= capture:
        raise AssertionError(
            "the `fi` that closes the transaction is not below the capture, so the reader "
            "and the file disagree about where the transaction ends"
        )
    return capture, opening, closing, lines[closing]


def capture_closed_early(text):
    """`postinst` with the `fi` that closed the status capture moved above the arms.

    This is the Critical, manufactured, and it is manufactured by moving ONE line:
    the `fi` that closed `if "$INSTALLER" install` is moved to sit immediately after
    `install_status=$?`, which is the edit `88bc2af` made and the only edit it made.
    Everything else is the shipped script, and the result parses, so what the
    control manufactures is a BEHAVIOUR and not a parse error: the arms and the
    `exit 1` are now at the top level, a run that SUCCEEDS falls into them with
    `install_status` never assigned, and STEP 5 -- the timer enable -- is below an
    `exit 1` no run can get past.

    It exists because the three substring checks that were in place instead were all
    TRUE of that script: they asserted that `install_status=$?` was present, that
    `if "$INSTALLER" install` was present, and that the status-4 body mentioned a
    missing resolver, and none of those can see a `fi` in the wrong place. A control
    that moved a line the checks never read would not have shown that, and one that
    rewrote the whole tail would be a second implementation of the check.

    THE ONE PLACE THIS IS NOT THE SHIPPED SCRIPT, and the difference is the shape
    rather than the defect: `88bc2af` read the capture as `${install_status:-1}`, so
    its default arm printed "exited 1"; the current script retired that default --
    `test_postinst_captures_the_installers_status_the_way_prerm_does` holds its
    absence -- so a run that never assigned the variable prints "exited , which is
    not a". What a successful configure does is the same either way: exit 1, and no
    timer enabled. Every claim in this paragraph is asserted by
    `ControlTests.test_a_capture_closed_before_the_arms_is_reported_by_the_method`.
    """
    capture, _opening, closing, moved = status_capture(text)
    lines = text.splitlines(keepends=True)
    return "".join(
        lines[: capture + 1] + [moved] + lines[capture + 1 : closing] + lines[closing + 1 :]
    )


def arms_unnested_into_a_chain(text):
    """`postinst` with its `case` on the install status turned into an `if`/`elif`/`else`.

    The shape `88bc2af` shipped: the arms sit at the TOP LEVEL, outside the capture's
    `fi`, each behind its own `-eq` test. Two edits rather than one, because the
    un-nesting is not a change of punctuation -- a `case` cannot be un-nested while
    it is still inside the `else`, so the `fi` moves too, which is
    `capture_closed_early`.

    It exists to demonstrate what a reader that only understands `case` does with a
    shape it does not understand, and the result parses, so a gate that cannot read
    it fails for the reason the gate is about rather than on a syntax error.
    """
    moved = capture_closed_early(text)
    tail = postinst_transaction_tail(moved)
    arms = numeric_case_arms(tail)
    if not arms:
        raise AssertionError(
            "postinst's status arms are not a readable `case`, so there is nothing to un-nest "
            "into a chain and this would be demonstrating nothing"
        )
    out, first = [], True
    for label, body in arms.items():
        if label == "*":
            out.append("else\n" + body + "\n")
            continue
        out.append(
            (f'if [ "$install_status" -eq {label} ]; then\n' if first
             else f'elif [ "$install_status" -eq {label} ]; then\n') + body + "\n"
        )
        first = False
    out.append("fi\n")
    lines = tail.splitlines(keepends=True)
    start = next(
        index for index, line in enumerate(lines) if line.strip() == 'case "$install_status" in'
    )
    end = next(index for index, line in enumerate(lines) if line.strip() == "esac")
    return moved.replace(
        tail, "".join(lines[:start]) + "".join(out) + "".join(lines[end + 1:]), 1
    )


def shell_parses(text):
    """Whether `sh` can PARSE ``text``, asked of the parser and not of a run.

    A run only reaches the parser as far as control flow takes it, so a script that
    is unparseable from here on can still run cleanly to its first `exit` -- and a
    control that manufactured an unparseable script would then be holding a property
    ("postinst parses") that it never claimed and that a mutation of the FI could
    never have broken on its own. `sh -n` reads the whole file and is the only
    question here that sees all of it.
    """
    with tempfile.TemporaryDirectory(
        prefix="mosdns-parse.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
    ) as scratch:
        script = Path(scratch) / "script.sh"
        script.write_text(text, encoding="utf-8")
        return subprocess.run(
            ["sh", "-n", str(script)], capture_output=True, text=True, check=False
        )


def unpinned_pair(list_body, commit="0000000000000000000000000000000000000000"):
    """A self-consistent China list and lock of an operator's own re-pin.

    Self-consistent on purpose: the published lock's `list_sha256` is the digest
    of the published list, exactly as `mosdns-cdnctl update-lists --pin-remote`
    writes them. So nothing but the overwrite itself can reveal that postinst
    replaced an operator's pin -- which is the whole of the property.
    """
    digest = hashlib.sha256(list_body.encode("utf-8")).hexdigest()
    lock = json.dumps(
        {
            "schema_version": 1,
            "repository": "v2fly/domain-list-community",
            "commit": commit,
            "sha256": hashlib.sha256(commit.encode("ascii")).hexdigest(),
            "list_sha256": digest,
            "entry": "data/cn",
        },
        indent=2,
    ) + "\n"
    return list_body, lock


def unconditional_publish(text):
    """`postinst` with the pair published on every run, as it was before the fix."""
    line = 'if [ ! -r "$PUBLISHED_LIST" ] || [ ! -r "$PUBLISHED_LOCK" ]; then'
    if line not in text:
        raise AssertionError(f"postinst does not guard the published pair with {line!r}")
    return text.replace(line, "if true; then")


def executed_lines(text):
    """The lines a shell script RUNS, with comments and `echo`s removed.

    Two removals and both are needed, and neither is a weakening of the check it
    serves. A comment that explains why the script never re-pins a list names the
    re-pinning command, and an operator is told to re-pin one by name when the
    published pair cannot be verified -- so a scan of the raw text cannot tell a
    script that RE-PINS from a script that says out loud that it does not, and the
    only ways to satisfy both are to delete the explanation or to delete the
    advice. What is forbidden is RUNNING the re-pin, and an `echo` does not run
    the string it prints.
    """
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^echo\b", stripped):
            continue
        lines.append(stripped)
    return lines


def _labels(text):
    return [label.strip() for label in text.split("|") if label.strip()]


def numeric_case_arms(text):
    """``{label: body}`` for a ``case`` whose arms are exit-status NUMBERS.

    `case_arms` deliberately refuses a numeric label, because a maintainer
    script's dpkg verbs are words and a reader that accepted anything would read a
    `case` on an exit status as a `case` on a verb. This reader is the other
    half: it reads only a number or the `*` default arm, so the two cannot be
    confused, and it is what lets a test ask "does prerm say something different
    for the installer's two refusals" as a question about two BODIES rather than
    about two substrings of a paragraph.
    """
    label_line = re.compile(r"^\s*([0-9]+|\*)\)(?P<inline>.*)$")
    lines = text.splitlines()
    arms = {}
    for index, line in enumerate(lines):
        match = label_line.match(line)
        if match is None:
            continue
        if match.group("inline").strip() in ("", ";;"):
            body = []
            cursor = index + 1
            while cursor < len(lines) and lines[cursor].strip() != ";;":
                body.append(lines[cursor])
                cursor += 1
            arms[match.group(1)] = "\n".join(body)
        else:
            arms[match.group(1)] = match.group("inline")
    return arms


def arm_bodies(text):
    """``{label: body}`` for a maintainer script's ``case`` arms. See case_arms."""
    bodies = {}
    for labels, body in case_arms(text):
        for label in labels:
            bodies[label] = body
    return bodies


def destructive_commands(label, body):
    """The removal commands in one arm, as the lines that carry them."""
    return [
        line.strip() for line in body.splitlines()
        if re.search(r"\brm\s+-[a-z]*[rf]", line) and not line.strip().startswith("#")
    ]


def shell_alternatives(text):
    """The `case` labels a maintainer script branches on, in the order it lists them.

    Read by `case_arms`, so the label set a script handles and the body attributed to
    each label can never come from two different parsers that disagree about where an
    arm ends.
    """
    return [label for labels, _body in case_arms(text) for label in labels]


def shell_code(text):
    """A shell script's COMMANDS, with its comments removed.

    A script that explains in a comment that it never runs `dpkg -i` would otherwise
    be caught by the check that says it never runs `dpkg -i`, and the only way to
    satisfy both would be to delete the explanation. A `#` inside a quoted string is
    not a comment, which is why this is a blunt instrument and is used only on the
    one script in this repository that the tests own.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def function_body(source, name):
    """One top-level function of a Python module, as text.

    Used to scope an assertion to a path rather than to the whole module, because
    the module legitimately does the thing the assertion forbids somewhere else: an
    install that enabled a unit and rolled back has to disable it again, and that is
    not the plain uninstall this project refuses to give a disable step.
    """
    pattern = re.compile(rf"^def {re.escape(name)}\(", re.MULTILINE)
    start = pattern.search(source)
    if start is None:
        raise AssertionError(f"{name} is not a top-level function of the module")
    rest = source[start.end():]
    end = re.search(r"^(?:def |class |[A-Za-z_][A-Za-z0-9_]* =)", rest, re.MULTILINE)
    return rest[: end.start()] if end is not None else rest


# The label every digest in this project is written under, and the label the pinned
# tag's commit is written under. Two readers, two labels, and a reader that selects
# by LABEL rather than by position -- because the first version of the build script's
# reader took the first non-comment line, and the moment a labelled line was added
# above the digest that reader returned the literal string "tag-commit:" and wrote it
# into the shipped BUILD-MANIFEST as the archive's digest.
#
# Position is the wrong thing to depend on, and the reason is not theoretical: a pin
# is a file that GAINS lines. Every new fact recorded beside the digest -- a second
# checksum, a source URL, a note about which release it is -- becomes the first line
# a positional reader picks up, and the failure is silent because the reader's own
# guard ("is it non-empty?") is answered by a label.
DIGEST_LABEL = "archive sha256:"
COMMIT_LABEL = "tag commit:"
# A sha256sum line: 64 lowercase hex, a separator, and the file name. A label cannot
# match it, because a label ends in a colon and the first field here is hex.
SHA256SUM_LINE = re.compile(r"^([0-9a-f]{64})[ \t]+\*?(\S+)$")
PIN_COMMIT_LINE = re.compile(r"^#\s*tag-commit:\s*([0-9a-f]{40})\s*$")
# A manifest field: `label` then whitespace then the value, to end of line. Anchored
# on the label WITH its colon so `archive sha256:` cannot match `archive sha256: xx`.
MANIFEST_FIELD = re.compile(r"^([a-z][a-z0-9 ]*):[ \t]+(\S.*?)[ \t]*$", re.MULTILINE)


def manifest_field(text, label):
    """One `label: value` line of a BUILD-MANIFEST, by label.

    The point of reading it this way is that "the digest appears somewhere in the
    file" is not the claim. The shipped manifest printed a real digest on the line
    BELOW the `archive sha256:` field, so a presence check passed while the field a
    person reads said `tag-commit:` -- and the gate was blind to the difference.
    """
    matches = MANIFEST_FIELD.findall(text)
    # The label the caller passes INCLUDES the colon, because that is how the field
    # reads in the file; the capture does not, because the colon is what separates the
    # two halves. Comparing the two directly is a field that can never be found, which
    # is a check that passes for the wrong reason whenever it is allowed to raise.
    values = [value for name, value in matches if name + ":" == label]
    if len(values) != 1:
        raise AssertionError(
            f"the manifest has {len(values)} {label!r} fields, want exactly one"
        )
    return values[0]


def pin_digest(text, where="the pin"):
    """The one `<64 hex>  <file name>` line of a pin, selected by SHAPE.

    Shape, not position, and not "the first line that is not a comment": the pin
    carries the tag's commit as a comment above the one `sha256sum -c` line, and a
    reader that took the first non-comment line took a comment's payload. A 64-hex
    first field is something a label cannot be, because a label ends in a colon.
    """
    digests = [
        match.groups()
        for match in (SHA256SUM_LINE.match(line.strip()) for line in text.splitlines())
        if match is not None
    ]
    if len(digests) != 1:
        raise AssertionError(f"{where} has {len(digests)} sha256sum lines, want exactly one")
    return digests[0]


def pin_commit(text, where="the pin"):
    """The one `# tag-commit: <40 hex>` of a pin, selected by LABEL.

    A comment, so that `sha256sum -c` stays clean on the pin: a bare
    `tag-commit: <40 hex>` line is neither a comment nor a digest, and `sha256sum -c`
    answers such a line with "WARNING: 1 line is improperly formatted" -- on a file
    whose own comment tells the reader to run exactly that command.
    """
    commits = [
        match.group(1) for match in
        (PIN_COMMIT_LINE.match(line) for line in text.splitlines())
        if match is not None
    ]
    if len(commits) != 1:
        raise AssertionError(f"{where} has {len(commits)} tag-commit lines, want exactly one")
    return commits[0]


def recorded_digest():
    """The pinned archive's digest and file name. See pin_digest for the rule."""
    return pin_digest(SOURCE_DIGEST.read_text(), SOURCE_DIGEST.name)


def recorded_commit():
    """The pinned tag's commit. See pin_commit for why it lives in a comment."""
    return pin_commit(SOURCE_DIGEST.read_text(), SOURCE_DIGEST.name)


# The reader the SHIPPED build script uses, extracted from the script and run here.
#
# Not a copy of it. The first version of the manifest test proved the TEST's reader
# correct while the shipped one stayed positional, so the shipped manifest printed a
# label where a checksum belongs and the gate passed; a copy of the shipped reader
# would have been free to drift the same way. Extracting the script's own sed
# expression and running `sed` with it means a change to the build script's reader is
# a change to what this control measures.
def shipped_reader_digest(text, where="the planted pin"):
    """What `scripts/build-deb.sh` would read as the archive's digest, from `text`.

    The script's OWN `$( ... )` extraction block is extracted and run, with
    `DNSCRYPT_PIN` pointed at a temporary copy of `text`. Not a copy of the reader, and
    not an assumption about its shape: the first version of the manifest test proved
    the TEST's reader correct while the shipped one stayed positional, so a copy of the
    shipped reader would have been free to drift the same way, and an earlier attempt
    at this control required the reader to be a `sed -n` and so reported "the reader
    changed shape" instead of "the reader returned the wrong value" -- which is a
    message about the control rather than about the defect.
    """
    script = BUILD_SCRIPT.read_text()
    block = re.search(
        r"^recorded_digest=\$\((?P<body>.*?)^\)$", script, re.MULTILINE | re.DOTALL
    )
    if block is None:
        raise AssertionError(
            "scripts/build-deb.sh no longer reads the digest from a $( ... ) block, so this "
            "control cannot run what the build actually runs"
        )
    with tempfile.NamedTemporaryFile(
        "w", suffix=".pin", delete=False, encoding="utf-8"
    ) as handle:
        handle.write(text)
        planted = handle.name
    try:
        program = (
            f'DNSCRYPT_PIN={shlex.quote(planted)}\n'
            "recorded_digest=$(" + block.group("body") + ")\n"
            'printf %s "$recorded_digest"\n'
        )
        result = subprocess.run(
            ["sh", "-c", program], capture_output=True, text=True, check=False
        )
    finally:
        os.unlink(planted)
    if result.returncode != 0:
        raise AssertionError(
            f"the shipped reader failed on {where}: {result.stderr.strip()[:300]}"
        )
    return result.stdout.strip()


def manifest_entries(text):
    """``packaging/mosdns-router.install`` as ``(source, destination)`` pairs.

    A source of ``-`` is an empty directory, which is how the three state
    directories are shipped: they have to exist before ``postinst`` provisions
    them, and they have to hold nothing.
    """
    entries = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) != 2:
            raise AssertionError(f"{stripped!r} is not a `source destination` line")
        entries.append((fields[0], fields[1]))
    return entries


# The four rule forms MOSDNS v5.3.4's domain_set reader accepts, and the only four
# this project's own converter can publish. A line that is not one of them is a line
# the gateway would read as something else, so the list is checked against the same
# four rather than against a guess at a domain syntax.
DOMAIN_SET_RULE_KINDS = ("domain", "full", "keyword", "regexp")
# An IPv4 literal in any of its spellings. A list of NAMES is what routes a query
# inside the network the user is not leaving; a list of ADDRESSES would be a
# configuration, and this project refuses to ship one.
IPV4_LITERAL = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def china_list_findings(text):
    """Every line of the published China list the gateway could not read as a rule.

    Read the way `internal/rules` reads it before it publishes: truncate at the
    first `#`, ignore a blank remainder, require one space-free section, and require
    the part before the first `:` to be a supported kind with a value behind it.
    """
    findings = []
    for number, raw in enumerate(text.splitlines(), start=1):
        expression = raw.split("#", 1)[0].strip()
        if not expression:
            continue
        if any(character.isspace() for character in expression):
            findings.append(f"line {number}: {expression!r} is not one space-free section")
            continue
        kind, separator, value = expression.partition(":")
        if not separator or kind not in DOMAIN_SET_RULE_KINDS or not value:
            findings.append(f"line {number}: {expression!r} is not a supported rule")
            continue
        if IPV4_LITERAL.search(value):
            findings.append(f"line {number}: {expression!r} carries an address, not a name")
    return findings


def is_ancestor_of_any(path, paths):
    """Whether ``path`` is a strict parent directory of anything in ``paths``.

    A package has to create `/etc` to install `/etc/mosdns/policy.yaml`, and a
    manifest that listed every parent of every file would be a list of `/` and `/usr`
    rather than of this package. So a directory in the staged tree that is on the way
    to a listed or generated path is derived rather than extra, and a directory that
    is on the way to nothing is exactly what the two other checks are for.
    """
    prefix = path if path.endswith("/") else path + "/"
    return any(other.startswith(prefix) for other in paths)


# Every directive systemd runs a program from, and the prefixes it allows in front
# of the path. Reading only ExecStart would miss an ExecStartPre=, an ExecStopPost=
# or an ExecReload= naming a path the package omits, and no unit uses one today --
# which is exactly why the check has to be about the family and not about the member
# in use this month.
EXEC_DIRECTIVES = (
    "ExecStartPre", "ExecStart", "ExecStartPost",
    "ExecReload", "ExecStop", "ExecStopPost",
)
# `-` ignores a failure, `+`/`!`/`!!` change the privileged/user execution, `:` leaves
# the environment alone. All of them are prefixes ON the path, so all of them have to
# come off before the path can be read.
EXEC_PREFIXES = "-+!:"


def unit_exec_paths(root, unit_names=SHIPPED_UNITS):
    """The absolute executable of every Exec* directive in the staged unit directory.

    Read back out of the unit files rather than out of a table, because the failure
    this catches is a unit naming a path the package does not install, and a table
    could only agree with itself.
    """
    found = {}
    for name in unit_names:
        text = (Path(root) / (UNIT_DIRECTORY + "/" + name).lstrip("/")).read_text()
        for section in ("Service", "Unit"):
            for key, value in parse_unit(text, name).get(section, []):
                if key not in EXEC_DIRECTIVES:
                    continue
                executable = value.lstrip(EXEC_PREFIXES).split()[0]
                if not executable.startswith("/"):
                    raise AssertionError(
                        f"{name}: {key}={value!r} names no absolute path, so nothing can decide "
                        "where the file goes"
                    )
                found.setdefault(executable, []).append(f"{name}:{key}")
    return found


def unit_documentation(root, name):
    """The manual page a staged unit documents itself with."""
    text = (Path(root) / (UNIT_DIRECTORY + "/" + name).lstrip("/")).read_text()
    pages = [
        value for key, value in parse_unit(text, name).get("Unit", []) if key == "Documentation"
    ]
    if len(pages) != 1:
        raise AssertionError(f"{name} names {len(pages)} manual pages, want exactly one")
    return pages[0]


# --- the tmpfiles.d entry ----------------------------------------------------

# The two staged-file shapes that neither `*.tmp` nor `.*.tmp` matches, and the
# producer that makes them. `internal/candidate` is the odd one out among this
# project's publishers: it calls `os.CreateTemp(directory, filepath.Base(path)+".*")`
# where the other three call `os.CreateTemp(dir, "."+base+".*.tmp")` -- so its
# staged file is `cloudflare-prefixes.txt.1234567`, with no leading dot and no
# suffix at all. A `*` matches the digits; the problem is that neither existing
# pattern names this directory, and the digits-only shape matches nothing else.
#
# These are reap lines and a reap line is a delete, so the two are named exactly
# rather than as a glob over the whole lists directory: a pattern loose enough to
# catch them would also catch the published files themselves.
STAGED_WITHOUT_A_SUFFIX = (
    "/var/lib/mosdns/lists/cloudflare-prefixes.txt.*",
    "/var/lib/mosdns/lists/cloudflare-ips.json.*",
)


def tmpfiles_lines(text):
    """The entry's directives as ``(type, path, fields)``, comments and blanks gone."""
    entries = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        entries.append((fields[0], fields[1] if len(fields) > 1 else "", fields[2:]))
    return entries


def tmpfiles_findings(text):
    """Every way the tmpfiles entry can fail to recreate the same directory.

    The properties are read rather than assumed because ``/run`` is a tmpfs: the
    group, the setgid bit and the default ACL postinst sets are all gone after a
    reboot, so this entry is the only thing that puts them back, and an entry that
    names the directory without the group is a directory the bridge cannot write.
    """
    findings = []
    entries = tmpfiles_lines(text)
    creating = [
        entry for entry in entries
        if entry[1] == "/run/mosdns" and entry[0] in ("d", "D", "z", "Z")
    ]
    if not creating:
        findings.append("/run/mosdns is never created on a boot")
    for kind, _path, fields in creating:
        if fields[:3] != ["2770", "root", STATE_GROUP_NAME]:
            findings.append(
                f"the /run/mosdns line is {' '.join([kind] + fields)}, "
                    f"want 2770 root {STATE_GROUP_NAME}"
            )
    acls = [entry for entry in entries if entry[1] == "/run/mosdns" and entry[0].startswith("a")]
    if not acls:
        findings.append("/run/mosdns is created with no ACL at all")
    elif creating and entries.index(acls[0]) < entries.index(creating[0]):
        # The shipped order is mode first, then the ACL, and it is the same
        # load-bearing pair postinst gets wrong so easily: systemd-tmpfiles applies
        # the `d` line's mode and the `a` line's ACL, and an ACL narrowed by a later
        # chmod is a directory that no service identity can write. An entry whose `a`
        # line comes first is exactly that, and a check that only asked "is there an
        # ACL" would pass it.
        findings.append(
            "the ACL on /run/mosdns is set BEFORE the line that creates it, so the mode is "
            "written after the ACL and narrows the mask the ACL created -- the same defect "
            "postinst's own order exists to avoid"
        )
    for _kind, _path, fields in acls:
        spec = " ".join(fields)
        if "g::rwx" not in spec:
            findings.append(f"the /run/mosdns ACL is {spec!r}, with no group rwx")
        if not re.search(r"(^|[\s,])d(?:efault)?:g::rwx($|[\s,])", spec):
            findings.append(
                f"the /run/mosdns ACL is {spec!r} and carries no DEFAULT group entry, so a file "
                "one identity creates is not group-writable for the other"
            )
    reaped = {entry[1] for entry in entries if entry[0] in ("r", "R")}
    for directory in ("/run/mosdns", "/var/lib/mosdns/runtime", "/etc/mosdns"):
        for suffix in ("*.tmp", ".*.tmp", "*.bak", ".*.bak"):
            if directory + "/" + suffix not in reaped:
                findings.append(
                    f"{directory}/{suffix} is never reaped. The dotted form is the one that does "
                    "the work: every publisher in this project names its temporary files with a "
                    "leading dot, and a * does not match one -- measured on the system-level test "
                    "machine, where the undotted pattern alone reaped nothing this project "
                    "produces"
                )
    for pattern in STAGED_WITHOUT_A_SUFFIX:
        if pattern not in reaped:
            findings.append(
                f"{pattern} is never reaped. internal/candidate is a FOURTH producer and the only "
                "one whose staged file has neither a leading dot nor a .tmp suffix: "
                "os.CreateTemp(directory, filepath.Base(path)+\".*\") leaves "
                "cloudflare-prefixes.txt.1234567 and cloudflare-ips.json.1234567 in "
                "/var/lib/mosdns/lists, so neither *.tmp nor .*.tmp matches them and a publication "
                "that dies between the staging and the rename leaves a file nothing manages"
            )
    for kind, path, _fields in entries:
        if kind in ("r", "R") and not path.startswith(
            ("/var/lib/mosdns/", "/etc/mosdns/", "/run/mosdns/")
        ):
            findings.append(
                f"the entry reaps {path}, which is not a directory this package writes"
            )
    return findings


# --- the provisioning order --------------------------------------------------


def identities_from(text):
    """The four identity names, read out of the shipped ``postinst``.

    Returned rather than written as constants here on purpose. A test that restates
    the names it is checking holds a second copy of a decision, and the two copies
    drift: the script is renamed for a reason and the constant is not, and the case
    then either fails for no reason or -- worse -- passes because both still say
    ``mosdns`` while the shipped script says something else and the units agree with
    the script. Reading them means this suite cannot be wrong about what the package
    calls its own accounts.
    """
    variables = shell_assignments(text)
    missing = [name for name in ("STATE_GROUP", "ROUTER_USER", "CONTROL_USER", "RESOLVER_USER") if name not in variables]
    if missing:
        raise AssertionError(f"postinst does not assign {missing}, so its identities cannot be read")
    return {
        "group": variables["STATE_GROUP"],
        "router": variables["ROUTER_USER"],
        "control": variables["CONTROL_USER"],
        "resolver": variables["RESOLVER_USER"],
    }


def source_identities():
    """The identity names, read from the ``postinst`` in this checkout.

    For the readers and helpers that take one document and are called before any
    staging root exists. The class-based cases read the STAGED copy instead, because
    the staged copy is what ships and a case about the package should read the
    package; both come from the same file, so a name that differs between them is a
    build that shipped something other than this checkout.
    """
    return identities_from((REPO / "packaging/debian/postinst").read_text(encoding="utf-8"))



def provisioning_steps(text):
    """What ``postinst`` provisions, in the order it does it.

    Returned as ``(what, path)`` pairs where ``what`` is one of ``group``,
    ``user``, ``directory`` or ``default-acl``. The order is load-bearing and this
    is the only thing that can see it: the mode has to be written before the ACL,
    because ``install -d -m 2770`` sets the group-class mask, and a setfacl that
    ran first would be narrowed by it. That is how a directory ends up passing
    every default-ACL check while neither service identity can write it.
    """
    variables = shell_assignments(text)
    names = identities_from(text)
    steps = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        # One expansion, and it is a single command: `expand_shell` returns a
        # string, and iterating a string one character at a time matches nothing.
        command = expand_shell(line, variables)
        # Matched against the name the script uses, not against a word-boundary
        # search for `mosdns`: the renamed identities all CONTAIN `mosdns`, and
        # `-` is a word boundary, so a reader written that way reported three
        # accounts named `mosdns` for a script that creates `mosdns-router*`.
        if re.search(r"\b(addgroup|groupadd)\b", command) and re.search(rf"(?<![\w-]){re.escape(names['group'])}(?![\w-])", command):
            steps.append(("group", names["group"]))
        if re.search(r"\b(adduser|useradd)\b", command) and re.search(rf"(?<![\w-]){re.escape(names['router'])}(?![\w-])", command):
            steps.append(("user", names["router"]))
        if re.search(r"\binstall\s+-d\b", command):
            for directory in STATE_DIRECTORIES:
                if re.search(r"(^|[\s/'\"])" + re.escape(directory) + r"([\s'\"]|$)", command):
                    steps.append(("directory", directory))
        if "setfacl" in command:
            # The same lookaround as the create above, and for the same reason:
            # `/var/lib/mosdns` is a PREFIX of `/var/lib/mosdns/runtime`, so a plain
            # substring test says the setfacl of the runtime directory also applies to
            # the state directory, and the order this reader reports is then a story
            # about four directories that are really two.
            for directory in STATE_DIRECTORIES:
                if re.search(
                    r"(?<![\w/.-])" + re.escape(directory) + r"(?![\w/.-])", command,
                ):
                    steps.append(("default-acl", directory))
    return steps


def shell_assignments(text):
    """The `NAME=literal` assignments at the top of a shell script.

    A maintainer script names its paths in variables rather than repeating them, so a
    reader that only looks for literals would find neither the group nor the
    directories -- and would report a correct script as provisioning nothing.
    """
    variables = {}
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line.strip())
        if match is None:
            continue
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        variables[match.group(1)] = value
    return variables


def expand_shell(line, variables):
    """One shell line with its `$NAME` references replaced by their assigned values."""
    def replace(match):
        name = match.group(1)
        return variables[name] if name in variables else match.group(0)

    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", replace, line)


# The three things postinst must do in this order, and the reader that sees it.
# The transaction is the last of them because the two provisioning steps are its
# prerequisites, and the timer enable is after it because a refusal must leave
# nothing enabled: a nightly `mosdns-cdnctl test --apply` running against a machine
# whose install was refused is this project's optimizer publishing into state
# directories nobody enabled it to publish into.
POSTINST_STEPS = (
    "state-directories",
    "install-transaction",
    "enable-timers",
)



# The three identities and the group they share, named once from the shipped
# script so that no case below carries a second copy of the decision ruling
# 191(d) made. Here rather than beside identities_from, because reading the
# script is a CALL and this module executes top to bottom: a constant defined
# before shell_assignments exists raises NameError at import, which turns a
# helper placed for readability into a suite that does not load at all.
# so that no case below carries a second copy of the decision ruling 191(d) made.
_IDENTITY_NAMES = source_identities()
STATE_GROUP_NAME = _IDENTITY_NAMES["group"]
ROUTER_USER_NAME = _IDENTITY_NAMES["router"]
CONTROL_USER_NAME = _IDENTITY_NAMES["control"]
RESOLVER_USER_NAME = _IDENTITY_NAMES["resolver"]

def postinst_steps(text):
    """Where postinst performs each of the three steps, in script order.

    Returned as ``(step, index)`` over the script's lines, so a caller can ask which
    of two came first without either of them being reported twice.
    """
    positions = {}
    for number, line in enumerate(text.splitlines()):
        if line.lstrip().startswith("#"):
            continue
        if "setfacl -d -m g::rwx" in line and "state-directories" not in positions:
            positions["state-directories"] = number
        if '"$INSTALLER" install' in line and "install-transaction" not in positions:
            positions["install-transaction"] = number
        if "systemctl enable" in line and "enable-timers" not in positions:
            positions["enable-timers"] = number
    return positions


def timer_position_findings(text):
    """Every way postinst could leave an enabled timer behind a refused install.

    The claim the script makes in its failure arm is "nothing is enabled and running",
    and it is only true if nothing was enabled before the transaction. So the enable
    has to come after a transaction that returned zero, and the arm that prints the
    claim has to contain no enable of its own.
    """
    findings = []
    positions = postinst_steps(text)
    for step in POSTINST_STEPS:
        if step not in positions:
            findings.append(f"postinst never performs {step}")
    transaction = positions.get("install-transaction")
    timers = positions.get("enable-timers")
    if transaction is not None and timers is not None and timers < transaction:
        findings.append(
            "postinst enables the timers BEFORE the install transaction, so a refused "
            "install leaves three enabled root timers behind while the failure message "
            "says nothing is enabled"
        )
    # The failure arm: everything between the `if` that guards the transaction and
    # the `fi` that closes it. An enable in there is the same defect with an extra
    # step of indirection. The closing `fi` has to be the one at COLUMN ZERO, and
    # matching an indented one is a reader that cannot tell a nested `if` from the
    # `if` it is nested in -- which the arm for the installer's status 3 now is,
    # because that arm asks `[ -n "${2:-}" ]` of the upgrade argument.
    lines = text.splitlines()
    start = next(
        (number for number, line in enumerate(lines) if '"$INSTALLER" install' in line), None
    )
    if start is not None:
        closing = next(
            (
                number
                for number in range(start + 1, len(lines))
                if lines[number].rstrip() == "fi"
            ),
            None,
        )
        if closing is not None:
            failure_arm = "\n".join(lines[start:closing + 1])
            if "systemctl enable" in failure_arm:
                findings.append(
                    "the install transaction's failure arm enables the timers, so the "
                    "refusal arm both leaves them enabled and claims nothing is"
                )
    return findings


def order_findings(text):
    """Every way the provisioning in ``text`` can be wrong: the order AND the commands.

    The order alone is not enough to read, because the order is a property of two
    commands and either command can be right about its place in the script and
    wrong about what it says. ``-m 2750`` is the mode this plan itself first named
    and it is the one that leaves a directory neither service identity can write,
    so the exact mode is read here and not merely the fact that a mode is set.
    """
    findings = []
    steps = provisioning_steps(text)
    for path in STATE_DIRECTORIES:
        if ("directory", path) not in steps:
            findings.append(f"{path} is never created")
        if ("default-acl", path) not in steps:
            findings.append(f"{path} is created with no default ACL for the service group")
        created = next((i for i, s in enumerate(steps) if s == ("directory", path)), None)
        acl = next((i for i, s in enumerate(steps) if s == ("default-acl", path)), None)
        if created is not None and acl is not None and acl < created:
            findings.append(
                f"the default ACL on {path} is set before its mode, so install's chmod narrows "
                "the mask the ACL created"
            )
        # Not `\b` around the path: a `/` is not a word character, so there is no
        # boundary between the space in front of a path and the path itself, and a
        # `\b` there never matches. The lookarounds are what say "this argument, and
        # not the longer path that starts with it".
        # The group is matched by NAME from the script's own variables, because the
        # shipped line is `install -d -o root -g "$STATE_GROUP" -m 2770` -- the
        # literal `mosdns` never appears in it, and a reader written against the old
        # spelling found nothing in a postinst that provisions four directories
        # correctly.
        names = identities_from(text)
        expected = (
            r"install\s+-d[^\n]*-o\s+root[^\n]*-g\s+"
            r"(?:\"\$STATE_GROUP\"|" + re.escape(names["group"]) + r")"
            r"[^\n]*-m\s+2770[^\n]*" +
            r"(?<![\w/.-])" + re.escape(path) + r"(?![\w/.-])"
        )
        if not re.search(expected, text):
            findings.append(
                f"{path} is not created with `install -d -o root -g {names['group']} "
                "-m 2770`; the mode is 2770 and not 2750, because 2750 caps the group at "
                "r-x and a default ACL cannot restore what the mask removed"
            )
        if not re.search(
            r"setfacl\s+-d\s+-m\s+g::rwx[^\n]*(?<![\w/.-])" + re.escape(path) + r"(?![\w/.-])",
            text,
        ):
            findings.append(
                f"{path} is not given `setfacl -d -m g::rwx`, the default ACL the two service "
                "identities share"
            )
    group = next((i for i, s in enumerate(steps) if s == ("group", STATE_GROUP_NAME)), None)
    if group is None:
        findings.append("the shared service group is never created")
    for kind in ("directory", "user"):
        first = next((i for i, s in enumerate(steps) if s == (kind, ROUTER_USER_NAME)), None)
        if group is not None and first is not None and first < group:
            findings.append(f"the {kind} mosdns is created before the group it belongs to")
    for path in STATE_DIRECTORIES:
        created = next((i for i, s in enumerate(steps) if s == ("directory", path)), None)
        if group is not None and created is not None and created < group:
            findings.append(f"{path} is created before the group it is owned by")
    return findings


# --- the production render ---------------------------------------------------

# The render has to be for the INSTALLED layout: the policy path both documents
# carry is the one the command is given, so the shipped pair must name
# /etc/mosdns/policy.yaml rather than a build directory. A private view of the
# filesystem is what makes that path resolve without one byte being written to
# this host's /etc, and the build script and this test do it for the same reason.
RENDER_IN_PRIVATE_ROOT = r"""
set -eu
stage='%(stage)s'
mkdir -p "$stage/etc/mosdns"
cp '%(policy)s' "$stage/etc/mosdns/policy.yaml"
if ! command -v bwrap >/dev/null 2>&1; then
	echo "bwrap (the bubblewrap package) is required to render for the installed layout:" >&2
	echo "it is what makes /etc/mosdns/policy.yaml resolve inside the render without" >&2
	echo "anything being written to this host's /etc" >&2
	exit 1
fi
exec bwrap --ro-bind / / --bind "$stage/etc" /etc --chdir / \
	'%(cdnctl)s' render --policy /etc/mosdns/policy.yaml --out /etc/mosdns
"""


def render_for_installed_layout(stage, policy, cdnctl):
    """Render the installed documents into ``stage`` and return the exit status."""
    script = RENDER_IN_PRIVATE_ROOT % {"stage": stage, "policy": policy, "cdnctl": cdnctl}
    # The renderer's own report is captured rather than printed: it is four lines of
    # `rendered-…-sha256:` per call, and a test run that scrolls it is a test run
    # whose failures are hard to find.
    return subprocess.run(
        ["sh", "-c", script], check=False, capture_output=True, text=True,
    ).returncode


# --- the shared build --------------------------------------------------------

_SHARED = {}
# A copy of a maintainer script, swapped in for the duration of a `with` block, so a
# control can run a test METHOD against a broken script rather than re-implementing
# what the method checks. Re-implementing is how a control passes while the method it
# is meant to hold is inverted: the control and the method were then two
# implementations, and only one of them was ever exercised.
@contextlib.contextmanager
def scripts_replaced(**replacements):
    """Swap the module's POSTINST / PRERM / POSTRM globals for the length of a block.

    In memory and nothing else: the files on disk are untouched, so a control cannot
    leave a broken maintainer script behind for the next run to read.

    The globals it rebinds are the ones `SCRIPTS` -- an `_Scripts`, not a dict -- 
    resolves, which are the ones the test METHODS read. That indirection is the whole
    reason the substitution can work at all, and it did not work at all in the
    previous version: `SCRIPTS` was a dict literal, so it held the three Path objects
    from import time, the methods iterated it, and a control that removed a verb from
    postrm still read the real file and watched the method PASS. A mechanism that
    cannot reach the code under test is worse than no mechanism, because a control
    written against it reports success while testing nothing.
    """
    unknown = sorted(set(replacements) - set(SCRIPT_GLOBALS))
    if unknown:
        raise AssertionError(
            f"scripts_replaced was asked for {unknown}, which are not maintainer scripts"
        )
    previous = {name: globals()[name.upper()] for name in replacements}
    try:
        for name, script in replacements.items():
            globals()[name.upper()] = _ScriptText(script)
        yield
    finally:
        for name, path in previous.items():
            globals()[name.upper()] = path


class _ScriptText:
    """A Path-shaped object whose read_text() returns a given string.

    The script readers take a path and call read_text on it. Rather than change their
    signatures for the sake of a test helper, the helper supplies the one method they
    use -- and nothing else, so a reader that grew a second file access would fail
    here rather than silently read the real one.
    """

    def __init__(self, text):
        self._text = text

    def read_text(self, encoding=None):
        return self._text

    def __str__(self):
        return "<a maintainer script held in memory>"


def scratch_directory(prefix):
    """A temporary directory that is REMOVED when this process ends.

    Every copy this module makes holds three compiled programs, so leaving them behind
    fills a small /tmp -- this one is a 1.7 GB tmpfs -- and a test that quietly eats
    the machine's scratch space is a test that breaks the next thing that wants it.
    The location is $TMPDIR, or MOSDNS_PACKAGE_TEST_TMPDIR for a host whose scratch
    is somewhere else.
    """
    directory = tempfile.mkdtemp(
        prefix=prefix, dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
    )
    atexit.register(shutil.rmtree, directory, True)
    return directory


def shared_staging():
    """The staging root, built once per process by the real build script.

    A build that fails is a failure and not a skip: the plan ruled that a package
    which cannot be built is a real problem, and a test that skipped would make
    the whole of this module's subject optional.
    """
    if "root" in _SHARED:
        return _SHARED["root"]
    directory = scratch_directory("mosdns-package-test.")
    _SHARED["directory"] = directory
    _SHARED["root"] = os.path.join(directory, "staging")
    result = subprocess.run(
        ["sh", str(BUILD_SCRIPT), "--stage", _SHARED["root"]],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        check=False,
    )
    _SHARED["status"] = result.returncode
    _SHARED["output"] = (result.stdout + result.stderr).strip()
    return _SHARED["root"]


def build_problem():
    """Why the shared staging root is unusable, or ``None`` when it is fine."""
    if "status" not in _SHARED:
        shared_staging()
    if _SHARED["status"] != 0:
        return f"scripts/build-deb.sh --stage exited {_SHARED['status']}:\n{_SHARED['output']}"
    return None


class _Staged(unittest.TestCase):
    """The staging root the real build produces, asked a question per test."""

    @classmethod
    def setUpClass(cls):
        cls.root = shared_staging()
        problem = build_problem()
        if problem is not None:
            raise AssertionError(problem)
        cls.inventory = staged_inventory(cls.root)

    def read(self, absolute):
        return (Path(self.root) / absolute.lstrip("/")).read_text(encoding="utf-8")

    def read_bytes(self, absolute):
        return (Path(self.root) / absolute.lstrip("/")).read_bytes()

    def entry(self, absolute):
        return inventory_get(self.inventory, absolute)

    def assertInstalledFile(self, absolute, mode=None):
        entry = self.entry(absolute)
        self.assertIsNotNone(entry, f"{absolute} is not installed at all")
        self.assertEqual(entry[1], "file", f"{absolute} is a {entry[1]}, not a regular file")
        self.assertGreater(entry[3], 0, f"{absolute} is empty")
        if mode is not None:
            self.assertEqual(entry[2], mode, f"{absolute} is {oct(entry[2])}, want {oct(mode)}")
        return entry


# --- the payload -------------------------------------------------------------


class PinnedRangeSnapshotTests(_Staged):
    """The range document this package ships, and the lock that accounts for it.

    These are the tests that make the offline install honest. Every other part of
    this step is machinery for publishing a file; these hold that the file is
    Cloudflare's, that nothing can change it unnoticed, and that it says how old
    it is -- because a selector classifying over somebody else's ranges resolves
    every query the machine makes and tells nobody.
    """

    # The IPv4 ranges Cloudflare published on the day the snapshot was taken.
    # Written out as literals, and not derived from the snapshot, because the
    # whole question is whether the shipped file holds Cloudflare's ranges and not
    # a plausible set of somebody else's: a test that computed its expectation
    # out of the file under test would agree with any file at all. These fifteen
    # were compared, one for one, with the list Cloudflare publishes separately at
    # https://www.cloudflare.com/ips-v4 -- the same ranges by a different route.
    PUBLISHED_RANGES = (
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
        "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
        "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    )
    # The prefix list those ranges render to: masked, deduplicated, ascending,
    # one per line. The form the rewriter reads and the form the lock's second
    # digest covers, so it is written out rather than rendered here -- a renderer
    # in this file would be a second implementation of the one under test and
    # would agree with it by construction.
    PUBLISHED_RANGES_TEXT = "".join(f"{prefix}\n" for prefix in PUBLISHED_RANGES)

    def snapshot_lock(self):
        return json.loads(self.read(RANGES_SNAPSHOT_LOCK))

    def test_the_shipped_snapshot_is_the_document_the_published_api_answers_with(self):
        """Byte for byte, in the shape this project's own reader accepts.

        A snapshot in any other shape is a file the reader refuses, so a snapshot
        in one of them would be a package whose install cannot complete offline --
        which is the one state this whole step exists to end. So the shape is
        asserted here rather than discovered by an install failing.
        """
        document = json.loads(self.read(RANGES_SNAPSHOT))
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(
            document["url"], "https://api.cloudflare.com/client/v4/ips",
            "the snapshot names an endpoint other than the one this project reads, so the reader "
            "would refuse it as a document of another endpoint",
        )
        self.assertTrue(document["etag"], "the snapshot records no validator, so there would be "
                                         "nothing to revalidate it against on the next run")
        body = document["body"]
        self.assertIs(body["success"], True)
        self.assertTrue(body["result"]["etag"], "the document records no revision marker")
        self.assertTrue(body["result"]["ipv6_cidrs"], "the document carries no IPv6 half, so it is "
                                                       "not the document the API publishes")

    def test_the_shipped_snapshot_holds_the_ranges_cloudflare_published(self):
        body = json.loads(self.read(RANGES_SNAPSHOT))["body"]
        self.assertEqual(
            sorted(set(body["result"]["ipv4_cidrs"])), list(self.PUBLISHED_RANGES),
            "the shipped snapshot does not hold Cloudflare's published IPv4 ranges, so a router "
            "that classified over it would be classifying over somebody else's space",
        )
        # And the shape a reader needs of each entry: a prefix, and one this
        # project will sample from. A range this project refuses to publish must
        # not be in a file it is going to publish.
        for entry in body["result"]["ipv4_cidrs"]:
            with self.subTest(entry=entry):
                self.assertRegex(entry, r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")

    def test_the_lock_accounts_for_both_artifacts_of_the_snapshot(self):
        # Two digests, and the reason is the two files: `sha256` is the snapshot
        # this package carries and `prefix_list_sha256` is the plain prefix list
        # that document renders to, which is the file the response rewriter reads
        # and the only one a router ever sees. A lock that recorded only the first
        # would account for a document and say nothing about the selector.
        lock = self.snapshot_lock()
        self.assertEqual(
            hashlib.sha256(self.read_bytes(RANGES_SNAPSHOT)).hexdigest(), lock["sha256"],
            "the shipped snapshot is not the bytes its lock records, so this package cannot account "
            "for the ranges in it",
        )
        self.assertEqual(
            hashlib.sha256(self.PUBLISHED_RANGES_TEXT.encode("utf-8")).hexdigest(),
            lock["prefix_list_sha256"],
            "the shipped lock does not record the prefix list Cloudflare's published ranges render to",
        )

    def test_the_lock_dates_the_pin_because_an_unmeasured_stale_pin_is_a_silent_one(self):
        # A three-month-old pin is a perfectly good input for a selector. A pin
        # whose age is written down nowhere is not, and there is no way to notice
        # the difference later: the machine resolves, the timer reports nothing,
        # and the ranges drift away from Cloudflare's one prefix at a time. So the
        # date is required, and it is a date this project can check the shape of.
        lock = self.snapshot_lock()
        pinned_at = lock.get("fetched_at", "")
        self.assertRegex(
            pinned_at, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
            f"the shipped lock's fetched_at is {pinned_at!r}, which is not an RFC 3339 UTC time, so "
            "nothing can measure the age of this pin",
        )
        self.assertEqual(lock.get("source"), "https://api.cloudflare.com/client/v4/ips")
        self.assertEqual(lock.get("revision"), json.loads(self.read(RANGES_SNAPSHOT))["body"]["result"]["etag"])
        self.assertEqual(lock.get("schema_version"), 1)

    def test_the_manifest_names_the_pinned_ranges_beside_the_pinned_list(self):
        # The manifest is where an operator looks to find out what a .deb was
        # built from. A pin it does not mention is a pin nobody can check against
        # the archive they were given.
        text = self.read(BUILD_MANIFEST)
        self.assertIn(hashlib.sha256(self.read_bytes(RANGES_SNAPSHOT)).hexdigest(), text)

    def test_the_pair_is_not_a_conffile_and_what_that_costs_is_written_down(self):
        """A hand-re-pinned pair is reverted by the next upgrade, silently.

        The pair is under `/usr/share`, beside the China list, and it is
        **deliberately not a conffile** -- the same position postinst's own
        message takes ("It is read here and never written") and the same one the
        China pair takes. The consequence is that `dpkg` replaces both files with
        the new package's on every upgrade, without asking: a hand-re-pinned
        snapshot survives exactly until the next upgrade and then the machine is
        back on the ranges the new package was built with, with nothing having
        said so.

        That is the right behaviour -- a conffile here would mean two files
        nobody edited differ from the package, and `postinst` verifies the pair
        against a lock `dpkg` also replaced, so a half-re-pinned pair would be
        refused rather than installed. But an operator who re-pins by hand has to
        be told, and the two places they would look are the manual and the
        `conffiles` file itself. Asserted as text because the failure is a
        sentence, and a sentence can only be held as one.
        """
        listed = [
            line.strip()
            for line in (REPO / "packaging" / "debian" / "conffiles").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]
        for path in (RANGES_SNAPSHOT, RANGES_SNAPSHOT_LOCK):
            self.assertNotIn(
                path, listed,
                f"{path} is a conffile, so an upgrade would ask before replacing it and a hand-made "
                f"pin would survive -- and a pair that survives an upgrade is a pair the package can "
                f"no longer account for, because postinst verifies it against a lock dpkg replaced",
            )
        manual = shipped_prose(REPO / "packaging" / "man" / "mosdns-cdnctl.1")
        self.assertIn(
            "without asking", manual,
            "mosdns-cdnctl(1) does not say that a hand-re-pinned pair is reverted by the next "
            "upgrade, and the manual is where an operator who re-pinned would look",
        )
        self.assertIn("conffile", manual)
        conffiles = (REPO / "packaging" / "debian" / "conffiles").read_text(encoding="utf-8")
        self.assertIn(
            "cloudflare-ranges", conffiles,
            "packaging/debian/conffiles does not mention the range pair at all, so the next reader "
            "sees seven conffiles, no range pair, and no reason -- and adds it",
        )
        # Lower-cased for the prose assertion, because this is a comment in a
        # Debian control file rather than roff: it shouts the consequence, and
        # the words are the words.
        self.assertIn("without asking", conffiles.lower())

    def test_the_manual_documents_every_verb_the_tool_implements(self):
        """A verb that exists and is not in the SYNOPSIS is a verb nobody can find.

        The gap this exists for is measured. `apply` and `status` were both fully
        implemented and neither appeared in the SYNOPSIS or the DESCRIPTION; the
        only mention of `status` anywhere in shipped documentation was one example
        line inside a conffile, for the ECH state rather than the selector. An
        operator reading this manual could not have discovered that
        `mosdns-cdnctl status --selector` is the supported way to see which
        preferred address is in service.

        **Read the SYNOPSIS, and read it as a reader would.** The verb list is cut
        out of the roff between `.SH SYNOPSIS` and `.SH DESCRIPTION` and the
        macro noise is stripped, rather than the verbs being restated as constants
        here: a test that holds its own copy of a list is a second thing that can
        disagree with the manual, and this project has shipped that defect
        repeatedly.
        """
        manual = shipped_prose(REPO / "packaging" / "man" / "mosdns-cdnctl.1")
        # **The raw roff, not `shipped_prose`.** That helper exists because a
        # sentence has to be read as a sentence, and it does its job by JOINING
        # every line of the document into one string -- which destroys the one
        # thing this case is about. A SYNOPSIS is a list: the verb is on its own
        # line and the flags are on the next, and `(?m)^\s*verb\b` is exactly the
        # assertion that reads that shape. The first version ran it over the
        # flattened prose and reported all ten verbs missing from a SYNOPSIS that
        # lists all ten, which is the third time in this project that a gate
        # failed for reading a document in a shape the document does not have.
        raw = (REPO / "packaging" / "man" / "mosdns-cdnctl.1").read_text(encoding="utf-8")
        section = re.search(r"^\.SH SYNOPSIS$(.*?)^\.SH DESCRIPTION$", raw, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(
            section, "mosdns-cdnctl(1) has no SYNOPSIS section, so there is nowhere a reader "
            "would look to find out what this tool can do",
        )
        synopsis = section.group(1)
        # The macro prefix is part of the line, and a SYNOPSIS line is `.I render`
        # rather than `render` -- so the assertion allows an optional macro before
        # the verb. Removing the macro NAME is what `shipped_prose` does elsewhere,
        # and doing it here too is what keeps the two readers agreeing about the
        # same file.
        prologue = r"(?:\.[A-Za-z]+(?:\([^)]*\))?\s*)*"
        # **The hyphen is optional-backslash-or-nothing, and it has to be.** roff
        # writes a hyphen as `\-` so it cannot be read as a hyphen-minus option, so
        # the SYNOPSIS says `update\-lists` while the dispatch table says
        # `update-lists` and `re.escape` reduces the Go side to a bare `-`. The
        # first version matched the three hyphenated verbs against the literal and
        # reported them missing from a SYNOPSIS that lists them. `\\?` is a regex
        # for an optional literal backslash, which is exactly what is between the
        # two spellings.
        def as_roff(verb):
            return r"\\?-".join(re.escape(part) for part in verb.split("-"))
        # The tool's own dispatch table, so the expectation is the code rather than
        # a list written beside it. **`case` arms of the TOP-LEVEL dispatch only**,
        # and that is a real narrowing rather than a convenience: the first version
        # took every `case "…":` in the file and picked up `dhcp` and `ech`, which
        # are the `--dhcp` and `--ech` FLAGS of `status` and not verbs at all. A
        # gate that cannot tell a verb from a flag reports a manual for documenting
        # commands that do not exist.
        dispatch = (REPO / "cmd" / "mosdns-cdnctl" / "main.go").read_text(encoding="utf-8")
        table = re.search(r"switch args\[0\] \{(.*?)\n\t\}", dispatch, re.DOTALL)
        self.assertIsNotNone(
            table, "the top-level verb dispatch was not found in main.go, so this case cannot "
            "know what the tool implements"
        )
        implemented = sorted(set(re.findall(r'case "([a-z][a-z-]*)":', table.group(1))))
        self.assertTrue(implemented, "no verb was read out of the tool's own dispatch table")
        for verb in implemented:
            with self.subTest(verb=verb):
                self.assertRegex(
                    synopsis, rf"(?m)^\s*{prologue}{as_roff(verb)}\b",
                    f"mosdns-cdnctl implements `{verb}` and the SYNOPSIS does not list it, so "
                    "the one place a reader looks for what this tool can do does not mention it",
                )
        # `status` needs a flag, and the SYNOPSIS cannot say that with an
        # alternation. A reader who typed the bare verb gets a refusal, so the
        # refusal has to be in the manual rather than being the first thing the
        # tool says to them.
        self.assertIn(
            "at least one path is required", manual,
            "the SYNOPSIS shows `status` with an alternation of flags and the manual never says "
            "one is required, so the first thing `mosdns-cdnctl status` says to an operator who "
            "read the manual is a usage refusal",
        )

    def test_the_manual_documents_the_state_documents_an_operator_has_to_read(self):
        """The published state is invisible in the manual, and one of the four is the
        whole point of the feature.

        `cdn-selector.json` holds the preferred address in service. It was in
        neither manual's FILES section, along with `health.json` and
        `bandwidth-budget.json`, so the only way to find out what the router was
        using was to read the source.

        **The paths come from the code**, not from constants here, for the reason
        the rest of this file keeps giving: two files spelling one path is how they
        drift. Each default is read out of the module that owns it and then required
        to be in the manual's FILES section, which also means renaming a state file
        fails this case instead of quietly leaving the documentation behind.
        """
        manual = shipped_prose(REPO / "packaging" / "man" / "mosdns-cdnctl.1")
        for variable, source, description in (
            ("DefaultSelectorPath", REPO / "internal" / "optimizer" / "runner.go", "the preferred address in service"),
            ("DefaultHealthPath", REPO / "internal" / "health" / "checker.go", "the health verdict"),
            ("DefaultBudgetPath", REPO / "internal" / "optimizer" / "budget.go", "the day's bandwidth spend"),
        ):
            with self.subTest(constant=variable):
                match = re.search(
                    rf'{variable}\s*=\s*"([^"]+)"', source.read_text(encoding="utf-8")
                )
                self.assertIsNotNone(
                    match, f"{variable} was not found in {source.name}, so this case cannot name the path"
                )
                self.assertIn(
                    match.group(1), manual,
                    f"{description} lives at {match.group(1)} and the manual's FILES section does "
                    "not list it, so an operator cannot find the file the feature exists to write",
                )

    def test_the_manual_states_the_outcomes_an_operator_cannot_infer_from_a_success(self):
        """A run that reports success and changed nothing is the worst kind, and it
        has to be documented rather than discovered.

        Three cases, and all three are silent on the exit status a timer records:

          * **the daily bandwidth budget ran out.** The shipped numbers make one
            hand-run `test` exhaust the day, and the run then keeps every mapping
            and exits 0. An operator who ran `test --apply` to fix something sees
            `applied: <address>` and concludes their change took effect.
          * **the proof window closed.** If the health timer is stopped the rewrite
            stops about five minutes later, with nothing anywhere saying so. DNS
            keeps working, which is what makes it hard to notice.
          * **`pin` refuses the nightly.** A pinned selector exits 3, which the
            unit's `SuccessExitStatus=4` does not excuse, so a correctly pinned
            router shows a failing timer forever.

        Asserted as prose because that is what it takes: each of these is a sentence
        an operator has to be able to find, and none of them is a code path a
        substring over the source can check.
        """
        manual = shipped_prose(REPO / "packaging" / "man" / "mosdns-cdnctl.1")
        # Lower-cased, because `shipped_prose` lower-cases: it is a reader of
        # sentences, and roff has no case to preserve a proper noun with. An
        # assertion written against the raw casing would fail on a manual that
        # says the thing in the sentence rather than in a variable name, which is
        # the wrong way round for a documentation gate.
        lowered = manual.lower()
        for phrase, because in (
            ("budget-exhausted", "the budget running out looks exactly like a successful run"),
            ("winner_proof_until", "an address published but not used has to be distinguishable from one in service"),
            ("successexitstatus", "a pinned router's nightly exits 3 forever and that is the pin working"),
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(
                    phrase, lowered,
                    f"mosdns-cdnctl(1) does not mention {phrase!r}, so an operator meets "
                    f"{because} with nothing written down to explain it",
                )

    def test_the_manual_documents_the_selector_modes_and_how_to_stop_the_feature(self):
        """Three ways to stop it, none of them equivalent, and all three were absent.

        The selector has three modes -- `auto`, `manual`, `disabled` -- and the
        manual named none of them. `disabled` in particular is reachable only by
        hand-editing the state file, because nothing in the project writes it, which
        makes it both the most complete way to stop rewriting and the one an
        operator has no way to guess.

        The modes are read out of the validator rather than restated, so a fourth
        mode fails this case.
        """
        manual = shipped_prose(REPO / "packaging" / "man" / "mosdns-cdnctl.1")
        modes = re.findall(
            r'"(auto|manual|disabled)"',
            (REPO / "internal" / "state" / "types.go").read_text(encoding="utf-8"),
        )
        self.assertTrue(modes, "no selector mode was read out of the validator")
        for mode in sorted(set(modes)):
            with self.subTest(mode=mode):
                # **In the same sentence as `mode:`, not as a bare word.** `manual`
                # and `auto` are ordinary English and occur all over a manual that
                # says "runs this by hand" and "the watchdog's default is on" -- a
                # bare substring would pass on a manual naming neither mode, which
                # is the state this case exists to catch. The window is generous
                # because `shipped_prose` joins roff arguments with `", "`, so an
                # enumeration of three modes never lands as three adjacent words.
                self.assertRegex(
                    manual,
                    rf"mode:[^.]{{0,60}}\b{re.escape(mode)}\b"
                    rf"|\b{re.escape(mode)}\b[^.]{{0,60}}mode:",
                    f"the selector accepts `mode: {mode}` and the manual never names it as one of "
                    "the three, so an operator reading the manual cannot tell what state their "
                    "router is in",
                )
        self.assertIn(
            "mosdns-cdn-optimizer.timer", manual,
            "the manual does not say how to stop the optimizer being scheduled, which is the "
            "first thing an operator who wants their address left alone would try",
        )

    def test_the_router_manual_documents_the_network_cases_an_operator_will_hit(self):
        """Three cases the manual was silent on, and they are the three that happen.

        The DHCP bridge handles all three correctly and none of them was written
        down anywhere:

          * **a statically configured resolver.** A connection with
            `ipv4.method manual` has no lease, so the resolvers come from the
            device's effective DNS rather than from `domain_name_servers`. An
            operator who configured their own resolver had no way to learn that it
            works, or that `dns-change` is the event that tells the router their
            list moved.
          * **unplugging the cable.** `down` publishes an EMPTY upstream list by
            design, so the domestic branch fails closed until an `up` or
            `dhcp4-change` arrives. That is deliberate rather than a bug, it is
            the opposite of what "the network went away" intuitively means, and it
            is the one behaviour of this package an operator is most likely to
            report as a defect.
          * **`dhcp.failure_policy`.** The knob that decides between failing closed
            and keeping the last resolvers, in a policy file the manual otherwise
            tells the operator to edit.

        The event names are read out of the bridge rather than restated, so a
        renamed action fails this case instead of leaving the manual describing a
        machine that does not exist.
        """
        manual = shipped_prose(REPO / "packaging" / "man" / "mosdns-router.8")
        lowered = manual.lower()
        for phrase, because in (
            ("ipv4.method manual", "an operator with a hand-configured resolver cannot tell "
                                   "that it is used, or which event reports a change to it"),
            ("dns-change", "the event a static-IP machine actually produces was named nowhere"),
            ("empty list", "unplugging the cable fails the domestic branch closed by design, and "
                           "that reads exactly like a defect when nobody has said so"),
            ("dhcp.failure_policy", "the knob that decides between failing closed and keeping the "
                                    "last resolvers was undocumented"),
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(
                    phrase, lowered,
                    f"mosdns-router(8) does not mention {phrase!r}, so an operator meets "
                    f"{because}",
                )
        # And the two policies the bridge actually implements, read from its own
        # source rather than from a list here: a manual that names one of them and
        # not the other describes a machine with half a choice.
        plugin = (REPO / "plugin" / "executable" / "dhcp_forward" / "dhcp_forward.go").read_text(
            encoding="utf-8"
        )
        policies = sorted(set(re.findall(r'failurePolicy\w+\s*=\s*"([a-z-]+)"', plugin)))
        self.assertTrue(policies, "no dhcp failure policy was read out of the plugin's own constants")
        for policy in policies:
            with self.subTest(policy=policy):
                self.assertIn(
                    policy, lowered,
                    f"the plugin implements `{policy}` and the manual never names it, so the "
                    "documented way to choose is not a way this build has",
                )


# --- the payload -------------------------------------------------------------


class PayloadTests(_Staged):
    """What the package puts on a machine, and at what mode."""

    def test_every_path_the_units_exec_is_installed_at_that_path(self):
        """A unit naming a path the package does not install is a failed unit."""
        wanted = unit_exec_paths(self.root)
        self.assertTrue(wanted, "no ExecStart path was read out of the shipped units")
        for executable, units in sorted(wanted.items()):
            with self.subTest(executable=executable):
                self.assertIsNotNone(
                    self.entry(executable),
                    f"{', '.join(units)} runs {executable}, which the package does not install",
                )
                self.assertInstalledFile(executable, 0o755)

    def test_the_three_binaries_are_exactly_the_three_this_project_ships(self):
        executables = {
            path for path, kind, _mode, _size in self.inventory
            if kind == "file" and path.startswith(BINARY_DIRECTORY + "/")
        }
        for binary in COMPILED + (INSTALLER_SCRIPT,):
            with self.subTest(binary=binary):
                self.assertIn(binary, executables)
        for path in sorted(executables - set(COMPILED) - {INSTALLER_SCRIPT}):
            if path.startswith(BRIDGE_PACKAGE + "/"):
                self.assertTrue(path.endswith(".py"), f"{path} is not an importable module")
                continue
            self.fail(f"{path} is in the binary directory and nothing decided on it")

    def test_the_package_installs_nothing_outside_the_prefixes_it_may_write(self):
        """The whole of "installs nothing it should not" is this list, read as it
        is: a path the package may write, or a directory on the way to one."""
        allowed = {
            path for path, _kind, _mode, _size in self.inventory
            if path.startswith(ALLOWED_PREFIXES) or path in GENERATED
        }
        for path, kind, _mode, _size in self.inventory:
            if path.startswith(DEBIAN):
                continue  # metadata, not payload: dpkg never unpacks it
            if path in allowed or is_ancestor_of_any(path, allowed):
                continue
            self.fail(
                f"{path} is a {kind} outside every prefix the package may write, and it is "
                "not a directory on the way to one that is"
            )

    def test_the_file_list_manifest_and_the_staged_tree_are_the_same_set(self):
        """The manifest is the package's own list of itself, so it has to be true in
        both directions: a listed path that is not there, and a staged file that is
        neither listed, generated, nor on the way to something that is."""
        listed = {destination for _source, destination in manifest_entries(MANIFEST.read_text())}
        known = listed | GENERATED
        staged = {
            path for path, _kind, _mode, _size in self.inventory if not path.startswith(DEBIAN)
        }
        for path in sorted(staged - known):
            if is_ancestor_of_any(path, known):
                continue
            self.fail(f"{path} is in the package but in neither the manifest nor the generated set")
        for path in sorted(listed - staged):
            self.fail(f"the manifest lists {path}, which the package does not contain")

    def test_the_manifest_names_every_source_that_exists_in_this_repository(self):
        for source, destination in manifest_entries(MANIFEST.read_text()):
            if source == "-":
                self.assertTrue(
                    destination.startswith("/"),
                    f"{destination!r} is a directory entry and must be an installed path",
                )
                continue
            with self.subTest(source=source):
                self.assertTrue(
                    (REPO / source).exists(), f"the manifest names {source}, which does not exist"
                )
                self.assertTrue(destination.startswith("/"), f"{destination!r} is not installed under /")

    def test_no_state_file_is_shipped_under_var_lib(self):
        """`/var/lib` holds generated state, and a package that ships state there
        is a package whose upgrade overwrites the operator's data."""
        for path, kind, _mode, _size in self.inventory:
            if path.startswith("/var/lib") and kind != "directory":
                self.fail(f"{path} is a {kind} under /var/lib: a shipped state file")
        for directory in PACKAGED_STATE_DIRECTORIES:
            with self.subTest(directory=directory):
                self.assertIsNotNone(
                    self.entry(directory), f"{directory} is not shipped as an empty directory"
                )
                self.assertEqual(self.entry(directory)[1], "directory")

    def test_nothing_is_shipped_under_run(self):
        """`/run` is a tmpfs, so a file shipped there is gone at the next reboot
        and the package would be relying on a boot-time side effect."""
        for path, _kind, _mode, _size in self.inventory:
            self.assertFalse(path.startswith("/run"), f"{path} is shipped under /run")

    def test_nothing_shipped_is_group_or_world_writable(self):
        for path, kind, mode, _size in self.inventory:
            if kind != "file":
                continue
            self.assertEqual(
                mode & 0o022, 0,
                f"{path} is {oct(mode)}: a file under /etc, /usr or the binary directory has no "
                "business being group- or world-writable",
            )

    def test_every_file_is_installed_with_the_mode_its_identity_needs(self):
        findings = mode_findings(self.inventory, MODES)
        self.assertEqual(
            findings, [],
            "a shipped file has the wrong mode, or is absent:\n" + "\n".join(findings),
        )

    def test_every_unit_file_is_installed_and_keeps_its_trailing_newline(self):
        for name in SHIPPED_UNITS:
            with self.subTest(unit=name):
                self.assertInstalledFile(UNIT_DIRECTORY + "/" + name, 0o644)
                self.assertTrue(
                    self.read(UNIT_DIRECTORY + "/" + name).endswith("\n"),
                    f"{name} does not end with a newline, so the last directive is not one",
                )


# --- the shipped documents ---------------------------------------------------


class ShippedDocumentTests(_Staged):
    """The documents, and the claim that they are what this project reviewed."""

    def test_the_two_routing_documents_are_a_fresh_production_render(self):
        """Byte equality against a render run now, from the policy the package
        installs, for the installed layout.

        A document that differs in a comment is a document the project can no
        longer explain, and comparing a rendering of the shipped policy against
        itself would prove only that the build is deterministic.
        """
        with tempfile.TemporaryDirectory(
            prefix="mosdns-render-check.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            status = render_for_installed_layout(
                scratch,
                # The policy the package INSTALLS and the control tool the package
                # INSTALLS: a render from different inputs is a different render.
                Path(self.root) / CONFIG_DIRECTORY.lstrip("/") / "policy.yaml",
                Path(self.root) / CDNCTL_BINARY.lstrip("/"),
            )
            self.assertEqual(status, 0, f"a production render exited {status}")
            for document in ROUTING_DOCUMENTS:
                with self.subTest(document=document):
                    fresh = Path(scratch) / "etc" / "mosdns" / Path(document).name
                    self.assertTrue(fresh.is_file(), f"the render published no {fresh.name}")
                    self.assertEqual(
                        self.read(document),
                        fresh.read_text(encoding="utf-8"),
                        f"{document} is not a fresh production render",
                    )

    def test_the_shipped_documents_are_the_ones_this_repository_reviewed(self):
        for document, committed in (
            (CONFIG_DIRECTORY + "/mosdns.yaml", "configs/mosdns.yaml"),
            (CONFIG_DIRECTORY + "/dnscrypt-proxy.toml", "configs/dnscrypt-proxy.toml"),
            (CONFIG_DIRECTORY + "/policy.yaml", "configs/policy.yaml"),
            (CHINA_LIST, "configs/cn-domains.txt"),
            (SOURCE_LOCK, "configs/source-lock.json"),
        ):
            with self.subTest(document=document):
                self.assertEqual(
                    self.read_bytes(document),
                    (REPO / committed).read_bytes(),
                    f"{document} is not {committed}",
                )

    def test_every_conffile_is_a_conffile_and_nothing_else_under_etc_is(self):
        listed = [
            line.strip() for line in CONFFILES.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertEqual(sorted(listed), sorted(EDITABLE_DOCUMENTS))
        shipped = {
            path for path, kind, _mode, _size in self.inventory
            if kind == "file" and path.startswith("/etc/")
        }
        self.assertEqual(
            sorted(shipped - set(EDITABLE_DOCUMENTS)),
            [DISPATCHER_SCRIPT],
            "the only file under /etc that is not a conffile is the dispatcher hook, which the "
            "installer removes on uninstall rather than leaving for dpkg to prompt about",
        )
        staged = self.read(DEBIAN + "/conffiles")
        self.assertEqual(
            sorted(line.strip() for line in staged.splitlines() if line.strip()),
            sorted(EDITABLE_DOCUMENTS),
            "the conffiles the package actually carries are not the ones the repository declares",
        )
        # dpkg reads DEBIAN/conffiles literally, one file name per line, so a comment
        # in the shipped list is a file named `#` that every install would try to own.
        self.assertNotIn(
            "#", staged,
            "the shipped conffiles list carries a comment, which dpkg reads as a file name",
        )

    def test_the_forced_ech_list_ships_with_at_least_one_comment_line(self):
        """A zero-byte list is refused by design, so the shipped file carries a `#`
        line: a file of comments is how this project ships "forcing off"."""
        text = self.read(CONFIG_DIRECTORY + "/force-ech-domains.txt")
        entries = [line.split("#", 1)[0].strip() for line in text.splitlines()]
        self.assertEqual(
            [entry for entry in entries if entry], [],
            f"the shipped forced-ECH list forces ECH for {[e for e in entries if e]}",
        )
        self.assertTrue(text.endswith("\n"), "the shipped forced-ECH list has no trailing newline")
        self.assertIn(
            "#", text,
            "the shipped forced-ECH list carries no comment line, and a zero-byte list is refused",
        )
        self.assertGreater(len(text), 0)

    def test_the_forced_ech_documentation_does_not_describe_deleted_behaviour(self):
        """Ruling 191(a) deleted the strict-mode A/AAAA suppression for a listed
        name, and the operator-facing documents described it as a FEATURE: "the
        rewriter answers an A or AAAA query for a listed name itself, with an empty
        NOERROR, and asks nobody". Shipping that after deleting it is worse than
        shipping nothing, because an operator who reads it will believe a listed
        name resolves without leaving this machine -- which is the one thing this
        router does not do, and which the foreign branch is where it is decided.

        The same file also told the operator to restart the router after editing the
        list, which was never true: the list is polled about twice a second
        (statewatch.DefaultPollInterval). Only policy.yaml needs a restart, because
        ech.enabled, ech.failure_policy and ech.stale_grace are resolved once in
        Init. An operator following the old instruction would restart the router to
        pick up a list change that was already live, and would conclude from the
        restart that the list needs one.
        """
        page = gzip.decompress(self.read_bytes(MAN_ROOT + "/man8/mosdns-router.8.gz")).decode()
        documents = {
            CONFIG_DIRECTORY + "/force-ech-domains.txt": self.read(CONFIG_DIRECTORY + "/force-ech-domains.txt"),
            "mosdns-router.8": page,
        }
        # Lowercased before matching, because a document that shouts a phrase is
        # making it as loudly as one that says it quietly, and a case that only
        # matched lowercase would hold one spelling of a claim rather than the
        # claim. The phrases themselves are written the way the shipped files wrote
        # them, because a paraphrase here would pass against prose that still makes
        # the assertion in different words.
        documents = {where: text.lower() for where, text in documents.items()}
        withdrawn = (
            "asks nobody",
            "with an empty noerror",
            "must not be leaked by looking it up",
            "a censored name must not be leaked",
        )
        for where, text in documents.items():
            for phrase in withdrawn:
                with self.subTest(document=where, phrase=phrase):
                    self.assertNotIn(
                        phrase, text,
                        f"{where} still describes the A/AAAA suppression that ruling 191(a) deleted",
                    )
        # And the reload instruction, which points at the wrong file.
        for where, text in documents.items():
            with self.subTest(document=where):
                self.assertNotIn(
                    "restart mosdns-router to have it forced", text,
                    f"{where} tells the operator to restart the router to reload the list, which is polled and needs no restart",
                )

    def test_the_forced_ech_documentation_states_the_browser_settings_and_the_cost(self):
        """Ruling 191(b): Firefox is NOT fixed by this package, and both of the
        settings that make it work default to the unsafe side. Total-ECH's README is
        explicit about both, and neither of them is about anything this router can
        observe -- so the only place an operator can learn them is this project's
        own documentation, and the only honest way to say it is that it is STATED
        rather than checked.

        The cost is stated for the same reason. "Forcing ECH" reads like a free
        privacy win, and it is not: the router answers the name's HTTPS query
        itself, with a key BORROWED from the ECH sources rather than one the origin
        published, and a listed name's A and AAAA are ordinary queries.
        """
        page = gzip.decompress(self.read_bytes(MAN_ROOT + "/man8/mosdns-router.8.gz")).decode()
        # Lowercased for the same reason as the withdrawn-phrase case: the conffile
        # shouts what the manual says quietly, and both are saying it.
        documents = {
            CONFIG_DIRECTORY + "/force-ech-domains.txt": self.read(CONFIG_DIRECTORY + "/force-ech-domains.txt").lower(),
            "mosdns-router.8": page.lower(),
        }
        required = (
            # The two settings, named exactly as about:config spells them.
            "network.dns.force_waiting_https_rr",
            "network.dns.echconfig.fallback_to_origin_when_all_failed",
            # That nobody here can check them.
            "not checked",
            # And that editing the list needs no restart, while the policy does.
            "policy.yaml",
        )
        for where, text in documents.items():
            for phrase in required:
                with self.subTest(document=where, phrase=phrase):
                    self.assertIn(
                        phrase, text,
                        f"{where} does not say {phrase!r}, and an operator reading only this file would run Firefox with both settings on the unsafe side",
                    )

    def test_the_user_candidate_and_profile_files_ship_empty_but_documented(self):
        """The candidate list is empty because there is nothing to measure, and the
        profile document declares an empty profile list because a per-hostname
        address has to be written down by an operator before it can be published.
        Neither file is zero bytes, and both say in comments what they are."""
        candidates = self.read(CONFIG_DIRECTORY + "/cloudflare.txt")
        entries = [
            line.split("#", 1)[0].strip()
            for line in candidates.splitlines()
            if not line.strip().startswith("#")
        ]
        self.assertEqual(
            [entry for entry in entries if entry], [],
            "the shipped candidate list names a candidate this project never chose",
        )
        profiles = self.read(CONFIG_DIRECTORY + "/cloudfront-domains.yaml")
        self.assertEqual(
            [line for line in profiles.splitlines() if line.strip() and not line.lstrip().startswith("#")],
            ["schema_version: 1", "profiles: []"],
            "the shipped profile document is not the empty document and nothing else",
        )
        for document, text in (
            (CONFIG_DIRECTORY + "/cloudflare.txt", candidates),
            (CONFIG_DIRECTORY + "/cloudfront-domains.yaml", profiles),
        ):
            with self.subTest(document=document):
                self.assertIn("#", text, f"{document} is undocumented")
                self.assertGreater(len(text), 0, f"{document} is zero bytes")

    def test_the_profile_document_is_the_empty_document_the_parser_accepts(self):
        """A document with no profiles in it is not an error, but an UNDECODABLE
        one is: the parser refuses a file it cannot read, and the nightly
        measurement would have nothing to work with. Its documented limit: this
        checks the document's shape, because the parser is Go and the package test
        suite is Python; `cmd/mosdns-cdnctl` holds the parser's own cases."""
        text = self.read(CONFIG_DIRECTORY + "/cloudfront-domains.yaml")
        keys = [
            line.split(":", 1)[0].strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            keys, ["schema_version", "profiles"],
            f"the profile document declares {keys}, want the two keys the parser reads",
        )
        self.assertRegex(text, r"(?m)^schema_version:\s*1\s*$")
        self.assertRegex(text, r"(?m)^profiles:\s*\[\s*\]\s*$")

    def test_every_listener_the_shipped_documents_name_is_loopback(self):
        for document, addresses in (
            (CONFIG_DIRECTORY + "/mosdns.yaml",
             yaml_listen_addresses(self.read(CONFIG_DIRECTORY + "/mosdns.yaml"))),
            (CONFIG_DIRECTORY + "/dnscrypt-proxy.toml",
             toml_listen_addresses(self.read(CONFIG_DIRECTORY + "/dnscrypt-proxy.toml"))),
        ):
            with self.subTest(document=document):
                self.assertTrue(addresses, f"{document} names no listener at all")
                for address in addresses:
                    self.assertEqual(
                        non_loopback(address), [],
                        f"{document} listens on {address}, which is not loopback",
                    )
        self.assertIn("127.0.0.1:53", self.read(CONFIG_DIRECTORY + "/mosdns.yaml"))
        self.assertIn("127.0.0.1:15353", self.read(CONFIG_DIRECTORY + "/dnscrypt-proxy.toml"))

    def test_the_resolver_document_turns_off_what_the_plan_forbids(self):
        text = self.read(CONFIG_DIRECTORY + "/dnscrypt-proxy.toml")
        for key, value in (
            ("doh_servers", "false"),
            ("odoh_servers", "false"),
            ("cache", "false"),
            ("ignore_system_dns", "true"),
        ):
            with self.subTest(key=key):
                self.assertRegex(text, rf"(?m)^{key} = {value}$")

    def test_the_china_list_is_a_list_of_names_and_never_of_addresses(self):
        """It is pinned by digest, and every line of it is one of the four rule
        forms a domain_set file may carry, so neither a hand edit nor a re-pin can
        turn it into a set of resolvers."""
        shipped = self.read_bytes(CHINA_LIST)
        self.assertEqual(
            hashlib.sha256(shipped).hexdigest(),
            json.loads(self.read(SOURCE_LOCK))["list_sha256"],
            "the shipped China list does not match the list_sha256 in the shipped source lock",
        )
        findings = china_list_findings(shipped.decode("utf-8"))
        self.assertEqual(
            findings[:5], [],
            f"{len(findings)} line(s) of {CHINA_LIST} are not a rule the gateway can read:\n"
            + "\n".join(f"  {finding}" for finding in findings[:5]),
        )


# --- what must not be in the package ----------------------------------------


class ForbiddenContentTests(_Staged):
    """Nothing in the package can put this machine on a resolver it refuses."""

    def test_no_forbidden_resolver_address_appears_anywhere_in_the_package(self):
        findings = content_findings(self.root, self.inventory, FORBIDDEN_ADDRESSES)
        self.assertEqual(
            findings, [],
            "a domestic public resolver or a DoH endpoint is named in the package:\n"
            + "\n".join(f"  {path}: {needle}" for path, needle in findings),
        )

    def test_no_forbidden_provider_or_tool_appears_in_any_shipped_document(self):
        findings = content_findings(
            self.root, self.inventory, FORBIDDEN_PROVIDERS, exempt=ROUTE_SCAN_EXEMPT,
        )
        self.assertEqual(
            findings, [],
            "the package names a resolver provider, an endpoint or a tool this project "
            "refuses to configure:\n"
            + "\n".join(f"  {path}: {needle}" for path, needle in findings),
        )

    def test_the_provider_scan_exempts_exactly_the_one_file_that_may_name_them(self):
        """An exemption is a hole in the gate, so the hole is one named file, it is
        asserted to be one file, and that file is pinned by digest and checked line
        by line rather than merely trusted."""
        self.assertEqual(ROUTE_SCAN_EXEMPT, (CHINA_LIST,))
        self.assertNotIn(
            CHINA_LIST, COMPILED,
            "the China list is a text file and must not be exempt twice over",
        )
        self.assertTrue((REPO / "configs" / "cn-domains.txt").is_file())

    def test_every_address_a_shipped_document_names_is_one_this_package_may_configure(self):
        """An allowlist, not the denylist above, and the reason is that a denylist
        cannot know an address nobody wrote down.

        Twelve IPv4 literals were on the denylist, and 1.2.4.8, 210.2.4.8,
        211.98.20.20 and 221.5.88.88 are all public resolvers inside the network this
        project routes out of. The denylist was also IPv4-only, so every domestic IPv6
        literal would have passed. This asks the other question -- is this one of the
        handful of addresses this package is allowed to name? -- and the answer is
        loopback, resolved's stub, the two pinned Quad9 bootstrap resolvers, and the
        RFC 5737 / RFC 3849 documentation ranges an EXAMPLE has to use."""
        findings = address_findings(self.root)
        self.assertEqual(
            findings, [],
            "a shipped configuration document names an address this package may not "
            "configure:\n" + "\n".join(f"  {finding}" for finding in findings),
        )

    def test_the_allowlist_admits_exactly_the_addresses_this_project_chose(self):
        """The allowlist is a hole in a gate, so the hole is asserted: loopback, the
        resolved stub inside it, the two pinned Quad9 bootstrap resolvers, ::1, and
        the four documentation ranges. One more address would be one more way to
        point a machine at a resolver, and the test that would notice is this one."""
        self.assertEqual(
            sorted(ALLOWED_ADDRESSES),
            sorted(("127.0.0.1", "::1", "9.9.9.9", "149.112.112.9")),
        )
        self.assertEqual(
            sorted(ALLOWED_NETWORKS),
            sorted(("127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")),
        )
        # Every allowed address really is reachable only from this machine or is a
        # pinned bootstrap, which is the claim the allowlist is making.
        import ipaddress

        for value in ALLOWED_ADDRESSES:
            address = ipaddress.ip_address(value)
            with self.subTest(address=value):
                self.assertTrue(
                    address.is_loopback or value in ("9.9.9.9", "149.112.112.9"),
                    f"{value} is in the allowlist and is neither loopback nor a pinned bootstrap",
                )
        # And the document a resolver is configured from is one of the six, so the
        # scan cannot be narrowed to a file this package does not ship.
        for document in CONFIG_VALUE_DOCUMENTS:
            with self.subTest(document=document):
                self.assertIn(document, EDITABLE_DOCUMENTS)

    def test_the_compiled_programs_are_exempt_from_the_content_scan_for_a_reason(self):
        """The exemption is a claim, so it is asserted rather than assumed: the
        router's own control tool embeds the resolvers it refuses."""
        for path in COMPILED:
            with self.subTest(path=path):
                self.assertInstalledFile(path, 0o755)
        self.assertIn(
            "COMPILED", (REPO / "installer" / "tests" / "test_package.py").read_text(),
        )
        source = (REPO / "internal" / "mosdnsconfig" / "render.go").read_text()
        self.assertIn(
            "114.114.114.114", source,
            "the compiled control tool is exempt from the address scan because it embeds the "
            "domestic resolvers it refuses; if that refusal moved, this exemption is wrong",
        )


# --- the maintainer scripts --------------------------------------------------


class MaintainerScriptTests(_Staged):
    """postinst, prerm and postrm, and the order their obligations run in."""

    def test_the_control_file_is_the_metadata_that_was_decided(self):
        fields = control_fields(self.read(DEBIAN + "/control"))
        for name, want in CONTROL_FIELDS.items():
            with self.subTest(field=name):
                self.assertEqual(fields.get(name.lower()), want)
        self.assertGreater(int(fields.get("installed-size", "0")), 0)
        for name in ("maintainer", "description"):
            with self.subTest(field=name):
                self.assertTrue(fields.get(name), f"the control file has no {name}")
        self.assertEqual(
            fields.get("architecture"), _built_architecture(),
            "the built package's Architecture is not the architecture it was built for",
        )
        self.assertIn(fields.get("architecture"), BUILT_ARCHITECTURES.split())
        self.assertEqual(
            control_fields(CONTROL.read_text()).get("architecture"), BUILT_ARCHITECTURES,
            "the repository's control file no longer declares the set of architectures this "
            "package is built for",
        )
        depends = dependency_names(fields)
        for name in CONTROL_DEPENDS:
            with self.subTest(depends=name):
                self.assertIn(name, depends)
        self.assertRegex(fields.get("depends", ""), r"python3 \(>=\s*3\.10\)")
        for field in ("recommends", "suggests", "enhances", "breaks", "replaces", "pre-depends"):
            self.assertNotIn(
                field, fields,
                f"the package declares {field}, which nothing in this plan decided on",
            )

    def test_the_acl_dependency_is_declared_because_postinst_cannot_work_without_it(self):
        """`setfacl` is the provisioning this plan makes load-bearing, so a machine
        without the `acl` package cannot install this one. Recorded amendment: the
        plan's dependency list predates the ruling that postinst, and only postinst,
        provisions the state directories' mode and default ACL."""
        fields = control_fields(self.read(DEBIAN + "/control"))
        self.assertIn("acl", dependency_names(fields))
        self.assertIn("setfacl", POSTINST.read_text())

    def test_the_depends_field_names_the_resolved_daemon_by_a_name_every_release_has(self):
        """**`libnss-resolve`, not `systemd-resolved`, and that is measured.**

        `systemd-resolved` is a binary package on 24.04 and 26.04 and does not
        exist at all on 22.04, where the daemon is part of `systemd` -- so
        `Depends: systemd-resolved` is a package dpkg refuses to configure on the
        oldest release this project supports, and it refuses it in the words of a
        broken install:

            dpkg: dependency problems prevent configuration of mosdns-router:
             mosdns-router depends on systemd-resolved; however:
              Package systemd-resolved is not installed.

        MEASURED on 22.04 in the Podman matrix (Task 4 Step 7), where a cell that
        would otherwise have installed reported a dependency problem instead.

        `libnss-resolve` exists on all three, brings the daemon with it where the
        daemon is a package of its own, and is the NSS module that makes a lookup
        on this machine go to the resolved stub. **The preflight still requires
        the daemon to be RUNNING** (`check_managers`), so nothing about the
        property the package needs is relaxed by naming it differently.

        **The reasoning is here rather than in `packaging/debian/control`**, because
        a `#` line inside a control stanza is a field continuation to `dpkg-deb` and
        not a comment. MEASURED, `dpkg-deb --build` refuses the file with `error:
        parsing file '.../DEBIAN/control' near line 6 package 'mosdns-router'`. So
        this case is where a reader who asks "why not `systemd-resolved`?" is sent.
        """
        fields = control_fields(self.read(DEBIAN + "/control"))
        depends = dependency_names(fields)
        self.assertIn("libnss-resolve", depends)
        self.assertNotIn(
            "systemd-resolved", depends,
            "`systemd-resolved` does not exist as a package on 22.04, so depending on it is a "
            "package that cannot be configured on one of the three releases this project supports",
        )
        # And the property itself is still required, by name, at run time.
        self.assertIn(
            "systemd-resolved.service", (REPO / "installer" / "mosdns_installer.py").read_text(),
            "the preflight has to require the resolved DAEMON to be running, whatever the "
            "dependency calls the package that carries it",
        )
        # **And the one thing this substitution costs, said out loud.** On 26.04 the
        # daemon is a `Recommends` of `libnss-resolve`, not a hard `Depends` --
        # MEASURED, `dpkg -s libnss-resolve` reads `Depends: libc6 (>= 2.39)` and
        # `Recommends: systemd-resolved` (`docs/measured-environment.md:555`) -- so a
        # hard dependency on the *package* became a soft one on the *daemon* on the
        # newest of the three releases.
        #
        # Nothing is *accepted* that was not accepted before: `check_managers` still
        # refuses unless `systemd-resolved.service` is ACTIVE, and every cell measured
        # here had it active (24.04 and 26.04 both report the unit active, and 22.04
        # has no separate package at all). But a `--no-install-recommends` install of
        # this package on a fresh 26.04 machine would get the NSS module and no
        # daemon behind it -- which is a fact about the CHOICE, and a reader has to be
        # able to find it rather than infer it. So the record that says so is
        # required to still say so, and the image is required to install the daemon
        # explicitly where the release has it as a package, which is what makes the
        # soft dependency safe inside a cell.
        measured = (REPO / "docs" / "measured-environment.md").read_text(encoding="utf-8")
        self.assertIn(
            "Recommends", measured,
            "the measured-environment record no longer says that the daemon is a Recommends of "
            "libnss-resolve on 26.04, so the cost of this substitution is not written down "
            "anywhere a reader would look for it",
        )
        containerfile = (
            REPO / "tests" / "podman" / "images" / "target.Containerfile"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "libnss-resolve", containerfile,
            "the target image and the control file must make the same substitution, for the same "
            "reason: two files spelling one fact is how they drift, and this is the third time "
            "that has been the defect in this project",
        )
        self.assertIn(
            "systemd-resolved", containerfile,
            "the target image no longer installs the daemon where the release has it as a package, "
            "so a cell on 26.04 has the NSS module and nothing behind it -- which is the exact "
            "failure Task 2 found and the soft dependency makes possible",
        )

    def test_every_maintainer_script_handles_every_call_dpkg_can_make(self):
        """Debian Policy 6.5, compared in both directions and against a table
        transcribed from the policy rather than from these scripts.

        The failure this exists for is real and was shipped: `postrm` had six of the
        seven first arguments dpkg may pass it, `failed-upgrade` was the missing one,
        and the arm that was missing falls into the default arm, which exits 1.
        `new-postrm failed-upgrade old-version new-version` is what dpkg calls when
        `old-postrm upgrade` fails, so a mid-upgrade unwind turned a recoverable
        failure into a half-installed package, and the test that should have caught it
        had enumerated the same six verbs.
        """
        for name, script in SCRIPTS.items():
            with self.subTest(script=name):
                findings = policy_verb_findings(name, script.read_text())
                self.assertEqual(
                    findings, [],
                    f"{name} disagrees with Debian Policy 6.5 about how it may be called:\n"
                    + "\n".join(f"  {finding}" for finding in findings),
                )

    def test_an_argument_dpkg_may_not_pass_is_never_read_unguarded(self):
        """`postinst configure` is called with a second argument that MAY be null
        (Policy 6.5, footnote 7) and `prerm deconfigure` with four, so a script that
        reads `$2` on a `postinst configure` may read an empty string where it
        expected a version. `postinst` does read it -- it is what tells a fresh
        install from an upgrade -- and the rule is therefore that every such reference
        is `${N:-}`-guarded rather than that none of them exists."""
        for name, script in SCRIPTS.items():
            body = shell_code(script.read_text())
            for number in ("2", "3", "4", "5"):
                unguarded = body.count("$" + number)
                guarded = body.count("${" + number)
                with self.subTest(script=name, argument=number):
                    self.assertEqual(
                        unguarded, guarded,
                        f"{name} reads ${number} somewhere without a ${{{number}:-}} default",
                    )

    def test_only_the_purge_arm_removes_anything(self):
        """A removal command in any other arm is a plain `dpkg --remove` deleting the
        operator's recorded backup, and the arms are computed from the label set so
        that two labels sharing one arm cannot hide it."""
        bodies = arm_bodies(POSTRM.read_text())
        for label, body in sorted(bodies.items()):
            if label in ("purge", "*"):
                continue
            with self.subTest(label=label):
                self.assertEqual(
                    destructive_commands(label, body), [],
                    f"postrm's {label!r} arm removes something, and only a purge may",
                )
        self.assertTrue(
            destructive_commands("purge", bodies["purge"]),
            "postrm's purge arm removes nothing, so --purge leaves the state directory",
        )

    def test_postinst_leaves_nothing_enabled_when_the_transaction_refuses(self):
        """The failure arm says "nothing is enabled and running". That is only true
        if nothing was enabled before the transaction, and the three timers are the
        thing that would be left behind: a nightly `mosdns-cdnctl test --apply`
        publishing into state directories an operator was told nothing was using."""
        findings = timer_position_findings(POSTINST.read_text())
        self.assertEqual(
            findings, [],
            "postinst could leave a timer enabled behind a refused install:\n"
            + "\n".join(f"  {finding}" for finding in findings),
        )
        positions = postinst_steps(POSTINST.read_text())
        self.assertLess(
            positions["state-directories"], positions["install-transaction"],
            "the transaction runs before the state directories are provisioned",
        )
        self.assertLess(
            positions["install-transaction"], positions["enable-timers"],
            "the timers are enabled before the transaction that has to succeed first",
        )

    def test_postinst_says_which_of_its_two_claims_it_can_make_on_a_refusal(self):
        """A fresh install enables nothing; an UPGRADE of an installation that is
        already running this package leaves whatever was already enabled, and saying
        "nothing is enabled" there would be the same kind of false claim this round is
        about. `postinst configure` is handed the previously configured version as its
        second argument, and a null one means there was none.

        BEHAVIOURAL, and the reason is that the two claims used to be SUBSTRINGS of
        the script's text: `${2:-}`, "Nothing is enabled" and "configured before" are
        all still present in a script whose `${2:-}` test is inverted, so the three
        assertions could not see the arm they were about. This runs the script twice
        with the same refusal and the two different second arguments dpkg passes, and
        reads which sentence each run PRINTED. `postinst_transaction_run`'s
        `second_argument=` existed for this and no test passed it, so the arm was held
        by nothing at all.
        """
        first, _calls = postinst_transaction_run(3)
        upgrade, _calls = postinst_transaction_run(3, second_argument="0.0.9")
        # The fresh install. `dpkg --configure` on a first install passes no second
        # argument, so `${2:-}` is empty and this is the arm a new machine takes.
        self.assertIn(
            "Nothing is enabled", first.stderr,
            "a refusal on a FIRST install did not print the claim that is true there, so the "
            "script told an operator with nothing enabled that it could not tell",
        )
        self.assertNotIn("configured before", first.stderr)
        # The upgrade. dpkg passes the version that was configured before, and saying
        # "nothing is enabled" here would be false in the other direction.
        self.assertIn(
            "configured before", upgrade.stderr,
            "a refusal on an UPGRADE did not print the claim that is true there, so the script "
            "promised nothing was enabled on a machine that was already running this package",
        )
        self.assertIn("version 0.0.9", upgrade.stderr,
                      "the upgrade arm does not name the version dpkg handed it, so an operator "
                      "cannot tell which install it is being told about")
        self.assertNotIn("Nothing is enabled", upgrade.stderr)
        # Both are refusals, so both exit non-zero; that is the other half of the
        # branch and neither run may succeed.
        for label, completed in (("first install", first), ("upgrade", upgrade)):
            with self.subTest(install=label):
                self.assertNotEqual(
                    completed.returncode, 0,
                    "a refused transaction exits 0, so dpkg records a failed installation as "
                    "configured",
                )

    # --- ruling 191(d): the identities, and ruling 191(e): the purge -----------

    def test_the_three_identities_carry_this_packages_own_name(self):
        """The whole of ruling 191(d), and the reason a purge can remove one.

        The resolver's used to be `dnscrypt-proxy`, which is the upstream package's
        own account, and postinst used to admit in as many words that a machine
        carrying both was sharing one identity. Every one of the three now carries
        this package's own name, so none of them can be somebody else's and the
        purge's fail-loud checks below have something they can actually check.
        """
        names = identities_from(POSTINST.read_text())
        self.assertEqual(
            [names["group"], names["router"], names["control"], names["resolver"]],
            ["mosdns-router", "mosdns-router", "mosdns-router-cdn", "mosdns-router-dnscrypt"],
            "an identity name does not carry this package's own",
        )
        # And nothing else in the package still creates one of the old names. The
        # legacy names are READ by the migration, so the check is for the verbs that
        # CREATE one.
        run = "\n".join(executed_lines(POSTINST.read_text()))
        for legacy in ("mosdns", "mosdns-cdn", "dnscrypt-proxy"):
            creating = re.search(
                rf"\b(?:addgroup|adduser|groupadd|useradd)\b[^\n]*(?<![\w-]){re.escape(legacy)}(?![\w-])",
                run,
            )
            self.assertIsNone(
                creating, f"postinst still creates an identity named {legacy}: "
                f"{creating.group(0) if creating else ''}",
            )

    def test_an_upgrade_moves_the_state_directories_before_it_drops_the_old_group(self):
        """The order inside the migration, and it is the whole of it.

        A state directory still owned by a group that is about to be deleted leaves
        the units unable to write it, and nothing in the transaction would say why:
        the preflight refuses on the group, the router cannot publish, and the
        message names a permission rather than a rename. So the chown and the ACL
        come first and the `delgroup` last, in the script's own text.
        """
        run = "\n".join(executed_lines(POSTINST.read_text()))
        # A REGEX and not `run.index('chgrp "$STATE_GROUP"')`, because the migration
        # now runs `chgrp -R` and the literal stopped being in the script -- so the
        # lookup raised ValueError, and a case that cannot find the command it is
        # ordering reports a broken script either way. Any option between the verb
        # and the variable is accepted here on purpose: what this case orders is
        # the chgrp against the delgroup, and `-R` is an argument to the first rather
        # than a different command.
        chgrp_match = re.search(r'chgrp(?:\s+-\S+)*\s+"\$STATE_GROUP"', run)
        self.assertIsNotNone(
            chgrp_match,
            "postinst no longer hands the state trees to the new group at all, so every "
            "file in them keeps the gid of the group this step is about to delete",
        )
        chgrp = chgrp_match.start()
        acl = run.index('setfacl -d -m g::rwx')
        deluser = run.index('deluser --system')
        delgroup = run.index('delgroup --system')
        self.assertLess(
            chgrp, delgroup,
            "the old group is removed before the state directories are handed to the "
            "new one, so the units have nothing to write and preflight says nothing "
            "about a rename",
        )
        self.assertLess(
            acl, delgroup,
            "the old group is removed before the default ACL is re-applied, and a "
            "default ACL grants by group, so the re-application has to follow the chown",
        )
        self.assertLess(deluser, delgroup, "a user is removed after the group that is its primary group")
        # Every one of the four directories is chowned, not just the parent. The
        # runtime and lists directories are where every published file lands, and a
        # parent-only chown leaves them on the old group.
        for directory in STATE_DIRECTORIES:
            with self.subTest(directory=directory):
                self.assertRegex(
                    run,
                    r'for directory in [^\n]*' + re.escape(directory),
                    f"{directory} is not in the migration's list at all",
                )

    def test_an_upgrade_hands_the_files_inside_the_state_tree_to_the_new_group(self):
        """The defect the four-directory `chgrp` could not see, and the one that
        takes a machine's DNS down rather than merely refusing an install.

        `chgrp` on a directory moves the DIRECTORY's group and leaves every child's
        own group alone, so walking the four directories without `-R` moved the
        directories and nothing else. The step then deleted the old group, and the
        published files were left group-owned by a gid nothing resolves -- at 0640,
        which with no group that exists is a file only root can read.

        Two consequences, and both are asserted here rather than described:

          * **the router cannot start.** `/var/lib/mosdns/lists/cloudflare-ips.json`
            is what the response rewriter builds its prefix watcher from, and it
            does that before anything else, so the router came up, failed, and bound
            nothing on port 53 -- while the transaction had already pointed
            NetworkManager at 127.0.0.1. The machine had no resolver and nothing
            watching for one, because the watchdog timer is enabled only after the
            transaction succeeds.
          * **no later install can succeed either.** `control.lock` is the same
            story, and preflight reports it as a lock this package did not write --
            so `dpkg --configure` refused forever with a message about a mode and a
            group rather than about a rename.

        And `/var/lib/mosdns/installer`, which holds the ownership marker and the
        recorded NetworkManager values, is not one of the four directories at all,
        so it kept the old gid outright: the two documents a later uninstall needs
        to prove what this package set.
        """
        with migrated_sandbox() as migration:
            new_gid = migration.groups[migration.names["new_group"]]
            legacy_gid = migration.groups[migration.names["legacy_group"]]
            self.assertEqual(
                migration.result.returncode, 0,
                f"the migration failed, so nothing below is about its effect: "
                f"{migration.stderr}",
            )
            # The directories, which the first version got right.
            for directory in STATE_DIRECTORIES:
                with self.subTest(directory=directory):
                    self.assertEqual(
                        migration.gid_of(directory), new_gid,
                        f"{directory} was not handed to the new group, so the units "
                        "cannot write it",
                    )
            # The files inside them, which it did not.
            for relative in (
                "var/lib/mosdns/lists/cn-domains.txt",
                "var/lib/mosdns/lists/source-lock.json",
                "var/lib/mosdns/lists/cloudflare-ips.json",
                "var/lib/mosdns/runtime/control.lock",
            ):
                with self.subTest(path=relative):
                    self.assertNotEqual(
                        migration.gid_of(relative), legacy_gid,
                        f"{relative} is still owned by the group the migration then "
                        "deletes, so at 0640 with no group that resolves only root can "
                        "read it and neither service identity can",
                    )
                    self.assertEqual(
                        migration.gid_of(relative), new_gid,
                        f"{relative} was not handed to the new group, so the router "
                        "cannot read a document it needs before it binds port 53",
                    )
            # And the directory that is not one of the four.
            for relative in (
                "var/lib/mosdns/installer",
                "var/lib/mosdns/installer/managed-by",
                "var/lib/mosdns/installer/network-manager-backup.json",
            ):
                with self.subTest(path=relative):
                    self.assertEqual(
                        migration.gid_of(relative), new_gid,
                        f"{relative} kept the old group's gid, and it is the "
                        "ownership marker and the recorded NetworkManager values -- "
                        "the two documents an uninstall reads to decide whether it "
                        "may put the machine's DNS back",
                    )

    def test_a_migration_that_finds_no_state_tree_is_not_a_failure(self):
        """The guard, and it is load-bearing rather than defensive.

        A machine that has never run this package has no state tree, and the
        migration runs on every `postinst configure` including `dpkg --configure`
        retries. If the step treated an absent directory as something to fail on,
        the retry dpkg itself recommends after a refusal would fail at the
        migration instead -- before the transaction, and with a message about a
        rename rather than about whatever the operator was sent back to fix.
        """
        with migrated_sandbox(empty=True) as migration:
            self.assertEqual(
                migration.result.returncode, 0,
                f"the migration refused a machine with no state tree at all: "
                f"{migration.stderr}",
            )

    def test_a_reinstall_is_not_told_its_own_group_belongs_to_another_package(self):
        """Ruling 191(d) removed the collision; it must not leave the report running.

        Two worlds, and both are this package's own STEP 1:

          * **this package's own accounts, already there.** A group AND the service
            identity that goes with it, which is what every re-run finds -- and a
            re-run is exactly what `dpkg` suggests after a refused install and
            exactly what an operator does next. Reporting that as another package's
            group sends them looking for a package that does not exist, on the
            success path as well as the failure one.
          * **a bare group, with no service identity behind it.** That is what a
            real collision looks like, and it is the only case the report is for.

        Run both, because the thing under test is which of the two the script calls
        a collision and a substring of the script cannot tell.
        """
        names = identities_from(POSTINST.read_text())
        claim = "belongs to another package"
        again = collision_report(groups=(names["group"],), users=(names["router"],))
        self.assertNotIn(
            claim, again,
            "postinst told a re-install that this package's own group belongs to "
            f"another package, which is the false sentence the rename removed the "
            f"need for. It printed:\n{again}",
        )
        self.assertNotIn(
            names["group"], again,
            "postinst reported this package's own group at all on a re-install, so "
            f"there is nothing in this output to tell a re-run from a collision:\n{again}",
        )
        bare = collision_report(groups=(names["group"],), users=())
        self.assertIn(
            claim, bare,
            "postinst no longer reports a bare group as another package's, so a real "
            f"collision is now silent. It printed:\n{bare}",
        )
        self.assertIn(
            names["group"], bare,
            "the report did not name the group it is about, so an operator cannot "
            f"tell which account to look at:\n{bare}",
        )

    def test_a_purge_removes_the_bytecode_cache_dpkg_cannot_see(self):
        """Ruling 191(e). dpkg owns every file this package lists and `__pycache__`
        is not one of them: Python writes it beside the bridge module the first time
        anything imports it, so it appears after unpacking. dpkg's own warning --
        "directory ... not empty so not removed" -- is the symptom, and it leaves
        the directory behind as well.

        Run rather than read, because the guard is the thing under test and a
        substring cannot see a `rm -rf` behind an `if`.
        """
        with purged_sandbox(accounts=(), running=(), foreign=()) as purge:
            self.assertEqual(
                purge.returncode, 0, f"purge failed: {purge.stdout}{purge.stderr}"
            )
            self.assertFalse(
                (purge.root / "usr/lib/mosdns-router/mosdns_dhcp_bridge/__pycache__").exists(),
                "the bytecode cache survives a purge, which is the residue dpkg warns "
                "about and cannot remove",
            )
            self.assertFalse(
                (purge.root / "usr/lib/mosdns-router/mosdns_dhcp_bridge").exists(),
                "the emptied bridge directory survives a purge",
            )

    def test_a_purge_leaves_a_bytecode_cache_that_is_a_symbolic_link(self):
        """The same three conditions as the state directory, applied to a path the
        bridge may have been replaced with. A symlink is not followed, only a
        directory is removed, and an absent directory is not an error."""
        with purged_sandbox(
            accounts=(), running=(), foreign=(), symlinked_cache_to="elsewhere",
        ) as purge:
            outside = purge.root / "elsewhere"
            self.assertTrue(
                (outside / "keep.txt").exists(),
                "the purge followed a symbolic link and removed what was behind it",
            )

    def test_a_purge_keeps_an_account_a_process_is_still_running_as(self):
        """Fail-loud rather than forced. `deluser --system` takes the NAME away, and
        a process still running under it then writes as a number nothing resolves --
        so the account is kept, and the message says which one and why."""
        with purged_sandbox(accounts=("mosdns-router",), running=[("mosdns-router", 3)], foreign=()) as purge:
            self.assertIn(
                "mosdns-router", purge.stderr,
                "the purge did not name the account it kept, so an operator cannot tell "
                "which one is still there",
            )
            self.assertIn(
                "LEFT ALONE", purge.stderr,
                "the purge did not say it left the account alone rather than forcing it",
            )
            self.assertIn(
                "deluser --system mosdns-router", purge.stderr,
                "the purge did not give the command that would remove it",
            )
            self.assertEqual(
                purge.removed, (),
                f"the purge removed an account a process was running as: {purge.removed}",
            )

    def test_a_purge_keeps_an_account_that_still_owns_a_file_elsewhere(self):
        """The other half of the same rule, and it is the one that catches the case
        the name cannot: an account this package created whose name nothing else
        uses, still owning a file in a tree this package does not own."""
        with purged_sandbox(accounts=("mosdns-router-cdn",), running=(), foreign=("mosdns-router-cdn",)) as purge:
            self.assertIn("outside this package's", purge.stderr)
            self.assertEqual(purge.removed, (), f"the purge removed an account that still owns a file: {purge.removed}")

    def test_a_purge_removes_the_accounts_nothing_is_using(self):
        """And the other half again: fail-loud that never says anything is a purge
        that removes nothing, which is what it did before ruling 191(d)."""
        with purged_sandbox(
            accounts=("mosdns-router", "mosdns-router-cdn", "mosdns-router-dnscrypt"),
            running=(), foreign=(),
        ) as purge:
            self.assertEqual(
                purge.removed,
                ("mosdns-router", "mosdns-router-cdn", "mosdns-router-dnscrypt"),
                f"a purge with nothing using the identities removed {purge.removed}",
            )
            for group in ("mosdns-router", "mosdns-router-dnscrypt"):
                self.assertIn(group, purge.removed_groups)

    def test_postinst_reports_a_service_account_it_did_not_create(self):
        """`addgroup --system dnscrypt-proxy` exits 0 when the group is already there,
        so on a machine that also carries the upstream dnscrypt-proxy package this
        one silently adopts its group. That is worth a line on the install's own
        output, because nothing else in the transaction would ever mention it."""
        text = POSTINST.read_text()
        names = identities_from(text)
        self.assertEqual(names["resolver"], RESOLVER_USER_NAME)
        # The check covers the shared state group too, which the old script did not:
        # both are names this package could collide with, and only one of them was
        # asked about. **Both spellings, in the script's own text**, rather than the
        # `for account in ...` loop this used to be: the loop was what made the
        # report fire on this package's own accounts, because a loop can only test
        # the one thing it iterates over, and the thing that distinguishes a
        # collision from a re-run is the account BEHIND the group.
        for group, user in (("STATE_GROUP", "ROUTER_USER"), ("RESOLVER_USER", "RESOLVER_USER")):
            with self.subTest(group=group):
                check = f'getent group "${group}"'
                self.assertIn(
                    check, text,
                    f"postinst never asks whether the {group} group it is about to "
                    "create is already there, and `addgroup --system` exits 0 when it "
                    "is, so a collision is adopted silently",
                )
                self.assertIn(
                    f'getent passwd "${user}"', text,
                    f"the {group} collision report does not ask whether this package's "
                    "own service identity is behind the group, so it fires on every "
                    "re-run -- which is what dpkg itself suggests after a refusal",
                )
        # The check has to come BEFORE the addgroup, or it reports a group this
        # script created itself and calls that a collision on every upgrade.
        self.assertLess(
            text.index('getent group "$STATE_GROUP"'),
            text.index('addgroup --system "$STATE_GROUP"'),
            "a group is created before postinst asks whether it already existed",
        )
        # And the message has to say the group belongs to ANOTHER package, which is
        # only true now that none of the three names is one this package also uses.
        self.assertIn(
            "belongs to another package", text,
            "the collision report does not say whose group it found, and the old "
            "wording admitted this install might be looking at its own",
        )

    def test_postinst_provisions_the_state_directories_in_the_load_bearing_order(self):
        """Mode first, then the ACL, for each directory. The reverse leaves a
        default ACL of `other::r-x` and a directory neither service identity can
        write, which every default-ACL check passes."""
        findings = order_findings(POSTINST.read_text())
        self.assertEqual(
            findings, [],
            "postinst does not provision the state directories correctly:\n"
            + "\n".join(f"  {finding}" for finding in findings),
        )
        # And the pairs themselves, adjacent and in that order, one directory at a
        # time. `order_findings` is the reader that decides; this reads the same fact
        # directly, so a bug in the reader cannot quietly pass this whole test.
        steps = provisioning_steps(POSTINST.read_text())
        for directory in STATE_DIRECTORIES:
            with self.subTest(directory=directory):
                created = steps.index(("directory", directory))
                self.assertEqual(
                    steps[created + 1], ("default-acl", directory),
                    f"{directory} is not followed immediately by its own default ACL",
                )

    def test_postinst_places_the_pinned_list_and_never_re_pins_it(self):
        """Re-pinning at install time is how an operator's reviewed pin becomes
        something nobody reviewed.

        The three tokens are still read out of the text, and they are still worth
        reading: a re-pin through any other spelling -- a `curl` of the archive
        beside an `install` -- would be caught by none of the behaviour below,
        because the behaviour is about what happens to the pair that is already
        there. What the behaviour adds is the half a grep cannot reach: whether
        the pair survives an upgrade, which is the next test.
        """
        text = SCRIPTS["postinst"].read_text()
        run = "\n".join(executed_lines(text))
        for forbidden in ("--pin-remote", "pin-remote", "update-lists"):
            with self.subTest(token=forbidden):
                self.assertNotIn(
                    forbidden, run,
                    f"postinst RUNS something containing {forbidden!r}, so an install or an "
                    "upgrade would re-pin the reviewed list",
                )
        self.assertIn(PUBLISHED_LIST, text)
        self.assertIn(PUBLISHED_LOCK, text)
        self.assertIn("list_sha256", text)
        self.assertIn("sha256sum", text)
        for source, destination in (
            (CHINA_LIST, PUBLISHED_LIST),
            (SOURCE_LOCK, PUBLISHED_LOCK),
        ):
            with self.subTest(path=destination):
                self.assertIn(source, text, f"postinst never places {source} at {destination}")

    def shipped_pair(self):
        """The pinned files the package carries, as the staged tree holds them.

        All four, and the name is historical: STEP 3 reads the China pair and the
        range pair, and the sandbox plants every shipped file the step names, so a
        fixture that supplied two of the four would fail before the step ran
        rather than quietly verifying nothing.
        """
        return {
            "SOURCE_LIST": self.read(CHINA_LIST),
            "SOURCE_LOCK": self.read(SOURCE_LOCK),
            "SOURCE_RANGES": self.read(RANGES_SNAPSHOT),
            "SOURCE_RANGES_LOCK": self.read(RANGES_SNAPSHOT_LOCK),
        }

    def test_postinst_leaves_a_pair_an_operator_re_pinned_alone(self):
        """The property the grep above cannot see, run as the script runs it.

        The published pair at `/var/lib/mosdns/lists` is the OPERATOR's:
        `mosdns-cdnctl update-lists --pin-remote HEAD` writes both files there.
        Replacing them with the shipped snapshot on every `configure` is the same
        act as re-pinning -- the plan's own ruling 59 forbids it -- and it is
        invisible, because the pair an operator's pin wrote is self-consistent
        and stays self-consistent after the overwrite. Nothing detects it until
        `update-lists --check` reports drift days later.

        So the gate has to be behavioural: plant a DIFFERING and internally
        consistent pair, run the step's own lines, and assert the bytes on disk are
        the bytes that were there. The other two cases are here so a script that
        simply never publishes anything cannot pass: absent, the pair is placed;
        half-present, the pair is placed, because the pair is the unit the lock
        describes and one half of it is not a record of anything.
        """
        shipped = self.shipped_pair()
        list_body, lock_body = unpinned_pair("domain:operator.example\n")
        planted = {"PUBLISHED_LIST": PUBLISHED_LIST, "PUBLISHED_LOCK": PUBLISHED_LOCK}
        cases = {
            "differing": {"PUBLISHED_LIST": list_body, "PUBLISHED_LOCK": lock_body},
            "absent": {},
        }
        for label, before in cases.items():
            with self.subTest(published=label):
                _root, variables, completed = sandboxed_postinst_step(
                    3,
                    {planted[name]: body for name, body in before.items()},
                    shipped,
                    text=SCRIPTS["postinst"].read_text(),
                )
                self.assertEqual(
                    completed.returncode, 0,
                    f"the published-pair step failed on a {label} pair: "
                    f"{completed.stdout}{completed.stderr}",
                )
                for name, source in (
                    ("PUBLISHED_LIST", "SOURCE_LIST"),
                    ("PUBLISHED_LOCK", "SOURCE_LOCK"),
                ):
                    self.assertEqual(
                        Path(variables[name]).read_text(encoding="utf-8"),
                        before.get(name, shipped[source]),
                        f"the {label} case did not leave the {name} as it found it",
                    )
        # And the words, because a silent correct behaviour is a behaviour an
        # operator cannot tell from one that happened by accident.
        _root, _variables, completed = sandboxed_postinst_step(
            3,
            {planted[name]: body for name, body in cases["differing"].items()},
            shipped,
            text=SCRIPTS["postinst"].read_text(),
        )
        self.assertIn("left exactly as they are", completed.stderr)

    def test_postinst_publishes_the_pair_when_it_is_not_readable(self):
        """A destination that is not a readable file is the other half of the rule.

        One half of the pair missing is the case: the lock describes the list
        beside it, so a list with no lock is a document nothing can account for,
        and the pair -- not the lock alone -- is what gets placed.
        """
        shipped = self.shipped_pair()
        list_body, _lock_body = unpinned_pair("domain:operator.example\n")
        _root, variables, completed = sandboxed_postinst_step(
            3, {PUBLISHED_LIST: list_body}, shipped, text=SCRIPTS["postinst"].read_text()
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for name, source in (
            ("PUBLISHED_LIST", "SOURCE_LIST"),
            ("PUBLISHED_LOCK", "SOURCE_LOCK"),
        ):
            self.assertEqual(
                Path(variables[name]).read_text(encoding="utf-8"),
                shipped[source],
                f"the pair was not placed even though the lock was unreadable ({name})",
            )

    def test_postinst_verifies_the_pinned_range_snapshot_and_refuses_a_mismatch(self):
        """The digest check the China list has, applied to the ranges.

        A snapshot whose bytes the lock does not record is a file of ranges this
        project cannot account for, and the router classifies every query it
        answers against exactly that file. So a mismatch stops the install before
        the transaction touches anything -- the same position, and for the same
        reason, as a list that does not verify: a machine left exactly as it was.

        The control is beside the case rather than implied by it, because a check
        that would pass against any input is not a check.
        """
        shipped = self.shipped_pair()
        cases = (
            # The control: the pair the package ships has to pass, or the check
            # would be one that refuses everything.
            ("the shipped snapshot", shipped["SOURCE_RANGES"], 0),
            (
                "a snapshot with one range changed",
                shipped["SOURCE_RANGES"].replace("104.16.0.0/13", "104.16.0.0/12"),
                1,
            ),
            ("a snapshot that is not a document", "{}\n", 1),
            ("a snapshot that is empty", "", 1),
        )
        for label, snapshot, want in cases:
            with self.subTest(snapshot=label):
                _root, variables, completed = sandboxed_postinst_step(
                    3, {}, dict(shipped, SOURCE_RANGES=snapshot),
                    text=SCRIPTS["postinst"].read_text(),
                )
                self.assertEqual(
                    completed.returncode, want,
                    f"STEP 3 exited {completed.returncode} for {label}, want {want} -- 0 for a pair "
                    f"it can account for and 1 for one it cannot: "
                    f"{completed.stdout}{completed.stderr}",
                )
                if want == 0:
                    continue
                for named in (variables["SOURCE_RANGES"], variables["SOURCE_RANGES_LOCK"]):
                    self.assertIn(
                        named, completed.stderr,
                        f"the refusal for the {label} does not name {named}, so an operator cannot "
                        "tell which of the two files to look at",
                    )
                self.assertIn("cannot account for", completed.stderr)
                # And the claim that nothing was touched, which is the whole
                # point of refusing here rather than one step later.
                self.assertIn("Nothing has been changed on this machine's DNS", completed.stderr)

    def test_postinst_refuses_when_the_shipped_range_snapshot_is_absent(self):
        """A package that cannot account for its own reference data does not run a
        transaction that classifies against it.

        This is a refusal and not a fallback, on purpose and against the obvious
        argument: a machine with a published document of its own needs no snapshot,
        so it would install. But this step is what PROMISES the install, and a
        package that ships a file and cannot verify it is a package whose other
        promises are worth exactly as much -- so it refuses before the machine's
        DNS is touched, exactly as it does for a China list that does not verify.
        The remedy is named and is not a re-pin: `dpkg` owns both files, so
        `apt install --reinstall` puts them back.

        Both files are tried, and the control is the same run with them present,
        because a check that refuses everything is not a check.
        """
        shipped = self.shipped_pair()
        _root, variables, present = sandboxed_postinst_step(
            3, {}, shipped, text=SCRIPTS["postinst"].read_text(),
        )
        self.assertEqual(
            present.returncode, 0,
            f"STEP 3 refused the pair the package ships: {present.stdout}{present.stderr}",
        )
        for absent in (("SOURCE_RANGES",), ("SOURCE_RANGES_LOCK",), ("SOURCE_RANGES", "SOURCE_RANGES_LOCK")):
            with self.subTest(absent=absent):
                _root, variables, completed = sandboxed_postinst_step(
                    3, {}, shipped, text=SCRIPTS["postinst"].read_text(), absent=absent,
                )
                self.assertNotEqual(
                    completed.returncode, 0,
                    f"STEP 3 accepted a package whose {', '.join(absent)} is not on disk, so an "
                    "install would publish whatever the transaction found -- and on a machine with "
                    "no published document of its own that is nothing at all",
                )
                self.assertIn(
                    variables["SOURCE_RANGES"], completed.stderr,
                    "the refusal does not name the snapshot it could not find",
                )
                self.assertIn(
                    "reinstall", completed.stderr,
                    "the refusal names no way out, and the way out is reinstalling the package",
                )

    def test_postinst_never_writes_the_published_ranges(self):
        """A carried-forward document survives a `dpkg` upgrade.

        The published envelope and the published prefix list are what a machine's
        selector is actually classifying against, and the only program that writes
        them is `mosdns-cdnctl update-lists --refresh-ranges` -- which is also the
        one that consults a machine's own document before the package's snapshot,
        so an upgrade offline republishes exactly what was there. `postinst`
        writing either of them would be the re-pinning this project's own rule
        forbids, done by the script whose whole argument is that it does not do
        it for the China list.
        """
        run = "\n".join(executed_lines(SCRIPTS["postinst"].read_text()))
        for path in (PUBLISHED_RANGES_CACHE, PUBLISHED_PREFIX_LIST):
            with self.subTest(path=path):
                self.assertNotIn(
                    path, run,
                    f"postinst RUNS something naming {path}, so an install or an upgrade would "
                    "replace the range list a selector was built against",
                )
        # And the one that is named: the snapshot is READ here and published by
        # the transaction, so a reader of this file can tell which is which.
        text = SCRIPTS["postinst"].read_text()
        self.assertIn(RANGES_SNAPSHOT, text)
        self.assertIn("sha256sum", text)

    def test_postinst_provisions_before_it_runs_the_install_transaction(self):
        """`postinst` provisions, then the transaction enables and starts; that
        order is the entire reason the provisioning is in this script, because a
        ReadWritePaths entry naming an absent directory fails its unit at start."""
        text = POSTINST.read_text()
        # The call, not the assignment of the path to a variable: the path is named
        # once so there is one answer to "which installer does this run", and looking
        # for the path itself finds the assignment and proves nothing about order.
        self.assertIn(f"INSTALLER={INSTALLER_SCRIPT}", text)
        self.assertIn('"$INSTALLER" install', text)
        self.assertLess(
            text.index("setfacl -d -m g::rwx /run/mosdns"),
            text.index('"$INSTALLER" install'),
            "postinst runs the install transaction before the state directories are provisioned",
        )

    def test_postinst_enables_the_timers_nothing_else_enables(self):
        text = POSTINST.read_text()
        for timer in (
            "mosdns-cdn-optimizer.timer",
            "mosdns-cdn-health.timer",
            "mosdns-list-check.timer",
            # The watchdog's timer, and the one whose absence is the failure the
            # previous plan recorded as an open decision: a machine whose resolver
            # can stop answering with nothing that will put it back.
            "mosdns-watchdog.timer",
        ):
            with self.subTest(timer=timer):
                self.assertIn(timer, text, f"{timer} is enabled by nothing")
        self.assertIn("daemon-reload", text)

    def test_a_timer_enable_that_fails_is_reported_and_does_not_fail_the_package(self):
        """STEP 5's `systemctl enable` was, until this round, the one command in
        `postinst` that was never reachable: the misplaced `fi` above it meant no
        install ever got there. Run `postinst_transaction_run(0, text=<88bc2af>)` and
        the call list is `[['daemon-reload']]` with no `enable` on it, while the same
        run against the current text issues it. So its failure had been decided by
        nobody, which is the one situation in which the decision below is a choice
        rather than a reading of something that already happened.

        THE DECISION, and it is recorded in the script's own comment as well:
        REPORTED, NOT FATAL. Reaching STEP 5 means the transaction succeeded -- the
        machine's DNS was taken over, the daemons are serving and the marker is
        written -- so a non-zero `postinst configure` would make dpkg record the
        package unpacked-but-UNCONFIGURED on a machine whose resolver works, and
        would offer `dpkg --configure`, which runs the whole transaction again.
        That is the `88bc2af` defect wearing the opposite sign: a successful install
        reported as a failure. Tolerant-and-silent is the other wrong answer, and
        worse here than anywhere else in the script, because
        `mosdns-cdn-health.timer` is the only thing on a machine that ever asks
        whether `127.0.0.1:53` still resolves.

        So: exit 0, and a warning that names all three timers, says the transaction
        succeeded, and gives the command to run. The shim fails the verb on every
        call, so a script that quietly retried and succeeded could not pass this.
        """
        completed, calls = postinst_transaction_run(0, failing_systemctl="enable")
        self.assertIn(
            ["enable", "mosdns-cdn-optimizer.timer", "mosdns-cdn-health.timer",
             "mosdns-list-check.timer", "mosdns-watchdog.timer"], calls,
            f"the enable never ran, so this case is not about a failing enable: {calls}",
        )
        self.assertEqual(
            completed.returncode, 0,
            "a failing timer enable failed the whole package, so dpkg records unconfigured a "
            "machine whose DNS was taken over successfully and whose resolver is serving, and "
            f"offers `dpkg --configure`, which runs the transaction again:\n{completed.stderr}",
        )
        for said in (
            "WARNING",
            "SUCCEEDED",
            "mosdns-cdn-health.timer",
            "the only thing on this machine that asks",
            "127.0.0.1:53",
            "sudo systemctl enable mosdns-cdn-health.timer",
        ):
            with self.subTest(said=said):
                self.assertIn(
                    said, completed.stderr,
                    "the warning does not say what an operator needs to know: a machine whose "
                    "health timer is not enabled has nothing watching its resolver, and this "
                    f"message does not mention {said!r}:\n{completed.stderr}",
                )
        # And the warning must not claim the install failed, which is the mistake it
        # exists to prevent.
        self.assertNotIn("dpkg --configure mosdns-router", completed.stderr)
        self.assertNotIn("which is not a", completed.stderr)

    def test_postinst_enables_nothing_where_systemd_is_not_running(self):
        """Both `[ -d /run/systemd/system ]` guards, read by RUNNING the script rather
        than by finding the two tests in its text.

        The harness's `systemd_running=` existed to ask this and no test passed it, so
        the guards were held by a scan that could only confirm the spelling. In a
        chroot, in a `dpkg --root` install, or on any machine where systemd is not
        PID 1, `systemctl` is absent, so both of these commands become `not found`
        lines in the output dpkg shows the operator -- and the `enable` becomes a
        pointless command whose failure STEP 5 then reports as a WARNING, which is a
        machine with no systemd being told that its health timer is not enabled.

        `set -e` IS NOT WHAT THE GUARDS ARE FOR, and this docstring says so because
        the previous version of it claimed the opposite and was wrong about the
        script as it now stands. Take the shipped text, replace the two guards with
        `if true`, and run it with no `systemctl` on `PATH` at all: it still EXITS 0.
        `daemon-reload` carries `|| true`, and the `enable` sits in an `if` CONDITION,
        which `set -e` exempts -- so neither one reaches `set -e`, and the "the first
        one would end the configure" the old text asserted cannot happen. What the
        mutation does change is visible and is the whole of the case: two
        `systemctl: not found` lines where the shipped run has none, and the entire
        WARNING block printed about timers nothing will ever start.
        """
        completed, calls = postinst_transaction_run(0, systemd_running=False)
        self.assertEqual(
            [call for call in calls if call[0] in ("daemon-reload", "enable")], [],
            f"postinst asked systemd to do something where systemd is not running: {calls}",
        )
        self.assertEqual(
            completed.returncode, 0,
            f"a successful install fails where systemd is not running:\n{completed.stderr}",
        )
        self.assertNotIn("command not found", completed.stderr)

    def test_prerm_disables_what_the_uninstall_deliberately_does_not(self):
        """Task 5's handoff: a plain uninstall with no package removal must not
        disable a unit the operator still has installed, so the disable is here,
        where the files are known to be going."""
        text = PRERM.read_text()
        self.assertIn("disable", text)
        for unit in ("mosdns-router.service", "dnscrypt-proxy.service"):
            with self.subTest(unit=unit):
                self.assertIn(unit, text)
        for timer in (
            "mosdns-cdn-optimizer.timer",
            "mosdns-cdn-health.timer",
            "mosdns-list-check.timer",
            "mosdns-watchdog.timer",
        ):
            with self.subTest(timer=timer):
                self.assertIn(timer, text)
        self.assertIn("uninstall", text)
        installer = (REPO / "installer" / "mosdns_installer.py").read_text()
        # Scoped to the uninstall path and not to the module: `_enable` DOES carry a
        # `systemctl disable`, as the undo of an enable it registered, and that is
        # correct -- an install that enabled a unit and then rolled back has to put
        # that unit back the way it found it. What must not exist is a disable in the
        # verb that restores a machine with no package removal behind it.
        for function in ("uninstall", "_stop_units", "_restore_unfinished", "_purge_state"):
            with self.subTest(function=function):
                self.assertNotIn(
                    '"disable"', function_body(installer, function),
                    f"{function} gained a disable step: a plain uninstall with no package removal "
                    "would disable a unit the operator still has installed",
                )

    def test_prerm_tells_the_installers_two_refusals_apart_and_says_what_dpkg_will_do(self):
        """dpkg ABORTS a removal whose pre-removal script exits non-zero.

        So the one sentence the old script printed -- "the files are about to be
        removed with this machine's DNS still pointed at 127.0.0.1 ... do not
        restart the machine" -- described a removal that is not happening, and it
        described both refusals with it. The installer distinguishes them
        precisely and for good reasons: exit 5 is "nothing was changed, because I
        could not prove the DNS is mine to change" and exit 6 is "a restore was
        attempted and did not finish". They are the same dpkg outcome and two
        different situations, and an operator reading one sentence for both is
        told to do the wrong thing.
        """
        text = PRERM.read_text()
        arms = numeric_case_arms(text)
        for status in ("5", "6"):
            with self.subTest(status=status):
                self.assertIn(
                    status, arms,
                    f"prerm has no arm for the installer's exit {status}, so it says the same "
                    "thing about both of its refusals",
                )
        self.assertNotEqual(
            arms["5"].strip(), arms["6"].strip(),
            "prerm says the same thing about a refusal that changed nothing and about a restore "
            "that did not finish",
        )
        for status in ("5", "6"):
            body = arms[status]
            with self.subTest(status=status, claim="what dpkg will do"):
                self.assertIn("still installed", body)
                self.assertIn("aborting", body.lower())
            with self.subTest(status=status, claim="not what it would do"):
                for false_claim in (
                    "the files are about to be removed",
                    "do not restart the machine",
                ):
                    self.assertNotIn(false_claim, text)
        # The distinction itself, in the words the two situations are told apart by.
        self.assertIn("nothing", arms["5"].lower())
        self.assertIn("still", arms["6"].lower())
        # And a default arm, because a status this script does not know is a
        # fact about the machine rather than about the script.
        self.assertIn("*", arms, "prerm has no default arm for an unrecognised status")

    def test_prerm_branches_on_the_installers_status_rather_than_its_own_success(self):
        # The status has to be captured, and `if ! cmd` cannot capture it: `$?`
        # after `!` is the status of the `!`, which is always zero. A script that
        # read it that way would print the same arm for every failure.
        text = PRERM.read_text()
        arm = arm_bodies(text)["remove"]
        self.assertIn('"$INSTALLER" uninstall', arm)
        self.assertNotIn("if ! \"$INSTALLER\" uninstall", arm)
        self.assertIn("status=$?", arm)
        self.assertIn('case "$status" in', arm)

    def test_prerms_exit_five_arm_claims_only_what_the_script_can_know(self):
        """The exit-5 arm used to assert "The machine's DNS is not this package's to change".

        That is a fact about the machine, and this script cannot establish it: the
        installer refuses on marker-absent, schema-unknown, UUID-missing or
        value-changed, and the first of those is a machine with a RECORD and no
        marker -- which the module itself documents as the more dangerous of the
        two states, because the record is the thing that would say what the
        connection was set to and it is the missing half. So the arm claims what
        the script can actually see: this run changed nothing, and the report above
        is what names the situation.
        """
        text = PRERM.read_text()
        body = numeric_case_arms(text)["5"]
        self.assertIn("changed NOTHING", body, "the arm no longer says the one thing it does know")
        self.assertIn("report above", body, "the arm no longer points at the deliverable")
        for unknowable in (
            "The machine's DNS is not this package's",
            "the machine's DNS is not this package's to change",
        ):
            with self.subTest(claim=unknowable):
                self.assertNotIn(unknowable, body)
        # And the weakening says WHY, so a later reader does not "fix" it back.
        self.assertIn("cannot ask", text)

    def test_postinst_does_not_promise_the_daemons_are_still_running_behind_a_failed_rollback(self):
        """postinst's failure arm said "whatever was enabled and running is still
        enabled and running" on an upgrade, and that became false when the
        transaction learned to RESTART a unit that was already running: a restart
        that fails leaves it down, and on an upgrade the connection is already
        127.0.0.1 by then, so the machine has no resolver at all.

        So the arm branches on the installer's STATUS rather than on `$2`, and the
        status it cannot account for gets a sentence that promises nothing. A script
        that kept the old sentence on a status-4 run would be telling an operator
        their resolver is fine on the one machine where it may not exist.
        """
        text = POSTINST.read_text()
        self.assertNotIn(
            "whatever was enabled and running is still",
            text,
            "postinst still claims every enabled and running unit survived a failed install, and "
            "a unit this package restarted may not have",
        )
        # The upgrade sentence is still there and still distinguishes the two
        # installs, because that distinction is real; only the promise is gone.
        self.assertIn("configured before", text)
        self.assertIn("the transaction is the authority on that", text)
        self.assertNotIn("so nothing has been changed", text)
        # And the message each arm is about, read from the arm rather than from the
        # paragraph, so a rewrap cannot make this pass. `postinst_transaction_run`
        # below is the real gate; these two assertions are here because they say
        # WHAT each arm has to say, and the run only says WHICH arm was reached.
        # `postinst_status_arms` RAISES on a shape it cannot read rather than
        # answering `{}`, so a script that un-nested these arms into an `if`/`elif`
        # chain fails here with the shape named instead of raising `KeyError` -- see
        # `ControlTests.test_status_arms_un_nested_into_an_if_chain_are_reported`.
        arms = postinst_status_arms(text)
        for status in ("3", "4"):
            self.assertIn(status, arms, f"postinst has no arm for the installer's exit {status}")
        self.assertIn("no resolver", arms["4"].lower())
        self.assertIn("emergency-rollback", arms["4"])
        self.assertIn("do not assume", arms["4"].lower())
        self.assertIn("DHCP lease generation", arms["3"])

    def test_postinst_succeeds_on_a_successful_install_and_reaches_the_timer_enable(self):
        """The install transaction SUCCEEDS and `postinst` exits 1, and STEP 5 -- the
        `systemctl enable` of the three timers -- is dead code.

        Both are one misplaced `fi`. `install_status` is captured in the `else` of
        `if "$INSTALLER" install`, and the `fi` that closed the capture was moved
        above the arms, so on a SUCCESSFUL run the variable was never assigned, the
        `${install_status:-1}` default made every test read as 1, the default arm
        printed "the install transaction exited 1, which is not a status this script
        knows", and the script reached the `exit 1` unconditionally.

        So `apt install mosdns-router` ran the whole transaction to success -- DNS
        taken over, marker written, daemons enabled and started -- and then dpkg
        recorded the package unpacked-but-unconfigured and told the operator the
        transaction had exited 1, which it had not. The three timers were never
        enabled on any install. `prerm` gets the same capture right, which is where
        the shape came from.

        This is behavioural on purpose. The three substring checks this replaced --
        `install_status=$?` is present, `if "$INSTALLER" install` is present, the
        status-4 body mentions "no resolver" -- were ALL TRUE of the broken script,
        and a substring cannot see a `fi` in the wrong place, so the suite reported
        green over a script that failed every configure. What it runs is the
        script's own lines from its STEP 4 header to its last, against a stub
        installer that changes nothing, and it reads the script's own exit status.
        """
        completed, calls = postinst_transaction_run(0)
        self.assertEqual(
            completed.returncode, 0,
            "postinst exits non-zero on a SUCCESSFUL install, so dpkg records the package "
            "unconfigured and the operator is told the transaction exited 1, which it did "
            f"not. The messages it printed were:\n{completed.stderr}",
        )
        enabled = [call for call in calls if call[:1] == ["enable"]]
        self.assertEqual(
            [call for call in enabled for call in call[1:] if call.endswith(".timer")],
            ["mosdns-cdn-optimizer.timer", "mosdns-cdn-health.timer",
             "mosdns-list-check.timer", "mosdns-watchdog.timer"],
            "a successful install did not reach STEP 5, or reached it with a different set of "
            f"timers. Every systemctl call it made was: {calls}",
        )
        # A successful install has nothing to try again, so the advice that follows a
        # refusal is not printed on it.
        self.assertNotIn("dpkg --configure mosdns-router", completed.stderr)
        self.assertNotIn("which is not a status", completed.stderr)

    def test_every_installers_status_reaches_its_own_arm_and_a_refusal_exits_non_zero(self):
        """One arm per status, the arm that status actually names, and a non-zero exit.

        A `fi` in the wrong place is invisible to a grep and visible to a run, so
        this runs the script. Each status gets its own assertion and its own message
        rather than one loop assertion, because a loop that failed would say which
        loop.
        """
        # One marker per arm, each inside a SINGLE `echo` line. A marker that spans
        # a wrap would make this test a test of where the file's text was broken,
        # which is a property a rewrap changes and nothing else.
        expectations = {
            1: (
                "refused this machine before it changed",
                "the installer's own EXIT_REFUSED, and the one this script sees most often",
            ),
            3: ("refused this machine and rolled back", "a transaction that rolled back"),
            4: ("did not finish AND its rollback did not", "a rollback that did not finish"),
            5: ("the installer's OWNERSHIP", "the ownership refusal"),
            6: ("RESTORE-INCOMPLETE", "a restore that did not finish"),
            42: ("exited 42, which is not a", "a status nothing else claims"),
        }
        every_marker = [markers[0] for markers in expectations.values()]
        for status, (marker, why) in expectations.items():
            with self.subTest(status=status, why=why):
                completed, calls = postinst_transaction_run(status)
                self.assertNotEqual(
                    completed.returncode, 0,
                    f"postinst exits 0 on a transaction that exited {status} ({why}), so dpkg "
                    "records a failed installation as configured",
                )
                others = [name for name in every_marker if name != marker]
                self.assertIn(
                    marker, completed.stderr,
                    f"the installer's {status} reached the wrong arm, or no arm:\n"
                    f"{completed.stderr}",
                )
                for other in others:
                    self.assertFalse(
                        other in completed.stderr,
                        f"the installer's {status} was described by another status's arm, "
                        "which tells the operator a different machine than the one they are on",
                    )
                # And it is not described as a status it did not exit. A capture that
                # loses the status makes every run land in the default arm saying 1,
                # which is how the Critical reported itself as a green suite. The
                # boundary is a word boundary, so `exited 4` does not match
                # `exited 42`.
                for other_status in expectations:
                    if other_status == status:
                        continue
                    self.assertIsNone(
                        re.search(rf"exited {other_status}\b", completed.stderr),
                        f"the installer's {status} was reported as having exited "
                        f"{other_status}",
                    )
                # And a refusal enables nothing, which is the sentence each arm makes.
                self.assertNotIn(
                    ["enable", "mosdns-cdn-health.timer"], calls,
                    f"a transaction that exited {status} still enabled the timers, and the arm "
                    f"that printed promised otherwise. Every systemctl call: {calls}",
                )
                self.assertIn("dpkg --configure mosdns-router", completed.stderr)

    def test_the_default_arm_keeps_the_promise_it_can_make_about_a_status_it_does_not_know(self):
        """Status 1 is `EXIT_REFUSED` -- the ordinary preflight refusal, and the status
        this script is most likely to see.

        It was reaching the DEFAULT arm, which called it "a status this script
        knows" nothing about: "the install transaction exited 1, which is not a
        status this script knows". The refusal part of that sentence is right --
        nothing about this machine's DNS can be promised from a transaction that
        refused before it changed anything -- and the "this script knows" part was
        false, which is the half an operator reads when they are trying to work out
        whether anything is wrong.
        """
        arms = postinst_status_arms(POSTINST.read_text())
        self.assertIn("1", arms, "postinst has no arm for the installer's own EXIT_REFUSED")
        self.assertNotIn(
            "not a status this script knows", arms["1"],
            "the arm for the installer's own preflight refusal still calls it unknown",
        )
        # The arm has to say the thing that IS true of a refusal, or the reader who
        # is told nothing can be promised learns nothing.
        self.assertIn("nothing", arms["1"].lower())

    def test_a_status_the_script_does_not_know_still_gets_the_unknown_arm(self):
        """…and the unknown-status arm has to survive, because the installer is a
        program this package does not own the whole exit table of. It also has to
        print the status it was GIVEN, not a default."""
        completed, _calls = postinst_transaction_run(42)
        self.assertIn("exited 42, which is not a", completed.stderr)
        self.assertNotEqual(completed.returncode, 0)

    def test_postinst_captures_the_installers_status_the_way_prerm_does(self):
        """`if ! cmd` cannot capture a status: `$?` after a `!` is the status of the
        `!`, which is always zero, so every arm would be the default one.

        Held on the TEXT as well as on the run, and for a different reason: the
        `${install_status:-1}` default is what made the misplaced `fi` a silent
        failure rather than a loud one. A capture that cannot be a bare `${...:-}`
        cannot default to 1, so the default cannot be reached with a status that
        was never assigned.
        """
        text = POSTINST.read_text()
        self.assertNotIn('if ! "$INSTALLER" install', text)
        self.assertIn('if "$INSTALLER" install', text)
        self.assertIn("install_status=$?", text)
        # Read through `executed_lines` because the comment above the capture NAMES
        # the default it is retiring, and a comment that names a construct is not a
        # use of it. What is forbidden is RUNNING a default.
        self.assertFalse(
            any("${install_status:-" in line for line in executed_lines(text)),
            "postinst still defaults the captured status, so a capture that never ran is "
            "indistinguishable from a transaction that exited 1",
        )

    def test_postrm_purges_only_when_purge_was_asked_for(self):
        """The data goes on `dpkg --purge` and not on `dpkg --remove`, and the
        ordering the installer's own `--purge` guarantees is already established
        because prerm has run the restore and failed loudly if it did not.

        Recorded deviation, and the reason it is a deviation: the plan asked for
        `postrm purge` to call the installer's `uninstall --purge`, and dpkg removes
        this package's files between `prerm remove` and `postrm purge`, so there is
        no installer here to call. The assertion below therefore holds the
        behaviour the plan was after -- purge on request, never on a plain removal,
        and never through a symlink -- rather than the spelling that cannot run.
        """
        text = POSTRM.read_text()
        self.assertIn("purge", text)
        self.assertIn("/var/lib/mosdns", text)
        self.assertIn("rm -rf /var/lib/mosdns", text)
        self.assertIn("-L /var/lib/mosdns", text, "the purge would follow a symbolic link")
        alternatives = shell_alternatives(text)
        for verb in ("remove", "upgrade", "abort-install", "abort-upgrade", "disappear", "purge"):
            with self.subTest(verb=verb):
                self.assertIn(
                    verb, alternatives,
                    f"postrm does not consider the {verb} case, so a removal may take a path it "
                    "was not written for",
                )
        # The purge case must be the one that removes the data, and the remove case
        # must not be: a plain removal that deleted the state directory would delete
        # the recorded backup of what this machine's DNS was set to. The bodies come
        # from `arm_bodies`, which computes them from the label SET, so the two verbs
        # that share one arm cannot hide a removal from this assertion -- which is the
        # way a hand-cut reader produced a false pass on the previous version of it.
        bodies = arm_bodies(text)
        self.assertIn("rm -rf /var/lib/mosdns", bodies["purge"])
        for label in ("remove", "disappear", "upgrade", "abort-install", "abort-upgrade"):
            with self.subTest(label=label):
                self.assertNotIn("rm -rf", bodies[label])

    def test_the_operator_has_a_purge_verb_that_does_both_halves_in_one_place(self):
        """The half postrm cannot do is still available, and it is the installer's
        own verb rather than a second implementation of the restore here."""
        self.assertIn("uninstall --purge", POSTRM.read_text())
        installer = (REPO / "installer" / "mosdns_installer.py").read_text()
        self.assertRegex(installer, r"def uninstall\([^)]*purge: bool = False")
        self.assertRegex(installer, r'arguments == \["uninstall"\]|arguments\[:1\] == \["uninstall"\]')

    def test_no_maintainer_script_installs_anything(self):
        for name, text in (
            ("postinst", POSTINST.read_text()),
            ("prerm", PRERM.read_text()),
            ("postrm", POSTRM.read_text()),
        ):
            with self.subTest(script=name):
                for forbidden in ("apt-get", "dpkg -i", "apt install", "debconf-set-selections"):
                    self.assertNotIn(forbidden, text)
                self.assertIn("set -e", text, f"{name} does not stop at its first failure")

    def test_the_maintainer_scripts_the_package_carries_are_the_repository_ones(self):
        for script, path in (
            ("postinst", POSTINST),
            ("prerm", PRERM),
            ("postrm", POSTRM),
        ):
            with self.subTest(script=script):
                self.assertEqual(
                    self.read(DEBIAN + "/" + script), path.read_text(),
                    f"DEBIAN/{script} is not the {path.name} this repository holds",
                )


# --- the tmpfiles entry ------------------------------------------------------


class TmpfilesTests(_Staged):
    """`/run/mosdns` is the one provisioned directory postinst cannot keep."""

    def test_the_tmpfiles_entry_recreates_run_mosdns_with_the_same_properties(self):
        findings = tmpfiles_findings(self.read(TMPFILES_PATH))
        self.assertEqual(
            findings, [],
            "the tmpfiles entry does not recreate the provisioned directory:\n"
            + "\n".join(f"  {finding}" for finding in findings),
        )

    def test_the_tmpfiles_entry_reaps_the_fourth_producer_staged_files(self):
        """`internal/candidate` stages where no existing pattern reaches.

        It is the one publisher in this project that does not name its temporary
        file with a leading dot and a `.tmp` suffix -- `os.CreateTemp(dir,
        filepath.Base(path)+".*")` -- so what it leaves in
        `/var/lib/mosdns/lists` is `cloudflare-prefixes.txt.1234567`. A
        publication that dies between the staging and the rename therefore leaves
        a file that neither `*.tmp` nor `.*.tmp` matches, in the one directory this
        entry did not reap at all.
        """
        findings = tmpfiles_findings(self.read(TMPFILES_PATH))
        self.assertEqual(
            findings, [],
            "the tmpfiles entry cannot do its job:\n" + "\n".join(f"  {f}" for f in findings),
        )

    def test_the_tmpfiles_acl_is_comma_separated(self):
        """Measured, not guessed: `parse_acl` splits the specification on commas, and
        a space-separated one is IGNORED with a diagnostic on stderr while the rest
        of the entry is applied -- so the directory is created with no ACL at all and
        every test that reads the text passes."""
        entries = tmpfiles_lines(self.read(TMPFILES_PATH))
        for _kind, path, fields in entries:
            if path != "/run/mosdns" or not _kind.startswith("a"):
                continue
            spec = " ".join(fields)
            with self.subTest(spec=spec):
                self.assertNotRegex(
                    spec, r"g::rwx\s+d:",
                    "the ACL separates its entries with a space, which systemd does not parse",
                )
                self.assertIn(
                    "g::rwx,d:g::rwx", spec,
                    "the ACL needs a COMMA between the access and the default group entry",
                )

    def test_the_tmpfiles_entry_names_run_mosdns_with_the_provisioned_mode(self):
        """Asserted separately from the findings above, because the obligation the
        plan states is a mode, a group and a default ACL rather than a directory."""
        entries = tmpfiles_lines(self.read(TMPFILES_PATH))
        creating = [
            entry for entry in entries
            if entry[1] == "/run/mosdns" and entry[0] in ("d", "D", "z", "Z")
        ]
        self.assertTrue(creating, f"{TMPFILES_PATH} never names /run/mosdns")
        for kind, _path, fields in creating:
            with self.subTest(kind=kind):
                self.assertEqual(
                    fields[:3], ["2770", "root", STATE_GROUP_NAME],
                    f"the /run/mosdns line is {' '.join([kind] + fields)}, "
                    f"want 2770 root {STATE_GROUP_NAME}",
                )
        acls = [entry for entry in entries if entry[1] == "/run/mosdns" and entry[0].startswith("a")]
        self.assertTrue(acls, f"{TMPFILES_PATH} sets no ACL on /run/mosdns")
        for _kind, _path, fields in acls:
            with self.subTest(spec=" ".join(fields)):
                self.assertIn("g::rwx", " ".join(fields))


# --- the hook, the installer and the manual pages ----------------------------


class InstalledProgramsTests(_Staged):
    """The three things the host runs that are not a systemd unit."""

    def test_the_dispatcher_hook_is_a_no_wait_hook_with_the_exact_invocation(self):
        self.assertInstalledFile(DISPATCHER_SCRIPT, 0o755)
        text = self.read(DISPATCHER_SCRIPT)
        self.assertTrue(text.startswith("#!"), "the hook has no interpreter line")
        commands = [line for line in text.splitlines() if line.startswith("Exec=")]
        self.assertEqual(
            len(commands), 1,
            "the hook has to declare exactly one Exec line, so a test can see what it runs",
        )
        command = commands[0]
        self.assertIn("python3", command)
        self.assertIn("-m mosdns_dhcp_bridge.cli", command)
        self.assertIn("--state-file /run/mosdns/dhcp-upstreams.json", command)
        self.assertIn("--lock-file /run/mosdns/dhcp-bridge.lock", command)
        self.assertIn("PYTHONPATH=" + BINARY_DIRECTORY, command)
        self.assertNotRegex(
            command, r"(^|\s)mosdns-dhcp-bridge(\s|$)",
            "the hook names a bare program, which resolves through $PATH in whatever environment "
            "NetworkManager happens to have",
        )
        self.assertRegex(
            text, r'(?m)^exec \$Exec "\$@"$',
            "the hook does not pass the dispatcher's own interface and action as separate "
            "arguments, so a name with a space in it would become two",
        )
        self.assertIn(
            "no-wait.d", DISPATCHER_SCRIPT,
            "the installed path is the blocking one",
        )

    def test_the_bridge_is_installed_where_the_hook_can_import_it(self):
        for module in BRIDGE_MODULES:
            with self.subTest(module=module):
                self.assertInstalledFile(BRIDGE_PACKAGE + "/" + module, 0o644)
        module = self.read(BRIDGE_PACKAGE + "/__init__.py")
        self.assertIn(
            "__all__", module,
            "the installed package directory has no __init__ re-exporting anything, so "
            "`-m mosdns_dhcp_bridge.cli` would run a module that is not a package member",
        )

    def test_the_installed_installer_script_is_a_program_that_runs_the_verbs(self):
        """mosdns-cdnctl execs this path, so it needs an interpreter line, the
        executable bit, and an entry point that turns a verb into an exit status."""
        self.assertInstalledFile(INSTALLER_SCRIPT, 0o755)
        text = self.read(INSTALLER_SCRIPT)
        self.assertTrue(text.startswith("#!"), "mosdns-cdnctl execs this path, so it needs a #!")
        self.assertIn('if __name__ == "__main__":', text)
        self.assertRegex(text, r"sys\.exit\(main\(sys\.argv\[1:\]\)\)")
        for verb in ("preflight", "install", "uninstall", "emergency-rollback"):
            with self.subTest(verb=verb):
                self.assertIn(verb, text)

    def test_every_unit_documents_itself_with_a_page_the_package_ships(self):
        for name in SHIPPED_UNITS:
            with self.subTest(unit=name):
                reference = unit_documentation(self.root, name)
                self.assertTrue(
                    reference.startswith("man:"), f"{name} documents itself as {reference!r}"
                )
                page = reference[len("man:"):]
                manual, _, section = page.partition("(")
                section = section.rstrip(")")
                installed = f"{MAN_ROOT}/man{section}/{manual}.{section}.gz"
                self.assertInstalledFile(installed, 0o644)
                body = gzip.decompress(self.read_bytes(installed)).decode("utf-8")
                # roff escapes a hyphen as a backslash-hyphen, and a page that spells
                # a name that way names the same page, so the escapes come out and the
                # case is folded before the name is compared.
                plain = body.replace("\\", "").lower()
                self.assertRegex(
                    plain, rf"(?m)^\.th\s+{re.escape(manual.lower())}\s+{re.escape(section)}\b",
                    f"{installed} does not open with a .TH line naming {manual}({section})",
                )

    def test_the_man_page_says_the_service_accounts_outlive_a_purge(self):
        """A purge removes three service accounts and two groups, and says so.

        It did not, once. The accounts were named `mosdns`, `mosdns-cdn` and
        `dnscrypt-proxy`, the third of which is the upstream dnscrypt-proxy package's
        own, so a `deluser` from here could take an identity another installed
        package still needed -- and the shipped answer was to leave all three behind
        and document that. Ruling 191(d) removed the reason instead of the risk: the
        names are now this package's own, so `postrm purge` removes them, and the
        manual page has to say that rather than the opposite.

        Both directions are held. A `postrm` that removes the accounts and a manual
        page that says they outlive the package is the defect in the other half, and
        it is the more likely one, because the old sentence is still true of some
        other package.
        """
        page = gzip.decompress(self.read_bytes(MAN_ROOT + "/man8/mosdns-router.8.gz")).decode()
        script = "\n".join(executed_lines(POSTRM.read_text()))
        # roff escapes the hyphens: the page says `mosdns\-router\-cdn`, and a
        # reader looking for the bare name finds nothing in a page that names the
        # account on every line. Escaped the way man(1) would, so a name with a
        # hyphen in it is comparable and a name without one still is.
        def roff(name):
            return name.replace("-", r"\-")
        self.assertIn(".SH ACCOUNTS AND REMOVAL", page)
        for account in (ROUTER_USER_NAME, CONTROL_USER_NAME, RESOLVER_USER_NAME):
            with self.subTest(account=account):
                self.assertIn(roff(account), page)
                self.assertIn(f'deluser --system "$user"', script)
        for name in (STATE_GROUP_NAME, RESOLVER_USER_NAME):
            with self.subTest(group=name):
                # The page escapes the hyphen; the script does not, because it is
                # shell and roff escapes mean nothing to it. Comparing the escaped
                # form against the script is how this case ended up asserting a
                # group name is absent from a shell script that names it plainly.
                self.assertIn(f'delgroup --system "$group"', script)
                self.assertIn(name, script)
                self.assertIn(roff(name), page)
        # The withdrawn sentence, in either spelling of the claim.
        for withdrawn in ("outlive the package", "which outlive the package"):
            self.assertNotIn(
                withdrawn, page,
                f"the manual page still says the accounts {withdrawn!r}, and a purge now removes them",
            )
        # And the two reasons a purge leaves one alone, both of which have to be in
        # the page as well as in the script: an operator whose account survived
        # needs to know which of the two applied and what to do about it.
        self.assertIn("left alone", page.lower())
        self.assertIn("deluser", page)
        self.assertIn("upstream", page)

    def test_the_three_named_manual_pages_are_the_three_this_package_documents(self):
        installed = sorted(
            path[len(MAN_ROOT) + 1:]
            for path, kind, _mode, _size in self.inventory
            if kind == "file" and path.startswith(MAN_ROOT + "/")
        )
        self.assertEqual(
            installed,
            ["man1/mosdns-cdnctl.1.gz", "man8/dnscrypt-proxy.8.gz", "man8/mosdns-router.8.gz"],
        )


# --- the build itself --------------------------------------------------------


class BuildTests(_Staged):
    """The script that produced all of it, and what it recorded about itself."""

    def test_the_build_manifest_records_the_toolchain_the_sources_and_the_binaries(self):
        text = self.read(BUILD_MANIFEST)
        self.assertIn("go1.25.8", text, "the manifest does not name the Go release")
        for name in ("go.mod", "go.sum"):
            with self.subTest(module=name):
                self.assertIn(name, text)
        self.assertIn("dnscrypt-proxy", text)
        self.assertIn(DNSCRYPT_VERSION, text)
        self.assertIn(DNSCRYPT_SOURCE_URL, text)
        # The FIELD, not "the digest appears somewhere". The shipped manifest printed
        # a real digest on the line below `archive sha256:` and the field itself said
        # `tag-commit:`, and a presence check passed while a person holding the .deb
        # read a label where a checksum belongs.
        digest = recorded_digest()[0]
        self.assertEqual(
            manifest_field(text, DIGEST_LABEL), digest,
            "the manifest's archive sha256 field is not the pinned archive's digest",
        )
        for binary in COMPILED:
            with self.subTest(binary=binary):
                actual = hashlib.sha256(self.read_bytes(binary)).hexdigest()
                self.assertIn(
                    actual, text,
                    f"{binary} is installed at {actual[:16]}… and the manifest does not record "
                    "that digest",
                )

    def test_the_shipped_binaries_carry_the_build_identity_not_dev_unknown_unknown(self):
        """`internal/buildinfo` exists so a shipped router can say which tree it is,
        and the first version of build-deb.sh injected no metadata at all -- so the
        router in the .deb reported dev/unknown/unknown while `make verify` was
        checking a DIFFERENT binary in build/. The flags are asserted here rather than
        the report, because a build that quietly drops them produces a package that
        looks right and answers nothing."""
        script = shell_code(BUILD_SCRIPT.read_text())
        for variable in ("Version=", "Revision=", "BuildTime="):
            with self.subTest(variable=variable):
                self.assertIn(
                    variable, script,
                    f"the build does not inject buildinfo.{variable.rstrip('=')} into the shipped "
                    "binaries",
                )
        self.assertIn("mosdns-router/internal/buildinfo", script)
        self.assertIn(
            '-ldflags "-s -w $METADATA_LDFLAGS"', script,
            "the Go build does not pass the metadata flags at all",
        )
        manifest = self.read(BUILD_MANIFEST)
        for field in ("version:", "revision:", "build time:"):
            with self.subTest(field=field):
                self.assertIn(field, manifest, f"the manifest records no {field}")
        # And the identity in the manifest is not the placeholder: `dev` and
        # `unknown` are what a build with no metadata injection and no git checkout
        # produce, and they are the two values this assertion exists to catch.
        for placeholder in ("revision:         unknown", "version:          dev"):
            with self.subTest(placeholder=placeholder):
                self.assertNotIn(placeholder, manifest)

    def test_the_shipped_router_reports_the_build_identity_it_was_given(self):
        """Run the SHIPPED file through the project's own build-info check.

        A flag that is present in the build script and absent from the binary is the
        failure a text assertion cannot see, and it is the one this task had:
        `build-deb.sh` passed `-s -w` and no metadata, so the router in the .deb
        answered with the compiled-in placeholders while `make verify` was checking a
        DIFFERENT binary in build/. `mosdns-router build-info` is a read-only
        subcommand that binds no socket and reaches nothing, and `internal/buildinfo`'s
        `Check` is the same function `make verify-build-info` uses -- so this asks the
        shipped bytes the same question the gate asks the built ones.
        """
        # `build-info` is a subcommand of the ROUTER, which is the program whose
        # identity an operator asks about; the control tool has no such verb and no
        # use for one.
        shipped = str(Path(self.root) / ROUTER_BINARY.lstrip("/"))
        result = subprocess.run(
            [shipped, "build-info"], capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(
            result.returncode, 0,
            f"the packaged router cannot be interrogated: {result.stderr[:300]}",
        )
        info = json.loads(result.stdout)
        for field in ("version", "revision", "build_time"):
            with self.subTest(field=field):
                self.assertNotIn(
                    str(info.get(field, ""))[:3], ("dev", "unk"),
                    f"the shipped router reports {field}={info.get(field)!r}, which is a "
                    "compiled-in placeholder",
                )
        self.assertRegex(str(info.get("revision", "")), r"^[0-9a-f]{7,}")
        # And the identity the manifest recorded is the identity the binary carries:
        # a manifest that described a different build would be a manifest nobody could
        # use to say what a .deb is.
        manifest = self.read(BUILD_MANIFEST)
        self.assertIn(f"revision:         {info['revision']}", manifest)
        self.assertIn(f"version:          {info['version']}", manifest)

    def test_the_manifest_records_the_pinned_tag_commit_not_only_the_archive_digest(self):
        """A digest proves the archive is the same bytes every time and says nothing
        about whether those bytes are what the tag points at today. With the commit
        beside it, a future divergence is attributable to a re-tag rather than to a
        transport change -- and a re-tag is a change somebody has to look at."""
        commit = recorded_commit()
        self.assertIn(
            f"# tag-commit: {commit}", SOURCE_DIGEST.read_text(),
            "packaging/debian/dnscrypt-proxy.sha256 records no tag commit, so a re-tag upstream "
            "and a corrupted download would be indistinguishable",
        )
        # In the manifest it is a FIELD OF ITS OWN, read by label for the same reason
        # the digest is: its whole purpose is being attributable later, and a value
        # that has to be found by searching the file for a 40-hex string is not.
        self.assertEqual(
            manifest_field(self.read(BUILD_MANIFEST), COMMIT_LABEL), commit,
            "the manifest does not record the pinned tag's commit under its own field",
        )
        self.assertIn("tag-commit:", shell_code(BUILD_SCRIPT.read_text()))

    def test_the_manifest_records_the_module_digests_that_were_built(self):
        text = self.read(BUILD_MANIFEST)
        for committed in ("go.mod", "go.sum"):
            with self.subTest(module=committed):
                digest = hashlib.sha256((REPO / committed).read_bytes()).hexdigest()
                self.assertIn(
                    digest, text,
                    f"the manifest does not record the {committed} digest that was built against",
                )

    def test_the_programs_the_build_verifies_with_are_the_programs_it_ships(self):
        """Same source, same flags, same architecture, differing only in `-o`.

        This is the claim the task report's first version got wrong: it said the three
        executed binaries were the shipped ones on an amd64 host, and for
        mosdns-router and mosdns-cdnctl that was FALSE, because this script passed
        `-s -w` and no `METADATA_LDFLAGS` while the Makefile passed both -- two
        different compilations of one source, one of which shipped and one of which
        the gate verified. With the metadata injected it is true, and MEASURED: two
        builds of cmd/mosdns-cdnctl with identical flags and an identical BuildTime
        produce digest 4b1bec2748665482fb6db7a7d1f4c850e0419ac3d94a174e7d88b141c617ea6c
        on both sides. The claim is asserted here as a property of the build rather
        than left as prose, because prose is what let it drift."""
        script = shell_code(BUILD_SCRIPT.read_text())
        # One function builds all three, and the flags it passes are the flags the
        # shipped copy and the verifier copy both get.
        self.assertEqual(
            script.count("build_go_binary ./cmd/"), 3,
            "the router, the control tool and the verifier's control tool are not all built by "
            "one function, so the shipped and verified copies can drift apart again",
        )
        self.assertEqual(
            script.count('build_go_binary ./cmd/mosdns-cdnctl "$verifier_dir/mosdns-cdnctl" "$HOST_ARCH"'),
            1,
        )
        self.assertIn("-ldflags \"-s -w $METADATA_LDFLAGS\"", script)
        # dnscrypt-proxy has no buildinfo of ours, so its two builds differ by nothing
        # at all -- same source, same flags, same arch.
        self.assertEqual(
            script.count('-mod=vendor -trimpath -ldflags "-s -w"'), 2,
            "the resolver is not built with one set of flags for the package and another for "
            "the verification",
        )

    def test_a_decoy_line_above_the_digest_does_not_become_the_digest(self):
        """The control for the reader, and the shape of the bug this round fixed.

        The shipped build script's reader took the first non-comment line's first
        field. The moment a labelled line was added above the digest -- a `tag-commit:`
        line, recorded for a reason -- that reader returned the literal string
        `tag-commit:`, its own non-empty guard was satisfied by a label, and the
        BUILD-MANIFEST shipped in the .deb printed `archive sha256:   tag-commit:`
        with the real digest on the NEXT line, where a person reading the package
        would not see it. Provenance verification was unaffected: `sha256sum -c` still
        checked the archive and exited 0.

        A pin is a file that GAINS lines, so the reader is asked about four extra ones
        above the digest and has to return the digest for all of them. The build
        script's own sed is run on the same file, because a test that proved the
        TEST's reader correct while the SHIPPED one stayed positional is exactly what
        the first version of this test did.
        """
        real = SOURCE_DIGEST.read_text()
        digest = recorded_digest()[0]
        decoys = [
            "tag-commit: 30c0a9e91c12a15c081ac90546dd657c4ab98fbc",
            "source: https://example.invalid/dnscrypt-proxy-2.1.18.tar.gz",
            "fetched: 2026-09-27",
            "note: the digest below is the one that matters",
        ]
        head, _, tail = real.rpartition("\n" + digest)
        self.assertTrue(tail, "the pin no longer ends with the digest line")

        for decoy in decoys:
            with self.subTest(decoy=decoy):
                planted = f"{head}\n{decoy}\n{digest}{tail}"
                self.assertEqual(
                    shipped_reader_digest(planted), digest,
                    "a labelled line above the digest changed the digest the build script reads",
                )
                # And the TEST's reader, which is the one every other assertion here
                # and in the build class use.
                self.assertEqual(pin_digest(planted, "the planted pin")[0], digest)

    def test_the_pin_is_clean_for_the_command_its_own_comment_names(self):
        """`sha256sum -c packaging/debian/dnscrypt-proxy.sha256` is the command the
        file's comment tells a reader to run. A bare `tag-commit: <40 hex>` line above
        the digest made it print `WARNING: 1 line is improperly formatted` -- on a
        checksum file, from a line that is not a checksum. Every non-comment,
        non-blank line is now a sha256sum line and nothing else, which is why the tag
        commit lives in a COMMENT."""
        entries = [
            line for line in SOURCE_DIGEST.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertTrue(entries, "the pin records nothing")
        for line in entries:
            with self.subTest(line=line):
                self.assertIsNotNone(
                    SHA256SUM_LINE.match(line.strip()),
                    f"{line!r} is not a sha256sum line, so `sha256sum -c` on this file warns",
                )
        self.assertIn(
            "sha256sum -c", SOURCE_DIGEST.read_text(),
            "the pin no longer tells the reader how to check it",
        )

    def test_the_recorded_source_digest_is_a_digest_of_the_named_archive(self):
        fields = recorded_digest()
        self.assertEqual(
            len(fields), 2, f"{SOURCE_DIGEST.name} is not a digest and a file name"
        )
        self.assertRegex(fields[0], r"^[0-9a-f]{64}$", f"{fields[0]!r} is not a SHA-256")
        self.assertEqual(fields[1], DNSCRYPT_ARCHIVE)
        self.assertIn(
            DNSCRYPT_SOURCE_URL, SOURCE_DIGEST.read_text(),
            "the recorded digest does not say where the archive comes from",
        )

    def test_the_verification_steps_run_a_build_this_machine_can_execute(self):
        """A cross build ships the TARGET's binaries, and the render and the
        resolver's `-check` are steps the BUILD MACHINE runs -- so they must run the
        host's own build of the same pinned sources, or `make package --arch arm64`
        fails on an amd64 host with "Exec format error", which is a fact about the
        host and not about the package. Read as two properties rather than one: the
        shipped path is the target's, and the path the build RUNS is the host's."""
        # `assertTrue` and not `assertRegex`: a failing regex assertion prints the
        # whole script, and a reviewer reading four hundred lines of build script to
        # find out which one line was wrong is not being helped.
        script = shell_code(BUILD_SCRIPT.read_text())
        for needle, why in (
            ('GOARCH="$3"', "the Go build takes no architecture argument"),
            ('build_go_binary ./cmd/mosdns-router "$BUILD/$PACKAGE.router" "$ARCH"',
             "the shipped router is not built for the architecture being packaged"),
            ("GOHOSTARCH", "the build never asks what it is running on"),
            ("verifier_dir=$BUILD/verifier-$HOST_ARCH",
             "the programs the build runs are not in a directory named for the host's architecture"),
            ('"$verifier_dir/mosdns-cdnctl" render',
             "the render does not run the host's build of the control tool"),
            ('"$verifier_dir/dnscrypt-proxy" -check',
             "the resolver's -check does not run the host's build of the resolver"),
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, script, why)
        self.assertNotIn(
            '"$STAGE/usr/lib/mosdns-router/mosdns-cdnctl" render', script,
            "the render runs the SHIPPED control tool, which a cross build cannot execute",
        )

    def test_the_redundant_postinst_path_is_a_link_to_the_one_script(self):
        """`packaging/mosdns-router.postinst` is in this plan's file map and
        `packaging/debian/postinst` is too, which is one script and two required
        paths. It is a COMMITTED SYMLINK rather than a second copy, and it is
        committed because a build script that created it would be writing into the
        source tree on every run: deleting the link would then break nothing, satisfy
        nothing, and come back unannounced. A test is what makes it real."""
        redundant = REPO / "packaging" / "mosdns-router.postinst"
        self.assertTrue(
            redundant.is_symlink(),
            f"{redundant.relative_to(REPO)} is not a symbolic link, so the plan's two required "
            "paths are either two copies of a maintainer script or one missing one",
        )
        self.assertEqual(
            os.readlink(redundant), "debian/postinst",
            "the link does not point at packaging/debian/postinst",
        )
        self.assertTrue(
            (redundant.parent / os.readlink(redundant)).is_file(),
            "the link's target is not a file",
        )
        self.assertNotIn(
            "ln -sf", shell_code(BUILD_SCRIPT.read_text()),
            "the build script creates the link, so it writes into the source tree on every run",
        )

    def test_the_build_script_refuses_to_build_an_unverified_source_tree(self):
        script = shell_code(BUILD_SCRIPT.read_text())
        self.assertIn("sha256sum", script)
        self.assertIn("dnscrypt-proxy.sha256", script)
        self.assertIn("CGO_ENABLED=0", script)
        self.assertIn("dpkg-deb", script)
        self.assertIn("--root-owner-group", script)
        self.assertIn("--build", script)
        self.assertIn("render", script, "the shipped documents are not rendered by the build")
        # `assertIn` on a whole script, so the failures that would dump four hundred
        # lines are the two below, which are short and say what is missing.
        self.assertNotIn("dpkg -i", script, "the build script must not install what it builds")
        self.assertNotIn("apt-get", script)
        self.assertTrue(
            "--build" in script and "--root-owner-group" in script,
            "the build does not hand dpkg-deb a staging root and a --root-owner-group",
        )

    def test_the_build_script_installs_nothing_on_the_host(self):
        # The comments, not the commands: a script whose header says "there is no
        # dpkg -i here" must not be caught by the check that says there is no dpkg -i
        # here, or the only way to satisfy both is to delete the explanation.
        script = shell_code(BUILD_SCRIPT.read_text())
        for forbidden in ("systemctl", "nmcli", "service ", "update-rc.d", "invoke-rc.d"):
            with self.subTest(token=forbidden):
                self.assertNotIn(
                    forbidden, script,
                    f"the build script contains {forbidden!r}: building a package must not touch "
                    "the host it is built on",
                )

    def test_the_package_would_be_readable_by_dpkg(self):
        """The staging root is a package: the control file names this package, and
        every payload file is in the digest file dpkg verifies on unpack."""
        md5sums = self.read(DEBIAN + "/md5sums")
        listed = {}
        for line in md5sums.splitlines():
            digest, _, path = line.partition("  ")
            listed["/" + path.lstrip("./")] = digest
        payload = sorted(
            path for path, kind, _mode, _size in self.inventory
            if kind == "file" and not path.startswith(DEBIAN)
        )
        self.assertEqual(sorted(listed), payload, "md5sums and the payload are different sets")
        for path, digest in listed.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.md5(self.read_bytes(path)).hexdigest(), digest)


# --- the artifact ------------------------------------------------------------


class BuiltPackageTests(_Staged):
    """The .deb the staging root is built into, read with dpkg's own tools.

    The staging root is the only thing under test, and this class is what shows that
    the artifact follows it: it builds the package from the very tree every other
    test asserted, then asks dpkg what it made. A staging root dpkg would refuse, or
    a package whose payload differs from the tree, is a package nobody has looked at.

    The metadata is read out of the package's own CONTROL member, with
    ``dpkg-deb -e``, rather than out of ``dpkg-deb --info``. That is not a
    preference: ``--info`` prints a human-readable report whose control-file listing
    sits above the stanza in the same indented shape a continuation line has, so a
    stanza parser reads the real ``Package:`` line as a continuation of the size
    header and reports a package with no Package field. The report is still asserted,
    for the two things only it can say -- that the maintainer scripts are in the
    control member and that they are executable.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.deb = os.path.join(
            _SHARED["directory"], f"mosdns-router_0.1.0_{_built_architecture()}.deb"
        )
        built = subprocess.run(
            ["dpkg-deb", "--root-owner-group", "--build", cls.root, cls.deb],
            capture_output=True, text=True, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        if built.returncode != 0:
            raise AssertionError(
                f"dpkg-deb --build exited {built.returncode}: {built.stdout}{built.stderr}"
            )
        cls.scratch = scratch_directory("mosdns-package-control-archive.")
        cls.extracted = os.path.join(cls.scratch, "control")
        extracted = subprocess.run(
            ["dpkg-deb", "-e", cls.deb, cls.extracted],
            capture_output=True, text=True, check=True,
            env={**os.environ, "LC_ALL": "C"},
        )

    def dpkg(self, *arguments):
        """One dpkg-deb call, in the C locale.

        LC_ALL=C because dpkg-deb translates its own output, and a test that greps an
        English label fails on a host whose locale is not English -- for the wrong
        reason, which is the worst kind of gate failure.
        """
        return subprocess.run(
            ["dpkg-deb", *arguments],
            capture_output=True, text=True, check=True,
            env={**os.environ, "LC_ALL": "C"},
        )

    def control_file(self):
        return (Path(self.extracted) / "control").read_text(encoding="utf-8")

    def test_dpkg_reads_the_metadata_the_test_expects(self):
        fields = control_fields(self.control_file())
        for name, want in CONTROL_FIELDS.items():
            with self.subTest(field=name):
                self.assertEqual(fields.get(name.lower()), want)
        self.assertEqual(
            fields.get("architecture"), _built_architecture(),
            "the package's Architecture is not the architecture it was built for",
        )
        self.assertGreater(int(fields.get("installed-size", "0")), 0)
        self.assertTrue(fields.get("maintainer"))
        self.assertTrue(fields.get("description"))

    def test_the_artifact_is_the_control_file_the_test_asserted(self):
        """Byte equality, not a field-by-field reading: the package must carry the
        metadata this repository holds, and a field-by-field reading cannot see a
        field nobody asked about."""
        self.assertEqual(
            self.control_file(),
            (Path(self.root) / "DEBIAN" / "control").read_text(encoding="utf-8"),
            "the control member of the .deb is not the staged DEBIAN/control",
        )

    def test_the_conffiles_the_package_declares_are_the_ones_it_carries(self):
        listed = [
            line.strip()
            for line in (Path(self.extracted) / "conffiles").read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(sorted(listed), sorted(EDITABLE_DOCUMENTS))
        self.assertNotIn("#", "".join(listed))

    def test_dpkg_prints_the_maintainer_scripts_as_executable(self):
        """dpkg runs these, and a control file that is not executable is a package
        whose install does nothing on some dpkg versions. The `*` is dpkg's own
        marker for an executable control file, and it is absent from the changelog
        line, so the comparison below is what gives the three assertions meaning."""
        stdout = self.dpkg("--info", self.deb).stdout
        for script in ("postinst", "prerm", "postrm"):
            with self.subTest(script=script):
                self.assertRegex(stdout, rf"\*\s+{script}\b")
        self.assertRegex(stdout, r"lines\s+changelog\b")
        for script in ("postinst", "prerm", "postrm"):
            with self.subTest(script=script):
                self.assertEqual(
                    inventory_get(self.inventory, DEBIAN + "/" + script)[2], 0o755,
                    f"the staged {script} is not executable, so dpkg would refuse to run it",
                )

    def test_the_package_contents_are_the_staged_tree(self):
        """The payload member only: DEBIAN lives in the control member, which
        dpkg-deb --contents does not print and the test above reads directly."""
        result = self.dpkg("--contents", self.deb)
        inside = set()
        for line in result.stdout.splitlines():
            fields = line.split(None, 5)
            if len(fields) < 6 or not fields[5].startswith("."):
                continue
            if not fields[0].startswith("-"):
                continue  # a directory, and the staging-root test knows what those are
            inside.add("/" + fields[5].lstrip("./"))
        staged = {
            path for path, kind, _mode, _size in self.inventory
            if kind == "file" and not path.startswith(DEBIAN)
        }
        self.assertEqual(sorted(inside - staged), [], "the package holds a file the tree does not")
        self.assertEqual(sorted(staged - inside), [], "the tree holds a file the package does not")


# --- the controls ------------------------------------------------------------


class ControlTests(unittest.TestCase):
    """Each check above, asked about a tree that is wrong on purpose.

    A gate that cannot fail is not a gate, and this suite is the gate that decides
    whether a package may put a machine on somebody else's resolver. So each of
    the ways this package can be wrong is manufactured here and the corresponding
    check is asserted to notice.

    THE LIST, and it is a list of what this class HOLDS rather than a theme. It is
    all thirty of this class's `test_` methods, one entry each, so it can be counted
    against them; the two groups are what the mutation plants. On the STAGED TREE,
    twenty: a missing executable, a missing file, a loose mode, a tight mode, a
    planted resolver address the content scan reports, that same planted address
    found through the METHOD that scans for them, an unlisted address the denylist
    could not have named, a planted middlebox, a planted DoH endpoint, a compressed
    document, an unreadable blob, a shipped state file, a missing tmpfiles reap
    pattern, a reversed tmpfiles entry, a tmpfiles entry with no default ACL, a
    space-separated ACL, a reap pattern that matches too much, a routing document
    that is not the render, a manifest entry that is not shipped, and a provider-scan
    exemption that has grown. On the MAINTAINER SCRIPTS, ten: a dpkg Policy 6.5 verb
    that is missing, a published pair an operator re-pinned, a capture closed before
    its arms, an `if`/`elif` chain in place of the `case`, a hard-coded capture, the
    timers enabled before the transaction, a reversed provisioning order, a directory
    created without its group, the mode this plan itself first named, and prerm's two
    refusals flattened into one sentence.

    FOUR OF THOSE THIRTY are about a third thing -- a VERIFIER rather than a tree or a
    script, because a reader that cannot read a shape is also a gate that cannot fail
    -- and they are named here because the group is a SUBSET of the two above and
    not a third set of cases: the missing-policy-verb case
    (`assertMethodFails` dropped the script substitutions), the
    timers-enabled-before-the-transaction case (the swap helper matched a comment),
    the operator-re-pinned-pair case (`unconditional_publish` was asserted against a
    token it had itself removed), and the capture-closed-before-its-arms case
    (`capture_closed_early` moved a different `fi` than the one it named). Each of
    those four existed in some earlier form of this suite and every one of them was a
    control that could not have failed, because the mutation it built was not the
    defect the gate was written for. The rule those four make is the only thing this
    class is for, and it is the fifth time this project has had to write it down.
    """

    @classmethod
    def setUpClass(cls):
        source = shared_staging()
        problem = build_problem()
        if problem is not None:
            raise AssertionError(problem)
        cls.original = source
        cls.copies = {}

    def assertMethodFails(self, case_class, method, **kwargs):
        """Assert that a test METHOD fails once the inputs it reads are replaced.

        ``staged=`` replaces a file in a private copy of the staging root; anything
        else is a maintainer script held in memory. The method is called directly,
        which is the whole point: a control that called the helper instead would be a
        second implementation of the check rather than evidence about the first.

        BOTH kinds apply at once, and they used not to: the staged branch returned
        before the script substitutions were made, so a control that wanted to
        plant a file AND hand the method a different maintainer script silently
        tested the real script. A control that cannot deliver a replacement to the
        code under test reports success while testing nothing.
        """
        staged = kwargs.pop("staged", None)
        if staged is None:
            with scripts_replaced(**kwargs):
                case = case_class(method)
                with self.assertRaises(AssertionError):
                    getattr(case, method)()
            return
        target = os.path.join(scratch_directory("mosdns-method-control."), "staging")
        shutil.copytree(self.original, target, symlinks=True)
        for relative, contents in staged.items():
            planted = Path(target) / relative.lstrip("/")
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_text(contents, encoding="utf-8")
        root = Path(target)
        with scripts_replaced(**kwargs):
            case = case_class(method)
            case.root = str(root)
            case.inventory = staged_inventory(root)
            with self.assertRaises(AssertionError):
                getattr(case, method)()

    def copy(self, mutate):
        """A private copy of the staged tree with ``mutate`` applied to it."""
        target = os.path.join(scratch_directory("mosdns-package-control."), "staging")
        shutil.copytree(self.original, target, symlinks=True)
        mutate(Path(target))
        return target, staged_inventory(target)

    # -- the four ways a package is wrong -----------------------------------

    def test_a_missing_executable_is_reported_by_the_exec_path_check(self):
        wanted = unit_exec_paths(self.original)
        self.assertIn(ROUTER_BINARY, wanted)
        _root, inventory = self.copy(
            lambda stage: os.remove(stage / ROUTER_BINARY.lstrip("/"))
        )
        missing = [
            path for path in wanted if inventory_get(inventory, path) is None
        ]
        self.assertEqual(
            missing, [ROUTER_BINARY],
            "a binary a unit's ExecStart names is absent and nothing noticed",
        )

    def test_a_missing_file_is_reported_by_the_mode_table(self):
        _root, inventory = self.copy(
            lambda stage: os.remove(stage / TMPFILES_PATH.lstrip("/"))
        )
        findings = mode_findings(inventory, MODES)
        self.assertIn(
            f"{TMPFILES_PATH} is not installed at all, want mode 0o644", findings,
            "an absent file passes the mode table",
        )

    def test_a_loose_mode_is_reported_by_the_mode_table(self):
        _root, inventory = self.copy(
            lambda stage: os.chmod(stage / DISPATCHER_SCRIPT.lstrip("/"), 0o777)
        )
        findings = mode_findings(inventory, MODES)
        self.assertIn(
            f"{DISPATCHER_SCRIPT} is {oct(0o777)}, want {oct(0o755)}", findings,
            "a world-writable dispatcher hook passes the mode table",
        )

    def test_a_tight_mode_is_reported_by_the_mode_table(self):
        _root, inventory = self.copy(
            lambda stage: os.chmod(stage / ROUTER_BINARY.lstrip("/"), 0o700)
        )
        findings = mode_findings(inventory, MODES)
        self.assertIn(
            f"{ROUTER_BINARY} is {oct(0o700)}, want {oct(0o755)}", findings,
            "a mode nobody can read as another user passes the mode table",
        )

    # -- the two ways a package can put a machine on the wrong resolver ------

    def test_a_planted_resolver_address_is_found_by_the_method_that_scans_for_them(self):
        """The METHOD, against a staged copy carrying one planted address.

        The address is one the DENYLIST covers, because that is the only thing this
        control can prove about this method. An address the denylist does not cover is
        the allowlist's business, and the control below plants exactly those.
        """
        address = "223.5.5.5"
        self.assertIn(
            address, FORBIDDEN_ADDRESSES,
            "the control plants an address the denylist does not list, so it proves nothing",
        )
        self.assertMethodFails(
            ForbiddenContentTests,
            "test_no_forbidden_resolver_address_appears_anywhere_in_the_package",
            staged={CONFIG_DIRECTORY + "/mosdns.yaml": f"listen: {address}:53\n"},
        )

    def test_an_unlisted_address_is_found_by_the_allowlist_method(self):
        """The allowlist's own control, and the one the denylist could not have: six
        addresses that are on neither list, four of them IPv4 and two IPv6, none of
        which the twelve-literal denylist would have named."""
        for address in ("1.2.4.8", "210.2.4.8", "211.98.20.20", "221.5.88.88", "2400:3200::1", "2402:4e00::"):
            with self.subTest(address=address):
                self.assertNotIn(
                    address, "".join(FORBIDDEN_ADDRESSES),
                    f"{address} is already on the denylist, so this control proves nothing about "
                    "the allowlist",
                )
                # The shape is an upstream line rather than a `listen:` line, because
                # `listen: <ipv6>:53` is ambiguous text and a control that plants an
                # unparseable line would be testing the tokeniser's tolerance rather
                # than the allowlist.
                self.assertMethodFails(
                    ForbiddenContentTests,
                    "test_every_address_a_shipped_document_names_is_one_this_package_may_configure",
                    staged={CONFIG_DIRECTORY + "/mosdns.yaml": f"  - addr: {address}\n"},
                )

    def test_a_planted_resolver_address_is_reported(self):
        path = CONFIG_DIRECTORY + "/mosdns.yaml"
        with tempfile.TemporaryDirectory(
            prefix="mosdns-planted.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            planted = Path(scratch) / path.lstrip("/")
            planted.parent.mkdir(parents=True)
            planted.write_text("listen: 223.5.5.5:53\n", encoding="utf-8")
            findings = content_findings(
                scratch, [(path, "file", 0o644, 21)], FORBIDDEN_ADDRESSES,
            )
            self.assertEqual(
                findings, [("/etc/mosdns/mosdns.yaml", "223.5.5.5")],
                "a domestic public resolver in a shipped document is not reported",
            )

    def test_a_planted_middlebox_is_reported(self):
        with tempfile.TemporaryDirectory(
            prefix="mosdns-planted.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            planted = Path(scratch) / DISPATCHER_SCRIPT.lstrip("/")
            planted.parent.mkdir(parents=True)
            planted.write_text("#!/bin/sh\nexec mitmproxy -p 53\n", encoding="utf-8")
            findings = content_findings(
                scratch, [(DISPATCHER_SCRIPT, "file", 0o755, 30)], FORBIDDEN_PROVIDERS,
            )
            self.assertEqual(
                findings, [(DISPATCHER_SCRIPT, "mitmproxy")],
                "a TLS-intercepting middlebox in the dispatcher hook is not reported",
            )

    def test_a_planted_doh_endpoint_is_reported(self):
        path = CONFIG_DIRECTORY + "/dnscrypt-proxy.toml"
        with tempfile.TemporaryDirectory(
            prefix="mosdns-planted.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            planted = Path(scratch) / path.lstrip("/")
            planted.parent.mkdir(parents=True)
            planted.write_text("server_names = ['cloudflare-dns.com']\n", encoding="utf-8")
            findings = content_findings(scratch, [(path, "file", 0o644, 34)], FORBIDDEN_PROVIDERS)
            self.assertEqual(findings, [(path, "cloudflare-dns.com")])

    def test_an_unreadable_blob_is_reported_rather_than_skipped(self):
        # A path that is NOT one of the compiled binaries, because those are exempt
        # from the content scan and an exempt path would report nothing.
        path = DATA_DIRECTORY + "/unexpected.bin"
        with tempfile.TemporaryDirectory(
            prefix="mosdns-planted.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            planted = Path(scratch) / path.lstrip("/")
            planted.parent.mkdir(parents=True)
            planted.write_bytes(b"\xff\xfe\x00\x01")
            findings = content_findings(scratch, [(path, "file", 0o755, 4)], FORBIDDEN_ADDRESSES)
            self.assertEqual(findings, [(path, "<not utf-8 text>")])

    def test_a_compressed_document_is_decompressed_and_scanned(self):
        """A needle hidden in a manual page is a needle this project would ship."""
        path = MAN_ROOT + "/man8/mosdns-router.8.gz"
        body = b".TH MOSDNS-ROUTER 8\n.br\nlisten 223.5.5.5\n"
        with tempfile.TemporaryDirectory(
            prefix="mosdns-planted.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            planted = Path(scratch) / path.lstrip("/")
            planted.parent.mkdir(parents=True)
            planted.write_bytes(gzip.compress(body))
            findings = content_findings(
                scratch, [(path, "file", 0o644, len(body))], FORBIDDEN_ADDRESSES,
            )
            self.assertEqual(
                findings, [(path, "223.5.5.5")],
                "a resolver address compressed into a manual page is not reported",
            )

    # -- the ways the package's own promises can be broken ------------------

    def test_a_shipped_state_file_is_reported(self):
        with tempfile.TemporaryDirectory(
            prefix="mosdns-planted.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            runtime = Path(scratch) / "var" / "lib" / "mosdns" / "runtime"
            runtime.mkdir(parents=True)
            (runtime / "ech-state.json").write_text("{}\n", encoding="utf-8")
            shipped = [
                path for path, kind, _mode, _size in staged_inventory(scratch)
                if path.startswith("/var/lib") and kind != "directory"
            ]
            self.assertEqual(shipped, ["/var/lib/mosdns/runtime/ech-state.json"])

    def test_a_missing_policy_verb_is_reported(self):
        """Round 2's control for the verb table, run against the METHOD.

        Removing `failed-upgrade` from postrm's `case` list is the edit that shipped
        in round 1. The method is what a reviewer reads, so the method is what has to
        fail -- and it has to fail while the substitution is in place, which is the
        part that did not work in the version this control was first written as.
        `SCRIPTS` was a dict of Paths bound at import, so rebinding the module globals
        left the method reading the file on disk and it passed.
        """
        good = POSTRM.read_text()
        self.assertEqual(policy_verb_findings("postrm", good), [])
        broken = good.replace("disappear | failed-upgrade)", "disappear)")
        self.assertNotIn("failed-upgrade)", broken, "the mutation changed nothing")
        self.assertTrue(
            any("failed-upgrade" in finding for finding in policy_verb_findings("postrm", broken)),
            "the reader does not name the missing verb, so the control cannot say what it caught",
        )
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_every_maintainer_script_handles_every_call_dpkg_can_make",
            postrm=broken,
        )
        # And the substitution reached the name the method iterates, rather than a
        # second copy of the script. A control whose mechanism cannot deliver a
        # replacement to the code under test reports success while testing nothing.
        with scripts_replaced(postrm=broken):
            self.assertIs(script_paths()["postrm"], SCRIPTS["postrm"])
            self.assertIn("failed-upgrade", SCRIPTS["postrm"].read_text() or "")
            self.assertTrue(policy_verb_findings("postrm", SCRIPTS["postrm"].read_text()))

    def test_a_pair_an_operator_re_pinned_is_reported_by_the_method(self):
        """The control for the published-pair gate, and the reason it is behavioural.

        The old gate only grepped for the re-pinning tokens and for the shape of
        the two `install` lines -- and it PASSED the script that replaced an
        operator's pair on every upgrade, because that script does contain exactly
        that shape. A gate that cannot fail on the defect it was written for is
        worse than no gate, so the control restores the unconditional publish and
        asks the METHOD to fail.
        """
        broken = unconditional_publish(POSTINST.read_text())
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_postinst_leaves_a_pair_an_operator_re_pinned_alone",
            postinst=broken,
            # The method reads the two shipped files out of the staged tree, so
            # the control asks for a copy of it even though it plants nothing.
            staged={},
        )
        # And the mutation really is the old script: the tokens the old grep
        # looked for are all still present in it, which is why the old gate
        # passed it.
        run = "\n".join(executed_lines(broken))
        for token in ("--pin-remote",):
            self.assertNotIn(
                token, run, "the control no longer reproduces the script the old gate passed"
            )
        # The mutation is only a control if it really removed the guard, and the
        # guard is the `if` line `unconditional_publish` replaced. Asserting that
        # the publish is still there -- rather than that a particular `install` line
        # reads a particular way -- is what says the mutation did the thing; the
        # install line names the group through a variable now, so a literal here
        # would be holding a spelling this package no longer ships.
        self.assertIn("if true; then", broken)
        self.assertNotIn(
            'if [ ! -r "$PUBLISHED_LIST" ] || [ ! -r "$PUBLISHED_LOCK" ]; then', broken,
            "the mutation did not remove the guard, so this control would pass against "
            "a script that was never defective",
        )
        names = identities_from(broken)
        self.assertIn(
            f'install -o root -g "$STATE_GROUP" -m 0640 "$SOURCE_LIST" "$PUBLISHED_LIST"',
            broken,
            f"the publish of the pair is gone entirely, so this is not the old script "
            f"but a different defect; the group it names is {names['group']}",
        )

    def test_a_capture_closed_before_the_arms_is_reported_by_the_method(self):
        """The control for the Critical, and the reason that gate had to become a run.

        `88bc2af` moved the `fi` that closed the status capture above the arms and
        left the arms and the `exit 1` below it, so `postinst` exited 1 on EVERY
        configure including a successful one and STEP 5's timer enable was dead
        code. The three checks in place at the time were all TRUE of that script,
        so the suite was green over a package that could not be installed. This
        control moves the one line that caused it and asks the METHOD to fail.

        The previous version of this control selected the LAST column-zero `fi` after
        the capture, which in the fixed script is STEP 5's guard and not the
        transaction's -- so it manufactured a script `sh` refuses to PARSE (an orphan
        `fi`, and a STEP 5 `if` with no closer) rather than the defect, and its own
        integrity check could not tell, because one `fi` was added and a different one
        removed and the count was the same either way. Everything below is here so
        that cannot recur: WHICH `fi` moved is derived twice and independently, the
        move is asserted line by line rather than by a count, and the defect is
        asserted as an OUTPUT rather than as a `sh -n` result.
        """
        good = POSTINST.read_text()
        broken = capture_closed_early(good)
        lines = good.splitlines(keepends=True)
        capture, opening, closing, moved = status_capture(good)

        # (1) WHICH `fi` moved. The reader matched `if "$INSTALLER" install`; the
        # second derivation does not read blocks at all and asks which column-zero
        # `fi` ends the transaction -- the last one above STEP 5's own guard, which is
        # the only other block between the capture and the end of the file. Two
        # derivations that agree, so a reader that went wrong is a failure here rather
        # than a control that quietly moved some other line.
        guard = next(
            index for index, line in enumerate(lines)
            if index > capture and line.strip() == f"if [ -d {SYSTEMD_RUNTIME_DIRECTORY} ]; then"
        )
        above_guard = [
            index for index, line in enumerate(lines)
            if capture < index < guard and line.rstrip() == "fi"
        ]
        self.assertEqual(closing, max(above_guard),
                         f"the reader moved the `fi` at line {closing + 1}, which is not the one "
                         f"that ends the transaction: the column-zero `fi`s between the capture "
                         f"(line {capture + 1}) and STEP 5's guard (line {guard + 1}) are "
                         f"{[index + 1 for index in above_guard]}")
        self.assertEqual(moved, "fi\n",
                         f"the control moved a {moved!r} rather than a `fi`, so it is not moving "
                         "the line the Critical was caused by")
        after_moved = lines[closing + 1:closing + 3]
        self.assertEqual(len(after_moved), 2, "there is no line after the `fi` that moved")
        self.assertEqual(after_moved[0], "\n",
                         "the line after the `fi` that moved is not a blank one, so the control is "
                         "moving some other block's closer")
        self.assertTrue(
            after_moved[1].startswith("# --- STEP 5"),
            f"the line after the `fi` that moved is {after_moved[1]!r} and not STEP 5's header, so "
            "the control is moving some other block's closer",
        )

        # (2) THAT IT IS THE SAME LINE, and that nothing else changed. Not a count:
        # `broken.count("fi\n") == good.count("fi\n")` is satisfied by adding one `fi`
        # and removing a different one, which is exactly what the previous version of
        # this control did. This compares every line, so the only difference that can
        # pass is the line that was at `closing` now sitting at `capture + 1`.
        after = broken.splitlines(keepends=True)
        self.assertEqual(len(after), len(lines),
                         "the control added or removed a line rather than moving one")
        for index in range(len(lines)):
            if index <= capture:
                expected = lines[index]
            elif index == capture + 1:
                expected = moved
            elif index <= closing:
                # Between the two positions everything is the original one line
                # earlier, because the `fi` is GONE from where it was rather than
                # copied to the new one.
                expected = lines[index - 1]
            else:
                expected = lines[index]
            self.assertEqual(
                after[index], expected,
                f"line {index + 1} of the mutated script is not the line that was there, so the "
                "control changed something beyond the one `fi` it moved",
            )

        # (3) THAT IT MANUFACTURES THE DEFECT AND NOT A PARSE ERROR. `88bc2af` shipped
        # a syntactically valid script that failed on every configure; the previous
        # version of this control shipped a script `sh` would not accept, which fails
        # for a reason no operator would ever see and which a mutation of the `fi` could
        # not have produced on its own. The mutant has to parse.
        self.assertEqual(shell_parses(good).returncode, 0,
                         "the shipped postinst does not parse, so dpkg cannot run it")
        self.assertEqual(shell_parses(broken).returncode, 0,
                         "the control's mutant does not parse, so it is holding a property it "
                         "never claimed instead of the defect it was written for")

        # (4) THAT IT PRODUCES THE OUTPUT THE DOCSTRING NAMES. A successful configure
        # now reaches the arms with `install_status` never assigned, prints the
        # unknown-status arm with the status EMPTY (the current script retired the
        # `${install_status:-1}` default, so there is nothing for the arm to print),
        # prints the advice that belongs only on a refusal, and never enables a timer.
        completed, calls = postinst_transaction_run(0, text=broken)
        self.assertNotEqual(completed.returncode, 0,
                            "a successful configure still exits 0 with the capture closed early")
        self.assertIn("exited , which is not a", completed.stderr,
                      "the unknown-status arm did not print the unset status it was given")
        self.assertIn("dpkg --configure mosdns-router", completed.stderr,
                      "a successful configure printed the advice that belongs on a refusal")
        self.assertEqual(
            [call for call in calls if call[:1] == ["enable"]], [],
            "a successful configure still enabled the timers, so STEP 5 is not dead code",
        )
        # And a run that really did refuse still reaches its OWN arm, because the only
        # thing this mutation breaks is the guarantee that a success cannot.
        refused, _calls = postinst_transaction_run(3, text=broken)
        self.assertIn("refused this machine and rolled back", refused.stderr,
                      "a run that refused reached the wrong arm, so this control is not holding "
                      "the arm routing and only the successful-run case")

        # (5) The three substring facts the OLD gate read are still present, which is
        # why it passed the broken script and why this control exists at all.
        self.assertIn("install_status=$?", broken)
        self.assertIn('if "$INSTALLER" install', broken)
        self.assertIn("no resolver", broken)

        self.assertMethodFails(
            MaintainerScriptTests,
            "test_postinst_succeeds_on_a_successful_install_and_reaches_the_timer_enable",
            postinst=broken,
        )
        # Only ONE of the two gates notices, and that is worth recording rather than
        # leaving to be discovered: the arm-routing gate runs the script for 1, 3, 4,
        # 5, 6 and 42, and a run that really did refuse still reaches its own arm
        # under this mutation, so that gate is about the ROUTING and this defect is
        # about the SUCCESSFUL run. Asserting the second gate here would be asserting
        # something false -- and it was false, in the first draft of this control.
        self.assertNotEqual(opening, closing)

    def test_status_arms_un_nested_into_an_if_chain_are_reported(self):
        """The control for the READER, and for the reason it is the reader and not the
        script that is at issue.

        `postinst_status_arms` reads a `case`, and it used to answer `{}` for
        anything else without a word -- so a script that un-nested the status arms
        into an `if`/`elif`/`else` chain, which is the shape `88bc2af` shipped and a
        shape a hand edit takes, turned every test that asks for an arm into a
        `KeyError`. A `KeyError` is an ERROR, not a FAILURE: a control aimed at
        `test_postinst_does_not_promise_the_daemons_are_still_running_behind_a_failed_rollback`
        saw a crash rather than a verdict, and a crash is not a gate.

        So the mutation here is the one that used to crash the gate, and the
        assertion is that it is now a FAILURE -- which `assertMethodFails` can only
        be if the raise is an `AssertionError` carrying the finding.
        """
        good = POSTINST.read_text()
        broken = arms_unnested_into_a_chain(good)
        self.assertNotEqual(broken, good, "the un-nesting changed nothing, so this is empty")
        self.assertEqual(
            shell_parses(broken).returncode, 0,
            "the un-nested script does not parse, so it is not the shape being demonstrated",
        )
        # The reader names the shape rather than answering nothing.
        arms, findings = postinst_status_arms_findings(broken)
        self.assertEqual(arms, {}, "the reader read arms out of an if/elif chain")
        self.assertEqual(len(findings), 1, f"expected one finding and got {findings}")
        self.assertIn("if`/`elif` chain", findings[0])
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_postinst_does_not_promise_the_daemons_are_still_running_behind_a_failed_rollback",
            postinst=broken,
        )

    def test_a_status_capture_that_never_reads_the_transactions_status_is_reported(self):
        """The second control on the same gate, for a DIFFERENT defect in the same line.

        Closing the capture early lets a SUCCESSFUL run reach the arms with no status
        at all, and leaves every other run reaching its own arm. Hard-coding the
        captured value does the opposite: the arms are reached on the right schedule
        and every run lands in the SAME one, because the status the `case` reads is
        no longer the status the transaction produced. It is the shape a well-meaning
        edit takes when somebody wants the arm routing to be easier to read, and it is
        caught by nothing a reader of the text can see -- `install_status=$?` is
        still there, spelled exactly as before.

        So the observable is asserted rather than described: a transaction that
        refused with 3 lands in arm 1.
        """
        good = POSTINST.read_text()
        broken = good.replace("install_status=$?", "install_status=1")
        self.assertNotEqual(broken, good, "the control changed nothing, so it is empty")
        completed, _calls = postinst_transaction_run(3, text=broken)
        self.assertIn(
            "refused this machine before it changed", completed.stderr,
            "a transaction that exited 3 did not land in the arm the hard-coded capture sends "
            "every run to, so this control is no longer producing the defect it describes",
        )
        self.assertNotIn("refused this machine and rolled back", completed.stderr)
        self.assertNotEqual(completed.returncode, 0)
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_every_installers_status_reaches_its_own_arm_and_a_refusal_exits_non_zero",
            postinst=broken,
        )

    def test_a_missing_staged_file_pattern_is_reported(self):
        """The control for the fourth producer's two reap lines.

        Deleted rather than loosened, because a reap line is a delete and the two
        published files in that directory are the very names the pattern is built
        from. The control also proves the check is about the lists directory and
        not about the entry in general: the three directories that were already
        reaped still pass with one of these two gone.
        """
        good = (REPO / "packaging" / "tmpfiles.d" / "mosdns-router.conf").read_text()
        for pattern in STAGED_WITHOUT_A_SUFFIX:
            with self.subTest(pattern=pattern):
                self.assertEqual(tmpfiles_findings(good), [])
                self.assertMethodFails(
                    TmpfilesTests,
                    "test_the_tmpfiles_entry_reaps_the_fourth_producer_staged_files",
                    staged={TMPFILES_PATH: good.replace(f"r {pattern}\n", "")},
                )

    def test_one_sentence_for_both_of_the_installers_refusals_is_reported(self):
        """The control for prerm's two arms.

        Flattened to one arm per status with the SAME text, which is precisely the
        defect: a script that cannot tell a refusal that changed nothing from a
        restore that did not finish.
        """
        text = PRERM.read_text()
        arms = numeric_case_arms(text)
        flattened = text.replace(
            arms["6"].strip(), arms["5"].strip()
        )
        self.assertEqual(
            numeric_case_arms(flattened)["5"].strip(),
            numeric_case_arms(flattened)["6"].strip(),
            "the control did not flatten the two arms",
        )
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_prerm_tells_the_installers_two_refusals_apart_and_says_what_dpkg_will_do",
            prerm=flattened,
        )

    def test_timers_enabled_before_the_transaction_are_reported(self):
        """Round 2's control for the enable's POSITION, against the method that holds
        it.

        The swap helper's previous version matched `"systemctl enable" in line` over
        every line, and the shipped postinst's comment at the head of STEP 5 contains
        that string -- so it relocated a comment, `postinst_steps` was unchanged, the
        findings were still `[]`, and the control passed on an unmutated order. It now
        skips comments the way `postinst_steps` does, and the control below asserts
        the mutation actually MOVED the enable, so a helper that goes quiet again is a
        failure here rather than a control that quietly stops checking.
        """
        good = POSTINST.read_text()
        self.assertEqual(
            timer_position_findings(good), [],
            "the shipped postinst does not pass its own order check",
        )
        broken = "\n".join(_swap_the_timer_enable_before_the_transaction(good))
        self.assertNotEqual(broken, good, "the swap changed nothing")
        positions = postinst_steps(broken)
        self.assertIn("enable-timers", positions)
        self.assertLess(
            positions["enable-timers"], positions["install-transaction"],
            "the swap did not move the enable before the transaction, so this proves nothing",
        )
        self.assertTrue(timer_position_findings(broken))
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_postinst_leaves_nothing_enabled_when_the_transaction_refuses",
            postinst=broken,
        )

    def test_a_reversed_provisioning_order_is_reported(self):
        """The METHOD, not the helper. A control that re-implemented the check would
        pass while the method it holds was inverted, and the class docstring's claim
        would be false; so the mutation is applied to a copy of the script and the
        method is called against it."""
        good = POSTINST.read_text()
        broken = "\n".join(_swap_a_directory_pair(good))
        self.assertNotEqual(broken, good, "the mutation changed nothing, so the control is empty")
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_postinst_provisions_the_state_directories_in_the_load_bearing_order",
            postinst=broken,
        )
        # And the method is what fails, for the reason it names, not for some other
        # reason it happens to have found.
        findings = order_findings(broken)
        self.assertTrue(
            any("narrows" in finding for finding in findings),
            f"reversing the mode and the ACL of one directory is not reported: {findings}",
        )

    def test_the_mode_this_plan_first_named_is_reported(self):
        """2750 caps the group at r-x on the directory, so a service identity
        cannot create a state file in it at all. Measured, not assumed."""
        broken = POSTINST.read_text().replace("-m 2770", "-m 2750")
        self.assertNotIn("-m 2770", broken, "the mutation changed nothing")
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_postinst_provisions_the_state_directories_in_the_load_bearing_order",
            postinst=broken,
        )
        self.assertTrue(
            any("-m 2770" in finding for finding in order_findings(broken)),
            "provisioning the state directories at 2750 is not named by the reader",
        )

    def test_a_directory_created_without_its_group_is_reported(self):
        # The group is named through a variable in the shipped script, so the
        # mutation changes the VARIABLE's value rather than a flag on a command
        # line. Rewriting `-g mosdns` on the install line changed nothing at all --
        # the text is not there -- and the control passed against a postinst that
        # was never defective.
        good = POSTINST.read_text()
        broken = re.sub(
            r"(?m)^(STATE_GROUP=)\S+$", r"\1root", good, count=1,
        )
        self.assertNotEqual(
            broken, good,
            "the mutation changed nothing: postinst does not assign STATE_GROUP at the "
            "start of a line, so the reader cannot be exercised this way",
        )
        self.assertEqual(
            identities_from(broken)["group"], "root",
            "the mutation did not move the group the reader resolves",
        )
        self.assertMethodFails(
            MaintainerScriptTests,
            "test_postinst_provisions_the_state_directories_in_the_load_bearing_order",
            postinst=broken,
        )

    def test_a_tmpfiles_entry_with_no_default_acl_is_reported(self):
        good = (REPO / "packaging" / "tmpfiles.d" / "mosdns-router.conf").read_text()
        self.assertEqual(tmpfiles_findings(good), [], "the shipped entry does not pass its own check")
        broken = re.sub(r"\bd:g::rwx\b", "g::rwx", good)
        self.assertNotEqual(broken, good, "the mutation changed nothing")
        findings = tmpfiles_findings(broken)
        self.assertTrue(
            any("DEFAULT group entry" in finding for finding in findings),
            f"a /run/mosdns ACL with no default entry is not reported: {findings}",
        )

    def test_a_reversed_tmpfiles_entry_is_reported(self):
        """The `a` line before the `d` line is the same load-bearing pair the postinst
        order is about, and nothing held it: a check that asked "is there an ACL" would
        pass an entry that creates the directory with no ACL at all."""
        good = (REPO / "packaging" / "tmpfiles.d" / "mosdns-router.conf").read_text()
        lines = [line for line in good.splitlines() if line]
        create = next(index for index, line in enumerate(lines) if line.startswith("d "))
        acl = next(index for index, line in enumerate(lines) if line.startswith("a "))
        self.assertLess(create, acl, "the shipped entry does not have the order it should")
        lines[create], lines[acl] = lines[acl], lines[create]
        self.assertMethodFails(
            TmpfilesTests,
            "test_the_tmpfiles_entry_recreates_run_mosdns_with_the_same_properties",
            staged={TMPFILES_PATH: "\n".join(lines) + "\n"},
        )
        self.assertTrue(
            any("BEFORE" in finding for finding in tmpfiles_findings("\n".join(lines))),
            "the reversed order is not named by the reader",
        )

    def test_a_space_separated_acl_is_reported(self):
        """The control for the comma. Replacing it with a space is a one-character
        edit that systemd answers with a diagnostic on stderr and then IGNORES, so
        the entry still "works", the directory is still created, and it carries no ACL
        at all. `tmpfiles_findings` cannot see the separator -- the specification is
        one opaque string to it -- so what this control proves is that the text the
        textual assertion reads is the text that would change."""
        good = (REPO / "packaging" / "tmpfiles.d" / "mosdns-router.conf").read_text()
        self.assertEqual(
            tmpfiles_findings(good), [], "the shipped entry does not pass its own check"
        )
        broken = good.replace("g::rwx,d:g::rwx", "g::rwx d:g::rwx")
        self.assertNotEqual(broken, good, "the mutation changed nothing")
        self.assertIn("g::rwx d:g::rwx", broken)
        self.assertNotIn("g::rwx,d:g::rwx", broken)

    def test_a_tmpfiles_entry_that_reaps_too_much_is_reported(self):
        good = (REPO / "packaging" / "tmpfiles.d" / "mosdns-router.conf").read_text()
        broken = good + "r /etc/ssl/*.tmp\n"
        findings = tmpfiles_findings(broken)
        self.assertTrue(
            any("/etc/ssl" in finding for finding in findings),
            f"reaping a directory this package does not write is not reported: {findings}",
        )

    def test_a_routing_document_that_is_not_the_render_is_reported(self):
        """One byte in a comment is enough, which is the point: a shipped document
        nobody can regenerate is a document the project can no longer explain."""
        def edit(stage):
            document = stage / CONFIG_DIRECTORY.lstrip("/") / "mosdns.yaml"
            document.write_text(document.read_text() + "# a hand edit\n")

        mutated, inventory = self.copy(edit)
        self.assertIsNotNone(inventory_get(inventory, CONFIG_DIRECTORY + "/mosdns.yaml"))
        committed = (REPO / "configs" / "mosdns.yaml").read_text()
        edited = (Path(mutated) / CONFIG_DIRECTORY.lstrip("/") / "mosdns.yaml").read_text()
        self.assertNotEqual(edited, committed, "the mutation changed nothing")
        with tempfile.TemporaryDirectory(
            prefix="mosdns-render-control.", dir=os.environ.get("MOSDNS_PACKAGE_TEST_TMPDIR") or None
        ) as scratch:
            status = render_for_installed_layout(
                scratch,
                Path(mutated) / CONFIG_DIRECTORY.lstrip("/") / "policy.yaml",
                Path(mutated) / CDNCTL_BINARY.lstrip("/"),
            )
            self.assertEqual(status, 0)
            fresh = (Path(scratch) / "etc" / "mosdns" / "mosdns.yaml").read_text()
            self.assertNotEqual(
                edited, fresh,
                "a shipped routing document with an extra comment byte is still a fresh render",
            )

    def test_the_provider_scan_exemption_cannot_silently_grow(self):
        """The exemption is a hole in the gate, so it is one named file and this
        test reads the table rather than trusting it."""
        self.assertEqual(
            ROUTE_SCAN_EXEMPT, (CHINA_LIST,),
            "a second file is exempt from the provider scan, and nobody decided on it",
        )
        self.assertEqual(
            (REPO / "configs" / "cn-domains.txt").is_file(), True,
            "the one exempt file's reviewed source has to exist",
        )

    def test_a_manifest_entry_that_is_not_shipped_is_reported(self):
        listed = {destination for _s, destination in manifest_entries(MANIFEST.read_text())}
        self.assertIn(TMPFILES_PATH, listed)
        _root, inventory = self.copy(
            lambda stage: os.remove(stage / TMPFILES_PATH.lstrip("/"))
        )
        shipped = {path for path, _kind, _mode, _size in inventory if not path.startswith(DEBIAN)}
        self.assertEqual(
            sorted(listed - shipped - GENERATED), [TMPFILES_PATH],
            "the manifest lists a file the package does not contain, and nothing noticed",
        )


def _swap_the_timer_enable_before_the_transaction(text):
    """Move the real `systemctl enable` lines above the install transaction.

    The commands, unchanged, in the wrong place: that is the mutation that shipped.
    Three things the previous version of this helper got wrong, and all three made it
    a no-op that reported success:

    * it matched `"systemctl enable" in line` over EVERY line, and the shipped
      postinst's COMMENT at the head of STEP 5 contains that string -- so the matcher
      relocated a comment and left the real enable where it was;
    * it therefore never checked that the thing it moved was a command;
    * it inserted at the guard line, which is right, but computed the guard index from
      the already-sliced list, so an index computed against the original lines was
      used against a shorter one.

    Comments are skipped for the same reason `postinst_steps` skips them: this helper
    and that reader have to agree about which lines are commands, or the order they
    report is a story about comments.
    """
    lines = text.splitlines()
    commands = [index for index, line in enumerate(lines) if not line.lstrip().startswith("#")]

    def first(predicate):
        return next(index for index in commands if predicate(lines[index]))

    enable = first(lambda line: "systemctl enable" in line)
    # The enable is the command plus its continuation, and the continuation is the
    # next line that ends the list of unit names.
    moved = [lines[enable]]
    cursor = enable + 1
    while cursor < len(lines) and not lines[cursor].lstrip().startswith("#"):
        moved.append(lines[cursor])
        cursor += 1
        # The last timer in the list, which is the one this control stops on. It
        # was `mosdns-list-check.timer` before the watchdog was added and is now
        # the last line of the enable, so naming the OLD last name would have
        # stopped after the third of four and moved half the command -- which is
        # the shape of control that cannot fail for the reason it is written for.
        if lines[cursor - 1].rstrip().endswith("mosdns-watchdog.timer"):
            break
    guard = next(
        index for index, line in enumerate(lines)
        if not line.lstrip().startswith("#") and line.strip().startswith('if "$INSTALLER" install')
    )
    assert enable > guard, "postinst already enables the timers before the transaction"
    rest = lines[:enable] + lines[cursor:]
    insertion = next(
        index for index, line in enumerate(rest) if line.strip().startswith('if "$INSTALLER" install')
    )
    return rest[:insertion] + moved + rest[insertion:]


def _swap_a_directory_pair(text):
    """Swap the create and the setfacl of the first provisioned directory.

    The two whole commands are swapped rather than their arguments, because what
    this mutation has to demonstrate is that the ORDER is read: the commands
    themselves stay exactly the ones the shipped script runs.
    """
    lines = text.splitlines()
    create = next(
        index for index, line in enumerate(lines)
        if "install -d" in line and STATE_DIRECTORIES[0] in line
    )
    acl = next(
        index for index, line in enumerate(lines)
        if "setfacl" in line and STATE_DIRECTORIES[0] in line
    )
    lines[create], lines[acl] = lines[acl], lines[create]
    return lines


if __name__ == "__main__":
    unittest.main()
