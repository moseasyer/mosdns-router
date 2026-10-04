#!/bin/sh
# Assert that a built .deb says what this repository's build promises it says.
#
# WHY A SEPARATE SCRIPT, INSTEAD OF A run: BLOCK IN THE WORKFLOW: two workflows
# need this exact set of checks -- the one that builds, and the one that publishes a
# built package as a Release -- and the second one must NOT trust the first. A
# publish step that re-checks nothing is a publish step that republishes whatever
# it was handed. Copying the block instead of sharing it would be worse: two copies
# of a gate drift, and the copy that drifts is the one nobody edits.
#
# It reads PACKAGE_VERSION out of scripts/build-deb.sh rather than taking it as an
# argument, because the whole point of the first assertion is that the file name,
# the control field and that line are ONE value. An argument would let a caller
# pass the value it was trying to check.
#
# Every assertion here has been false in this repository's history, which is the
# only reason it is here:
#
#   the control Version vs PACKAGE_VERSION   0.1.0 and 0.2.0 in one tree, and no
#                                           test caught it because nothing compared
#                                           them; found by RUNNING a build
#   the seven conffiles                      dpkg replaces an edited conffile on
#                                           upgrade without asking, so its absence
#                                           is silent data loss
#   maintainer script modes                  a non-executable one makes install do
#                                           nothing on some dpkg versions
#   the generated-document header            without it an operator edits a file the
#                                           next render overwrites
#   every binding key on the loopback        a wildcard bind on this package's FIRST
#                                           HTTP listener, which is `api.http` and
#                                           not `listen:`, shipped green once
#   the API listener EXISTS                  otherwise a renderer that dropped the
#                                           api block leaves the loopback assertion
#                                           with nothing to examine, and a gate that
#                                           passes because it examined nothing is
#                                           the failure this script exists to
#                                           prevent
#
# Usage: scripts/assert-deb.sh <path/to/package.deb>
# Exits non-zero on the first failure, and says which one.

set -eu

if [ $# -ne 1 ]; then
	echo "usage: scripts/assert-deb.sh <path/to/package.deb>" >&2
	exit 2
fi

# Resolve the package to an absolute path BEFORE changing directory, because the
# script reads PACKAGE_VERSION from the repository and so has to cd there. A
# relative path that happened to be right when it was typed and wrong after the cd
# is a failure mode that looks like "no such package".
deb=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

fail() {
	echo "assert-deb: $1" >&2
	exit 1
}

test -f "$deb" || fail "no such package: $1"

want=$(sed -n 's/^PACKAGE_VERSION=//p' scripts/build-deb.sh)
test -n "$want" || fail "scripts/build-deb.sh states no PACKAGE_VERSION"

# The version in the file name, the control field and scripts/build-deb.sh are one
# value. They were 0.1.0 and 0.2.0 in the same tree until a build was actually run.
case $(basename "$deb") in
*"_${want}_"*) ;;
*) fail "file name says $(basename "$deb"), and PACKAGE_VERSION is $want" ;;
esac

got=$(dpkg-deb --field "$deb" Version)
test "$got" = "$want" || fail "control says Version $got, PACKAGE_VERSION is $want"

# All seven are conffiles so an upgrade asks before replacing a file a person
# changed. dpkg reads this from DEBIAN/conffiles, not from a control field.
ctl=$(mktemp -d "${TMPDIR:-/tmp}/mosdns-assert-deb.XXXXXX")
trap 'rm -rf "$ctl"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
dpkg-deb -e "$deb" "$ctl" >/dev/null 2>&1 || fail "dpkg-deb -e refused the package"
test -f "$ctl/conffiles" || fail "the package declares no conffiles at all"
for f in /etc/mosdns/mosdns.yaml /etc/mosdns/dnscrypt-proxy.toml \
	/etc/mosdns/policy.yaml /etc/mosdns/force-ech-domains.txt \
	/etc/mosdns/cloudflare.txt /etc/mosdns/cloudfront-domains.yaml \
	/etc/mosdns/watchdog.yaml; do
	grep -qx "$f" "$ctl/conffiles" || fail "$f is not a conffile"
done

# A maintainer script that is not executable is a package whose install silently
# does nothing on some dpkg versions. dpkg-deb writes the member names as
# "./postinst", so this reads the control tar once rather than extracting it three
# times.
modes=$(dpkg-deb --ctrl-tarfile "$deb" | tar -tv | grep -E ' \./(postinst|prerm|postrm)$' || true)
test "$(printf '%s\n' "$modes" | grep -c .)" -eq 3 \
	|| fail "expected three maintainer scripts, got:$(printf '%s\n' "$modes" | tr '\n' ' ')"
printf '%s\n' "$modes" | while read -r line; do
	case "$line" in
	-*x*) ;;
	*) fail "not executable: $line" ;;
	esac
done

# The routing document declares itself generated, which is what tells an operator to
# edit the policy instead. A package whose document lost that header would send the
# next edit to a file the next render overwrites.
doc=$(dpkg-deb --fsys-tarfile "$deb" | tar -xO ./etc/mosdns/mosdns.yaml) \
	|| fail "the package ships no /etc/mosdns/mosdns.yaml"
printf '%s\n' "$doc" | head -5 | grep -q 'Generated by internal/mosdnsconfig.Render' \
	|| fail "the shipped routing document does not declare itself generated"

# Every listener this router opens is on the loopback and nowhere else, and it
# binds nothing on a wildcard. This reads EVERY key that binds rather than the one
# that happened to be first: a gate written against `listen:` alone passes a
# document whose api block binds 0.0.0.0, and this package's first HTTP listener is
# exactly that key.
binds=$(printf '%s\n' "$doc" | grep -nE '^[[:space:]]*(listen|http|bind|address)[[:space:]]*:' || true)
test -n "$binds" || fail "the shipped document binds nothing at all"
bad=$(printf '%s\n' "$binds" \
	| grep -vE ':[[:space:]]*(127\.0\.0\.1|\[::1\]|::1|localhost)(:[0-9]+)?[[:space:]]*$' || true)
test -z "$bad" || fail "a listener is not on the loopback:$(printf '%s\n' "$bad" | tr '\n' ' ')"

# The API listener exists. Without this a renderer that dropped the api block would
# leave the loopback assertion with nothing to check.
printf '%s\n' "$doc" | grep -qE '^[[:space:]]*http[[:space:]]*:[[:space:]]*(127\.0\.0\.1|\[::1\])' \
	|| fail "the shipped document has no loopback API listener"

# The revision the package records, so a caller that promotes this package can put
# the tag where the build actually came from instead of where the branch points.
manifest=$(dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/share/doc/mosdns-router/BUILD-MANIFEST 2>/dev/null || true)
rev=$(printf '%s\n' "$manifest" | sed -n 's/^revision: *//p' | head -1)
test -n "$rev" || fail "the package records no build revision"

printf 'assert-deb: ok  version=%s revision=%s\n' "$want" "$rev"
printf '%s\n' "$rev"