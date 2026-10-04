#!/bin/sh
# Build the mosdns-router Debian package from this checkout.
#
# Two things this script will not do, and both are the hard boundary this project
# works under: it installs nothing on the machine that runs it, and it reads no
# state of that machine. There is no `dpkg -i`, no `apt-get`, no `systemctl`, no
# `nmcli`, and no maintainer script is ever executed here. Everything it does
# happens inside a staging root, and the only thing that leaves it is a .deb file
# and a printed path.
#
#   scripts/build-deb.sh                     build ./build/mosdns-router_0.2.0_amd64.deb
#   scripts/build-deb.sh --stage DIR         build only the staging root, and stop
#   scripts/build-deb.sh --arch arm64        build for the other supported release
#
# The two steps, and why they are two: the staging root is what the package-content
# test asserts against, and it is the whole of the package's content, so a test that
# could see the .deb but not the tree would be testing a file it cannot read the way
# dpkg reads it. `--stage` exists so both are the same build.
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO"

PACKAGE=mosdns-router
# The .deb's version, and therefore the one in the control file and the file name.
# Distinct from the build IDENTITY below on purpose: the two are different facts, and
# the first version of this script called both `VERSION`, so a `VERSION=` the Makefile
# passed in was silently ignored and the shipped binary's version was whatever this
# line said rather than the revision the Makefile had computed.
PACKAGE_VERSION=0.2.0
BUILD=build
STAGE=
STAGE_ONLY=
ARCH=$(dpkg --print-architecture)

# The upstream source the packaged resolver is built from, and where its archive
# has to be. `packaging/debian/dnscrypt-proxy.sha256` is the pin: the digest is
# checked BEFORE the archive is opened, so a tree nobody pinned is never built, and
# an archive that is absent is a loud failure with the command to fetch it rather
# than a package that silently lacks a resolver.
#
# The archive is NOT committed, and the build has other prerequisites that are not
# either -- Go 1.25.8 exactly, and bwrap, because the render below has to be for the
# installed layout. The Makefile's `package` target carries the same list with the
# seed command in it, so a contributor meets it before the gate fails rather than
# after.
DNSCRYPT_VERSION=2.1.18
DNSCRYPT_ARCHIVE=dnscrypt-proxy-$DNSCRYPT_VERSION.tar.gz
DNSCRYPT_SOURCE_URL=https://github.com/DNSCrypt/dnscrypt-proxy/archive/refs/tags/$DNSCRYPT_VERSION.tar.gz
DNSCRYPT_PIN=packaging/debian/dnscrypt-proxy.sha256
DNSCRYPT_DIR=build/dnscrypt-proxy

# The Go release every build here is made with. `make` refuses any other, and this
# script refuses any other too, because the packaged resolver's own go.mod declares
# exactly this one and a different patch of the same minor cannot build it.
GO_REQUIRED_VERSION=1.25.8
GO=${GO:-go}

# The build identity the shipped binaries carry, derived the same three ways the
# Makefile derives it, because a package built outside `make` must report the same
# identity as one built inside it -- and because the first version of this script
# passed NO metadata at all, so the router in the .deb answered a version question
# with dev/unknown/unknown while the Makefile's own verify-build-info was checking a
# DIFFERENT binary. The Makefile passes its three values in, so `make build` and
# `make package` agree by construction rather than by two copies of one expression.
BUILDINFO_PKG=mosdns-router/internal/buildinfo
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
REVISION=${REVISION:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}
BUILD_TIME=${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
METADATA_LDFLAGS="-X $BUILDINFO_PKG.Version=$VERSION -X $BUILDINFO_PKG.Revision=$REVISION -X $BUILDINFO_PKG.BuildTime=$BUILD_TIME"

# A private view of the filesystem, and why the build needs one. The two shipped
# documents are the output of `mosdns-cdnctl render`, and the render stamps the
# policy path it was GIVEN into both of them. The installed path is
# /etc/mosdns/policy.yaml, so the render has to be for the installed layout -- and
# making that path resolve is what a private view of / is for. Nothing here writes
# to this host's /etc: the view is a bubblewrap sandbox whose /etc is this staging
# root, and it is the only mechanism that can produce a shipped document naming the
# installed path without touching the machine doing the build.
BWRAP=${BWRAP:-bwrap}

# The scratch this build creates and does not ship, removed however it ends. The
# extraction is in the list because a vendored Go tree left in the repository makes
# `gofmt -l .` list a hundred files of somebody else's code, and a formatting gate
# that reports upstream's tree is a gate nobody can read.
scratch_paths=""
die() {
	echo "build-deb.sh: $*" >&2
	exit 1
}
cleanup() {
	for path in $scratch_paths; do
		rm -rf "$path"
	done
}
trap cleanup EXIT

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required and is not installed: $2"
}

usage() {
	die "usage: scripts/build-deb.sh [--stage DIR] [--arch ARCH]"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--stage)
		[ $# -ge 2 ] || usage
		STAGE=$2
		STAGE_ONLY=1
		shift 2
		;;
	--arch)
		[ $# -ge 2 ] || usage
		ARCH=$2
		shift 2
		;;
	-h | --help)
		echo "usage: scripts/build-deb.sh [--stage DIR] [--arch ARCH]"
		exit 0
		;;
	*) usage ;;
	esac
done

case "$ARCH" in
amd64 | arm64) ;;
*) die "--arch $ARCH is not one this package builds for: amd64 arm64" ;;
esac

need dpkg-deb "it writes the package and nothing else here can"
need sha256sum "the pinned source is verified with it"
need install "the staging tree is placed with it"
need "$GO" "the Go release this module and the packaged resolver both pin is $GO_REQUIRED_VERSION"
need "$BWRAP" "the shipped documents are rendered for the INSTALLED layout, which needs a private view of /: install the bubblewrap package"
need gzip "the manual pages ship compressed, as the Debian manual page convention has them"

# --- the toolchain ------------------------------------------------------------

go_release=$("$GO" version | awk '{print $3}' | sed 's/^go//')
[ "$go_release" = "$GO_REQUIRED_VERSION" ] ||
	die "Go $GO_REQUIRED_VERSION is required, found ${go_release:-unknown} in $("$GO" version)"

# --- the three programs -------------------------------------------------------
#
# The router and the control tool are built here rather than read out of build/,
# with the same flags the Makefile uses, so the staging root never depends on a
# previous make having run. The resolver cannot be: see the source pin below.
#
# HOST_ARCH matters for a CROSS build, and for one reason only: the two verification
# steps further down -- rendering the documents and asking the resolver whether it
# accepts the one it rendered -- are steps this BUILD MACHINE runs. Both read a file
# and write a file, neither has an architecture-dependent result, and a document that
# is correct for amd64 is the document arm64 reads. So the verification steps run the
# host's own build of the same pinned sources, and the SHIPPED binaries are the target
# architecture's. Running the target's binary instead would make `make package
# --arch arm64` fail on every amd64 host with "Exec format error", which is a fact
# about the host and not about the package.
HOST_ARCH=$("$GO" env GOHOSTARCH)

build_go_binary() {
	# $1 the package path, $2 the output path, $3 the architecture.
	# -trimpath so the binary carries no path from the machine that built it, which
	# is what makes the digest in the build manifest mean anything: the same source
	# at the same release produces the same bytes on any machine.
	CGO_ENABLED=0 GOOS=linux GOARCH="$3" "$GO" build -mod=readonly -trimpath \
		-ldflags "-s -w $METADATA_LDFLAGS" -o "$2" "$1"
}

mkdir -p "$BUILD"
build_go_binary ./cmd/mosdns-router "$BUILD/$PACKAGE.router" "$ARCH"
build_go_binary ./cmd/mosdns-cdnctl "$BUILD/$PACKAGE.cdnctl" "$ARCH"

# --- the pinned resolver, verified before it is opened -----------------------

dnscrypt_archive() {
	# The archive is not committed: it is fetched once, pinned here, and used from
	# wherever it was seeded. MOSDNS_DNSCRYPT_ARCHIVE is the escape hatch for a host
	# that keeps it somewhere else, and it is verified against the same pin, so a
	# path that is wrong about WHERE it is can never be wrong about WHAT it is.
	if [ -n "${MOSDNS_DNSCRYPT_ARCHIVE:-}" ]; then
		printf '%s\n' "$MOSDNS_DNSCRYPT_ARCHIVE"
		return 0
	fi
	printf '%s\n' "$BUILD/$DNSCRYPT_ARCHIVE"
}

archive=$(dnscrypt_archive)
if [ ! -f "$archive" ]; then
	die "the pinned dnscrypt-proxy source is not at $archive and a package that cannot
     be built is a real problem rather than something to skip. Seed it with:

       mkdir -p $BUILD
       curl -L -o $archive \\
         $DNSCRYPT_SOURCE_URL

     or point MOSDNS_DNSCRYPT_ARCHIVE at a copy you already have. Its digest is
     recorded in $DNSCRYPT_PIN and is checked before anything is built from it."
fi

# `sha256sum -c` against the pin, with the archive's own directory as the working
# directory, because the pin names a bare file name. This is the line that makes
# "never builds an unverified tree" true: it runs before the archive is opened, and
# a mismatch exits non-zero out of `set -e`.
# SELECTED BY SHAPE, and the shape is a 64-lowercase-hex first field. Not by
# position, and the first version of this line was exactly that -- "the first
# non-comment, non-blank line, first field" -- which broke the moment a labelled line
# was added above the digest: `recorded_digest` became the literal string
# `tag-commit:`, the non-empty guard was satisfied by a label, and the shipped
# BUILD-MANIFEST printed
#
#     archive sha256:   tag-commit:
#
# with the real digest on the NEXT line, where a person reading the .deb would not
# see it. A pin is a file that gains lines; position is not a stable way to find the
# one that matters. A label cannot be mistaken for a digest because a label ends in a
# colon, and a 64-hex field cannot be a label because a label is not hex.
recorded_digest=$(
	sed -n 's/^\([0-9a-f]\{64\}\)[[:space:]]\{1,\}\S\{1,\}$/\1/p' "$DNSCRYPT_PIN"
)
[ -n "$recorded_digest" ] ||
	die "$DNSCRYPT_PIN records no archive digest, and this build refuses to build from a tree
     whose digest nobody pinned. The line it wants is a sha256sum line: 64 hex characters,
     whitespace, and the archive's file name."
# The tag's commit, selected by LABEL inside a comment. A comment, not a bare
# `tag-commit:` line, because this file is a `sha256sum -c` file: a bare label above
# the digest makes that command print "WARNING: 1 line is improperly formatted" on a
# file whose own comment tells the reader to run it. Recorded here so that a future
# divergence is attributable to a RE-TAG -- which moves this SHA -- rather than to a
# transport change, which would not, and neither number is a signature.
recorded_commit=$(
	sed -n 's/^#[[:space:]]*tag-commit:[[:space:]]*\([0-9a-f]\{40\}\)[[:space:]]*$/\1/p' "$DNSCRYPT_PIN"
)
[ -n "$recorded_commit" ] ||
	die "$DNSCRYPT_PIN records no tag commit, so a re-tag upstream and a corrupted
     download would be indistinguishable and the pin would absorb the first silently"
( cd "$(dirname -- "$archive")" && sha256sum -c "$REPO/$DNSCRYPT_PIN" ) ||
	die "$archive does not match the digest recorded in $DNSCRYPT_PIN, and an unverified
     source tree is never built. The pin is the upstream tag's tarball digest; if
     upstream re-tagged, that is a change somebody has to look at, not a pin to
     update."

# A private extraction, and never over the tree it came from: the same tree built
# twice must not accumulate a second copy of anything.
rm -rf "$DNSCRYPT_DIR"
scratch_paths="$scratch_paths $DNSCRYPT_DIR"
mkdir -p "$DNSCRYPT_DIR"
tar -xzf "$archive" -C "$DNSCRYPT_DIR" --strip-components=1
[ -f "$DNSCRYPT_DIR/go.mod" ] || die "$archive has no go.mod in it, so it is not the source this package pins"
grep -q "^go $GO_REQUIRED_VERSION\$" "$DNSCRYPT_DIR/go.mod" ||
	die "the pinned resolver's go.mod asks for a Go release other than $GO_REQUIRED_VERSION"

# -mod=vendor because the archive ships its own vendor directory: a build that
# reached for the module proxy would be a build whose inputs are not the ones that
# were verified. CGO_ENABLED=0 because every one of this package's programs is a
# static Go binary and a package that ships a dynamically linked one would have to
# declare its libraries.
( cd "$DNSCRYPT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" "$GO" build \
	-mod=vendor -trimpath -ldflags "-s -w" \
	-o "$REPO/$BUILD/$PACKAGE.dnscrypt-proxy" ./dnscrypt-proxy )

# The two programs the verification steps below RUN, built for the machine doing the
# building. Same sources, same flags, different GOARCH -- and both are scratch, so
# neither is in the package and neither is in the build manifest.
verifier_dir=$BUILD/verifier-$HOST_ARCH
rm -rf "$verifier_dir"
# Absolute, like the staging root: the render below runs with its working directory
# at /, where a relative path resolves against that root instead of this one.
case "$verifier_dir" in
/*) ;;
*) verifier_dir=$REPO/$verifier_dir ;;
esac
scratch_paths="$scratch_paths $verifier_dir"
mkdir -p "$verifier_dir"
build_go_binary ./cmd/mosdns-cdnctl "$verifier_dir/mosdns-cdnctl" "$HOST_ARCH"
( cd "$DNSCRYPT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH="$HOST_ARCH" "$GO" build \
	-mod=vendor -trimpath -ldflags "-s -w" \
	-o "$verifier_dir/dnscrypt-proxy" ./dnscrypt-proxy )

# --- the staging root ---------------------------------------------------------

if [ -n "$STAGE" ]; then
	rm -rf "$STAGE"
else
	STAGE=$BUILD/staging-$ARCH
	rm -rf "$STAGE"
fi
# Absolute, because the render below runs in a private view of / with its working
# directory at /, and a relative staging path would resolve against THAT root rather
# than against this one -- which is a missing executable, not a relative path.
case "$STAGE" in
/*) ;;
*) STAGE=$REPO/$STAGE ;;
esac
mkdir -p "$STAGE/DEBIAN"
chmod 755 "$STAGE/DEBIAN"

place() {
	# place SOURCE DESTINATION [MODE]
	# The mode is explicit at every call site rather than inherited from the source
	# file or from this script's umask: a package's modes are part of what it
	# installs, and "whatever it happened to be" is not an answer a package-content
	# test can check.
	mode=${3:-644}
	install -D -m "$mode" "$1" "$STAGE$2"
}

# The two directories the installer's own record needs, and the three that survive
# a reboot. They are created here with nothing in them, which is the only state this
# package may put under /var/lib: an empty directory the postinst provisions.
#
# Every parent is created at 0755 as well, rather than being left to the umask, so
# the modes dpkg records are the ones that were asked for. A directory at 0775 in a
# package is a warning every installation of it will produce.
for directory in \
	/etc \
	/etc/mosdns \
	/etc/NetworkManager \
	/etc/NetworkManager/dispatcher.d \
	/etc/NetworkManager/dispatcher.d/no-wait.d \
	/usr \
	/usr/lib \
	/usr/lib/mosdns-router \
	/usr/lib/mosdns-router/mosdns_dhcp_bridge \
	/usr/lib/systemd \
	/usr/lib/systemd/system \
	/usr/lib/tmpfiles.d \
	/usr/share \
	/usr/share/doc \
	/usr/share/doc/mosdns-router \
	/usr/share/man \
	/usr/share/man/man1 \
	/usr/share/man/man8 \
	/usr/share/mosdns-router \
	/var \
	/var/lib \
	/var/lib/mosdns \
	/var/lib/mosdns/runtime \
	/var/lib/mosdns/lists; do
	install -d -m 755 "$STAGE$directory"
done

# The three programs, at the exact paths the units' ExecStart lines name, and the
# installer at the exact path mosdns-cdnctl's emergency-rollback verb execs.
place "$BUILD/$PACKAGE.router" /usr/lib/mosdns-router/mosdns-router 755
place "$BUILD/$PACKAGE.cdnctl" /usr/lib/mosdns-router/mosdns-cdnctl 755
place "$BUILD/$PACKAGE.dnscrypt-proxy" /usr/lib/mosdns-router/dnscrypt-proxy 755
place installer/mosdns_installer.py /usr/lib/mosdns-router/mosdns_installer.py 755

# The bridge, as an importable package: the dispatcher hook runs
# `python3 -m mosdns_dhcp_bridge.cli`, so the modules are files under a package
# directory and never a script with a name on $PATH.
for module in __init__ cli collect publish; do
	place "bridge/mosdns_dhcp_bridge/$module.py" \
		"/usr/lib/mosdns-router/mosdns_dhcp_bridge/$module.py" 644
done

# The units.
for unit in "$REPO"/packaging/systemd/*; do
	place "$unit" "/usr/lib/systemd/system/$(basename -- "$unit")" 644
done

# The documents an operator edits. policy.yaml is the committed output of
# config.Marshal(config.Defaults()); the other three say in their own comments what
# they are for. The forced-ECH list ships with comments and no entries, because a
# zero-byte list is REFUSED by the response rewriter and a file of comments is how
# this project ships "forcing off".
place configs/policy.yaml /etc/mosdns/policy.yaml 644
place packaging/config/force-ech-domains.txt /etc/mosdns/force-ech-domains.txt 644
place packaging/config/cloudflare.txt /etc/mosdns/cloudflare.txt 644
place packaging/config/cloudfront-domains.yaml /etc/mosdns/cloudfront-domains.yaml 644
# The watchdog's setting, at 0644 like the four above and a conffile like all of
# them. It is placed here rather than generated, and the two numbers in it are
# the shipped defaults the program also holds: a case reads this file and the
# program's constants and requires them equal, because a switch whose default
# exists in two places is a switch whose default is one of them.
place packaging/config/watchdog.yaml /etc/mosdns/watchdog.yaml 644

# The NetworkManager hook, executable, because NetworkManager runs it.
place packaging/networkmanager/10-mosdns-dhcp-bridge \
	/etc/NetworkManager/dispatcher.d/no-wait.d/10-mosdns-dhcp-bridge 755

# The tmpfiles entry, the licence and the pinned reference data.
place packaging/tmpfiles.d/mosdns-router.conf /usr/lib/tmpfiles.d/mosdns-router.conf 644
place packaging/copyright "/usr/share/doc/$PACKAGE/copyright" 644
place configs/cn-domains.txt /usr/share/mosdns-router/cn-domains.txt 644
place configs/source-lock.json /usr/share/mosdns-router/source-lock.json 644
# The pinned Cloudflare range document, and the lock that accounts for it. The
# second of the two pairs this package carries and the reason an installation can
# complete on a machine with no route to the internet: the prefix list the
# response rewriter refuses to construct without comes from one endpoint, so a
# package that ships no snapshot of it cannot be installed offline at all. It is
# placed and verified, never re-pinned, exactly as the China pair is.
place configs/cloudflare-ranges.json /usr/share/mosdns-router/cloudflare-ranges.json 644
place configs/cloudflare-ranges.lock.json /usr/share/mosdns-router/cloudflare-ranges.lock.json 644

# The manual pages, compressed the way a Debian package ships them. `gzip -9n` and
# not plain gzip because gzip records the name and the timestamp by default, and a
# timestamp would make the same page compress to different bytes on every build,
# which is the one thing a pinned digest cannot survive.
for page in mosdns-cdnctl.1 mosdns-router.8 dnscrypt-proxy.8; do
	section=$(printf '%s' "$page" | sed 's/.*\.//')
	gzip -9n -c "packaging/man/$page" >"$STAGE/usr/share/man/man$section/$page.gz"
	chmod 644 "$STAGE/usr/share/man/man$section/$page.gz"
done

# --- the two generated documents ----------------------------------------------
#
# Rendered here, through the control tool this very package installs, and not
# copied out of the repository. A hand-maintained shipped copy bypasses the render
# path the policy makes mandatory, and it drifts silently: the repository's copy
# would still be what a reviewer reads while the package carried something else.
#
# The render runs in a private view of / whose /etc is this staging root, so the
# policy it reads and the paths it stamps are the installed ones. Both documents
# then name /etc/mosdns/policy.yaml, which is what makes them byte-equal to a
# production render, and the package-content test re-renders and compares.
render_log=$(mktemp)
scratch_paths="$scratch_paths $render_log"
if ! "$BWRAP" --ro-bind / / --bind "$STAGE/etc" /etc --chdir / \
	"$verifier_dir/mosdns-cdnctl" render \
	--policy /etc/mosdns/policy.yaml --out /etc/mosdns >"$render_log" 2>&1; then
	cat "$render_log" >&2
	die "mosdns-cdnctl render refused, so this package has no routing documents to ship.
     The message above is the renderer's own."
fi
sed 's/^/build-deb.sh: /' "$render_log"
chmod 644 "$STAGE/etc/mosdns/mosdns.yaml" "$STAGE/etc/mosdns/dnscrypt-proxy.toml"

# The resolver is asked whether it accepts the document it is about to run, because
# `-check` is its command mode: it loads the configuration, validates it, and exits
# without initialising networking, so it binds no socket, opens no connection and
# touches nothing outside this staging root. A document this binary refuses is a
# document whose foreign branch would be gone the first time the unit started.
if ! "$verifier_dir/dnscrypt-proxy" -check \
	-config "$STAGE/etc/mosdns/dnscrypt-proxy.toml" >"$render_log" 2>&1; then
	sed 's/^/build-deb.sh: /' "$render_log" >&2
	die "the packaged dnscrypt-proxy 2.1.18 refuses the resolver document this build
     rendered. A package that ships a resolver which will not load its own
     configuration is a failed first start, so the build refuses to make one."
fi

# --- the build manifest -------------------------------------------------------
#
# What this package is, made of. Not a changelog entry: the digests are here so that
# a person holding a .deb can say which tree, which Go release and which upstream
# archive it came from without trusting the build host that produced it.
{
	echo "mosdns-router build manifest"
	echo "==========================="
	echo
	echo "package:          $PACKAGE"
	echo "package version:  $PACKAGE_VERSION"
	echo "build identity:"
	echo "version:          $VERSION"
	echo "revision:         $REVISION"
	echo "build time:       $BUILD_TIME"
	echo "buildinfo pkg:    $BUILDINFO_PKG"
	echo "architecture:     $ARCH"
	echo "build script:     scripts/build-deb.sh"
	echo
	echo "Toolchain"
	echo "---------"
	echo "go release:       go$GO_REQUIRED_VERSION"
	echo "cgo:              disabled (every shipped program is a static binary)"
	echo "trimpath:         yes (no path from the build host is compiled in)"
	echo
	echo "Module digests (sha256)"
	echo "------------------------"
	for module in go.mod go.sum; do
		echo "$module:  $(sha256sum "$module" | cut -d' ' -f1)"
	done
	echo
	echo "dnscrypt-proxy $DNSCRYPT_VERSION"
	echo "----------------------$(printf '%*s' ${#DNSCRYPT_VERSION} '' | tr ' ' '-')"
	echo "source:             $DNSCRYPT_SOURCE_URL"
	echo "archive:            $DNSCRYPT_ARCHIVE"
	echo "archive sha256:     $recorded_digest"
	echo "tag commit:         $recorded_commit"
	echo "go.mod sha256:      $(sha256sum "$DNSCRYPT_DIR/go.mod" | cut -d' ' -f1)"
	echo "go.sum sha256:      $(sha256sum "$DNSCRYPT_DIR/go.sum" | cut -d' ' -f1)"
	echo "modules.txt sha256: $(sha256sum "$DNSCRYPT_DIR/vendor/modules.txt" | cut -d' ' -f1)"
	echo "build flags:        -mod=vendor CGO_ENABLED=0 -trimpath -ldflags -s -w"
	echo "built for:          $ARCH"
	echo "verified with:      the host's own build of the same sources ($HOST_ARCH), because"
	echo "                    the render and the resolver's -check are steps this build machine"
	echo "                    runs and neither has an architecture-dependent result"
	echo
	echo "Shipped binary digests (sha256)"
	echo "--------------------------------"
	sha256sum \
		"$STAGE/usr/lib/mosdns-router/mosdns-router" \
		"$STAGE/usr/lib/mosdns-router/mosdns-cdnctl" \
		"$STAGE/usr/lib/mosdns-router/dnscrypt-proxy" |
		sed 's#'"$STAGE"'##' | awk '{print $2 ":  " $1}'
	echo
	echo "Generated document digests (sha256)"
	echo "-----------------------------------"
	for document in mosdns.yaml dnscrypt-proxy.toml; do
		echo "$document:  $(sha256sum "$STAGE/etc/mosdns/$document" | cut -d' ' -f1)"
	done
	echo "render policy:   /etc/mosdns/policy.yaml"
	echo "render out:      /etc/mosdns"
	echo
	echo "Reference data"
	echo "--------------"
	echo "cn-domains.txt sha256: $(sha256sum "$STAGE/usr/share/mosdns-router/cn-domains.txt" | cut -d' ' -f1)"
	echo "The install verifies that digest against list_sha256 in source-lock.json and"
	echo "never re-pins it; see /etc/mosdns/policy.yaml and mosdns-cdnctl(1)."
	echo
	echo "cloudflare-ranges.json sha256: $(sha256sum "$STAGE/usr/share/mosdns-router/cloudflare-ranges.json" | cut -d' ' -f1)"
	echo "ranges-pinned-at: $(sed -n 's/.*"fetched_at"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STAGE/usr/share/mosdns-router/cloudflare-ranges.lock.json")"
	echo "ranges-pinned-revision: $(sed -n 's/.*"revision"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$STAGE/usr/share/mosdns-router/cloudflare-ranges.lock.json")"
	echo "The install verifies that digest against sha256 in cloudflare-ranges.lock.json, and"
	echo "refuses a snapshot it cannot account for rather than installing a selector over"
	echo "ranges it cannot name. It is never re-pinned: the published artifacts under"
	echo "/var/lib/mosdns/lists are written only by 'mosdns-cdnctl update-lists"
	echo "--refresh-ranges', which reads a machine's own document before this one. Run"
	echo "'mosdns-cdnctl update-lists --check' to see how old the pin is."
} >"$STAGE/usr/share/doc/$PACKAGE/BUILD-MANIFEST"
chmod 644 "$STAGE/usr/share/doc/$PACKAGE/BUILD-MANIFEST"

# --- the Debian metadata ------------------------------------------------------

place packaging/debian/control /DEBIAN/control 644
place packaging/debian/changelog /DEBIAN/changelog 644
# The conffiles list, with its comments stripped, because dpkg reads this file
# literally: a `#` line in DEBIAN/conffiles is a file named `#`, and a comment in
# the repository's copy is a file the package would try to own on every install.
# The explanation stays in packaging/debian/conffiles, where a person reads it.
grep -v '^[[:space:]]*#' packaging/debian/conffiles | grep -v '^[[:space:]]*$' \
	>"$STAGE/DEBIAN/conffiles"
chmod 644 "$STAGE/DEBIAN/conffiles"
# 755 on the maintainer scripts: dpkg runs them, and a package whose postinst is not
# executable is a package whose install silently does nothing on some dpkg versions.
for script in postinst prerm postrm; do
	place "packaging/debian/$script" "/DEBIAN/$script" 755
done

# Two fields are computed rather than copied, and both of them are fields dpkg
# REJECTS if they are the repository's own text:
#
#   Installed-Size  is in kibibytes, it is computed because a typed one is wrong the
#                   moment a binary changes size, and dpkg warns about a missing one.
#   Architecture    the repository declares the SET this package is built for and the
#                   built package carries the ONE it was built for, because dpkg
#                   rejects a space-separated Architecture field. A binary labelled
#                   with a name it does not have is worse than a missing label.
#
# Neither insertion may leave a blank line behind it: a blank line ENDS a stanza in a
# Debian control file, so an inserted line followed by one is two stanzas, and dpkg
# reports the second as a package with no Package field. The field goes immediately
# above Description, which is where the format's own convention puts it.
installed_size=$(du -sk --apparent-size "$STAGE" | cut -f1)
{
	sed -e 's/^Architecture:.*/Architecture: '"$ARCH"'/' \
		-e '/^Description:/i Installed-Size: '"$installed_size" \
		packaging/debian/control
} >"$STAGE/DEBIAN/control"
chmod 644 "$STAGE/DEBIAN/control"

# md5sums is what dpkg verifies an unpacked file against, and it is written here
# rather than left out: a package with no md5sums is a package dpkg will warn about
# and an owner cannot check. The paths are relative to the package root, which is
# what the file's own format asks for.
( cd "$STAGE" && find . -type f ! -path './DEBIAN/*' -print0 |
	sort -z | xargs -0 md5sum >DEBIAN/md5sums )
chmod 644 "$STAGE/DEBIAN/md5sums"

# --- and the package ----------------------------------------------------------

if [ -n "$STAGE_ONLY" ]; then
	echo "build-deb.sh: staged at $STAGE; no package was written, because --stage was asked for"
	exit 0
fi

# The staging root is the only thing under test and the only thing dpkg-deb is
# given. --root-owner-group because this build does not run as root and a package
# whose file owners are the build user's uid is a package that installs files
# nobody can read.
mkdir -p "$BUILD"
out=$BUILD/${PACKAGE}_${PACKAGE_VERSION}_${ARCH}.deb
rm -f "$out"
dpkg-deb --root-owner-group --build "$STAGE" "$out"
echo "build-deb.sh: wrote $out ($(wc -c <"$out") bytes)"
echo "build-deb.sh: inspect it with"
echo "  dpkg-deb --info $out"
echo "  dpkg-deb --contents $out"
echo "build-deb.sh: nothing was installed on this machine, and no maintainer script ran."
