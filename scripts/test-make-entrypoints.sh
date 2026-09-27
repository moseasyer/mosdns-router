#!/bin/sh
# Regression test for the Make entry points. It proves three things about the
# real Makefile:
#
# 1. Every entry point runs through an exact go1.25.8 toolchain guard, so a
#    different or missing Go release is refused before any command runs.
# 2. Every Go invocation the entry points plan is readonly, so building,
#    testing, and vetting can never rewrite go.mod or go.sum.
# 3. The Python bridge suite is reachable from the test entry points, because
#    the state document the Go plugin reads is written by Python.
#
# The entry points are exercised with stand-in toolchains and with `make -n`,
# so the test never builds the project, never needs a second Go release, and
# never touches the repository's module files.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

work=$(mktemp -d "${TMPDIR:-/tmp}/mosdns-make-entrypoints.XXXXXX")
cleanup() {
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

real_go=${GO:-go}

cat >"$work/go-wrong-version" <<'EOF'
#!/bin/sh
if [ "${1-}" = version ]; then
	echo "go version go1.24.6 linux/amd64"
	exit 0
fi
echo "the wrong Go release must never be used for a real command" >&2
exit 1
EOF
# The exact release the guard must accept, and a same-minor patch it must not:
# dnscrypt-proxy 2.1.18 declares `go 1.25.8` in its own go.mod, so an older patch
# of the same minor cannot build the packaged resolver. A guard that accepted the
# minor instead of the exact release would let that build fail later, off-host.
cat >"$work/go-required-version" <<'EOF'
#!/bin/sh
if [ "${1-}" = version ]; then
	echo "go version go1.25.8 linux/amd64"
	exit 0
fi
echo "the required Go release must never be used for a real command" >&2
exit 1
EOF
cat >"$work/go-superseded-version" <<'EOF'
#!/bin/sh
if [ "${1-}" = version ]; then
	echo "go version go1.25.0 linux/amd64"
	exit 0
fi
echo "a superseded Go release must never be used for a real command" >&2
exit 1
EOF
cat >"$work/go-not-go" <<'EOF'
#!/bin/sh
echo "not a go toolchain" >&2
exit 127
EOF
chmod 0755 "$work/go-wrong-version" "$work/go-required-version" "$work/go-superseded-version" "$work/go-not-go"

cp go.mod "$work/go.mod.before"
cp go.sum "$work/go.sum.before"

failures=0
fail() {
	echo "make entry point regression: $1" >&2
	failures=$((failures + 1))
}

run_make() {
	# run_make ok|fail DESCRIPTION ARGS...
	# `ok` requires a zero status; `fail` requires any non-zero status, because
	# the exact status of a refused build belongs to make, not to this contract.
	expectation=$1
	shift
	description=$1
	shift
	status=0
	make --no-print-directory "$@" >"$work/output" 2>"$work/error" || status=$?
	case "$expectation" in
	ok)
		if [ "$status" -ne 0 ]; then
			fail "$description exited $status, want success"
			sed 's/^/    /' "$work/error" >&2 || true
		fi
		;;
	fail)
		if [ "$status" -eq 0 ]; then
			fail "$description succeeded, want a refusal"
			sed 's/^/    /' "$work/output" >&2 || true
		fi
		;;
	*)
		fail "internal error: unknown expectation $expectation"
		;;
	esac
}

# 1. The guard accepts the pinned release and refuses everything else.
run_make ok "check-go with $real_go" check-go GO="$real_go"
run_make ok "check-go with the pinned go1.25.8" check-go GO="$work/go-required-version"
run_make fail "check-go with the superseded go1.25.0" check-go GO="$work/go-superseded-version"
run_make fail "check-go with go1.24.6" check-go GO="$work/go-wrong-version"
run_make fail "check-go with a non-Go program" check-go GO="$work/go-not-go"

# 2. Every entry point goes through the guard and stays readonly.
for target in test test-integration build cross-build verify verify-build-info; do
	status=0
	make --no-print-directory -n "$target" GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
	if [ "$status" -ne 0 ]; then
		fail "dry run of $target exited $status"
		sed 's/^/    /' "$work/dryrun" >&2 || true
		continue
	fi
	if ! grep -q 'go-wrong-version version' "$work/dryrun"; then
		fail "$target does not probe the Go toolchain version"
	fi
	planned_go=0
	while IFS= read -r line; do
		case "$line" in
		*' build '*|*' test '*|*' vet '*|*' run '*)
			planned_go=$((planned_go + 1))
			case "$line" in
			*' -mod=readonly '*) ;;
			*) fail "$target invokes Go without -mod=readonly: $line" ;;
			esac
			case "$line" in
			*' -mod=mod '*|*' mod tidy'*|*' get '*) fail "$target can mutate module files: $line" ;;
			esac
			;;
		esac
	done <"$work/dryrun"
	if [ "$planned_go" -eq 0 ]; then
		fail "$target plans no Go build/test/vet command"
	fi
done

# 3. Every produced binary carries the version, revision, and build time, and a
#    verification step parses them back out of the built router.
for target in build cross-build verify-build-info; do
	status=0
	make --no-print-directory -n "$target" GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
	if [ "$status" -ne 0 ]; then
		fail "dry run of $target exited $status"
		continue
	fi
	builds=0
	while IFS= read -r line; do
		case "$line" in
		*' build '*)
			builds=$((builds + 1))
			for variable in Version Revision BuildTime; do
				case "$line" in
				*"-X mosdns-router/internal/buildinfo.$variable="*) ;;
				*) fail "$target does not inject buildinfo.$variable: $line" ;;
				esac
			done
			;;
		esac
	done <"$work/dryrun"
	if [ "$builds" -eq 0 ]; then
		fail "$target plans no Go build command"
	fi
done

status=0
make --no-print-directory -n verify-build-info GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
if ! grep -q 'internal/buildinfo/cmd/check' "$work/dryrun"; then
	fail "verify-build-info does not parse the built router's build-info output"
	sed 's/^/    /' "$work/dryrun" >&2 || true
fi

# 4. The overridable metadata variables must reach the linker.
for override in "VERSION 1.2.3" "REVISION cafebabe" "BUILD_TIME 2026-09-25T00:00:00Z"; do
	set -- $override
	variable=$1
	value=$2
	case "$variable" in
	VERSION) field=Version ;;
	REVISION) field=Revision ;;
	BUILD_TIME) field=BuildTime ;;
	*) fail "internal error: unknown override $variable" ;;
	esac
	status=0
	make --no-print-directory -n build GO="$work/go-wrong-version" "$variable=$value" >"$work/override" 2>&1 || status=$?
	if [ "$status" -ne 0 ]; then
		fail "dry run of build $variable=$value exited $status"
		continue
	fi
	if ! grep -q -- "-X mosdns-router/internal/buildinfo.$field=$value" "$work/override"; then
		fail "build does not honour the $variable override"
		sed 's/^/    /' "$work/override" >&2 || true
	fi
done

# 6. The Python bridge suite runs from the test entry points, because the state
#    document the Go plugin reads is written by Python and a change to one half
#    that only the other half's suite can see is a change nobody noticed.
for target in test test-python verify; do
	status=0
	make --no-print-directory -n "$target" GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
	if [ "$status" -ne 0 ]; then
		fail "dry run of $target exited $status"
		sed 's/^/    /' "$work/dryrun" >&2 || true
		continue
	fi
	if ! grep -q 'unittest discover -s bridge/tests' "$work/dryrun"; then
		fail "$target does not run the python bridge suite"
		sed 's/^/    /' "$work/dryrun" >&2 || true
	fi
done

# 6b. The installer suite runs from the acceptance gate. `test-python` discovers
#     bridge/tests only, so without a target of its own NOTHING holds the eight unit
#     files, the preflight, the transaction, the uninstall or the package's content
#     to what this project decided -- and a gate that stops enforcing the rules a
#     package is built under keeps passing. The target has to name the installer
#     suite, and `verify` has to depend on the TARGET rather than repeating its
#     recipe, so the two cannot drift apart while the recipe still works.
for target in test-installer verify; do
	status=0
	make --no-print-directory -n "$target" GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
	if [ "$status" -ne 0 ]; then
		fail "dry run of $target exited $status"
		sed 's/^/    /' "$work/dryrun" >&2 || true
		continue
	fi
	if ! grep -q 'unittest discover -s installer/tests' "$work/dryrun"; then
		fail "$target does not run the python installer suite"
		sed 's/^/    /' "$work/dryrun" >&2 || true
	fi
done

# 6c. `package` is part of the gate, and it installs nothing. A package that cannot
#     be built is a real problem rather than something to skip, so the build belongs
#     in the acceptance gate -- and a build that installed what it built would put
#     the machine running the gate on a resolver, which is the one thing this
#     project's whole boundary is about. So `verify` reaches the target, the target
#     runs the build script, and the planned commands install nothing.
status=0
make --no-print-directory -n verify GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
	fail "dry run of verify exited $status"
	sed 's/^/    /' "$work/dryrun" >&2 || true
elif ! grep -q 'scripts/build-deb.sh' "$work/dryrun"; then
	fail "verify does not build the package, so the artifact whose content this project decides is not in the gate"
	sed 's/^/    /' "$work/dryrun" >&2 || true
fi
for forbidden in 'dpkg -i' 'apt-get' 'systemctl ' 'nmcli '; do
	if grep -q -- "$forbidden" "$work/dryrun"; then
		fail "the acceptance gate plans a command that would change this machine: $forbidden"
	fi
done

# 7. The acceptance gate runs the end-to-end suite. tests/integration is the only
#    place the routing and the response-rewrite promises are checked at all -- a
#    document-level test cannot see where a query was sent, and cannot see what a
#    client received -- and `go test -short ./...` skips it, so a gate that stopped
#    depending on it would quietly stop proving anything end to end. The flag is
#    part of the assertion, not only of the target's own comment: -count=1 is what
#    stops a cached result from satisfying the gate with no case run, and a verify
#    that reached the package without it would be a gate that says nothing.
status=0
make --no-print-directory -n verify GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
	fail "dry run of verify exited $status"
	sed 's/^/    /' "$work/dryrun" >&2 || true
elif ! grep -q 'test -mod=readonly -count=1 .*tests/integration' "$work/dryrun"; then
	fail "verify does not run the end-to-end suite in tests/integration with -count=1, so a cached result could satisfy it with no case run"
	sed 's/^/    /' "$work/dryrun" >&2 || true
fi
# The unit-test entry point must not run it either: it is the -short suite, and
# running the same cases twice in one gate would double the gate's cost for
# nothing.
status=0
make --no-print-directory -n test GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
	fail "dry run of test exited $status"
	sed 's/^/    /' "$work/dryrun" >&2 || true
elif ! grep -q 'test -mod=readonly -short' "$work/dryrun"; then
	fail "test does not run the unit suites with -short, so the end-to-end suite runs twice per gate"
	sed 's/^/    /' "$work/dryrun" >&2 || true
elif grep -q 'tests/integration' "$work/dryrun"; then
	fail "test runs the end-to-end suite, which belongs to test-integration"
	sed 's/^/    /' "$work/dryrun" >&2 || true
fi

# 7b. -count=1 belongs to the test-integration recipe. This suite binds sockets
#     and runs a child process, and neither is an input the Go test cache can
#     see, so a cached result is a gate satisfied without a single case having
#     been asked. The Makefile says so in a comment; this is the assertion that
#     stops the flag and the reasoning from drifting apart, which is what happens
#     if the flag is dropped and only the comment is left.
status=0
make --no-print-directory -n test-integration GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
	fail "dry run of test-integration exited $status"
	sed 's/^/    /' "$work/dryrun" >&2 || true
elif ! grep -q 'test -mod=readonly -count=1 .*tests/integration' "$work/dryrun"; then
	fail "test-integration does not pass -count=1, so a cached result could satisfy the gate with no case run"
	sed 's/^/    /' "$work/dryrun" >&2 || true
fi

# 7c. MOSDNS_REQUIRE_INTEGRATION has to be exported by the recipe, and on by
#     default. The end-to-end suite skips on a host with no non-loopback IPv4
#     address, because the production DHCP state decoder refuses a loopback
#     upstream; that skip is right on a laptop and wrong in a gate, so the switch
#     turns it into a failure. Nothing set the switch, so a loopback-only host
#     passed `make verify` with zero end-to-end coverage and no indication of it.
#     `?=` keeps the opt-out working: `make verify MOSDNS_REQUIRE_INTEGRATION=0`.
#     This is the assertion that stops the export and the default from drifting
#     apart, which is what happens if either is dropped and only the comment is
#     left.
for target in test-integration verify; do
	status=0
	make --no-print-directory -n "$target" GO="$work/go-wrong-version" >"$work/dryrun" 2>&1 || status=$?
	if [ "$status" -ne 0 ]; then
		fail "dry run of $target exited $status"
		sed 's/^/    /' "$work/dryrun" >&2 || true
		continue
	fi
	if ! grep -q "MOSDNS_REQUIRE_INTEGRATION='1' .*tests/integration" "$work/dryrun"; then
		fail "$target does not run the end-to-end suite with MOSDNS_REQUIRE_INTEGRATION=1, so a host that skips those cases passes the gate silently"
		sed 's/^/    /' "$work/dryrun" >&2 || true
	fi
done
# The opt-out has to survive: a developer on a loopback-only host must still be
# able to run the gate, which is what `?=` is for, and a gate that cannot be run
# at all is a gate nobody runs.
status=0
make --no-print-directory -n test-integration MOSDNS_REQUIRE_INTEGRATION=0 GO="$work/go-wrong-version" >"$work/override" 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
	fail "dry run of test-integration with MOSDNS_REQUIRE_INTEGRATION=0 exited $status"
	sed 's/^/    /' "$work/override" >&2 || true
elif ! grep -q "MOSDNS_REQUIRE_INTEGRATION='0' .*tests/integration" "$work/override"; then
	fail "test-integration honours MOSDNS_REQUIRE_INTEGRATION=0, so a developer on a host without a usable address cannot run the gate at all"
	sed 's/^/    /' "$work/override" >&2 || true
fi

# 8. Nothing the test ran may change the module files.
if ! cmp -s "$work/go.mod.before" go.mod; then
	fail "go.mod was modified while checking the entry points"
fi
if ! cmp -s "$work/go.sum.before" go.sum; then
	fail "go.sum was modified while checking the entry points"
fi

if [ "$failures" -ne 0 ]; then
	echo "make entry point regression test failed with $failures problem(s)" >&2
	exit 1
fi
echo "make entry point regression test passed"
