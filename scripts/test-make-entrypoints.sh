#!/bin/sh
# Regression test for the Make entry points. It proves two things about the
# real Makefile:
#
# 1. Every entry point runs through an exact go1.25.0 toolchain guard, so a
#    different or missing Go release is refused before any command runs.
# 2. Every Go invocation the entry points plan is readonly, so building,
#    testing, and vetting can never rewrite go.mod or go.sum.
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
cat >"$work/go-not-go" <<'EOF'
#!/bin/sh
echo "not a go toolchain" >&2
exit 127
EOF
chmod 0755 "$work/go-wrong-version" "$work/go-not-go"

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
run_make fail "check-go with go1.24.6" check-go GO="$work/go-wrong-version"
run_make fail "check-go with a non-Go program" check-go GO="$work/go-not-go"

# 2. Every entry point goes through the guard and stays readonly.
for target in test build cross-build verify; do
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

# 3. Nothing the test ran may change the module files.
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
