#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
helper="$root/scripts/go-module-safe.sh"
if [ ! -f "$helper" ]; then
	echo "safe module wrapper is missing: $helper" >&2
	exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/mosdns-module-wrapper-test.XXXXXX")
cleanup() {
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cp "$helper" "$work/go-module-safe.sh"
cat >"$work/fake-go" <<'EOF'
#!/bin/sh
set -eu
case "${1-}" in
	test|build|vet)
		printf '%s\n' '// fake-go module mutation' >> go.mod
		printf '%s\n' '// fake-go checksum mutation' >> go.sum
		if [ "${FAKE_GO_FAIL:-0}" = 1 ]; then
			exit 42
		fi
		exit 0
		;;
	*)
		echo "unexpected fake-go arguments: $*" >&2
		exit 64
		;;
esac
EOF
chmod 0755 "$work/fake-go"
cat >"$work/Makefile" <<'EOF'
MODULE_SAFE = sh go-module-safe.sh
.PHONY: module-wrapper-success module-wrapper-failure
module-wrapper-success:
	@$(MODULE_SAFE) $(FAKE_GO) test
module-wrapper-failure:
	@FAKE_GO_FAIL=1 $(MODULE_SAFE) $(FAKE_GO) test
EOF
cat >"$work/go.mod" <<'EOF'
module example.invalid/module-wrapper

go 1.25.0

toolchain go1.25.0
EOF
cat >"$work/go.sum" <<'EOF'
example.invalid/module-wrapper v1.0.0 h1:pre-existing-checksum
EOF
printf '%s\n' '// pre-existing go.mod edit' >>"$work/go.mod"
printf '%s\n' '// pre-existing go.sum edit' >>"$work/go.sum"
cp "$work/go.mod" "$work/expected.go.mod"
cp "$work/go.sum" "$work/expected.go.sum"

run_case() {
	mode=$1
	expect_failure=$2
	output="$work/$mode.out"
	set +e
	(
		cd "$work"
		make --no-print-directory -f Makefile FAKE_GO="$work/fake-go" "module-wrapper-$mode" >"$output" 2>&1
	)
	status=$?
	set -e
	if [ "$expect_failure" = yes ] && [ "$status" -eq 0 ]; then
		echo "module wrapper unexpectedly succeeded in $mode case" >&2
		cat "$output" >&2
		return 1
	fi
	if [ "$expect_failure" = no ] && [ "$status" -ne 0 ]; then
		echo "module wrapper failed in $mode case with status $status" >&2
		cat "$output" >&2
		return 1
	fi
	if ! cmp -s "$work/expected.go.mod" "$work/go.mod"; then
		echo "go.mod was not byte-restored after $mode case" >&2
		diff -u "$work/expected.go.mod" "$work/go.mod" >&2 || true
		return 1
	fi
	if ! cmp -s "$work/expected.go.sum" "$work/go.sum"; then
		echo "go.sum was not byte-restored after $mode case" >&2
		diff -u "$work/expected.go.sum" "$work/go.sum" >&2
		return 1
	fi
}

run_case success no
run_case failure yes
echo "module wrapper regression test passed"
