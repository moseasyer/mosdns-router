#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
	echo "usage: go-module-safe.sh COMMAND [ARG ...]" >&2
	exit 2
fi

module_dir=$(pwd)
mod_path="$module_dir/go.mod"
sum_path="$module_dir/go.sum"
snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/mosdns-go-module.XXXXXX")
mod_snapshot="$snapshot_dir/go.mod"
sum_snapshot="$snapshot_dir/go.sum"
mod_present=0
sum_present=0

snapshot_file() {
	path=$1
	snapshot=$2
	if [ -e "$path" ] || [ -L "$path" ]; then
		if ! cp -p "$path" "$snapshot"; then
			rm -rf "$snapshot_dir"
			echo "go-module-safe.sh: snapshot failed: $path" >&2
			exit 1
		fi
		return 0
	fi
	return 1
}

if snapshot_file "$mod_path" "$mod_snapshot"; then
	mod_present=1
fi
if snapshot_file "$sum_path" "$sum_snapshot"; then
	sum_present=1
fi

restore_files() {
	original_status=$1
	# Clear handlers before touching files so a second signal cannot interrupt
	# restoration. Disable errexit only after preserving the invoking status.
	trap - EXIT HUP INT TERM
	set +e
	restore_status=0
	if [ "$mod_present" -eq 1 ]; then
		cp -p "$mod_snapshot" "$mod_path" || restore_status=1
	else
		rm -f "$mod_path" || restore_status=1
	fi
	if [ "$sum_present" -eq 1 ]; then
		cp -p "$sum_snapshot" "$sum_path" || restore_status=1
	else
		rm -f "$sum_path" || restore_status=1
	fi
	rm -rf "$snapshot_dir" || restore_status=1
	if [ "$original_status" -eq 0 ] && [ "$restore_status" -ne 0 ]; then
		exit "$restore_status"
	fi
	exit "$original_status"
}

on_exit() {
	status=$?
	restore_files "$status"
}

on_signal() {
	case "$1" in
		HUP) status=129 ;;
		INT) status=130 ;;
		TERM) status=143 ;;
		*) status=1 ;;
	esac
	restore_files "$status"
}

trap on_exit EXIT
trap 'on_signal HUP' HUP
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

"$@"
