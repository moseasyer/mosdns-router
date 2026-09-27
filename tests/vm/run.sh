#!/usr/bin/env bash
# Boot the disposable system-level test machine.
#
# This is the tool for what a container cannot model: a real NetworkManager
# managing a real wired NIC, a real DHCP lease, a real systemd-resolved takeover
# of /etc/resolv.conf, and therefore a real install/uninstall transaction. The
# container (tests/system/) covers the tools' output formats and the unit files;
# this covers the machine.
#
# Two properties are non-negotiable and are enforced below rather than trusted:
#
#   1. The host's DNS is never involved. The guest gets user-mode NAT, which is a
#      private network stack of its own; nothing in the guest can reach the
#      host's resolver, and nothing in the guest can change it.
#   2. No acceleration is assumed. This host has no /dev/kvm and no vmx/svm flag,
#      so qemu runs under TCG (pure software emulation). That is slow -- expect
#      minutes for a boot and much longer for an install. It is correct, not fast.
#
# Usage:
#   tests/vm/run.sh install        # create the disk, install unattended
#   tests/vm/run.sh up [wait]      # boot, wait for SSH (default 900s)
#   tests/vm/run.sh run CMD...     # boot, wait, run CMD in the guest, power off
#   tests/vm/run.sh down           # force off, keep the disk
#   tests/vm/run.sh destroy        # remove the disk
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

VM_NAME="${MOSDNS_VM_NAME:-mosdns-test-vm}"
VM_DIR="${MOSDNS_VM_DIR:-$ROOT/build/vm}"
DISK="$VM_DIR/$VM_NAME.qcow2"
# NOT under /tmp: this host's /tmp is a 1.7G tmpfs and the desktop ISO is ~6G, so
# an ISO staged there fails part-way with curl error 23 and a full tmpfs. /home
# is real disk.
ISO="${MOSDNS_VM_ISO:-$HOME/iso/ubuntu-24.04.5.1-desktop-amd64.iso}"
SEED="$HERE/autoinstall.yaml"
MEM="${MOSDNS_VM_MEM:-3072}"
CPUS="${MOSDNS_VM_CPUS:-2}"
SSH_PORT="${MOSDNS_VM_SSH_PORT:-2222}"
MONITOR_SOCK="$VM_DIR/monitor.sock"
SERIAL_LOG="$VM_DIR/serial.log"

mkdir -p "$VM_DIR"

die() { printf '\n!! %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed"; }
need qemu-system-x86_64
need qemu-img

# TCG unless the host actually offers KVM. Never guess: a wrong -accel makes qemu
# fail in a way that looks like an unrelated bug.
ACCEL=tcg
if [ -w /dev/kvm ]; then
  ACCEL=kvm
fi

qemu_args() {
  # -nographic: no window. The desktop is installed but never started, and the
  #   only console anyone looks at is the serial log.
  # user-mode NAT: a private network for the guest. The host's resolver is not
  #   reachable from here, which is the property that makes this safe to run.
  # -no-reboot: the installer reboots at the end; we want that to end the run.
  printf '%s\n' \
    -name "$VM_NAME" \
    -machine q35 \
    -accel "$ACCEL" \
    -m "$MEM" \
    -smp "$CPUS" \
    -drive "file=$DISK,if=virtio,format=qcow2" \
    -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial "file:$SERIAL_LOG" \
    -monitor "unix:$MONITOR_SOCK,server,nowait" \
    -no-reboot
}

case "${1:-}" in
  install)
    [ -f "$ISO" ] || die "ISO not found: $ISO (see the ledger for the download URL)"
    qemu-img create -f qcow2 -F qcow2 "$DISK" 20G
    cp "$SEED" "$VM_DIR/autoinstall.yaml"
    # A NoCloud seed: the installer reads a filesystem labelled CIDATA.
    mkisofs -output seed.img -volid CIDATA -joliet -rock \
      -quiet "$VM_DIR/autoinstall.yaml" 2>/dev/null \
      || die "mkisofs/genisoimage is required for the autoinstall seed"
    qemu-img create -f qcow2 -F qcow2 "$VM_DIR/overlay.qcow2" 20G \
      && qemu-img rebase -u -b "$DISK" -F qcow2 "$VM_DIR/overlay.qcow2"
    printf 'installing (TCG, expect this to take a long time)...\n'
    qemu-system-x86_64 $(qemu_args) \
      -drive "file=$ISO,if=virtio,media=cdrom,readonly=on" \
      -drive "file=$VM_DIR/seed.img,if=virtio,format=raw,readonly=on" \
      -kernel /dev/null 2>/dev/null || true
    printf 'install finished; serial log at %s\n' "$SERIAL_LOG"
    ;;

  up|run)
    [ -f "$DISK" ] || die "no disk at $DISK -- run 'install' first"
    printf 'booting (%s, expect minutes)...\n' "$ACCEL"
    qemu-system-x86_64 $(qemu_args) >/dev/null 2>&1 &
    QPID=$!
    wait=900
    [ "$1" = up ] && [ -n "${2:-}" ] && wait="$2"
    printf 'waiting up to %ss for SSH on 127.0.0.1:%s...\n' "$wait" "$SSH_PORT"
    i=0
    while [ "$i" -lt "$wait" ]; do
      if ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
             -o ConnectTimeout=3 -p "$SSH_PORT" mosdns@127.0.0.1 true 2>/dev/null; then
        printf 'up.\n'
        if [ "$1" = up ]; then exit 0; fi
        shift
        ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -p "$SSH_PORT" mosdns@127.0.0.1 "$@"
        rc=$?
        printf 'guest exit=%s; powering off\n' "$rc"
        printf 'systemctl poweroff\n' \
          | socat - "UNIX-CONNECT:$MONITOR_SOCK" 2>/dev/null || true
        kill "$QPID" 2>/dev/null || true
        exit "$rc"
      fi
      kill -0 "$QPID" 2>/dev/null || die "qemu exited; see $SERIAL_LOG"
      sleep 5; i=$((i+5))
    done
    die "SSH did not come up within ${wait}s; see $SERIAL_LOG"
    ;;

  down)
    [ -S "$MONITOR_SOCK" ] && printf 'quit\n' | socat - "UNIX-CONNECT:$MONITOR_SOCK" 2>/dev/null || true
    pkill -f "qemu-system-x86_64 -name $VM_NAME" 2>/dev/null || true
    printf 'down.\n'
    ;;

  destroy)
    "$0" down || true
    rm -f "$DISK" "$VM_DIR/overlay.qcow2" "$VM_DIR/seed.img" "$SERIAL_LOG" "$MONITOR_SOCK"
    printf 'destroyed.\n'
    ;;

  *) die "usage: $0 {install|up|run|down|destroy}" ;;
esac
