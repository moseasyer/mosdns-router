#!/bin/sh
# The target's entrypoint: point the resolver at the resolved stub, then hand
# over to systemd. Nothing else.
#
# ## Why there is anything here at all
#
# `/etc/resolv.conf` has to be `/run/systemd/resolve/stub-resolv.conf` for the
# routing scenarios to measure resolved rather than the container runtime. It
# cannot be done in the Containerfile: podman mounts a generated resolv.conf over
# that path in every build step, and `ln -sf` there fails with `Device or
# resource busy` (measured, at the step that tried it). At run time the same
# mount is in place, and both `rm` and `ln` fail against it.
#
# So this script unmounts it **inside the container's own mount namespace** and
# puts the stub there. The host is not involved at all: the mount is created by
# the runtime inside this container, and the harness refuses to bind any host
# path under `/etc`, `/run`, `/var` or `/sys` in the first place. Verified after a
# real run on the development host: its `/etc/resolv.conf` was untouched, same
# symlink and same mtime.
#
# ## Why it fails rather than continuing
#
# A target that could not be given the stub keeps the runtime's resolver, which
# is `nameserver 10.89.0.1` -- the bridge gateway. Every DNS assertion in a
# scenario would then measure the gateway rather than the mock router or
# resolved, the package would not be the thing under test, and the failure would
# read like a bug in a package that has not been installed yet. So a target that
# cannot be prepared is a target that does not boot, and it says why.
#
# The unmount needs `CAP_SYS_ADMIN`, which the measured flag set already grants
# (`--cap-add=SYS_ADMIN`). It is the same reason `--cgroupns=host` and
# `--privileged` are not used instead.

set -eu

RESOLV_CONF=/etc/resolv.conf
STUB=/run/systemd/resolve/stub-resolv.conf

# Unmount the runtime's bind if it is one. `umount` on a plain file fails, which
# is the right answer: it means there is nothing mounted over it and the file
# below is the image's own.
umount "$RESOLV_CONF" 2>/dev/null || true

if ! rm -f "$RESOLV_CONF" || ! ln -s "$STUB" "$RESOLV_CONF"; then
    echo "target: refusing to boot -- $RESOLV_CONF could not be pointed at $STUB." >&2
    echo "target: a target that cannot be given the resolved stub keeps the container" >&2
    echo "target: runtime's resolver (the bridge gateway), and every DNS scenario would" >&2
    echo "target: measure that instead of the router or of resolved. The usual cause is" >&2
    echo "target: the container lacking CAP_SYS_ADMIN, which is what unmounting a bind needs." >&2
    exit 1
fi

# The NetworkManager sequence is NOT here, and that is measured rather than
# stylistic. `nmcli` reaches NetworkManager over D-Bus, and before `/sbin/init`
# there is no bus to connect to, so a sequence run here fails its first command
# with:
#
#   Error: Could not create NMClient object: Could not connect: No such file or directory.
#
# (measured, with an entrypoint that tried) and leaves every target unmanaged --
# every scenario then fails for a reason that has nothing to do with the package,
# and the whole matrix is `incomplete` with exit 3. The sequence is a systemd
# unit this image installs and enables (`target-nm-setup.service`), so it runs
# once, at boot, from the image's own init. A test asserts this file names
# neither `nmcli` nor `systemctl`.
#
# `exec`, not a call: systemd has to be PID 1, or `--systemd=always` is a no-op
# and a target's units are managed by a systemd that is merely a child of a
# shell.
exec /sbin/init "$@"
