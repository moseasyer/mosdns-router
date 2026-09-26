#!/bin/sh
# Entrypoint for the system-level test image.
#
# Its one real job is to make /etc/resolv.conf a symlink to the resolved stub,
# because podman bind-mounts a generated file there on every run and a
# bind-mounted resolv.conf is not the shape a real Ubuntu has. The installer's
# preflight refuses to proceed when /etc/resolv.conf is not the stub, so a test
# machine with a bind mount there would let that first check pass for entirely
# the wrong reason -- and would then let the install "succeed" without ever
# proving it can take the stub over.
#
# Replacing a bind mount needs CAP_SYS_ADMIN, which is why the run command in
# the Dockerfile header carries --cap-add=SYS_ADMIN. Everything else here is
# deliberately small: this is a test machine, and a large entrypoint is a large
# thing that can differ from the machine it is modelling.
set -eu

STUB=/run/systemd/resolve/stub-resolv.conf

# podman's mount is on /etc/resolv.conf itself; a recursive unmount covers the
# case where it arrived as a bind of a directory's file.
umount /etc/resolv.conf 2>/dev/null || umount -l /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf

# A dangling symlink is the correct state here, and is exactly what a real boot
# has for the first few hundred milliseconds: resolved creates the stub file a
# moment after systemd starts, and writes through this link thereafter. What must
# NOT be here is a file naming a resolver outside this container -- that is the
# thing the container exists to prevent -- so if the link cannot be made, an
# empty file is the fallback and it fails closed.
ln -sfn ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf \
  || : > /etc/resolv.conf

if [ "${1:-}" = "/lib/systemd/systemd" ]; then
    exec "$@"
fi
exec /lib/systemd/systemd
