# The target: a disposable Ubuntu that runs systemd, and on which NetworkManager
# manages a real ethernet device.
#
# The base image is a build argument and nothing else. `FROM ubuntu:24.04` here
# would float to whatever the registry serves that day, which is the one thing
# `tests/podman/images.lock.json` exists to prevent; the build command reads the
# digest from that file and passes `docker.io/library/ubuntu:24.04@sha256:…`. There
# is deliberately no default, so a build that forgets the argument fails at the
# first instruction instead of pulling a moving tag.
#
# **This project's package is NOT installed here.** A scenario copies the built
# `.deb` in and installs it, so the install transaction -- the claim this whole
# plan exists to close -- is exercised by `install_test.py` rather than by this
# image build. An image that installed the package would make its own packaging
# the thing under test before a single scenario ran. That rule is a test
# (`test_no_containerfile_installs_the_project_package`).
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# What the scenarios need, by name, because they are not interchangeable:
#
#   systemd-sysv       supplies /sbin/init, which --systemd=always makes PID 1
#   dbus               NetworkManager's control channel; nmcli cannot run without it
#   network-manager    the thing whose device state the harness asserts
#   libnss-resolve     the resolver daemon, and the NSS module that makes a
#                      lookup in the target go to 127.0.0.53 rather than past it
#   python3            the scenarios themselves
#   iproute2           `ss`, which the failure scenarios read and Task 4 asserts
#   dnsutils           `dig`, which is how the routing scenarios measure anything
#   curl, ca-certificates  for the scenarios that fetch, and to fetch with
#   procps             `ps`, for the failure scenarios that look at processes
#
# `libnss-resolve` rather than `systemd-resolved`, and that is measured rather
# than preferred: `systemd-resolved` is a binary package on 24.04 and 26.04 and
# **does not exist on 22.04**, where the daemon is part of `systemd` -- so
# naming it fails the 22.04 build with `E: Unable to locate package
# systemd-resolved`. `libnss-resolve` exists on all three and brings the daemon
# with it where it is a separate package (24.04: `Depends: … systemd-resolved
# (= 255.4-…)`) and is the NSS module everywhere. Without it, `getent hosts` in a
# target would read /etc/hosts and then the network and never ask the stub, and a
# scenario that measured names rather than queries would measure the wrong
# resolver.
#
# `--no-install-recommends` because a reproducible image is one whose contents
# are the list above: a recommendation pulled in by a future upload is a
# difference between two runs of "the same" image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd-sysv \
        dbus \
        network-manager \
        libnss-resolve \
        python3 \
        iproute2 \
        dnsutils \
        curl \
        ca-certificates \
        procps \
    && rm -rf /var/lib/apt/lists/*

# `/etc/resolv.conf` is NOT touched here, and that is a measurement rather than
# an omission.
#
# Podman mounts a generated resolv.conf over `/etc/resolv.conf` in every build
# step as well as in every container, so a `RUN ln -sf …/stub-resolv.conf
# /etc/resolv.conf` in this file fails with:
#
#   ln: failed to create symbolic link '/etc/resolv.conf': Device or resource busy
#
# (measured, at the step that carried it, before it was removed.) The base image
# also ships a regular file here and systemd-resolved does not take it over by
# itself -- it writes `/run/systemd/resolve/stub-resolv.conf` and leaves
# /etc/resolv.conf alone -- so a target that keeps the runtime's file answers
# through the bridge gateway and the routing scenarios measure the wrong
# resolver.
#
# So the target's entrypoint replaces it at boot, inside the container's own
# mount namespace. `tests/podman/tests/test_images.py` holds both halves of that.

# `systemd-networkd` is disabled, and NetworkManager is the only manager.
#
# Both daemons claim the same device. With both enabled, which one owns eth0 is a
# race, and the symptom is an intermittent DHCP failure on one release and none at
# all on another -- which is a very expensive thing to debug from a later failure.
RUN systemctl disable systemd-networkd.service \
    || systemctl mask systemd-networkd.service

# The two unprivileged accounts the two-user scenario acts as, and the
# setgid-shared directory it checks the control lock in. The package creates these
# too; the image creates them because the image does not carry the package, and a
# scenario that had to `useradd` first would be testing `useradd` by the time it
# reached the lock.
RUN groupadd --system mosdns \
    && groupadd --system mosdns-cdn \
    && useradd --system --gid mosdns --home-dir /var/lib/mosdns --no-create-home mosdns \
    && useradd --system --gid mosdns-cdn --home-dir /var/lib/mosdns --no-create-home mosdns-cdn \
    && groupadd mosdns-router-mosdns-cdn \
    && usermod --append --groups mosdns-router-mosdns-cdn mosdns \
    && install -d -m 2775 -o mosdns -g mosdns /var/lib/mosdns/runtime

# The NetworkManager sequence, and the boot check that makes a target that could
# not be measured refuse to look like an installer bug.
#
# This is a systemd unit rather than a line in the entrypoint, and the reason is
# measured rather than stylistic: `nmcli` talks to NetworkManager over D-Bus, so
# before `/sbin/init` there is no bus to connect to. An entrypoint that ran the
# three steps itself would fail its first command with `Error: Could not create
# NMClient object: Could not connect: No such file or directory` and leave every
# target unmanaged. So the sequence runs once, at boot, from the image's own init,
# and it is enabled here rather than by a scenario.
#
# The COPY paths are relative to the build's **context**, which is the repository
# root -- not to this file's own directory. A path that is correct in an editor
# and wrong in a build fails at the last step of a build that has already
# installed a systemd and a NetworkManager, so `CopySourceTest` checks them.
COPY tests/podman/images/target-nm-setup.sh /usr/local/bin/mosdns-target-nm-setup
RUN chmod 0755 /usr/local/bin/mosdns-target-nm-setup
COPY tests/podman/images/target-nm-setup.service /etc/systemd/system/target-nm-setup.service
RUN systemctl enable target-nm-setup.service

# The entrypoint is a hand-off and nothing else. `exec` rather than a call, so
# systemd becomes PID 1 rather than a child of a shell -- the shape that makes
# `--systemd=always` a no-op and a target's units something no PID 1 systemd
# manages. It is asserted as well as written:
# `test_the_entrypoint_does_not_perform_the_sequence_itself`.
COPY tests/podman/images/target-entrypoint.sh /usr/local/bin/mosdns-target-entrypoint
RUN chmod 0755 /usr/local/bin/mosdns-target-entrypoint
ENTRYPOINT ["/usr/local/bin/mosdns-target-entrypoint"]

# No `CMD`, and nothing of this project's started here. The package installs its
# own units and enables them itself; an image that pre-enabled one would make
# `systemctl is-enabled` pass on a package that never installed anything.
