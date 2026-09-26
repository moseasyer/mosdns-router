# System-level test image for the native-system-packaging and Podman plans.
#
# The point of this image is to be a machine that is NOT the developer's. It
# carries real systemd, real NetworkManager, real systemd-resolved, real POSIX
# ACLs, and real iproute2 output, because the installer's preflight is written
# against exactly those tools' real output formats. A test that runs on the
# developer's host proves nothing about any of them.
#
# Build one per target release:
#   podman build -t mosdns-test:24.04 --build-arg BASE=ubuntu:24.04 -f tests/system/Dockerfile .
#
# Run it with systemd as PID 1:
#   podman run --rm --systemd=always --cgroupns=private --name mosdns-test \
#     -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
#     -v "$PWD/tests/system/entrypoint.sh:/entrypoint.sh:ro" \
#     mosdns-test:24.04 /entrypoint.sh sleep infinity
#
# Nothing in here may reach the host's network stack, its resolver, or its
# /etc. The container gets its own netns and its own resolved.

ARG BASE=ubuntu:24.04
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive

# systemd is the point; the rest are the tools whose real output the preflight
# parses. iproute2 gives `ss`, acl gives getfacl/setfacl, policykit is what
# NetworkManager's polkit agent needs to exist at all in a container.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd \
      systemd-sysv \
      systemd-resolved \
      network-manager \
      dbus \
      iproute2 \
      acl \
      policykit-1 \
      python3 \
      python3-minimal \
      ca-certificates \
      curl \
      procps \
      util-linux \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# systemd inside a container must not try to run the things that only make
# sense on a real boot, and a hung boot is the single most common way a
# container image like this fails.
RUN mkdir -p /etc/systemd/system \
 && ln -sf /dev/null /etc/systemd/system/dev-ttyS0.device \
 && rm -f /lib/systemd/system/multi-user.target.wants/* \
 && ln -sf /lib/systemd/system/getty.target /etc/systemd/system/getty.target

# The system users the packages create are deliberately NOT created here: a
# pre-created `mosdns` or `dnscrypt-proxy` user would let a test pass that
# should have proved postinst makes it. The users systemd's own units need,
# however, must exist or those units cannot start.
RUN systemd-sysusers \
 && systemd-tmpfiles --create --boot --prefix=/run --prefix=/run/lock

# A resolver that is this project's own, never the host's. The stub listener is
# what the installer's preflight requires, and the install then REPLACES the
# stub with the router -- so a test machine whose resolver is not the stub would
# let the installer's first check pass for the wrong reason.
#
# /etc/resolv.conf cannot be symlinked here: podman bind-mounts it into every
# container, including build containers, so it is a mount point and `ln -sf`
# fails with EBUSY. The entrypoint unmounts and replaces it at run time, which
# is why the run command needs --cap-add=SYS_ADMIN.
RUN mkdir -p /etc/systemd/resolved \
 && printf '[Resolve]\nDNSStubListener=yes\n' > /etc/systemd/resolved/resolved.conf

COPY tests/system/entrypoint.sh /usr/local/lib/mosdns-test-entrypoint
RUN chmod 0755 /usr/local/lib/mosdns-test-entrypoint

# The installer's preflight reads /etc/os-release and dpkg --print-architecture.
# Both must be real in the image, and the release line must match the base, or a
# test would pass here and fail on the machine it is meant to model.
RUN set -eu; \
    . /etc/os-release; \
    echo "model=$PRETTY_NAME arch=$(dpkg --print-architecture)" \
      | tee /etc/mosdns-test-model

STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/lib/mosdns-test-entrypoint"]
CMD ["/lib/systemd/systemd"]
