# The mock DHCP/DNS router: one dnsmasq serving both roles.
#
# Both roles in one daemon is the point. The plan's Task 3 has a target obtain an
# address **by DHCP** and then receive a **new DNS address** when the router is
# reconfigured, and both events have to come from the same container on the same
# network or the target's NetworkManager is not talking to anything the harness
# controls. `isc-dhcp-server` plus a separate forwarder would have a lease and no
# DNS to publish, and the change a DHCP scenario is looking for would not exist.
#
# No EXPOSE and no published port. The bridge network is private to the run, and a
# mock router that reached the host's port 53 would break the host's resolver in
# order to test a resolver. The image therefore needs no port declaration at all,
# which is asserted by a test rather than left to review.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsmasq-base \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/dnsmasq.d /var/lib/mosdns-mock-router

# The DHCP options the router publishes, and the only source of option 6.
#
# Written here rather than in the config beside it, because a control command
# has to rewrite this file and SIGHUP only re-reads it: `dnsmasq(8)` says "SIGHUP
# does NOT re-read the configuration file", and re-reads `/etc/hosts`,
# `/etc/ethers` and the files named by --dhcp-hostsfile, --dhcp-optsfile and
# friends. It exists at boot with the router's own address so a run that never
# reloads still has a definite baseline, and the scenario overwrites it with the
# second address and signals the daemon.
#
# It is written **in the image**, in one source file, rather than committed as a
# second file beside dnsmasq.conf: a committed copy is a second place the
# address 10.89.0.2 appears, and a scenario that rewrote the committed copy
# instead of this one would be writing the source tree -- which is mounted
# read-only in every container and is the one thing on this host a run must not
# change. The path below is the one `dnsmasq.conf` names with `dhcp-optsfile`,
# and a case in `tests/podman/tests/test_dhcp_scenario.py` holds the two
# together.
RUN printf '6,10.89.0.2\n' > /etc/dnsmasq-dhcp-opts \
    && chmod 0644 /etc/dnsmasq-dhcp-opts

# The router's configuration, and the directory its DHCP server writes leases
# into. Both are here rather than supplied at run time, because `CMD` below names
# `/etc/dnsmasq.conf` and dnsmasq exits immediately with "can't open
# /etc/dnsmasq.conf (No such file or directory)" when the file is absent -- a
# container that dies on start and a DHCP exchange that never happens, which
# reads like a network problem and is a missing file.
#
# The COPY path is relative to the build's **context**, which is the repository
# root and not this file's directory. A path that is right in an editor and wrong
# in a build fails on the last step of a build that has already installed a
# package index, and `CopySourceTest` in `tests/podman/tests/test_images.py`
# checks it.
#
# **A reload does not rewrite this file.** `dnsmasq(8)`, NOTES: "SIGHUP does NOT
# re-read the configuration file." The file a control command rewrites is the one
# this config names with `dhcp-optsfile`, which dnsmasq *does* re-read on
# SIGHUP; it is written inside the container and does not exist in the checkout,
# so a reload cannot touch the source tree. The whole reason is written out at
# the top of the config.
COPY tests/podman/mock-router/dnsmasq.conf /etc/dnsmasq.conf

# `dnsmasq --keep-in-foreground`, exec'd, so a signal reaches the daemon itself.
#
# The control action is: rewrite the option file inside the container and send
# SIGHUP, and dnsmasq re-reads that file on SIGHUP. That only works if the
# process the signal names is dnsmasq -- an entrypoint that started it in the
# background and then waited would have the shell as PID 1, the signal would go to
# the shell, and the scenario would wait for a DNS change that cannot arrive.
CMD ["/usr/sbin/dnsmasq", "--keep-in-foreground", "--conf-file=/etc/dnsmasq.conf"]
