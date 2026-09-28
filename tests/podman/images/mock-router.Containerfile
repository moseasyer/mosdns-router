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
    && mkdir -p /etc/dnsmasq.d

# `dnsmasq --keep-in-foreground`, exec'd, so a signal reaches the daemon itself.
#
# The control action is: rewrite the config inside the container and send SIGHUP,
# and dnsmasq re-reads its configuration on SIGHUP. That only works if the
# process the signal names is dnsmasq -- an entrypoint that started it in the
# background and then waited would have the shell as PID 1, the signal would go to
# the shell, and the scenario would wait for a DNS change that cannot arrive.
CMD ["/usr/sbin/dnsmasq", "--keep-in-foreground", "--conf-file=/etc/dnsmasq.conf"]
