# The mock foreign resolver: a DNSCrypt server built from THIS repository's Go
# module, reached by the packaged resolver's own unit.
#
# Two stages, for the reason `mock-cdn.Containerfile` gives: a single-stage image
# carries a Go toolchain to serve one small binary, and every layer of it is in
# the image a run leaves behind.
#
# **The serving stage installs nothing, and it must not.** The whole point of this
# image is that `dnscrypt-proxy` 2.1.18 -- the binary this project builds from a
# digest-pinned source archive and installs as `/usr/lib/mosdns-router/
# dnscrypt-proxy` -- can complete a certificate exchange with it and then answer
# a query. Anything installed in this image is installed in the same release the
# resolver came from, which is the one thing this cell is not measuring; a
# resolver that could only talk to a mock because both were built against
# something extra would prove nothing about the packaged pair.
#
# `mock-cdn.Containerfile` is the other half of the argument and it made the same
# point about `caddy`: a mock that is not this project's code answers differently
# from one that is. Here the code is this module's own, and it is a DNSCrypt
# resolver because that is the only protocol `dnscrypt-proxy` 2.1.18 accepts --
# `fetchServerInfo` handles DNSCrypt, DoH and ODoH and returns "Unsupported
# protocol" for anything else, and a `[static.*]` entry in its config carries a
# `Stamp` and no address at all.
#
# The source is copied whole, and the package path is named so the image is built
# from this checkout rather than from whatever a published module happens to
# contain.
ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends golang-go ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The module and its dependencies, before the sources, so a change to this
# repository's own code does not invalidate the dependency layer of every image
# build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -mod=readonly -trimpath -o /out/mock-foreign ./tests/podman/mock-foreign

FROM ${BASE_IMAGE}
COPY --from=build /out/mock-foreign /usr/local/bin/mock-foreign

# No EXPOSE, and no published port. The resolver is reached from the target over
# the run's private bridge network; publishing it would be a way for the host to
# reach a resolver whose answers are test addresses, and the harness refuses a
# published port on every container it starts.
#
# The address is the one the plan's own table names, and the port is 443 because
# that is what every DNSCrypt stamp in the wild carries and what makes the
# override a change of *address* rather than of port as well. The counters
# document is written to /run so the harness can read it with `podman exec cat`
# rather than parsing the log.
CMD ["/usr/local/bin/mock-foreign", \
     "--listen=0.0.0.0:443", \
     "--counters=/run/mosdns-mock-foreign/counters.json", \
     "--answer=198.51.100.7"]
