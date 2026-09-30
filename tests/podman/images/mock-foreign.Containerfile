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

# **The Go toolchain is a pinned artifact, not the release's.** The first version
# of this file installed `golang-go` from the release's own archive, and that
# makes the compiler a function of the release. It is Go 1.18 on 22.04, and 1.18
# cannot read this module's `go.mod`:
#
#     go: errors parsing go.mod:
#     /src/go.mod:3: invalid go version '1.25.8': must match format 1.23
#     Error: building at STEP "RUN go mod download": while running runtime: exit status 1
#
# so the 22.04 cell could not start and the run reported `harness error: could
# not build the mock-foreign image for 22.04` -- a matrix built to compare three
# releases, unable to compare two. 24.04 and 26.04 happen to carry a new enough
# compiler, and that is the dangerous half of it: a cell that passed there was
# built by a different toolchain than the cell that failed, for a reason that has
# nothing to do with what the mock is.
#
# So the tarball is the one the Go project publishes for this version, checked
# against a digest written HERE rather than against whatever the download
# returned, and the version is this module's own `go` directive -- a bump of
# `go.mod` that nobody carried into this file fails the build instead of
# compiling against whatever the file happens to say. Both are held by
# `test_the_build_toolchain_is_pinned_and_not_the_distributions` and
# `test_the_pinned_digests_are_the_official_ones` in
# `tests/podman/tests/test_images.py`, and the second asks go.dev's published
# release list rather than trusting a transcription.
#
# The digests are the `case` below and ONLY there, because a digest written in
# the prose as well is a digest that can be updated in one place and not the
# other. They are from `https://go.dev/dl/?mode=json&include=all` on 2026-10-01.
#
# Neither number is a signature, and neither is the dnscrypt-proxy archive's: a
# digest proves the bytes are the bytes that were published, and says nothing
# about who published them. The task report's NOT VERIFIED section says so.
#
# `TARGETARCH` carries a default rather than being relied on, because a build
# that is not told the architecture gets the one this matrix runs -- and an
# architecture with no digest in the `case` REFUSES, rather than falling through
# to a toolchain nobody pinned.
ARG GO_VERSION=1.25.8
ARG TARGETARCH=amd64
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "${TARGETARCH}" in \
         amd64) GO_SHA256=ceb5e041bbc3893846bd1614d76cb4681c91dadee579426cf21a63f2d7e03be6 ;; \
         arm64) GO_SHA256=7d137f59f66bb93f40a6b2b11e713adc2a9d0c8d9ae581718e3fad19e5295dc7 ;; \
         *) echo "no pinned Go ${GO_VERSION} tarball for ${TARGETARCH}: add its digest rather than letting the build fetch whatever is there" >&2; exit 1 ;; \
       esac \
    && curl -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm -f /tmp/go.tar.gz

# `git` is deliberately absent. The module's dependencies are fetched by
# `go mod download` over the proxy, not by a VCS client, and an image build that
# carried a VCS would carry a credential helper and a config file this project has
# no reason to have in it.
ENV PATH=/usr/local/go/bin:$PATH

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
# **`--listen` and `--address` are different addresses, and the difference is the
# whole of what this image is for.** `--listen` is the wildcard, because the
# container is reached on whatever address the private network gave it.
# `--address` is the address the DNSCrypt stamp carries, and a stamp names the
# address a client DIALS -- so with only `--listen`, the first version of this
# image published a stamp naming `0.0.0.0:443`, which a client resolves to itself.
# MEASURED, on all three releases: `dnscrypt-proxy` in the target dialled the
# target's own port 443, got nothing, and the install transaction refused at its
# own barrier with
#
#     dnscrypt-proxy.service was started but nothing answered a DNS query at
#     127.0.0.1:15353 within 60s
#
# a sentence about a resolver that says nothing about an address nobody could
# dial. The address below is `routing_test.MOCK_FOREIGN_ADDRESS` and the two
# spellings are held to each other by
# `test_the_image_publishes_the_address_this_scenario_dials` in
# `tests/podman/tests/test_install_routing_scenario.py`; the program refuses an
# unspecified address outright, so a cell that loses the flag fails loudly instead
# of waiting out the transaction's whole budget.
#
# The port is 443 because that is what every DNSCrypt stamp in the wild carries
# and what makes the override a change of *address* rather than of port as well.
# The counters document is written to /run so the harness can read it with
# `podman exec cat` rather than parsing the log.
CMD ["/usr/local/bin/mock-foreign", \
     "--listen=0.0.0.0:443", \
     "--address=10.89.0.40:443", \
     "--counters=/run/mosdns-mock-foreign/counters.json", \
     "--answer=198.51.100.7"]
