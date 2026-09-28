# The mock CDN: a TLS server serving certificate-authenticated test names, built
# from THIS repository's Go module.
#
# Two stages, because the first one is a Go toolchain and the second one is not.
# A single-stage image carries roughly 800 MB of compiler to serve a few hundred
# kilobytes of static binary, and every layer of it is in the image a run leaves
# behind.
#
# The build context is the repository, read-only into the build; nothing here
# writes to it. `-mod=readonly` is the reason: a `go build` that updated `go.mod`
# or `go.sum` inside the build would be a silent edit to the checkout, made by a
# command whose job is to change nothing, and it is asserted rather than assumed.
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

# Now the sources. `tests/podman/mock-cdn` is Task 5's; the build names the
# package path so the image is built from this checkout rather than from whatever
# a published module happens to contain.
COPY . .
RUN go build -mod=readonly -trimpath -o /out/mock-cdn ./tests/podman/mock-cdn

# The serving stage. Caddy is here because the plan's Task 5 step 1 needs
# certificate-authenticated HTTPS with Cloudflare-style and CloudFront-style
# response headers, and doing that in a hand-written listener is a second TLS
# stack to get wrong before a single ECH assertion is reached.
FROM ${BASE_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends caddy ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/mock-cdn /usr/local/bin/mock-cdn

# No EXPOSE: the CDN is reached from the target and the client container over the
# run's private bridge network, and a published port would be a way for the host
# to reach a test server that answers with test certificates.
CMD ["/usr/local/bin/mock-cdn"]
