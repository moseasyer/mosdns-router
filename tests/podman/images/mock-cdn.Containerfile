# The mock CDN: a TLS server serving certificate-authenticated test names, built
# from THIS repository's Go module.
#
# Two stages, because the first one is a Go toolchain and the second one is not.
# A single-stage image carries roughly 800 MB of compiler to serve a few hundred
# kilobytes of static binary, and every layer of it is in the image a run leaves
# behind.
#
# **The serving stage installs nothing at all, and that is deliberate.** The plan's
# Task 5 step 1 needs certificate-authenticated HTTPS on `cloudflare.test` and
# `distribution.test`, with Cloudflare-style and CloudFront-style response
# headers, an expected body marker, a small file and a throttled large one. The
# plan also says the mock CDN is "built from the repository's Go module", and
# `crypto/tls` in that module does all of it.
#
# The first version of this file installed `caddy` in the serving stage to avoid
# writing the TLS server. That was the wrong trade in two ways, and the second one
# only showed up when the build was measured:
#
#   * `caddy` **does not exist on Ubuntu 22.04** -- not in `main`, not in
#     `universe`, not in the archive at all. Measured against the locked 22.04
#     digest: `apt-cache policy caddy` and `apt-cache search ^caddy` are both
#     empty. So the image could not be built on a third of the matrix, and
#     nothing in the suite could see it, because the availability check named two
#     of the three Containerfiles. Both are fixed: the file is discovered by glob
#     now, and `caddy` is gone.
#   * A CDN server that is not this project's code answers differently from one
#     that is, and the plan's Task 5 step 3 makes assertions about *this* module's
#     ECH and CDN behaviour. Caddy would have been the thing under test.
#
# The certificates are not baked in: Task 5 generates its own test material and
# `podman cp`s it, because a private key in a committed image layer is a private
# key in the repository's history.
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

# The serving stage: the base image and the binary. No package, so there is no
# package that a release might not have -- which is the property the availability
# check enforces across every image in this directory, and the reason it is worth
# stating here rather than leaving to the reader.
FROM ${BASE_IMAGE}
COPY --from=build /out/mock-cdn /usr/local/bin/mock-cdn

# No EXPOSE: the CDN is reached from the target and the client container over the
# run's private bridge network, and a published port would be a way for the host
# to reach a test server that answers with test certificates.
CMD ["/usr/local/bin/mock-cdn"]
