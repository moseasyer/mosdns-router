"""What the matrix builds from: the locked Ubuntu digests, and how a build is given one.

`images.lock.json` is a small file with one job, and the job is that **two runs
of the matrix are the same three images**. A tag does not do that -- `ubuntu:24.04`
is whatever the registry serves that day, and an Ubuntu point release lands under
it without the tag changing -- so every base image is pinned by digest and the
reference a build gets is `repo:tag@digest`: the tag for the human, the digest for
the machine.

**A digest is only useful if it was real.** A lock entry that was typed out of a
habit matches `sha256:`, is 64 characters of hex, and produces a reference that
fails at `podman build` with a message about a repository rather than about the
lock. So this module is where the shape is enforced, and the enforcement is a
*refusal* rather than a convention: `base_image_reference` raises rather than
returning a reference it cannot vouch for, because a caller that got a plausible
string back would go on to build against it.

Three refusals, and each is a different way a lock can be wrong:

* **no `sha256:` prefix** (or a digest that is not 64 lowercase hex characters
  after it). The prefix is what makes a digest a *reference*; a bare hex string
  pasted into `repo@…` is not one.
* **no entry for the version.** Falling back to the tag would be the worst of
  the three answers available: the build would succeed against a floating image
  and the lock would be doing nothing.
* **an entry recorded `unavailable`.** A version whose image cannot be pulled is
  a finding that names the reason, and a build cannot use an absence -- so the
  refusal carries the reason, so the reader learns *that* and *why* from the
  refusal rather than from a digest somebody typed.

Nothing in this module talks to a registry, a container runtime or the host. It
reads a file, checks its shape, and composes a string. Which registry a digest
came from is recorded **in the lock**, per entry, in `resolved_by` -- so a reader
who doubts one can re-run that one command and get the same answer. A digest with
no provenance is a claim; this is what makes the file reviewable.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "mosdns-podman-images/1"

# The official Ubuntu images, which is where the digests are pulled from. A digest
# is a hash of one manifest in one repository, so naming a different repository's
# tag with one is a reference that resolves to something else or to nothing.
REPOSITORY = "docker.io/library/ubuntu"

# The architecture these digests were resolved on. A digest is per-architecture,
# and a lock that did not say which one it pinned would be read as pinning all of
# them -- an arm64 run would then pull a manifest nobody verified.
ARCH = "amd64"

# A release is a year and a zero-padded month, which is what Ubuntu has used since
# 2006. `24.4` is the same month written badly, and a lock that accepted it would
# let a typo through to a pull that fails with a message about a repository.
_VERSION = re.compile(r"\d+\.(0[1-9]|1[0-2])")

# The digest's shape, whole. A prefix check alone would accept `sha256:whatever`
# and produce a reference as unusable as one with no prefix at all.
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

# The key a lock file lives at, and the file it lives in. Named so `run.py` and a
# build command cannot each spell it differently.
LOCK_RELATIVE_PATH = "tests/podman/images.lock.json"


class LockError(Exception):
    """A lock entry cannot be used to build.

    Raised rather than returned, because every failure here is one a build cannot
    proceed past, and a caller handed a plausible reference would go on to build
    against an image this plan never verified.
    """


def default_lock_path(repo_root: str | Path | None = None) -> Path:
    """The lock file, resolved against the repository by default.

    The harness's file map names one path for it, and a build command that spelled
    the path itself would be free to spell it differently from `run.py`.
    """
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[3]
    return root / LOCK_RELATIVE_PATH


def load_lock(path: str | Path | None = None) -> dict[str, Any]:
    """Read and parse a lock file, refusing one that is not the documented shape.

    A lock file that is missing is a different answer from one whose entry is
    unusable, and both are refusals: the first says the file is not there, the
    second says what is wrong with what is in it. Neither falls back to a tag.
    """
    location = Path(path) if path else default_lock_path()
    if not location.is_file():
        raise LockError(
            f"no image lock at {location}. It is a committed file, not something this harness "
            f"generates: a lock written at run time would record whatever the registry served "
            f"that day, which is the thing the lock exists to prevent"
        )
    try:
        document = json.loads(location.read_text(encoding="utf-8"))
    except json.JSONDecodeError as broken:
        raise LockError(f"{location} is not valid JSON: {broken}") from broken
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise LockError(
            f"{location} is not a {SCHEMA} document. A lock compared against an older one has "
            f"to be able to say it is not the same shape rather than reporting every field as "
            f"changed"
        )
    if not isinstance(document.get("images"), dict) or not document["images"]:
        raise LockError(f"{location} has no images, so it pins nothing")
    if document.get("arch") != ARCH:
        raise LockError(
            f"{location} pins {document.get('arch')!r} and this harness runs {ARCH}. A digest is "
            f"per-architecture, so a lock that does not say which one it pinned would be read as "
            f"pinning all of them"
        )
    return document


def check_version(version: str) -> str:
    """The version, or a refusal naming it.

    Checked where the key is read rather than at pull time, so `--versions 24.4`
    fails with the version in the message instead of with a manifest error.
    """
    text = str(version).strip()
    if not _VERSION.fullmatch(text):
        raise LockError(
            f"refusing version {text!r}: a release is a year and a zero-padded month ('24.04', "
            f"'26.10'). A cell for a version nobody ships produces a report row with a "
            f"requirement string naming a release that does not exist, and a lock entry for one "
            f"produces a pull that fails with a message about a repository"
        )
    return text


def base_image_reference(entry: Mapping[str, Any], version: str) -> str:
    """The reference a build is given: `docker.io/library/ubuntu:<version>@<digest>`.

    Tag *and* digest, in that order and in one string: the tag names the release
    for a human reading a log, and the digest names the bytes for the machine
    pulling them. A tag alone floats to whatever the registry serves that day; a
    digest alone loses which release the matrix meant to test.

    Raises on every way the entry can be unusable, with the version in the
    message, because a caller that received a plausible reference would build
    against an image nothing verified.
    """
    release = check_version(version)
    if not isinstance(entry, Mapping):
        raise LockError(f"the lock entry for {release} is not a record: {entry!r}")
    if entry.get("unavailable"):
        reason = str(entry.get("reason") or entry["unavailable"])
        raise LockError(
            f"{release} is recorded unavailable and no image can be built from it: {reason}. "
            f"This is a recorded finding, not a gap -- the lock carries the reason so a reader "
            f"learns that and why from the refusal, and nothing here writes a digest in its place"
        )
    digest = entry.get("digest")
    if not digest:
        raise LockError(
            f"the lock entry for {release} has no digest, so the build would fall back to a "
            f"floating tag -- which is the one answer worse than none, because the build would "
            f"succeed against an image the lock never pinned"
        )
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise LockError(
            f"the lock entry for {release} holds {digest!r}, which is not a digest reference. "
            f"A base image is pinned as '{REPOSITORY}:{release}@sha256:<64 hex characters>', and "
            f"both the 'sha256:' prefix and the 64 characters are part of what makes the string "
            f"resolvable -- a bare digest or a truncated one fails at build time with a message "
            f"about the repository rather than about the lock"
        )
    return f"{REPOSITORY}:{release}@{digest}"


def reference_for_version(version: str, path: str | Path | None = None) -> str:
    """The reference for one version, read from the lock.

    The whole of what a build command needs, in one call, so a caller cannot
    assemble a reference from a lock entry and skip the checks in between.
    """
    lock = load_lock(path)
    images = lock["images"]
    release = check_version(version)
    if release not in images:
        raise LockError(
            f"the lock has no entry for {release}. It covers "
            f"{', '.join(sorted(images))}. A version the lock does not cover cannot be built, "
            f"and a bare tag would be a floating image -- which is the thing the lock exists "
            f"to prevent"
        )
    return base_image_reference(images[release], release)


def every_reference(path: str | Path | None = None) -> dict[str, str]:
    """Every version's reference, as `{version: reference}`.

    A build that iterates the lock rather than a hard-coded list picks up a
    release the matrix added without anybody editing a second list, and a version
    recorded `unavailable` raises here rather than being skipped silently -- a
    matrix run with one version quietly missing is an incomplete run reported as
    a complete one.
    """
    images = load_lock(path)["images"]
    return {
        version: base_image_reference(entry, version)
        for version, entry in sorted(images.items())
    }


# -- the images this harness builds, and the tags that name them ----------------

# Where the Containerfiles live, relative to the repository root. Discovered by
# role rather than by glob so a role with no Containerfile is a refusal with a
# name in it -- a glob would return an empty list and a build would be skipped
# with nothing said, which is how a scenario ends up running against an image
# nothing accounts for.
CONTAINERFILE_DIRECTORY = "tests/podman/images"
CONTAINERFILE_SUFFIX = ".Containerfile"

# The roles a cell builds, in the order it needs them: the router owns the
# address the target will be given, so it is started first.
#
# `mock-foreign` is third, and its position is not alphabetical: it is the mock
# foreign *listener*, reached by the packaged resolver's own unit, so it is only
# started by the scenarios that measure the branch split (`run.MOCK_SCENARIOS`)
# and a cell running `dhcp` alone never pays for its build. It is in this tuple
# rather than discovered from the directory because the tuple is the set a cell
# BUILDS for every version, and a build that skipped it would leave the routing
# scenario with no image to start a container from.
IMAGE_ROLES = ("mock-router", "target", "mock-foreign")

# How much of the content hash goes in the tag. Twelve hex characters is 48 bits:
# enough that two different Containerfiles do not collide by accident, and short
# enough that the tag is still readable when a container fails to start and the
# operator has to type it.
TAG_HASH_LENGTH = 12

_ROLE = re.compile(r"[a-z][a-z0-9-]*")


def containerfile(role: str, repo_root: str | Path | None = None) -> Path:
    """The Containerfile for `role`, or a refusal naming the role.

    **The role is a shape, not a path.** `containerfile("../../etc/passwd")`
    would return a file outside the repository if the name were merely joined to
    a directory, and a build would then be handed a Containerfile the repository
    does not contain. The pattern below admits a lowercase word with hyphens and
    nothing else, and the file still has to exist -- so both a traversal and a
    role nobody has written an image for are refusals rather than a build against
    whatever was there.
    """
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[3]
    if not _ROLE.fullmatch(str(role or "")):
        raise LockError(
            f"refusing image role {role!r}: a role is a lowercase name with hyphens, and it is "
            f"joined to {CONTAINERFILE_DIRECTORY} -- anything else would be a path rather than a "
            f"role, and a build would be handed a file this repository does not contain"
        )
    path = root / CONTAINERFILE_DIRECTORY / f"{role}{CONTAINERFILE_SUFFIX}"
    if not path.is_file():
        raise LockError(
            f"there is no {CONTAINERFILE_DIRECTORY}/{role}{CONTAINERFILE_SUFFIX}, so the matrix "
            f"cannot build the {role} image. The roles with a Containerfile are "
            f"{', '.join(sorted(known_roles())) or 'none'}"
        )
    return path


def known_roles(repo_root: str | Path | None = None) -> list[str]:
    """Every role with a Containerfile, for the refusals that have to name them."""
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[3]
    directory = root / CONTAINERFILE_DIRECTORY
    if not directory.is_dir():
        return []
    return sorted(
        path.name[: -len(CONTAINERFILE_SUFFIX)]
        for path in directory.glob(f"*{CONTAINERFILE_SUFFIX}")
    )


def image_tag(role: str, version: str, base_reference: str) -> str:
    """The tag a built image is named, derived from everything that goes into it.

    A tag is this harness's **cache key**, and podman has no other way to know
    whether a tag it is asked to reuse is the image this run would have built. So
    the tag carries a hash of the two inputs that decide the bytes: the
    Containerfile's contents and the base reference. Edit the Containerfile and
    the tag changes and the image is rebuilt; change nothing and the tag is
    identical and the build is skipped.

    **Without the Containerfile in the key, a stale image is what the matrix
    runs.** That is not a theoretical risk in this project: the DHCP task
    changed `mock-router.Containerfile` to have dnsmasq read a configuration file
    that is copied in at build time, and an image tagged by version alone would
    have been reused with no configuration in it -- a container whose daemon
    exits at start, reported as a network failure.

    **The files a Containerfile COPIES are in the key too**, and the third live
    instance of the same defect is the reason. `mock-router.Containerfile` copies
    `tests/podman/mock-router/dnsmasq.conf` in with a `COPY`, and that config is
    the whole of the router's configuration -- an edit to it changes the image's
    bytes and changes nothing about the tag. So a run after an edit to the config
    reused the image built before it. Task 8 hit this: the mock router was given
    `address=/install-probe.example/…` so that a restored machine could actually
    resolve, the file changed, the tag did not, and the live run kept reporting a
    rollback that could not resolve -- which reads as a defect in the watchdog
    and is a stale image.

    So the key is every input the build reads: the Containerfile, the base
    reference, and the contents of every file the Containerfile copies. The
    copies are found by parsing the `COPY` lines rather than by globbing the
    directory, so a file the Containerfile does not copy cannot change the tag --
    a tag that moved for an unused file would rebuild the image for nothing,
    which is the same mistake in the other direction.

    The version is validated rather than interpolated, so a typo in it is a
    refusal instead of a second image for a release nobody ships.
    """
    release = check_version(version)
    reference = str(base_reference or "").strip()
    if not reference:
        raise LockError(
            f"refusing to name the {role} image: no base reference. The base image comes from "
            f"{LOCK_RELATIVE_PATH} and has to be a 'repo:tag@sha256:…' reference, or the build "
            f"would be against a floating tag"
        )
    containerfile_path = containerfile(role)
    digest = hashlib.sha256()
    digest.update(containerfile_path.read_bytes())
    for copied in copied_sources(containerfile_path):
        digest.update(b"\0")
        digest.update(copied.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(copied.read_bytes())
    digest.update(b"\0")
    digest.update(reference.encode("utf-8"))
    return f"{RESOURCE_TAG_PREFIX}-{role}:{release}-{digest.hexdigest()[:TAG_HASH_LENGTH]}"


# A `COPY` line, as the two shapes the three Containerfiles use: `COPY <src> <dst>`
# and `COPY ["<src>", "<dst>"]`. The source list is the part before the last
# token, so a multi-source `COPY` contributes every file it names.
_COPY = re.compile(r"^\s*COPY\s+(.+)$", re.IGNORECASE)


def copied_sources(containerfile_path: Path, repo_root: Path | None = None) -> list[Path]:
    """Every file the Containerfile copies in, in the order it names them.

    Read out of the `COPY` lines rather than by globbing the Containerfile's own
    directory, and that is the whole of the design: a tag must move when the
    image's bytes would move and not otherwise. The `COPY` source is relative to
    the **build context**, which is the repository root and not this file's
    directory -- so a path resolved against the wrong root is a build that fails
    or an image built from something else.

    A `COPY` whose source is not a file on disk is **skipped rather than
    refused**, and the reason is which failure each answer produces. A Containerfile
    that copies a file a later task has not written yet would otherwise make
    every image untaggable in this tree, and the build would report the real
    problem. What this costs is stated rather than hidden: a `COPY` from outside
    the repository -- a URL, or a path above the context -- is not in the tag, so
    an image built from one is reused after whatever that source becomes. None of
    the three Containerfiles does that, and a case below holds it.
    """
    root = Path(repo_root) if repo_root else containerfile_path.resolve().parents[3]
    found: list[Path] = []
    for line in containerfile_path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = _COPY.match(line)
        if match is None:
            continue
        remainder = match.group(1).strip()
        if remainder.startswith("["):
            remainder = remainder.strip("[]")
        tokens = [
            token.strip().strip("\"'")
            for token in remainder.split()
            if token.strip().strip("\"'")
        ]
        for source in tokens[:-1]:  # the last token is the destination
            if source.startswith("--"):
                continue
            candidate = root / source
            if candidate.is_file():
                found.append(candidate)
    return found


# Images are names, not resources in the run's namespace, so this prefix is the
# harness's own rather than a run's: it is what makes `podman images` on an
# operator's machine legible, and it is why an image this harness built is
# recognisable as one. `cleanup` does not remove images -- they are podman's
# store, they are content-addressed by what went into them, and removing them
# would make the next run pay for a build it does not need.
RESOURCE_TAG_PREFIX = "mosdns"


__all__ = [
    "ARCH",
    "CONTAINERFILE_DIRECTORY",
    "IMAGE_ROLES",
    "LOCK_RELATIVE_PATH",
    "LockError",
    "REPOSITORY",
    "SCHEMA",
    "TAG_HASH_LENGTH",
    "base_image_reference",
    "check_version",
    "containerfile",
    "default_lock_path",
    "every_reference",
    "image_tag",
    "known_roles",
    "load_lock",
    "reference_for_version",
]
