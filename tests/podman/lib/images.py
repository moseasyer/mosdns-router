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


__all__ = [
    "ARCH",
    "LOCK_RELATIVE_PATH",
    "LockError",
    "REPOSITORY",
    "SCHEMA",
    "base_image_reference",
    "check_version",
    "default_lock_path",
    "every_reference",
    "load_lock",
    "reference_for_version",
]
