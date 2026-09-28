"""The three images, the digest lock, and the NetworkManager sequence that has to be in this order.

Two things in this file are about a **file's contents** and one is about
**behaviour**, and keeping them apart is the point.

**The lock and the Containerfiles are configuration, and a test reads them the
way a build does.** There is no way to run a Containerfile in this suite without
building an image on the operator's machine, which the boundary forbids; a
Containerfile *is* a set of lines, and "this line installs systemd-resolved" is
the whole claim. So those cases parse the file and assert on what it says. What
they do not do is assert that a line is merely *present* -- each one names the
consequence of its absence, and several assert both directions, because a test
that can only fail on a line that was added is a change detector rather than a
test.

**The entrypoint's order is behaviour, and it is tested by running it.** The
previous plan's entire NetworkManager SKIPPED list came from concluding that a
container cannot make NetworkManager manage a device. This harness does not
conclude; it *runs the sequence and checks the field*. That is possible here
because the harness can run the three commands, then ask, and a case can reorder
them and require the check to fail -- which is what
`EntryPointOrderTest` does, with a real `sh`, a real `nmcli` model and a real
exit status. The plan's review focus is explicit that the sequence is "asserted,
not assumed", and this file is where that assertion lives.

**The measured facts, which are what make the check worth having:**

* the profile must exist first. With no profile for `eth0`, `nmcli device set
  eth0 managed yes` **returns success**, the audit log records
  `op="device-managed" … result="success"`, and `GENERAL.NM-MANAGED` stays `no`
  after the restart -- re-measured in this session on Ubuntu 24.04, see the
  report;
* the restart is required. The override is written under
  `/run/NetworkManager/devices/` and only the restart re-reads it;
* the device must be a bridge network's `eth0` of type `ethernet`. Podman's
  default rootless network hands a container a `tun/tap` device and
  NetworkManager refuses that type by design.

So the check requires **both** the profile and the field, and reports both. A
check that asserted only the field would pass on an entrypoint that reordered
the steps if a later scenario created the profile -- which is exactly the defect
that was amended into this task, and which had the previous plan's Task 2 and
Task 3 disagreeing about who creates it.
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tests" / "podman" / "lib"))

import images  # noqa: E402
import podman  # noqa: E402

IMAGES = REPO / "tests" / "podman" / "images"
TARGET_CONTAINERFILE = IMAGES / "target.Containerfile"
MOCK_ROUTER_CONTAINERFILE = IMAGES / "mock-router.Containerfile"
MOCK_CDN_CONTAINERFILE = IMAGES / "mock-cdn.Containerfile"
ENTRYPOINT = IMAGES / "target-entrypoint.sh"
NM_SETUP = IMAGES / "target-nm-setup.sh"
NM_UNIT = IMAGES / "target-nm-setup.service"
NM_DECLARATION = IMAGES / "10-mosdns-target.conf"
LOCK = REPO / "tests" / "podman" / "images.lock.json"

# The field the whole plan turns on, named once so a case can assert the script
# reports *this* field rather than some other one.
GENERAL_MANAGED_FIELD = "GENERAL.NM-MANAGED"

# The packages the plan's Task 2 Step 3 names for the target image. Written out
# rather than derived from the Containerfile, so a line that stops installing one
# of them is a change this file can see -- the scenarios below need them by name.
TARGET_PACKAGES = (
    "systemd-sysv",
    "dbus",
    "network-manager",
    "libnss-resolve",
    "python3",
    "iproute2",
    "dnsutils",
    "curl",
    "ca-certificates",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def run_lines(text: str) -> list[str]:
    """The lines of a Containerfile that actually run something.

    A comment is not an instruction, and these three Containerfiles talk about
    the very things several cases forbid -- `dnsmasq-base`, `EXPOSE`, `go build`
    -- in their prose. Reading raw text would have every case that checks what a
    file *does* fail on a file that explains what it does not, which is how a
    guard gets deleted.
    """
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def containerfile_stages(text: str) -> list[tuple[str, list[str]]]:
    """A Containerfile's instructions grouped by stage, in file order.

    A list of `(name, instructions)` pairs rather than a dict, because the last
    stage is the one a container runs and the named ones are the ones a
    `COPY --from` reads, and both are wanted -- a dict that also carried a
    `final` alias would make a case about the stage *count* count the alias.
    """
    stages: list[tuple[str, list[str]]] = []
    for line in folded_lines(text):
        if line.startswith("FROM "):
            parts = line.split()
            name = parts[3] if len(parts) > 3 and parts[2] == "AS" else f"stage-{len(stages)}"
            stages.append((name, []))
            continue
        if not stages:
            continue
        stages[-1][1].append(line)
    return stages


def stage_named(stages: list[tuple[str, list[str]]], name: str) -> list[str] | None:
    """One stage's instructions, or None when there is no stage by that name."""
    for stage_name, body in stages:
        if stage_name == name:
            return body
    return None


def shell_statements(path: Path) -> list[str]:
    """A shell script's instructions: comments out, continuations joined.

    The same reasoning as `run_lines`, for the two scripts in `images/`. Both
    explain at length why they do *not* do a thing several cases forbid, and a
    case that read the prose would fail on the explanation.
    """
    lines = run_lines(read(path))
    statements: list[str] = []
    index = 0
    while index < len(lines):
        statement = lines[index]
        while statement.endswith("\\") and index + 1 < len(lines):
            index += 1
            statement = statement[:-1].rstrip() + " " + lines[index]
        statements.append(statement)
        index += 1
    return statements


def folded_lines(text: str) -> list[str]:
    """Every non-comment line, with backslash continuations joined.

    A Containerfile folds a long instruction over several lines, and a case that
    looked for a token on one physical line would be testing the file's
    formatting rather than what it says. So `systemd-resolved` counts whether it
    is on its own line or the last of three.
    """
    lines = run_lines(text)
    folded: list[str] = []
    index = 0
    while index < len(lines):
        statement = lines[index]
        while statement.endswith("\\") and index + 1 < len(lines):
            index += 1
            statement = statement[:-1].rstrip() + " " + lines[index]
        folded.append(statement)
        index += 1
    return folded


def instructions(text: str) -> list[str]:
    """Every `RUN` in a Containerfile, continuations joined.

    Only the `RUN` lines, because a case about what a file *installs* or *copies*
    is a case about the instructions that do the installing -- and reading the
    whole file would have every case match the prose that explains the file.
    """
    return [line for line in folded_lines(text) if line.startswith("RUN ")]


# Every way a Containerfile can get a `.deb`'s contents into the image. The rule
# the suite enforces is "no Containerfile installs the project's package at build
# time", and a rule that only reads `apt-get install` tokens is a rule about one
# spelling of "install": `RUN dpkg -i /tmp/mosdns-router.deb`, `ADD x.deb /`, and
# `COPY` of a `.deb` all bypass it, and the first two do it in a single line that
# looks nothing like a package list.
PACKAGE_INSTALLERS = ("apt-get", "apt", "dpkg", "apk", "yum", "dnf", "zypper", "pip", "pip3")
DEB_SUFFIX = (".deb", ".rpm")


def package_artifacts(text: str) -> list[str]:
    """Every package file and every installer's argument list a Containerfile uses.

    Two shapes, because there are two ways to be wrong: a *named package* (through
    `apt-get install`, which the previous version of this rule read) and a *package
    file* (through `dpkg -i`, `ADD`, or a `COPY` of a `.deb`). The second is the
    one that matters for this project, whose own artifact is a `.deb` -- a build
    that installed it would make the image's own packaging the thing under test
    before a scenario ran.
    """
    found: list[str] = []
    for line in instructions(text):
        tokens = line.split()
        for installer in PACKAGE_INSTALLERS:
            if installer in tokens:
                index = tokens.index(installer)
                found.append(" ".join(tokens[index : index + 6]))
    # Scanned over *every* instruction, not only the `RUN` ones: `ADD x.deb /tmp/`
    # and `COPY x.deb /tmp/` are two of the three shapes this rule exists for, and
    # an earlier version of it read `apt-get install` tokens only, so a `COPY` of a
    # `.deb` -- the spelling this project would actually use, its artifact being a
    # `.deb` -- scored as clean.
    for line in folded_lines(text):
        for token in line.split():
            if token.endswith(DEB_SUFFIX):
                found.append(token)
    return found


def installed_packages(text: str) -> set[str]:
    """Every package every `apt-get install` in the file installs.

    Read from the joined instructions, and stopped at the first `&&`, so the
    `rm -rf /var/lib/apt/lists/*` that follows the install in every one of these
    files is not read as a package name. A Containerfile that installs nothing
    names no package, and the case that says "no Containerfile installs the
    project package" would pass on it -- which is why the control case builds a
    Containerfile that does install it.
    """
    found: set[str] = set()
    for statement in instructions(text):
        if "apt-get" not in statement:
            continue
        tokens = statement.split()
        if "install" not in tokens:
            continue
        for token in tokens[tokens.index("install") + 1 :]:
            if token == "&&" or token.endswith(";"):
                break
            if token.startswith("-"):
                continue
            found.add(token)
    return found


def _by_package(conflicts) -> dict:
    """`[(package, release), ...]` regrouped as `{package: [releases]}`, for a message."""
    grouped: dict = {}
    for package, version in conflicts:
        grouped.setdefault(package, []).append(version)
    return grouped


def package_release_conflicts(installed, availability) -> list[tuple[str, str]]:
    """(package, release) for every package `installed` names that `availability`
    records as absent from a release.

    The rule the availability case enforces, as a function, so that a control can
    point **this** code at a Containerfile that violates it. A control that
    re-implements the rule proves nothing about the rule; a control that calls it
    proves the rule can fail.

    `installed` is a set of package names and `availability` maps a package to
    `{release: note}`, where a note beginning `ABSENT` is the recorded absence. A
    package the table does not mention at all produces no conflict, which is the
    other half of the rule: a package nobody recorded cannot be known to be missing
    anywhere, and the table's own coverage case is what holds that the table is
    about this matrix.
    """
    conflicts: list[tuple[str, str]] = []
    for package in sorted(installed):
        for version, note in availability.get(package, {}).items():
            if note.startswith("ABSENT"):
                conflicts.append((package, version))
    return conflicts


def looks_like_no_registry(stderr: str) -> bool:
    """Whether a podman failure is "the network is not there" rather than "no such digest".

    The distinction is the difference between a skip and a failure, and getting it
    backwards is the worst of both: a stale or fabricated digest would be skipped
    as though the operator were offline. So it is a *named* set of network-shaped
    messages, and a digest error is deliberately not in it -- a message naming a
    manifest or a digest is a real answer from the registry and it fails the case.

    The control below is what keeps this honest: a message naming a missing
    manifest is not in the set.
    """
    lowered = stderr.lower()
    return any(
        marker in lowered
        for marker in (
            "dial tcp",
            "connection refused",
            "no such host",
            "network is unreachable",
            "temporary failure in name resolution",
            "i/o timeout",
            "context deadline exceeded",
            "proxyconnect",
            "x509: certificate",
            "tls handshake",
        )
    )


class LockFileTest(unittest.TestCase):
    """`images.lock.json`, and what a build does with an entry in it."""

    def test_the_lock_file_is_json_with_a_version_for_each_release(self):
        """The three versions the plan's matrix runs, and no others.

        Asserted as a set of literals, so a fourth entry -- a version nobody
        decided to test -- is visible rather than silently swept along.
        """
        lock = images.load_lock(LOCK)
        self.assertEqual(sorted(lock["images"]), ["22.04", "24.04", "26.04"])

    def test_every_entry_carries_a_digest_with_the_sha256_prefix(self):
        """A bare hex digest is not a digest a `podman pull` can be given.

        The rule is structural rather than a convention: `docker.io/library/
        ubuntu:24.04@<digest>` is only a valid reference when the digest is
        `sha256:`-prefixed, and a lock entry that lost its prefix would produce a
        reference that fails at `podman build` with a message about the
        repository rather than about the lock.
        """
        lock = images.load_lock(LOCK)
        for version, entry in sorted(lock["images"].items()):
            with self.subTest(version=version):
                self.assertIn("digest", entry, f"{version} has no digest")
                self.assertTrue(
                    entry["digest"].startswith("sha256:"),
                    f"{version} holds {entry['digest']!r}, which is not a digest reference",
                )
                self.assertRegex(entry["digest"], r"^sha256:[0-9a-f]{64}$")

    def test_a_digest_is_sixty_four_hex_characters(self):
        """Length and alphabet, because a plausible-looking digest is still a lie.

        A digest nobody pulled would still match `sha256:` -- that is the whole
        problem this case exists for. It would be written out of a habit, and a
        habit produces the right prefix and 64 characters and nothing that could
        distinguish it from a real one. What this holds is the *shape*; the
        honest check is `ImageDigestVerificationTest`, which pulls.
        """
        lock = images.load_lock(LOCK)
        for version, entry in sorted(lock["images"].items()):
            with self.subTest(version=version):
                digest = entry["digest"]
                self.assertEqual(len(digest.split(":", 1)[1]), 64, version)
                self.assertTrue(
                    all(c in "0123456789abcdef" for c in digest.split(":", 1)[1]),
                    f"{version} holds {digest!r}, which is not lowercase hex",
                )

    def test_a_lock_entry_without_the_sha256_prefix_is_refused(self):
        """The rejection is in code, and it is the build that gets it.

        A build constructs `docker.io/library/ubuntu:<version>@<digest>` from the
        lock. A digest without the prefix makes that a reference podman cannot
        resolve, and the error names the repository rather than the lock file --
        so the check has to happen where the lock is read.
        """
        with self.assertRaises(images.LockError) as caught:
            images.base_image_reference({"digest": "281c5745f657873d78e5531fc5ba8575f"}, "22.04")
        message = str(caught.exception)
        self.assertIn("sha256:", message)
        self.assertIn("22.04", message)

    def test_a_digest_that_is_not_a_digest_at_all_is_refused(self):
        """The prefix check is a prefix, not a shape check, and the shape is here too.

        `sha256:not-a-digest` passes a prefix test, and the reference it produces
        is as unusable as the one without the prefix -- so the whole shape is
        checked where the entry is read.
        """
        with self.assertRaises(images.LockError):
            images.base_image_reference({"digest": "sha256:not-a-digest"}, "24.04")

    def test_a_version_with_no_entry_is_refused_by_name(self):
        """A build for a version the lock does not cover must stop.

        Falling back to a tag would be the worst of the three answers available:
        the run would use a floating image, the whole point of the lock -- that
        two runs of the matrix are the same three images -- would be gone, and
        nothing would report it. So the refusal names the version and the
        versions the lock *does* cover, which is the information a caller needs to
        act on.
        """
        with self.assertRaises(images.LockError) as caught:
            images.reference_for_version("20.04", LOCK)
        message = str(caught.exception)
        self.assertIn("20.04", message)
        self.assertIn("22.04", message)

    def test_a_version_the_lock_covers_gives_a_usable_reference(self):
        """The control for the case above: the ordinary path works.

        Without it, a `LockError` that fired on *every* version would pass
        `test_a_version_with_no_entry_is_refused_by_name` and leave the harness
        unable to build anything at all.
        """
        self.assertEqual(
            images.reference_for_version("24.04", LOCK),
            "docker.io/library/ubuntu:24.04@sha256:"
            "496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4",
        )

    def test_iterating_the_lock_refuses_a_version_recorded_unavailable(self):
        """A matrix run with one version quietly missing is an incomplete run reported as complete.

        `every_reference` is what a build iterates, so it raises on an absence
        rather than skipping it. A caller that wanted to tolerate an absence has
        the lock to read and the absence is *recorded*, with a reason.
        """
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "images.lock.json"
            path.write_text(
                json.dumps(
                    {
                        "arch": "amd64",
                        "images": {
                            "22.04": {"digest": "sha256:" + "d" * 64},
                            "26.04": {
                                "unavailable": "no manifest for the tag on the registry"
                            },
                        },
                        "schema": "mosdns-podman-images/1",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(images.LockError) as caught:
                images.every_reference(path)
            self.assertIn("26.04", str(caught.exception))

    def test_a_missing_lock_file_is_a_refusal_and_not_a_generated_one(self):
        """The lock is a committed file; writing one at run time records a moving target.

        A generated lock would record whatever the registry served that day, which
        is the exact thing the file exists to prevent, and it would do so silently
        -- the run would have a lock and a digest and no history.
        """
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(images.LockError) as caught:
                images.load_lock(Path(scratch) / "images.lock.json")
            self.assertIn("committed file", str(caught.exception))

    def test_a_version_recorded_as_unavailable_says_why(self):
        """An absent image is a finding with a reason, not a gap and not a guess.

        A version whose image cannot be pulled is recorded `unavailable` with the
        reason, so a reader learns *that* and *why* from the lock rather than
        from a digest somebody typed. And `base_image_reference` refuses it,
        because a build cannot use an absence.
        """
        entry = {"unavailable": "registry has no manifest for docker.io/library/ubuntu:99.04"}
        with self.assertRaises(images.LockError) as caught:
            images.base_image_reference(entry, "26.04")
        message = str(caught.exception)
        self.assertIn("26.04", message)
        self.assertIn("no manifest", message)

    def test_the_reference_it_builds_pins_the_tag_and_the_digest(self):
        """`repo:tag@digest`, which is the form a build has to be given.

        A tag alone floats to whatever the registry serves that day; a digest
        alone loses which release the harness meant to test. Both are needed, in
        that order and in one reference.
        """
        reference = images.base_image_reference(
            {"digest": "sha256:" + "b" * 64}, "24.04"
        )
        self.assertEqual(
            reference, "docker.io/library/ubuntu:24.04@sha256:" + "b" * 64
        )

    def test_the_lock_records_where_each_digest_came_from(self):
        """A digest with no provenance is a claim, and a claim is not a pin.

        Every entry says how it was obtained, so a reader who doubts one can
        re-run that one command and get the same answer -- which is the only thing
        that makes a lock file reviewable rather than decorative.
        """
        lock = images.load_lock(LOCK)
        for version, entry in sorted(lock["images"].items()):
            with self.subTest(version=version):
                self.assertIn("resolved_by", entry, version)
                self.assertTrue(
                    "podman image inspect" in entry["resolved_by"],
                    f"{version} does not say how its digest was read",
                )
                self.assertIn("docker.io/library/ubuntu:" + version, entry["resolved_by"])
class TargetContainerfileTest(unittest.TestCase):
    """The target image: the packages the scenarios need, and the ones it must not have."""

    def test_it_installs_the_packages_the_plan_names(self):
        """Each of the nine, by name.

        They are not interchangeable and not a wish list: `systemd-sysv` is what
        supplies `/sbin/init` for `--systemd=always`, `network-manager` is the
        thing whose device state the harness asserts, `libnss-resolve` is what
        makes a name lookup in the target go to the stub rather than past it, and
        `dnsutils` supplies `dig`, which is how the routing scenarios measure the
        resolver at all.
        """
        packages = installed_packages(read(TARGET_CONTAINERFILE))
        for package in TARGET_PACKAGES:
            with self.subTest(package=package):
                self.assertIn(
                    package,
                    packages,
                    f"the target image does not install {package}, and the scenarios need it",
                )

    def test_it_installs_nss_integration_for_the_stub_resolver(self):
        """`libnss-resolve`, which exists on all three releases.

        **This is the cross-version correction, and it was found by building the
        image on 22.04.** The first version of this Containerfile named
        `systemd-resolved`, which is a binary package on 24.04 and 26.04 and does
        not exist on 22.04 at all -- there the daemon is part of `systemd`, which
        `systemd-sysv` already pulls in. The build failed with:

            E: Unable to locate package systemd-resolved

        `libnss-resolve` is the package that exists on all three, and it is what
        the matrix wants anyway rather than a coincidence:

        * 22.04 -- `Depends: … systemd (= 249.11-0ubuntu3.22)`, the daemon comes
          with it;
        * 24.04 -- `Depends: … systemd-resolved (= 255.4-1ubuntu8.17)`;
        * 26.04 -- `Depends: libc6`, the daemon is in `systemd` again.

        and it is the NSS module, without which `getent hosts` in a target reads
        `/etc/hosts` and then the network, and never asks 127.0.0.53 at all. A
        routing scenario that measured names rather than queries would have been
        measuring the wrong resolver and said nothing.
        """
        self.assertIn("libnss-resolve", installed_packages(read(TARGET_CONTAINERFILE)))

    def test_it_names_no_resolved_package_that_only_exists_on_two_releases(self):
        """`systemd-resolved` is the exact name that broke the 22.04 build.

        Asserted because the name is *plausible*: it is the package on two of the
        three releases and the daemon on all three, so it is what anyone reaching
        for "the resolved package" writes. A case that only checked the packages
        were present would have passed here -- the test above caught it, by
        asking for a package the build could not find.
        """
        packages = installed_packages(read(TARGET_CONTAINERFILE))
        self.assertNotIn(
            "systemd-resolved",
            packages,
            "systemd-resolved is a binary package on 24.04 and 26.04 only; on 22.04 the daemon "
            "is part of systemd, and naming it there fails the build with 'Unable to locate "
            "package'. libnss-resolve is the package that exists on all three",
        )

    def test_it_installs_test_tools_too(self):
        """`procps` for `ps`, which the failure scenarios read.

        Named in the plan's Step 3 as "test tools" and asserted by name here,
        because "and test tools" is exactly the phrase that goes stale: a
        Containerfile written for an earlier task kept its own tools and lost this
        one, and the scenario that needed `ps` failed for a reason that had
        nothing to do with what it was testing.
        """
        self.assertIn("procps", installed_packages(read(TARGET_CONTAINERFILE)))

    def test_it_does_not_install_the_project_package_at_build_time(self):
        """The `.deb` is copied in at scenario time, by Task 4.

        A Containerfile that installed the package would make the target's own
        packaging the thing under test before a single scenario ran, and the
        install transaction -- the claim this whole plan exists to close -- would
        have been exercised by the image build instead of by `install_test.py`.
        """
        packages = installed_packages(read(TARGET_CONTAINERFILE))
        for package in packages:
            with self.subTest(package=package):
                self.assertNotIn(
                    "mosdns-router",
                    package,
                    "the target image installs the project's package at build time; the .deb "
                    "is copied in at scenario time so the install transaction is what is tested",
                )

    def test_no_image_installs_a_package_file_or_names_a_package_installer(self):
        """The rule, over the ways to install that `apt-get install` is not.

        The previous version of this rule read `apt-get install` tokens and nothing
        else, so `RUN dpkg -i /tmp/x.deb` -- the spelling this project actually
        uses, since its artifact is a `.deb` -- passed it. That is a rule about one
        spelling of "install", and the artifact a build would have smuggled in is
        exactly the one the spelling does not catch.
        """
        for containerfile in containerfiles():
            with self.subTest(containerfile=containerfile.name):
                offenders = [
                    artifact
                    for artifact in package_artifacts(read(containerfile))
                    if "mosdns-router" in artifact
                    or artifact.endswith(DEB_SUFFIX)
                ]
                self.assertEqual(
                    offenders, [],
                    f"{containerfile.name} gets a package into the image at build time: {offenders}. "
                    f"The .deb is copied in at scenario time, so the install transaction is what "
                    f"is under test",
                )

    def test_the_package_file_detector_sees_a_deb(self):
        """The control, and the limit of the previous rule beside it.

        Three shapes, each of which a build could plausibly write, and the first of
        which is what the old `apt-get`-only rule scored as clean.
        """
        for offending in (
            "FROM ubuntu:24.04\nRUN dpkg -i /tmp/mosdns-router_0.1.0_amd64.deb\n",
            "FROM ubuntu:24.04\nADD build/mosdns-router_0.1.0_amd64.deb /tmp/\n",
            "FROM ubuntu:24.04\nCOPY build/mosdns-router.deb /tmp/\n",
        ):
            with self.subTest(containerfile=offending.splitlines()[1]):
                self.assertTrue(
                    [a for a in package_artifacts(offending) if a.endswith(DEB_SUFFIX)],
                    "the detector misses a way of getting a .deb into an image",
                )
                self.assertFalse(
                    installed_packages(offending),
                    "installed_packages scores a dpkg/ADD/COPY of a .deb as no package at all, "
                    "which is the hole this case documents",
                )

    def test_no_containerfile_installs_the_project_package(self):
        """The rule over all three images, not just the target.

        The mock router and the mock CDN are the images a scenario would be
        *un*willing to trust if they carried the package, because a mock that
        already had the thing it mocks answers differently from one that has to
        have it installed into it.
        """
        for containerfile in (TARGET_CONTAINERFILE, MOCK_ROUTER_CONTAINERFILE, MOCK_CDN_CONTAINERFILE):
            with self.subTest(containerfile=containerfile.name):
                packages = installed_packages(read(containerfile))
                self.assertFalse(
                    [p for p in packages if "mosdns-router" in p],
                    f"{containerfile.name} installs the project package at build time",
                )

    def test_the_rule_can_fail(self):
        """The control. A check that cannot fail is a comment.

        The four previous rounds in this project each found one, so every rule
        this file states is also shown failing once on a file built for the
        purpose. Here: a Containerfile that really does install the package must
        be reported by the same code that just said the three real ones are
        clean.
        """
        offending = "FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y mosdns-router\n"
        self.assertIn("mosdns-router", installed_packages(offending))

    def test_the_resolver_is_pointed_at_the_stub_by_the_entrypoint_not_the_build(self):
        """`/etc/resolv.conf` is a runtime bind mount, so the image cannot own it.

        **Measured, and it is the reason this lives where it does.** Podman mounts
        a generated resolv.conf over `/etc/resolv.conf` in every container *and*
        in every build step, so a `RUN ln -sf` in the Containerfile fails with `ln:
        failed to create symbolic link '/etc/resolv.conf': Device or resource busy`
        -- measured by building this image. At run time the same mount is in place
        and both `rm` and `ln` fail against it. The entrypoint, running as PID 1
        inside the target with the `SYS_ADMIN` the measured flag set already
        grants, unmounts it *inside the container's own mount namespace* and puts
        the resolved stub there.

        The host is not involved: the mount is created by the runtime inside the
        container's namespace, and this harness refuses to bind any host path
        under `/etc`, `/run`, `/var` or `/sys` in the first place. Verified after
        the real run: this host's `/etc/resolv.conf` was still the same
        `../run/systemd/resolve/stub-resolv.conf` symlink with the same mtime.

        Each half is asserted on its own statement rather than on one regex over
        the whole file, because the script names the paths in variables -- a
        single pattern that had to follow the indirection is a pattern that
        quietly stops matching when the script is written a little differently,
        and a check that stops matching is a check that has stopped failing.
        """
        statements = shell_statements(ENTRYPOINT)
        assigned = dict(
            statement.split("=", 1)
            for statement in statements
            if re.fullmatch(r"[A-Z_]+=/[^\s]*", statement)
        )
        self.assertEqual(assigned.get("RESOLV_CONF"), "/etc/resolv.conf", statements)
        self.assertEqual(assigned.get("STUB"), "/run/systemd/resolve/stub-resolv.conf", statements)
        self.assertTrue(
            [line for line in statements if line.startswith("umount ") and "$RESOLV_CONF" in line],
            f"the entrypoint never unmounts the runtime's bind over {assigned.get('RESOLV_CONF')}, "
            f"so `rm` and `ln` below it fail with 'Device or resource busy': {statements}",
        )
        self.assertTrue(
            [line for line in statements if "ln -s" in line and "$STUB" in line],
            f"the entrypoint never points {assigned.get('RESOLV_CONF')} at the resolved stub: "
            f"{statements}",
        )

    def test_the_containerfile_does_not_try_to_symlink_the_resolver_at_build_time(self):
        """A build step cannot replace it, and the case says so rather than a comment.

        The failure is `Device or resource busy` at STEP 4 of the build, so it is
        loud -- but only once somebody tries it, and a reviewer reading a
        Containerfile has no way to know. Asserted on the instructions.
        """
        self.assertFalse(
            [line for line in instructions(read(TARGET_CONTAINERFILE)) if "/etc/resolv.conf" in line],
            "the Containerfile touches /etc/resolv.conf, which is a runtime bind mount and cannot "
            "be replaced at build time",
        )

    def test_the_build_time_symlink_detector_is_a_detector_and_not_a_pass(self):
        """The control for the case above.

        Without it, a case asserting "no instruction mentions /etc/resolv.conf"
        would also be satisfied by an emptied Containerfile, and the defect would
        be reported as covered.
        """
        offending = (
            "FROM ubuntu:24.04\n"
            "RUN ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf\n"
        )
        self.assertTrue(
            [line for line in instructions(offending) if "/etc/resolv.conf" in line]
        )

    def test_the_entrypoint_refuses_a_target_it_could_not_give_the_stub_resolver(self):
        """Silently continuing is the failure this rule is for.

        If the resolver cannot be replaced, the target keeps the runtime's
        resolv.conf -- `nameserver 10.89.0.1`, the bridge gateway. Every DNS
        assertion in a scenario then measures the gateway rather than the mock
        router or resolved, the package is not the thing under test, and the
        failure reads like an installer bug in a package that is not installed
        yet. The refusal belongs to the image, at boot, for the same reason the
        managed-device check does: a scenario is the wrong place to learn that
        the target was never measurable.

        Both halves are held. The `umount` is allowed to fail -- a plain file
        there is the right answer, not an error -- and the two that must not are
        the `rm` and the `ln`, so the umount's `|| true` cannot be the thing that
        swallows the failure.
        """
        statements = shell_statements(ENTRYPOINT)
        unmounts = [line for line in statements if line.startswith("umount ")]
        self.assertEqual(len(unmounts), 1, f"expected one umount of the runtime's bind: {statements}")
        self.assertIn(
            "||",
            unmounts[0],
            f"the umount is not allowed to fail, so a target whose resolver really is a bind "
            f"mount would not boot: {unmounts[0]!r}",
        )
        replacing = [
            line
            for line in statements
            if line.startswith(("rm -f", "ln -s")) or "rm -f" in line
        ]
        self.assertTrue(replacing, f"the entrypoint does not replace the resolver: {statements}")
        for line in replacing:
            with self.subTest(statement=line):
                self.assertIn(
                    "!",
                    line,
                    f"this replacement is not checked, so a target that could not be given the "
                    f"stub would boot anyway: {line!r}",
                )
        self.assertTrue(
            [line for line in statements if line.strip() == "exit 1"],
            f"the entrypoint has no failure exit, so an unprepared target boots anyway: {statements}",
        )

    def test_it_masks_the_units_that_would_otherwise_fight_systemd(self):
        """`systemd-networkd` and `systemd-resolved`'s own resolv.conf handling.

        A container image that enables `systemd-networkd` alongside
        NetworkManager has two managers claiming the same device, and the
        resulting logs are a coin toss. This is asserted because the fix is
        invisible when it works: a missing mask shows up as an intermittent
        `dhcp_test` failure on one release and none at all.
        """
        text = read(TARGET_CONTAINERFILE)
        self.assertIn("systemd-networkd", text)
        self.assertRegex(text, r"(mask|disable).*systemd-networkd|systemd-networkd.*(mask|disable)")

    def test_it_creates_the_users_the_scenarios_act_as(self):
        """`mosdns` and `mosdns-cdn`, so the two-user scenario is not a `useradd` away.

        The package creates them, and the image does not carry the package, so an
        image that did not create them would make `two_user_lock_test` fail on a
        missing user rather than on the control lock -- which is the failure the
        scenario exists to detect.
        """
        text = read(TARGET_CONTAINERFILE)
        for account in ("mosdns", "mosdns-cdn"):
            with self.subTest(account=account):
                self.assertIn(account, text)

    def test_it_starts_nothing_from_the_image_that_a_scenario_owns(self):
        """No `CMD` that starts the project, and no unit enabled for it.

        The project installs its own units and enables them itself; an image that
        pre-enabled one would make `is-enabled` pass on a package that never
        installed anything.
        """
        text = read(TARGET_CONTAINERFILE)
        for unit in ("mosdns-router.service", "mosdns-cdn-optimizer.service"):
            with self.subTest(unit=unit):
                self.assertNotIn(
                    "systemctl enable " + unit,
                    text,
                    f"the image enables {unit}, so the packaged unit's own enable step is "
                    f"never exercised",
                )
class MockRouterContainerfileTest(unittest.TestCase):
    """The mock DHCP/DNS router: `dnsmasq`, and nothing that could answer for real."""

    def test_it_installs_dnsmasq(self):
        """The plan's Step 3 -- `dnsmasq-base`, which is the package on Ubuntu.

        One daemon is both the DHCP server and the forwarder, which is what lets
        a single container produce both the lease and the DNS change a target
        observes; a router image with only `isc-dhcp-server` would have a lease
        and no DNS to publish.

        `dnsmasq-base` rather than `dnsmasq`: on Ubuntu the `dnsmasq` package is
        the systemd unit wrapper, and this image runs the daemon in the
        foreground as PID 1 where a unit is not what starts it. The assertion
        accepts either, and separately requires the binary the CMD names, so a
        future edit cannot satisfy the case with a package that provides no
        daemon.
        """
        packages = installed_packages(read(MOCK_ROUTER_CONTAINERFILE))
        self.assertTrue(
            [package for package in packages if package.startswith("dnsmasq")],
            f"the mock router image installs no dnsmasq package; it installs {sorted(packages)}",
        )

    def test_it_installs_the_dnsmasq_package_that_provides_the_daemon(self):
        """The exact package, because the case above accepts a family.

        `dnsmasq-base` is the one that ships `/usr/sbin/dnsmasq`. The other member
        of the family is the unit wrapper, and an image that installed only that
        would have no binary for the CMD to name.
        """
        self.assertIn("dnsmasq-base", installed_packages(read(MOCK_ROUTER_CONTAINERFILE)))

    def test_it_has_a_command_a_control_action_can_hup(self):
        """dnsmasq re-reads its configuration on SIGHUP, which is the control.

        Task 3's step 3 rewrites the config inside the container and sends HUP, so
        the image's command has to be one a signal can reach -- dnsmasq itself,
        in the foreground, rather than a wrapper that started it in the
        background and waited. A shell in between would be PID 1, the signal
        would go to the shell, and the scenario would wait for a DNS change that
        cannot arrive.
        """
        commands = [
            line for line in run_lines(read(MOCK_ROUTER_CONTAINERFILE)) if line.startswith("CMD ")
        ]
        self.assertEqual(len(commands), 1, f"the router image has {len(commands)} CMD lines: {commands}")
        self.assertRegex(
            commands[0],
            r"^CMD\s+\[?[\"']?/usr/sbin/dnsmasq\b",
            f"the router's CMD does not exec dnsmasq itself: {commands[0]!r}",
        )
        self.assertIn("--keep-in-foreground", commands[0])

    def test_it_does_not_bind_the_hosts_resolver_ports(self):
        """No `EXPOSE`, and no published port for the resolver.

        The whole plan is that a run changes no host state, and a mock router
        reachable on the host's port 53 would break the host's resolver in order
        to test a resolver. The bridge network is private, so the image needs no
        port declaration at all -- asserted on the **instructions**, because the
        file's comment says "No EXPOSE" and a case that read the prose would fail
        on the explanation.
        """
        lines = run_lines(read(MOCK_ROUTER_CONTAINERFILE))
        self.assertFalse(
            [line for line in lines if line.upper().startswith("EXPOSE")],
            "the mock router image declares an EXPOSE, and the run's network is private",
        )
        for port in ("53:53", "15353"):
            with self.subTest(port=port):
                self.assertFalse(
                    [line for line in lines if port in line],
                    f"the mock router image names {port}, which would reach the host's resolver",
                )
class MockCdnContainerfileTest(unittest.TestCase):
    """The mock CDN: built from this repository's Go module, not from a base image."""

    def test_it_builds_from_the_repositories_go_module(self):
        """`go build` inside the image, from the source tree, in two stages.

        Two stages because the plan's own constraint is that no image carries a
        toolchain it does not need, and a CDN server with a Go toolchain in it is
        a much larger image for the same few hundred kilobytes of static binary.
        Asserted as the build stage *having* the toolchain and the serving stage
        not having it, because a `FROM` count is a symptom and the two claims are
        the ones that matter.
        """
        stages = containerfile_stages(read(MOCK_CDN_CONTAINERFILE))
        self.assertEqual(len(stages), 2, f"the CDN image is not two stages: {stages}")
        build = stage_named(stages, "build")
        self.assertIsNotNone(
            build,
            f"no build stage: {[name for name, _ in stages]}. A multi-stage build names the "
            f"stage it copies out of",
        )
        final = stages[-1][1]
        self.assertTrue(
            any("golang" in line for line in build),
            "the build stage does not install a Go toolchain, so nothing here is compiled",
        )
        self.assertFalse(
            [line for line in final if "golang" in line],
            f"the serving stage installs a Go toolchain: {final}",
        )
        self.assertTrue(
            any("COPY --from=build" in line for line in final),
            f"the serving stage copies nothing out of the build stage: {final}",
        )

    def test_the_cdn_image_serves_from_this_module_and_installs_no_server(self):
        """The plan's own answer, and the absence is the point.

        The plan says the mock CDN is built from the repository's Go module, so the
        server is `crypto/tls` in that module. The first version of this file
        installed `caddy` in the serving stage to avoid writing it, and **caddy
        does not exist on Ubuntu 22.04** -- measured against the locked digest with
        `universe` enabled: `apt-cache policy caddy` and `apt-cache search ^caddy`
        are both empty. So the image could not be built on a third of the matrix.

        Two properties, because either alone is satisfiable by accident: it
        **builds** the server from this module, and its serving stage **installs no
        package**, so there is nothing for a release to lack.
        """
        stages = containerfile_stages(read(MOCK_CDN_CONTAINERFILE))
        build = stage_named(stages, "build")
        self.assertIsNotNone(build, [name for name, _ in stages])
        self.assertTrue(
            any("golang" in line for line in build),
            "the build stage does not install a Go toolchain, so nothing here is compiled",
        )
        self.assertTrue(
            any("go build" in line and "tests/podman/mock-cdn" in line for line in build),
            f"the CDN server is not built from this module: {build}",
        )
        serving = stages[-1][1]
        self.assertEqual(
            [line for line in serving if "apt-get install" in line],
            [],
            f"the serving stage installs a package, and a package is a thing a release may not "
            f"have: {serving}",
        )
        self.assertTrue(
            any("COPY --from=build" in line for line in serving),
            f"the serving stage copies nothing out of the build stage: {serving}",
        )

    def test_the_cdn_rule_can_fail(self):
        """The control: a Containerfile that installs caddy is reported.

        Without it, "the serving stage installs nothing" would also be satisfied by
        a helper that never read the file -- and this round's defect was exactly a
        check that could not see the file it was supposed to read.
        """
        offending = (
            "ARG BASE_IMAGE\nFROM ${BASE_IMAGE} AS build\n"
            "RUN apt-get update && apt-get install -y golang-go\n"
            "FROM ${BASE_IMAGE}\n"
            "RUN apt-get update && apt-get install -y caddy\n"
        )
        serving = containerfile_stages(offending)[-1][1]
        self.assertTrue(
            [line for line in serving if "apt-get install" in line],
            "the control does not reproduce the defect, so the case above is not a check",
        )

    def test_it_compiles_the_cdn_server_from_this_module(self):
        """The module's own path, so the image is built from this checkout.

        A CDN image built from a published module would test whatever that module
        happens to be, and the plan's Task 5 step 3 makes assertions about *this*
        project's ECH and CDN behaviour.
        """
        text = read(MOCK_CDN_CONTAINERFILE)
        self.assertIn("go build", text)
        self.assertRegex(text, r"mosdns-router|\./cmd/|/src")

    def test_the_build_is_read_only_about_the_module_cache(self):
        """`-mod=readonly`, so an image build cannot rewrite go.mod.

        The gate's own rule, applied to the image build: a `go build` that
        updated `go.mod` inside a container would be a silent edit to the
        checkout, made by a command whose job is to change nothing.
        """
        self.assertIn("-mod=readonly", read(MOCK_CDN_CONTAINERFILE))


def containerfiles(directory: Path | None = None) -> list[Path]:
    """Every Containerfile in the images directory, sorted.

    **Discovered, not listed.** The first version of the availability check named
    two of the three files, and its own docstring said "every package the three
    Containerfiles install" -- so the one it left out was the one carrying
    `caddy`, which does not exist on 22.04, and the check written to catch exactly
    that could not see it. A hand-maintained list of the files to check is a
    fourth thing that can drift from the three that exist, and it drifts silently:
    a Containerfile added in a later task is checked by nobody.

    Discovered by glob, so a new image joins the set the moment it is written. The
    control below is what makes that a claim rather than a hope.
    """
    return sorted((directory or IMAGES).glob("*.Containerfile"))


class ResolverPackageAvailabilityTest(unittest.TestCase):
    """Defect 1, made structural: a package that exists on only some releases.

    The target image's first version named `systemd-resolved`, which is a binary
    package on 24.04 and 26.04 and does not exist on 22.04 at all — where the
    daemon is part of `systemd`. The failure was a build error on one third of the
    matrix and nothing at all on the other two thirds, which is the worst shape a
    build problem can have: it does not show up until the release it belongs to is
    the one being built.

    The rule is therefore not "install `libnss-resolve`" — that is this matrix's
    answer, and a later release could break it too. The rule is: **every package
    any of these images installs must exist on every release the lock pins.** Two
    ways of holding it, because they fail differently:

    * a **recorded availability table** for the packages that were ever found to
      differ, with the measurement beside it, and a case that reads the table and
      fails on a package it says is absent; and
    * a **live check** that asks each locked image's own apt, so a release the
      lock later adds is covered without anybody editing the table.
    """

    # What was measured, per package, per release. `absent` is a fact about the
    # archive, not a preference, and the reason is in the entry.
    AVAILABILITY = {
        "libnss-resolve": {
            "22.04": "present (Depends: systemd = 249.11-0ubuntu3.22, the daemon with it)",
            "24.04": "present (Depends: systemd-resolved = 255.4-1ubuntu8.17)",
            "26.04": "present (Depends: libc6 >= 2.39; the daemon is in systemd)",
        },
        "systemd-resolved": {
            "22.04": "ABSENT -- the daemon is part of systemd on 22.04",
            "24.04": "present",
            "26.04": "present",
        },
    }

    def locked_versions(self) -> list[str]:
        return sorted(images.load_lock(LOCK)["images"])
    def test_it_checks_every_containerfile_in_the_images_directory(self):
        """The set is discovered, and the control shows a new file joins it.

        The defect this round fixes was a two-file list in a check that claimed to
        cover three. A glob cannot have that defect, and the control is what makes
        the glob load-bearing rather than decorative: a directory containing an
        extra Containerfile must produce a longer list, with no edit to this file.
        """
        self.assertEqual(
            [path.name for path in containerfiles()],
            ["mock-cdn.Containerfile", "mock-router.Containerfile", "target.Containerfile"],
            "the images directory no longer holds the three files this suite was written "
            "against; a new image must be added to this list deliberately or not at all",
        )
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            for name in ("a.Containerfile", "b.Containerfile"):
                (directory / name).write_text("FROM ubuntu:24.04\n", encoding="utf-8")
            (directory / "not-a-containerfile.txt").write_text("x\n", encoding="utf-8")
            self.assertEqual(
                [path.name for path in containerfiles(directory)],
                ["a.Containerfile", "b.Containerfile"],
                "the discovery is not driven by the directory's contents, so adding a "
                "Containerfile would not add it to the set this check looks at",
            )

    def test_every_image_in_the_set_is_covered_by_a_case_class(self):
        """A new image joins the availability set *and* the rest of this file.

        Discovery fixes the availability check. This is the other half: the file
        also has to be a `MockRouter`-shaped or `Target`-shaped image for the
        package and copy-source cases to mean anything, and a Containerfile nobody
        asserts anything about is an image nobody has read.
        """
        mentioned = " ".join(read(path) for path in containerfiles())
        for path in containerfiles():
            with self.subTest(containerfile=path.name):
                self.assertIn(
                    path.name,
                    read(LOCK).replace("mock-cdn", "mock-cdn")
                    + mentioned
                    + Path(__file__).read_text(encoding="utf-8"),
                    f"{path.name} is not named anywhere outside this case, so nothing in the "
                    f"suite reads it",
                )

    def test_the_table_covers_every_release_the_lock_pins(self):
        """A table that has fallen behind the lock would certify nothing.

        The availability claims are per release, and a release added to the lock
        would not be in the table — so the case that reads the table checks the
        two sets agree first. A table is a record; a stale record is worse than
        none, because it looks like a measurement.
        """
        for package, per_release in self.AVAILABILITY.items():
            with self.subTest(package=package):
                self.assertEqual(
                    sorted(per_release),
                    self.locked_versions(),
                    f"the availability table for {package} does not cover the releases the lock "
                    f"pins, so the claims in it are not about the matrix",
                )

    def test_it_names_no_package_the_table_records_as_absent_on_any_release(self):
        """The rule, read from the table. `systemd-resolved` is the case that
        produced it, so it is the control this case is held against.

        The failure mode it prevents is named in the docstring: a build that
        works on two releases and fails on the third, with a matrix of three that
        reports two thirds of itself as passing.
        """
        for containerfile in containerfiles():
            conflicts = package_release_conflicts(
                installed_packages(read(containerfile)), self.AVAILABILITY
            )
            with self.subTest(containerfile=containerfile.name):
                self.assertEqual(
                    conflicts, [],
                    f"{containerfile.name} installs "
                    + ", ".join(
                        f"{package}, which the availability table records as absent on "
                        f"{', '.join(releases)}"
                        for package, releases in _by_package(conflicts).items()
                    )
                    if conflicts
                    else f"{containerfile.name} conflicts with nothing, which is the rule",
                )

    def test_the_check_would_fail_on_a_package_absent_from_one_release(self):
        """The control, and it is the same code as the case above this one.

        A case that read a table and found nothing wrong would also pass on a check
        that never looked, so the rule is pointed at a Containerfile that violates
        it and it has to report the violation.

        **The first version of this control was a tautology wearing a control's
        name.** It ended

            self.assertIn("systemd-resolved", installed_packages(read(TARGET_CONTAINERFILE))
                          | {"systemd-resolved"})

        which is `assertIn` against a set that contains the probed value by
        construction -- true for `set()`, for `{"libnss-resolve"}`, and for
        `{"totally-unrelated"}`. It called itself "the reason the case above is not a
        tautology" while being unable to fail for any input at all. A case that says
        it is a control and is not one is worse than no case, because it is read as
        evidence.

        So the rule is now `package_release_conflicts`, the case above calls it, and
        this control calls it too -- against synthetic Containerfile text, which is
        what `installed_packages` takes, so nothing on disk is involved. Two probes:
        the package the images used to name, which must be reported, and the package
        they name now, which must not.
        """
        # The recorded half, so the control is not only about the helper.
        recorded = self.AVAILABILITY["systemd-resolved"]
        absent = [
            version for version, note in recorded.items() if note.startswith("ABSENT")
        ]
        self.assertEqual(absent, ["22.04"])

        def containerfile_including(package: str) -> str:
            return (
                "FROM ubuntu:24.04\n"
                "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
                f"    {package} \\\n"
                "    && rm -rf /var/lib/apt/lists/*\n"
            )

        self.assertEqual(
            package_release_conflicts(
                installed_packages(containerfile_including("systemd-resolved")),
                self.AVAILABILITY,
            ),
            [("systemd-resolved", "22.04")],
            "the rule does not report the package the images used to install, so the case "
            "above would pass on a rule that never fails",
        )
        # And the other direction, or "reports everything" would satisfy the case
        # above just as well as "reports nothing".
        self.assertEqual(
            package_release_conflicts(
                installed_packages(containerfile_including("libnss-resolve")),
                self.AVAILABILITY,
            ),
            [],
            "the rule reports a package the table records as present everywhere, so the "
            "control above would be satisfied by a rule that flags every package",
        )
        # And that the synthetic file really does install what it claims to, so the
        # control is not passing because the probe read nothing.
        self.assertEqual(
            installed_packages(containerfile_including("systemd-resolved")),
            {"systemd-resolved"},
            "the synthetic Containerfile did not install what the control claims, so both "
            "probes above are vacuous",
        )

    def test_the_resolver_integration_package_is_one_of_them(self):
        """The matrix's own answer, and it has to be a name the table covers.

        Without this the rule above would be satisfied by an image that installs
        no resolver integration at all, which is also a broken target — a routing
        scenario would resolve past the stub and measure the wrong thing. The
        name is matched through the availability table rather than spelled in a
        second list, so "a package the table knows about" and "the resolver
        integration" cannot be two different sets.
        """
        installed = installed_packages(read(TARGET_CONTAINERFILE))
        known = [package for package in installed if package in self.AVAILABILITY]
        self.assertEqual(
            known,
            ["libnss-resolve"],
            f"the target image installs {sorted(installed)}; of those, the ones the availability "
            f"table covers are {known}, and the resolver integration has to be libnss-resolve -- "
            f"the name that exists on all three releases",
        )


class SetupUnitTest(unittest.TestCase):
    """The systemd unit that runs the sequence once, at boot.

    Found by running the image, which is the only way this was going to be found:
    the unit as first written looked correct -- `Requires=NetworkManager.service`
    reads like the obvious way to say "NetworkManager must be up first" -- and
    produced a boot in which NetworkManager ended up not running at all.

    The unit is a file in `images/`, `COPY`d into the image, rather than a
    `printf` in the Containerfile. That is not tidiness: a unit written as a
    `printf` argument list is not parseable as a unit file by anything, including
    the cases below, so "this unit has no `Requires=`" was a claim about a
    sentence in a Containerfile rather than about a unit.
    """

    def unit_directives(self, text: str) -> dict[str, set[str]]:
        """A unit file's `[Section]` keys, as `Key=Value` strings.

        The `Key=Value` shape rather than a dict, because a unit may repeat a key
        (`After=` twice) and a dict would silently keep only one of them -- which
        is how a case about a unit's ordering could pass on a unit that ordered
        against the wrong thing.
        """
        sections: dict[str, set[str]] = {}
        section = ""
        for line in run_lines(text):
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                sections.setdefault(section, set())
                continue
            key, _, value = line.partition("=")
            sections.setdefault(section, set()).add(f"{key.strip()}={value.strip()}")
        return sections

    def setUp(self):
        self.assertTrue(
            NM_UNIT.is_file(),
            f"{NM_UNIT} does not exist, so the image installs the NetworkManager sequence from "
            f"a printf and no case can read the unit it installs",
        )
        self.sections = self.unit_directives(read(NM_UNIT))
        self.containerfile = read(TARGET_CONTAINERFILE)

    def test_the_unit_is_installed_at_the_path_it_is_enabled_from(self):
        self.assertIn(
            f"COPY {NM_UNIT.relative_to(REPO)} /etc/systemd/system/{NM_UNIT.name}",
            " ".join(folded_lines(self.containerfile)),
        )
        self.assertIn(
            "systemctl enable target-nm-setup.service",
            " ".join(instructions(self.containerfile)),
        )

    def test_the_unit_runs_the_script_the_image_installs(self):
        """`ExecStart` names a path the image has to create.

        A unit whose `ExecStart` names a script the image never copied fails at
        boot with `status=203/EXEC`, which is a *different* diagnosis from the
        managed-device one this unit exists to give, and it arrives with no
        sequence run at all.
        """
        started = {
            value.split("=", 1)[1]
            for value in self.sections.get("Service", set())
            if value.startswith("ExecStart=")
        }
        self.assertTrue(started, "the unit runs nothing")
        for path in started:
            with self.subTest(exec_start=path):
                self.assertIn(path, " ".join(folded_lines(self.containerfile)))
        self.assertEqual(
            started,
            {"/usr/local/bin/mosdns-target-nm-setup"},
            f"the unit runs {sorted(started)} rather than the one script this image owns",
        )

    def test_the_unit_waits_for_networkmanager_without_requiring_it(self):
        """Defect 2, as a ruling. **A unit that restarts a service must not
        `Requires=` it**, and the reason is not "insufficient" but "wrong".

        `Requires=NetworkManager.service` reads like the obvious way to say
        "NetworkManager must be up first", and it is the correct spelling of that
        sentence. What makes it wrong here is what `Requires=` *also* means: a
        deactivating required unit deactivates the requiring one. The script's
        third step is `systemctl restart NetworkManager`, and a restart is a stop
        followed by a start — so NetworkManager's own restart SIGTERMed the setup
        unit, systemd restarted it, it created another profile and restarted
        NetworkManager again, and the target came up with **NetworkManager not
        running at all**:

            Main process exited, code=killed, status=15/TERM   (on every pass)
            Warning: There are 4 other connections with the name 'eth0-managed'.

        So the unit **fails its own precondition** — the ordering that was meant to
        guarantee the daemon is up is what took the daemon down, and the
        consequence is not a slow boot but a target that cannot be measured at
        all. That is the difference between insufficient and wrong: a missing
        `After=` would be a race, and a race is fixed by waiting; this is a cycle,
        and a cycle is not fixed by adding more ordering.

        The correct ordering, and it is one directive:

        * `After=NetworkManager.service` — necessary, because the script has to be
          able to reach `nmcli`. It only orders the *job*; it does not wait for
          the daemon to be answering, and the script's own bounded wait for
          `nmcli general status` is what does that.
        * **not** `Requires=` — and not `PartOf=`, `BindsTo=` or `PropagatesStopTo=`,
          which propagate a stop the same way.
        """
        unit = self.sections.get("Unit", set())
        self.assertIn("After=NetworkManager.service", unit)
        # The whole family, not just the one that bit: every one of these makes a
        # deactivating NetworkManager deactivating this unit, and a later task
        # reaching for `PartOf=` is reaching for the same cycle.
        for directive in ("Requires=", "BindsTo=", "PartOf=", "PropagatesStopTo=", "Upholds="):
            offenders = [value for value in unit if value.startswith(directive)]
            self.assertEqual(
                offenders, [],
                f"the unit declares {offenders}, and the script restarts NetworkManager: a "
                f"deactivating required unit deactivates the requiring one, so the restart tears "
                f"down the very unit doing the restarting",
            )

    def test_the_ordering_ruling_is_held_even_when_the_restart_is_gated(self):
        """The gate on the version does not make the ordering safe, so the case still bites.

        The `device set` + restart are skipped on 1.36 and run on 1.44+, so on a
        1.36 target this unit cannot tear NetworkManager down. That is *per
        release*, and the ordering directives are *per unit* — the next release
        that crosses the gate is a 1.44+ one, and the hazard is back with the same
        file. A guard that only mattered below the gate would be switched off
        exactly when it is needed.
        """
        unit = self.sections.get("Unit", set())
        gated = any("nmcli device set" in line for line in shell_statements(NM_SETUP))
        self.assertTrue(
            gated,
            "the setup no longer runs the override at all, so this case is guarding a hazard "
            "that is no longer reachable; the ruling is about the ordering, and it holds "
            "whenever the restart comes back",
        )
        self.assertEqual(
            [value for value in unit if value.startswith("Requires=")], []
        )

    def test_the_requires_check_sees_a_requires_when_one_is_written(self):
        """The control for the case above.

        Without it, "no `Requires=NetworkManager.service`" would also be satisfied
        by a parser that never read a unit file at all.
        """
        written = "[Unit]\nAfter=NetworkManager.service\nRequires=NetworkManager.service\n"
        self.assertIn(
            "Requires=NetworkManager.service",
            self.unit_directives(written).get("Unit", set()),
        )
        self.assertNotIn(
            "Requires=NetworkManager.service",
            self.unit_directives("[Unit]\nAfter=NetworkManager.service\n").get("Unit", set()),
        )
        # And a repeated key is visible, which is why the values are a set of
        # `Key=Value` strings rather than a dict.
        repeated = self.unit_directives("[Unit]\nAfter=a.service\nAfter=b.service\n")
        self.assertEqual(repeated["Unit"], {"After=a.service", "After=b.service"})

    def test_the_unit_runs_before_the_network_is_declared_online(self):
        """Otherwise a scenario that waits for `network-online.target` waits for a device that is not managed.

        Nothing else in the image brings the network up -- the profile this unit
        creates is what activates -- so the ordering against
        `network-online.target` is what makes "the device has its address" mean
        "NetworkManager gave it one" rather than "the runtime gave it one".
        """
        self.assertIn(
            "Before=network-online.target", self.sections.get("Unit", set())
        )

    def test_the_unit_is_oneshot_so_a_failure_is_a_failure_and_not_a_restart_loop(self):
        """A `Type=simple` unit whose process exits non-zero is `failed`; the check's exit is the signal.

        And `Restart=` is absent on purpose: a restart loop would re-run the
        restart of NetworkManager, which is how the defect above turned into four
        profiles. One run, one verdict, and the harness's own
        `assert_networkmanager_manages_device` reports the cell as incomplete.
        """
        service = self.sections.get("Service", set())
        self.assertIn("Type=oneshot", service)
        self.assertFalse(
            [value for value in service if value.startswith("Restart=")],
            f"the unit restarts itself, and each pass restarts NetworkManager again: {sorted(service)}",
        )

    def test_the_profile_is_created_only_when_it_is_absent(self):
        """Re-running the unit must not stack up profiles under one name.

        **Measured.** `nmcli connection add` with a name that already exists does
        not fail: it *warns* -- `Warning: There are 4 other connections with the
        name 'eth0-managed'` -- and creates another. So a unit that runs twice,
        which systemd did here, leaves several profiles for one device, and Task
        3's `nmcli connection up eth0-managed` would then be ambiguous.

        The three measured commands and their order are unchanged; what changes is
        that the first is now guarded, and a case holds the guard.
        """
        statements = shell_statements(NM_SETUP)
        guarded = [
            index
            for index, line in enumerate(statements)
            if "connection show" in line and line.startswith(("if ", "if!", "if\t"))
        ]
        self.assertTrue(
            guarded,
            f"the setup adds the profile unconditionally, so a second run of the unit stacks "
            f"profiles under one name: {statements}",
        )
        add_index = next(
            (i for i, line in enumerate(statements) if "connection add" in line), None
        )
        self.assertIsNotNone(add_index, statements)
        self.assertLess(
            guarded[0],
            add_index,
            f"the guard is after the add, so it guards nothing: {statements}",
        )
class FailedUnitTest(unittest.TestCase):
    """A target boots with no failed unit, or a scenario cannot tell its own fault
    from the image's.

    `netplan-configure.service` fails on 26.04 in this image -- measured, and it is
    the only failed unit in a fresh target. It is netplan's backend configuration
    unit and there is no netplan configuration to apply, so it exits non-zero on
    every boot. Nothing here is broken by it and every scenario still runs, which
    is exactly what makes it a problem: a `systemctl --failed` assertion in Task 4
    or 5 would have to special-case it, and a target that boots with a red unit is
    the shape of thing an operator stops trusting.

    So the image masks it, and this case holds that. The alternative — leaving it —
    is not obviously wrong, which is why the case names the consequence rather than
    asserting a preference.
    """

    def masked_units(self) -> set[str]:
        """Every unit the image masks, read from the `mask` invocations only.

        Collected per `systemctl` fragment rather than by searching the whole
        instruction for `.service` tokens: an instruction that both disables one
        unit and enables another names three services and masks one, and a filter
        on `.service` alone cannot tell which is which. `systemctl disable
        systemd-networkd.service || systemctl mask systemd-networkd.service` is
        exactly that shape.
        """
        masked = set()
        for line in instructions(read(TARGET_CONTAINERFILE)):
            for fragment in line.replace("&&", " ; ").replace("||", " ; ").split(";"):
                tokens = fragment.split()
                if "systemctl" not in tokens or "mask" not in tokens:
                    continue
                masked |= {t for t in tokens if t.endswith(".service")}
        return masked

    def test_it_masks_the_one_unit_that_fails_on_a_fresh_boot(self):
        self.assertIn(
            "netplan-configure.service",
            self.masked_units(),
            f"the image does not mask netplan-configure.service, so every 26.04 target boots "
            f"with one failed unit; the image masks {sorted(self.masked_units())}",
        )

    def test_it_masks_nothing_beyond_the_two_it_can_name_a_reason_for(self):
        """A `systemctl mask *` would make a real failure invisible instead.

        The alternative to masking one noisy unit is masking the world, and the
        cost of that is that the next thing which *should* fail never does. The
        set is therefore held to two, each with a measured reason:
        `netplan-configure.service` fails on a fresh boot and
        `systemd-networkd.service` would otherwise claim the same device as
        NetworkManager.
        """
        self.assertEqual(
            self.masked_units(),
            {"netplan-configure.service", "systemd-networkd.service"},
            f"the image masks {sorted(self.masked_units())}; each mask needs a measured reason "
            f"and a unit that fails for no reason is a way of hiding the next one",
        )


class ManagedDeclarationTest(unittest.TestCase):
    """The device is declared managed by configuration, on every release.

    Measured, and it is a correction rather than a preference. NetworkManager's
    stock `/usr/lib/NetworkManager/conf.d/10-globally-managed-devices.conf` says:

        [keyfile]
        unmanaged-devices=*,except:type:wifi,except:type:gsm,except:type:cdma

    so an `eth0` on a bridge is unmanaged by default -- except that on 24.04 and
    26.04 it comes up managed anyway, and on 22.04 it does not. `except:` is
    NetworkManager's own documented key for "this matched device is handled by
    NetworkManager even when it would not otherwise be", and `interface-name:` is
    the portable selector for it. In a disposable test target whose interface is
    not special, declaring it managed is the mechanism, not a way around one.
    """

    def setUp(self):
        self.assertTrue(
            NM_DECLARATION.is_file(),
            f"{NM_DECLARATION} does not exist, so the image declares nothing and a target is "
            f"managed only where NetworkManager happens to manage it by default",
        )
        self.text = read(NM_DECLARATION)

    def keyfile_values(self) -> list[str]:
        """The `unmanaged-devices` values the declaration sets, as written."""
        values = []
        for line in run_lines(self.text):
            key, _, value = line.partition("=")
            if key.strip() == "unmanaged-devices":
                values.append(value.strip())
        return values

    def test_it_narrows_the_stock_list_rather_than_replacing_it(self):
        """The list is the stock one plus one `except:`, and that is the whole trick.

        `unmanaged-devices=*` with an `except:interface-name:eth0` leaves every
        other device exactly as NetworkManager shipped it. Asserted against the
        stock file's own value, read out of the running images, so a declaration
        that quietly widened to manage everything in the container would fail --
        and one that dropped the `except:` would fail too, because that is a
        no-op, not a declaration.
        """
        values = self.keyfile_values()
        self.assertEqual(len(values), 1, f"the declaration sets it {len(values)} times: {values}")
        value = values[0]
        self.assertTrue(value.startswith("*"), f"it does not narrow a wildcard: {value!r}")
        self.assertIn("except:interface-name:eth0", value)
        # The stock file's own value, so "narrowing" is checked against the thing
        # being narrowed rather than against a paraphrase of it.
        self.assertIn(
            "except:type:wifi,except:type:gsm,except:type:cdma",
            value,
            f"the declaration replaced the stock exceptions rather than adding to them: {value!r}. "
            f"Dropping them would make the container's wifi and modem devices unmanaged too",
        )

    def test_the_declaration_is_ported_in_as_a_file_and_lands_in_conf_d(self):
        """`COPY`ed to `/etc/NetworkManager/conf.d/`, not written by a `RUN`.

        A `RUN` that writes the file is a second copy of the declaration's text in
        the Containerfile, and the two would drift — which is the shape of defect
        this repository keeps finding. So the declaration is one file, and the
        cases above read that file.
        """
        statements = folded_lines(read(TARGET_CONTAINERFILE))
        copies = [line for line in statements if "NetworkManager/conf.d" in line]
        self.assertEqual(len(copies), 1, f"expected one COPY into conf.d: {copies}")
        self.assertIn(str(NM_DECLARATION.relative_to(REPO)), copies[0])
        self.assertFalse(
            [
                line
                for line in instructions(read(TARGET_CONTAINERFILE))
                if "conf.d" in line
            ],
            "the Containerfile also writes a conf.d entry with a RUN, so the declaration exists "
            "twice and the two can disagree",
        )

    def test_the_declaration_names_the_device_the_harness_asserts(self):
        """`except:interface-name:eth0`, tied to `podman.NM_DEVICE` rather than to a literal.

        The harness asserts the managed field on `podman.NM_DEVICE` and the
        declaration excepts a name typed into a configuration file. Nothing
        connected them, so an interface rename in one place left the other
        asserting a device that no longer exists -- and on 24.04 and 26.04, where
        the declaration is inert, **nothing would fail**: the target comes up
        managed anyway and every case stays green over a declaration that names
        the wrong device. On 22.04 it would fail, which is the reason to catch it
        here rather than there.
        """
        from podman import NM_DEVICE

        self.assertIn(
            f"except:interface-name:{NM_DEVICE}",
            self.text,
            f"the declaration does not name {NM_DEVICE}, which is the device the harness "
            f"asserts on and the one this image creates a profile for",
        )
        self.assertIn(
            f"DEVICE={NM_DEVICE}",
            read(NM_SETUP),
            f"the setup script creates a profile for a device that is not {NM_DEVICE}",
        )

    def test_the_declaration_is_documented_as_the_mechanism_only_where_it_is_one(self):
        """**The one thing a contributor cannot discover for themselves.**

        Measured: on 24.04 (nmcli 1.46.0) and 26.04 (nmcli 1.54.3), a bridge
        device comes up **managed with the declaration removed and
        `/run/NetworkManager/devices` cleared** -- `GENERAL.NM-MANAGED: yes`,
        `STATE: 100 (connected)`. So on those two releases the shipped snippet is
        **inert**: masked, misspelled or renamed, the boot check still passes and
        the target still comes up managed. The check cannot fail because of the
        declaration there, and it can only fail on 22.04, where the snippet is the
        mechanism.

        Presenting it as load-bearing on all three is the falsifiable claim this
        case exists for, and the failure it causes is concrete: a contributor
        renames the file, runs the matrix, sees 24.04 pass, concludes the rename
        is fine, and ships an image whose 22.04 target is unmanaged. So the
        inertness is stated in all three records, and this case is what stops it
        being quietly dropped from one of them.
        """
        for path, label in (
            (NM_DECLARATION, "the declaration's own comment"),
            (REPO / "docs/testing.md", "the contributor page"),
            (REPO / "docs/superpowers/plans/2026-09-25-podman-integration-matrix.md", "the plan"),
        ):
            with self.subTest(record=label):
                body = read(path).lower()
                self.assertIn("inert", body, f"{label} does not say the snippet is inert on 24.04 and 26.04")
                for release in ("24.04", "26.04"):
                    self.assertIn(release, body, f"{label} does not name {release}")
                self.assertIn(
                    "22.04", body, f"{label} does not say where the declaration IS the mechanism"
                )

    def test_the_declaration_is_a_conf_d_snippet_and_not_a_whole_main_conf(self):
        """It belongs in `conf.d/`, not over `/etc/NetworkManager/NetworkManager.conf`.

        Overwriting the main file would drop every other `lib:` snippet the distro
        ships — the firewall defaults and the resolved DNS integration on this
        release — for a reason that has nothing to do with the device's managed
        state. That is a silent loss, and it is what `conf.d/` is for.
        """
        statements = folded_lines(read(TARGET_CONTAINERFILE))
        self.assertFalse(
            [line for line in statements if line.endswith("/etc/NetworkManager/NetworkManager.conf")],
            "the image overwrites the main NetworkManager.conf, which drops every other "
            "distro-shipped lib: snippet",
        )
class HarnessRefusalNamesTheDeclarationTest(unittest.TestCase):
    """`podman.py`'s refusal has to name the declaration, which is now the baseline.

    The refusal is what an operator reads when a target comes up unmanaged, and it
    is the same shape of problem this project has hit four times: a message that
    names a sequence which is not what the image does, sends the reader to run it,
    and the reader concludes the harness is wrong. The declaration is now part of
    the required setup, so it is part of what the refusal says.
    """

    def setUp(self):
        import podman as podman_module

        self.podman = podman_module

    def test_the_refusal_names_the_configuration_declaration(self):
        self.assertIn("conf.d", self.podman.NM_UNMANAGED_EXPLANATION)
        self.assertIn("except:interface-name:eth0", self.podman.NM_UNMANAGED_EXPLANATION)

    def test_the_refusal_still_names_the_sequence_and_the_profile(self):
        """Adding the declaration must not displace what was already there.

        The sequence is still what runs on 24.04 and 26.04, and the profile is
        still what Task 3 modifies, so a refusal that mentioned only the
        declaration would be the same class of error in the other direction.
        """
        message = self.podman.NM_UNMANAGED_EXPLANATION
        self.assertIn("nmcli device set eth0 managed yes", message)
        self.assertIn("systemctl restart NetworkManager", message)
        self.assertIn(self.podman.NM_PROFILE_STEP, message)

    def test_the_refusal_carries_the_measured_version_boundary(self):
        """The one fact that distinguishes a 22.04 `no` from a 24.04 `no`.

        They look identical from the outside and have different causes: below 1.44
        the persistent device override does not exist, so the sequence cannot help
        and the declaration is the only mechanism. A reader told "restart" on
        22.04 restarts, finds it worked, and is looking at the wrong thing.
        """
        message = self.podman.NM_UNMANAGED_EXPLANATION
        self.assertIn("1.44", message)
        self.assertIn("1.36.6", message)
class PlanAgreesWithTheImageTest(unittest.TestCase):
    """The plan is the record the next implementer works from, so it is held here.

    Task 1's suite established this pattern: the plan and the harness disagreed
    about who creates the `eth0` connection profile, and nothing would have
    noticed until every cell of the matrix was `incomplete` for ever. The
    architecture note carried a prohibition — *do not add a `NetworkManager.conf.d`
    entry* — that was reasoned from the 24.04 measurement and does not survive the
    22.04 one, and a next task reading it would refuse the declaration the image
    now depends on.
    """

    def setUp(self):
        self.plan = (REPO / "docs/superpowers/plans/2026-09-25-podman-integration-matrix.md").read_text(
            encoding="utf-8"
        )

    def test_the_architecture_note_no_longer_forbids_the_declaration(self):
        self.assertNotIn(
            "Do **not** add a `NetworkManager.conf.d` entry",
            self.plan,
            "the plan still forbids the conf.d declaration the target image now ships, so the next "
            "task will read a prohibition against the mechanism this plan depends on",
        )

    def test_the_architecture_note_states_the_measured_version_boundary(self):
        """The boundary, with the measurement that establishes it.

        Named because a boundary without its evidence is the same as the wrong
        prohibition: an implementer cannot tell a measured threshold from a
        remembered one, and this repository has been bitten by exactly that.
        """
        for token in ("1.36.6", "1.42.4", "1.44.2", "1.46.0", "1.54.3", "1.44"):
            with self.subTest(token=token):
                self.assertIn(token, self.plan)

    def test_the_plan_does_not_name_a_package_22_04_does_not_have(self):
        """**The plan would have sent the next implementer into a failed build.**

        The plan's Task 2 Step 3 still listed `systemd-resolved` among the packages
        the target image installs. That is the exact package this task measured
        absent from 22.04 -- `E: Unable to locate package systemd-resolved` -- and
        the Containerfile now says `libnss-resolve` with the reason. A plan that
        names the other one sends the next implementer straight back to the
        failure, and no case in the suite can stop them, because they would not
        read the Containerfile.

        The check is on the plan's *instruction*, not on a comment: the sentence
        that tells an implementer what to install.
        """
        step = self.plan[self.plan.index("### Task 2:") : self.plan.index("### Task 3:")]
        # Matched on the *instruction* rather than on any mention: the step is
        # allowed to name systemd-resolved in order to say it is not the one to
        # install, and a case that forbade the word would forbid the correction as
        # well as the error. What must not appear is an "installs …" sentence naming
        # it, and the sentence is delimited at the first full stop so the search
        # cannot run past the end of the instruction into the explanation.
        instruction = re.search(r"Target image installs[^.]*", step)
        self.assertIsNotNone(
            instruction, "the plan's Task 2 no longer says what the target image installs"
        )
        self.assertIn("libnss-resolve", instruction.group(0))
        self.assertNotIn(
            "systemd-resolved",
            instruction.group(0),
            "the plan's Task 2 still tells an implementer to install systemd-resolved, which "
            "22.04 does not have; the Containerfile says libnss-resolve and says why",
        )
        # And the control, because a search that finds nothing is also a search that
        # cannot find the real thing. Run against a synthetic stale sentence rather
        # than against this plan: the first version of this control asserted the
        # plan *still* contained the stale wording, which is a self-defeating case
        # -- it fails exactly when the correction lands.
        stale = "Target image installs `systemd-sysv`, `systemd-resolved`, `python3`."
        self.assertIsNotNone(
            re.search(r"Target image installs[^.]*systemd-resolved", stale),
            "the detector does not recognise the stale instruction, so the case above would "
            "pass on a plan that still had it",
        )
        self.assertIsNone(
            re.search(r"Target image installs[^.]*systemd-resolved", "Target image installs `python3`."),
            "the detector matches nothing at all, so the control above is not a control",
        )

    def test_the_plan_says_the_sequence_runs_from_the_unit_and_not_the_entrypoint(self):
        """**Same paragraph, second stale claim, and it is the load-bearing one.**

        The plan said "The target's **entrypoint** must perform the NetworkManager
        device sequence". The implementation deliberately runs it from
        `target-nm-setup.service`, because `nmcli` reaches NetworkManager over
        D-Bus and there is no bus before `/sbin/init` -- measured: `Error: Could not
        create NMClient object: Could not connect: No such file or directory` -- and
        a case in this suite *asserts* the entrypoint must not perform it. So a
        Task 3 implementer following the plan would put the sequence in the
        entrypoint, boot every target unmanaged, and fail every cell for a reason
        that has nothing to do with the package.

        Held here because this suite already holds the plan's conf.d prohibition
        and its version table, and those were the other two claims that had gone
        stale in the same paragraph.
        """
        # **The whole plan, not Task 2's slice.** This was `self.plan[index("### Task 2:")
        # : index("### Task 3:")]`, and that region was the whole defect: the claim it
        # is about is a claim *about Task 3*, and Task 3's step 4 said the opposite in
        # two sentences, and the architecture note said it in a third. A case that
        # scans the paragraph under test will pass on a plan whose other 300 lines
        # contradict it, and this one did -- for a whole round, green, after the two
        # sentences inside the region had already been fixed. The region is now the
        # entire document, because "the plan does not say this" is a claim about the
        # plan.
        step = self.plan
        self.assertNotIn(
            "entrypoint must perform the NetworkManager device sequence",
            step,
            "the plan still tells an implementer to run the sequence from the entrypoint, which "
            "has no D-Bus before /sbin/init; the image runs it from target-nm-setup.service",
        )
        self.assertIn("target-nm-setup.service", step)

        # **And the two sentences that were left behind in the same paragraph.** The
        # fix round corrected the paragraph's opening claim and left the rest of it
        # saying the opposite, which is worse than not having corrected it: a
        # reader who trusts the corrected sentence reads past the two below and
        # implements them. A Task 3 implementer following "The profile is created
        # here, in the image's entrypoint" puts the profile in the entrypoint --
        # before there is a D-Bus -- and every target boots unmanaged, and
        # `test_the_entrypoint_does_not_perform_the_sequence_itself` in
        # `ImageHandsOverToSystemdTest` fails, so the cause is at least visible.
        # The second one is the subtler: "The entrypoint must then fail loudly if
        # `nmcli -g GENERAL.NM-MANAGED` is not `yes`" asks for a check in a place
        # where `nmcli` cannot answer, so the check would pass vacuously and the
        # boot would be unchecked.
        self.assertEqual(
            entrypoint_sentences_that_act(step), [],
            "the plan still gives the image's entrypoint an action to perform; the sequence "
            "and the check both run from target-nm-setup.service. NOTE: this detector does not "
            "model negation, so a hit is a REVIEW ITEM -- read each one and decide; see the "
            "contract above ENTRYPOINT_OWNS_AN_ORDER.",
        )

        # The control, because a detector that finds nothing is also a detector that
        # cannot find the real thing. Run against the two sentences that *were*
        # there, verbatim, plus the three the plan still says correctly -- so the
        # detector is shown to separate them rather than to flag the word.
        stale = (
            "The profile is created **here, in the image's entrypoint**, and not at "
            "scenario time: Task 3 step 4 works on the profile this line creates.\n"
            "The entrypoint must then **fail loudly** if `nmcli -g GENERAL.NM-MANAGED "
            "device show eth0` is not `yes` afterwards.\n"
        )
        correct = (
            "The sequence runs from `target-nm-setup.service`, and not from the "
            "entrypoint.\n"
            "The target's **entrypoint** has its own job and does not touch "
            "NetworkManager: it points `/etc/resolv.conf` at the resolved stub and "
            "then `exec`s `/sbin/init` so systemd is PID 1.\n"
            "An entrypoint that ran these commands itself would fail its first one, "
            "because there is no D-Bus before `/sbin/init`.\n"
        )
        found = entrypoint_sentences_that_act(stale)
        self.assertEqual(
            len(found), 2,
            f"the detector does not recognise the two stale sentences, so the case above "
            f"would pass on a plan that still had them; it found {found}",
        )
        self.assertEqual(
            entrypoint_sentences_that_act(correct), [],
            "the detector flags the plan's own correct sentences about the entrypoint, so "
            "it cannot be used to hold the two stale ones -- the verb list is too wide",
        )

        # **The third one, verbatim, and it is the form the other two are not.** The
        # architecture note stated the order as *data* -- "So the entrypoint order is:
        # create the `eth0` connection profile, then `nmcli device set eth0 managed
        # yes`, then `systemctl restart NetworkManager`" -- with no prepositional
        # phrase, no "must" and no entrypoint-as-subject, so it was outside every
        # enumerated construction and the detector reported the plan clean. That is
        # the residual the last round recorded as "reads constructions, not grammar"
        # landing on live text that contradicted the paragraph it had just fixed, and
        # it is why the list is extended rather than the gap documented: a detector
        # that misses contradictory text in the document it is the detector *for* is
        # worse than no detector, because it reports a clean plan.
        note_stale = (
            "So the entrypoint order is: **create the `eth0` connection profile, then "
            "`nmcli device set eth0 managed yes`, then `systemctl restart "
            "NetworkManager`** — and the profile therefore belongs to **Task 2's image "
            "entrypoint, not to Task 3**."
        )
        self.assertNotIn(
            note_stale, self.plan,
            "the architecture note has reverted to the sentence this control plants, so the "
            "plant is no longer a plant and the control below is testing the detector "
            "against text the plan does not contain",
        )
        self.assertEqual(
            len(entrypoint_sentences_that_act(note_stale)), 1,
            "the detector does not recognise the architecture note's data form, so the case "
            "above would pass on a plan whose own architecture preamble assigns the sequence "
            "to the entrypoint",
        )
        # And the corrected form of the same sentence, so extending the list does not
        # extend it into the plan's own text. **Read out of the plan, not typed here.**
        # The first version of this control was a hand-written paraphrase that ended
        # "an entrypoint that ran any of of the three would fail its first one", while
        # the plan says "... measured on this host as `Error: Could not create NMClient
        # object: Could not connect: No such file or directory`" -- so a report
        # describing it as "verbatim" was quoting the test rather than the document,
        # and the two files visibly disagreed. Reading the real text makes the drift
        # impossible rather than corrected, and `assertIn` below makes a paraphrase a
        # failure instead of a silent substitution.
        # Anchored forward from the note itself, and closed at the end of the
        # measured error rather than at the next sentence: both anchors occur in the
        # note *above* this one as well, so a plain `index` for either finds line 17
        # and slices an empty string.
        closing = "No such file or directory`."
        start = self.plan.index("Within Task 2 it belongs to")
        note_correct = self.plan[start : self.plan.index(closing, start) + len(closing)]
        self.assertTrue(
            note_correct.startswith("Within Task 2 it belongs to")
            and note_correct.endswith(closing),
            "the architecture note's text has changed shape and this control reads the "
            f"plan rather than a paraphrase, so it has to be re-pointed: {note_correct!r}",
        )
        self.assertEqual(
            entrypoint_sentences_that_act(note_correct), [],
            "the detector flags the plan's own architecture note, which now assigns the "
            "sequence to the unit and explains why the entrypoint cannot do it",
        )

        # And the positive half, so the fix is not only "the old words are gone": the
        # plan has to *say* the unit creates the profile and the unit runs the check.
        # Both patterns are read against the whole plan, and both are anchored so they
        # cannot be satisfied by a sentence in a different section from the one that
        # used to contradict them -- `target-nm-setup.service` must be the subject, and
        # "fail loudly" must belong to the unit or the script rather than to anything
        # else. Checked against the whole plan, not the Task 2 slice, for the reason
        # above.
        self.assertRegex(
            step,
            r"target-nm-setup\.service[^.]*(?:creates|created)[^.]*profile",
            "the plan no longer says which component creates the profile, so an implementer "
            "has nothing to follow but the sentences this case removed",
        )
        self.assertRegex(
            step,
            r"[Tt]he (?:unit|script)[^.]*fail loudly",
            "the plan no longer says the boot check must fail loudly, which is the only part "
            "of it that makes an ineffective declaration visible",
        )

    def test_the_detector_cannot_fire_on_a_sentence_it_cannot_see(self):
        """**The branch's third alternative could never fire, and it was the one that
        could false-positive.**

        `entrypoint_sentences_that_act` replaces every inline-code span with two
        spaces *before* matching -- correctly, because a sentence is delimited by a
        full stop and `/etc/NetworkManager/conf.d/10-mosdns-target.conf` is full of
        them. The third alternative of `ENTRYPOINT_OWNS_AN_ORDER` required the
        literal `eth0` between `the` and `connection`, so it matched a sentence
        nobody writes (no backticks) and missed every sentence the plan writes
        (always backticked). Measured: raw 1, post-strip 0.

        So the branch was credited with a form it did not have, and the one form it
        had was the dangerous one: `target-nm-setup.service creates the eth0
        connection profile` -- a correct sentence with **no mention of the
        entrypoint in it** -- is reported as the entrypoint acting. That is a false
        positive waiting for the day somebody stops backticking `eth0`, and a guard
        that reports correct text as a defect trains the next reader to ignore it.

        Three properties, and the second is the one this round exists for:

        1. every alternative of the branch fires on a sentence the plan actually
           writes, and is required to;
        2. a correct sentence is **not** reported -- several of them, including the
           two that a naive version of this branch does report;
        3. a stale one still is, so (2) is not the detector being switched off.
        """
        # 1. Reach. Each alternative gets a sentence in the plan's own idiom.
        for label, sentence in (
            ("a named order", "So the entrypoint order is: create the connection profile, then restart NetworkManager."),
            ("an adjectival head noun", "The entrypoint boot sequence is: set the device managed, then restart NetworkManager."),
            ("a possessive", "The entrypoint's order is: create the connection profile, then restart NetworkManager."),
        ):
            with self.subTest(alternative=label):
                self.assertEqual(
                    len(entrypoint_sentences_that_act(sentence)), 1,
                    f"the detector's {label} form did not fire on a sentence the plan writes "
                    f"in exactly this shape: {sentence!r}",
                )

        # 2. The false positives, one per way this branch has produced one. A correct
        # sentence must yield nothing, and a sentence that is *about* the entrypoint
        # saying it does not do the work is the case a reviewer found.
        for sentence in (
            "The entrypoint order is not the unit's order: the unit creates the profile, "
            "then sets the device managed, then restarts NetworkManager.",
            "The unit creates the eth0 connection profile, then sets the device managed, "
            "then restarts NetworkManager. The entrypoint has its own job.",
            "target-nm-setup.service creates the eth0 connection profile.",
            "The entrypoint has its own job: it points the resolver at the stub, then "
            "execs /sbin/init.",
        ):
            with self.subTest(should_not_report=sentence[:60]):
                self.assertEqual(
                    entrypoint_sentences_that_act(sentence), [],
                    "the detector reports a correct sentence as a defect, so the guard is a "
                    "thing to be worked around rather than obeyed",
                )

        # 3. And the reach survives the tightening, or (2) proves only that the
        # detector was switched off.
        self.assertEqual(
            len(entrypoint_sentences_that_act(
                "So the entrypoint order is: create the `eth0` connection profile, then "
                "`systemctl restart NetworkManager`, and the profile belongs to Task 2."
            )),
            1,
            "the detector no longer recognises the architecture note's own wording, so the "
            "two assertions above would pass on a detector that finds nothing",
        )

    def test_the_plan_records_that_the_active_connection_is_nms_own(self):
        """Task 3's first surprise, recorded where Task 3 will read it.

        On 24.04 and 26.04 the device comes up activated on a profile NetworkManager
        creates for itself, named `eth0` — not on `eth0-managed`. A DHCP scenario
        that reads `nmcli connection up eth0-managed` and then wonders why the lease
        belongs to a different profile has been given a fact for free.
        """
        self.assertIn("connected (externally)", self.plan)
        self.assertIn("eth0-managed", self.plan)
# The constructions that put an **action** on the image's entrypoint, spelled out
# rather than inferred.
#
# ## The contract: a hit is a REVIEW ITEM, not a defect
#
# This detector reads prose, and the branch below reads it badly on purpose in one
# narrow way: it does **not** model negation. A sentence that names the entrypoint
# and then denies it does the work is flagged, because denying negation generally in
# a regex over English is a losing game. The plan's own correct sentences pass
# because of the *phrasings they happen to use*, not because the detector can tell
# right from wrong, and the next reader needs that here rather than in a report that
# lives outside version control.
#
# So: a hit is something to **read and judge**, and the case that uses this reports
# them in full rather than a count. Two live false positives are pinned as controls
# -- a correct sentence about the unit that the naive version of this branch reports,
# and a sentence that says the entrypoint's order is *not* the order -- so the
# detector's reach is bounded by something other than hope. If this ever gets noisy
# enough to be ignored, the fix is a narrower branch and a new control, not a
# quieter assertion.
#
# Inferred was the first attempt and it did not work, which is worth recording: the
# rule has to tell a prescriptive sentence from the plan's *correct* sentences about
# the entrypoint, and all of them mention it. The correct ones are negative or
# past-tense -- "an entrypoint that ran these commands itself would fail its first
# one" -- while the stale ones are present-tense or imperative.
ACTION_VERB = re.compile(
    r"\b(?:creat|run|perform|execut|restart|set)\w*\b", re.IGNORECASE
)
# "created here, in the image's entrypoint" -- an action located in the entrypoint.
# It needs an action verb in the same sentence, or it would also catch the plan's
# correct "nmcli cannot answer in the entrypoint", which is the opposite claim.
IN_THE_ENTRYPOINT = re.compile(
    r"in the (?:image's |target's )?entrypoint\b", re.IGNORECASE
)
# "The entrypoint must then fail loudly" -- a prescription about the entrypoint.
ENTRYPOINT_MUST = re.compile(r"\bentrypoint\b[^.]{0,40}?\bmust\b", re.IGNORECASE)
# "the entrypoint creates the profile" -- the entrypoint as the subject of a verb.
ENTRYPOINT_IS_THE_SUBJECT = re.compile(
    r"\bentrypoint\s+(?:creates?|runs|performs|executes)\b", re.IGNORECASE
)
# **The data form: the entrypoint named as the thing whose ORDER is being given.**
# "So the entrypoint order is: create the `eth0` connection profile, then `nmcli
# device set eth0 managed yes`, then `systemctl restart NetworkManager`" -- no
# prepositional phrase about the entrypoint, no "must", no entrypoint as the subject
# of a verb. It is the shape the architecture note used, and it was outside all three
# other branches, so the detector reported the plan clean while the sentence every
# task brief derives from assigned the sequence to the entrypoint.
#
# **One alternative, and the other two are gone.** It used to have three:
#
#   * a third alternative requiring the literal `eth0` between `the` and `connection`
#     -- which **could never fire**, because the caller replaces inline-code spans
#     before matching and the plan always backticks `eth0` (raw 1, post-strip 0), and
#     which was the only alternative that flagged a *correct* sentence: "the unit
#     creates the eth0 connection profile" mentions no entrypoint at all. It was
#     dead code with a false-positive future, and dropping it is the honest fix;
#   * an `entrypoint <verb>` alternative that was **entirely redundant** with
#     `ENTRYPOINT_IS_THE_SUBJECT` above and with the `must` in `ENTRYPOINT_MUST`,
#     which between them cover every string it matched.
#
# What is left is the one thing the branch is for: a sentence that gives the
# entrypoint an ordered set of actions. The head noun may carry an adjective --
# "the entrypoint order", "the entrypoint boot sequence" -- because the first plant
# for this branch used the second form and the branch did not match it, which is the
# same lesson as the dead alternative in the other direction: a pattern nobody
# exercised is a pattern whose reach is unknown.
#
# The copula is required, and the one negation the branch handles is a single
# lookahead: "the entrypoint order **is not** the unit's order" is a denial, and it
# was a live false positive.
ENTRYPOINT_OWNS_AN_ORDER = re.compile(
    r"\bentrypoint(?:'s)?\s+(?:\w+\s+){0,2}(?:order|sequence|steps|boot)\b"
    r"\s+(?:is|are|was|were)\b(?!\s*(?:not\b|n't\b))",
    re.IGNORECASE,
)


def entrypoint_sentences_that_act(text: str) -> list[str]:
    """The sentences of `text` that give the image's entrypoint an action to take.

    **A hit is a review item, not a defect.** See the note above
    `ENTRYPOINT_OWNS_AN_ORDER`: this reads prose and does not model negation, so
    what it returns is a list for a person to read. It is reported in full rather
    than as a count, because a count would hide which sentence fired.

    Sentence-shaped on purpose, so a report quotes the whole instruction an
    implementer would follow rather than a bare match. Inline-code spans are
    replaced first, because a sentence is delimited by a full stop and
    `/etc/NetworkManager/conf.d/10-mosdns-target.conf` is full of them -- and the
    replacement is a code span too, so the boundaries still come from the prose.
    That replacement is also why no pattern below may require a name from inside a
    backtick span: it will never see one.
    """
    stripped = re.sub(r"`[^`]*`", " `` ", text)
    acted = []
    for sentence in re.split(r"(?<=\.)\s+", stripped):
        if (
            IN_THE_ENTRYPOINT.search(sentence) and ACTION_VERB.search(sentence)
        ) or (
            ENTRYPOINT_OWNS_AN_ORDER.search(sentence) and ACTION_VERB.search(sentence)
        ) or ENTRYPOINT_MUST.search(sentence) or ENTRYPOINT_IS_THE_SUBJECT.search(
            sentence
        ):
            acted.append(" ".join(sentence.split()))
    return acted


def _gate_line(gate: str) -> str:
    """The one conditional of a setup script, for a failure message.

    The whole flattened script is several hundred characters of unrelated `echo`,
    so quoting it in an assertion failure buries the two words that matter. The
    conditional is the sentence a reader needs.
    """
    for fragment in gate.split(" if "):
        if "-ge" in fragment and "nm_minor" in fragment:
            return "if " + fragment.split("; then")[0] + "; then"
    return gate[:120]


class CopySourceTest(unittest.TestCase):
    """Every `COPY` names a file that is in the repository.

    A Containerfile is built with the repository as its context, so a `COPY` path
    is relative to the repository root -- not to the Containerfile's own
    directory, which is where a Containerfile's author naturally writes it. The
    failure is loud (`Error: building at STEP "COPY …": copier: stat: "…": no
    such file or directory`, measured) but it is loud only at the last step of a
    build that has already installed a systemd and NetworkManager, so a case that
    checks the paths costs nothing and saves that build.
    """

    def copy_sources(self, text: str) -> list[str]:
        found = []
        for line in folded_lines(text):
            if not line.startswith("COPY "):
                continue
            parts = line.split()[1:]
            for index, token in enumerate(parts):
                if token.startswith("--from="):
                    continue
                if not token.startswith("/") and not token.startswith("."):
                    found.append(token)
        return found

    def test_every_copy_source_exists_in_the_repository(self):
        for containerfile in (TARGET_CONTAINERFILE, MOCK_ROUTER_CONTAINERFILE, MOCK_CDN_CONTAINERFILE):
            for source in self.copy_sources(read(containerfile)):
                with self.subTest(containerfile=containerfile.name, source=source):
                    if "*" in source:
                        continue
                    self.assertTrue(
                        (REPO / source).exists(),
                        f"{containerfile.name} copies {source!r}, which is not in the repository. "
                        f"A build's context is the repository root, not the Containerfile's "
                        f"directory",
                    )

    def test_the_copy_check_sees_a_source_that_is_not_there(self):
        """The control: the check has to be able to fail.

        `COPY target-nm-setup.sh` is the exact mistake this task made, and it is
        why the case exists. Asserted on a Containerfile that really does name a
        file the repository does not have.
        """
        self.assertEqual(
            self.copy_sources("FROM ubuntu:24.04\nCOPY target-nm-setup.sh /usr/local/bin/x\n"),
            ["target-nm-setup.sh"],
        )
        self.assertFalse((REPO / "target-nm-setup.sh").exists())

    def test_a_copy_from_another_stage_is_not_a_path_in_the_repository(self):
        """`COPY --from=build …` reads a stage, not the context.

        A case that required every COPY's first token to exist in the repository
        would fail on a perfectly good multi-stage build -- and would be deleted
        the first time somebody wrote one, which is the fate of a guard that
        cannot tell the difference between two things.
        """
        self.assertEqual(
            self.copy_sources("FROM ubuntu:24.04 AS build\nFROM ubuntu:24.04\nCOPY --from=build /out/x /usr/bin/x\n"),
            [],
        )
class LockSchemaTest(unittest.TestCase):
    """The file's shape, because a lock that cannot be read cannot be used."""

    def test_it_is_valid_json_with_a_schema_and_the_images(self):
        """Parsed, not read as text: `json.tool` is a gate and a reader is a parser."""
        document = json.loads(read(LOCK))
        self.assertEqual(document["schema"], images.SCHEMA)
        self.assertIn("images", document)

    def test_the_image_references_name_the_official_ubuntu_repository(self):
        """`docker.io/library/ubuntu`, which is what the digests were pulled from.

        A digest is a hash of one particular manifest in one particular
        repository; naming a different repository's tag with it is a reference
        that resolves to something else, or to nothing.
        """
        lock = images.load_lock(LOCK)
        for version, entry in sorted(lock["images"].items()):
            with self.subTest(version=version):
                self.assertEqual(
                    images.base_image_reference(entry, version),
                    f"docker.io/library/ubuntu:{version}@{entry['digest']}",
                )

    def test_a_version_key_that_is_not_a_release_is_refused(self):
        """`24.4` is a typo, and a lock that accepted it would fail at pull time.

        A cell for a version nobody ships produces a report row with a
        requirement string naming a release that does not exist. The shape is
        checked where the key is read, so a `--versions 24.4` fails with the
        version in the message rather than at `podman build`.
        """
        for bad in ("24.4", "24", "24.04.1", "latest", ""):
            with self.subTest(version=bad):
                with self.assertRaises(images.LockError) as caught:
                    images.base_image_reference({"digest": "sha256:" + "c" * 64}, bad)
                self.assertIn(repr(bad), str(caught.exception))

    def test_every_package_the_images_install_exists_on_every_locked_release(self):
        """The build has to work on 22.04, 24.04 *and* 26.04.

        **Found by building.** The first version of the target Containerfile named
        `systemd-resolved`, and the 22.04 build failed with `E: Unable to locate
        package systemd-resolved`: it is a binary package on 24.04 and 26.04 and
        does not exist on 22.04, where the daemon is part of `systemd`. A
        Containerfile that installs a package only two of the three releases have
        is a matrix that is one third shorter than it claims, and the failure
        arrives as a build error naming a package rather than as a report row.

        So this asks each locked image's own apt, per release, for every package
        the three Containerfiles install. It is the one case in the file that
        needs a registry and a package archive, and it skips -- saying what it did
        not check -- when it cannot ask.
        """
        import subprocess

        wanted = sorted(
            {
                package
                for containerfile in containerfiles()
                for package in installed_packages(read(containerfile))
            }
        )
        self.assertTrue(
            wanted,
            "no image installs anything, so this check would pass on an empty set and say "
            "nothing about package availability",
        )
        for version, entry in sorted(images.load_lock(LOCK)["images"].items()):
            if entry.get("unavailable"):
                continue
            reference = images.base_image_reference(entry, version)
            probe = (
                "apt-get update -qq >/dev/null 2>&1; "
                + " ".join(f"apt-cache show {package} >/dev/null 2>&1 || echo MISSING:{package};" for package in wanted)
                + " true"
            )
            completed = subprocess.run(
                ["podman", "run", "--rm", reference, "sh", "-c", probe],
                capture_output=True,
                text=True,
                timeout=900,
            )
            if completed.returncode != 0 and looks_like_no_registry(completed.stderr):
                self.skipTest(
                    f"{version} could not be run here, so the package list was NOT verified on "
                    f"that release: {completed.stderr.strip()[:200]}"
                )
            self.assertEqual(
                completed.returncode, 0, f"{version} could not be run: {completed.stderr.strip()[-200:]}"
            )
            missing = [
                line.split(":", 1)[1]
                for line in completed.stdout.splitlines()
                if line.startswith("MISSING:")
            ]
            self.assertEqual(
                missing, [],
                f"the images install {missing}, which {version} does not have",
            )

    def test_the_skip_detector_does_not_call_a_missing_manifest_a_network_problem(self):
        """The control for the skip rule the two verification cases use.

        A skip detector that also matched a manifest error would turn a
        fabricated or stale digest into a skip, and the run would report "no
        network" for an answer the registry gave. So a message naming a manifest
        is required NOT to be read as offline.
        """
        self.assertTrue(
            looks_like_no_registry(
                "Error: initializing source docker://docker.io/library/ubuntu:24.04: "
                "dial tcp: lookup docker.io: no such host"
            )
        )
        for answer in (
            "reading manifest sha256:aaaa: manifest unknown",
            "Error: initializing source: name unknown: Error reading manifest",
            "manifest for docker.io/library/ubuntu@sha256:bbbb not found",
        ):
            with self.subTest(answer=answer):
                self.assertFalse(
                    looks_like_no_registry(answer),
                    "a message naming a manifest is the registry's answer, not an offline host",
                )

    def test_it_names_the_architecture_the_digests_are_for(self):
        """The digests are amd64, resolved on this host, and saying so is required.

        A digest is per-architecture. A lock that did not say which one it pinned
        would be read as pinning all of them, and an arm64 run would pull a
        manifest the harness never verified.
        """
        self.assertIn("arch", json.loads(read(LOCK)))
class ImageDigestVerificationTest(unittest.TestCase):
    """The digests are real, and the proof is that the registry still serves them.

    A digest nobody pulled is indistinguishable from one that was, by inspection:
    both match `sha256:` and both are 64 hex characters. So this case asks the
    registry, and it is the only case in the file that needs a network.

    Skipped -- never failed -- when there is no registry to ask, because a test
    suite that turns red because the operator is offline is a suite that gets
    muted. The skip says what it did not check, so the absence of the check is
    visible in the output rather than silent.
    """

    def test_every_locked_digest_is_still_served_by_the_registry(self):
        """Ask the registry for the manifest, from a `podman build` of nothing.

        The reference is checked by *building* it, because that is what a real
        build does with it and because it is the only form that exercises the
        whole reference: `podman manifest inspect` refuses a reference carrying
        both a tag and a digest (measured: `Error: Docker references with both a
        tag and digest are currently not supported`), so a case that used it
        would have been checking a different string than the one a build gets.
        """
        import subprocess
        import tempfile

        for version, entry in sorted(images.load_lock(LOCK)["images"].items()):
            with self.subTest(version=version):
                if entry.get("unavailable"):
                    self.skipTest(f"{version} is recorded unavailable: {entry['unavailable']}")
                reference = images.base_image_reference(entry, version)
                tag = f"mosdns-lockprobe-{version.replace('.', '')}"
                # The probe image is removed whether the case passes or fails. A
                # verification that leaves an image behind is a verification the
                # next run pays for, and three of them a day is a disk.
                self.addCleanup(
                    subprocess.run,
                    ["podman", "rmi", "-f", tag],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                with tempfile.TemporaryDirectory() as scratch:
                    containerfile = Path(scratch) / "Containerfile"
                    containerfile.write_text(
                        f"ARG BASE_IMAGE\nFROM ${{BASE_IMAGE}}\n", encoding="utf-8"
                    )
                    completed = subprocess.run(
                        [
                            "podman", "build", "-f", str(containerfile),
                            "-t", tag,
                            "--build-arg", f"BASE_IMAGE={reference}", scratch,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=900,
                    )
                if completed.returncode != 0 and looks_like_no_registry(completed.stderr):
                    self.skipTest(
                        f"the registry could not be asked about {version}, so the digest was "
                        f"NOT verified in this run: {completed.stderr.strip()[:200]}"
                    )
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"{reference} cannot be built from, so the lock is stale and a build would "
                    f"fail: {completed.stderr.strip()[-300:]}",
                )

    def test_the_lock_names_the_release_it_thinks_it_pinned(self):
        """`ubuntu:26.04` really is 26.04, and not a tag that means something else.

        The check is the image's own `/etc/os-release`, read from a throwaway
        container of the locked digest. A `26.04` tag that resolved to a
        different release would make every cell of the matrix mislabelled, and
        nothing downstream could tell.
        """
        import subprocess

        for version, entry in sorted(images.load_lock(LOCK)["images"].items()):
            with self.subTest(version=version):
                if entry.get("unavailable"):
                    self.skipTest(f"{version} is recorded unavailable")
                reference = images.base_image_reference(entry, version)
                completed = subprocess.run(
                    [
                        "podman", "run", "--rm", "--network", "none", reference,
                        "sh", "-c", '. /etc/os-release; printf "%s" "$VERSION_ID"',
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if completed.returncode != 0 and looks_like_no_registry(completed.stderr):
                    self.skipTest(
                        f"the image for {version} could not be pulled here, so its VERSION_ID was "
                        f"NOT verified in this run: {completed.stderr.strip()[:200]}"
                    )
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"{reference} could not be run: {completed.stderr.strip()[-200:]}",
                )
                # VERSION_ID carries the point release -- `26.04.1` for the
                # 26.04 tag -- so this is a prefix test on the release the
                # operator asked for, not an equality against the tag. A tag that
                # resolved to a *different* release still fails it.
                reported = completed.stdout.strip()
                self.assertTrue(
                    reported == version or reported.startswith(version + "."),
                    f"the tag ubuntu:{version} serves VERSION_ID={reported!r}, which is a "
                    f"different release than the one the matrix is testing",
                )


if __name__ == "__main__":
    unittest.main()
class ImageHandsOverToSystemdTest(unittest.TestCase):
    """The image's own boot path: entrypoint, and where the sequence runs.

    These three are about the *image's files* rather than about what the setup
    script does when it runs, so they do not need the modelled `nmcli` and
    `systemctl` at all -- and they were here by accident, inheriting the harness
    below for nothing.

    They were in the wrong class for a second reason that is the one this file's
    suite-shape guard now refuses: `SetupScriptTestCase` has three subclasses, and
    a case in a base runs once per subclass. So each of these ran four times, under
    four different sets of dials, while the base's own docstring said the cases were
    not inherited. The dials do not reach this far -- the assertions read files and
    never call `run_setup` -- which is exactly why the duplication was invisible and
    why the run count alone could not have found it.
    """

    def test_the_entrypoint_hands_over_to_systemd(self):
        """`exec` into the init, so it becomes PID 1.

        Without the `exec`, the shell stays PID 1 and systemd is a child, which
        is the shape that makes `--systemd=always` a no-op: a target whose units
        systemd "started" are not managed by a PID 1 systemd at all, and
        `systemctl` answers to the child.
        """
        text = read(ENTRYPOINT)
        self.assertRegex(text, r"exec\s+/sbin/init|exec\s+.*init")

    def test_the_entrypoint_does_not_perform_the_sequence_itself(self):
        """The sequence runs once, from systemd, and not twice.

        An entrypoint that also ran the three steps would do them before
        `/sbin/init` exists -- before there is a D-Bus for `nmcli` to talk to.
        Measured in this session, on the real image, for the entrypoint that
        tried: `Error: Could not create NMClient object: Could not connect: No such
        file or directory`, and `GENERAL.NM-MANAGED` stayed `no`.

        The case reads the entrypoint's **instructions**, not its text: the file
        quotes that error and names all three commands in the comment explaining
        why it does not run them, and a case that read the prose would fail on
        the explanation.
        """
        instructions = " ".join(shell_statements(ENTRYPOINT))
        for command in ("nmcli", "systemctl", "device set", "connection add"):
            with self.subTest(command=command):
                self.assertNotIn(command, instructions)

    def test_the_setup_is_installed_as_a_unit_the_image_enables(self):
        """The sequence is part of the image's boot, not of a scenario.

        A sequence a scenario ran would leave the window where the target is
        unmanaged open to the first scenario, and the plan's whole correction --
        that the profile must exist *before* the steps -- only holds if the steps
        run once, at boot, in order.
        """
        text = read(TARGET_CONTAINERFILE)
        self.assertIn("target-nm-setup.service", text)
        self.assertRegex(text, r"systemctl\s+enable\s+.*target-nm-setup")


class SetupScriptTestCase(unittest.TestCase):
    """A real `sh`, a model of `nmcli` and `systemctl`, and a trace to read.

    Everything that tests the target's setup executes the *real* script against
    the modelled tools. That is possible -- and necessary -- because the sequence
    is the load-bearing measured fact of this plan and a case that only found the
    words in a file would not notice them in the wrong order.

    Three classes use it and they ask different questions of the same script, so the
    harness is here and the cases are not inherited: an ordering question and a
    version-gate question have opposite dials, and inheriting would run each case
    once per subclass, under dials that make it vacuous.

    **It carries no cases, and that is a rule rather than a habit.** A base that
    declares a case has it run once per subclass, so three cases in a base with three
    subclasses run nine times more than they were written -- and this class did
    exactly that until `test_no_class_in_this_tree_silently_inherits_a_class_that_carries_cases`
    in `test_suite_shape.py` reported it. The three cases that were here read the
    image's files and needed no harness; they are `ImageHandsOverToSystemdTest` now.
    """

    # -- a model of the two tools -------------------------------------------

    NMCLI_MODEL = '''#!/bin/sh
# A model of the `nmcli` calls the target's setup makes, in the shape the real
# ones have. State lives in $NM_STATE and every call is appended to $NM_TRACE as
# the full expanded command line, so a case reads the *order the commands were
# run in* rather than the order they appear in a file.
#
# Three behaviours this models that a naive model would get wrong, and which are
# the whole reason the setup is worth testing:
#
#   1. `nmcli device set eth0 managed yes` **returns success whether or not a
#      connection profile exists for the device.** Measured: with no profile the
#      audit log records `op="device-managed" ... result="success"` and
#      `GENERAL.NM-MANAGED` is still `no` after the restart. A model that made
#      `device set` fail without a profile would make the ordering test pass for
#      the wrong reason.
#   2. The persistent device override exists **only from NetworkManager 1.44** —
#      measured `no` at 1.36.6 (22.04) and 1.42.4 (23.04) and `yes` at 1.44.2
#      (23.10), 1.46.0 (24.04) and 1.54.3 (26.04). Below the boundary the
#      override is never written, whatever `device set` answers.
#   3. The conf.d declaration is a *mechanism that can fail silently*: the file is
#      written, NetworkManager reads it, and the field is still `no`. A model in
#      which the declaration always worked would make the boot check
#      untestable, which is the one thing the ruling asks it to be.
#
# The two dials a case sets, both by environment:
#
#   NM_VERSION      the `nmcli --version` the model answers. Default 1.46.0.
#   NM_DECLARED     `yes` (default) the conf.d declaration took effect and the
#                   device is managed from the moment the daemon answers;
#                   `ineffective` the declaration is present and ignored, which is
#                   what a target on a release where the selector does not match
#                   looks like.
state="${NM_STATE:?}"
trace="${NM_TRACE:?}"
echo "nmcli $*" >> "$trace"
version="${NM_VERSION:-1.46.0}"
# The persistent device override arrived in 1.44. Measured on this host at 1.36.6,
# 1.42.4, 1.44.2, 1.46.0 and 1.54.3; the comparison is on major and minor only,
# because that is what was measured.
major="${version%%.*}"
rest="${version#*.}"
minor="${rest%%.*}"
if [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 44 ]; }; then
    has_override=yes
else
    has_override=no
fi
fields=""
while [ "$1" = "-g" ]; do fields="$2"; shift 2; done
verb="$1"; shift
case "$verb" in
  general)
    # The readiness probe the script makes before anything else. Answering it is
    # what "NetworkManager is up" means here.
    [ "$1" = "status" ] && exit 0
    echo "unmodelled: nmcli general $1" >&2; exit 64
    ;;
  --version)
    echo "nmcli tool, version $version"
    exit 0
    ;;
  connection)
    what="$1"; shift
    case "$what" in
      add)
        name=""
        prev=""
        for token in "$@"; do
          if [ "$prev" = "con-name" ]; then name="$token"; fi
          prev="$token"
        done
        if [ -f "$state/profile" ]; then
          echo "Error: connection with the name '$name' already exists." >&2
          exit 10
        fi
        printf '%s' "$name" > "$state/profile"
        echo "Connection '$name' (52663ce3-8787-46a8-a924-968cb4f12df0) successfully added."
        ;;
      show)
        if [ -f "$state/profile" ] && [ "$1" = "$(cat "$state/profile")" ]; then
          echo "connection.id: $1"
        else
          echo "Error: unknown connection '$1'" >&2
          exit 10
        fi
        ;;
      *) echo "unmodelled: nmcli connection $what" >&2; exit 64 ;;
    esac
    ;;
  device)
    what="$1"; shift
    case "$what" in
      set)
        # Success either way. That is the measured behaviour, and it is the
        # reason the profile has to come first: without one this writes nothing
        # the restart will re-read.
        if [ -f "$state/profile" ] && [ "$has_override" = yes ]; then
          echo yes > "$state/override"
        fi
        echo "Device '$1' state set to '$2'."
        ;;
      show)
        case "$fields" in
          GENERAL.NM-MANAGED)
            # The field reads what NetworkManager has *read*, not what has been
            # written: the override only takes effect when a restart re-reads it,
            # and until then the file on disk is exactly what the plan says it is
            # -- present, and not yet in force. So `$state/override` is not
            # consulted here, only `$state/managed` (written by the restart) and
            # the declaration.
            if [ -f "$state/managed" ]; then
              cat "$state/managed"
            elif [ "${NM_DECLARED:-yes}" = yes ]; then
              echo yes
            else
              echo no
            fi
            ;;
          GENERAL.TYPE)
            echo "${NM_TYPE:-ethernet}"
            ;;
          GENERAL.CONNECTION)
            echo "${NM_ACTIVE_CONNECTION:-eth0}"
            ;;
          *) echo "unmodelled field: $fields" >&2; exit 64 ;;
        esac
        ;;
      *) echo "unmodelled: nmcli device $what" >&2; exit 64 ;;
    esac
    ;;
  *) echo "unmodelled: nmcli $verb" >&2; exit 64 ;;
esac
'''

    SYSTEMCTL_MODEL = '''#!/bin/sh
# A model of `systemctl restart NetworkManager` and nothing else. The restart is
# the step that re-reads the override under /run/NetworkManager/devices/, so a
# model without it cannot tell a correct setup from one that forgot it -- which
# is the second of the three mutations the suite applies.
#
# The re-read happens only when an override was actually written, and an override
# is written only when a connection profile existed for the device at the moment
# `device set` ran. That is the measured behaviour, and it is the whole reason the
# profile step has to come first.
state="${NM_STATE:?}"
trace="${NM_TRACE:?}"
echo "systemctl $*" >> "$trace"
if [ "$1" = "restart" ] && [ "$2" = "NetworkManager" ]; then
  # The restart re-reads the override, and only the override. Below 1.44 no
  # override is ever written, so the restart changes nothing at all -- measured:
  # on 1.36 the field holds whatever the declaration says, before and after.
  # Modelling it as "a restart with no override sets the field to no" would make
  # a working declaration look like the restart's victim, which is not what
  # happens, and the control case in DeclarationHoldsHonestTest would fail for
  # a reason in the model rather than in the script.
  [ -f "$state/override" ] && cp "$state/override" "$state/managed"
  exit 0
fi
echo "unmodelled: systemctl $*" >&2
exit 64
'''

    def setUp(self):
        self.state = None

    def _tmpdir(self):
        import tempfile

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return directory.name

    def _tool(self, name: str, model: str) -> Path:
        directory = Path(self._tmpdir()) / "bin"
        directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text(model, encoding="utf-8")
        path.chmod(0o755)
        return path

    # The dials every case in this class runs with, and why they are the safe
    # direction.
    #
    # `NM_DECLARED=ineffective` makes the conf.d declaration *not* take effect, so
    # the only thing in the model that can make `GENERAL.NM-MANAGED` read `yes`
    # is the sequence -- in the order this class checks. That is what stops the
    # ordering assertions from being vacuous: with a working declaration the
    # field is `yes` from the moment the daemon answers, every case would pass,
    # and the class would be a test of the word "yes".
    #
    # `NM_VERSION=1.46.0` is the lowest release on the matrix that *has* the
    # persistent device override, so the two commands under test actually run. A
    # higher version would also do; a lower one would skip them and the trace
    # assertions below would fail, which is the point of the assertions.
    ORDER_DIALS = {"NM_VERSION": "1.46.0", "NM_DECLARED": "ineffective"}

    def run_setup(self, script: Path, **dials):
        """Run a setup script with the modelled tools on PATH, and read the trace back.

        A **fresh** state directory per call, not one per test. The model's
        `managed` and `override` files are what the sequence writes and the check
        reads, so two runs sharing one state directory see each other's answer --
        and a case that ran the correct script first and a mutation second would
        read the first run's `yes` and pass a mutation that ought to fail. That is
        exactly the shape of a control that cannot fail, so the state is per run.

        `dials` are the model's environment: `NM_VERSION` for the
        `nmcli --version` it answers, and `NM_DECLARED` for whether the conf.d
        declaration took effect.
        """
        import os
        import subprocess

        self.state = Path(self._tmpdir()) / "state"
        self.state.mkdir(parents=True)
        tools = Path(self._tmpdir()) / "bin"
        tools.mkdir(exist_ok=True)
        (tools / "nmcli").write_text(self.NMCLI_MODEL, encoding="utf-8")
        (tools / "systemctl").write_text(self.SYSTEMCTL_MODEL, encoding="utf-8")
        for tool in tools.iterdir():
            tool.chmod(0o755)
        trace = tools / "trace"
        trace.write_text("", encoding="utf-8")
        environment = dict(os.environ)
        environment["PATH"] = f"{tools}:{environment['PATH']}"
        environment["NM_STATE"] = str(self.state)
        environment["NM_TRACE"] = str(trace)
        environment.update({key: str(value) for key, value in dials.items()})
        completed = subprocess.run(
            ["sh", str(script)],
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
        )
        return completed, [line for line in trace.read_text(encoding="utf-8").splitlines() if line]

    def nm_managed(self) -> str:
        return (self.state / "managed").read_text(encoding="utf-8").strip() if (self.state / "managed").exists() else "absent"

    def profile_exists(self) -> bool:
        return (self.state / "profile").exists()

    # -- the mutations --------------------------------------------------------

    def _write_variant(self, lines: list[str], name: str) -> Path:
        directory = Path(self._tmpdir()) / name
        directory.mkdir(exist_ok=True)
        path = directory / "target-nm-setup.sh"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def reorder(self, script: Path) -> Path:
        """A copy with the profile step moved to just after the restart.

        Three things had to be got right, and each of them was got wrong first --
        which is why they are written down rather than left in the code:

        * **instructions, not text.** The profile step is named in this file's
          own comments, and a helper that searches the raw text finds the comment
          first and moves *that*, leaving the script unchanged. Every mutation in
          this class runs on `shell_statements`, which is comments-stripped.
        * **the index is recomputed after the pop.** The profile step is *before*
          the restart in a correct script, so removing it shifts every later index
          down by one, and inserting at the pre-pop index puts the line straight
          back.
        * **the whole `if … fi` block moves, not just the add.** The add is inside
          a guard (`if ! nmcli connection show …; then`), and moving the one line
          would leave a guard whose body is gone -- a different script, failing
          for a reason that has nothing to do with the ordering.
        """
        statements = shell_statements(script)
        block_start = next(
            i for i, line in enumerate(statements) if "nmcli connection add" in line
        )
        guard = next(
            (
                i
                for i in range(block_start - 1, -1, -1)
                if statements[i].startswith(("if ", "if!", "if\t"))
            ),
            block_start,
        )
        end = next(
            (i for i in range(block_start + 1, len(statements)) if statements[i] == "fi"),
            block_start,
        )
        restart = next(
            i
            for i, line in enumerate(statements)
            if line.startswith("systemctl restart NetworkManager")
        )
        block = statements[guard : end + 1]
        remainder = statements[:guard] + statements[end + 1 :]
        shifted = restart - 1 if guard < restart else restart
        return self._write_variant(remainder[: shifted + 1] + block + remainder[shifted + 1 :], "reordered")

    def drop_line(self, script: Path, needle: str) -> Path:
        """A copy with the instruction containing `needle` removed."""
        statements = [
            line
            for line in shell_statements(script)
            if not (needle in line and not line.startswith("#"))
        ]
        return self._write_variant(statements, "dropped")



    # -- the cases ------------------------------------------------------------


class EntryPointOrderTest(SetupScriptTestCase):
    """The NetworkManager sequence, run, and required to be in this order.

    Every case here runs with `ORDER_DIALS`, which makes the sequence the only
    mechanism that can produce `yes` -- so an assertion about the order cannot be
    satisfied by the conf.d declaration alone. Each case asserts the three commands
    were actually invoked before it compares their positions, because an index into
    a trace that does not contain the lines is a comparison of nothing.
    """

    # -- the cases ------------------------------------------------------------

    def test_the_script_exists_and_is_executable_shape(self):
        """A `sh` script with a shebang, so it can be both run here and `COPY`ed in.

        Not a "it runs" case: this asserts the *form*, because the file is copied
        into the image and executed as PID 1's entry, and a file without a
        shebang is not that.
        """
        text = read(NM_SETUP)
        self.assertTrue(text.startswith("#!/bin/sh"), text[:40])
        self.assertIn("set -e", text)

    def test_the_three_commands_are_in_this_order(self):
        """**The case this task exists for.**

        The order is not a style preference. Measured, twice in this plan: with
        the profile first, the three commands take `GENERAL.NM-MANAGED` to
        `yes`; with it last, the `device set` is accepted, the restart happens,
        and the field stays `no` -- so a target boots unmanaged, every scenario
        fails for a reason that has nothing to do with the package, and the whole
        matrix is `incomplete` with exit 3.

        Read off the **trace**, not the file: the case requires the calls in the
        order the model recorded them, which is the order they were actually run
        in. A script with the three commands in the right order and something
        else before them would still pass this, and the next case is what holds
        that.
        """
        completed, trace = self.run_setup(NM_SETUP, **self.ORDER_DIALS)
        self.assertEqual(
            completed.returncode,
            0,
            f"the setup script failed:\n{completed.stdout}\n{completed.stderr}",
        )
        # The ordering below is only meaningful if the three commands ran. With a
        # working declaration they need not, and every index below would compare
        # the wrong lines -- so their presence is asserted first.
        self.assertIn("nmcli connection add", " ".join(trace), trace)
        self.assertIn("nmcli device set", " ".join(trace), trace)
        self.assertIn("systemctl restart NetworkManager", " ".join(trace), trace)
        profile = [i for i, line in enumerate(trace) if "connection add" in line]
        override = [i for i, line in enumerate(trace) if "device set" in line]
        restart = [i for i, line in enumerate(trace) if "systemctl restart" in line]
        self.assertEqual(len(profile), 1, trace)
        self.assertEqual(len(override), 1, trace)
        self.assertEqual(len(restart), 1, trace)
        self.assertLess(
            profile[0],
            override[0],
            f"the profile must be created before the override; the trace was {trace}",
        )
        self.assertLess(
            override[0],
            restart[0],
            f"the override must be set before the restart re-reads it; the trace was {trace}",
        )

    def test_the_commands_are_the_three_the_plan_names(self):
        """The exact spellings, verbatim -- read off the trace, not the file.

        The script writes `"$DEVICE"` and `"$PROFILE"` where the commands are, so
        the *expanded* commands are what matter and what the model recorded. A
        `nmcli device set eth0 managed no` in the same position would satisfy
        the ordering case and unmanage every target; `systemctl restart
        systemd-networkd` would satisfy it and do nothing.
        """
        completed, trace = self.run_setup(NM_SETUP, **self.ORDER_DIALS)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "nmcli connection add type ethernet ifname eth0 con-name eth0-managed ipv4.method auto",
            " ".join(trace),
        )
        self.assertIn("nmcli device set eth0 managed yes", trace)
        self.assertIn("systemctl restart NetworkManager", trace)

    def test_it_fails_loudly_when_the_field_is_not_yes(self):
        """A boot that cannot be measured must stop, and must say what it saw.

        Silently continuing is the failure this rule exists for: every scenario
        downstream then fails against an unmanaged device, and the failure reads
        like an installer bug in a package that has not been installed yet.
        """
        text = read(NM_SETUP)
        self.assertIn("GENERAL.NM-MANAGED", text)
        self.assertIn("yes", text)
        self.assertRegex(text, r"exit 1|return 1|false")

    def test_the_failure_message_names_the_profile_and_the_observed_value(self):
        """Both facts, not a bare "unmanaged".

        A message that says only `NM-MANAGED is no` sends the reader to the
        two-step sequence that the plan already measured as insufficient on its
        own -- they run it, it succeeds, and they conclude the harness is wrong.
        The profile is the part that is easy to forget.
        """
        text = read(NM_SETUP)
        self.assertIn("eth0-managed", text)
        self.assertIn("connection profile", text.lower())

    def test_the_failure_message_names_the_networkmanager_version(self):
        """**Measured: the two failures are identical from the outside and have different causes.**

        On 24.04 and 26.04 the override is written under
        `/run/NetworkManager/devices/` and the restart re-reads it, so a `no` means
        the restart did not happen. On 22.04 (nmcli 1.36) there is no persistent
        device override at all: the field stays `no` with or without a profile and
        with or without a restart, and no change to this script can alter it.

        A reader who is told "restart" on 22.04 checks the restart, finds it
        happened, and has been sent looking at the wrong thing. So the message
        carries the version, which is the one fact that distinguishes the two
        causes, and it names the file to read to tell them apart.
        """
        completed, _ = self.run_setup(NM_SETUP, **self.ORDER_DIALS)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        # With the override dropped the field reads `no`, and the message has to
        # carry both the observed value and the version. The dials matter: with a
        # *working* declaration the field is `yes` either way and dropping the
        # restart would be invisible, so the case would be asserting nothing.
        dropped = self.drop_line(NM_SETUP, "systemctl restart NetworkManager")
        completed, _ = self.run_setup(dropped, **self.ORDER_DIALS)
        self.assertNotEqual(completed.returncode, 0)
        message = completed.stdout + completed.stderr
        self.assertIn("nmcli", message)
        self.assertIn(GENERAL_MANAGED_FIELD, message)

    def test_the_setup_script_declares_the_device_managed_rather_than_only_sequencing(self):
        """**Superseded case, replaced by the ruling.** The old version of this
        case asserted the setup script contained no `conf.d` entry, which was the
        plan's instruction before the 22.04 measurement falsified its premise.

        The property that replaced it is narrower and is the one that matters: the
        *script* does not declare anything, because a daemon reads its
        configuration from files and not from a shell script. The declaration lives
        in one place — `images/10-mosdns-target.conf`, `COPY`ed into `conf.d/` —
        and `ManagedDeclarationTest` holds that. What the script must not do is
        declare it a *second* time, by writing the snippet itself.
        """
        instructions = shell_statements(NM_SETUP)
        # Matched on the *assignment*, not on the key: the boot check's message
        # quotes 'except:interface-name:' to point the reader at the file, and a
        # filter on the key alone reports the message as a second declaration.
        writers = [
            line for line in instructions if "unmanaged-devices=" in line
        ]
        self.assertEqual(
            writers,
            [],
            f"the setup script writes the declaration itself, so the image has two copies of it "
            f"that can disagree: {writers}",
        )
        # And the script has to *mention* it, because the boot check's message
        # points the reader at the file -- a message naming a file the image does
        # not ship is the failure this whole case family is about.
        text = read(NM_SETUP)
        self.assertIn("10-mosdns-target.conf", text)
        self.assertIn("except:interface-name:", text)

    def test_moving_the_profile_after_the_restart_makes_the_check_fail(self):
        """**The control, and the reason the case above is not a comment.**

        The same script with one edit: the profile is created *after* the restart.
        The model says the field is then `no` -- which is what was measured on
        this host -- and the setup must exit non-zero rather than hand a target
        to the scenarios. A test that only checked the good ordering would pass
        here too, and would be a test of the file's spelling.
        """
        reordered = self.reorder(NM_SETUP)
        completed, trace = self.run_setup(reordered, **self.ORDER_DIALS)
        self.assertNotEqual(
            completed.returncode,
            0,
            f"the check passed with the profile created after the restart; the trace was {trace}\n"
            f"{completed.stdout}\n{completed.stderr}",
        )
        self.assertIn("eth0-managed", str(completed.stderr) + completed.stdout)

    def test_dropping_the_restart_makes_the_check_fail(self):
        """The other of the two measured facts.

        `nmcli device set eth0 managed yes` returns success and does not take
        effect until NetworkManager re-reads the override. Without the restart
        the override is written and never read, the field stays `no`, and the
        setup must fail.
        """
        dropped = self.drop_line(NM_SETUP, "systemctl restart NetworkManager")
        completed, trace = self.run_setup(dropped, **self.ORDER_DIALS)
        self.assertNotEqual(
            completed.returncode,
            0,
            f"the check passed with the restart dropped; the trace was {trace}\n"
            f"{completed.stdout}\n{completed.stderr}",
        )

    def test_dropping_the_profile_makes_the_check_fail(self):
        """The third of the three, and the one the plan's architecture note is about.

        With no profile at all, both remaining steps are accepted, the audit log
        records `result="success"`, and the field stays `no`. This is what the
        plan measured on every container it tried, and it is why the profile
        belongs to this image's boot rather than to a later scenario.
        """
        dropped = self.drop_line(NM_SETUP, "nmcli connection add")
        completed, trace = self.run_setup(dropped, **self.ORDER_DIALS)
        self.assertNotEqual(
            completed.returncode,
            0,
            f"the check passed with the profile step dropped; the trace was {trace}\n"
            f"{completed.stdout}\n{completed.stderr}",
        )

    def test_reordering_needs_a_script_whose_profile_line_is_movable(self):
        """The control's own precondition, asserted where the control is used.

        `reorder` finds one profile line and one restart line and moves the first
        after the second. If either stopped being findable -- a rewrite, a
        variable, a loop -- the control would silently produce the *unmodified*
        script, the assertion above would pass for the wrong reason, and the
        defect it exists to catch would be reported as covered. So the mutation
        has to be shown to be a mutation, and it was shown to be a broken one
        here: an index computed before a `pop` puts the line back where it was.
        """
        original = read(NM_SETUP)
        reordered = self.reorder(NM_SETUP)
        mutated = read(reordered)
        self.assertNotEqual(mutated, original, "the mutation produced the unmodified script")
        self.assertLess(
            original.index("nmcli connection add"),
            original.index("systemctl restart NetworkManager"),
            "the shipped script already has the profile after the restart, so the control "
            "asserts nothing",
        )
        self.assertLess(
            mutated.index("systemctl restart NetworkManager"),
            mutated.index("nmcli connection add"),
            "the mutation did not move the profile after the restart",
        )
        # A move, not an edit: the same statements, the same count. The variant is
        # written from the comments-stripped statements (see `reorder`), so the
        # comparison is against those and not against the file's prose.
        self.assertEqual(
            sorted(mutated.splitlines()),
            sorted(shell_statements(NM_SETUP)),
            "the mutation changed the script rather than moving one part of it, so the case "
            "above is not testing the ordering",
        )
        self.assertEqual(
            len(mutated.splitlines()), len(shell_statements(NM_SETUP))
        )

class DeclarationHoldsHonestTest(SetupScriptTestCase):
    """The boot check does not trust the declaration. **The ruling's case.**

    The declaration is the *baseline*; the check is what keeps the baseline
    honest. A conf.d entry that is written, read, and does not take effect — a
    selector that does not match, a directory the daemon does not read, a distro
    that overrides it — must still fail the boot, or the image would hand an
    unmanaged device to every scenario and the failure would read like a bug in a
    package that is not installed yet.

    Both halves are held, because either alone proves nothing:

    * a declaration that did **not** take effect, on a release with no override
      to rescue it, must fail; and
    * a **working** field with **no** declaration at all must pass, which is the
      control: it shows the verdict comes from the observed field and not from
      the presence of a file.
    """

    def test_a_declaration_that_did_not_take_effect_fails_the_boot(self):
        completed, trace = self.run_setup(NM_SETUP, NM_VERSION="1.36.6", NM_DECLARED="ineffective")
        self.assertNotEqual(
            completed.returncode,
            0,
            "the setup booted with GENERAL.NM-MANAGED still 'no' after a declaration that did "
            f"not take effect; the trace was {trace}\n{completed.stdout}\n{completed.stderr}",
        )
        message = completed.stdout + completed.stderr
        self.assertIn(GENERAL_MANAGED_FIELD, message)
        self.assertIn("no", message)

    def test_a_managed_device_passes_without_the_sequence_having_run(self):
        """The control, and the reason the case above means anything.

        The same release with no override — the script skipped the two commands
        because 1.36 has no persistent device override — and a device the daemon
        is managing anyway, which is what a working conf.d declaration looks like.
        It passes, on the observed field. So the two cases differ in one thing, the
        field, and the verdict is the field.
        """
        completed, trace = self.run_setup(NM_SETUP, NM_VERSION="1.36.6", NM_DECLARED="yes")
        self.assertEqual(
            completed.returncode,
            0,
            "a target whose device is managed was refused:\n" + completed.stdout + completed.stderr,
        )
        self.assertNotIn(
            "nmcli device set",
            " ".join(trace),
            "the sequence ran on 1.36, so this is not the control it claims to be",
        )

    def test_the_check_asks_the_field_and_not_the_configuration(self):
        """A field of `no` is fatal even where the sequence *could* rescue it.

        The other direction, and the one that shows the check is not a version
        comparison in disguise: on 1.46 the sequence writes the override and the
        field becomes `yes`, so a run there passes; on the same 1.46, with the
        override not written because the profile step is gone, the field stays
        `no` and the boot must fail. The check cannot be satisfied by the script
        knowing which release it is on.
        """
        dropped = self.drop_line(NM_SETUP, "nmcli device set")
        completed, trace = self.run_setup(dropped, NM_VERSION="1.46.0", NM_DECLARED="ineffective")
        self.assertNotEqual(
            completed.returncode,
            0,
            f"the check passed with no override written and the declaration ineffective; "
            f"the trace was {trace}",
        )
        # And with the override written the same version passes, so the two differ
        # only in the field.
        worked, _ = self.run_setup(NM_SETUP, NM_VERSION="1.46.0", NM_DECLARED="ineffective")
        self.assertEqual(worked.returncode, 0, worked.stdout + worked.stderr)
class OverrideVersionGateTest(SetupScriptTestCase):
    """The `device set` + restart are gated on the measured NetworkManager boundary.

    Measured on this host, with a connection profile present — the profile-first
    precondition, which one of the intermediate runs failed to satisfy and which is
    itself the second confirmation of the rule:

    | release | nmcli | three steps | `managed=true` in the override, as the command's *input* |
    |---|---|---|---|
    | 22.04 | 1.36.6 | `no` | absent |
    | 23.04 | 1.42.4 | `no` | absent |
    | 23.10 | 1.44.2 | `yes` | present |
    | 24.04 | 1.46.0 | `yes` | present |
    | 26.04 | 1.54.3 | `yes` | present |

    "As the command's input" is the careful half, and it is a correction of the
    first version of this table. On 22.04 the override file *does* grow a
    `managed=true` key once the device is managed -- but that is NetworkManager
    recording state it already has, and it appears without the command having run.
    With the declaration removed from the 22.04 image the command is accepted, the
    restart happens, the field stays `no`, and no key appears. So **the field is
    the discriminator** and a case that read the file would have been reading a
    consequence.

    So the boundary is **1.44**, and the two sides are adjacent releases: 1.42.4
    fails and 1.44.2 works, with nothing in between to be excused. The gate skips
    the two commands below it, and its failure direction is the safe one: a
    version wrongly read as old skips two commands whose effect the conf.d
    baseline already provides, while a version wrongly read as *new* would run a
    sequence measured to do nothing.
    """

    def test_it_runs_the_override_and_the_restart_where_the_override_exists(self):
        for version in ("1.44.2", "1.46.0", "1.54.3"):
            with self.subTest(nmcli=version):
                completed, trace = self.run_setup(NM_SETUP, NM_VERSION=version)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("nmcli device set eth0 managed yes", " ".join(trace))
                self.assertIn("systemctl restart NetworkManager", " ".join(trace))

    def test_it_skips_them_where_the_override_does_not_exist(self):
        """The measured no-op is not run, and the run says why.

        Running it would print a success that changes nothing, which is exactly
        the failure the plan's architecture note warns about: an operator reads
        `result="success"` and concludes the harness is wrong.
        """
        for version in ("1.36.6", "1.42.4"):
            with self.subTest(nmcli=version):
                completed, trace = self.run_setup(NM_SETUP, NM_VERSION=version)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertNotIn("nmcli device set", " ".join(trace))
                self.assertNotIn("systemctl restart NetworkManager", " ".join(trace))
                self.assertIn(
                    version,
                    completed.stdout + completed.stderr,
                    "the run did not say which version it skipped the sequence for",
                )

    def test_the_boundary_is_the_measured_one_and_not_a_round_number(self):
        """The threshold, compared **numerically** against the measurements.

        A gate at 1.40 or 1.50 would be a number nobody measured and would look
        exactly as authoritative. So this does not check that the string `1.44`
        appears somewhere in the script -- the weakest form of check there is, and
        the one the previous version of this case used, which passed on a comment
        saying `1.44` in a sentence about something else. It **parses the number
        out of the script's own comparison** and puts every measured `no` below it
        and every measured `yes` at or above it, using the table in `podman.py`.

        The table is the one record of the five measurements, and this case is what
        makes it load-bearing. Previously `podman.NM_OVERRIDE_MEASUREMENTS` existed,
        carried a comment claiming "the suite asserts both against this list", and
        was read by nothing: a table that nothing checks is a comment with braces
        on it, and a comment that a later reader believes is a measurement.
        """
        from podman import NM_OVERRIDE_MEASUREMENTS

        threshold = self.script_threshold()
        self.assertEqual(
            len(threshold), 2,
            f"the script does not declare its override boundary as a major.minor number: "
            f"{threshold!r}. A threshold read out of prose cannot be compared to a measurement",
        )
        for version, works in sorted(NM_OVERRIDE_MEASUREMENTS.items()):
            with self.subTest(nmcli=version, sequence_works=works):
                major, minor = (int(part) for part in version.split(".")[:2])
                at_or_above = (major, minor) >= threshold
                self.assertEqual(
                    at_or_above, works,
                    f"nmcli {version} was measured to "
                    f"{'work' if works else 'not work'} with the override sequence, and the "
                    f"script's threshold {threshold[0]}.{threshold[1]} puts it on the other "
                    f"side. The gate would run two commands that do nothing, or skip two that "
                    f"work",
                )
        # And the table is not empty, because an empty one would satisfy the loop.
        self.assertEqual(len(NM_OVERRIDE_MEASUREMENTS), 5)

    def script_threshold(self) -> tuple:
        """The boundary the script's own comparison uses, as a number.

        Read from the comparison rather than from the comment above it, because a
        comment is prose and this is the value the shell acts on. The two spellings
        of "1" are both accepted for the major, since the script compares
        `[ "$nm_major" -gt 1 ]` and `[ "$nm_major" -eq 1 ]`.
        """
        gate = " ".join(shell_statements(NM_SETUP))
        # The gate is a shell conditional, so it is read as one: `major > M` or
        # (`major == M` and `minor >= N`). Both numbers come from the comparison
        # itself -- which is the value the shell acts on -- and not from the prose
        # above it, which is where the previous version of this case looked and
        # which is why a comment saying `1.44` about something else satisfied it.
        minor = re.search(r'nm_minor"?\s+-ge\s+(\d+)', gate)
        major = re.search(r'nm_major"?\s+-eq\s+(\d+)', gate)
        above = re.search(r'nm_major"?\s+-gt\s+(\d+)', gate)
        for pattern, name in ((minor, "-ge nm_minor"), (major, "-eq nm_major"), (above, "-gt nm_major")):
            self.assertIsNotNone(
                pattern,
                f"the gate has no `{name}` comparison; the conditional reads: "
                f"{_gate_line(gate)}",
            )
        # `-gt N` and `-eq N` name the same boundary major: a major above it passes
        # unconditionally, and that major itself is decided by the minor test. Two
        # different numbers would mean a band of majors the gate skips, which is
        # the one thing a version comparison must not have.
        self.assertEqual(
            int(above.group(1)), int(major.group(1)),
            f"the gate passes majors above {above.group(1)} unconditionally and decides "
            f"{major.group(1)} by the minor test, so there is a band of majors it skips",
        )
        return (int(major.group(1)), int(minor.group(1)))

    def test_the_threshold_the_script_uses_is_the_one_podman_records(self):
        """The two records, compared, so neither can move alone.

        `podman.py`'s refusal prints the boundary to an operator and the script
        gates on it. Those are two files and two purposes, and a case that checked
        only one of them would leave a refusal quoting 1.44 beside a gate at 1.40 --
        which reads as authoritative and is wrong.
        """
        from podman import NM_OVERRIDE_MINIMUM

        self.assertEqual(
            self.script_threshold(),
            tuple(NM_OVERRIDE_MINIMUM),
            "the setup script gates on a different version than the harness's refusal quotes",
        )

    def test_a_two_digit_major_runs_the_sequence(self):
        """The `[ "$nm_major" -gt 1 ]` branch, which no other case reached.

        It is the branch for a hypothetical NetworkManager 2.x, and it is
        unreachable by every measured release -- which is exactly why it needs a
        case. A guard on an unreachable branch is a guard nobody has run, and the
        review is right that the harness makes this one argument away. The failure
        direction is safe either way (skipping costs nothing the declaration does
        not provide), so this is about the *other* direction: a 2.x that does have
        the override must not have its sequence silently dropped.
        """
        completed, trace = self.run_setup(NM_SETUP, NM_VERSION="2.0.0")
        self.assertEqual(
            completed.returncode, 0, completed.stdout + completed.stderr
        )
        self.assertIn("nmcli device set eth0 managed yes", " ".join(trace))
        self.assertIn("systemctl restart NetworkManager", " ".join(trace))

    def test_the_profile_is_still_created_where_the_sequence_is_skipped(self):
        """Task 3 modifies this profile, so it has to exist on 22.04 too.

        The gate is about the two *override* commands. Dropping the profile with
        them would leave `eth0-managed` absent on 22.04, and Task 3's
        `nmcli connection modify eth0-managed` and `connection up eth0-managed`
        would have nothing to act on — a second silent gap on a third of the
        matrix.
        """
        completed, trace = self.run_setup(NM_SETUP, NM_VERSION="1.36.6")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        # `assertIn(substring, list)` is element equality, not a substring
        # search, so this has to look inside the lines. Written the other way it
        # fails on a trace that plainly contains the command.
        self.assertIn(
            "nmcli connection add type ethernet ifname eth0 con-name eth0-managed",
            " ".join(trace),
        )
