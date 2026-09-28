#!/usr/bin/env python3
"""The Podman integration matrix harness.

    python3 tests/podman/run.py preflight
    python3 tests/podman/run.py matrix --arch amd64 --versions 22.04,24.04,26.04
    python3 tests/podman/run.py cleanup

What this harness is for is closing the system-level claims that the packaging
plan had to record SKIPPED, inside disposable containers on the development
host rather than on it. Each target container has its own network namespace and
its own `/etc`, so a run that changes DNS changes only the container's DNS.

**There is no virtual machine and no `podman machine`.** The plan's earlier
architecture was a Podman machine, which needs qemu; this host has none, is not
going to get any, and rootless Podman containers are proven to work here.

**The NetworkManager device is checked, not assumed.** A container on Podman's
default rootless network gets a tun/tap device that NetworkManager refuses by
design, so a target is put on a netavark bridge network where it gets an
`eth0` of type `ethernet`; and `nmcli device set eth0 managed yes` is followed
by `systemctl restart NetworkManager` in the target's own init, because the
override is only re-read on restart. `run_target` asserts the device is managed
before the first scenario runs, so a target that booted wrong cannot be
mistaken for an installer bug.

**Nothing here touches this machine's resolver.** The source tree is mounted
read-only at `/workspace`, the only other mount is the cgroup filesystem, and
no host `/etc`, `/run`, `/var` or `/sys` is bound in. The source tree itself
may live anywhere, including under `/home` -- where this checkout is -- because
it is bound read-only, and a read-only bind of a source directory exposes that
directory's bytes and nothing a target can change on the host. What stays
refused everywhere is a mount that could *influence* the host: a writable bind,
`--volumes-from`, a device. The podman executable, the connection URI and the
source tree are the harness's whole input, and every argument array goes
through `lib/podman.py`.

Exit codes are the interface: 0 all requested tests passed, 1 a test failure,
2 a harness or configuration error, 3 an incomplete matrix or a skipped
required architecture.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

import images  # noqa: E402
import snapshot  # noqa: E402
from podman import (  # noqa: E402
    DEFAULT_NETWORK_SUBNET,
    CleanupFailed,
    NetworkManagerDeviceError,
    Podman,
    PodmanError,
    RunResources,
    assert_networkmanager_manages_device,
    new_run_id,
    podman_session,
)
from report import (  # noqa: E402
    EXIT_HARNESS_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
    Report,
    ScenarioResult,
    Skip,
    VersionResult,
)

DEFAULT_VERSIONS = ("22.04", "24.04", "26.04")
DEFAULT_RESULTS_DIR = REPO / "build" / "test-results"

# The first line of every preflight, because it is the fact this plan turns on
# and the previous plan got wrong. It is stated before any command runs so that
# a reader who stops after one line still has the load-bearing fact.
NM_DEVICE_FACT = (
    "NetworkManager: a target's device must be a bridge network's eth0 of type "
    "ethernet -- Podman's default rootless network hands it a tun/tap device, "
    "which NetworkManager refuses -- and the target image makes it managed two "
    "ways: by declaring it in "
    "/etc/NetworkManager/conf.d/10-mosdns-target.conf ('except:interface-name:eth0', "
    "which works on every release this matrix runs), and, where NetworkManager has "
    "a persistent device override to re-read -- measured from nmcli 1.44 -- by "
    "'nmcli device set eth0 managed yes' followed by "
    "'systemctl restart NetworkManager'. Below 1.44 the two commands are accepted "
    "and change nothing, and the declaration is the only mechanism that works."
)

NM_DEVICE_NOT_CHECKABLE = (
    "Whether a target would come up with GENERAL.NM-MANAGED: yes cannot be "
    "checked here, because checking it means building tests/podman/images/"
    "target.Containerfile and running a container from it, and a preflight is a "
    "read. Build the image and ask a running target instead.\n"
    "Two things decide the answer, and neither is a preference:\n"
    "  - the target must be on a netavark BRIDGE network (a tun/tap device is "
    "refused by design);\n"
    "  - and the image's own check decides it either way. The two steps above are "
    "skipped on a NetworkManager without a persistent device override (measured: "
    "nmcli 1.36.6 and 1.42.4 have none, 1.44.2 and later do), and the check then "
    "reports what it actually saw.\n"
    "This harness will not assume it either way: run_target asserts it on a "
    "running target and refuses with the two steps above if it is not 'yes'."
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_target(
    podman: Podman,
    run_id: str,
    arch: str,
    version: str,
    image: str,
    scenarios,
    network_name: str = "testnet",
    subnet: str = DEFAULT_NETWORK_SUBNET,
    device: str = "eth0",
) -> VersionResult:
    """Run one matrix cell: a private network, a target, the scenarios, teardown.

    The order is the point. The network is created first because a target on
    the wrong network gets a tun/tap device; the device is asserted next and
    before the first scenario; the scenarios run inside a session whose
    teardown happens whatever they do.
    """
    network = RunResources(podman, run_id).network_name(network_name)
    results: list[ScenarioResult] = []
    detail: str | None = None
    with podman_session(podman, run_id, network=network) as run:
        try:
            podman.create_network(network, subnet)
            container = run.track_container(run.container_name("target", version))
            podman.run_container(image=image, name=container, network=network)
            assert_networkmanager_manages_device(podman, container, device)
        except NetworkManagerDeviceError as refusal:
            # A target that booted wrong is not an installer failure and is not
            # a pass either: the cell is incomplete and the reason is the two
            # steps, carried into the report verbatim.
            return VersionResult(
                version=version,
                arch=arch,
                detail=str(refusal),
                skips=[
                    Skip(
                        requirement=(
                            f"'nmcli -g GENERAL.NM-MANAGED device show {device}' is 'yes' "
                            f"in a running target on a bridge network"
                        ),
                        reason=str(refusal).splitlines()[0],
                    )
                ],
            )
        for name, scenario in scenarios:
            try:
                outcome = scenario()
            except Exception as error:  # noqa: BLE001 - a scenario's failure is a result
                results.append(
                    ScenarioResult(
                        name=name,
                        status="failed",
                        detail=f"{type(error).__name__}: {error}",
                        log=f"logs/{version}-{name}.log",
                    )
                )
                # The target is in a known-bad state, and the scenarios after
                # this one would each fail for that reason rather than their
                # own. They are not recorded, and the version detail says so.
                detail = f"stopped after {name}: the remaining scenarios did not run"
                break
            results.append(outcome if outcome is not None else ScenarioResult(name=name, status="passed"))
    return VersionResult(version=version, arch=arch, scenarios=tuple(results), detail=detail)


def _podman_from(args) -> Podman:
    return Podman(
        executable=args.podman,
        connection=args.connection,
        source_tree=args.source_tree,
    )


def _require_podman(podman: Podman) -> None:
    if not podman.available():
        raise PodmanError(
            f"podman was not found at {podman.executable!r}. It is a prerequisite that the "
            f"operator provides: this harness does not install Podman, and it does not need a "
            f"virtual machine or qemu, because it runs rootless containers on the local host. "
            f"Install Podman with your package manager and re-run; there is nothing this "
            f"harness can do about a missing binary, and it will not try"
        )


def snapshot_settings() -> dict:
    """Where a snapshot's command runner and Firefox roots come from.

    One function, two values, and it exists so that a *case* can supply a table
    and a temp directory instead of this machine. A snapshot collects the state of
    whatever host it runs on, so a test that took a real one would assert on the
    operator's resolver and NetworkManager and Firefox profile -- which is the
    dependency NO-HOST-MUTATION.md exists to forbid, in the one place the harness
    deliberately looks at the host.

    Production reads nothing from the environment here: the runner is
    `snapshot.SubprocessRunner` and the roots are its defaults. A case replaces
    this attribute. It is a seam rather than a CLI option because a way to ask the
    harness to snapshot a *fake* host is not a thing an operator needs.
    """
    return {
        "runner": snapshot.SubprocessRunner(),
        "firefox_roots": snapshot.DEFAULT_FIREFOX_ROOTS,
    }


def _snapshot(moment: str, run_id: str, results_dir: Path) -> Path:
    """Take one snapshot and write it where the plan's comparison looks for it.

    `build/test-results/<run-id>/host-before.json` and `host-after.json`. The
    comparison is Task 7's and this is the producer; until both exist the claim
    "a run changed nothing on the host" has no evidence behind it, whatever the
    collector can do on its own.
    """
    settings = snapshot_settings()
    document = snapshot.collect_document(
        settings["runner"],
        run_id=run_id,
        taken_utc=_now(),
        firefox_roots=settings["firefox_roots"],
    )
    return snapshot.write_snapshot(document, results_dir, run_id, moment)


def _base_images(versions, lock: str | None) -> dict:
    """Each version's base image reference, read from the lock.

    Resolved **before** the run does anything, so a lock the harness cannot use
    stops the run rather than being discovered when a container will not start.
    The failure that matters is the fallback, and there is none: a version with no
    entry, an entry without a `sha256:` digest, and an entry recorded `unavailable`
    are all refusals carrying their reason. Falling back to a tag would let the
    run succeed against a floating image with the lock sitting in the repository
    saying otherwise, and nothing in the report to say so.

    A `LockError` is translated into a `PodmanError` so that it reaches the exit
    code every other configuration failure reaches -- 2, harness or configuration
    error -- rather than falling through the interpreter's own handler.
    """
    try:
        return {version: images.reference_for_version(version, lock) for version in versions}
    except images.LockError as refusal:
        raise PodmanError(str(refusal)) from refusal


def _write_report(report: Report, results_dir: Path) -> Path:
    directory = results_dir / report.run_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.json"
    path.write_text(report.to_json(), encoding="utf-8")
    return path


def _report_shell(args, podman: Podman, results, started: str, error: str | None) -> Report:
    return Report(
        run_id=args.run_id,
        arch=getattr(args, "arch", "amd64"),
        started_utc=started,
        finished_utc=_now(),
        podman_version=_safe(podman.client_version, "unknown"),
        store_driver=_safe(podman.store_graph_driver, "unknown"),
        connection=args.connection,
        results=tuple(results),
        harness_error=error,
    )


def _safe(read, fallback: str) -> str:
    try:
        return read()
    except PodmanError:
        return fallback


def command_preflight(args) -> int:
    print(NM_DEVICE_FACT)
    podman = _podman_from(args)
    _require_podman(podman)
    print("")
    print(f"podman:          {podman.executable}")
    print(f"connection:      {args.connection or 'none -- the local rootless Podman, which is the acceptance path'}")
    if args.connection:
        print("                 (a Podman service URI for a remote or native service, never a machine name)")
    print(f"client version:  {_safe(podman.client_version, 'unreadable')}")
    print(f"store driver:    {_safe(podman.store_graph_driver, 'unreadable')}")
    print(f"source tree:     {podman.source_tree} (read-only at /workspace)")
    print("")
    print(NM_DEVICE_NOT_CHECKABLE)
    return EXIT_OK


def _run_cells(args, podman: Podman, versions, base_images: dict) -> list:
    """Run one cell per version, and say honestly which ones did not run.

    **No scenario is registered yet**, which is the whole of the plan's Task 2
    state: the target image and the lock are here, the scenarios arrive in Task 3
    on. So every requested version is reported `incomplete` with the reason, which
    is the honest answer and the reason the exit code is 3 rather than 0.

    The loop is shaped for what Task 3 registers, and the shape is the point: the
    image a cell is started from is `base_images[version]` -- the locked
    reference, resolved before the run -- and not a name this function builds. A
    cell that reached for its own tag would be a matrix that tested a different
    Ubuntu than the one it was pinned to, on the one run nobody re-reads the lock.

    The requirement string each cell carries names that reference, so a report
    left behind says which image it was about rather than only which version it
    asked for.
    """
    reason = "no scenario is registered in this build of the harness"
    return [
        VersionResult(
            version=version,
            arch=args.arch,
            detail=f"{reason}, so this cell was not run",
            skips=[
                Skip(
                    requirement=f"the {version} {args.arch} scenarios on "
                    f"{base_images[version]}",
                    reason=reason,
                )
            ],
        )
        for version in versions
    ]


def command_matrix(args) -> int:
    podman = _podman_from(args)
    _require_podman(podman)
    # A scenario that was asked for and is not registered is a configuration
    # error, not a cell that did not run. `--scenario` is the flag the plan's
    # own acceptance commands pass from Task 3 on, and parsing it and then
    # ignoring it made the plan's first "expected: PASS" command report
    # "no scenario is registered" -- which reads as though the harness looked
    # for `dhcp` and did not find it, when in fact it never looked. So the
    # refusal is explicit, names the scenario, and is exit 2.
    requested = tuple(args.scenario or ())
    if requested:
        raise PodmanError(
            f"refusing --scenario {', '.join(requested)}: no scenario is registered in this "
            f"build of the harness, so the requested one cannot be run. The target image, the "
            f"mock router and the scenarios arrive in the tasks after this one; until a scenario "
            f"is registered, 'matrix' with no --scenario reports every version incomplete and "
            f"exits {EXIT_INCOMPLETE}"
        )
    # The run id names the result directory, so a run that writes one needs
    # one. `cleanup` does not: with no --run-id it sweeps the whole namespace,
    # and a run id invented here would silently narrow that sweep to a run that
    # never happened.
    args.run_id = args.run_id or new_run_id()
    started = _now()
    versions = _versions(args)
    # The lock is read before the run does anything, not when a container starts.
    # A reference resolved lazily is a reference a run can get wrong quietly, and
    # the failure it produces -- a build or a pull against a floating tag, with
    # the lock in the repository saying otherwise -- is invisible in the report.
    base_images = _base_images(versions, args.lock)
    results_dir = Path(args.results_dir)

    # The 'before' snapshot, and the 'after' on the way out whatever happened in
    # between. Taken in a `try`/`finally` rather than after the report because the
    # case where a contributor wants to know what the host looked like afterwards
    # is the case where the run broke, and a snapshot taken only on the happy path
    # is a snapshot that exists when it is least needed.
    _snapshot(snapshot.BEFORE, args.run_id, results_dir)
    try:
        results = _run_cells(args, podman, versions, base_images)
        report = _report_shell(args, podman, results, started, None)
        path = _write_report(report, results_dir)
    finally:
        _snapshot(snapshot.AFTER, args.run_id, results_dir)
    print(f"run {report.run_id}: {report.status} (exit {report.exit_code})")
    for result in report.results:
        print(f"  {result.arch}/{result.version}: {result.status}")
        # The reason a cell did not pass, on the terminal as well as in the
        # report. A run that prints three `incomplete` lines and nothing else
        # leaves the reader to open the JSON to learn that nothing ran at all,
        # and "incomplete" is exactly the status that most needs its reason
        # next to it.
        for skip in result.skips:
            print(f"      not closed: {skip.reason}")
    print(f"report: {path}")
    return report.exit_code


def command_cleanup(args) -> int:
    podman = _podman_from(args)
    _require_podman(podman)
    # Every run this harness makes shares the one `mosdns-` namespace, so a bare
    # `cleanup` is the documented way to recover a host. Podman's `name=`
    # filter is a substring match and `RunResources` anchors it, so the sweep
    # reaches this harness's own runs and nothing else.
    prefix = f"mosdns-{args.run_id}" if args.run_id else "mosdns-"
    # With no --run-id the sweep is responsible for the whole namespace, so its
    # scope is `mosdns-` rather than one run's prefix.
    run = RunResources(podman, args.run_id or "", network=None, scope=prefix)
    for name in podman.all_container_names(prefix):
        run.track_container(name)
    for name in podman.all_volume_names(prefix):
        run.track_volume(name)
    # Networks are swept by listing rather than by guessing a name: a run's
    # network is `<prefix>-testnet` by convention, and a cleanup that removed a
    # network by a name it invented would report an error for a network that
    # never existed.
    networks = [name for name in podman.network_names(prefix) if name.startswith(prefix)]
    run.networks = networks
    outcome = run.cleanup()
    for error in outcome.errors:
        print(f"teardown: {error.message}")
    for kind, name in outcome.survivors:
        print(f"still present: {kind} {name}")
    if not outcome.ok:
        print(f"cleanup left {len(outcome.survivors)} resource(s) behind")
        return EXIT_HARNESS_ERROR
    if not outcome.removed:
        print("nothing to clean up")
    return EXIT_OK


def _versions(args) -> tuple[str, ...]:
    """The requested versions, or a refusal naming the one that is not a version.

    `--versions 24.4` used to produce a row for a version that does not exist:
    a cell reported `incomplete` for an Ubuntu release nobody ships, and the
    report carried a requirement string naming it. That is a typo the run
    cannot see and the reader cannot act on, and this plan's rule is that a
    requirement which was not closed is recorded -- it is not a rule that a
    misspelling becomes a requirement. So the shape is checked: two or three
    dot-separated numbers, which is what `22.04`, `24.04` and `26.04` are.

    The check is on the shape and not against the three known releases, so a
    later task that adds a release does not have to change the parser -- and a
    release that has genuinely stopped being published is caught by the image
    lock, which is where the list of real versions belongs.

    The shape is a year and a **zero-padded** month, which is what Ubuntu uses
    for every release since 2006: `24.04` and `26.10` are releases, `24.4` is
    the same month written badly and is the spelling the review measured
    producing a row, and `24.04.1` is a point release, which is not a thing
    this matrix has an image for.
    """
    if not args.versions:
        return DEFAULT_VERSIONS
    versions = tuple(part.strip() for part in args.versions.split(",") if part.strip())
    for version in versions:
        if not re.fullmatch(r"\d+\.(0[1-9]|1[0-2])", version):
            raise PodmanError(
                f"refusing --versions {args.versions!r}: {version!r} is not a version. A "
                f"release is a year and a zero-padded month ('24.04', '26.10'), and a cell "
                f"for a version that does not exist is a row in the report nobody can act on"
            )
    return versions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Run the Podman integration matrix in disposable containers.",
    )
    _add_global_options(parser)

    subparsers = parser.add_subparsers(dest="command", required=True)

    # The same global options are attached to every subcommand as well, because
    # a caller who writes the subcommand first is not wrong, and `run.py matrix
    # --arch amd64 --results-dir X` is the shape the plan's own acceptance
    # commands use. Without this, argparse rejects the whole invocation with
    # "unrecognized arguments" and exit 2.
    preflight = subparsers.add_parser("preflight", help="report whether this host can run the matrix")
    _add_global_options(preflight)

    matrix = subparsers.add_parser("matrix", help="run scenarios across the Ubuntu version matrix")
    # The matrix options are on the top-level parser as well, for the same
    # reason the globals are on every subparser: the plan's own Task 7 targets
    # write `run.py matrix --connection … --arch arm64 --versions …`, and a CI
    # variable or a Make target that puts the options first is not wrong.
    # Attaching them only to the subparser made the first half of the fix
    # invisible: `run.py --arch arm64 matrix` died with argparse's usage error
    # and exit 2, and only the post-subcommand spelling was tested.
    _add_matrix_options(parser)
    _add_matrix_options(matrix)
    _add_global_options(matrix)

    cleanup = subparsers.add_parser(
        "cleanup",
        help="remove this harness's leftover containers, network and volumes",
        epilog=(
            "With no --run-id every run of this harness is swept. The sweep is "
            "anchored on the mosdns- namespace and reaches nothing else."
        ),
    )
    _add_global_options(cleanup)

    return parser


def _add_matrix_options(parser: argparse.ArgumentParser) -> None:
    """The options `matrix` reads, on the top-level parser and on the subparser.

    `argparse.SUPPRESS` for the same reason as the globals: the subparser must
    not overwrite a value the top-level parser already set, and the two
    spellings have to resolve to one value whichever side of the subcommand
    they were written on. These are not attached to `preflight` or `cleanup`,
    which do not read them -- a global option is one every subcommand honours,
    and these are two.
    """
    parser.add_argument(
        "--arch", default=argparse.SUPPRESS,
        help="the architecture to run (default: amd64)",
    )
    parser.add_argument(
        "--versions", default=argparse.SUPPRESS,
        help=f"a comma-separated version list (default: {','.join(DEFAULT_VERSIONS)})",
    )
    parser.add_argument(
        "--scenario", default=argparse.SUPPRESS, action="append",
        help=(
            "a scenario to run; repeatable. No scenario is registered in this build of "
            "the harness, so naming one is refused rather than ignored."
        ),
    )


def _add_global_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--podman", default=argparse.SUPPRESS,
        help="the podman executable to use (default: podman on PATH)",
    )
    parser.add_argument(
        "--connection", default=argparse.SUPPRESS,
        help=(
            "a Podman service URI for a remote or native service, e.g. "
            "ssh://host/run/user/1000/podman/podman.sock. Never a machine name: "
            "there is no machine."
        ),
    )
    parser.add_argument(
        "--source-tree", default=argparse.SUPPRESS,
        help="the checkout to mount read-only at /workspace (default: this repository)",
    )
    parser.add_argument(
        "--results-dir", default=argparse.SUPPRESS,
        help=f"where run results are written (default: {DEFAULT_RESULTS_DIR})",
    )
    parser.add_argument(
        "--run-id", default=argparse.SUPPRESS,
        help="the run id; a UTC timestamp by default",
    )
    parser.add_argument(
        "--lock", default=argparse.SUPPRESS,
        help=(
            f"the image lock to resolve base images from (default: {images.LOCK_RELATIVE_PATH})"
        ),
    )


# The defaults for the options argparse suppresses on the subparsers, applied
# once after parsing so that the two spellings of every option resolve to one
# value regardless of where on the command line they were written.
GLOBAL_DEFAULTS = {
    "podman": "podman",
    "connection": None,
    "source_tree": str(REPO),
    "results_dir": str(DEFAULT_RESULTS_DIR),
    "run_id": None,
    "arch": "amd64",
    "versions": None,
    "scenario": None,
    "lock": None,
}


def main(argv=None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as refusal:
        # A bad invocation is a configuration error, and the number has to come
        # from here rather than from argparse's own exit, so that the four exit
        # codes are one contract rather than two.
        return EXIT_HARNESS_ERROR if refusal.code else EXIT_OK
    for name, value in GLOBAL_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, value)
    handlers = {
        "preflight": command_preflight,
        "matrix": command_matrix,
        "cleanup": command_cleanup,
    }
    try:
        return handlers[args.command](args)
    except PodmanError as error:
        # A harness or configuration error, and distinctly not a test failure:
        # nothing was proved either way. `CleanupFailed` is a `PodmanError` --
        # it subclasses it, deliberately, so a teardown failure raised out of a
        # scenario loop is reported rather than escaping as a crash -- so this
        # one `except` covers it and there is no second branch for it below.
        print(f"harness error: {error}")
        return EXIT_HARNESS_ERROR
    except Exception as error:  # noqa: BLE001 - the exit-code contract's net
        # Anything else a handler raises is still the harness's own fault, and
        # the contract reserves exit 1 for a *test* failure. Without this a
        # `TypeError` in a later task's handler escaped as a traceback and exit
        # 1 from the interpreter, which a caller reading the number would go
        # and investigate as a broken installer.
        #
        # `KeyboardInterrupt` and `SystemExit` derive from `BaseException` and
        # are not caught: a Ctrl-C is a Ctrl-C, and `argparse` already routes
        # its own exits through the `SystemExit` handler above.
        print(f"harness error: {type(error).__name__}: {error}")
        return EXIT_HARNESS_ERROR


if __name__ == "__main__":
    sys.exit(main())
