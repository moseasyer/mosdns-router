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
no host `/etc`, `/run`, `/var`, `/sys` or `/home` is bound in. The podman
executable, the connection URI and the source tree are the harness's whole
input, and every argument array goes through `lib/podman.py`.

Exit codes are the interface: 0 all requested tests passed, 1 a test failure,
2 a harness or configuration error, 3 an incomplete matrix or a skipped
required architecture.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

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
    "which NetworkManager refuses -- and it becomes managed only after "
    "'nmcli device set eth0 managed yes' followed by "
    "'systemctl restart NetworkManager' in the target."
)

NM_DEVICE_NOT_CHECKABLE = (
    "Whether a target would come up with GENERAL.NM-MANAGED: yes cannot be "
    "checked here, because no target image is built yet. This harness will not "
    "assume it: run_target asserts it on a running target and refuses with the "
    "two steps above if it is not 'yes'."
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
            f"virtual machine or qemu, because it runs rootless containers on the local host."
        )


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


def command_matrix(args) -> int:
    podman = _podman_from(args)
    _require_podman(podman)
    started = _now()
    versions = _versions(args)
    # Task 1 of the plan registers no scenario: the target image, the mock
    # router and the scenarios arrive in the tasks after it. Every requested
    # version is therefore reported incomplete with the reason, which is the
    # honest answer and the reason the exit code is 3 rather than 0.
    results = [
        VersionResult(
            version=version,
            arch=args.arch,
            detail="no scenario is registered yet, so this cell was not run",
            skips=[
                Skip(
                    requirement=f"the {version} amd64 scenarios",
                    reason="no scenario is registered in this build of the harness",
                )
            ],
        )
        for version in versions
    ]
    report = _report_shell(args, podman, results, started, None)
    path = _write_report(report, Path(args.results_dir))
    print(f"run {report.run_id}: {report.status} (exit {report.exit_code})")
    for result in report.results:
        print(f"  {result.arch}/{result.version}: {result.status}")
    print(f"report: {path}")
    return report.exit_code


def command_cleanup(args) -> int:
    podman = _podman_from(args)
    _require_podman(podman)
    if args.run_id:
        prefixes = [f"mosdns-{args.run_id}"]
        network = f"mosdns-{args.run_id}-testnet"
    else:
        # Every run this harness has ever made shares the one namespace, so a
        # bare `cleanup` is the documented way to recover a host.
        prefixes = [_all_harness_prefixes(podman)]
        network = None
    failures = 0
    for prefix in prefixes:
        run = RunResources(podman, prefix[len("mosdns-"):], network=network)
        for name in podman.all_container_names(prefix):
            run.track_container(name)
        for name in podman.all_volume_names(prefix):
            run.track_volume(name)
        outcome = run.cleanup()
        for error in outcome.errors:
            print(f"teardown: {error.message}")
        for kind, name in outcome.survivors:
            failures += 1
            print(f"still present: {kind} {name}")
        if failures:
            break
    if failures:
        print(f"cleanup left {failures} resource(s) behind")
        return EXIT_HARNESS_ERROR
    return EXIT_OK


def _all_harness_prefixes(podman: Podman) -> str:
    """The namespace every run of this harness shares, as a filter prefix.

    Podman's `name=` filter is a substring match, so the sweep is anchored by
    `RunResources` and the prefix here is the literal `mosdns-`, which is this
    harness's own namespace and nothing else's.
    """
    return "mosdns-"


def _versions(args) -> tuple[str, ...]:
    if not args.versions:
        return DEFAULT_VERSIONS
    return tuple(part.strip() for part in args.versions.split(",") if part.strip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Run the Podman integration matrix in disposable containers.",
    )
    parser.add_argument(
        "--podman", default="podman",
        help="the podman executable to use (default: podman on PATH)",
    )
    parser.add_argument(
        "--connection", default=None,
        help=(
            "a Podman service URI for a remote or native service, e.g. "
            "ssh://host/run/user/1000/podman/podman.sock. Never a machine name: "
            "there is no machine."
        ),
    )
    parser.add_argument(
        "--source-tree", default=str(REPO),
        help="the checkout to mount read-only at /workspace (default: this repository)",
    )
    parser.add_argument(
        "--results-dir", default=str(DEFAULT_RESULTS_DIR),
        help=f"where run results are written (default: {DEFAULT_RESULTS_DIR})",
    )
    parser.add_argument("--run-id", default=None, help="the run id; a UTC timestamp by default")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("preflight", help="report whether this host can run the matrix")

    matrix = subparsers.add_parser("matrix", help="run scenarios across the Ubuntu version matrix")
    matrix.add_argument("--arch", default="amd64", help="the architecture to run (default: amd64)")
    matrix.add_argument(
        "--versions", default=None,
        help=f"a comma-separated version list (default: {','.join(DEFAULT_VERSIONS)})",
    )
    matrix.add_argument(
        "--scenario", default=None, action="append",
        help="a scenario to run; repeatable. No scenario is registered yet.",
    )

    cleanup = subparsers.add_parser("cleanup", help="remove this harness's leftover containers, network and volumes")
    cleanup.add_argument("--run-id", default=None, help="one run only (default: every run)")

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as refusal:
        # A bad invocation is a configuration error, and the number has to come
        # from here rather than from argparse's own exit, so that the four exit
        # codes are one contract rather than two.
        return EXIT_HARNESS_ERROR if refusal.code else EXIT_OK
    if not getattr(args, "run_id", None):
        args.run_id = new_run_id()
    handlers = {
        "preflight": command_preflight,
        "matrix": command_matrix,
        "cleanup": command_cleanup,
    }
    try:
        return handlers[args.command](args)
    except PodmanError as error:
        # A harness or configuration error, and distinctly not a test failure:
        # nothing was proved either way.
        print(f"harness error: {error}")
        return EXIT_HARNESS_ERROR
    except CleanupFailed as failure:
        print(f"harness error: {failure}")
        return EXIT_HARNESS_ERROR


if __name__ == "__main__":
    sys.exit(main())
