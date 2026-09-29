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
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "scenarios"))

import dhcp_test  # noqa: E402
import images  # noqa: E402
import snapshot  # noqa: E402
from podman import (  # noqa: E402
    CONTAINER_CAPABILITIES,
    DEFAULT_NETWORK_SUBNET,
    NM_SETUP_ACTIVE,
    NM_SETUP_UNIT,
    CleanupFailed,
    NetworkManagerDeviceError,
    NetworkManagerSetupError,
    Podman,
    PodmanError,
    RunResources,
    new_run_id,
    podman_session,
    wait_for_networkmanager_device,
    wait_for_networkmanager_setup,
)
from report import (  # noqa: E402
    EXIT_HARNESS_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
    STATUS_PASSED,
    Report,
    ScenarioResult,
    Skip,
    VersionResult,
)

DEFAULT_VERSIONS = ("22.04", "24.04", "26.04")
DEFAULT_RESULTS_DIR = REPO / "build" / "test-results"

# -- the scenario registry -----------------------------------------------------
#
# One mapping, name -> builder, and both the refusal and the runner read it. A
# second list would drift: a scenario registered in one and not the other is
# either a scenario nobody can ask for or a refusal that lies about which names
# would have worked, and neither shows up anywhere.
#
# The builders are looked up by name at call time rather than bound at import
# time, so a scenario module that fails to import takes the whole harness down
# loudly at start-up instead of at the first scenario -- and so a later task
# adding a scenario is one entry here and one module.
def build_scenarios() -> dict[str, str]:
    """`{name: "module:function"}` for every scenario the harness can run.

    Strings rather than objects, so the mapping is a literal and a case can read
    it with `ast.literal_eval` -- the same reasoning as the policed flag sets in
    `lib/podman.py`: a registry built by a function call is invisible to a reader
    that walks the source, and the thing that has to be held to the code is
    exactly the thing that names the code.
    """
    return {"dhcp": "dhcp_test:build_scenario"}


def _resolve_builder(name: str):
    target = build_scenarios()[name]
    module_name, _, function_name = target.partition(":")
    module = __import__(module_name)
    return getattr(module, function_name)


SCENARIO_NAMES = tuple(sorted(build_scenarios()))

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
    "This harness will not assume it either way: run_target *waits* for it on a "
    "running target -- a single query would be a race, because `podman run -d` "
    "returns before the target has booted -- and refuses with the two steps above "
    "if it is not 'yes'."
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
    router_image: str | None = None,
    network_name: str = "testnet",
    subnet: str = DEFAULT_NETWORK_SUBNET,
    device: str = "eth0",
    results_dir: Path | None = None,
) -> VersionResult:
    """Run one matrix cell: a private network, a mock router, a target, the scenarios, teardown.

    The order is the point, and each step is a precondition of the one after it:

    1. the **network** is created first, because a target on Podman's default
       rootless network gets a tun/tap device and NetworkManager refuses that by
       design;
    2. the **mock router** is started next, and started *before* the target
       because podman hands out the first free address in the pool, which is the
       router's -- a target left to its own devices would be given the router's
       address and the DHCP exchange would be a target talking to itself. Both
       addresses are named by the plan and both are passed with `--ip`;
    3. the **device** is waited for next, before the first scenario, so a target
       that booted unmanaged is reported as itself rather than as an installer
       bug -- and waited for, not asked, because `podman run -d` returns before
       the target has booted; and
    4. the **scenarios** run inside a session whose teardown happens whatever
       they do.

    Both containers are tracked, so `cleanup` removes them. A container named by
    hand is one nothing finds.
    """
    network = RunResources(podman, run_id).network_name(network_name)
    results: list[ScenarioResult] = []
    detail: str | None = None
    with podman_session(podman, run_id, network=network) as run:
        try:
            podman.create_network(network, subnet)
            router = run.track_container(run.container_name("mock-router", version))
            podman.run_container(
                image=router_image or image,
                name=router,
                network=network,
                extra_args=["--ip", dhcp_test.MOCK_ROUTER_ADDRESS],
                # dnsmasq does not run an init and is not traced, so the target's
                # SYS_ADMIN and SYS_PTRACE are not its business -- but it *does*
                # need NET_ADMIN and NET_RAW, measured, and it exits 5 without
                # them. The measurement is in `CONTAINER_CAPABILITIES`.
                capabilities=CONTAINER_CAPABILITIES["mock-router"],
            )
            container = run.track_container(run.container_name("target", version))
            podman.run_container(
                image=image,
                name=container,
                network=network,
                extra_args=["--ip", dhcp_test.TARGET_ADDRESS],
            )
            # Two gates, in this order, and the order is the fix.
            #
            # **First: the target's own setup unit.** `GENERAL.NM-MANAGED` is
            # produced *by* `target-nm-setup.service`, and on 24.04 and 26.04 the
            # unit's third step is `systemctl restart NetworkManager`. So a field
            # reads `yes` from the `conf.d` declaration while the unit is still
            # running and about to restart the daemon underneath it. Gating on the
            # field alone let a scenario's `nmcli connection up` land inside that
            # restart and fail with `Error: NetworkManager is not running` -- about
            # one run in four, and one in six measured before any of this round's
            # code. Measured state per release, and the same on all three:
            # `active`/`exited`/`success`.
            #
            # **Then: the field.** Not redundant. A unit that finished with the
            # device unmanaged is a target the unit's own check would have failed
            # on, but the harness does not rely on that having been said -- and
            # the field is what every scenario downstream actually needs.
            #
            # The clock is the scenario seam so a case can run a cell without
            # sitting out either budget; production waits.
            clock = scenario_clock()
            wait_for_networkmanager_setup(
                podman, container,
                now=clock["now"], sleep=clock["sleep"],
            )
            wait_for_networkmanager_device(
                podman, container, device,
                now=clock["now"], sleep=clock["sleep"],
            )
        except NetworkManagerSetupError as refusal:
            # Its own `except`, before the device one, so the skip names the
            # requirement that was actually not met. Both are the same refusal
            # shape -- an incomplete cell, not a failed one -- and the subclassing
            # is what lets one reporting path serve both.
            return VersionResult(
                version=version,
                arch=arch,
                detail=str(refusal),
                skips=[
                    Skip(
                        requirement=(
                            f"'{NM_SETUP_UNIT}' reaches '{NM_SETUP_ACTIVE}' in a running "
                            f"target, before any scenario runs"
                        ),
                        reason=str(refusal).splitlines()[0],
                    )
                ],
            )
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


def _build_images(podman: Podman, versions, base_images: dict) -> dict[str, dict[str, str]]:
    """Every image each cell needs, built from the lock and tagged by content.

    **Built, not named.** A harness that started the target from
    `localhost/mosdns-target:24.04` would be testing an image nothing in the
    repository accounts for, and the digest `images.lock.json` pins would be a
    comment in a file. So the base image reaches the build as a build argument --
    `BASE_IMAGE=docker.io/library/ubuntu:24.04@sha256:…` -- resolved from the lock
    before the run does anything, and the Containerfile has no `FROM` a reader
    could mistake for the input.

    **The tag is the cache key**, and it is a hash of the Containerfile and the
    base reference, so an image this run would not build is not reused and an
    image it would build again is. `images.image_tag` is where that is written
    down, and the case in `tests/podman/tests/test_matrix_cell.py` is what holds
    it to a Containerfile edit.

    A build that fails is a harness error -- exit 2 -- and not a failed cell: a
    cell that could not start proves nothing about the package, and reporting it
    as `failed` would send a reader looking for an installer bug.
    """
    built: dict[str, dict[str, str]] = {}
    for version in versions:
        reference = base_images[version]
        built[version] = {}
        for role in images.IMAGE_ROLES:
            tag = images.image_tag(role, version, reference)
            if podman.image_exists(tag):
                built[version][role] = tag
                continue
            try:
                podman.build_image(
                    tag,
                    str(images.containerfile(role)),
                    build_args=(("BASE_IMAGE", reference),),
                    context=str(REPO),
                )
            except PodmanError as failure:
                raise PodmanError(
                    f"could not build the {role} image for {version} ({tag}) from {reference}: "
                    f"{failure}. Nothing was proved about that release, so this is a harness "
                    f"error rather than a failed cell -- a cell that could not start is not a "
                    f"result"
                ) from failure
            built[version][role] = tag
    return built


def scenario_clock() -> dict:
    """The clock a scenario's bounded waits run on.

    One function, two values, and it exists for the same reason
    `snapshot_settings()` does two directories below: a scenario is a thing that
    waits, and a *case* that runs one has to be able to run it without spending
    the scenario's real budget. The DHCP scenario's first wait is bounded at
    ninety seconds and its failure path is the one most of its cases are about,
    so a case driving a `matrix` run against a fake podman would otherwise sit
    through every bound in turn -- a suite nobody runs, and the one that would
    be pruned first.

    It is a seam rather than a CLI option because "wait longer on this run" is
    not a thing an operator needs, while "prove the wait is bounded" is a thing
    a test needs. Production uses the real clock and a case replaces this
    function.
    """
    return {"now": time.monotonic, "sleep": time.sleep}


def _run_cells(args, podman: Podman, versions, base_images: dict, cell_images: dict) -> list:
    """Run one cell per version, with the scenarios that were asked for.

    The cell is started from `cell_images[version]`, whose entries were built
    from `base_images[version]` -- the locked reference, resolved before the run
    -- and not from a name this function builds. A cell that reached for its own
    tag would be a matrix that tested a different Ubuntu than the one it was
    pinned to, on the one run nobody re-reads the lock.
    """
    requested = tuple(args.scenario or ()) or SCENARIO_NAMES
    clock = scenario_clock()
    cells = []
    for version in versions:
        builders = [
            (name, _resolve_builder(name)) for name in requested
        ]
        scenarios = [
            (name, builder(
                podman=podman,
                version=version,
                arch=args.arch,
                run_id=args.run_id,
                router=RunResources(podman, args.run_id).container_name("mock-router", version),
                target=RunResources(podman, args.run_id).container_name("target", version),
                network=RunResources(podman, args.run_id).network_name("testnet"),
                results_dir=Path(args.results_dir),
                now=clock["now"],
                sleep=clock["sleep"],
            ))
            for name, builder in builders
        ]
        cells.append(
            run_target(
                podman,
                run_id=args.run_id,
                arch=args.arch,
                version=version,
                image=cell_images[version]["target"],
                router_image=cell_images[version]["mock-router"],
                scenarios=scenarios,
                results_dir=Path(args.results_dir),
            )
        )
    return cells


def command_matrix(args) -> int:
    podman = _podman_from(args)
    _require_podman(podman)
    # A scenario that was asked for and is not registered is a configuration
    # error, not a cell that did not run. `--scenario` is the flag the plan's
    # own acceptance commands pass from Task 3 on, and parsing it and then
    # ignoring it made the plan's first "expected: PASS" command report
    # "no scenario is registered" -- which reads as though the harness looked
    # for `dhcp` and did not find it, when in fact it never looked. So the
    # refusal is explicit, names every scenario that was asked for, and is
    # exit 2.
    registered = build_scenarios()
    requested = tuple(args.scenario or ())
    unknown = [name for name in requested if name not in registered]
    if unknown:
        raise PodmanError(
            f"refusing --scenario {', '.join(unknown)}: no such scenario is registered in this "
            f"build of the harness, so the requested one cannot be run. The registered scenarios "
            f"are {', '.join(sorted(registered)) or 'none'}, and 'matrix' with no --scenario runs "
            f"all of them. A scenario that is registered but fails is a *failed cell* with the "
            f"reason in the report; one that is not registered is a configuration error, because "
            f"nothing ran and nothing was proved"
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
        cell_images = _build_images(podman, versions, base_images)
        results = _run_cells(args, podman, versions, base_images, cell_images)
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
        for scenario in result.scenarios:
            if scenario.status != STATUS_PASSED and scenario.detail:
                print(f"      {scenario.name}: {scenario.detail.splitlines()[0]}")
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
