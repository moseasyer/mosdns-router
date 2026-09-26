"""Turn one NetworkManager dispatcher event into a published DHCP DNS state.

The dispatcher runs this program with the event's variables in the environment
and reads nothing but the exit status, so the module is a thin, honest shell
around two decisions:

* **Which event is this, and which interface is it about?** The action comes from
  ``NM_DISPATCHER_ACTION``; the interface comes from ``DEVICE_IP_IFACE``, then
  the dispatcher's own first positional argument -- the ``script INTERFACE ACTION``
  form every supported release uses -- then ``INTERFACE``, then ``DEVICE``.
  ``NM_DISPLAY_NAME`` is a connection profile's human-readable name, never a
  device name, so it is not consulted. An action the bridge does not handle is
  not an error: NetworkManager runs this program for events that have nothing to
  do with DNS, and the right answer to those is to change nothing and succeed.
* **What did the lease say?** The publisher answers whether the state changed, and
  only the actions that collect have their address list read first. The recorded
  source is the one that answered -- the raw NetworkManager DHCP field, the
  event's own variables, the effective device DNS, or resolved -- because a
  renewal, an interface coming up, and a DNS change that renews nothing all reach
  the same resolvers through the same source, and a state that recorded the event
  instead would be a new generation for each of them. A ``down`` event publishes
  no resolvers and never runs a command, because the lease those resolvers came
  from is gone; it is the only event whose recorded source is the event, since no
  source answered. A source that could not be read at all is not an empty lease:
  the event is reported and nothing is published, so a wedged D-Bus leaves the
  last good generation in place.

The program is run two ways, and the command line says which, rather than the
program guessing. NetworkManager runs it as a dispatcher event, with the event's
variables in the environment. An installation runs it with
``--capture-current INTERFACE`` before any event exists, because it has to know
which resolvers are in use before it rewrites NetworkManager. The two are
mutually exclusive and one of them is required: a command line carrying both, or
neither, is a command line this program reports rather than a machine it cannot
act on. A capture is that same publication path with an interface the caller
names -- the same collector, the same publisher, the same recorded source, and
the same refusal ladder -- so a capture and the first event after it are one
state rather than two generations, and a capture cannot record a document an
event would have refused.

The module also owns the exit status the dispatcher acts on. Nothing here calls
``sys.exit``: ``main`` returns a code, and only the process entry point turns it
into an exit status, so every path is testable.
"""

from __future__ import annotations

import datetime
import os
import subprocess
import sys
from typing import Dict, List, Mapping, NamedTuple, Optional, Sequence

from .collect import (
    CommandRunner,
    SourcesUnavailable,
    collect_dns_with_source,
    is_interface_name,
)
from .publish import (
    InvalidStateError,
    LockUnavailable,
    PublicationError,
    publish_if_changed,
)

__all__ = ["main", "console_entry", "real_runner"]

USAGE = (
    "usage: mosdns-dhcp-bridge --state-file PATH --lock-file PATH "
    "[--capture-current INTERFACE | INTERFACE [ACTION]]"
)

# The dispatcher names the event in this variable. An absent or empty one means
# the program was not run by the dispatcher at all, which is a misconfiguration
# worth reporting rather than ignoring.
ACTION_VARIABLE = "NM_DISPATCHER_ACTION"

# The variables NetworkManager defines as the interface, most specific first,
# with the dispatcher's own positional argument ranked between the first and the
# rest. DEVICE_IP_IFACE is the interface the IP configuration is bound to,
# INTERFACE is the dispatcher script's own interface, and DEVICE is the last
# resort.
INTERFACE_VARIABLES = ("DEVICE_IP_IFACE", "INTERFACE", "DEVICE")

CONNECTION_UUID_VARIABLE = "CONNECTION_UUID"

# The mode an installation runs this program in: no dispatcher event exists yet,
# so the caller names the interface itself. It is mutually exclusive with the
# dispatcher's environment, and each of the two on its own is a complete mode.
CAPTURE_OPTION = "--capture-current"

# The field that carries the UUID of the connection a device is using. Its
# sibling GENERAL.CONNECTION holds the connection's *name* -- the string a
# profile is called, which is not what the state records -- so this is the field a
# capture has to ask for, and a value that is not a UUID is refused by the
# publisher rather than written.
CONNECTION_FIELD = "GENERAL.CON-UUID"

# The events whose DNS the bridge collects. Every one of them records the source
# that answered, never the event itself: the same lease read through the same
# source by an interface coming up, a lease renewal, and a DNS change is one
# state, and a new generation would flush the plugin's cache for resolvers that
# never moved.
COLLECTING_ACTIONS = ("up", "dhcp4-change", "dhcp6-change", "dns-change")

# A down event publishes an empty list instead of collecting: the addresses the
# collector would find belong to a lease that no longer exists. It is the only
# event whose recorded source is the event, because no source answered.
DISABLING_ACTION = "down"
DISABLING_SOURCE = "down"

# Each option with the kind of value it takes, so a refusal names what is missing
# rather than calling a missing interface a missing path.
OPTIONS = {
    "--state-file": "path",
    "--lock-file": "path",
    CAPTURE_OPTION: "interface name",
}
# The two paths are required in both modes; the capture option is the mode.
REQUIRED_OPTIONS = ("--state-file", "--lock-file")

# NetworkManager runs a dispatcher script as `script INTERFACE ACTION`, so two
# positional arguments may follow the options: the interface the event is about
# and the event itself. The action is read from NM_DISPATCHER_ACTION, which is
# the value NetworkManager exports for it, so the echoed argument is accepted and
# not interpreted.
MAXIMUM_POSITIONAL_ARGUMENTS = 2

# A read-only nmcli or resolvectl query against NetworkManager's own state
# answers in milliseconds. The bound only exists so a wedged D-Bus cannot hold a
# dispatcher slot open; a command that reaches it is treated as an unavailable
# source by the collector, not as a failure.
COMMAND_TIMEOUT_SECONDS = 5.0

EXIT_SUCCESS = 0
EXIT_INVALID_INPUT = 2
EXIT_LOCKED = 3
# One status for a state that could not be published and for a lease that could
# not be read: both leave the previous generation standing, and both mean the
# operator has to look at this machine.
EXIT_STATE = 4


class _Request(NamedTuple):
    """The command line as one mode: an interface to capture, or a dispatcher's arguments.

    ``capture`` is the interface an installation named and is empty when the
    dispatcher runs the program, which it can only be: a capture with no interface
    is refused while the command line is read. That is the whole of the mode, and it
    is decided here, before any command runs, because the two invocations read
    different things and neither may act as the other.
    """

    state_file: str
    lock_file: str
    capture: str
    positionals: List[str]


def main(argv: Sequence[str], env: Mapping[str, str], run: CommandRunner) -> int:
    """Publish the state for one event, or for a capture, and return its exit status.

    ``argv`` is the command line without the program name, ``env`` the dispatcher's
    environment, and ``run`` executes one read-only command. Returns 0 when the
    state was published or was already current, 2 for a command line or
    environment the bridge cannot act on -- including one that names neither mode
    or both of them -- 3 while another bridge process holds the publication lock,
    and 4 when the state could not be published or no source that reports the
    lease could be read.

    Nothing raises out of this function. The dispatcher reads the exit status and
    nothing else, so a raised error would replace a documented status with a
    traceback and leave an operator guessing which stage failed.
    """
    try:
        request = _options(argv)
    except ValueError as error:
        return _fail(EXIT_INVALID_INPUT, str(error))

    # The variable's presence is what says this is a dispatcher run, not its value:
    # NetworkManager always exports an action of its own, so an exported but empty
    # one is a malformed event rather than an absent one. Reading presence rather
    # than content is what makes the two modes exactly exclusive -- a shell that
    # exported the variable once cannot decide which mode this program runs in.
    exported = ACTION_VARIABLE in env

    if request.capture:
        if exported:
            return _fail(
                EXIT_INVALID_INPUT,
                f"{CAPTURE_OPTION} and {ACTION_VARIABLE} are two ways to run this "
                f"program and cannot both be given: a capture has no dispatcher "
                f"event, and an event is told its interface by NetworkManager; "
                f"{USAGE}",
            )
        return _capture(request, env, run)
    if not exported:
        return _fail(
            EXIT_INVALID_INPUT,
            f"{ACTION_VARIABLE} is not set, so this is neither a dispatcher event "
            f"nor a capture; an installation with no event names the interface "
            f"with {CAPTURE_OPTION}; {USAGE}",
        )
    action = env[ACTION_VARIABLE]
    if not isinstance(action, str) or not action:
        return _fail(
            EXIT_INVALID_INPUT,
            f"{ACTION_VARIABLE} is set but names no action, so this is not a "
            f"dispatcher event; {USAGE}",
        )
    return _dispatcher(request, env, action, run)


def _dispatcher(
    request: _Request, env: Mapping[str, str], action: str, run: CommandRunner
) -> int:
    """Publish the state one NetworkManager event is about, and return its exit status.

    ``action`` is the event's own action, already read from the environment, and
    the decision this makes is the one the module docstring describes: which event
    this is, and which interface it is about.
    """
    if action != DISABLING_ACTION and action not in COLLECTING_ACTIONS:
        # An event this bridge does not act on: no command is run and no file is
        # touched, so the state keeps describing the last real lease.
        return EXIT_SUCCESS

    try:
        interface = _interface(env, request.positionals)
    except ValueError as error:
        return _fail(EXIT_INVALID_INPUT, str(error))

    if action == DISABLING_ACTION:
        upstreams: List[str] = []
        source = DISABLING_SOURCE
    else:
        try:
            collected = collect_dns_with_source(env, interface, run)
        except SourcesUnavailable as error:
            # Reported before the lock is taken and before the state is opened:
            # a NetworkManager that cannot be queried says nothing about the
            # lease, and publishing an empty state here would disable a working
            # router on one failed query.
            return _fail(EXIT_STATE, str(error))
        except ValueError as error:
            return _fail(EXIT_INVALID_INPUT, str(error))
        upstreams, source = collected.addresses, collected.source

    return _publish(
        request,
        interface,
        upstreams,
        source,
        env.get(CONNECTION_UUID_VARIABLE, ""),
    )


def _capture(request: _Request, env: Mapping[str, str], run: CommandRunner) -> int:
    """Publish the lease in use right now on an interface an installation named.

    This is the dispatcher's publication path with an explicit interface, not a
    second writer of the state. The addresses come from the same collector, the
    recorded source is the one that answered rather than the fact that a capture
    happened, and the same publisher decides whether anything changed. A capture
    and the first event after it therefore record one state rather than two
    generations for a lease that never moved, and a source token of the capture's
    own would make every later event a new generation for resolvers that did not
    change.
    """
    interface = request.capture
    # The name is checked here rather than left to the collector, for the same
    # reason the event's own interface is: it reaches fixed argument arrays and the
    # published document, and refusing it is still free because nothing has run.
    if not is_interface_name(interface):
        return _fail(
            EXIT_INVALID_INPUT,
            f"{CAPTURE_OPTION} is not a network interface name: {interface!r}",
        )

    try:
        collected = collect_dns_with_source(env, interface, run)
    except SourcesUnavailable as error:
        return _fail(EXIT_STATE, str(error))
    except ValueError as error:
        return _fail(EXIT_INVALID_INPUT, str(error))

    try:
        connection_uuid = _connection_uuid(env, interface, run)
    except SourcesUnavailable as error:
        # After the collection and before the lock, for the same reason: a
        # connection that could not be read says nothing about the lease, and a
        # state without the connection its resolvers came from is one the
        # publisher refuses, so the last good generation stands.
        return _fail(EXIT_STATE, str(error))

    return _publish(
        request,
        interface,
        collected.addresses,
        collected.source,
        connection_uuid,
    )


def _connection_uuid(
    env: Mapping[str, str], interface: str, run: CommandRunner
) -> str:
    """Return the connection the lease on ``interface`` belongs to.

    NetworkManager exports ``CONNECTION_UUID`` to every dispatcher event it runs,
    so an event never has to ask. An installation runs before any event exists and
    has no such variable, and asks NetworkManager once instead. The lookup is
    mandatory rather than a convenience: a state that names resolvers has to name
    the connection they belong to, and the publisher refuses one whose connection
    is empty, so a capture that cannot name the connection publishes nothing at
    all rather than a document the router would not read.

    A command that could not be read raises the collector's own failure, for the
    same reason the collector raises it: a NetworkManager that cannot be queried
    is not evidence that the lease lost its resolvers. The message names no
    address, no UUID, and no interface, because it is written to a log.
    """
    exported = env.get(CONNECTION_UUID_VARIABLE, "")
    if exported:
        return exported
    answer: Optional[str] = None
    try:
        output = run(["nmcli", "-g", CONNECTION_FIELD, "device", "show", interface])
        answer = output if isinstance(output, str) else None
    except Exception:
        # Deliberately broad, and confined to the injected call: the runner owns
        # process handling, so a missing binary, a non-zero status, and a timeout
        # all arrive here, and all mean the same thing -- no answer.
        answer = None
    if answer is None:
        raise SourcesUnavailable(
            "the connection of the captured interface could not be read: nmcli -g "
            f"{CONNECTION_FIELD} device show failed"
        )
    return answer.strip()


def _publish(
    request: _Request,
    interface: str,
    upstreams: Sequence[str],
    source: str,
    connection_uuid: str,
) -> int:
    """Publish one observation's facts and return the exit status for it.

    Both modes publish through here, which is what makes a capture and a
    dispatcher event the same writer rather than two: the lock, the validation,
    the decision about whether the state changed, and the meaning of every exit
    status are decided once, so a capture cannot record a document an event would
    have refused, nor refuse one an event would have published.
    """
    try:
        publish_if_changed(
            request.state_file,
            interface=interface,
            connection_uuid=connection_uuid,
            upstreams=upstreams,
            source=source,
            now=_observed_now(),
            lock_path=request.lock_file,
        )
    except LockUnavailable as error:
        return _fail(EXIT_LOCKED, str(error))
    except (InvalidStateError, PublicationError, OSError) as error:
        return _fail(EXIT_STATE, str(error))
    except ValueError as error:
        return _fail(EXIT_INVALID_INPUT, str(error))
    return EXIT_SUCCESS


def _options(argv: Sequence[str]) -> _Request:
    """Return the paths, the capture interface, and the dispatcher's arguments.

    Every option is required and none may be repeated. A default would let a
    typo in the dispatcher unit create a second, empty state file beside the real
    one instead of failing. Anything that is not an option is the dispatcher's own
    interface and action arguments, and more of them than the dispatcher passes is
    a command line this program does not understand; beside a capture they are
    refused outright, because the capture has already named the interface and a
    reader of the command line could not tell which of the two was used.
    """
    values: Dict[str, str] = {}
    positionals: List[str] = []
    index = 0
    while index < len(argv):
        option = argv[index]
        if not option.startswith("-"):
            positionals.append(option)
            index += 1
            continue
        if option not in OPTIONS:
            raise ValueError(f"unknown argument {option!r}; {USAGE}")
        if option in values:
            raise ValueError(f"{option} is given more than once; {USAGE}")
        kind = OPTIONS[option]
        if index + 1 >= len(argv):
            raise ValueError(f"{option} needs a {kind}; {USAGE}")
        argument = argv[index + 1]
        if not argument:
            raise ValueError(f"{option} needs a non-empty {kind}; {USAGE}")
        values[option] = argument
        index += 2
    missing = [option for option in REQUIRED_OPTIONS if option not in values]
    if missing:
        raise ValueError(f"missing {', '.join(missing)}; {USAGE}")
    if len(positionals) > MAXIMUM_POSITIONAL_ARGUMENTS:
        raise ValueError(
            f"the dispatcher passes an interface and an action, got {' '.join(positionals)}"
        )
    if positionals and CAPTURE_OPTION in values:
        raise ValueError(
            f"{CAPTURE_OPTION} already names the interface, so the dispatcher's own "
            f"arguments do not belong on the same command line: {' '.join(positionals)}"
        )
    return _Request(
        state_file=values["--state-file"],
        lock_file=values["--lock-file"],
        capture=values.get(CAPTURE_OPTION, ""),
        positionals=positionals,
    )


def _interface(env: Mapping[str, str], positionals: Sequence[str]) -> str:
    """Return the interface this event is about.

    The dispatcher's own first positional argument is this event's interface, so
    it is consulted after ``DEVICE_IP_IFACE`` -- the field NetworkManager defines
    for the same thing, and the most specific one -- and before the two older
    names the dispatcher also exports. ``NM_DISPLAY_NAME`` is a connection
    profile's human-readable name, never a device name, so it is not consulted.

    The value is validated here rather than left to the collector, because the
    down path never collects and would otherwise publish an interface name no
    kernel device could own. An event with no interface at all is rejected: the
    addresses it carries have no meaning without one.
    """
    candidates = [(INTERFACE_VARIABLES[0], env.get(INTERFACE_VARIABLES[0], ""))]
    candidates.append(("the dispatcher's interface argument", positionals[0] if positionals else ""))
    candidates.extend((variable, env.get(variable, "")) for variable in INTERFACE_VARIABLES[1:])
    for variable, value in candidates:
        if not value:
            continue
        if is_interface_name(value):
            return value
        raise ValueError(f"{variable} is not a network interface name: {value!r}")
    raise ValueError(
        f"no interface in {INTERFACE_VARIABLES[0]}, the dispatcher's interface argument, "
        f"{' or '.join(INTERFACE_VARIABLES[1:])}; NM_DISPLAY_NAME is a connection name and "
        "is never used as an interface"
    )


def _observed_now() -> datetime.datetime:
    """Return the time of this event, which is when the addresses are observed."""
    return datetime.datetime.now(datetime.timezone.utc)


def _fail(code: int, message: str) -> int:
    """Report a failure on the dispatcher's own error stream and return ``code``.

    The dispatcher collects the program's standard error into the NetworkManager
    log, so a rejected event says why in one line instead of leaving an operator
    with a silent exit status.
    """
    sys.stderr.write(f"mosdns-dhcp-bridge: {message}\n")
    return code


def real_runner(argv: Sequence[str]) -> str:
    """Run one read-only command and return its standard output.

    The command is an argument array and never a shell string, so an interface
    name or an address that reaches this function cannot be reinterpreted. A
    non-zero status, a missing binary, and a command that outruns the timeout all
    raise, which the collector reads as "this source could not be read".
    """
    completed = subprocess.run(
        list(argv),
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    return completed.stdout


def console_entry() -> int:
    """Run the bridge for the process the dispatcher started."""
    return main(sys.argv[1:], os.environ, real_runner)


if __name__ == "__main__":
    sys.exit(console_entry())
