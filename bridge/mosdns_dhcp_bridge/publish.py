"""Publish the versioned DHCP DNS state the router's resolver plugin reads.

This module is the only writer of the DHCP state document. Three properties
make the published file safe for a fail-closed reader to trust:

* **Serialised.** One exclusive advisory lock on a dedicated lock file, never on
  the state file itself, so two dispatcher events cannot interleave a
  read-compare-write sequence and a state file that a stale process happens to
  hold open cannot block publication.
* **Validated.** An existing state is decoded strictly -- exact key set, no
  duplicate keys, schema 1, a positive generation, an interface and source the
  Go state validator accepts, an RFC 3339 UTC observation time, and a
  last-good marker consistent with the upstream list -- because a generation
  the reader cannot trust is worse than a missing one. A state that fails is
  reported and left in place instead of being overwritten.
* **Atomic.** A same-directory temporary file is written, flushed, synced,
  narrowed to 0640, and renamed over the target, and the directory entry is
  synced afterwards, so a reader sees either the previous document or the next
  one. A failure before the rename leaves the previous document untouched.

An event that would record the same state writes nothing at all, so a DHCP lease
renewal that names the same resolvers cannot invalidate the plugin's in-memory
generation or its cache.
"""

from __future__ import annotations

import contextlib
import datetime
import errno
import fcntl
import json
import os
import re
import uuid
from typing import Any, Dict, Iterator, List, NamedTuple, Optional, Sequence, Tuple

from .collect import is_interface_name, normalize_upstreams, usable_address

__all__ = [
    "InvalidStateError",
    "LockUnavailable",
    "PublicationError",
    "publish_if_changed",
]


class InvalidStateError(ValueError):
    """The existing state file is not a state document the reader can trust."""


class LockUnavailable(Exception):
    """Another bridge process holds the publication lock."""


class PublicationError(OSError):
    """The state could not be committed; whatever was published before stands."""


# The schema version the Go ``state.DHCPState`` decoder requires. It is written
# into every document rather than assumed, so a future reader can tell which
# contract produced the file.
SCHEMA_VERSION = 1

# The field order mirrors the Go struct declaration, so a document produced here
# is byte-identical to the one the Go writer would produce for the same values.
STATE_FIELDS = (
    "schema_version",
    "generation",
    "interface",
    "connection_uuid",
    "upstreams",
    "observed_at",
    "source",
    "last_good",
)

# The observation time is the one timestamp the plugin reads. It is written in
# whole UTC seconds, which is the shortest form RFC 3339 requires and the form
# Go's time.Time marshals to; sub-second precision would not survive a JSON
# round trip through the Go reader anyway.
OBSERVED_AT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
OBSERVED_AT_EXAMPLE = "2026-09-25T00:00:00Z"

# The same bound the Go state validator applies to a source token, so a token
# this module accepts is one ``DHCPState.Validate`` accepts.
MAXIMUM_SOURCE_LENGTH = 32
_SOURCE_TOKEN = re.compile(r"[a-z0-9][a-z0-9-]{0,%d}\Z" % (MAXIMUM_SOURCE_LENGTH - 1))

# A dedicated lock file next to the state, never the state itself: the state is
# read by another program and is replaced by rename, so neither its name nor its
# inode can be the thing two writers agree on.
DEFAULT_LOCK_NAME = "dhcp-bridge.lock"

# The exact modes the runtime state carries whatever the caller's umask is. The
# state file holds the DNS servers a query is sent to, so it is readable by the
# router and nobody else.
STATE_FILE_MODE = 0o640
LOCK_FILE_MODE = 0o640
DIRECTORY_MODE = 0o750

# A fixed temporary name is safe because the publication lock is held for the
# whole write, and a name next to the target keeps the rename on one filesystem
# so it stays atomic.
TEMPORARY_SUFFIX = ".tmp"


class _Record(NamedTuple):
    """The published facts that decide whether an event changes the state.

    ``last_good`` is derived from the upstream list rather than accepted from the
    caller: a state with resolvers is good and a state without any is disabled,
    and a caller that could disagree with that would publish a file the Go
    reader rejects.
    """

    interface: str
    connection_uuid: str
    upstreams: List[str]
    source: str
    last_good: bool


def publish_if_changed(
    path: str,
    *,
    interface: str,
    upstreams: Sequence[str],
    source: str,
    now: datetime.datetime,
    connection_uuid: str = "",
    lock_path: Optional[str] = None,
) -> bool:
    """Publish the DHCP DNS state to ``path`` when it differs from what is there.

    ``interface`` is the device the event is about, ``upstreams`` the addresses
    the collector returned, ``source`` the token naming the event that collected
    them, ``now`` the UTC time the addresses were observed, and
    ``connection_uuid`` the NetworkManager profile the lease belongs to, which
    may be empty for an event that has no connection.

    Returns True when a new state was published and False when the recorded state
    already said the same thing, in which case the file is not opened for
    writing. A state that disables the branch for an interface the published
    state does not describe is also reported unchanged and written nowhere: it
    says nothing about the interface that is currently forwarding. Raises
    ValueError for an input the Go state validator would refuse,
    InvalidStateError for an existing state file that is not a valid document,
    LockUnavailable when another bridge process holds the lock, and
    PublicationError when the new state could not be committed.
    """
    if not isinstance(path, str) or not path:
        raise ValueError(f"state path must be a non-empty path, got {path!r}")
    record = _new_record(interface, connection_uuid, upstreams, source)
    observed_at = _observed_at(now)
    lock = default_lock_path(path) if lock_path is None else lock_path
    with _held_lock(lock):
        existing = _existing_state(path)
        if existing is not None and _identity(existing[1]) == _identity(record):
            return False
        if existing is not None and not _may_replace(existing[1], record):
            return False
        generation = 1 if existing is None else existing[0] + 1
        _commit(path, _document(generation, record, observed_at))
    return True


def _may_replace(existing: _Record, incoming: _Record) -> bool:
    """Report whether ``incoming`` may take the state away from ``existing``.

    One file describes one router's domestic resolvers, and a machine can run
    several NetworkManager connections. A state that disables the branch is a
    claim that this interface lost its lease, and a laptop interface that comes
    up with no DNS makes no such claim about the WAN interface that is
    forwarding every query, so it is recorded nowhere and nothing is written.
    Only an interface that actually carries resolvers takes ownership, because
    that is a real change of the WAN the queries go to.
    """
    if incoming.interface == existing.interface:
        return True
    return incoming.last_good


def _new_record(
    interface: str, connection_uuid: str, upstreams: Sequence[str], source: str
) -> _Record:
    """Validate the event and return the facts it would publish.

    Every check here is one the Go state reader applies to the same fields, so a
    value that reaches the file is a value the router can use. The address rules
    are the collector's, reused rather than restated: a second copy of "which
    address may be forwarded to" is how the two halves of the bridge drift apart.
    """
    if not is_interface_name(interface):
        raise ValueError(f"interface is not a network interface name: {interface!r}")
    if not _is_source_token(source):
        raise ValueError(f"source must be a lowercase token such as dhcp4: {source!r}")
    if not isinstance(upstreams, (list, tuple)) or not all(
        isinstance(value, str) for value in upstreams
    ):
        raise ValueError(f"upstreams must be a list of address strings, got {upstreams!r}")
    addresses = []
    for value in upstreams:
        # The canonical form is required, not recomputed: an address that would
        # be rewritten on the way in is an event that silently publishes
        # something other than what the collector reported.
        if usable_address(value) != value:
            raise ValueError(f"upstream is not a bare address usable for a query: {value!r}")
        addresses.append(value)
    if connection_uuid and not _is_connection_uuid(connection_uuid):
        raise ValueError(f"connection_uuid must be a canonical UUID: {connection_uuid!r}")
    record = _Record(
        interface=interface,
        connection_uuid=connection_uuid,
        # The order a caller or a previous document used is normalised away here,
        # so an event that names the same resolvers in another order is the same
        # state rather than a new generation.
        upstreams=normalize_upstreams(addresses),
        source=source,
        last_good=bool(addresses),
    )
    if record.last_good and not record.connection_uuid:
        raise ValueError("a state with upstreams must record its connection_uuid")
    return record


def _observed_at(now: datetime.datetime) -> str:
    """Return ``now`` as the RFC 3339 UTC timestamp the state records."""
    if not isinstance(now, datetime.datetime):
        raise ValueError(f"now must be a datetime: {now!r}")
    return now.astimezone(datetime.timezone.utc).strftime(OBSERVED_AT_FORMAT)


def _identity(record: _Record) -> Tuple[Any, ...]:
    """Return the fields whose sameness makes two events one state.

    The observation time is deliberately absent: a lease that renews with the
    same resolvers at a later second is not a new generation, and writing it
    would make the plugin reload and drop its cache for nothing.
    """
    return (
        record.interface,
        record.connection_uuid,
        tuple(record.upstreams),
        record.source,
        record.last_good,
    )


def _document(generation: int, record: _Record, observed_at: str) -> Dict[str, Any]:
    """Return the state document for ``record`` at ``generation``."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": generation,
        "interface": record.interface,
        "connection_uuid": record.connection_uuid,
        "upstreams": list(record.upstreams),
        "observed_at": observed_at,
        "source": record.source,
        "last_good": record.last_good,
    }


@contextlib.contextmanager
def _held_lock(lock_path: str) -> Iterator[None]:
    """Hold the publication lock for the duration of one publication.

    The lock is taken without waiting: a dispatcher event that cannot publish
    immediately must fail loudly and let NetworkManager carry on rather than
    block the rest of the dispatcher's work behind a stuck predecessor. The
    descriptor is read-only, so a process that holds the publication lock has no
    way to modify the state the lock protects, and closing it releases the lock.
    """
    _ensure_directory(lock_path)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDONLY, LOCK_FILE_MODE)
    try:
        # The mode argument is applied only when the file is created and the
        # umask can narrow it, so the exact mode is pinned on every acquire.
        os.fchmod(descriptor, LOCK_FILE_MODE)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise LockUnavailable(
                    f"{lock_path}: another bridge process holds the publication lock"
                ) from None
            raise PublicationError(f"{lock_path}: lock: {error}") from None
        yield
    finally:
        os.close(descriptor)


def _existing_state(path: str) -> Optional[Tuple[int, _Record]]:
    """Return the published generation and record, or None when there is none.

    An existing state is validated in full before it is used, and a state that
    cannot be trusted is reported instead of replaced: overwriting it would
    discard the evidence of whatever wrote it, and publishing on top of a
    generation this module never validated would make the file's history
    unreviewable.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return None
    except UnicodeDecodeError as error:
        # A state file that is not text is invalid state, not a rejected request,
        # and a decode error would otherwise be reported as a bad argument.
        raise InvalidStateError(f"{path}: is not a state document: {error}") from None
    return _decode(path, text)


def _decode(path: str, text: str) -> Tuple[int, _Record]:
    """Return the generation and record of a valid state document.

    Every rejection names the field that failed, because the only reader of this
    module is whoever has to fix the file.
    """
    try:
        document = json.loads(text, object_pairs_hook=_object)
    except ValueError as error:
        raise InvalidStateError(f"{path}: is not a state document: {error}") from None
    if not isinstance(document, dict):
        raise InvalidStateError(f"{path}: must be a JSON object")
    _require_keys(path, document)
    _require_schema(path, document["schema_version"])
    generation = _existing_generation(path, document["generation"])
    record = _existing_record(path, document)
    return generation, record


def _object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Return a JSON object, refusing a key the document names twice.

    ``json.loads`` keeps the last value for a repeated key, which would let a
    document hide a second value for any field from this validator while a
    different parser read the first.
    """
    document: Dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate key {key!r}")
        document[key] = value
    return document


def _require_keys(path: str, document: Dict[str, Any]) -> None:
    """Reject a document that does not carry exactly the state fields."""
    present = set(document)
    if present != set(STATE_FIELDS):
        raise InvalidStateError(
            f"{path}: fields must be exactly {sorted(STATE_FIELDS)}, got {sorted(present)}"
        )


def _require_schema(path: str, value: Any) -> None:
    """Reject a document written against a different state contract.

    ``type(...) is int`` rather than ``isinstance`` because JSON true and false
    decode to booleans, which are integers in Python.
    """
    if type(value) is not int or value != SCHEMA_VERSION:
        raise InvalidStateError(
            f"{path}: schema_version must be {SCHEMA_VERSION}, got {value!r}"
        )


def _existing_generation(path: str, value: Any) -> int:
    """Return a positive integer generation.

    ``type(...) is int`` rather than ``isinstance`` for the same reason as
    ``_require_schema``: a state whose generation is ``true`` has no generation.
    """
    if type(value) is not int or value < 1:
        raise InvalidStateError(f"{path}: generation must be a positive integer, got {value!r}")
    return value


def _existing_record(path: str, document: Dict[str, Any]) -> _Record:
    """Return the validated record of an existing state document.

    The field rules are the ones a new event is held to, run through
    ``_new_record`` and re-labelled as invalid state, because a second copy of
    "which interface, source, address, and uuid may be recorded" is exactly how a
    writer and its reader drift apart. Only the two fields a caller supplies
    rather than derives are checked here: the observation time, and the last-good
    marker, which must agree with the upstream list the document actually carries.
    """
    last_good = document["last_good"]
    if type(last_good) is not bool:
        raise InvalidStateError(f"{path}: last_good must be a boolean, got {last_good!r}")
    _require_observed_at(path, document["observed_at"])
    try:
        record = _new_record(
            document["interface"],
            document["connection_uuid"],
            document["upstreams"],
            document["source"],
        )
    except ValueError as error:
        raise InvalidStateError(f"{path}: {error}") from None
    if last_good != record.last_good:
        raise InvalidStateError(
            f"{path}: last_good={last_good} contradicts {len(record.upstreams)} upstream(s)"
        )
    return record


def _require_observed_at(path: str, value: Any) -> None:
    """Reject an observation time that is not this publisher's UTC format."""
    if not isinstance(value, str) or len(value) != len(OBSERVED_AT_EXAMPLE):
        raise InvalidStateError(
            f"{path}: observed_at must be an RFC 3339 UTC time like {OBSERVED_AT_EXAMPLE}, "
            f"got {value!r}"
        )
    try:
        datetime.datetime.strptime(value, OBSERVED_AT_FORMAT)
    except ValueError:
        raise InvalidStateError(
            f"{path}: observed_at must be an RFC 3339 UTC time like {OBSERVED_AT_EXAMPLE}, "
            f"got {value!r}"
        ) from None


def _commit(path: str, document: Dict[str, Any]) -> None:
    """Write ``document`` to ``path`` atomically.

    The temporary file is created in the target's own directory so the rename
    cannot cross a filesystem, and it is only ever renamed after the complete
    document is on disk. Anything that fails before the rename leaves the
    previous state in place, and a temporary file that could not be removed is
    reported instead of left behind in the runtime directory.
    """
    _ensure_directory(path)
    directory = os.path.dirname(path) or "."
    temporary = path + TEMPORARY_SUFFIX
    payload = json.dumps(document, indent=2) + "\n"
    try:
        handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, STATE_FILE_MODE)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            # Pinned after the sync because the mode belongs to the inode this
            # file already is; the rename below publishes that inode, so the
            # target's mode is the one set here.
            os.fchmod(stream.fileno(), STATE_FILE_MODE)
        os.replace(temporary, path)
    except OSError as error:
        raise PublicationError(
            " ".join(filter(None, [f"{path}: write state: {error}", _discard(temporary)]))
        ) from None
    try:
        _sync_directory(directory)
    except OSError as error:
        raise PublicationError(
            f"{path}: the new state is in place but the directory entry is not durable: {error}"
        ) from None


def _discard(temporary: str) -> str:
    """Remove a temporary file, reporting a failure to do so."""
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        return ""
    except OSError as error:
        return f"remove {temporary}: {error}"
    return ""


def _sync_directory(directory: str) -> None:
    """Sync the directory entry so a renamed file survives a power loss."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_directory(path: str) -> None:
    """Create the directory of ``path`` with the runtime mode when it is absent.

    The mode is pinned on a directory this module creates, because the umask
    would otherwise leave the runtime state readable only by its owner. A
    directory that already exists is left as it is: its ownership and its
    default ACLs belong to the packaging, not to the bridge.
    """
    directory = os.path.dirname(path) or "."
    if os.path.isdir(directory):
        return
    os.makedirs(directory, mode=DIRECTORY_MODE, exist_ok=True)
    os.chmod(directory, DIRECTORY_MODE)


def _is_source_token(source: Any) -> bool:
    """Report whether ``source`` is a token the Go state validator accepts."""
    return isinstance(source, str) and _SOURCE_TOKEN.match(source) is not None


def _is_connection_uuid(connection_uuid: str) -> bool:
    """Report whether ``connection_uuid`` is the canonical form of a UUID."""
    try:
        return str(uuid.UUID(connection_uuid)) == connection_uuid
    except (AttributeError, TypeError, ValueError):
        return False


def default_lock_path(path: str) -> str:
    """Return the dedicated lock file that belongs to the state at ``path``."""
    return os.path.join(os.path.dirname(path) or ".", DEFAULT_LOCK_NAME)
