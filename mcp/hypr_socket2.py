"""Small, dependency-free client for Hyprland's ``.socket2.sock`` event stream.

The helpers in this module deliberately do not call ``hyprctl``.  They first
wait on the compositor event stream and only invoke a caller supplied polling
fallback when one was explicitly provided.  Results disclose which endpoint
source produced them plus a path digest, never the absolute socket path.

An explicit ``socket_path`` (or ``HYPR_AGENT_PORTAL_SOCKET2_PATH``) is useful
for tests and for the short Unix-socket paths used by the isolated runner.
Normal sessions are resolved from ``XDG_RUNTIME_DIR`` and
``HYPRLAND_INSTANCE_SIGNATURE``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
from typing import Any


SOCKET_PATH_ENV = "HYPR_AGENT_PORTAL_SOCKET2_PATH"
_SOCKET_NAME = ".socket2.sock"
_READ_SIZE = 64 * 1024
_MAX_EVENT_LINE_BYTES = 1024 * 1024
_MAX_TOTAL_BYTES = 1024 * 1024
_MAX_EVENT_FIELDS = 16


class Socket2Error(RuntimeError):
    """Base error for socket2 configuration failures."""


class Socket2ConfigurationError(Socket2Error):
    """The Hyprland socket path cannot be resolved safely."""


class Socket2ProtocolError(Socket2Error):
    """The socket2 peer exceeded a bounded event-stream contract."""


@dataclass(frozen=True)
class _SocketIdentity:
    device: int
    inode: int
    uid: int


def _socket_source(
    socket_path: str | os.PathLike[str] | None,
    environ: Mapping[str, str] | None,
) -> str:
    if socket_path is not None:
        return "explicit"
    env = os.environ if environ is None else environ
    if env.get(SOCKET_PATH_ENV):
        return "environment_override"
    return "hyprland_session"


def _path_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(os.fsencode(path)).hexdigest()}"


def _validate_socket_path(path: Path) -> _SocketIdentity:
    """Validate a same-user Unix socket without following a final symlink.

    ``lstat`` gives a portable early rejection.  On Linux, an ``O_PATH``
    descriptor pins the directory entry long enough for ``fstat`` to confirm
    the same inode before connect.  The caller keeps the returned identity and
    checks it again after connect to detect a pathname replacement race.
    """

    try:
        before = os.lstat(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise Socket2ConfigurationError(
            f"cannot inspect socket2 endpoint: {type(exc).__name__}: {exc.strerror or 'I/O error'}"
        ) from exc
    if stat.S_ISLNK(before.st_mode):
        raise Socket2ConfigurationError("socket2 endpoint must not be a symlink")
    if not stat.S_ISSOCK(before.st_mode):
        raise Socket2ConfigurationError("socket2 endpoint must be a Unix socket")
    if before.st_uid != os.getuid():
        raise Socket2ConfigurationError("socket2 endpoint must be owned by the current uid")

    flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise Socket2ConfigurationError(
            f"cannot securely open socket2 endpoint: {type(exc).__name__}: {exc.strerror or 'I/O error'}"
        ) from exc
    try:
        pinned = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISSOCK(pinned.st_mode):
        raise Socket2ConfigurationError("socket2 endpoint changed to a non-socket")
    identity = _SocketIdentity(before.st_dev, before.st_ino, before.st_uid)
    if (pinned.st_dev, pinned.st_ino, pinned.st_uid) != (
        identity.device,
        identity.inode,
        identity.uid,
    ):
        raise Socket2ConfigurationError("socket2 endpoint changed during validation")
    return identity


def _verify_socket_identity(path: Path, identity: _SocketIdentity) -> None:
    """Reject replacement of the validated pathname during ``connect``."""

    try:
        current = os.lstat(path)
    except OSError as exc:
        raise Socket2ConfigurationError(
            f"socket2 endpoint disappeared during connect: {type(exc).__name__}: {exc.strerror or 'I/O error'}"
        ) from exc
    if not stat.S_ISSOCK(current.st_mode) or current.st_uid != os.getuid():
        raise Socket2ConfigurationError("socket2 endpoint became unsafe during connect")
    if (current.st_dev, current.st_ino, current.st_uid) != (
        identity.device,
        identity.inode,
        identity.uid,
    ):
        raise Socket2ConfigurationError("socket2 endpoint was replaced during connect")


def _verify_peer_uid(connection: socket.socket) -> None:
    """Require the connected compositor peer to run as the current uid."""

    if not hasattr(socket, "SO_PEERCRED"):
        raise Socket2ConfigurationError("SO_PEERCRED is required to authenticate socket2")
    try:
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", credentials)
    except (OSError, struct.error) as exc:
        raise Socket2ConfigurationError(
            f"cannot authenticate socket2 peer: {type(exc).__name__}"
        ) from exc
    if uid != os.getuid():
        raise Socket2ConfigurationError("socket2 peer must run as the current uid")


def resolve_socket2_path(
    socket_path: str | os.PathLike[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the event socket, allowing an explicit short-path injection.

    Resolution order is the function argument, the portal-specific override,
    then ``$XDG_RUNTIME_DIR/hypr/$HYPRLAND_INSTANCE_SIGNATURE/.socket2.sock``.
    Relative paths and NUL bytes are rejected before connecting.
    """

    env = os.environ if environ is None else environ
    configured = socket_path if socket_path is not None else env.get(SOCKET_PATH_ENV)
    if configured is None:
        runtime = env.get("XDG_RUNTIME_DIR")
        signature = env.get("HYPRLAND_INSTANCE_SIGNATURE")
        if not runtime or not signature:
            raise Socket2ConfigurationError(
                "XDG_RUNTIME_DIR and HYPRLAND_INSTANCE_SIGNATURE are required "
                f"unless {SOCKET_PATH_ENV} is set"
            )
        if signature in {".", ".."} or "/" in signature or "\x00" in signature:
            raise Socket2ConfigurationError("invalid HYPRLAND_INSTANCE_SIGNATURE")
        configured = Path(runtime) / "hypr" / signature / _SOCKET_NAME

    text = os.fspath(configured)
    if "\x00" in text:
        raise Socket2ConfigurationError("socket path contains a NUL byte")
    path = Path(text)
    if not path.is_absolute():
        raise Socket2ConfigurationError("socket path must be absolute")
    return path


@dataclass(frozen=True)
class HyprlandEvent:
    """A parsed Hyprland event line."""

    name: str
    payload: str
    fields: tuple[str, ...]
    received_at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "payload": self.payload,
            "fields": list(self.fields),
            "receivedAt": self.received_at,
        }


def parse_event_line(line: bytes | str, *, received_at: float | None = None) -> HyprlandEvent | None:
    """Parse ``event>>comma,separated,payload``; malformed lines are ignored."""

    if isinstance(line, bytes):
        text = line.decode("utf-8", errors="replace")
    else:
        text = line
    text = text.rstrip("\r\n")
    if ">>" not in text:
        return None
    name, payload = text.split(">>", 1)
    name = name.strip()
    if not name:
        return None
    # Hyprland's supported events use at most four structured fields here.
    # Keep a little forward-compatible headroom while preventing a comma-dense
    # peer payload from expanding one bounded line into millions of objects.
    fields = tuple(payload.split(",", _MAX_EVENT_FIELDS - 1)) if payload else ()
    return HyprlandEvent(name, payload, fields, time.monotonic() if received_at is None else received_at)


def _normal_address(value: str) -> str:
    value = value.strip().lower()
    return value[2:] if value.startswith("0x") else value


def event_details(event: HyprlandEvent) -> dict[str, str]:
    """Return named fields for window/workspace events used by wait helpers."""

    fields = event.fields
    details: dict[str, str] = {}
    if event.name == "openwindow" and fields:
        keys = ("address", "workspace", "class", "title")
        # Window titles may contain commas; preserve them as part of the title.
        for index, key in enumerate(keys[: min(3, len(fields))]):
            details[key] = fields[index]
        if len(fields) >= 4:
            details["title"] = ",".join(fields[3:])
    elif event.name in {"closewindow", "activewindowv2"} and fields:
        details["address"] = fields[0]
    elif event.name in {"workspace", "createworkspace", "destroyworkspace"} and fields:
        details["workspace"] = fields[0]
    elif event.name in {"workspacev2", "createworkspacev2", "destroyworkspacev2"} and fields:
        details["workspaceId"] = fields[0]
        if len(fields) > 1:
            details["workspace"] = ",".join(fields[1:])
    elif event.name == "movewindow" and fields:
        details["address"] = fields[0]
        if len(fields) > 1:
            details["workspace"] = ",".join(fields[1:])
    elif event.name == "movewindowv2" and fields:
        details["address"] = fields[0]
        if len(fields) > 1:
            details["workspaceId"] = fields[1]
        if len(fields) > 2:
            details["workspace"] = ",".join(fields[2:])
    return details


Predicate = Callable[[HyprlandEvent], bool]
Fallback = Callable[[], Any]


def _result(
    status: str,
    *,
    path: Path,
    source: str,
    event: HyprlandEvent | None,
    reconnects: int,
    connected: bool,
    reason: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "status": status,
        "method": "socket2",
        "eventDriven": True,
        "socket": {"source": source, "pathDigest": _path_digest(path)},
        "connected": connected,
        "reconnects": reconnects,
        "pollFallback": {"used": False, "available": False},
    }
    if event is not None:
        value["event"] = event.as_dict()
        value["details"] = event_details(event)
    if reason:
        value["reason"] = reason
    return value


def sanitize_event_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Return privacy-safe wait metadata without event titles or class names.

    Only bounded, allowlisted transport diagnostics, the already-digested
    endpoint identifier, and a validated window address survive.  In
    particular, raw ``event`` payloads/fields, titles, class names, paths, and
    fallback result objects are never copied.
    """

    if not isinstance(result, Mapping):
        return {}
    sanitized: dict[str, Any] = {}
    method = result.get("method")
    if method in {"socket2", "poll", "existing"}:
        sanitized["method"] = method
    status = result.get("status")
    if status in {"matched", "timeout", "transport_unavailable"}:
        sanitized["status"] = status
    reconnects = result.get("reconnects")
    if isinstance(reconnects, int) and not isinstance(reconnects, bool) and reconnects >= 0:
        sanitized["reconnects"] = reconnects

    socket_info = result.get("socket")
    digest = socket_info.get("pathDigest") if isinstance(socket_info, Mapping) else result.get("pathDigest")
    if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
        sanitized["pathDigest"] = digest.casefold()

    candidates: list[Any] = [result.get("address")]
    details = result.get("details")
    if isinstance(details, Mapping):
        candidates.append(details.get("address"))
    for candidate in candidates:
        if isinstance(candidate, str) and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", candidate):
            sanitized["address"] = candidate
            break
    return sanitized


def _apply_fallback(result: dict[str, Any], fallback: Fallback | None) -> dict[str, Any]:
    if fallback is None:
        result["pollFallback"] = {
            "used": False,
            "available": False,
            "reason": result.get("reason", result["status"]),
        }
        return result
    try:
        fallback_value = fallback()
    except Exception as exc:  # The caller still receives the socket diagnosis.
        result["pollFallback"] = {
            "used": True,
            "available": True,
            "matched": False,
            "error": _fallback_error(exc),
        }
        return result
    result["method"] = "poll"
    result["eventDriven"] = False
    result["pollFallback"] = {
        "used": True,
        "available": True,
        "matched": bool(fallback_value),
        "result": _sanitize_fallback_value(fallback_value),
    }
    if fallback_value:
        result["status"] = "matched"
    return result


def _hidden_value(value: Any) -> dict[str, Any]:
    try:
        encoded = os.fsencode(value) if isinstance(value, os.PathLike) else str(value).encode("utf-8", "replace")
    except TypeError:
        encoded = repr(value).encode("utf-8", "replace")
    return {
        "redacted": True,
        "digest": f"sha256:{hashlib.sha256(encoded).hexdigest()}",
        "length": len(encoded),
    }


def _path_result_key(key: Any) -> bool:
    normalized = str(key).casefold().replace("-", "_")
    return normalized.endswith("path") or normalized in {
        "cwd", "dir", "directory", "dirname", "file", "filename", "runtime_dir", "working_directory"
    }


def _sanitize_fallback_value(value: Any) -> Any:
    """Keep polling diagnostics useful without returning filesystem paths."""

    if isinstance(value, os.PathLike):
        return _hidden_value(value)
    if isinstance(value, str):
        return _hidden_value(value) if os.path.isabs(value) else value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _hidden_value(item) if _path_result_key(key) else _sanitize_fallback_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize_fallback_value(item) for item in value]
    return {"type": type(value).__name__, "omitted": True}


def _fallback_error(exc: Exception) -> str:
    if isinstance(exc, OSError):
        return f"{type(exc).__name__}: {exc.strerror or 'poll fallback failed'}"
    return f"{type(exc).__name__}: poll fallback failed"


def _transport_error(exc: OSError) -> str:
    """Describe a transport failure without echoing its absolute filename."""

    return f"{type(exc).__name__}: {exc.strerror or 'socket transport error'}"


def wait_for_event(
    event_names: str | Sequence[str],
    predicate: Predicate | None = None,
    *,
    timeout: float = 5.0,
    socket_path: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    reconnect_delay: float = 0.05,
    poll_fallback: Fallback | None = None,
) -> dict[str, Any]:
    """Wait for a matching socket2 event, reconnecting until ``timeout``.

    A clean EOF, a startup race where the socket does not exist yet, and
    transient connection errors are retried.  ``poll_fallback`` is never
    implicit and, when used, changes ``method`` to ``poll`` in the result.
    """

    if timeout < 0:
        raise ValueError("timeout must be non-negative")
    if reconnect_delay < 0:
        raise ValueError("reconnect_delay must be non-negative")
    names = {event_names} if isinstance(event_names, str) else set(event_names)
    if not names or not all(isinstance(item, str) and item for item in names):
        raise ValueError("event_names must contain at least one non-empty name")
    encoded_names = {name.encode("utf-8") for name in names}
    path = resolve_socket2_path(socket_path, environ=environ)
    source = _socket_source(socket_path, environ)
    deadline = time.monotonic() + timeout
    reconnects = 0
    ever_connected = False
    last_error: str | None = None
    buffer = b""
    total_received = 0

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status = "timeout" if ever_connected else "transport_unavailable"
            reason = last_error or "no matching event before timeout"
            return _apply_fallback(
                _result(status, path=path, source=source, event=None, reconnects=reconnects,
                        connected=ever_connected, reason=reason),
                poll_fallback,
            )

        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            identity = _validate_socket_path(path)
            connection.settimeout(min(remaining, 0.25))
            connection.connect(os.fspath(path))
            _verify_socket_identity(path, identity)
            _verify_peer_uid(connection)
            ever_connected = True
            buffer = b""
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return _apply_fallback(
                        _result("timeout", path=path, source=source, event=None, reconnects=reconnects,
                                connected=True, reason="no matching event before timeout"),
                        poll_fallback,
                    )
                connection.settimeout(min(remaining, 0.25))
                try:
                    chunk = connection.recv(_READ_SIZE)
                except socket.timeout:
                    continue
                if not chunk:
                    last_error = "socket2 stream closed"
                    reconnects += 1
                    break
                buffer += chunk
                pieces = buffer.split(b"\n")
                buffer = pieces.pop()
                if any(len(raw) > _MAX_EVENT_LINE_BYTES for raw in pieces) or len(buffer) > _MAX_EVENT_LINE_BYTES:
                    raise Socket2ProtocolError("socket2 event line exceeded the 1 MiB byte limit")
                total_received += len(chunk)
                if total_received > _MAX_TOTAL_BYTES:
                    raise Socket2ProtocolError("socket2 stream exceeded the 1 MiB total byte limit")
                for raw in pieces:
                    separator = raw.find(b">>")
                    if separator <= 0 or raw[:separator].strip() not in encoded_names:
                        continue
                    event = parse_event_line(raw)
                    if event is None:
                        continue
                    if predicate is None or predicate(event):
                        return _result("matched", path=path, source=source, event=event,
                                       reconnects=reconnects, connected=True)
        except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError, OSError) as exc:
            last_error = _transport_error(exc)
            reconnects += 1
        finally:
            connection.close()

        remaining = deadline - time.monotonic()
        if remaining > 0 and reconnect_delay:
            time.sleep(min(reconnect_delay, remaining))


def _window_matches(event: HyprlandEvent, filters: Mapping[str, str]) -> bool:
    details = event_details(event)
    aliases = {"class_name": "class", "className": "class"}
    for raw_key, expected in filters.items():
        key = aliases.get(raw_key, raw_key)
        actual = details.get(key)
        if actual is None:
            return False
        if key == "address":
            if _normal_address(actual) != _normal_address(str(expected)):
                return False
        elif str(expected).casefold() not in actual.casefold():
            return False
    return True


def wait_for_window(
    filters: Mapping[str, str] | None = None,
    *,
    timeout: float = 5.0,
    socket_path: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    reconnect_delay: float = 0.05,
    poll_fallback: Fallback | None = None,
) -> dict[str, Any]:
    """Wait for an ``openwindow`` event matching address/class/title/workspace."""

    selected = dict(filters or {})
    allowed = {"address", "workspace", "class", "class_name", "className", "title"}
    unknown = set(selected) - allowed
    if unknown:
        raise ValueError(f"unsupported window filter(s): {', '.join(sorted(unknown))}")
    return wait_for_event(
        "openwindow",
        lambda event: _window_matches(event, selected),
        timeout=timeout,
        socket_path=socket_path,
        environ=environ,
        reconnect_delay=reconnect_delay,
        poll_fallback=poll_fallback,
    )


def wait_for_close(
    address: str,
    *,
    timeout: float = 5.0,
    socket_path: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    reconnect_delay: float = 0.05,
    poll_fallback: Fallback | None = None,
) -> dict[str, Any]:
    """Wait for ``closewindow`` for one exact, prefix-insensitive address."""

    if not address.strip():
        raise ValueError("address must be non-empty")
    expected = _normal_address(address)
    return wait_for_event(
        "closewindow",
        lambda event: bool(event.fields) and _normal_address(event.fields[0]) == expected,
        timeout=timeout,
        socket_path=socket_path,
        environ=environ,
        reconnect_delay=reconnect_delay,
        poll_fallback=poll_fallback,
    )


__all__ = [
    "HyprlandEvent",
    "SOCKET_PATH_ENV",
    "Socket2ConfigurationError",
    "Socket2Error",
    "Socket2ProtocolError",
    "event_details",
    "parse_event_line",
    "resolve_socket2_path",
    "sanitize_event_result",
    "wait_for_close",
    "wait_for_event",
    "wait_for_window",
]
