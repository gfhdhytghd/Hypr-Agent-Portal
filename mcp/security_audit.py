"""Safe audit journaling and replay preflight helpers.

This module deliberately has no dependency on the MCP server.  Callers can add
auditing without coupling the security policy to a transport or UI toolkit.
Journal records are JSON Lines and sensitive input is represented by a digest
unless a caller makes the explicit, discouraged choice to retain plaintext.

Replay is intentionally conservative: :func:`preflight_replay` validates a
journal record but never performs the action.  Its ``execute`` policy flag only
marks validated entries as executable for a separate, policy-enforcing caller.
"""

from __future__ import annotations

import dataclasses
import datetime as _datetime
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping
from typing import Any


SCHEMA_VERSION = 1
DEFAULT_JOURNAL_NAME = "audit.jsonl"
DEFAULT_JOURNAL_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_JOURNAL_BACKUPS = 2
_MAX_CONFIGURED_JOURNAL_BYTES = 1024 * 1024 * 1024
_MAX_CONFIGURED_JOURNAL_BACKUPS = 16
_APPLICATION_DIR = "hypr-agent-portal"
_MAX_SUMMARY_ITEMS = 64
_MAX_SUMMARY_TEXT = 512

_SENSITIVE_EXACT_KEYS = {
    "args",
    "argv",
    "clipboard",
    "clipboard_data",
    "clipboard_text",
    "command",
    "command_line",
    "content",
    "data",
    "input_text",
    "input_path",
    "file_path",
    "filepath",
    "hyprctl_output",
    "journal_path",
    "output",
    "output_path",
    "path",
    "password",
    "query",
    "secret",
    "socket_path",
    "socketpath",
    "source_path",
    "stderr",
    "stdout",
    "target_path",
    "text",
    "token",
    "url",
    "value",
}
_SENSITIVE_KEY_PARTS = ("clipboard", "password", "secret", "token")
_MEDIA_KEY_PARTS = (
    "accessibility",
    "accessibilitytree",
    "base64",
    "dataurl",
    "image",
    "pixels",
    "screenshot",
    "tree",
)
_MEDIA_METADATA_CONTAINERS = {"dimensions", "metadata", "output", "size", "source"}
_MEDIA_METADATA_EXACT_KEYS = {
    "channels",
    "digest",
    "format",
    "height",
    "length",
    "maxdimension",
    "mime",
    "mimetype",
    "quality",
    "sha256",
    "width",
}
_UI_CONTENT_CONTAINER_KEYS = {
    "activerelatedwindow",
    "elements",
    "globalmenu",
    "relatedwindow",
    "relatedwindows",
    "uihints",
}
_UI_TEXT_KEYS = {
    "description",
    "initialtitle",
    "label",
    "message",
    "name",
    "notes",
    "placeholder",
    "title",
    "tooltip",
    "windowtitle",
}
_EPHEMERAL_KEY_RE = re.compile(r"(?:^|_)(?:element|menu)_index$")
_CLIPBOARD_TOOLS = {
    "copy_text",
    "paste",
    "paste_file",
    "paste_image",
    "paste_text",
    "set_clipboard",
}
_IDENTITY_KEYS = (
    "address",
    "pid",
    "processStartTime",
    "process_start_time",
    "class",
    "initialClass",
    "initial_class",
    "workspace",
)


class AuditError(RuntimeError):
    """Base exception for audit journal failures."""


class UnsafeJournalPath(AuditError):
    """Raised when a journal path escapes its bounded XDG directory."""


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _xdg_root(storage: str) -> pathlib.Path:
    """Return the allowed per-user root for ``state`` or ``runtime`` storage."""

    if storage == "state":
        configured = os.environ.get("XDG_STATE_HOME")
        return pathlib.Path(configured) if configured else pathlib.Path.home() / ".local" / "state"
    if storage == "runtime":
        configured = os.environ.get("XDG_RUNTIME_DIR")
        if not configured:
            raise UnsafeJournalPath("XDG_RUNTIME_DIR is required for runtime journals")
        return pathlib.Path(configured)
    raise ValueError("storage must be 'state' or 'runtime'")


def _is_beneath(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_journal_path(
    name: str | os.PathLike[str] = DEFAULT_JOURNAL_NAME,
    *,
    storage: str = "state",
) -> pathlib.Path:
    """Resolve a journal name below a private XDG application directory.

    ``name`` must be relative.  Parent traversal, absolute paths, and symlinked
    existing targets are rejected so configuration cannot redirect audit data
    to an arbitrary file.  Parent directories are created with mode ``0700``.
    """

    relative = pathlib.Path(name)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise UnsafeJournalPath("journal name must be a non-empty relative path without traversal")

    xdg_root = _xdg_root(storage).expanduser().resolve(strict=False)
    unresolved_root = xdg_root / _APPLICATION_DIR
    if unresolved_root.is_symlink():
        raise UnsafeJournalPath("journal application directory must not be a symlink")
    root = unresolved_root.resolve(strict=False)
    unresolved_candidate = root / relative
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise UnsafeJournalPath("journal path must not contain symlinks")
    candidate = unresolved_candidate.resolve(strict=False)
    if not _is_beneath(candidate, root):
        raise UnsafeJournalPath("journal path escapes the application state directory")

    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    candidate.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if candidate.exists() and candidate.is_symlink():
        raise UnsafeJournalPath("journal target must not be a symlink")
    return candidate


def _digest(value: str | bytes) -> dict[str, Any]:
    raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
    return {
        "redacted": True,
        "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "length": len(value),
        "encoding": "bytes" if isinstance(value, bytes) else "utf-8",
    }


def _sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    compact = _compact_key(key)
    path_like = normalized.endswith("path") or normalized in {
        "cwd",
        "dir",
        "directory",
        "dirname",
        "file",
        "filename",
        "runtime_dir",
        "working_directory",
    }
    return (
        normalized in _SENSITIVE_EXACT_KEYS
        or compact in {"commandline", "hyprctloutput"}
        or compact.endswith("url")
        or path_like
        or any(part in normalized for part in _SENSITIVE_KEY_PARTS)
    )


def _compact_key(key: str) -> str:
    return "".join(character for character in key.casefold() if character.isalnum())


def _media_key(key: str) -> bool:
    """Return whether a key can carry screen or accessibility content.

    This intentionally matches broadly.  Audit records are a persistence
    boundary, so an unfamiliar payload spelling must be omitted rather than
    accidentally retaining the first part of a base64 image or UI tree.
    """

    compact = _compact_key(key)
    return any(part in compact for part in _MEDIA_KEY_PARTS)


def _ui_content_container_key(key: str) -> bool:
    compact = _compact_key(key)
    return compact in _UI_CONTENT_CONTAINER_KEYS or compact.startswith("relatedwindows")


def _ui_text_key(key: str) -> bool:
    compact = _compact_key(key)
    return compact in _UI_TEXT_KEYS or compact.endswith(("title", "label", "tooltip"))


def _redact_ui_content(value: Any) -> dict[str, Any]:
    redacted: dict[str, Any] = {"omitted": True, "type": type(value).__name__}
    if isinstance(value, (list, tuple, set, frozenset, Mapping)):
        redacted["count"] = len(value)
    elif isinstance(value, (str, bytes)):
        redacted.update(_digest(value))
        redacted.pop("redacted", None)
    return redacted


def _media_metadata_key(key: str) -> bool:
    compact = _compact_key(key)
    if compact in _MEDIA_METADATA_EXACT_KEYS:
        return True
    return compact.endswith(("width", "height", "sha256", "hash", "digest", "format", "mime", "mimetype"))


def _safe_media_metadata_scalar(key: str, value: Any) -> Any | None:
    """Validate metadata values before allowing them into a journal."""

    compact = _compact_key(key)
    if compact.endswith(("width", "height")) or compact in {
        "channels",
        "length",
        "maxdimension",
        "quality",
    }:
        return value if value is None or isinstance(value, (bool, int, float)) else None
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    if compact.endswith(("sha256", "hash")):
        return value if re.fullmatch(r"[0-9a-fA-F]{64}", value) else None
    if compact.endswith("digest"):
        return value if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value) else None
    if compact.endswith("format"):
        return value if normalized in {"jpeg", "jpg", "png", "webp"} else None
    if compact.endswith(("mime", "mimetype")):
        return value if normalized in {"image/jpeg", "image/png", "image/webp"} else None
    return None


def _media_metadata(value: Any, *, _depth: int = 0) -> dict[str, Any]:
    """Extract only non-content image size/format/hash metadata."""

    if _depth >= 3 or not isinstance(value, Mapping):
        return {}
    metadata: dict[str, Any] = {}
    for index, (key, item) in enumerate(value.items()):
        if index >= _MAX_SUMMARY_ITEMS:
            break
        key_text = str(key)
        compact = _compact_key(key_text)
        if _media_metadata_key(key_text):
            safe_value = _safe_media_metadata_scalar(key_text, item)
            if safe_value is not None:
                metadata[key_text] = safe_value
        elif compact in _MEDIA_METADATA_CONTAINERS and isinstance(item, Mapping):
            nested = _media_metadata(item, _depth=_depth + 1)
            if nested:
                metadata[key_text] = nested
    return metadata


def _redact_media(value: Any) -> dict[str, Any]:
    """Create a fail-closed representation of persisted visual/UI content."""

    redacted: dict[str, Any] = {"omitted": True, "type": type(value).__name__}
    metadata = _media_metadata(value)
    if metadata:
        redacted["metadata"] = metadata
    elif isinstance(value, (str, bytes)):
        # A digest is useful for correlation without retaining any prefix.
        redacted.update(_digest(value))
        redacted.pop("redacted", None)
    return redacted


def _json_safe(value: Any, *, sensitive: bool, store_sensitive_plaintext: bool) -> Any:
    if sensitive and not store_sensitive_plaintext:
        if isinstance(value, bytes):
            return _digest(value)
        if isinstance(value, str):
            return _digest(value)
        # Composite sensitive values get one canonical digest, avoiding leakage
        # through keys, list lengths, or nested fragments.
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
        return _digest(serialized)

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return _digest(value)
    if isinstance(value, pathlib.PurePath):
        return str(value) if store_sensitive_plaintext else _digest(os.fspath(value))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _json_safe(dataclasses.asdict(value), sensitive=sensitive, store_sensitive_plaintext=store_sensitive_plaintext)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            # Media/UI state is never made plaintext by the general sensitive
            # data opt-in.  Persisting it requires a separate explicit design.
            if _media_key(key_text):
                safe_value = _safe_media_metadata_scalar(key_text, item) if _media_metadata_key(key_text) else None
                result[key_text] = safe_value if safe_value is not None else _redact_media(item)
            elif _ui_content_container_key(key_text):
                result[key_text] = _redact_ui_content(item)
            elif _ui_text_key(key_text):
                serialized = item if isinstance(item, (str, bytes)) else json.dumps(
                    item, sort_keys=True, separators=(",", ":"), default=repr
                )
                result[key_text] = _digest(serialized)
            else:
                result[key_text] = _json_safe(
                    item,
                    sensitive=sensitive or _sensitive_key(key_text),
                    store_sensitive_plaintext=store_sensitive_plaintext,
                )
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            _json_safe(item, sensitive=sensitive, store_sensitive_plaintext=store_sensitive_plaintext)
            for item in value
        ]
    return repr(value)


def sanitize_args(value: Any, *, store_sensitive_plaintext: bool = False) -> Any:
    """Return a JSON-safe argument tree with sensitive values redacted.

    Text-bearing, credential, and clipboard keys are hashed by default.  Raw
    ``bytes`` are always hashed because JSON cannot represent them safely.
    """

    return _json_safe(value, sensitive=False, store_sensitive_plaintext=store_sensitive_plaintext)


def _short_text(value: str) -> str:
    return value if len(value) <= _MAX_SUMMARY_TEXT else value[:_MAX_SUMMARY_TEXT] + "..."


def summarize_state(value: Any, *, _depth: int = 0) -> Any:
    """Build a bounded, non-sensitive before/after or result summary."""

    if _depth >= 4:
        return {"truncated": True, "type": type(value).__name__}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _short_text(value)
    if isinstance(value, bytes):
        return _digest(value)
    if isinstance(value, pathlib.PurePath):
        return _digest(os.fspath(value))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    if isinstance(value, Mapping):
        summary: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_SUMMARY_ITEMS:
                summary["_truncated_items"] = len(value) - _MAX_SUMMARY_ITEMS
                break
            key_text = str(key)
            if _media_key(key_text):
                safe_value = _safe_media_metadata_scalar(key_text, item) if _media_metadata_key(key_text) else None
                summary[key_text] = safe_value if safe_value is not None else _redact_media(item)
            elif _ui_content_container_key(key_text):
                summary[key_text] = _redact_ui_content(item)
            elif _ui_text_key(key_text):
                serialized = item if isinstance(item, (str, bytes)) else json.dumps(
                    item, sort_keys=True, separators=(",", ":"), default=repr
                )
                summary[key_text] = _digest(serialized)
            elif _sensitive_key(key_text):
                summary[key_text] = _json_safe(item, sensitive=True, store_sensitive_plaintext=False)
            else:
                summary[key_text] = summarize_state(item, _depth=_depth + 1)
        return summary
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        summary_items = [summarize_state(item, _depth=_depth + 1) for item in items[:_MAX_SUMMARY_ITEMS]]
        if len(items) > _MAX_SUMMARY_ITEMS:
            summary_items.append({"truncated_items": len(items) - _MAX_SUMMARY_ITEMS})
        return summary_items
    return _short_text(repr(value))


def _extract_identity(target: Any, before: Any, explicit: Any) -> dict[str, Any] | None:
    candidates = [explicit, target, before]
    identity: dict[str, Any] = {}
    for candidate in candidates:
        if isinstance(candidate, Mapping):
            nested = candidate.get("window")
            sources = (candidate, nested) if isinstance(nested, Mapping) else (candidate,)
            for source in sources:
                for key in _IDENTITY_KEYS:
                    if key in source and source[key] not in (None, ""):
                        identity.setdefault(key, source[key])
        elif isinstance(candidate, str) and candidate.startswith("address:"):
            identity.setdefault("address", candidate.split(":", 1)[1])
    return sanitize_args(identity) if identity else None


class AuditJournal:
    """Append-only JSONL audit journal with private, bounded storage."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        session_id: str | None = None,
        storage: str = "state",
        store_sensitive_plaintext: bool = False,
        max_bytes: int | None = None,
        backup_count: int | None = None,
    ) -> None:
        self.path = resolve_journal_path(path or DEFAULT_JOURNAL_NAME, storage=storage)
        self.session_id = session_id or str(uuid.uuid4())
        self.store_sensitive_plaintext = store_sensitive_plaintext
        configured_max = os.environ.get(
            "HYPR_AGENT_PORTAL_SECURITY_AUDIT_MAX_BYTES",
            os.environ.get("HYPR_AGENT_PORTAL_AUDIT_MAX_BYTES", str(DEFAULT_JOURNAL_MAX_BYTES)),
        )
        configured_backups = os.environ.get(
            "HYPR_AGENT_PORTAL_SECURITY_AUDIT_BACKUPS",
            os.environ.get("HYPR_AGENT_PORTAL_AUDIT_BACKUPS", str(DEFAULT_JOURNAL_BACKUPS)),
        )
        self.max_bytes = int(configured_max) if max_bytes is None else int(max_bytes)
        self.backup_count = int(configured_backups) if backup_count is None else int(backup_count)
        if not 1 <= self.max_bytes <= _MAX_CONFIGURED_JOURNAL_BYTES:
            raise ValueError(f"audit max_bytes must be between 1 and {_MAX_CONFIGURED_JOURNAL_BYTES}")
        if not 0 <= self.backup_count <= _MAX_CONFIGURED_JOURNAL_BACKUPS:
            raise ValueError(f"audit backup_count must be between 0 and {_MAX_CONFIGURED_JOURNAL_BACKUPS}")
        self._lock = threading.Lock()

    @staticmethod
    def _validate_fd(descriptor: int, *, kind: str) -> os.stat_result:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
            raise UnsafeJournalPath(f"{kind} is not a private current-user regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise UnsafeJournalPath(f"{kind} has unsafe permissions")
        return metadata

    def _open_lock(self, directory_fd: int) -> int:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path.name + ".lock", flags, 0o600, dir_fd=directory_fd)
        try:
            self._validate_fd(descriptor, kind="audit lock")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _validate_named_file(directory_fd: int, name: str) -> os.stat_result | None:
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise UnsafeJournalPath(f"unsafe audit rotation entry: {name}")
        return metadata

    def _rotate_locked(self, directory_fd: int, descriptor: int) -> int:
        if self.backup_count == 0:
            raise AuditError("audit journal size limit reached and rotation is disabled")
        opened = self._validate_fd(descriptor, kind="audit journal")
        named = self._validate_named_file(directory_fd, self.path.name)
        if named is None or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise UnsafeJournalPath("audit journal changed during rotation")
        for index in range(self.backup_count, 1, -1):
            source = f"{self.path.name}.{index - 1}"
            destination = f"{self.path.name}.{index}"
            if self._validate_named_file(directory_fd, source) is None:
                continue
            self._validate_named_file(directory_fd, destination)
            os.replace(source, destination, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        first = f"{self.path.name}.1"
        self._validate_named_file(directory_fd, first)
        os.replace(self.path.name, first, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        flags = os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        new_descriptor = os.open(self.path.name, flags, 0o600, dir_fd=directory_fd)
        try:
            self._validate_fd(new_descriptor, kind="audit journal")
        except Exception:
            os.close(new_descriptor)
            raise
        os.close(descriptor)
        try:
            os.fsync(directory_fd)
        except Exception:
            os.close(new_descriptor)
            raise
        return new_descriptor

    def record(
        self,
        tool: str,
        *,
        target: Any = None,
        args: Any = None,
        result: Any = None,
        before: Any = None,
        after: Any = None,
        dry_run: bool = False,
        target_identity: Any = None,
    ) -> dict[str, Any]:
        """Append and return one audit record.

        The write is a single append under a process-local lock.  File mode is
        forced to ``0600`` on every append to repair permissive umasks.
        """

        record = {
            "schema_version": SCHEMA_VERSION,
            "event_id": str(uuid.uuid4()),
            "timestamp": _utc_now(),
            "session_id": self.session_id,
            "tool": str(tool),
            "target": summarize_state(target),
            "target_identity": _extract_identity(target, before, target_identity),
            "args": sanitize_args(args if args is not None else {}, store_sensitive_plaintext=self.store_sensitive_plaintext),
            "result": summarize_state(result),
            "before": summarize_state(before),
            "after": summarize_state(after),
            "dry_run": bool(dry_run),
        }
        payload = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        encoded = payload.encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise AuditError("one audit record exceeds the configured journal size limit")
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with self._lock:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            directory_fd = os.open(self.path.parent, directory_flags)
            lock_fd = self._open_lock(directory_fd)
            descriptor = os.open(self.path.name, flags, 0o600, dir_fd=directory_fd)
            try:
                os.fchmod(descriptor, 0o600)
                metadata = self._validate_fd(descriptor, kind="audit journal")
                if metadata.st_size + len(encoded) > self.max_bytes:
                    descriptor = self._rotate_locked(directory_fd, descriptor)
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise AuditError("failed to append audit record")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(lock_fd)
                os.close(directory_fd)
        return record

    def read(self) -> list[dict[str, Any]]:
        """Read valid JSON object records; blank lines are ignored."""

        if not self.path.exists():
            return []
        if self.path.is_symlink() or not self.path.is_file():
            raise UnsafeJournalPath("journal target is not a regular non-symlink file")
        records: list[dict[str, Any]] = []
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise UnsafeJournalPath("journal target is not a regular file")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    decoded = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditError(f"invalid JSON at journal line {line_number}") from exc
                if not isinstance(decoded, dict):
                    raise AuditError(f"journal line {line_number} is not an object")
                records.append(decoded)
        return records


@dataclasses.dataclass(frozen=True)
class ReplayPolicy:
    """Policy inputs for replay preflight.  Replay is plan-only by default."""

    execute: bool = False
    allow_clipboard: bool = False
    readonly: bool = False
    dry_run: bool = False
    max_record_age_seconds: float | None = 300.0


@dataclasses.dataclass(frozen=True)
class ReplayDecision:
    event_id: str
    tool: str
    accepted: bool
    executable: bool
    reasons: tuple[str, ...]
    record: Mapping[str, Any]


@dataclasses.dataclass(frozen=True)
class ReplayPreflight:
    """Immutable replay plan.  This object never executes journal entries."""

    plan_only: bool
    decisions: tuple[ReplayDecision, ...]

    @property
    def accepted(self) -> tuple[ReplayDecision, ...]:
        return tuple(item for item in self.decisions if item.accepted)

    @property
    def rejected(self) -> tuple[ReplayDecision, ...]:
        return tuple(item for item in self.decisions if not item.accepted)


def _walk(value: Any) -> Iterable[tuple[str | None, Any]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield None, item
            yield from _walk(item)


def _contains_digest(value: Any) -> bool:
    return any(
        isinstance(item, Mapping)
        and item.get("redacted") is True
        and isinstance(item.get("digest"), str)
        for _, item in _walk({"root": value})
    )


def _contains_ephemeral_id(value: Any) -> bool:
    return any(key is not None and _EPHEMERAL_KEY_RE.search(key.casefold()) is not None for key, _ in _walk(value))


def _uses_clipboard(record: Mapping[str, Any]) -> bool:
    tool = str(record.get("tool", "")).casefold()
    if tool in _CLIPBOARD_TOOLS or "clipboard" in tool or tool.startswith("paste"):
        return True
    args = record.get("args", {})
    if isinstance(args, Mapping):
        action = str(args.get("action", "")).casefold()
        method = str(args.get("method", "auto")).casefold()
        if action in _CLIPBOARD_TOOLS or action.startswith("paste"):
            return True
        # type_text's auto backend is allowed to fall back to clipboard paste.
        if (tool in {"type", "type_text"} or action in {"type", "type_text"}) and method in {
            "auto",
            "clipboard",
            "paste",
        }:
            return True
    return any(key is not None and "clipboard" in key.casefold() for key, _ in _walk(args))


def _parse_timestamp(value: Any) -> _datetime.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
    return parsed.astimezone(_datetime.timezone.utc)


def _identity_mismatch(recorded: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    compared = False
    for key in _IDENTITY_KEYS:
        if key in recorded:
            compared = True
            # Stable evidence present in the journal must still be available;
            # comparing only the intersection would accept a resolver that
            # silently dropped pid/starttime and permit address reuse.
            if key not in current:
                return True
            if str(recorded[key]) != str(current[key]):
                return True
    return not compared


def preflight_replay(
    records: Iterable[Mapping[str, Any]],
    *,
    resolve_target: Callable[[Any], Mapping[str, Any] | None] | None,
    policy: ReplayPolicy | None = None,
) -> ReplayPreflight:
    """Validate journal entries and return a non-executing replay plan.

    ``resolve_target`` must return the current stable identity of a target, or
    ``None`` if it is gone.  Targeted records without enough identity evidence
    are rejected rather than risking delivery to a recycled window address.
    Setting ``ReplayPolicy.execute`` only changes ``executable`` flags; the
    caller remains responsible for dispatch and for revalidating immediately
    before each action.
    """

    selected = policy or ReplayPolicy()
    decisions: list[ReplayDecision] = []
    now = _datetime.datetime.now(_datetime.timezone.utc)

    for record in records:
        reasons: list[str] = []
        schema = record.get("schema_version")
        if type(schema) is not int or schema > SCHEMA_VERSION:
            reasons.append("newer_schema" if type(schema) is int and schema > SCHEMA_VERSION else "invalid_schema")
        if selected.readonly:
            reasons.append("readonly")
        if selected.dry_run or record.get("dry_run") is True:
            reasons.append("dry_run")

        args = record.get("args", {})
        if _contains_digest(args):
            reasons.append("digested_sensitive_data")
        if _contains_ephemeral_id(args):
            reasons.append("ephemeral_element_id")
        if _uses_clipboard(record) and not selected.allow_clipboard:
            reasons.append("clipboard_permission_required")

        target = record.get("target")
        identity = record.get("target_identity")
        targeted = target not in (None, "", {}) or identity not in (None, "", {})
        if targeted:
            if resolve_target is None:
                reasons.append("unverifiable_target")
            else:
                try:
                    current = resolve_target(target)
                except Exception:  # A lookup failure must fail closed, not abort the plan.
                    current = None
                    reasons.append("target_resolution_failed")
                if current is None and "target_resolution_failed" not in reasons:
                    reasons.append("missing_target")
                elif current is not None and (not isinstance(identity, Mapping) or not identity):
                    reasons.append("unverifiable_target")
                elif current is not None and _identity_mismatch(identity, current):
                    reasons.append("stale_target")

            if selected.max_record_age_seconds is not None:
                timestamp = _parse_timestamp(record.get("timestamp"))
                if timestamp is None:
                    reasons.append("invalid_timestamp")
                elif (now - timestamp).total_seconds() > selected.max_record_age_seconds:
                    reasons.append("stale_target")

        # Keep reason order deterministic while suppressing duplicates.
        unique_reasons = tuple(dict.fromkeys(reasons))
        accepted = not unique_reasons
        decisions.append(
            ReplayDecision(
                event_id=str(record.get("event_id", "")),
                tool=str(record.get("tool", "")),
                accepted=accepted,
                executable=accepted and selected.execute,
                reasons=unique_reasons,
                record=record,
            )
        )

    return ReplayPreflight(plan_only=not selected.execute, decisions=tuple(decisions))


__all__ = [
    "SCHEMA_VERSION",
    "AuditError",
    "AuditJournal",
    "ReplayDecision",
    "ReplayPolicy",
    "ReplayPreflight",
    "UnsafeJournalPath",
    "preflight_replay",
    "resolve_journal_path",
    "sanitize_args",
    "summarize_state",
]
