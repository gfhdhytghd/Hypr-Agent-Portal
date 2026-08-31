"""Cross-process, fail-closed lease for desktop mutation calls.

The lock is an advisory ``flock`` rooted in the caller's private
``XDG_RUNTIME_DIR``.  Lock ownership, not the JSON stored in the lock file, is
authoritative: leftover or malformed metadata from a crashed process never
grants access.

Typical use is one non-blocking acquisition per mutating MCP call::

    lease = ProcessMutationLease()
    with lease.acquire() as holder:
        perform_mutation()

Only process identifiers and an unguessable per-instance identifier are
written to disk.  Tool arguments, client-provided labels, environment values,
and other potentially sensitive data are never persisted.
"""

from __future__ import annotations

import dataclasses
import datetime as _datetime
import errno
import fcntl
import json
import os
import pathlib
import stat
import threading
import uuid
from collections.abc import Mapping
from typing import Any


_APPLICATION_DIR = "hypr-agent-portal"
_DEFAULT_FILENAME = "mutation.lock"
_MAX_METADATA_BYTES = 8192


class ProcessLeaseError(RuntimeError):
    """Base exception for process mutation lease failures."""


class UnsafeLeasePath(ProcessLeaseError):
    """The runtime directory or lock file is not safe for a private lease."""


class LeaseUnavailable(ProcessLeaseError):
    """The lease could not be opened or maintained safely."""


class LeaseConflict(ProcessLeaseError):
    """Another process currently owns the non-blocking mutation lease."""

    def __init__(self, holder: Mapping[str, Any] | None = None) -> None:
        self.holder = dict(holder or {})
        if self.holder:
            details = ", ".join(f"{key}={value}" for key, value in sorted(self.holder.items()))
            super().__init__(f"mutation lease is already held ({details})")
        else:
            super().__init__("mutation lease is already held (holder details unavailable)")


@dataclasses.dataclass(frozen=True)
class LeaseHolder:
    """Non-sensitive metadata describing the current lock owner."""

    pid: int
    uid: int
    instance_id: str
    acquired_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "uid": self.uid,
            "instanceId": self.instance_id,
            "acquiredAt": self.acquired_at,
        }


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _private_directory(path: pathlib.Path, *, create: bool) -> pathlib.Path:
    if not path.is_absolute():
        raise UnsafeLeasePath("runtime directory must be absolute")

    if create:
        try:
            path.mkdir(mode=0o700, parents=False, exist_ok=True)
        except OSError as exc:
            raise LeaseUnavailable(f"cannot create private lease directory: {exc}") from exc

    try:
        info = path.lstat()
    except OSError as exc:
        raise LeaseUnavailable(f"cannot inspect lease directory: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise UnsafeLeasePath("lease directory must be a real directory")
    if info.st_uid != os.getuid():
        raise UnsafeLeasePath("lease directory must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise UnsafeLeasePath("lease directory must not be accessible by group or other users")
    return path


def resolve_lease_path(runtime_dir: str | os.PathLike[str] | None = None) -> pathlib.Path:
    """Resolve the fixed lease file below a private runtime directory.

    ``runtime_dir`` exists primarily for tests and embedding.  When omitted,
    ``XDG_RUNTIME_DIR`` is required; the function deliberately has no fallback
    to ``/tmp`` or a home directory.
    """

    configured = runtime_dir if runtime_dir is not None else os.environ.get("XDG_RUNTIME_DIR")
    if not configured:
        raise UnsafeLeasePath("XDG_RUNTIME_DIR is required for the mutation lease")

    root = _private_directory(pathlib.Path(configured), create=False)
    application_dir = _private_directory(root / _APPLICATION_DIR, create=True)
    return application_dir / _DEFAULT_FILENAME


def _safe_holder_metadata(raw: bytes) -> dict[str, Any]:
    """Parse only the known, non-sensitive holder fields from best-effort data."""

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(value, Mapping):
        return {}

    holder: dict[str, Any] = {}
    for key in ("pid", "uid"):
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            holder[key] = item
    for key in ("instanceId", "acquiredAt"):
        item = value.get(key)
        if isinstance(item, str) and 0 < len(item) <= 128:
            holder[key] = item
    return holder


class _HeldLease:
    """Context guard returned by :meth:`ProcessMutationLease.acquire`."""

    def __init__(self, lease: ProcessMutationLease, holder: LeaseHolder) -> None:
        self._lease = lease
        self.holder = holder
        self._released = False

    def __enter__(self) -> LeaseHolder:
        return self.holder

    def release(self) -> None:
        if not self._released:
            self._lease.release()
            self._released = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


class ProcessMutationLease:
    """A reusable manager that serializes mutating calls across processes.

    Acquisition is always non-blocking.  Filesystem, metadata-write, and lock
    errors deny the mutation rather than degrading to an unlocked operation.
    """

    def __init__(self, *, runtime_dir: str | os.PathLike[str] | None = None) -> None:
        self.path = resolve_lease_path(runtime_dir)
        self.instance_id = str(uuid.uuid4())
        self._fd: int | None = None
        self._holder: LeaseHolder | None = None
        self._state_lock = threading.Lock()

    @property
    def holder(self) -> LeaseHolder | None:
        return self._holder

    def _open_lock_file(self) -> int:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise LeaseUnavailable(f"cannot open mutation lease: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeLeasePath("mutation lease must be a regular file")
            if info.st_uid != os.getuid():
                raise UnsafeLeasePath("mutation lease must be owned by the current user")
            if info.st_nlink != 1:
                raise UnsafeLeasePath("mutation lease must have exactly one filesystem link")
            if stat.S_IMODE(info.st_mode) & 0o177:
                raise UnsafeLeasePath("mutation lease must be private to the current user")
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _read_holder(fd: int) -> dict[str, Any]:
        try:
            raw = os.pread(fd, _MAX_METADATA_BYTES + 1, 0)
        except OSError:
            return {}
        if len(raw) > _MAX_METADATA_BYTES:
            return {}
        return _safe_holder_metadata(raw)

    @staticmethod
    def _write_all(fd: int, payload: bytes) -> None:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError(errno.EIO, "short write to mutation lease")
            offset += written
        os.fsync(fd)

    def acquire(self) -> _HeldLease:
        """Acquire immediately and return a context guard.

        :class:`LeaseConflict` includes best-effort, allowlisted holder details.
        Malformed or stale metadata is reported as unavailable details and is
        never used to decide whether the lock can be taken.
        """

        with self._state_lock:
            if self._fd is not None:
                raise LeaseUnavailable("this mutation lease manager is already holding the lease")
            fd = self._open_lock_file()
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    holder = self._read_holder(fd)
                    os.close(fd)
                    raise LeaseConflict(holder) from exc
                os.close(fd)
                raise LeaseUnavailable(f"cannot acquire mutation lease: {exc}") from exc

            holder = LeaseHolder(
                pid=os.getpid(),
                uid=os.getuid(),
                instance_id=self.instance_id,
                acquired_at=_utc_now(),
            )
            payload = json.dumps(holder.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
            try:
                self._write_all(fd, payload)
            except OSError as exc:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
                raise LeaseUnavailable(f"cannot publish mutation lease ownership: {exc}") from exc

            self._fd = fd
            self._holder = holder
            return _HeldLease(self, holder)

    def release(self) -> None:
        """Clear ownership metadata and release the held lock."""

        with self._state_lock:
            fd = self._fd
            if fd is None:
                return
            error: OSError | None = None
            try:
                self._write_all(fd, b"{}")
            except OSError as exc:
                error = exc
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError as exc:
                error = error or exc
            finally:
                os.close(fd)
                self._fd = None
                self._holder = None
            if error is not None:
                raise LeaseUnavailable(f"cannot safely release mutation lease: {error}") from error

    def __enter__(self) -> LeaseHolder:
        return self.acquire().holder

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


# Short alias for integrations that do not need to repeat "Mutation".
ProcessLease = ProcessMutationLease


__all__ = [
    "LeaseConflict",
    "LeaseHolder",
    "LeaseUnavailable",
    "ProcessLease",
    "ProcessLeaseError",
    "ProcessMutationLease",
    "UnsafeLeasePath",
    "resolve_lease_path",
]
