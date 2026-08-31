"""Security policy primitives for hypr-agent-portal's MCP server.

The module deliberately has no dependency on the monolithic MCP server.  Callers
describe an action and its target, then honor :class:`PolicyDecision.execute`
before sending anything to the compositor.
"""

from __future__ import annotations

import fnmatch
import fcntl
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping


class AuthorizationLevel(IntEnum):
    VIEW = 0
    CLICK = 1
    FULL = 2

    @classmethod
    def parse(cls, value: str | "AuthorizationLevel") -> "AuthorizationLevel":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError as error:
            raise ValueError(f"unknown authorization level: {value!r}") from error


class ClipboardCapability(str, Enum):
    READ = "read"
    WRITE = "write"
    PASTE_TEXT = "paste_text"
    PASTE_FILE = "paste_file"
    PASTE_IMAGE = "paste_image"

    @classmethod
    def parse(cls, value: str | "ClipboardCapability") -> "ClipboardCapability":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as error:
            raise ValueError(f"unknown clipboard capability: {value!r}") from error


class ScopeMatch(str, Enum):
    ANY = "any"
    ALL = "all"


class DecisionCode(str, Enum):
    ALLOW = "allow"
    DRY_RUN = "dry_run"
    READONLY = "readonly"
    OUT_OF_SCOPE = "out_of_scope"
    APP_PERMISSION = "app_permission"
    PRIVACY_EXCLUDED = "privacy_excluded"
    SCREEN_LOCKED = "screen_locked"
    LAYER_SURFACE_ACTIVE = "layer_surface_active"
    KEYBOARD_GRAB_ACTIVE = "keyboard_grab_active"
    PANIC_ACTIVE = "panic_active"
    GUARD_UNAVAILABLE = "guard_unavailable"
    HUMAN_TAKEOVER = "human_takeover"
    CLIPBOARD_PERMISSION = "clipboard_permission"
    MUTATION_LEASE_REQUIRED = "mutation_lease_required"
    MUTATION_LEASE_HELD = "mutation_lease_held"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_PENDING = "confirmation_pending"
    CONFIRMATION_INVALID = "confirmation_invalid"


def _normalize(value: Any) -> str:
    return str(value or "").strip().casefold()


def _normalize_address(value: Any) -> str:
    address = _normalize(value)
    if address.startswith("address:"):
        address = address.split(":", 1)[1]
    if "@" in address:
        address = address.split("@", 1)[0]
    return address


def _workspace_value(value: Any) -> str:
    if isinstance(value, Mapping):
        value = value.get("name", value.get("id", ""))
    return _normalize(value)


@dataclass(frozen=True)
class WindowIdentity:
    address: str = ""
    class_name: str = ""
    workspace: str = ""
    pid: str = ""
    process_start_time: str = ""
    launched: bool = False
    initial_class: str = ""

    @classmethod
    def from_window(cls, window: Mapping[str, Any], *, launched: bool = False) -> "WindowIdentity":
        pid = str(window.get("pid") or "")
        start_time = next(
            (
                str(window.get(key))
                for key in ("processStartTime", "processStarttime", "process_start_time", "pidStartTime", "starttime")
                if window.get(key) not in (None, "")
            ),
            "",
        )
        if pid and not start_time:
            try:
                stat_text = (pathlib.Path("/proc") / pid / "stat").read_text()
                # comm is parenthesized and may contain spaces, so a naïve
                # split shifts field 22. Fields after the last ')' begin at
                # field 3; starttime is therefore remainder index 19.
                remainder = stat_text.rsplit(")", 1)[1].split()
                start_time = remainder[19] if len(remainder) > 19 else ""
            except (OSError, ValueError):
                start_time = ""
        return cls(
            address=_normalize_address(window.get("address")),
            class_name=str(window.get("class") or ""),
            initial_class=str(window.get("initialClass") or ""),
            workspace=_workspace_value(window.get("workspace")),
            pid=pid,
            process_start_time=start_time,
            launched=launched,
        )

    def fingerprint(self) -> Mapping[str, str]:
        return {
            "address": _normalize_address(self.address),
            "class": _normalize(self.class_name),
            "initialClass": _normalize(self.initial_class),
            "workspace": _workspace_value(self.workspace),
            "pid": str(self.pid or ""),
            "processStartTime": str(self.process_start_time or ""),
        }

    def class_identities(self) -> tuple[str, ...]:
        """Return distinct normalized runtime and stable initial classes."""
        return tuple(dict.fromkeys(filter(None, (_normalize(self.class_name), _normalize(self.initial_class)))))

    def confinement_class(self) -> str:
        """Use the stable initial class when available to prevent runtime spoofing."""
        return _normalize(self.initial_class) or _normalize(self.class_name)


@dataclass(frozen=True)
class GuardInputs:
    # None asks the policy to inspect /proc; a bool is an authoritative signal
    # from the compositor/session integration.
    screen_locked: bool | None = None
    layer_surface_active: bool = False
    keyboard_grab_active: bool = False
    panic_active: bool = False
    available: bool = True
    error: str = ""


@dataclass(frozen=True)
class ActionRequest:
    owner: str
    action: str
    required_level: AuthorizationLevel = AuthorizationLevel.VIEW
    mutating: bool = False
    target: WindowIdentity | None = None
    # Additional identities whose resulting scope must also be allowed.  The
    # primary target remains the source window used for app authorization;
    # move/rename operations add their destination identity here.
    scope_targets: tuple[WindowIdentity, ...] = field(default_factory=tuple)
    clipboard_capabilities: frozenset[ClipboardCapability] = field(default_factory=frozenset)
    destructive: bool = False
    confirmation_token: str | None = None
    confirmation_context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.owner.strip():
            raise ValueError("action owner must not be empty")
        if not self.action.strip():
            raise ValueError("action name must not be empty")
        required_level = AuthorizationLevel.parse(self.required_level)
        # Mutations must never inherit the VIEW default accidentally.  Clipboard
        # injection and explicitly destructive actions require full control.
        if self.mutating:
            required_level = max(required_level, AuthorizationLevel.CLICK)
        if self.clipboard_capabilities or self.destructive:
            required_level = max(required_level, AuthorizationLevel.FULL)
        object.__setattr__(self, "required_level", required_level)
        object.__setattr__(
            self,
            "clipboard_capabilities",
            frozenset(ClipboardCapability.parse(item) for item in self.clipboard_capabilities),
        )
        object.__setattr__(self, "scope_targets", tuple(self.scope_targets))
        object.__setattr__(self, "confirmation_context", MappingProxyType(dict(self.confirmation_context)))


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    execute: bool
    code: DecisionCode
    reason: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "execute": self.execute,
            "code": self.code.value,
            "reason": self.reason,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class ConfinementConfig:
    launched_only: bool = False
    classes: frozenset[str] = field(default_factory=frozenset)
    workspaces: frozenset[str] = field(default_factory=frozenset)
    addresses: frozenset[str] = field(default_factory=frozenset)
    match: ScopeMatch = ScopeMatch.ANY

    def __post_init__(self) -> None:
        object.__setattr__(self, "classes", frozenset(_normalize(item) for item in self.classes if _normalize(item)))
        object.__setattr__(self, "workspaces", frozenset(_workspace_value(item) for item in self.workspaces if _workspace_value(item)))
        object.__setattr__(self, "addresses", frozenset(_normalize_address(item) for item in self.addresses if _normalize_address(item)))
        object.__setattr__(self, "match", ScopeMatch(self.match))

    @property
    def enabled(self) -> bool:
        return self.launched_only or bool(self.classes or self.workspaces or self.addresses)


@dataclass(frozen=True)
class PolicyConfig:
    readonly: bool = False
    dry_run: bool = False
    confinement: ConfinementConfig = field(default_factory=ConfinementConfig)
    # Fail closed for mutations: an unconfigured application is observable but
    # cannot be clicked or typed into until explicitly granted CLICK or FULL.
    default_authorization: AuthorizationLevel = AuthorizationLevel.VIEW
    app_authorizations: Mapping[str, AuthorizationLevel] = field(default_factory=dict)
    mutation_lease_required: bool = True
    mutation_lease_ttl_seconds: float = 30.0
    confirmation_ttl_seconds: float = 60.0
    confirmation_pending_limit: int = 128
    confirmation_pending_per_owner: int = 16
    confirmation_min_interval_seconds: float = 0.0
    clipboard_permissions: frozenset[ClipboardCapability] = field(
        default_factory=lambda: frozenset(
            {
                ClipboardCapability.WRITE,
                ClipboardCapability.PASTE_TEXT,
                ClipboardCapability.PASTE_FILE,
                ClipboardCapability.PASTE_IMAGE,
            }
        )
    )
    privacy_classes: frozenset[str] = field(default_factory=frozenset)
    block_locked_view: bool = True
    block_locked_mutation: bool = True
    block_layer_mutation: bool = True
    block_keyboard_grab_mutation: bool = True
    human_takeover_enabled: bool = True
    human_takeover_cooldown_seconds: float = 2.0
    lock_process_names: frozenset[str] = field(
        default_factory=lambda: frozenset({"hyprlock", "swaylock", "swaylock-effects", "gtklock", "waylock"})
    )

    def __post_init__(self) -> None:
        if self.mutation_lease_ttl_seconds <= 0:
            raise ValueError("mutation lease TTL must be positive")
        if self.confirmation_ttl_seconds <= 0:
            raise ValueError("confirmation TTL must be positive")
        if not 1 <= self.confirmation_pending_limit <= 4096:
            raise ValueError("confirmation pending limit must be between 1 and 4096")
        if not 1 <= self.confirmation_pending_per_owner <= min(1024, self.confirmation_pending_limit):
            raise ValueError("confirmation per-owner limit must be positive and no greater than the total limit")
        if not 0 <= self.confirmation_min_interval_seconds <= 3600:
            raise ValueError("confirmation minimum interval must be between 0 and 3600 seconds")
        if self.human_takeover_cooldown_seconds < 0:
            raise ValueError("human takeover cooldown must not be negative")
        object.__setattr__(self, "default_authorization", AuthorizationLevel.parse(self.default_authorization))
        object.__setattr__(
            self,
            "app_authorizations",
            MappingProxyType({_normalize(pattern): AuthorizationLevel.parse(level) for pattern, level in self.app_authorizations.items()}),
        )
        object.__setattr__(
            self,
            "clipboard_permissions",
            frozenset(ClipboardCapability.parse(item) for item in self.clipboard_permissions),
        )
        object.__setattr__(
            self,
            "privacy_classes",
            frozenset(_normalize(item) for item in self.privacy_classes if _normalize(item)),
        )
        object.__setattr__(
            self,
            "lock_process_names",
            frozenset(_normalize(item) for item in self.lock_process_names if _normalize(item)),
        )


@dataclass(frozen=True)
class MutationLease:
    owner: str
    expires_at: float


_CHALLENGE_ID_LENGTH = 32
_CHALLENGE_FILE_LIMIT = 64 * 1024
_CHALLENGE_LOCK_NAME = ".capacity.lock"
_CHALLENGE_RATE_STATE_LIMIT = 512 * 1024


def _valid_challenge_id(value: str) -> bool:
    return len(value) == _CHALLENGE_ID_LENGTH and all(character in "0123456789abcdef" for character in value)


def default_confirmation_directory(env: Mapping[str, str] | None = None) -> pathlib.Path:
    values = os.environ if env is None else env
    runtime = values.get("XDG_RUNTIME_DIR", "").strip()
    if not runtime:
        raise RuntimeError("XDG_RUNTIME_DIR is required for external confirmation challenges")
    return pathlib.Path(runtime) / "hypr-agent-portal-confirmations"


def _validate_directory(fd: int, path: pathlib.Path) -> None:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"confirmation path is not a directory: {path}")
    if metadata.st_uid != os.getuid():
        raise RuntimeError(f"confirmation directory is not owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RuntimeError(f"confirmation directory permissions must be 0700: {path}")


def _open_confirmation_directory(path: pathlib.Path, *, create: bool) -> int:
    path = path.expanduser()
    if not path.is_absolute():
        raise RuntimeError("confirmation directory must be an absolute path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(path.parent, flags)
    try:
        _validate_directory(parent_fd, path.parent)
        if create:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
        directory_fd = os.open(path.name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        _validate_directory(directory_fd, path)
    except Exception:
        os.close(directory_fd)
        raise
    return directory_fd


def _challenge_filename(challenge_id: str, state: str) -> str:
    if not _valid_challenge_id(challenge_id):
        raise ValueError("invalid confirmation challenge id")
    if state not in {"pending", "approved"}:
        raise ValueError("invalid confirmation challenge state")
    return f"{challenge_id}.{state}.json"


def _read_challenge(directory_fd: int, filename: str) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    file_fd = os.open(filename, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise RuntimeError("confirmation challenge is not a current-user regular file")
        if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("confirmation challenge has unsafe links or permissions")
        if metadata.st_size > _CHALLENGE_FILE_LIMIT:
            raise RuntimeError("confirmation challenge is too large")
        chunks: list[bytes] = []
        remaining = _CHALLENGE_FILE_LIMIT + 1
        while remaining:
            chunk = os.read(file_fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            raise RuntimeError("confirmation challenge is too large")
    finally:
        os.close(file_fd)
    try:
        value = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("confirmation challenge is not valid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("confirmation challenge must contain an object")
    return value


def _lock_confirmation_directory(directory_fd: int) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(_CHALLENGE_LOCK_NAME, flags, 0o600, dir_fd=directory_fd)
    try:
        metadata = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise RuntimeError("confirmation capacity lock has unsafe ownership, links, or permissions")
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return lock_fd
    except Exception:
        os.close(lock_fd)
        raise


def _challenge_entries_locked(directory_fd: int, now: float) -> list[dict[str, Any] | None]:
    """Remove valid expired records and return all remaining challenge slots.

    Unknown, malformed, or unsafe matching entries still consume a total slot.
    This prevents a same-UID writer from bypassing the global cap, while no
    symlink or non-regular file is ever followed or interpreted.
    """
    entries: list[dict[str, Any] | None] = []
    for filename in os.listdir(directory_fd):
        parts = filename.split(".")
        if len(parts) != 3 or not _valid_challenge_id(parts[0]) or parts[1] not in {"pending", "approved"} or parts[2] != "json":
            continue
        try:
            metadata = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            entries.append(None)
            continue
        try:
            challenge = _read_challenge(directory_fd, filename)
            expires_at = float(challenge.get("expiresAt", 0))
        except (OSError, RuntimeError, TypeError, ValueError):
            entries.append(None)
            continue
        if expires_at <= now:
            try:
                os.unlink(filename, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            if parts[1] == "approved":
                try:
                    _dispatch_native_approval("cancel", parts[0], None)
                except (OSError, RuntimeError, ValueError):
                    pass
            continue
        entries.append(challenge)
    return entries


def _rate_state_locked(lock_fd: int, now: float, interval: float) -> dict[str, float]:
    metadata = os.fstat(lock_fd)
    if metadata.st_size > _CHALLENGE_RATE_STATE_LIMIT:
        raise RuntimeError("confirmation rate state is too large")
    raw = os.pread(lock_fd, metadata.st_size, 0)
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("confirmation rate state is invalid") from error
    if not isinstance(decoded, dict):
        raise RuntimeError("confirmation rate state is invalid")
    state: dict[str, float] = {}
    for key, value in decoded.items():
        if not isinstance(key, str) or len(key) != 64:
            raise RuntimeError("confirmation rate state is invalid")
        try:
            timestamp = float(value)
        except (TypeError, ValueError) as error:
            raise RuntimeError("confirmation rate state is invalid") from error
        if now - timestamp < interval:
            state[key] = timestamp
    return state


def _write_rate_state_locked(lock_fd: int, state: Mapping[str, float]) -> None:
    payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > _CHALLENGE_RATE_STATE_LIMIT:
        raise RuntimeError("confirmation rate state is too large")
    os.ftruncate(lock_fd, 0)
    view = memoryview(payload)
    offset = 0
    while view:
        written = os.pwrite(lock_fd, view, offset)
        if written <= 0:
            raise RuntimeError("failed to persist confirmation rate state")
        offset += written
        view = view[written:]
    os.fsync(lock_fd)


def _trusted_hyprctl_binary() -> pathlib.Path:
    """Return a system-owned hyprctl, never a PATH-controlled executable."""
    for candidate in (pathlib.Path("/usr/bin/hyprctl"), pathlib.Path("/usr/local/bin/hyprctl")):
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            continue
        if stat.S_IMODE(metadata.st_mode) & 0o022 or not os.access(resolved, os.X_OK):
            continue
        return resolved
    raise RuntimeError("a root-owned, non-writable hyprctl is required for physical approval")


def _lua_quote(value: str) -> str:
    """Quote an ASCII approval payload as one Lua string literal."""
    escaped: list[str] = ['"']
    for character in value:
        code = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == '"':
            escaped.append('\\"')
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif 32 <= code <= 126:
            escaped.append(character)
        else:
            escaped.append(f"\\{code:03d}")
    escaped.append('"')
    return "".join(escaped)


def _hyprland_config_provider(binary: str) -> str:
    result = subprocess.run(
        [binary, "systeminfo"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cannot determine Hyprland config provider: {result.stdout.strip() or 'no response'}")
    for line in result.stdout.splitlines():
        label, separator, value = line.partition(":")
        if separator and label.strip().casefold() == "configprovider":
            return value.strip().casefold()
    raise RuntimeError("Hyprland systeminfo did not report configProvider")


def _dispatch_native_approval(action: str, challenge_id: str, ttl_ms: int | None = None) -> bool:
    """Arm/query the compositor-only physical approval state.

    There is intentionally no native ``approve`` action.  ``status`` becomes
    successful only after the plugin's real-keyboard listener observes F12.
    """
    if action not in {"arm", "status", "cancel"} or not _valid_challenge_id(challenge_id):
        raise ValueError("invalid native approval request")
    payload = f"{action} {challenge_id}"
    if action == "arm":
        if ttl_ms is None or ttl_ms < 1000 or ttl_ms > 120000:
            raise ValueError("native approval TTL must be between 1000 and 120000 ms")
        payload += f" {ttl_ms}"

    binary = str(_trusted_hyprctl_binary())
    provider = _hyprland_config_provider(binary)
    last_output = ""
    if provider == "lua":
        commands = [
            [binary, "dispatch", f"hl.plugin.{namespace}.approval({_lua_quote(payload)})"]
            for namespace in ("hypr_agent_portal", "hypr_agent_protal")
        ]
    else:
        commands = [
            [binary, "dispatch", dispatcher, payload]
            for dispatcher in ("hypr-agent-portal:approval", "hypr-agent-protal:approval")
        ]

    for index, command in enumerate(commands):
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5,
            check=False,
        )
        output = result.stdout.strip()
        last_output = output
        if provider != "lua" and output == "Invalid dispatcher":
            continue
        if action == "status" and output == "approval-pending-press-f12":
            return False
        if result.returncode == 0 and output == "ok":
            return True
        # Lua reports a missing plugin namespace/function as an evaluation
        # error rather than "Invalid dispatcher".  Only that unknown response
        # falls back to the one-release compatibility namespace; structured
        # approval errors are authoritative and must not be retried elsewhere.
        if provider == "lua" and index == 0 and not output.startswith("approval-"):
            continue
        raise RuntimeError(f"native physical approval {action} failed: {output or 'no response'}")
    raise RuntimeError(f"physical approval dispatcher is unavailable: {last_output or 'no response'}")


def approve_confirmation(
    challenge_id: str,
    *,
    confirmation_dir: str | pathlib.Path | None = None,
    wall_clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    poll_interval: float = 0.1,
) -> dict[str, Any]:
    """Approve a challenge only after native code observes a physical F12."""
    path = pathlib.Path(confirmation_dir) if confirmation_dir is not None else default_confirmation_directory()
    directory_fd = _open_confirmation_directory(path, create=False)
    pending = _challenge_filename(challenge_id, "pending")
    approved = _challenge_filename(challenge_id, "approved")
    armed = False
    preserve_native_approval = False
    try:
        challenge = _read_challenge(directory_fd, pending)
        if challenge.get("challengeId") != challenge_id:
            raise RuntimeError("confirmation challenge id does not match its filename")
        if float(challenge.get("expiresAt", 0)) <= wall_clock():
            os.unlink(pending, dir_fd=directory_fd)
            raise RuntimeError("confirmation challenge has expired")
        remaining_ms = min(120000, max(1000, int((float(challenge["expiresAt"]) - wall_clock()) * 1000)))
        if not _dispatch_native_approval("arm", challenge_id, remaining_ms):
            raise RuntimeError("native physical approval could not be armed")
        armed = True
        while not _dispatch_native_approval("status", challenge_id, None):
            if float(challenge.get("expiresAt", 0)) <= wall_clock():
                try:
                    os.unlink(pending, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
                raise RuntimeError("confirmation challenge expired before physical approval")
            sleep(max(0.01, poll_interval))

        # Re-read after the external wait.  The id and expiry must still match
        # before the pending-to-approved link transition is made atomically.
        challenge = _read_challenge(directory_fd, pending)
        if challenge.get("challengeId") != challenge_id or float(challenge.get("expiresAt", 0)) <= wall_clock():
            raise RuntimeError("confirmation challenge changed or expired during physical approval")
        # linkat with a non-existent destination is non-overwriting.  Removing
        # pending afterwards leaves one immutable-by-convention approved file.
        os.link(pending, approved, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.unlink(pending, dir_fd=directory_fd)
        os.chmod(approved, 0o400, dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
        # Keep the native proof alive until SecurityPolicy consumes this exact
        # approved record.  A same-UID process copying/linking the JSON alone
        # therefore cannot manufacture authorization.
        preserve_native_approval = True
        return challenge
    finally:
        if armed and not preserve_native_approval:
            try:
                _dispatch_native_approval("cancel", challenge_id, None)
            except (OSError, RuntimeError, ValueError):
                pass
        os.close(directory_fd)


def reject_confirmation(
    challenge_id: str,
    *,
    confirmation_dir: str | pathlib.Path | None = None,
) -> bool:
    """Reject and remove a pending challenge from a trusted local process."""
    path = pathlib.Path(confirmation_dir) if confirmation_dir is not None else default_confirmation_directory()
    directory_fd = _open_confirmation_directory(path, create=False)
    filename = _challenge_filename(challenge_id, "pending")
    try:
        _read_challenge(directory_fd, filename)
        os.unlink(filename, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True
    except FileNotFoundError:
        return False
    finally:
        os.close(directory_fd)


class SecurityPolicy:
    """Thread-safe evaluator and state store for MCP security decisions."""

    def __init__(
        self,
        config: PolicyConfig | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        proc_root: str | pathlib.Path = "/proc",
        confirmation_dir: str | pathlib.Path | None = None,
    ) -> None:
        self.config = config or PolicyConfig()
        self._clock = clock
        self._wall_clock = wall_clock
        self._proc_root = pathlib.Path(proc_root)
        self._confirmation_dir = pathlib.Path(confirmation_dir) if confirmation_dir is not None else None
        self._lock = threading.RLock()
        self._launched_identities: dict[str, Mapping[str, str]] = {}
        self._lease: MutationLease | None = None
        self._human_takeover_until = 0.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **kwargs: Any) -> "SecurityPolicy":
        return cls(policy_config_from_env(env), **kwargs)

    def register_launched_window(self, window: WindowIdentity | Mapping[str, Any] | str) -> None:
        if isinstance(window, Mapping):
            identity = WindowIdentity.from_window(window)
        elif isinstance(window, WindowIdentity):
            identity = window
        else:
            identity = WindowIdentity(address=window)
        normalized = _normalize_address(identity.address)
        if not normalized:
            raise ValueError("launched window address must not be empty")
        with self._lock:
            self._launched_identities[normalized] = self._launch_provenance(identity)

    def unregister_launched_window(self, window: WindowIdentity | Mapping[str, Any] | str) -> None:
        if isinstance(window, Mapping):
            address = WindowIdentity.from_window(window).address
        elif isinstance(window, WindowIdentity):
            address = window.address
        else:
            address = window
        with self._lock:
            self._launched_identities.pop(_normalize_address(address), None)

    def acquire_mutation_lease(self, owner: str, ttl_seconds: float | None = None) -> MutationLease | None:
        if not owner.strip():
            raise ValueError("lease owner must not be empty")
        ttl = self.config.mutation_lease_ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        if ttl <= 0:
            raise ValueError("lease TTL must be positive")
        with self._lock:
            current = self._current_lease_locked()
            if current is not None and current.owner != owner:
                return None
            self._lease = MutationLease(owner=owner, expires_at=self._clock() + ttl)
            return self._lease

    def current_mutation_lease(self) -> MutationLease | None:
        with self._lock:
            return self._current_lease_locked()

    def release_mutation_lease(self, owner: str) -> bool:
        with self._lock:
            current = self._current_lease_locked()
            if current is None or current.owner != owner:
                return False
            self._lease = None
            return True

    def _current_lease_locked(self) -> MutationLease | None:
        if self._lease is not None and self._lease.expires_at <= self._clock():
            self._lease = None
        return self._lease

    def record_human_activity(self, *, cooldown_seconds: float | None = None) -> float:
        cooldown = self.config.human_takeover_cooldown_seconds if cooldown_seconds is None else float(cooldown_seconds)
        if cooldown < 0:
            raise ValueError("human takeover cooldown must not be negative")
        with self._lock:
            self._human_takeover_until = max(self._human_takeover_until, self._clock() + cooldown)
            return self._human_takeover_until

    def clear_human_takeover(self) -> None:
        with self._lock:
            self._human_takeover_until = 0.0

    def human_takeover_active(self) -> bool:
        with self._lock:
            return self.config.human_takeover_enabled and self._clock() < self._human_takeover_until

    def state(self) -> dict[str, Any]:
        """Return non-secret policy state suitable for ``doctor`` output."""
        with self._lock:
            lease = self._current_lease_locked()
            return {
                "readonly": self.config.readonly,
                "dryRun": self.config.dry_run,
                "defaultAuthorization": self.config.default_authorization.name.lower(),
                "confinementEnabled": self.config.confinement.enabled,
                "confirmationMode": "external",
                "launchedWindowCount": len(self._launched_identities),
                "mutationLease": (
                    {"owner": lease.owner, "expiresAt": lease.expires_at} if lease is not None else None
                ),
                "humanTakeoverActive": (
                    self.config.human_takeover_enabled and self._clock() < self._human_takeover_until
                ),
                "humanTakeoverUntil": self._human_takeover_until,
            }

    def detect_lock_screen(self) -> tuple[str, ...]:
        """Return matching lock process names from procfs; failures are ignored."""
        matches: set[str] = set()
        try:
            entries = tuple(self._proc_root.iterdir())
        except OSError:
            return ()
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                name = _normalize((entry / "comm").read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if name in self.config.lock_process_names:
                matches.add(name)
        return tuple(sorted(matches))

    def request_confirmation(self, request: ActionRequest, ttl_seconds: float | None = None) -> str:
        """Create a pending external-approval challenge and return its id.

        The returned id is deliberately not a usable confirmation by itself.
        A trusted local process must call :func:`approve_confirmation` before a
        matching destructive request can consume it.
        """
        if not request.destructive:
            raise ValueError("confirmation challenges may only be requested for destructive actions")
        ttl = self.config.confirmation_ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        if ttl <= 0:
            raise ValueError("confirmation TTL must be positive")
        challenge_id = secrets.token_hex(_CHALLENGE_ID_LENGTH // 2)
        now = self._wall_clock()
        challenge = {
            "version": 1,
            "challengeId": challenge_id,
            "owner": request.owner,
            "action": request.action,
            "target": dict(request.target.fingerprint()) if request.target else None,
            "scopeTargets": [dict(target.fingerprint()) for target in request.scope_targets],
            "context": dict(request.confirmation_context),
            "fingerprint": self._request_fingerprint(request),
            "createdAt": now,
            "expiresAt": now + ttl,
        }
        try:
            payload = json.dumps(challenge, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        except (TypeError, ValueError) as error:
            raise ValueError("confirmation context must be JSON serializable") from error
        if len(payload) > _CHALLENGE_FILE_LIMIT:
            raise ValueError("confirmation challenge is too large")
        directory = self._confirmation_dir or default_confirmation_directory()
        with self._lock:
            directory_fd = _open_confirmation_directory(directory, create=True)
            filename = _challenge_filename(challenge_id, "pending")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            capacity_lock_fd: int | None = None
            try:
                capacity_lock_fd = _lock_confirmation_directory(directory_fd)
                existing = _challenge_entries_locked(directory_fd, now)
                if len(existing) >= self.config.confirmation_pending_limit:
                    raise RuntimeError("confirmation challenge capacity exhausted")
                owner_entries = [item for item in existing if item is not None and item.get("owner") == request.owner]
                if len(owner_entries) >= self.config.confirmation_pending_per_owner:
                    raise RuntimeError("confirmation challenge capacity exhausted for owner")
                if self.config.confirmation_min_interval_seconds:
                    rate_state = _rate_state_locked(
                        capacity_lock_fd,
                        now,
                        self.config.confirmation_min_interval_seconds,
                    )
                    owner_key = hashlib.sha256(request.owner.encode()).hexdigest()
                    if owner_key in rate_state:
                        raise RuntimeError("confirmation challenge rate limit exceeded for owner")
                    if len(rate_state) >= self.config.confirmation_pending_limit:
                        raise RuntimeError("confirmation challenge rate-state capacity exhausted")
                else:
                    rate_state = {}
                    owner_key = ""
                file_fd = os.open(filename, flags, 0o600, dir_fd=directory_fd)
                try:
                    view = memoryview(payload)
                    while view:
                        written = os.write(file_fd, view)
                        if written <= 0:
                            raise RuntimeError("failed to write confirmation challenge")
                        view = view[written:]
                    os.fsync(file_fd)
                finally:
                    os.close(file_fd)
                if owner_key:
                    rate_state[owner_key] = now
                    _write_rate_state_locked(capacity_lock_fd, rate_state)
                os.fsync(directory_fd)
            finally:
                if capacity_lock_fd is not None:
                    os.close(capacity_lock_fd)
                os.close(directory_fd)
        return challenge_id

    def issue_confirmation(self, request: ActionRequest, ttl_seconds: float | None = None) -> str:
        """Compatibility alias that creates only a pending challenge.

        Despite the historical name, this method no longer issues a usable
        token and therefore cannot self-authorize an MCP request.
        """
        return self.request_confirmation(request, ttl_seconds)

    def evaluate(
        self,
        request: ActionRequest,
        guards: GuardInputs | None = None,
        *,
        preview_dry_run: bool = False,
    ) -> PolicyDecision:
        guards = guards or GuardInputs()
        target = request.target

        if target is not None and self.privacy_excluded(target):
            return self._deny(DecisionCode.PRIVACY_EXCLUDED, "target application is excluded by privacy policy")

        if request.mutating and guards.panic_active:
            return self._deny(DecisionCode.PANIC_ACTIVE, "panic stop is active; resume is required before mutations")
        if request.mutating and not guards.available:
            return self._deny(
                DecisionCode.GUARD_UNAVAILABLE,
                "native compositor guard state is unavailable",
                {"error": guards.error} if guards.error else {},
            )
        if request.mutating and guards.layer_surface_active and self.config.block_layer_mutation:
            return self._deny(DecisionCode.LAYER_SURFACE_ACTIVE, "an input-intercepting layer surface is active")
        if request.mutating and guards.keyboard_grab_active and self.config.block_keyboard_grab_mutation:
            return self._deny(DecisionCode.KEYBOARD_GRAB_ACTIVE, "another surface holds the keyboard grab")

        lock_processes = self.detect_lock_screen() if guards.screen_locked is None else ()
        locked = bool(lock_processes) if guards.screen_locked is None else guards.screen_locked
        if locked and ((request.mutating and self.config.block_locked_mutation) or (not request.mutating and self.config.block_locked_view)):
            return self._deny(
                DecisionCode.SCREEN_LOCKED,
                "screen lock is active",
                {"lockProcesses": list(lock_processes)},
            )

        if request.mutating and self.config.readonly:
            return self._deny(DecisionCode.READONLY, "security policy is in read-only mode")

        # Panic control is a server/compositor safety action rather than an
        # application action.  Stop/status must always work, while resume is
        # still constrained by readonly mode and one-time confirmation.
        authorized = AuthorizationLevel.FULL if request.action == "panic" else self.authorization_for(target)
        if authorized < request.required_level:
            return self._deny(
                DecisionCode.APP_PERMISSION,
                "application authorization level is insufficient",
                {"authorized": authorized.name.lower(), "required": request.required_level.name.lower()},
            )

        if request.mutating and request.action not in {"launch", "launch_app", "open_app", "panic"}:
            scoped_identities = (target, *request.scope_targets)
            if any(not self._in_scope(identity) for identity in scoped_identities):
                return self._deny(DecisionCode.OUT_OF_SCOPE, "source or resulting target is outside the configured confinement")

        if request.mutating and request.action != "panic" and self.human_takeover_active():
            return self._deny(DecisionCode.HUMAN_TAKEOVER, "recent human input paused agent mutations")

        missing_clipboard = request.clipboard_capabilities - self.config.clipboard_permissions
        if missing_clipboard:
            return self._deny(
                DecisionCode.CLIPBOARD_PERMISSION,
                "clipboard capability is not permitted",
                {"missing": sorted(item.value for item in missing_clipboard)},
            )

        # A dry-run never takes a mutation lease or consumes a one-time token.
        if request.mutating and (self.config.dry_run or preview_dry_run):
            return PolicyDecision(
                allowed=True,
                execute=False,
                code=DecisionCode.DRY_RUN,
                reason="action passed policy checks but dry-run mode suppresses execution",
                details={"wouldRequireConfirmation": request.destructive},
            )

        if request.mutating and self.config.mutation_lease_required:
            with self._lock:
                lease = self._current_lease_locked()
            if lease is None:
                return self._deny(DecisionCode.MUTATION_LEASE_REQUIRED, "a mutation lease is required")
            if lease.owner != request.owner:
                return self._deny(
                    DecisionCode.MUTATION_LEASE_HELD,
                    "another owner holds the mutation lease",
                    {"holder": lease.owner, "expiresAt": lease.expires_at},
                )

        if request.destructive:
            if not request.confirmation_token:
                return self._deny(DecisionCode.CONFIRMATION_REQUIRED, "destructive action requires confirmation")
            confirmation_status = self._consume_confirmation(request)
            if confirmation_status == "pending":
                return self._deny(
                    DecisionCode.CONFIRMATION_PENDING,
                    "confirmation challenge is awaiting external approval",
                    {"challengeId": request.confirmation_token},
                )
            if confirmation_status != "approved":
                return self._deny(DecisionCode.CONFIRMATION_INVALID, "confirmation token is invalid, expired, used, or does not match the action")

        return PolicyDecision(True, True, DecisionCode.ALLOW, "action is allowed")

    def authorization_for(self, target: WindowIdentity | None) -> AuthorizationLevel:
        if target is None:
            return self.config.default_authorization
        identity_levels: list[AuthorizationLevel] = []
        for class_name in target.class_identities():
            # Within one identity exact matches win, then the longest wildcard.
            matches = [
                (pattern == class_name, len(pattern), level)
                for pattern, level in self.config.app_authorizations.items()
                if fnmatch.fnmatchcase(class_name, pattern)
            ]
            identity_levels.append(
                max(matches, key=lambda item: (item[0], item[1]))[2]
                if matches
                else self.config.default_authorization
            )
        if not identity_levels:
            return self.config.default_authorization
        # A runtime class transition cannot raise an application's privilege.
        return min(identity_levels)

    def privacy_excluded(self, target: WindowIdentity | Mapping[str, Any]) -> bool:
        """Return whether a window is hidden by the configured privacy policy."""
        identity = WindowIdentity.from_window(target) if isinstance(target, Mapping) else target
        return any(
            self._matches_patterns(class_name, self.config.privacy_classes)
            for class_name in identity.class_identities()
        )

    def _in_scope(self, target: WindowIdentity | None) -> bool:
        config = self.config.confinement
        if not config.enabled:
            return True
        if target is None:
            return False
        address = _normalize_address(target.address)
        with self._lock:
            launched = target.launched or self._launched_identities.get(address) == self._launch_provenance(target)
        checks: list[bool] = []
        if config.launched_only:
            checks.append(launched)
        if config.classes:
            # initialClass is compositor-recorded at window creation and is the
            # stable confinement identity. Fall back to runtime class only for
            # synthetic/legacy identities that do not provide it.
            checks.append(self._matches_patterns(target.confinement_class(), config.classes))
        if config.workspaces:
            checks.append(_workspace_value(target.workspace) in config.workspaces)
        if config.addresses:
            checks.append(address in config.addresses)
        return all(checks) if config.match is ScopeMatch.ALL else any(checks)

    @staticmethod
    def _launch_provenance(target: WindowIdentity) -> Mapping[str, str]:
        # Workspace is mutable after a legitimate launch (move/minimize).
        # Provenance instead follows the immutable process/window tuple;
        # workspace confinement remains an independent `_in_scope` check.
        return {
            "address": _normalize_address(target.address),
            "class": target.confinement_class(),
            "initialClass": _normalize(target.initial_class),
            "pid": str(target.pid or ""),
            "processStartTime": str(target.process_start_time or ""),
        }

    @staticmethod
    def _matches_patterns(value: str, patterns: Iterable[str]) -> bool:
        normalized = _normalize(value)
        return any(fnmatch.fnmatchcase(normalized, _normalize(pattern)) for pattern in patterns)

    def _request_fingerprint(self, request: ActionRequest) -> str:
        body = {
            "action": request.action,
            "owner": request.owner,
            "target": request.target.fingerprint() if request.target else None,
            "scopeTargets": [target.fingerprint() for target in request.scope_targets],
            "context": dict(request.confirmation_context),
        }
        try:
            encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError) as error:
            raise ValueError("confirmation context must be JSON serializable") from error
        return hashlib.sha256(encoded.encode()).hexdigest()

    def _consume_confirmation(self, request: ActionRequest) -> str:
        assert request.confirmation_token is not None
        challenge_id = request.confirmation_token
        if not _valid_challenge_id(challenge_id):
            return "invalid"
        fingerprint = self._request_fingerprint(request)
        directory = self._confirmation_dir or default_confirmation_directory()
        with self._lock:
            try:
                directory_fd = _open_confirmation_directory(directory, create=False)
            except FileNotFoundError:
                return "invalid"
            try:
                pending = _challenge_filename(challenge_id, "pending")
                approved = _challenge_filename(challenge_id, "approved")
                try:
                    challenge = _read_challenge(directory_fd, approved)
                    state = "approved"
                    filename = approved
                except FileNotFoundError:
                    try:
                        challenge = _read_challenge(directory_fd, pending)
                    except (FileNotFoundError, RuntimeError, OSError):
                        return "invalid"
                    state = "pending"
                    filename = pending
                except (RuntimeError, OSError):
                    # Unsafe/malformed approved records (including a hard link
                    # to pending) are forged evidence, not a reason to crash
                    # the policy evaluator.
                    try:
                        os.unlink(approved, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                    except FileNotFoundError:
                        pass
                    try:
                        _dispatch_native_approval("cancel", challenge_id, None)
                    except (OSError, RuntimeError, ValueError):
                        pass
                    return "invalid"
                try:
                    expires_at = float(challenge.get("expiresAt", 0))
                except (TypeError, ValueError):
                    if state == "approved":
                        try:
                            os.unlink(filename, dir_fd=directory_fd)
                        except FileNotFoundError:
                            pass
                        try:
                            _dispatch_native_approval("cancel", challenge_id, None)
                        except (OSError, RuntimeError, ValueError):
                            pass
                    return "invalid"
                if expires_at <= self._wall_clock():
                    try:
                        os.unlink(filename, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
                    if state == "approved":
                        try:
                            _dispatch_native_approval("cancel", challenge_id, None)
                        except (OSError, RuntimeError, ValueError):
                            pass
                    return "invalid"
                valid = bool(
                    challenge.get("challengeId") == challenge_id
                    and hmac.compare_digest(
                        str(challenge.get("owner", "")).encode(),
                        request.owner.encode(),
                    )
                    and hmac.compare_digest(str(challenge.get("fingerprint", "")), fingerprint)
                )
                if not valid:
                    return "invalid"
                if state == "pending":
                    return "pending"

                # The JSON record is not an authorization proof by itself: a
                # FULL-authorized same-UID app could otherwise copy/link a
                # pending record to the approved name.  Require the matching
                # compositor-resident physical-F12 state at final consumption.
                try:
                    native_approved = _dispatch_native_approval("status", challenge_id, None)
                except (OSError, RuntimeError, ValueError):
                    native_approved = False
                if not native_approved:
                    try:
                        os.unlink(approved, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                    except FileNotFoundError:
                        pass
                    try:
                        _dispatch_native_approval("cancel", challenge_id, None)
                    except (OSError, RuntimeError, ValueError):
                        pass
                    return "invalid"

                try:
                    os.unlink(approved, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    return "approved"
                finally:
                    try:
                        _dispatch_native_approval("cancel", challenge_id, None)
                    except (OSError, RuntimeError, ValueError):
                        pass
            finally:
                os.close(directory_fd)

    @staticmethod
    def _deny(code: DecisionCode, reason: str, details: Mapping[str, Any] | None = None) -> PolicyDecision:
        return PolicyDecision(False, False, code, reason, details or {})


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _env_set(env: Mapping[str, str], name: str) -> frozenset[str]:
    return frozenset(item.strip() for item in env.get(name, "").split(",") if item.strip())


def policy_config_from_env(env: Mapping[str, str] | None = None) -> PolicyConfig:
    """Build policy configuration from ``HYPR_AGENT_PORTAL_SECURITY_*`` vars."""
    source = os.environ if env is None else env
    values = dict(source)
    prefix = "HYPR_AGENT_PORTAL_SECURITY_"

    # Public short aliases keep the common configuration approachable while
    # SECURITY_* remains the unambiguous canonical form. Canonical values win.
    for short_name, canonical_name in {
        "HYPR_AGENT_PORTAL_READONLY": prefix + "READONLY",
        "HYPR_AGENT_PORTAL_DRYRUN": prefix + "DRY_RUN",
        "HYPR_AGENT_PORTAL_APP_POLICIES": prefix + "APP_AUTHORIZATIONS",
        "HYPR_AGENT_PORTAL_PRIVACY_CLASSES": prefix + "PRIVACY_CLASSES",
    }.items():
        if canonical_name not in values and short_name in values:
            values[canonical_name] = values[short_name]

    confinement = values.get("HYPR_AGENT_PORTAL_CONFINE", "")
    if confinement:
        buckets: dict[str, list[str]] = {"class": [], "workspace": [], "address": []}
        launched_only = False
        for item in (part.strip() for part in confinement.split(",") if part.strip()):
            if item.casefold() == "launched":
                launched_only = True
                continue
            kind, separator, value = item.partition(":")
            if not separator or kind.casefold() not in buckets or not value.strip():
                raise ValueError(f"invalid HYPR_AGENT_PORTAL_CONFINE item: {item!r}")
            buckets[kind.casefold()].append(value.strip())
        values.setdefault(prefix + "CONFINE_LAUNCHED", "1" if launched_only else "0")
        values.setdefault(prefix + "CONFINE_CLASSES", ",".join(buckets["class"]))
        values.setdefault(prefix + "CONFINE_WORKSPACES", ",".join(buckets["workspace"]))
        values.setdefault(prefix + "CONFINE_ADDRESSES", ",".join(buckets["address"]))

    if prefix + "CLIPBOARD_PERMISSIONS" not in values and "HYPR_AGENT_PORTAL_CLIPBOARD" in values:
        clipboard_short = values["HYPR_AGENT_PORTAL_CLIPBOARD"].strip().casefold()
        clipboard_aliases = {
            "none": "",
            "read": "read",
            "write": "write",
            "full": ",".join(item.value for item in ClipboardCapability),
        }
        values[prefix + "CLIPBOARD_PERMISSIONS"] = clipboard_aliases.get(
            clipboard_short, values["HYPR_AGENT_PORTAL_CLIPBOARD"]
        )
    authorizations: dict[str, AuthorizationLevel] = {}
    for entry in _env_set(values, prefix + "APP_AUTHORIZATIONS"):
        if "=" not in entry:
            raise ValueError(f"invalid app authorization {entry!r}; expected pattern=level")
        pattern, level = entry.rsplit("=", 1)
        if not pattern.strip():
            raise ValueError("application authorization pattern must not be empty")
        authorizations[pattern.strip()] = AuthorizationLevel.parse(level)
    clipboard_raw = values.get(prefix + "CLIPBOARD_PERMISSIONS")
    clipboard = (
        PolicyConfig().clipboard_permissions
        if clipboard_raw is None
        else frozenset(ClipboardCapability.parse(item) for item in _env_set(values, prefix + "CLIPBOARD_PERMISSIONS"))
    )
    confinement = ConfinementConfig(
        launched_only=_env_bool(values, prefix + "CONFINE_LAUNCHED", False),
        classes=_env_set(values, prefix + "CONFINE_CLASSES"),
        workspaces=_env_set(values, prefix + "CONFINE_WORKSPACES"),
        addresses=_env_set(values, prefix + "CONFINE_ADDRESSES"),
        match=ScopeMatch(values.get(prefix + "CONFINE_MATCH", ScopeMatch.ANY.value).strip().lower()),
    )
    return PolicyConfig(
        readonly=_env_bool(values, prefix + "READONLY", False),
        dry_run=_env_bool(values, prefix + "DRY_RUN", False),
        confinement=confinement,
        default_authorization=AuthorizationLevel.parse(values.get(prefix + "DEFAULT_AUTHORIZATION", "view")),
        app_authorizations=authorizations,
        mutation_lease_required=_env_bool(values, prefix + "MUTATION_LEASE_REQUIRED", True),
        mutation_lease_ttl_seconds=float(values.get(prefix + "MUTATION_LEASE_TTL", "30")),
        confirmation_ttl_seconds=float(values.get(prefix + "CONFIRMATION_TTL", "60")),
        confirmation_pending_limit=int(values.get(prefix + "CONFIRMATION_PENDING_LIMIT", "128")),
        confirmation_pending_per_owner=int(values.get(prefix + "CONFIRMATION_PENDING_PER_OWNER", "16")),
        confirmation_min_interval_seconds=float(values.get(prefix + "CONFIRMATION_MIN_INTERVAL", "0")),
        clipboard_permissions=clipboard,
        privacy_classes=_env_set(values, prefix + "PRIVACY_CLASSES"),
        block_locked_view=_env_bool(values, prefix + "BLOCK_LOCKED_VIEW", True),
        block_locked_mutation=_env_bool(values, prefix + "BLOCK_LOCKED_MUTATION", True),
        block_layer_mutation=_env_bool(values, prefix + "BLOCK_LAYER_MUTATION", True),
        block_keyboard_grab_mutation=_env_bool(values, prefix + "BLOCK_KEYBOARD_GRAB_MUTATION", True),
        human_takeover_enabled=_env_bool(values, prefix + "HUMAN_TAKEOVER", True),
        human_takeover_cooldown_seconds=float(values.get(prefix + "HUMAN_TAKEOVER_COOLDOWN", "2")),
        lock_process_names=_env_set(values, prefix + "LOCK_PROCESSES") or PolicyConfig().lock_process_names,
    )


def policy_from_env(env: Mapping[str, str] | None = None, **kwargs: Any) -> SecurityPolicy:
    return SecurityPolicy(policy_config_from_env(env), **kwargs)


def _approval_cli(arguments: list[str]) -> int:
    if len(arguments) not in {2, 4} or arguments[0] != "approve" or (
        len(arguments) == 4 and arguments[2] != "--directory"
    ):
        print(
            "usage: security_policy.py approve CHALLENGE_ID [--directory PATH]",
            file=sys.stderr,
        )
        return 2
    challenge_id = arguments[1]
    directory = arguments[3] if len(arguments) == 4 else None
    print(f"Physical approval requested for challenge {challenge_id}; press F12 on a real keyboard.")
    try:
        challenge = approve_confirmation(challenge_id, confirmation_dir=directory)
    except KeyboardInterrupt:
        print("approval cancelled", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError) as error:
        print(f"approval failed: {error}", file=sys.stderr)
        return 1
    print(f"approved {challenge['action']} for owner {challenge['owner']}")
    return 0


__all__ = [
    "ActionRequest",
    "AuthorizationLevel",
    "ClipboardCapability",
    "ConfinementConfig",
    "DecisionCode",
    "GuardInputs",
    "MutationLease",
    "PolicyConfig",
    "PolicyDecision",
    "ScopeMatch",
    "SecurityPolicy",
    "WindowIdentity",
    "approve_confirmation",
    "default_confirmation_directory",
    "policy_config_from_env",
    "policy_from_env",
    "reject_confirmation",
]


if __name__ == "__main__":
    raise SystemExit(_approval_cli(sys.argv[1:]))
