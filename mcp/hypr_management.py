"""Targeted Hyprland window and workspace management.

This module is intentionally independent from the MCP transport and security
policy.  It validates every value used in a ``hyprctl`` argument, never invokes
a shell, and verifies mutations against a fresh compositor snapshot.  The MCP
layer remains responsible for policy, confirmation, process leases, and audit
logging before calling :class:`HyprManagement`.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Callable, Mapping, Protocol, Sequence

_ADDRESS_RE = re.compile(r"^(?:address:)?(0x[0-9a-fA-F]+)$")
_QUALIFIED_ADDRESS_RE = re.compile(
    r"^(?P<address>address:0x[0-9a-fA-F]+)@pid=[1-9][0-9]*@start=[1-9][0-9]*$"
)
_SAFE_WORKSPACE_RE = re.compile(r"^[^,;\r\n\x00]{1,128}$")
_SAFE_NAME_RE = re.compile(r"^[^,;\r\n\x00]{1,96}$")


class HyprManagementError(RuntimeError):
    """Base error returned by this module."""


class InvalidRequest(HyprManagementError, ValueError):
    """An unsafe or unsupported management request."""


class TargetNotFound(HyprManagementError):
    """The requested window or workspace does not exist."""


class CommandFailed(HyprManagementError):
    """A hyprctl command failed before state could be verified."""


class VerificationFailed(HyprManagementError):
    """Hyprland did not reach the requested state."""


class StaleTarget(VerificationFailed):
    """The selected address no longer identifies the window that was bound."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class ManagementResult:
    action: str
    target: str
    commands: tuple[tuple[str, ...], ...]
    before: Mapping[str, Any] | None
    after: Mapping[str, Any] | None
    changed: bool
    verified: bool
    destructive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "commands": [list(command) for command in self.commands],
            "before": dict(self.before) if self.before is not None else None,
            "after": dict(self.after) if self.after is not None else None,
            "changed": self.changed,
            "verified": self.verified,
            "mutating": True,
            "destructive": self.destructive,
        }


@dataclass(frozen=True)
class WindowIdentity:
    """Fields that distinguish a window from a recycled Hyprland address."""

    address: str
    pid: str
    class_name: str
    initial_class: str
    process_start_time: str | None = None


_PROCESS_START_FIELDS = (
    "processStartTime",
    "processStarttime",
    "process_start_time",
    "process_starttime",
    "pidStartTime",
    "startTime",
    "starttime",
)


def window_identity(window: Mapping[str, Any]) -> WindowIdentity:
    """Freeze the identity fields exposed by one ``hyprctl clients`` row."""

    try:
        address = bare_address(window.get("address", ""))
    except InvalidRequest as error:
        raise VerificationFailed(f"window state has an invalid address: {window.get('address')!r}") from error
    start_time = next((window.get(field) for field in _PROCESS_START_FIELDS if field in window), None)
    return WindowIdentity(
        address=address,
        pid=str(window.get("pid", "")),
        class_name=str(window.get("class", "")),
        initial_class=str(window.get("initialClass", "")),
        process_start_time=None if start_time is None else str(start_time),
    )


def identity_matches(window: Mapping[str, Any] | None, expected: WindowIdentity) -> bool:
    if window is None:
        return False
    try:
        return window_identity(window) == expected
    except VerificationFailed:
        return False


def process_start_time(pid: Any) -> str:
    """Read Linux /proc field 22 without trusting whitespace in comm."""

    try:
        pid_text = str(int(pid))
        if int(pid_text) <= 0:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise VerificationFailed("window identity requires a positive pid") from error
    try:
        with open(f"/proc/{pid_text}/stat", "r", encoding="utf-8") as stream:
            line = stream.readline().rstrip("\n")
    except OSError as error:
        raise VerificationFailed(f"cannot read process start time for pid {pid_text}") from error
    close = line.rfind(")")
    fields = line[close + 2 :].split() if close >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit() or int(fields[19]) <= 0:
        raise VerificationFailed(f"invalid process start time for pid {pid_text}")
    return fields[19]


def qualified_window_target(window: Mapping[str, Any]) -> str:
    identity = window_identity(window)
    if not identity.pid.isdigit() or int(identity.pid) <= 0:
        raise VerificationFailed("window identity requires a positive pid")
    start = identity.process_start_time or process_start_time(identity.pid)
    if not str(start).isdigit() or int(str(start)) <= 0:
        raise VerificationFailed("window identity requires a positive process start time")
    return f"address:{identity.address.lower()}@pid={identity.pid}@start={start}"


class StateClient(Protocol):
    def clients(self) -> list[Mapping[str, Any]]: ...

    def workspaces(self) -> list[Mapping[str, Any]]: ...

    def active_window(self) -> Mapping[str, Any]: ...

    def active_workspace(self) -> Mapping[str, Any]: ...


Runner = Callable[[Sequence[str]], Any]


def normalize_address(address: str) -> str:
    selector = str(address).strip()
    qualified = _QUALIFIED_ADDRESS_RE.fullmatch(selector)
    if qualified is not None:
        selector = qualified.group("address")
    elif selector.startswith("address:") and "@" in selector:
        raise InvalidRequest("malformed qualified window selector")
    match = _ADDRESS_RE.fullmatch(selector)
    if not match:
        raise InvalidRequest("window target must be an address:0x... selector")
    return f"address:{match.group(1).lower()}"


def bare_address(address: Any) -> str:
    return normalize_address(str(address)).split(":", 1)[1]


def address_matches(left: Any, right: Any) -> bool:
    try:
        return bare_address(left) == bare_address(right)
    except InvalidRequest:
        return False


def normalize_workspace(workspace: str | int, *, allow_special: bool = True) -> str:
    """Return a deterministic Hyprland workspace selector.

    Positive integers select numbered workspaces.  Ordinary strings are made
    explicit ``name:`` selectors.  ``special`` is the default special workspace
    and ``special:NAME`` is a named special workspace.  Relative selectors are
    deliberately rejected because they cannot be verified deterministically.
    """

    if isinstance(workspace, bool):
        raise InvalidRequest("workspace must not be boolean")
    if isinstance(workspace, int):
        if workspace <= 0:
            raise InvalidRequest("numbered workspaces must be positive")
        return str(workspace)
    value = str(workspace).strip()
    if not _SAFE_WORKSPACE_RE.fullmatch(value):
        raise InvalidRequest("workspace contains a delimiter or control character")
    if value.isdecimal():
        number = int(value)
        if number <= 0:
            raise InvalidRequest("numbered workspaces must be positive")
        return str(number)
    lower = value.casefold()
    if lower == "special":
        if not allow_special:
            raise InvalidRequest("special workspaces are not valid for this action")
        return "special"
    if lower.startswith("special:"):
        if not allow_special:
            raise InvalidRequest("special workspaces are not valid for this action")
        name = value.split(":", 1)[1].strip()
        if not name or not _SAFE_NAME_RE.fullmatch(name):
            raise InvalidRequest("special workspace name is invalid")
        return f"special:{name}"
    if lower.startswith("name:"):
        name = value.split(":", 1)[1].strip()
        if not name or not _SAFE_NAME_RE.fullmatch(name):
            raise InvalidRequest("named workspace is invalid")
        return f"name:{name}"
    if value in {"+1", "-1", "previous", "previous_per_monitor", "empty"}:
        raise InvalidRequest("relative workspace selectors are not supported")
    if not _SAFE_NAME_RE.fullmatch(value):
        raise InvalidRequest("named workspace is invalid")
    return f"name:{value}"


def _workspace_name(workspace: Mapping[str, Any] | Any) -> str:
    if isinstance(workspace, Mapping):
        return str(workspace.get("name", workspace.get("id", "")))
    return str(workspace)


def workspace_matches(workspace: Mapping[str, Any] | Any, selector: str) -> bool:
    name = _workspace_name(workspace)
    if selector.isdecimal():
        if isinstance(workspace, Mapping) and str(workspace.get("id", "")) == selector:
            return True
        return name == selector
    if selector.startswith("name:"):
        return name == selector.split(":", 1)[1]
    if selector == "special":
        return name in {"special", "special:special"}
    return name == selector


def _integer(value: Any, field: str, *, minimum: int = -100000, maximum: int = 100000) -> int:
    if isinstance(value, bool):
        raise InvalidRequest(f"{field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise InvalidRequest(f"{field} must be an integer") from error
    if str(value).strip() not in {str(parsed), f"+{parsed}"} and not isinstance(value, int):
        raise InvalidRequest(f"{field} must be an integer")
    if not minimum <= parsed <= maximum:
        raise InvalidRequest(f"{field} is outside the supported range")
    return parsed


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise InvalidRequest(f"{field} must be a boolean")
    return value


def _coerce_result(value: Any) -> CommandResult:
    if isinstance(value, CommandResult):
        return value
    if isinstance(value, subprocess.CompletedProcess):
        return CommandResult(value.returncode, str(value.stdout or ""), str(value.stderr or ""))
    if isinstance(value, Mapping):
        return CommandResult(int(value.get("returncode", 0)), str(value.get("stdout", "")), str(value.get("stderr", "")))
    if isinstance(value, str):
        return CommandResult(stdout=value)
    if value is None:
        return CommandResult()
    raise TypeError("runner returned an unsupported result")


def subprocess_runner(argv: Sequence[str]) -> CommandResult:
    command = list(argv)
    if len(command) == 4 and command[:3] == ["hyprctl", "dispatch", "hypr-agent-portal:manage"]:
        source_ctl = Path(__file__).resolve().parents[1] / "scripts" / "hypr-agent-portalctl"
        portalctl = shutil.which("hypr-agent-portalctl") or (str(source_ctl) if source_ctl.is_file() else "")
        if not portalctl:
            raise CommandFailed("hypr-agent-portalctl is required for provider-aware native management dispatch")
        command = [portalctl, "manage", command[3]]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5.0)
    except subprocess.TimeoutExpired as error:
        raise CommandFailed("hyprctl timed out") from error
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


class HyprctlStateClient:
    def __init__(self, runner: Runner = subprocess_runner) -> None:
        self._runner = runner

    def _query(self, name: str) -> Any:
        result = _coerce_result(self._runner(("hyprctl", "-j", name)))
        if result.returncode != 0:
            raise CommandFailed(result.stderr.strip() or f"hyprctl -j {name} failed")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise CommandFailed(f"hyprctl -j {name} returned invalid JSON") from error

    def clients(self) -> list[Mapping[str, Any]]:
        value = self._query("clients")
        if not isinstance(value, list):
            raise CommandFailed("hyprctl clients response is not a list")
        return value

    def workspaces(self) -> list[Mapping[str, Any]]:
        value = self._query("workspaces")
        if not isinstance(value, list):
            raise CommandFailed("hyprctl workspaces response is not a list")
        return value

    def active_window(self) -> Mapping[str, Any]:
        value = self._query("activewindow")
        return value if isinstance(value, Mapping) else {}

    def active_workspace(self) -> Mapping[str, Any]:
        value = self._query("activeworkspace")
        return value if isinstance(value, Mapping) else {}


class HyprManagement:
    """Generate, execute, and verify targeted Hyprland management actions."""

    def __init__(self, runner: Runner = subprocess_runner, state: StateClient | None = None) -> None:
        self.runner = runner
        self.state = state or HyprctlStateClient(runner)
        self._minimized_from: dict[WindowIdentity, str] = {}

    def _run(self, command: Sequence[str]) -> None:
        result = _coerce_result(self.runner(tuple(command)))
        if result.returncode != 0:
            raise CommandFailed(result.stderr.strip() or result.stdout.strip() or "hyprctl command failed")

    def _clients(self) -> list[Mapping[str, Any]]:
        return list(self.state.clients())

    def _window(self, target: str, *, required: bool = True) -> Mapping[str, Any] | None:
        wanted = bare_address(target)
        for window in self._clients():
            try:
                if bare_address(window.get("address", "")) == wanted:
                    return window
            except InvalidRequest:
                continue
        if required:
            raise TargetNotFound(f"window {normalize_address(target)} was not found")
        return None

    def _execute_window(
        self,
        action: str,
        target: str,
        commands: Sequence[Sequence[str]],
        before: Mapping[str, Any],
        verify: Callable[[Mapping[str, Any] | None], bool],
        *,
        destructive: bool = False,
    ) -> ManagementResult:
        frozen = tuple(tuple(command) for command in commands)
        if not frozen:
            return ManagementResult(action, target, (), before, before, False, True, destructive)
        identity = window_identity(before)
        current = self._window(target, required=False)
        if not identity_matches(current, identity):
            raise StaleTarget(
                f"{action} refused stale target {target}: expected {identity!r}, observed {current!r}"
            )
        for command in frozen:
            self._run(command)
        after = self._window(target, required=False)
        if not destructive and not identity_matches(after, identity):
            raise StaleTarget(
                f"{action} target identity changed for {target}: expected {identity!r}, observed {after!r}"
            )
        if not verify(after):
            raise VerificationFailed(f"{action} verification failed for {target}: observed {after!r}")
        return ManagementResult(action, target, frozen, before, after, True, True, destructive)

    @staticmethod
    def _manage_command(action: str, before: Mapping[str, Any], *arguments: Any) -> tuple[str, ...]:
        allowed = {
            "focus", "close", "move", "resize", "minimize", "restore",
            "maximize", "unmaximize", "fullscreen", "unfullscreen",
            "floating", "tiled", "pin", "unpin", "move_to_workspace",
        }
        if action not in allowed:
            raise InvalidRequest(f"unsupported native management action: {action!r}")
        target = qualified_window_target(before)
        payload = ",".join((action, target, *(str(value) for value in arguments)))
        return ("hyprctl", "dispatch", "hypr-agent-portal:manage", payload)

    def focus(self, address: str) -> ManagementResult:
        target = normalize_address(address)
        before = self._window(target)
        active = self.state.active_window()
        if active and address_matches(active.get("address", ""), target):
            return ManagementResult("focus", target, (), before, before, False, True)
        command = self._manage_command("focus", before)
        return self._execute_window(
            "focus", target, (command,), before,
            lambda after: after is not None and address_matches(self.state.active_window().get("address", ""), target),
        )

    def close(self, address: str) -> ManagementResult:
        target = normalize_address(address)
        before = self._window(target)
        identity = window_identity(before)
        command = self._manage_command("close", before)
        return self._execute_window(
            "close",
            target,
            (command,),
            before,
            lambda after: after is None or not identity_matches(after, identity),
            destructive=True,
        )

    def move(self, address: str, x: int, y: int) -> ManagementResult:
        target = normalize_address(address)
        before = self._window(target)
        point = (_integer(x, "x"), _integer(y, "y"))
        if tuple(before.get("at", ())) == point:
            return ManagementResult("move", target, (), before, before, False, True)
        command = self._manage_command("move", before, point[0], point[1])
        return self._execute_window("move", target, (command,), before, lambda after: after is not None and tuple(after.get("at", ())) == point)

    def resize(self, address: str, width: int, height: int) -> ManagementResult:
        target = normalize_address(address)
        before = self._window(target)
        size = (_integer(width, "width", minimum=1), _integer(height, "height", minimum=1))
        if tuple(before.get("size", ())) == size:
            return ManagementResult("resize", target, (), before, before, False, True)
        command = self._manage_command("resize", before, size[0], size[1])
        return self._execute_window("resize", target, (command,), before, lambda after: after is not None and tuple(after.get("size", ())) == size)

    def move_to_workspace(self, address: str, workspace: str | int, *, follow: bool = False) -> ManagementResult:
        target = normalize_address(address)
        selector = normalize_workspace(workspace)
        follow = _boolean(follow, "follow")
        before = self._window(target)
        if workspace_matches(before.get("workspace", {}), selector):
            return ManagementResult("move_to_workspace", target, (), before, before, False, True)
        command = self._manage_command("move_to_workspace", before, selector, "follow" if follow else "silent")
        return self._execute_window(
            "move_to_workspace", target, (command,), before,
            lambda after: after is not None and workspace_matches(after.get("workspace", {}), selector),
        )

    def minimize(
        self,
        address: str,
        enabled: bool = True,
        *,
        minimized_workspace: str = "special:hypr-agent-portal-minimized",
        restore_workspace: str | int | None = None,
    ) -> ManagementResult:
        target = normalize_address(address)
        before = self._window(target)
        minimized = normalize_workspace(minimized_workspace)
        if not minimized.startswith("special"):
            raise InvalidRequest("minimize requires a special workspace")
        key = window_identity(before)
        enabled = _boolean(enabled, "enabled")
        if enabled:
            if workspace_matches(before.get("workspace", {}), minimized):
                return ManagementResult("minimize", target, (), before, before, False, True)
            original = _workspace_name(before.get("workspace", {}))
            command = self._manage_command("minimize", before, minimized)
            result = self._execute_window(
                "minimize", target, (command,), before,
                lambda after: after is not None and workspace_matches(after.get("workspace", {}), minimized),
            )
            self._minimized_from[key] = normalize_workspace(original)
            return ManagementResult(
                "minimize", result.target, result.commands, result.before,
                result.after, result.changed, result.verified,
            )
        destination = normalize_workspace(restore_workspace) if restore_workspace is not None else self._minimized_from.get(key)
        if not destination:
            raise InvalidRequest("restore_workspace is required when the original workspace is unknown")
        command = self._manage_command("restore", before, destination)
        result = self._execute_window(
            "restore", target, (command,), before,
            lambda after: after is not None and workspace_matches(after.get("workspace", {}), destination),
        )
        self._minimized_from.pop(key, None)
        return ManagementResult("restore", result.target, result.commands, result.before, result.after, result.changed, result.verified)

    def _fullscreen_mode(self, address: str, mode: int, action: str, enabled: bool) -> ManagementResult:
        target = normalize_address(address)
        before = self._window(target)
        current = int(before.get("fullscreen", 0) or 0)
        desired = mode if enabled else 0
        # Maximized and fullscreen are distinct Hyprland modes.  Unsetting one
        # must not accidentally unset (or toggle into) the other.
        if (enabled and current == mode) or (not enabled and current != mode):
            return ManagementResult(action, target, (), before, before, False, True)
        native_action = (
            "maximize" if mode == 1 and enabled else
            "unmaximize" if mode == 1 else
            "fullscreen" if enabled else
            "unfullscreen"
        )
        command = self._manage_command(native_action, before)
        return self._execute_window(
            action, target, (command,), before,
            lambda after: after is not None and int(after.get("fullscreen", 0) or 0) == desired,
        )

    def maximize(self, address: str, enabled: bool = True) -> ManagementResult:
        # Hyprland JSON encodes maximized as 1; dispatcher argument 1 toggles it.
        return self._fullscreen_mode(address, 1, "maximize", _boolean(enabled, "enabled"))

    def fullscreen(self, address: str, enabled: bool = True) -> ManagementResult:
        # Hyprland JSON encodes fullscreen as 2; dispatcher argument 0 toggles it.
        return self._fullscreen_mode(address, 2, "fullscreen", _boolean(enabled, "enabled"))

    def _toggle_property(self, address: str, field: str, enabled_action: str, disabled_action: str, enabled: bool) -> ManagementResult:
        target = normalize_address(address)
        before = self._window(target)
        desired = _boolean(enabled, "enabled")
        if bool(before.get(field, False)) == desired:
            return ManagementResult(field, target, (), before, before, False, True)
        command = self._manage_command(enabled_action if desired else disabled_action, before)
        return self._execute_window(field, target, (command,), before, lambda after: after is not None and bool(after.get(field, False)) == desired)

    def floating(self, address: str, enabled: bool = True) -> ManagementResult:
        return self._toggle_property(address, "floating", "floating", "tiled", enabled)

    def pin(self, address: str, enabled: bool = True) -> ManagementResult:
        return self._toggle_property(address, "pinned", "pin", "unpin", enabled)

    def list_workspaces(self, *, include_special: bool = True) -> list[dict[str, Any]]:
        workspaces = [dict(item) for item in self.state.workspaces()]
        if include_special:
            return workspaces
        return [item for item in workspaces if not _workspace_name(item).startswith("special")]

    def _find_workspace(self, selector: str) -> Mapping[str, Any] | None:
        return next((workspace for workspace in self.state.workspaces() if workspace_matches(workspace, selector)), None)

    def switch_workspace(self, workspace: str | int) -> ManagementResult:
        selector = normalize_workspace(workspace)
        before = dict(self.state.active_workspace())
        if workspace_matches(before, selector):
            return ManagementResult("switch_workspace", selector, (), before, before, False, True)
        if self._find_workspace(selector) is None:
            raise TargetNotFound(f"workspace {selector} was not found")
        command = ("hyprctl", "dispatch", "hypr-agent-portal:manage", f"workspace_switch,{selector}")
        self._run(command)
        after = dict(self.state.active_workspace())
        if not workspace_matches(after, selector):
            raise VerificationFailed(f"workspace switch verification failed: observed {after!r}")
        return ManagementResult("switch_workspace", selector, (command,), before, after, True, True)

    def create_workspace(self, workspace: str | int) -> ManagementResult:
        selector = normalize_workspace(workspace)
        if self._find_workspace(selector) is not None:
            raise InvalidRequest(f"workspace {selector} already exists")
        before = dict(self.state.active_workspace())
        command = ("hyprctl", "dispatch", "hypr-agent-portal:manage", f"workspace_create,{selector}")
        self._run(command)
        after = dict(self.state.active_workspace())
        if not workspace_matches(after, selector):
            raise VerificationFailed(f"workspace create verification failed: observed {after!r}")
        return ManagementResult("create_workspace", selector, (command,), before, after, True, True)

    def create_or_activate_workspace(self, workspace: str | int) -> ManagementResult:
        selector = normalize_workspace(workspace)
        existed = self._find_workspace(selector) is not None
        before = dict(self.state.active_workspace())
        if workspace_matches(before, selector):
            return ManagementResult("activate_workspace", selector, (), before, before, False, True)
        command = ("hyprctl", "dispatch", "hypr-agent-portal:manage", f"workspace_activate,{selector}")
        self._run(command)
        after = dict(self.state.active_workspace())
        if not workspace_matches(after, selector):
            raise VerificationFailed(f"workspace activate verification failed: observed {after!r}")
        return ManagementResult(
            "activate_workspace" if existed else "create_workspace",
            selector,
            (command,),
            before,
            after,
            True,
            True,
        )

    def rename_workspace(self, workspace: str | int, new_name: str) -> ManagementResult:
        selector = normalize_workspace(workspace, allow_special=False)
        current = self._find_workspace(selector)
        if current is None:
            raise TargetNotFound(f"workspace {selector} was not found")
        workspace_id = _integer(current.get("id"), "workspace id", minimum=1)
        name = str(new_name).strip()
        if not _SAFE_NAME_RE.fullmatch(name) or name.startswith(("name:", "special:")):
            raise InvalidRequest("new workspace name must be a plain safe name")
        if _workspace_name(current) == name:
            return ManagementResult("rename_workspace", selector, (), current, current, False, True)
        command = ("hyprctl", "dispatch", "hypr-agent-portal:manage", f"workspace_rename,{selector},{name}")
        self._run(command)
        after = self._find_workspace(f"name:{name}")
        if after is None or int(after.get("id", -1)) != workspace_id:
            raise VerificationFailed(f"workspace rename verification failed: expected id {workspace_id} named {name!r}")
        return ManagementResult("rename_workspace", selector, (command,), current, after, True, True)

    def special_workspace(self, action: str, workspace: str | int) -> tuple[str, ...]:
        normalized = str(action).strip().casefold().replace("-", "_")
        native = {"show_special": "special_show", "hide_special": "special_hide", "toggle_special": "special_toggle"}.get(normalized)
        selector = normalize_workspace(workspace)
        if native is None or not (selector == "special" or selector.startswith("special:")):
            raise InvalidRequest("special workspace action or selector is invalid")
        command = ("hyprctl", "dispatch", "hypr-agent-portal:manage", f"{native},{selector}")
        self._run(command)
        return command

    def window_action(self, action: str, address: str, **arguments: Any) -> ManagementResult:
        actions: dict[str, Callable[..., ManagementResult]] = {
            "focus": self.focus,
            "close": self.close,
            "move": self.move,
            "resize": self.resize,
            "minimize": self.minimize,
            "maximize": self.maximize,
            "fullscreen": self.fullscreen,
            "floating": self.floating,
            "pin": self.pin,
            "move_to_workspace": self.move_to_workspace,
            "movetoworkspace": self.move_to_workspace,
        }
        handler = actions.get(str(action).strip().casefold())
        if handler is None:
            raise InvalidRequest(f"unsupported window action: {action!r}")
        return handler(address, **arguments)

    def workspace_action(self, action: str, **arguments: Any) -> ManagementResult | list[dict[str, Any]]:
        normalized = str(action).strip().casefold().replace("-", "_")
        if normalized == "list":
            return self.list_workspaces(**arguments)
        if normalized in {"switch", "activate"}:
            return self.switch_workspace(arguments["workspace"])
        if normalized == "create":
            return self.create_workspace(arguments["workspace"])
        if normalized == "create_or_activate":
            return self.create_or_activate_workspace(arguments["workspace"])
        if normalized == "rename":
            return self.rename_workspace(arguments["workspace"], arguments["new_name"])
        if normalized in {"move_window", "move_window_to_workspace"}:
            return self.move_to_workspace(arguments["address"], arguments["workspace"], follow=arguments.get("follow", False))
        raise InvalidRequest(f"unsupported workspace action: {action!r}")


__all__ = [
    "CommandFailed",
    "CommandResult",
    "HyprManagement",
    "HyprManagementError",
    "HyprctlStateClient",
    "InvalidRequest",
    "ManagementResult",
    "StaleTarget",
    "TargetNotFound",
    "VerificationFailed",
    "WindowIdentity",
    "address_matches",
    "bare_address",
    "identity_matches",
    "normalize_address",
    "normalize_workspace",
    "process_start_time",
    "qualified_window_target",
    "subprocess_runner",
    "window_identity",
    "workspace_matches",
]
