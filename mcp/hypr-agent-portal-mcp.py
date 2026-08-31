#!/usr/bin/env python3
import base64
import copy
import hashlib
import json
import math
import mimetypes
import os
import pathlib
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


MCP_MODULE_DIR = pathlib.Path(__file__).resolve().parent
if str(MCP_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_MODULE_DIR))

from compat_env import promote_legacy_environment
from security_audit import AuditJournal, ReplayPolicy, preflight_replay
from security_doctor import security_readiness_diagnostics
from process_lease import LeaseConflict, ProcessLeaseError, ProcessMutationLease
from security_policy import (
    ActionRequest,
    AuthorizationLevel,
    ClipboardCapability,
    DecisionCode,
    GuardInputs,
    PolicyDecision,
    SecurityPolicy,
    WindowIdentity,
    policy_from_env,
)
from action_sequence import CancellationToken, run_action_sequence
from hypr_management import HyprManagement, normalize_workspace
from hypr_socket2 import wait_for_close as socket2_wait_for_close
from hypr_socket2 import wait_for_window as socket2_wait_for_window
from hypr_socket2 import sanitize_event_result
from image_pipeline import ImagePipelineError, map_point, render_marks, transform_image
from ocr_backend import ocr_image, probe_ocr_backends
from visual_targets import (
    VisualTargetError,
    element_is_editable,
    make_snapshot_binding,
    resolve_click_target,
    resolve_type_into_target,
)
from target_identity import qualify_address, parse_target, strip_target_qualifier


LEGACY_ENVIRONMENT_USES = promote_legacy_environment()

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER_VERSION = "0.4.0"
SNAPSHOTS: dict[str, dict[str, Any]] = {}
VISUAL_CACHE: dict[str, dict[str, Any]] = {}
VISUAL_CACHE_TTL_SECONDS = 30.0
ACTIVE_SEQUENCE_CANCELLATION: CancellationToken | None = None
PENDING_SEQUENCE_CANCEL = False
SEQUENCE_WORKER_PENDING = False
SEQUENCE_STATE_LOCK = threading.Lock()
HYPR_MANAGEMENT = HyprManagement()
GLOBAL_MENU_LIMIT = 80
GLOBAL_MENU_TREE_TIMEOUT_SECONDS = 0.2
DEFAULT_MODEL_SCREENSHOT_RESOLUTION = "logical"
GEOMETRY_EPSILON = 0.5
MAX_TOOL_WAIT_SECONDS = 30.0
LAUNCH_UNMATCHED_WINDOW_GRACE_SECONDS = 1.0
SECURITY_OWNER = f"stdio:{os.getpid()}"
SECURITY_POLICY: SecurityPolicy = policy_from_env()


def env_enabled(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on", "enabled"}


SECURITY_AUDIT: AuditJournal | None = None
if env_enabled("HYPR_AGENT_PORTAL_SECURITY_AUDIT", False):
    SECURITY_AUDIT = AuditJournal(os.environ.get("HYPR_AGENT_PORTAL_SECURITY_AUDIT_NAME", "audit.jsonl"))
PROCESS_MUTATION_LEASE: ProcessMutationLease | None = None
# This latch covers mutation paths that do not pass through the native input
# dispatchers (AT-SPI, DBusMenu, clipboard, and launch).  It is deliberately
# process-local and is synchronized with the native latch on every guard probe.
SERVER_PANIC_ACTIVE = False

_ATSPI_INIT_ERROR: str | None | bool = None
_ATSPI: Any = None
ATSPI_CHILD_ENV = "HYPR_AGENT_PORTAL_ATSPI_CHILD"
ATSPI_CHILD_MODES = {"--atspi-probe", "--atspi-snapshot", "--atspi-action"}
ELEMENT_CLICK_MODE_ENV = "HYPR_AGENT_PORTAL_ELEMENT_CLICK_MODE"
SESSION_ENV_KEYS = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "WAYLAND_DISPLAY", "DISPLAY", "HYPRLAND_INSTANCE_SIGNATURE")
A11Y_LAUNCH_ENV = {
    "NO_AT_BRIDGE": "0",
    "QT_LINUX_ACCESSIBILITY_ALWAYS_ON": "1",
    "GTK_MODULES": "gail:atk-bridge",
}
CHROMIUM_LIKE_EXECUTABLES = {
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
    "brave",
    "brave-browser",
    "microsoft-edge",
    "vivaldi",
    "opera",
    "electron",
    "code",
    "codium",
    "discord",
    "slack",
}


def find_ctl() -> pathlib.Path:
    candidates = [pathlib.Path(p) for p in [os.environ.get("HYPR_AGENT_PORTAL_CTL")] if p]
    candidates.extend(
        [
            ROOT / "scripts" / "hypr-agent-portalctl",
            pathlib.Path(__file__).resolve().with_name("hypr-agent-portalctl"),
        ]
    )
    found = shutil.which("hypr-agent-portalctl")
    if found:
        candidates.append(pathlib.Path(found))

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("hypr-agent-portalctl not found")


COMPUTER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": [
                "screenshot",
                "windows",
                "move",
                "click",
                "doubleclick",
                "press",
                "release",
                "scroll",
                "drag",
                "key",
                "type",
                "copy_text",
                "paste_text",
                "paste_file",
                "paste_image",
                "session",
                "get_app_state",
                "read_app_state",
                "wait",
                "wait_for_window",
                "wait_for_close",
                "doctor",
                "launch",
                "launch_app",
                "open_app",
                "get_cursor_position",
                "activate_menu_item",
                "left_click",
                "right_click",
                "middle_click",
                "double_click",
                "triple_click",
                "hover",
                "left_click_drag",
            ],
            "description": "Computer use action to perform.",
        },
        "app": {"type": "string", "description": "Preferred app/window selector for semantic tools and compatibility aliases. Use this instead of target/global coordinates when possible."},
        "command": {"type": "string", "description": "Command line to launch for launch/open_app actions. Prefer app for simple app names."},
        "args": {"type": "array", "items": {"type": "string"}, "description": "Additional launch arguments."},
        "url": {"type": "string", "description": "URL or file target to pass to a launched app, usually with new_window for browsers."},
        "new_window": {"type": "boolean", "default": True, "description": "For browser launches, request a new window and use about:blank when no URL is supplied."},
        "reuse_existing": {"type": "boolean", "default": True, "description": "For launch/open_app, return an already running matching app instead of forcing a new launch. Set false only when the user explicitly asks for a new instance/window."},
        "timeout": {
            "type": "number",
            "minimum": 0,
            "maximum": MAX_TOOL_WAIT_SECONDS,
            "description": "Seconds to wait for a launched app window to appear. Values are capped at 30 seconds.",
        },
        "target": {
            "type": "string",
            "description": "Low-level Hyprland window selector, for example address:0x1234. Prefer app plus screenshot/window-relative coordinates unless you intentionally need global-coordinate fallback.",
        },
        "coordinate": {
            "type": "array",
            "items": {"type": "number"},
            "minItems": 2,
            "maxItems": 2,
            "description": "Compatibility coordinate pair. With app, interpreted in coordinate_space. With target and coordinate_space screenshot/window, target is treated as the app selector. Global is only for explicit coordinate_space=global fallback.",
        },
        "start_coordinate": {
            "type": "array",
            "items": {"type": "number"},
            "minItems": 2,
            "maxItems": 2,
            "description": "Compatibility drag start coordinate pair.",
        },
        "coordinate_space": {
            "type": "string",
            "enum": ["screenshot", "window", "global"],
            "default": "screenshot",
            "description": "Coordinate space for app-relative compatibility aliases. Prefer screenshot pixels from get_app_state. Global is only for low-level computer fallback.",
        },
        "x": {"type": "number", "description": "X coordinate in coordinate_space; global only when coordinate_space=global."},
        "y": {"type": "number", "description": "Y coordinate in coordinate_space; global only when coordinate_space=global."},
        "x2": {"type": "number", "description": "Destination X coordinate for drag in coordinate_space; global only when coordinate_space=global."},
        "y2": {"type": "number", "description": "Destination Y coordinate for drag in coordinate_space; global only when coordinate_space=global."},
        "dx": {"type": "number", "description": "Horizontal scroll wheel ticks."},
        "dy": {"type": "number", "description": "Vertical scroll wheel ticks."},
        "scroll_direction": {"type": "string", "enum": ["up", "down", "left", "right"], "description": "Compatibility scroll direction."},
        "scroll_amount": {"type": "number", "description": "Compatibility scroll tick amount."},
        "button": {"type": "string", "enum": ["left", "right", "middle", "side", "extra"], "default": "left"},
        "element_click_mode": {
            "type": "string",
            "enum": ["pointer", "auto", "atspi"],
            "default": "pointer",
            "description": "For element_index click actions: pointer converts the element frame to screenshot coordinates and sends native pointer input; auto tries AT-SPI then pointer; atspi requires an AT-SPI action.",
        },
        "key": {"type": "string", "description": "Key name or shortcut for key actions, for example enter, escape, v, f5, alt+left."},
        "keycode": {"type": "integer", "description": "Raw evdev keycode for key actions, ydotool-style."},
        "keys": {"type": "string", "description": "Shortcut string for key actions, for example ctrl+v or alt+tab."},
        "modifiers": {"type": "string", "description": "Optional key modifiers, for example ctrl+shift."},
        "text": {"type": "string", "description": "Text for type/copy_text/paste_text actions."},
        "name": {"type": "string", "description": "Accessible name/text to match for link or element clicking."},
        "show_cursor": {
            "type": "boolean",
            "description": "For screenshot debugging, draw the cursor indicator on the returned image. The real desktop indicator is rendered by the Hyprland plugin.",
            "default": False,
        },
        "cursor_source": {
            "type": "string",
            "enum": ["auto", "agent", "hyprland", "none"],
            "description": "For screenshot debugging, choose the cursor indicator source. auto prefers the last background pointer coordinate.",
            "default": "none",
        },
        "method": {
            "type": "string",
            "enum": ["auto", "paste", "keys", "atspi"],
            "description": "For type, choose auto, clipboard paste, literal key events, or explicit AT-SPI text insertion.",
            "default": "auto",
        },
        "repeat": {"type": "integer", "description": "Number of times to repeat a key action."},
        "source": {"type": "string", "enum": ["auto", "hyprland", "agent"], "default": "auto", "description": "Cursor source for get_cursor_position."},
        "include_global": {"type": "boolean", "default": False, "description": "Include Hyprland global logical coordinates in get_cursor_position diagnostics."},
        "prefer_related": {
            "type": "boolean",
            "default": False,
            "description": "Deprecated/unsafe when true. Inspect get_app_state and explicitly target the related popup address instead.",
            "default": True,
        },
        "restore_clipboard": {
            "type": "boolean",
            "description": "For type/paste_text, read and restore the previous text clipboard after sending paste. This requires clipboard read permission.",
            "default": False,
        },
        "restore_delay": {
            "type": "number",
            "description": "Seconds to wait before restoring clipboard after paste.",
            "default": 1.0,
        },
        "path": {"type": "string", "description": "Filesystem path for paste_file/paste_image actions."},
        "duration": {"type": "number", "description": "Duration in seconds for wait or drag pacing."},
        "title": {"type": "string", "description": "Window title substring for wait_for_window."},
        "class": {"type": "string", "description": "Window class substring for wait_for_window."},
        "session_action": {
            "type": "string",
            "enum": ["begin", "sync", "end"],
            "description": "For session, begin/sync/end a related-window workspace guard session.",
        },
        "visible_workspace": {"type": "boolean", "description": "For windows, only return active-workspace clients."},
        "related_to": {
            "type": "string",
            "description": "For windows, return the selected Hyprland window and same-process related windows such as dialogs or helper popups.",
        },
        "menu_index": {
            "type": "string",
            "description": "Global menu item id from get_app_state, for activate_menu_item.",
        },
    },
    "required": ["action"],
    "additionalProperties": False,
}

# Compatibility ``computer`` parity for the richer direct tools.  These are
# still routed through the same handle() policy gate as their direct forms.
COMPUTER_SCHEMA["properties"]["action"]["enum"].extend(
    [
        "perform_secondary_action", "set_value",
        "ocr", "click_text", "get_marks", "click_mark", "type_into",
        "sequence", "manage_window", "list_workspaces", "manage_workspace",
    ]
)
COMPUTER_SCHEMA["properties"].update(
    {
        "snapshot_id": {"type": "string"},
        "ocr_id": {"type": "string"},
        "marks_id": {"type": "string"},
        "mark_id": {"type": ["string", "integer"]},
        "target_text": {"type": "string"},
        "match": {"type": "string", "enum": ["exact", "contains"], "default": "exact"},
        "casefold": {"type": "boolean", "default": True},
        "nth": {"type": "integer", "minimum": 1, "default": 1},
        "backend": {"type": "string", "enum": ["auto", "tesseract-cli", "pytesseract"], "default": "auto"},
        "language": {"type": "string"},
        "page_segmentation_mode": {"type": "integer", "minimum": 0, "maximum": 13},
        "region": {"type": "object"},
        "scale": {"type": "number", "exclusiveMinimum": 0, "maximum": 8},
        "zoom": {"type": "number", "exclusiveMinimum": 0, "maximum": 8},
        "format": {"type": "string", "enum": ["png", "jpeg", "jpg", "webp"]},
        "quality": {"type": "integer", "minimum": 1, "maximum": 100},
        "max_dimension": {"type": "integer", "minimum": 1, "maximum": 8192},
        "include_elements": {"type": "boolean", "default": True},
        "locator": {"type": "object"},
        "element_index": {"type": "string"},
        "secondary_action": {"type": "string"},
        "value": {"type": "string"},
        "accessible_name": {"type": "string"},
        "accessible_text": {"type": "string"},
        "click_count": {"type": "integer", "minimum": 1, "maximum": 3},
        "mouse_button": {"type": "string", "enum": ["left", "right", "middle"]},
        "steps": {"type": "array", "maxItems": 128, "items": {"type": "object"}},
        "stop_on_error": {"type": "boolean", "default": True},
        "dry_run": {"type": "boolean", "default": False},
        "max_steps": {"type": "integer", "minimum": 1, "maximum": 128},
        "address": {"type": "string"},
        "window_action": {"type": "string", "enum": ["focus", "close", "move", "resize", "minimize", "restore", "maximize", "unmaximize", "fullscreen", "unfullscreen", "floating", "tiled", "pin", "unpin", "move_to_workspace"]},
        "workspace_action": {"type": "string", "enum": ["switch", "activate", "create", "create_or_activate", "rename", "move_window", "move_window_to_workspace", "show_special", "hide_special", "toggle_special"]},
        "workspace": {"type": ["string", "integer"]},
        "new_name": {"type": "string"},
        "enabled": {"type": "boolean"},
        "follow": {"type": "boolean"},
        "width": {"type": "integer"},
        "height": {"type": "integer"},
        "include_special": {"type": "boolean", "default": True},
        "minimized_workspace": {"type": "string"},
        "restore_workspace": {"type": ["string", "integer"]},
    }
)


def string_property(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def number_property(description: str) -> dict[str, Any]:
    return {"type": "number", "description": description}


def timeout_property(description: str) -> dict[str, Any]:
    return {"type": "number", "minimum": 0, "maximum": MAX_TOOL_WAIT_SECONDS, "description": description}


def integer_property(description: str) -> dict[str, Any]:
    return {"type": "integer", "description": description}


def object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def coordinate_schema(description: str) -> dict[str, Any]:
    return {"type": "array", "items": {"type": "number"}, "minItems": 2, "maxItems": 2, "description": description}


def coordinate_space_property(*, include_global: bool = False) -> dict[str, Any]:
    values = ["screenshot", "window"]
    if include_global:
        values.append("global")
    return {
        "type": "string",
        "enum": values,
        "default": "screenshot",
        "description": "Coordinate space. screenshot uses get_app_state pixels; window uses logical coordinates from the target window's top-left.",
    }


def element_click_mode_property() -> dict[str, Any]:
    return {
        "type": "string",
        "enum": ["pointer", "auto", "atspi"],
        "default": "pointer",
        "description": "For element_index clicks: pointer uses the element frame center and native pointer input; auto tries AT-SPI then pointer; atspi requires an AT-SPI action.",
    }


READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
ACTION_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}
LAUNCH_ANNOTATIONS = dict(ACTION_ANNOTATIONS)

READ_ONLY_TOOL_NAMES = {
    "list_apps",
    "list_windows",
    "get_app_state",
    "read_app_state",
    "screenshot",
    "get_screenshot",
    "get_cursor_position",
    "wait",
    "wait_for_window",
    "wait_for_close",
    "security_status",
    "ocr",
    "get_marks",
    "list_workspaces",
}


def tool_definitions() -> list[dict[str, Any]]:
    app = string_property("App name, Hyprland class/title, pid, or address:0x... selector.")
    launch_app = string_property("App name, desktop id, executable, or simple command to launch, for example chromium, dolphin, org.kde.dolphin.desktop.")
    launch_schema = object_schema(
        {
            "app": launch_app,
            "command": string_property("Full command line to launch. Prefer app unless custom arguments are needed."),
            "args": {"type": "array", "items": {"type": "string"}, "description": "Additional command arguments."},
            "url": string_property("Optional URL or file target to pass to the launched app."),
            "new_window": {"type": "boolean", "default": True, "description": "For browsers, request a new window and open about:blank when no URL is supplied. Use only when launching a new browser window is intended."},
            "reuse_existing": {"type": "boolean", "default": True, "description": "Return an already running matching app instead of launching another copy. Set false only when the user explicitly asks for a new instance/window."},
            "timeout": timeout_property("Seconds to wait for a Hyprland window to appear. Defaults to 8; capped at 30."),
        }
    )
    element_index = string_property("Element index from the last get_app_state result.")
    menu_index = string_property("Global menu item id from get_app_state, for example menu:12.")
    coordinate = coordinate_schema("(x, y) coordinate in coordinate_space. Defaults to screenshot pixels from get_app_state.")
    start_coordinate = coordinate_schema("(x, y) starting coordinate for a drag in coordinate_space.")
    point_props = {
        "app": app,
        "element_index": element_index,
        "name": string_property("Accessible name/text to match before falling back to coordinates."),
        "coordinate": coordinate,
        "x": number_property("X coordinate in coordinate_space."),
        "y": number_property("Y coordinate in coordinate_space."),
        "coordinate_space": coordinate_space_property(),
        "element_click_mode": element_click_mode_property(),
    }
    screenshot_props = {
        "app": app,
        "target": string_property("Hyprland window selector, for example address:0x1234."),
        "show_cursor": {"type": "boolean", "default": False},
        "cursor_source": {"type": "string", "enum": ["auto", "agent", "hyprland", "none"], "default": "none"},
        "region": {"type": "object", "properties": {key: {"type": "number"} for key in ("x", "y", "width", "height")}, "required": ["x", "y", "width", "height"], "additionalProperties": False},
        "coordinate_space": coordinate_space_property(),
        "scale": {"type": "number", "exclusiveMinimum": 0, "maximum": 8},
        "zoom": {"type": "number", "exclusiveMinimum": 0, "maximum": 8},
        "format": {"type": "string", "enum": ["png", "jpeg", "jpg", "webp"], "default": "png"},
        "quality": {"type": "integer", "minimum": 1, "maximum": 100, "default": 85},
        "max_dimension": {"type": "integer", "minimum": 1, "maximum": 8192},
    }
    definitions = [
        {
            "name": "computer",
            "title": "hypr-agent-portal",
            "description": "hypr-agent-portal compatibility tool for Hyprland background Computer Use, including browser/Chromium control through Hyprland. Prefer app plus get_app_state/screenshot coordinates; target/x/y global coordinates are only the low-level fallback. Do not use Browser MCP when the user explicitly asks for hypr-agent-portal. Do not use the obsolete hyprcum namespace.",
            "inputSchema": COMPUTER_SCHEMA,
            "annotations": ACTION_ANNOTATIONS,
        },
        {
            "name": "list_apps",
            "description": "List running Hyprland apps/windows available to hypr-agent-portal. Start here before choosing a target app unless the user explicitly asks to launch a new app/window.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema({}),
        },
        {
            "name": "launch_app",
            "description": "Open or launch an app through Hyprland and return a window selector. By default this reuses an already running matching window; set reuse_existing=false only when the user explicitly asks for a new instance/window. For browser tasks, use this instead of Browser MCP only when an app launch/open is requested.",
            "annotations": LAUNCH_ANNOTATIONS,
            "inputSchema": launch_schema,
        },
        {
            "name": "open_app",
            "description": "Compatibility alias for launch_app.",
            "annotations": LAUNCH_ANNOTATIONS,
            "inputSchema": launch_schema,
        },
        {
            "name": "get_app_state",
            "description": "Get a target app/window screenshot, accessibility tree, and uiHints. Call this before action tools, then use element_index or screenshot/window-relative coordinates. uiHints separates AT-SPI menu entries from tab/ribbon/toolbar controls; do not substitute a same-named menu for a requested tab.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema({"app": app}, ["app"]),
        },
        {
            "name": "read_app_state",
            "description": "Compatibility alias for get_app_state.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema({"app": app}, ["app"]),
        },
        {
            "name": "screenshot",
            "description": "Capture an unoccluded screenshot for an app/window, or the visible compositor if no app is passed. Prefer app over low-level target.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema(screenshot_props),
        },
        {
            "name": "get_screenshot",
            "description": "Compatibility alias for screenshot.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema(screenshot_props),
        },
        {
            "name": "get_cursor_position",
            "description": "Return the current cursor position in monitor, screenshot, or window-relative coordinates.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "source": {"type": "string", "enum": ["auto", "hyprland", "agent"], "default": "auto"},
                    "include_global": {"type": "boolean", "default": False},
                }
            ),
        },
        {
            "name": "list_windows",
            "description": "Compatibility alias for list_apps.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema({}),
        },
        {
            "name": "click",
            "description": "Click a visible element by index, accessible name/text, or screenshot/window-relative coordinates. Element clicks use the native pointer path so the visible agent cursor overlay appears.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    **point_props,
                    "click_count": integer_property("Number of clicks. Defaults to 1."),
                    "mouse_button": {"type": "string", "enum": ["left", "right", "middle"], "default": "left"},
                },
                ["app"],
            ),
        },
        {
            "name": "perform_secondary_action",
            "description": "Invoke a secondary AT-SPI action exposed by an element.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema({"app": app, "element_index": element_index, "action": string_property("Secondary action name.")}, ["app", "element_index", "action"]),
        },
        {
            "name": "activate_menu_item",
            "description": "Activate a global app-menu item from get_app_state. Uses DBusMenu/GMenu when the app exposes a menu model; this is independent of AT-SPI menu roles.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema({"app": app, "menu_index": menu_index}, ["app", "menu_index"]),
        },
        {
            "name": "scroll",
            "description": "Scroll an element or coordinate in a direction by pages.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    **point_props,
                    "direction": {"type": "string", "enum": ["up", "down", "left", "right"]},
                    "pages": number_property("Number of pages to scroll. Defaults to 1."),
                },
                ["app", "direction"],
            ),
        },
        {
            "name": "drag",
            "description": "Drag from one screenshot/window-relative coordinate to another.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "start_coordinate": start_coordinate,
                    "coordinate": coordinate_schema("(x, y) destination coordinate in coordinate_space."),
                    "from_x": number_property("Start X coordinate in coordinate_space."),
                    "from_y": number_property("Start Y coordinate in coordinate_space."),
                    "to_x": number_property("End X coordinate in coordinate_space."),
                    "to_y": number_property("End Y coordinate in coordinate_space."),
                    "coordinate_space": coordinate_space_property(),
                    "duration": number_property("Drag pacing duration in seconds. Defaults to 0.2."),
                },
                ["app"],
            ),
        },
        {
            "name": "left_click",
            "description": "Compatibility alias for click with the left button.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(point_props, ["app"]),
        },
        {
            "name": "right_click",
            "description": "Compatibility alias for click with the right button.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(point_props, ["app"]),
        },
        {
            "name": "middle_click",
            "description": "Compatibility alias for click with the middle button.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(point_props, ["app"]),
        },
        {
            "name": "double_click",
            "description": "Compatibility alias for a double left click.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(point_props, ["app"]),
        },
        {
            "name": "triple_click",
            "description": "Compatibility alias for a triple left click.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(point_props, ["app"]),
        },
        {
            "name": "hover",
            "description": "Compatibility alias: move the background pointer to an element or coordinate without clicking.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(point_props, ["app"]),
        },
        {
            "name": "move_mouse",
            "description": "Compatibility alias for hover.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(point_props, ["app"]),
        },
        {
            "name": "left_click_drag",
            "description": "Compatibility alias for drag using start_coordinate and coordinate.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "start_coordinate": start_coordinate,
                    "coordinate": coordinate,
                    "coordinate_space": coordinate_space_property(),
                    "duration": number_property("Drag pacing duration in seconds. Defaults to 0.2."),
                },
                ["app", "start_coordinate", "coordinate"],
            ),
        },
        {
            "name": "type_text",
            "description": "Type literal text into the target app. Use paste_text for multiline, tabular, CSV/TSV, Unicode-heavy, or long text. method=auto prefers a focused AT-SPI editable control, then uses isolated background key/paste input; method=atspi explicitly requests accessibility text insertion.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "text": string_property("Literal text to type."),
                    "method": {"type": "string", "enum": ["auto", "paste", "keys", "atspi"], "default": "auto"},
                },
                ["app", "text"],
            ),
        },
        {
            "name": "type",
            "description": "Compatibility alias for type_text.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "text": string_property("Literal text to type."),
                    "method": {"type": "string", "enum": ["auto", "paste", "keys", "atspi"], "default": "auto"},
                },
                ["app", "text"],
            ),
        },
        {
            "name": "paste_text",
            "description": "Paste text through the clipboard into the target app. Prefer this for multiline, tabular, CSV/TSV, Unicode-heavy, or long text because it is much faster than key-by-key typing.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "text": string_property("Text to place on the clipboard and paste into the target app."),
                    "restore_clipboard": {
                        "type": "boolean",
                        "default": False,
                        "description": "Read and restore the previous text clipboard after paste. This requires clipboard read permission.",
                    },
                    "restore_delay": number_property("Seconds to wait before restoring clipboard after paste. Defaults to 1."),
                    "prefer_related": {"type": "boolean", "default": False, "description": "Deprecated/unsafe when true; explicitly target the popup address."},
                },
                ["app", "text"],
            ),
        },
        {
            "name": "press_key",
            "description": "Press a key or key-combination, using xdotool-style syntax such as ctrl+v, Return, alt+left, or super+c.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "key": string_property("Key or key-combination to press."),
                    "keys": string_property("Compatibility shortcut string, for example alt+left."),
                    "modifiers": string_property("Optional modifiers when key is a bare key, for example alt."),
                    "keycode": integer_property("Raw evdev keycode, ydotool-style."),
                    "repeat": integer_property("Number of times to repeat the key. Defaults to 1."),
                },
                ["app"],
            ),
        },
        {
            "name": "key",
            "description": "Compatibility alias for press_key. Accepts key, keys, modifiers, keycode, or text.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "key": string_property("Key or key-combination to press."),
                    "keys": string_property("Compatibility shortcut string, for example alt+left."),
                    "modifiers": string_property("Optional modifiers when key is a bare key, for example alt."),
                    "keycode": integer_property("Raw evdev keycode, ydotool-style."),
                    "text": string_property("Compatibility key text."),
                    "repeat": integer_property("Number of times to repeat the key. Defaults to 1."),
                },
                ["app"],
            ),
        },
        {
            "name": "set_value",
            "description": "Set the value of a settable accessibility element.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema({"app": app, "element_index": element_index, "value": string_property("Value to assign.")}, ["app", "element_index", "value"]),
        },
        {
            "name": "wait",
            "description": "Compatibility alias: wait for a short duration.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema({"duration": number_property("Seconds to wait. Defaults to 1.")}),
        },
        {
            "name": "wait_for_window",
            "description": "Wait for a Hyprland window or same-process related popup/dialog to appear, then return its app state. Use after actions expected to open dialogs or new windows.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "related_to": string_property("Root app/window selector whose related popup/dialog should appear."),
                    "title": string_property("Window title substring to wait for."),
                    "class": string_property("Window class substring to wait for."),
                    "timeout": timeout_property("Seconds to wait. Defaults to 5; capped at 30."),
                }
            ),
        },
        {
            "name": "wait_for_close",
            "description": "Wait for a target window/dialog to close. If related_to is provided, return the surviving related/root app state.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "app": app,
                    "target": string_property("Target window selector to wait for close, for example address:0x1234."),
                    "related_to": string_property("Root app/window selector to return after the target closes."),
                    "timeout": timeout_property("Seconds to wait. Defaults to 5; capped at 30."),
                }
            ),
        },
        {
            "name": "security_status",
            "description": "Return the active desktop-control security policy and readiness diagnostics without exposing secrets.",
            "annotations": READ_ONLY_ANNOTATIONS,
            "inputSchema": object_schema({}),
        },
        {
            "name": "request_confirmation",
            "description": "Create a pending challenge bound to an exact high-risk call. A person must approve it from an independent local TTY before it can authorize the action.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "tool_name": string_property("Tool that will be called after confirmation."),
                    "arguments": {"type": "object", "description": "Exact arguments for the confirmed tool call, excluding confirmation_token."},
                },
                ["tool_name", "arguments"],
            ),
        },
        {
            "name": "panic",
            "description": "Immediately cancel active background operations. panic latches writes off; cancel is one-shot; resume clears the latch; status is read-only.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {"mode": {"type": "string", "enum": ["panic", "cancel", "resume", "status"], "default": "panic"}}
            ),
        },
        {
            "name": "audit_replay",
            "description": "Preflight the redacted audit journal and optionally replay only entries that remain safe after identity and policy validation.",
            "annotations": ACTION_ANNOTATIONS,
            "inputSchema": object_schema(
                {
                    "execute": {"type": "boolean", "default": False},
                    "allow_clipboard": {"type": "boolean", "default": False},
                    "max_record_age_seconds": number_property("Reject older targeted records. Defaults to 300."),
                }
            ),
        },
    ]

    visual_common = {
        "app": app,
        "region": {"type": "object", "properties": {key: {"type": "number"} for key in ("x", "y", "width", "height")}, "required": ["x", "y", "width", "height"], "additionalProperties": False},
        "coordinate_space": coordinate_space_property(),
        "scale": {"type": "number", "exclusiveMinimum": 0, "maximum": 8},
        "zoom": {"type": "number", "exclusiveMinimum": 0, "maximum": 8},
        "format": {"type": "string", "enum": ["png", "jpeg", "jpg", "webp"], "default": "png"},
        "quality": {"type": "integer", "minimum": 1, "maximum": 100, "default": 85},
        "max_dimension": {"type": "integer", "minimum": 1, "maximum": 8192},
    }
    definitions.extend(
        [
            {
                "name": "ocr",
                "description": "Run a local OCR backend on a newly captured, privacy-filtered target screenshot. Returns normalized confidence 0..1, screenshot pixel boxes, and an opaque short-lived ocr_id.",
                "annotations": READ_ONLY_ANNOTATIONS,
                "inputSchema": object_schema({"app": app, "backend": {"type": "string", "enum": ["auto", "tesseract-cli", "pytesseract"], "default": "auto"}, "language": {"type": "string"}, "page_segmentation_mode": {"type": "integer", "minimum": 0, "maximum": 13}, "timeout": timeout_property("Local OCR timeout."), "region": visual_common["region"], "coordinate_space": coordinate_space_property()}, ["app"]),
            },
            {
                "name": "click_text",
                "description": "Click OCR text from an opaque current ocr_id. The server revalidates screenshot hash, process identity, and geometry before input.",
                "annotations": ACTION_ANNOTATIONS,
                "inputSchema": object_schema({"app": app, "ocr_id": {"type": "string"}, "text": {"type": "string"}, "match": {"type": "string", "enum": ["exact", "contains"], "default": "exact"}, "casefold": {"type": "boolean", "default": True}, "nth": {"type": "integer", "minimum": 1, "default": 1}, "mouse_button": {"type": "string", "enum": ["left", "right", "middle"], "default": "left"}, "click_count": {"type": "integer", "minimum": 1, "maximum": 3}}, ["app", "ocr_id", "text"]),
            },
            {
                "name": "get_marks",
                "description": "Render a non-destructive numbered Set-of-Marks overlay for a bound target screenshot and return an opaque marks_id mapping.",
                "annotations": READ_ONLY_ANNOTATIONS,
                "inputSchema": object_schema({**visual_common, "snapshot_id": {"type": "string"}, "ocr_id": {"type": "string"}, "include_elements": {"type": "boolean", "default": True}}, ["app"]),
            },
            {
                "name": "click_mark",
                "description": "Click one bound Set-of-Marks id after live identity, geometry, and screenshot-hash validation.",
                "annotations": ACTION_ANNOTATIONS,
                "inputSchema": object_schema({"app": app, "marks_id": {"type": "string"}, "mark_id": {"type": ["string", "integer"]}, "mouse_button": {"type": "string", "enum": ["left", "right", "middle"], "default": "left"}, "click_count": {"type": "integer", "minimum": 1, "maximum": 3}}, ["app", "marks_id", "mark_id"]),
            },
            {
                "name": "type_into",
                "description": "Atomically resolve and verify an editable target, focus it, refresh state, then input text using auto/AT-SPI/paste/keys.",
                "annotations": ACTION_ANNOTATIONS,
                "inputSchema": object_schema({"app": app, "snapshot_id": {"type": "string"}, "ocr_id": {"type": "string"}, "marks_id": {"type": "string"}, "mark_id": {"type": ["string", "integer"]}, "target_text": {"type": "string"}, "element_index": element_index, "accessible_name": {"type": "string"}, "accessible_text": {"type": "string"}, "locator": {"type": "object"}, "match": {"type": "string", "enum": ["exact", "contains"], "default": "exact"}, "nth": {"type": "integer", "minimum": 1, "default": 1}, "text": {"type": "string"}, "method": {"type": "string", "enum": ["auto", "atspi", "paste", "keys"], "default": "auto"}}, ["app", "text"]),
            },
            {
                "name": "sequence",
                "description": "Run an ordered action sequence. Every step re-enters the ordinary single-tool policy, confirmation, confinement, lease, and audit gateway; nested sequences are rejected.",
                "annotations": ACTION_ANNOTATIONS,
                "inputSchema": object_schema({"steps": {"type": "array", "minItems": 1, "maxItems": 128, "items": {"type": "object"}}, "stop_on_error": {"type": "boolean", "default": True}, "dry_run": {"type": "boolean", "default": False}, "max_steps": {"type": "integer", "minimum": 1, "maximum": 128}}, ["steps"]),
            },
            {
                "name": "manage_window",
                "description": "Targeted, verified Hyprland window management: focus/close/move/resize/minimize/maximize/fullscreen/floating/pin/move_to_workspace.",
                "annotations": ACTION_ANNOTATIONS,
                "inputSchema": object_schema({"action": {"type": "string", "enum": ["focus", "close", "move", "resize", "minimize", "restore", "maximize", "unmaximize", "fullscreen", "unfullscreen", "floating", "tiled", "pin", "unpin", "move_to_workspace"]}, "app": app, "target": {"type": "string"}, "address": {"type": "string"}, "x": {"type": "integer"}, "y": {"type": "integer"}, "width": {"type": "integer", "minimum": 1}, "height": {"type": "integer", "minimum": 1}, "enabled": {"type": "boolean", "description": "Explicit desired state for minimize/maximize/fullscreen/floating/pin; inverse action names set false."}, "workspace": {"type": ["string", "integer"]}, "follow": {"type": "boolean"}, "minimized_workspace": {"type": "string"}, "restore_workspace": {"type": ["string", "integer"]}}, ["action"]),
            },
            {
                "name": "list_workspaces",
                "description": "List Hyprland workspaces; special workspaces are included by default and explicitly identified by Hyprland.",
                "annotations": READ_ONLY_ANNOTATIONS,
                "inputSchema": object_schema({"include_special": {"type": "boolean", "default": True}}),
            },
            {
                "name": "manage_workspace",
                "description": "Verified Hyprland workspace switch/create-or-activate/rename and targeted window move. special: selectors retain Hyprland special-workspace semantics.",
                "annotations": ACTION_ANNOTATIONS,
                "inputSchema": object_schema({"action": {"type": "string", "enum": ["switch", "activate", "create", "create_or_activate", "rename", "move_window", "move_window_to_workspace", "show_special", "hide_special", "toggle_special"]}, "workspace": {"type": ["string", "integer"]}, "new_name": {"type": "string"}, "app": app, "target": {"type": "string"}, "address": {"type": "string"}, "follow": {"type": "boolean"}}, ["action", "workspace"]),
            },
        ]
    )

    readonly_actions = {
        "screenshot",
        "windows",
        "get_app_state",
        "read_app_state",
        "wait",
        "wait_for_window",
        "wait_for_close",
        "doctor",
        "get_cursor_position",
        "ocr",
        "get_marks",
        "list_workspaces",
    }
    exposed: list[dict[str, Any]] = []
    for definition in definitions:
        item = copy.deepcopy(definition)
        name = str(item["name"])
        mutating = name == "computer" or name not in READ_ONLY_TOOL_NAMES
        if mutating:
            item["inputSchema"].setdefault("properties", {})["confirmation_token"] = {
                "type": "string",
                "description": "Externally approved, one-time challenge ID from request_confirmation for a high-risk action.",
            }
        if name == "computer" and SECURITY_POLICY.config.readonly:
            enum = item["inputSchema"]["properties"]["action"]["enum"]
            item["inputSchema"]["properties"]["action"]["enum"] = [action for action in enum if action in readonly_actions]
        if name == "panic" and SECURITY_POLICY.config.readonly:
            item["inputSchema"]["properties"]["mode"]["enum"] = ["panic", "cancel", "status"]
            item["inputSchema"]["properties"]["mode"]["default"] = "panic"
        if SECURITY_POLICY.config.readonly and name not in {"computer", "panic"} and mutating:
            continue
        exposed.append(item)
    return exposed


def response(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def call_ctl(args: list[str]) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            [str(find_ctl()), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=hyprctl_environment(),
            check=False,
            timeout=MAX_TOOL_WAIT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"hypr-agent-portalctl timed out after {MAX_TOOL_WAIT_SECONDS:g}s") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"hypr-agent-portalctl exited {proc.returncode}").strip())
    if not proc.stdout.strip():
        return {}
    return json.loads(proc.stdout)


def cleanup_screenshot_provenance(provenance: Any) -> None:
    """Best-effort inode-bound cleanup for artifacts created by one ctl request."""
    if not isinstance(provenance, dict):
        return
    root_value = provenance.get("root")
    if not isinstance(root_value, str) or not root_value:
        return
    root = pathlib.Path(root_value)
    if root.name != f"hypr-agent-portal-{os.getuid()}":
        return

    valid_directories: dict[pathlib.Path, tuple[int, int]] = {}
    for record in provenance.get("directories", []):
        if not isinstance(record, dict):
            continue
        path_value = record.get("path")
        if not isinstance(path_value, str) or not path_value:
            continue
        path = pathlib.Path(path_value)
        if path.parent != root:
            continue
        try:
            info = os.lstat(path)
        except (FileNotFoundError, OSError):
            continue
        if (
            stat.S_ISDIR(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == os.getuid()
            and (int(info.st_dev), int(info.st_ino), int(info.st_ctime_ns))
            == (int(record.get("device", -1)), int(record.get("inode", -1)), int(record.get("ctimeNs", -1)))
        ):
            valid_directories[path] = (int(info.st_dev), int(info.st_ino))

    for record in provenance.get("files", []):
        if not isinstance(record, dict):
            continue
        path_value = record.get("path")
        if not isinstance(path_value, str) or not path_value:
            continue
        path = pathlib.Path(path_value)
        if path.parent != root and path.parent not in valid_directories:
            continue
        try:
            info = os.lstat(path)
        except (FileNotFoundError, OSError):
            continue
        if (int(info.st_dev), int(info.st_ino), int(info.st_ctime_ns), int(info.st_mtime_ns), int(info.st_size)) != (
            int(record.get("device", -1)),
            int(record.get("inode", -1)),
            int(record.get("ctimeNs", -1)),
            int(record.get("mtimeNs", -1)),
            int(record.get("size", -1)),
        ):
            continue
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid():
            try:
                path.unlink()
            except OSError:
                pass

    for path, expected_identity in reversed(list(valid_directories.items())):
        try:
            info = os.lstat(path)
        except (FileNotFoundError, OSError):
            continue
        if (int(info.st_dev), int(info.st_ino)) != expected_identity:
            continue
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid():
            try:
                path.rmdir()
            except OSError:
                pass


def consume_screenshot_result(info: dict[str, Any]) -> tuple[dict[str, Any], str]:
    provenance = info.pop("cleanupProvenance", None)
    try:
        data = info.pop("pngBase64")
        if not isinstance(data, str):
            raise RuntimeError("hypr-agent-portalctl returned an invalid screenshot payload")
        info.pop("sessionPath", None)
        info.pop("pngPath", None)
        return info, data
    finally:
        cleanup_screenshot_provenance(provenance)


def run_available(command: str, args: list[str], *, input_bytes: bytes | None = None, input_text: str | None = None, timeout: float = 5.0) -> bool:
    executable = shutil.which(command)
    if not executable:
        return False
    run_kwargs: dict[str, Any]
    if input_text is not None:
        run_kwargs = {"input": input_text, "text": True}
    else:
        run_kwargs = {"input": input_bytes}
    try:
        proc = subprocess.run(
            [executable, *args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            **run_kwargs,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{command} timed out") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"{command} failed with exit code {proc.returncode}")
    return True


def run_capture(command: str, args: list[str], *, timeout: float = 5.0) -> tuple[bool, bytes]:
    executable = shutil.which(command)
    if not executable:
        return False, b""
    try:
        proc = subprocess.run([executable, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, b""
    if proc.returncode != 0:
        return False, b""
    return True, proc.stdout


def bounded_timeout_seconds(value: Any, default: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    seconds = float(value)
    if not math.isfinite(seconds):
        return default
    return max(0.0, min(seconds, MAX_TOOL_WAIT_SECONDS))


def busctl_user(args: list[str], *, timeout: float = 2.0) -> tuple[bool, str]:
    executable = shutil.which("busctl")
    if not executable:
        return False, ""
    try:
        proc = subprocess.run(
            [executable, "--user", *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=session_environment(),
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, ""
    return proc.returncode == 0, proc.stdout


def hyprctl_environment() -> dict[str, str]:
    env = os.environ.copy()
    if not env.get("XDG_RUNTIME_DIR"):
        env["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    if env.get("HYPRLAND_INSTANCE_SIGNATURE"):
        return env

    hyprctl = shutil.which("hyprctl", path=env.get("PATH"))
    proc = None
    if hyprctl:
        proc = subprocess.run([hyprctl, "instances", "-j"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, check=False)
    if proc is not None and proc.returncode == 0 and proc.stdout.strip():
        try:
            instances = json.loads(proc.stdout)
        except json.JSONDecodeError:
            instances = []
        if instances:
            wayland_display = env.get("WAYLAND_DISPLAY")
            matching = [item for item in instances if wayland_display and item.get("wl_socket") == wayland_display]
            selected = max(matching or instances, key=lambda item: int(item.get("time") or 0))
            if selected.get("instance"):
                env["HYPRLAND_INSTANCE_SIGNATURE"] = str(selected["instance"])
            if not env.get("WAYLAND_DISPLAY") and selected.get("wl_socket"):
                env["WAYLAND_DISPLAY"] = str(selected["wl_socket"])
            return env

    runtime_root = pathlib.Path(env["XDG_RUNTIME_DIR"]) / "hypr"
    sockets = sorted(runtime_root.glob("*/.socket.sock"), key=lambda path: path.stat().st_mtime, reverse=True)
    if sockets:
        env["HYPRLAND_INSTANCE_SIGNATURE"] = sockets[0].parent.name
    return env


def lua_quote(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= code <= 126:
            out.append(ch)
        else:
            out.append(f"\\{code:03d}")
    out.append('"')
    return "".join(out)


def hyprland_config_provider() -> str | None:
    hyprctl = shutil.which("hyprctl")
    if not hyprctl:
        return None
    proc = subprocess.run([hyprctl, "systeminfo"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=hyprctl_environment(), check=False)
    if proc.returncode != 0:
        return None
    match = re.search(r"^configProvider:\s*(\S+)", proc.stdout, re.MULTILINE)
    if not match:
        return None
    return match.group(1).lower()


def is_lua_config_provider() -> bool:
    return hyprland_config_provider() == "lua"


def session_environment() -> dict[str, str]:
    env = hyprctl_environment()
    runtime_dir = env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    env["XDG_RUNTIME_DIR"] = runtime_dir
    bus_path = pathlib.Path(runtime_dir) / "bus"
    if not env.get("DBUS_SESSION_BUS_ADDRESS") and bus_path.exists():
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"
    return env


def ensure_session_environment() -> dict[str, str]:
    env = session_environment()
    for key in SESSION_ENV_KEYS:
        value = env.get(key)
        if value:
            os.environ[key] = value
    return env


def result_text(info: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(info, ensure_ascii=False)}],
        "structuredContent": info,
        "isError": False,
    }


def mcp_text(text: str, *, is_error: bool = False, structured: dict[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if structured is not None:
        result["structuredContent"] = structured
    return result


def mcp_snapshot_result(snapshot: dict[str, Any]) -> dict[str, Any]:
    content = [{"type": "text", "text": render_snapshot_text(snapshot)}]
    related_image = snapshot.get("activeRelatedScreenshotPngBase64")
    active_related = snapshot.get("activeRelatedWindow") or {}
    if isinstance(related_image, str) and related_image:
        title = str(active_related.get("title") or active_related.get("initialTitle") or "related popup")
        target = window_selector(active_related) if active_related.get("address") else ""
        content.append({"type": "text", "text": f'Active related popup screenshot: "{title}" {target}'.strip()})
        content.append({"type": "image", "mimeType": "image/png", "data": related_image})
    image = snapshot.get("screenshotPngBase64")
    if isinstance(image, str) and image:
        if isinstance(related_image, str) and related_image:
            content.append({"type": "text", "text": "Root target screenshot:"})
        content.append({"type": "image", "mimeType": "image/png", "data": image})
    structured = {k: v for k, v in snapshot.items() if k not in {"screenshotPngBase64", "activeRelatedScreenshotPngBase64"}}
    return {"content": content, "structuredContent": structured, "isError": False}


def model_screenshot_resolution() -> str:
    raw = normalize(os.environ.get("HYPR_AGENT_PORTAL_MODEL_RESOLUTION") or DEFAULT_MODEL_SCREENSHOT_RESOLUTION)
    if raw in {"full", "native", "hidpi"}:
        return "full"
    return "logical"


def model_screenshot_max_dimension() -> int:
    raw = os.environ.get("HYPR_AGENT_PORTAL_MODEL_MAX_DIMENSION")
    if not raw:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def screenshot_command_base() -> list[str]:
    max_dimension = model_screenshot_max_dimension()
    cmd = ["screenshot", "--base64", "--model-resolution", model_screenshot_resolution()]
    if max_dimension > 0:
        cmd.extend(["--max-dimension", str(max_dimension)])
    return cmd


def require_target(args: dict[str, Any]) -> str:
    target = args.get("target")
    if not isinstance(target, str) or not target:
        app = args.get("app")
        if isinstance(app, str) and app:
            return window_selector(resolve_hypr_window(app))
    if not isinstance(target, str) or not target:
        raise RuntimeError("action requires target")
    return target


def require_xy(args: dict[str, Any]) -> tuple[float, float]:
    pair = coordinate_pair(args.get("coordinate"))
    if pair is not None:
        return pair
    x = args.get("x")
    y = args.get("y")
    if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
        raise RuntimeError("action requires numeric x and y")
    return float(x), float(y)


def target_address(target: str) -> str | None:
    try:
        target = strip_target_qualifier(target)
    except ValueError:
        return None
    if target.startswith("address:"):
        return target.split(":", 1)[1].lower()
    return None


def target_uses_xwayland(target: str, window: dict[str, Any] | None = None) -> bool | None:
    if isinstance(window, dict) and isinstance(window.get("xwayland"), bool):
        return bool(window["xwayland"])

    address = target_address(target)
    try:
        windows = call_ctl(["windows", "--related-to", target]).get("windows", [])
    except Exception:
        return None

    for candidate in windows:
        candidate_address = str(candidate.get("address") or "").lower()
        if (address and candidate_address == address) or candidate.get("hyprAgentPortalRelation") == "self":
            if isinstance(candidate.get("xwayland"), bool):
                return bool(candidate["xwayland"])
    return None


def related_windows_for(target: str) -> list[dict[str, Any]]:
    return call_ctl(["windows", "--related-to", target]).get("windows", [])


def privacy_filtered_related_windows(windows: Any) -> list[dict[str, Any]]:
    return [
        window
        for window in (windows if isinstance(windows, list) else [])
        if isinstance(window, dict) and not SECURITY_POLICY.privacy_excluded(window)
    ]


def related_popups_for(target: str) -> list[dict[str, Any]]:
    windows = privacy_filtered_related_windows(related_windows_for(target))
    root = next((window for window in windows if window.get("hyprAgentPortalRelation") == "self"), None)
    root_class = normalize((root or {}).get("class") or (root or {}).get("initialClass"))
    candidates = []
    for window in windows:
        if window.get("hyprAgentPortalRelation") != "related" or not isinstance(window.get("address"), str):
            continue
        if window.get("hidden", False) or not window.get("mapped", True):
            continue
        window_class = normalize(window.get("class") or window.get("initialClass"))
        is_popup = window.get("hyprAgentPortalWindowKind") == "popup"
        is_dialog_like = bool(window.get("floating")) or (bool(root_class) and window_class != root_class)
        if is_popup or is_dialog_like:
            candidates.append(window)
    return candidates


def active_related_windows(related_windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for window in related_windows:
        if not isinstance(window, dict) or window.get("hyprAgentPortalRelation") != "related":
            continue
        if not isinstance(window.get("address"), str):
            continue
        if window.get("hidden", False) or not window.get("mapped", True):
            continue
        is_popup = window.get("hyprAgentPortalWindowKind") == "popup"
        is_dialog = bool(window.get("floating"))
        if is_popup or is_dialog:
            candidates.append(window)
    candidates.sort(
        key=lambda window: (
            0 if window.get("hyprAgentPortalWindowKind") == "popup" else 1,
            int(window.get("focusHistoryID") if isinstance(window.get("focusHistoryID"), int) else 1_000_000),
        )
    )
    return candidates


def attach_active_related_preview(snapshot: dict[str, Any]) -> None:
    related = active_related_windows([item for item in snapshot.get("relatedWindows") or [] if isinstance(item, dict)])
    if not related:
        return
    active = related[0]
    snapshot["activeRelatedWindow"] = active
    snapshot["activeRelatedTarget"] = window_selector(active)
    snapshot["attention"] = {
        "type": "active-related-popup",
        "target": snapshot["activeRelatedTarget"],
        "title": str(active.get("title") or active.get("initialTitle") or ""),
        "message": "A related popup/dialog is open. Operate this target before continuing with the root window.",
    }
    try:
        screenshot, png_base64 = screenshot_for_window(active)
        snapshot["activeRelatedScreenshot"] = screenshot
        snapshot["activeRelatedScreenshotPngBase64"] = png_base64
    except Exception as exc:
        snapshot["activeRelatedScreenshotError"] = str(exc)


def session_action(action: str, target: str) -> dict[str, Any]:
    try:
        return call_ctl(["session", "--json", action, target])
    except Exception as exc:
        return {"ok": False, "action": action, "target": target, "error": str(exc)}


def sync_related_session(target: str, session_info: dict[str, Any]) -> list[dict[str, Any]]:
    session_info["sync"] = session_action("sync", target)
    try:
        return related_popups_for(target)
    except Exception as exc:
        session_info["relatedError"] = str(exc)
        return []


def begin_related_action_session(target: str) -> dict[str, Any]:
    return {"begin": session_action("begin", target), "sync": None, "end": None, "active": False}


def finish_related_action_session(target: str, session_info: dict[str, Any]) -> list[dict[str, Any]]:
    related_windows: list[dict[str, Any]] = []
    for attempt in range(6):
        related_windows = sync_related_session(target, session_info)
        if related_windows:
            break
        if attempt < 5:
            time.sleep(0.08)
    session_info["active"] = bool(related_windows)
    if not related_windows:
        session_info["end"] = session_action("end", target)
    return related_windows


def normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def window_selector(window: dict[str, Any]) -> str:
    address = str(window.get("address") or "")
    if not address:
        raise RuntimeError("target window has no address")
    # Hyprland client addresses are hexadecimal. Keep non-Hyprland synthetic
    # fixture/back-end selectors usable, but never treat them as native-bound.
    if re.fullmatch(r"0x[0-9a-fA-F]+", address) is None:
        return f"address:{address}"
    pid = window.get("pid")
    start_time = process_start_time(pid)
    try:
        return qualify_address(address, pid, start_time)
    except ValueError as exc:
        raise RuntimeError(f"target identity unavailable: {exc}") from exc


def window_geometry(window: dict[str, Any]) -> dict[str, float]:
    at = window.get("at") or [0, 0]
    size = window.get("size") or [0, 0]
    return {"x": float(at[0] or 0), "y": float(at[1] or 0), "width": float(size[0] or 0), "height": float(size[1] or 0)}


def window_origin(snapshot: dict[str, Any]) -> tuple[float, float]:
    window = snapshot.get("window") or {}
    geom = window_geometry(window) if isinstance(window, dict) else {}
    if geom.get("width", 0.0) > 0 and geom.get("height", 0.0) > 0:
        return float(geom["x"]), float(geom["y"])
    screenshot = snapshot.get("screenshot") or {}
    bounds = screenshot.get("logicalBounds") or {}
    return float(bounds.get("x") or 0.0), float(bounds.get("y") or 0.0)


def list_hypr_windows() -> list[dict[str, Any]]:
    windows = call_ctl(["windows"]).get("windows", [])
    return [window for window in windows if isinstance(window, dict) and window.get("mapped", True) and not window.get("hidden", False)]


def resolve_hypr_window(app: str) -> dict[str, Any]:
    try:
        parsed_target = parse_target(app)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    query = normalize(parsed_target.selector)
    if not query:
        raise RuntimeError("Missing required argument: app")

    windows = list_hypr_windows()

    def address_matches(window: dict[str, Any]) -> bool:
        address = normalize(window.get("address"))
        matches = query == address or query == address.removeprefix("0x") or (query.startswith("address:") and query.split(":", 1)[1] == address)
        if not matches or not parsed_target.qualified:
            return matches
        identity = WindowIdentity.from_window(window)
        return identity.pid == parsed_target.pid and identity.process_start_time == parsed_target.process_start_time

    def score(window: dict[str, Any]) -> tuple[int, int, float]:
        fields = {
            "class": normalize(window.get("class")),
            "initialClass": normalize(window.get("initialClass")),
            "title": normalize(window.get("title")),
            "initialTitle": normalize(window.get("initialTitle")),
            "pid": str(window.get("pid") or ""),
        }
        if address_matches(window):
            primary = 0
        elif fields["pid"] == query:
            primary = 1
        elif fields["class"] == query or fields["initialClass"] == query:
            primary = 2
        elif fields["title"] == query or fields["initialTitle"] == query:
            primary = 3
        elif query in fields["class"] or query in fields["initialClass"]:
            primary = 4
        elif query in fields["title"] or query in fields["initialTitle"]:
            primary = 5
        else:
            primary = 100
        focus = window.get("focusHistoryID")
        focus_score = int(focus) if isinstance(focus, int) else 1_000_000
        geom = window_geometry(window)
        area = geom["width"] * geom["height"]
        return primary, focus_score, -area

    matches = [window for window in windows if score(window)[0] < 100]
    if not matches:
        raise RuntimeError(f'appNotFound("{app}")')
    return sorted(matches, key=score)[0]


def list_apps_text(windows: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for window in sorted(windows, key=lambda item: (normalize(item.get("class")), normalize(item.get("title")), int(item.get("pid") or 0))):
        workspace = window.get("workspace") or {}
        name = str(window.get("class") or window.get("initialClass") or "unknown")
        title = str(window.get("title") or "untitled")
        address = str(window.get("address") or "")
        pid = int(window.get("pid") or 0)
        attrs = [f"running", f"pid={pid}", f"window={window_selector(window)}", f"workspace={workspace.get('name', workspace.get('id', ''))}"]
        if window.get("xwayland"):
            attrs.append("xwayland")
        lines.append(f"{name} -- {title} [{', '.join(attrs)}]")
    return "\n".join(lines) if lines else "No running Hyprland apps are visible to hypr-agent-portal."


def executable_basename(value: str) -> str:
    return pathlib.Path(value).name.lower()


def normalize_desktop_id(value: str) -> str:
    return value[:-8] if value.endswith(".desktop") else value


def resolve_launch_executable(name: str) -> str:
    aliases = {
        "chrome": ["google-chrome-stable", "google-chrome", "chromium"],
        "google-chrome": ["google-chrome-stable", "google-chrome", "chromium"],
        "chromium": ["chromium", "chromium-browser", "google-chrome-stable", "google-chrome"],
        "browser": ["chromium", "google-chrome-stable", "google-chrome", "firefox"],
    }
    candidates = aliases.get(name.lower(), [name])
    for candidate in candidates:
        if shutil.which(candidate):
            return candidate
    return name


def launch_parts(args: dict[str, Any]) -> tuple[list[str], str]:
    command = args.get("command")
    app = args.get("app")
    if isinstance(command, str) and command.strip():
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            raise RuntimeError(f"invalid launch command: {exc}") from exc
        match_query = executable_basename(parts[0]) if parts else command
    elif isinstance(app, str) and app.strip():
        app_value = app.strip()
        if app_value.endswith(".desktop"):
            parts = ["gtk-launch", normalize_desktop_id(app_value)]
            match_query = normalize_desktop_id(app_value)
        else:
            try:
                parts = shlex.split(app_value)
            except ValueError as exc:
                raise RuntimeError(f"invalid app command: {exc}") from exc
            if parts:
                parts[0] = resolve_launch_executable(parts[0])
            match_query = executable_basename(parts[0]) if parts else app_value
    else:
        raise RuntimeError("launch_app requires app or command")

    if not parts:
        raise RuntimeError("launch_app resolved to an empty command")

    extra_args = args.get("args")
    if isinstance(extra_args, list):
        parts.extend(str(item) for item in extra_args if isinstance(item, str))

    url = args.get("url")
    new_window = args.get("new_window")
    if not isinstance(new_window, bool):
        new_window = True

    browser_like = launch_is_chromium_like(parts)
    if browser_like:
        if "--force-renderer-accessibility" not in parts:
            parts.append("--force-renderer-accessibility")
        if new_window and not any(part == "--new-window" or part.startswith("--app=") for part in parts):
            parts.append("--new-window")
        if isinstance(url, str) and url:
            parts.append(url)
        elif new_window and not any(not part.startswith("-") for part in parts[1:]):
            parts.append("about:blank")
    elif isinstance(url, str) and url:
        parts.append(url)

    return parts, match_query


def launch_is_chromium_like(parts: list[str]) -> bool:
    if not parts:
        return False
    base = executable_basename(parts[0])
    if base in CHROMIUM_LIKE_EXECUTABLES:
        return True
    return any(token in base for token in ("chrom", "brave", "electron", "discord", "slack"))


def launch_command_string(parts: list[str]) -> str:
    env_parts = ["env", *[f"{key}={value}" for key, value in A11Y_LAUNCH_ENV.items()]]
    return shlex.join([*env_parts, *parts])


def hyprctl_exec(command: str) -> str:
    hyprctl = shutil.which("hyprctl")
    if not hyprctl:
        raise RuntimeError("hyprctl not found")
    env = hyprctl_environment()
    if is_lua_config_provider():
        dispatch_args = [hyprctl, "dispatch", f"hl.dsp.exec_cmd({lua_quote(command)})"]
    else:
        dispatch_args = [hyprctl, "dispatch", "exec", command]
    try:
        proc = subprocess.run(
            dispatch_args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=MAX_TOOL_WAIT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"hyprctl launch dispatch timed out after {MAX_TOOL_WAIT_SECONDS:g}s") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"{' '.join(dispatch_args[:3])} failed with exit code {proc.returncode}").strip())
    return proc.stdout.strip()


def window_identities(windows: list[dict[str, Any]]) -> set[str]:
    identities: set[str] = set()
    for window in windows:
        for key in ("address", "stableId"):
            value = str(window.get(key) or "")
            if value:
                identities.add(f"{key}:{value}")
    return identities


def window_matches_launch(window: dict[str, Any], query: str) -> bool:
    normalized = normalize(query)
    if not normalized:
        return False
    fields = [
        normalize(window.get("class")),
        normalize(window.get("initialClass")),
        normalize(window.get("title")),
        normalize(window.get("initialTitle")),
        str(window.get("pid") or ""),
    ]
    desktop = normalized.removesuffix(".desktop")
    return any(normalized == field or desktop == field or normalized in field or desktop in field for field in fields if field)


def wait_for_launch_window(before_ids: set[str], query: str, timeout: float, *, allow_existing_fallback: bool = True) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    effective_timeout = bounded_timeout_seconds(timeout, 8.0)
    deadline = time.monotonic() + effective_timeout
    latest: list[dict[str, Any]] = []
    last_new_windows: list[dict[str, Any]] = []
    first_unmatched_window_at: float | None = None
    while True:
        latest = list_hypr_windows()
        new_windows = [window for window in latest if not (window_identities([window]) & before_ids)]
        if new_windows:
            last_new_windows = new_windows
        matching_new = [window for window in new_windows if window_matches_launch(window, query)]
        if matching_new:
            return matching_new[0], matching_new
        if allow_existing_fallback:
            matching_existing = [window for window in latest if window_matches_launch(window, query)]
            if matching_existing:
                return matching_existing[0], []
        now = time.monotonic()
        if new_windows and first_unmatched_window_at is None:
            first_unmatched_window_at = now
        if last_new_windows and first_unmatched_window_at is not None and now - first_unmatched_window_at >= min(
            LAUNCH_UNMATCHED_WINDOW_GRACE_SECONDS, effective_timeout
        ):
            return last_new_windows[0], last_new_windows
        if now >= deadline:
            if last_new_windows:
                return last_new_windows[0], last_new_windows
            return None, []
        time.sleep(0.2)


def remember_snapshot(query: str, snapshot: dict[str, Any]) -> None:
    window = snapshot.get("window") or {}
    app = snapshot.get("app") or {}
    keys = [
        query,
        window_selector(window) if window.get("address") else "",
        window.get("address"),
        window.get("class"),
        window.get("initialClass"),
        window.get("title"),
        app.get("name"),
        app.get("bundleIdentifier"),
        str(app.get("pid") or ""),
    ]
    for key in keys:
        normalized = normalize(key)
        if normalized:
            SNAPSHOTS[normalized] = snapshot


def process_start_time(pid: Any) -> str:
    try:
        value = int(pid)
        stat_text = pathlib.Path(f"/proc/{value}/stat").read_text()
        remainder = stat_text.rsplit(")", 1)[1].split()
        return remainder[19] if len(remainder) > 19 else ""
    except (OSError, TypeError, ValueError):
        return ""


def cache_visual(kind: str, payload: dict[str, Any], snapshot: dict[str, Any]) -> str:
    token = f"{kind}_{secrets.token_urlsafe(18)}"
    window = snapshot.get("window") or {}
    screenshot = snapshot.get("screenshot") or {}
    VISUAL_CACHE[token] = {
        "kind": kind,
        "payload": payload,
        "snapshot": snapshot,
        "capturedAt": float(snapshot.get("capturedAt") or time.time()),
        "sha256": str(screenshot.get("sha256") or ""),
        "address": normalize(window.get("address")),
        "pid": int(window.get("pid") or 0),
        "starttime": str(snapshot.get("windowStartTime") or ""),
        "windowBounds": dict(snapshot.get("windowBounds") or {}),
        "sourceSize": {"width": screenshot.get("width"), "height": screenshot.get("height")},
    }
    return token


def visual_cache_entry(token: Any, expected_kind: str, *, validate_live: bool = True) -> dict[str, Any]:
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"{expected_kind}_id is required")
    entry = VISUAL_CACHE.get(token)
    if not isinstance(entry, dict) or entry.get("kind") != expected_kind:
        raise RuntimeError(f"visual cache miss for {expected_kind}_id")
    age = time.time() - float(entry.get("capturedAt") or 0.0)
    if age < 0 or age > VISUAL_CACHE_TTL_SECONDS:
        VISUAL_CACHE.pop(token, None)
        raise RuntimeError(f"stale visual target: {expected_kind} cache TTL expired")
    if not validate_live:
        return entry
    selector = qualify_address(entry["address"], entry["pid"], entry["starttime"])
    window = resolve_hypr_window(selector)
    if SECURITY_POLICY.privacy_excluded(window):
        raise RuntimeError("visual target is now privacy-excluded")
    identity = {
        "address": normalize(window.get("address")),
        "pid": int(window.get("pid") or 0),
        "starttime": process_start_time(window.get("pid")),
        "windowBounds": window_geometry(window),
    }
    for field in ("address", "pid", "starttime", "windowBounds"):
        if identity[field] != entry[field]:
            raise RuntimeError(f"stale visual target: window {field} changed")
    screenshot, png_base64 = screenshot_for_window(window)
    raw = base64.b64decode(png_base64, validate=True)
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise RuntimeError("stale visual target: screenshot content hash changed")
    if {"width": screenshot.get("width"), "height": screenshot.get("height")} != entry["sourceSize"]:
        raise RuntimeError("stale visual target: screenshot source size changed")
    return entry


def current_snapshot(app: str) -> dict[str, Any]:
    snapshot = SNAPSHOTS.get(normalize(app))
    if snapshot is None:
        snapshot = build_app_snapshot(app)
    else:
        snapshot, _ = refresh_snapshot_geometry(snapshot, app, rebuild_on_resize=True)
    return snapshot


def snapshot_window_query(snapshot: dict[str, Any], fallback: str) -> str:
    target = str(snapshot.get("target") or "")
    if target:
        return target
    window = snapshot.get("window") or {}
    if isinstance(window, dict) and window.get("address"):
        return window_selector(window)
    return fallback


def snapshot_geometry(snapshot: dict[str, Any]) -> dict[str, float]:
    bounds = snapshot.get("windowBounds")
    if isinstance(bounds, dict):
        return {
            "x": float(bounds.get("x") or 0.0),
            "y": float(bounds.get("y") or 0.0),
            "width": float(bounds.get("width") or 0.0),
            "height": float(bounds.get("height") or 0.0),
        }
    window = snapshot.get("window") or {}
    return window_geometry(window) if isinstance(window, dict) else {"x": 0.0, "y": 0.0, "width": 0.0, "height": 0.0}


def geometry_size_changed(old: dict[str, float], new: dict[str, float]) -> bool:
    return abs(float(old.get("width") or 0.0) - float(new.get("width") or 0.0)) > GEOMETRY_EPSILON or abs(
        float(old.get("height") or 0.0) - float(new.get("height") or 0.0)
    ) > GEOMETRY_EPSILON


def geometry_position_delta(old: dict[str, float], new: dict[str, float]) -> tuple[float, float]:
    return float(new.get("x") or 0.0) - float(old.get("x") or 0.0), float(new.get("y") or 0.0) - float(old.get("y") or 0.0)


def geometry_moved(old: dict[str, float], new: dict[str, float]) -> bool:
    dx, dy = geometry_position_delta(old, new)
    return abs(dx) > GEOMETRY_EPSILON or abs(dy) > GEOMETRY_EPSILON


def shift_snapshot_to_live_window(snapshot: dict[str, Any], live_window: dict[str, Any], dx: float, dy: float) -> dict[str, Any]:
    shifted = copy.deepcopy(snapshot)
    shifted["window"] = live_window
    shifted["windowBounds"] = window_geometry(live_window)
    shifted["target"] = window_selector(live_window)
    screenshot = shifted.get("screenshot")
    if isinstance(screenshot, dict):
        bounds = screenshot.get("logicalBounds")
        if isinstance(bounds, dict):
            bounds["x"] = float(bounds.get("x") or 0.0) + dx
            bounds["y"] = float(bounds.get("y") or 0.0) + dy
    return shifted


def compact_geometry_info(geometry: dict[str, float]) -> dict[str, float]:
    return {key: round(float(geometry.get(key) or 0.0), 3) for key in ["x", "y", "width", "height"]}


def refresh_snapshot_geometry(snapshot: dict[str, Any], app: str, *, rebuild_on_resize: bool) -> tuple[dict[str, Any], dict[str, Any] | None]:
    query = snapshot_window_query(snapshot, app)
    live_window = resolve_hypr_window(query)
    old_geometry = snapshot_geometry(snapshot)
    live_geometry = window_geometry(live_window)
    target = window_selector(live_window)

    if geometry_size_changed(old_geometry, live_geometry):
        info = {
            "type": "windowGeometryChanged",
            "change": "resized",
            "old": compact_geometry_info(old_geometry),
            "current": compact_geometry_info(live_geometry),
            "target": target,
            "rebuilt": bool(rebuild_on_resize),
        }
        if rebuild_on_resize:
            rebuilt = build_app_snapshot(target)
            return rebuilt, info
        return snapshot, info

    if geometry_moved(old_geometry, live_geometry):
        dx, dy = geometry_position_delta(old_geometry, live_geometry)
        shifted = shift_snapshot_to_live_window(snapshot, live_window, dx, dy)
        info = {
            "type": "windowGeometryChanged",
            "change": "moved",
            "delta": {"x": round(dx, 3), "y": round(dy, 3)},
            "old": compact_geometry_info(old_geometry),
            "current": compact_geometry_info(live_geometry),
            "target": target,
            "rebuilt": False,
        }
        remember_snapshot(app, shifted)
        return shifted, info

    return snapshot, None


def ensure_global_menu_backends() -> dict[str, Any]:
    info: dict[str, Any] = {"kdeAppMenuLoaded": False, "gtkMenuProxyStarted": False, "errors": []}
    ok, out = busctl_user(["call", "org.kde.kded6", "/kded", "org.kde.kded6", "loadModule", "s", "appmenu"], timeout=1.5)
    if ok:
        info["kdeAppMenuLoaded"] = "true" in out.lower() or "b " in out
    elif out:
        info["errors"].append(out.strip())
    systemctl = shutil.which("systemctl")
    if systemctl:
        try:
            proc = subprocess.run(
                [systemctl, "--user", "start", "plasma-gmenudbusmenuproxy.service"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=session_environment(),
                check=False,
                timeout=1.5,
            )
            info["gtkMenuProxyStarted"] = proc.returncode == 0
        except subprocess.TimeoutExpired:
            info["errors"].append("plasma-gmenudbusmenuproxy start timed out")
    return info


def dbus_services_for_pid(pid: int) -> list[str]:
    if pid <= 0:
        return []
    ok, out = busctl_user(["list"], timeout=2.0)
    if not ok:
        return []
    services: list[str] = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            service_pid = int(parts[1])
        except ValueError:
            continue
        if service_pid == pid and parts[0].startswith(":"):
            services.append(parts[0])
    return services


def dbus_tree_paths(service: str) -> list[str]:
    ok, out = busctl_user(["tree", service], timeout=GLOBAL_MENU_TREE_TIMEOUT_SECONDS)
    if not ok:
        return []
    paths: list[str] = []
    for line in out.splitlines():
        match = re.search(r"(/[A-Za-z0-9_./-]+)", line)
        if match:
            paths.append(match.group(1))
    return paths


def glib_variant_to_plain(value: Any) -> Any:
    try:
        unpacked = value.unpack()
    except Exception:
        try:
            return value.print_(False)
        except Exception:
            return str(value)
    if isinstance(unpacked, bytes):
        return unpacked.decode("utf-8", "replace")
    if isinstance(unpacked, (list, tuple)):
        return [glib_variant_to_plain(item) for item in unpacked]
    if isinstance(unpacked, dict):
        return {str(k): glib_variant_to_plain(v) for k, v in unpacked.items()}
    return unpacked


def dbusmenu_item_property(item: Any, name: str) -> Any:
    try:
        value = item.property_get(name)
    except Exception:
        return None
    return glib_variant_to_plain(value)


def walk_dbusmenu_items(service: str, object_path: str, *, limit: int = GLOBAL_MENU_LIMIT) -> tuple[list[dict[str, Any]], str]:
    try:
        import gi

        gi.require_version("Dbusmenu", "0.4")
        from gi.repository import Dbusmenu, GLib
    except Exception as exc:
        return [], f"Dbusmenu GI unavailable: {exc}"

    try:
        client = Dbusmenu.Client.new(service, object_path)
        loop = GLib.MainLoop()
        GLib.timeout_add(350, lambda: (loop.quit(), False)[1])
        loop.run()
        root = client.get_root()
    except Exception as exc:
        return [], str(exc)
    if root is None:
        return [], "DBusMenu root is empty"

    records: list[dict[str, Any]] = []

    def walk(item: Any, path: list[int], depth: int) -> None:
        if len(records) >= limit:
            return
        label = str(dbusmenu_item_property(item, "label") or "").replace("_", "").strip()
        enabled = dbusmenu_item_property(item, "enabled")
        visible = dbusmenu_item_property(item, "visible")
        item_type = dbusmenu_item_property(item, "type")
        children = list(item.get_children() or [])
        if label and path:
            records.append(
                {
                    "menuIndex": f"dbusmenu:{len(records)}",
                    "provider": "dbusmenu",
                    "service": service,
                    "objectPath": object_path,
                    "path": path,
                    "depth": depth,
                    "label": label,
                    "enabled": True if enabled is None else bool(enabled),
                    "visible": True if visible is None else bool(visible),
                    "type": item_type or "",
                    "hasChildren": bool(children),
                }
            )
        for child_index, child in enumerate(children):
            walk(child, [*path, child_index], depth + 1)

    walk(root, [], 0)
    return records, ""


def gmenu_item_attributes(model: Any, index: int) -> dict[str, Any]:
    attrs: dict[str, Any] = {}
    iterator = model.iterate_item_attributes(index)
    while True:
        ok, name, value = iterator.get_next()
        if not ok:
            break
        attrs[str(name)] = glib_variant_to_plain(value)
    return attrs


def walk_gmenu_items(service: str, object_path: str, *, limit: int = GLOBAL_MENU_LIMIT) -> tuple[list[dict[str, Any]], str]:
    try:
        from gi.repository import Gio, GLib
    except Exception as exc:
        return [], f"Gio unavailable: {exc}"
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        model = Gio.DBusMenuModel.get(bus, service, object_path)
        loop = GLib.MainLoop()
        GLib.timeout_add(350, lambda: (loop.quit(), False)[1])
        loop.run()
    except Exception as exc:
        return [], str(exc)

    records: list[dict[str, Any]] = []

    def walk(model_obj: Any, path: list[int], depth: int) -> None:
        if len(records) >= limit:
            return
        try:
            count = int(model_obj.get_n_items())
        except Exception:
            return
        for item_index in range(count):
            if len(records) >= limit:
                return
            attrs = gmenu_item_attributes(model_obj, item_index)
            label = str(attrs.get("label") or attrs.get("verb-icon") or "").strip()
            action = str(attrs.get("action") or "")
            target = attrs.get("target")
            links: list[tuple[str, Any]] = []
            iterator = model_obj.iterate_item_links(item_index)
            while True:
                ok, name, linked = iterator.get_next()
                if not ok:
                    break
                links.append((str(name), linked))
            if label or action:
                records.append(
                    {
                        "menuIndex": f"gmenu:{len(records)}",
                        "provider": "gmenu",
                        "service": service,
                        "objectPath": object_path,
                        "path": [*path, item_index],
                        "depth": depth,
                        "label": label or action,
                        "action": action,
                        "target": target,
                        "attributes": attrs,
                        "hasChildren": bool(links),
                    }
                )
            for _, linked_model in links:
                walk(linked_model, [*path, item_index], depth + 1)

    walk(model, [], 0)
    return records, ""


def global_menu_for_window(window: dict[str, Any]) -> dict[str, Any]:
    pid = int(window.get("pid") or 0)
    backend = ensure_global_menu_backends()
    services = dbus_services_for_pid(pid)
    providers: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    errors: list[str] = []
    for service in services:
        paths = dbus_tree_paths(service)
        for path in paths:
            if path == "/com/canonical/dbusmenu" or path.endswith("/dbusmenu"):
                records, error_text = walk_dbusmenu_items(service, path)
                providers.append({"provider": "dbusmenu", "service": service, "objectPath": path, "itemCount": len(records)})
                if error_text:
                    errors.append(f"{service}{path}: {error_text}")
                for record in records:
                    record["menuIndex"] = f"menu:{len(items)}"
                    items.append(record)
            elif path.endswith("/menus/menubar"):
                records, error_text = walk_gmenu_items(service, path)
                providers.append({"provider": "gmenu", "service": service, "objectPath": path, "itemCount": len(records)})
                if error_text:
                    errors.append(f"{service}{path}: {error_text}")
                for record in records:
                    record["menuIndex"] = f"menu:{len(items)}"
                    items.append(record)
    return {
        "status": "ok" if providers else "unavailable",
        "backend": backend,
        "services": services,
        "providers": providers,
        "items": items[:GLOBAL_MENU_LIMIT],
        "truncated": len(items) > GLOBAL_MENU_LIMIT,
        "errors": errors[:12],
    }


def find_global_menu_item(snapshot: dict[str, Any], menu_index: str) -> dict[str, Any]:
    menu = snapshot.get("globalMenu") or {}
    for item in menu.get("items") or []:
        if str(item.get("menuIndex") or "") == str(menu_index):
            return dict(item)
    raise RuntimeError(f'unknown menu_index "{menu_index}"')


def refind_dbusmenu_item(service: str, object_path: str, path: list[int]) -> Any:
    import gi

    gi.require_version("Dbusmenu", "0.4")
    from gi.repository import Dbusmenu, GLib

    client = Dbusmenu.Client.new(service, object_path)
    loop = GLib.MainLoop()
    GLib.timeout_add(350, lambda: (loop.quit(), False)[1])
    loop.run()
    item = client.get_root()
    if item is None:
        raise RuntimeError("DBusMenu root is empty")
    for child_index in path:
        children = list(item.get_children() or [])
        if not isinstance(child_index, int) or child_index < 0 or child_index >= len(children):
            raise RuntimeError("DBusMenu item path no longer exists")
        item = children[child_index]
    return item


def activate_dbusmenu_item(item_info: dict[str, Any]) -> dict[str, Any]:
    from gi.repository import GLib

    item = refind_dbusmenu_item(str(item_info.get("service") or ""), str(item_info.get("objectPath") or ""), list(item_info.get("path") or []))
    item.handle_event("clicked", GLib.Variant("s", ""), int(time.time()))
    return {"ok": True, "provider": "dbusmenu", "menuIndex": item_info.get("menuIndex"), "label": item_info.get("label")}


def gtk_action_candidates_for_menu(item_info: dict[str, Any]) -> list[tuple[str, str]]:
    action = str(item_info.get("action") or "")
    if "." in action:
        namespace, action_name = action.split(".", 1)
    else:
        namespace, action_name = "", action
    object_path = str(item_info.get("objectPath") or "")
    base_path = object_path.split("/menus/", 1)[0] if "/menus/" in object_path else object_path
    candidates: list[tuple[str, str]] = []
    if namespace in {"win", "window"} and base_path:
        candidates.append((base_path, action_name))
    if namespace in {"app", "application"}:
        parts = [part for part in base_path.split("/") if part]
        if len(parts) >= 2:
            candidates.append(("/" + "/".join(parts[:2]), action_name))
        candidates.append((base_path, action_name))
    if not candidates and base_path:
        candidates.append((base_path, action_name))
    return candidates


def activate_gmenu_item(item_info: dict[str, Any]) -> dict[str, Any]:
    try:
        from gi.repository import Gio, GLib
    except Exception as exc:
        raise RuntimeError(f"Gio unavailable: {exc}") from exc
    action = str(item_info.get("action") or "")
    if not action:
        raise RuntimeError("GMenu item has no action to activate")
    service = str(item_info.get("service") or "")
    target = item_info.get("target")
    parameters: list[Any] = []
    if target is not None:
        if hasattr(target, "is_of_type"):
            parameters.append(target)
        elif isinstance(target, bool):
            parameters.append(GLib.Variant("b", target))
        elif isinstance(target, int):
            parameters.append(GLib.Variant("i", target))
        elif isinstance(target, str):
            parameters.append(GLib.Variant("s", target))
        else:
            parameters.append(GLib.Variant("s", str(target)))
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    last_error = ""
    for action_path, action_name in gtk_action_candidates_for_menu(item_info):
        try:
            bus.call_sync(
                service,
                action_path,
                "org.gtk.Actions",
                "Activate",
                GLib.Variant("(sava{sv})", (action_name, parameters, {})),
                None,
                Gio.DBusCallFlags.NONE,
                1500,
                None,
            )
            return {"ok": True, "provider": "gmenu", "menuIndex": item_info.get("menuIndex"), "label": item_info.get("label"), "action": action}
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(last_error or f"could not activate GMenu action {action}")


def lookup_element(snapshot: dict[str, Any], element_index: str) -> dict[str, Any]:
    try:
        index = int(element_index)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f'unknown element_index "{element_index}"') from exc
    for element in snapshot.get("elements") or []:
        if int(element.get("index", -1)) == index:
            return dict(element)
    raise RuntimeError(f'unknown element_index "{element_index}"')


def element_runtime_id(element: dict[str, Any]) -> tuple[Any, ...]:
    runtime_id = element.get("runtimeId")
    return tuple(runtime_id) if isinstance(runtime_id, list) else ()


def element_identity_text(element: dict[str, Any]) -> str:
    return " ".join(
        part
        for part in [
            str(element.get("name") or ""),
            str(element.get("value") or ""),
            str(element.get("automationId") or ""),
        ]
        if part
    )


def frame_distance(a: dict[str, Any], b: dict[str, Any]) -> float:
    frame_a = a.get("frame")
    frame_b = b.get("frame")
    if not isinstance(frame_a, dict) or not isinstance(frame_b, dict):
        return 1_000_000.0
    ax = float(frame_a.get("x") or 0.0) + float(frame_a.get("width") or 0.0) / 2.0
    ay = float(frame_a.get("y") or 0.0) + float(frame_a.get("height") or 0.0) / 2.0
    bx = float(frame_b.get("x") or 0.0) + float(frame_b.get("width") or 0.0) / 2.0
    by = float(frame_b.get("y") or 0.0) + float(frame_b.get("height") or 0.0) / 2.0
    return ((ax - bx) ** 2 + (ay - by) ** 2) ** 0.5


def element_match_score(old: dict[str, Any], candidate: dict[str, Any], fallback_index: int) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    old_runtime = element_runtime_id(old)
    candidate_runtime = element_runtime_id(candidate)
    old_role = element_role(old)
    candidate_role = element_role(candidate)
    old_name = normalize(old.get("name"))
    candidate_name = normalize(candidate.get("name"))
    old_value = normalize(old.get("value"))
    candidate_value = normalize(candidate.get("value"))
    old_automation = normalize(old.get("automationId"))
    candidate_automation = normalize(candidate.get("automationId"))

    if old_runtime and old_runtime == candidate_runtime:
        score += 1000.0
        reasons.append("runtimeId")
    if old_automation and old_automation == candidate_automation:
        score += 420.0
        reasons.append("automationId")
    if old_role and old_role == candidate_role:
        score += 90.0
        reasons.append("role")
    if old_name and old_name == candidate_name:
        score += 180.0
        reasons.append("name")
    elif old_name and candidate_name and (old_name in candidate_name or candidate_name in old_name):
        score += 70.0
        reasons.append("name-prefix")
    if old_value and old_value == candidate_value:
        score += 120.0
        reasons.append("value")
    elif old_value and candidate_value and (old_value in candidate_value or candidate_value in old_value):
        score += 45.0
        reasons.append("value-prefix")
    if normalize(old.get("source")) and normalize(old.get("source")) == normalize(candidate.get("source")):
        score += 20.0
        reasons.append("source")
    if int(candidate.get("index", -1)) == fallback_index:
        score += 55.0
        reasons.append("same-index")

    old_actions = {normalize(action) for action in old.get("actions") or [] if action}
    candidate_actions = {normalize(action) for action in candidate.get("actions") or [] if action}
    if old_actions and candidate_actions and old_actions & candidate_actions:
        score += 25.0
        reasons.append("actions")

    distance = frame_distance(old, candidate)
    if distance < 1_000_000.0:
        score += max(0.0, 45.0 - min(distance, 450.0) / 10.0)
    return score, reasons


def refind_element_in_snapshot(snapshot: dict[str, Any], old_element: dict[str, Any], fallback_index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    candidates: list[tuple[float, list[str], dict[str, Any]]] = []
    for candidate in snapshot.get("elements") or []:
        if not isinstance(candidate, dict):
            continue
        score, reasons = element_match_score(old_element, candidate, fallback_index)
        if reasons:
            candidates.append((score, reasons, dict(candidate)))
    candidates.sort(key=lambda item: item[0], reverse=True)

    if candidates:
        score, reasons, element = candidates[0]
        old_has_identity = bool(element_runtime_id(old_element) or normalize(old_element.get("automationId")) or element_identity_text(old_element))
        role_matches = element_role(old_element) == element_role(element)
        strong_identity = any(reason in reasons for reason in ["runtimeId", "automationId", "name", "value"])
        same_index = "same-index" in reasons
        if score >= 160.0 and (strong_identity or role_matches or same_index):
            return element, {"matched": True, "score": round(score, 3), "matchedBy": reasons, "oldIndex": fallback_index, "newIndex": element.get("index")}
        if not old_has_identity and role_matches and same_index:
            return element, {"matched": True, "score": round(score, 3), "matchedBy": reasons, "oldIndex": fallback_index, "newIndex": element.get("index")}

    raise RuntimeError(f'element_index "{fallback_index}" became stale after the target window changed size; call get_app_state and choose the visible element again')


def element_snapshot_for_action(app: str, element_index: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    snapshot = SNAPSHOTS.get(normalize(app))
    if snapshot is None:
        snapshot = build_app_snapshot(app)
    old_element = lookup_element(snapshot, element_index)
    fallback_index = int(element_index)
    snapshot, refresh_info = refresh_snapshot_geometry(snapshot, app, rebuild_on_resize=False)

    if isinstance(refresh_info, dict) and refresh_info.get("change") == "resized":
        rebuilt = build_app_snapshot(str(refresh_info.get("target") or snapshot_window_query(snapshot, app)))
        element, rematch_info = refind_element_in_snapshot(rebuilt, old_element, fallback_index)
        return rebuilt, element, {"geometryRefresh": refresh_info, "elementRematch": rematch_info}

    element = lookup_element(snapshot, element_index)
    if isinstance(refresh_info, dict):
        return snapshot, element, {"geometryRefresh": refresh_info}
    return snapshot, element, None


def screenshot_point_to_global(snapshot: dict[str, Any], x: float, y: float) -> tuple[float, float]:
    screenshot = snapshot.get("screenshot") or {}
    bounds = screenshot.get("logicalBounds") or {}
    sx = screenshot_axis_scale(screenshot, "x")
    sy = screenshot_axis_scale(screenshot, "y")
    return float(bounds.get("x") or 0.0) + float(x) / sx, float(bounds.get("y") or 0.0) + float(y) / sy


def window_point_to_global(snapshot: dict[str, Any], x: float, y: float) -> tuple[float, float]:
    origin_x, origin_y = window_origin(snapshot)
    return origin_x + float(x), origin_y + float(y)


def point_to_global(snapshot: dict[str, Any], x: float, y: float, coordinate_space: Any = "screenshot") -> tuple[float, float]:
    space = normalize(coordinate_space or "screenshot").replace("_", "-")
    if space in {"screenshot", "screenshot-pixel", "screenshot-pixels", "image", "pixel", "pixels"}:
        return screenshot_point_to_global(snapshot, x, y)
    if space in {"window", "window-relative", "window-logical", "logical"}:
        return window_point_to_global(snapshot, x, y)
    if space == "global":
        return x, y
    raise RuntimeError(f"unsupported coordinate_space: {coordinate_space}")


def point_to_window(snapshot: dict[str, Any], x: float, y: float, coordinate_space: Any = "screenshot") -> tuple[float, float]:
    space = normalize(coordinate_space or "screenshot").replace("_", "-")
    if space in {"window", "window-relative", "window-logical", "logical"}:
        return float(x), float(y)
    global_x, global_y = point_to_global(snapshot, x, y, coordinate_space)
    origin_x, origin_y = window_origin(snapshot)
    return global_x - origin_x, global_y - origin_y


def pointer_call_coordinates(snapshot: dict[str, Any], x: float, y: float, coordinate_space: Any) -> tuple[float, float, float, float, bool]:
    global_x, global_y = point_to_global(snapshot, x, y, coordinate_space)
    space = normalize(coordinate_space or "screenshot").replace("_", "-")
    if space == "global":
        return global_x, global_y, global_x, global_y, False
    window_x, window_y = point_to_window(snapshot, x, y, coordinate_space)
    return global_x, global_y, window_x, window_y, True


def pointer_ctl_args(snapshot: dict[str, Any], x: float, y: float, coordinate_space: Any, action: str, button: str = "left") -> tuple[list[str], dict[str, Any]]:
    global_x, global_y, window_x, window_y, use_relative = pointer_call_coordinates(snapshot, x, y, coordinate_space)
    args = ["pointer", "--json"]
    if use_relative:
        args.append("--relative")
        dispatch_x, dispatch_y = window_x, window_y
    else:
        dispatch_x, dispatch_y = global_x, global_y
    args.extend([str(snapshot["target"]), str(dispatch_x), str(dispatch_y), action, button])
    return args, {
        "global": {"x": global_x, "y": global_y},
        "window": {"x": window_x, "y": window_y, "coordinateSpace": "window"},
        "dispatchCoordinateSpace": "window" if use_relative else "global",
        "dispatchCoordinate": {"x": dispatch_x, "y": dispatch_y},
    }


def coordinate_pair(value: Any) -> tuple[float, float] | None:
    if not isinstance(value, (list, tuple)) or len(value) < 2:
        return None
    x, y = value[0], value[1]
    if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
        return None
    return float(x), float(y)


def point_from_args(args: dict[str, Any], *, prefix: str = "", coordinate_key: str = "coordinate") -> tuple[float, float] | None:
    pair = coordinate_pair(args.get(coordinate_key))
    if pair is not None:
        return pair

    if prefix:
        x_key = f"{prefix}_x"
        y_key = f"{prefix}_y"
    else:
        x_key = "x"
        y_key = "y"
    x = args.get(x_key)
    y = args.get(y_key)
    if isinstance(x, (int, float)) and isinstance(y, (int, float)):
        return float(x), float(y)
    return None


def snapshot_position(snapshot: dict[str, Any], global_x: float, global_y: float) -> dict[str, Any]:
    screenshot = snapshot.get("screenshot") or {}
    bounds = screenshot.get("logicalBounds") or {}
    sx = screenshot_axis_scale(screenshot, "x")
    sy = screenshot_axis_scale(screenshot, "y")
    left = float(bounds.get("x") or 0.0)
    top = float(bounds.get("y") or 0.0)
    width = float(bounds.get("width") or 0.0)
    height = float(bounds.get("height") or 0.0)
    origin_x, origin_y = window_origin(snapshot)
    window = snapshot.get("window") or {}
    geom = window_geometry(window) if isinstance(window, dict) else {}
    window_width = float(geom.get("width") or width)
    window_height = float(geom.get("height") or height)
    window_x = global_x - origin_x
    window_y = global_y - origin_y
    screenshot_x = (global_x - left) * sx
    screenshot_y = (global_y - top) * sy
    screenshot_width = float(screenshot.get("width") or width * sx)
    screenshot_height = float(screenshot.get("height") or height * sy)
    return {
        "window": {"x": window_x, "y": window_y, "coordinateSpace": "window"},
        "screenshot": {"x": screenshot_x, "y": screenshot_y, "coordinateSpace": "screenshot"},
        "insideWindow": 0 <= window_x <= window_width and 0 <= window_y <= window_height,
        "insideScreenshot": 0 <= screenshot_x <= screenshot_width and 0 <= screenshot_y <= screenshot_height,
    }


def element_center(element: dict[str, Any]) -> tuple[float, float]:
    frame = element.get("frame")
    if not isinstance(frame, dict):
        raise RuntimeError("element has no frame; use x/y coordinates instead")
    return float(frame.get("x") or 0.0) + float(frame.get("width") or 0.0) / 2.0, float(frame.get("y") or 0.0) + float(frame.get("height") or 0.0) / 2.0


def screenshot_size(snapshot: dict[str, Any]) -> tuple[float, float]:
    screenshot = snapshot.get("screenshot") or {}
    return float(screenshot.get("width") or 0.0), float(screenshot.get("height") or 0.0)


def frame_intersection(frame: dict[str, Any], width: float, height: float) -> dict[str, float] | None:
    x = float(frame.get("x") or 0.0)
    y = float(frame.get("y") or 0.0)
    w = float(frame.get("width") or 0.0)
    h = float(frame.get("height") or 0.0)
    if w <= 0 or h <= 0 or width <= 0 or height <= 0:
        return None
    left = max(0.0, x)
    top = max(0.0, y)
    right = min(width, x + w)
    bottom = min(height, y + h)
    if right <= left or bottom <= top:
        return None
    return {"x": left, "y": top, "width": right - left, "height": bottom - top}


def element_visible_rect(snapshot: dict[str, Any], element: dict[str, Any]) -> dict[str, float] | None:
    frame = element.get("frame")
    if not isinstance(frame, dict):
        return None
    width, height = screenshot_size(snapshot)
    return frame_intersection(frame, width, height)


def element_is_visible(snapshot: dict[str, Any], element: dict[str, Any]) -> bool:
    return element_visible_rect(snapshot, element) is not None


def visible_element_center(snapshot: dict[str, Any], element: dict[str, Any]) -> tuple[float, float]:
    rect = element_visible_rect(snapshot, element)
    if rect is None:
        raise RuntimeError("element is outside the current screenshot; scroll to it or choose a visible element")
    return rect["x"] + rect["width"] / 2.0, rect["y"] + rect["height"] / 2.0


def element_text(element: dict[str, Any]) -> str:
    parts = [
        str(element.get("name") or ""),
        str(element.get("value") or ""),
        str(element.get("automationId") or ""),
    ]
    return " ".join(part for part in parts if part)


def element_role(element: dict[str, Any]) -> str:
    return normalize(element.get("localizedControlType") or element.get("controlType") or "")


def element_matches_text(element: dict[str, Any], needle: str) -> bool:
    return normalize(needle) in normalize(element_text(element))


def find_element_by_text(snapshot: dict[str, Any], text: str, *, role: str | None = None, nth: int = 1, visible_only: bool = True) -> dict[str, Any]:
    matches = []
    role_norm = normalize(role) if role else ""
    for element in snapshot.get("elements") or []:
        if role_norm and element_role(element) != role_norm:
            continue
        if not element_matches_text(element, text):
            continue
        if visible_only and not element_is_visible(snapshot, element):
            continue
        matches.append(dict(element))
    matches.sort(key=lambda item: (float((element_visible_rect(snapshot, item) or {}).get("y") or 0.0), float((element_visible_rect(snapshot, item) or {}).get("x") or 0.0)))
    if nth < 1:
        nth = 1
    if len(matches) < nth:
        raise RuntimeError(f'no visible element matching "{text}"')
    return matches[nth - 1]


def control_overlay(snapshot: dict[str, Any], x: float | None = None, y: float | None = None, *, coordinate_space: Any = "screenshot", action: str = "move") -> dict[str, Any] | None:
    try:
        if x is None or y is None:
            width, height = screenshot_size(snapshot)
            x = width / 2.0
            y = height / 2.0
            coordinate_space = "screenshot"
        global_x, global_y = point_to_global(snapshot, float(x), float(y), coordinate_space)
        return call_ctl(["indicator", "--json", str(snapshot["target"]), str(global_x), str(global_y), str(action or "move")])
    except Exception:
        return None


def action_point(snapshot: dict[str, Any], args: dict[str, Any], *, default_center: bool = False) -> tuple[float, float]:
    element_index = args.get("element_index")
    if isinstance(element_index, str) and element_index:
        return visible_element_center(snapshot, lookup_element(snapshot, element_index))

    name = args.get("name") or args.get("text")
    if isinstance(name, str) and name:
        return visible_element_center(snapshot, find_element_by_text(snapshot, name))

    point = point_from_args(args)
    if point is not None:
        return point

    if default_center:
        screenshot = snapshot.get("screenshot") or {}
        return float(screenshot.get("width") or 0.0) / 2.0, float(screenshot.get("height") or 0.0) / 2.0

    raise RuntimeError("action requires element_index, coordinate, or x/y")


MAX_CURSOR_STATE_BYTES = 1024 * 1024


def screenshot_state_root() -> pathlib.Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = pathlib.Path(runtime).absolute() if runtime else pathlib.Path(tempfile.gettempdir()).absolute()
    try:
        base_info = os.lstat(base)
    except OSError as exc:
        raise RuntimeError(f"screenshot state base is unavailable: {base}: {exc.strerror}") from exc
    if stat.S_ISLNK(base_info.st_mode) or not stat.S_ISDIR(base_info.st_mode):
        raise RuntimeError(f"screenshot state base must be a real directory: {base}")
    if runtime and (base_info.st_uid != os.getuid() or stat.S_IMODE(base_info.st_mode) != 0o700):
        raise RuntimeError(f"XDG_RUNTIME_DIR must be owned by uid {os.getuid()} with mode 0700: {base}")

    root = base / f"hypr-agent-portal-{os.getuid()}"
    try:
        root_info = os.lstat(root)
    except FileNotFoundError:
        return root
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeError(f"hypr-agent-portal state root must be a real directory: {root}")
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700:
        raise RuntimeError(f"hypr-agent-portal state root must be owned by uid {os.getuid()} with mode 0700: {root}")
    return root


def cursor_state_path() -> pathlib.Path:
    return screenshot_state_root() / "cursor.json"


def screenshot_for_window(window: dict[str, Any]) -> tuple[dict[str, Any], str]:
    return consume_screenshot_result(call_ctl([*screenshot_command_base(), "--target", window_selector(window), "--no-cursor"]))


def hyprctl_json(*args: str) -> Any:
    hyprctl = shutil.which("hyprctl")
    if not hyprctl:
        raise RuntimeError("hyprctl is unavailable; a running Hyprland session and hyprctl in PATH are required for this action")
    try:
        proc = subprocess.run(
            [hyprctl, *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=hyprctl_environment(),
            check=False,
            timeout=MAX_TOOL_WAIT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"hyprctl {' '.join(args)} timed out after {MAX_TOOL_WAIT_SECONDS:g}s") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"hyprctl {' '.join(args)} failed").strip())
    return json.loads(proc.stdout or "null")


def hyprland_cursor_position() -> dict[str, float]:
    data = hyprctl_json("cursorpos", "-j")
    return {"x": float(data.get("x") or 0.0), "y": float(data.get("y") or 0.0)}


def agent_cursor_position() -> dict[str, Any] | None:
    root = screenshot_state_root()
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, flags)
    except FileNotFoundError:
        return None
    root_info = os.fstat(root_fd)
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700:
        os.close(root_fd)
        raise RuntimeError("refusing unsafe hypr-agent-portal state root")
    try:
        fd = os.open("cursor.json", os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
    except FileNotFoundError:
        os.close(root_fd)
        return None
    except OSError as exc:
        os.close(root_fd)
        raise RuntimeError(f"refusing unsafe cursor state: {exc.strerror}") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > MAX_CURSOR_STATE_BYTES
        ):
            raise RuntimeError("refusing unsafe cursor state ownership, type, links, permissions, or size")
        chunks = bytearray()
        while len(chunks) <= MAX_CURSOR_STATE_BYTES:
            chunk = os.read(fd, min(65536, MAX_CURSOR_STATE_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > MAX_CURSOR_STATE_BYTES:
            raise RuntimeError("refusing oversized cursor state")
        try:
            data = json.loads(chunks.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
    finally:
        os.close(fd)
        os.close(root_fd)
    x = data.get("x")
    y = data.get("y")
    if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
        return None
    return {
        "x": float(x),
        "y": float(y),
        "target": str(data.get("target") or ""),
        "action": str(data.get("action") or ""),
        "button": str(data.get("button") or ""),
        "timestamp": float(data.get("timestamp") or 0.0),
    }


def monitor_position(global_x: float, global_y: float) -> dict[str, Any] | None:
    monitors = hyprctl_json("monitors", "-j")
    if not isinstance(monitors, list):
        return None
    for monitor in monitors:
        if not isinstance(monitor, dict):
            continue
        x = float(monitor.get("x") or 0.0)
        y = float(monitor.get("y") or 0.0)
        width = float(monitor.get("width") or 0.0)
        height = float(monitor.get("height") or 0.0)
        if x <= global_x < x + width and y <= global_y < y + height:
            return {
                "name": monitor.get("name"),
                "id": monitor.get("id"),
                "x": global_x - x,
                "y": global_y - y,
                "width": width,
                "height": height,
                "scale": monitor.get("scale"),
                "coordinateSpace": "monitor",
            }
    return None


def atspi_init_error() -> str | None:
    global _ATSPI_INIT_ERROR, _ATSPI
    if _ATSPI_INIT_ERROR is not None:
        return _ATSPI_INIT_ERROR if isinstance(_ATSPI_INIT_ERROR, str) else None
    if os.environ.get(ATSPI_CHILD_ENV) != "1":
        _ATSPI_INIT_ERROR = "AT-SPI is isolated to child subprocesses to keep the MCP transport alive after native toolkit crashes."
        return _ATSPI_INIT_ERROR
    try:
        ensure_session_environment()
        import gi  # type: ignore

        gi.require_version("Atspi", "2.0")
        from gi.repository import Atspi  # type: ignore

        Atspi.init()
        _ATSPI = Atspi
        _ATSPI_INIT_ERROR = False
        return None
    except Exception as exc:
        _ATSPI_INIT_ERROR = f"{type(exc).__name__}: {exc}"
        return _ATSPI_INIT_ERROR


def atspi_available() -> bool:
    return atspi_init_error() is None and _ATSPI is not None


def atspi_safe(call: Any, default: Any = None) -> Any:
    try:
        value = call()
        return default if value is None else value
    except Exception:
        return default


def atspi_desktop() -> Any:
    if not atspi_available():
        return None
    return _ATSPI.get_desktop(0)


def atspi_child_count(node: Any) -> int:
    return int(atspi_safe(node.get_child_count, 0) or 0)


def atspi_child_at(node: Any, index: int) -> Any:
    return atspi_safe(lambda: node.get_child_at_index(index))


def atspi_name(node: Any) -> str:
    return str(atspi_safe(node.get_name, "") or "")


def atspi_role(node: Any) -> str:
    return str(atspi_safe(node.get_role_name, "") or "")


def atspi_pid(node: Any) -> int:
    try:
        return int(atspi_safe(node.get_process_id, 0) or 0)
    except Exception:
        return 0


def atspi_state_contains(node: Any, state: Any) -> bool:
    state_set = atspi_safe(node.get_state_set)
    if state_set is None:
        return False
    return bool(atspi_safe(lambda: state_set.contains(state), False))


def atspi_node_is_currently_visible(node: Any, bounds: dict[str, float] | None = None) -> bool:
    if bounds is None and atspi_child_count(node) == 0:
        return False
    if atspi_state_contains(node, _ATSPI.StateType.SHOWING) or atspi_state_contains(node, _ATSPI.StateType.VISIBLE):
        return True
    return bounds is not None


def atspi_extents(node: Any) -> dict[str, float] | None:
    component = atspi_safe(node.get_component_iface)
    if component is None:
        return None
    rect = atspi_safe(lambda: _ATSPI.Component.get_extents(component, _ATSPI.CoordType.SCREEN))
    if rect is None or rect.width <= 0 or rect.height <= 0 or rect.width > 100000 or rect.height > 100000:
        return None
    if abs(float(rect.x)) > 100000 or abs(float(rect.y)) > 100000:
        return None
    return {"x": float(rect.x), "y": float(rect.y), "width": float(rect.width), "height": float(rect.height)}


def rects_overlap(a: dict[str, float], b: dict[str, float], *, margin: float = 0.0) -> bool:
    return (
        a["x"] + a["width"] >= b["x"] - margin
        and b["x"] + b["width"] >= a["x"] - margin
        and a["y"] + a["height"] >= b["y"] - margin
        and b["y"] + b["height"] >= a["y"] - margin
    )


def screenshot_axis_scale(screenshot: dict[str, Any], axis: str) -> float:
    bounds = screenshot.get("logicalBounds") or {}
    logical_extent = float(bounds.get("width" if axis == "x" else "height") or 0.0)
    pixel_extent = float(screenshot.get("width" if axis == "x" else "height") or 0.0)
    if logical_extent > 0 and pixel_extent > 0:
        return pixel_extent / logical_extent
    scale = float(screenshot.get("scale") or 1.0)
    return scale if scale > 0 else 1.0


def atspi_bounds_are_global(atspi_window_bounds: dict[str, float] | None, screenshot: dict[str, Any]) -> bool:
    if atspi_window_bounds is None:
        return True
    screenshot_bounds = screenshot.get("logicalBounds") or {}
    if not all(key in screenshot_bounds for key in ["x", "y", "width", "height"]):
        return True
    if float(screenshot_bounds.get("width") or 0.0) <= 0 or float(screenshot_bounds.get("height") or 0.0) <= 0:
        return True
    screenshot_rect = {key: float(screenshot_bounds.get(key) or 0.0) for key in ["x", "y", "width", "height"]}
    return rects_overlap(atspi_window_bounds, screenshot_rect, margin=8.0)


def atspi_bounds_to_screenshot_frame(
    bounds: dict[str, float],
    atspi_window_bounds: dict[str, float] | None,
    screenshot: dict[str, Any],
    hypr_window: dict[str, Any],
) -> dict[str, float]:
    screenshot_bounds = screenshot.get("logicalBounds") or {}
    screenshot_x = float(screenshot_bounds.get("x") or 0.0)
    screenshot_y = float(screenshot_bounds.get("y") or 0.0)
    sx = screenshot_axis_scale(screenshot, "x")
    sy = screenshot_axis_scale(screenshot, "y")

    if atspi_bounds_are_global(atspi_window_bounds, screenshot):
        logical_x = bounds["x"]
        logical_y = bounds["y"]
    else:
        geom = window_geometry(hypr_window)
        root_x = float((atspi_window_bounds or {}).get("x") or 0.0)
        root_y = float((atspi_window_bounds or {}).get("y") or 0.0)
        logical_x = geom["x"] + bounds["x"] - root_x
        logical_y = geom["y"] + bounds["y"] - root_y

    return {
        "x": (logical_x - screenshot_x) * sx,
        "y": (logical_y - screenshot_y) * sy,
        "width": bounds["width"] * sx,
        "height": bounds["height"] * sy,
    }


def atspi_iter_apps() -> list[Any]:
    root = atspi_desktop()
    if root is None:
        return []
    apps = []
    for index in range(atspi_child_count(root)):
        app = atspi_child_at(root, index)
        if app is not None and atspi_name(app):
            apps.append(app)
    return apps


def atspi_app_windows(app: Any) -> list[tuple[int, Any]]:
    windows = []
    for index in range(atspi_child_count(app)):
        child = atspi_child_at(app, index)
        if child is None:
            continue
        role = atspi_role(child).lower()
        bounds = atspi_extents(child)
        if role in {"frame", "window", "dialog", "alert", "filler"} or bounds is not None:
            windows.append((index, child))
    return windows


def atspi_match_window(app: Any, hypr_window: dict[str, Any]) -> tuple[int, Any] | None:
    windows = atspi_app_windows(app)
    if not windows:
        return None
    title = normalize(hypr_window.get("title"))
    for index, node in windows:
        if title and title in normalize(atspi_name(node)):
            return index, node
    for index, node in windows:
        if atspi_state_contains(node, _ATSPI.StateType.ACTIVE):
            return index, node
    for index, node in windows:
        if atspi_state_contains(node, _ATSPI.StateType.SHOWING):
            return index, node
    return windows[0]


def atspi_rect_identity_matches(actual: dict[str, float] | None, expected: Any, *, tolerance: float = 2.0) -> bool:
    """Compare captured AT-SPI root geometry without accepting another window."""
    if actual is None or not isinstance(expected, dict):
        return False
    for key in ("x", "y", "width", "height"):
        try:
            if abs(float(actual[key]) - float(expected[key])) > tolerance:
                return False
        except (KeyError, TypeError, ValueError):
            return False
    return float(actual.get("width") or 0.0) > 0 and float(actual.get("height") or 0.0) > 0


def atspi_root_identity(index: int, node: Any) -> dict[str, Any]:
    """Stable-enough identity captured for a single top-level AT-SPI root."""
    return {
        "windowIndex": int(index),
        "title": atspi_name(node),
        "role": atspi_role(node),
        "accessibleId": atspi_accessible_id(node),
        "bounds": atspi_extents(node),
    }


def atspi_resolve_window_for_mutation(hypr_window: dict[str, Any]) -> tuple[Any, int, Any] | None:
    """Fail-closed AT-SPI resolver used only by mutation subprocesses.

    Unlike the observation resolver, this never falls back by class/app name,
    ACTIVE/SHOWING state, or first window.  The process lifetime and the exact
    captured top-level root must still match immediately before mutation.
    """
    if not atspi_available():
        return None
    try:
        pid = int(hypr_window.get("pid") or 0)
    except (TypeError, ValueError):
        return None
    expected_start = str(hypr_window.get("processStartTime") or "")
    root_identity = hypr_window.get("atspiRootIdentity")
    title = normalize(hypr_window.get("title"))
    if pid <= 0 or not expected_start or not title or not isinstance(root_identity, dict):
        return None
    if process_start_time(pid) != expected_start:
        return None
    try:
        expected_index = int(root_identity["windowIndex"])
    except (KeyError, TypeError, ValueError):
        return None
    expected_root_title = normalize(root_identity.get("title"))
    expected_role = normalize(root_identity.get("role"))
    expected_accessible_id = str(root_identity.get("accessibleId") or "")
    if not expected_root_title or expected_root_title != title:
        return None

    matching_apps = [app for app in atspi_iter_apps() if atspi_pid(app) == pid]
    if len(matching_apps) != 1:
        return None
    app = matching_apps[0]
    candidates = [(index, node) for index, node in atspi_app_windows(app) if index == expected_index]
    if len(candidates) != 1:
        return None
    index, node = candidates[0]
    if normalize(atspi_name(node)) != expected_root_title:
        return None
    if expected_role and normalize(atspi_role(node)) != expected_role:
        return None
    if expected_accessible_id and atspi_accessible_id(node) != expected_accessible_id:
        return None
    if not atspi_rect_identity_matches(atspi_extents(node), root_identity.get("bounds")):
        return None
    return app, index, node


def atspi_resolve_window(hypr_window: dict[str, Any]) -> tuple[Any, int, Any] | None:
    if not atspi_available():
        return None
    pid = int(hypr_window.get("pid") or 0)
    title = normalize(hypr_window.get("title"))
    klass = normalize(hypr_window.get("class"))
    for app in atspi_iter_apps():
        if pid and atspi_pid(app) == pid:
            matched = atspi_match_window(app, hypr_window)
            if matched:
                return app, matched[0], matched[1]
    for app in atspi_iter_apps():
        name = normalize(atspi_name(app))
        if (klass and (klass == name or klass in name or name in klass)) or (title and title in name):
            matched = atspi_match_window(app, hypr_window)
            if matched:
                return app, matched[0], matched[1]
    return None


def atspi_action_names(node: Any) -> list[str]:
    names = []
    count = int(atspi_safe(node.get_n_actions, 0) or 0)
    for index in range(count):
        name = str(atspi_safe(lambda i=index: node.get_action_name(i), "") or "")
        description = str(atspi_safe(lambda i=index: node.get_action_description(i), "") or "")
        label = name or description
        if label and label not in names:
            names.append(label)
    return names


def atspi_accessible_id(node: Any) -> str:
    return str(atspi_safe(node.get_accessible_id, "") or "")


def atspi_text_value(node: Any) -> str:
    if not bool(atspi_safe(node.is_text, False)):
        return ""
    text_iface = atspi_safe(node.get_text_iface)
    if text_iface is None:
        return ""
    count = int(atspi_safe(lambda: _ATSPI.Text.get_character_count(text_iface), 0) or 0)
    if count <= 0:
        return ""
    value = str(atspi_safe(lambda: _ATSPI.Text.get_text(text_iface, 0, min(count, 500)), "") or "")
    return value + "..." if count > 500 else value


def atspi_numeric_value(node: Any) -> str:
    value_iface = atspi_safe(node.get_value_iface)
    if value_iface is None:
        return ""
    current = atspi_safe(lambda: _ATSPI.Value.get_current_value(value_iface))
    return "" if current is None else str(current)


def atspi_image_frame(
    node: Any,
    bounds: dict[str, float] | None,
    atspi_window_bounds: dict[str, float] | None,
    screenshot: dict[str, Any],
    hypr_window: dict[str, Any],
) -> dict[str, float] | None:
    if bounds is None:
        return None
    if atspi_window_bounds is None:
        return bounds
    return atspi_bounds_to_screenshot_frame(bounds, atspi_window_bounds, screenshot, hypr_window)


def corrected_large_grid_cell_bounds(
    cell_bounds: dict[str, float],
    table_bounds: dict[str, float],
    *,
    row: int,
    col: int,
    large_grid: bool,
    header_y_offset: float | None,
) -> tuple[dict[str, float], float | None]:
    if large_grid and header_y_offset is None and row == 0 and col == 0:
        same_origin_y = abs(float(cell_bounds.get("y") or 0.0) - float(table_bounds.get("y") or 0.0)) <= 1.0
        header_y_offset = float(cell_bounds.get("height") or 0.0) if same_origin_y else 0.0
    if header_y_offset:
        corrected = dict(cell_bounds)
        corrected["y"] = float(corrected["y"]) + header_y_offset
        return corrected, header_y_offset
    return cell_bounds, header_y_offset


def atspi_record_for(
    node: Any,
    index: int,
    path: list[int],
    bounds: dict[str, float] | None,
    atspi_window_bounds: dict[str, float] | None,
    screenshot: dict[str, Any],
    hypr_window: dict[str, Any],
) -> dict[str, Any]:
    role = atspi_role(node)
    return {
        "index": index,
        "runtimeId": path[:],
        "automationId": atspi_accessible_id(node),
        "name": atspi_name(node),
        "controlType": role,
        "localizedControlType": role,
        "className": str(atspi_safe(node.get_toolkit_name, "") or ""),
        "value": atspi_text_value(node) or atspi_numeric_value(node),
        "nativeWindowHandle": 0,
        "frame": atspi_image_frame(node, bounds, atspi_window_bounds, screenshot, hypr_window),
        "actions": atspi_action_names(node),
        "focused": atspi_state_contains(node, _ATSPI.StateType.FOCUSED),
        "editable": bool(atspi_safe(node.is_editable_text, False)) and bool(atspi_safe(node.is_text, False)),
        "source": "atspi",
    }


def atspi_render_tree(root: Any, root_path: list[int], screenshot: dict[str, Any], hypr_window: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], dict[str, float] | None, str]:
    records: list[dict[str, Any]] = []
    lines: list[str] = []
    atspi_window_bounds = atspi_extents(root)
    deadline = time.monotonic() + 4.5
    truncated_reason = ""

    def mark_truncated(reason: str) -> None:
        nonlocal truncated_reason
        if not truncated_reason:
            truncated_reason = reason

    def budget_exhausted() -> bool:
        if len(records) >= 500:
            mark_truncated("record-limit")
            return True
        if time.monotonic() >= deadline:
            mark_truncated("time-limit")
            return True
        return False

    def visit(node: Any, depth: int, path: list[int], bounds_hint: dict[str, float] | None = None) -> None:
        if node is None or len(records) >= 500 or depth > 64:
            if len(records) >= 500:
                mark_truncated("record-limit")
            return
        if budget_exhausted():
            return
        bounds = bounds_hint if bounds_hint is not None else atspi_extents(node)
        if depth > 0 and not atspi_node_is_currently_visible(node, bounds):
            return
        index = len(records)
        record = atspi_record_for(node, index, path, bounds, atspi_window_bounds, screenshot, hypr_window)
        records.append(record)

        role = record["localizedControlType"] or record["controlType"] or "element"
        title = record["name"] or record["automationId"] or ""
        value_segment = ""
        if record["value"] and record["value"] != title:
            safe_value = str(record["value"]).replace("\r", "\\r").replace("\n", "\\n")
            value_segment = " Value: " + safe_value
        actions_segment = " Secondary Actions: " + ", ".join(record["actions"]) if record["actions"] else ""
        frame_segment = ""
        if isinstance(record["frame"], dict):
            frame = record["frame"]
            frame_segment = " Frame: {{x: {0}, y: {1}, width: {2}, height: {3}}}".format(
                round(frame["x"]), round(frame["y"]), round(frame["width"]), round(frame["height"])
            )
        lines.append(("\t" * (depth + 1)) + f"{index} {role} {title}{value_segment}{actions_segment}{frame_segment}".rstrip())

        if visit_table_cells(node, depth, path, bounds):
            return

        child_count = min(atspi_child_count(node), 512)
        for child_index in range(child_count):
            if budget_exhausted():
                return
            visit(atspi_child_at(node, child_index), depth + 1, path + [child_index])

    def visit_table_cells(node: Any, depth: int, path: list[int], table_bounds: dict[str, float] | None) -> bool:
        if table_bounds is None or not bool(atspi_safe(node.is_table, False)):
            return False
        table_iface = atspi_safe(node.get_table_iface)
        if table_iface is None:
            return False

        total_rows = int(atspi_safe(lambda: _ATSPI.Table.get_n_rows(table_iface), 0) or 0)
        total_cols = int(atspi_safe(lambda: _ATSPI.Table.get_n_columns(table_iface), 0) or 0)
        max_rows = min(total_rows, 200)
        max_cols = min(total_cols, 200)
        large_grid = total_rows > 1000 or total_cols > 100
        header_y_offset: float | None = None
        empty_rows = 0
        for row in range(max_rows):
            if budget_exhausted():
                return True
            row_visible = False
            empty_cols = 0
            for col in range(max_cols):
                if budget_exhausted():
                    return True
                cell = atspi_safe(lambda r=row, c=col: _ATSPI.Table.get_accessible_at(table_iface, r, c))
                if cell is None:
                    empty_cols += 1
                    if col > 0 and empty_cols >= 3:
                        break
                    continue
                cell_bounds = atspi_extents(cell)
                if cell_bounds is None or not rects_overlap(cell_bounds, table_bounds, margin=1.0):
                    empty_cols += 1
                    if col > 0 and empty_cols >= 3:
                        break
                    continue
                cell_bounds, header_y_offset = corrected_large_grid_cell_bounds(
                    cell_bounds,
                    table_bounds,
                    row=row,
                    col=col,
                    large_grid=large_grid,
                    header_y_offset=header_y_offset,
                )
                row_visible = True
                empty_cols = 0
                child_index = atspi_safe(lambda r=row, c=col: _ATSPI.Table.get_index_at(table_iface, r, c))
                if isinstance(child_index, int) and child_index >= 0:
                    child_path = path + [child_index]
                else:
                    child_path = path + [row, col]
                visit(cell, depth + 1, child_path, cell_bounds)
            if row_visible:
                empty_rows = 0
            else:
                empty_rows += 1
                if row > 0 and empty_rows >= 2:
                    break
        return True

    visit(root, 0, root_path)
    return records, lines, atspi_window_bounds, truncated_reason


def atspi_resolve_path(app: Any, path: list[Any]) -> Any:
    node = app
    for index in path:
        node = atspi_child_at(node, int(index))
        if node is None:
            return None
    return node


def atspi_resolve_path_in_root(window_node: Any, root_index: int, path: list[Any]) -> Any:
    """Resolve a captured runtimeId without allowing it to escape its root."""
    if not path:
        return None
    try:
        if int(path[0]) != int(root_index):
            return None
    except (TypeError, ValueError):
        return None
    node = window_node
    for index in path[1:]:
        try:
            node = atspi_child_at(node, int(index))
        except (TypeError, ValueError):
            return None
        if node is None:
            return None
    return node


def atspi_node_for_element(snapshot: dict[str, Any], element: dict[str, Any]) -> Any:
    window = snapshot.get("window") or {}
    resolved = atspi_resolve_window(window)
    if not resolved:
        return None
    app, _, _ = resolved
    path = element.get("runtimeId")
    if not isinstance(path, list):
        return None
    return atspi_resolve_path(app, path)


def atspi_preferred_action_index(node: Any) -> int | None:
    preferred = {"click", "press", "activate", "default.activate", "invoke", "select", "toggle", "open", "jump"}
    count = int(atspi_safe(node.get_n_actions, 0) or 0)
    fallback = None
    for index in range(count):
        name = str(atspi_safe(lambda i=index: node.get_action_name(i), "") or "")
        description = str(atspi_safe(lambda i=index: node.get_action_description(i), "") or "")
        lower = (name or description).lower()
        if lower in preferred:
            return index
        if fallback is None and ("activate" in lower or "click" in lower or "press" in lower):
            fallback = index
    return fallback


def atspi_do_action(node: Any, action_name: str | None = None) -> bool:
    if node is None:
        return False
    if action_name is None:
        index = atspi_preferred_action_index(node)
        return bool(index is not None and atspi_safe(lambda: node.do_action(index), False))
    normalized = action_name.lower()
    count = int(atspi_safe(node.get_n_actions, 0) or 0)
    for index in range(count):
        name = str(atspi_safe(lambda i=index: node.get_action_name(i), "") or "")
        description = str(atspi_safe(lambda i=index: node.get_action_description(i), "") or "")
        if normalized in {name.lower(), description.lower()}:
            return bool(atspi_safe(lambda: node.do_action(index), False))
    return False


def atspi_find_first(root: Any, predicate: Any) -> Any:
    if root is None:
        return None
    if predicate(root):
        return root
    for index in range(atspi_child_count(root)):
        found = atspi_find_first(atspi_child_at(root, index), predicate)
        if found is not None:
            return found
    return None


def atspi_insert_text(snapshot: dict[str, Any], text: str, *, focused_only: bool = False) -> bool:
    resolved = atspi_resolve_window(snapshot.get("window") or {})
    if not resolved:
        return False
    _, _, window_node = resolved

    return atspi_insert_text_in_window(window_node, text, focused_only=focused_only)


def atspi_node_is_editable(node: Any, *, focused_only: bool = False) -> bool:
    if node is None or not bool(atspi_safe(node.is_editable_text, False)) or not bool(atspi_safe(node.is_text, False)):
        return False
    return not focused_only or atspi_state_contains(node, _ATSPI.StateType.FOCUSED)


def atspi_insert_text_at_node(node: Any, text: str, *, focused_only: bool = False) -> bool:
    if not atspi_node_is_editable(node, focused_only=focused_only):
        return False
    editable_iface = atspi_safe(node.get_editable_text_iface)
    text_iface = atspi_safe(node.get_text_iface)
    if editable_iface is None or text_iface is None:
        return False
    character_count = int(atspi_safe(lambda: _ATSPI.Text.get_character_count(text_iface), 0) or 0)
    offset = int(atspi_safe(lambda: _ATSPI.Text.get_caret_offset(text_iface), character_count))
    if offset < 0 or offset > character_count:
        offset = character_count
    return bool(atspi_safe(lambda: _ATSPI.EditableText.insert_text(editable_iface, offset, text, len(text)), False))


def atspi_insert_text_in_window(
    window_node: Any,
    text: str,
    *,
    focused_only: bool = False,
    runtime_id: list[Any] | None = None,
    root_index: int | None = None,
) -> bool:
    if runtime_id is not None:
        if root_index is None:
            return False
        node = atspi_resolve_path_in_root(window_node, root_index, runtime_id)
    else:
        node = atspi_find_first(window_node, lambda candidate: atspi_node_is_editable(candidate, focused_only=focused_only))
    return atspi_insert_text_at_node(node, text, focused_only=focused_only)


def atspi_set_node_value(node: Any, value: str) -> bool:
    if node is None:
        return False
    if bool(atspi_safe(node.is_editable_text, False)):
        editable_iface = atspi_safe(node.get_editable_text_iface)
        if editable_iface is not None and bool(atspi_safe(lambda: _ATSPI.EditableText.set_text_contents(editable_iface, value), False)):
            return True
    value_iface = atspi_safe(node.get_value_iface)
    if value_iface is not None:
        try:
            return bool(_ATSPI.Value.set_current_value(value_iface, float(value)))
        except Exception:
            return False
    return False


def atspi_set_element_value(snapshot: dict[str, Any], element: dict[str, Any], value: str) -> bool:
    node = atspi_node_for_element(snapshot, element)
    return atspi_set_node_value(node, value)


def atspi_snapshot(window: dict[str, Any], screenshot: dict[str, Any]) -> dict[str, Any]:
    init_error = atspi_init_error()
    if init_error is not None:
        return {"status": "unavailable", "error": init_error, "elements": [], "treeLines": [], "windowBounds": None}
    resolved = atspi_resolve_window(window)
    if not resolved:
        return {"status": "not-found", "error": "No matching AT-SPI app/window for this Hyprland client.", "elements": [], "treeLines": [], "windowBounds": None}
    app, window_index, window_node = resolved
    elements, tree_lines, bounds, truncated_reason = atspi_render_tree(window_node, [window_index], screenshot, window)
    return {
        "status": "ok",
        "resolutionMode": "observation-compatible",
        "appName": atspi_name(app),
        "appPid": atspi_pid(app),
        "windowTitle": atspi_name(window_node),
        "rootIdentity": atspi_root_identity(window_index, window_node),
        "windowBounds": bounds,
        "treeTruncated": bool(truncated_reason),
        "treeTruncatedReason": truncated_reason,
        "elements": elements,
        "treeLines": tree_lines,
    }


def atspi_empty_snapshot(status: str, error_message: str) -> dict[str, Any]:
    return {"status": status, "error": error_message, "elements": [], "treeLines": [], "windowBounds": None}


def trim_process_output(value: str, limit: int = 1200) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def atspi_child_env() -> dict[str, str]:
    env = session_environment()
    env[ATSPI_CHILD_ENV] = "1"
    return env


def run_atspi_child(mode: str, payload: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any]:
    if mode not in ATSPI_CHILD_MODES:
        return {"status": "error", "error": f"unknown AT-SPI child mode: {mode}", "ok": False}
    try:
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve()), mode],
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=atspi_child_env(),
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stderr = trim_process_output(exc.stderr or "") if isinstance(exc.stderr, str) else ""
        detail = f"AT-SPI child timed out after {timeout:g}s"
        if stderr:
            detail = f"{detail}: {stderr}"
        return {"status": "timeout", "error": detail, "ok": False}

    stdout = proc.stdout.strip()
    if proc.returncode != 0:
        if proc.returncode < 0:
            status = "crashed"
            detail = f"AT-SPI child exited from signal {-proc.returncode}"
        else:
            status = "error"
            detail = f"AT-SPI child exited with status {proc.returncode}"
        stderr = trim_process_output(proc.stderr or "")
        if stderr:
            detail = f"{detail}: {stderr}"
        return {"status": status, "error": detail, "ok": False}

    try:
        result = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        detail = f"AT-SPI child returned invalid JSON: {exc}"
        stderr = trim_process_output(proc.stderr or "")
        if stderr:
            detail = f"{detail}: {stderr}"
        return {"status": "error", "error": detail, "ok": False}
    return result if isinstance(result, dict) else {"status": "error", "error": "AT-SPI child returned a non-object result.", "ok": False}


def atspi_snapshot_isolated(window: dict[str, Any], screenshot: dict[str, Any]) -> dict[str, Any]:
    result = run_atspi_child("--atspi-snapshot", {"window": window, "screenshot": screenshot}, timeout=6.0)
    if result.get("status") == "ok" and isinstance(result.get("elements"), list) and isinstance(result.get("treeLines"), list):
        return result
    status = str(result.get("status") or "error")
    error_message = str(result.get("error") or "AT-SPI child failed")
    return atspi_empty_snapshot(status, error_message)


def atspi_child_probe() -> dict[str, Any]:
    result = run_atspi_child("--atspi-probe", {}, timeout=3.0)
    if isinstance(result.get("available"), bool):
        return result
    return {"available": False, "mode": "isolated-child", "status": result.get("status", "error"), "error": str(result.get("error") or "AT-SPI child probe failed")}


def require_atspi_mutation_identity(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Revalidate the full Hypr/AT-SPI binding before launching a mutator."""
    window = snapshot.get("window")
    if not isinstance(window, dict):
        raise RuntimeError("AT-SPI mutation denied: captured Hyprland window identity is missing")
    address = normalize(window.get("address"))
    try:
        pid = int(window.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    starttime = str(window.get("processStartTime") or snapshot.get("windowStartTime") or "")
    title = str(window.get("title") or "")
    root_identity = window.get("atspiRootIdentity")
    if not address or pid <= 0 or not starttime or not title or not isinstance(root_identity, dict):
        raise RuntimeError("AT-SPI mutation denied: incomplete pid/starttime/root/title binding")
    try:
        selector = qualify_address(address, pid, starttime)
        live = resolve_hypr_window(selector)
    except Exception as exc:
        raise RuntimeError(f"AT-SPI mutation denied: captured process/window disappeared or changed: {exc}") from exc
    live_start = process_start_time(live.get("pid"))
    expected_fields = {
        "address": address,
        "pid": pid,
        "starttime": starttime,
        "class": normalize(window.get("class")),
        "initialClass": normalize(window.get("initialClass")),
        "title": normalize(title),
        "initialTitle": normalize(window.get("initialTitle")),
    }
    actual_fields = {
        "address": normalize(live.get("address")),
        "pid": int(live.get("pid") or 0),
        "starttime": live_start,
        "class": normalize(live.get("class")),
        "initialClass": normalize(live.get("initialClass")),
        "title": normalize(live.get("title")),
        "initialTitle": normalize(live.get("initialTitle")),
    }
    if actual_fields != expected_fields:
        raise RuntimeError("AT-SPI mutation denied: captured Hyprland window identity changed")
    if not atspi_rect_identity_matches(window_geometry(live), window_geometry(window), tolerance=1.0):
        raise RuntimeError("AT-SPI mutation denied: captured Hyprland window geometry changed")
    if normalize(root_identity.get("title")) != expected_fields["title"]:
        raise RuntimeError("AT-SPI mutation denied: captured AT-SPI root does not match Hyprland title")
    return window


def atspi_child_action(operation: str, window: dict[str, Any], *, runtime_id: Any = None, action: str | None = None, text: str | None = None, value: str | None = None) -> dict[str, Any]:
    payload = {"operation": operation, "window": window}
    if runtime_id is not None:
        payload["runtimeId"] = runtime_id
    if action is not None:
        payload["action"] = action
    if text is not None:
        payload["text"] = text
    if value is not None:
        payload["value"] = value
    result = run_atspi_child("--atspi-action", payload, timeout=4.0)
    if isinstance(result.get("ok"), bool):
        return result
    return {"ok": False, "status": result.get("status", "error"), "error": str(result.get("error") or "AT-SPI action child failed")}


def atspi_do_action_isolated(snapshot: dict[str, Any], element: dict[str, Any], action_name: str | None = None) -> bool:
    window = require_atspi_mutation_identity(snapshot)
    result = atspi_child_action("do_action", window, runtime_id=element.get("runtimeId"), action=action_name)
    return bool(result.get("ok"))


def element_has_primary_atspi_action(element: dict[str, Any]) -> bool:
    if element.get("source") != "atspi":
        return False
    actions = element.get("actions")
    if not isinstance(actions, list):
        return False
    preferred = {"click", "press", "activate", "default.activate", "invoke", "select", "toggle", "open", "jump"}
    for action in actions:
        if str(action).lower() in preferred:
            return True
    return False


def element_is_menu_item(element: dict[str, Any]) -> bool:
    role = normalize(element.get("controlType") or element.get("localizedControlType") or "")
    return "menu item" in role or role in {"menuitem", "check menu item", "radio menu item"}


def element_click_mode(args: dict[str, Any]) -> str:
    raw = args.get("element_click_mode")
    if raw is None:
        raw = os.environ.get(ELEMENT_CLICK_MODE_ENV, "pointer")
    mode = normalize(raw).replace("_", "-")
    aliases = {
        "native": "pointer",
        "coordinate": "pointer",
        "coordinates": "pointer",
        "coords": "pointer",
        "pointer-first": "pointer",
        "atspi-first": "auto",
        "semantic": "atspi",
    }
    mode = aliases.get(mode, mode)
    if mode not in {"pointer", "auto", "atspi"}:
        return "pointer"
    return mode


def element_atspi_actions(element: dict[str, Any]) -> set[str]:
    if element.get("source") != "atspi":
        return set()
    actions = element.get("actions")
    if not isinstance(actions, list):
        return set()
    return {str(action).lower() for action in actions}


def scroll_action_for_direction(direction: str) -> str:
    normalized = direction.lower()
    if normalized == "down":
        return "scrollDown"
    if normalized == "up":
        return "scrollUp"
    if normalized == "left":
        return "scrollLeft"
    if normalized == "right":
        return "scrollRight"
    raise RuntimeError(f"Invalid scroll direction: {direction}")


def element_supports_scroll_direction(element: dict[str, Any], direction: str) -> bool:
    return scroll_action_for_direction(direction).lower() in element_atspi_actions(element)


def best_scroll_element(snapshot: dict[str, Any], direction: str) -> dict[str, Any] | None:
    candidates = []
    for element in snapshot.get("elements") or []:
        if not isinstance(element, dict) or not element_supports_scroll_direction(element, direction):
            continue
        rect = element_visible_rect(snapshot, element)
        if rect is None:
            continue
        role = element_role(element)
        area = rect["width"] * rect["height"]
        priority = 0
        if "document" in role:
            priority += 1000
        if "web" in role:
            priority += 100
        candidates.append((priority, area, element))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def element_hint_record(element: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {
        "index": element.get("index"),
        "name": str(element.get("name") or ""),
        "controlType": str(element.get("controlType") or element.get("localizedControlType") or ""),
    }
    frame = element.get("frame")
    if isinstance(frame, dict):
        record["frame"] = frame
    actions = element.get("actions")
    if isinstance(actions, list) and actions:
        record["actions"] = [str(action) for action in actions[:8]]
    return record


def element_role_is_tab_like(role: str) -> bool:
    if role in {"tab", "page tab", "tab list", "page tab list"}:
        return True
    words = set(role.replace("-", " ").split())
    return "tab" in words and "table" not in words


def element_role_is_actionable(role: str) -> bool:
    if role in {"push button", "button", "toggle button", "menu item", "check menu item", "radio menu item"}:
        return True
    return "button" in role or role.endswith("menu item")


def text_is_bulk_paste_candidate(text: str) -> bool:
    return "\n" in text or "\t" in text or len(text) > 80


def snapshot_has_grid_target(snapshot: dict[str, Any]) -> bool:
    for element in snapshot.get("elements") or []:
        if not isinstance(element, dict):
            continue
        role = element_role(element)
        if role in {"table", "table cell", "spreadsheet"} or "spreadsheet" in role:
            return True
    return False


def prepare_grid_bulk_paste(snapshot: dict[str, Any], text: str) -> dict[str, Any] | None:
    if not text_is_bulk_paste_candidate(text) or not snapshot_has_grid_target(snapshot):
        return None
    target = str(snapshot.get("target") or "")
    if not target:
        return None
    # In grids/spreadsheets, Ctrl+V while a cell is being edited inserts all
    # lines into that one cell. Escape returns to cell-selection mode first.
    info = keyboard(target, "escape", "")
    time.sleep(0.08)
    return info


def ui_hints_for_elements(snapshot: dict[str, Any], elements: list[dict[str, Any]]) -> dict[str, Any]:
    hints: dict[str, Any] = {
        "notes": [
            "AT-SPI roles are toolkit descriptions, not visual intent. A controlType of menu can be a classic menu, an app command label, or a ribbon/notebookbar page selector depending on the toolkit.",
            "When the requested action is to switch a tab/ribbon/page, prefer visible elements whose controlType contains tab/page tab or toolbar controls exposed after that tab. If no tab element is exposed, use screenshot/window-relative coordinates on the visible tab label, then refresh get_app_state.",
        ],
        "visibleMenus": [],
        "visibleTabs": [],
        "visibleToolbars": [],
        "visibleActions": [],
    }
    for element in elements:
        if not isinstance(element, dict) or not element_is_visible(snapshot, element):
            continue
        role = element_role(element)
        if role == "menu":
            hints["visibleMenus"].append(element_hint_record(element))
        elif element_role_is_tab_like(role):
            hints["visibleTabs"].append(element_hint_record(element))
        elif role in {"tool bar", "toolbar"} or "tool bar" in role or "toolbar" in role:
            hints["visibleToolbars"].append(element_hint_record(element))
        elif element_role_is_actionable(role) and (element.get("name") or element.get("value") or element.get("automationId")):
            hints["visibleActions"].append(element_hint_record(element))
    for key in ("visibleMenus", "visibleTabs", "visibleToolbars", "visibleActions"):
        if len(hints[key]) > 24:
            hints[key] = hints[key][:24]
            hints[f"{key}Truncated"] = True
    has_form_control = any(
        element_role(element) in {"radio button", "check box", "combo box", "text", "entry", "spin button", "slider", "table cell", "list item", "tree item"}
        for element in elements
        if isinstance(element, dict)
    )
    has_confirm_action = any(
        normalize(element.get("name") or element.get("value") or "") in {"ok", "apply", "confirm", "finish", "submit", "确定", "应用", "确认", "完成", "提交"}
        for element in elements
        if isinstance(element, dict) and element_role_is_actionable(element_role(element))
    )
    if has_form_control and has_confirm_action:
        hints["notes"].append(
            "Before activating a confirm/apply/submit/finish button, refresh or inspect the current app state and verify the visible form values/selections match the requested result."
        )
    return hints


def atspi_insert_text_isolated(snapshot: dict[str, Any], text: str, *, runtime_id: Any = None) -> bool:
    window = require_atspi_mutation_identity(snapshot)
    result = atspi_child_action("insert_text", window, runtime_id=runtime_id, text=text)
    return bool(result.get("ok"))


def atspi_insert_focused_text_isolated(snapshot: dict[str, Any], text: str) -> bool:
    window = require_atspi_mutation_identity(snapshot)
    result = atspi_child_action("insert_focused_text", window, text=text)
    return bool(result.get("ok"))


def atspi_set_element_value_isolated(snapshot: dict[str, Any], element: dict[str, Any], value: str) -> bool:
    window = require_atspi_mutation_identity(snapshot)
    result = atspi_child_action("set_value", window, runtime_id=element.get("runtimeId"), value=value)
    return bool(result.get("ok"))


def atspi_child_probe_payload() -> dict[str, Any]:
    init_error = atspi_init_error()
    if init_error is not None:
        return {"available": False, "mode": "isolated-child", "status": "unavailable", "error": init_error}
    desktop = atspi_desktop()
    if desktop is None:
        return {"available": False, "mode": "isolated-child", "status": "unavailable", "error": "AT-SPI desktop is unavailable."}
    return {"available": True, "mode": "isolated-child", "status": "ok", "desktopChildren": atspi_child_count(desktop)}


def atspi_child_action_payload(payload: dict[str, Any]) -> dict[str, Any]:
    init_error = atspi_init_error()
    if init_error is not None:
        return {"ok": False, "status": "unavailable", "error": init_error}
    window = payload.get("window") if isinstance(payload.get("window"), dict) else {}
    operation = str(payload.get("operation") or "")
    resolved = atspi_resolve_window_for_mutation(window)
    if not resolved:
        return {
            "ok": False,
            "status": "identity-mismatch",
            "error": "AT-SPI mutation denied: pid/starttime or captured root identity no longer matches.",
        }
    app, root_index, window_node = resolved
    if operation in {"insert_text", "insert_focused_text"}:
        text = payload.get("text")
        if not isinstance(text, str):
            return {"ok": False, "status": "error", "error": "insert_text requires text"}
        runtime_id = payload.get("runtimeId")
        if runtime_id is not None and not isinstance(runtime_id, list):
            return {"ok": False, "status": "error", "error": "insert_text runtimeId must be a list"}
        return {
            "ok": atspi_insert_text_in_window(
                window_node,
                text,
                focused_only=operation == "insert_focused_text",
                runtime_id=runtime_id,
                root_index=root_index,
            ),
            "status": "ok",
        }

    runtime_id = payload.get("runtimeId")
    if not isinstance(runtime_id, list):
        return {"ok": False, "status": "error", "error": "AT-SPI action requires runtimeId"}
    node = atspi_resolve_path_in_root(window_node, root_index, runtime_id)
    if node is None:
        return {"ok": False, "status": "not-found", "error": "AT-SPI runtimeId no longer resolves."}

    if operation == "do_action":
        action = payload.get("action")
        return {"ok": atspi_do_action(node, action if isinstance(action, str) and action else None), "status": "ok"}
    if operation == "set_value":
        value = payload.get("value")
        if not isinstance(value, str):
            return {"ok": False, "status": "error", "error": "set_value requires value"}
        return {"ok": atspi_set_node_value(node, value), "status": "ok"}
    return {"ok": False, "status": "error", "error": f"unknown AT-SPI operation: {operation}"}


def atspi_child_main(mode: str) -> int:
    os.environ[ATSPI_CHILD_ENV] = "1"
    ensure_session_environment()
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            payload = {}
        if mode == "--atspi-probe":
            result = atspi_child_probe_payload()
        elif mode == "--atspi-snapshot":
            window = payload.get("window") if isinstance(payload.get("window"), dict) else {}
            screenshot = payload.get("screenshot") if isinstance(payload.get("screenshot"), dict) else {}
            result = atspi_snapshot(window, screenshot)
        elif mode == "--atspi-action":
            result = atspi_child_action_payload(payload)
        else:
            result = {"status": "error", "error": f"unknown AT-SPI child mode: {mode}", "ok": False}
    except Exception as exc:
        result = {"status": "error", "error": f"{type(exc).__name__}: {exc}", "ok": False}
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0


def clipboard_snapshot_text() -> dict[str, Any]:
    snapshot: dict[str, Any] = {"wayland": None, "x11": None, "attempted": ["wayland", "x11"]}

    ok, data = run_capture("wl-paste", ["--no-newline", "--type", "text/plain;charset=utf-8"])
    if ok:
        snapshot["wayland"] = {"mime": "text/plain;charset=utf-8", "data": data}
    else:
        ok, data = run_capture("wl-paste", ["--no-newline", "--type", "text/plain"])
        if ok:
            snapshot["wayland"] = {"mime": "text/plain", "data": data}

    ok, data = run_capture("xclip", ["-selection", "clipboard", "-out", "-target", "UTF8_STRING"])
    if ok:
        snapshot["x11"] = {"mime": "UTF8_STRING", "data": data}
    else:
        ok, data = run_capture("xclip", ["-selection", "clipboard", "-out", "-target", "STRING"])
        if ok:
            snapshot["x11"] = {"mime": "STRING", "data": data}

    return snapshot


def clipboard_text_matches(protocol: str, mime: str, data: bytes) -> bool:
    if protocol == "wayland":
        ok, current = run_capture("wl-paste", ["--no-newline", "--type", mime], timeout=1.0)
    else:
        ok, current = run_capture("xclip", ["-selection", "clipboard", "-out", "-target", mime], timeout=1.0)
    return (ok and current == data) or (not ok and data == b"")


def restore_clipboard_text(snapshot: dict[str, Any]) -> dict[str, Any]:
    methods: list[str] = []
    checks: list[dict[str, Any]] = []
    pending_checks: list[tuple[str, str, str, bytes]] = []

    def restore_writer(command: str, args: list[str], data: bytes | None = None) -> bool:
        try:
            return run_available(command, args, input_bytes=data)
        except RuntimeError:
            return False

    wayland = snapshot.get("wayland")
    if isinstance(wayland, dict) and isinstance(wayland.get("data"), bytes):
        mime = str(wayland.get("mime") or "text/plain;charset=utf-8")
        if restore_writer("wl-copy", ["--type", mime], wayland["data"]):
            method = f"wl-copy:{mime}"
            methods.append(method)
            pending_checks.append((method, "wayland", mime, wayland["data"]))
    elif "wayland" in snapshot.get("attempted", []):
        if restore_writer("wl-copy", ["--clear"]):
            method = "wl-copy:clear"
            methods.append(method)
            pending_checks.append((method, "wayland", "text/plain;charset=utf-8", b""))

    x11 = snapshot.get("x11")
    if isinstance(x11, dict) and isinstance(x11.get("data"), bytes):
        mime = str(x11.get("mime") or "UTF8_STRING")
        if restore_writer("xclip", ["-selection", "clipboard"], x11["data"]):
            method = "xclip:text"
            methods.append(method)
            pending_checks.append((method, "x11", mime, x11["data"]))
    elif "x11" in snapshot.get("attempted", []):
        if restore_writer("xclip", ["-selection", "clipboard"], b""):
            method = "xclip:clear-text"
            methods.append(method)
            pending_checks.append((method, "x11", "UTF8_STRING", b""))

    if pending_checks:
        time.sleep(0.05)
    for method, protocol, mime, data in pending_checks:
        checks.append({"method": method, "verified": clipboard_text_matches(protocol, mime, data), "bytes": len(data)})

    verified = bool(checks) and all(bool(check.get("verified")) for check in checks)
    return {"methods": methods, "checks": checks, "verified": verified}


def try_clipboard_write(
    methods: list[str],
    errors: list[str],
    label: str,
    command: str,
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    input_text: str | None = None,
) -> bool:
    try:
        if run_available(command, args, input_bytes=input_bytes, input_text=input_text):
            methods.append(label)
            return True
    except RuntimeError as exc:
        errors.append(f"{label}: {exc}")
    return False


def set_clipboard_text(text: str, target_is_xwayland: bool | None = None) -> list[str]:
    methods: list[str] = []
    errors: list[str] = []

    def write_wayland() -> bool:
        return try_clipboard_write(methods, errors, "wl-copy:text", "wl-copy", ["--type", "text/plain;charset=utf-8"], input_text=text)

    def write_x11() -> bool:
        return try_clipboard_write(methods, errors, "xclip:text", "xclip", ["-selection", "clipboard"], input_text=text)

    writers = [write_x11, write_wayland] if target_is_xwayland is True else [write_wayland, write_x11]
    for writer in writers:
        if writer() and target_is_xwayland is not None:
            break

    if not methods:
        detail = f": {'; '.join(errors)}" if errors else ""
        raise RuntimeError(f"no clipboard writer found{detail}")
    return methods


def set_clipboard_bytes(data: bytes, mime: str) -> list[str]:
    methods: list[str] = []
    if run_available("wl-copy", ["--type", mime], input_bytes=data):
        methods.append(f"wl-copy:{mime}")
    if run_available("xclip", ["-selection", "clipboard", "-t", mime], input_bytes=data):
        methods.append(f"xclip:{mime}")
    if not methods:
        raise RuntimeError("no clipboard writer found")
    return methods


def file_uri(path: pathlib.Path) -> str:
    return path.resolve().as_uri()


def set_clipboard_uri(path: pathlib.Path) -> list[str]:
    payload = f"{file_uri(path)}\r\n"
    methods: list[str] = []
    if run_available("wl-copy", ["--type", "text/uri-list"], input_text=payload):
        methods.append("wl-copy:text/uri-list")
    if run_available("xclip", ["-selection", "clipboard", "-t", "text/uri-list"], input_text=payload):
        methods.append("xclip:text/uri-list")
    if not methods:
        raise RuntimeError("no clipboard writer found")
    return methods


def keyboard(target: str, key: str, modifiers: str = "", x: float | None = None, y: float | None = None) -> dict[str, Any]:
    cmd = ["keyboard", "--json", target, "tap", key, modifiers]
    if x is not None or y is not None:
        if x is None or y is None:
            raise RuntimeError("keyboard x/y must be passed together")
        cmd.extend(["--x", str(x), "--y", str(y)])
    return call_ctl(cmd)


ASCII_KEYMAP: dict[str, tuple[str, str]] = {
    "\n": ("enter", ""),
    "\r": ("enter", ""),
    "\t": ("tab", ""),
    " ": ("space", ""),
    "-": ("minus", ""),
    "_": ("minus", "shift"),
    "=": ("equal", ""),
    "+": ("equal", "shift"),
    "[": ("leftbrace", ""),
    "{": ("leftbrace", "shift"),
    "]": ("rightbrace", ""),
    "}": ("rightbrace", "shift"),
    "\\": ("backslash", ""),
    "|": ("backslash", "shift"),
    ";": ("semicolon", ""),
    ":": ("semicolon", "shift"),
    "'": ("apostrophe", ""),
    '"': ("apostrophe", "shift"),
    "`": ("grave", ""),
    "~": ("grave", "shift"),
    ",": ("comma", ""),
    "<": ("comma", "shift"),
    ".": ("dot", ""),
    ">": ("dot", "shift"),
    "/": ("slash", ""),
    "?": ("slash", "shift"),
    "1": ("1", ""),
    "!": ("1", "shift"),
    "2": ("2", ""),
    "@": ("2", "shift"),
    "3": ("3", ""),
    "#": ("3", "shift"),
    "4": ("4", ""),
    "$": ("4", "shift"),
    "5": ("5", ""),
    "%": ("5", "shift"),
    "6": ("6", ""),
    "^": ("6", "shift"),
    "7": ("7", ""),
    "&": ("7", "shift"),
    "8": ("8", ""),
    "*": ("8", "shift"),
    "9": ("9", ""),
    "(": ("9", "shift"),
    "0": ("0", ""),
    ")": ("0", "shift"),
}


def key_for_char(ch: str) -> tuple[str, str] | None:
    if "a" <= ch <= "z":
        return ch, ""
    if "A" <= ch <= "Z":
        return ch.lower(), "shift"
    return ASCII_KEYMAP.get(ch)


def can_type_with_keys(text: str) -> bool:
    return all(key_for_char(ch) is not None for ch in text)


def type_with_keys(target: str, text: str, *, delay: float = 0.015) -> dict[str, Any]:
    sent: list[dict[str, Any]] = []
    for ch in text:
        key = key_for_char(ch)
        if key is None:
            raise RuntimeError(f"character cannot be typed as key events: U+{ord(ch):04X}")
        key_name, modifiers = key
        sent.append(keyboard(target, key_name, modifiers))
        if delay > 0:
            time.sleep(delay)
    return {"ok": True, "target": target, "method": "keys", "characters": len(text), "keys": len(sent)}


def prefer_related_target(target: str, enabled: bool = False) -> tuple[str, dict[str, Any] | None]:
    if not enabled:
        return target, None

    raise RuntimeError("automatic related-window rerouting is disabled; inspect app state and target the popup explicitly")

def key_from_args(args: dict[str, Any]) -> tuple[str, str]:
    keycode = args.get("keycode")
    if isinstance(keycode, int):
        if keycode < 0:
            raise RuntimeError("keycode must be non-negative")
        modifiers = args.get("modifiers") if isinstance(args.get("modifiers"), str) else ""
        return str(keycode), modifiers

    keys = args.get("keys")
    if isinstance(keys, str) and keys:
        parts = [p for p in keys.replace("-", "+").split("+") if p]
        if not parts:
            raise RuntimeError("empty keys shortcut")
        return parts[-1], "+".join(parts[:-1])

    key = args.get("key") or args.get("text")
    if not isinstance(key, str) or not key:
        raise RuntimeError("key action requires key or keys")
    modifiers = args.get("modifiers") if isinstance(args.get("modifiers"), str) else ""
    return key, modifiers


def paste(
    target: str,
    args: dict[str, Any],
    methods: list[str],
    *,
    text_clipboard_snapshot: dict[str, Any] | None = None,
    target_for_input: str | None = None,
    related: dict[str, Any] | None = None,
) -> dict[str, Any]:
    x = args.get("x")
    y = args.get("y")
    if target_for_input is None:
        prefer_related = args.get("prefer_related")
        target_for_input, related = prefer_related_target(target, False if not isinstance(prefer_related, bool) else prefer_related)
    session_info: dict[str, Any] = {"begin": session_action("begin", target), "sync": None, "end": None, "active": False}
    time.sleep(0.08)
    key_info = keyboard(target_for_input, "v", "ctrl", float(x) if isinstance(x, (int, float)) else None, float(y) if isinstance(y, (int, float)) else None)

    time.sleep(0.12)
    related_windows = sync_related_session(target, session_info)

    restore_info: dict[str, Any] = {"methods": [], "checks": [], "verified": False}
    should_restore = args.get("restore_clipboard", False)
    if text_clipboard_snapshot is not None and should_restore is True:
        delay = args.get("restore_delay", 1.0)
        if not isinstance(delay, (int, float)):
            delay = 1.0
        time.sleep(max(0.0, min(float(delay), 5.0)))
        restore_info = restore_clipboard_text(text_clipboard_snapshot)

    related_windows = sync_related_session(target, session_info)
    session_info["active"] = bool(related_windows)
    if not related_windows:
        session_info["end"] = session_action("end", target)

    next_step = None
    if related_windows:
        first = related_windows[0]
        next_step = (
            f'A related popup/dialog opened; operate it with app="address:{first.get("address")}" '
            "before returning to the root window."
        )

    return {
        "ok": True,
        "target": target,
        "resolvedTarget": target_for_input,
        "relatedTarget": related,
        "relatedWindows": related_windows,
        "session": session_info,
        "next": next_step,
        "method": "paste",
        "clipboard": methods,
        "pasteKey": key_info,
        "clipboardRestored": bool(restore_info["verified"]),
        "clipboardRestore": restore_info["methods"],
        "clipboardRestoreChecks": restore_info["checks"],
    }


def type_text(target: str, text: str, args: dict[str, Any]) -> dict[str, Any]:
    method = args.get("method") if isinstance(args.get("method"), str) else "auto"
    if method not in {"auto", "paste", "keys"}:
        raise RuntimeError("type method must be auto, paste, or keys")

    prefer_related = args.get("prefer_related")
    target_for_input, related = prefer_related_target(target, False if not isinstance(prefer_related, bool) else prefer_related)

    if method == "keys" or (method == "auto" and not text_is_bulk_paste_candidate(text) and can_type_with_keys(text)):
        info = type_with_keys(target_for_input, text)
        info.update({"target": target, "resolvedTarget": target_for_input, "relatedTarget": related})
        return info

    target_is_xwayland = target_uses_xwayland(target_for_input, related)
    snapshot = clipboard_snapshot_text() if args.get("restore_clipboard", False) is True else None
    methods = set_clipboard_text(text, target_is_xwayland)
    return paste(target, args, methods, text_clipboard_snapshot=snapshot, target_for_input=target_for_input, related=related)


def synthetic_elements(window: dict[str, Any], screenshot: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    width = float(screenshot.get("width") or window_geometry(window)["width"])
    height = float(screenshot.get("height") or window_geometry(window)["height"])
    title = str(window.get("title") or window.get("class") or "window")
    element = {
        "index": 0,
        "runtimeId": ["hyprland", str(window.get("address") or "")],
        "automationId": str(window.get("address") or ""),
        "name": title,
        "controlType": "window",
        "localizedControlType": "window",
        "className": str(window.get("class") or ""),
        "value": "",
        "nativeWindowHandle": 0,
        "frame": {"x": 0.0, "y": 0.0, "width": width, "height": height},
        "actions": [],
        "source": "hyprland",
    }
    line = "\t0 window {0} Frame: {{x: 0, y: 0, width: {1}, height: {2}}}".format(title, round(width), round(height))
    return [element], [line]


def build_app_snapshot(app_query: str) -> dict[str, Any]:
    window = dict(resolve_hypr_window(app_query))
    captured_starttime = process_start_time(window.get("pid"))
    if captured_starttime:
        window["processStartTime"] = captured_starttime
    target = window_selector(window)
    try:
        related_windows = privacy_filtered_related_windows(related_windows_for(target))
    except Exception as exc:
        related_windows = []
        related_error = str(exc)
    else:
        related_error = ""
    screenshot, png_base64 = screenshot_for_window(window)
    png_bytes = base64.b64decode(png_base64, validate=True)
    captured_at = time.time()
    screenshot_id = f"snap_{secrets.token_urlsafe(18)}"
    screenshot = dict(screenshot)
    screenshot.update(
        {
            "id": screenshot_id,
            "sha256": hashlib.sha256(png_bytes).hexdigest(),
        }
    )
    atspi = atspi_snapshot_isolated(window, screenshot)
    root_identity = atspi.get("rootIdentity")
    if atspi.get("status") == "ok" and isinstance(root_identity, dict):
        # This exact capture-time root is mandatory for every AT-SPI mutation.
        # Observation may still use the documented compatible resolver.
        window["atspiRootIdentity"] = dict(root_identity)
    global_menu = global_menu_for_window(window)
    elements = atspi["elements"] if atspi["status"] == "ok" and atspi["elements"] else []
    tree_lines = atspi["treeLines"] if atspi["status"] == "ok" and atspi["treeLines"] else []
    if not elements:
        elements, tree_lines = synthetic_elements(window, screenshot)

    app = {
        "name": str(window.get("class") or window.get("initialClass") or window.get("title") or "unknown"),
        "bundleIdentifier": str(window.get("class") or window.get("initialClass") or ""),
        "pid": int(window.get("pid") or 0),
    }
    snapshot = {
        "app": app,
        "windowTitle": str(window.get("title") or ""),
        "windowBounds": window_geometry(window),
        "target": target,
        "window": window,
        "relatedWindows": related_windows,
        "relatedTargets": [
            window_selector(related)
            for related in related_windows
            if related.get("hyprAgentPortalRelation") == "related" and isinstance(related.get("address"), str)
        ],
        "screenshot": screenshot,
        "screenshotPngBase64": png_base64,
        "snapshotId": screenshot_id,
        "capturedAt": captured_at,
        "windowStartTime": captured_starttime,
        "treeLines": tree_lines,
        "elements": elements,
        "accessibility": {k: v for k, v in atspi.items() if k not in {"elements", "treeLines"}},
        "globalMenu": global_menu,
    }
    snapshot["uiHints"] = ui_hints_for_elements(snapshot, elements)
    if related_error:
        snapshot["relatedWindowsError"] = related_error
    attach_active_related_preview(snapshot)
    cache_id = cache_visual("snapshot", snapshot, snapshot)
    snapshot["snapshotId"] = cache_id
    screenshot["id"] = cache_id
    remember_snapshot(app_query, snapshot)
    return snapshot


def is_app_not_found_error(exc: Exception) -> bool:
    return "appNotFound(" in str(exc)


def snapshot_target_address(snapshot: dict[str, Any]) -> str:
    target = str(snapshot.get("target") or "")
    address = target_address(target)
    if address:
        return address
    window = snapshot.get("window") or {}
    return normalize(window.get("address"))


def fallback_targets_after_target_closed(before: dict[str, Any]) -> list[str]:
    old_address = snapshot_target_address(before)
    pid = int((before.get("app") or {}).get("pid") or 0)
    candidates: list[tuple[int, str]] = []
    seen: set[str] = set()

    def add_candidate(window: dict[str, Any], score: int) -> None:
        if SECURITY_POLICY.privacy_excluded(window):
            return
        address = normalize(window.get("address"))
        if not address or address == old_address or address in seen:
            return
        if window.get("hidden", False) or not window.get("mapped", True):
            return
        seen.add(address)
        candidates.append((score, f"address:{address}"))

    for window in before.get("relatedWindows") or []:
        if not isinstance(window, dict):
            continue
        relation = window.get("hyprAgentPortalRelation")
        if relation not in {"self", "related"}:
            continue
        kind = window.get("hyprAgentPortalWindowKind") or ""
        floating = bool(window.get("floating"))
        score = 0
        if relation == "related":
            score += 1
        if kind == "popup" or floating:
            score += 2
        add_candidate(window, score)

    if pid:
        for window in list_hypr_windows():
            if int(window.get("pid") or 0) == pid:
                add_candidate(window, 10)

    candidates.sort(key=lambda item: item[0])
    return [target for _, target in candidates]


def compact_window_info(window: dict[str, Any]) -> dict[str, Any]:
    address = str(window.get("address") or "")
    workspace = window.get("workspace") or {}
    return {
        "target": f"address:{address}" if address else "",
        "address": address,
        "class": str(window.get("class") or window.get("initialClass") or ""),
        "pid": int(window.get("pid") or 0),
        "kind": window.get("hyprAgentPortalWindowKind") or "",
        "relation": window.get("hyprAgentPortalRelation") or "",
        "workspace": workspace.get("name", workspace.get("id", "")),
    }


def compact_element_info(element: dict[str, Any], x: float, y: float, coordinate_space: str) -> dict[str, Any]:
    frame = element.get("frame") if isinstance(element.get("frame"), dict) else {}
    return {
        "index": element.get("index"),
        "name": str(element.get("name") or ""),
        "value": str(element.get("value") or ""),
        "controlType": str(element.get("controlType") or element.get("localizedControlType") or ""),
        "coordinate": {"x": x, "y": y, "coordinateSpace": coordinate_space},
        "frame": frame,
    }


def window_delta(before_windows: list[dict[str, Any]], after_windows: list[dict[str, Any]]) -> dict[str, Any]:
    before = {normalize(window.get("address")): window for window in privacy_filtered_related_windows(before_windows) if window.get("address")}
    after = {normalize(window.get("address")): window for window in privacy_filtered_related_windows(after_windows) if window.get("address")}
    opened = [compact_window_info(after[address]) for address in sorted(after.keys() - before.keys())]
    closed = [compact_window_info(before[address]) for address in sorted(before.keys() - after.keys())]
    result: dict[str, Any] = {}
    if opened:
        result["opened"] = opened
    if closed:
        result["closed"] = closed
    return result


def action_popup_mismatch(action_result: dict[str, Any], opened: list[dict[str, Any]]) -> dict[str, Any] | None:
    clicked = action_result.get("clickedElement")
    if not isinstance(clicked, dict) or not opened:
        return None
    clicked_text = normalize(" ".join([str(clicked.get("name") or ""), str(clicked.get("value") or "")]))
    if not clicked_text:
        return None
    clicked_tokens = [token for token in re.split(r"[^0-9a-zA-Z\u4e00-\u9fff]+", clicked_text) if len(token) >= 2]
    if not clicked_tokens:
        return None
    unexpected = []
    for item in opened:
        title = normalize(item.get("title") or "")
        if title and not any(token in title for token in clicked_tokens):
            unexpected.append(item)
    if not unexpected:
        return None
    return {
        "type": "action-opened-unexpected-window",
        "clickedElement": clicked,
        "opened": unexpected,
        "message": "The action opened a related window whose title does not match the clicked element text. Refresh app state and recover instead of continuing the assumed workflow.",
    }


def merge_last_action(after: dict[str, Any], before: dict[str, Any], action_result: dict[str, Any] | None = None) -> None:
    delta = window_delta(
        [item for item in before.get("relatedWindows") or [] if isinstance(item, dict)],
        [item for item in after.get("relatedWindows") or [] if isinstance(item, dict)],
    )
    if not action_result and not delta:
        return
    info: dict[str, Any] = dict(action_result or {})
    if delta:
        info["windowDelta"] = delta
        if delta.get("opened"):
            info["message"] = "The action changed the related window set; inspect opened/closed windows before continuing."
            mismatch = action_popup_mismatch(info, [item for item in delta.get("opened") or [] if isinstance(item, dict)])
            if mismatch:
                info["warning"] = mismatch
                after["attention"] = mismatch
    after["lastAction"] = info


def snapshot_after_action(app: str, before: dict[str, Any], action_result: dict[str, Any] | None = None) -> dict[str, Any]:
    if action_result:
        time.sleep(0.35)
    try:
        after = build_app_snapshot(app)
    except Exception as exc:
        if not is_app_not_found_error(exc):
            raise
        errors: list[str] = [str(exc)]
        for candidate in fallback_targets_after_target_closed(before):
            try:
                candidate_window = resolve_hypr_window(candidate)
                candidate_identity = WindowIdentity.from_window(candidate_window)
                if SECURITY_POLICY.privacy_excluded(candidate_identity):
                    raise RuntimeError("fallback target is privacy-excluded")
                if SECURITY_POLICY.authorization_for(candidate_identity) < AuthorizationLevel.VIEW:
                    raise RuntimeError("fallback target is not authorized for observation")
                if not SECURITY_POLICY._in_scope(candidate_identity):
                    raise RuntimeError("fallback target is outside configured confinement")
                after = build_app_snapshot(window_selector(candidate_window))
                if dict(WindowIdentity.from_window(after.get("window") or {}).fingerprint()) != dict(candidate_identity.fingerprint()):
                    raise RuntimeError("fallback target identity changed before snapshot")
                after["lastAction"] = {
                    "targetClosed": True,
                    "previousTarget": before.get("target") or app,
                    "continuedWithTarget": after.get("target"),
                    "message": "The previous target closed after the action; continue with this related/root window state.",
                    "windowDelta": window_delta(
                        [item for item in before.get("relatedWindows") or [] if isinstance(item, dict)],
                        [item for item in after.get("relatedWindows") or [] if isinstance(item, dict)],
                    ),
                }
                if action_result:
                    after["lastAction"]["result"] = action_result
                return after
            except Exception as candidate_exc:
                errors.append(f"{candidate}: {candidate_exc}")
        raise RuntimeError("; ".join(errors)) from exc
    merge_last_action(after, before, action_result)
    return after


def render_snapshot_text(snapshot: dict[str, Any]) -> str:
    app = snapshot.get("app") or {}
    window = snapshot.get("window") or {}
    app_ref = app.get("bundleIdentifier") or app.get("name") or "unknown"
    lines = [
        f"App={app_ref} (pid {app.get('pid', 0)})",
        'Window: "{0}", App: {1}.'.format(snapshot.get("windowTitle") or app.get("name") or "", app.get("name") or "unknown"),
        "Hyprland: target={0}, class={1}, workspace={2}, xwayland={3}.".format(
            snapshot.get("target"),
            window.get("class") or "",
            (window.get("workspace") or {}).get("name", (window.get("workspace") or {}).get("id", "")),
            bool(window.get("xwayland")),
        ),
    ]
    last_action = snapshot.get("lastAction") or {}
    attention = snapshot.get("attention") or {}
    if isinstance(attention, dict) and attention.get("type") == "action-opened-unexpected-window":
        lines.extend(
            [
                "",
                "ACTION WARNING:",
                f"- {attention.get('message')}",
            ]
        )
        clicked = attention.get("clickedElement") or {}
        if isinstance(clicked, dict):
            lines.append('- clicked element index={0} name="{1}" value="{2}"'.format(clicked.get("index"), clicked.get("name"), clicked.get("value")))
        for item in (attention.get("opened") or [])[:4]:
            if isinstance(item, dict):
                lines.append('- opened {0} title="{1}" class={2}'.format(item.get("target"), item.get("title"), item.get("class")))
    if isinstance(last_action, dict) and last_action.get("targetClosed"):
        lines.extend(
            [
                "",
                "ACTION RESULT:",
                "- Previous target {0} closed after the action; continue with {1}.".format(
                    last_action.get("previousTarget") or "",
                    last_action.get("continuedWithTarget") or snapshot.get("target") or "",
                ),
            ]
        )
    if isinstance(last_action, dict) and isinstance(last_action.get("windowDelta"), dict):
        delta = last_action["windowDelta"]
        opened = delta.get("opened") or []
        closed = delta.get("closed") or []
        if opened or closed:
            if "ACTION RESULT:" not in lines:
                lines.extend(["", "ACTION RESULT:"])
            for item in opened[:6]:
                lines.append('- opened {0} title="{1}" class={2} kind={3}'.format(item.get("target"), item.get("title"), item.get("class"), item.get("kind")))
            for item in closed[:6]:
                lines.append('- closed {0} title="{1}" class={2} kind={3}'.format(item.get("target"), item.get("title"), item.get("class"), item.get("kind")))
    active_related = snapshot.get("activeRelatedWindow") or {}
    if active_related:
        title = str(active_related.get("title") or active_related.get("initialTitle") or "")
        klass = str(active_related.get("class") or active_related.get("initialClass") or "")
        target = snapshot.get("activeRelatedTarget") or (window_selector(active_related) if active_related.get("address") else "")
        lines.extend(
            [
                "",
                "ACTIVE RELATED POPUP DETECTED:",
                f'- target={target} title="{title}" class={klass}',
                "- Operate this popup/dialog target first. Its screenshot is attached before the root window screenshot.",
            ]
        )
        if snapshot.get("activeRelatedScreenshotError"):
            lines.append(f"- popup screenshot unavailable: {snapshot.get('activeRelatedScreenshotError')}")
    related = [
        window
        for window in snapshot.get("relatedWindows") or []
        if isinstance(window, dict) and window.get("hyprAgentPortalRelation") == "related"
    ]
    if related:
        lines.extend(["", "Related windows/dialogs:"])
        for window in related:
            title = str(window.get("title") or window.get("initialTitle") or "")
            klass = str(window.get("class") or window.get("initialClass") or "")
            workspace = window.get("workspace") or {}
            workspace_name = workspace.get("name", workspace.get("id", ""))
            kind = window.get("hyprAgentPortalWindowKind") or "related"
            lines.append(
                '- target=address:{0} title="{1}" class={2} kind={3} workspace={4}'.format(
                    window.get("address"),
                    title,
                    klass,
                    kind,
                    workspace_name,
                )
            )
    elif snapshot.get("relatedWindowsError"):
        lines.extend(["", f"Related windows: unavailable. {snapshot.get('relatedWindowsError')}"])
    global_menu = snapshot.get("globalMenu") or {}
    if global_menu.get("providers") or global_menu.get("errors"):
        lines.extend(["", "Global menu models:"])
        for provider in global_menu.get("providers") or []:
            lines.append(
                "- {0} service={1} path={2} items={3}".format(
                    provider.get("provider"),
                    provider.get("service"),
                    provider.get("objectPath"),
                    provider.get("itemCount", 0),
                )
            )
        if global_menu.get("errors"):
            lines.append("- warnings: {0}".format("; ".join(str(item) for item in global_menu.get("errors") or [])))
        menu_items = [item for item in global_menu.get("items") or [] if item.get("label")]
        if menu_items:
            lines.append("Global menu actions:")
            for item in menu_items[:16]:
                indent = "  " * min(3, int(item.get("depth") or 0))
                action = str(item.get("action") or "")
                suffix = f" action={action}" if action else ""
                disabled = "" if item.get("enabled", True) else " disabled"
                lines.append(f"- {indent}{item.get('menuIndex')} {item.get('label')}{suffix}{disabled}")
        elif global_menu.get("providers"):
            lines.append("- no menu items were exposed by the provider for this window")
    ui_hints = snapshot.get("uiHints") or {}
    hint_notes = ui_hints.get("notes") or []
    if hint_notes:
        lines.extend(["", "UI hints:"])
        lines.extend(f"- {note}" for note in hint_notes)
    for label, key in (
        ("Visible tab-like controls", "visibleTabs"),
        ("Visible menu/toolkit command controls", "visibleMenus"),
        ("Visible toolbar containers", "visibleToolbars"),
        ("Visible actionable controls", "visibleActions"),
    ):
        controls = ui_hints.get(key) or []
        if controls:
            lines.append(f"{label}:")
            for control in controls[:8]:
                frame = control.get("frame") or {}
                frame_text = ""
                if isinstance(frame, dict):
                    frame_text = " Frame: {{x: {0}, y: {1}, width: {2}, height: {3}}}".format(
                        round(float(frame.get("x") or 0.0)),
                        round(float(frame.get("y") or 0.0)),
                        round(float(frame.get("width") or 0.0)),
                        round(float(frame.get("height") or 0.0)),
                    )
                lines.append(
                    "- {0} {1} {2}{3}".format(
                        control.get("index"),
                        control.get("controlType") or "element",
                        control.get("name") or "",
                        frame_text,
                    ).rstrip()
                )
    lines.extend(str(line) for line in snapshot.get("treeLines") or [])
    accessibility = snapshot.get("accessibility") or {}
    if accessibility.get("treeTruncated"):
        lines.extend(["", "Accessibility tree truncated: {0}.".format(accessibility.get("treeTruncatedReason") or "limit")])
    if accessibility.get("status") != "ok":
        lines.extend(["", "Accessibility: {0}. {1}".format(accessibility.get("status", "unavailable"), accessibility.get("error", ""))])
    return "\n".join(lines)


def tool_list_apps(_: dict[str, Any]) -> dict[str, Any]:
    windows = [window for window in list_hypr_windows() if not SECURITY_POLICY.privacy_excluded(window)]
    public_windows = []
    for window in windows:
        item = dict(window)
        item["target"] = window_selector(window)
        item["processStartTime"] = process_start_time(window.get("pid"))
        public_windows.append(item)
    return mcp_text(list_apps_text(windows), structured={"windows": public_windows})


def privacy_filter_windows(payload: dict[str, Any]) -> dict[str, Any]:
    filtered = dict(payload)
    windows = filtered.get("windows")
    if isinstance(windows, list):
        filtered["windows"] = [
            window
            for window in windows
            if isinstance(window, dict) and not SECURITY_POLICY.privacy_excluded(window)
        ]
    return filtered


def require_safe_full_capture(target: Any) -> None:
    if isinstance(target, str) and target:
        return
    if any(SECURITY_POLICY.privacy_excluded(window) for window in list_hypr_windows()):
        raise RuntimeError(
            "full-compositor capture is blocked while a privacy-excluded application is visible; "
            "capture a permitted target window instead"
        )


def tool_launch_app(args: dict[str, Any]) -> dict[str, Any]:
    parts, match_query = launch_parts(args)
    reuse_existing = args.get("reuse_existing")
    if not isinstance(reuse_existing, bool):
        reuse_existing = True
    timeout = bounded_timeout_seconds(args.get("timeout", 8), 8.0)

    if reuse_existing:
        try:
            existing = resolve_hypr_window(match_query)
            result = {
                "ok": True,
                "reused": True,
                "app": match_query,
                "target": window_selector(existing),
                "window": existing,
                "next": f'Call get_app_state with app="{window_selector(existing)}" or app="{match_query}".',
            }
            if SECURITY_POLICY.privacy_excluded(existing):
                result = {"ok": True, "reused": True, "privacyExcluded": True}
            return mcp_text(json.dumps(result, ensure_ascii=False), structured=result)
        except Exception:
            pass

    before = list_hypr_windows()
    before_ids = window_identities(before)
    command = launch_command_string(parts)
    output = hyprctl_exec(command)
    window, new_windows = wait_for_launch_window(before_ids, match_query, timeout, allow_existing_fallback=reuse_existing)
    result: dict[str, Any] = {
        "ok": True,
        "reused": False,
        "app": match_query,
        "command": command,
        "argv": parts,
        "hyprctlOutput": output,
        "accessibility": {
            "environment": A11Y_LAUNCH_ENV,
            "chromiumLikeFlagsApplied": launch_is_chromium_like(parts),
        },
        "newWindows": new_windows,
    }
    if window is not None:
        if SECURITY_POLICY.privacy_excluded(window):
            result = {"ok": True, "reused": False, "privacyExcluded": True}
        else:
            result["target"] = window_selector(window)
            result["window"] = window
            result["next"] = f'Call get_app_state with app="{window_selector(window)}" or app="{match_query}".'
    else:
        result["warning"] = "No Hyprland window appeared before timeout; use list_apps to inspect current windows."
    return mcp_text(json.dumps(result, ensure_ascii=False), structured=result)


def tool_get_app_state(args: dict[str, Any]) -> dict[str, Any]:
    app = args.get("app")
    if not isinstance(app, str) or not app:
        raise RuntimeError("Missing required argument: app")
    return mcp_snapshot_result(build_app_snapshot(app))


def validate_visual_request_limits(args: dict[str, Any]) -> None:
    for key in ("scale", "zoom"):
        value = args.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or not 0 < float(value) <= 8):
            raise RuntimeError(f"{key} must be greater than 0 and at most 8")
    max_dimension = args.get("max_dimension")
    if max_dimension is not None and (isinstance(max_dimension, bool) or not isinstance(max_dimension, int) or not 1 <= max_dimension <= 8192):
        raise RuntimeError("max_dimension must be an integer from 1 to 8192")


def tool_screenshot(args: dict[str, Any]) -> dict[str, Any]:
    validate_visual_request_limits(args)
    cmd = screenshot_command_base()
    app = args.get("app")
    target = args.get("target")
    window: dict[str, Any] | None = None
    if isinstance(app, str) and app:
        window = resolve_hypr_window(app)
        target = window_selector(window)
    elif isinstance(target, str) and target:
        window = resolve_hypr_window(target)
    if isinstance(target, str) and target:
        cmd.extend(["--target", target])
    else:
        require_safe_full_capture(target)
    if args.get("show_cursor") is False:
        cmd.append("--no-cursor")
    cursor_source = args.get("cursor_source")
    if isinstance(cursor_source, str) and cursor_source:
        cmd.extend(["--cursor-source", cursor_source])
    info, data = consume_screenshot_result(call_ctl(cmd))
    raw = base64.b64decode(data, validate=True)
    output_format = str(args.get("format") or "png").lower()
    transform_requested = any(
        key in args for key in ("region", "scale", "zoom", "quality", "max_dimension", "format")
    )
    mime_type = "image/png"
    if transform_requested:
        raw, transform = transform_image(
            raw,
            screenshot=info,
            window=window,
            region=args.get("region") if isinstance(args.get("region"), dict) else None,
            coordinate_space=str(args.get("coordinate_space") or "screenshot"),
            scale=args.get("scale") if isinstance(args.get("scale"), (int, float)) else None,
            zoom=args.get("zoom") if isinstance(args.get("zoom"), (int, float)) else None,
            output_format=output_format,
            quality=int(args.get("quality") or 85),
            max_dimension=int(args["max_dimension"]) if isinstance(args.get("max_dimension"), int) else None,
        )
        info["transform"] = transform
        output_format = str(transform["output"]["format"])
        mime_type = f"image/{output_format}"
        data = base64.b64encode(raw).decode("ascii")
    info["sha256"] = hashlib.sha256(raw).hexdigest()
    info["format"] = output_format
    info["outputBytes"] = len(raw)
    return {
        "content": [
            {"type": "text", "text": json.dumps(info, ensure_ascii=False)},
            {"type": "image", "mimeType": mime_type, "data": data},
        ],
        "structuredContent": info,
        "isError": False,
    }


def tool_get_cursor_position(args: dict[str, Any]) -> dict[str, Any]:
    source = str(args.get("source") or "auto").lower()
    if source not in {"auto", "hyprland", "agent"}:
        raise RuntimeError("source must be auto, hyprland, or agent")

    hypr = hyprland_cursor_position()
    agent = agent_cursor_position()
    selected = hypr
    selected_source = "hyprland"
    if source == "agent" or (source == "auto" and agent is not None):
        if agent is None:
            raise RuntimeError("no agent cursor position is recorded yet")
        selected = {"x": agent["x"], "y": agent["y"]}
        selected_source = "agent"

    global_x = float(selected["x"])
    global_y = float(selected["y"])
    result: dict[str, Any] = {
        "source": selected_source,
        "monitor": monitor_position(global_x, global_y),
        "agentCursor": agent,
    }

    app = args.get("app")
    if isinstance(app, str) and app:
        snapshot = SNAPSHOTS.get(normalize(app)) or build_app_snapshot(app)
        result["app"] = {
            "name": (snapshot.get("app") or {}).get("name"),
            "target": snapshot.get("target"),
            "windowTitle": snapshot.get("windowTitle"),
        }
        result["position"] = snapshot_position(snapshot, global_x, global_y)
    else:
        result["position"] = result["monitor"]

    if args.get("include_global"):
        result["global"] = {"x": global_x, "y": global_y, "coordinateSpace": "global"}

    return mcp_text(json.dumps(result, ensure_ascii=False), structured=result)


def semantic_click(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    button = str(args.get("mouse_button") or "left")
    click_count = int(args.get("click_count") or 1)

    element_index = args.get("element_index")
    element = None
    refresh_info = None
    if isinstance(element_index, str) and element_index:
        snapshot, element, refresh_info = element_snapshot_for_action(app, element_index)
        x, y = visible_element_center(snapshot, element)
        coordinate_space = "screenshot"
    else:
        snapshot = current_snapshot(app)
        point = action_point(snapshot, args)
        x, y = point
        coordinate_space = args.get("coordinate_space") or "screenshot"

    target = str(snapshot["target"])
    session_info = begin_related_action_session(target)

    if element is not None and button == "left" and click_count == 1:
        mode = element_click_mode(args)
        if mode == "pointer" and element_is_menu_item(element) and element_has_primary_atspi_action(element):
            mode = "atspi"
        if mode in {"auto", "atspi"}:
            if not element_has_primary_atspi_action(element):
                if mode == "atspi":
                    raise RuntimeError("element has no AT-SPI action; use element_click_mode=pointer for native pointer click")
            else:
                control_overlay(snapshot, float(x), float(y), coordinate_space=coordinate_space, action="click")
                if atspi_do_action_isolated(snapshot, element):
                    action_result = {"method": "atspi", "clickedElement": compact_element_info(element, float(x), float(y), coordinate_space), "session": session_info}
                    if refresh_info:
                        action_result.update(refresh_info)
                    finish_related_action_session(target, session_info)
                    return mcp_snapshot_result(
                        snapshot_after_action(
                            app,
                            snapshot,
                            action_result,
                        )
                    )
                if mode == "atspi":
                    finish_related_action_session(target, session_info)
                    raise RuntimeError("AT-SPI element action failed; use element_click_mode=pointer for native pointer click")

    action = "doubleclick" if click_count > 1 and button == "left" else "click"
    ctl_args, pointer_info = pointer_ctl_args(snapshot, float(x), float(y), coordinate_space, action, button)
    info: dict[str, Any] = {
        "method": "pointer",
        "target": target,
        "button": button,
        "clickCount": click_count,
        "coordinate": {"x": float(x), "y": float(y), "coordinateSpace": coordinate_space},
        **pointer_info,
    }
    if refresh_info:
        info.update(refresh_info)
    if element is not None:
        info["clickedElement"] = compact_element_info(element, float(x), float(y), coordinate_space)
    for index in range(max(1, click_count)):
        if action == "doubleclick":
            break
        call_ctl(ctl_args)
        if index + 1 < click_count:
            time.sleep(0.12)
    if action == "doubleclick":
        call_ctl(ctl_args)
    finish_related_action_session(target, session_info)
    info["session"] = session_info
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, info))


def semantic_perform_secondary_action(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    action = str(args.get("action") or "")
    if not action:
        raise RuntimeError("Missing required argument: action")
    snapshot, element, refresh_info = element_snapshot_for_action(app, str(args.get("element_index") or ""))
    target = str(snapshot["target"])
    session_info = begin_related_action_session(target)
    try:
        x, y = visible_element_center(snapshot, element)
        control_overlay(snapshot, x, y, action=action)
    except Exception:
        control_overlay(snapshot, action=action)
    if not atspi_do_action_isolated(snapshot, element, action):
        finish_related_action_session(target, session_info)
        raise RuntimeError(f"{action} is not a valid secondary action for element")
    finish_related_action_session(target, session_info)
    info = {"method": "atspi", "action": action, "session": session_info}
    if refresh_info:
        info.update(refresh_info)
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, info))


def semantic_activate_menu_item(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    menu_index = str(args.get("menu_index") or args.get("menuIndex") or "")
    if not menu_index:
        raise RuntimeError("activate_menu_item requires menu_index from get_app_state")
    snapshot = current_snapshot(app)
    target = str(snapshot["target"])
    session_info = begin_related_action_session(target)
    item = find_global_menu_item(snapshot, menu_index)
    provider = str(item.get("provider") or "")
    if provider == "dbusmenu":
        result = activate_dbusmenu_item(item)
    elif provider == "gmenu":
        result = activate_gmenu_item(item)
    else:
        finish_related_action_session(target, session_info)
        raise RuntimeError(f"unsupported global menu provider: {provider}")
    time.sleep(0.12)
    finish_related_action_session(target, session_info)
    result["session"] = session_info
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, result))


def semantic_scroll(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    direction = str(args.get("direction") or "down").lower()
    action_name = scroll_action_for_direction(direction)
    pages = float(args.get("pages") or 1.0)
    if pages <= 0:
        raise RuntimeError("pages must be > 0")
    element_index = args.get("element_index")
    element = None
    refresh_info = None
    if isinstance(element_index, str) and element_index:
        snapshot, element, refresh_info = element_snapshot_for_action(app, element_index)
        x, y = visible_element_center(snapshot, element)
        coordinate_space = "screenshot"
    else:
        snapshot = current_snapshot(app)
        element = best_scroll_element(snapshot, direction)
        if element is not None:
            x, y = visible_element_center(snapshot, element)
            coordinate_space = "screenshot"
        else:
            x, y = action_point(snapshot, args, default_center=True)
            coordinate_space = args.get("coordinate_space") or "screenshot"

    if element is None and (not isinstance(element_index, str) or not element_index):
        coordinate_space = args.get("coordinate_space") or "screenshot"
    ctl_args, pointer_info = pointer_ctl_args(snapshot, x, y, coordinate_space, "scroll", "0")
    ticks = max(1.0, pages * 5.0)
    dx = 0.0
    dy = 0.0
    if direction == "up":
        dy = ticks
    elif direction == "down":
        dy = -ticks
    elif direction == "left":
        dx = ticks
    elif direction == "right":
        dx = -ticks
    else:
        raise RuntimeError(f"Invalid scroll direction: {direction}")
    try:
        call_ctl([*ctl_args[:-1], str(dy), "--dx", str(dx)])
        action_result = {"method": "pointer", "action": "scroll", "direction": direction, "pages": pages, **pointer_info}
        if refresh_info:
            action_result.update(refresh_info)
        return mcp_snapshot_result(snapshot_after_action(app, snapshot, action_result))
    except Exception:
        if element is None or not element_supports_scroll_direction(element, direction):
            raise
        control_overlay(snapshot, x, y, coordinate_space=coordinate_space, action="scroll")
        ok = False
        for _ in range(max(1, min(10, int(round(pages))))):
            ok = atspi_do_action_isolated(snapshot, element, action_name) or ok
        if not ok:
            raise
        action_result = {"method": "atspi", "action": action_name, "direction": direction, "pages": pages}
        if refresh_info:
            action_result.update(refresh_info)
        return mcp_snapshot_result(snapshot_after_action(app, snapshot, action_result))


def semantic_drag(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    snapshot = current_snapshot(app)
    start = point_from_args(args, prefix="from", coordinate_key="start_coordinate")
    end = point_from_args(args, prefix="to", coordinate_key="coordinate")
    if start is None or end is None:
        raise RuntimeError("drag requires start_coordinate/coordinate or from_x/from_y/to_x/to_y")
    coordinate_space = args.get("coordinate_space") or "screenshot"
    from_global_x, from_global_y, from_window_x, from_window_y, use_relative = pointer_call_coordinates(snapshot, start[0], start[1], coordinate_space)
    to_global_x, to_global_y, to_window_x, to_window_y, _ = pointer_call_coordinates(snapshot, end[0], end[1], coordinate_space)
    if use_relative:
        ctl_args = [
            "pointer",
            "--json",
            "--relative",
            str(snapshot["target"]),
            str(from_window_x),
            str(from_window_y),
            "drag",
            "left",
            str(to_window_x),
            str(to_window_y),
        ]
    else:
        ctl_args = ["pointer", "--json", str(snapshot["target"]), str(from_global_x), str(from_global_y), "drag", "left", str(to_global_x), str(to_global_y)]
    duration = float(args.get("duration") or 0.2)
    call_ctl([*ctl_args, "--duration", str(max(0.0, min(duration, 3.0)))])
    action_result = {
        "method": "pointer",
        "target": str(snapshot["target"]),
        "action": "drag",
        "button": "left",
        "from": {"x": start[0], "y": start[1], "coordinateSpace": coordinate_space},
        "to": {"x": end[0], "y": end[1], "coordinateSpace": coordinate_space},
        "windowFrom": {"x": from_window_x, "y": from_window_y, "coordinateSpace": "window"},
        "windowTo": {"x": to_window_x, "y": to_window_y, "coordinateSpace": "window"},
        "globalFrom": {"x": from_global_x, "y": from_global_y},
        "globalTo": {"x": to_global_x, "y": to_global_y},
        "dispatchCoordinateSpace": "window" if use_relative else "global",
        "duration": max(0.0, min(duration, 3.0)),
    }
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, action_result))


def semantic_hover(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    element_index = args.get("element_index")
    refresh_info = None
    if isinstance(element_index, str) and element_index:
        snapshot, element, refresh_info = element_snapshot_for_action(app, element_index)
        x, y = visible_element_center(snapshot, element)
        coordinate_space = "screenshot"
    else:
        snapshot = current_snapshot(app)
        x, y = action_point(snapshot, args)
        coordinate_space = args.get("coordinate_space") or "screenshot"
    ctl_args, pointer_info = pointer_ctl_args(snapshot, x, y, coordinate_space, "move", "left")
    call_ctl(ctl_args)
    action_result = {"method": "pointer", "action": "move", **pointer_info}
    if refresh_info:
        action_result.update(refresh_info)
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, action_result))


def semantic_type_text(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    text = args.get("text")
    if not isinstance(text, str) or not text:
        raise RuntimeError("Missing required argument: text")
    snapshot = current_snapshot(app)
    control_overlay(snapshot, action="type")
    method = args.get("method") if isinstance(args.get("method"), str) else "auto"
    runtime_id = args.get("_atspi_runtime_id")
    has_focused_editable = any(
        isinstance(element, dict) and element.get("source") == "atspi" and element.get("focused") is True and element.get("editable") is True
        for element in snapshot.get("elements") or []
    )
    if method == "auto" and not text_is_bulk_paste_candidate(text):
        if isinstance(runtime_id, list):
            if atspi_insert_text_isolated(snapshot, text, runtime_id=runtime_id):
                return mcp_snapshot_result(snapshot_after_action(app, snapshot, {"method": "atspi", "targeting": "runtime-id"}))
        elif has_focused_editable and atspi_insert_focused_text_isolated(snapshot, text):
            return mcp_snapshot_result(snapshot_after_action(app, snapshot, {"method": "atspi", "targeting": "focused-editable"}))
    if method == "atspi":
        if atspi_insert_text_isolated(snapshot, text, runtime_id=runtime_id):
            return mcp_snapshot_result(snapshot_after_action(app, snapshot, {"method": "atspi", "targeting": "editable"}))
        raise RuntimeError("explicit AT-SPI text insertion failed; no keyboard or clipboard fallback was attempted")
    type_args = dict(args)
    prepare_grid_bulk_paste(snapshot, text)
    info = type_text(str(snapshot["target"]), text, type_args)
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, info))


def semantic_paste_text(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    text = args.get("text")
    if not isinstance(text, str):
        raise RuntimeError("Missing required argument: text")
    snapshot = current_snapshot(app)
    control_overlay(snapshot, action="type")
    target = str(snapshot["target"])
    prepare_info = prepare_grid_bulk_paste(snapshot, text)
    prefer_related = args.get("prefer_related")
    target_for_input, related = prefer_related_target(target, False if not isinstance(prefer_related, bool) else prefer_related)
    target_is_xwayland = target_uses_xwayland(target_for_input, related)
    clipboard = clipboard_snapshot_text() if args.get("restore_clipboard", False) is True else None
    methods = set_clipboard_text(text, target_is_xwayland)
    info = paste(target, args, methods, text_clipboard_snapshot=clipboard, target_for_input=target_for_input, related=related)
    if prepare_info is not None:
        info["preparedForGridPaste"] = {"escape": prepare_info}
    return result_text(info)


def semantic_press_key(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    snapshot = current_snapshot(app)
    key, modifiers = key_from_args(args)
    repeat = args.get("repeat", 1)
    if not isinstance(repeat, int) or repeat < 1:
        repeat = 1
    try:
        element = best_scroll_element(snapshot, "down") or best_scroll_element(snapshot, "up")
        if element is not None:
            x, y = visible_element_center(snapshot, element)
            control_overlay(snapshot, x, y, action="key")
        else:
            x = y = None
            control_overlay(snapshot, action="key")
    except Exception:
        x = y = None
        control_overlay(snapshot, action="key")
    info: dict[str, Any] = {}
    for _ in range(min(repeat, 100)):
        info = keyboard(str(snapshot["target"]), key, modifiers, x, y)
    if info:
        info["repeat"] = min(repeat, 100)
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, info if info else None))


def semantic_set_value(args: dict[str, Any]) -> dict[str, Any]:
    app = str(args.get("app") or "")
    value = args.get("value")
    if not isinstance(value, str):
        raise RuntimeError("Missing required argument: value")
    snapshot, element, refresh_info = element_snapshot_for_action(app, str(args.get("element_index") or ""))
    element_point: tuple[float, float] | None = None
    try:
        x, y = visible_element_center(snapshot, element)
        element_point = (x, y)
        control_overlay(snapshot, x, y, action="set_value")
    except Exception:
        control_overlay(snapshot, action="set_value")
    if not atspi_set_element_value_isolated(snapshot, element, value):
        raise RuntimeError("Cannot set a value for an element that is not settable")
    action_result = {"method": "atspi", "action": "set_value"}
    if element_point is not None:
        action_result["element"] = compact_element_info(element, element_point[0], element_point[1], "screenshot")
    if refresh_info:
        action_result.update(refresh_info)
    return mcp_snapshot_result(snapshot_after_action(app, snapshot, action_result))


def active_sequence_checkpoint() -> None:
    if ACTIVE_SEQUENCE_CANCELLATION is None:
        return
    if ACTIVE_SEQUENCE_CANCELLATION.cancelled:
        raise RuntimeError(ACTIVE_SEQUENCE_CANCELLATION.reason)
    if collect_runtime_guards().panic_active:
        ACTIVE_SEQUENCE_CANCELLATION.cancel("panic is active")
        raise RuntimeError("panic is active")


def semantic_wait(args: dict[str, Any]) -> dict[str, Any]:
    duration = bounded_timeout_seconds(args.get("duration", 1), 1.0)
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        active_sequence_checkpoint()
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    active_sequence_checkpoint()
    return result_text({"ok": True, "duration": duration})


def window_matches_wait(window: dict[str, Any], args: dict[str, Any]) -> bool:
    title = normalize(args.get("title"))
    klass = normalize(args.get("class"))
    if title:
        haystack = normalize(f"{window.get('title') or ''} {window.get('initialTitle') or ''}")
        if title not in haystack:
            return False
    if klass:
        haystack = normalize(f"{window.get('class') or ''} {window.get('initialClass') or ''}")
        if klass not in haystack:
            return False
    if window.get("hidden", False) or not window.get("mapped", True):
        return False
    return True


def wait_window_candidates(args: dict[str, Any]) -> list[dict[str, Any]]:
    related_to = args.get("related_to") or args.get("app")
    if isinstance(related_to, str) and related_to:
        windows = related_windows_for(related_to)
        related = [window for window in windows if isinstance(window, dict) and window.get("hyprAgentPortalRelation") == "related"]
        return [window for window in related if window_matches_wait(window, args)]
    return [window for window in list_hypr_windows() if window_matches_wait(window, args)]


def semantic_wait_for_window(args: dict[str, Any]) -> dict[str, Any]:
    if not any(isinstance(args.get(key), str) and args.get(key) for key in ("app", "related_to", "title", "class")):
        raise RuntimeError("wait_for_window requires app, related_to, title, or class")
    timeout = bounded_timeout_seconds(args.get("timeout", 5), 5.0)
    def candidates_now() -> list[dict[str, Any]]:
        return [window for window in wait_window_candidates(args) if not SECURITY_POLICY.privacy_excluded(window)]

    candidates = candidates_now()
    event_result: dict[str, Any] = {"method": "existing", "eventDriven": False}
    if not candidates:
        filters = {
            key: str(args[key])
            for key in ("title", "class")
            if isinstance(args.get(key), str) and args.get(key)
        }
        if not filters and isinstance(args.get("app"), str) and args.get("app"):
            filters["class"] = str(args["app"])
        # The socket path is resolved internally from the session environment;
        # it is intentionally not exposed as a tool parameter or audit field.
        deadline = time.monotonic() + timeout
        while not candidates and time.monotonic() < deadline:
            event_result = socket2_wait_for_window(
                filters,
                timeout=min(0.25, max(0.0, deadline - time.monotonic())),
                environ=hyprctl_environment(),
                poll_fallback=lambda: candidates_now(),
            )
            candidates = candidates_now()
            active_sequence_checkpoint()
            # A matching socket event may belong to a privacy-excluded window.
            # Keep waiting for an allowed match instead of returning its title
            # or terminating the wait early.
    if not candidates:
        raise RuntimeError(f"wait_for_window timed out after {timeout}s ({event_result.get('method', 'socket2')})")
    candidates.sort(
        key=lambda window: (
            0 if window.get("hyprAgentPortalWindowKind") == "popup" else 1,
            int(window.get("focusHistoryID") if isinstance(window.get("focusHistoryID"), int) else 1_000_000),
        )
    )
    selected = candidates[0]
    snapshot = build_app_snapshot(window_selector(selected))
    wait_backend = sanitize_event_result(event_result)
    event_address = normalize(str(wait_backend.get("address") or "")).removeprefix("0x")
    selected_address = normalize(str(selected.get("address") or "")).removeprefix("0x")
    if not event_address or event_address != selected_address:
        wait_backend.pop("address", None)
    snapshot["lastAction"] = {
        "wait": "window",
        "matchedTarget": snapshot.get("target"),
        "waitBackend": wait_backend,
        "message": "Window appeared; operate this returned target before continuing.",
    }
    return mcp_snapshot_result(snapshot)


def target_exists(target: str) -> bool:
    address = target_address(target)
    if not address:
        try:
            resolve_hypr_window(target)
            return True
        except Exception:
            return False
    for window in list_hypr_windows():
        if address and normalize(window.get("address")) == address:
            return True
    return False


def semantic_wait_for_close(args: dict[str, Any]) -> dict[str, Any]:
    target = args.get("target") or args.get("app")
    if not isinstance(target, str) or not target:
        raise RuntimeError("wait_for_close requires target or app")
    timeout = bounded_timeout_seconds(args.get("timeout", 5), 5.0)
    related_to = args.get("related_to")
    if isinstance(related_to, str) and related_to:
        related_window = resolve_hypr_window(related_to)
        if SECURITY_POLICY.privacy_excluded(related_window):
            raise RuntimeError("related_to window is privacy-excluded")
    try:
        address = str(resolve_hypr_window(target).get("address") or "")
    except Exception:
        address = target_address(target)
    event_result: dict[str, Any] = {"method": "existing", "eventDriven": False}
    if target_exists(target):
        deadline = time.monotonic() + timeout
        while target_exists(target) and time.monotonic() < deadline:
            event_result = socket2_wait_for_close(
                address,
                timeout=min(0.25, max(0.0, deadline - time.monotonic())),
                environ=hyprctl_environment(),
                poll_fallback=lambda: not target_exists(target),
            )
            active_sequence_checkpoint()
    if target_exists(target):
        raise RuntimeError(f"wait_for_close timed out after {timeout}s: {target} is still present")
    event_public = sanitize_event_result(event_result)
    if isinstance(related_to, str) and related_to:
        # Re-resolve after the external wait: the address may have been reused
        # or the selector may now match a privacy-excluded window.
        related_window = resolve_hypr_window(related_to)
        if SECURITY_POLICY.privacy_excluded(related_window):
            raise RuntimeError("related_to window became privacy-excluded while waiting")
        snapshot = build_app_snapshot(window_selector(related_window))
        snapshot["lastAction"] = {
            "wait": "close",
            "targetClosed": True,
            "previousTarget": target,
            "continuedWithTarget": snapshot.get("target"),
            "waitBackend": event_public,
            "message": "The target closed; continue with this related/root window state.",
        }
        return mcp_snapshot_result(snapshot)
    return result_text({"ok": True, "targetClosed": True, "previousTarget": target, "waitBackend": event_public})


def alias_click(button: str, click_count: int) -> Any:
    def call(args: dict[str, Any]) -> dict[str, Any]:
        next_args = dict(args)
        next_args["mouse_button"] = button
        next_args["click_count"] = click_count
        return semantic_click(next_args)

    return call


def accessibility_diagnostics(target: str | None = None) -> dict[str, Any]:
    resolved_env = session_environment()
    atspi_probe = atspi_child_probe()
    diag: dict[str, Any] = {
        "pythonGI": shutil.which("python3") is not None,
        "atspi": atspi_probe,
        "session": {
            "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", ""),
            "DBUS_SESSION_BUS_ADDRESS": os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""),
            "WAYLAND_DISPLAY": os.environ.get("WAYLAND_DISPLAY", ""),
            "DISPLAY": os.environ.get("DISPLAY", ""),
        },
        "hyprland": {
            "XDG_RUNTIME_DIR": resolved_env.get("XDG_RUNTIME_DIR", ""),
            "HYPRLAND_INSTANCE_SIGNATURE": resolved_env.get("HYPRLAND_INSTANCE_SIGNATURE", ""),
            "WAYLAND_DISPLAY": resolved_env.get("WAYLAND_DISPLAY", ""),
            "DBUS_SESSION_BUS_ADDRESS": resolved_env.get("DBUS_SESSION_BUS_ADDRESS", ""),
        },
        "recommendations": [
            "For Qt apps launched after configuration, set QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1.",
            "For Chromium/Chrome launched after configuration, add --force-renderer-accessibility.",
            "Keep Hyprland screenshots enabled; AT-SPI is an enhancement, not the capture source.",
        ],
    }
    proc = subprocess.run(["busctl", "--user", "--list"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=resolved_env, check=False)
    diag["org.a11y.Bus"] = proc.returncode == 0 and "org.a11y.Bus" in proc.stdout
    gsettings = subprocess.run(["gsettings", "get", "org.gnome.desktop.interface", "toolkit-accessibility"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=resolved_env, check=False)
    if gsettings.returncode == 0:
        diag["toolkitAccessibility"] = gsettings.stdout.strip()
    if target:
        try:
            window = resolve_hypr_window(target)
            env_path = pathlib.Path("/proc") / str(int(window.get("pid") or 0)) / "environ"
            values = {}
            for entry in env_path.read_bytes().split(b"\0"):
                if b"=" not in entry:
                    continue
                key, value = entry.split(b"=", 1)
                decoded_key = key.decode("utf-8", "ignore")
                if decoded_key in {"QT_LINUX_ACCESSIBILITY_ALWAYS_ON", "NO_AT_BRIDGE", "GTK_MODULES", "GTK_USE_PORTAL", "QT_QPA_PLATFORM", "WAYLAND_DISPLAY", "DISPLAY"}:
                    values[decoded_key] = value.decode("utf-8", "ignore")
            diag["target"] = {"window": window, "environment": values}
        except Exception as exc:
            diag["targetError"] = str(exc)
    return diag


def tool_security_status(_: dict[str, Any]) -> dict[str, Any]:
    runtime_guards = collect_runtime_guards()
    policy_state = SECURITY_POLICY.state()
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    mutation_lease_path = (
        str(pathlib.Path(runtime_dir) / "hypr-agent-portal" / "mutation.lock")
        if runtime_dir
        else ""
    )
    diagnostics = security_readiness_diagnostics(
        {
            "readonly": policy_state["readonly"],
            "dry_run": policy_state["dryRun"],
            "confinement": policy_state["confinementEnabled"],
            "app_policy": dict(SECURITY_POLICY.config.app_authorizations),
            "clipboard_policy": sorted(item.value for item in SECURITY_POLICY.config.clipboard_permissions),
            "privacy_policy": sorted(SECURITY_POLICY.config.privacy_classes),
            "audit_enabled": SECURITY_AUDIT is not None,
            "audit_path": str(SECURITY_AUDIT.path) if SECURITY_AUDIT is not None else "",
            "lockscreen_protection": SECURITY_POLICY.config.block_locked_mutation,
            "mutation_lease_path": str(PROCESS_MUTATION_LEASE.path) if PROCESS_MUTATION_LEASE is not None else mutation_lease_path,
            "panic_enabled": True,
        },
        lockscreen_indicators=SECURITY_POLICY.detect_lock_screen(),
        panic_probe=lambda: (
            runtime_guards.available,
            "native guard dispatcher is available" if runtime_guards.available else runtime_guards.error,
        ),
    )
    result = {
        "policy": policy_state,
        "readiness": diagnostics,
        "legacyEnvironment": [
            {"canonical": item.canonical, "legacy": item.legacy}
            for item in LEGACY_ENVIRONMENT_USES
        ],
        "runtimeGuards": {
            "available": runtime_guards.available,
            "screenLocked": runtime_guards.screen_locked,
            "layerSurfaceActive": runtime_guards.layer_surface_active,
            "keyboardGrabActive": runtime_guards.keyboard_grab_active,
            "panicActive": runtime_guards.panic_active,
            "error": runtime_guards.error,
            "humanTakeoverScope": "native in-flight cancellation only; human input is not exposed as a persistent cross-path MCP latch",
        },
    }
    return mcp_text(json.dumps(result, ensure_ascii=False), structured=result)


def tool_request_confirmation(args: dict[str, Any]) -> dict[str, Any]:
    tool_name = args.get("tool_name")
    arguments = args.get("arguments")
    if not isinstance(tool_name, str) or not tool_name:
        raise RuntimeError("request_confirmation requires tool_name")
    if not isinstance(arguments, dict):
        raise RuntimeError("request_confirmation requires an arguments object")
    if tool_name in {"request_confirmation", "security_status", "audit_replay"}:
        raise RuntimeError(f"confirmation cannot target {tool_name}")
    clean_arguments = {key: value for key, value in arguments.items() if key != "confirmation_token"}
    clean_arguments, resolved_target = prepare_execution_args(tool_name, clean_arguments)
    request = build_security_request(tool_name, clean_arguments, force_destructive=True, resolved_target=resolved_target)
    if not request.mutating:
        raise RuntimeError("confirmation tokens are only issued for mutating actions")
    challenge_id = SECURITY_POLICY.request_confirmation(request)
    result = {
        "ok": True,
        "toolName": tool_name,
        "action": request.action,
        "target": request.target.fingerprint() if request.target else None,
        "challengeId": challenge_id,
        "expiresInSeconds": SECURITY_POLICY.config.confirmation_ttl_seconds,
        "approvalCommand": f"python3 mcp/security_policy.py approve {challenge_id}",
        "next": "Ask a person to run approvalCommand in an independent local interactive terminal, then repeat the exact tool call once with confirmation_token set to challengeId.",
    }
    return mcp_text(json.dumps(result, ensure_ascii=False), structured=result)


def tool_panic(args: dict[str, Any]) -> dict[str, Any]:
    global SERVER_PANIC_ACTIVE
    mode = str(args.get("mode") or "panic").casefold()
    if mode not in {"panic", "cancel", "resume", "status"}:
        raise RuntimeError("panic mode must be panic, cancel, resume, or status")
    info = call_ctl(["panic", mode, "--json"])
    if mode == "panic":
        SERVER_PANIC_ACTIVE = True
        with SEQUENCE_STATE_LOCK:
            if ACTIVE_SEQUENCE_CANCELLATION is not None:
                ACTIVE_SEQUENCE_CANCELLATION.cancel("panic requested")
        SNAPSHOTS.clear()
        VISUAL_CACHE.clear()
    elif mode == "cancel":
        # One-shot cancellation stops in-flight native work but deliberately
        # does not create a cross-path latch or synthetic human cooldown.
        SNAPSHOTS.clear()
        VISUAL_CACHE.clear()
        with SEQUENCE_STATE_LOCK:
            if ACTIVE_SEQUENCE_CANCELLATION is not None:
                ACTIVE_SEQUENCE_CANCELLATION.cancel("cancel requested")
    elif mode == "resume":
        SERVER_PANIC_ACTIVE = False
        SECURITY_POLICY.clear_human_takeover()
    elif mode == "status" and isinstance(info.get("panicActive"), bool):
        SERVER_PANIC_ACTIVE = info["panicActive"]
    return result_text(info)


def replay_target_identity(target: Any) -> dict[str, Any] | None:
    if isinstance(target, dict):
        selector = target.get("address") or target.get("target")
    else:
        selector = target
    if not isinstance(selector, str) or not selector:
        return None
    window = resolve_hypr_window(selector)
    return dict(WindowIdentity.from_window(window).fingerprint())


def tool_audit_replay(args: dict[str, Any]) -> dict[str, Any]:
    if SECURITY_AUDIT is None:
        raise RuntimeError("audit logging is not enabled")
    execute = bool(args.get("execute", False))
    allow_clipboard = bool(args.get("allow_clipboard", False))
    max_age = args.get("max_record_age_seconds", 300.0)
    if not isinstance(max_age, (int, float)) or isinstance(max_age, bool) or max_age < 0:
        raise RuntimeError("max_record_age_seconds must be a non-negative number")
    records = SECURITY_AUDIT.read()
    replay = preflight_replay(
        records,
        resolve_target=replay_target_identity,
        policy=ReplayPolicy(
            execute=execute,
            allow_clipboard=allow_clipboard,
            readonly=SECURITY_POLICY.config.readonly,
            dry_run=SECURITY_POLICY.config.dry_run,
            max_record_age_seconds=float(max_age),
        ),
    )
    results: list[dict[str, Any]] = []
    if execute:
        for decision in replay.decisions:
            if not decision.executable:
                continue
            record = decision.record
            tool_name = str(record.get("tool") or "")
            tool_args = record.get("args")
            if tool_name in {"audit_replay", "request_confirmation", "security_status", "panic"} or not isinstance(tool_args, dict):
                results.append({"eventId": decision.event_id, "ok": False, "error": "unsupported replay entry"})
                break
            nested = handle(
                {
                    "jsonrpc": "2.0",
                    "id": f"replay:{decision.event_id}",
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": tool_args},
                }
            )
            nested_result = nested.get("result") if isinstance(nested, dict) else None
            ok = isinstance(nested_result, dict) and nested_result.get("isError") is not True
            results.append({"eventId": decision.event_id, "ok": ok, "result": nested_result})
            if not ok:
                break
    structured = {
        "planOnly": replay.plan_only,
        "decisions": [
            {
                "eventId": item.event_id,
                "tool": item.tool,
                "accepted": item.accepted,
                "executable": item.executable,
                "reasons": list(item.reasons),
            }
            for item in replay.decisions
        ],
        "results": results,
    }
    return mcp_text(json.dumps(structured, ensure_ascii=False), structured=structured)


def visual_snapshot_for_args(args: dict[str, Any], kind: str, id_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = visual_cache_entry(args.get(id_key), kind)
    snapshot = entry["snapshot"]
    app = args.get("app")
    if isinstance(app, str) and app:
        resolved = resolve_hypr_window(app)
        if normalize(resolved.get("address")) != entry["address"]:
            raise RuntimeError("visual cache target does not match app")
    return snapshot, entry


def tool_ocr(args: dict[str, Any]) -> dict[str, Any]:
    validate_visual_request_limits(args)
    app = args.get("app")
    if not isinstance(app, str) or not app:
        raise RuntimeError("ocr requires app")
    snapshot = build_app_snapshot(app)
    raw = base64.b64decode(str(snapshot.get("screenshotPngBase64") or ""), validate=True)
    ocr_transform = None
    if isinstance(args.get("region"), dict):
        raw, ocr_transform = transform_image(
            raw,
            screenshot=snapshot.get("screenshot"),
            window=snapshot.get("window"),
            region=args["region"],
            coordinate_space=str(args.get("coordinate_space") or "screenshot"),
            output_format="png",
        )
    result = ocr_image(
        raw,
        backend=str(args.get("backend") or "auto"),
        language=args.get("language") if isinstance(args.get("language"), str) else None,
        page_segmentation_mode=args.get("page_segmentation_mode") if isinstance(args.get("page_segmentation_mode"), int) else None,
        timeout=bounded_timeout_seconds(args.get("timeout", 15), 15.0),
    )
    words = []
    for word in result.get("words") or []:
        if not isinstance(word, dict):
            continue
        item = dict(word)
        if ocr_transform is not None and isinstance(item.get("bbox"), dict):
            bbox = item["bbox"]
            affine = ocr_transform["mappings"]["outputToScreenshot"]
            top_left = map_point({"x": bbox.get("x"), "y": bbox.get("y")}, affine)
            bottom_right = map_point(
                {"x": float(bbox.get("x") or 0) + float(bbox.get("width") or 0), "y": float(bbox.get("y") or 0) + float(bbox.get("height") or 0)},
                affine,
            )
            item["bbox"] = {
                "x": top_left["x"],
                "y": top_left["y"],
                "width": bottom_right["x"] - top_left["x"],
                "height": bottom_right["y"] - top_left["y"],
                "right": bottom_right["x"],
                "bottom": bottom_right["y"],
            }
        confidence = item.get("confidence")
        if isinstance(confidence, (int, float)):
            item["confidence"] = max(0.0, min(1.0, float(confidence) / 100.0))
        words.append(item)
    payload = {
        **result,
        "words": words,
        "regions": words,
        "confidenceScale": "0-1",
        "coordinateSpace": "screenshot",
        "binding": make_snapshot_binding(snapshot),
        "captureTransform": ocr_transform,
    }
    ocr_id = cache_visual("ocr", payload, snapshot)
    structured = {**payload, "ocrId": ocr_id, "snapshotId": snapshot.get("snapshotId")}
    return mcp_text(json.dumps(structured, ensure_ascii=False), structured=structured)


def _resolved_click_args(args: dict[str, Any], *, kind: str, id_key: str, locator: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    snapshot, entry = visual_snapshot_for_args(args, kind, id_key)
    ocr_result = entry["payload"] if kind == "ocr" else None
    mark_set = entry["payload"] if kind == "marks" else None
    resolved = resolve_click_target(snapshot, locator, ocr_result=ocr_result, mark_set=mark_set)
    click_args = {
        "app": str(snapshot["target"]),
        "coordinate": [resolved.point["x"], resolved.point["y"]],
        "coordinate_space": "screenshot",
        "mouse_button": str(args.get("mouse_button") or "left"),
        "click_count": int(args.get("click_count") or 1),
    }
    return click_args, resolved.to_dict()


def tool_click_text(args: dict[str, Any]) -> dict[str, Any]:
    text_value = args.get("text")
    if not isinstance(text_value, str) or not text_value:
        raise RuntimeError("click_text requires text")
    if str(args.get("match") or "exact") not in {"exact", "contains"}:
        raise RuntimeError("match must be exact or contains")
    locator = {
        "ocr": {
            "text": text_value,
            "match": str(args.get("match") or "exact"),
            "casefold": args.get("casefold", True) is not False,
            "nth": int(args.get("nth") or 1),
        }
    }
    click_args, resolved = _resolved_click_args(args, kind="ocr", id_key="ocr_id", locator=locator)
    result = semantic_click(click_args)
    result.setdefault("structuredContent", {})["resolvedVisualTarget"] = resolved
    return result


def tool_get_marks(args: dict[str, Any]) -> dict[str, Any]:
    validate_visual_request_limits(args)
    snapshot_id = args.get("snapshot_id")
    if isinstance(snapshot_id, str) and snapshot_id:
        snapshot_entry = visual_cache_entry(snapshot_id, "snapshot")
    else:
        app_value = args.get("app")
        if not isinstance(app_value, str) or not app_value:
            raise RuntimeError("get_marks requires app")
        fresh = build_app_snapshot(app_value)
        snapshot_id = fresh["snapshotId"]
        snapshot_entry = visual_cache_entry(snapshot_id, "snapshot", validate_live=False)
    snapshot = snapshot_entry["snapshot"]
    app = args.get("app")
    if isinstance(app, str) and app and normalize(resolve_hypr_window(app).get("address")) != snapshot_entry["address"]:
        raise RuntimeError("snapshot target does not match app")
    candidates: list[dict[str, Any]] = []
    if args.get("include_elements", True) is not False:
        for element in snapshot.get("elements") or []:
            if not isinstance(element, dict) or not isinstance(element.get("frame"), dict):
                continue
            if (
                not element_role_is_actionable(element_role(element))
                and not element_is_editable(element)
                and not element_has_primary_atspi_action(element)
            ):
                continue
            candidates.append({"source": "element", "frame": element["frame"], "index": element.get("index"), "name": element.get("name")})
    ocr_entry = None
    if isinstance(args.get("ocr_id"), str):
        ocr_entry = visual_cache_entry(args["ocr_id"], "ocr")
        if ocr_entry["sha256"] != snapshot_entry["sha256"] or ocr_entry["address"] != snapshot_entry["address"]:
            raise RuntimeError("OCR and snapshot bindings do not match")
        for index, region in enumerate(ocr_entry["payload"].get("regions") or []):
            if isinstance(region, dict) and isinstance(region.get("bbox"), dict):
                candidates.append({"source": "ocr", "frame": region["bbox"], "ocr_index": index, "text": region.get("text")})
    raw = base64.b64decode(str(snapshot.get("screenshotPngBase64") or ""), validate=True)
    encoded, metadata = render_marks(
        raw,
        candidates,
        screenshot=snapshot.get("screenshot"),
        window=snapshot.get("window"),
        region=args.get("region") if isinstance(args.get("region"), dict) else None,
        coordinate_space=str(args.get("coordinate_space") or "screenshot"),
        scale=args.get("scale") if isinstance(args.get("scale"), (int, float)) else None,
        zoom=args.get("zoom") if isinstance(args.get("zoom"), (int, float)) else None,
        output_format=str(args.get("format") or "png"),
        quality=int(args.get("quality") or 85),
        max_dimension=int(args["max_dimension"]) if isinstance(args.get("max_dimension"), int) else None,
    )
    marks = []
    for mark in metadata.get("marks") or []:
        marks.append(
            {
                "id": str(mark["markId"]),
                "source": mark.get("source"),
                "frame": mark.get("screenshotBox"),
                "elementIndex": mark.get("elementIndex"),
                "ocrIndex": mark.get("ocrIndex"),
                "text": mark.get("text"),
                "name": mark.get("name"),
                "point": mark.get("screenshotPoint"),
            }
        )
    payload = {"binding": make_snapshot_binding(snapshot), "marks": marks, "render": metadata}
    marks_id = cache_visual("marks", payload, snapshot)
    structured = {"marksId": marks_id, "snapshotId": snapshot_id, **payload}
    return {
        "content": [
            {"type": "text", "text": json.dumps(structured, ensure_ascii=False)},
            {"type": "image", "mimeType": f"image/{metadata['output']['format']}", "data": base64.b64encode(encoded).decode("ascii")},
        ],
        "structuredContent": structured,
        "isError": False,
    }


def tool_click_mark(args: dict[str, Any]) -> dict[str, Any]:
    click_args, resolved = _resolved_click_args(
        args,
        kind="marks",
        id_key="marks_id",
        locator={"mark_id": args.get("mark_id")},
    )
    result = semantic_click(click_args)
    result.setdefault("structuredContent", {})["resolvedVisualTarget"] = resolved
    return result


def tool_type_into(args: dict[str, Any]) -> dict[str, Any]:
    text_value = args.get("text")
    if not isinstance(text_value, str) or not text_value:
        raise RuntimeError("type_into requires non-empty text")
    entry: dict[str, Any]
    ocr_result = None
    mark_set = None
    locator = args.get("locator") if isinstance(args.get("locator"), dict) else {}
    visual_ids = sum(isinstance(args.get(key), str) and bool(args.get(key)) for key in ("ocr_id", "marks_id", "snapshot_id"))
    if visual_ids > 1:
        raise RuntimeError("type_into requires exactly one snapshot/OCR/marks binding")
    locator_match = locator.get("match")
    locator_ocr = locator.get("ocr") if isinstance(locator.get("ocr"), dict) else {}
    if str(locator_match or locator_ocr.get("match") or args.get("match") or "exact") not in {"exact", "contains"}:
        raise RuntimeError("type_into match must be exact or contains")
    if isinstance(args.get("ocr_id"), str):
        if any(key in args for key in ("element_index", "accessible_name", "accessible_text", "marks_id", "snapshot_id")):
            raise RuntimeError("type_into OCR targeting cannot be combined with another locator")
        _, entry = visual_snapshot_for_args(args, "ocr", "ocr_id")
        ocr_result = entry["payload"]
        locator = dict(locator) or {"ocr": {"text": args.get("target_text"), "match": args.get("match", "exact"), "nth": args.get("nth", 1)}}
    elif isinstance(args.get("marks_id"), str):
        if any(key in args for key in ("element_index", "accessible_name", "accessible_text", "ocr_id", "snapshot_id")):
            raise RuntimeError("type_into mark targeting cannot be combined with another locator")
        _, entry = visual_snapshot_for_args(args, "marks", "marks_id")
        mark_set = entry["payload"]
        locator = dict(locator) or {"mark_id": args.get("mark_id")}
    else:
        if isinstance(args.get("snapshot_id"), str):
            _, entry = visual_snapshot_for_args(args, "snapshot", "snapshot_id")
        else:
            app_value = args.get("app")
            if not isinstance(app_value, str) or not app_value:
                raise RuntimeError("type_into requires app")
            fresh = build_app_snapshot(app_value)
            entry = visual_cache_entry(fresh["snapshotId"], "snapshot", validate_live=False)
        locator = dict(locator) or {key: args[key] for key in ("element_index", "accessible_name", "accessible_text", "name", "match", "nth", "casefold") if key in args}
        selector_count = sum(key in locator for key in ("element_index", "elementIndex"))
        selector_count += int(any(key in locator for key in ("accessible_name", "name")))
        selector_count += int(any(key in locator for key in ("accessible_text", "text")))
        if selector_count != 1:
            raise RuntimeError("type_into requires exactly one editable element locator")
    snapshot = entry["snapshot"]
    resolved = resolve_type_into_target(snapshot, locator, ocr_result=ocr_result, mark_set=mark_set)
    original_element = resolved.get("element") if isinstance(resolved.get("element"), dict) else {}
    identity_fields = ("runtimeId", "automationId", "path", "accessiblePath", "name", "controlType", "localizedControlType", "frame")
    original_identity = {key: original_element.get(key) for key in identity_fields}
    focus_result = semantic_click({"app": snapshot["target"], "element_index": str(resolved["elementIndex"])})
    focus_state = focus_result.get("structuredContent") if isinstance(focus_result, dict) else None
    if not isinstance(focus_state, dict):
        raise RuntimeError("type_into could not refresh state after focusing")
    if focus_state.get("attention") or (focus_state.get("lastAction") or {}).get("targetClosed"):
        raise RuntimeError("type_into target changed or opened a popup while focusing; inspect refreshed state")
    refreshed = build_app_snapshot(str(snapshot["target"]))
    verified = resolve_type_into_target(refreshed, {"element_index": str(resolved["elementIndex"])})
    refreshed_element = verified.get("element") if isinstance(verified.get("element"), dict) else {}
    refreshed_identity = {key: refreshed_element.get(key) for key in identity_fields}
    if refreshed_identity != original_identity:
        raise RuntimeError("type_into target became stale after focus: editable control identity changed")
    focused_states = refreshed_element.get("states")
    reports_focused = refreshed_element.get("focused") is True or (
        isinstance(focused_states, list) and any(normalize(state) == "focused" for state in focused_states)
    )
    if not element_is_editable(refreshed_element) or not reports_focused:
        raise RuntimeError("type_into target did not remain editable and focused after the focus refresh")
    requested_method = str(args.get("method") or "auto")
    runtime_id = refreshed_element.get("runtimeId")
    if requested_method == "atspi" and not isinstance(runtime_id, list):
        raise RuntimeError("type_into method=atspi requires an exact AT-SPI runtimeId for the verified editable target")
    type_result = semantic_type_text(
        {
            "app": refreshed["target"],
            "text": text_value,
            "method": requested_method,
            "_atspi_runtime_id": runtime_id,
        }
    )
    type_result.setdefault("structuredContent", {})["typeInto"] = {
        "source": resolved["source"],
        "elementIndex": verified["elementIndex"],
        "editableVerified": True,
        "stateRefreshedBeforeInput": True,
    }
    return type_result


def require_resulting_workspace_scope(workspace: Any, window: dict[str, Any] | None = None) -> None:
    selector = normalize_workspace(workspace)
    identity_workspace = selector.split(":", 1)[1] if selector.startswith("name:") else selector
    if window is None:
        identity = WindowIdentity(address=f"workspace:{selector}", class_name="hyprland-workspace", workspace=identity_workspace)
    else:
        current = WindowIdentity.from_window(window)
        identity = WindowIdentity(
            address=current.address,
            class_name=current.class_name,
            workspace=identity_workspace,
            pid=current.pid,
            process_start_time=current.process_start_time,
            launched=current.launched,
        )
    if not SECURITY_POLICY._in_scope(identity):
        raise RuntimeError(f"resulting workspace {selector} is outside configured confinement")


def tool_manage_window(args: dict[str, Any]) -> dict[str, Any]:
    action = str(args.get("window_action") or args.get("action") or "")
    target = args.get("app") or args.get("target") or args.get("address")
    if not isinstance(target, str) or not target:
        raise RuntimeError("manage_window requires app/target/address")
    window = resolve_hypr_window(target)
    options = {key: value for key, value in args.items() if key not in {"action", "window_action", "app", "target", "address", "confirmation_token"}}
    inverse = {
        "restore": "minimize",
        "unmaximize": "maximize",
        "unfullscreen": "fullscreen",
        "tiled": "floating",
        "unpin": "pin",
    }
    if action in inverse:
        action = inverse[action]
        options["enabled"] = False
    if action == "move_to_workspace":
        require_resulting_workspace_scope(options.get("workspace"), window)
    elif action == "minimize":
        enabled = options.get("enabled", True) is not False
        destination = options.get("minimized_workspace", "special:hypr-agent-portal-minimized") if enabled else options.get("restore_workspace")
        if destination is None and SECURITY_POLICY.config.confinement.enabled:
            raise RuntimeError("restore_workspace is required under confinement")
        if destination is not None:
            require_resulting_workspace_scope(destination, window)
    result = HYPR_MANAGEMENT.window_action(action, str(window["address"]), **options)
    return result_text(result.to_dict())


def tool_list_workspaces(args: dict[str, Any]) -> dict[str, Any]:
    workspaces = HYPR_MANAGEMENT.list_workspaces(include_special=args.get("include_special", True) is not False)
    redacted = [
        {key: value for key, value in workspace.items() if normalize(key) not in {"lastwindow", "lastwindowtitle"}}
        for workspace in workspaces
        if isinstance(workspace, dict)
    ]
    return result_text({"workspaces": redacted})


def visible_special_workspaces() -> set[str]:
    monitors = hyprctl_json("monitors", "-j")
    visible: set[str] = set()
    for monitor in monitors if isinstance(monitors, list) else []:
        special = monitor.get("specialWorkspace") if isinstance(monitor, dict) else None
        if not isinstance(special, dict):
            continue
        name = str(special.get("name") or "")
        if name:
            visible.add(name)
    return visible


def dispatch_special_workspace(workspace: Any, action: str) -> dict[str, Any]:
    selector = normalize_workspace(workspace)
    if selector != "special" and not selector.startswith("special:"):
        raise RuntimeError(f"{action} requires special or special:NAME")
    before = visible_special_workspaces()
    default_special_names = {"special", "special:special"}
    shown = selector in before or (selector == "special" and bool(default_special_names & before))
    should_dispatch = action == "toggle_special" or (action == "show_special" and not shown) or (action == "hide_special" and shown)
    command: list[str] | None = None
    if should_dispatch:
        command = list(HYPR_MANAGEMENT.special_workspace(action, selector))
    after = visible_special_workspaces()
    now_shown = selector in after or (selector == "special" and bool(default_special_names & after))
    expected = (not shown) if action == "toggle_special" else action == "show_special"
    if now_shown != expected:
        raise RuntimeError(f"{action} verification failed for {selector}")
    return {
        "action": action,
        "target": selector,
        "commands": [command] if command else [],
        "before": {"visible": shown, "specialWorkspaces": sorted(before)},
        "after": {"visible": now_shown, "specialWorkspaces": sorted(after)},
        "changed": should_dispatch,
        "verified": True,
        "mutating": True,
        "destructive": False,
    }


def tool_manage_workspace(args: dict[str, Any]) -> dict[str, Any]:
    action = str(args.get("workspace_action") or args.get("action") or "")
    options = {key: value for key, value in args.items() if key not in {"action", "workspace_action", "confirmation_token", "app", "target"}}
    if action in {"show_special", "hide_special", "toggle_special"}:
        return result_text(dispatch_special_workspace(args.get("workspace"), action))
    if action in {"move_window", "move_window_to_workspace"}:
        target = args.get("app") or args.get("target") or args.get("address")
        if not isinstance(target, str) or not target:
            raise RuntimeError("workspace move_window requires app/target/address")
        window = resolve_hypr_window(target)
        require_resulting_workspace_scope(options.get("workspace"), window)
        options["address"] = str(window["address"])
    elif action == "rename":
        require_resulting_workspace_scope(args.get("workspace"))
        require_resulting_workspace_scope(f"name:{args.get('new_name')}")
    result = HYPR_MANAGEMENT.workspace_action(action, **options)
    return result_text(result.to_dict() if hasattr(result, "to_dict") else {"workspaces": result})


def tool_sequence(args: dict[str, Any]) -> dict[str, Any]:
    global ACTIVE_SEQUENCE_CANCELLATION, PENDING_SEQUENCE_CANCEL, SEQUENCE_WORKER_PENDING
    token = CancellationToken()
    with SEQUENCE_STATE_LOCK:
        SEQUENCE_WORKER_PENDING = False
        if ACTIVE_SEQUENCE_CANCELLATION is not None:
            raise RuntimeError("sequence_active: another action sequence is already running")
        ACTIVE_SEQUENCE_CANCELLATION = token
        if PENDING_SEQUENCE_CANCEL:
            token.cancel("cancelled before sequence startup")
            PENDING_SEQUENCE_CANCEL = False
    raw_steps = args.get("steps") or []
    if len(json.dumps(raw_steps, ensure_ascii=False).encode("utf-8")) > 1024 * 1024:
        with SEQUENCE_STATE_LOCK:
            if ACTIVE_SEQUENCE_CANCELLATION is token:
                ACTIVE_SEQUENCE_CANCELLATION = None
        raise RuntimeError("sequence payload exceeds the 1 MiB limit")
    forbidden_controls = {"sequence", "panic", "request_confirmation", "audit_replay", "security_status"}
    for index, step in enumerate(raw_steps if isinstance(raw_steps, list) else []):
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or step.get("tool") or "").casefold()
        arguments = step.get("arguments", step.get("args", {}))
        nested = str(arguments.get("action") or "").casefold() if isinstance(arguments, dict) else ""
        if action in forbidden_controls or (action == "computer" and nested in forbidden_controls):
            with SEQUENCE_STATE_LOCK:
                if ACTIVE_SEQUENCE_CANCELLATION is token:
                    ACTIVE_SEQUENCE_CANCELLATION = None
            raise RuntimeError(f"sequence step {index} cannot invoke control action {action or nested}")
    started = time.monotonic()

    def panic_probe() -> bool:
        return bool(collect_runtime_guards().panic_active)

    def execute_step(step: Any, context: Any) -> dict[str, Any]:
        context.checkpoint()
        if time.monotonic() - started > MAX_TOOL_WAIT_SECONDS:
            token.cancel("sequence exceeded the 30 second limit")
            context.checkpoint()
        name = str(step.action)
        step_args = dict(step.arguments)
        if name not in SEMANTIC_TOOLS:
            step_args["action"] = name
            name = "computer"
        nested = handle({"jsonrpc": "2.0", "id": f"sequence:{context.sequence_id}:{context.step_index}", "method": "tools/call", "params": {"name": name, "arguments": step_args}})
        if not isinstance(nested, dict):
            raise RuntimeError("sequence step produced no response")
        return nested.get("result", nested)

    try:
        sequence_dry_run = SECURITY_POLICY.config.dry_run or args.get("dry_run", False) is True

        def preview_step(step: Any, context: Any) -> dict[str, Any]:
            name = str(step.action)
            step_args = dict(step.arguments)
            if name not in SEMANTIC_TOOLS:
                step_args["action"] = name
                name = "computer"
            step_args, resolved_target = prepare_execution_args(name, step_args)
            if sequence_dry_run and not SECURITY_POLICY.config.dry_run:
                request = build_security_request(name, step_args, dry_run_preview=True, resolved_target=resolved_target)
                return SECURITY_POLICY.evaluate(request, GuardInputs(), preview_dry_run=True).to_dict()
            request = build_security_request(name, step_args, resolved_target=resolved_target)
            guards = GuardInputs() if sequence_dry_run else collect_runtime_guards()
            return SECURITY_POLICY.evaluate(request, guards).to_dict()

        result = run_action_sequence(
            args.get("steps") or [],
            executor=execute_step,
            policy_probe=preview_step if sequence_dry_run else None,
            stop_on_error=args.get("stop_on_error", True) is not False,
            dry_run=sequence_dry_run,
            cancellation=token,
            panic_probe=panic_probe,
            max_steps=min(128, int(args.get("max_steps") or 128)),
        )
        return result_text(result)
    finally:
        with SEQUENCE_STATE_LOCK:
            if ACTIVE_SEQUENCE_CANCELLATION is token:
                ACTIVE_SEQUENCE_CANCELLATION = None


SEMANTIC_TOOLS = {
    "list_apps": tool_list_apps,
    "list_windows": tool_list_apps,
    "launch_app": tool_launch_app,
    "open_app": tool_launch_app,
    "get_app_state": tool_get_app_state,
    "read_app_state": tool_get_app_state,
    "screenshot": tool_screenshot,
    "get_screenshot": tool_screenshot,
    "get_cursor_position": tool_get_cursor_position,
    "click": semantic_click,
    "left_click": alias_click("left", 1),
    "right_click": alias_click("right", 1),
    "middle_click": alias_click("middle", 1),
    "double_click": alias_click("left", 2),
    "triple_click": alias_click("left", 3),
    "perform_secondary_action": semantic_perform_secondary_action,
    "activate_menu_item": semantic_activate_menu_item,
    "scroll": semantic_scroll,
    "drag": semantic_drag,
    "left_click_drag": semantic_drag,
    "hover": semantic_hover,
    "move_mouse": semantic_hover,
    "type_text": semantic_type_text,
    "type": semantic_type_text,
    "paste_text": semantic_paste_text,
    "press_key": semantic_press_key,
    "key": semantic_press_key,
    "set_value": semantic_set_value,
    "wait": semantic_wait,
    "wait_for_window": semantic_wait_for_window,
    "wait_for_close": semantic_wait_for_close,
    "security_status": tool_security_status,
    "request_confirmation": tool_request_confirmation,
    "panic": tool_panic,
    "audit_replay": tool_audit_replay,
    "ocr": tool_ocr,
    "click_text": tool_click_text,
    "get_marks": tool_get_marks,
    "click_mark": tool_click_mark,
    "type_into": tool_type_into,
    "sequence": tool_sequence,
    "manage_window": tool_manage_window,
    "list_workspaces": tool_list_workspaces,
    "manage_workspace": tool_manage_workspace,
}


def computer(args: dict[str, Any]) -> dict[str, Any]:
    action = str(args.get("action") or "")

    richer = {
        "set_value": semantic_set_value,
        "ocr": tool_ocr,
        "click_text": tool_click_text,
        "get_marks": tool_get_marks,
        "click_mark": tool_click_mark,
        "type_into": tool_type_into,
        "sequence": tool_sequence,
        "manage_window": tool_manage_window,
        "list_workspaces": tool_list_workspaces,
        "manage_workspace": tool_manage_workspace,
    }
    if action == "perform_secondary_action":
        mapped = dict(args)
        mapped["action"] = str(args.get("secondary_action") or "")
        return semantic_perform_secondary_action(mapped)
    if action in richer:
        return richer[action](args)
    if action == "screenshot":
        return tool_screenshot(args)

    if action in {"launch", "launch_app", "open_app"}:
        return tool_launch_app(args)
    if action in {"get_app_state", "read_app_state"}:
        return tool_get_app_state(args)
    if action == "wait_for_window":
        return semantic_wait_for_window(args)
    if action == "wait_for_close":
        return semantic_wait_for_close(args)

    app = args.get("app")
    if isinstance(app, str) and app:
        if action == "get_cursor_position":
            return tool_get_cursor_position(args)
        if action == "left_click":
            return alias_click("left", 1)(args)
        if action == "right_click":
            return alias_click("right", 1)(args)
        if action == "middle_click":
            return alias_click("middle", 1)(args)
        if action == "double_click":
            return alias_click("left", 2)(args)
        if action == "triple_click":
            return alias_click("left", 3)(args)
        if action == "hover":
            return semantic_hover(args)
        if action == "left_click_drag":
            return semantic_drag(args)
        if action == "click":
            return semantic_click(args)
        if action == "doubleclick":
            next_args = dict(args)
            next_args["click_count"] = 2
            return semantic_click(next_args)
        if action == "move":
            return semantic_hover(args)
        if action == "scroll":
            next_args = dict(args)
            if "direction" not in next_args and isinstance(args.get("scroll_direction"), str):
                next_args["direction"] = args.get("scroll_direction")
            if "pages" not in next_args and isinstance(args.get("scroll_amount"), (int, float)):
                next_args["pages"] = max(1.0, float(args["scroll_amount"]) / 5.0)
            return semantic_scroll(next_args)
        if action == "drag":
            return semantic_drag(args)
        if action == "type":
            return semantic_type_text(args)
        if action == "paste_text":
            return semantic_paste_text(args)
        if action == "key":
            return semantic_press_key(args)
        if action == "activate_menu_item":
            return semantic_activate_menu_item(args)

    if action == "get_cursor_position":
        return tool_get_cursor_position(args)
    if action in {"left_click", "right_click", "middle_click", "double_click", "triple_click", "hover"}:
        mapped = dict(args)
        mapped["action"] = "move" if action == "hover" else ("doubleclick" if action in {"double_click", "triple_click"} else "click")
        mapped["button"] = {
            "left_click": "left",
            "right_click": "right",
            "middle_click": "middle",
            "double_click": "left",
            "triple_click": "left",
            "hover": "left",
        }[action]
        args = mapped
        action = str(args["action"])

    if action == "left_click_drag":
        start = coordinate_pair(args.get("start_coordinate"))
        end = coordinate_pair(args.get("coordinate"))
        if start is None or end is None:
            raise RuntimeError("left_click_drag requires start_coordinate and coordinate")
        mapped = dict(args)
        mapped.update({"action": "drag", "x": start[0], "y": start[1], "x2": end[0], "y2": end[1], "button": "left"})
        args = mapped
        action = "drag"

    target = args.get("target")
    coordinate_space = normalize(args.get("coordinate_space") or "screenshot")
    if (
        isinstance(target, str)
        and target
        and not isinstance(args.get("app"), str)
        and coordinate_space in {"screenshot", "window", "screenshot-pixel", "screenshot-pixels", "image", "pixel", "pixels", "window-relative", "window-logical", "logical"}
    ):
        mapped = dict(args)
        mapped["app"] = target
        if action == "move":
            return semantic_hover(mapped)
        if action == "click":
            return semantic_click(mapped)
        if action == "doubleclick":
            mapped["click_count"] = 2
            return semantic_click(mapped)
        if action == "scroll":
            if "direction" not in mapped and isinstance(args.get("scroll_direction"), str):
                mapped["direction"] = args.get("scroll_direction")
            if "pages" not in mapped and isinstance(args.get("scroll_amount"), (int, float)):
                mapped["pages"] = max(1.0, float(args["scroll_amount"]) / 5.0)
            return semantic_scroll(mapped)
        if action == "drag":
            if "start_coordinate" not in mapped and isinstance(args.get("x"), (int, float)) and isinstance(args.get("y"), (int, float)):
                mapped["start_coordinate"] = [float(args["x"]), float(args["y"])]
            if "coordinate" not in mapped and isinstance(args.get("x2"), (int, float)) and isinstance(args.get("y2"), (int, float)):
                mapped["coordinate"] = [float(args["x2"]), float(args["y2"])]
            return semantic_drag(mapped)

    if action == "screenshot":
        cmd = screenshot_command_base()
        target = args.get("target")
        app = args.get("app")
        if (not isinstance(target, str) or not target) and isinstance(app, str) and app:
            target = window_selector(resolve_hypr_window(app))
        if isinstance(target, str) and target:
            cmd.extend(["--target", target])
        else:
            require_safe_full_capture(target)
        show_cursor = args.get("show_cursor")
        if show_cursor is False:
            cmd.append("--no-cursor")
        cursor_source = args.get("cursor_source")
        if isinstance(cursor_source, str) and cursor_source:
            cmd.extend(["--cursor-source", cursor_source])
        elif show_cursor is True:
            cmd.extend(["--cursor-source", "auto"])
        info, data = consume_screenshot_result(call_ctl(cmd))
        text = json.dumps(info, ensure_ascii=False)
        return {
            "content": [
                {"type": "text", "text": text},
                {"type": "image", "mimeType": "image/png", "data": data},
            ],
            "structuredContent": info,
            "isError": False,
        }

    if action == "windows":
        cmd = ["windows"]
        if args.get("visible_workspace"):
            cmd.append("--visible-workspace")
        related_to = args.get("related_to")
        if isinstance(related_to, str) and related_to:
            cmd.extend(["--related-to", related_to])
        return result_text(privacy_filter_windows(call_ctl(cmd)))

    if action == "session":
        session_action = args.get("session_action")
        if not isinstance(session_action, str) or not session_action:
            raise RuntimeError("session requires session_action")
        cmd = ["session", "--json", session_action]
        target = args.get("target")
        if isinstance(target, str) and target:
            cmd.append(target)
        return result_text(call_ctl(cmd))

    if action in {"move", "click", "doubleclick", "press", "release"}:
        target = require_target(args)
        x, y = require_xy(args)
        button = args.get("button") or "left"
        info = call_ctl(["pointer", "--json", target, str(x), str(y), action, str(button)])
        return result_text(info)

    if action == "scroll":
        target = require_target(args)
        x, y = require_xy(args)
        amount = args.get("scroll_amount", 1)
        if not isinstance(amount, (int, float)):
            amount = 1
        direction = str(args.get("scroll_direction") or "").lower()
        dy = args.get("dy", amount)
        dx = args.get("dx", 0)
        if direction == "up":
            dy, dx = abs(float(amount)), 0
        elif direction == "down":
            dy, dx = -abs(float(amount)), 0
        elif direction == "left":
            dx, dy = abs(float(amount)), 0
        elif direction == "right":
            dx, dy = -abs(float(amount)), 0
        if not isinstance(dx, (int, float)) or not isinstance(dy, (int, float)):
            raise RuntimeError("scroll requires numeric dx/dy")
        info = call_ctl(["pointer", "--json", target, str(x), str(y), "scroll", str(dy), "--dx", str(dx)])
        return result_text(info)

    if action == "drag":
        target = require_target(args)
        x, y = require_xy(args)
        x2 = args.get("x2")
        y2 = args.get("y2")
        if not isinstance(x2, (int, float)) or not isinstance(y2, (int, float)):
            raise RuntimeError("drag requires numeric x2 and y2")
        button = args.get("button") or "left"
        duration = args.get("duration", 0.15)
        info = call_ctl(["pointer", "--json", target, str(x), str(y), "drag", str(button), str(x2), str(y2), "--duration", str(max(0.0, min(float(duration), 3.0)))])
        info.update({"from": {"x": x, "y": y}, "to": {"x": x2, "y": y2}})
        return result_text(info)

    if action == "key":
        target = require_target(args)
        key, modifiers = key_from_args(args)
        x = args.get("x")
        y = args.get("y")
        repeat = args.get("repeat", 1)
        if not isinstance(repeat, int) or repeat < 1:
            repeat = 1
        info = {}
        for _ in range(min(repeat, 100)):
            info = keyboard(target, key, modifiers, float(x) if isinstance(x, (int, float)) else None, float(y) if isinstance(y, (int, float)) else None)
        return result_text(info)

    if action == "type":
        target = require_target(args)
        text_value = args.get("text")
        if not isinstance(text_value, str):
            raise RuntimeError("type requires text")
        return result_text(type_text(target, text_value, args))

    if action == "copy_text":
        text_value = args.get("text")
        if not isinstance(text_value, str):
            raise RuntimeError("copy_text requires text")
        return result_text({"ok": True, "clipboard": set_clipboard_text(text_value)})

    if action == "paste_text":
        target = require_target(args)
        text_value = args.get("text")
        if not isinstance(text_value, str):
            raise RuntimeError("paste_text requires text")
        prefer_related = args.get("prefer_related")
        target_for_input, related = prefer_related_target(target, False if not isinstance(prefer_related, bool) else prefer_related)
        target_is_xwayland = target_uses_xwayland(target_for_input, related)
        snapshot = clipboard_snapshot_text() if args.get("restore_clipboard", False) is True else None
        methods = set_clipboard_text(text_value, target_is_xwayland)
        return result_text(paste(target, args, methods, text_clipboard_snapshot=snapshot, target_for_input=target_for_input, related=related))

    if action == "paste_file":
        target = require_target(args)
        path_value = args.get("path")
        if not isinstance(path_value, str):
            raise RuntimeError("paste_file requires path")
        path = pathlib.Path(path_value).expanduser()
        if not path.is_file():
            raise RuntimeError(f"file not found: {path}")
        return result_text(paste(target, args, set_clipboard_uri(path)))

    if action == "paste_image":
        target = require_target(args)
        path_value = args.get("path")
        if not isinstance(path_value, str):
            raise RuntimeError("paste_image requires path")
        path = pathlib.Path(path_value).expanduser()
        if not path.is_file():
            raise RuntimeError(f"file not found: {path}")
        mime = mimetypes.guess_type(path.name)[0] or "image/png"
        if not mime.startswith("image/"):
            raise RuntimeError(f"not an image MIME type: {mime}")
        return result_text(paste(target, args, set_clipboard_bytes(path.read_bytes(), mime)))

    if action == "wait":
        duration = bounded_timeout_seconds(args.get("duration", 1), 1.0)
        time.sleep(duration)
        return result_text({"ok": True, "duration": duration})

    if action == "doctor":
        target = args.get("target")
        return result_text(accessibility_diagnostics(target if isinstance(target, str) and target else None))

    raise RuntimeError(f"unsupported action: {action}")


OBSERVATION_ACTIONS = {
    "screenshot",
    "list_apps",
    "windows",
    "get_app_state",
    "read_app_state",
    "wait",
    "wait_for_window",
    "wait_for_close",
    "doctor",
    "get_cursor_position",
    "security_status",
    "audit_replay",
    "request_confirmation",
    "ocr",
    "get_marks",
    "list_workspaces",
}
CLICK_LEVEL_ACTIONS = {
    "move",
    "click",
    "doubleclick",
    "press",
    "release",
    "scroll",
    "drag",
    "left_click",
    "right_click",
    "middle_click",
    "double_click",
    "triple_click",
    "hover",
    "move_mouse",
    "left_click_drag",
    "click_text",
    "click_mark",
}
FULL_LEVEL_ACTIONS = {
    "launch",
    "launch_app",
    "open_app",
    "key",
    "press_key",
    "type",
    "type_text",
    "copy_text",
    "paste_text",
    "paste_file",
    "paste_image",
    "session",
    "set_value",
    "perform_secondary_action",
    "activate_menu_item",
    "panic",
    "type_into",
    "sequence",
    "manage_window",
    "manage_workspace",
}
HIGH_RISK_SHORTCUTS = {"alt+f4", "ctrl+w", "ctrl+shift+w", "delete", "shift+delete"}
HIGH_RISK_WORDS = {
    "apply",
    "buy",
    "close",
    "confirm",
    "delete",
    "erase",
    "finish",
    "overwrite",
    "pay",
    "purchase",
    "remove",
    "replace",
    "send",
    "submit",
    "提交",
    "删除",
    "发送",
    "购买",
    "确认",
    "覆盖",
}
LAUNCH_SHELLS_AND_INTERPRETERS = {
    "bash",
    "bun",
    "csh",
    "dash",
    "deno",
    "fish",
    "js",
    "ksh",
    "lua",
    "node",
    "nu",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "ruby",
    "sh",
    "tcsh",
    "tclsh",
    "zsh",
}


def canonical_security_action(tool_name: str, args: dict[str, Any]) -> str:
    if tool_name == "computer":
        return str(args.get("action") or "")
    aliases = {
        "open_app": "launch_app",
        "read_app_state": "get_app_state",
        "get_screenshot": "screenshot",
        "list_windows": "list_apps",
        "type": "type_text",
        "key": "press_key",
        "left_click_drag": "drag",
        "move_mouse": "hover",
    }
    return aliases.get(tool_name, tool_name)


def action_is_mutating(action: str) -> bool:
    return action not in OBSERVATION_ACTIONS


def action_required_level(action: str) -> AuthorizationLevel:
    if action in FULL_LEVEL_ACTIONS:
        return AuthorizationLevel.FULL
    if action in CLICK_LEVEL_ACTIONS:
        return AuthorizationLevel.CLICK
    if action in OBSERVATION_ACTIONS:
        return AuthorizationLevel.VIEW
    # Unknown/new actions are fail-closed at FULL rather than silently
    # inheriting observation privileges.
    return AuthorizationLevel.FULL


def action_clipboard_capabilities(action: str, args: dict[str, Any]) -> frozenset[ClipboardCapability]:
    capabilities: set[ClipboardCapability] = set()
    if action == "copy_text":
        capabilities.add(ClipboardCapability.WRITE)
    elif action == "paste_text":
        capabilities.update({ClipboardCapability.WRITE, ClipboardCapability.PASTE_TEXT})
        if args.get("restore_clipboard", False) is True:
            capabilities.add(ClipboardCapability.READ)
    elif action == "paste_file":
        capabilities.update({ClipboardCapability.WRITE, ClipboardCapability.PASTE_FILE})
    elif action == "paste_image":
        capabilities.update({ClipboardCapability.WRITE, ClipboardCapability.PASTE_IMAGE})
    elif action in {"type", "type_text", "type_into"}:
        method = str(args.get("method") or "auto")
        text_value = str(args.get("text") or "")
        if method in {"paste", "auto"}:
            capabilities.update({ClipboardCapability.WRITE, ClipboardCapability.PASTE_TEXT})
    return frozenset(capabilities)


def cached_action_intent(args: dict[str, Any], *, allow_fresh: bool = True) -> dict[str, Any]:
    app = args.get("app") or args.get("target")
    if not isinstance(app, str) or not app:
        return {}
    snapshot = SNAPSHOTS.get(normalize(app))
    if not isinstance(snapshot, dict):
        has_semantic_locator = any(
            isinstance(args.get(key), str) and bool(args.get(key))
            for key in ("element_index", "menu_index", "menuIndex")
        )
        if not has_semantic_locator:
            return {}
        if SECURITY_POLICY.config.dry_run or not allow_fresh:
            return {"kind": "semantic", "resolutionDeferred": "dry-run does not capture fresh app state"}
        try:
            window = resolve_hypr_window(app)
            if SECURITY_POLICY.privacy_excluded(window):
                return {"kind": "semantic", "resolutionError": "target is privacy-excluded"}
            snapshot = build_app_snapshot(app)
        except Exception as exc:
            return {"kind": "semantic", "resolutionError": f"{type(exc).__name__}: {exc}"}
    element_index = args.get("element_index")
    if isinstance(element_index, str) and element_index:
        try:
            element = lookup_element(snapshot, element_index)
        except RuntimeError:
            return {}
        return {
            "kind": "element",
            "index": element_index,
            "name": str(element.get("name") or ""),
            "value": str(element.get("value") or ""),
            "role": str(element.get("controlType") or element.get("localizedControlType") or ""),
        }
    menu_index = args.get("menu_index") or args.get("menuIndex")
    if isinstance(menu_index, str) and menu_index:
        try:
            item = find_global_menu_item(snapshot, menu_index)
        except RuntimeError:
            return {}
        return {
            "kind": "menu",
            "index": menu_index,
            "label": str(item.get("label") or ""),
            "action": str(item.get("action") or ""),
        }
    return {}


def cached_visual_intent(action: str, args: dict[str, Any]) -> dict[str, Any]:
    try:
        if action == "click_text":
            entry = visual_cache_entry(args.get("ocr_id"), "ocr", validate_live=False)
            snapshot = entry["snapshot"]
            resolved = resolve_click_target(
                snapshot,
                {"ocr": {"text": args.get("text"), "match": args.get("match", "exact"), "casefold": args.get("casefold", True), "nth": args.get("nth", 1)}},
                ocr_result=entry["payload"],
            )
            return {"kind": "ocr", **resolved.to_dict()}
        if action == "click_mark":
            entry = visual_cache_entry(args.get("marks_id"), "marks", validate_live=False)
            resolved = resolve_click_target(entry["snapshot"], {"mark_id": args.get("mark_id")}, mark_set=entry["payload"])
            mark = next(
                (
                    item
                    for item in entry["payload"].get("marks", [])
                    if isinstance(item, dict) and str(item.get("id", item.get("markId", ""))) == str(args.get("mark_id"))
                ),
                {},
            )
            return {
                "kind": "mark",
                **resolved.to_dict(),
                "text": mark.get("text"),
                "name": mark.get("name"),
            }
        if action == "type_into":
            locator = args.get("locator") if isinstance(args.get("locator"), dict) else {}
            entry = None
            ocr_result = None
            mark_set = None
            if isinstance(args.get("ocr_id"), str):
                entry = visual_cache_entry(args["ocr_id"], "ocr", validate_live=False)
                ocr_result = entry["payload"]
                locator = locator or {"ocr": {"text": args.get("target_text"), "match": args.get("match", "exact"), "nth": args.get("nth", 1)}}
            elif isinstance(args.get("marks_id"), str):
                entry = visual_cache_entry(args["marks_id"], "marks", validate_live=False)
                mark_set = entry["payload"]
                locator = locator or {"mark_id": args.get("mark_id")}
            elif isinstance(args.get("snapshot_id"), str):
                entry = visual_cache_entry(args["snapshot_id"], "snapshot", validate_live=False)
                locator = locator or {
                    key: args.get(key)
                    for key in ("element_index", "accessible_name", "accessible_text", "name", "match", "nth")
                    if args.get(key) is not None
                }
            if entry is None:
                return {"kind": "type_into", "locator": locator}
            resolved = resolve_type_into_target(entry["snapshot"], locator, ocr_result=ocr_result, mark_set=mark_set)
            element = resolved.get("element") if isinstance(resolved.get("element"), dict) else {}
            return {
                "kind": "type_into",
                "source": resolved.get("source"),
                "elementIndex": resolved.get("elementIndex"),
                "name": element.get("name"),
                "role": element.get("controlType"),
                "frame": resolved.get("frame"),
            }
    except Exception as exc:
        return {"kind": "visual", "resolutionError": f"{type(exc).__name__}: {exc}"}
    return {}


def launch_payload_is_high_risk(args: dict[str, Any]) -> bool:
    # `command` is the explicit arbitrary-command escape hatch even if another
    # fallback field would ultimately be used by launch_parts().
    if "command" in args:
        return True
    extra_args = args.get("args")
    if extra_args not in (None, "", [], ()):
        return True
    app = args.get("app")
    if not isinstance(app, str) or not app.strip():
        return False
    try:
        parts = shlex.split(app)
    except ValueError:
        return True
    if len(parts) != 1:
        return True
    base = executable_basename(parts[0])
    url = args.get("url")
    if isinstance(url, str) and url:
        url_browsers = {
            *CHROMIUM_LIKE_EXECUTABLES,
            "firefox", "firefox-developer-edition", "librewolf", "waterfox", "floorp",
        }
        if base not in url_browsers and not any(token in base for token in ("chrom", "brave")):
            return True
    if base in LAUNCH_SHELLS_AND_INTERPRETERS:
        return True
    # Versioned Python executables (python3, python3.13, pypy3) are command
    # interpreters too; launching them must not bypass physical confirmation.
    return bool(re.fullmatch(r"(?:python|pypy)(?:\d+(?:\.\d+)*)?", base))


def action_is_high_risk(action: str, args: dict[str, Any], *, allow_fresh_intent: bool = True) -> bool:
    if action == "panic":
        return str(args.get("mode") or "panic").casefold() == "resume"
    if action in {"launch", "launch_app", "open_app"} and launch_payload_is_high_risk(args):
        return True
    if action == "manage_window" and str(args.get("window_action") or args.get("action") or "").casefold() == "close":
        return True
    if isinstance(args.get("keycode"), int):
        # Raw evdev keycodes are intentionally treated as high risk: layout and
        # kernel mappings vary, so a numeric code cannot be safely classified
        # as harmless at the policy layer.
        return True
    try:
        key_name, modifiers = key_from_args(args)
    except Exception:
        key_name, modifiers = str(args.get("keys") or args.get("key") or ""), str(args.get("modifiers") or "")
    modifier_parts = [part for part in re.split(r"[+\-\s]+", modifiers.casefold()) if part]
    modifier_parts = ["ctrl" if part == "control" else part for part in modifier_parts]
    modifier_parts.sort(key=lambda part: ({"ctrl": 0, "alt": 1, "shift": 2, "super": 3}.get(part, 9), part))
    shortcut = "+".join([*modifier_parts, key_name.casefold().replace("key_", "")]).strip("+")
    if shortcut in HIGH_RISK_SHORTCUTS:
        return True
    intent = cached_action_intent(args, allow_fresh=allow_fresh_intent) or cached_visual_intent(action, args)
    labels = " ".join(
        str(args.get(key) or "")
        for key in ("name", "action", "menu_text", "description")
    ) + " " + " ".join(str(value) for value in intent.values())
    labels = labels.casefold()
    return any(word in labels for word in HIGH_RISK_WORDS)


def security_target(args: dict[str, Any], *, resolve: bool) -> WindowIdentity | None:
    selector = args.get("app") or args.get("target") or args.get("address")
    if not selector:
        for key, kind in (("ocr_id", "ocr"), ("marks_id", "marks"), ("snapshot_id", "snapshot")):
            token = args.get(key)
            if isinstance(token, str) and token:
                try:
                    entry = visual_cache_entry(token, kind, validate_live=False)
                    selector = qualify_address(entry["address"], entry["pid"], entry["starttime"])
                except Exception:
                    pass
                break
    if not selector and isinstance(args.get("workspace"), (str, int)):
        workspace = normalize_workspace(args["workspace"])
        identity_workspace = workspace.split(":", 1)[1] if workspace.startswith("name:") else workspace
        return WindowIdentity(address=f"workspace:{workspace}", class_name="hyprland-workspace", workspace=identity_workspace)
    if not isinstance(selector, str) or not selector:
        return None
    if not resolve:
        return WindowIdentity(address=selector)
    window = resolve_hypr_window(selector)
    return WindowIdentity.from_window(window)


def execution_selector(args: dict[str, Any]) -> tuple[str, str] | None:
    """Return the selector actually consumed by semantic/management tools."""
    for key in ("app", "target", "address"):
        value = args.get(key)
        if isinstance(value, str) and value:
            return key, value
    return None


def prepare_execution_args(tool_name: str, args: dict[str, Any]) -> tuple[dict[str, Any], WindowIdentity | None]:
    """Resolve an ambiguous selector once and bind execution to that window.

    The canonical address is passed to the backend, while the complete
    address/pid/starttime/class/workspace identity is retained for a second
    check immediately before execution.
    """
    prepared = dict(args)
    action = canonical_security_action(tool_name, prepared)
    if action in {"launch", "launch_app", "open_app", "sequence", "panic"}:
        return prepared, None
    if prepared.get("prefer_related") is True:
        raise RuntimeError("prefer_related is unsafe; inspect app state and target the related popup explicitly")
    selectors = [
        (key, value)
        for key in ("app", "target", "address")
        if isinstance((value := prepared.get(key)), str) and value
    ]
    if not selectors:
        return prepared, None
    resolved: list[tuple[str, WindowIdentity]] = []
    for key, value in selectors:
        try:
            window = resolve_hypr_window(value)
        except Exception as exc:
            prefix = "identity_unavailable_for_dry_run" if SECURITY_POLICY.config.dry_run else "target identity unavailable for policy evaluation"
            raise RuntimeError(f"{prefix}: {exc}") from exc
        resolved.append((key, WindowIdentity.from_window(window)))
    identity = resolved[0][1]
    if not identity.address:
        raise RuntimeError("target identity unavailable for policy evaluation: missing address")
    expected = dict(identity.fingerprint())
    if any(dict(candidate.fingerprint()) != expected for _, candidate in resolved[1:]):
        raise RuntimeError("conflicting app/target/address selectors resolve to different windows")
    try:
        canonical = qualify_address(identity.address, identity.pid, identity.process_start_time)
    except ValueError as exc:
        raise RuntimeError(f"target identity unavailable for policy evaluation: {exc}") from exc
    # Preserve keys expected by legacy/direct handlers, but make every one of
    # them point to the single policy-bound identity.
    for key, _ in selectors:
        prepared[key] = canonical
    return prepared, identity


def revalidate_execution_identity(expected: WindowIdentity | None) -> None:
    if expected is None:
        return
    try:
        current_window = resolve_hypr_window(qualify_address(expected.address, expected.pid, expected.process_start_time))
    except Exception as exc:
        raise RuntimeError(f"target became unavailable after policy evaluation: {exc}") from exc
    current = WindowIdentity.from_window(current_window)
    if dict(current.fingerprint()) != dict(expected.fingerprint()):
        raise RuntimeError("target identity changed after policy evaluation; refusing stale or retargeted action")


def workspace_identity_value(workspace: Any) -> str:
    selector = normalize_workspace(workspace)
    return selector.split(":", 1)[1] if selector.startswith("name:") else selector


def resulting_scope_targets(action: str, args: dict[str, Any], source: WindowIdentity | None) -> tuple[WindowIdentity, ...]:
    """Project destination identities so dry-run and execution share policy."""
    destination: Any = None
    if action == "manage_window":
        operation = str(args.get("window_action") or args.get("action") or "").casefold()
        if operation == "move_to_workspace":
            destination = args.get("workspace")
        elif operation in {"minimize", "restore"}:
            enabled = args.get("enabled", True) is not False and operation != "restore"
            destination = args.get("minimized_workspace", "special:hypr-agent-portal-minimized") if enabled else args.get("restore_workspace")
            if destination is None and SECURITY_POLICY.config.confinement.enabled:
                raise RuntimeError("restore_workspace is required under confinement")
    elif action == "manage_workspace":
        operation = str(args.get("workspace_action") or args.get("action") or "").casefold()
        if operation in {"move_window", "move_window_to_workspace"}:
            destination = args.get("workspace")
        elif operation == "rename":
            destination = f"name:{args.get('new_name')}"
    if destination is None:
        return ()
    workspace = workspace_identity_value(destination)
    if source is None or source.class_name == "hyprland-workspace":
        destination_identity = WindowIdentity(
            address=f"workspace:{normalize_workspace(destination)}",
            class_name="hyprland-workspace",
            workspace=workspace,
        )
    else:
        destination_identity = WindowIdentity(
            address=source.address,
            class_name=source.class_name,
            initial_class=source.initial_class,
            workspace=workspace,
            pid=source.pid,
            process_start_time=source.process_start_time,
            launched=source.launched,
        )
    return (destination_identity,)


def build_security_request(
    tool_name: str,
    args: dict[str, Any],
    *,
    force_destructive: bool | None = None,
    dry_run_preview: bool = False,
    resolved_target: WindowIdentity | None = None,
) -> ActionRequest:
    action = canonical_security_action(tool_name, args)
    mutating = action_is_mutating(action)
    required_level = action_required_level(action)
    if action == "sequence":
        # The sequence is an orchestration envelope only. Every step re-enters
        # handle() and independently acquires policy/confirmation/leases.
        mutating = False
        required_level = AuthorizationLevel.VIEW
    if action == "panic":
        panic_mode = str(args.get("mode") or "panic").casefold()
        mutating = panic_mode == "resume"
        if not mutating:
            required_level = AuthorizationLevel.VIEW
    if resolved_target is not None:
        target = resolved_target
    elif action in {"launch", "launch_app", "open_app", "sequence", "panic"}:
        target = security_target(args, resolve=False)
    else:
        # Identity lookup is read-only and is required in dry-run too.  A
        # placeholder identity would misreport per-app authorization and
        # confinement, making preview disagree with real execution.
        try:
            target = security_target(args, resolve=True)
        except Exception as exc:
            if SECURITY_POLICY.config.dry_run or dry_run_preview:
                raise RuntimeError(f"identity_unavailable_for_dry_run: {exc}") from exc
            raise
    scope_targets = resulting_scope_targets(action, args, target)
    # Confirmation contexts are hashed inside SecurityPolicy and never written
    # verbatim to the audit log. Include the full action payload so a token
    # issued for one string, path, or value cannot authorize a different one.
    context = {key: value for key, value in args.items() if key != "confirmation_token"}
    intent = cached_action_intent(args, allow_fresh=not dry_run_preview) or cached_visual_intent(action, args)
    if intent:
        context["resolved_intent"] = intent
    return ActionRequest(
        owner=SECURITY_OWNER,
        action=action,
        required_level=required_level,
        mutating=mutating,
        target=target,
        scope_targets=scope_targets,
        clipboard_capabilities=action_clipboard_capabilities(action, args),
        destructive=action_is_high_risk(action, args, allow_fresh_intent=not dry_run_preview) if force_destructive is None else force_destructive,
        confirmation_token=args.get("confirmation_token") if isinstance(args.get("confirmation_token"), str) else None,
        confirmation_context=context,
    )


def collect_runtime_guards() -> GuardInputs:
    """Collect compositor-owned mutation guards, failing closed on any gap."""
    global SERVER_PANIC_ACTIVE
    try:
        state = call_ctl(["guard", "--json"])
    except Exception as exc:
        return GuardInputs(
            screen_locked=None,
            panic_active=SERVER_PANIC_ACTIVE,
            available=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    required = ("screenLocked", "layerSurfaceActive", "keyboardGrabActive", "panicActive")
    invalid = [field for field in required if not isinstance(state.get(field), bool)]
    if state.get("available") is not True or invalid:
        detail = "native guard response is incomplete"
        if invalid:
            detail += ": " + ", ".join(invalid)
        return GuardInputs(
            screen_locked=None,
            panic_active=SERVER_PANIC_ACTIVE,
            available=False,
            error=detail,
        )

    SERVER_PANIC_ACTIVE = state["panicActive"]
    return GuardInputs(
        screen_locked=state["screenLocked"],
        layer_surface_active=state["layerSurfaceActive"],
        keyboard_grab_active=state["keyboardGrabActive"],
        panic_active=SERVER_PANIC_ACTIVE,
        available=True,
    )


def security_result(decision: PolicyDecision, request: ActionRequest, *, is_error: bool) -> dict[str, Any]:
    security = decision.to_dict()
    security["dryRun"] = not decision.execute and decision.allowed
    security["details"] = {**security.get("details", {}), "action": request.action}
    text_value = f"Security policy: {decision.code.value}: {decision.reason}"
    return {
        "content": [{"type": "text", "text": text_value}],
        "structuredContent": {"security": security},
        "isError": is_error,
    }


def ensure_policy_lease(request: ActionRequest) -> None:
    if not request.mutating or not SECURITY_POLICY.config.mutation_lease_required:
        return
    current = SECURITY_POLICY.current_mutation_lease()
    if current is None or current.owner == SECURITY_OWNER:
        if SECURITY_POLICY.acquire_mutation_lease(SECURITY_OWNER) is None:
            raise RuntimeError("failed to acquire in-process mutation lease")


def acquire_process_mutation_lease() -> Any:
    global PROCESS_MUTATION_LEASE
    if PROCESS_MUTATION_LEASE is None:
        PROCESS_MUTATION_LEASE = ProcessMutationLease()
    return PROCESS_MUTATION_LEASE.acquire()


def audit_security_call(
    tool_name: str,
    args: dict[str, Any],
    request: ActionRequest,
    result: dict[str, Any],
    *,
    dry_run: bool = False,
) -> None:
    if SECURITY_AUDIT is None:
        return
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    SECURITY_AUDIT.record(
        tool_name,
        target=args.get("app") or args.get("target"),
        args=args,
        result=structured if structured is not None else result,
        before=SNAPSHOTS.get(normalize(str(args.get("app") or args.get("target") or ""))),
        after=structured,
        dry_run=dry_run,
        target_identity=request.target.fingerprint() if request.target else None,
    )


def audit_preparation_failure(tool_name: str, args: dict[str, Any], result: dict[str, Any]) -> None:
    """Journal fail-closed request preparation errors without resolving a target.

    Conflicting selectors and unsafe compatibility options can be rejected
    before an ActionRequest exists.  They are still security-relevant calls
    and must not disappear from the audit trail.
    """
    action = canonical_security_action(tool_name, args) or "invalid_request"
    request = ActionRequest(
        owner=SECURITY_OWNER,
        action=action,
        required_level=action_required_level(action),
        mutating=action_is_mutating(action),
        confirmation_context={key: value for key, value in args.items() if key != "confirmation_token"},
    )
    audit_security_call(tool_name, args, request, result)


def newly_launched_window(result: Any) -> dict[str, Any] | None:
    """Return a launch-qualified window, never an existing-window reuse.

    `launch_app` can dispatch a command and still fall back to a matching
    pre-existing window.  Only a selected window also present in the launch
    result's `newWindows` provenance set may gain launched-only scope.
    """
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    if not isinstance(structured, dict) or structured.get("reused") is not False:
        return None
    selected = structured.get("window")
    candidates = structured.get("newWindows")
    if not isinstance(selected, dict) or not isinstance(candidates, list):
        return None
    selected_identity = dict(WindowIdentity.from_window(selected).fingerprint())
    for candidate in candidates:
        if isinstance(candidate, dict) and dict(WindowIdentity.from_window(candidate).fingerprint()) == selected_identity:
            return selected
    return None


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    req_id = message.get("id")

    if method == "initialize":
        return response(
            req_id,
            {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "hypr-agent-portal", "version": SERVER_VERSION},
                "capabilities": {"tools": {"listChanged": False}},
            },
        )

    if method == "tools/list":
        return response(req_id, {"tools": tool_definitions()})

    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name != "computer" and name not in SEMANTIC_TOOLS:
            return response(req_id, {"content": [{"type": "text", "text": "unknown tool"}], "isError": True})
        request: ActionRequest | None = None
        execution_args = dict(args)
        execution_identity: WindowIdentity | None = None
        try:
            execution_args, execution_identity = prepare_execution_args(str(name), args)
            request = build_security_request(str(name), execution_args, resolved_target=execution_identity)
            if request.action == "panic":
                # Emergency stop/status/resume must remain callable while the
                # desktop is locked or another client owns an input grab.
                guards = GuardInputs(screen_locked=False)
            elif not SECURITY_POLICY.config.dry_run:
                guards = collect_runtime_guards()
            else:
                guards = GuardInputs()
            is_sequence = request.action == "sequence"
            if request.mutating and not is_sequence and not SECURITY_POLICY.config.readonly and not SECURITY_POLICY.config.dry_run:
                ensure_policy_lease(request)
            decision = SECURITY_POLICY.evaluate(request, guards)
            if not decision.allowed:
                result = security_result(decision, request, is_error=True)
                audit_security_call(str(name), args, request, result)
                return response(req_id, result)
            if not decision.execute and not (is_sequence and decision.allowed and SECURITY_POLICY.config.dry_run):
                result = security_result(decision, request, is_error=False)
                audit_security_call(str(name), args, request, result, dry_run=True)
                return response(req_id, result)

            def invoke() -> dict[str, Any]:
                if name == "computer":
                    return computer(execution_args)
                return SEMANTIC_TOOLS[str(name)](execution_args)

            if request.mutating and not is_sequence:
                with acquire_process_mutation_lease():
                    revalidate_execution_identity(execution_identity)
                    result = invoke()
            else:
                revalidate_execution_identity(execution_identity)
                result = invoke()
            if request.action in {"launch", "launch_app", "open_app"}:
                launched_window = newly_launched_window(result)
                if launched_window is not None:
                    SECURITY_POLICY.register_launched_window(launched_window)
            audit_security_call(str(name), execution_args, request, result)
            return response(req_id, result)
        except LeaseConflict as exc:
            decision = PolicyDecision(
                False,
                False,
                DecisionCode.MUTATION_LEASE_HELD,
                str(exc),
                {"holder": exc.holder},
            )
            request = request or build_security_request(str(name), args)
            result = security_result(decision, request, is_error=True)
            audit_security_call(str(name), args, request, result)
            return response(req_id, result)
        except ProcessLeaseError as exc:
            decision = PolicyDecision(False, False, DecisionCode.MUTATION_LEASE_REQUIRED, str(exc))
            request = request or build_security_request(str(name), args)
            result = security_result(decision, request, is_error=True)
            audit_security_call(str(name), args, request, result)
            return response(req_id, result)
        except Exception as exc:
            result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
            if request is not None:
                audit_security_call(str(name), args, request, result)
            else:
                try:
                    audit_preparation_failure(str(name), args, result)
                except Exception:
                    # The original fail-closed request error must remain the
                    # response even if the journal itself is unavailable.
                    pass
            return response(req_id, result)

    if method and method.startswith("notifications/"):
        global PENDING_SEQUENCE_CANCEL
        if method in {"notifications/turn-ended", "notifications/cancelled"}:
            SNAPSHOTS.clear()
            VISUAL_CACHE.clear()
            with SEQUENCE_STATE_LOCK:
                if ACTIVE_SEQUENCE_CANCELLATION is not None:
                    ACTIVE_SEQUENCE_CANCELLATION.cancel(str(method))
                elif method == "notifications/cancelled" and SEQUENCE_WORKER_PENDING:
                    PENDING_SEQUENCE_CANCEL = True
        return None

    return error(req_id, -32601, f"method not found: {method}")


def main() -> int:
    global SEQUENCE_WORKER_PENDING
    ensure_session_environment()
    output_lock = threading.Lock()
    workers: list[threading.Thread] = []

    def emit(out: dict[str, Any] | None) -> None:
        if out is not None:
            with output_lock:
                print(json.dumps(out, ensure_ascii=False), flush=True)

    def run_message(msg: dict[str, Any]) -> None:
        try:
            emit(handle(msg))
        except Exception as exc:
            emit(error(msg.get("id"), -32603, str(exc)))

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except Exception as exc:
            emit(error(None, -32700, str(exc)))
            continue
        params = msg.get("params") if isinstance(msg, dict) else None
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        is_sequence_call = msg.get("method") == "tools/call" and (
            name == "sequence"
            or (name == "computer" and isinstance(arguments, dict) and arguments.get("action") == "sequence")
        )
        if is_sequence_call:
            with SEQUENCE_STATE_LOCK:
                SEQUENCE_WORKER_PENDING = True
            worker = threading.Thread(target=run_message, args=(msg,), name="hypr-agent-portal-sequence", daemon=False)
            workers.append(worker)
            worker.start()
        else:
            run_message(msg)
        workers = [worker for worker in workers if worker.is_alive()]
    for worker in workers:
        worker.join()
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ATSPI_CHILD_MODES:
        raise SystemExit(atspi_child_main(sys.argv[1]))
    raise SystemExit(main())
