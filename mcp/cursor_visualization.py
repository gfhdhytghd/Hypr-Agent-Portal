"""Bounded visualization-only settings shared by the stdio bridge and CLI.

No session identity is accepted from the MCP caller or host environment.
"""
import re
import secrets

DEFAULT_SETTINGS = {
    "theme": "gradient", "motion_ms": 450, "arc": 25, "spring": 72,
    "reduced_motion": False, "idle_ms": 30000, "fade_ms": 200, "size": 42,
}
BOUNDS = {
    "motion_ms": (0, 3000), "arc": (0, 100), "spring": (0, 100),
    "idle_ms": (100, 60000), "fade_ms": (0, 5000), "size": (16, 128),
}
THEMES = ("gradient", "classic", "minimal", "codex")
ENV_PREFIX = "HYPR_AGENT_PORTAL_CURSOR_"


def new_session_id():
    return "mcp_" + secrets.token_hex(24)


def validate_session(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) is None:
        raise ValueError("cursor_session must be 1..64 ASCII letters, digits, underscores or hyphens")
    return value


def validate_settings(values, *, from_strings=False):
    if not isinstance(values, dict):
        raise ValueError("cursor settings must be an object")
    result = {}
    for key, value in values.items():
        if key not in DEFAULT_SETTINGS:
            raise ValueError(f"unknown cursor setting: {key}")
        if key == "theme":
            if value not in THEMES:
                raise ValueError("cursor theme must be gradient, classic, minimal or codex")
        elif key == "reduced_motion":
            if from_strings and value in ("0", "1"):
                value = value == "1"
            if not isinstance(value, bool):
                raise ValueError("cursor reduced_motion must be a boolean (CLI/env: 0 or 1)")
        else:
            if from_strings and isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
                value = int(value)
            low, high = BOUNDS[key]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"cursor {key} must be an integer in {low}..{high}")
        result[key] = value
    return result


def settings_from_env(env):
    values = {key: env[ENV_PREFIX + key.upper()] for key in DEFAULT_SETTINGS if ENV_PREFIX + key.upper() in env}
    return {**DEFAULT_SETTINGS, **validate_settings(values, from_strings=True)}


def metadata(session=None, settings=None):
    parts = []
    if session is not None:
        parts.append("cursor_session=" + validate_session(session))
    for key, value in validate_settings(settings or {}).items():
        parts.append(f"{key}={int(value) if isinstance(value, bool) else value}")
    return parts


def state_filename(session=None):
    return "cursor.json" if session is None else f"cursor-{validate_session(session)}.json"


def settings_schema():
    return {
        "theme": {"type": "string", "enum": list(THEMES)},
        "reduced_motion": {"type": "boolean"},
        **{key: {"type": "integer", "minimum": low, "maximum": high} for key, (low, high) in BOUNDS.items()},
    }
