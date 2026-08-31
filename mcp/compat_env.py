#!/usr/bin/env python3
"""One-release compatibility helpers for the protal -> portal rename.

New names always win when both spellings are present.  Callers may use
``promote_legacy_environment`` once, before reading their normal environment
variables, or use ``getenv`` for individual settings.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Mapping, MutableMapping


CURRENT_NAME = "hypr-agent-portal"
LEGACY_NAME = "hypr-agent-protal"
CURRENT_ENV_PREFIX = "HYPR_AGENT_PORTAL_"
LEGACY_ENV_PREFIX = "HYPR_AGENT_PROTAL_"

# Keep this list explicit so an accidental similarly named variable is not
# silently promoted into the process environment.
ENV_ALIASES: dict[str, str] = {
    "HYPR_AGENT_PORTAL_ATSPI_CHILD": "HYPR_AGENT_PROTAL_ATSPI_CHILD",
    "HYPR_AGENT_PORTAL_CTL": "HYPR_AGENT_PROTAL_CTL",
    "HYPR_AGENT_PORTAL_ELEMENT_CLICK_MODE": "HYPR_AGENT_PROTAL_ELEMENT_CLICK_MODE",
    "HYPR_AGENT_PORTAL_MODEL_MAX_DIMENSION": "HYPR_AGENT_PROTAL_MODEL_MAX_DIMENSION",
    "HYPR_AGENT_PORTAL_MODEL_RESOLUTION": "HYPR_AGENT_PROTAL_MODEL_RESOLUTION",
}


@dataclass(frozen=True)
class LegacyEnvironmentUse:
    """A legacy variable copied to its canonical replacement."""

    canonical: str
    legacy: str


def getenv(
    canonical: str,
    default: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Read a canonical setting with a one-release legacy fallback."""

    source = os.environ if environ is None else environ
    if canonical in source:
        return source[canonical]
    legacy = ENV_ALIASES.get(canonical)
    if legacy is not None and legacy in source:
        return source[legacy]
    return default


def promote_legacy_environment(
    environ: MutableMapping[str, str] | None = None,
) -> tuple[LegacyEnvironmentUse, ...]:
    """Copy recognized legacy values to missing canonical variables.

    The operation never overwrites a canonical value.  The return value lets
    the executable report a deprecation notice without this low-level helper
    writing to stderr (important for MCP stdio transports).
    """

    target = os.environ if environ is None else environ
    promoted: list[LegacyEnvironmentUse] = []
    for canonical, legacy in ENV_ALIASES.items():
        if canonical not in target and legacy in target:
            target[canonical] = target[legacy]
            promoted.append(LegacyEnvironmentUse(canonical, legacy))
    return tuple(promoted)


def config_directory_candidates(
    *,
    environ: Mapping[str, str] | None = None,
    home: str | os.PathLike[str] | None = None,
) -> tuple[Path, Path]:
    """Return canonical then legacy per-user configuration directories."""

    source = os.environ if environ is None else environ
    if source.get("XDG_CONFIG_HOME"):
        base = Path(source["XDG_CONFIG_HOME"]).expanduser()
    else:
        base_home = Path(home).expanduser() if home is not None else Path.home()
        base = base_home / ".config"
    return base / CURRENT_NAME, base / LEGACY_NAME


def config_file_candidates(
    relative_path: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    home: str | os.PathLike[str] | None = None,
) -> tuple[Path, Path]:
    """Return canonical then legacy candidates for a config-relative file."""

    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("configuration path must be relative and may not contain '..'")
    current, legacy = config_directory_candidates(environ=environ, home=home)
    return current / relative, legacy / relative


def existing_config_file(
    relative_path: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
    home: str | os.PathLike[str] | None = None,
) -> Path | None:
    """Choose an existing canonical config file, falling back to legacy."""

    return next(
        (path for path in config_file_candidates(relative_path, environ=environ, home=home) if path.is_file()),
        None,
    )


def config_namespace_candidates(*, lua: bool) -> tuple[str, str]:
    """Return canonical then legacy Hyprland configuration namespaces."""

    if lua:
        return "plugin.hypr_agent_portal", "plugin.hypr_agent_protal"
    return "plugin:hypr-agent-portal", "plugin:hypr-agent-protal"
