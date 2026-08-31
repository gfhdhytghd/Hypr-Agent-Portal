"""Installed entry point for the hypr-agent-portal stdio MCP server."""

from __future__ import annotations

import importlib.metadata
import pathlib
import runpy
import sys


_DISTRIBUTION_NAME = "hypr-agent-portal"
_SERVER_SCRIPT_NAME = "hypr-agent-portal-mcp.py"


def _console_sibling() -> pathlib.Path | None:
    """Return the server beside the invoked console script, when unambiguous."""
    invoked = pathlib.Path(sys.argv[0])
    if invoked.name != "hypr-agent-portal":
        return None
    # A bare argv[0] would resolve relative to an attacker-controlled cwd. The
    # shell normally supplies the resolved path for a PATH-launched executable.
    if not invoked.is_absolute() and invoked.parent == pathlib.Path("."):
        return None
    try:
        entrypoint = invoked.resolve(strict=True)
    except OSError:
        return None
    candidate = entrypoint.with_name(_SERVER_SCRIPT_NAME)
    return candidate if candidate.is_file() else None


def _distribution_script() -> pathlib.Path | None:
    """Locate the installed script from this distribution's RECORD metadata."""
    try:
        distribution = importlib.metadata.distribution(_DISTRIBUTION_NAME)
    except importlib.metadata.PackageNotFoundError:
        return None
    for installed_file in distribution.files or ():
        if pathlib.PurePath(installed_file).name != _SERVER_SCRIPT_NAME:
            continue
        try:
            candidate = pathlib.Path(distribution.locate_file(installed_file)).resolve(strict=True)
        except OSError:
            continue
        if candidate.is_file():
            return candidate
    return None


def server_script() -> pathlib.Path:
    """Resolve the MCP script without searching an untrusted PATH or cwd."""
    server = _console_sibling() or _distribution_script()
    if server is None:
        raise SystemExit(
            f"installed MCP server script {_SERVER_SCRIPT_NAME!r} was not found "
            "beside the console entry point or in package metadata"
        )
    return server


def main() -> None:
    """Run the MCP server installed by this distribution."""
    runpy.run_path(str(server_script()), run_name="__main__")


if __name__ == "__main__":
    main()
