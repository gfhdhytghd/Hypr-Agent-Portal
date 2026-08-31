#!/usr/bin/env python3
"""Fail-closed regression tests for the mutation-only AT-SPI resolver."""

from __future__ import annotations

import importlib.util
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp" / "hypr-agent-portal-mcp.py"


def load_mcp():
    spec = importlib.util.spec_from_file_location("hypr_agent_portal_mcp_atspi_strict", MCP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class Node:
    def __init__(self, title: str, *, pid: int = 0, accessible_id: str = "", bounds=None, children=None):
        self.title = title
        self.pid = pid
        self.accessible_id = accessible_id
        self.bounds = dict(bounds or {"x": 50.0, "y": 60.0, "width": 800.0, "height": 600.0})
        self.children = list(children or [])
        self.role = "frame"


def main() -> int:
    mcp = load_mcp()
    bounds = {"x": 50.0, "y": 60.0, "width": 800.0, "height": 600.0}
    root_a = Node("Document A", accessible_id="root-a", bounds=bounds)
    root_b = Node("Document B", accessible_id="root-b", bounds=bounds)
    app_a = Node("Editor", pid=3100, children=[root_a, root_b])
    app_b = Node("Editor", pid=3200, children=[Node("Document A", accessible_id="root-a", bounds=bounds)])
    window = {
        "pid": 3100,
        "processStartTime": "9001",
        "title": "Document A",
        "atspiRootIdentity": {
            "windowIndex": 0,
            "title": "Document A",
            "role": "frame",
            "accessibleId": "root-a",
            "bounds": bounds,
        },
    }
    originals = {
        name: getattr(mcp, name)
        for name in (
            "atspi_available", "process_start_time", "atspi_iter_apps", "atspi_pid",
            "atspi_app_windows", "atspi_name", "atspi_role", "atspi_accessible_id", "atspi_extents",
        )
    }
    try:
        mcp.atspi_available = lambda: True
        mcp.process_start_time = lambda _pid: "9001"
        mcp.atspi_pid = lambda node: node.pid
        mcp.atspi_app_windows = lambda app: list(enumerate(app.children))
        mcp.atspi_name = lambda node: node.title
        mcp.atspi_role = lambda node: node.role
        mcp.atspi_accessible_id = lambda node: node.accessible_id
        mcp.atspi_extents = lambda node: dict(node.bounds)

        mcp.atspi_iter_apps = lambda: [app_a]
        assert mcp.atspi_resolve_window_for_mutation(window) == (app_a, 0, root_a)

        # Cross-PID: same app/root names in PID B cannot replace PID A.
        mcp.atspi_iter_apps = lambda: [app_b]
        assert mcp.atspi_resolve_window_for_mutation(window) is None

        # Same PID, different root: no active/showing/first/title fallback.
        app_a.children = [root_b, root_a]
        mcp.atspi_iter_apps = lambda: [app_a]
        assert mcp.atspi_resolve_window_for_mutation(window) is None
        app_a.children = [root_a, root_b]

        # PID reuse/starttime drift.
        mcp.process_start_time = lambda _pid: "9002"
        assert mcp.atspi_resolve_window_for_mutation(window) is None
        mcp.process_start_time = lambda _pid: "9001"

        # Captured root stable identity drift.
        root_a.accessible_id = "replacement-root"
        assert mcp.atspi_resolve_window_for_mutation(window) is None
        root_a.accessible_id = "root-a"

        # Root geometry drift beyond the documented tolerance.
        root_a.bounds["x"] += 4.0
        assert mcp.atspi_resolve_window_for_mutation(window) is None
        root_a.bounds = dict(bounds)

        assert mcp.atspi_resolve_window_for_mutation(window) == (app_a, 0, root_a)
    finally:
        for name, value in originals.items():
            setattr(mcp, name, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
