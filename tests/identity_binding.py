#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))

from target_identity import parse_target, qualify_address, strip_target_qualifier


def load_ctl():
    path = ROOT / "scripts" / "hypr-agent-portalctl"
    loader = importlib.machinery.SourceFileLoader("hypr_agent_portalctl_identity", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def load_mcp():
    path = ROOT / "mcp" / "hypr-agent-portal-mcp.py"
    spec = importlib.util.spec_from_file_location("hypr_agent_portal_mcp_identity", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeAtspiNode:
    def __init__(self, *, title="", role="frame", bounds=None, accessible_id="", children=None, pid=0):
        self.title = title
        self.role = role
        self.bounds = bounds or {"x": 10.0, "y": 20.0, "width": 640.0, "height": 480.0}
        self.accessible_id = accessible_id
        self.children = list(children or [])
        self.pid = pid


def test_atspi_mutation_identity(mcp) -> None:
    """Confused-deputy regressions: every mismatch must produce zero actions."""
    original = {
        name: getattr(mcp, name)
        for name in (
            "atspi_init_error", "atspi_available", "process_start_time", "atspi_iter_apps",
            "atspi_pid", "atspi_app_windows", "atspi_name", "atspi_role",
            "atspi_accessible_id", "atspi_extents", "atspi_child_at", "atspi_do_action",
        )
    }
    actions = []
    expected_bounds = {"x": 10.0, "y": 20.0, "width": 640.0, "height": 480.0}
    leaf = FakeAtspiNode(title="Save")
    root_a = FakeAtspiNode(title="Document A", bounds=expected_bounds, accessible_id="root-a", children=[leaf])
    root_b = FakeAtspiNode(title="Document B", bounds=expected_bounds, accessible_id="root-b", children=[leaf])
    app_a = FakeAtspiNode(title="Editor", children=[root_a, root_b], pid=4100)
    app_b = FakeAtspiNode(title="Editor", children=[FakeAtspiNode(title="Document A", bounds=expected_bounds, accessible_id="root-a", children=[leaf])], pid=4200)
    window = {
        "address": "0xabc",
        "pid": 4100,
        "processStartTime": "777",
        "class": "Editor",
        "title": "Document A",
        "at": [10, 20],
        "size": [640, 480],
        "atspiRootIdentity": {
            "windowIndex": 0,
            "title": "Document A",
            "role": "frame",
            "accessibleId": "root-a",
            "bounds": expected_bounds,
        },
    }
    try:
        mcp.atspi_init_error = lambda: None
        mcp.atspi_available = lambda: True
        mcp.process_start_time = lambda pid: "777" if int(pid) == 4100 else "888"
        mcp.atspi_pid = lambda node: node.pid
        mcp.atspi_app_windows = lambda app: list(enumerate(app.children))
        mcp.atspi_name = lambda node: node.title
        mcp.atspi_role = lambda node: node.role
        mcp.atspi_accessible_id = lambda node: node.accessible_id
        mcp.atspi_extents = lambda node: dict(node.bounds)
        mcp.atspi_child_at = lambda node, index: node.children[index] if 0 <= index < len(node.children) else None
        mcp.atspi_do_action = lambda node, action=None: actions.append((node, action)) or True

        # PID A disappeared. Same class/title in PID B must never be used.
        mcp.atspi_iter_apps = lambda: [app_b]
        denied = mcp.atspi_child_action_payload({"operation": "do_action", "window": window, "runtimeId": [0, 0]})
        assert denied["ok"] is False and denied["status"] == "identity-mismatch"
        assert actions == []

        # Same PID with several roots: title/root-index mismatch must not pick
        # ACTIVE, SHOWING, first, or the other same-process root.
        swapped = FakeAtspiNode(title="Document B", bounds=expected_bounds, accessible_id="root-b", children=[leaf])
        app_a.children = [swapped, root_a]
        mcp.atspi_iter_apps = lambda: [app_a]
        denied = mcp.atspi_child_action_payload({"operation": "do_action", "window": window, "runtimeId": [0, 0]})
        assert denied["ok"] is False and actions == []

        # Both the direct-tool wrapper and the compatibility computer route
        # arrive at the same strict child gate and produce no native action.
        original_require = mcp.require_atspi_mutation_identity
        original_child_action = mcp.atspi_child_action
        original_semantic_action = mcp.semantic_perform_secondary_action
        try:
            mcp.require_atspi_mutation_identity = lambda _snapshot: window
            mcp.atspi_child_action = lambda operation, child_window, runtime_id=None, action=None, **_kwargs: mcp.atspi_child_action_payload(
                {"operation": operation, "window": child_window, "runtimeId": runtime_id, "action": action}
            )
            snapshot = {"window": window}
            element = {"runtimeId": [0, 0]}
            assert mcp.atspi_do_action_isolated(snapshot, element) is False
            mcp.semantic_perform_secondary_action = lambda _args: {"ok": mcp.atspi_do_action_isolated(snapshot, element)}
            assert mcp.computer({"action": "perform_secondary_action", "secondary_action": "jump"}) == {"ok": False}
            assert actions == []
        finally:
            mcp.require_atspi_mutation_identity = original_require
            mcp.atspi_child_action = original_child_action
            mcp.semantic_perform_secondary_action = original_semantic_action

        # PID reuse/starttime drift is denied even when all visible metadata matches.
        app_a.children = [root_a, root_b]
        mcp.process_start_time = lambda _pid: "778"
        denied = mcp.atspi_child_action_payload({"operation": "do_action", "window": window, "runtimeId": [0, 0]})
        assert denied["ok"] is False and actions == []

        # Captured root geometry drift is another root-identity change.
        mcp.process_start_time = lambda _pid: "777"
        root_a.bounds = {"x": 14.0, "y": 20.0, "width": 640.0, "height": 480.0}
        denied = mcp.atspi_child_action_payload({"operation": "do_action", "window": window, "runtimeId": [0, 0]})
        assert denied["ok"] is False and actions == []
        root_a.bounds = dict(expected_bounds)

        # A runtimeId is interpreted relative to the verified captured root.
        allowed = mcp.atspi_child_action_payload({"operation": "do_action", "window": window, "runtimeId": [0, 0]})
        assert allowed["ok"] is True and actions == [(leaf, None)]
        actions.clear()
        escaped = mcp.atspi_child_action_payload({"operation": "do_action", "window": window, "runtimeId": [1, 0]})
        assert escaped["ok"] is False and actions == []
    finally:
        for name, value in original.items():
            setattr(mcp, name, value)


def test_atspi_direct_and_computer_share_mutators(mcp) -> None:
    calls = []
    originals = (mcp.semantic_set_value, mcp.semantic_perform_secondary_action)
    try:
        mcp.semantic_set_value = lambda args: calls.append(("set", dict(args))) or {"ok": True}
        mcp.semantic_perform_secondary_action = lambda args: calls.append(("action", dict(args))) or {"ok": True}
        # Rebind table entry because it was created when the module loaded.
        mcp.computer({"action": "set_value", "app": "address:0xabc", "element_index": "1", "value": "x"})
        mcp.computer({"action": "perform_secondary_action", "app": "address:0xabc", "element_index": "1", "secondary_action": "jump"})
        assert calls[0][0] == "set"
        assert calls[1][0] == "action" and calls[1][1]["action"] == "jump"
    finally:
        mcp.semantic_set_value, mcp.semantic_perform_secondary_action = originals


def main() -> int:
    qualified = qualify_address("0xAbC", 321, 998877)
    assert qualified == "address:0xabc@pid=321@start=998877"
    parsed = parse_target(qualified)
    assert parsed.selector == "address:0xabc"
    assert parsed.pid == "321" and parsed.process_start_time == "998877"
    assert strip_target_qualifier(qualified) == "address:0xabc"
    assert strip_target_qualifier("title:^Editor$") == "title:^Editor$"
    for invalid in (
        "address:0xabc@pid=321",
        "address:0xabc@pid=0@start=1",
        "address:0xabc@start=1@pid=321",
    ):
        try:
            parse_target(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted malformed qualifier: {invalid}")

    ctl = load_ctl()
    client = {"address": "0xabc", "pid": 321, "class": "Editor", "title": "doc"}
    ctl.process_start_time = lambda _pid: "998877"
    assert ctl.selector_matches(client, qualified)
    # Simulate /proc identity changing while the compositor address is reused.
    ctl.process_start_time = lambda _pid: "998878"
    assert not ctl.selector_matches(client, qualified)
    assert ctl.selector_matches(client, "address:0xabc")  # legacy CLI remains compatible

    mcp = load_mcp()
    test_atspi_mutation_identity(mcp)
    test_atspi_direct_and_computer_share_mutators(mcp)
    live = {
        "address": "0xabc",
        "pid": 321,
        "processStartTime": "998877",
        "class": "Editor",
        "initialClass": "Editor",
        "workspace": {"name": "1"},
    }
    mcp.resolve_hypr_window = lambda _selector: dict(live)
    prepared, identity = mcp.prepare_execution_args("click", {"app": "Editor", "x": 1, "y": 2})
    assert prepared["app"] == qualified
    assert identity is not None and identity.pid == "321"
    live["processStartTime"] = "998878"
    try:
        mcp.revalidate_execution_identity(identity)
    except RuntimeError as exc:
        assert "identity changed" in str(exc) or "unavailable" in str(exc)
    else:
        raise AssertionError("address reuse was not rejected before execution")

    source = (ROOT / "src" / "plugin" / "main.cpp").read_text()
    assert "processStartTimeForPid" in source
    assert "window->getPID() != identity.pid" in source
    assert "*actualStartTime != identity.processStartTime" in source
    assert "auto window = resolveTargetWindow(targetRegex);" in source
    assert "auto window = resolveTargetWindow(parts[0]);" in source
    assert "const auto window = resolveTargetWindow(target);" in source
    assert source.count("resolveTargetWindow(parts[1])") >= 3
    assert "captureScreenshotSession(std::filesystem::path(path), targetWindow)" in source
    assert "captureScreenshotSession(std::filesystem::path(path), parsedTarget.selector)" not in source
    screenshot_dispatch = source[source.index("SDispatchResult dispatchScreenshot("):source.index("SDispatchResult dispatchSession(")]
    assert "window && window->m_isMapped && screenshotPrivacyDenied(window)" in screenshot_dispatch
    assert "!window->isHidden()" not in screenshot_dispatch
    assert "m_workspace->isVisible()" not in screenshot_dispatch
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
