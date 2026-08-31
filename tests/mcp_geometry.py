#!/usr/bin/env python3
import importlib.util
import math
import os
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp" / "hypr-agent-portal-mcp.py"


def load_mcp():
    spec = importlib.util.spec_from_file_location("hypr_agent_portal_mcp", MCP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def near(actual: float, expected: float, epsilon: float = 0.001) -> None:
    assert abs(actual - expected) <= epsilon, f"{actual} != {expected}"


class DummyActionNode:
    def __init__(self, actions: list[str]) -> None:
        self.actions = actions

    def get_n_actions(self) -> int:
        return len(self.actions)

    def get_action_name(self, index: int) -> str:
        return self.actions[index]

    def get_action_description(self, index: int) -> str:
        return ""


def main() -> int:
    mcp = load_mcp()
    assert mcp.bounded_timeout_seconds(30000, 8.0) == 30.0
    assert mcp.bounded_timeout_seconds(-1, 8.0) == 0.0
    assert mcp.bounded_timeout_seconds(True, 8.0) == 8.0
    assert mcp.bounded_timeout_seconds(math.nan, 8.0) == 8.0
    assert mcp.bounded_timeout_seconds(math.inf, 8.0) == 8.0
    window = {"at": [1772, 2108], "size": [1416, 828]}
    screenshot = {
        "width": 2862,
        "height": 1686,
        "scale": 2.0,
        "logicalBounds": {"x": 1764.5, "y": 2100.5, "width": 1431.0, "height": 843.0},
    }
    root_local = {"x": 0.0, "y": 0.0, "width": 1416.0, "height": 828.0}
    file_menu_local = {"x": 0.0, "y": 0.0, "width": 57.0, "height": 22.0}

    frame = mcp.atspi_bounds_to_screenshot_frame(file_menu_local, root_local, screenshot, window)
    near(frame["x"], 15.0)
    near(frame["y"], 15.0)
    near(frame["width"], 114.0)
    near(frame["height"], 44.0)

    root_frame = mcp.atspi_bounds_to_screenshot_frame(root_local, root_local, screenshot, window)
    near(root_frame["x"], 15.0)
    near(root_frame["y"], 15.0)
    near(root_frame["width"], 2832.0)
    near(root_frame["height"], 1656.0)

    root_global = {"x": 1772.0, "y": 2108.0, "width": 1416.0, "height": 828.0}
    file_menu_global = {"x": 1772.0, "y": 2108.0, "width": 57.0, "height": 22.0}
    global_frame = mcp.atspi_bounds_to_screenshot_frame(file_menu_global, root_global, screenshot, window)
    assert global_frame == frame

    corrected, offset = mcp.corrected_large_grid_cell_bounds(
        {"x": 40.5, "y": 146.5, "width": 149.0, "height": 30.0},
        {"x": 40.5, "y": 146.5, "width": 1308.0, "height": 596.0},
        row=0,
        col=0,
        large_grid=True,
        header_y_offset=None,
    )
    near(offset, 30.0)
    near(corrected["y"], 176.5)
    second, offset = mcp.corrected_large_grid_cell_bounds(
        {"x": 40.5, "y": 176.5, "width": 149.0, "height": 30.0},
        {"x": 40.5, "y": 146.5, "width": 1308.0, "height": 596.0},
        row=1,
        col=0,
        large_grid=True,
        header_y_offset=offset,
    )
    near(second["y"], 206.5)
    small, small_offset = mcp.corrected_large_grid_cell_bounds(
        {"x": 0.0, "y": 0.0, "width": 80.0, "height": 20.0},
        {"x": 0.0, "y": 0.0, "width": 240.0, "height": 80.0},
        row=0,
        col=0,
        large_grid=False,
        header_y_offset=None,
    )
    near(small["y"], 0.0)
    assert small_offset is None

    snapshot = {"window": window, "screenshot": screenshot}
    near(mcp.window_point_to_global(snapshot, 0, 0)[0], 1772.0)
    near(mcp.window_point_to_global(snapshot, 0, 0)[1], 2108.0)
    near(mcp.screenshot_point_to_global(snapshot, 15, 15)[0], 1772.0)
    near(mcp.screenshot_point_to_global(snapshot, 15, 15)[1], 2108.0)
    pos = mcp.snapshot_position(snapshot, 1772.0, 2108.0)
    near(pos["window"]["x"], 0.0)
    near(pos["window"]["y"], 0.0)
    near(pos["screenshot"]["x"], 15.0)
    near(pos["screenshot"]["y"], 15.0)
    shadow_pos = mcp.snapshot_position(snapshot, 3190.0, 2108.0)
    assert shadow_pos["insideScreenshot"] is True
    assert shadow_pos["insideWindow"] is False

    model_screenshot = {
        "width": 1431,
        "height": 843,
        "scale": 1.0,
        "scaleX": 1.0,
        "scaleY": 1.0,
        "logicalBounds": screenshot["logicalBounds"],
    }
    model_snapshot = {"window": window, "screenshot": model_screenshot}
    near(mcp.screenshot_point_to_global(model_snapshot, 0, 0)[0], 1764.5)
    near(mcp.screenshot_point_to_global(model_snapshot, 0, 0)[1], 2100.5)
    model_pos = mcp.snapshot_position(model_snapshot, 1764.5 + 100, 2100.5 + 100)
    near(model_pos["screenshot"]["x"], 100.0)
    near(model_pos["screenshot"]["y"], 100.0)

    original_list_hypr_windows = mcp.list_hypr_windows
    original_build_app_snapshot = mcp.build_app_snapshot
    try:
        moved_snapshot = {
            "app": {"name": "demo", "bundleIdentifier": "demo", "pid": 1},
            "target": "address:0xa11",
            "window": {"address": "0xa11", "pid": os.getpid(), "class": "demo", "at": [10, 20], "size": [100, 80]},
            "windowBounds": {"x": 10.0, "y": 20.0, "width": 100.0, "height": 80.0},
            "screenshot": {"width": 100, "height": 80, "logicalBounds": {"x": 10.0, "y": 20.0, "width": 100.0, "height": 80.0}},
            "elements": [{"index": 3, "source": "atspi", "controlType": "push button", "name": "OK", "frame": {"x": 20.0, "y": 10.0, "width": 20.0, "height": 20.0}}],
            "treeLines": [],
            "uiHints": {},
            "accessibility": {"status": "ok"},
        }
        mcp.SNAPSHOTS.clear()
        mcp.SNAPSHOTS["demo"] = moved_snapshot
        mcp.list_hypr_windows = lambda: [{"address": "0xa11", "pid": os.getpid(), "class": "demo", "at": [45, 60], "size": [100, 80], "mapped": True, "hidden": False}]
        shifted = mcp.current_snapshot("demo")
        near(shifted["screenshot"]["logicalBounds"]["x"], 45.0)
        near(shifted["screenshot"]["logicalBounds"]["y"], 60.0)
        near(mcp.screenshot_point_to_global(shifted, 30, 20)[0], 75.0)
        near(mcp.screenshot_point_to_global(shifted, 30, 20)[1], 80.0)

        resized_snapshot = {
            **moved_snapshot,
            "target": "address:0xb22",
            "window": {"address": "0xb22", "pid": os.getpid(), "class": "demo", "at": [10, 20], "size": [100, 80]},
            "windowBounds": {"x": 10.0, "y": 20.0, "width": 100.0, "height": 80.0},
            "elements": [
                {
                    "index": 3,
                    "runtimeId": [0, 1, 2],
                    "automationId": "ok-button",
                    "source": "atspi",
                    "controlType": "push button",
                    "name": "OK",
                    "frame": {"x": 20.0, "y": 10.0, "width": 20.0, "height": 20.0},
                }
            ],
        }
        rebuilt_snapshot = {
            **resized_snapshot,
            "target": "address:0xb22",
            "window": {"address": "0xb22", "pid": os.getpid(), "class": "demo", "at": [10, 20], "size": [180, 120]},
            "windowBounds": {"x": 10.0, "y": 20.0, "width": 180.0, "height": 120.0},
            "screenshot": {"width": 180, "height": 120, "logicalBounds": {"x": 10.0, "y": 20.0, "width": 180.0, "height": 120.0}},
            "elements": [
                {"index": 0, "source": "atspi", "controlType": "frame", "name": "Demo", "frame": {"x": 0.0, "y": 0.0, "width": 180.0, "height": 120.0}},
                {
                    "index": 9,
                    "runtimeId": [0, 1, 2],
                    "automationId": "ok-button",
                    "source": "atspi",
                    "controlType": "push button",
                    "name": "OK",
                    "frame": {"x": 80.0, "y": 60.0, "width": 30.0, "height": 24.0},
                },
            ],
        }
        mcp.SNAPSHOTS.clear()
        mcp.SNAPSHOTS["demo"] = resized_snapshot
        mcp.list_hypr_windows = lambda: [{"address": "0xb22", "pid": os.getpid(), "class": "demo", "at": [10, 20], "size": [180, 120], "mapped": True, "hidden": False}]
        mcp.build_app_snapshot = lambda app: rebuilt_snapshot
        element_snapshot, element, refresh = mcp.element_snapshot_for_action("demo", "3")
        assert element_snapshot is rebuilt_snapshot
        assert element["index"] == 9
        assert refresh["geometryRefresh"]["change"] == "resized"
        assert refresh["elementRematch"]["matched"] is True
        assert "runtimeId" in refresh["elementRematch"]["matchedBy"]
    finally:
        mcp.SNAPSHOTS.clear()
        mcp.list_hypr_windows = original_list_hypr_windows
        mcp.build_app_snapshot = original_build_app_snapshot

    original_related_windows_for = mcp.related_windows_for
    try:
        mcp.related_windows_for = lambda target: [
            {"address": "0x1", "hyprAgentPortalRelation": "self", "class": "libreoffice-calc", "mapped": True, "hidden": False},
            {
                "address": "0x2",
                "hyprAgentPortalRelation": "related",
                "hyprAgentPortalWindowKind": "related",
                "class": "libreoffice-calc",
                "mapped": True,
                "hidden": False,
                "floating": False,
            },
            {
                "address": "0x3",
                "hyprAgentPortalRelation": "related",
                "hyprAgentPortalWindowKind": "related",
                "class": "soffice",
                "mapped": True,
                "hidden": False,
                "floating": True,
            },
        ]
        related = mcp.related_popups_for("address:0x1")
        assert [item["address"] for item in related] == ["0x3"]
        selected, meta = mcp.prefer_related_target("address:0x1")
        assert selected == "address:0x1" and meta is None
        try:
            mcp.prefer_related_target("address:0x1", True)
        except RuntimeError as exc:
            assert "target the popup explicitly" in str(exc)
        else:
            raise AssertionError("automatic related-window rerouting remained enabled")
        active = mcp.active_related_windows(mcp.related_windows_for("address:0x1"))
        assert [item["address"] for item in active] == ["0x3"]
    finally:
        mcp.related_windows_for = original_related_windows_for

    assert mcp.atspi_preferred_action_index(DummyActionNode(["showContextMenu", "jump"])) == 1
    assert mcp.element_has_primary_atspi_action({"source": "atspi", "actions": ["jump"]}) is True
    assert mcp.element_has_primary_atspi_action({"source": "synthetic", "actions": ["jump"]}) is False
    assert mcp.element_is_menu_item({"controlType": "menu item"}) is True
    assert mcp.element_is_menu_item({"controlType": "push button"}) is False
    assert mcp.element_click_mode({}) == "pointer"
    assert mcp.element_click_mode({"element_click_mode": "auto"}) == "auto"
    assert mcp.element_click_mode({"element_click_mode": "semantic"}) == "atspi"
    assert mcp.scroll_action_for_direction("down") == "scrollDown"
    assert mcp.element_supports_scroll_direction({"source": "atspi", "actions": ["scrollDown"]}, "down") is True

    scroll_snapshot = {
        "screenshot": {"width": 2862, "height": 1686},
        "elements": [
            {"source": "atspi", "controlType": "document web", "actions": ["scrollDown"], "frame": {"x": 15.0, "y": 363.0, "width": 5664.0, "height": 2964.0}},
            {"source": "atspi", "controlType": "section", "actions": ["scrollDown"], "frame": {"x": 15.0, "y": 363.0, "width": 200.0, "height": 200.0}},
        ],
    }
    scroll_element = mcp.best_scroll_element(scroll_snapshot, "down")
    assert scroll_element is scroll_snapshot["elements"][0]
    center = mcp.visible_element_center(scroll_snapshot, scroll_element)
    near(center[0], 1438.5)
    near(center[1], 1024.5)

    hints_snapshot = {
        "screenshot": {"width": 1000, "height": 600},
    }
    hints = mcp.ui_hints_for_elements(
        hints_snapshot,
        [
            {"index": 1, "source": "atspi", "controlType": "menu", "name": "Insert", "frame": {"x": 100.0, "y": 0.0, "width": 80.0, "height": 36.0}},
            {"index": 2, "source": "atspi", "controlType": "page tab", "name": "Insert", "frame": {"x": 200.0, "y": 0.0, "width": 90.0, "height": 36.0}},
            {"index": 3, "source": "atspi", "controlType": "tool bar", "name": "Formatting", "frame": {"x": 0.0, "y": 40.0, "width": 1000.0, "height": 80.0}},
            {"index": 4, "source": "atspi", "controlType": "table", "name": "Sheet", "frame": {"x": 0.0, "y": 120.0, "width": 1000.0, "height": 400.0}},
        ],
    )
    assert hints["visibleMenus"][0]["index"] == 1
    assert hints["visibleTabs"][0]["index"] == 2
    assert all(item["index"] != 4 for item in hints["visibleTabs"])
    assert hints["visibleToolbars"][0]["index"] == 3
    assert "can be a classic menu" in hints["notes"][0]
    form_hints = mcp.ui_hints_for_elements(
        {"screenshot": {"width": 500, "height": 360}},
        [
            {"index": 1, "source": "atspi", "controlType": "radio button", "name": "Option", "frame": {"x": 10, "y": 10, "width": 60, "height": 20}},
            {"index": 2, "source": "atspi", "controlType": "push button", "name": "OK", "frame": {"x": 10, "y": 40, "width": 60, "height": 20}},
        ],
    )
    assert any("verify the visible form values" in note for note in form_hints["notes"])
    action_hints = mcp.ui_hints_for_elements(
        hints_snapshot,
        [
            {"index": 5, "source": "atspi", "controlType": "push button", "name": "Chart", "frame": {"x": 100.0, "y": 40.0, "width": 80.0, "height": 32.0}},
        ],
    )
    assert action_hints["visibleActions"][0]["index"] == 5
    menu_snapshot = {
        "app": {"name": "demo", "bundleIdentifier": "demo", "pid": 42},
        "window": {"class": "demo", "workspace": {"name": "1"}, "xwayland": False},
        "target": "address:0x1",
        "windowTitle": "Demo",
        "treeLines": [],
        "globalMenu": {
            "providers": [{"provider": "dbusmenu", "service": ":1.2", "objectPath": "/com/canonical/dbusmenu", "itemCount": 2}],
            "items": [
                {"menuIndex": "menu:0", "provider": "dbusmenu", "label": "File", "depth": 0, "enabled": True},
                {"menuIndex": "menu:1", "provider": "dbusmenu", "label": "Open", "depth": 1, "enabled": True},
            ],
        },
        "uiHints": {},
        "accessibility": {"status": "ok"},
    }
    rendered = mcp.render_snapshot_text(menu_snapshot)
    assert "Global menu models:" in rendered
    assert "menu:1 Open" in rendered
    assert mcp.find_global_menu_item(menu_snapshot, "menu:1")["label"] == "Open"
    popup_snapshot = {
        **menu_snapshot,
        "activeRelatedTarget": "address:0xpopup",
        "activeRelatedWindow": {"address": "0xpopup", "title": "Chart Type", "class": "soffice"},
    }
    rendered_popup = mcp.render_snapshot_text(popup_snapshot)
    assert "ACTIVE RELATED POPUP DETECTED:" in rendered_popup
    assert "address:0xpopup" in rendered_popup
    delta = mcp.window_delta(
        [{"address": "0xroot", "title": "Root", "hyprAgentPortalRelation": "self"}],
        [
            {"address": "0xroot", "title": "Root", "hyprAgentPortalRelation": "self"},
            {"address": "0xpopup", "title": "Dialog", "hyprAgentPortalWindowKind": "popup", "hyprAgentPortalRelation": "related"},
        ],
    )
    assert delta["opened"][0]["target"] == "address:0xpopup"
    action_delta_snapshot = {**menu_snapshot, "lastAction": {"windowDelta": delta}}
    assert "opened address:0xpopup" in mcp.render_snapshot_text(action_delta_snapshot)
    original_build_app_snapshot = mcp.build_app_snapshot
    original_list_hypr_windows = mcp.list_hypr_windows
    original_resolve_hypr_window = mcp.resolve_hypr_window
    try:
        before_popup = {
            "target": "address:0xpopup",
            "app": {"pid": 1234},
            "relatedWindows": [
                {
                    "address": "0xroot",
                    "hyprAgentPortalRelation": "related",
                    "hyprAgentPortalWindowKind": "related",
                    "mapped": True,
                    "hidden": False,
                    "floating": False,
                }
            ],
        }

        def fake_build_app_snapshot(app: str) -> dict:
            if app == "address:0xpopup":
                raise RuntimeError('appNotFound("address:0xpopup")')
            assert app == "address:0xroot"
            return {
                "app": {"name": "root", "bundleIdentifier": "root", "pid": 1234},
                "window": {"address": "0xroot", "class": "root", "workspace": {"name": "1"}, "pid": 1234, "processStartTime": "5678", "xwayland": False},
                "target": "address:0xroot",
                "windowTitle": "Root",
                "treeLines": [],
                "uiHints": {},
                "accessibility": {"status": "ok"},
            }

        mcp.build_app_snapshot = fake_build_app_snapshot
        mcp.list_hypr_windows = lambda: []
        mcp.resolve_hypr_window = lambda app: {"address": "0xroot", "class": "root", "workspace": {"name": "1"}, "pid": 1234, "processStartTime": "5678"}
        after_closed = mcp.snapshot_after_action("address:0xpopup", before_popup)
        assert after_closed["target"] == "address:0xroot"
        assert after_closed["lastAction"]["targetClosed"] is True
        rendered_after_closed = mcp.render_snapshot_text(after_closed)
        assert "ACTION RESULT:" in rendered_after_closed
        assert "address:0xpopup closed" in rendered_after_closed
    finally:
        mcp.build_app_snapshot = original_build_app_snapshot
        mcp.list_hypr_windows = original_list_hypr_windows
        mcp.resolve_hypr_window = original_resolve_hypr_window
    original_wait_window_candidates = mcp.wait_window_candidates
    original_build_app_snapshot = mcp.build_app_snapshot
    try:
        mcp.wait_window_candidates = lambda args: [{"address": "0xwait", "title": "Dialog", "hyprAgentPortalWindowKind": "popup"}]
        mcp.build_app_snapshot = lambda app: {
            "app": {"name": "wait", "bundleIdentifier": "wait", "pid": 1},
            "window": {"address": "0xwait", "class": "wait", "workspace": {"name": "1"}, "xwayland": False},
            "target": app,
            "windowTitle": "Dialog",
            "treeLines": [],
            "uiHints": {},
            "accessibility": {"status": "ok"},
        }
        waited = mcp.semantic_wait_for_window({"related_to": "address:0xroot", "timeout": 0})
        assert waited["structuredContent"]["target"] == "address:0xwait"
        assert waited["structuredContent"]["lastAction"]["wait"] == "window"
    finally:
        mcp.wait_window_candidates = original_wait_window_candidates
        mcp.build_app_snapshot = original_build_app_snapshot
    gmenu_action = {"objectPath": "/org/example/window/1/menus/menubar", "action": "win.insert-chart"}
    assert mcp.gtk_action_candidates_for_menu(gmenu_action)[0] == ("/org/example/window/1", "insert-chart")
    assert mcp.text_is_bulk_paste_candidate("A\tB\n1\t2") is True
    assert mcp.text_is_bulk_paste_candidate("short") is False
    assert mcp.snapshot_has_grid_target({"elements": [{"controlType": "table cell"}]}) is True

    original_list_hypr_windows = mcp.list_hypr_windows
    original_monotonic = mcp.time.monotonic
    original_sleep = mcp.time.sleep
    try:
        existing_window = {"address": "0xold", "class": "chromium", "title": "Old Chromium"}
        mcp.list_hypr_windows = lambda: [existing_window]
        reused, reused_new = mcp.wait_for_launch_window({"address:0xold"}, "chromium", 0.0, allow_existing_fallback=True)
        assert reused is existing_window
        assert reused_new == []
        strict, strict_new = mcp.wait_for_launch_window({"address:0xold"}, "chromium", 0.0, allow_existing_fallback=False)
        assert strict is None
        assert strict_new == []

        unrelated_new = {"address": "0xnew", "class": "splash", "title": "Starting"}
        mcp.list_hypr_windows = lambda: [existing_window, unrelated_new]
        selected, selected_new = mcp.wait_for_launch_window({"address:0xold"}, "chromium", 0.0, allow_existing_fallback=False)
        assert selected is unrelated_new
        assert selected_new == [unrelated_new]

        monotonic_values = iter([0.0, 0.0, 1.1])
        mcp.time.monotonic = lambda: next(monotonic_values)
        mcp.time.sleep = lambda duration: None
        selected, selected_new = mcp.wait_for_launch_window({"address:0xold"}, "chromium", 30.0, allow_existing_fallback=False)
        assert selected is unrelated_new
        assert selected_new == [unrelated_new]
    finally:
        mcp.list_hypr_windows = original_list_hypr_windows
        mcp.time.monotonic = original_monotonic
        mcp.time.sleep = original_sleep

    original_launch_parts = mcp.launch_parts
    original_list_hypr_windows = mcp.list_hypr_windows
    original_hyprctl_exec = mcp.hyprctl_exec
    original_wait_for_launch_window = mcp.wait_for_launch_window
    launch_timeouts = []
    try:
        mcp.launch_parts = lambda args: (["fake-app"], "fake-app")
        mcp.list_hypr_windows = lambda: []
        mcp.hyprctl_exec = lambda command: "ok"

        def capture_launch_timeout(before_ids, query, timeout, *, allow_existing_fallback=True):
            launch_timeouts.append(timeout)
            return None, []

        mcp.wait_for_launch_window = capture_launch_timeout
        mcp.tool_launch_app({"app": "fake-app", "reuse_existing": False, "timeout": 30000})
        assert launch_timeouts == [mcp.MAX_TOOL_WAIT_SECONDS]
    finally:
        mcp.launch_parts = original_launch_parts
        mcp.list_hypr_windows = original_list_hypr_windows
        mcp.hyprctl_exec = original_hyprctl_exec
        mcp.wait_for_launch_window = original_wait_for_launch_window

    original_busctl_user = mcp.busctl_user
    busctl_timeouts = []
    try:
        mcp.busctl_user = lambda args, timeout=2.0: (busctl_timeouts.append(timeout) or False, "")
        assert mcp.dbus_tree_paths(":1.234") == []
        assert busctl_timeouts == [mcp.GLOBAL_MENU_TREE_TIMEOUT_SECONDS]
    finally:
        mcp.busctl_user = original_busctl_user
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
