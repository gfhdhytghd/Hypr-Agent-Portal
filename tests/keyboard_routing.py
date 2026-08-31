#!/usr/bin/env python3
import importlib.util
import pathlib
from types import SimpleNamespace


ROOT = pathlib.Path(__file__).resolve().parents[1]
MCP = ROOT / "mcp" / "hypr-agent-portal-mcp.py"
PLUGIN = ROOT / "src" / "plugin" / "main.cpp"


def load_mcp():
    spec = importlib.util.spec_from_file_location("hypr_agent_portal_mcp_keyboard", MCP)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeStateSet:
    def __init__(self, focused_state: object, focused: bool) -> None:
        self.focused_state = focused_state
        self.focused = focused

    def contains(self, state: object) -> bool:
        return self.focused and state is self.focused_state


class FakeEditableNode:
    def __init__(self, focused_state: object, focused: bool = True) -> None:
        self.state_set = FakeStateSet(focused_state, focused)
        self.editable_iface = object()
        self.text_iface = object()

    def is_editable_text(self) -> bool:
        return True

    def is_text(self) -> bool:
        return True

    def get_state_set(self):
        return self.state_set

    def get_editable_text_iface(self):
        return self.editable_iface

    def get_text_iface(self):
        return self.text_iface

    def get_child_count(self) -> int:
        return 0


def test_atspi_caret_insertion(mcp) -> None:
    focused_state = object()
    inserted: list[tuple[object, int, str, int]] = []
    fake_atspi = SimpleNamespace(
        StateType=SimpleNamespace(FOCUSED=focused_state),
        Text=SimpleNamespace(get_character_count=lambda _iface: 11, get_caret_offset=lambda _iface: 4),
        EditableText=SimpleNamespace(insert_text=lambda iface, offset, text, length: inserted.append((iface, offset, text, length)) or True),
    )
    original_atspi = mcp._ATSPI
    original_resolve = mcp.atspi_resolve_window
    try:
        node = FakeEditableNode(focused_state)
        mcp._ATSPI = fake_atspi
        mcp.atspi_resolve_window = lambda _window: (object(), 0, node)
        assert mcp.atspi_insert_text({"window": {}}, "hello", focused_only=True) is True
        assert inserted == [(node.editable_iface, 4, "hello", 5)]

        inserted.clear()
        node.state_set.focused = False
        assert mcp.atspi_insert_text({"window": {}}, "hello", focused_only=True) is False
        assert inserted == []
    finally:
        mcp._ATSPI = original_atspi
        mcp.atspi_resolve_window = original_resolve


def test_semantic_text_routing(mcp) -> None:
    focused_snapshot = {
        "target": "address:0xabc",
        "window": {"address": "0xabc"},
        "elements": [{"source": "atspi", "focused": True, "editable": True}],
    }
    calls: list[str] = []
    originals = {
        "current_snapshot": mcp.current_snapshot,
        "control_overlay": mcp.control_overlay,
        "atspi_insert_focused_text_isolated": mcp.atspi_insert_focused_text_isolated,
        "atspi_insert_text_isolated": mcp.atspi_insert_text_isolated,
        "prepare_grid_bulk_paste": mcp.prepare_grid_bulk_paste,
        "type_text": mcp.type_text,
        "snapshot_after_action": mcp.snapshot_after_action,
        "mcp_snapshot_result": mcp.mcp_snapshot_result,
    }
    try:
        mcp.current_snapshot = lambda _app: focused_snapshot
        mcp.control_overlay = lambda *_args, **_kwargs: None
        mcp.prepare_grid_bulk_paste = lambda *_args, **_kwargs: None
        mcp.snapshot_after_action = lambda _app, _snapshot, info=None: {"action": info}
        mcp.mcp_snapshot_result = lambda result: result
        mcp.atspi_insert_text_isolated = lambda *_args, **_kwargs: calls.append("explicit-atspi") or True
        mcp.type_text = lambda *_args, **_kwargs: calls.append("keys") or {"method": "keys"}

        mcp.atspi_insert_focused_text_isolated = lambda *_args, **_kwargs: calls.append("focused-atspi") or True
        result = mcp.semantic_type_text({"app": "demo", "text": "abc", "method": "auto"})
        assert calls == ["focused-atspi"]
        assert result["action"] == {"method": "atspi", "targeting": "focused-editable"}

        calls.clear()
        mcp.atspi_insert_focused_text_isolated = lambda *_args, **_kwargs: calls.append("focused-atspi") or False
        result = mcp.semantic_type_text({"app": "demo", "text": "abc", "method": "auto"})
        assert calls == ["focused-atspi", "keys"]
        assert result["action"]["method"] == "keys"

        calls.clear()
        result = mcp.semantic_type_text({"app": "demo", "text": "a\tb", "method": "auto"})
        assert calls == ["keys"]
        assert result["action"]["method"] == "keys"

        calls.clear()
        focused_snapshot["elements"] = [{"source": "atspi", "focused": False, "editable": True}]
        result = mcp.semantic_type_text({"app": "demo", "text": "abc", "method": "auto"})
        assert calls == ["keys"]
        assert result["action"]["method"] == "keys"

        calls.clear()
        result = mcp.semantic_type_text({"app": "demo", "text": "abc", "method": "atspi"})
        assert calls == ["explicit-atspi"]
        assert result["action"] == {"method": "atspi", "targeting": "editable"}
    finally:
        for name, value in originals.items():
            setattr(mcp, name, value)


def test_plugin_focus_invariants() -> None:
    source = PLUGIN.read_text(encoding="utf-8")
    start = source.index("SDispatchResult dispatchKeyboard(")
    end = source.index("SDispatchResult dispatchScreenshot(", start)
    dispatcher = source[start:end]
    assert "KeyboardResourceTransaction" in dispatcher
    assert "setKeyboardFocus" not in dispatcher
    assert "g_pSeatManager->sendKeyboard" not in dispatcher
    assert "targetKeyConflictsWithPhysicalInput" in dispatcher
    assert "restoreXWaylandKeyboardFocusLater" in dispatcher
    assert "input.keyboard.key.listen" in source
    assert "input.mouse.button.listen" in source
    assert "input.mouse.move.listen" in source

    takeover_start = source.index("void handleHumanTakeover(")
    takeover_end = source.index("void sendClipboardSelectionToNativeTarget", takeover_start)
    takeover = source[takeover_start:takeover_end]
    assert "if (pointerInput)" in takeover
    assert "if (hadAsyncOperation)\n            cancelAsyncPointerOperation();" in takeover
    assert "if (hadKeyboardLease)\n        restoreXWaylandKeyboardFocus();" in takeover
    # Keyboard events call the handler with false, pointer events with true:
    # only the pointer branch cancels an in-flight drag, while both reclaim an
    # active XWayland keyboard lease.
    assert "handleHumanTakeover(false)" in source
    assert source.count("handleHumanTakeover(true)") >= 3

    approval_start = source.index("SDispatchResult dispatchApproval(")
    approval_end = source.index("SDispatchResult dispatchGuard(", approval_start)
    approval = source[approval_start:approval_end]
    assert 'action == "arm"' in approval
    assert 'action == "status"' in approval
    assert 'action == "cancel"' in approval
    assert 'action == "approve"' not in approval
    assert "validApprovalChallengeId" in approval
    assert "ttlMs < 1000 || ttlMs > 120000" in approval
    assert "never extends its" in approval
    assert '"hypr-agent-portal:approval"' in source
    assert '"hypr-agent-protal:approval"' in source
    assert "case eLuaDispatcher::APPROVAL: return dispatchApproval(payload);" in source
    assert "int luaApproval(lua_State* L)" in source
    assert 'addLuaFunction(g_pluginHandle, name, "approval", luaApproval)' in source

    physical_start = source.index("void handlePhysicalApprovalKey(")
    physical_end = source.index("void sendClipboardSelectionToNativeTarget", physical_start)
    physical = source[physical_start:physical_end]
    assert "event.state != WL_KEYBOARD_KEY_STATE_PRESSED" in physical
    assert "event.keycode != KEY_F12" in physical
    assert "physicalApprovalKeyHeld()" in physical
    assert "!keyboard->isVirtual()" in source
    assert "handlePhysicalApprovalKey(event);" in source


def main() -> int:
    mcp = load_mcp()
    test_atspi_caret_insertion(mcp)
    test_semantic_text_routing(mcp)
    test_plugin_focus_invariants()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
