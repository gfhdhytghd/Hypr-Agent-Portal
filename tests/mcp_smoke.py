#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: mcp_smoke.py <mcp-script>", file=sys.stderr)
        return 2

    script = pathlib.Path(sys.argv[1]).resolve()
    repo = script.parents[1]
    payload = "\n".join(
        [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "hypr-agent-protal-smoke", "version": "0"},
                    },
                }
            ),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            "",
        ]
    )

    proc = subprocess.run(
        [sys.executable, str(script)],
        input=payload,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=repo,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return proc.returncode or 1

    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert lines[0]["result"]["serverInfo"]["name"] == "hypr-agent-protal"
    tools = lines[1]["result"]["tools"]
    tools_by_name = {tool["name"]: tool for tool in tools}
    expected_tools = {
        "computer",
        "list_apps",
        "launch_app",
        "open_app",
        "get_app_state",
        "read_app_state",
        "screenshot",
        "get_screenshot",
        "get_cursor_position",
        "list_windows",
        "click",
        "perform_secondary_action",
        "activate_menu_item",
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
        "type_text",
        "type",
        "paste_text",
        "press_key",
        "key",
        "set_value",
        "wait",
        "wait_for_window",
        "wait_for_close",
    }
    assert set(tools_by_name) == expected_tools
    assert lines[0]["result"]["serverInfo"]["version"] == "0.3.47"
    actions = set(tools_by_name["computer"]["inputSchema"]["properties"]["action"]["enum"])
    for action in ["screenshot", "windows", "click", "scroll", "drag", "key", "type", "paste_image", "session", "get_app_state", "read_app_state", "wait", "wait_for_window", "wait_for_close", "doctor", "launch", "launch_app", "open_app", "get_cursor_position", "activate_menu_item", "left_click", "left_click_drag", "hover"]:
        assert action in actions
    assert tools_by_name["launch_app"]["inputSchema"]["properties"]["url"]["type"] == "string"
    assert tools_by_name["launch_app"]["inputSchema"]["properties"]["new_window"]["default"] is True
    assert tools_by_name["launch_app"]["inputSchema"]["properties"]["reuse_existing"]["default"] is True
    assert tools_by_name["launch_app"]["inputSchema"]["properties"]["timeout"]["minimum"] == 0
    assert tools_by_name["launch_app"]["inputSchema"]["properties"]["timeout"]["maximum"] == 30
    assert tools_by_name["computer"]["inputSchema"]["properties"]["timeout"]["maximum"] == 30
    assert tools_by_name["computer"]["inputSchema"]["properties"]["coordinate"]["minItems"] == 2
    assert "window" in tools_by_name["computer"]["inputSchema"]["properties"]["coordinate_space"]["enum"]
    assert tools_by_name["computer"]["inputSchema"]["properties"]["keycode"]["type"] == "integer"
    assert tools_by_name["computer"]["inputSchema"]["properties"]["show_cursor"]["type"] == "boolean"
    assert tools_by_name["computer"]["inputSchema"]["properties"]["show_cursor"]["default"] is False
    assert "agent" in tools_by_name["computer"]["inputSchema"]["properties"]["cursor_source"]["enum"]
    assert tools_by_name["computer"]["inputSchema"]["properties"]["cursor_source"]["default"] == "none"
    assert "keys" in tools_by_name["computer"]["inputSchema"]["properties"]["method"]["enum"]
    assert "atspi" in tools_by_name["type_text"]["inputSchema"]["properties"]["method"]["enum"]
    assert tools_by_name["paste_text"]["inputSchema"]["required"] == ["app", "text"]
    assert tools_by_name["paste_text"]["inputSchema"]["properties"]["restore_clipboard"]["default"] is True
    assert tools_by_name["computer"]["inputSchema"]["properties"]["prefer_related"]["type"] == "boolean"
    assert tools_by_name["computer"]["inputSchema"]["properties"]["restore_clipboard"]["type"] == "boolean"
    assert tools_by_name["computer"]["inputSchema"]["properties"]["restore_delay"]["default"] == 1.0
    assert tools_by_name["computer"]["inputSchema"]["properties"]["related_to"]["type"] == "string"
    assert "begin" in tools_by_name["computer"]["inputSchema"]["properties"]["session_action"]["enum"]

    assert tools_by_name["get_app_state"]["inputSchema"]["required"] == ["app"]
    assert tools_by_name["get_cursor_position"]["inputSchema"]["properties"]["include_global"]["default"] is False
    assert tools_by_name["click"]["inputSchema"]["properties"]["element_index"]["type"] == "string"
    assert tools_by_name["click"]["inputSchema"]["properties"]["name"]["type"] == "string"
    assert tools_by_name["click"]["inputSchema"]["properties"]["coordinate"]["minItems"] == 2
    assert "window" in tools_by_name["click"]["inputSchema"]["properties"]["coordinate_space"]["enum"]
    assert tools_by_name["click"]["inputSchema"]["properties"]["element_click_mode"]["default"] == "pointer"
    assert "atspi" in tools_by_name["click"]["inputSchema"]["properties"]["element_click_mode"]["enum"]
    assert tools_by_name["computer"]["inputSchema"]["properties"]["element_click_mode"]["default"] == "pointer"
    assert tools_by_name["drag"]["inputSchema"]["required"] == ["app"]
    assert tools_by_name["left_click_drag"]["inputSchema"]["required"] == ["app", "start_coordinate", "coordinate"]
    assert tools_by_name["press_key"]["inputSchema"]["properties"]["key"]["type"] == "string"
    assert tools_by_name["press_key"]["inputSchema"]["properties"]["keys"]["type"] == "string"
    assert tools_by_name["press_key"]["inputSchema"]["properties"]["modifiers"]["type"] == "string"
    assert tools_by_name["press_key"]["inputSchema"]["properties"]["keycode"]["type"] == "integer"
    assert tools_by_name["key"]["inputSchema"]["properties"]["repeat"]["type"] == "integer"
    assert tools_by_name["key"]["inputSchema"]["properties"]["keys"]["type"] == "string"
    assert tools_by_name["key"]["inputSchema"]["properties"]["modifiers"]["type"] == "string"
    assert tools_by_name["key"]["inputSchema"]["properties"]["keycode"]["type"] == "integer"
    assert tools_by_name["set_value"]["inputSchema"]["required"] == ["app", "element_index", "value"]
    assert tools_by_name["wait_for_window"]["inputSchema"]["properties"]["related_to"]["type"] == "string"
    assert tools_by_name["wait_for_window"]["inputSchema"]["properties"]["timeout"]["maximum"] == 30
    assert tools_by_name["wait_for_close"]["inputSchema"]["properties"]["related_to"]["type"] == "string"
    assert tools_by_name["wait_for_close"]["inputSchema"]["properties"]["timeout"]["maximum"] == 30
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
