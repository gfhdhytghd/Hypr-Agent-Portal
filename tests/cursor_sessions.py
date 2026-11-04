#!/usr/bin/env python3
"""Headless cursor identity, wire, lifecycle and security contract tests."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))
import cursor_visualization as visual


def load(path):
    name = "cursor_test_" + uuid.uuid4().hex
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def bridge(**settings):
    env = {key: value for key, value in os.environ.items() if not key.startswith(("HYPR_AGENT_PORTAL_", "HYPR_AGENT_PROTAL_"))}
    env.update({"HYPR_AGENT_PORTAL_SECURITY_ENABLED": "1", "HYPR_AGENT_PORTAL_SECURITY_DEFAULT_AUTHORIZATION": "full"})
    env.update({"HYPR_AGENT_PORTAL_" + key: value for key, value in settings.items()})
    with patch.dict(os.environ, env, clear=True):
        return load(ROOT / "mcp" / "hypr-agent-portal-mcp.py")


class CursorSessions(unittest.TestCase):
    def test_process_ids_not_environment_or_caller_controlled(self):
        one = bridge(CURSOR_SESSION="attacker")
        two = bridge(CURSOR_SESSION="attacker")
        self.assertNotEqual(one.CURSOR_SESSION, two.CURSOR_SESSION)
        self.assertNotEqual(one.CURSOR_SESSION, "attacker")
        visual.validate_session(one.CURSOR_SESSION)
        # Separate actual Python processes independently mint identity too.
        cmd = [sys.executable, "-c", "from cursor_visualization import new_session_id; print(new_session_id())"]
        env = {**os.environ, "PYTHONPATH": str(ROOT / "mcp")}
        ids = [subprocess.check_output(cmd, env=env, text=True).strip() for _ in range(2)]
        self.assertNotEqual(ids[0], ids[1])
        with self.assertRaises(ValueError):
            one.call_ctl(["pointer", "--cursor-session=attacker"])

    def test_bounds_and_host_environment(self):
        self.assertEqual(visual.settings_from_env({}), visual.DEFAULT_SETTINGS)
        self.assertEqual(visual.validate_settings({"theme": "codex"}), {"theme": "codex"})
        for key, (low, high) in visual.BOUNDS.items():
            self.assertEqual(visual.validate_settings({key: low})[key], low)
            self.assertEqual(visual.validate_settings({key: high})[key], high)
            for bad in (low - 1, high + 1, 1.5, True, "4", float("nan")):
                with self.assertRaises(ValueError, msg=f"{key}: {bad}"):
                    visual.validate_settings({key: bad})
        for bad in ("../other", "", "a" * 65, "ä", "a,b"):
            with self.assertRaises(ValueError):
                visual.validate_session(bad)
        for bad in ({"theme": "file:/tmp/x"}, {"reduced_motion": 1}, {"unknown": 2}):
            with self.assertRaises(ValueError):
                visual.validate_settings(bad)
        settings = visual.settings_from_env({visual.ENV_PREFIX + "REDUCED_MOTION": "1", visual.ENV_PREFIX + "SIZE": "64"})
        self.assertTrue(settings["reduced_motion"])
        self.assertEqual(settings["size"], 64)
        with self.assertRaises(ValueError):
            bridge(CURSOR_SIZE="129")

    def test_native_propagation_all_paths_and_lua(self):
        ctl = load(ROOT / "scripts" / "hypr-agent-portalctl")
        mcp = bridge(CURSOR_THEME="minimal", CURSOR_REDUCED_MOTION="1")
        calls = []
        def fake_run(command, **kwargs):
            self.assertIn("--cursor-session", command)
            args = ctl.build_parser().parse_args(command[1:])
            ctl.cursor_options(args)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(args.func(args), 0)
            return subprocess.CompletedProcess(command, 0, "{}", "")
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"XDG_RUNTIME_DIR": tmp}):
            with patch.object(mcp, "find_ctl", return_value="ctl"), patch.object(mcp, "hyprctl_environment", return_value={}), patch.object(mcp.subprocess, "run", side_effect=fake_run), patch.object(ctl, "dispatch", side_effect=lambda name, payload: (calls.append((name, payload)), subprocess.CompletedProcess([], 0, "ok", ""))[1]), patch.object(ctl, "window_relative_to_global", return_value=(12, 14)):
                paths = [
                    ["pointer", "address:0x1", "1", "2", "move", "--json"],
                    ["pointer", "address:0x1", "1", "2", "scroll", "3", "--dx", "4", "--json"],
                    ["pointer", "address:0x1", "1", "2", "drag", "left", "3", "4", "--relative", "--json"],
                    ["pointer", "address:0x1", "1", "2", "move", "--relative", "--dispatcher", "hypr-agent-protal:pointer", "--json"],
                    ["keyboard", "address:0x1", "tap", "enter", "--json"],
                    ["keyboard", "address:0x1", "tap", "v", "ctrl", "--x", "1", "--y", "2", "--json"],
                    ["indicator", "address:0x1", "1", "2", "key", "--json"],
                ]
                for args in paths:
                    mcp.call_ctl(args)
                for name, payload in calls:
                    self.assertIn("cursor_session=" + mcp.CURSOR_SESSION, payload)
                    self.assertIn("theme=minimal", payload)
                    self.assertIn("reduced_motion=1", payload)
                self.assertTrue(calls[2][0].endswith(":pointer-relative"))
                self.assertEqual(calls[3][0], "hypr-agent-protal:pointer-relative")
                self.assertEqual(calls[4][1].split(",")[:4], ["address:0x1", "tap", "enter", ""])
                mcp.end_own_agent_cursor()
                self.assertEqual(calls[-1], ("hypr-agent-portal:indicator-end", mcp.CURSOR_SESSION))
        for namespace in ("portal", "protal"):
            self.assertEqual(ctl.lua_plugin_dispatcher(f"hypr-agent-{namespace}:indicator-end", "own"), f'hl.plugin.hypr_agent_{namespace}.indicator_end("own")')
        legacy = ctl.build_parser().parse_args(["keyboard", "address:0x1", "tap", "enter"])
        self.assertEqual(ctl.cursor_payload(legacy, "address:0x1,tap,enter,"), "address:0x1,tap,enter,")
        bad = ctl.build_parser().parse_args(["pointer", "address:0x1", "1", "2", "move", "--cursor-size", "129"])
        with patch.object(ctl, "dispatch", side_effect=AssertionError("invalid config dispatched")):
            with self.assertRaises(ValueError):
                ctl.pointer(bad)

    def test_keyed_state_cleanup_preserves_other_and_legacy(self):
        ctl = load(ROOT / "scripts" / "hypr-agent-portalctl")
        mcp = bridge()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"XDG_RUNTIME_DIR": tmp}):
            paths = [ctl.cursor_state_path(cursor_session=mcp.CURSOR_SESSION), ctl.cursor_state_path(cursor_session="other"), ctl.cursor_state_path()]
            for i, path in enumerate(paths):
                ctl.write_agent_cursor(path, target="address:0x1", x=i+1, y=2, action="move", button="left")
            self.assertEqual(mcp.agent_cursor_position()["x"], 1)
            args = ctl.build_parser().parse_args(["indicator-end", "--cursor-session", mcp.CURSOR_SESSION, "--json"])
            with patch.object(ctl, "dispatch", return_value=subprocess.CompletedProcess([], 0, "ok", "")), contextlib.redirect_stdout(io.StringIO()):
                ctl.indicator_end(args)
            self.assertFalse(paths[0].exists())
            self.assertTrue(paths[1].exists())
            self.assertTrue(paths[2].exists())
            self.assertIsNone(mcp.agent_cursor_position())
            # Screenshot debug reads only the chosen session, not cursor.json.
            session = {"cursorPosition": {"x": 99, "y": 99}}
            position, source = ctl.select_cursor_position(session, "agent", paths[1])
            self.assertEqual(position["x"], 2)
            self.assertEqual(source, "agent")

    def test_state_settings_and_security_gates(self):
        mcp = bridge()
        mcp.agent_cursor_position = lambda: None
        mcp.collect_runtime_guards = lambda: mcp.GuardInputs(available=True, screen_locked=False, panic_active=False, layer_surface_active=False, keyboard_grab_active=False)
        state = mcp.tool_get_agent_cursor_state({})["structuredContent"]
        self.assertEqual(state["settings"], visual.DEFAULT_SETTINGS)
        mcp.tool_set_agent_cursor_settings({"settings": {"theme": "classic", "size": 64}})
        self.assertEqual(mcp.CURSOR_SETTINGS["theme"], "classic")
        old = dict(mcp.CURSOR_SETTINGS)
        with self.assertRaises(ValueError):
            mcp.tool_set_agent_cursor_settings({"settings": {"theme": "minimal", "size": 129}})
        self.assertEqual(mcp.CURSOR_SETTINGS, old)
        with self.assertRaises(ValueError):
            mcp.tool_set_agent_cursor_settings({"settings": {}, "cursor_session": "other"})
        readonly = bridge(SECURITY_READONLY="1")
        names = {tool["name"] for tool in readonly.tool_definitions()}
        self.assertIn("get_agent_cursor_state", names)
        self.assertNotIn("set_agent_cursor_settings", names)
        self.assertNotIn("end_agent_cursor", names)
        for tool in ("set_agent_cursor_settings", "end_agent_cursor"):
            req = mcp.build_security_request(tool, {})
            self.assertTrue(req.mutating)
            self.assertEqual(req.required_level, mcp.AuthorizationLevel.FULL)
        dry = bridge(SECURITY_DRY_RUN="1")
        dry.call_ctl = lambda *_: (_ for _ in ()).throw(AssertionError("dry-run dispatched"))
        before = dict(dry.CURSOR_SETTINGS)
        result = dry.handle({"id": 1, "method": "tools/call", "params": {"name": "set_agent_cursor_settings", "arguments": {"settings": {"size": 88}}}})
        self.assertNotIn("error", result)
        self.assertTrue(result["result"]["structuredContent"]["security"]["dryRun"])
        self.assertEqual(dry.CURSOR_SETTINGS, before)
        blocked = bridge(SECURITY_DEFAULT_AUTHORIZATION="view")
        blocked.call_ctl = lambda *_: (_ for _ in ()).throw(AssertionError("denied action dispatched"))
        result = blocked.handle({"id": 1, "method": "tools/call", "params": {"name": "end_agent_cursor", "arguments": {}}})
        self.assertTrue(result["result"]["isError"])

    def test_eof_exception_and_shutdown_cleanup(self):
        for failure in (False, True):
            mcp = bridge()
            calls = []
            def fake_ctl(args):
                calls.append(args)
                return {"ok": True}
            with patch.object(mcp, "ensure_session_environment"), patch.object(mcp, "call_ctl", side_effect=fake_ctl), patch.object(mcp.sys, "stdin", io.StringIO("")):
                if failure:
                    with patch.object(mcp, "stdio_main", side_effect=RuntimeError("test shutdown")):
                        with self.assertRaises(RuntimeError):
                            mcp.main()
                else:
                    self.assertEqual(mcp.main(), 0)
            self.assertEqual(calls, [["indicator-end", "--json"]])
            self.assertTrue(mcp.CURSOR_ENDED)


if __name__ == "__main__":
    unittest.main()
