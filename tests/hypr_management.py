#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hypr_management", ROOT / "mcp" / "hypr_management.py")
assert SPEC is not None and SPEC.loader is not None
hypr_management = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = hypr_management
SPEC.loader.exec_module(hypr_management)

CTL_LOADER = importlib.machinery.SourceFileLoader(
    "hypr_agent_portalctl_management", str(ROOT / "scripts" / "hypr-agent-portalctl")
)
portalctl = CTL_LOADER.load_module()


class FakeCompositor:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.windows: list[dict] = [
            {
                "address": "0xabc",
                "pid": 101,
                "class": "demo",
                "initialClass": "demo-initial",
                "processStartTime": 1001,
                "at": [10, 20],
                "size": [640, 480],
                "workspace": {"id": 1, "name": "1"},
                "floating": False,
                "pinned": False,
                "fullscreen": 0,
            },
            {
                "address": "0xdef",
                "pid": 202,
                "class": "other",
                "initialClass": "other-initial",
                "processStartTime": 2002,
                "at": [30, 40],
                "size": [800, 600],
                "workspace": {"id": 2, "name": "dev"},
                "floating": True,
                "pinned": False,
                "fullscreen": 0,
            },
        ]
        self.workspace_rows: list[dict] = [
            {"id": 1, "name": "1", "windows": 1},
            {"id": 2, "name": "dev", "windows": 1},
            {"id": -98, "name": "special:scratch", "windows": 0},
        ]
        self.active_address = "0xdef"
        self.active_workspace_row = {"id": 2, "name": "dev"}

    def _window(self, selector: str) -> dict | None:
        address = selector.split(":", 1)[-1]
        return next((item for item in self.windows if item["address"] == address), None)

    @staticmethod
    def _workspace_name(selector: str) -> str:
        if selector.startswith("name:"):
            return selector.split(":", 1)[1]
        if selector == "special":
            return "special:special"
        return selector

    def __call__(self, argv):
        command = tuple(argv)
        self.commands.append(command)
        if command[:2] == ("hyprctl", "--batch"):
            script = command[2]
            target = script.split("focuswindow ", 1)[1].split(" ;", 1)[0]
            window = self._window(target)
            assert window is not None
            self.active_address = window["address"]
            mode, operation = script.rsplit(" ", 2)[-2:]
            window["fullscreen"] = (1 if mode == "1" else 2) if operation == "set" else 0
            return hypr_management.CommandResult(stdout="ok")
        if command[:2] != ("hyprctl", "dispatch"):
            return hypr_management.CommandResult(returncode=1, stderr="unexpected command")
        dispatcher = command[2]
        arguments = command[3:]
        if dispatcher == "hypr-agent-portal:manage":
            parts = arguments[0].split(",")
            action = parts[0]
            if action in {"workspace_switch", "workspace_create", "workspace_activate"}:
                selector = parts[1]
                name = self._workspace_name(selector)
                row = next((item for item in self.workspace_rows if item["name"] == name), None)
                if action == "workspace_switch" and row is None:
                    return hypr_management.CommandResult(returncode=1, stderr="workspace_switch target was not found")
                if action == "workspace_create" and row is not None:
                    return hypr_management.CommandResult(returncode=1, stderr="workspace_create target already exists")
                if row is None:
                    row = {"id": max(item["id"] for item in self.workspace_rows) + 1, "name": name, "windows": 0}
                    self.workspace_rows.append(row)
                self.active_workspace_row = {"id": row["id"], "name": row["name"]}
                return hypr_management.CommandResult(stdout="ok")
            if action == "workspace_rename":
                selector, name = parts[1:]
                old_name = self._workspace_name(selector)
                row = next(item for item in self.workspace_rows if item["name"] == old_name)
                row["name"] = name
                if self.active_workspace_row["id"] == row["id"]:
                    self.active_workspace_row["name"] = name
                for candidate in self.windows:
                    if candidate["workspace"]["id"] == row["id"]:
                        candidate["workspace"]["name"] = name
                return hypr_management.CommandResult(stdout="ok")
            if action in {"special_show", "special_hide", "special_toggle"}:
                return hypr_management.CommandResult(stdout="ok")
            action, qualified = parts[:2]
            assert qualified.startswith("address:") and "@pid=" in qualified and "@start=" in qualified
            target = qualified.split("@", 1)[0]
            window = self._window(target)
            assert window is not None
            expected = f"address:{window['address']}@pid={window['pid']}@start={window['processStartTime']}"
            assert qualified == expected
            if action == "focus":
                self.active_address = window["address"]
            elif action == "close":
                self.windows.remove(window)
            elif action in {"move", "resize"}:
                window["at" if action == "move" else "size"] = [int(parts[2]), int(parts[3])]
            elif action in {"maximize", "unmaximize", "fullscreen", "unfullscreen"}:
                self.active_address = window["address"]
                window["fullscreen"] = {"maximize": 1, "fullscreen": 2}.get(action, 0)
            elif action in {"floating", "tiled"}:
                window["floating"] = action == "floating"
            elif action in {"pin", "unpin"}:
                window["pinned"] = action == "pin"
            elif action in {"minimize", "restore", "move_to_workspace"}:
                selector = parts[2]
                name = self._workspace_name(selector)
                known = next((item for item in self.workspace_rows if item["name"] == name), None)
                workspace_id = known["id"] if known else (-99 if name.startswith("special:") else len(self.workspace_rows) + 1)
                window["workspace"] = {"id": workspace_id, "name": name}
                if action == "move_to_workspace" and parts[3] == "follow":
                    self.active_workspace_row = {"id": workspace_id, "name": name}
            else:
                return hypr_management.CommandResult(returncode=1, stderr=f"unsupported native action {action}")
            return hypr_management.CommandResult(stdout="ok")
        if dispatcher == "focuswindow":
            window = self._window(arguments[0])
            assert window is not None
            self.active_address = window["address"]
        elif dispatcher == "closewindow":
            target = self._window(arguments[0])
            self.windows.remove(target)
        elif dispatcher in {"movewindowpixel", "resizewindowpixel"}:
            values, target = arguments[0].split(",", 1)
            _, first, second = values.split()
            window = self._window(target)
            assert window is not None
            window["at" if dispatcher == "movewindowpixel" else "size"] = [int(first), int(second)]
        elif dispatcher in {"movetoworkspace", "movetoworkspacesilent"}:
            selector, target = arguments[0].split(",", 1)
            window = self._window(target)
            assert window is not None
            name = self._workspace_name(selector)
            known = next((item for item in self.workspace_rows if item["name"] == name), None)
            workspace_id = known["id"] if known else (-99 if name.startswith("special:") else len(self.workspace_rows) + 1)
            window["workspace"] = {"id": workspace_id, "name": name}
            if dispatcher == "movetoworkspace":
                self.active_workspace_row = {"id": workspace_id, "name": name}
        elif dispatcher == "togglefloating":
            window = self._window(arguments[0])
            window["floating"] = not window["floating"]
        elif dispatcher == "pin":
            window = self._window(arguments[0])
            window["pinned"] = not window["pinned"]
        elif dispatcher == "workspace":
            selector = arguments[0]
            name = self._workspace_name(selector)
            row = next((item for item in self.workspace_rows if item["name"] == name), None)
            if row is None:
                row = {"id": -99 if name.startswith("special:") else max(item["id"] for item in self.workspace_rows) + 1, "name": name, "windows": 0}
                self.workspace_rows.append(row)
            self.active_workspace_row = {"id": row["id"], "name": row["name"]}
        elif dispatcher == "renameworkspace":
            workspace_id, name = int(arguments[0]), arguments[1]
            row = next(item for item in self.workspace_rows if item["id"] == workspace_id)
            row["name"] = name
            if self.active_workspace_row["id"] == workspace_id:
                self.active_workspace_row["name"] = name
            for window in self.windows:
                if window["workspace"]["id"] == workspace_id:
                    window["workspace"]["name"] = name
        else:
            return hypr_management.CommandResult(returncode=1, stderr=f"unsupported {dispatcher}")
        return hypr_management.CommandResult(stdout="ok")

    def clients(self):
        return copy.deepcopy(self.windows)

    def workspaces(self):
        return copy.deepcopy(self.workspace_rows)

    def active_window(self):
        return copy.deepcopy(next((item for item in self.windows if item["address"] == self.active_address), {}))

    def active_workspace(self):
        return copy.deepcopy(self.active_workspace_row)


class HyprManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeCompositor()
        self.manager = hypr_management.HyprManagement(self.fake, self.fake)

    def test_selectors_are_canonical_and_injection_safe(self) -> None:
        self.assertEqual(hypr_management.normalize_address("0xABC"), "address:0xabc")
        self.assertEqual(
            hypr_management.normalize_address("address:0xABC@pid=123@start=456"),
            "address:0xabc",
        )
        self.assertEqual(hypr_management.normalize_workspace(3), "3")
        self.assertEqual(hypr_management.normalize_workspace("dev"), "name:dev")
        self.assertEqual(hypr_management.normalize_workspace("special:scratch"), "special:scratch")
        with self.assertRaises(hypr_management.InvalidRequest):
            hypr_management.normalize_address("address:0xabc; dispatch exec evil")
        with self.assertRaises(hypr_management.InvalidRequest):
            hypr_management.normalize_workspace("dev,window")
        with self.assertRaises(hypr_management.InvalidRequest):
            hypr_management.normalize_workspace("previous")

    def test_focus_and_close_are_targeted_and_verified(self) -> None:
        result = self.manager.focus("0xabc")
        self.assertEqual(
            result.commands,
            (("hyprctl", "dispatch", "hypr-agent-portal:manage", "focus,address:0xabc@pid=101@start=1001"),),
        )
        self.assertEqual(self.fake.active_address, "0xabc")
        closed = self.manager.close("address:0xabc")
        self.assertTrue(closed.destructive)
        self.assertIsNone(closed.after)
        self.assertEqual(self.fake.windows[0]["address"], "0xdef")

    def test_move_and_resize_generate_exact_targeted_dispatches(self) -> None:
        moved = self.manager.move("0xabc", -50, 75)
        self.assertEqual(
            moved.commands[0],
            ("hyprctl", "dispatch", "hypr-agent-portal:manage", "move,address:0xabc@pid=101@start=1001,-50,75"),
        )
        resized = self.manager.resize("0xabc", 1024, 768)
        self.assertEqual(
            resized.commands[0],
            ("hyprctl", "dispatch", "hypr-agent-portal:manage", "resize,address:0xabc@pid=101@start=1001,1024,768"),
        )
        self.assertEqual(resized.after["size"], [1024, 768])
        with self.assertRaises(hypr_management.InvalidRequest):
            self.manager.resize("0xabc", 0, 100)
        with self.assertRaises(hypr_management.InvalidRequest):
            self.manager.maximize("0xabc", "false")

    def test_every_window_management_action_uses_qualified_native_gateway(self) -> None:
        before = self.fake.windows[0]
        expected = {
            "focus", "close", "move", "resize", "minimize", "restore",
            "maximize", "unmaximize", "fullscreen", "unfullscreen",
            "floating", "tiled", "pin", "unpin", "move_to_workspace",
        }
        for action in expected:
            command = self.manager._manage_command(action, before)
            self.assertEqual(command[:3], ("hyprctl", "dispatch", "hypr-agent-portal:manage"))
            self.assertTrue(command[3].startswith(f"{action},address:0xabc@pid=101@start=1001"))

    def test_recycled_address_before_dispatch_is_rejected_without_mutation(self) -> None:
        fake = self.fake

        class RecyclingState:
            calls = 0

            def clients(self):
                self.calls += 1
                rows = fake.clients()
                if self.calls == 2:
                    rows[0].update(
                        pid=999,
                        **{"class": "replacement", "initialClass": "replacement-initial", "processStartTime": 9009},
                    )
                return rows

            def workspaces(self):
                return fake.workspaces()

            def active_window(self):
                return fake.active_window()

            def active_workspace(self):
                return fake.active_workspace()

        commands: list[tuple[str, ...]] = []

        def runner(argv):
            commands.append(tuple(argv))
            return hypr_management.CommandResult(stdout="unexpected")

        manager = hypr_management.HyprManagement(runner, RecyclingState())
        with self.assertRaisesRegex(hypr_management.StaleTarget, "refused stale target"):
            manager.move("0xabc", 55, 66)
        self.assertEqual(commands, [])

    def test_recycled_address_after_dispatch_fails_semantic_verification(self) -> None:
        def replacing_runner(argv):
            result = self.fake(argv)
            if tuple(argv)[:3] == ("hyprctl", "dispatch", "hypr-agent-portal:manage"):
                target = next(item for item in self.fake.windows if item["address"] == "0xabc")
                target.update(
                    pid=999,
                    **{"class": "replacement", "initialClass": "replacement-initial", "processStartTime": 9009},
                )
            return result

        manager = hypr_management.HyprManagement(replacing_runner, self.fake)
        with self.assertRaisesRegex(hypr_management.StaleTarget, "target identity changed"):
            manager.move("0xabc", 55, 66)

    def test_window_identity_uses_initial_class_and_optional_process_start(self) -> None:
        original = hypr_management.window_identity(self.fake.windows[0])
        same_address = copy.deepcopy(self.fake.windows[0])
        same_address["initialClass"] = "reused"
        self.assertNotEqual(original, hypr_management.window_identity(same_address))
        same_address = copy.deepcopy(self.fake.windows[0])
        same_address["processStartTime"] += 1
        self.assertNotEqual(original, hypr_management.window_identity(same_address))

    def test_minimize_uses_private_special_workspace_and_can_restore(self) -> None:
        minimized = self.manager.minimize("0xabc")
        self.assertEqual(minimized.action, "minimize")
        self.assertEqual(minimized.after["workspace"]["name"], "special:hypr-agent-portal-minimized")
        self.assertEqual(
            minimized.commands[0][-1],
            "minimize,address:0xabc@pid=101@start=1001,special:hypr-agent-portal-minimized",
        )
        restored = self.manager.minimize("0xabc", False)
        self.assertEqual(restored.action, "restore")
        self.assertEqual(restored.after["workspace"]["name"], "1")

    def test_minimize_restore_state_is_bound_to_full_window_identity(self) -> None:
        self.manager.minimize("0xabc")
        recycled = next(item for item in self.fake.windows if item["address"] == "0xabc")
        recycled.update(
            pid=303,
            **{"class": "new-owner", "initialClass": "new-owner", "processStartTime": 3003},
        )
        with self.assertRaisesRegex(hypr_management.InvalidRequest, "original workspace is unknown"):
            self.manager.minimize("0xabc", False)
        self.assertEqual(recycled["workspace"]["name"], "special:hypr-agent-portal-minimized")

    def test_maximize_and_fullscreen_are_focused_target_batches(self) -> None:
        maximized = self.manager.maximize("0xabc")
        self.assertEqual(maximized.after["fullscreen"], 1)
        self.assertEqual(
            maximized.commands[0],
            ("hyprctl", "dispatch", "hypr-agent-portal:manage", "maximize,address:0xabc@pid=101@start=1001"),
        )
        self.manager.maximize("0xabc", False)
        fullscreen = self.manager.fullscreen("0xabc")
        self.assertEqual(fullscreen.after["fullscreen"], 2)
        self.assertEqual(fullscreen.commands[0][-1], "fullscreen,address:0xabc@pid=101@start=1001")

    def test_floating_and_pin_only_toggle_when_needed(self) -> None:
        floating = self.manager.floating("0xabc", True)
        pinned = self.manager.pin("0xabc", True)
        self.assertTrue(floating.after["floating"])
        self.assertTrue(pinned.after["pinned"])
        command_count = len(self.fake.commands)
        unchanged = self.manager.pin("0xabc", True)
        self.assertFalse(unchanged.changed)
        self.assertEqual(len(self.fake.commands), command_count)

    def test_move_window_supports_named_special_and_follow_semantics(self) -> None:
        moved = self.manager.move_to_workspace("0xabc", "dev")
        self.assertEqual(moved.after["workspace"]["name"], "dev")
        self.assertEqual(moved.commands[0][-1], "move_to_workspace,address:0xabc@pid=101@start=1001,name:dev,silent")
        followed = self.manager.move_to_workspace("0xabc", "special:scratch", follow=True)
        self.assertEqual(followed.commands[0][-1], "move_to_workspace,address:0xabc@pid=101@start=1001,special:scratch,follow")
        self.assertEqual(followed.after["workspace"]["name"], "special:scratch")

    def test_workspace_list_switch_create_rename_and_move_window(self) -> None:
        ordinary = self.manager.list_workspaces(include_special=False)
        self.assertEqual([item["name"] for item in ordinary], ["1", "dev"])
        switched = self.manager.switch_workspace(1)
        self.assertEqual(switched.after["id"], 1)
        created = self.manager.create_or_activate_workspace("docs")
        self.assertEqual(created.action, "create_workspace")
        self.assertEqual(created.after["name"], "docs")
        renamed = self.manager.rename_workspace("dev", "development")
        self.assertEqual(renamed.after["id"], 2)
        self.assertEqual(renamed.after["name"], "development")
        moved = self.manager.workspace_action(
            "move_window", address="0xabc", workspace="development", follow=False
        )
        self.assertEqual(moved.after["workspace"]["name"], "development")
        with self.assertRaises(hypr_management.InvalidRequest):
            self.manager.rename_workspace("special:scratch", "renamed")
        self.assertIn(
            ("hyprctl", "dispatch", "hypr-agent-portal:manage", "workspace_switch,1"),
            self.fake.commands,
        )
        self.assertIn(
            ("hyprctl", "dispatch", "hypr-agent-portal:manage", "workspace_rename,name:dev,development"),
            self.fake.commands,
        )
        special = self.manager.special_workspace("show_special", "special:scratch")
        self.assertEqual(
            special,
            ("hyprctl", "dispatch", "hypr-agent-portal:manage", "special_show,special:scratch"),
        )

    def test_workspace_switch_create_and_activate_inverse_matrix(self) -> None:
        with self.assertRaisesRegex(hypr_management.TargetNotFound, "was not found"):
            self.manager.switch_workspace("missing")
        with self.assertRaisesRegex(hypr_management.InvalidRequest, "already exists"):
            self.manager.create_workspace("dev")

        created = self.manager.create_workspace("new-only")
        self.assertEqual(created.commands[0][-1], "workspace_create,name:new-only")
        with self.assertRaisesRegex(hypr_management.InvalidRequest, "already exists"):
            self.manager.create_workspace("new-only")

        activated_existing = self.manager.create_or_activate_workspace("dev")
        self.assertEqual(activated_existing.action, "activate_workspace")
        self.assertEqual(activated_existing.commands[0][-1], "workspace_activate,name:dev")
        activated_new = self.manager.create_or_activate_workspace("activate-new")
        self.assertEqual(activated_new.action, "create_workspace")
        self.assertEqual(activated_new.commands[0][-1], "workspace_activate,name:activate-new")

        strict_create = self.manager.workspace_action("create", workspace="strict-create")
        self.assertEqual(strict_create.commands[0][-1], "workspace_create,name:strict-create")
        self.manager.create_or_activate_workspace("dev")
        strict_switch = self.manager.workspace_action("switch", workspace="strict-create")
        self.assertEqual(strict_switch.commands[0][-1], "workspace_switch,name:strict-create")

    def test_failed_command_and_failed_verification_fail_closed(self) -> None:
        def failed(_argv):
            return {"returncode": 1, "stderr": "denied"}

        manager = hypr_management.HyprManagement(failed, self.fake)
        with self.assertRaisesRegex(hypr_management.CommandFailed, "denied"):
            manager.move("0xabc", 1, 2)

        def no_op(_argv):
            return None

        manager = hypr_management.HyprManagement(no_op, self.fake)
        with self.assertRaises(hypr_management.VerificationFailed):
            manager.resize("0xabc", 333, 222)

    def test_default_json_state_client_is_injectable(self) -> None:
        calls = []
        payloads = {
            "clients": self.fake.windows,
            "workspaces": self.fake.workspace_rows,
            "activewindow": self.fake.active_window(),
            "activeworkspace": self.fake.active_workspace(),
        }

        def runner(argv):
            calls.append(tuple(argv))
            return {"stdout": json.dumps(payloads[argv[-1]])}

        state = hypr_management.HyprctlStateClient(runner)
        self.assertEqual(state.clients()[0]["address"], "0xabc")
        self.assertEqual(state.active_workspace()["name"], "dev")
        self.assertEqual(calls, [("hyprctl", "-j", "clients"), ("hyprctl", "-j", "activeworkspace")])

    def test_native_management_source_contract_holds_identity_across_dispatch(self) -> None:
        source = (ROOT / "src" / "plugin" / "main.cpp").read_text(encoding="utf-8")
        block = source.split("SDispatchResult dispatchManage", 1)[1].split("SDispatchResult dispatchPanic", 1)[0]
        self.assertIn("!identity.valid || !identity.qualified", block)
        self.assertIn("const PHLWINDOW window = resolveTargetWindow(parts[1]);", block)
        self.assertIn("window->m_isMapped", block)
        self.assertIn("runBuiltinDispatcher", block)
        self.assertNotIn("runBuiltinDispatcher(parts[0]", block)
        self.assertIn('"hypr-agent-portal:manage", dispatchManage', source)
        self.assertIn('"hypr-agent-protal:manage", dispatchManage', source)
        self.assertIn('addLuaFunction(g_pluginHandle, name, "manage", luaManage)', source)

    def test_portalctl_manage_dispatch_is_provider_aware(self) -> None:
        payload = "focus,address:0xabc@pid=101@start=1001"
        lua_calls = []

        def fake_run(argv, **_kwargs):
            lua_calls.append(tuple(argv))
            return __import__("subprocess").CompletedProcess(argv, 0, "ok", "")

        with mock.patch.object(portalctl, "is_lua_config_provider", return_value=True), mock.patch.object(
            portalctl.subprocess, "run", side_effect=fake_run
        ):
            result = portalctl.dispatch("hypr-agent-portal:manage", payload)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            lua_calls[0][2],
            'hl.plugin.hypr_agent_portal.manage("focus,address:0xabc@pid=101@start=1001")',
        )
        self.assertEqual(
            portalctl.lua_plugin_dispatcher("hypr-agent-protal:manage", "workspace_activate,name:dev"),
            'hl.plugin.hypr_agent_protal.manage("workspace_activate,name:dev")',
        )

        legacy_calls = []
        with mock.patch.object(portalctl, "is_lua_config_provider", return_value=False), mock.patch.object(
            portalctl.subprocess,
            "run",
            side_effect=lambda argv, **_kwargs: legacy_calls.append(tuple(argv)) or __import__("subprocess").CompletedProcess(argv, 0, "ok", ""),
        ):
            portalctl.dispatch("hypr-agent-protal:manage", payload)
        self.assertEqual(
            legacy_calls[0],
            ("hyprctl", "dispatch", "hypr-agent-protal:manage", payload),
        )


if __name__ == "__main__":
    unittest.main()
