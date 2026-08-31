#!/usr/bin/env python3
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "hypr-agent-portal-sandbox"


class SandboxRunnerTests(unittest.TestCase):
    def run_runner(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(RUNNER), *args],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def write_managed_layout(self, session: Path, status: str) -> None:
        for name in ("home", "config", "cache", "state", "data", "logs"):
            (session / name).mkdir(mode=0o700, exist_ok=True)
        lock = session / ".hypr-agent-portal-sandbox.lock"
        lock.write_text("", encoding="utf-8")
        lock.chmod(0o600)
        marker = {
            "format": 1,
            "ownerUid": os.getuid(),
            "root": str(session.resolve()),
            "rootKind": "explicit",
            "backend": "headless",
            "status": status,
            "updatedAt": 0,
        }
        marker_path = session / ".hypr-agent-portal-sandbox.json"
        marker_path.write_text(json.dumps(marker), encoding="utf-8")
        marker_path.chmod(0o600)

    def test_dry_run_does_not_create_explicit_session_directory(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            session = Path(parent) / "session"
            env = dict(os.environ)
            env["PATH"] = "/nonexistent"
            result = self.run_runner(
                "run",
                "--backend",
                "headless",
                "--dry-run",
                "--json",
                "--session-dir",
                str(session),
                "--",
                "/bin/true",
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["command"], ["/bin/true"])
            self.assertFalse(payload["ok"])
            self.assertFalse(payload["diagnostics"]["ok"])
            self.assertIsNone(payload["diagnostics"]["commands"]["Hyprland"])
            self.assertIsNone(payload["diagnostics"]["commands"]["dbus-daemon"])
            self.assertFalse(session.exists())

    def test_cleanup_refuses_unmarked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as session:
            sentinel = Path(session) / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            result = self.run_runner("cleanup", session)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(sentinel.exists())

    def test_invalid_dimensions_fail_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            session = Path(parent) / "session"
            result = self.run_runner("run", "--backend", "headless", "--width", "1", "--session-dir", str(session), "--dry-run")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(session.exists())

    def test_missing_dependencies_fail_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            session = Path(parent) / "session"
            env = dict(os.environ)
            env["PATH"] = "/nonexistent"
            result = self.run_runner("run", "--backend", "headless", "--session-dir", str(session), "--", "/bin/true", env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required dependencies are unavailable", result.stderr)
            self.assertFalse(session.exists())

    def test_reuse_requires_owned_stopped_marker(self) -> None:
        with tempfile.TemporaryDirectory() as session_text:
            session = Path(session_text)
            self.write_managed_layout(session, "stopped")
            sentinel = session / "profile-state"
            sentinel.write_text("keep", encoding="utf-8")
            result = self.run_runner(
                "run", "--backend", "headless", "--session-dir", str(session), "--reuse", "--dry-run", "--json", "--", "/bin/true"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(sentinel.exists())

    def test_reuse_rejects_non_stopped_marker(self) -> None:
        with tempfile.TemporaryDirectory() as session_text:
            session = Path(session_text)
            self.write_managed_layout(session, "starting")
            result = self.run_runner("run", "--backend", "headless", "--session-dir", str(session), "--reuse", "--dry-run")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected 'stopped'", result.stderr)

    def test_cleanup_refuses_home_directory(self) -> None:
        result = self.run_runner("cleanup", str(Path.home()), "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing unsafe session directory", result.stderr)

    def test_cleanup_refuses_broad_and_repository_roots(self) -> None:
        for path in (Path("/tmp"), ROOT):
            result = self.run_runner("cleanup", str(path), "--dry-run")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing unsafe session directory", result.stderr)

    def test_cleanup_refuses_forged_incomplete_layout(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            session = Path(parent) / "private-data"
            session.mkdir(mode=0o700)
            marker = {
                "format": 1,
                "ownerUid": os.getuid(),
                "root": str(session.resolve()),
                "rootKind": "explicit",
                "status": "stopped",
            }
            marker_path = session / ".hypr-agent-portal-sandbox.json"
            marker_path.write_text(json.dumps(marker), encoding="utf-8")
            marker_path.chmod(0o600)
            sentinel = session / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            result = self.run_runner("cleanup", str(session))
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(sentinel.exists())

    def test_explicit_cleanup_removes_only_managed_state(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            session = Path(parent) / "profile"
            session.mkdir(mode=0o700)
            self.write_managed_layout(session, "stopped")
            sentinel = session / "keep-me"
            sentinel.write_text("keep", encoding="utf-8")
            result = self.run_runner("cleanup", str(session), "--json")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["removed"])
            self.assertTrue(payload["managedStateRemoved"])
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertFalse((session / "home").exists())

    def test_signal_returncode_is_normalized_for_shells(self) -> None:
        namespace = runpy.run_path(str(RUNNER), run_name="sandbox_runner_module")
        self.assertEqual(namespace["normalized_returncode"](-signal.SIGTERM), 143)
        self.assertEqual(namespace["normalized_returncode"](7), 7)

    def test_session_env_exports_cleanup_marker(self) -> None:
        namespace = runpy.run_path(str(RUNNER), run_name="sandbox_runner_module")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "session.env"
            namespace["write_env_file"](
                path,
                {
                    "HOME": "/tmp/example-home",
                    "HYPR_AGENT_PORTAL_SANDBOX_ID": "cleanup-marker",
                },
            )
            text = path.read_text(encoding="utf-8")
            self.assertIn("HYPR_AGENT_PORTAL_SANDBOX_ID=cleanup-marker", text)

    def test_nested_mounts_are_refused_before_cleanup(self) -> None:
        namespace = runpy.run_path(str(RUNNER), run_name="sandbox_runner_module")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mounted = root / "mounted"
            mounted.mkdir()
            real_ismount = os.path.ismount
            with mock.patch("os.path.ismount", side_effect=lambda path: Path(path) == mounted or real_ismount(path)):
                with self.assertRaises(namespace["SandboxError"]):
                    namespace["ensure_no_nested_mounts"](root)
            with mock.patch("os.path.ismount", side_effect=lambda path: Path(path) == root or real_ismount(path)):
                with self.assertRaises(namespace["SandboxError"]):
                    namespace["ensure_no_nested_mounts"](root)

    def test_session_marker_kills_descendant_after_leader_exits(self) -> None:
        namespace = runpy.run_path(str(RUNNER), run_name="sandbox_runner_module")
        marker = "sandbox-test-marker"
        env = dict(os.environ)
        env["HYPR_AGENT_PORTAL_SANDBOX_ID"] = marker
        leader = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)']); print(p.pid, flush=True)",
            ],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env=env,
        )
        assert leader.stdout is not None
        child_pid = int(leader.stdout.readline())
        self.assertTrue(namespace["process_is_running"](child_pid))
        leader.stdout.close()
        leader.wait(timeout=5)
        namespace["terminate_marked_processes"](marker, timeout=0.1)
        deadline = time.monotonic() + 3.0
        while namespace["process_is_running"](child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(namespace["process_is_running"](child_pid))
        self.assertFalse(namespace["process_group_exists"](leader.pid))


if __name__ == "__main__":
    unittest.main()
