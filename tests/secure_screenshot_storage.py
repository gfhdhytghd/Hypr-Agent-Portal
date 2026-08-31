#!/usr/bin/env python3
import argparse
import base64
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import stat
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name: str, path: pathlib.Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def screenshot_args() -> argparse.Namespace:
    return argparse.Namespace(
        output_dir=None,
        target="",
        dispatcher="hypr-agent-portal:screenshot",
        no_cursor=True,
        cursor_source="none",
        model_resolution="full",
        max_dimension=0,
        base64=True,
    )


def native_fixture(ctl, root: pathlib.Path, session_path: pathlib.Path, *, valid: bool = True) -> dict:
    artifact_id = "fixture-0123456789abcdef"
    artifact_root = root / artifact_id
    artifact_root.mkdir(mode=0o700)
    raw = artifact_root / "monitor-0.rgba"
    raw.write_bytes(bytes([10, 20, 30, 255]) * (4 if valid else 3))
    raw.chmod(0o600)
    session = {
        "id": artifact_id,
        "cursorPosition": {"x": 0, "y": 0},
        "windows": [],
        "monitors": [{
            "name": "fixture",
            "geometry": {"x": 0, "y": 0, "width": 2, "height": 2},
            "scale": 1,
            "artifactPath": str(raw),
            "artifactWidth": 2,
            "artifactHeight": 2,
        }],
    }
    fd = os.open(session_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(session, stream)
    return session


def main() -> int:
    ctl = load("secure_storage_ctl", ROOT / "scripts" / "hypr-agent-portalctl")
    mcp = load("secure_storage_mcp", ROOT / "mcp" / "hypr-agent-portal-mcp.py")
    native_source = (ROOT / "src" / "plugin" / "screenshot_capture.cpp").read_text()
    for marker in ("O_EXCL", "O_NOFOLLOW", "openPrivateArtifactParent", "mkdirat", "ArtifactCleanup"):
        assert marker in native_source

    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(temporary)
        root = ctl.state_root(str(base))
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        created = ctl._write_exclusive(root, "private.bin", b"secret")
        assert stat.S_IMODE(created.stat().st_mode) == 0o600

        victim = base / "victim"
        victim.write_text("unchanged")
        cursor = root / "cursor.json"
        cursor.symlink_to(victim)
        ctl.write_agent_cursor(cursor, target="address:0x1", x=1, y=2, action="move", button="left")
        assert victim.read_text() == "unchanged"
        assert cursor.is_file() and not cursor.is_symlink()
        assert stat.S_IMODE(cursor.stat().st_mode) == 0o600

    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(temporary)
        victim = base / "victim-dir"
        victim.mkdir(mode=0o700)
        (base / ctl.PRIVATE_ROOT_NAME).symlink_to(victim, target_is_directory=True)
        try:
            ctl.state_root(str(base))
        except RuntimeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("precreated private-root symlink was accepted")

    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(temporary)
        hostile = base / ctl.PRIVATE_ROOT_NAME
        hostile.mkdir(mode=0o755)
        try:
            ctl.state_root(str(base))
        except RuntimeError as exc:
            assert "mode 0700" in str(exc)
        else:
            raise AssertionError("unsafe precreated private root permissions were accepted")

    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(temporary)
        previous_xdg = os.environ.pop("XDG_RUNTIME_DIR", None)
        previous_tempdir = tempfile.tempdir
        tempfile.tempdir = str(base)
        try:
            fallback_root = ctl.state_root()
            assert fallback_root.parent == base
            assert stat.S_IMODE(fallback_root.stat().st_mode) == 0o700
        finally:
            tempfile.tempdir = previous_tempdir
            if previous_xdg is not None:
                os.environ["XDG_RUNTIME_DIR"] = previous_xdg

    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(temporary)
        actual_runtime = base / "actual-runtime"
        actual_runtime.mkdir(mode=0o700)
        runtime_link = base / "runtime-link"
        runtime_link.symlink_to(actual_runtime, target_is_directory=True)
        previous_xdg = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = str(runtime_link)
        try:
            try:
                ctl.state_root()
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("symlink XDG_RUNTIME_DIR was accepted")
        finally:
            if previous_xdg is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = previous_xdg

    with tempfile.TemporaryDirectory() as runtime_text:
        runtime = pathlib.Path(runtime_text)
        previous = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = str(runtime)
        try:
            ctl.dispatch = lambda _dispatcher, payload: (
                native_fixture(ctl, ctl.state_root(), pathlib.Path(payload.split(",", 1)[0])),
                subprocess.CompletedProcess([], 0, "ok\n", ""),
            )[1]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert ctl.screenshot(screenshot_args()) == 0
            result = json.loads(output.getvalue())
            provenance = result["cleanupProvenance"]
            for record in provenance["files"]:
                path = pathlib.Path(record["path"])
                assert path.exists()
                assert stat.S_IMODE(path.stat().st_mode) == 0o600
            info, encoded = mcp.consume_screenshot_result(result)
            assert base64.b64decode(encoded).startswith(b"\x89PNG")
            assert "cleanupProvenance" not in info
            assert "sessionPath" not in info and "pngPath" not in info
            assert str(ctl.state_root()) not in json.dumps(info)
            assert all(not pathlib.Path(record["path"]).exists() for record in provenance["files"])
            assert all(not pathlib.Path(record["path"]).exists() for record in provenance["directories"])

            ctl.dispatch = lambda _dispatcher, payload: (
                native_fixture(ctl, ctl.state_root(), pathlib.Path(payload.split(",", 1)[0]), valid=False),
                subprocess.CompletedProcess([], 0, "ok\n", ""),
            )[1]
            failure_output = io.StringIO()
            with contextlib.redirect_stderr(failure_output):
                assert ctl.screenshot(screenshot_args()) == 1
            assert "invalid artifact size" in failure_output.getvalue()
            assert str(runtime) not in failure_output.getvalue()
            private_root = ctl.state_root()
            assert mcp.cursor_state_path() == private_root / "cursor.json"
            ctl.write_agent_cursor(private_root / "cursor.json", target="address:0x1", x=3, y=4, action="move", button="left")
            assert mcp.agent_cursor_position()["x"] == 3.0
            (private_root / "cursor.json").unlink()
            cursor_victim = runtime / "cursor-victim"
            cursor_victim.write_text('{"x": 8, "y": 9}')
            cursor_victim.chmod(0o600)
            (private_root / "cursor.json").symlink_to(cursor_victim)
            try:
                mcp.agent_cursor_position()
            except RuntimeError as exc:
                assert "unsafe cursor state" in str(exc)
            else:
                raise AssertionError("cursor symlink was accepted")
            (private_root / "cursor.json").unlink()
            (private_root / "cursor.json").write_bytes(b"x" * (mcp.MAX_CURSOR_STATE_BYTES + 1))
            (private_root / "cursor.json").chmod(0o600)
            try:
                mcp.agent_cursor_position()
            except RuntimeError as exc:
                assert "unsafe cursor state" in str(exc) or "oversized" in str(exc)
            else:
                raise AssertionError("oversized cursor state was accepted")
            (private_root / "cursor.json").unlink()

            leftovers = [path for path in private_root.iterdir() if path.name != "cursor.json"]
            assert leftovers == [], leftovers

            artifact_root = private_root / "manual-artifact"
            artifact_root.mkdir(mode=0o700)
            artifact = artifact_root / "raw.rgba"
            artifact.write_bytes(b"raw")
            artifact.chmod(0o600)
            record = ctl._artifact_record(artifact)
            dir_record = ctl._artifact_record(artifact_root, directory=True)
            artifact.unlink()
            artifact.write_bytes(b"replacement")
            artifact.chmod(0o600)
            mcp.cleanup_screenshot_provenance({"root": str(private_root), "files": [record], "directories": [dir_record]})
            assert artifact.read_bytes() == b"replacement"
            assert artifact_root.exists()

            exception_root = private_root / "exception-artifact"
            exception_root.mkdir(mode=0o700)
            exception_file = exception_root / "raw.rgba"
            exception_file.write_bytes(b"raw")
            exception_file.chmod(0o600)
            exception_provenance = {
                "root": str(private_root),
                "files": [ctl._artifact_record(exception_file)],
                "directories": [ctl._artifact_record(exception_root, directory=True)],
            }
            try:
                mcp.consume_screenshot_result({"cleanupProvenance": exception_provenance, "sessionPath": "/private", "pngPath": "/private"})
            except KeyError:
                pass
            else:
                raise AssertionError("missing screenshot payload did not fail")
            assert not exception_file.exists() and not exception_root.exists()
        finally:
            if previous is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = previous

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
