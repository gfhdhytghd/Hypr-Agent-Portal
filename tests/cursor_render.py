#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import json
import pathlib
import tempfile
from unittest.mock import patch


def load_ctl():
    repo = pathlib.Path(__file__).resolve().parents[1]
    path = repo / "scripts" / "hypr-agent-portalctl"
    loader = importlib.machinery.SourceFileLoader("hypr_agent_portalctl", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_automatic_asset_reference(tmp: pathlib.Path) -> None:
    # The script imports Pillow when launched. This ownership check never
    # decodes an image and should also run in a Pillow-free unit environment.
    source = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "install-codex-cursor-asset"
    loader = importlib.machinery.SourceFileLoader("cursor_asset", str(source))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    with patch.dict("sys.modules", {"PIL": __import__("types").SimpleNamespace(Image=None)}):
        loader.exec_module(module)

    reference = tmp / "source.png"
    reference.write_bytes(b"fixture")
    module.DEFAULT_OPEN_CODEX_REFERENCE = reference
    reference.chmod(0o600)
    with module.open_default_reference() as stream:
        assert stream.read() == b"fixture"
    reference.chmod(0o666)
    assert module.open_default_reference() is None
    alias = tmp / "untrusted.png"
    alias.symlink_to(reference)
    reference.chmod(0o600)
    module.DEFAULT_OPEN_CODEX_REFERENCE = alias
    assert module.open_default_reference() is None


def main() -> int:
    ctl = load_ctl()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = pathlib.Path(tmpdir)
        test_automatic_asset_reference(tmp)
        artifact = tmp / "monitor.rgba"
        artifact.write_bytes(bytes([240, 240, 240, 255]) * 100)
        artifact.chmod(0o600)
        session = {
            "cursorPosition": {"x": 4.0, "y": 5.0},
            "windows": [],
            "monitors": [
                {
                    "name": "test",
                    "geometry": {"x": 0.0, "y": 0.0, "width": 10.0, "height": 10.0},
                    "scale": 1.0,
                    "artifactPath": str(artifact),
                    "artifactWidth": 10,
                    "artifactHeight": 10,
                }
            ],
        }

        png, metadata = ctl.render_session_png(session, cursor_source="hyprland", cursor_path=tmp / "missing.json")
        assert png.startswith(b"\x89PNG\r\n\x1a\n")
        assert metadata["cursorIndicator"]["visible"] is True
        assert metadata["cursorIndicator"]["source"] == "hyprland"
        assert metadata["cursorIndicator"]["pixelPosition"] == {"x": 4, "y": 5}

        (tmp / "cursor.json").write_text(json.dumps({"x": 8, "y": 9, "target": "address:0x1"}))
        (tmp / "cursor.json").chmod(0o600)
        _, metadata = ctl.render_session_png(session, cursor_source="auto", cursor_path=tmp / "cursor.json")
        assert metadata["cursorIndicator"]["visible"] is True
        assert metadata["cursorIndicator"]["source"] == "agent"
        assert metadata["cursorPosition"] == {"x": 8.0, "y": 9.0}

        _, metadata = ctl.render_session_png(session, cursor_source="none", cursor_path=tmp / "cursor.json")
        assert metadata["cursorIndicator"]["enabled"] is False
        assert metadata["cursorIndicator"]["visible"] is False

        small_png, small_metadata = ctl.render_session_png(session, max_dimension=5)
        assert small_png.startswith(b"\x89PNG\r\n\x1a\n")
        assert small_metadata["width"] == 5
        assert small_metadata["height"] == 5
        assert small_metadata["sourceWidth"] == 10
        assert small_metadata["sourceHeight"] == 10
        assert small_metadata["modelDownsample"]["enabled"] is True

        hidpi_artifact = tmp / "hidpi.rgba"
        hidpi_artifact.write_bytes(bytes([200, 200, 200, 255]) * 400)
        hidpi_artifact.chmod(0o600)
        hidpi_session = {
            "cursorPosition": {"x": 4.0, "y": 5.0},
            "windows": [],
            "monitors": [
                {
                    "name": "hidpi",
                    "geometry": {"x": 0.0, "y": 0.0, "width": 10.0, "height": 10.0},
                    "scale": 2.0,
                    "artifactPath": str(hidpi_artifact),
                    "artifactWidth": 20,
                    "artifactHeight": 20,
                }
            ],
        }
        _, logical_metadata = ctl.render_session_png(hidpi_session, model_resolution="logical")
        assert logical_metadata["width"] == 10
        assert logical_metadata["height"] == 10
        assert logical_metadata["sourceWidth"] == 20
        assert logical_metadata["sourceHeight"] == 20
        assert logical_metadata["scaleX"] == 1.0
        assert logical_metadata["scaleY"] == 1.0
        assert logical_metadata["modelDownsample"]["mode"] == "logical"

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
