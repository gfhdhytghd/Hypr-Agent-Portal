#!/usr/bin/env python3
"""Logical-axis artifacts must reach MCP unchanged for all output transforms."""
import importlib.machinery
import importlib.util
import pathlib
import struct
import tempfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def png_rgba(png):
    """Decode the controller's filter-0 RGBA PNG without optional Pillow."""
    data = bytearray()
    offset = 8
    while offset < len(png):
        length = struct.unpack_from(">I", png, offset)[0]
        kind = png[offset + 4:offset + 8]
        payload = png[offset + 8:offset + 8 + length]
        if kind == b"IHDR":
            width, height, depth, color, _, _, _ = struct.unpack(">IIBBBBB", payload)
            assert (depth, color) == (8, 6)
        elif kind == b"IDAT":
            data.extend(payload)
        offset += length + 12
    rows = zlib.decompress(data)
    stride = width * 4 + 1
    assert all(rows[y * stride] == 0 for y in range(height))
    return width, height, b"".join(rows[y * stride + 1:(y + 1) * stride] for y in range(height))


def main():
    ctl = load("transform_ctl", ROOT / "scripts/hypr-agent-portalctl")
    mcp = load("transform_mcp", ROOT / "mcp/hypr-agent-portal-mcp.py")
    expected = (
        (1, 2, 3, 4, 5, 6), (4, 1, 5, 2, 6, 3),
        (6, 5, 4, 3, 2, 1), (3, 6, 2, 5, 1, 4),
        (3, 2, 1, 6, 5, 4), (1, 4, 2, 5, 3, 6),
        (4, 5, 6, 1, 2, 3), (6, 3, 5, 2, 4, 1),
    )
    with tempfile.TemporaryDirectory() as tmp:
        artifact = pathlib.Path(tmp) / "logical.rgba"
        for transform, pixels in enumerate(expected):
            width, height = (2, 3) if transform % 2 else (3, 2)
            raw = bytes(channel for pixel in pixels for channel in (pixel * 10, pixel, 0, 255))
            artifact.write_bytes(raw)
            artifact.chmod(0o600)
            for scale in (1.0, 1.25, 2.0):
                geometry = {"x": -70.5, "y": 25.25, "width": width / scale, "height": height / scale}
                session = {"monitors": [{"geometry": geometry, "scale": scale,
                    "transform": transform, "artifactPath": str(artifact),
                    "artifactWidth": width, "artifactHeight": height, "artifactTopDown": True}]}
                png, metadata = ctl.render_session_png(session)
                assert png_rgba(png) == (width, height, raw), transform
                snapshot = {"target": "address:0x123", "screenshot": metadata,
                            "window": {"at": [geometry["x"], geometry["y"]], "size": [geometry["width"], geometry["height"]]}}
                for y in range(height):
                    for x in range(width):
                        gx, gy, wx, wy, relative = mcp.pointer_call_coordinates(snapshot, x + 0.5, y + 0.5, "screenshot")
                        assert relative
                        assert abs(gx - (geometry["x"] + (x + 0.5) / scale)) < 1e-9
                        assert abs(gy - (geometry["y"] + (y + 0.5) / scale)) < 1e-9
                        assert abs(wx - (x + 0.5) / scale) < 1e-9
                        assert abs(wy - (y + 0.5) / scale) < 1e-9
    print("all 8 transforms: PNG pixels and MCP click mapping passed at scales 1, 1.25, 2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
