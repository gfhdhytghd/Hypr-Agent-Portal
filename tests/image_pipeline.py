#!/usr/bin/env python3
import importlib.util
import io
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "mcp" / "image_pipeline.py"


def load_pipeline():
    spec = importlib.util.spec_from_file_location("hypr_agent_portal_image_pipeline", MODULE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def near(actual: float, expected: float, epsilon: float = 0.001) -> None:
    assert abs(actual - expected) <= epsilon, f"{actual} != {expected}"


def main() -> int:
    pipeline = load_pipeline()
    status = pipeline.backend_status()
    assert set(status) >= {"available", "backend", "formats", "diagnostic"}

    original_image = pipeline.Image
    original_error = pipeline._PIL_IMPORT_ERROR
    try:
        pipeline.Image = None
        pipeline._PIL_IMPORT_ERROR = ImportError("fixture: no Pillow")
        unavailable = pipeline.backend_status()
        assert unavailable["available"] is False
        assert "Pillow is not installed" in unavailable["diagnostic"]
        try:
            pipeline.transform_image(b"not-an-image")
            raise AssertionError("missing Pillow should fail clearly")
        except pipeline.ImagePipelineError as exc:
            assert "Install the optional 'Pillow'" in str(exc)
    finally:
        pipeline.Image = original_image
        pipeline._PIL_IMPORT_ERROR = original_error

    if not status["available"]:
        return 0

    from PIL import Image

    source = Image.new("RGBA", (100, 80))
    for y in range(80):
        for x in range(100):
            source.putpixel((x, y), (x * 2, y * 3, (x + y) % 256, 255))
    buffer = io.BytesIO()
    source.save(buffer, format="PNG")
    source_bytes = buffer.getvalue()
    screenshot = {
        "width": 100,
        "height": 80,
        "logicalBounds": {"x": 90.0, "y": 190.0, "width": 50.0, "height": 40.0},
    }
    window = {"at": [100.0, 200.0], "size": [30.0, 20.0]}

    cropped, metadata = pipeline.transform_image(
        source_bytes,
        screenshot=screenshot,
        window=window,
        region={"x": 5, "y": 4, "width": 10, "height": 6},
        coordinate_space="window",
        zoom=2,
    )
    assert cropped.startswith(b"\x89PNG\r\n\x1a\n")
    assert metadata["source"] == {"width": 100, "height": 80}
    assert metadata["cropInScreenshot"] == {"x": 30, "y": 28, "width": 20, "height": 12}
    assert metadata["output"]["width"] == 40
    assert metadata["output"]["height"] == 24
    assert metadata["output"]["format"] == "png"
    mapped = pipeline.map_point({"x": 35, "y": 31}, metadata["mappings"]["screenshotToOutput"])
    assert mapped == {"x": 10.0, "y": 6.0}
    inverse = pipeline.map_point(mapped, metadata["mappings"]["outputToScreenshot"])
    near(inverse["x"], 35)
    near(inverse["y"], 31)
    window_point = pipeline.map_point({"x": 10, "y": 7}, metadata["mappings"]["windowToOutput"])
    assert window_point == {"x": 20.0, "y": 12.0}
    assert Image.open(io.BytesIO(cropped)).size == (40, 24)

    clipped, clipped_meta = pipeline.transform_image(
        source_bytes,
        region={"x": -10, "y": -5, "width": 30, "height": 20},
        scale=3,
        max_dimension=25,
    )
    assert clipped_meta["cropInScreenshot"] == {"x": 0, "y": 0, "width": 20, "height": 15}
    assert clipped_meta["clipped"] is True
    assert clipped_meta["output"]["width"] == 25
    assert clipped_meta["output"]["height"] == 19
    assert Image.open(io.BytesIO(clipped)).size == (25, 19)

    if "jpeg" in status["formats"]:
        jpeg, jpeg_meta = pipeline.transform_image(source_bytes, output_format="jpg", quality=63, max_dimension=50)
        assert jpeg.startswith(b"\xff\xd8")
        assert jpeg_meta["output"]["format"] == "jpeg"
        assert jpeg_meta["output"]["quality"] == 63
        assert jpeg_meta["output"]["width"] == 50
        assert jpeg_meta["output"]["height"] == 40
        assert Image.open(io.BytesIO(jpeg)).format == "JPEG"

    marked, mark_meta = pipeline.render_marks(
        source_bytes,
        [
            {"source": "atspi", "index": 7, "name": "OK", "frame": {"x": 10, "y": 10, "width": 20, "height": 15}},
            {"source": "ocr", "ocr_index": 3, "text": "Save", "box": [60, 40, 25, 12]},
            {"source": "atspi", "index": 99, "frame": {"x": 200, "y": 200, "width": 5, "height": 5}},
        ],
        region={"x": 5, "y": 5, "width": 90, "height": 65},
        zoom=1.5,
    )
    assert source_bytes == buffer.getvalue(), "mark overlay must not mutate the source bytes"
    assert marked != source_bytes
    assert mark_meta["markCount"] == 2
    assert [entry["markId"] for entry in mark_meta["marks"]] == ["1", "2"]
    assert mark_meta["marks"][0]["elementIndex"] == 7
    assert mark_meta["marks"][1]["ocrIndex"] == 3
    assert mark_meta["marks"][0]["id"] == "1"
    assert mark_meta["marks"][0]["source"] == "element"
    assert mark_meta["marks"][0]["frame"] == mark_meta["marks"][0]["screenshotBox"]
    assert mark_meta["overlay"]["sourceImageModified"] is False
    assert Image.open(io.BytesIO(marked)).size == (135, 98)
    point = mark_meta["marks"][0]["screenshotPoint"]
    assert point == {"x": 20.0, "y": 17.5}
    output_point = mark_meta["marks"][0]["outputPoint"]
    near(output_point["x"], 22.5)
    near(output_point["y"], 18.846153846)

    visual_spec = importlib.util.spec_from_file_location("visual_targets_integration", ROOT / "mcp" / "visual_targets.py")
    visual = importlib.util.module_from_spec(visual_spec)
    assert visual_spec.loader is not None
    sys.modules[visual_spec.name] = visual
    visual_spec.loader.exec_module(visual)
    visual_snapshot = {
        "target": "address:0xmark",
        "window": {"address": "0xmark", "class": "fixture", "pid": 9, "at": [0, 0], "size": [100, 80]},
        "screenshot": {"id": "mark-shot", "sha256": "f" * 64, "width": 100, "height": 80,
                       "logicalBounds": {"x": 0, "y": 0, "width": 100, "height": 80}},
        "elements": [{"index": 7, "frame": {"x": 10, "y": 10, "width": 20, "height": 15}}],
    }
    binding = visual.make_snapshot_binding(visual_snapshot)
    _, directly_resolvable = pipeline.render_marks(
        source_bytes,
        [{"source": "atspi", "index": 7, "frame": {"x": 10, "y": 10, "width": 20, "height": 15}}],
        binding=binding,
    )
    assert visual.validate_mark_set(directly_resolvable, visual_snapshot)["1"]["elementIndex"] == 7
    resolved_mark = visual.resolve_mark_target(visual_snapshot, directly_resolvable, "1").to_dict()
    assert resolved_mark["source"] == "mark"
    assert resolved_mark["elementIndex"] == 7

    larger = Image.new("RGB", (200, 200), "black")
    larger_buffer = io.BytesIO()
    larger.save(larger_buffer, format="PNG")

    for bad_call in (
        lambda: pipeline.transform_image(source_bytes, region={"x": 200, "y": 0, "width": 2, "height": 2}),
        lambda: pipeline.transform_image(source_bytes, scale=2, zoom=2),
        lambda: pipeline.transform_image(source_bytes, output_format="gif"),
        lambda: pipeline.transform_image(source_bytes, region={"x": 0, "y": 0, "width": 1, "height": 0}),
        lambda: pipeline.transform_image(source_bytes, zoom=float("nan")),
        lambda: pipeline.transform_image(source_bytes, scale=float("inf")),
        lambda: pipeline.transform_image(source_bytes, zoom=pipeline.MAX_SCALE + 1),
        lambda: pipeline.transform_image(source_bytes, max_dimension=float("nan")),
        lambda: pipeline.transform_image(source_bytes, max_dimension=pipeline.MAX_DIMENSION + 1),
        lambda: pipeline.transform_image(source_bytes, region={"x": 1e308, "y": 0, "width": 1e308, "height": 2}),
        lambda: pipeline.transform_image(larger_buffer.getvalue(), scale=pipeline.MAX_SCALE),
    ):
        try:
            bad_call()
            raise AssertionError("invalid image request should fail")
        except pipeline.ImagePipelineError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
