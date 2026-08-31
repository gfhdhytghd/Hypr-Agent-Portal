#!/usr/bin/env python3
"""Optional-Pillow screenshot transformations for hypr-agent-portal.

The module deliberately has no dependency on the MCP server.  Callers pass an
already privacy-filtered screenshot and its geometry, and receive newly encoded
bytes plus JSON-serializable coordinate mapping metadata.  Input bytes and files
are never modified.
"""

from __future__ import annotations

import io
import math
from collections.abc import Mapping, Sequence
from typing import Any

try:
    from PIL import Image, ImageDraw, ImageFont, features

    _PIL_IMPORT_ERROR: BaseException | None = None
except (ImportError, OSError) as exc:  # pragma: no cover - exercised by monkeypatch
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
    ImageFont = None  # type: ignore[assignment]
    features = None  # type: ignore[assignment]
    _PIL_IMPORT_ERROR = exc


class ImagePipelineError(RuntimeError):
    """Invalid image request or unavailable image capability."""


MAX_IMAGE_PIXELS = 64_000_000
MAX_SCALE = 64.0
MAX_DIMENSION = 32_768


def backend_status() -> dict[str, Any]:
    """Return a stable, user-facing capability diagnostic."""

    if Image is None:
        detail = f": {_PIL_IMPORT_ERROR}" if _PIL_IMPORT_ERROR else ""
        return {
            "available": False,
            "backend": None,
            "formats": [],
            "diagnostic": (
                "Pillow is not installed; region crop, zoom, compression, and "
                f"Set-of-Marks overlays are unavailable{detail}. Install the "
                "optional 'Pillow' Python package to enable image processing."
            ),
        }

    supported = ["png"]
    if features is not None and features.check("jpg"):
        supported.append("jpeg")
    if features is not None and features.check("webp"):
        supported.append("webp")
    return {
        "available": True,
        "backend": "Pillow",
        "version": getattr(Image, "__version__", None),
        "formats": supported,
        "diagnostic": None,
    }


def require_backend() -> None:
    status = backend_status()
    if not status["available"]:
        raise ImagePipelineError(status["diagnostic"])


def _finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ImagePipelineError(f"{name} must be a finite number")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ImagePipelineError(f"{name} must be a finite number") from exc
    if not math.isfinite(result):
        raise ImagePipelineError(f"{name} must be a finite number")
    return result


def _positive_number(value: Any, name: str) -> float:
    result = _finite_number(value, name)
    if result <= 0:
        raise ImagePipelineError(f"{name} must be greater than zero")
    return result


def _rect(value: Any, name: str = "region") -> dict[str, float]:
    if not isinstance(value, Mapping):
        raise ImagePipelineError(f"{name} must be an object with x, y, width, and height")
    try:
        result = {key: _finite_number(value[key], f"{name}.{key}") for key in ("x", "y", "width", "height")}
    except KeyError as exc:
        raise ImagePipelineError(f"{name} is missing {exc.args[0]}") from exc
    if result["width"] <= 0 or result["height"] <= 0:
        raise ImagePipelineError(f"{name} width and height must be greater than zero")
    return result


def _window_origin(window: Mapping[str, Any] | None) -> tuple[float, float]:
    if not isinstance(window, Mapping):
        raise ImagePipelineError("coordinate_space=window requires target window geometry")
    at = window.get("at")
    if isinstance(at, Sequence) and not isinstance(at, (str, bytes)) and len(at) >= 2:
        return _finite_number(at[0], "window.at[0]"), _finite_number(at[1], "window.at[1]")
    bounds = window.get("windowBounds") if isinstance(window.get("windowBounds"), Mapping) else window
    if "x" in bounds and "y" in bounds:
        return _finite_number(bounds["x"], "window.x"), _finite_number(bounds["y"], "window.y")
    raise ImagePipelineError("coordinate_space=window requires window.at or window x/y")


def _logical_bounds(screenshot: Mapping[str, Any] | None) -> dict[str, float]:
    if not isinstance(screenshot, Mapping) or not isinstance(screenshot.get("logicalBounds"), Mapping):
        raise ImagePipelineError("coordinate_space=window requires screenshot.logicalBounds")
    return _rect(screenshot["logicalBounds"], "screenshot.logicalBounds")


def _window_to_screenshot_affine(
    source_width: int,
    source_height: int,
    screenshot: Mapping[str, Any] | None,
    window: Mapping[str, Any] | None,
) -> dict[str, float]:
    bounds = _logical_bounds(screenshot)
    window_x, window_y = _window_origin(window)
    scale_x = source_width / bounds["width"]
    scale_y = source_height / bounds["height"]
    return {
        "scaleX": scale_x,
        "scaleY": scale_y,
        "offsetX": (window_x - bounds["x"]) * scale_x,
        "offsetY": (window_y - bounds["y"]) * scale_y,
    }


def _apply_rect_affine(rect: Mapping[str, float], affine: Mapping[str, float]) -> dict[str, float]:
    transformed = {
        "x": rect["x"] * affine["scaleX"] + affine["offsetX"],
        "y": rect["y"] * affine["scaleY"] + affine["offsetY"],
        "width": rect["width"] * affine["scaleX"],
        "height": rect["height"] * affine["scaleY"],
    }
    if not all(math.isfinite(value) for value in transformed.values()):
        raise ImagePipelineError("coordinate transform produced a non-finite rectangle")
    return transformed


def _inverse_affine(affine: Mapping[str, float]) -> dict[str, float]:
    sx = affine["scaleX"]
    sy = affine["scaleY"]
    if sx == 0 or sy == 0:
        raise ImagePipelineError("coordinate transform is not invertible")
    return {
        "scaleX": 1.0 / sx,
        "scaleY": 1.0 / sy,
        "offsetX": -affine["offsetX"] / sx,
        "offsetY": -affine["offsetY"] / sy,
    }


def map_point(point: Mapping[str, Any], affine: Mapping[str, Any]) -> dict[str, float]:
    """Apply one of the affine mappings returned in transformation metadata."""

    x = _finite_number(point.get("x"), "point.x")
    y = _finite_number(point.get("y"), "point.y")
    return {
        "x": x * _finite_number(affine.get("scaleX"), "affine.scaleX")
        + _finite_number(affine.get("offsetX"), "affine.offsetX"),
        "y": y * _finite_number(affine.get("scaleY"), "affine.scaleY")
        + _finite_number(affine.get("offsetY"), "affine.offsetY"),
    }


def _normalize_format(value: Any) -> str:
    normalized = str(value or "png").strip().lower().replace("image/", "")
    if normalized == "jpg":
        normalized = "jpeg"
    if normalized not in {"png", "jpeg", "webp"}:
        raise ImagePipelineError("format must be png, jpeg/jpg, or webp")
    status = backend_status()
    if normalized not in status["formats"]:
        raise ImagePipelineError(
            f"Pillow backend does not support requested {normalized} encoding; "
            f"available formats: {', '.join(status['formats']) or 'none'}"
        )
    return normalized


def _decode(image_bytes: bytes):
    require_backend()
    if not isinstance(image_bytes, bytes) or not image_bytes:
        raise ImagePipelineError("image_bytes must be non-empty bytes")
    try:
        image = Image.open(io.BytesIO(image_bytes))
        if image.width <= 0 or image.height <= 0 or image.width * image.height > MAX_IMAGE_PIXELS:
            raise ImagePipelineError(
                f"decoded screenshot exceeds the {MAX_IMAGE_PIXELS}-pixel processing budget"
            )
        image.load()
    except ImagePipelineError:
        raise
    except Exception as exc:
        raise ImagePipelineError(f"could not decode screenshot: {exc}") from exc
    return image


def _prepare(
    image_bytes: bytes,
    *,
    screenshot: Mapping[str, Any] | None,
    window: Mapping[str, Any] | None,
    region: Mapping[str, Any] | None,
    coordinate_space: str,
    scale: float | None,
    zoom: float | None,
    max_dimension: int | None,
):
    image = _decode(image_bytes)
    source_width, source_height = image.size
    if source_width <= 0 or source_height <= 0:
        raise ImagePipelineError("decoded screenshot has invalid dimensions")
    if source_width * source_height > MAX_IMAGE_PIXELS:
        raise ImagePipelineError(f"decoded screenshot exceeds the {MAX_IMAGE_PIXELS}-pixel processing budget")

    normalized_space = str(coordinate_space or "screenshot").strip().lower().replace("_", "-")
    if normalized_space in {"screenshot-pixel", "screenshot-pixels", "image", "pixel", "pixels"}:
        normalized_space = "screenshot"
    elif normalized_space in {"window-relative", "window-logical", "logical"}:
        normalized_space = "window"
    if normalized_space not in {"screenshot", "window"}:
        raise ImagePipelineError("coordinate_space must be screenshot or window")

    window_to_screenshot = None
    requested = _rect(region) if region is not None else {
        "x": 0.0,
        "y": 0.0,
        "width": float(source_width),
        "height": float(source_height),
    }
    if normalized_space == "window":
        window_to_screenshot = _window_to_screenshot_affine(source_width, source_height, screenshot, window)
        requested_screenshot = _apply_rect_affine(requested, window_to_screenshot)
    else:
        requested_screenshot = dict(requested)

    if not all(math.isfinite(value) for value in requested_screenshot.values()):
        raise ImagePipelineError("transformed region must contain finite coordinates and dimensions")
    requested_right = requested_screenshot["x"] + requested_screenshot["width"]
    requested_bottom = requested_screenshot["y"] + requested_screenshot["height"]
    if not math.isfinite(requested_right) or not math.isfinite(requested_bottom):
        raise ImagePipelineError("transformed region extent is too large")

    left = max(0, math.floor(requested_screenshot["x"]))
    top = max(0, math.floor(requested_screenshot["y"]))
    right = min(source_width, math.ceil(requested_right))
    bottom = min(source_height, math.ceil(requested_bottom))
    if right <= left or bottom <= top:
        raise ImagePipelineError("requested region does not intersect the screenshot")
    crop = {"x": left, "y": top, "width": right - left, "height": bottom - top}
    image = image.crop((left, top, right, bottom))

    if scale is not None and zoom is not None:
        raise ImagePipelineError("provide only one of scale or zoom")
    requested_scale = _positive_number(zoom if zoom is not None else (scale if scale is not None else 1.0), "zoom")
    if requested_scale > MAX_SCALE:
        raise ImagePipelineError(f"zoom/scale must not exceed {MAX_SCALE:g}")
    requested_width = crop["width"] * requested_scale
    requested_height = crop["height"] * requested_scale
    if not math.isfinite(requested_width) or not math.isfinite(requested_height):
        raise ImagePipelineError("requested output dimensions are too large")
    width = max(1, round(requested_width))
    height = max(1, round(requested_height))
    max_dimension_value = None
    if max_dimension is not None:
        raw_max_dimension = _positive_number(max_dimension, "max_dimension")
        if not raw_max_dimension.is_integer():
            raise ImagePipelineError("max_dimension must be a positive integer")
        max_dimension_value = int(raw_max_dimension)
        if max_dimension_value > MAX_DIMENSION:
            raise ImagePipelineError(f"max_dimension must not exceed {MAX_DIMENSION}")
        if max(width, height) > max_dimension_value:
            fit = max_dimension_value / max(width, height)
            width = max(1, round(width * fit))
            height = max(1, round(height * fit))
    if width * height > MAX_IMAGE_PIXELS:
        raise ImagePipelineError(
            f"requested output exceeds the {MAX_IMAGE_PIXELS}-pixel processing budget; "
            "use max_dimension or a smaller region/scale"
        )
    if image.size != (width, height):
        image = image.resize((width, height), Image.Resampling.LANCZOS)

    screenshot_to_output = {
        "scaleX": width / crop["width"],
        "scaleY": height / crop["height"],
        "offsetX": -left * width / crop["width"],
        "offsetY": -top * height / crop["height"],
    }
    mappings: dict[str, Any] = {
        "screenshotToOutput": screenshot_to_output,
        "outputToScreenshot": _inverse_affine(screenshot_to_output),
    }
    if window_to_screenshot is not None:
        window_to_output = {
            "scaleX": window_to_screenshot["scaleX"] * screenshot_to_output["scaleX"],
            "scaleY": window_to_screenshot["scaleY"] * screenshot_to_output["scaleY"],
            "offsetX": window_to_screenshot["offsetX"] * screenshot_to_output["scaleX"] + screenshot_to_output["offsetX"],
            "offsetY": window_to_screenshot["offsetY"] * screenshot_to_output["scaleY"] + screenshot_to_output["offsetY"],
        }
        mappings.update(
            {
                "windowToScreenshot": window_to_screenshot,
                "screenshotToWindow": _inverse_affine(window_to_screenshot),
                "windowToOutput": window_to_output,
                "outputToWindow": _inverse_affine(window_to_output),
            }
        )

    metadata = {
        "source": {"width": source_width, "height": source_height},
        "output": {"width": width, "height": height},
        "requestedRegion": {**requested, "coordinateSpace": normalized_space},
        "requestedRegionInScreenshot": requested_screenshot,
        "cropInScreenshot": crop,
        "clipped": crop != {
            "x": requested_screenshot["x"],
            "y": requested_screenshot["y"],
            "width": requested_screenshot["width"],
            "height": requested_screenshot["height"],
        },
        "requestedScale": requested_scale,
        "effectiveScale": {"x": width / crop["width"], "y": height / crop["height"]},
        "maxDimension": max_dimension_value,
        "mappings": mappings,
    }
    return image, metadata


def _encode(image, output_format: str, quality: int) -> tuple[bytes, dict[str, Any]]:
    normalized = _normalize_format(output_format)
    quality_value = int(_finite_number(quality, "quality"))
    if not 1 <= quality_value <= 100:
        raise ImagePipelineError("quality must be between 1 and 100")
    options: dict[str, Any] = {}
    alpha_flattened = False
    if normalized == "png":
        options = {"compress_level": max(0, min(9, round((100 - quality_value) * 9 / 99)))}
    else:
        options = {"quality": quality_value}
        if normalized == "jpeg":
            if image.mode not in {"RGB", "L"}:
                base = Image.new("RGB", image.size, "white")
                if "A" in image.getbands():
                    base.paste(image, mask=image.getchannel("A"))
                else:
                    base.paste(image.convert("RGB"))
                image = base
                alpha_flattened = True
            options["optimize"] = True
    destination = io.BytesIO()
    try:
        image.save(destination, format=normalized.upper(), **options)
    except Exception as exc:
        raise ImagePipelineError(f"could not encode {normalized} screenshot: {exc}") from exc
    return destination.getvalue(), {
        "format": normalized,
        "mimeType": f"image/{normalized}",
        "quality": quality_value,
        "byteLength": destination.tell(),
        "alphaFlattened": alpha_flattened,
    }


def transform_image(
    image_bytes: bytes,
    *,
    screenshot: Mapping[str, Any] | None = None,
    window: Mapping[str, Any] | None = None,
    region: Mapping[str, Any] | None = None,
    coordinate_space: str = "screenshot",
    scale: float | None = None,
    zoom: float | None = None,
    output_format: str = "png",
    quality: int = 85,
    max_dimension: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Crop, magnify/downscale, and encode a screenshot with reversible mapping."""

    image, metadata = _prepare(
        image_bytes,
        screenshot=screenshot,
        window=window,
        region=region,
        coordinate_space=coordinate_space,
        scale=scale,
        zoom=zoom,
        max_dimension=max_dimension,
    )
    encoded, encoding = _encode(image, output_format, quality)
    metadata["output"].update(encoding)
    return encoded, metadata


def _candidate_box(candidate: Mapping[str, Any]) -> dict[str, float]:
    for key in ("frame", "box", "bbox", "bounds"):
        value = candidate.get(key)
        if isinstance(value, Mapping):
            return _rect(value, f"mark.{key}")
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) == 4:
            return _rect(dict(zip(("x", "y", "width", "height"), value)), f"mark.{key}")
    return _rect(candidate, "mark")


def render_marks(
    image_bytes: bytes,
    candidates: Sequence[Mapping[str, Any]],
    *,
    screenshot: Mapping[str, Any] | None = None,
    window: Mapping[str, Any] | None = None,
    region: Mapping[str, Any] | None = None,
    coordinate_space: str = "screenshot",
    candidate_coordinate_space: str = "screenshot",
    scale: float | None = None,
    zoom: float | None = None,
    output_format: str = "png",
    quality: int = 85,
    max_dimension: int | None = None,
    binding: Mapping[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Draw numbered marks on a transformed copy and return click mappings."""

    image, metadata = _prepare(
        image_bytes,
        screenshot=screenshot,
        window=window,
        region=region,
        coordinate_space=coordinate_space,
        scale=scale,
        zoom=zoom,
        max_dimension=max_dimension,
    )
    image = image.convert("RGBA")
    draw = ImageDraw.Draw(image, "RGBA")
    font = ImageFont.load_default()
    mappings = metadata["mappings"]
    candidate_space = str(candidate_coordinate_space or "screenshot").strip().lower().replace("_", "-")
    if candidate_space in {"window-relative", "window-logical", "logical"}:
        candidate_space = "window"
    if candidate_space not in {"screenshot", "window"}:
        raise ImagePipelineError("candidate_coordinate_space must be screenshot or window")
    to_screenshot = mappings.get("windowToScreenshot") if candidate_space == "window" else {
        "scaleX": 1.0,
        "scaleY": 1.0,
        "offsetX": 0.0,
        "offsetY": 0.0,
    }
    if to_screenshot is None:
        to_screenshot = _window_to_screenshot_affine(
            metadata["source"]["width"], metadata["source"]["height"], screenshot, window
        )
    screenshot_to_output = mappings["screenshotToOutput"]
    mark_map: list[dict[str, Any]] = []
    out_w, out_h = image.size
    for candidate_index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping):
            raise ImagePipelineError(f"marks[{candidate_index}] must be an object")
        box = _apply_rect_affine(_candidate_box(candidate), to_screenshot)
        visible_left = max(0.0, box["x"])
        visible_top = max(0.0, box["y"])
        visible_right = min(float(metadata["source"]["width"]), box["x"] + box["width"])
        visible_bottom = min(float(metadata["source"]["height"]), box["y"] + box["height"])
        if visible_right <= visible_left or visible_bottom <= visible_top:
            continue
        visible_box = {
            "x": visible_left,
            "y": visible_top,
            "width": visible_right - visible_left,
            "height": visible_bottom - visible_top,
        }
        output_box = _apply_rect_affine(visible_box, screenshot_to_output)
        left = max(0.0, output_box["x"])
        top = max(0.0, output_box["y"])
        right = min(float(out_w), output_box["x"] + output_box["width"])
        bottom = min(float(out_h), output_box["y"] + output_box["height"])
        if right <= left or bottom <= top:
            continue
        mark_id = str(len(mark_map) + 1)
        draw.rectangle((left, top, right, bottom), outline=(255, 48, 48, 245), width=2)
        label_box = draw.textbbox((0, 0), mark_id, font=font, stroke_width=1)
        label_w = label_box[2] - label_box[0] + 8
        label_h = label_box[3] - label_box[1] + 6
        label_x = min(max(0.0, left), max(0.0, out_w - label_w))
        label_y = min(max(0.0, top), max(0.0, out_h - label_h))
        draw.rounded_rectangle(
            (label_x, label_y, label_x + label_w, label_y + label_h),
            radius=3,
            fill=(220, 28, 28, 245),
            outline=(255, 255, 255, 255),
            width=1,
        )
        draw.text((label_x + 4, label_y + 2), mark_id, font=font, fill=(255, 255, 255, 255), stroke_width=1)
        center_screenshot = {
            "x": visible_box["x"] + visible_box["width"] / 2,
            "y": visible_box["y"] + visible_box["height"] / 2,
        }
        raw_source = str(candidate.get("source", "element")).strip().lower()
        source = "element" if raw_source in {"element", "atspi", "accessible", "accessibility"} else raw_source
        if source not in {"element", "ocr", "point"}:
            raise ImagePipelineError(f"marks[{candidate_index}].source is unsupported: {raw_source!r}")
        entry: dict[str, Any] = {
            "id": mark_id,
            "markId": mark_id,
            "candidateIndex": candidate_index,
            "source": source,
            "frame": visible_box,
            "screenshotBox": visible_box,
            "outputBox": output_box,
            "screenshotPoint": center_screenshot,
            "outputPoint": map_point(center_screenshot, screenshot_to_output),
        }
        for source_key, result_key in (
            ("index", "elementIndex"),
            ("element_index", "elementIndex"),
            ("elementIndex", "elementIndex"),
            ("ocr_index", "ocrIndex"),
            ("ocrIndex", "ocrIndex"),
            ("text", "text"),
            ("name", "name"),
        ):
            if source_key in candidate and result_key not in entry:
                entry[result_key] = candidate[source_key]
        if source == "element" and "elementIndex" not in entry:
            raise ImagePipelineError(f"marks[{candidate_index}] element source requires an element index")
        if source == "ocr" and "ocrIndex" not in entry:
            raise ImagePipelineError(f"marks[{candidate_index}] OCR source requires an OCR index")
        mark_map.append(entry)

    encoded, encoding = _encode(image, output_format, quality)
    metadata["output"].update(encoding)
    metadata["marks"] = mark_map
    if binding is not None and not isinstance(binding, Mapping):
        raise ImagePipelineError("binding must be an object")
    if binding is not None:
        metadata["binding"] = dict(binding)
    metadata["markCount"] = len(mark_map)
    metadata["overlay"] = {
        "type": "set-of-marks",
        "sourceImageModified": False,
        "privacyFiltering": "caller-provided-input",
    }
    return encoded, metadata


__all__ = [
    "ImagePipelineError",
    "backend_status",
    "map_point",
    "render_marks",
    "require_backend",
    "transform_image",
]
