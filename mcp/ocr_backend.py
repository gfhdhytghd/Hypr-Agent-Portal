"""Optional, local-only OCR backends for hypr-agent-portal.

The public :func:`ocr_image` function accepts an image path or bytes and
returns JSON-serializable OCR words.  Bounding boxes are always expressed in
pixels relative to the supplied image; confidence values use Tesseract's
0--100 scale.  Missing or broken optional dependencies degrade to a structured
diagnostic instead of making the MCP server fail to import.

No network OCR provider is supported here.  The preferred backend is the
``tesseract`` executable because it can consume bytes on stdin without a
temporary file.  ``pytesseract`` plus Pillow is a secondary adapter.
"""

from __future__ import annotations

import csv
import hashlib
import importlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from typing import Any, Callable, Mapping


DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_IMAGE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024 * 1024

Runner = Callable[..., Any]
Which = Callable[[str], str | None]

_LANGUAGE_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")


class OcrInputError(ValueError):
    """The caller supplied an unsafe or unsupported OCR request."""


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def probe_ocr_backends(*, which: Which | None = None) -> dict[str, Any]:
    """Return side-effect-free availability diagnostics for local OCR.

    Detection deliberately does not execute Tesseract or import optional
    Python packages.  Runtime failures are reported by :func:`ocr_image`.
    """

    find_executable = which or shutil.which
    executable = find_executable("tesseract")
    has_pytesseract = _module_available("pytesseract")
    has_pillow = _module_available("PIL")
    backends = [
        {
            "id": "tesseract-cli",
            "available": bool(executable),
            "executable": executable,
            "detail": (
                f"local executable found at {executable}"
                if executable
                else "tesseract executable was not found in PATH"
            ),
        },
        {
            "id": "pytesseract",
            "available": has_pytesseract and has_pillow,
            "detail": (
                "pytesseract and Pillow are importable"
                if has_pytesseract and has_pillow
                else "requires optional Python packages pytesseract and Pillow"
            ),
            "components": {"pytesseract": has_pytesseract, "pillow": has_pillow},
        },
    ]
    available = [item["id"] for item in backends if item["available"]]
    return {
        "available": bool(available),
        "preferred": available[0] if available else None,
        "localOnly": True,
        "backends": backends,
        "installHint": (
            None
            if available
            else "Install the local tesseract executable (and desired language data); "
            "alternatively install pytesseract plus Pillow."
        ),
    }


def _read_source(source: str | os.PathLike[str] | bytes | bytearray | memoryview, limit: int) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    elif isinstance(source, (str, os.PathLike)):
        path = Path(source).expanduser()
        try:
            metadata = path.stat()
        except OSError as exc:
            raise OcrInputError(f"cannot read OCR image: {exc}") from exc
        if not path.is_file():
            raise OcrInputError("OCR source path must be a regular file")
        if metadata.st_size > limit:
            raise OcrInputError(f"OCR image exceeds the {limit}-byte limit")
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise OcrInputError(f"cannot read OCR image: {exc}") from exc
    else:
        raise OcrInputError("OCR source must be image bytes or a filesystem path")
    if not data:
        raise OcrInputError("OCR image is empty")
    if len(data) > limit:
        raise OcrInputError(f"OCR image exceeds the {limit}-byte limit")
    return data


def _image_dimensions(data: bytes) -> tuple[int | None, int | None]:
    # PNG dimensions are fixed in the IHDR header.
    if len(data) >= 24 and data.startswith(b"\x89PNG\r\n\x1a\n"):
        width, height = struct.unpack(">II", data[16:24])
        return (width or None), (height or None)

    # Read only JPEG marker framing; decoding pixels remains the OCR backend's
    # responsibility.  SOF markers other than DHT/JPG/DAC carry dimensions.
    if len(data) >= 4 and data[:2] == b"\xff\xd8":
        offset = 2
        sof_markers = set(range(0xC0, 0xD4)) - {0xC4, 0xC8, 0xCC}
        while offset + 4 <= len(data):
            if data[offset] != 0xFF:
                offset += 1
                continue
            while offset < len(data) and data[offset] == 0xFF:
                offset += 1
            if offset >= len(data):
                break
            marker = data[offset]
            offset += 1
            if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
                continue
            if offset + 2 > len(data):
                break
            segment_length = int.from_bytes(data[offset : offset + 2], "big")
            if segment_length < 2 or offset + segment_length > len(data):
                break
            if marker in sof_markers and segment_length >= 7:
                height = int.from_bytes(data[offset + 3 : offset + 5], "big")
                width = int.from_bytes(data[offset + 5 : offset + 7], "big")
                return (width or None), (height or None)
            offset += segment_length
    return None, None


def _number(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _confidence(value: Any) -> float | None:
    try:
        result = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if result < 0:
        return None
    return round(min(100.0, result), 4)


def _word(row: Mapping[str, Any]) -> dict[str, Any] | None:
    text = str(row.get("text", "")).strip()
    confidence = _confidence(row.get("conf", row.get("confidence")))
    if not text or confidence is None:
        return None
    x = max(0, _number(row.get("left", row.get("x"))))
    y = max(0, _number(row.get("top", row.get("y"))))
    width = max(0, _number(row.get("width")))
    height = max(0, _number(row.get("height")))
    result: dict[str, Any] = {
        "text": text,
        "confidence": confidence,
        "bbox": {
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "right": x + width,
            "bottom": y + height,
        },
    }
    for output_name, source_name in (
        ("page", "page_num"),
        ("block", "block_num"),
        ("paragraph", "par_num"),
        ("line", "line_num"),
        ("word", "word_num"),
    ):
        if source_name in row:
            result[output_name] = max(0, _number(row[source_name]))
    return result


def _text_from_words(words: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    current_key: tuple[int, int, int, int] | None = None
    current_words: list[str] = []
    for word in words:
        key = tuple(int(word.get(name, 0)) for name in ("page", "block", "paragraph", "line"))
        if current_words and key != current_key:
            lines.append(" ".join(current_words))
            current_words = []
        current_key = key
        current_words.append(str(word["text"]))
    if current_words:
        lines.append(" ".join(current_words))
    return "\n".join(lines)


def _parse_tsv(payload: bytes) -> tuple[list[dict[str, Any]], tuple[int | None, int | None]]:
    text = payload.decode("utf-8", errors="replace")
    rows = csv.DictReader(io.StringIO(text), delimiter="\t")
    required = {"text", "conf", "left", "top", "width", "height"}
    if rows.fieldnames is None or not required.issubset(set(rows.fieldnames)):
        raise RuntimeError("tesseract returned malformed TSV output")
    words: list[dict[str, Any]] = []
    page_width: int | None = None
    page_height: int | None = None
    for row in rows:
        if _number(row.get("level"), -1) == 1:
            page_width = max(0, _number(row.get("width"))) or page_width
            page_height = max(0, _number(row.get("height"))) or page_height
        parsed = _word(row)
        if parsed is not None:
            words.append(parsed)
    return words, (page_width, page_height)


def _default_runner(args: list[str], *, input: bytes, timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def _run_cli(
    executable: str,
    data: bytes,
    *,
    language: str | None,
    page_segmentation_mode: int | None,
    timeout: float,
    max_output_bytes: int,
    runner: Runner | None,
) -> tuple[list[dict[str, Any]], tuple[int | None, int | None], str]:
    args = [executable, "stdin", "stdout"]
    if language:
        args.extend(["-l", language])
    if page_segmentation_mode is not None:
        args.extend(["--psm", str(page_segmentation_mode)])
    args.append("tsv")
    completed = (runner or _default_runner)(args, input=data, timeout=timeout)
    return_code = int(getattr(completed, "returncode", 0))
    stdout = bytes(getattr(completed, "stdout", b"") or b"")
    stderr = bytes(getattr(completed, "stderr", b"") or b"")
    if len(stdout) > max_output_bytes:
        raise RuntimeError(f"tesseract output exceeds the {max_output_bytes}-byte limit")
    stderr_text = stderr.decode("utf-8", errors="replace").strip()
    if return_code != 0:
        detail = stderr_text[:1000] or "no diagnostic output"
        raise RuntimeError(f"tesseract exited with status {return_code}: {detail}")
    words, dimensions = _parse_tsv(stdout)
    return words, dimensions, stderr_text[:1000]


def _run_pytesseract(
    data: bytes,
    *,
    language: str | None,
    page_segmentation_mode: int | None,
    timeout: float,
) -> tuple[list[dict[str, Any]], tuple[int | None, int | None]]:
    pytesseract = importlib.import_module("pytesseract")
    pillow_image = importlib.import_module("PIL.Image")
    image = pillow_image.open(io.BytesIO(data))
    image.load()
    config = "" if page_segmentation_mode is None else f"--psm {page_segmentation_mode}"
    output = pytesseract.image_to_data(
        image,
        lang=language,
        config=config,
        output_type=pytesseract.Output.DICT,
        timeout=timeout,
    )
    keys = list(output)
    length = max((len(output[key]) for key in keys), default=0)
    words: list[dict[str, Any]] = []
    for index in range(length):
        row = {key: output[key][index] for key in keys if index < len(output[key])}
        parsed = _word(row)
        if parsed is not None:
            words.append(parsed)
    width, height = image.size
    return words, (int(width), int(height))


def _degraded_result(
    *,
    image: Mapping[str, Any],
    diagnostics: Mapping[str, Any],
    code: str,
    message: str,
    backend: str | None = None,
) -> dict[str, Any]:
    return {
        "available": False,
        "degraded": True,
        "backend": backend,
        "text": "",
        "words": [],
        "confidenceScale": "0-100",
        "coordinateSpace": "image_pixels",
        "image": dict(image),
        "error": {"code": code, "message": message},
        "diagnostics": dict(diagnostics),
    }


def ocr_image(
    source: str | os.PathLike[str] | bytes | bytearray | memoryview,
    *,
    backend: str = "auto",
    language: str | None = None,
    page_segmentation_mode: int | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    runner: Runner | None = None,
    which: Which | None = None,
) -> dict[str, Any]:
    """OCR an image locally and return text, confidence, and pixel boxes.

    Dependency and runtime backend failures are safe degraded results.  Invalid
    caller input raises :class:`OcrInputError`, allowing an MCP schema error to
    be distinguished from an optional dependency being absent.
    """

    if backend not in {"auto", "tesseract-cli", "pytesseract"}:
        raise OcrInputError("backend must be auto, tesseract-cli, or pytesseract")
    if language is not None and not _LANGUAGE_RE.fullmatch(language):
        raise OcrInputError("language must be a short Tesseract language expression")
    if page_segmentation_mode is not None and not 0 <= page_segmentation_mode <= 13:
        raise OcrInputError("page_segmentation_mode must be between 0 and 13")
    if not 0 < timeout <= 120:
        raise OcrInputError("timeout must be greater than 0 and at most 120 seconds")
    if max_image_bytes <= 0 or max_output_bytes <= 0:
        raise OcrInputError("byte limits must be positive")

    data = _read_source(source, max_image_bytes)
    width, height = _image_dimensions(data)
    image: dict[str, Any] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "width": width,
        "height": height,
    }
    diagnostics = probe_ocr_backends(which=which)
    selected = diagnostics["preferred"] if backend == "auto" else backend
    selected_status = next(
        (item for item in diagnostics["backends"] if item["id"] == selected),
        None,
    )
    if selected is None or selected_status is None or not selected_status["available"]:
        requested = "a local OCR backend" if backend == "auto" else backend
        return _degraded_result(
            image=image,
            diagnostics=diagnostics,
            code="ocr_backend_unavailable",
            message=f"{requested} is unavailable; {diagnostics['installHint'] or selected_status['detail']}",
            backend=None if backend == "auto" else backend,
        )

    try:
        if selected == "tesseract-cli":
            words, reported_dimensions, warning = _run_cli(
                str(selected_status["executable"]),
                data,
                language=language,
                page_segmentation_mode=page_segmentation_mode,
                timeout=timeout,
                max_output_bytes=max_output_bytes,
                runner=runner,
            )
        else:
            words, reported_dimensions = _run_pytesseract(
                data,
                language=language,
                page_segmentation_mode=page_segmentation_mode,
                timeout=timeout,
            )
            warning = ""
    except subprocess.TimeoutExpired:
        return _degraded_result(
            image=image,
            diagnostics=diagnostics,
            code="ocr_timeout",
            message=f"local OCR exceeded the {timeout:g}-second timeout",
            backend=selected,
        )
    except Exception as exc:
        return _degraded_result(
            image=image,
            diagnostics=diagnostics,
            code="ocr_backend_failed",
            message=f"{selected} failed: {type(exc).__name__}: {exc}",
            backend=selected,
        )

    if image["width"] is None:
        image["width"] = reported_dimensions[0]
    if image["height"] is None:
        image["height"] = reported_dimensions[1]
    result: dict[str, Any] = {
        "available": True,
        "degraded": False,
        "backend": selected,
        "text": _text_from_words(words),
        "words": words,
        "confidenceScale": "0-100",
        "coordinateSpace": "image_pixels",
        "image": image,
        "diagnostics": diagnostics,
    }
    if warning:
        result["backendWarning"] = warning
    return result


__all__ = [
    "DEFAULT_MAX_IMAGE_BYTES",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "OcrInputError",
    "ocr_image",
    "probe_ocr_backends",
]
