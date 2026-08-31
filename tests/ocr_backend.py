#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ocr_backend", ROOT / "mcp" / "ocr_backend.py")
assert SPEC is not None and SPEC.loader is not None
ocr_backend = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ocr_backend
SPEC.loader.exec_module(ocr_backend)


PNG_HEADER = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (320).to_bytes(4, "big") + (180).to_bytes(4, "big")
TSV_FIXTURE = b"""level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext
1\t1\t0\t0\t0\t0\t0\t0\t320\t180\t-1\t
5\t1\t1\t1\t1\t1\t12\t20\t40\t18\t96.25\tHello
5\t1\t1\t1\t1\t2\t56\t20\t42\t18\t88\tworld
5\t1\t1\t1\t2\t1\t12\t50\t55\t20\t71.5\tSecond
5\t1\t1\t1\t2\t2\t72\t50\t30\t20\t-1\tignored
"""


class Completed:
    def __init__(self, returncode: int = 0, stdout: bytes = TSV_FIXTURE, stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class OcrBackendTests(unittest.TestCase):
    def test_fake_tesseract_returns_structured_words_and_image_binding(self) -> None:
        calls: list[tuple[list[str], bytes, float]] = []

        def runner(args: list[str], *, input: bytes, timeout: float) -> Completed:
            calls.append((args, input, timeout))
            return Completed()

        result = ocr_backend.ocr_image(
            PNG_HEADER,
            language="eng+deu",
            page_segmentation_mode=6,
            runner=runner,
            which=lambda name: "/fixture/tesseract" if name == "tesseract" else None,
        )

        self.assertTrue(result["available"])
        self.assertFalse(result["degraded"])
        self.assertEqual(result["backend"], "tesseract-cli")
        self.assertEqual(result["text"], "Hello world\nSecond")
        self.assertEqual(result["image"]["width"], 320)
        self.assertEqual(result["image"]["height"], 180)
        self.assertEqual(len(result["image"]["sha256"]), 64)
        self.assertEqual(result["words"][0]["confidence"], 96.25)
        self.assertEqual(
            result["words"][0]["bbox"],
            {"x": 12, "y": 20, "width": 40, "height": 18, "right": 52, "bottom": 38},
        )
        self.assertEqual(calls[0][0], ["/fixture/tesseract", "stdin", "stdout", "-l", "eng+deu", "--psm", "6", "tsv"])
        self.assertEqual(calls[0][1], PNG_HEADER)

    def test_path_input_and_tsv_page_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(b"not-an-image-header")
            result = ocr_backend.ocr_image(
                path,
                runner=lambda *args, **kwargs: Completed(),
                which=lambda name: "/fixture/tesseract",
            )
        self.assertTrue(result["available"])
        self.assertEqual((result["image"]["width"], result["image"]["height"]), (320, 180))

    def test_missing_dependencies_degrade_with_install_diagnostic(self) -> None:
        original = ocr_backend._module_available
        ocr_backend._module_available = lambda name: False
        try:
            result = ocr_backend.ocr_image(PNG_HEADER, which=lambda name: None)
        finally:
            ocr_backend._module_available = original
        self.assertFalse(result["available"])
        self.assertTrue(result["degraded"])
        self.assertEqual(result["error"]["code"], "ocr_backend_unavailable")
        self.assertIn("Install", result["error"]["message"])
        self.assertEqual(result["words"], [])
        self.assertTrue(result["diagnostics"]["localOnly"])

    def test_backend_failure_and_timeout_are_safe_degraded_results(self) -> None:
        failed = ocr_backend.ocr_image(
            PNG_HEADER,
            runner=lambda *args, **kwargs: Completed(2, b"", b"missing language data"),
            which=lambda name: "/fixture/tesseract",
        )
        self.assertEqual(failed["error"]["code"], "ocr_backend_failed")
        self.assertIn("missing language data", failed["error"]["message"])

        def timeout(*args: object, **kwargs: object) -> Completed:
            raise subprocess.TimeoutExpired("tesseract", 0.01)

        timed_out = ocr_backend.ocr_image(
            PNG_HEADER,
            timeout=0.01,
            runner=timeout,
            which=lambda name: "/fixture/tesseract",
        )
        self.assertEqual(timed_out["error"]["code"], "ocr_timeout")

    def test_malformed_output_is_reported_and_never_fabricates_words(self) -> None:
        result = ocr_backend.ocr_image(
            PNG_HEADER,
            runner=lambda *args, **kwargs: Completed(stdout=b"text\tconf\nhello\t99\n"),
            which=lambda name: "/fixture/tesseract",
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["error"]["code"], "ocr_backend_failed")
        self.assertEqual(result["words"], [])

    def test_input_validation_and_size_limit(self) -> None:
        with self.assertRaises(ocr_backend.OcrInputError):
            ocr_backend.ocr_image(b"")
        with self.assertRaises(ocr_backend.OcrInputError):
            ocr_backend.ocr_image(PNG_HEADER, language="eng;rm -rf")
        with self.assertRaises(ocr_backend.OcrInputError):
            ocr_backend.ocr_image(PNG_HEADER, page_segmentation_mode=99)
        with self.assertRaises(ocr_backend.OcrInputError):
            ocr_backend.ocr_image(PNG_HEADER, max_image_bytes=8)


if __name__ == "__main__":
    unittest.main()
