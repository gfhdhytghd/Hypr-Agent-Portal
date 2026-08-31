#!/usr/bin/env python3
import importlib.util
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "mcp" / "visual_targets.py"


def load_module():
    spec = importlib.util.spec_from_file_location("visual_targets", MODULE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expect_error(module, code, operation):
    try:
        operation()
    except module.VisualTargetError as error:
        assert error.code == code, error.to_dict()
        return error
    raise AssertionError(f"expected VisualTargetError({code})")


def snapshot(*, shot_id="shot-7", digest="a" * 64, at=(100, 200), size=(800, 600)):
    return {
        "target": "address:0xabc",
        "app": {"pid": 42},
        "window": {"address": "0xabc", "class": "demo", "pid": 42, "at": list(at), "size": list(size)},
        "screenshot": {
            "id": shot_id,
            "sha256": digest,
            "width": 800,
            "height": 600,
            "logicalBounds": {"x": at[0], "y": at[1], "width": size[0], "height": size[1]},
        },
        "elements": [
            {
                "index": 2,
                "controlType": "text field",
                "name": "Search",
                "text": "query",
                "states": ["enabled", "editable"],
                "frame": {"x": 90, "y": 80, "width": 300, "height": 50},
            },
            {
                "index": 3,
                "controlType": "push button",
                "name": "Open",
                "text": "Open document",
                "frame": {"x": 500, "y": 400, "width": 100, "height": 40},
            },
            {
                "index": 4,
                "controlType": "text field",
                "name": "Second Search",
                "text": "another query",
                "editable": True,
                "frame": {"x": 90, "y": 150, "width": 300, "height": 50},
            },
        ],
    }


def main() -> int:
    module = load_module()
    snap = snapshot()
    binding = module.make_snapshot_binding(snap)
    assert binding["screenshotId"] == "shot-7"
    assert binding["screenshotHash"] == "a" * 64
    assert binding["windowIdentity"] == {"address": "0xabc", "pid": 42, "class": "demo"}
    assert module.validate_snapshot_binding(binding, snap) == binding

    expect_error(module, "stale_visual_target", lambda: module.validate_snapshot_binding(binding, snapshot(shot_id="shot-8")))
    expect_error(module, "stale_visual_target", lambda: module.validate_snapshot_binding(binding, snapshot(digest="b" * 64)))
    expect_error(module, "stale_visual_target", lambda: module.validate_snapshot_binding(binding, snapshot(at=(101, 200))))
    unbound = snapshot()
    del unbound["screenshot"]["id"]
    expect_error(module, "unbound_screenshot", lambda: module.make_snapshot_binding(unbound))

    regions = [
        {"text": "Save", "confidence": 0.99, "frame": {"x": 10, "y": 10, "width": 50, "height": 20}},
        {"text": "save as", "confidence": 0.91, "bbox": [20, 40, 80, 20]},
        {"text": "Search files", "confidence": 0.87, "box": {"x": 100, "y": 90, "width": 150, "height": 20}},
    ]
    ocr = {"binding": binding, "regions": regions}
    assert module.match_ocr_regions(regions, "save")[0] == 0
    assert module.match_ocr_regions(regions, "save", match="contains", nth=2)[0] == 1
    assert module.match_ocr_regions(regions, r"^search\s+files$", match="regex")[0] == 2
    expect_error(module, "visual_target_not_found", lambda: module.match_ocr_regions(regions, "SAVE", casefold=False))
    expect_error(module, "invalid_regex", lambda: module.match_ocr_regions(regions, "[", match="regex"))
    target = module.resolve_click_target(
        snap, {"ocr": {"text": "save", "match": "contains", "nth": 2}}, ocr_result=ocr
    ).to_dict()
    assert target["source"] == "ocr"
    assert target["ocrIndex"] == 1
    assert target["point"] == {"x": 60.0, "y": 50.0, "coordinateSpace": "screenshot"}
    percent_ocr = {
        "binding": binding,
        "confidenceScale": "0-100",
        "regions": [{"text": "Percent", "confidence": 95, "bbox": [10, 10, 40, 20]}],
    }
    percent_target = module.resolve_ocr_target(snap, percent_ocr, "Percent").to_dict()
    assert percent_target["confidence"] == 0.95
    assert module.validate_ocr_result(percent_ocr, snap)[0]["confidenceScale"] == "0-1"
    inferred_percent = {"binding": binding, "regions": [{"text": "95", "confidence": 95, "bbox": [1, 1, 2, 2]}]}
    assert module.validate_ocr_result(inferred_percent, snap)[0]["confidence"] == 0.95
    expect_error(module, "unsafe_regex", lambda: module.match_ocr_regions(regions, "(a+)+$", match="regex"))
    expect_error(module, "unsafe_regex", lambda: module.match_ocr_regions(regions, "a|aa", match="regex"))
    expect_error(module, "unsafe_regex", lambda: module.match_ocr_regions(regions, "a*a*b", match="regex"))
    expect_error(module, "unsafe_regex_candidate", lambda: module.match_ocr_regions(
        [{"text": "a" * (module.MAX_REGEX_CANDIDATE_LENGTH + 1)}], "a+", match="regex"
    ))
    stale_ocr = {"binding": {**binding, "screenshotHash": "b" * 64}, "regions": regions}
    expect_error(
        module,
        "stale_visual_target",
        lambda: module.resolve_click_target(snap, {"ocr": {"text": "Save"}}, ocr_result=stale_ocr),
    )

    marks = {
        "binding": binding,
        "marks": [
            {
                "id": "1",
                "source": "element",
                "elementIndex": 3,
                "frame": {"x": 500, "y": 400, "width": 100, "height": 40},
            },
            {
                "id": "2",
                "source": "ocr",
                "ocrIndex": 2,
                "frame": {"x": 100, "y": 90, "width": 150, "height": 20},
            },
            {"id": "3", "source": "point", "frame": {"x": 700, "y": 500, "width": 1, "height": 1}},
            {
                "id": "4",
                "source": "element",
                "elementIndex": 2,
                "frame": {"x": 90, "y": 80, "width": 300, "height": 50},
            },
        ],
    }
    mark_target = module.resolve_click_target(snap, {"mark_id": 1}, mark_set=marks).to_dict()
    assert mark_target["markId"] == "1"
    assert mark_target["elementIndex"] == 3
    assert mark_target["point"]["x"] == 550
    duplicate = {"binding": binding, "marks": [marks["marks"][0], marks["marks"][0]]}
    expect_error(module, "duplicate_mark_id", lambda: module.validate_mark_set(duplicate, snap))
    outside = {
        "binding": binding,
        "marks": [{"id": "x", "source": "point", "frame": {"x": 799, "y": 599, "width": 10, "height": 10}}],
    }
    expect_error(module, "target_out_of_bounds", lambda: module.validate_mark_set(outside, snap))
    moved_element = snapshot()
    moved_element["elements"][1]["frame"]["x"] = 501
    expect_error(module, "stale_visual_target", lambda: module.resolve_mark_target(moved_element, marks, "1"))

    by_index = module.resolve_type_into_target(snap, {"element_index": 2})
    assert by_index["editableVerified"] is True
    assert by_index["focusRequired"] is True
    assert by_index["refreshBeforeInputRequired"] is True
    assert by_index["elementIndex"] == 2
    by_name = module.resolve_type_into_target(snap, {"accessible_name": "search", "match": "contains", "nth": 2})
    assert by_name["elementIndex"] == 4
    by_text = module.resolve_type_into_target(snap, {"accessible_text": r"^query$", "match": "regex"})
    assert by_text["elementIndex"] == 2
    by_ocr = module.resolve_type_into_target(
        snap, {"ocr": {"text": "Search files"}}, ocr_result=ocr
    )
    assert by_ocr["source"] == "ocr"
    assert by_ocr["elementIndex"] == 2
    by_mark = module.resolve_type_into_target(snap, {"mark_id": "4"}, mark_set=marks)
    assert by_mark["source"] == "mark"
    assert by_mark["elementIndex"] == 2
    expect_error(module, "target_not_editable", lambda: module.resolve_type_into_target(snap, {"element_index": 3}))
    expect_error(
        module,
        "target_not_editable",
        lambda: module.resolve_type_into_target(snap, {"mark_id": "1"}, mark_set=marks),
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
