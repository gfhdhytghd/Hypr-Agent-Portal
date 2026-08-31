"""Pure helpers for screenshot-bound OCR, marks, click, and typing targets.

The MCP server owns capture/OCR/rendering and input dispatch.  This module only
validates the untrusted, short-lived targeting metadata that joins those
operations.  In particular, coordinates from OCR or a Set-of-Marks overlay are
never accepted after the screenshot or its window geometry changes.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


MAX_REGEX_LENGTH = 256
MAX_REGEX_CANDIDATE_LENGTH = 4096
MAX_MATCH_CANDIDATES = 4096


class VisualTargetError(ValueError):
    """A structured target-validation error suitable for an MCP response."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "details": dict(self.details)}


class StaleVisualTargetError(VisualTargetError):
    def __init__(self, message: str, **details: Any) -> None:
        super().__init__("stale_visual_target", message, **details)


@dataclass(frozen=True)
class MatchSpec:
    text: str
    mode: str = "exact"
    casefold: bool = True
    nth: int = 1

    def __post_init__(self) -> None:
        mode = str(self.mode).strip().lower()
        if mode not in {"exact", "contains", "regex"}:
            raise VisualTargetError("invalid_match_mode", f"unsupported match mode: {self.mode!r}")
        if not isinstance(self.nth, int) or isinstance(self.nth, bool) or self.nth < 1:
            raise VisualTargetError("invalid_nth", "nth must be a one-based positive integer")
        if mode == "regex":
            _validate_safe_regex(str(self.text))
        object.__setattr__(self, "mode", mode)


@dataclass(frozen=True)
class ResolvedTarget:
    source: str
    point: Mapping[str, Any]
    frame: Mapping[str, float]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "point": dict(self.point),
            "frame": dict(self.frame),
            **dict(self.metadata),
        }


def _finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise VisualTargetError("invalid_geometry", f"{name} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise VisualTargetError("invalid_geometry", f"{name} must be a finite number") from error
    if not math.isfinite(number):
        raise VisualTargetError("invalid_geometry", f"{name} must be a finite number")
    return number


def _frame(value: Mapping[str, Any] | None, *, name: str = "frame") -> dict[str, float]:
    if not isinstance(value, Mapping):
        raise VisualTargetError("invalid_geometry", f"{name} must be an object")
    result = {
        "x": _finite_number(value.get("x"), f"{name}.x"),
        "y": _finite_number(value.get("y"), f"{name}.y"),
        "width": _finite_number(value.get("width"), f"{name}.width"),
        "height": _finite_number(value.get("height"), f"{name}.height"),
    }
    if result["width"] <= 0 or result["height"] <= 0:
        raise VisualTargetError("invalid_geometry", f"{name} must have positive width and height")
    return result


def _sequence_pair(value: Any, name: str) -> tuple[float, float]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) < 2:
        raise VisualTargetError("invalid_geometry", f"{name} must contain two numbers")
    return _finite_number(value[0], f"{name}[0]"), _finite_number(value[1], f"{name}[1]")


def _screenshot(snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
    screenshot = snapshot.get("screenshot")
    if not isinstance(screenshot, Mapping):
        raise VisualTargetError("invalid_snapshot", "snapshot.screenshot is required")
    return screenshot


def _screenshot_size(snapshot: Mapping[str, Any]) -> tuple[float, float]:
    screenshot = _screenshot(snapshot)
    width = _finite_number(screenshot.get("width"), "screenshot.width")
    height = _finite_number(screenshot.get("height"), "screenshot.height")
    if width <= 0 or height <= 0:
        raise VisualTargetError("invalid_geometry", "screenshot dimensions must be positive")
    return width, height


def _first_string(mapping: Mapping[str, Any], names: Iterable[str]) -> str:
    for name in names:
        value = mapping.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _screenshot_identity(
    snapshot: Mapping[str, Any],
    *,
    screenshot_id: str | None = None,
    screenshot_hash: str | None = None,
) -> tuple[str, str]:
    screenshot = _screenshot(snapshot)
    identifier = str(screenshot_id or "").strip() or _first_string(
        screenshot, ("id", "screenshotId", "captureId")
    ) or _first_string(snapshot, ("screenshotId", "captureId"))
    digest = str(screenshot_hash or "").strip() or _first_string(
        screenshot, ("sha256", "hash", "screenshotHash", "contentHash")
    ) or _first_string(snapshot, ("screenshotHash", "contentHash"))
    raw = screenshot.get("bytes", screenshot.get("data"))
    if not digest and isinstance(raw, (bytes, bytearray, memoryview)):
        digest = hashlib.sha256(bytes(raw)).hexdigest()
    if digest.lower().startswith("sha256:"):
        digest = digest.split(":", 1)[1]
    if not identifier or not digest:
        raise VisualTargetError(
            "unbound_screenshot",
            "both screenshot id and content hash are required for visual targeting",
            hasScreenshotId=bool(identifier),
            hasScreenshotHash=bool(digest),
        )
    return identifier, digest.lower()


def _window_identity(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    window = snapshot.get("window")
    if not isinstance(window, Mapping):
        raise VisualTargetError("invalid_snapshot", "snapshot.window is required")
    address = _first_string(window, ("address",))
    if not address:
        target = str(snapshot.get("target") or "")
        address = target.split(":", 1)[1] if target.startswith("address:") else target
    if not address:
        raise VisualTargetError("invalid_snapshot", "window address is required")
    pid_value = window.get("pid", snapshot.get("app", {}).get("pid") if isinstance(snapshot.get("app"), Mapping) else None)
    pid = None if pid_value in (None, "") else int(pid_value)
    return {
        "address": address.casefold(),
        "pid": pid,
        "class": _first_string(window, ("class", "initialClass")),
    }


def _geometry(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    screenshot = _screenshot(snapshot)
    window = snapshot.get("window")
    if not isinstance(window, Mapping):
        raise VisualTargetError("invalid_snapshot", "snapshot.window is required")
    width, height = _screenshot_size(snapshot)
    at_x, at_y = _sequence_pair(window.get("at"), "window.at")
    win_width, win_height = _sequence_pair(window.get("size"), "window.size")
    logical = screenshot.get("logicalBounds")
    if logical is None:
        logical_frame = {"x": at_x, "y": at_y, "width": win_width, "height": win_height}
    else:
        logical_frame = _frame(logical, name="screenshot.logicalBounds")
    return {
        "window": {"x": at_x, "y": at_y, "width": win_width, "height": win_height},
        "screenshot": {"width": width, "height": height, "logicalBounds": logical_frame},
    }


def make_snapshot_binding(
    snapshot: Mapping[str, Any],
    *,
    screenshot_id: str | None = None,
    screenshot_hash: str | None = None,
) -> dict[str, Any]:
    """Return the immutable identity envelope OCR/mark results must carry."""

    identifier, digest = _screenshot_identity(
        snapshot, screenshot_id=screenshot_id, screenshot_hash=screenshot_hash
    )
    return {
        "screenshotId": identifier,
        "screenshotHash": digest,
        "windowIdentity": _window_identity(snapshot),
        "geometry": _geometry(snapshot),
    }


def _numbers_equal(left: Any, right: Any, tolerance: float) -> bool:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return set(left) == set(right) and all(_numbers_equal(left[key], right[key], tolerance) for key in left)
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return math.isclose(float(left), float(right), abs_tol=tolerance, rel_tol=0.0)
    return left == right


def validate_snapshot_binding(
    binding: Mapping[str, Any], snapshot: Mapping[str, Any], *, geometry_tolerance: float = 0.01
) -> dict[str, Any]:
    """Fail closed when a visual result no longer describes this snapshot."""

    if not isinstance(binding, Mapping):
        raise VisualTargetError("missing_binding", "visual result is missing its snapshot binding")
    current = make_snapshot_binding(snapshot)
    for key in ("screenshotId", "screenshotHash", "windowIdentity"):
        if binding.get(key) != current[key]:
            raise StaleVisualTargetError(
                f"{key} changed since the visual result was generated",
                field=key,
                expected=binding.get(key),
                actual=current[key],
            )
    if not _numbers_equal(binding.get("geometry"), current["geometry"], geometry_tolerance):
        raise StaleVisualTargetError(
            "window or screenshot geometry changed since the visual result was generated",
            field="geometry",
            expected=binding.get("geometry"),
            actual=current["geometry"],
        )
    return current


def _region_frame(region: Mapping[str, Any], *, name: str = "OCR region") -> dict[str, float]:
    value = region.get("frame", region.get("bbox", region.get("box")))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) == 4:
        value = {"x": value[0], "y": value[1], "width": value[2], "height": value[3]}
    return _frame(value, name=name)


def _inside_screenshot(frame: Mapping[str, float], snapshot: Mapping[str, Any], *, tolerance: float = 0.01) -> bool:
    width, height = _screenshot_size(snapshot)
    return (
        frame["x"] >= -tolerance
        and frame["y"] >= -tolerance
        and frame["x"] + frame["width"] <= width + tolerance
        and frame["y"] + frame["height"] <= height + tolerance
    )


def _validate_frame(frame: Mapping[str, float], snapshot: Mapping[str, Any], name: str) -> None:
    if not _inside_screenshot(frame, snapshot):
        raise VisualTargetError("target_out_of_bounds", f"{name} is outside the bound screenshot", frame=dict(frame))


def _validate_safe_regex(pattern: str) -> None:
    """Accept a deliberately small, linear-time-oriented regex subset.

    Python's standard ``re`` engine has no timeout.  Grouping, alternation,
    lookarounds and backreferences are therefore rejected rather than letting
    untrusted locators construct nested/backtracking expressions.  Character
    classes, anchors, escaped classes and simple atom quantifiers remain useful
    for UI labels (for example ``^Save\\s+as$``).
    """

    if len(pattern) > MAX_REGEX_LENGTH:
        raise VisualTargetError(
            "unsafe_regex", f"regular expression exceeds {MAX_REGEX_LENGTH} characters"
        )
    escaped = False
    in_class = False
    unbounded_quantifiers = 0
    optional_quantifiers = 0
    previous_was_quantifier = False
    for index, character in enumerate(pattern):
        if escaped:
            if character.isdigit() or character in {"g", "k"}:
                raise VisualTargetError("unsafe_regex", "regular expression backreferences are not supported")
            escaped = False
            previous_was_quantifier = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == "[":
            in_class = True
            previous_was_quantifier = False
            continue
        if character == "]" and in_class:
            in_class = False
            previous_was_quantifier = False
            continue
        if not in_class and character in {"(", ")", "|"}:
            raise VisualTargetError(
                "unsafe_regex",
                "regular expression grouping, lookarounds, and alternation are not supported",
                offset=index,
            )
        if not in_class and character in {"{", "}"}:
            raise VisualTargetError(
                "unsafe_regex", "bounded repetition syntax is not supported", offset=index
            )
        if not in_class and character in {"*", "+", "?"}:
            if previous_was_quantifier:
                raise VisualTargetError("unsafe_regex", "stacked quantifiers are not supported", offset=index)
            if character in {"*", "+"}:
                unbounded_quantifiers += 1
                if unbounded_quantifiers > 1:
                    raise VisualTargetError(
                        "unsafe_regex",
                        "at most one unbounded quantifier is supported",
                        offset=index,
                    )
            else:
                optional_quantifiers += 1
                if optional_quantifiers > 8:
                    raise VisualTargetError(
                        "unsafe_regex", "at most eight optional quantifiers are supported", offset=index
                    )
            previous_was_quantifier = True
        elif not in_class:
            previous_was_quantifier = False


def _text_matches(candidate: str, spec: MatchSpec) -> bool:
    if len(candidate) > MAX_REGEX_CANDIDATE_LENGTH and spec.mode == "regex":
        raise VisualTargetError(
            "unsafe_regex_candidate",
            f"regex candidate exceeds {MAX_REGEX_CANDIDATE_LENGTH} characters",
        )
    left = candidate.casefold() if spec.casefold else candidate
    right = spec.text.casefold() if spec.casefold else spec.text
    if spec.mode == "exact":
        return left == right
    if spec.mode == "contains":
        return right in left
    flags = re.IGNORECASE if spec.casefold else 0
    try:
        return re.search(spec.text, candidate, flags=flags) is not None
    except re.error as error:
        raise VisualTargetError("invalid_regex", f"invalid regular expression: {error}") from error


def match_ocr_regions(
    regions: Sequence[Mapping[str, Any]],
    text: str,
    *,
    match: str = "exact",
    casefold: bool = True,
    nth: int = 1,
) -> tuple[int, Mapping[str, Any]]:
    """Return ``(original_index, region)`` for the one-based nth match."""

    if len(regions) > MAX_MATCH_CANDIDATES:
        raise VisualTargetError(
            "too_many_visual_candidates",
            f"visual match input exceeds {MAX_MATCH_CANDIDATES} candidates",
        )
    spec = MatchSpec(str(text), match, casefold, nth)
    matches = [(index, region) for index, region in enumerate(regions) if _text_matches(str(region.get("text", "")), spec)]
    if len(matches) < spec.nth:
        raise VisualTargetError(
            "visual_target_not_found",
            f"OCR text did not produce match {spec.nth}",
            text=spec.text,
            match=spec.mode,
            casefold=spec.casefold,
            nth=spec.nth,
            matchCount=len(matches),
        )
    return matches[spec.nth - 1]


def _confidence_scale(value: Any) -> str | None:
    normalized = str(value or "").strip().lower().replace(" ", "")
    if normalized in {"0-1", "0..1", "fraction", "normalized", "unit"}:
        return "0-1"
    if normalized in {"0-100", "0..100", "percent", "percentage", "%"}:
        return "0-100"
    return None


def _normalize_confidence(value: Any, *, declared_scale: str | None, name: str) -> tuple[float, str]:
    number = _finite_number(value, name)
    scale = declared_scale or ("0-100" if number > 1.0 else "0-1")
    upper = 100.0 if scale == "0-100" else 1.0
    if not 0.0 <= number <= upper:
        raise VisualTargetError(
            "invalid_ocr_result", f"{name} must be within the declared {scale} scale"
        )
    return (number / 100.0 if scale == "0-100" else number), scale


def validate_ocr_result(result: Mapping[str, Any], snapshot: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    if not isinstance(result, Mapping):
        raise VisualTargetError("invalid_ocr_result", "OCR result must be an object")
    validate_snapshot_binding(result.get("binding"), snapshot)
    regions = result.get("regions")
    if not isinstance(regions, Sequence) or isinstance(regions, (str, bytes)):
        raise VisualTargetError("invalid_ocr_result", "OCR result regions must be an array")
    raw_declared_scale = result.get("confidenceScale")
    declared_scale = _confidence_scale(raw_declared_scale)
    if raw_declared_scale not in (None, "") and declared_scale is None:
        raise VisualTargetError(
            "invalid_ocr_result",
            "OCR confidenceScale must be 0-1/normalized or 0-100/percent",
        )
    normalized_regions: list[Mapping[str, Any]] = []
    for index, region in enumerate(regions):
        if not isinstance(region, Mapping):
            raise VisualTargetError("invalid_ocr_result", f"OCR region {index} must be an object")
        if not str(region.get("text", "")):
            raise VisualTargetError("invalid_ocr_result", f"OCR region {index} has no text")
        frame = _region_frame(region, name=f"OCR region {index}")
        _validate_frame(frame, snapshot, f"OCR region {index}")
        confidence = region.get("confidence")
        if confidence is not None:
            region_scale_value = region.get("confidenceScale")
            region_scale = _confidence_scale(region_scale_value)
            if region_scale_value not in (None, "") and region_scale is None:
                raise VisualTargetError(
                    "invalid_ocr_result",
                    f"OCR region {index} confidenceScale is unsupported",
                )
            confidence_value, input_scale = _normalize_confidence(
                confidence,
                declared_scale=region_scale or declared_scale,
                name=f"OCR region {index}.confidence",
            )
            normalized_regions.append(
                {
                    **dict(region),
                    "confidence": confidence_value,
                    "confidenceScale": "0-1",
                    "confidenceInputScale": input_scale,
                }
            )
        else:
            normalized_regions.append(dict(region))
    return normalized_regions


def _center(frame: Mapping[str, float]) -> dict[str, Any]:
    return {
        "x": frame["x"] + frame["width"] / 2.0,
        "y": frame["y"] + frame["height"] / 2.0,
        "coordinateSpace": "screenshot",
    }


def resolve_ocr_target(
    snapshot: Mapping[str, Any],
    result: Mapping[str, Any],
    text: str,
    *,
    match: str = "exact",
    casefold: bool = True,
    nth: int = 1,
) -> ResolvedTarget:
    regions = validate_ocr_result(result, snapshot)
    index, region = match_ocr_regions(regions, text, match=match, casefold=casefold, nth=nth)
    frame = _region_frame(region)
    return ResolvedTarget(
        "ocr",
        _center(frame),
        frame,
        {"ocrIndex": index, "text": str(region.get("text")), "confidence": region.get("confidence")},
    )


def validate_mark_set(mark_set: Mapping[str, Any], snapshot: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if not isinstance(mark_set, Mapping):
        raise VisualTargetError("invalid_mark_set", "mark set must be an object")
    validate_snapshot_binding(mark_set.get("binding"), snapshot)
    marks = mark_set.get("marks")
    if not isinstance(marks, Sequence) or isinstance(marks, (str, bytes)):
        raise VisualTargetError("invalid_mark_set", "mark set marks must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    for index, mark in enumerate(marks):
        if not isinstance(mark, Mapping):
            raise VisualTargetError("invalid_mark_set", f"mark {index} must be an object")
        mark_id = str(mark.get("id", mark.get("markId", ""))).strip()
        if not mark_id:
            raise VisualTargetError("invalid_mark_set", f"mark {index} has no id")
        if mark_id in result:
            raise VisualTargetError("duplicate_mark_id", f"duplicate mark id: {mark_id}")
        source = str(mark.get("source", "")).strip().lower()
        if source not in {"element", "ocr", "point"}:
            raise VisualTargetError("invalid_mark_set", f"mark {mark_id} has unsupported source {source!r}")
        frame = _region_frame(mark, name=f"mark {mark_id}")
        _validate_frame(frame, snapshot, f"mark {mark_id}")
        if source == "element" and mark.get("elementIndex") is None:
            raise VisualTargetError("invalid_mark_set", f"element mark {mark_id} has no elementIndex")
        if source == "ocr" and mark.get("ocrIndex") is None:
            raise VisualTargetError("invalid_mark_set", f"OCR mark {mark_id} has no ocrIndex")
        result[mark_id] = mark
    return result


def _element_by_index(snapshot: Mapping[str, Any], index: Any) -> Mapping[str, Any]:
    wanted = str(index)
    for element in snapshot.get("elements", []):
        if isinstance(element, Mapping) and str(element.get("index")) == wanted:
            return element
    raise VisualTargetError("element_not_found", f"element index {wanted!r} was not found")


def _element_frame(element: Mapping[str, Any], snapshot: Mapping[str, Any]) -> dict[str, float]:
    frame = _frame(element.get("frame"), name="element frame")
    _validate_frame(frame, snapshot, "element frame")
    return frame


def resolve_mark_target(
    snapshot: Mapping[str, Any], mark_set: Mapping[str, Any], mark_id: str | int
) -> ResolvedTarget:
    marks = validate_mark_set(mark_set, snapshot)
    wanted = str(mark_id)
    if wanted not in marks:
        raise VisualTargetError("mark_not_found", f"mark id {wanted!r} was not found")
    mark = marks[wanted]
    source = str(mark.get("source")).lower()
    frame = _region_frame(mark, name=f"mark {wanted}")
    metadata: dict[str, Any] = {"markId": wanted, "markSource": source}
    if source == "element":
        element = _element_by_index(snapshot, mark.get("elementIndex"))
        current_frame = _element_frame(element, snapshot)
        if not _numbers_equal(frame, current_frame, 0.01):
            raise StaleVisualTargetError(
                "marked element geometry changed", field="mark.frame", expected=frame, actual=current_frame
            )
        metadata.update({"elementIndex": element.get("index"), "element": element})
    elif source == "ocr":
        metadata["ocrIndex"] = mark.get("ocrIndex")
    return ResolvedTarget("mark", _center(frame), frame, metadata)


def resolve_click_target(
    snapshot: Mapping[str, Any],
    locator: Mapping[str, Any],
    *,
    ocr_result: Mapping[str, Any] | None = None,
    mark_set: Mapping[str, Any] | None = None,
) -> ResolvedTarget:
    """Resolve an OCR or mark click locator without dispatching input."""

    if not isinstance(locator, Mapping):
        raise VisualTargetError("invalid_locator", "click locator must be an object")
    if "mark_id" in locator or "markId" in locator:
        if mark_set is None:
            raise VisualTargetError("missing_mark_set", "mark click requires a screenshot-bound mark set")
        return resolve_mark_target(snapshot, mark_set, locator.get("mark_id", locator.get("markId")))
    ocr = locator.get("ocr", locator)
    if isinstance(ocr, Mapping) and "text" in ocr:
        if ocr_result is None:
            raise VisualTargetError("missing_ocr_result", "OCR click requires a screenshot-bound OCR result")
        return resolve_ocr_target(
            snapshot,
            ocr_result,
            str(ocr.get("text", "")),
            match=str(ocr.get("match", "exact")),
            casefold=bool(ocr.get("casefold", True)),
            nth=ocr.get("nth", 1),
        )
    raise VisualTargetError("invalid_locator", "click locator must contain OCR text or mark_id")


def _element_text(element: Mapping[str, Any], field: str) -> str:
    if field == "name":
        return str(element.get("name", ""))
    return str(element.get("text", element.get("value", "")))


def _match_element(
    snapshot: Mapping[str, Any], field: str, value: str, *, match: str, casefold: bool, nth: int
) -> Mapping[str, Any]:
    elements = snapshot.get("elements", [])
    if not isinstance(elements, Sequence) or isinstance(elements, (str, bytes)):
        raise VisualTargetError("invalid_snapshot", "snapshot elements must be an array")
    if len(elements) > MAX_MATCH_CANDIDATES:
        raise VisualTargetError(
            "too_many_visual_candidates",
            f"visual match input exceeds {MAX_MATCH_CANDIDATES} candidates",
        )
    spec = MatchSpec(value, match, casefold, nth)
    matches = [
        element
        for element in elements
        if isinstance(element, Mapping) and _text_matches(_element_text(element, field), spec)
    ]
    if len(matches) < nth:
        raise VisualTargetError(
            "element_not_found", f"accessible {field} did not produce match {nth}", matchCount=len(matches)
        )
    return matches[nth - 1]


def element_is_editable(element: Mapping[str, Any]) -> bool:
    if element.get("editable") is True:
        return True
    states = element.get("states", element.get("state", []))
    if isinstance(states, str):
        states = re.split(r"[\s,|]+", states)
    if isinstance(states, Sequence) and any(str(state).casefold() == "editable" for state in states):
        return True
    attributes = element.get("attributes")
    if isinstance(attributes, Mapping) and str(attributes.get("editable", "")).casefold() in {"1", "true", "yes"}:
        return True
    role = str(element.get("controlType", element.get("role", ""))).strip().casefold()
    return role in {
        "edit",
        "entry",
        "editable text",
        "password text",
        "search box",
        "spin button",
        "text box",
        "text field",
    }


def _overlap_area(left: Mapping[str, float], right: Mapping[str, float]) -> float:
    width = max(0.0, min(left["x"] + left["width"], right["x"] + right["width"]) - max(left["x"], right["x"]))
    height = max(0.0, min(left["y"] + left["height"], right["y"] + right["height"]) - max(left["y"], right["y"]))
    return width * height


def _editable_element_at(snapshot: Mapping[str, Any], frame: Mapping[str, float]) -> Mapping[str, Any] | None:
    candidates: list[tuple[float, Mapping[str, Any]]] = []
    for element in snapshot.get("elements", []):
        if not isinstance(element, Mapping) or not element_is_editable(element):
            continue
        try:
            element_frame = _element_frame(element, snapshot)
        except VisualTargetError:
            continue
        overlap = _overlap_area(frame, element_frame)
        center = _center(frame)
        contains_center = (
            element_frame["x"] <= center["x"] <= element_frame["x"] + element_frame["width"]
            and element_frame["y"] <= center["y"] <= element_frame["y"] + element_frame["height"]
        )
        if overlap > 0 or contains_center:
            candidates.append((overlap + (1e12 if contains_center else 0), element))
    return max(candidates, key=lambda pair: pair[0])[1] if candidates else None


def resolve_type_into_target(
    snapshot: Mapping[str, Any],
    locator: Mapping[str, Any],
    *,
    ocr_result: Mapping[str, Any] | None = None,
    mark_set: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve a type target and prove it is editable before focus/input.

    The returned contract deliberately says that focus and a pre-input state
    refresh are required.  The caller must click/focus, refresh, and then type;
    this pure module does not perform those stateful operations.
    """

    if not isinstance(locator, Mapping):
        raise VisualTargetError("invalid_locator", "type_into locator must be an object")
    element: Mapping[str, Any] | None = None
    source = ""
    visual: ResolvedTarget | None = None
    if "element_index" in locator or "elementIndex" in locator:
        element = _element_by_index(snapshot, locator.get("element_index", locator.get("elementIndex")))
        source = "element_index"
    elif "accessible_name" in locator or "name" in locator:
        value = str(locator.get("accessible_name", locator.get("name", "")))
        element = _match_element(
            snapshot,
            "name",
            value,
            match=str(locator.get("match", "exact")),
            casefold=bool(locator.get("casefold", True)),
            nth=locator.get("nth", 1),
        )
        source = "accessible_name"
    elif "accessible_text" in locator or ("text" in locator and "ocr" not in locator):
        value = str(locator.get("accessible_text", locator.get("text", "")))
        element = _match_element(
            snapshot,
            "text",
            value,
            match=str(locator.get("match", "exact")),
            casefold=bool(locator.get("casefold", True)),
            nth=locator.get("nth", 1),
        )
        source = "accessible_text"
    elif "mark_id" in locator or "markId" in locator:
        if mark_set is None:
            raise VisualTargetError("missing_mark_set", "mark target requires a screenshot-bound mark set")
        visual = resolve_mark_target(snapshot, mark_set, locator.get("mark_id", locator.get("markId")))
        possible = visual.metadata.get("element")
        element = possible if isinstance(possible, Mapping) else _editable_element_at(snapshot, visual.frame)
        source = "mark"
    elif "ocr" in locator:
        ocr = locator.get("ocr")
        if not isinstance(ocr, Mapping) or "text" not in ocr:
            raise VisualTargetError("invalid_locator", "OCR type target requires text")
        if ocr_result is None:
            raise VisualTargetError("missing_ocr_result", "OCR type target requires a screenshot-bound OCR result")
        visual = resolve_ocr_target(
            snapshot,
            ocr_result,
            str(ocr.get("text", "")),
            match=str(ocr.get("match", "exact")),
            casefold=bool(ocr.get("casefold", True)),
            nth=ocr.get("nth", 1),
        )
        element = _editable_element_at(snapshot, visual.frame)
        source = "ocr"
    else:
        raise VisualTargetError(
            "invalid_locator", "type_into locator requires element_index, accessible name/text, OCR, or mark"
        )

    if element is None or not element_is_editable(element):
        raise VisualTargetError(
            "target_not_editable",
            "type_into target could not be verified as an editable accessibility element",
            source=source,
        )
    frame = _element_frame(element, snapshot)
    return {
        "source": source,
        "elementIndex": element.get("index"),
        "element": element,
        "frame": frame,
        "point": _center(frame),
        "editableVerified": True,
        "focusRequired": True,
        "clickRequired": True,
        "refreshBeforeInputRequired": True,
        "visualTarget": visual.to_dict() if visual is not None else None,
    }
