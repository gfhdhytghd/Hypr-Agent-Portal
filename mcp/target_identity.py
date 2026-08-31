"""Stable Hyprland window selectors for policy-to-native execution binding."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


_QUALIFIED_ADDRESS_RE = re.compile(
    r"^(?P<address>address:0x[0-9a-fA-F]+)@pid=(?P<pid>[1-9][0-9]*)@start=(?P<start>[1-9][0-9]*)$"
)
_PLAIN_ADDRESS_RE = re.compile(r"^address:0x[0-9a-fA-F]+$")


@dataclass(frozen=True)
class QualifiedTarget:
    selector: str
    pid: str = ""
    process_start_time: str = ""

    @property
    def qualified(self) -> bool:
        return bool(self.pid and self.process_start_time)


def parse_target(value: Any) -> QualifiedTarget:
    target = str(value or "").strip()
    match = _QUALIFIED_ADDRESS_RE.fullmatch(target)
    if match:
        return QualifiedTarget(
            selector=match.group("address").lower(),
            pid=match.group("pid"),
            process_start_time=match.group("start"),
        )
    if target.startswith("address:") and "@" in target:
        raise ValueError("malformed qualified window selector")
    return QualifiedTarget(selector=target)


def strip_target_qualifier(value: Any) -> str:
    return parse_target(value).selector


def qualify_address(address: Any, pid: Any, process_start_time: Any) -> str:
    selector = str(address or "").strip()
    if not selector.startswith("address:"):
        selector = f"address:{selector}"
    if not _PLAIN_ADDRESS_RE.fullmatch(selector):
        raise ValueError("qualified target requires an address:0x... selector")
    pid_text = str(pid or "").strip()
    start_text = str(process_start_time or "").strip()
    if not pid_text.isdigit() or int(pid_text) <= 0:
        raise ValueError("qualified target requires a positive pid")
    if not start_text.isdigit() or int(start_text) <= 0:
        raise ValueError("qualified target requires /proc process start time")
    return f"{selector.lower()}@pid={pid_text}@start={start_text}"


def qualify_window(window: Mapping[str, Any], *, process_start_time: str = "") -> str:
    start = process_start_time or next(
        (
            str(window.get(key))
            for key in ("processStartTime", "processStarttime", "process_start_time", "pidStartTime", "starttime")
            if window.get(key) not in (None, "")
        ),
        "",
    )
    return qualify_address(window.get("address"), window.get("pid"), start)
