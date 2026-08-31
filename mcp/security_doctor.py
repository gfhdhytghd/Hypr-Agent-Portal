"""Security-readiness diagnostics for hypr-agent-portal.

The module deliberately has no dependency on the MCP server and performs no
subprocess calls.  Runtime-specific facts (most notably panic-dispatcher and
lock-screen state) can be supplied through callbacks, which keeps the doctor
safe to call and straightforward to unit test.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any


ENV_PREFIX = "HYPR_AGENT_PORTAL_"

_ENV_NAMES: dict[str, tuple[str, ...]] = {
    "readonly": ("READONLY", "READ_ONLY"),
    "dry_run": ("DRY_RUN", "DRYRUN"),
    "confinement": ("CONFINEMENT", "CONFINE"),
    "app_policy": ("APP_POLICY", "APP_POLICY_PATH"),
    "clipboard_policy": ("CLIPBOARD_POLICY",),
    "clipboard_read": ("CLIPBOARD_READ", "ALLOW_CLIPBOARD_READ"),
    "privacy_policy": ("PRIVACY_POLICY", "PRIVACY_POLICY_PATH", "PRIVACY_EXCLUDE"),
    "audit_enabled": ("AUDIT", "AUDIT_ENABLED"),
    "audit_path": ("AUDIT_PATH", "AUDIT_LOG", "AUDIT_LOG_PATH"),
    "lockscreen_protection": ("LOCKSCREEN_PROTECTION", "LOCKSCREEN_GUARD"),
    "mutation_lease_path": ("MUTATION_LEASE_PATH", "LEASE_PATH"),
    "panic_enabled": ("PANIC_ENABLED", "PANIC_DISPATCHER"),
}

_CONFIG_NAMES: dict[str, tuple[str, ...]] = {
    "readonly": ("readonly", "read_only", "security.readonly", "security.read_only"),
    "dry_run": ("dry_run", "dryrun", "security.dry_run"),
    "confinement": ("confinement", "confine", "security.confinement"),
    "app_policy": ("app_policy", "app_policy_path", "security.app_policy"),
    "clipboard_policy": ("clipboard_policy", "security.clipboard_policy"),
    "clipboard_read": ("clipboard_read", "allow_clipboard_read", "security.clipboard_read"),
    "privacy_policy": ("privacy_policy", "privacy_policy_path", "privacy_exclude", "security.privacy_policy"),
    "audit_enabled": ("audit", "audit_enabled", "security.audit", "security.audit_enabled"),
    "audit_path": ("audit_path", "audit_log", "audit_log_path", "security.audit_path"),
    "lockscreen_protection": ("lockscreen_protection", "lockscreen_guard", "security.lockscreen_protection"),
    "mutation_lease_path": ("mutation_lease_path", "lease_path", "security.mutation_lease_path"),
    "panic_enabled": ("panic_enabled", "panic_dispatcher", "security.panic_enabled"),
}

_TRUE = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSE = frozenset({"0", "false", "no", "off", "disabled", "none", ""})

PathProbe = Callable[[Path], bool | tuple[bool, str | None] | Mapping[str, Any]]
BooleanProbe = Callable[[], bool | tuple[bool, str | None] | Mapping[str, Any]]


def _nested_get(config: Mapping[str, Any], dotted_name: str) -> tuple[bool, Any]:
    if dotted_name in config:
        return True, config[dotted_name]
    current: Any = config
    for part in dotted_name.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _resolve(
    name: str,
    config: Mapping[str, Any],
    environ: Mapping[str, str],
) -> tuple[Any, str | None]:
    for candidate in _CONFIG_NAMES[name]:
        found, value = _nested_get(config, candidate)
        if found:
            return value, f"config:{candidate}"
    for suffix in _ENV_NAMES[name]:
        variable = ENV_PREFIX + suffix
        if variable in environ:
            return environ[variable], f"env:{variable}"
    return None, None


def _boolean(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _TRUE:
            return True
        if normalized in _FALSE:
            return False
    return default


def _configured(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in _FALSE
    if isinstance(value, Mapping) or isinstance(value, Sequence):
        return bool(value)
    return True


def _probe_value(value: Any, *, default_detail: str) -> tuple[bool, str]:
    if isinstance(value, Mapping):
        available = _boolean(value.get("available", value.get("ok", value.get("active"))))
        detail = value.get("detail") or value.get("reason") or default_detail
        return available, str(detail)
    if isinstance(value, tuple):
        available = _boolean(value[0] if value else False)
        detail = value[1] if len(value) > 1 and value[1] else default_detail
        return available, str(detail)
    return _boolean(value), default_detail


def _default_path_probe(path: Path) -> tuple[bool, str]:
    """Check likely writability without creating or modifying any file."""
    expanded = path.expanduser()
    if expanded.exists():
        if expanded.is_dir():
            return os.access(expanded, os.W_OK | os.X_OK), "existing directory"
        return os.access(expanded, os.W_OK), "existing file"

    parent = expanded.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    ok = parent.is_dir() and os.access(parent, os.W_OK | os.X_OK)
    return ok, f"nearest existing parent: {parent}"


def _path_status(path: Path, probe: PathProbe | None) -> tuple[bool, str]:
    try:
        result = (probe or _default_path_probe)(path)
        return _probe_value(result, default_detail=str(path.expanduser()))
    except Exception as exc:  # Diagnostics should report a broken probe, not fail.
        return False, f"probe failed: {type(exc).__name__}: {exc}"


def _lockscreen_status(
    environ: Mapping[str, str],
    probe: BooleanProbe | None,
    indicators: Sequence[str] | None,
) -> tuple[bool, str]:
    if probe is not None:
        try:
            return _probe_value(probe(), default_detail="lock-screen probe")
        except Exception as exc:
            return False, f"probe failed: {type(exc).__name__}: {exc}"

    locked_variables = (
        "HYPR_AGENT_PORTAL_SESSION_LOCKED",
        "XDG_SESSION_LOCKED",
        "SESSION_LOCKED",
    )
    active = [name for name in locked_variables if _boolean(environ.get(name))]
    supplied = [str(item) for item in (indicators or ()) if str(item).strip()]
    detected = active + supplied
    return bool(detected), ", ".join(detected) if detected else "no lock-screen indicator supplied"


def security_readiness_diagnostics(
    config: Mapping[str, Any] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    lockscreen_probe: BooleanProbe | None = None,
    lockscreen_indicators: Sequence[str] | None = None,
    panic_probe: BooleanProbe | None = None,
    path_probe: PathProbe | None = None,
) -> dict[str, Any]:
    """Return a structured, side-effect-free security readiness report.

    ``config`` wins over environment variables.  Callers that already know the
    compositor's lock state may provide ``lockscreen_probe`` or simple indicator
    strings.  ``panic_probe`` is intentionally injected: this module never runs
    a dispatcher command merely to determine whether one exists.
    """
    supplied_config: Mapping[str, Any] = config or {}
    supplied_environ: Mapping[str, str] = environ if environ is not None else os.environ

    resolved: dict[str, Any] = {}
    sources: dict[str, str | None] = {}
    for name in _CONFIG_NAMES:
        resolved[name], sources[name] = _resolve(name, supplied_config, supplied_environ)

    readonly = _boolean(resolved["readonly"])
    dry_run = _boolean(resolved["dry_run"])
    mutation_capable = not readonly and not dry_run
    audit_enabled = _boolean(resolved["audit_enabled"], _configured(resolved["audit_path"]))
    lockscreen_protection = _boolean(resolved["lockscreen_protection"])
    panic_enabled = _boolean(resolved["panic_enabled"], panic_probe is not None)

    checks: list[dict[str, Any]] = []
    blockers: list[str] = []
    warnings: list[str] = []
    recommendations: list[str] = []

    def add(
        check_id: str,
        status: str,
        summary: str,
        *,
        source: str | None = None,
        details: Mapping[str, Any] | None = None,
        recommendation: str | None = None,
    ) -> None:
        item: dict[str, Any] = {"id": check_id, "status": status, "summary": summary}
        if source:
            item["source"] = source
        if details:
            item["details"] = dict(details)
        if recommendation:
            item["recommendation"] = recommendation
            if recommendation not in recommendations:
                recommendations.append(recommendation)
        checks.append(item)
        if status == "blocker":
            blockers.append(summary)
        elif status == "warning":
            warnings.append(summary)

    add(
        "readonly",
        "pass" if readonly else "info",
        "read-only mode is enabled" if readonly else "mutating tools may be exposed",
        source=sources["readonly"],
        details={"enabled": readonly},
    )
    add(
        "dry_run",
        "pass" if dry_run else "info",
        "dry-run mode is enabled" if dry_run else "actions are not globally in dry-run mode",
        source=sources["dry_run"],
        details={"enabled": dry_run},
    )

    confinement = _configured(resolved["confinement"])
    add(
        "confinement",
        "pass" if confinement or not mutation_capable else "blocker",
        "operation confinement is configured"
        if confinement
        else ("mutation is enabled without operation confinement" if mutation_capable else "confinement is not required in non-mutating mode"),
        source=sources["confinement"],
        details={"configured": confinement, "mutationCapable": mutation_capable},
        recommendation="Configure allowed window addresses, application classes, or workspaces before enabling mutation."
        if mutation_capable and not confinement
        else None,
    )

    app_policy = _configured(resolved["app_policy"])
    add(
        "app_policy",
        "pass" if app_policy else ("warning" if mutation_capable else "info"),
        "per-application policy is configured"
        if app_policy
        else "no per-application authorization policy is configured",
        source=sources["app_policy"],
        details={"configured": app_policy},
        recommendation="Set an explicit view/click/full-control policy for application classes."
        if mutation_capable and not app_policy
        else None,
    )

    clipboard_policy = _configured(resolved["clipboard_policy"])
    clipboard_read = _boolean(resolved["clipboard_read"])
    add(
        "clipboard",
        "pass" if clipboard_policy or not mutation_capable else "warning",
        "clipboard permissions are explicitly configured"
        if clipboard_policy
        else "clipboard permissions use implicit defaults",
        source=sources["clipboard_policy"] or sources["clipboard_read"],
        details={"configured": clipboard_policy, "readEnabled": clipboard_read},
        recommendation="Configure clipboard read, write, text, image, and file permissions explicitly."
        if mutation_capable and not clipboard_policy
        else None,
    )

    privacy_policy = _configured(resolved["privacy_policy"])
    add(
        "privacy",
        "pass" if privacy_policy else "warning",
        "privacy exclusions are configured" if privacy_policy else "no privacy-window exclusion policy is configured",
        source=sources["privacy_policy"],
        details={"configured": privacy_policy},
        recommendation="Exclude password managers, authentication dialogs, terminals, and other sensitive app classes."
        if not privacy_policy
        else None,
    )

    locked, lock_detail = _lockscreen_status(supplied_environ, lockscreen_probe, lockscreen_indicators)
    lock_status = "pass"
    lock_summary = "lock-screen protection is configured"
    if locked and mutation_capable and not lockscreen_protection:
        lock_status = "blocker"
        lock_summary = "a lock-screen indicator is active but lock-screen protection is disabled"
    elif not lockscreen_protection:
        lock_status = "warning" if mutation_capable else "info"
        lock_summary = "lock-screen protection is not configured"
    add(
        "lockscreen",
        lock_status,
        lock_summary,
        source=sources["lockscreen_protection"],
        details={"protectionEnabled": lockscreen_protection, "locked": locked, "indicator": lock_detail},
        recommendation="Enable the lock-screen guard so screenshot and input tools fail closed while locked."
        if not lockscreen_protection
        else None,
    )

    lease_value = resolved["mutation_lease_path"]
    lease_path = Path(str(lease_value)).expanduser() if _configured(lease_value) else None
    lease_ok, lease_detail = _path_status(lease_path, path_probe) if lease_path else (False, "not configured")
    add(
        "mutation_lease",
        "pass" if (lease_path and lease_ok) or not mutation_capable else "blocker",
        "mutation lease path is usable"
        if lease_path and lease_ok
        else ("mutation is enabled without a usable lease path" if mutation_capable else "mutation lease is not required in non-mutating mode"),
        source=sources["mutation_lease_path"],
        details={"configured": bool(lease_path), "path": str(lease_path) if lease_path else None, "writable": lease_ok, "probe": lease_detail},
        recommendation="Configure a mutation lease path in a private, writable runtime directory."
        if mutation_capable and (not lease_path or not lease_ok)
        else None,
    )

    audit_value = resolved["audit_path"]
    audit_path = Path(str(audit_value)).expanduser() if _configured(audit_value) else None
    audit_ok, audit_detail = _path_status(audit_path, path_probe) if audit_path else (False, "not configured")
    if audit_enabled and audit_path and audit_ok:
        audit_status, audit_summary = "pass", "audit logging has a usable destination"
    elif audit_enabled:
        audit_status, audit_summary = "blocker", "audit logging is enabled without a usable destination"
    else:
        audit_status, audit_summary = ("warning", "audit logging is disabled") if mutation_capable else ("info", "audit logging is disabled")
    add(
        "audit",
        audit_status,
        audit_summary,
        source=sources["audit_enabled"] or sources["audit_path"],
        details={"enabled": audit_enabled, "path": str(audit_path) if audit_path else None, "writable": audit_ok, "probe": audit_detail},
        recommendation="Enable redacted audit logging to a private, writable destination."
        if not audit_enabled or not audit_ok
        else None,
    )

    panic_available = False
    panic_detail = "no panic-dispatcher probe supplied"
    if panic_probe is not None:
        try:
            panic_available, panic_detail = _probe_value(panic_probe(), default_detail="panic-dispatcher probe")
        except Exception as exc:
            panic_detail = f"probe failed: {type(exc).__name__}: {exc}"
    if not mutation_capable:
        panic_status, panic_summary = "pass", "panic dispatcher is not required in non-mutating mode"
    elif panic_enabled and panic_available:
        panic_status, panic_summary = "pass", "panic dispatcher is available"
    else:
        panic_status, panic_summary = "blocker", "mutation is enabled without an available panic dispatcher"
    add(
        "panic_dispatcher",
        panic_status,
        panic_summary,
        source=sources["panic_enabled"],
        details={"enabled": panic_enabled, "available": panic_available, "probe": panic_detail},
        recommendation="Register an emergency-stop dispatcher and inject a health probe for it."
        if mutation_capable and not (panic_enabled and panic_available)
        else None,
    )

    passed = sum(item["status"] == "pass" for item in checks)
    evaluated = sum(item["status"] in {"pass", "warning", "blocker"} for item in checks)
    return {
        "schemaVersion": 1,
        "ready": not blockers,
        "mode": "readonly" if readonly else ("dry-run" if dry_run else "mutation"),
        "summary": {
            "checks": len(checks),
            "passed": passed,
            "blockers": len(blockers),
            "warnings": len(warnings),
            "readinessPercent": round(100 * passed / evaluated) if evaluated else 100,
        },
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "recommendations": recommendations,
    }


def run_security_doctor(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Compatibility-friendly public alias for the readiness diagnostic."""
    return security_readiness_diagnostics(*args, **kwargs)


__all__ = ["ENV_PREFIX", "run_security_doctor", "security_readiness_diagnostics"]
