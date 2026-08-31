"""Safe, policy-preserving action sequence orchestration.

This module intentionally knows nothing about Hyprland, MCP transports, audit
journals, or mutation leases.  A sequence never acquires a lease around the
whole batch.  Instead, every step is sent through ``executor`` independently so
the server can reuse its normal single-tool policy, confirmation, per-call
process lease, and audit path.

``policy_probe`` is optional and must be non-consuming.  In particular, it must
not redeem a one-time confirmation token.  Final authorization belongs in the
single-step executor.
"""

from __future__ import annotations

import threading
import uuid
import copy
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


class SequenceDefinitionError(ValueError):
    """The requested sequence is malformed or unsafe to execute."""


class SequenceInterrupted(RuntimeError):
    """Base class for cooperative sequence interruption."""

    reason = "interrupted"


class SequenceCancelled(SequenceInterrupted):
    reason = "cancelled"


class SequencePanicked(SequenceInterrupted):
    reason = "panic"


@dataclass(frozen=True)
class ActionStep:
    """A normalized action and its exact single-tool arguments."""

    action: str
    arguments: Mapping[str, Any]
    step_id: str


class CancellationToken:
    """Thread-safe cooperative cancellation shared with a running sequence."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason = "cancel requested"

    def cancel(self, reason: str = "cancel requested") -> None:
        self._reason = str(reason or "cancel requested")
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason


@dataclass(frozen=True)
class StepContext:
    """Context available to policy probes and cooperative executors."""

    sequence_id: str
    step_index: int
    step_count: int
    dry_run: bool
    cancellation: CancellationToken
    panic_probe: Callable[[], bool]

    def checkpoint(self) -> None:
        """Raise promptly when panic or cancellation has been requested."""

        try:
            panic_active = bool(self.panic_probe())
        except Exception as exc:
            raise SequencePanicked(f"panic status is unavailable: {type(exc).__name__}: {exc}") from exc
        if panic_active:
            raise SequencePanicked("panic is active")
        if self.cancellation.cancelled:
            raise SequenceCancelled(self.cancellation.reason)


StepExecutor = Callable[[ActionStep, StepContext], Any]
PolicyProbe = Callable[[ActionStep, StepContext], Mapping[str, Any] | bool | None]


_SEQUENCE_ACTIONS = frozenset(
    {
        "sequence",
        "batch",
        "action_sequence",
        "action-sequence",
        "run_sequence",
        "run-sequence",
    }
)


def _normalize_steps(steps: Sequence[Mapping[str, Any]], max_steps: int) -> list[ActionStep]:
    if isinstance(steps, (str, bytes)) or not isinstance(steps, Sequence):
        raise SequenceDefinitionError("steps must be an array of action objects")
    if not steps:
        raise SequenceDefinitionError("steps must not be empty")
    if len(steps) > max_steps:
        raise SequenceDefinitionError(f"sequence exceeds the {max_steps}-step limit")

    normalized: list[ActionStep] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(steps):
        if not isinstance(raw, Mapping):
            raise SequenceDefinitionError(f"step {index} must be an object")
        action = str(raw.get("action") or raw.get("tool") or "").strip()
        if not action:
            raise SequenceDefinitionError(f"step {index} has no action")
        if action.casefold().replace(" ", "_") in _SEQUENCE_ACTIONS:
            raise SequenceDefinitionError(f"step {index} cannot recursively invoke a sequence")
        arguments = raw.get("arguments", raw.get("args", {}))
        if not isinstance(arguments, Mapping):
            raise SequenceDefinitionError(f"step {index} arguments must be an object")
        if action.casefold() == "computer":
            nested_action = str(arguments.get("action") or "").strip().casefold().replace(" ", "_")
            if nested_action in _SEQUENCE_ACTIONS:
                raise SequenceDefinitionError(f"step {index} cannot recursively invoke a computer sequence")
        step_id = str(raw.get("id") or f"step-{index + 1}").strip()
        if not step_id:
            raise SequenceDefinitionError(f"step {index} id must not be empty")
        if step_id in seen_ids:
            raise SequenceDefinitionError(f"duplicate step id: {step_id}")
        seen_ids.add(step_id)
        # Copy the mapping so later caller mutation cannot change the authorized
        # intent between policy evaluation and execution.
        normalized.append(ActionStep(action=action, arguments=copy.deepcopy(dict(arguments)), step_id=step_id))
    return normalized


def _policy_disposition(value: Mapping[str, Any] | bool | None) -> tuple[bool, bool]:
    """Return ``(allowed, execute)`` from a non-consuming policy preview."""

    if value is None or value is True:
        return True, True
    if value is False:
        return False, False
    security = value.get("security")
    decision = security if isinstance(security, Mapping) else value
    allowed = bool(decision.get("allowed", not bool(value.get("isError", False))))
    execute = bool(decision.get("execute", allowed)) if allowed else False
    return allowed, execute


def _result_is_error(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if bool(value.get("isError", False)):
        return True
    structured = value.get("structuredContent")
    return isinstance(structured, Mapping) and bool(structured.get("isError", False))


def _step_record(step: ActionStep, index: int, status: str, **extra: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "index": index,
        "id": step.step_id,
        "action": step.action,
        "status": status,
    }
    record.update(extra)
    return record


def run_action_sequence(
    steps: Sequence[Mapping[str, Any]],
    *,
    executor: StepExecutor,
    policy_probe: PolicyProbe | None = None,
    stop_on_error: bool = True,
    dry_run: bool = False,
    cancellation: CancellationToken | None = None,
    panic_probe: Callable[[], bool] | None = None,
    sequence_id: str | None = None,
    max_steps: int = 128,
) -> dict[str, Any]:
    """Run ordered steps without creating a batch-wide mutation lease.

    ``executor`` must invoke the server's ordinary *single action* gateway for
    every call.  That gateway remains responsible for final policy evaluation,
    one-time confirmation redemption, per-step lease acquisition/release, and
    audit recording.  The optional ``policy_probe`` can reject or mark a step as
    non-executing, but it must not mutate authorization state.

    Cancellation and panic are checked before and after each callback.  A long
    executor can call ``context.checkpoint()`` at safe interruption points.
    """

    if not callable(executor):
        raise TypeError("executor must be callable")
    if policy_probe is not None and not callable(policy_probe):
        raise TypeError("policy_probe must be callable")
    if max_steps < 1:
        raise ValueError("max_steps must be positive")

    normalized = _normalize_steps(steps, max_steps)
    token = cancellation or CancellationToken()
    probe = panic_probe or (lambda: False)
    sequence_value = str(sequence_id or uuid.uuid4())
    records: list[dict[str, Any]] = []
    stop_reason: str | None = None
    stop_index: int | None = None

    for index, step in enumerate(normalized):
        context = StepContext(
            sequence_id=sequence_value,
            step_index=index,
            step_count=len(normalized),
            dry_run=bool(dry_run),
            cancellation=token,
            panic_probe=probe,
        )
        try:
            context.checkpoint()
        except SequenceInterrupted as exc:
            stop_reason, stop_index = exc.reason, index
            records.append(_step_record(step, index, exc.reason, error=str(exc)))
            break

        preview: Mapping[str, Any] | bool | None = None
        if policy_probe is not None:
            try:
                preview = policy_probe(step, context)
                context.checkpoint()
            except SequenceInterrupted as exc:
                stop_reason, stop_index = exc.reason, index
                records.append(_step_record(step, index, exc.reason, error=str(exc)))
                break
            except Exception as exc:  # policy failures are fail-closed
                records.append(
                    _step_record(
                        step,
                        index,
                        "policy_error",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                if stop_on_error:
                    stop_reason, stop_index = "error", index
                    break
                continue

        allowed, policy_execute = _policy_disposition(preview)
        if not allowed:
            records.append(
                _step_record(step, index, "denied", policy=dict(preview) if isinstance(preview, Mapping) else preview)
            )
            if stop_on_error:
                stop_reason, stop_index = "error", index
                break
            continue
        if dry_run or not policy_execute:
            records.append(
                _step_record(step, index, "dry_run", policy=dict(preview) if isinstance(preview, Mapping) else preview)
            )
            continue

        try:
            result = executor(step, context)
            context.checkpoint()
        except SequenceInterrupted as exc:
            stop_reason, stop_index = exc.reason, index
            records.append(_step_record(step, index, exc.reason, error=str(exc)))
            break
        except Exception as exc:
            records.append(
                _step_record(
                    step,
                    index,
                    "error",
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            if stop_on_error:
                stop_reason, stop_index = "error", index
                break
            continue

        if _result_is_error(result):
            records.append(_step_record(step, index, "error", result=result))
            if stop_on_error:
                stop_reason, stop_index = "error", index
                break
        else:
            records.append(_step_record(step, index, "ok", result=result))

    if len(records) < len(normalized):
        reason = stop_reason or "stopped"
        for index in range(len(records), len(normalized)):
            step = normalized[index]
            records.append(_step_record(step, index, "skipped", reason=reason))

    statuses = [record["status"] for record in records]
    failed = any(status in {"error", "policy_error", "denied"} for status in statuses)
    interrupted = stop_reason in {"cancelled", "panic"}
    return {
        "sequenceId": sequence_value,
        "ok": not failed and not interrupted,
        "dryRun": bool(dry_run),
        "stopOnError": bool(stop_on_error),
        "stopped": stop_reason is not None,
        "stopReason": stop_reason,
        "stopIndex": stop_index,
        "steps": records,
        "counts": {
            "total": len(normalized),
            "ok": statuses.count("ok"),
            "dryRun": statuses.count("dry_run"),
            "error": sum(status in {"error", "policy_error", "denied"} for status in statuses),
            "cancelled": statuses.count("cancelled"),
            "panic": statuses.count("panic"),
            "skipped": statuses.count("skipped"),
        },
    }


__all__ = [
    "ActionStep",
    "CancellationToken",
    "PolicyProbe",
    "SequenceCancelled",
    "SequenceDefinitionError",
    "SequenceInterrupted",
    "SequencePanicked",
    "StepContext",
    "StepExecutor",
    "run_action_sequence",
]
