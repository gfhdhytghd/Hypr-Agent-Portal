#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("action_sequence", ROOT / "mcp" / "action_sequence.py")
assert SPEC is not None and SPEC.loader is not None
action_sequence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = action_sequence
SPEC.loader.exec_module(action_sequence)


def steps(count: int = 3) -> list[dict[str, object]]:
    return [
        {"id": f"item-{index}", "action": "click", "arguments": {"x": index, "y": index + 1}}
        for index in range(count)
    ]


class ActionSequenceTests(unittest.TestCase):
    def test_ordered_results_and_policy_before_each_executor(self) -> None:
        calls: list[tuple[str, int]] = []

        def policy(step: object, context: object) -> dict[str, bool]:
            calls.append(("policy", context.step_index))
            return {"allowed": True, "execute": True}

        def execute(step: object, context: object) -> dict[str, object]:
            calls.append(("execute", context.step_index))
            return {"action": step.action, "x": step.arguments["x"]}

        result = action_sequence.run_action_sequence(steps(), executor=execute, policy_probe=policy)
        self.assertTrue(result["ok"])
        self.assertEqual(
            calls,
            [("policy", 0), ("execute", 0), ("policy", 1), ("execute", 1), ("policy", 2), ("execute", 2)],
        )
        self.assertEqual([record["status"] for record in result["steps"]], ["ok", "ok", "ok"])
        self.assertEqual([record["result"]["x"] for record in result["steps"]], [0, 1, 2])

    def test_stop_on_error_marks_remaining_steps_skipped(self) -> None:
        executed: list[int] = []

        def execute(_step: object, context: object) -> dict[str, bool]:
            executed.append(context.step_index)
            if context.step_index == 1:
                return {"isError": True}
            return {"ok": True}

        result = action_sequence.run_action_sequence(steps(4), executor=execute)
        self.assertFalse(result["ok"])
        self.assertEqual(executed, [0, 1])
        self.assertEqual([record["status"] for record in result["steps"]], ["ok", "error", "skipped", "skipped"])
        self.assertEqual(result["stopReason"], "error")
        self.assertEqual(result["stopIndex"], 1)

    def test_continue_on_error_runs_later_steps(self) -> None:
        def execute(_step: object, context: object) -> dict[str, int]:
            if context.step_index == 1:
                raise RuntimeError("broken step")
            return {"index": context.step_index}

        result = action_sequence.run_action_sequence(steps(), executor=execute, stop_on_error=False)
        self.assertFalse(result["ok"])
        self.assertFalse(result["stopped"])
        self.assertEqual([record["status"] for record in result["steps"]], ["ok", "error", "ok"])

    def test_dry_run_still_probes_every_step_but_never_executes(self) -> None:
        probed: list[int] = []
        executed: list[int] = []

        def policy(_step: object, context: object) -> dict[str, bool]:
            probed.append(context.step_index)
            return {"allowed": True, "execute": True}

        def execute(_step: object, context: object) -> None:
            executed.append(context.step_index)

        result = action_sequence.run_action_sequence(
            steps(), executor=execute, policy_probe=policy, dry_run=True
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["dryRun"])
        self.assertEqual(probed, [0, 1, 2])
        self.assertEqual(executed, [])
        self.assertEqual([record["status"] for record in result["steps"]], ["dry_run"] * 3)

    def test_policy_denial_cannot_fall_through_to_executor(self) -> None:
        executed: list[int] = []

        def policy(_step: object, context: object) -> dict[str, bool]:
            return {"allowed": context.step_index != 1, "execute": context.step_index != 1}

        def execute(_step: object, context: object) -> dict[str, bool]:
            executed.append(context.step_index)
            return {"ok": True}

        result = action_sequence.run_action_sequence(steps(), executor=execute, policy_probe=policy)
        self.assertEqual(executed, [0])
        self.assertEqual([record["status"] for record in result["steps"]], ["ok", "denied", "skipped"])

    def test_executor_can_cooperatively_cancel_mid_step(self) -> None:
        token = action_sequence.CancellationToken()

        def execute(_step: object, context: object) -> dict[str, bool]:
            token.cancel("operator cancelled")
            context.checkpoint()
            return {"unreachable": True}

        result = action_sequence.run_action_sequence(steps(), executor=execute, cancellation=token)
        self.assertFalse(result["ok"])
        self.assertEqual([record["status"] for record in result["steps"]], ["cancelled", "skipped", "skipped"])
        self.assertEqual(result["stopReason"], "cancelled")
        self.assertIn("operator cancelled", result["steps"][0]["error"])

    def test_panic_between_steps_stops_before_next_policy_or_execution(self) -> None:
        panic = {"active": False}
        executed: list[int] = []

        def execute(_step: object, context: object) -> dict[str, bool]:
            executed.append(context.step_index)
            if context.step_index == 0:
                panic["active"] = True
            return {"ok": True}

        result = action_sequence.run_action_sequence(
            steps(), executor=execute, panic_probe=lambda: panic["active"]
        )
        self.assertEqual(executed, [0])
        # The post-executor checkpoint observes panic, so the in-flight step is
        # reported interrupted rather than falsely reported successful.
        self.assertEqual([record["status"] for record in result["steps"]], ["panic", "skipped", "skipped"])
        self.assertEqual(result["stopReason"], "panic")

    def test_cancel_is_one_shot_for_a_new_sequence_when_token_is_not_reused(self) -> None:
        old_token = action_sequence.CancellationToken()
        old_token.cancel()
        stopped = action_sequence.run_action_sequence(steps(1), executor=lambda *_: {}, cancellation=old_token)
        resumed = action_sequence.run_action_sequence(steps(1), executor=lambda *_: {})
        self.assertEqual(stopped["stopReason"], "cancelled")
        self.assertTrue(resumed["ok"])
        self.assertEqual(resumed["steps"][0]["status"], "ok")

    def test_malformed_and_recursive_sequences_are_rejected(self) -> None:
        with self.assertRaises(action_sequence.SequenceDefinitionError):
            action_sequence.run_action_sequence([], executor=lambda *_: {})
        with self.assertRaises(action_sequence.SequenceDefinitionError):
            action_sequence.run_action_sequence(
                [{"action": "sequence", "arguments": {}}], executor=lambda *_: {}
            )
        with self.assertRaises(action_sequence.SequenceDefinitionError):
            action_sequence.run_action_sequence(
                [{"action": "computer", "arguments": {"action": "batch"}}], executor=lambda *_: {}
            )
        with self.assertRaises(action_sequence.SequenceDefinitionError):
            action_sequence.run_action_sequence(
                [{"id": "same", "action": "click"}, {"id": "same", "action": "click"}],
                executor=lambda *_: {},
            )

    def test_each_executor_call_gets_an_independent_step_boundary(self) -> None:
        # A synthetic lease counter catches any future attempt to hold an outer
        # lease: each executor call must enter and leave independently.
        lease_depth = 0
        max_depth = 0

        def execute(_step: object, _context: object) -> dict[str, bool]:
            nonlocal lease_depth, max_depth
            self.assertEqual(lease_depth, 0)
            lease_depth += 1
            max_depth = max(max_depth, lease_depth)
            lease_depth -= 1
            return {"ok": True}

        result = action_sequence.run_action_sequence(steps(), executor=execute)
        self.assertTrue(result["ok"])
        self.assertEqual(max_depth, 1)
        self.assertEqual(lease_depth, 0)


if __name__ == "__main__":
    unittest.main()
