#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compat_env", ROOT / "mcp" / "compat_env.py")
assert SPEC is not None and SPEC.loader is not None
compat_env = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compat_env
SPEC.loader.exec_module(compat_env)


class CompatEnvironmentTests(unittest.TestCase):
    def test_canonical_value_wins(self) -> None:
        env = {
            "HYPR_AGENT_PORTAL_CTL": "/new/ctl",
            "HYPR_AGENT_PROTAL_CTL": "/old/ctl",
        }
        self.assertEqual(compat_env.getenv("HYPR_AGENT_PORTAL_CTL", environ=env), "/new/ctl")
        self.assertEqual(compat_env.promote_legacy_environment(env), ())
        self.assertEqual(env["HYPR_AGENT_PORTAL_CTL"], "/new/ctl")

    def test_legacy_value_is_promoted_without_mutating_unrelated_keys(self) -> None:
        env = {"HYPR_AGENT_PROTAL_MODEL_RESOLUTION": "full", "OTHER": "kept"}
        uses = compat_env.promote_legacy_environment(env)
        self.assertEqual(env["HYPR_AGENT_PORTAL_MODEL_RESOLUTION"], "full")
        self.assertEqual(env["OTHER"], "kept")
        self.assertEqual(
            uses,
            (
                compat_env.LegacyEnvironmentUse(
                    "HYPR_AGENT_PORTAL_MODEL_RESOLUTION",
                    "HYPR_AGENT_PROTAL_MODEL_RESOLUTION",
                ),
            ),
        )

    def test_unknown_legacy_variable_is_not_promoted(self) -> None:
        env = {"HYPR_AGENT_PROTAL_UNKNOWN": "unsafe"}
        self.assertEqual(compat_env.promote_legacy_environment(env), ())
        self.assertNotIn("HYPR_AGENT_PORTAL_UNKNOWN", env)

    def test_config_file_prefers_current_then_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            current, legacy = compat_env.config_file_candidates(
                "cursor.abgr", environ={"XDG_CONFIG_HOME": directory}
            )
            legacy.parent.mkdir(parents=True)
            legacy.touch()
            self.assertEqual(
                compat_env.existing_config_file("cursor.abgr", environ={"XDG_CONFIG_HOME": directory}),
                legacy,
            )
            current.parent.mkdir(parents=True)
            current.touch()
            self.assertEqual(
                compat_env.existing_config_file("cursor.abgr", environ={"XDG_CONFIG_HOME": directory}),
                current,
            )
            self.assertEqual(current.parent, base / "hypr-agent-portal")

    def test_rejects_config_directory_escape(self) -> None:
        with self.assertRaises(ValueError):
            compat_env.config_file_candidates("../secret")

    def test_config_namespaces_are_ordered(self) -> None:
        self.assertEqual(
            compat_env.config_namespace_candidates(lua=True),
            ("plugin.hypr_agent_portal", "plugin.hypr_agent_protal"),
        )
        self.assertEqual(
            compat_env.config_namespace_candidates(lua=False),
            ("plugin:hypr-agent-portal", "plugin:hypr-agent-protal"),
        )


if __name__ == "__main__":
    unittest.main()
