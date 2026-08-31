#!/usr/bin/env python3
"""Security contract tests for the hypr-agent-portal MCP server.

These tests intentionally avoid a running Hyprland session.  Policy decisions,
audit redaction, tool exposure, and dry-run interception must all be testable
before any compositor command is sent.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile
import threading
import uuid
from collections.abc import Iterator
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
MCP_DIR = ROOT / "mcp"
MCP = MCP_DIR / "hypr-agent-portal-mcp.py"
POLICY = MCP_DIR / "security_policy.py"
AUDIT = MCP_DIR / "security_audit.py"


def load_path(path: pathlib.Path, stem: str) -> Any:
    name = f"hypr_agent_portal_test_{stem}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(MCP_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(MCP_DIR))
    return module


@contextlib.contextmanager
def security_environment(**values: str | None) -> Iterator[None]:
    prefix = "HYPR_AGENT_PORTAL_"
    # Integration tests exercise mutation plumbing explicitly. Production's
    # unconfigured default remains VIEW and is covered by the policy test.
    if "SECURITY_DEFAULT_AUTHORIZATION" not in values:
        values["SECURITY_DEFAULT_AUTHORIZATION"] = "full"
    previous = {key: value for key, value in os.environ.items() if key.startswith(prefix)}
    for key in list(os.environ):
        if key.startswith(prefix):
            os.environ.pop(key)
    for key, value in values.items():
        env_key = key if key.startswith(prefix) else f"{prefix}{key}"
        if value is not None:
            os.environ[env_key] = value
    try:
        yield
    finally:
        for key in list(os.environ):
            if key.startswith(prefix):
                os.environ.pop(key)
        os.environ.update(previous)


def policy_module() -> Any:
    assert POLICY.is_file(), "mcp/security_policy.py is required"
    return load_path(POLICY, "security_policy")


def audit_module() -> Any:
    assert AUDIT.is_file(), "mcp/security_audit.py is required"
    return load_path(AUDIT, "security_audit")


def make_policy(mod: Any, **overrides: Any) -> Any:
    values = {
        "default_authorization": mod.AuthorizationLevel.FULL,
        "mutation_lease_required": False,
        "human_takeover_enabled": False,
    }
    values.update(overrides)
    return mod.SecurityPolicy(mod.PolicyConfig(**values))


def window(
    mod: Any,
    address: str = "0xabc",
    class_name: str = "org.example.Editor",
    workspace: str = "3",
    *,
    initial_class: str = "",
    launched: bool = False,
) -> Any:
    return mod.WindowIdentity(
        address=address,
        class_name=class_name,
        initial_class=initial_class,
        workspace=workspace,
        launched=launched,
    )


def request(mod: Any, **overrides: Any) -> Any:
    values = {
        "owner": "test-client",
        "action": "click",
        "required_level": mod.AuthorizationLevel.CLICK,
        "mutating": True,
        "target": window(mod),
    }
    values.update(overrides)
    return mod.ActionRequest(**values)


def assert_denied(decision: Any, code: Any) -> None:
    assert decision.allowed is False
    assert decision.execute is False
    assert decision.code == code
    encoded = decision.to_dict()
    assert encoded["allowed"] is False
    assert encoded["execute"] is False
    assert encoded["code"] == (code.value if hasattr(code, "value") else code)
    assert isinstance(encoded["reason"], str) and encoded["reason"]


def physically_approve(module: Any, challenge_id: str, **kwargs: Any) -> dict[str, Any]:
    simulator = getattr(module, "_test_physical_approval_simulator", None)
    if simulator is None:
        simulator = {"approved": set(), "calls": []}

        def dispatcher(action: str, candidate: str, ttl_ms: int | None) -> bool:
            simulator["calls"].append((action, candidate, ttl_ms))
            if action == "arm":
                # Simulate the physical F12 arriving immediately after arm.
                simulator["approved"].add(candidate)
                return True
            if action == "status":
                return candidate in simulator["approved"]
            if action == "cancel":
                simulator["approved"].discard(candidate)
                return True
            raise AssertionError(action)

        module._dispatch_native_approval = dispatcher
        module._test_physical_approval_simulator = simulator
    before = len(simulator["calls"])
    result = module.approve_confirmation(challenge_id, **kwargs)
    calls = simulator["calls"][before:]
    assert [call[0] for call in calls] == ["arm", "status"]
    assert all(call[1] == challenge_id for call in calls)
    assert calls[0][2] is not None
    return result


def mcp_policy_runtime(module: Any) -> Any:
    return sys.modules[module.SECURITY_POLICY.__class__.__module__]


def test_policy_readonly_and_dry_run() -> None:
    mod = policy_module()
    readonly = make_policy(mod, readonly=True)
    assert_denied(readonly.evaluate(request(mod)), mod.DecisionCode.READONLY)
    observed = readonly.evaluate(
        request(mod, action="screenshot", required_level=mod.AuthorizationLevel.VIEW, mutating=False)
    )
    assert observed.allowed and observed.execute

    dry_run = make_policy(mod, dry_run=True)
    decision = dry_run.evaluate(request(mod))
    assert decision.allowed is True
    assert decision.execute is False
    assert decision.code == mod.DecisionCode.DRY_RUN
    assert decision.to_dict()["execute"] is False


def test_policy_confinement() -> None:
    mod = policy_module()
    confined = make_policy(
        mod,
        confinement=mod.ConfinementConfig(
            classes=frozenset({"org.example.Allowed"}),
            workspaces=frozenset({"safe"}),
            addresses=frozenset({"0x123"}),
            match=mod.ScopeMatch.ANY,
        ),
    )
    for allowed_target in (
        window(mod, class_name="org.example.Allowed"),
        window(mod, workspace="safe"),
        window(mod, address="0x123"),
    ):
        assert confined.evaluate(request(mod, target=allowed_target)).allowed
    assert_denied(
        confined.evaluate(request(mod, target=window(mod, "0x999", "org.example.Other", "9"))),
        mod.DecisionCode.OUT_OF_SCOPE,
    )

    launched_only = make_policy(mod, confinement=mod.ConfinementConfig(launched_only=True))
    target = window(mod, "0x777")
    assert_denied(launched_only.evaluate(request(mod, target=target)), mod.DecisionCode.OUT_OF_SCOPE)
    launched_only.register_launched_window(target)
    assert launched_only.evaluate(request(mod, target=target)).allowed
    moved_target = mod.WindowIdentity(
        address=target.address,
        class_name=target.class_name,
        workspace="different-workspace",
        pid=target.pid,
        process_start_time=target.process_start_time,
    )
    assert launched_only.evaluate(request(mod, target=moved_target)).allowed
    recycled = mod.WindowIdentity(
        address=target.address,
        class_name=target.class_name,
        workspace=target.workspace,
        pid="999",
        process_start_time="recycled",
    )
    assert_denied(launched_only.evaluate(request(mod, target=recycled)), mod.DecisionCode.OUT_OF_SCOPE)
    launched_only.unregister_launched_window(target.address)
    assert_denied(launched_only.evaluate(request(mod, target=target)), mod.DecisionCode.OUT_OF_SCOPE)


def test_policy_lock_layer_and_keyboard_grab_guards() -> None:
    mod = policy_module()
    policy = make_policy(mod)
    guarded = (
        (mod.GuardInputs(screen_locked=True), mod.DecisionCode.SCREEN_LOCKED),
        (mod.GuardInputs(layer_surface_active=True), mod.DecisionCode.LAYER_SURFACE_ACTIVE),
        (mod.GuardInputs(keyboard_grab_active=True), mod.DecisionCode.KEYBOARD_GRAB_ACTIVE),
        (mod.GuardInputs(panic_active=True), mod.DecisionCode.PANIC_ACTIVE),
        (mod.GuardInputs(available=False, error="probe failed"), mod.DecisionCode.GUARD_UNAVAILABLE),
    )
    for guards, code in guarded:
        assert_denied(policy.evaluate(request(mod), guards=guards), code)

    view = request(mod, action="screenshot", required_level=mod.AuthorizationLevel.VIEW, mutating=False)
    assert_denied(policy.evaluate(view, guards=mod.GuardInputs(screen_locked=True)), mod.DecisionCode.SCREEN_LOCKED)
    assert policy.evaluate(view, guards=mod.GuardInputs(layer_surface_active=True)).allowed
    assert policy.evaluate(view, guards=mod.GuardInputs(keyboard_grab_active=True)).allowed


def test_mcp_runtime_guards_are_authoritative_and_fail_closed() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_runtime_guards")

    states = (
        ({"available": True, "screenLocked": True, "layerSurfaceActive": False, "keyboardGrabActive": False, "panicActive": False}, "screen_locked"),
        ({"available": True, "screenLocked": False, "layerSurfaceActive": True, "keyboardGrabActive": False, "panicActive": False}, "layer_surface_active"),
        ({"available": True, "screenLocked": False, "layerSurfaceActive": False, "keyboardGrabActive": True, "panicActive": False}, "keyboard_grab_active"),
        ({"available": True, "screenLocked": False, "layerSurfaceActive": False, "keyboardGrabActive": False, "panicActive": True}, "panic_active"),
    )
    for state, expected in states:
        module.call_ctl = lambda _args, state=state: state
        guards = module.collect_runtime_guards()
        request_value = module.build_security_request("launch_app", {"command": "must-not-run"})
        decision = module.SECURITY_POLICY.evaluate(request_value, guards)
        assert decision.allowed is False
        assert decision.code.value == expected

    module.SERVER_PANIC_ACTIVE = False
    module.call_ctl = lambda _args: (_ for _ in ()).throw(RuntimeError("native guard unavailable"))
    unavailable = module.collect_runtime_guards()
    assert unavailable.available is False
    request_value = module.build_security_request("launch_app", {"command": "must-not-run"})
    assert module.SECURITY_POLICY.evaluate(request_value, unavailable).code == module.DecisionCode.GUARD_UNAVAILABLE


def test_mcp_panic_latches_all_mutation_paths_until_resume() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_panic_latch")
    module.SECURITY_POLICY = module.SecurityPolicy(
        type(module.SECURITY_POLICY.config)(
            default_authorization=module.AuthorizationLevel.FULL,
            mutation_lease_required=False,
            human_takeover_enabled=False,
        )
    )

    native_panic = False

    def fake_ctl(args: list[str]) -> dict[str, Any]:
        nonlocal native_panic
        if args[0] == "panic":
            mode = args[1]
            if mode == "panic":
                native_panic = True
            elif mode == "resume":
                native_panic = False
            return {"ok": True, "action": mode, "panicActive": native_panic}
        if args[0] == "guard":
            return {
                "available": True,
                "screenLocked": False,
                "layerSurfaceActive": False,
                "keyboardGrabActive": False,
                "panicActive": native_panic,
            }
        raise AssertionError(args)

    module.call_ctl = fake_ctl
    stop_request = module.build_security_request("panic", {"mode": "cancel"})
    assert module.SECURITY_POLICY.evaluate(stop_request, module.GuardInputs(screen_locked=False)).allowed
    module.tool_panic({"mode": "cancel"})
    assert module.SERVER_PANIC_ACTIVE is False
    guards = module.collect_runtime_guards()
    request_value = module.build_security_request("activate_menu_item", {})
    assert module.SECURITY_POLICY.evaluate(request_value, guards).allowed

    module.tool_panic({"mode": "panic"})
    assert module.SERVER_PANIC_ACTIVE is True
    guards = module.collect_runtime_guards()
    assert module.SECURITY_POLICY.evaluate(request_value, guards).code == module.DecisionCode.PANIC_ACTIVE
    resume_request = module.build_security_request("panic", {"mode": "resume"})
    resume_decision = module.SECURITY_POLICY.evaluate(resume_request, module.GuardInputs(screen_locked=False))
    assert resume_decision.code in {module.DecisionCode.CONFIRMATION_REQUIRED, module.DecisionCode.CONFIRMATION_PENDING}
    module.tool_panic({"mode": "resume"})
    assert module.SERVER_PANIC_ACTIVE is False
    assert module.collect_runtime_guards().panic_active is False


def test_policy_detects_known_lock_processes_without_real_procfs() -> None:
    mod = policy_module()
    with tempfile.TemporaryDirectory() as temporary:
        proc_root = pathlib.Path(temporary)
        for pid, name in (("100", "hyprlock\n"), ("101", "ordinary-app\n"), ("not-a-pid", "swaylock\n")):
            process = proc_root / pid
            process.mkdir()
            (process / "comm").write_text(name, encoding="utf-8")
        policy = mod.SecurityPolicy(
            mod.PolicyConfig(mutation_lease_required=False, human_takeover_enabled=False),
            proc_root=proc_root,
        )
        assert policy.detect_lock_screen() == ("hyprlock",)


def test_policy_application_authorization_and_privacy() -> None:
    mod = policy_module()
    default_policy = mod.SecurityPolicy(
        mod.PolicyConfig(mutation_lease_required=False, human_takeover_enabled=False)
    )
    assert default_policy.config.default_authorization == mod.AuthorizationLevel.VIEW
    assert_denied(default_policy.evaluate(request(mod)), mod.DecisionCode.APP_PERMISSION)
    assert default_policy.evaluate(
        request(mod, action="screenshot", required_level=mod.AuthorizationLevel.VIEW, mutating=False)
    ).allowed

    target = window(mod, class_name="org.example.ViewOnly")
    policy = make_policy(
        mod,
        app_authorizations={"org.example.ViewOnly": mod.AuthorizationLevel.VIEW},
        privacy_classes=frozenset({"org.example.Secret"}),
    )
    assert_denied(policy.evaluate(request(mod, target=target)), mod.DecisionCode.APP_PERMISSION)
    assert policy.evaluate(
        request(mod, action="screenshot", required_level=mod.AuthorizationLevel.VIEW, mutating=False, target=target)
    ).allowed
    secret = window(mod, class_name="org.example.Secret")
    assert_denied(
        policy.evaluate(request(mod, action="screenshot", required_level=mod.AuthorizationLevel.VIEW, mutating=False, target=secret)),
        mod.DecisionCode.PRIVACY_EXCLUDED,
    )


def test_policy_class_changes_cannot_bypass_stable_identity_rules() -> None:
    mod = policy_module()
    changed = mod.WindowIdentity.from_window(
        {
            "address": "0xclass-change",
            "class": "org.example.RuntimeAllowed",
            "initialClass": "org.example.StableSecret",
            "workspace": {"name": "3"},
        }
    )
    assert changed.class_name == "org.example.RuntimeAllowed"
    assert changed.initial_class == "org.example.StableSecret"
    assert changed.fingerprint()["initialClass"] == "org.example.stablesecret"

    privacy = make_policy(mod, privacy_classes={"org.example.StableSecret"})
    view = request(
        mod,
        action="screenshot",
        required_level=mod.AuthorizationLevel.VIEW,
        mutating=False,
        target=changed,
    )
    assert_denied(privacy.evaluate(view), mod.DecisionCode.PRIVACY_EXCLUDED)

    authorization = make_policy(
        mod,
        app_authorizations={
            "org.example.RuntimeAllowed": mod.AuthorizationLevel.FULL,
            "org.example.StableSecret": mod.AuthorizationLevel.VIEW,
        },
    )
    assert authorization.authorization_for(changed) == mod.AuthorizationLevel.VIEW
    assert_denied(authorization.evaluate(request(mod, target=changed)), mod.DecisionCode.APP_PERMISSION)

    runtime_only_grant = make_policy(
        mod,
        default_authorization=mod.AuthorizationLevel.VIEW,
        app_authorizations={"org.example.RuntimeAllowed": mod.AuthorizationLevel.FULL},
    )
    assert runtime_only_grant.authorization_for(changed) == mod.AuthorizationLevel.VIEW

    runtime_spoof = make_policy(
        mod,
        confinement=mod.ConfinementConfig(classes={"org.example.RuntimeAllowed"}),
    )
    assert_denied(runtime_spoof.evaluate(request(mod, target=changed)), mod.DecisionCode.OUT_OF_SCOPE)

    stable_allowed = make_policy(
        mod,
        confinement=mod.ConfinementConfig(classes={"org.example.StableSecret"}),
    )
    assert stable_allowed.evaluate(request(mod, target=changed)).allowed


def test_policy_mutation_lease_is_single_owner_and_expires() -> None:
    mod = policy_module()
    now = [100.0]
    policy = mod.SecurityPolicy(
        mod.PolicyConfig(
            default_authorization=mod.AuthorizationLevel.FULL,
            mutation_lease_required=True,
            human_takeover_enabled=False,
        ),
        clock=lambda: now[0],
    )
    assert_denied(policy.evaluate(request(mod)), mod.DecisionCode.MUTATION_LEASE_REQUIRED)
    assert policy.acquire_mutation_lease("test-client", ttl_seconds=5.0)
    assert policy.evaluate(request(mod)).allowed
    assert not policy.acquire_mutation_lease("other-client", ttl_seconds=5.0)
    assert_denied(
        policy.evaluate(request(mod, owner="other-client")),
        mod.DecisionCode.MUTATION_LEASE_HELD,
    )
    now[0] += 6.0
    assert policy.acquire_mutation_lease("other-client", ttl_seconds=5.0)
    assert policy.evaluate(request(mod, owner="other-client")).allowed
    policy.release_mutation_lease("other-client")
    assert_denied(policy.evaluate(request(mod, owner="other-client")), mod.DecisionCode.MUTATION_LEASE_REQUIRED)


def test_policy_confirmation_tokens_are_bound_and_one_time() -> None:
    mod = policy_module()
    now = [200.0]
    with tempfile.TemporaryDirectory() as temporary:
        confirmation_dir = pathlib.Path(temporary) / "confirmations"
        policy = mod.SecurityPolicy(
            mod.PolicyConfig(
                default_authorization=mod.AuthorizationLevel.FULL,
                mutation_lease_required=False,
                human_takeover_enabled=False,
            ),
            clock=lambda: now[0],
            wall_clock=lambda: now[0],
            confirmation_dir=confirmation_dir,
        )
        destructive = request(
            mod,
            action="close_window",
            required_level=mod.AuthorizationLevel.FULL,
            destructive=True,
            confirmation_context={"target": "0xabc", "operation": "close"},
        )
        assert_denied(policy.evaluate(destructive), mod.DecisionCode.CONFIRMATION_REQUIRED)
        challenge = policy.request_confirmation(destructive, ttl_seconds=5.0)
        confirmed = request(
            mod,
            action=destructive.action,
            required_level=destructive.required_level,
            destructive=True,
            confirmation_context=destructive.confirmation_context,
            confirmation_token=challenge,
        )
        # Merely requesting a challenge cannot authorize the MCP caller.
        assert_denied(policy.evaluate(confirmed), mod.DecisionCode.CONFIRMATION_PENDING)
        physically_approve(mod, challenge, confirmation_dir=confirmation_dir, wall_clock=lambda: now[0])
        assert policy.evaluate(confirmed).allowed
        assert_denied(policy.evaluate(confirmed), mod.DecisionCode.CONFIRMATION_INVALID)

        challenge = policy.request_confirmation(destructive, ttl_seconds=5.0)
        physically_approve(mod, challenge, confirmation_dir=confirmation_dir, wall_clock=lambda: now[0])
        mismatched = request(
            mod,
            action="delete_file",
            required_level=mod.AuthorizationLevel.FULL,
            destructive=True,
            confirmation_context=destructive.confirmation_context,
            confirmation_token=challenge,
        )
        assert_denied(policy.evaluate(mismatched), mod.DecisionCode.CONFIRMATION_INVALID)
        correctly_bound = request(
            mod,
            action=destructive.action,
            required_level=destructive.required_level,
            destructive=True,
            confirmation_context=destructive.confirmation_context,
            confirmation_token=challenge,
        )
        assert policy.evaluate(correctly_bound).allowed

        expiring = policy.request_confirmation(destructive, ttl_seconds=1.0)
        now[0] += 2.0
        try:
            physically_approve(mod, expiring, confirmation_dir=confirmation_dir, wall_clock=lambda: now[0])
        except RuntimeError as error:
            assert "expired" in str(error)
        else:
            raise AssertionError("expired confirmation challenge was approved")


def test_confirmation_waits_for_native_physical_proof() -> None:
    mod = policy_module()
    with tempfile.TemporaryDirectory() as temporary:
        confirmation_dir = pathlib.Path(temporary) / "confirmations"
        policy = mod.SecurityPolicy(
            mod.PolicyConfig(
                default_authorization=mod.AuthorizationLevel.FULL,
                mutation_lease_required=False,
                human_takeover_enabled=False,
            ),
            confirmation_dir=confirmation_dir,
        )
        destructive = request(mod, action="close_window", destructive=True)
        challenge = policy.request_confirmation(destructive, ttl_seconds=5.0)
        calls: list[str] = []
        statuses = iter((False, True))
        native_approved = [False]

        def dispatcher(action: str, candidate: str, ttl_ms: int | None) -> bool:
            assert candidate == challenge
            calls.append(action)
            if action == "arm":
                return True
            if action == "status":
                if not native_approved[0]:
                    result = next(statuses)
                    native_approved[0] = result
                    return result
                return True
            if action == "cancel":
                native_approved[0] = False
                return True
            raise AssertionError(action)

        original = mod._dispatch_native_approval
        mod._dispatch_native_approval = dispatcher
        try:
            mod.approve_confirmation(
                challenge,
                confirmation_dir=confirmation_dir,
                sleep=lambda _: None,
            )
        finally:
            mod._dispatch_native_approval = original
        assert calls == ["arm", "status", "status"]
        assert not (confirmation_dir / f"{challenge}.pending.json").exists()
        assert (confirmation_dir / f"{challenge}.approved.json").is_file()

        mod._dispatch_native_approval = dispatcher
        try:
            confirmed = request(
                mod,
                action=destructive.action,
                destructive=True,
                confirmation_token=challenge,
            )
            assert policy.evaluate(confirmed).allowed
        finally:
            mod._dispatch_native_approval = original
        assert calls == ["arm", "status", "status", "status", "cancel"]
        assert native_approved[0] is False
        assert not (confirmation_dir / f"{challenge}.approved.json").exists()


def test_confirmation_capacity_expiry_rate_and_symlink_safety() -> None:
    mod = policy_module()
    now = [1000.0]
    with tempfile.TemporaryDirectory() as temporary:
        confirmation_dir = pathlib.Path(temporary) / "confirmations"
        config = mod.PolicyConfig(
            default_authorization=mod.AuthorizationLevel.FULL,
            mutation_lease_required=False,
            human_takeover_enabled=False,
            confirmation_pending_limit=2,
            confirmation_pending_per_owner=1,
        )
        policy = mod.SecurityPolicy(config, wall_clock=lambda: now[0], confirmation_dir=confirmation_dir)
        first = policy.request_confirmation(request(mod, destructive=True), ttl_seconds=1)
        try:
            policy.request_confirmation(request(mod, destructive=True))
        except RuntimeError as error:
            assert "owner" in str(error)
        else:
            raise AssertionError("per-owner confirmation capacity was bypassed")
        pending = confirmation_dir / f"{first}.pending.json"
        approved = confirmation_dir / f"{first}.approved.json"
        pending.replace(approved)
        approved.chmod(0o400)
        now[0] += 2
        cancel_calls: list[tuple[str, str]] = []
        original_dispatch = mod._dispatch_native_approval
        mod._dispatch_native_approval = lambda action, candidate, _ttl: cancel_calls.append((action, candidate)) or True
        try:
            second = policy.request_confirmation(request(mod, destructive=True), ttl_seconds=30)
        finally:
            mod._dispatch_native_approval = original_dispatch
        assert not approved.exists()
        assert cancel_calls == [("cancel", first)]
        mod.reject_confirmation(second, confirmation_dir=confirmation_dir)
        rate_dir = pathlib.Path(temporary) / "rate-confirmations"
        rate_policy = mod.SecurityPolicy(
            mod.PolicyConfig(
                default_authorization=mod.AuthorizationLevel.FULL,
                mutation_lease_required=False,
                human_takeover_enabled=False,
                confirmation_pending_limit=2,
                confirmation_pending_per_owner=1,
                confirmation_min_interval_seconds=5,
            ),
            wall_clock=lambda: now[0],
            confirmation_dir=rate_dir,
        )
        rate_challenge = rate_policy.request_confirmation(request(mod, destructive=True))
        mod.reject_confirmation(rate_challenge, confirmation_dir=rate_dir)
        try:
            rate_policy.request_confirmation(request(mod, destructive=True))
        except RuntimeError as error:
            assert "rate limit" in str(error)
        else:
            raise AssertionError("confirmation minimum interval was bypassed")
        now[0] += 5
        policy.request_confirmation(request(mod, owner="other", destructive=True))
        policy.request_confirmation(request(mod, owner="third", destructive=True))
        try:
            policy.request_confirmation(request(mod, owner="fourth", destructive=True))
        except RuntimeError as error:
            assert "capacity exhausted" in str(error)
        else:
            raise AssertionError("global confirmation capacity was bypassed")

    with tempfile.TemporaryDirectory() as temporary:
        confirmation_dir = pathlib.Path(temporary) / "confirmations"
        policy = mod.SecurityPolicy(
            mod.PolicyConfig(
                default_authorization=mod.AuthorizationLevel.FULL,
                mutation_lease_required=False,
                human_takeover_enabled=False,
                confirmation_pending_limit=1,
                confirmation_pending_per_owner=1,
            ),
            wall_clock=lambda: now[0],
            confirmation_dir=confirmation_dir,
        )
        confirmation_dir.mkdir(mode=0o700)
        outside = pathlib.Path(temporary) / "outside.json"
        outside.write_text("do not follow", encoding="utf-8")
        fake_id = "a" * 32
        (confirmation_dir / f"{fake_id}.pending.json").symlink_to(outside)
        try:
            policy.request_confirmation(request(mod, destructive=True))
        except RuntimeError as error:
            assert "capacity exhausted" in str(error)
        else:
            raise AssertionError("unsafe challenge entry did not consume a fail-closed slot")
        assert outside.read_text(encoding="utf-8") == "do not follow"


def test_confirmation_capacity_is_atomic_across_policy_instances() -> None:
    mod = policy_module()
    with tempfile.TemporaryDirectory() as temporary:
        confirmation_dir = pathlib.Path(temporary) / "confirmations"
        config = mod.PolicyConfig(
            default_authorization=mod.AuthorizationLevel.FULL,
            mutation_lease_required=False,
            human_takeover_enabled=False,
            confirmation_pending_limit=1,
            confirmation_pending_per_owner=1,
        )
        policies = [mod.SecurityPolicy(config, confirmation_dir=confirmation_dir) for _ in range(2)]
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def create(index: int) -> None:
            barrier.wait()
            try:
                policies[index].request_confirmation(request(mod, owner=f"owner-{index}", destructive=True))
                outcomes.append("created")
            except RuntimeError:
                outcomes.append("rejected")

        threads = [threading.Thread(target=create, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        assert outcomes.count("created") == 1 and outcomes.count("rejected") == 1


def test_forged_approved_file_requires_live_native_proof() -> None:
    mod = policy_module()
    with tempfile.TemporaryDirectory() as temporary:
        confirmation_dir = pathlib.Path(temporary) / "confirmations"
        policy = mod.SecurityPolicy(
            mod.PolicyConfig(
                default_authorization=mod.AuthorizationLevel.FULL,
                mutation_lease_required=False,
                human_takeover_enabled=False,
            ),
            confirmation_dir=confirmation_dir,
        )
        destructive = request(mod, action="close_window", destructive=True)
        challenge = policy.request_confirmation(destructive, ttl_seconds=5.0)
        pending = confirmation_dir / f"{challenge}.pending.json"
        forged = confirmation_dir / f"{challenge}.approved.json"
        shutil.copyfile(pending, forged)
        forged.chmod(0o400)

        calls: list[str] = []

        def no_native_proof(action: str, candidate: str, ttl_ms: int | None) -> bool:
            assert candidate == challenge
            calls.append(action)
            return action == "cancel"

        original = mod._dispatch_native_approval
        mod._dispatch_native_approval = no_native_proof
        try:
            confirmed = request(
                mod,
                action=destructive.action,
                destructive=True,
                confirmation_token=challenge,
            )
            assert_denied(policy.evaluate(confirmed), mod.DecisionCode.CONFIRMATION_INVALID)
        finally:
            mod._dispatch_native_approval = original
        assert calls == ["status", "cancel"]
        assert not forged.exists()
        assert pending.is_file()

        # A hard link is rejected earlier by the single-link file invariant,
        # but must still be removed without crashing the evaluator.
        challenge = policy.request_confirmation(destructive, ttl_seconds=5.0)
        pending = confirmation_dir / f"{challenge}.pending.json"
        forged = confirmation_dir / f"{challenge}.approved.json"
        os.link(pending, forged)
        calls.clear()
        mod._dispatch_native_approval = no_native_proof
        try:
            confirmed = request(
                mod,
                action=destructive.action,
                destructive=True,
                confirmation_token=challenge,
            )
            assert_denied(policy.evaluate(confirmed), mod.DecisionCode.CONFIRMATION_INVALID)
        finally:
            mod._dispatch_native_approval = original
        assert calls == ["cancel"]
        assert not forged.exists()
        assert pending.is_file()


def test_native_approval_dispatch_supports_lua_and_compat_namespace() -> None:
    mod = policy_module()
    challenge = "a" * 32
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> Any:
        assert kwargs.get("stdin") is mod.subprocess.DEVNULL
        assert kwargs.get("shell") is None
        calls.append(list(command))
        if command[1:] == ["systeminfo"]:
            return mod.subprocess.CompletedProcess(command, 0, "configProvider: lua\n", "")
        expression = command[2]
        assert command[:2] == ["/usr/bin/hyprctl", "dispatch"]
        if '.approval("arm ' in expression or '.approval("cancel ' in expression:
            return mod.subprocess.CompletedProcess(command, 0, "ok\n", "")
        if "hypr_agent_portal.approval" in expression:
            return mod.subprocess.CompletedProcess(command, 1, "lua plugin function unavailable\n", "")
        assert "hypr_agent_protal.approval" in expression
        return mod.subprocess.CompletedProcess(command, 1, "approval-pending-press-f12\n", "")

    original_binary = mod._trusted_hyprctl_binary
    original_run = mod.subprocess.run
    mod._trusted_hyprctl_binary = lambda: pathlib.Path("/usr/bin/hyprctl")
    mod.subprocess.run = fake_run
    try:
        assert mod._dispatch_native_approval("arm", challenge, 5000) is True
        assert mod._dispatch_native_approval("status", challenge) is False
        assert mod._dispatch_native_approval("cancel", challenge) is True
    finally:
        mod._trusted_hyprctl_binary = original_binary
        mod.subprocess.run = original_run

    dispatches = [command for command in calls if command[1] == "dispatch"]
    assert dispatches == [
        ["/usr/bin/hyprctl", "dispatch", f'hl.plugin.hypr_agent_portal.approval("arm {challenge} 5000")'],
        ["/usr/bin/hyprctl", "dispatch", f'hl.plugin.hypr_agent_portal.approval("status {challenge}")'],
        ["/usr/bin/hyprctl", "dispatch", f'hl.plugin.hypr_agent_protal.approval("status {challenge}")'],
        ["/usr/bin/hyprctl", "dispatch", f'hl.plugin.hypr_agent_portal.approval("cancel {challenge}")'],
    ]


def test_native_approval_dispatch_keeps_legacy_provider_argv_safe() -> None:
    mod = policy_module()
    challenge = "b" * 32
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> Any:
        calls.append(list(command))
        if command[1:] == ["systeminfo"]:
            return mod.subprocess.CompletedProcess(command, 0, "configProvider: hyprlang\n", "")
        if command[2] == "hypr-agent-portal:approval":
            return mod.subprocess.CompletedProcess(command, 1, "Invalid dispatcher\n", "")
        return mod.subprocess.CompletedProcess(command, 0, "ok\n", "")

    original_binary = mod._trusted_hyprctl_binary
    original_run = mod.subprocess.run
    mod._trusted_hyprctl_binary = lambda: pathlib.Path("/usr/bin/hyprctl")
    mod.subprocess.run = fake_run
    try:
        assert mod._dispatch_native_approval("cancel", challenge) is True
    finally:
        mod._trusted_hyprctl_binary = original_binary
        mod.subprocess.run = original_run
    assert calls[-2:] == [
        ["/usr/bin/hyprctl", "dispatch", "hypr-agent-portal:approval", f"cancel {challenge}"],
        ["/usr/bin/hyprctl", "dispatch", "hypr-agent-protal:approval", f"cancel {challenge}"],
    ]

def test_policy_clipboard_capabilities_are_independent() -> None:
    mod = policy_module()
    policy = make_policy(
        mod,
        clipboard_permissions=frozenset({mod.ClipboardCapability.WRITE, mod.ClipboardCapability.PASTE_TEXT}),
    )
    allowed = request(
        mod,
        action="paste_text",
        clipboard_capabilities=frozenset({mod.ClipboardCapability.WRITE, mod.ClipboardCapability.PASTE_TEXT}),
    )
    assert policy.evaluate(allowed).allowed
    for capability in (
        mod.ClipboardCapability.READ,
        mod.ClipboardCapability.PASTE_FILE,
        mod.ClipboardCapability.PASTE_IMAGE,
    ):
        assert_denied(
            policy.evaluate(request(mod, action="clipboard", clipboard_capabilities=frozenset({capability}))),
            mod.DecisionCode.CLIPBOARD_PERMISSION,
        )


def test_policy_human_takeover_cooldown() -> None:
    mod = policy_module()
    now = [300.0]
    policy = mod.SecurityPolicy(
        mod.PolicyConfig(
            default_authorization=mod.AuthorizationLevel.FULL,
            mutation_lease_required=False,
            human_takeover_enabled=True,
            human_takeover_cooldown_seconds=2.0,
        ),
        clock=lambda: now[0],
    )
    policy.record_human_activity()
    assert_denied(policy.evaluate(request(mod)), mod.DecisionCode.HUMAN_TAKEOVER)
    view = request(mod, action="screenshot", required_level=mod.AuthorizationLevel.VIEW, mutating=False)
    assert policy.evaluate(view).allowed
    now[0] += 2.1
    assert policy.evaluate(request(mod)).allowed
    policy.record_human_activity()
    policy.clear_human_takeover()
    assert policy.evaluate(request(mod)).allowed


def test_policy_environment_contract() -> None:
    mod = policy_module()
    with security_environment(
        SECURITY_READONLY="1",
        SECURITY_DRY_RUN="1",
        SECURITY_CONFINE_CLASSES="org.example.Safe",
        SECURITY_CONFINE_WORKSPACES="2",
        SECURITY_APP_AUTHORIZATIONS="org.example.Safe=click,org.example.View=view",
        SECURITY_CLIPBOARD_PERMISSIONS="write,paste_text",
        SECURITY_PRIVACY_CLASSES="org.example.Secret,org.example.Passwords",
        SECURITY_CONFIRMATION_PENDING_LIMIT="9",
        SECURITY_CONFIRMATION_PENDING_PER_OWNER="3",
        SECURITY_CONFIRMATION_MIN_INTERVAL="0.5",
    ):
        policy = mod.policy_from_env()
    config = policy.config
    assert config.readonly is True
    assert config.dry_run is True
    assert "org.example.safe" in config.confinement.classes
    assert "2" in config.confinement.workspaces
    assert config.app_authorizations["org.example.safe"] == mod.AuthorizationLevel.CLICK
    assert config.app_authorizations["org.example.view"] == mod.AuthorizationLevel.VIEW
    assert mod.ClipboardCapability.WRITE in config.clipboard_permissions
    assert mod.ClipboardCapability.READ not in config.clipboard_permissions
    assert "org.example.secret" in config.privacy_classes
    assert config.confirmation_pending_limit == 9
    assert config.confirmation_pending_per_owner == 3
    assert config.confirmation_min_interval_seconds == 0.5


def test_audit_redacts_sensitive_values_and_keeps_useful_metadata() -> None:
    mod = audit_module()
    with tempfile.TemporaryDirectory() as temporary:
        old_state_home = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = temporary
        try:
            journal = mod.AuditJournal("audit.jsonl", session_id="security-test")
        finally:
            if old_state_home is None:
                os.environ.pop("XDG_STATE_HOME", None)
            else:
                os.environ["XDG_STATE_HOME"] = old_state_home
        path = journal.path
        entry = journal.record(
            "paste_text",
            target="address:0xabc",
            target_identity={"address": "0xabc", "class": "org.example.Editor", "workspace": "3"},
            args={
                "text": "super secret pasted text",
                "password": "correct horse battery staple",
                "token": "bearer-token",
                "coordinate": [12, 34],
                "path": "/home/alice/private/document.txt",
                "socketPath": "/run/user/1000/hypr/secret/.socket2.sock",
                "nested": {"output_path": pathlib.Path("/tmp/private-output.png")},
            },
            result={
                "ok": True,
                "content": "private result",
                "socketPath": "/run/user/1000/hypr/private-result/.socket2.sock",
            },
            before={
                "title": "Before",
                "tree": {"value": "private field"},
                "working-directory": "/home/alice/private-before",
            },
            after={"title": "After", "filename": "/home/alice/private-after.txt"},
            dry_run=True,
        )
        assert entry["schema_version"] == mod.SCHEMA_VERSION
        assert entry["tool"] == "paste_text"
        assert entry["dry_run"] is True
        assert entry["args"]["coordinate"] == [12, 34]
        for value in (
            entry["args"]["text"],
            entry["args"]["password"],
            entry["args"]["token"],
            entry["args"]["path"],
            entry["args"]["socketPath"],
            entry["args"]["nested"]["output_path"],
        ):
            assert value["redacted"] is True
            assert value["digest"].startswith("sha256:")
            assert value["length"] > 0
        serialized = path.read_text(encoding="utf-8")
        for secret in (
            "super secret pasted text",
            "correct horse battery staple",
            "bearer-token",
            "private result",
            "private field",
            "/home/alice/private/document.txt",
            "/run/user/1000/hypr/secret/.socket2.sock",
            "/tmp/private-output.png",
            "/run/user/1000/hypr/private-result/.socket2.sock",
            "/home/alice/private-before",
            "/home/alice/private-after.txt",
        ):
            assert secret not in serialized
        assert len(journal.read()) == 1
        decoded = json.loads(serialized)
        assert decoded["session_id"] == "security-test"
        assert decoded["timestamp"].endswith("Z")

    raw = mod.sanitize_args({"text": "allowed only by explicit opt-in"}, store_sensitive_plaintext=True)
    assert raw["text"] == "allowed only by explicit opt-in"
    path_value = mod.sanitize_args(pathlib.Path("/home/alice/private/direct.txt"))
    assert path_value["redacted"] is True
    summary = mod.summarize_state({"cwd": "/home/alice/project", "artifact": pathlib.Path("/tmp/private.bin")})
    assert summary["cwd"]["redacted"] is True
    assert summary["artifact"]["redacted"] is True


def test_audit_rotation_limits_permissions_symlinks_and_concurrency() -> None:
    mod = audit_module()
    with tempfile.TemporaryDirectory() as temporary:
        old_state_home = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = temporary
        try:
            journal = mod.AuditJournal("bounded.jsonl", session_id="bounded", max_bytes=1200, backup_count=2)
            for index in range(20):
                journal.record("click", args={"index": index}, result={"ok": True})
            paths = [journal.path, pathlib.Path(str(journal.path) + ".1"), pathlib.Path(str(journal.path) + ".2")]
            assert all(path.is_file() and not path.is_symlink() for path in paths)
            assert all(path.stat().st_size <= 1200 for path in paths)
            assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)
            for path in paths:
                for line in path.read_text(encoding="utf-8").splitlines():
                    assert isinstance(json.loads(line), dict)

            no_rotate = mod.AuditJournal("failclosed.jsonl", max_bytes=1200, backup_count=0)
            while True:
                before = no_rotate.path.read_bytes() if no_rotate.path.exists() else b""
                try:
                    no_rotate.record("click", args={"n": len(before)})
                except mod.AuditError:
                    assert no_rotate.path.read_bytes() == before
                    break

            guarded = mod.AuditJournal("guarded.jsonl", max_bytes=1200, backup_count=1)
            guarded.record("click", args={"first": True})
            guarded.max_bytes = guarded.path.stat().st_size + 1
            outside = pathlib.Path(temporary) / "outside"
            outside.write_text("unchanged", encoding="utf-8")
            pathlib.Path(str(guarded.path) + ".1").symlink_to(outside)
            try:
                guarded.record("click", args={"second": True})
            except mod.UnsafeJournalPath:
                pass
            else:
                raise AssertionError("symlinked audit backup was accepted")
            assert outside.read_text(encoding="utf-8") == "unchanged"

            concurrent_a = mod.AuditJournal("concurrent.jsonl", max_bytes=1024 * 1024)
            concurrent_b = mod.AuditJournal("concurrent.jsonl", max_bytes=1024 * 1024)
            threads = [
                threading.Thread(target=lambda j=instance: [j.record("click", args={"i": i}) for i in range(25)])
                for instance in (concurrent_a, concurrent_b)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
            assert all(not thread.is_alive() for thread in threads)
            assert len(concurrent_a.read()) == 50
        finally:
            if old_state_home is None:
                os.environ.pop("XDG_STATE_HOME", None)
            else:
                os.environ["XDG_STATE_HOME"] = old_state_home


def test_audit_never_persists_snapshot_or_accessibility_payloads() -> None:
    mod = audit_module()
    markers = {
        "png": "REAL-SNAPSHOT-PNG-MARKER",
        "image": "REAL-IMAGE-BASE64-MARKER",
        "data_url": "REAL-DATA-URL-MARKER",
        "pixels": "REAL-PIXELS-MARKER",
        "tree": "REAL-ACCESSIBILITY-TREE-MARKER",
        "ui": "REAL-BUILD-APP-SNAPSHOT-UI-TEXT-MARKER",
    }
    snapshot = {
        "app": {"name": markers["ui"], "bundleIdentifier": "org.example.Editor", "pid": 4242},
        "windowTitle": markers["ui"],
        "windowBounds": {"x": 10, "y": 20, "width": 1280, "height": 720},
        "target": "address:0xabc",
        "window": {
            "address": "0xabc",
            "pid": 4242,
            "class": "org.example.Editor",
            "title": markers["ui"],
            "initialTitle": markers["ui"],
            "at": [10, 20],
            "size": [1280, 720],
        },
        "relatedWindows": [{"address": "0xdef", "class": "org.example.Dialog", "title": markers["ui"]}],
        "relatedTargets": ["address:0xdef"],
        "screenshot": {
            "width": 1280,
            "height": 720,
            "format": "png",
            "sha256": "a" * 64,
            "screenshotPngBase64": markers["png"],
        },
        "imageBase64": markers["image"],
        "previewDataUrl": f"data:image/png;base64,{markers['data_url']}",
        "rawPixels": markers["pixels"],
        "screenshotWidth": 1280,
        "screenshotHeight": 720,
        "screenshotHash": "b" * 64,
        "imageFormat": "png",
        "snapshotId": "snap_fixture",
        "capturedAt": 1234.5,
        "windowStartTime": "123",
        "treeLines": [markers["ui"]],
        "elements": [{"index": 0, "name": markers["ui"], "value": markers["ui"], "controlType": "button"}],
        "accessibilityTree": {
            "role": "document",
            "name": markers["tree"],
            "children": [{"name": markers["tree"]}],
        },
        "accessibility": {"status": "ok", "description": markers["ui"]},
        "globalMenu": {"items": [{"label": markers["ui"], "path": [markers["ui"]]}]},
        "uiHints": {"notes": [markers["ui"]], "visibleActions": [{"name": markers["ui"]}]},
        "activeRelatedWindow": {"address": "0xdef", "title": markers["ui"]},
        "attention": {"type": "active-related-popup", "title": markers["ui"], "message": markers["ui"]},
        "safe": {"source": {"width": 1280, "height": 720}, "output": {"width": 640, "height": 360}},
    }

    # The general plaintext opt-in must not disable media/UI-state redaction.
    sanitized = mod.sanitize_args(snapshot, store_sensitive_plaintext=True)
    assert sanitized["screenshot"]["omitted"] is True
    assert sanitized["screenshot"]["metadata"] == {
        "width": 1280,
        "height": 720,
        "format": "png",
        "sha256": "a" * 64,
    }
    for key in ("imageBase64", "previewDataUrl", "rawPixels", "accessibilityTree"):
        assert sanitized[key]["omitted"] is True
    for key in ("elements", "globalMenu", "uiHints", "relatedWindows", "activeRelatedWindow"):
        assert sanitized[key]["omitted"] is True
    assert sanitized["window"]["address"] == "0xabc"
    assert sanitized["window"]["class"] == "org.example.Editor"
    assert sanitized["window"]["title"]["redacted"] is True
    assert sanitized["windowTitle"]["redacted"] is True
    assert sanitized["app"]["name"]["redacted"] is True
    assert sanitized["screenshotWidth"] == 1280
    assert sanitized["screenshotHeight"] == 720
    assert sanitized["screenshotHash"] == "b" * 64
    assert sanitized["imageFormat"] == "png"
    hostile_metadata = mod.sanitize_args(
        {"screenshot": {"format": markers["image"], "digest": markers["tree"], "width": 12}}
    )
    assert hostile_metadata["screenshot"]["metadata"] == {"width": 12}

    with tempfile.TemporaryDirectory() as temporary:
        old_state_home = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = temporary
        try:
            journal = mod.AuditJournal(
                "snapshot-audit.jsonl",
                session_id="snapshot-security-test",
                store_sensitive_plaintext=True,
            )
        finally:
            if old_state_home is None:
                os.environ.pop("XDG_STATE_HOME", None)
            else:
                os.environ["XDG_STATE_HOME"] = old_state_home
        entry = journal.record(
            "get_app_state",
            args={"snapshot": snapshot, "screenshotPngBase64": markers["png"]},
            result={"snapshot": snapshot, "pngBase64": markers["png"]},
            before=snapshot,
            after={**snapshot, "outputWidth": 640, "outputHeight": 360},
        )
        serialized = journal.path.read_text(encoding="utf-8")

    for marker in markers.values():
        assert marker not in serialized
    assert entry["args"]["screenshotPngBase64"]["omitted"] is True
    assert entry["result"]["pngBase64"]["omitted"] is True
    assert entry["before"]["screenshot"]["metadata"]["width"] == 1280
    assert entry["before"]["screenshot"]["metadata"]["height"] == 720
    assert entry["before"]["screenshot"]["metadata"]["sha256"] == "a" * 64
    assert entry["after"]["outputWidth"] == 640
    assert entry["after"]["outputHeight"] == 360


def test_audit_redacts_launch_commands_urls_and_process_output() -> None:
    mod = audit_module()
    marker = "REAL-LAUNCH-CREDENTIAL-MARKER"
    launch_args = {
        "command": f"browser --url https://example.invalid/?token={marker}",
        "argv": ["browser", "--query", marker],
        "args": {"query": marker, "safeFlag": True},
        "url": f"https://example.invalid/open?access_token={marker}",
        "callbackUrl": f"https://callback.invalid/?code={marker}",
        "query": marker,
    }
    backend_result = {
        "ok": True,
        "stdout": f"launched {marker}",
        "stderr": f"warning {marker}",
        "output": {"line": marker},
        "hyprctlOutput": f"Window title: {marker}",
    }

    with tempfile.TemporaryDirectory() as temporary:
        old_state_home = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = temporary
        try:
            journal = mod.AuditJournal("launch-audit.jsonl", session_id="launch-security-test")
        finally:
            if old_state_home is None:
                os.environ.pop("XDG_STATE_HOME", None)
            else:
                os.environ["XDG_STATE_HOME"] = old_state_home
        entry = journal.record(
            "launch_app",
            args=launch_args,
            result=backend_result,
            before={"commandLine": launch_args["command"]},
            after={"process": backend_result},
        )
        serialized = journal.path.read_text(encoding="utf-8")

    assert marker not in serialized
    for key in ("command", "argv", "args", "url", "callbackUrl", "query"):
        assert entry["args"][key]["redacted"] is True
        assert entry["args"][key]["digest"].startswith("sha256:")
        assert entry["args"][key]["length"] > 0
    for key in ("stdout", "stderr", "output", "hyprctlOutput"):
        assert entry["result"][key]["redacted"] is True
        assert entry["result"][key]["digest"].startswith("sha256:")
    assert entry["before"]["commandLine"]["redacted"] is True
    assert entry["after"]["process"]["stdout"]["redacted"] is True


def test_audit_replay_defaults_to_plan_only_and_rejects_unsafe_records() -> None:
    mod = audit_module()
    assert mod._identity_mismatch(
        {"address": "0xabc", "pid": "123", "processStartTime": "456"},
        {"address": "0xabc", "pid": "123"},
    )
    records = [
        {
            "schema_version": mod.SCHEMA_VERSION,
            "event_id": "one",
            "timestamp": "2099-01-01T00:00:00Z",
            "tool": "click",
            "target": "address:0xabc",
            "target_identity": {"address": "0xabc", "class": "org.example.Editor"},
            "args": {"element_index": "4.2"},
        },
        {
            "schema_version": mod.SCHEMA_VERSION,
            "event_id": "two",
            "timestamp": "2099-01-01T00:00:00Z",
            "tool": "paste_text",
            "target": "address:0xabc",
            "target_identity": {"address": "0xabc", "class": "org.example.Editor"},
            "args": {"text": {"redacted": True, "digest": "sha256:deadbeef", "length": 3}},
        },
    ]

    def resolve_target(_: Any) -> dict[str, str]:
        return {"address": "0xabc", "class": "org.example.Editor"}

    preflight = mod.preflight_replay(records, resolve_target=resolve_target)
    assert preflight.plan_only is True
    assert all(not decision.executable for decision in preflight.decisions)
    reasons = {reason for decision in preflight.decisions for reason in decision.reasons}
    assert "ephemeral_element_id" in reasons
    assert "digested_sensitive_data" in reasons


def mcp_tool_list(module: Any) -> dict[str, dict[str, Any]]:
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    response = module.handle(message)
    assert response is not None
    return {tool["name"]: tool for tool in response["result"]["tools"]}


def mcp_tool_call(module: Any, name: str, arguments: dict[str, Any], request_id: int = 1) -> dict[str, Any]:
    message = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    response_value = module.handle(message)
    assert response_value is not None
    assert response_value["id"] == request_id
    return response_value["result"]


def test_mcp_default_view_allows_inventory_through_handle() -> None:
    with security_environment(
        SECURITY_DEFAULT_AUTHORIZATION="view",
        MUTATION_LEASE_REQUIRED="0",
        HUMAN_TAKEOVER="0",
    ):
        module = load_path(MCP, "mcp_default_view_inventory")

    windows = [
        {"address": "0x1", "pid": 101, "class": "org.example.Editor", "title": "Editor"},
        {"address": "0x2", "pid": 102, "class": "org.example.Terminal", "title": "Terminal"},
    ]
    module.list_hypr_windows = lambda: windows
    module.process_start_time = lambda pid: {101: "1001", 102: "1002"}.get(pid, "")
    module.call_ctl = lambda args: {
        "available": True,
        "screenLocked": False,
        "layerSurfaceActive": False,
        "keyboardGrabActive": False,
        "panicActive": False,
    } if args == ["guard", "--json"] else (_ for _ in ()).throw(AssertionError(args))

    for request_id, tool_name in enumerate(("list_apps", "list_windows"), start=10):
        result = mcp_tool_call(module, tool_name, {}, request_id)
        assert result["isError"] is False
        returned = result["structuredContent"]["windows"]
        assert [item["address"] for item in returned] == ["0x1", "0x2"]
        assert [item["target"] for item in returned] == [
            "address:0x1@pid=101@start=1001",
            "address:0x2@pid=102@start=1002",
        ]


def test_mcp_panic_handle_flow_requires_external_resume_approval() -> None:
    old_runtime = os.environ.get("XDG_RUNTIME_DIR")
    with tempfile.TemporaryDirectory() as temporary:
        os.environ["XDG_RUNTIME_DIR"] = temporary
        try:
            with security_environment(
                SECURITY_DEFAULT_AUTHORIZATION="full",
                MUTATION_LEASE_REQUIRED="0",
                HUMAN_TAKEOVER="0",
            ):
                module = load_path(MCP, "mcp_panic_handle_flow")

            native_panic = False
            panic_modes: list[str] = []

            def fake_ctl(args: list[str]) -> dict[str, Any]:
                nonlocal native_panic
                if args == ["guard", "--json"]:
                    return {
                        "available": True,
                        "screenLocked": False,
                        "layerSurfaceActive": False,
                        "keyboardGrabActive": False,
                        "panicActive": native_panic,
                    }
                if len(args) == 3 and args[0] == "panic" and args[2] == "--json":
                    mode = args[1]
                    panic_modes.append(mode)
                    if mode == "panic":
                        native_panic = True
                    elif mode == "resume":
                        native_panic = False
                    return {"ok": True, "action": mode, "panicActive": native_panic}
                raise AssertionError(args)

            launched: list[dict[str, Any]] = []

            def fake_launch(args: dict[str, Any]) -> dict[str, Any]:
                launched.append(dict(args))
                return module.mcp_text("launched", structured={"ok": True})

            module.call_ctl = fake_ctl
            module.resolve_hypr_window = lambda selector: {
                "address": "0xabc",
                "class": "org.example.TestApp",
                "workspace": {"name": "1"},
                "title": str(selector),
            }
            module.acquire_process_mutation_lease = lambda: contextlib.nullcontext()
            module.SEMANTIC_TOOLS["launch_app"] = fake_launch

            cancelled = mcp_tool_call(module, "panic", {"mode": "cancel"}, 20)
            assert cancelled["isError"] is False
            assert module.SERVER_PANIC_ACTIVE is False
            assert native_panic is False

            mutation = mcp_tool_call(module, "launch_app", {"app": "safe-test-app"}, 21)
            assert mutation["isError"] is False, mutation
            assert launched == [{"app": "safe-test-app"}]

            unconfirmed_resume = mcp_tool_call(module, "panic", {"mode": "resume"}, 22)
            assert unconfirmed_resume["isError"] is True
            assert unconfirmed_resume["structuredContent"]["security"]["code"] == "confirmation_required"
            assert "resume" not in panic_modes

            challenge_result = mcp_tool_call(
                module,
                "request_confirmation",
                {"tool_name": "panic", "arguments": {"mode": "resume"}},
                23,
            )
            assert challenge_result["isError"] is False
            challenge_id = challenge_result["structuredContent"]["challengeId"]

            panicked = mcp_tool_call(module, "panic", {"mode": "panic"}, 24)
            assert panicked["isError"] is False
            assert module.SERVER_PANIC_ACTIVE is True
            assert native_panic is True

            blocked_mutation = mcp_tool_call(module, "launch_app", {"app": "must-not-launch"}, 25)
            assert blocked_mutation["isError"] is True
            assert blocked_mutation["structuredContent"]["security"]["code"] == "panic_active"
            assert launched == [{"app": "safe-test-app"}]

            pending_resume = mcp_tool_call(
                module,
                "panic",
                {"mode": "resume", "confirmation_token": challenge_id},
                26,
            )
            assert pending_resume["isError"] is True
            assert pending_resume["structuredContent"]["security"]["code"] == "confirmation_pending"
            assert "resume" not in panic_modes

            # This helper models a separate, trusted local approver. The MCP
            # API itself exposes challenge creation but no approval endpoint.
            physically_approve(mcp_policy_runtime(module), challenge_id)
            resumed = mcp_tool_call(
                module,
                "panic",
                {"mode": "resume", "confirmation_token": challenge_id},
                27,
            )
            assert resumed["isError"] is False
            assert panic_modes == ["cancel", "panic", "resume"]
            assert module.SERVER_PANIC_ACTIVE is False
            assert native_panic is False

            mutation_after_resume = mcp_tool_call(module, "launch_app", {"app": "safe-test-app-2"}, 28)
            assert mutation_after_resume["isError"] is False
            assert launched[-1] == {"app": "safe-test-app-2"}
        finally:
            if old_runtime is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = old_runtime


def test_mcp_annotations_are_conservative() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_annotations")
    tools = mcp_tool_list(module)
    readonly = {
        "list_apps",
        "list_windows",
        "get_app_state",
        "read_app_state",
        "screenshot",
        "get_screenshot",
        "get_cursor_position",
        "wait",
        "wait_for_window",
        "wait_for_close",
        "security_status",
        "ocr",
        "get_marks",
        "list_workspaces",
    }
    mutating = set(tools) - readonly - {"computer"}
    for name in readonly:
        annotations = tools[name]["annotations"]
        assert annotations["readOnlyHint"] is True, name
    for name in mutating:
        annotations = tools[name]["annotations"]
        assert annotations["readOnlyHint"] is False, name
        assert annotations["destructiveHint"] is True, name
        assert annotations["openWorldHint"] is True, name
    computer_annotations = tools["computer"]["annotations"]
    assert computer_annotations["readOnlyHint"] is False
    assert computer_annotations["destructiveHint"] is True
    assert computer_annotations["openWorldHint"] is True


def test_mcp_readonly_hides_all_mutations() -> None:
    with security_environment(READONLY="1"):
        module = load_path(MCP, "mcp_readonly")
    tools = mcp_tool_list(module)
    allowed = {
        "computer",
        "list_apps",
        "list_windows",
        "get_app_state",
        "read_app_state",
        "screenshot",
        "get_screenshot",
        "get_cursor_position",
        "wait",
        "wait_for_window",
        "wait_for_close",
        "security_status",
        "panic",
        "ocr",
        "get_marks",
        "list_workspaces",
    }
    assert set(tools) == allowed
    actions = set(tools["computer"]["inputSchema"]["properties"]["action"]["enum"])
    forbidden = {
        "launch",
        "launch_app",
        "open_app",
        "move",
        "click",
        "doubleclick",
        "press",
        "release",
        "scroll",
        "drag",
        "key",
        "type",
        "copy_text",
        "paste_text",
        "paste_file",
        "paste_image",
        "session",
        "activate_menu_item",
        "left_click",
        "right_click",
        "middle_click",
        "double_click",
        "triple_click",
        "hover",
        "left_click_drag",
        "click_text",
        "click_mark",
        "type_into",
        "sequence",
        "manage_window",
        "manage_workspace",
    }
    assert actions.isdisjoint(forbidden)
    assert set(tools["panic"]["inputSchema"]["properties"]["mode"]["enum"]) == {"panic", "cancel", "status"}


def test_mcp_dry_run_never_calls_backend_and_returns_security_metadata() -> None:
    with security_environment(DRYRUN="1"):
        module = load_path(MCP, "mcp_dry_run")

    def forbidden_backend(*_: Any, **__: Any) -> Any:
        raise AssertionError("dry-run reached compositor/backend")

    module.call_ctl = forbidden_backend
    module.resolve_hypr_window = lambda selector: {
        "address": "0xabc",
        "class": "org.example.Editor",
        "workspace": {"name": "1"},
        "pid": 123,
        "processStartTime": "456",
    }
    message = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "computer",
            "arguments": {
                "action": "click",
                "target": "address:0xabc",
                "coordinate_space": "global",
                "x": 10,
                "y": 20,
            },
        },
    }
    response = module.handle(message)
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    security = result["structuredContent"]["security"]
    assert security["dryRun"] is True
    assert security["execute"] is False
    assert security["details"]["action"] == "click"


def test_mcp_privacy_filters_inventory_and_blocks_full_capture() -> None:
    with security_environment(PRIVACY_CLASSES="org.example.Secret"):
        module = load_path(MCP, "mcp_privacy")
    windows = [
        {"address": "0x1", "pid": 101, "class": "org.example.Editor", "title": "Visible"},
        {"address": "0x2", "pid": 102, "class": "org.example.Secret", "title": "Do not disclose"},
    ]
    module.list_hypr_windows = lambda: windows
    module.process_start_time = lambda pid: {101: "1001", 102: "1002"}.get(pid, "")
    result = module.tool_list_apps({})["structuredContent"]
    assert [window["address"] for window in result["windows"]] == ["0x1"]
    try:
        module.require_safe_full_capture(None)
    except RuntimeError as error:
        assert "privacy-excluded" in str(error)
    else:
        raise AssertionError("full capture was allowed with a private window visible")


def test_mcp_clipboard_read_is_opt_in_and_confirmation_binds_payload() -> None:
    old_runtime = os.environ.get("XDG_RUNTIME_DIR")
    with tempfile.TemporaryDirectory() as temporary:
        os.environ["XDG_RUNTIME_DIR"] = temporary
        try:
            with security_environment(SECURITY_DEFAULT_AUTHORIZATION="full"):
                module = load_path(MCP, "mcp_clipboard_confirmation")
            default_caps = module.action_clipboard_capabilities("paste_text", {"text": "first"})
            assert module.ClipboardCapability.READ not in default_caps
            restore_caps = module.action_clipboard_capabilities(
                "paste_text", {"text": "first", "restore_clipboard": True}
            )
            assert module.ClipboardCapability.READ in restore_caps

            original = module.build_security_request("type_text", {"text": "first"}, force_destructive=True)
            changed = module.build_security_request("type_text", {"text": "second"}, force_destructive=True)
            challenge = module.SECURITY_POLICY.request_confirmation(original)
            physically_approve(mcp_policy_runtime(module), challenge)
            changed = module.ActionRequest(
                owner=changed.owner,
                action=changed.action,
                required_level=changed.required_level,
                mutating=changed.mutating,
                target=changed.target,
                clipboard_capabilities=changed.clipboard_capabilities,
                destructive=True,
                confirmation_token=challenge,
                confirmation_context=changed.confirmation_context,
            )
            assert module.SECURITY_POLICY.acquire_mutation_lease(module.SECURITY_OWNER)
            decision = module.SECURITY_POLICY.evaluate(changed)
            assert decision.code == module.DecisionCode.CONFIRMATION_INVALID
        finally:
            if old_runtime is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = old_runtime


def test_mcp_high_risk_element_intent_uses_cached_semantics() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_semantic_confirmation")
    module.SNAPSHOTS["editor"] = {
        "elements": [
            {"index": 7, "name": "Submit purchase", "value": "", "controlType": "button"},
        ]
    }
    args = {"app": "editor", "element_index": "7"}
    assert module.action_is_high_risk("click", args) is True
    assert module.cached_action_intent(args)["name"] == "Submit purchase"


def test_mcp_security_status_is_structured_and_secret_free() -> None:
    with security_environment(PRIVACY_CLASSES="org.example.Secret"):
        module = load_path(MCP, "mcp_security_status")
    structured = module.tool_security_status({})["structuredContent"]
    assert structured["policy"]["readonly"] is False
    assert isinstance(structured["readiness"]["checks"], list)
    encoded = json.dumps(structured, sort_keys=True)
    privacy = next(check for check in structured["readiness"]["checks"] if check["id"] == "privacy")
    assert privacy["details"]["configured"] is True
    assert "confirmationToken" not in encoded


def test_mcp_mutation_schemas_accept_confirmation_tokens() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_confirmation_schema")
    tools = mcp_tool_list(module)
    for name, tool in tools.items():
        annotations = tool.get("annotations", {})
        if name == "computer" or annotations.get("readOnlyHint") is False:
            assert "confirmation_token" in tool["inputSchema"]["properties"], name


def test_mcp_feature_tools_have_direct_computer_parity_and_fail_closed_levels() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_feature_parity")
    tools = mcp_tool_list(module)
    names = {
        "ocr", "click_text", "get_marks", "click_mark", "type_into",
        "sequence", "manage_window", "list_workspaces", "manage_workspace",
    }
    assert names <= set(tools)
    actions = set(tools["computer"]["inputSchema"]["properties"]["action"]["enum"])
    assert names <= actions
    assert module.action_required_level("ocr") == module.AuthorizationLevel.VIEW
    assert module.action_required_level("click_text") == module.AuthorizationLevel.CLICK
    assert module.action_required_level("type_into") == module.AuthorizationLevel.FULL
    assert module.action_required_level("unknown-future-action") == module.AuthorizationLevel.FULL


def test_mcp_visual_cache_rejects_hash_and_identity_changes() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_visual_cache")
    raw = b"fixture-image"
    window = {"address": "0xabc", "pid": 42, "at": [10, 20], "size": [300, 200], "class": "Editor"}
    snapshot = {
        "window": dict(window),
        "windowBounds": {"x": 10.0, "y": 20.0, "width": 300.0, "height": 200.0},
        "windowStartTime": "123",
        "capturedAt": module.time.time(),
        "screenshot": {"width": 300, "height": 200, "sha256": module.hashlib.sha256(raw).hexdigest()},
    }
    token = module.cache_visual("snapshot", snapshot, snapshot)
    module.resolve_hypr_window = lambda _selector: dict(window)
    module.process_start_time = lambda _pid: "123"
    module.screenshot_for_window = lambda _window: ({"width": 300, "height": 200}, module.base64.b64encode(raw).decode())
    assert module.visual_cache_entry(token, "snapshot")["address"] == "0xabc"
    module.screenshot_for_window = lambda _window: ({"width": 300, "height": 200}, module.base64.b64encode(b"changed").decode())
    try:
        module.visual_cache_entry(token, "snapshot")
    except RuntimeError as exc:
        assert "hash changed" in str(exc)
    else:
        raise AssertionError("changed screenshot hash was accepted")
    module.screenshot_for_window = lambda _window: ({"width": 300, "height": 200}, module.base64.b64encode(raw).decode())
    module.resolve_hypr_window = lambda _selector: {**window, "pid": 99}
    try:
        module.visual_cache_entry(token, "snapshot")
    except RuntimeError as exc:
        assert "pid changed" in str(exc)
    else:
        raise AssertionError("reused address with a new pid was accepted")


def test_mcp_workspace_target_is_synthetic_and_confinable() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_workspace_target")
    target = module.security_target({"workspace": "special:scratch"}, resolve=True)
    assert target is not None
    assert target.address == "workspace:special:scratch"
    assert target.class_name == "hyprland-workspace"
    assert target.workspace == "special:scratch"


def test_mcp_get_marks_handler_and_computer_alias_use_editable_elements() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_marks_handler")
    raw = b"fixture"
    snapshot = {
        "snapshotId": "snapshot_test",
        "capturedAt": module.time.time(),
        "target": "address:0xabc",
        "app": {"pid": 42},
        "window": {"address": "0xabc", "pid": 42, "class": "Editor", "at": [0, 0], "size": [100, 80]},
        "windowBounds": {"x": 0.0, "y": 0.0, "width": 100.0, "height": 80.0},
        "windowStartTime": "123",
        "screenshot": {"id": "snapshot_test", "sha256": module.hashlib.sha256(raw).hexdigest(), "width": 100, "height": 80},
        "screenshotPngBase64": module.base64.b64encode(raw).decode(),
        "elements": [{"index": 7, "name": "Editor", "controlType": "entry", "editable": True, "frame": {"x": 5, "y": 6, "width": 40, "height": 20}}],
    }
    entry = {"kind": "snapshot", "snapshot": snapshot, "payload": snapshot, "address": "0xabc", "sha256": snapshot["screenshot"]["sha256"]}
    module.visual_cache_entry = lambda *_args, **_kwargs: entry
    module.resolve_hypr_window = lambda _selector: snapshot["window"]
    module.render_marks = lambda _raw, candidates, **_kwargs: (
        b"overlay",
        {
            "output": {"format": "png"},
            "marks": [{"markId": "1", "source": "element", "screenshotBox": candidates[0]["frame"], "elementIndex": 7, "name": "Editor", "screenshotPoint": {"x": 25, "y": 16}}],
        },
    )
    direct = module.tool_get_marks({"app": "address:0xabc", "snapshot_id": "snapshot_test"})
    assert direct["structuredContent"]["marks"][0]["elementIndex"] == 7
    compat = module.computer({"action": "get_marks", "app": "address:0xabc", "snapshot_id": "snapshot_test"})
    assert compat["structuredContent"]["marks"][0]["frame"]["width"] == 40


def test_mcp_sequence_envelope_does_not_claim_full_or_batch_lease() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_sequence_envelope")
    request = module.build_security_request("sequence", {"steps": [{"action": "wait", "arguments": {"duration": 0}}]})
    assert request.mutating is False
    assert request.required_level == module.AuthorizationLevel.VIEW
    assert module.action_is_mutating("sequence") is True  # schema remains hidden in readonly mode


def test_mcp_sequence_request_dry_run_is_non_consuming_and_backend_free() -> None:
    with security_environment(SECURITY_MUTATION_LEASE_REQUIRED="1"):
        module = load_path(MCP, "mcp_sequence_dryrun")
    module.call_ctl = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("dry-run touched backend"))
    module.resolve_hypr_window = lambda selector: {
        "address": "0xabc",
        "class": "org.example.Editor",
        "workspace": {"name": "safe"},
        "pid": 123,
        "processStartTime": "456",
    }
    result = module.tool_sequence(
        {
            "dry_run": True,
            "steps": [
                {
                    "action": "press_key",
                    "arguments": {
                        "app": "address:0xabc",
                        "key": "f4",
                        "modifiers": "alt",
                        "confirmation_token": "approved-token-must-not-be-read",
                    },
                }
            ],
        }
    )["structuredContent"]
    assert result["dryRun"] is True
    assert result["steps"][0]["status"] == "dry_run"
    policy = result["steps"][0]["policy"]
    assert policy["details"]["wouldRequireConfirmation"] is True
    module.resolve_hypr_window = lambda selector: {
        "address": "0xabc" if selector == "allowed" else "0xdef",
        "class": "org.example.Editor",
        "workspace": {"name": "safe"},
        "pid": 123 if selector == "allowed" else 456,
        "processStartTime": "111" if selector == "allowed" else "222",
    }
    conflict = module.tool_sequence(
        {
            "dry_run": True,
            "steps": [{"action": "click", "arguments": {"app": "allowed", "target": "restricted", "x": 1, "y": 1}}],
        }
    )["structuredContent"]
    assert conflict["steps"][0]["status"] == "policy_error"
    assert "conflicting app/target/address" in conflict["steps"][0]["error"]


def test_mcp_high_risk_key_forms_and_default_special_equivalence() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_key_special")
    assert module.action_is_high_risk("press_key", {"key": "f4", "modifiers": "alt"})
    assert module.action_is_high_risk("press_key", {"key": "w", "modifiers": "shift+ctrl"})
    assert module.action_is_high_risk("press_key", {"keycode": 30})
    states = [[{"name": "special:special"}], []]
    module.visible_special_workspaces = lambda: {item["name"] for item in states[0]}

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def dispatch(*_args: Any, **_kwargs: Any) -> Any:
        states[0] = states[1]
        return Proc()

    original_run = module.subprocess.run
    module.subprocess.run = dispatch
    try:
        result = module.dispatch_special_workspace("special", "hide_special")
    finally:
        module.subprocess.run = original_run
    assert result["before"]["visible"] is True
    assert result["after"]["visible"] is False


def test_mcp_policy_target_is_bound_across_direct_and_computer_paths() -> None:
    for tool_name, arguments in (
        ("get_app_state", {"app": "Editor"}),
        ("computer", {"action": "get_app_state", "app": "Editor"}),
    ):
        with security_environment():
            module = load_path(MCP, f"mcp_target_binding_{tool_name}")
        windows = [
            {
                "address": "0xabc",
                "class": "org.example.Editor",
                "workspace": {"name": "safe"},
                "pid": 100,
                "processStartTime": "111",
            },
            {
                "address": "0xabc",
                "class": "org.example.Editor",
                "workspace": {"name": "safe"},
                "pid": 200,
                "processStartTime": "222",
            },
        ]
        resolve_calls = 0

        def resolve(_selector: str) -> dict[str, Any]:
            nonlocal resolve_calls
            value = windows[min(resolve_calls, len(windows) - 1)]
            resolve_calls += 1
            return value

        invoked: list[bool] = []
        module.resolve_hypr_window = resolve
        module.call_ctl = lambda *_args, **_kwargs: {
            "available": True,
            "screenLocked": False,
            "layerSurfaceActive": False,
            "keyboardGrabActive": False,
            "panicActive": False,
        }
        module.SEMANTIC_TOOLS["get_app_state"] = lambda _args: invoked.append(True) or module.result_text({"ok": True})
        module.computer = lambda _args: invoked.append(True) or module.result_text({"ok": True})
        response_value = mcp_tool_call(module, tool_name, arguments)
        assert response_value["isError"] is True
        assert "identity changed" in response_value["content"][0]["text"]
        assert invoked == []


def test_mcp_dry_run_resolves_real_identity_and_preflights_named_destination_scope() -> None:
    with security_environment(SECURITY_DRY_RUN="1", SECURITY_CONFINE_WORKSPACES="safe"):
        module = load_path(MCP, "mcp_dryrun_destination_scope")
    module.resolve_hypr_window = lambda _selector: {
        "address": "0xabc",
        "class": "org.example.Editor",
        "workspace": {"name": "safe"},
        "pid": 123,
        "processStartTime": "456",
    }
    safe = module.build_security_request(
        "manage_window",
        {"app": "Editor", "window_action": "move_to_workspace", "workspace": "name:safe"},
    )
    assert safe.target.workspace == "safe"
    assert safe.scope_targets[0].workspace == "safe"
    assert module.SECURITY_POLICY.evaluate(safe, module.GuardInputs()).allowed
    unsafe = module.build_security_request(
        "manage_window",
        {"app": "Editor", "window_action": "move_to_workspace", "workspace": "name:outside"},
    )
    decision = module.SECURITY_POLICY.evaluate(unsafe, module.GuardInputs())
    assert decision.allowed is False
    assert decision.code == module.DecisionCode.OUT_OF_SCOPE


def test_mcp_reused_launch_never_gains_launched_only_scope() -> None:
    for tool_name in ("launch_app", "computer"):
        with security_environment(
            SECURITY_CONFINE_LAUNCHED="1",
            SECURITY_MUTATION_LEASE_REQUIRED="0",
            SECURITY_HUMAN_TAKEOVER="0",
        ):
            module = load_path(MCP, f"mcp_launch_provenance_{tool_name}")
        module.call_ctl = lambda *_args, **_kwargs: {
            "available": True,
            "screenLocked": False,
            "layerSurfaceActive": False,
            "keyboardGrabActive": False,
            "panicActive": False,
        }
        module.acquire_process_mutation_lease = lambda: contextlib.nullcontext()
        reused = {
            "address": "0xabc",
            "class": "org.example.Existing",
            "workspace": {"name": "1"},
            "pid": 100,
            "processStartTime": "111",
        }
        created = {
            "address": "0xdef",
            "class": "org.example.Created",
            "workspace": {"name": "1"},
            "pid": 200,
            "processStartTime": "222",
        }

        def fake_launch(arguments: dict[str, Any]) -> dict[str, Any]:
            if arguments.get("app") == "existing":
                payload = {"ok": True, "reused": True, "window": reused, "newWindows": []}
            else:
                payload = {"ok": True, "reused": False, "window": created, "newWindows": [created]}
            return module.mcp_text("launch", structured=payload)

        module.SEMANTIC_TOOLS["launch_app"] = fake_launch
        module.computer = fake_launch
        reused_args = {"app": "existing"}
        created_args = {"app": "created"}
        if tool_name == "computer":
            reused_args["action"] = "launch_app"
            created_args["action"] = "launch_app"
        assert mcp_tool_call(module, tool_name, reused_args)["isError"] is False
        assert module.SECURITY_POLICY._in_scope(module.WindowIdentity.from_window(reused)) is False
        assert mcp_tool_call(module, tool_name, created_args)["isError"] is False
        assert module.SECURITY_POLICY._in_scope(module.WindowIdentity.from_window(created)) is True


def test_mcp_arbitrary_launch_payloads_require_confirmation_direct_and_computer() -> None:
    with security_environment(SECURITY_MUTATION_LEASE_REQUIRED="0", SECURITY_HUMAN_TAKEOVER="0"):
        module = load_path(MCP, "mcp_launch_confirmation")
    module.call_ctl = lambda *_args, **_kwargs: {
        "available": True, "screenLocked": False, "layerSurfaceActive": False,
        "keyboardGrabActive": False, "panicActive": False,
    }
    module.acquire_process_mutation_lease = lambda: contextlib.nullcontext()
    invoked: list[dict[str, Any]] = []

    def fake_launch(arguments: dict[str, Any]) -> dict[str, Any]:
        invoked.append(dict(arguments))
        return module.mcp_text("launch", structured={"ok": True, "reused": True})

    module.SEMANTIC_TOOLS["launch_app"] = fake_launch
    module.SEMANTIC_TOOLS["open_app"] = fake_launch
    module.computer = fake_launch
    risky = (
        ("launch_app", {"command": "rm -rf /tmp/example"}),
        ("open_app", {"app": "bash -c 'echo unsafe'"}),
        ("computer", {"action": "launch_app", "app": "python3", "args": ["-c", "print(1)"]}),
        ("launch_app", {"app": "rm", "url": "/tmp/example"}),
        ("computer", {"action": "launch_app", "app": "rm", "url": "/tmp/example"}),
    )
    for index, (tool_name, arguments) in enumerate(risky, start=200):
        result = mcp_tool_call(module, tool_name, arguments, index)
        assert result["isError"] is True
        assert result["structuredContent"]["security"]["code"] == "confirmation_required"
    assert invoked == []
    assert mcp_tool_call(module, "launch_app", {"app": "firefox"}, 210)["isError"] is False
    assert invoked == [{"app": "firefox"}]


def test_mcp_conflicting_selectors_fail_before_all_backend_paths() -> None:
    with security_environment(
        SECURITY_CONFINE_CLASSES="org.example.Allowed",
        SECURITY_PRIVACY_CLASSES="org.example.Restricted",
        SECURITY_MUTATION_LEASE_REQUIRED="0",
        SECURITY_HUMAN_TAKEOVER="0",
    ):
        module = load_path(MCP, "mcp_confused_deputy")
    allowed = {"address": "0xa", "class": "org.example.Allowed", "workspace": {"name": "1"}, "pid": 1, "processStartTime": "11"}
    restricted = {"address": "0xb", "class": "org.example.Restricted", "workspace": {"name": "1"}, "pid": 2, "processStartTime": "22"}
    module.resolve_hypr_window = lambda selector: allowed if selector in {"allowed", "address:0xa"} else restricted
    module.call_ctl = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("backend called"))
    invoked: list[str] = []
    direct = (
        ("click", {"x": 1, "y": 1}),
        ("press_key", {"key": "a"}),
        ("type_text", {"text": "x", "method": "keys"}),
        ("paste_text", {"text": "x"}),
        ("session", {"session_action": "begin"}),
        ("manage_window", {"window_action": "focus"}),
        ("manage_workspace", {"workspace_action": "move_window", "workspace": "1"}),
    )
    for index, (tool_name, extra) in enumerate(direct, start=220):
        module.SEMANTIC_TOOLS[tool_name] = lambda _args, n=tool_name: invoked.append(n) or module.result_text({"ok": True})
        arguments = {"app": "allowed", "target": "address:0xb", **extra}
        result = mcp_tool_call(module, tool_name, arguments, index)
        assert result["isError"] is True
        assert "conflicting app/target/address" in result["content"][0]["text"]
        compat = mcp_tool_call(module, "computer", {"action": tool_name, **arguments}, index + 100)
        assert compat["isError"] is True
    assert invoked == []


def test_mcp_prepare_conflict_writes_one_sanitized_error_audit() -> None:
    old_state_home = os.environ.get("XDG_STATE_HOME")
    with tempfile.TemporaryDirectory() as temporary:
        os.environ["XDG_STATE_HOME"] = temporary
        try:
            with security_environment(
                SECURITY_AUDIT="1",
                SECURITY_AUDIT_NAME="prepare-failure.jsonl",
                SECURITY_MUTATION_LEASE_REQUIRED="0",
                SECURITY_HUMAN_TAKEOVER="0",
            ):
                module = load_path(MCP, "mcp_prepare_failure_audit")
        finally:
            if old_state_home is None:
                os.environ.pop("XDG_STATE_HOME", None)
            else:
                os.environ["XDG_STATE_HOME"] = old_state_home

        allowed = {
            "address": "0xa",
            "class": "org.example.Allowed",
            "workspace": {"name": "1"},
            "pid": 1,
            "processStartTime": "11",
        }
        restricted = {
            "address": "0xb",
            "class": "org.example.Restricted",
            "workspace": {"name": "1"},
            "pid": 2,
            "processStartTime": "22",
        }
        module.resolve_hypr_window = (
            lambda selector: allowed if selector in {"allowed", "address:0xa"} else restricted
        )
        module.call_ctl = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("backend called")
        )
        arguments = {
            "app": "allowed",
            "target": "address:0xb",
            "x": 1,
            "y": 1,
            "text": "must-not-appear-in-audit",
            "confirmation_token": "must-not-appear-token",
        }
        result = mcp_tool_call(module, "click", arguments, 229)
        original_error = "conflicting app/target/address selectors resolve to different windows"
        assert result["isError"] is True
        assert result["content"] == [{"type": "text", "text": original_error}]

        assert module.SECURITY_AUDIT is not None
        records = module.SECURITY_AUDIT.read()
        assert len(records) == 1
        record = records[0]
        assert record["tool"] == "click"
        assert record["result"]["isError"] is True
        assert record["args"]["text"]["redacted"] is True
        assert record["args"]["confirmation_token"]["redacted"] is True
        raw_journal = module.SECURITY_AUDIT.path.read_text(encoding="utf-8")
        assert "must-not-appear-in-audit" not in raw_journal
        assert "must-not-appear-token" not in raw_journal

        class BrokenJournal:
            def record(self, *_args: Any, **_kwargs: Any) -> None:
                raise OSError("journal unavailable")

        durable_journal = module.SECURITY_AUDIT
        module.SECURITY_AUDIT = BrokenJournal()
        result = mcp_tool_call(module, "click", arguments, 230)
        assert result["isError"] is True
        assert result["content"] == [{"type": "text", "text": original_error}]
        assert len(durable_journal.read()) == 1


def test_mcp_atspi_failure_never_falls_back_and_auto_declares_clipboard() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_atspi_no_fallback")
    assert module.ClipboardCapability.WRITE in module.action_clipboard_capabilities("type_text", {"method": "auto", "text": "x"})
    assert not module.action_clipboard_capabilities("type_text", {"method": "atspi", "text": "x"})
    module.current_snapshot = lambda _app: {"target": "address:0xa", "elements": []}
    module.control_overlay = lambda *_args, **_kwargs: None
    module.atspi_insert_text_isolated = lambda *_args, **_kwargs: False
    module.type_text = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fallback called"))
    try:
        module.semantic_type_text({"app": "address:0xa", "text": "x", "method": "atspi"})
    except RuntimeError as exc:
        assert "no keyboard or clipboard fallback" in str(exc)
    else:
        raise AssertionError("failed AT-SPI insertion unexpectedly succeeded")


def test_mcp_wait_backend_does_not_leak_unselected_privacy_event() -> None:
    with security_environment(SECURITY_PRIVACY_CLASSES="org.example.Secret"):
        module = load_path(MCP, "mcp_wait_event_privacy")
    allowed = {
        "address": "0xabc",
        "class": "org.example.Allowed",
        "title": "Allowed",
        "pid": 42,
        "processStartTime": "123",
    }
    calls = 0

    def candidates(_args: dict[str, Any]) -> list[dict[str, Any]]:
        nonlocal calls
        calls += 1
        return [] if calls == 1 else [allowed]

    module.wait_window_candidates = candidates
    module.socket2_wait_for_window = lambda *_args, **_kwargs: {
        "method": "socket2", "status": "matched", "reconnects": 0,
        "details": {"address": "0xdef", "class": "org.example.Secret", "title": "Private title"},
        "event": {"name": "openwindow", "payload": "0xdef,1,Secret,Private title", "fields": ["0xdef", "1", "Secret", "Private title"]},
    }
    module.build_app_snapshot = lambda _selector: {"target": "address:0xabc"}
    result = module.semantic_wait_for_window({"title": "Allowed", "timeout": 0.1})["structuredContent"]
    backend = result["lastAction"]["waitBackend"]
    assert backend == {"method": "socket2", "status": "matched", "reconnects": 0}
    assert "Private title" not in repr(result)


def test_mcp_related_privacy_filter_and_sequence_singleton_claim() -> None:
    with security_environment(SECURITY_PRIVACY_CLASSES="org.example.Secret"):
        module = load_path(MCP, "mcp_related_sequence_lock")
    windows = [
        {"address": "0xa", "class": "org.example.Allowed", "title": "Allowed"},
        {"address": "0xb", "class": "org.example.Secret", "title": "Private title"},
    ]
    assert module.privacy_filtered_related_windows(windows) == [windows[0]]
    delta = module.window_delta([], windows)
    assert len(delta["opened"]) == 1 and "title" not in delta["opened"][0]
    try:
        module.prepare_execution_args("paste_text", {"app": "address:0xa", "prefer_related": True})
    except RuntimeError as exc:
        assert "target the related popup explicitly" in str(exc)

    entered = threading.Event()
    release = threading.Event()
    module.run_action_sequence = lambda *_args, **_kwargs: (entered.set(), release.wait(2), {"ok": True})[-1]
    first_error: list[Exception] = []

    def first() -> None:
        try:
            module.tool_sequence({"steps": []})
        except Exception as exc:
            first_error.append(exc)

    thread = threading.Thread(target=first)
    thread.start()
    assert entered.wait(1)
    try:
        module.tool_sequence({"steps": []})
    except RuntimeError as exc:
        assert "sequence_active" in str(exc)
    else:
        raise AssertionError("concurrent sequence was admitted")
    release.set()
    thread.join(2)
    assert not thread.is_alive() and first_error == []


def test_mcp_type_into_atspi_binds_exact_second_editable_direct_and_computer() -> None:
    with security_environment(SECURITY_MUTATION_LEASE_REQUIRED="0", SECURITY_HUMAN_TAKEOVER="0"):
        module = load_path(MCP, "mcp_type_into_runtime_binding")

    class Node:
        def __init__(self, name: str, *, editable: bool = True, children: list[Any] | None = None) -> None:
            self.name = name
            self.editable = editable
            self.children = children or []
            self.writes: list[str] = []

        def get_child_at_index(self, index: int) -> Any:
            return self.children[index]

    first_node = Node("first")
    second_node = Node("second")
    root_node = Node("root", editable=False, children=[first_node, second_node])
    original_insert = module.atspi_insert_text_at_node
    module.atspi_init_error = lambda: None
    module.atspi_resolve_window_for_mutation = lambda _window: (object(), 7, root_node)

    def insert_exact(node: Node, text: str, *, focused_only: bool = False) -> bool:
        assert node.editable and not focused_only
        node.writes.append(text)
        return True

    module.atspi_insert_text_at_node = insert_exact
    try:
        child_result = module.atspi_child_action_payload(
            {"operation": "insert_text", "window": {}, "runtimeId": [7, 1], "text": "second-only"}
        )
    finally:
        module.atspi_insert_text_at_node = original_insert
    assert child_result["ok"] is True
    assert first_node.writes == [] and second_node.writes == ["second-only"]

    exact_auto: list[Any] = []
    module.current_snapshot = lambda _app: {"target": "address:0xabc", "elements": []}
    module.control_overlay = lambda *_args, **_kwargs: None
    module.atspi_insert_text_isolated = lambda _snapshot, _text, *, runtime_id=None: exact_auto.append(runtime_id) or True
    module.atspi_insert_focused_text_isolated = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("auto used focused-first"))
    module.snapshot_after_action = lambda _app, snapshot_value, _result: snapshot_value
    auto_result = module.semantic_type_text(
        {"app": "address:0xabc", "text": "auto-exact", "method": "auto", "_atspi_runtime_id": [7, 1]}
    )
    assert auto_result["isError"] is False and exact_auto == [[7, 1]]

    window = {
        "address": "0xabc", "class": "org.example.Editor", "workspace": {"name": "1"},
        "pid": 123, "processStartTime": "456",
    }
    elements = [
        {"index": 1, "runtimeId": [7, 0], "name": "First", "controlType": "entry", "localizedControlType": "entry", "frame": {"x": 1, "y": 1, "width": 10, "height": 10}, "editable": True, "focused": False, "source": "atspi"},
        {"index": 2, "runtimeId": [7, 1], "name": "Second", "controlType": "entry", "localizedControlType": "entry", "frame": {"x": 20, "y": 1, "width": 10, "height": 10}, "editable": True, "focused": True, "source": "atspi"},
    ]
    snapshot = {
        "snapshotId": "snap-test", "target": "address:0xabc", "window": window, "elements": elements,
        "screenshot": {"id": "snap-test", "sha256": "a" * 64, "width": 100, "height": 50, "logicalBounds": {"x": 0, "y": 0, "width": 100, "height": 50}},
    }
    module.resolve_hypr_window = lambda _selector: dict(window)
    module.call_ctl = lambda *_args, **_kwargs: {
        "available": True, "screenLocked": False, "layerSurfaceActive": False,
        "keyboardGrabActive": False, "panicActive": False,
    }
    module.acquire_process_mutation_lease = lambda: contextlib.nullcontext()
    module.build_app_snapshot = lambda _selector: snapshot
    module.visual_cache_entry = lambda *_args, **_kwargs: {"snapshot": snapshot}
    module.semantic_click = lambda _args: module.mcp_text("focus", structured={"target": "address:0xabc"})
    delivered: list[dict[str, Any]] = []
    module.semantic_type_text = lambda arguments: delivered.append(dict(arguments)) or module.mcp_text("typed", structured={"ok": True})
    cases: list[tuple[str, dict[str, Any]]] = []
    for method in ("atspi", "auto", "paste", "keys"):
        cases.extend(
            [
                ("type_into", {"app": "Editor", "element_index": "2", "text": f"direct-{method}", "method": method}),
                ("computer", {"action": "type_into", "app": "Editor", "element_index": "2", "text": f"compat-{method}", "method": method}),
            ]
        )
    for request_id, (tool_name, arguments) in enumerate(cases, start=500):
        result = mcp_tool_call(module, tool_name, arguments, request_id)
        assert result["isError"] is False, result
    assert [item["_atspi_runtime_id"] for item in delivered] == [[7, 1]] * len(cases)
    assert all(item["app"] == "address:0xabc" for item in delivered)

    elements[1]["focused"] = False
    delivered_before = len(delivered)
    for request_id, (tool_name, arguments) in enumerate(cases, start=600):
        result = mcp_tool_call(module, tool_name, arguments, request_id)
        assert result["isError"] is True
        assert "editable and focused" in result["content"][0]["text"]
    assert len(delivered) == delivered_before


def test_mcp_workspace_semantics_match_direct_and_computer_handlers() -> None:
    with security_environment():
        module = load_path(MCP, "mcp_workspace_semantics")
    calls: list[tuple[str, dict[str, Any]]] = []

    class Result:
        def __init__(self, action: str, workspace: Any) -> None:
            self.action = action
            self.workspace = workspace

        def to_dict(self) -> dict[str, Any]:
            return {"action": self.action, "target": self.workspace, "verified": True}

    class Manager:
        def workspace_action(self, action: str, **options: Any) -> Result:
            calls.append((action, dict(options)))
            return Result(action, options.get("workspace"))

    module.HYPR_MANAGEMENT = Manager()
    direct = module.tool_manage_workspace({"action": "create", "workspace": "direct-new"})
    compat = module.computer(
        {"action": "manage_workspace", "workspace_action": "switch", "workspace": "existing"}
    )
    idempotent = module.computer(
        {"action": "manage_workspace", "workspace_action": "create_or_activate", "workspace": "either"}
    )
    assert direct["structuredContent"]["action"] == "create"
    assert compat["structuredContent"]["action"] == "switch"
    assert idempotent["structuredContent"]["action"] == "create_or_activate"
    assert calls == [
        ("create", {"workspace": "direct-new"}),
        ("switch", {"workspace": "existing"}),
        ("create_or_activate", {"workspace": "either"}),
    ]


TESTS = [
    test_policy_readonly_and_dry_run,
    test_policy_confinement,
    test_policy_lock_layer_and_keyboard_grab_guards,
    test_mcp_runtime_guards_are_authoritative_and_fail_closed,
    test_mcp_panic_latches_all_mutation_paths_until_resume,
    test_policy_detects_known_lock_processes_without_real_procfs,
    test_policy_application_authorization_and_privacy,
    test_policy_class_changes_cannot_bypass_stable_identity_rules,
    test_policy_mutation_lease_is_single_owner_and_expires,
    test_policy_confirmation_tokens_are_bound_and_one_time,
    test_confirmation_waits_for_native_physical_proof,
    test_confirmation_capacity_expiry_rate_and_symlink_safety,
    test_confirmation_capacity_is_atomic_across_policy_instances,
    test_forged_approved_file_requires_live_native_proof,
    test_native_approval_dispatch_supports_lua_and_compat_namespace,
    test_native_approval_dispatch_keeps_legacy_provider_argv_safe,
    test_policy_clipboard_capabilities_are_independent,
    test_policy_human_takeover_cooldown,
    test_policy_environment_contract,
    test_audit_redacts_sensitive_values_and_keeps_useful_metadata,
    test_audit_rotation_limits_permissions_symlinks_and_concurrency,
    test_audit_never_persists_snapshot_or_accessibility_payloads,
    test_audit_redacts_launch_commands_urls_and_process_output,
    test_audit_replay_defaults_to_plan_only_and_rejects_unsafe_records,
    test_mcp_default_view_allows_inventory_through_handle,
    test_mcp_panic_handle_flow_requires_external_resume_approval,
    test_mcp_annotations_are_conservative,
    test_mcp_readonly_hides_all_mutations,
    test_mcp_dry_run_never_calls_backend_and_returns_security_metadata,
    test_mcp_privacy_filters_inventory_and_blocks_full_capture,
    test_mcp_clipboard_read_is_opt_in_and_confirmation_binds_payload,
    test_mcp_high_risk_element_intent_uses_cached_semantics,
    test_mcp_security_status_is_structured_and_secret_free,
    test_mcp_mutation_schemas_accept_confirmation_tokens,
    test_mcp_feature_tools_have_direct_computer_parity_and_fail_closed_levels,
    test_mcp_visual_cache_rejects_hash_and_identity_changes,
    test_mcp_workspace_target_is_synthetic_and_confinable,
    test_mcp_get_marks_handler_and_computer_alias_use_editable_elements,
    test_mcp_sequence_envelope_does_not_claim_full_or_batch_lease,
    test_mcp_sequence_request_dry_run_is_non_consuming_and_backend_free,
    test_mcp_high_risk_key_forms_and_default_special_equivalence,
    test_mcp_policy_target_is_bound_across_direct_and_computer_paths,
    test_mcp_dry_run_resolves_real_identity_and_preflights_named_destination_scope,
    test_mcp_reused_launch_never_gains_launched_only_scope,
    test_mcp_arbitrary_launch_payloads_require_confirmation_direct_and_computer,
    test_mcp_conflicting_selectors_fail_before_all_backend_paths,
    test_mcp_prepare_conflict_writes_one_sanitized_error_audit,
    test_mcp_atspi_failure_never_falls_back_and_auto_declares_clipboard,
    test_mcp_wait_backend_does_not_leak_unselected_privacy_event,
    test_mcp_related_privacy_filter_and_sequence_singleton_claim,
    test_mcp_type_into_atspi_binds_exact_second_editable_direct_and_computer,
    test_mcp_workspace_semantics_match_direct_and_computer_handlers,
]


def main() -> int:
    for test in TESTS:
        test()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
