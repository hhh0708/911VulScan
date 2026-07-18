"""Threat-model helpers must stay type-neutral after Phase 5.

Fixed ApplicationType attack models and trust conclusions were removed.
Stage 1/2 helpers must not inject CLI/library dismissal policy.
"""

from __future__ import annotations

from context.application_context import ApplicationContext
from prompts import threat_model
from prompts.verification_prompts import (
    get_verification_prompt,
    get_verification_system_prompt,
)
from prompts.vulnerability_analysis import get_system_prompt as get_stage1_system_prompt


def _neutral_ctx(**kwargs) -> ApplicationContext:
    return ApplicationContext(
        status="ok",
        purpose=kwargs.get("purpose", "test component"),
        components=kwargs.get("components", ["core"]),
        exposed_interfaces=kwargs.get("exposed_interfaces", ["public API"]),
        documented_security_claims=kwargs.get(
            "documented_security_claims",
            ["README claims this is safe"],
        ),
    )


def test_stage2_has_no_type_based_cli_or_library_policy():
    ctx = _neutral_ctx()
    sys_prompt = get_verification_system_prompt(ctx)
    assert "CLI tool" not in sys_prompt
    assert "exported functions ARE the attack surface" not in sys_prompt

    prompt = get_verification_prompt("code", "safe", "av", "reason", app_context=ctx)
    assert "NO ABILITY TO RUN CLI COMMANDS" not in prompt
    assert "outside the library's trust boundary" not in prompt
    assert "it is NOT a vulnerability" not in prompt


def test_stage1_has_no_type_based_dismissal():
    ctx = _neutral_ctx()
    text = get_stage1_system_prompt(ctx)
    assert "CLI tool" not in text
    assert "Path traversal, local file reads" not in text


def test_threat_model_helpers_are_neutral():
    ctx = _neutral_ctx()
    assert threat_model.stage1_system_note(ctx) == ""
    assert threat_model.stage2_system_note(ctx) == ""
    assert threat_model.stage1_context_note(ctx) == ""
    assert threat_model.stage2_context_note(ctx) == ""
    assert "NOT an attack vector" not in threat_model.stage1_input_question(ctx)


def test_hardcoded_profile_overrides_removed():
    import importlib.util

    for mod in (
        "real_world",
        "real_world.high_confidence_backstop",
        "utilities.evidence_rules",
        "core.code_evidence",
    ):
        try:
            spec = importlib.util.find_spec(mod)
        except ModuleNotFoundError:
            spec = None
        assert spec is None, f"{mod} must be removed"
