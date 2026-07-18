"""Canonical DynamicVerificationInput / Result / TestPlan schemas."""

from __future__ import annotations

from typing import Any, Dict, List, TypedDict

DYNAMIC_SCHEMA_VERSION = "1.1"
DYNAMIC_PROMPT_VERSION = "testplan-v2"
DYNAMIC_COMPILER_VERSION = "policy-compiler-v2"
DYNAMIC_RUNNER_VERSION = "runner-v2"
DYNAMIC_TOOLS_VERSION = "tools-v2"

SUPPORTED_DYNAMIC_LANGUAGES = frozenset(
    {
        "c",
        "cpp",
        "c++",
        "python",
        "py",
        "go",
        "golang",
        "javascript",
        "js",
        "typescript",
        "ts",
    }
)

EXECUTION_STATES = frozenset(
    {"pending", "running", "succeeded", "failed", "blocked", "skipped"}
)
DECISIONS = frozenset({"reproduced", "not_reproduced", "inconclusive"})

TESTPLAN_KEYS = (
    "entrypoint",
    "payload",
    "setup_requirements",
    "invocation",
    "success_oracle",
    "negative_oracle",
    "expected_artifacts",
)

# Forbidden keys in model TestPlan output (must never be accepted from LLM)
FORBIDDEN_TESTPLAN_KEYS = frozenset(
    {
        "dockerfile",
        "docker_compose",
        "docker-compose",
        "host_command",
        "host_commands",
        "docker_run_args",
        "privileged",
        "volumes",
        "binds",
        "network_mode",
        "devices",
        "pid_mode",
        "ipc_mode",
    }
)

RESULT_KEYS = (
    "test_id",
    "finding_id",
    "execution_state",
    "decision",
    "target_reached",
    "preconditions_satisfied",
    "oracle_results",
    "evidence_ids",
    "evidence",
    "artifacts",
    "attempts",
    "confidence",
    "provenance",
)


class TestPlan(TypedDict, total=False):
    entrypoint: str
    payload: Any
    setup_requirements: List[Any]
    invocation: Dict[str, Any]
    success_oracle: Dict[str, Any]
    negative_oracle: Dict[str, Any]
    expected_artifacts: List[Any]


class DynamicVerificationInput(TypedDict, total=False):
    test_id: str
    finding_id: str
    unit_id: str
    stage1_candidate: Dict[str, Any]
    stage2_verification: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    target_code: str
    language: str
    build_runtime_context: Dict[str, Any]
    preconditions: List[Any]
    repository_manifest: Dict[str, Any]
    sandbox_policy: Dict[str, Any]
    provenance: Dict[str, Any]


class DynamicVerificationResult(TypedDict, total=False):
    test_id: str
    finding_id: str
    execution_state: str
    decision: str
    target_reached: bool
    preconditions_satisfied: bool
    oracle_results: Dict[str, Any]
    evidence_ids: List[str]
    evidence: List[Dict[str, Any]]
    artifacts: List[Any]
    attempts: List[Dict[str, Any]]
    confidence: float
    provenance: Dict[str, Any]


def empty_dynamic_result(
    *,
    test_id: str = "",
    finding_id: str = "",
    execution_state: str = "failed",
    decision: str = "inconclusive",
    reason: str = "",
) -> Dict[str, Any]:
    if execution_state not in EXECUTION_STATES:
        execution_state = "failed"
    if decision not in DECISIONS:
        decision = "inconclusive"
    # Incomplete / failed / blocked / skipped never become not_reproduced or reproduced
    if execution_state in ("failed", "blocked", "skipped", "pending", "running"):
        if decision in ("reproduced", "not_reproduced"):
            decision = "inconclusive"
    return {
        "test_id": test_id,
        "finding_id": finding_id,
        "execution_state": execution_state,
        "decision": decision,
        "target_reached": False,
        "preconditions_satisfied": False,
        "oracle_results": {},
        "evidence_ids": [],
        "evidence": [],
        "artifacts": [],
        "attempts": [],
        "confidence": 0.0,
        "provenance": {
            "schema_version": DYNAMIC_SCHEMA_VERSION,
            "prompt_version": DYNAMIC_PROMPT_VERSION,
            "compiler_version": DYNAMIC_COMPILER_VERSION,
            "runner_version": DYNAMIC_RUNNER_VERSION,
            "reason": reason,
        },
    }


def skipped_dynamic_result(
    *,
    test_id: str = "",
    finding_id: str = "",
    reason: str = "",
) -> Dict[str, Any]:
    return empty_dynamic_result(
        test_id=test_id,
        finding_id=finding_id,
        execution_state="skipped",
        decision="inconclusive",
        reason=reason,
    )


def blocked_dynamic_result(
    *,
    test_id: str = "",
    finding_id: str = "",
    reason: str = "",
) -> Dict[str, Any]:
    return empty_dynamic_result(
        test_id=test_id,
        finding_id=finding_id,
        execution_state="blocked",
        decision="inconclusive",
        reason=reason,
    )


def normalize_language(language: str | None) -> str:
    return str(language or "").strip().lower()


def is_supported_language(language: str | None) -> bool:
    return normalize_language(language) in SUPPORTED_DYNAMIC_LANGUAGES


def validate_test_plan(plan: Any) -> tuple[Dict[str, Any] | None, str]:
    """Validate declarative TestPlan. Reject Dockerfile/host/Docker args."""
    if not isinstance(plan, dict):
        return None, "test_plan must be an object"
    forbidden = FORBIDDEN_TESTPLAN_KEYS & set(plan.keys())
    if forbidden:
        return None, f"forbidden TestPlan keys: {sorted(forbidden)}"
    # Nested scan for dangerous requests
    blob = str(plan).lower()
    for token in (
        "privileged",
        "docker.sock",
        "/var/run/docker.sock",
        "network_mode=host",
        "pid: host",
        "ipc: host",
        "hostnetwork",
    ):
        if token in blob:
            return None, f"forbidden sandbox request in TestPlan: {token}"
    out: Dict[str, Any] = {}
    for key in TESTPLAN_KEYS:
        out[key] = plan.get(key)
    if not out.get("entrypoint") and not out.get("invocation"):
        return None, "TestPlan requires entrypoint or invocation"
    if not isinstance(out.get("success_oracle"), (dict, str, type(None))):
        return None, "success_oracle must be object or string"
    if not isinstance(out.get("negative_oracle"), (dict, str, type(None))):
        return None, "negative_oracle must be object or string"
    out.setdefault("setup_requirements", [])
    out.setdefault("expected_artifacts", [])
    out.setdefault("payload", {})
    if out["setup_requirements"] is None:
        out["setup_requirements"] = []
    if out["expected_artifacts"] is None:
        out["expected_artifacts"] = []
    return out, ""


def can_emit_not_reproduced(
    *,
    build_ok: bool,
    harness_ok: bool,
    target_reached: bool,
    preconditions_satisfied: bool,
    positive_oracle_done: bool,
    negative_oracle_done: bool,
) -> bool:
    """not_reproduced only when all success-path preconditions hold."""
    return all(
        (
            build_ok,
            harness_ok,
            target_reached,
            preconditions_satisfied,
            positive_oracle_done,
            negative_oracle_done,
        )
    )


def normalize_dynamic_decision(
    *,
    claimed: str,
    build_ok: bool,
    harness_ok: bool,
    target_reached: bool,
    preconditions_satisfied: bool,
    positive_oracle_done: bool,
    negative_oracle_done: bool,
    timed_out: bool = False,
    unsupported: bool = False,
    success_hit: bool = False,
    evidence_ok: bool = True,
) -> tuple[str, str]:
    """Return (execution_state, decision). Legacy claimed status is ignored for promotion."""
    del claimed  # never trust harness/legacy status strings as oracle evidence
    if unsupported:
        return "skipped", "inconclusive"
    if not build_ok or timed_out:
        return "failed", "inconclusive"
    if not harness_ok or not evidence_ok:
        return "failed", "inconclusive"
    if (
        target_reached
        and preconditions_satisfied
        and success_hit
        and positive_oracle_done
        and evidence_ok
        and build_ok
        and harness_ok
    ):
        return "succeeded", "reproduced"
    if can_emit_not_reproduced(
        build_ok=build_ok,
        harness_ok=harness_ok,
        target_reached=target_reached,
        preconditions_satisfied=preconditions_satisfied,
        positive_oracle_done=positive_oracle_done,
        negative_oracle_done=negative_oracle_done,
    ) and not success_hit:
        return "succeeded", "not_reproduced"
    return "succeeded", "inconclusive"
