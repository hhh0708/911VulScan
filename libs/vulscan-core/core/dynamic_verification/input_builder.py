"""Build DynamicVerificationInput from Stage 1/2 confirmed candidates."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.dynamic_verification.fingerprint import compute_test_id
from core.dynamic_verification.policy import default_sandbox_policy
from core.dynamic_verification.schema import DynamicVerificationInput, is_supported_language


def is_dynamic_eligible(stage1: dict, stage2: dict | None) -> tuple[bool, str]:
    """Require full canonical Stage1/2 + finding_id + resolvable evidence[]."""
    if (stage1 or {}).get("decision") != "candidate":
        return False, f"stage1_decision={(stage1 or {}).get('decision')!r}"
    s2 = stage2 or {}
    if not isinstance(s2, dict) or not s2:
        return False, "missing_stage2_verification"
    if s2.get("execution_state") != "succeeded":
        return False, f"stage2_execution_state={s2.get('execution_state')!r}"
    if s2.get("decision") != "confirmed":
        return False, f"stage2_decision={s2.get('decision')!r}"
    finding_id = s2.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip():
        return False, "missing_finding_id"
    evidence = s2.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return False, "missing_resolvable_evidence"
    ids = {
        e.get("evidence_id")
        for e in evidence
        if isinstance(e, dict) and e.get("evidence_id")
    }
    cited = list(s2.get("evidence_ids") or [])
    if cited and not all(c in ids for c in cited):
        return False, "evidence_ids_not_resolvable"
    if not ids:
        return False, "evidence_table_empty"
    return True, ""


def build_dynamic_input(
    *,
    stage1_result: dict,
    stage2_result: dict,
    finding: Optional[dict] = None,
    unit: Optional[dict] = None,
    evidence: Optional[List[dict]] = None,
    language: str = "",
    repo_path: str = "",
    repo_name: str = "",
    sandbox_policy: Optional[dict] = None,
    model: str = "",
) -> DynamicVerificationInput:
    finding = finding or {}
    unit = unit or {}
    unit_id = (
        stage1_result.get("unit_id")
        or (stage1_result.get("location") or {}).get("function")
        or "unknown"
    )
    finding_id = (stage2_result or {}).get("finding_id") or ""

    # Target code from unit primary_code only (canonical) — not code_by_route
    target_code = ""
    if unit:
        code = unit.get("code", {})
        if isinstance(code, dict):
            target_code = code.get("primary_code") or ""
        else:
            target_code = str(code or "")

    lang = (
        language
        or unit.get("language")
        or (stage1_result.get("provenance") or {}).get("language")
        or ""
    ).strip().lower()

    evid = list(evidence or [])
    if not evid and isinstance(stage2_result.get("evidence"), list):
        evid = list(stage2_result["evidence"])

    stage1_candidate = {
        k: stage1_result.get(k)
        for k in (
            "unit_id",
            "decision",
            "candidate_type",
            "cwe_id",
            "location",
            "source",
            "propagation",
            "sink",
            "guards",
            "impact",
            "preconditions",
            "evidence_ids",
            "counter_evidence_ids",
            "confidence",
        )
        if k in stage1_result
    }
    stage1_candidate.setdefault("unit_id", unit_id)
    stage1_candidate.setdefault("decision", stage1_result.get("decision"))

    preconditions = list(stage1_result.get("preconditions") or [])
    policy = sandbox_policy or default_sandbox_policy()

    din: Dict[str, Any] = {
        "finding_id": finding_id,
        "unit_id": unit_id,
        "stage1_candidate": stage1_candidate,
        "stage2_verification": {
            k: stage2_result.get(k)
            for k in (
                "finding_id",
                "execution_state",
                "decision",
                "verified_source",
                "propagation",
                "sink",
                "guards",
                "impact",
                "evidence_ids",
                "counter_evidence_ids",
                "evidence",
                "confidence",
                "provenance",
            )
            if k in stage2_result
        },
        "evidence": evid,
        "target_code": target_code,
        "language": lang,
        "build_runtime_context": {
            "language": lang,
            "supported": is_supported_language(lang),
            "repo_path": repo_path or "",
        },
        "preconditions": preconditions,
        "repository_manifest": {
            "name": repo_name or "",
            "path": repo_path or "",
            "language": lang,
            "allowed_packages": list(
                (finding.get("repository_manifest") or {}).get("allowed_packages") or []
            ),
        },
        "sandbox_policy": policy,
        "provenance": {
            "model": model,
            "stage1_immutable": True,
            "stage2_immutable": True,
        },
    }
    din["test_id"] = compute_test_id(din)
    return din  # type: ignore[return-value]
