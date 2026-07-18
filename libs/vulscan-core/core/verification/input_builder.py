"""Build VerificationInput from Stage 1 candidate + DetectionInput."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from context.application_context import REPO_TEXT_ISOLATION_NOTICE
from core.detection.fingerprint import compute_detection_fingerprint
from core.detection.input_builder import build_detection_input
from core.verification.evidence import make_tool_evidence
from core.verification.fingerprint import compute_finding_id
from core.verification.schema import VerificationInput


def _app_dict(app_context: Any) -> Dict[str, Any]:
    if app_context is None:
        return {"status": "unavailable"}
    if hasattr(app_context, "to_dict"):
        try:
            return app_context.to_dict()
        except Exception:  # noqa: BLE001
            pass
    if isinstance(app_context, dict):
        return dict(app_context)
    return {"status": "unavailable"}


def _target_code_from_unit(unit: Optional[dict], detection_input: dict) -> str:
    if unit:
        code = unit.get("code", {})
        if isinstance(code, dict):
            return code.get("primary_code", "") or ""
        return str(code or "")
    # Fall back to evidence table
    for ev in detection_input.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("kind") == "target_code":
            content = ev.get("content") or {}
            if isinstance(content, dict):
                return content.get("code") or ""
    return ""


def append_tool_evidence(
    evidence: List[dict],
    *,
    kind: str = "",
    source: str = "",
    content: Any = None,
    confidence: str = "observed",
    tool: str = "",
    tool_input: Any = None,
    full_result: Any = None,
) -> str:
    """Append a tool-derived evidence entry; return its evidence_id.

    Evidence ID is derived from the *full* redacted content hash — never from
    ``result_preview``. Preview is stored for display only.
    """
    del confidence  # kept for call-site compatibility
    if tool or full_result is not None or tool_input is not None:
        entry = make_tool_evidence(
            tool=tool or (kind.replace("tool_", "") if kind.startswith("tool_") else kind or "tool"),
            tool_input=tool_input if tool_input is not None else {},
            full_result=full_result if full_result is not None else content,
            source=source or f"stage2.tool.{tool or kind}",
        )
    else:
        # Legacy path: hash full content dict (still not preview-only)
        entry = make_tool_evidence(
            tool=kind or "tool",
            tool_input={},
            full_result=content,
            source=source or "stage2.tool",
        )
    eid = entry["evidence_id"]
    if any(e.get("evidence_id") == eid for e in evidence):
        return eid
    evidence.append(entry)
    return eid


def build_verification_input(
    stage1_result: dict,
    *,
    unit: Optional[dict] = None,
    app_context: Any = None,
    call_graph: Optional[dict] = None,
    analyzer_output_path: str = "",
    repo_path: str = "",
    index_stats: Optional[dict] = None,
    model: str = "",
) -> VerificationInput:
    """Assemble VerificationInput. Does not mutate stage1_result."""
    unit_id = stage1_result.get("unit_id") or stage1_result.get("route_key") or "unknown"

    # Rebuild DetectionInput from unit when available; else reconstruct minimally.
    if unit is not None:
        detection_input = build_detection_input(
            unit, app_context=app_context, call_graph=call_graph
        )
    else:
        detection_input = {
            "unit_id": unit_id,
            "language": "unknown",
            "target_unit": {"id": unit_id},
            "reachability": {},
            "call_graph_neighborhood": {},
            "app_context": _app_dict(app_context),
            "enhancement": {},
            "evidence": list(stage1_result.get("_evidence") or []),
            "untrusted_isolation_notice": REPO_TEXT_ISOLATION_NOTICE,
        }

    din_fp = compute_detection_fingerprint(detection_input, model=model)
    # Stage 1 candidate slice — copy only DetectionResult fields (immutable view)
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
            "uncertainties",
            "confidence",
            "provenance",
        )
        if k in stage1_result or k in (
            "unit_id",
            "decision",
            "evidence_ids",
            "counter_evidence_ids",
        )
    }
    stage1_candidate["unit_id"] = unit_id
    stage1_candidate.setdefault("decision", stage1_result.get("decision"))
    stage1_candidate.setdefault("evidence_ids", stage1_result.get("evidence_ids") or [])
    stage1_candidate.setdefault(
        "counter_evidence_ids", stage1_result.get("counter_evidence_ids") or []
    )

    finding_id = compute_finding_id(unit_id, din_fp, stage1_candidate)
    evidence = list(detection_input.get("evidence") or [])
    # Merge Stage 1 cited evidence IDs are already in the table from DetectionInput.

    target_code = _target_code_from_unit(unit, detection_input)
    app_dict = detection_input.get("app_context") or _app_dict(app_context)
    enhancement = detection_input.get("enhancement") or {}

    index_prov = {
        "analyzer_output_path": analyzer_output_path or "",
        "repo_path": repo_path or "",
        "stats": index_stats or {},
    }

    return {
        "finding_id": finding_id,
        "unit_id": unit_id,
        "stage1_candidate": stage1_candidate,
        "detection_input": {
            k: v for k, v in detection_input.items() if k != "evidence"
        },
        "evidence": evidence,
        "call_graph": call_graph or {},
        "app_context": app_dict,
        "enhancement": enhancement,
        "repository_index_provenance": index_prov,
        "untrusted_isolation_notice": REPO_TEXT_ISOLATION_NOTICE,
        "target_code": target_code,
    }
