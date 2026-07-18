"""Final-state reducer — sole authority for final_state and metrics aggregation."""

from __future__ import annotations

from typing import Any

from core.final_artifact.evidence_index import (
    collect_evidence_ids_from_finding,
    scan_raw_evidence_lists,
)
from core.final_artifact.metrics import AnalysisMetrics
from core.final_artifact.schema import FINAL_STATES, SCHEMA_VERSION


def _stage1(stage1: dict[str, Any] | None) -> dict[str, Any]:
    return stage1 or {}


def _stage2(stage2: dict[str, Any] | None) -> dict[str, Any]:
    return stage2 or {}


def _dynamic(dynamic: dict[str, Any] | None) -> dict[str, Any]:
    return dynamic or {}


def _stage2_pending(stage2: dict[str, Any]) -> bool:
    state = stage2.get("execution_state")
    return state in (None, "pending", "running")


def _stage2_absent_or_skipped(stage2: dict[str, Any]) -> bool:
    if not stage2:
        return True
    return stage2.get("execution_state") in (None, "skipped", "pending", "running")


def _dynamic_absent_skipped_or_blocked(dynamic: dict[str, Any]) -> bool:
    if not dynamic:
        return True
    return dynamic.get("execution_state") in (None, "skipped", "blocked", "pending", "running")


def compute_final_state(
    stage1: dict[str, Any] | None,
    stage2: dict[str, Any] | None,
    dynamic: dict[str, Any] | None,
) -> str:
    """Merge stage snapshots into a single final_state."""
    s1 = _stage1(stage1)
    s2 = _stage2(stage2)
    dyn = _dynamic(dynamic)

    s1_decision = s1.get("decision")
    s2_state = s2.get("execution_state")
    s2_decision = s2.get("decision")
    dyn_state = dyn.get("execution_state")
    dyn_decision = dyn.get("decision")

    # Error: explicit stage1 error or hard execution failures.
    if s1_decision == "error":
        return "error"
    if s2_state == "failed":
        return "error"
    if dyn_state == "failed":
        return "error"

    # Dynamic reproduced wins when execution succeeded.
    if dyn_decision == "reproduced" and dyn_state == "succeeded":
        return "reproduced"

    # Stage 2 rejected is authoritative (never confirmed_*).
    if s2_decision == "rejected" and s2_state == "succeeded":
        return "rejected"

    # Stage 2 confirmed paths.
    if s2_decision == "confirmed" and s2_state == "succeeded":
        if dyn_decision == "not_reproduced" and dyn_state == "succeeded":
            return "confirmed_not_reproduced"
        if _dynamic_absent_skipped_or_blocked(dyn):
            return "confirmed_not_dynamically_tested"
        if dyn_decision == "inconclusive":
            return "inconclusive"

    # Stage 1 candidate awaiting or skipping stage 2.
    if s1_decision == "candidate" and _stage2_absent_or_skipped(s2):
        if _stage2_pending(s2) or not s2:
            return "candidate"

    # Inconclusive from any stage (without reproduced).
    if s1_decision == "inconclusive":
        return "inconclusive"
    if s2_decision == "inconclusive":
        return "inconclusive"
    if dyn_decision == "inconclusive":
        return "inconclusive"

    # Residual stage1 candidate after inconclusive stage2 skip paths.
    if s1_decision == "candidate":
        return "candidate"

    return "inconclusive"


def _finding_key(stage1: dict[str, Any] | None, unit_id: str) -> str:
    s1 = _stage1(stage1)
    return (
        s1.get("finding_id")
        or s1.get("unit_id")
        or unit_id
    )


def _build_finding_record(
    *,
    unit_id: str,
    stage1: dict[str, Any] | None,
    stage2: dict[str, Any] | None,
    dynamic: dict[str, Any] | None,
) -> dict[str, Any]:
    final_state = compute_final_state(stage1, stage2, dynamic)
    if final_state not in FINAL_STATES:
        final_state = "error"

    evidence_ids: list[str] = []
    for stage in (stage1, stage2, dynamic):
        if stage:
            evidence_ids.extend(stage.get("evidence_ids") or [])

    finding_id = None
    if stage2:
        finding_id = stage2.get("finding_id")
    if not finding_id and stage1:
        finding_id = stage1.get("finding_id")
    if not finding_id:
        finding_id = _finding_key(stage1, unit_id)

    return {
        "unit_id": unit_id,
        "finding_id": finding_id,
        "final_state": final_state,
        "stage1_detection": stage1,
        "stage2_verification": stage2,
        "dynamic_verification": dynamic,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


def _index_results_by_unit(
    results: list[dict[str, Any]] | None,
    *,
    unit_key: str = "unit_id",
    alt_key: str = "finding_id",
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in results or []:
        uid = item.get(unit_key) or item.get(alt_key)
        if uid:
            indexed[uid] = item
    return indexed


def _aggregate_metrics(
    *,
    total_units: int,
    reachability_counts: dict[str, int],
    stage1_results: list[dict[str, Any]] | None,
    stage2_results: list[dict[str, Any]] | None,
    dynamic_results: list[dict[str, Any]] | None,
    findings: list[dict[str, Any]],
) -> AnalysisMetrics:
    reachable = int(reachability_counts.get("reachable", 0))
    unreachable = int(reachability_counts.get("unreachable", 0))
    unknown = int(reachability_counts.get("unknown_reachability", 0))

    metrics = AnalysisMetrics(
        total_units=total_units,
        reachable=reachable,
        unreachable=unreachable,
        unknown_reachability=unknown,
    )

    for s1 in stage1_results or []:
        decision = s1.get("decision")
        if decision == "candidate":
            metrics.stage1_candidates += 1
        elif decision == "no_finding":
            metrics.stage1_no_finding += 1
        elif decision == "inconclusive":
            metrics.stage1_inconclusive += 1
        elif decision == "error":
            metrics.stage1_errors += 1

    for s2 in stage2_results or []:
        state = s2.get("execution_state")
        decision = s2.get("decision")
        if state == "failed":
            metrics.stage2_failed += 1
        elif decision == "confirmed" and state == "succeeded":
            metrics.stage2_confirmed += 1
        elif decision == "rejected" and state == "succeeded":
            metrics.stage2_rejected += 1
        elif decision == "inconclusive":
            metrics.stage2_inconclusive += 1

    for dyn in dynamic_results or []:
        state = dyn.get("execution_state")
        decision = dyn.get("decision")
        if state == "failed":
            metrics.dynamic_failed += 1
        elif state == "blocked":
            metrics.dynamic_blocked += 1
        elif state == "skipped":
            metrics.dynamic_skipped += 1
        elif decision == "reproduced" and state == "succeeded":
            metrics.dynamic_reproduced += 1
        elif decision == "not_reproduced" and state == "succeeded":
            metrics.dynamic_not_reproduced += 1
        elif decision == "inconclusive":
            metrics.dynamic_inconclusive += 1

    final_state_counts: dict[str, int] = {}
    for f in findings:
        fs = f.get("final_state", "")
        final_state_counts[fs] = final_state_counts.get(fs, 0) + 1

    return metrics


def _bucket_findings(
    findings: list[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Return (findings, candidates, rejected, inconclusive, errors) lists."""
    candidates: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    inconclusive: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for finding in findings:
        state = finding.get("final_state")
        if state == "candidate":
            candidates.append(finding)
        elif state == "rejected":
            rejected.append(finding)
        elif state == "inconclusive":
            inconclusive.append(finding)
        elif state == "error":
            errors.append(finding)

    return findings, candidates, rejected, inconclusive, errors


def reduce_to_final_artifact(
    *,
    run_meta: dict[str, Any],
    units: list[dict[str, Any]] | None,
    stage1_results: list[dict[str, Any]] | None,
    stage2_results: list[dict[str, Any]] | None,
    dynamic_results: list[dict[str, Any]] | None,
    evidence_lists: list[list[dict[str, Any]]] | None,
    reachability_counts: dict[str, int],
    artifact_manifest: list[dict[str, Any]],
    configuration: dict[str, Any],
    repository: dict[str, Any] | None = None,
    stage_status: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    evidence_producer_stages: list[str] | None = None,
    evidence_source_hashes: list[str] | None = None,
    reachability_missing: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Reduce multi-stage results into a canonical FinalScanArtifact dict.

    Returns ``(artifact, errors)``. Non-empty *errors* (e.g. evidence conflicts)
    must fail FinalScanArtifact validation — never overwrite conflicting evidence.
    """
    reduce_errors: list[str] = []
    warnings: list[str] = []
    total_units = len(units) if units is not None else len(stage1_results or [])
    if reachability_counts.get("total_units") is not None:
        total_units = int(reachability_counts["total_units"])

    if reachability_missing:
        warnings.append(
            "reachability artifact missing; reachable/unreachable/unknown not invented"
        )

    s1_by_unit = _index_results_by_unit(stage1_results)
    s2_by_unit = _index_results_by_unit(stage2_results)
    dyn_by_unit = _index_results_by_unit(dynamic_results)

    # Map dynamic results by finding_id when unit_id differs.
    dyn_by_finding: dict[str, dict[str, Any]] = {}
    for item in dynamic_results or []:
        fid = item.get("finding_id")
        if fid:
            dyn_by_finding[fid] = item

    findings: list[dict[str, Any]] = []
    processed_units: set[str] = set()

    candidate_unit_ids = [
        uid
        for uid, s1 in s1_by_unit.items()
        if s1.get("decision") in ("candidate", "inconclusive", "error")
    ]
    if not candidate_unit_ids and stage1_results:
        candidate_unit_ids = list(s1_by_unit.keys())

    for unit_id in candidate_unit_ids:
        s1 = s1_by_unit.get(unit_id)
        if not s1 or s1.get("decision") == "no_finding":
            continue
        s2 = s2_by_unit.get(unit_id)
        dyn = dyn_by_unit.get(unit_id)
        if not dyn and s2:
            dyn = dyn_by_finding.get(s2.get("finding_id", ""))
        finding = _build_finding_record(
            unit_id=unit_id,
            stage1=s1,
            stage2=s2,
            dynamic=dyn,
        )
        findings.append(finding)
        processed_units.add(unit_id)

    # Stage2-only entries (shouldn't happen often).
    for unit_id, s2 in s2_by_unit.items():
        if unit_id in processed_units:
            continue
        s1 = s1_by_unit.get(unit_id)
        finding = _build_finding_record(
            unit_id=unit_id,
            stage1=s1,
            stage2=s2,
            dynamic=dyn_by_unit.get(unit_id),
        )
        if finding["final_state"] != "inconclusive" or s2:
            findings.append(finding)

    all_findings, candidates, rejected, inconclusive, errors = _bucket_findings(findings)

    # Collect all evidence lists; identical content for same ID is OK, conflicts fail.
    lists = list(evidence_lists or [])
    stages = list(evidence_producer_stages or [])
    hashes = list(evidence_source_hashes or [])
    for s1 in stage1_results or []:
        if isinstance(s1.get("evidence"), list) and s1["evidence"]:
            lists.append(s1["evidence"])
            stages.append("stage1")
            # Prefer explicit source hash on the stage record; never invent "".
            hashes.append(str(s1.get("source_artifact_hash") or "") or None)
    for s2 in stage2_results or []:
        if isinstance(s2.get("evidence"), list) and s2["evidence"]:
            lists.append(s2["evidence"])
            stages.append("stage2")
            hashes.append(str(s2.get("source_artifact_hash") or "") or None)
    for dyn in dynamic_results or []:
        if isinstance(dyn.get("evidence"), list) and dyn["evidence"]:
            lists.append(dyn["evidence"])
            stages.append("dynamic")
            hashes.append(str(dyn.get("source_artifact_hash") or "") or None)

    evidence_index, evidence_errors = scan_raw_evidence_lists(
        lists,
        producer_stages=stages or None,
        source_artifact_hashes=hashes or None,
    )
    reduce_errors.extend(evidence_errors)

    for finding in all_findings:
        for eid in collect_evidence_ids_from_finding(finding):
            if eid not in evidence_index:
                reduce_errors.append(
                    f"finding {finding.get('finding_id')!r} references "
                    f"missing evidence_id {eid!r}"
                )

    metrics = _aggregate_metrics(
        total_units=total_units,
        reachability_counts=reachability_counts,
        stage1_results=stage1_results,
        stage2_results=stage2_results,
        dynamic_results=dynamic_results,
        findings=all_findings,
    )

    unit_summary = {
        "total_units": total_units,
        "reachable": metrics.reachable,
        "unreachable": metrics.unreachable,
        "unknown_reachability": metrics.unknown_reachability,
        "analyzed": len(stage1_results or []),
        "with_findings": len(all_findings),
    }

    stage_status_out = dict(stage_status or {})
    if reachability_missing:
        stage_status_out["reachability"] = "partial"

    prov = dict(provenance or {})
    if reduce_errors:
        prov["evidence_validation_errors"] = list(reduce_errors)
    if warnings:
        prov["warnings"] = list(warnings)

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "run": dict(run_meta),
        "repository": dict(repository or {}),
        "configuration": dict(configuration),
        "stage_status": stage_status_out,
        "unit_summary": unit_summary,
        "findings": all_findings,
        "candidates": candidates,
        "rejected": rejected,
        "inconclusive": inconclusive,
        "errors": errors,
        "evidence_index": evidence_index,
        "artifact_manifest": list(artifact_manifest),
        "metrics": metrics.to_dict(),
        "provenance": prov,
    }
    return artifact, reduce_errors
