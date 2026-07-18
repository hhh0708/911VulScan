"""Build HTML/Go report view data from a FinalScanArtifact."""

from __future__ import annotations

import glob
import os
import re
from datetime import datetime
from typing import Any

from core.final_artifact.report_views import (
    REPORT_SECTION_ORDER,
    SECTION_LABELS_EN,
    bucket_findings_by_final_state,
    report_sections,
)
from utilities.file_io import read_json
from utilities.llm_pricing import format_cost, get_active_currency, resolve_display_currency

FINAL_STATE_COLORS: dict[str, str] = {
    "reproduced": "#dc3545",
    "confirmed_not_dynamically_tested": "#e94560",
    "confirmed_not_reproduced": "#fd7e14",
    "candidate": "#ffc107",
    "rejected": "#28a745",
    "inconclusive": "#6c757d",
    "error": "#343a40",
}

SECTION_DESCRIPTIONS: dict[str, str] = {
    "reproduced": (
        "Vulnerability dynamically reproduced in isolated Docker testing. "
        "Immediate remediation required."
    ),
    "confirmed_not_dynamically_tested": (
        "Stage 2 attacker simulation confirmed the issue; dynamic testing was "
        "not run or was blocked/skipped."
    ),
    "confirmed_not_reproduced": (
        "Stage 2 confirmed the issue, but dynamic testing did not reproduce it."
    ),
    "candidate": (
        "Stage 1 flagged a security candidate awaiting or without Stage 2 confirmation."
    ),
    "rejected": (
        "Stage 2 attacker simulation rejected the Stage 1 candidate as not exploitable."
    ),
    "inconclusive": (
        "Pipeline stages could not reach a definitive conclusion. Manual review recommended."
    ),
    "error": (
        "Analysis or verification failed for this unit. Check pipeline logs."
    ),
}

_STATE_PRIORITY = {state: idx for idx, state in enumerate(REPORT_SECTION_ORDER)}

_OPEN_BY_DEFAULT = frozenset(
    {
        "reproduced",
        "confirmed_not_dynamically_tested",
        "confirmed_not_reproduced",
        "candidate",
    }
)


def _finding_location(finding: dict[str, Any]) -> tuple[str, str]:
    """Return (file_path, function_name) for a finding record."""
    s1 = finding.get("stage1_detection") or {}
    location = s1.get("location") or finding.get("location") or {}
    unit_id = finding.get("unit_id") or ""

    file_path = location.get("file") or ""
    func = location.get("function") or ""

    if not file_path and unit_id:
        if ":" in unit_id:
            file_path, func = unit_id.rsplit(":", 1)
        else:
            file_path = unit_id

    if not func:
        func = unit_id.split(":")[-1] if ":" in unit_id else unit_id

    return file_path or "unknown", func or "unknown"


def _attack_vector_from_stages(
    s1: dict[str, Any],
    s2: dict[str, Any],
) -> str:
    source = s2.get("verified_source") or s1.get("source") or ""
    propagation = s2.get("propagation") or s1.get("propagation") or ""
    sink = s2.get("sink") or s1.get("sink") or ""
    parts = [p for p in (source, propagation, sink) if p]
    return " → ".join(parts)


def _analysis_from_stages(
    s1: dict[str, Any],
    s2: dict[str, Any],
    evidence_index: dict[str, dict[str, Any]],
) -> str:
    for stage in (s2, s1):
        impact = (stage.get("impact") or "").strip()
        if impact:
            return impact[:300]

    for stage in (s2, s1):
        text = _evidence_text(evidence_index, stage.get("evidence_ids"))
        if text:
            return text[:300]

    ctype = (s1.get("candidate_type") or "").strip()
    if ctype:
        return f"Candidate type: {ctype}"[:300]
    return ""


def _evidence_text(
    evidence_index: dict[str, dict[str, Any]],
    evidence_ids: list[str] | None,
) -> str:
    parts: list[str] = []
    for eid in evidence_ids or []:
        entry = evidence_index.get(eid) or {}
        content = entry.get("content")
        if isinstance(content, dict):
            for key in ("summary", "text", "explanation", "note", "impact"):
                val = content.get(key)
                if val:
                    parts.append(str(val))
                    break
            else:
                parts.append(str(content)[:200])
        elif content:
            parts.append(str(content)[:200])
    return "\n".join(parts)


def _dynamic_test_fields(finding: dict[str, Any]) -> tuple[str, str]:
    dyn = finding.get("dynamic_verification") or {}
    if not dyn:
        return "", ""

    decision = (dyn.get("decision") or "").strip()
    state = (dyn.get("execution_state") or "").strip()
    if state and state not in ("succeeded", "pending", "running"):
        status = state
    elif decision:
        status = decision
    else:
        status = state

    details = ""
    attempts = dyn.get("attempts") or []
    if attempts and isinstance(attempts[-1], dict):
        details = str(attempts[-1].get("summary") or attempts[-1].get("error") or "")[:300]
    return status, details


def _artifact_finding_row(
    finding: dict[str, Any],
    evidence_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    final_state = finding.get("final_state") or "inconclusive"
    s1 = finding.get("stage1_detection") or {}
    s2 = finding.get("stage2_verification") or {}
    file_path, func = _finding_location(finding)
    dt_status, dt_details = _dynamic_test_fields(finding)

    return {
        "verdict": final_state,
        "final_state": final_state,
        "verdict_label": SECTION_LABELS_EN.get(final_state, final_state),
        "verdict_color": FINAL_STATE_COLORS.get(final_state, "#6c757d"),
        "file": file_path,
        "function": func,
        "attack_vector": _attack_vector_from_stages(s1, s2),
        "analysis": _analysis_from_stages(s1, s2, evidence_index),
        "dynamic_test_status": dt_status,
        "dynamic_test_details": dt_details,
        "number": 0,
    }


def _build_stats(
    artifact: dict[str, Any],
    file_states: dict[str, str],
) -> dict[str, int]:
    metrics = artifact.get("metrics") or {}
    unit_summary = artifact.get("unit_summary") or {}
    findings = artifact.get("findings") or []

    total_units = int(
        metrics.get("total_units")
        or unit_summary.get("analyzed")
        or unit_summary.get("total_units")
        or len(findings)
    )

    return {
        "total_units": total_units,
        "total_files": len(file_states),
        "reproduced": int(metrics.get("dynamic_reproduced", 0)),
        "confirmed": int(metrics.get("stage2_confirmed", 0)),
        "candidates": int(metrics.get("stage1_candidates", 0)),
        "rejected": int(metrics.get("stage2_rejected", 0)),
        "inconclusive": int(metrics.get("stage1_inconclusive", 0))
        + int(metrics.get("stage2_inconclusive", 0)),
        "errors": int(metrics.get("stage1_errors", 0))
        + int(metrics.get("stage2_failed", 0))
        + int(metrics.get("dynamic_failed", 0)),
    }


def _state_chart(
    state_counts: dict[str, int],
    *,
    labels_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    labels_map = labels_map or SECTION_LABELS_EN
    labels: list[str] = []
    data: list[int] = []
    colors: list[str] = []
    for state in REPORT_SECTION_ORDER:
        count = state_counts.get(state, 0)
        if count <= 0:
            continue
        labels.append(labels_map.get(state, state))
        data.append(count)
        colors.append(FINAL_STATE_COLORS.get(state, "#6c757d"))
    return {"labels": labels, "data": data, "colors": colors}


def _format_step_reports(raw_reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    formatted: list[dict[str, Any]] = []
    for sr in raw_reports:
        duration = float(sr.get("duration_seconds") or 0)
        cost = float(sr.get("cost_usd") or 0)
        if duration >= 60:
            dur_str = f"{duration / 60:.1f}m"
        else:
            dur_str = f"{duration:.1f}s"
        cost_str = (
            format_cost(cost, resolve_display_currency(sr.get("cost_currency")))
            if cost > 0
            else "-"
        )
        formatted.append(
            {
                "step": sr.get("step", "unknown"),
                "duration": dur_str,
                "cost": cost_str,
                "status": sr.get("status", "unknown"),
                "timestamp": sr.get("timestamp", ""),
            }
        )
    formatted.sort(key=lambda item: item.get("timestamp", ""))
    return formatted


def _load_step_reports(directory: str) -> list[dict[str, Any]]:
    reports: list[dict] = []
    for path in glob.glob(os.path.join(directory, "*.report.json")):
        try:
            reports.append(read_json(path))
        except (OSError, ValueError):
            continue
    return reports


def _diff_block(artifact: dict[str, Any]) -> dict[str, Any] | None:
    provenance = artifact.get("provenance") or {}
    raw_diff = artifact.get("diff") or provenance.get("diff")
    if not isinstance(raw_diff, dict) or raw_diff.get("mode") != "incremental":
        return None
    return {
        "mode": raw_diff.get("mode"),
        "base_sha": raw_diff.get("base_sha", ""),
        "head_sha": raw_diff.get("head_sha", ""),
        "scope": raw_diff.get("scope", ""),
        "units_in_diff": raw_diff.get("units_in_diff", 0) or 0,
        "units_total_parsed": raw_diff.get("units_total_parsed", 0) or 0,
        "changed_files": raw_diff.get("changed_files", 0) or 0,
        "pr_number": raw_diff.get("pr_number") or 0,
    }


def _remediation_html(findings: list[dict[str, Any]]) -> str:
    actionable = [
        f
        for f in findings
        if f.get("final_state") in _OPEN_BY_DEFAULT
    ]
    if not actionable:
        return (
            "<p>No high-priority findings in this artifact. "
            "Review rejected and inconclusive items if needed.</p>"
        )
    return (
        "<p>Remediation guidance is not auto-generated for FinalScanArtifact reports. "
        "See confirmed and reproduced findings below, or run the summary/disclosure "
        "report formats for LLM-authored remediation notes.</p>"
    )


def build_report_data_from_artifact(
    artifact: dict[str, Any],
    *,
    step_reports: list[dict[str, Any]] | None = None,
    artifact_dir: str | None = None,
) -> dict[str, Any]:
    """Build display-ready report data for the Go HTML renderer."""
    evidence_index = artifact.get("evidence_index") or {}
    buckets = bucket_findings_by_final_state(artifact)

    findings: list[dict[str, Any]] = []
    state_counts: dict[str, int] = {key: 0 for key in REPORT_SECTION_ORDER}
    file_states: dict[str, str] = {}

    for state in REPORT_SECTION_ORDER:
        for record in buckets.get(state, []):
            row = _artifact_finding_row(record, evidence_index)
            findings.append(row)
            state_counts[state] = state_counts.get(state, 0) + 1

            file_path = row["file"]
            prev = file_states.get(file_path)
            if prev is None or _STATE_PRIORITY.get(state, 99) < _STATE_PRIORITY.get(prev, 99):
                file_states[file_path] = state

    for idx, row in enumerate(findings, 1):
        row["number"] = idx

    findings_by_verdict: list[dict[str, Any]] = []
    for section in report_sections(artifact, chinese=False):
        key = section["key"]
        group_rows = [f for f in findings if f["final_state"] == key]
        if not group_rows:
            continue
        findings_by_verdict.append(
            {
                "verdict": key,
                "verdict_label": section["label"],
                "verdict_color": FINAL_STATE_COLORS.get(key, "#6c757d"),
                "count": len(group_rows),
                "open_by_default": key in _OPEN_BY_DEFAULT,
                "findings": group_rows,
                "subgroups": [],
                "has_subgroups": False,
            }
        )

    file_state_counts: dict[str, int] = {}
    for state in file_states.values():
        file_state_counts[state] = file_state_counts.get(state, 0) + 1

    repository = artifact.get("repository") or {}
    run_meta = artifact.get("run") or {}
    provenance = artifact.get("provenance") or {}

    reports_raw = list(step_reports or [])
    if not reports_raw and artifact_dir:
        reports_raw = _load_step_reports(artifact_dir)
    elif not reports_raw:
        manifest = provenance.get("step_reports")
        if isinstance(manifest, list):
            reports_raw = [item for item in manifest if isinstance(item, dict)]

    step_reports_data = _format_step_reports(reports_raw)
    total_duration_seconds = sum(
        float(sr.get("duration_seconds") or 0) for sr in reports_raw
    )
    total_cost_usd = sum(float(sr.get("cost_usd") or 0) for sr in reports_raw)

    categories = [
        {
            "key": state,
            "verdict": SECTION_LABELS_EN[state],
            "color": FINAL_STATE_COLORS[state],
            "description": SECTION_DESCRIPTIONS[state],
        }
        for state in REPORT_SECTION_ORDER
    ]

    timestamp = (
        run_meta.get("completed_at")
        or run_meta.get("started_at")
        or provenance.get("generated_at")
        or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    if isinstance(timestamp, str) and "T" in timestamp:
        timestamp = re.sub(r"Z$", "", timestamp.replace("T", " ", 1))

    return {
        "title": "Security Analysis Report",
        "timestamp": timestamp,
        "repo_name": repository.get("name", ""),
        "commit_sha": repository.get("commit_sha", ""),
        "language": repository.get("language", ""),
        "repo_url": repository.get("url", ""),
        "total_duration_seconds": total_duration_seconds,
        "total_cost_usd": total_cost_usd,
        "cost_currency": get_active_currency(),
        "stats": _build_stats(artifact, file_states),
        "unit_chart": _state_chart(state_counts),
        "file_chart": _state_chart(file_state_counts),
        "remediation_html": _remediation_html(findings),
        "findings": findings,
        "findings_by_verdict": findings_by_verdict,
        "step_reports": step_reports_data,
        "categories": categories,
        "diff": _diff_block(artifact),
    }
