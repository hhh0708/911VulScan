"""CSV export from a validated FinalScanArtifact (final_state only)."""

from __future__ import annotations

import csv
import os
from typing import Any

from core.final_artifact.report_views import REPORT_SECTION_ORDER, report_sections


CSV_COLUMNS = (
    "final_state",
    "section_label",
    "finding_id",
    "unit_id",
    "file",
    "function",
    "stage1_decision",
    "stage2_decision",
    "stage2_execution_state",
    "dynamic_decision",
    "dynamic_execution_state",
    "evidence_ids",
)


def _location(finding: dict[str, Any]) -> tuple[str, str]:
    s1 = finding.get("stage1_detection") or {}
    location = s1.get("location") or finding.get("location") or {}
    unit_id = finding.get("unit_id") or ""
    file_path = location.get("file") or ""
    func = location.get("function") or ""
    if not file_path and unit_id and ":" in unit_id:
        file_path, func = unit_id.rsplit(":", 1)
    return str(file_path), str(func or "")


def rows_from_artifact(artifact: dict[str, Any]) -> list[dict[str, str]]:
    """Build CSV rows using report_sections / final_state (include empty sections as zero rows)."""
    rows: list[dict[str, str]] = []
    # include_empty=False: only emit finding rows; empty artifact → zero data rows
    for section in report_sections(artifact, chinese=False, include_empty=False):
        key = section["key"]
        label = section["label"]
        for finding in section["findings"]:
            s1 = finding.get("stage1_detection") or {}
            s2 = finding.get("stage2_verification") or {}
            dyn = finding.get("dynamic_verification") or {}
            file_path, func = _location(finding)
            eids = finding.get("evidence_ids") or []
            rows.append(
                {
                    "final_state": key,
                    "section_label": label,
                    "finding_id": str(finding.get("finding_id") or ""),
                    "unit_id": str(finding.get("unit_id") or ""),
                    "file": file_path,
                    "function": func,
                    "stage1_decision": str(s1.get("decision") or ""),
                    "stage2_decision": str(s2.get("decision") or ""),
                    "stage2_execution_state": str(s2.get("execution_state") or ""),
                    "dynamic_decision": str(dyn.get("decision") or ""),
                    "dynamic_execution_state": str(dyn.get("execution_state") or ""),
                    "evidence_ids": ";".join(str(e) for e in eids),
                }
            )
    return rows


def count_by_final_state(artifact: dict[str, Any]) -> dict[str, int]:
    """Count findings per final_state for homology checks (all seven keys)."""
    counts = {key: 0 for key in REPORT_SECTION_ORDER}
    for finding in artifact.get("findings") or []:
        state = finding.get("final_state")
        if state in counts:
            counts[state] += 1
    return counts


def write_csv_from_artifact(artifact: dict[str, Any], output_path: str) -> str:
    """Write FinalScanArtifact findings to CSV. Returns output_path."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    rows = rows_from_artifact(artifact)
    with open(output_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CSV_COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return output_path
