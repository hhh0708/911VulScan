"""Report section buckets from FinalScanArtifact (no final_state re-derivation)."""

from __future__ import annotations

from typing import Any

from core.final_artifact.schema import FINAL_STATES

REPORT_SECTION_ORDER: tuple[str, ...] = (
    "reproduced",
    "confirmed_not_dynamically_tested",
    "confirmed_not_reproduced",
    "candidate",
    "rejected",
    "inconclusive",
    "error",
)

SECTION_LABELS_ZH: dict[str, str] = {
    "reproduced": "动态验证已复现",
    "confirmed_not_dynamically_tested": "Stage 2 已确认（未动态测试）",
    "confirmed_not_reproduced": "Stage 2 已确认（动态未复现）",
    "candidate": "候选漏洞",
    "rejected": "已拒绝",
    "inconclusive": "不确定",
    "error": "错误",
}

SECTION_LABELS_EN: dict[str, str] = {
    "reproduced": "Dynamically reproduced",
    "confirmed_not_dynamically_tested": "Confirmed (not dynamically tested)",
    "confirmed_not_reproduced": "Confirmed (not reproduced dynamically)",
    "candidate": "Candidates",
    "rejected": "Rejected",
    "inconclusive": "Inconclusive",
    "error": "Errors",
}


def section_labels(*, chinese: bool = True) -> dict[str, str]:
    """Return display labels keyed by final_state."""
    return SECTION_LABELS_ZH if chinese else SECTION_LABELS_EN


def bucket_findings_by_final_state(
    artifact: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Bucket findings by existing final_state without recomputing it."""
    buckets: dict[str, list[dict[str, Any]]] = {key: [] for key in REPORT_SECTION_ORDER}
    for finding in artifact.get("findings") or []:
        state = finding.get("final_state")
        if state in buckets:
            buckets[state].append(finding)
    return buckets


def report_sections(
    artifact: dict[str, Any],
    *,
    chinese: bool = True,
    include_empty: bool = False,
) -> list[dict[str, Any]]:
    """Return ordered section dicts for HTML/MD/CSV renderers.

    Each section: ``{"key", "label", "findings"}``.
    """
    labels = section_labels(chinese=chinese)
    buckets = bucket_findings_by_final_state(artifact)
    sections: list[dict[str, Any]] = []
    for key in REPORT_SECTION_ORDER:
        items = buckets[key]
        if items or include_empty:
            sections.append(
                {
                    "key": key,
                    "label": labels[key],
                    "findings": items,
                }
            )
    return sections


def is_final_scan_artifact(doc: dict[str, Any]) -> bool:
    """True when *doc* looks like a canonical FinalScanArtifact."""
    if doc.get("schema_version") != "1.0":
        return False
    findings = doc.get("findings") or []
    if not findings:
        return "unit_summary" in doc and "metrics" in doc
    return any(f.get("final_state") in FINAL_STATES for f in findings)
