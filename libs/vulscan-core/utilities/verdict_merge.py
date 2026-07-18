"""Merge Stage 1 / Stage 2 / dynamic-test statuses into one verdict.

This is pipeline status aggregation only — not static source/sink heuristics
or evidence-rule reconciliation.
"""

from __future__ import annotations

from core.verdict import Verdict, is_actionable, normalize_verdict


def merge_verdicts(
    finding: dict,
    dynamic_result: dict | None = None,
) -> dict:
    """Merge Stage 1, Stage 2, and dynamic statuses into one verdict."""
    stage1 = normalize_verdict(
        finding.get("stage1_verdict")
        or finding.get("final_verdict")
        or finding.get("verdict")
    )
    stage2 = str(finding.get("stage2_verdict") or "").lower()
    dynamic_status = str((dynamic_result or {}).get("status") or "").upper()
    conflicts: list[str] = []
    evidence_chain = [
        {"source": "stage1", "verdict": stage1.value},
        {"source": "stage2", "verdict": stage2 or "not_run"},
        {"source": "dynamic", "verdict": dynamic_status or "not_run"},
    ]

    stage2_positive = stage2 in {"confirmed", "agreed"}
    stage2_negative = stage2 in {"rejected", "inconclusive"}
    static_positive = is_actionable(stage1)
    dynamic_positive = dynamic_status == "CONFIRMED"
    dynamic_uncertain = dynamic_status in {
        "NOT_REPRODUCED",
        "BLOCKED",
        "INCONCLUSIVE",
        "ERROR",
    }

    if stage2_negative and dynamic_positive:
        conflicts.append("stage2_dynamic_conflict")
    if (static_positive or stage2_positive) and dynamic_uncertain:
        conflicts.append("static_positive_dynamic_unconfirmed")
    if not static_positive and dynamic_positive:
        conflicts.append("static_dynamic_conflict")

    if conflicts:
        verdict = Verdict.INCONCLUSIVE
    elif dynamic_positive and (static_positive or stage2_positive):
        verdict = Verdict.VULNERABLE
    elif stage2_positive and static_positive and not dynamic_status:
        verdict = stage1
    elif static_positive and not stage2 and not dynamic_status:
        verdict = stage1
    else:
        verdict = Verdict.INCONCLUSIVE

    return {
        "verdict": verdict.value.upper(),
        "evidence_status": (
            "incomplete" if verdict == Verdict.INCONCLUSIVE else "complete"
        ),
        "conflicts": conflicts,
        "evidence_chain": evidence_chain,
    }
