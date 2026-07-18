"""Shared finding verdict helpers for pipeline, reports, and dynamic tests.

Phase 10b: dynamic eligibility requires full canonical Stage 2 verification:
``execution_state=succeeded``, ``decision=confirmed``, ``finding_id``, and
resolvable ``evidence[]``. No ``stage2_verdict``-only compatibility path.
"""

from __future__ import annotations


def is_stage2_confirmed(finding: dict) -> bool:
    """True only for full Stage 2 succeeded + confirmed with evidence."""
    s2 = finding.get("stage2_verification")
    if not isinstance(s2, dict):
        return False
    if s2.get("execution_state") != "succeeded" or s2.get("decision") != "confirmed":
        return False
    if not s2.get("finding_id"):
        return False
    evidence = s2.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return False
    return any(isinstance(e, dict) and e.get("evidence_id") for e in evidence)


def is_testable_finding(finding: dict) -> bool:
    """Eligible for dynamic testing only with full canonical Stage 2 confirm."""
    return is_stage2_confirmed(finding)


def filter_testable_findings(findings):
    return [f for f in findings if is_testable_finding(f)]


def count_testable_findings(findings):
    return len(filter_testable_findings(findings))
