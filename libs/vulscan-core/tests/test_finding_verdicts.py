"""Unit tests for dynamic-test eligibility (`is_testable_finding`)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utilities.finding_verdicts import (  # noqa: E402
    filter_testable_findings,
    is_testable_finding,
)


def _confirmed(**extra):
    base = {
        "stage2_verification": {
            "execution_state": "succeeded",
            "decision": "confirmed",
            "finding_id": "fid",
            "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
        }
    }
    base["stage2_verification"].update(extra)
    return base


def test_full_stage2_confirmed_is_testable():
    assert is_testable_finding(_confirmed())


def test_stage2_verdict_only_not_testable():
    assert not is_testable_finding({"stage2_verdict": "confirmed"})
    assert not is_testable_finding({"stage2_verdict": "agreed"})
    assert not is_testable_finding({"stage2_verdict": "vulnerable"})


def test_missing_evidence_not_testable():
    assert not is_testable_finding(
        {
            "stage2_verification": {
                "execution_state": "succeeded",
                "decision": "confirmed",
                "finding_id": "fid",
                "evidence": [],
            }
        }
    )


def test_filter_testable_findings():
    findings = [
        {"id": 1, **_confirmed()},
        {"id": 2, "stage2_verdict": "confirmed"},
        {"id": 3, "stage2_verdict": "rejected"},
    ]
    kept = [f["id"] for f in filter_testable_findings(findings)]
    assert kept == [1]
