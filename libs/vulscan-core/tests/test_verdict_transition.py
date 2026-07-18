"""Regression tests for the authoritative verdict transition model.

Guards the bug where Stage 2 refining its reasoning (agree=False) while keeping
the verdict produced a contradictory ``DISAGREED: vulnerable -> vulnerable``.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.verdict import (  # noqa: E402
    Verdict,
    canonical_verdict,
    classify_transition,
    is_actionable,
    is_reportable,
    is_safe,
    normalize_verdict,
    summarize_transition,
    transition_of,
    verdict_of,
)


def test_normalize_handles_case_and_aliases():
    assert normalize_verdict("VULNERABLE") is Verdict.VULNERABLE
    assert normalize_verdict("vuln") is Verdict.VULNERABLE
    assert normalize_verdict("uncertain") is Verdict.INCONCLUSIVE
    assert normalize_verdict("") is Verdict.ERROR
    assert normalize_verdict(None, default=Verdict.SAFE) is Verdict.SAFE


def test_kept_verdict_with_refined_reasoning_is_not_a_disagreement():
    # The exact historical bug: agree=False but verdict unchanged.
    t = classify_transition("vulnerable", "vulnerable", reasoning_agrees=False)
    assert not t.verdict_changed
    assert t.reasoning_refined

    symbol, label = summarize_transition("vulnerable", "vulnerable", reasoning_agrees=False)
    assert symbol == "="
    assert label == "CONFIRMED: vulnerable (reasoning refined)"
    assert "→" not in label  # never rendered as a transition arrow


def test_full_agreement_is_confirmation():
    symbol, label = summarize_transition("vulnerable", "vulnerable", reasoning_agrees=True)
    assert (symbol, label) == ("=", "CONFIRMED: vulnerable")


def test_actual_verdict_change_is_a_change():
    symbol, label = summarize_transition("vulnerable", "safe", reasoning_agrees=False)
    assert symbol == "~"
    assert label == "CHANGED: vulnerable → safe"


def test_reasoning_refined_only_when_verdict_kept():
    # If the verdict changed, reasoning_refined must be False regardless of agree.
    t = classify_transition("vulnerable", "safe", reasoning_agrees=False)
    assert t.verdict_changed
    assert not t.reasoning_refined


def test_actionable_property():
    assert Verdict.VULNERABLE.is_actionable
    assert Verdict.BYPASSABLE.is_actionable
    assert Verdict.CANDIDATE.is_actionable
    assert not Verdict.SAFE.is_actionable
    assert not Verdict.INCONCLUSIVE.is_actionable


def test_is_actionable_and_reportable_groups():
    assert is_actionable("vulnerable") and is_actionable("BYPASSABLE")
    assert is_actionable("candidate")
    assert not is_actionable("inconclusive")
    # reportable is the superset that includes inconclusive
    assert is_reportable("inconclusive")
    assert not is_reportable("safe")
    assert not is_reportable("protected")


def test_is_safe_group():
    # The {protected, safe, no_finding} group
    assert is_safe("safe") and is_safe("PROTECTED")
    assert is_safe("no_finding")
    assert not is_safe("vulnerable")
    assert not is_safe("inconclusive")
    assert not is_safe("")


def test_canonical_verdict_recases_known_passes_through_unknown():
    # Known verdicts (and aliases) collapse to the canonical lower-case form.
    assert canonical_verdict("VULNERABLE") == "vulnerable"
    assert canonical_verdict("vuln") == "vulnerable"
    assert canonical_verdict(Verdict.SAFE) == "safe"
    # Unknown labels (e.g. a CWE short name historically stored in the field)
    # must survive verbatim rather than collapse to a default verdict.
    assert canonical_verdict("path_traversal") == "path_traversal"
    assert canonical_verdict("") == ""
    assert canonical_verdict(None) == ""


def test_verdict_of_prefers_finding_then_verdict():
    assert verdict_of({"finding": "vulnerable", "verdict": "SAFE"}) is Verdict.VULNERABLE
    assert verdict_of({"verdict": "SAFE"}) is Verdict.SAFE  # falls back to verdict
    assert verdict_of({}) is Verdict.ERROR
    assert verdict_of("bypassable") is Verdict.BYPASSABLE  # bare value tolerated


def test_transition_of_uses_preserved_stage1():
    # Reasoning refined but verdict kept (the historical bug shape).
    r = {
        "stage1_finding": "vulnerable",
        "finding": "vulnerable",
        "verification": {"agree": False},
    }
    t = transition_of(r)
    assert not t.verdict_changed and t.reasoning_refined

    # Real overturn.
    r2 = {
        "stage1_finding": "vulnerable",
        "finding": "safe",
        "verification": {"agree": False},
    }
    assert transition_of(r2).verdict_changed

    # Unverified finding: no stage1 preserved -> assumed unchanged.
    assert not transition_of({"finding": "vulnerable"}).verdict_changed
