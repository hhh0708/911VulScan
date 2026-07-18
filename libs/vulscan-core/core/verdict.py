"""Authoritative verdict model for the detection pipeline.

Historically the per-unit conclusion was smeared across several fields with
overlapping, drifting meanings:

* ``finding``            — lower-case verdict ("vulnerable")
* ``verdict``            — UPPER-case verdict ("VULNERABLE")
* ``verification.agree`` — boolean: did Stage 2 agree with Stage 1?
* ``correct_finding``    — Stage 2's verdict
* ``stage2_verdict``     — yet another derived label (confirmed/agreed/rejected)

Display and metrics each read a different field, which is how the pipeline
produced contradictions like ``DISAGREED: vulnerable -> vulnerable``: the
*label* was driven by the ``agree`` flag (a reasoning-level signal) while the
*arrow* showed the verdict, and those are two independent dimensions.

This module is the single source of truth. Two genuinely independent
dimensions are modelled explicitly:

* did the **verdict** change (vulnerable -> safe)?
* was only the **reasoning** refined (same verdict, different justification)?

``summarize_transition`` renders them coherently so a kept verdict can never be
printed as a disagreement.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    """Canonical verdict values (lower-case is the on-disk form)."""

    CANDIDATE = "candidate"  # Stage 1 candidate discovery (not confirmed)
    VULNERABLE = "vulnerable"
    BYPASSABLE = "bypassable"
    INCONCLUSIVE = "inconclusive"
    PROTECTED = "protected"
    SAFE = "safe"
    NO_FINDING = "no_finding"
    ERROR = "error"

    @property
    def is_actionable(self) -> bool:
        """Whether this verdict represents a finding worth acting on/testing."""
        return self in (Verdict.VULNERABLE, Verdict.BYPASSABLE, Verdict.CANDIDATE)

    def __str__(self) -> str:  # so f"{verdict}" yields the bare value
        return self.value


# Historical / alternate spellings mapped to the canonical enum.
_ALIASES: dict[str, Verdict] = {
    "candidate": Verdict.CANDIDATE,
    "vuln": Verdict.VULNERABLE,
    "vulnerability": Verdict.VULNERABLE,
    "vulnerable": Verdict.VULNERABLE,
    "bypass": Verdict.BYPASSABLE,
    "bypassable": Verdict.BYPASSABLE,
    "inconclusive": Verdict.INCONCLUSIVE,
    "uncertain": Verdict.INCONCLUSIVE,
    "protected": Verdict.PROTECTED,
    "safe": Verdict.SAFE,
    "no_finding": Verdict.NO_FINDING,
    "nofinding": Verdict.NO_FINDING,
    "error": Verdict.ERROR,
}


def normalize_verdict(value: object, default: Verdict = Verdict.ERROR) -> Verdict:
    """Coerce any historical verdict spelling (case/alias) to a ``Verdict``."""
    if isinstance(value, Verdict):
        return value
    if not value:
        return default
    return _ALIASES.get(str(value).strip().lower(), default)


@dataclass(frozen=True)
class VerdictTransition:
    """The two independent dimensions of a Stage 1 -> Stage 2 transition."""

    stage1: Verdict
    final: Verdict
    reasoning_refined: bool

    @property
    def verdict_changed(self) -> bool:
        return self.stage1 != self.final


def classify_transition(
    stage1: object,
    final: object,
    reasoning_agrees: object | None = None,
) -> VerdictTransition:
    """Resolve the structured transition between Stage 1 and the final verdict.

    ``reasoning_agrees`` is Stage 2's ``agree`` flag (may be ``None`` when the
    finding was never verified). ``reasoning_refined`` is only meaningful when
    the verdict itself did not change.
    """
    s1 = normalize_verdict(stage1)
    fin = normalize_verdict(final, default=s1)
    reasoning_refined = reasoning_agrees is False and s1 == fin
    return VerdictTransition(stage1=s1, final=fin, reasoning_refined=reasoning_refined)


def summarize_transition(
    stage1: object,
    final: object,
    reasoning_agrees: object | None = None,
) -> tuple[str, str]:
    """Render a coherent ``(symbol, label)`` for a verdict transition.

    Cases:
      * verdict changed              -> ``("~", "CHANGED: a -> b")``
      * verdict kept, reasoning same -> ``("=", "CONFIRMED: a")``
      * verdict kept, reasoning new  -> ``("=", "CONFIRMED: a (reasoning refined)")``

    The contradictory ``DISAGREED: vulnerable -> vulnerable`` is impossible:
    a transition is a *disagreement* only when the verdict actually changes.
    """
    t = classify_transition(stage1, final, reasoning_agrees)
    if t.verdict_changed:
        return "~", f"CHANGED: {t.stage1.value} → {t.final.value}"
    if t.reasoning_refined:
        return "=", f"CONFIRMED: {t.final.value} (reasoning refined)"
    return "=", f"CONFIRMED: {t.final.value}"


# ---------------------------------------------------------------------------
# Semantic groups — the single definition of "what counts as what".
#
# Historically each call site re-spelled these sets inline
# (``in ("vulnerable", "bypassable")`` etc.), so they drifted: some report
# paths included ``inconclusive`` and some did not. They are defined once here.
# ---------------------------------------------------------------------------

#: Verdicts that represent a finding to act on / feed to dynamic testing.
ACTIONABLE_VERDICTS = frozenset(
    {Verdict.VULNERABLE, Verdict.BYPASSABLE, Verdict.CANDIDATE}
)

#: Verdicts worth surfacing in a report (actionable + needs-human-review).
REPORTABLE_VERDICTS = ACTIONABLE_VERDICTS | {Verdict.INCONCLUSIVE}

#: Verdicts that mean "no exploitable finding here" (defended or clean).
SAFE_VERDICTS = frozenset({Verdict.PROTECTED, Verdict.SAFE, Verdict.NO_FINDING})


def is_actionable(value: object) -> bool:
    """True for ``candidate``/``vulnerable``/``bypassable`` (any spelling)."""
    if isinstance(value, dict):
        return verdict_of(value) in ACTIONABLE_VERDICTS
    return normalize_verdict(value) in ACTIONABLE_VERDICTS


def is_reportable(value: object) -> bool:
    """True for ``vulnerable``/``bypassable``/``inconclusive`` (any spelling)."""
    if isinstance(value, dict):
        return verdict_of(value) in REPORTABLE_VERDICTS
    return normalize_verdict(value) in REPORTABLE_VERDICTS


def is_safe(value: object) -> bool:
    """True for ``protected``/``safe``/``no_finding`` (any spelling)."""
    if isinstance(value, dict):
        return verdict_of(value) in SAFE_VERDICTS
    return normalize_verdict(value) in SAFE_VERDICTS


def canonical_verdict(value: object) -> str:
    """Return the canonical lower-case spelling of a *recognized* verdict.

    Unlike :func:`normalize_verdict`, an unrecognized value is passed through
    unchanged (as a string) rather than collapsed to a default. This makes it
    safe to canonicalize the on-disk ``stage1_verdict``/``stage2_verdict``
    fields, which historically also carried non-verdict labels (e.g. a CWE
    short name) that must be preserved verbatim.
    """
    if isinstance(value, Verdict):
        return value.value
    text = "" if value is None else str(value)
    canonical = _ALIASES.get(text.strip().lower())
    return canonical.value if canonical is not None else text


def verdict_of(result: object, default: Verdict = Verdict.ERROR) -> Verdict:
    """Resolve the *final* verdict of a result dict.

    Prefers Stage 1 ``decision``, then historical ``finding`` / ``verdict``.
    """
    if not isinstance(result, dict):
        return normalize_verdict(result, default)
    raw = result.get("decision") or result.get("finding") or result.get("verdict")
    return normalize_verdict(raw, default)


def transition_of(result: dict) -> VerdictTransition:
    """Resolve the Stage 1 -> final transition for a result dict.

    Relies on ``stage1_finding`` being preserved on the result during
    verification. When it is absent (e.g. an unverified finding) the verdict is
    assumed unchanged.
    """
    final = result.get("finding") or result.get("verdict")
    stage1 = result.get("stage1_finding") or final
    verification = result.get("verification") or {}
    return classify_transition(stage1, final, reasoning_agrees=verification.get("agree"))
