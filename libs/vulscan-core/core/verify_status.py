"""Map Stage 2 verification fields to granular confirmation strength labels.

Verdict spellings/casing are resolved through :mod:`core.verdict`.
"""

from __future__ import annotations

from typing import Any

from core.verdict import is_actionable, is_safe


def map_verification_status(
    finding: dict[str, Any],
    *,
    full_result: dict[str, Any] | None = None,
) -> str:
    """Return confirmed | likely | uncertain | disagreed | protected | timeout | max_iterations."""
    full = full_result or finding
    verification = finding.get("verification") or full.get("verification") or {}
    stage1 = (
        finding.get("verdict")
        or finding.get("finding")
        or full.get("finding", "")
    )

    explanation = (verification.get("explanation") or "").strip()
    if explanation == "Max iterations reached":
        return "max_iterations"
    if "timeout" in explanation.lower():
        return "timeout"

    agree = verification.get("agree")
    correct = verification.get("correct_finding") or finding.get("finding") or ""

    if not verification:
        if is_safe(stage1):
            return "protected"
        return "uncertain"

    exploit_path = verification.get("exploit_path") or {}
    sink_reached = exploit_path.get("sink_reached", True)
    attacker_control = exploit_path.get("attacker_control_at_sink", "unknown")
    path_broken = exploit_path.get("path_broken_at")

    if agree is False:
        if is_safe(correct):
            return "protected"
        return "disagreed"

    if is_safe(correct):
        return "protected"

    if not sink_reached or path_broken or attacker_control == "none":
        if is_actionable(stage1):
            return "likely"
        return "protected"

    if agree and is_actionable(correct):
        if exploit_path and sink_reached and attacker_control not in ("none", "unknown"):
            return "confirmed"
        return "likely"

    if agree:
        return "likely"

    return "uncertain"
