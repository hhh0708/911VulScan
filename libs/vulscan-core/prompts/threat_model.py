"""Threat-model helpers used by Stage 1/2 prompt assembly.

Phase 5 removed fixed ApplicationType attack models and trust conclusions.
Phase 10 removes the fixed \"internet browser attacker\" persona. Attacker
capability must be derived from Stage 1 preconditions, external_inputs,
exposed_interfaces, and call-graph / code evidence — or marked unknown.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def stage2_system_note(app_context) -> str:
    """No type-based trust policy is appended."""
    return ""


def stage2_attacker_description(
    app_context=None,
    *,
    preconditions: Optional[List[Any]] = None,
    external_inputs: Optional[List[Any]] = None,
    exposed_interfaces: Optional[List[Any]] = None,
    call_graph_summary: Optional[Dict[str, Any]] = None,
) -> str:
    """Describe attacker capability from evidence only — never default remote/local."""
    del app_context  # App type must not imply attacker capability
    parts: List[str] = [
        "## Attacker capability (evidence-derived only)",
        "Do NOT assume a remote browser attacker or a local shell user by default.",
        "Capability is unknown unless supported by the fields below.",
    ]
    if preconditions:
        parts.append(f"- Stage 1 preconditions: {preconditions!r}")
    else:
        parts.append("- Stage 1 preconditions: (none / unknown)")
    if external_inputs:
        parts.append(f"- external_inputs: {external_inputs!r}")
    else:
        parts.append("- external_inputs: unknown")
    if exposed_interfaces:
        parts.append(f"- exposed_interfaces: {exposed_interfaces!r}")
    else:
        parts.append("- exposed_interfaces: unknown")
    if call_graph_summary:
        parts.append(f"- call_graph evidence summary: {call_graph_summary!r}")
    else:
        parts.append("- call_graph evidence: unknown / not provided")
    parts.append(
        "If attacker capability cannot be determined from these sources, "
        "treat it as **unknown** and prefer inconclusive over inventing a threat model."
    )
    return "\n".join(parts)


def stage2_context_note(app_context) -> str:
    return ""


def stage2_closing_note(app_context) -> str:
    return (
        "\n\nAttacker capability reminder: unknown unless evidenced by "
        "preconditions / external_inputs / exposed_interfaces / call-graph."
    )


def stage1_system_note(app_context) -> str:
    return ""


def stage1_context_note(app_context) -> str:
    return ""


def stage1_input_question(app_context) -> str:
    """Neutral input-origin question (no type-based dismissal rules)."""
    return """2. **Where does input come from?**
   - External users (HTTP requests, uploads)? → potential concern
   - Other input channels present in the code? → evaluate reachability and impact
   - Do not dismiss a finding solely because documentation claims it is intended"""
