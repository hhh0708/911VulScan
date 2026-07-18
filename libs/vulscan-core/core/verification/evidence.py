"""Stage 2 evidence artifacts: stable IDs, hashing, redaction."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from utilities.credentials import redact_secrets

# Roles required for decision=confirmed
CONFIRMED_EVIDENCE_ROLES = frozenset(
    {"source", "propagation", "sink", "impact"}
)
# Counter-evidence reason kinds that justify decision=rejected
REJECT_REASON_KINDS = frozenset(
    {
        "path_break",
        "broken_path",
        "valid_guard",
        "guard",
        "precondition_failure",
        "precondition",
        "unreachable",
    }
)


def content_hash(content: Any) -> str:
    """SHA-256 over canonical JSON of *full* content (never preview)."""
    payload = json.dumps(content, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def stable_evidence_id(
    *,
    kind: str,
    source: str,
    content_digest: str,
    tool: str = "",
) -> str:
    """Stable ID from kind/source/full-content hash — never from preview text."""
    material = f"{kind}|{source}|{tool}|{content_digest}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"ev_{kind}_{digest}"


def redact_value(value: Any) -> Any:
    """Recursively redact secret-looking strings for storage/display."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value


def make_tool_evidence(
    *,
    tool: str,
    tool_input: Any,
    full_result: Any,
    source: str = "",
    preview_limit: int = 800,
) -> Dict[str, Any]:
    """Build a normalized tool evidence artifact.

    Preview is display-only and must not participate in evidence_id generation.
    """
    redacted_input = redact_value(tool_input)
    redacted_result = redact_value(full_result)
    digest = content_hash(
        {"tool": tool, "input": redacted_input, "result": redacted_result}
    )
    kind = f"tool_{tool}"
    src = source or f"stage2.tool.{tool}"
    eid = stable_evidence_id(
        kind=kind, source=src, content_digest=digest, tool=tool
    )
    preview = _preview(redacted_result, limit=preview_limit)
    return {
        "evidence_id": eid,
        "kind": kind,
        "source": src,
        "confidence": "observed",
        "provenance": {
            "source": src,
            "tool": tool,
            "stage": "stage2",
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "content": {
            "tool": tool,
            "input": redacted_input,
            "result": redacted_result,
            "content_hash": digest,
            "result_preview": preview,  # display only
        },
        "content_hash": digest,
    }


def resolve_evidence(
    evidence_table: List[dict], evidence_ids: List[str]
) -> List[Dict[str, Any]]:
    """Return full evidence artifacts for resolvable IDs (order preserved)."""
    by_id = {
        e.get("evidence_id"): e
        for e in evidence_table
        if isinstance(e, dict) and e.get("evidence_id")
    }
    out: List[Dict[str, Any]] = []
    for eid in evidence_ids:
        entry = by_id.get(eid)
        if entry is not None:
            out.append(entry)
    return out


def roles_covered_by_evidence(
    evidence_entries: List[dict],
    evidence_roles: Optional[Dict[str, Any]] = None,
) -> set[str]:
    covered: set[str] = set()
    if isinstance(evidence_roles, dict):
        for role, ids in evidence_roles.items():
            role_l = str(role).lower().strip()
            if role_l in CONFIRMED_EVIDENCE_ROLES and ids:
                covered.add(role_l)
    for ev in evidence_entries:
        if not isinstance(ev, dict):
            continue
        for key in ("role", "covers", "evidence_role"):
            val = ev.get(key)
            if isinstance(val, str) and val.lower() in CONFIRMED_EVIDENCE_ROLES:
                covered.add(val.lower())
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.lower() in CONFIRMED_EVIDENCE_ROLES:
                        covered.add(item.lower())
        content = ev.get("content") or {}
        if isinstance(content, dict):
            for key in ("role", "covers"):
                val = content.get(key)
                if isinstance(val, str) and val.lower() in CONFIRMED_EVIDENCE_ROLES:
                    covered.add(val.lower())
                elif isinstance(val, list):
                    for item in val:
                        if (
                            isinstance(item, str)
                            and item.lower() in CONFIRMED_EVIDENCE_ROLES
                        ):
                            covered.add(item.lower())
        kind = str(ev.get("kind") or "").lower()
        for role in CONFIRMED_EVIDENCE_ROLES:
            if role in kind:
                covered.add(role)
    return covered


def has_reject_counter_evidence(counter_entries: List[dict]) -> bool:
    for ev in counter_entries:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("kind") or "").lower()
        content = ev.get("content") if isinstance(ev.get("content"), dict) else {}
        reason = str(
            content.get("reject_reason")
            or content.get("reason_kind")
            or content.get("reason")
            or ""
        ).lower()
        for token in REJECT_REASON_KINDS:
            if token in kind or token in reason:
                return True
        # Explicit boolean flags
        if content.get("path_broken") or content.get("guard_valid"):
            return True
        if content.get("precondition_failed") or content.get("precondition_unmet"):
            return True
    return False


def _preview(result: Any, limit: int = 800) -> Any:
    try:
        text = json.dumps(result, default=str, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        text = str(result)
    if len(text) > limit:
        return text[:limit] + "…"
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return text
