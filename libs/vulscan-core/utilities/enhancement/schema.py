"""Neutral Context Enhancement schema (single-shot and agentic).

Canonical payload fields only — no security classification or verdicts.
"""

from __future__ import annotations

from typing import Any, Dict, List, TypedDict

ENHANCEMENT_SCHEMA_VERSION = "1.0"
ENHANCEMENT_PROMPT_VERSION = "neutral-context-v1"

PAYLOAD_KEYS = (
    "related_units",
    "relation_type",
    "types_and_definitions",
    "call_context",
    "dataflow_observations",
    "build_runtime_context",
    "unknowns",
    "provenance",
)

# Recursively stripped from enhancement payloads (never persist).
FORBIDDEN_KEYS = frozenset(
    {
        "security_classification",
        "classification_reasoning",
        "exploitable",
        "vulnerable_internal",
        "additional_callers",
        "verdict",
        "finding",
        "confirmed",
        "decision",
        "cwe_id",
        "cwe_name",
        "attack_vector",
        "vulnerabilities",
        "severity",
        "why_vulnerable",
        "not_a_vulnerability",
    }
)


def strip_forbidden(obj: Any) -> Any:
    """Recursively remove verdict / security-classification / vuln-conclusion keys."""
    if isinstance(obj, dict):
        return {
            k: strip_forbidden(v)
            for k, v in obj.items()
            if k not in FORBIDDEN_KEYS
        }
    if isinstance(obj, list):
        return [strip_forbidden(v) for v in obj]
    return obj


class RelatedUnit(TypedDict, total=False):
    id: str
    relation_type: str
    reason: str


class EnhancementPayload(TypedDict, total=False):
    related_units: List[RelatedUnit]
    relation_type: str
    types_and_definitions: List[Any]
    call_context: Dict[str, Any]
    dataflow_observations: List[Any]
    build_runtime_context: Dict[str, Any]
    unknowns: List[Any]
    provenance: Dict[str, Any]


def empty_enhancement(
    *,
    mode: str = "unknown",
    model: str = "",
    error: Any = None,
) -> Dict[str, Any]:
    """Return an empty canonical enhancement payload."""
    payload: Dict[str, Any] = {
        "related_units": [],
        "relation_type": "",
        "types_and_definitions": [],
        "call_context": {
            "direct_calls": [],
            "direct_callers": [],
            "notes": [],
        },
        "dataflow_observations": [],
        "build_runtime_context": {},
        "unknowns": [],
        "provenance": {
            "schema_version": ENHANCEMENT_SCHEMA_VERSION,
            "prompt_version": ENHANCEMENT_PROMPT_VERSION,
            "mode": mode,
            "model": model,
        },
    }
    if error is not None:
        payload["provenance"]["error"] = error
        if isinstance(error, dict) and error.get("message"):
            payload["unknowns"].append(
                {"kind": "enhancement_error", "detail": error.get("message")}
            )
    return payload


def normalize_enhancement(raw: Any, *, mode: str = "unknown", model: str = "") -> Dict[str, Any]:
    """Coerce arbitrary LLM/tool output into the canonical payload."""
    base = empty_enhancement(mode=mode, model=model)
    if not isinstance(raw, dict):
        base["unknowns"].append({"kind": "invalid_payload", "detail": "non-object"})
        return base

    # --- related_units ---
    related = raw.get("related_units")
    if related is None and raw.get("include_functions"):
        # Migrate legacy agentic include_functions → related_units
        related = []
        for item in raw.get("include_functions") or []:
            if isinstance(item, dict):
                related.append(
                    {
                        "id": item.get("id", ""),
                        "relation_type": item.get("relation_type") or "related",
                        "reason": item.get("reason", ""),
                    }
                )
    if isinstance(related, list):
        cleaned = []
        for item in related:
            if not isinstance(item, dict):
                continue
            cleaned.append(
                {
                    "id": str(item.get("id") or ""),
                    "relation_type": str(
                        item.get("relation_type") or item.get("type") or "related"
                    ),
                    "reason": str(item.get("reason") or ""),
                }
            )
        base["related_units"] = cleaned

    if isinstance(raw.get("relation_type"), str):
        base["relation_type"] = raw["relation_type"]
    elif base["related_units"]:
        # Summarize dominant relation type
        types = [r.get("relation_type") or "" for r in base["related_units"]]
        base["relation_type"] = types[0] if len(set(types)) == 1 else "mixed"

    if isinstance(raw.get("types_and_definitions"), list):
        base["types_and_definitions"] = raw["types_and_definitions"]

    call_ctx = raw.get("call_context")
    if isinstance(call_ctx, dict):
        base["call_context"] = {
            "direct_calls": list(call_ctx.get("direct_calls") or []),
            "direct_callers": list(call_ctx.get("direct_callers") or []),
            "notes": list(call_ctx.get("notes") or []),
        }
    else:
        # Migrate legacy usage_context string into notes
        if isinstance(raw.get("usage_context"), str) and raw["usage_context"]:
            base["call_context"]["notes"] = [raw["usage_context"]]

    obs = raw.get("dataflow_observations")
    if obs is None and isinstance(raw.get("data_flow"), dict):
        # Migrate single-shot data_flow → observations (neutral, no vuln labels)
        df = raw["data_flow"]
        obs = []
        for inp in df.get("inputs") or []:
            obs.append({"kind": "input", "value": inp})
        for out in df.get("outputs") or []:
            obs.append({"kind": "output", "value": out})
        for tv in df.get("tainted_variables") or []:
            obs.append({"kind": "tainted_variable", "value": tv})
        # Drop security_relevant_flows / injection type guesses
    if isinstance(obs, list):
        base["dataflow_observations"] = obs

    if isinstance(raw.get("build_runtime_context"), dict):
        base["build_runtime_context"] = raw["build_runtime_context"]

    if isinstance(raw.get("unknowns"), list):
        base["unknowns"] = raw["unknowns"]

    prov = raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {}
    base["provenance"] = {
        **base["provenance"],
        **{k: v for k, v in prov.items() if k != "error" or v},
        "schema_version": ENHANCEMENT_SCHEMA_VERSION,
        "prompt_version": ENHANCEMENT_PROMPT_VERSION,
        "mode": mode or prov.get("mode") or mode,
        "model": model or prov.get("model") or "",
    }
    if raw.get("error") is not None:
        base["provenance"]["error"] = raw["error"]

    # Strip forbidden fields recursively (never persist).
    cleaned = {k: strip_forbidden(base[k]) for k in PAYLOAD_KEYS}
    return cleaned


def _contains_forbidden(obj: Any) -> bool:
    if isinstance(obj, dict):
        if FORBIDDEN_KEYS & set(obj.keys()):
            return True
        return any(_contains_forbidden(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_forbidden(v) for v in obj)
    return False


def validate_enhancement(payload: Any) -> bool:
    """Return True if payload has the required canonical shape."""
    if not isinstance(payload, dict):
        return False
    for key in PAYLOAD_KEYS:
        if key not in payload:
            return False
    if not isinstance(payload["related_units"], list):
        return False
    if not isinstance(payload["provenance"], dict):
        return False
    if _contains_forbidden(payload):
        return False
    return True
