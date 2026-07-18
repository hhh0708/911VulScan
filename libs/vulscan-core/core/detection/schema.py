"""Canonical Stage 1 DetectionInput / DetectionResult schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict

DETECTION_SCHEMA_VERSION = "1.0"
DETECTION_PROMPT_VERSION = "candidate-discovery-v1"

DECISIONS = frozenset({"candidate", "no_finding", "inconclusive", "error"})

RESULT_KEYS = (
    "unit_id",
    "decision",
    "candidate_type",
    "cwe_id",
    "location",
    "source",
    "propagation",
    "sink",
    "guards",
    "impact",
    "preconditions",
    "evidence_ids",
    "counter_evidence_ids",
    "uncertainties",
    "confidence",
    "provenance",
)

# Forbidden in Stage 1 results (candidate discovery only).
FORBIDDEN_RESULT_KEYS = frozenset(
    {
        "confirmed",
        "verdict",
        "finding",
        "security_classification",
        "classification_reasoning",
        "vulnerable",
        "exploitable",
        "vulnerable_internal",
        "agree",
        "correct_finding",
    }
)


class EvidenceEntry(TypedDict, total=False):
    evidence_id: str
    kind: str
    source: str
    provenance: Dict[str, Any]
    confidence: str
    content: Any


class DetectionInput(TypedDict, total=False):
    unit_id: str
    language: str
    target_unit: Dict[str, Any]
    reachability: Dict[str, Any]
    call_graph_neighborhood: Dict[str, Any]
    app_context: Dict[str, Any]
    enhancement: Dict[str, Any]
    evidence: List[EvidenceEntry]
    untrusted_isolation_notice: str


class DetectionResult(TypedDict, total=False):
    unit_id: str
    decision: str
    candidate_type: str
    cwe_id: Any
    location: Dict[str, Any]
    source: str
    propagation: str
    sink: str
    guards: List[Any]
    impact: str
    preconditions: List[Any]
    evidence_ids: List[str]
    counter_evidence_ids: List[str]
    uncertainties: List[Any]
    confidence: float
    provenance: Dict[str, Any]


def empty_detection_result(
    unit_id: str = "",
    *,
    decision: str = "error",
    reason: str = "",
    model: str = "",
) -> Dict[str, Any]:
    return {
        "unit_id": unit_id,
        "decision": decision if decision in DECISIONS else "error",
        "candidate_type": "",
        "cwe_id": 0,
        "location": {},
        "source": "",
        "propagation": "",
        "sink": "",
        "guards": [],
        "impact": "",
        "preconditions": [],
        "evidence_ids": [],
        "counter_evidence_ids": [],
        "uncertainties": [{"kind": "error", "detail": reason}] if reason else [],
        "confidence": 0.0,
        "provenance": {
            "schema_version": DETECTION_SCHEMA_VERSION,
            "prompt_version": DETECTION_PROMPT_VERSION,
            "model": model,
        },
    }


def _coerce_id_list(value: Any) -> Optional[List[str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        return None
    out: List[str] = []
    for item in value:
        if item is None:
            continue
        if not isinstance(item, (str, int)):
            return None
        out.append(str(item))
    return out


def _is_unsafe_location_file(value: Any) -> bool:
    """True when a ``location.file`` value is not a repo-relative path.

    Repos being scanned are untrusted: absolute paths (POSIX, Windows drive,
    UNC) or ``..`` segments would point outside the scanned tree, so the
    schema boundary refuses to propagate them.
    """
    if not isinstance(value, str):
        return True
    if not value:
        return False
    if value.startswith(("/", "\\", "~")):
        return True
    if len(value) >= 2 and value[0].isalpha() and value[1] == ":":
        return True  # Windows drive-qualified path
    return any(seg == ".." for seg in value.replace("\\", "/").split("/"))


def normalize_detection_result(
    raw: Any,
    *,
    unit_id: str,
    evidence_ids: set[str],
    model: str = "",
) -> Dict[str, Any]:
    """Validate and coerce LLM output into DetectionResult.

    Invalid enums, types, or unknown evidence IDs → ``decision=inconclusive``.
    Never auto-patches into a stronger finding. Never emits ``confirmed``.
    """
    base = empty_detection_result(unit_id, decision="inconclusive", model=model)

    if not isinstance(raw, dict):
        base["uncertainties"].append(
            {"kind": "invalid_payload", "detail": "non-object response"}
        )
        return base

    # Reject confirmed / legacy verdict claims at top level.
    if "confirmed" in raw or raw.get("decision") == "confirmed":
        base["uncertainties"].append(
            {"kind": "forbidden_field", "detail": "Stage 1 must not emit confirmed"}
        )
        return base

    decision = raw.get("decision")
    if not isinstance(decision, str) or decision not in DECISIONS:
        # Map legacy finding/verdict strings only to inconclusive — never to candidate.
        legacy = raw.get("finding") or raw.get("verdict")
        if isinstance(legacy, str) and legacy.lower() in (
            "vulnerable",
            "bypassable",
            "safe",
            "protected",
        ):
            base["uncertainties"].append(
                {
                    "kind": "legacy_verdict_rejected",
                    "detail": f"legacy field {legacy!r} is not a Stage 1 decision",
                }
            )
            return base
        base["uncertainties"].append(
            {"kind": "invalid_decision", "detail": f"got {decision!r}"}
        )
        return base

    if decision == "confirmed":
        base["uncertainties"].append(
            {"kind": "forbidden_decision", "detail": "confirmed"}
        )
        return base

    evid = _coerce_id_list(raw.get("evidence_ids"))
    counter = _coerce_id_list(raw.get("counter_evidence_ids"))
    if evid is None or counter is None:
        base["uncertainties"].append(
            {"kind": "invalid_type", "detail": "evidence_ids must be string arrays"}
        )
        return base

    unknown = [eid for eid in evid + counter if eid not in evidence_ids]
    if unknown:
        base["decision"] = "inconclusive"
        base["uncertainties"].append(
            {
                "kind": "unknown_evidence_id",
                "detail": f"referenced IDs not in evidence table: {unknown}",
            }
        )
        base["evidence_ids"] = [e for e in evid if e in evidence_ids]
        base["counter_evidence_ids"] = [e for e in counter if e in evidence_ids]
        base["confidence"] = float(raw.get("confidence") or 0.0) if isinstance(
            raw.get("confidence"), (int, float)
        ) else 0.0
        return base

    conf = raw.get("confidence", 0.0)
    if not isinstance(conf, (int, float)):
        base["uncertainties"].append(
            {"kind": "invalid_type", "detail": "confidence must be a number"}
        )
        return base

    guards = raw.get("guards", [])
    preconditions = raw.get("preconditions", [])
    uncertainties = raw.get("uncertainties", [])
    if not isinstance(guards, list) or not isinstance(preconditions, list):
        base["uncertainties"].append(
            {"kind": "invalid_type", "detail": "guards/preconditions must be arrays"}
        )
        return base
    if not isinstance(uncertainties, list):
        uncertainties = [{"kind": "invalid_type", "detail": "uncertainties coerced"}]

    location = raw.get("location") if isinstance(raw.get("location"), dict) else {}
    loc_file = location.get("file")
    if loc_file is not None and _is_unsafe_location_file(loc_file):
        # Sanitize: drop the offending path, keep the rest of the finding.
        location = {k: v for k, v in location.items() if k != "file"}
        uncertainties = list(uncertainties) + [
            {
                "kind": "invalid_location_file",
                "detail": "location.file must be a relative path without '..'",
            }
        ]
    cwe = raw.get("cwe_id", 0)
    if cwe is None:
        cwe = 0
    if not isinstance(cwe, (int, str)):
        base["uncertainties"].append(
            {"kind": "invalid_type", "detail": "cwe_id must be int or string"}
        )
        return base

    prov = raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {}
    result = {
        "unit_id": unit_id,
        "decision": decision,
        "candidate_type": str(raw.get("candidate_type") or ""),
        "cwe_id": cwe,
        "location": location,
        "source": str(raw.get("source") or ""),
        "propagation": str(raw.get("propagation") or ""),
        "sink": str(raw.get("sink") or ""),
        "guards": guards,
        "impact": str(raw.get("impact") or ""),
        "preconditions": preconditions,
        "evidence_ids": evid,
        "counter_evidence_ids": counter,
        "uncertainties": uncertainties,
        "confidence": float(conf),
        "provenance": {
            "schema_version": DETECTION_SCHEMA_VERSION,
            "prompt_version": DETECTION_PROMPT_VERSION,
            "model": model,
            **{k: v for k, v in prov.items() if k not in FORBIDDEN_RESULT_KEYS},
        },
    }

    # Strip any forbidden keys that slipped into nested structures.
    for key in list(result.keys()):
        if key in FORBIDDEN_RESULT_KEYS:
            del result[key]

    # candidate without any supporting evidence → inconclusive
    if decision == "candidate" and not evid:
        result["decision"] = "inconclusive"
        result["uncertainties"] = list(result["uncertainties"]) + [
            {
                "kind": "missing_evidence",
                "detail": "candidate requires at least one evidence_id",
            }
        ]

    # unknown reachability / thin evidence must not force no_finding
    # (handled in prompt; schema only blocks illegal strengthenings)

    return {k: result[k] for k in RESULT_KEYS}


def validate_detection_result(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in RESULT_KEYS:
        if key not in payload:
            return False
    if payload.get("decision") not in DECISIONS:
        return False
    if payload.get("decision") == "confirmed" or "confirmed" in payload:
        return False
    if FORBIDDEN_RESULT_KEYS & set(payload.keys()):
        return False
    if not isinstance(payload.get("evidence_ids"), list):
        return False
    if not isinstance(payload.get("counter_evidence_ids"), list):
        return False
    return True
