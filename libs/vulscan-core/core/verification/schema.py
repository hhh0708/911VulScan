"""Canonical Stage 2 VerificationInput / VerificationResult schemas."""

from __future__ import annotations

from typing import Any, Dict, List, TypedDict

from core.verification.evidence import (
    CONFIRMED_EVIDENCE_ROLES,
    has_reject_counter_evidence,
    resolve_evidence,
    roles_covered_by_evidence,
)

VERIFICATION_SCHEMA_VERSION = "1.0"
VERIFICATION_PROMPT_VERSION = "candidate-verify-v2"
VERIFICATION_TOOLS_VERSION = "tools-v2"

EXECUTION_STATES = frozenset(
    {"pending", "running", "succeeded", "failed", "skipped"}
)
DECISIONS = frozenset({"confirmed", "rejected", "inconclusive"})

RESULT_KEYS = (
    "finding_id",
    "execution_state",
    "decision",
    "verified_source",
    "propagation",
    "sink",
    "guards",
    "impact",
    "evidence_ids",
    "counter_evidence_ids",
    "evidence",
    "missing_evidence",
    "uncertainties",
    "confidence",
    "provenance",
)

FORBIDDEN_RESULT_KEYS = frozenset(
    {
        "agree",
        "correct_finding",
        "stage1_finding",
        "verification_note",
        "finding",
        "verdict",
        "attack_vector",
        "reasoning",
    }
)


class VerificationInput(TypedDict, total=False):
    finding_id: str
    unit_id: str
    stage1_candidate: Dict[str, Any]
    detection_input: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    call_graph: Dict[str, Any]
    app_context: Dict[str, Any]
    enhancement: Dict[str, Any]
    repository_index_provenance: Dict[str, Any]
    untrusted_isolation_notice: str
    target_code: str


class VerificationResult(TypedDict, total=False):
    finding_id: str
    execution_state: str
    decision: str
    verified_source: str
    propagation: str
    sink: str
    guards: List[Any]
    impact: str
    evidence_ids: List[str]
    counter_evidence_ids: List[str]
    evidence: List[Dict[str, Any]]
    missing_evidence: List[Any]
    uncertainties: List[Any]
    confidence: float
    provenance: Dict[str, Any]


def empty_verification_result(
    finding_id: str = "",
    *,
    execution_state: str = "failed",
    decision: str = "inconclusive",
    reason: str = "",
    model: str = "",
    evidence: List[dict] | None = None,
) -> Dict[str, Any]:
    if execution_state not in EXECUTION_STATES:
        execution_state = "failed"
    if decision not in DECISIONS:
        decision = "inconclusive"
    # Never treat incomplete runs as confirmed/rejected.
    if execution_state in ("failed", "skipped") and decision in (
        "confirmed",
        "rejected",
    ):
        decision = "inconclusive"
    return {
        "finding_id": finding_id,
        "execution_state": execution_state,
        "decision": decision,
        "verified_source": "",
        "propagation": "",
        "sink": "",
        "guards": [],
        "impact": "",
        "evidence_ids": [],
        "counter_evidence_ids": [],
        "evidence": list(evidence or []),
        "missing_evidence": [],
        "uncertainties": [{"kind": "error", "detail": reason}] if reason else [],
        "confidence": 0.0,
        "provenance": {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "prompt_version": VERIFICATION_PROMPT_VERSION,
            "tools_version": VERIFICATION_TOOLS_VERSION,
            "model": model,
        },
    }


def skipped_result(finding_id: str, *, reason: str, model: str = "") -> Dict[str, Any]:
    return empty_verification_result(
        finding_id,
        execution_state="skipped",
        decision="inconclusive",
        reason=reason,
        model=model,
    )


def _coerce_id_list(value: Any) -> List[str] | None:
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


def normalize_verification_result(
    raw: Any,
    *,
    finding_id: str,
    evidence_ids: set[str],
    evidence_table: List[dict] | None = None,
    model: str = "",
    execution_state: str = "succeeded",
) -> Dict[str, Any]:
    """Validate finish payload into VerificationResult.

    Unknown evidence IDs or illegal enums → decision=inconclusive.
    confirmed requires citable source/propagation/sink/impact evidence.
    rejected requires counter-evidence of path break / guard / precondition.
    Never auto-promote to confirmed.
    """
    table = list(evidence_table or [])
    base = empty_verification_result(
        finding_id,
        execution_state=execution_state if execution_state in EXECUTION_STATES else "failed",
        decision="inconclusive",
        model=model,
        evidence=table,
    )

    if execution_state in ("failed", "skipped"):
        base["execution_state"] = execution_state
        base["decision"] = "inconclusive"
        if isinstance(raw, dict) and raw.get("reason"):
            base["uncertainties"].append(
                {"kind": "termination", "detail": str(raw.get("reason"))}
            )
        return base

    if not isinstance(raw, dict):
        base["execution_state"] = "failed"
        base["uncertainties"].append(
            {"kind": "invalid_payload", "detail": "non-object finish payload"}
        )
        return base

    # Reject legacy fields
    if FORBIDDEN_RESULT_KEYS & set(raw.keys()):
        base["execution_state"] = "succeeded"
        base["decision"] = "inconclusive"
        base["uncertainties"].append(
            {
                "kind": "forbidden_fields",
                "detail": sorted(FORBIDDEN_RESULT_KEYS & set(raw.keys())),
            }
        )
        return base

    decision = raw.get("decision")
    if not isinstance(decision, str) or decision not in DECISIONS:
        legacy = raw.get("correct_finding") or raw.get("finding")
        base["decision"] = "inconclusive"
        base["uncertainties"].append(
            {
                "kind": "invalid_decision",
                "detail": f"got {decision!r} (legacy={legacy!r})",
            }
        )
        return base

    evid = _coerce_id_list(raw.get("evidence_ids"))
    counter = _coerce_id_list(raw.get("counter_evidence_ids"))
    if evid is None or counter is None:
        base["decision"] = "inconclusive"
        base["uncertainties"].append(
            {"kind": "invalid_type", "detail": "evidence_ids must be string arrays"}
        )
        return base

    unknown = [eid for eid in evid + counter if eid not in evidence_ids]
    if unknown:
        base["decision"] = "inconclusive"
        base["evidence_ids"] = [e for e in evid if e in evidence_ids]
        base["counter_evidence_ids"] = [e for e in counter if e in evidence_ids]
        cited = resolve_evidence(table, base["evidence_ids"] + base["counter_evidence_ids"])
        base["evidence"] = cited
        base["uncertainties"].append(
            {
                "kind": "unknown_evidence_id",
                "detail": f"referenced IDs not in evidence table: {unknown}",
            }
        )
        conf = raw.get("confidence", 0.0)
        if isinstance(conf, (int, float)):
            base["confidence"] = float(conf)
        return base

    conf = raw.get("confidence", 0.0)
    if not isinstance(conf, (int, float)):
        base["decision"] = "inconclusive"
        base["uncertainties"].append(
            {"kind": "invalid_type", "detail": "confidence must be a number"}
        )
        return base

    guards = raw.get("guards", [])
    missing = raw.get("missing_evidence", [])
    uncertainties = raw.get("uncertainties", [])
    if not isinstance(guards, list) or not isinstance(missing, list):
        base["decision"] = "inconclusive"
        base["uncertainties"].append(
            {"kind": "invalid_type", "detail": "guards/missing_evidence must be arrays"}
        )
        return base
    if not isinstance(uncertainties, list):
        uncertainties = []

    verified_source = str(raw.get("verified_source") or "")
    propagation = str(raw.get("propagation") or "")
    sink = str(raw.get("sink") or "")
    impact = str(raw.get("impact") or "")
    evidence_roles = raw.get("evidence_roles") if isinstance(raw.get("evidence_roles"), dict) else {}

    cited_support = resolve_evidence(table, evid)
    cited_counter = resolve_evidence(table, counter)

    # --- confirmed gates ---
    if decision == "confirmed":
        if not evid:
            decision = "inconclusive"
            uncertainties = list(uncertainties) + [
                {
                    "kind": "missing_evidence",
                    "detail": "confirmed requires at least one evidence_id",
                }
            ]
        elif not all((verified_source.strip(), propagation.strip(), sink.strip(), impact.strip())):
            decision = "inconclusive"
            uncertainties = list(uncertainties) + [
                {
                    "kind": "missing_path_fields",
                    "detail": "confirmed requires verified_source, propagation, sink, impact",
                }
            ]
        else:
            covered = roles_covered_by_evidence(cited_support, evidence_roles)
            # Allow explicit evidence_roles OR field+id pairing via roles map keys
            if evidence_roles:
                missing_roles = sorted(CONFIRMED_EVIDENCE_ROLES - covered)
            else:
                # Without roles map: require each textual field non-empty (above)
                # AND at least one cited evidence tagged/covering each role,
                # OR len(evid)>=4 as weak fallback is NOT allowed — must cover roles.
                missing_roles = sorted(CONFIRMED_EVIDENCE_ROLES - covered)
                # If roles absent on evidence, accept when evidence_roles omitted only if
                # each of the four path fields is non-empty AND evid cites ≥1 id AND
                # caller attached role via content — otherwise downgrade.
                if missing_roles and not evidence_roles:
                    # Synthesize coverage from path fields only when evidence_roles
                    # explicitly maps them — otherwise inconclusive.
                    pass
            if missing_roles:
                decision = "inconclusive"
                uncertainties = list(uncertainties) + [
                    {
                        "kind": "missing_role_evidence",
                        "detail": (
                            "confirmed requires citable evidence for "
                            f"source/propagation/sink/impact; missing={missing_roles}"
                        ),
                    }
                ]

    # --- rejected gates ---
    if decision == "rejected":
        if not counter:
            decision = "inconclusive"
            uncertainties = list(uncertainties) + [
                {
                    "kind": "missing_counter_evidence",
                    "detail": "rejected requires counter_evidence_ids",
                }
            ]
        elif not has_reject_counter_evidence(cited_counter):
            decision = "inconclusive"
            uncertainties = list(uncertainties) + [
                {
                    "kind": "insufficient_counter_evidence",
                    "detail": (
                        "rejected requires counter evidence proving path break, "
                        "valid guard, or unmet precondition"
                    ),
                }
            ]

    prov = raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {}
    cited_all = resolve_evidence(table, evid + counter)
    result = {
        "finding_id": finding_id,
        "execution_state": "succeeded",
        "decision": decision,
        "verified_source": verified_source,
        "propagation": propagation,
        "sink": sink,
        "guards": guards,
        "impact": impact,
        "evidence_ids": evid,
        "counter_evidence_ids": counter,
        "evidence": cited_all,
        "missing_evidence": missing,
        "uncertainties": uncertainties,
        "confidence": float(conf),
        "provenance": {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "prompt_version": VERIFICATION_PROMPT_VERSION,
            "tools_version": VERIFICATION_TOOLS_VERSION,
            "model": model,
            **{k: v for k, v in prov.items() if k not in FORBIDDEN_RESULT_KEYS},
        },
    }
    return {k: result[k] for k in RESULT_KEYS}


def validate_verification_result(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in RESULT_KEYS:
        if key not in payload:
            return False
    if payload.get("execution_state") not in EXECUTION_STATES:
        return False
    if payload.get("decision") not in DECISIONS:
        return False
    if FORBIDDEN_RESULT_KEYS & set(payload.keys()):
        return False
    # Mutual exclusion: confirmed cannot be failed/skipped
    if payload["decision"] == "confirmed" and payload["execution_state"] != "succeeded":
        return False
    return True
