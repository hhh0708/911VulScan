"""Content-addressed fingerprints and stable finding_id for Stage 2."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from core.verification.schema import (
    VERIFICATION_PROMPT_VERSION,
    VERIFICATION_SCHEMA_VERSION,
    VERIFICATION_TOOLS_VERSION,
)


def _sha256_json(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    ).hexdigest()


def compute_finding_id(
    unit_id: str,
    detection_input_fingerprint: str,
    stage1_candidate: Dict[str, Any],
) -> str:
    """Stable SHA-256 finding_id from unit + DetectionInput fp + candidate body."""
    candidate_core = {
        "decision": stage1_candidate.get("decision"),
        "candidate_type": stage1_candidate.get("candidate_type"),
        "cwe_id": stage1_candidate.get("cwe_id"),
        "source": stage1_candidate.get("source"),
        "propagation": stage1_candidate.get("propagation"),
        "sink": stage1_candidate.get("sink"),
        "impact": stage1_candidate.get("impact"),
        "evidence_ids": stage1_candidate.get("evidence_ids") or [],
        "location": stage1_candidate.get("location") or {},
    }
    payload = {
        "unit_id": unit_id,
        "detection_input_fingerprint": detection_input_fingerprint,
        "stage1_candidate": candidate_core,
    }
    return _sha256_json(payload)


def compute_verification_fingerprint(
    verification_input: Dict[str, Any],
    *,
    model: str = "",
    prompt_version: str = VERIFICATION_PROMPT_VERSION,
    schema_version: str = VERIFICATION_SCHEMA_VERSION,
    tools_version: str = VERIFICATION_TOOLS_VERSION,
    analyzer_index_hash: str = "",
    call_graph_hash: str = "",
) -> str:
    """Fingerprint over VerificationInput + versions (no unit_id-only restore)."""
    # Exclude raw target_code from fingerprint payload duplication — hash it.
    vin = dict(verification_input)
    code = vin.pop("target_code", "") or ""
    payload = {
        "verification_input": vin,
        "target_code_hash": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "stage1_candidate": verification_input.get("stage1_candidate") or {},
        "analyzer_index_hash": analyzer_index_hash or "",
        "call_graph_hash": call_graph_hash
        or _sha256_json(verification_input.get("call_graph") or {}),
        "model": model or "",
        "prompt_version": prompt_version,
        "schema_version": schema_version,
        "tools_version": tools_version,
    }
    return _sha256_json(payload)
