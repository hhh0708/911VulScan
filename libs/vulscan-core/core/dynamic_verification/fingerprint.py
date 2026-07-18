"""Content-addressed fingerprints for dynamic verification."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from core.dynamic_verification.schema import (
    DYNAMIC_COMPILER_VERSION,
    DYNAMIC_PROMPT_VERSION,
    DYNAMIC_RUNNER_VERSION,
    DYNAMIC_SCHEMA_VERSION,
)


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)


def compute_test_id(dynamic_input: Dict[str, Any]) -> str:
    """Stable SHA-256 test_id from DynamicVerificationInput fingerprint material."""
    material = {
        "finding_id": dynamic_input.get("finding_id"),
        "unit_id": dynamic_input.get("unit_id"),
        "stage1_candidate": dynamic_input.get("stage1_candidate"),
        "stage2_decision": (dynamic_input.get("stage2_verification") or {}).get(
            "decision"
        ),
        "stage2_state": (dynamic_input.get("stage2_verification") or {}).get(
            "execution_state"
        ),
        "target_code_hash": hashlib.sha256(
            (dynamic_input.get("target_code") or "").encode("utf-8")
        ).hexdigest(),
        "language": dynamic_input.get("language"),
        "preconditions": dynamic_input.get("preconditions"),
        "sandbox_policy": dynamic_input.get("sandbox_policy"),
        "evidence_ids": sorted(
            e.get("evidence_id")
            for e in (dynamic_input.get("evidence") or [])
            if isinstance(e, dict) and e.get("evidence_id")
        ),
        "schema_version": DYNAMIC_SCHEMA_VERSION,
    }
    return hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()


def compute_dynamic_fingerprint(
    dynamic_input: Dict[str, Any],
    *,
    test_plan: Optional[Dict[str, Any]] = None,
    image_digest: str = "",
    model: str = "",
    policy_hash: str = "",
) -> str:
    """Base checkpoint fingerprint (stable). Image digest is stored separately.

    ``image_digest`` is included only when non-empty so load/save use the same
    base fingerprint; digest is verified via checkpoint metadata.
    """
    stage2 = dynamic_input.get("stage2_verification") or {}
    material = {
        "dynamic_input": {
            "test_id": dynamic_input.get("test_id"),
            "finding_id": dynamic_input.get("finding_id"),
            "unit_id": dynamic_input.get("unit_id"),
            "language": dynamic_input.get("language"),
            "target_code_hash": hashlib.sha256(
                (dynamic_input.get("target_code") or "").encode("utf-8")
            ).hexdigest(),
            "preconditions": dynamic_input.get("preconditions"),
            "sandbox_policy": dynamic_input.get("sandbox_policy"),
            "build_runtime_context": dynamic_input.get("build_runtime_context"),
            "repository_manifest": dynamic_input.get("repository_manifest"),
            "stage2_decision": stage2.get("decision"),
            "stage2_evidence_ids": stage2.get("evidence_ids"),
            "stage2_counter_ids": stage2.get("counter_evidence_ids"),
        },
        "test_plan": test_plan or {},
        "stage2_evidence_hashes": sorted(
            e.get("content_hash") or e.get("evidence_id")
            for e in (dynamic_input.get("evidence") or [])
            if isinstance(e, dict)
        ),
        "policy_hash": policy_hash or "",
        "versions": {
            "schema": DYNAMIC_SCHEMA_VERSION,
            "prompt": DYNAMIC_PROMPT_VERSION,
            "compiler": DYNAMIC_COMPILER_VERSION,
            "runner": DYNAMIC_RUNNER_VERSION,
            "model": model,
        },
    }
    # Only fold digest into fingerprint when explicitly provided (post-build verify)
    if image_digest:
        material["image_digest"] = image_digest
    return hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()
