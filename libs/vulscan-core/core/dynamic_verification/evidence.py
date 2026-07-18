"""Stable dynamic-verification evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from utilities.credentials import redact_secrets


def _hash(material: Any) -> str:
    payload = json.dumps(material, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def make_dynamic_evidence(
    *,
    kind: str,
    stdout: str = "",
    stderr: str = "",
    exit_code: int | None = None,
    signal: int | None = None,
    sanitizer_report: str = "",
    observations: Optional[Dict[str, Any]] = None,
    image_digest: str = "",
    test_plan_hash: str = "",
    run_command_hash: str = "",
    source: str = "dynamic.runner",
) -> Dict[str, Any]:
    stdout_h = _hash(stdout or "")
    stderr_h = _hash(stderr or "")
    content = {
        "stdout_hash": stdout_h,
        "stderr_hash": stderr_h,
        "exit_code": exit_code,
        "signal": signal,
        "sanitizer_report_hash": _hash(sanitizer_report or "") if sanitizer_report else "",
        "observations": observations or {},
        "image_digest": image_digest or "",
        "test_plan_hash": test_plan_hash or "",
        "run_command_hash": run_command_hash or "",
        # Previews are display-only
        "stdout_preview": redact_secrets((stdout or "")[:400]),
        "stderr_preview": redact_secrets((stderr or "")[:400]),
    }
    digest = _hash(content)
    eid = f"ev_dyn_{kind}_{digest[:16]}"
    return {
        "evidence_id": eid,
        "kind": kind,
        "source": source,
        "content_hash": digest,
        "content": content,
        "provenance": {
            "source": source,
            "stage": "dynamic",
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }


def append_unique(evidence: List[dict], entry: dict) -> str:
    eid = entry.get("evidence_id") or ""
    if any(e.get("evidence_id") == eid for e in evidence):
        return eid
    evidence.append(entry)
    return eid
