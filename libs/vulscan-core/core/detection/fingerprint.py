"""Content-addressed fingerprints for Stage 1 analyze checkpoints."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from core.detection.schema import DETECTION_PROMPT_VERSION, DETECTION_SCHEMA_VERSION


def _sha256_json(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    ).hexdigest()


def compute_detection_fingerprint(
    detection_input: Dict[str, Any],
    *,
    model: str = "",
    prompt_version: str = DETECTION_PROMPT_VERSION,
    schema_version: str = DETECTION_SCHEMA_VERSION,
    graph_version: Optional[str] = None,
) -> str:
    """Fingerprint over full DetectionInput + versions (no code duplication)."""
    # Hash code content inside evidence rather than storing raw code again.
    app = detection_input.get("app_context") or {}
    enh = detection_input.get("enhancement") or {}
    payload = {
        "detection_input": detection_input,
        "app_context_hash": _sha256_json(app),
        "enhancement_hash": _sha256_json(enh),
        "graph_version": graph_version
        or _sha256_json(detection_input.get("call_graph_neighborhood") or {}),
        "model": model or "",
        "prompt_version": prompt_version,
        "schema_version": schema_version,
    }
    return _sha256_json(payload)
