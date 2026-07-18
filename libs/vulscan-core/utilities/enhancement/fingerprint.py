"""Content-addressed fingerprints for Context Enhancement checkpoints."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from utilities.enhancement.schema import (
    ENHANCEMENT_PROMPT_VERSION,
    ENHANCEMENT_SCHEMA_VERSION,
)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(obj: Any) -> str:
    return _sha256_text(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str))


def _unit_code(unit: dict) -> str:
    code = unit.get("code", {})
    if isinstance(code, dict):
        return code.get("primary_code", "") or ""
    return str(code or "")


def _structure_metadata(unit: dict) -> Dict[str, Any]:
    code = unit.get("code", {}) if isinstance(unit.get("code"), dict) else {}
    origin = code.get("primary_origin", {}) if isinstance(code.get("primary_origin"), dict) else {}
    meta = unit.get("metadata", {}) if isinstance(unit.get("metadata"), dict) else {}
    root_kind = ""
    reason = unit.get("entry_point_reason") or ""
    if isinstance(reason, str) and reason.startswith("structural_root:"):
        root_kind = reason.split(":", 1)[1]
    elif unit.get("is_entry_point"):
        root_kind = "structural_root"
    return {
        "id": unit.get("id", ""),
        "unit_type": unit.get("unit_type", ""),
        "file_path": origin.get("file_path") or meta.get("file_path") or "",
        "start_line": origin.get("start_line") or meta.get("start_line") or 0,
        "end_line": origin.get("end_line") or meta.get("end_line") or 0,
        "function_name": origin.get("function_name") or meta.get("function_name") or "",
        "class_name": origin.get("class_name") or meta.get("class_name") or "",
        "parameters": meta.get("parameters") or unit.get("parameters") or [],
        "reachability": unit.get("reachability") or "",
        "is_entry_point": bool(unit.get("is_entry_point")),
        "structural_root_kind": root_kind,
    }


def graph_neighborhood(
    unit_id: str,
    call_graph: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Local resolved / low / unresolved neighborhood around unit_id."""
    if not call_graph or not isinstance(call_graph, dict):
        return {"resolved": [], "low": [], "unresolved": []}

    nodes = call_graph.get("nodes") or {}
    resolved = call_graph.get("resolved_edges") or []
    unresolved = call_graph.get("unresolved_edges") or []

    local_resolved = []
    local_low = []
    for edge in resolved:
        if not isinstance(edge, dict):
            continue
        if edge.get("caller") != unit_id and edge.get("callee") != unit_id:
            continue
        item = {
            "caller": edge.get("caller"),
            "callee": edge.get("callee"),
            "confidence": edge.get("confidence", "exact"),
        }
        if (edge.get("confidence") or "exact") == "exact":
            local_resolved.append(item)
        else:
            local_low.append(item)

    local_unresolved = []
    for edge in unresolved:
        if not isinstance(edge, dict):
            continue
        if edge.get("caller") != unit_id:
            cands = edge.get("candidates") or []
            if unit_id not in cands:
                continue
        local_unresolved.append(
            {
                "caller": edge.get("caller"),
                "callee_name": edge.get("callee_name"),
                "reason": edge.get("reason"),
                "candidates": sorted(edge.get("candidates") or []),
            }
        )

    # Include node kind/visibility for the unit itself if present.
    node = nodes.get(unit_id) or {}
    return {
        "node": {
            "kind": node.get("kind"),
            "visibility": node.get("visibility"),
            "is_exported": node.get("is_exported"),
        },
        "resolved": sorted(local_resolved, key=lambda e: (e["caller"], e["callee"])),
        "low": sorted(local_low, key=lambda e: (e["caller"], e["callee"])),
        "unresolved": sorted(
            local_unresolved, key=lambda e: (e["caller"] or "", e["callee_name"] or "")
        ),
    }


def hash_file(path: Optional[str | Path]) -> str:
    """SHA-256 of file contents, or empty string if missing."""
    if not path:
        return ""
    p = Path(path)
    if not p.is_file():
        return ""
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_app_context(app_context: Any) -> str:
    if app_context is None:
        return ""
    if hasattr(app_context, "to_dict"):
        try:
            return _sha256_json(app_context.to_dict())
        except Exception:  # noqa: BLE001
            pass
    if isinstance(app_context, dict):
        return _sha256_json(app_context)
    return _sha256_text(str(app_context))


@dataclass
class EnhancementFingerprintInputs:
    unit: dict
    call_graph: Optional[Dict[str, Any]] = None
    app_context: Any = None
    analyzer_output_path: Optional[str] = None
    analyzer_output_hash: Optional[str] = None
    model: str = ""
    mode: str = "agentic"
    prompt_version: str = ENHANCEMENT_PROMPT_VERSION
    schema_version: str = ENHANCEMENT_SCHEMA_VERSION


def compute_enhancement_fingerprint(inputs: EnhancementFingerprintInputs) -> str:
    """Stable fingerprint covering code, structure, graph, context, and versions."""
    unit = inputs.unit or {}
    unit_id = unit.get("id", "")
    code = _unit_code(unit)
    analyzer_hash = inputs.analyzer_output_hash
    if analyzer_hash is None:
        analyzer_hash = hash_file(inputs.analyzer_output_path)

    payload = {
        "code_hash": _sha256_text(code),
        "structure": _structure_metadata(unit),
        "graph_neighborhood": graph_neighborhood(unit_id, inputs.call_graph),
        "app_context_hash": hash_app_context(inputs.app_context),
        "analyzer_output_hash": analyzer_hash or "",
        "model": inputs.model or "",
        "mode": inputs.mode or "",
        "prompt_version": inputs.prompt_version or ENHANCEMENT_PROMPT_VERSION,
        "schema_version": inputs.schema_version or ENHANCEMENT_SCHEMA_VERSION,
    }
    return _sha256_json(payload)
