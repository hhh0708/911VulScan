"""Build canonical DetectionInput from unit + call graph + app context + enhancement."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from context.application_context import REPO_TEXT_ISOLATION_NOTICE
from utilities.enhancement.fingerprint import graph_neighborhood
from utilities.enhancement.schema import normalize_enhancement
from utilities.language_infer import infer_language

from core.detection.schema import DetectionInput


def _sha_short(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _app_context_dict(app_context: Any) -> Dict[str, Any]:
    if app_context is None:
        return {"status": "unavailable"}
    if hasattr(app_context, "to_dict"):
        try:
            return app_context.to_dict()
        except Exception:  # noqa: BLE001
            pass
    if isinstance(app_context, dict):
        return dict(app_context)
    return {"status": "unavailable", "raw": str(app_context)}


def build_evidence_table(
    unit: dict,
    *,
    enhancement: dict,
    app_context: dict,
    neighborhood: dict,
    reachability: dict,
) -> List[dict]:
    """Structured evidence entries with stable IDs."""
    evidence: List[dict] = []

    def add(
        kind: str,
        source: str,
        content: Any,
        *,
        confidence: str = "observed",
        extra_prov: Optional[dict] = None,
    ) -> None:
        payload = json.dumps(content, sort_keys=True, default=str)
        eid = f"ev_{kind}_{_sha_short(f'{source}|{payload}')}"
        # Deduplicate by id
        if any(e["evidence_id"] == eid for e in evidence):
            return
        evidence.append(
            {
                "evidence_id": eid,
                "kind": kind,
                "source": source,
                "provenance": {
                    "source": source,
                    **(extra_prov or {}),
                },
                "confidence": confidence,
                "content": content,
            }
        )

    code = unit.get("code", {}) if isinstance(unit.get("code"), dict) else {}
    primary = code.get("primary_code", "") or ""
    origin = code.get("primary_origin", {}) if isinstance(code.get("primary_origin"), dict) else {}

    add(
        "target_code",
        "unit.code",
        {
            "code_hash": hashlib.sha256(primary.encode("utf-8")).hexdigest(),
            "file_path": origin.get("file_path", ""),
            "function_name": origin.get("function_name", ""),
            "start_line": origin.get("start_line"),
            "end_line": origin.get("end_line"),
            # Include code text as untrusted content for the model (not system).
            "code": primary,
        },
        confidence="exact",
    )

    add(
        "reachability",
        "call_graph.reachability",
        reachability,
        confidence="exact" if reachability.get("status") == "reachable" else "low",
    )

    add(
        "call_graph_neighborhood",
        "call_graph.neighborhood",
        neighborhood,
        confidence="exact",
    )

    if enhancement:
        add(
            "enhancement",
            "enhancement.payload",
            {
                "related_units": enhancement.get("related_units") or [],
                "call_context": enhancement.get("call_context") or {},
                "dataflow_observations": enhancement.get("dataflow_observations") or [],
                "types_and_definitions": enhancement.get("types_and_definitions") or [],
                "build_runtime_context": enhancement.get("build_runtime_context") or {},
                "unknowns": enhancement.get("unknowns") or [],
            },
            confidence="low",
            extra_prov={"untrusted": True},
        )

    if app_context and app_context.get("status") != "unavailable":
        add(
            "app_context_facts",
            "app_context",
            {
                "status": app_context.get("status"),
                "purpose": app_context.get("purpose"),
                "components": app_context.get("components"),
                "exposed_interfaces": app_context.get("exposed_interfaces"),
                "external_inputs": app_context.get("external_inputs"),
                "privileged_operations": app_context.get("privileged_operations"),
                "trust_boundaries": app_context.get("trust_boundaries"),
                "deployment_assumptions": app_context.get("deployment_assumptions"),
                "unknowns": app_context.get("unknowns"),
            },
            confidence="low",
            extra_prov={"untrusted": True},
        )
        claims = app_context.get("documented_security_claims") or []
        if claims:
            add(
                "untrusted_claims",
                "app_context.documented_security_claims",
                claims,
                confidence="untrusted",
                extra_prov={"untrusted": True, "isolation": True},
            )

    meta = unit.get("metadata") or {}
    if meta.get("direct_calls") or meta.get("direct_callers"):
        add(
            "static_metadata",
            "unit.metadata",
            {
                "direct_calls": meta.get("direct_calls") or [],
                "direct_callers": meta.get("direct_callers") or [],
            },
            confidence="exact",
        )

    return evidence


def build_detection_input(
    unit: dict,
    *,
    app_context: Any = None,
    call_graph: Optional[dict] = None,
    language: Optional[str] = None,
) -> DetectionInput:
    """Assemble DetectionInput. Ignores legacy agent_context entirely."""
    unit_id = unit.get("id", "unknown")
    code = unit.get("code", {}) if isinstance(unit.get("code"), dict) else {}
    primary = code.get("primary_code", "") or ""
    lang = infer_language(
        language
        or unit.get("language")
        or (unit.get("metadata") or {}).get("language"),
        unit_id,
        primary,
    )

    # Ignore legacy agent_context / security_classification completely.
    enhancement_raw = unit.get("enhancement") or {}
    enhancement = normalize_enhancement(enhancement_raw, mode="passthrough")

    app_dict = _app_context_dict(app_context)
    neighborhood = graph_neighborhood(unit_id, call_graph)
    reachability = {
        "status": unit.get("reachability") or "unknown",
        "is_entry_point": bool(unit.get("is_entry_point")),
        "entry_point_reason": unit.get("entry_point_reason") or "",
    }

    evidence = build_evidence_table(
        unit,
        enhancement=enhancement,
        app_context=app_dict,
        neighborhood=neighborhood,
        reachability=reachability,
    )

    origin = code.get("primary_origin", {}) if isinstance(code.get("primary_origin"), dict) else {}
    target_unit = {
        "id": unit_id,
        "unit_type": unit.get("unit_type", "function"),
        "file_path": origin.get("file_path", ""),
        "function_name": origin.get("function_name", ""),
        "class_name": origin.get("class_name"),
        "start_line": origin.get("start_line"),
        "end_line": origin.get("end_line"),
        "files_included": origin.get("files_included") or [],
    }

    return {
        "unit_id": unit_id,
        "language": lang,
        "target_unit": target_unit,
        "reachability": reachability,
        "call_graph_neighborhood": neighborhood,
        "app_context": app_dict,
        "enhancement": {
            "related_units": enhancement.get("related_units") or [],
            "relation_type": enhancement.get("relation_type") or "",
            "types_and_definitions": enhancement.get("types_and_definitions") or [],
            "call_context": enhancement.get("call_context") or {},
            "dataflow_observations": enhancement.get("dataflow_observations") or [],
            "build_runtime_context": enhancement.get("build_runtime_context") or {},
            "unknowns": enhancement.get("unknowns") or [],
            "provenance": enhancement.get("provenance") or {},
        },
        "evidence": evidence,
        "untrusted_isolation_notice": REPO_TEXT_ISOLATION_NOTICE,
    }
