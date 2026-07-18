"""Unified call-graph document schema and normalization helpers.

Canonical fields persisted in ``call_graph.json``:
  nodes, resolved_edges, unresolved_edges, structural_roots, provenance

Legacy fields (functions / call_graph / reverse_call_graph) are produced only
by :func:`to_legacy_export` for adapters — never written into canonical files.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utilities.file_io import read_json, write_json

SCHEMA_VERSION = "1.0"

CANONICAL_KEYS = frozenset(
    {
        "nodes",
        "resolved_edges",
        "unresolved_edges",
        "structural_roots",
        "provenance",
    }
)

_LEGACY_KEYS = frozenset(
    {
        "functions",
        "call_graph",
        "reverse_call_graph",
        "callGraph",
        "reverseCallGraph",
        "classes",
        "imports",
        "statistics",
        "repository",
        "repoRoot",
    }
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _node_from_function(func_id: str, func_data: Dict[str, Any], language: str) -> Dict[str, Any]:
    name = func_data.get("name") or func_id.split(":")[-1]
    file_path = (
        func_data.get("file_path")
        or func_data.get("filePath")
        or (func_id.split(":")[0] if ":" in func_id else "")
    )
    class_name = func_data.get("class_name") or func_data.get("className") or func_data.get("receiver")
    unit_type = func_data.get("unit_type") or func_data.get("unitType") or "function"
    is_exported = bool(
        func_data.get("is_exported", func_data.get("isExported", False))
    )
    kind = unit_type
    if func_data.get("kind"):
        kind = func_data["kind"]
    elif name == "main":
        kind = "program_entry"
    elif name == "init" and language == "go":
        kind = "module_init"
    elif unit_type == "module_level":
        kind = "module_init"
    elif unit_type in ("lambda", "nested_function", "closure"):
        kind = unit_type
    elif class_name and name == "__call__":
        kind = "callable"
    elif class_name:
        kind = "method"

    visibility = "public" if is_exported else "private"
    parent_id = func_data.get("parent_id") or func_data.get("parentId")
    if language == "python":
        if (
            not class_name
            and not parent_id
            and name
            and not name.startswith("_")
            and unit_type not in ("lambda", "nested_function", "closure", "module_level")
        ):
            visibility = "public"
            is_exported = True
    elif language == "go" and name and name[0].isupper():
        visibility = "public"
        is_exported = True
    elif language in ("c", "cpp", "c++") and not func_data.get("is_static", False):
        visibility = "public"
        is_exported = True
    elif language in ("javascript", "typescript", "js", "ts"):
        if func_data.get("is_exported", func_data.get("isExported", False)):
            visibility = "public"
            is_exported = True

    return {
        "id": func_id,
        "name": name,
        "qualified_name": func_data.get("qualified_name")
        or func_data.get("qualifiedName")
        or (f"{class_name}.{name}" if class_name else name),
        "file_path": file_path,
        "start_line": func_data.get("start_line", func_data.get("startLine", 0)),
        "end_line": func_data.get("end_line", func_data.get("endLine", 0)),
        "kind": kind,
        "visibility": visibility,
        "is_exported": is_exported,
        "receiver_type": class_name,
        "parent_id": parent_id,
        "language": language,
        "unit_type": unit_type,
        "code": func_data.get("code", ""),
        "decorators": func_data.get("decorators", []),
        "package": func_data.get("package", ""),
        "is_static": bool(func_data.get("is_static", False)),
    }


def _legacy_from_nodes(nodes: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    functions: Dict[str, Dict[str, Any]] = {}
    for func_id, node in nodes.items():
        functions[func_id] = {
            "name": node.get("name"),
            "qualified_name": node.get("qualified_name"),
            "file_path": node.get("file_path"),
            "filePath": node.get("file_path"),
            "start_line": node.get("start_line"),
            "startLine": node.get("start_line"),
            "end_line": node.get("end_line"),
            "endLine": node.get("end_line"),
            "unit_type": node.get("unit_type") or node.get("kind"),
            "unitType": node.get("unit_type") or node.get("kind"),
            "class_name": node.get("receiver_type"),
            "className": node.get("receiver_type"),
            "is_exported": node.get("is_exported", False),
            "isExported": node.get("is_exported", False),
            "code": node.get("code", ""),
            "decorators": node.get("decorators", []),
            "package": node.get("package", ""),
            "is_static": node.get("is_static", False),
            "kind": node.get("kind"),
            "parent_id": node.get("parent_id"),
        }
    return functions


def _edges_to_adjacency(
    resolved_edges: Iterable[Dict[str, Any]],
    *,
    exact_only: bool = False,
) -> Dict[str, List[str]]:
    graph: Dict[str, List[str]] = {}
    for edge in resolved_edges:
        caller = edge.get("caller")
        callee = edge.get("callee")
        if not caller or not callee:
            continue
        if exact_only and (edge.get("confidence") or "exact") != "exact":
            continue
        graph.setdefault(caller, [])
        if callee not in graph[caller]:
            graph[caller].append(callee)
    return graph


def _adjacency_to_reverse(call_graph: Dict[str, List[str]]) -> Dict[str, List[str]]:
    reverse: Dict[str, List[str]] = {}
    for caller, callees in call_graph.items():
        for callee in callees:
            reverse.setdefault(callee, [])
            if caller not in reverse[callee]:
                reverse[callee].append(caller)
    return reverse


def is_valid_canonical(data: Any) -> bool:
    """Return True if ``data`` is a usable canonical call-graph document."""
    if not isinstance(data, dict):
        return False
    if not CANONICAL_KEYS <= set(data.keys()):
        return False
    if not isinstance(data.get("nodes"), dict):
        return False
    for key in ("resolved_edges", "unresolved_edges", "structural_roots"):
        if not isinstance(data.get(key), list):
            return False
    if not isinstance(data.get("provenance"), dict):
        return False
    return True


def strip_to_canonical(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Return only canonical fields (+ schema_version/language metadata)."""
    out = {
        "schema_version": doc.get("schema_version") or SCHEMA_VERSION,
        "language": doc.get("language") or (doc.get("provenance") or {}).get("language") or "unknown",
        "nodes": doc.get("nodes") or {},
        "resolved_edges": list(doc.get("resolved_edges") or []),
        "unresolved_edges": list(doc.get("unresolved_edges") or []),
        "structural_roots": list(doc.get("structural_roots") or []),
        "provenance": dict(doc.get("provenance") or {}),
    }
    # Ensure provenance carries schema/language.
    out["provenance"].setdefault("schema_version", SCHEMA_VERSION)
    out["provenance"].setdefault("language", out["language"])
    return out


def to_legacy_export(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Build a legacy-shaped export from a canonical (or normalized) document.

    This is the *only* place production adapters should obtain
    ``functions`` / ``call_graph`` / ``reverse_call_graph``.
    """
    nodes = doc.get("nodes") or {}
    resolved = doc.get("resolved_edges") or []
    call_graph = _edges_to_adjacency(resolved, exact_only=False)
    reverse = _adjacency_to_reverse(call_graph)
    for nid in nodes:
        call_graph.setdefault(nid, [])
        reverse.setdefault(nid, [])
    return {
        "functions": _legacy_from_nodes(nodes),
        "call_graph": call_graph,
        "reverse_call_graph": reverse,
        "repository": (doc.get("provenance") or {}).get("repository", ""),
        "statistics": (doc.get("provenance") or {}).get("statistics", {}),
    }


def normalize_call_graph(
    data: Dict[str, Any],
    *,
    language: str = "unknown",
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Normalize legacy or partial call-graph JSON into a canonical document."""
    from utilities.call_graph.structural_roots import detect_structural_roots

    lang = data.get("language") or language
    unresolved_edges = list(
        data.get("unresolved_edges") or data.get("unresolvedEdges") or []
    )
    structural_roots = list(data.get("structural_roots") or [])

    if data.get("nodes") is not None and data.get("resolved_edges") is not None:
        # Canonical (or already-normalized) document.
        nodes = dict(data["nodes"])
        resolved_edges = list(data.get("resolved_edges") or [])
    elif data.get("resolved_edges") is not None and data.get("functions"):
        # Builder hybrid: keep edge confidence; build nodes from functions.
        functions = data.get("functions") or {}
        nodes = {
            fid: _node_from_function(fid, fdata, lang)
            for fid, fdata in functions.items()
        }
        resolved_edges = list(data.get("resolved_edges") or [])
    else:
        # Pure legacy adjacency — edges default to exact (AST-era exports).
        functions = data.get("functions") or {}
        nodes = {
            fid: _node_from_function(fid, fdata, lang)
            for fid, fdata in functions.items()
        }
        call_graph = data.get("call_graph") or data.get("callGraph") or {}
        resolved_edges = []
        for caller, callees in call_graph.items():
            for callee in callees or []:
                resolved_edges.append(
                    {
                        "caller": caller,
                        "callee": callee,
                        "kind": "call",
                        "confidence": "exact",
                    }
                )

    if not structural_roots:
        structural_roots = detect_structural_roots(nodes, language=lang)

    prov = dict(data.get("provenance") or {})
    if provenance:
        prov.update(provenance)
    prov.setdefault("schema_version", SCHEMA_VERSION)
    prov.setdefault("builder", prov.get("builder") or "utilities.call_graph.normalize")
    prov.setdefault("built_at", _now_iso())
    prov.setdefault("language", lang)
    if data.get("repository") or data.get("repoRoot"):
        prov.setdefault("repository", data.get("repository") or data.get("repoRoot"))

    return {
        "schema_version": SCHEMA_VERSION,
        "language": lang,
        "nodes": nodes,
        "resolved_edges": resolved_edges,
        "unresolved_edges": unresolved_edges,
        "structural_roots": structural_roots,
        "provenance": prov,
    }


def finalize_call_graph(
    data: Dict[str, Any],
    *,
    language: str = "unknown",
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Normalize to canonical form and attach unresolved stats into provenance."""
    doc = normalize_call_graph(data, language=language, provenance=provenance)
    stats = {
        "unresolved": unresolved_stats(doc),
        "structural_roots": len(doc.get("structural_roots") or []),
        "resolved_edges": len(doc.get("resolved_edges") or []),
        "nodes": len(doc.get("nodes") or {}),
    }
    doc["provenance"]["statistics"] = stats
    return strip_to_canonical(doc)


def unresolved_stats(doc: Dict[str, Any]) -> Dict[str, Any]:
    edges = doc.get("unresolved_edges") or []
    by_reason: Dict[str, int] = {}
    for edge in edges:
        reason = edge.get("reason") or "unknown"
        by_reason[reason] = by_reason.get(reason, 0) + 1
    return {
        "total": len(edges),
        "by_reason": by_reason,
    }


def write_call_graph(
    path: str | Path, data: Dict[str, Any], *, language: str = "unknown"
) -> Dict[str, Any]:
    """Write *canonical-only* call_graph.json (no legacy dual-source fields)."""
    doc = finalize_call_graph(data, language=language)
    write_json(path, doc)
    return doc


def load_call_graph(
    path: str | Path, *, language: str = "unknown"
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Load and finalize a call graph.

    Returns ``(doc, error)``. On failure ``doc`` is None and ``error`` explains why.
    Accepts legacy-shaped files by normalizing them in memory; the returned
    document is always canonical-only.
    """
    try:
        data = read_json(path)
    except Exception as exc:  # noqa: BLE001 — surface any I/O/parse failure
        return None, f"read_failed: {exc}"

    if not isinstance(data, dict):
        return None, "invalid_type"

    # Already canonical or legacy-convertible?
    try:
        doc = finalize_call_graph(data, language=language or data.get("language") or "unknown")
    except Exception as exc:  # noqa: BLE001
        return None, f"normalize_failed: {exc}"

    if not is_valid_canonical(doc):
        return None, "schema_invalid"

    # Dual-source conflict: if file mixes canonical + legacy adjacency that
    # disagrees with resolved_edges, reject.
    if data.get("nodes") is not None and (
        data.get("call_graph") is not None or data.get("callGraph") is not None
    ):
        legacy_adj = data.get("call_graph") or data.get("callGraph") or {}
        from_resolved = _edges_to_adjacency(doc["resolved_edges"], exact_only=False)
        # Compare edge sets (order-insensitive)
        def _edge_set(adj: Dict[str, List[str]]):
            return {(c, t) for c, ts in adj.items() for t in (ts or [])}

        if _edge_set(legacy_adj) != _edge_set(from_resolved):
            return None, "dual_source_conflict"

    return doc, None
