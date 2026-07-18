"""Three-state reachability via a worklist / fixed-point algorithm.

Statuses form a lattice (unreachable < unknown < reachable). Reachable is
sticky and is only proven via ``confidence == "exact"`` resolved edges.
Unknown contamination (low-confidence edges, unresolved edges, empty
candidate dynamic sites) is propagated to a fixed point so results do not
depend on edge iteration order.
"""

from __future__ import annotations

from collections import deque
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


class ReachabilityStatus(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


# Lattice rank: higher wins and is never downgraded.
_RANK = {
    ReachabilityStatus.UNREACHABLE.value: 0,
    ReachabilityStatus.UNKNOWN.value: 1,
    ReachabilityStatus.REACHABLE.value: 2,
}

_EXACT = "exact"


def scoped_candidates(
    nodes: Dict[str, Dict[str, Any]],
    *,
    caller_id: str,
    callee_name: str,
    language: str = "unknown",
) -> List[str]:
    """Generate language-scoped candidate callees for an unresolved name.

    Prefer same-file name matches; then same-package / same-directory.
    Results are sorted for determinism.
    """
    if not callee_name or callee_name.startswith("<"):
        return []

    caller = nodes.get(caller_id) or {}
    caller_file = (caller.get("file_path") or "").replace("\\", "/")
    if not caller_file and ":" in caller_id:
        caller_file = caller_id.split(":", 1)[0].replace("\\", "/")

    same_file: List[str] = []
    same_scope: List[str] = []
    lang = (language or caller.get("language") or "unknown").lower()
    caller_pkg = caller.get("package") or ""
    caller_dir = "/".join(caller_file.split("/")[:-1]) if caller_file else ""

    simple = callee_name.split(".")[-1]
    for nid in sorted(nodes.keys()):
        if nid == caller_id:
            continue
        node = nodes[nid]
        name = node.get("name") or ""
        qn = node.get("qualified_name") or ""
        if name != simple and name != callee_name and not qn.endswith("." + simple):
            if qn != callee_name:
                continue
        file_path = (node.get("file_path") or "").replace("\\", "/")
        if caller_file and file_path == caller_file:
            same_file.append(nid)
            continue
        if lang == "go":
            if caller_pkg and node.get("package") == caller_pkg:
                same_scope.append(nid)
        elif caller_dir and "/".join(file_path.split("/")[:-1]) == caller_dir:
            same_scope.append(nid)

    if same_file:
        return sorted(dict.fromkeys(same_file))
    return sorted(dict.fromkeys(same_scope))


def _partition_edges(
    node_ids: Set[str],
    resolved_edges: Iterable[Dict[str, Any]],
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    exact_forward: Dict[str, List[str]] = {nid: [] for nid in node_ids}
    low_forward: Dict[str, List[str]] = {nid: [] for nid in node_ids}

    # Sort for order-independent construction.
    edges = sorted(
        (e for e in (resolved_edges or []) if isinstance(e, dict)),
        key=lambda e: (
            e.get("caller") or "",
            e.get("callee") or "",
            e.get("confidence") or "",
        ),
    )
    for edge in edges:
        caller = edge.get("caller")
        callee = edge.get("callee")
        if caller not in node_ids or callee not in node_ids or callee == caller:
            continue
        conf = (edge.get("confidence") or _EXACT).lower()
        bucket = exact_forward if conf == _EXACT else low_forward
        if callee not in bucket[caller]:
            bucket[caller].append(callee)

    for nid in node_ids:
        exact_forward[nid].sort()
        low_forward[nid].sort()
    return exact_forward, low_forward


def compute_reachability(
    nodes: Dict[str, Dict[str, Any]],
    resolved_edges: Iterable[Dict[str, Any]],
    unresolved_edges: Iterable[Dict[str, Any]],
    structural_roots: Iterable[Dict[str, Any]] | Iterable[str],
    *,
    language: str = "unknown",
) -> Dict[str, str]:
    """Return ``node_id -> status`` via fixed-point worklist propagation."""
    node_ids = set(nodes.keys())
    root_ids: Set[str] = set()
    for root in structural_roots or []:
        if isinstance(root, str):
            root_ids.add(root)
        elif isinstance(root, dict) and root.get("id"):
            root_ids.add(root["id"])
    root_ids &= node_ids

    if not root_ids:
        return {nid: ReachabilityStatus.UNKNOWN.value for nid in sorted(node_ids)}

    status: Dict[str, str] = {
        nid: ReachabilityStatus.UNREACHABLE.value for nid in node_ids
    }
    exact_forward, low_forward = _partition_edges(node_ids, resolved_edges)

    unresolved_list = sorted(
        (e for e in (unresolved_edges or []) if isinstance(e, dict)),
        key=lambda e: (
            e.get("caller") or "",
            e.get("callee_name") or "",
            e.get("reason") or "",
            tuple(sorted(e.get("candidates") or [])),
        ),
    )

    # Pre-resolve scoped candidates deterministically (mutate edge copies only
    # when the original edge dict is mutable — same as before).
    for edge in unresolved_list:
        if edge.get("candidates"):
            edge["candidates"] = sorted(edge["candidates"])
            continue
        caller = edge.get("caller")
        if caller not in node_ids:
            continue
        cands = scoped_candidates(
            nodes,
            caller_id=caller,
            callee_name=edge.get("callee_name") or "",
            language=language,
        )
        if cands:
            edge["candidates"] = cands
            edge.setdefault("candidate_source", "language_scope")

    def _raise(nid: str, new_status: str) -> bool:
        """Raise status in the lattice; return True if changed."""
        if nid not in node_ids:
            return False
        if _RANK[new_status] > _RANK[status[nid]]:
            status[nid] = new_status
            return True
        return False

    worklist: deque[str] = deque()
    in_queue: Set[str] = set()

    def _enqueue(nid: str) -> None:
        if nid in node_ids and nid not in in_queue:
            worklist.append(nid)
            in_queue.add(nid)

    for rid in sorted(root_ids):
        _raise(rid, ReachabilityStatus.REACHABLE.value)
        _enqueue(rid)

    global_unknown = False

    while worklist:
        current = worklist.popleft()
        in_queue.discard(current)
        cur_st = status[current]

        if cur_st == ReachabilityStatus.REACHABLE.value:
            for callee in exact_forward.get(current, []):
                if _raise(callee, ReachabilityStatus.REACHABLE.value):
                    _enqueue(callee)
            for callee in low_forward.get(current, []):
                if _raise(callee, ReachabilityStatus.UNKNOWN.value):
                    _enqueue(callee)

        if cur_st in (
            ReachabilityStatus.REACHABLE.value,
            ReachabilityStatus.UNKNOWN.value,
        ):
            # Unknown propagates through exact+low outgoing edges.
            if cur_st == ReachabilityStatus.UNKNOWN.value:
                for callee in exact_forward.get(current, []) + low_forward.get(
                    current, []
                ):
                    if _raise(callee, ReachabilityStatus.UNKNOWN.value):
                        _enqueue(callee)

            for edge in unresolved_list:
                if edge.get("caller") != current:
                    continue
                candidates = list(edge.get("candidates") or [])
                if candidates:
                    for cand in candidates:
                        if _raise(cand, ReachabilityStatus.UNKNOWN.value):
                            _enqueue(cand)
                else:
                    global_unknown = True

        if global_unknown:
            break

    if global_unknown:
        for nid in sorted(node_ids):
            if status[nid] != ReachabilityStatus.REACHABLE.value:
                status[nid] = ReachabilityStatus.UNKNOWN.value

    return status


def filter_keep_ids(
    status_map: Dict[str, str],
    *,
    keep: Optional[Set[str]] = None,
) -> Set[str]:
    """IDs to keep for ``scope=reachable``: reachable + unknown."""
    keep = keep or {
        ReachabilityStatus.REACHABLE.value,
        ReachabilityStatus.UNKNOWN.value,
    }
    return {nid for nid, st in status_map.items() if st in keep}


def all_unknown(node_ids: Iterable[str]) -> Dict[str, str]:
    """Mark every id as unknown (missing/invalid call graph)."""
    return {nid: ReachabilityStatus.UNKNOWN.value for nid in node_ids}
