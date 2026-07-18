"""Unified call graph schema, structural roots, and three-state reachability."""

from utilities.call_graph.schema import (
    CANONICAL_KEYS,
    SCHEMA_VERSION,
    finalize_call_graph,
    is_valid_canonical,
    load_call_graph,
    normalize_call_graph,
    strip_to_canonical,
    to_legacy_export,
    unresolved_stats,
    write_call_graph,
)
from utilities.call_graph.structural_roots import detect_structural_roots
from utilities.call_graph.reachability import (
    ReachabilityStatus,
    all_unknown,
    compute_reachability,
    filter_keep_ids,
    scoped_candidates,
)

__all__ = [
    "CANONICAL_KEYS",
    "SCHEMA_VERSION",
    "finalize_call_graph",
    "is_valid_canonical",
    "load_call_graph",
    "normalize_call_graph",
    "strip_to_canonical",
    "to_legacy_export",
    "unresolved_stats",
    "write_call_graph",
    "detect_structural_roots",
    "ReachabilityStatus",
    "all_unknown",
    "compute_reachability",
    "filter_keep_ids",
    "scoped_candidates",
]
