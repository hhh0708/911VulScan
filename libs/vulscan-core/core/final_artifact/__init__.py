"""Canonical final scan artifact package."""

from core.final_artifact.evidence_index import (
    build_evidence_index,
    collect_evidence_ids_from_finding,
    merge_evidence_indexes,
    resolve_evidence_ids,
    scan_raw_evidence_lists,
    validate_evidence_index,
)
from core.final_artifact.finalize import (
    FinalArtifactIntegrityError,
    load_and_validate_final_artifact,
    remove_stale_final_artifacts,
    write_final_scan_artifact,
    verify_run_manifest_before_report,
)
from core.final_artifact.manifest import (
    ManifestEntry,
    dumps_stable,
    hash_file,
    make_entry,
    validate_upstream_hashes,
)
from core.final_artifact.metrics import AnalysisMetrics
from core.final_artifact.reducer import compute_final_state, reduce_to_final_artifact
from core.final_artifact.report_data import build_report_data_from_artifact
from core.final_artifact.schema import (
    CATEGORY_STATES,
    FINAL_STATES,
    LEGACY_FORBIDDEN_KEYS,
    SCHEMA_VERSION,
    FinalScanArtifact,
    FindingRecord,
    StageStatus,
    UnitSummary,
)
from core.final_artifact.validate import fail_on, validate_final_scan_artifact, exit_code_for_fail_on, matches_fail_on

__all__ = [
    "AnalysisMetrics",
    "CATEGORY_STATES",
    "FINAL_STATES",
    "FinalScanArtifact",
    "FindingRecord",
    "LEGACY_FORBIDDEN_KEYS",
    "ManifestEntry",
    "SCHEMA_VERSION",
    "StageStatus",
    "UnitSummary",
    "build_evidence_index",
    "build_report_data_from_artifact",
    "collect_evidence_ids_from_finding",
    "compute_final_state",
    "dumps_stable",
    "exit_code_for_fail_on",
    "fail_on",
    "FinalArtifactIntegrityError",
    "hash_file",
    "load_and_validate_final_artifact",
    "make_entry",
    "matches_fail_on",
    "merge_evidence_indexes",
    "reduce_to_final_artifact",
    "remove_stale_final_artifacts",
    "resolve_evidence_ids",
    "validate_evidence_index",
    "validate_final_scan_artifact",
    "validate_upstream_hashes",
    "verify_run_manifest_before_report",
    "write_final_scan_artifact",
]
