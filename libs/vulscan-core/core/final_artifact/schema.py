"""Canonical FinalScanArtifact and related types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "1.0"

FINAL_STATES = frozenset(
    {
        "reproduced",
        "confirmed_not_dynamically_tested",
        "confirmed_not_reproduced",
        "candidate",
        "rejected",
        "inconclusive",
        "error",
    }
)

LEGACY_FORBIDDEN_KEYS = frozenset(
    {
        "application_type",
        "finding",
        "verdict",
        "stage1_verdict",
        "stage2_verdict",
        "final_verdict",
        "vulnerable",
        "bypassable",
        "protected",
        "safe",
        "agreed",
        "disagreed",
        "confirmed_vulnerabilities",
        "attack_vector",
        "reasoning",
        "code_by_route",
        "classifications",
        "vulnerabilities",
    }
)

CATEGORY_STATES = frozenset({"candidate", "rejected", "inconclusive", "error"})


@dataclass
class StageStatus:
    """Per-stage pipeline execution status."""

    parse: str = "pending"
    enhance: str = "pending"
    analyze: str = "pending"
    verify: str = "pending"
    dynamic_test: str = "pending"
    report: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UnitSummary:
    """High-level unit counts for the run."""

    total_units: int = 0
    reachable: int = 0
    unreachable: int = 0
    unknown_reachability: int = 0
    analyzed: int = 0
    with_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingRecord:
    """Single unit finding with independent stage snapshots."""

    unit_id: str
    finding_id: str | None = None
    final_state: str = "candidate"
    stage1_detection: dict[str, Any] | None = None
    stage2_verification: dict[str, Any] | None = None
    dynamic_verification: dict[str, Any] | None = None
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FinalScanArtifact:
    """Top-level canonical artifact for a completed scan run."""

    schema_version: str = SCHEMA_VERSION
    run: dict[str, Any] = field(default_factory=dict)
    repository: dict[str, Any] = field(default_factory=dict)
    configuration: dict[str, Any] = field(default_factory=dict)
    stage_status: dict[str, Any] = field(default_factory=dict)
    unit_summary: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    inconclusive: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    evidence_index: dict[str, dict[str, Any]] = field(default_factory=dict)
    artifact_manifest: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
