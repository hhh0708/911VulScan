"""
Output schemas for 911VulScan CLI.

All CLI commands produce a JSON envelope on stdout:
    {
        "schema_version": "1.0",
        "status": "completed|partial|failed",
        "run_id": "...",
        "stage": "...",
        "data": {...},
        "metrics": {...},
        "artifacts": [...],
        "warnings": [...],
        "errors": [...]
    }

Human-readable progress goes to stderr.

Each pipeline step also writes a {step}.report.json file with
standardized metadata (timing, cost, inputs, outputs).
"""

import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal

from core.final_artifact.metrics import AnalysisMetrics
from core.final_artifact.validate import fail_on, exit_code_for_fail_on, matches_fail_on
from utilities.file_io import write_json


# Re-export for backward-compatible imports from core.schemas
__all__ = [
    "AnalysisMetrics",
    "AnalyzeResult",
    "DynamicTestStepResult",
    "EnhanceResult",
    "ParseResult",
    "ReportResult",
    "ScanResult",
    "StepReport",
    "UsageInfo",
    "VerifyResult",
    "error",
    "exit_code_for_fail_on",
    "fail_on",
    "make_envelope",
    "matches_fail_on",
    "success",
]


EnvelopeStatus = Literal["completed", "partial", "failed"]


# ---------------------------------------------------------------------------
# JSON Envelope
# ---------------------------------------------------------------------------

def make_envelope(
    *,
    status: EnvelopeStatus,
    run_id: str | None = None,
    stage: str | None = None,
    data: dict | None = None,
    metrics: dict | None = None,
    artifacts: list | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    schema_version: str = "1.0",
) -> dict:
    """Create a canonical CLI response envelope."""
    return {
        "schema_version": schema_version,
        "status": status,
        "run_id": run_id,
        "stage": stage,
        "data": data or {},
        "metrics": metrics,
        "artifacts": artifacts or [],
        "warnings": warnings or [],
        "errors": errors or [],
    }


def success(data: dict, **kwargs: Any) -> dict:
    """Create a completed response envelope."""
    return make_envelope(status="completed", data=data, **kwargs)


def error(
    message: str,
    data: dict | None = None,
    errors: list[str] | None = None,
    **kwargs: Any,
) -> dict:
    """Create a failed response envelope."""
    return make_envelope(
        status="failed",
        data=data or {},
        errors=errors or [message],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Result types for each command
# ---------------------------------------------------------------------------

@dataclass
class ParseResult:
    """Result of `911vulscan parse`."""
    dataset_path: str
    analyzer_output_path: str | None = None
    units_count: int = 0
    language: str = "unknown"
    scope: str = "all"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UsageInfo:
    """Token usage and cost summary."""
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    cost_currency: str = "USD"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalyzeResult:
    """Result of `911vulscan analyze`."""
    results_path: str
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return {
            "results_path": self.results_path,
            "metrics": self.metrics.to_dict(),
            "usage": self.usage.to_dict(),
        }


@dataclass
class ReportResult:
    """Result of `911vulscan report`."""
    output_path: str
    format: str = "html"
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return {
            "output_path": self.output_path,
            "format": self.format,
            "usage": self.usage.to_dict(),
        }


@dataclass
class ScanResult:
    """Result of `911vulscan scan` (all-in-one)."""
    output_dir: str  # run_dir: {output_root}/runs/{run_id}/
    run_id: str | None = None
    output_root: str | None = None
    dataset_path: str | None = None
    enhanced_dataset_path: str | None = None
    analyzer_output_path: str | None = None
    app_context_path: str | None = None
    results_path: str | None = None
    verified_results_path: str | None = None
    pipeline_output_path: str | None = None
    report_path: str | None = None
    summary_path: str | None = None
    dynamic_test_path: str | None = None
    units_count: int = 0
    language: str = "unknown"
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    usage: UsageInfo = field(default_factory=UsageInfo)
    step_reports: list = field(default_factory=list)
    skipped_steps: list = field(default_factory=list)
    status: str = "completed"  # completed | partial | failed
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "output_dir": self.output_dir,
            "run_id": self.run_id,
            "output_root": self.output_root,
            "dataset_path": self.dataset_path,
            "enhanced_dataset_path": self.enhanced_dataset_path,
            "analyzer_output_path": self.analyzer_output_path,
            "app_context_path": self.app_context_path,
            "results_path": self.results_path,
            "verified_results_path": self.verified_results_path,
            "pipeline_output_path": self.pipeline_output_path,
            "report_path": self.report_path,
            "summary_path": self.summary_path,
            "dynamic_test_path": self.dynamic_test_path,
            "units_count": self.units_count,
            "language": self.language,
            "metrics": self.metrics.to_dict(),
            "usage": self.usage.to_dict(),
            "step_reports": self.step_reports,
            "skipped_steps": self.skipped_steps,
            "status": self.status,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


# ---------------------------------------------------------------------------
# Enhance result
# ---------------------------------------------------------------------------

@dataclass
class EnhanceResult:
    """Result of `911vulscan enhance`."""
    enhanced_dataset_path: str
    units_enhanced: int = 0
    error_count: int = 0
    error_summary: dict = field(default_factory=dict)
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        result = {
            "enhanced_dataset_path": self.enhanced_dataset_path,
            "units_enhanced": self.units_enhanced,
            "error_count": self.error_count,
            "usage": self.usage.to_dict(),
        }
        if self.error_summary:
            result["error_summary"] = self.error_summary
        return result


# ---------------------------------------------------------------------------
# Verify result
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    """Result of `911vulscan verify` (Stage 2 candidate verification)."""
    verified_results_path: str
    candidates_input: int = 0
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    confirmed: int = 0
    rejected: int = 0
    inconclusive: int = 0
    verified_unit_ids: frozenset[str] = field(default_factory=frozenset)
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return {
            "verified_results_path": self.verified_results_path,
            "candidates_input": self.candidates_input,
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "skipped": self.skipped,
            "confirmed": self.confirmed,
            "rejected": self.rejected,
            "inconclusive": self.inconclusive,
            "verified_unit_ids": sorted(self.verified_unit_ids),
            "usage": self.usage.to_dict(),
        }


# ---------------------------------------------------------------------------
# Dynamic test result
# ---------------------------------------------------------------------------

@dataclass
class DynamicTestStepResult:
    """Result of `911vulscan dynamic-test`."""
    results_json_path: str
    results_md_path: str | None = None
    candidates_input: int = 0
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    blocked: int = 0
    skipped: int = 0
    reproduced: int = 0
    not_reproduced: int = 0
    inconclusive: int = 0
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return {
            "results_json_path": self.results_json_path,
            "results_md_path": self.results_md_path,
            "candidates_input": self.candidates_input,
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "blocked": self.blocked,
            "skipped": self.skipped,
            "reproduced": self.reproduced,
            "not_reproduced": self.not_reproduced,
            "inconclusive": self.inconclusive,
            "usage": self.usage.to_dict(),
        }


# ---------------------------------------------------------------------------
# Step Report — written as {step}.report.json by every pipeline step
# ---------------------------------------------------------------------------

@dataclass
class StepReport:
    """Standardized report written by each pipeline step.

    Written as ``{step}.report.json`` in the output directory.
    Status: completed | partial | failed | skipped
    """
    step: str
    status: str = "completed"
    timestamp: str = ""
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    cost_currency: str = "USD"
    token_usage: dict = field(default_factory=lambda: {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    })
    summary: dict = field(default_factory=dict)
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def to_dict(self) -> dict:
        return asdict(self)

    def write(self, output_dir: str) -> str:
        """Write ``{step}.report.json`` to *output_dir*. Returns the path."""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f"{self.step}.report.json")
        write_json(path, self.to_dict())
        return path
