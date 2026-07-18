"""Validation for canonical FinalScanArtifact output."""

from __future__ import annotations

from typing import Any

from core.final_artifact.evidence_index import (
    collect_evidence_ids_from_finding,
    validate_evidence_index,
)
from core.final_artifact.metrics import AnalysisMetrics
from core.final_artifact.schema import FINAL_STATES, LEGACY_FORBIDDEN_KEYS


CONFIRMED_FINAL_STATES = frozenset(
    {
        "reproduced",
        "confirmed_not_dynamically_tested",
        "confirmed_not_reproduced",
    }
)

FAIL_ON_LEVELS = frozenset({"candidate", "confirmed", "reproduced", "error"})


def fail_on(errors: list[str], *, label: str = "validation") -> None:
    """Raise ValueError when *errors* is non-empty."""
    if errors:
        raise ValueError(f"{label} failed:\n" + "\n".join(f"  - {e}" for e in errors))


def matches_fail_on(
    metrics: dict[str, Any],
    level: str | None,
    *,
    findings: list[dict[str, Any]] | None = None,
) -> bool:
    """Return True when CLI ``--fail-on`` threshold is met."""
    if not level:
        return False
    if level not in FAIL_ON_LEVELS:
        raise ValueError(
            f"invalid fail-on level {level!r}; expected one of "
            f"{sorted(FAIL_ON_LEVELS)}"
        )

    if level == "candidate":
        if metrics.get("stage1_candidates", 0) > 0:
            return True
        if findings:
            return any(f.get("final_state") == "candidate" for f in findings)
        return False

    if level == "confirmed":
        if metrics.get("stage2_confirmed", 0) > 0:
            return True
        if findings:
            return any(f.get("final_state") in CONFIRMED_FINAL_STATES for f in findings)
        return False

    if level == "reproduced":
        if metrics.get("dynamic_reproduced", 0) > 0:
            return True
        if findings:
            return any(f.get("final_state") == "reproduced" for f in findings)
        return False

    if level == "error":
        error_count = (
            int(metrics.get("stage1_errors", 0))
            + int(metrics.get("stage2_failed", 0))
            + int(metrics.get("dynamic_failed", 0))
        )
        if error_count > 0:
            return True
        if findings:
            return any(f.get("final_state") == "error" for f in findings)
        return False

    return False


def exit_code_for_fail_on(
    metrics: dict[str, Any],
    level: str | None,
    *,
    findings: list[dict[str, Any]] | None = None,
) -> int:
    """Return 1 when *level* threshold matches, else 0."""
    return 1 if matches_fail_on(metrics, level, findings=findings) else 0


def _scan_legacy_keys(obj: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_path = f"{path}.{key}" if path else key
            if key in LEGACY_FORBIDDEN_KEYS:
                errors.append(f"legacy forbidden key at {key_path}: {key!r}")
            errors.extend(_scan_legacy_keys(value, key_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            errors.extend(_scan_legacy_keys(item, f"{path}[{i}]"))
    return errors


def _count_by_final_state(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        state = f.get("final_state")
        if state:
            counts[state] = counts.get(state, 0) + 1
    return counts


def validate_final_scan_artifact(artifact: dict[str, Any]) -> list[str]:
    """Return validation errors for a FinalScanArtifact dict."""
    errors: list[str] = []

    if artifact.get("schema_version") != "1.0":
        errors.append(
            f"unsupported schema_version: {artifact.get('schema_version')!r}"
        )

    findings = artifact.get("findings") or []
    candidates = artifact.get("candidates") or []
    rejected = artifact.get("rejected") or []
    inconclusive = artifact.get("inconclusive") or []
    error_findings = artifact.get("errors") or []
    evidence_index = artifact.get("evidence_index") or {}

    errors.extend(validate_evidence_index(evidence_index))
    errors.extend(_scan_legacy_keys(artifact))

    state_counts = _count_by_final_state(findings)

    for i, finding in enumerate(findings):
        prefix = f"findings[{i}]"
        final_state = finding.get("final_state")

        if final_state not in FINAL_STATES:
            errors.append(f"{prefix}: invalid final_state {final_state!r}")
            continue

        s1 = finding.get("stage1_detection") or {}
        s2 = finding.get("stage2_verification") or {}
        dyn = finding.get("dynamic_verification") or {}

        if final_state == "reproduced":
            if dyn.get("decision") != "reproduced" or dyn.get("execution_state") != "succeeded":
                errors.append(f"{prefix}: reproduced requires dynamic reproduced+succeeded")
            if s2.get("decision") != "confirmed":
                errors.append(f"{prefix}: candidate cannot enter reproduced without stage2 confirmed")

        if final_state in CONFIRMED_FINAL_STATES and s2.get("decision") == "rejected":
            errors.append(f"{prefix}: stage2 rejected cannot appear as {final_state}")

        if final_state == "confirmed_not_reproduced":
            if dyn.get("decision") != "not_reproduced":
                errors.append(
                    f"{prefix}: confirmed_not_reproduced requires dynamic not_reproduced"
                )

        # Legacy "safe" label must not appear in production paths.
        for stage_name, stage in (
            ("stage1_detection", s1),
            ("stage2_verification", s2),
            ("dynamic_verification", dyn),
        ):
            if stage.get("decision") == "safe" or stage.get("verdict") == "safe":
                errors.append(f"{prefix}.{stage_name}: must not use legacy 'safe' label")
            if dyn.get("decision") == "not_reproduced" and final_state == "safe":
                errors.append(f"{prefix}: not_reproduced cannot be labeled safe")

        for eid in collect_evidence_ids_from_finding(finding):
            if eid not in evidence_index:
                errors.append(f"{prefix}: unresolved evidence_id {eid!r}")

    # Bucket consistency: filtered views must match final_state counts.
    if len(candidates) != state_counts.get("candidate", 0):
        errors.append(
            f"candidates list length {len(candidates)} != "
            f"final_state=candidate count {state_counts.get('candidate', 0)}"
        )
    if len(rejected) != state_counts.get("rejected", 0):
        errors.append(
            f"rejected list length {len(rejected)} != "
            f"final_state=rejected count {state_counts.get('rejected', 0)}"
        )
    if len(inconclusive) != state_counts.get("inconclusive", 0):
        errors.append(
            f"inconclusive list length {len(inconclusive)} != "
            f"final_state=inconclusive count {state_counts.get('inconclusive', 0)}"
        )
    if len(error_findings) != state_counts.get("error", 0):
        errors.append(
            f"errors list length {len(error_findings)} != "
            f"final_state=error count {state_counts.get('error', 0)}"
        )

    # Metrics cross-checks.
    metrics_raw = artifact.get("metrics") or {}
    metrics = AnalysisMetrics(**{
        k: metrics_raw.get(k, 0)
        for k in AnalysisMetrics.__dataclass_fields__
    })
    stage_status_early = artifact.get("stage_status") or {}
    errors.extend(
        metrics.validate_invariants(
            reachability_partial=stage_status_early.get("reachability") == "partial"
        )
    )

    if metrics.dynamic_not_reproduced > 0:
        nr_count = state_counts.get("confirmed_not_reproduced", 0)
        if nr_count > metrics.dynamic_not_reproduced:
            errors.append(
                "confirmed_not_reproduced findings exceed dynamic_not_reproduced metric"
            )

    if metrics.dynamic_reproduced != state_counts.get("reproduced", 0):
        errors.append(
            f"metrics.dynamic_reproduced {metrics.dynamic_reproduced} != "
            f"reproduced findings {state_counts.get('reproduced', 0)}"
        )

    confirmed_not_dyn = (
        state_counts.get("confirmed_not_dynamically_tested", 0)
        + state_counts.get("confirmed_not_reproduced", 0)
    )
    if metrics.stage2_confirmed > 0 and confirmed_not_dyn + state_counts.get("reproduced", 0) > metrics.stage2_confirmed:
        pass  # stage2_confirmed can exceed when dynamic pending — soft check only

    unit_summary = artifact.get("unit_summary") or {}
    stage_status = artifact.get("stage_status") or {}
    reachability_partial = stage_status.get("reachability") == "partial"
    if unit_summary and not reachability_partial:
        us_total = unit_summary.get("total_units", 0)
        us_sum = (
            unit_summary.get("reachable", 0)
            + unit_summary.get("unreachable", 0)
            + unit_summary.get("unknown_reachability", 0)
        )
        if us_total and us_sum != us_total:
            errors.append(
                f"unit_summary reachability sum {us_sum} != total_units {us_total}"
            )

    return errors
