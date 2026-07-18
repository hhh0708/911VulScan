"""Atomic FinalScanArtifact write + external run_artifact_manifest.json."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

from core.final_artifact.evidence_index import validate_evidence_index
from core.final_artifact.manifest import hash_file, make_entry, validate_upstream_hashes
from core.final_artifact.report_views import is_final_scan_artifact
from core.final_artifact.validate import validate_final_scan_artifact
from utilities.file_io import read_json, write_json


FINAL_ARTIFACT_FILENAME = "pipeline_output.json"
RUN_MANIFEST_FILENAME = "run_artifact_manifest.json"


class FinalArtifactIntegrityError(Exception):
    """Raised when FinalScanArtifact or run manifest fails integrity checks."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors) if self.errors else "integrity failed")


def load_and_validate_final_artifact(path: str) -> dict[str, Any]:
    """Load FinalScanArtifact and run full integrity checks before any report.

    Checks:
      * JSON readable
      * looks like FinalScanArtifact
      * full schema validation (``validate_final_scan_artifact``)
      * evidence index validation
      * run manifest SHA-256 verification beside the artifact

    Returns the validated artifact dict.
    Raises ``FinalArtifactIntegrityError`` on any failure.
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FinalArtifactIntegrityError([f"FinalScanArtifact not found: {path}"])

    try:
        artifact = read_json(path)
    except Exception as exc:  # noqa: BLE001
        raise FinalArtifactIntegrityError([f"FinalScanArtifact unreadable: {exc}"]) from exc

    if not isinstance(artifact, dict) or not is_final_scan_artifact(artifact):
        raise FinalArtifactIntegrityError(
            [
                "Input must be a FinalScanArtifact (pipeline_output.json). "
                "Legacy results.json is not accepted for reports."
            ]
        )

    errors = list(validate_final_scan_artifact(artifact))
    errors.extend(validate_evidence_index(artifact.get("evidence_index") or {}))

    artifact_dir = os.path.dirname(path)
    # When the file is not named pipeline_output.json, still verify using its dir
    # but ensure the on-disk file hash matches the manifest entry for this path.
    errors.extend(verify_run_manifest_before_report(artifact_dir))

    # If artifact lives at a non-standard name, also check its content hash
    # against any matching relative_path entry.
    rel = os.path.relpath(path, artifact_dir).replace("\\", "/")
    if rel != FINAL_ARTIFACT_FILENAME:
        manifest_path = os.path.join(artifact_dir, RUN_MANIFEST_FILENAME)
        if os.path.isfile(manifest_path):
            try:
                doc = read_json(manifest_path)
                for entry in doc.get("artifacts") or []:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("relative_path") == rel:
                        want = entry.get("sha256") or ""
                        if want and hash_file(path) != want:
                            errors.append(f"manifest hash mismatch: {rel}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"run_artifact_manifest unreadable: {exc}")

    if errors:
        raise FinalArtifactIntegrityError(errors)
    return artifact


def remove_stale_final_artifacts(output_dir: str) -> None:
    """Delete prior pipeline_output.json and run_artifact_manifest.json in *output_dir*."""
    for name in (FINAL_ARTIFACT_FILENAME, RUN_MANIFEST_FILENAME):
        path = os.path.join(output_dir, name)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def write_final_scan_artifact(
    artifact: dict[str, Any],
    *,
    output_dir: str,
    upstream_entries: list[dict[str, Any]],
    producer_stage: str = "finalize",
) -> tuple[str, str, list[str]]:
    """Validate, atomically write FinalScanArtifact, then write external run manifest.

    Internal ``artifact_manifest`` lists upstream inputs only (never self hash).

    Returns:
        ``(artifact_path, run_manifest_path, errors)``. Non-empty *errors* means
        the caller must set Envelope status to partial/failed and must not emit
        complete reports.
    """
    os.makedirs(output_dir, exist_ok=True)
    artifact_path = os.path.join(output_dir, FINAL_ARTIFACT_FILENAME)
    run_manifest_path = os.path.join(output_dir, RUN_MANIFEST_FILENAME)

    artifact = dict(artifact)
    artifact["artifact_manifest"] = list(upstream_entries or [])

    errors = list(validate_upstream_hashes(artifact["artifact_manifest"], output_dir))
    errors.extend(validate_final_scan_artifact(artifact))
    if errors:
        return artifact_path, run_manifest_path, errors

    tmp = artifact_path + ".tmp"
    write_json(tmp, artifact, ensure_ascii=False)
    os.replace(tmp, artifact_path)

    artifact_sha = hash_file(artifact_path)
    input_hashes = {
        e["relative_path"]: e["sha256"]
        for e in upstream_entries
        if e.get("relative_path") and e.get("sha256")
    }

    final_entry = make_entry(
        relative_path=FINAL_ARTIFACT_FILENAME,
        artifact_type="final_scan_artifact",
        schema_version=str(artifact.get("schema_version") or "1.0"),
        sha256=artifact_sha,
        producer_stage=producer_stage,
        created_at=_now_iso(),
        input_artifact_hashes=input_hashes,
    )

    run_manifest = {
        "schema_version": "1.0",
        "created_at": _now_iso(),
        "final_scan_artifact": {
            "relative_path": FINAL_ARTIFACT_FILENAME,
            "sha256": artifact_sha,
            "schema_version": str(artifact.get("schema_version") or "1.0"),
        },
        "artifacts": list(upstream_entries) + [final_entry],
    }

    tmp_m = run_manifest_path + ".tmp"
    write_json(tmp_m, run_manifest, ensure_ascii=False)
    os.replace(tmp_m, run_manifest_path)

    return artifact_path, run_manifest_path, []


def append_report_to_run_manifest(
    output_dir: str,
    report_path: str,
    *,
    artifact_sha: str = "",
) -> None:
    """After successful report generation, append report hash to external manifest."""
    run_manifest_path = os.path.join(output_dir, RUN_MANIFEST_FILENAME)
    if not os.path.isfile(run_manifest_path) or not os.path.isfile(report_path):
        return
    doc = read_json(run_manifest_path)
    if not artifact_sha:
        artifact_sha = (doc.get("final_scan_artifact") or {}).get("sha256") or ""
    rel = os.path.relpath(report_path, output_dir).replace("\\", "/")
    # Skip if already registered (idempotent).
    existing = {
        e.get("relative_path")
        for e in (doc.get("artifacts") or [])
        if isinstance(e, dict)
    }
    if rel in existing:
        return
    entry = make_entry(
        relative_path=rel,
        artifact_type="report",
        schema_version="1.0",
        sha256=hash_file(report_path),
        producer_stage="report",
        created_at=_now_iso(),
        input_artifact_hashes={FINAL_ARTIFACT_FILENAME: artifact_sha}
        if artifact_sha
        else {},
    )
    arts = list(doc.get("artifacts") or [])
    arts.append(entry)
    doc["artifacts"] = arts
    tmp = run_manifest_path + ".tmp"
    write_json(tmp, doc, ensure_ascii=False)
    os.replace(tmp, run_manifest_path)


_REPORT_SUFFIXES = (".md", ".html", ".csv", ".txt")


def append_report_tree_to_run_manifest(
    output_dir: str,
    report_dir: str,
    *,
    artifact_sha: str = "",
) -> None:
    """Recursively register Markdown/HTML/CSV/disclosure files under report_dir."""
    if not os.path.isdir(report_dir):
        return
    for root, _dirs, files in os.walk(report_dir):
        for name in files:
            lower = name.lower()
            if not any(lower.endswith(sfx) for sfx in _REPORT_SUFFIXES):
                continue
            append_report_to_run_manifest(
                output_dir,
                os.path.join(root, name),
                artifact_sha=artifact_sha,
            )


def verify_run_manifest_before_report(output_dir: str) -> list[str]:
    """Re-verify external run manifest hashes before report generation."""
    path = os.path.join(output_dir, RUN_MANIFEST_FILENAME)
    if not os.path.isfile(path):
        return ["run_artifact_manifest.json missing"]
    try:
        doc = read_json(path)
    except Exception as exc:  # noqa: BLE001
        return [f"run_artifact_manifest unreadable: {exc}"]

    errors: list[str] = []
    for entry in doc.get("artifacts") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("artifact_type") == "report":
            continue
        rel = entry.get("relative_path") or ""
        want = entry.get("sha256") or ""
        if not rel or not want:
            continue
        full = os.path.join(output_dir, rel)
        if not os.path.isfile(full):
            errors.append(f"manifest missing file: {rel}")
            continue
        if hash_file(full) != want:
            errors.append(f"manifest hash mismatch: {rel}")
    return errors
