"""Artifact manifest entries and deterministic JSON helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def dumps_stable(obj: Any) -> str:
    """Deterministic JSON serialization."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def hash_file(path: str | Path) -> str:
    """SHA-256 hex digest of file contents."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class ManifestEntry:
    relative_path: str
    artifact_type: str
    schema_version: str
    sha256: str
    producer_stage: str
    created_at: str = ""
    input_artifact_hashes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_entry(
    *,
    relative_path: str,
    artifact_type: str,
    schema_version: str,
    sha256: str,
    producer_stage: str,
    created_at: str = "",
    input_artifact_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a manifest entry dict."""
    entry = ManifestEntry(
        relative_path=relative_path,
        artifact_type=artifact_type,
        schema_version=schema_version,
        sha256=sha256,
        producer_stage=producer_stage,
        created_at=created_at,
        input_artifact_hashes=input_artifact_hashes or {},
    )
    return entry.to_dict()


def validate_upstream_hashes(
    manifest: list[dict[str, Any]],
    base_dir: str | Path,
) -> list[str]:
    """Verify manifest sha256 values against files on disk."""
    errors: list[str] = []
    base = Path(base_dir)
    for entry in manifest:
        rel = entry.get("relative_path")
        expected = entry.get("sha256")
        if not rel or not expected:
            errors.append(f"manifest entry missing relative_path or sha256: {entry!r}")
            continue
        path = base / rel
        if not path.is_file():
            errors.append(f"manifest artifact not found: {rel}")
            continue
        actual = hash_file(path)
        if actual != expected:
            errors.append(
                f"hash mismatch for {rel}: expected {expected}, got {actual}"
            )
    return errors
