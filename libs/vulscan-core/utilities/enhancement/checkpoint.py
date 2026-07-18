"""Content-addressed checkpoint manager for Context Enhancement.

Filenames are ``sha256(full_unit_id).json``. Writes use temp file + atomic
replace. Corrupt / schema-invalid / fingerprint-mismatched files are ignored
and the unit is reprocessed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple

from utilities.enhancement.schema import (
    ENHANCEMENT_SCHEMA_VERSION,
    normalize_enhancement,
    validate_enhancement,
)
from utilities.file_io import read_json

SUMMARY_FILE = "_summary.json"


def unit_id_filename(unit_id: str) -> str:
    """Return checkpoint basename for a unit id (full SHA-256 hex + .json)."""
    digest = hashlib.sha256(unit_id.encode("utf-8")).hexdigest()
    return f"{digest}.json"


class EnhanceCheckpointManager:
    """Manages per-unit enhance checkpoints with fingerprint invalidation."""

    def __init__(self, checkpoint_dir: str):
        self.dir = checkpoint_dir

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def path_for(self, unit_id: str) -> str:
        return os.path.join(self.dir, unit_id_filename(unit_id))

    def save(
        self,
        unit_id: str,
        *,
        fingerprint: str,
        enhancement: Dict[str, Any],
        usage: Optional[Dict[str, Any]] = None,
        schema_version: str = ENHANCEMENT_SCHEMA_VERSION,
    ) -> None:
        """Atomically write a checkpoint (payload + fingerprint only)."""
        self.ensure_dir()
        payload = {
            "unit_id": unit_id,
            "fingerprint": fingerprint,
            "schema_version": schema_version,
            "enhancement": normalize_enhancement(enhancement),
            "usage": usage or {},
            "saved_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        # Forbidden content must never be persisted.
        for banned in ("code", "unit", "verdict", "finding", "agent_context", "llm_context"):
            payload.pop(banned, None)

        dest = self.path_for(unit_id)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".enhance_cp_", suffix=".tmp", dir=self.dir
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, dest)
        except Exception:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            raise

    def load_valid(
        self,
        unit_id: str,
        expected_fingerprint: str,
    ) -> Optional[Dict[str, Any]]:
        """Load checkpoint if fingerprint matches and payload is valid.

        Corrupt / mismatched files are deleted (invalidated) and return None.
        """
        path = self.path_for(unit_id)
        if not os.path.isfile(path):
            return None
        try:
            data = read_json(path)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(
                f"[EnhanceCheckpoint] Invalidating corrupt checkpoint for {unit_id}: {exc}",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        if not isinstance(data, dict):
            self._invalidate(path)
            return None

        # Reject checkpoints that illegally store code / unit / verdict.
        if any(k in data for k in ("code", "unit", "verdict", "finding")):
            print(
                f"[EnhanceCheckpoint] Invalidating checkpoint with forbidden fields: {unit_id}",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        if data.get("unit_id") != unit_id:
            # Collision isolation: wrong unit_id in file named by hash → invalidate
            print(
                f"[EnhanceCheckpoint] unit_id mismatch in {path}; invalidating",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        if data.get("fingerprint") != expected_fingerprint:
            print(
                f"[EnhanceCheckpoint] Fingerprint mismatch for {unit_id}; deleting stale checkpoint",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        enhancement = data.get("enhancement")
        if not validate_enhancement(enhancement):
            # Try normalize once
            enhancement = normalize_enhancement(enhancement or {})
            if not validate_enhancement(enhancement):
                self._invalidate(path)
                return None

        if enhancement.get("provenance", {}).get("error"):
            return None  # errored runs are not completed

        return {
            "unit_id": unit_id,
            "fingerprint": data.get("fingerprint"),
            "schema_version": data.get("schema_version") or ENHANCEMENT_SCHEMA_VERSION,
            "enhancement": enhancement,
            "usage": data.get("usage") or {},
        }

    def _invalidate(self, path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass

    def restore_matching(
        self,
        units: list,
        fingerprint_for,
    ) -> Tuple[Set[str], Dict[str, Dict[str, Any]]]:
        """Restore enhancements onto units when fingerprints match.

        ``fingerprint_for(unit) -> str`` computes the expected fingerprint.

        Returns (restored_ids, usage_by_id).
        """
        restored: Set[str] = set()
        usage_by_id: Dict[str, Dict[str, Any]] = {}
        for unit in units:
            uid = unit.get("id")
            if not uid:
                continue
            fp = fingerprint_for(unit)
            cp = self.load_valid(uid, fp)
            if not cp:
                continue
            unit["enhancement"] = cp["enhancement"]
            restored.add(uid)
            if cp.get("usage"):
                usage_by_id[uid] = cp["usage"]
        return restored, usage_by_id

    def write_summary(
        self,
        total_units: int,
        completed: int,
        errors: int,
        error_breakdown: dict,
        phase: str = "in_progress",
        usage: dict | None = None,
    ) -> None:
        self.ensure_dir()
        data = {
            "step": "enhance",
            "phase": phase,
            "timestamp": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "total_units": total_units,
            "completed": completed,
            "errors": errors,
            "error_breakdown": error_breakdown,
            "schema_version": ENHANCEMENT_SCHEMA_VERSION,
        }
        if usage is not None:
            data["usage"] = usage
        dest = os.path.join(self.dir, SUMMARY_FILE)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".enhance_sum_", suffix=".tmp", dir=self.dir
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, dest)
        except Exception:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            raise
