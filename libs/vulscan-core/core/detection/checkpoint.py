"""Content-addressed Stage 1 analyze checkpoints.

Filenames are ``sha256(unit_id).json``. Payload stores only result, fingerprint,
and usage — never code copies.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple

from core.detection.schema import (
    DETECTION_SCHEMA_VERSION,
    normalize_detection_result,
    validate_detection_result,
)
from utilities.file_io import read_json

SUMMARY_FILE = "_summary.json"


def unit_id_filename(unit_id: str) -> str:
    return f"{hashlib.sha256(unit_id.encode('utf-8')).hexdigest()}.json"


class AnalyzeCheckpointManager:
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
        result: Dict[str, Any],
        usage: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.ensure_dir()
        payload = {
            "unit_id": unit_id,
            "fingerprint": fingerprint,
            "schema_version": DETECTION_SCHEMA_VERSION,
            "result": result,
            "usage": usage or {},
            "saved_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        for banned in ("code", "code_for_route", "unit", "primary_code"):
            payload.pop(banned, None)
            if isinstance(payload.get("result"), dict):
                payload["result"].pop(banned, None)

        dest = self.path_for(unit_id)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".analyze_cp_", suffix=".tmp", dir=self.dir
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
        evidence_ids: set[str],
    ) -> Optional[Dict[str, Any]]:
        path = self.path_for(unit_id)
        if not os.path.isfile(path):
            return None
        try:
            data = read_json(path)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(
                f"[AnalyzeCheckpoint] Invalidating corrupt checkpoint for {unit_id}: {exc}",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        if not isinstance(data, dict):
            self._invalidate(path)
            return None

        if any(k in data for k in ("code", "code_for_route", "unit", "primary_code")):
            print(
                f"[AnalyzeCheckpoint] Forbidden code fields in checkpoint; invalidating {unit_id}",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        if data.get("unit_id") != unit_id:
            self._invalidate(path)
            return None

        if data.get("fingerprint") != expected_fingerprint:
            print(
                f"[AnalyzeCheckpoint] Fingerprint mismatch for {unit_id}; deleting",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        result = data.get("result")
        if not validate_detection_result(result):
            result = normalize_detection_result(
                result or {}, unit_id=unit_id, evidence_ids=evidence_ids
            )
            if not validate_detection_result(result):
                self._invalidate(path)
                return None

        if result.get("decision") == "error":
            return None

        return {
            "unit_id": unit_id,
            "fingerprint": data.get("fingerprint"),
            "result": result,
            "usage": data.get("usage") or {},
        }

    def _invalidate(self, path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass

    def restore_matching(
        self,
        units_and_fps: list,
    ) -> Tuple[Dict[int, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        """units_and_fps: list of (index, unit_id, fingerprint, evidence_ids).

        Returns (results_by_index, usage_by_id).
        """
        restored: Dict[int, Dict[str, Any]] = {}
        usage_by_id: Dict[str, Dict[str, Any]] = {}
        for index, unit_id, fp, evid_ids in units_and_fps:
            cp = self.load_valid(unit_id, fp, evid_ids)
            if not cp:
                continue
            restored[index] = cp["result"]
            if cp.get("usage"):
                usage_by_id[unit_id] = cp["usage"]
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
            "step": "Analyze",
            "phase": phase,
            "timestamp": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "total_units": total_units,
            "completed": completed,
            "errors": errors,
            "error_breakdown": error_breakdown,
            "schema_version": DETECTION_SCHEMA_VERSION,
        }
        if usage is not None:
            data["usage"] = usage
        dest = os.path.join(self.dir, SUMMARY_FILE)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".analyze_sum_", suffix=".tmp", dir=self.dir
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
