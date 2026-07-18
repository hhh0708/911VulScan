"""Content-addressed Stage 2 verify checkpoints (keyed by finding_id)."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.verification.schema import (
    VERIFICATION_SCHEMA_VERSION,
    normalize_verification_result,
    validate_verification_result,
)
from utilities.file_io import read_json

SUMMARY_FILE = "_summary.json"


def finding_id_filename(finding_id: str) -> str:
    digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()
    return f"{digest}.json"


class VerifyCheckpointManager:
    def __init__(self, checkpoint_dir: str):
        self.dir = checkpoint_dir

    def ensure_dir(self) -> None:
        os.makedirs(self.dir, exist_ok=True)

    def path_for(self, finding_id: str) -> str:
        return os.path.join(self.dir, finding_id_filename(finding_id))

    def save(
        self,
        finding_id: str,
        *,
        fingerprint: str,
        result: Dict[str, Any],
        usage: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.ensure_dir()
        payload = {
            "finding_id": finding_id,
            "fingerprint": fingerprint,
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "result": result,
            "usage": usage or {},
            "saved_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        for banned in (
            "code",
            "code_by_route",
            "unit",
            "finding",
            "verdict",
            "agree",
            "correct_finding",
        ):
            payload.pop(banned, None)

        dest = self.path_for(finding_id)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".verify_cp_", suffix=".tmp", dir=self.dir
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
        finding_id: str,
        expected_fingerprint: str,
        evidence_ids: set[str],
    ) -> Optional[Dict[str, Any]]:
        path = self.path_for(finding_id)
        if not os.path.isfile(path):
            return None
        try:
            data = read_json(path)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(
                f"[VerifyCheckpoint] Invalidating corrupt checkpoint: {exc}",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        if not isinstance(data, dict):
            self._invalidate(path)
            return None

        if any(k in data for k in ("code", "code_by_route", "unit")):
            self._invalidate(path)
            return None

        if data.get("finding_id") != finding_id:
            self._invalidate(path)
            return None

        if data.get("fingerprint") != expected_fingerprint:
            print(
                f"[VerifyCheckpoint] Fingerprint mismatch for {finding_id[:16]}…; deleting",
                file=sys.stderr,
            )
            self._invalidate(path)
            return None

        result = data.get("result")
        if not validate_verification_result(result):
            result = normalize_verification_result(
                result or {},
                finding_id=finding_id,
                evidence_ids=evidence_ids,
                execution_state=(result or {}).get("execution_state", "failed"),
            )
            if not validate_verification_result(result):
                self._invalidate(path)
                return None

        # Failed runs are not treated as completed restores
        if result.get("execution_state") == "failed":
            return None

        return {
            "finding_id": finding_id,
            "fingerprint": data.get("fingerprint"),
            "result": result,
            "usage": data.get("usage") or {},
        }

    def _invalidate(self, path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass

    def write_summary(
        self,
        total: int,
        completed: int,
        errors: int,
        error_breakdown: dict,
        phase: str = "in_progress",
        usage: dict | None = None,
        metrics: dict | None = None,
    ) -> None:
        self.ensure_dir()
        data = {
            "step": "Verify",
            "phase": phase,
            "timestamp": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "total_units": total,
            "completed": completed,
            "errors": errors,
            "error_breakdown": error_breakdown,
            "schema_version": VERIFICATION_SCHEMA_VERSION,
        }
        if usage is not None:
            data["usage"] = usage
        if metrics is not None:
            data["metrics"] = metrics
        dest = os.path.join(self.dir, SUMMARY_FILE)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".verify_sum_", suffix=".tmp", dir=self.dir
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
