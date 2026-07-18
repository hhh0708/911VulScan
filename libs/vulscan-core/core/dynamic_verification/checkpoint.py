"""Content-addressed checkpoints for dynamic verification."""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Optional

from utilities.file_io import read_json, write_json


class DynamicCheckpointManager:
    """Fingerprint-gated checkpoint store keyed by test_id.

    Fingerprint used for lookup is the *base* fingerprint (no image digest).
    On restore, verify image digest, base image digest, policy hash,
    compiler/runner versions, TestPlan hash, and build context hash.
    """

    def __init__(self, directory: str):
        self.directory = directory

    def ensure_dir(self) -> None:
        os.makedirs(self.directory, exist_ok=True)

    def _path(self, test_id: str) -> str:
        safe = hashlib.sha256(test_id.encode("utf-8")).hexdigest()
        return os.path.join(self.directory, f"{safe}.json")

    def save(
        self,
        test_id: str,
        *,
        fingerprint: str,
        result: Dict[str, Any],
        attempt_id: str = "",
        usage: Optional[dict] = None,
        image_digest: str = "",
        base_image_digest: str = "",
        policy_hash: str = "",
        compiler_version: str = "",
        runner_version: str = "",
        test_plan_hash: str = "",
        build_context_hash: str = "",
    ) -> None:
        self.ensure_dir()
        payload = {
            "test_id": test_id,
            "fingerprint": fingerprint,
            "image_digest": image_digest or "",
            "base_image_digest": base_image_digest or "",
            "policy_hash": policy_hash or "",
            "compiler_version": compiler_version or "",
            "runner_version": runner_version or "",
            "test_plan_hash": test_plan_hash or "",
            "build_context_hash": build_context_hash or "",
            "attempt_id": attempt_id,
            "result": result,
            "usage": usage or {},
        }
        path = self._path(test_id)
        tmp = path + ".tmp"
        write_json(tmp, payload)
        os.replace(tmp, path)

    def load_valid(
        self,
        test_id: str,
        fingerprint: str,
        *,
        require_image_digest: bool = False,
        expected_policy_hash: str = "",
        expected_compiler_version: str = "",
        expected_runner_version: str = "",
        expected_test_plan_hash: str = "",
        expected_image_digest: str = "",
        expected_base_image_digest: str = "",
        expected_build_context_hash: str = "",
    ) -> Optional[Dict[str, Any]]:
        path = self._path(test_id)
        if not os.path.isfile(path):
            return None
        try:
            data = read_json(path)
        except Exception:  # noqa: BLE001
            return None
        if data.get("fingerprint") != fingerprint:
            try:
                os.remove(path)
            except OSError:
                pass
            return None
        if require_image_digest and not data.get("image_digest"):
            return None

        checks = (
            ("policy_hash", expected_policy_hash),
            ("compiler_version", expected_compiler_version),
            ("runner_version", expected_runner_version),
            ("test_plan_hash", expected_test_plan_hash),
            ("image_digest", expected_image_digest),
            ("base_image_digest", expected_base_image_digest),
            ("build_context_hash", expected_build_context_hash),
        )
        for field, expected in checks:
            if not expected:
                continue
            if data.get(field) != expected:
                return None

        result = data.get("result") or {}
        if result.get("execution_state") == "failed":
            return None
        return data
