"""Evidence index construction and validation."""

from __future__ import annotations

import hashlib
from typing import Any

from core.final_artifact.manifest import dumps_stable


_META_KEYS = frozenset(
    {
        "evidence_id",
        "content_hash",
        "producer_stage",
        "source_artifact_hash",
        "provenance",
    }
)


def is_valid_sha256(value: object) -> bool:
    s = str(value or "")
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def compute_content_hash(entry: dict[str, Any]) -> str:
    payload = entry.get("content")
    if payload is None:
        payload = {k: v for k, v in entry.items() if k not in ("evidence_id", "content_hash")}
    return hashlib.sha256(dumps_stable(payload).encode("utf-8")).hexdigest()


def _canonical_content_key(entry: dict[str, Any]) -> str:
    """Stable comparison key — never trust an illegal content_hash."""
    declared = entry.get("content_hash")
    if declared is not None and declared != "":
        # Normalize for validity check; only trust lowercase hex SHA-256
        lowered = str(declared).lower()
        if is_valid_sha256(lowered):
            return lowered
        # Illegal declared hash — fall through to actual content (caller also errors)
    content = entry.get("content")
    if content is not None:
        return dumps_stable(content)
    body = {k: v for k, v in entry.items() if k not in _META_KEYS}
    return dumps_stable(body)


def scan_raw_evidence_lists(
    evidence_lists: list[list[dict[str, Any]]],
    *,
    producer_stages: list[str] | None = None,
    source_artifact_hashes: list[str] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Scan raw evidence lists before indexing."""
    errors: list[str] = []
    index: dict[str, dict[str, Any]] = {}

    def _stage_at(seq: list | None, idx: int):
        if not seq or idx >= len(seq):
            return None
        return seq[idx]

    for i, lst in enumerate(evidence_lists or []):
        stage = _stage_at(producer_stages, i)
        src_hash = _stage_at(source_artifact_hashes, i)
        seen_in_list: dict[str, str] = {}
        for item in lst or []:
            if not isinstance(item, dict):
                errors.append(f"evidence entry is not an object (stage={stage!r})")
                continue
            eid = item.get("evidence_id")
            if not eid:
                errors.append(f"evidence missing evidence_id (stage={stage!r})")
                continue

            declared = item.get("content_hash")
            if declared is not None and declared != "":
                lowered = str(declared).lower()
                if not is_valid_sha256(lowered):
                    errors.append(
                        f"illegal content_hash for evidence_id {eid!r} "
                        f"(must be lowercase sha-256 hex) stage={stage!r}"
                    )
                elif item.get("content") is not None:
                    actual = compute_content_hash(item)
                    if lowered != actual:
                        errors.append(
                            f"content_hash mismatch for evidence_id {eid!r} "
                            f"(stage={stage!r})"
                        )

            key = _canonical_content_key(item)
            if eid in seen_in_list and seen_in_list[eid] != key:
                errors.append(
                    f"duplicate evidence_id {eid!r} with inconsistent content "
                    f"within stage={stage!r}"
                )
                continue
            seen_in_list[eid] = key

            enriched = dict(item)
            if stage:
                enriched.setdefault("producer_stage", stage)
            # Never persist empty string as provenance source.
            if enriched.get("source_artifact_hash") == "":
                del enriched["source_artifact_hash"]
            if src_hash:
                enriched.setdefault("source_artifact_hash", src_hash)

            if eid in index:
                if _canonical_content_key(index[eid]) != key:
                    errors.append(
                        f"evidence_id {eid!r} has inconsistent content across stages"
                    )
                continue
            index[eid] = enriched

    ordered = {k: index[k] for k in sorted(index.keys())}
    return ordered, errors


def build_evidence_index(evidence: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build evidence_id -> evidence object index from a flat evidence list."""
    index: dict[str, dict[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, dict):
            continue
        eid = item.get("evidence_id")
        if not eid:
            continue
        index[eid] = item
    return {k: index[k] for k in sorted(index.keys())}


def validate_evidence_index(index: dict[str, dict[str, Any]]) -> list[str]:
    """Return errors if IDs have inconsistent or illegal content hashes."""
    errors: list[str] = []
    seen_keys: dict[str, str] = {}
    for eid, entry in index.items():
        declared = entry.get("content_hash")
        if declared is not None and declared != "":
            lowered = str(declared).lower()
            if not is_valid_sha256(lowered):
                errors.append(
                    f"illegal content_hash for evidence_id {eid!r} "
                    f"(must be lowercase sha-256 hex)"
                )
            elif entry.get("content") is not None:
                actual = compute_content_hash(entry)
                if lowered != actual:
                    errors.append(f"content_hash mismatch for evidence_id {eid!r}")
        key = _canonical_content_key(entry)
        prior = seen_keys.get(eid)
        if prior is not None and prior != key:
            errors.append(
                f"evidence_id {eid!r} has inconsistent content (hash/key mismatch)"
            )
        else:
            seen_keys[eid] = key
    return errors


def merge_evidence_indexes(
    *indexes: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Merge multiple indexes; return merged index and consistency errors."""
    merged: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for index in indexes:
        for eid, entry in index.items():
            if eid in merged:
                if _canonical_content_key(merged[eid]) != _canonical_content_key(entry):
                    errors.append(
                        f"evidence_id {eid!r} has inconsistent content across sources"
                    )
            else:
                merged[eid] = entry
    ordered = {k: merged[k] for k in sorted(merged.keys())}
    return ordered, errors


def resolve_evidence_ids(
    ids: list[str],
    index: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Resolve evidence IDs to objects; return (resolved, missing_ids)."""
    resolved: list[dict[str, Any]] = []
    missing: list[str] = []
    for eid in ids:
        entry = index.get(eid)
        if entry is None:
            missing.append(eid)
        else:
            resolved.append(entry)
    return resolved, missing


def collect_evidence_ids_from_finding(finding: dict[str, Any]) -> list[str]:
    """Gather all evidence_ids referenced by a finding record."""
    ids: list[str] = []
    ids.extend(finding.get("evidence_ids") or [])
    for stage_key in ("stage1_detection", "stage2_verification", "dynamic_verification"):
        stage = finding.get(stage_key) or {}
        ids.extend(stage.get("evidence_ids") or [])
        ids.extend(stage.get("counter_evidence_ids") or [])
        for ev in stage.get("evidence") or []:
            if isinstance(ev, dict) and ev.get("evidence_id"):
                ids.append(ev["evidence_id"])
    prov = finding.get("merge_provenance") or {}
    ids.extend(prov.get("merged_from_evidence_ids") or [])
    seen: set[str] = set()
    ordered: list[str] = []
    for eid in ids:
        if eid not in seen:
            seen.add(eid)
            ordered.append(eid)
    return ordered
