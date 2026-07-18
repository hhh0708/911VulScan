"""Offline advisory lookup; never overrides source-code verdicts."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from utilities.file_io import run_utf8


MAX_FINGERPRINT_FILES = 2000
MAX_FINGERPRINT_BYTES = 20 * 1024 * 1024


@dataclass(frozen=True)
class PackageIdentity:
    ecosystem: str
    name: str
    version: str = ""
    source: str = ""


@dataclass
class AdvisoryObservation:
    advisory_id: str
    ecosystem: str
    package: str
    affected: bool | None
    version_note: str
    cwe_ids: list[int] = field(default_factory=list)
    source_match: str = "not_checked"
    fingerprint_hits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def detect_package_identities(repo_path: str) -> list[PackageIdentity]:
    """Read common package/build metadata without contacting a registry."""
    root = Path(repo_path)
    identities: list[PackageIdentity] = []
    package_json = _read_json(root / "package.json")
    if package_json:
        identities.append(
            PackageIdentity(
                "npm",
                str(package_json.get("name") or root.name),
                str(package_json.get("version") or ""),
                "package.json",
            )
        )
    pyproject = _read_text(root / "pyproject.toml")
    if pyproject:
        project = _toml_section_values(pyproject, "project")
        poetry = _toml_section_values(pyproject, "tool.poetry")
        values = project or poetry
        if values.get("name"):
            identities.append(
                PackageIdentity(
                    "pypi",
                    values["name"],
                    values.get("version", ""),
                    "pyproject.toml",
                )
            )
    go_mod = _read_text(root / "go.mod")
    if go_mod:
        match = re.search(r"(?m)^\s*module\s+(\S+)", go_mod)
        if match:
            identities.append(PackageIdentity("go", match.group(1), "", "go.mod"))
    cargo = _read_text(root / "Cargo.toml")
    if cargo:
        values = _toml_section_values(cargo, "package")
        if values.get("name"):
            identities.append(
                PackageIdentity(
                    "cargo",
                    values["name"],
                    values.get("version", ""),
                    "Cargo.toml",
                )
            )
    if not identities:
        native = _detect_native_identity(root)
        if native:
            identities.append(native)

    git_version = _git_version(root)
    if git_version:
        identities = [
            PackageIdentity(item.ecosystem, item.name, item.version or git_version, item.source)
            for item in identities
        ]
    return _dedupe_identities(identities)


def load_advisory_cache(paths: Iterable[str] | None = None) -> list[dict]:
    """Load deterministic local advisory snapshots; malformed entries are ignored."""
    candidates = list(paths or [])
    env_cache = os.environ.get("VULSCAN_ADVISORY_CACHE")
    if env_cache:
        candidates.append(env_cache)
    candidates.append(
        str(Path(__file__).resolve().parents[1] / "data" / "advisory_cache.json")
    )
    advisories: list[dict] = []
    for path in candidates:
        data = _read_json(Path(path))
        if isinstance(data, dict):
            data = data.get("advisories") or []
        if isinstance(data, list):
            advisories.extend(item for item in data if isinstance(item, dict))
    by_id = {
        str(item.get("id")): item
        for item in advisories
        if item.get("id") and item.get("package") and item.get("ecosystem")
    }
    return list(by_id.values())


def scan_repo_advisories(
    repo_path: str,
    advisory_paths: Iterable[str] | None = None,
) -> dict:
    """Return version matches and patch fingerprints as a separate evidence lane."""
    identities = detect_package_identities(repo_path)
    advisories = load_advisory_cache(advisory_paths)
    observations: list[AdvisoryObservation] = []
    for identity in identities:
        for advisory in advisories:
            if str(advisory.get("ecosystem", "")).lower() != identity.ecosystem.lower():
                continue
            if _normalize_package(advisory.get("package", "")) != _normalize_package(
                identity.name
            ):
                continue
            affected, reason = _version_affected(identity.version, advisory)
            source_match, fingerprint_hits = _evaluate_fingerprints(
                Path(repo_path), advisory.get("fingerprints") or {}
            )
            observations.append(
                AdvisoryObservation(
                    advisory_id=str(advisory["id"]),
                    ecosystem=identity.ecosystem,
                    package=identity.name,
                    affected=affected,
                    version_note=reason,
                    cwe_ids=_parse_cwe_ids(advisory.get("cwe_ids") or []),
                    source_match=source_match,
                    fingerprint_hits=fingerprint_hits,
                )
            )
    return {
        "schema_version": 1,
        "mode": "offline",
        "note": (
            "Advisory/version/fingerprint observations are independent leads; "
            "they do not override source-code verdicts."
        ),
        "packages": [asdict(item) for item in identities],
        "cache_entries": len(advisories),
        "observations": [item.to_dict() for item in observations],
    }


def advisory_matches_for_finding(intel: dict, cwe_id: int | str | None) -> list[dict]:
    try:
        cwe = int(cwe_id or 0)
    except (TypeError, ValueError):
        cwe = 0
    matches = []
    for item in intel.get("observations") or []:
        cwes = item.get("cwe_ids") or []
        if not cwe or not cwes or cwe in cwes:
            matches.append(item)
    return matches


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_text(path: Path, limit: int = 1024 * 1024) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _toml_section_values(text: str, section: str) -> dict[str, str]:
    match = re.search(
        rf"(?ms)^\[{re.escape(section)}\]\s*(.*?)(?=^\[|\Z)",
        text,
    )
    if not match:
        return {}
    return {
        key: value
        for key, value in re.findall(
            r'(?m)^\s*([A-Za-z0-9_-]+)\s*=\s*["\']([^"\']+)["\']',
            match.group(1),
        )
    }


def _detect_native_identity(root: Path) -> PackageIdentity | None:
    for name in ("CMakeLists.txt", "meson.build"):
        text = _read_text(root / name)
        if not text:
            continue
        match = re.search(
            r"(?is)(?:project\s*\(|project\s*\()\s*['\"]?([A-Za-z0-9_.+-]+)",
            text,
        )
        version = re.search(
            r"(?is)\bversion\s*[: ]\s*['\"]?([0-9]+(?:\.[0-9A-Za-z_-]+)+)",
            text,
        )
        if match:
            return PackageIdentity(
                "generic",
                match.group(1),
                version.group(1) if version else "",
                name,
            )
    return PackageIdentity("generic", root.name, "", "directory")


def _git_version(root: Path) -> str:
    try:
        completed = run_utf8(
            ["git", "-C", str(root), "describe", "--tags", "--exact-match"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip().lstrip("v") if completed.returncode == 0 else ""


def _normalize_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def _dedupe_identities(items: list[PackageIdentity]) -> list[PackageIdentity]:
    deduped: dict[tuple[str, str], PackageIdentity] = {}
    for item in items:
        deduped[(item.ecosystem, _normalize_package(item.name))] = item
    return list(deduped.values())


def _version_tuple(version: str) -> tuple[int, ...] | None:
    numbers = re.findall(r"\d+", version or "")
    return tuple(map(int, numbers[:4])) if numbers else None


def _pad_version(value: tuple[int, ...], width: int) -> tuple[int, ...]:
    """Zero-pad a version tuple so comparisons are always same-length.

    Python compares tuples lexicographically, so ``(2,) >= (2, 0)`` is True;
    padding makes ``2`` and ``2.0`` compare equal as intended.
    """
    return value + (0,) * max(0, width - len(value))


def _version_affected(version: str, advisory: dict) -> tuple[bool | None, str]:
    current = _version_tuple(version)
    if current is None:
        return None, "Package version is unknown"
    ranges = advisory.get("affected_ranges") or []
    if not ranges:
        return None, "Advisory has no normalized affected range"
    for item in ranges:
        if not isinstance(item, dict):
            continue
        introduced = _version_tuple(str(item.get("introduced", "0"))) or (0,)
        fixed = _version_tuple(str(item.get("fixed", "")))
        last = _version_tuple(str(item.get("last_affected", "")))
        width = max(
            [len(current), len(introduced)]
            + ([len(fixed)] if fixed is not None else [])
            + ([len(last)] if last is not None else [])
        )
        current_p = _pad_version(current, width)
        introduced_p = _pad_version(introduced, width)
        fixed_p = _pad_version(fixed, width) if fixed is not None else None
        last_p = _pad_version(last, width) if last is not None else None
        if current_p >= introduced_p and (
            (fixed_p is not None and current_p < fixed_p)
            or (last_p is not None and current_p <= last_p)
            or (fixed_p is None and last_p is None)
        ):
            return True, f"{version} matches affected range {item}"
    return False, f"{version} does not match any affected range"


def _evaluate_fingerprints(root: Path, fingerprints: dict) -> tuple[str, list[str]]:
    vulnerable = [str(item) for item in fingerprints.get("vulnerable_regex") or []]
    patched = [str(item) for item in fingerprints.get("patched_regex") or []]
    if not vulnerable and not patched:
        return "not_checked", []
    evidence: list[str] = []
    vulnerable_hit = False
    patched_hit = False
    bytes_read = 0
    files_read = 0
    for path in root.rglob("*"):
        if files_read >= MAX_FINGERPRINT_FILES or bytes_read >= MAX_FINGERPRINT_BYTES:
            break
        if not path.is_file() or any(part.startswith(".") for part in path.parts):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 1024 * 1024:
            continue
        text = _read_text(path)
        files_read += 1
        bytes_read += len(text.encode("utf-8", errors="ignore"))
        for pattern in vulnerable:
            if re.search(pattern, text, re.MULTILINE):
                vulnerable_hit = True
                evidence.append(f"vulnerable_regex matched {path.relative_to(root)}")
        for pattern in patched:
            if re.search(pattern, text, re.MULTILINE):
                patched_hit = True
                evidence.append(f"patched_regex matched {path.relative_to(root)}")
    if vulnerable_hit and patched_hit:
        return "conflict", evidence[:20]
    if vulnerable_hit:
        return "vulnerable_pattern_present", evidence[:20]
    if patched_hit:
        return "patched_pattern_present", evidence[:20]
    return "unknown", evidence


def _parse_cwe_ids(values: Iterable) -> list[int]:
    parsed = []
    for value in values:
        match = re.search(r"\d+", str(value))
        if match:
            parsed.append(int(match.group(0)))
    return parsed
