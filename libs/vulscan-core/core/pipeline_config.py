"""
Unified immutable pipeline configuration and scan request.

``PipelineConfig`` holds pipeline knobs. ``ScanRequest`` is the complete,
immutable input to ``scan_repository`` — CLI layers must fully construct it
before orchestration. Stages read the request; they never mutate it or fill
defaults.

Each run gets a unique ``run_id``. Artifacts land under::

    {output_root}/runs/{run_id}/

where ``output_root`` is ``PipelineConfig.output_dir``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime, timezone
from typing import Any, Literal

from utilities.file_io import write_json

# run_id may only contain safe path segment characters (no traversal).
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

Scope = Literal["all", "reachable"]

SUPPORTED_LANGUAGES = frozenset({"python", "javascript", "go", "c"})
LANGUAGE_ALIASES = {
    "typescript": "javascript",
    "ts": "javascript",
    "js": "javascript",
    "nodejs": "javascript",
    "node": "javascript",
    "cpp": "c",
    "c++": "c",
    "cxx": "c",
    "cc": "c",
}
REMOVED_LANGUAGES = frozenset({"ruby", "php", "zig"})
VALID_SCOPES = frozenset({"all", "reachable"})
REMOVED_LEVELS = frozenset({"codeql", "exploitable"})

SCAN_MANIFEST_NAME = "scan_manifest.json"
FIXED_PIPELINE = (
    "parse",
    "app_context",
    "reachability",
    "enhance",
    "detect",
    "verify",
    "dynamic_verify",
)
VALID_MODELS = frozenset({"opus", "sonnet"})
VALID_ENHANCE_MODES = frozenset({"agentic", "single-shot"})


class PipelineConfigError(ValueError):
    """Invalid pipeline configuration or removed CLI surface."""


def normalize_language(language: str) -> str:
    """Normalize a language string to a canonical supported language."""
    if not language or not str(language).strip():
        raise PipelineConfigError("language must be a non-empty string")

    raw = str(language).strip().lower()
    if raw == "auto":
        return "auto"

    if raw in REMOVED_LANGUAGES:
        raise PipelineConfigError(
            f"Language {raw!r} is no longer supported. "
            f"Supported languages: {', '.join(sorted(SUPPORTED_LANGUAGES))} "
            "(typescript is accepted as an alias for javascript)."
        )

    canonical = LANGUAGE_ALIASES.get(raw, raw)
    if canonical not in SUPPORTED_LANGUAGES:
        raise PipelineConfigError(
            f"Unsupported language: {language!r}. "
            f"Supported: auto, {', '.join(sorted(SUPPORTED_LANGUAGES))} "
            "(typescript → javascript)."
        )
    return canonical


def normalize_scope(scope: str) -> Scope:
    """Normalize scope to ``all`` or ``reachable``."""
    if not scope or not str(scope).strip():
        raise PipelineConfigError("scope must be 'all' or 'reachable'")

    raw = str(scope).strip().lower()
    if raw in REMOVED_LEVELS or raw == "level":
        raise PipelineConfigError(
            f"Processing level {raw!r} is no longer supported. "
            "Use --scope all|reachable instead of --level / codeql / exploitable."
        )
    if raw not in VALID_SCOPES:
        raise PipelineConfigError(
            f"Invalid scope: {scope!r}. Expected 'all' or 'reachable'."
        )
    return raw  # type: ignore[return-value]


@dataclass(frozen=True)
class PipelineConfig:
    """Immutable scan pipeline configuration knobs."""

    language: str = "auto"
    scope: Scope = "reachable"
    app_context: bool = True
    enhance: bool = True
    verify: bool = True
    dynamic_verify: bool = False
    workers: int = 8
    output_dir: str = ""  # output_root — runs live under output_dir/runs/<run_id>/

    def __post_init__(self) -> None:
        object.__setattr__(self, "language", normalize_language(self.language))
        object.__setattr__(self, "scope", normalize_scope(self.scope))
        if self.workers < 1:
            raise PipelineConfigError(f"workers must be >= 1, got {self.workers}")
        if not str(self.output_dir).strip():
            raise PipelineConfigError("output_dir (output_root) is required")

    def with_updates(self, **kwargs: Any) -> PipelineConfig:
        """Return a new config with selected fields replaced (still immutable)."""
        return replace(self, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> PipelineConfig:
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass(frozen=True)
class ScanRequest:
    """Complete immutable input to ``scan_repository``.

    The CLI must populate every field (including defaults) before calling the
    scanner. Downstream stages must not fill defaults or mutate this object.
    """

    repo_path: str
    config: PipelineConfig
    model: str = "opus"
    enhance_mode: str = "agentic"
    skip_tests: bool = True
    limit: int | None = None
    generate_report: bool = True
    repo_name: str | None = None
    repo_url: str | None = None
    commit_sha: str | None = None
    diff_manifest: str | None = None
    run_id: str = ""

    def __post_init__(self) -> None:
        if not self.repo_path or not str(self.repo_path).strip():
            raise PipelineConfigError("repo_path is required")
        object.__setattr__(self, "repo_path", os.path.abspath(self.repo_path))

        if not isinstance(self.config, PipelineConfig):
            raise PipelineConfigError("config must be a PipelineConfig instance")

        model = str(self.model).strip().lower()
        if model not in VALID_MODELS:
            raise PipelineConfigError(
                f"Invalid model: {self.model!r}. Expected one of {sorted(VALID_MODELS)}."
            )
        object.__setattr__(self, "model", model)

        enhance_mode = str(self.enhance_mode).strip().lower()
        if enhance_mode not in VALID_ENHANCE_MODES:
            raise PipelineConfigError(
                f"Invalid enhance_mode: {self.enhance_mode!r}. "
                f"Expected one of {sorted(VALID_ENHANCE_MODES)}."
            )
        object.__setattr__(self, "enhance_mode", enhance_mode)

        if self.limit is not None and self.limit < 1:
            raise PipelineConfigError(f"limit must be >= 1 or None, got {self.limit}")

        object.__setattr__(self, "run_id", validate_run_id(self.run_id))

        if self.diff_manifest:
            object.__setattr__(
                self, "diff_manifest", os.path.abspath(self.diff_manifest)
            )

        # Normalize output_root on the embedded config.
        root = os.path.abspath(self.config.output_dir)
        if self.config.output_dir != root:
            object.__setattr__(self, "config", self.config.with_updates(output_dir=root))

    @property
    def output_root(self) -> str:
        return self.config.output_dir

    @property
    def run_dir(self) -> str:
        return os.path.join(self.output_root, "runs", self.run_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "config": self.config.to_dict(),
            "model": self.model,
            "enhance_mode": self.enhance_mode,
            "skip_tests": self.skip_tests,
            "limit": self.limit,
            "generate_report": self.generate_report,
            "repo_name": self.repo_name,
            "repo_url": self.repo_url,
            "commit_sha": self.commit_sha,
            "diff_manifest": self.diff_manifest,
            "run_id": self.run_id,
        }

    def config_dict_for_hash(self) -> dict[str, Any]:
        """Request fields that define configuration (excludes random run_id)."""
        data = self.to_dict()
        data.pop("run_id", None)
        return data

    def config_hash(self) -> str:
        """Stable hash of configuration — identical configs share the same hash.

        ``run_id`` is excluded so repeated scans with the same settings produce
        the same ``config_hash``.
        """
        payload = json.dumps(
            self.config_dict_for_hash(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validate_run_id(run_id: str) -> str:
    """Validate ``run_id`` is a single safe path segment (no traversal)."""
    if not run_id or not str(run_id).strip():
        raise PipelineConfigError(
            "run_id is required; the CLI must allocate run identity "
            "before calling scan_repository"
        )
    value = str(run_id).strip()
    if value in {".", ".."} or "/" in value or "\\" in value:
        raise PipelineConfigError(
            f"Invalid run_id {value!r}: path separators and '..' are not allowed"
        )
    if not _RUN_ID_RE.fullmatch(value):
        raise PipelineConfigError(
            f"Invalid run_id {value!r}: only alphanumeric, '.', '_', '-' "
            "are allowed (max 128 chars, must start with alphanumeric)"
        )
    return value


def generate_run_id() -> str:
    """Allocate a unique run identity (time-sortable + entropy)."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{ts}_{uuid.uuid4().hex[:10]}"


def ensure_run_dir(output_root: str, run_id: str) -> str:
    """Create ``{output_root}/runs/{run_id}/`` and return its absolute path."""
    safe_id = validate_run_id(run_id)
    root = os.path.abspath(output_root)
    runs_root = os.path.abspath(os.path.join(root, "runs"))
    run_dir = os.path.abspath(os.path.join(runs_root, safe_id))
    # Defend against any future validation gaps / symlink tricks.
    if os.path.commonpath([runs_root, run_dir]) != runs_root:
        raise PipelineConfigError(
            f"run_id {safe_id!r} escapes the runs directory"
        )
    os.makedirs(run_dir, exist_ok=True)
    return run_dir


def write_scan_manifest(request: ScanRequest) -> str:
    """Write immutable ``scan_manifest.json`` into the run directory.

    Records the full ScanRequest, run_id, config hash, and fixed pipeline order.
    """
    run_dir = ensure_run_dir(request.output_root, request.run_id)
    path = os.path.join(run_dir, SCAN_MANIFEST_NAME)
    if os.path.exists(path):
        raise RuntimeError(
            f"{SCAN_MANIFEST_NAME} already exists at {path}; "
            "refusing to overwrite (manifest is immutable)."
        )

    payload: dict[str, Any] = {
        "version": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_id": request.run_id,
        "run_dir": run_dir,
        "output_root": request.output_root,
        "config_hash": request.config_hash(),
        "request": request.to_dict(),
        "pipeline": list(FIXED_PIPELINE),
    }

    write_json(path, payload, indent=2)

    try:
        os.chmod(path, 0o444)
    except OSError:
        pass

    return path
