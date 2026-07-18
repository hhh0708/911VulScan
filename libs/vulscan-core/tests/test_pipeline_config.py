"""Tests for PipelineConfig, ScanRequest, and scan_manifest.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.pipeline_config import (
    FIXED_PIPELINE,
    PipelineConfig,
    PipelineConfigError,
    SCAN_MANIFEST_NAME,
    ScanRequest,
    ensure_run_dir,
    generate_run_id,
    normalize_language,
    normalize_scope,
    write_scan_manifest,
)


def _cfg(**kwargs) -> PipelineConfig:
    kwargs.setdefault("output_dir", "/tmp/out")
    return PipelineConfig(**kwargs)


def _request(tmp_path=None, **kwargs) -> ScanRequest:
    root = str(tmp_path) if tmp_path is not None else "/tmp/out"
    run_id = kwargs.pop("run_id", None) or generate_run_id()
    config = kwargs.pop("config", None) or _cfg(output_dir=root)
    return ScanRequest(
        repo_path=kwargs.pop("repo_path", "/tmp/repo"),
        config=config,
        run_id=run_id,
        **kwargs,
    )


def test_defaults():
    cfg = _cfg()
    assert cfg.language == "auto"
    assert cfg.scope == "reachable"
    assert cfg.app_context is True
    assert cfg.enhance is True
    assert cfg.verify is True
    assert cfg.dynamic_verify is False
    assert cfg.workers == 8


def test_output_dir_required():
    with pytest.raises(PipelineConfigError, match="output_dir"):
        PipelineConfig(output_dir="")


def test_immutable():
    cfg = _cfg()
    with pytest.raises(Exception):
        cfg.scope = "all"  # type: ignore[misc]


def test_language_aliases():
    assert normalize_language("typescript") == "javascript"
    assert normalize_language("TS") == "javascript"
    assert normalize_language("cpp") == "c"
    assert normalize_language("c++") == "c"
    assert normalize_language("python") == "python"


@pytest.mark.parametrize("lang", ["ruby", "php", "zig"])
def test_removed_languages_rejected(lang):
    with pytest.raises(PipelineConfigError, match="no longer supported"):
        normalize_language(lang)


@pytest.mark.parametrize("level", ["codeql", "exploitable"])
def test_removed_levels_rejected(level):
    with pytest.raises(PipelineConfigError):
        normalize_scope(level)


def test_scope_valid():
    assert normalize_scope("all") == "all"
    assert normalize_scope("REACHABLE") == "reachable"


def test_scan_request_requires_run_id(tmp_path):
    with pytest.raises(PipelineConfigError, match="run_id"):
        ScanRequest(
            repo_path=str(tmp_path),
            config=_cfg(output_dir=str(tmp_path)),
            run_id="",
        )


def test_scan_request_run_dir(tmp_path):
    req = _request(tmp_path, run_id="run_abc")
    assert req.run_dir == str(tmp_path / "runs" / "run_abc")
    assert req.output_root == str(tmp_path.resolve())


def test_scan_manifest_records_full_request(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    req = _request(
        tmp_path,
        repo_path=str(repo),
        run_id="run_manifest",
        model="sonnet",
        enhance_mode="single-shot",
        generate_report=False,
        limit=3,
    )
    path = write_scan_manifest(req)
    assert path.endswith(SCAN_MANIFEST_NAME)
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["run_id"] == "run_manifest"
    assert data["request"] == req.to_dict()
    assert data["config_hash"] == req.config_hash()
    assert data["pipeline"] == list(FIXED_PIPELINE)
    assert data["output_root"] == req.output_root
    assert Path(data["run_dir"]).name == "run_manifest"

    with pytest.raises(RuntimeError, match="immutable"):
        write_scan_manifest(req)


def test_repeated_runs_do_not_collide(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    r1 = _request(tmp_path, repo_path=str(repo), run_id="run_one")
    r2 = _request(tmp_path, repo_path=str(repo), run_id="run_two")
    p1 = write_scan_manifest(r1)
    p2 = write_scan_manifest(r2)
    assert Path(p1).parent != Path(p2).parent
    assert Path(p1).exists() and Path(p2).exists()


def test_ensure_run_dir(tmp_path):
    d = ensure_run_dir(str(tmp_path), "rid1")
    assert Path(d).is_dir()
    assert Path(d).name == "rid1"


@pytest.mark.parametrize(
    "bad_id",
    [
        "../escape",
        "..\\escape",
        "foo/bar",
        "foo\\bar",
        "../../etc",
        ".",
        "..",
        "has space",
        "bad;id",
        "",
    ],
)
def test_run_id_rejects_unsafe_values(tmp_path, bad_id):
    with pytest.raises(PipelineConfigError):
        ensure_run_dir(str(tmp_path), bad_id)


def test_config_hash_excludes_run_id(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    a = _request(tmp_path, repo_path=str(repo), run_id="run_aaa")
    b = _request(tmp_path, repo_path=str(repo), run_id="run_bbb")
    assert a.run_id != b.run_id
    assert a.config_hash() == b.config_hash()
    assert "run_id" not in a.config_dict_for_hash()


def test_with_updates_returns_new_instance():
    cfg = _cfg()
    cfg2 = cfg.with_updates(scope="all", workers=2)
    assert cfg.scope == "reachable"
    assert cfg2.scope == "all"
    assert cfg2.workers == 2
    assert cfg is not cfg2
