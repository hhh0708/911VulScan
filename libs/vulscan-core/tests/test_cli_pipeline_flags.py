"""CLI flag surface for unified ScanRequest entry points."""

from __future__ import annotations

import argparse
import inspect
import sys

import pytest


def test_scan_help_shows_scope_and_run_id(capsys):
    from vulscan.cli import main

    with pytest.raises(SystemExit):
        old = sys.argv
        try:
            sys.argv = ["vulscan", "scan", "--help"]
            main()
        finally:
            sys.argv = old
    out = capsys.readouterr().out
    assert "--scope" in out
    assert "--dynamic-verify" in out
    assert "--no-verify" in out
    assert "--run-id" in out
    assert "--level" not in out
    assert "--real-world" not in out
    assert "--backoff" not in out


def test_removed_level_flag_errors(capsys):
    from vulscan.cli import main

    old = sys.argv
    try:
        sys.argv = ["vulscan", "scan", "/tmp/repo", "--level", "reachable"]
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2
    finally:
        sys.argv = old
    err = capsys.readouterr().err
    assert "--level has been removed" in err


def test_removed_real_world_flag_errors(capsys):
    from vulscan.cli import main

    old = sys.argv
    try:
        sys.argv = ["vulscan", "scan", "/tmp/repo", "--real-world"]
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2
    finally:
        sys.argv = old
    err = capsys.readouterr().err
    assert "--real-world has been removed" in err


def test_removed_language_rejected_by_argparse():
    from vulscan.cli import main

    old = sys.argv
    try:
        sys.argv = ["vulscan", "scan", "/tmp/repo", "--language", "ruby"]
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2
    finally:
        sys.argv = old


def test_cmd_scan_passes_single_scan_request(monkeypatch, tmp_path):
    captured = {}
    from vulscan import cli as cli_mod

    def fake_scan(request):
        captured["request"] = request
        from core.schemas import ScanResult
        return ScanResult(
            output_dir=str(tmp_path / "runs" / request.run_id),
            run_id=request.run_id,
            output_root=str(tmp_path),
        )

    monkeypatch.setattr("core.scanner.scan_repository", fake_scan, raising=True)

    ns = argparse.Namespace(
        repo=str(tmp_path),
        output=str(tmp_path / "out"),
        language="typescript",
        scope="reachable",
        no_verify=False,
        no_context=False,
        no_enhance=False,
        enhance_mode="agentic",
        no_report=True,
        dynamic_verify=False,
        no_skip_tests=False,
        limit=None,
        model="opus",
        workers=4,
        repo_name=None,
        repo_url=None,
        commit_sha=None,
        diff_manifest=None,
        run_id="cli_run_1",
    )
    rc = cli_mod.cmd_scan(ns)
    assert rc in (0, 1)
    assert list(captured) == ["request"]
    req = captured["request"]
    assert req.config.language == "javascript"
    assert req.config.scope == "reachable"
    assert req.config.verify is True
    assert req.config.dynamic_verify is False
    assert req.config.workers == 4
    assert req.run_id == "cli_run_1"
    assert req.generate_report is False
    assert req.model == "opus"


def test_cmd_scan_no_verify_and_dynamic_verify(monkeypatch, tmp_path):
    captured = {}
    from vulscan import cli as cli_mod

    def fake_scan(request):
        captured["request"] = request
        from core.schemas import ScanResult
        return ScanResult(output_dir=str(tmp_path), run_id=request.run_id)

    monkeypatch.setattr("core.scanner.scan_repository", fake_scan, raising=True)

    ns = argparse.Namespace(
        repo=str(tmp_path),
        output=str(tmp_path / "out"),
        language="python",
        scope="all",
        no_verify=True,
        no_context=True,
        no_enhance=True,
        enhance_mode="single-shot",
        no_report=True,
        dynamic_verify=True,
        no_skip_tests=False,
        limit=1,
        model="sonnet",
        workers=1,
        repo_name=None,
        repo_url=None,
        commit_sha=None,
        diff_manifest=None,
        run_id="cli_run_2",
    )
    cli_mod.cmd_scan(ns)
    req = captured["request"]
    assert req.config.scope == "all"
    assert req.config.verify is False
    assert req.config.dynamic_verify is True
    assert req.config.app_context is False
    assert req.config.enhance is False
    assert req.limit == 1
    assert req.enhance_mode == "single-shot"


def test_build_scan_request_allocates_run_id(tmp_path):
    from vulscan.cli import build_scan_request

    ns = argparse.Namespace(
        repo=str(tmp_path),
        output=str(tmp_path / "out"),
        language="python",
        scope="reachable",
        no_verify=False,
        no_context=False,
        no_enhance=False,
        enhance_mode="agentic",
        no_report=False,
        dynamic_verify=False,
        no_skip_tests=False,
        limit=None,
        model="opus",
        workers=8,
        repo_name=None,
        repo_url=None,
        commit_sha=None,
        diff_manifest=None,
        run_id=None,
    )
    req = build_scan_request(ns)
    assert req.run_id
    assert (tmp_path / "out" / "runs" / req.run_id).is_dir()


def test_scan_repository_has_no_dual_config_params():
    from core.scanner import scan_repository

    params = inspect.signature(scan_repository).parameters
    for banned in (
        "language", "scope", "verify", "config", "output_dir",
        "real_world", "processing_level", "backoff_seconds",
    ):
        assert banned not in params
