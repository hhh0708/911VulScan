"""Phase 12 Docker dynamic E2E — full engine path per language.

Calls ``run_one_dynamic_verification`` with ``test_plan_override`` and asserts
``DynamicVerificationResult`` (``execution_state`` + ``decision``). Never calls
``decide_from_oracles()`` directly to prove reproduction.

Locally: skip when Docker is unavailable (not a pass).
CI (``VULSCAN_REQUIRE_DOCKER_E2E=1``): skip is a failure.

Each case writes evidence under ``artifacts/docker-e2e/<language>/`` at repo root.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from core.dynamic_verification.engine import run_one_dynamic_verification
from core.dynamic_verification.oracle import parse_harness_stdout
from utilities.dynamic_tester.docker_executor import _local_image_exists

FIXTURES = Path(__file__).parent / "fixtures" / "phase12_docker"
REPO_ROOT = Path(__file__).resolve().parents[3]
ARTIFACTS_ROOT = REPO_ROOT / "artifacts" / "docker-e2e"
REQUIRE = os.environ.get("VULSCAN_REQUIRE_DOCKER_E2E") == "1"

BASE_IMAGES = {
    "python": "python:3.11-slim",
    "javascript": "node:20-slim",
    "go": "golang:1.22-alpine",
    "c": "gcc:13",
}


def _require_docker() -> None:
    if shutil.which("docker") is None:
        if REQUIRE:
            pytest.fail("Docker CLI required in CI but not found")
        pytest.skip("Docker CLI unavailable")
    try:
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        if REQUIRE:
            pytest.fail(f"Docker daemon required in CI: {exc}")
        pytest.skip("Docker daemon unreachable")
    if proc.returncode != 0:
        if REQUIRE:
            pytest.fail("Docker daemon not running (CI must not skip)")
        pytest.skip("Docker daemon not running")


def _require_base_image(language: str) -> None:
    base = BASE_IMAGES[language]
    if not _local_image_exists(base):
        msg = f"base image missing locally: {base}"
        if REQUIRE:
            pytest.fail(msg)
        pytest.skip(msg)


def _stage2_evidence() -> list[dict]:
    # Omit content_hash — engine/evidence layer computes canonical hashes.
    return [
        {
            "evidence_id": "ev-stage2",
            "kind": "observation",
            "content": {"text": "stage2 confirmed"},
        }
    ]


def _stage_payload(
    *,
    finding_id: str,
    unit_id: str,
    source_file: str,
    function: str,
) -> tuple[dict, dict, dict]:
    stage1 = {
        "unit_id": unit_id,
        "decision": "candidate",
        "location": {"file": source_file, "function": function},
        "preconditions": [],
    }
    stage2 = {
        "finding_id": finding_id,
        "unit_id": unit_id,
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence_ids": ["ev-stage2"],
        "evidence": _stage2_evidence(),
    }
    finding = {"location": {"file": source_file, "function": function}}
    return stage1, stage2, finding


def _plan_reproduced(entry: str, *, marker: str = "ORACLE_HIT") -> dict:
    return {
        "entrypoint": entry,
        "payload": {"marker": marker},
        "setup_requirements": [],
        "invocation": {"command": entry},
        "success_oracle": {"type": "marker", "value": marker},
        "negative_oracle": {"type": "exit_code", "value": 99},
        "expected_artifacts": [],
    }


def _plan_not_reproduced(entry: str) -> dict:
    return {
        "entrypoint": entry,
        "payload": {},
        "setup_requirements": [],
        "invocation": {"command": entry},
        "success_oracle": {"type": "marker", "value": "EXPLOIT_CONFIRMED"},
        "negative_oracle": {"type": "exit_code", "value": 0},
        "expected_artifacts": [],
    }


def _plan_missing_symbol(entry: str) -> dict:
    return {
        "entrypoint": entry,
        "payload": {},
        "setup_requirements": [],
        "invocation": {"command": entry},
        "success_oracle": {"type": "marker", "value": "ORACLE_HIT"},
        "negative_oracle": {"type": "exit_code", "value": 99},
        "expected_artifacts": [],
    }


def _image_artifact(result: dict) -> dict:
    for art in result.get("artifacts") or []:
        if isinstance(art, dict) and art.get("kind") == "image":
            return art
    return {}


def _execution_evidence(result: dict) -> dict:
    for ev in result.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("kind") == "execution":
            return ev
    return {}


def _write_case_artifacts(language: str, result: dict) -> Path:
    out = ARTIFACTS_ROOT / language
    out.mkdir(parents=True, exist_ok=True)

    img = _image_artifact(result)
    ev = _execution_evidence(result)
    content = ev.get("content") or {}
    obs = content.get("observations") or {}

    build_cmd = img.get("build_command") or obs.get("build_command") or []
    run_cmd = img.get("run_command") or obs.get("run_command") or []
    stdout_text = content.get("stdout_preview") or ""
    stderr_text = content.get("stderr_preview") or ""

    (out / "build_command.json").write_text(
        json.dumps(build_cmd, indent=2), encoding="utf-8"
    )
    (out / "run_command.json").write_text(
        json.dumps(run_cmd, indent=2), encoding="utf-8"
    )
    (out / "image_digest.txt").write_text(
        img.get("image_digest") or "", encoding="utf-8"
    )
    (out / "base_image_digest.txt").write_text(
        img.get("base_image_digest") or "", encoding="utf-8"
    )
    (out / "stdout.txt").write_text(stdout_text, encoding="utf-8")
    (out / "stderr.txt").write_text(stderr_text, encoding="utf-8")

    harness_obj: dict[str, Any] | None = None
    if stdout_text.strip():
        parsed, _ = parse_harness_stdout(stdout_text)
        if parsed:
            harness_obj = parsed
    (out / "harness.json").write_text(
        json.dumps(harness_obj or {}, indent=2), encoding="utf-8"
    )
    (out / "dynamic_result.json").write_text(
        json.dumps(result, indent=2, default=str), encoding="utf-8"
    )
    (out / "evidence.json").write_text(
        json.dumps(result.get("evidence") or [], indent=2, default=str),
        encoding="utf-8",
    )
    return out


def _run_engine_case(
    *,
    language: str,
    repo: Path,
    source_rel: str,
    function: str,
    test_plan: dict,
    finding_id: str,
    unit_id: str,
    artifact_language: str | None = None,
) -> dict:
    stage1, stage2, finding = _stage_payload(
        finding_id=finding_id,
        unit_id=unit_id,
        source_file=source_rel,
        function=function,
    )
    result = run_one_dynamic_verification(
        stage1_result=stage1,
        stage2_result=stage2,
        finding=finding,
        language=language,
        repo_path=str(repo),
        repo_name=f"phase12-{language}",
        test_plan_override=test_plan,
    )
    _write_case_artifacts(artifact_language or language, result)
    return result


def _assert_reproduced_result(result: dict) -> None:
    assert result.get("execution_state") == "succeeded", result
    assert result.get("decision") == "reproduced", result
    assert result.get("target_reached") is True, result
    oracles = result.get("oracle_results") or {}
    assert oracles.get("success_hit") is True, oracles
    img = _image_artifact(result)
    assert img.get("image_digest"), "image digest must be captured before cleanup"
    assert img.get("base_image_digest"), "base image digest must be recorded"
    build_cmd = img.get("build_command") or []
    assert build_cmd, "build_command must be recorded"
    joined = " ".join(str(x) for x in build_cmd)
    assert "--network" in joined
    assert "--pull=false" in joined


def _assert_not_reproduced_result(result: dict) -> None:
    assert result.get("execution_state") == "succeeded", result
    assert result.get("decision") == "not_reproduced", result
    assert result.get("target_reached") is True, result
    oracles = result.get("oracle_results") or {}
    assert oracles.get("success_hit") is False, oracles
    assert oracles.get("negative_pass") is True, oracles
    assert oracles.get("negative_executed") is True, oracles


def _assert_missing_symbol_result(result: dict) -> None:
    assert result.get("decision") == "inconclusive", result
    assert result.get("execution_state") in ("failed", "blocked"), result
    reason = (result.get("provenance") or {}).get("reason") or ""
    combined = reason.lower()
    assert any(
        tok in combined
        for tok in ("build_failed", "build_or_infra", "undefined reference", "link")
    ), reason
    img = _image_artifact(result)
    build_cmd = img.get("build_command") or []
    assert build_cmd, "missing-symbol case must run a real docker build"


def _setup_repo(tmp_path: Path, language: str, *, variant: str = "vuln") -> tuple[Path, str, str]:
    repo = tmp_path / f"{language}-repo"
    repo.mkdir()
    if language == "python":
        src = FIXTURES / "python_target" / ("safe.py" if variant == "safe" else "vuln.py")
        target = repo / "vuln.py"
        target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return repo, "vuln.py", "vulnerable"
    if language == "javascript":
        src = FIXTURES / "js_target" / "vuln.js"
        target = repo / "vuln.js"
        target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return repo, "vuln.js", "vulnerable"
    if language == "go":
        src = FIXTURES / "go_target" / "vuln.go"
        target = repo / "vuln.go"
        target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return repo, "vuln.go", "Vulnerable"
    if language == "c":
        if variant == "missing":
            (repo / "stub.c").write_text(
                "#include <stdio.h>\n\nint other(void) { return 0; }\n",
                encoding="utf-8",
            )
            return repo, "stub.c", "definitely_missing_symbol_xyz"
        src = FIXTURES / "c_target" / "vuln.c"
        target = repo / "vuln.c"
        target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return repo, "vuln.c", "vulnerable"
    raise AssertionError(f"unsupported language: {language}")


@pytest.fixture(scope="module", autouse=True)
def _docker_gate():
    _require_docker()


def test_python_real_call_reproduced(tmp_path):
    _require_base_image("python")
    repo, source_rel, function = _setup_repo(tmp_path, "python")
    result = _run_engine_case(
        language="python",
        repo=repo,
        source_rel=source_rel,
        function=function,
        test_plan=_plan_reproduced("vulnerable"),
        finding_id="fid-py",
        unit_id="vuln.py:vulnerable",
    )
    _assert_reproduced_result(result)


def test_javascript_real_call_reproduced(tmp_path):
    _require_base_image("javascript")
    repo, source_rel, function = _setup_repo(tmp_path, "javascript")
    result = _run_engine_case(
        language="javascript",
        repo=repo,
        source_rel=source_rel,
        function=function,
        test_plan=_plan_reproduced("vulnerable"),
        finding_id="fid-js",
        unit_id="vuln.js:vulnerable",
    )
    _assert_reproduced_result(result)


def test_go_real_call_reproduced(tmp_path):
    _require_base_image("go")
    repo, source_rel, function = _setup_repo(tmp_path, "go")
    result = _run_engine_case(
        language="go",
        repo=repo,
        source_rel=source_rel,
        function=function,
        test_plan=_plan_reproduced("Vulnerable"),
        finding_id="fid-go",
        unit_id="vuln.go:Vulnerable",
    )
    _assert_reproduced_result(result)


def test_c_real_link_and_call_reproduced(tmp_path):
    _require_base_image("c")
    repo, source_rel, function = _setup_repo(tmp_path, "c")
    result = _run_engine_case(
        language="c",
        repo=repo,
        source_rel=source_rel,
        function=function,
        test_plan=_plan_reproduced("vulnerable"),
        finding_id="fid-c",
        unit_id="vuln.c:vulnerable",
    )
    _assert_reproduced_result(result)


def test_missing_symbol_build_blocked(tmp_path):
    _require_base_image("c")
    repo, source_rel, function = _setup_repo(tmp_path, "c", variant="missing")
    result = _run_engine_case(
        language="c",
        repo=repo,
        source_rel=source_rel,
        function=function,
        test_plan=_plan_missing_symbol(function),
        finding_id="fid-missing",
        unit_id=f"stub.c:{function}",
        artifact_language="missing_symbol",
    )
    _assert_missing_symbol_result(result)


def test_not_reproduced_negative_oracle(tmp_path):
    _require_base_image("python")
    repo, source_rel, function = _setup_repo(tmp_path, "python", variant="safe")
    result = _run_engine_case(
        language="python",
        repo=repo,
        source_rel=source_rel,
        function=function,
        test_plan=_plan_not_reproduced("vulnerable"),
        finding_id="fid-safe",
        unit_id="vuln.py:vulnerable",
        artifact_language="not_reproduced",
    )
    _assert_not_reproduced_result(result)
