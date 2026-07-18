"""Reporter emission rules after Phase 10 Stage 2 confirmation gate.

Findings require ``stage2_verification.execution_state=succeeded`` and
``decision=confirmed``. Unverified candidates go to ``candidates`` / ``inconclusive``.
"""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub
_anth = sys.modules["anthropic"]
if not hasattr(_anth, "RateLimitError"):
    _anth.RateLimitError = type("RateLimitError", (Exception,), {})
if not hasattr(_anth, "AuthenticationError"):
    _anth.AuthenticationError = type("AuthenticationError", (Exception,), {})


def _confirmed_s2(**extra):
    base = {
        "finding_id": "fid",
        "execution_state": "succeeded",
        "decision": "confirmed",
        "verified_source": "s",
        "propagation": "p",
        "sink": "k",
        "impact": "i",
        "evidence_ids": ["ev1"],
        "counter_evidence_ids": [],
        "evidence": [{"evidence_id": "ev1", "kind": "obs", "content": {}}],
        "guards": [],
        "missing_evidence": [],
        "uncertainties": [],
        "confidence": 0.9,
        "provenance": {},
    }
    base.update(extra)
    return base


@pytest.fixture
def stage2_confirmed_results(tmp_path: Path) -> Path:
    results = {
        "dataset": "agreement-test",
        "results": [
            {
                "unit_id": "app.py:login",
                "route_key": "app.py:login",
                "decision": "candidate",
                "verdict": "VULNERABLE",
                "cwe_id": 798,
                "cwe_name": "Hardcoded Credentials",
                "stage2_verification": _confirmed_s2(),
            },
        ],
        "metrics": {"total": 1, "candidate": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results), encoding="utf-8")
    return path


def test_stage2_confirmed_emitted(tmp_path, stage2_confirmed_results):
    from core.reporter import build_pipeline_output

    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(stage2_confirmed_results),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 1
    assert "login" in data["findings"][0]["location"]["function"]
    finding = data["findings"][0]
    assert finding["final_state"] == "confirmed_not_dynamically_tested"
    assert finding["stage2_verification"]["decision"] == "confirmed"


@pytest.fixture
def legacy_agree_only_results(tmp_path: Path) -> Path:
    """Legacy agree=True without stage2_verification must NOT become a finding."""
    results = {
        "dataset": "legacy-agree",
        "results": [
            {
                "unit_id": "app.py:unserialize",
                "route_key": "app.py:unserialize",
                "decision": "candidate",
                "verdict": "VULNERABLE",
                "finding": "vulnerable",
                "verification": {
                    "agree": True,
                    "correct_finding": "vulnerable",
                },
            },
        ],
        "metrics": {"total": 1, "candidate": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results), encoding="utf-8")
    return path


def test_legacy_agree_not_emitted_as_finding(tmp_path, legacy_agree_only_results):
    from core.reporter import build_pipeline_output

    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(legacy_agree_only_results),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    # Legacy agree=True must not become a confirmed finding — it stays a
    # stage-1 candidate in the canonical final_state model.
    assert all(f["final_state"] == "candidate" for f in data["findings"])
    assert any(c["unit_id"] == "app.py:unserialize" for c in data["candidates"])


@pytest.fixture
def stage2_rejected_results(tmp_path: Path) -> Path:
    results = {
        "dataset": "agreement-test-drop",
        "results": [
            {
                "unit_id": "app.py:requests_example",
                "route_key": "app.py:requests_example",
                "decision": "candidate",
                "stage2_verification": {
                    "finding_id": "fid",
                    "execution_state": "succeeded",
                    "decision": "rejected",
                    "evidence_ids": [],
                    "counter_evidence_ids": ["ev_c"],
                    "evidence": [{"evidence_id": "ev_c", "kind": "counter", "content": {}}],
                    "confidence": 0.5,
                    "provenance": {},
                    "verified_source": "",
                    "propagation": "",
                    "sink": "",
                    "impact": "",
                    "guards": [],
                    "missing_evidence": [],
                    "uncertainties": [],
                },
            },
        ],
        "metrics": {"total": 1, "candidate": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results), encoding="utf-8")
    return path


def test_stage2_rejected_not_in_findings(tmp_path, stage2_rejected_results):
    from core.reporter import build_pipeline_output

    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(stage2_rejected_results),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    # Rejected units are never emitted as confirmed findings; they land in
    # the canonical `rejected` bucket with final_state=rejected.
    assert all(f["final_state"] == "rejected" for f in data["findings"])
    assert [f["unit_id"] for f in data["rejected"]] == ["app.py:requests_example"]


def test_stage1_verdict_emitted_in_canonical_lowercase(tmp_path, stage2_confirmed_results):
    from core.reporter import build_pipeline_output

    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(stage2_confirmed_results),
        output_path=str(out),
        language="python",
    )
    finding = json.loads(out.read_text(encoding="utf-8"))["findings"][0]
    assert finding["stage1_detection"]["decision"] == "candidate"
    assert finding["stage2_verification"]["decision"] == "confirmed"


def test_verifier_confirmed_findings_includes_stage2_confirmed():
    from core.verifier import _write_verified_results
    import tempfile, os

    experiment = {"dataset": "test", "metrics": {}}
    merged = [
        {
            "unit_id": "app.py:login",
            "route_key": "app.py:login",
            "decision": "candidate",
            "stage2_verification": {
                "execution_state": "succeeded",
                "decision": "confirmed",
            },
        },
        {
            "unit_id": "app.py:safe_fn",
            "route_key": "app.py:safe_fn",
            "decision": "candidate",
            "stage2_verification": {
                "execution_state": "succeeded",
                "decision": "rejected",
            },
        },
    ]
    metrics = {
        "candidates_input": 2,
        "attempted": 2,
        "succeeded": 2,
        "failed": 0,
        "skipped": 0,
        "confirmed": 1,
        "rejected": 1,
        "inconclusive": 0,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        path = f.name

    try:
        _write_verified_results(path, experiment, merged, metrics)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        confirmed = data["confirmed_findings"]
        assert len(confirmed) == 1
        assert confirmed[0]["route_key"] == "app.py:login"
        assert "code_by_route" not in data
    finally:
        os.unlink(path)
