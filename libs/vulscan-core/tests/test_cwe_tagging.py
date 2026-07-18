"""Regression tests for CWE tagging in Stage 1 Detection Schema."""

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


def test_stage1_prompt_includes_cwe_fields():
    from prompts.vulnerability_analysis import get_detection_prompt
    from core.detection.input_builder import build_detection_input

    din = build_detection_input(
        {
            "id": "test.py:foo",
            "language": "python",
            "code": {"primary_code": "def foo(): pass", "primary_origin": {}},
            "reachability": "unknown",
        }
    )
    prompt = get_detection_prompt(din)
    assert "cwe_id" in prompt


def test_normalize_detection_preserves_cwe():
    from core.detection.schema import normalize_detection_result

    evid = {"ev_a"}
    result = normalize_detection_result(
        {
            "decision": "candidate",
            "candidate_type": "sqli",
            "cwe_id": 89,
            "location": {},
            "source": "q",
            "propagation": "p",
            "sink": "s",
            "guards": [],
            "impact": "x",
            "preconditions": [],
            "evidence_ids": ["ev_a"],
            "counter_evidence_ids": [],
            "uncertainties": [],
            "confidence": 0.9,
        },
        unit_id="u",
        evidence_ids=evid,
    )
    assert result["cwe_id"] == 89
    assert result["decision"] == "candidate"


def test_normalize_defaults_cwe_when_missing():
    from core.detection.schema import normalize_detection_result

    result = normalize_detection_result(
        {
            "decision": "no_finding",
            "evidence_ids": [],
            "counter_evidence_ids": [],
            "uncertainties": [],
            "confidence": 0.5,
            "guards": [],
            "preconditions": [],
        },
        unit_id="u",
        evidence_ids=set(),
    )
    assert result["cwe_id"] == 0


@pytest.fixture
def results_with_cwe(tmp_path: Path) -> Path:
    results = {
        "dataset": "cwe-test",
        "results": [
            {
                "unit_id": "test.py:foo",
                "route_key": "test.py:foo",
                "decision": "candidate",
                "finding": "candidate",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
                "stage2_verification": {
                    "finding_id": "fid",
                    "execution_state": "succeeded",
                    "decision": "confirmed",
                    "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
                    "evidence_ids": ["ev1"],
                },
            },
        ],
        "code_by_route": {"test.py:foo": "def foo(): pass"},
        "confirmed_findings": [
            {
                "unit_id": "test.py:foo",
                "route_key": "test.py:foo",
                "decision": "candidate",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
                "stage2_verification": {
                    "finding_id": "fid",
                    "execution_state": "succeeded",
                    "decision": "confirmed",
                    "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
                    "evidence_ids": ["ev1"],
                },
            },
        ],
        "metrics": {"total": 1, "candidate": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_pipeline_output_carries_cwe(tmp_path, results_with_cwe):
    from core.reporter import build_pipeline_output

    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(results_with_cwe),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    finding = data["findings"][0]
    s1 = finding.get("stage1_detection") or finding
    assert s1.get("cwe_id") == 89
