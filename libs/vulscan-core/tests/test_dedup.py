"""Regression tests for caller/callee dedup based on CWE.

When the call graph shows A→B as the only edge into B and both findings
share the same CWE, they should be collapsed into one — regardless of
whether the attack_vector strings match.

Dedup matches on CWE rather than attack_vector text because the LLM
generates different attack_vector wording on different runs, while CWE
is stable.
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


def _s2_confirmed() -> dict:
    return {
        "finding_id": "fid",
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence": [{"evidence_id": "ev1", "kind": "obs"}],
        "evidence_ids": ["ev1"],
        "verified_source": "user_input",
        "sink": "sql_exec",
    }


def _with_s2(finding: dict) -> dict:
    out = dict(finding)
    out.setdefault("source", "user_input")
    out.setdefault("sink", "sql_exec")
    out.setdefault("decision", "candidate")
    out.setdefault("stage2_verification", _s2_confirmed())
    return out


@pytest.fixture
def caller_callee_results(tmp_path: Path) -> tuple[Path, Path]:
    """Build a results.json and call_graph.json with a caller/callee pair sharing one CWE."""
    results = {
        "dataset": "dedup-test",
        "results": [
            {
                "unit_id": "app.py:get_user",
                "route_key": "app.py:get_user",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /user?id=' OR '1'='1' --",
                "reasoning": "SQL injection via run_query",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
            },
            {
                "unit_id": "app.py:run_query",
                "route_key": "app.py:run_query",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /user?id=' OR '1'='1' --",
                "reasoning": "SQL injection — sink for get_user",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
            },
        ],
        "code_by_route": {
            "app.py:get_user": "def get_user(): ...",
            "app.py:run_query": "def run_query(q): ...",
        },
        "confirmed_findings": [
            _with_s2({
                "unit_id": "app.py:get_user",
                "route_key": "app.py:get_user",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /user?id=' OR '1'='1' --",
            }),
            _with_s2({
                "unit_id": "app.py:run_query",
                "route_key": "app.py:run_query",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /user?id=' OR '1'='1' --",
            }),
        ],
        "metrics": {"total": 2, "vulnerable": 2},
    }
    results["results"] = [_with_s2(r) for r in results["results"]]

    call_graph = {
        "nodes": {
            "app.py:get_user": {"id": "app.py:get_user"},
            "app.py:run_query": {"id": "app.py:run_query"},
        },
        "resolved_edges": [
            {"caller": "app.py:get_user", "callee": "app.py:run_query", "kind": "call", "confidence": "exact"},
        ],
    }

    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(results))

    cg_path = tmp_path / "call_graph.json"
    cg_path.write_text(json.dumps(call_graph))

    return results_path, cg_path


def test_caller_callee_collapsed(tmp_path, caller_callee_results):
    """get_user + run_query with the same attack vector should collapse to 1 finding."""
    from core.reporter import build_pipeline_output
    results_path, _cg_path = caller_callee_results
    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    findings = data["findings"]
    assert len(findings) == 1, f"expected 1 (collapsed), got {len(findings)}: {[f.get('unit_id') for f in findings]}"
    survivor = findings[0]
    loc = (survivor.get("stage1_detection") or {}).get("location") or {}
    assert "get_user" in (loc.get("function") or survivor.get("unit_id", ""))
    s2 = survivor.get("stage2_verification") or {}
    prov = s2.get("merge_provenance") or survivor.get("merge_provenance") or {}
    assert "app.py:run_query" in prov.get("merged_from_unit_ids", [])


def test_different_attack_vector_same_cwe_collapsed(tmp_path):
    """The LLM writes different attack_vector text per run, but both get
    CWE-89. Dedup must still fire on CWE match."""
    from core.reporter import build_pipeline_output
    results = {
        "dataset": "dedup-cwe-test",
        "results": [
            {
                "unit_id": "app.py:get_user",
                "route_key": "app.py:get_user",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /user?id=' OR 1=1--",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
            },
            {
                "unit_id": "app.py:run_query",
                "route_key": "app.py:run_query",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "injection via unsanitized query parameter",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
            },
        ],
        "code_by_route": {
            "app.py:get_user": "def get_user(): ...",
            "app.py:run_query": "def run_query(q): ...",
        },
        "confirmed_findings": [
            _with_s2({
                "unit_id": "app.py:get_user",
                "route_key": "app.py:get_user",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /user?id=' OR 1=1--",
                "cwe_id": 89,
            }),
            _with_s2({
                "unit_id": "app.py:run_query",
                "route_key": "app.py:run_query",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "injection via unsanitized query parameter",
                "cwe_id": 89,
            }),
        ],
        "metrics": {"total": 2, "vulnerable": 2},
    }
    results["results"] = [_with_s2(r) for r in results["results"]]
    call_graph = {
        "nodes": {
            "app.py:get_user": {"id": "app.py:get_user"},
            "app.py:run_query": {"id": "app.py:run_query"},
        },
        "resolved_edges": [
            {"caller": "app.py:get_user", "callee": "app.py:run_query", "kind": "call", "confidence": "exact"},
        ],
    }
    rp = tmp_path / "results.json"
    rp.write_text(json.dumps(results))
    (tmp_path / "call_graph.json").write_text(json.dumps(call_graph))
    out = tmp_path / "po.json"
    build_pipeline_output(results_path=str(rp), output_path=str(out), language="python")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 1, (
        f"expected 1 (collapsed on CWE), got {len(data['findings'])}. "
        "Different attack_vector text but same CWE-89 must still dedup."
    )
    assert "get_user" in (
        (data["findings"][0].get("stage1_detection") or {}).get("location", {}).get("function")
        or data["findings"][0].get("unit_id", "")
    )


def test_cwe_zero_not_collapsed(tmp_path):
    """Two CWE-0 (unknown) findings must NOT collapse — 0==0 is meaningless."""
    from core.reporter import build_pipeline_output
    results = {
        "dataset": "dedup-cwe0-test",
        "results": [
            {
                "unit_id": "app.py:caller",
                "route_key": "app.py:caller",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "some attack",
                "cwe_id": 0,
                "cwe_name": "Unknown",
            },
            {
                "unit_id": "app.py:callee",
                "route_key": "app.py:callee",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "some attack",
                "cwe_id": 0,
                "cwe_name": "Unknown",
            },
        ],
        "code_by_route": {
            "app.py:caller": "def caller(): ...",
            "app.py:callee": "def callee(): ...",
        },
        "confirmed_findings": [
            _with_s2({
                "unit_id": "app.py:caller",
                "route_key": "app.py:caller",
                "cwe_id": 0,
                # Distinct empty sink identity — must not merge on CWE-0 alone
                "source": "",
                "sink": "",
            }),
            _with_s2({
                "unit_id": "app.py:callee",
                "route_key": "app.py:callee",
                "cwe_id": 0,
                "source": "",
                "sink": "",
            }),
        ],
        "metrics": {"total": 2, "vulnerable": 2},
    }
    results["results"] = [
        _with_s2({**r, "source": "", "sink": "", "decision": "candidate"})
        for r in results["results"]
    ]
    call_graph = {
        "nodes": {
            "app.py:caller": {"id": "app.py:caller"},
            "app.py:callee": {"id": "app.py:callee"},
        },
        "resolved_edges": [
            {"caller": "app.py:caller", "callee": "app.py:callee", "kind": "call", "confidence": "exact"},
        ],
    }
    rp = tmp_path / "results.json"
    rp.write_text(json.dumps(results))
    (tmp_path / "call_graph.json").write_text(json.dumps(call_graph))
    out = tmp_path / "po.json"
    build_pipeline_output(results_path=str(rp), output_path=str(out), language="python")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 2, "CWE-0 + CWE-0 must NOT collapse (both unknown)"


def test_independent_findings_not_collapsed(tmp_path):
    """Findings with different attack vectors must NOT be collapsed."""
    from core.reporter import build_pipeline_output
    results = {
        "dataset": "no-dedup",
        "results": [
            {
                "unit_id": "app.py:ping",
                "route_key": "app.py:ping",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /ping?ip=-w 1000",
                "cwe_id": 78,
                "cwe_name": "Command Injection",
            },
            {
                "unit_id": "app.py:login",
                "route_key": "app.py:login",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "POST /login brute-force",
                "cwe_id": 798,
                "cwe_name": "Hardcoded Credentials",
            },
        ],
        "code_by_route": {
            "app.py:ping": "def ping(): ...",
            "app.py:login": "def login(): ...",
        },
        "confirmed_findings": [
            _with_s2({"unit_id": "app.py:ping", "route_key": "app.py:ping", "verdict": "vulnerable", "finding": "vulnerable"}),
            _with_s2({"unit_id": "app.py:login", "route_key": "app.py:login", "verdict": "vulnerable", "finding": "vulnerable"}),
        ],
        "metrics": {"total": 2, "vulnerable": 2},
    }
    results["results"] = [_with_s2(r) for r in results["results"]]
    rp = tmp_path / "results.json"
    rp.write_text(json.dumps(results))
    out = tmp_path / "po.json"
    build_pipeline_output(results_path=str(rp), output_path=str(out), language="python")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 2, "independent findings must NOT be collapsed"
