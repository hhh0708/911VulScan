"""Phase 11 end-to-end final_state fixture matrix (no LLM / no Docker)."""

from __future__ import annotations

import hashlib

import pytest

from core.final_artifact.reducer import compute_final_state, reduce_to_final_artifact
from core.final_artifact.validate import validate_final_scan_artifact
from core.final_artifact.report_views import bucket_findings_by_final_state


def _sha(label: str) -> str:
    """Evidence content_hash must be lowercase sha-256 hex (strict validation)."""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _s1(decision="candidate", finding_id="f1"):
    return {
        "decision": decision,
        "finding_id": finding_id,
        "evidence": [{"evidence_id": "e_s1", "content_hash": _sha("s1")}],
    }


def _s2(decision="confirmed", state="succeeded", finding_id="f1"):
    return {
        "decision": decision,
        "execution_state": state,
        "finding_id": finding_id,
        "evidence": [{"evidence_id": "e_s2", "content_hash": _sha("s2")}],
    }


def _dyn(decision="reproduced", state="succeeded", finding_id="f1"):
    return {
        "decision": decision,
        "execution_state": state,
        "finding_id": finding_id,
        "evidence": [{"evidence_id": "e_dyn", "content_hash": _sha("dyn")}],
    }


@pytest.mark.parametrize(
    "s1,s2,dyn,expected",
    [
        (_s1("no_finding"), None, None, "inconclusive"),
        (_s1("candidate"), _s2("rejected"), None, "rejected"),
        (_s1("candidate"), _s2("confirmed"), None, "confirmed_not_dynamically_tested"),
        (_s1("candidate"), _s2("confirmed"), _dyn("reproduced"), "reproduced"),
        (_s1("candidate"), _s2("confirmed"), _dyn("not_reproduced"), "confirmed_not_reproduced"),
        (_s1("candidate"), _s2("confirmed", state="failed"), None, "error"),
        (
            _s1("candidate"),
            _s2("confirmed"),
            _dyn(decision="inconclusive", state="blocked"),
            "confirmed_not_dynamically_tested",
        ),
        (_s1("candidate"), None, None, "candidate"),
    ],
)
def test_final_state_fixture_matrix(s1, s2, dyn, expected):
    assert compute_final_state(s1, s2, dyn) == expected


def test_partial_pipeline_continues_with_error_bucket():
    e1 = {"evidence_id": "e_s1", "content_hash": _sha("s1")}
    e2 = {"evidence_id": "e_s2", "content_hash": _sha("s2")}
    artifact, reduce_errs = reduce_to_final_artifact(
        run_meta={"run_id": "r1"},
        units=[{"unit_id": "u1"}, {"unit_id": "u2"}],
        stage1_results=[
            {
                **_s1("candidate", "f1"),
                "unit_id": "u1",
                "evidence_ids": ["e_s1"],
                "evidence": [e1],
            },
            {**_s1("error", "f2"), "unit_id": "u2", "evidence_ids": []},
        ],
        stage2_results=[
            {
                **_s2("confirmed", finding_id="f1"),
                "unit_id": "u1",
                "evidence_ids": ["e_s2"],
                "evidence": [e2],
            }
        ],
        dynamic_results=[],
        evidence_lists=[[e1], [e2]],
        reachability_counts={
            "reachable": 1,
            "unreachable": 0,
            "unknown_reachability": 1,
        },
        artifact_manifest=[],
        configuration={},
    )
    assert not reduce_errs, reduce_errs
    errors = validate_final_scan_artifact(artifact)
    assert errors == [], errors
    buckets = bucket_findings_by_final_state(artifact)
    assert buckets["error"] or artifact.get("errors")
    assert "safe" not in (artifact.get("metrics") or {})


def test_not_reproduced_not_safe_label():
    assert (
        compute_final_state(_s1(), _s2("confirmed"), _dyn("not_reproduced"))
        == "confirmed_not_reproduced"
    )
    assert compute_final_state(_s1(), _s2("confirmed"), _dyn("not_reproduced")) != "rejected"


def test_docker_e2e_skipped_without_daemon():
    """Without Docker, integration must skip — never count as passed success."""
    import shutil
    import subprocess

    if shutil.which("docker") is None:
        pytest.skip("Docker CLI not available — dynamic e2e not production-ready here")
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip("Docker daemon unreachable — dynamic e2e skipped")
    if proc.returncode != 0:
        pytest.skip("Docker daemon not running — dynamic e2e skipped")
    # Environment has Docker: still do not claim full 4-lang readiness in this unit test.
    pytest.skip("Docker present but Phase 11 four-language e2e runs only in dedicated CI job")
