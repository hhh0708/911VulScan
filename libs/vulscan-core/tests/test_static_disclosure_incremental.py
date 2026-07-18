"""Incremental static disclosure generation on verify resume.

Fixtures build a canonical FinalScanArtifact via ``build_pipeline_output``
(the Phase 11/12 contract: ``load_and_validate_final_artifact`` rejects the
legacy ``stage2_verdict`` pipeline shape).
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))


def _stage2(finding_id: str, evidence_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "execution_state": "succeeded",
        "decision": "confirmed",
        "evidence_ids": [evidence_id],
        "evidence": [{"evidence_id": evidence_id, "kind": "obs", "content": {}}],
    }


def _unit(unit_id: str, finding_id: str, evidence_id: str) -> dict:
    return {
        "unit_id": unit_id,
        "route_key": unit_id,
        "decision": "candidate",
        "candidate_type": "vulnerable",
        "location": {"file": unit_id.split(":")[0], "function": unit_id},
        "stage2_verification": _stage2(finding_id, evidence_id),
    }


def _write_artifact(scan_dir: Path, pairs: list[tuple[str, str]]) -> Path:
    """Write results.json for (finding_id, unit_id) pairs and reduce it into a
    validated FinalScanArtifact (+ run manifest) inside *scan_dir*."""
    from core.reporter import build_pipeline_output

    results = {
        "dataset": "cwe-testbench",
        "results": [
            _unit(uid, fid, f"ev_{fid.lower()}")
            for fid, uid in pairs
        ],
        "metrics": {"total": len(pairs), "candidate": len(pairs)},
    }
    results_path = scan_dir / "results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    output_path = scan_dir / "pipeline_output.json"
    _path, _count, errors = build_pipeline_output(
        results_path=str(results_path),
        output_path=str(output_path),
        repo_name="cwe-testbench",
        language="c",
    )
    assert not errors, errors
    return output_path


def test_resume_only_generates_docs_for_newly_verified_units(tmp_path: Path):
    from core.reporter import generate_disclosure_docs

    scan_dir = tmp_path / "scan"
    disclosures = scan_dir / "disclosures"
    disclosures.mkdir(parents=True)
    artifact_path = _write_artifact(
        scan_dir, [("VULN-001", "src/a.c:foo"), ("VULN-005", "src/b.c:bar")]
    )

    existing = disclosures / "DISCLOSURE_01_VULNERABLE.md"
    existing.write_text("# already done\n", encoding="utf-8")

    calls: list[str] = []

    def _fake_disclosure(finding, product_name):
        calls.append(finding["finding_id"])
        return f"# {finding['finding_id']}\n", {
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
            "cost_usd": 0.0,
        }

    with patch(
        "report.generator.generate_disclosure",
        side_effect=_fake_disclosure,
    ):
        generate_disclosure_docs(
            str(artifact_path),
            str(disclosures),
            verified_unit_ids={"src/b.c:bar"},
        )

    assert calls == ["VULN-005"]
    assert existing.read_text(encoding="utf-8") == "# already done\n"
    assert (disclosures / "DISCLOSURE_02_VULNERABLE.md").is_file()


def test_fill_missing_when_nothing_newly_verified(tmp_path: Path):
    from core.reporter import generate_disclosure_docs

    scan_dir = tmp_path / "scan"
    disclosures = scan_dir / "disclosures"
    disclosures.mkdir(parents=True)
    artifact_path = _write_artifact(
        scan_dir, [("VULN-001", "src/a.c:foo"), ("VULN-005", "src/b.c:bar")]
    )
    (disclosures / "DISCLOSURE_01_VULNERABLE.md").write_text("# ok\n", encoding="utf-8")

    calls: list[str] = []

    def _fake_disclosure(finding, product_name):
        calls.append(finding["finding_id"])
        return f"# {finding['finding_id']}\n", {
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
            "cost_usd": 0.0,
        }

    with patch(
        "report.generator.generate_disclosure",
        side_effect=_fake_disclosure,
    ):
        generate_disclosure_docs(
            str(artifact_path),
            str(disclosures),
            verified_unit_ids=set(),
        )

    assert calls == ["VULN-005"]
