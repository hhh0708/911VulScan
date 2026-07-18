"""Incremental dynamic disclosure generation on resume.

Fixtures build a canonical FinalScanArtifact via ``build_pipeline_output``
(the Phase 11/12 contract: ``load_and_validate_final_artifact`` rejects the
legacy ``stage2_verdict`` pipeline shape) plus a dynamic_test_results.json
keyed by the same ``finding_id`` values.
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


def _write_scan_artifacts(scan_dir: Path, pairs: list[tuple[str, str]]) -> Path:
    """Write results.json + dynamic_test_results.json for (finding_id, unit_id)
    pairs and reduce them into a validated FinalScanArtifact in *scan_dir*."""
    from core.reporter import build_pipeline_output

    results = {
        "dataset": "cwe-testbench",
        "results": [
            {
                "unit_id": uid,
                "route_key": uid,
                "decision": "candidate",
                "candidate_type": "vulnerable",
                "location": {"file": uid.split(":")[0], "function": uid},
                "stage2_verification": _stage2(fid, f"ev_{fid.lower()}"),
            }
            for fid, uid in pairs
        ],
        "metrics": {"total": len(pairs), "candidate": len(pairs)},
    }
    (scan_dir / "results.json").write_text(json.dumps(results), encoding="utf-8")
    (scan_dir / "dynamic_test_results.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "finding_id": fid,
                        "unit_id": uid,
                        "execution_state": "succeeded",
                        "decision": "reproduced",
                        "status": "CONFIRMED",
                        "details": "ok",
                    }
                    for fid, uid in pairs
                ]
            }
        ),
        encoding="utf-8",
    )
    output_path = scan_dir / "pipeline_output.json"
    _path, _count, errors = build_pipeline_output(
        results_path=str(scan_dir / "results.json"),
        output_path=str(output_path),
        repo_name="cwe-testbench",
        language="c",
    )
    assert not errors, errors
    return output_path


def test_resume_only_generates_docs_for_newly_tested_findings(tmp_path: Path):
    from core.reporter import generate_dynamic_disclosure_docs

    scan_dir = tmp_path / "scan"
    disclosures = scan_dir / "disclosures"
    disclosures.mkdir(parents=True)
    artifact_path = _write_scan_artifacts(
        scan_dir, [("VULN-001", "src/a.c:foo"), ("VULN-005", "src/b.c:bar")]
    )

    existing = disclosures / "DYNAMIC_DISCLOSURE_01_VULNERABLE.md"
    existing.write_text("# already done\n", encoding="utf-8")

    calls: list[str] = []

    def _fake_disclosure(finding, dyn, product_name, language=None):
        calls.append(finding["finding_id"])
        return f"# {finding['finding_id']}\n", {
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
            "cost_usd": 0.0,
        }

    with patch(
        "report.generator.generate_dynamic_disclosure",
        side_effect=_fake_disclosure,
    ):
        generate_dynamic_disclosure_docs(
            str(artifact_path),
            str(scan_dir),
            tested_finding_ids={"VULN-005"},
        )

    assert calls == ["VULN-005"]
    assert existing.read_text(encoding="utf-8") == "# already done\n"
    assert (disclosures / "DYNAMIC_DISCLOSURE_02_VULNERABLE.md").is_file()


def test_fill_missing_when_nothing_newly_tested(tmp_path: Path):
    from core.reporter import generate_dynamic_disclosure_docs

    scan_dir = tmp_path / "scan"
    disclosures = scan_dir / "disclosures"
    disclosures.mkdir(parents=True)
    artifact_path = _write_scan_artifacts(
        scan_dir, [("VULN-001", "src/a.c:foo"), ("VULN-005", "src/b.c:bar")]
    )

    (disclosures / "DYNAMIC_DISCLOSURE_01_VULNERABLE.md").write_text("# ok\n", encoding="utf-8")

    calls: list[str] = []

    def _fake_disclosure(finding, dyn, product_name, language=None):
        calls.append(finding["finding_id"])
        return f"# {finding['finding_id']}\n", {
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
            "cost_usd": 0.0,
        }

    with patch(
        "report.generator.generate_dynamic_disclosure",
        side_effect=_fake_disclosure,
    ):
        generate_dynamic_disclosure_docs(
            str(artifact_path),
            str(scan_dir),
            tested_finding_ids=set(),
        )

    assert calls == ["VULN-005"]
