"""Offline advisory lookup stays separate from source verdicts."""

from __future__ import annotations

import json
from pathlib import Path

from utilities.advisory_lookup import (
    advisory_matches_for_finding,
    detect_package_identities,
    scan_repo_advisories,
)


def test_detect_python_and_go_package_identities(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo-lib"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    (tmp_path / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
    identities = detect_package_identities(str(tmp_path))
    ecosystems = {item.ecosystem for item in identities}
    assert "pypi" in ecosystems
    assert "go" in ecosystems


def test_advisory_version_and_fingerprint_are_leads_only(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text(
        "project(demo VERSION 1.0.0)\n",
        encoding="utf-8",
    )
    (tmp_path / "parser.c").write_text(
        "assert(value < 10);\nvalue *= 10;\n",
        encoding="utf-8",
    )
    cache = tmp_path / "advisories.json"
    cache.write_text(
        json.dumps(
            {
                "advisories": [
                    {
                        "id": "CVE-TEST-0001",
                        "ecosystem": "generic",
                        "package": "demo",
                        "cwe_ids": [190],
                        "affected_ranges": [{"introduced": "0", "fixed": "1.1.0"}],
                        "fingerprints": {
                            "vulnerable_regex": [r"assert\(value < 10\);\s*value \*= 10;"],
                            "patched_regex": [r"if \(value >= 10\) return;"],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    intel = scan_repo_advisories(str(tmp_path), [str(cache)])
    assert intel["note"].startswith("Advisory")
    assert intel["observations"]
    obs = intel["observations"][0]
    assert obs["affected"] is True
    assert obs["source_match"] == "vulnerable_pattern_present"
    matches = advisory_matches_for_finding(intel, 190)
    assert matches and matches[0]["advisory_id"] == "CVE-TEST-0001"
