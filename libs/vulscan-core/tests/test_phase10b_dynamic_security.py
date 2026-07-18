"""Phase 10b: eliminate false reproduced/not_reproduced; tighten sandbox."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.dynamic_verification.harness import build_real_call_harness
from core.dynamic_verification.input_builder import is_dynamic_eligible
from core.dynamic_verification.oracle import (
    compute_oracles,
    parse_harness_stdout,
    parse_target_call_begin,
)
from core.dynamic_verification.policy import (
    compile_test_plan,
    validate_docker_argv_allowlist,
    validate_setup_requirements,
)
from core.dynamic_verification.staging import resolve_repo_source_path, verify_staged_source
from utilities.finding_verdicts import is_testable_finding


def _plan(entry="foo", success=None, negative=None):
    return {
        "entrypoint": entry,
        "payload": {},
        "setup_requirements": [],
        "invocation": {"command": entry},
        "success_oracle": success or {"type": "return_value"},
        "negative_oracle": negative or {"type": "exit_code", "value": 0},
        "expected_artifacts": [],
    }


def test_python_import_without_call_not_reproduced():
    """Import-only must not set call_begun / target_reached."""
    adapter, err = build_real_call_harness(
        _plan("missing_fn"),
        language="python",
        test_id="t1",
        unit_id="m.py:missing_fn",
        target_module="target_code",
        target_qualname="missing_fn",
        source_basename="target_code.py",
    )
    assert err == ""
    # Harness source must emit TARGET_CALL_BEGIN only after resolve+callable check
    script = adapter["test_script"]
    assert "TARGET_CALL_BEGIN" in script
    assert "importlib.import_module" in script
    # Must not print TARGET_CALL_BEGIN before resolve
    begin_idx = script.index("TARGET_CALL_BEGIN")
    resolve_idx = script.index("_resolve")
    assert resolve_idx < begin_idx


def test_js_require_without_export_call_not_not_reproduced():
    adapter, err = build_real_call_harness(
        _plan("doEvil"),
        language="javascript",
        test_id="t1",
        unit_id="a.js:doEvil",
        source_basename="target_code.js",
        target_qualname="doEvil",
    )
    assert err == ""
    script = adapter["test_script"]
    assert "require(" in script
    assert "TARGET_CALL_BEGIN" in script
    assert "typeof fn !== \"function\"" in script or "typeof fn !== 'function'" in script
    # Must not set oracles/preconditions in harness JSON
    assert "preconditions_satisfied" not in script
    assert '"oracles"' not in script and "oracles:" not in script.split("report")[0]


def test_go_and_native_placeholder_forbidden():
    go, gerr = build_real_call_harness(
        _plan("RealFn"),
        language="go",
        test_id="t",
        unit_id="m.go:RealFn",
        target_symbol="RealFn",
        package_name="main",
    )
    assert gerr == ""
    assert "RealFn()" in go["test_script"]
    assert "target_reached" not in go["test_script"]

    native, nerr = build_real_call_harness(
        _plan("vuln_fn"),
        language="c",
        test_id="t",
        unit_id="a.c:vuln_fn",
        target_symbol="vuln_fn",
        source_basename="target_code.c",
    )
    assert nerr == ""
    assert "vuln_fn()" in native["test_script"]
    assert "target_reached" not in native["test_script"]

    bad, berr = build_real_call_harness(
        _plan(""),
        language="go",
        test_id="t",
        unit_id="x",
        target_symbol="",
    )
    assert bad is None
    assert "unresolvable" in berr or "missing" in berr


def test_missing_symbol_blocks_adapter():
    compiled, err = compile_test_plan(
        _plan(""),
        language="python",
        test_id="t",
        unit_id="a.py:",
        location={"file": "a.py", "function": ""},
    )
    assert compiled is None
    assert "blocked" in err or "missing" in err or "adapter" in err


def test_staging_relative_path_and_escape(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    src = repo / "pkg" / "mod.py"
    src.parent.mkdir()
    src.write_text("def foo():\n    return 1\n", encoding="utf-8")

    real, err = resolve_repo_source_path("pkg/mod.py", str(repo))
    assert err == ""
    assert real and real.endswith("mod.py")

    bad, berr = resolve_repo_source_path("../outside.py", str(repo))
    assert bad is None
    assert "escape" in berr or "not_a_file" in berr

    # symlink escape
    outside = tmp_path / "secret.txt"
    outside.write_text("x", encoding="utf-8")
    link = repo / "link.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink not permitted")
    # realpath of link points outside → reject
    r2, e2 = resolve_repo_source_path("link.py", str(repo))
    assert r2 is None
    assert "escape" in e2

    work = tmp_path / "work"
    work.mkdir()
    staged = work / "mod.py"
    staged.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    ok, _ = verify_staged_source(str(work), "mod.py")
    assert ok


def test_legacy_status_cannot_complete_oracle():
    plan = _plan(success={"type": "marker", "value": "PWNED"}, negative={"type": "exit_code", "value": 0})
    # Even if someone passes legacy CONFIRMED, compute_oracles ignores it
    oracles = compute_oracles(
        plan=plan,
        harness={
            "schema_version": "1.0",
            "test_id": "t",
            "unit_id": "u",
            "entrypoint": "foo",
            "call_begun": True,
            "call_completed": True,
            "return_repr": "None",
            "exception_type": None,
            "exception_message": None,
        },
        exit_code=0,
        stdout='{"schema_version":"1.0"}',
        stderr="TARGET_CALL_BEGIN {\"test_id\":\"t\",\"unit_id\":\"u\",\"entrypoint\":\"foo\"}\n",
        call_begun=True,
    )
    assert oracles["success_hit"] is False  # no PWNED marker
    assert oracles["positive_oracle_done"] is True


def test_external_deps_rejected():
    pinned, err = validate_setup_requirements(["requests"], allowed_packages=set())
    assert err
    pinned2, err2 = validate_setup_requirements(
        ["requests==2.0.0"], allowed_packages=set()
    )
    assert err2 == "requirements_require_local_manifest"
    pinned3, err3 = validate_setup_requirements(
        ["requests==2.0.0"], allowed_packages={"requests"}
    )
    assert err3 == ""
    assert pinned3 == ["requests==2.0.0"]


def test_no_canonical_stage2_evidence_not_dynamic_eligible():
    s1 = {"decision": "candidate", "unit_id": "u"}
    ok, reason = is_dynamic_eligible(
        s1,
        {
            "finding_id": "fid",
            "execution_state": "succeeded",
            "decision": "confirmed",
            "evidence_ids": ["ev1"],
            # missing evidence[]
        },
    )
    assert not ok
    assert "evidence" in reason

    assert not is_testable_finding({"stage2_verdict": "confirmed"})
    assert not is_testable_finding(
        {
            "stage2_verification": {
                "execution_state": "succeeded",
                "decision": "confirmed",
                "finding_id": "fid",
                "evidence": [],
            }
        }
    )
    assert is_testable_finding(
        {
            "stage2_verification": {
                "execution_state": "succeeded",
                "decision": "confirmed",
                "finding_id": "fid",
                "evidence": [{"evidence_id": "ev1", "kind": "x"}],
            }
        }
    )


def test_malformed_and_multiple_json_rejected():
    obj, err = parse_harness_stdout("")
    assert obj is None
    obj2, err2 = parse_harness_stdout("{}{}")
    assert obj2 is None
    assert "multiple" in err2 or "malformed" in err2

    good = {
        "schema_version": "1.0",
        "test_id": "t",
        "unit_id": "u",
        "entrypoint": "foo",
        "call_begun": True,
        "call_completed": True,
        "return_repr": "1",
        "exception_type": None,
        "exception_message": None,
        "observations": {},
    }
    obj3, err3 = parse_harness_stdout(json.dumps(good))
    assert err3 == ""
    assert obj3["call_begun"] is True

    # Forbidden self-reported oracles
    bad = dict(good)
    bad["oracles"] = {"success": True}
    obj4, err4 = parse_harness_stdout(json.dumps(bad))
    assert obj4 is None


def test_target_call_begin_required():
    expected = {
        "test_id": "t",
        "finding_id": "f",
        "unit_id": "u",
        "entrypoint": "foo",
        "attempt_id": "a1",
    }
    meta, err = parse_target_call_begin("imported ok\n", expected=expected)
    assert meta is None
    assert err

    # Incomplete identity → not reached
    meta_bad, err_bad = parse_target_call_begin(
        'TARGET_CALL_BEGIN {"test_id":"t","unit_id":"u","entrypoint":"foo"}\n',
        expected=expected,
    )
    assert meta_bad is None
    assert err_bad

    payload = json.dumps(expected)
    meta2, err2 = parse_target_call_begin(
        f"TARGET_CALL_BEGIN {payload}\n",
        expected=expected,
    )
    assert err2 == ""
    assert meta2["entrypoint"] == "foo"
    assert meta2["finding_id"] == "f"


def test_docker_argv_allowlist():
    assert validate_docker_argv_allowlist(["--network", "none", "--read-only"]) == ""
    assert validate_docker_argv_allowlist(["--privileged"]) != ""
    assert validate_docker_argv_allowlist(["-v", "/:/host"]) != ""
    assert validate_docker_argv_allowlist(["--secret", "id=x"]) != ""


def test_needs_network_blocked():
    plan = _plan()
    plan["needs_network"] = True
    compiled, err = compile_test_plan(
        plan,
        language="python",
        test_id="t",
        unit_id="a.py:foo",
        location={"file": "a.py", "function": "foo"},
        source_basename="a.py",
    )
    # needs_network on plan may only be in sandbox policy path
    compiled2, err2 = compile_test_plan(
        _plan("foo"),
        language="python",
        test_id="t",
        unit_id="a.py:foo",
        location={"file": "a.py", "function": "foo"},
        source_basename="a.py",
        policy={"network": "isolated_test"},
    )
    assert compiled2 is None
    assert "needs_network" in err2


def test_compile_emits_build_network_none():
    compiled, err = compile_test_plan(
        _plan("foo"),
        language="python",
        test_id="t",
        unit_id="a.py:foo",
        location={"file": "a.py", "function": "foo"},
        source_basename="a.py",
    )
    assert err == "", err
    assert "--network" in compiled["build_argv"]
    assert "none" in compiled["build_argv"]
    assert "--read-only" in compiled["run_argv"]
    assert "TARGET_CALL_BEGIN" in compiled["test_script"]
    assert "pip install" not in compiled["dockerfile"]


def test_reproduced_requires_call_and_oracle_hit():
    from core.dynamic_verification.oracle import decide_from_oracles

    state, decision, _ = decide_from_oracles(
        build_ok=True,
        harness_ok=True,
        call_begun=False,
        preconditions_satisfied=True,
        oracle_results={
            "success_hit": True,
            "success_executed": True,
            "negative_pass": True,
            "negative_executed": True,
        },
        harness_parse_ok=True,
        evidence_resolvable=True,
        marker_ok=False,
        harness_call_begun=True,
        identity_match=True,
    )
    assert decision != "reproduced"

    state2, decision2, _ = decide_from_oracles(
        build_ok=True,
        harness_ok=True,
        call_begun=True,
        preconditions_satisfied=True,
        oracle_results={
            "success_hit": True,
            "success_executed": True,
            "negative_pass": False,
            "negative_executed": True,
        },
        harness_parse_ok=True,
        evidence_resolvable=True,
        marker_ok=True,
        harness_call_begun=True,
        identity_match=True,
    )
    assert decision2 == "reproduced"
