"""Trusted runner-side oracle computation and strict harness JSON parsing."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple

HARNESS_SCHEMA_VERSION = "1.0"

MARKER_IDENTITY_KEYS = (
    "test_id",
    "finding_id",
    "unit_id",
    "entrypoint",
    "attempt_id",
)


def parse_harness_stdout(
    stdout: str,
    *,
    expected: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Parse container stdout as exactly one JSON object; enforce identity match."""
    text = stdout if isinstance(stdout, str) else ""
    stripped = text.strip()
    if not stripped:
        return None, "empty_stdout"

    decoder = json.JSONDecoder()
    try:
        obj, idx = decoder.raw_decode(stripped)
    except json.JSONDecodeError as exc:
        return None, f"malformed_json:{exc}"

    rest = stripped[idx:].strip()
    if rest:
        return None, "multiple_json_values"

    if not isinstance(obj, dict):
        return None, "json_not_object"

    err = _validate_harness_fields(obj)
    if err:
        return None, err

    if expected:
        for key in ("test_id", "unit_id", "entrypoint"):
            want = str(expected.get(key) or "")
            got = str(obj.get(key) or "")
            if not want or got != want:
                return None, f"harness_identity_mismatch:{key}"
        # finding_id / attempt_id optional in older harnesses but required when expected
        for key in ("finding_id", "attempt_id"):
            if key in expected and expected[key]:
                if str(obj.get(key) or "") != str(expected[key]):
                    return None, f"harness_identity_mismatch:{key}"

    return obj, ""


def _validate_harness_fields(obj: dict) -> str:
    required_types = {
        "schema_version": str,
        "test_id": str,
        "unit_id": str,
        "entrypoint": str,
        "call_begun": bool,
        "call_completed": bool,
    }
    for key, typ in required_types.items():
        if key not in obj:
            return f"missing_field:{key}"
        if not isinstance(obj[key], typ):
            return f"bad_type:{key}"
    if obj.get("schema_version") != HARNESS_SCHEMA_VERSION:
        return f"unsupported_schema:{obj.get('schema_version')!r}"
    if "oracles" in obj or "preconditions_satisfied" in obj:
        return "forbidden_harness_oracle_fields"
    if "target_reached" in obj:
        return "forbidden_harness_target_reached_field"
    return ""


_TARGET_CALL_BEGIN_RE = re.compile(
    r"^TARGET_CALL_BEGIN\s+(\{.*\})\s*$",
    re.MULTILINE,
)


def parse_target_call_begin(
    stderr: str,
    *,
    expected: Dict[str, str],
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Require exactly one TARGET_CALL_BEGIN matching full identity.

    Returns (marker_dict, error). error non-empty → not target reached.
    """
    text = stderr or ""
    matches = list(_TARGET_CALL_BEGIN_RE.finditer(text))
    # Also collect line-based markers
    line_objs: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("TARGET_CALL_BEGIN"):
            continue
        payload = line[len("TARGET_CALL_BEGIN") :].strip()
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            return None, "marker_malformed_json"
        if not isinstance(obj, dict):
            return None, "marker_not_object"
        line_objs.append(obj)

    if len(line_objs) == 0 and not matches:
        return None, "marker_missing"
    if len(line_objs) > 1:
        return None, "multiple_markers"

    obj = line_objs[0] if line_objs else None
    if obj is None and matches:
        if len(matches) != 1:
            return None, "multiple_markers"
        try:
            obj = json.loads(matches[0].group(1))
        except json.JSONDecodeError:
            return None, "marker_malformed_json"
        if not isinstance(obj, dict):
            return None, "marker_not_object"

    assert obj is not None
    for key in MARKER_IDENTITY_KEYS:
        want = str(expected.get(key) or "")
        got = str(obj.get(key) or "")
        if not want:
            return None, f"expected_missing:{key}"
        if got != want:
            return None, f"marker_identity_mismatch:{key}"
    return obj, ""


def compute_oracles(
    *,
    plan: Dict[str, Any],
    harness: Optional[Dict[str, Any]],
    exit_code: Optional[int],
    stdout: str,
    stderr: str,
    call_begun: bool,
) -> Dict[str, Any]:
    success_spec = plan.get("success_oracle") or {}
    negative_spec = plan.get("negative_oracle") or {}
    if isinstance(success_spec, str):
        success_spec = {"type": "marker", "value": success_spec}
    if isinstance(negative_spec, str):
        negative_spec = {"type": "marker", "value": negative_spec}

    success_hit = _eval_oracle_spec(
        success_spec,
        harness=harness,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        call_begun=call_begun,
    )
    negative_pass = _eval_oracle_spec(
        negative_spec,
        harness=harness,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        call_begun=call_begun,
        negative=True,
    )

    return {
        "success_executed": bool(call_begun and success_spec),
        "success_hit": bool(success_hit),
        "negative_executed": bool(call_begun and negative_spec),
        "negative_pass": bool(negative_pass),
        "positive_oracle_done": bool(call_begun and success_spec),
        "negative_oracle_done": bool(call_begun and negative_spec and negative_pass),
    }


def _eval_oracle_spec(
    spec: Any,
    *,
    harness: Optional[dict],
    exit_code: Optional[int],
    stdout: str,
    stderr: str,
    call_begun: bool,
    negative: bool = False,
) -> Optional[bool]:
    del negative
    if not spec or not isinstance(spec, dict):
        return False
    if not call_begun:
        return False

    otype = str(spec.get("type") or spec.get("kind") or "marker").lower()
    combined = f"{stdout}\n{stderr}"

    if otype in ("exit_code", "exit"):
        expected = spec.get("value", spec.get("equals", 0))
        try:
            return exit_code == int(expected)
        except (TypeError, ValueError):
            return False

    if otype in ("signal",):
        name = str(spec.get("value") or spec.get("signal") or "").upper()
        return bool(name) and name in combined.upper()

    if otype in ("sanitizer", "asan", "ubsan"):
        markers = ("AddressSanitizer", "UndefinedBehaviorSanitizer", "ERROR: AddressSanitizer")
        return any(m in stderr or m in stdout for m in markers)

    if otype in ("http_status",):
        want = spec.get("value") or spec.get("status")
        return f"HTTP {want}" in combined or f'"status": {want}' in combined

    if otype in ("file_contains", "file_change"):
        needle = str(spec.get("value") or spec.get("contains") or "")
        return bool(needle) and needle in combined

    if otype in ("return_value", "return_equals"):
        if not harness:
            return False
        expected = spec.get("value", spec.get("equals"))
        actual = harness.get("return_repr")
        if expected is None:
            return actual is not None and harness.get("call_completed") is True
        return str(actual) == str(expected)

    if otype in ("exception", "raises"):
        if not harness:
            return False
        want = str(spec.get("value") or spec.get("exception_type") or "")
        got = str(harness.get("exception_type") or "")
        if not want:
            return bool(got)
        return want in got

    if otype in ("marker", "stdout_contains", "stderr_contains"):
        needle = str(spec.get("value") or spec.get("marker") or "")
        if not needle:
            return False
        if otype == "stderr_contains":
            return needle in (stderr or "")
        return needle in combined

    return False


def evaluate_preconditions(
    preconditions: list,
    evidence_table: list,
) -> Tuple[bool, list]:
    """Evaluate structured preconditions individually.

    Each item: {precondition_id, description, supporting_evidence_ids, status?}
    All required items must be individually satisfied via their supporting IDs.
    Empty list → satisfied.
    """
    if not preconditions:
        return True, []

    by_id = {
        e.get("evidence_id"): e
        for e in evidence_table
        if isinstance(e, dict) and e.get("evidence_id")
    }
    evaluated = []
    all_ok = True
    for i, pre in enumerate(preconditions):
        if not isinstance(pre, dict):
            # Legacy string precondition → unknown
            item = {
                "precondition_id": f"pre_{i}",
                "description": str(pre),
                "supporting_evidence_ids": [],
                "status": "unknown",
            }
            evaluated.append(item)
            all_ok = False
            continue
        pid = str(pre.get("precondition_id") or f"pre_{i}")
        desc = str(pre.get("description") or "")
        support = list(pre.get("supporting_evidence_ids") or [])
        if not support:
            status = "unknown"
            all_ok = False
        elif not all(sid in by_id for sid in support):
            status = "unsatisfied"
            all_ok = False
        else:
            status = "satisfied"
        # Allow explicit status override only to unsatisfied/unknown, never invent satisfied
        explicit = pre.get("status")
        if explicit in ("unsatisfied", "unknown"):
            status = explicit
            if status != "satisfied":
                all_ok = False
        evaluated.append(
            {
                "precondition_id": pid,
                "description": desc,
                "supporting_evidence_ids": support,
                "status": status,
            }
        )
        if status != "satisfied":
            all_ok = False
    return all_ok, evaluated


def decide_from_oracles(
    *,
    build_ok: bool,
    harness_ok: bool,
    call_begun: bool,
    preconditions_satisfied: bool,
    oracle_results: Dict[str, Any],
    harness_parse_ok: bool,
    evidence_resolvable: bool,
    marker_ok: bool = False,
    harness_call_begun: bool = False,
    identity_match: bool = False,
    infra_error: bool = False,
    target_blocked: bool = False,
) -> Tuple[str, str, str]:
    """Return (execution_state, decision, reason)."""
    if target_blocked:
        return "blocked", "inconclusive", "target_unresolvable"
    if not build_ok or infra_error:
        return "failed", "inconclusive", "build_or_infra_error"
    if not harness_parse_ok:
        return "failed", "inconclusive", "harness_json_invalid"
    if not harness_ok:
        return "failed", "inconclusive", "harness_invalid"
    if not marker_ok or not call_begun:
        return "succeeded", "inconclusive", "target_call_not_begun"
    if not harness_call_begun or not identity_match:
        return "succeeded", "inconclusive", "identity_or_call_mismatch"
    if not evidence_resolvable:
        return "failed", "inconclusive", "execution_evidence_unresolvable"

    success_hit = bool(oracle_results.get("success_hit"))
    success_exec = bool(oracle_results.get("success_executed"))
    neg_pass = bool(oracle_results.get("negative_pass"))
    neg_exec = bool(oracle_results.get("negative_executed"))

    if (
        success_hit
        and success_exec
        and preconditions_satisfied
        and marker_ok
        and harness_call_begun
        and identity_match
        and evidence_resolvable
    ):
        return "succeeded", "reproduced", "success_oracle_hit"

    if (
        marker_ok
        and harness_call_begun
        and identity_match
        and preconditions_satisfied
        and success_exec
        and not success_hit
        and neg_exec
        and neg_pass
        and build_ok
        and harness_ok
        and harness_parse_ok
    ):
        return "succeeded", "not_reproduced", "success_miss_negative_pass"

    return "succeeded", "inconclusive", "oracle_incomplete"
