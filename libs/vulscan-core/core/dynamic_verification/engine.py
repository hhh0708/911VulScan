"""Dynamic verification engine: TestPlan → policy compile → sandboxed run."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from core.dynamic_verification.checkpoint import DynamicCheckpointManager
from core.dynamic_verification.evidence import append_unique, make_dynamic_evidence
from core.dynamic_verification.fingerprint import compute_dynamic_fingerprint
from core.dynamic_verification.input_builder import (
    build_dynamic_input,
    is_dynamic_eligible,
)
from core.dynamic_verification.oracle import (
    compute_oracles,
    decide_from_oracles,
    evaluate_preconditions,
    parse_harness_stdout,
    parse_target_call_begin,
)
from core.dynamic_verification.policy import compile_test_plan, reject_unsafe_request
from core.dynamic_verification.schema import (
    DYNAMIC_COMPILER_VERSION,
    DYNAMIC_PROMPT_VERSION,
    DYNAMIC_RUNNER_VERSION,
    DYNAMIC_SCHEMA_VERSION,
    blocked_dynamic_result,
    empty_dynamic_result,
    is_supported_language,
    skipped_dynamic_result,
    validate_test_plan,
)
from core.dynamic_verification.staging import resolve_repo_source_path
from utilities.credentials import safe_exception_message
from utilities.llm_client import TokenTracker, get_global_tracker
from utilities.model_registry import ModelRole, model_for

TESTPLAN_SYSTEM = f"""You generate a declarative dynamic TestPlan for verifying a confirmed vulnerability candidate.

Return ONLY a JSON object with these keys:
  entrypoint, payload, setup_requirements, invocation,
  success_oracle, negative_oracle, expected_artifacts

HARD RULES:
- Do NOT output dockerfile, docker-compose, host commands, docker run args,
  privileged flags, volume mounts, devices, or network_mode.
- success_oracle / negative_oracle declare WHAT to observe (exit_code, sanitizer,
  marker, return_value, exception). Do NOT claim oracles already succeeded.
- setup_requirements may only reference pinned packages already in the repo lockfile.
- Do not request network.

Schema: {DYNAMIC_SCHEMA_VERSION}
Prompt: {DYNAMIC_PROMPT_VERSION}
"""


def generate_test_plan(
    dynamic_input: Dict[str, Any],
    *,
    tracker: TokenTracker | None = None,
    model: str | None = None,
) -> tuple[Dict[str, Any] | None, str]:
    tracker = tracker or get_global_tracker()
    model_id = model or model_for(ModelRole.PRIMARY)
    from utilities.llm_client import AnthropicClient
    from utilities.llm_json_utils import DEFAULT_JSON_RETRIES

    prompt = _build_testplan_prompt(dynamic_input)
    client = AnthropicClient(model=model_id, tracker=tracker)
    try:
        parsed = client.analyze_json_sync(
            prompt,
            max_tokens=4096,
            system=TESTPLAN_SYSTEM,
            context="dynamic test plan",
            retries=DEFAULT_JSON_RETRIES,
        )
    except Exception as exc:  # noqa: BLE001
        return None, safe_exception_message(exc)

    if not isinstance(parsed, dict):
        return None, "model returned non-object TestPlan"
    unsafe = reject_unsafe_request(parsed)
    if unsafe:
        return None, unsafe
    plan, err = validate_test_plan(parsed)
    if plan is None:
        return None, err
    return plan, ""


def _build_testplan_prompt(din: Dict[str, Any]) -> str:
    return (
        "## DynamicVerificationInput\n"
        f"test_id: {din.get('test_id')}\n"
        f"finding_id: {din.get('finding_id')}\n"
        f"unit_id: {din.get('unit_id')}\n"
        f"language: {din.get('language')}\n\n"
        "### Stage 1 candidate\n"
        f"```json\n{json.dumps(din.get('stage1_candidate'), indent=2, default=str)}\n```\n\n"
        "### Stage 2 VerificationResult\n"
        f"```json\n{json.dumps(din.get('stage2_verification'), indent=2, default=str)}\n```\n\n"
        "### Preconditions\n"
        f"```json\n{json.dumps(din.get('preconditions'), indent=2, default=str)}\n```\n\n"
        "Emit a declarative TestPlan JSON only. Oracle fields describe observations, not outcomes."
    )


def run_one_dynamic_verification(
    *,
    stage1_result: dict,
    stage2_result: dict,
    finding: Optional[dict] = None,
    unit: Optional[dict] = None,
    language: str = "",
    repo_path: str = "",
    repo_name: str = "",
    checkpoint: Optional[DynamicCheckpointManager] = None,
    tracker: TokenTracker | None = None,
    max_infra_retries: int = 1,
    execute: bool = True,
    test_plan_override: Optional[dict] = None,
) -> Dict[str, Any]:
    """Run dynamic verification. Never mutates Stage 1/2 results."""
    tracker = tracker or get_global_tracker()
    ok, reason = is_dynamic_eligible(stage1_result, stage2_result)
    finding_id = (stage2_result or {}).get("finding_id") or ""
    if not ok:
        return skipped_dynamic_result(
            finding_id=str(finding_id),
            reason=f"not_eligible:{reason}",
        )

    din = build_dynamic_input(
        stage1_result=stage1_result,
        stage2_result=stage2_result,
        finding=finding,
        unit=unit,
        evidence=list((stage2_result or {}).get("evidence") or []),
        language=language,
        repo_path=repo_path,
        repo_name=repo_name,
        model=model_for(ModelRole.PRIMARY),
    )
    test_id = din["test_id"]
    finding_id = din["finding_id"]

    if not is_supported_language(din.get("language")):
        return skipped_dynamic_result(
            test_id=test_id,
            finding_id=finding_id,
            reason=f"unsupported_language:{din.get('language')!r}",
        )

    attempts: List[Dict[str, Any]] = []
    evidence_table: List[dict] = list(din.get("evidence") or [])

    if test_plan_override is not None:
        plan, plan_err = validate_test_plan(test_plan_override)
        if plan is None:
            return empty_dynamic_result(
                test_id=test_id,
                finding_id=finding_id,
                execution_state="failed",
                reason=plan_err,
            )
    else:
        plan, plan_err = generate_test_plan(din, tracker=tracker)
        if plan is None:
            return empty_dynamic_result(
                test_id=test_id,
                finding_id=finding_id,
                execution_state="failed",
                reason=f"test_plan_generation_failed:{plan_err}",
            )

    location = (din.get("stage1_candidate") or {}).get("location") or (
        (finding or {}).get("location") or {}
    )
    source_basename = ""
    if repo_path and location.get("file"):
        resolved, serr = resolve_repo_source_path(str(location["file"]), repo_path)
        if serr:
            return blocked_dynamic_result(
                test_id=test_id,
                finding_id=finding_id,
                reason=f"staging_path_rejected:{serr}",
            )
        import os

        source_basename = os.path.basename(resolved or "")

    # Dry-run compile (attempt_id placeholder) for policy/fingerprint gating.
    compiled_probe, cerr = compile_test_plan(
        plan,
        language=din.get("language") or "",
        test_id=test_id,
        unit_id=din.get("unit_id") or "",
        finding_id=finding_id,
        attempt_id="probe",
        policy=din.get("sandbox_policy"),
        location=location if isinstance(location, dict) else {},
        allowed_packages=set(
            (din.get("repository_manifest") or {}).get("allowed_packages") or []
        )
        or None,
        source_basename=source_basename,
    )
    if compiled_probe is None:
        return blocked_dynamic_result(
            test_id=test_id,
            finding_id=finding_id,
            reason=f"policy_rejected:{cerr}",
        )

    # Checkpoint fingerprint is content-addressed WITHOUT volatile digest for lookup;
    # stored record also carries digests/versions for post-restore verification.
    fp_base = compute_dynamic_fingerprint(
        din,
        test_plan=plan,
        image_digest="",
        model=model_for(ModelRole.PRIMARY),
        policy_hash=compiled_probe.get("policy_hash", ""),
    )
    if checkpoint:
        cached = checkpoint.load_valid(
            test_id,
            fp_base,
            require_image_digest=True,
            expected_policy_hash=compiled_probe.get("policy_hash", ""),
            expected_compiler_version=DYNAMIC_COMPILER_VERSION,
            expected_runner_version=DYNAMIC_RUNNER_VERSION,
            expected_test_plan_hash=compiled_probe.get("test_plan_hash", ""),
        )
        if cached and cached.get("result"):
            return cached["result"]

    if not execute:
        result = empty_dynamic_result(
            test_id=test_id,
            finding_id=finding_id,
            execution_state="pending",
            reason="execute=false",
        )
        result["artifacts"] = [
            {
                "kind": "compiled_test",
                "test_plan_hash": compiled_probe.get("test_plan_hash"),
                "run_command_hash": compiled_probe.get("run_command_hash"),
                "policy_hash": compiled_probe.get("policy_hash"),
                "base_image": compiled_probe.get("base_image"),
            }
        ]
        result["evidence"] = evidence_table
        return result

    last_result: Dict[str, Any] | None = None
    last_compiled: Dict[str, Any] = compiled_probe
    for infra_try in range(max_infra_retries + 1):
        attempt_id = uuid.uuid4().hex
        compiled, cerr = compile_test_plan(
            plan,
            language=din.get("language") or "",
            test_id=test_id,
            unit_id=din.get("unit_id") or "",
            finding_id=finding_id,
            attempt_id=attempt_id,
            policy=din.get("sandbox_policy"),
            location=location if isinstance(location, dict) else {},
            allowed_packages=set(
                (din.get("repository_manifest") or {}).get("allowed_packages") or []
            )
            or None,
            source_basename=source_basename,
        )
        if compiled is None:
            return blocked_dynamic_result(
                test_id=test_id,
                finding_id=finding_id,
                reason=f"policy_rejected:{cerr}",
            )
        last_compiled = compiled
        attempt_rec: Dict[str, Any] = {
            "attempt_id": attempt_id,
            "infra_retry": infra_try,
            "test_plan_hash": compiled.get("test_plan_hash"),
        }
        try:
            last_result = _execute_compiled(
                din=din,
                compiled=compiled,
                finding=finding or {},
                repo_path=repo_path,
                evidence_table=evidence_table,
                attempts=attempts,
                attempt_rec=attempt_rec,
            )
        except Exception as exc:  # noqa: BLE001
            last_result = empty_dynamic_result(
                test_id=test_id,
                finding_id=finding_id,
                execution_state="failed",
                reason=safe_exception_message(exc),
            )
            last_result["evidence"] = evidence_table
            last_result["attempts"] = attempts + [attempt_rec]
            if not _is_transient_infra(str(exc)) or infra_try >= max_infra_retries:
                break
            continue
        if (last_result or {}).get("execution_state") != "failed" or not _is_transient_infra(
            (last_result or {}).get("provenance", {}).get("reason", "")
        ):
            break

    assert last_result is not None
    last_result["provenance"] = {
        **(last_result.get("provenance") or {}),
        "schema_version": DYNAMIC_SCHEMA_VERSION,
        "prompt_version": DYNAMIC_PROMPT_VERSION,
        "compiler_version": DYNAMIC_COMPILER_VERSION,
        "runner_version": DYNAMIC_RUNNER_VERSION,
        "fingerprint_base": fp_base,
    }
    last_result["evidence"] = evidence_table

    if checkpoint and last_result.get("execution_state") not in ("failed",):
        img = ""
        base_dig = ""
        ctx_hash = ""
        for art in last_result.get("artifacts") or []:
            if not isinstance(art, dict):
                continue
            if art.get("image_digest") and not img:
                img = art["image_digest"]
            if art.get("base_image_digest") and not base_dig:
                base_dig = art["base_image_digest"]
            if art.get("build_context_hash") and not ctx_hash:
                ctx_hash = art["build_context_hash"]
        checkpoint.save(
            test_id,
            fingerprint=fp_base,
            result=last_result,
            attempt_id=(attempts[-1]["attempt_id"] if attempts else ""),
            image_digest=img,
            base_image_digest=base_dig,
            policy_hash=last_compiled.get("policy_hash", ""),
            compiler_version=DYNAMIC_COMPILER_VERSION,
            runner_version=DYNAMIC_RUNNER_VERSION,
            test_plan_hash=last_compiled.get("test_plan_hash", ""),
            build_context_hash=ctx_hash,
        )
    return last_result


def _is_transient_infra(msg: str) -> bool:
    m = (msg or "").lower()
    return any(
        tok in m
        for tok in (
            "connection reset",
            "temporarily unavailable",
            "docker daemon",
            "cannot connect to the docker",
            "network is unreachable",
            "i/o timeout",
        )
    )


def _execute_compiled(
    *,
    din: Dict[str, Any],
    compiled: Dict[str, Any],
    finding: dict,
    repo_path: str,
    evidence_table: List[dict],
    attempts: List[dict],
    attempt_rec: dict,
) -> Dict[str, Any]:
    from utilities.dynamic_tester.docker_executor import run_single_container

    test_id = din["test_id"]
    finding_id = din["finding_id"]
    unit_id = str(din.get("unit_id") or "")
    attempt_id = str(attempt_rec.get("attempt_id") or "")
    plan = compiled.get("test_plan") or {}
    entrypoint = str(
        plan.get("entrypoint")
        or (plan.get("invocation") or {}).get("command")
        or ""
    )

    generation = dict(compiled)
    generation["_policy_compiled"] = True
    generation["needs_attacker_server"] = False

    source_file = None
    loc = finding.get("location") or (din.get("stage1_candidate") or {}).get("location") or {}
    if repo_path and loc.get("file"):
        resolved, err = resolve_repo_source_path(str(loc["file"]), repo_path)
        if err:
            return blocked_dynamic_result(
                test_id=test_id,
                finding_id=finding_id,
                reason=f"staging_path_rejected:{err}",
            )
        source_file = resolved

    execution = run_single_container(
        generation,
        finding_id,
        source_file=source_file,
        language=din.get("language"),
        repo_path=repo_path or None,
        finding=finding,
        repo_info=din.get("repository_manifest") or {},
        sandbox_run_argv=compiled.get("run_argv"),
        sandbox_build_argv=compiled.get("build_argv"),
        require_staged_source=True,
    )

    build_err = getattr(execution, "build_error", None) if execution else "no_execution"
    timed_out = bool(getattr(execution, "timed_out", False)) if execution else False
    stdout = getattr(execution, "stdout", "") or ""
    stderr = getattr(execution, "stderr", "") or ""
    exit_code = getattr(execution, "exit_code", None) if execution else None
    image_tag = getattr(execution, "image_tag", "") or ""
    # Digest comes from executor BEFORE cleanup — never re-inspect here.
    image_digest = getattr(execution, "image_digest", "") or ""
    base_image_digest = getattr(execution, "base_image_digest", "") or ""
    build_context_hash = getattr(execution, "build_context_hash", "") or ""
    build_ok = execution is not None and not build_err

    if getattr(execution, "staging_blocked", False):
        state = "blocked"
        # Missing local base image is blocked, not failed
        reason = build_err or "staging_blocked"
        result = blocked_dynamic_result(
            test_id=test_id,
            finding_id=finding_id,
            reason=reason,
        )
        result["artifacts"] = [
            {
                "kind": "image",
                "image_digest": image_digest,
                "base_image_digest": base_image_digest,
                "base_image": getattr(execution, "base_image", "") or compiled.get("base_image"),
                "build_context_hash": build_context_hash,
                "image_tag": image_tag,
                "build_command": getattr(execution, "build_command", []) or [],
                "run_command": getattr(execution, "run_command", []) or [],
            }
        ]
        attempts.append({**attempt_rec, "execution_state": state, "decision": "inconclusive"})
        result["attempts"] = list(attempts)
        return result

    expected_identity = {
        "test_id": test_id,
        "finding_id": finding_id,
        "unit_id": unit_id,
        "entrypoint": entrypoint,
        "attempt_id": attempt_id,
    }
    begin_meta, marker_err = parse_target_call_begin(stderr, expected=expected_identity)
    marker_ok = begin_meta is not None and not marker_err
    call_begun = marker_ok

    harness_obj, parse_err = parse_harness_stdout(stdout, expected=expected_identity)
    harness_parse_ok = harness_obj is not None and not parse_err
    harness_call_begun = bool(harness_obj and harness_obj.get("call_begun") is True)
    identity_match = marker_ok and harness_parse_ok
    harness_ok = build_ok and not timed_out and harness_parse_ok

    preconditions = list(din.get("preconditions") or [])
    pre_ok, pre_eval = evaluate_preconditions(preconditions, evidence_table)

    oracle_results = compute_oracles(
        plan=plan,
        harness=harness_obj,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        call_begun=call_begun,
    )

    ev = make_dynamic_evidence(
        kind="execution",
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        sanitizer_report=stderr if "AddressSanitizer" in stderr else "",
        observations={
            "marker_ok": marker_ok,
            "marker_error": marker_err,
            "harness_parse_ok": harness_parse_ok,
            "parse_error": parse_err,
            "harness_call_begun": harness_call_begun,
            "identity_match": identity_match,
            "target_call_begin": begin_meta,
            "preconditions": pre_eval,
            "build_command": getattr(execution, "build_command", []) or [],
            "run_command": getattr(execution, "run_command", []) or [],
        },
        image_digest=image_digest,
        test_plan_hash=compiled.get("test_plan_hash", ""),
        run_command_hash=compiled.get("run_command_hash", ""),
    )
    eid = append_unique(evidence_table, ev)
    evidence_ok = bool(eid and ev.get("content_hash"))

    if not build_ok:
        state, decision, reason = (
            "failed",
            "inconclusive",
            f"build_failed:{(build_err or '')[:500]}",
        )
    elif timed_out:
        state, decision, reason = "failed", "inconclusive", "timeout"
    else:
        state, decision, reason = decide_from_oracles(
            build_ok=build_ok,
            harness_ok=harness_ok,
            call_begun=call_begun,
            preconditions_satisfied=pre_ok,
            oracle_results=oracle_results,
            harness_parse_ok=harness_parse_ok,
            evidence_resolvable=evidence_ok,
            marker_ok=marker_ok,
            harness_call_begun=harness_call_begun,
            identity_match=identity_match,
            target_blocked=False,
        )

    attempt_rec["evidence_id"] = eid
    attempt_rec["execution_state"] = state
    attempt_rec["decision"] = decision
    attempt_rec["image_digest"] = image_digest
    attempt_rec["base_image_digest"] = base_image_digest
    attempts.append(dict(attempt_rec))

    result = empty_dynamic_result(
        test_id=test_id,
        finding_id=finding_id,
        execution_state=state,
        decision=decision,
        reason=reason,
    )
    result["target_reached"] = bool(marker_ok and harness_call_begun and identity_match)
    result["preconditions_satisfied"] = pre_ok
    result["precondition_results"] = pre_eval
    result["oracle_results"] = oracle_results
    result["evidence_ids"] = [eid]
    result["evidence"] = list(evidence_table)
    result["artifacts"] = [
        {"kind": "dockerfile", "hash": compiled.get("test_plan_hash")},
        {"kind": "test_script", "filename": compiled.get("test_filename")},
        {
            "kind": "image",
            "image_digest": image_digest,
            "base_image_digest": base_image_digest,
            "base_image": getattr(execution, "base_image", "") or compiled.get("base_image"),
            "build_context_hash": build_context_hash,
            "image_tag": image_tag,
            "build_command": getattr(execution, "build_command", []) or [],
            "run_command": getattr(execution, "run_command", []) or [],
        },
        {"kind": "policy", "policy_hash": compiled.get("policy_hash")},
    ]
    result["attempts"] = list(attempts)
    result["confidence"] = 0.8 if decision == "reproduced" else 0.4
    return result
