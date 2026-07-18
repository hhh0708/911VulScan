"""Dynamic testing module for 911VulScan.

Takes pipeline_output.json from the static analysis pipeline and dynamically
tests all detected vulnerabilities using Docker containers.

Supports checkpoint/resume: each completed finding is saved to a per-unit
checkpoint file so interrupted runs can resume automatically.

Public API:
    run_dynamic_tests(pipeline_output_path, output_dir) -> list[DynamicTestResult]
"""

import json
import os
import sys
import uuid

from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence
from utilities.dynamic_tester.test_generator import (
    generate_test,
    regenerate_test,
    repair_test_from_compile_errors,
    apply_local_compile_repairs,
)
from utilities.dynamic_tester.docker_executor import run_single_container, prune_vulscan_test_artifacts
from utilities.dynamic_tester.result_collector import collect_result, is_harness_failure_result
from utilities.dynamic_tester.reporter import generate_report
from utilities.dynamic_tester.native_platform import resolve_native_test_source
from utilities.dynamic_tester.staging_limits import resolve_repo_file
from utilities.dynamic_tester.native_test_plan import ProvenExploitRegistry
from utilities.dynamic_tester.php_dockerfile import is_registry_pull_failure
from utilities.llm_client import get_global_tracker
from utilities.llm_pricing import format_cost, get_active_currency
from utilities.file_io import read_json, open_utf8


from utilities.finding_verdicts import is_testable_finding


def _print_execution_error_preview(error_type: str, error_msg: str, max_chars: int = 1600) -> None:
    """Print a truncated build/runtime log so users see failures during the run."""
    if not error_msg:
        return
    text = error_msg.strip()
    if len(text) > max_chars:
        text = "...(truncated)...\n" + text[-max_chars:]
    print(f"  --- {error_type} log (preview) ---", file=sys.stderr)
    for line in text.splitlines()[-35:]:
        print(f"    | {line}", file=sys.stderr)
    print("  --- end preview ---", file=sys.stderr)


def _result_from_checkpoint(finding_id: str, cp_data: dict) -> DynamicTestResult:
    """Rehydrate a DynamicTestResult from a checkpoint dictionary."""
    evidence = []
    for e in cp_data.get("evidence", []) or []:
        if isinstance(e, dict) and "type" in e and "content" in e:
            evidence.append(TestEvidence(type=e["type"], content=str(e["content"])))

    return DynamicTestResult(
        finding_id=finding_id,
        status=cp_data.get("status", "ERROR"),
        details=cp_data.get("details", ""),
        evidence=evidence,
        elapsed_seconds=cp_data.get("elapsed_seconds", 0),
        generation_cost_usd=cp_data.get("generation_cost_usd", 0),
        generation_input_tokens=cp_data.get("generation_input_tokens", 0),
        generation_output_tokens=cp_data.get("generation_output_tokens", 0),
        retry_count=cp_data.get("retry_count", 0),
        test_code=cp_data.get("test_code", ""),
        dockerfile=cp_data.get("dockerfile", ""),
        docker_compose=cp_data.get("docker_compose", ""),
    )


def run_dynamic_tests(
    pipeline_output_path: str,
    output_dir: str | None = None,
    max_retries: int = 3,
    checkpoint_path: str | None = None,
    repo_path: str | None = None,
    project_name: str | None = None,
    language: str | None = None,
) -> list[DynamicTestResult]:
    """Run dynamic tests for all findings in a pipeline output file.

    Args:
        pipeline_output_path: Path to pipeline_output.json
        output_dir: Directory for output files. Defaults to same directory
                    as pipeline_output_path.
        max_retries: Max retries per finding on error (default 3).
        checkpoint_path: Path to checkpoint directory for resume support.
        repo_path: Path to the repository root. When given, the vulnerable
            source file is pre-staged into the Docker build context so
            ``COPY <filename> .`` works on the first try.

    Returns:
        List of DynamicTestResult objects
    """
    # Load pipeline output
    pipeline = read_json(pipeline_output_path)
    all_findings = pipeline.get("findings", [])
    findings = [f for f in all_findings if is_testable_finding(f)]
    repo_info = {
        "name": pipeline.get("repository", {}).get("name", "unknown"),
        "language": pipeline.get("repository", {}).get("language", "Python"),
        "application_type": pipeline.get("application_type", "unknown"),
    }

    # Resolve/create output_dir before any early return — the empty-results
    # artifact must be writable even when there is nothing to test.
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(pipeline_output_path))
    os.makedirs(output_dir, exist_ok=True)

    if not all_findings:
        print("No findings to test.", file=sys.stderr)
        _write_results_json(output_dir, repo_info["name"], len(all_findings), results=[])
        return []
    if not findings:
        print("No testable findings to test.", file=sys.stderr)
        _write_results_json(output_dir, repo_info["name"], len(all_findings), results=[])
        return []

    # Set up checkpoint support
    checkpoint = None
    checkpointed = {}
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "dynamic_test_checkpoints")

    from core.checkpoint import StepCheckpoint
    checkpoint = StepCheckpoint("dynamic_test", output_dir)
    checkpoint.dir = checkpoint_path
    if checkpoint.exists:
        testable_ids = {
            f.get("id", f"FINDING-{i+1}") for i, f in enumerate(findings)
        }
        checkpointed = {
            fid: cp for fid, cp in checkpoint.load().items()
            if fid in testable_ids
        }

    # Count successful vs errored checkpoints. Errored ones are NOT "already
    # done" — they'll be retried with fresh test generation on resume.
    successful_ids = {fid for fid, cp in checkpointed.items()
                      if cp.get("status") != "ERROR"}
    errored_ids = {fid for fid in checkpointed.keys() if fid not in successful_ids}

    if successful_ids:
        print(f"Restored {len(successful_ids)} already-tested findings from checkpoints",
              file=sys.stderr, flush=True)
    if errored_ids:
        print(f"Retrying {len(errored_ids)} previously errored findings",
              file=sys.stderr, flush=True)

    # Use the global tracker so step_context captures dynamic-test cost in
    # dynamic-test.report.json (same as enhance/analyze/verify).
    tracker = get_global_tracker()

    # Inject prior usage from ALL existing checkpoints (both successful and
    # errored) so the report shows total cost across runs. The errored
    # entries will be retried — their initial attempt cost is preserved,
    # and the retry API calls get added on top.
    _prior_input = 0
    _prior_output = 0
    _prior_cost = 0.0
    for _cp in checkpointed.values():
        _prior_cost += _cp.get("generation_cost_usd", 0) or 0
        _prior_input += _cp.get("generation_input_tokens", 0) or 0
        _prior_output += _cp.get("generation_output_tokens", 0) or 0
    if _prior_cost > 0 or _prior_input > 0 or _prior_output > 0:
        tracker.add_prior_usage(_prior_input, _prior_output, _prior_cost)

    results: list[DynamicTestResult] = []
    tested_this_run: set[str] = set()
    exploit_registry = ProvenExploitRegistry()
    batch_run_id = uuid.uuid4().hex[:8]

    def _execute_generation(generation, finding_obj, finding_id, source_file, repo_info_local):
        return run_single_container(
            generation,
            finding_id,
            source_file=source_file,
            language=repo_info.get("language"),
            repo_path=repo_path,
            batch_run_id=batch_run_id,
            finding=finding_obj,
            repo_info=repo_info_local,
        )

    total = len(findings)
    restored = len(successful_ids)
    remaining = total - restored
    _completed = restored
    _errors = 0

    # Write initial summary so Go CLI can show accurate counts
    checkpoint.ensure_dir()
    checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")

    print(f"Dynamic testing {total} findings from {repo_info['name']} "
          f"({restored} already done, {remaining} remaining)",
          file=sys.stderr)

    try:
      for i, finding in enumerate(findings):
        finding_id = finding.get("id", f"FINDING-{i+1}")

        # Skip already-checkpointed findings, but ONLY if they succeeded.
        # Errored findings fall through to fresh test generation + Docker run,
        # so code/prompt fixes take effect on resume.
        cp_data = checkpointed.get(finding_id)
        if cp_data and cp_data.get("status") != "ERROR":
            result = _result_from_checkpoint(finding_id, cp_data)
            results.append(result)
            continue

        print(f"\n[{i+1}/{total}] Testing {finding_id}: "
              f"{finding.get('name', 'unknown')}...", file=sys.stderr)
        tested_this_run.add(finding_id)

        platform = resolve_native_test_source(finding, repo_path)
        if platform.blocked:
            print(f"  Blocked: {platform.blocked_reason}", file=sys.stderr)
            result = DynamicTestResult(
                finding_id=finding_id,
                status="BLOCKED",
                details=platform.blocked_reason,
            )
            results.append(result)
            if checkpoint:
                checkpoint.save(finding_id, result.to_dict())
                _completed += 1
                checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")
            continue

        repo_info_run = dict(repo_info)
        if platform.platform_notes:
            repo_info_run["platform_notes"] = platform.platform_notes
        if platform.harness_notes:
            repo_info_run["harness_notes"] = platform.harness_notes

        # Begin per-unit tracking so we can capture token counts for this
        # finding in addition to cost.
        tracker.start_unit_tracking()

        # Step 1: Generate test
        print("  Generating test...", file=sys.stderr)
        generation = generate_test(
            finding, repo_info_run, tracker, repo_path=repo_path,
            exploit_registry=exploit_registry,
        )
        unit_usage = tracker.get_unit_usage()
        generation_cost = unit_usage["cost_usd"]

        generation_retry_count = 0
        while generation is None and generation_retry_count < max_retries:
            generation_retry_count += 1
            print(
                f"  Test generation failed. Retry "
                f"{generation_retry_count}/{max_retries}...",
                file=sys.stderr,
            )
            generation = generate_test(
                finding, repo_info_run, tracker, repo_path=repo_path,
                exploit_registry=exploit_registry,
            )
            unit_usage = tracker.get_unit_usage()
            generation_cost = unit_usage["cost_usd"]

        if generation is None:
            print("  Test generation failed.", file=sys.stderr)
            result = collect_result(finding, None, None, generation_cost)
            result.retry_count = generation_retry_count
            result.generation_input_tokens = unit_usage["input_tokens"]
            result.generation_output_tokens = unit_usage["output_tokens"]
            results.append(result)
            if checkpoint:
                checkpoint.save(finding_id, result.to_dict())
                _completed += 1
                _errors += 1
                checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")
            continue

        print(f"  Generated ({format_cost(generation_cost)}). Running in Docker...",
              file=sys.stderr)

        # Resolve the vulnerable source file for pre-staging.
        source_file = platform.source_path
        if not source_file and repo_path:
            rel_path = finding.get("location", {}).get("file", "")
            if rel_path:
                candidate = resolve_repo_file(rel_path, repo_path)
                if candidate:
                    source_file = candidate

        # Step 2: Execute in Docker and retry on errors
        execution = _execute_generation(generation, finding, finding_id, source_file, repo_info_run)
        result = collect_result(finding, generation, execution, generation_cost)
        retry_count = generation_retry_count

        if result.status == "ERROR" and (
            execution.build_error
            or (execution.exit_code != 0 and execution.stderr)
            or result.details
        ):
            if execution.build_error:
                _print_execution_error_preview("Build", execution.build_error)
            elif execution.exit_code != 0 and execution.stderr:
                _print_execution_error_preview("Runtime", execution.stderr)
            elif result.details:
                _print_execution_error_preview("Application", result.details)

        if result.status == "ERROR" and execution and is_registry_pull_failure(execution.build_error):
            result = DynamicTestResult(
                finding_id=finding_id,
                status="BLOCKED",
                details=(
                    "Docker registry unreachable (auth.docker.io timeout). "
                    "Pre-pull base images with proxy or configure Docker daemon proxies, then retry."
                ),
                test_code=generation.get("test_script", "") if generation else "",
                dockerfile=generation.get("dockerfile", "") if generation else "",
                elapsed_seconds=execution.elapsed_seconds if execution else 0,
                generation_cost_usd=generation_cost,
                retry_count=retry_count,
            )
            results.append(result)
            if checkpoint:
                checkpoint.save(finding_id, result.to_dict())
                _completed += 1
                checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")
            print(f"  Result: BLOCKED (registry unreachable)", file=sys.stderr)
            continue

        while retry_count < max_retries and (
            result.status == "ERROR"
            or is_harness_failure_result(result, execution, generation)
        ):
            # Extract error message: build error > stderr > application-level details
            if execution.build_error:
                error_msg = execution.build_error
                error_type = "Build"
            elif execution.exit_code != 0 and execution.stderr:
                error_msg = execution.stderr
                error_type = "Runtime"
            else:
                error_msg = result.details
                error_type = "Application"

            if execution.timed_out:
                print(f"  Timed out — not retrying.", file=sys.stderr)
                break

            _print_execution_error_preview(error_type, error_msg)

            # Free local repair pass (struct typo, missing stdio.h, etc.)
            if error_type == "Build":
                local_fix = apply_local_compile_repairs(
                    generation,
                    finding,
                    repo_info_run,
                    repo_path=repo_path,
                    exploit_registry=exploit_registry,
                )
                if local_fix is not None:
                    print("  Applying local compile fixes...", file=sys.stderr)
                    generation = local_fix
                    execution = _execute_generation(generation, finding, finding_id, source_file, repo_info_run)
                    result = collect_result(finding, generation, execution, generation_cost)
                    if result.status != "ERROR" or not (
                        execution.build_error
                        or (execution.exit_code != 0 and execution.stderr)
                        or is_harness_failure_result(result, execution, generation)
                    ):
                        print(f"  Local compile fix succeeded: {result.status}",
                              file=sys.stderr)
                        break
                    if execution.build_error:
                        error_msg = execution.build_error
                        error_type = "Build"
                    elif execution.exit_code != 0 and execution.stderr:
                        error_msg = execution.stderr
                        error_type = "Runtime"
                    else:
                        error_msg = result.details
                        error_type = "Application"

            retry_count += 1
            repair_label = (
                "LLM compile repair" if error_type == "Build" else "LLM test repair"
            )
            print(f"  {error_type} error. Retry {retry_count}/{max_retries} "
                  f"with {repair_label}...", file=sys.stderr)

            retry_gen = None
            if error_type == "Build":
                retry_gen = repair_test_from_compile_errors(
                    finding,
                    repo_info_run,
                    generation,
                    error_msg,
                    tracker,
                    repo_path=repo_path,
                    exploit_registry=exploit_registry,
                )
            if retry_gen is None:
                print(f"  Falling back to full test regeneration...", file=sys.stderr)
                retry_gen = regenerate_test(
                    finding,
                    repo_info_run,
                    generation,
                    error_msg,
                    tracker,
                    repo_path=repo_path,
                    exploit_registry=exploit_registry,
                )
            # Refresh unit usage after retry (tracker accumulates across calls
            # on the same thread).
            unit_usage = tracker.get_unit_usage()
            generation_cost = unit_usage["cost_usd"]

            if retry_gen is None:
                print(f"  Retry generation failed.", file=sys.stderr)
                break

            generation = retry_gen
            execution = _execute_generation(generation, finding, finding_id, source_file, repo_info_run)
            result = collect_result(finding, generation, execution, generation_cost)
            print(f"  Retry {retry_count} result: {result.status} "
                  f"({format_cost(generation_cost)})", file=sys.stderr)

        result.retry_count = retry_count
        result.generation_input_tokens = unit_usage["input_tokens"]
        result.generation_output_tokens = unit_usage["output_tokens"]
        results.append(result)

        if result.status == "CONFIRMED" and generation:
            platform_reg = resolve_native_test_source(finding, repo_path)
            if platform_reg.source_basename:
                from utilities.dynamic_tester.native_symbols import (
                    extract_entry_symbol,
                    implementation_symbol,
                )
                exploit_registry.register(
                    finding_id,
                    platform_reg.source_basename,
                    implementation_symbol(extract_entry_symbol(finding)),
                    generation.get("test_script", ""),
                )

        # Save checkpoint and update summary after each finding
        if checkpoint:
            checkpoint.save(finding_id, result.to_dict())
            _completed += 1
            if result.status == "ERROR":
                _errors += 1
            checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")

        print(f"  Result: {result.status} ({result.elapsed_seconds:.1f}s)",
              file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[Dynamic Test] Interrupted — progress saved to checkpoints",
              file=sys.stderr, flush=True)
        prune_vulscan_test_artifacts(batch_run_id)
        return results

    # Generate report
    total_cost = tracker.total_cost_usd
    report_md = generate_report(results, repo_info["name"], total_cost)

    report_path = os.path.join(output_dir, "DYNAMIC_TEST_RESULTS.md")
    with open_utf8(report_path, "w") as f:
        f.write(report_md)
    print(f"\nReport written to {report_path}", file=sys.stderr)

    # Save structured results JSON
    results_path = _write_results_json(
        output_dir,
        repo_info["name"],
        len(all_findings),
        results=results,
        total_cost_usd=total_cost,
        findings=findings,
    )
    print(f"Results JSON written to {results_path}", file=sys.stderr)

    # Merged verdicts for report consumers live in dynamic_test_results.json
    # (written above, not covered by run_artifact_manifest.json). Do NOT
    # rewrite pipeline_output.json here: its sha256 is recorded in
    # run_artifact_manifest.json by write_final_scan_artifact, so any rewrite
    # breaks verify_run_manifest_before_report and bypasses
    # validate_final_scan_artifact.

    # LLM-generated Chinese verification explainers (one per tested finding).
    try:
        from core.reporter import generate_dynamic_disclosure_docs

        generate_dynamic_disclosure_docs(
            pipeline_output_path,
            output_dir,
            language=language or repo_info.get("language"),
            tested_finding_ids=tested_this_run,
        )
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print(f"  WARNING: dynamic disclosure generation failed: {exc}",
              file=sys.stderr)

    # Mark done. Checkpoints are preserved as a permanent artifact alongside
    # results — allows retroactive retry of errored findings after fixes.
    if checkpoint:
        checkpoint.write_summary(total, _completed, _errors, {}, phase="done")

    prune_vulscan_test_artifacts(batch_run_id)
    return results


def _write_results_json(
    output_dir: str,
    repo_name: str,
    total_findings: int,
    *,
    results: list[DynamicTestResult],
    total_cost_usd: float = 0.0,
    findings: list[dict] | None = None,
) -> str:
    """Write the dynamic test JSON artifact consistently."""
    from utilities.verdict_merge import merge_verdicts

    finding_by_id = {
        f.get("id"): f for f in (findings or []) if isinstance(f, dict) and f.get("id")
    }
    serialized = []
    for result in results:
        payload = result.to_dict()
        decision = merge_verdicts(
            finding_by_id.get(result.finding_id, {"id": result.finding_id}),
            payload,
        )
        payload["merged_verdict"] = decision
        payload["final_verdict"] = decision.get("verdict")
        payload["evidence_status"] = decision.get("evidence_status")
        serialized.append(payload)

    results_path = os.path.join(output_dir, "dynamic_test_results.json")
    with open_utf8(results_path, "w") as f:
        json.dump({
            "repository": repo_name,
            "total_findings": total_findings,
            "findings_tested": len(results),
            "total_cost_usd": round(total_cost_usd, 6),
            "cost_currency": get_active_currency(),
            "results": serialized,
        }, f, indent=2, ensure_ascii=False)
    return results_path
