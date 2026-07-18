"""
All-in-one scanner orchestrator.

Runs the fixed production pipeline:

    parse → app_context → reachability → enhance → detect → verify
        → build pipeline_output → dynamic_verify → report

``scan_repository`` accepts a single immutable ``ScanRequest``. The CLI must
fully construct that request (including ``run_id``) before invocation. Stages
read the request; they never mutate it or fill defaults.

Artifacts for each run are written to::

    {request.config.output_dir}/runs/{request.run_id}/
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from core.pipeline_config import (
    FIXED_PIPELINE,
    ScanRequest,
    ensure_run_dir,
    write_scan_manifest,
)
from core.schemas import (
    ScanResult, AnalysisMetrics, StepReport,
)
from core.step_report import step_context
from core import tracking
from utilities.file_io import read_json, write_json
from utilities.llm_config import format_active_llm_label
from utilities.llm_pricing import format_cost, resolve_display_currency
from utilities.model_registry import ModelRole, model_for

# Rate-limit backoff is an operational constant (not part of ScanRequest).
_DEFAULT_BACKOFF_SECONDS = 30

# Import app context generator (optional)
try:
    from context.application_context import (
        generate_application_context,
        save_context,
    )
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False


def scan_repository(request: ScanRequest) -> ScanResult:
    """Scan a repository for vulnerabilities using a complete ScanRequest.

    The request must already include a unique ``run_id``. Results are written
    under ``{output_root}/runs/{run_id}/``. Stages never modify the request.
    """
    if not isinstance(request, ScanRequest):
        raise TypeError(
            f"scan_repository() accepts only ScanRequest, got {type(request).__name__}"
        )

    cfg = request.config
    run_dir = ensure_run_dir(request.output_root, request.run_id)
    write_scan_manifest(request)

    tracking.reset_tracking()

    result = ScanResult(
        output_dir=run_dir,
        run_id=request.run_id,
        output_root=request.output_root,
    )
    collected_step_reports: list[dict] = []

    total_steps = _count_steps(
        cfg.app_context, cfg.enhance, cfg.verify,
        request.generate_report, cfg.dynamic_verify,
    )
    step_num = 0

    def _step_label(name: str) -> str:
        nonlocal step_num
        step_num += 1
        return f"[{step_num}/{total_steps}] {name}"

    _print_banner(request, run_dir)

    # ---------------------------------------------------------------
    # Step 1: Parse (always extract all units; scope applied later)
    # ---------------------------------------------------------------
    from core.parser_adapter import parse_repository

    print(_step_label("Parsing repository..."), file=sys.stderr)

    with step_context("parse", run_dir, inputs={
        "repo_path": request.repo_path,
        "language": cfg.language,
        "scope": "all",
        "skip_tests": request.skip_tests,
    }) as ctx:
        parse_result = parse_repository(
            repo_path=request.repo_path,
            output_dir=run_dir,
            language=cfg.language,
            scope="all",
            skip_tests=request.skip_tests,
            diff_manifest=request.diff_manifest,
        )

        ctx.summary = {
            "total_units": parse_result.units_count,
            "language": parse_result.language,
            "scope": parse_result.scope,
        }
        _diff_report = os.path.join(run_dir, "diff_filter.report.json")
        if os.path.exists(_diff_report):
            try:
                ctx.summary["diff_stats"] = read_json(_diff_report)
            except (json.JSONDecodeError, OSError):
                pass
        ctx.outputs = {
            "dataset_path": parse_result.dataset_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
        }

    result.dataset_path = parse_result.dataset_path
    result.analyzer_output_path = parse_result.analyzer_output_path
    result.units_count = parse_result.units_count
    result.language = parse_result.language
    collected_step_reports.append(_load_step_report(run_dir, "parse"))

    print(f"  Parsed: {parse_result.units_count} units ({parse_result.language})",
          file=sys.stderr)
    print(file=sys.stderr)

    active_dataset_path = parse_result.dataset_path

    # ---------------------------------------------------------------
    # Step 2: Application Context
    # ---------------------------------------------------------------
    app_context_path: str | None = None
    if cfg.app_context and HAS_APP_CONTEXT:
        print(_step_label("Generating application context..."), file=sys.stderr)

        with step_context("app-context", run_dir, inputs={
            "repo_path": request.repo_path,
        }) as ctx:
            try:
                from context.application_context import (
                    STATUS_UNAVAILABLE,
                    ApplicationContext,
                )

                context = generate_application_context(
                    Path(request.repo_path),
                    dataset_path=parse_result.dataset_path,
                    analyzer_output_path=parse_result.analyzer_output_path,
                    parse_artifacts_dir=run_dir,
                )
                # Never fabricate a default application type on failure.
                if context.status == STATUS_UNAVAILABLE:
                    print(
                        f"  App context unavailable: "
                        f"{(context.provenance or {}).get('error', 'unknown')}",
                        file=sys.stderr,
                    )
                    print("  Continuing pipeline with status=unavailable.", file=sys.stderr)
                app_context_path = os.path.join(run_dir, "application_context.json")
                save_context(context, Path(app_context_path))
                result.app_context_path = app_context_path
                ctx.summary = {
                    "status": context.status,
                    "purpose": context.purpose,
                }
                ctx.outputs = {"app_context_path": app_context_path}
                print(f"  App context status: {context.status}", file=sys.stderr)
            except Exception as e:
                from context.application_context import ApplicationContext
                from utilities.credentials import safe_exception_message

                safe_msg = safe_exception_message(e)
                print(
                    f"  WARNING: App context generation failed: {safe_msg}",
                    file=sys.stderr,
                )
                print("  Continuing with status=unavailable.", file=sys.stderr)
                context = ApplicationContext.unavailable(safe_msg)
                app_context_path = os.path.join(run_dir, "application_context.json")
                save_context(context, Path(app_context_path))
                result.app_context_path = app_context_path
                ctx.summary = {"status": "unavailable", "reason": safe_msg}
                ctx.outputs = {"app_context_path": app_context_path}

        collected_step_reports.append(_load_step_report(run_dir, "app-context"))
    elif cfg.app_context:
        print(_step_label("Skipping application context (module not available)."),
              file=sys.stderr)
        result.skipped_steps.append("app-context")
    else:
        print(_step_label("Skipping application context (--no-context)."),
              file=sys.stderr)
        result.skipped_steps.append("app-context")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 3: Reachability (scope filter)
    # ---------------------------------------------------------------
    if cfg.scope == "reachable":
        from core.parser_adapter import apply_reachability_filter

        print(_step_label("Applying reachability filter..."), file=sys.stderr)

        with step_context("reachability", run_dir, inputs={
            "dataset_path": active_dataset_path,
            "scope": cfg.scope,
        }) as ctx:
            dataset = read_json(active_dataset_path)
            pre_count = len(dataset.get("units", []))
            dataset = apply_reachability_filter(
                dataset,
                run_dir,
                "reachable",
            )
            post_count = len(dataset.get("units", []))
            write_json(active_dataset_path, dataset, indent=2)
            result.units_count = post_count
            parse_result.units_count = post_count

            rf = (dataset.get("metadata") or {}).get("reachability_filter") or {}
            ctx.summary = {
                "scope": cfg.scope,
                "units_before": pre_count,
                "units_after": post_count,
                "reachable": rf.get("reachable_units"),
                "unreachable": rf.get("unreachable_units"),
                "unknown_reachability": rf.get("unknown_units"),
            }
            ctx.outputs = {"dataset_path": active_dataset_path}

            # Persist three-state reachability into metrics (never invent totals).
            result.metrics = AnalysisMetrics(
                total_units=int(rf.get("original_units") or pre_count),
                reachable=int(rf.get("reachable_units") or 0),
                unreachable=int(rf.get("unreachable_units") or 0),
                unknown_reachability=int(rf.get("unknown_units") or 0),
            )

        collected_step_reports.append(_load_step_report(run_dir, "reachability"))
        print(f"  Reachable units: {result.units_count}", file=sys.stderr)
    else:
        print(_step_label("Skipping reachability filter (scope=all)."), file=sys.stderr)
        result.skipped_steps.append("reachability")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 4: Enhance
    # ---------------------------------------------------------------
    if cfg.enhance:
        from core.enhancer import enhance_dataset

        print(_step_label("Enhancing dataset..."), file=sys.stderr)

        enhanced_path = os.path.join(run_dir, "dataset_enhanced.json")

        with step_context("enhance", run_dir, inputs={
            "dataset_path": active_dataset_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
            "repo_path": request.repo_path,
            "mode": request.enhance_mode,
        }) as ctx:
            enhance_result = enhance_dataset(
                dataset_path=active_dataset_path,
                output_path=enhanced_path,
                analyzer_output_path=parse_result.analyzer_output_path,
                repo_path=request.repo_path,
                mode=request.enhance_mode,
                workers=cfg.workers,
                backoff_seconds=_DEFAULT_BACKOFF_SECONDS,
                call_graph_path=os.path.join(run_dir, "call_graph.json"),
                app_context_path=app_context_path,
            )

            ctx.summary = {
                "units_enhanced": enhance_result.units_enhanced,
                "error_count": enhance_result.error_count,
                "mode": request.enhance_mode,
            }
            if enhance_result.error_summary:
                ctx.summary["error_summary"] = enhance_result.error_summary
            ctx.outputs = {
                "enhanced_dataset_path": enhance_result.enhanced_dataset_path,
            }

        result.enhanced_dataset_path = enhance_result.enhanced_dataset_path
        active_dataset_path = enhance_result.enhanced_dataset_path
        collected_step_reports.append(_load_step_report(run_dir, "enhance"))

        print(f"  Enhanced: {enhance_result.units_enhanced} units", file=sys.stderr)
        if enhance_result.error_summary:
            print(f"  Errors: {enhance_result.error_count} ({enhance_result.error_summary})", file=sys.stderr)
    else:
        print(_step_label("Skipping enhancement (--no-enhance)."), file=sys.stderr)
        result.skipped_steps.append("enhance")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 5: Detect (Stage 1)
    # ---------------------------------------------------------------
    from core.analyzer import run_analysis

    print(_step_label("Running vulnerability detection (Stage 1)..."), file=sys.stderr)

    with step_context("analyze", run_dir, inputs={
        "dataset_path": active_dataset_path,
        "model": request.model,
        "limit": request.limit,
    }) as ctx:
        analyze_result = run_analysis(
            dataset_path=active_dataset_path,
            output_dir=run_dir,
            analyzer_output_path=parse_result.analyzer_output_path,
            app_context_path=app_context_path,
            repo_path=request.repo_path,
            limit=request.limit,
            model=request.model,
            workers=cfg.workers,
            backoff_seconds=_DEFAULT_BACKOFF_SECONDS,
            call_graph_path=os.path.join(run_dir, "call_graph.json"),
        )

        ctx.summary = {
            "total_units": analyze_result.metrics.total_units,
            "analyzed": (
                analyze_result.metrics.total_units
                - analyze_result.metrics.stage1_errors
            ),
            "stage1": {
                "candidates": analyze_result.metrics.stage1_candidates,
                "no_finding": analyze_result.metrics.stage1_no_finding,
                "inconclusive": analyze_result.metrics.stage1_inconclusive,
                "errors": analyze_result.metrics.stage1_errors,
            },
        }
        ctx.outputs = {"results_path": analyze_result.results_path}

    result.results_path = analyze_result.results_path
    # Merge Stage 1 metrics while preserving reachability three-state counts.
    am = analyze_result.metrics
    result.metrics = AnalysisMetrics(
        total_units=am.total_units or result.metrics.total_units,
        reachable=result.metrics.reachable,
        unreachable=result.metrics.unreachable,
        unknown_reachability=result.metrics.unknown_reachability,
        stage1_candidates=am.stage1_candidates,
        stage1_no_finding=am.stage1_no_finding,
        stage1_inconclusive=am.stage1_inconclusive,
        stage1_errors=am.stage1_errors,
    )
    collected_step_reports.append(_load_step_report(run_dir, "analyze"))
    print(file=sys.stderr)

    active_results_path = analyze_result.results_path
    verified_unit_ids_for_report = None

    # ---------------------------------------------------------------
    # Step 6: Verify (Stage 2)
    # ---------------------------------------------------------------
    has_findings = analyze_result.metrics.stage1_candidates > 0

    if cfg.verify and has_findings:
        from core.verifier import run_verification

        print(_step_label("Running verification (Stage 2)..."), file=sys.stderr)

        with step_context("verify", run_dir, inputs={
            "results_path": analyze_result.results_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
        }) as ctx:
            verify_result = run_verification(
                results_path=analyze_result.results_path,
                output_dir=run_dir,
                analyzer_output_path=parse_result.analyzer_output_path,
                app_context_path=app_context_path,
                repo_path=request.repo_path,
                workers=cfg.workers,
                backoff_seconds=_DEFAULT_BACKOFF_SECONDS,
                dataset_path=active_dataset_path,
                call_graph_path=os.path.join(run_dir, "call_graph.json"),
            )

            ctx.summary = {
                "candidates_input": verify_result.candidates_input,
                "attempted": verify_result.attempted,
                "succeeded": verify_result.succeeded,
                "failed": verify_result.failed,
                "skipped": verify_result.skipped,
                "confirmed": verify_result.confirmed,
                "rejected": verify_result.rejected,
                "inconclusive": verify_result.inconclusive,
            }
            ctx.outputs = {
                "verified_results_path": verify_result.verified_results_path,
            }

        result.verified_results_path = verify_result.verified_results_path
        active_results_path = verify_result.verified_results_path
        verified_unit_ids_for_report = verify_result.verified_unit_ids
        collected_step_reports.append(_load_step_report(run_dir, "verify"))

        print(
            f"  Stage 2: confirmed={verify_result.confirmed} "
            f"rejected={verify_result.rejected} "
            f"inconclusive={verify_result.inconclusive} "
            f"failed={verify_result.failed} skipped={verify_result.skipped}",
            file=sys.stderr,
        )

        result.metrics = AnalysisMetrics(
            total_units=analyze_result.metrics.total_units,
            reachable=analyze_result.metrics.reachable,
            unreachable=analyze_result.metrics.unreachable,
            unknown_reachability=analyze_result.metrics.unknown_reachability,
            stage1_candidates=analyze_result.metrics.stage1_candidates,
            stage1_no_finding=analyze_result.metrics.stage1_no_finding,
            stage1_inconclusive=analyze_result.metrics.stage1_inconclusive,
            stage1_errors=analyze_result.metrics.stage1_errors,
            stage2_confirmed=verify_result.confirmed,
            stage2_rejected=verify_result.rejected,
            stage2_inconclusive=verify_result.inconclusive,
            stage2_failed=verify_result.failed,
        )
    elif cfg.verify and not has_findings:
        print(_step_label("Skipping verification (no Stage 1 candidates)."),
              file=sys.stderr)
        result.skipped_steps.append("verify")
    else:
        print(_step_label("Skipping verification (--no-verify)."),
              file=sys.stderr)
        result.skipped_steps.append("verify")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 7: Dynamic Verify (opt-in) — before FinalScanArtifact
    # ---------------------------------------------------------------
    # Preserve reachability from earlier metrics when updating stage counters.
    def _metrics_with_reachability(**kwargs) -> AnalysisMetrics:
        return AnalysisMetrics(
            total_units=result.metrics.total_units,
            reachable=result.metrics.reachable,
            unreachable=result.metrics.unreachable,
            unknown_reachability=result.metrics.unknown_reachability,
            stage1_candidates=result.metrics.stage1_candidates,
            stage1_no_finding=result.metrics.stage1_no_finding,
            stage1_inconclusive=result.metrics.stage1_inconclusive,
            stage1_errors=result.metrics.stage1_errors,
            stage2_confirmed=result.metrics.stage2_confirmed,
            stage2_rejected=result.metrics.stage2_rejected,
            stage2_inconclusive=result.metrics.stage2_inconclusive,
            stage2_failed=result.metrics.stage2_failed,
            **kwargs,
        )

    if cfg.dynamic_verify and has_findings:
        if not shutil.which("docker"):
            print(_step_label("Skipping dynamic verify (Docker not found)."),
                  file=sys.stderr)
            result.skipped_steps.append("dynamic-verify")
        else:
            from core.dynamic_tester import run_tests

            print(_step_label("Running dynamic verify (Docker)..."), file=sys.stderr)

            with step_context("dynamic-test", run_dir, inputs={
                "results_path": active_results_path,
            }) as ctx:
                dt_result = run_tests(
                    results_path=active_results_path,
                    output_dir=run_dir,
                    repo_path=request.repo_path,
                    project_name=request.repo_name,
                    language=result.language,
                    dataset_path=active_dataset_path,
                )

                ctx.summary = {
                    "candidates_input": dt_result.candidates_input,
                    "attempted": dt_result.attempted,
                    "succeeded": dt_result.succeeded,
                    "failed": dt_result.failed,
                    "blocked": dt_result.blocked,
                    "skipped": dt_result.skipped,
                    "reproduced": dt_result.reproduced,
                    "not_reproduced": dt_result.not_reproduced,
                    "inconclusive": dt_result.inconclusive,
                }
                ctx.outputs = {
                    "results_json_path": dt_result.results_json_path,
                    "results_md_path": dt_result.results_md_path,
                }

            result.dynamic_test_path = dt_result.results_json_path
            result.metrics = _metrics_with_reachability(
                dynamic_reproduced=dt_result.reproduced,
                dynamic_not_reproduced=dt_result.not_reproduced,
                dynamic_inconclusive=dt_result.inconclusive,
                dynamic_failed=dt_result.failed,
                dynamic_blocked=dt_result.blocked,
                dynamic_skipped=dt_result.skipped,
            )
            collected_step_reports.append(
                _load_step_report(run_dir, "dynamic-test"),
            )

            print(
                f"  Dynamic verify: reproduced={dt_result.reproduced} "
                f"not_reproduced={dt_result.not_reproduced} "
                f"blocked={dt_result.blocked}",
                file=sys.stderr,
            )
            if dt_result.blocked or dt_result.failed:
                if result.status == "completed":
                    result.status = "partial"
                if dt_result.blocked:
                    result.warnings.append(
                        f"dynamic verification blocked for {dt_result.blocked} unit(s)"
                    )
                if dt_result.failed:
                    result.warnings.append(
                        f"dynamic verification failed for {dt_result.failed} unit(s)"
                    )
    elif cfg.dynamic_verify and not has_findings:
        print(_step_label("Skipping dynamic verify (no findings to test)."),
              file=sys.stderr)
        result.skipped_steps.append("dynamic-verify")
    else:
        print(_step_label("Skipping dynamic verify (not enabled)."), file=sys.stderr)
        result.skipped_steps.append("dynamic-verify")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 8: FinalScanArtifact reducer + validation (once)
    # ---------------------------------------------------------------
    from core.reporter import build_pipeline_output
    from core.final_artifact.finalize import verify_run_manifest_before_report

    print(_step_label("Building FinalScanArtifact..."), file=sys.stderr)

    pipeline_output_path = os.path.join(run_dir, "pipeline_output.json")
    finalize_errors: list[str] = []

    with step_context("finalize", run_dir, inputs={
        "results_path": active_results_path,
        "dynamic_test_path": result.dynamic_test_path,
    }) as ctx:
        _path, _count, finalize_errors = build_pipeline_output(
            results_path=active_results_path,
            output_path=pipeline_output_path,
            repo_name=request.repo_name or os.path.basename(request.repo_path),
            repo_url=request.repo_url,
            commit_sha=request.commit_sha,
            language=result.language,
            processing_level=cfg.scope,
            step_reports=collected_step_reports,
            repo_path=request.repo_path,
        )
        ctx.outputs = {
            "pipeline_output_path": pipeline_output_path,
            "run_artifact_manifest": os.path.join(run_dir, "run_artifact_manifest.json"),
        }
        if finalize_errors:
            ctx.status = "partial"
            ctx.errors.extend(finalize_errors)

    collected_step_reports.append(_load_step_report(run_dir, "finalize"))

    # Sync metrics from FinalScanArtifact when valid; otherwise clear stale path.
    if finalize_errors:
        result.errors.extend(list(finalize_errors))
        if os.path.isfile(pipeline_output_path):
            try:
                os.remove(pipeline_output_path)
            except OSError:
                pass
        result.pipeline_output_path = None
        result.status = "failed"
    elif os.path.isfile(pipeline_output_path):
        result.pipeline_output_path = pipeline_output_path
        try:
            artifact = read_json(pipeline_output_path)
            m = artifact.get("metrics") or {}
            result.metrics = AnalysisMetrics(
                **{
                    k: m.get(k, getattr(result.metrics, k, 0))
                    for k in AnalysisMetrics.__dataclass_fields__
                }
            )
            if (artifact.get("stage_status") or {}).get("reachability") == "partial":
                result.status = "partial"
                result.warnings.append(
                    "reachability artifact missing; counts not invented"
                )
            for w in (artifact.get("provenance") or {}).get("warnings") or []:
                result.warnings.append(str(w))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            result.status = "failed"
            result.errors.append(f"FinalScanArtifact unreadable: {exc}")
            result.pipeline_output_path = None
    else:
        result.status = "failed"
        result.errors.append("FinalScanArtifact was not written")
        result.pipeline_output_path = None

    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 9: Report (only if FinalScanArtifact validated)
    # ---------------------------------------------------------------
    if request.generate_report:
        if finalize_errors:
            print(
                _step_label(
                    "Skipping report generation (FinalScanArtifact validation failed)."
                ),
                file=sys.stderr,
            )
            result.skipped_steps.append("report")
        else:
            manifest_errs = verify_run_manifest_before_report(run_dir)
            if manifest_errs:
                print(
                    _step_label(
                        "Skipping report generation (run manifest verification failed)."
                    ),
                    file=sys.stderr,
                )
                for err in manifest_errs:
                    print(f"  - {err}", file=sys.stderr)
                result.skipped_steps.append("report")
            else:
                from core.reporter import (
                    generate_summary_report,
                    generate_disclosure_docs,
                )
                from core.final_artifact.finalize import (
                    append_report_tree_to_run_manifest,
                )

                print(_step_label("Generating reports..."), file=sys.stderr)

                with step_context("report", run_dir, inputs={
                    "pipeline_output_path": pipeline_output_path,
                }) as ctx:
                    report_dir = os.path.join(run_dir, "report")
                    os.makedirs(report_dir, exist_ok=True)

                    summary_path = os.path.join(report_dir, "SUMMARY_REPORT.md")
                    disclosures_dir = os.path.join(report_dir, "disclosures")

                    outputs = {}

                    try:
                        generate_summary_report(
                            pipeline_output_path,
                            summary_path,
                            verified_unit_ids=verified_unit_ids_for_report,
                        )
                        result.summary_path = summary_path
                        outputs["summary_path"] = summary_path
                        print(f"  Summary: {summary_path}", file=sys.stderr)
                    except Exception as e:
                        print(f"  WARNING: Summary report failed: {e}", file=sys.stderr)
                        ctx.errors.append(f"Summary report: {e}")
                        result.warnings.append(f"Summary report: {e}")
                        if result.status == "completed":
                            result.status = "partial"

                    if has_findings:
                        try:
                            generate_disclosure_docs(
                                pipeline_output_path,
                                disclosures_dir,
                                verified_unit_ids=verified_unit_ids_for_report,
                            )
                            outputs["disclosures_dir"] = disclosures_dir
                            print(f"  Disclosures: {disclosures_dir}", file=sys.stderr)
                        except Exception as e:
                            print(
                                f"  WARNING: Disclosure docs failed: {e}",
                                file=sys.stderr,
                            )
                            ctx.errors.append(f"Disclosure docs: {e}")
                            result.warnings.append(f"Disclosure docs: {e}")
                            if result.status == "completed":
                                result.status = "partial"

                    # Register MD/HTML/CSV and every disclosure under report/.
                    append_report_tree_to_run_manifest(run_dir, report_dir)

                    ctx.summary = {"formats_generated": list(outputs.keys())}
                    ctx.outputs = outputs

                collected_step_reports.append(_load_step_report(run_dir, "report"))
    else:
        print(_step_label("Skipping report generation (--no-report)."), file=sys.stderr)
        result.skipped_steps.append("report")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Final: Aggregate scan report
    # ---------------------------------------------------------------
    result.usage = tracking.get_usage()
    result.step_reports = collected_step_reports

    _write_scan_report(run_dir, result, collected_step_reports)
    _print_summary(result)

    _export_scan_results(
        output_dir=run_dir,
        project_name=request.repo_name,
        language=result.language,
        dynamic_ran=cfg.dynamic_verify and "dynamic-verify" not in result.skipped_steps,
        report_ran=request.generate_report and "report" not in result.skipped_steps,
    )

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _count_steps(
    app_context: bool,
    enhance: bool,
    verify: bool,
    generate_report: bool,
    dynamic_verify: bool,
) -> int:
    """Count visible progress lines for the fixed pipeline stages.

    Every stage prints exactly one numbered label per run — either its action
    or a "Skipping ..." line (including runtime-conditional skips such as
    "no Stage 1 candidates" or "Docker not found") — so the denominator is
    always the full stage count: FIXED_PIPELINE + build-artifact + report.
    """
    _ = (app_context, enhance, verify, generate_report, dynamic_verify)
    return len(FIXED_PIPELINE) + 2


def _load_step_report(output_dir: str, step: str) -> dict:
    """Load a step report JSON from disk. Returns empty dict on failure."""
    path = os.path.join(output_dir, f"{step}.report.json")
    try:
        return read_json(path)
    except Exception:
        return {"step": step, "status": "unknown"}


def _read_app_context_label(app_context_path: str | None) -> str:
    """Return a neutral label for pipeline_output (never fabricates web_app)."""
    if not app_context_path:
        return "unavailable"
    try:
        data = read_json(app_context_path)
    except Exception:
        return "unavailable"
    status = data.get("status") or "unavailable"
    if status != "ok":
        return "unavailable"
    purpose = (data.get("purpose") or "").strip()
    if purpose:
        return purpose[:120]
    return "ok"


def _write_scan_report(
    output_dir: str,
    result: ScanResult,
    step_reports: list[dict],
) -> str:
    """Write ``scan.report.json`` — the aggregate report for the full pipeline."""
    total_cost = sum(sr.get("cost_usd", 0) for sr in step_reports)
    total_duration = sum(sr.get("duration_seconds", 0) for sr in step_reports)
    total_input = sum(
        sr.get("token_usage", {}).get("input_tokens", 0) for sr in step_reports
    )
    total_output = sum(
        sr.get("token_usage", {}).get("output_tokens", 0) for sr in step_reports
    )

    scan_report = StepReport(
        step="scan",
        summary={
            "units_count": result.units_count,
            "language": result.language,
            "run_id": result.run_id,
            "metrics": result.metrics.to_dict(),
            "steps_completed": [sr.get("step") for sr in step_reports],
            "steps_skipped": result.skipped_steps,
        },
        inputs={"repo_path": result.output_dir.replace(os.path.abspath("."), ".")},
        outputs={
            "dataset_path": result.dataset_path,
            "enhanced_dataset_path": result.enhanced_dataset_path,
            "results_path": result.results_path,
            "verified_results_path": result.verified_results_path,
            "pipeline_output_path": result.pipeline_output_path,
            "summary_path": result.summary_path,
            "dynamic_test_path": result.dynamic_test_path,
        },
        cost_usd=round(total_cost, 6),
        cost_currency=resolve_display_currency(),
        duration_seconds=round(total_duration, 2),
        token_usage={
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_tokens": total_input + total_output,
        },
    )

    path = scan_report.write(output_dir)
    print(f"[Scan] Aggregate report: {path}", file=sys.stderr)
    return path


def _export_scan_results(
    output_dir: str,
    project_name: str | None,
    language: str | None,
    dynamic_ran: bool,
    report_ran: bool,
) -> None:
    """Copy human-facing and key JSON artifacts to 911VulScan_Scan_Results/."""
    if not project_name:
        return
    try:
        from utilities.scan_results_export import (
            export_dynamic_results,
            export_static_results,
            project_results_dir,
        )

        export_static_results(output_dir, project_name, language=language)
        if dynamic_ran:
            export_dynamic_results(output_dir, project_name, language=language)

        print(
            f"[911VulScan] Results tree: {project_results_dir(project_name, language)}",
            file=sys.stderr,
        )
    except Exception as exc:
        print(f"[911VulScan] WARNING: failed to export scan results: {exc}", file=sys.stderr)


def _print_banner(request: ScanRequest, run_dir: str) -> None:
    """Print the scan configuration banner (must match scan_manifest.json)."""
    cfg = request.config
    print("=" * 60, file=sys.stderr)
    print("911VULSCAN SCAN", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Repository:    {request.repo_path}", file=sys.stderr)
    print(f"  Output root:   {request.output_root}", file=sys.stderr)
    print(f"  Run ID:        {request.run_id}", file=sys.stderr)
    print(f"  Run dir:       {run_dir}", file=sys.stderr)
    print(f"  Language:      {cfg.language}", file=sys.stderr)
    print(f"  Scope:         {cfg.scope}", file=sys.stderr)
    print(f"  Enhance:       {cfg.enhance} ({request.enhance_mode})", file=sys.stderr)
    print(f"  Verify (S2):   {cfg.verify}", file=sys.stderr)
    print(f"  App context:   {cfg.app_context}", file=sys.stderr)
    print(f"  Report:        {request.generate_report}", file=sys.stderr)
    print(f"  Dynamic verify:{cfg.dynamic_verify}", file=sys.stderr)
    workers_label = f"{cfg.workers} (parallel)" if cfg.workers > 1 else "1 (sequential)"
    print(f"  Workers:       {workers_label}", file=sys.stderr)
    print(f"  Model:         {request.model}", file=sys.stderr)
    print(f"  Config hash:   {request.config_hash()[:16]}…", file=sys.stderr)
    try:
        print(f"  LLM:           {format_active_llm_label(model_for(ModelRole.PRIMARY))}", file=sys.stderr)
    except ValueError:
        pass
    print("=" * 60, file=sys.stderr)
    print(file=sys.stderr)


def _print_summary(result: ScanResult) -> None:
    """Print the final scan summary."""
    print("=" * 60, file=sys.stderr)
    print("SCAN COMPLETE", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    if result.run_id:
        print(f"  Run ID:         {result.run_id}", file=sys.stderr)
    print(f"  Units analyzed: {result.metrics.total_units}", file=sys.stderr)
    print(f"  Stage 1 candidates: {result.metrics.stage1_candidates}", file=sys.stderr)
    print(f"  Stage 2 confirmed:  {result.metrics.stage2_confirmed}", file=sys.stderr)
    print(f"  Stage 2 rejected:   {result.metrics.stage2_rejected}", file=sys.stderr)
    print(
        f"  Inconclusive:       "
        f"{result.metrics.stage1_inconclusive + result.metrics.stage2_inconclusive}",
        file=sys.stderr,
    )
    print(
        f"  Errors:             "
        f"{result.metrics.stage1_errors + result.metrics.stage2_failed}",
        file=sys.stderr,
    )
    if result.metrics.dynamic_reproduced:
        print(
            f"  Dynamic reproduced: {result.metrics.dynamic_reproduced}",
            file=sys.stderr,
        )
    print(f"  Cost:           {format_cost(result.usage.total_cost_usd, result.usage.cost_currency)}", file=sys.stderr)
    print(f"  Output:         {result.output_dir}", file=sys.stderr)
    if result.skipped_steps:
        print(f"  Skipped:        {', '.join(result.skipped_steps)}", file=sys.stderr)
    if result.usage.total_input_tokens == 0 and (
        result.metrics.stage1_errors + result.metrics.stage2_failed
    ) > 0:
        print("", file=sys.stderr)
        print("  *** No API calls succeeded — repository was NOT analyzed. ***", file=sys.stderr)
        print("  *** Check your API key: vulscan set-api-key                 ***", file=sys.stderr)
        print("  ***   or: echo \"$ANTHROPIC_API_KEY\" | vulscan set-api-key --stdin ***", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
