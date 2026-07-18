#!/usr/bin/env python3
"""
911VulScan CLI — Unified command-line interface for vulnerability analysis.

Commands:
    vulscan scan /path/to/repo --output /tmp/results
    vulscan parse /path/to/repo --output /tmp/results
    vulscan enhance dataset.json --analyzer-output ao.json --repo-path /repo -o enhanced.json
    vulscan analyze dataset.json --output /tmp/results
    vulscan verify results.json --analyzer-output ao.json --output /tmp/results
    vulscan build-output results.json -o pipeline_output.json
    vulscan dynamic-test pipeline_output.json -o /tmp/dt/
    vulscan report results.json --format html --output report.html

All commands output JSON to stdout and logs to stderr.
Exit codes: 0 = success (default even when findings exist), 1 = --fail-on matched, 2 = error.
"""

import argparse
import json
import os
import sys
import tempfile

from utilities.file_io import read_json
from utilities.credentials import safe_exception_message
from core.final_artifact.validate import exit_code_for_fail_on


def _output_json(data: dict):
    """Write JSON to stdout."""
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _load_step_reports(directory: str) -> list[dict]:
    """Load all {step}.report.json files from a directory.

    Used by standalone commands (build-output, report) to feed
    cost/duration data into pipeline_output.json.
    """
    import glob
    reports = []
    for path in glob.glob(os.path.join(directory, "*.report.json")):
        try:
            reports.append(read_json(path))
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def build_scan_request(args) -> "ScanRequest":
    """Fully construct an immutable ScanRequest from CLI args (no deferred defaults)."""
    from core.pipeline_config import (
        PipelineConfig,
        ScanRequest,
        ensure_run_dir,
        generate_run_id,
    )

    output_root = os.path.abspath(args.output or tempfile.mkdtemp(prefix="911vulscan_"))
    run_id = getattr(args, "run_id", None) or generate_run_id()
    ensure_run_dir(output_root, run_id)

    config = PipelineConfig(
        language=args.language or "auto",
        scope=args.scope,
        app_context=not args.no_context,
        enhance=not args.no_enhance,
        verify=not args.no_verify,
        dynamic_verify=bool(args.dynamic_verify),
        workers=args.workers,
        output_dir=output_root,
    )
    return ScanRequest(
        repo_path=os.path.abspath(args.repo),
        config=config,
        model=args.model,
        enhance_mode=args.enhance_mode,
        skip_tests=not args.no_skip_tests,
        limit=args.limit,
        generate_report=not args.no_report,
        repo_name=getattr(args, "repo_name", None),
        repo_url=getattr(args, "repo_url", None),
        commit_sha=getattr(args, "commit_sha", None),
        diff_manifest=getattr(args, "diff_manifest", None),
        run_id=run_id,
    )


def cmd_scan(args):
    """Scan a repository end-to-end."""
    from core.scanner import scan_repository
    from core.schemas import error, make_envelope

    try:
        request = build_scan_request(args)
        result = scan_repository(request)

        scan_payload = result.to_dict()
        # Surface the diff block on the envelope so the Go CLI banner can
        # render an "Incremental: base..head" line on success.
        if result.pipeline_output_path and os.path.exists(result.pipeline_output_path):
            try:
                po = read_json(result.pipeline_output_path)
                diff_block = po.get("diff") or (po.get("provenance") or {}).get("diff")
                if isinstance(diff_block, dict) and diff_block.get("mode") == "incremental":
                    scan_payload["diff"] = diff_block
            except (json.JSONDecodeError, OSError):
                pass

        status = result.status if result.status in ("completed", "partial", "failed") else "completed"
        env = make_envelope(
            status=status,
            run_id=result.run_id,
            stage="scan",
            data=scan_payload,
            metrics=result.metrics.to_dict(),
            warnings=list(result.warnings),
            errors=list(result.errors),
        )
        _output_json(env)

        if status == "failed":
            return 2
        fail_on_code = exit_code_for_fail_on(
            result.metrics.to_dict(),
            getattr(args, "fail_on", None),
        )
        return fail_on_code if fail_on_code else (1 if status == "partial" else 0)

    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_parse(args):
    """Parse a repository into a dataset."""
    from core.parser_adapter import parse_repository
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = args.output or tempfile.mkdtemp(prefix="911vulscan_parse_")

    try:
        with step_context("parse", output_dir, inputs={
            "repo_path": os.path.abspath(args.repo),
            "language": args.language or "auto",
            "scope": args.scope,
            "skip_tests": not args.no_skip_tests,
        }) as ctx:
            result = parse_repository(
                repo_path=args.repo,
                output_dir=output_dir,
                language=args.language or "auto",
                scope=args.scope,
                skip_tests=not args.no_skip_tests,
                name=getattr(args, "name", None),
                diff_manifest=getattr(args, "diff_manifest", None),
            )

            ctx.summary = {
                "total_units": result.units_count,
                "language": result.language,
                "scope": result.scope,
            }
            # Surface diff stats in the parse step report if present.
            diff_report = os.path.join(output_dir, "diff_filter.report.json")
            if os.path.exists(diff_report):
                try:
                    ctx.summary["diff_stats"] = read_json(diff_report)
                except (json.JSONDecodeError, OSError):
                    pass
            ctx.outputs = {
                "dataset_path": result.dataset_path,
                "analyzer_output_path": result.analyzer_output_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_enhance(args):
    """Enhance a dataset with security context."""
    from core.enhancer import enhance_dataset
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    # Default output path: same dir as input, with _enhanced suffix
    if args.output:
        output_path = args.output
    else:
        base, ext = os.path.splitext(args.dataset)
        output_path = f"{base}_enhanced{ext}"

    output_dir = os.path.dirname(os.path.abspath(output_path))

    try:
        with step_context("enhance", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "analyzer_output_path": os.path.abspath(args.analyzer_output) if args.analyzer_output else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
            "mode": args.mode,
        }) as ctx:
            result = enhance_dataset(
                dataset_path=args.dataset,
                output_path=output_path,
                analyzer_output_path=args.analyzer_output,
                repo_path=args.repo_path,
                mode=args.mode,
                checkpoint_path=args.checkpoint,
                workers=args.workers,
                backoff_seconds=args.backoff,
            )

            ctx.summary = {
                "units_enhanced": result.units_enhanced,
                "error_count": result.error_count,
                "mode": args.mode,
            }
            if result.error_summary:
                ctx.summary["error_summary"] = result.error_summary
            ctx.outputs = {
                "enhanced_dataset_path": result.enhanced_dataset_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_analyze(args):
    """Run vulnerability analysis on a dataset.

    With --verify, chains Stage 1 detection into Stage 2 verification
    automatically (convenience shortcut for ``analyze`` + ``verify``).
    """
    from core.analyzer import run_analysis
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="911vulscan_analyze_")

    if getattr(args, "exploitable_all", False) or getattr(args, "exploitable_only", False):
        print(
            "Error: --exploitable-all / --exploitable-only were removed. "
            "Stage 1 is candidate discovery and no longer filters on "
            "security_classification.",
            file=sys.stderr,
        )
        return 2

    try:
        with step_context("analyze", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "model": args.model,
            "limit": args.limit,
        }) as ctx:
            result = run_analysis(
                dataset_path=args.dataset,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=args.app_context,
                repo_path=args.repo_path,
                limit=args.limit,
                model=args.model,
                workers=args.workers,
                checkpoint_path=getattr(args, "checkpoint", None),
                backoff_seconds=args.backoff,
            )

            ctx.summary = {
                "total_units": result.metrics.total_units,
                "analyzed": (
                    result.metrics.total_units - result.metrics.stage1_errors
                ),
                "stage1": {
                    "candidates": result.metrics.stage1_candidates,
                    "no_finding": result.metrics.stage1_no_finding,
                    "inconclusive": result.metrics.stage1_inconclusive,
                    "errors": result.metrics.stage1_errors,
                },
            }
            ctx.outputs = {
                "results_path": result.results_path,
            }

        # If --verify, chain into Stage 2
        if args.verify:
            if not args.analyzer_output:
                print("[Analyze] WARNING: --verify requires --analyzer-output. "
                      "Skipping verification.", file=sys.stderr)
            else:
                from core.verifier import run_verification
                with step_context("verify", output_dir, inputs={
                    "results_path": result.results_path,
                    "analyzer_output_path": os.path.abspath(args.analyzer_output),
                }) as vctx:
                    vresult = run_verification(
                        results_path=result.results_path,
                        output_dir=output_dir,
                        analyzer_output_path=args.analyzer_output,
                        app_context_path=args.app_context,
                        repo_path=args.repo_path,
                        workers=args.workers,
                        backoff_seconds=args.backoff,
                    )

                    vctx.summary = {
                        "candidates_input": vresult.candidates_input,
                        "attempted": vresult.attempted,
                        "succeeded": vresult.succeeded,
                        "failed": vresult.failed,
                        "skipped": vresult.skipped,
                        "confirmed": vresult.confirmed,
                        "rejected": vresult.rejected,
                        "inconclusive": vresult.inconclusive,
                    }
                    vctx.outputs = {
                        "verified_results_path": vresult.verified_results_path,
                    }

                _output_json(success(vresult.to_dict()))
                metrics = {
                    "stage2_confirmed": vresult.confirmed,
                    "stage2_rejected": vresult.rejected,
                    "stage2_inconclusive": vresult.inconclusive,
                    "stage2_failed": vresult.failed,
                }
                return exit_code_for_fail_on(
                    metrics,
                    getattr(args, "fail_on", None),
                )

        _output_json(success(result.to_dict()))

        metrics = result.metrics.to_dict() if hasattr(result.metrics, "to_dict") else {}
        return exit_code_for_fail_on(
            metrics,
            getattr(args, "fail_on", None),
        )

    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_verify(args):
    """Run Stage 2 attacker-simulation verification on Stage 1 results."""
    from core.verifier import run_verification
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="911vulscan_verify_")

    try:
        with step_context("verify", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "analyzer_output_path": os.path.abspath(args.analyzer_output),
            "app_context_path": os.path.abspath(args.app_context) if args.app_context else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
        }) as ctx:
            result = run_verification(
                results_path=args.results,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=args.app_context,
                repo_path=args.repo_path,
                workers=args.workers,
                checkpoint_path=getattr(args, "checkpoint", None),
                backoff_seconds=args.backoff,
            )

            ctx.summary = {
                "candidates_input": result.candidates_input,
                "attempted": result.attempted,
                "succeeded": result.succeeded,
                "failed": result.failed,
                "skipped": result.skipped,
                "confirmed": result.confirmed,
                "rejected": result.rejected,
                "inconclusive": result.inconclusive,
            }
            ctx.outputs = {
                "verified_results_path": result.verified_results_path,
            }

        _output_json(success(result.to_dict()))

        metrics = {
            "stage2_confirmed": result.confirmed,
            "stage2_rejected": result.rejected,
            "stage2_inconclusive": result.inconclusive,
            "stage2_failed": result.failed,
        }
        return exit_code_for_fail_on(
            metrics,
            getattr(args, "fail_on", None),
        )

    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_build_output(args):
    """Build pipeline_output.json from analysis results."""
    from core.reporter import build_pipeline_output
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = os.path.dirname(os.path.abspath(args.output))

    # Load existing step reports for cost/duration data
    results_dir = os.path.dirname(os.path.abspath(args.results))
    step_reports = _load_step_reports(results_dir)

    try:
        with step_context("build-output", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
        }) as ctx:
            path, findings_count, finalize_errors = build_pipeline_output(
                results_path=args.results,
                output_path=args.output,
                repo_name=args.repo_name,
                repo_url=args.repo_url,
                language=args.language,
                commit_sha=args.commit_sha,
                processing_level=args.processing_level,
                step_reports=step_reports,
            )

            ctx.outputs = {"pipeline_output_path": path}
            if finalize_errors:
                ctx.status = "partial"
                ctx.errors.extend(finalize_errors)

        from core.schemas import make_envelope

        data = {"pipeline_output_path": path, "findings_count": findings_count}
        if finalize_errors:
            env = make_envelope(
                status="partial",
                stage="finalize",
                data=data,
                errors=list(finalize_errors),
            )
        else:
            env = make_envelope(
                status="completed",
                stage="finalize",
                data=data,
            )
        _output_json(env)
        return 0 if not finalize_errors else 1

    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_dynamic_test(args):
    """Run Docker-isolated dynamic exploit testing."""
    from core.dynamic_tester import run_tests
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="vulscan_dyntest_")
    export_name = getattr(args, "project_name", None) or getattr(args, "repo_name", None)
    export_lang = getattr(args, "language", None)
    exit_code = 0

    try:
        # Accept results JSON (preferred) or legacy pipeline path alias.
        results_path = getattr(args, "results", None) or getattr(
            args, "pipeline_output", None
        )
        with step_context("dynamic-test", output_dir, inputs={
            "results_path": os.path.abspath(results_path),
            "max_retries": args.max_retries,
        }) as ctx:
            result = run_tests(
                results_path=results_path,
                output_dir=output_dir,
                max_retries=args.max_retries,
                repo_path=getattr(args, "repo_path", None),
                project_name=export_name,
                language=export_lang,
            )

            ctx.summary = result.to_dict()
            ctx.outputs = {
                "results_json_path": result.results_json_path,
                "results_md_path": result.results_md_path,
            }

        _output_json(success(result.to_dict(), stage="dynamic-test"))

        metrics = {
            "dynamic_reproduced": result.reproduced,
            "dynamic_not_reproduced": result.not_reproduced,
            "dynamic_inconclusive": result.inconclusive,
            "dynamic_failed": result.failed,
        }
        return exit_code_for_fail_on(
            metrics,
            getattr(args, "fail_on", None),
        )
    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        exit_code = 2
    finally:
        # Export after step_context writes dynamic-test.report.json.
        if export_name and os.path.isdir(output_dir):
            try:
                from utilities.scan_results_export import export_dynamic_results

                export_dynamic_results(output_dir, export_name, language=export_lang)
            except Exception as exc:
                print(
                    f"[Dynamic Test] WARNING: export to 911VulScan_Scan_Results failed: {safe_exception_message(exc)}",
                    file=sys.stderr,
                )

    return exit_code


def _default_report_output(results_path: str, fmt: str) -> str:
    """Derive a sensible default output path based on format."""
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(results_path)), "final-reports")
    defaults = {
        "html": os.path.join(reports_dir, "report.html"),
        "csv": os.path.join(reports_dir, "report.csv"),
        "summary": os.path.join(reports_dir, "report.md"),
        "disclosure": os.path.join(reports_dir, "disclosures"),
    }
    return defaults.get(fmt, os.path.join(reports_dir, "report"))


def cmd_report(args):
    """Generate reports from a FinalScanArtifact.

    Accepts ``pipeline_output.json`` or raw ``results.json``. When only
    results are given, FinalScanArtifact is auto-built after deleting any
    stale ``pipeline_output.json`` / ``run_artifact_manifest.json``.
    """
    from core.final_artifact.finalize import (
        FinalArtifactIntegrityError,
        remove_stale_final_artifacts,
    )
    from core.final_artifact.report_views import is_final_scan_artifact
    from core.reporter import (
        build_pipeline_output,
        generate_csv_report,
        generate_summary_report,
        generate_disclosure_docs,
    )
    from core.schemas import error, make_envelope, success
    from core.step_report import step_context

    fmt = args.format
    output_path = args.output or _default_report_output(args.results, fmt)
    output_dir = os.path.dirname(os.path.abspath(output_path)) or os.getcwd()

    # Check if dynamic tests have been run (for summary/disclosure formats)
    if fmt in ("summary", "disclosure") and not getattr(args, "skip_dt_check", False):
        results_dir = os.path.dirname(os.path.abspath(args.results))
        dt_results_path = os.path.join(results_dir, "dynamic_test_results.json")
        if not os.path.exists(dt_results_path):
            print(
                "\nDynamic tests haven't been run yet.\n"
                "If this is intentional, press Y to generate reports without dynamic test data.\n"
                "Otherwise, run 'vulscan dynamic-test' first.\n",
                file=sys.stderr,
            )
            if not sys.stdin.isatty():
                answer = "y"
            else:
                sys.stderr.write("[Y/n] ")
                sys.stderr.flush()
                try:
                    answer = sys.stdin.readline().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = "n"
            if answer not in ("y", "yes", ""):
                print("Aborted. Run 'vulscan dynamic-test' first.", file=sys.stderr)
                return 0

    try:
        with step_context("report", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "format": fmt,
        }) as ctx:
            if fmt == "html":
                _output_json(
                    error(
                        "HTML reports are generated by the Go CLI. "
                        "Use 'vulscan report -f html' instead."
                    )
                )
                return 2

            pipeline_output_path = getattr(args, "pipeline_output", None)
            input_path = os.path.abspath(
                pipeline_output_path or args.results
            )

            needs_artifact = fmt in ("csv", "summary", "disclosure")
            if needs_artifact:
                use_existing = False
                if os.path.isfile(input_path):
                    try:
                        use_existing = is_final_scan_artifact(read_json(input_path))
                    except (json.JSONDecodeError, OSError):
                        use_existing = False

                if not use_existing:
                    # Auto-build: never reuse a stale FinalScanArtifact.
                    results_dir = os.path.dirname(os.path.abspath(args.results))
                    step_reports = _load_step_reports(results_dir)
                    pipeline_output_path = os.path.join(
                        output_dir, "pipeline_output.json"
                    )
                    remove_stale_final_artifacts(output_dir)
                    path, findings_count, finalize_errors = build_pipeline_output(
                        results_path=args.results,
                        output_path=pipeline_output_path,
                        repo_name=args.repo_name,
                        step_reports=step_reports,
                    )
                    if finalize_errors:
                        status = "failed" if findings_count == 0 else "partial"
                        env = make_envelope(
                            status=status,
                            stage="report",
                            data={
                                "pipeline_output_path": path,
                                "findings_count": findings_count,
                            },
                            errors=list(finalize_errors),
                        )
                        _output_json(env)
                        return 2 if status == "failed" else 1
                    input_path = os.path.abspath(path)
                else:
                    input_path = os.path.abspath(input_path)

            if fmt == "csv":
                result = generate_csv_report(input_path, output_path)
            elif fmt == "summary":
                result = generate_summary_report(input_path, output_path)
            elif fmt == "disclosure":
                result = generate_disclosure_docs(input_path, output_path)
            else:
                _output_json(error(f"Unknown format: {fmt}"))
                return 2

            ctx.summary = {"format": fmt}
            ctx.outputs = {"output_path": output_path}

        project_name = (
            getattr(args, "project_name", None) or getattr(args, "repo_name", None)
        )
        if project_name:
            results_dir = os.path.dirname(os.path.abspath(args.results))
            try:
                from utilities.scan_results_export import export_static_results

                export_static_results(
                    results_dir,
                    project_name,
                    language=getattr(args, "language", None),
                    root=_scan_results_root_from_args(args),
                )
            except Exception as exc:
                print(
                    f"[911VulScan] WARNING: export to 911VulScan_Scan_Results failed: {safe_exception_message(exc)}",
                    file=sys.stderr,
                )

        _output_json(success(result.to_dict()))
        return 0

    except FinalArtifactIntegrityError as e:
        _output_json(error(safe_exception_message(e), errors=list(e.errors)))
        return 2
    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def _scan_results_root_from_args(args):
    root = getattr(args, "scan_results_root", None)
    if not root:
        return None
    from pathlib import Path
    return Path(root)


def cmd_export_results(args):
    """Export scan artifacts to 911VulScan_Scan_Results/ (internal + CLI)."""
    from utilities.scan_results_export import export_all_results
    from core.schemas import success, error

    scan_dir = os.path.abspath(args.scan_dir)
    if not os.path.isdir(scan_dir):
        _output_json(error(f"Scan directory not found: {scan_dir}"))
        return 2

    try:
        base = export_all_results(
            scan_dir,
            args.project_name,
            language=getattr(args, "language", None),
            include_static=not args.dynamic_only,
            include_dynamic=not args.static_only,
            root=_scan_results_root_from_args(args),
        )
        _output_json(success({"export_dir": str(base)}))
        return 0
    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_checkpoint_status(args):
    """Report checkpoint status for a checkpoint directory.

    Internal subcommand — not user-facing. Called by the Go CLI to get
    accurate completed/errored counts by reading actual checkpoint files.
    """
    from core.checkpoint import StepCheckpoint
    from core.schemas import success, error

    checkpoint_dir = args.checkpoint_dir
    if not os.path.isdir(checkpoint_dir):
        _output_json(error(f"Checkpoint directory not found: {checkpoint_dir}"))
        return 2

    try:
        status = StepCheckpoint.status(checkpoint_dir)
        _output_json(success(status))
        return 0
    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


def cmd_report_data(args):
    """Prepare pre-computed report data as JSON for the Go HTML renderer.

    Internal subcommand — not user-facing. Called by the Go CLI to get
    all data needed to render the HTML overview report from a
    FinalScanArtifact (pipeline_output.json).

    Runs full integrity checks before emitting report data; failures return
    ``status=failed`` with no report payload.
    """
    from core.final_artifact.finalize import (
        FinalArtifactIntegrityError,
        load_and_validate_final_artifact,
    )
    from core.final_artifact.report_data import build_report_data_from_artifact
    from core.schemas import error, make_envelope
    from core.step_report import step_context

    artifact_path = getattr(args, "pipeline_output", None) or args.results
    artifact_path = os.path.abspath(artifact_path)
    results_dir = os.path.dirname(artifact_path)

    try:
        # validate_final_scan_artifact + verify_run_manifest_before_report
        artifact = load_and_validate_final_artifact(artifact_path)

        with step_context("report-data", results_dir, inputs={
            "artifact_path": artifact_path,
        }) as ctx:
            step_reports = _load_step_reports(results_dir)
            report_data = build_report_data_from_artifact(
                artifact,
                step_reports=step_reports,
                artifact_dir=results_dir,
            )
            ctx.summary = {
                "findings": len(report_data.get("findings", [])),
                "artifact_path": artifact_path,
            }

        run_id = (artifact.get("run") or {}).get("run_id")
        env = make_envelope(
            status="completed",
            run_id=run_id,
            stage="report-data",
            data=report_data,
        )
        _output_json(env)
        return 0

    except FinalArtifactIntegrityError as e:
        _output_json(
            make_envelope(
                status="failed",
                stage="report-data",
                data={},
                errors=list(e.errors),
            )
        )
        return 2
    except Exception as e:
        _output_json(error(safe_exception_message(e)))
        return 2


_REMOVED_CLI_FLAGS = {
    "--level": (
        "--level has been removed. Use --scope all|reachable instead "
        "(codeql/exploitable levels are no longer supported)."
    ),
    "--real-world": (
        "--real-world has been removed from the production pipeline. "
        "Use the standard scan flow with --scope all|reachable."
    ),
    "--llm-reachability": (
        "--llm-reachability has been removed. Reachability is controlled by "
        "--scope all|reachable."
    ),
    "--llm-reachability-max-code-bytes": (
        "--llm-reachability-max-code-bytes has been removed with "
        "--llm-reachability."
    ),
    "--dynamic-test": (
        "--dynamic-test has been renamed to --dynamic-verify "
        "(still off by default; must be passed explicitly)."
    ),
    "--skip-dynamic-test": (
        "--skip-dynamic-test has been removed. Dynamic verification is off by "
        "default; pass --dynamic-verify to enable it."
    ),
}


def _reject_removed_flags(argv: list[str]) -> None:
    """Exit with a clear error if removed production flags are present."""
    for arg in argv:
        key = arg.split("=", 1)[0]
        if key in _REMOVED_CLI_FLAGS:
            print(_REMOVED_CLI_FLAGS[key], file=sys.stderr)
            raise SystemExit(2)


def main():
    _reject_removed_flags(sys.argv[1:])

    parser = argparse.ArgumentParser(
        prog="vulscan",
        description="Two-stage SAST tool using Claude for vulnerability analysis",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---------------------------------------------------------------
    # scan — all-in-one
    # ---------------------------------------------------------------
    _lang_choices = [
        "auto", "python", "javascript", "typescript", "go", "c", "cpp", "c++",
    ]

    scan_p = subparsers.add_parser(
        "scan",
        help="Scan a repository (full pipeline: parse → app_context → "
             "reachability → enhance → detect → verify → dynamic_verify)",
    )
    scan_p.add_argument("repo", help="Path to repository")
    scan_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    scan_p.add_argument(
        "--language", "-l",
        choices=_lang_choices,
        default="auto",
        help="Language (default: auto-detect; typescript→javascript, cpp→c)",
    )
    scan_p.add_argument(
        "--scope",
        choices=["all", "reachable"],
        default="reachable",
        help="Unit selection scope (default: reachable)",
    )
    scan_p.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip Stage 2 attacker simulation (enabled by default)",
    )
    scan_p.add_argument("--no-context", action="store_true", help="Skip application context generation")
    scan_p.add_argument("--no-enhance", action="store_true", help="Skip context enhancement step")
    scan_p.add_argument(
        "--enhance-mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    scan_p.add_argument("--no-report", action="store_true", help="Skip report generation")
    scan_p.add_argument(
        "--dynamic-verify",
        action="store_true",
        help="Enable Docker-isolated dynamic verification (off by default; must be explicit)",
    )
    scan_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    scan_p.add_argument("--limit", type=int, help="Max units to analyze")
    scan_p.add_argument("--model", choices=["opus", "sonnet"], default="opus", help="Model (default: opus)")
    scan_p.add_argument("--workers", type=int, default=8,
                        help="Number of parallel workers for LLM steps (default: 8)")
    scan_p.add_argument("--repo-name", help="Repository name (org/repo)")
    scan_p.add_argument("--repo-url", help="Repository URL")
    scan_p.add_argument("--commit-sha", help="Commit SHA")
    scan_p.add_argument("--diff-manifest", help="Path to diff_manifest.json for incremental scanning")
    scan_p.add_argument(
        "--run-id",
        default=None,
        help="Unique run identity (default: auto-generated). "
             "Results are written to {output}/runs/{run_id}/.",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=["candidate", "confirmed", "reproduced", "error"],
        default=None,
        help="Exit 1 only when findings at this level are present (default: always 0)",
    )
    scan_p.set_defaults(func=cmd_scan)

    # ---------------------------------------------------------------
    # parse — repository parsing only
    # ---------------------------------------------------------------
    parse_p = subparsers.add_parser("parse", help="Parse a repository into a dataset")
    parse_p.add_argument("repo", help="Path to repository")
    parse_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    parse_p.add_argument(
        "--language", "-l",
        choices=_lang_choices,
        default="auto",
        help="Language (default: auto-detect; typescript→javascript, cpp→c)",
    )
    parse_p.add_argument(
        "--scope",
        choices=["all", "reachable"],
        default="reachable",
        help="Unit selection scope (default: reachable)",
    )
    parse_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    parse_p.add_argument("--name", help="Dataset name (default: derived from repo path)")
    parse_p.add_argument("--diff-manifest", help="Path to diff_manifest.json; tags units with diff_selected")
    parse_p.set_defaults(func=cmd_parse)

    # ---------------------------------------------------------------
    # enhance — add security context to a dataset
    # ---------------------------------------------------------------
    enhance_p = subparsers.add_parser("enhance", help="Enhance a dataset with security context")
    enhance_p.add_argument("dataset", help="Path to dataset JSON from parse step")
    enhance_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (required for agentic mode)")
    enhance_p.add_argument("--repo-path", help="Path to the repository (required for agentic mode)")
    enhance_p.add_argument("--output", "-o", help="Output path for enhanced dataset (default: {input}_enhanced.json)")
    enhance_p.add_argument("--checkpoint", help="Path to save/resume checkpoint (agentic mode)")
    enhance_p.add_argument(
        "--mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    enhance_p.add_argument("--workers", type=int, default=8,
                           help="Number of parallel workers for LLM calls (default: 8)")
    enhance_p.add_argument("--backoff", type=int, default=30,
                           help="Seconds to wait when rate-limited (default: 30)")
    enhance_p.set_defaults(func=cmd_enhance)

    # ---------------------------------------------------------------
    # analyze — run analysis on existing dataset
    # ---------------------------------------------------------------
    analyze_p = subparsers.add_parser("analyze", help="Run vulnerability analysis on a dataset")
    analyze_p.add_argument("dataset", help="Path to dataset JSON")
    analyze_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    analyze_p.add_argument("--verify", action="store_true", help="Enable Stage 2 attacker simulation")
    analyze_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (for Stage 2)")
    analyze_p.add_argument("--app-context", help="Path to application_context.json")
    analyze_p.add_argument("--limit", type=int, help="Max units to analyze")
    analyze_p.add_argument("--repo-path", help="Path to the repository (for context correction)")
    exploit_group = analyze_p.add_mutually_exclusive_group()
    exploit_group.add_argument("--exploitable-all", action="store_true",
                               help="Analyze units classified as exploitable or vulnerable_internal (safer, compensates for parser gaps)")
    exploit_group.add_argument("--exploitable-only", action="store_true",
                               help="Analyze only units classified as exploitable (strict, use after parser entry point fixes)")
    analyze_p.add_argument("--model", choices=["opus", "sonnet"], default="opus", help="Model (default: opus)")
    analyze_p.add_argument("--workers", type=int, default=8,
                           help="Number of parallel workers for LLM calls (default: 8)")
    analyze_p.add_argument("--checkpoint", help="Path to checkpoint directory for save/resume")
    analyze_p.add_argument("--backoff", type=int, default=30,
                           help="Seconds to wait when rate-limited (default: 30)")
    analyze_p.add_argument(
        "--fail-on",
        choices=["candidate", "confirmed", "reproduced", "error"],
        default=None,
        help="Exit 1 only when findings at this level are present (default: always 0)",
    )
    analyze_p.set_defaults(func=cmd_analyze)

    # ---------------------------------------------------------------
    # verify — Stage 2 attacker simulation (standalone)
    # ---------------------------------------------------------------
    verify_p = subparsers.add_parser("verify", help="Run Stage 2 verification on analysis results")
    verify_p.add_argument("results", help="Path to results.json from analyze step")
    verify_p.add_argument("--analyzer-output", required=True, help="Path to analyzer_output.json")
    verify_p.add_argument("--app-context", help="Path to application_context.json")
    verify_p.add_argument("--repo-path", help="Path to the repository")
    verify_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    verify_p.add_argument("--workers", type=int, default=8,
                          help="Number of parallel workers for LLM calls (default: 8)")
    verify_p.add_argument("--checkpoint", help="Path to checkpoint directory for save/resume")
    verify_p.add_argument("--backoff", type=int, default=30,
                          help="Seconds to wait when rate-limited (default: 30)")
    verify_p.add_argument(
        "--fail-on",
        choices=["candidate", "confirmed", "reproduced", "error"],
        default=None,
        help="Exit 1 only when findings at this level are present (default: always 0)",
    )
    verify_p.set_defaults(func=cmd_verify)

    # ---------------------------------------------------------------
    # build-output — assemble pipeline_output.json
    # ---------------------------------------------------------------
    bo_p = subparsers.add_parser("build-output", help="Build pipeline_output.json from results")
    bo_p.add_argument("results", help="Path to results.json or results_verified.json")
    bo_p.add_argument("--output", "-o", required=True, help="Output path for pipeline_output.json")
    bo_p.add_argument("--repo-name", help="Repository name (e.g. owner/repo)")
    bo_p.add_argument("--repo-url", help="Repository URL")
    bo_p.add_argument("--language", help="Primary language")
    bo_p.add_argument("--commit-sha", help="Commit SHA")
    bo_p.add_argument("--processing-level", help="Processing level used")
    bo_p.set_defaults(func=cmd_build_output)

    # ---------------------------------------------------------------
    # dynamic-test — Docker-isolated exploit testing
    # ---------------------------------------------------------------
    dt_p = subparsers.add_parser("dynamic-test", help="Run dynamic exploit testing (requires Docker)")
    dt_p.add_argument(
        "pipeline_output",
        help="Path to Stage 1/2 results JSON (results.json or results_verified.json)",
    )
    dt_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    dt_p.add_argument("--repo-path", help="Path to the repository root (for pre-staging source files into Docker build context)")
    dt_p.add_argument("--max-retries", type=int, default=3,
                      help="Max retries per finding on error (default: 3)")
    dt_p.add_argument("--project-name", help="Project name for 911VulScan_Scan_Results export (default: --repo-name)")
    dt_p.add_argument("--repo-name", help="Project name (e.g. local/cjson)")
    dt_p.add_argument("--language", "-l", help="Language subfolder under project (e.g. c)")
    dt_p.add_argument("--scan-results-root", help="Override 911VulScan_Scan_Results root directory")
    dt_p.add_argument(
        "--fail-on",
        choices=["candidate", "confirmed", "reproduced", "error"],
        default=None,
        help="Exit 1 only when findings at this level are present (default: always 0)",
    )
    dt_p.set_defaults(func=cmd_dynamic_test)

    # ---------------------------------------------------------------
    # report — generate reports from results
    # ---------------------------------------------------------------
    report_p = subparsers.add_parser("report", help="Generate reports from analysis results")
    report_p.add_argument("results", help="Path to results JSON or pipeline_output.json")
    report_p.add_argument(
        "--format", "-f",
        choices=["html", "csv", "summary", "disclosure"],
        default="disclosure",
        help="Report format (default: disclosure)",
    )
    report_p.add_argument(
        "--dataset",
        help="Deprecated/ignored: CSV no longer requires a dataset (FinalScanArtifact only)",
    )
    report_p.add_argument("--pipeline-output", help="Path to pipeline_output.json (for summary/disclosure; auto-built if absent)")
    report_p.add_argument("--repo-name", help="Repository name (used when auto-building pipeline_output)")
    report_p.add_argument("--project-name", help="Project name for 911VulScan_Scan_Results export (default: --repo-name)")
    report_p.add_argument("--language", "-l", help="Language subfolder under project (e.g. c)")
    report_p.add_argument("--scan-results-root", help="Override 911VulScan_Scan_Results root directory")
    report_p.add_argument("--output", "-o", help="Output path (default: derived from results path and format)")
    report_p.set_defaults(func=cmd_report)

    export_p = subparsers.add_parser(
        "export-results",
        help="Export scan artifacts to 911VulScan_Scan_Results/ (usually automatic)",
    )
    export_p.add_argument("--scan-dir", required=True, help="Internal scan output directory")
    export_p.add_argument("--project-name", required=True, help="Project name (e.g. local/cjson)")
    export_p.add_argument("--language", "-l", default=None, help="Language subfolder (e.g. c)")
    export_p.add_argument("--scan-results-root", help="Override 911VulScan_Scan_Results root")
    export_p.add_argument("--static-only", action="store_true", help="Export only static/")
    export_p.add_argument("--dynamic-only", action="store_true", help="Export only dynamic/")
    export_p.set_defaults(func=cmd_export_results)

    # ---------------------------------------------------------------
    # report-data — internal: prepare pre-computed report data as JSON
    # ---------------------------------------------------------------
    rd_p = subparsers.add_parser("report-data", help="(internal) Prepare report data for Go renderer")
    rd_p.add_argument(
        "results",
        help="Path to FinalScanArtifact (pipeline_output.json)",
    )
    rd_p.add_argument(
        "--pipeline-output",
        dest="pipeline_output",
        help="Alias for results (FinalScanArtifact path)",
    )
    rd_p.set_defaults(func=cmd_report_data)

    # ---------------------------------------------------------------
    # checkpoint-status — internal: report checkpoint status for Go CLI
    # ---------------------------------------------------------------
    cs_p = subparsers.add_parser("checkpoint-status",
        help="(internal) Report checkpoint status for a directory")
    cs_p.add_argument("checkpoint_dir", help="Path to checkpoint directory")
    cs_p.set_defaults(func=cmd_checkpoint_status)

    args = parser.parse_args()
    return args.func(args)


def _get_version() -> str:
    """Get version from package."""
    try:
        from vulscan import __version__
        return __version__
    except ImportError:
        return "0.1.0"


if __name__ == "__main__":
    sys.exit(main())
