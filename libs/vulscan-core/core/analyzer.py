"""
Stage 1 — evidence-constrained candidate discovery.

Production path: ``run_analysis`` → ``core.detection`` (no experiment.py).
Checkpoints are content-addressed (fingerprint over DetectionInput + versions).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from core.schemas import AnalyzeResult, AnalysisMetrics
from core import tracking
from core.progress import ProgressReporter
from core.detection.analyze import analyze_detection_input
from core.detection.checkpoint import AnalyzeCheckpointManager
from core.detection.fingerprint import compute_detection_fingerprint
from core.detection.input_builder import build_detection_input
from utilities.llm_client import AnthropicClient, get_global_tracker
from utilities.llm_config import format_active_llm_label
from utilities.model_registry import ModelRole, model_for
from utilities.file_io import read_json, write_json
from utilities.rate_limiter import get_rate_limiter, is_retryable_error
from utilities.credentials import safe_exception_message

try:
    from context.application_context import load_context

    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False
    load_context = None


def _load_call_graph(path: Optional[str]) -> Optional[dict]:
    if not path or not os.path.isfile(path):
        return None
    try:
        from utilities.call_graph.schema import load_call_graph

        doc, err = load_call_graph(path)
        return doc if err is None else None
    except Exception:  # noqa: BLE001
        try:
            return read_json(path)
        except Exception:  # noqa: BLE001
            return None


def _code_for_unit(unit: dict) -> str:
    code_field = unit.get("code", {})
    if isinstance(code_field, dict):
        return code_field.get("primary_code", "") or ""
    return str(code_field or "")


def _process_unit(
    client,
    unit,
    index,
    app_context,
    call_graph,
    model_id: str,
):
    """Process a single unit. Returns result envelope without mutating shared state."""
    uid = unit.get("id", f"unit_{index}")
    start = time.monotonic()
    tracker = get_global_tracker()
    tracker.start_unit_tracking()

    try:
        din = build_detection_input(
            unit, app_context=app_context, call_graph=call_graph
        )
        result = analyze_detection_input(client, din, model=model_id)
        result["unit_id"] = uid
        decision = result.get("decision", "error")
        elapsed = time.monotonic() - start
        return {
            "index": index,
            "result": result,
            "route_key": uid,
            "code_for_route": _code_for_unit(unit),
            "decision": decision,
            "detection_input": din,
            "elapsed": elapsed,
            "error": None,
            "worker": threading.current_thread().name,
            "usage": tracker.get_unit_usage(),
        }
    except Exception as e:
        elapsed = time.monotonic() - start
        safe = safe_exception_message(e)
        return {
            "index": index,
            "result": {
                "unit_id": uid,
                "decision": "error",
                "candidate_type": "",
                "cwe_id": 0,
                "location": {},
                "source": "",
                "propagation": "",
                "sink": "",
                "guards": [],
                "impact": "",
                "preconditions": [],
                "evidence_ids": [],
                "counter_evidence_ids": [],
                "uncertainties": [{"kind": "exception", "detail": safe}],
                "confidence": 0.0,
                "provenance": {"error": {"type": "exception", "message": safe}},
                "route_key": uid,
            },
            "route_key": uid,
            "code_for_route": "",
            "decision": "error",
            "detection_input": None,
            "elapsed": elapsed,
            "error": safe,
            "worker": threading.current_thread().name,
            "usage": tracker.get_unit_usage(),
        }


def _count_decisions(results: list) -> dict:
    counts = {
        "candidate": 0,
        "no_finding": 0,
        "inconclusive": 0,
        "error": 0,
        "vulnerable": 0,
        "bypassable": 0,
        "protected": 0,
        "safe": 0,
        "errors": 0,
    }
    for r in results:
        if not r:
            continue
        d = r.get("decision", "error")
        if d in ("candidate", "no_finding", "inconclusive", "error"):
            counts[d] += 1
        if d == "error":
            counts["errors"] += 1
        elif d == "no_finding":
            counts["safe"] += 1
        # Do NOT map candidate → vulnerable.
    return counts


def _run_detection(
    units,
    client,
    app_context,
    call_graph,
    workers,
    model_id: str,
    checkpoint: AnalyzeCheckpointManager | None = None,
    summary_callback=None,
):
    total = len(units)
    tracker = get_global_tracker()

    results = [None] * total
    units_to_process = []

    # Precompute fingerprints / restore
    restored_count = 0
    if checkpoint is not None:
        restore_args = []
        fps = []
        for i, unit in enumerate(units):
            din = build_detection_input(
                unit, app_context=app_context, call_graph=call_graph
            )
            fp = compute_detection_fingerprint(din, model=model_id)
            evid = {
                e.get("evidence_id")
                for e in (din.get("evidence") or [])
                if isinstance(e, dict) and e.get("evidence_id")
            }
            fps.append((i, unit, din, fp, evid))
            restore_args.append((i, unit.get("id", f"unit_{i}"), fp, evid))

        restored, _usage = checkpoint.restore_matching(restore_args)
        for i, result in restored.items():
            results[i] = result
            restored_count += 1

        for i, unit, din, fp, evid in fps:
            if i not in restored:
                units_to_process.append((i, unit, din, fp))
    else:
        for i, unit in enumerate(units):
            din = build_detection_input(
                unit, app_context=app_context, call_graph=call_graph
            )
            fp = compute_detection_fingerprint(din, model=model_id)
            units_to_process.append((i, unit, din, fp))

    if restored_count:
        print(
            f"[Detect] Restored {restored_count} units from checkpoints",
            file=sys.stderr,
            flush=True,
        )

    progress = ProgressReporter(
        "Detect", total, tracker=tracker, completed=restored_count
    )
    mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
    print(
        f"[Detect] Mode: {mode}, {len(units_to_process)} units to process "
        f"({restored_count} already done)",
        file=sys.stderr,
        flush=True,
    )

    def _process_and_save(i, unit, din, fp):
        out = _process_unit(client, unit, i, app_context, call_graph, model_id)
        if checkpoint is not None and out["decision"] != "error":
            checkpoint.save(
                out["result"].get("unit_id", f"unit_{i}"),
                fingerprint=fp,
                result=out["result"],
                usage=out.get("usage"),
            )
        return out

    if workers <= 1:
        try:
            for i, unit, din, fp in units_to_process:
                out = _process_and_save(i, unit, din, fp)
                results[i] = out["result"]
                if summary_callback:
                    summary_callback(out["decision"], usage=out.get("usage"))
                progress.report(
                    out["result"].get("unit_id", f"unit_{i}"),
                    detail=out["decision"],
                    unit_elapsed=out["elapsed"],
                )
        except KeyboardInterrupt:
            print(
                "[Detect] Interrupted — progress saved to checkpoints",
                file=sys.stderr,
            )
            progress.finish()
            return results
    else:
        executor = ThreadPoolExecutor(max_workers=workers)
        futures = {
            executor.submit(_process_and_save, i, unit, din, fp): (i, unit)
            for i, unit, din, fp in units_to_process
        }
        try:
            for future in as_completed(futures):
                out = future.result()
                i = out["index"]
                results[i] = out["result"]
                if summary_callback:
                    summary_callback(out["decision"], usage=out.get("usage"))
                progress.report(
                    out["result"].get("unit_id", f"unit_{i}"),
                    detail=f"{out['decision']}  [{out['worker']}]",
                    unit_elapsed=out["elapsed"],
                )
        except KeyboardInterrupt:
            print(
                "[Detect] Interrupted — cancelling pending work...", file=sys.stderr
            )
            executor.shutdown(wait=False, cancel_futures=True)
            progress.finish()
            return results
        executor.shutdown(wait=False)

    progress.finish()
    # Fill any None holes
    for i, r in enumerate(results):
        if r is None:
            results[i] = {
                "unit_id": units[i].get("id", f"unit_{i}"),
                "decision": "error",
                "uncertainties": [{"kind": "missing", "detail": "no result"}],
                "confidence": 0.0,
                "evidence_ids": [],
                "counter_evidence_ids": [],
                "provenance": {},
            }
    return results


def run_analysis(
    dataset_path: str,
    output_dir: str,
    analyzer_output_path: str | None = None,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    limit: int | None = None,
    model: str = "opus",
    exploitable_filter: str | None = None,
    workers: int = 8,
    checkpoint_path: str | None = None,
    backoff_seconds: int = 30,
    call_graph_path: str | None = None,
) -> AnalyzeResult:
    """Run Stage 1 candidate discovery on a dataset.

    Production-only path via ``core.detection``. Does not import ``experiment``.
    ``exploitable_filter`` is rejected (removed with security_classification).
    """
    _ = repo_path  # reserved for future tool-use; not used to mutate verdicts
    os.makedirs(output_dir, exist_ok=True)

    from utilities.rate_limiter import configure_rate_limiter

    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoints")
    checkpoint = AnalyzeCheckpointManager(checkpoint_path)
    checkpoint.ensure_dir()

    model_id = model_for(ModelRole.PRIMARY if model == "opus" else ModelRole.SECONDARY)
    logged_model = format_active_llm_label(model_id)
    print(f"[Analyze] Model: {logged_model}", file=sys.stderr)
    print("[Analyze] Mode: candidate discovery (Detection Schema)", file=sys.stderr)

    client = AnthropicClient(model=model_id)

    app_context = None
    if app_context_path and HAS_APP_CONTEXT and os.path.exists(app_context_path):
        app_context = load_context(Path(app_context_path))
        status = getattr(app_context, "status", "ok")
        print(f"[Analyze] App context status: {status}", file=sys.stderr)

    if call_graph_path is None:
        if analyzer_output_path:
            sibling = os.path.join(
                os.path.dirname(analyzer_output_path), "call_graph.json"
            )
            if os.path.isfile(sibling):
                call_graph_path = sibling
        if call_graph_path is None:
            sibling = os.path.join(output_dir, "call_graph.json")
            if os.path.isfile(sibling):
                call_graph_path = sibling
    call_graph = _load_call_graph(call_graph_path)

    print(f"[Analyze] Loading dataset: {dataset_path}", file=sys.stderr)
    dataset = read_json(dataset_path)
    units = dataset.get("units", [])

    if any("diff_selected" in u for u in units):
        _pre = len(units)
        units = [u for u in units if u.get("diff_selected")]
        print(f"[Analyze] Diff filter: {_pre} -> {len(units)} units", file=sys.stderr)

    if exploitable_filter:
        print(
            f"[Analyze] Error: exploitable_filter={exploitable_filter!r} was removed. "
            "Stage 1 no longer consumes security_classification.",
            file=sys.stderr,
        )
        raise ValueError(
            "exploitable_filter is no longer supported "
            "(Enhance/Stage 1 no longer emit security_classification)"
        )

    if limit:
        units = units[:limit]

    total = len(units)
    print(f"[Analyze] Analyzing {total} units...", file=sys.stderr)

    _summary_completed = 0
    _summary_errors = 0
    _summary_error_breakdown: dict = {}
    _summary_input_tokens = 0
    _summary_output_tokens = 0
    _summary_cost_usd = 0.0

    def _usage_dict():
        return {
            "input_tokens": _summary_input_tokens,
            "output_tokens": _summary_output_tokens,
            "cost_usd": round(_summary_cost_usd, 6),
        }

    checkpoint.write_summary(
        total,
        _summary_completed,
        _summary_errors,
        _summary_error_breakdown,
        phase="in_progress",
        usage=_usage_dict(),
    )

    def _summary_callback(decision, usage=None):
        nonlocal _summary_completed, _summary_errors, _summary_error_breakdown
        nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
        if decision == "error":
            _summary_errors += 1
            _summary_error_breakdown["api"] = (
                _summary_error_breakdown.get("api", 0) + 1
            )
        else:
            _summary_completed += 1
        if usage:
            _summary_input_tokens += usage.get("input_tokens", 0)
            _summary_output_tokens += usage.get("output_tokens", 0)
            _summary_cost_usd += usage.get("cost_usd", 0.0)
        checkpoint.write_summary(
            total,
            _summary_completed,
            _summary_errors,
            _summary_error_breakdown,
            phase="in_progress",
            usage=_usage_dict(),
        )

    results = _run_detection(
        units,
        client,
        app_context,
        call_graph,
        workers,
        model_id,
        checkpoint=checkpoint,
        summary_callback=_summary_callback,
    )

    retryable_indices = [
        i
        for i, r in enumerate(results)
        if r
        and is_retryable_error((r.get("provenance") or {}).get("error") or r.get("error"))
    ]
    if retryable_indices:
        rate_limiter = get_rate_limiter()
        backoff = rate_limiter.time_until_ready()
        if backoff > 0:
            print(
                f"[Analyze] Retrying {len(retryable_indices)} failed units "
                f"(waiting {backoff:.0f}s)...",
                file=sys.stderr,
            )
            rate_limiter.wait_if_needed()
        else:
            print(
                f"[Analyze] Retrying {len(retryable_indices)} failed units...",
                file=sys.stderr,
            )

        for i in retryable_indices:
            unit = units[i]
            din = build_detection_input(
                unit, app_context=app_context, call_graph=call_graph
            )
            fp = compute_detection_fingerprint(din, model=model_id)
            out = _process_unit(client, unit, i, app_context, call_graph, model_id)
            results[i] = out["result"]
            if out["decision"] != "error":
                _summary_errors = max(0, _summary_errors - 1)
                _summary_completed += 1
                checkpoint.save(
                    out["result"].get("unit_id", f"unit_{i}"),
                    fingerprint=fp,
                    result=out["result"],
                    usage=out.get("usage"),
                )
            retry_usage = out.get("usage") or {}
            _summary_input_tokens += retry_usage.get("input_tokens", 0)
            _summary_output_tokens += retry_usage.get("output_tokens", 0)
            _summary_cost_usd += retry_usage.get("cost_usd", 0.0)
            checkpoint.write_summary(
                total,
                _summary_completed,
                _summary_errors,
                _summary_error_breakdown,
                phase="in_progress",
                usage=_usage_dict(),
            )

    checkpoint.write_summary(
        total,
        _summary_completed,
        _summary_errors,
        _summary_error_breakdown,
        phase="done",
        usage=_usage_dict(),
    )

    tracking.log_usage("Stage 1")
    counts = _count_decisions(results)

    results_path = os.path.join(output_dir, "results.json")
    experiment_result = {
        "dataset": os.path.basename(dataset_path),
        "model": logged_model,
        "timestamp": datetime.now().isoformat(),
        "schema_version": "detection-1.0",
        "metrics": {
            "total": len(units),
            "candidate": counts.get("candidate", 0),
            "no_finding": counts.get("no_finding", 0),
            "inconclusive": counts.get("inconclusive", 0),
            "error": counts.get("error", 0),
            **counts,
        },
        "results": results,
    }
    write_json(results_path, experiment_result)
    print(f"\n[Analyze] Results written to {results_path}", file=sys.stderr)

    usage = tracking.get_usage()
    metrics = AnalysisMetrics(
        total_units=len(units),
        stage1_candidates=counts.get("candidate", 0),
        stage1_no_finding=counts.get("no_finding", 0),
        stage1_inconclusive=counts.get("inconclusive", 0),
        stage1_errors=counts.get("error", 0),
    )
    return AnalyzeResult(
        results_path=results_path,
        metrics=metrics,
        usage=usage,
    )
