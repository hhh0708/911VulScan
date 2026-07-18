"""
Stage 2 — candidate verification state machine.

Only Stage 1 ``decision=candidate`` enters verification. Results are written
to ``stage2_verification`` without mutating the Stage 1 DetectionResult.
"""

from __future__ import annotations

import copy
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional

from core.schemas import VerifyResult
from core import tracking
from core.progress import ProgressReporter
from core.verification.checkpoint import VerifyCheckpointManager
from core.verification.engine import CandidateVerifier, VERIFIER_MODEL
from core.verification.fingerprint import compute_verification_fingerprint
from core.verification.input_builder import build_verification_input
from core.verification.schema import skipped_result
from utilities.llm_client import get_global_tracker, get_shared_llm_client
from utilities.file_io import read_json, write_json
from utilities.llm_config import format_active_llm_label
from utilities.agentic_enhancer.repository_index import load_index_from_file
from utilities.credentials import safe_exception_message
from utilities.enhancement.fingerprint import hash_file
from utilities.rate_limiter import get_rate_limiter, is_retryable_error

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


def _load_units_by_id(dataset_path: Optional[str]) -> dict:
    if not dataset_path or not os.path.isfile(dataset_path):
        return {}
    try:
        data = read_json(dataset_path)
        return {u.get("id"): u for u in data.get("units", []) if u.get("id")}
    except Exception:  # noqa: BLE001
        return {}


def _empty_metrics() -> dict:
    return {
        "candidates_input": 0,
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
        "confirmed": 0,
        "rejected": 0,
        "inconclusive": 0,
    }


def _tally(metrics: dict, s2: dict) -> None:
    state = s2.get("execution_state", "failed")
    decision = s2.get("decision", "inconclusive")
    if state == "skipped":
        metrics["skipped"] += 1
        return
    metrics["attempted"] += 1
    if state == "succeeded":
        metrics["succeeded"] += 1
    elif state == "failed":
        metrics["failed"] += 1
    # Decision tallies are mutually exclusive for non-skipped
    if decision == "confirmed":
        metrics["confirmed"] += 1
    elif decision == "rejected":
        metrics["rejected"] += 1
    else:
        metrics["inconclusive"] += 1


def run_verification(
    results_path: str,
    output_dir: str,
    analyzer_output_path: str,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    workers: int = 8,
    checkpoint_path: str | None = None,
    backoff_seconds: int = 30,
    dataset_path: str | None = None,
    call_graph_path: str | None = None,
) -> VerifyResult:
    """Run Stage 2 verification on Stage 1 candidates only."""
    os.makedirs(output_dir, exist_ok=True)

    from utilities.rate_limiter import configure_rate_limiter

    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "verify_checkpoints")
    checkpoint = VerifyCheckpointManager(checkpoint_path)
    checkpoint.ensure_dir()

    print(f"[Verify] Model: {format_active_llm_label(VERIFIER_MODEL)}", file=sys.stderr)
    print(f"[Verify] Loading results: {results_path}", file=sys.stderr)
    experiment = read_json(results_path)
    all_results = experiment.get("results", [])

    # Only decision=candidate enters verification
    candidates = [
        r for r in all_results if (r or {}).get("decision") == "candidate"
    ]
    non_candidates = [
        r for r in all_results if (r or {}).get("decision") != "candidate"
    ]

    metrics = _empty_metrics()
    metrics["candidates_input"] = len(candidates)
    print(
        f"[Verify] {len(candidates)} candidates to verify "
        f"(out of {len(all_results)} Stage 1 results)",
        file=sys.stderr,
    )

    # Mark non-candidates as skipped (do not mutate Stage 1 fields)
    for r in non_candidates:
        if "stage2_verification" in r:
            continue  # keep prior stage2 if present
        uid = r.get("unit_id") or r.get("route_key") or "unknown"
        r["stage2_verification"] = skipped_result(
            finding_id=f"skipped:{uid}",
            reason=f"stage1_decision={(r or {}).get('decision')!r} is not candidate",
            model=VERIFIER_MODEL,
        )
        _tally(metrics, r["stage2_verification"])

    if not candidates:
        verified_path = os.path.join(output_dir, "results_verified.json")
        _write_verified_results(verified_path, experiment, all_results, metrics)
        return _to_verify_result(verified_path, metrics, frozenset())

    # Missing/corrupt analyzer, dataset, call graph, or target code must NOT abort
    # the whole Stage 2 batch — each affected candidate becomes failed/inconclusive.
    index_missing = not analyzer_output_path or not os.path.exists(analyzer_output_path)
    if index_missing:
        print(
            f"[Verify] WARNING: analyzer_output missing/corrupt at "
            f"{analyzer_output_path!r} — candidates will be marked failed/inconclusive",
            file=sys.stderr,
        )

    app_context = None
    if app_context_path and HAS_APP_CONTEXT and os.path.exists(app_context_path):
        app_context = load_context(Path(app_context_path))

    if call_graph_path is None and analyzer_output_path:
        sibling = os.path.join(os.path.dirname(analyzer_output_path), "call_graph.json")
        if os.path.isfile(sibling):
            call_graph_path = sibling
        else:
            alt = os.path.join(output_dir, "call_graph.json")
            if os.path.isfile(alt):
                call_graph_path = alt
    call_graph = _load_call_graph(call_graph_path)
    if call_graph_path and call_graph is None:
        print(
            f"[Verify] WARNING: call graph missing/corrupt at {call_graph_path!r}",
            file=sys.stderr,
        )

    if dataset_path is None:
        # Prefer enhanced dataset beside results
        for name in ("dataset_enhanced.json", "dataset.json"):
            candidate_path = os.path.join(output_dir, name)
            if os.path.isfile(candidate_path):
                dataset_path = candidate_path
                break
    units_by_id = _load_units_by_id(dataset_path)
    if dataset_path and not units_by_id:
        print(
            f"[Verify] WARNING: dataset missing/empty at {dataset_path!r}",
            file=sys.stderr,
        )

    index = None
    index_stats: dict = {}
    analyzer_hash = ""
    if not index_missing:
        print(
            f"[Verify] Loading repository index from {analyzer_output_path}",
            file=sys.stderr,
        )
        try:
            index = load_index_from_file(analyzer_output_path, repo_path)
            index_stats = (
                index.get_statistics() if hasattr(index, "get_statistics") else {}
            )
            analyzer_hash = hash_file(analyzer_output_path)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[Verify] WARNING: failed to load repository index: "
                f"{safe_exception_message(exc)} — candidates marked failed",
                file=sys.stderr,
            )
            index = None
    call_graph_hash = hash_file(call_graph_path) if call_graph_path else ""

    shared_client = get_shared_llm_client()
    tracker = get_global_tracker()
    verifier = CandidateVerifier(
        index=index,
        tracker=tracker,
        app_context=app_context,
        client=shared_client,
    )

    # Build VerificationInputs + fingerprints
    work_items = []
    for r in candidates:
        # Preserve Stage 1 immutability — work on a shallow copy for stage2 only
        stage1_snapshot = {
            k: copy.deepcopy(v)
            for k, v in r.items()
            if k != "stage2_verification"
        }
        unit = units_by_id.get(stage1_snapshot.get("unit_id") or "")
        vin = build_verification_input(
            stage1_snapshot,
            unit=unit,
            app_context=app_context,
            call_graph=call_graph,
            analyzer_output_path=analyzer_output_path or "",
            repo_path=repo_path or "",
            index_stats=index_stats,
            model=VERIFIER_MODEL,
        )
        fp = compute_verification_fingerprint(
            vin,
            model=VERIFIER_MODEL,
            analyzer_index_hash=analyzer_hash,
            call_graph_hash=call_graph_hash,
        )
        evid_ids = {
            e.get("evidence_id")
            for e in (vin.get("evidence") or [])
            if isinstance(e, dict) and e.get("evidence_id")
        }
        work_items.append((r, vin, fp, evid_ids))

    # Restore from checkpoints
    to_run = []
    restored = 0
    for r, vin, fp, evid_ids in work_items:
        # If already has a terminal succeeded/skipped stage2 from a prior merge, keep it
        # unless fingerprint would require re-run — checkpoint is authoritative.
        cp = checkpoint.load_valid(vin["finding_id"], fp, evid_ids)
        if cp:
            r["stage2_verification"] = cp["result"]
            _tally(metrics, cp["result"])
            restored += 1
        else:
            to_run.append((r, vin, fp, evid_ids))

    if restored:
        print(f"[Verify] Restored {restored} from checkpoints", file=sys.stderr)

    progress = ProgressReporter("Verify", len(work_items), tracker=tracker, completed=restored)
    print(
        f"[Verify] Running candidate verification on {len(to_run)} findings...",
        file=sys.stderr,
    )

    def _run_one(r, vin, fp, evid_ids):
        start = time.monotonic()
        tracker.start_unit_tracking()
        try:
            s2 = verifier.verify(vin)
        except Exception as exc:  # noqa: BLE001
            from core.verification.schema import empty_verification_result

            s2 = empty_verification_result(
                vin["finding_id"],
                execution_state="failed",
                decision="inconclusive",
                reason=safe_exception_message(exc),
                model=VERIFIER_MODEL,
            )
        usage = tracker.get_unit_usage()
        # Never overwrite Stage 1 — only set stage2_verification
        # Rejected/confirmed must not rewrite decision=candidate
        r["stage2_verification"] = s2
        if s2.get("execution_state") != "failed":
            checkpoint.save(
                vin["finding_id"],
                fingerprint=fp,
                result=s2,
                usage=usage,
            )
        elapsed = time.monotonic() - start
        return r, s2, elapsed, usage, threading.current_thread().name

    if workers <= 1:
        for item in to_run:
            r, s2, elapsed, usage, worker = _run_one(*item)
            _tally(metrics, s2)
            progress.report(
                item[1]["unit_id"],
                detail=f"{s2.get('execution_state')}/{s2.get('decision')}",
                unit_elapsed=elapsed,
            )
    else:
        executor = ThreadPoolExecutor(max_workers=workers)
        futures = {
            executor.submit(_run_one, r, vin, fp, evid): (r, vin)
            for r, vin, fp, evid in to_run
        }
        try:
            for future in as_completed(futures):
                r, s2, elapsed, usage, worker = future.result()
                _tally(metrics, s2)
                uid = (futures[future][1] or {}).get("unit_id", "?")
                progress.report(
                    uid,
                    detail=f"{s2.get('execution_state')}/{s2.get('decision')} [{worker}]",
                    unit_elapsed=elapsed,
                )
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            print("[Verify] Interrupted — progress saved", file=sys.stderr)
        else:
            executor.shutdown(wait=False)

    progress.finish()

    # Ensure every Stage 1 result has stage2_verification
    for r in all_results:
        if "stage2_verification" not in r:
            uid = r.get("unit_id") or "unknown"
            r["stage2_verification"] = skipped_result(
                finding_id=f"skipped:{uid}",
                reason="not_processed",
                model=VERIFIER_MODEL,
            )

    checkpoint.write_summary(
        len(work_items),
        metrics["succeeded"] + metrics["skipped"],
        metrics["failed"],
        {"failed": metrics["failed"]},
        phase="done",
        metrics=metrics,
    )

    tracking.log_usage("Stage 2")
    verified_path = os.path.join(output_dir, "results_verified.json")
    verified_ids = frozenset(
        r.get("unit_id") or ""
        for r in all_results
        if (r.get("stage2_verification") or {}).get("decision") == "confirmed"
        and (r.get("stage2_verification") or {}).get("execution_state")
        == "succeeded"
    )
    _write_verified_results(verified_path, experiment, all_results, metrics)
    print(f"[Verify] Results written to {verified_path}", file=sys.stderr)
    print(f"[Verify] Metrics: {metrics}", file=sys.stderr)
    return _to_verify_result(verified_path, metrics, verified_ids)


def _write_verified_results(path, experiment, results, metrics):
    # Strip code_by_route from output
    out = {
        "dataset": experiment.get("dataset"),
        "model": experiment.get("model"),
        "timestamp": experiment.get("timestamp"),
        "verify": True,
        "schema_version": "verification-1.0",
        "metrics": metrics,
        "results": results,
        "confirmed_findings": [
            r
            for r in results
            if (r.get("stage2_verification") or {}).get("decision") == "confirmed"
            and (r.get("stage2_verification") or {}).get("execution_state")
            == "succeeded"
        ],
    }
    write_json(path, out)


def _to_verify_result(path, metrics, verified_ids) -> VerifyResult:
    return VerifyResult(
        verified_results_path=path,
        verified_unit_ids=verified_ids,
        usage=tracking.get_usage(),
        candidates_input=metrics["candidates_input"],
        attempted=metrics["attempted"],
        succeeded=metrics["succeeded"],
        failed=metrics["failed"],
        skipped=metrics["skipped"],
        confirmed=metrics["confirmed"],
        rejected=metrics["rejected"],
        inconclusive=metrics["inconclusive"],
    )
