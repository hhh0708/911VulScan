"""
Context enhancement wrapper.

Wraps utilities/context_enhancer.py, providing a path-based interface
for both agentic and single-shot enhancement modes.

Checkpoints are always enabled. Per-unit progress is saved to
``{output_dir}/enhance_checkpoints/`` (SHA-256 of unit_id) with
content-addressed fingerprints so code/graph/context changes invalidate
stale restores.
"""

import os
import sys

from core.schemas import EnhanceResult
from core import tracking
from core.progress import ProgressReporter
from utilities.rate_limiter import configure_rate_limiter
from utilities.llm_config import format_active_llm_label
from utilities.model_registry import ModelRole, model_for
from utilities.file_io import read_json, write_json


def enhance_dataset(
    dataset_path: str,
    output_path: str,
    analyzer_output_path: str | None = None,
    repo_path: str | None = None,
    mode: str = "agentic",
    checkpoint_path: str | None = None,
    model: str = "sonnet",
    workers: int = 8,
    backoff_seconds: int = 30,
    call_graph_path: str | None = None,
    app_context_path: str | None = None,
) -> EnhanceResult:
    """Enhance a parsed dataset with neutral context.

    Args:
        dataset_path: Path to dataset.json from the parse step.
        output_path: Path to write the enhanced dataset.
        analyzer_output_path: Path to analyzer_output.json (required for agentic).
        repo_path: Path to the repository (required for agentic mode).
        mode: "agentic" or "single-shot".
        checkpoint_path: Checkpoint directory (auto-derived if None).
        model: Reserved (model comes from ModelRole.SECONDARY).
        workers: Parallel workers.
        backoff_seconds: Rate-limit backoff.
        call_graph_path: Optional call_graph.json for fingerprint neighborhood.
        app_context_path: Optional application_context.json for fingerprint.

    Returns:
        EnhanceResult with output path, stats, and usage.
    """
    _ = model  # role-resolved below
    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    model_id = model_for(ModelRole.SECONDARY)
    print(f"[Enhance] Mode: {mode}", file=sys.stderr)
    print(f"[Enhance] Model: {format_active_llm_label(model_id)}", file=sys.stderr)

    if checkpoint_path is None:
        output_dir = os.path.dirname(os.path.abspath(output_path))
        checkpoint_path = os.path.join(output_dir, "enhance_checkpoints")

    if call_graph_path is None and analyzer_output_path:
        sibling = os.path.join(os.path.dirname(analyzer_output_path), "call_graph.json")
        if os.path.isfile(sibling):
            call_graph_path = sibling

    from utilities.llm_client import AnthropicClient, get_global_tracker
    from utilities.context_enhancer import ContextEnhancer

    tracker = get_global_tracker()
    client = AnthropicClient(model=model_id, tracker=tracker)
    enhancer = ContextEnhancer(
        client=client,
        tracker=tracker,
        call_graph_path=call_graph_path,
        app_context_path=app_context_path,
    )

    print(f"[Enhance] Loading dataset: {dataset_path}", file=sys.stderr)
    dataset = read_json(dataset_path)
    units = dataset.get("units", [])
    print(f"[Enhance] Units to enhance: {len(units)}", file=sys.stderr)

    progress = ProgressReporter("Enhance", len(units), tracker=tracker)

    def _on_unit_done(unit_id: str, classification: str, unit_elapsed: float):
        progress.report(
            unit_label=unit_id,
            detail=classification,
            unit_elapsed=unit_elapsed,
        )

    def _on_restored(count: int):
        progress.completed = count

    if mode == "agentic":
        if not analyzer_output_path:
            raise ValueError("Agentic mode requires --analyzer-output")
        enhanced = enhancer.enhance_dataset_agentic(
            dataset=dataset,
            analyzer_output_path=analyzer_output_path,
            repo_path=repo_path,
            checkpoint_path=checkpoint_path,
            progress_callback=_on_unit_done,
            restored_callback=_on_restored,
            workers=workers,
        )
    elif mode == "single-shot":
        enhanced = enhancer.enhance_dataset(
            dataset,
            progress_callback=_on_unit_done,
            restored_callback=_on_restored,
            workers=workers,
            checkpoint_path=checkpoint_path,
            analyzer_output_path=analyzer_output_path,
        )
    else:
        raise ValueError(f"Unknown enhancement mode: {mode}. Use 'agentic' or 'single-shot'.")

    progress.finish()

    # Neutral stats: related_units / unknowns / errors (no security_classification)
    classifications: dict = {}
    error_count = 0
    error_summary: dict = {}

    for unit in enhanced.get("units", []):
        enh = unit.get("enhancement") or {}
        err = (enh.get("provenance") or {}).get("error")
        if err:
            error_count += 1
            err_type = err.get("type", "unknown") if isinstance(err, dict) else "unknown"
            error_summary[err_type] = error_summary.get(err_type, 0) + 1
            continue
        rel = enh.get("relation_type") or "context"
        classifications[rel] = classifications.get(rel, 0) + 1

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    write_json(output_path, enhanced)
    print(f"[Enhance] Enhanced dataset: {output_path}", file=sys.stderr)
    print(f"[Enhance] Relation types: {classifications}", file=sys.stderr)
    if error_count:
        print(f"[Enhance] Errors: {error_count} ({error_summary})", file=sys.stderr)

    tracking.log_usage("Enhance")
    usage = tracking.get_usage()

    return EnhanceResult(
        enhanced_dataset_path=output_path,
        units_enhanced=len(units) - error_count,
        error_count=error_count,
        error_summary=error_summary,
        usage=usage,
    )
