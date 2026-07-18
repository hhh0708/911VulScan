"""
Context Enhancer — neutral context layer (single-shot and agentic).

Outputs only the Enhancement Schema fields. Does not classify exploitability,
guess callers, or mutate call graph / reachability / verdicts.

Both modes share fingerprinting and EnhanceCheckpointManager.
"""

from __future__ import annotations

import json
import argparse
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Optional

import anthropic

from .llm_client import (
    AnthropicClient,
    TokenTracker,
    get_global_tracker,
    get_shared_llm_client,
)
from .llm_config import format_active_llm_label
from .llm_pricing import format_cost, resolve_display_currency
from .model_registry import ModelRole, model_for
from .agentic_enhancer import RepositoryIndex, enhance_unit_with_agent, load_index_from_file
from .rate_limiter import get_rate_limiter, is_retryable_error
from .file_io import read_json, write_json
from utilities.credentials import safe_exception_message
from utilities.enhancement.schema import (
    ENHANCEMENT_PROMPT_VERSION,
    ENHANCEMENT_SCHEMA_VERSION,
    empty_enhancement,
    normalize_enhancement,
)
from utilities.enhancement.fingerprint import (
    EnhancementFingerprintInputs,
    compute_enhancement_fingerprint,
    hash_file,
)
from utilities.enhancement.checkpoint import EnhanceCheckpointManager

_null_logger = logging.getLogger("null")
_null_logger.addHandler(logging.NullHandler())

CONTEXT_ENHANCEMENT_MODEL = model_for(ModelRole.SECONDARY)


def _build_error_info(exc: Exception) -> dict:
    info = {
        "type": "unknown",
        "exception_class": type(exc).__name__,
        "message": safe_exception_message(exc),
    }
    if isinstance(exc, anthropic.APIConnectionError):
        info["type"] = "connection"
    elif isinstance(exc, anthropic.APITimeoutError):
        info["type"] = "timeout"
    elif isinstance(exc, anthropic.RateLimitError):
        info["type"] = "rate_limit"
        info["status_code"] = getattr(exc, "status_code", None)
        if hasattr(exc, "response") and exc.response is not None:
            info["request_id"] = exc.response.headers.get("request-id")
            retry_after = exc.response.headers.get("retry-after")
            if retry_after:
                info["retry_after"] = retry_after
    elif isinstance(exc, anthropic.APIStatusError):
        info["type"] = "api_status"
        info["status_code"] = exc.status_code
        if hasattr(exc, "response") and exc.response is not None:
            info["request_id"] = exc.response.headers.get("request-id")
    agent_state = getattr(exc, "agent_state", None)
    if agent_state:
        info["agent_state"] = agent_state
    return info


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


def _load_app_context(path: Optional[str]) -> Any:
    if not path or not os.path.isfile(path):
        return None
    try:
        from context.application_context import load_context

        return load_context(Path(path))
    except Exception:  # noqa: BLE001
        try:
            return read_json(path)
        except Exception:  # noqa: BLE001
            return None


def get_context_enhancement_prompt(
    function_id: str,
    function_name: str,
    function_code: str,
    unit_type: str,
    class_name: Optional[str],
    static_deps: list[str],
    static_callers: list[str],
    context_functions: list[dict],
    reachability_status: Optional[str] = None,
) -> str:
    """Neutral single-shot enhancement prompt (shared schema with agentic)."""
    deps_list = "\n".join(f"- {d}" for d in static_deps) if static_deps else "- None identified"
    callers_list = (
        "\n".join(f"- {c}" for c in static_callers) if static_callers else "- None identified"
    )

    context_section = ""
    if context_functions:
        context_section = "## Other Functions in Same File\n"
        for f in context_functions[:5]:
            context_section += f"### {f.get('name', 'unknown')} ({f.get('unit_type', 'function')})\n"
            code_preview = f.get("code", "")[:200]
            if len(f.get("code", "")) > 200:
                code_preview += "..."
            context_section += f"```\n{code_preview}\n```\n\n"
    else:
        context_section = "## Other Functions in Same File\nNo other functions in file.\n"

    reach_line = (
        f"**Reachability (from call graph, do not recompute):** `{reachability_status}`\n"
        if reachability_status
        else ""
    )

    return f"""You are a code-context analyst gathering neutral structural context.

You MUST NOT classify exploitability, invent callers from naming patterns,
mutate call graphs, or produce vulnerability verdicts.

## Target Unit
**ID:** `{function_id}`
**Name:** `{function_name}`
**Type:** {unit_type}
{f'**Class:** {class_name}' if class_name else ''}
{reach_line}
```
{function_code}
```

## Static metadata
**Direct calls:**
{deps_list}

**Direct callers:**
{callers_list}

{context_section}

## Task
Return JSON with ONLY these Enhancement Schema fields (schema {ENHANCEMENT_SCHEMA_VERSION},
prompt {ENHANCEMENT_PROMPT_VERSION}):

```json
{{
  "related_units": [
    {{"id": "file:symbol", "relation_type": "callee|caller|type|definition|related", "reason": "..."}}
  ],
  "relation_type": "mixed|callee|caller|type|definition|related|",
  "types_and_definitions": [],
  "call_context": {{
    "direct_calls": [],
    "direct_callers": [],
    "notes": []
  }},
  "dataflow_observations": [
    {{"kind": "input|output|binding|other", "value": "..."}}
  ],
  "build_runtime_context": {{}},
  "unknowns": [{{"kind": "...", "detail": "..."}}],
  "provenance": {{"mode": "single-shot"}}
}}
```

Respond with JSON only."""


class ContextEnhancer:
    """Enhances units with neutral context (single-shot or agentic)."""

    def __init__(
        self,
        client: AnthropicClient = None,
        tracker: TokenTracker = None,
        logger: logging.Logger = None,
        call_graph_path: Optional[str] = None,
        app_context_path: Optional[str] = None,
        call_graph: Optional[dict] = None,
        app_context: Any = None,
    ):
        self.tracker = tracker or get_global_tracker()
        self.client = client or AnthropicClient(
            model=CONTEXT_ENHANCEMENT_MODEL, tracker=self.tracker
        )
        self.logger = logger or _null_logger
        self._use_logger = logger is not None
        self.call_graph_path = call_graph_path
        self.app_context_path = app_context_path
        self.call_graph = call_graph if call_graph is not None else _load_call_graph(call_graph_path)
        self.app_context = (
            app_context if app_context is not None else _load_app_context(app_context_path)
        )
        self._analyzer_output_hash: Optional[str] = None
        self.stats = {
            "units_processed": 0,
            "units_enhanced": 0,
            "related_units_total": 0,
            "unknowns_total": 0,
            "errors": 0,
            "restored_from_checkpoint": 0,
        }

    def _log(self, level: str, msg: str, **extras):
        if self._use_logger:
            log_func = getattr(self.logger, level, self.logger.info)
            log_func(msg, extra=extras)
        else:
            suffix = " ".join(f"{k}={v}" for k, v in extras.items() if v is not None)
            print(f"{msg} {suffix}" if suffix else msg, file=sys.stderr)

    def fingerprint_for(
        self,
        unit: dict,
        *,
        mode: str,
        analyzer_output_path: Optional[str] = None,
    ) -> str:
        if analyzer_output_path and self._analyzer_output_hash is None:
            self._analyzer_output_hash = hash_file(analyzer_output_path)
        return compute_enhancement_fingerprint(
            EnhancementFingerprintInputs(
                unit=unit,
                call_graph=self.call_graph,
                app_context=self.app_context,
                analyzer_output_path=analyzer_output_path,
                analyzer_output_hash=self._analyzer_output_hash,
                model=CONTEXT_ENHANCEMENT_MODEL,
                mode=mode,
                prompt_version=ENHANCEMENT_PROMPT_VERSION,
                schema_version=ENHANCEMENT_SCHEMA_VERSION,
            )
        )

    def enhance_unit(self, unit: dict, all_units: dict) -> dict:
        """Single-shot enhance; writes ``unit['enhancement']`` only."""
        self.stats["units_processed"] += 1

        function_id = unit.get("id", "unknown")
        code_section = unit.get("code", {})
        function_name = code_section.get("primary_origin", {}).get("function_name", "unknown")
        function_code = code_section.get("primary_code", "")
        unit_type = unit.get("unit_type", "function")
        class_name = code_section.get("primary_origin", {}).get("class_name")
        static_deps = unit.get("metadata", {}).get("direct_calls", [])
        static_callers = unit.get("metadata", {}).get("direct_callers", [])
        reachability_status = unit.get("reachability")

        file_path = code_section.get("primary_origin", {}).get("file_path", "")
        context_functions = []
        for other_id, other_unit in all_units.items():
            if other_id == function_id:
                continue
            other_file = (
                other_unit.get("code", {}).get("primary_origin", {}).get("file_path", "")
            )
            if other_file == file_path:
                context_functions.append(
                    {
                        "id": other_id,
                        "name": other_unit.get("code", {})
                        .get("primary_origin", {})
                        .get("function_name", "unknown"),
                        "code": other_unit.get("code", {}).get("primary_code", ""),
                        "unit_type": other_unit.get("unit_type", "function"),
                    }
                )

        prompt = get_context_enhancement_prompt(
            function_id=function_id,
            function_name=function_name,
            function_code=function_code,
            unit_type=unit_type,
            class_name=class_name,
            static_deps=static_deps,
            static_callers=static_callers,
            context_functions=context_functions,
            reachability_status=reachability_status,
        )

        try:
            from utilities.llm_json_utils import DEFAULT_JSON_RETRIES

            analysis = self.client.analyze_json_sync(
                prompt,
                max_tokens=4096,
                model=CONTEXT_ENHANCEMENT_MODEL,
                context=f"context enhancement {function_id}",
                retries=DEFAULT_JSON_RETRIES,
            )
            if analysis:
                self.stats["units_enhanced"] += 1
                payload = normalize_enhancement(
                    analysis, mode="single-shot", model=CONTEXT_ENHANCEMENT_MODEL
                )
                if not payload["call_context"].get("direct_calls"):
                    payload["call_context"]["direct_calls"] = list(static_deps or [])
                if not payload["call_context"].get("direct_callers"):
                    payload["call_context"]["direct_callers"] = list(static_callers or [])
                self.stats["related_units_total"] += len(payload.get("related_units") or [])
                self.stats["unknowns_total"] += len(payload.get("unknowns") or [])
                unit["enhancement"] = payload
            else:
                unit["enhancement"] = empty_enhancement(
                    mode="single-shot",
                    model=CONTEXT_ENHANCEMENT_MODEL,
                    error={"type": "parse", "message": "empty LLM JSON"},
                )
                self.stats["errors"] += 1
        except Exception as e:
            self.stats["errors"] += 1
            self._log(
                "error",
                "Error enhancing unit",
                unit_id=function_id,
                error=safe_exception_message(e),
            )
            unit["enhancement"] = empty_enhancement(
                mode="single-shot",
                model=CONTEXT_ENHANCEMENT_MODEL,
                error=_build_error_info(e),
            )

        return unit

    def _checkpoint_dir(self, checkpoint_path: Optional[str]) -> Optional[str]:
        if not checkpoint_path:
            return None
        if os.path.isdir(checkpoint_path) or not checkpoint_path.endswith(".json"):
            return checkpoint_path
        return os.path.splitext(checkpoint_path)[0] + "_checkpoints"

    def enhance_dataset(
        self,
        dataset: dict,
        batch_size: int = 10,
        progress_callback: Optional[Callable] = None,
        workers: int = 10,
        checkpoint_path: Optional[str] = None,
        analyzer_output_path: Optional[str] = None,
        restored_callback: Optional[Callable] = None,
    ) -> dict:
        """Single-shot enhancement with shared content-addressed checkpoints."""
        all_units = dataset.get("units", [])
        # Diff filter selects work units, but context lookup uses the full dataset.
        units_by_id = {u.get("id"): u for u in all_units if u.get("id")}
        units = all_units
        if any("diff_selected" in u for u in all_units):
            _pre = len(all_units)
            units = [u for u in all_units if u.get("diff_selected")]
            self._log("info", f"Diff filter: {_pre} -> {len(units)} units")

        total = len(units)
        mode = "single-shot"
        self._log("info", f"Enhancing {total} units (single-shot)", units=total)
        self._log("info", f"Model: {format_active_llm_label(CONTEXT_ENHANCEMENT_MODEL)}")
        cp_mgr = None
        restored_ids: set = set()
        if checkpoint_path:
            cp_dir = self._checkpoint_dir(checkpoint_path)
            cp_mgr = EnhanceCheckpointManager(cp_dir)
            cp_mgr.ensure_dir()
            restored_ids, _ = cp_mgr.restore_matching(
                units,
                lambda u: self.fingerprint_for(
                    u, mode=mode, analyzer_output_path=analyzer_output_path
                ),
            )
            self.stats["restored_from_checkpoint"] = len(restored_ids)
            if restored_ids:
                self._log("info", f"Restored {len(restored_ids)} units from checkpoints")
                if restored_callback:
                    restored_callback(len(restored_ids))

        def _process_one(unit):
            unit_start = time.monotonic()
            uid = unit.get("id", "?")
            if uid in restored_ids:
                detail = "restored"
            else:
                self.enhance_unit(unit, units_by_id)
                fp = self.fingerprint_for(
                    unit, mode=mode, analyzer_output_path=analyzer_output_path
                )
                if cp_mgr is not None:
                    enh = unit.get("enhancement") or {}
                    if not enh.get("provenance", {}).get("error"):
                        cp_mgr.save(
                            uid,
                            fingerprint=fp,
                            enhancement=enh,
                            usage={},
                        )
                detail = "ok" if not (unit.get("enhancement") or {}).get("provenance", {}).get(
                    "error"
                ) else "error"
            elapsed = time.monotonic() - unit_start
            return uid, detail, elapsed, threading.current_thread().name

        if workers <= 1:
            for unit in units:
                uid, detail, elapsed, _ = _process_one(unit)
                if progress_callback:
                    progress_callback(uid, detail, elapsed)
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(_process_one, unit): unit for unit in units}
                for future in as_completed(futures):
                    uid, detail, elapsed, worker = future.result()
                    if progress_callback:
                        progress_callback(uid, f"{detail}  [{worker}]", elapsed)

        # Recompute aggregate stats
        self.stats = {
            "units_processed": 0,
            "units_enhanced": 0,
            "related_units_total": 0,
            "unknowns_total": 0,
            "errors": 0,
            "restored_from_checkpoint": len(restored_ids),
        }
        for unit in units:
            enh = unit.get("enhancement") or {}
            self.stats["units_processed"] += 1
            if enh.get("provenance", {}).get("error"):
                self.stats["errors"] += 1
            else:
                self.stats["units_enhanced"] += 1
                self.stats["related_units_total"] += len(enh.get("related_units") or [])
                self.stats["unknowns_total"] += len(enh.get("unknowns") or [])

        token_stats = self.tracker.get_totals()
        dataset["metadata"] = dataset.get("metadata", {})
        dataset["metadata"]["llm_enhanced"] = True
        dataset["metadata"]["enhancement_mode"] = "single-shot"
        dataset["metadata"]["enhancement_schema_version"] = ENHANCEMENT_SCHEMA_VERSION
        dataset["metadata"]["llm_model"] = format_active_llm_label(CONTEXT_ENHANCEMENT_MODEL)
        dataset["metadata"]["enhancement_stats"] = self.stats
        dataset["metadata"]["token_usage"] = token_stats
        self._log(
            "info",
            "Enhancement complete",
            units=self.stats["units_processed"],
            details=self.stats,
        )
        for unit in dataset.get("units", []):
            unit.pop("_enhancement_usage", None)
        return dataset

    def enhance_dataset_agentic(
        self,
        dataset: dict,
        analyzer_output_path: str,
        repo_path: str = None,
        batch_size: int = 5,
        verbose: bool = False,
        checkpoint_path: str = None,
        progress_callback: Optional[Callable] = None,
        restored_callback: Optional[Callable] = None,
        workers: int = 10,
    ) -> dict:
        """Agentic enhancement with shared fingerprint + checkpoint manager."""
        units = dataset.get("units", [])
        if any("diff_selected" in u for u in units):
            _pre = len(units)
            units = [u for u in units if u.get("diff_selected")]
            self._log("info", f"Diff filter: {_pre} -> {len(units)} units")

        total = len(units)
        mode = "agentic"
        self._analyzer_output_hash = hash_file(analyzer_output_path)

        # Prefer call_graph.json beside analyzer output when not preloaded.
        if self.call_graph is None and analyzer_output_path:
            sibling = os.path.join(os.path.dirname(analyzer_output_path), "call_graph.json")
            self.call_graph = _load_call_graph(sibling) or self.call_graph

        cp_mgr = None
        restored_ids: set = set()
        usage_by_id: dict = {}
        if checkpoint_path:
            cp_dir = self._checkpoint_dir(checkpoint_path)
            cp_mgr = EnhanceCheckpointManager(cp_dir)
            cp_mgr.ensure_dir()
            restored_ids, usage_by_id = cp_mgr.restore_matching(
                units,
                lambda u: self.fingerprint_for(
                    u, mode=mode, analyzer_output_path=analyzer_output_path
                ),
            )
            self.stats["restored_from_checkpoint"] = len(restored_ids)
            if restored_ids:
                self._log(
                    "info",
                    f"Restored {len(restored_ids)} already-processed units from checkpoints",
                    units=len(restored_ids),
                )
                if restored_callback:
                    restored_callback(len(restored_ids))

        _summary_completed = len(restored_ids)
        _summary_errors = 0
        _summary_error_breakdown: dict = {}
        _summary_input_tokens = sum(u.get("input_tokens", 0) for u in usage_by_id.values())
        _summary_output_tokens = sum(u.get("output_tokens", 0) for u in usage_by_id.values())
        _summary_cost_usd = sum(u.get("cost_usd", 0.0) for u in usage_by_id.values())

        if cp_mgr is not None:
            if _summary_input_tokens or _summary_output_tokens:
                self.tracker.add_prior_usage(
                    _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
                )
            cp_mgr.write_summary(
                total,
                _summary_completed,
                _summary_errors,
                _summary_error_breakdown,
                phase="in_progress",
                usage={
                    "input_tokens": _summary_input_tokens,
                    "output_tokens": _summary_output_tokens,
                    "cost_usd": round(_summary_cost_usd, 6),
                },
            )

        remaining = total - len(restored_ids)
        self._log(
            "info",
            f"Enhancing {remaining} units with agentic analysis "
            f"({len(restored_ids)} already done)",
            units=remaining,
        )
        self._log("info", f"Model: {format_active_llm_label(CONTEXT_ENHANCEMENT_MODEL)}")
        if cp_mgr is not None:
            self._log("info", f"Checkpoint dir: {cp_mgr.dir}")

        self._log("info", f"Loading repository index from {analyzer_output_path}")
        index = load_index_from_file(analyzer_output_path, repo_path)
        stats = index.get_statistics()
        self._log(
            "info",
            f"Indexed {stats['total_functions']} functions from {stats['total_files']} files",
        )

        shared_client = get_shared_llm_client()
        units_to_process = [
            unit for unit in units if unit.get("id") not in restored_ids
        ]

        def _enhance_one(unit):
            unit_id = unit.get("id")
            unit_start = time.monotonic()
            detail = "ok"
            try:
                enhance_unit_with_agent(
                    unit,
                    index,
                    self.tracker,
                    verbose,
                    client=shared_client,
                    reachability_status=unit.get("reachability"),
                )
                if (unit.get("enhancement") or {}).get("provenance", {}).get("error"):
                    detail = "error"
            except Exception as e:
                detail = "error"
                error_info = _build_error_info(e)
                self._log(
                    "error",
                    "Error processing unit",
                    unit_id=unit_id,
                    error=error_info.get("message", safe_exception_message(e)),
                    error_type=error_info.get("type", "unknown"),
                )
                unit["enhancement"] = empty_enhancement(
                    mode="agentic",
                    model=CONTEXT_ENHANCEMENT_MODEL,
                    error=error_info,
                )
                unit["_enhancement_usage"] = {}

            if cp_mgr is not None and detail != "error":
                fp = self.fingerprint_for(
                    unit, mode=mode, analyzer_output_path=analyzer_output_path
                )
                usage = unit.get("_enhancement_usage") or {}
                prov = (unit.get("enhancement") or {}).get("provenance") or {}
                if not usage:
                    usage = {
                        "input_tokens": prov.get("input_tokens", 0),
                        "output_tokens": prov.get("output_tokens", 0),
                        "cost_usd": prov.get("cost_usd", 0.0),
                    }
                cp_mgr.save(
                    unit_id,
                    fingerprint=fp,
                    enhancement=unit.get("enhancement") or {},
                    usage=usage,
                )

            elapsed = time.monotonic() - unit_start
            return unit_id or "?", detail, elapsed, threading.current_thread().name

        def _update_summary(detail, unit):
            nonlocal _summary_completed, _summary_errors, _summary_error_breakdown
            nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
            if cp_mgr is None:
                return
            if detail == "error":
                _summary_errors += 1
                err = (unit.get("enhancement") or {}).get("provenance", {}).get("error", {})
                err_type = err.get("type", "unknown") if isinstance(err, dict) else "unknown"
                _summary_error_breakdown[err_type] = (
                    _summary_error_breakdown.get(err_type, 0) + 1
                )
            else:
                _summary_completed += 1
            usage = unit.get("_enhancement_usage") or {}
            prov = (unit.get("enhancement") or {}).get("provenance") or {}
            _summary_input_tokens += usage.get("input_tokens", 0) or prov.get(
                "input_tokens", 0
            )
            _summary_output_tokens += usage.get("output_tokens", 0) or prov.get(
                "output_tokens", 0
            )
            _summary_cost_usd += usage.get("cost_usd", 0.0) or prov.get("cost_usd", 0.0)
            cp_mgr.write_summary(
                total,
                _summary_completed,
                _summary_errors,
                _summary_error_breakdown,
                phase="in_progress",
                usage={
                    "input_tokens": _summary_input_tokens,
                    "output_tokens": _summary_output_tokens,
                    "cost_usd": round(_summary_cost_usd, 6),
                },
            )

        if workers <= 1:
            try:
                for unit in units_to_process:
                    uid, detail, elapsed, _ = _enhance_one(unit)
                    _update_summary(detail, unit)
                    if progress_callback:
                        progress_callback(uid, detail, elapsed)
            except KeyboardInterrupt:
                self._log("warning", "Interrupted — progress saved to checkpoints")
                return dataset
        else:
            executor = ThreadPoolExecutor(max_workers=workers)
            futures = {executor.submit(_enhance_one, unit): unit for unit in units_to_process}
            try:
                for future in as_completed(futures):
                    unit = futures[future]
                    uid, detail, elapsed, worker = future.result()
                    _update_summary(detail, unit)
                    if progress_callback:
                        progress_callback(uid, f"{detail}  [{worker}]", elapsed)
            except KeyboardInterrupt:
                self._log("warning", "Interrupted — cancelling pending work...")
                executor.shutdown(wait=False, cancel_futures=True)
                self._log("info", "Progress saved to checkpoints")
                return dataset
            executor.shutdown(wait=False)

        # Retry transient failures
        retryable_units = [
            unit
            for unit in units
            if is_retryable_error(
                (unit.get("enhancement") or {}).get("provenance", {}).get("error")
            )
        ]
        if retryable_units:
            rate_limiter = get_rate_limiter()
            backoff = rate_limiter.time_until_ready()
            if backoff > 0:
                self._log(
                    "info",
                    f"Retrying {len(retryable_units)} failed units "
                    f"(waiting {backoff:.0f}s for rate limit to clear)...",
                )
                rate_limiter.wait_if_needed()
            else:
                self._log(
                    "info",
                    f"Retrying {len(retryable_units)} failed units (transient errors)...",
                )
            for unit in retryable_units:
                unit.pop("enhancement", None)
                unit.pop("_enhancement_usage", None)
                uid, detail, elapsed, _ = _enhance_one(unit)
                if detail != "error":
                    _summary_errors = max(0, _summary_errors - 1)
                    _summary_completed += 1
                usage = unit.get("_enhancement_usage") or {}
                prov = (unit.get("enhancement") or {}).get("provenance") or {}
                _summary_input_tokens += usage.get("input_tokens", 0) or prov.get(
                    "input_tokens", 0
                )
                _summary_output_tokens += usage.get("output_tokens", 0) or prov.get(
                    "output_tokens", 0
                )
                _summary_cost_usd += usage.get("cost_usd", 0.0) or prov.get("cost_usd", 0.0)
                if cp_mgr is not None:
                    cp_mgr.write_summary(
                        total,
                        _summary_completed,
                        _summary_errors,
                        _summary_error_breakdown,
                        phase="in_progress",
                        usage={
                            "input_tokens": _summary_input_tokens,
                            "output_tokens": _summary_output_tokens,
                            "cost_usd": round(_summary_cost_usd, 6),
                        },
                    )
                if progress_callback:
                    progress_callback(uid, f"{detail} (retry)", elapsed)

        if cp_mgr is not None:
            cp_mgr.write_summary(
                total,
                _summary_completed,
                _summary_errors,
                _summary_error_breakdown,
                phase="done",
                usage={
                    "input_tokens": _summary_input_tokens,
                    "output_tokens": _summary_output_tokens,
                    "cost_usd": round(_summary_cost_usd, 6),
                },
            )

        agentic_stats = self._compute_agentic_stats(units)
        token_stats = self.tracker.get_totals()
        dataset["metadata"] = dataset.get("metadata", {})
        dataset["metadata"]["agentic_enhanced"] = True
        dataset["metadata"]["enhancement_mode"] = "agentic"
        dataset["metadata"]["enhancement_schema_version"] = ENHANCEMENT_SCHEMA_VERSION
        dataset["metadata"]["agentic_stats"] = agentic_stats
        dataset["metadata"]["token_usage"] = token_stats
        self._log(
            "info",
            "Agentic enhancement complete",
            units=agentic_stats["units_processed"],
            details=agentic_stats,
        )
        self._log(
            "info",
            "Token usage",
            input_tokens=token_stats["total_input_tokens"],
            output_tokens=token_stats["total_output_tokens"],
            total_tokens=token_stats["total_tokens"],
            cost=format_cost(
                token_stats["total_cost_usd"],
                resolve_display_currency(token_stats.get("cost_currency")),
            ),
        )
        for unit in dataset.get("units", []):
            unit.pop("_enhancement_usage", None)
        return dataset

    @staticmethod
    def _compute_agentic_stats(units: list) -> dict:
        stats = {
            "units_processed": 0,
            "units_with_context": 0,
            "total_iterations": 0,
            "related_units_total": 0,
            "unknowns_total": 0,
            "errors": 0,
            "error_summary": {},
        }
        for unit in units:
            enh = unit.get("enhancement")
            if not enh:
                continue
            err = (enh.get("provenance") or {}).get("error")
            if err:
                stats["errors"] += 1
                err_type = err.get("type", "unknown") if isinstance(err, dict) else "unknown"
                stats["error_summary"][err_type] = stats["error_summary"].get(err_type, 0) + 1
                continue
            stats["units_processed"] += 1
            related = enh.get("related_units") or []
            if related:
                stats["units_with_context"] += 1
                stats["related_units_total"] += len(related)
            stats["unknowns_total"] += len(enh.get("unknowns") or [])
            stats["total_iterations"] += (enh.get("provenance") or {}).get("iterations", 0)
        return stats

    def get_token_stats(self) -> dict:
        return self.tracker.get_totals()

    def get_last_call_stats(self) -> dict:
        return self.client.get_last_call()


def main():
    parser = argparse.ArgumentParser(
        description="Enhance parser output with neutral LLM context"
    )
    parser.add_argument("input", help="Input dataset JSON file")
    parser.add_argument("-o", "--output", help="Output file path (default: overwrites input)")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--agentic", action="store_true")
    parser.add_argument("--analyzer-output", help="Path to analyzer_output.json")
    parser.add_argument("--repo-path", help="Repository root path")
    parser.add_argument("--call-graph", help="Path to call_graph.json")
    parser.add_argument("--app-context", help="Path to application_context.json")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--checkpoint", help="Checkpoint directory for save/resume")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        logging.error(f"Error: Input file not found: {input_path}")
        return 1

    dataset = read_json(input_path)
    enhancer = ContextEnhancer(
        call_graph_path=args.call_graph,
        app_context_path=args.app_context,
    )

    if args.agentic:
        if not args.analyzer_output:
            logging.error("Error: --analyzer-output is required for agentic mode")
            return 1
        analyzer_path = Path(args.analyzer_output)
        if not analyzer_path.exists():
            logging.error(f"Error: Analyzer output not found: {analyzer_path}")
            return 1
        enhanced = enhancer.enhance_dataset_agentic(
            dataset,
            analyzer_output_path=str(analyzer_path),
            repo_path=args.repo_path,
            batch_size=args.batch_size,
            verbose=args.verbose,
            checkpoint_path=args.checkpoint,
        )
    else:
        enhanced = enhancer.enhance_dataset(
            dataset,
            batch_size=args.batch_size,
            checkpoint_path=args.checkpoint,
            analyzer_output_path=args.analyzer_output,
        )

    output_path = Path(args.output) if args.output else input_path
    write_json(output_path, enhanced)
    logging.info(f"Enhanced dataset written to: {output_path}")
    return 0


if __name__ == "__main__":
    exit(main())
