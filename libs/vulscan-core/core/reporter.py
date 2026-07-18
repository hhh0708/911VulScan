"""
Report generation wrapper.

Wraps the existing report generators:
- generate_report.py   — HTML report with Chart.js
- export_csv.py        — CSV export
- report/generator.py  — LLM-based summary and disclosure documents

Also provides ``build_pipeline_output()`` which assembles analysis results
into the ``pipeline_output.json`` format consumed by ``python -m report``
and ``run_dynamic_tests()``.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.schemas import ReportResult, UsageInfo
from utilities.file_io import open_utf8, read_json, write_json
from utilities.llm_pricing import format_cost, resolve_display_currency, get_active_currency
from utilities.safe_filename import safe_filename

# Root of vulscan-core
_CORE_ROOT = Path(__file__).parent.parent


def _load_diff_metadata(scan_dir: str) -> dict | None:
    """Return a summary dict if this scan dir contains a diff_manifest.json.

    Combines fields from diff_manifest.json and diff_filter.report.json so the
    HTML/report consumers have one place to read PR/incremental metadata.
    """
    manifest_path = os.path.join(scan_dir, "diff_manifest.json")
    if not os.path.exists(manifest_path):
        return None
    try:
        manifest = read_json(manifest_path)
    except (json.JSONDecodeError, OSError):
        return None
    out = {
        "mode": "incremental",
        "base_ref": manifest.get("base_ref"),
        "base_sha": manifest.get("base_sha"),
        "head_sha": manifest.get("head_sha"),
        "scope": manifest.get("scope"),
        "pr_number": manifest.get("pr_number") or None,
        "changed_files": len(manifest.get("changed_files") or []),
    }
    filter_report = os.path.join(scan_dir, "diff_filter.report.json")
    if os.path.exists(filter_report):
        try:
            stats = read_json(filter_report)
            out["units_in_diff"] = stats.get("selected")
            out["units_total_parsed"] = stats.get("total")
            out["callers_added"] = stats.get("callers_added") or 0
            out["fallback_file_match"] = stats.get("fallback_file_match") or 0
        except (json.JSONDecodeError, OSError):
            pass
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Map language hints to the code-fence language tag used in Markdown.
_FENCE_LANG = {
    "python": "python",
    "py": "python",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "go": "go",
    "golang": "go",
    "java": "java",
    "ruby": "ruby",
    "rb": "ruby",
    "php": "php",
    "rust": "rust",
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "csharp": "csharp",
    "c#": "csharp",
}


def _build_vulnerable_code_section(file_path: str, code: str, language: str | None) -> str:
    """Build a pre-rendered Markdown `## Vulnerable Code` section.

    The disclosure generator splices this verbatim into the LLM prompt so the
    model cannot rewrite the snippet. Prior behaviour (asking the LLM for a
    "minimal code snippet") produced fabricated code in DISCLOSURE_01/05.
    """
    if not code:
        return ""
    fence_lang = _FENCE_LANG.get((language or "").lower(), "")
    return (
        "## 漏洞代码\n\n"
        f"`{file_path}`：\n\n"
        f"```{fence_lang}\n{code}\n```"
    )


def _target_code_from_stage2(stage2: dict | None) -> str:
    """Return verbatim target code from Stage 2 evidence, if present."""
    for ev in (stage2 or {}).get("evidence") or []:
        if not isinstance(ev, dict) or ev.get("kind") != "target_code":
            continue
        content = ev.get("content")
        code = content.get("code") if isinstance(content, dict) else None
        if isinstance(code, str) and code.strip():
            return code
    return ""


def _attach_vulnerable_code_sections(artifact: dict, *, language: str | None) -> None:
    """Attach a pre-rendered, verbatim Vulnerable Code section to each finding.

    Pulls Stage 2 ``target_code`` evidence through ``_build_vulnerable_code_section``
    so report/generator.py can splice the real snippet into the LLM output (see
    ``_splice_code_section``) instead of letting the LLM rewrite it. Also hoists
    ``stage1_detection.location`` to the finding top level for report consumers.
    Mutates findings in place so every bucket view sees the same dicts.
    """
    fence_language = language or (artifact.get("repository") or {}).get("language")
    for finding in artifact.get("findings") or []:
        s1 = finding.get("stage1_detection") or {}
        location = s1.get("location") or finding.get("location") or {}
        if location and not finding.get("location"):
            finding["location"] = dict(location)
        if finding.get("vulnerable_code_section"):
            continue
        code = _target_code_from_stage2(finding.get("stage2_verification"))
        if not code:
            continue
        section = _build_vulnerable_code_section(
            location.get("file") or "unknown", code, fence_language
        )
        if section:
            finding["vulnerable_code_section"] = section


# ---------------------------------------------------------------------------
# Deduplication — collapse caller/callee pairs (canonical call graph only)
# ---------------------------------------------------------------------------

def _route_key(record: dict) -> str:
    return record.get("route_key") or record.get("unit_id") or ""


def _finding_id_for(record: dict) -> str | None:
    s2 = record.get("stage2_verification") or {}
    return s2.get("finding_id") or record.get("finding_id")


def _reverse_adjacency_from_resolved(resolved_edges: list[dict]) -> dict[str, list[str]]:
    """Build callee → callers map from canonical resolved_edges."""
    reverse: dict[str, list[str]] = {}
    for edge in resolved_edges or []:
        if not isinstance(edge, dict):
            continue
        caller = edge.get("caller")
        callee = edge.get("callee")
        if caller and callee:
            reverse.setdefault(callee, []).append(caller)
    return reverse


def _source_sink_identity(record: dict) -> tuple[str, str]:
    s1 = record.get("stage1_detection") or {}
    source = s1.get("source") or record.get("source") or ""
    sink = s1.get("sink") or record.get("sink") or ""
    return str(source), str(sink)


def _evidence_ids_for(record: dict) -> set[str]:
    ids: set[str] = set()
    s2 = record.get("stage2_verification") or {}
    for eid in record.get("evidence_ids") or s2.get("evidence_ids") or []:
        if eid:
            ids.add(str(eid))
    for ev in s2.get("evidence") or []:
        if isinstance(ev, dict) and ev.get("evidence_id"):
            ids.add(str(ev["evidence_id"]))
    return ids


def _dedup_caller_callee(
    confirmed: list[dict],
    all_results: list[dict],
    call_graph_path: str,
) -> tuple[list[dict], set[str]]:
    """Collapse callee into caller when source+sink, evidence, and call edge align.

    Uses canonical ``nodes`` + ``resolved_edges`` only (never ``reverse_call_graph``).
    Callees merged into a caller are removed from the primary list but their
    ``finding_id`` and ``evidence_ids`` are preserved on the caller via
    ``merge_provenance`` for reversible unmerge.

    Returns:
        ``(deduped_findings, removed_unit_ids)``
    """
    if not os.path.isfile(call_graph_path):
        return confirmed, set()

    try:
        from utilities.call_graph.schema import normalize_call_graph

        cg_data = read_json(call_graph_path)
        doc = normalize_call_graph(cg_data)
    except (json.JSONDecodeError, OSError, ImportError):
        return confirmed, set()

    nodes = doc.get("nodes") or {}
    reverse_cg = _reverse_adjacency_from_resolved(doc.get("resolved_edges") or [])

    by_key = {_route_key(f): f for f in confirmed}

    merge_into: dict[str, str] = {}
    for callee_key, callers in reverse_cg.items():
        if len(callers) != 1:
            continue
        caller_key = callers[0]
        if nodes and (callee_key not in nodes or caller_key not in nodes):
            continue
        caller = by_key.get(caller_key)
        callee = by_key.get(callee_key)
        if not caller or not callee:
            continue
        caller_ss = _source_sink_identity(caller)
        callee_ss = _source_sink_identity(callee)
        # Require non-empty identical source+sink (empty≠empty must not merge).
        if not caller_ss[0] or not caller_ss[1] or caller_ss != callee_ss:
            continue
        caller_ev = _evidence_ids_for(caller)
        callee_ev = _evidence_ids_for(callee)
        if not caller_ev or not callee_ev or not (caller_ev & callee_ev):
            continue
        merge_into[callee_key] = caller_key

    if not merge_into:
        return confirmed, set()

    absorbed: dict[str, dict] = {}
    for callee_key, caller_key in merge_into.items():
        callee = by_key.get(callee_key)
        caller = by_key.get(caller_key)
        if not callee or not caller:
            continue
        entry = absorbed.setdefault(
            caller_key,
            {
                "merged_from_unit_ids": [],
                "merged_from_finding_ids": [],
                "merged_from_evidence_ids": [],
            },
        )
        entry["merged_from_unit_ids"].append(callee_key)
        for fid in (_finding_id_for(callee), _finding_id_for(caller)):
            if fid and fid not in entry["merged_from_finding_ids"]:
                entry["merged_from_finding_ids"].append(fid)
        for eid in sorted(_evidence_ids_for(caller) | _evidence_ids_for(callee)):
            if eid not in entry["merged_from_evidence_ids"]:
                entry["merged_from_evidence_ids"].append(eid)

    deduped: list[dict] = []
    removed = 0
    for f in confirmed:
        rk = _route_key(f)
        if rk in merge_into:
            removed += 1
            continue
        out = dict(f)
        if rk in absorbed:
            prov = dict(absorbed[rk])
            out["merge_provenance"] = prov
            # Fold merged IDs into canonical evidence_ids (not provenance-only).
            eids = list(out.get("evidence_ids") or [])
            for eid in prov.get("merged_from_evidence_ids") or []:
                if eid and eid not in eids:
                    eids.append(eid)
            out["evidence_ids"] = eids
            s2 = out.get("stage2_verification")
            if isinstance(s2, dict):
                s2 = dict(s2)
                s2_eids = list(s2.get("evidence_ids") or [])
                for eid in prov.get("merged_from_evidence_ids") or []:
                    if eid and eid not in s2_eids:
                        s2_eids.append(eid)
                s2["evidence_ids"] = s2_eids
                out["stage2_verification"] = s2
        deduped.append(out)

    if removed:
        print(
            f"[Report] Deduplicated {removed} caller/callee finding(s)",
            file=sys.stderr,
        )
    return deduped, set(merge_into.keys())


def _apply_display_dedup(
    artifact: dict,
    *,
    merged_callees: set[str],
    merge_by_unit: dict[str, dict],
) -> dict:
    """Remove merged callees from display findings only; keep stage metrics intact.

    Merged finding_id / unit_id / evidence_id are folded into the survivor's
    canonical ``evidence_ids`` (and recorded in ``merge_provenance``).
    """
    if not merged_callees and not merge_by_unit:
        return artifact

    display: list[dict] = []
    for finding in artifact.get("findings") or []:
        uid = str(finding.get("unit_id") or "")
        if uid in merged_callees:
            continue
        out = dict(finding)
        prov = merge_by_unit.get(uid)
        if prov:
            out["merge_provenance"] = dict(prov)
            eids = list(out.get("evidence_ids") or [])
            for eid in prov.get("merged_from_evidence_ids") or []:
                if eid and eid not in eids:
                    eids.append(eid)
            out["evidence_ids"] = eids
        display.append(out)

    candidates: list[dict] = []
    rejected: list[dict] = []
    inconclusive: list[dict] = []
    errors: list[dict] = []
    for finding in display:
        state = finding.get("final_state")
        if state == "candidate":
            candidates.append(finding)
        elif state == "rejected":
            rejected.append(finding)
        elif state == "inconclusive":
            inconclusive.append(finding)
        elif state == "error":
            errors.append(finding)

    artifact = dict(artifact)
    artifact["findings"] = display
    artifact["candidates"] = candidates
    artifact["rejected"] = rejected
    artifact["inconclusive"] = inconclusive
    artifact["errors"] = errors
    unit_summary = dict(artifact.get("unit_summary") or {})
    unit_summary["with_findings"] = len(display)
    artifact["unit_summary"] = unit_summary
    return artifact


def _stage1_decision(result: dict) -> str:
    """Return canonical stage1 decision from ``decision`` or ``stage1_detection``."""
    if result.get("decision"):
        return str(result["decision"])
    s1 = result.get("stage1_detection") or {}
    if s1.get("decision"):
        return str(s1["decision"])
    return "no_finding"


def _load_reachability_from_scan_dir(scan_dir: str) -> dict[str, int] | None:
    """Load explicit reachability counts from dataset metadata or unit tags."""
    for name in ("dataset_enhanced.json", "dataset.json"):
        path = os.path.join(scan_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            dataset = read_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        meta = (dataset.get("metadata") or {}).get("reachability_filter") or {}
        if meta:
            return {
                "total_units": int(
                    meta.get("original_units") or len(dataset.get("units") or [])
                ),
                "reachable": int(meta.get("reachable_units") or 0),
                "unreachable": int(meta.get("unreachable_units") or 0),
                "unknown_reachability": int(meta.get("unknown_units") or 0),
            }
        units = dataset.get("units") or []
        if units and any(u.get("reachability") for u in units):
            counts = {"reachable": 0, "unreachable": 0, "unknown_reachability": 0}
            for unit in units:
                status = unit.get("reachability") or "unknown"
                if status == "reachable":
                    counts["reachable"] += 1
                elif status == "unreachable":
                    counts["unreachable"] += 1
                else:
                    counts["unknown_reachability"] += 1
            counts["total_units"] = len(units)
            return counts
    return None


def _reachability_counts_from_metrics(
    metrics: dict,
    scan_dir: str,
    total_fallback: int,
) -> tuple[dict[str, int], bool]:
    """Return reachability counts; second value is True when counts were unavailable."""
    explicit = _load_reachability_from_scan_dir(scan_dir)
    if explicit is not None:
        return explicit, False

    total = int(metrics.get("total_units") or metrics.get("total") or total_fallback)
    reachable = metrics.get("reachable")
    unknown = metrics.get("unknown_reachability")
    if reachable is not None and unknown is not None:
        return {
            "total_units": total,
            "reachable": int(reachable),
            "unreachable": int(metrics.get("unreachable") or 0),
            "unknown_reachability": int(unknown),
        }, False

    print(
        "[Report] Warning: reachability counts unavailable; using zeros "
        "(not inventing reachable=total or unknown=total).",
        file=sys.stderr,
    )
    return {
        "total_units": total,
        "reachable": 0,
        "unreachable": 0,
        "unknown_reachability": 0,
    }, True


def _stage1_record(result: dict) -> dict:
    uid = _route_key(result)
    s2 = result.get("stage2_verification") or {}
    return {
        "unit_id": uid,
        "finding_id": s2.get("finding_id") or result.get("finding_id") or f"f-{uid}",
        "decision": _stage1_decision(result),
        "candidate_type": result.get("candidate_type"),
        "cwe_id": result.get("cwe_id") or 0,
        "cwe_name": result.get("cwe_name"),
        "location": result.get("location")
        or {
            "file": uid.split(":")[0] if ":" in uid else "unknown",
            "function": uid,
        },
        "source": result.get("source") or "",
        "propagation": result.get("propagation") or "",
        "sink": result.get("sink") or "",
        "impact": result.get("impact") or "",
        "preconditions": result.get("preconditions") or [],
        "evidence_ids": result.get("evidence_ids") or s2.get("evidence_ids") or [],
        "evidence": result.get("evidence") or [],
    }


def _collect_evidence_lists(all_results: list[dict]) -> list[list[dict]]:
    lists: list[list[dict]] = []
    for result in all_results:
        s1_ev = result.get("evidence")
        if isinstance(s1_ev, list) and s1_ev:
            lists.append(s1_ev)
        s2 = result.get("stage2_verification") or {}
        evidence = s2.get("evidence")
        if isinstance(evidence, list) and evidence:
            lists.append(evidence)
    return lists


# ---------------------------------------------------------------------------
# Pipeline output builder
# ---------------------------------------------------------------------------

def _json_path(path: str) -> str:
    """Store filesystem paths with forward slashes for stable JSON on Windows."""
    return Path(path).resolve().as_posix()


def build_pipeline_output(
    results_path: str,
    output_path: str,
    repo_name: str | None = None,
    repo_url: str | None = None,
    language: str | None = None,
    commit_sha: str | None = None,
    application_type: str = "unavailable",
    processing_level: str | None = None,
    step_reports: list[dict] | None = None,
    repo_path: str | None = None,
) -> tuple[str, int, list[str]]:
    """Build FinalScanArtifact once after all enabled stages (incl. dynamic).

    Uses reducer + validation + external ``run_artifact_manifest.json``.
    Does not write legacy verdict fields. *application_type* is ignored.

    Returns:
        ``(output_path, findings_count, errors)``. Non-empty errors → partial/failed.
    """
    del application_type
    from core.final_artifact.finalize import write_final_scan_artifact
    from core.final_artifact.manifest import hash_file, make_entry
    from core.final_artifact.reducer import reduce_to_final_artifact

    print(f"[Report] Building FinalScanArtifact (pipeline_output.json)...", file=sys.stderr)

    experiment = read_json(results_path)
    # hash_file imported above — used when attaching source_artifact_hash
    all_results = experiment.get("results", [])
    metrics = experiment.get("metrics", {})

    scan_dir = os.path.dirname(os.path.abspath(results_path))
    call_graph_path = os.path.join(scan_dir, "call_graph.json")
    dynamic_path = os.path.join(scan_dir, "dynamic_test_results.json")

    def _is_stage2_confirmed(r: dict) -> bool:
        s2 = (r or {}).get("stage2_verification") or {}
        return (
            s2.get("decision") == "confirmed"
            and s2.get("execution_state") == "succeeded"
        )

    # Dedup is display-only: keep ALL stage1/stage2 records for metrics.
    confirmed = experiment.get("confirmed_findings")
    if confirmed is not None:
        confirmed = [r for r in confirmed if _is_stage2_confirmed(r)]
    else:
        confirmed = [r for r in all_results if _is_stage2_confirmed(r)]

    confirmed_deduped, merged_callees = _dedup_caller_callee(
        confirmed, all_results, call_graph_path
    )
    merge_by_unit: dict[str, dict] = {}
    for f in confirmed_deduped:
        rk = _route_key(f)
        if f.get("merge_provenance"):
            merge_by_unit[rk] = f["merge_provenance"]

    results_hash = ""
    try:
        results_hash = hash_file(results_path) if os.path.isfile(results_path) else ""
    except OSError:
        results_hash = ""

    stage1_results = []
    stage2_results = []
    for r in all_results:
        uid = _route_key(r)
        s1 = _stage1_record(r)
        if results_hash:
            s1["source_artifact_hash"] = results_hash
        stage1_results.append(s1)
        s2 = r.get("stage2_verification")
        if isinstance(s2, dict) and s2:
            s2_out = dict(s2)
            s2_out.setdefault("unit_id", uid)
            if results_hash:
                s2_out["source_artifact_hash"] = results_hash
            stage2_results.append(s2_out)

    dynamic_results: list[dict] = []
    dynamic_hash = ""
    if os.path.isfile(dynamic_path):
        try:
            dynamic_hash = hash_file(dynamic_path)
            dynamic_data = read_json(dynamic_path)
            for dyn in dynamic_data.get("results") or []:
                if isinstance(dyn, dict):
                    d = dict(dyn)
                    if dynamic_hash:
                        d["source_artifact_hash"] = dynamic_hash
                    dynamic_results.append(d)
        except (json.JSONDecodeError, OSError):
            pass

    reachability, reachability_missing = _reachability_counts_from_metrics(
        metrics, scan_dir, len(all_results)
    )

    costs: dict[str, dict] = {}
    durations: dict[str, float] = {}
    skipped_steps: list[str] = []
    if step_reports:
        for sr in step_reports:
            step = sr.get("step", "unknown")
            if sr.get("status") == "skipped":
                skipped_steps.append(step)
            if sr.get("cost_usd"):
                costs[step] = {"actual": sr["cost_usd"]}
            if sr.get("duration_seconds"):
                durations[step] = sr["duration_seconds"]

    evidence_lists = _collect_evidence_lists(all_results)
    artifact, reduce_errors = reduce_to_final_artifact(
        run_meta={
            "analysis_date": datetime.now(timezone.utc).isoformat(),
            "results_path": _json_path(results_path),
        },
        units=[{"id": _route_key(r)} for r in all_results],
        stage1_results=stage1_results,
        stage2_results=stage2_results,
        dynamic_results=dynamic_results,
        evidence_lists=evidence_lists,
        evidence_producer_stages=(
            ["results"] * len(evidence_lists) if results_hash else None
        ),
        evidence_source_hashes=(
            [results_hash] * len(evidence_lists) if results_hash else None
        ),
        reachability_counts=reachability,
        reachability_missing=reachability_missing,
        artifact_manifest=[],
        configuration={
            "scope": processing_level,
            "language": language or "",
        },
        repository={
            "name": repo_name or experiment.get("dataset", "unknown"),
            "url": repo_url or "",
            "language": language or "",
            "commit_sha": commit_sha,
        },
        provenance={
            "pipeline_stats": {
                "processing_level": processing_level,
                "costs": costs,
                "durations": durations,
                "skipped_steps": skipped_steps,
            },
        },
    )
    if reduce_errors:
        print(
            "[Report] FinalScanArtifact evidence/reduce errors (blocking write): "
            + "; ".join(reduce_errors),
            file=sys.stderr,
        )
        for err in reduce_errors:
            print(f"  - {err}", file=sys.stderr)
        return output_path, 0, list(reduce_errors)

    # Display-only dedup: stage1/stage2 metrics stay undeduped.
    before_dedup = len(artifact.get("findings") or [])
    artifact = _apply_display_dedup(
        artifact,
        merged_callees=merged_callees,
        merge_by_unit=merge_by_unit,
    )
    stats = (artifact.get("provenance") or {}).setdefault("pipeline_stats", {})
    stats["findings_before_display_dedup"] = before_dedup
    stats["findings_after_dedup"] = len(artifact.get("findings") or [])

    # Wire the anti-fabrication mechanism: pre-rendered verbatim code sections.
    _attach_vulnerable_code_sections(artifact, language=language)

    diff_meta = _load_diff_metadata(scan_dir)
    if diff_meta is not None:
        artifact["provenance"]["diff"] = diff_meta
        _banner = (
            f"[Report] Incremental scan: base={diff_meta.get('base_ref')}, "
            f"scope={diff_meta.get('scope')}, "
            f"{diff_meta.get('units_in_diff', '?')}/{diff_meta.get('units_total_parsed', '?')} units"
        )
        if diff_meta.get("pr_number"):
            _banner += f", PR #{diff_meta['pr_number']}"
        print(_banner, file=sys.stderr)

    if repo_path and os.path.isdir(repo_path):
        from utilities.advisory_lookup import scan_repo_advisories

        advisory_intel = scan_repo_advisories(repo_path)
        if advisory_intel:
            artifact["provenance"]["advisory_intel"] = advisory_intel

    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    # Upstream manifest: dataset, analyzer, call graph, app context,
    # enhanced dataset, Stage1/2 results, dynamic, step reports, scan manifest.
    upstream: list[dict] = []
    upstream_specs: list[tuple[str, str, str]] = [
        # (absolute_or_rel, relative_path_in_manifest, producer_stage)
        (results_path, os.path.basename(results_path), "analyze_or_verify"),
        (os.path.join(scan_dir, "dataset.json"), "dataset.json", "parse"),
        (
            os.path.join(scan_dir, "analyzer_output.json"),
            "analyzer_output.json",
            "parse",
        ),
        (os.path.join(scan_dir, "call_graph.json"), "call_graph.json", "parse"),
        (
            os.path.join(scan_dir, "application_context.json"),
            "application_context.json",
            "parse",
        ),
        (
            os.path.join(scan_dir, "dataset_enhanced.json"),
            "dataset_enhanced.json",
            "enhance",
        ),
        (
            os.path.join(scan_dir, "dynamic_test_results.json"),
            "dynamic_test_results.json",
            "dynamic",
        ),
        (os.path.join(scan_dir, "scan_manifest.json"), "scan_manifest.json", "scan"),
    ]
    # Prefer verified results when present as Stage 2 artifact.
    verified = os.path.join(scan_dir, "results_verified.json")
    if os.path.isfile(verified):
        upstream_specs.append(
            (verified, "results_verified.json", "verify")
        )
    for full, rel, stage in upstream_specs:
        if not os.path.isfile(full):
            continue
        try:
            upstream.append(
                make_entry(
                    relative_path=rel,
                    artifact_type="upstream",
                    schema_version="1.0",
                    sha256=hash_file(full),
                    producer_stage=stage,
                )
            )
        except OSError:
            continue
    # Step reports (*.report.json)
    try:
        for name in sorted(os.listdir(scan_dir)):
            if not name.endswith(".report.json"):
                continue
            full = os.path.join(scan_dir, name)
            if not os.path.isfile(full):
                continue
            upstream.append(
                make_entry(
                    relative_path=name,
                    artifact_type="upstream",
                    schema_version="1.0",
                    sha256=hash_file(full),
                    producer_stage="step_report",
                )
            )
    except OSError:
        pass

    # Ensure artifact lands at output_path name (usually pipeline_output.json)
    target_name = os.path.basename(output_path)
    if target_name != "pipeline_output.json":
        # write to requested path via finalize into output_dir then rename if needed
        pass

    artifact_path, _run_manifest, write_errors = write_final_scan_artifact(
        artifact,
        output_dir=output_dir,
        upstream_entries=upstream,
        producer_stage="finalize",
    )
    all_errors = list(reduce_errors) + list(write_errors)
    if all_errors:
        # Do not leave a silently-invalid complete artifact
        print(
            "[Report] FinalScanArtifact validation FAILED — "
            "reports must not treat this as complete.",
            file=sys.stderr,
        )
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return artifact_path, 0, all_errors

    if os.path.abspath(artifact_path) != os.path.abspath(output_path):
        import shutil

        shutil.copy2(artifact_path, output_path)

    findings_count = len(artifact.get("findings") or [])
    print(f"  pipeline_output.json: {findings_count} findings", file=sys.stderr)
    print(f"  Written to {output_path}", file=sys.stderr)
    print(f"  run_artifact_manifest.json written beside artifact", file=sys.stderr)

    return output_path, findings_count, []


def generate_html_report(*_args, **_kwargs) -> ReportResult:
    """Removed from the production path — HTML is rendered by the Go CLI."""
    raise RuntimeError(
        "HTML reports are generated by the Go CLI via report-data + FinalScanArtifact. "
        "Use 'vulscan report -f html' (do not call generate_html_report)."
    )


def generate_csv_report(
    artifact_path: str,
    output_path: str,
    *,
    dataset_path: str | None = None,
) -> ReportResult:
    """Export FinalScanArtifact findings to CSV (final_state sections only).

    *dataset_path* is ignored (kept only for call-site compatibility) and must
    not be required. Legacy verdict/safe/vulnerable columns are not emitted.
    """
    del dataset_path
    from core.final_artifact.csv_export import write_csv_from_artifact
    from core.final_artifact.finalize import load_and_validate_final_artifact

    print("[Report] Generating CSV report from FinalScanArtifact...", file=sys.stderr)
    artifact = load_and_validate_final_artifact(artifact_path)
    write_csv_from_artifact(artifact, output_path)
    print(f"  CSV report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="csv")


def _finding_unit_id(finding: dict) -> str:
    """Stable unit key for matching pipeline findings to verify checkpoints."""
    s1 = finding.get("stage1_detection") or {}
    location = s1.get("location") or finding.get("location") or {}
    return (
        finding.get("unit_id")
        or location.get("function")
        or location.get("route_key")
        or finding.get("route_key")
        or ""
    )


def _disclosure_label(finding: dict) -> str:
    s1 = finding.get("stage1_detection") or {}
    return (
        s1.get("candidate_type")
        or finding.get("short_name")
        or finding.get("name")
        or f"FINDING_{finding.get('finding_id', 'unknown')}"
    )


def _safe_disclosure_name(label: str) -> str:
    """Sanitize an LLM-controlled label for use in a disclosure filename."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(label).replace(" ", "_")).upper()
    return safe_filename(cleaned) or "FINDING"


def generate_summary_report(
    results_path: str,
    output_path: str,
    *,
    verified_unit_ids: set[str] | frozenset[str] | None = None,
) -> ReportResult:
    """Generate LLM-based summary report (Markdown).

    Calls report/generator.py directly (in-process) for proper cost tracking.

    When *verified_unit_ids* is empty and the summary file already exists,
    regeneration is skipped (typical verify resume with no new findings).
    """
    from report.generator import (
        generate_summary_report as _generate_summary,
        _summary_looks_complete,
    )
    from core.final_artifact.finalize import load_and_validate_final_artifact

    print("[Report] Generating summary report (LLM)...", file=sys.stderr)

    if (
        verified_unit_ids is not None
        and not verified_unit_ids
        and os.path.isfile(output_path)
        and os.path.getsize(output_path) > 0
    ):
        try:
            with open_utf8(output_path) as existing:
                existing_text = existing.read()
        except OSError:
            existing_text = ""
        if _summary_looks_complete(existing_text):
            print(f"  Summary report already exists — skipping: {output_path}",
                  file=sys.stderr)
            return ReportResult(
                output_path=output_path,
                format="summary",
                usage=_usage_to_info({
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "cost_usd": 0.0,
                }),
            )
        print(f"  Summary report incomplete — regenerating: {output_path}",
              file=sys.stderr)

    pipeline_data = load_and_validate_final_artifact(results_path)
    report_text, usage = _generate_summary(pipeline_data)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open_utf8(output_path, "w") as f:
        f.write(report_text)

    print(f"  Summary report: {output_path}", file=sys.stderr)
    currency = resolve_display_currency(usage.get("currency", usage.get("cost_currency")))
    print(
        f"  Cost: {format_cost(usage['cost_usd'], currency)} ({usage['total_tokens']:,} tokens)",
        file=sys.stderr,
    )

    # Record in global tracker so step_context picks it up
    _record_usage_in_tracker(usage)

    return ReportResult(output_path=output_path, format="summary", usage=_usage_to_info(usage))


def generate_disclosure_docs(
    results_path: str,
    output_dir: str,
    *,
    verified_unit_ids: set[str] | frozenset[str] | None = None,
) -> ReportResult:
    """Generate per-vulnerability disclosure documents.

    Calls report/generator.py directly (in-process) for proper cost tracking.

    When *verified_unit_ids* is non-empty (typical verify resume), only
    findings verified in that run get new LLM documents. When it is empty,
    only missing files on disk are generated.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from core.final_artifact.finalize import load_and_validate_final_artifact
    from core.final_artifact.validate import CONFIRMED_FINAL_STATES
    from report.generator import (
        generate_disclosure as _generate_disclosure,
        _merge_usage,
    )

    print("[Report] Generating disclosure documents (LLM)...", file=sys.stderr)

    pipeline_data = load_and_validate_final_artifact(results_path)

    os.makedirs(output_dir, exist_ok=True)

    product_name = pipeline_data["repository"]["name"]

    confirmed_findings = [
        f for f in pipeline_data.get("findings", [])
        if f.get("final_state") in CONFIRMED_FINAL_STATES
    ]
    confirmed = [
        (i, finding)
        for i, finding in enumerate(confirmed_findings, 1)
    ]

    items = []
    skipped_existing = 0
    for i, finding in confirmed:
        label = _disclosure_label(finding)
        safe_name = _safe_disclosure_name(label)
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        filepath = os.path.join(output_dir, filename)
        unit_id = _finding_unit_id(finding)
        if verified_unit_ids:
            if unit_id not in verified_unit_ids:
                continue
        elif os.path.isfile(filepath) and os.path.getsize(filepath) > 0:
            skipped_existing += 1
            continue
        items.append((i, finding, filepath))

    all_usages = []
    count = 0

    if not confirmed:
        print("  No confirmed vulnerabilities to generate disclosures for.", file=sys.stderr)
    elif not items:
        if skipped_existing:
            print(
                f"  All {skipped_existing} static disclosures already exist — skipping.",
                file=sys.stderr,
            )
        else:
            print("  No matching confirmed findings for disclosure generation.",
                  file=sys.stderr)
    else:
        if verified_unit_ids:
            print(
                f"  Generating {len(items)} disclosures for newly verified "
                f"findings (8 workers)...",
                file=sys.stderr,
            )
        elif skipped_existing:
            print(
                f"  Filling {len(items)} missing disclosures "
                f"({skipped_existing} already exist, 8 workers)...",
                file=sys.stderr,
            )
        else:
            print(f"  Generating {len(items)} disclosures in parallel (8 workers)...",
                  file=sys.stderr)

        def _one(args):
            i, finding, filepath = args
            disclosure_text, usage = _generate_disclosure(finding, product_name)
            with open_utf8(filepath, "w") as f:
                f.write(disclosure_text)
            return _disclosure_label(finding), filepath, usage

        executor = ThreadPoolExecutor(max_workers=8)
        futures = {executor.submit(_one, item): item for item in items}
        try:
            for future in as_completed(futures):
                name, filepath, usage = future.result()
                all_usages.append(usage)
                count += 1
                print(f"  [{count}/{len(items)}] {name} -> {filepath}",
                      file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[Report] Interrupted — cancelling pending disclosures...",
                  file=sys.stderr, flush=True)
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        executor.shutdown(wait=False)

    merged_usage = _merge_usage(all_usages) if all_usages else {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0}

    print(f"  Disclosures: {count} files in {output_dir}", file=sys.stderr)
    currency = resolve_display_currency(merged_usage.get("currency", merged_usage.get("cost_currency")))
    print(
        f"  Cost: {format_cost(merged_usage['cost_usd'], currency)} ({merged_usage['total_tokens']:,} tokens)",
        file=sys.stderr,
    )

    # Record in global tracker so step_context picks it up
    _record_usage_in_tracker(merged_usage)

    return ReportResult(output_path=output_dir, format="disclosure", usage=_usage_to_info(merged_usage))


def generate_dynamic_disclosure_docs(
    pipeline_path: str,
    output_dir: str,
    *,
    language: str | None = None,
    tested_finding_ids: set[str] | frozenset[str] | None = None,
) -> ReportResult:
    """Generate per-finding Chinese dynamic-verification explanation documents.

    Reads ``dynamic_test_results.json`` from *output_dir* and merges each
    result with the matching pipeline finding.

    When *tested_finding_ids* is non-empty (typical resume run), only those
    findings get new LLM documents. When it is empty, only missing files on
    disk are generated so a prior interrupted disclosure pass can finish
    without redoing the full set.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from core.final_artifact.finalize import load_and_validate_final_artifact
    from report.generator import (
        generate_dynamic_disclosure as _generate_dynamic_disclosure,
        _merge_usage,
    )

    print("[Dynamic Test] Generating dynamic verification documents (LLM)...",
          file=sys.stderr)

    pipeline_data = load_and_validate_final_artifact(pipeline_path)

    dynamic_path = os.path.join(output_dir, "dynamic_test_results.json")
    if not os.path.isfile(dynamic_path):
        print("  No dynamic_test_results.json — skipping dynamic disclosures.",
              file=sys.stderr)
        return ReportResult(
            output_path=output_dir,
            format="dynamic_disclosure",
            usage=_usage_to_info({"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0}),
        )

    dynamic_data = read_json(dynamic_path)
    results_by_id = {
        r.get("finding_id"): r
        for r in dynamic_data.get("results", [])
        if r.get("finding_id")
    }
    if not results_by_id:
        print("  No dynamic test results — skipping dynamic disclosures.",
              file=sys.stderr)
        return ReportResult(
            output_path=output_dir,
            format="dynamic_disclosure",
            usage=_usage_to_info({"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0}),
        )

    disclosures_dir = os.path.join(output_dir, "disclosures")
    os.makedirs(disclosures_dir, exist_ok=True)

    product_name = pipeline_data["repository"]["name"]
    lang = language or pipeline_data.get("repository", {}).get("language")
    # Canonical FinalScanArtifact findings are keyed by `finding_id` (`id` is
    # the pre-Phase-11 legacy key — kept only as a fallback).
    findings_by_id = {
        (f.get("finding_id") or f.get("id")): f
        for f in pipeline_data.get("findings", [])
        if f.get("finding_id") or f.get("id")
    }

    items = []
    skipped_existing = 0
    for i, (finding_id, dyn) in enumerate(sorted(results_by_id.items()), 1):
        finding = findings_by_id.get(finding_id)
        if not finding:
            continue
        safe_name = _safe_disclosure_name(_disclosure_label(finding))
        filename = f"DYNAMIC_DISCLOSURE_{i:02d}_{safe_name}.md"
        filepath = os.path.join(disclosures_dir, filename)
        if tested_finding_ids:
            if finding_id not in tested_finding_ids:
                continue
        elif os.path.isfile(filepath) and os.path.getsize(filepath) > 0:
            skipped_existing += 1
            continue
        items.append((i, finding, dyn, filepath))

    all_usages: list[dict] = []
    count = 0

    if not items:
        if skipped_existing:
            print(
                f"  All {skipped_existing} dynamic disclosures already exist — skipping.",
                file=sys.stderr,
            )
        else:
            print("  No matching pipeline findings for dynamic results.", file=sys.stderr)
    else:
        if tested_finding_ids:
            print(
                f"  Generating {len(items)} dynamic verification docs for "
                f"newly tested findings (8 workers)...",
                file=sys.stderr,
            )
        elif skipped_existing:
            print(
                f"  Filling {len(items)} missing dynamic verification docs "
                f"({skipped_existing} already exist, 8 workers)...",
                file=sys.stderr,
            )
        else:
            print(f"  Generating {len(items)} dynamic verification docs (8 workers)...",
                  file=sys.stderr)

        def _one(args):
            idx, finding, dyn, filepath = args
            text, usage = _generate_dynamic_disclosure(
                finding, dyn, product_name, language=lang
            )
            with open_utf8(filepath, "w") as f:
                f.write(text)
            return finding.get("finding_id") or finding.get("id"), filepath, usage

        executor = ThreadPoolExecutor(max_workers=8)
        futures = {executor.submit(_one, item): item for item in items}
        try:
            for future in as_completed(futures):
                fid, filepath, usage = future.result()
                all_usages.append(usage)
                count += 1
                print(f"  [{count}/{len(items)}] {fid} -> {filepath}",
                      file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[Dynamic Test] Interrupted — cancelling pending dynamic disclosures...",
                  file=sys.stderr, flush=True)
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        executor.shutdown(wait=False)

    merged_usage = _merge_usage(all_usages) if all_usages else {
        "input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0,
    }
    print(f"  Dynamic disclosures: {count} files in {disclosures_dir}", file=sys.stderr)
    currency = resolve_display_currency(merged_usage.get("currency", merged_usage.get("cost_currency")))
    print(
        f"  Cost: {format_cost(merged_usage['cost_usd'], currency)} ({merged_usage['total_tokens']:,} tokens)",
        file=sys.stderr,
    )
    _record_usage_in_tracker(merged_usage)

    return ReportResult(
        output_path=disclosures_dir,
        format="dynamic_disclosure",
        usage=_usage_to_info(merged_usage),
    )


def _record_usage_in_tracker(usage: dict):
    """Record usage in the global TokenTracker so step_context captures it."""
    try:
        from utilities.llm_client import get_global_tracker
        from utilities.llm_config import resolve_model
        from report.generator import MODEL as REPORT_MODEL

        tracker = get_global_tracker()
        if usage.get("total_tokens", 0) > 0:
            tracker.record_call(
                model=resolve_model(REPORT_MODEL),
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
            )
    except Exception:
        pass  # Best effort — don't break report generation


def _usage_to_info(usage: dict):
    """Convert a usage dict to a UsageInfo dataclass."""
    return UsageInfo(
        total_calls=1,
        total_input_tokens=usage.get("input_tokens", 0),
        total_output_tokens=usage.get("output_tokens", 0),
        total_tokens=usage.get("total_tokens", 0),
        total_cost_usd=usage.get("cost_usd", 0.0),
        cost_currency=resolve_display_currency(
            usage.get("currency", usage.get("cost_currency"))
        ),
    )
