"""
Report Generator - generates security reports and disclosure documents from pipeline output.

Returns (text, usage_dict) tuples from LLM functions so callers can track costs.
"""

import json
import os
import re
import sys
from pathlib import Path

import anthropic

from .schema import validate_pipeline_output, ValidationError
from utilities.file_io import open_utf8, read_json
from utilities.llm_config import resolve_llm_config, resolve_model
from utilities.llm_pricing import format_cost, get_active_currency, get_model_pricing, resolve_display_currency
from utilities.model_registry import ModelRole, model_for
from utilities.llm_client import get_shared_llm_client
from utilities.safe_dotenv import load_scan_safe_dotenv
from utilities.safe_filename import safe_filename

load_scan_safe_dotenv()

PROMPTS_DIR = Path(__file__).parent / "prompts"
# Internal Claude id; resolved to provider model at API/pricing time.
MODEL = model_for(ModelRole.SECONDARY)


def _env_int(name: str, default: int) -> int:
    """Read an int env var at import time, falling back on invalid values."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"Warning: invalid {name}={raw!r}; using {default}", file=sys.stderr)
        return default


# Output token limits for LLM report generation. Summary LLM output ends at
# Skipped Steps; vulnerability tables are appended deterministically in code.
SUMMARY_MAX_TOKENS = _env_int("VULSCAN_REPORT_SUMMARY_MAX_TOKENS", 8192)
DISCLOSURE_MAX_TOKENS = _env_int("VULSCAN_REPORT_DISCLOSURE_MAX_TOKENS", 8192)
DYNAMIC_DISCLOSURE_MAX_TOKENS = _env_int(
    "VULSCAN_REPORT_DYNAMIC_DISCLOSURE_MAX_TOKENS", 8192
)


def _extract_usage(response, model: str | None = None) -> dict:
    """Extract usage info from an LLM API response."""
    usage = response.usage
    billed = resolve_model(model or MODEL)
    pricing = get_model_pricing(billed)
    input_cost = (usage.input_tokens / 1_000_000) * pricing["input"]
    output_cost = (usage.output_tokens / 1_000_000) * pricing["output"]
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.input_tokens + usage.output_tokens,
        "cost_usd": round(input_cost + output_cost, 6),
        "currency": pricing["currency"],
    }


def _extract_response_text(response) -> str:
    """Return concatenated text blocks from an LLM response."""
    parts: list[str] = []
    for block in getattr(response, "content", None) or []:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if text:
            parts.append(str(text))
    if parts:
        return "\n".join(parts)
    stop = getattr(response, "stop_reason", "?")
    raise RuntimeError(
        f"LLM returned no text content (stop_reason={stop}, blocks={len(getattr(response, 'content', None) or [])})"
    )


def _merge_usage(usages: list[dict]) -> dict:
    """Merge multiple usage dicts into one."""
    merged = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cost_usd": 0.0,
        "currency": None,
    }
    for u in usages:
        merged["input_tokens"] += u["input_tokens"]
        merged["output_tokens"] += u["output_tokens"]
        merged["total_tokens"] += u["total_tokens"]
        merged["cost_usd"] = round(merged["cost_usd"] + u["cost_usd"], 6)
        if u.get("currency"):
            merged["currency"] = u["currency"]
    merged["currency"] = resolve_display_currency(merged.get("currency"))
    return merged


def _check_api_key():
    """Check that an LLM API key is configured."""
    try:
        resolve_llm_config()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print("Set ANTHROPIC_API_KEY or configure VULSCAN_LLM_PROVIDER with a matching key.", file=sys.stderr)
        sys.exit(1)


def load_prompt(name: str) -> str:
    """Load a prompt template from the prompts directory."""
    with open_utf8(PROMPTS_DIR / f"{name}.txt") as f:
        return f.read()


def _require_final_scan_artifact(pipeline_data: dict) -> None:
    """Raise when *pipeline_data* is not a canonical FinalScanArtifact."""
    from core.final_artifact.report_views import is_final_scan_artifact

    if not is_final_scan_artifact(pipeline_data):
        raise ValueError(
            "Report generation requires a FinalScanArtifact (pipeline_output.json). "
            "Legacy pipeline output with stage1_verdict/stage2_verdict is no longer supported."
        )


def _compact_for_summary(pipeline_data: dict) -> dict:
    """Create a compact copy of pipeline_data for the summary prompt.

    Strips large fields (vulnerable_code, steps_to_reproduce, description)
    from findings to avoid exceeding the context window.
    """
    compact = {k: v for k, v in pipeline_data.items() if k != "findings"}
    compact["findings"] = []
    for f in pipeline_data.get("findings", []):
        s1 = f.get("stage1_detection") or {}
        compact["findings"].append({
            "finding_id": f.get("finding_id"),
            "unit_id": f.get("unit_id"),
            "final_state": f.get("final_state"),
            "candidate_type": s1.get("candidate_type"),
            "location": s1.get("location"),
            "cwe_id": s1.get("cwe_id"),
            "cwe_name": s1.get("cwe_name"),
            "impact": s1.get("impact"),
        })
    return compact


def _uses_chinese_headers(report_text: str) -> bool:
    return "## 结果" in report_text or "## 管道统计" in report_text


def _artifact_finding_name(finding: dict) -> str:
    s1 = finding.get("stage1_detection") or {}
    return (
        s1.get("candidate_type")
        or finding.get("short_name")
        or finding.get("name")
        or f"CWE-{s1.get('cwe_id') or 0}"
    )


def _artifact_finding_cwe(finding: dict) -> int:
    s1 = finding.get("stage1_detection") or {}
    return int(s1.get("cwe_id") or finding.get("cwe_id") or 0)


def _artifact_finding_location(finding: dict) -> str:
    s1 = finding.get("stage1_detection") or {}
    location = s1.get("location") or finding.get("location") or {}
    file_path = location.get("file") or "unknown"
    func = location.get("function") or finding.get("unit_id") or file_path
    if ":" in str(func):
        return str(func)
    return f"{file_path}:{func}"


def _safe_disclosure_name(label: str) -> str:
    """Sanitize an LLM-controlled label for use in a disclosure filename."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(label).replace(" ", "_")).upper()
    return safe_filename(cleaned) or "FINDING"


def _build_final_artifact_findings_sections(
    pipeline_data: dict,
    *,
    chinese: bool,
) -> str:
    from core.final_artifact.report_views import report_sections

    sections = report_sections(pipeline_data, chinese=chinese)
    if not sections:
        empty = "未发现任何 findings。" if chinese else "No findings to report."
        return empty

    blocks: list[str] = []
    for sec in sections:
        header = f"## {sec['label']}"
        findings = sec["findings"]
        if chinese:
            table_header = "| # | 漏洞 | 位置 | CWE | 状态 |"
        else:
            table_header = "| # | Finding | Location | CWE | State |"
        lines = [
            header,
            "",
            table_header,
            "|---|------|------|-----|------|",
        ]
        for i, finding in enumerate(findings, 1):
            lines.append(
                "| {idx} | {name} | {location} | CWE-{cwe} | {state} |".format(
                    idx=i,
                    name=_artifact_finding_name(finding),
                    location=_artifact_finding_location(finding),
                    cwe=_artifact_finding_cwe(finding),
                    state=finding.get("final_state") or sec["key"],
                )
            )
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _build_results_section(pipeline_data: dict, *, chinese: bool) -> str:
    """Build the Results verdict table from FinalScanArtifact metrics."""
    metrics = pipeline_data.get("metrics") or {}
    if chinese:
        return (
            "## 结果\n\n"
            "| 判定 | 数量 |\n"
            "|------|------|\n"
            f"| 动态验证已复现 | {metrics.get('dynamic_reproduced', 0)} |\n"
            f"| Stage 2 已确认 | {metrics.get('stage2_confirmed', 0)} |\n"
            f"| 候选 | {metrics.get('stage1_candidates', 0)} |\n"
            f"| 已拒绝 | {metrics.get('stage2_rejected', 0)} |\n"
            f"| 不确定 | {metrics.get('stage1_inconclusive', 0) + metrics.get('stage2_inconclusive', 0)} |\n"
            f"| 错误 | {metrics.get('stage1_errors', 0) + metrics.get('stage2_failed', 0) + metrics.get('dynamic_failed', 0)} |"
        )
    return (
        "## Results\n\n"
        "| Verdict | Count |\n"
        "|---------|-------|\n"
        f"| Dynamically reproduced | {metrics.get('dynamic_reproduced', 0)} |\n"
        f"| Stage 2 confirmed | {metrics.get('stage2_confirmed', 0)} |\n"
        f"| Candidates | {metrics.get('stage1_candidates', 0)} |\n"
        f"| Rejected | {metrics.get('stage2_rejected', 0)} |\n"
        f"| Inconclusive | {metrics.get('stage1_inconclusive', 0) + metrics.get('stage2_inconclusive', 0)} |\n"
        f"| Errors | {metrics.get('stage1_errors', 0) + metrics.get('stage2_failed', 0) + metrics.get('dynamic_failed', 0)} |"
    )


def _replace_results_section(report_text: str, pipeline_data: dict) -> str:
    """Replace the LLM-generated Results section with deterministic counts."""
    chinese = _uses_chinese_headers(report_text)
    new_section = _build_results_section(pipeline_data, chinese=chinese)
    match = re.search(r"\n## (?:Results|结果)\b", report_text)
    if not match:
        stats_match = re.search(r"\n## (?:Pipeline Statistics|管道统计)\b", report_text)
        if stats_match:
            return (
                report_text[:stats_match.start()].rstrip()
                + "\n\n"
                + new_section
                + report_text[stats_match.start():]
            )
        return new_section + "\n\n" + report_text

    rest = report_text[match.end():]
    next_header = re.search(r"\n## ", rest)
    end = match.end() + (next_header.start() if next_header else len(rest))
    return report_text[:match.start()] + "\n\n" + new_section + report_text[end:]


def _build_confirmed_vulnerabilities_section(
    pipeline_data: dict,
    *,
    chinese: bool,
) -> str:
    return _build_final_artifact_findings_sections(pipeline_data, chinese=chinese)


def _build_false_positives_section(
    pipeline_data: dict,
    *,
    chinese: bool,
) -> str:
    from core.final_artifact.report_views import bucket_findings_by_final_state

    rejected = pipeline_data.get("rejected") or bucket_findings_by_final_state(
        pipeline_data
    ).get("rejected", [])
    header = "## 消除的误报" if chinese else "## False Positives Eliminated"
    if not rejected:
        empty = "无消除的误报。" if chinese else "No false positives to report."
        return f"{header}\n\n{empty}"
    lines = [
        header,
        "",
        "| Finding | Stage 1 | Stage 2 | Reason |",
        "|---------|---------|---------|--------|",
    ]
    for finding in rejected:
        s1 = finding.get("stage1_detection") or {}
        s2 = finding.get("stage2_verification") or {}
        lines.append(
            "| {name} | {s1} | {s2} | Stage 2 rejected |".format(
                name=_artifact_finding_name(finding),
                s1=s1.get("decision") or "candidate",
                s2=s2.get("decision") or "rejected",
            )
        )
    return "\n".join(lines)


def _build_methodology_section(*, chinese: bool) -> str:
    if chinese:
        return (
            "## 方法\n\n"
            "两阶段分析：\n"
            "1. 阶段 1：对过滤后的代码单元进行 LLM 漏洞检测\n"
            "2. 阶段 2：攻击者模拟验证可利用性\n\n"
            "攻击者模型：互联网远程攻击者，仅有浏览器/HTTP 客户端，无服务器侧访问权限，无管理员凭据。"
        )
    return (
        "## Methodology\n\n"
        "Two-stage analysis:\n"
        "1. Stage 1: LLM-based vulnerability detection on filtered code units\n"
        "2. Stage 2: Attacker simulation to verify exploitability\n\n"
        "Attacker model: Remote attacker with browser access, no server-side access, no admin credentials."
    )


def _strip_llm_tail_sections(report_text: str) -> str:
    """Remove any LLM-generated tail sections before deterministic splice."""
    patterns = (
        r"\n## (?:Confirmed Vulnerabilities|已确认漏洞)\b",
        r"\n## (?:False Positives Eliminated|消除的误报)\b",
        r"\n## (?:Methodology|方法|方法论)\b",
    )
    earliest = len(report_text)
    for pattern in patterns:
        match = re.search(pattern, report_text)
        if match:
            earliest = min(earliest, match.start())
    if earliest < len(report_text):
        return report_text[:earliest].rstrip()
    return report_text.rstrip()


def _finalize_summary_report(report_text: str, pipeline_data: dict) -> str:
    """Inject deterministic counts/tables from FinalScanArtifact report views."""
    chinese = _uses_chinese_headers(report_text)
    base = _strip_llm_tail_sections(report_text)
    base = _replace_results_section(base, pipeline_data)
    sections = [
        base,
        _build_confirmed_vulnerabilities_section(pipeline_data, chinese=chinese),
        _build_false_positives_section(pipeline_data, chinese=chinese),
        _build_methodology_section(chinese=chinese),
    ]
    return "\n\n".join(section for section in sections if section)


def _summary_looks_complete(report_text: str) -> bool:
    """Heuristic check that the LLM filled the summary template."""
    results_headers = ("## Results", "## 结果")
    stats_headers = ("## Pipeline Statistics", "## 管道统计")
    methodology_headers = ("## Methodology", "## 方法", "## 方法论")
    return (
        any(section in report_text for section in results_headers)
        and any(section in report_text for section in stats_headers)
        and any(section in report_text for section in methodology_headers)
    )


def generate_summary_report(pipeline_data: dict) -> tuple[str, dict]:
    """Generate a summary report from pipeline data.

    Returns:
        (report_text, usage_dict) where usage_dict has input_tokens,
        output_tokens, total_tokens, cost_usd.
    """
    _require_final_scan_artifact(pipeline_data)
    _check_api_key()
    client = get_shared_llm_client()

    summary_data = _compact_for_summary(pipeline_data)
    system_prompt = load_prompt("system")
    user_prompt = load_prompt("summary").replace("{pipeline_data}", json.dumps(summary_data, indent=2))

    last_err: Exception | None = None
    for attempt in range(2):
        response = client.messages.create(
            model=MODEL,
            max_tokens=SUMMARY_MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        try:
            report_text = _extract_response_text(response)
            stop = getattr(response, "stop_reason", "")
            usage = _extract_usage(response)
            report_text = _finalize_summary_report(report_text, pipeline_data)
            if stop == "max_tokens" or not _summary_looks_complete(report_text):
                raise RuntimeError(
                    f"Summary output incomplete "
                    f"(stop_reason={stop}, output_tokens={usage['output_tokens']})"
                )
            return report_text, usage
        except RuntimeError as exc:
            last_err = exc
            if attempt == 0:
                print(f"  Summary LLM issue, retrying once... ({exc})", file=sys.stderr)
                continue
            raise
    raise last_err  # pragma: no cover


def _splice_code_section(llm_output: str, code_section: str) -> str:
    """Insert the verbatim code block into the LLM-generated disclosure.

    The LLM generates everything except the Vulnerable Code section. This
    function inserts the server-built code block at the right position.

    As a safety net, if the LLM ignored the instruction and still generated
    its own ``## Vulnerable Code`` / ``## 漏洞代码`` block, that block is stripped first.
    """
    if not code_section:
        return llm_output

    # Safety net: strip any LLM-generated Vulnerable Code section.
    output = llm_output
    for pattern in (
        r'## Vulnerable Code.*?(?=\n## |\Z)',
        r'## 漏洞代码.*?(?=\n## |\Z)',
    ):
        output = re.sub(pattern, '', output, flags=re.DOTALL)

    # Insert the real code section before reproduction steps (zh or en).
    for insertion_point in ('## 复现步骤', '## Steps to Reproduce'):
        if insertion_point in output:
            return output.replace(
                insertion_point,
                f"{code_section}\n\n{insertion_point}",
                1,
            )

    for fallback in ('## 影响', '## Impact'):
        if fallback in output:
            return output.replace(fallback, f"{code_section}\n\n{fallback}", 1)

    return output + f"\n\n{code_section}"


def _build_poc_code_section(test_code: str, language: str | None) -> str:
    """Build a verbatim PoC appendix for dynamic verification docs."""
    if not test_code or not test_code.strip():
        return ""
    fence_lang = _FENCE_LANG.get((language or "").lower(), "") if language else ""
    if not fence_lang and test_code.lstrip().startswith("<?php"):
        fence_lang = "php"
    elif not fence_lang and "def " in test_code[:200]:
        fence_lang = "python"
    return (
        "## PoC 代码\n\n"
        f"```{fence_lang}\n{test_code.strip()}\n```"
    )


def _build_docker_env_section(dockerfile: str, docker_compose: str | None = None) -> str:
    """Build Dockerfile appendix for dynamic verification docs."""
    parts: list[str] = []
    if dockerfile and dockerfile.strip():
        parts.extend([
            "## 测试环境配置",
            "",
            "### Dockerfile",
            "",
            "```dockerfile",
            dockerfile.strip(),
            "```",
            "",
        ])
    if docker_compose and docker_compose.strip():
        parts.extend([
            "### docker-compose.yml",
            "",
            "```yaml",
            docker_compose.strip(),
            "```",
            "",
        ])
    return "\n".join(parts).rstrip()


def _splice_dynamic_sections(
    llm_output: str,
    *,
    poc_section: str = "",
    docker_section: str = "",
) -> str:
    """Append server-built PoC / Docker sections to dynamic verification docs."""
    output = llm_output
    for pattern in (
        r'## PoC 代码.*?(?=\n## |\Z)',
        r'## 测试环境配置.*?(?=\n## |\Z)',
    ):
        output = re.sub(pattern, '', output, flags=re.DOTALL)

    appendix = "\n\n".join(s for s in (poc_section, docker_section) if s)
    if not appendix:
        return output.rstrip()
    return output.rstrip() + "\n\n" + appendix + "\n"


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


def generate_dynamic_disclosure(
    finding: dict,
    dynamic_result: dict,
    product_name: str,
    *,
    language: str | None = None,
) -> tuple[str, dict]:
    """Generate a Chinese dynamic-verification explanation for one finding."""
    _check_api_key()
    client = get_shared_llm_client()

    poc_section = _build_poc_code_section(
        dynamic_result.get("test_code") or "",
        language,
    )
    docker_section = _build_docker_env_section(
        dynamic_result.get("dockerfile") or "",
        dynamic_result.get("docker_compose"),
    )

    payload = {
        "finding_id": finding.get("id"),
        "short_name": finding.get("short_name"),
        "name": finding.get("name"),
        "product_name": product_name,
        "cwe_id": finding.get("cwe_id"),
        "cwe_name": finding.get("cwe_name"),
        "location": finding.get("location"),
        "description": finding.get("description"),
        "impact": finding.get("impact"),
        "stage1_verdict": finding.get("stage1_verdict"),
        "stage2_verdict": finding.get("stage2_verdict"),
        "dynamic_status": dynamic_result.get("status"),
        "dynamic_details": dynamic_result.get("details"),
        "dynamic_evidence": dynamic_result.get("evidence", []),
        "elapsed_seconds": dynamic_result.get("elapsed_seconds"),
        "retry_count": dynamic_result.get("retry_count"),
    }

    user_prompt = (
        load_prompt("dynamic_disclosure")
        .replace("{verification_data}", json.dumps(payload, indent=2, ensure_ascii=False), 1)
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=DYNAMIC_DISCLOSURE_MAX_TOKENS,
        system=load_prompt("system"),
        messages=[{"role": "user", "content": user_prompt}],
    )

    llm_output = _extract_response_text(response)
    final_output = _splice_dynamic_sections(
        llm_output,
        poc_section=poc_section,
        docker_section=docker_section,
    )
    return final_output, _extract_usage(response)


def generate_disclosure(vulnerability_data: dict, product_name: str) -> tuple[str, dict]:
    """Generate a disclosure document for a single vulnerability.

    Returns:
        (disclosure_text, usage_dict)
    """
    _check_api_key()
    client = get_shared_llm_client()

    system_prompt = load_prompt("system")

    # The vulnerable-code markdown block is spliced into the LLM output
    # AFTER generation — the LLM never sees or produces it. This prevents
    # the LLM from hallucinating the snippet. Raw source (verbatim section
    # or Stage evidence content) must therefore never reach the prompt.
    code_section = vulnerability_data.get("vulnerable_code_section") or ""
    payload = {}
    for key, value in vulnerability_data.items():
        if key in ("vulnerable_code_section", "vulnerable_code", "evidence"):
            continue
        if (
            key in ("stage1_detection", "stage2_verification", "dynamic_verification")
            and isinstance(value, dict)
        ):
            value = {k: v for k, v in value.items() if k != "evidence"}
        payload[key] = value
    payload["product_name"] = product_name

    user_prompt = (
        load_prompt("disclosure")
        .replace("{vulnerability_data}", json.dumps(payload, indent=2), 1)
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=DISCLOSURE_MAX_TOKENS,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )

    llm_output = _extract_response_text(response)
    final_output = _splice_code_section(llm_output, code_section)

    return final_output, _extract_usage(response)


def generate_all(pipeline_path: str, output_dir: str) -> None:
    """Generate all reports from a FinalScanArtifact pipeline output file."""
    from core.final_artifact.validate import CONFIRMED_FINAL_STATES

    pipeline_data = read_json(pipeline_path)

    try:
        _require_final_scan_artifact(pipeline_data)
        validate_pipeline_output(pipeline_data)
    except (ValidationError, ValueError) as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Generate summary report
    print("Generating summary report...")
    summary, _usage = generate_summary_report(pipeline_data)
    with open_utf8(output_path / "SUMMARY_REPORT.md", "w") as f:
        f.write(summary)
    print(f"  -> {output_path / 'SUMMARY_REPORT.md'}")

    # Generate disclosure for each confirmed finding
    disclosures_dir = output_path / "disclosures"
    disclosures_dir.mkdir(exist_ok=True)

    product_name = pipeline_data["repository"]["name"]
    confirmed = [
        f for f in pipeline_data.get("findings", [])
        if f.get("final_state") in CONFIRMED_FINAL_STATES
    ]

    for i, finding in enumerate(confirmed, 1):
        label = _artifact_finding_name(finding)
        print(f"Generating disclosure for {label}...")
        disclosure, _usage = generate_disclosure(finding, product_name)

        safe_name = _safe_disclosure_name(label)
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        with open_utf8(disclosures_dir / filename, "w") as f:
            f.write(disclosure)
        print(f"  -> {disclosures_dir / filename}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python generator.py <pipeline_output.json> <output_dir>")
        sys.exit(1)

    generate_all(sys.argv[1], sys.argv[2])
    print("Done.")
