"""
Agent Prompts — neutral Context Enhancement (no security classification).

Gather related units, types, call/dataflow observations, and unknowns.
Do not classify exploitability or invent callers by naming patterns.
"""

from typing import List, Optional


SYSTEM_PROMPT = """You are a code-context analyst. Your job is to gather neutral
structural context that helps later analysis stages understand a code unit.

You MUST NOT:
- Assign security classifications (exploitable, vulnerable_internal, etc.)
- Guess additional callers from naming patterns
- Invent call-graph edges or reachability claims
- Produce vulnerability verdicts or severity scores

You SHOULD:
1. Identify related units that clarify types, callees, callers, and definitions
   already evidenced by code or static metadata.
2. Record observed dataflow facts (inputs/outputs/bindings) without labeling
   them as vulnerabilities.
3. Note build/runtime context when visible (imports, env reads, config).
4. Explicitly list unknowns when evidence is missing.

Complete with the `finish` tool using the Enhancement Schema fields only."""


def get_user_prompt(
    unit_id: str,
    unit_type: str,
    primary_code: str,
    static_deps: List[str],
    static_callers: List[str],
    is_entry_point: bool = False,
    reachable_from_entry: Optional[bool] = None,
    entry_point_path: Optional[List[str]] = None,
    reaching_entry_point: Optional[str] = None,
    reachability_status: Optional[str] = None,
) -> str:
    """Generate the initial user prompt for neutral context enhancement."""
    deps_str = ", ".join(static_deps[:10]) if static_deps else "None identified"
    callers_str = ", ".join(static_callers[:10]) if static_callers else "None identified"

    reach_bits = []
    if reachability_status:
        reach_bits.append(f"**Reachability status (from call graph):** `{reachability_status}`")
    if is_entry_point:
        reach_bits.append("**Structural root:** yes")
    reach_section = ""
    if reach_bits:
        reach_section = "\n### Call-graph facts (do not recompute)\n" + "\n".join(reach_bits) + "\n"

    return f"""## Code Unit to Contextualize

**ID:** `{unit_id}`
**Type:** {unit_type}
{reach_section}
### Code
```
{primary_code}
```

### Static metadata (do not invent beyond this without evidence)
**Direct calls:** {deps_str}
**Direct callers:** {callers_str}

---

## Your Task

1. Explore related definitions/types/callees needed to understand this unit.
2. Record dataflow observations as facts (no vulnerability labels).
3. List unknowns where evidence is missing.
4. Call `finish` with the Enhancement Schema fields only.

Begin."""


def get_continuation_prompt(tool_results: list[dict]) -> str:
    """Generate continuation prompt with tool results."""
    parts = []
    for tr in tool_results:
        name = tr.get("tool_name", "tool")
        result = tr.get("result", {})
        parts.append(f"### Result from `{name}`\n```json\n{result}\n```")
    return (
        "Tool results follow. Continue gathering context or call `finish`.\n\n"
        + "\n\n".join(parts)
    )
