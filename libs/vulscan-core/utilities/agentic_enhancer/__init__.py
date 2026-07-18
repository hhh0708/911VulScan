"""
Agentic Context Enhancer

Iteratively explores the codebase via tool use to gather *neutral*
structural context. Does not classify exploitability or recompute
reachability — reads canonical call-graph facts already stamped on units.
"""

from .agent import ContextAgent, AgentResult, enhance_unit_with_agent
from .repository_index import RepositoryIndex, load_index_from_file
from .tools import TOOL_DEFINITIONS, ToolExecutor

__all__ = [
    "ContextAgent",
    "AgentResult",
    "enhance_unit_with_agent",
    "RepositoryIndex",
    "load_index_from_file",
    "TOOL_DEFINITIONS",
    "ToolExecutor",
]
