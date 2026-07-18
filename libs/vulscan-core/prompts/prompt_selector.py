"""
Prompt Selector

Thin wrappers over Stage 1 detection prompts.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from context.application_context import ApplicationContext


def get_analysis_prompt(
    code: str,
    language: str = None,
    route: str = None,
    files_included: list[str] = None,
    security_classification: str = None,
    classification_reasoning: str = None,
    app_context: "ApplicationContext" = None,
) -> str:
    """Legacy wrapper — ignores security_classification / classification_reasoning."""
    from prompts.vulnerability_analysis import get_analysis_prompt as _get

    return _get(
        code=code,
        language=language or "unknown",
        route=route,
        files_included=files_included,
        app_context=app_context,
    )


def get_system_prompt(
    app_context: "ApplicationContext" = None,
    *,
    replay_risk: bool = False,
    internal_vuln: bool = False,
) -> str:
    """Legacy-compatible system prompt (ignores classification / replay flags)."""
    del app_context, replay_risk, internal_vuln
    from prompts.vulnerability_analysis import get_detection_system_prompt

    return get_detection_system_prompt()
