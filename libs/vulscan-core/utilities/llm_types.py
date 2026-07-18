"""Unified LLM response types (Anthropic-shaped for callers)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TextBlock:
    type: str = "text"
    text: str = ""


@dataclass
class ToolUseBlock:
    type: str = "tool_use"
    id: str = ""
    name: str = ""
    input: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class MessageResponse:
    content: list[Any]
    stop_reason: str
    usage: LLMUsage


def normalize_content_block(block: Any) -> Any:
    """Convert provider SDK blocks into simple dataclass blocks."""
    block_type = getattr(block, "type", None)
    if block_type == "text" or hasattr(block, "text") and getattr(block, "type", "text") == "text":
        text = getattr(block, "text", "")
        if isinstance(block, dict):
            return TextBlock(text=block.get("text", ""))
        return TextBlock(text=text)
    if block_type == "tool_use" or (isinstance(block, dict) and block.get("type") == "tool_use"):
        if isinstance(block, dict):
            return ToolUseBlock(
                id=block.get("id", ""),
                name=block.get("name", ""),
                input=block.get("input", {}) or {},
            )
        return ToolUseBlock(
            id=getattr(block, "id", ""),
            name=getattr(block, "name", ""),
            input=getattr(block, "input", {}) or {},
        )
    if isinstance(block, dict):
        if block.get("type") == "text":
            return TextBlock(text=block.get("text", ""))
        if block.get("type") == "tool_use":
            return ToolUseBlock(
                id=block.get("id", ""),
                name=block.get("name", ""),
                input=block.get("input", {}) or {},
            )
    return block


def normalize_message_response(response: Any) -> MessageResponse:
    """Normalize a provider response to MessageResponse."""
    content = [normalize_content_block(b) for b in response.content]
    usage = response.usage
    return MessageResponse(
        content=content,
        stop_reason=getattr(response, "stop_reason", "end_turn") or "end_turn",
        usage=LLMUsage(
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
        ),
    )
