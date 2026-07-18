"""OpenAI-compatible backend for DeepSeek, Qwen, and custom endpoints."""

from __future__ import annotations

import json
import uuid
from typing import Any

from openai import OpenAI, RateLimitError

from utilities.llm_config import LLMProviderConfig, resolve_model
from utilities.llm_errors import LLMRateLimitError
from utilities.llm_types import MessageResponse, TextBlock, ToolUseBlock, LLMUsage


class OpenAICompatMessagesAPI:
    def __init__(self, backend: "OpenAICompatBackend"):
        self._backend = backend

    def create(self, **kwargs: Any) -> MessageResponse:
        return self._backend.create_message(**kwargs)


class OpenAICompatBackend:
    provider = "openai_compat"

    def __init__(self, config: LLMProviderConfig):
        if not config.base_url:
            raise ValueError("OpenAI-compatible provider requires VULSCAN_LLM_BASE_URL")
        self.config = config
        self.raw_client = OpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            max_retries=5,
        )
        self.messages = OpenAICompatMessagesAPI(self)

    @property
    def client(self):
        return self

    def _anthropic_tools_to_openai(self, tools: list[dict] | None) -> list[dict] | None:
        if not tools:
            return None
        converted = []
        for tool in tools:
            converted.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
                    },
                }
            )
        return converted

    def _anthropic_messages_to_openai(
        self,
        messages: list[dict],
        system: str | None,
    ) -> list[dict]:
        openai_messages: list[dict] = []
        if system:
            openai_messages.append({"role": "system", "content": system})

        for message in messages:
            role = message["role"]
            content = message["content"]

            if role == "user" and isinstance(content, str):
                openai_messages.append({"role": "user", "content": content})
                continue

            if role == "user" and isinstance(content, list):
                tool_results = [item for item in content if _block_type(item) == "tool_result"]
                if tool_results:
                    for item in tool_results:
                        openai_messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": _block_field(item, "tool_use_id"),
                                "content": _block_field(item, "content"),
                            }
                        )
                    continue

                text_parts = []
                for item in content:
                    if _block_type(item) == "text":
                        text_parts.append(_block_field(item, "text"))
                if text_parts:
                    openai_messages.append({"role": "user", "content": "\n".join(text_parts)})
                continue

            if role == "assistant":
                text_parts: list[str] = []
                tool_calls: list[dict] = []
                blocks = content if isinstance(content, list) else [content]
                for block in blocks:
                    block_type = _block_type(block)
                    if block_type == "text":
                        text_parts.append(_block_field(block, "text"))
                    elif block_type == "tool_use":
                        tool_calls.append(
                            {
                                "id": _block_field(block, "id") or f"call_{uuid.uuid4().hex[:12]}",
                                "type": "function",
                                "function": {
                                    "name": _block_field(block, "name"),
                                    "arguments": json.dumps(_block_field(block, "input") or {}),
                                },
                            }
                        )
                assistant_message: dict[str, Any] = {"role": "assistant"}
                if text_parts:
                    assistant_message["content"] = "\n".join(text_parts)
                else:
                    assistant_message["content"] = None
                if tool_calls:
                    assistant_message["tool_calls"] = tool_calls
                openai_messages.append(assistant_message)
                continue

            openai_messages.append({"role": role, "content": content})

        return openai_messages

    def _openai_response_to_message(self, response: Any) -> MessageResponse:
        choice = response.choices[0]
        message = choice.message
        blocks: list[Any] = []

        if message.content:
            blocks.append(TextBlock(text=message.content))

        tool_calls = getattr(message, "tool_calls", None) or []
        for tool_call in tool_calls:
            fn = tool_call.function
            try:
                args = json.loads(fn.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            blocks.append(
                ToolUseBlock(
                    id=tool_call.id,
                    name=fn.name,
                    input=args,
                )
            )

        stop_reason = "end_turn"
        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason == "tool_calls":
            stop_reason = "tool_use"
        elif finish_reason == "length":
            stop_reason = "max_tokens"
        elif finish_reason:
            stop_reason = "end_turn"

        usage = response.usage
        return MessageResponse(
            content=blocks,
            stop_reason=stop_reason,
            usage=LLMUsage(
                input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                output_tokens=getattr(usage, "completion_tokens", 0) or 0,
            ),
        )

    def create_message(self, **kwargs: Any) -> MessageResponse:
        json_mode = bool(kwargs.pop("json_mode", False))
        model = resolve_model(kwargs.pop("model"), self.config)
        max_tokens = kwargs.pop("max_tokens", 4096)
        messages = kwargs.pop("messages")
        system = kwargs.pop("system", None)
        tools = kwargs.pop("tools", None)

        openai_messages = self._anthropic_messages_to_openai(messages, system)
        openai_tools = self._anthropic_tools_to_openai(tools)

        request_kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": openai_messages,
        }
        if openai_tools:
            request_kwargs["tools"] = openai_tools
        if json_mode:
            request_kwargs["response_format"] = {"type": "json_object"}

        try:
            response = self.raw_client.chat.completions.create(**request_kwargs)
        except RateLimitError as exc:
            retry_after = 0.0
            response_obj = getattr(exc, "response", None)
            if response_obj is not None:
                retry_after = float(response_obj.headers.get("retry-after", 0) or 0)
            raise LLMRateLimitError(str(exc), retry_after=retry_after, response=response_obj) from exc

        message = self._openai_response_to_message(response)
        if not message.content and json_mode:
            # Some providers reject response_format; retry once without it.
            request_kwargs.pop("response_format", None)
            response = self.raw_client.chat.completions.create(**request_kwargs)
            message = self._openai_response_to_message(response)
        return message


def _block_type(block: Any) -> str | None:
    if isinstance(block, dict):
        return block.get("type")
    return getattr(block, "type", None)


def _block_field(block: Any, name: str) -> Any:
    if isinstance(block, dict):
        return block.get(name)
    return getattr(block, name, None)
