"""Tests for dynamic verification disclosure generation helpers."""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub

from report import generator as _mod


def test_splice_dynamic_sections_appends_poc_and_docker():
    llm = "# 动态验证报告\n\n## 结论\n\n已确认。\n"
    poc = "## PoC 代码\n\n```php\n<?php echo 1;\n```"
    docker = "## 测试环境配置\n\n```dockerfile\nFROM php:8.3-cli\n```"
    out = _mod._splice_dynamic_sections(llm, poc_section=poc, docker_section=docker)
    assert "## PoC 代码" in out
    assert "## 测试环境配置" in out
    assert "FROM php:8.3-cli" in out


def test_splice_code_section_supports_chinese_headings():
    llm = "# 安全披露\n\n## 概述\n\n说明。\n\n## 复现步骤\n\n步骤。\n"
    code = "## 漏洞代码\n\n```php\n$name = $fd->getName();\n```"
    out = _mod._splice_code_section(llm, code)
    assert out.index("## 漏洞代码") < out.index("## 复现步骤")
    assert "$name = $fd->getName();" in out
