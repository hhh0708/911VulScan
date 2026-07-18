"""Tests for CredentialResolver and secret redaction."""

from __future__ import annotations

import json
import os
import stat

import pytest

from utilities.credentials import (
    CredentialError,
    CredentialResolver,
    mask_secret,
    redact_secrets,
    safe_exception_message,
)


def test_mask_secret_never_returns_full_value():
    # Construct at runtime so the source tree never stores a real-looking key literal.
    secret = "sk-" + ("abcdefghijklmnop" * 2)
    masked = mask_secret(secret)
    assert secret not in masked
    assert "..." in masked


def test_redact_secrets_removes_known_and_pattern_values():
    secret = "sk-" + "live-" + ("token" * 4)
    text = f"failed with key={secret} and Authorization: Bearer {secret}"
    out = redact_secrets(text, [secret])
    assert secret not in out
    assert "***REDACTED***" in out


def test_resolver_prefers_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-from-env")
    resolver = CredentialResolver(env=os.environ, config_paths=[tmp_path / "missing.json"])
    cred = resolver.resolve(preferred_env="DEEPSEEK_API_KEY")
    assert cred.value == "sk-from-env"
    assert cred.source.startswith("env:")
    assert "***REDACTED***" in repr(cred)


def test_resolver_reads_0600_config(tmp_path, monkeypatch):
    for name in (
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
        "VULSCAN_LLM_API_KEY",
        "OPENAI_API_KEY",
        "DASHSCOPE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"api_key": "sk-from-file"}), encoding="utf-8")
    if os.name != "nt":
        os.chmod(cfg, 0o600)

    resolver = CredentialResolver(env={}, config_paths=[cfg])
    cred = resolver.resolve(preferred_env="ANTHROPIC_API_KEY", allow_config_file=True)
    assert cred.value == "sk-from-file"
    assert cred.source.startswith("config:")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits not enforced on Windows")
def test_resolver_rejects_insecure_config_permissions(tmp_path, monkeypatch):
    for name in (
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_API_KEY",
        "VULSCAN_LLM_API_KEY",
        "OPENAI_API_KEY",
        "DASHSCOPE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"api_key": "sk-test-key"}), encoding="utf-8")
    os.chmod(cfg, 0o644)
    assert cfg.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH)

    resolver = CredentialResolver(env={}, config_paths=[cfg])
    with pytest.raises(CredentialError, match="0600"):
        resolver.resolve(preferred_env="ANTHROPIC_API_KEY", allow_config_file=True)


def test_safe_exception_message_redacts(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-redact")
    exc = ValueError("boom sk-test-redact failed")
    msg = safe_exception_message(exc)
    assert "sk-test-redact" not in msg
    assert "***REDACTED***" in msg


def test_gitleaks_config_has_no_broad_path_allowlist():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    path = os.path.join(root, ".gitleaks.toml")
    assert os.path.isfile(path), ".gitleaks.toml must exist at repo root"
    text = open(path, encoding="utf-8").read()
    assert "useDefault" in text
    assert "vulscan-generic-api-key-assignment" in text
    assert "libs/vulscan-core/tests/" not in text
    assert r".*\.md$" not in text
    assert "Exact synthetic test placeholders" in text
