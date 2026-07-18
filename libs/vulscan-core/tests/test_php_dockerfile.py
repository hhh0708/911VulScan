"""Tests for PHP dynamic-test Dockerfile helpers."""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub

import importlib.util
import json

_PHP_DOCKERFILE = _CORE_ROOT / "utilities" / "dynamic_tester" / "php_dockerfile.py"
_spec = importlib.util.spec_from_file_location("php_dockerfile", _PHP_DOCKERFILE)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

ensure_composer_in_dockerfile = _mod.ensure_composer_in_dockerfile
is_registry_pull_failure = _mod.is_registry_pull_failure
sanitize_composer_json_text = _mod.sanitize_composer_json_text


def test_ensure_composer_injects_after_from():
    dockerfile = """FROM php:8.3-cli
WORKDIR /work
RUN composer install --no-dev --quiet
"""
    out = ensure_composer_in_dockerfile(dockerfile)
    assert "COPY --from=composer:2 /usr/bin/composer /usr/bin/composer" in out
    lines = out.splitlines()
    from_idx = next(i for i, l in enumerate(lines) if l.startswith("FROM "))
    composer_idx = next(
        i for i, l in enumerate(lines) if "COPY --from=composer" in l
    )
    assert composer_idx == from_idx + 1


def test_ensure_composer_skips_when_already_present():
    dockerfile = """FROM php:8.3-cli
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
RUN composer install
"""
    assert ensure_composer_in_dockerfile(dockerfile) == dockerfile


def test_sanitize_composer_json_drops_ext_grpc():
    raw = json.dumps(
        {
            "require": {
                "php": ">=8.1",
                "ext-grpc": "*",
                "google/protobuf": "^3.25",
            }
        },
        indent=2,
    )
    out = sanitize_composer_json_text(raw)
    data = json.loads(out)
    assert "ext-grpc" not in data["require"]
    assert "google/protobuf" in data["require"]
    assert data["config"]["audit"]["block-insecure"] is False


def test_is_registry_pull_failure():
    err = "failed to solve: failed to fetch anonymous token: Get https://auth.docker.io/token: i/o timeout"
    assert is_registry_pull_failure(err)
    assert not is_registry_pull_failure("composer: not found")
