"""Tests for dynamic-test Docker image/container cleanup."""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub


@pytest.fixture
def docker_executor():
    from utilities.dynamic_tester import docker_executor

    return docker_executor


def test_teardown_compose_removes_local_images(docker_executor, monkeypatch):
    calls = []

    def fake_cleanup(cmd, timeout=30, cwd=None):
        calls.append((cmd, cwd))
        return True

    monkeypatch.setattr(docker_executor, "_run_docker_cleanup", fake_cleanup)
    docker_executor._teardown_compose(
        ["docker", "compose", "-p", "vuln-001"],
        "/tmp/work",
    )

    assert calls
    cmd, cwd = calls[0]
    assert cmd[:4] == ["docker", "compose", "-p", "vuln-001"]
    assert "down" in cmd
    assert "--rmi" in cmd
    assert "local" in cmd
    assert cwd == "/tmp/work"


def test_cleanup_after_test_single_container_path(docker_executor, monkeypatch):
    from utilities.dynamic_tester.build_plan import ResourceScope

    calls = []
    scope = ResourceScope.create("VULN-001", batch_run_id="run1234")

    def fake_cleanup(cmd, timeout=30, cwd=None):
        calls.append(cmd)
        return True

    monkeypatch.setattr(docker_executor, "_run_docker_cleanup", fake_cleanup)
    monkeypatch.setattr(docker_executor, "_remove_image_tag", lambda tag: calls.append(["rmi", tag]))

    docker_executor._cleanup_after_test(
        scope=scope,
        image_tag=scope.image_tag,
        network_name=None,
        container_name=scope.container_name,
        compose_base=None,
        work_dir=None,
    )

    assert ["rmi", scope.image_tag] in calls
    assert not any(cmd[:3] == ["docker", "network", "rm"] for cmd in calls)
    assert ["docker", "rm", "-f", scope.container_name] in calls
    assert not any(cmd[:3] == ["docker", "image", "prune"] for cmd in calls)


def test_cleanup_after_test_compose_path(docker_executor, monkeypatch):
    teardown_calls = []

    monkeypatch.setattr(
        docker_executor,
        "_teardown_compose",
        lambda base, work_dir: teardown_calls.append((base, work_dir)),
    )

    def fake_cleanup(cmd, timeout=30, cwd=None):
        return True

    monkeypatch.setattr(docker_executor, "_run_docker_cleanup", fake_cleanup)

    docker_executor._cleanup_after_test(
        compose_base=["docker", "compose", "-p", "vuln-001"],
        work_dir="/tmp/work",
    )

    assert teardown_calls == [(["docker", "compose", "-p", "vuln-001"], "/tmp/work")]


def test_compose_build_failure_still_tears_down(docker_executor, monkeypatch, tmp_path):
    from utilities.dynamic_tester.build_plan import ResourceScope

    calls = []
    scope = ResourceScope.create("VULN-001", batch_run_id="runabcd1")

    def fake_run_command(cmd, timeout, cwd=None):
        calls.append(cmd)
        if cmd[-1] == "build":
            return "build failed", "", 1, False
        return "", "", 0, False

    monkeypatch.setattr(docker_executor, "_run_command", fake_run_command)
    monkeypatch.setattr(
        docker_executor,
        "_teardown_compose",
        lambda base, work_dir: calls.append(["teardown", *base]),
    )

    result = docker_executor._run_compose(str(tmp_path), scope, 5, 5)

    assert result.build_error is not None
    assert any(c[0] == "teardown" for c in calls)


def test_prune_vulscan_test_artifacts_scoped_to_run(docker_executor, monkeypatch):
    calls = []

    monkeypatch.setattr(docker_executor, "_prune_dangling_images", lambda: calls.append("prune"))
    monkeypatch.setattr(
        docker_executor,
        "_remove_orphan_vulscan_images",
        lambda run_id=None: calls.append(("sweep", run_id)),
    )
    monkeypatch.setattr(
        docker_executor,
        "_cleanup_labeled_containers",
        lambda run_id: calls.append(("containers", run_id)),
    )

    docker_executor.prune_vulscan_test_artifacts("batch99")

    assert ("containers", "batch99") in calls
    assert ("sweep", "batch99") in calls
    assert "prune" in calls
