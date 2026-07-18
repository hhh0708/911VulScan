"""Tests for Docker execution scaffolding."""

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


def test_run_single_container_does_not_make_workdir_read_only(monkeypatch, tmp_path):
    from utilities.dynamic_tester import docker_executor
    from utilities.dynamic_tester.build_plan import ResourceScope

    commands = []
    scope = ResourceScope.create("VULN-001", batch_run_id="runtest1")

    def fake_run_command(cmd, timeout, cwd=None):
        commands.append(cmd)
        return "", "", 0, False

    monkeypatch.setattr(docker_executor, "_run_command", fake_run_command)
    result = docker_executor._run_single(str(tmp_path), scope, 1, 1)

    assert result.build_error is None
    run_cmd = next(cmd for cmd in commands if cmd[:2] == ["docker", "run"])
    # Sandbox policy: rootfs is read-only on purpose (Phase 10 hardening, also
    # asserted by test_phase10b_dynamic_security). The workdir stays writable
    # through rw tmpfs mounts, so tests can still execute.
    assert "--read-only" in run_cmd
    tmpfs_mounts = [run_cmd[i + 1] for i, c in enumerate(run_cmd) if c == "--tmpfs" and i + 1 < len(run_cmd)]
    assert tmpfs_mounts, "read-only rootfs requires writable tmpfs scratch space"
    assert any("rw" in mount for mount in tmpfs_mounts)
    assert scope.container_name in run_cmd
    label_args = [run_cmd[i + 1] for i, c in enumerate(run_cmd) if c == "--label" and i + 1 < len(run_cmd)]
    assert any("vulscan.run_id=runtest1" in label for label in label_args)

