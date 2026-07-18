"""Authoritative build and runtime models for dynamic verification."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Literal

from utilities.dynamic_tester.native_test_plan import NativeTestPlan

ExecutionMode = Literal["single", "compose"]
NetworkMode = Literal["none", "compose_internal"]

_VULSCAN_IMAGE_PREFIX = "vulscan-test-"
_VULSCAN_NETWORK_PREFIX = "vulscan-net-"
_VULSCAN_CONTAINER_PREFIX = "vulscan-ctr-"
_VULSCAN_COMPOSE_PREFIX = "vulscan-"
_LABEL_RUN = "vulscan.run_id"
_LABEL_FINDING = "vulscan.finding_id"


@dataclass(frozen=True)
class RuntimePolicy:
    """Container runtime constraints applied at execution time."""

    network_mode: NetworkMode = "none"
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 512
    cap_drop_all: bool = True
    no_new_privileges: bool = True

    @classmethod
    def single_container(cls) -> RuntimePolicy:
        return cls(network_mode="none")

    @classmethod
    def compose_internal(cls) -> RuntimePolicy:
        return cls(network_mode="compose_internal")


@dataclass
class ResourceScope:
    """Unique Docker resource names and labels for one finding within a batch run."""

    batch_run_id: str
    finding_id: str
    safe_id: str

    @classmethod
    def create(
        cls,
        finding_id: str,
        *,
        batch_run_id: str | None = None,
    ) -> ResourceScope:
        run_id = batch_run_id or uuid.uuid4().hex[:8]
        safe_id = re.sub(r"[^a-z0-9-]", "-", finding_id.lower()).strip("-_.") or "finding"
        return cls(batch_run_id=run_id, finding_id=finding_id, safe_id=safe_id)

    @property
    def image_tag(self) -> str:
        return f"{_VULSCAN_IMAGE_PREFIX}{self.batch_run_id}-{self.safe_id}"

    @property
    def container_name(self) -> str:
        return f"{_VULSCAN_CONTAINER_PREFIX}{self.batch_run_id}-{self.safe_id}"

    @property
    def compose_project(self) -> str:
        return f"{_VULSCAN_COMPOSE_PREFIX}{self.batch_run_id}-{self.safe_id}"

    @property
    def network_name(self) -> str:
        return f"{_VULSCAN_NETWORK_PREFIX}{self.batch_run_id}-{self.safe_id}"

    def docker_labels(self) -> dict[str, str]:
        return {
            _LABEL_RUN: self.batch_run_id,
            _LABEL_FINDING: self.finding_id,
        }

    def compose_base(self) -> list[str]:
        return ["docker", "compose", "-p", self.compose_project]


@dataclass
class BuildPlan:
    """Deterministic build context assembled before Docker execution."""

    language: str
    test_filename: str
    test_script: str
    requirements: str = ""
    requirements_filename: str = "requirements.txt"
    needs_attacker_server: bool = False
    execution_mode: ExecutionMode = "single"
    staged_files: list[str] = field(default_factory=list)
    source_basename: str | None = None
    source_path: str | None = None
    go_module_path: str | None = None
    native_plan: NativeTestPlan | None = None
    runtime: str = "linux"
    blocked: bool = False
    blocked_reason: str = ""
    package_root: str | None = None

    @property
    def uses_compose(self) -> bool:
        return self.execution_mode == "compose" and self.needs_attacker_server

    def runtime_policy(self) -> RuntimePolicy:
        if self.uses_compose:
            return RuntimePolicy.compose_internal()
        return RuntimePolicy.single_container()

    def to_generation_dict(self) -> dict:
        """Serialize to the legacy generation dict consumed by the executor."""
        return {
            "test_filename": self.test_filename,
            "test_script": self.test_script,
            "requirements": self.requirements,
            "requirements_filename": self.requirements_filename,
            "needs_attacker_server": self.needs_attacker_server,
            "docker_compose": None,
            "dockerfile": "",
            "_language": self.language,
            "_runtime": self.runtime,
            "_execution_mode": self.execution_mode,
            "_staged_files": list(self.staged_files),
            "_source_basename": self.source_basename,
            "_go_module_path": self.go_module_path,
            "_native_plan": self.native_plan,
            "_blocked": self.blocked,
            "_blocked_reason": self.blocked_reason,
        }


def merge_generation_with_plan(generation: dict, plan: BuildPlan) -> dict:
    """Overlay LLM generation fields onto a materialized build plan."""
    out = plan.to_generation_dict()
    out.update(
        {
            k: v
            for k, v in generation.items()
            if k
            in {
                "test_script",
                "test_filename",
                "requirements",
                "requirements_filename",
                "needs_attacker_server",
            }
            and v is not None
        }
    )
    if plan.needs_attacker_server or generation.get("needs_attacker_server"):
        out["needs_attacker_server"] = True
        out["_execution_mode"] = "compose"
    return out
