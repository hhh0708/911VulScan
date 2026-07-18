"""Trusted sandbox policy + policy compiler for dynamic verification.

Model emits declarative TestPlan only. Dockerfile / docker argv are compiled
here. No placeholder harnesses. Build uses --network=none. needs_network plans
are blocked until a trusted compose compiler ships.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from core.dynamic_verification.harness import build_real_call_harness, resolve_target_identity
from core.dynamic_verification.schema import (
    DYNAMIC_COMPILER_VERSION,
    normalize_language,
    validate_test_plan,
)

DEFAULT_SANDBOX_POLICY: Dict[str, Any] = {
    "privileged": False,
    "docker_socket": False,
    "host_network": False,
    "host_pid": False,
    "host_ipc": False,
    "device_mappings": False,
    "read_only_rootfs": True,
    "tmpfs": ["/tmp", "/var/tmp", "/run"],
    "cpus": "1",
    "memory": "512m",
    "pids_limit": 256,
    "timeout_seconds": 120,
    "source_mount": "ro",
    "network": "none",
    "pass_host_credentials": False,
    "pass_proxy_env": False,
    "build_network": "none",
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges"],
}

# Allowlisted docker build/run flag tokens (exact or prefix forms checked separately)
DOCKER_BUILD_ALLOWLIST = frozenset(
    {
        "docker",
        "build",
        "-t",
        "--network",
        "none",
        "--build-arg",  # only non-secret args; secrets forbidden separately
        ".",
    }
)

_FORBIDDEN_PLAN_PATTERNS = [
    re.compile(r"privileged\s*[:=]\s*true", re.I),
    re.compile(r"docker\.sock", re.I),
    re.compile(r"/var/run/docker\.sock", re.I),
    re.compile(r"network[_-]?mode\s*[:=]\s*['\"]?host", re.I),
    re.compile(r"--privileged", re.I),
    re.compile(r"bind[_-]?mount", re.I),
]

_UNPINNED_REQ = re.compile(
    r"^[A-Za-z0-9_.-]+$"  # bare name without ==, ~=, ===, @
)


def default_sandbox_policy(*, needs_network: bool = False) -> Dict[str, Any]:
    policy = dict(DEFAULT_SANDBOX_POLICY)
    if needs_network:
        policy["network"] = "isolated_test"
    return policy


def reject_unsafe_request(obj: Any) -> Optional[str]:
    ok, err = validate_test_plan(obj) if isinstance(obj, dict) else (None, "")
    if isinstance(obj, dict) and err and "forbidden" in err:
        return err
    text = json.dumps(obj, default=str) if not isinstance(obj, str) else obj
    for pat in _FORBIDDEN_PLAN_PATTERNS:
        if pat.search(text):
            return f"rejected unsafe sandbox request matching {pat.pattern}"
    if isinstance(obj, dict):
        for key in (
            "dockerfile",
            "docker_compose",
            "privileged",
            "host_mount",
            "volumes",
            "devices",
        ):
            if key in obj and obj[key]:
                return f"rejected model-supplied {key}"
    return None


def validate_setup_requirements(
    requirements: List[Any],
    *,
    allowed_packages: Optional[Set[str]] = None,
) -> Tuple[List[str], str]:
    """Only allow deps already present in repo manifest/lockfile (pinned)."""
    allowed = {a.lower() for a in (allowed_packages or set())}
    out: List[str] = []
    for item in requirements or []:
        if not isinstance(item, str) or not item.strip():
            continue
        line = item.strip()
        if any(c in line for c in (";", "|", "`", "$", "\n", "&&", "http://", "https://")):
            return [], f"rejected_unsafe_requirement:{line!r}"
        # Must be pinned
        if _UNPINNED_REQ.match(line):
            return [], f"unpinned_requirement:{line!r}"
        if not any(op in line for op in ("==", "===", "~=", "@", ".whl", ".tar.gz")):
            return [], f"unpinned_requirement:{line!r}"
        name = re.split(r"[=<>!~@\[]", line, maxsplit=1)[0].strip().lower()
        if allowed and name not in allowed:
            return [], f"requirement_not_in_manifest:{name!r}"
        # If no manifest provided, reject all downloads (offline build)
        if not allowed:
            return [], "requirements_require_local_manifest"
        out.append(line)
    return out, ""


def compile_test_plan(
    plan: Dict[str, Any],
    *,
    language: str,
    test_id: str = "",
    unit_id: str = "",
    finding_id: str = "",
    attempt_id: str = "",
    target_code: str = "",
    policy: Optional[Dict[str, Any]] = None,
    location: Optional[dict] = None,
    allowed_packages: Optional[Set[str]] = None,
    source_basename: str = "",
) -> Tuple[Dict[str, Any] | None, str]:
    """Compile TestPlan → trusted Dockerfile + real-call harness + run argv."""
    del target_code  # never use placeholder target_code blobs for calling
    unsafe = reject_unsafe_request(plan)
    if unsafe:
        return None, unsafe

    validated, err = validate_test_plan(plan)
    if validated is None:
        return None, err

    policy = dict(policy or default_sandbox_policy())
    for k in (
        "privileged",
        "docker_socket",
        "host_network",
        "host_pid",
        "host_ipc",
        "device_mappings",
        "pass_host_credentials",
        "pass_proxy_env",
    ):
        policy[k] = False
    policy["read_only_rootfs"] = True
    policy["build_network"] = "none"
    if policy.get("network") == "isolated_test" or validated.get("needs_network"):
        return None, "needs_network_blocked_until_compose_compiler"

    # setup_requirements: reject external downloads by default
    reqs = validated.get("setup_requirements") or []
    if reqs:
        pinned, rerr = validate_setup_requirements(reqs, allowed_packages=allowed_packages)
        if rerr:
            return None, rerr
    else:
        pinned = []

    identity = resolve_target_identity(
        unit_id=unit_id,
        entrypoint=str(
            validated.get("entrypoint")
            or (validated.get("invocation") or {}).get("command")
            or ""
        ),
        location=location,
        language=language,
    )
    if source_basename:
        identity["source_basename"] = source_basename

    adapter, aerr = build_real_call_harness(
        validated,
        language=language,
        test_id=test_id or "unknown",
        unit_id=unit_id or "unknown",
        finding_id=finding_id or "",
        attempt_id=attempt_id or "",
        target_module=identity.get("module", ""),
        target_qualname=identity.get("qualname", ""),
        target_symbol=identity.get("symbol", ""),
        package_name=identity.get("package_name", ""),
        source_basename=identity.get("source_basename", ""),
    )
    if adapter is None:
        return None, f"adapter_blocked:{aerr}"

    lang = normalize_language(language)
    dockerfile = _dockerfile_for(
        lang,
        harness_name=adapter["test_filename"],
        source_basename=identity.get("source_basename") or "",
        link_sources=adapter.get("link_sources") or [],
        has_requirements=bool(pinned),
    )
    run_argv = build_docker_run_argv(policy)
    build_argv = build_docker_build_argv(policy)
    # Validate allowlist
    allow_err = validate_docker_argv_allowlist(build_argv + run_argv)
    if allow_err:
        return None, allow_err

    plan_hash = hashlib.sha256(
        json.dumps(validated, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    cmd_hash = hashlib.sha256(
        json.dumps({"build": build_argv, "run": run_argv}, sort_keys=True).encode("utf-8")
    ).hexdigest()
    policy_hash = hashlib.sha256(
        json.dumps(policy, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    base_image = _base_image_for(lang)
    return {
        "test_plan": validated,
        "dockerfile": dockerfile,
        "test_script": adapter["test_script"],
        "test_filename": adapter["test_filename"],
        "requirements": "\n".join(pinned) + ("\n" if pinned else ""),
        "requirements_filename": "requirements.txt" if lang in ("python", "py") else "",
        "docker_compose": None,
        "needs_attacker_server": False,
        "sandbox_policy": policy,
        "run_argv": run_argv,
        "build_argv": build_argv,
        "test_plan_hash": plan_hash,
        "run_command_hash": cmd_hash,
        "policy_hash": policy_hash,
        "compiler_version": DYNAMIC_COMPILER_VERSION,
        "base_image": base_image,
        "_policy_compiled": True,
        "_requires_target_evidence": True,
        "_target_identity": identity,
        "_adapter": {k: v for k, v in adapter.items() if k != "test_script"},
    }, ""


def build_docker_run_argv(policy: Dict[str, Any]) -> List[str]:
    argv = [
        "--network",
        "none",
        "--memory",
        str(policy.get("memory") or "512m"),
        "--cpus",
        str(policy.get("cpus") or "1"),
        "--pids-limit",
        str(policy.get("pids_limit") or 256),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
    ]
    for mount in policy.get("tmpfs") or ["/tmp", "/var/tmp", "/run"]:
        argv.extend(["--tmpfs", f"{mount}:rw,noexec,nosuid,size=256m"])
    return argv


def build_docker_build_argv(policy: Dict[str, Any]) -> List[str]:
    """Trusted docker build flags — always --network=none, no secrets/SSH/proxy."""
    del policy
    return ["--network", "none"]


def validate_docker_argv_allowlist(argv: List[str]) -> str:
    """Reject disallowed docker flags (host mounts, privileged, secrets, etc.)."""
    banned_substrings = (
        "docker.sock",
        "--privileged",
        "--pid=host",
        "--network=host",
        "--ipc=host",
        "--mount",
        "--volume",
        "-v",
        "--secret",
        "--ssh",
        "SSH_AUTH_SOCK",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "ANTHROPIC",
        "AWS_",
        "GITHUB_TOKEN",
    )
    joined = " ".join(argv)
    for b in banned_substrings:
        if b in joined:
            return f"docker_argv_banned:{b}"
    return ""


def _base_image_for(lang: str) -> str:
    if lang in ("python", "py"):
        return "python:3.11-slim"
    if lang in ("javascript", "js", "typescript", "ts"):
        return "node:20-slim"
    if lang in ("go", "golang"):
        return "golang:1.22-alpine"
    return "gcc:13"


def _dockerfile_for(
    lang: str,
    *,
    harness_name: str,
    source_basename: str,
    link_sources: List[str],
    has_requirements: bool,
) -> str:
    # Offline builds: never RUN pip/npm/go get. Copy local artifacts only.
    base = _base_image_for(lang)
    if lang in ("python", "py"):
        src = source_basename or "target_code.py"
        req_lines = ""
        if has_requirements:
            # Still no network — requirements must already be vendored; skip pip
            req_lines = (
                "COPY requirements.txt .\n"
                "# Offline: do not pip install; deps must be pre-vendored in image/base\n"
            )
        return (
            f"FROM {base}\n"
            "WORKDIR /app\n"
            f"{req_lines}"
            f"COPY {harness_name} .\n"
            f"COPY {src} .\n"
            f'CMD ["python", "{harness_name}"]\n'
        )

    if lang in ("javascript", "js", "typescript", "ts"):
        src = source_basename or "target_code.js"
        return (
            f"FROM {base}\n"
            "WORKDIR /app\n"
            f"COPY {harness_name} .\n"
            f"COPY {src} .\n"
            f'CMD ["node", "{harness_name}"]\n'
        )

    if lang in ("go", "golang"):
        return (
            f"FROM {base}\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            # Offline: init module when repo has no go.mod; never go get
            "RUN test -f go.mod || go mod init vulscan-e2e\n"
            "RUN go build -mod=readonly -o /app/vulscan_test .\n"
            'CMD ["/app/vulscan_test"]\n'
        )

    # C / C++
    src = source_basename or ("target_code.cpp" if lang in ("cpp", "c++") else "target_code.c")
    sources = " ".join([harness_name] + [s for s in link_sources if s and s != harness_name])
    if src not in sources.split():
        sources = f"{sources} {src}".strip()
    compiler = "g++" if lang in ("cpp", "c++") or harness_name.endswith(".cpp") else "gcc"
    return (
        f"FROM {base}\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        f"RUN {compiler} -O1 -g -fsanitize=address -fno-omit-frame-pointer "
        f"-o /app/vulscan_test {sources}\n"
        'CMD ["/app/vulscan_test"]\n'
    )
