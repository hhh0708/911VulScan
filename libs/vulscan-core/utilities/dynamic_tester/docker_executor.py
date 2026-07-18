"""Docker container execution for dynamic exploit tests.

Handles building images, running containers with timeouts,
and collecting stdout/stderr output. All execution is isolated
in Docker containers with no host volume mounts or privileged mode.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a declared dependency
    yaml = None

from utilities.dynamic_tester.build_plan import ResourceScope
from utilities.dynamic_tester.compose_builder import build_compose_yaml
from utilities.dynamic_tester.dockerfile_builder import (
    apply_dockerfile_finalization,
    collect_staged_files,
)
from utilities.dynamic_tester.language_registry import materialize_build_plan
from utilities.file_io import open_utf8, run_utf8

# Minimum free disk (bytes) required before docker build.
_MIN_DISK_BYTES = 512 * 1024 * 1024  # 512 MiB

# Docker label keys for scoped cleanup.
_LABEL_RUN = "vulscan.run_id"

# Timeouts
DEFAULT_CONTAINER_TIMEOUT = 120   # seconds per container
DEFAULT_BUILD_TIMEOUT = 300       # seconds for docker build

# Path to the bundled attacker server
_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker_templates")
ATTACKER_SERVER_PATH = os.path.join(_TEMPLATES_DIR, "attacker_server.py")

def _check_disk_space(work_dir: str) -> str | None:
    """Return an error message when free disk is below the minimum threshold."""
    try:
        usage = shutil.disk_usage(work_dir)
    except OSError as exc:
        return f"disk check failed: {exc}"
    if usage.free < _MIN_DISK_BYTES:
        return (
            f"insufficient disk space: {usage.free} bytes free "
            f"(minimum {_MIN_DISK_BYTES})"
        )
    return None


def _format_docker_labels(scope: ResourceScope) -> list[str]:
    args: list[str] = []
    for key, value in scope.docker_labels().items():
        args.extend(["--label", f"{key}={value}"])
    return args


class DockerExecutionResult:
    """Result from running a Docker container."""

    def __init__(self):
        self.stdout: str = ""
        self.stderr: str = ""
        self.exit_code: int = -1
        self.timed_out: bool = False
        self.build_error: str | None = None
        self.elapsed_seconds: float = 0.0
        self.image_tag: str = ""
        self.staging_blocked: bool = False
        # Digests captured BEFORE image cleanup (executor owns inspect).
        self.image_digest: str = ""
        self.base_image: str = ""
        self.base_image_digest: str = ""
        self.build_context_hash: str = ""
        self.build_command: list[str] = []
        self.run_command: list[str] = []

    @property
    def success(self) -> bool:
        return self.build_error is None and not self.timed_out


def _inspect_image_digest(image_ref: str) -> str:
    """Return sha256 Id (or RepoDigest) for a local image. No pull."""
    if not image_ref:
        return ""
    try:
        proc = run_utf8(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return (proc.stdout or "").strip()


def _local_image_exists(image_ref: str) -> bool:
    """True iff image is present locally. Never pulls."""
    if not image_ref:
        return False
    try:
        proc = run_utf8(
            ["docker", "image", "inspect", image_ref],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _extract_base_image_from_dockerfile(work_dir: str) -> str:
    path = os.path.join(work_dir, "Dockerfile")
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.upper().startswith("FROM "):
                    # FROM [--platform=..] image[:tag] [AS name]
                    parts = stripped.split()
                    # skip optional --platform=
                    idx = 1
                    while idx < len(parts) and parts[idx].startswith("--"):
                        idx += 1
                    if idx < len(parts):
                        return parts[idx]
    except OSError:
        return ""
    return ""


def _hash_build_context(work_dir: str) -> str:
    import hashlib

    h = hashlib.sha256()
    for root, _dirs, files in os.walk(work_dir):
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, work_dir).replace("\\", "/")
            h.update(rel.encode("utf-8"))
            try:
                with open(path, "rb") as fh:
                    while True:
                        chunk = fh.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
            except OSError:
                continue
    return h.hexdigest()


# Service-level keys that can break container isolation / escape to the host.
# These are stripped from any LLM-generated compose service before execution.
_DANGEROUS_COMPOSE_SERVICE_KEYS = frozenset({
    "privileged", "cap_add", "devices", "device_cgroup_rules", "security_opt",
    "userns_mode", "group_add", "sysctls", "cgroup_parent", "ipc", "pid",
    "uts", "pid_mode", "volumes", "volumes_from", "ports", "network_mode",
    "extra_hosts", "dns", "dns_search", "privileged_mode", "shm_size",
})

# Regex fallback patterns when PyYAML is unavailable or the doc won't parse.
_DANGEROUS_COMPOSE_LINE_RE = re.compile(
    r'^\s*(?:' + '|'.join(re.escape(k) for k in sorted(_DANGEROUS_COMPOSE_SERVICE_KEYS)) + r')\s*:',
    re.IGNORECASE,
)


def _sanitize_compose(content: str) -> str:
    """Harden an LLM-generated docker-compose file before execution.

    NOTE: currently not wired into any production caller — compose files are
    built by ``compose_builder`` instead. Before enabling this, add caller
    coverage tests for the sanitization path.

    LLM output is attacker-influenced (it embeds scanned-repo text), so a
    prompt-injection payload could request host bind mounts, ``privileged``,
    host networking, or added capabilities and escape the sandbox. We parse the
    document and keep only safe service keys, dropping the dangerous ones, and
    rewrite remote attacker images to the locally-built server.
    """
    if yaml is not None:
        sanitized = _sanitize_compose_yaml(content)
        if sanitized is not None:
            return sanitized
    return _sanitize_compose_regex(content)


def _sanitize_compose_yaml(content: str) -> str | None:
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None

    # `version:` is obsolete in modern compose and triggers warnings.
    doc.pop("version", None)

    services = doc.get("services")
    if isinstance(services, dict):
        for name, svc in list(services.items()):
            if not isinstance(svc, dict):
                continue
            for key in list(svc.keys()):
                if str(key).lower() in _DANGEROUS_COMPOSE_SERVICE_KEYS:
                    svc.pop(key, None)
            # Re-route remote attacker images to the local build context.
            image = svc.get("image")
            if isinstance(image, str) and "attacker" in image.lower():
                svc.pop("image", None)
                svc["build"] = "./attacker-server"

    # Drop any top-level named volumes (they can bind host paths via driver opts).
    doc.pop("volumes", None)

    return yaml.safe_dump(doc, default_flow_style=False, sort_keys=False)


def _sanitize_compose_regex(content: str) -> str:
    """Best-effort line-based fallback when YAML parsing is unavailable."""
    content = re.sub(r'^version:.*\n', '', content, flags=re.MULTILINE)
    content = re.sub(
        r'image:\s*[^\n]*attacker[^\n]*',
        'build: ./attacker-server',
        content,
        flags=re.IGNORECASE,
    )
    # Drop lines (and their indented block bodies) for dangerous directives.
    kept: list[str] = []
    skip_indent: int | None = None
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if skip_indent is not None:
            if stripped and indent <= skip_indent:
                skip_indent = None
            else:
                continue
        if _DANGEROUS_COMPOSE_LINE_RE.match(line):
            skip_indent = indent
            continue
        kept.append(line)
    return "".join(kept)


def _normalize_stage_language(language: str | None) -> str:
    lang = (language or "").strip().lower()
    if lang == "golang":
        return "go"
    return lang


def _stage_source_files(
    work_dir: str,
    source_file: str | None,
    repo_path: str | None = None,
    language: str | None = None,
) -> tuple[str | None, list[str], str | None]:
    """Copy vulnerable source, project headers, and module companions into *work_dir*.

    Returns:
        (source_basename, list of staged relative paths, go module import path)
    """
    if not source_file or not os.path.isfile(source_file):
        return None, [], None

    lang = _normalize_stage_language(language)
    if lang in {"python", "py"} or source_file.endswith(".py"):
        from utilities.dynamic_tester.python_stage import stage_python_project

        source_basename, staged, blocked = stage_python_project(
            work_dir, source_file, repo_path=repo_path
        )
        if blocked:
            return source_basename, staged, None
        if staged:
            return source_basename, staged, None

    if lang in {"javascript", "js", "typescript", "ts"} or source_file.endswith(
        (".js", ".ts", ".jsx", ".tsx")
    ):
        from utilities.dynamic_tester.javascript_stage import stage_javascript_project

        source_basename, staged, blocked = stage_javascript_project(
            work_dir, source_file, repo_path=repo_path
        )
        if blocked:
            return source_basename, staged, None
        if staged:
            return source_basename, staged, None

    if lang == "go" or source_file.endswith(".go"):
        from utilities.dynamic_tester.go_stage import stage_go_module

        source_basename, staged, module_import = stage_go_module(
            work_dir, source_file, repo_path=repo_path
        )
        if staged and module_import:
            return source_basename, staged, module_import

    from utilities.dynamic_tester.native_stage import (
        enumerate_stage_artifacts,
        stage_data_directory,
    )

    source_basename, staged, path_by_basename = enumerate_stage_artifacts(
        source_file, repo_path
    )

    for basename, full_path in path_by_basename.items():
        dest = os.path.join(work_dir, basename)
        os.makedirs(os.path.dirname(dest) or work_dir, exist_ok=True)
        shutil.copy2(full_path, dest)

    data_files = stage_data_directory(work_dir, repo_path, staged)
    staged = sorted(set(staged + data_files))
    return source_basename, staged, None

def _write_test_files(
    work_dir: str,
    generation: dict,
    source_file: str | None = None,
    language: str | None = None,
    repo_path: str | None = None,
    finding: dict | None = None,
    repo_info: dict | None = None,
) -> dict:
    """Write generated test files into the working directory.

    Stages source artifacts, finalizes the Dockerfile deterministically, then
    writes all build-context files. LLM docker-compose/dockerfile are ignored.
    """
    if finding is not None and repo_info is not None:
        plan = materialize_build_plan(
            generation,
            finding,
            repo_info,
            repo_path=repo_path,
            native_plan=generation.get("_native_plan"),
        )
        if plan.blocked:
            generation = dict(generation)
            generation["_blocked"] = True
            generation["_blocked_reason"] = plan.blocked_reason
            return generation
        generation = dict(generation)
        generation["_language"] = plan.language
        generation["_runtime"] = plan.runtime
        generation["_go_module_path"] = plan.go_module_path
        generation["needs_attacker_server"] = plan.needs_attacker_server

    source_basename, _pre_staged, go_module_path = _stage_source_files(
        work_dir, source_file, repo_path=repo_path, language=language
    )
    generation = dict(generation)
    generation["_staged_source_basename"] = source_basename
    generation["_staged_paths"] = list(_pre_staged or [])

    # Write test script
    test_filename = generation.get("test_filename", "test_exploit.py")
    test_path = os.path.join(work_dir, test_filename)
    os.makedirs(os.path.dirname(test_path), exist_ok=True)
    with open_utf8(test_path, "w") as f:
        f.write(generation["test_script"])

    # Write requirements after finalization (composer.json may be sanitized).
    req_filename = generation.get("requirements_filename", "requirements.txt")

    # Copy attacker server if needed (before docker-compose so it's available)
    if generation.get("needs_attacker_server"):
        attacker_dir = os.path.join(work_dir, "attacker-server")
        os.makedirs(attacker_dir, exist_ok=True)
        shutil.copy2(ATTACKER_SERVER_PATH, os.path.join(attacker_dir, "server.py"))
        # Write attacker Dockerfile
        with open_utf8(os.path.join(attacker_dir, "Dockerfile"), "w") as f:
            f.write("FROM python:3.11-slim\nWORKDIR /app\nCOPY server.py .\n"
                    "EXPOSE 9999\nCMD [\"python\", \"server.py\"]\n")

    # Framework-owned compose topology when attacker server is required.
    if generation.get("needs_attacker_server"):
        compose_content = build_compose_yaml()
        with open_utf8(os.path.join(work_dir, "docker-compose.yml"), "w") as f:
            f.write(compose_content)

    # Finalize Dockerfile from actual staged files (authoritative at build time).
    staged_files = collect_staged_files(work_dir)
    generation = apply_dockerfile_finalization(
        generation,
        staged_files=staged_files,
        source_basename=source_basename,
        language=language or generation.get("_language"),
        go_module_path=go_module_path,
    )

    with open_utf8(os.path.join(work_dir, "Dockerfile"), "w") as f:
        f.write(generation["dockerfile"])

    if generation.get("requirements"):
        req_path = os.path.join(work_dir, req_filename)
        os.makedirs(os.path.dirname(req_path) or work_dir, exist_ok=True)
        with open_utf8(req_path, "w") as f:
            f.write(generation["requirements"])

    return generation


def _run_command(cmd: list[str], timeout: int, cwd: str = None) -> tuple[str, str, int, bool]:
    """Run a command with timeout. Returns (stdout, stderr, exit_code, timed_out)."""
    try:
        result = run_utf8(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1, True
    except FileNotFoundError as exc:
        # Missing executable (e.g. docker CLI absent) — report as a normal
        # command failure so best-effort cleanup paths warn and continue
        # instead of crashing the whole run after results were written.
        return "", f"executable not found: {exc}", 127, False


def _combined_output(stdout: str, stderr: str) -> str:
    """Combine command output streams without losing Docker diagnostics."""
    if stdout and stderr:
        return stdout + "\n" + stderr
    return stderr or stdout


def _docker_cleanup_warn(cmd: list[str], detail: str) -> None:
    label = " ".join(cmd[:4])
    if len(cmd) > 4:
        label += " ..."
    snippet = detail.strip().replace("\n", " ")[:240]
    print(f"[Docker cleanup] warning: {label} failed: {snippet}", file=sys.stderr)


def _run_docker_cleanup(
    cmd: list[str],
    timeout: int = 30,
    cwd: str | None = None,
) -> bool:
    """Run a cleanup command; return True on success."""
    stdout, stderr, code, timed_out = _run_command(cmd, timeout=timeout, cwd=cwd)
    if code == 0 and not timed_out:
        return True
    detail = "timed out" if timed_out else _combined_output(stdout, stderr)
    _docker_cleanup_warn(cmd, detail or f"exit {code}")
    return False


def _teardown_compose(compose_base: list[str], work_dir: str | None) -> None:
    """Stop compose project containers and remove locally-built service images."""
    _run_docker_cleanup(
        compose_base + ["down", "--volumes", "--remove-orphans", "--rmi", "local"],
        timeout=60,
        cwd=work_dir,
    )


def _remove_image_tag(image_tag: str) -> None:
    for _ in range(2):
        if _run_docker_cleanup(["docker", "rmi", "-f", image_tag], timeout=30):
            return
        time.sleep(0.5)


def _prune_dangling_images() -> None:
    # Never run a bare `docker image prune -f`: that deletes every dangling
    # image on the host. The label filter scopes the prune to dangling images
    # built by vulscan (they carry the run label from ResourceScope).
    _run_docker_cleanup(
        ["docker", "image", "prune", "-f", "--filter", f"label={_LABEL_RUN}"],
        timeout=60,
    )


def _remove_orphan_vulscan_images(batch_run_id: str | None = None) -> None:
    """Delete vulscan-test-* images scoped to *batch_run_id* when provided."""
    filters = ["reference=vulscan-test-*"]
    if batch_run_id:
        filters.append(f"label={_LABEL_RUN}={batch_run_id}")
    stdout, stderr, code, timed_out = _run_command(
        ["docker", "images", "--filter", filters[0], "-q"]
        + (["--filter", filters[1]] if len(filters) > 1 else []),
        timeout=30,
    )
    if code != 0 or timed_out:
        _docker_cleanup_warn(
            ["docker", "images", "--filter", filters[0]],
            "timed out" if timed_out else _combined_output(stdout, stderr),
        )
        return
    image_ids = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not image_ids:
        return
    _run_docker_cleanup(["docker", "rmi", "-f", *image_ids], timeout=120)


def _cleanup_labeled_containers(batch_run_id: str) -> None:
    stdout, stderr, code, timed_out = _run_command(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label={_LABEL_RUN}={batch_run_id}",
        ],
        timeout=30,
    )
    if code != 0 or timed_out:
        return
    ids = [line.strip() for line in stdout.splitlines() if line.strip()]
    if ids:
        _run_docker_cleanup(["docker", "rm", "-f", *ids], timeout=60)


def prune_vulscan_test_artifacts(batch_run_id: str | None = None) -> None:
    """Reclaim disk from dangling build layers and run-scoped vulscan-test images.

    Only resources labeled for *batch_run_id* are removed. Without a run id
    nothing is pruned at all: a global sweep could delete unrelated images
    from the host or from concurrent dynamic-test batches.
    """
    if not batch_run_id:
        return
    _cleanup_labeled_containers(batch_run_id)
    _remove_orphan_vulscan_images(batch_run_id)
    _prune_dangling_images()


def _cleanup_after_test(
    *,
    scope: ResourceScope | None = None,
    image_tag: str | None = None,
    network_name: str | None = None,
    container_name: str | None = None,
    compose_base: list[str] | None = None,
    work_dir: str | None = None,
) -> None:
    """Best-effort cleanup after one dynamic-test Docker invocation."""
    if container_name:
        _run_docker_cleanup(["docker", "rm", "-f", container_name], timeout=15)
    if compose_base is not None:
        _teardown_compose(compose_base, work_dir)
    if image_tag:
        _remove_image_tag(image_tag)
    if network_name:
        _run_docker_cleanup(["docker", "network", "rm", network_name], timeout=15)


def run_single_container(
    generation: dict,
    finding_id: str,
    container_timeout: int = DEFAULT_CONTAINER_TIMEOUT,
    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
    source_file: str | None = None,
    language: str | None = None,
    repo_path: str | None = None,
    batch_run_id: str | None = None,
    finding: dict | None = None,
    repo_info: dict | None = None,
    sandbox_run_argv: list[str] | None = None,
    sandbox_build_argv: list[str] | None = None,
    require_staged_source: bool = False,
) -> DockerExecutionResult:
    """Build and run a single Docker container for a test."""
    result = DockerExecutionResult()
    start_time = time.time()

    scope = ResourceScope.create(finding_id, batch_run_id=batch_run_id)
    image_tag = scope.image_tag
    network_name = scope.network_name
    container_name = scope.container_name
    compose_base = scope.compose_base()
    used_compose = False

    raw_work_dir = tempfile.mkdtemp(prefix=f"vulscan-test-{scope.safe_id}-")
    parent = os.path.dirname(raw_work_dir)
    safe_basename = re.sub(r"[^a-z0-9-]", "", os.path.basename(raw_work_dir).lower()).strip("-")
    work_dir = os.path.join(parent, safe_basename)
    if work_dir != raw_work_dir:
        os.rename(raw_work_dir, work_dir)

    try:
        disk_err = _check_disk_space(work_dir)
        if disk_err:
            result.build_error = disk_err
            return result

        # Safe path resolution when repo_path is provided
        if source_file and repo_path:
            from core.dynamic_verification.staging import resolve_repo_source_path

            try:
                repo_real = os.path.realpath(repo_path)
                if os.path.isabs(source_file):
                    rel = os.path.relpath(os.path.realpath(source_file), repo_real)
                else:
                    rel = source_file
            except (ValueError, OSError):
                result.build_error = "staging_path_rejected:path_escape_rejected"
                result.staging_blocked = True
                return result
            resolved, err = resolve_repo_source_path(rel, repo_path)
            if err:
                result.build_error = f"staging_path_rejected:{err}"
                result.staging_blocked = True
                return result
            source_file = resolved

        generation = _write_test_files(
            work_dir,
            generation,
            source_file=source_file,
            language=language,
            repo_path=repo_path,
            finding=finding,
            repo_info=repo_info,
        )

        if generation.get("_blocked"):
            result.build_error = generation.get("_blocked_reason", "staging blocked")
            result.staging_blocked = True
            return result

        if require_staged_source:
            from core.dynamic_verification.staging import verify_staged_source

            basename = (
                generation.get("_staged_source_basename")
                or (os.path.basename(source_file) if source_file else "")
            )
            ok, reason = verify_staged_source(work_dir, basename)
            if not ok:
                result.build_error = f"staged_source_missing:{reason}"
                result.staging_blocked = True
                return result

        # Multi-container network path blocked until trusted compose compiler exists
        if generation.get("needs_attacker_server"):
            result.build_error = "needs_network_blocked_until_compose_compiler"
            result.staging_blocked = True
            return result

        result = _run_single(
            work_dir,
            scope,
            container_timeout,
            build_timeout,
            sandbox_run_argv=sandbox_run_argv or generation.get("run_argv"),
            sandbox_build_argv=sandbox_build_argv or generation.get("build_argv"),
            base_image_hint=generation.get("base_image") or "",
        )
        result.image_tag = scope.image_tag
    finally:
        result.elapsed_seconds = time.time() - start_time
        # Digests must already be on result from _run_single before cleanup.
        _cleanup_after_test(
            scope=scope,
            image_tag=None if used_compose else image_tag,
            network_name=network_name if used_compose else None,
            container_name=container_name if not used_compose else None,
            compose_base=compose_base if used_compose else None,
            work_dir=work_dir,
        )
        shutil.rmtree(work_dir, ignore_errors=True)

    return result


def _run_single(
    work_dir: str,
    scope: ResourceScope,
    container_timeout: int,
    build_timeout: int,
    sandbox_run_argv: list[str] | None = None,
    sandbox_build_argv: list[str] | None = None,
    base_image_hint: str = "",
) -> DockerExecutionResult:
    """Build and run a single Docker container under sandbox policy."""
    result = DockerExecutionResult()
    image_tag = scope.image_tag
    container_name = scope.container_name
    result.image_tag = image_tag
    result.build_context_hash = _hash_build_context(work_dir)

    base_image = base_image_hint or _extract_base_image_from_dockerfile(work_dir)
    result.base_image = base_image
    # True offline build: base image must already exist locally — never pull.
    if base_image and not _local_image_exists(base_image):
        result.build_error = f"base_image_missing_locally:{base_image}"
        result.staging_blocked = True
        return result
    if base_image:
        result.base_image_digest = _inspect_image_digest(base_image)

    build_extra = list(sandbox_build_argv) if sandbox_build_argv else ["--network", "none"]
    # Never allow host network / secrets / SSH / pull during build
    banned = {"--privileged", "--secret", "--ssh", "--pull"}
    build_extra = [a for a in build_extra if a not in banned and "docker.sock" not in a]
    # Strip proxy / SSH / secret / pull flags (offline, no registry)
    proxy_keys = ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy")
    cleaned: list[str] = []
    i = 0
    while i < len(build_extra):
        a = build_extra[i]
        al = a.lower()
        if al in ("--secret", "--ssh", "--pull") or al.startswith("--pull="):
            i += 1
            continue
        if al == "--build-arg" and i + 1 < len(build_extra):
            val = build_extra[i + 1].lower()
            if any(k in val for k in proxy_keys) or "ssh" in val:
                i += 2
                continue
            cleaned.extend(["--build-arg", build_extra[i + 1]])
            i += 2
            continue
        if a.startswith("--build-arg="):
            val = a.split("=", 1)[1].lower()
            if any(k in val for k in proxy_keys) or "ssh" in val:
                i += 1
                continue
        cleaned.append(a)
        i += 1
    build_extra = cleaned
    if "--network" not in build_extra:
        build_extra = ["--network", "none", *build_extra]
    if not any(a.startswith("--pull=") for a in build_extra):
        build_extra = ["--pull=false", *build_extra]

    build_cmd = ["docker", "build", *build_extra, "-t", image_tag, "."]
    result.build_command = list(build_cmd)
    stdout, stderr, code, timed_out = _run_command(
        build_cmd,
        timeout=build_timeout,
        cwd=work_dir,
    )
    if code != 0 or timed_out:
        result.build_error = _combined_output(stdout, stderr) if not timed_out else "Build timed out"
        result.stdout = stdout
        result.stderr = stderr
        result.timed_out = timed_out
        return result

    # Capture image digest BEFORE any cleanup path.
    result.image_digest = _inspect_image_digest(image_tag)

    # Trusted policy argv (Phase 10) — never privileged / host net / docker.sock
    policy_argv = list(sandbox_run_argv) if sandbox_run_argv else [
        "--network", "none",
        "--memory", "512m",
        "--cpus", "1",
        "--pids-limit", "256",
        "--cap-drop", "ALL",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
        "--tmpfs", "/var/tmp:rw,noexec,nosuid,size=128m",
        "--tmpfs", "/run:rw,noexec,nosuid,size=64m",
        "--security-opt", "no-new-privileges",
    ]
    # Strip any accidental host-escape flags
    banned = {"--privileged", "--pid=host", "--network=host", "--ipc=host"}
    policy_argv = [a for a in policy_argv if a not in banned and "docker.sock" not in a]

    run_cmd = [
        "docker", "run",
        "--name", container_name,
        *policy_argv,
        *_format_docker_labels(scope),
        image_tag,
    ]
    result.run_command = list(run_cmd)
    stdout, stderr, code, timed_out = _run_command(
        run_cmd,
        timeout=container_timeout,
        cwd=work_dir,
    )

    if timed_out:
        _run_docker_cleanup(["docker", "rm", "-f", container_name], timeout=15)

    result.stdout = stdout
    result.stderr = stderr
    result.exit_code = code
    result.timed_out = timed_out
    # Re-confirm digest still available before caller cleans up image
    if not result.image_digest:
        result.image_digest = _inspect_image_digest(image_tag)

    return result


def _run_compose(
    work_dir: str,
    scope: ResourceScope,
    container_timeout: int,
    build_timeout: int,
) -> DockerExecutionResult:
    """Build and run multi-service test via docker compose."""
    result = DockerExecutionResult()
    compose_base = scope.compose_base()

    try:
        stdout, stderr, code, timed_out = _run_command(
            compose_base + ["build"],
            timeout=build_timeout,
            cwd=work_dir,
        )
        if code != 0 or timed_out:
            result.build_error = _combined_output(stdout, stderr) if not timed_out else "Compose build timed out"
            result.stdout = stdout
            result.stderr = stderr
            result.timed_out = timed_out
            return result

        stdout, stderr, code, timed_out = _run_command(
            compose_base + ["up", "-d"],
            timeout=60,
            cwd=work_dir,
        )
        if code != 0 or timed_out:
            result.build_error = _combined_output(stdout, stderr) if not timed_out else "Compose up timed out"
            result.stdout = stdout
            result.stderr = stderr
            result.timed_out = timed_out
            return result

        stdout, stderr, code, timed_out = _run_command(
            compose_base + ["logs", "--no-log-prefix", "-f", "test"],
            timeout=container_timeout,
            cwd=work_dir,
        )
        result.stdout = stdout
        result.stderr = stderr
        result.exit_code = code
        result.timed_out = timed_out
    finally:
        _teardown_compose(compose_base, work_dir)

    return result


# Legacy alias kept for any external/test callers.
def _cleanup_docker(image_tag: str, network_name: str) -> None:
    """Best-effort cleanup of Docker resources (single-container path)."""
    _cleanup_after_test(image_tag=image_tag, network_name=network_name)
