"""Language stage registry and BuildPlan resolution."""

from __future__ import annotations

import os
from typing import Protocol

from utilities.dynamic_tester.build_plan import BuildPlan
from utilities.dynamic_tester.dockerfile_builder import normalize_language
from utilities.dynamic_tester.go_stage import plan_go_staged_files
from utilities.dynamic_tester.javascript_stage import plan_javascript_staged_files
from utilities.dynamic_tester.native_platform import (
    list_staged_files_for_finding,
    resolve_native_test_source,
)
from utilities.dynamic_tester.native_test_plan import (
    NativeTestPlan,
    ProvenExploitRegistry,
    build_native_test_plan,
)
from utilities.dynamic_tester.python_stage import plan_python_staged_files

_NATIVE_LANGUAGES = frozenset({"c", "cpp", "c++"})
_GO_LANGUAGES = frozenset({"go", "golang"})
_PYTHON_LANGUAGES = frozenset({"python", "py"})
_JS_LANGUAGES = frozenset({"javascript", "js", "typescript", "ts"})

_TEST_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "c": (".c",),
    "cpp": (".cpp", ".cc", ".cxx"),
    "c++": (".cpp", ".cc", ".cxx"),
    "python": (".py",),
    "py": (".py",),
    "go": (".go",),
    "golang": (".go",),
    "javascript": (".js",),
    "js": (".js",),
    "typescript": (".ts",),
    "ts": (".ts",),
    "php": (".php",),
    "ruby": (".rb",),
}


class LanguageStage(Protocol):
    """Protocol for per-language staging and validation."""

    def plan_staging(
        self,
        finding: dict,
        repo_path: str | None,
        source_path: str | None,
    ) -> tuple[list[str], str | None, str | None, str]: ...

    def validate_test_filename(self, test_filename: str) -> bool: ...


def allowed_test_extensions(language: str) -> tuple[str, ...]:
    lang = normalize_language(language)
    return _TEST_EXTENSIONS.get(lang, (".py",))


def validate_test_filename_for_language(test_filename: str, language: str) -> bool:
    name = (test_filename or "").lower()
    exts = allowed_test_extensions(language)
    return any(name.endswith(ext) for ext in exts)


def _resolve_source_path(finding: dict, repo_path: str | None) -> str | None:
    resolution = resolve_native_test_source(finding, repo_path)
    if resolution.source_path:
        return resolution.source_path
    if not repo_path:
        return None
    rel = finding.get("location", {}).get("file", "")
    if not rel:
        return None
    candidate = os.path.join(repo_path, rel)
    return candidate if os.path.isfile(candidate) else None


def resolve_native_plan(
    finding: dict,
    repo_path: str | None,
    registry: ProvenExploitRegistry | None = None,
) -> NativeTestPlan | None:
    resolution = resolve_native_test_source(finding, repo_path)
    source_path = resolution.source_path or _resolve_source_path(finding, repo_path)
    source_basename = resolution.source_basename
    if not source_basename and source_path:
        source_basename = os.path.basename(source_path)
    if not source_basename:
        return None
    return build_native_test_plan(
        finding,
        repo_path=repo_path,
        source_path=source_path,
        source_basename=source_basename,
        registry=registry,
    )


def materialize_build_plan(
    generation: dict,
    finding: dict,
    repo_info: dict,
    repo_path: str | None = None,
    native_plan: NativeTestPlan | None = None,
) -> BuildPlan:
    """Assemble authoritative BuildPlan from LLM generation + repo context."""
    language = repo_info.get("language", "Python")
    lang_norm = normalize_language(language)
    test_filename = generation.get("test_filename", "test_exploit.py")
    test_script = generation.get("test_script", "")
    needs_attacker = bool(generation.get("needs_attacker_server"))

    resolution = resolve_native_test_source(finding, repo_path)
    runtime = resolution.runtime or "linux"
    source_path = resolution.source_path or _resolve_source_path(finding, repo_path)

    if resolution.source_basename:
        source_basename = resolution.source_basename
        staged_files = list(resolution.staged_basenames)
    else:
        source_basename, staged_files = list_staged_files_for_finding(finding, repo_path)

    go_module_path = None
    package_root = None
    blocked = False
    blocked_reason = ""

    if lang_norm in _NATIVE_LANGUAGES:
        if native_plan is None:
            native_plan = resolve_native_plan(finding, repo_path)
    elif lang_norm in _GO_LANGUAGES and source_path:
        go_staged, go_module_path = plan_go_staged_files(source_path, repo_path)
        if not go_staged:
            blocked = True
            blocked_reason = "Go project requires go.mod near finding source"
        else:
            staged_files = sorted(set(staged_files) | set(go_staged))
    elif lang_norm in _PYTHON_LANGUAGES and source_path:
        py_staged, package_root, reason = plan_python_staged_files(source_path, repo_path)
        if reason:
            blocked = True
            blocked_reason = reason
        elif py_staged:
            staged_files = sorted(set(staged_files) | set(py_staged))
    elif lang_norm in _JS_LANGUAGES and source_path:
        js_staged, package_root, reason = plan_javascript_staged_files(source_path, repo_path)
        if reason:
            blocked = True
            blocked_reason = reason
        elif js_staged:
            staged_files = sorted(set(staged_files) | set(js_staged))

    if test_filename and test_filename not in staged_files:
        staged_files.append(test_filename)

    execution_mode = "compose" if needs_attacker else "single"

    return BuildPlan(
        language=language,
        test_filename=test_filename,
        test_script=test_script,
        requirements=generation.get("requirements", "") or "",
        requirements_filename=generation.get("requirements_filename", "requirements.txt"),
        needs_attacker_server=needs_attacker,
        execution_mode=execution_mode,
        staged_files=sorted(set(staged_files)),
        source_basename=source_basename,
        source_path=source_path,
        go_module_path=go_module_path,
        native_plan=native_plan,
        runtime=runtime,
        blocked=blocked,
        blocked_reason=blocked_reason,
        package_root=package_root,
    )


def should_use_framework_dockerfile(plan: BuildPlan) -> bool:
    """Whether the framework owns Dockerfile generation for this plan."""
    lang = normalize_language(plan.language)
    if lang in _NATIVE_LANGUAGES:
        return bool(plan.staged_files)
    if lang in _GO_LANGUAGES:
        return "module/go.mod" in plan.staged_files
    if lang in _PYTHON_LANGUAGES:
        return True
    if lang in _JS_LANGUAGES:
        return True
    return False
