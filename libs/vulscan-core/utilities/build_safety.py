"""Host build-execution policy for untrusted target repositories.

Several extraction steps would otherwise run the *target* repository's own
build tooling directly on the host:

  * ``cmake`` configure (to emit ``compile_commands.json`` for the C parser)
  * CodeQL ``database create`` for compiled languages (c/cpp/go), which runs
    the project's autobuild on the host by default.

When the target repository is untrusted (the normal case for a scanner), that
is arbitrary code execution on the host. We therefore default to *not* running
target build tooling, and require an explicit opt-in for trusted repositories.

Set ``VULSCAN_ALLOW_HOST_BUILD=1`` (or true/yes/on) to re-enable host builds.
"""

from __future__ import annotations

import os

# Languages whose CodeQL extractor invokes the project build (autobuild) by
# default. Interpreted languages (python/javascript/ruby/php) extract without
# building and are unaffected by this policy.
_COMPILED_CODEQL_LANGUAGES = {
    "c", "cpp", "c-cpp", "go", "java", "csharp", "swift", "kotlin",
}

_TRUTHY = {"1", "true", "yes", "on"}


def host_build_allowed() -> bool:
    """True only if the operator explicitly opted into running target builds."""
    return os.environ.get("VULSCAN_ALLOW_HOST_BUILD", "").strip().lower() in _TRUTHY


def ensure_safe_codeql_create(cmd: list[str], language: str) -> list[str]:
    """Return a ``codeql database create`` argv that won't autobuild untrusted code.

    For compiled languages we append ``--build-mode=none`` (extraction without
    invoking the project's build system) unless the operator allowed host
    builds. Interpreted languages and explicit opt-in are returned unchanged.
    """
    lang = (language or "").strip().lower()
    if lang not in _COMPILED_CODEQL_LANGUAGES:
        return cmd
    if host_build_allowed():
        return cmd
    if any(str(arg).startswith("--build-mode") for arg in cmd):
        return cmd
    return [*cmd, "--build-mode=none"]
