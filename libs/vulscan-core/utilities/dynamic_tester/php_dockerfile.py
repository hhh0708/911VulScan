"""PHP dynamic-test Dockerfile fixes (Composer, dependency sanitization)."""

from __future__ import annotations

import json
import re


_COMPOSER_RUN_RE = re.compile(r"\bcomposer\s+(install|require|update|dump-autoload)\b", re.I)
_COMPOSER_PRESENT_RE = re.compile(
    r"COPY\s+--from=composer|getcomposer\.org|/usr/bin/composer",
    re.I,
)


def sanitize_composer_json_text(text: str) -> str:
    """Drop optional native extensions that break slim PHP test images."""
    if not text or not text.strip():
        return text
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return re.sub(r'"ext-grpc"\s*:\s*"[^"]*"\s*,?\s*', "", text, flags=re.I)

    if not isinstance(data, dict):
        return text

    req = data.get("require")
    if isinstance(req, dict):
        for key in list(req.keys()):
            if key.lower().startswith("ext-grpc"):
                del req[key]
        data["require"] = req

    config = data.get("config")
    if not isinstance(config, dict):
        config = {}
    # Dynamic tests need installable deps; Composer 2.9+ blocks advisory-affected packages.
    audit = config.get("audit")
    if not isinstance(audit, dict):
        audit = {}
    audit.setdefault("block-insecure", False)
    config["audit"] = audit
    data["config"] = config

    return json.dumps(data, indent=2) + "\n"


def ensure_composer_in_dockerfile(dockerfile: str) -> str:
    """Inject Composer binary when the Dockerfile runs composer without installing it."""
    if not dockerfile or not _COMPOSER_RUN_RE.search(dockerfile):
        return dockerfile
    if _COMPOSER_PRESENT_RE.search(dockerfile):
        return dockerfile

    lines = dockerfile.splitlines()
    out: list[str] = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.strip().upper().startswith("FROM "):
            out.append("COPY --from=composer:2 /usr/bin/composer /usr/bin/composer")
            inserted = True

    if not inserted:
        out.insert(0, "COPY --from=composer:2 /usr/bin/composer /usr/bin/composer")

    return "\n".join(out)


def finalize_php_dockerfile(dockerfile: str) -> str:
    """Apply deterministic PHP Dockerfile corrections."""
    return ensure_composer_in_dockerfile(dockerfile)


def is_registry_pull_failure(build_error: str | None) -> bool:
    """True when Docker failed to reach a registry (not a harness bug)."""
    if not build_error:
        return False
    lowered = build_error.lower()
    markers = (
        "auth.docker.io",
        "registry-1.docker.io",
        "failed to fetch anonymous token",
        "deadlineexceeded",
        "i/o timeout",
        "connection timed out",
        "tls handshake timeout",
    )
    return any(m in lowered for m in markers)
