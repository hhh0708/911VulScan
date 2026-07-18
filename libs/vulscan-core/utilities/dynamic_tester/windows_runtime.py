"""Windows-container support detection for native dynamic tests.

Important: Linux Docker hosts cannot run Windows container images
(mcr.microsoft.com/windows/...). There is no gcc:13-equivalent Windows image
that can be pulled on Linux the same way. Windows containers require a Windows
Docker host with OS container mode enabled.
"""

from __future__ import annotations

import os
import subprocess

from utilities.file_io import run_utf8

WINDOWS_NATIVE_IMAGE = os.environ.get(
    "VULSCAN_WINDOWS_NATIVE_IMAGE",
    "mcr.microsoft.com/windows/servercore:ltsc2022",
)


def docker_host_ostype() -> str:
    """Return docker info OSType (linux/windows) or 'unknown'."""
    try:
        proc = run_utf8(
            ["docker", "info", "-f", "{{.OSType}}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if proc.returncode != 0:
        return "unknown"
    return (proc.stdout or "").strip().lower() or "unknown"


def windows_containers_enabled() -> bool:
    """True when the operator explicitly opts into Windows container tests."""
    return os.environ.get("VULSCAN_ENABLE_WINDOWS_CONTAINERS", "").strip() in {
        "1",
        "true",
        "yes",
    }


def windows_builder_image() -> str | None:
    """Optional Windows builder image with cl.exe/MSVC or LLVM preinstalled."""
    value = os.environ.get("VULSCAN_WINDOWS_BUILDER_IMAGE", "").strip()
    return value or None


def windows_containers_supported() -> bool:
    """True only on a Windows Docker host with the feature flag enabled."""
    return windows_containers_enabled() and docker_host_ostype() == "windows"


def windows_container_guidance(rel_path: str, impl_symbol: str) -> str:
    """Explain why pure-Windows targets cannot run on the current host."""
    ostype = docker_host_ostype()
    lines = [
        f"Windows-only target `{rel_path}` has no Linux implementation of "
        f"`{impl_symbol}()` in this repository.",
        f"The current Docker host runs `{ostype}` containers.",
    ]
    if ostype == "linux":
        lines.extend([
            "Linux Docker cannot run Windows images such as "
            f"`{WINDOWS_NATIVE_IMAGE}` (unlike pulling `gcc:13` on Linux).",
            "Options:",
            "1. Keep using the automatic Linux-port mapping when a matching "
            f"`{impl_symbol}()` implementation exists elsewhere in the repo.",
            "2. Run 911VulScan on a Windows machine with Docker set to "
            "Windows containers, then set VULSCAN_ENABLE_WINDOWS_CONTAINERS=1.",
            "3. Add a Linux port of the vulnerable code to the repository.",
        ])
    else:
        lines.extend([
            "Set VULSCAN_ENABLE_WINDOWS_CONTAINERS=1 to attempt an experimental "
            f"Windows container build using `{WINDOWS_NATIVE_IMAGE}`.",
            "Note: there is no lightweight gcc:13-equivalent image on Windows; "
            "builds rely on MSVC/LLVM inside Server Core and are slower to set up.",
        ])
    return " ".join(lines)
