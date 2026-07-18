"""Tests for native platform resolution in dynamic testing."""

import os
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


def test_windows_harness_maps_to_linux_processimage(tmp_path):
    from utilities.dynamic_tester.native_platform import resolve_native_test_source

    repo = tmp_path / "repo"
    linux_dir = repo / "linux"
    win_dir = repo / "windows" / "HarnessForWindowsDLL" / "dllTest2"
    linux_dir.mkdir(parents=True)
    win_dir.mkdir(parents=True)

    (linux_dir / "imgRead.c").write_text(
        "int ProcessImage(char *filename){return 0;}\n"
    )
    (win_dir / "dllTest2.cpp").write_text(
        '#include "DamnVulnerableHeader.h"\n'
        "int FuzzMe(char *filename){ ProcessImage(filename); return 0; }\n"
    )
    (win_dir / "DamnVulnerableHeader.h").write_text(
        'extern "C" int ProcessImage(char *filename);\n'
    )

    finding = {
        "location": {
            "file": "windows/HarnessForWindowsDLL/dllTest2/dllTest2.cpp",
            "function": "dllTest2.cpp:FuzzMe",
        }
    }

    resolution = resolve_native_test_source(finding, str(repo))
    assert not resolution.blocked
    assert resolution.source_basename == "imgRead.c"
    assert resolution.source_path.endswith(os.path.join("linux", "imgRead.c"))
    # Platform notes must explain that the Windows harness maps onto the
    # Linux implementation of the same symbol.
    assert "linux/imgRead.c" in resolution.platform_notes
    assert "ProcessImage" in resolution.platform_notes


def test_windows_only_without_linux_impl_is_blocked(tmp_path):
    from utilities.dynamic_tester.native_platform import resolve_native_test_source

    repo = tmp_path / "repo"
    win_dir = repo / "windows"
    win_dir.mkdir(parents=True)
    (win_dir / "only.cpp").write_text("int FuzzMe(char *f){return 0;}\n")

    finding = {
        "location": {
            "file": "windows/only.cpp",
            "function": "only.cpp:FuzzMe",
        }
    }

    resolution = resolve_native_test_source(finding, str(repo))
    assert resolution.blocked
    assert "Windows-only target" in resolution.blocked_reason


def test_list_staged_files_uses_linux_fallback(tmp_path):
    from utilities.dynamic_tester.native_platform import list_staged_files_for_finding

    repo = tmp_path / "repo"
    linux_dir = repo / "linux"
    win_dir = repo / "windows"
    linux_dir.mkdir(parents=True)
    win_dir.mkdir(parents=True)
    (linux_dir / "imgRead.c").write_text("int ProcessImage(char *f){return 0;}\n")
    (linux_dir / "imgRead.h").write_text("#define IMGREAD_H\n")
    (win_dir / "dllTest2.cpp").write_text("int FuzzMe(char *f){return 0;}\n")

    finding = {
        "location": {
            "file": "windows/dllTest2.cpp",
            "function": "dllTest2.cpp:FuzzMe",
        }
    }

    basename, staged = list_staged_files_for_finding(finding, str(repo))
    assert basename == "imgRead.c"
    assert "imgRead.h" in staged
