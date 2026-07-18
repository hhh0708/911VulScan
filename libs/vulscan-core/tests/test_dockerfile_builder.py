"""Tests for deterministic Dockerfile assembly (dockerfile_builder)."""

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


BROKEN_HEREDOC_DOCKERFILE = """\
FROM gcc:13
WORKDIR /work
COPY cJSON.c .
COPY test_exploit.c .
RUN cat > cJSON.h << 'HDREOF'
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
HDREOF
RUN gcc -fsanitize=address -o /work/test_exploit test_exploit.c cJSON.c
CMD ["/work/test_exploit"]
"""


def test_validate_dockerfile_rejects_broken_heredoc():
    from utilities.dynamic_tester.dockerfile_builder import validate_dockerfile

    errors = validate_dockerfile(BROKEN_HEREDOC_DOCKERFILE)
    assert errors, "broken heredoc Dockerfile must fail validation"
    assert any("heredoc" in e.lower() or "extern" in e.lower() for e in errors)


def test_build_native_dockerfile_cjson_style():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
        validate_dockerfile,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script='void cJSON_Minify(char *json);\n',
        staged_files=["cJSON.c", "cJSON.h", "test_exploit.c"],
        source_basename="cJSON.c",
    )
    dockerfile = build_native_dockerfile(ctx)

    assert "FROM gcc:13" in dockerfile
    assert "COPY cJSON.c ." in dockerfile
    assert "COPY cJSON.h ." in dockerfile
    assert "COPY test_exploit.c ." in dockerfile
    assert "HDREOF" not in dockerfile
    assert "<< 'HDREOF'" not in dockerfile
    assert "test_exploit.c cJSON.c" in dockerfile or "cJSON.c" in dockerfile
    assert "vulscan_native_compat.h" in dockerfile
    assert "test -x /work/test_exploit" in dockerfile
    assert validate_dockerfile(dockerfile) == []


def test_build_native_skips_source_when_included_in_test():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script='#include "cJSON.c"\n',
        staged_files=["cJSON.c", "cJSON.h", "test_exploit.c"],
    )
    dockerfile = build_native_dockerfile(ctx)
    assert "cJSON.c cJSON.c" not in dockerfile
    assert "test_exploit.c" in dockerfile
    # cJSON.c should not appear twice on compile line
    compile_line = [ln for ln in dockerfile.splitlines() if ln.startswith("RUN gcc")][0]
    assert compile_line.count("cJSON.c") == 0


def test_build_native_compiles_target_source_as_object():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script="void cJSON_Minify(char *);\nint main(){return 0;}\n",
        staged_files=["cJSON.c", "cJSON.h", "test_exploit.c"],
        source_basename="cJSON.c",
    )
    dockerfile = build_native_dockerfile(ctx)

    compile_lines = [ln for ln in dockerfile.splitlines() if ln.startswith("RUN gcc")]
    assert any("-c cJSON.c" in ln and "-Dmain=vulscan_target_main_" in ln for ln in compile_lines)
    link_line = compile_lines[-1]
    assert "test_exploit.c cJSON.c" not in link_line
    assert "/work/.vulscan-objects/" in link_line


def test_build_native_renames_target_main_before_linking():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script="int main(void){return 0;}\n",
        staged_files=["dvcp.c", "test_exploit.c"],
        source_basename="dvcp.c",
    )
    dockerfile = build_native_dockerfile(ctx)

    assert "COPY dvcp.c ." in dockerfile
    assert "-Dmain=vulscan_target_main_dvcp_" in dockerfile
    assert "__AFL_FUZZ_TESTCASE_BUF" in dockerfile
    link_line = [ln for ln in dockerfile.splitlines() if "-o /work/test_exploit" in ln][0]
    assert "test_exploit.c dvcp.c" not in link_line
    assert "/work/.vulscan-objects/dvcp_" in link_line


def test_build_native_cpp_uses_permissive_and_windows_compat():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.cpp",
        test_script="int main(void){return 0;}\n",
        staged_files=["DamnVulnerableHeader.h", "dllTest2.cpp", "test_exploit.cpp"],
        source_basename="dllTest2.cpp",
    )
    dockerfile = build_native_dockerfile(ctx)

    assert "RUN g++" in dockerfile
    assert "-fpermissive" in dockerfile
    assert "#define __declspec(x)" in dockerfile
    assert "-Dmain=vulscan_target_main_dllTest2_" in dockerfile


def test_build_native_uses_cpp_compiler_for_cpp_target_with_c_harness():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        _COMPAT_HEADER_LINES,
        build_native_dockerfile,
    )

    header = "\n".join(_COMPAT_HEADER_LINES)
    assert 'extern "C" {' in header
    assert header.index('extern "C" {') < header.index("vulscan_emit_result_json")
    assert header.index("vulscan_emit_result_json") < header.rindex("}")

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script="extern int FuzzMe(char *);\nint main(void){return 0;}\n",
        staged_files=["DamnVulnerableHeader.h", "dllTest2.cpp", "test_exploit.c"],
        source_basename="dllTest2.cpp",
    )
    dockerfile = build_native_dockerfile(ctx)

    compile_lines = [ln for ln in dockerfile.splitlines() if ln.startswith("RUN ")]
    assert any(ln.startswith("RUN g++") and "-c dllTest2.cpp" in ln for ln in compile_lines)
    link_line = [ln for ln in compile_lines if "-o /work/test_exploit" in ln][0]
    assert link_line.startswith("RUN g++")
    assert "-x c test_exploit.c -x none" in link_line


def test_finalize_replaces_llm_dockerfile_for_native(tmp_path):
    from utilities.dynamic_tester.dockerfile_builder import (
        finalize_dockerfile,
        validate_dockerfile,
    )

    dockerfile = finalize_dockerfile(
        BROKEN_HEREDOC_DOCKERFILE,
        language="c",
        test_filename="test_exploit.c",
        test_script="void cJSON_Minify(char *);",
        staged_files=["cJSON.c", "cJSON.h", "test_exploit.c"],
        source_basename="cJSON.c",
    )
    assert "HDREOF" not in dockerfile
    assert validate_dockerfile(dockerfile) == []


def test_write_test_files_emits_valid_native_dockerfile(tmp_path):
    from utilities.dynamic_tester.docker_executor import _write_test_files
    from utilities.dynamic_tester.dockerfile_builder import (
        validate_dockerfile as validate_df,
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "cJSON.c").write_text("void cJSON_Minify(char *json) {}\n")
    (repo / "cJSON.h").write_text("#ifndef CJSON_H\n#define CJSON_H\n#endif\n")

    work_dir = tmp_path / "work"
    work_dir.mkdir()
    generation = {
        "dockerfile": BROKEN_HEREDOC_DOCKERFILE,
        "test_script": "void cJSON_Minify(char *);\nint main(){return 0;}\n",
        "test_filename": "test_exploit.c",
        "_language": "c",
    }

    out = _write_test_files(
        str(work_dir),
        generation,
        source_file=str(repo / "cJSON.c"),
        language="c",
    )

    written = (work_dir / "Dockerfile").read_text(encoding="utf-8")
    assert out["dockerfile"] == written
    assert validate_df(written) == []
    assert "COPY cJSON.h ." in written
    assert "HDREOF" not in written


def test_list_staged_files_for_finding(tmp_path):
    from utilities.dynamic_tester.dockerfile_builder import list_staged_files_for_finding

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "lib.c").write_text("int x;")
    (repo / "lib.h").write_text("#define LIB_H")

    finding = {"location": {"file": "lib.c"}}
    basename, staged = list_staged_files_for_finding(finding, str(repo))
    assert basename == "lib.c"
    assert "lib.h" in staged
    assert "lib.c" in staged
