"""Tests for native dynamic-test link mode and compile-source selection."""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))


def test_symbol_is_static_in_cjson_utils():
    from utilities.dynamic_tester.native_link_mode import symbol_is_static_in_source

    source = _CORE_ROOT.parent.parent / "Project_for_911VulScan" / "cJSON" / "cJSON_Utils.c"
    if not source.is_file():
        return
    assert symbol_is_static_in_source(str(source), "decode_array_index_from_pointer")


def test_should_compile_when_using_project_headers():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        _compile_sources,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script='#include "cJSON_Utils.h"\nint main(void){return 0;}',
        staged_files=["test_exploit.c", "cJSON_Utils.c", "cJSON.c", "cJSON_Utils.h", "cJSON.h"],
        source_basename="cJSON_Utils.c",
        target_symbol="decode_array_index_from_pointer",
        finding_source_path=str(
            _CORE_ROOT.parent.parent / "Project_for_911VulScan" / "cJSON" / "cJSON_Utils.c"
        ),
    )
    sources = _compile_sources(ctx)
    assert "cJSON_Utils.c" in sources
    assert "cJSON.c" in sources


def test_should_not_compile_self_contained_reimplementation():
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        _compile_sources,
    )

    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script=(
            "static int decode_array_index_from_pointer(const unsigned char *p, size_t *i)"
            "{ return 0; }\nint main(void){return 0;}"
        ),
        staged_files=["test_exploit.c", "cJSON_Utils.c"],
        source_basename="cJSON_Utils.c",
        target_symbol="decode_array_index_from_pointer",
    )
    sources = _compile_sources(ctx)
    assert "cJSON_Utils.c" not in sources


def test_logic_only_reproduction_detected():
    from utilities.dynamic_tester.native_link_mode import is_logic_only_reproduction

    finding = {
        "location": {"function": "decode_array_index_from_pointer"},
    }
    generation = {
        "test_script": (
            "static int decode_array_index_from_pointer(const unsigned char *p, size_t *i)"
            "{ char buf[8]; buf[10]=1; return 0; }"
            "int main(void){return 0;}"
        ),
    }
    source = _CORE_ROOT.parent.parent / "Project_for_911VulScan" / "cJSON" / "cJSON_Utils.c"
    if not source.is_file():
        return
    assert is_logic_only_reproduction(
        generation, finding, source_path=str(source)
    )


def test_sanitize_strncopy_typo():
    from utilities.dynamic_tester.native_link_mode import sanitize_native_test_script

    fixed = sanitize_native_test_script("strncopy(dst, src, 4);")
    assert "strncpy" in fixed
    assert "strncopy" not in fixed


def test_collect_result_downgrades_logic_only_confirmed():
    from utilities.dynamic_tester.docker_executor import DockerExecutionResult
    from utilities.dynamic_tester.result_collector import collect_result

    source = _CORE_ROOT.parent.parent / "Project_for_911VulScan" / "cJSON" / "cJSON_Utils.c"
    if not source.is_file():
        return

    execution = DockerExecutionResult()
    execution.stderr = "ERROR: AddressSanitizer: stack-buffer-overflow\n"
    execution.exit_code = 1

    result = collect_result(
        {"id": "VULN-TEST", "location": {"function": "decode_array_index_from_pointer"}},
        {
            "test_script": (
                "static int decode_array_index_from_pointer(const unsigned char *p, size_t *i)"
                "{ return 0; } int main(void){return 0;}"
            ),
            "dockerfile": "FROM gcc:13",
            "_finding_source_path": str(source),
        },
        execution,
    )
    assert result.status == "INCONCLUSIVE"
    assert "reimplementation" in result.details.lower()
