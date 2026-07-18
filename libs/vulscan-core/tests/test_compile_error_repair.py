"""Tests for compile-error extraction and deterministic harness repair."""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))


SAMPLE_BUILD_LOG = """
#13 ERROR: process "/bin/sh -c gcc ... test_exploit.c ..." did not complete successfully: exit code: 1
1.073 test_exploit.c:26:34: error: storage size of 'cap' isn't known
1.073    26 |     struct vulscan_child_capture cap = vulscan_run_asan_child_ptr(do_attack, &payload);
1.193 test_exploit.c:18:13: error: 'stderr' undeclared (first use in this function)
1.193    18 |     setvbuf(stderr, NULL, _IONBF, 0);
"""


def test_extract_compiler_diagnostics():
    from utilities.dynamic_tester.compile_error_repair import extract_compiler_diagnostics

    diag = extract_compiler_diagnostics(SAMPLE_BUILD_LOG)
    assert "storage size of 'cap' isn't known" in diag
    assert "'stderr' undeclared" in diag
    assert "ERROR: process" not in diag


def test_apply_deterministic_compile_fixes_struct_and_stdio():
    from utilities.dynamic_tester.compile_error_repair import apply_deterministic_compile_fixes

    script = (
        "void run(void) {\n"
        "    struct vulscan_child_capture cap;\n"
        "    setvbuf(stderr, NULL, _IONBF, 0);\n"
        "    vulscan_emit_result_json(\"ERROR\", \"\", \"\");\n"
        "}\n"
    )
    fixed = apply_deterministic_compile_fixes(
        script, language="c", test_filename="test_exploit.c"
    )
    assert "struct vulscan_child_capture" not in fixed
    assert "vulscan_child_capture cap" in fixed
    assert "#include <stdio.h>" in fixed
    assert '#include "vulscan_native_compat.h"' in fixed


def test_js_process_exit_does_not_add_c_include():
    from utilities.dynamic_tester.compile_error_repair import apply_deterministic_compile_fixes

    script = (
        "const _ = require('./lodash.js');\n"
        "console.log(JSON.stringify({status: 'ERROR', details: 'x', evidence: []}));\n"
        "process.exit(0);\n"
    )
    fixed = apply_deterministic_compile_fixes(
        script, language="javascript", test_filename="test_exploit.js"
    )
    assert "#include" not in fixed
    assert "process.exit(0)" in fixed


def test_strip_c_preprocessor_from_js():
    from utilities.dynamic_tester.compile_error_repair import (
        sanitize_high_level_test_script,
        script_has_c_preprocessor,
    )

    script = "#include <stdlib.h>\nconst x = 1;\n"
    cleaned = sanitize_high_level_test_script(
        script, language="javascript", test_filename="test_exploit.js"
    )
    assert "#include" not in cleaned
    assert "const x = 1" in cleaned
    assert script_has_c_preprocessor(script)
    assert not script_has_c_preprocessor(cleaned)


def test_deterministic_repair_generation_returns_none_when_unchanged():
    from utilities.dynamic_tester.compile_error_repair import deterministic_repair_generation

    gen = {"test_script": "int main(void){return 0;}\n", "test_filename": "test_exploit.c"}
    assert deterministic_repair_generation(gen) is None


def test_sanitize_struct_vulscan_child_capture():
    from utilities.dynamic_tester.native_link_mode import sanitize_native_test_script

    fixed = sanitize_native_test_script("struct vulscan_child_capture x;")
    assert fixed == "vulscan_child_capture x;"
