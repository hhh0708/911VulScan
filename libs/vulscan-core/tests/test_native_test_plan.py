"""Tests for native dynamic test planning."""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    sys.modules["anthropic"] = _stub


def test_extract_struct_layouts_img_struct():
    from utilities.dynamic_tester.native_test_plan import extract_struct_layouts

    source = """
    struct Image {
        char header[4];
        int width;
        int height;
        char data[10];
    };
    """
    layouts = extract_struct_layouts(source)
    assert len(layouts) == 1
    assert layouts[0].name == "Image"
    assert layouts[0].estimated_size == 22


def test_extract_payload_hints_from_steps():
    from utilities.dynamic_tester.native_test_plan import extract_payload_hints

    hints = extract_payload_hints(
        "Set width=0x7FFFFFFF and height=2 to trigger integer overflow"
    )
    assert hints["width"] == "0x7FFFFFFF"
    assert hints["height"] == "2"


def test_validate_rejects_partial_fwrite_and_fclose_stderr():
    from utilities.dynamic_tester.native_test_plan import (
        NativeTestPlan,
        NativeTestStrategy,
        StructField,
        StructLayout,
        validate_native_test_script,
    )

    plan = NativeTestPlan(
        cwe_id=787,
        strategy=NativeTestStrategy.ASAN_CRASH,
        sanitizer_flags="-fsanitize=address,undefined -g -O0",
        struct_layouts=[
            StructLayout(
                name="Image",
                fields=(
                    StructField("header", 4, "char header[4]"),
                    StructField("width", 4, "int width"),
                    StructField("height", 4, "int height"),
                    StructField("data", 10, "char data[10]"),
                ),
                body="",
            )
        ],
    )
    bad_script = (
        'int main(){ FILE *f=fopen("/tmp/x","wb"); '
        'unsigned w=1,h=1; fwrite(&w,8,1,f); fclose(stderr); return 0; }'
    )
    errors = validate_native_test_script(bad_script, plan=plan)
    assert any("8 bytes" in e for e in errors)
    assert any("fclose(stderr)" in e for e in errors)


def test_proven_exploit_registry_hints_for_siblings():
    from utilities.dynamic_tester.native_test_plan import ProvenExploitRegistry

    registry = ProvenExploitRegistry()
    registry.register(
        "VULN-003",
        "imgRead.c",
        "ProcessImage",
        "struct Image img; img.width = -1; img.height = 1; fwrite(&img, sizeof(img), 1, fp);",
    )
    hints = registry.hints_for("imgRead.c", "ProcessImage")
    assert "VULN-003" in hints
    assert "sizeof(img)" in hints


def test_build_native_dockerfile_uses_ubsan_flags(tmp_path):
    from utilities.dynamic_tester.dockerfile_builder import (
        StagedBuildContext,
        build_native_dockerfile,
    )
    from utilities.dynamic_tester.native_test_plan import (
        NativeTestPlan,
        NativeTestStrategy,
    )

    plan = NativeTestPlan(
        cwe_id=190,
        strategy=NativeTestStrategy.ASAN_CRASH,
        sanitizer_flags="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O0",
    )
    ctx = StagedBuildContext(
        language="c",
        test_filename="test_exploit.c",
        test_script="int main(void){return 0;}\n",
        staged_files=["dvcp.c", "test_exploit.c"],
        sanitizer_flags=plan.sanitizer_flags,
        struct_layout_header_lines=plan.struct_layout_header_lines(),
    )
    dockerfile = build_native_dockerfile(ctx)
    assert "-fsanitize=address,undefined" in dockerfile
    assert "vulscan_native_runtime.c" in dockerfile
    assert "vulscan_run_asan_child_void" in dockerfile or "vulscan_native_compat.h" in dockerfile
