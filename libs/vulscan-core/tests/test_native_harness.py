"""Tests for native harness validation and notes."""

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


def test_native_test_script_rejects_execl_of_staged_binary():
    from utilities.dynamic_tester.native_harness import native_test_script_errors

    script = (
        'int main(void) {\n'
        '  execl("/work/imgRead", "imgRead", "/tmp/x", NULL);\n'
        '  return 0;\n'
        '}\n'
    )
    errors = native_test_script_errors(script, "imgRead.c")
    assert errors


def test_build_linked_harness_notes_mentions_test_exploit(tmp_path):
    from utilities.dynamic_tester.native_harness import build_linked_harness_notes

    source = tmp_path / "dvcp.c"
    source.write_text("int ProcessImage(char *filename){return 0;}\n")
    finding = {"location": {"function": "dvcp.c:ProcessImage"}}

    notes = build_linked_harness_notes(finding, "dvcp.c", str(source))
    assert "/work/test_exploit" in notes
    assert "ProcessImage" in notes
    assert "NEVER execl" in notes
