"""Tests for scan progress numbering."""


def test_count_steps_fixed_pipeline():
    from core.scanner import _count_steps

    assert _count_steps(
        app_context=True,
        enhance=True,
        verify=True,
        generate_report=True,
        dynamic_verify=False,
    ) == 9


def test_count_steps_counts_numbered_skip_lines():
    from core.scanner import _count_steps

    assert _count_steps(
        app_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_verify=False,
    ) == 9


def test_count_steps_independent_of_optional_flags():
    from core.scanner import _count_steps

    a = _count_steps(True, True, True, True, True)
    b = _count_steps(False, False, False, False, False)
    assert a == b == 9
