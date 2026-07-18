"""Tests for dynamic test generation validation."""


def test_cxx_generation_filename_is_allowed():
    from utilities.dynamic_tester.test_generator import _reject_invalid_generation

    parsed = {
        "dockerfile": "# assembled by 911VulScan",
        "test_script": "int main(){return 0;}",
        "test_filename": "test_exploit.cxx",
    }

    assert not _reject_invalid_generation(parsed, {"language": "cpp"})

