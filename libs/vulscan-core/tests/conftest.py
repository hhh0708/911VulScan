"""Shared fixtures for 911VulScan tests."""
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Ensure the project root is on sys.path so imports like `from utilities...` work
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if "anthropic" not in sys.modules:
    _anthropic = types.ModuleType("anthropic")
    _anthropic.Anthropic = MagicMock()
    _anthropic.RateLimitError = type("RateLimitError", (Exception,), {})
    _anthropic.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _anthropic

if "dotenv" not in sys.modules:
    _dotenv = types.ModuleType("dotenv")
    _dotenv.load_dotenv = MagicMock()
    sys.modules["dotenv"] = _dotenv

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_PYTHON_REPO = FIXTURES_DIR / "sample_python_repo"
SAMPLE_JS_REPO = FIXTURES_DIR / "sample_js_repo"


@pytest.fixture
def sample_python_repo():
    """Path to the sample Python repository fixture."""
    return str(SAMPLE_PYTHON_REPO)


@pytest.fixture
def sample_js_repo():
    """Path to the sample JavaScript repository fixture."""
    return str(SAMPLE_JS_REPO)


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Temporary output directory for parser results."""
    return str(tmp_path / "output")
