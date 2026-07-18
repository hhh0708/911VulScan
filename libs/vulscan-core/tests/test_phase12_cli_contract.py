"""Phase 12: frozen CLI envelope contract shared by Python and Go."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.schemas import make_envelope

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "phase12_envelope_fixture.json"

# Top-level keys required by Python ``make_envelope`` and Go ``types.Envelope``.
ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "run_id",
        "stage",
        "data",
        "metrics",
        "artifacts",
        "warnings",
        "errors",
    }
)


@pytest.fixture
def frozen_envelope() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_frozen_fixture_exists_and_has_contract_keys(frozen_envelope: dict) -> None:
    assert set(frozen_envelope.keys()) == ENVELOPE_KEYS


def test_make_envelope_emits_contract_keys() -> None:
    envelope = make_envelope(
        status="completed",
        run_id="test-run",
        stage="parse",
        data={"dataset_path": "/tmp/dataset.json"},
        metrics={"total_units": 3},
        artifacts=[{"kind": "dataset", "path": "/tmp/dataset.json"}],
        warnings=["example warning"],
        errors=[],
    )
    assert set(envelope.keys()) == ENVELOPE_KEYS


def test_make_envelope_defaults_match_go_optional_fields() -> None:
    """Go marks run_id/stage/metrics/artifacts/warnings as omitempty; Python always emits them."""
    envelope = make_envelope(status="failed", errors=["boom"])
    assert envelope["run_id"] is None
    assert envelope["stage"] is None
    assert envelope["metrics"] is None
    assert envelope["artifacts"] == []
    assert envelope["warnings"] == []
    assert envelope["errors"] == ["boom"]


def test_frozen_fixture_documents_go_envelope_shape(frozen_envelope: dict) -> None:
    """Documented Go Envelope (apps/vulscan-cli/internal/types/results.go) field names."""
    documented_go_fields = {
        "schema_version": str,
        "status": str,
        "run_id": str,
        "stage": str,
        "data": dict,
        "metrics": dict,
        "artifacts": list,
        "warnings": list,
        "errors": list,
    }
    for key, expected_type in documented_go_fields.items():
        assert key in frozen_envelope
        if frozen_envelope[key] is not None:
            assert isinstance(frozen_envelope[key], expected_type)
