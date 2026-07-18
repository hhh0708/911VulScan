"""Canonical dynamic verification layer (Phase 10)."""

from __future__ import annotations

from core.dynamic_verification.input_builder import (
    build_dynamic_input,
    is_dynamic_eligible,
)
from core.dynamic_verification.schema import (
    DECISIONS,
    EXECUTION_STATES,
    SUPPORTED_DYNAMIC_LANGUAGES,
    TestPlan,
    DynamicVerificationInput,
    DynamicVerificationResult,
    can_emit_not_reproduced,
    empty_dynamic_result,
    is_supported_language,
    normalize_dynamic_decision,
    skipped_dynamic_result,
    validate_test_plan,
)

__all__ = [
    "DECISIONS",
    "EXECUTION_STATES",
    "SUPPORTED_DYNAMIC_LANGUAGES",
    "TestPlan",
    "DynamicVerificationInput",
    "DynamicVerificationResult",
    "build_dynamic_input",
    "is_dynamic_eligible",
    "can_emit_not_reproduced",
    "empty_dynamic_result",
    "is_supported_language",
    "normalize_dynamic_decision",
    "skipped_dynamic_result",
    "validate_test_plan",
]
