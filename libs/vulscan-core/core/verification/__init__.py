"""Stage 2 candidate verification state machine."""

from core.verification.schema import (
    VERIFICATION_PROMPT_VERSION,
    VERIFICATION_SCHEMA_VERSION,
    VERIFICATION_TOOLS_VERSION,
    DECISIONS,
    EXECUTION_STATES,
    empty_verification_result,
    normalize_verification_result,
    skipped_result,
    validate_verification_result,
)
from core.verification.fingerprint import (
    compute_finding_id,
    compute_verification_fingerprint,
)
from core.verification.checkpoint import VerifyCheckpointManager


def build_verification_input(*args, **kwargs):
    from core.verification.input_builder import build_verification_input as _impl

    return _impl(*args, **kwargs)


def append_tool_evidence(*args, **kwargs):
    from core.verification.input_builder import append_tool_evidence as _impl

    return _impl(*args, **kwargs)


def CandidateVerifier(*args, **kwargs):
    from core.verification.engine import CandidateVerifier as _Impl

    return _Impl(*args, **kwargs)


__all__ = [
    "VERIFICATION_PROMPT_VERSION",
    "VERIFICATION_SCHEMA_VERSION",
    "VERIFICATION_TOOLS_VERSION",
    "DECISIONS",
    "EXECUTION_STATES",
    "empty_verification_result",
    "normalize_verification_result",
    "skipped_result",
    "validate_verification_result",
    "compute_finding_id",
    "compute_verification_fingerprint",
    "build_verification_input",
    "append_tool_evidence",
    "VerifyCheckpointManager",
    "CandidateVerifier",
]
