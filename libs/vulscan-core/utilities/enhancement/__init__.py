"""Neutral Context Enhancement schema, fingerprinting, and checkpoints."""

from utilities.enhancement.schema import (
    ENHANCEMENT_SCHEMA_VERSION,
    ENHANCEMENT_PROMPT_VERSION,
    EnhancementPayload,
    empty_enhancement,
    normalize_enhancement,
    validate_enhancement,
)
from utilities.enhancement.fingerprint import (
    EnhancementFingerprintInputs,
    compute_enhancement_fingerprint,
    graph_neighborhood,
)
from utilities.enhancement.checkpoint import EnhanceCheckpointManager

__all__ = [
    "ENHANCEMENT_SCHEMA_VERSION",
    "ENHANCEMENT_PROMPT_VERSION",
    "EnhancementPayload",
    "empty_enhancement",
    "normalize_enhancement",
    "validate_enhancement",
    "EnhancementFingerprintInputs",
    "compute_enhancement_fingerprint",
    "graph_neighborhood",
    "EnhanceCheckpointManager",
]
