"""Stage 1 candidate-discovery layer (evidence-constrained)."""

from core.detection.schema import (
    DETECTION_PROMPT_VERSION,
    DETECTION_SCHEMA_VERSION,
    DECISIONS,
    DetectionInput,
    DetectionResult,
    EvidenceEntry,
    empty_detection_result,
    normalize_detection_result,
    validate_detection_result,
)
from core.detection.input_builder import build_detection_input, build_evidence_table
from core.detection.checkpoint import AnalyzeCheckpointManager
from core.detection.fingerprint import compute_detection_fingerprint

# Lazy re-export to avoid circular import with prompts.vulnerability_analysis
def analyze_detection_input(*args, **kwargs):
    from core.detection.analyze import analyze_detection_input as _impl

    return _impl(*args, **kwargs)


__all__ = [
    "DETECTION_PROMPT_VERSION",
    "DETECTION_SCHEMA_VERSION",
    "DECISIONS",
    "DetectionInput",
    "DetectionResult",
    "EvidenceEntry",
    "empty_detection_result",
    "normalize_detection_result",
    "validate_detection_result",
    "build_detection_input",
    "build_evidence_table",
    "analyze_detection_input",
    "AnalyzeCheckpointManager",
    "compute_detection_fingerprint",
]
