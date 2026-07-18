"""
Stage 2 Finding Verifier — compatibility shim.

Production Stage 2 lives in ``core.verification``. Import
``CandidateVerifier`` from there for new code.
"""

from __future__ import annotations


def __getattr__(name: str):
    if name in {
        "VERIFIER_MODEL",
        "MAX_ITERATIONS",
        "VERIFICATION_TOOLS",
        "CandidateVerifier",
        "FindingVerifier",
    }:
        from core.verification import engine as _engine

        mapping = {
            "VERIFIER_MODEL": _engine.VERIFIER_MODEL,
            "MAX_ITERATIONS": _engine.MAX_ITERATIONS,
            "VERIFICATION_TOOLS": _engine.VERIFICATION_TOOLS,
            "CandidateVerifier": _engine.CandidateVerifier,
            "FindingVerifier": _engine.CandidateVerifier,
        }
        return mapping[name]
    if name == "VerificationResult":
        return _LegacyVerificationResult
    raise AttributeError(name)


class _LegacyVerificationResult:
    """Deprecated — use core.verification.schema instead."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def to_dict(self):
        return dict(self.__dict__)
