"""Utility modules for 911VulScan vulnerability analysis."""

from .llm_client import (
    AnthropicClient,
    TokenTracker,
    get_global_tracker,
    reset_global_tracker,
    get_shared_llm_client,
    MODEL_PRICING
)
from .context_enhancer import ContextEnhancer

# Legacy helpers using the old verdict schema — only research/experiment.py
# still needs them. Imported lazily (PEP 562) so ``import utilities`` does not
# pull in the legacy stack; ``from utilities import JSONCorrector`` keeps
# working via the module-level __getattr__ below.
_LAZY_ATTRS = {
    "JSONCorrector": "json_corrector",
    "ContextCorrector": "context_corrector",
    "ContextReviewer": "context_reviewer",
    "GroundTruthChallenger": "ground_truth_challenger",
}

__all__ = [
    'AnthropicClient',
    'TokenTracker',
    'get_global_tracker',
    'reset_global_tracker',
    'MODEL_PRICING',
    'JSONCorrector',
    'ContextCorrector',
    'ContextReviewer',
    'ContextEnhancer',
    'GroundTruthChallenger',
]


def __getattr__(name: str):
    module_name = _LAZY_ATTRS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value
