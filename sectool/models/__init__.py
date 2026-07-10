"""Provider-agnostic LLM adapter layer.

See base.py for the ModelAdapter interface, prompt.py for the shared prompt
template every adapter uses, and registry.py for how a ModelConfig turns
into a concrete adapter instance.
"""

from sectool.models.base import FixRequest, FixResponse, ModelAdapter, ModelAdapterError
from sectool.models.registry import build_adapter

__all__ = [
    "FixRequest",
    "FixResponse",
    "ModelAdapter",
    "ModelAdapterError",
    "build_adapter",
]
