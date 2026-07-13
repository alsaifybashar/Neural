"""Instantiates the right ModelAdapter subclass for a ModelConfig.provider.

Adding a new provider means adding one entry to `_ADAPTERS` and one adapter
module -- nothing else in the pipeline references provider names directly.
"""

from __future__ import annotations

from sectool.config import ModelConfig
from sectool.models.anthropic_adapter import AnthropicAdapter
from sectool.models.base import ModelAdapter, ModelAdapterError
from sectool.models.ollama_adapter import OllamaAdapter
from sectool.models.openai_adapter import OpenAIAdapter

_ADAPTERS: dict[str, type[ModelAdapter]] = {
    "anthropic": AnthropicAdapter,
    "openai": OpenAIAdapter,
    "ollama": OllamaAdapter,
}


def build_adapter(config: ModelConfig) -> ModelAdapter:
    adapter_cls = _ADAPTERS.get(config.provider)
    if adapter_cls is None:
        raise ModelAdapterError(
            f"Unknown provider '{config.provider}' for model '{config.name}'. "
            f"Known providers: {sorted(_ADAPTERS)}"
        )
    return adapter_cls(config)
