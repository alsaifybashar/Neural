"""Adapter for Anthropic's Claude models via the official `anthropic` SDK."""

from __future__ import annotations

import os

from sectool.models.base import FixRequest, FixResponse, ModelAdapter, ModelAdapterError
from sectool.models.prompt import build_fix_prompt


class AnthropicAdapter(ModelAdapter):
    def __init__(self, config):
        super().__init__(config)
        try:
            import anthropic  # Imported lazily so installing this package
            # isn't required unless the config actually asks for Anthropic.
        except ImportError as exc:
            raise ModelAdapterError(
                "The 'anthropic' package is required for provider "
                "'anthropic'. Install it with `pip install anthropic`."
            ) from exc

        api_key = os.environ.get(config.api_key_env or "ANTHROPIC_API_KEY")
        if not api_key:
            raise ModelAdapterError(
                f"No API key found in env var "
                f"'{config.api_key_env or 'ANTHROPIC_API_KEY'}' for model "
                f"'{config.name}'."
            )
        self._client = anthropic.Anthropic(api_key=api_key)

    def propose_fix(self, request: FixRequest) -> FixResponse:
        prompt = build_fix_prompt(
            finding=request.finding,
            code_context=request.code_context,
            context_file_path=request.context_file_path,
            prior_feedback=request.prior_feedback,
        )
        try:
            message = self._client.messages.create(
                model=self.config.model_id,
                max_tokens=self.config.max_output_tokens,
                temperature=self.config.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as ModelAdapterError
            raise ModelAdapterError(
                f"Anthropic API call failed for model '{self.config.name}': {exc}"
            ) from exc

        raw_response = "".join(
            block.text for block in message.content if block.type == "text"
        )
        return FixResponse(
            patch_text=self.extract_diff(raw_response),
            raw_response=raw_response,
            prompt_text=prompt,
        )
