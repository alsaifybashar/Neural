"""Adapter for OpenAI-compatible chat completion models via the `openai` SDK."""

from __future__ import annotations

import os

from sectool.models.base import FixRequest, FixResponse, ModelAdapter, ModelAdapterError
from sectool.models.prompt import build_fix_prompt


class OpenAIAdapter(ModelAdapter):
    def __init__(self, config):
        super().__init__(config)
        try:
            import openai
        except ImportError as exc:
            raise ModelAdapterError(
                "The 'openai' package is required for provider 'openai'. "
                "Install it with `pip install openai`."
            ) from exc

        api_key = os.environ.get(config.api_key_env or "OPENAI_API_KEY")
        if not api_key:
            raise ModelAdapterError(
                f"No API key found in env var "
                f"'{config.api_key_env or 'OPENAI_API_KEY'}' for model "
                f"'{config.name}'."
            )
        self._client = openai.OpenAI(api_key=api_key, base_url=config.base_url)

    def propose_fix(self, request: FixRequest) -> FixResponse:
        prompt = build_fix_prompt(
            finding=request.finding,
            code_context=request.code_context,
            context_file_path=request.context_file_path,
            prior_feedback=request.prior_feedback,
        )
        try:
            completion = self._client.chat.completions.create(
                model=self.config.model_id,
                max_tokens=self.config.max_output_tokens,
                temperature=self.config.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as ModelAdapterError
            raise ModelAdapterError(
                f"OpenAI API call failed for model '{self.config.name}': {exc}"
            ) from exc

        raw_response = completion.choices[0].message.content or ""
        return FixResponse(
            patch_text=self.extract_diff(raw_response),
            raw_response=raw_response,
            prompt_text=prompt,
        )
