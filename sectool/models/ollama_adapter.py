"""Adapter for local/open-weight models served by Ollama.

No API key required since Ollama serves models from a local (or otherwise
self-hosted) HTTP endpoint -- this is the adapter used for the
"local/open-weight models" leg of the evaluation, so cost/latency and
data-residency can be compared against the hosted-API models.
"""

from __future__ import annotations

import requests

from sectool.models.base import FixRequest, FixResponse, ModelAdapter, ModelAdapterError
from sectool.models.prompt import build_fix_prompt

DEFAULT_OLLAMA_URL = "http://localhost:11434"


class OllamaAdapter(ModelAdapter):
    def __init__(self, config):
        super().__init__(config)
        self._base_url = (config.base_url or DEFAULT_OLLAMA_URL).rstrip("/")

    def propose_fix(self, request: FixRequest) -> FixResponse:
        prompt = build_fix_prompt(
            finding=request.finding,
            code_context=request.code_context,
            context_file_path=request.context_file_path,
            prior_feedback=request.prior_feedback,
        )
        try:
            response = requests.post(
                f"{self._base_url}/api/chat",
                json={
                    "model": self.config.model_id,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.max_output_tokens,
                    },
                },
                timeout=600,  # Local inference on CPU can be slow; this is
                # a ceiling, not an expectation.
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ModelAdapterError(
                f"Ollama request failed for model '{self.config.name}' at "
                f"{self._base_url}: {exc}"
            ) from exc

        raw_response = response.json().get("message", {}).get("content", "")
        return FixResponse(
            patch_text=self.extract_diff(raw_response),
            raw_response=raw_response,
            prompt_text=prompt,
        )
