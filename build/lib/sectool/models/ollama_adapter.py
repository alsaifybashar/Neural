"""Adapter for local/open-weight models served by Ollama.

No API key required since Ollama serves models from a local (or otherwise
self-hosted) HTTP endpoint -- this is the adapter used for the
"local/open-weight models" leg of the evaluation, so cost/latency and
data-residency can be compared against the hosted-API models.
"""

from __future__ import annotations

import requests

from sectool.models.base import (
    FatalModelAdapterError,
    FixRequest,
    FixResponse,
    ModelAdapter,
    ModelAdapterError,
)
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
            context_start_line=request.context_start_line,
            related_occurrences=request.related_occurrences,
            compile_command=request.compile_command,
            context_truncated=request.context_truncated,
            task_findings=request.task_findings,
            remediation_guidance=request.remediation_guidance,
            tool_history=request.tool_history,
            context_round=request.context_round,
            max_context_rounds=request.max_context_rounds,
        )
        options: dict = {"num_predict": self.config.max_output_tokens}
        # Omitted temperature (None) leaves Ollama's own default in place;
        # for comparable repeated runs against local models, set an explicit
        # 0.0 in the model config.
        if self.config.temperature is not None:
            options["temperature"] = self.config.temperature
        try:
            response = requests.post(
                f"{self._base_url}/api/chat",
                json={
                    "model": self.config.model_id,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": options,
                },
                timeout=600,  # Local inference on CPU can be slow; this is
                # a ceiling, not an expectation.
            )
            response.raise_for_status()
        except requests.ConnectionError as exc:
            # The server itself is unreachable -- this will recur
            # identically for every remaining finding, not just this one.
            raise FatalModelAdapterError(
                f"Could not reach Ollama at {self._base_url} for model "
                f"'{self.config.name}': {exc}"
            ) from exc
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                # Model not pulled/loaded -- also won't change on retry.
                raise FatalModelAdapterError(
                    f"Model '{self.config.model_id}' not found on the Ollama "
                    f"server at {self._base_url} (has it been pulled?): {exc}"
                ) from exc
            raise ModelAdapterError(
                f"Ollama request failed for model '{self.config.name}' at "
                f"{self._base_url}: {exc}"
            ) from exc
        except requests.RequestException as exc:
            # Timeouts and other transport hiccups: worth another attempt.
            raise ModelAdapterError(
                f"Ollama request failed for model '{self.config.name}' at "
                f"{self._base_url}: {exc}"
            ) from exc

        payload = response.json()
        raw_response = payload.get("message", {}).get("content", "")
        return FixResponse(
            patch_text=self.extract_diff(raw_response),
            raw_response=raw_response,
            prompt_text=prompt,
            # Ollama reports usage as *_eval_count; absent on some builds
            # and on cached prompts, so these may legitimately be None.
            input_tokens=payload.get("prompt_eval_count"),
            output_tokens=payload.get("eval_count"),
        )
