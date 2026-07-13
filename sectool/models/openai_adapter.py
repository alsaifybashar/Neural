"""Adapter for OpenAI-compatible chat completion models via the `openai` SDK."""

from __future__ import annotations

import os

from sectool.models.base import (
    FatalModelAdapterError,
    FixRequest,
    FixResponse,
    ModelAdapter,
    ModelAdapterError,
)
from sectool.models.prompt import build_fix_prompt

# OpenAI's structured error `code` field that specifically means "no
# credit/quota left on this account", as distinct from `rate_limit_exceeded`
# (too many requests right now -- may well succeed on retry or after a
# short backoff). Both surface as HTTP 429, so the code (not the status)
# is what distinguishes "will never succeed" from "try again shortly".
_INSUFFICIENT_QUOTA_CODE = "insufficient_quota"


class OpenAIAdapter(ModelAdapter):
    def __init__(self, config):
        super().__init__(config)
        try:
            import openai
        except ImportError as exc:
            raise FatalModelAdapterError(
                "The 'openai' package is required for provider 'openai'. "
                "Install it with `pip install openai`."
            ) from exc

        self._openai = openai
        api_key = os.environ.get(config.api_key_env or "OPENAI_API_KEY")
        if not api_key:
            raise FatalModelAdapterError(
                f"No API key found in env var "
                f"'{config.api_key_env or 'OPENAI_API_KEY'}' for model "
                f"'{config.name}'."
            )
        # max_retries=1 (SDK default is higher): see the matching comment in
        # anthropic_adapter.py -- our own dispatcher retry loop is the
        # higher-level retry; we don't need the SDK compounding on top of it.
        self._client = openai.OpenAI(api_key=api_key, base_url=config.base_url, max_retries=1)

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
        openai = self._openai
        try:
            completion = self._client.chat.completions.create(
                model=self.config.model_id,
                max_tokens=self.config.max_output_tokens,
                temperature=self.config.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
        except (
            openai.AuthenticationError,
            openai.PermissionDeniedError,
            openai.NotFoundError,
        ) as exc:
            raise FatalModelAdapterError(
                f"OpenAI rejected the request for model '{self.config.name}' "
                f"in a way that will not change on retry ({type(exc).__name__}): {exc}"
            ) from exc
        except openai.APIError as exc:
            if getattr(exc, "code", None) == _INSUFFICIENT_QUOTA_CODE:
                raise FatalModelAdapterError(
                    f"OpenAI reports insufficient quota for model "
                    f"'{self.config.name}': {exc}"
                ) from exc
            raise ModelAdapterError(
                f"OpenAI API call failed for model '{self.config.name}': {exc}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - network errors etc: transient
            raise ModelAdapterError(
                f"OpenAI API call failed for model '{self.config.name}': {exc}"
            ) from exc

        raw_response = completion.choices[0].message.content or ""
        usage = getattr(completion, "usage", None)
        return FixResponse(
            patch_text=self.extract_diff(raw_response),
            raw_response=raw_response,
            prompt_text=prompt,
            input_tokens=getattr(usage, "prompt_tokens", None),
            output_tokens=getattr(usage, "completion_tokens", None),
        )
