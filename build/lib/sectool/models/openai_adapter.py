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

# The one 400 code that is a property of the *finding* (its prompt size),
# not of the model config, and so must stay transient instead of aborting
# the model for the rest of the run.
_CONTEXT_LENGTH_CODE = "context_length_exceeded"


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
        request_kwargs: dict = {
            "model": self.config.model_id,
            "messages": [{"role": "user", "content": prompt}],
        }
        # gpt-5/o-series reject the legacy `max_tokens` field; older models
        # and most OpenAI-compatible local servers (vLLM, LM Studio) predate
        # `max_completion_tokens`. "auto" picks by endpoint: the real OpenAI
        # API gets the new field, a custom base_url gets the old one.
        max_tokens_param = self.config.max_tokens_param
        if max_tokens_param == "auto":
            max_tokens_param = (
                "max_tokens" if self.config.base_url else "max_completion_tokens"
            )
        request_kwargs[max_tokens_param] = self.config.max_output_tokens
        # Sampling/reasoning parameters only when configured -- reasoning
        # models reject an explicit `temperature` with a 400.
        if self.config.temperature is not None:
            request_kwargs["temperature"] = self.config.temperature
        if self.config.effort is not None:
            request_kwargs["reasoning_effort"] = self.config.effort
        try:
            completion = self._client.chat.completions.create(**request_kwargs)
        except (
            openai.AuthenticationError,
            openai.PermissionDeniedError,
            openai.NotFoundError,
        ) as exc:
            raise FatalModelAdapterError(
                f"OpenAI rejected the request for model '{self.config.name}' "
                f"in a way that will not change on retry ({type(exc).__name__}): {exc}"
            ) from exc
        except openai.BadRequestError as exc:
            if getattr(exc, "code", None) == _CONTEXT_LENGTH_CODE:
                raise ModelAdapterError(
                    f"OpenAI rejected the prompt for model "
                    f"'{self.config.name}' as too long: {exc}"
                ) from exc
            # Other 400s are request-shape problems (unsupported
            # `temperature`, wrong max-tokens field, bad `reasoning_effort`)
            # this adapter will rebuild identically for every finding.
            raise FatalModelAdapterError(
                f"OpenAI rejected the request parameters for model "
                f"'{self.config.name}' ({exc}). This recurs on every retry -- "
                f"fix the model config (e.g. remove 'temperature', or set "
                f"'max_tokens_param')."
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
