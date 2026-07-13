"""Adapter for Anthropic's Claude models via the official `anthropic` SDK."""

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

# Anthropic's structured error `type` field (see anthropic.types.shared.error_type
# .ErrorType) that specifically means "no credit/quota left", as distinct from
# "rate_limit_error" (too many requests right now -- may well succeed on retry)
# or "overloaded_error" (server-side, also worth retrying).
_BILLING_ERROR_TYPE = "billing_error"

# Substrings identifying a 400 as "this specific prompt is too big", the one
# BadRequestError that is a property of the *finding* (its context), not of
# the model config -- so it must stay transient rather than aborting the
# whole model. Anthropic phrases it as "prompt is too long: N tokens > M".
_CONTEXT_LENGTH_MARKERS = ("prompt is too long", "context length", "too many tokens")


def _is_context_length_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in _CONTEXT_LENGTH_MARKERS)


class AnthropicAdapter(ModelAdapter):
    def __init__(self, config):
        super().__init__(config)
        try:
            import anthropic  # Imported lazily so installing this package
            # isn't required unless the config actually asks for Anthropic.
        except ImportError as exc:
            raise FatalModelAdapterError(
                "The 'anthropic' package is required for provider "
                "'anthropic'. Install it with `pip install anthropic`."
            ) from exc

        self._anthropic = anthropic
        api_key = os.environ.get(config.api_key_env or "ANTHROPIC_API_KEY")
        if not api_key:
            raise FatalModelAdapterError(
                f"No API key found in env var "
                f"'{config.api_key_env or 'ANTHROPIC_API_KEY'}' for model "
                f"'{config.name}'."
            )
        # max_retries=1 (SDK default is higher): our own dispatcher retry
        # loop already re-tries the whole request with model feedback, so
        # letting the SDK also retry several times internally on a 429/5xx
        # just compounds latency, especially on an error that turns out to
        # be fatal (e.g. insufficient quota returns 429 too) and will never
        # succeed no matter how many times either layer retries it.
        self._client = anthropic.Anthropic(api_key=api_key, max_retries=1)

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
        anthropic = self._anthropic
        request_kwargs: dict = {
            "model": self.config.model_id,
            "max_tokens": self.config.max_output_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        # Sampling/reasoning parameters are included only when configured:
        # current-generation Claude models reject an explicit `temperature`
        # (HTTP 400), so the safe default is to send nothing.
        if self.config.temperature is not None:
            request_kwargs["temperature"] = self.config.temperature
        if self.config.thinking is not None:
            request_kwargs["thinking"] = {"type": self.config.thinking}
        if self.config.effort is not None:
            request_kwargs["output_config"] = {"effort": self.config.effort}
        try:
            message = self._client.messages.create(**request_kwargs)
        except (
            anthropic.AuthenticationError,
            anthropic.PermissionDeniedError,
            anthropic.NotFoundError,
        ) as exc:
            raise FatalModelAdapterError(
                f"Anthropic rejected the request for model '{self.config.name}' "
                f"in a way that will not change on retry ({type(exc).__name__}): {exc}"
            ) from exc
        except anthropic.BadRequestError as exc:
            if _is_context_length_error(exc):
                # Too much prompt for this one finding -- the next finding
                # (or a retry with shorter feedback) can still succeed.
                raise ModelAdapterError(
                    f"Anthropic rejected the prompt for model "
                    f"'{self.config.name}' as too long: {exc}"
                ) from exc
            # Any other 400 is a malformed request shape (unsupported
            # `temperature`/`thinking`/`max_tokens`...) that this adapter
            # will rebuild identically for every finding -- retrying burns
            # the whole budget on a config problem. Observed live: newer
            # Claude models rejecting `temperature` cost every attempt of
            # an entire run before this was classified fatal.
            raise FatalModelAdapterError(
                f"Anthropic rejected the request parameters for model "
                f"'{self.config.name}' ({exc}). This recurs on every retry -- "
                f"fix the model config (e.g. remove 'temperature', or check "
                f"'thinking'/'effort'/'max_output_tokens')."
            ) from exc
        except anthropic.APIStatusError as exc:
            if getattr(exc, "type", None) == _BILLING_ERROR_TYPE:
                raise FatalModelAdapterError(
                    f"Anthropic reports no quota/credit remaining for model "
                    f"'{self.config.name}': {exc}"
                ) from exc
            raise ModelAdapterError(
                f"Anthropic API call failed for model '{self.config.name}': {exc}"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - network errors etc: transient
            raise ModelAdapterError(
                f"Anthropic API call failed for model '{self.config.name}': {exc}"
            ) from exc

        raw_response = "".join(
            block.text for block in message.content if block.type == "text"
        )
        usage = getattr(message, "usage", None)
        return FixResponse(
            patch_text=self.extract_diff(raw_response),
            raw_response=raw_response,
            prompt_text=prompt,
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
        )
