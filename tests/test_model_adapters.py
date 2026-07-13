"""Tests that each adapter classifies SDK errors as fatal (never worth
retrying: bad key, no permission, model not found, no quota/credit left)
vs transient (worth the dispatcher's normal retry-with-feedback loop).

This is exercised by mocking the underlying SDK client's create() call to
raise real SDK exception instances (constructed with a fake httpx.Response
so their `.code`/`.type` fields are populated exactly as they would be from
a real API response) -- no network access, no real API key needed.
"""

from unittest.mock import MagicMock

import httpx
import pytest

from sectool.config import ModelConfig
from sectool.findings.schema import Finding
from sectool.models.anthropic_adapter import AnthropicAdapter
from sectool.models.base import FatalModelAdapterError, FixRequest, ModelAdapterError
from sectool.models.ollama_adapter import OllamaAdapter
from sectool.models.openai_adapter import OpenAIAdapter


def make_finding() -> Finding:
    return Finding(
        report_hash="h1", file_path="a.c", line=1, column=1, message="m",
        checker_name="cert-str31-c", analyzer_name="clang-tidy", severity="HIGH",
        cert_rule_ids=["STR31-C"], cert_guideline="sei-cert-c",
    )


def make_request() -> FixRequest:
    return FixRequest(
        finding=make_finding(), code_context="void f(){}", context_file_path="a.c",
        attempt_number=1,
    )


# -- OpenAI ------------------------------------------------------------------

def openai_error(cls, *, code=None, error_type=None):
    import openai as openai_pkg

    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    resp = httpx.Response(429, request=req)
    body = {"message": "boom", "type": error_type, "code": code, "param": None}
    return cls(cls.__name__, response=resp, body=body)


@pytest.fixture
def openai_adapter(monkeypatch) -> OpenAIAdapter:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")
    adapter = OpenAIAdapter(ModelConfig(name="m", provider="openai", model_id="gpt-5"))
    adapter._client = MagicMock()
    return adapter


def test_openai_authentication_error_is_fatal(openai_adapter):
    import openai as openai_pkg

    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    resp = httpx.Response(401, request=req)
    openai_adapter._client.chat.completions.create.side_effect = openai_pkg.AuthenticationError(
        "bad key", response=resp, body={"message": "bad key", "type": None, "code": None, "param": None}
    )
    with pytest.raises(FatalModelAdapterError):
        openai_adapter.propose_fix(make_request())


def test_openai_insufficient_quota_is_fatal(openai_adapter):
    import openai as openai_pkg

    openai_adapter._client.chat.completions.create.side_effect = openai_error(
        openai_pkg.RateLimitError, code="insufficient_quota", error_type="insufficient_quota"
    )
    with pytest.raises(FatalModelAdapterError):
        openai_adapter.propose_fix(make_request())


def test_openai_plain_rate_limit_is_transient(openai_adapter):
    import openai as openai_pkg

    openai_adapter._client.chat.completions.create.side_effect = openai_error(
        openai_pkg.RateLimitError, code="rate_limit_exceeded", error_type="rate_limit_error"
    )
    with pytest.raises(ModelAdapterError) as exc_info:
        openai_adapter.propose_fix(make_request())
    assert not isinstance(exc_info.value, FatalModelAdapterError)


def test_openai_internal_server_error_is_transient(openai_adapter):
    import openai as openai_pkg

    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    resp = httpx.Response(500, request=req)
    openai_adapter._client.chat.completions.create.side_effect = openai_pkg.InternalServerError(
        "oops", response=resp, body={"message": "oops", "type": None, "code": None, "param": None}
    )
    with pytest.raises(ModelAdapterError) as exc_info:
        openai_adapter.propose_fix(make_request())
    assert not isinstance(exc_info.value, FatalModelAdapterError)


def test_openai_missing_key_is_fatal(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(FatalModelAdapterError):
        OpenAIAdapter(ModelConfig(name="m", provider="openai", model_id="gpt-5"))


# -- Anthropic ----------------------------------------------------------------

@pytest.fixture
def anthropic_adapter(monkeypatch) -> AnthropicAdapter:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    adapter = AnthropicAdapter(
        ModelConfig(name="m", provider="anthropic", model_id="claude-sonnet-5")
    )
    adapter._client = MagicMock()
    return adapter


def anthropic_error(cls, *, status, error_type):
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    resp = httpx.Response(status, request=req)
    body = {"type": "error", "error": {"type": error_type, "message": "boom"}}
    return cls(cls.__name__, response=resp, body=body)


def test_anthropic_authentication_error_is_fatal(anthropic_adapter):
    import anthropic as anthropic_pkg

    anthropic_adapter._client.messages.create.side_effect = anthropic_error(
        anthropic_pkg.AuthenticationError, status=401, error_type="authentication_error"
    )
    with pytest.raises(FatalModelAdapterError):
        anthropic_adapter.propose_fix(make_request())


def test_anthropic_billing_error_is_fatal(anthropic_adapter):
    import anthropic as anthropic_pkg

    anthropic_adapter._client.messages.create.side_effect = anthropic_error(
        anthropic_pkg.RateLimitError, status=429, error_type="billing_error"
    )
    with pytest.raises(FatalModelAdapterError):
        anthropic_adapter.propose_fix(make_request())


def test_anthropic_plain_rate_limit_is_transient(anthropic_adapter):
    import anthropic as anthropic_pkg

    anthropic_adapter._client.messages.create.side_effect = anthropic_error(
        anthropic_pkg.RateLimitError, status=429, error_type="rate_limit_error"
    )
    with pytest.raises(ModelAdapterError) as exc_info:
        anthropic_adapter.propose_fix(make_request())
    assert not isinstance(exc_info.value, FatalModelAdapterError)


def test_anthropic_overloaded_is_transient(anthropic_adapter):
    import anthropic as anthropic_pkg

    anthropic_adapter._client.messages.create.side_effect = anthropic_error(
        anthropic_pkg.InternalServerError, status=529, error_type="overloaded_error"
    )
    with pytest.raises(ModelAdapterError) as exc_info:
        anthropic_adapter.propose_fix(make_request())
    assert not isinstance(exc_info.value, FatalModelAdapterError)


def test_anthropic_missing_key_is_fatal(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(FatalModelAdapterError):
        AnthropicAdapter(ModelConfig(name="m", provider="anthropic", model_id="claude-sonnet-5"))


# -- Ollama --------------------------------------------------------------------

def test_ollama_connection_error_is_fatal(monkeypatch):
    import requests

    adapter = OllamaAdapter(ModelConfig(name="m", provider="ollama", model_id="llama3:70b"))

    def fake_post(*args, **kwargs):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "post", fake_post)
    with pytest.raises(FatalModelAdapterError):
        adapter.propose_fix(make_request())


def test_ollama_model_not_found_is_fatal(monkeypatch):
    import requests

    adapter = OllamaAdapter(ModelConfig(name="m", provider="ollama", model_id="llama3:70b"))

    fake_response = MagicMock()
    fake_response.status_code = 404
    fake_response.raise_for_status.side_effect = requests.HTTPError(response=fake_response)

    monkeypatch.setattr(requests, "post", lambda *a, **k: fake_response)
    with pytest.raises(FatalModelAdapterError):
        adapter.propose_fix(make_request())


def test_ollama_timeout_is_transient(monkeypatch):
    import requests

    adapter = OllamaAdapter(ModelConfig(name="m", provider="ollama", model_id="llama3:70b"))

    def fake_post(*args, **kwargs):
        raise requests.Timeout("slow")

    monkeypatch.setattr(requests, "post", fake_post)
    with pytest.raises(ModelAdapterError) as exc_info:
        adapter.propose_fix(make_request())
    assert not isinstance(exc_info.value, FatalModelAdapterError)


# -- Token usage capture --------------------------------------------------------
# Each provider reports usage under different names; the adapters normalize
# them onto FixResponse.input_tokens/output_tokens so the UI/transcript can
# compare models without knowing providers.

def test_openai_success_captures_token_usage(openai_adapter):
    completion = MagicMock()
    completion.choices[0].message.content = "```diff\n- a\n+ b\n```"
    completion.usage.prompt_tokens = 120
    completion.usage.completion_tokens = 45
    openai_adapter._client.chat.completions.create.return_value = completion

    response = openai_adapter.propose_fix(make_request())
    assert response.input_tokens == 120
    assert response.output_tokens == 45
    assert response.patch_text == "- a\n+ b"


def test_anthropic_success_captures_token_usage(anthropic_adapter):
    block = MagicMock()
    block.type = "text"
    block.text = "```diff\n- a\n+ b\n```"
    message = MagicMock()
    message.content = [block]
    message.usage.input_tokens = 200
    message.usage.output_tokens = 33
    anthropic_adapter._client.messages.create.return_value = message

    response = anthropic_adapter.propose_fix(make_request())
    assert response.input_tokens == 200
    assert response.output_tokens == 33
    assert response.patch_text == "- a\n+ b"


def test_ollama_success_captures_token_usage(monkeypatch):
    import requests

    adapter = OllamaAdapter(ModelConfig(name="m", provider="ollama", model_id="llama3:70b"))
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "message": {"content": "```diff\n- a\n+ b\n```"},
        "prompt_eval_count": 80,
        "eval_count": 25,
    }
    monkeypatch.setattr(requests, "post", lambda *a, **k: fake_response)

    response = adapter.propose_fix(make_request())
    assert response.input_tokens == 80
    assert response.output_tokens == 25


def test_ollama_missing_usage_counts_are_none(monkeypatch):
    # Some Ollama builds/cached prompts omit the counts entirely -- the
    # adapter must report "unknown", not crash or invent zeros.
    import requests

    adapter = OllamaAdapter(ModelConfig(name="m", provider="ollama", model_id="llama3:70b"))
    fake_response = MagicMock()
    fake_response.json.return_value = {"message": {"content": "no diff"}}
    monkeypatch.setattr(requests, "post", lambda *a, **k: fake_response)

    response = adapter.propose_fix(make_request())
    assert response.input_tokens is None
    assert response.output_tokens is None
