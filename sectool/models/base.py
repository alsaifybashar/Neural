"""Provider-agnostic interface every LLM adapter implements.

Why an adapter interface at all: the tool's purpose is to *compare* models
across providers (hosted APIs and local/open-weight models alike), so the
dispatcher and retry loop must not know or care whether a given model is
Claude, GPT, or a local Llama served by Ollama. Adding a new model to
evaluate should mean adding one config entry and, at most, one small
adapter class -- never touching the dispatcher.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from sectool.config import ModelConfig
from sectool.findings.schema import Finding


@dataclass
class FixRequest:
    """Everything an adapter needs to ask a model for one fix attempt."""

    finding: Finding
    code_context: str  # Source of the flagged function/file.
    context_file_path: str
    attempt_number: int
    prior_feedback: str | None = None  # Set on retries; see prompt.py.


@dataclass
class FixResponse:
    """A model's answer to one FixRequest."""

    patch_text: str  # Extracted unified diff (may be empty if extraction
    # failed -- callers must check for that rather than assume success).
    raw_response: str  # Full, unmodified model output, kept for audit/debug.
    prompt_text: str  # Exact prompt sent, stored alongside the response so
    # a FixAttempt row is fully self-contained/reproducible.


class ModelAdapterError(RuntimeError):
    """Raised when a model call fails (network, auth, rate limit, ...).

    The dispatcher treats this as an attempt failure (consumes a retry) or
    task abort, depending on config; distinct from a bare Exception so that
    an adapter's own bugs aren't silently swallowed as expected failures.
    """


class ModelAdapter(ABC):
    """One provider/model, configured once and reused across findings."""

    def __init__(self, config: ModelConfig):
        self.config = config

    @abstractmethod
    def propose_fix(self, request: FixRequest) -> FixResponse:
        """Ask the model to fix `request.finding` and return its patch.

        Implementations must use `sectool.models.prompt.build_fix_prompt`
        to build the prompt text -- see that module's docstring for why
        prompt construction is centralized rather than per-adapter.
        """

    @staticmethod
    def extract_diff(raw_response: str) -> str:
        """Pull the contents of a ```diff fenced code block out of a raw
        model response. Shared by every adapter since the prompt asks all
        models for the same output shape (see prompt._INSTRUCTIONS).

        Falls back to returning the whole response stripped of fences if
        no ```diff block is found, so a model that ignores the fencing
        instruction still produces *something* for the verifier to try
        applying rather than silently losing the attempt.
        """
        marker = "```diff"
        start = raw_response.find(marker)
        if start == -1:
            # Some models omit the language tag; accept a bare fence too.
            start = raw_response.find("```")
            if start == -1:
                return raw_response.strip()
            start += 3
        else:
            start += len(marker)

        end = raw_response.find("```", start)
        if end == -1:
            return raw_response[start:].strip()

        return raw_response[start:end].strip()
