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
from dataclasses import dataclass, field
import json

from sectool.config import ModelConfig
from sectool.findings.schema import Finding


@dataclass
class FixRequest:
    """Everything an adapter needs to ask a model for one fix attempt."""

    finding: Finding
    code_context: str  # Source of the flagged function/file.
    context_file_path: str  # Repo-relative -- what the diff headers must use.
    attempt_number: int
    prior_feedback: str | None = None  # Set on retries; see prompt.py.
    context_start_line: int = 1  # File line code_context starts at, so the
    # prompt's line-number gutter shows real file line numbers.
    related_occurrences: list = field(default_factory=list)  # Snippets of
    # other project files referencing an identifier the finding names
    # (sectool.context.OccurrenceSnippet) -- lets the model produce one
    # coherent multi-file diff for fixes that rename a declaration.
    compile_command: str = ""
    context_truncated: bool = False
    task_findings: list[Finding] = field(default_factory=list)
    remediation_guidance: str = ""
    tool_history: list[dict] = field(default_factory=list)
    context_round: int = 0
    max_context_rounds: int = 4


@dataclass
class FixResponse:
    """A model's answer to one FixRequest."""

    patch_text: str  # Extracted unified diff (may be empty if extraction
    # failed -- callers must check for that rather than assume success).
    raw_response: str  # Full, unmodified model output, kept for audit/debug.
    prompt_text: str  # Exact prompt sent, stored alongside the response so
    # a FixAttempt row is fully self-contained/reproducible.
    input_tokens: int | None = None  # Prompt tokens as counted by the
    # provider itself, not estimated locally. None when the provider
    # doesn't report usage (e.g. some Ollama builds omit the counts).
    output_tokens: int | None = None  # Completion tokens, same caveat.


def _json_object_candidates(text: str):
    """Yield every balanced, decodable JSON object in `text`, in order.

    `raw_decode` at each `{` position consumes a complete object, so nested
    objects inside an already-yielded one are not yielded again, and braces
    in surrounding prose or code snippets are simply skipped over.
    """
    decoder = json.JSONDecoder()
    index = 0
    while True:
        start = text.find("{", index)
        if start == -1:
            return
        try:
            value, end = decoder.raw_decode(text, start)
        except (json.JSONDecodeError, ValueError):
            index = start + 1
            continue
        if isinstance(value, dict):
            yield value
        index = end


def parse_model_action(raw_response: str) -> dict | None:
    """Decode the provider-neutral JSON action from a raw model response.

    Models rarely return the single bare JSON object the prompt asks for:
    they wrap it in ```json fences, in <function_calls>-style tags carried
    over from their native tool-calling training, or surround it with prose
    that itself contains braces (all observed in recorded runs). A decoder
    that demands one perfectly isolated object therefore rejects real,
    well-intentioned protocol responses and the whole attempt is wasted.

    Instead, scan for every balanced JSON object anywhere in the response
    and keep the ones that carry an "action" key. If a `propose_fix` object
    is present it wins even when tool-action objects precede it: the model
    stated its final intent, and tool requests it emitted in the same
    response were never serviced anyway. Otherwise the first action object
    is returned (one tool action per round, as instructed). Returns None
    when nothing decodable carries an "action" key -- the dispatcher's
    format-retry loop takes it from there.
    """
    if not raw_response:
        return None
    actions = [
        value
        for value in _json_object_candidates(raw_response)
        if isinstance(value.get("action"), str)
    ]
    if not actions:
        return None
    for action in actions:
        if action.get("action") == "propose_fix":
            return action
    return actions[0]


def _looks_like_unified_diff(text: str) -> bool:
    return "diff --git" in text or (
        "--- " in text and "+++ " in text and "@@" in text
    )


def looks_like_action_attempt(raw_response: str) -> bool:
    """Heuristic for the dispatcher's format-retry decision: did the model
    try (and fail) to speak the JSON action protocol, or did it answer in
    some other deliberate shape?

    True means "re-ask with a format reminder is worthwhile". A response
    that instead contains a plausible unified diff is left to the legacy
    diff fallback path rather than re-asked -- the model made a different
    kind of mistake (ignoring the protocol), and its diff may still apply.
    """
    if '"action"' in raw_response or "'action'" in raw_response:
        return True
    if "<function_calls" in raw_response or "<tool_call" in raw_response:
        return True
    return not _looks_like_unified_diff(raw_response)


class ModelAdapterError(RuntimeError):
    """Raised when a model call fails in a way that *might* succeed on
    retry: a transient rate limit, a momentary server error, a network
    blip. The dispatcher's retry loop treats this as a normal attempt
    failure -- it consumes one of `max_attempts` and feeds the error back
    to the model as context for the next try, same as a failed
    verification gate.
    """


class FatalModelAdapterError(ModelAdapterError):
    """Raised when a model call fails in a way that will fail identically
    on every retry: bad/expired API key, no permission for this model,
    the model doesn't exist, or the account has no quota/credit left.

    Retrying these wastes time and, for hosted APIs, still counts against
    rate limits -- and since the condition applies to the *model*, not the
    finding, it will recur for every remaining finding too. The dispatcher
    does not retry a FatalModelAdapterError; it re-raises immediately so
    the caller (the CLI's dispatch loop) can stop sending this model any
    further work for the rest of the run instead of burning through every
    finding's retry budget on a model that can never succeed.
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
                return raw_response.strip("\r\n")
            start += 3
        else:
            start += len(marker)

        end = raw_response.find("```", start)
        if end == -1:
            return raw_response[start:].strip("\r\n")

        return raw_response[start:end].strip("\r\n")
