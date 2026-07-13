"""Run configuration for sectool.

A single YAML/JSON config file (see `docs/config.example.json`) describes:
  * which project to scan and how to build/test it,
  * which SEI CERT guidelines to filter findings to,
  * which LLMs to evaluate and how to reach them,
  * how many fix attempts to allow per finding.

Keeping this in one place means the CLI, dispatcher, and verifier all agree
on the same knobs instead of each parsing their own bit of argv.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# SEI CERT guideline labels as they appear in CodeChecker's checker label
# config (config/labels/analyzers/*.json in the CodeChecker source). These
# are the exact strings CodeChecker's own `--guideline` / `-e guideline:...`
# flags expect, confirmed against the CodeChecker source: a checker carries
# a "guideline:sei-cert-c" (or "-cpp") label plus a companion
# "sei-cert-c:<rule-id>" label that names the specific rule it enforces.
DEFAULT_CERT_GUIDELINES = ("sei-cert-c", "sei-cert-cpp")


@dataclass
class ProjectConfig:
    """Describes the C/C++ project under evaluation."""

    # Root directory of the project's source checkout.
    root: Path

    # Shell command CodeChecker should run to observe the build
    # (used by `CodeChecker log -b "<build_command>"`). Must be a full,
    # from-clean build so every compiled translation unit is captured.
    build_command: str

    # Shell command that runs the project's existing test suite, e.g.
    # "ctest --output-on-failure" or "make test". Run from `root` after a
    # successful build. Optional: if the project has no test suite, leave
    # empty and the Verifier will skip that stage (and note it as skipped,
    # not passed, in the report).
    test_command: str = ""

    # Directory name (relative to root) the build_command produces object
    # files/binaries in, if any cleanup is required between attempts.
    build_dir: str = "build"

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ProjectConfig":
        return ProjectConfig(
            root=Path(data["root"]).expanduser().resolve(),
            build_command=data["build_command"],
            test_command=data.get("test_command", ""),
            build_dir=data.get("build_dir", "build"),
        )


@dataclass
class ModelConfig:
    """One LLM to evaluate.

    `provider` selects which sectool.models adapter is instantiated
    (see sectool/models/registry.py). `model_id` is the provider-specific
    model name (e.g. "claude-sonnet-5", "gpt-5", "llama3:70b").
    """

    name: str  # Human-readable label used in reports/leaderboards.
    provider: str  # "anthropic" | "openai" | "ollama"
    model_id: str
    api_key_env: str | None = None  # Env var holding the API key, if any.
    base_url: str | None = None  # Override endpoint, e.g. local Ollama host.
    max_output_tokens: int = 4096
    temperature: float | None = None  # None (the default) means the sampling
    # parameter is omitted from the request entirely. Current-generation
    # reasoning models (claude-opus-4-8, claude-sonnet-5, gpt-5, ...) reject
    # an explicit `temperature` with an HTTP 400, so sending 0.0 by default
    # made every call to them fail. Set an explicit value only for models
    # documented to accept it (e.g. Ollama-served open-weight models, where
    # 0.0 keeps repeated runs comparable).
    thinking: str | None = None  # Anthropic only: "adaptive" | "disabled".
    # Sent as `thinking={"type": ...}`; None omits the parameter.
    effort: str | None = None  # Reasoning-effort hint. Anthropic: sent as
    # `output_config={"effort": ...}`; OpenAI: sent as `reasoning_effort`.
    # None omits it. Thinking/reasoning tokens count against
    # max_output_tokens, so raise that cap when enabling these.
    max_tokens_param: str = "auto"  # OpenAI only: which request field carries
    # max_output_tokens. "auto" = `max_completion_tokens` against the real
    # OpenAI endpoint (required by gpt-5/o-series) but `max_tokens` when a
    # custom base_url points at an OpenAI-compatible server (vLLM, LM Studio)
    # that may predate the newer field. "max_tokens"/"max_completion_tokens"
    # force one explicitly.
    input_cost_per_mtok: float | None = None  # USD per million input tokens,
    # user-supplied (prices change; the tool hardcodes none). Used only to
    # compute the estimated-cost column in reports.
    output_cost_per_mtok: float | None = None  # USD per million output tokens.

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ModelConfig":
        return ModelConfig(
            name=data["name"],
            provider=data["provider"],
            model_id=data["model_id"],
            api_key_env=data.get("api_key_env"),
            base_url=data.get("base_url"),
            max_output_tokens=data.get("max_output_tokens", 4096),
            temperature=data.get("temperature"),
            thinking=data.get("thinking"),
            effort=data.get("effort"),
            max_tokens_param=data.get("max_tokens_param", "auto"),
            input_cost_per_mtok=data.get("input_cost_per_mtok"),
            output_cost_per_mtok=data.get("output_cost_per_mtok"),
        )


@dataclass
class RunConfig:
    """Top-level configuration for one `sectool run` invocation."""

    project: ProjectConfig
    models: list[ModelConfig]
    output_dir: Path
    cert_guidelines: tuple[str, ...] = DEFAULT_CERT_GUIDELINES
    # Extra `-e`/`--enable` arguments passed verbatim to `CodeChecker analyze`
    # (and to the verifier's rescan, which must see the same checker set),
    # e.g. ["profile:security", "checkers:security.ArrayBound"]. Empty keeps
    # the analyze command exactly as before.
    checker_enables: tuple[str, ...] = ()
    # Which findings become fix tasks:
    #   "cert" - findings that map to a SEI CERT rule (historical behavior).
    #   "cwe"  - findings with at least one mapped CWE id. On benchmark
    #            corpora like Juliet this is the mode that actually surfaces
    #            the memory-safety findings, which mostly have no CERT label.
    #   "all"  - every finding the scan produced.
    dispatch_filter: str = "cert"
    # fnmatch patterns applied to checker names after dispatch_filter --
    # the lever for keeping broadened scans (e.g. profile:security) from
    # exploding into thousands of tasks. include=[] means "include all".
    include_checkers: tuple[str, ...] = ()
    exclude_checkers: tuple[str, ...] = ()
    # Derive CWE ids from `CWE(\d+)_` path segments (the Juliet layout, where
    # this is ground truth). Disable for real projects whose paths could
    # coincidentally match.
    cwe_from_filename: bool = True
    max_attempts_per_finding: int = 3
    # Cap on how many findings to dispatch in one run. Phase 0/1 runs
    # intentionally work on a small slice; None means "all matched findings".
    finding_limit: int | None = None
    context_max_files: int = 8
    context_max_lines: int = 240
    # How many leading lines of each locally-included header are shown as
    # dependency context (include guards, type/constant definitions).
    context_include_head_lines: int = 40
    max_context_rounds: int = 4
    # How many times per attempt an undecodable model response is answered
    # with a format reminder and re-asked, instead of burning the whole
    # attempt. These re-asks do not consume max_attempts_per_finding.
    max_format_retries: int = 2

    @staticmethod
    def from_file(path: Path) -> "RunConfig":
        data = json.loads(Path(path).read_text())
        dispatch_filter = data.get("dispatch_filter", "cert")
        if dispatch_filter not in ("cert", "cwe", "all"):
            raise ValueError(
                f"dispatch_filter must be 'cert', 'cwe', or 'all', "
                f"got {dispatch_filter!r}"
            )
        return RunConfig(
            project=ProjectConfig.from_dict(data["project"]),
            models=[ModelConfig.from_dict(m) for m in data["models"]],
            output_dir=Path(data.get("output_dir", "results")).expanduser().resolve(),
            cert_guidelines=tuple(
                data.get("cert_guidelines", DEFAULT_CERT_GUIDELINES)
            ),
            checker_enables=tuple(data.get("checker_enables", ())),
            dispatch_filter=dispatch_filter,
            include_checkers=tuple(data.get("include_checkers", ())),
            exclude_checkers=tuple(data.get("exclude_checkers", ())),
            cwe_from_filename=data.get("cwe_from_filename", True),
            max_attempts_per_finding=data.get("max_attempts_per_finding", 3),
            finding_limit=data.get("finding_limit"),
            context_max_files=data.get("context_max_files", 8),
            context_max_lines=data.get("context_max_lines", 240),
            context_include_head_lines=data.get("context_include_head_lines", 40),
            max_context_rounds=data.get("max_context_rounds", 4),
            max_format_retries=data.get("max_format_retries", 2),
        )
