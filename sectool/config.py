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
    temperature: float = 0.0  # Deterministic by default: fixing bugs is not
    # the place for creative sampling, and it keeps repeated runs comparable.

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ModelConfig":
        return ModelConfig(
            name=data["name"],
            provider=data["provider"],
            model_id=data["model_id"],
            api_key_env=data.get("api_key_env"),
            base_url=data.get("base_url"),
            max_output_tokens=data.get("max_output_tokens", 4096),
            temperature=data.get("temperature", 0.0),
        )


@dataclass
class RunConfig:
    """Top-level configuration for one `sectool run` invocation."""

    project: ProjectConfig
    models: list[ModelConfig]
    output_dir: Path
    cert_guidelines: tuple[str, ...] = DEFAULT_CERT_GUIDELINES
    max_attempts_per_finding: int = 3
    # Cap on how many findings to dispatch in one run. Phase 0/1 runs
    # intentionally work on a small slice; None means "all matched findings".
    finding_limit: int | None = None
    context_max_files: int = 8
    context_max_lines: int = 240
    max_context_rounds: int = 4

    @staticmethod
    def from_file(path: Path) -> "RunConfig":
        data = json.loads(Path(path).read_text())
        return RunConfig(
            project=ProjectConfig.from_dict(data["project"]),
            models=[ModelConfig.from_dict(m) for m in data["models"]],
            output_dir=Path(data.get("output_dir", "results")).expanduser().resolve(),
            cert_guidelines=tuple(
                data.get("cert_guidelines", DEFAULT_CERT_GUIDELINES)
            ),
            max_attempts_per_finding=data.get("max_attempts_per_finding", 3),
            finding_limit=data.get("finding_limit"),
            context_max_files=data.get("context_max_files", 8),
            context_max_lines=data.get("context_max_lines", 240),
            max_context_rounds=data.get("max_context_rounds", 4),
        )
