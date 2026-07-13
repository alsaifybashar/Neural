"""Pre-run environment checks, surfaced as an explicit checklist before any
scanning or model calls happen.

Directly addresses "if something is missing we should show the user that
it's missing": rather than letting a missing API key or an un-pulled Ollama
model surface as a confusing stack trace three steps into a run, every
prerequisite is checked up front and reported with a clear ok/missing
verdict. A missing *model* prerequisite (bad key, package not installed,
model not pulled) excludes just that model from the run with a warning;
a missing *project* prerequisite (CodeChecker itself, or -- for `run`,
which needs to create git worktrees -- the project not being a git repo
with at least one commit) is a hard error, since nothing in the pipeline
can proceed without it.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import requests

from sectool.config import ModelConfig, RunConfig

LEVEL_ERROR = "error"
LEVEL_WARNING = "warning"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""
    level: str = LEVEL_ERROR  # only meaningful when ok is False


def check_codechecker(codechecker_bin: str = "CodeChecker") -> CheckResult:
    try:
        proc = subprocess.run(
            [codechecker_bin, "version"], capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        return CheckResult(
            "CodeChecker installed", False,
            f"'{codechecker_bin}' not found on PATH -- see docs/SETUP.md.",
        )
    except subprocess.TimeoutExpired:
        return CheckResult("CodeChecker installed", False, "'CodeChecker version' timed out.")

    if proc.returncode != 0:
        return CheckResult(
            "CodeChecker installed", False,
            f"'CodeChecker version' exited {proc.returncode}: {proc.stderr.strip()}",
        )
    return CheckResult("CodeChecker installed", True)


def check_git_repo(project_root: Path, require_commit: bool) -> CheckResult:
    proc = subprocess.run(
        ["git", "-C", str(project_root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return CheckResult(
            "Project is a git repository", False,
            f"{project_root} is not a git repository (required so the "
            "Verifier can isolate each patch attempt in a git worktree). "
            "Run `git init && git add -A && git commit -m baseline` in it first.",
        )
    if require_commit:
        head = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        )
        if head.returncode != 0:
            return CheckResult(
                "Project has at least one commit", False,
                f"{project_root} has no commits yet -- `git worktree add` needs "
                "a ref to check out. Run `git add -A && git commit -m baseline`.",
            )
    return CheckResult("Project is a git repository", True)


def check_model_output_budget(config: ModelConfig) -> CheckResult | None:
    """Warn (never block) when thinking/reasoning is enabled with a small
    output cap: thinking tokens count against max_output_tokens, so a 4096
    cap can silently truncate the visible answer to nothing."""
    reasoning_enabled = config.thinking not in (None, "disabled") or config.effort
    if reasoning_enabled and config.max_output_tokens < 8192:
        return CheckResult(
            f"Model '{config.name}' output budget", False,
            f"thinking/effort is enabled but max_output_tokens is "
            f"{config.max_output_tokens}; reasoning tokens count against "
            "this cap, so responses may be truncated. Consider >= 8192.",
            level=LEVEL_WARNING,
        )
    return None


def check_model(config: ModelConfig) -> CheckResult:
    name = f"Model '{config.name}' ({config.provider})"

    if config.provider in ("anthropic", "openai"):
        if importlib.util.find_spec(config.provider) is None:
            return CheckResult(
                name, False,
                f"The '{config.provider}' package isn't installed "
                f"(`pip install {config.provider}`).",
                level=LEVEL_WARNING,
            )
        env_var = config.api_key_env or f"{config.provider.upper()}_API_KEY"
        if not os.environ.get(env_var):
            return CheckResult(
                name, False,
                f"No API key in env var '{env_var}'. This model will be "
                "skipped for this run.",
                level=LEVEL_WARNING,
            )
        return CheckResult(name, True)

    if config.provider == "ollama":
        base_url = (config.base_url or "http://localhost:11434").rstrip("/")
        try:
            resp = requests.get(f"{base_url}/api/tags", timeout=5)
            resp.raise_for_status()
        except requests.RequestException as exc:
            return CheckResult(
                name, False,
                f"Could not reach Ollama at {base_url}: {exc}",
                level=LEVEL_WARNING,
            )
        tags = [m.get("name", "") for m in resp.json().get("models", [])]
        base_model_id = config.model_id.split(":")[0]
        if not any(t == config.model_id or t.split(":")[0] == base_model_id for t in tags):
            return CheckResult(
                name, False,
                f"Model '{config.model_id}' is not pulled on the Ollama "
                f"server at {base_url} (run `ollama pull {config.model_id}`). "
                "This model will be skipped for this run.",
                level=LEVEL_WARNING,
            )
        return CheckResult(name, True)

    return CheckResult(name, False, f"Unknown provider '{config.provider}'.")


def run_preflight(
    config: RunConfig, codechecker_bin: str = "CodeChecker", require_git: bool = True
) -> tuple[list[CheckResult], list[ModelConfig]]:
    """Runs every check and returns (all results, models safe to dispatch to).

    `require_git` should be False for `sectool scan` (which never applies a
    patch, so git isn't needed) and True for `sectool run`.
    """
    results = [check_codechecker(codechecker_bin)]
    if require_git:
        results.append(check_git_repo(config.project.root, require_commit=True))

    runnable_models = []
    for model_config in config.models:
        result = check_model(model_config)
        results.append(result)
        if result.ok:
            runnable_models.append(model_config)
        budget_warning = check_model_output_budget(model_config)
        if budget_warning is not None:
            results.append(budget_warning)

    return results, runnable_models


def has_hard_failure(results: list[CheckResult]) -> bool:
    return any(not r.ok and r.level == LEVEL_ERROR for r in results)
