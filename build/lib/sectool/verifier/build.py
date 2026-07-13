"""Runs the project's build and (optionally) test commands inside a worktree.

`build_command`/`test_command` come from this run's `ProjectConfig`, which
the user who set up the evaluation controls -- not from LLM output or any
other untrusted source. Running them via the shell (`shell=True`) is
therefore an accepted, deliberate choice (it's how a developer would type
them at a terminal, e.g. "cmake -B build && cmake --build build"), not a
place where external input reaches a shell.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 900


@dataclass
class CommandResult:
    ok: bool
    detail: str  # Combined stdout+stderr tail on failure; empty on success.
    skipped: bool = False
    full_detail: str = ""


def run_build(
    worktree_path: Path, build_command: str, timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> CommandResult:
    return _run_shell(worktree_path, build_command, timeout)


def run_tests(
    worktree_path: Path, test_command: str, timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> CommandResult:
    if not test_command.strip():
        # No test suite configured for this project: the Verifier still
        # reports this explicitly (skipped, not passed) so a report reader
        # never mistakes "no tests were run" for "tests passed".
        return CommandResult(ok=True, detail="No test_command configured; skipped.", skipped=True)
    return _run_shell(worktree_path, test_command, timeout)


def _run_shell(worktree_path: Path, command: str, timeout: int) -> CommandResult:
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=worktree_path,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        full = f"{_text(exc.stdout)}\n{_text(exc.stderr)}".strip()
        return CommandResult(
            ok=False,
            detail=f"Command timed out after {timeout}s: {command}\n"
            f"{_diagnostic_excerpt(full)}",
            full_detail=full,
        )

    if proc.returncode != 0:
        full = f"{proc.stdout}\n{proc.stderr}".strip()
        return CommandResult(
            ok=False,
            detail=f"Command exited {proc.returncode}: {command}\n"
            f"{_diagnostic_excerpt(full)}",
            full_detail=full,
        )
    return CommandResult(ok=True, detail="")


def _tail(text, max_lines: int = 100) -> str:
    """Keep only the last `max_lines` of output when feeding failures back
    to a model -- compiler/test output can be enormous, and the tail is
    almost always where the actual error is."""
    if text is None:
        return ""
    lines = text.splitlines()
    return "\n".join(lines[-max_lines:])


def _text(value) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def _diagnostic_excerpt(text: str, max_lines: int = 40) -> str:
    """Keep actionable diagnostics and nearby context for an LLM retry."""
    lines = text.splitlines()
    markers = (" error:", "fatal error:", "undefined reference", "FAILED", "AssertionError")
    indexes = [i for i, line in enumerate(lines) if any(marker in line for marker in markers)]
    if not indexes:
        return "\n".join(lines[-max_lines:])
    selected: set[int] = set()
    for index in indexes:
        selected.update(range(max(0, index - 2), min(len(lines), index + 4)))
        if len(selected) >= max_lines:
            break
    return "\n".join(lines[i] for i in sorted(selected)[:max_lines])
