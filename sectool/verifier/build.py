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
        return CommandResult(
            ok=False,
            detail=f"Command timed out after {timeout}s: {command}\n"
            f"{_tail(exc.stdout)}\n{_tail(exc.stderr)}",
        )

    if proc.returncode != 0:
        return CommandResult(
            ok=False,
            detail=f"Command exited {proc.returncode}: {command}\n"
            f"{_tail(proc.stdout)}\n{_tail(proc.stderr)}",
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
