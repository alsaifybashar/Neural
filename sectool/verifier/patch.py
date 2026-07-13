"""Applies a model-produced unified diff inside a worktree.

Uses `git apply` rather than the POSIX `patch` tool: it's stricter about
hunk context matching (fewer silent misapplications), it's already a
dependency (worktrees require git), and its error messages name the exact
hunk that failed, which is exactly the feedback we want to hand back to the
model on retry.

Model-produced diffs are frequently *almost* right: the change itself is
unambiguous but a hunk header miscounts its lines or the line numbers are
off (models guess them). Rejecting those outright wastes an attempt on a
patch a human would have applied without thinking, so application walks a
ladder of increasingly tolerant `git apply` invocations -- never tolerant
about the changed lines themselves, only about the bookkeeping around them:

    1. exact             - the diff as given
    2. --recount         - recompute hunk line counts (fixes miscounted
                           `@@` headers; content still must match)
    3. --recount -C1     - additionally require only 1 line of surrounding
                           context to match instead of all of it

If every rung fails, the failure detail fed back to the model includes the
authoritative, line-numbered file content around each failed hunk, so the
retry can be anchored to the file's real text instead of to a git error
message that only says "does not apply".
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
import re

from sectool.verifier.feedback import annotate_with_source

# (label, extra git-apply args), in the order they're tried.
_STRATEGIES: list[tuple[str, list[str]]] = [
    ("exact", []),
    ("--recount", ["--recount"]),
    ("--recount -C1", ["--recount", "-C1"]),
]

_PATCH_FEEDBACK_INTRO = (
    "The file's actual content around the failed hunk is shown below with "
    "a `N | ` line-number gutter (the gutter is not part of the file). "
    "Regenerate your diff so its context lines reproduce these lines "
    "exactly and its hunk headers use these line numbers:"
)


@dataclass
class PatchApplyResult:
    applied: bool
    detail: str  # Empty on success; on failure, git's stderr (hunk failure
    # detail) plus the authoritative file content around each failed hunk.
    strategy: str = ""  # Which _STRATEGIES rung applied the patch ("exact"
    # when the diff was correct as given); empty on failure.


@dataclass
class PatchValidationResult:
    valid: bool
    detail: str = ""
    patch_text: str = ""
    touched_files: tuple[str, ...] = ()


_HEADER_RE = re.compile(r"^(---|\+\+\+)\s+([^\t\n]+)", re.MULTILINE)
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.MULTILINE)


def validate_patch(patch_text: str, project_root: Path | None = None) -> PatchValidationResult:
    """Validate the model's diff shape and path confinement before git sees it."""
    if not patch_text.strip():
        return PatchValidationResult(False, "Model response contained no patch content.")
    headers = _HEADER_RE.findall(patch_text)
    if not headers or not _HUNK_RE.search(patch_text):
        return PatchValidationResult(
            False,
            "Response is not a complete unified diff with file headers and a valid hunk header.",
        )
    old_paths = [p for kind, p in headers if kind == "---"]
    new_paths = [p for kind, p in headers if kind == "+++"]
    if len(old_paths) != len(new_paths):
        return PatchValidationResult(False, "Unified diff has unmatched ---/+++ file headers.")

    touched: list[str] = []
    for raw in old_paths + new_paths:
        if raw == "/dev/null":
            return PatchValidationResult(False, "Creating or deleting files is not allowed.")
        path = raw[2:] if raw.startswith(("a/", "b/")) else raw
        candidate = Path(path)
        if candidate.is_absolute() or ".." in candidate.parts or not path:
            return PatchValidationResult(False, f"Patch path is outside the project: {raw}")
        if project_root is not None:
            root = Path(project_root).resolve()
            try:
                (root / candidate).resolve().relative_to(root)
            except ValueError:
                return PatchValidationResult(False, f"Patch path is outside the project: {raw}")
        if raw in new_paths and path not in touched:
            touched.append(path)

    if not any(line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
               for line in patch_text.splitlines()):
        return PatchValidationResult(False, "Unified diff contains no changed lines.")
    normalized = patch_text + ("" if patch_text.endswith("\n") else "\n")
    return PatchValidationResult(True, patch_text=normalized, touched_files=tuple(touched))


def apply_patch(worktree_path: Path, patch_text: str) -> PatchApplyResult:
    validation = validate_patch(patch_text, worktree_path)
    if not validation.valid:
        return PatchApplyResult(applied=False, detail=validation.detail)
    patch_text = validation.patch_text

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False
    ) as f:
        f.write(patch_text)
        if not patch_text.endswith("\n"):
            f.write("\n")  # A trailing newline is required for some hunks
            # to apply cleanly; models frequently omit it.
        patch_file = Path(f.name)

    try:
        first_stderr = ""
        for label, extra_args in _STRATEGIES:
            proc = subprocess.run(
                ["git", "apply", "--whitespace=fix", *extra_args, str(patch_file)],
                cwd=worktree_path,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                return PatchApplyResult(applied=True, detail="", strategy=label)
            if not first_stderr:
                # The strict attempt's error names the failed hunk most
                # precisely; later rungs' errors add nothing new.
                first_stderr = proc.stderr.strip()
    finally:
        patch_file.unlink(missing_ok=True)

    return PatchApplyResult(
        applied=False,
        detail=annotate_with_source(worktree_path, first_stderr, _PATCH_FEEDBACK_INTRO),
    )
