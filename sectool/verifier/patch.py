"""Applies a model-produced unified diff inside a worktree.

Uses `git apply` rather than the POSIX `patch` tool: it's stricter about
hunk context matching (fewer silent misapplications), it's already a
dependency (worktrees require git), and its error messages name the exact
hunk that failed, which is exactly the feedback we want to hand back to the
model on retry.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PatchApplyResult:
    applied: bool
    detail: str  # Empty on success; git's stderr (hunk failure detail) on failure.


def apply_patch(worktree_path: Path, patch_text: str) -> PatchApplyResult:
    if not patch_text.strip():
        return PatchApplyResult(
            applied=False, detail="Model response contained no patch content."
        )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False
    ) as f:
        f.write(patch_text)
        if not patch_text.endswith("\n"):
            f.write("\n")  # A trailing newline is required for some hunks
            # to apply cleanly; models frequently omit it.
        patch_file = Path(f.name)

    try:
        proc = subprocess.run(
            ["git", "apply", "--whitespace=fix", str(patch_file)],
            cwd=worktree_path,
            capture_output=True,
            text=True,
        )
    finally:
        patch_file.unlink(missing_ok=True)

    if proc.returncode != 0:
        return PatchApplyResult(applied=False, detail=proc.stderr.strip())
    return PatchApplyResult(applied=True, detail="")
