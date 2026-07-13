"""Apply a verified patch to the user's checkout only after approval."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from sectool.verifier.patch import validate_patch


@dataclass
class WorkingTreeApplyResult:
    status: str  # applied | conflict | error
    detail: str
    touched_files: tuple[str, ...] = ()


def apply_verified_patch(project_root: Path, patch_text: str) -> WorkingTreeApplyResult:
    root = Path(project_root).resolve()
    validation = validate_patch(patch_text, root)
    if not validation.valid:
        return WorkingTreeApplyResult("error", validation.detail)

    overlapping = []
    for path in validation.touched_files:
        status = subprocess.run(
            ["git", "status", "--porcelain", "--", path],
            cwd=root, capture_output=True, text=True,
        )
        if status.stdout.strip():
            overlapping.append(path)
    if overlapping:
        return WorkingTreeApplyResult(
            "conflict",
            "Refusing to overwrite uncommitted changes in: " + ", ".join(overlapping),
            validation.touched_files,
        )

    check = subprocess.run(
        ["git", "apply", "--check", "--whitespace=fix", "-"],
        cwd=root, input=validation.patch_text, capture_output=True, text=True,
    )
    if check.returncode != 0:
        return WorkingTreeApplyResult(
            "conflict", "Verified patch no longer applies to the working tree:\n" + check.stderr.strip(),
            validation.touched_files,
        )
    applied = subprocess.run(
        ["git", "apply", "--whitespace=fix", "-"],
        cwd=root, input=validation.patch_text, capture_output=True, text=True,
    )
    if applied.returncode != 0:
        return WorkingTreeApplyResult("error", applied.stderr.strip(), validation.touched_files)
    return WorkingTreeApplyResult(
        "applied", "Applied verified patch to: " + ", ".join(validation.touched_files),
        validation.touched_files,
    )
