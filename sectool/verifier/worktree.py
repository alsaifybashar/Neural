"""Isolates each fix attempt in its own `git worktree`.

Using a git worktree (rather than a plain directory copy) means each
attempt gets a full, independent checkout that shares the repo's object
store (cheap to create/destroy) while never touching the user's actual
working directory -- a bad patch or a failed build in one attempt can't
corrupt the original project or bleed into the next attempt.

This requires the target project to be a git repository. That's an
intentional constraint, not an oversight: real-world C/C++ projects almost
always are, and for synthetic corpora (e.g. a Juliet test case) wrapping it
in a throwaway `git init` costs nothing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


class WorktreeError(RuntimeError):
    """Raised when git worktree creation/removal fails."""


class Worktree:
    """Context manager for one isolated, disposable checkout.

    Usage:
        with Worktree(project_root) as wt_path:
            ... apply patch / build / test inside wt_path ...
    (removed automatically on exit, even if the block raises)
    """

    def __init__(self, project_root: Path, base_ref: str = "HEAD"):
        self.project_root = Path(project_root)
        self.base_ref = base_ref
        self._tmp_parent: str | None = None
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self._tmp_parent = tempfile.mkdtemp(prefix="sectool-worktree-")
        self.path = Path(self._tmp_parent) / "wt"
        try:
            subprocess.run(
                [
                    "git",
                    "worktree",
                    "add",
                    "--detach",
                    str(self.path),
                    self.base_ref,
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            shutil.rmtree(self._tmp_parent, ignore_errors=True)
            raise WorktreeError(
                f"Failed to create git worktree from {self.project_root} "
                f"at {self.base_ref}: {exc.stderr}"
            ) from exc
        return self.path

    def __exit__(self, *exc_info) -> None:
        if self.path is not None:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(self.path)],
                cwd=self.project_root,
                capture_output=True,
                text=True,
            )
        if self._tmp_parent is not None:
            shutil.rmtree(self._tmp_parent, ignore_errors=True)
