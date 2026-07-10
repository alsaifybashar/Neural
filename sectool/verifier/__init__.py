"""Verifies that a proposed patch actually fixes a finding safely.

This is the trust boundary of the whole tool: a patch is only ever counted
as "fixed" after it clears every stage in `Verifier.verify()` --
applying cleanly, building, passing the project's existing tests (if any),
and a CodeChecker re-scan showing the original finding gone with no new
findings introduced. See verifier.py for the orchestration and
worktree.py/patch.py/build.py for each stage's mechanics.
"""

from sectool.verifier.verifier import Verifier

__all__ = ["Verifier"]
