"""The human-in-the-loop contract between a proposed fix and the Verifier.

By default `sectool run` (when attached to a terminal, and not run with
`-y`) pauses here: after a model proposes a patch and before that patch is
ever applied to a worktree or spends any build/test time, a human decides
what happens next. This is deliberately a separate, blocking concern from
`events.py` (which is one-way, fire-and-forget progress reporting) --
reviewing a fix is a two-way interaction that can change what the
dispatcher does next.

`sectool.interactive.review_fix` is the concrete terminal implementation
of `ReviewCallback`; `dispatcher.py` only depends on this module's types,
not on `questionary`/`rich`, so the retry loop stays testable with a
scripted callback (see tests/test_dispatcher.py).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from sectool.models.base import FixResponse


class ReviewAction(str, enum.Enum):
    APPLY = "apply"  # Proceed exactly as the fully-automated loop would:
    # apply the patch and run the verification gates.
    RETRY = "retry"  # Don't verify this response. Ask the model again,
    # counting against the same attempt budget, with an optional human
    # note replacing the usual "verification failed" feedback.
    SKIP = "skip"  # Stop working this finding for this model; recorded as
    # FindingStatus.SKIPPED, same as an unreadable source file.
    QUIT = "quit"  # Abort the entire run. Whatever findings/models already
    # completed are still scored and reported -- this stops future work,
    # it does not discard past results.


@dataclass
class ReviewDecision:
    action: ReviewAction
    note: str = ""  # Only meaningful when action is RETRY: free-text
    # feedback a human is giving the model instead of a verifier failure.


# (response, attempt_number, max_attempts) -> ReviewDecision
ReviewCallback = Callable[["FixResponse", int, int], ReviewDecision]


class VerifiedPatchAction(str, enum.Enum):
    APPLY = "apply"
    KEEP = "keep"
    DISCARD = "discard"
