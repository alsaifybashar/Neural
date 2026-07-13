"""A minimal event-hook mechanism so the pipeline can report progress
without any of its core modules (scanner, verifier, dispatcher) importing
a UI library or knowing how their progress gets displayed.

Every stage-boundary in Scanner.scan()/Verifier.verify()/Dispatcher.
run_finding() calls `emit(on_event, stage, status, ...)`. `on_event` is an
optional `Callable[[Event], None]` threaded through from the CLI; when
it's None (as in every existing test), emit() is a no-op, so this adds no
behavior or dependency to code that doesn't care about progress reporting.
`sectool/ui.py` is the one place that turns these events into terminal
output (spinners, panels, progress bars).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# stage identifiers, dotted like a namespace so a UI layer can pattern-match
# on prefix (e.g. everything under "verify.*") without an enum import cycle.
STAGE_SCAN_LOG = "scan.log"
STAGE_SCAN_ANALYZE = "scan.analyze"
STAGE_SCAN_PARSE = "scan.parse"

STAGE_VERIFY_PATCH = "verify.patch"
STAGE_VERIFY_BUILD = "verify.build"
STAGE_VERIFY_TEST = "verify.test"
STAGE_VERIFY_RESCAN = "verify.rescan"
STAGE_VERIFY_RESULT = "verify.result"

# The rescan gate's inner CodeChecker pipeline, re-namespaced from scan.*
# by the Verifier so a UI can render them as sub-steps of the gate rather
# than mistaking them for a second top-level project scan.
STAGE_VERIFY_RESCAN_LOG = "verify.rescan.log"
STAGE_VERIFY_RESCAN_ANALYZE = "verify.rescan.analyze"
STAGE_VERIFY_RESCAN_PARSE = "verify.rescan.parse"

STAGE_DISPATCH_ATTEMPT = "dispatch.attempt"
STAGE_DISPATCH_MODEL_CALL = "dispatch.model_call"
STAGE_DISPATCH_CONTEXT_TOOL = "dispatch.context_tool"
STAGE_DISPATCH_FINDING_RESULT = "dispatch.finding_result"

STATUS_START = "start"
STATUS_DONE = "done"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"


@dataclass
class Event:
    stage: str
    status: str
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    at: float = field(default_factory=time.monotonic)


OnEvent = Optional[Callable[[Event], None]]


def emit(on_event: OnEvent, stage: str, status: str, message: str = "", **data: Any) -> None:
    if on_event is not None:
        on_event(Event(stage=stage, status=status, message=message, data=data))


def tee(*handlers: OnEvent) -> OnEvent:
    """Combine several optional handlers into one OnEvent, so a single
    pipeline event stream can feed both the live terminal UI and a
    persistent transcript without either knowing about the other. None
    entries are dropped; if nothing is left, returns None so emit() stays
    a no-op."""
    active = [h for h in handlers if h is not None]
    if not active:
        return None
    if len(active) == 1:
        return active[0]

    def _fan_out(event: Event) -> None:
        for handler in active:
            handler(event)

    return _fan_out
