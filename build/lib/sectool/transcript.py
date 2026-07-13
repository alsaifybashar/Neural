"""Persists the full event stream of a run -- most importantly every
model interaction (exact prompt, raw response, extracted patch, latency,
token usage, request parameters) -- to a JSON-lines file.

Why alongside the terminal UI rather than instead of it: the panels in
ui.py answer "what is happening right now", but a model evaluation is
only useful if it can be re-examined after the fact -- diffing what two
models were asked and answered, aggregating latency/token cost, feeding
runs into other tooling. JSONL is the format for that: one self-contained
JSON object per line, appendable, greppable, trivially parseable.

Each line is flushed as it's written (same philosophy as FindingStore:
never batch at the end), so a crashed or interrupted run still leaves a
complete transcript of everything that happened up to the crash.
"""

from __future__ import annotations

import enum
import json
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sectool.events import Event


def _jsonable(value: Any) -> Any:
    """Best-effort conversion of event payload values to JSON. Events carry
    arbitrary objects (FixResponse, FixRequest, FindingStatus, ...); a
    transcript must never crash the run it's recording, so anything
    unrecognized degrades to str() rather than raising."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, enum.Enum):
        return _jsonable(value.value)
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    return str(value)


class TranscriptWriter:
    """An OnEvent callback (see sectool.events) that appends every event
    it receives to `path` as one JSON object per line. Compose it with the
    terminal UI via events.tee(run_ui, transcript_writer)."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")
        self._t0 = time.monotonic()

    def write_record(self, record: dict[str, Any]) -> None:
        """Write one arbitrary record (used for run-level metadata like the
        config used and which models are being evaluated, which never flows
        through the event stream)."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "elapsed_s": round(time.monotonic() - self._t0, 3),
            **{k: _jsonable(v) for k, v in record.items()},
        }
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()

    def __call__(self, event: Event) -> None:
        self.write_record({
            "stage": event.stage,
            "status": event.status,
            "message": event.message,
            **event.data,
        })

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "TranscriptWriter":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
