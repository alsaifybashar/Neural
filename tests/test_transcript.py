"""Tests for the JSONL run transcript: every event written is one
self-contained, parseable JSON line, with the payload objects that matter
for post-hoc analysis (FixResponse, FindingStatus, dataclasses) expanded
rather than str()-ed away."""

import json

from sectool.events import Event, emit, tee
from sectool.findings.schema import FindingStatus
from sectool.models.base import FixResponse
from sectool.transcript import TranscriptWriter, _jsonable


def read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_events_written_as_parseable_jsonl(tmp_path):
    path = tmp_path / "transcript.jsonl"
    with TranscriptWriter(path) as writer:
        emit(writer, "scan.log", "start", "Recording build...", path="/x")
        emit(writer, "scan.log", "done")

    records = read_lines(path)
    assert len(records) == 2
    assert records[0]["stage"] == "scan.log"
    assert records[0]["status"] == "start"
    assert records[0]["message"] == "Recording build..."
    assert records[0]["path"] == "/x"
    assert "ts" in records[0] and "elapsed_s" in records[0]


def test_model_response_expanded_with_metadata(tmp_path):
    path = tmp_path / "transcript.jsonl"
    response = FixResponse(
        patch_text="--- a\n+++ b",
        raw_response="here is a patch",
        prompt_text="fix this finding",
        input_tokens=120,
        output_tokens=45,
    )
    with TranscriptWriter(path) as writer:
        emit(
            writer, "dispatch.model_call", "done", response=response,
            latency_s=1.25, model_name="m", model_id="claude-sonnet-5",
            temperature=0.0, max_output_tokens=4096,
            finding_hash="h1", attempt_number=1,
        )

    (record,) = read_lines(path)
    assert record["response"]["prompt_text"] == "fix this finding"
    assert record["response"]["raw_response"] == "here is a patch"
    assert record["response"]["input_tokens"] == 120
    assert record["response"]["output_tokens"] == 45
    assert record["latency_s"] == 1.25
    assert record["model_id"] == "claude-sonnet-5"
    assert record["finding_hash"] == "h1"


def test_write_record_for_run_level_metadata(tmp_path):
    path = tmp_path / "transcript.jsonl"
    with TranscriptWriter(path) as writer:
        writer.write_record({"stage": "run.start", "models": ["a", "b"]})

    (record,) = read_lines(path)
    assert record["stage"] == "run.start"
    assert record["models"] == ["a", "b"]


def test_appends_across_writers(tmp_path):
    # A crash-and-rerun against the same path must not clobber what the
    # earlier run recorded.
    path = tmp_path / "transcript.jsonl"
    with TranscriptWriter(path) as w1:
        w1.write_record({"stage": "one"})
    with TranscriptWriter(path) as w2:
        w2.write_record({"stage": "two"})
    assert [r["stage"] for r in read_lines(path)] == ["one", "two"]


def test_jsonable_degrades_unknown_objects_to_str():
    class Weird:
        def __str__(self):
            return "weird"

    assert _jsonable(Weird()) == "weird"
    assert _jsonable(FindingStatus.FIXED) == FindingStatus.FIXED.value
    assert _jsonable({"k": (1, 2)}) == {"k": [1, 2]}


def test_tee_feeds_ui_and_transcript(tmp_path):
    path = tmp_path / "transcript.jsonl"
    seen = []
    with TranscriptWriter(path) as writer:
        on_event = tee(seen.append, writer)
        emit(on_event, "verify.build", "start")

    assert len(seen) == 1 and isinstance(seen[0], Event)
    assert read_lines(path)[0]["stage"] == "verify.build"
