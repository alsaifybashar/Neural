from sectool.events import Event, emit, tee


def test_emit_is_noop_when_on_event_is_none():
    # Must not raise -- every pipeline call site does `emit(on_event, ...)`
    # unconditionally, relying on this being a safe no-op in tests/library
    # use that don't care about progress reporting.
    emit(None, "some.stage", "start", "hello", foo="bar")


def test_emit_calls_on_event_with_populated_event():
    received = []
    emit(received.append, "scan.log", "start", "Recording build...", path="/x")

    assert len(received) == 1
    event = received[0]
    assert isinstance(event, Event)
    assert event.stage == "scan.log"
    assert event.status == "start"
    assert event.message == "Recording build..."
    assert event.data == {"path": "/x"}


def test_tee_of_nothing_is_none():
    # emit() relies on a None on_event being a no-op, so tee() must
    # collapse back to None rather than an empty fan-out callable.
    assert tee() is None
    assert tee(None, None) is None


def test_tee_of_one_handler_is_that_handler():
    handler = lambda event: None  # noqa: E731
    assert tee(None, handler) is handler


def test_tee_fans_out_to_all_handlers():
    first, second = [], []
    on_event = tee(first.append, None, second.append)
    emit(on_event, "scan.log", "start")
    assert len(first) == 1 and len(second) == 1
    assert first[0] is second[0]
