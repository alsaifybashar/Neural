"""Regression tests for RunUI's model_call rendering.

dispatch.model_call is both a spinner stage and the carrier of the model's
response payload; a dispatch-order bug once made the spinner checkmark
swallow the done event, so the full prompt/response panels -- the core
"see exactly what was sent and answered" feature -- never rendered in a
real run. These tests pin the rendered output itself, not just the event
plumbing."""

from sectool.events import (
    STAGE_DISPATCH_MODEL_CALL,
    STATUS_DONE,
    STATUS_START,
    emit,
)
from sectool.models.base import FixResponse
from sectool.ui import RunUI, console


def make_response() -> FixResponse:
    return FixResponse(
        patch_text="--- a/a.c\n+++ b/a.c",
        raw_response="explanation\n```diff\n--- a/a.c\n+++ b/a.c\n```",
        prompt_text="THE-EXACT-PROMPT",
        input_tokens=1240,
        output_tokens=356,
    )


def drive_model_call(run_ui: RunUI) -> str:
    with console.capture() as capture:
        emit(run_ui, STAGE_DISPATCH_MODEL_CALL, STATUS_START, "Asking...")
        emit(
            run_ui, STAGE_DISPATCH_MODEL_CALL, STATUS_DONE,
            response=make_response(), latency_s=3.2, model_name="m",
            model_id="claude-sonnet-5", temperature=0.0,
            max_output_tokens=4096, finding_hash="h1", attempt_number=1,
        )
    return capture.get()


def test_model_call_done_renders_prompt_response_and_metadata():
    output = drive_model_call(RunUI())
    assert "Prompt sent to model" in output
    assert "THE-EXACT-PROMPT" in output
    assert "Raw model response" in output
    assert "Extracted patch" in output
    # The metadata line: how the model was invoked and what it cost.
    assert "model=claude-sonnet-5" in output
    assert "latency=3.2s" in output
    assert "tokens_in=1,240" in output
    assert "tokens_out=356" in output
    # The spinner stage still closes out with its checkmark line too.
    assert "Waiting for model" in output


def test_show_prompts_false_hides_prompt_but_keeps_response():
    output = drive_model_call(RunUI(show_prompts=False))
    assert "THE-EXACT-PROMPT" not in output
    assert "Raw model response" in output


def test_stage_summary_renders_under_checkmark():
    run_ui = RunUI()
    with console.capture() as capture:
        emit(run_ui, "scan.log", STATUS_START, "Recording build...")
        emit(run_ui, "scan.log", STATUS_DONE, "path",
             summary="42 compiler invocation(s) recorded -> compile_commands.json")
    output = capture.get()
    assert "CodeChecker log" in output
    assert "42 compiler invocation(s) recorded" in output


def test_nested_rescan_stage_hands_off_spinner_and_renders_both():
    # verify.rescan starts, then its inner log stage starts while the
    # rescan spinner is still active -- both must complete with their own
    # checkmark lines and no rich live-display crash.
    run_ui = RunUI()
    with console.capture() as capture:
        emit(run_ui, "verify.rescan", STATUS_START, "Re-scanning...")
        emit(run_ui, "verify.rescan.log", STATUS_START, "Recording build...")
        emit(run_ui, "verify.rescan.log", STATUS_DONE, summary="2 invocation(s)")
        emit(run_ui, "verify.rescan", STATUS_DONE,
             summary="target finding resolved; 5 finding(s) post-patch, 0 new vs baseline")
    output = capture.get()
    assert "rescan: CodeChecker log" in output
    assert "2 invocation(s)" in output
    assert "Re-scanning with CodeChecker" in output
    assert "target finding resolved" in output


def test_verify_result_renders_one_line_verdict():
    from sectool.findings.schema import VerificationResult, VerificationStage

    run_ui = RunUI()
    result = VerificationResult(
        finding_hash="h1", model_name="m", attempt_number=1,
        stage_reached=VerificationStage.BUILD, passed=False,
        detail="Build failed:\n...", target_resolved=False,
        new_findings=[], duration_seconds=12.34,
    )
    with console.capture() as capture:
        emit(run_ui, "verify.result", "error", result.detail,
             passed=False, result=result)
    output = capture.get()
    assert "Attempt verification FAILED" in output
    assert "build gate" in output
    assert "12.3s" in output
