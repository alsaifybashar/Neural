"""Tests the retry loop's control flow using a scripted fake model adapter
and a scripted fake verifier, so the loop's logic (attempt counting,
feedback threading, terminal status resolution) can be checked without a
real LLM call, a real build, or CodeChecker installed.
"""

from pathlib import Path
import json

import pytest

from sectool.config import ModelConfig, ProjectConfig
from sectool.dispatcher import Dispatcher, resolve_final_status
from sectool.findings.schema import (
    Finding,
    FindingStatus,
    VerificationResult,
    VerificationStage,
)
from sectool.findings.store import FindingStore
from sectool.models.base import FixRequest, FixResponse


# Every adapter double carries a config, matching the ModelAdapter contract
# (its __init__ sets self.config); the dispatcher reads request parameters
# off it for the model_call events.
def make_model_config() -> ModelConfig:
    return ModelConfig(name="model-a", provider="openai", model_id="scripted-model")


class ScriptedAdapter:
    """Returns a pre-scripted FixResponse per call, and records every
    FixRequest it was given so tests can assert feedback was threaded
    through correctly on retries."""

    def __init__(self, responses: list[FixResponse]):
        self._responses = list(responses)
        self.requests: list[FixRequest] = []
        self.config = make_model_config()

    def propose_fix(self, request: FixRequest) -> FixResponse:
        self.requests.append(request)
        return self._responses.pop(0)


class ScriptedVerifier:
    """Returns a pre-scripted VerificationResult per call, ignoring its
    inputs beyond recording them."""

    def __init__(self, results: list[VerificationResult]):
        self._results = list(results)
        self.calls: list[dict] = []

    def verify(self, finding, model_name, attempt_number, patch_text, baseline_findings, on_event=None):
        self.calls.append(
            {
                "attempt_number": attempt_number,
                "patch_text": patch_text,
            }
        )
        return self._results.pop(0)


def make_finding() -> Finding:
    return Finding(
        report_hash="h1",
        file_path="src/a.c",
        line=2,
        column=1,
        message="msg",
        checker_name="cert-str31-c",
        analyzer_name="clang-tidy",
        severity="HIGH",
        cert_rule_ids=["STR31-C"],
        cert_guideline="sei-cert-c",
    )


def result(passed, target_resolved, attempt_number=1, new_findings=None) -> VerificationResult:
    return VerificationResult(
        finding_hash="h1",
        model_name="model-a",
        attempt_number=attempt_number,
        stage_reached=VerificationStage.PASSED if passed else VerificationStage.BUILD,
        passed=passed,
        detail="detail",
        target_resolved=target_resolved,
        new_findings=new_findings or [],
    )


def response(patch="--- a/src/a.c\n+++ b/src/a.c\n@@ -1,3 +1,3 @@\n-int main() {\n+int main(void) {\n     return 0;\n }\n") -> FixResponse:
    return FixResponse(patch_text=patch, raw_response=f"```diff\n{patch}```", prompt_text="p")


@pytest.fixture
def project(tmp_path) -> ProjectConfig:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int main() {\n    return 0;\n}\n")
    return ProjectConfig(root=tmp_path, build_command="true", test_command="")


def test_first_attempt_success_stops_loop(tmp_path, project):
    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response()])
    verifier = ScriptedVerifier([result(passed=True, target_resolved=True)])
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)

    status = dispatcher.run_finding(make_finding(), "model-a", adapter, baseline_findings=[])

    assert status == FindingStatus.FIXED
    assert len(adapter.requests) == 1
    assert len(verifier.calls) == 1
    # The request carries what the prompt needs for an appliable diff: the
    # repo-relative path for the diff headers and the context's real
    # starting line for the numbered gutter.
    request = adapter.requests[0]
    assert request.context_file_path == "src/a.c"
    assert request.context_start_line == 1  # small file -> whole file shown
    store.close()


def test_retries_until_success_and_threads_feedback(tmp_path, project):
    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response(), response()])
    verifier = ScriptedVerifier(
        [
            result(passed=False, target_resolved=False, attempt_number=1),
            result(passed=True, target_resolved=True, attempt_number=2),
        ]
    )
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)

    status = dispatcher.run_finding(make_finding(), "model-a", adapter, baseline_findings=[])

    assert status == FindingStatus.FIXED
    assert len(adapter.requests) == 2
    assert adapter.requests[0].prior_feedback is None
    assert adapter.requests[1].prior_feedback == "detail"
    store.close()


def test_exhausting_attempts_without_resolution_is_failed(tmp_path, project):
    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response(), response()])
    verifier = ScriptedVerifier(
        [
            result(passed=False, target_resolved=False, attempt_number=1),
            result(passed=False, target_resolved=False, attempt_number=2),
        ]
    )
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=2)

    status = dispatcher.run_finding(make_finding(), "model-a", adapter, baseline_findings=[])

    assert status == FindingStatus.FAILED
    assert len(adapter.requests) == 2


def test_exhausting_attempts_with_new_findings_is_regressed(tmp_path, project):
    store = FindingStore(tmp_path / "store.db")
    regressed_finding = make_finding()
    regressed_finding.report_hash = "h2"
    adapter = ScriptedAdapter([response()])
    verifier = ScriptedVerifier(
        [
            result(
                passed=False, target_resolved=True, attempt_number=1,
                new_findings=[regressed_finding],
            ),
        ]
    )
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=1)

    status = dispatcher.run_finding(make_finding(), "model-a", adapter, baseline_findings=[])

    assert status == FindingStatus.REGRESSED


def test_request_carries_cross_file_occurrences(tmp_path, project):
    # The finding's message names an identifier that also appears in a
    # sibling file -- the request must carry that file's snippet so the
    # prompt can show it and the model can patch both files at once.
    (project.root / "src" / "b.c").write_text(
        "void helper__fn(void);\nvoid helper__fn(void) {}\n"
    )
    finding = make_finding()
    finding.message = "identifier 'helper__fn' is reserved because it contains '__'"
    (project.root / "src" / "a.c").write_text("void helper__fn(void);\nint main() { return 0; }\n")

    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response()])
    verifier = ScriptedVerifier([result(passed=True, target_resolved=True)])
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=1)
    dispatcher.run_finding(finding, "model-a", adapter, baseline_findings=[])

    occurrences = adapter.requests[0].related_occurrences
    assert [o.file_path for o in occurrences] == ["src/b.c"]
    assert "helper__fn" in occurrences[0].text
    store.close()


@pytest.mark.parametrize(
    "passed,target_resolved,has_new,expected",
    [
        (True, True, False, FindingStatus.FIXED),
        (False, True, True, FindingStatus.REGRESSED),
        (False, False, False, FindingStatus.FAILED),
        (False, True, False, FindingStatus.FAILED),
    ],
)
def test_resolve_final_status_matrix(passed, target_resolved, has_new, expected):
    assert resolve_final_status(passed, target_resolved, has_new) == expected


def test_run_finding_emits_expected_event_sequence_on_first_try_success(tmp_path, project):
    """Covers the "developer flow" requirement that every stage announce
    itself: a UI hooked up via on_event must see an attempt start, a model
    call start+done (carrying the request/response for prompt/diff
    rendering), and a finding_result at the end."""
    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response()])
    verifier = ScriptedVerifier([result(passed=True, target_resolved=True)])
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)

    events = []
    dispatcher.run_finding(
        make_finding(), "model-a", adapter, baseline_findings=[], on_event=events.append
    )

    stages = [(e.stage, e.status) for e in events]
    assert stages == [
        ("dispatch.attempt", "start"),
        ("dispatch.model_call", "start"),
        ("dispatch.model_call", "done"),
        ("dispatch.finding_result", "done"),
    ]
    model_call_done = events[2]
    assert model_call_done.data["response"].patch_text.startswith("--- a/")
    # Call metadata for the UI's metadata line and the run transcript.
    assert model_call_done.data["model_name"] == "model-a"
    assert model_call_done.data["model_id"] == "scripted-model"
    assert model_call_done.data["finding_hash"] == "h1"
    assert model_call_done.data["latency_s"] >= 0
    finding_result = events[3]
    assert finding_result.data["finding_status"] == FindingStatus.FIXED
    store.close()


def test_run_finding_emits_error_event_on_adapter_failure(tmp_path, project):
    from sectool.models.base import ModelAdapterError

    class FailingAdapter:
        config = make_model_config()

        def propose_fix(self, request):
            raise ModelAdapterError("boom")

    store = FindingStore(tmp_path / "store.db")
    verifier = ScriptedVerifier([result(passed=False, target_resolved=False, attempt_number=2)])
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=2)

    events = []
    dispatcher.run_finding(
        make_finding(), "model-a", FailingAdapter(), baseline_findings=[], on_event=events.append
    )

    stages = [(e.stage, e.status) for e in events]
    # First attempt's model call errors (no verify follows); second attempt
    # succeeds in calling the model and gets verified.
    assert stages[:2] == [("dispatch.attempt", "start"), ("dispatch.model_call", "start")]
    assert events[2].stage == "dispatch.model_call" and events[2].status == "error"
    store.close()


def test_run_finding_does_not_retry_a_fatal_adapter_error(tmp_path, project):
    """A FatalModelAdapterError (bad key, no quota, ...) means every
    remaining attempt would fail identically -- the dispatcher must not
    burn through max_attempts retrying it, and must propagate the error
    (rather than swallow it into a FAILED status) so the caller can stop
    sending this model any further findings for the rest of the run."""
    from sectool.models.base import FatalModelAdapterError

    call_count = 0

    class FatallyBrokenAdapter:
        config = make_model_config()

        def propose_fix(self, request):
            nonlocal call_count
            call_count += 1
            raise FatalModelAdapterError("insufficient quota")

    store = FindingStore(tmp_path / "store.db")
    verifier = ScriptedVerifier([])  # must never be called
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)

    finding = make_finding()
    with pytest.raises(FatalModelAdapterError):
        dispatcher.run_finding(
            finding, "model-a", FatallyBrokenAdapter(), baseline_findings=[]
        )

    assert call_count == 1  # not retried up to max_attempts
    assert len(verifier.calls) == 0  # never reached verification
    attempts = store.attempts_for(finding.report_hash, "model-a")
    assert len(attempts) == 1
    assert "fatal adapter error" in attempts[0].raw_model_response
    store.close()


# -- Human-in-the-loop review gate -------------------------------------------

class ScriptedReview:
    """Returns a pre-scripted ReviewDecision per call, and records every
    (response, attempt_number, max_attempts) it was given."""

    def __init__(self, decisions):
        self._decisions = list(decisions)
        self.calls: list[tuple] = []

    def __call__(self, response, attempt_number, max_attempts):
        self.calls.append((response, attempt_number, max_attempts))
        return self._decisions.pop(0)


def test_review_apply_behaves_like_no_review(tmp_path, project):
    from sectool.review import ReviewAction, ReviewDecision

    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response()])
    verifier = ScriptedVerifier([result(passed=True, target_resolved=True)])
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)
    review = ScriptedReview([ReviewDecision(action=ReviewAction.APPLY)])

    status = dispatcher.run_finding(
        make_finding(), "model-a", adapter, baseline_findings=[], review=review
    )

    assert status == FindingStatus.FIXED
    assert len(review.calls) == 1
    assert len(verifier.calls) == 1
    store.close()


def test_review_retry_skips_verification_and_threads_human_note(tmp_path, project):
    from sectool.review import ReviewAction, ReviewDecision

    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response(), response()])
    verifier = ScriptedVerifier([result(passed=True, target_resolved=True, attempt_number=2)])
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)
    review = ScriptedReview([
        ReviewDecision(action=ReviewAction.RETRY, note="use snprintf instead"),
        ReviewDecision(action=ReviewAction.APPLY),
    ])

    status = dispatcher.run_finding(
        make_finding(), "model-a", adapter, baseline_findings=[], review=review
    )

    assert status == FindingStatus.FIXED
    assert len(adapter.requests) == 2
    assert "use snprintf instead" in adapter.requests[1].prior_feedback
    # First attempt's response was never sent to the verifier at all.
    assert len(verifier.calls) == 1
    assert verifier.calls[0]["attempt_number"] == 2
    store.close()


def test_review_skip_stops_without_verifying(tmp_path, project):
    from sectool.review import ReviewAction, ReviewDecision

    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response()])
    verifier = ScriptedVerifier([])  # must never be called
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)
    review = ScriptedReview([ReviewDecision(action=ReviewAction.SKIP)])

    status = dispatcher.run_finding(
        make_finding(), "model-a", adapter, baseline_findings=[], review=review
    )

    assert status == FindingStatus.SKIPPED
    assert len(verifier.calls) == 0
    store.close()


def test_review_quit_raises_run_aborted_without_verifying(tmp_path, project):
    from sectool.dispatcher import RunAborted
    from sectool.review import ReviewAction, ReviewDecision

    store = FindingStore(tmp_path / "store.db")
    adapter = ScriptedAdapter([response()])
    verifier = ScriptedVerifier([])  # must never be called
    dispatcher = Dispatcher(store=store, verifier=verifier, project=project, max_attempts=3)
    review = ScriptedReview([ReviewDecision(action=ReviewAction.QUIT)])

    with pytest.raises(RunAborted):
        dispatcher.run_finding(
            make_finding(), "model-a", adapter, baseline_findings=[], review=review
        )

    assert len(verifier.calls) == 0
    store.close()


def test_tool_assisted_structured_edits_generate_multifile_patch(tmp_path, project):
    symbol = "shared__name"
    (project.root / "src" / "a.c").write_text(
        f"int {symbol}(void) {{ return 1; }}\n"
    )
    (project.root / "src" / "b.c").write_text(
        f"int call(void) {{ return {symbol}(); }}\n"
    )
    finding = make_finding()
    finding.line = 1
    finding.message = f"identifier '{symbol}' is reserved"
    search = json.dumps({"action": "search_symbol", "symbol": symbol, "offset": 0})
    ids = ["src/a.c:1", "src/b.c:1"]
    proposal = json.dumps({
        "action": "propose_fix",
        "root_cause": "double underscore makes the identifier reserved",
        "edits": [
            {
                "path": "src/a.c",
                "old_text": f"int {symbol}(void) {{ return 1; }}",
                "new_text": "int shared_name(void) { return 1; }",
                "expected_occurrences": 1,
                "context_ids": [ids[0]],
            },
            {
                "path": "src/b.c",
                "old_text": f"int call(void) {{ return {symbol}(); }}",
                "new_text": "int call(void) { return shared_name(); }",
                "expected_occurrences": 1,
                "context_ids": [ids[1]],
            },
        ],
        "occurrence_dispositions": [
            {"context_id": context_id, "disposition": "edited", "reason": "rename"}
            for context_id in ids
        ],
    })
    adapter = ScriptedAdapter([
        FixResponse("", search, "p1"),
        FixResponse("", proposal, "p2"),
    ])
    verifier = ScriptedVerifier([result(passed=True, target_resolved=True)])
    store = FindingStore(tmp_path / "structured.db")
    dispatcher = Dispatcher(store, verifier, project, max_attempts=1)

    status = dispatcher.run_finding(finding, "model-a", adapter, [])

    assert status == FindingStatus.FIXED
    assert len(adapter.requests) == 2
    patch = verifier.calls[0]["patch_text"]
    assert "shared_name" in patch
    assert "--- a/src/a.c" in patch and "--- a/src/b.c" in patch
    assert adapter.requests[1].tool_history[0]["request"]["action"] == "search_symbol"
    store.close()
