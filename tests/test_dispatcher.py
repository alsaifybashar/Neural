"""Tests the retry loop's control flow using a scripted fake model adapter
and a scripted fake verifier, so the loop's logic (attempt counting,
feedback threading, terminal status resolution) can be checked without a
real LLM call, a real build, or CodeChecker installed.
"""

from pathlib import Path

import pytest

from sectool.config import ProjectConfig
from sectool.dispatcher import Dispatcher, resolve_final_status
from sectool.findings.schema import (
    Finding,
    FindingStatus,
    VerificationResult,
    VerificationStage,
)
from sectool.findings.store import FindingStore
from sectool.models.base import FixRequest, FixResponse


class ScriptedAdapter:
    """Returns a pre-scripted FixResponse per call, and records every
    FixRequest it was given so tests can assert feedback was threaded
    through correctly on retries."""

    def __init__(self, responses: list[FixResponse]):
        self._responses = list(responses)
        self.requests: list[FixRequest] = []

    def propose_fix(self, request: FixRequest) -> FixResponse:
        self.requests.append(request)
        return self._responses.pop(0)


class ScriptedVerifier:
    """Returns a pre-scripted VerificationResult per call, ignoring its
    inputs beyond recording them."""

    def __init__(self, results: list[VerificationResult]):
        self._results = list(results)
        self.calls: list[dict] = []

    def verify(self, finding, model_name, attempt_number, patch_text, baseline_findings):
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


def response(patch="--- a/src/a.c\n+++ b/src/a.c\n") -> FixResponse:
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
