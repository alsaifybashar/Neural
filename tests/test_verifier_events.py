"""Tests the Verifier's gate events: key-facts summaries on passing gates,
the re-namespaced verify.rescan.* sub-stage events from the nested
CodeChecker rescan, and the per-attempt verify.result verdict. All four
gates are faked so no git worktree, compiler, or CodeChecker is needed."""

import pytest

import sectool.verifier.verifier as verifier_module
from sectool.config import ProjectConfig
from sectool.events import emit
from sectool.findings.schema import Finding, VerificationStage
from sectool.scanner.codechecker import ScanResult
from sectool.verifier.build import CommandResult
from sectool.verifier.patch import PatchApplyResult
from sectool.verifier.verifier import Verifier, _patched_file_count

PATCH = "--- a/src/a.c\n+++ b/src/a.c\n@@ -1 +1 @@\n-x\n+y\n"


def make_finding(report_hash="h1", message="m") -> Finding:
    return Finding(
        report_hash=report_hash, file_path="src/a.c", line=1, column=1,
        message=message, checker_name="cert-str31-c", analyzer_name="clang-tidy",
        severity="HIGH", cert_rule_ids=["STR31-C"], cert_guideline="sei-cert-c",
    )


class FakeWorktree:
    def __init__(self, root):
        self._root = root

    def __enter__(self):
        return self._root

    def __exit__(self, *exc_info):
        return False


class FakeRescanScanner:
    """Stands in for the nested rescan Scanner: emits one inner stage's
    events through the forwarded on_event and reports `findings`."""

    findings: list[Finding] = []

    def __init__(self, **kwargs):
        pass

    def scan(self, build_command, only_cert_findings=True, on_event=None):
        emit(on_event, "scan.log", "start", "Recording build...")
        emit(on_event, "scan.log", "done", summary="2 compiler invocation(s) recorded")
        return ScanResult(
            findings=list(self.findings),
            total_reports_before_filter=len(self.findings),
            reports_json_path=None,
        )


@pytest.fixture
def verifier(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier_module, "Worktree", FakeWorktree)
    monkeypatch.setattr(verifier_module, "apply_patch",
                        lambda path, text: PatchApplyResult(applied=True, detail=""))
    monkeypatch.setattr(verifier_module, "run_build",
                        lambda path, cmd, timeout: CommandResult(ok=True, detail=""))
    monkeypatch.setattr(verifier_module, "run_tests",
                        lambda path, cmd, timeout: CommandResult(ok=True, detail=""))
    monkeypatch.setattr(verifier_module, "Scanner", FakeRescanScanner)
    FakeRescanScanner.findings = []
    project = ProjectConfig(root=tmp_path, build_command="make", test_command="make test")
    return Verifier(project=project)


def run_verify(verifier, baseline=None):
    events = []
    result = verifier.verify(
        finding=make_finding(), model_name="m", attempt_number=1,
        patch_text=PATCH, baseline_findings=baseline or [],
        on_event=events.append,
    )
    return result, events


def test_passing_gates_emit_key_fact_summaries(verifier):
    result, events = run_verify(verifier)
    assert result.passed

    summaries = {e.stage: e.data.get("summary") for e in events if e.status == "done"}
    assert summaries["verify.patch"] == "patch applied cleanly to 1 file(s)"
    assert summaries["verify.build"] == "exit 0: make"
    assert summaries["verify.test"] == "exit 0: make test"
    assert "target finding resolved; 0 finding(s) post-patch" in summaries["verify.rescan"]


def test_rescan_inner_stages_are_renamespaced(verifier):
    _, events = run_verify(verifier)
    stages = [(e.stage, e.status) for e in events]
    # The nested scan's events appear between rescan start and done, under
    # the verify.rescan.* namespace -- never as top-level scan.*.
    assert ("verify.rescan.log", "start") in stages
    assert ("verify.rescan.log", "done") in stages
    assert not any(s.startswith("scan.") for s, _ in stages)
    inner_done = next(e for e in events if e.stage == "verify.rescan.log" and e.status == "done")
    assert inner_done.data["summary"] == "2 compiler invocation(s) recorded"


def test_verify_result_event_carries_verdict(verifier):
    result, events = run_verify(verifier)
    verdicts = [e for e in events if e.stage == "verify.result"]
    assert len(verdicts) == 1
    assert verdicts[0].status == "done"
    assert verdicts[0].data["result"].stage_reached == VerificationStage.PASSED


def test_unresolved_target_fails_rescan_gate(verifier):
    # The rescan still reports the original finding: gate errors, result
    # records target_resolved=False, and the verdict event says error.
    FakeRescanScanner.findings = [make_finding("h1")]
    result, events = run_verify(verifier, baseline=[make_finding("h1")])

    assert not result.passed and not result.target_resolved
    rescan_error = next(e for e in events if e.stage == "verify.rescan" and e.status == "error")
    assert "still present" in rescan_error.message
    assert events[-1].stage == "verify.result" and events[-1].status == "error"


def test_new_finding_fails_rescan_gate_with_summary(verifier):
    FakeRescanScanner.findings = [make_finding("h-new", "different finding")]
    result, events = run_verify(verifier)

    assert not result.passed and result.target_resolved
    assert [f.report_hash for f in result.new_findings] == ["h-new"]
    rescan_error = next(e for e in events if e.stage == "verify.rescan" and e.status == "error")
    assert "1 new finding(s) introduced" in rescan_error.message


def test_patched_file_count():
    assert _patched_file_count(PATCH) == 1
    two_files = PATCH + "--- a/src/b.c\n+++ b/src/b.c\n@@ -1 +1 @@\n-x\n+y\n"
    assert _patched_file_count(two_files) == 2
    assert _patched_file_count("") == 0
