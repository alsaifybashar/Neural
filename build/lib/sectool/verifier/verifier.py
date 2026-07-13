"""Orchestrates the four-gate verification pipeline for one patch attempt.

Gates, run in order, short-circuiting on the first failure (so the
feedback handed back to the model on retry is always the *earliest*,
most actionable problem rather than a confusing pile of downstream
symptoms):

    1. patch  - does the diff apply cleanly?
    2. build  - does the project still compile?
    3. test   - do the project's existing tests still pass (if any)?
    4. rescan - does a fresh CodeChecker scan show the target finding gone,
                with no findings introduced that weren't in the baseline?

Only a patch that clears all four is ever recorded as FIXED.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from sectool.config import ProjectConfig
from sectool.events import (
    STAGE_VERIFY_BUILD,
    STAGE_VERIFY_PATCH,
    STAGE_VERIFY_RESCAN,
    STAGE_VERIFY_RESULT,
    STAGE_VERIFY_TEST,
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
    STATUS_START,
    Event,
    OnEvent,
    emit,
)
from sectool.findings.schema import (
    Finding, VerificationResult, VerificationStage, normalized_finding_identity,
)
from sectool.scanner.cert_mapping import CertRuleMapper, DEFAULT_CERT_GUIDELINES
from sectool.scanner.codechecker import Scanner
from sectool.verifier.build import run_build, run_tests
from sectool.verifier.feedback import annotate_with_source
from sectool.verifier.patch import apply_patch
from sectool.verifier.worktree import Worktree

# Intro for compiler/test diagnostics: unlike the patch gate (where the
# hunk itself failed), here the diff applied but broke locations the model
# may never have seen -- show it their post-patch content.
_GATE_FEEDBACK_INTRO = (
    "The referenced file content (after your patch was applied) is shown "
    "below with a `N | ` line-number gutter (the gutter is not part of the "
    "file). Use these exact lines and line numbers when writing hunks that "
    "touch these files:"
)


def _patched_file_count(patch_text: str) -> int:
    """Number of distinct files a unified diff touches, from its `+++ `
    headers -- the key fact worth one line when the patch gate passes."""
    return len({
        line[4:].strip() for line in patch_text.splitlines()
        if line.startswith("+++ ")
    })


def _rescan_namespaced(on_event: OnEvent) -> OnEvent:
    """Wraps `on_event` so the nested rescan Scanner's scan.log/analyze/
    parse events arrive as verify.rescan.log/analyze/parse (see the stage
    constants in sectool/events.py)."""
    if on_event is None:
        return None

    def _forward(event: Event) -> None:
        substage = event.stage.rsplit(".", 1)[-1]
        on_event(Event(
            stage=f"verify.rescan.{substage}", status=event.status,
            message=event.message, data=event.data, at=event.at,
        ))

    return _forward


@dataclass
class Verifier:
    project: ProjectConfig
    codechecker_bin: str = "CodeChecker"
    cert_mapper: CertRuleMapper | None = None
    cert_guidelines: tuple[str, ...] = DEFAULT_CERT_GUIDELINES
    checker_enables: tuple[str, ...] = ()
    cwe_from_filename: bool = True
    build_timeout: int = 900
    test_timeout: int = 900

    def verify(
        self,
        finding: Finding,
        model_name: str,
        attempt_number: int,
        patch_text: str,
        baseline_findings: list[Finding],
        on_event: OnEvent = None,
        target_findings: list[Finding] | None = None,
    ) -> VerificationResult:
        """Run all four gates against `patch_text` for one finding.

        `baseline_findings` is the pre-patch scan of the *whole* project
        (not just this finding) so the rescan step can tell "new finding
        introduced by this patch" apart from "pre-existing finding this
        patch happens not to touch".

        `on_event`, if given, is called at the start/end of each gate (see
        sectool/events.py) so a caller (sectool/ui.py) can render a live
        checklist of patch/build/test/rescan as they happen, and the final
        pass/fail verdict.
        """
        start = time.monotonic()
        target_findings = target_findings or [finding]
        baseline_identities = Counter(
            normalized_finding_identity(f, self.project.root) for f in baseline_findings
        )

        with Worktree(self.project.root) as worktree_path:
            emit(on_event, STAGE_VERIFY_PATCH, STATUS_START, "Applying patch...")
            patch_result = apply_patch(worktree_path, patch_text)
            if not patch_result.applied:
                emit(on_event, STAGE_VERIFY_PATCH, STATUS_ERROR, patch_result.detail)
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.PATCH, passed=False,
                    detail=f"Patch did not apply:\n{patch_result.detail}",
                    on_event=on_event,
                )
            patched_files = _patched_file_count(patch_text)
            how = (
                "cleanly"
                if patch_result.strategy in ("", "exact")
                # A fallback rung applying is worth surfacing: the change
                # landed, but the model's diff bookkeeping was off.
                else f"via `git apply {patch_result.strategy}`"
            )
            emit(
                on_event, STAGE_VERIFY_PATCH, STATUS_DONE,
                summary=f"patch applied {how} to {patched_files} file(s)",
            )

            emit(on_event, STAGE_VERIFY_BUILD, STATUS_START, "Building...")
            build_result = run_build(
                worktree_path, self.project.build_command, self.build_timeout
            )
            if not build_result.ok:
                emit(
                    on_event, STAGE_VERIFY_BUILD, STATUS_ERROR, build_result.detail,
                    full_detail=build_result.full_detail,
                )
                annotated = annotate_with_source(
                    worktree_path, build_result.detail, _GATE_FEEDBACK_INTRO
                )
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.BUILD, passed=False,
                    detail=f"Build failed:\n{annotated}",
                    on_event=on_event,
                )
            emit(
                on_event, STAGE_VERIFY_BUILD, STATUS_DONE,
                summary=f"exit 0: {self.project.build_command}",
            )

            emit(on_event, STAGE_VERIFY_TEST, STATUS_START, "Running tests...")
            test_result = run_tests(
                worktree_path, self.project.test_command, self.test_timeout
            )
            if test_result.skipped:
                emit(on_event, STAGE_VERIFY_TEST, STATUS_SKIPPED, test_result.detail)
            elif not test_result.ok:
                emit(
                    on_event, STAGE_VERIFY_TEST, STATUS_ERROR, test_result.detail,
                    full_detail=test_result.full_detail,
                )
                annotated = annotate_with_source(
                    worktree_path, test_result.detail, _GATE_FEEDBACK_INTRO
                )
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.TEST, passed=False,
                    detail=f"Tests failed:\n{annotated}",
                    on_event=on_event,
                )
            else:
                emit(
                    on_event, STAGE_VERIFY_TEST, STATUS_DONE,
                    summary=f"exit 0: {self.project.test_command}",
                )

            emit(on_event, STAGE_VERIFY_RESCAN, STATUS_START, "Re-scanning with CodeChecker...")
            scanner = Scanner(
                project_root=worktree_path,
                workdir=worktree_path / ".sectool-rescan",
                codechecker_bin=self.codechecker_bin,
                cert_mapper=self.cert_mapper,
                cert_guidelines=self.cert_guidelines,
                checker_enables=self.checker_enables,
                cwe_from_filename=self.cwe_from_filename,
            )
            # The nested scan's own log/analyze/parse events are forwarded
            # re-namespaced under verify.rescan.* so the UI can show them as
            # sub-steps of this gate (with their stage summaries) instead of
            # a second top-level "scanning project" sequence.
            rescan = scanner.scan(
                self.project.build_command, only_cert_findings=False,
                on_event=_rescan_namespaced(on_event),
            )
            rescan_identities = Counter(
                normalized_finding_identity(f, worktree_path) for f in rescan.findings
            )
            unresolved_targets = []
            for target in target_findings:
                identity = normalized_finding_identity(target, self.project.root)
                if rescan_identities[identity] >= max(1, baseline_identities[identity]):
                    unresolved_targets.append(target)
            target_resolved = not unresolved_targets
            remaining = baseline_identities.copy()
            new_findings = []
            for candidate in rescan.findings:
                identity = normalized_finding_identity(candidate, worktree_path)
                if remaining[identity]:
                    remaining[identity] -= 1
                else:
                    new_findings.append(candidate)

            if not target_resolved:
                locations = ", ".join(
                    f"{target.file_path}:{target.line}" for target in unresolved_targets[:5]
                )
                emit(
                    on_event, STAGE_VERIFY_RESCAN, STATUS_ERROR,
                    f"{len(unresolved_targets)} target finding(s) still present: {locations}",
                )
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.RESCAN, passed=False,
                    detail=(
                        "Build and tests passed, but the re-scan still reports "
                        f"{len(unresolved_targets)} grouped target(s): {locations}."
                    ),
                    target_resolved=False,
                    new_findings=new_findings,
                    on_event=on_event,
                )

            if new_findings:
                summary = "; ".join(
                    f"{f.checker_name} at {f.file_path}:{f.line}" for f in new_findings[:5]
                )
                emit(
                    on_event, STAGE_VERIFY_RESCAN, STATUS_ERROR,
                    f"{len(new_findings)} new finding(s) introduced: {summary}",
                )
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.RESCAN, passed=False,
                    detail=(
                        f"Original finding resolved, but the patch introduced "
                        f"{len(new_findings)} new finding(s): {summary}"
                    ),
                    target_resolved=True,
                    new_findings=new_findings,
                    on_event=on_event,
                )

            emit(
                on_event, STAGE_VERIFY_RESCAN, STATUS_DONE,
                summary=(
                    f"target finding resolved; {len(rescan.findings)} "
                    f"finding(s) post-patch, 0 new vs baseline"
                ),
            )
            return self._result(
                finding, model_name, attempt_number, start,
                stage=VerificationStage.PASSED, passed=True,
                detail="Patch applied, build and tests passed, target "
                       "finding resolved, no new findings introduced.",
                target_resolved=True,
                new_findings=[],
                on_event=on_event,
            )

    @staticmethod
    def _result(
        finding: Finding,
        model_name: str,
        attempt_number: int,
        start: float,
        stage: VerificationStage,
        passed: bool,
        detail: str,
        on_event: OnEvent,
        target_resolved: bool = False,
        new_findings: list[Finding] | None = None,
    ) -> VerificationResult:
        result = VerificationResult(
            finding_hash=finding.report_hash,
            model_name=model_name,
            attempt_number=attempt_number,
            stage_reached=stage,
            passed=passed,
            detail=detail,
            failure_category="" if passed else stage.value,
            target_resolved=target_resolved,
            new_findings=new_findings or [],
            duration_seconds=time.monotonic() - start,
        )
        emit(
            on_event, STAGE_VERIFY_RESULT,
            STATUS_DONE if passed else STATUS_ERROR,
            detail, passed=passed, result=result,
            failure_category=None if passed else stage.value,
        )
        return result
