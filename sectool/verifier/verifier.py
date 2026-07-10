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
from dataclasses import dataclass
from pathlib import Path

from sectool.config import ProjectConfig
from sectool.findings.schema import Finding, VerificationResult, VerificationStage
from sectool.scanner.cert_mapping import CertRuleMapper
from sectool.scanner.codechecker import Scanner
from sectool.verifier.build import run_build, run_tests
from sectool.verifier.patch import apply_patch
from sectool.verifier.worktree import Worktree


@dataclass
class Verifier:
    project: ProjectConfig
    codechecker_bin: str = "CodeChecker"
    cert_mapper: CertRuleMapper | None = None
    build_timeout: int = 900
    test_timeout: int = 900

    def verify(
        self,
        finding: Finding,
        model_name: str,
        attempt_number: int,
        patch_text: str,
        baseline_findings: list[Finding],
    ) -> VerificationResult:
        """Run all four gates against `patch_text` for one finding.

        `baseline_findings` is the pre-patch scan of the *whole* project
        (not just this finding) so the rescan step can tell "new finding
        introduced by this patch" apart from "pre-existing finding this
        patch happens not to touch".
        """
        start = time.monotonic()
        baseline_hashes = {f.report_hash for f in baseline_findings}

        with Worktree(self.project.root) as worktree_path:
            patch_result = apply_patch(worktree_path, patch_text)
            if not patch_result.applied:
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.PATCH, passed=False,
                    detail=f"Patch did not apply:\n{patch_result.detail}",
                )

            build_result = run_build(
                worktree_path, self.project.build_command, self.build_timeout
            )
            if not build_result.ok:
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.BUILD, passed=False,
                    detail=f"Build failed:\n{build_result.detail}",
                )

            test_result = run_tests(
                worktree_path, self.project.test_command, self.test_timeout
            )
            if not test_result.ok:
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.TEST, passed=False,
                    detail=f"Tests failed:\n{test_result.detail}",
                )

            scanner = Scanner(
                project_root=worktree_path,
                workdir=worktree_path / ".sectool-rescan",
                codechecker_bin=self.codechecker_bin,
                cert_mapper=self.cert_mapper,
            )
            rescan = scanner.scan(
                self.project.build_command, only_cert_findings=False
            )
            rescan_hashes = {f.report_hash for f in rescan.findings}

            target_resolved = finding.report_hash not in rescan_hashes
            new_findings = [
                f for f in rescan.findings if f.report_hash not in baseline_hashes
            ]

            if not target_resolved:
                return self._result(
                    finding, model_name, attempt_number, start,
                    stage=VerificationStage.RESCAN, passed=False,
                    detail=(
                        "Build and tests passed, but the re-scan still "
                        "reports the original finding -- the patch did not "
                        "resolve it (or resolved a different location)."
                    ),
                    target_resolved=False,
                    new_findings=new_findings,
                )

            if new_findings:
                summary = "; ".join(
                    f"{f.checker_name} at {f.file_path}:{f.line}" for f in new_findings[:5]
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
                )

            return self._result(
                finding, model_name, attempt_number, start,
                stage=VerificationStage.PASSED, passed=True,
                detail="Patch applied, build and tests passed, target "
                       "finding resolved, no new findings introduced.",
                target_resolved=True,
                new_findings=[],
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
        target_resolved: bool = False,
        new_findings: list[Finding] | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            finding_hash=finding.report_hash,
            model_name=model_name,
            attempt_number=attempt_number,
            stage_reached=stage,
            passed=passed,
            detail=detail,
            target_resolved=target_resolved,
            new_findings=new_findings or [],
            duration_seconds=time.monotonic() - start,
        )
