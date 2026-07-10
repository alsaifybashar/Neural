"""Bounded, feedback-driven retry loop that turns one Finding + one model
into a final FindingStatus, recording every attempt along the way.

Loop shape, per (finding, model):

    for attempt in 1..max_attempts:
        ask the model for a patch (including the previous attempt's
            verification failure as feedback, if this is a retry)
        record the attempt (prompt + raw response + extracted patch)
        verify the patch (patch/build/test/rescan gates)
        record the verification result
        if it passed: done, status = FIXED
        otherwise: the failure detail becomes next attempt's feedback

    if attempts are exhausted without a pass: status = REGRESSED if the
    last attempt resolved the target finding but introduced new ones,
    otherwise FAILED.

Everything is written to the FindingStore as it happens (not batched at
the end) so a crashed or interrupted run still leaves a readable partial
result.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sectool.config import ProjectConfig
from sectool.context import extract_code_context
from sectool.findings.schema import Finding, FindingStatus, FixAttempt
from sectool.findings.store import FindingStore
from sectool.models.base import FixRequest, ModelAdapter, ModelAdapterError
from sectool.verifier.verifier import Verifier

LOG = logging.getLogger(__name__)


def resolve_final_status(
    passed: bool, target_resolved: bool, has_new_findings: bool
) -> FindingStatus:
    """Maps a verification outcome to the terminal status recorded once
    attempts are exhausted (or a pass is reached).

    Kept as a standalone function (rather than inlined) because this exact
    mapping is also what the Scorer re-derives when reading results back
    out of the store -- having one definition avoids the two drifting.
    """
    if passed:
        return FindingStatus.FIXED
    if target_resolved and has_new_findings:
        return FindingStatus.REGRESSED
    return FindingStatus.FAILED


class Dispatcher:
    def __init__(
        self,
        store: FindingStore,
        verifier: Verifier,
        project: ProjectConfig,
        max_attempts: int = 3,
    ):
        self.store = store
        self.verifier = verifier
        self.project = project
        self.max_attempts = max_attempts

    def run_finding(
        self,
        finding: Finding,
        model_name: str,
        adapter: ModelAdapter,
        baseline_findings: list[Finding],
    ) -> FindingStatus:
        """Run the full retry loop for one (finding, model) pair."""
        prior_feedback: str | None = None
        last_target_resolved = False
        last_has_new_findings = False

        source_path = self.project.root / finding.file_path
        try:
            context = extract_code_context(source_path, finding.line)
        except OSError as exc:
            LOG.warning(
                "Could not read source for %s:%s (%s); skipping.",
                finding.file_path, finding.line, exc,
            )
            return FindingStatus.SKIPPED

        for attempt_number in range(1, self.max_attempts + 1):
            request = FixRequest(
                finding=finding,
                code_context=context.text,
                context_file_path=finding.file_path,
                attempt_number=attempt_number,
                prior_feedback=prior_feedback,
            )

            try:
                response = adapter.propose_fix(request)
            except ModelAdapterError as exc:
                LOG.warning(
                    "Model '%s' failed on attempt %d for %s: %s",
                    model_name, attempt_number, finding.report_hash, exc,
                )
                self.store.add_fix_attempt(
                    FixAttempt(
                        finding_hash=finding.report_hash,
                        model_name=model_name,
                        attempt_number=attempt_number,
                        patch_text="",
                        prompt_text="",
                        raw_model_response=f"<adapter error: {exc}>",
                    )
                )
                prior_feedback = f"Your previous response caused an error: {exc}"
                continue

            self.store.add_fix_attempt(
                FixAttempt(
                    finding_hash=finding.report_hash,
                    model_name=model_name,
                    attempt_number=attempt_number,
                    patch_text=response.patch_text,
                    prompt_text=response.prompt_text,
                    raw_model_response=response.raw_response,
                )
            )

            result = self.verifier.verify(
                finding=finding,
                model_name=model_name,
                attempt_number=attempt_number,
                patch_text=response.patch_text,
                baseline_findings=baseline_findings,
            )
            self.store.add_verification_result(result)

            last_target_resolved = result.target_resolved
            last_has_new_findings = bool(result.new_findings)

            if result.passed:
                return FindingStatus.FIXED

            prior_feedback = result.detail

        return resolve_final_status(
            passed=False,
            target_resolved=last_target_resolved,
            has_new_findings=last_has_new_findings,
        )
