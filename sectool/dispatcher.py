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
import time
from dataclasses import replace
from pathlib import Path

from sectool.config import ProjectConfig
from sectool.context import (
    build_dependency_context,
    extract_code_context,
    identifiers_from_message,
)
from sectool.context_tools import ContextToolExecutor
from sectool.events import (
    STAGE_DISPATCH_ATTEMPT,
    STAGE_DISPATCH_FINDING_RESULT,
    STAGE_DISPATCH_MODEL_CALL,
    STAGE_DISPATCH_CONTEXT_TOOL,
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_START,
    OnEvent,
    emit,
)
from sectool.findings.schema import Finding, FindingStatus, FixAttempt
from sectool.findings.store import FindingStore
from sectool.models.base import (
    FatalModelAdapterError,
    FixRequest,
    ModelAdapter,
    ModelAdapterError,
    parse_model_action,
)
from sectool.security_rules import remediation_for, requires_complete_symbol_edit
from sectool.verifier.edits import (
    StructuredEdit, build_patch_from_edits, uncovered_context_ids,
)
from sectool.review import ReviewAction, ReviewCallback
from sectool.verifier.verifier import Verifier
from sectool.verifier.patch import validate_patch

LOG = logging.getLogger(__name__)


class RunAborted(Exception):
    """Raised when a human reviewer chooses to quit mid-run (see
    sectool/review.py). Propagates up through `run_finding` to the CLI's
    dispatch loop, which stops sending further work but still scores and
    reports whatever completed before the abort -- this is a deliberate
    stop, not a crash, so results already collected are not discarded.
    """


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
        compile_commands_path: Path | None = None,
        context_max_files: int = 8,
        context_max_lines: int = 240,
        max_context_rounds: int = 4,
    ):
        self.store = store
        self.verifier = verifier
        self.project = project
        self.max_attempts = max_attempts
        self.compile_commands_path = compile_commands_path
        self.context_max_files = context_max_files
        self.context_max_lines = context_max_lines
        self.max_context_rounds = max_context_rounds
        self.last_verified_result = None

    def run_finding(
        self,
        finding: Finding,
        model_name: str,
        adapter: ModelAdapter,
        baseline_findings: list[Finding],
        on_event: OnEvent = None,
        review: ReviewCallback | None = None,
        task_findings: list[Finding] | None = None,
    ) -> FindingStatus:
        """Run the full retry loop for one (finding, model) pair.

        `on_event`, if given, is called around each attempt and model call
        (see sectool/events.py), and is forwarded as-is into
        Verifier.verify() so its own gate-by-gate events interleave
        correctly with this loop's attempt/model_call events.

        `review`, if given, is called with every model response *before*
        it's ever applied to a worktree or spends any build/test time (see
        sectool/review.py). This is the "controlled, not automated" mode:
        with no `review` callback the loop behaves exactly as the fully
        automated version always has (apply and verify every response);
        with one, a human decides per attempt whether to apply & verify,
        ask the model to retry with their own note instead of a verifier
        failure, skip this finding, or quit the whole run.
        """
        self.last_verified_result = None
        task_findings = task_findings or [finding]
        task_symbols = identifiers_from_message(finding.message)
        task_symbol = (
            task_symbols[0]
            if task_symbols and requires_complete_symbol_edit(finding.checker_name)
            else ""
        )
        prior_feedback: str | None = None
        last_target_resolved = False
        last_has_new_findings = False

        source_path = self.project.root / finding.file_path
        # Diff headers must be repo-relative (`git apply` runs at the
        # worktree root), but CodeChecker reports absolute paths -- resolve
        # here so the model is told the exact path to use instead of having
        # to guess how much of the absolute path to strip.
        try:
            diff_path = str(
                Path(finding.file_path).resolve().relative_to(self.project.root.resolve())
            )
        except ValueError:
            diff_path = finding.file_path
        try:
            context = extract_code_context(source_path, finding.line)
        except OSError as exc:
            LOG.warning(
                "Could not read source for %s:%s (%s); skipping.",
                finding.file_path, finding.line, exc,
            )
            emit(
                on_event, STAGE_DISPATCH_FINDING_RESULT, STATUS_ERROR,
                f"Could not read source: {exc}", finding_status=FindingStatus.SKIPPED,
                model_name=model_name, finding_hash=finding.report_hash,
            )
            return FindingStatus.SKIPPED

        # Where else the project references identifiers this finding names
        # (e.g. a reserved-identifier namespace declared again in a sibling
        # file and called from main) -- computed once per finding, shown in
        # every attempt's prompt so a rename lands everywhere at once.
        dependency_context = build_dependency_context(
            project_root=self.project.root,
            source_path=source_path,
            finding_message=finding.message,
            compile_commands_path=self.compile_commands_path,
            max_files=self.context_max_files,
            max_lines=self.context_max_lines,
            primary_range=(context.start_line, context.end_line),
        )
        tool_executor = ContextToolExecutor(
            self.project.root, self.compile_commands_path, source_path
        )

        for attempt_number in range(1, self.max_attempts + 1):
            emit(
                on_event, STAGE_DISPATCH_ATTEMPT, STATUS_START,
                attempt_number=attempt_number, max_attempts=self.max_attempts,
                model_name=model_name, finding_hash=finding.report_hash,
            )
            request = FixRequest(
                finding=finding,
                code_context=context.text,
                context_file_path=diff_path,
                attempt_number=attempt_number,
                prior_feedback=prior_feedback,
                context_start_line=context.start_line,
                related_occurrences=dependency_context.snippets,
                compile_command=dependency_context.compile_command,
                context_truncated=dependency_context.truncated,
                task_findings=task_findings,
                remediation_guidance=remediation_for(
                    finding.checker_name, finding.cert_rule_ids
                ),
                max_context_rounds=self.max_context_rounds,
            )

            # Request parameters attached to every model_call event so both
            # the live UI and the run transcript can show exactly how the
            # model was invoked, not just what it said.
            call_params = {
                "model_name": model_name,
                "model_id": adapter.config.model_id,
                "temperature": adapter.config.temperature,
                "max_output_tokens": adapter.config.max_output_tokens,
                "finding_hash": finding.report_hash,
                "attempt_number": attempt_number,
            }
            emit(
                on_event, STAGE_DISPATCH_MODEL_CALL, STATUS_START,
                f"Asking {model_name} for a fix...", request=request, **call_params,
            )
            call_started = time.monotonic()
            try:
                response = adapter.propose_fix(request)
                total_input_tokens = response.input_tokens or 0
                total_output_tokens = response.output_tokens or 0
                raw_responses = [response.raw_response]
                searched_context_ids: set[str] = set()
                searched_for_task_symbol = False
                task_symbol_search_complete = not task_symbol
                action = parse_model_action(response.raw_response)
                context_round = 0
                while (
                    action is not None
                    and action.get("action") != "propose_fix"
                    and context_round < self.max_context_rounds
                ):
                    context_round += 1
                    emit(
                        on_event, STAGE_DISPATCH_CONTEXT_TOOL, STATUS_START,
                        f"Context action {context_round}/{self.max_context_rounds}: "
                        f"{action.get('action', 'unknown')}",
                        action=action, round=context_round,
                    )
                    tool_result = tool_executor.execute(action)
                    if (
                        action.get("action") == "search_symbol"
                        and action.get("symbol") == task_symbol
                    ):
                        searched_for_task_symbol = True
                        task_symbol_search_complete = not tool_result.payload.get(
                            "truncated", False
                        )
                    for item in tool_result.payload.get("results", []):
                        if item.get("context_id"):
                            searched_context_ids.add(item["context_id"])
                    request.tool_history.append({
                        "round": context_round,
                        "request": action,
                        "result": tool_result.as_prompt_text(),
                    })
                    request.context_round = context_round
                    emit(
                        on_event, STAGE_DISPATCH_CONTEXT_TOOL,
                        STATUS_DONE if tool_result.ok else STATUS_ERROR,
                        tool_result.as_prompt_text(), result=tool_result,
                        round=context_round,
                    )
                    response = adapter.propose_fix(request)
                    total_input_tokens += response.input_tokens or 0
                    total_output_tokens += response.output_tokens or 0
                    raw_responses.append(response.raw_response)
                    action = parse_model_action(response.raw_response)

                response.input_tokens = total_input_tokens or None
                response.output_tokens = total_output_tokens or None

                if action is not None and action.get("action") == "propose_fix":
                    disposition_map = {
                        item.get("context_id"): item.get("disposition")
                        for item in action.get("occurrence_dispositions", [])
                        if item.get("context_id")
                    }
                    missing = searched_context_ids - set(disposition_map)
                    unchanged = {
                        context_id for context_id in searched_context_ids
                        if disposition_map.get(context_id) != "edited"
                    }
                    if task_symbol and not searched_for_task_symbol:
                        response.patch_text = ""
                        response.raw_response = "\n\n".join(raw_responses)
                        prior_feedback = (
                            f"Search the complete syntax-aware occurrence set for "
                            f"'{task_symbol}' before proposing its rename."
                        )
                    elif not task_symbol_search_complete:
                        response.patch_text = ""
                        response.raw_response = "\n\n".join(raw_responses)
                        prior_feedback = (
                            f"The search for '{task_symbol}' was truncated. Request "
                            "the next_offset page before proposing the fix."
                        )
                    elif missing:
                        response.patch_text = ""
                        response.raw_response = "\n\n".join(raw_responses)
                        prior_feedback = (
                            "Structured proposal omitted dispositions for searched "
                            f"occurrences: {', '.join(sorted(missing))}"
                        )
                    elif unchanged:
                        response.patch_text = ""
                        response.raw_response = "\n\n".join(raw_responses)
                        prior_feedback = (
                            "A symbol rename must edit every syntax occurrence; "
                            f"not edited: {', '.join(sorted(unchanged))}"
                        )
                    else:
                        try:
                            edits = [
                                StructuredEdit(
                                    path=item["path"], old_text=item["old_text"],
                                    new_text=item["new_text"],
                                    expected_occurrences=int(item.get("expected_occurrences", 1)),
                                )
                                for item in action.get("edits", [])
                            ]
                        except (KeyError, TypeError, ValueError) as exc:
                            edits = []
                            prior_feedback = f"Malformed structured edits: {exc}"
                        edit_result = build_patch_from_edits(self.project.root, edits)
                        uncovered = uncovered_context_ids(
                            self.project.root, edits, searched_context_ids
                        )
                        if edit_result.valid and uncovered:
                            edit_result.valid = False
                            edit_result.detail = (
                                "Structured edits do not cover searched occurrences: "
                                f"{', '.join(sorted(uncovered))}"
                            )
                        response.patch_text = edit_result.patch_text
                        response.raw_response = "\n\n".join(raw_responses)
                        if not edit_result.valid:
                            prior_feedback = edit_result.detail
                elif action is not None:
                    response.patch_text = ""
                    response.raw_response = "\n\n".join(raw_responses)
                    prior_feedback = (
                        f"Context round limit ({self.max_context_rounds}) reached "
                        "without a propose_fix action."
                    )
            except FatalModelAdapterError as exc:
                # Unlike a transient ModelAdapterError below, this will fail
                # identically on every retry (bad key, no quota, model
                # doesn't exist, ...) and applies to the *model*, not this
                # finding -- so we don't consume a retry here. We record
                # what happened (it's still auditable via `sectool show`)
                # and re-raise so the caller can stop sending this model
                # any further findings for the rest of the run, instead of
                # repeating the same doomed call for every one of them.
                LOG.error(
                    "Model '%s' hit a fatal error on attempt %d for %s: %s",
                    model_name, attempt_number, finding.report_hash, exc,
                )
                emit(
                    on_event, STAGE_DISPATCH_MODEL_CALL, STATUS_ERROR, str(exc),
                    fatal=True, latency_s=time.monotonic() - call_started, **call_params,
                )
                self.store.add_fix_attempt(
                    FixAttempt(
                        finding_hash=finding.report_hash,
                        model_name=model_name,
                        attempt_number=attempt_number,
                        patch_text="",
                        prompt_text="",
                        raw_model_response=f"<fatal adapter error: {exc}>",
                    )
                )
                raise
            except ModelAdapterError as exc:
                LOG.warning(
                    "Model '%s' failed on attempt %d for %s: %s",
                    model_name, attempt_number, finding.report_hash, exc,
                )
                emit(
                    on_event, STAGE_DISPATCH_MODEL_CALL, STATUS_ERROR, str(exc),
                    latency_s=time.monotonic() - call_started, **call_params,
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

            emit(
                on_event, STAGE_DISPATCH_MODEL_CALL, STATUS_DONE,
                response=response, latency_s=time.monotonic() - call_started,
                **call_params,
            )

            for task_finding in task_findings:
                self.store.add_fix_attempt(
                    FixAttempt(
                        finding_hash=task_finding.report_hash,
                        model_name=model_name,
                        attempt_number=attempt_number,
                        patch_text=response.patch_text,
                        prompt_text=response.prompt_text,
                        raw_model_response=response.raw_response,
                    )
                )

            validation = validate_patch(response.patch_text, self.project.root)
            if not validation.valid:
                failure_detail = prior_feedback if action is not None and prior_feedback else validation.detail
                prior_feedback = (
                    "Your response was rejected before verification: "
                    f"{failure_detail}"
                )
                emit(
                    on_event, STAGE_DISPATCH_ATTEMPT, STATUS_ERROR,
                    prior_feedback, failure_category="invalid_response",
                )
                continue
            response.patch_text = validation.patch_text

            if review is not None:
                decision = review(response, attempt_number, self.max_attempts)

                if decision.action == ReviewAction.QUIT:
                    emit(
                        on_event, STAGE_DISPATCH_FINDING_RESULT, STATUS_ERROR,
                        "Run aborted by reviewer", finding_status=FindingStatus.SKIPPED,
                        model_name=model_name, finding_hash=finding.report_hash,
                    )
                    raise RunAborted()

                if decision.action == ReviewAction.SKIP:
                    emit(
                        on_event, STAGE_DISPATCH_FINDING_RESULT, STATUS_ERROR,
                        "Skipped by reviewer", finding_status=FindingStatus.SKIPPED,
                        model_name=model_name, finding_hash=finding.report_hash,
                    )
                    return FindingStatus.SKIPPED

                if decision.action == ReviewAction.RETRY:
                    # Don't spend any build/test time on a response the
                    # reviewer already rejected -- go straight to the next
                    # attempt (if any), with the human's note standing in
                    # for the usual "verification failed" feedback.
                    prior_feedback = (
                        f"A human reviewer asked for changes instead of "
                        f"accepting this patch: {decision.note}"
                        if decision.note
                        else "A human reviewer rejected this patch and asked "
                        "you to try a different approach."
                    )
                    continue

                # decision.action == ReviewAction.APPLY: fall through and
                # verify exactly as the fully-automated loop would.

            verify_kwargs = dict(
                finding=finding, model_name=model_name,
                attempt_number=attempt_number, patch_text=response.patch_text,
                baseline_findings=baseline_findings, on_event=on_event,
            )
            if len(task_findings) > 1:
                verify_kwargs["target_findings"] = task_findings
            result = self.verifier.verify(**verify_kwargs)
            result.patch_text = validation.patch_text
            result.touched_files = list(validation.touched_files)
            if result.passed:
                artifact_dir = self.store.db_path.parent / "verified-patches"
                artifact_dir.mkdir(parents=True, exist_ok=True)
                safe_model = "".join(c if c.isalnum() or c in "-_" else "_" for c in model_name)
                artifact = artifact_dir / f"{finding.report_hash}-{safe_model}-{attempt_number}.patch"
                artifact.write_text(validation.patch_text)
                result.artifact_path = str(artifact)
            self.store.add_verification_result(result)
            for task_finding in task_findings[1:]:
                self.store.add_verification_result(
                    replace(result, finding_hash=task_finding.report_hash)
                )

            last_target_resolved = result.target_resolved
            last_has_new_findings = bool(result.new_findings)

            if result.passed:
                self.last_verified_result = result
                emit(
                    on_event, STAGE_DISPATCH_FINDING_RESULT, STATUS_DONE,
                    finding_status=FindingStatus.FIXED,
                    model_name=model_name, finding_hash=finding.report_hash,
                )
                return FindingStatus.FIXED

            prior_feedback = result.detail

        final_status = resolve_final_status(
            passed=False,
            target_resolved=last_target_resolved,
            has_new_findings=last_has_new_findings,
        )
        emit(
            on_event, STAGE_DISPATCH_FINDING_RESULT, STATUS_ERROR,
            finding_status=final_status,
            model_name=model_name, finding_hash=finding.report_hash,
        )
        return final_status
