"""Lets a developer choose which findings to dispatch to a model, instead
of always blasting every matched finding at every configured model.

Three ways in, in priority order:
  1. `--select "1,3,5-7"` -- an explicit spec, for scripting/CI.
  2. An interactive checkbox picker (questionary) -- the default when
     stdout is a TTY.
  3. A non-interactive fallback (respecting `finding_limit`) when neither
     of the above applies, e.g. piped output or a dumb terminal --
     printed explicitly so it's never a silent surprise.
"""

from __future__ import annotations

import sys

import questionary

from sectool import ui
from sectool.findings.schema import Finding
from sectool.models.base import FixResponse
from sectool.review import ReviewAction, ReviewDecision, VerifiedPatchAction


def parse_selection_spec(spec: str, n: int) -> list[int]:
    """Parses a spec like "1,3,5-7" (1-indexed, inclusive ranges) against
    `n` available items, returning sorted, de-duplicated 0-indexed indices.

    Kept as a standalone pure function so it can be unit-tested without a
    terminal (see tests/test_interactive.py).
    """
    if spec.strip().lower() == "all":
        return list(range(n))

    indices: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, _, end_str = part.partition("-")
            try:
                start, end = int(start_str), int(end_str)
            except ValueError as exc:
                raise ValueError(f"Invalid range '{part}' in selection spec.") from exc
            if start < 1 or end > n or start > end:
                raise ValueError(
                    f"Range '{part}' is out of bounds for {n} finding(s)."
                )
            indices.update(range(start - 1, end))
        else:
            try:
                i = int(part)
            except ValueError as exc:
                raise ValueError(f"Invalid selection '{part}'.") from exc
            if i < 1 or i > n:
                raise ValueError(f"Selection '{i}' is out of bounds for {n} finding(s).")
            indices.add(i - 1)

    return sorted(indices)


def select_findings(
    findings: list[Finding],
    select_spec: str | None = None,
    non_interactive: bool = False,
    finding_limit: int | None = None,
    project_root=None,
) -> list[Finding]:
    """Returns the subset of `findings` the user chose to dispatch."""
    if not findings:
        return []

    if select_spec:
        indices = parse_selection_spec(select_spec, len(findings))
        ui.print_info(f"Selected {len(indices)}/{len(findings)} finding(s) via --select.")
        return [findings[i] for i in indices]

    if non_interactive or not sys.stdout.isatty():
        selected = findings[:finding_limit] if finding_limit else findings
        ui.print_warning(
            f"Non-interactive session: dispatching {len(selected)}/{len(findings)} "
            f"matched finding(s)"
            + (f" (finding_limit={finding_limit})" if finding_limit else "")
            + ". Pass --select \"1,3,5-7\" or run in a terminal to choose individually."
        )
        return selected

    ui.console.print(ui.render_findings_table(findings, project_root=project_root))
    default_checked = (
        set(range(min(finding_limit, len(findings)))) if finding_limit else set(range(len(findings)))
    )
    choices = [
        questionary.Choice(
            title=(
                f"{i + 1}. {f.file_path}:{f.line} "
                f"[{', '.join(f.cwe_ids or f.cert_rule_ids) or '-'}] "
                f"{f.checker_name}"
            ),
            value=i,
            checked=i in default_checked,
        )
        for i, f in enumerate(findings)
    ]
    answer = questionary.checkbox(
        "Select findings to dispatch to the model(s) (space to toggle, enter to confirm):",
        choices=choices,
    ).ask()

    if answer is None:  # Ctrl-C / cancelled
        ui.print_warning("Selection cancelled; no findings will be dispatched.")
        return []

    return [findings[i] for i in answer]


def review_fix(response: FixResponse, attempt_number: int, max_attempts: int) -> ReviewDecision:
    """The interactive `sectool.review.ReviewCallback` used by `sectool run`'s
    default (controlled, not automated) mode.

    Called after `ui.RunUI` has already printed the full prompt, the
    model's full raw response, and the extracted diff for this attempt
    (via the dispatch.model_call event) -- this function's only job is to
    ask what to do next, not to re-print anything.
    """
    choices = [
        questionary.Choice("Apply and verify (run build/test/rescan gates)", value=ReviewAction.APPLY),
        questionary.Choice(
            "Retry -- ask the model again, optionally with your own note",
            value=ReviewAction.RETRY,
        ),
        questionary.Choice("Skip this finding for this model", value=ReviewAction.SKIP),
        questionary.Choice("Quit the run (results collected so far are still scored/reported)", value=ReviewAction.QUIT),
    ]

    action = questionary.select(
        f"Attempt {attempt_number}/{max_attempts}: what should happen with this patch?",
        choices=choices,
        default=choices[0],
    ).ask()

    if action is None:  # Ctrl-C
        ui.print_warning("No selection made; treating as quit.")
        return ReviewDecision(action=ReviewAction.QUIT)

    if action == ReviewAction.RETRY:
        note = questionary.text(
            "Optional note to send back to the model instead of a verifier "
            "failure (leave blank for none):"
        ).ask()
        return ReviewDecision(action=ReviewAction.RETRY, note=note or "")

    return ReviewDecision(action=action)


def review_verified_patch(artifact_path: Path) -> VerifiedPatchAction:
    choices = [
        questionary.Choice("Apply verified patch to the working tree", value=VerifiedPatchAction.APPLY),
        questionary.Choice("Keep patch artifact without applying", value=VerifiedPatchAction.KEEP),
        questionary.Choice("Discard working-tree application (artifact remains auditable)", value=VerifiedPatchAction.DISCARD),
    ]
    action = questionary.select(
        f"Verification passed. Patch artifact: {artifact_path}",
        choices=choices,
        default=choices[0],
    ).ask()
    return action or VerifiedPatchAction.KEEP
