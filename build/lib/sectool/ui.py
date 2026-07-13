"""Turns sectool.events.Event callbacks into terminal output.

This is the *only* module that imports `rich` -- the pipeline modules
(scanner, verifier, dispatcher) stay UI-agnostic and only ever call
`sectool.events.emit()`, so they remain trivially testable without a
terminal (see tests/test_events_ui.py) and this module can be swapped
(e.g. for a JSON-lines log renderer in CI) without touching pipeline code.

Design choices driven directly by the "understand what's happening in
detail" ask:
  * Every long-running step (CodeChecker log/analyze/parse, each
    verification gate, each model call) gets a spinner the moment it
    starts and a checkmark/cross with elapsed time the moment it ends --
    nothing runs silently.
  * The dispatch loop (findings x models x attempts) gets a real progress
    bar with an ETA, since unlike a single subprocess call we do have a
    comparable unit of work to extrapolate from.
  * The full prompt sent to the model, its full raw response, and the
    extracted diff are always shown in full -- never truncated -- since
    understanding exactly what was asked and what came back is the point.
  * A failed gate's full detail (compiler errors, failing test output,
    the specific new findings introduced) is shown in its own panel, not
    squeezed into one line, so a multi-line error is easy to actually read
    rather than scroll past.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.syntax import Syntax
from rich.table import Table

from sectool.events import (
    STAGE_DISPATCH_ATTEMPT,
    STAGE_DISPATCH_FINDING_RESULT,
    STAGE_DISPATCH_MODEL_CALL,
    STAGE_DISPATCH_CONTEXT_TOOL,
    STAGE_DISPATCH_FORMAT_RETRY,
    STAGE_SCAN_ANALYZE,
    STAGE_SCAN_LOG,
    STAGE_SCAN_PARSE,
    STAGE_VERIFY_BUILD,
    STAGE_VERIFY_PATCH,
    STAGE_VERIFY_RESCAN,
    STAGE_VERIFY_RESCAN_ANALYZE,
    STAGE_VERIFY_RESCAN_LOG,
    STAGE_VERIFY_RESCAN_PARSE,
    STAGE_VERIFY_RESULT,
    STAGE_VERIFY_TEST,
    STATUS_DONE,
    STATUS_ERROR,
    STATUS_SKIPPED,
    STATUS_START,
    Event,
)
from sectool.findings.schema import Finding, FindingStatus
from sectool.scorer import ModelScore

console = Console()

# Human labels for every stage this UI knows how to render a spinner for.
_SPINNER_STAGE_LABELS = {
    STAGE_SCAN_LOG: "CodeChecker log (recording build)",
    STAGE_SCAN_ANALYZE: "CodeChecker analyze (running analyzers)",
    STAGE_SCAN_PARSE: "CodeChecker parse (reading results)",
    STAGE_VERIFY_PATCH: "Applying patch",
    STAGE_VERIFY_BUILD: "Building",
    STAGE_VERIFY_TEST: "Running tests",
    STAGE_VERIFY_RESCAN: "Re-scanning with CodeChecker",
    # The rescan gate's inner pipeline, indented so it reads as sub-steps
    # of "Re-scanning" rather than a second top-level project scan.
    STAGE_VERIFY_RESCAN_LOG: "  rescan: CodeChecker log",
    STAGE_VERIFY_RESCAN_ANALYZE: "  rescan: CodeChecker analyze",
    STAGE_VERIFY_RESCAN_PARSE: "  rescan: CodeChecker parse",
    STAGE_DISPATCH_MODEL_CALL: "Waiting for model",
    STAGE_DISPATCH_CONTEXT_TOOL: "Gathering requested context",
    STAGE_DISPATCH_FORMAT_RETRY: "Re-asking after undecodable response",
}

_STATUS_ICON = {
    STATUS_DONE: "[green]✔[/green]",  # check
    STATUS_ERROR: "[red]✖[/red]",  # cross
    STATUS_SKIPPED: "[yellow]○[/yellow]",  # circle
}

_FINDING_STATUS_STYLE = {
    FindingStatus.FIXED: ("[bold green]FIXED[/bold green]", "✔"),
    FindingStatus.REGRESSED: ("[bold yellow]REGRESSED[/bold yellow]", "⚠"),
    FindingStatus.FAILED: ("[bold red]FAILED[/bold red]", "✖"),
    FindingStatus.SKIPPED: ("[dim]SKIPPED[/dim]", "○"),
}


def print_header(text: str) -> None:
    console.rule(f"[bold]{text}[/bold]")


def print_info(text: str) -> None:
    console.print(text)


def print_warning(text: str) -> None:
    console.print(f"[yellow]Warning:[/yellow] {text}")


def print_error(text: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {text}")


def render_preflight(results: list) -> None:
    """Prints the preflight checklist. Takes `list[preflight.CheckResult]`
    (not type-hinted against that module to avoid a circular import --
    ui.py is imported by cli.py, which also imports preflight.py)."""
    console.print()
    for r in results:
        if r.ok:
            console.print(f"  [green]✔[/green] {r.name}")
        elif r.level == "warning":
            console.print(f"  [yellow]⚠[/yellow] {r.name} -- {r.detail}")
        else:
            console.print(f"  [red]✖[/red] {r.name} -- {r.detail}")
    console.print()


def render_findings_table(
    findings: list[Finding],
    selected_indices: set[int] | None = None,
    project_root: object = None,
) -> Table:
    """Numbered table of findings, suitable both as a plain listing and as
    the reference table shown above an interactive checkbox selector.

    `project_root`, if given, is stripped from each finding's file path for
    display only (Finding.file_path itself is left untouched -- other code
    relies on it being resolvable as-is). Locations use overflow="fold"
    (wrap instead of ellipsize): a truncated "/home/ubunt…" path is worse
    than useless for picking findings, since it's exactly the information
    a developer needs to tell findings apart.
    """
    table = Table(title=f"{len(findings)} security finding(s)")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Location", overflow="fold", ratio=3)
    table.add_column("CWE / CERT")
    table.add_column("Severity")
    table.add_column("Checker")
    table.add_column("Message", overflow="fold", ratio=2)

    for i, f in enumerate(findings, start=1):
        row_style = "bold" if selected_indices and i in selected_indices else None
        path = f.file_path
        if project_root is not None:
            try:
                path = str(_relative_path(f.file_path, project_root))
            except ValueError:
                pass
        table.add_row(
            str(i),
            f"{path}:{f.line}",
            ", ".join(f.cwe_ids or f.cert_rule_ids) or "-",
            f.severity,
            f.checker_name,
            f.message,
            style=row_style,
        )
    return table


def _relative_path(file_path: str, project_root) -> str:
    from pathlib import Path
    return str(Path(file_path).resolve().relative_to(Path(project_root).resolve()))


def render_leaderboard(scores: dict[str, ModelScore]) -> Table:
    table = Table(title="Leaderboard")
    for col in (
        "Model", "Total", "Fixed", "Fix rate", "Regressed",
        "Regression rate", "Failed", "Skipped", "Infra excluded", "Avg attempts",
    ):
        table.add_column(col)

    for s in scores.values():
        table.add_row(
            s.model_name,
            str(s.total),
            str(s.fixed),
            f"{s.fix_rate:.1%}",
            str(s.regressed),
            f"[bold]{s.regression_rate:.1%}[/bold]" if s.regressed else f"{s.regression_rate:.1%}",
            str(s.failed),
            str(s.skipped),
            str(s.infrastructure_failures),
            f"{s.avg_attempts_to_resolve:.2f}" if s.avg_attempts_to_resolve else "-",
        )
    return table


def render_prompt(prompt_text: str) -> None:
    """Prints the exact prompt sent to a model, in full -- never truncated.
    This is the literal text the model saw, including the shared
    instructions (see models/prompt.py), the finding detail, the CERT
    rule, the analyzer trace, the source code shown, and (on a retry) the
    previous attempt's rejection reason -- everything relevant to judging
    why the model responded the way it did."""
    console.print(Panel(prompt_text, title="Prompt sent to model", border_style="blue", title_align="left"))


def render_response(raw_response: str, patch_text: str) -> None:
    console.print(Panel(raw_response, title="Raw model response", border_style="magenta", title_align="left"))
    if patch_text.strip():
        console.print(Panel(
            Syntax(patch_text, "diff", background_color="default"),
            title="Extracted patch",
            border_style="cyan",
            title_align="left",
        ))
    else:
        print_warning("No diff could be extracted from the model's response -- this attempt will fail patch application.")


def render_call_metadata(
    model_id: str | None,
    latency_s: float | None,
    input_tokens: int | None,
    output_tokens: int | None,
    temperature: float | None,
    max_output_tokens: int | None,
) -> None:
    """One dim line of how the model was invoked and what it cost in time
    and tokens -- the comparison signals (latency, throughput, token
    volume) that matter when the whole point of a run is judging models
    against each other. Any field the provider didn't report is simply
    omitted rather than shown as a placeholder."""
    parts: list[str] = []
    if model_id:
        parts.append(f"model={model_id}")
    if latency_s is not None:
        parts.append(f"latency={latency_s:.1f}s")
    if input_tokens is not None:
        parts.append(f"tokens_in={input_tokens:,}")
    if output_tokens is not None:
        parts.append(f"tokens_out={output_tokens:,}")
        if latency_s:
            parts.append(f"({output_tokens / latency_s:.0f} tok/s)")
    if temperature is not None:
        parts.append(f"temperature={temperature}")
    if max_output_tokens is not None:
        parts.append(f"max_tokens={max_output_tokens}")
    if parts:
        console.print(f"[dim]{'  '.join(parts)}[/dim]")


def render_verdict(status: FindingStatus, detail: str = "") -> None:
    label, icon = _FINDING_STATUS_STYLE[status]
    console.print(f"{icon} {label}" + (f" -- {detail}" if detail else ""))


class DispatchProgress:
    """Wraps a rich.progress.Progress bar over the outer (finding, model)
    loop -- this is the one place an ETA is honest, since we have a
    comparable unit of work (one finding x one model) to extrapolate
    average duration from, unlike a single opaque subprocess call."""

    def __init__(self, total: int):
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        self._task_id = None
        self._total = total

    def __enter__(self) -> "DispatchProgress":
        self._progress.__enter__()
        self._task_id = self._progress.add_task("Dispatching", total=self._total)
        return self

    def __exit__(self, *exc_info) -> None:
        self._progress.__exit__(*exc_info)

    def advance(self, description: str) -> None:
        self._progress.update(self._task_id, advance=1, description=description)


@dataclass
class RunUI:
    """The on_event callback passed into Scanner.scan()/Dispatcher.
    run_finding() during `sectool run`. Stateful only in the sense of
    tracking when the currently-displayed spinner/stage started, so it can
    print an elapsed time once that stage ends.
    """

    show_prompts: bool = True  # Set False to suppress prompt/response panels
    # entirely (e.g. a quieter automated log); when shown, they're always
    # shown in full -- see render_prompt's docstring for why.
    _stage_start: dict[str, float] | None = None
    _status: object = None  # active rich.status.Status, if any

    def __post_init__(self) -> None:
        self._stage_start = {}

    def __call__(self, event: Event) -> None:
        if event.stage in _SPINNER_STAGE_LABELS:
            self._handle_spinner_stage(event)
            if event.stage == STAGE_DISPATCH_MODEL_CALL and event.status == STATUS_DONE:
                # model_call is both a spinner stage (start -> done with
                # elapsed time) and the carrier of the response payload;
                # the spinner checkmark alone would silently drop the
                # prompt/response/metadata display.
                self._handle_model_response(event)
        elif event.stage == STAGE_VERIFY_RESULT:
            self._handle_verify_result(event)
        elif event.stage == STAGE_DISPATCH_ATTEMPT:
            self._handle_attempt(event)
        elif event.stage == STAGE_DISPATCH_FINDING_RESULT:
            self._handle_finding_result(event)

    def _handle_spinner_stage(self, event: Event) -> None:
        label = _SPINNER_STAGE_LABELS[event.stage]
        if event.status == STATUS_START:
            self._stage_start[event.stage] = time.monotonic()
            if self._status is not None:
                # Stages can nest (the rescan gate contains its own
                # log/analyze/parse); hand the spinner off to the inner
                # stage -- the outer one's elapsed time is still tracked
                # in _stage_start and reported when it completes.
                self._status.stop()
            self._status = console.status(f"{label.strip()}...")
            self._status.start()
            return

        elapsed = time.monotonic() - self._stage_start.get(event.stage, time.monotonic())
        if self._status is not None:
            self._status.stop()
            self._status = None

        icon = _STATUS_ICON.get(event.status, "?")
        console.print(f"{icon} {label} ({elapsed:.1f}s)")
        if event.data.get("summary"):
            # The stage's key facts (finding counts, file counts, output
            # paths, ...) -- one dim line under the checkmark.
            console.print(f"  [dim]{event.data['summary']}[/dim]")

        if event.status == STATUS_ERROR and event.message:
            # Full detail in its own panel -- compiler errors and failing
            # test output are often many lines, and this is exactly the
            # information needed to understand *why* a gate failed, so it
            # is never truncated here (verifier/build.py already caps what
            # gets stored/fed back to the model to the last 100 lines).
            console.print(Panel(
                event.message, title=f"{label} -- failure detail",
                border_style="red", title_align="left",
            ))
        elif event.status == STATUS_SKIPPED and event.message:
            console.print(f"  [dim]{event.message}[/dim]")

    def _handle_verify_result(self, event: Event) -> None:
        """One-line verdict for the whole attempt. A failing gate's full
        detail was already shown in its own panel, so this only names the
        outcome, the gate reached, and the total verification time."""
        result = event.data.get("result")
        if result is None:
            return
        duration = f"{result.duration_seconds:.1f}s"
        if result.passed:
            console.print(
                f"[bold green]Attempt verification PASSED[/bold green] ({duration})"
            )
        else:
            console.print(
                f"[bold red]Attempt verification FAILED[/bold red] at the "
                f"{result.stage_reached.value} gate ({duration})"
            )

    def _handle_attempt(self, event: Event) -> None:
        n = event.data.get("attempt_number")
        total = event.data.get("max_attempts")
        console.print(f"\n[bold]-- Attempt {n}/{total} --[/bold]")

    def _handle_model_response(self, event: Event) -> None:
        response = event.data.get("response")
        if response is None:
            return
        render_call_metadata(
            model_id=event.data.get("model_id"),
            latency_s=event.data.get("latency_s"),
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            temperature=event.data.get("temperature"),
            max_output_tokens=event.data.get("max_output_tokens"),
        )
        if self.show_prompts:
            render_prompt(response.prompt_text)
        render_response(response.raw_response, response.patch_text)

    def _handle_finding_result(self, event: Event) -> None:
        status = event.data.get("finding_status")
        if status is not None:
            render_verdict(status, event.message)
