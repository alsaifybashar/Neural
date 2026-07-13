"""`sectool` command line entrypoint.

Subcommands, matching the pipeline stages a developer is likely to want to
run independently while iterating:

    sectool scan   <config>            - CodeChecker only; list matched
                                          findings. No model calls.
    sectool run    <config>             - full pipeline: preflight checks,
                                           scan, interactive finding
                                           selection, dispatch to every
                                           runnable model with retries,
                                           verify, score, report.
    sectool report <db> -o <dir>        - re-score/re-render a report from
                                           an existing run's database, with
                                           no re-scanning or model calls.
    sectool show   <db> <finding_hash>  - reprint one finding's full
                                           prompt/response/patch/
                                           verification history from a
                                           stored run.

Every step that can take a while or fail prints what it's doing as it
happens (see sectool/ui.py and sectool/events.py) -- nothing here runs
silently.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import click

from sectool import ui
from sectool.config import RunConfig
from sectool.dispatcher import Dispatcher, RunAborted, resolve_final_status
from sectool.events import tee
from sectool.findings.store import FindingStore
from sectool.findings.tasks import tasks_for_selection
from sectool.interactive import review_fix, review_verified_patch, select_findings
from sectool.models.base import FatalModelAdapterError
from sectool.models.registry import build_adapter
from sectool.preflight import has_hard_failure, run_preflight
from sectool.report import write_report
from sectool.scanner.cert_mapping import CertRuleMapper
from sectool.scanner.codechecker import Scanner
from sectool.scorer import score
from sectool.transcript import TranscriptWriter
from sectool.ui import DispatchProgress, RunUI
from sectool.verifier.verifier import Verifier
from sectool.verifier.application import apply_verified_patch
from sectool.review import VerifiedPatchAction

LOG = logging.getLogger("sectool")


@click.group()
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
def main(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@main.command()
@click.argument("config_path", type=click.Path(exists=True, path_type=Path))
def scan(config_path: Path) -> None:
    """Run CodeChecker and list matched SEI CERT findings, without
    dispatching anything to a model. Useful for validating a project's
    build_command/CERT guideline config cheaply."""
    config = RunConfig.from_file(config_path)

    ui.print_header("Preflight checks")
    results, _ = run_preflight(config, require_git=False)
    ui.render_preflight(results)
    if has_hard_failure(results):
        ui.print_error("Cannot continue until the issue(s) above are fixed.")
        sys.exit(1)

    cert_mapper = CertRuleMapper(
        guidelines=config.cert_guidelines,
        cache_path=config.output_dir / "cert_rule_map.json",
    )
    scanner = Scanner(
        project_root=config.project.root,
        workdir=config.output_dir / "scan",
        cert_guidelines=config.cert_guidelines,
        cert_mapper=cert_mapper,
    )

    ui.print_header("Scanning")
    run_ui = RunUI()
    result = scanner.scan(
        config.project.build_command, only_cert_findings=False, on_event=run_ui
    )
    cert_findings = [f for f in result.findings if f.cert_rule_ids]

    ui.print_info(
        f"\n{result.total_reports_before_filter} total findings, "
        f"{len(cert_findings)} matched SEI CERT guidelines "
        f"{config.cert_guidelines}."
    )
    if cert_findings:
        ui.console.print(ui.render_findings_table(cert_findings, project_root=config.project.root))


@main.command()
@click.argument("config_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-y", "--yes", is_flag=True,
    help="Skip interactive selection; dispatch all matched findings "
         "(respecting finding_limit). Use for CI/non-interactive runs.",
)
@click.option(
    "--select", "select_spec", default=None,
    help='Explicit selection instead of the interactive picker, e.g. '
         '"1,3,5-7" or "all".',
)
@click.option(
    "--show-prompts/--no-show-prompts", default=True,
    help="Show the full prompt sent to each model as it's dispatched "
         "(default: on). Response/diff and gate failure detail are always "
         "shown regardless of this flag.",
)
@click.option(
    "--transcript/--no-transcript", "transcript_enabled", default=True,
    help="Record every event of the run -- full prompts, responses, "
         "patches, latency/token metadata, verdicts -- to a timestamped "
         "JSONL file in the output directory (default: on).",
)
def run(
    config_path: Path,
    yes: bool,
    select_spec: str | None,
    show_prompts: bool,
    transcript_enabled: bool,
) -> None:
    """Run the full pipeline: preflight checks, scan, select findings,
    dispatch to the configured model with retries, verify, score, report."""
    config = RunConfig.from_file(config_path)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    if len(config.models) != 1:
        ui.print_error(
            "Exactly one model must be configured per run; use separate "
            "output directories to compare models."
        )
        sys.exit(1)

    ui.print_header("Preflight checks")
    results, runnable_models = run_preflight(config, require_git=True)
    ui.render_preflight(results)
    if has_hard_failure(results):
        ui.print_error("Cannot continue until the issue(s) above are fixed.")
        sys.exit(1)
    if not runnable_models:
        ui.print_error(
            "No configured model passed its checks -- nothing to dispatch to."
        )
        sys.exit(1)
    skipped = [m.name for m in config.models if m not in runnable_models]
    if skipped:
        ui.print_warning(f"Continuing without: {', '.join(skipped)}")

    cert_mapper = CertRuleMapper(
        guidelines=config.cert_guidelines,
        cache_path=config.output_dir / "cert_rule_map.json",
    )
    scanner = Scanner(
        project_root=config.project.root,
        workdir=config.output_dir / "scan",
        cert_guidelines=config.cert_guidelines,
        cert_mapper=cert_mapper,
    )

    run_ui = RunUI(show_prompts=show_prompts)

    transcript_writer: TranscriptWriter | None = None
    transcript_path: Path | None = None
    if transcript_enabled:
        # Timestamped name so re-running against the same output_dir keeps
        # one file per run instead of interleaving several runs' events.
        transcript_path = (
            config.output_dir
            / f"transcript-{datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl"
        )
        transcript_writer = TranscriptWriter(transcript_path)
        transcript_writer.write_record({
            "stage": "run.start",
            "status": "start",
            "config_path": str(config_path),
            "project_root": str(config.project.root),
            "models": [m.name for m in runnable_models],
            "max_attempts": config.max_attempts_per_finding,
        })
        ui.print_info(f"Recording full run transcript to {transcript_path}")
    on_event = tee(run_ui, transcript_writer)

    try:
        ui.print_header("Scanning")
        scan_result = scanner.scan(
            config.project.build_command, only_cert_findings=False, on_event=on_event
        )
        baseline_findings = scan_result.findings
        all_cert_findings = [f for f in baseline_findings if f.cert_rule_ids]
        ui.print_info(
            f"\n{scan_result.total_reports_before_filter} total findings, "
            f"{len(all_cert_findings)} matched SEI CERT guidelines."
        )
        if not all_cert_findings:
            ui.print_warning("No SEI CERT findings to dispatch; nothing to do.")
            return

        ui.print_header("Select findings")
        dispatch_targets = select_findings(
            all_cert_findings,
            select_spec=select_spec,
            non_interactive=yes,
            finding_limit=config.finding_limit,
            project_root=config.project.root,
        )
        if not dispatch_targets:
            ui.print_warning("No findings selected; nothing to do.")
            return
        selected_findings = dispatch_targets
        dispatch_tasks = tasks_for_selection(all_cert_findings, selected_findings)
        ui.print_info(
            f"Dispatching {len(selected_findings)} finding(s) as "
            f"{len(dispatch_tasks)} root-cause task(s) to "
            f"{len(runnable_models)} model(s), up to "
            f"{config.max_attempts_per_finding} attempt(s) each."
        )

        store = FindingStore(config.output_dir / "findings.db")
        for task in dispatch_tasks:
            for finding in task.findings:
                store.upsert_finding(finding)

        verifier = Verifier(project=config.project, cert_mapper=cert_mapper)
        dispatcher = Dispatcher(
            store=store,
            verifier=verifier,
            project=config.project,
            max_attempts=config.max_attempts_per_finding,
            compile_commands_path=config.output_dir / "scan" / "compile_commands.json",
            context_max_files=config.context_max_files,
            context_max_lines=config.context_max_lines,
            max_context_rounds=config.max_context_rounds,
        )

        controlled = not yes and sys.stdout.isatty()
        review = review_fix if controlled else None
        ui.print_header("Dispatching")
        if controlled:
            ui.print_info(
                "Controlled mode: you'll review each model response before it's "
                "applied and verified (pass -y to fully automate instead)."
            )
        total_units = len(dispatch_tasks) * len(runnable_models)
        aborted_models: dict[str, str] = {}
        run_was_aborted = False
        verified_results = []
        with DispatchProgress(total=total_units) as progress:
            for model_config in runnable_models:
                if run_was_aborted:
                    break
                try:
                    adapter = build_adapter(model_config)
                except Exception as exc:  # noqa: BLE001
                    ui.print_error(f"Could not initialize model '{model_config.name}': {exc}")
                    aborted_models[model_config.name] = str(exc)
                    for _ in dispatch_tasks:
                        progress.advance(f"{model_config.name}: skipped (init failed)")
                    continue

                model_aborted_reason: str | None = None
                for i, task in enumerate(dispatch_tasks):
                    finding = task.primary
                    if model_aborted_reason is not None:
                        progress.advance(f"{model_config.name}: skipped (model unavailable)")
                        continue

                    ui.console.rule(
                        f"{finding.file_path}:{finding.line} "
                        f"({finding.primary_cert_rule()}) -- {model_config.name}"
                    )
                    try:
                        status = dispatcher.run_finding(
                            finding=finding,
                            model_name=model_config.name,
                            adapter=adapter,
                            baseline_findings=baseline_findings,
                            on_event=on_event,
                            review=review,
                            task_findings=task.findings,
                        )
                    except FatalModelAdapterError as exc:
                        # This model can't succeed on any remaining finding
                        # either (bad key, no quota, model doesn't exist, ...)
                        # -- stop sending it work rather than repeating the
                        # same doomed call for every remaining task.
                        remaining = len(dispatch_tasks) - i - 1
                        ui.print_error(
                            f"Model '{model_config.name}' hit an unrecoverable error -- "
                            f"skipping its remaining {remaining} finding(s) for this run: {exc}"
                        )
                        model_aborted_reason = str(exc)
                        progress.advance(f"{model_config.name}: skipped (model unavailable)")
                        continue
                    except RunAborted:
                        ui.print_warning(
                            "Run aborted by reviewer -- scoring and reporting what "
                            "completed so far; no further findings/models will be dispatched."
                        )
                        run_was_aborted = True
                        progress.advance(f"{model_config.name}: run aborted")
                        break

                    progress.advance(
                        f"{model_config.name}: {finding.primary_cert_rule()} -> {status.value}"
                    )
                    if status.value == "fixed" and dispatcher.last_verified_result is not None:
                        verified = dispatcher.last_verified_result
                        verified_results.append(verified)
                        ui.print_info(f"Verified patch retained at {verified.artifact_path}")

                if model_aborted_reason is not None:
                    aborted_models[model_config.name] = model_aborted_reason

        if verified_results:
            ui.print_header("Verified patches")
            if controlled:
                for verified in verified_results:
                    action = review_verified_patch(Path(verified.artifact_path))
                    if action == VerifiedPatchAction.APPLY:
                        apply_result = apply_verified_patch(
                            config.project.root, verified.patch_text
                        )
                        if apply_result.status == "applied":
                            ui.print_info(apply_result.detail)
                        else:
                            ui.print_warning(
                                f"{apply_result.detail}\nPatch retained at "
                                f"{verified.artifact_path}"
                            )
                    elif action == VerifiedPatchAction.KEEP:
                        ui.print_info("Working tree unchanged; verified patch retained.")
                    else:
                        ui.print_info("Working tree unchanged; application discarded.")
            else:
                ui.print_info(
                    "Non-interactive mode never modifies the working tree; "
                    f"retained {len(verified_results)} verified patch artifact(s)."
                )

        ui.print_header("Results")
        if aborted_models:
            for name, reason in aborted_models.items():
                ui.print_warning(f"'{name}' did not complete this run: {reason}")
        scores = score(store)
        write_report(scores, config.output_dir)
        store.close()

        ui.console.print(ui.render_leaderboard(scores))
        ui.print_info(f"Full report:        {config.output_dir}/report.html")
        ui.print_info(f"Raw data (db):       {config.output_dir}/findings.db")
        if transcript_path is not None:
            ui.print_info(f"Transcript (JSONL):  {transcript_path}")
        ui.print_info(
            "Inspect any result:  sectool show "
            f"{config.output_dir}/findings.db <finding_hash> [--model NAME]"
        )
    finally:
        if transcript_writer is not None:
            transcript_writer.close()


@main.command(name="report")
@click.argument("db_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o", "--output", "output_dir", type=click.Path(path_type=Path), required=True
)
def report_cmd(db_path: Path, output_dir: Path) -> None:
    """Re-score and re-render a report from an existing run's database,
    without re-scanning or making any model calls."""
    store = FindingStore(db_path)
    scores = score(store)
    write_report(scores, output_dir)
    store.close()
    ui.print_info(f"Report written to {output_dir}/report.html")


@main.command()
@click.argument("db_path", type=click.Path(exists=True, path_type=Path))
@click.argument("finding_hash")
@click.option("--model", "model_name", default=None, help="Only show this model's attempts.")
def show(db_path: Path, finding_hash: str, model_name: str | None) -> None:
    """Reprint one finding's full prompt/response/patch/verification
    history from a stored run -- the durable way to inspect a result once
    it has scrolled out of the terminal."""
    store = FindingStore(db_path)
    finding = store.get_finding(finding_hash)
    if finding is None:
        ui.print_error(f"No finding with hash '{finding_hash}' in {db_path}.")
        store.close()
        sys.exit(1)

    ui.print_header(f"{finding.file_path}:{finding.line} [{', '.join(finding.cert_rule_ids)}]")
    ui.print_info(finding.message)

    model_names = [model_name] if model_name else store.distinct_model_names()
    latest_per_model = store.latest_verification_per_model(finding_hash)

    for m in model_names:
        attempts = store.attempts_for(finding_hash, m)
        if not attempts:
            continue
        ui.print_header(f"Model: {m}")
        for attempt in attempts:
            ui.console.print(f"[bold]Attempt {attempt.attempt_number}[/bold] ({attempt.created_at})")
            ui.render_prompt(attempt.prompt_text)
            ui.render_response(attempt.raw_model_response, attempt.patch_text)

        if m in latest_per_model:
            result = latest_per_model[m]
            ui.render_verdict(
                resolve_final_status(
                    result.passed, result.target_resolved, bool(result.new_findings)
                ),
                detail=result.detail,
            )

    store.close()


if __name__ == "__main__":
    sys.exit(main())
