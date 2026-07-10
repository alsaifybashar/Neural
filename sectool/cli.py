"""`sectool` command line entrypoint.

Three subcommands, matching the pipeline stages a user is likely to want
to run independently while iterating (e.g. re-check that scanning finds
the expected CERT findings before spending API budget on model calls):

    sectool scan   <config>  - run CodeChecker only; report matched findings.
    sectool run    <config>  - full pipeline: scan, dispatch to every
                                configured model with retries, verify, score.
    sectool report <db> -o <dir> - re-score and re-render a report from an
                                    existing run's database, with no
                                    re-scanning or model calls.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from sectool.config import RunConfig
from sectool.dispatcher import Dispatcher
from sectool.findings.store import FindingStore
from sectool.models.registry import build_adapter
from sectool.report import write_report
from sectool.scanner.cert_mapping import CertRuleMapper
from sectool.scanner.codechecker import Scanner
from sectool.scorer import score
from sectool.verifier.verifier import Verifier

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
    """Run CodeChecker and report how many SEI CERT findings were found,
    without dispatching anything to a model. Useful for validating a
    project's build_command/CERT guideline config cheaply."""
    config = RunConfig.from_file(config_path)
    scanner = Scanner(
        project_root=config.project.root,
        workdir=config.output_dir / "scan",
        cert_guidelines=config.cert_guidelines,
    )
    result = scanner.scan(config.project.build_command, only_cert_findings=False)
    cert_findings = [f for f in result.findings if f.cert_rule_ids]

    click.echo(
        f"{result.total_reports_before_filter} total findings, "
        f"{len(cert_findings)} matched SEI CERT guidelines "
        f"{config.cert_guidelines}."
    )
    for f in cert_findings[:20]:
        click.echo(
            f"  {f.file_path}:{f.line} [{', '.join(f.cert_rule_ids)}] "
            f"{f.checker_name}: {f.message}"
        )
    if len(cert_findings) > 20:
        click.echo(f"  ... and {len(cert_findings) - 20} more.")


@main.command()
@click.argument("config_path", type=click.Path(exists=True, path_type=Path))
def run(config_path: Path) -> None:
    """Run the full scan -> dispatch -> verify -> score -> report pipeline."""
    config = RunConfig.from_file(config_path)
    config.output_dir.mkdir(parents=True, exist_ok=True)

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

    click.echo("Scanning with CodeChecker...")
    scan_result = scanner.scan(config.project.build_command, only_cert_findings=False)
    baseline_findings = scan_result.findings
    dispatch_targets = [f for f in baseline_findings if f.cert_rule_ids]
    if config.finding_limit is not None:
        dispatch_targets = dispatch_targets[: config.finding_limit]

    click.echo(
        f"{scan_result.total_reports_before_filter} total findings, "
        f"dispatching {len(dispatch_targets)} SEI CERT findings to "
        f"{len(config.models)} model(s)."
    )

    store = FindingStore(config.output_dir / "findings.db")
    for finding in dispatch_targets:
        store.upsert_finding(finding)

    verifier = Verifier(project=config.project, cert_mapper=cert_mapper)
    dispatcher = Dispatcher(
        store=store,
        verifier=verifier,
        project=config.project,
        max_attempts=config.max_attempts_per_finding,
    )

    for model_config in config.models:
        click.echo(f"-- Model: {model_config.name} --")
        adapter = build_adapter(model_config)
        for i, finding in enumerate(dispatch_targets, start=1):
            status = dispatcher.run_finding(
                finding=finding,
                model_name=model_config.name,
                adapter=adapter,
                baseline_findings=baseline_findings,
            )
            click.echo(
                f"  [{i}/{len(dispatch_targets)}] {finding.file_path}:"
                f"{finding.line} ({finding.primary_cert_rule()}) -> {status.value}"
            )

    scores = score(store)
    write_report(scores, config.output_dir)
    store.close()

    click.echo(f"\nReport written to {config.output_dir}/report.html")
    for model_name, s in scores.items():
        click.echo(
            f"  {model_name}: fix_rate={s.fix_rate:.1%} "
            f"regression_rate={s.regression_rate:.1%} "
            f"(fixed {s.fixed}/{s.total}, regressed {s.regressed})"
        )


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
    click.echo(f"Report written to {output_dir}/report.html")


if __name__ == "__main__":
    sys.exit(main())
