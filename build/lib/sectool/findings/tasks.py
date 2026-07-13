"""Group analyzer reports that share one security root cause."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from sectool.context import identifiers_from_message
from sectool.findings.schema import Finding
from sectool.security_rules import requires_complete_symbol_edit


@dataclass
class FixTask:
    task_id: str
    findings: list[Finding]
    checker_name: str
    symbol: str = ""

    @property
    def primary(self) -> Finding:
        return self.findings[0]


def group_findings(findings: list[Finding]) -> list[FixTask]:
    grouped: dict[tuple[str, str, str, str], list[Finding]] = {}
    for finding in findings:
        symbols = identifiers_from_message(finding.message)
        symbol = (
            symbols[0]
            if symbols and requires_complete_symbol_edit(finding.checker_name)
            else ""
        )
        # Findings without a named root-cause symbol stay location-specific.
        location = "" if symbol else f"{finding.file_path}:{finding.line}"
        taxonomy = finding.primary_evaluation_rule()
        grouped.setdefault(
            (taxonomy, finding.checker_name, symbol, location), []
        ).append(finding)
    tasks = []
    for (taxonomy, checker, symbol, _), members in grouped.items():
        key = symbol or members[0].report_hash
        tasks.append(FixTask(f"{taxonomy}:{checker}:{key}", members, checker, symbol))
    return tasks


def tasks_for_selection(all_findings: list[Finding], selected: list[Finding]) -> list[FixTask]:
    selected_hashes = {finding.report_hash for finding in selected}
    return [
        task for task in group_findings(all_findings)
        if any(member.report_hash in selected_hashes for member in task.findings)
    ]


def filter_findings(
    findings: list[Finding],
    dispatch_filter: str,
    include_checkers: tuple[str, ...] = (),
    exclude_checkers: tuple[str, ...] = (),
) -> list[Finding]:
    """Select the analyzer reports that are valid evaluation tasks.

    Taxonomy filtering and checker filtering are deliberately separate. A
    Juliet path supplies ground-truth CWE metadata, while the checker is the
    concrete analyzer evidence the model must resolve. This prevents support
    code warnings from silently becoming the benchmark just because they were
    emitted in the same scan.
    """
    if dispatch_filter not in {"cert", "cwe", "all"}:
        raise ValueError(f"Unsupported dispatch_filter: {dispatch_filter!r}")

    selected = []
    for finding in findings:
        if dispatch_filter == "cert" and not finding.cert_rule_ids:
            continue
        if dispatch_filter == "cwe" and not finding.cwe_ids:
            continue
        if include_checkers and not any(
            fnmatchcase(finding.checker_name, pattern) for pattern in include_checkers
        ):
            continue
        if any(
            fnmatchcase(finding.checker_name, pattern) for pattern in exclude_checkers
        ):
            continue
        selected.append(finding)
    return selected
