"""Group analyzer reports that share one security root cause."""

from __future__ import annotations

from dataclasses import dataclass

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
    grouped: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        symbols = identifiers_from_message(finding.message)
        symbol = (
            symbols[0]
            if symbols and requires_complete_symbol_edit(finding.checker_name)
            else ""
        )
        # Findings without a named root-cause symbol stay location-specific.
        location = "" if symbol else f"{finding.file_path}:{finding.line}"
        grouped.setdefault((finding.checker_name, symbol, location), []).append(finding)
    tasks = []
    for (checker, symbol, _), members in grouped.items():
        key = symbol or members[0].report_hash
        tasks.append(FixTask(f"{checker}:{key}", members, checker, symbol))
    return tasks


def tasks_for_selection(all_findings: list[Finding], selected: list[Finding]) -> list[FixTask]:
    selected_hashes = {finding.report_hash for finding in selected}
    return [
        task for task in group_findings(all_findings)
        if any(member.report_hash in selected_hashes for member in task.findings)
    ]
