"""Wraps the `CodeChecker log|analyze|parse` CLI pipeline.

Three CodeChecker CLI stages, run in order:

  1. `CodeChecker log -o compile_commands.json -b "<build_command>"`
     Records the real build's compiler invocations into a JSON Compilation
     Database. Must be a full/clean build or files that weren't compiled
     are invisible to CodeChecker.

  2. `CodeChecker analyze compile_commands.json -o <reports_dir>
      -e guideline:sei-cert-c -e guideline:sei-cert-cpp`
     Runs the underlying analyzers (Clang Static Analyzer, clang-tidy,
     cppcheck, ...) restricted to checkers covering the SEI CERT C/C++
     guidelines, writing one .plist per translation unit into reports_dir.
     (`-e guideline:<name>` is CodeChecker's documented namespaced-enable
     syntax -- see `CodeChecker analyze --help`.)

  3. `CodeChecker parse <reports_dir> --export json -o <reports.json>`
     Converts the .plist files into the JSON schema implemented by
     `Report.to_json()` in CodeChecker's own source
     (tools/report-converter/codechecker_report_converter/report/
     __init__.py), which is what `parse_report_json` below decodes:

        {
          "version": 1,
          "reports": [
            {
              "file": {"id": ..., "path": ..., "original_path": ...},
              "line": int, "column": int, "message": str,
              "checker_name": str, "severity": str, "report_hash": str,
              "analyzer_name": str,
              "bug_path_events": [{"file": ..., "line": ..., "column": ...,
                                    "message": ...}, ...],
              ...
            }
          ]
        }

This module only shells out to CodeChecker and reshapes its output; it does
not itself know which checker maps to which CERT rule -- that join is done
by `sectool.scanner.cert_mapping.CertRuleMapper` in `Scanner.scan()`.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sectool.findings.schema import BugPathEvent, Finding
from sectool.scanner.cert_mapping import CertRuleMapper, DEFAULT_CERT_GUIDELINES


class ScanError(RuntimeError):
    """Raised when a CodeChecker CLI stage exits non-zero or emits output
    this module can't parse. Kept distinct from a bare CalledProcessError
    so callers see the stage name and captured stderr in one message."""


@dataclass
class ScanResult:
    """Output of a full scan: every CERT-relevant finding, plus how many
    total findings CodeChecker reported before CERT filtering (useful for
    sanity-checking that the guideline filter isn't silently dropping
    everything, e.g. because of a typo'd guideline name)."""

    findings: list[Finding]
    total_reports_before_filter: int
    reports_json_path: Path


class Scanner:
    """Runs CodeChecker against a project and returns CERT-tagged findings."""

    def __init__(
        self,
        project_root: Path,
        workdir: Path,
        codechecker_bin: str = "CodeChecker",
        cert_guidelines: tuple[str, ...] = DEFAULT_CERT_GUIDELINES,
        cert_mapper: CertRuleMapper | None = None,
    ):
        self.project_root = Path(project_root)
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.codechecker_bin = codechecker_bin
        self.cert_guidelines = cert_guidelines
        self.cert_mapper = cert_mapper or CertRuleMapper(
            codechecker_bin=codechecker_bin,
            guidelines=cert_guidelines,
            cache_path=self.workdir / "cert_rule_map.json",
        )

    def scan(self, build_command: str, only_cert_findings: bool = True) -> ScanResult:
        """Run the full log -> analyze -> parse pipeline and return
        CERT-tagged Findings.

        `only_cert_findings=False` keeps every finding CodeChecker reports
        (still CERT-tagged where applicable) instead of dropping the ones
        outside the configured guidelines -- useful for the Verifier's
        post-patch re-scan, which needs to see *any* new finding a patch
        introduces, not just CERT ones, to judge regressions correctly.
        """
        compile_db = self._log(build_command)
        reports_dir = self._analyze(compile_db)
        reports_json = self._parse(reports_dir)

        raw = json.loads(reports_json.read_text())
        all_reports = raw.get("reports", [])
        findings = parse_report_json(raw, self.cert_mapper)

        if only_cert_findings:
            findings = [f for f in findings if f.cert_rule_ids]

        return ScanResult(
            findings=findings,
            total_reports_before_filter=len(all_reports),
            reports_json_path=reports_json,
        )

    def _log(self, build_command: str) -> Path:
        compile_db = self.workdir / "compile_commands.json"
        self._run(
            ["log", "-o", str(compile_db), "-b", build_command],
            stage="log",
            cwd=self.project_root,
        )
        if not compile_db.exists():
            raise ScanError(
                "CodeChecker log did not produce a compilation database at "
                f"{compile_db}; check that build_command actually invokes "
                "the compiler."
            )
        return compile_db

    def _analyze(self, compile_db: Path) -> Path:
        reports_dir = self.workdir / "reports"
        args = ["analyze", str(compile_db), "-o", str(reports_dir), "--clean"]
        for guideline in self.cert_guidelines:
            args += ["-e", f"guideline:{guideline}"]
        self._run(args, stage="analyze", cwd=self.project_root)
        return reports_dir

    def _parse(self, reports_dir: Path) -> Path:
        reports_json = self.workdir / "reports.json"
        self._run(
            ["parse", str(reports_dir), "--export", "json", "-o", str(reports_json)],
            stage="parse",
            cwd=self.project_root,
            # `CodeChecker parse` exits non-zero when findings are present
            # (its exit code communicates "were there any reports", not
            # "did parsing fail") -- so unlike log/analyze we don't treat a
            # non-zero exit here as an error.
            check_exit_code=False,
        )
        if not reports_json.exists():
            raise ScanError(
                f"CodeChecker parse did not produce {reports_json}"
            )
        return reports_json

    def _run(
        self,
        args: list[str],
        stage: str,
        cwd: Path,
        check_exit_code: bool = True,
    ) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            [self.codechecker_bin, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        if check_exit_code and proc.returncode != 0:
            raise ScanError(
                f"'CodeChecker {stage}' failed (exit {proc.returncode}):\n"
                f"{proc.stderr}"
            )
        return proc


def parse_report_json(raw: dict, cert_mapper: CertRuleMapper) -> list[Finding]:
    """Decode CodeChecker's `parse --export json` output into Findings,
    tagging each with its SEI CERT rule id(s) via `cert_mapper`.

    Pure/offline: takes already-loaded JSON and an already-buildable
    mapper, so it can be exercised in tests against a canned fixture
    without CodeChecker installed (see tests/test_scanner_parsing.py).
    """
    findings: list[Finding] = []
    for report in raw.get("reports", []):
        checker_name = report["checker_name"]
        guideline, rule_ids = cert_mapper.rules_for(checker_name)

        bug_path_events = [
            BugPathEvent(
                file_path=event["file"]["path"],
                line=event["line"],
                column=event["column"],
                message=event["message"],
            )
            for event in report.get("bug_path_events", [])
        ]

        findings.append(
            Finding(
                report_hash=report["report_hash"],
                file_path=report["file"]["path"],
                line=report["line"],
                column=report["column"],
                message=report["message"],
                checker_name=checker_name,
                analyzer_name=report.get("analyzer_name") or "",
                severity=report.get("severity") or "UNSPECIFIED",
                cert_rule_ids=rule_ids,
                cert_guideline=guideline,
                bug_path_events=bug_path_events,
            )
        )
    return findings
