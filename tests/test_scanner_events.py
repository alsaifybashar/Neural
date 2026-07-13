"""Tests the Scanner's stage events -- in particular the end-of-stage
summaries (compiler invocations recorded, report files produced, findings
parsed) -- by faking the CodeChecker subprocess so each stage produces the
artifacts the real CLI would, without CodeChecker installed."""

import json

import pytest

from sectool.scanner.cert_mapping import CertRuleMapper
from sectool.scanner.codechecker import Scanner


REPORT = {
    "file": {"id": 1, "path": "src/a.c", "original_path": "src/a.c"},
    "line": 3, "column": 1, "message": "strcpy is unsafe",
    "checker_name": "cert-str31-c", "severity": "HIGH",
    "report_hash": "h1", "analyzer_name": "clang-tidy",
    "bug_path_events": [],
}


class StaticMapper(CertRuleMapper):
    """Maps every checker to one CERT rule without shelling out."""

    def __init__(self):
        pass

    def rules_for(self, checker_name):
        return "sei-cert-c", ["STR31-C"]


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    scanner = Scanner(
        project_root=tmp_path,
        workdir=tmp_path / "work",
        cert_mapper=StaticMapper(),
    )

    def fake_run(args, stage, cwd, check_exit_code=True):
        # Produce exactly the artifact each real CodeChecker stage would.
        if stage == "log":
            (scanner.workdir / "compile_commands.json").write_text(
                json.dumps([{"command": "gcc a.c"}, {"command": "gcc b.c"}])
            )
        elif stage == "analyze":
            reports_dir = scanner.workdir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            (reports_dir / "a.c_clang-tidy.plist").write_text("<plist/>")
        elif stage == "parse":
            (scanner.workdir / "reports.json").write_text(
                json.dumps({"version": 1, "reports": [REPORT]})
            )

    monkeypatch.setattr(scanner, "_run", fake_run)
    return scanner


def test_scan_emits_stage_summaries(scanner):
    events = []
    result = scanner.scan("make", on_event=events.append)

    by_stage = {(e.stage, e.status): e for e in events}
    log_done = by_stage[("scan.log", "done")]
    assert log_done.data["compile_commands"] == 2
    assert "2 compiler invocation(s)" in log_done.data["summary"]

    analyze_done = by_stage[("scan.analyze", "done")]
    assert analyze_done.data["report_files"] == 1
    assert "1 analyzer report file(s)" in analyze_done.data["summary"]

    parse_done = by_stage[("scan.parse", "done")]
    assert parse_done.data["total_reports"] == 1
    assert "1 raw finding(s) parsed" in parse_done.data["summary"]

    assert result.total_reports_before_filter == 1
    assert result.findings[0].cert_rule_ids == ["STR31-C"]


def test_scan_stage_order(scanner):
    events = []
    scanner.scan("make", on_event=events.append)
    assert [(e.stage, e.status) for e in events] == [
        ("scan.log", "start"), ("scan.log", "done"),
        ("scan.analyze", "start"), ("scan.analyze", "done"),
        ("scan.parse", "start"), ("scan.parse", "done"),
    ]


def test_undecodable_parse_output_is_scan_error(scanner, monkeypatch):
    from sectool.scanner.codechecker import ScanError

    original = scanner._run

    def corrupting_run(args, stage, cwd, check_exit_code=True):
        original(args, stage, cwd, check_exit_code)
        if stage == "parse":
            (scanner.workdir / "reports.json").write_text("not json{")

    monkeypatch.setattr(scanner, "_run", corrupting_run)
    events = []
    with pytest.raises(ScanError):
        scanner.scan("make", on_event=events.append)
    assert events[-1].stage == "scan.parse" and events[-1].status == "error"


def test_analyze_passes_configured_checker_enables(tmp_path, monkeypatch):
    scanner = Scanner(
        project_root=tmp_path,
        workdir=tmp_path / "work",
        cert_mapper=StaticMapper(),
        checker_enables=("profile:security", "checkers:security.ArrayBound"),
    )
    captured = {}

    def fake_run(args, stage, cwd, check_exit_code=True):
        captured["args"] = args
        (scanner.workdir / "reports").mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(scanner, "_run", fake_run)
    scanner._analyze(tmp_path / "compile_commands.json", None)

    args = captured["args"]
    assert ["-e", "profile:security"] == args[-4:-2]
    assert ["-e", "checkers:security.ArrayBound"] == args[-2:]
