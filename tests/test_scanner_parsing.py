"""Tests for decoding `CodeChecker parse --export json` output into
Findings, using a canned fixture instead of a real CodeChecker run (see
sectool/scanner/codechecker.py's docstring for where this JSON schema was
verified against CodeChecker's own Report.to_json() source).
"""

import json
from pathlib import Path

from sectool.scanner.cert_mapping import CertRuleMapper
from sectool.scanner.codechecker import cwe_metadata_from_path, parse_report_json

FIXTURES = Path(__file__).parent / "fixtures"


def make_mapper(tmp_path) -> CertRuleMapper:
    """A CertRuleMapper pre-loaded with a fixed mapping, so this test
    never shells out to the real CodeChecker binary."""
    cache_path = tmp_path / "cert_rule_map.json"
    cache_path.write_text(
        json.dumps(
            {
                "cert-str31-c": {"guideline": "sei-cert-c", "rule_ids": ["STR31-C"]},
                "cert-err34-c": {"guideline": "sei-cert-c", "rule_ids": ["ERR34-C"]},
            }
        )
    )
    return CertRuleMapper(cache_path=cache_path)


def test_parse_report_json_produces_one_finding_per_report(tmp_path):
    raw = json.loads((FIXTURES / "sample_codechecker_report.json").read_text())
    mapper = make_mapper(tmp_path)

    findings = parse_report_json(raw, mapper)

    assert len(findings) == 3
    assert {f.report_hash for f in findings} == {
        "hash-str31c-main-42",
        "hash-err34c-parse-17",
        "hash-deadstores-util-8",
    }


def test_cert_covered_findings_are_tagged_with_rule_ids(tmp_path):
    raw = json.loads((FIXTURES / "sample_codechecker_report.json").read_text())
    mapper = make_mapper(tmp_path)

    findings = {f.report_hash: f for f in parse_report_json(raw, mapper)}

    str31c = findings["hash-str31c-main-42"]
    assert str31c.cert_rule_ids == ["STR31-C"]
    assert str31c.cert_guideline == "sei-cert-c"
    assert str31c.primary_cert_rule() == "STR31-C"
    assert str31c.file_path == "src/main.c"
    assert str31c.line == 42
    assert len(str31c.bug_path_events) == 2
    assert str31c.bug_path_events[0].message == "'buf' declared here with size 16"


def test_non_cert_finding_has_no_rule_ids(tmp_path):
    raw = json.loads((FIXTURES / "sample_codechecker_report.json").read_text())
    mapper = make_mapper(tmp_path)

    findings = {f.report_hash: f for f in parse_report_json(raw, mapper)}

    dead_stores = findings["hash-deadstores-util-8"]
    assert dead_stores.cert_rule_ids == []
    assert dead_stores.primary_cert_rule() == "UNMAPPED"


def test_scanner_only_cert_findings_filter_matches_manual_filter(tmp_path):
    raw = json.loads((FIXTURES / "sample_codechecker_report.json").read_text())
    mapper = make_mapper(tmp_path)

    findings = parse_report_json(raw, mapper)
    cert_only = [f for f in findings if f.cert_rule_ids]

    assert len(cert_only) == 2
    assert all(f.cert_rule_ids for f in cert_only)


def test_juliet_path_supplies_separate_cwe_ground_truth(tmp_path):
    raw = json.loads((FIXTURES / "sample_codechecker_report.json").read_text())
    raw["reports"][0]["file"]["path"] = (
        "C/testcases/CWE121_Stack_Based_Buffer_Overflow/"
        "CWE121_demo__bad.c"
    )

    finding = parse_report_json(raw, make_mapper(tmp_path))[0]

    assert finding.cwe_ids == ["CWE-121"]
    assert finding.cwe_name == "Stack Based Buffer Overflow"
    assert finding.cert_rule_ids == ["STR31-C"]
    assert finding.primary_evaluation_rule() == "CWE-121"


def test_cwe_filename_inference_can_be_disabled(tmp_path):
    raw = json.loads((FIXTURES / "sample_codechecker_report.json").read_text())
    raw["reports"][0]["file"]["path"] = "CWE121_Buffer_Overflow/example.c"
    finding = parse_report_json(
        raw, make_mapper(tmp_path), cwe_from_filename=False
    )[0]
    assert finding.cwe_ids == []


def test_cwe_metadata_strips_juliet_flow_variant_suffix():
    assert cwe_metadata_from_path("CWE121_Stack_Based_Buffer_Overflow__01.c") == (
        ["CWE-121"], "Stack Based Buffer Overflow"
    )
