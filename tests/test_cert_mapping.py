"""Tests for the checker-name -> SEI CERT rule mapping logic.

Exercises `parse_checker_listing`, the pure function extracted specifically
so this mapping logic can be verified against a canned
`CodeChecker checkers --guideline ... --details -o json` fixture without
CodeChecker installed (see sectool/scanner/cert_mapping.py's docstring for
where that JSON shape was verified against CodeChecker's own source).
"""

import json
from pathlib import Path

from sectool.scanner.cert_mapping import CertRuleMapper, parse_checker_listing

FIXTURES = Path(__file__).parent / "fixtures"


def load_checkers_listing() -> list[dict]:
    return json.loads((FIXTURES / "sample_checkers_listing.json").read_text())


def test_parse_checker_listing_extracts_rule_ids():
    checkers = load_checkers_listing()

    result = parse_checker_listing(checkers, guideline="sei-cert-c")

    assert result == {
        "cert-err34-c": ["ERR34-C"],
        "cert-str31-c": ["STR31-C"],
    }


def test_parse_checker_listing_respects_guideline_prefix():
    checkers = load_checkers_listing()

    result = parse_checker_listing(checkers, guideline="sei-cert-cpp")

    assert result == {"bugprone-exception-escape": ["MSC53-CPP"]}
    # The two sei-cert-c checkers must not leak into the cpp guideline.
    assert "cert-err34-c" not in result
    assert "cert-str31-c" not in result


def test_cert_rule_mapper_uses_cache_without_invoking_codechecker(tmp_path):
    cache_path = tmp_path / "cert_rule_map.json"
    cache_path.write_text(
        json.dumps(
            {
                "cert-str31-c": {"guideline": "sei-cert-c", "rule_ids": ["STR31-C"]},
            }
        )
    )

    mapper = CertRuleMapper(
        codechecker_bin="this-binary-does-not-exist",
        cache_path=cache_path,
    )

    guideline, rule_ids = mapper.rules_for("cert-str31-c")

    assert guideline == "sei-cert-c"
    assert rule_ids == ["STR31-C"]


def test_cert_rule_mapper_unmapped_checker_returns_empty(tmp_path):
    cache_path = tmp_path / "cert_rule_map.json"
    cache_path.write_text(json.dumps({}))

    mapper = CertRuleMapper(cache_path=cache_path)

    guideline, rule_ids = mapper.rules_for("some-unrelated-checker")

    assert guideline == ""
    assert rule_ids == []
