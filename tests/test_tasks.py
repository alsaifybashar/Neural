from sectool.findings.schema import Finding
from sectool.findings.tasks import filter_findings, group_findings


def finding(report_hash, checker, *, cwe_ids=(), cert_rule_ids=()):
    return Finding(
        report_hash=report_hash,
        file_path=f"src/{report_hash}.c",
        line=1,
        column=1,
        message="out of bounds access",
        checker_name=checker,
        analyzer_name="clangsa",
        severity="HIGH",
        cwe_ids=list(cwe_ids),
        cert_rule_ids=list(cert_rule_ids),
    )


def test_cwe_dispatch_filter_and_checker_patterns_are_both_required():
    findings = [
        finding("target", "security.ArrayBound", cwe_ids=["CWE-121"]),
        finding("noise", "clang-diagnostic-unused-parameter", cwe_ids=["CWE-121"]),
        finding("support", "security.ArrayBound"),
    ]

    selected = filter_findings(
        findings, "cwe", include_checkers=("security.*",)
    )

    assert [item.report_hash for item in selected] == ["target"]


def test_tasks_with_different_cwe_ground_truth_are_not_grouped():
    first = finding("one", "security.ArrayBound", cwe_ids=["CWE-121"])
    second = finding("two", "security.ArrayBound", cwe_ids=["CWE-122"])
    assert len(group_findings([first, second])) == 2
