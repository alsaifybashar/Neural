from sectool.findings.schema import Finding, FindingStatus


def make_finding(**overrides) -> Finding:
    defaults = dict(
        report_hash="h1",
        file_path="src/a.c",
        line=1,
        column=1,
        message="msg",
        checker_name="cert-str31-c",
        analyzer_name="clang-tidy",
        severity="HIGH",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_primary_cert_rule_returns_first_rule():
    f = make_finding(cert_rule_ids=["STR31-C", "ARR30-C"])
    assert f.primary_cert_rule() == "STR31-C"


def test_primary_cert_rule_unmapped_when_empty():
    f = make_finding(cert_rule_ids=[])
    assert f.primary_cert_rule() == "UNMAPPED"


def test_default_status_is_open():
    f = make_finding()
    assert f.status == FindingStatus.OPEN
