from sectool.findings.schema import BugPathEvent, Finding
from sectool.models.prompt import build_fix_prompt


def make_finding() -> Finding:
    return Finding(
        report_hash="h1",
        file_path="src/a.c",
        line=42,
        column=5,
        message="Call to strcpy is insecure",
        checker_name="cert-str31-c",
        analyzer_name="clang-tidy",
        severity="HIGH",
        cert_rule_ids=["STR31-C"],
        cert_guideline="sei-cert-c",
        bug_path_events=[BugPathEvent("src/a.c", 40, 3, "'buf' declared here")],
    )


def test_prompt_includes_cert_rule_and_location():
    prompt = build_fix_prompt(
        finding=make_finding(), code_context="void f() {}", context_file_path="src/a.c"
    )

    assert "STR31-C" in prompt
    assert "sei-cert-c" in prompt
    assert "src/a.c:42:5" in prompt
    assert "'buf' declared here" in prompt
    assert "```diff" in prompt  # instructs the required output format


def test_prompt_without_prior_feedback_has_no_retry_section():
    prompt = build_fix_prompt(
        finding=make_finding(), code_context="void f() {}", context_file_path="src/a.c"
    )

    assert "previous attempt was rejected" not in prompt


def test_prompt_with_prior_feedback_includes_retry_section():
    prompt = build_fix_prompt(
        finding=make_finding(),
        code_context="void f() {}",
        context_file_path="src/a.c",
        prior_feedback="Build failed: undefined reference to `strcpy`",
    )

    assert "previous attempt was rejected" in prompt
    assert "undefined reference" in prompt


def test_unmapped_finding_states_no_rule_matched():
    finding = make_finding()
    finding.cert_rule_ids = []
    finding.cert_guideline = ""

    prompt = build_fix_prompt(
        finding=finding, code_context="void f() {}", context_file_path="src/a.c"
    )

    assert "none matched" in prompt
