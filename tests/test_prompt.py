from sectool.context import OccurrenceSnippet
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
    assert '"action":"propose_fix"' in prompt
    assert "Do not write a unified diff" in prompt


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


def test_source_is_line_numbered_from_context_start():
    prompt = build_fix_prompt(
        finding=make_finding(),
        code_context="void f()\n{\n    strcpy(dst, src);\n}",
        context_file_path="src/a.c",
        context_start_line=40,
    )

    # Real file line numbers in the gutter, so hunk headers can be exact
    # even when the context is a mid-file window.
    assert "   40 | void f()" in prompt
    assert "   42 |     strcpy(dst, src);" in prompt
    assert "lines 40-43" in prompt
    # The model gets authoritative lines but returns exact structured edits.
    assert "line-number gutter" in prompt
    assert "old_text" in prompt
    assert "exact text without line gutters" in prompt


def test_related_occurrences_render_numbered_with_multi_file_allowance():
    prompt = build_fix_prompt(
        finding=make_finding(),
        code_context="void f() {}",
        context_file_path="src/a.c",
        related_occurrences=[
            OccurrenceSnippet(
                file_path="src/b.cpp", start_line=23,
                text="namespace demo__ns\n{\nvoid badSink();\n}",
            ),
            OccurrenceSnippet(
                file_path="main.cpp", start_line=1388,
                text="demo__ns::good();",
            ),
        ],
    )

    assert "Other occurrences of the flagged identifier(s)" in prompt
    assert "### src/b.cpp (lines 23-26)" in prompt
    assert "   23 | namespace demo__ns" in prompt
    assert "### main.cpp (lines 1388-1388)" in prompt
    assert " 1388 | demo__ns::good();" in prompt
    # The model is explicitly allowed (and told) to patch multiple files.
    assert "Structured edits MAY target multiple files" in prompt
    assert "account for ALL syntax" in prompt


def test_no_occurrences_means_no_section():
    prompt = build_fix_prompt(
        finding=make_finding(), code_context="void f() {}", context_file_path="src/a.c"
    )
    assert "Other occurrences" not in prompt


def test_unmapped_finding_states_no_rule_matched():
    finding = make_finding()
    finding.cert_rule_ids = []
    finding.cert_guideline = ""

    prompt = build_fix_prompt(
        finding=finding, code_context="void f() {}", context_file_path="src/a.c"
    )

    assert "none matched" in prompt
