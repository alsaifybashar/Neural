"""Builds the prompt sent to every model for a given fix attempt.

Centralizing this is what makes the model comparison meaningful: every
adapter (Anthropic, OpenAI, Ollama, ...) is handed the *exact same* prompt
text for a given (finding, attempt) pair. If each adapter built its own
prompt, differences in fix quality could just be differences in prompting
rather than differences in model capability -- and the entire point of
this tool is to compare models, not prompt styles.
"""

from __future__ import annotations

from sectool.findings.schema import Finding

_INSTRUCTIONS = """\
You are a secure coding assistant fixing a single static-analysis finding \
in a C/C++ codebase. The finding was raised by CodeChecker and maps to a \
SEI CERT C/C++ Coding Standard rule.

Requirements for your fix:
1. Produce the SMALLEST change that resolves the finding. Do not refactor, \
rename, reformat, or "improve" unrelated code.
2. Preserve the existing function's behavior and public signature unless \
the vulnerability makes that impossible.
3. Do not introduce new dependencies, macros, or files.
4. Respond with ONLY a unified diff (git-style, starting with `--- a/...` \
and `+++ b/...` headers) inside a single ```diff fenced code block. Do not \
include any explanation before or after the diff.
"""


def build_fix_prompt(
    finding: Finding,
    code_context: str,
    context_file_path: str,
    prior_feedback: str | None = None,
) -> str:
    """Assemble the full prompt text for one fix attempt.

    `code_context` is the source of the function/file containing the
    finding (see verifier/build.py or the dispatcher for how much
    surrounding code is included -- deliberately just the flagged
    function/file, not the whole project, per the tool's design: patches
    should be scoped and attributable to a single finding).

    `prior_feedback`, when set, is the previous attempt's verification
    failure (compiler error, failing test, or newly introduced finding)
    and turns this into a retry prompt instead of a first attempt.
    """
    rule_line = (
        f"SEI CERT rule(s): {', '.join(finding.cert_rule_ids)} "
        f"({finding.cert_guideline})"
        if finding.cert_rule_ids
        else "SEI CERT rule(s): none matched"
    )

    trace_lines = "\n".join(
        f"  {i + 1}. {e.file_path}:{e.line}:{e.column} - {e.message}"
        for i, e in enumerate(finding.bug_path_events)
    ) or "  (no bug path trace reported)"

    parts = [
        _INSTRUCTIONS,
        "## Finding",
        f"Checker: {finding.checker_name} (analyzer: {finding.analyzer_name})",
        rule_line,
        f"Severity: {finding.severity}",
        f"Location: {finding.file_path}:{finding.line}:{finding.column}",
        f"Message: {finding.message}",
        "",
        "## Analyzer trace (source-to-sink path)",
        trace_lines,
        "",
        f"## Source ({context_file_path})",
        "```c",
        code_context,
        "```",
    ]

    if prior_feedback:
        parts += [
            "",
            "## Your previous attempt was rejected",
            "The following verification failure occurred. Fix this while "
            "still resolving the original finding above:",
            prior_feedback,
        ]

    return "\n".join(parts)
