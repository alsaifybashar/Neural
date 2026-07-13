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

PROMPT_PROTOCOL_VERSION = "security-repair-v2"

_INSTRUCTIONS = """\
You are resolving one concrete security root-cause task in a C/C++ codebase. \
CodeChecker supplied the analyzer evidence. The task may also carry CWE \
benchmark ground truth and/or SEI CERT rule metadata; use those labels to \
understand the intended weakness class, then confirm the actual data flow and \
unsafe operation in the supplied source before editing.

Requirements:
1. Investigate until you have enough authoritative source to make one coherent \
change. If a name, signature, or declaration changes, account for ALL syntax \
references, including later references in the same file.
2. Remove the unsafe behavior while preserving intended non-vulnerable behavior, \
testcase structure, and public signatures where possible. Do not preserve the \
vulnerability merely to keep output identical.
3. Do not introduce new dependencies, macros, files, analyzer suppressions, or \
warning-disable pragmas. The weakness must be repaired in executable source.
4. Respond with ONLY one JSON object. Do not write a unified diff.

Before the final proposal you may request one tool action per response:
{"action":"search_symbol","symbol":"name","offset":0}
{"action":"read_range","path":"repo/relative.cpp","start_line":1,"end_line":80}
{"action":"read_definition","path":"repo/relative.cpp","line":42}
{"action":"inspect_build","path":"repo/relative.cpp"}

When ready, return:
{"action":"propose_fix","root_cause":"...","edits":[{"path":"...",\
"old_text":"exact text without line gutters","new_text":"replacement",\
"expected_occurrences":1,"context_ids":["path:line"]}],\
"occurrence_dispositions":[{"context_id":"path:line","disposition":"edited|unchanged",\
"reason":"..."}]}

Every search result must have a disposition. If search results are truncated, \
request the next page before proposing a symbol rename. The host validates exact \
text and generates the unified diff deterministically.
"""


def _numbered(code_context: str, start_line: int) -> str:
    """Renders source with the `N | ` gutter the instructions describe, so
    the model can write hunk headers against the file's real line numbers
    instead of guessing them from an unnumbered (and possibly mid-file)
    window -- guessed numbers are the main way model diffs fail to apply."""
    return "\n".join(
        f"{start_line + i:>5} | {line}"
        for i, line in enumerate(code_context.splitlines())
    )


def build_fix_prompt(
    finding: Finding,
    code_context: str,
    context_file_path: str,
    prior_feedback: str | None = None,
    context_start_line: int = 1,
    related_occurrences: list = (),
    compile_command: str = "",
    context_truncated: bool = False,
    task_findings: list[Finding] = (),
    remediation_guidance: str = "",
    tool_history: list[dict] = (),
    context_round: int = 0,
    max_context_rounds: int = 4,
) -> str:
    """Assemble the full prompt text for one fix attempt.

    `code_context` is the source of the function/file containing the
    finding (see verifier/build.py or the dispatcher for how much
    surrounding code is included -- deliberately just the flagged
    function/file, not the whole project, per the tool's design: patches
    should be scoped and attributable to a single finding).
    `context_start_line` is the 1-indexed file line the context starts at,
    so the numbered gutter shows real file line numbers even when the
    context is a mid-file window.

    `context_file_path` is the repo-relative source identity used by context
    tools and structured edits, not necessarily CodeChecker's absolute path.

    `related_occurrences` (list of sectool.context.OccurrenceSnippet) are
    places elsewhere in the project that reference an identifier the
    finding names -- shown so a fix that renames a declaration can update
    every reference in one multi-file diff instead of failing the build.

    `prior_feedback`, when set, is the previous attempt's verification
    failure (compiler error, failing test, or newly introduced finding)
    and turns this into a retry prompt instead of a first attempt.
    """
    cert_line = (
        f"SEI CERT rule(s): {', '.join(finding.cert_rule_ids)} "
        f"({finding.cert_guideline})"
        if finding.cert_rule_ids
        else "SEI CERT rule(s): none matched"
    )
    cwe_line = (
        f"Benchmark weakness: {', '.join(finding.cwe_ids)}"
        + (f" ({finding.cwe_name})" if finding.cwe_name else "")
        if finding.cwe_ids
        else "Benchmark weakness: none supplied"
    )

    trace_lines = "\n".join(
        f"  {i + 1}. {e.file_path}:{e.line}:{e.column} - {e.message}"
        for i, e in enumerate(finding.bug_path_events)
    ) or "  (no bug path trace reported)"

    parts = [
        _INSTRUCTIONS,
        "## Finding",
        f"Prompt protocol: {PROMPT_PROTOCOL_VERSION}",
        f"Checker: {finding.checker_name} (analyzer: {finding.analyzer_name})",
        cwe_line,
        cert_line,
        f"Severity: {finding.severity}",
        f"Location: {finding.file_path}:{finding.line}:{finding.column}",
        f"Message: {finding.message}",
        "",
    ]
    if task_findings:
        parts += [
            "## Grouped target locations",
            *[
                f"- {item.report_hash}: {item.file_path}:{item.line}:{item.column} "
                f"[{item.primary_evaluation_rule()}] - {item.message}"
                for item in task_findings
            ],
            "",
        ]
    if remediation_guidance:
        parts += ["## Reviewed remediation guidance", remediation_guidance, ""]
    if compile_command:
        parts += [
            "## Translation-unit compile command",
            compile_command,
            "",
        ]
    parts += [
        "## Analyzer trace (source-to-sink path)",
        trace_lines,
        "",
        f"## Source ({context_file_path}, lines "
        f"{context_start_line}-{context_start_line + max(len(code_context.splitlines()) - 1, 0)}, "
        f"shown with a line-number gutter)",
        "```c",
        _numbered(code_context, context_start_line),
        "```",
    ]

    if related_occurrences:
        parts += [
            "",
            "## Other occurrences of the flagged identifier(s) and related project context",
            "If your fix renames or changes a declaration, it must also "
            "update every reference shown below -- otherwise the project "
            "will not compile. Structured edits MAY target multiple files; "
            "use each snippet's exact repo-relative path and omit the gutter "
            "from old_text/new_text.",
        ]
        for occ in related_occurrences:
            end_line = occ.start_line + max(len(occ.text.splitlines()) - 1, 0)
            parts += [
                "",
                f"### {occ.file_path} (lines {occ.start_line}-{end_line}) "
                f"[{getattr(occ, 'relationship', 'identifier reference')}]",
                "```c",
                _numbered(occ.text, occ.start_line),
                "```",
            ]

    if context_truncated:
        parts += [
            "",
            "Context collection reached its configured limit. Do not modify "
            "symbols whose complete set of references is not shown.",
        ]

    if tool_history:
        parts += ["", "## Context-tool transcript"]
        for entry in tool_history:
            parts += [
                f"### Round {entry.get('round', '?')}",
                f"Request: {entry.get('request', {})}",
                f"Result: {entry.get('result', '')}",
            ]
    parts += [
        "",
        f"Context round: {context_round}/{max_context_rounds}. ",
        "Return `propose_fix` now if the round limit has been reached.",
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
