"""Tests the function-boundary heuristic used to scope what source a model
sees for a given finding (see sectool/context.py's docstring for why this
is a heuristic rather than a real parse), and the cross-file identifier
occurrence search that lets fixes span every affected file."""

from sectool.context import (
    build_dependency_context,
    extract_code_context,
    find_identifier_occurrences,
    identifier_at_location,
    identifiers_from_message,
)


def test_short_file_returns_whole_file(tmp_path):
    path = tmp_path / "small.c"
    path.write_text("int main() {\n    return 0;\n}\n")

    ctx = extract_code_context(path, line=2)

    assert ctx.is_whole_file
    assert ctx.start_line == 1
    assert "return 0" in ctx.text


def _padding_function(name: str, n_lines: int = 4) -> str:
    body = "\n".join(f"    int {name}_local_{i} = {i};" for i in range(n_lines))
    return f"void {name}(void) {{\n{body}\n}}\n"


def test_long_file_extracts_enclosing_function(tmp_path):
    # Build a file well over the whole-file threshold, with a clearly
    # identifiable target function buried in the middle.
    padding_before = "\n".join(_padding_function(f"before_{i}") for i in range(20))
    target = (
        "void bad_copy_username(const char *input) {\n"
        "    char buf[16];\n"
        "    strcpy(buf, input);\n"
        "    printf(\"user: %s\\n\", buf);\n"
        "}\n"
    )
    padding_after = "\n".join(_padding_function(f"after_{i}") for i in range(20))
    path = tmp_path / "big.c"
    path.write_text(padding_before + "\n" + target + "\n" + padding_after)

    target_line = padding_before.count("\n") + 1 + 3  # the strcpy() line
    ctx = extract_code_context(path, line=target_line)

    assert not ctx.is_whole_file
    assert "bad_copy_username" in ctx.text
    assert "strcpy(buf, input)" in ctx.text
    # Should not have pulled in the entire file.
    assert ctx.text.count("void ") < 5


def test_missing_function_boundary_falls_back_to_window(tmp_path):
    # A file with no brace-delimited function at all near the target line
    # (e.g. a huge block of #define macros) should fall back to a fixed
    # line window rather than raising or returning nonsense bounds.
    lines = [f"#define VALUE_{i} {i}" for i in range(300)]
    path = tmp_path / "macros.c"
    path.write_text("\n".join(lines))

    ctx = extract_code_context(path, line=150)

    assert not ctx.is_whole_file
    assert ctx.start_line < 150 < ctx.end_line


# -- Cross-file identifier occurrences ----------------------------------------

def test_identifiers_from_message_extracts_quoted_identifiers():
    msg = "identifier 'CWE121_ns__72' is reserved because it contains '__'"
    assert identifiers_from_message(msg) == ["CWE121_ns__72"]


def test_identifiers_from_message_skips_short_and_invalid_tokens():
    # 'if' is too short; '2bad' is not a valid identifier start; duplicates
    # collapse.
    msg = "'if' with 'longname' and '2bad' and 'longname' again"
    assert identifiers_from_message(msg) == ["longname"]


def _mini_project(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.cpp").write_text(
        "namespace demo__ns {\nvoid bad();\n}\n"
    )
    (src / "b.cpp").write_text(
        "// sink definitions\nnamespace demo__ns {\nvoid bad() {}\n}\n"
    )
    (tmp_path / "main.cpp").write_text(
        "int main() {\n    demo__ns::bad();\n    return 0;\n}\n"
    )
    (tmp_path / "notes.txt").write_text("demo__ns mentioned in a non-source file\n")
    return src / "a.cpp"


def test_occurrences_found_in_siblings_and_project_not_flagged_file(tmp_path):
    flagged = _mini_project(tmp_path)
    snippets = find_identifier_occurrences(tmp_path, ["demo__ns"], flagged)

    files = [s.file_path for s in snippets]
    assert "src/b.cpp" in files  # sibling searched first
    assert "main.cpp" in files
    assert "src/a.cpp" not in files  # the flagged file is the main context
    assert "notes.txt" not in files  # non-source files ignored

    b = next(s for s in snippets if s.file_path == "src/b.cpp")
    assert "namespace demo__ns" in b.text
    assert b.start_line == 1  # hit at line 2, minus context, clamped


def test_occurrences_include_primary_file_outside_displayed_range(tmp_path):
    flagged = _mini_project(tmp_path)
    flagged.write_text(flagged.read_text() + "\nusing namespace demo__ns;\n")
    snippets = find_identifier_occurrences(
        tmp_path, ["demo__ns"], flagged, exclude_range=(1, 2)
    )
    own = [snippet for snippet in snippets if snippet.file_path == "src/a.cpp"]
    assert own
    assert any("demo__ns" in snippet.text for snippet in own)
    assert all(snippet.text for snippet in snippets)


def test_occurrences_match_whole_words_only(tmp_path):
    flagged = _mini_project(tmp_path)
    (tmp_path / "other.cpp").write_text("int demo__ns_similar = 1;\n")
    snippets = find_identifier_occurrences(tmp_path, ["demo__ns"], flagged)
    assert "other.cpp" not in [s.file_path for s in snippets]


def test_occurrences_respect_caps(tmp_path):
    flagged = _mini_project(tmp_path)
    for i in range(10):
        (tmp_path / f"extra_{i}.cpp").write_text("void f() { demo__ns::bad(); }\n" * 30)
    snippets = find_identifier_occurrences(tmp_path, ["demo__ns"], flagged)

    assert len({s.file_path for s in snippets}) <= 5
    assert sum(len(s.text.splitlines()) for s in snippets) <= 40


def test_no_identifiers_means_no_search(tmp_path):
    flagged = _mini_project(tmp_path)
    assert find_identifier_occurrences(tmp_path, [], flagged) == []


def test_unquoted_generic_message_words_do_not_trigger_project_search(tmp_path):
    flagged = tmp_path / "target.c"
    flagged.write_text("void bad(void) { char data[4]; }\n")
    (tmp_path / "unrelated.c").write_text("int data = 1; int name = 2;\n")

    context = build_dependency_context(
        tmp_path, flagged, "macro name is a reserved identifier"
    )

    assert context.snippets == []


def test_identifier_at_finding_column_handles_preprocessor_macro(tmp_path):
    header = tmp_path / "sample.h"
    header.write_text("#define _SAMPLE_H 1\n")
    assert identifier_at_location(header, 1, 9) == "_SAMPLE_H"
