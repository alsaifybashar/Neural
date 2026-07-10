"""Tests the function-boundary heuristic used to scope what source a model
sees for a given finding (see sectool/context.py's docstring for why this
is a heuristic rather than a real parse)."""

from sectool.context import extract_code_context


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
