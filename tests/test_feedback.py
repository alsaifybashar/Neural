"""Tests annotate_with_source: failure text naming path:line locations gets
the referenced files' numbered content appended; anything unresolvable
leaves the text untouched."""

from sectool.verifier.feedback import annotate_with_source

INTRO = "Referenced content:"


def make_tree(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "b.cpp").write_text(
        "\n".join(f"int line_{n};" for n in range(1, 41)) + "\n"
    )
    return tmp_path


def test_gcc_style_error_gets_numbered_snippet(tmp_path):
    root = make_tree(tmp_path)
    detail = "src/b.cpp:25:9: error: use of undeclared identifier 'demo_ns'"
    out = annotate_with_source(root, detail, INTRO)

    assert detail in out
    assert INTRO in out
    assert "src/b.cpp around line 25" in out
    assert "   25 | int line_25;" in out
    assert "   17 | int line_17;" in out  # radius reaches back 8 lines


def test_git_apply_error_gets_snippet(tmp_path):
    root = make_tree(tmp_path)
    out = annotate_with_source(root, "error: patch failed: src/b.cpp:10", INTRO)
    assert "src/b.cpp around line 10" in out


def test_path_relative_to_build_dir_is_located_by_suffix(tmp_path):
    # Compiler output from `make -C src` references bare "b.cpp:5" --
    # resolution falls back to locating the file by its trailing parts.
    root = make_tree(tmp_path)
    out = annotate_with_source(root, "b.cpp:5:1: error: boom", INTRO)
    assert "src/b.cpp around line 5" in out


def test_absolute_path_is_displayed_repo_relative(tmp_path):
    root = make_tree(tmp_path)
    detail = f"{root}/src/b.cpp:7:1: error: boom"
    out = annotate_with_source(root, detail, INTRO)
    assert "src/b.cpp around line 7" in out


def test_unresolvable_references_leave_detail_unchanged(tmp_path):
    root = make_tree(tmp_path)
    detail = "nonexistent.cpp:12:1: error: boom"
    assert annotate_with_source(root, detail, INTRO) == detail


def test_no_references_leave_detail_unchanged(tmp_path):
    root = make_tree(tmp_path)
    detail = "collect2: error: ld returned 1 exit status"
    assert annotate_with_source(root, detail, INTRO) == detail
