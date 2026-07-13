"""Tests the tolerant patch-application ladder against real `git apply`,
using the failure modes model-produced diffs actually exhibit: miscounted
hunk headers, wrong line numbers, and slightly-off context -- plus the
authoritative-source feedback produced when nothing can apply."""

import pytest

from sectool.verifier.patch import apply_patch, validate_patch

FILE_CONTENT = """\
#include <string.h>

#define GREETING "hello"

namespace demo__ns
{

void copy(char *dst, const char *src)
{
    strcpy(dst, src);
}

}
"""


@pytest.fixture
def worktree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text(FILE_CONTENT)
    return tmp_path


def patch_with(header: str, context_before: str = "#define GREETING \"hello\"\n\n") -> str:
    return (
        "--- a/src/a.c\n"
        "+++ b/src/a.c\n"
        f"{header}\n"
        f"{_prefix_context(context_before)}"
        "-namespace demo__ns\n"
        "+namespace demo_ns\n"
        " {\n"
    )


def _prefix_context(text: str) -> str:
    return "".join(f" {line}\n" for line in text.splitlines())


def test_correct_patch_applies_exactly(worktree):
    result = apply_patch(worktree, patch_with("@@ -3,4 +3,4 @@"))
    assert result.applied
    assert result.strategy == "exact"
    assert "demo_ns" in (worktree / "src" / "a.c").read_text()


def test_miscounted_hunk_header_applies_via_recount(worktree):
    # Counts of 99 are nonsense, but the content is exact -- the ladder's
    # --recount rung recomputes them.
    result = apply_patch(worktree, patch_with("@@ -3,99 +3,99 @@"))
    assert result.applied
    assert result.strategy == "--recount"
    assert "demo_ns" in (worktree / "src" / "a.c").read_text()


def test_wrong_line_numbers_apply_via_recount(worktree):
    # Guessed start lines (the example from a real run: the model's @@ -25
    # pointed nowhere near the namespace) -- content still matches, git
    # finds it by searching once counts are sane.
    result = apply_patch(worktree, patch_with("@@ -40,4 +40,4 @@"))
    assert result.applied
    assert "demo_ns" in (worktree / "src" / "a.c").read_text()


def test_slightly_wrong_outer_context_applies_via_reduced_context(worktree):
    # The model misremembered the macro line ("hi" instead of "hello"):
    # the outer context is wrong but the line adjacent to the change is
    # right, so the -C1 rung applies it.
    patch = patch_with("@@ -3,4 +3,4 @@", context_before="#define GREETING \"hi\"\n\n")
    result = apply_patch(worktree, patch)
    assert result.applied
    assert result.strategy == "--recount -C1"
    assert "demo_ns" in (worktree / "src" / "a.c").read_text()
    # The tolerant rung must not have touched the mismatched context line.
    assert '"hello"' in (worktree / "src" / "a.c").read_text()


def test_unappliable_patch_feeds_back_authoritative_source(worktree):
    patch = (
        "--- a/src/a.c\n"
        "+++ b/src/a.c\n"
        "@@ -5,3 +5,3 @@\n"
        " int completely;\n"
        "-int wrong = 1;\n"
        "+int wrong = 2;\n"
        " int context;\n"
    )
    result = apply_patch(worktree, patch)
    assert not result.applied
    assert result.strategy == ""
    assert "patch failed" in result.detail
    # The retry feedback contains the file's real, numbered lines around
    # the failed hunk -- what the regenerated diff must reproduce.
    assert "actual content around the failed hunk" in result.detail
    assert "5 | namespace demo__ns" in result.detail
    assert "Regenerate your diff" in result.detail


def test_empty_patch_fails_without_invoking_git(worktree):
    result = apply_patch(worktree, "   \n")
    assert not result.applied
    assert "no patch content" in result.detail


def test_validation_preserves_trailing_blank_context_line(worktree):
    patch = patch_with("@@ -3,4 +3,4 @@") + " \n"
    result = validate_patch(patch, worktree)
    assert result.valid
    assert result.patch_text.endswith(" \n")


def test_validation_rejects_analyzer_suppression_as_a_fix(worktree):
    patch = (
        "--- a/src/a.c\n"
        "+++ b/src/a.c\n"
        "@@ -8,3 +8,3 @@\n"
        " {\n"
        "-    strcpy(dst, src);\n"
        "+    strcpy(dst, src); // NOLINT\n"
        " }\n"
    )
    result = validate_patch(patch, worktree)
    assert not result.valid
    assert "suppressions" in result.detail
