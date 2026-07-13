import json

from sectool.context import build_dependency_context
from sectool.findings.schema import Finding, normalized_finding_identity
from sectool.verifier.patch import validate_patch
from sectool.context_tools import ContextToolExecutor
from sectool.findings.tasks import group_findings


def finding(path, line=10):
    return Finding(
        report_hash="hash", file_path=str(path), line=line, column=1,
        message="declaration uses identifier 'shared_name'",
        checker_name="bugprone-reserved-identifier",
        analyzer_name="clang-tidy", severity="HIGH",
    )


def test_dependency_context_includes_compile_command_and_reference(tmp_path):
    source = tmp_path / "a.c"
    sibling = tmp_path / "b.c"
    source.write_text("int shared_name(void) { return 0; }\n")
    sibling.write_text("int call(void) { return shared_name(); }\n")
    db = tmp_path / "compile_commands.json"
    db.write_text(json.dumps([{
        "directory": str(tmp_path), "file": "a.c", "command": "cc -Wall -c a.c"
    }]))
    context = build_dependency_context(tmp_path, source, finding(source).message, db)
    assert context.compile_command == "cc -Wall -c a.c"
    assert any(s.file_path == "b.c" for s in context.snippets)


def test_patch_validation_rejects_traversal_and_missing_hunk(tmp_path):
    unsafe = "--- a/../secret\n+++ b/../secret\n@@ -1 +1 @@\n-x\n+y\n"
    assert not validate_patch(unsafe, tmp_path).valid
    assert not validate_patch("--- a/a.c\n+++ b/a.c\n", tmp_path).valid


def test_finding_identity_ignores_checkout_prefix_hash_and_line(tmp_path):
    original = finding(tmp_path / "src" / "a.c", line=10)
    moved = finding(tmp_path / "other-worktree" / "src" / "a.c", line=14)
    # Normalize each absolute path against its own checkout root.
    assert normalized_finding_identity(original, tmp_path) == normalized_finding_identity(
        moved, tmp_path / "other-worktree"
    )


def test_group_findings_clusters_same_checker_and_symbol(tmp_path):
    first = finding(tmp_path / "a.cpp")
    second = finding(tmp_path / "b.cpp")
    second.report_hash = "other"
    tasks = group_findings([first, second])
    assert len(tasks) == 1
    assert len(tasks[0].findings) == 2


def test_namespace_search_finds_all_required_juliet_code_references():
    root = __import__("pathlib").Path(
        "C/testcases/CWE121_Stack_Based_Buffer_Overflow/s01"
    ).resolve()
    source = root / "CWE121_Stack_Based_Buffer_Overflow__CWE135_72a.cpp"
    result = ContextToolExecutor(root, focus_path=source).search_symbol(
        "CWE121_Stack_Based_Buffer_Overflow__CWE135_72"
    )
    locations = {(item["path"], item["line"]) for item in result.payload["results"]}
    assert result.payload["total"] == 9
    assert (source.name, 104) in locations
    assert ("testcases.h", 1812) in locations
    assert ("testcases.h", 2034) in locations
