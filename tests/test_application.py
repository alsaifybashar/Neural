import subprocess

from sectool.verifier.application import apply_verified_patch


PATCH = """--- a/a.c
+++ b/a.c
@@ -1 +1 @@
-int x;
+int x = 1;
"""


def init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    (path / "a.c").write_text("int x;\n")
    subprocess.run(["git", "add", "a.c"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=path, check=True)


def test_apply_verified_patch_to_clean_tree(tmp_path):
    init_repo(tmp_path)
    result = apply_verified_patch(tmp_path, PATCH)
    assert result.status == "applied"
    assert (tmp_path / "a.c").read_text() == "int x = 1;\n"


def test_refuses_overlapping_dirty_file(tmp_path):
    init_repo(tmp_path)
    (tmp_path / "a.c").write_text("int user_edit;\n")
    result = apply_verified_patch(tmp_path, PATCH)
    assert result.status == "conflict"
    assert "uncommitted changes" in result.detail
    assert (tmp_path / "a.c").read_text() == "int user_edit;\n"
