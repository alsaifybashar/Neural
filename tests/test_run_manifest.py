import json
import subprocess

from sectool.config import ModelConfig, ProjectConfig, RunConfig
from sectool.run_manifest import (
    add_selection_metadata,
    create_run_manifest,
    write_run_manifest,
)
from sectool.findings.schema import Finding


def test_manifest_records_comparability_and_selection_metadata(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.c").write_text("int main(void) { return 0; }\n")
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    subprocess.run(["git", "add", "a.c"], cwd=project, check=True)
    subprocess.run(
        [
            "git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "commit", "-qm", "baseline",
        ],
        cwd=project,
        check=True,
    )
    config_path = tmp_path / "run.json"
    config_path.write_text(json.dumps({"fixture": True}))
    config = RunConfig(
        project=ProjectConfig(project, "make", "make test"),
        models=[ModelConfig("model", "openai", "model-id")],
        output_dir=tmp_path / "results",
        dispatch_filter="cwe",
        checker_enables=("profile:security",),
    )

    manifest = create_run_manifest(config, config_path)
    finding = Finding(
        report_hash="h1", file_path="CWE121_Buffer/a.c", line=1, column=1,
        message="out of bounds", checker_name="security.ArrayBound",
        analyzer_name="clangsa", severity="HIGH", cwe_ids=["CWE-121"],
    )
    add_selection_metadata(manifest, 10, [finding], [finding])
    output = tmp_path / "manifest.json"
    write_run_manifest(output, manifest)
    saved = json.loads(output.read_text())

    assert saved["prompt_protocol_version"] == "security-repair-v2"
    assert saved["project"]["git_commit"]
    assert saved["evaluation"]["dispatch_filter"] == "cwe"
    assert saved["models"][0]["model_id"] == "model-id"
    assert saved["selection"]["selected"][0]["cwe_ids"] == ["CWE-121"]
