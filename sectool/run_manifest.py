"""Reproducibility metadata for security-repair evaluation runs."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sectool import __version__
from sectool.config import RunConfig
from sectool.models.prompt import PROMPT_PROTOCOL_VERSION


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_run_manifest(config: RunConfig, config_path: Path) -> dict[str, Any]:
    """Build metadata that lets two model runs be checked for comparability."""
    config_bytes = Path(config_path).read_bytes()
    root = config.project.root
    dirty_patch = _git(root, "diff", "--binary", "HEAD").encode()
    untracked = _git(root, "ls-files", "--others", "--exclude-standard")
    return {
        "schema_version": 1,
        "run_id": str(uuid.uuid4()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "sectool_version": __version__,
        "prompt_protocol_version": PROMPT_PROTOCOL_VERSION,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "config_path": str(Path(config_path).resolve()),
        "config_sha256": _sha256(config_bytes),
        "project": {
            "root": str(root),
            "git_commit": _git(root, "rev-parse", "HEAD"),
            "git_dirty": bool(_git(root, "status", "--porcelain")),
            "tracked_diff_sha256": _sha256(dirty_patch),
            "untracked_files": untracked.splitlines() if untracked else [],
            "build_command": config.project.build_command,
            "test_command": config.project.test_command,
        },
        "evaluation": {
            "dispatch_filter": config.dispatch_filter,
            "checker_enables": list(config.checker_enables),
            "include_checkers": list(config.include_checkers),
            "exclude_checkers": list(config.exclude_checkers),
            "cwe_from_filename": config.cwe_from_filename,
            "max_attempts_per_finding": config.max_attempts_per_finding,
            "max_context_rounds": config.max_context_rounds,
            "max_format_retries": config.max_format_retries,
            "context_max_files": config.context_max_files,
            "context_max_lines": config.context_max_lines,
        },
        "models": [
            {
                "name": model.name,
                "provider": model.provider,
                "model_id": model.model_id,
                "base_url": model.base_url,
                "max_output_tokens": model.max_output_tokens,
                "temperature": model.temperature,
                "thinking": model.thinking,
                "effort": model.effort,
                "max_tokens_param": model.max_tokens_param,
            }
            for model in config.models
        ],
    }


def write_run_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def add_selection_metadata(
    manifest: dict[str, Any],
    raw_finding_count: int,
    matched_findings: list,
    selected_findings: list,
) -> None:
    manifest["selection"] = {
        "raw_finding_count": raw_finding_count,
        "matched_finding_count": len(matched_findings),
        "selected_finding_count": len(selected_findings),
        "selected": [
            {
                "report_hash": finding.report_hash,
                "path": finding.file_path,
                "line": finding.line,
                "checker": finding.checker_name,
                "cwe_ids": finding.cwe_ids,
                "cert_rule_ids": finding.cert_rule_ids,
            }
            for finding in selected_findings
        ],
    }
