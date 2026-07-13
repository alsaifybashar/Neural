"""Tests for the preflight checks, using monkeypatch to fake subprocess/
network/env results rather than depending on this machine's actual
CodeChecker install, API keys, or an Ollama server."""

import subprocess

import pytest

from sectool.config import ModelConfig
from sectool.preflight import (
    LEVEL_ERROR,
    LEVEL_WARNING,
    check_codechecker,
    check_git_repo,
    check_model,
    has_hard_failure,
)
from sectool.preflight import CheckResult


def test_check_codechecker_missing_binary_is_hard_error():
    result = check_codechecker(codechecker_bin="this-binary-does-not-exist")
    assert result.ok is False
    assert result.level == LEVEL_ERROR
    assert "not found on PATH" in result.detail


def test_check_codechecker_ok(monkeypatch):
    def fake_run(args, capture_output, text, timeout):
        return subprocess.CompletedProcess(args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = check_codechecker()
    assert result.ok is True


def test_check_codechecker_nonzero_exit_is_error(monkeypatch):
    def fake_run(args, capture_output, text, timeout):
        return subprocess.CompletedProcess(args, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = check_codechecker()
    assert result.ok is False
    assert "boom" in result.detail


def test_check_git_repo_not_a_repo(tmp_path):
    result = check_git_repo(tmp_path, require_commit=True)
    assert result.ok is False
    assert "not a git repository" in result.detail


def test_check_git_repo_no_commits(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    result = check_git_repo(tmp_path, require_commit=True)
    assert result.ok is False
    assert "no commits yet" in result.detail


def test_check_git_repo_with_commit_ok(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "a@b.c"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "a"], cwd=tmp_path, capture_output=True)
    (tmp_path / "f.txt").write_text("x")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True
    )
    result = check_git_repo(tmp_path, require_commit=True)
    assert result.ok is True


def test_check_git_repo_without_require_commit_skips_head_check(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    result = check_git_repo(tmp_path, require_commit=False)
    assert result.ok is True


def make_model_config(**overrides) -> ModelConfig:
    defaults = dict(name="m", provider="anthropic", model_id="claude-sonnet-5")
    defaults.update(overrides)
    return ModelConfig(**defaults)


def test_check_model_anthropic_missing_key_is_warning(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = check_model(make_model_config(provider="anthropic"))
    assert result.ok is False
    assert result.level == LEVEL_WARNING
    assert "ANTHROPIC_API_KEY" in result.detail


def test_check_model_anthropic_with_key_ok(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    result = check_model(make_model_config(provider="anthropic"))
    assert result.ok is True


def test_check_model_custom_api_key_env(monkeypatch):
    monkeypatch.delenv("MY_KEY", raising=False)
    result = check_model(
        make_model_config(provider="anthropic", api_key_env="MY_KEY")
    )
    assert result.ok is False
    assert "MY_KEY" in result.detail


def test_check_model_ollama_unreachable_is_warning(monkeypatch):
    import requests

    def fake_get(url, timeout):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "get", fake_get)
    result = check_model(
        make_model_config(provider="ollama", model_id="llama3:70b", base_url="http://x:1")
    )
    assert result.ok is False
    assert result.level == LEVEL_WARNING


def test_check_model_ollama_model_not_pulled_is_warning(monkeypatch):
    import requests

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"models": [{"name": "mistral:7b"}]}

    monkeypatch.setattr(requests, "get", lambda url, timeout: FakeResponse())
    result = check_model(make_model_config(provider="ollama", model_id="llama3:70b"))
    assert result.ok is False
    assert "not pulled" in result.detail


def test_check_model_ollama_model_pulled_ok(monkeypatch):
    import requests

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"models": [{"name": "llama3:70b"}]}

    monkeypatch.setattr(requests, "get", lambda url, timeout: FakeResponse())
    result = check_model(make_model_config(provider="ollama", model_id="llama3:70b"))
    assert result.ok is True


def test_has_hard_failure_true_only_for_error_level():
    results = [
        CheckResult("a", True),
        CheckResult("b", False, level=LEVEL_WARNING),
    ]
    assert has_hard_failure(results) is False

    results.append(CheckResult("c", False, level=LEVEL_ERROR))
    assert has_hard_failure(results) is True
