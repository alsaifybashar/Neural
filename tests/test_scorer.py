"""Tests the Scorer's aggregation logic against a hand-built FindingStore,
covering the three terminal outcomes (fixed / regressed / failed) and the
per-CERT-rule breakdown."""

from sectool.findings.schema import (
    Finding, FixAttempt, VerificationResult, VerificationStage,
)
from sectool.findings.store import FindingStore
from sectool.scorer import score


def make_finding(report_hash, rule_id) -> Finding:
    return Finding(
        report_hash=report_hash,
        file_path="src/a.c",
        line=1,
        column=1,
        message="msg",
        checker_name="cert-str31-c",
        analyzer_name="clang-tidy",
        severity="HIGH",
        cert_rule_ids=[rule_id],
        cert_guideline="sei-cert-c",
    )


def add_result(store, finding_hash, model_name, attempt_number, passed, target_resolved, new_findings=None):
    store.add_verification_result(
        VerificationResult(
            finding_hash=finding_hash,
            model_name=model_name,
            attempt_number=attempt_number,
            stage_reached=VerificationStage.PASSED if passed else VerificationStage.RESCAN,
            passed=passed,
            detail="",
            target_resolved=target_resolved,
            new_findings=new_findings or [],
        )
    )


def test_score_counts_fixed_regressed_and_failed(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding("h-fixed", "STR31-C"))
    store.upsert_finding(make_finding("h-regressed", "STR31-C"))
    store.upsert_finding(make_finding("h-failed", "ARR30-C"))

    add_result(store, "h-fixed", "model-a", 1, passed=True, target_resolved=True)
    add_result(
        store, "h-regressed", "model-a", 1, passed=False, target_resolved=True,
        new_findings=[make_finding("h-new", "OTHER-C")],
    )
    add_result(store, "h-failed", "model-a", 3, passed=False, target_resolved=False)

    scores = score(store)
    store.close()

    s = scores["model-a"]
    assert s.total == 3
    assert s.fixed == 1
    assert s.regressed == 1
    assert s.failed == 1
    assert s.fix_rate == 1 / 3
    assert s.regression_rate == 1 / 3
    assert s.avg_attempts_to_resolve == 1.0


def test_score_breaks_down_by_cert_rule(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding("h1", "STR31-C"))
    store.upsert_finding(make_finding("h2", "STR31-C"))
    store.upsert_finding(make_finding("h3", "ARR30-C"))

    add_result(store, "h1", "model-a", 1, passed=True, target_resolved=True)
    add_result(store, "h2", "model-a", 1, passed=False, target_resolved=False)
    add_result(store, "h3", "model-a", 1, passed=True, target_resolved=True)

    scores = score(store)
    store.close()

    per_rule = scores["model-a"].per_rule
    assert per_rule["STR31-C"].total == 2
    assert per_rule["STR31-C"].fixed == 1
    assert per_rule["STR31-C"].fix_rate == 0.5
    assert per_rule["ARR30-C"].fixed == 1
    assert per_rule["ARR30-C"].fix_rate == 1.0


def test_score_handles_multiple_models_independently(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding("h1", "STR31-C"))

    add_result(store, "h1", "model-a", 1, passed=True, target_resolved=True)
    add_result(store, "h1", "model-b", 1, passed=False, target_resolved=False)

    scores = score(store)
    store.close()

    assert scores["model-a"].fixed == 1
    assert scores["model-b"].failed == 1


def test_score_counts_model_output_but_excludes_infrastructure(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding("h-output", "STR31-C"))
    store.upsert_finding(make_finding("h-infra", "STR31-C"))
    for finding_hash, category in (
        ("h-output", "model_output"), ("h-infra", "infrastructure")
    ):
        store.add_fix_attempt(FixAttempt(
            finding_hash=finding_hash, model_name="model-a", attempt_number=1,
            patch_text="", prompt_text="", raw_model_response="",
        ))
        store.add_verification_result(VerificationResult(
            finding_hash=finding_hash, model_name="model-a", attempt_number=1,
            stage_reached=VerificationStage.PATCH, passed=False, detail="failed",
            failure_category=category,
        ))

    result = score(store)["model-a"]
    store.close()

    assert result.total == 1
    assert result.failed == 1
    assert result.infrastructure_failures == 1
    assert result.failure_categories == {"model_output": 1}
