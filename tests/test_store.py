"""Round-trip tests for FindingStore: what goes in via upsert/add_* must
come back out unchanged, since the Scorer and any later re-scoring trusts
this layer completely."""

from sectool.findings.schema import (
    BugPathEvent,
    Finding,
    FindingStatus,
    FixAttempt,
    VerificationResult,
    VerificationStage,
)
from sectool.findings.store import FindingStore


def make_finding(report_hash="h1", **overrides) -> Finding:
    defaults = dict(
        report_hash=report_hash,
        file_path="src/a.c",
        line=10,
        column=2,
        message="msg",
        checker_name="cert-str31-c",
        analyzer_name="clang-tidy",
        severity="HIGH",
        cert_rule_ids=["STR31-C"],
        cert_guideline="sei-cert-c",
        bug_path_events=[BugPathEvent("src/a.c", 9, 1, "declared here")],
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_upsert_and_get_finding_roundtrips(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    finding = make_finding()

    store.upsert_finding(finding)
    fetched = store.get_finding("h1")

    assert fetched is not None
    assert fetched.report_hash == "h1"
    assert fetched.cert_rule_ids == ["STR31-C"]
    assert fetched.bug_path_events[0].message == "declared here"
    store.close()


def test_cwe_and_failure_category_roundtrip(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding(cwe_ids=["CWE-121"], cwe_name="Buffer Overflow"))
    store.add_verification_result(VerificationResult(
        finding_hash="h1", model_name="model-a", attempt_number=1,
        stage_reached=VerificationStage.PATCH, passed=False,
        detail="not JSON", failure_category="model_output",
    ))

    assert store.get_finding("h1").cwe_ids == ["CWE-121"]
    result = store.latest_verification_per_model("h1")["model-a"]
    assert result.failure_category == "model_output"
    store.close()


def test_upsert_finding_is_idempotent_on_same_hash(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding(message="first"))
    store.upsert_finding(make_finding(message="second"))

    assert len(store.all_findings()) == 1
    assert store.get_finding("h1").message == "second"
    store.close()


def test_fix_attempt_roundtrip(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding())
    attempt = FixAttempt(
        finding_hash="h1",
        model_name="claude-sonnet-5",
        attempt_number=1,
        patch_text="--- a/src/a.c\n+++ b/src/a.c\n",
        prompt_text="fix this",
        raw_model_response="```diff\n--- a/src/a.c\n+++ b/src/a.c\n```",
    )
    store.add_fix_attempt(attempt)

    fetched = store.attempts_for("h1", "claude-sonnet-5")
    assert len(fetched) == 1
    assert fetched[0].patch_text == attempt.patch_text
    store.close()


def test_verification_result_roundtrip_and_latest_per_model(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding())

    store.add_verification_result(
        VerificationResult(
            finding_hash="h1", model_name="model-a", attempt_number=1,
            stage_reached=VerificationStage.BUILD, passed=False,
            detail="build failed", target_resolved=False,
        )
    )
    store.add_verification_result(
        VerificationResult(
            finding_hash="h1", model_name="model-a", attempt_number=2,
            stage_reached=VerificationStage.PASSED, passed=True,
            detail="ok", target_resolved=True,
        )
    )

    latest = store.latest_verification_per_model("h1")
    assert set(latest) == {"model-a"}
    assert latest["model-a"].attempt_number == 2
    assert latest["model-a"].passed is True
    store.close()


def test_distinct_model_names_preserves_first_seen_order(tmp_path):
    store = FindingStore(tmp_path / "store.db")
    store.upsert_finding(make_finding())
    for model, attempt_no in [("model-b", 1), ("model-a", 1), ("model-b", 2)]:
        store.add_fix_attempt(
            FixAttempt(
                finding_hash="h1", model_name=model, attempt_number=attempt_no,
                patch_text="", prompt_text="", raw_model_response="",
            )
        )

    assert store.distinct_model_names() == ["model-b", "model-a"]
    store.close()
