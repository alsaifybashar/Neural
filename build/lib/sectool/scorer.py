"""Aggregates a FindingStore into the metrics the tool exists to produce:
per-model, per-SEI-CERT-rule fix rate, and per-model regression rate.

Regression rate is the primary trust signal (a model that "fixes" findings
by breaking the build, breaking tests, or introducing new vulnerabilities
is worse than one that just fails to fix them) -- see PLAN.md's metrics
priorities. Fix rate broken down by CERT rule shows *where* a model is
reliable rather than only an aggregate number, which is what makes the
comparison actionable (e.g. "model A is strong on buffer-handling rules
but weak on concurrency rules").

Attempts-to-resolve is included as a secondary/efficiency signal since it's
already fully captured in stored verification results at no extra cost --
not because it's the headline metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sectool.dispatcher import resolve_final_status
from sectool.findings.schema import FindingStatus
from sectool.findings.store import FindingStore


@dataclass
class RuleScore:
    rule_id: str
    total: int = 0
    fixed: int = 0
    regressed: int = 0
    failed: int = 0

    @property
    def fix_rate(self) -> float:
        return self.fixed / self.total if self.total else 0.0


@dataclass
class ModelScore:
    model_name: str
    total: int = 0
    fixed: int = 0
    regressed: int = 0
    failed: int = 0
    skipped: int = 0
    infrastructure_failures: int = 0
    attempts_to_resolve: list[int] = field(default_factory=list)
    per_rule: dict[str, RuleScore] = field(default_factory=dict)
    failure_categories: dict[str, int] = field(default_factory=dict)

    @property
    def fix_rate(self) -> float:
        return self.fixed / self.total if self.total else 0.0

    @property
    def regression_rate(self) -> float:
        return self.regressed / self.total if self.total else 0.0

    @property
    def avg_attempts_to_resolve(self) -> float | None:
        if not self.attempts_to_resolve:
            return None
        return sum(self.attempts_to_resolve) / len(self.attempts_to_resolve)


def score(store: FindingStore) -> dict[str, ModelScore]:
    """Compute one ModelScore per model that has attempts recorded in
    `store`. Reads only already-persisted data -- does not re-run any
    model or the verifier -- so re-scoring a finished run is instant and
    side-effect free."""
    findings_by_hash = {f.report_hash: f for f in store.all_findings()}
    scores: dict[str, ModelScore] = {
        name: ModelScore(model_name=name) for name in store.distinct_model_names()
    }

    for finding_hash, finding in findings_by_hash.items():
        rule_id = finding.primary_evaluation_rule()
        latest = store.latest_verification_per_model(finding_hash)

        for model_name, result in latest.items():
            model_score = scores.setdefault(model_name, ModelScore(model_name=model_name))
            if result.failure_category == "infrastructure":
                # Provider/network/configuration failures are properties of
                # the experiment setup, not evidence about repair capability.
                model_score.infrastructure_failures += 1
                continue
            status = resolve_final_status(
                passed=result.passed,
                target_resolved=result.target_resolved,
                has_new_findings=bool(result.new_findings),
            )

            model_score.total += 1
            rule_score = model_score.per_rule.setdefault(
                rule_id, RuleScore(rule_id=rule_id)
            )
            rule_score.total += 1
            if result.failure_category:
                model_score.failure_categories[result.failure_category] = (
                    model_score.failure_categories.get(result.failure_category, 0) + 1
                )

            if status == FindingStatus.FIXED:
                model_score.fixed += 1
                rule_score.fixed += 1
                model_score.attempts_to_resolve.append(result.attempt_number)
            elif status == FindingStatus.REGRESSED:
                model_score.regressed += 1
                rule_score.regressed += 1
            elif status == FindingStatus.FAILED:
                model_score.failed += 1
                rule_score.failed += 1
            elif status == FindingStatus.SKIPPED:
                model_score.skipped += 1

    return scores
