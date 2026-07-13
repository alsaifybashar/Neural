"""Renders Scorer output as JSON/CSV (machine-readable) and Markdown/HTML
(human-readable leaderboard), per the tool's "structured reports" design.

JSON/CSV are the source of truth for anything downstream (spreadsheets,
further analysis); the Markdown/HTML views exist purely for a human
skimming one run's results and are generated from the same ModelScore
objects, so they can never disagree with the machine-readable output.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from jinja2 import Template

from sectool.scorer import ModelScore

_HTML_TEMPLATE = Template(
    """<!doctype html>
<html><head><meta charset="utf-8"><title>sectool report</title>
<style>
body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; }
table { border-collapse: collapse; margin-bottom: 2rem; width: 100%; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: right; }
th, td:first-child { text-align: left; }
th { background: #f2f2f2; }
h2 { margin-top: 2.5rem; }
</style></head>
<body>
<h1>sectool evaluation report</h1>

<h2>Leaderboard</h2>
<table>
<tr><th>Model</th><th>Total</th><th>Fixed</th><th>Fix rate</th>
<th>Regressed</th><th>Regression rate</th><th>Failed</th><th>Skipped</th>
<th>Infrastructure exclusions</th><th>Avg attempts to resolve</th></tr>
{% for s in scores %}
<tr>
<td>{{ s.model_name }}</td><td>{{ s.total }}</td><td>{{ s.fixed }}</td>
<td>{{ "%.1f%%"|format(s.fix_rate * 100) }}</td>
<td>{{ s.regressed }}</td>
<td>{{ "%.1f%%"|format(s.regression_rate * 100) }}</td>
<td>{{ s.failed }}</td><td>{{ s.skipped }}</td>
<td>{{ s.infrastructure_failures }}</td>
<td>{{ "%.2f"|format(s.avg_attempts_to_resolve) if s.avg_attempts_to_resolve else "-" }}</td>
</tr>
{% endfor %}
</table>

{% for s in scores %}
<h2>{{ s.model_name }} - per CWE / CERT rule</h2>
<table>
<tr><th>Rule</th><th>Total</th><th>Fixed</th><th>Fix rate</th>
<th>Regressed</th><th>Failed</th></tr>
{% for rule in s.per_rule.values() %}
<tr>
<td>{{ rule.rule_id }}</td><td>{{ rule.total }}</td><td>{{ rule.fixed }}</td>
<td>{{ "%.1f%%"|format(rule.fix_rate * 100) }}</td>
<td>{{ rule.regressed }}</td><td>{{ rule.failed }}</td>
</tr>
{% endfor %}
</table>
{% endfor %}
</body></html>
"""
)


def to_dict(scores: dict[str, ModelScore]) -> dict:
    return {
        model_name: {
            "total": s.total,
            "fixed": s.fixed,
            "regressed": s.regressed,
            "failed": s.failed,
            "skipped": s.skipped,
            "infrastructure_failures": s.infrastructure_failures,
            "failure_categories": s.failure_categories,
            "fix_rate": s.fix_rate,
            "regression_rate": s.regression_rate,
            "avg_attempts_to_resolve": s.avg_attempts_to_resolve,
            "per_rule": {
                rule_id: {
                    "total": r.total,
                    "fixed": r.fixed,
                    "regressed": r.regressed,
                    "failed": r.failed,
                    "fix_rate": r.fix_rate,
                }
                for rule_id, r in s.per_rule.items()
            },
        }
        for model_name, s in scores.items()
    }


def to_csv(scores: dict[str, ModelScore]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "model", "total", "fixed", "fix_rate", "regressed",
            "regression_rate", "failed", "skipped", "avg_attempts_to_resolve",
            "infrastructure_failures", "failure_categories",
        ]
    )
    for s in scores.values():
        writer.writerow(
            [
                s.model_name, s.total, s.fixed, f"{s.fix_rate:.4f}",
                s.regressed, f"{s.regression_rate:.4f}", s.failed, s.skipped,
                f"{s.avg_attempts_to_resolve:.2f}" if s.avg_attempts_to_resolve else "",
                s.infrastructure_failures, json.dumps(s.failure_categories, sort_keys=True),
            ]
        )
    return buf.getvalue()


def render_html(scores: dict[str, ModelScore]) -> str:
    return _HTML_TEMPLATE.render(scores=list(scores.values()))


def write_report(scores: dict[str, ModelScore], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(to_dict(scores), indent=2))
    (output_dir / "report.csv").write_text(to_csv(scores))
    (output_dir / "report.html").write_text(render_html(scores))
