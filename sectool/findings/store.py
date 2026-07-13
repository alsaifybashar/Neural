"""SQLite-backed persistence for findings, fix attempts, and verification
results.

Why SQLite instead of e.g. one JSON file per finding: a full evaluation run
dispatches every (finding x model) pair through a multi-attempt retry loop,
and we want to be able to re-open a run's results later (resume an
interrupted run, re-score without re-scanning, inspect one finding's full
attempt history) without re-parsing a pile of loose files. A single file
also makes a completed run trivially easy to hand to someone else.

Note on `Finding.status`: this store treats it as "has this finding been
scanned / is it in scope for dispatch", not "did model X fix it" -- a
finding can be FIXED by one model and FAILED by another in the same run.
Per-model outcomes are derived from `verification_results` (see
`latest_verification_per_model`), not stored redundantly on the finding
row. The Scorer is the place that joins these back together.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from sectool.findings.schema import (
    BugPathEvent,
    Finding,
    FindingStatus,
    FixAttempt,
    VerificationResult,
    VerificationStage,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    report_hash     TEXT PRIMARY KEY,
    file_path       TEXT NOT NULL,
    line            INTEGER NOT NULL,
    column          INTEGER NOT NULL,
    message         TEXT NOT NULL,
    checker_name    TEXT NOT NULL,
    analyzer_name   TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cert_rule_ids   TEXT NOT NULL,  -- JSON list[str]
    cert_guideline  TEXT NOT NULL,
    bug_path_events TEXT NOT NULL, -- JSON list[dict]
    status          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fix_attempts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_hash        TEXT NOT NULL REFERENCES findings(report_hash),
    model_name          TEXT NOT NULL,
    attempt_number      INTEGER NOT NULL,
    patch_text          TEXT NOT NULL,
    prompt_text         TEXT NOT NULL,
    raw_model_response  TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    UNIQUE(finding_hash, model_name, attempt_number)
);

CREATE TABLE IF NOT EXISTS verification_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_hash    TEXT NOT NULL REFERENCES findings(report_hash),
    model_name      TEXT NOT NULL,
    attempt_number  INTEGER NOT NULL,
    stage_reached   TEXT NOT NULL,
    passed          INTEGER NOT NULL,
    detail          TEXT NOT NULL,
    target_resolved INTEGER NOT NULL,
    new_findings    TEXT NOT NULL,  -- JSON list[dict] (full Finding dicts)
    duration_seconds REAL NOT NULL,
    patch_text       TEXT NOT NULL DEFAULT '',
    touched_files    TEXT NOT NULL DEFAULT '[]',
    artifact_path    TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    UNIQUE(finding_hash, model_name, attempt_number)
);
"""


class FindingStore:
    """Thin, explicit data-access layer over a single SQLite file.

    Deliberately not an ORM: the schema is small and stable enough that
    hand-written SQL is easier to audit than an abstraction layer, and
    "can we trust what this tool records" is exactly the kind of thing a
    reader should be able to verify by reading straight SQL.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        with closing(self._conn.cursor()) as cur:
            cur.executescript(_SCHEMA)
            columns = {
                row[1]
                for row in cur.execute("PRAGMA table_info(verification_results)")
            }
            for name, declaration in (
                ("patch_text", "TEXT NOT NULL DEFAULT ''"),
                ("touched_files", "TEXT NOT NULL DEFAULT '[]'"),
                ("artifact_path", "TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in columns:
                    cur.execute(
                        f"ALTER TABLE verification_results "
                        f"ADD COLUMN {name} {declaration}"
                    )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "FindingStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- Findings ---------------------------------------------------------

    def upsert_finding(self, finding: Finding) -> None:
        """Insert a finding, or update it if a re-scan hashes to the same
        report_hash (CodeChecker's hash is stable across identical scans,
        so this is idempotent when re-running the same scan twice)."""
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                INSERT INTO findings (
                    report_hash, file_path, line, column, message,
                    checker_name, analyzer_name, severity, cert_rule_ids,
                    cert_guideline, bug_path_events, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(report_hash) DO UPDATE SET
                    file_path=excluded.file_path,
                    line=excluded.line,
                    column=excluded.column,
                    message=excluded.message,
                    checker_name=excluded.checker_name,
                    analyzer_name=excluded.analyzer_name,
                    severity=excluded.severity,
                    cert_rule_ids=excluded.cert_rule_ids,
                    cert_guideline=excluded.cert_guideline,
                    bug_path_events=excluded.bug_path_events
                """,
                (
                    finding.report_hash,
                    finding.file_path,
                    finding.line,
                    finding.column,
                    finding.message,
                    finding.checker_name,
                    finding.analyzer_name,
                    finding.severity,
                    json.dumps(finding.cert_rule_ids),
                    finding.cert_guideline,
                    json.dumps(
                        [vars(e) for e in finding.bug_path_events]
                    ),
                    finding.status.value,
                ),
            )
        self._conn.commit()

    def set_finding_status(self, report_hash: str, status: FindingStatus) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "UPDATE findings SET status = ? WHERE report_hash = ?",
                (status.value, report_hash),
            )
        self._conn.commit()

    def get_finding(self, report_hash: str) -> Finding | None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT * FROM findings WHERE report_hash = ?", (report_hash,)
            )
            row = cur.fetchone()
        return _row_to_finding(row) if row else None

    def all_findings(self) -> list[Finding]:
        with closing(self._conn.cursor()) as cur:
            cur.execute("SELECT * FROM findings ORDER BY file_path, line")
            rows = cur.fetchall()
        return [_row_to_finding(r) for r in rows]

    # -- Fix attempts -------------------------------------------------------

    def add_fix_attempt(self, attempt: FixAttempt) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO fix_attempts (
                    finding_hash, model_name, attempt_number, patch_text,
                    prompt_text, raw_model_response, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.finding_hash,
                    attempt.model_name,
                    attempt.attempt_number,
                    attempt.patch_text,
                    attempt.prompt_text,
                    attempt.raw_model_response,
                    attempt.created_at,
                ),
            )
        self._conn.commit()

    def attempts_for(self, finding_hash: str, model_name: str) -> list[FixAttempt]:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                SELECT * FROM fix_attempts
                WHERE finding_hash = ? AND model_name = ?
                ORDER BY attempt_number
                """,
                (finding_hash, model_name),
            )
            rows = cur.fetchall()
        return [
            FixAttempt(
                finding_hash=r["finding_hash"],
                model_name=r["model_name"],
                attempt_number=r["attempt_number"],
                patch_text=r["patch_text"],
                prompt_text=r["prompt_text"],
                raw_model_response=r["raw_model_response"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # -- Verification results ----------------------------------------------

    def add_verification_result(self, result: VerificationResult) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO verification_results (
                    finding_hash, model_name, attempt_number, stage_reached,
                    passed, detail, target_resolved, new_findings,
                    duration_seconds, created_at
                    , patch_text, touched_files, artifact_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.finding_hash,
                    result.model_name,
                    result.attempt_number,
                    result.stage_reached.value,
                    int(result.passed),
                    result.detail,
                    int(result.target_resolved),
                    json.dumps(
                        [_finding_to_dict(f) for f in result.new_findings]
                    ),
                    result.duration_seconds,
                    result.created_at,
                    result.patch_text,
                    json.dumps(result.touched_files),
                    result.artifact_path,
                ),
            )
        self._conn.commit()

    def all_verification_results(self) -> list[VerificationResult]:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT * FROM verification_results ORDER BY "
                "finding_hash, model_name, attempt_number"
            )
            rows = cur.fetchall()
        return [_row_to_verification_result(r) for r in rows]

    def distinct_model_names(self) -> list[str]:
        """Every model that has at least one recorded fix attempt, in the
        order they were first attempted -- used by the Scorer to know
        which models to include in a leaderboard without needing the
        original RunConfig on hand (e.g. when re-scoring a stored run)."""
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                "SELECT model_name FROM fix_attempts GROUP BY model_name "
                "ORDER BY MIN(id)"
            )
            rows = cur.fetchall()
        return [r["model_name"] for r in rows]

    def latest_verification_per_model(
        self, finding_hash: str
    ) -> dict[str, VerificationResult]:
        """Most recent attempt's result per model for one finding -- this
        is what "did model X ultimately resolve this finding" means, since
        earlier failed attempts are retried, not averaged."""
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                SELECT * FROM verification_results
                WHERE finding_hash = ?
                ORDER BY model_name, attempt_number
                """,
                (finding_hash,),
            )
            rows = cur.fetchall()
        latest: dict[str, VerificationResult] = {}
        for row in rows:
            result = _row_to_verification_result(row)
            latest[result.model_name] = result  # later attempt overwrites
        return latest


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "report_hash": finding.report_hash,
        "file_path": finding.file_path,
        "line": finding.line,
        "column": finding.column,
        "message": finding.message,
        "checker_name": finding.checker_name,
        "analyzer_name": finding.analyzer_name,
        "severity": finding.severity,
        "cert_rule_ids": finding.cert_rule_ids,
        "cert_guideline": finding.cert_guideline,
    }


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        report_hash=row["report_hash"],
        file_path=row["file_path"],
        line=row["line"],
        column=row["column"],
        message=row["message"],
        checker_name=row["checker_name"],
        analyzer_name=row["analyzer_name"],
        severity=row["severity"],
        cert_rule_ids=json.loads(row["cert_rule_ids"]),
        cert_guideline=row["cert_guideline"],
        bug_path_events=[
            BugPathEvent(**e) for e in json.loads(row["bug_path_events"])
        ],
        status=FindingStatus(row["status"]),
    )


def _row_to_verification_result(row: sqlite3.Row) -> VerificationResult:
    new_findings_raw = json.loads(row["new_findings"])
    return VerificationResult(
        finding_hash=row["finding_hash"],
        model_name=row["model_name"],
        attempt_number=row["attempt_number"],
        stage_reached=VerificationStage(row["stage_reached"]),
        passed=bool(row["passed"]),
        detail=row["detail"],
        target_resolved=bool(row["target_resolved"]),
        new_findings=[
            Finding(
                report_hash=f["report_hash"],
                file_path=f["file_path"],
                line=f["line"],
                column=f["column"],
                message=f["message"],
                checker_name=f["checker_name"],
                analyzer_name=f["analyzer_name"],
                severity=f["severity"],
                cert_rule_ids=f["cert_rule_ids"],
                cert_guideline=f["cert_guideline"],
            )
            for f in new_findings_raw
        ],
        duration_seconds=row["duration_seconds"],
        patch_text=row["patch_text"] if "patch_text" in row.keys() else "",
        touched_files=json.loads(row["touched_files"]) if "touched_files" in row.keys() else [],
        artifact_path=row["artifact_path"] if "artifact_path" in row.keys() else "",
        created_at=row["created_at"],
    )
