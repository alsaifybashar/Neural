"""Maps CodeChecker checker names to the SEI CERT C/C++ rules they enforce.

CodeChecker's report JSON (`CodeChecker parse --export json`) tells you which
*checker* fired (e.g. `checker_name: "bugprone-exception-escape"`), not which
CERT rule that corresponds to. The checker -> CERT rule mapping instead
lives in CodeChecker's own checker *label* data, which is queryable via:

    CodeChecker checkers --guideline sei-cert-c --details -o json

This returns a JSON array of objects shaped like:

    {
      "status": "enabled",
      "name": "bugprone-exception-escape",
      "analyzer": "clang-tidy",
      "description": "...",
      "labels": [
        "doc_url:https://...",
        "guideline:sei-cert-cpp",
        "sei-cert-cpp:msc53-cpp",   <- the specific rule this checker covers
        "severity:MEDIUM"
      ]
    }

(verified against CodeChecker's source: analyzer/codechecker_analyzer/cli/
checkers.py `__print_checkers_json_format` / `__guideline_to_label`, and the
label data in config/labels/analyzers/*.json, since the tool isn't installed
in every environment this code runs in and the docs alone don't show the
JSON shape.)

The rule id lives after the guideline-name prefix in the matching label,
lower-cased and hyphenated (e.g. "msc53-cpp"); we upper-case it to match the
canonical SEI CERT rule id spelling ("MSC53-CPP").
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CERT_GUIDELINES = ("sei-cert-c", "sei-cert-cpp")


class CertMappingError(RuntimeError):
    """Raised when `CodeChecker checkers` can't be run or parsed.

    Kept distinct from a bare RuntimeError so callers (and tests) can catch
    "the CERT mapping is unavailable" specifically, e.g. to fail a run
    loudly rather than silently dispatching un-tagged findings.
    """


@dataclass
class CertRuleMap:
    """checker_name -> (guideline, [rule_id, ...]) for one guideline query."""

    guideline: str
    checker_to_rules: dict[str, list[str]] = field(default_factory=dict)


class CertRuleMapper:
    """Builds and caches the checker-name -> CERT-rule-id mapping.

    Queries `CodeChecker checkers` once per guideline and caches the merged
    result to a JSON file so repeated runs (and offline test fixtures)
    don't need CodeChecker installed just to re-derive the same mapping.
    """

    def __init__(
        self,
        codechecker_bin: str = "CodeChecker",
        guidelines: tuple[str, ...] = DEFAULT_CERT_GUIDELINES,
        cache_path: Path | None = None,
    ):
        self.codechecker_bin = codechecker_bin
        self.guidelines = guidelines
        self.cache_path = cache_path
        # checker_name -> {"guideline": str, "rule_ids": [str, ...]}
        self._map: dict[str, dict] | None = None

    def build(self, force_refresh: bool = False) -> dict[str, dict]:
        """Return the checker_name -> {guideline, rule_ids} mapping,
        loading from cache if present and not force_refresh."""
        if self._map is not None and not force_refresh:
            return self._map

        if not force_refresh and self.cache_path and self.cache_path.exists():
            self._map = json.loads(self.cache_path.read_text())
            return self._map

        merged: dict[str, dict] = {}
        for guideline in self.guidelines:
            for checker_name, rule_ids in self._query_guideline(guideline).items():
                entry = merged.setdefault(
                    checker_name, {"guideline": guideline, "rule_ids": []}
                )
                for rule_id in rule_ids:
                    if rule_id not in entry["rule_ids"]:
                        entry["rule_ids"].append(rule_id)

        self._map = merged
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(merged, indent=2, sort_keys=True))
        return merged

    def rules_for(self, checker_name: str) -> tuple[str, list[str]]:
        """(guideline, rule_ids) for a checker, or ("", []) if it isn't
        covered by any configured CERT guideline."""
        mapping = self.build()
        entry = mapping.get(checker_name)
        if entry is None:
            return "", []
        return entry["guideline"], entry["rule_ids"]

    def _query_guideline(self, guideline: str) -> dict[str, list[str]]:
        try:
            proc = subprocess.run(
                [
                    self.codechecker_bin,
                    "checkers",
                    "--guideline",
                    guideline,
                    "--details",
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            raise CertMappingError(
                f"Failed to query CodeChecker for guideline '{guideline}': {exc}"
            ) from exc

        try:
            checkers = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise CertMappingError(
                f"Unexpected output from 'CodeChecker checkers --guideline "
                f"{guideline} --details -o json': {exc}"
            ) from exc

        return parse_checker_listing(checkers, guideline)


def parse_checker_listing(
    checkers: list[dict], guideline: str
) -> dict[str, list[str]]:
    """Pure function extracted from CertRuleMapper so the label-parsing
    logic (the part most likely to break across CodeChecker versions) can
    be unit-tested against a canned JSON fixture without invoking the
    CodeChecker binary at all.
    """
    prefix = f"{guideline}:"
    result: dict[str, list[str]] = {}
    for checker in checkers:
        name = checker["name"]
        rule_ids = [
            label[len(prefix):].upper()
            for label in checker.get("labels", [])
            if label.startswith(prefix)
        ]
        if rule_ids:
            result[name] = rule_ids
    return result
