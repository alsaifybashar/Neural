"""Validate structured model edits and generate unified diffs deterministically."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class StructuredEdit:
    path: str
    old_text: str
    new_text: str
    expected_occurrences: int = 1


@dataclass
class EditBuildResult:
    valid: bool
    detail: str = ""
    patch_text: str = ""
    touched_files: tuple[str, ...] = ()


def build_patch_from_edits(root: Path, edits: list[StructuredEdit]) -> EditBuildResult:
    root = Path(root).resolve()
    by_path: dict[str, list[StructuredEdit]] = {}
    for edit in edits:
        candidate = Path(edit.path)
        if candidate.is_absolute() or ".." in candidate.parts or not edit.path:
            return EditBuildResult(False, f"Edit path is outside the project: {edit.path}")
        try:
            (root / candidate).resolve().relative_to(root)
        except ValueError:
            return EditBuildResult(False, f"Edit path is outside the project: {edit.path}")
        if not edit.old_text or edit.old_text == edit.new_text:
            return EditBuildResult(False, f"Edit for {edit.path} has no effective replacement.")
        by_path.setdefault(candidate.as_posix(), []).append(edit)

    chunks: list[str] = []
    for path, file_edits in by_path.items():
        target = root / path
        if not target.is_file():
            return EditBuildResult(False, f"Edit target does not exist: {path}")
        before = target.read_text(errors="replace")
        after = before
        for edit in file_edits:
            count, replaced = _replace_exact(
                after, edit.old_text, edit.new_text, edit.expected_occurrences
            )
            if count != edit.expected_occurrences:
                return EditBuildResult(
                    False,
                    f"Edit for {path} expected {edit.expected_occurrences} exact old_text "
                    f"match(es), found {count}. Request authoritative source and retry.",
                )
            after = replaced
        chunks.extend(difflib.unified_diff(
            before.splitlines(keepends=True), after.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}", n=3,
        ))
    patch = "".join(chunks)
    if not patch:
        return EditBuildResult(False, "Structured edits generated an empty patch.")
    return EditBuildResult(True, patch_text=patch, touched_files=tuple(by_path))


def _replace_exact(
    source: str, old_text: str, new_text: str, expected: int
) -> tuple[int, str]:
    """Prefer complete-line matching for a single authoritative source line."""
    if "\n" not in old_text and "\r" not in old_text:
        lines = source.splitlines(keepends=True)
        matches = [
            index for index, line in enumerate(lines)
            if line.rstrip("\r\n") == old_text
        ]
        if matches:
            if len(matches) == expected:
                for index in matches:
                    ending = lines[index][len(lines[index].rstrip("\r\n")):]
                    lines[index] = new_text + ending
            return len(matches), "".join(lines)
    count = source.count(old_text)
    replaced = source.replace(old_text, new_text, expected) if count == expected else source
    return count, replaced


def uncovered_context_ids(
    root: Path, edits: list[StructuredEdit], context_ids: set[str]
) -> set[str]:
    """Return searched path:line identifiers not touched by any exact edit."""
    root = Path(root)
    covered: set[str] = set()
    for edit in edits:
        try:
            source = (root / edit.path).read_text(errors="replace")
        except OSError:
            continue
        search_from = 0
        for _ in range(edit.expected_occurrences):
            index = source.find(edit.old_text, search_from)
            if index < 0:
                break
            start_line = source.count("\n", 0, index) + 1
            end_line = start_line + edit.old_text.count("\n")
            covered.update(
                context_id for context_id in context_ids
                if context_id.startswith(f"{edit.path}:")
                and start_line <= int(context_id.rsplit(":", 1)[1]) <= end_line
            )
            search_from = index + len(edit.old_text)
    return context_ids - covered
