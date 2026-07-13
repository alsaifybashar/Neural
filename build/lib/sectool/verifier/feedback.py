"""Turns failure text that *names* source locations into failure text that
*shows* them.

Both `git apply` errors and compiler/test diagnostics reference locations
as `path:line`, usually in files the model has never seen (a build break in
72b.cpp after a rename made in 72a.cpp). Feeding the bare error back makes
the retry a guess; appending the referenced files' actual, line-numbered
content gives the model the exact text its next diff must match. The same
mechanism serves the patch gate (see verifier/patch.py) and the build/test
gates (see verifier/verifier.py), differing only in the intro sentence.
"""

from __future__ import annotations

import re
from pathlib import Path

# gcc/clang diagnostics ("src/a.c:12:5: error: ...") and git apply's
# "error: patch failed: src/a.c:12". A path may be absolute (worktree) or
# relative to wherever the build command ran.
_LOCATION_RE = re.compile(
    r"(?:error: patch failed: |^|\s)"
    r"([\w./\\-]+\.(?:c|cc|cpp|cxx|h|hh|hpp)):(\d+)",
    re.MULTILINE,
)

_SNIPPET_RADIUS = 8  # Lines shown either side of a referenced line.
_MAX_REFS = 5


def annotate_with_source(root: Path, detail: str, intro: str) -> str:
    """`detail` plus, when it references resolvable `path:line` locations,
    `intro` and a numbered snippet of each referenced file. Returns
    `detail` unchanged when nothing resolves -- annotation must never turn
    usable feedback into an exception."""
    sections: list[str] = []
    seen: set[tuple[str, int]] = set()
    for path_str, line_str in _LOCATION_RE.findall(detail):
        if len(sections) >= _MAX_REFS:
            break
        resolved = _resolve(root, path_str)
        if resolved is None:
            continue
        display = _display_path(root, resolved)
        line = int(line_str)
        key = (display, line // (_SNIPPET_RADIUS * 2) or 1)  # collapse
        # near-duplicate refs into one snippet per region.
        if key in seen:
            continue
        seen.add(key)
        snippet = _numbered_snippet(resolved, line)
        if snippet:
            sections.append(f"{display} around line {line}:\n{snippet}")

    if not sections:
        return detail
    return detail + "\n\n" + intro + "\n" + "\n\n".join(sections)


def _resolve(root: Path, path_str: str) -> Path | None:
    candidate = Path(path_str)
    if candidate.is_absolute():
        return candidate if candidate.is_file() else None
    direct = root / candidate
    if direct.is_file():
        return direct
    # Build output is often relative to the directory make ran in, not the
    # project root -- fall back to locating the file by its trailing parts.
    suffix = candidate.parts
    for match in root.rglob(candidate.name):
        if match.is_file() and match.parts[-len(suffix):] == suffix:
            return match
    return None


def _display_path(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)


def _numbered_snippet(path: Path, line: int) -> str:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if not lines:
        return ""
    start = max(1, line - _SNIPPET_RADIUS)
    end = min(len(lines), line + _SNIPPET_RADIUS)
    return "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(start, end + 1))
