"""Extracts the source code shown to a model for one finding.

Per the tool's design (see PLAN.md), a model sees the flagged function (not
the whole project) so its patch stays scoped and attributable to a single
finding. C/C++ has no cheap, dependency-free way to find "the enclosing
function" short of a real parser, so this uses a brace-depth heuristic:
scan backward from the finding's line for what looks like a function
signature at brace-depth 0, then scan forward for the matching closing
brace. This is good enough for typical, reasonably-formatted C/C++ and is
not meant to replace a real AST -- if it can't confidently find a function
boundary, it falls back to a fixed line window around the finding, which is
always safe (if less precise) context.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_FALLBACK_WINDOW_LINES = 60
_MAX_SCAN_LINES = 2000  # Guard against pathological inputs (e.g. a
# minified/generated file with no reasonable "function" to extract).

_CONTROL_KEYWORDS = ("if", "for", "while", "switch", "else", "do")


@dataclass
class CodeContext:
    text: str
    start_line: int  # 1-indexed, inclusive
    end_line: int  # 1-indexed, inclusive
    is_whole_file: bool


def extract_code_context(file_path: Path, line: int) -> CodeContext:
    lines = Path(file_path).read_text(errors="replace").splitlines()
    if not lines:
        return CodeContext(text="", start_line=0, end_line=0, is_whole_file=True)

    if len(lines) <= _FALLBACK_WINDOW_LINES * 2:
        return CodeContext(
            text="\n".join(lines), start_line=1, end_line=len(lines), is_whole_file=True
        )

    boundary = _find_function_boundary(lines, line)
    if boundary is not None:
        start, end = boundary
        return CodeContext(
            text="\n".join(lines[start - 1 : end]),
            start_line=start,
            end_line=end,
            is_whole_file=False,
        )

    start = max(1, line - _FALLBACK_WINDOW_LINES)
    end = min(len(lines), line + _FALLBACK_WINDOW_LINES)
    return CodeContext(
        text="\n".join(lines[start - 1 : end]),
        start_line=start,
        end_line=end,
        is_whole_file=False,
    )


def _find_function_boundary(lines: list[str], line: int) -> tuple[int, int] | None:
    """Best-effort (start_line, end_line), both 1-indexed inclusive, or
    None if no confident function boundary was found near `line`."""
    idx = line - 1
    if idx >= len(lines):
        return None

    start_idx = None
    scan_floor = max(0, idx - _MAX_SCAN_LINES)
    for i in range(idx, scan_floor - 1, -1):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith(("//", "*", "/*", "#")):
            continue
        if stripped.startswith(_CONTROL_KEYWORDS):
            continue
        looks_like_signature = (
            "(" in stripped
            and not stripped.endswith(";")
            and (stripped.endswith("{") or stripped.endswith(")"))
        )
        if looks_like_signature:
            start_idx = i
            break

    if start_idx is None:
        return None

    depth = 0
    opened = False
    end_idx = None
    for i in range(start_idx, min(len(lines), start_idx + _MAX_SCAN_LINES)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth > 0:
            opened = True
        if opened and depth == 0:
            end_idx = i
            break

    if end_idx is None or end_idx < idx:
        return None  # Didn't find a closing brace, or it closed before
        # reaching the finding's own line -- don't trust the boundary.

    return start_idx + 1, end_idx + 1
