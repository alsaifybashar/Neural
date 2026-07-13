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

import json
import re
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

    boundary = _find_function_boundary_tree_sitter(Path(file_path), lines, line)
    if boundary is None:
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


def _find_function_boundary_tree_sitter(
    file_path: Path, lines: list[str], line: int
) -> tuple[int, int] | None:
    """Use a real C/C++ syntax tree when the optional parser is available."""
    try:
        from tree_sitter import Language, Parser
        if file_path.suffix.lower() == ".c":
            import tree_sitter_c as grammar
        else:
            import tree_sitter_cpp as grammar
        parser = Parser(Language(grammar.language()))
        tree = parser.parse("\n".join(lines).encode())
    except (ImportError, AttributeError, TypeError, ValueError):
        return None

    target_row = max(0, line - 1)
    best = None
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.start_point.row <= target_row <= node.end_point.row:
            if node.type in {"function_definition", "declaration", "namespace_definition"}:
                best = node
            stack.extend(node.children)
    if best is None:
        return None
    return best.start_point.row + 1, best.end_point.row + 1


# -- Cross-file identifier occurrences ---------------------------------------
# A fix that renames a declaration (namespace, function, macro) must update
# every reference or the build gate can never pass -- e.g. a Juliet testcase
# namespace declared in 72a.cpp is re-declared in 72b.cpp and called from
# main.cpp. These helpers find those other locations so the prompt can show
# them to the model up front.

_SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}
_QUOTED_IDENTIFIER_RE = re.compile(r"'([A-Za-z_][A-Za-z0-9_]{3,})'")

_MAX_OCCURRENCE_FILES = 5
_MAX_SNIPPETS_PER_FILE = 3
_MAX_TOTAL_SNIPPET_LINES = 40
_SNIPPET_CONTEXT_LINES = 3


@dataclass
class OccurrenceSnippet:
    file_path: str  # Repo-relative -- ready for display and diff headers.
    start_line: int  # 1-indexed first line of `text` in the file.
    text: str
    relationship: str = "identifier reference"


@dataclass
class DependencyContext:
    snippets: list[OccurrenceSnippet]
    compile_command: str = ""
    truncated: bool = False


def identifiers_from_message(message: str) -> list[str]:
    """Identifiers the finding's message names in single quotes (CodeChecker
    checkers consistently quote them, e.g. "identifier 'X' is reserved").
    Only plausible C/C++ identifiers of >= 4 chars, so short quoted
    fragments like 'if' never trigger a project-wide search."""
    return list(dict.fromkeys(_QUOTED_IDENTIFIER_RE.findall(message)))


def find_identifier_occurrences(
    project_root: Path,
    identifiers: list[str],
    exclude_path: Path,
    exclude_range: tuple[int, int] | None = None,
) -> list[OccurrenceSnippet]:
    """Whole-word occurrences of `identifiers` in the project's source
    files, as bounded numbered-snippet groups (files/snippets/lines caps --
    prompt cost must stay bounded even for a common identifier).

    Only the already displayed range in the flagged file is skipped. Other
    parts of that same file remain essential evidence (for example a later
    using-directive referencing a renamed namespace).
    """
    if not identifiers:
        return []
    project_root = Path(project_root).resolve()
    exclude = Path(exclude_path).resolve()
    word_re = re.compile(
        r"\b(?:" + "|".join(re.escape(i) for i in identifiers) + r")\b"
    )

    snippets: list[OccurrenceSnippet] = []
    total_lines = 0
    files_used = 0
    for path in _candidate_files(project_root, exclude):
        if files_used >= _MAX_OCCURRENCE_FILES or total_lines >= _MAX_TOTAL_SNIPPET_LINES:
            break
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        hit_lines = [
            n for n, text in enumerate(lines, start=1)
            if word_re.search(text)
            and not (
                path.resolve() == exclude
                and (
                    exclude_range is None
                    or exclude_range[0] <= n <= exclude_range[1]
                )
            )
        ]
        if not hit_lines:
            continue

        files_used += 1
        rel = str(path.relative_to(project_root))
        for start, end in _merged_ranges(hit_lines, len(lines))[:_MAX_SNIPPETS_PER_FILE]:
            if total_lines >= _MAX_TOTAL_SNIPPET_LINES:
                break
            snippet_lines = end - start + 1
            if total_lines + snippet_lines > _MAX_TOTAL_SNIPPET_LINES:
                break
            snippets.append(OccurrenceSnippet(
                file_path=rel,
                start_line=start,
                text="\n".join(lines[start - 1:end]),
            ))
            total_lines += end - start + 1
    return snippets


def build_dependency_context(
    project_root: Path,
    source_path: Path,
    finding_message: str,
    compile_commands_path: Path | None = None,
    max_files: int = _MAX_OCCURRENCE_FILES,
    max_lines: int = _MAX_TOTAL_SNIPPET_LINES,
    primary_range: tuple[int, int] | None = None,
    focus_line: int | None = None,
    focus_column: int | None = None,
    force_symbol_at_location: bool = False,
    bug_path_events: list = (),
    include_head_lines: int = 40,
) -> DependencyContext:
    """Collect bounded cross-file evidence relevant to a finding.

    CodeChecker's compilation database supplies the exact translation-unit
    command. Identifier references and local includes then identify source
    that must participate in coherent multi-file changes. This intentionally
    has a dependency-free fallback so context collection cannot block a run.
    """
    project_root = Path(project_root).resolve()
    source_path = Path(source_path).resolve()
    compile_command = _compile_command_for(compile_commands_path, source_path)

    identifiers = identifiers_from_message(finding_message)
    if not identifiers and force_symbol_at_location and focus_line is not None:
        symbol = identifier_at_location(source_path, focus_line, focus_column or 1)
        if symbol:
            identifiers.append(symbol)
    identifiers = list(dict.fromkeys(identifiers))
    snippets = find_identifier_occurrences(
        project_root, identifiers, source_path, exclude_range=primary_range
    )

    trace_snippets = _bug_path_snippets(
        project_root, bug_path_events, source_path, primary_range
    )
    include_snippets = _local_include_snippets(
        project_root, source_path, include_head_lines
    )
    combined = trace_snippets + include_snippets + snippets
    selected: list[OccurrenceSnippet] = []
    used_files: set[str] = set()
    used_lines = 0
    truncated = False
    for snippet in combined:
        line_count = len(snippet.text.splitlines())
        if (snippet.file_path not in used_files and len(used_files) >= max_files) or used_lines + line_count > max_lines:
            truncated = True
            continue
        selected.append(snippet)
        used_files.add(snippet.file_path)
        used_lines += line_count
    return DependencyContext(selected, compile_command, truncated)


def _compile_command_for(path: Path | None, source_path: Path) -> str:
    if path is None or not Path(path).is_file():
        return ""
    try:
        entries = json.loads(Path(path).read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return ""
    source = source_path.resolve()
    for entry in entries:
        directory = Path(entry.get("directory", "."))
        candidate = Path(entry.get("file", ""))
        if not candidate.is_absolute():
            candidate = directory / candidate
        try:
            matches = candidate.resolve() == source
        except OSError:
            matches = False
        if matches:
            return entry.get("command") or " ".join(entry.get("arguments", []))
    return ""


def identifier_at_location(source_path: Path, line: int, column: int = 1) -> str:
    """Return the C/C++ identifier at (or immediately after) a finding column."""
    try:
        lines = source_path.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    if line < 1 or line > len(lines):
        return ""
    text = lines[line - 1]
    index = max(0, min(len(text), column - 1))
    matches = list(re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", text))
    containing = [match for match in matches if match.start() <= index < match.end()]
    if containing:
        return containing[0].group(0)
    following = next((match for match in matches if match.start() >= index), None)
    return following.group(0) if following else ""


def _local_include_snippets(
    project_root: Path, source_path: Path, head_lines: int
) -> list[OccurrenceSnippet]:
    try:
        lines = source_path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    result: list[OccurrenceSnippet] = []
    for line in lines:
        match = re.match(r'\s*#\s*include\s*"([^"]+)"', line)
        if not match:
            continue
        candidates = [source_path.parent / match.group(1), project_root / match.group(1)]
        header = next((p for p in candidates if p.is_file()), None)
        if header is None:
            continue
        header_lines = header.read_text(errors="replace").splitlines()[:head_lines]
        result.append(OccurrenceSnippet(
            file_path=str(header.resolve().relative_to(project_root)),
            start_line=1,
            text="\n".join(header_lines),
            relationship="local include",
        ))
    return result


def _bug_path_snippets(
    project_root: Path,
    events: list,
    source_path: Path,
    primary_range: tuple[int, int] | None,
) -> list[OccurrenceSnippet]:
    """Source snippets for analyzer trace events outside the primary window."""
    snippets: list[OccurrenceSnippet] = []
    seen: set[tuple[str, int]] = set()
    for event in events:
        event_path = Path(getattr(event, "file_path", ""))
        if not event_path.is_absolute():
            event_path = project_root / event_path
        try:
            event_path = event_path.resolve()
            relative = event_path.relative_to(project_root).as_posix()
        except (OSError, ValueError):
            continue
        line = int(getattr(event, "line", 0) or 0)
        if not event_path.is_file() or line < 1 or (relative, line) in seen:
            continue
        if (
            event_path == source_path
            and primary_range is not None
            and primary_range[0] <= line <= primary_range[1]
        ):
            continue
        lines = event_path.read_text(errors="replace").splitlines()
        start, end = max(1, line - 3), min(len(lines), line + 3)
        snippets.append(OccurrenceSnippet(
            file_path=relative,
            start_line=start,
            text="\n".join(lines[start - 1:end]),
            relationship=f"analyzer trace event at line {line}",
        ))
        seen.add((relative, line))
    return snippets


def _candidate_files(project_root: Path, exclude: Path):
    """Project source files, the flagged file's own directory first,
    hidden directories skipped."""
    def source_files(base: Path, recursive: bool):
        pattern = "**/*" if recursive else "*"
        for p in sorted(base.glob(pattern)):
            if p.suffix.lower() not in _SOURCE_EXTENSIONS or not p.is_file():
                continue
            if any(part.startswith(".") for part in p.relative_to(project_root).parts):
                continue
            yield p

    sibling_dir = exclude.parent
    seen: set[Path] = set()
    if exclude.is_file() and exclude.is_relative_to(project_root):
        seen.add(exclude)
        yield exclude
    if sibling_dir.is_relative_to(project_root):
        for p in source_files(sibling_dir, recursive=False):
            seen.add(p)
            yield p
    for p in source_files(project_root, recursive=True):
        if p not in seen:
            yield p


def _merged_ranges(hit_lines: list[int], file_len: int) -> list[tuple[int, int]]:
    """Expand each hit by the snippet context radius and merge overlaps,
    so a cluster of nearby references becomes one snippet, not several."""
    ranges: list[tuple[int, int]] = []
    for line in hit_lines:
        start = max(1, line - _SNIPPET_CONTEXT_LINES)
        end = min(file_len, line + _SNIPPET_CONTEXT_LINES)
        if ranges and start <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))
    return ranges


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
