"""Provider-neutral source-inspection tools used by the bounded LLM loop."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from sectool.context import _SOURCE_EXTENSIONS, extract_code_context


@dataclass
class ContextToolResult:
    ok: bool
    action: str
    payload: dict

    def as_prompt_text(self) -> str:
        return json.dumps(
            {"ok": self.ok, "action": self.action, **self.payload},
            ensure_ascii=True,
        )


class ContextToolExecutor:
    def __init__(
        self, project_root: Path, compile_commands_path: Path | None = None,
        focus_path: Path | None = None,
    ):
        self.root = Path(project_root).resolve()
        self.compile_commands_path = compile_commands_path
        self.focus_path = Path(focus_path).resolve() if focus_path else None

    def execute(self, action: dict) -> ContextToolResult:
        name = action.get("action", "")
        if name == "search_symbol":
            return self.search_symbol(str(action.get("symbol", "")), int(action.get("offset", 0)))
        if name == "read_range":
            return self.read_range(
                str(action.get("path", "")), int(action.get("start_line", 1)),
                int(action.get("end_line", 1)),
            )
        if name == "read_definition":
            return self.read_definition(str(action.get("path", "")), int(action.get("line", 1)))
        if name == "inspect_build":
            return self.inspect_build(str(action.get("path", "")))
        return ContextToolResult(False, name, {"error": f"Unknown context action: {name}"})

    def search_symbol(self, symbol: str, offset: int = 0, limit: int = 50) -> ContextToolResult:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
            return ContextToolResult(False, "search_symbol", {"error": "Invalid C/C++ identifier."})
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        hits = []
        for path in self._candidate_source_paths():
            if not path.is_file() or path.suffix.lower() not in _SOURCE_EXTENSIONS:
                continue
            if any(part.startswith(".") for part in path.relative_to(self.root).parts):
                continue
            try:
                source = path.read_text(errors="replace")
                lines = source.splitlines()
            except OSError:
                continue
            if not pattern.search(source):
                continue
            syntax_hits = _syntax_identifier_hits(path, source, symbol)
            candidates = syntax_hits or [
                (number, "textual-fallback")
                for number, text in enumerate(lines, 1) if pattern.search(text)
            ]
            for number, role in candidates:
                if 1 <= number <= len(lines):
                    rel = path.relative_to(self.root).as_posix()
                    hits.append({
                        "context_id": f"{rel}:{number}", "path": rel,
                        "line": number, "text": lines[number - 1], "role": role,
                    })
        page = hits[offset:offset + limit]
        next_offset = offset + len(page)
        return ContextToolResult(True, "search_symbol", {
            "symbol": symbol, "total": len(hits), "results": page,
            "truncated": next_offset < len(hits),
            "next_offset": next_offset if next_offset < len(hits) else None,
            "scope": "focused translation-unit subtree plus compilation-database files",
        })

    def read_range(self, path: str, start: int, end: int) -> ContextToolResult:
        target = self._safe_file(path)
        if target is None:
            return ContextToolResult(False, "read_range", {"error": "Path is outside the project or missing."})
        lines = target.read_text(errors="replace").splitlines()
        start = max(1, start)
        end = min(len(lines), max(start, end), start + 199)
        numbered = [f"{n:>6} | {lines[n - 1]}" for n in range(start, end + 1)]
        return ContextToolResult(True, "read_range", {
            "path": path, "start_line": start, "end_line": end,
            "context_id": f"{path}:{start}-{end}", "source": "\n".join(numbered),
        })

    def read_definition(self, path: str, line: int) -> ContextToolResult:
        target = self._safe_file(path)
        if target is None:
            return ContextToolResult(False, "read_definition", {"error": "Path is outside the project or missing."})
        context = extract_code_context(target, line)
        return self.read_range(path, context.start_line, context.end_line)

    def inspect_build(self, path: str) -> ContextToolResult:
        if self.compile_commands_path is None or not Path(self.compile_commands_path).is_file():
            return ContextToolResult(False, "inspect_build", {"error": "Compilation database is unavailable."})
        try:
            entries = json.loads(Path(self.compile_commands_path).read_text(errors="replace"))
        except (OSError, json.JSONDecodeError):
            return ContextToolResult(False, "inspect_build", {"error": "Compilation database is unreadable."})
        matches = []
        for entry in entries:
            file_path = Path(entry.get("file", ""))
            if file_path.name == Path(path).name or str(file_path).endswith(path):
                matches.append({
                    "file": entry.get("file", ""),
                    "directory": entry.get("directory", ""),
                    "command": entry.get("command") or entry.get("arguments", []),
                })
        return ContextToolResult(True, "inspect_build", {"path": path, "commands": matches[:10]})

    def _safe_file(self, path: str) -> Path | None:
        candidate = Path(path)
        if candidate.is_absolute() or ".." in candidate.parts:
            return None
        target = (self.root / candidate).resolve()
        try:
            target.relative_to(self.root)
        except ValueError:
            return None
        return target if target.is_file() else None

    def _candidate_source_paths(self) -> list[Path]:
        candidates: set[Path] = set()
        if self.focus_path is not None and self.focus_path.is_relative_to(self.root):
            candidates.update(self.focus_path.parent.rglob("*"))
        if self.compile_commands_path is not None and Path(self.compile_commands_path).is_file():
            try:
                entries = json.loads(Path(self.compile_commands_path).read_text(errors="replace"))
                parents = []
                for entry in entries:
                    candidate = Path(entry.get("file", ""))
                    if not candidate.is_absolute():
                        candidate = Path(entry.get("directory", self.root)) / candidate
                    resolved = candidate.resolve()
                    if resolved.is_relative_to(self.root):
                        parents.append(str(resolved.parent))
                        candidates.add(resolved)
                if parents and not candidates:
                    common = Path(os.path.commonpath(parents))
                    if common.is_relative_to(self.root):
                        candidates.update(common.rglob("*"))
            except (OSError, json.JSONDecodeError, ValueError):
                pass
        if not candidates:
            candidates.update(self.root.rglob("*"))
        return [
            path for path in sorted(candidates)
            if path.is_file()
            and path.suffix.lower() in _SOURCE_EXTENSIONS
            and not any(part.startswith(".") for part in path.relative_to(self.root).parts)
        ]


def _syntax_identifier_hits(path: Path, source: str, symbol: str) -> list[tuple[int, str]]:
    try:
        from tree_sitter import Language, Parser
        if path.suffix.lower() == ".c":
            import tree_sitter_c as grammar
        else:
            import tree_sitter_cpp as grammar
        data = source.encode()
        tree = Parser(Language(grammar.language())).parse(data)
    except (ImportError, AttributeError, TypeError, ValueError):
        return []
    accepted = {
        "identifier", "namespace_identifier", "type_identifier",
        "field_identifier", "qualified_identifier",
    }
    hits: set[tuple[int, str]] = set()
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in accepted and data[node.start_byte:node.end_byte].decode(errors="replace") == symbol:
            hits.add((node.start_point.row + 1, node.type))
        stack.extend(node.children)
    return sorted(hits)
