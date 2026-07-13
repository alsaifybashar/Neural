"""Reviewed remediation guidance for common CodeChecker findings."""

from __future__ import annotations


_RULES = {
    "bugprone-reserved-identifier": (
        "Reserved identifiers can collide with implementation names. Rename the "
        "declared identifier to a non-reserved name without changing behavior. "
        "Update every declaration, definition, using-directive, and code reference "
        "to the same symbol. A C/C++ identifier containing a double underscore is "
        "reserved; removing one underscore is an acceptable minimal remediation."
    ),
    "cert-msc51-cpp": (
        "Do not seed a pseudo-random generator with a predictable constant. Use an "
        "appropriate unpredictable seed while preserving the surrounding behavior."
    ),
    "clang-diagnostic-reserved-macro-identifier": (
        "Macro names beginning with an underscore followed by an uppercase "
        "letter are reserved to the implementation. Rename the reported macro "
        "and update every preprocessor occurrence of that same macro. Do not "
        "rename unrelated platform or standard-library macros merely because "
        "they also use reserved spelling."
    ),
}

_SYMBOL_WIDE_CHECKERS = {
    "bugprone-reserved-identifier",
    "clang-diagnostic-reserved-macro-identifier",
}


def remediation_for(checker_name: str, rule_ids: list[str]) -> str:
    if checker_name in _RULES:
        return _RULES[checker_name]
    rules = ", ".join(rule_ids) or "the reported analyzer rule"
    return (
        f"Resolve {rules} exactly as described by the analyzer. Preserve behavior, "
        "interfaces, and unrelated code; request more source when the remediation "
        "depends on declarations or callers not yet shown."
    )


def requires_complete_symbol_edit(checker_name: str) -> bool:
    return checker_name in _SYMBOL_WIDE_CHECKERS
