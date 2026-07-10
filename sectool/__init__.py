"""sectool: CodeChecker + LLM pipeline for resolving SEI CERT C/C++ findings.

This package implements the tool described in PLAN.md: it runs CodeChecker
against a C/C++ project, filters findings down to those covered by the SEI
CERT C/CPP secure coding standards, dispatches each finding to one or more
LLMs for a fix, verifies every proposed fix (build, existing tests, and a
CodeChecker re-scan) before accepting it, and scores/reports how each model
performed. The scoring is the point of the tool: it exists to answer "which
model can we trust to fix security issues without breaking or re-breaking
the code", not just to auto-patch a codebase.

Package layout (see each module's docstring for details):

    sectool.findings   - Finding/FixAttempt/VerificationResult data model
                          and the SQLite-backed FindingStore.
    sectool.scanner     - CodeChecker CLI wrapper + SEI CERT rule mapper.
    sectool.models      - Provider-agnostic LLM adapter layer.
    sectool.verifier    - Build + test + re-scan verification pipeline.
    sectool.dispatcher  - Bounded retry loop wiring models + verifier.
    sectool.scorer      - Aggregates a FindingStore into comparison metrics.
    sectool.report      - Renders the scorer's output as JSON/CSV/HTML.
    sectool.cli         - `sectool` command line entrypoint.
"""

__version__ = "0.1.0"
