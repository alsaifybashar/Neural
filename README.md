# sectool

CodeChecker + LLM pipeline for resolving and evaluating how well different
LLMs fix SEI CERT C/C++ security findings, without introducing regressions.

See [`PLAN.md`](PLAN.md) for the full design rationale and phased rollout.
This README covers what's implemented and how to run it.

## What it does

1. **Scan** a C/C++ project with CodeChecker, restricted to checkers that
   cover the SEI CERT C and C++ Coding Standards, and tag every finding
   with the specific CERT rule(s) it violates (e.g. `STR31-C`).
2. **Dispatch** each finding to one or more LLMs (Anthropic, OpenAI, or a
   local/open-weight model via Ollama), asking for a minimal patch scoped
   to that single finding.
3. **Verify** every proposed patch through four gates, in order: does it
   apply cleanly, does the project still build, do its existing tests
   still pass, and does a CodeChecker re-scan confirm the finding is gone
   with no new findings introduced. A patch is only ever recorded as
   "fixed" if it clears all four.
4. **Retry**, feeding the specific verification failure back to the model,
   up to a configurable number of attempts per finding.
5. **Score and report**: per-model fix rate broken down by CERT rule, and
   per-model regression rate (a patch that "fixes" the target finding but
   breaks the build/tests/introduces new findings) -- the regression rate
   is the primary signal for "can we trust this model".

## Setup

System dependencies (CodeChecker, clang-tidy, cppcheck) need `sudo` and
must be installed manually -- see [`docs/SETUP.md`](docs/SETUP.md).

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running

```sh
cp docs/config.example.json my-run.json   # edit project root / build+test commands / models
sectool scan my-run.json                  # scan only, sanity-check CERT findings are matched
sectool run my-run.json                   # full pipeline: scan, dispatch, verify, score, report
sectool report results/my-run/findings.db -o results/my-run   # re-render a report, no re-run
```

`sectool run` writes `report.json` / `report.csv` / `report.html` plus a
`findings.db` SQLite database (every finding, every fix attempt's prompt
and raw response, and every verification result) into `output_dir`.

## Module map

```
sectool/
  config.py           RunConfig / ProjectConfig / ModelConfig (one JSON file drives a run)
  context.py           Extracts the function/file source shown to a model for a finding
  dispatcher.py         The bounded retry loop tying a model + the Verifier together
  scorer.py             Aggregates a FindingStore into per-model/per-CERT-rule metrics
  report.py             Renders Scorer output as JSON/CSV/HTML
  cli.py                `sectool scan|run|report`

  findings/
    schema.py            Finding / FixAttempt / VerificationResult data model
    store.py              SQLite persistence for all of the above

  scanner/
    codechecker.py         Wraps `CodeChecker log|analyze|parse`
    cert_mapping.py         Maps checker names -> SEI CERT rule ids

  models/
    base.py                 ModelAdapter interface + FixRequest/FixResponse
    prompt.py                 Shared prompt template (same prompt, every model)
    anthropic_adapter.py       Claude via the `anthropic` SDK
    openai_adapter.py           GPT via the `openai` SDK
    ollama_adapter.py            Local/open-weight models via Ollama's HTTP API
    registry.py                  ModelConfig.provider -> concrete adapter

  verifier/
    verifier.py             Orchestrates the four verification gates
    worktree.py               Isolates each attempt in a disposable `git worktree`
    patch.py                    Applies a model's unified diff via `git apply`
    build.py                     Runs the project's build/test commands
```

## Tests

Offline, no CodeChecker/API keys/network required -- everything that talks
to CodeChecker or an LLM is exercised against canned fixtures instead
(see `tests/fixtures/`, and the docstrings in `scanner/codechecker.py` and
`scanner/cert_mapping.py` for exactly where those fixtures' JSON shapes
were verified against CodeChecker's own source):

```sh
pytest
```

## Current status

Phase 0 (per PLAN.md) is implemented: the full scan -> dispatch -> verify
-> score -> report pipeline runs end-to-end against any git-backed C/C++
project once the system dependencies in `docs/SETUP.md` are installed.
Not yet done: running it against the actual Juliet subset + a real OSS
project (Phase 1), which needs the system tools installed first.
