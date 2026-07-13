# sectool

`sectool` is a CLI-first workflow for taking C/C++ security findings from
CodeChecker, giving an LLM enough source context to propose a fix, validating
that fix in an isolated checkout, and recording whether the model actually
resolved the issue without breaking the project.

The goal is not just to ask a model for a patch. The goal is to make the task
understandable, observable, repeatable, and measurable.

See [`PLAN.md`](PLAN.md) for the larger design rationale and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the deeper technical
walkthrough. This README describes the implemented tool and how to run it.

## Why this exists

Static analyzers are good at finding security-relevant code patterns, but the
raw finding is often not enough for an LLM to produce a correct fix. A model can
see a warning at one line, miss related declarations or call sites, and return a
patch that compiles nowhere or changes the wrong thing.

`sectool` closes that gap by:

- Mapping CodeChecker reports to SEI CERT C/C++ rules.
- Grouping findings that share one root-cause symbol into a single fix task.
- Supplying focused source context, analyzer trace data, compile command data,
  curated remediation guidance, and syntax-aware source search tools.
- Requiring provider-neutral JSON actions instead of free-form prose patches.
- Generating unified diffs itself from exact structured replacements.
- Verifying each attempt through patch, build, test, and CodeChecker re-scan
  gates before calling anything fixed.
- Persisting prompts, raw responses, tool calls, patches, verification results,
  reports, and transcripts so runs can be audited later.

The failure mode this is designed to prevent is the model "fixing" a symptom it
does not understand. For example, a reserved-identifier warning on a namespace
must update every syntax reference to that namespace, not just the declaration
line shown by CodeChecker.

## How it works

The normal full pipeline is:

1. **Preflight** checks CodeChecker, git, and the configured model connection.
2. **Scan** runs `CodeChecker log`, `CodeChecker analyze`, and `CodeChecker parse`.
3. **Map** filters/tag findings by SEI CERT C/C++ guideline labels.
4. **Select** lets the user choose findings interactively, by `--select`, or all
   findings in non-interactive `-y` mode.
5. **Group** turns related analyzer reports into root-cause fix tasks.
6. **Dispatch** sends each task to the configured model with bounded retries.
7. **Investigate** lets the model request source-search/read/build-context
   actions before proposing a fix.
8. **Edit** accepts only exact structured replacements and generates the diff in
   the host tool.
9. **Validate** checks the diff and then verifies it in a disposable git
   worktree.
10. **Report** writes database, JSON, CSV, HTML, transcript, and verified patch
    artifacts.

The CLI prints each major step while it runs. Long-running work is surfaced with
spinners, progress bars, prompt/response panels, context-tool events, and
gate-by-gate verification output.

## Setup

System dependencies such as CodeChecker, clang-tidy, and cppcheck need to be
installed separately. See [`docs/SETUP.md`](docs/SETUP.md).

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Create a run config from the example:

```sh
cp docs/config.example.json my-run.json
```

Important config fields:

- `project.root`: C/C++ checkout to scan.
- `project.build_command`: full build command CodeChecker observes and the
  verifier repeats.
- `project.test_command`: optional project test command.
- `output_dir`: where scans, transcripts, database, reports, and patch artifacts
  are written.
- `cert_guidelines`: CodeChecker guideline labels, normally `sei-cert-c` and
  `sei-cert-cpp`.
- `max_attempts_per_finding`: retry budget per root-cause task.
- `context_max_files` / `context_max_lines`: initial dependency context budget.
- `max_context_rounds`: maximum model-requested context actions per attempt.
- `models`: exactly one model per run. Use separate output directories when
  comparing models.

Supported providers are Anthropic, OpenAI, and Ollama. Provider-specific
adapters share the same prompt and JSON action protocol so model comparisons are
not mixed with prompt differences.

## Commands

```sh
sectool scan my-run.json
sectool run my-run.json
sectool run my-run.json --select "1,3,5-7"
sectool run my-run.json -y --no-show-prompts
sectool report results/my-run/findings.db -o results/my-run
sectool show results/my-run/findings.db <finding_hash> [--model NAME]
```

`sectool scan` runs CodeChecker and lists matched SEI CERT findings. It does not
call any model.

`sectool run` executes the full workflow. In an interactive terminal it uses
controlled mode: after every model response, the user can apply and verify,
retry with a note, skip the finding, or quit the run. With `-y`, it dispatches
automatically and never modifies the original working tree.

`sectool report` re-scores and re-renders an existing `findings.db` without
running CodeChecker or any model.

`sectool show` replays one finding's stored prompt, raw response, patch, and
verification history.

## Model Communication

The model is not asked to return a free-form patch as its primary interface.
Each request contains:

- CodeChecker checker, analyzer, severity, location, message, CERT rule IDs,
  and bug path events.
- The source window around the finding, shown with real file line numbers.
- Related occurrence snippets from dependency context.
- The compile command for the translation unit when available.
- Reviewed remediation guidance for known checker/rule combinations.
- Grouped target locations when multiple findings share one root cause.
- Retry feedback from the earliest failed verification gate.
- A transcript of prior context-tool requests and results in the same attempt.

The response must be one JSON object. Before proposing a fix, the model may ask
for one context action per round:

```json
{"action":"search_symbol","symbol":"name","offset":0}
{"action":"read_range","path":"repo/relative.cpp","start_line":1,"end_line":80}
{"action":"read_definition","path":"repo/relative.cpp","line":42}
{"action":"inspect_build","path":"repo/relative.cpp"}
```

When it has enough context, the model returns:

```json
{
  "action": "propose_fix",
  "root_cause": "short explanation",
  "edits": [
    {
      "path": "repo/relative.cpp",
      "old_text": "exact source text",
      "new_text": "replacement source text",
      "expected_occurrences": 1,
      "context_ids": ["repo/relative.cpp:42"]
    }
  ],
  "occurrence_dispositions": [
    {
      "context_id": "repo/relative.cpp:42",
      "disposition": "edited",
      "reason": "renamed the namespace declaration"
    }
  ]
}
```

The host validates the structured edit, applies exact text replacements, and
builds the unified diff deterministically. This prevents common model errors
such as wrong hunk numbers, malformed diffs, path traversal, empty patches, or
renaming only a substring that happened to match.

Legacy unified-diff responses are still parsed for compatibility, but the
current prompt and verifier are built around structured edits.

## Understanding The Issue

The tool improves model understanding in three layers.

First, the initial prompt explains the security task, not just the line number.
It includes the analyzer message, CERT mapping, bug path, compile command,
source window, dependency snippets, grouped targets, and known remediation
guidance.

Second, the model can ask bounded follow-up questions through source tools. The
important one for symbol-wide fixes is `search_symbol`, which performs
syntax-aware identifier search using tree-sitter when available and falls back
to textual search. Results include `context_id`, path, line, source text, role,
total count, truncation status, and next offset.

Third, the dispatcher enforces completeness. For checkers that require complete
symbol edits, such as `bugprone-reserved-identifier`, the model must search the
flagged symbol, retrieve all pages if results are truncated, and provide a
disposition for every returned occurrence. A symbol rename is rejected before
verification if any searched occurrence is missing or marked unchanged.

This is the fix for the earlier failure mode where the model renamed only a few
namespace declarations and call sites but missed another same-file reference and
header declarations. The model did not have complete context, and the host did
not force evidence that all references were accounted for. The current workflow
does both.

## Attempts And Feedback

Each root-cause task gets up to `max_attempts_per_finding` attempts.

For every attempt:

1. The dispatcher builds a `FixRequest`.
2. The model may spend up to `max_context_rounds` source-inspection rounds.
3. The model proposes structured edits.
4. The host validates and converts them into a unified diff.
5. In controlled mode, the user decides whether to verify, retry, skip, or quit.
6. The verifier runs the four gates.
7. On failure, the earliest actionable failure detail becomes feedback for the
   next attempt.

Retries are not blind. Patch failures include patch validation or `git apply`
detail. Build and test failures are annotated with relevant post-patch source
snippets when file/line references can be resolved. Re-scan failures tell the
model whether the target finding remained or whether new findings were
introduced.

Fatal provider errors, such as a bad key or unavailable model, stop dispatching
that model for the rest of the run instead of burning every finding's retry
budget.

## Validation And Verification

There are two validation layers.

Before verification, `sectool` validates the model response:

- JSON action can be parsed.
- Context round limit was respected.
- Required symbol searches were completed.
- Every searched occurrence has a disposition.
- Structured edit paths are repo-relative and inside the project.
- `old_text` is exact, non-empty, and changes to different text.
- Expected occurrence counts match the source.
- Generated patch is non-empty and syntactically valid.

Then the verifier runs in a disposable `git worktree` so a bad patch cannot
modify the user's checkout:

1. **Patch gate**: apply the diff with `git apply`. Tolerant apply strategies
   exist for line-number bookkeeping errors, but the strict result is preferred.
2. **Build gate**: run `project.build_command`.
3. **Test gate**: run `project.test_command`, or record the stage as skipped if
   no test command is configured.
4. **Re-scan gate**: run CodeChecker again and compare against the baseline.

A patch is recorded as `FIXED` only if it applies, builds, passes tests or has no
tests configured, removes every grouped target finding, and introduces no new
findings compared with the baseline.

## Results And Artifacts

Each run writes to `output_dir`:

- `findings.db`: SQLite database containing findings, attempts, prompts, raw
  responses, patches, verification results, and statuses.
- `report.json`: machine-readable scoring output.
- `report.csv`: spreadsheet-friendly scoring output.
- `report.html`: browsable report.
- `transcript-YYYYMMDD-HHMMSS.jsonl`: event-by-event transcript of the run when
  transcripts are enabled.
- `cert_rule_map.json`: cached CodeChecker-to-CERT mapping.
- `scan/`: CodeChecker scan work directory and compilation database.
- `verified-patches/`: patches that passed all verification gates.

Interactive runs ask whether to apply each verified patch to the original
working tree after dispatch completes. Application is refused if a touched file
has uncommitted changes or the patch no longer applies.

Non-interactive `-y` runs retain verified patch artifacts but never modify the
original working tree.

## Scoring

Scoring is computed from the persisted database, not from live process state.
This makes `sectool report` side-effect free.

Per model, the report includes:

- `total`: findings with a recorded verification result.
- `fixed`: findings whose latest attempt passed all gates.
- `failed`: findings that did not resolve the target.
- `regressed`: findings where the target was resolved but new findings were
  introduced.
- `skipped`: findings skipped before completion.
- `fix_rate`: `fixed / total`.
- `regression_rate`: `regressed / total`.
- `avg_attempts_to_resolve`: average attempt number for fixed findings.
- per-SEI-CERT-rule totals and fix rates.

Regression rate is treated as a primary trust signal. A model that removes the
target finding by breaking the build, breaking tests, or introducing new
security findings is not considered successful.

## Module Map

```text
sectool/
  cli.py                    CLI commands: scan, run, report, show
  config.py                 RunConfig, ProjectConfig, ModelConfig
  context.py                Initial source and dependency context collection
  context_tools.py          Model-requested source inspection actions
  dispatcher.py             Attempt loop, context loop, edit validation handoff
  events.py                 Event dataclass and fan-out helpers
  interactive.py            Finding selection and review prompts
  preflight.py              CodeChecker, git, and model availability checks
  report.py                 JSON, CSV, and HTML report writer
  review.py                 Human review decision types
  scorer.py                 Model/rule scoring
  security_rules.py         Curated remediation guidance and checker policies
  transcript.py             JSONL event transcript writer
  ui.py                     Rich terminal rendering

  findings/
    schema.py               Finding, FixAttempt, VerificationResult models
    store.py                SQLite persistence
    tasks.py                Root-cause grouping

  scanner/
    codechecker.py          CodeChecker log/analyze/parse wrapper
    cert_mapping.py         Checker-to-SEI-CERT mapping

  models/
    base.py                 Provider-neutral model interface and parsing
    prompt.py               Shared prompt template and JSON action protocol
    anthropic_adapter.py    Anthropic SDK adapter
    openai_adapter.py       OpenAI SDK adapter
    ollama_adapter.py       Ollama HTTP adapter
    registry.py             Provider-to-adapter factory

  verifier/
    application.py          Safe application of verified patches to checkout
    build.py                Build/test command execution
    edits.py                Structured edit validation and diff generation
    feedback.py             Source-annotated verifier feedback
    patch.py                Patch validation and git apply strategies
    verifier.py             Patch/build/test/rescan verification gates
    worktree.py             Disposable git worktree isolation
```

## Testing

The test suite is offline. It does not require CodeChecker, API keys, or
network access; scanner and model behavior are tested with fixtures and scripted
adapters.

```sh
pytest
```

The current tests cover scanner parsing, CERT mapping, prompt construction,
context collection, context tools, grouping, patch application, structured edit
generation, verifier feedback, transcript writing, scoring, report generation,
interactive selection, and CLI/report behavior.

Recent validation also covered the concrete Juliet reserved-identifier case:
syntax search found all nine references to the namespace, deterministic
structured edits generated a five-file patch, `git apply` accepted it, and the
target Juliet testcase compiled.
