# Plan: LLM-Assisted Security Fix Pipeline & Model Evaluation Tool

## 1. Summary

A CLI tool that combines **CodeChecker** (static analysis for C/C++) with **LLMs** to automatically resolve security findings, verify that each fix is safe (compiles, passes tests, introduces no new findings), and produce structured, comparable results across multiple LLMs/providers. The core purpose is not just "auto-fix code" but **building a trustworthy, repeatable evaluation harness** for how well different models resolve real security issues without introducing regressions.

Decisions locked in from clarification:
- **Corpus**: Juliet C/C++ Test Suite (CWE-labeled, ground truth) + at least one real-world OSS project (ecological validity).
- **Verification gate**: build success → existing test suite passes → CodeChecker re-scan shows target finding resolved and no new findings introduced.
- **Models**: provider-agnostic — hosted APIs (Anthropic, OpenAI, etc.) and local/open-weight models (Ollama/vLLM), behind one adapter interface.
- **Fix strategy**: iterative agentic loop — model gets verification failures (build errors, test failures, new findings) fed back as context, bounded to N retries.
- **Deliverable**: CLI tool producing structured JSON/CSV + a generated HTML/Markdown report per run.
- **Scope**: MVP first — one real project + a Juliet subset (~50-100 cases), 2-3 models, full pipeline proven end-to-end before scaling.
- **Patch scope**: model sees the flagged function/file + CodeChecker's finding detail (CWE, message, analyzer trace); patch must be minimal and scoped to that one finding.
- **Metrics emphasis**: fix success rate per CWE category, and regression/new-vulnerability rate (safety is the primary "can we trust this" signal). Efficiency (attempts/latency/cost) is useful secondary data to capture even though not flagged as top priority, since it's nearly free to log alongside the above.

## 2. Architecture

```
                        ┌─────────────────┐
                        │   Orchestrator    │  (CLI entrypoint: `sectool run ...`)
                        └────────┬─────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌───────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  Scanner       │      │  Fix Dispatcher   │      │  Verifier          │
│ (CodeChecker   │─────▶│ (per finding,      │─────▶│ (build + test +   │
│  wrapper)      │      │  per model)        │      │  re-scan + diff)   │
└───────────────┘      └──────────────────┘      └──────────────────┘
        │                        │                        │
        │                        ▼                        │
        │              ┌──────────────────┐                │
        │              │  Model Adapter    │                │
        │              │  Layer (LiteLLM-  │                │
        │              │  style, pluggable)│                │
        │              └──────────────────┘                │
        ▼                                                   ▼
┌───────────────┐                                 ┌──────────────────┐
│ Finding Store  │◀────────────────────────────────│  Scorer/Reporter  │
│ (SQLite/JSON)  │                                 │ (per-CWE, safety,  │
└───────────────┘                                 │  leaderboard)      │
                                                    └──────────────────┘
```

### Components

1. **Scanner** — wraps `CodeChecker analyze` + `CodeChecker parse`, normalizes findings into an internal schema (file, line, CWE, checker name, severity, message, bug-path/trace). Runs once per target project to produce the baseline finding set.

2. **Finding Store** — durable record (SQLite or JSON-lines) of every finding, its status (open / attempted / fixed / failed / regressed), which model attempted it, how many retries, and links to each patch attempt. This is the backbone that makes results reproducible and re-runnable without re-scanning from scratch.

3. **Model Adapter Layer** — a single interface (`propose_fix(finding, code_context, prior_feedback) -> patch`) with concrete adapters per provider/model. Must support hosted APIs (Anthropic, OpenAI, etc.) and local/open-weight models (Ollama/vLLM) behind the same call shape, so adding a new model is a config entry, not a code change.

4. **Fix Dispatcher** — for a given finding + model, builds the prompt context (flagged function/file, CodeChecker's finding detail including CWE and analyzer trace, prior failure feedback if this is a retry), calls the Model Adapter, and extracts a patch (unified diff or full-function replacement — decide in Phase 0 spike, see §4).

5. **Verifier** — applies the patch to an isolated copy/worktree of the project, then runs, in order (short-circuiting on first failure so retries get the earliest, most actionable signal):
   1. Build (project's existing build system).
   2. Existing test suite (if present).
   3. CodeChecker re-scan on the changed file(s)/project — confirms the target finding is gone and diffs the full finding set for anything new.
   Each stage's failure output (compiler error, test failure, new finding) becomes the feedback given to the model on retry.

6. **Retry Loop** — bounded (e.g. default 3 attempts, configurable). Stops on: verified success, exhausted retries, or an unrecoverable error (e.g. model refuses / repeats identical patch). All attempts are recorded, not just the last one — needed for the "attempts to converge" data even though efficiency isn't the top-line metric.

7. **Scorer/Reporter** — aggregates the Finding Store into:
   - Per-model, per-CWE fix success rate.
   - Per-model regression rate (build breaks, test breaks, new findings introduced) — the primary trust signal.
   - Supplementary: attempts-to-converge, latency, token/cost per finding.
   - Output: JSON/CSV for machine consumption + a generated HTML/Markdown report with a leaderboard table.

## 3. Corpus & Test Harness Requirements

- **Juliet subset**: select ~50-100 test cases across a handful of CWEs relevant to your real target(s) (e.g. CWE-119/120 buffer overflow, CWE-416 use-after-free, CWE-476 NULL deref, CWE-190 integer overflow). Juliet cases are self-contained and already compile standalone, so they're the fastest path to a working verifier.
- **Real OSS project**: needs (a) a working build (CMake/Make/etc. reproducible in a container), (b) an existing test suite that runs in CI-like fashion, (c) CodeChecker already able to produce a clean compile_commands.json for it. Pick a project you can build once and cache — Phase 0 should validate this before any model work starts.
- Both corpora run through the *same* Scanner → Dispatcher → Verifier → Scorer pipeline; Juliet gives ground-truth labels (does the fix actually address the known-injected CWE), the OSS project gives real-world signal without ground truth (verification relies purely on build/tests/re-scan diff).

## 4. Open Implementation Questions (to resolve in Phase 0, not blocking planning)

- Patch format: full unified diff (higher risk of hallucinated line numbers) vs. "replace this function" (safer to apply, slightly less flexible) — spike both against 5-10 Juliet cases before committing.
- Isolation mechanism for applying/building patches per attempt: git worktree per attempt vs. container per attempt vs. plain temp-dir copy. Recommend git worktree for source projects with git history, container if the OSS project's build has heavy system dependencies.
- How much of CodeChecker's bug-path/trace to include in the prompt (full trace vs. summarized) — affects prompt size/cost and may affect fix quality; worth a small ablation.
- Timeout/cost caps per finding (wall-clock and $ budget) to prevent a bad retry loop from running away, especially once local/open-weight models are in the mix with potentially slower inference.

## 5. Phased Rollout

**Phase 0 — Spike (1 target, no retries, 1 model)**
- Stand up CodeChecker against one Juliet case and one OSS project; confirm compile_commands.json and clean baseline scan.
- Wire a single model adapter, single-shot (no retry loop yet), and the three-stage Verifier.
- Goal: prove the full scan → fix → verify path works end-to-end on ~5 findings before investing further.

**Phase 1 — MVP**
- Juliet subset (~50-100 cases) + 1 real OSS project.
- 2-3 models (mix of hosted + local, per your requirement) behind the adapter layer.
- Full retry loop, Finding Store, Scorer, and a basic generated report.
- Manually spot-check a sample of scoring decisions against your own reading of the diffs, to sanity-check the Verifier isn't producing false positives/negatives (e.g. a "pass" that's actually a no-op patch, or a "regression" that's actually an unrelated flaky test).

**Phase 2 — Scale out**
- Expand to full Juliet suite (or a larger curated slice) and additional OSS projects.
- Add more models to the roster.
- Harden cost/timeout controls, parallelize dispatch across findings/models.

**Phase 3 — Reporting polish**
- Leaderboard views (per-CWE breakdown, safety/regression rate front and center per your priority).
- Optional: surface attempts/latency/cost as secondary columns, not headline metrics.

## 6. Risks / Things to Watch

- **False sense of safety**: passing build+tests+re-scan is strong but not proof of security — a model could satisfy all three gates with a fix that's syntactically different but still exploitable in a way none of the three checks exercise. Worth noting explicitly in any report generated by the tool so results aren't over-claimed.
- **Flaky tests / flaky builds** in the real OSS project will look like "regressions" caused by the model's patch. Need a baseline flakiness check (run build+tests once on unmodified code) before attributing failures to the patch.
- **CodeChecker false positives** in the original baseline scan mean some "findings" sent to the model aren't real bugs — the model "fixing" them (or not) shouldn't be scored the same as a true positive. Consider tagging Juliet cases with known ground truth and, for the OSS project, spot-checking a sample of baseline findings for true/false positive rate before it's used for scoring.
- **Local/open-weight model infra**: adds an operational dependency (Ollama/vLLM serving) — Phase 0 should confirm this is running reliably before it's counted on for Phase 1 comparisons.
