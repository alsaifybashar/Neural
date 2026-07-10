# Setup

`sectool`'s Python package is installed and unit-tested already (see
`../pyproject.toml` and `../tests/`). What's left is installing the system
tools it shells out to: CodeChecker itself, and the underlying static
analyzers CodeChecker orchestrates (clang-tidy, cppcheck, and a
Clang/LLVM toolchain for the Clang Static Analyzer). These require `sudo`
and were **not** installed as part of building this tool, since the
sandbox this was built in has no passwordless sudo -- run the steps below
yourself.

## 1. Install the static analyzers (Ubuntu/Debian)

```sh
sudo apt update
sudo apt install -y clang clang-tidy cppcheck
```

Verify:

```sh
clang-tidy --version
cppcheck --version
```

## 2. Install CodeChecker

CodeChecker itself is a Python tool and does **not** need sudo -- install
it into the same virtualenv as `sectool`:

```sh
source .venv/bin/activate   # the venv this project's pyproject.toml was installed into
pip install codechecker
CodeChecker version
```

If you'd rather build from source (e.g. to track a specific CodeChecker
version), see https://github.com/Ericsson/codechecker#install-guide.

## 3. Confirm the SEI CERT checker guideline is available

This is the mapping `sectool.scanner.cert_mapping.CertRuleMapper` queries
at runtime (see that module's docstring for how the exact CLI/JSON shape
was verified against CodeChecker's source):

```sh
CodeChecker checkers --guideline sei-cert-c --details -o json | head -c 500
CodeChecker checkers --guideline           # lists all available guidelines;
                                            # sei-cert-c / sei-cert-cpp should
                                            # appear here.
```

If these guideline names ever change in a future CodeChecker release,
update `DEFAULT_CERT_GUIDELINES` in `sectool/config.py` and
`sectool/scanner/cert_mapping.py`.

## 4. Model access

Set whichever of these you plan to evaluate (see `docs/config.example.json`
for how each maps to a `ModelConfig`):

```sh
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
```

For local/open-weight models, install and run Ollama
(https://ollama.com/download), then pull a model:

```sh
ollama pull llama3:70b
```

No API key is needed for the Ollama adapter; it talks to
`http://localhost:11434` by default (override via a model's `base_url` in
the config).

## 5. Smoke-test the pipeline (Phase 0)

Once the above is installed, validate scanning against a small project
before spending API budget on model calls:

```sh
cp docs/config.example.json my-run.json
# edit my-run.json: set project.root, build_command, test_command
sectool scan my-run.json
```

This should print how many CodeChecker findings were found in total and
how many matched the SEI CERT guidelines. If it reports 0 CERT findings on
a project you know has some, double-check `build_command` actually invokes
the compiler (CodeChecker's `log` step only sees files that are actually
compiled) and that step 3 above showed checkers for your guidelines.

Once `scan` looks right, run the full pipeline (this does make real model
API calls):

```sh
sectool run my-run.json
```

Note that `sectool run`'s Verifier requires `project.root` to be a git
repository (it isolates every patch attempt in a disposable `git
worktree` -- see `sectool/verifier/worktree.py`). If your target project
isn't already a git repo, `git init && git add -A && git commit -m
"baseline"` in it first.
