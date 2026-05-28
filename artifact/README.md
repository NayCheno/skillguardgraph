# SkillGuardGraph — Artifact Package

**Artifact for:** Cross-Layer Evidence Fusion for Detecting and Containing
Malicious Skills in LLM Agent Ecosystems

This package contains all code, data, configurations, and expected outputs
needed to reproduce every result reported in the paper.

---

## Artifact Inventory

| Component | Path | Description |
|---|---|---|
| Core library | `experiments/src/skillguardgraph/` | Evidence graph, analyzers, policy engine |
| Experiment scripts | `experiments/scripts/` | 15 scripts for benchmark, evaluation, significance, ecosystem collection, and analysis |
| Unit tests | `experiments/tests/` | 73 tests for analyzers, graph, and policy engine |
| Configuration | `experiments/configs/` | Policy rules and sandbox settings |
| Example inputs | `experiments/examples/` | Sample manifests and runtime traces |
| Makefile | `experiments/Makefile` | Reproducible experiment targets |
| Dockerfile | `Dockerfile` | Docker image for smoke-test reproduction |
| Environment | `environment.yml` | Conda environment specification |
| Expected outputs | `EXPECTED_OUTPUTS.md` | Descriptions of all output files and metrics |
| Paper | `paper/` | LaTeX source, figures, bibliography |
| Documentation | `docs/` | Threat model, benchmark card, metrics, etc. |

---

## Requirements

### Hardware

- Any modern machine (x86_64 or ARM64).
- 2 GB RAM minimum, 4 GB recommended.
- 500 MB disk space for full reproduction.
- No GPU required.

### Software

- **Python 3.10 or later** (any OS: Linux, macOS, Windows).
- No external Python packages required beyond the standard library.
- `pytest>=8` for running unit tests.
- Git (to clone the repository).

**Optional:**
- **Docker** — a `Dockerfile` is provided for containerized smoke-test reproduction.
- **Conda** — an `environment.yml` is provided for environment setup.

Network access is not required for smoke tests or synthetic reproduction. The real public ecosystem measurement step (`make real-ecosystem`, `make real-ecosystem-large`, or `make eval-all`) requires outbound access to GitHub's public APIs/raw content endpoints, npm registry APIs, PyPI JSON endpoints, and Hugging Face Space metadata/file endpoints. If available, set `GITHUB_TOKEN` and `HF_TOKEN` to reduce rate-limit failures during larger crawls.

---

## Quick Start for Artifact Reviewers

```bash
# 1. Clone and enter the repository
git clone <repo-url>
cd skillguardgraph/experiments

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install the package
pip install -e ".[dev]"

# 4. Run the smoke test (5 minutes)
make smoke
```

Expected: the demo prints a JSON policy report to stdout, and all 109 unit
tests pass.

### Alternative: Docker

```bash
docker build -t skillguardgraph .
docker run --rm skillguardgraph
```

### Alternative: Conda

```bash
conda env create -f environment.yml
conda activate skillguardgraph
cd experiments && make smoke
```

---

## Three Run Modes

### Mode 1: Smoke Test (~5 minutes)

Verifies the system is functional. No benchmark building or full evaluation.

```bash
make smoke
```

What it does:
1. Runs `run_demo.py` — scans a sample manifest and evaluates a sample trace.
2. Runs all 120 unit tests (`pytest tests/ -q`).

### Mode 2: Main Reproduction (~30 minutes)

Reproduces all primary paper results (Tables 1–12).

```bash
make reproduce
```

What it does:
1. `make benchmark` — Builds 4010-sample benchmark (1000 benign, 3010 malicious across 7 attack classes, ~430 samples each).
2. `make validate` — Validates label integrity and class balance.
3. `make eval-main` — Runs detection evaluation (8 methods), ablation study (6 configs), runtime red-team evaluation, local runtime harness, local sandbox harness, third-party public-code sandbox fixtures, bounded corpus-derived package sandbox cases, public-advisory cross-checking, bounded public remote endpoint probing, bounded GitHub repo sandbox execution, bounded remote task execution, bounded TypeScript repo execution, bootstrap CI, and generalization stress checks.
4. `make tables` — Generates formatted tables in plain text and LaTeX.

### Mode 3: Full Reproduction (~2+ hours)

Reproduces all paper results including ecosystem measurement and real-corpus statistics.

```bash
make eval-all
```

What it does:
1. Everything in Mode 2.
2. `make ecosystem` — Builds 1200-sample synthetic ecosystem corpus from 5 sources.
3. `make triage` — Triages ecosystem findings, identifies risk patterns.
4. `make real-ecosystem` — Collects a 1,000-artifact passive multi-source corpus (GitHub MCP repositories + npm MCP packages + discovered PyPI MCP packages + Hugging Face Spaces + Smithery hosted-registry entries + official MCP Registry entries), writes a data card, and records real-finding triage inputs.

A supplementary large-batch command is also available: `make real-ecosystem-large` collects a 2,000-artifact passive corpus into `real_ecosystem_large_*` outputs without replacing the reviewer-friendly 1,000-artifact batch. An additional `make real-ecosystem-xl` target collects a 3,000-artifact four-source corpus into `real_ecosystem_xl_*` outputs. A `make real-ecosystem-5k` target now checks in a 5,000-artifact quota-tuned corpus, and `make real-ecosystem-10k` checks in a 10,000-artifact quota-tuned corpus. These larger targets use `--resume` so partially warmed caches can survive upstream rate limits.
---

## Expected Outputs

### Main results (`results/main/`)

| File | Format | Description |
|---|---|---|
| `detector_eval.json` | JSON, ~20 KB | Precision, recall, F1, FPR, AUROC/AUPRC, threshold sweep for 8 detection methods |
| `ablation.json` | JSON, ~7 KB | Per-class recall and metrics for 6 ablation configs |
| `runtime_redteam.json` | JSON, ~2 KB | ASR, usability, and per-class runtime defense metrics |
| `failure_analysis.json` | JSON, ~1 KB | False-positive/false-negative counts and evidence path attribution |
| `runtime_harness.json` | JSON, ~3 KB | Local instrumented toy runtime harness metrics |
| `sandbox_harness.json` | JSON, ~2 KB | Local isolated sandbox harness metrics |
| `third_party_sandbox.json` | JSON, ~3 KB | Archive-backed third-party public-code sandbox fixture metrics |
| `corpus_package_sandbox.json` | JSON, ~4 KB | Bounded corpus-derived third-party package sandbox metrics |
| `public_advisory_audit.json` | JSON, ~2 KB | Public-advisory cross-check for the main real public corpus |
| `remote_endpoint_audit.json` | JSON, ~2 KB | Bounded public remote MCP endpoint audit metrics |
| `github_repo_sandbox.json` | JSON, ~2 KB | Bounded source-available GitHub repo sandbox metrics |
| `significance_tests.json` | JSON, ~1 KB | McNemar test and paired-bootstrap comparison for fusion vs weighted voting |
| `typescript_repo_sandbox.json` | JSON, ~2 KB | Bounded source-available TypeScript repo sandbox metrics |
| `remote_task_audit.json` | JSON, ~2 KB | Bounded harmless remote MCP tool-call audit metrics |
| `generalization_eval.json` | JSON, ~120 KB | Held-out-template, hard-negative, mutation-robustness, and label-leakage checks |
| `tables.txt` | Text, ~10 KB | 12 formatted plain-text tables |
| `tables.tex` | LaTeX, ~10 KB | 12 LaTeX tables with labels for paper inclusion |
| `completion_audit.json` | JSON, ~4 KB | Current-state completion audit summary |
| `completion_audit.md` | Markdown, ~1 KB | Human-readable completion audit report |

### Ecosystem results (`results/ecosystem/`)

| File | Format | Description |
|---|---|---|
| `ecosystem_triage.json` | JSON, ~1.7 MB | Full synthetic triage output for 1200 samples |
| `risk_patterns.json` | JSON, ~1.5 KB | Synthetic aggregated risk pattern rates and severity |
| `real_ecosystem_samples.jsonl` | JSONL, variable | Passive real public MCP artifact sample records |
| `real_ecosystem_results.json` | JSON, ~3 KB | Real-corpus aggregated counts, per-source severity distribution, and top passive findings |
| `real_ecosystem_data_card.json` | JSON, ~2 KB | Source/date/version/license/dedup collection metadata |
| `real_high_risk_triage.json` | JSON, ~3 KB | Manual triage notes for all HIGH-severity real findings |
| `real_ecosystem_large_results.json` | JSON, ~4 KB | Supplementary 2,000-artifact aggregate counts and per-source severity distribution |
| `real_ecosystem_large_data_card.json` | JSON, ~2 KB | Supplementary 2,000-artifact source/date/version/license/dedup metadata |
| `real_ecosystem_xl_results.json` | JSON, ~5 KB | Supplementary 3,000-artifact aggregate counts and per-source severity distribution |
| `real_ecosystem_xl_data_card.json` | JSON, ~2 KB | Supplementary 3,000-artifact source/date/version/license/dedup metadata |
| `real_ecosystem_5k_results.json` | JSON, ~6 KB | Supplementary 5,000-artifact aggregate counts and per-source severity distribution |
| `real_ecosystem_5k_data_card.json` | JSON, ~2 KB | Supplementary 5,000-artifact source/date/version/license/dedup metadata |
| `real_ecosystem_10k_results.json` | JSON, ~8 KB | Supplementary 10,000-artifact aggregate counts and per-source severity distribution |
| `real_ecosystem_10k_data_card.json` | JSON, ~2 KB | Supplementary 10,000-artifact source/date/version/license/dedup metadata |

### Key numbers to verify

| Result | Expected |
|---|---|
| Benchmark size | 4010 samples (1000 benign + 3010 malicious, 7 classes) |
| Fusion Precision / Recall / F1 | 1.000 / 1.000 / 1.000 |
| Fusion FPR | 0.000 |
| Fusion AUROC / AUPRC | 1.000 / 0.986 |
| FPR reduction vs naive union | 100.0% |
| Naive union F1 / FPR | 0.858 / 1.000 |
| Weighted voting F1 / FPR | 0.936 / 0.208 |
| Ablation: no_runtime ΔF1 | -0.639 |
| Runtime ASR | 0.000 |
| Task success rate | 1.000 |
| False block rate | 0.000 |
| Third-party fixture sandbox | 3 fixtures, 3 archive resolutions, 1 blocked subprocess, 0 unsafe egress |
| Corpus-derived package sandbox | 3 PyPI cases, 3 archive resolutions, 2 client tool calls, 1 blocked subprocess, 0 unsafe egress |
| Unit tests | 120 (all pass) |
| Public advisory audit | 2 advisories tracked, 1 corpus match, 0 currently vulnerable matches |
| Public remote endpoint audit | 4 endpoints, 2 initialize+tools/list successes, 2 protected rejections |
| GitHub repo sandbox | 2 GitHub cases, tool registry total 18, blender delegate observed |
| TypeScript repo sandbox | 2 TypeScript cases, tool registry total 4, CLI delegate observed |
| Completion audit | generated on demand |
| Public remote task audit | 2 harmless tool calls succeeded, 1 structured result observed |
| Ecosystem corpus size | 1200 synthetic + 1000 real public artifacts (300 GitHub + 200 npm + 150 discovered PyPI + 150 Hugging Face Spaces + 100 Smithery hosted-registry entries + 100 official MCP Registry entries) |
| Supplementary scaled corpus | 2000 real public artifacts (1200 GitHub + 500 npm + 300 Hugging Face Spaces) |
| Supplementary XL corpus | 3000 real public artifacts (1999 GitHub + 600 npm + 20 PyPI + 381 Hugging Face Spaces) |
| Supplementary 5k corpus | 5000 real public artifacts (2600 GitHub + 2000 npm + 20 PyPI + 380 Hugging Face Spaces) |
| Supplementary 10k corpus | 10000 real public artifacts (4000 GitHub + 4000 npm + 1620 PyPI + 380 Hugging Face Spaces) |

See `EXPECTED_OUTPUTS.md` for complete output documentation with example
snippets and field-level descriptions.

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'skillguardgraph'`

Ensure you ran `pip install -e ".[dev]"` from the `experiments/` directory,
or set `PYTHONPATH=src` when running scripts directly.

### `FileNotFoundError` when running `make tables`

Run `make eval-main` first. `make tables` reads JSON results that are
produced by the evaluation scripts.

### `make eval-all` fails midway

Each Makefile target can be run independently. Run the failing step
directly to see the error. All targets are idempotent — re-running overwrites
previous results.

### Python version errors

The codebase requires Python 3.10+ (uses `match` statements and modern
type hints). Check with `python --version`.

### `pytest` not found

Install it: `pip install pytest>=8`, or use `pip install -e ".[dev]"`
which includes it as a dev dependency.

---

## License

Research use only. The benchmark and code may be used for academic
reproduction, extension, and comparison. Offensive use is prohibited.
Derived datasets must maintain the same ethical constraints.
See `experiments/SECURITY_ETHICS.md` and `docs/ethics_protocol.md`.

---

## Ethics

- **All data is synthetic.** No real credentials, real enterprise data,
  or real user information appears anywhere in this artifact.
- **No network calls.** All experiments run entirely locally. No data
  leaves your machine.
- **Sinkhole domains only.** Any network references in the benchmark
  point to `*.sinkhole.test`, `*.example.invalid`, or `127.0.0.1`.
- **No operational payloads.** Attack samples are non-operational by
  design. They demonstrate detection patterns, not exploitation.
- **Sandbox isolation.** Dynamic experiments run in containers with no
  host filesystem or network access.

For the complete ethics protocol, see `docs/ethics_protocol.md`.
