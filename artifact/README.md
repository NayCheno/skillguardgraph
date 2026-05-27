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
| Experiment scripts | `experiments/scripts/` | 9 scripts for benchmark, evaluation, tables |
| Unit tests | `experiments/tests/` | 31 tests for analyzers and policy engine |
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

No network access required.

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

Expected: the demo prints a JSON policy report to stdout, and all 31 unit
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
2. Runs all 31 unit tests (`pytest tests/ -q`).

### Mode 2: Main Reproduction (~30 minutes)

Reproduces all primary paper results (Tables 1–5).

```bash
make reproduce
```

What it does:
1. `make benchmark` — Builds 4010-sample benchmark (1000 benign, 3010 malicious across 7 attack classes, ~430 samples each).
2. `make validate` — Validates label integrity and class balance.
3. `make eval-main` — Runs detection evaluation (8 methods), ablation study (6 configs), and runtime red-team evaluation.
4. `make tables` — Generates formatted tables in plain text and LaTeX.

### Mode 3: Full Reproduction (~2+ hours)

Reproduces all paper results including ecosystem measurement.

```bash
make eval-all
```

What it does:
1. Everything in Mode 2.
2. `make ecosystem` — Builds 1200-sample synthetic ecosystem corpus from 5 sources.
3. `make triage` — Triages ecosystem findings, identifies risk patterns.

---

## Expected Outputs

### Main results (`results/main/`)

| File | Format | Description |
|---|---|---|
| `detector_eval.json` | JSON, ~2 KB | Precision, recall, F1, FPR for 8 detection methods |
| `ablation.json` | JSON, ~7 KB | Per-class recall and metrics for 6 ablation configs |
| `runtime_redteam.json` | JSON, ~2 KB | ASR, usability, and per-class runtime defense metrics |
| `tables.txt` | Text, ~3 KB | 5 formatted plain-text tables |
| `tables.tex` | LaTeX, ~3 KB | 5 LaTeX tables with labels for paper inclusion |

### Ecosystem results (`results/ecosystem/`)

| File | Format | Description |
|---|---|---|
| `ecosystem_triage.json` | JSON, ~1.7 MB | Full triage output for 1200 samples |
| `risk_patterns.json` | JSON, ~1.5 KB | Aggregated risk pattern rates and severity |

### Key numbers to verify

| Result | Expected |
|---|---|
| Benchmark size | 4010 samples (1000 benign + 3010 malicious, 7 classes) |
| Fusion F1 | 0.909 |
| Fusion FPR | 0.194 |
| FPR reduction vs naive union | 80.6% |
| Naive union F1 | 0.858 |
| Naive union FPR | 1.000 |
| Ablation: no_runtime ΔF1 | -0.291 |
| Runtime ASR | 0.000 |
| Task success rate | 0.806 |
| False block rate | 0.000 |
| Ecosystem corpus size | 1200 samples |
| Unit tests | 31 (all pass) |

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
