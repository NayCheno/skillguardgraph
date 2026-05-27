# SkillGuardGraph — Research Prototype

Cross-layer evidence fusion for detecting and containing malicious skills
in LLM agent ecosystems.

This repository contains the full experimental artifact accompanying the
paper. All data is synthetic; no real credentials, real enterprise data, or
real external network calls are involved. See `SECURITY_ETHICS.md` for
details.

---

## Quick Start

**Prerequisites:** Python 3.10+, any OS. No external packages required
beyond the standard library (unit tests use `pytest`).

```bash
cd experiments
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Smoke test (~5 min)

Validates that the system is functional. Runs the demo CLI and unit tests.

```bash
make smoke
```

Expected: demo JSON output printed to stdout, all tests pass.

### Reproduce main results (~30 min)

Builds the benchmark (seed=42), validates labels, runs detection evaluation,
ablation study, runtime red-team evaluation, generalization stress checks, and generates all paper tables.

```bash
make reproduce
```

### Full reproduction (~2+ hours)

Includes the ecosystem corpus crawl (1200 synthetic samples) and triage.

```bash
make eval-all
```

---

## Directory Structure

```
experiments/
├── Makefile                 # Reproducible experiment targets
├── README.md                # This file
├── pyproject.toml           # Python package metadata
├── requirements.txt         # Runtime dependencies
├── SECURITY_ETHICS.md       # Ethics and safety constraints
├── configs/
│   ├── policy.yaml          # Human-readable policy rules
│   └── sandbox.yaml         # Sandbox isolation configuration
├── data/
│   └── README.md            # Data directory placeholder
├── examples/
│   ├── manifests/           # Sample skill manifests
│   └── traces/              # Sample runtime traces
├── results/
│   ├── main/                # Detection, ablation, runtime, tables
│   ├── ecosystem/           # Ecosystem crawl + triage results
│   └── README.md
├── scripts/
│   ├── build_benchmark.py   # Generate benchmark (1000 benign + 3010 malicious)
│   ├── validate_labels.py   # Validate benchmark label integrity
│   ├── run_detector_eval.py # Detection comparison (8 methods)
│   ├── run_ablation.py      # Layer ablation study (6 configs)
│   ├── run_runtime_redteam.py # Runtime defense + usability evaluation
│   ├── make_tables.py       # Generate paper tables (txt + LaTeX)
│   ├── run_runtime_harness.py # Local instrumented toy runtime harness
│   ├── run_sandbox_harness.py # Local isolated sandbox harness
│   ├── run_generalization_eval.py # Held-out, hard-negative, mutation, leakage checks
│   ├── crawl_ecosystem.py   # Generate synthetic ecosystem corpus
│   ├── crawl_real_ecosystem.py # Collect real public corpus metadata/source snapshots
│   ├── triage_findings.py   # Triage ecosystem findings
│   ├── run_failure_analysis.py # Analyze FP/FN and evidence path attribution
│   ├── run_latency.py       # Measure pipeline latency
│   ├── run_bootstrap_ci.py  # Bootstrap confidence intervals
│   ├── run_significance_tests.py # Paired significance vs weighted voting
│   ├── run_demo.py          # Quick demo of scanning + evaluation
│   └── run_ablation_stub.py # Minimal ablation for smoke tests
├── src/
│   └── skillguardgraph/     # Core library
│       ├── runtime_harness.py # Safe local runtime task templates
│       └── sandbox_harness.py # Local isolated sandbox case runner
└── tests/
    ├── test_analyzers.py    # Tests for metadata, static, sandbox analyzers
    ├── test_policy_engine.py # Tests for cross-layer policy engine
    ├── test_evidence_graph.py # Tests for typed evidence graph materialization
    ├── test_runtime_harness.py # Tests for local runtime harness instrumentation
    └── test_sandbox_harness.py # Tests for local isolated sandbox harness
```

---

## Makefile Targets

| Target | Description | Time |
|---|---|---|
| `make smoke` | Demo + unit tests | ~5 min |
| `make test` | Unit tests (verbose) | ~2 min |
| `make benchmark` | Build benchmark (4010 samples) | ~5 min |
| `make validate` | Validate benchmark labels | ~2 min |
| `make eval-main` | Detection + ablation + runtime eval + runtime/sandbox harnesses + bootstrap + generalization | ~15 min |
| `make tables` | Generate tables + failure analysis + significance | ~1 min |
| `make ecosystem` | Crawl synthetic ecosystem corpus | ~10 min |
| `make real-ecosystem` | Crawl passive real public GitHub + npm MCP corpus | network-bound |
| `make triage` | Triage synthetic ecosystem findings | ~5 min |
| `make reproduce` | benchmark + validate + eval-main + tables | ~30 min |
| `make eval-all` | reproduce + ecosystem + triage + real-ecosystem | network-bound |
| `make scan` | Scan a sample manifest | ~5 sec |
| `make trace` | Evaluate a sample trace | ~5 sec |
| `make runtime-harness` | Run local instrumented runtime harness | ~1 min |
| `make sandbox-harness` | Run local isolated sandbox harness | ~1 min |
| `make clean` | Remove all generated results and data | instant |

---

## Expected Outputs

After `make reproduce`, the following files are generated:

```
results/main/detector_eval.json   # Detection metrics, AUROC/AUPRC, threshold sweep
results/main/ablation.json        # Ablation results for 6 configurations
results/main/runtime_redteam.json  # Runtime defense + usability metrics
results/main/runtime_harness.json # Local instrumented runtime harness metrics
results/main/sandbox_harness.json # Local isolated sandbox harness metrics
results/main/failure_analysis.json # FP/FN and evidence path attribution
results/main/significance_tests.json # McNemar + paired-bootstrap baseline comparison
results/main/tables.txt           # Formatted plain-text tables
results/main/generalization_eval.json # Held-out/hard-negative/mutation/leakage checks
results/main/tables.tex           # LaTeX tables for paper inclusion
```

After `make eval-all` (additional files):

```
results/ecosystem/ecosystem_triage.json      # Full synthetic ecosystem triage (1200 samples)
results/ecosystem/risk_patterns.json         # Synthetic aggregated risk pattern statistics
results/ecosystem/real_ecosystem_samples.jsonl   # Real public repository sample records
results/ecosystem/real_ecosystem_results.json    # Real-corpus aggregated metrics
results/ecosystem/real_ecosystem_data_card.json  # Source/date/version/license/dedup metadata
results/ecosystem/real_high_risk_triage.json     # Manual triage for HIGH real findings
```

Key result numbers:

| Metric | Value |
|---|---|
| Benchmark size | 4,010 (1,000 benign + 3,010 malicious, 7 classes) |
| Fusion Precision | 1.000 |
| Fusion Recall | 1.000 |
| Fusion F1 | 1.000 |
| Fusion FPR | 0.000 |
| Fusion AUROC / AUPRC | 1.000 / 0.986 |
| FPR reduction vs naive union | 100.0% |
| Weighted Voting F1 | 0.936 |
| Weighted Voting FPR | 0.208 |
| Per-class fusion recall | 1.000 for all 7 classes |
| Ablation: no_runtime F1 drop | -0.639 |
| Ablation: no_metadata F1 drop | -0.077 |
| Runtime ASR | 0.000 |
| Task success rate | 1.000 |
| False block rate | 0.000 |
| Latency p50 / p95 | 0.5ms / 0.6ms |
| Sandbox harness recall / benign alert rate | 1.000 / 0.000 |
| Real public corpus | 1,000 artifacts (750 GitHub + 250 npm) |
| Real corpus high severity | 2 |
| Real corpus confirmed vulnerabilities | 0 |

See `../artifact/EXPECTED_OUTPUTS.md` for full output documentation.
---

## Individual Commands

Each experiment step can be run independently:

```bash
# Build benchmark
PYTHONPATH=src python scripts/build_benchmark.py

# Detection evaluation (8 methods: metadata, static, sandbox, runtime,
# naive_union, weighted_voting, llm_judge, fusion)
PYTHONPATH=src python scripts/run_detector_eval.py

# Ablation study (6 configs: full, no_metadata, no_static, no_sandbox,
# no_runtime, no_sequence)
PYTHONPATH=src python scripts/run_ablation.py

# Runtime red-team evaluation
PYTHONPATH=src python scripts/run_runtime_redteam.py


# Local instrumented runtime harness
PYTHONPATH=src python scripts/run_runtime_harness.py

# Generalization stress checks
PYTHONPATH=src python scripts/run_generalization_eval.py
# Generate paper tables
PYTHONPATH=src python scripts/make_tables.py

# Ecosystem corpus (1200 synthetic samples from 5 sources)
PYTHONPATH=src python scripts/crawl_ecosystem.py

# Triage ecosystem findings
PYTHONPATH=src python scripts/triage_findings.py

# Unit tests
PYTHONPATH=src python -m pytest tests/ -v
```

---

## Reproducibility

- All random generation uses `seed=42` (hardcoded in scripts).
- The benchmark is deterministic: rebuilding produces identical samples.
- No network access is required for any experiment.
- No external Python packages are required beyond `pytest` (for tests).
- All synthetic data is generated in-memory; `make clean` removes caches.

---

## Ethics and Safety

This prototype is for **defensive research only**. Key constraints:

- All attack samples use synthetic data with fake credentials.
- All network destinations point to sinkhole domains (`*.sinkhole.test`,
  `*.example.invalid`, `127.0.0.1`).
- No real credentials, tokens, or API keys appear anywhere.
- No real exploit code targeting production systems is included.
- Dynamic sandbox experiments run in isolated containers with no host access.

See `SECURITY_ETHICS.md` for the full policy, and
`../docs/ethics_protocol.md` for the complete ethics protocol.

---

## Citation

If you use this artifact, please cite:

```bibtex
@software{skillguardgraph2026,
  title   = {SkillGuardGraph: Cross-Layer Evidence Fusion for
             Detecting Malicious Skills in LLM Agent Ecosystems},
  year    = {2026},
  url     = {https://github.com/skillguardgraph/skillguardgraph}
}
```
