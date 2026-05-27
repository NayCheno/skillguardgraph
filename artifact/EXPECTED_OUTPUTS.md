# Expected Outputs — SkillGuardGraph Artifact

This document describes every output file produced by the experiment
pipeline, its format, approximate size, and the key metrics it contains.

---

## 1. Detection Evaluation

**File:** `results/main/detector_eval.json`
**Format:** JSON
**Size:** ~2 KB
**Produced by:** `make eval-main` (step: `run_detector_eval.py`)

### Structure

```json
{
  "total_samples": 4010,
  "methods": {
    "<method_name>": {
      "TP": <int>,
      "FP": <int>,
      "TN": <int>,
      "FN": <int>,
      "precision": <float>,
      "recall": <float>,
      "f1": <float>,
      "fpr": <float>
    }
  }
}
```

### Methods evaluated

| Method | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| metadata_only | 0.890 | 0.302 | 0.451 | 0.112 |
| static_only | 1.000 | 0.219 | 0.360 | 0.000 |
| sandbox_only | 1.000 | 0.219 | 0.360 | 0.000 |
| runtime_only | 1.000 | 0.422 | 0.594 | 0.000 |
| naive_union | 0.751 | 1.000 | 0.858 | 1.000 |
| weighted_voting | 0.954 | 0.887 | 0.920 | 0.128 |
| llm_judge | 0.751 | 1.000 | 0.858 | 1.000 |
| **fusion** | **0.962** | **0.767** | **0.853** | **0.091** |

---

## 2. Ablation Study

**File:** `results/main/ablation.json`
**Format:** JSON
**Size:** ~7 KB
**Produced by:** `make eval-main` (step: `run_ablation.py`)

### Ablation configurations

| Config | F1 | F1 Delta from Full |
|---|---|---|
| full | 0.853 | - |
| no_metadata | 0.650 | -0.204 |
| no_static | 0.853 | +0.000 |
| no_sandbox | 0.853 | +0.000 |
| no_runtime | 0.360 | -0.494 |
| no_sequence | 0.815 | -0.038 |

### Per-attack-class recall (full fusion)

| Class | Recall |
|---|---|
| capability_laundering | 0.588 |
| consent_laundering | 0.595 |
| cross_skill_confused_deputy | **1.000** |
| delayed_rug_pull | 0.619 |
| persistence_pivot | 1.000 |
| scope_inflation | 1.000 |
| split_exfiltration | 0.565 |

---

## 3. Runtime Red-Team Evaluation

**File:** `results/main/runtime_redteam.json`
**Format:** JSON
**Size:** ~2 KB
**Produced by:** `make eval-main` (step: `run_runtime_redteam.py`)

### Runtime defense metrics

| Metric | Value | Description |
|---|---|---|
| ASR | 0.055 | Attack Success Rate |
| ASR_blocked | 0.945 | Fraction of attacks blocked |
| UTCR | 0.165 | Unauthorized Tool Call Rate |
| UTCR_blocked_rate | 1.000 | Block rate for tainted calls |
| EDR | 0.423 | Exfiltration Data Rate |
| EDR_blocked_rate | 1.000 | Block rate for exfiltration |
| BRI | 1.534 | Blast Radius Index |
| PS_blocked_rate | 1.000 | Persistence strategy block rate |
| SC | 0.055 | Stealth Coefficient |

### Usability metrics

| Metric | Value | Description |
|---|---|---|
| Task success rate | 1.000 | Benign tasks completed successfully |
| False block rate | 0.000 | Benign tasks incorrectly blocked |
| Approval burden | 0.000 | Unnecessary HITL prompts |

---

## 4. Latency Measurement

**File:** `results/main/latency.json`
**Format:** JSON
**Size:** ~1 KB
**Produced by:** `make eval-main` (step: `run_latency.py`)

### Latency results (500 samples)

| Component | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---|---|---|---|---|
| **Total pipeline** | **0.3** | **0.4** | **0.4** | **0.4** |
| metadata_ms | 0.009 | 0.012 | 0.014 | 0.033 |
| static_ms | 0.223 | 0.269 | 0.280 | 0.305 |
| sandbox_ms | 0.057 | 0.070 | 0.075 | 0.090 |
| runtime_ms | 0.007 | 0.012 | 0.015 | 0.016 |
| fusion_ms | 0.024 | 0.034 | 0.042 | 0.071 |

---

## 5. Bootstrap Confidence Intervals

**File:** `results/main/bootstrap_ci.json`
**Format:** JSON
**Size:** ~1 KB
**Produced by:** `make eval-main` (step: `run_bootstrap_ci.py`)

### Fusion 95% Bootstrap CIs (1,000 replicates)

| Metric | Mean | 95% CI Low | 95% CI High |
|---|---|---|---|
| Precision | 0.9621 | 0.9534 | 0.9694 |
| Recall | 0.7665 | 0.7514 | 0.7817 |
| F1 | 0.8532 | 0.8427 | 0.8633 |
| FPR | 0.0911 | 0.0738 | 0.1107 |

---

## 6. Paper Tables

**Files:** `results/main/tables.txt`, `results/main/tables.tex`
**Format:** Plain text / LaTeX
**Size:** ~3 KB each
**Produced by:** `make tables` (step: `make_tables.py`)

---

## 7. Ecosystem Triage

**File:** `results/ecosystem/ecosystem_triage.json`
**Format:** JSON
**Size:** ~1.7 MB
**Produced by:** `make triage` (step: `triage_findings.py`)

### Key ecosystem numbers (synthetic, 1,200 samples)

| Metric | Value |
|---|---|
| Total samples | 1,200 |
| High severity | 310 (25.8%) |
| Scope inflation | 244 (20.3%) |
| Description-code mismatch | 273 (22.8%) |
| Untrusted publisher | 910 (75.8%) |

---

## 8. Risk Patterns Summary

**File:** `results/ecosystem/risk_patterns.json`
**Format:** JSON
**Size:** ~1.5 KB
**Produced by:** `make triage` (step: `triage_findings.py`)

---

## Notes

- All random generation uses `seed=42` (hardcoded).
- All network destinations point to sinkhole domains.
- No real credentials, tokens, or API keys appear anywhere.
- All external URLs use `*.example.invalid`, `*.sinkhole.test`, or `127.0.0.1`.
