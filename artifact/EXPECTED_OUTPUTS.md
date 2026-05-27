# Expected Outputs — SkillGuardGraph Artifact

This document describes every output file produced by the experiment pipeline, its format, approximate size, and the key metrics it contains.

---

## 1. Detection Evaluation

**File:** `results/main/detector_eval.json`
**Format:** JSON
**Size:** ~20 KB
**Produced by:** `make eval-main` or `python scripts/run_detector_eval.py`

### Structure

```json
{
  "total_samples": 4010,
  "methods": {
    "<method_name>": {
      "TP": 0,
      "FP": 0,
      "TN": 0,
      "FN": 0,
      "precision": 0.0,
      "recall": 0.0,
      "f1": 0.0,
      "fpr": 0.0
    }
  },
  "score_metrics": {
    "<method_name>": {
      "auroc": 0.0,
      "auprc": 0.0,
      "fpr_at_recall": {"85": 0.0, "90": 0.0, "95": 0.0},
      "threshold_sweep": []
    }
  },
  "per_attack_class_recall": {}
}
```

### Methods evaluated

| Method | Precision | Recall | F1 | FPR | AUROC | AUPRC |
|---|---:|---:|---:|---:|---:|---:|
| metadata_only | 0.9398 | 0.1920 | 0.3189 | 0.0370 | 0.5775 | 0.8691 |
| static_only | 1.0000 | 0.2199 | 0.3606 | 0.0000 | 0.6099 | 0.9027 |
| sandbox_only | 1.0000 | 0.2199 | 0.3606 | 0.0000 | 0.7857 | 0.9466 |
| runtime_only | 1.0000 | 0.5980 | 0.7484 | 0.0000 | 0.7990 | 0.9499 |
| naive_union | 0.7506 | 1.0000 | 0.8575 | 1.0000 | 0.5000 | 0.8753 |
| weighted_voting | 0.9315 | 0.9399 | 0.9357 | 0.2080 | 0.8925 | 0.9670 |
| llm_judge | 0.7506 | 1.0000 | 0.8575 | 1.0000 | 0.7988 | 0.9363 |
| **fusion** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **1.0000** | **0.9855** |

---

## 2. Ablation Study

**File:** `results/main/ablation.json`
**Format:** JSON
**Size:** ~7 KB
**Produced by:** `make eval-main` or `python scripts/run_ablation.py`

### Ablation configurations

| Config | Precision | Recall | F1 | FPR | F1 Delta from Full |
|---|---:|---:|---:|---:|---:|
| full | 1.0000 | 1.0000 | 1.0000 | 0.0000 | +0.0000 |
| no_metadata | 1.0000 | 0.8571 | 0.9231 | 0.0000 | -0.0769 |
| no_static | 1.0000 | 1.0000 | 1.0000 | 0.0000 | +0.0000 |
| no_sandbox | 1.0000 | 1.0000 | 1.0000 | 0.0000 | +0.0000 |
| no_runtime | 1.0000 | 0.2199 | 0.3606 | 0.0000 | -0.6394 |
| no_sequence | 1.0000 | 0.7970 | 0.8870 | 0.0000 | -0.1130 |

### Per-attack-class recall (full fusion)

| Class | Recall |
|---|---:|
| capability_laundering | 1.0000 |
| consent_laundering | 1.0000 |
| cross_skill_confused_deputy | 1.0000 |
| delayed_rug_pull | 1.0000 |
| persistence_pivot | 1.0000 |
| scope_inflation | 1.0000 |
| split_exfiltration | 1.0000 |

---

## 3. Runtime Red-Team Evaluation

**File:** `results/main/runtime_redteam.json`
**Format:** JSON
**Size:** ~2 KB
**Produced by:** `make eval-main` or `python scripts/run_runtime_redteam.py`

### Runtime defense metrics

| Metric | Value | Description |
|---|---:|---|
| ASR | 0.0000 | Attack Success Rate |
| ASR_blocked | 1.0000 | Fraction of attacks blocked |
| UTCR | 0.1635 | Unauthorized Tool Call Rate before blocked effects |
| UTCR_blocked_rate | 1.0000 | Block rate for tainted calls |
| EDR | 0.4206 | Exfiltration Data Rate before blocked effects |
| EDR_blocked_rate | 1.0000 | Block rate for exfiltration |
| BRI | 1.5322 | Blast Radius Index before blocked effects |
| PS_blocked_rate | 1.0000 | Persistence strategy block rate |
| SC | 0.0000 | Stealth Coefficient |

### Usability metrics

| Metric | Value | Description |
|---|---:|---|
| Task success rate | 1.0000 | Benign tasks completed successfully |
| False block rate | 0.0000 | Benign tasks incorrectly blocked |
| Approval burden | 0.0000 | Unnecessary HITL prompts |

---

## 4. Latency Measurement

**File:** `results/main/latency.json`
**Format:** JSON
**Size:** ~1 KB
**Produced by:** `python scripts/run_latency.py`

### Latency results (500 samples)

| Component | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---|---:|---:|---:|---:|
| **Total pipeline** | **0.3** | **0.4** | **0.5** | **0.6** |
| metadata_ms | 0.011 | 0.016 | 0.022 | 0.038 |
| static_ms | 0.223 | 0.273 | 0.292 | 0.386 |
| sandbox_ms | 0.058 | 0.070 | 0.077 | 0.101 |
| runtime_ms | 0.008 | 0.015 | 0.021 | 0.026 |
| fusion_ms | 0.043 | 0.064 | 0.076 | 0.095 |

---

## 5. Bootstrap Confidence Intervals

**File:** `results/main/bootstrap_ci.json`
**Format:** JSON
**Size:** ~1 KB
**Produced by:** `python scripts/run_bootstrap_ci.py`

### Fusion 95% Bootstrap CIs (1,000 replicates)

| Metric | Mean | 95% CI Low | 95% CI High |
|---|---:|---:|---:|
| Precision | 1.0000 | 1.0000 | 1.0000 |
| Recall | 1.0000 | 1.0000 | 1.0000 |
| F1 | 1.0000 | 1.0000 | 1.0000 |
| FPR | 0.0000 | 0.0000 | 0.0000 |

---

## 6. Failure Analysis

**Files:** `results/main/failure_analysis.json`, `results/main/failure_cases.md`
**Produced by:** `python scripts/run_failure_analysis.py`

| Metric | Value |
|---|---:|
| False negatives | 0 |
| False positives | 0 |
| Evidence path attribution | 3,010 / 3,010 (100.0%) |

---

## 7. Paper Tables

**Files:** `results/main/tables.txt`, `results/main/tables.tex`
**Format:** Plain text / LaTeX
**Size:** ~4 KB each
**Produced by:** `make tables` or `python scripts/make_tables.py`

---

## 8. Ecosystem Triage

**File:** `results/ecosystem/ecosystem_triage.json`
**Format:** JSON
**Size:** ~1.7 MB
**Produced by:** `make triage` (step: `triage_findings.py`)

### Key ecosystem numbers (synthetic, 1,200 samples)

| Metric | Value |
|---|---:|
| Total samples | 1,200 |
| High severity | 95 (7.9%) |
| Scope inflation | 244 (20.3%) |
| Description-code mismatch | 273 (22.8%) |
| Untrusted publisher | 910 (75.8%) |

---

## Notes

- All random generation uses `seed=42` where generation is randomized.
- All network destinations point to sinkhole domains.
- No real credentials, tokens, or API keys appear in the artifact.
- All external URLs use `*.example.invalid`, `*.sinkhole.test`, or `127.0.0.1`.
