# Expected Outputs — SkillGuardGraph Artifact

This document describes every output file produced by the experiment pipeline, its format, approximate size, and the key metrics it contains.

---

## 1. Detection Evaluation

**File:** `results/main/detector_eval.json`
**Format:** JSON
**Produced by:** `python scripts/run_detector_eval.py`

Key fields:

- per-method confusion counts and precision/recall/F1/FPR;
- `score_metrics` with AUROC, AUPRC, FPR@Recall, and threshold sweeps;
- `per_attack_class_recall`.

### Current method metrics

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
**Produced by:** `python scripts/run_ablation.py`

| Config | Precision | Recall | F1 | FPR | F1 Delta from Full |
|---|---:|---:|---:|---:|---:|
| full | 1.0000 | 1.0000 | 1.0000 | 0.0000 | +0.0000 |
| no_metadata | 1.0000 | 0.8571 | 0.9231 | 0.0000 | -0.0769 |
| no_static | 1.0000 | 1.0000 | 1.0000 | 0.0000 | +0.0000 |
| no_sandbox | 1.0000 | 1.0000 | 1.0000 | 0.0000 | +0.0000 |
| no_runtime | 1.0000 | 0.2199 | 0.3606 | 0.0000 | -0.6394 |
| no_sequence | 1.0000 | 0.7970 | 0.8870 | 0.0000 | -0.1130 |

All seven attack classes retain 1.0000 recall under full fusion in the current artifact state.

---

## 3. Runtime Red-Team Evaluation

**File:** `results/main/runtime_redteam.json`
**Format:** JSON
**Produced by:** `python scripts/run_runtime_redteam.py`

| Metric | Value |
|---|---:|
| ASR | 0.0000 |
| ASR_blocked | 1.0000 |
| UTCR | 0.1635 |
| UTCR_blocked_rate | 1.0000 |
| EDR | 0.4206 |
| EDR_blocked_rate | 1.0000 |
| BRI | 1.5322 |
| PS_blocked_rate | 1.0000 |
| SC | 0.0000 |
| Task success rate | 1.0000 |
| False block rate | 0.0000 |
| Approval burden | 0.0000 |

---

## 4. Latency Measurement

**File:** `results/main/latency.json`
**Format:** JSON
**Produced by:** `python scripts/run_latency.py`

| Component | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---|---:|---:|---:|---:|
| Total pipeline | 0.342 | 0.418 | 0.452 | 0.599 |
| metadata_ms | 0.011 | 0.016 | 0.022 | 0.038 |
| static_ms | 0.223 | 0.273 | 0.292 | 0.386 |
| sandbox_ms | 0.058 | 0.070 | 0.077 | 0.101 |
| runtime_ms | 0.008 | 0.015 | 0.021 | 0.026 |
| fusion_ms | 0.043 | 0.064 | 0.076 | 0.095 |

---

## 5. Bootstrap Confidence Intervals

**File:** `results/main/bootstrap_ci.json`
**Format:** JSON
**Produced by:** `python scripts/run_bootstrap_ci.py`

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

## 7. Significance Tests

**File:** `results/main/significance_tests.json`
**Format:** JSON
**Produced by:** `python scripts/run_significance_tests.py`

| Metric | Value |
|---|---:|
| Fusion-only correct samples | 389 |
| Weighted-only correct samples | 0 |
| McNemar exact p-value | < 1e-6 |
| Paired bootstrap ΔPrecision | +0.0684 [0.0592, 0.0775] |
| Paired bootstrap ΔRecall | +0.0603 [0.0517, 0.0695] |
| Paired bootstrap ΔF1 | +0.0644 [0.0582, 0.0706] |
| Paired bootstrap ΔFPR | -0.2081 [-0.2342, -0.1830] |

---

## 8. Paper Tables

**Files:** `results/main/tables.txt`, `results/main/tables.tex`
**Format:** Plain text / LaTeX
**Produced by:** `python scripts/make_tables.py`

---

## 9. Synthetic Ecosystem Triage

**Files:** `results/ecosystem/ecosystem_triage.json`, `results/ecosystem/risk_patterns.json`
**Produced by:** `python scripts/crawl_ecosystem.py` and `python scripts/triage_findings.py`

| Metric | Value |
|---|---:|
| Total samples | 1,200 |
| High severity | 95 (7.9%) |
| Medium severity | 154 (12.8%) |
| Scope inflation | 244 (20.3%) |
| Description-code mismatch | 273 (22.8%) |
| Untrusted publisher | 910 (75.8%) |

---

## 10. Real Public Ecosystem Measurement

**Files:**

- `results/ecosystem/real_ecosystem_samples.jsonl`
- `results/ecosystem/real_ecosystem_results.json`
- `results/ecosystem/real_ecosystem_data_card.json`
- `results/ecosystem/real_high_risk_triage.json`

**Produced by:** `python scripts/crawl_real_ecosystem.py --target 1000 --pages-per-query 3 --source-budget 100`

| Metric | Value |
|---|---:|
| Total repositories | 1,000 |
| Source-available samples | 45 |
| Manifest-only samples | 955 |
| High severity | 2 |
| Medium severity | 19 |
| Missing signatures | 1,000 (100.0%) |
| Untrusted publishers | 232 (23.2%) |
| Open-world network access | 19 (1.9%) |
| Scope inflation | 5 (0.5%) |
| Confirmed vulnerabilities | 0 |

---

## Notes

- All synthetic generation uses `seed=42` where randomness is involved.
- All synthetic network destinations point to sinkhole or reserved domains.
- No real credentials, tokens, or API keys appear in the artifact.
- Smoke tests and synthetic reproduction do not require network access.
- Real public ecosystem measurement requires outbound access to GitHub's public APIs and raw content endpoints.
