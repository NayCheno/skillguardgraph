# Expected Outputs — SkillGuardGraph Artifact

This document describes every output file produced by the experiment pipeline, its format, approximate size, and the key metrics it contains.

---

## 1. Detection Evaluation

**File:** `results/main/detector_eval.json`  
**Format:** JSON  
**Produced by:** `python scripts/run_detector_eval.py`

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

## 4. Local Runtime Harness

**File:** `results/main/runtime_harness.json`  
**Format:** JSON  
**Produced by:** `python scripts/run_runtime_harness.py`

| Metric | Value |
|---|---:|
| Benign tasks | 60 |
| Attack tasks | 63 |
| ASR | 0.0000 |
| ASR reduction vs no defense | 1.0000 |
| Task success rate | 1.0000 |
| False block rate | 0.0000 |
| Evidence path coverage | 1.0000 |
| Policy p95 latency | 0.265 ms |

---

## 5. Local Sandbox Harness

**File:** `results/main/sandbox_harness.json`  
**Format:** JSON  
**Produced by:** `python scripts/run_sandbox_harness.py`

| Metric | Value |
|---|---:|
| Benign cases | 16 |
| Malicious cases | 24 |
| Blocked network attempts | 8 |
| Blocked shell attempts | 8 |
| Malicious detection recall | 1.0000 |
| Benign alert rate | 0.0000 |
| Unsafe egress events | 0 |
| Sandbox p95 latency | 41.681 ms |

---

## 6. Third-Party Public-Code Sandbox

**File:** `results/main/third_party_sandbox.json`  
**Format:** JSON  
**Produced by:** `python scripts/run_third_party_sandbox.py`

| Metric | Value |
|---|---:|
| Fixtures executed | 3 |
| Archive fixtures resolved | 3 |
| Subprocess attempts observed | 1 |
| No unsafe egress | true |
| Fixture p95 latency | 91.206 ms |

This fixture suite executes curated public third-party code resolved from downloaded package source archives inside the sandbox harness. It is stronger than the repository-only toy sandbox, but it still does not amount to arbitrary third-party package execution.

---

## 7. Corpus-Derived Package Sandbox

**File:** `results/main/corpus_package_sandbox.json`
**Format:** JSON
**Produced by:** `python scripts/run_corpus_package_sandbox.py`

| Metric | Value |
|---|---:|
| Cases executed | 3 |
| Archive cases resolved | 3 |
| Client tool calls observed | 2 |
| Subprocess attempts observed | 1 |
| Registered tools observed | 2 |
| No unsafe egress | true |
| Case p95 latency | 91.746 ms |

This sandbox executes bounded source-available third-party PyPI package cases drawn from the checked-in real-corpus batch. It is stronger than curated archive snippets because it resolves real package test/server files from public source distributions, but it still does not amount to arbitrary marketplace package execution.

---

## 8. Latency Measurement

**File:** `results/main/latency.json`  
**Format:** JSON  
**Produced by:** `python scripts/run_latency.py`

| Component | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---|---:|---:|---:|---:|
| Total pipeline | 0.410 | 0.499 | 0.518 | 0.568 |
| metadata_ms | 0.012 | 0.014 | 0.016 | 0.029 |
| static_ms | 0.287 | 0.353 | 0.362 | 0.399 |
| sandbox_ms | 0.058 | 0.070 | 0.073 | 0.083 |
| runtime_ms | 0.008 | 0.011 | 0.013 | 0.017 |
| fusion_ms | 0.046 | 0.063 | 0.072 | 0.079 |

---

## 9. Bootstrap Confidence Intervals

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

## 10. Failure Analysis

**Files:** `results/main/failure_analysis.json`, `results/main/failure_cases.md`  
**Produced by:** `python scripts/run_failure_analysis.py`

| Metric | Value |
|---|---:|
| False negatives | 0 |
| False positives | 0 |
| Evidence path attribution | 3,010 / 3,010 (100.0%) |

---

## 11. Significance Tests

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

## 12. Generalization Stress Checks

**File:** `results/main/generalization_eval.json`  
**Format:** JSON  
**Produced by:** `python scripts/run_generalization_eval.py`

| Check | Samples | Precision | Recall | F1 | FPR | Key acceptance |
|---|---:|---:|---:|---:|---:|---|
| Held-out templates | 385 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | F1 >= 0.90; FPR <= 0.08 |
| Hard negatives | 250 | n/a | n/a | n/a | 0.0000 | FPR <= 0.08 |
| Mutated held-out | 385 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | F1 drop <= 0.10 |
| Label-blinded audit | 475 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0 decision changes |

---

## 13. Paper Tables

**Files:** `results/main/tables.txt`, `results/main/tables.tex`  
**Format:** Plain text / LaTeX  
**Produced by:** `python scripts/make_tables.py`

---

## 14. Synthetic Ecosystem Triage

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

## 15. Real Public Ecosystem Measurement

**Files:**

- `results/ecosystem/real_ecosystem_samples.jsonl`
- `results/ecosystem/real_ecosystem_results.json`
- `results/ecosystem/real_ecosystem_data_card.json`
- `results/ecosystem/real_high_risk_triage.json`

**Produced by:** `python scripts/crawl_real_ecosystem.py --target 1000 --pages-per-query 3 --source-budget 100 --resume` (defaults to `github_mcp,npm_mcp,pypi_mcp,hf_spaces_mcp,smithery_mcp`)

| Metric | Value |
|---|---:|
| Total artifacts | 1,000 |
| GitHub MCP repositories | 400 |
| npm MCP packages | 200 |
| PyPI MCP packages | 150 |
| Hugging Face Spaces | 150 |
| Smithery hosted registry entries | 100 |
| Source-available samples | 18 |
| Manifest-only samples | 982 |
| High severity | 2 |
| Medium severity | 35 |
| Missing signatures | 800 (80.0%) |
| Untrusted publishers | 552 (55.2%) |
| Open-world network access | 108 (10.8%) |
| Scope inflation | 31 (3.1%) |
| Confirmed vulnerabilities | 0 |

---

## 16. Supplementary Large Public Ecosystem Measurement

**Files:**

- `results/ecosystem/real_ecosystem_large_samples.jsonl`
- `results/ecosystem/real_ecosystem_large_results.json`
- `results/ecosystem/real_ecosystem_large_data_card.json`

**Produced by:** `python scripts/crawl_real_ecosystem.py --target 2000 --pages-per-query 3 --source-budget 25 --sources github_mcp,npm_mcp,hf_spaces_mcp --output-prefix real_ecosystem_large --resume`

| Metric | Value |
|---|---:|
| Total artifacts | 2,000 |
| GitHub MCP repositories | 1,200 |
| npm MCP packages | 500 |
| Hugging Face Spaces | 300 |
| Source-available samples | 5 |
| Manifest-only samples | 1,995 |
| High severity | 0 |
| Medium severity | 9 |
| Missing signatures | 1,500 (75.0%) |
| Untrusted publishers | 746 (37.3%) |

---

## 17. Supplementary XL Public Ecosystem Measurement

**Files:**

- `results/ecosystem/real_ecosystem_xl_samples.jsonl`
- `results/ecosystem/real_ecosystem_xl_results.json`
- `results/ecosystem/real_ecosystem_xl_data_card.json`

**Produced by:** `python scripts/crawl_real_ecosystem.py --target 3000 --pages-per-query 3 --output-prefix real_ecosystem_xl --resume`

| Metric | Value |
|---|---:|
| Total artifacts | 3,000 |
| GitHub MCP repositories | 1,999 |
| npm MCP packages | 600 |
| PyPI MCP packages | 20 |
| Hugging Face Spaces | 381 |
| Source-available samples | 2 |
| Manifest-only samples | 2,998 |
| High severity | 0 |
| Medium severity | 14 |
| Missing signatures | 2,400 (80.0%) |
| Untrusted publishers | 1,294 (43.1%) |

---

## 18. Supplementary 5k Public Ecosystem Measurement

**Files:**

- `results/ecosystem/real_ecosystem_5k_samples.jsonl`
- `results/ecosystem/real_ecosystem_5k_results.json`
- `results/ecosystem/real_ecosystem_5k_data_card.json`

**Produced by:** `python scripts/crawl_real_ecosystem.py --target 5000 --pages-per-query 6 --source-budget 25 --sources github_mcp,npm_mcp,pypi_mcp,hf_spaces_mcp --source-quotas github_mcp=2600,npm_mcp=2000,pypi_mcp=20,hf_spaces_mcp=380 --output-prefix real_ecosystem_5k --resume`

| Metric | Value |
|---|---:|
| Total artifacts | 5,000 |
| GitHub MCP repositories | 2,600 |
| npm MCP packages | 2,000 |
| PyPI MCP packages | 20 |
| Hugging Face Spaces | 380 |
| Source-available samples | 21 |
| Manifest-only samples | 4,979 |
| High severity | 0 |
| Medium severity | 59 |
| Missing signatures | 3,000 (60.0%) |
| Untrusted publishers | 2,592 (51.84%) |

---

## 19. Supplementary 10k Public Ecosystem Measurement

**Files:**

- `results/ecosystem/real_ecosystem_10k_samples.jsonl`
- `results/ecosystem/real_ecosystem_10k_results.json`
- `results/ecosystem/real_ecosystem_10k_data_card.json`

**Produced by:** `python scripts/crawl_real_ecosystem.py --target 10000 --pages-per-query 10 --source-budget 0 --sources github_mcp,npm_mcp,pypi_mcp,hf_spaces_mcp --source-quotas github_mcp=4000,npm_mcp=4000,pypi_mcp=1620,hf_spaces_mcp=380 --output-prefix real_ecosystem_10k --resume`

| Metric | Value |
|---|---:|
| Total artifacts | 10,000 |
| GitHub MCP repositories | 4,000 |
| npm MCP packages | 4,000 |
| PyPI MCP packages | 1,620 |
| Hugging Face Spaces | 380 |
| Source-available samples | 0 |
| Manifest-only samples | 10,000 |
| High severity | 0 |
| Medium severity | 112 |
| Missing signatures | 8,000 (80.0%) |
| Untrusted publishers | 6,458 (64.58%) |

---

## 20. Completion Audit

**Files:** `results/main/completion_audit.json`, `results/main/completion_audit.md`  \n**Format:** JSON / Markdown  \n**Produced by:** `python scripts/run_completion_audit.py`

The audit summarizes which current-state artifact checks pass, which high-level blockers remain, and whether the repository is currently clean. It is intended as a release/readiness report and is generated on demand rather than committed as a canonical benchmark result.

---

## Notes

- All synthetic generation uses `seed=42` where randomness is involved.
- All synthetic network destinations point to sinkhole or reserved domains.
- No real credentials, tokens, or API keys appear in the artifact.
- Smoke tests and synthetic reproduction do not require network access.
- Real public ecosystem measurement requires outbound access to GitHub's public APIs/raw content endpoints, npm registry APIs, PyPI JSON endpoints, and Hugging Face Space metadata/file endpoints. If available, set `GITHUB_TOKEN` and `HF_TOKEN` to reduce rate-limit failures during larger crawls.
