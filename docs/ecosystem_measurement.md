# Ecosystem Measurement Report

## 1. Scope

SkillGuardGraph now includes two measurement tracks:

1. **Synthetic ecosystem measurement** from `experiments/scripts/crawl_ecosystem.py`, used to stress-test policy behavior under controlled threat-pattern prevalence.
2. **Real public repository measurement** from `experiments/scripts/crawl_real_ecosystem.py`, used for external-validity checks under a strict passive-analysis boundary.

The real measurement does **not** execute third-party code, perform destructive probing, use credentials, or claim confirmed vulnerabilities without separate validation.

## 2. Real Public Corpus Measurement

### 2.1 Collection protocol

- Source: GitHub public repositories returned by MCP-related search queries.
- Collector: `experiments/scripts/crawl_real_ecosystem.py`.
- Output files:
  - `experiments/results/ecosystem/real_ecosystem_samples.jsonl`
  - `experiments/results/ecosystem/real_ecosystem_results.json`
  - `experiments/results/ecosystem/real_ecosystem_data_card.json`
  - `experiments/results/ecosystem/real_high_risk_triage.json`
- Dedup rule: repository `full_name`.
- Version provenance: `default_branch` plus GitHub `created_at`, `updated_at`, and `pushed_at` timestamps.
- License provenance: SPDX identifier when GitHub provides one; otherwise `unknown`.
- Source coverage: fetch likely Python/TypeScript/JavaScript entrypoints for a bounded subset of repositories; retain the rest as metadata-only samples.

### 2.2 Dataset statistics

| Metric | Value |
|---|---:|
| Total public repositories | 1,000 |
| Source-available samples | 45 |
| Manifest-only samples | 955 |
| High severity | 2 |
| Medium severity | 19 |
| Low severity | 979 |

### 2.3 Language and license mix

Top language counts in the measured corpus:

| Language | Count |
|---|---:|
| Python | 422 |
| TypeScript | 400 |
| JavaScript | 52 |
| Go | 48 |
| Unknown | 20 |

Top license counts:

| License | Count |
|---|---:|
| MIT | 623 |
| Apache-2.0 | 150 |
| Unknown | 118 |
| NOASSERTION | 51 |
| GPL-3.0 | 21 |

### 2.4 Risk-pattern prevalence

| Pattern | Count | Rate |
|---|---:|---:|
| Missing signature | 1,000 | 100.0% |
| Untrusted publisher | 232 | 23.2% |
| Open-world network access | 19 | 1.9% |
| Scope inflation | 5 | 0.5% |
| Instruction-like descriptions | 0 | 0.0% |
| Description-code mismatch | 0 | 0.0% |

### 2.5 Interpretation

1. **Signatures are absent across the measured public corpus.** This makes governance-layer provenance weak in today's open MCP ecosystem.
2. **Only a small fraction of repositories trigger high-severity passive findings.** After the fusion calibration, the real public corpus produces 2 HIGH findings and 19 MEDIUM findings, substantially lower than the synthetic stress-test corpus.
3. **Metadata-only coverage dominates.** 955/1,000 repositories were retained as manifest-only samples because the collector intentionally bounds source probing and does not recurse through full repositories. This is acceptable for catalog-level measurement but not for code-complete vulnerability confirmation.
4. **Real-world prevalence is much lower than synthetic stress prevalence.** This is expected: the synthetic corpus is designed to exercise suspicious patterns, while the public GitHub corpus is used as a conservative external-validity check.

## 3. Manual triage and disclosure status

All HIGH-severity real findings were manually reviewed in `experiments/results/ecosystem/real_high_risk_triage.json`.

| Repo | Initial risk | Manual outcome | Disclosure |
|---|---|---|---|
| `JetBrains/mcp-jetbrains` | HIGH | Likely false positive / metadata inconsistency only | Not sent |
| `Joooook/12306-mcp` | HIGH | Likely false positive / insufficient exploit evidence | Not sent |

`docs/disclosure_log.md` records the disclosure decision. The current batch yields **0 confirmed vulnerabilities** and **0 outbound disclosures** because passive evidence alone does not satisfy the disclosure threshold in `docs/disclosure_log_template.md`.

## 4. Synthetic ecosystem measurement

Synthetic ecosystem outputs remain useful for controlled prevalence experiments and for exercising policy behavior under noisier conditions.

Current synthetic summary from `experiments/results/ecosystem/risk_patterns.json`:

| Metric | Value |
|---|---:|
| Total samples | 1,200 |
| High severity | 95 (7.9%) |
| Medium severity | 154 (12.8%) |
| Scope inflation | 244 (20.3%) |
| Description-code mismatch | 273 (22.8%) |
| Untrusted publisher | 910 (75.8%) |

The paper should treat these synthetic results as stress-test evidence, not as real-world prevalence estimates.

## 5. Limitations

1. **GitHub-query bias.** The real corpus covers public GitHub search results, not private registries, hosted marketplaces, or enterprise catalogs.
2. **Manifest-only dominance.** Most real samples are metadata-only because the collector intentionally bounds raw source fetching for safety and runtime reasons.
3. **No runtime validation.** The real measurement does not execute third-party code, so it cannot confirm dynamic exfiltration, persistence, or approval-laundering behaviors.
4. **No confirmed-vulnerability claims.** The measurement is appropriate for prevalence and governance observations, not for naming exploitable packages without follow-up validation.

## 6. Claim boundary

Use the real measurement to support the claim that governance metadata in the public MCP ecosystem is immature (especially signatures/provenance) and that passive catalog measurement can surface suspicious mismatches. Do **not** use it to claim that SkillGuardGraph has validated real-world exploit paths for the named repositories above.
