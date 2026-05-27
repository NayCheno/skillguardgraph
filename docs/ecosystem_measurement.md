# Ecosystem Measurement Report

## 1. Scope

SkillGuardGraph now includes two measurement tracks:

1. **Synthetic ecosystem measurement** from `experiments/scripts/crawl_ecosystem.py`, used to stress-test policy behavior under controlled threat-pattern prevalence.
2. **Real public ecosystem measurement** from `experiments/scripts/crawl_real_ecosystem.py`, used for external-validity checks under a strict passive-analysis boundary.

The real measurement does **not** execute third-party code, perform destructive probing, use credentials, or claim confirmed vulnerabilities without separate validation.

## 2. Real Public Corpus Measurement

### 2.1 Collection protocol

- Sources: GitHub public repositories returned by MCP-related search queries, plus npm packages returned by MCP-related registry search terms.
- Collector: `experiments/scripts/crawl_real_ecosystem.py`.
- Output files:
  - `experiments/results/ecosystem/real_ecosystem_samples.jsonl`
  - `experiments/results/ecosystem/real_ecosystem_results.json`
  - `experiments/results/ecosystem/real_ecosystem_data_card.json`
  - `experiments/results/ecosystem/real_high_risk_triage.json`
- Dedup rule: source-specific artifact identifier (`full_name` for GitHub, package name for npm), with `linked_repository` recorded when an npm package points to GitHub.
- Version provenance: GitHub `default_branch` plus `created_at`/`updated_at`/`pushed_at`; npm latest package version plus publication/update timestamps.
- License provenance: SPDX identifier when an upstream API provides one; otherwise `unknown`.
- Source coverage: fetch likely Python/TypeScript/JavaScript entrypoints for a bounded subset of GitHub repositories or linked npm repositories; retain the rest as metadata-only samples.

### 2.2 Dataset statistics

| Metric | Value |
|---|---:|
| Total public artifacts | 1,000 |
| GitHub MCP repositories | 750 |
| npm MCP packages | 250 |
| Source-available samples | 34 |
| Manifest-only samples | 966 |
| High severity | 3 |
| Medium severity | 26 |
| Low severity | 971 |

### 2.3 Language and license mix

Top language counts in the measured corpus:

| Language | Count |
|---|---:|
| TypeScript | 361 |
| Python | 308 |
| Unknown | 225 |
| Go | 31 |
| JavaScript | 17 |

Top license counts:

| License | Count |
|---|---:|
| MIT | 475 |
| Apache-2.0 | 220 |
| Unknown | 96 |
| NOASSERTION | 89 |
| AGPL-3.0 | 40 |

### 2.4 Risk-pattern prevalence

| Pattern | Count | Rate |
|---|---:|---:|
| Missing signature | 750 | 75.0% |
| Untrusted publisher | 188 | 18.8% |
| Open-world network access | 10 | 1.0% |
| Scope inflation | 9 | 0.9% |
| Instruction-like descriptions | 0 | 0.0% |
| Description-code mismatch | 0 | 0.0% |

### 2.5 Interpretation

1. **Governance provenance remains weak, but npm is measurably better than GitHub-only metadata.** Missing signatures drop from the prior GitHub-only 100.0% result to 75.0% once npm package attestations and signatures are included, but the public ecosystem still lacks ubiquitous provenance.
2. **Only a small fraction of artifacts trigger high-severity passive findings.** After the multi-source passive crawl, the real corpus produces 3 HIGH findings and 26 MEDIUM findings, and all 3 HIGH findings remain unconfirmed after manual review.
3. **Metadata-only coverage still dominates.** 966/1,000 artifacts remain manifest-only because the collector intentionally bounds source probing and does not recurse through full repositories or package tarballs. This is acceptable for catalog-level measurement but not for code-complete vulnerability confirmation.
4. **Multi-source coverage is better than the prior GitHub-only snapshot, but still incomplete.** The current batch spans GitHub MCP repositories and npm MCP packages; it still does not cover PyPI, hosted marketplaces, or enterprise-private catalogs.
5. **Real-world prevalence is much lower than synthetic stress prevalence.** This is expected: the synthetic corpus is designed to exercise suspicious patterns, while the public corpus is used as a conservative external-validity check.

## 3. Manual triage and disclosure status

All HIGH-severity real findings were manually reviewed in `experiments/results/ecosystem/real_high_risk_triage.json`.

| Repo | Initial risk | Manual outcome | Disclosure |
|---|---|---|---|
| `idosal/git-mcp` | HIGH | Likely false positive / metadata-capability mismatch only | Not sent |
| `firecrawl/firecrawl-mcp-server` | HIGH | Likely false positive / insufficient exploit evidence | Not sent |
| `excalidraw/excalidraw-mcp` | HIGH | Likely false positive / heuristic scope extraction overfire | Not sent |

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

1. **Query and registry bias.** The real corpus now spans GitHub and npm, but it still excludes PyPI, hosted marketplaces, and private enterprise catalogs.
2. **Manifest-only dominance.** Most real samples are metadata-only because the collector intentionally bounds raw source fetching for safety and runtime reasons.
3. **No runtime validation.** The real measurement does not execute third-party code, so it cannot confirm dynamic exfiltration, persistence, or approval-laundering behaviors.
4. **No confirmed-vulnerability claims.** The measurement is appropriate for prevalence and governance observations, not for naming exploitable packages without follow-up validation.

## 6. Claim boundary

Use the real measurement to support the claim that governance metadata across public MCP repositories and packages is immature (especially signatures/provenance) and that passive catalog measurement can surface suspicious mismatches. Do **not** use it to claim that SkillGuardGraph has validated real-world exploit paths for the named artifacts above.
