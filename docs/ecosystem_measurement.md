# Ecosystem Measurement Report

## 1. Scope

SkillGuardGraph includes two measurement tracks:

1. **Synthetic ecosystem measurement** from `experiments/scripts/crawl_ecosystem.py`, used to stress-test policy behavior under controlled threat-pattern prevalence.
2. **Real public ecosystem measurement** from `experiments/scripts/crawl_real_ecosystem.py`, used for external-validity checks under a strict passive-analysis boundary.

The real measurement does **not** execute third-party code, perform destructive probing, use credentials, or claim confirmed vulnerabilities without separate validation.

## 2. Real Public Corpus Measurement

### 2.1 Collection protocol

- Sources: GitHub public repositories returned by MCP-related search queries, npm packages returned by MCP-related registry search terms, and Hugging Face Spaces returned by MCP-oriented space search terms.
- Collector: `experiments/scripts/crawl_real_ecosystem.py`.
- Output files:
  - `experiments/results/ecosystem/real_ecosystem_samples.jsonl`
  - `experiments/results/ecosystem/real_ecosystem_results.json`
  - `experiments/results/ecosystem/real_ecosystem_data_card.json`
  - `experiments/results/ecosystem/real_high_risk_triage.json`
- Dedup rule: source-specific artifact identifier (`full_name` for GitHub, package name for npm, space id for Hugging Face), with `linked_repository` recorded when an npm package points to GitHub.
- Version provenance: GitHub `default_branch` plus `created_at`/`updated_at`/`pushed_at`; npm latest package version plus publication/update timestamps; Hugging Face `sha` plus `createdAt`/`lastModified` when exposed.
- License provenance: SPDX identifier when an upstream API provides one; otherwise `unknown`.
- Source coverage: fetch a bounded set of likely Python/TypeScript/JavaScript entrypoints using explicit candidates, GitHub contents listings, package.json-derived entrypoints, and Hugging Face `app_file`/sibling metadata when available; retain the rest as metadata-only samples.

### 2.2 Dataset statistics

| Metric | Value |
|---|---:|
| Total public artifacts | 1,000 |
| GitHub MCP repositories | 630 |
| npm MCP packages | 200 |
| PyPI MCP packages | 20 |
| Hugging Face Spaces | 150 |
| Source-available samples | 22 |
| Manifest-only samples | 978 |
| High severity | 2 |
| Medium severity | 16 |
| Low severity | 982 |

### 2.3 Language and license mix

Top language counts in the measured corpus:

| Language | Count |
|---|---:|
| Python | 328 |
| Unknown | 233 |
| TypeScript | 190 |
| Gradio | 98 |
| Go | 31 |

Top license counts:

| License | Count |
|---|---:|
| MIT | 393 |
| Unknown | 232 |
| Apache-2.0 | 197 |
| NOASSERTION | 72 |
| AGPL-3.0 | 33 |

### 2.4 Risk-pattern prevalence

| Pattern | Count | Rate |
|---|---:|---:|
| Missing signature | 800 | 80.0% |
| Untrusted publisher | 328 | 32.8% |
| Open-world network access | 8 | 0.8% |
| Scope inflation | 7 | 0.7% |
| Instruction-like descriptions | 0 | 0.0% |
| Description-code mismatch | 0 | 0.0% |

### 2.5 Interpretation

1. **Governance provenance remains weak even after adding a curated PyPI slice.** Missing signatures still appear on 800/1,000 artifacts (80.0%) because GitHub repositories, many PyPI projects, and Hugging Face Spaces do not expose strong signing metadata through the passive collector.
2. **Only a very small fraction of artifacts trigger high-severity passive findings.** After the refined four-source passive crawl, the real corpus produces 2 HIGH findings and 16 MEDIUM findings, and both HIGH findings remain unconfirmed after manual review.
3. **Metadata-only coverage still dominates.** 978/1,000 artifacts remain manifest-only because the collector intentionally bounds source probing and does not recurse through full repositories, package tarballs, or hosted space bundles. This is acceptable for catalog-level measurement but not for code-complete vulnerability confirmation.
4. **Source discovery is slightly richer but still bounded.** The collector now consults GitHub contents listings, package.json-derived entrypoints, curated PyPI project links, and Hugging Face `app_file`/sibling metadata before bounded source fetch, but the full 1,000-artifact batch still remains overwhelmingly metadata-only.
5. **Multi-source coverage is better than the prior GitHub-only snapshot, but still incomplete.** The current batch spans GitHub MCP repositories, npm MCP packages, curated PyPI MCP packages, and Hugging Face Spaces; it still does not cover broader PyPI search, hosted enterprise marketplaces, or private catalogs.
6. **Real-world prevalence is much lower than synthetic stress prevalence.** This is expected: the synthetic corpus is designed to exercise suspicious patterns, while the public corpus is used as a conservative external-validity check.

### 2.6 Supplementary scaled batch

A supplementary large-batch run is checked in as:

- `experiments/results/ecosystem/real_ecosystem_large_results.json`
- `experiments/results/ecosystem/real_ecosystem_large_data_card.json`

This run uses the passive collector with `--target 2000 --pages-per-query 3 --source-budget 25 --sources github_mcp,npm_mcp,hf_spaces_mcp --output-prefix real_ecosystem_large --resume` and reaches 2,000 artifacts (1,200 GitHub, 500 npm, 300 Hugging Face). It produces 0 HIGH and 9 MEDIUM findings, but only 5 source-available samples. We therefore treat it as a scale-out catalog measurement, not as stronger code-level validation.

## 3. Manual triage and disclosure status

All HIGH-severity real findings were manually reviewed in `experiments/results/ecosystem/real_high_risk_triage.json`.

| Repo | Initial risk | Manual outcome | Disclosure |
|---|---|---|---|
| `idosal/git-mcp` | HIGH | Likely false positive / metadata-capability mismatch only | Not sent |
| `firecrawl/firecrawl-mcp-server` | HIGH | Likely false positive / insufficient exploit evidence | Not sent |

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

1. **Query and registry bias.** The real corpus now spans GitHub, npm, a curated PyPI seed list, and Hugging Face Spaces, but it still excludes broad PyPI discovery, hosted enterprise marketplaces, and private enterprise catalogs.
2. **Manifest-only dominance.** Most real samples are metadata-only because the collector intentionally bounds raw source fetching for safety and runtime reasons.
3. **No runtime validation.** The real measurement does not execute third-party code, so it cannot confirm dynamic exfiltration, persistence, or approval-laundering behaviors.
4. **No confirmed-vulnerability claims.** The measurement is appropriate for prevalence and governance observations, not for naming exploitable packages without follow-up validation.

## 6. Claim boundary

Use the real measurement to support the claim that governance metadata across public MCP repositories, packages, and spaces is immature (especially signatures/provenance) and that passive catalog measurement can surface suspicious mismatches. Do **not** use it to claim that SkillGuardGraph has validated real-world exploit paths for the named artifacts above.
