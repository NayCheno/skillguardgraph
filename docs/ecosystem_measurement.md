# Ecosystem Measurement Report

## 1. Scope

SkillGuardGraph includes two measurement tracks:

1. **Synthetic ecosystem measurement** from `experiments/scripts/crawl_ecosystem.py`, used to stress-test policy behavior under controlled threat-pattern prevalence.
2. **Real public ecosystem measurement** from `experiments/scripts/crawl_real_ecosystem.py`, used for external-validity checks under a strict passive-analysis boundary.

The real measurement does **not** execute third-party code, perform destructive probing, use credentials, or claim confirmed vulnerabilities without separate validation.

## 2. Real Public Corpus Measurement

### 2.1 Collection protocol

- Sources: GitHub public repositories returned by MCP-related search queries, npm packages returned by MCP-related registry search terms, discovered PyPI MCP packages, Hugging Face Spaces returned by MCP-oriented space search terms, hosted Smithery registry entries returned by MCP-oriented registry search terms, and official MCP Registry entries returned by the registry list API.
- Collector: `experiments/scripts/crawl_real_ecosystem.py`.
- Output files:
  - `experiments/results/ecosystem/real_ecosystem_samples.jsonl`
  - `experiments/results/ecosystem/real_ecosystem_results.json`
  - `experiments/results/ecosystem/real_ecosystem_data_card.json`
  - `experiments/results/ecosystem/real_high_risk_triage.json`
- Dedup rule: source-specific artifact identifier (`full_name` for GitHub, package name for npm/PyPI, space id for Hugging Face, `qualifiedName` for Smithery, and server `name` for the official MCP Registry), with `linked_repository` recorded when an upstream package points to GitHub.
- Version provenance: GitHub `default_branch` plus `created_at`/`updated_at`/`pushed_at`; npm/PyPI latest package version plus publication/update timestamps; Hugging Face `sha` plus `createdAt`/`lastModified` when exposed; Smithery `createdAt` plus hosted deployment metadata when exposed; official MCP Registry `publishedAt`/`updatedAt` plus server version when exposed.
- License provenance: SPDX identifier when an upstream API provides one; otherwise `unknown`.
- Source coverage: fetch a bounded set of likely Python/TypeScript/JavaScript entrypoints using explicit candidates, GitHub contents listings, package.json-derived entrypoints, and Hugging Face `app_file`/`sibling` metadata when available; hosted Smithery entries and official MCP Registry entries remain metadata-only because the collector does not execute or decompile remote services.

### 2.2 Dataset statistics

| Metric | Value |
|---|---:|
| Total public artifacts | 1,000 |
| GitHub MCP repositories | 300 |
| npm MCP packages | 200 |
| PyPI MCP packages | 150 |
| Hugging Face Spaces | 150 |
| Smithery hosted registry entries | 100 |
| Official MCP Registry entries | 100 |
| Source-available samples | 15 |
| Manifest-only samples | 985 |
| High severity | 1 |
| Medium severity | 35 |
| Low severity | 964 |
### 2.3 Language and license mix

Top language counts in the measured corpus:

| Language | Count |
|---|---:|
| Unknown | 215 |
| Python | 307 |
| Official/hosted remote | 200 |
| Gradio | 98 |
| TypeScript | 90 |

Top license counts:

| License | Count |
|---|---:|
| Unknown | 481 |
| MIT | 296 |
| Apache-2.0 | 115 |
| NOASSERTION | 29 |
| AGPL-3.0 | 17 |

### 2.4 Risk-pattern prevalence

| Pattern | Count | Rate |
|---|---:|---:|
| Missing signature | 800 | 80.0% |
| Untrusted publisher | 552 | 55.2% |
| Open-world network access | 199 | 19.9% |
| Scope inflation | 31 | 3.1% |
| Instruction-like descriptions | 2 | 0.2% |
| Description-code mismatch | 7 | 0.7% |

### 2.5 Interpretation

1. **Governance provenance remains weak even after adding both hosted and official registry slices.** Missing signatures still appear on 800/1,000 artifacts (80.0%) because GitHub repositories, many PyPI projects, Hugging Face Spaces, and public registries do not expose strong signing metadata through the passive collector.
2. **Only a very small fraction of artifacts trigger high-severity passive findings.** After the refined six-source passive crawl, the real corpus produces 1 HIGH finding and 35 MEDIUM findings, and the remaining HIGH finding remains unconfirmed after manual review.
3. **Metadata-only coverage still dominates.** 985/1,000 artifacts remain manifest-only because the collector intentionally bounds source probing and does not recurse through full repositories, package tarballs, or hosted services. This is acceptable for catalog-level measurement but not for code-complete vulnerability confirmation.
4. **Source discovery is broader but still bounded.** The collector now combines GitHub contents listings, package.json-derived entrypoints, broad PyPI simple-index discovery, Hugging Face `app_file`/sibling metadata, Smithery hosted-registry metadata, and the official MCP Registry list API before bounded source fetch, but the full 1,000-artifact batch still remains overwhelmingly metadata-only.
5. **Multi-source coverage is stronger than the prior GitHub-only snapshot, but still incomplete.** The current batch spans GitHub MCP repositories, npm MCP packages, 150 discovered PyPI MCP packages, 150 Hugging Face Spaces, 100 Smithery hosted-registry entries, and 100 official MCP Registry entries; it still does not cover private enterprise catalogs.
6. **Real-world prevalence is much lower than synthetic stress prevalence.** This is expected: the synthetic corpus is designed to exercise suspicious patterns, while the public corpus is used as a conservative external-validity check.

### 2.5.1 Public advisory cross-check

We additionally cross-check the main 1,000-artifact public corpus against a curated set of official MCP advisories recorded in `experiments/results/ecosystem/public_advisory_audit.json`. The current audit now tracks five official MCP-related advisories: `GHSA-345p-7cg4-v4c7` / `CVE-2026-25536` for `@modelcontextprotocol/sdk`, `GHSA-vjqx-cfc4-9h6v` / `CVE-2026-27735` for `@modelcontextprotocol/server-git`, `GHSA-q66q-fx2p-7w4m` / `CVE-2025-53109` for `@modelcontextprotocol/server-filesystem`, `GHSA-j975-95f5-7wqh` / `CVE-2025-53365` for `mcp`, and `GHSA-rww4-4w9c-7733` / `CVE-2026-27124` for `fastmcp`. Four advisory-backed package families are present in the checked-in corpus, and all observed versions are patched, so the cross-check still yields 0 currently vulnerable matches in the measured snapshot. We treat this as external grounding for real ecosystem risk, not as a replacement for disclosure-backed validation of newly surfaced findings.

### 2.6 Supplementary scaled batch


A supplementary large-batch run is checked in as:

- `experiments/results/ecosystem/real_ecosystem_large_results.json`
- `experiments/results/ecosystem/real_ecosystem_large_data_card.json`

This run uses the passive collector with `--target 2000 --pages-per-query 3 --source-budget 25 --sources github_mcp,npm_mcp,hf_spaces_mcp --output-prefix real_ecosystem_large --resume` and reaches 2,000 artifacts (1,200 GitHub, 500 npm, 300 Hugging Face). It produces 0 HIGH and 9 MEDIUM findings, but only 5 source-available samples. We therefore treat it as a scale-out catalog measurement, not as stronger code-level validation.

### 2.7 Supplementary XL batch

A larger supplementary batch is also checked in as:

- `experiments/results/ecosystem/real_ecosystem_xl_results.json`
- `experiments/results/ecosystem/real_ecosystem_xl_data_card.json`

This run uses `--target 3000 --pages-per-query 3 --source-budget 25 --output-prefix real_ecosystem_xl --resume` and reaches 3,000 artifacts (1,999 GitHub, 600 npm, 20 curated PyPI, 381 Hugging Face). It produces 0 HIGH and 14 MEDIUM findings, but only 2 source-available samples. We treat it as a scale-out catalog measurement that improves ecosystem breadth, not as stronger code-level validation.


### 2.8 Supplementary 5k batch

A 5,000-artifact quota-tuned batch is also checked in as:

- `experiments/results/ecosystem/real_ecosystem_5k_results.json`
- `experiments/results/ecosystem/real_ecosystem_5k_data_card.json`

This run uses `--target 5000 --pages-per-query 6 --source-budget 25 --sources github_mcp,npm_mcp,pypi_mcp,hf_spaces_mcp --source-quotas github_mcp=2600,npm_mcp=2000,pypi_mcp=20,hf_spaces_mcp=380 --output-prefix real_ecosystem_5k --resume` and reaches 5,000 artifacts. It produces 0 HIGH and 59 MEDIUM findings, but only 21 source-available samples. We treat it as a scale-out catalog measurement that reaches the roadmap's minimum real-corpus scale target without upgrading any exploit or deployment claims.
### 2.9 Supplementary 10k batch

A 10,000-artifact quota-tuned batch is also checked in as:

- `experiments/results/ecosystem/real_ecosystem_10k_results.json`
- `experiments/results/ecosystem/real_ecosystem_10k_data_card.json`

This run uses `--target 10000 --pages-per-query 10 --source-budget 0 --sources github_mcp,npm_mcp,pypi_mcp,hf_spaces_mcp --source-quotas github_mcp=4000,npm_mcp=4000,pypi_mcp=1620,hf_spaces_mcp=380 --output-prefix real_ecosystem_10k --resume` and reaches 10,000 artifacts. It produces 0 HIGH and 112 MEDIUM findings, but 0 source-available samples because the batch disables source fetch for scale. We treat it as breadth-only catalog evidence that satisfies the roadmap's strongest public-corpus scale target, not as deeper implementation validation.

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

1. **Query and registry bias.** The real corpus now spans GitHub, npm, broad PyPI simple-index discovery, Hugging Face Spaces, Smithery's public hosted registry, and the official MCP Registry, but it still excludes private enterprise catalogs.
2. **Manifest-only dominance.** Most real samples are metadata-only because the collector intentionally bounds raw source fetching for safety and runtime reasons.
3. **No runtime validation.** The real measurement does not execute third-party code, so it cannot confirm dynamic exfiltration, persistence, or approval-laundering behaviors.
4. **No confirmed-vulnerability claims.** The measurement is appropriate for prevalence and governance observations, not for naming exploitable packages without follow-up validation.

## 6. Claim boundary

Use the real measurement to support the claim that governance metadata across public MCP repositories, packages, and spaces is immature (especially signatures/provenance) and that passive catalog measurement can surface suspicious mismatches. Do **not** use it to claim that SkillGuardGraph has validated real-world exploit paths for the named artifacts above.
