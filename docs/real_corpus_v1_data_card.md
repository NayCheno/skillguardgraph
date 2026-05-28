# Real Corpus v1 Data Card

## Overview

| Field | Value |
|---|---|
| Corpus name | SkillGuardGraph Real Public MCP Corpus v1 |
| Version | 1.0.0 |
| Collection date | 2026-05-28 |
| Collector | `experiments/scripts/crawl_real_ecosystem.py` |
| Total artifacts | 1,000 |
| Source-available | 15 (1.5%) |
| Manifest-only | 985 (98.5%) |

## Source distribution

| Source | Count | Quota |
|---|---|---|
| GitHub MCP repositories | 300 | 30% |
| npm MCP packages | 200 | 20% |
| PyPI MCP packages (discovered) | 150 | 15% |
| Hugging Face Spaces | 150 | 15% |
| Smithery hosted registry | 100 | 10% |
| Official MCP Registry | 100 | 10% |

## Language distribution

| Language | Count |
|---|---|
| Python | 307 |
| Unknown | 215 |
| Official/hosted remote | 200 |
| Gradio | 98 |
| TypeScript | 90 |

## License distribution

| License | Count |
|---|---|
| Unknown | 481 |
| MIT | 296 |
| Apache-2.0 | 115 |
| NOASSERTION | 29 |
| AGPL-3.0 | 17 |

## Risk severity

| Severity | Count | Rate |
|---|---|---|
| Low | 963 | 96.3% |
| Medium | 35 | 3.5% |
| High | 2 | 0.2% |

## Risk patterns

| Pattern | Count | Rate |
|---|---|---|
| Missing signature | 800 | 80.0% |
| Untrusted publisher | 552 | 55.2% |
| Open-world network access | 199 | 19.9% |
| Scope inflation | 31 | 3.1% |
| Description-code mismatch | 7 | 0.7% |
| Instruction-like descriptions | 2 | 0.2% |

## Source-available findings

8 of 15 source-available artifacts have policy findings (C1/C7 constraints):
- 2 HIGH (firecrawl/firecrawl-mcp-server: C1 + C7)
- 6 MEDIUM (Figma-Context-MCP, Portkey-AI/gateway, mission-control, n8n-mcp, firebase-tools: C1 + C7)

All findings are L2 (explainable cross-layer paths without runtime replay). No L3/L4 confirmed findings.

## Sampling bias

1. **GitHub-heavy.** 30% of the corpus comes from GitHub search, which over-represents popular/active repositories.
2. **English-centric.** Search queries are in English, potentially missing non-English MCP ecosystems.
3. **Public-only.** Private enterprise catalogs, internal tools, and non-public marketplaces are excluded.
4. **Source-fetching bounded.** Only 15/1,000 artifacts had source entrypoints resolved due to safety and runtime constraints.
5. **No runtime validation.** The collector does not execute third-party code.

## Safety constraints

- No real credentials used
- No operational payloads generated
- No destructive probing performed
- Source analysis is passive (regex + AST pattern matching only)
- All findings require manual triage before any external communication

## Reproduction

```bash
cd experiments
PYTHONPATH=src python scripts/crawl_real_ecosystem.py --target 1000 --pages-per-query 2 --output-prefix real_ecosystem_results
```

Note: Reproduction requires network access to GitHub API, npm registry, PyPI, Hugging Face, Smithery, and the official MCP Registry. Results may vary due to repository availability and API rate limits.
