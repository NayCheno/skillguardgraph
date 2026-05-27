# Disclosure Log

This log records the disposition of real-ecosystem findings reviewed during the passive multi-source MCP measurement.

## 2026-05-27 review batch

### Scope

- Source corpus: `experiments/results/ecosystem/real_ecosystem_samples.jsonl`
- Summary stats: `experiments/results/ecosystem/real_ecosystem_results.json`
- Manual triage: `experiments/results/ecosystem/real_high_risk_triage.json`
- Review boundary: passive metadata and checked-in source review only; no third-party code execution, no destructive validation, no credential use.

### Outcome

| Repo | Initial risk | Triage result | Disclosure |
|---|---|---|---|
| `idosal/git-mcp` | HIGH | Likely false positive / metadata-capability mismatch only | Not sent |
| `firecrawl/firecrawl-mcp-server` | HIGH | Likely false positive / insufficient exploit evidence | Not sent |

### Rationale

No artifact in this batch met the disclosure template threshold in `docs/disclosure_log_template.md`:

1. no finding was confirmed exploitable in a controlled environment;
2. no material unauthorized data access or destructive effect was reproduced; and
3. the passive evidence was insufficient to distinguish a true vulnerability from heuristic scope extraction noise.

Accordingly, this batch produced **0 confirmed vulnerabilities** and **0 outbound disclosures**. The artifacts remain categorized as suspicious measurement examples only and are not named in the paper as confirmed vulnerable packages.
