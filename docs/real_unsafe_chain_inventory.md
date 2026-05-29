# Real-World Unsafe Chain Inventory

This document catalogs cross-layer unsafe chains identified by SkillGuardGraph in real public MCP artifacts, with LLM-assisted dual-reviewer classification.

## Classification

| Level | Definition | Paper usage |
|---|---|---|
| L1 risk signal | Metadata/source layer inconsistency | Ecosystem risk pattern statistics |
| L2 unsafe chain | Explainable cross-layer path, not replayed | High-confidence unsafe chain |
| L3 replay-confirmed | Sandbox/read-only replay confirms path | Confirmed unsafe behavior |
| L4 confirmed vulnerability | Vendor/maintainer confirmed, or reproducible exploitable path | Vulnerability claim |

## LLM Review Summary

| Metric | Value |
|---|---|
| Total artifacts reviewed | 86 |
| Reviewer agreement rate | 77% (66/86) |
| L1 (risk signal) | 66 |
| L2 (unsafe chain) | 20 |
| L3 (replay-confirmed) | 0 |
| L4 (confirmed vulnerability) | 0 |

## L2 Unsafe Chains (20 findings)

| # | Artifact | Source | Availability | Key Evidence |
|---|---|---|---|---|
| 1 | GLips/Figma-Context-MCP | github | source_available | C1+C7: read_only annotation vs write/export scopes + credential access |
| 2 | builderz-labs/mission-control | github | source_available | C1+C7: admin+write+export+send+run scopes vs read-only claim |
| 3 | search-mcp-server | pypi | source_available | Read-only claim with network-capable search implementation |
| 4 | HolmesGPT/holmesgpt | github | source_available | Network access patterns in observability tool |
| 5 | JoeanAmier/XHS-Downloader | github | source_available | Data download + persistence patterns |
| 6 | NoeFabris/opencode-antigravity-auth | github | source_available | Auth-related cross-layer patterns |
| 7 | ParisNeo/lollms-webui | github | source_available | Web UI with elevated scope requests |
| 8 | TraderAlice/OpenAlice | github | source_available | Trading tool with network+write patterns |
| 9 | financial-datasets/mcp-server | github | source_available | Financial data access with network sinks |
| 10 | @iflow-mcp/garethcott-enhanced-postgres-mcp-server | npm | manifest_only | C1+C7: read-only vs write scope mismatch |
| 11 | @solvapay/mcp | npm | manifest_only | C1+C7: export scope vs read-only annotation |
| 12 | linux-mcp-server | pypi | manifest_only | C1+C7: admin scope request |
| 13 | andysalvo/agentic-platform | smithery | manifest_only | C1+C7: modify scope vs read-only claim |
| 14 | mpprimo/ratings | smithery | manifest_only | C1+C7: send scope vs read-only annotation |
| 15 | rafsilva85/skillflow | smithery | manifest_only | Scope inflation pattern |
| 16 | xqb/vibe-pay | smithery | manifest_only | Payment tool with elevated scopes |
| 17 | zoro/orchestrator | smithery | manifest_only | Orchestration tool with broad permissions |
| 18 | ai.agentdm/agentdm | official_registry | manifest_only | Agent management with elevated scopes |
| 19 | ai.cirra/salesforce-mcp | official_registry | manifest_only | CRM integration with broad permissions |
| 20 | JHSeo-git/my-first-mcp-2 | smithery | manifest_only | Network access patterns in tool |

## Disclosure Status

| Artifact | Disclosure Decision | Reason |
|---|---|---|
| All 20 L2 findings | Not sent | Metadata governance issues, not exploitable vulnerabilities |

## Limitations

1. **No L3/L4 findings.** None of the findings have been replay-confirmed or vendor-confirmed.
2. **Passive analysis only.** The collector does not execute third-party code.
3. **LLM reviewer limitations.** LLM-based classification has 77% agreement rate; some L2 classifications may be false positives.
4. **Source coverage.** Only 50/1,000 artifacts have source code available for analysis.
