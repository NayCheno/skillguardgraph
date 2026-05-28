# Real-World Unsafe Chain Inventory

This document catalogs cross-layer unsafe chains identified by SkillGuardGraph in real public MCP artifacts.

## Classification

| Level | Definition | Paper usage |
|---|---|---|
| L1 risk signal | Metadata/source layer inconsistency | Ecosystem risk pattern statistics |
| L2 unsafe chain | Explainable cross-layer path, not replayed | High-confidence unsafe chain |
| L3 replay-confirmed | Sandbox/read-only replay confirms path | Confirmed unsafe behavior |
| L4 confirmed vulnerability | Vendor/maintainer confirmed, or reproducible exploitable path | Vulnerability claim |

## Current findings

### L2 unsafe chains (source-available artifacts with cross-layer evidence)

| # | Artifact | Source | Risk | Constraints | Evidence layers | L2 confidence |
|---|---|---|---|---|---|---|
| 1 | firecrawl/firecrawl-mcp-server | github | HIGH | C1, C7 | metadata + static (network_send sink, env_var source, credential label, external sink) | High |
| 2 | GLips/Figma-Context-MCP | github | MEDIUM | C1, C7 | metadata + static (credential label, write/export scopes vs read-only claim) | High |
| 3 | Portkey-AI/gateway | github | MEDIUM | C1, C7 | metadata + static (env_var source, untrusted label, write/export scopes) | High |
| 4 | builderz-labs/mission-control | github | MEDIUM | C1, C7 | metadata (admin + write + export + send + run scopes vs read-only claim) | Medium |
| 5 | czlonkowski/n8n-mcp | github | MEDIUM | C1, C7 | metadata (export scope vs read_only annotation, trusted server claim) | Medium |
| 6 | firebase/firebase-tools | github | MEDIUM | C1, C7 | metadata (delete + export + run scopes vs read-only claim) | Medium |
| 7 | ahujasid/blender-mcp | github | LOW | — | metadata + static (subprocess sink observed in sandbox) | Low |
| 8 | BeehiveInnovations/pal-mcp-server | github | LOW | — | static (shell_exec sink via subprocess) | Low |

### L1 risk signals (manifest-only artifacts with metadata inconsistencies)

| Pattern | Count | Rate |
|---|---|---|
| Missing signature | 800/1,000 | 80.0% |
| Untrusted publisher | 552/1,000 | 55.2% |
| Open-world network access | 199/1,000 | 19.9% |
| Scope inflation | 31/1,000 | 3.1% |
| Description-code mismatch | 7/1,000 | 0.7% |
| Instruction-like descriptions | 2/1,000 | 0.2% |

## Detailed case studies

### Case 1: firecrawl/firecrawl-mcp-server (HIGH)

**Artifact:** https://github.com/firecrawl/firecrawl-mcp-server
**Language:** JavaScript | **License:** MIT | **Stars:** 6,401

**Cross-layer evidence chain:**
1. **Metadata layer:** Manifest declares `read_only_or_low_risk` capability, requests `read`, `list`, `send`, `query` scopes.
2. **Static layer:** Source code identifies `network_send` sink, `env_var` source, `credential` data label, and `external` sink type.
3. **Mismatch:** Manifest claims read-only behavior, but implementation includes outbound network calls to external services using API credentials from environment variables.

**Constraint violations:**
- C1 (Declaration-Implementation-Permission): Declared read-only but implementation performs network sends.
- C7 (Least-Privilege Scope): Task context suggests read-only need but skill requests send/query scopes.

**Interpretation:** This is a web scraping MCP server that necessarily makes outbound HTTP requests. The C1 finding reflects a genuine mismatch between the manifest's "read-only" claim and the tool's actual network behavior. While this is likely intentional functionality rather than malicious behavior, it demonstrates that cross-layer evidence fusion correctly identifies declaration-implementation inconsistencies that single-layer metadata scanning would flag as benign.

### Case 2: GLips/Figma-Context-MCP (MEDIUM)

**Artifact:** https://github.com/GLips/Figma-Context-MCP
**Language:** TypeScript | **License:** MIT | **Stars:** 14,889

**Cross-layer evidence chain:**
1. **Metadata layer:** Manifest claims `read_only` annotation, requests `read`, `list`, `send`, `export`, `write` scopes.
2. **Static layer:** Source code contains `credential` data label and `credential_access` inferred capability.
3. **Mismatch:** Tool claims read-only but requests write and export scopes, and accesses Figma API credentials.

**Constraint violations:**
- C1: Read-only annotation contradicts write/export scope requests.
- C7: Elevated scopes exceed what a read-only viewer would need.

**Interpretation:** Figma MCP needs write access to modify designs and export assets. The metadata annotations are inaccurate, creating a cross-layer inconsistency.

### Case 3: Portkey-AI/gateway (MEDIUM)

**Artifact:** https://github.com/Portkey-AI/gateway
**Language:** TypeScript | **License:** MIT | **Stars:** 11,879

**Cross-layer evidence chain:**
1. **Metadata layer:** Requests `read`, `list`, `send`, `export`, `write` scopes.
2. **Static layer:** Source identifies `env_var` source, `untrusted` source label.
3. **Mismatch:** Gateway reads API keys from environment and forwards requests to external LLM providers.

**Constraint violations:**
- C1: Write/export scopes for what could be a read-only proxy.
- C7: Scope exceeds typical read-only gateway need.

## Disclosure status

| Artifact | Disclosure decision | Reason |
|---|---|---|
| firecrawl/firecrawl-mcp-server | Not sent | Likely false positive: intentional network behavior for web scraping |
| GLips/Figma-Context-MCP | Not sent | Metadata inaccuracy, not a security vulnerability |
| Portkey-AI/gateway | Not sent | Expected behavior for API gateway |
| builderz-labs/mission-control | Not sent | Admin scope appropriate for agent management |
| czlonkowski/n8n-mcp | Not sent | Export scope for workflow automation |
| firebase/firebase-tools | Not sent | Delete/export scopes for Firebase management |

## Limitations

1. **No L3/L4 findings.** None of the source-available findings have been replay-confirmed or vendor-confirmed. All are L2 (explainable cross-layer paths without runtime confirmation).
2. **Passive analysis only.** The collector does not execute third-party code, so dynamic behaviors (conditional network access, delayed persistence) are not observed.
3. **Scope mismatch is common.** Many MCP tools request broader scopes than their annotations claim, which may reflect metadata template reuse rather than intentional deception.
4. **No dual-human audit.** Single-reviewer triage only; Cohen's κ cannot be computed.
