# Related Work Matrix

| Work / Source | Main focus | Limitation for this paper's target | How SkillGuardGraph differs |
|---|---|---|---|
| MCP Specification | Protocol, tools, resources, prompts, authorization, trust and safety guidance | Specification guidance is not a complete detection framework | Uses MCP concepts as evidence surfaces and enforces graph constraints |
| OWASP MCP Tool Poisoning | Runtime tool-response poisoning and trust gap | Describes attack and mitigations, not a benchmark/system | Models runtime response as tainted evidence and links it to high-privilege calls |
| MCPTox | Benchmark for MCP metadata tool poisoning | Focuses primarily on registration-stage metadata poisoning | Extends to implementation, runtime, approval, persistence, and updates |
| MCP-ITP | Implicit tool poisoning, poisoned tool can remain uninvoked | Focuses on metadata-driven implicit attack generation | Adds permission/provenance/sequence-level containment |
| ToolHijacker | Tool-selection attack via malicious tool documents | Focuses on retrieval/selection | Extends to execution governance and cross-tool flow |
| TRUSTDESC | Trusted description generation from implementation | Requires analyzable implementation and focuses on descriptions | Treats trusted description as one graph evidence source |
| VIPER-MCP | Taint-style vulnerability auditing in MCP servers | Strong implementation-level focus, less about agent call-chain policy | Integrates taint evidence with runtime provenance and permissions |
| MCP-BiFlow | Bidirectional data-flow risks in MCP ecosystem | Strong flow analysis, less about approval/version/policy governance | Adds lifecycle-wide graph constraints and enforcement decisions |
| MCPShield | Adaptive trust calibration for MCP agents | Invocation-centered trust cognition; overlap risk | Differentiates through typed cross-layer graph, drift, approval integrity, and naive-union ablation |
| NIST AI RMF / GenAI Profile | Lifecycle risk management | High-level governance guidance | Operationalizes lifecycle governance into evidence graph and policy actions |
| CCF NIS A list | Venue classification | Not technical prior work | Helps target CCS/S&P/USENIX Security/NDSS-style contribution standards |

