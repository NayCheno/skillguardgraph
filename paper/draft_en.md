# SkillGuardGraph: Cross-Layer Evidence Fusion for Detecting and Containing Malicious Skills in LLM Agent Ecosystems

> Working draft for a CCF-A-style systems security paper.

## Abstract

Large language model (LLM) agents increasingly rely on external skills—tools, connectors, actions, applications, MCP servers, blocks, and graph nodes—to access private data, invoke APIs, modify files, and perform persistent work across sessions. This capability expansion creates a new security problem: malicious skills can exploit the gaps between declared metadata, implemented behavior, granted permissions, runtime outputs, user approval, and post-approval updates. Existing defenses typically operate at a single layer, such as prompt-injection filtering, metadata scanning, static analysis, sandbox probing, or human-in-the-loop approval. We argue that malicious skills are compositional objects, and that their most damaging behaviors emerge across lifecycle and privilege boundaries.

We present **SkillGuardGraph**, a cross-layer evidence fusion framework for detecting and containing malicious skills in LLM agent ecosystems. SkillGuardGraph represents skill metadata, implementation summaries, sandbox observations, runtime provenance, permission scopes, approval dialogs, and version histories as a typed evidence graph. It then enforces source-aware, permission-aware, and version-aware constraints over tool-call chains. This design enables detection of attacks that are invisible to single-layer defenses, including capability laundering, cross-skill confused deputy attacks, delayed rug-pulls, consent laundering, persistence pivots, split exfiltration, and scope inflation.

We propose a benchmark and evaluation protocol spanning real benign skills, real-world MCP/tool samples, metadata poisoning cases, implementation mismatch cases, runtime-output poisoning cases, cross-skill sequences, persistence attacks, and update-drift attacks. The evaluation compares SkillGuardGraph with metadata-only detectors, implementation-only analyzers, sandbox-only probing, runtime-only policies, and a naive detector union. The central hypothesis is that graph fusion preserves high recall on compositional attacks while materially reducing false positives and approval burden relative to naive combination.

## 1. Introduction

LLM agents are no longer isolated chat systems. They increasingly operate through external skills: OpenAI Actions and Apps, Anthropic connectors and MCP servers, Microsoft Copilot connectors and plugins, LangChain tools and graphs, AutoGPT blocks and agents, and Google Vertex AI Agent Builder extensions. These skills act as discoverable and reusable capability units outside the model’s core reasoning loop. They connect models to files, repositories, enterprise knowledge bases, cloud APIs, email systems, ticketing systems, and local execution environments.

This shift changes the threat model. Prompt injection is no longer only about causing a model to produce unsafe text. A malicious or compromised skill can manipulate tool selection, request excessive permissions, return untrusted instructions as context, alter persistent memory or configuration, and exploit differences between what the user approves and what the execution layer actually performs.

A common defensive response is to stack several controls: scan the manifest, scan the code, run a sandbox, require approval, and log the event. This is necessary but insufficient. The critical security property often does not belong to one tool or one layer. It belongs to a sequence:

```text
untrusted web page → model context → internal search tool → confidential result → third-party summarizer → external send action
```

Every individual step can appear legitimate, while the composed flow violates a policy. Similarly, a skill may be approved as read-only, then later update its handler, expand OAuth scopes, or return instruction-like output that affects high-privilege actions. These behaviors cannot be reliably captured by a single metadata classifier or a static analyzer.

This paper makes the following claim:

> Malicious skills exploit cross-layer trust gaps that are invisible to single-layer defenses. Effective defense requires evidence fusion across declaration, implementation, permission, runtime provenance, approval integrity, persistence, and version drift.

### Contributions

1. **Threat taxonomy.** We define a compositional taxonomy of malicious skill behaviors: capability laundering, cross-skill confused deputy, delayed rug-pull, consent laundering, persistence pivot, split exfiltration, and scope inflation.
2. **Evidence graph.** We introduce a typed cross-layer evidence graph that unifies metadata, implementation, sandbox, runtime, permission, approval, and version evidence.
3. **Constraint system.** We define source-aware and permission-aware constraints over evidence paths and call sequences.
4. **Benchmark design.** We propose a lifecycle-complete benchmark with benign-paired cases and trace-grounded validators.
5. **Evaluation plan.** We provide an ablation methodology that explicitly compares graph fusion with naive detector union.

## 2. Background

### 2.1 Skills in agent ecosystems

We use *skill* as a platform-neutral term for external capability units that an LLM agent can discover, register, invoke, and reuse. A skill may be implemented as an MCP server tool, a custom connector, an OpenAPI action, a LangChain tool, an AutoGPT block, or a managed cloud extension. Despite naming differences, these artifacts share four properties:

1. They expose metadata that describes their capabilities.
2. They often require permissions or credentials.
3. They return outputs that may re-enter the model context.
4. They may evolve over time through updates or configuration changes.

### 2.2 Model Context Protocol as a representative substrate

MCP standardizes how LLM applications integrate external data sources and tools. It defines hosts, clients, servers, resources, prompts, and tools. Tools enable models to interact with external systems and may represent arbitrary code execution or data access paths. The MCP specification explicitly requires attention to user consent, data privacy, and tool safety, and notes that descriptions or annotations should be treated as untrusted unless they originate from trusted servers.

MCP is useful for this paper because it exposes the core elements of the broader skill ecosystem: metadata, tool schemas, model-controlled invocation, tool results, authorization, roots, and server trust boundaries. However, the proposed framework is not MCP-specific.

### 2.3 Existing defenses

Existing approaches can be grouped into six categories:

| Layer | Example defense | Limitation |
|---|---|---|
| Metadata | rules, LLM judge, description vetting | misses implementation and runtime behavior |
| Implementation | SAST, taint analysis, capability extraction | unavailable for closed-source skills; weak on runtime chains |
| Dynamic | sandbox probing, synthetic tasks | coverage and cost limitations |
| Runtime | policy enforcement, least privilege | needs provenance and pre-deployment context |
| Approval | HITL prompts | approval text can be contaminated or incomplete |
| Governance | signatures, reputation, audit, rollback | often post-hoc unless fused into policy decisions |

These layers are complementary, but naive composition can increase false positives without detecting subtle cross-layer attacks. SkillGuardGraph addresses this through evidence fusion.

## 3. Threat Model

### 3.1 Assets

We consider the following assets:

- private files and repositories;
- enterprise documents and knowledge bases;
- credentials, tokens, and OAuth grants;
- email, messaging, ticketing, and external APIs;
- persistent memory, configuration, hooks, policy stores, and agent settings;
- user trust and approval decisions.

### 3.2 Attacker capabilities

The attacker may:

- publish or operate a third-party skill;
- compromise a benign skill or its update chain;
- control external content that a skill reads, such as a webpage, email, document, repository, or ticket;
- craft metadata, schema, or descriptions to manipulate tool selection;
- cause a skill to return untrusted or instruction-like output;
- request excessive permissions;
- influence approval dialogs or summaries;
- introduce delayed behavior via version or dependency updates.

The attacker does not need direct access to the model weights or system prompt.

### 3.3 Non-goals

We do not aim to prove that all prompt injection can be detected. We also do not require model internals. The system is intended to reduce attack success and blast radius by enforcing constraints at the skill lifecycle and execution layers.

## 4. Compositional Malicious Skill Behaviors

### 4.1 Capability laundering

A skill declares benign behavior but implements or requests high-risk capabilities. Example evidence chain:

```text
declares(read_only_summary) + requires_scope(write/export) + observes(external_write)
```

### 4.2 Cross-skill confused deputy

An untrusted skill does not execute a harmful action itself. Instead, it influences the agent to call a trusted internal tool.

```text
untrusted_tool_output → model_context → call(internal_high_privilege_tool)
```

### 4.3 Delayed rug-pull

The skill is benign during review but changes behavior after approval.

```text
approved(v1) → update(v1.1) → behavior_fingerprint_drift → high_risk_event
```

### 4.4 Consent laundering

The approval dialog is influenced by untrusted context, presenting a high-risk action as a benign one.

```text
untrusted_context → approval_text
actual_action = external_write(confidential_data)
```

### 4.5 Persistence pivot

The attack writes to persistent memory, configuration, hooks, or policy stores so that later sessions are influenced.

```text
untrusted_source → persistent_store_write
```

### 4.6 Split exfiltration

Multiple individually benign tools combine to exfiltrate sensitive data.

```text
sensitive_read → transform → external_write
```

### 4.7 Scope inflation

The user task only requires low privilege, but the skill requests broad permissions.

```text
task_need(read) + granted_scope(write/delete/export/admin)
```

## 5. SkillGuardGraph Design

### 5.1 Overview

SkillGuardGraph is composed of six modules:

```text
Skill registry / connector catalog / MCP server
        │
        ▼
Metadata Analyzer
        ▼
Implementation Analyzer
        ▼
Sandbox Prober
        ▼
Runtime Provenance Monitor
        ▼
Evidence Fusion Graph
        ▼
Policy Enforcer
```

### 5.2 Evidence model

An evidence item is a typed assertion:

```text
Evidence(kind, subject, predicate, object, confidence, attributes)
```

Examples:

```json
{
  "kind": "metadata",
  "subject": "tool:pdf_summarizer",
  "predicate": "declares_capability",
  "object": "read_only_summary",
  "confidence": 0.91,
  "attributes": {"source": "manifest.description"}
}
```

```json
{
  "kind": "runtime",
  "subject": "call:42",
  "predicate": "flows_to",
  "object": "sink:external_email",
  "confidence": 0.88,
  "attributes": {"data_label": "confidential", "source_label": "untrusted"}
}
```

### 5.3 Graph schema

#### Node types

| Node type | Examples |
|---|---|
| Skill | MCP server, connector, action, tool |
| Version | approved version, candidate update |
| Metadata | description, schema, annotations |
| CodeSlice | handler, dependency, sink, source |
| RuntimeEvent | tool call, response, network event, file event |
| DataObject | document, token, repository file, email |
| TrustLabel | internal, approved third-party, unknown, untrusted |
| PolicyDecision | allow, degrade, HITL, deny, quarantine, rollback |

#### Edge types

| Edge | Meaning |
|---|---|
| declares | metadata claims capability |
| implements | code supports capability |
| observes | sandbox/runtime observes behavior |
| flows_to | data or instruction flows between nodes |
| calls | agent invokes tool |
| requires_scope | skill requires permission |
| signed_by | version signature |
| updated_from | version drift |
| approved_by | approval chain |

## 6. Constraint System

### C1. Declaration–implementation–permission consistency

A skill violates C1 when declared capability, inferred capability, and granted permission materially disagree.

```text
DeclaredCapability ⊆ InferredCapability ⊆ GrantedPermission
```

This is enforced as a graph query over `declares`, `implements`, and `requires_scope` edges.

### C2. Source-aware high-privilege flow

A high-risk finding is generated when an untrusted source reaches a high-privilege tool or external sink without an explicit policy boundary.

```text
UntrustedSource → LLMContext → HighPrivilegeTool → ExternalSink
```

### C3. Cross-tool exfiltration sequence

The system identifies call sequences in which sensitive data is read, transformed, and externalized.

```text
SensitiveRead → Transform → ExternalWrite
```

This is a sequence property, not a tool property.

### C4. Version drift after approval

A skill update is flagged if post-approval behavior fingerprint changes in high-risk dimensions.

```text
approved(v) ∧ updated_to(v') ∧ drift(v,v') > τ ∧ high_risk(v')
```

### C5. Approval integrity

Approval text is unsafe if it is derived solely from model context or untrusted tool output. The UI must include execution-layer facts: true action, target sink, affected data class, permission scope, and reversibility.

### C6. Persistence boundary

Any flow from untrusted sources to persistent stores is high risk unless explicitly isolated and reversible.

## 7. Implementation Plan

### 7.1 Metadata Analyzer

Inputs: manifest, tool description, JSON schema, annotations, OAuth scopes, publisher metadata.

Outputs:

- declared capabilities;
- suspicious instruction-like content;
- scope mismatch signals;
- annotation trust label;
- publisher/signature status.

### 7.2 Implementation Analyzer

Inputs: source code or package artifact when available.

Outputs:

- recovered entrypoints;
- inferred capabilities;
- sources and sinks;
- taint summaries;
- dependency risk metadata.

The implementation analyzer can wrap existing SAST tools. Its output is normalized into evidence items.

### 7.3 Sandbox Prober

Inputs: candidate skill, synthetic tasks, fake credentials, fake files, fake enterprise data.

Outputs:

- observed file operations;
- observed network operations to sinkhole;
- observed persistent writes;
- observed mismatch between claimed and actual behavior.

### 7.4 Runtime Provenance Monitor

Inputs: production or staging traces.

Outputs:

- source labels for user, web, email, document, tool output, internal data;
- tool-call chains;
- argument and result summaries;
- approval dialog lineage;
- policy decisions.

### 7.5 Policy Enforcer

Policy decisions:

| Decision | Use case |
|---|---|
| allow | low-risk, trusted evidence path |
| degrade | run with reduced permissions or structured output only |
| HITL | require user/admin approval with execution-layer facts |
| sandbox-only | run in isolated environment |
| deny | high-risk policy violation |
| quarantine | remove from catalog or disable version |
| rollback | revert to previously approved version |

## 8. Benchmark and Evaluation

### 8.1 Dataset

We propose four corpora:

1. **Real benign corpus**: open-source MCP servers, official examples, LangChain tools, connector samples.
2. **Known attack corpus**: metadata poisoning, tool-selection attacks, implicit poisoning, trusted-description baselines.
3. **New compositional corpus**: cross-skill, update-drift, HITL laundering, persistence pivot, split exfiltration.
4. **Real-world measurement corpus**: public skill/MCP repositories and optionally anonymized enterprise catalogs.

### 8.2 Metrics

Detection metrics:

- Precision, Recall, F1, AUROC, FPR.

Attack impact metrics:

- ASR: Attack Success Rate;
- UTCR: Unauthorized Tool Call Rate;
- EDR: Exfiltration Data Rate;
- BRI: Blast Radius Index;
- PS: Persistence Score;
- SC: Stealth Coefficient.

Usability and deployment metrics:

- Task Success Rate;
- Approval Burden;
- latency;
- token and compute cost;
- evidence path completeness.

### 8.3 Baselines

| Baseline | Description |
|---|---|
| Metadata rules | keyword/schema/scope rules |
| LLM metadata judge | prompt-based review of descriptions |
| Trusted description | implementation-derived descriptions |
| SAST | CodeQL/Semgrep/Snyk-style analysis |
| MCP-aware taint | protocol-aware request/return flow analysis |
| Sandbox only | dynamic probing only |
| HITL only | approval without graph context |
| Least privilege only | permission boundary without provenance |
| Naive union | any detector alert blocks |
| SkillGuardGraph | full evidence fusion |

### 8.4 Ablation

We remove one evidence family at a time:

- no metadata evidence;
- no implementation evidence;
- no sandbox observations;
- no runtime provenance;
- no sequence constraints;
- no version drift;
- no approval integrity;
- no persistence boundary.

### 8.5 Expected results

The expected outcome is not merely higher recall. Naive union may achieve high recall but should produce excessive false positives. SkillGuardGraph should preserve high recall on compositional attacks while reducing false positives by requiring coherent evidence paths.

A strong result would show:

- compositional attack recall ≥ 85%;
- benign FPR ≤ 5–8%;
- FPR reduced by ≥ 20% relative to naive union;
- task success drop ≤ 10–15%;
- runtime policy latency ≤ 100–300ms/tool-call, excluding LLM judge.

## 9. Related Work

### 9.1 Prompt injection and tool poisoning

Early prompt-injection work showed that LLM-integrated applications are vulnerable to malicious instructions embedded in external data. Recent work shifted attention toward tool metadata, tool selection, and MCP-based ecosystems. MCPTox introduced a large-scale benchmark for MCP tool poisoning. MCP-ITP studied implicit tool poisoning, in which an uninvoked poisoned tool influences calls to legitimate high-privilege tools. ToolHijacker studied attacks on tool selection in LLM agents.

### 9.2 Trusted descriptions and metadata defenses

TRUSTDESC argues that developer-written tool descriptions should not be trusted and proposes generating implementation-faithful descriptions from code and dynamic verification. SkillGuardGraph treats trusted descriptions as one evidence source and checks consistency with permissions, runtime behavior, and version drift.

### 9.3 MCP implementation analysis

VIPER-MCP and MCP-BiFlow highlight that MCP servers require protocol-aware taint analysis and entrypoint recovery. SkillGuardGraph incorporates implementation-level results but extends them to runtime provenance and cross-tool call sequences.

### 9.4 Runtime trust calibration

MCPShield proposes a security cognition layer for adaptive trust calibration around MCP tool invocation. SkillGuardGraph differs by focusing on typed cross-layer evidence, sequence-level policies, approval integrity, version drift, and lifecycle-wide governance.

## 10. Discussion

### 10.1 Why not only least privilege?

Least privilege reduces blast radius but does not fully solve cross-skill influence or approval laundering. A low-privilege tool can still influence a high-privilege tool through the model context. Therefore, least privilege must be combined with source-aware information flow.

### 10.2 Why not only HITL?

HITL can fail when the approval dialog is generated from tainted context or hides critical execution-layer facts. SkillGuardGraph treats approval as a policy boundary that itself requires integrity checks.

### 10.3 Deployment modes

- **Registry mode**: pre-publication review, signing, reputation, drift monitoring.
- **Enterprise catalog mode**: RBAC, DLP, scope minimization, audit integration.
- **Runtime gateway mode**: call-chain monitoring, structured output enforcement, source isolation.
- **Developer CI mode**: metadata linting, permission diff, code analysis, sandbox replay.

### 10.4 Limitations

- Closed-source skills limit implementation analysis.
- Dynamic probing has incomplete coverage.
- Provenance labeling may be unavailable in some agent platforms.
- Some policies require platform integration.
- Real-world exploit reproduction must be ethically constrained.

## 11. Ethics

All attack cases should use synthetic data, fake credentials, sinkhole domains, and isolated environments. The artifact should not include operational payloads against real systems. Real vulnerabilities found in public repositories should be responsibly disclosed before publication. The benchmark should release minimized, non-operational cases when needed.

## 12. Conclusion

Malicious skills are not merely bad tools. They are compositional attack surfaces spanning metadata, implementation, permissions, runtime outputs, approvals, persistence, and updates. SkillGuardGraph provides a framework for detecting and containing these attacks by fusing evidence across layers and enforcing security constraints over call sequences. The key contribution is not a larger detector stack, but a principled way to reason about cross-layer trust gaps in agent ecosystems.

