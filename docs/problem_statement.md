# SkillGuardGraph Problem Statement

## 1. Research Question

How can we detect compositional malicious skills that span metadata, implementation, permissions, runtime provenance, approval, persistence, and version updates in LLM agent ecosystems?

More precisely: given a third-party skill (tool, connector, action, MCP server) registered in an agent platform, how do we determine whether it exhibits cross-layer malicious behavior — behavior that is invisible when any single defensive layer (metadata scanning, static analysis, sandbox probing, runtime monitoring, human-in-the-loop approval) is examined in isolation?

## 2. Threat Boundary

### 2.1 In Scope

The threat model covers third-party skills consumed by LLM-based agent systems. We use "skill" as a unifying term encompassing:

- **MCP servers and tools** as defined by the Model Context Protocol specification (tool definitions, resource providers, prompt templates).
- **Connectors** in enterprise agent platforms (e.g., Microsoft Copilot connectors, Salesforce Agent actions).
- **Actions and tools** in open-source agent frameworks (e.g., LangChain tools, AutoGPT blocks, CrewAI tasks).
- **Plugin-style extensions** in commercial agent products (e.g., ChatGPT plugins/custom GPTs, Claude tool use).

The attacker is a skill author or publisher who can control one or more of: the manifest/schema declaration, the implementation source code, the runtime return values, the OAuth/API permission scope, the approval-facing text, the memory/config write behavior, and the version update trajectory.

### 2.2 Attack Classes

We define seven compositional attack classes, each spanning multiple lifecycle boundaries:

| ID | Attack Class | Core Mechanism |
|---|---|---|
| T1 | Capability laundering | Declares benign capability; implementation or granted permission includes high-risk operations |
| T2 | Cross-skill confused deputy | Low-trust skill outputs content that induces the agent to invoke a high-privilege internal skill |
| T3 | Delayed rug-pull | Skill passes initial review; a minor version update introduces malicious behavior or permission drift |
| T4 | Consent laundering | Approval dialog text is derived from untrusted context, causing high-risk actions to appear low-risk |
| T5 | Persistence pivot | Malicious effect is not immediate exfiltration but persistent write to memory, config, hooks, or knowledge stores that influence future sessions |
| T6 | Split exfiltration | Multiple skills cooperatively perform sensitive-read, transform, and external-write; no single skill appears malicious in isolation |
| T7 | Scope inflation | The user task requires read-only access, but the skill requests or is granted write, delete, export, or admin scope |

### 2.3 Non-Goals

The following are explicitly out of scope:

1. **Model training security.** We do not address data poisoning during LLM pre-training, fine-tuning, or RLHF. The target is the skill/tool layer, not the model weights.
2. **General jailbreak and prompt injection taxonomy.** While prompt injection is an attack vector that skills may exploit (e.g., T2), we do not aim to solve the general jailbreak problem. Our concern is skill-mediated cross-layer trust violations.
3. **Reverse-engineering closed-source platform internals.** We treat agent platform runtime internals (e.g., OpenAI's function-calling sandbox, Anthropic's tool execution environment, Microsoft's Copilot orchestration layer) as opaque when not publicly documented. Observations are limited to externally observable surfaces: tool definitions, returned outputs, approval dialogs, and side effects.
4. **Network-level or infrastructure attacks.** DDoS, TLS interception, supply-chain compromise of build tooling, and similar infrastructure threats are outside our threat model unless they directly manifest as skill-layer cross-layer trust violations.
5. **Single-layer detector engineering.** Building the best possible metadata classifier or the best possible static taint analyzer is not the goal. Individual detectors serve as evidence sources for the fusion system.

## 3. Core Thesis

**Malicious skills exploit cross-layer trust gaps invisible to single-layer defenses; effective defense requires evidence fusion across declaration, implementation, permission, runtime provenance, approval integrity, persistence, and version drift.**

### Expanded Thesis

Single-layer defenses — metadata scanners, code analyzers, sandbox probes, runtime monitors, human-in-the-loop approval — each reduce a specific risk surface. However, the most consequential malicious skill behaviors are compositional: they exploit the gap between what a skill declares and what it implements (T1), between what enters the agent context and what the agent subsequently authorizes (T2), between what was approved and what a subsequent version does (T3), between what the user sees in an approval dialog and what actually executes (T4), between what happens in one session and what persists into the next (T5), between what each individual tool does and what a coordinated chain accomplishes (T6), and between what a task requires and what permissions are granted (T7).

These cross-layer gaps are structural: they exist because each defensive layer operates on a partial view of the skill's lifecycle. A metadata scanner cannot see runtime provenance. A runtime monitor cannot see the original approval intent. A static analyzer cannot see version drift. Therefore, defense must operate on a unified evidence structure — a typed evidence graph — that connects declarations, implementations, permissions, runtime events, approval records, persistence operations, and version history, and enforces cross-layer constraints over this graph.

## 4. Research Questions

| RQ | Question | Corresponding Experiment |
|---|---|---|
| RQ1 | Where do per-layer detectors fail against compositional malicious skills? | Per-layer detector evaluation: measure precision, recall, F1, and FPR of each detector (metadata, static, sandbox, runtime) individually against the benchmark, isolating attack classes that span multiple layers. |
| RQ2 | Can a typed cross-layer evidence graph identify inconsistencies among metadata declarations, implementation behavior, granted permissions, and runtime provenance? | Graph constraint evaluation: construct evidence graphs from benchmark samples, measure constraint violation detection rate, evidence path completeness, and false constraint triggers on benign samples. |
| RQ3 | Does evidence fusion with cross-layer constraints significantly outperform naive union and voting ensemble baselines? | Ablation study comparing: (a) metadata-only, (b) static-only, (c) sandbox-only, (d) runtime-only, (e) naive union (any-detector-alarm → block), (f) weighted voting, (g) LLM judge, (h) evidence graph fusion. Report recall on compositional attacks, FPR on benign corpus, and statistical significance. |
| RQ4 | Can source-aware, permission-aware runtime constraints reduce attack success rate, unauthorized tool calls, data exfiltration, blast radius, persistence, and stealth without unacceptable usability degradation? | Runtime red-team evaluation: deploy the full system with policy enforcement (allow, degrade, sandbox-only, HITL, deny, quarantine, rollback) against adversarial task suites; measure ASR, UTCR, EDR, BRI, PS, SC, task success rate, approval burden, and false block rate. |
| RQ5 | Are cross-layer trust gaps and permission drift prevalent in real-world MCP/tool/agent ecosystems? | Ecosystem measurement: crawl and analyze ≥1,000 (target ≥5,000) open-source MCP servers, tools, and connectors; run metadata and static analyzers; triage high-risk findings; report prevalence of scope inflation, description-code mismatch, open-world network overreach, and undocumented persistence. |

## 5. Target Venue

This work targets a CCF-A systems security conference: ACM CCS, IEEE Symposium on Security and Privacy (S&P), USENIX Security, or NDSS.

The contribution profile matches the expected shape for these venues:

1. **New threat model.** A taxonomy of compositional malicious skill attacks spanning seven lifecycle boundaries, grounded in real ecosystem observations.
2. **New system.** A typed evidence graph that fuses metadata, implementation, runtime, permission, approval, persistence, and version evidence, with a formal constraint library and policy enforcement engine.
3. **New benchmark.** A compositional malicious skill benchmark with ≥3,000 malicious variants across ≥7 attack classes, with labeled evidence paths.
4. **Ecosystem measurement.** Large-scale measurement of real-world MCP/tool/agent ecosystems revealing cross-layer trust gap prevalence.
5. **Rigorous evaluation.** Detection, ablation, defense impact, cost, and usability experiments with statistical confidence intervals and qualitative failure analysis.

## 6. Differentiation from Existing Work

### 6.1 MCPTox

**MCPTox** provides a benchmark for MCP metadata tool poisoning, focusing primarily on the registration stage: poisoned descriptions, misleading tool names, and injected instructions in tool metadata.

**SkillGuardGraph differs** by extending the attack surface beyond registration-stage metadata to encompass implementation backdoors (T1), cross-tool chain attacks (T6), approval text manipulation (T4), persistence pivots (T5), version drift (T3), and scope inflation (T7). Where MCPTox evaluates a metadata classifier, SkillGuardGraph evaluates a cross-layer fusion system and demonstrates that metadata-only detection is insufficient for compositional attacks.

### 6.2 TRUSTDESC

**TRUSTDESC** generates trusted descriptions from tool implementation code, ensuring that the displayed description faithfully represents what the code actually does. This addresses description-code mismatch at the metadata layer.

**SkillGuardGraph differs** by treating trusted description generation as one evidence source within a broader graph, not as a standalone defense. TRUSTDESC requires analyzable source code and does not address runtime behavior, permission scope, approval integrity, persistence, version drift, or cross-tool chains. In our framework, a skill can have a perfectly faithful description and still exhibit malicious cross-layer behavior (e.g., T2, T5, T6).

### 6.3 VIPER-MCP

**VIPER-MCP** applies taint-style vulnerability auditing to MCP servers, identifying data flows from user-controlled inputs to sensitive sinks within a single server's implementation.

**SkillGuardGraph differs** by operating at the agent execution level rather than the server implementation level. VIPER-MCP's taint analysis is a valuable evidence source for our implementation analyzer, but it does not model the agent's tool-call chain, the provenance of data flowing across multiple skills, the approval layer, or the temporal dimension of version updates. We integrate taint evidence as one layer in a cross-layer graph.

### 6.4 MCP-BiFlow

**MCP-BiFlow** analyzes bidirectional data-flow risks in the MCP ecosystem, identifying cases where data flows from untrusted sources into the agent context and then back out through privileged tool calls.

**SkillGuardGraph differs** by adding governance-layer constraints that flow analysis alone cannot capture: approval integrity (whether the user's consent is based on trustworthy information), version drift (whether behavior changed after approval), persistence boundaries (whether the attack's effect survives across sessions), and least-privilege scope alignment (whether granted permissions exceed task requirements). Flow analysis provides the provenance edges in our graph; governance constraints provide the policy layer.

### 6.5 MCPShield

**MCPShield** introduces adaptive trust calibration for MCP agents, using metadata-guided probing and runtime trust scores to govern tool invocation.

**SkillGuardGraph differs** in four ways. First, we formalize cross-layer constraints in a typed evidence graph rather than relying on calibrated trust scores alone, producing explainable evidence paths rather than scalar risk values. Second, we cover the version drift dimension (T3), which invocation-time trust calibration cannot detect because the drift occurs between invocations. Third, we cover the approval integrity dimension (T4), which requires modeling the relationship between untrusted context and approval dialog content. Fourth, our evaluation includes a systematic ablation against naive union to demonstrate that graph fusion provides value beyond simple detector stacking — a critical validity check that distinguishes a systems contribution from an engineering integration.

### 6.6 Additional Differentiation

Beyond the five named systems, SkillGuardGraph is also distinct from:

- **LLM-as-judge baselines** that use a language model to evaluate tool safety. Our constraint library is deterministic and auditable; LLM judges serve as a baseline, not the core mechanism.
- **Static application security testing (SAST)** tools applied to skill code. SAST identifies implementation-level vulnerabilities but lacks the agent execution context, permission model, and cross-skill chain awareness needed for compositional attack detection.
- **Agent governance frameworks** (e.g., NIST AI RMF, OWASP LLM Top 10) that provide high-level risk categories but do not operationalize detection into a concrete system with measurable constraints, evidence paths, and policy actions.

## 7. Scope of Contribution

The expected paper contributions are:

1. **Threat contribution:** A lifecycle-spanning taxonomy of compositional malicious skill attacks, with formal definitions mapping each attack class to lifecycle boundaries, attacker capabilities, observable evidence, and defensive invariants.
2. **System contribution:** SkillGuardGraph — a typed evidence graph system with a constraint library (C1–C7), a fusion scorer, and a policy enforcement engine supporting allow, degrade, sandbox-only, HITL, deny, quarantine, and rollback decisions.
3. **Benchmark contribution:** A compositional malicious skill benchmark with labeled evidence paths, covering seven attack classes across metadata, implementation, runtime, permission, approval, persistence, and version dimensions.
4. **Measurement contribution:** Large-scale measurement of real-world MCP/tool/agent ecosystems, reporting prevalence of cross-layer trust gaps.
5. **Evaluation contribution:** Detection, ablation, defense impact, cost, and usability experiments demonstrating that evidence graph fusion significantly outperforms single-layer detectors and naive union baselines.
