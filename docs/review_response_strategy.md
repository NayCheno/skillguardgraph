# Review Response Strategy

This document turns the current evidence state into a reviewer-facing response plan.

## 1. Submission positioning

Recommended positioning today:

> SkillGuardGraph is a reproducible benchmark-and-artifact paper on cross-layer malicious skill detection, with typed evidence fusion, local runtime/sandbox harnesses, and passive multi-source ecosystem measurement.

Do **not** position it as:

- a production-ready deployed defense;
- a paper with confirmed real-world exploit validation; or
- a comprehensive ecosystem census.

## 2. Primary reviewer risks

| Reviewer concern | Why they may raise it | Response strategy | Evidence |
|---|---|---|---|
| "This is just a detector pipeline." | Multiple analyzers are visible in the implementation. | Center the response on typed evidence fusion, C1-C7, and explicit evidence-path output. | `docs/evidence_graph_spec.md`, `experiments/src/skillguardgraph/evidence_graph.py`, `experiments/src/skillguardgraph/policy_engine.py` |
| "Synthetic results are too perfect." | Fusion scores are 1.000 / 1.000 / 1.000 / 0.000 on the benchmark. | Point to held-out, hard-negative, mutation, and label-blinding stress checks; explicitly concede that they are still synthetic. | `experiments/results/main/generalization_eval.json`, `paper/main.tex` |
| "Real-world evidence is weak." | No confirmed vulnerabilities, low source coverage, passive measurement only. | Agree with the limitation; frame the multi-source public-corpus work as passive catalog measurement and governance evidence. | `docs/ecosystem_measurement.md`, `docs/claim_checklist.md`, `experiments/results/ecosystem/real_high_risk_triage.json` |
| "Your runtime/sandbox story is toy-only." | Harnesses are local and fixture-based. | Emphasize that they are deliberately scoped artifact mechanisms, not deployed runtime proof; highlight third-party public-code fixture execution as an intermediate step. | `experiments/results/main/runtime_harness.json`, `experiments/results/main/sandbox_harness.json`, `experiments/results/main/third_party_sandbox.json` |
| "Scale does not imply validation." | 5k/10k batches are mostly metadata-only. | Agree and separate scale-out catalog evidence from source-backed or exploit-backed claims. | `experiments/results/ecosystem/real_ecosystem_5k_results.json`, `experiments/results/ecosystem/real_ecosystem_10k_results.json`, `docs/ecosystem_measurement.md` |

## 3. What to emphasize in the paper and rebuttal

1. The paper's core value is the **cross-layer evidence model**, not any individual detector.
2. The artifact is unusually strong in **reproducibility** and **claim hygiene**.
3. Runtime and sandbox experiments are useful because they provide **execution-time provenance under safe controls**, even when they are not deployed production monitors.
4. The ecosystem results are best framed as **passive governance and prevalence evidence**, not exploit confirmation.

## 4. What to concede immediately

Concede these points quickly rather than resisting them:

- no confirmed real vulnerabilities;
- no arbitrary third-party sandbox execution beyond curated public-code fixtures;
- no authenticated or task-level production agent-runtime deployment;
- limited source-available coverage in the real batches;
- incomplete marketplace/private-catalog coverage.

## 5. Rebuttal structure

If rebuttal space is limited, respond in this order:

1. Re-state the claim boundary.
2. Clarify the main contribution (typed evidence fusion and constraints).
3. Point to the strongest artifact evidence (significance tests, generalization stress checks, explainability outputs).
4. Acknowledge real-world limitations without weakening the supported synthetic/artifact contribution.
5. Point to the multi-source public-corpus batches as breadth evidence only.

## 6. No-go triggers for claim inflation

Do not upgrade the paper's wording unless all corresponding evidence exists in the repo:

- confirmed or disclosure-backed real cases;
- third-party dynamic sandbox execution beyond bounded source-available public-package cases;
- authenticated or task-level production-like runtime integration;
- private enterprise catalog coverage beyond today's public-source/public-registry slice;
- stronger source-backed real-world validation.

If a reviewer asks for any of those directly, respond that they are future work and out of scope for the current artifact claim boundary.
