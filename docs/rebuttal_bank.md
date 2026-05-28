# Rebuttal Bank

This file collects concise responses to likely reviewer objections.

## 1. "This is just a detector pipeline."

Response:
- The core contribution is not detector stacking but typed evidence fusion over cross-layer constraints C1-C7.
- The artifact exposes explicit evidence-path output and constraint-level findings rather than only a score.
- The ablation shows sequence/runtime constraints carry distinct signal beyond metadata-only checks.

Evidence:
- `docs/evidence_graph_spec.md`
- `experiments/src/skillguardgraph/evidence_graph.py`
- `experiments/src/skillguardgraph/policy_engine.py`
- `experiments/results/main/ablation.json`

## 2. "The synthetic benchmark is too easy."

Response:
- We agree that the synthetic benchmark alone is insufficient for broad deployment claims.
- The artifact therefore includes held-out-template, hard-negative, mutation, and label-blinding stress checks.
- The paper explicitly frames the synthetic results as artifact-consistency evidence, not proof of production generalization.

Evidence:
- `experiments/results/main/generalization_eval.json`
- `paper/main.tex`
- `docs/01_initial_research_plan.md`

## 3. "Static and sandbox layers do not matter because ablations are flat."

Response:
- In the current artifact, runtime provenance dominates aggregate synthetic performance.
- Static and sandbox layers are retained as auxiliary evidence sources and deployment hooks, not overclaimed as the main driver of current benchmark recall.
- The paper now states this directly in the evaluation and limitations sections.

Evidence:
- `experiments/results/main/ablation.json`
- `paper/main.tex`

## 4. "Your real-world evidence is weak."

Response:
- Correct; the current real-world contribution is a passive multi-source catalog measurement, not confirmed exploit validation.
- The paper, brief, and claim checklist explicitly keep deployment-grade claims out of scope.
- We do not claim confirmed vulnerabilities because the current triage produced suspicious mismatches only.

Evidence:
- `docs/00_project_brief.md`
- `docs/claim_checklist.md`
- `experiments/results/ecosystem/real_high_risk_triage.json`
- `docs/disclosure_log.md`

## 5. "The runtime and sandbox experiments are not real deployments."

Response:
- Correct; they are local toy harnesses that produce execution-time provenance under strict safety controls.
- They are included to strengthen the artifact's runtime/sandbox story while preserving the non-execution boundary for third-party code.
- The paper names them as local harnesses and explicitly excludes production deployment claims.

Evidence:
- `experiments/src/skillguardgraph/runtime_harness.py`
- `experiments/src/skillguardgraph/sandbox_harness.py`
- `experiments/results/main/runtime_harness.json`
- `experiments/results/main/sandbox_harness.json`
- `paper/main.tex`

## 6. "Why should we trust the larger corpus numbers if source coverage is low?"

Response:
- We do not present the large batches as code-complete vulnerability audits.
- The 2k and 3k batches are supplementary scale-out catalog measurements intended to show breadth, not stronger exploit evidence.
- The artifact docs and measurement report state this limitation directly.

Evidence:
- `docs/ecosystem_measurement.md`
- `artifact/EXPECTED_OUTPUTS.md`
- `artifact/README.md`
