# SkillGuardGraph Project Index

This index is the stable entry point for reviewers and maintainers.

## Required Reading Order

1. `docs/00_project_brief.md` — current scope, claim boundary, and status.
2. `docs/01_initial_research_plan.md` — research plan distilled from roadmap and execution plan.
3. `docs/execution_checklist.md` — actionable checklist extracted from roadmap, docs, artifact, evaluation, and paper goals.
4. `docs/claim_boundary.md` — precise claim boundary and evidence classification.
5. `docs/claim_checklist.md`, `docs/mock_review.md`, `docs/rebuttal_bank.md`, and `docs/review_response_strategy.md` — submission- and review-facing claim audit material.
6. `checklists/acceptance_checklist.md` — final acceptance gate.
7. `artifact/README.md` and `artifact/EXPECTED_OUTPUTS.md` — reproduction and expected outputs.
8. `paper/main.tex` and `paper/appendix.tex` — paper draft.

## Repository Map

| Area | Paths | Purpose |
|---|---|---|
| Research framing | `docs/problem_statement.md`, `docs/optimized_idea_zh.md`, `docs/roadmap.md`, `docs/plan.md` | Research question, claims, roadmap, and execution plan. |
| Threat model | `docs/threat_taxonomy_zh.md`, `docs/attack_classes.md`, `paper/background.tex` | Lifecycle threat model and seven compositional attack classes. |
| Evidence graph and policy | `docs/evidence_graph_spec.md`, `docs/policy_spec.md`, `experiments/src/skillguardgraph/` | Typed evidence graph, constraints C1-C7, analyzers, fusion, and policy engine. |
| Evaluation | `docs/metrics.md`, `docs/benchmark_card.md`, `experiments/scripts/`, `experiments/results/` | Metrics, benchmark card, experiment runners, generated results. |
| Ecosystem and ethics | `docs/ecosystem_measurement.md`, `docs/disclosure_log_template.md`, `docs/ethics_protocol.md`, `artifact/SECURITY_ETHICS.md` | Measurement scope, disclosure process, safety constraints. |
| Review and submission | `docs/claim_checklist.md`, `docs/mock_review.md`, `docs/rebuttal_bank.md`, `docs/review_response_strategy.md`, `docs/claim_boundary.md` | Claim-to-evidence audit, claim boundary, mock review notes, rebuttal material, and reviewer-handling strategy. |
| Paper | `paper/main.tex`, `paper/appendix.tex`, `paper/references.bib`, `paper/figures/` | Submission draft and supporting material. |
| Artifact | `artifact/`, `Dockerfile`, `environment.yml`, `experiments/Makefile` | Reviewer package, reproducibility commands, environment definitions. |
| Benchmark | `docs/benchmark_v1_spec.md`, `experiments/data/benchmark_v0/`, `experiments/scripts/build_benchmark.py`, `experiments/scripts/build_benchmark_v1.py` | Benchmark v0 (frozen sanity check) and v1 (label-blind primary evaluation). |
| Result index | `experiments/results/result_index.json` | Tags every result with evidence source, generation command, and claim boundary. |
## Current Claim Boundary

SkillGuardGraph is a reproducible research prototype and synthetic benchmark for studying cross-layer malicious skill behavior. It supports claims about typed evidence fusion, graph constraints, safe trace-replay evaluation on synthetic benchmark data, and passive public-repository measurement with explicit claim boundaries. Real-world deployment claims remain out of scope until runtime-confirmed and disclosure-backed case studies are complete.
