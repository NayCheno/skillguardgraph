# SkillGuardGraph Project Index

This index is the stable entry point for reviewers and maintainers.

## Required Reading Order

1. `docs/00_project_brief.md` — current scope, claim boundary, and status.
2. `docs/01_initial_research_plan.md` — research plan distilled from roadmap and execution plan.
3. `docs/execution_checklist.md` — actionable checklist extracted from roadmap, docs, artifact, evaluation, and paper goals.
4. `docs/roadmap.md` — full milestone roadmap.
5. `docs/plan.md` — detailed phase-by-phase execution plan.
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
| Paper | `paper/main.tex`, `paper/appendix.tex`, `paper/references.bib`, `paper/figures/` | Submission draft and supporting material. |
| Artifact | `artifact/`, `Dockerfile`, `environment.yml`, `experiments/Makefile` | Reviewer package, reproducibility commands, environment definitions. |

## Current Claim Boundary

SkillGuardGraph is a reproducible research prototype and synthetic benchmark for studying cross-layer malicious skill behavior. It supports claims about typed evidence fusion, graph constraints, and safe trace-replay evaluation on synthetic benchmark data. Real-world deployment claims remain out of scope until real corpus measurement and disclosure-backed case studies are complete.
