# Roadmap Mirror

The canonical roadmap is `docs/roadmap.md`. This mirror exists because the project takeover instructions reference `milestones/roadmap.md`.

## Milestones

| Milestone | Status | Canonical source |
|---|---|---|
| M0 — Paper story freeze | Mostly complete | `docs/roadmap.md`, `docs/problem_statement.md` |
| M1 — Taxonomy and benchmark protocol | Mostly complete | `docs/attack_classes.md`, `docs/benchmark_card.md` |
| M2 — Evidence Graph v0 | Mostly complete | `docs/evidence_graph_spec.md`, `experiments/src/skillguardgraph/evidence_graph.py` |
| M3 — Analyzer and sandbox v0 | Mostly complete for safe synthetic evaluation | `experiments/src/skillguardgraph/`, `experiments/tests/` |
| M4 — Fusion engine v1 | Complete for synthetic benchmark; real-world calibration remains open | `experiments/src/skillguardgraph/fusion.py`, `experiments/results/main/detector_eval.json` |
| M5 — Main evaluation | Mostly complete; statistical comparison can be strengthened | `experiments/scripts/`, `experiments/results/main/` |
| M6 — Real ecosystem measurement | Partially complete; synthetic measurement exists, real corpus remains open | `experiments/scripts/crawl_real_ecosystem.py`, `docs/ecosystem_measurement.md` |
| M7 — Paper and artifact freeze | In progress | `paper/`, `artifact/`, `docs/execution_checklist.md` |

## Current Priority

1. Keep synthetic artifact internally consistent.
2. Align paper claims and tables with regenerated results.
3. Complete real corpus measurement and manual triage for CCF-A-strength claims.
4. Freeze artifact only after full checks pass from a clean checkout.
