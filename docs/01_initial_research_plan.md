# Initial Research Plan

This plan condenses `docs/roadmap.md`, `docs/plan.md`, and the external review into an executable research sequence.

## Phase 1 — Baseline Artifact Closure

Goal: make the synthetic benchmark artifact internally consistent and reviewable.

Deliverables:

- benchmark generation and label validation;
- metadata/static/sandbox/runtime baselines;
- graph fusion and policy constraints C1-C7;
- detector evaluation with precision, recall, F1, FPR, AUROC, AUPRC, and threshold sweeps;
- ablation, runtime red-team, latency, bootstrap CI, failure analysis, held-out/hard-negative robustness checks, label-leakage audit, and generated paper tables;
- artifact guide, expected outputs, ethics note, Dockerfile, and environment file.

Acceptance:

- `python -m pytest -q` passes in `experiments/`;
- detector results show fusion outperforming naive union and weighted voting on false-positive control;
- high-risk decisions include evidence paths;
- held-out-template, hard-negative, mutation, and label-blinding checks meet their recorded acceptance gates;
- tables regenerate from JSON results.

## Phase 2 — Paper Consistency Pass

Goal: align the paper with the actual evidence level.

Deliverables:

- abstract and introduction state the synthetic benchmark/prototype boundary clearly;
- method sections describe typed graph construction, constraints, fusion scoring, and runtime enforcement without overclaiming production deployment;
- evaluation section matches current result JSON and generated tables;
- limitations explicitly separate synthetic validity from real ecosystem claims;
- ethics section matches `docs/ethics_protocol.md` and `artifact/SECURITY_ETHICS.md`.

Acceptance:

- every numeric claim in `paper/main.tex` traces to `experiments/results/`;
- every RQ has a table, figure, or appendix result;
- no real-world deployment claim is made without real measurement evidence.

## Phase 3 — Real Ecosystem Measurement

Goal: add external validity without violating safety constraints.

Deliverables:

- real corpus collection script and data card;
- source, date, version, license, deduplication, and filtering metadata for each sample;
- passive metadata/source analysis only by default;
- manual triage of high-risk findings;
- responsible disclosure log entries for confirmed real vulnerabilities.

Acceptance:

- minimum 1,000 real public samples, strong target 5,000+;
- at least three ecosystem risk patterns reported;
- no destructive calls or real credential use;
- suspicious vs confirmed findings separated.

## Phase 4 — Submission Freeze

Goal: produce a reproducible paper and artifact package.

Deliverables:

- clean checkout reproduction commands;
- regenerated result JSON, tables, and figures;
- final `paper/main.tex` and appendix;
- final artifact inventory and expected output hashes/checks;
- claim-to-evidence audit.

Acceptance:

- all final checks in `checklists/acceptance_checklist.md` pass;
- `git status --short` is clean after commits;
- commit history is split by coherent reviewable goals.
