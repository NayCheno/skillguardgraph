# Acceptance Checklist

Use this as the final gate before marking the active goal complete.

## Required Documents

- [x] `README.md` read and preserved.
- [x] `PROJECT_INDEX.md` present.
- [x] `docs/00_project_brief.md` present.
- [x] `docs/01_initial_research_plan.md` present.
- [x] `milestones/roadmap.md` present.
- [x] `milestones/weekly_execution_plan.md` present.
- [x] `checklists/acceptance_checklist.md` present.
- [x] `docs/execution_checklist.md` present.

## Research and Prototype

- [x] Threat model covers metadata, implementation, permissions, runtime provenance, approval, persistence, and version updates.
- [x] Benchmark covers seven compositional attack classes.
- [x] Evidence graph and policy engine support C1-C7.
- [x] Fusion returns risk score, decision, violated constraints, and evidence path.
- [x] Graph schema consistency validation is explicitly tested.

## Evaluation

- [x] Detector evaluation reports precision, recall, F1, FPR.
- [x] Detector evaluation reports AUROC/AUPRC and threshold sweep metrics.
- [x] Per-attack-class recall is reported.
- [x] Ablation results are generated.
- [x] Runtime red-team metrics are generated.
- [x] Latency and bootstrap CI results are available.
- [x] Local instrumented runtime harness metrics are generated.
- [x] Local isolated sandbox harness metrics are generated.
- [x] Failure-case markdown is current with latest detector outputs.
- [x] Curated third-party public-code sandbox metrics are generated.
- [x] Bounded corpus-derived third-party package sandbox metrics are generated.
- [x] Fusion vs calibrated/learned baseline significance is documented.
- [x] Held-out-template, hard-negative, mutation-robustness, and label-leakage stress checks are generated.

- [x] Public advisory cross-check output is generated.
- [x] Public remote endpoint audit output is generated.
## Ecosystem and Ethics

- [x] Synthetic ecosystem measurement exists.
- [x] Real corpus crawler entry point exists.
- [x] Responsible disclosure template exists.
- [x] Safety and ethics constraints are documented.
- [x] Real corpus measurement has been run and data-carded.
- [x] Real high-risk findings, if any, have manual triage and disclosure log entries.

## Paper

- [x] `paper/main.tex` sections are complete and internally consistent.
- [x] Paper tables/figures match regenerated results.
- [x] Related work and bibliography cover required MCP/tool-security baselines.
- [x] Limitations and ethics do not overclaim beyond synthetic evidence.

## Artifact Release

- [x] `make smoke` passes.
- [x] `make test` or `python -m pytest -q` passes.
- [x] Main reproduction scripts pass.
- [x] Generalization stress checks regenerate and are included in generated paper tables.
- [x] Local runtime harness acceptance checks pass.
- [x] Local isolated sandbox harness acceptance checks pass.
- [x] Curated third-party public-code sandbox acceptance checks pass.
- [x] Bounded corpus-derived third-party package sandbox acceptance checks pass.
- [x] Tables regenerate.
- [x] Public advisory cross-check runs against the checked-in main real corpus.
- [x] Public remote endpoint audit completes against the checked-in remote corpus slice.
- [x] Current completion audit can be generated on demand.
- [x] Docker/Conda instructions are verified or limitations are recorded (Docker build/run passed; `conda` command is unavailable on this workstation).
- [x] No secrets, credentials, real third-party payloads, or unsafe egress targets are present.
- [x] `git status --short` is clean.
- [x] Final response lists commits, remaining risks, and unfinished items.
