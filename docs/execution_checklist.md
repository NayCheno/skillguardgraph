# SkillGuardGraph Execution Checklist

This checklist is extracted from `README.md`, `docs/roadmap.md`, `docs/plan.md`, `docs/artifact_checklist.md`, `docs/metrics.md`, `docs/ecosystem_measurement.md`, `artifact/README.md`, `artifact/EXPECTED_OUTPUTS.md`, `paper/`, and the external review dated 2026-05-27.

## Intake and Project Structure

- [x] Preserve top-level `docs/`, `paper/`, `experiments/`, and `artifact/` structure.
- [x] Add stable entry points: `PROJECT_INDEX.md`, `docs/00_project_brief.md`, `docs/01_initial_research_plan.md`.
- [x] Add milestone and acceptance mirrors under `milestones/` and `checklists/`.
- [x] Record missing original inputs: the checkout did not contain `PROJECT_INDEX.md`, `docs/00_project_brief.md`, `docs/01_initial_research_plan.md`, `milestones/roadmap.md`, `milestones/weekly_execution_plan.md`, `checklists/acceptance_checklist.md`, or `skills/git-history-distiller/` before this pass.

## Prototype and Evidence Graph

- [x] Maintain typed evidence graph nodes/edges for metadata, permissions, static evidence, runtime events, approval, persistence, and version updates.
- [x] Keep constraints C1-C7 covered by tests and documentation.
- [x] Ensure high-risk fusion decisions return evidence paths.
- [x] Normalize runtime sink traces consistently (`sink_type`, `external`, `is_external`) so external dataflow evidence is not dropped.
- [x] Treat benign local persistence as weaker than untrusted persistence; C6 remains the strong persistence signal.
- [x] Add schema-level graph consistency validation for node/edge references and evidence path serialization.
- [x] Add conservative Python AST source--sink summaries for aliased imports and variable-to-sink flows.

## Benchmark and Evaluation

- [x] Maintain benchmark v0 with 1,000 benign and 3,010 malicious synthetic samples across seven attack classes.
- [x] Keep label validation and fixed seed generation.
- [x] Report precision, recall, F1, and FPR for metadata/static/sandbox/runtime, naive union, weighted voting, LLM judge, and fusion.
- [x] Report AUROC, AUPRC, threshold sweep, and FPR@Recall for detector scores.
- [x] Report per-attack-class recall.
- [x] Regenerate paper tables from result JSON.
- [x] Run failure analysis and evidence path attribution.
- [x] Update failure-case narrative after detector calibration so markdown does not describe stale failures.
- [x] Add paired statistical comparison for fusion vs calibrated voting/learned baselines beyond current bootstrap summaries.
- [x] Add held-out-template, hard-negative, mutation-robustness, and label-leakage stress checks.

## Runtime, Latency, and Usability

- [x] Run synthetic runtime red-team evaluation.
- [x] Report ASR, UTCR, EDR, PS, SC, task success, false block rate, and approval burden.
- [x] Add a local instrumented toy runtime harness with at least 50 benign and 50 attack tasks, provenance capture, acceptance gates, and no third-party code execution.
- [x] Report latency p50/p95/p99 for core pipeline components.
- [x] Add a local isolated sandbox harness with blocked network/shell helpers, toy cases, and acceptance checks.
- [x] Deepen sandbox/runtime realism only within safety constraints: fake credentials, sinkhole DNS, no real egress.
- [x] Add a curated third-party public-code sandbox fixture suite executed under the same isolation boundary.
- [x] Add a bounded corpus-derived package sandbox for source-available third-party PyPI cases.

## Ecosystem Measurement and Disclosure

- [x] Provide synthetic ecosystem measurement report and triage outputs.
- [x] Provide responsible disclosure template and artifact ethics guidance.
- [x] Include `experiments/scripts/crawl_real_ecosystem.py` as the real corpus collection entry point.
- [x] Run a real public corpus measurement with recorded source/date/version/license/dedup metadata.
- [x] Manually triage high-risk real findings.
- [x] Keep suspicious findings separate from confirmed vulnerabilities.
- [x] Add a bounded public remote endpoint audit over official-registry deployments.
- [x] Cross-check the main real public corpus against known official MCP advisories.
- [x] Use disclosure log entries before publishing real vulnerable package identities.

## Paper

- [x] Ensure `paper/main.tex` has complete abstract, introduction, threat model, design, formal model, implementation, evaluation, related work, limitations, ethics, and conclusion sections.
- [x] Ensure all paper numbers match `experiments/results/` after regeneration.
- [x] Update paper tables to include AUROC/AUPRC and threshold-sweep takeaways.
- [x] Align paper claims with the safe synthetic/prototype boundary.
- [x] Add paper discussion of generalization stress checks and remaining synthetic-validity boundary.
- [x] Ensure figures referenced in LaTeX exist and render from source diagrams or checked-in PDFs.
- [x] Ensure bibliography entries cover MCPTox, MCPShield, TRUSTDESC, VIPER-MCP, MCP-BiFlow, tool poisoning, prompt injection, and supply-chain security.

## Artifact and Release Polish

- [x] Provide `Dockerfile`, `environment.yml`, `experiments/Makefile`, `artifact/README.md`, `artifact/EXPECTED_OUTPUTS.md`, and `artifact/SECURITY_ETHICS.md`.
- [x] Provide CI workflow for tests and reproduction pipeline.
- [x] Refresh artifact expected outputs after final result regeneration.
- [x] Include `run_generalization_eval.py` in `eval-main` and generated paper tables.
- [x] Include `run_runtime_harness.py` in `eval-main` and generated paper tables.
- [x] Include `run_sandbox_harness.py` in `eval-main` and generated paper tables.
- [x] Include `run_third_party_sandbox.py` in `eval-main`.
- [x] Include `run_corpus_package_sandbox.py` in `eval-main`.
- [x] Provide a scriptable completion audit for the current checkout.
- [x] Include `run_public_advisory_audit.py` in `eval-main`.
- [x] Include `run_remote_endpoint_audit.py` in `eval-main`.
- [x] Run smoke, tests, main evaluation, ablation, runtime red-team, latency, bootstrap, failure analysis, tables, and available Docker/Conda checks before final delivery.
- [x] Confirm no real secrets, credentials, or operational payloads are included.
- [x] Confirm `git status --short` is clean and list commits.
