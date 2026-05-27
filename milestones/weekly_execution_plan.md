# Weekly Execution Plan

This file mirrors the phase plan in `docs/plan.md` as concrete checkpoints.

## W1 — Intake and Scope Freeze

- Read required project documents and external review.
- Create `PROJECT_INDEX.md`, project brief, initial research plan, and execution checklist.
- Confirm claim boundary: synthetic artifact/prototype unless real measurement evidence is added.

## W2-W3 — Documentation and Taxonomy Closure

- Audit threat taxonomy, attack classes, metrics, ethics, and policy docs for consistency.
- Ensure seven attack classes map to C1-C7 constraints and paper threat model.
- Update acceptance checklist as items become verified.

## W4-W7 — Benchmark and Evaluation Closure

- Validate benchmark generation and labels.
- Regenerate detector evaluation, ablation, runtime red-team, latency, bootstrap, failure analysis, and tables.
- Add or refresh AUROC/AUPRC, threshold sweep, and FPR@Recall outputs.

## W8-W10 — Paper Consistency Pass

- Update `paper/main.tex` and appendix sections.
- Ensure every numeric paper claim traces to `experiments/results/`.
- Refresh figures/tables and citation coverage.

## W11-W14 — Ecosystem Measurement

- Run real corpus collection where network and safety constraints permit.
- Record source/date/version/license/dedup metadata.
- Triage high-risk findings and populate disclosure logs for confirmed vulnerabilities.

## W15 — Artifact Freeze

- Run all available checks.
- Refresh `artifact/EXPECTED_OUTPUTS.md`.
- Confirm no secrets or operational payloads.
- Commit final release polish and verify clean status.
