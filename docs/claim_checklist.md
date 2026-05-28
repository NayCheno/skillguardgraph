# Claim-to-Evidence Checklist

This file is the paper-facing audit map for SkillGuardGraph's current claim boundary.

## Strong claims supported now

| Claim | Evidence | Status |
|---|---|---|
| Fusion outperforms naive union on the synthetic benchmark | `experiments/results/main/detector_eval.json`, `experiments/results/main/significance_tests.json` | Supported |
| Fusion provides evidence paths for high-risk synthetic detections | `experiments/results/main/failure_analysis.json`, `experiments/src/skillguardgraph/fusion.py`, `experiments/tests/test_evidence_graph.py` | Supported |
| Runtime provenance is the dominant signal in the current artifact | `experiments/results/main/ablation.json` | Supported |
| The artifact includes held-out, hard-negative, mutation, and label-blinding stress checks | `experiments/results/main/generalization_eval.json`, `experiments/scripts/run_generalization_eval.py` | Supported |
| The artifact includes a local instrumented runtime harness | `experiments/results/main/runtime_harness.json`, `experiments/src/skillguardgraph/runtime_harness.py` | Supported |
| The artifact includes a local isolated sandbox harness | `experiments/results/main/sandbox_harness.json`, `experiments/src/skillguardgraph/sandbox_harness.py` | Supported |
| Passive multi-source public measurement is implemented and documented | `experiments/results/ecosystem/real_ecosystem_results.json`, `experiments/results/ecosystem/real_ecosystem_data_card.json`, `docs/ecosystem_measurement.md` | Supported |

## Claims that must remain explicitly limited

| Claim area | Current evidence | Required wording |
|---|---|---|
| Real-world exploit confirmation | Passive repo/package/space metadata + bounded source only | Do not claim confirmed vulnerabilities or exploit paths |
| Dynamic sandboxing | Local toy sandbox harness only; no third-party skill execution | Do not claim production sandbox coverage |
| Production runtime deployment | Local toy runtime harness only | Do not claim deployed agent-runtime efficacy |
| Ecosystem prevalence | 1k main batch + 2k/3k supplementary catalog measurements | Frame as passive catalog evidence, not exhaustive market coverage |
| PyPI coverage | Curated seeds + simple-index discovery only | Do not claim comprehensive PyPI measurement |

## Open claim gaps before stronger submission positioning

| Gap | Missing evidence |
|---|---|
| 5k+ / 10k+ real public artifacts | Larger checked-in corpus with regenerated stats |
| Confirmed real cases | Responsible disclosure-backed validations |
| Third-party dynamic sandbox | Isolated execution of non-toy external skills |
| Production-like runtime data | Real agent integration and overhead measurements |
| Broader marketplace coverage | Hosted enterprise or other external tool catalogs |

## Pre-submission checks

Before upgrading any claim in `paper/main.tex`, verify:

1. the exact number appears in a checked-in result artifact;
2. the result artifact can be regenerated from a documented command;
3. the paper wording matches the evidence boundary in `docs/00_project_brief.md`; and
4. any real-world finding has matching triage/disclosure records under `docs/` and `experiments/results/ecosystem/`.
