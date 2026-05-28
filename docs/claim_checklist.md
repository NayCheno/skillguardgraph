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
| The artifact includes an archive-backed third-party public-code sandbox fixture suite | `experiments/results/main/third_party_sandbox.json`, `experiments/src/skillguardgraph/third_party_sandbox.py`, `experiments/scripts/run_third_party_sandbox.py` | Supported |
| The artifact includes a bounded corpus-derived third-party package sandbox over source-available PyPI cases | `experiments/results/main/corpus_package_sandbox.json`, `experiments/src/skillguardgraph/corpus_package_sandbox.py`, `experiments/scripts/run_corpus_package_sandbox.py` | Supported |
| Passive multi-source public measurement is implemented and documented, including supplementary 2k/3k/5k/10k batches | `experiments/results/ecosystem/real_ecosystem_results.json`, `experiments/results/ecosystem/real_ecosystem_large_results.json`, `experiments/results/ecosystem/real_ecosystem_xl_results.json`, `experiments/results/ecosystem/real_ecosystem_5k_results.json`, `experiments/results/ecosystem/real_ecosystem_10k_results.json`, `docs/ecosystem_measurement.md` | Supported |
| The artifact includes a public-advisory cross-check over the main real public corpus | `experiments/results/ecosystem/public_advisory_audit.json`, `experiments/scripts/run_public_advisory_audit.py` | Supported |

## Claims that must remain explicitly limited

| Claim area | Current evidence | Required wording |
|---|---|---|
| Real-world exploit confirmation | Passive repo/package/space metadata + bounded source, plus advisory cross-checking for known public MCP cases | Do not claim newly confirmed vulnerabilities or exploit paths from this artifact alone |
| Dynamic sandboxing | Local toy sandbox harness plus archive-backed curated third-party public-code fixtures and bounded source-available PyPI package cases only; no arbitrary third-party skill execution | Do not claim production sandbox coverage |
| Production runtime deployment | Local toy runtime harness only | Do not claim deployed agent-runtime efficacy |
| Ecosystem prevalence | 1k main batch including public hosted-registry and official-registry slices + 2k/3k/5k/10k supplementary catalog measurements | Frame as passive catalog evidence, not exhaustive market coverage |
| PyPI coverage | Simple-index discovery only | Do not claim comprehensive PyPI measurement |

## Open claim gaps before stronger submission positioning

| Gap | Missing evidence |
|---|---|
| Confirmed real cases | Responsible disclosure-backed validations |
| Third-party dynamic sandbox beyond bounded public-package cases | Isolated execution of non-toy external skills at arbitrary package / marketplace breadth |
| Production-like runtime data | Real agent integration and overhead measurements |
| Private/enterprise marketplace coverage | Private enterprise or other non-public tool catalogs |

## Pre-submission checks

Before upgrading any claim in `paper/main.tex`, verify:

1. the exact number appears in a checked-in result artifact;
2. the result artifact can be regenerated from a documented command;
3. the paper wording matches the evidence boundary in `docs/00_project_brief.md`; and
4. any real-world finding has matching triage/disclosure records under `docs/` and `experiments/results/ecosystem/`.
