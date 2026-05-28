# SkillGuardGraph Project Brief

## Thesis

Malicious skills in LLM agent ecosystems exploit cross-layer trust gaps across metadata, implementation, permissions, runtime provenance, approval, persistence, and version updates. A useful defense must fuse typed evidence across these layers and return auditable evidence paths, not just aggregate detector votes.

## Scope

SkillGuardGraph currently targets a safe research setting:

- synthetic skill manifests and runtime traces;
- fake credentials, synthetic data, and sinkhole-only destinations;
- static and simulated dynamic evidence collection;
- deterministic policy constraints C1-C7 over a typed evidence graph;
- reproducible benchmark, ablation, runtime red-team, latency, bootstrap, and table-generation scripts.

## Non-Goals

- No real credential handling.
- No operational payloads against real services.
- No closed-platform sandbox reverse engineering.
- No claim of production-grade deployment until real ecosystem measurement, manual triage, and responsible disclosure evidence are complete.

## Research Questions

| RQ | Question | Evidence target |
|---|---|---|
| RQ1 | Where do per-layer detectors fail on compositional malicious skills? | Detector comparison over metadata/static/sandbox/runtime baselines. |
| RQ2 | Can a typed evidence graph express cross-layer inconsistencies? | C1-C7 constraint coverage and evidence path attribution. |
| RQ3 | Does graph fusion outperform naive union and voting baselines? | Precision/recall/F1/FPR, AUROC/AUPRC, threshold sweep, bootstrap CI. |
| RQ4 | Can runtime constraints reduce attack success while preserving benign task success? | ASR, UTCR, EDR, PS, SC, false block rate, latency. |
| RQ5 | Are cross-layer mismatches observable in public ecosystems? | Real corpus crawler, data card, risk pattern triage, disclosure workflow. |

## Current Status

- Prototype and synthetic artifact are functional.
- The benchmark covers seven attack classes and 4,010 samples.
- Fusion evaluation reports threshold-independent metrics, paired significance tests, held-out/hard-negative robustness checks, a local instrumented runtime harness, a curated third-party public-code sandbox fixture suite, a bounded corpus-derived PyPI package sandbox, a bounded GitHub repo sandbox, a bounded public remote endpoint audit, a bounded public remote task audit, label-leakage audit, and regenerated paper tables.
- A passive real public measurement over 1,000 public MCP artifacts (300 GitHub repositories, 200 npm packages, 150 discovered PyPI packages, 150 Hugging Face Spaces, 100 Smithery hosted-registry entries, and 100 official MCP Registry entries) is included with a data card, an official-advisory cross-check, and manual triage of all HIGH findings, alongside supplementary 2k/3k/5k/10k scale-out catalog batches.
- The remaining claim boundary is deployment-grade external validity: passive multi-source catalog evidence, local toy-harness evidence, and synthetic stress checks do not replace production runtime confirmation or disclosure-backed real vulnerability case studies.

## Canonical Acceptance Source

Use `docs/execution_checklist.md` for the working checklist and `checklists/acceptance_checklist.md` for final release gates.
