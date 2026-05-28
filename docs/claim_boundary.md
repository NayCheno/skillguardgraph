# Claim Boundary — SkillGuardGraph

This document defines the precise boundary between what the artifact can and cannot claim.

## What the artifact claims

| Claim | Evidence type | Confidence |
|---|---|---|
| Cross-layer fusion outperforms naive union on the synthetic benchmark | Synthetic benchmark (4,010 samples) | High — reproducible |
| Cross-layer fusion outperforms weighted voting on the synthetic benchmark | Synthetic benchmark + McNemar + bootstrap | High — reproducible |
| Runtime provenance is the dominant evidence signal in the synthetic benchmark | Ablation over synthetic benchmark | High — reproducible |
| The artifact generalizes to a vocabulary-shifted independent benchmark | Independent benchmark (410 samples) | High — reproducible |
| Held-out, hard-negative, mutation, and label-blinding stress checks pass | Synthetic stress suite | High — reproducible |
| Runtime containment achieves zero ASR and zero false-block on the local harness | Local instrumented harness (105+105 tasks) | Medium — local toy harness, not production |
| Passive public MCP ecosystem shows weak governance provenance (80% unsigned) | Passive crawl of 1,000 public artifacts | Medium — catalog-level, not code-complete |
| Passive measurement finds 2 HIGH findings in 1,000 artifacts, both unconfirmed | Manual triage of passive results | Medium — passive evidence only |

## What the artifact does NOT claim

| Non-claim | Reason |
|---|---|
| Real-world vulnerability discovery | No confirmed vulnerabilities; 2 HIGH findings are unconfirmed after manual triage |
| Production deployment readiness | No authenticated runtime integration, no overhead measurement in a real agent |
| Full cross-layer fusion is necessary for all attack types | Static and sandbox layers show no aggregate F1 drop on the synthetic benchmark |
| Comprehensive ecosystem coverage | Passive metadata-only for 98.5% of corpus; excludes private/enterprise catalogs |
| LLM judge baseline represents state-of-the-art | LLM judge stub uses a fixed heuristic, not a production LLM-based detector |
| Independent benchmark proves real-world separability | Still synthetic; different vocabulary but same generator family |

## Evidence classification

Every result table in the artifact is tagged with its evidence source:

| Tag | Meaning | Used for |
|---|---|---|
| `synthetic` | Template-generated benchmark data | Main detection table, ablation, generalization |
| `synthetic-stress` | Synthetic data with mutation/blinding | Stress check tables |
| `independent-synthetic` | Separate generator, different vocabulary | Independent benchmark table |
| `local-harness` | Instrumented local toy harness | Runtime containment table |
| `local-sandbox` | Subprocess-isolated toy sandbox | Sandbox containment table |
| `third-party-fixture` | Curated public-code archive fixtures | Third-party sandbox table |
| `corpus-package` | Bounded source-available PyPI cases | Corpus package sandbox table |
| `github-repo` | Bounded source-available GitHub entrypoints | GitHub repo sandbox table |
| `typescript-repo` | Bounded source-available TS/JS entrypoints | TS repo sandbox table |
| `remote-endpoint` | Unauthenticated public endpoint probes | Remote endpoint audit table |
| `remote-task` | Harmless read-only tool calls on public endpoints | Remote task audit table |
| `real-passive` | Passive metadata crawl of 1,000 public artifacts | Ecosystem measurement table |
| `real-catalog` | Supplementary 2k/3k/5k/10k catalog batches | Appendix ecosystem tables |

## Claim consistency rules

1. The abstract must not use "vulnerability" without qualifier — use "unsafe chain" or "governance risk."
2. The main detection table is tagged `synthetic`; it cannot be cited as proof of real-world detection.
3. The ecosystem measurement section uses `real-passive` evidence only; it cannot claim exploit confirmation.
4. All numeric claims in the paper must trace to a checked-in result JSON under `experiments/results/`.
5. Ablation claims must be stated conditionally: "In the synthetic benchmark, static/sandbox layers show no aggregate F1 drop because their signals overlap with runtime evidence."
6. The evaluation must explicitly position synthetic F1=1.000 as artifact-consistency evidence, not as deployment proof.

## Comparison: before and after claim reset

| Section | Before (risky wording) | After (corrected wording) |
|---|---|---|
| Abstract | "reaches 100.0% precision and recall" | "reaches 100.0% precision and recall on the synthetic benchmark" |
| Ablation | "runtime provenance is the dominant signal" | "In the synthetic benchmark, runtime provenance is the dominant signal; static/sandbox layers show no aggregate F1 change because their signals overlap with runtime evidence" |
| Ecosystem | "cross-layer governance gaps are prevalent" | "passive catalog-level measurement finds governance metadata immaturity; this does not constitute exploit confirmation" |
| Runtime | "ASR = 0.0" | "ASR = 0.0 on the local instrumented toy harness; this does not constitute production runtime evidence" |
| Limitations | "external validity remains future work" | Explicit enumeration of all remaining gaps per Section 8 |
