# Mock Review Notes

Date: 2026-05-28

## Summary judgment

SkillGuardGraph is a strong artifact-oriented research prototype with a coherent systems framing, but it is not yet a complete top-tier systems-security submission in its current evidence state.

## Strengths

1. Clear cross-layer thesis spanning metadata, implementation, permissions, runtime provenance, approval, persistence, and updates.
2. Reproducible synthetic benchmark and evaluation pipeline with checked-in results.
3. Explicit claim-boundary discipline: the paper and docs no longer overstate runtime or ecosystem evidence.
4. Evidence-path output and constraint library are reviewer-visible and test-backed.
5. Supplementary multi-source ecosystem measurements show serious effort toward external validity.

## Weaknesses

1. Real-world evidence remains passive and metadata-heavy.
2. No confirmed real vulnerabilities or disclosure-backed case studies.
3. Local runtime/sandbox harnesses are still toy harnesses rather than third-party execution environments.
4. Source-available coverage in real batches remains too low for strong exploit or implementation claims.
5. The 5k and 10k ecosystem measurements materially improve breadth but not validation depth.

## Likely reviewer scores if submitted now

| Dimension | Assessment |
|---|---|
| Novelty | Positive |
| Technical depth | Moderate |
| Evaluation rigor | Strong on synthetic artifact; weak on real-world validation |
| Artifact quality | Strong |
| External validity | Weak-to-moderate |

## Go / no-go recommendation

- **Go** for artifact-focused, benchmark-focused, or early-measurement venues.
- **No-go** for strongest system-security claim set until real-case validation improves materially.

## Minimum improvements that would change this recommendation

1. The artifact now reaches 10k passive public artifacts, so the next missing step is no longer scale alone but materially better source coverage and validated real cases.
2. At least one disclosure-ready or confirmed real case study.
3. Third-party dynamic sandbox execution under safe isolation.
4. Production-like runtime integration rather than only toy harnesses.

## Paper handling guidance

If submitted before those improvements land:

- emphasize benchmark + typed evidence fusion + artifact quality;
- frame ecosystem results as passive catalog evidence;
- keep deployment claims in limitations/future work;
- avoid implying that the local harnesses are equivalent to production runtime instrumentation.
