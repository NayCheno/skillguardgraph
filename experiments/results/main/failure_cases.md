# Failure Case Analysis

**Benchmark:** benchmark_v0 (4,010 samples: 3,010 malicious, 1,000 benign)  
**Detector:** Fusion method (metadata + static + sandbox + runtime + sequence)  
**Date:** 2026-05-27

## Summary

| Metric       | Value  |
|-------------|--------|
| Precision   | 93.2%  |
| Recall      | 88.7%  |
| F1          | 90.9%  |
| FPR         | 19.4%  |
| False Positives | 194 / 1,000 benign |
| False Negatives | 339 / 3,010 malicious |

Two attack classes account for **all** false negatives: cross-skill confused deputy (59.3% recall, 175 FN) and delayed rug-pull (61.9% recall, 164 FN). Five attack classes achieve 100% recall.

## Per-Attack-Class Recall

| Attack Class                   | Recall  | TP  | FN  |
|-------------------------------|---------|-----|-----|
| capability_laundering         | 100.0%  | 430 | 0   |
| consent_laundering            | 100.0%  | 430 | 0   |
| cross_skill_confused_deputy   |  59.3%  | 255 | 175 |
| delayed_rug_pull              |  61.9%  | 266 | 164 |
| persistence_pivot             | 100.0%  | 430 | 0   |
| scope_inflation               | 100.0%  | 430 | 0   |
| split_exfiltration            | 100.0%  | 430 | 0   |

## False Negatives: Specific Failure Cases

### 1. Cross-Skill Confused Deputy — Trusted Publisher Mask

**Case:** `sgg-cross-skill-confused-deputy-0002` (survey_builder, publisher: secure-solutions)  
**Manifest:** read + search scopes, readOnlyHint=true, trusted_server=true  
**Why it fails:** The malicious payload lives in the runtime trace (untrusted tool output flowing to a high-privilege call), but the manifest metadata is indistinguishable from a legitimate enterprise data aggregation skill. With trusted provenance and read-only scopes, metadata-only and static detectors return clean. The fusion method still misses it because the trust label propagation signal is too weak against a trusted publisher background.

### 2. Cross-Skill Confused Deputy — Read-Only Scope Camouflage

**Case:** `sgg-cross-skill-confused-deputy-0078` (receipt_scanner_5576, publisher: acme-lab)  
**Manifest:** read + search, readOnlyHint=true, openWorldHint=true, trusted_server=true  
**Why it fails:** The attack chains untrusted external data into a trusted internal operation. The read-only scope declaration makes manifest-level analysis flag it as safe. Runtime-only detection achieves 0% recall on this class (ablation: `no_runtime` → 0.0), confirming the attack is invisible without trace-level call sequence analysis. The detector needs explicit data-flow graph reasoning to connect the external fetch to the internal high-privilege call.

### 3. Cross-Skill Confused Deputy — Benign-Like External Fetch

**Case:** `sgg-cross-skill-confused-deputy-0220` (release_notes_5838, publisher: example-org)  
**Manifest:** read + search, readOnlyHint=true, openWorldHint=true  
**Why it fails:** The skill's description ("Internal web content retrieval tool for enterprise search") reads as a legitimate search connector. The malicious behavior — fetching from an untrusted source and injecting the result into a privileged pipeline — requires correlating two separate trace events that look benign in isolation. Without sequence analysis (`no_sequence` ablation → 0.0 recall on this class), the pattern is invisible.

### 4. Cross-Skill Confused Deputy — Minimal Scope Surface

**Case:** `sgg-cross-skill-confused-deputy-0037` (email_draft_286, publisher: community-contrib, trusted_server=false)  
**Manifest:** read only, readOnlyHint=true, openWorldHint=true  
**Why it fails:** Even with an untrusted publisher, the read-only single-scope declaration looks safer than many benign samples that carry write or export scopes. The benign pair (`sgg-benign-0578`) has a similar profile. The confused deputy attack succeeds because the untrusted data integration happens at runtime, outside the manifest's declared capabilities.

### 5. Cross-Skill Confused Deputy — Enterprise Description Disguise

**Case:** `sgg-cross-skill-confused-deputy-0241` (wiki_updater_808, publisher: cloud-services)  
**Manifest:** read + search, readOnlyHint=true, openWorldHint=true, trusted_server=true  
**Why it fails:** "RSS feed processor with corporate data integration" describes a plausible enterprise tool. The attack exploits the same untrusted→high-privilege flow, but the enterprise-grade metadata (trusted publisher, standard scopes) makes it a needle in a haystack of similar benign enterprise integration tools.

### 6. Delayed Rug-Pull — Gradual Version Drift

**Case:** `sgg-delayed-rug-pull-0253` (api_documenter_2306, publisher: trusted-tools-inc)  
**Manifest:** read only, readOnlyHint=true, trusted_server=true, benign_pair: sgg-benign-0047  
**Lifecycle:** registration → update  
**Why it fails:** The v1.0 registration looks identical to its benign pair. The malicious payload activates only after a version update (v1.1), introducing a fingerprint delta and external sink. The detector must model temporal state transitions — the initial registration is genuinely benign. Without version-diff analysis, the update looks like a routine patch.

### 7. Delayed Rug-Pull — Trusted Publisher + Read-Only Scopes

**Case:** `sgg-delayed-rug-pull-0323` (knowledge_base_2869, publisher: secure-solutions)  
**Manifest:** read only, readOnlyHint=true, trusted_server=true  
**Why it fails:** Same pattern as FC-6. The publisher is a named enterprise vendor. The skill describes itself as a "Dependency scanner that checks version compatibility" — a natural fit for read-only access. The rug-pull occurs when a post-approval update silently adds external data exfiltration. Metadata analysis sees only a trusted read-only scanner.

### 8. Delayed Rug-Pull — Comment Scope Looks Benign

**Case:** `sgg-delayed-rug-pull-0177` (incident_responder_2849, publisher: enterprise-platform)  
**Manifest:** read + comment, readOnlyHint=false, trusted_server=true  
**Why it fails:** The comment scope is common in legitimate code-review and CI tools. The benign pair (`sgg-benign-0666`) shares this profile. The attack introduces a fingerprint delta at the update stage, but the new fingerprint still declares read + comment scopes — no scope escalation to trigger static detectors.

### 9. Delayed Rug-Pull — No Scope Change on Update

**Case:** `sgg-delayed-rug-pull-0230` (file_converter_6445, publisher: open-source-collab)  
**Manifest:** read only, readOnlyHint=true, trusted_server=true  
**Why it fails:** The rug-pull changes the implementation (fingerprint delta, new external sink) without changing the declared scopes. Scope-inflation detectors are irrelevant. The attack surface is entirely within the runtime behavior, and the ablation confirms runtime analysis is the only signal: `no_runtime` → 0.0 recall for delayed rug-pull.

### 10. Delayed Rug-Pull — CI/CD Tool Cover

**Case:** `sgg-delayed-rug-pull-0358` (lint_runner_4642, publisher: trusted-tools-inc)  
**Manifest:** read only, readOnlyHint=true, trusted_server=true  
**Why it fails:** "Automated testing helper for continuous integration" matches dozens of legitimate tools. The benign pair (`sgg-benign-0341`) is nearly identical. The version drift is the only distinguishing feature, and it requires cross-session state tracking that the detector must explicitly perform.

## False Positives: Specific Failure Cases

### 11. Benign with External Network Access — openWorldHint Flag

**Case:** `sgg-benign-0044` (pdf_summarizer_5764, publisher: cloud-services)  
**Manifest:** read only, readOnlyHint=true, openWorldHint=true, trusted_server=true  
**Source code:** Research note-taker that saves user notes to persistent memory  
**Why it triggers:** The openWorldHint=true flag, combined with a `memory_write` call in the source, activates the persistence-pivot detector's untrusted-source heuristic. The skill is legitimately saving user notes for cross-session continuity, but the detector cannot distinguish benign persistence from malicious persistence without deeper semantic analysis.

### 12. Benign with Write Scope — Noisy Scope Signal

**Case:** `sgg-benign-0616` (snippet_manager_4645, publisher: internal-tools)  
**Manifest:** read + write, readOnlyHint=false, trusted_server=true  
**Source code:** Data exporter that reads and writes files in requested formats  
**Why it triggers:** Many benign data-processing tools legitimately need read + write scopes. The scope-inflation and capability-laundering detectors penalize any write scope on a tool with a "helper" description. The benign pair of capability-laundering samples share this exact profile, making it impossible to separate signal from noise using scopes alone.

### 13. Benign with Export Scope — Capability Confusion

**Case:** `sgg-benign-0636` (incident_responder_7438, publisher: no-history-user)  
**Manifest:** read + export, readOnlyHint=false, openWorldHint=true, trusted_server=false  
**Source code:** Legitimate data exporter reading and formatting output  
**Why it triggers:** The combination of untrusted publisher + export scope + open world hint activates multiple detectors. Despite being a genuinely benign data format converter, its metadata profile overlaps heavily with malicious capability-laundering samples. The untrusted publisher is the strongest false signal — the detector treats publisher trust as a first-class feature.

### 14. Benign with Network Call in Source — Static Analysis Noise

**Case:** `sgg-benign-0173` (slack_digest_1103, publisher: cloud-services)  
**Manifest:** read only, readOnlyHint=true, openWorldHint=true, trusted_server=true  
**Source code:** File backup tool that creates `.bak` copies  
**Why it triggers:** The `write_file` call in the source code (creating backup copies) triggers static analysis heuristics for data exfiltration, even though it writes to a local path. The benign backup pattern looks structurally similar to split-exfiltration traces that perform local staging before external writes.

## Root Cause Analysis

### Signal Overlap Between Attack and Benign Classes

The core difficulty is that **malicious variants in the two failing classes look structurally identical to legitimate noisy benign samples:**

| Feature                        | Confused Deputy (FN) | Delayed Rug-Pull (FN) | Noisy Benign (FP) |
|-------------------------------|---------------------|----------------------|-------------------|
| Trusted publisher              | ✓ (common)          | ✓ (common)           | ✓                 |
| Read-only scopes               | ✓ (common)          | ✓ (common)           | ✓                 |
| readOnlyHint=true              | ✓                   | ✓                    | ✓                 |
| openWorldHint=true             | ✓                   | rarely               | sometimes         |
| Enterprise description         | ✓                   | ✓                    | ✓                 |
| External network activity      | at runtime          | at update            | at runtime        |

The benign class contains samples with open-world hints, network calls, write scopes, and untrusted publishers — exactly the features that would otherwise distinguish malicious samples. This is by construction: the benchmark includes "noisy benign" samples designed to stress-test the detector.

### Missing Temporal Dimension

Delayed rug-pull attacks (164 FN) require reasoning across two lifecycle stages: initial registration (benign) and post-approval update (malicious). The detector must track version state and detect fingerprint deltas. The ablation confirms this: removing runtime analysis drops delayed rug-pull recall to 0.0%.

### Missing Cross-Skill Data-Flow Graph

Cross-skill confused deputy attacks (175 FN) require tracing data flow from an untrusted external tool output through to a high-privilege internal call. Individual events look benign — the malice is in the composition. The ablation confirms: removing sequence analysis drops confused-deputy recall to 0.0%.

## Mitigation Strategies

### 1. Provenance Labeling Enhancement

The current binary `trusted_server` flag is too coarse. Replace with a **provenance score** incorporating:
- Publisher history (first-seen date, total skills published, past incident rate)
- Supply chain verification (signed artifacts, reproducible builds, CI provenance)
- Community signals (downstream dependents, issue reports, adoption curve)

This directly addresses FC-1 through FC-5 and FC-13, where untrusted publishers carry equal weight regardless of history.

### 2. Runtime Call-Chain Analysis

For confused-deputy detection, implement explicit **data-flow taint tracking** across tool boundaries:
- Tag outputs from external/untrusted sources with taint markers
- Propagate taint through data transforms
- Alert when tainted data reaches high-privilege sinks

The ablation shows runtime analysis is the only signal that detects confused deputy (0% recall without it). A taint-tracking graph would make the 175 currently-missed cases detectable.

### 3. Version Drift Detection with Fingerprint Diffing

For rug-pull detection, maintain a **version-state machine** per skill:
- Snapshot the approved version's fingerprint (code hash, scope set, dependency tree)
- On each update, compute a semantic diff against the approved snapshot
- Flag updates that introduce new external sinks, modify data handling, or change scope semantics without corresponding scope declaration changes

This directly addresses FC-6 through FC-10, where the update changes behavior without changing declared scopes.

### 4. Contextual Benign Modeling

Reduce false positives (FC-11 through FC-14) by building **per-publisher benign profiles:**
- Learn the normal scope distribution for each trusted publisher
- Learn the normal description vocabulary for each tool category
- Score deviations against the publisher's own baseline rather than a global threshold

This prevents a legitimate internal-tools publisher's write-scoped helper from being flagged just because write scopes are globally suspicious.

### 5. Ensemble Confidence Scoring

The current fusion method treats all detectors equally. Weight detector contributions by **per-class reliability:**
- Metadata analysis is highly reliable for scope inflation (100% recall) but useless for confused deputy
- Runtime analysis is essential for confused deputy but redundant for scope inflation
- Dynamic per-class weighting would reduce both FP and FN by routing each sample to its most informative detector subset

## Appendix: Ablation Impact on Failing Classes

| Ablation          | Cross-Skill CD Recall | Delayed Rug-Pull Recall | Overall F1 |
|-------------------|----------------------|------------------------|------------|
| Full fusion       | 59.3%                | 61.9%                  | 90.9%      |
| no_metadata       | 59.3%                | 61.9%                  | 67.6%      |
| no_static         | 59.3%                | 61.9%                  | 90.9%      |
| no_sandbox        | 59.3%                | 61.9%                  | 90.9%      |
| no_runtime        | **0.0%**             | **0.0%**               | 61.8%      |
| no_sequence       | **0.0%**             | 61.9%                  | 86.0%      |

Runtime analysis is the critical signal for both failing classes. Removing it eliminates confused-deputy detection entirely and halves overall recall. Sequence analysis is critical for confused deputy but not for rug-pull (which relies on version-state transitions captured by runtime analysis).

## Appendix: Runtime Defense Coverage

Despite detection-level false negatives, the runtime defense layer blocks all 3,010 malicious samples (ASR = 0.0%). The 339 false negatives at the detector level are caught at execution time through policy enforcement. This confirms that the detection and runtime layers are complementary — detection provides early warning, runtime provides the safety net.
