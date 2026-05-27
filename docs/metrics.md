# SkillGuardGraph Metric Definitions

This document defines all metrics used in the SkillGuardGraph evaluation. Each metric includes a formal definition, computation formula, and interpretation guidance. All metrics are computed over the benchmark dataset and reported with bootstrap 95% confidence intervals.

---

## 1. Detection Metrics

Detection metrics evaluate the ability of individual detectors and the fusion system to correctly classify skills as malicious or benign.

### 1.1 Confusion Matrix Foundation

For a binary classification at the skill level (or at the evidence-path level for fusion):

|  | Predicted Malicious | Predicted Benign |
|---|---|---|
| **Actually Malicious** | TP (true positive) | FN (false negative) |
| **Actually Benign** | FP (false positive) | TN (true negative) |

### 1.2 Precision

**Definition:** Of all skills flagged as malicious, the fraction that are truly malicious.

**Formula:**

```
Precision = TP / (TP + FP)
```

**Interpretation:** High precision means few false alarms. In a deployment context, precision directly affects operator trust: low precision causes alert fatigue.

### 1.3 Recall (True Positive Rate / Sensitivity)

**Definition:** Of all truly malicious skills, the fraction detected.

**Formula:**

```
Recall = TP / (TP + FN)
```

**Interpretation:** High recall means few missed attacks. For security-critical applications, recall is often weighted more heavily, but SkillGuardGraph requires both high recall and acceptable precision (see hard thresholds).

### 1.4 F1 Score

**Definition:** Harmonic mean of precision and recall.

**Formula:**

```
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```

**Interpretation:** Single-number summary balancing precision and recall. Reported alongside precision and recall to avoid masking trade-offs.

### 1.5 False Positive Rate (FPR)

**Definition:** Of all truly benign skills, the fraction incorrectly flagged as malicious.

**Formula:**

```
FPR = FP / (FP + TN)
```

**Interpretation:** FPR is the critical deployment constraint. Even moderate FPR (e.g., 5%) over thousands of skills produces an unmanageable volume of false alerts. The paper's central claim requires that evidence graph fusion achieves lower FPR than naive union while maintaining recall.

### 1.6 AUROC (Area Under the Receiver Operating Characteristic Curve)

**Definition:** Area under the curve plotting true positive rate (recall) vs. false positive rate as the decision threshold varies from 0 to 1.

**Formula:**

```
AUROC = ∫₀¹ TPR(FPR⁻¹(t)) dt    (computed numerically via trapezoidal rule)
```

**Interpretation:** Threshold-independent measure of separability. AUROC = 0.5 indicates random performance; AUROC = 1.0 indicates perfect separation. Reported for each detector and for the fusion system.

### 1.7 AUPRC (Area Under the Precision-Recall Curve)

**Definition:** Area under the curve plotting precision vs. recall as the decision threshold varies.

**Formula:**

```
AUPRC = ∫₀¹ Precision(Recall⁻¹(t)) dt    (computed numerically via trapezoidal rule)
```

**Interpretation:** More informative than AUROC when the positive class (malicious) is rare. AUPRC is sensitive to class imbalance, making it the preferred summary metric for ecosystem measurement where malicious skills are the minority.

---

## 2. Attack Impact Metrics

Attack impact metrics evaluate the severity and reach of successful attacks when defenses are deployed. These metrics are computed over adversarial red-team task suites against the runtime enforcement system.

### 2.1 Attack Success Rate (ASR)

**Definition:** Fraction of attack attempts in which the attacker achieves the intended malicious objective (e.g., data exfiltration, unauthorized action execution, persistence establishment).

**Formula:**

```
ASR = successful_attacks / total_attack_attempts
```

**Interpretation:** ASR is the primary defense efficacy metric. An ASR of 0.0 means the defense blocks all attacks; ASR of 1.0 means the defense is fully bypassed. ASR is computed per attack class (T1–T7) and aggregated.

### 2.2 Unauthorized Tool Call Rate (UTCR)

**Definition:** Fraction of tool calls that the policy engine would deny or degrade but that were nonetheless executed (indicating enforcement bypass or policy gap).

**Formula:**

```
UTCR = unauthorized_tool_calls / total_tool_calls_in_attack_sessions
```

**Interpretation:** UTCR captures enforcement coverage at the tool-call granularity rather than the attack-instance granularity. A single attack may involve multiple tool calls; UTCR reveals how many of those calls slipped through.

### 2.3 Exfiltration Data Rate (EDR)

**Definition:** Fraction of sensitive data objects that reach an external sink (network send, email, file upload to untrusted destination) during a successful attack.

**Formula:**

```
EDR = exfiltrated_data_objects / total_sensitive_data_objects_accessed
```

**Interpretation:** EDR measures the actual data loss, not just whether an attack "succeeded." An attack that triggers but only exfiltrates 2 of 50 sensitive records has EDR = 0.04, indicating partial containment.

### 2.4 Blast Radius Index (BRI)

**Definition:** A composite metric quantifying the maximum potential impact scope of a successful attack.

**Formula:**

```
BRI = reachable_assets × mean_sensitivity_level × mean_permission_weight
```

Where:
- `reachable_assets` = the number of distinct data objects, services, or accounts reachable from the attack's execution path in the evidence graph.
- `mean_sensitivity_level` = the average sensitivity label (on a normalized 0–1 scale, where 1 = highest sensitivity such as credentials, PII, financial data) of reachable assets.
- `mean_permission_weight` = the average granted permission weight (normalized 0–1 scale, where 1 = full admin/destructive capability) along the attack path.

**Interpretation:** BRI captures "how bad could it get" rather than "did it get bad." Two attacks with the same ASR can have vastly different BRI values. BRI is reported as a distribution over attack instances, not a single number.

### 2.5 Persistence Score (PS)

**Definition:** Fraction of successful attacks whose malicious effect persists beyond the current session, surviving session restart, context clearing, or time delay.

**Formula:**

```
PS = persistent_attacks / successful_attacks
```

An attack is classified as persistent if any of the following hold:
- Malicious content is written to memory, config, hooks, or knowledge stores (T5).
- A version update that introduced the attack remains installed after the session (T3).
- The attack modifies policy or trust labels that affect future sessions.

**Interpretation:** PS distinguishes "fire and forget" attacks from "establish foothold" attacks. High PS with moderate ASR may be more dangerous than high ASR with zero PS.

### 2.6 Stealth Coefficient (SC)

**Definition:** Fraction of successful attacks that did not trigger any alert, approval request, or logged anomaly during execution.

**Formula:**

```
SC = stealth_successful_attacks / successful_attacks
```

An attack is classified as stealthy if:
- No policy engine alert was raised (risk score below alert threshold), AND
- No HITL approval was triggered for the malicious action, AND
- No anomaly was logged in the audit trail.

**Interpretation:** SC measures the defense's blind spot. SC = 0.0 means every successful attack at least triggered an alert (even if not blocked); SC = 1.0 means the defense was completely silent. SC is reported alongside ASR: a system with ASR = 0.15 and SC = 0.90 has a very different risk profile than one with ASR = 0.15 and SC = 0.10.

---

## 3. Usability Metrics

Usability metrics evaluate whether the defense system is acceptable for real-world deployment without degrading the user experience or blocking legitimate work.

### 3.1 Task Success Rate (TSR)

**Definition:** Fraction of benign (legitimate) task executions that complete successfully under the deployed defense policy.

**Formula:**

```
TSR = successfully_completed_benign_tasks / total_benign_tasks
```

**Interpretation:** TSR captures the "cost of defense." A system that blocks all attacks (ASR = 0.0) but reduces TSR from 0.95 to 0.70 is not deployable. The hard threshold requires TSR drop ≤ 10–15% compared to the undefended baseline.

### 3.2 Approval Burden (AB)

**Definition:** Average number of HITL approval prompts per task execution.

**Formula:**

```
AB = total_approval_prompts / total_tasks
```

**Interpretation:** Each approval prompt interrupts the user's workflow. AB is reported as a mean with distribution. High AB indicates the defense is over-triggering HITL gates. The acceptable range depends on task criticality: low-stakes tasks tolerate AB < 0.5; high-stakes tasks may tolerate AB up to 2–3.

### 3.3 False Block Rate (FBR)

**Definition:** Fraction of benign tasks that are incorrectly denied, degraded, or sandboxed by the policy engine.

**Formula:**

```
FBR = incorrectly_blocked_benign_tasks / total_benign_tasks
```

**Interpretation:** FBR is a stricter usability metric than TSR. TSR includes tasks that fail for unrelated reasons (e.g., API errors, timeouts); FBR isolates failures caused by the defense system itself. FBR should be < 5% for a deployable system.

---

## 4. Performance Metrics

Performance metrics evaluate the engineering feasibility and computational cost of the defense system.

### 4.1 Runtime Latency

**Definition:** Wall-clock time added by the defense system per tool call, from evidence collection through fusion scoring to policy decision.

**Formula:**

```
Latency = time(policy_decision) − time(evidence_collection_start)
```

Reported as:
- **p50** (median)
- **p95** (95th percentile)
- **p99** (99th percentile)
- **max**

**Interpretation:** The hard threshold is 100–300 ms per tool call for the online path (excluding LLM judge, which is counted separately). Latency is measured on the target hardware specified in the experimental setup.

### 4.2 Token Cost

**Definition:** Number of LLM tokens consumed by the defense system per skill evaluation (for metadata analysis, sandbox task generation, and optional LLM-judge scoring).

**Formula:**

```
TokenCost = input_tokens + output_tokens    (per skill evaluation)
```

Reported as:
- Mean and standard deviation across the benchmark.
- Breakdown by component (metadata analysis, static analysis, sandbox probing, LLM judge, runtime monitoring).

**Interpretation:** Token cost is the primary recurring operational expense. The evidence graph fusion system should minimize reliance on LLM inference for the online path; LLM usage is acceptable for offline analysis and sandbox probing.

### 4.3 Sandbox Cost

**Definition:** Compute and time resources consumed by sandbox probing per skill.

**Formula:**

```
SandboxCost = {
    wall_time: sandbox_execution_duration,
    cpu_seconds: CPU time consumed,
    memory_peak_mb: peak memory usage,
    network_calls: number of mock network requests
}
```

**Interpretation:** Sandbox probing is the most expensive evidence source. Sandbox cost is reported per skill and amortized over the corpus to estimate total evaluation cost.

### 4.4 Throughput

**Definition:** Number of skill evaluations completed per unit time.

**Formula:**

```
Throughput = skills_evaluated / wall_clock_time
```

Reported as:
- Online throughput (tool-call latency path only).
- Offline throughput (full analysis including sandbox).

**Interpretation:** Throughput determines scalability. For ecosystem measurement of ≥5,000 skills, offline throughput must be sufficient to complete analysis within a reasonable time budget.

---

## 5. Explainability Metrics

Explainability metrics evaluate whether the defense system produces actionable output for security analysts.

### 5.1 Evidence Path Coverage (EPC)

**Definition:** Fraction of high-risk policy decisions (deny, quarantine, rollback) that are accompanied by a complete, human-readable evidence path showing the chain of constraint violations from evidence to decision.

**Formula:**

```
EPC = decisions_with_complete_evidence_path / total_high_risk_decisions
```

An evidence path is considered complete if it includes:
1. The violated constraint(s) (e.g., C1: capability consistency violation).
2. The specific graph nodes and edges involved.
3. The evidence source for each node (metadata, static, sandbox, runtime).
4. The risk contribution of each constraint violation to the final score.

**Interpretation:** The hard threshold requires EPC ≥ 80% for high-risk alerts, with a strong target of ≥ 95%. EPC measures whether analysts can understand and act on the system's output without reverse-engineering the scoring logic.

### 5.2 Alert Triage Time (ATT)

**Definition:** Median time for a security analyst to assess a high-risk alert and determine whether it is a true positive or false positive, given the system's evidence path output.

**Formula:**

```
ATT = median(triage_end_time − triage_start_time)    (measured in user study or timed exercise)
```

**Interpretation:** ATT operationalizes explainability. A system with EPC = 1.0 but poorly structured evidence paths may still have high ATT. The goal is ATT < 2 minutes per alert for trained analysts.

---

## 6. Statistical Methods

### 6.1 Bootstrap Confidence Intervals

All reported metrics are accompanied by 95% bootstrap confidence intervals.

**Procedure:**
1. For a metric computed over N samples, generate B = 1,000 bootstrap replicates by sampling N observations with replacement.
2. Compute the metric on each replicate.
3. Report the 2.5th and 97.5th percentiles of the bootstrap distribution as the 95% CI.

**Rationale:** Bootstrap CIs make no parametric assumptions and are valid for skewed distributions common in security metrics (e.g., ASR near 0 or 1, heavy-tailed latency).

### 6.2 Significance Tests

#### McNemar's Test (Detection Comparison)

Used to test whether two classifiers (e.g., fusion vs. naive union) have significantly different error rates on the same test set.

- **Null hypothesis H₀:** The two classifiers have the same error rate.
- **Test statistic:** χ² = (b − c)² / (b + c), where b = samples misclassified by classifier 1 but not 2, c = the converse.
- **Significance level:** α = 0.05, with Bonferroni correction for multiple comparisons.

#### Paired Bootstrap Test (Metric Comparison)

Used to test whether one system achieves a significantly higher metric value than another (e.g., fusion recall vs. best single-layer recall).

**Procedure:**
1. Compute the observed difference Δ = metric_fusion − metric_baseline on the full dataset.
2. For B = 1,000 bootstrap replicates, compute Δ_b.
3. The p-value is the fraction of replicates where Δ_b ≤ 0 (i.e., the baseline is at least as good as fusion).
4. Report significance at α = 0.05.

#### Wilcoxon Signed-Rank Test (Per-Sample Comparison)

Used when metrics are paired at the sample level (e.g., comparing latency distributions across the same tool calls under two configurations).

### 6.3 Multiple Comparison Correction

When reporting results across multiple attack classes (T1–T7), multiple detectors, and multiple metrics, we apply the Benjamini-Hochberg procedure to control the false discovery rate (FDR) at 5%. This is preferred over Bonferroni correction because it is less conservative while still controlling for spurious findings.

---

## 7. Hard Thresholds

The following thresholds define the minimum acceptable performance for the system to be considered viable. These are derived from the project plan (Section 0.2) and represent deployment-grade requirements.

### 7.1 Detection Thresholds

| Threshold | Requirement | Rationale |
|---|---|---|
| Fusion vs. naive union: FPR | Fusion FPR must be **strictly lower** than naive union FPR | The central contribution claim: cross-layer constraints reduce false alarms compared to any-alarm-is-alarm |
| Fusion vs. naive union: Recall | Fusion recall must **not significantly decrease** compared to naive union (paired bootstrap test, α = 0.05) | Lowering FPR by simply blocking fewer things is not a contribution |
| Fusion vs. best single-layer: Recall on compositional attacks | Fusion recall must improve by **≥ 10 percentage points** over the best individual detector | Demonstrates that fusion captures cross-layer attacks that no single layer can detect |

### 7.2 Usability Thresholds

| Threshold | Requirement | Rationale |
|---|---|---|
| Task Success Rate drop | TSR under defense must be **≤ 10–15%** lower than undefended baseline | Defense must not break legitimate workflows |
| False Block Rate | FBR must be **< 5%** | Only a small fraction of benign tasks should be incorrectly blocked |

### 7.3 Performance Thresholds

| Threshold | Requirement | Rationale |
|---|---|---|
| Runtime latency (online path) | p95 latency must be **≤ 300 ms** per tool call (excluding LLM judge) | Defense must not introduce perceptible delay in agent interactions |
| Runtime latency (target) | p50 latency should be **≤ 100 ms** per tool call | Median experience should be near-instantaneous |

### 7.4 Explainability Thresholds

| Threshold | Requirement | Rationale |
|---|---|---|
| Evidence Path Coverage (minimum) | **≥ 80%** of high-risk alerts must have a complete evidence path | Security analysts must be able to understand and act on most alerts |
| Evidence Path Coverage (strong target) | **≥ 95%** of high-risk alerts must have a complete evidence path | Near-complete explainability for audit and compliance |

### 7.5 Non-Threshold Reporting Requirements

The following are not pass/fail thresholds but must always be reported alongside primary detection results:

- **FPR** (not just recall): any detection result table that omits FPR is incomplete.
- **Latency**: any system claim that omits latency is incomplete.
- **Task success rate**: any defense evaluation that omits usability impact is incomplete.
- **Per-attack-class breakdown**: aggregate metrics can mask failure on specific attack classes.
- **Confidence intervals**: point estimates without confidence intervals are insufficient for CCF-A publication.

---

## 8. Metric Computation in Practice

### 8.1 Skill-Level vs. Path-Level Metrics

Detection metrics (Precision, Recall, F1, FPR, AUROC, AUPRC) are computed at two granularities:
- **Skill level:** Each skill is classified as malicious or benign as a whole.
- **Evidence-path level:** Each constraint-violating path is classified as a true or false detection. A single malicious skill may trigger multiple evidence paths.

Both are reported; skill-level metrics are the primary comparison point, and path-level metrics provide diagnostic granularity.

### 8.2 Per-Attack-Class Reporting

Attack impact metrics (ASR, UTCR, EDR, BRI, PS, SC) are reported per attack class (T1–T7) in addition to aggregates. This prevents a system that excels at T1 and T7 but fails on T3–T6 from claiming high aggregate performance.

### 8.3 Metric Aggregation Over Defenses

When comparing defense policies (allow, degrade, sandbox-only, HITL, deny, quarantine, rollback), metrics are reported per policy action type and in aggregate. This reveals whether the system over-relies on a single policy action (e.g., always denying rather than intelligently degrading).
