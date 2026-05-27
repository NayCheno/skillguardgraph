# SkillGuardGraph Policy Specification

## 1. Overview

The SkillGuardGraph policy engine evaluates cross-layer evidence graphs against a set of structural constraints (C1–C7) and produces a **decision** with supporting **evidence paths**. This document specifies the decision taxonomy, constraint-to-decision mapping, threshold configuration, and deployment modes.

## 2. Policy Decisions

Seven distinct decisions are available, ordered from least to most restrictive:

| Decision | Label | When Appropriate |
|---|---|---|
| **ALLOW** | `allow` | No constraints violated. The skill may execute with full capabilities. |
| **DEGRADE** | `degrade` | One or more MEDIUM-severity constraints triggered. The skill is restricted: high-risk scopes are revoked or downgraded to read-only equivalents. The skill may still function in a reduced capacity. |
| **SANDBOX_ONLY** | `sandbox_only` | Static or metadata signals are concerning but runtime evidence is absent. The skill executes only inside a disposable sandbox with no network access and ephemeral storage. |
| **HITL** | `hitl` | One or more HIGH-severity constraints triggered. Execution is paused until a human reviewer approves. The evidence path is surfaced to the reviewer for informed consent. |
| **DENY** | `deny` | One or more CRITICAL-severity constraints triggered. The skill is blocked from execution entirely. The decision is logged with a full evidence trail. |
| **QUARANTINE** | `quarantine` | The skill exhibits patterns consistent with active exploitation (e.g., untrusted-to-persistence write chain). The skill is isolated, its publisher is flagged, and downstream dependents are notified. |
| **ROLLBACK** | `rollback` | A previously-approved skill has been updated with capabilities that violate constraints relative to its approved baseline. The update is reverted to the last approved version. |

### Decision Precedence

When multiple constraints trigger, the most restrictive decision wins:

```
ALLOW < DEGRADE < SANDBOX_ONLY < HITL < DENY < QUARANTINE < ROLLBACK
```

The policy engine currently emits ALLOW, DEGRADE, HITL, and DENY. SANDBOX_ONLY, QUARANTINE, and ROLLBACK are reserved for advanced deployment configurations (see §6).

## 3. Constraint-to-Decision Mapping

### C1: Declared Read-Only But Write Scope
- **Signal**: A manifest claims read-only capability (`declares_capability=read_only_or_low_risk`) but also requests write scopes (`requires_high_risk_scope`).
- **Default decision**: HITL (HIGH severity)
- **Rationale**: The contradiction may be an honest configuration error or a deliberate attempt to bypass review. A human should decide.
- **Deployment override**: In developer CI, downgrade to DEGRADE with a lint warning.

### C2: Untrusted Source to High-Privilege Sink
- **Signal**: A runtime trace shows an untrusted input source reaching a high-privilege tool call without an intervening sanitization or approval gate.
- **Default decision**: DENY (CRITICAL severity)
- **Rationale**: This is the canonical privilege escalation path. Automated denial is appropriate.
- **Deployment override**: In sandbox mode, downgrade to SANDBOX_ONLY.

### C3: Sensitive Data to External Sink
- **Signal**: Data labeled `sensitive` flows to an external sink (network, email) without redaction.
- **Default decision**: HITL (HIGH severity)
- **Rationale**: Data exfiltration risk. Requires human judgment on whether the transfer is authorized.
- **Deployment override**: In enterprise catalog with DLP integration, DENY automatically.

### C4: Post-Approval Drift
- **Signal**: A skill was approved at version X but is now executing with capabilities not present at approval time.
- **Default decision**: ROLLBACK (reserved)
- **Rationale**: Approved trust boundaries have been violated by an update.
- **Current implementation**: Returns MEDIUM/DEGRADE. Full ROLLBACK requires deployment integration.

### C5: Tainted Approval Text
- **Signal**: The manifest or approval request contains instruction-like language (e.g., "ignore previous instructions", "you are now") suggesting prompt injection.
- **Default decision**: DEGRADE (MEDIUM severity)
- **Rationale**: The approval text itself is adversarial. Scope should be restricted, but the skill may still be usable in a limited capacity.
- **Deployment override**: In HITL mode, escalate to human review.

### C6: Untrusted Source Writing to Persistent Store
- **Signal**: An untrusted input source reaches a persistence write (agent memory, config store, database).
- **Default decision**: HITL (HIGH severity)
- **Rationale**: Persistent writes from untrusted sources create durable attack surfaces. A human should verify the write is safe.
- **Deployment override**: In runtime gateway mode with write-ahead logging, allow with rollback capability.

### C7: Least-Privilege Scope Alignment
- **Signal**: The declared scopes significantly exceed the scopes actually used by the skill's observable behavior.
- **Default decision**: DEGRADE (MEDIUM severity)
- **Rationale**: Over-broad scopes increase blast radius. Degrading to the observed set reduces risk without blocking the skill.
- **Deployment override**: In developer CI, emit as a lint warning only.

## 4. Threshold Configuration

### 4.1 Score Computation

Findings are aggregated into a 0–10 risk score:

| Severity | Weight |
|---|---|
| LOW | 1 |
| MEDIUM | 3 |
| HIGH | 7 |
| CRITICAL | 10 |

The raw score is the sum of weights, capped at 10.0.

### 4.2 Decision Thresholds

| Score Range | Severity | Decision |
|---|---|---|
| 0 | LOW | ALLOW |
| 1–3 | MEDIUM | DEGRADE |
| 4–6 | HIGH | HITL |
| 7–10 | CRITICAL | DENY |

When multiple findings are present, the presence of any CRITICAL finding overrides the score-based decision and forces DENY. Similarly, any HIGH finding forces at least HITL.

### 4.3 Configurable Thresholds (Future)

The policy engine is designed for threshold overrides via configuration:

```yaml
# policy.yaml
thresholds:
  allow_max_score: 0
  degrade_max_score: 3
  hitl_max_score: 6
  # above hitl_max_score → deny

constraints:
  C1:
    default_severity: high
    override_severity: medium  # in CI mode
  C2:
    default_severity: critical
    sandbox_downgrade: true
```

## 5. Evidence Paths

### 5.1 Purpose

Every policy decision MUST be accompanied by an evidence path — the set of evidence items that contributed to the finding. Evidence paths serve three purposes:

1. **Auditability**: A reviewer can trace exactly why a decision was made.
2. **Debugging**: Developers can identify which behaviors triggered constraints.
3. **Appeal**: If a skill is denied, the evidence path shows what to fix.

### 5.2 Structure

An evidence path is a list of `Evidence` items, each containing:
- `kind`: The layer of origin (`metadata`, `static`, `runtime`, `sandbox`, `approval`, `governance`)
- `subject`: The entity being described (skill name, trace event ID)
- `predicate`: The assertion type (e.g., `requires_high_risk_scope`, `flows_to`)
- `object`: The assertion value
- `confidence`: 0.0–1.0 confidence in the assertion
- `attrs`: Additional context

### 5.3 Collection Rules

- Evidence paths are collected from HIGH and CRITICAL findings only.
- Evidence items are deduplicated by identity (same object reference).
- Maximum path length is bounded to prevent excessive memory use (current limit: 50 items per path, 20 items per finding).
- The path preserves insertion order (evidence collection order).

### 5.4 Serialization

Evidence paths serialize to JSON for storage and transmission:

```json
{
  "risk": "high",
  "decision": "hitl",
  "score": 7.0,
  "findings": [
    {
      "constraint": "C2_UNTRUSTED_TO_HIGH_PRIVILEGE",
      "severity": "critical",
      "message": "Untrusted source reaches high-privilege tool call",
      "evidence": [...],
      "nodes": ["trace:e1"]
    }
  ],
  "evidence_path": [
    {
      "kind": "runtime",
      "subject": "trace:e1",
      "predicate": "has_source_label",
      "object": "untrusted",
      "confidence": 0.9,
      "attrs": {"type": "source", "label": "untrusted"}
    }
  ]
}
```

## 6. Deployment Modes

### 6.1 Registry Mode

**Context**: Skill marketplace or registry where skills are published and consumed.

- All constraints (C1–C7) are evaluated at upload time.
- C4 (post-approval drift) is evaluated at update time.
- Decisions: ALLOW → publish; DEGRADE → publish with warnings; HITL → hold for review; DENY → reject upload.
- Evidence paths are stored alongside the skill listing.

### 6.2 Enterprise Catalog

**Context**: Internal skill catalog within an organization.

- All constraints evaluated at catalog entry and at periodic re-evaluation.
- C7 (least-privilege) is enforced more strictly: over-scoped skills are auto-degraded.
- C3 (sensitive data to external) integrates with DLP (Data Loss Prevention) policies.
- Decisions: ALLOW → available; HITL → requires org admin approval; DENY → blocked from catalog.
- Evidence paths feed into compliance dashboards.

### 6.3 Runtime Gateway

**Context**: A gateway or proxy that intercepts skill execution at runtime.

- C2 (untrusted-to-privilege) and C6 (untrusted-to-persistence) are evaluated in real time on each request.
- C3 (sensitive-to-external) is evaluated with runtime data labels.
- Decisions are enforced synchronously before tool calls execute.
- HITL decisions trigger an interactive approval prompt (timeout: 30s, default: deny).
- Evidence paths are logged to an audit trail.

### 6.4 Developer CI

**Context**: Pre-commit or CI pipeline checks during skill development.

- C1 (readonly-vs-write) is a lint warning, not a blocker.
- C5 (tainted approval text) is informational.
- C7 (least-privilege) is a lint warning with suggested scope reduction.
- Decisions: ALLOW/DEGRADE → pass; HITL → warning with exit code; DENY → fail build.
- Evidence paths are emitted as structured CI annotations.

## 7. Baseline Comparison

For experimental evaluation, seven baseline detectors are available alongside the full fusion pipeline:

| Baseline | Evidence Used | Approach |
|---|---|---|
| `metadata_only` | metadata, permission, governance | C1 + C5 constraints only |
| `static_only` | static | Source-sink pattern detection |
| `sandbox_only` | sandbox | Sandbox observation flags |
| `runtime_only` | runtime, approval | C2 + C3 + C6 constraints |
| `naive_union` | all | Any suspicious signal → escalate |
| `weighted_voting` | all | Weighted sum of suspicious signals |
| `llm_judge` | all | Simulated cross-layer corroboration |

The full fusion pipeline (`fuse_and_evaluate`) is expected to outperform all baselines by combining cross-layer evidence with structural graph constraints, achieving both higher precision (fewer false positives from single-layer noise) and higher recall (catching multi-layer attack patterns that single-layer baselines miss).
