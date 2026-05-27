# Expected Outputs — SkillGuardGraph Artifact

This document describes every output file produced by the experiment
pipeline, its format, approximate size, and the key metrics it contains.

---

## 1. Detection Evaluation

**File:** `results/main/detector_eval.json`
**Format:** JSON
**Size:** ~2 KB
**Produced by:** `make eval-main` (step: `run_detector_eval.py`)

### Structure

```json
{
  "total_samples": 4010,
  "methods": {
    "<method_name>": {
      "TP": <int>,
      "FP": <int>,
      "TN": <int>,
      "FN": <int>,
      "precision": <float>,
      "recall": <float>,
      "f1": <float>,
      "fpr": <float>
    }
  }
}
```

### Methods evaluated

| Method | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| metadata_only | 0.890 | 0.302 | 0.451 | 0.112 |
| static_only | 1.000 | 0.219 | 0.360 | 0.000 |
| sandbox_only | 1.000 | 0.219 | 0.360 | 0.000 |
| runtime_only | 1.000 | 0.422 | 0.594 | 0.000 |
| naive_union | 0.751 | 1.000 | 0.858 | 1.000 |
| weighted_voting | 0.954 | 0.887 | 0.920 | 0.128 |
| llm_judge | 0.751 | 1.000 | 0.858 | 1.000 |
| fusion | 0.932 | 0.887 | 0.909 | 0.194 |

---

## 2. Ablation Study

**File:** `results/main/ablation.json`
**Format:** JSON
**Size:** ~7 KB
**Produced by:** `make eval-main` (step: `run_ablation.py`)

### Structure

```json
{
  "total_samples": 4010,
  "ablations": {
    "<config_name>": {
      "TP": <int>,
      "FP": <int>,
      "TN": <int>,
      "FN": <int>,
      "precision": <float>,
      "recall": <float>,
      "f1": <float>,
      "fpr": <float>,
      "per_attack_class_recall": {
        "<class>": {
          "TP": <int>,
          "FN": <int>,
          "total": <int>,
          "recall": <float>
        }
      }
    }
  }
}
```

### Ablation configurations

| Config | F1 | F1 Delta from Full |
|---|---|---|
| full | 0.909 | - |
| no_metadata | 0.676 | -0.233 |
| no_static | 0.909 | +0.000 |
| no_sandbox | 0.909 | +0.000 |
| no_runtime | 0.618 | -0.291 |
| no_sequence | 0.860 | -0.050 |

### Attack classes (7 classes, 100 samples each)

| Class | Full Config Recall |
|---|---|
| capability_laundering | 1.000 |
| consent_laundering | 1.000 |
| cross_skill_confused_deputy | 1.000 |
| delayed_rug_pull | 1.000 |
| persistence_pivot | 1.000 |
| scope_inflation | 1.000 |
| split_exfiltration | 1.000 |

---

## 3. Runtime Red-Team Evaluation

**File:** `results/main/runtime_redteam.json`
**Format:** JSON
**Size:** ~2 KB
**Produced by:** `make eval-main` (step: `run_runtime_redteam.py`)

### Structure

```json
{
  "malicious_with_trace": 3010,
  "benign_total": 1000,
  "runtime_defense": {
    "ASR": <float>,
    "ASR_blocked": <float>,
    "UTCR": <float>,
    "UTCR_blocked_rate": <float>,
    "EDR": <float>,
    "EDR_blocked_rate": <float>,
    "BRI": <float>,
    "PS_blocked_rate": <float>,
    "PS_attempts": <int>,
    "PS_blocked": <int>,
    "SC": <float>,
    "SC_count": <int>
  },
  "usability": {
    "task_success_rate": <float>,
    "false_block_rate": <float>,
    "approval_burden": <float>,
    "task_success_count": <int>,
    "false_block_count": <int>,
    "hitl_count": <int>
  },
  "per_attack_class": { ... }
}
```

### Runtime defense metrics

| Metric | Value | Description |
|---|---|---|
| ASR | 0.000 | Attack Success Rate — fraction of attacks that succeeded |
| ASR_blocked | 1.000 | Fraction of attacks blocked |
| UTCR | 0.286 | Upstream Tainted Call Rate |
| UTCR_blocked_rate | 1.000 | Block rate for tainted calls |
| EDR | 0.714 | Exfiltration/Data-rate |
| EDR_blocked_rate | 1.000 | Block rate for exfiltration |
| BRI | 2.000 | Branching Risk Index (avg sensitive nodes) |
| PS_blocked_rate | 1.000 | Persistence strategy block rate |
| SC | 0.000 | Stealth Coefficient (0 = fully visible) |

### Usability metrics

| Metric | Value | Description |
|---|---|---|
| Task success rate | 0.806 | Benign tasks completed successfully |
| False block rate | 0.000 | Benign tasks incorrectly blocked |
| Approval burden | 0.112 | Unnecessary HITL prompts |

---

## 4. Paper Tables

**Files:** `results/main/tables.txt`, `results/main/tables.tex`
**Format:** Plain text / LaTeX
**Size:** ~3 KB each
**Produced by:** `make tables` (step: `make_tables.py`)

### tables.txt example (Table 1: Detection Comparison)

```
========================================================================
SkillGuardGraph Experiment Results
========================================================================

Table 1: Detection Comparison
+-----------------+-----------+--------+--------+--------+
| Method          | Precision | Recall | F1     | FPR    |
+-----------------+-----------+--------+--------+--------+
| metadata_only   | 0.8900    | 0.3020 | 0.4510 | 0.1120 |
| static_only     | 1.0000    | 0.2190 | 0.3600 | 0.0000 |
| sandbox_only    | 1.0000    | 0.2190 | 0.3600 | 0.0000 |
| runtime_only    | 1.0000    | 0.4220 | 0.5940 | 0.0000 |
| naive_union     | 0.7510    | 1.0000 | 0.8580 | 1.0000 |
| weighted_voting | 0.9540    | 0.8870 | 0.9200 | 0.1280 |
| llm_judge       | 0.7510    | 1.0000 | 0.8580 | 1.0000 |
| fusion          | 0.9320    | 0.8870 | 0.9090 | 0.1940 |
+-----------------+-----------+--------+--------+--------+
```

### tables.txt example (Table 5: Usability Metrics)

```
Table 5: Usability Metrics
+--------------------+--------+
| Metric             | Value  |
+--------------------+--------+
| Task Success Rate  | 0.8060 |
| False Block Rate   | 0.0000 |
| Approval Burden    | 0.1120 |
| Task Success Count | 806    |
| False Block Count  | 0      |
| HITL Count         | 112    |
+--------------------+--------+
```

### LaTeX tables

The `tables.tex` file contains 5 `table` environments with `\label`
keys ready for `\ref` in the paper:

| Table | Label |
|---|---|
| Table 1: Detection Comparison | `tab:detection` |
| Table 2: Per-Attack-Class Recall | `tab:per_class` |
| Table 3: Ablation Results | `tab:ablation` |
| Table 4: Runtime Defense Metrics | `tab:runtime` |
| Table 5: Usability Metrics | `tab:usability` |

---

## 5. Ecosystem Triage

**File:** `results/ecosystem/ecosystem_triage.json`
**Format:** JSON
**Size:** ~1.7 MB
**Produced by:** `make triage` (step: `triage_findings.py`)

### Structure

```json
{
  "metadata": {
    "total_samples": 1200,
    "total_findings": 620,
    "analyzed_at": "<ISO-8601 timestamp>"
  },
  "risk_patterns": {
    "total_triaged": 1200,
    "risk_pattern_rates": {
      "scope_inflation": { "count": 244, "rate": 0.203 },
      "description_mismatch": { "count": 273, "rate": 0.228 },
      "untrusted_publisher": { "count": 910, "rate": 0.758 },
      "missing_signature": { "count": 910, "rate": 0.758 },
      "open_world": { "count": 66, "rate": 0.055 },
      "instruction_like": { "count": 68, "rate": 0.057 }
    },
    "severity_distribution": {
      "low": 890,
      "high": 310
    },
    "decision_distribution": {
      "allow": 890,
      "hitl": 310
    },
    "per_source_risk": {
      "huggingface_spaces": { "count": 169, "mean_score": 2.84, ... },
      "npm_registry": { "count": 361, "mean_score": 2.33, ... },
      "enterprise_catalog": { "count": 121, "mean_score": 2.98, ... },
      "github_mcp": { "count": 357, "mean_score": 2.49, ... },
      "community_forum": { "count": 192, "mean_score": 2.76, ... }
    },
    "constraint_frequency": {
      "C1_DECLARED_READONLY_BUT_WRITE_SCOPE": 310,
      "C7_LEAST_PRIVILEGE_SCOPE": 310
    }
  },
  "case_studies": [ ... ]
}
```

### Key ecosystem numbers

| Metric | Value |
|---|---|
| Total samples | 1200 |
| Samples with findings | 620 |
| High severity | 310 (25.8%) |
| Low severity | 890 (74.2%) |
| HITL decisions | 310 (25.8%) |
| Allow decisions | 890 (74.2%) |
| Sources | 5 (GitHub MCP, npm, HuggingFace, enterprise catalog, community forum) |

---

## 6. Risk Patterns Summary

**File:** `results/ecosystem/risk_patterns.json`
**Format:** JSON
**Size:** ~1.5 KB
**Produced by:** `make triage` (step: `triage_findings.py`)

A subset of the ecosystem triage output, containing only the aggregated
risk pattern statistics. Same structure as `risk_patterns` in the full
triage file.

---

## 7. Benchmark Data (not committed)

**Path:** `data/benchmark_v0/`
**Produced by:** `make benchmark`

The benchmark is generated at runtime (seed=42) and not committed to
version control. After `make benchmark`:

- 1000 benign samples (paired with malicious counterparts)
- 3010 malicious samples across 7 attack classes
- Each sample is a JSON object with manifest, trace, label, and metadata

After `make validate`, label integrity is confirmed (class balance,
no label leakage between benign/malicious).

---

## 8. Ecosystem Corpus (not committed)

**Path:** `data/ecosystem/`
**Produced by:** `make ecosystem`

1200 synthetic skill samples from 5 source categories, generated at
runtime. Not committed to version control. After `make triage`, the
triage results appear in `results/ecosystem/`.

---

## Reproducibility Guarantees

- **Deterministic:** All random generation uses `seed=42`. Re-running any
  target produces identical output.
- **Idempotent:** Each target overwrites its outputs cleanly. No
  incremental state to corrupt.
- **Independent:** Individual targets can be run in isolation as long as
  their prerequisites are satisfied (e.g., `make tables` requires
  `make eval-main` to have run first).
- **Portable:** No OS-specific behavior. No network access. No external
  dependencies beyond Python 3.10+ and pytest.
