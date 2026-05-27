# SkillGuardGraph Prototype Skeleton

This is a defensive research prototype scaffold for the paper idea:

> Cross-layer evidence fusion for detecting and containing malicious skills in LLM agent ecosystems.

The code is intentionally non-operational with respect to real exploit payloads. It provides a safe skeleton for manifest scanning, trace normalization, graph construction, and policy evaluation.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m skillguardgraph.cli scan-manifest examples/manifests/suspicious_scope_drift.json
python -m skillguardgraph.cli eval-trace examples/traces/cross_skill_flow.json
python -m pytest -q
```

## Modules

| Module | Purpose |
|---|---|
| `models.py` | Dataclasses for evidence, findings, policy decisions |
| `metadata_analyzer.py` | Safe manifest/schema/scope analyzer |
| `runtime_monitor.py` | Converts runtime traces into evidence |
| `evidence_graph.py` | Lightweight typed evidence graph |
| `policy_engine.py` | Cross-layer constraint evaluation |
| `sandbox_prober.py` | Placeholder for isolated probing results |
| `scoring.py` | Risk and confidence scoring helpers |
| `cli.py` | CLI entry points |

## Design constraints

- No real external network calls.
- No real credential handling.
- No exploit payload generation.
- All examples use synthetic data and sinkhole labels.

## Example output

```json
{
  "risk": "high",
  "decision": "hitl_or_deny",
  "findings": [
    {
      "constraint": "C1_DECLARED_READONLY_BUT_WRITE_SCOPE",
      "severity": "high",
      "summary": "Skill declares read-only behavior but requests write/export scope."
    }
  ]
}
```



## Makefile commands

```bash
make demo
make test
make scan
make trace
make ablation
```
