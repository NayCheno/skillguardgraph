#!/usr/bin/env python3
"""Runtime defense evaluation (red-team metrics).

For each malicious sample with a runtime_trace:
  - ASR:  Attack Success Rate (decision == ALLOW for malicious)
  - UTCR: Unauthorized Tool Call Rate
  - EDR:  Exfiltration Data Rate (external_sink reached)
  - BRI:  Blast Radius Index (number of sensitive nodes reachable)
  - PS:   Persistence Score (persistence_pivot blocked)
  - SC:   Stealth Coefficient (attack succeeded without triggering findings)

Also computes:
  - Task Success Rate: benign samples correctly allowed
  - False Block Rate: benign samples incorrectly blocked
  - Approval Burden: average HITL decisions per sample

Output: experiments/results/main/runtime_redteam.json
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # experiments/
DATA_PATH = ROOT / "data" / "benchmark_v0" / "samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "runtime_redteam.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.fusion import fuse_and_evaluate  # noqa: E402
from skillguardgraph.models import Decision  # noqa: E402
from skillguardgraph.sandbox_prober import probe_skill  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_div(num: int | float, den: int | float) -> float:
    return num / den if den > 0 else 0.0


def load_samples(path: Path) -> list[dict]:
    samples = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def is_malicious(label: str) -> bool:
    return label != "benign"


# ---------------------------------------------------------------------------
# Runtime trace analysis helpers
# ---------------------------------------------------------------------------

def _events_by_type(trace: dict, event_type: str) -> list[dict]:
    return [e for e in trace.get("events", []) if e.get("type") == event_type]


def _has_external_sink(trace: dict) -> bool:
    for e in _events_by_type(trace, "sink"):
        if e.get("external") is True:
            return True
    return False


def _count_unauthorized_tools(trace: dict) -> int:
    """Count tool calls that would be unauthorized (high-privilege from untrusted)."""
    events = {str(e.get("id")): e for e in trace.get("events", [])}
    untrusted_sources = {eid for eid, e in events.items() if e.get("type") == "source" and e.get("label") == "untrusted"}
    high_priv_calls = {eid for eid, e in events.items() if e.get("type") == "tool_call" and e.get("privilege") == "high"}

    # Build reachable set from untrusted sources via flows
    flows = trace.get("flows", [])
    reachable: set[str] = set()
    frontier = set(untrusted_sources)
    while frontier:
        frontier_next: set[str] = set()
        for flow in flows:
            if flow.get("from") in frontier:
                frontier_next.add(flow.get("to"))
        frontier_next -= reachable
        reachable |= frontier_next
        frontier = frontier_next

    return len(high_priv_calls & reachable)


def _count_sensitive_nodes(trace: dict) -> int:
    """Count nodes with sensitivity labels (blast radius proxy)."""
    count = 0
    for e in trace.get("events", []):
        if e.get("type") == "data" and e.get("sensitivity") in ("confidential", "secret", "sensitive"):
            count += 1
        if e.get("type") == "tool_call" and e.get("privilege") == "high":
            count += 1
        if e.get("type") == "sink" and e.get("external") is True:
            count += 1
    return count


def _has_persistence_write(trace: dict) -> bool:
    return len(_events_by_type(trace, "persistence_write")) > 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"Loading samples from {DATA_PATH} ...")
    samples = load_samples(DATA_PATH)
    total = len(samples)
    print(f"  {total} samples loaded.")

    # Separate malicious-with-trace and benign
    malicious_with_trace: list[dict] = []
    benign_samples: list[dict] = []

    for sample in samples:
        if is_malicious(sample.get("label", "benign")):
            if sample.get("runtime_trace") is not None:
                malicious_with_trace.append(sample)
        else:
            benign_samples.append(sample)

    print(f"  Malicious with trace: {len(malicious_with_trace)}")
    print(f"  Benign samples: {len(benign_samples)}")

    # --- Malicious runtime metrics ---
    asr_count = 0          # attacks that would succeed (ALLOW)
    utcr_total = 0         # unauthorized tool calls
    utcr_blocked = 0       # unauthorized tool calls that were blocked
    edr_count = 0          # external sink reached
    edr_blocked = 0        # external sink blocked
    bri_total = 0          # blast radius sum
    ps_total = 0           # persistence attempts
    ps_blocked = 0         # persistence attempts blocked
    sc_count = 0           # stealth: succeeded + no findings

    per_class: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "blocked": 0, "asr": 0,
        "utcr_total": 0, "utcr_blocked": 0,
        "edr_total": 0, "edr_blocked": 0,
    })

    for sample in malicious_with_trace:
        label = sample.get("label", "malicious")
        attack_class = sample.get("attack_class") or label
        trace = sample["runtime_trace"]
        manifest = sample.get("manifest")
        source_code = sample.get("source_code")

        skill_name = "unknown_skill"
        if manifest is not None:
            skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
        sandbox_obs = None
        if manifest is not None:
            sandbox_obs = probe_skill(skill_name, manifest, source_code)

        report = fuse_and_evaluate(
            manifest=manifest or {},
            source_code=source_code or "",
            trace=trace,
            skill_name=skill_name,
        )

        allowed = report.decision == Decision.ALLOW
        has_findings = len(report.findings) > 0

        per_class[attack_class]["total"] += 1

        # ASR
        if allowed:
            asr_count += 1
            per_class[attack_class]["asr"] += 1
        else:
            per_class[attack_class]["blocked"] += 1

        # UTCR
        utc = _count_unauthorized_tools(trace)
        utcr_total += utc
        per_class[attack_class]["utcr_total"] += utc
        if not allowed and utc > 0:
            utcr_blocked += utc
            per_class[attack_class]["utcr_blocked"] += utc

        # EDR
        if _has_external_sink(trace):
            edr_count += 1
            per_class[attack_class]["edr_total"] += 1
            if not allowed:
                edr_blocked += 1
                per_class[attack_class]["edr_blocked"] += 1

        # BRI
        bri_total += _count_sensitive_nodes(trace)

        # PS
        if _has_persistence_write(trace):
            ps_total += 1
            if not allowed:
                ps_blocked += 1

        # SC
        if allowed and not has_findings:
            sc_count += 1

    n_mal = len(malicious_with_trace)

    # --- Benign metrics ---
    task_success = 0
    false_block = 0
    hitl_decisions = 0

    for sample in benign_samples:
        manifest = sample.get("manifest")
        source_code = sample.get("source_code")
        skill_name = "unknown_skill"
        if manifest is not None:
            skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
        sandbox_obs = None
        if manifest is not None:
            sandbox_obs = probe_skill(skill_name, manifest, source_code)

        report = fuse_and_evaluate(
            manifest=manifest or {},
            source_code=source_code or "",
            trace=None,
            skill_name=skill_name,
        )

        if report.decision == Decision.ALLOW:
            task_success += 1
        elif report.decision in (Decision.DENY, Decision.ROLLBACK):
            false_block += 1
        if report.decision == Decision.HITL:
            hitl_decisions += 1

    n_benign = len(benign_samples)

    # Per-class metrics
    per_class_result: dict[str, dict] = {}
    for ac in sorted(per_class.keys()):
        pc = per_class[ac]
        ac_total = pc["total"]
        per_class_result[ac] = {
            "total": ac_total,
            "blocked": pc["blocked"],
            "asr": round(safe_div(pc["asr"], ac_total), 4),
            "utcr": round(safe_div(pc["utcr_total"], pc["utcr_total"]), 4) if pc["utcr_total"] > 0 else 0.0,
            "utcr_blocked_rate": round(safe_div(pc["utcr_blocked"], pc["utcr_total"]), 4) if pc["utcr_total"] > 0 else 0.0,
            "edr_total": pc["edr_total"],
            "edr_blocked": pc["edr_blocked"],
            "edr_blocked_rate": round(safe_div(pc["edr_blocked"], pc["edr_total"]), 4) if pc["edr_total"] > 0 else 0.0,
        }

    result = {
        "malicious_with_trace": n_mal,
        "benign_total": n_benign,
        "runtime_defense": {
            "ASR": round(safe_div(asr_count, n_mal), 4),
            "ASR_blocked": round(safe_div(n_mal - asr_count, n_mal), 4),
            "UTCR": round(safe_div(utcr_total, n_mal), 4) if n_mal > 0 else 0.0,
            "UTCR_blocked_rate": round(safe_div(utcr_blocked, utcr_total), 4) if utcr_total > 0 else 0.0,
            "EDR": round(safe_div(edr_count, n_mal), 4) if n_mal > 0 else 0.0,
            "EDR_blocked_rate": round(safe_div(edr_blocked, edr_count), 4) if edr_count > 0 else 0.0,
            "BRI": round(safe_div(bri_total, n_mal), 4) if n_mal > 0 else 0.0,
            "PS_blocked_rate": round(safe_div(ps_blocked, ps_total), 4) if ps_total > 0 else 0.0,
            "PS_attempts": ps_total,
            "PS_blocked": ps_blocked,
            "SC": round(safe_div(sc_count, n_mal), 4),
            "SC_count": sc_count,
        },
        "usability": {
            "task_success_rate": round(safe_div(task_success, n_benign), 4) if n_benign > 0 else 0.0,
            "false_block_rate": round(safe_div(false_block, n_benign), 4) if n_benign > 0 else 0.0,
            "approval_burden": round(safe_div(hitl_decisions, n_benign), 4) if n_benign > 0 else 0.0,
            "task_success_count": task_success,
            "false_block_count": false_block,
            "hitl_count": hitl_decisions,
        },
        "per_attack_class": per_class_result,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(f"\nResults written to {OUT_PATH}")
    rt = result["runtime_defense"]
    us = result["usability"]
    print(f"\nRuntime Defense:")
    print(f"  ASR:       {rt['ASR']}")
    print(f"  BRI:       {rt['BRI']}")
    print(f"  SC:        {rt['SC']}")
    print(f"  PS blocked: {rt['PS_blocked']}/{rt['PS_attempts']}")
    print(f"\nUsability:")
    print(f"  Task Success Rate:  {us['task_success_rate']}")
    print(f"  False Block Rate:   {us['false_block_rate']}")
    print(f"  Approval Burden:    {us['approval_burden']}")


if __name__ == "__main__":
    main()
