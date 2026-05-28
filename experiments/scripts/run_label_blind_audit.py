#!/usr/bin/env python3
"""Verify benchmark_v1 decisions are label-blind."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_PATH = ROOT / "data" / "benchmark_v1" / "samples.jsonl"
RESULT_PATH = ROOT / "results" / "main" / "label_blind_audit.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.evidence_graph import EvidenceGraph  # noqa: E402
from skillguardgraph.fusion import fuse_from_evidence_list  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.models import Evidence  # noqa: E402
from skillguardgraph.policy_engine import evaluate as policy_evaluate  # noqa: E402
from skillguardgraph.runtime_monitor import trace_to_evidence  # noqa: E402
from skillguardgraph.simulated_prober import observations_to_evidence, probe_skill  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402

LABEL_FIELDS = {
    "case_id",
    "label",
    "attack_class",
    "expected_evidence",
    "success_validator",
    "benign_pair",
    "lifecycle_stages",
    "template_id",
    "generator_name",
    "hard_negative_class",
}



def _load_samples() -> list[dict[str, Any]]:
    if not SAMPLES_PATH.exists():
        raise SystemExit(f"Missing benchmark file: {SAMPLES_PATH}. Run build_benchmark_v1.py first.")
    samples: list[dict[str, Any]] = []
    with SAMPLES_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples



def _normalize_trace(trace: dict[str, Any] | None) -> dict[str, Any] | None:
    if not trace:
        return None
    if trace.get("events") and trace.get("flows"):
        return trace
    return trace



def _strip_label_fields(sample: dict[str, Any]) -> dict[str, Any]:
    stripped = copy.deepcopy(sample)
    for field in LABEL_FIELDS:
        stripped.pop(field, None)
    return stripped



def _run_pipeline(sample: dict[str, Any]) -> tuple[list[Evidence], EvidenceGraph, Any, Any]:
    manifest = sample.get("manifest") or {}
    source_code = str(sample.get("source_code") or "")
    skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
    trace = _normalize_trace(sample.get("runtime_trace"))

    evidence: list[Evidence] = []
    evidence.extend(analyze_manifest(manifest))
    evidence.extend(analyze_source(skill_name, source_code))
    evidence.extend(observations_to_evidence(probe_skill(skill_name, manifest, source_code)))
    if trace:
        evidence.extend(trace_to_evidence(trace))

    graph = EvidenceGraph(evidence=evidence)
    policy_report = policy_evaluate(graph)
    fused_report = fuse_from_evidence_list(evidence)
    return evidence, graph, policy_report, fused_report



def main() -> None:
    samples = _load_samples()

    decision_changes = 0
    risk_changes = 0
    score_changes = 0
    evidence_changes = 0
    graph_issue_changes = 0
    changed_cases: list[dict[str, Any]] = []

    for sample in samples:
        unblind_evidence, unblind_graph, unblind_policy, unblind_fused = _run_pipeline(sample)
        blind_sample = _strip_label_fields(sample)
        blind_evidence, blind_graph, blind_policy, blind_fused = _run_pipeline(blind_sample)

        decision_changed = unblind_fused.decision != blind_fused.decision
        risk_changed = unblind_fused.risk != blind_fused.risk
        score_changed = unblind_fused.score != blind_fused.score
        evidence_changed = [item.to_dict() for item in unblind_evidence] != [item.to_dict() for item in blind_evidence]
        graph_changed = unblind_graph.validate_consistency() != blind_graph.validate_consistency()

        decision_changes += int(decision_changed)
        risk_changes += int(risk_changed)
        score_changes += int(score_changed)
        evidence_changes += int(evidence_changed)
        graph_issue_changes += int(graph_changed)

        if decision_changed or risk_changed or score_changed or evidence_changed or graph_changed:
            changed_cases.append(
                {
                    "case_id": sample.get("case_id"),
                    "label": sample.get("label"),
                    "decision_changed": decision_changed,
                    "risk_changed": risk_changed,
                    "score_changed": score_changed,
                    "evidence_changed": evidence_changed,
                    "graph_changed": graph_changed,
                    "unblind": {
                        "decision": unblind_fused.decision.value,
                        "risk": unblind_fused.risk.value,
                        "score": unblind_fused.score,
                        "policy_decision": unblind_policy.decision.value,
                        "finding_constraints": [finding.constraint for finding in unblind_fused.findings],
                    },
                    "blind": {
                        "decision": blind_fused.decision.value,
                        "risk": blind_fused.risk.value,
                        "score": blind_fused.score,
                        "policy_decision": blind_policy.decision.value,
                        "finding_constraints": [finding.constraint for finding in blind_fused.findings],
                    },
                }
            )

    total_samples = len(samples)
    payload = {
        "samples_path": str(SAMPLES_PATH),
        "total_samples": total_samples,
        "decision_changes": decision_changes,
        "decision_change_rate": round(decision_changes / total_samples, 6) if total_samples else 0.0,
        "risk_changes": risk_changes,
        "score_changes": score_changes,
        "evidence_changes": evidence_changes,
        "graph_issue_changes": graph_issue_changes,
        "label_fields_removed": sorted(LABEL_FIELDS),
        "acceptance": {"decision_change_rate_is_zero": decision_changes == 0},
        "changed_cases": changed_cases,
    }

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RESULT_PATH.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

    print(f"Audited {total_samples} samples from {SAMPLES_PATH}")
    print(f"Decision changes: {decision_changes}")
    print(f"Decision change rate: {payload['decision_change_rate']}")
    print(f"Risk changes: {risk_changes}")
    print(f"Score changes: {score_changes}")
    print(f"Evidence changes: {evidence_changes}")
    print(f"Wrote audit report to {RESULT_PATH}")
    print(f"Acceptance decision_change_rate_is_zero: {'PASS' if decision_changes == 0 else 'FAIL'}")

    if decision_changes != 0:
        raise SystemExit("Label-blind audit failed: detection decisions changed after stripping label fields.")


if __name__ == "__main__":
    main()
