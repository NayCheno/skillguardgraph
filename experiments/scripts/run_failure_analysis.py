#!/usr/bin/env python3
"""Analyze fusion failure cases: false negatives and false positives.

Produces a structured report of WHY fusion misses certain attacks and
WHY it flags benign samples, with evidence paths for each case.

Usage:
    PYTHONPATH=src python scripts/run_failure_analysis.py
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # experiments/
DATA_PATH = ROOT / "data" / "benchmark_v0" / "samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "failure_analysis.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.evidence_graph import EvidenceGraph  # noqa: E402
from skillguardgraph.fusion import fuse_from_evidence_list  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.models import Evidence, Severity  # noqa: E402
from skillguardgraph.runtime_monitor import trace_to_evidence  # noqa: E402
from skillguardgraph.simulated_prober import observations_to_evidence, probe_skill  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402


def load_samples(path: Path) -> list[dict]:
    samples = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def collect_evidence(sample: dict) -> list[Evidence]:
    evidence: list[Evidence] = []
    manifest = sample.get("manifest", {})
    source_code = sample.get("source_code", "")
    skill_name = str(manifest.get("name", sample.get("case_id", "unknown")))
    evidence.extend(analyze_manifest(manifest))
    evidence.extend(analyze_source(skill_name, source_code))
    observations = probe_skill(skill_name, manifest, source_code)
    evidence.extend(observations_to_evidence(observations))
    trace = sample.get("runtime_trace")
    if trace:
        evidence.extend(trace_to_evidence(trace))
    return evidence


def analyze_failure(sample: dict, evidence: list[Evidence], report) -> dict:
    """Analyze why a sample was misclassified."""
    graph = EvidenceGraph(evidence=evidence)

    # Count evidence by kind
    kind_counts = defaultdict(int)
    for ev in evidence:
        kind_counts[ev.kind] += 1

    # Count suspicious predicates
    suspicious_preds = {
        "declares_readonly_with_write_scope", "scope_inflation",
        "hidden_instruction", "requires_high_risk_scope",
        "source_identified", "sink_identified", "is_external_sink",
        "sandbox_observed_write", "sandbox_observed_network",
        "sandbox_observed_shell", "sandbox_observed_persistence",
        "flows_to", "persists_to", "post_approval_drift",
        "high_risk_version_change", "approval_text_lineage",
        "writes_persistent_store", "is_high_privilege_call",
    }
    suspicious_evidence = [ev for ev in evidence if ev.predicate in suspicious_preds]
    suspicious_kinds = {ev.kind for ev in suspicious_evidence}

    # Check which constraints fired
    from skillguardgraph.policy_engine import evaluate as policy_eval
    policy_report = policy_eval(graph)
    fired_constraints = [f.constraint for f in policy_report.findings
                         if f.severity in (Severity.HIGH, Severity.CRITICAL)]

    return {
        "case_id": sample.get("case_id", "unknown"),
        "label": sample.get("label", "unknown"),
        "evidence_by_kind": dict(kind_counts),
        "suspicious_predicates": sorted({ev.predicate for ev in suspicious_evidence}),
        "suspicious_kinds": sorted(suspicious_kinds),
        "fired_constraints": fired_constraints,
        "fusion_score": report.score,
        "fusion_risk": report.risk.value if hasattr(report.risk, 'value') else str(report.risk),
        "graph_nodes": graph.node_count,
        "graph_edges": graph.edge_count,
    }


def main() -> None:
    print(f"Loading samples from {DATA_PATH} ...")
    samples = load_samples(DATA_PATH)
    print(f"Loaded {len(samples)} samples.")

    false_negatives = []
    false_positives = []
    true_positives = 0
    true_negatives = 0

    # Per-class FN breakdown
    class_fn = defaultdict(list)

    for s in samples:
        evidence = collect_evidence(s)
        report = fuse_from_evidence_list(evidence)

        is_malicious = s["label"] != "benign"
        predicted_malicious = report.risk in (Severity.HIGH, Severity.CRITICAL)

        if is_malicious and not predicted_malicious:
            analysis = analyze_failure(s, evidence, report)
            false_negatives.append(analysis)
            class_fn[s["label"]].append(analysis)
        elif not is_malicious and predicted_malicious:
            analysis = analyze_failure(s, evidence, report)
            false_positives.append(analysis)
        elif is_malicious and predicted_malicious:
            true_positives += 1
        else:
            true_negatives += 1

    # Compute evidence path attribution
    # For true positives, check if fusion returns evidence path
    tp_with_path = 0
    tp_total = 0
    for s in samples:
        if s["label"] == "benign":
            continue
        evidence = collect_evidence(s)
        report = fuse_from_evidence_list(evidence)
        if report.risk in (Severity.HIGH, Severity.CRITICAL):
            tp_total += 1
            if report.evidence_path and len(report.evidence_path) > 0:
                tp_with_path += 1

    attribution_rate = tp_with_path / tp_total if tp_total else 0

    # Summarize FN by attack class
    fn_summary = {}
    for cls, cases in class_fn.items():
        # Find common patterns in FN cases
        all_preds = defaultdict(int)
        all_constraints = defaultdict(int)
        for c in cases:
            for p in c["suspicious_predicates"]:
                all_preds[p] += 1
            for f in c["fired_constraints"]:
                all_constraints[f] += 1

        fn_summary[cls] = {
            "count": len(cases),
            "common_suspicious_predicates": dict(sorted(all_preds.items(), key=lambda x: -x[1])[:5]),
            "fired_constraints": dict(all_constraints),
            "mean_score": round(sum(c["fusion_score"] for c in cases) / len(cases), 2) if cases else 0,
        }

    # Summarize FP by pattern
    fp_patterns = defaultdict(int)
    for fp in false_positives:
        for pred in fp["suspicious_predicates"]:
            fp_patterns[pred] += 1

    output = {
        "total_samples": len(samples),
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_negatives_count": len(false_negatives),
        "false_positives_count": len(false_positives),
        "evidence_path_attribution_rate": round(attribution_rate, 4),
        "evidence_path_attribution": f"{tp_with_path}/{tp_total}",
        "fn_by_class": fn_summary,
        "fp_top_patterns": dict(sorted(fp_patterns.items(), key=lambda x: -x[1])[:10]),
        "sample_fn_cases": false_negatives[:20],
        "sample_fp_cases": false_positives[:20],
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults written to {OUT_PATH}")
    print(f"\n{'='*60}")
    print(f"Failure Analysis Summary")
    print(f"{'='*60}")
    print(f"TP={true_positives}  TN={true_negatives}  FN={len(false_negatives)}  FP={len(false_positives)}")
    print(f"Evidence path attribution: {tp_with_path}/{tp_total} = {attribution_rate:.1%}")
    print(f"\nFN by attack class:")
    for cls, summary in sorted(fn_summary.items()):
        print(f"  {cls}: {summary['count']} FN, mean_score={summary['mean_score']}")
    print(f"\nFP top patterns:")
    for pred, count in sorted(fp_patterns.items(), key=lambda x: -x[1])[:5]:
        print(f"  {pred}: {count}")


if __name__ == "__main__":
    main()
