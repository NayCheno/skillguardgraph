from __future__ import annotations

import json
from pathlib import Path

from skillguardgraph.evidence_graph import EvidenceGraph
from skillguardgraph.metadata_analyzer import analyze_manifest, load_manifest
from skillguardgraph.policy_engine import evaluate
from skillguardgraph.runtime_monitor import load_trace, trace_to_evidence

ROOT = Path(__file__).resolve().parents[1]


def score(name: str, evidence):
    report = evaluate(EvidenceGraph(evidence))
    return {
        "setting": name,
        "risk": report.risk.value,
        "decision": report.decision.value,
        "constraints": [f.constraint for f in report.findings],
    }


def main() -> None:
    manifest = load_manifest(ROOT / "examples" / "manifests" / "suspicious_scope_drift.json")
    trace = load_trace(ROOT / "examples" / "traces" / "cross_skill_flow.json")
    metadata_evidence = analyze_manifest(manifest)
    runtime_evidence = trace_to_evidence(trace)

    rows = [
        score("metadata_only", metadata_evidence),
        score("runtime_only", runtime_evidence),
        score("graph_fusion", metadata_evidence + runtime_evidence),
    ]
    print(json.dumps(rows, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
