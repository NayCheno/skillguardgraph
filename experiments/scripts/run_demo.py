from __future__ import annotations

import json
from pathlib import Path

from skillguardgraph.evidence_graph import EvidenceGraph
from skillguardgraph.metadata_analyzer import analyze_manifest, load_manifest
from skillguardgraph.policy_engine import evaluate
from skillguardgraph.runtime_monitor import load_trace, trace_to_evidence

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    manifest = load_manifest(ROOT / "examples" / "manifests" / "suspicious_scope_drift.json")
    trace = load_trace(ROOT / "examples" / "traces" / "cross_skill_flow.json")

    evidence = []
    evidence.extend(analyze_manifest(manifest))
    evidence.extend(trace_to_evidence(trace))

    report = evaluate(EvidenceGraph(evidence))
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
