from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from .evidence_graph import EvidenceGraph
from .metadata_analyzer import analyze_manifest, load_manifest
from .policy_engine import evaluate
from .runtime_monitor import load_trace, trace_to_evidence


def _print_report(evidence, pretty: bool = True) -> None:
    graph = EvidenceGraph(evidence)
    report = evaluate(graph)
    payload = {
        "evidence_count": len(graph.evidence),
        "report": report.to_dict(),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None))


def cmd_scan_manifest(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.path)
    evidence = analyze_manifest(manifest)
    _print_report(evidence, pretty=not args.compact)


def cmd_eval_trace(args: argparse.Namespace) -> None:
    trace = load_trace(args.path)
    evidence = trace_to_evidence(trace)
    _print_report(evidence, pretty=not args.compact)


def cmd_eval_combined(args: argparse.Namespace) -> None:
    evidence = []
    for manifest_path in args.manifest:
        evidence.extend(analyze_manifest(load_manifest(manifest_path)))
    for trace_path in args.trace:
        evidence.extend(trace_to_evidence(load_trace(trace_path)))
    _print_report(evidence, pretty=not args.compact)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SkillGuardGraph research prototype CLI")
    sub = parser.add_subparsers(required=True)

    p_manifest = sub.add_parser("scan-manifest", help="Analyze a skill manifest")
    p_manifest.add_argument("path", type=Path)
    p_manifest.add_argument("--compact", action="store_true")
    p_manifest.set_defaults(func=cmd_scan_manifest)

    p_trace = sub.add_parser("eval-trace", help="Evaluate a synthetic runtime trace")
    p_trace.add_argument("path", type=Path)
    p_trace.add_argument("--compact", action="store_true")
    p_trace.set_defaults(func=cmd_eval_trace)

    p_combined = sub.add_parser("eval-combined", help="Evaluate manifests and traces together")
    p_combined.add_argument("--manifest", type=Path, action="append", default=[])
    p_combined.add_argument("--trace", type=Path, action="append", default=[])
    p_combined.add_argument("--compact", action="store_true")
    p_combined.set_defaults(func=cmd_eval_combined)

    return parser


def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
