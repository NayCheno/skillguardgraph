#!/usr/bin/env python3
"""Ablation study: remove one evidence source at a time.

Ablations:
  - full:        all evidence sources (baseline reference)
  - no_metadata: skip manifest evidence
  - no_static:   skip source code evidence
  - no_sandbox:  skip sandbox evidence
  - no_runtime:  skip runtime trace evidence
  - no_sequence: use only C1, C4, C5, C7 constraints (not C2, C3, C6)

Compares each ablation with full fusion.

Output: experiments/results/main/ablation.json
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # experiments/
DATA_PATH = ROOT / "data" / "benchmark_v0" / "samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "ablation.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.evidence_graph import EvidenceGraph  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.models import (  # noqa: E402
    Decision,
    Evidence,
    Finding,
    RiskReport,
    Severity,
)
from skillguardgraph.policy_engine import evaluate as policy_evaluate  # noqa: E402
from skillguardgraph.runtime_monitor import trace_to_evidence  # noqa: E402
from skillguardgraph.sandbox_prober import probe_skill, observations_to_evidence  # noqa: E402
from skillguardgraph.scoring import aggregate_score  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_malicious(label: str) -> bool:
    return label != "benign"


def predicted_malicious(report: RiskReport) -> bool:
    return report.risk in (Severity.HIGH, Severity.CRITICAL)


def safe_div(num: int, den: int) -> float:
    return num / den if den > 0 else 0.0


def load_samples(path: Path) -> list[dict]:
    samples = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


# Constraint IDs used by no_sequence ablation
SEQUENCE_CONSTRAINTS = {"C2", "C3", "C6"}
ALL_CONSTRAINTS = {"C1", "C2", "C3", "C4", "C5", "C6", "C7"}


def _constraint_id(finding: Finding) -> str:
    """Extract C1..C7 identifier from a finding's constraint string."""
    c = finding.constraint.upper()
    for tag in ALL_CONSTRAINTS:
        if tag in c:
            return tag
    return ""


def fuse_with_filter(
    evidence: list[Evidence],
    exclude_constraints: set[str] | None = None,
) -> RiskReport:
    """Fuse evidence with optional constraint filtering, matching fusion.py logic."""
    if not evidence:
        return RiskReport(
            risk=Severity.LOW,
            decision=Decision.ALLOW,
            findings=[],
            score=0.0,
            evidence_path=[],
        )
    graph = EvidenceGraph(evidence=evidence)
    report = policy_evaluate(graph)

    if exclude_constraints:
        report.findings = [
            f for f in report.findings
            if _constraint_id(f) not in exclude_constraints
        ]
        report.score = aggregate_score(report.findings)
        if report.score >= 7.0:
            report.risk = Severity.CRITICAL
            report.decision = Decision.DENY
        elif report.score >= 4.0:
            report.risk = Severity.HIGH
            report.decision = Decision.HITL
        elif report.score >= 1.0:
            report.risk = Severity.MEDIUM
            report.decision = Decision.DEGRADE
        else:
            report.risk = Severity.LOW
            report.decision = Decision.ALLOW

    # If policy already found HIGH/CRITICAL, collect evidence paths
    if report.risk in (Severity.HIGH, Severity.CRITICAL):
        seen: set[int] = set()
        report.evidence_path = []
        for finding in report.findings:
            if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                for ev in finding.evidence:
                    ev_id = id(ev)
                    if ev_id not in seen:
                        seen.add(ev_id)
                        report.evidence_path.append(ev)
        return report

    # Multi-layer agreement fallback
    _SUSPICIOUS = {
        "declares_readonly_with_write_scope", "scope_inflation",
        "hidden_instruction", "has_source_label", "requires_high_risk_scope",
        "source_identified", "sink_identified", "is_external_sink",
        "is_credential_access", "is_pii_access", "sandbox_observed_write",
        "sandbox_observed_network", "sandbox_observed_shell",
        "sandbox_observed_persistence", "flows_to", "persists_to",
        "high_privilege_tool", "external_sink",
    }
    suspicious_kinds: set[str] = set()
    suspicious_evidence: list[Evidence] = []
    for ev in evidence:
        if ev.predicate in _SUSPICIOUS:
            suspicious_kinds.add(ev.kind)
            suspicious_evidence.append(ev)

    if len(suspicious_kinds) >= 2 and suspicious_evidence:
        report.risk = Severity.HIGH
        report.decision = Decision.HITL
        report.score = max(report.score, 6.0)
        report.evidence_path = suspicious_evidence[:20]
        return report

    if suspicious_evidence:
        report.risk = Severity.MEDIUM
        report.decision = Decision.DEGRADE
        report.score = max(report.score, 3.0)
        report.evidence_path = suspicious_evidence[:20]
        return report

    report.evidence_path = []
    return report


# ---------------------------------------------------------------------------
# Ablation definitions
# ---------------------------------------------------------------------------

def run_ablation(
    sample: dict,
    ablation: str,
) -> RiskReport:
    """Run fusion with a specific evidence source removed."""
    manifest = sample.get("manifest")
    source_code = sample.get("source_code")
    trace = sample.get("runtime_trace")

    evidence: list[Evidence] = []

    # Collect evidence based on ablation
    if ablation != "no_metadata" and manifest is not None:
        evidence.extend(analyze_manifest(manifest))

    if ablation != "no_static" and source_code is not None:
        skill_name = "unknown_skill"
        if manifest is not None:
            skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
        evidence.extend(analyze_source(skill_name, source_code))

    if ablation != "no_sandbox" and manifest is not None:
        skill_name = str(manifest.get("name") or "unknown_skill")
        observations = probe_skill(skill_name, manifest, source_code)
        evidence.extend(observations_to_evidence(observations))

    if ablation != "no_runtime" and trace is not None:
        evidence.extend(trace_to_evidence(trace))

    # no_sequence: filter out C2, C3, C6 findings
    exclude = SEQUENCE_CONSTRAINTS if ablation == "no_sequence" else None
    return fuse_with_filter(evidence, exclude_constraints=exclude)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"Loading samples from {DATA_PATH} ...")
    samples = load_samples(DATA_PATH)
    total = len(samples)
    print(f"  {total} samples loaded.")

    ablation_names = ["full", "no_metadata", "no_static", "no_sandbox", "no_runtime", "no_sequence"]

    # Per-ablation confusion counts
    confusion: dict[str, dict[str, int]] = {
        a: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for a in ablation_names
    }

    # Per-ablation per-attack-class recall
    attack_classes: set[str] = set()
    class_tp: dict[str, dict[str, int]] = {a: defaultdict(int) for a in ablation_names}
    class_fn: dict[str, dict[str, int]] = {a: defaultdict(int) for a in ablation_names}

    for i, sample in enumerate(samples):
        if (i + 1) % 100 == 0:
            print(f"  Processing sample {i + 1}/{total} ...")

        label = sample.get("label", "benign")
        mal = is_malicious(label)
        attack_class = sample.get("attack_class") or label
        if mal:
            attack_classes.add(attack_class)

        for ablation in ablation_names:
            report = run_ablation(sample, ablation)
            pred = predicted_malicious(report)

            if mal and pred:
                confusion[ablation]["TP"] += 1
            elif mal and not pred:
                confusion[ablation]["FN"] += 1
            elif not mal and pred:
                confusion[ablation]["FP"] += 1
            else:
                confusion[ablation]["TN"] += 1

            if mal:
                if pred:
                    class_tp[ablation][attack_class] += 1
                else:
                    class_fn[ablation][attack_class] += 1

    # Build results
    def metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
        prec = safe_div(tp, tp + fp)
        rec = safe_div(tp, tp + fn)
        f1 = safe_div(2 * prec * rec, prec + rec) if (prec + rec) > 0 else 0.0
        fpr = safe_div(fp, fp + tn)
        return {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        }

    ablation_results: dict[str, dict] = {}
    for a in ablation_names:
        c = confusion[a]
        m = metrics(c["TP"], c["FP"], c["TN"], c["FN"])
        # Per-attack-class recall
        per_class: dict[str, dict] = {}
        for ac in sorted(attack_classes):
            t = class_tp[a][ac]
            f = class_fn[a][ac]
            total_c = t + f
            per_class[ac] = {
                "TP": t, "FN": f, "total": total_c,
                "recall": round(safe_div(t, total_c), 4),
            }
        ablation_results[a] = {**m, "per_attack_class_recall": per_class}

    result = {
        "total_samples": total,
        "ablations": ablation_results,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(f"\nResults written to {OUT_PATH}")
    print(f"Full fusion F1: {ablation_results['full']['f1']}")
    for a in ablation_names[1:]:
        delta = round(ablation_results[a]["f1"] - ablation_results["full"]["f1"], 4)
        print(f"  {a}: F1={ablation_results[a]['f1']}  (delta={delta:+.4f})")


if __name__ == "__main__":
    main()
