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
from skillguardgraph.simulated_prober import probe_skill, observations_to_evidence  # noqa: E402
from skillguardgraph.fusion import fuse_from_evidence_list  # noqa: E402
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
    """Fuse evidence with optional constraint filtering.

    Uses the new hybrid fusion logic from fusion.py for the full config.
    For ablated configs, re-evaluates constraints with exclusions applied.
    """
    from skillguardgraph.fusion import (
        _CONSTRAINT_WEIGHTS,
        _CROSS_LAYER_BONUS,
        _PREDICATE_WEIGHTS,
    )

    if not evidence:
        return RiskReport(
            risk=Severity.LOW, decision=Decision.ALLOW,
            findings=[], score=0.0, evidence_path=[],
        )

    graph = EvidenceGraph(evidence=evidence)
    report = policy_evaluate(graph)

    # Filter constraints for ablation
    if exclude_constraints:
        report.findings = [
            f for f in report.findings
            if _constraint_id(f) not in exclude_constraints
        ]

    # Constraint score (respecting exclusions)
    constraint_score = 0.0
    high_findings = []
    for finding in report.findings:
        w = _CONSTRAINT_WEIGHTS.get(finding.constraint, 2.0)
        if finding.severity == Severity.CRITICAL:
            constraint_score += w * 1.5
        elif finding.severity == Severity.HIGH:
            constraint_score += w
        elif finding.severity == Severity.MEDIUM:
            constraint_score += w * 0.5
        if finding.severity in (Severity.HIGH, Severity.CRITICAL):
            high_findings.append(finding)

    # Signal score (deduplicated)
    predicate_max: dict[str, float] = {}
    evidence_kinds: set[str] = set()
    seen_ps: set[tuple] = set()
    strong_signals = []
    for ev in evidence:
        w = _PREDICATE_WEIGHTS.get(ev.predicate, 0.0)
        if w > 0:
            key = (ev.predicate, ev.subject)
            if key not in seen_ps:
                seen_ps.add(key)
                c = w * ev.confidence
                predicate_max[ev.predicate] = max(predicate_max.get(ev.predicate, 0.0), c)
                evidence_kinds.add(ev.kind)
                if w >= 2.0:
                    strong_signals.append(ev)
    signal_score = min(sum(predicate_max.values()), 8.0)

    # Cross-layer bonus
    cross_layer_bonus = 0.0
    if len(evidence_kinds) >= 3:
        cross_layer_bonus = _CROSS_LAYER_BONUS
    elif len(evidence_kinds) >= 2:
        cross_layer_bonus = _CROSS_LAYER_BONUS * 0.5

    # Cross-layer consistency bonuses mirror the production fusion scorer.
    consistency_bonus = 0.0

    has_runtime_write = any(
        ev.predicate in (
            "is_external_sink", "flows_to", "sandbox_observed_write",
            "sandbox_observed_network", "sink_identified",
            "writes_persistent_store", "persists_to",
        )
        for ev in evidence
    )
    has_untrusted = any(
        ev.predicate == "has_source_label" and ev.object in (
            "untrusted", "external_web", "external_email", "external_api_response",
            "synthetic_web_page", "synthetic_email", "synthetic_chat", "external",
        ) for ev in evidence
    )
    has_high_priv = any(ev.predicate == "is_high_privilege_call" for ev in evidence)
    has_version_drift = any(
        ev.predicate in ("post_approval_drift", "high_risk_version_change")
        for ev in evidence
    )
    has_tainted_approval = any(
        ev.predicate == "approval_text_lineage" and ev.object == "untrusted_context_only"
        for ev in evidence
    )
    has_explicit_readonly_claim = any(
        ev.predicate == "declares_readonly_with_write_scope" for ev in evidence
    )
    has_external_network = any(
        ev.predicate in ("is_external_sink", "sandbox_observed_network")
        for ev in evidence
    )

    if exclude_constraints is None or "C1" not in exclude_constraints:
        if has_explicit_readonly_claim and has_external_network:
            consistency_bonus += 2.5
    if exclude_constraints is None or "C2" not in exclude_constraints:
        if has_untrusted and has_high_priv:
            consistency_bonus += 3.0
    if exclude_constraints is None or "C4" not in exclude_constraints:
        if has_version_drift and has_runtime_write:
            consistency_bonus += 2.5
    if exclude_constraints is None or "C5" not in exclude_constraints:
        if has_tainted_approval and has_runtime_write:
            consistency_bonus += 2.0
    # Hybrid scoring
    wv_path = signal_score + cross_layer_bonus
    constraint_path = constraint_score + consistency_bonus
    total_score = max(wv_path, constraint_path)

    # Decision
    if total_score >= 9.0:
        risk, decision = Severity.CRITICAL, Decision.DENY
    elif total_score >= 4.5:
        risk, decision = Severity.HIGH, Decision.HITL
    elif total_score >= 3.0:
        risk, decision = Severity.MEDIUM, Decision.DEGRADE
    else:
        risk, decision = Severity.LOW, Decision.ALLOW

    # Evidence path
    evidence_path = []
    seen_ids = set()
    for f in high_findings:
        for ev in f.evidence:
            if id(ev) not in seen_ids:
                seen_ids.add(id(ev))
                evidence_path.append(ev)
    for ev in strong_signals:
        if id(ev) not in seen_ids:
            seen_ids.add(id(ev))
            evidence_path.append(ev)

    return RiskReport(
        risk=risk, decision=decision,
        findings=report.findings,
        score=round(total_score, 2),
        evidence_path=evidence_path[:30],
    )

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

    if ablation == "full":
        return fuse_from_evidence_list(evidence)

    # no_sequence: filter out C2, C3, C6 findings and consistency bonuses.
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
