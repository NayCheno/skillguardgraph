#!/usr/bin/env python3
"""Evaluate each detector layer and full fusion on the benchmark.

Reads samples.jsonl, runs each baseline detector and the full fusion pipeline,
then computes per-method TP/FP/TN/FN, Precision, Recall, F1, FPR,
and per-attack-class recall for the full fusion.

Output: experiments/results/main/detector_eval.json
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent  # experiments/
DATA_PATH = ROOT / "data" / "benchmark_v0" / "samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "detector_eval.json"

# ---------------------------------------------------------------------------
# Imports from skillguardgraph
# ---------------------------------------------------------------------------
sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.baselines import BASELINES, run_all_baselines  # noqa: E402
from skillguardgraph.fusion import fuse_and_evaluate  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.models import Decision, Evidence, RiskReport, Severity  # noqa: E402
from skillguardgraph.runtime_monitor import trace_to_evidence  # noqa: E402
from skillguardgraph.simulated_prober import probe_skill, observations_to_evidence  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_malicious(label: str) -> bool:
    return label != "benign"


def predicted_malicious(report: RiskReport) -> bool:
    return report.risk in (Severity.HIGH, Severity.CRITICAL)


def load_samples(path: Path) -> list[dict]:
    samples = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def collect_evidence(sample: dict) -> list[Evidence]:
    """Collect all available evidence for a sample."""
    evidence: list[Evidence] = []
    manifest = sample.get("manifest")
    if manifest is not None:
        evidence.extend(analyze_manifest(manifest))
    source_code = sample.get("source_code")
    if source_code is not None:
        skill_name = "unknown_skill"
        if manifest is not None:
            skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
        evidence.extend(analyze_source(skill_name, source_code))
    if manifest is not None:
        observations = probe_skill(
            skill_name=str(manifest.get("name") or "unknown_skill"),
            manifest=manifest,
            source_code=source_code,
        )
        evidence.extend(observations_to_evidence(observations))
    trace = sample.get("runtime_trace")
    if trace is not None:
        evidence.extend(trace_to_evidence(trace))
    return evidence


def safe_div(num: int, den: int) -> float:
    return num / den if den > 0 else 0.0


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall) if (precision + recall) > 0 else 0.0
    fpr = safe_div(fp, fp + tn)
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"Loading samples from {DATA_PATH} ...")
    samples = load_samples(DATA_PATH)
    total = len(samples)
    print(f"  {total} samples loaded.")

    # Pre-collect evidence and pre-compute reports per method
    # Method names: all baselines + "fusion"
    method_names = list(BASELINES.keys()) + ["fusion"]

    # Per-method confusion counts
    confusion: dict[str, dict[str, int]] = {
        m: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for m in method_names
    }

    # Per-attack-class recall for fusion
    attack_classes: set[str] = set()
    fusion_class_tp: dict[str, int] = defaultdict(int)
    fusion_class_fn: dict[str, int] = defaultdict(int)

    # Per-method per-sample decisions (for debugging)
    per_sample: list[dict] = []

    for i, sample in enumerate(samples):
        if (i + 1) % 100 == 0:
            print(f"  Processing sample {i + 1}/{total} ...")

        label = sample.get("label", "benign")
        mal = is_malicious(label)
        attack_class = sample.get("attack_class") or label
        if mal:
            attack_classes.add(attack_class)

        # Collect evidence once
        evidence = collect_evidence(sample)

        sample_result: dict = {"case_id": sample.get("case_id"), "label": label}

        # Run baselines on the shared evidence list
        baseline_reports = run_all_baselines(evidence)

        for bname, breport in baseline_reports.items():
            pred_mal = predicted_malicious(breport)
            if mal and pred_mal:
                confusion[bname]["TP"] += 1
            elif mal and not pred_mal:
                confusion[bname]["FN"] += 1
            elif not mal and pred_mal:
                confusion[bname]["FP"] += 1
            else:
                confusion[bname]["TN"] += 1
            sample_result[bname] = pred_mal

        # Full fusion (uses individual sources, not pre-collected evidence)
        manifest = sample.get("manifest")
        source_code = sample.get("source_code")
        trace = sample.get("runtime_trace")
        skill_name = "unknown_skill"
        if manifest is not None:
            skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
        sandbox_obs = None
        if manifest is not None:
            sandbox_obs = probe_skill(skill_name, manifest, source_code)

        fusion_report = fuse_and_evaluate(
            manifest=manifest or {},
            source_code=source_code or "",
            trace=trace,
            skill_name=skill_name,
        )
        pred_mal = predicted_malicious(fusion_report)
        if mal and pred_mal:
            confusion["fusion"]["TP"] += 1
        elif mal and not pred_mal:
            confusion["fusion"]["FN"] += 1
        elif not mal and pred_mal:
            confusion["fusion"]["FP"] += 1
        else:
            confusion["fusion"]["TN"] += 1
        sample_result["fusion"] = pred_mal

        # Per-attack-class recall for fusion
        if mal:
            if pred_mal:
                fusion_class_tp[attack_class] += 1
            else:
                fusion_class_fn[attack_class] += 1

        per_sample.append(sample_result)

    # Build results
    methods: dict[str, dict] = {}
    for m in method_names:
        c = confusion[m]
        methods[m] = compute_metrics(c["TP"], c["FP"], c["TN"], c["FN"])

    # Per-attack-class recall for fusion
    per_class_recall: dict[str, dict] = {}
    for ac in sorted(attack_classes):
        tp_c = fusion_class_tp[ac]
        fn_c = fusion_class_fn[ac]
        total_c = tp_c + fn_c
        per_class_recall[ac] = {
            "TP": tp_c,
            "FN": fn_c,
            "total": total_c,
            "recall": round(safe_div(tp_c, total_c), 4),
        }

    result = {
        "total_samples": total,
        "methods": methods,
        "per_attack_class_recall": per_class_recall,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(f"\nResults written to {OUT_PATH}")
    print(f"\nTotal samples: {total}")
    print(f"Fusion F1:  {methods['fusion']['f1']}")
    print(f"Naive Union F1: {methods['naive_union']['f1']}")
    print(f"Fusion FPR: {methods['fusion']['fpr']}")
    print(f"Naive Union FPR: {methods['naive_union']['fpr']}")
    fpr_reduction = methods['naive_union']['fpr'] - methods['fusion']['fpr']
    print(f"FPR reduction (naive_union - fusion): {round(fpr_reduction, 4)}")


if __name__ == "__main__":
    main()
