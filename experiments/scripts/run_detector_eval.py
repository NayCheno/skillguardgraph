#!/usr/bin/env python3
"""Evaluate each detector layer and full fusion on the benchmark.

Reads samples.jsonl, runs each baseline detector and the full fusion pipeline,
then computes per-method TP/FP/TN/FN, Precision, Recall, F1, FPR,
AUROC/AUPRC, FPR at target recalls, and per-attack-class recall for the full fusion.

Output: experiments/results/main/detector_eval*.json (varies by --benchmark)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent  # experiments/
DATA_PATHS = {
    "v0": ROOT / "data" / "benchmark_v0" / "samples.jsonl",
    "v1": ROOT / "data" / "benchmark_v1" / "samples.jsonl",
}
OUT_PATHS = {
    "v0": ROOT / "results" / "main" / "detector_eval.json",
    "v1": ROOT / "results" / "main" / "detector_eval_v1.json",
    "both": ROOT / "results" / "main" / "detector_eval_both.json",
}

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


def _trapezoid_area(points: list[tuple[float, float]]) -> float:
    area = 0.0
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        area += (x1 - x0) * (y0 + y1) / 2.0
    return area


def compute_score_metrics(labels: list[bool], scores: list[float]) -> dict:
    """Compute threshold-independent detector metrics from continuous scores."""
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return {
            "auroc": 0.0,
            "auprc": 0.0,
            "fpr_at_recall": {},
            "threshold_sweep": [],
        }

    thresholds = sorted(set(scores), reverse=True)
    roc_points: list[tuple[float, float]] = [(0.0, 0.0)]
    pr_points: list[tuple[float, float]] = [(0.0, 1.0)]
    sweep: list[dict] = []

    for threshold in thresholds:
        tp = fp = tn = fn = 0
        for label, score in zip(labels, scores):
            pred = score >= threshold
            if label and pred:
                tp += 1
            elif label:
                fn += 1
            elif pred:
                fp += 1
            else:
                tn += 1

        metrics = compute_metrics(tp, fp, tn, fn)
        roc_points.append((metrics["fpr"], metrics["recall"]))
        pr_points.append((metrics["recall"], metrics["precision"] if tp + fp else 1.0))
        sweep.append({
            "threshold": round(threshold, 4),
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "fpr": metrics["fpr"],
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
        })

    roc_points.append((1.0, 1.0))
    roc_points = sorted(set(roc_points))
    pr_points = sorted(pr_points)

    fpr_at_recall: dict[str, float | None] = {}
    for target in (0.85, 0.90, 0.95):
        candidates = [row["fpr"] for row in sweep if row["recall"] >= target]
        fpr_at_recall[f"{int(target * 100)}"] = round(min(candidates), 4) if candidates else None

    return {
        "auroc": round(_trapezoid_area(roc_points), 4),
        "auprc": round(_trapezoid_area(pr_points), 4),
        "fpr_at_recall": fpr_at_recall,
        "threshold_sweep": sweep,
    }



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark",
        choices=("v0", "v1", "both"),
        default="v0",
        help="Benchmark split to evaluate.",
    )
    return parser.parse_args()


def evaluate_benchmark(benchmark_name: str, data_path: Path) -> dict:
    print(f"Loading {benchmark_name} samples from {data_path} ...")
    samples = load_samples(data_path)
    total = len(samples)
    print(f"  {total} samples loaded.")

    # Pre-collect evidence and pre-compute reports per method
    method_names = list(BASELINES.keys()) + ["fusion"]

    score_labels: list[bool] = []
    method_scores: dict[str, list[float]] = {m: [] for m in method_names}
    confusion: dict[str, dict[str, int]] = {
        m: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for m in method_names
    }

    attack_classes: set[str] = set()
    fusion_class_tp: dict[str, int] = defaultdict(int)
    fusion_class_fn: dict[str, int] = defaultdict(int)

    for i, sample in enumerate(samples):
        if (i + 1) % 100 == 0:
            print(f"  [{benchmark_name}] Processing sample {i + 1}/{total} ...")

        label = sample.get("label", "benign")
        mal = is_malicious(label)
        attack_class = sample.get("attack_class") or label
        if mal:
            attack_classes.add(attack_class)

        evidence = collect_evidence(sample)

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
            method_scores[bname].append(float(breport.score))

        manifest = sample.get("manifest")
        source_code = sample.get("source_code")
        trace = sample.get("runtime_trace")
        skill_name = "unknown_skill"
        if manifest is not None:
            skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")

        fusion_report = fuse_and_evaluate(
            manifest=manifest or {},
            source_code=source_code or "",
            trace=trace,
            skill_name=skill_name,
        )
        pred_mal = predicted_malicious(fusion_report)
        method_scores["fusion"].append(float(fusion_report.score))
        if mal and pred_mal:
            confusion["fusion"]["TP"] += 1
        elif mal and not pred_mal:
            confusion["fusion"]["FN"] += 1
        elif not mal and pred_mal:
            confusion["fusion"]["FP"] += 1
        else:
            confusion["fusion"]["TN"] += 1

        score_labels.append(mal)
        if mal:
            if pred_mal:
                fusion_class_tp[attack_class] += 1
            else:
                fusion_class_fn[attack_class] += 1


    methods: dict[str, dict] = {}
    for method_name in method_names:
        counts = confusion[method_name]
        methods[method_name] = compute_metrics(counts["TP"], counts["FP"], counts["TN"], counts["FN"])

    per_class_recall: dict[str, dict] = {}
    for attack_class in sorted(attack_classes):
        tp_c = fusion_class_tp[attack_class]
        fn_c = fusion_class_fn[attack_class]
        total_c = tp_c + fn_c
        per_class_recall[attack_class] = {
            "TP": tp_c,
            "FN": fn_c,
            "total": total_c,
            "recall": round(safe_div(tp_c, total_c), 4),
        }

    result = {
        "benchmark": benchmark_name,
        "data_path": str(data_path.relative_to(ROOT)),
        "total_samples": total,
        "methods": methods,
        "score_metrics": {
            method_name: compute_score_metrics(score_labels, method_scores[method_name])
            for method_name in method_names
        },
        "per_attack_class_recall": per_class_recall,
    }

    print(f"\n[{benchmark_name}] Total samples: {total}")
    print(f"[{benchmark_name}] Fusion F1:  {methods['fusion']['f1']}")
    print(f"[{benchmark_name}] Naive Union F1: {methods['naive_union']['f1']}")
    print(f"[{benchmark_name}] Fusion FPR: {methods['fusion']['fpr']}")
    print(f"[{benchmark_name}] Naive Union FPR: {methods['naive_union']['fpr']}")
    fpr_reduction = methods['naive_union']['fpr'] - methods['fusion']['fpr']
    print(f"[{benchmark_name}] FPR reduction (naive_union - fusion): {round(fpr_reduction, 4)}")
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    benchmark_names = ["v0", "v1"] if args.benchmark == "both" else [args.benchmark]

    if args.benchmark == "both":
        result = {
            "benchmarks": {
                benchmark_name: evaluate_benchmark(benchmark_name, DATA_PATHS[benchmark_name])
                for benchmark_name in benchmark_names
            }
        }
    else:
        benchmark_name = benchmark_names[0]
        result = evaluate_benchmark(benchmark_name, DATA_PATHS[benchmark_name])

    out_path = OUT_PATHS[args.benchmark]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(f"\nResults written to {out_path}")


if __name__ == "__main__":
    main()
