#!/usr/bin/env python3
"""Compute bootstrap 95% confidence intervals for all detection metrics.

Reads detector_eval.json and ablation.json, computes bootstrap CIs
for Precision, Recall, F1, and FPR using 1,000 replicates.

Usage:
    PYTHONPATH=src python scripts/run_bootstrap_ci.py
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # experiments/
DETECTOR_EVAL_PATH = ROOT / "results" / "main" / "detector_eval.json"
ABLATION_PATH = ROOT / "results" / "main" / "ablation.json"
BENCHMARK_PATH = ROOT / "data" / "benchmark_v0" / "samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "bootstrap_ci.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.baselines import BASELINES  # noqa: E402
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
    skill_name = str(manifest.get("name", manifest.get("case_id", "unknown")))
    evidence.extend(analyze_manifest(manifest))
    evidence.extend(analyze_source(skill_name, source_code))
    observations = probe_skill(skill_name, manifest, source_code)
    evidence.extend(observations_to_evidence(observations))
    trace = sample.get("runtime_trace")
    if trace:
        evidence.extend(trace_to_evidence(trace))
    return evidence


def is_malicious(label: str) -> bool:
    return label != "benign"


def predicted_malicious_fusion(evidence: list[Evidence]) -> bool:
    report = fuse_from_evidence_list(evidence)
    return report.risk in (Severity.HIGH, Severity.CRITICAL)


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def bootstrap_ci(
    samples: list[dict],
    evidence_cache: list[list[Evidence]],
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> dict:
    """Compute bootstrap 95% CIs for fusion metrics."""
    rng = random.Random(seed)
    n = len(samples)

    # Pre-compute predictions for all samples
    predictions = [predicted_malicious_fusion(ev) for ev in evidence_cache]
    labels = [is_malicious(s["label"]) for s in samples]

    # Bootstrap replicates
    replicate_metrics: list[dict] = []
    for _ in range(n_bootstrap):
        # Sample with replacement
        indices = [rng.randint(0, n - 1) for _ in range(n)]
        tp = fp = tn = fn = 0
        for i in indices:
            if labels[i] and predictions[i]:
                tp += 1
            elif not labels[i] and predictions[i]:
                fp += 1
            elif not labels[i] and not predictions[i]:
                tn += 1
            else:
                fn += 1
        replicate_metrics.append(compute_metrics(tp, fp, tn, fn))

    # Compute percentiles
    def percentile(data: list[float], p: float) -> float:
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * p / 100.0
        f = int(k)
        c = min(f + 1, len(sorted_data) - 1)
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])

    result = {}
    for metric in ["precision", "recall", "f1", "fpr"]:
        values = [r[metric] for r in replicate_metrics]
        result[metric] = {
            "mean": round(sum(values) / len(values), 4),
            "ci_low": round(percentile(values, 2.5), 4),
            "ci_high": round(percentile(values, 97.5), 4),
        }

    return result


def main() -> None:
    if not BENCHMARK_PATH.exists():
        print("ERROR: Benchmark not found. Run 'make benchmark' first.")
        sys.exit(1)

    print("Loading samples ...")
    samples = load_samples(BENCHMARK_PATH)
    print(f"Loaded {len(samples)} samples.")

    print("Collecting evidence (cached) ...")
    evidence_cache = [collect_evidence(s) for s in samples]

    print("Computing bootstrap CIs (1000 replicates) ...")
    fusion_ci = bootstrap_ci(samples, evidence_cache)

    output = {
        "n_samples": len(samples),
        "n_bootstrap": 1000,
        "seed": 42,
        "fusion_ci": fusion_ci,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults written to {OUT_PATH}")
    print(f"\nFusion 95% Bootstrap Confidence Intervals:")
    for metric, vals in fusion_ci.items():
        print(f"  {metric:10s}: {vals['mean']:.4f} [{vals['ci_low']:.4f}, {vals['ci_high']:.4f}]")


if __name__ == "__main__":
    main()
