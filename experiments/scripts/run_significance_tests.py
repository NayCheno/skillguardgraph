#!/usr/bin/env python3
"""Compute paired significance comparisons for SkillGuardGraph baselines.

Current focus: fusion vs weighted_voting on the synthetic benchmark.
Outputs a JSON report with:
- confusion matrices
- exact McNemar test on correctness disagreements
- paired bootstrap deltas for precision/recall/F1/FPR
"""
from __future__ import annotations

import json
import math
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_PATH = ROOT / "data" / "benchmark_v0" / "samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "significance_tests.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.baselines import weighted_voting  # noqa: E402
from skillguardgraph.fusion import fuse_from_evidence_list  # noqa: E402
from skillguardgraph.models import Evidence, Severity  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.runtime_monitor import trace_to_evidence  # noqa: E402
from skillguardgraph.simulated_prober import observations_to_evidence, probe_skill  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402


def load_samples(path: Path) -> list[dict]:
    samples = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def collect_evidence(sample: dict) -> list[Evidence]:
    evidence: list[Evidence] = []
    manifest = sample.get("manifest", {})
    source_code = sample.get("source_code", "")
    skill_name = str(manifest.get("name") or sample.get("case_id") or "unknown")
    evidence.extend(analyze_manifest(manifest))
    evidence.extend(analyze_source(skill_name, source_code))
    evidence.extend(observations_to_evidence(probe_skill(skill_name, manifest, source_code)))
    if sample.get("runtime_trace"):
        evidence.extend(trace_to_evidence(sample["runtime_trace"]))
    return evidence


def is_malicious(label: str) -> bool:
    return label != "benign"


def predicted_malicious(report) -> bool:
    return report.risk in (Severity.HIGH, Severity.CRITICAL)


def compute_metrics(truth: list[bool], pred: list[bool]) -> dict:
    tp = fp = tn = fn = 0
    for label, guess in zip(truth, pred):
        if label and guess:
            tp += 1
        elif label:
            fn += 1
        elif guess:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }


def mcnemar_exact(truth: list[bool], a_pred: list[bool], b_pred: list[bool]) -> dict:
    b_only_correct = 0
    a_only_correct = 0
    for label, a_guess, b_guess in zip(truth, a_pred, b_pred):
        a_correct = a_guess == label
        b_correct = b_guess == label
        if a_correct and not b_correct:
            a_only_correct += 1
        elif b_correct and not a_correct:
            b_only_correct += 1

    n = a_only_correct + b_only_correct
    if n == 0:
        p_value = 1.0
    elif min(a_only_correct, b_only_correct) == 0:
        # All discordant pairs favor one method; use log to avoid overflow
        log_p = math.log(2.0) - n * math.log(2.0)
        p_value = max(0.0, min(1.0, math.exp(log_p)))
    else:
        tail = sum(math.comb(n, k) for k in range(0, min(a_only_correct, b_only_correct) + 1))
        p_value = min(1.0, 2.0 * tail / (2 ** n))

    return {
        "fusion_only_correct": a_only_correct,
        "weighted_only_correct": b_only_correct,
        "p_value": round(p_value, 6),
    }


def paired_bootstrap_delta(
    truth: list[bool],
    fusion_pred: list[bool],
    voting_pred: list[bool],
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> dict:
    rng = random.Random(seed)
    n = len(truth)
    metrics = ["precision", "recall", "f1", "fpr"]
    deltas = {metric: [] for metric in metrics}

    for _ in range(n_bootstrap):
        indices = [rng.randint(0, n - 1) for _ in range(n)]
        truth_i = [truth[i] for i in indices]
        fusion_i = [fusion_pred[i] for i in indices]
        voting_i = [voting_pred[i] for i in indices]
        fusion_metrics = compute_metrics(truth_i, fusion_i)
        voting_metrics = compute_metrics(truth_i, voting_i)
        for metric in metrics:
            deltas[metric].append(fusion_metrics[metric] - voting_metrics[metric])

    def percentile(values: list[float], pct: float) -> float:
        values = sorted(values)
        idx = (len(values) - 1) * pct / 100.0
        lo = int(idx)
        hi = min(lo + 1, len(values) - 1)
        return values[lo] + (idx - lo) * (values[hi] - values[lo])

    return {
        metric: {
            "mean_delta": round(sum(vals) / len(vals), 4),
            "ci_low": round(percentile(vals, 2.5), 4),
            "ci_high": round(percentile(vals, 97.5), 4),
        }
        for metric, vals in deltas.items()
    }


def main() -> None:
    samples = load_samples(BENCHMARK_PATH)
    truth: list[bool] = []
    fusion_pred: list[bool] = []
    voting_pred: list[bool] = []

    for sample in samples:
        truth.append(is_malicious(sample["label"]))
        evidence = collect_evidence(sample)
        fusion_pred.append(predicted_malicious(fuse_from_evidence_list(evidence)))
        voting_pred.append(predicted_malicious(weighted_voting(evidence)))

    fusion_metrics = compute_metrics(truth, fusion_pred)
    voting_metrics = compute_metrics(truth, voting_pred)
    output = {
        "benchmark_samples": len(samples),
        "comparison": "fusion_vs_weighted_voting",
        "fusion": fusion_metrics,
        "weighted_voting": voting_metrics,
        "mcnemar_exact": mcnemar_exact(truth, fusion_pred, voting_pred),
        "paired_bootstrap_delta": paired_bootstrap_delta(truth, fusion_pred, voting_pred),
    }

    OUT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(json.dumps(output["mcnemar_exact"], indent=2))


if __name__ == "__main__":
    main()
