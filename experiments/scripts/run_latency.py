#!/usr/bin/env python3
"""Measure per-sample inference latency of SkillGuardGraph fusion pipeline.

Reports p50, p95, p99, max, and mean latency in milliseconds.
Also reports per-module breakdown (metadata, static, sandbox, runtime, fusion).

Usage:
    PYTHONPATH=src python scripts/run_latency.py
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # experiments/
DATA_PATH = ROOT / "data" / "benchmark_v0" / "samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "latency.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.evidence_graph import EvidenceGraph  # noqa: E402
from skillguardgraph.fusion import fuse_from_evidence_list  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.models import Evidence  # noqa: E402
from skillguardgraph.runtime_monitor import trace_to_evidence  # noqa: E402
from skillguardgraph.simulated_prober import probe_skill, observations_to_evidence  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402


def load_samples(path: Path, limit: int = 500) -> list[dict]:
    """Load a subset of samples for latency measurement."""
    samples = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def measure_latency(samples: list[dict]) -> dict:
    """Measure per-sample and per-module latency."""
    total_latencies: list[float] = []
    metadata_latencies: list[float] = []
    static_latencies: list[float] = []
    sandbox_latencies: list[float] = []
    runtime_latencies: list[float] = []
    fusion_latencies: list[float] = []

    for sample in samples:
        manifest = sample.get("manifest", {})
        source_code = sample.get("source_code", "")
        trace = sample.get("runtime_trace", {})

        evidence: list[Evidence] = []

        # Metadata analyzer
        t0 = time.perf_counter()
        evidence.extend(analyze_manifest(manifest))
        metadata_latencies.append((time.perf_counter() - t0) * 1000)

        # Static analyzer

        sid = sample.get("case_id", "unknown")
        t0 = time.perf_counter()
        evidence.extend(analyze_source(sid, source_code))
        static_latencies.append((time.perf_counter() - t0) * 1000)

        # Sandbox prober
        t0 = time.perf_counter()
        observations = probe_skill(sid, manifest, source_code)
        evidence.extend(observations_to_evidence(observations))
        sandbox_latencies.append((time.perf_counter() - t0) * 1000)

        # Runtime monitor
        t0 = time.perf_counter()
        evidence.extend(trace_to_evidence(trace))
        runtime_latencies.append((time.perf_counter() - t0) * 1000)

        # Fusion (includes graph construction + policy evaluation)
        t0 = time.perf_counter()
        fuse_from_evidence_list(evidence)
        fusion_latencies.append((time.perf_counter() - t0) * 1000)

        total_latencies.append(
            metadata_latencies[-1]
            + static_latencies[-1]
            + sandbox_latencies[-1]
            + runtime_latencies[-1]
            + fusion_latencies[-1]
        )

    def percentile(data: list[float], p: float) -> float:
        if not data:
            return 0.0
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * p / 100.0
        f = int(k)
        c = f + 1
        if c >= len(sorted_data):
            return sorted_data[-1]
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])

    def summarize(data: list[float]) -> dict:
        if not data:
            return {"mean": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0}
        return {
            "mean": round(statistics.mean(data), 3),
            "p50": round(percentile(data, 50), 3),
            "p95": round(percentile(data, 95), 3),
            "p99": round(percentile(data, 99), 3),
            "max": round(max(data), 3),
        }

    return {
        "n_samples": len(samples),
        "total_ms": summarize(total_latencies),
        "per_module": {
            "metadata_ms": summarize(metadata_latencies),
            "static_ms": summarize(static_latencies),
            "sandbox_ms": summarize(sandbox_latencies),
            "runtime_ms": summarize(runtime_latencies),
            "fusion_ms": summarize(fusion_latencies),
        },
    }


def main() -> None:
    if not DATA_PATH.exists():
        print(f"ERROR: Benchmark data not found at {DATA_PATH}")
        print("Run 'make benchmark' first.")
        sys.exit(1)

    print(f"Loading samples from {DATA_PATH} ...")
    samples = load_samples(DATA_PATH, limit=500)
    print(f"Loaded {len(samples)} samples for latency measurement.")

    print("Measuring latency ...")
    results = measure_latency(samples)

    # Write results
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Results written to {OUT_PATH}")

    # Print summary
    print(f"\n{'='*60}")
    print("Latency Results (ms)")
    print(f"{'='*60}")
    print(f"Samples measured: {results['n_samples']}")
    t = results["total_ms"]
    print(f"Total pipeline:   p50={t['p50']:.1f}  p95={t['p95']:.1f}  p99={t['p99']:.1f}  max={t['max']:.1f}  mean={t['mean']:.1f}")
    for name, m in results["per_module"].items():
        print(f"  {name:16s}: p50={m['p50']:.3f}  p95={m['p95']:.3f}  p99={m['p99']:.3f}  max={m['max']:.3f}  mean={m['mean']:.3f}")


if __name__ == "__main__":
    main()
