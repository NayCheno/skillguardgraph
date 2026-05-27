#!/usr/bin/env python3
"""Measure per-sample latency for the SkillGuardGraph fusion pipeline.

Reports:
- Mean, median, p95, p99 latency per sample
- Per-layer breakdown (metadata, static, sandbox, fusion)
- Total throughput
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

from skillguardgraph.fusion import fuse_and_evaluate  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.sandbox_prober import probe_skill, observations_to_evidence  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402
from skillguardgraph.runtime_monitor import trace_to_evidence  # noqa: E402


def load_samples(path: Path) -> list[dict]:
    samples = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def percentile(data: list[float], p: float) -> float:
    """Compute the p-th percentile."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(len(sorted_data) * p / 100)
    idx = min(idx, len(sorted_data) - 1)
    return sorted_data[idx]


def main() -> None:
    print(f"Loading samples from {DATA_PATH} ...")
    samples = load_samples(DATA_PATH)
    total = len(samples)
    print(f"  {total} samples loaded.")

    # Limit to 500 samples for latency measurement
    sample_size = min(500, total)
    import random
    rng = random.Random(42)
    sampled = rng.sample(samples, sample_size)

    metadata_latencies: list[float] = []
    static_latencies: list[float] = []
    sandbox_latencies: list[float] = []
    runtime_latencies: list[float] = []
    fusion_latencies: list[float] = []
    total_latencies: list[float] = []

    for i, sample in enumerate(sampled):
        if (i + 1) % 100 == 0:
            print(f"  Processing sample {i + 1}/{sample_size} ...")

        manifest = sample.get("manifest")
        source_code = sample.get("source_code")
        trace = sample.get("runtime_trace")

        t_total_start = time.perf_counter()

        # Metadata
        if manifest:
            t0 = time.perf_counter()
            analyze_manifest(manifest)
            metadata_latencies.append((time.perf_counter() - t0) * 1000)

        # Static
        if source_code:
            t0 = time.perf_counter()
            skill_name = str(manifest.get("name", "unknown")) if manifest else "unknown"
            analyze_source(skill_name, source_code)
            static_latencies.append((time.perf_counter() - t0) * 1000)

        # Sandbox
        if manifest:
            t0 = time.perf_counter()
            skill_name = str(manifest.get("name", "unknown"))
            obs = probe_skill(skill_name, manifest, source_code)
            observations_to_evidence(obs)
            sandbox_latencies.append((time.perf_counter() - t0) * 1000)

        # Runtime
        if trace:
            t0 = time.perf_counter()
            trace_to_evidence(trace)
            runtime_latencies.append((time.perf_counter() - t0) * 1000)

        # Full fusion
        t0 = time.perf_counter()
        sandbox_obs = None
        if manifest:
            skill_name = str(manifest.get("name", "unknown"))
            sandbox_obs = probe_skill(skill_name, manifest, source_code)
        fuse_and_evaluate(
            manifest=manifest,
            source_code=source_code,
            runtime_trace=trace,
            sandbox_observations=sandbox_obs,
        )
        fusion_latencies.append((time.perf_counter() - t0) * 1000)

        total_latencies.append((time.perf_counter() - t_total_start) * 1000)

    def stats(latencies: list[float]) -> dict:
        if not latencies:
            return {"mean": 0, "median": 0, "p95": 0, "p99": 0, "min": 0, "max": 0, "count": 0}
        return {
            "mean": round(statistics.mean(latencies), 3),
            "median": round(statistics.median(latencies), 3),
            "p95": round(percentile(latencies, 95), 3),
            "p99": round(percentile(latencies, 99), 3),
            "min": round(min(latencies), 3),
            "max": round(max(latencies), 3),
            "count": len(latencies),
        }

    result = {
        "sample_size": sample_size,
        "total_samples": total,
        "per_layer_ms": {
            "metadata": stats(metadata_latencies),
            "static": stats(static_latencies),
            "sandbox": stats(sandbox_latencies),
            "runtime": stats(runtime_latencies),
        },
        "fusion_ms": stats(fusion_latencies),
        "total_per_sample_ms": stats(total_latencies),
        "throughput_samples_per_sec": round(sample_size / (sum(total_latencies) / 1000), 1) if total_latencies else 0,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(f"\nResults written to {OUT_PATH}")
    print(f"\nLatency (ms) per sample:")
    for layer, s in result["per_layer_ms"].items():
        print(f"  {layer:12s}: mean={s['mean']:.3f}  median={s['median']:.3f}  p95={s['p95']:.3f}")
    fs = result["fusion_ms"]
    print(f"  {'fusion':12s}: mean={fs['mean']:.3f}  median={fs['median']:.3f}  p95={fs['p95']:.3f}")
    ts = result["total_per_sample_ms"]
    print(f"  {'total':12s}: mean={ts['mean']:.3f}  median={ts['median']:.3f}  p95={ts['p95']:.3f}")
    print(f"\nThroughput: {result['throughput_samples_per_sec']} samples/sec")


if __name__ == "__main__":
    main()
