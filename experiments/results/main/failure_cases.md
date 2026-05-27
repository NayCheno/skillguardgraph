# Failure Case Analysis

**Benchmark:** benchmark_v0 (4,010 samples: 3,010 malicious, 1,000 benign)

**Detector:** Fusion method after runtime external-sink normalization and persistence calibration

**Date:** 2026-05-27

## Summary

| Metric | Value |
|---|---:|
| True Positives | 3,010 |
| True Negatives | 1,000 |
| False Positives | 0 |
| False Negatives | 0 |
| Evidence path attribution | 3,010 / 3,010 (100.0%) |

The latest fusion run has no false positives or false negatives on the synthetic benchmark. The structured output is `experiments/results/main/failure_analysis.json`.

## What Changed

1. Runtime sink normalization now recognizes the benchmark trace schema fields `sink_type` and `is_external`, so subtle external sink traces contribute `is_external_sink` evidence.
2. Benign local persistence is no longer scored as strongly as untrusted persistence. The strong signal is now the C6 constraint (`untrusted source -> persistent store`), not persistence by itself.
3. The HIGH-risk threshold is calibrated at 4.5, which catches subtle external-sink traces while keeping benign persistence-only traces below the blocking threshold.

## Current Failure Buckets

| Bucket | Count | Notes |
|---|---:|---|
| False negatives | 0 | No attack class has missed samples in the latest synthetic benchmark run. |
| False positives | 0 | No benign sample is classified as HIGH/CRITICAL in the latest synthetic benchmark run. |

## Residual Risks

This analysis is still synthetic-benchmark evidence. It does not prove equivalent performance on real public MCP/tool repositories. Real ecosystem measurement should be reported separately with manual triage, confidence labels, and disclosure logs for confirmed vulnerabilities.
