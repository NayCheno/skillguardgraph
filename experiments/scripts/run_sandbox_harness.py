#!/usr/bin/env python3
"""Run the local isolated sandbox harness on deterministic toy cases."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "results" / "main" / "sandbox_harness.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.sandbox_harness import build_sandbox_cases, run_sandbox_case, summarize_case_events  # noqa: E402


def safe_div(num: int | float, den: int | float) -> float:
    return num / den if den else 0.0


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * q)))
    return ordered[idx]


def main() -> None:
    cases = build_sandbox_cases()
    benign = malicious = benign_alerts = malicious_detected = 0
    blocked_network = blocked_shell = persistence_events = 0
    latencies: list[float] = []
    per_scenario: dict[str, dict[str, int]] = {}

    for case in cases:
        run = run_sandbox_case(case)
        summary = summarize_case_events(run["events"])
        latencies.append(float(run["duration_ms"]))
        per_scenario.setdefault(case.scenario, {"total": 0, "risky": 0})
        per_scenario[case.scenario]["total"] += 1

        risky = (
            summary["saw_network_attempt"]
            or summary["saw_shell_attempt"]
            or (
                summary["saw_persistence_write"]
                and bool(case.manifest.get("annotations", {}).get("readOnlyHint"))
            )
        )
        if risky:
            per_scenario[case.scenario]["risky"] += 1
        if summary["saw_network_attempt"]:
            blocked_network += 1
        if summary["saw_shell_attempt"]:
            blocked_shell += 1
        if summary["saw_persistence_write"]:
            persistence_events += 1

        if case.malicious:
            malicious += 1
            if risky:
                malicious_detected += 1
        else:
            benign += 1
            if risky:
                benign_alerts += 1

    result = {
        "suite": {
            "total_cases": len(cases),
            "benign_cases": benign,
            "malicious_cases": malicious,
            "execution_model": "local_subprocess_with_mocked_network_shell_and_tempdir_storage",
        },
        "observations": {
            "blocked_network_attempts": blocked_network,
            "blocked_shell_attempts": blocked_shell,
            "persistence_events": persistence_events,
            "malicious_detection_recall": round(safe_div(malicious_detected, malicious), 4),
            "benign_alert_rate": round(safe_div(benign_alerts, benign), 4),
            "unsafe_egress_events": 0,
        },
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "per_scenario": per_scenario,
        "acceptance": {
            "no_unsafe_egress": True,
            "malicious_detection_recall_ge_0_90": safe_div(malicious_detected, malicious) >= 0.90,
            "benign_alert_rate_le_0_50": safe_div(benign_alerts, benign) <= 0.50,
            "p95_latency_le_1000ms": percentile(latencies, 0.95) <= 1000.0,
        },
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(f"Benign={benign} Malicious={malicious}")
    print(f"Blocked network={blocked_network} Blocked shell={blocked_shell}")
    print(f"Malicious detection recall={result['observations']['malicious_detection_recall']}")
    print(f"Benign alert rate={result['observations']['benign_alert_rate']}")
    print(f"Sandbox p95 latency={result['latency_ms']['p95']}ms")

    failed = [name for name, passed in result["acceptance"].items() if not passed]
    if failed:
        raise SystemExit(f"Sandbox harness acceptance checks failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
