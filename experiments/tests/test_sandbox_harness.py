"""Tests for the local isolated sandbox harness."""
from __future__ import annotations

from skillguardgraph.sandbox_harness import build_sandbox_cases, run_sandbox_case, summarize_case_events


def test_sandbox_harness_builds_benign_and_malicious_cases():
    cases = build_sandbox_cases(per_scenario=2)
    benign = [case for case in cases if not case.malicious]
    malicious = [case for case in cases if case.malicious]
    assert benign
    assert malicious
    assert {case.scenario for case in malicious} >= {"network_exfiltration", "shell_execution", "persistence_pivot"}


def test_sandbox_case_blocks_network_attempts():
    case = next(case for case in build_sandbox_cases(per_scenario=1) if case.scenario == "network_exfiltration")
    run = run_sandbox_case(case)
    summary = summarize_case_events(run["events"])
    assert summary["saw_network_attempt"] is True
    assert summary["unsafe_egress"] is False


def test_sandbox_case_blocks_shell_attempts():
    case = next(case for case in build_sandbox_cases(per_scenario=1) if case.scenario == "shell_execution")
    run = run_sandbox_case(case)
    summary = summarize_case_events(run["events"])
    assert summary["saw_shell_attempt"] is True
    assert summary["unsafe_egress"] is False


def test_benign_export_case_writes_only_locally():
    case = next(case for case in build_sandbox_cases(per_scenario=1) if case.scenario == "benign_local_export")
    run = run_sandbox_case(case)
    summary = summarize_case_events(run["events"])
    assert summary["saw_file_write"] is True
    assert summary["saw_network_attempt"] is False
    assert summary["saw_shell_attempt"] is False
