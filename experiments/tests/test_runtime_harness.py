"""Tests for the local instrumented runtime harness."""
from __future__ import annotations

from skillguardgraph.fusion import fuse_and_evaluate
from skillguardgraph.models import Decision, Severity
from skillguardgraph.runtime_harness import InstrumentedRuntimeHarness, build_runtime_harness_tasks


def test_runtime_harness_builds_required_task_volume():
    tasks = build_runtime_harness_tasks()
    benign = [task for task in tasks if not task.malicious]
    attacks = [task for task in tasks if task.malicious]
    assert len(benign) == 105
    assert len(attacks) == 105
    assert {task.scenario for task in benign} >= {
        "local_read",
        "local_export",
        "trusted_sync",
        "preference_save",
        "data_export",
        "web_scrape",
        "file_sync",
        "calendar_read",
        "chat_respond",
        "code_format",
        "search_query",
    }
    assert {task.scenario for task in attacks} >= {
        "capability_laundering",
        "cross_skill_confused_deputy",
        "delayed_rug_pull",
        "consent_laundering",
        "persistence_pivot",
        "split_exfiltration",
        "scope_inflation",
        "obfuscated_exfil",
        "credential_theft",
        "config_poison",
        "approval_bypass",
    }


def test_runtime_harness_emits_trace_manifest_and_source():
    task = build_runtime_harness_tasks(benign=1, attack_per_class=1)[0]
    run = InstrumentedRuntimeHarness().run(task)
    assert run["manifest"]["name"]
    assert run["source_code"].strip()
    assert run["runtime_trace"]["events"]
    assert "flows" in run["runtime_trace"]


def test_runtime_harness_benign_task_is_not_blocked():
    task = next(task for task in build_runtime_harness_tasks() if task.scenario == "trusted_sync")
    run = InstrumentedRuntimeHarness().run(task)
    report = fuse_and_evaluate(run["manifest"], run["source_code"], run["runtime_trace"], run["manifest"]["name"])
    assert report.decision in {Decision.ALLOW, Decision.DEGRADE}
    assert report.risk in {Severity.LOW, Severity.MEDIUM}


def test_runtime_harness_attack_task_has_evidence_path():
    task = next(task for task in build_runtime_harness_tasks() if task.scenario == "split_exfiltration")
    run = InstrumentedRuntimeHarness().run(task)
    report = fuse_and_evaluate(run["manifest"], run["source_code"], run["runtime_trace"], run["manifest"]["name"])
    assert report.decision != Decision.ALLOW
    assert report.risk in {Severity.HIGH, Severity.CRITICAL}
    assert report.evidence_path
