#!/usr/bin/env python3
"""Generate a current-state completion audit for SkillGuardGraph."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
EXPERIMENTS = ROOT / "experiments"
RESULTS_MAIN = EXPERIMENTS / "results" / "main"
RESULTS_ECO = EXPERIMENTS / "results" / "ecosystem"
OUT_JSON = RESULTS_MAIN / "completion_audit.json"
OUT_MD = RESULTS_MAIN / "completion_audit.md"

REQUIRED_DOCS = [
    ROOT / "README.md",
    ROOT / "PROJECT_INDEX.md",
    ROOT / "docs" / "00_project_brief.md",
    ROOT / "docs" / "01_initial_research_plan.md",
    ROOT / "milestones" / "roadmap.md",
    ROOT / "milestones" / "weekly_execution_plan.md",
    ROOT / "checklists" / "acceptance_checklist.md",
    ROOT / "docs" / "execution_checklist.md",
    ROOT / "docs" / "claim_checklist.md",
    ROOT / "docs" / "mock_review.md",
    ROOT / "docs" / "rebuttal_bank.md",
    ROOT / "docs" / "review_response_strategy.md",
    ROOT / "paper" / "main.tex",
    ROOT / "paper" / "appendix.tex",
]

RESULT_FILES = [
    RESULTS_MAIN / "detector_eval.json",
    RESULTS_MAIN / "ablation.json",
    RESULTS_MAIN / "runtime_redteam.json",
    RESULTS_MAIN / "runtime_harness.json",
    RESULTS_MAIN / "sandbox_harness.json",
    RESULTS_MAIN / "third_party_sandbox.json",
    RESULTS_MAIN / "corpus_package_sandbox.json",
    RESULTS_MAIN / "remote_endpoint_audit.json",
    RESULTS_MAIN / "github_repo_sandbox.json",
    RESULTS_MAIN / "remote_task_audit.json",
    RESULTS_MAIN / "typescript_repo_sandbox.json",
    RESULTS_MAIN / "latency.json",
    RESULTS_MAIN / "bootstrap_ci.json",
    RESULTS_MAIN / "generalization_eval.json",
    RESULTS_MAIN / "failure_analysis.json",
    RESULTS_MAIN / "significance_tests.json",
    RESULTS_MAIN / "tables.txt",
    RESULTS_MAIN / "tables.tex",
    RESULTS_ECO / "real_ecosystem_results.json",
    RESULTS_ECO / "real_ecosystem_data_card.json",
    RESULTS_ECO / "real_high_risk_triage.json",
    RESULTS_ECO / "real_ecosystem_5k_results.json",
    RESULTS_ECO / "real_ecosystem_10k_results.json",
    RESULTS_ECO / "public_advisory_audit.json",
]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def git_status_clean() -> bool:
    proc = subprocess.run(
        ["git", "status", "--short"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip() == ""


def main() -> None:
    docs_present = {str(path.relative_to(ROOT)): path.exists() for path in REQUIRED_DOCS}
    results_present = {str(path.relative_to(ROOT)): path.exists() for path in RESULT_FILES}

    main_eco = read_json(RESULTS_ECO / "real_ecosystem_results.json")
    batch_5k = read_json(RESULTS_ECO / "real_ecosystem_5k_results.json")
    batch_10k = read_json(RESULTS_ECO / "real_ecosystem_10k_results.json")
    triage = read_json(RESULTS_ECO / "real_high_risk_triage.json")
    runtime_harness = read_json(RESULTS_MAIN / "runtime_harness.json")
    sandbox_harness = read_json(RESULTS_MAIN / "sandbox_harness.json")
    third_party = read_json(RESULTS_MAIN / "third_party_sandbox.json")
    corpus_package_sandbox = read_json(RESULTS_MAIN / "corpus_package_sandbox.json")
    generalization = read_json(RESULTS_MAIN / "generalization_eval.json")
    public_advisory = read_json(RESULTS_ECO / "public_advisory_audit.json")
    github_repo_sandbox = read_json(RESULTS_MAIN / "github_repo_sandbox.json")
    remote_endpoint_audit = read_json(RESULTS_MAIN / "remote_endpoint_audit.json")
    typescript_repo_sandbox = read_json(RESULTS_MAIN / "typescript_repo_sandbox.json")
    remote_task_audit = read_json(RESULTS_MAIN / "remote_task_audit.json")

    supported = {
        "docs_present": all(docs_present.values()),
        "results_present": all(results_present.values()),
        "git_clean": git_status_clean(),
        "runtime_harness_acceptance": all(runtime_harness["acceptance"].values()),
        "sandbox_harness_acceptance": all(sandbox_harness["acceptance"].values()),
        "third_party_fixture_acceptance": all(third_party["acceptance"].values()),
        "generalization_acceptance": all(generalization["acceptance"].values()),
        "corpus_package_acceptance": all(corpus_package_sandbox["acceptance"].values()),
        "public_advisory_audit_present": int(public_advisory.get("advisories_total", 0)) >= 1,
        "github_repo_acceptance": all(github_repo_sandbox["acceptance"].values()),
        "public_corpus_reaches_5k": int(batch_5k.get("total_samples", 0)) >= 5000,
        "typescript_repo_acceptance": all(typescript_repo_sandbox["acceptance"].values()),
        "remote_endpoint_audit_acceptance": all(remote_endpoint_audit["acceptance"].values()),
        "remote_task_audit_acceptance": all(remote_task_audit["acceptance"].values()),
        "public_corpus_reaches_10k": int(batch_10k.get("total_samples", 0)) >= 10000,
    }

    unresolved = {
        "confirmed_real_cases": int(triage["summary"].get("confirmed_vulnerabilities", 0)) == 0,
        "disclosures_sent": int(triage["summary"].get("disclosures_sent", 0)) == 0,
        "advisory_backed_cases_in_corpus": int(public_advisory.get("advisories_present_in_corpus", 0)),
        "currently_vulnerable_advisory_matches": int(public_advisory.get("currently_vulnerable_matches", 0)),
        "main_batch_source_available": int(main_eco.get("code_availability", {}).get("source_available", 0)),
        "main_batch_total": int(main_eco.get("total_samples", 0)),
        "tenk_batch_source_available": int(batch_10k.get("code_availability", {}).get("source_available", 0)),
        "tenk_batch_total": int(batch_10k.get("total_samples", 0)),
        "strong_submission_blockers": [
            "No disclosure-backed or independently validated real case studies from the measured snapshot.",
            "No arbitrary third-party dynamic sandbox execution beyond bounded source-available public-package and GitHub repo/TypeScript cases.",
            "No authenticated production runtime deployment evidence.",
            "No private enterprise catalog coverage.",
        ],
    }

    summary = {
        "supported": supported,
        "current_real_batches": {
            "main": main_eco,
            "supplementary_5k": batch_5k,
            "supplementary_10k": batch_10k,
        },
        "triage_summary": triage["summary"],
        "unresolved": unresolved,
        "public_advisory_summary": {
            "advisories_total": public_advisory.get("advisories_total", 0),
            "advisories_present_in_corpus": public_advisory.get("advisories_present_in_corpus", 0),
            "currently_vulnerable_matches": public_advisory.get("currently_vulnerable_matches", 0),
        },
        "remote_endpoint_summary": {
            "cases_probed": remote_endpoint_audit.get("cases_probed", 0),
            "initialize_successes": remote_endpoint_audit.get("initialize_successes", 0),
            "tools_list_successes": remote_endpoint_audit.get("tools_list_successes", 0),
            "protected_endpoints_observed": remote_endpoint_audit.get("protected_endpoints_observed", 0),
        },
        "remote_task_summary": {
            "cases_executed": remote_task_audit.get("cases_executed", 0),
            "successful_tool_calls": remote_task_audit.get("successful_tool_calls", 0),
            "structured_tool_results": remote_task_audit.get("structured_tool_results", 0),
        },
    }

    OUT_JSON.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Completion Audit",
        "",
        "## Supported checks",
        "",
    ]
    for key, value in supported.items():
        lines.append(f"- {key}: {'PASS' if value else 'FAIL'}")
    lines.extend([
        "",
        "## Current real-corpus state",
        f"- TypeScript repo sandbox: {typescript_repo_sandbox.get('cases_executed', 0)} cases, tool_registry_total={typescript_repo_sandbox.get('tool_registry_total', 0)}, cli_calls={typescript_repo_sandbox.get('cli_calls', 0)}",
        "",
        f"- main batch: {main_eco.get('total_samples', 0)} artifacts, source_available={main_eco.get('code_availability', {}).get('source_available', 0)}",
        f"- advisory-backed cases in corpus: {public_advisory.get('advisories_present_in_corpus', 0)} (currently vulnerable={public_advisory.get('currently_vulnerable_matches', 0)})",
        f"- corpus-derived package sandbox: {corpus_package_sandbox.get('cases_executed', 0)} cases, archive_resolved={corpus_package_sandbox.get('archive_cases_resolved', 0)}",
        f"- public remote endpoint audit: {remote_endpoint_audit.get('cases_probed', 0)} probed, initialize_successes={remote_endpoint_audit.get('initialize_successes', 0)}, tools_list_successes={remote_endpoint_audit.get('tools_list_successes', 0)}",
        f"- GitHub repo sandbox: {github_repo_sandbox.get('cases_executed', 0)} cases, tool_registry_total={github_repo_sandbox.get('tool_registry_total', 0)}",
        f"- 5k batch: {batch_5k.get('total_samples', 0)} artifacts",
        f"- public remote task audit: {remote_task_audit.get('cases_executed', 0)} executed, successful_tool_calls={remote_task_audit.get('successful_tool_calls', 0)}, structured_results={remote_task_audit.get('structured_tool_results', 0)}",
        f"- 10k batch: {batch_10k.get('total_samples', 0)} artifacts, source_available={batch_10k.get('code_availability', {}).get('source_available', 0)}",
        f"- confirmed real vulnerabilities: {triage['summary'].get('confirmed_vulnerabilities', 0)}",
        f"- disclosures sent: {triage['summary'].get('disclosures_sent', 0)}",
        "",
        "## Remaining blockers",
        "",
    ])
    for blocker in unresolved["strong_submission_blockers"]:
        lines.append(f"- {blocker}")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Audit written to {OUT_JSON}")
    print(f"Audit summary written to {OUT_MD}")


if __name__ == "__main__":
    main()
