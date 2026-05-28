"""Tests for bounded source-available TypeScript GitHub repo sandbox execution."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from skillguardgraph.typescript_repo_sandbox import build_typescript_repo_cases

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_typescript_repo_sandbox.py"
RESULT = ROOT / "results" / "main" / "typescript_repo_sandbox.json"


def test_typescript_repo_cases_resolve_from_main_batch():
    cases = build_typescript_repo_cases()
    assert len(cases) >= 2
    repos = {case.repo for case in cases}
    assert {"21st-dev/magic-mcp", "Done-0/fuck-u-code"}.issubset(repos)
    for case in cases:
        assert case.raw_url.startswith("https://raw.githubusercontent.com/")
        assert case.source_path in case.source_paths
        assert case.invoke.strip()


def test_typescript_repo_sandbox_runner_executes():
    subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT), check=True, timeout=120)
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["acceptance"]["all_cases_executed"] is True
    assert payload["acceptance"]["tool_registry_observed"] is True
    assert payload["acceptance"]["cli_delegate_observed"] is True
    assert payload["acceptance"]["no_unsafe_egress"] is True
