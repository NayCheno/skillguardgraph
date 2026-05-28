"""Tests for bounded corpus-derived third-party package sandbox execution."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from skillguardgraph.corpus_package_sandbox import build_corpus_package_cases

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_corpus_package_sandbox.py"
RESULT = ROOT / "results" / "main" / "corpus_package_sandbox.json"


def test_corpus_package_cases_resolve_from_main_batch():
    cases = build_corpus_package_cases()
    assert len(cases) >= 3
    names = {case.package_name for case in cases}
    assert {"autodoc-mcp", "mcp-server-creator", "search-mcp-server"}.issubset(names)
    for case in cases:
        assert case.version
        assert case.artifact_url.startswith("https://pypi.org/project/")
        assert case.source_path in case.source_paths
        assert case.invoke.strip()


def test_corpus_package_sandbox_runner_executes():
    subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT), check=True, timeout=120)
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["acceptance"]["all_cases_executed"] is True
    assert payload["acceptance"]["archive_cases_resolved_ge_3"] is True
    assert payload["acceptance"]["subprocess_or_client_events_captured"] is True
    assert payload["acceptance"]["registered_tools_observed"] is True
    assert payload["acceptance"]["no_unsafe_egress"] is True
