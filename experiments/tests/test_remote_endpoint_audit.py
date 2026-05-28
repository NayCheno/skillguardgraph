"""Tests for bounded public remote MCP endpoint probing."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_remote_endpoint_audit.py"
RESULT = ROOT / "results" / "main" / "remote_endpoint_audit.json"

sys.path.insert(0, str(ROOT / "scripts"))

from run_remote_endpoint_audit import PROFILES, _parse_mcp_http_body, build_remote_cases  # noqa: E402


def test_parse_mcp_http_body_handles_json_and_sse():
    direct = _parse_mcp_http_body('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}')
    assert direct["result"]["ok"] is True
    sse = _parse_mcp_http_body('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n')
    assert sse["result"]["tools"] == []


def test_remote_profiles_resolve_from_corpus():
    cases = build_remote_cases()
    assert len(cases) == len(PROFILES)
    repos = {case["repo"] for case in cases}
    assert {profile.repo for profile in PROFILES} == repos
    for case in cases:
        assert case["url"].startswith("https://")
        assert case["source"] == "official_registry_mcp"


def test_remote_endpoint_audit_runner_executes():
    subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT), check=True, timeout=180)
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["acceptance"]["all_cases_probed"] is True
    assert payload["acceptance"]["initialize_success_ge_2"] is True
    assert payload["acceptance"]["tools_list_success_ge_1"] is True
    assert payload["acceptance"]["protected_endpoint_observed"] is True
