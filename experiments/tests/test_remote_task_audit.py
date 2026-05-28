"""Tests for bounded harmless remote MCP tool-call execution."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_remote_task_audit.py"
RESULT = ROOT / "results" / "main" / "remote_task_audit.json"

sys.path.insert(0, str(ROOT / "scripts"))

from run_remote_task_audit import CASES, _parse_mcp_http_body, build_remote_task_audit  # noqa: E402


def test_parse_mcp_http_body_handles_json_and_sse():
    direct = _parse_mcp_http_body('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}')
    assert direct["result"]["ok"] is True
    sse = _parse_mcp_http_body('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n\n')
    assert sse["result"]["content"] == []


def test_remote_task_cases_are_configured():
    assert len(CASES) == 2
    assert {case.repo for case in CASES} == {"ai.aarna/atars-mcp", "ai.agenticshelf/mcp"}
    for case in CASES:
        assert case.url.startswith("https://")
        assert case.tool_name
        assert case.expected_signal


def test_remote_task_audit_runner_executes():
    subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT), check=True, timeout=180)
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["acceptance"]["all_cases_executed"] is True
    assert payload["acceptance"]["successful_tool_calls_ge_2"] is True
    assert payload["acceptance"]["all_signals_matched"] is True
    assert payload["acceptance"]["structured_result_observed"] is True
