"""Tests for third-party public-code sandbox fixtures."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from skillguardgraph.third_party_sandbox import build_third_party_fixtures

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_third_party_sandbox.py"
RESULT = ROOT / "results" / "main" / "third_party_sandbox.json"


def test_third_party_fixtures_have_urls_and_invocations():
    fixtures = build_third_party_fixtures()
    assert len(fixtures) >= 3
    for fixture in fixtures:
        assert fixture.source_url.startswith("https://")
        assert fixture.source_code.strip()
        assert fixture.invoke.strip()


def test_third_party_sandbox_runner_executes():
    subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT), check=True, timeout=60)
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["acceptance"]["all_fixtures_executed"] is True
    assert payload["acceptance"]["subprocess_attempts_captured"] is True
    assert payload["acceptance"]["no_unsafe_egress"] is True
