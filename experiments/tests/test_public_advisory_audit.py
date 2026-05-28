"""Tests for public advisory cross-checking against the real corpus."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "results" / "ecosystem" / "real_ecosystem_samples.jsonl"
SCRIPT = ROOT / "scripts" / "run_public_advisory_audit.py"
RESULT = ROOT / "results" / "ecosystem" / "public_advisory_audit.json"

sys.path.insert(0, str(ROOT / "scripts"))

from run_public_advisory_audit import ADVISORIES, build_advisory_audit  # noqa: E402


def test_public_advisory_catalog_has_official_sources():
    assert len(ADVISORIES) >= 5
    for advisory in ADVISORIES:
        assert advisory.advisory_id.startswith("GHSA-")
        assert advisory.cve_id.startswith("CVE-")
        assert advisory.source_urls
        assert any("github.com/advisories" in url for url in advisory.source_urls)


def test_public_advisory_audit_matches_sdk_and_filesystem_cases():
    payload = build_advisory_audit()
    sdk = next(case for case in payload["cases"] if case["package_name"] == "@modelcontextprotocol/sdk")
    fs_case = next(case for case in payload["cases"] if case["package_name"] == "@modelcontextprotocol/server-filesystem")
    assert sdk["status"] == "present_patched"
    assert any(match["repo"] == "@modelcontextprotocol/sdk" for match in sdk["matches"])
    assert fs_case["status"] == "present_patched"
    assert any(match["repo"] == "@modelcontextprotocol/server-filesystem" for match in fs_case["matches"])
    assert payload["advisories_present_in_corpus"] >= 4


def test_public_advisory_runner_executes():
    assert SAMPLES.exists()
    subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT), check=True, timeout=120)
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["advisories_total"] >= 5
    assert payload["advisories_present_in_corpus"] >= 4
    assert payload["patched_or_unaffected_matches"] >= 4
    assert payload["currently_vulnerable_matches"] == 0
