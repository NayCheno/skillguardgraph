"""Tests for passive real-corpus crawler helpers."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from crawl_real_ecosystem import (  # noqa: E402
    _package_json_entrypoints,
    build_hf_manifest,
    extract_github_repo_ref,
    npm_entrypoint_candidates,
    normalize_repo_url,
    cached_source_samples,
)


def test_normalize_repo_url_handles_git_variants():
    assert normalize_repo_url("git+https://github.com/org/repo.git") == "https://github.com/org/repo"
    assert normalize_repo_url("git@github.com:org/repo.git") == "https://github.com/org/repo"


def test_extract_github_repo_ref_ignores_non_github_urls():
    assert extract_github_repo_ref("https://github.com/org/repo.git") == ("org", "repo")
    assert extract_github_repo_ref("https://example.com/org/repo") is None


def test_package_json_entrypoints_collect_main_bin_and_exports():
    package_json = """{
      \"main\": \"dist/index.js\",
      \"bin\": {\"mcp\": \"cli.js\"},
      \"exports\": {\".\": \"./server.ts\", \"./pkg\": {\"default\": \"./src/app.js\"}}
    }"""
    paths = _package_json_entrypoints(package_json)
    assert "dist/index.js" in paths
    assert "cli.js" in paths
    assert "server.ts" in paths
    assert "src/app.js" in paths


def test_npm_entrypoint_candidates_collect_bin_and_module():
    version_doc = {
        "main": "index.js",
        "module": "src/index.ts",
        "bin": {"tool": "bin/cli.js"},
    }
    paths = npm_entrypoint_candidates(version_doc)
    assert paths == ["index.js", "src/index.ts", "bin/cli.js"]


def test_build_hf_manifest_marks_liked_spaces_as_trusted():
    meta = {
        "id": "org/space",
        "author": "org",
        "likes": 75,
        "tags": ["gradio", "mcp-server"],
        "host": "https://org-space.hf.space",
        "cardData": {"title": "Space", "sdk": "gradio"},
    }
    tools = [{"name": "tool", "scopes": ["read"], "has_network": False, "has_file_write": False, "has_shell": False}]
    manifest = build_hf_manifest(meta, tools)
    assert manifest["trusted_server"] is True
    assert manifest["source"] == "hf_spaces_mcp"
    assert manifest["tool_count"] == 1

def test_cached_source_samples_filter_and_sort_by_source():
    cache = {
        "github_mcp:b": {"source": "github_mcp", "dedup_key": "b"},
        "github_mcp:a": {"source": "github_mcp", "dedup_key": "a"},
        "npm_mcp:x": {"source": "npm_mcp", "dedup_key": "x"},
    }
    samples = cached_source_samples(cache, "github_mcp")
    assert [sample["dedup_key"] for sample in samples] == ["a", "b"]
