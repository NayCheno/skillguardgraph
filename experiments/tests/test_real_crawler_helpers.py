"""Tests for passive real-corpus crawler helpers."""
from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import crawl_real_ecosystem as cre  # noqa: E402
from crawl_real_ecosystem import (  # noqa: E402
    _package_json_entrypoints,
    _rate_limit_hint,
    _request_headers,
    build_hf_manifest,
    build_official_registry_manifest,
    build_official_registry_tools,
    build_smithery_manifest,
    build_smithery_tools,
    cached_source_samples,
    canonicalize_package_name,
    extract_github_repo_ref,
    npm_entrypoint_candidates,
    normalize_repo_url,
    parse_source_quotas,
    tarball_member_texts,
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


def test_build_smithery_manifest_marks_verified_servers_trusted():
    detail = {
        "qualifiedName": "demo/server",
        "displayName": "Demo Server",
        "description": "Search and compare MCP servers through a hosted gateway.",
        "remote": True,
        "deploymentUrl": "https://demo.run.tools",
        "connections": [{"type": "http"}],
        "tools": [
            {
                "name": "search_servers",
                "description": "Search and compare remote MCP servers",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
            }
        ],
    }
    summary = {"namespace": "demo", "verified": True, "bySmithery": False, "useCount": 42, "isDeployed": True}
    tools = build_smithery_tools(detail)
    manifest = build_smithery_manifest(summary, detail, tools)
    assert manifest["trusted_server"] is True
    assert manifest["source"] == "smithery_mcp"
    assert manifest["annotations"]["openWorldHint"] is True
    assert manifest["tool_count"] == 1

def test_build_official_registry_manifest_marks_remote_registry_entries_trusted():
    server_doc = {
        "name": "io.github.example/demo-server",
        "description": "Browse and execute remote tools over streamable-http.",
        "title": "Demo Server",
        "version": "1.2.3",
        "remotes": [{"type": "streamable-http", "url": "https://example.invalid/mcp"}],
        "repository": {"url": "https://github.com/example/demo-server", "source": "github"},
    }
    meta = {"io.modelcontextprotocol.registry/official": {"status": "active", "isLatest": True}}
    tools = build_official_registry_tools(server_doc)
    manifest = build_official_registry_manifest(server_doc, meta, tools)
    assert manifest["trusted_server"] is True
    assert manifest["source"] == "official_registry_mcp"
    assert manifest["annotations"]["openWorldHint"] is True
    assert tools[0]["has_network"] is True
    assert "run" in tools[0]["scopes"]
    assert "query" in tools[0]["scopes"]


def test_tarball_member_texts_reads_package_json_entrypoints():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        package_json = b'{"main":"dist/index.js","bin":{"tool":"bin/cli.js"}}'
        info = tarfile.TarInfo("package/package.json")
        info.size = len(package_json)
        archive.addfile(info, io.BytesIO(package_json))

        index_js = b'console.log("hello")'
        info = tarfile.TarInfo("package/dist/index.js")
        info.size = len(index_js)
        archive.addfile(info, io.BytesIO(index_js))

        cli_js = b'console.log("cli")'
        info = tarfile.TarInfo("package/bin/cli.js")
        info.size = len(cli_js)
        archive.addfile(info, io.BytesIO(cli_js))

    original = cre.fetch_bytes
    cre.fetch_bytes = lambda url: buffer.getvalue()
    try:
        members = tarball_member_texts("https://registry.npmjs.org/pkg.tgz", ["dist/index.js"])
    finally:
        cre.fetch_bytes = original

    paths = [member["path"] for member in members]
    assert any(path.endswith("dist/index.js") for path in paths)
    assert any(path.endswith("bin/cli.js") for path in paths)


def test_cached_source_samples_filter_and_sort_by_source():
    cache = {
        "github_mcp:b": {"source": "github_mcp", "dedup_key": "b"},
        "github_mcp:a": {"source": "github_mcp", "dedup_key": "a"},
        "npm_mcp:x": {"source": "npm_mcp", "dedup_key": "x"},
    }
    samples = cached_source_samples(cache, "github_mcp")
    assert [sample["dedup_key"] for sample in samples] == ["a", "b"]


def test_request_headers_include_github_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    headers = _request_headers("github")
    assert headers["Authorization"] == "Bearer secret"
    assert headers["Accept"] == "application/vnd.github+json"


def test_request_headers_include_smithery_token(monkeypatch):
    monkeypatch.setenv("SMITHERY_API_KEY", "secret")
    headers = _request_headers("smithery")
    assert headers["Authorization"] == "Bearer secret"


def test_rate_limit_hint_mentions_resume():
    assert "GITHUB_TOKEN" in _rate_limit_hint("github")
    assert "--resume" in _rate_limit_hint("github")


def test_canonicalize_package_name_normalizes_variants():
    assert canonicalize_package_name("Aivpp.My_Test-MCP") == "aivpp-my-test-mcp"


def test_parse_source_quotas_validates_total_and_members():
    quotas = parse_source_quotas(
        "github_mcp=10,npm_mcp=5,pypi_mcp=2,hf_spaces_mcp=1,smithery_mcp=1,official_registry_mcp=1",
        ["github_mcp", "npm_mcp", "pypi_mcp", "hf_spaces_mcp", "smithery_mcp", "official_registry_mcp"],
        20,
    )
    assert quotas["github_mcp"] == 10
    assert quotas["hf_spaces_mcp"] == 1
    assert quotas["smithery_mcp"] == 1
    assert quotas["official_registry_mcp"] == 1