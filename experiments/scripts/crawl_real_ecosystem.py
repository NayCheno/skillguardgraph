#!/usr/bin/env python3
"""Crawl real MCP server/tool repositories from GitHub and analyze them.

Collects metadata from real open-source MCP servers, tools, and connectors.
Runs metadata and static analyzers to identify cross-layer trust gaps.

Usage:
    PYTHONPATH=src python scripts/crawl_real_ecosystem.py [--target N]

Uses GitHub Search API (unauthenticated, 10 requests/min).
Results are cached to avoid re-crawling.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent  # experiments/
sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.metadata_analyzer import analyze_manifest
from skillguardgraph.static_analyzer import analyze_source
from skillguardgraph.models import Evidence, Severity

# Output paths
OUT_DIR = ROOT / "results" / "ecosystem"
OUT_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = OUT_DIR / "real_ecosystem_cache.json"
RESULTS_FILE = OUT_DIR / "real_ecosystem_results.json"

# Rate limiting
REQUEST_DELAY = 6.5  # seconds between GitHub API requests (10/min for search)

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _github_search(query: str, per_page: int = 100, page: int = 1) -> Dict[str, Any]:
    """Search GitHub repositories."""
    url = f"https://api.github.com/search/repositories?q={urllib.request.quote(query)}&per_page={per_page}&page={page}&sort=stars&order=desc"
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SkillGuardGraph-Research/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  Rate limited, waiting 60s...")
            time.sleep(60)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        raise


def _fetch_raw(owner: str, repo: str, path: str, branch: str = "main") -> Optional[str]:
    """Fetch raw file content from GitHub (no rate limit)."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "SkillGuardGraph-Research/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError):
        # Try master branch
        if branch == "main":
            return _fetch_raw(owner, repo, path, branch="master")
        return None


# ---------------------------------------------------------------------------
# MCP tool extraction from source code
# ---------------------------------------------------------------------------

# Python MCP server patterns
_PY_TOOL_DECORATOR = re.compile(r'@(?:server|app|mcp)\s*\.\s*tool\s*\(\s*["\'](\w+)["\']', re.MULTILINE)
_PY_LIST_TOOLS = re.compile(r'def\s+list_tools\s*\(', re.MULTILINE)
_PY_CALL_TOOL = re.compile(r'def\s+call_tool\s*\(', re.MULTILINE)

# TypeScript MCP server patterns
_TS_REGISTER_TOOL = re.compile(r'server\.tool\s*\(\s*["\'](\w+)["\']', re.MULTILINE)
_TS_SET_REQUEST = re.compile(r'setRequestHandler\s*\(\s*ListToolsRequest', re.MULTILINE)

# Description extraction
_PY_DESC_FROM_DOCSTRING = re.compile(r'"""([^"]{10,200})"""', re.MULTILINE)
_PY_DESC_FROM_PARAM = re.compile(r'description\s*=\s*["\']([^"\']{10,200})["\']', re.MULTILINE)

# Scope/capability patterns
_SCOPE_PATTERNS = re.compile(r'(read|write|delete|send|admin|export|modify|execute|run)', re.IGNORECASE)
_NETWORK_PATTERNS = re.compile(r'(requests\.(get|post|put)|fetch\(|axios\.|http\.|urllib|aiohttp)', re.IGNORECASE)
_FILE_PATTERNS = re.compile(r'(open\s*\(|writeFile|fs\.write|path\.join|shutil|os\.remove)', re.IGNORECASE)
_SHELL_PATTERNS = re.compile(r'(subprocess|os\.system|exec\(|eval\(|child_process|spawn)', re.IGNORECASE)


def extract_tools_from_python(source: str, repo_name: str) -> List[Dict[str, Any]]:
    """Extract tool definitions from Python MCP server source."""
    tools = []

    # Find @server.tool() or @app.tool() decorators
    for match in _PY_TOOL_DECORATOR.finditer(source):
        tool_name = match.group(1)
        # Try to find description near the decorator
        start = match.start()
        context = source[start:start + 500]
        desc_match = _PY_DESC_FROM_DOCSTRING.search(context) or _PY_DESC_FROM_PARAM.search(context)
        description = desc_match.group(1) if desc_match else f"Tool {tool_name} from {repo_name}"

        # Infer capabilities from source
        scopes = set(_SCOPE_PATTERNS.findall(source))
        has_network = bool(_NETWORK_PATTERNS.search(source))
        has_file = bool(_FILE_PATTERNS.search(source))
        has_shell = bool(_SHELL_PATTERNS.search(source))

        tools.append({
            "name": tool_name,
            "description": description,
            "scopes": sorted(scopes)[:5] if scopes else ["read"],
            "has_network": has_network,
            "has_file_write": has_file,
            "has_shell": has_shell,
            "language": "python",
        })

    return tools


def extract_tools_from_typescript(source: str, repo_name: str) -> List[Dict[str, Any]]:
    """Extract tool definitions from TypeScript MCP server source."""
    tools = []

    for match in _TS_REGISTER_TOOL.finditer(source):
        tool_name = match.group(1)
        start = match.start()
        context = source[start:start + 500]
        desc_match = _PY_DESC_FROM_PARAM.search(context)
        description = desc_match.group(1) if desc_match else f"Tool {tool_name} from {repo_name}"

        scopes = set(_SCOPE_PATTERNS.findall(source))
        has_network = bool(_NETWORK_PATTERNS.search(source))
        has_file = bool(_FILE_PATTERNS.search(source))
        has_shell = bool(_SHELL_PATTERNS.search(source))

        tools.append({
            "name": tool_name,
            "description": description,
            "scopes": sorted(scopes)[:5] if scopes else ["read"],
            "has_network": has_network,
            "has_file_write": has_file,
            "has_shell": has_shell,
            "language": "typescript",
        })

    return tools


# ---------------------------------------------------------------------------
# Manifest construction for analyzer
# ---------------------------------------------------------------------------

def build_manifest(repo: Dict[str, Any], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a manifest dict for the metadata analyzer."""
    all_scopes = set()
    for t in tools:
        all_scopes.update(t.get("scopes", []))

    description = repo.get("description") or f"MCP server from {repo['full_name']}"

    return {
        "name": repo["name"],
        "description": description,
        "scopes": sorted(all_scopes)[:8],
        "annotations": {
            "readOnlyHint": not any(t.get("has_file_write") or t.get("has_shell") for t in tools),
            "destructiveHint": any(t.get("has_shell") for t in tools),
        },
        "publisher": repo["owner"]["login"],
        "trusted_server": repo.get("stargazers_count", 0) > 100,
        "signature": None,
        "tool_count": len(tools),
        "stars": repo.get("stargazers_count", 0),
        "language": repo.get("language", "unknown"),
        "source": "github_mcp",
    }


# ---------------------------------------------------------------------------
# Main crawl logic
# ---------------------------------------------------------------------------

def crawl_github_mcp(target: int = 500) -> List[Dict[str, Any]]:
    """Crawl GitHub for MCP server repositories."""
    cache = {}
    if CACHE_FILE.exists():
        cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        print(f"Loaded {len(cache)} cached repos")

    # Search queries to find MCP servers
    queries = [
        "mcp server language:python",
        "mcp server language:typescript",
        "mcp tool server",
        "modelcontextprotocol server",
        "mcp-server in:name",
        "mcp server tool description",
    ]

    repos = {}
    for q in queries:
        if len(repos) >= target:
            break
        print(f"Searching: '{q}' ...")
        try:
            result = _github_search(q, per_page=100)
            items = result.get("items", [])
            print(f"  Found {len(items)} repos")
            for item in items:
                full_name = item["full_name"]
                if full_name not in repos and full_name not in cache:
                    repos[full_name] = item
            time.sleep(REQUEST_DELAY)
        except Exception as e:
            print(f"  Error: {e}")
            time.sleep(10)

    print(f"\nTotal unique repos to analyze: {len(repos)} (cached: {len(cache)})")

    # Analyze each repo
    samples = list(cache.values()) if cache else []
    analyzed = 0

    for full_name, repo in list(repos.items())[:target]:
        owner = repo["owner"]["login"]
        name = repo["name"]

        # Try to fetch source files
        source_files = []
        for ext, patterns in [
            ("py", [f"src/{name}/server.py", f"src/{name}/main.py", f"{name}/server.py",
                     "server.py", "main.py", "src/server.py", "src/main.py",
                     f"src/{name}/__init__.py"]),
            ("ts", [f"src/index.ts", f"src/server.ts", "index.ts", "server.ts"]),
        ]:
            for path in patterns:
                content = _fetch_raw(owner, name, path)
                if content and len(content) > 100:
                    source_files.append((path, content))
                    break
            if source_files:
                break

        if not source_files:
            continue

        # Extract tools
        all_tools = []
        for path, content in source_files:
            if path.endswith(".py"):
                all_tools.extend(extract_tools_from_python(content, name))
            elif path.endswith(".ts"):
                all_tools.extend(extract_tools_from_typescript(content, name))

        if not all_tools:
            # Create a generic tool entry
            all_tools = [{"name": name, "description": repo.get("description", ""),
                         "scopes": ["read"], "has_network": False, "has_file_write": False,
                         "has_shell": False, "language": repo.get("language", "unknown")}]

        # Build manifest and run analyzers
        manifest = build_manifest(repo, all_tools)
        source_code = "\n".join(content for _, content in source_files)

        # Run analyzers
        meta_evidence = analyze_manifest(manifest)
        static_evidence = analyze_source(full_name, source_code)

        sample = {
            "repo": full_name,
            "url": repo["html_url"],
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", "unknown"),
            "description": repo.get("description", ""),
            "manifest": manifest,
            "tools": all_tools,
            "meta_evidence": [e.to_dict() for e in meta_evidence],
            "static_evidence": [e.to_dict() for e in static_evidence],
            "meta_findings_count": len(meta_evidence),
            "static_findings_count": len(static_evidence),
        }

        samples.append(sample)
        cache[full_name] = sample
        analyzed += 1

        if analyzed % 10 == 0:
            print(f"  Analyzed {analyzed}/{len(repos)} repos ({len(samples)} total samples)")
            # Save cache periodically
            CACHE_FILE.write_text(json.dumps(cache, indent=1), encoding="utf-8")

        # Rate limit for raw content fetches (less strict)
        if analyzed % 20 == 0:
            time.sleep(1)

    # Save final cache
    CACHE_FILE.write_text(json.dumps(cache, indent=1), encoding="utf-8")
    print(f"\nTotal samples collected: {len(samples)}")

    return samples


def compute_real_stats(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute statistics from real ecosystem samples."""
    total = len(samples)

    # Risk pattern counts
    scope_inflation = 0
    description_mismatch = 0
    untrusted_publisher = 0
    missing_signature = 0
    open_world = 0
    instruction_like = 0

    high_severity = 0
    medium_severity = 0

    for s in samples:
        manifest = s.get("manifest", {})
        tools = s.get("tools", [])

        # Scope inflation: description says read-only but has write scopes
        desc = (manifest.get("description") or "").lower()
        scopes = set(manifest.get("scopes", []))
        if any(w in desc for w in ["read", "query", "search", "view", "list", "summarize"]):
            if scopes & {"write", "delete", "send", "admin", "export", "modify"}:
                scope_inflation += 1

        # Description-code mismatch
        has_write = any(t.get("has_file_write") or t.get("has_shell") for t in tools)
        if "read" in desc and has_write:
            description_mismatch += 1

        # Untrusted publisher
        if not manifest.get("trusted_server", False):
            untrusted_publisher += 1

        # Missing signature
        if not manifest.get("signature"):
            missing_signature += 1

        # Open world network access
        if any(t.get("has_network") for t in tools):
            open_world += 1

        # Instruction-like descriptions
        if any(phrase in desc for phrase in ["ignore", "override", "disregard", "forget"]):
            instruction_like += 1

        # Severity from meta evidence
        meta_count = s.get("meta_findings_count", 0)
        static_count = s.get("static_findings_count", 0)
        if meta_count >= 3 or static_count >= 3:
            high_severity += 1
        elif meta_count >= 1 or static_count >= 1:
            medium_severity += 1

    return {
        "total_samples": total,
        "sources": {"github_mcp": total},
        "risk_patterns": {
            "scope_inflation": {"count": scope_inflation, "rate": round(scope_inflation / total, 4) if total else 0},
            "description_mismatch": {"count": description_mismatch, "rate": round(description_mismatch / total, 4) if total else 0},
            "untrusted_publisher": {"count": untrusted_publisher, "rate": round(untrusted_publisher / total, 4) if total else 0},
            "missing_signature": {"count": missing_signature, "rate": round(missing_signature / total, 4) if total else 0},
            "open_world_network": {"count": open_world, "rate": round(open_world / total, 4) if total else 0},
            "instruction_like": {"count": instruction_like, "rate": round(instruction_like / total, 4) if total else 0},
        },
        "severity": {
            "high": high_severity,
            "medium": medium_severity,
            "low": total - high_severity - medium_severity,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Crawl real MCP ecosystem from GitHub")
    parser.add_argument("--target", type=int, default=500, help="Target number of repos to analyze")
    parser.add_argument("--resume", action="store_true", help="Resume from cache")
    args = parser.parse_args()

    print(f"=== Real MCP Ecosystem Crawl ===")
    print(f"Target: {args.target} repos")
    print()

    samples = crawl_github_mcp(target=args.target)

    print(f"\nComputing statistics...")
    stats = compute_real_stats(samples)

    # Save results
    RESULTS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(f"\nResults written to {RESULTS_FILE}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"Real Ecosystem Measurement Results")
    print(f"{'='*60}")
    print(f"Total samples: {stats['total_samples']}")
    print(f"\nRisk patterns:")
    for pattern, data in stats["risk_patterns"].items():
        print(f"  {pattern}: {data['count']} ({data['rate']*100:.1f}%)")
    print(f"\nSeverity distribution:")
    for level, count in stats["severity"].items():
        print(f"  {level}: {count}")


if __name__ == "__main__":
    main()
