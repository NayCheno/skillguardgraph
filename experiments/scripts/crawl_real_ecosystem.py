#!/usr/bin/env python3
"""Crawl real MCP-related repositories from GitHub and analyze them safely.

Passive collection only:
- GitHub Search API for public repositories
- optional raw source fetches for likely entrypoints
- metadata/static analysis only; no execution of third-party code

Outputs:
- results/ecosystem/real_ecosystem_cache.json
- results/ecosystem/real_ecosystem_samples.jsonl
- results/ecosystem/real_ecosystem_results.json
- results/ecosystem/real_ecosystem_data_card.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.evidence_graph import EvidenceGraph  # noqa: E402
from skillguardgraph.metadata_analyzer import analyze_manifest  # noqa: E402
from skillguardgraph.policy_engine import evaluate as policy_evaluate  # noqa: E402
from skillguardgraph.static_analyzer import analyze_source  # noqa: E402

OUT_DIR = ROOT / "results" / "ecosystem"
OUT_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = OUT_DIR / "real_ecosystem_cache.json"
SAMPLES_FILE = OUT_DIR / "real_ecosystem_samples.jsonl"
RESULTS_FILE = OUT_DIR / "real_ecosystem_results.json"
DATA_CARD_FILE = OUT_DIR / "real_ecosystem_data_card.json"

SEARCH_DELAY_SECONDS = 6.5
SEARCH_PER_PAGE = 100

SEARCH_QUERIES = [
    '"model context protocol" server',
    '"model context protocol" tool',
    'mcp server language:python',
    'mcp server language:typescript',
    'mcp tool server',
    'mcp-server in:name',
    'modelcontextprotocol server',
    'model context protocol client tool',
]

PY_TOOL_DECORATOR = re.compile(r'@(?:server|app|mcp)\s*\.\s*tool\s*\(\s*["\']([\w-]+)["\']', re.MULTILINE)
TS_REGISTER_TOOL = re.compile(r'server\.tool\s*\(\s*["\']([\w-]+)["\']', re.MULTILINE)
PY_DESC_FROM_DOCSTRING = re.compile(r'"""([^\"]{10,200})"""', re.MULTILINE)
PY_DESC_FROM_PARAM = re.compile(r'description\s*=\s*["\']([^"\']{10,200})["\']', re.MULTILINE)
SCOPE_PATTERNS = re.compile(r'(read|write|delete|send|admin|export|modify|execute|run|search|query|list|summarize)', re.IGNORECASE)
NETWORK_PATTERNS = re.compile(r'(requests\.(get|post|put)|fetch\(|axios\.|http\.|urllib|aiohttp|websocket|ws\.)', re.IGNORECASE)
FILE_PATTERNS = re.compile(r'(open\s*\(|writeFile|fs\.write|shutil|os\.remove|unlink\(|mkdir\()', re.IGNORECASE)
SHELL_PATTERNS = re.compile(r'(subprocess|os\.system|exec\(|eval\(|child_process|spawn\(|pty)', re.IGNORECASE)
SOURCE_LANGUAGES = {"python", "typescript", "javascript"}


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def github_request(url: str) -> Dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SkillGuardGraph-Research/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def github_search(query: str, page: int) -> Dict[str, Any]:
    encoded_query = urllib.parse.quote(query)
    url = (
        "https://api.github.com/search/repositories"
        f"?q={encoded_query}&per_page={SEARCH_PER_PAGE}&page={page}&sort=stars&order=desc"
    )
    try:
        return github_request(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            print("  Search rate limited; sleeping 60s before retry")
            time.sleep(60)
            return github_request(url)
        raise


def fetch_raw(owner: str, repo: str, path: str, branch: str) -> Optional[str]:
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "SkillGuardGraph-Research/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None


def license_id(repo: Dict[str, Any]) -> str:
    lic = repo.get("license") or {}
    if isinstance(lic, dict):
        return str(lic.get("spdx_id") or lic.get("key") or "unknown")
    return "unknown"


def entrypoint_candidates() -> Iterable[str]:
    yield from (
        "src/server.py",
        "server.py",
        "src/main.py",
        "main.py",
        "src/index.ts",
        "index.ts",
        "src/server.ts",
        "server.ts",
    )


def extract_tools_from_python(source: str, repo_name: str) -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    for match in PY_TOOL_DECORATOR.finditer(source):
        tool_name = match.group(1)
        context = source[match.start():match.start() + 500]
        desc_match = PY_DESC_FROM_DOCSTRING.search(context) or PY_DESC_FROM_PARAM.search(context)
        description = desc_match.group(1) if desc_match else f"Tool {tool_name} from {repo_name}"
        scopes = {s.lower() for s in SCOPE_PATTERNS.findall(source)}
        tools.append({
            "name": tool_name,
            "description": description,
            "scopes": sorted(scopes)[:8] if scopes else ["read"],
            "has_network": bool(NETWORK_PATTERNS.search(source)),
            "has_file_write": bool(FILE_PATTERNS.search(source)),
            "has_shell": bool(SHELL_PATTERNS.search(source)),
            "language": "python",
        })
    return tools


def extract_tools_from_typescript(source: str, repo_name: str) -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    for match in TS_REGISTER_TOOL.finditer(source):
        tool_name = match.group(1)
        context = source[match.start():match.start() + 500]
        desc_match = PY_DESC_FROM_PARAM.search(context)
        description = desc_match.group(1) if desc_match else f"Tool {tool_name} from {repo_name}"
        scopes = {s.lower() for s in SCOPE_PATTERNS.findall(source)}
        tools.append({
            "name": tool_name,
            "description": description,
            "scopes": sorted(scopes)[:8] if scopes else ["read"],
            "has_network": bool(NETWORK_PATTERNS.search(source)),
            "has_file_write": bool(FILE_PATTERNS.search(source)),
            "has_shell": bool(SHELL_PATTERNS.search(source)),
            "language": "typescript",
        })
    return tools


def build_manifest(repo: Dict[str, Any], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    all_scopes = set()
    has_file_write = False
    has_shell = False
    for tool in tools:
        all_scopes.update(tool.get("scopes", []))
        has_file_write = has_file_write or bool(tool.get("has_file_write"))
        has_shell = has_shell or bool(tool.get("has_shell"))

    description = repo.get("description") or f"MCP-related repository from {repo['full_name']}"
    return {
        "name": repo["name"],
        "description": description,
        "scopes": sorted(all_scopes)[:8] if all_scopes else ["read"],
        "annotations": {
            "readOnlyHint": not has_file_write and not has_shell,
            "destructiveHint": has_shell,
            "openWorldHint": any(tool.get("has_network") for tool in tools),
        },
        "publisher": repo["owner"]["login"],
        "trusted_server": repo.get("stargazers_count", 0) >= 100,
        "signature": None,
        "tool_count": len(tools),
        "stars": repo.get("stargazers_count", 0),
        "language": repo.get("language") or "unknown",
        "source": "github_mcp",
        "default_branch": repo.get("default_branch") or "main",
        "license": license_id(repo),
    }


def load_cache() -> Dict[str, Dict[str, Any]]:
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return {}


def save_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    CACHE_FILE.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")


def repo_search_space(target: int, pages_per_query: int) -> Dict[str, Dict[str, Any]]:
    repos: Dict[str, Dict[str, Any]] = {}
    for query in SEARCH_QUERIES:
        for page in range(1, pages_per_query + 1):
            if len(repos) >= target * 2:
                return repos
            print(f"Searching query={query!r} page={page} ...")
            result = github_search(query, page)
            items = result.get("items", [])
            print(f"  Got {len(items)} repositories")
            if not items:
                break
            for item in items:
                full_name = item["full_name"]
                current = repos.setdefault(full_name, item)
                current.setdefault("_matched_queries", [])
                if query not in current["_matched_queries"]:
                    current["_matched_queries"].append(query)
            time.sleep(SEARCH_DELAY_SECONDS)
    return repos


def analyze_repo(repo: Dict[str, Any], attempt_source_fetch: bool) -> Dict[str, Any]:
    owner = repo["owner"]["login"]
    name = repo["name"]
    default_branch = repo.get("default_branch") or "main"

    source_files: List[Dict[str, str]] = []
    if attempt_source_fetch:
        for path in entrypoint_candidates():
            content = fetch_raw(owner, name, path, default_branch)
            if content and len(content) > 100:
                source_files.append({"path": path, "content": content})
                if len(source_files) >= 2:
                    break

    source_blobs = [item["content"] for item in source_files]
    tools: List[Dict[str, Any]] = []
    for item in source_files:
        if item["path"].endswith(".py"):
            tools.extend(extract_tools_from_python(item["content"], name))
        elif item["path"].endswith(".ts"):
            tools.extend(extract_tools_from_typescript(item["content"], name))

    if not tools:
        combined = "\n".join(source_blobs)
        scopes = {s.lower() for s in SCOPE_PATTERNS.findall(combined)} if combined else {"read"}
        tools = [{
            "name": name,
            "description": repo.get("description") or f"Repository {repo['full_name']}",
            "scopes": sorted(scopes)[:8] if scopes else ["read"],
            "has_network": bool(NETWORK_PATTERNS.search(combined)),
            "has_file_write": bool(FILE_PATTERNS.search(combined)),
            "has_shell": bool(SHELL_PATTERNS.search(combined)),
            "language": (repo.get("language") or "unknown").lower(),
        }]

    manifest = build_manifest(repo, tools)
    source_code = "\n\n".join(source_blobs)
    meta_evidence = analyze_manifest(manifest)
    static_evidence = analyze_source(repo["full_name"], source_code) if source_code else []
    graph = EvidenceGraph(meta_evidence + static_evidence)
    policy_report = policy_evaluate(graph)
    findings = [finding.to_dict() for finding in policy_report.findings]

    highest_severity = "low"
    if any(f["severity"] == "critical" for f in findings):
        highest_severity = "critical"
    elif any(f["severity"] == "high" for f in findings):
        highest_severity = "high"
    elif any(f["severity"] == "medium" for f in findings):
        highest_severity = "medium"

    return {
        "repo": repo["full_name"],
        "url": repo["html_url"],
        "source": "github_mcp",
        "query_matches": sorted(repo.get("_matched_queries", [])),
        "dedup_key": repo["full_name"],
        "crawled_at": iso_now(),
        "created_at": repo.get("created_at"),
        "updated_at": repo.get("updated_at"),
        "pushed_at": repo.get("pushed_at"),
        "default_branch": default_branch,
        "license": license_id(repo),
        "stars": repo.get("stargazers_count", 0),
        "language": repo.get("language") or "unknown",
        "archived": bool(repo.get("archived", False)),
        "fork": bool(repo.get("fork", False)),
        "code_availability": "source_available" if source_files else "manifest_only",
        "source_paths": [item["path"] for item in source_files],
        "manifest": manifest,
        "tools": tools,
        "meta_evidence": [e.to_dict() for e in meta_evidence],
        "static_evidence": [e.to_dict() for e in static_evidence],
        "policy_risk": highest_severity,
        "policy_decision": policy_report.decision.value,
        "policy_score": policy_report.score,
        "policy_findings": findings,
    }


def crawl_github_mcp(target: int, pages_per_query: int, resume: bool, source_budget: int) -> List[Dict[str, Any]]:
    cache = load_cache() if resume else {}
    if cache:
        print(f"Loaded {len(cache)} cached repositories")

    repos = repo_search_space(target, pages_per_query)
    print(f"Search produced {len(repos)} unique repository candidates")

    samples: List[Dict[str, Any]] = list(cache.values())
    fetched = 0
    remaining_source_budget = source_budget

    for full_name, repo in repos.items():
        if len(samples) >= target:
            break
        if full_name in cache:
            continue

        language = str(repo.get("language") or "").lower()
        attempt_source_fetch = remaining_source_budget > 0 and language in SOURCE_LANGUAGES
        try:
            sample = analyze_repo(repo, attempt_source_fetch=attempt_source_fetch)
            samples.append(sample)
            cache[full_name] = sample
            fetched += 1
            if attempt_source_fetch:
                remaining_source_budget -= 1
            if fetched % 25 == 0:
                print(f"  analyzed {fetched} new repos ({len(samples)} total samples)")
                save_cache(cache)
        except Exception as exc:
            print(f"  skipping {full_name}: {exc}")

    save_cache(cache)
    return samples[:target]


def compute_real_stats(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(samples)
    risk_pattern_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    availability_counts: Counter[str] = Counter()
    license_counts: Counter[str] = Counter()
    language_counts: Counter[str] = Counter()
    high_risk_samples: List[Dict[str, Any]] = []

    for sample in samples:
        by_source[sample["source"]].append(sample)
        availability_counts[sample["code_availability"]] += 1
        license_counts[sample.get("license") or "unknown"] += 1
        language_counts[(sample.get("language") or "unknown").lower()] += 1
        severity_counts[sample["policy_risk"]] += 1
        if sample["policy_risk"] in {"high", "critical"}:
            high_risk_samples.append(sample)

        manifest = sample["manifest"]
        description = (manifest.get("description") or "").lower()
        scopes = {str(s).lower() for s in manifest.get("scopes", [])}
        tools = sample.get("tools", [])

        if any(word in description for word in ["read", "query", "search", "view", "list", "summarize"]):
            if scopes & {"write", "delete", "send", "admin", "export", "modify"}:
                risk_pattern_counts["scope_inflation"] += 1
        if "read" in description and any(t.get("has_file_write") or t.get("has_shell") for t in tools):
            risk_pattern_counts["description_mismatch"] += 1
        if not manifest.get("trusted_server", False):
            risk_pattern_counts["untrusted_publisher"] += 1
        if not manifest.get("signature"):
            risk_pattern_counts["missing_signature"] += 1
        if any(t.get("has_network") for t in tools):
            risk_pattern_counts["open_world_network"] += 1
        if any(phrase in description for phrase in ["ignore", "override", "disregard", "forget"]):
            risk_pattern_counts["instruction_like"] += 1

    per_source_risk = {}
    for source, source_samples in by_source.items():
        scores = [float(sample.get("policy_score", 0.0)) for sample in source_samples]
        high_count = sum(1 for sample in source_samples if sample["policy_risk"] in {"high", "critical"})
        per_source_risk[source] = {
            "count": len(source_samples),
            "mean_score": round(sum(scores) / len(scores), 3) if scores else 0.0,
            "max_score": round(max(scores), 3) if scores else 0.0,
            "high_risk_count": high_count,
        }

    top_high_risk = sorted(
        high_risk_samples,
        key=lambda sample: (-float(sample.get("policy_score", 0.0)), -int(sample.get("stars", 0)), sample["repo"]),
    )[:25]

    return {
        "total_samples": total,
        "sources": {source: len(items) for source, items in by_source.items()},
        "code_availability": dict(availability_counts),
        "languages": dict(language_counts),
        "licenses": dict(license_counts),
        "risk_patterns": {
            name: {
                "count": count,
                "rate": round(count / total, 4) if total else 0.0,
            }
            for name, count in sorted(risk_pattern_counts.items())
        },
        "severity": dict(severity_counts),
        "per_source_risk": per_source_risk,
        "top_high_risk": [
            {
                "repo": sample["repo"],
                "url": sample["url"],
                "license": sample.get("license", "unknown"),
                "stars": sample.get("stars", 0),
                "code_availability": sample.get("code_availability"),
                "policy_risk": sample.get("policy_risk"),
                "policy_decision": sample.get("policy_decision"),
                "policy_score": sample.get("policy_score"),
                "findings": [finding["constraint"] for finding in sample.get("policy_findings", []) if finding["severity"] in {"high", "critical"}],
            }
            for sample in top_high_risk
        ],
    }


def build_data_card(target: int, pages_per_query: int, source_budget: int, samples: List[Dict[str, Any]], stats: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "crawl_started_goal": "Passive real-public MCP/tool repository measurement",
        "crawl_completed_at": iso_now(),
        "target_samples": target,
        "actual_samples": len(samples),
        "queries": SEARCH_QUERIES,
        "pages_per_query": pages_per_query,
        "search_per_page": SEARCH_PER_PAGE,
        "source_budget": source_budget,
        "dedup_rule": "Deduplicate by repository full_name; merge matched queries into query_matches.",
        "filter_rule": "Public GitHub repositories returned by MCP-related search queries; include metadata-only samples when source entrypoints are not recognized or source budget is exhausted.",
        "version_rule": "Record default_branch together with created_at/updated_at/pushed_at from GitHub Search API metadata.",
        "license_rule": "Record SPDX identifier when GitHub provides it; otherwise mark unknown.",
        "availability_rule": stats.get("code_availability", {}),
        "safety_boundary": "Passive metadata/source collection only; no third-party code execution, no destructive calls, no credential use.",
        "limitations": [
            "GitHub Search API coverage is incomplete and query-biased.",
            "Repository-level signals do not prove deployable vulnerabilities.",
            "Manifest-only samples retain metadata evidence but weak implementation coverage.",
        ],
    }


def write_samples_jsonl(samples: List[Dict[str, Any]]) -> None:
    with SAMPLES_FILE.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(sample, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Crawl public MCP-related repositories from GitHub")
    parser.add_argument("--target", type=int, default=1000, help="Number of repositories to retain")
    parser.add_argument("--pages-per-query", type=int, default=3, help="Search pages to request for each query")
    parser.add_argument("--source-budget", type=int, default=200, help="Maximum number of repositories for which raw source entrypoints are fetched")
    parser.add_argument("--resume", action="store_true", help="Resume from cached per-repo samples")
    args = parser.parse_args()

    print("=== Real MCP Ecosystem Crawl ===")
    print(f"target={args.target} pages_per_query={args.pages_per_query} source_budget={args.source_budget} resume={args.resume}")

    samples = crawl_github_mcp(args.target, args.pages_per_query, args.resume, args.source_budget)
    print(f"Collected {len(samples)} samples")

    stats = compute_real_stats(samples)
    data_card = build_data_card(args.target, args.pages_per_query, args.source_budget, samples, stats)

    write_samples_jsonl(samples)
    RESULTS_FILE.write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    DATA_CARD_FILE.write_text(json.dumps(data_card, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Results written to {RESULTS_FILE}")
    print(f"Data card written to {DATA_CARD_FILE}")
    print(f"Samples written to {SAMPLES_FILE}")
    print("Severity distribution:")
    for level, count in sorted(stats.get("severity", {}).items()):
        print(f"  {level}: {count}")


if __name__ == "__main__":
    main()
