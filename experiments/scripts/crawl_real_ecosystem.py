#!/usr/bin/env python3
"""Crawl real MCP-related artifacts from multiple public ecosystems safely.

The collector remains passive: it reads public metadata and a bounded amount of
checked-in source text, but it never executes third-party code, uses real
credentials, or performs destructive calls.

Outputs:
- results/ecosystem/real_ecosystem_samples.jsonl
- results/ecosystem/real_ecosystem_results.json
- results/ecosystem/real_ecosystem_data_card.json
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tarfile
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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

def set_output_prefix(prefix: str) -> None:
    global CACHE_FILE, SAMPLES_FILE, RESULTS_FILE, DATA_CARD_FILE
    CACHE_FILE = OUT_DIR / f"{prefix}_cache.json"
    SAMPLES_FILE = OUT_DIR / f"{prefix}_samples.jsonl"
    RESULTS_FILE = OUT_DIR / f"{prefix}_results.json"
    DATA_CARD_FILE = OUT_DIR / f"{prefix}_data_card.json"

SEARCH_DELAY_SECONDS = 6.5
SEARCH_PER_PAGE = 100
NPM_SEARCH_SIZE = 100
SOURCE_LANGUAGES = {"python", "typescript", "javascript"}

SOURCE_WEIGHTS: Dict[str, float] = {
    "github_mcp": 0.60,
    "npm_mcp": 0.25,
    "hf_spaces_mcp": 0.15,
}

GITHUB_SOURCE_QUERIES: Dict[str, List[str]] = {
    "github_mcp": [
        '"model context protocol" mcp in:name,description,readme',
        'mcp server language:python in:name,description,readme',
        'mcp server language:typescript in:name,description,readme',
        '"@modelcontextprotocol/sdk" in:file language:typescript',
        'langchain tool language:python in:name,description,readme',
        'langgraph tool language:python in:name,description,readme',
        'crewai_tools language:python in:name,description,readme',
        'autogpt plugin in:name,description,readme',
        'agent tool language:typescript in:name,description,readme',
        'agent action language:python in:name,description,readme',
    ],
}

NPM_SEARCH_TERMS = [
    "modelcontextprotocol",
    '"mcp server"',
    '"mcp tool"',
]
HF_SEARCH_LIMIT = 200

PY_TOOL_DECORATOR = re.compile(r'@(?:server|app|mcp)\s*\.\s*tool\s*\(\s*["\']([\w-]+)["\']', re.MULTILINE)
TS_REGISTER_TOOL = re.compile(r'server\.tool\s*\(\s*["\']([\w-]+)["\']', re.MULTILINE)
PY_DESC_FROM_DOCSTRING = re.compile(r'"""([^\"]{10,200})"""', re.MULTILINE)
PY_DESC_FROM_PARAM = re.compile(r'description\s*=\s*["\']([^"\']{10,200})["\']', re.MULTILINE)
SCOPE_PATTERNS = re.compile(r'(read|write|delete|send|admin|export|modify|execute|run|search|query|list|summarize)', re.IGNORECASE)
NETWORK_PATTERNS = re.compile(r'(requests\.(get|post|put)|fetch\(|axios\.|http\.|urllib|aiohttp|websocket|ws\.)', re.IGNORECASE)
FILE_PATTERNS = re.compile(r'(open\s*\(|writeFile|fs\.write|shutil|os\.remove|unlink\(|mkdir\()', re.IGNORECASE)
SHELL_PATTERNS = re.compile(r'(subprocess|os\.system|exec\(|eval\(|child_process|spawn\(|pty)', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _json_request(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def github_request(url: str) -> Dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "skillguardgraph-research-bot",
    }
    return _json_request(url, headers=headers)


def github_search(query: str, page: int) -> Dict[str, Any]:
    encoded_query = urllib.parse.quote(query)
    url = (
        "https://api.github.com/search/repositories"
        f"?q={encoded_query}&per_page={SEARCH_PER_PAGE}&page={page}&sort=stars&order=desc"
    )
    try:
        return github_request(url)
    except Exception:
        time.sleep(SEARCH_DELAY_SECONDS)
        return github_request(url)


def github_repo(owner: str, repo: str) -> Dict[str, Any]:
    return github_request(f"https://api.github.com/repos/{owner}/{repo}")


def fetch_raw(owner: str, repo: str, path: str, branch: str) -> Optional[str]:
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "skillguardgraph-research-bot"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def github_contents(owner: str, repo: str, branch: str, path: str = "") -> Any:
    encoded_path = urllib.parse.quote(path.strip("/"))
    url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    if encoded_path:
        url += f"/{encoded_path}"
    sep = "&" if "?" in url else "?"
    return github_request(f"{url}{sep}ref={urllib.parse.quote(branch)}")

def fetch_bytes(url: str) -> Optional[bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "skillguardgraph-research-bot"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except Exception:
        return None


def tarball_member_texts(tarball_url: str, candidate_suffixes: List[str]) -> List[Dict[str, str]]:
    blob = fetch_bytes(tarball_url)
    if not blob:
        return []

    matches: List[Dict[str, str]] = []
    seen: set[str] = set()

    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            package_json = next((member for member in members if member.name.endswith("/package.json")), None)
            dynamic_suffixes: List[str] = []
            if package_json is not None:
                extracted = archive.extractfile(package_json)
                if extracted is not None:
                    package_json_text = extracted.read().decode("utf-8", errors="replace")
                    dynamic_suffixes = _package_json_entrypoints(package_json_text)

            wanted_suffixes = [
                _normalize_repo_path(path)
                for path in list(candidate_suffixes) + dynamic_suffixes
                if path
            ]
            for suffix in wanted_suffixes:
                for member in members:
                    if member.name in seen or not member.name.endswith(suffix):
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    matches.append({
                        "path": member.name,
                        "content": extracted.read().decode("utf-8", errors="replace"),
                    })
                    seen.add(member.name)
                    break

            if len(matches) < 3:
                for member in members:
                    lower = member.name.lower()
                    if member.name in seen:
                        continue
                    if lower.endswith((".py", ".ts", ".js")) and any(token in lower for token in ("mcp", "server", "index", "main", "tool", "cli", "app")):
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            continue
                        matches.append({
                            "path": member.name,
                            "content": extracted.read().decode("utf-8", errors="replace"),
                        })
                        seen.add(member.name)
                        if len(matches) >= 3:
                            break
    except tarfile.TarError:
        return []

    return matches[:3]


def hf_spaces_search(query: str, limit: int) -> List[Dict[str, Any]]:
    encoded = urllib.parse.quote(query)
    return _json_request(f"https://huggingface.co/api/spaces?search={encoded}&limit={limit}")


def hf_space_metadata(space_id: str) -> Dict[str, Any]:
    encoded = urllib.parse.quote(space_id, safe="/")
    return _json_request(f"https://huggingface.co/api/spaces/{encoded}")


def fetch_hf_space_file(space_id: str, path: str) -> Optional[str]:
    encoded_id = urllib.parse.quote(space_id, safe="/")
    encoded_path = urllib.parse.quote(path.strip("/"))
    url = f"https://huggingface.co/spaces/{encoded_id}/resolve/main/{encoded_path}"
    req = urllib.request.Request(url, headers={"User-Agent": "skillguardgraph-research-bot"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

def npm_search(term: str, offset: int) -> Dict[str, Any]:
    query = urllib.parse.quote(term)
    url = f"https://registry.npmjs.org/-/v1/search?text={query}&size={NPM_SEARCH_SIZE}&from={offset}"
    return _json_request(url)


def npm_package_metadata(name: str) -> Dict[str, Any]:
    encoded = urllib.parse.quote(name, safe="@")
    return _json_request(f"https://registry.npmjs.org/{encoded}")


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------

def normalize_repo_url(url: str | None) -> str | None:
    if not url:
        return None
    value = str(url).strip()
    value = value.replace("git+", "")
    value = value.replace("git://", "https://")
    if value.endswith(".git"):
        value = value[:-4]
    if value.startswith("git@github.com:"):
        value = value.replace("git@github.com:", "https://github.com/")
    return value


def extract_github_repo_ref(url: str | None) -> Optional[Tuple[str, str]]:
    normalized = normalize_repo_url(url)
    if not normalized:
        return None
    parsed = urllib.parse.urlparse(normalized)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def license_id(repo: Dict[str, Any]) -> str:
    lic = repo.get("license") or {}
    if isinstance(lic, dict):
        return lic.get("spdx_id") or lic.get("key") or "unknown"
    return str(lic) if lic else "unknown"


def entrypoint_candidates() -> Iterable[str]:
    yield from (
        "server.py",
        "main.py",
        "src/server.py",
        "src/main.py",
        "index.ts",
        "src/index.ts",
        "server.ts",
        "src/server.ts",
        "index.js",
        "src/index.js",
    )


def _normalize_repo_path(path: str) -> str:
    value = path.lstrip("./")
    return value[1:] if value.startswith("/") else value


def _package_json_entrypoints(package_json_text: str) -> List[str]:
    try:
        doc = json.loads(package_json_text)
    except Exception:
        return []

    values: List[str] = []
    for key in ("main", "module", "types"):
        value = doc.get(key)
        if isinstance(value, str):
            values.append(value)
    bin_field = doc.get("bin")
    if isinstance(bin_field, str):
        values.append(bin_field)
    elif isinstance(bin_field, dict):
        values.extend(str(v) for v in bin_field.values())
    exports = doc.get("exports")
    if isinstance(exports, str):
        values.append(exports)
    elif isinstance(exports, dict):
        for export_value in exports.values():
            if isinstance(export_value, str):
                values.append(export_value)
            elif isinstance(export_value, dict):
                values.extend(str(v) for v in export_value.values() if isinstance(v, str))
    normalized = []
    for value in values:
        value = _normalize_repo_path(value)
        if value.endswith((".py", ".ts", ".js")) and value not in normalized:
            normalized.append(value)
    return normalized


def npm_entrypoint_candidates(version_doc: Dict[str, Any]) -> List[str]:
    candidates: List[str] = []
    for key in ("main", "module", "types"):
        value = version_doc.get(key)
        if isinstance(value, str):
            normalized = _normalize_repo_path(value)
            if normalized.endswith((".py", ".ts", ".js")) and normalized not in candidates:
                candidates.append(normalized)
    bin_field = version_doc.get("bin")
    if isinstance(bin_field, str):
        normalized = _normalize_repo_path(bin_field)
        if normalized.endswith((".py", ".ts", ".js")) and normalized not in candidates:
            candidates.append(normalized)
    elif isinstance(bin_field, dict):
        for value in bin_field.values():
            normalized = _normalize_repo_path(str(value))
            if normalized.endswith((".py", ".ts", ".js")) and normalized not in candidates:
                candidates.append(normalized)
    return candidates


def discover_source_paths(owner: str, repo: str, branch: str, extra_paths: Optional[List[str]] = None) -> List[str]:
    candidates: List[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        normalized = _normalize_repo_path(path)
        if normalized and normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)

    for path in entrypoint_candidates():
        add(path)
    for path in extra_paths or []:
        add(path)

    for listing_path in ("", "src", "server", "app"):
        try:
            listing = github_contents(owner, repo, branch, listing_path)
        except Exception:
            continue
        items = listing if isinstance(listing, list) else [listing]
        for item in items:
            if not isinstance(item, dict) or item.get("type") != "file":
                continue
            rel_path = str(item.get("path") or "")
            name = str(item.get("name") or "").lower()
            if name == "package.json":
                add(rel_path)
            elif rel_path.endswith((".py", ".ts", ".js")) and any(token in name for token in ("mcp", "server", "index", "main", "tool", "cli")):
                add(rel_path)

    package_json_paths = [path for path in list(candidates) if path.endswith("package.json")]
    for package_json_path in package_json_paths[:2]:
        content = fetch_raw(owner, repo, package_json_path, branch)
        if not content:
            continue
        for path in _package_json_entrypoints(content):
            add(path)

    source_paths = [path for path in candidates if path.endswith((".py", ".ts", ".js"))]
    return source_paths[:12]


# ---------------------------------------------------------------------------
# Tool extraction
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tool extraction
# ---------------------------------------------------------------------------

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


def summarize_tools_from_source(source_blobs: List[str], artifact_name: str, fallback_language: str) -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = []
    for blob in source_blobs:
        tools.extend(extract_tools_from_python(blob, artifact_name))
        tools.extend(extract_tools_from_typescript(blob, artifact_name))
    if tools:
        return tools

    combined = "\n".join(source_blobs)
    scopes = {str(s).lower() for s in SCOPE_PATTERNS.findall(combined)} if combined else {"read"}
    return [{
        "name": artifact_name,
        "description": f"Artifact {artifact_name}",
        "scopes": sorted(scopes)[:8] if scopes else ["read"],
        "has_network": bool(NETWORK_PATTERNS.search(combined)),
        "has_file_write": bool(FILE_PATTERNS.search(combined)),
        "has_shell": bool(SHELL_PATTERNS.search(combined)),
        "language": fallback_language or "unknown",
    }]


# ---------------------------------------------------------------------------
# Manifest builders
# ---------------------------------------------------------------------------

def _aggregate_tool_flags(tools: List[Dict[str, Any]]) -> Tuple[set[str], bool, bool, bool]:
    all_scopes: set[str] = set()
    has_network = False
    has_file_write = False
    has_shell = False
    for tool in tools:
        all_scopes.update(tool.get("scopes", []))
        has_network = has_network or bool(tool.get("has_network"))
        has_file_write = has_file_write or bool(tool.get("has_file_write"))
        has_shell = has_shell or bool(tool.get("has_shell"))
    return all_scopes, has_network, has_file_write, has_shell


def build_github_manifest(repo: Dict[str, Any], tools: List[Dict[str, Any]], source_label: str) -> Dict[str, Any]:
    all_scopes, has_network, has_file_write, has_shell = _aggregate_tool_flags(tools)
    description = repo.get("description") or f"Public repository {repo['full_name']}"
    return {
        "name": repo["name"],
        "description": description,
        "scopes": sorted(all_scopes)[:8] if all_scopes else ["read"],
        "annotations": {
            "readOnlyHint": not has_file_write and not has_shell,
            "destructiveHint": has_shell,
            "openWorldHint": has_network,
        },
        "publisher": repo["owner"]["login"],
        "trusted_server": repo.get("stargazers_count", 0) >= 100,
        "signature": None,
        "tool_count": len(tools),
        "stars": repo.get("stargazers_count", 0),
        "language": repo.get("language") or "unknown",
        "source": source_label,
        "default_branch": repo.get("default_branch") or "main",
        "license": license_id(repo),
    }


def build_npm_manifest(
    package_name: str,
    package_doc: Dict[str, Any],
    version_doc: Dict[str, Any],
    package_search_entry: Dict[str, Any],
    linked_repo: Optional[Dict[str, Any]],
    tools: List[Dict[str, Any]],
) -> Dict[str, Any]:
    all_scopes, has_network, has_file_write, has_shell = _aggregate_tool_flags(tools)
    publisher = package_search_entry.get("package", {}).get("publisher") or {}
    trusted_publisher = publisher.get("trustedPublisher")
    dist = version_doc.get("dist") or {}
    signatures = dist.get("signatures") or []
    linked_stars = int(linked_repo.get("stargazers_count", 0)) if linked_repo else 0
    description = version_doc.get("description") or package_search_entry.get("package", {}).get("description") or f"npm package {package_name}"
    manifest = {
        "name": package_name,
        "description": description,
        "scopes": sorted(all_scopes)[:8] if all_scopes else ["read"],
        "annotations": {
            "readOnlyHint": not has_file_write and not has_shell,
            "destructiveHint": has_shell,
            "openWorldHint": has_network,
        },
        "publisher": publisher.get("username") or version_doc.get("author", {}).get("name") or "unknown",
        "trusted_server": bool(trusted_publisher) or linked_stars >= 100,
        "signature": signatures[0]["keyid"] if signatures else None,
        "tool_count": len(tools),
        "stars": linked_stars,
        "language": (linked_repo or {}).get("language") or tools[0].get("language") or "unknown",
        "source": "npm_mcp",
        "version": version_doc.get("version"),
        "license": version_doc.get("license") or package_search_entry.get("package", {}).get("license") or "unknown",
        "downloads_weekly": package_search_entry.get("downloads", {}).get("weekly", 0),
        "dist_integrity": bool(dist.get("integrity")),
        "repository": normalize_repo_url((version_doc.get("repository") or {}).get("url") if isinstance(version_doc.get("repository"), dict) else version_doc.get("repository")),
    }
    return manifest


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def load_cache() -> Dict[str, Dict[str, Any]]:
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    return {}


def save_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    CACHE_FILE.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")


def cached_sample(cache: Dict[str, Dict[str, Any]], source: str, dedup_key: str) -> Optional[Dict[str, Any]]:
    namespaced = f"{source}:{dedup_key}"
    if namespaced in cache:
        return cache[namespaced]
    legacy = cache.get(dedup_key)
    if legacy and legacy.get("source") == source:
        cache[namespaced] = legacy
        return legacy
    return None


def put_cached_sample(cache: Dict[str, Dict[str, Any]], source: str, dedup_key: str, sample: Dict[str, Any]) -> None:
    cache[f"{source}:{dedup_key}"] = sample


def cached_source_samples(cache: Dict[str, Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
    samples = [
        sample
        for key, sample in cache.items()
        if key.startswith(f"{source}:")
    ]
    samples.sort(key=lambda sample: str(sample.get("dedup_key") or sample.get("repo") or ""))
    return samples

# ---------------------------------------------------------------------------
# Analysis core
# ---------------------------------------------------------------------------

def analyze_artifact(
    *,
    artifact_id: str,
    artifact_url: str,
    source_label: str,
    dedup_key: str,
    manifest: Dict[str, Any],
    tools: List[Dict[str, Any]],
    source_files: List[Dict[str, str]],
    source_code: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    meta_evidence = analyze_manifest(manifest)
    static_evidence = analyze_source(artifact_id, source_code) if source_code else []
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

    sample = {
        "repo": artifact_id,
        "url": artifact_url,
        "source": source_label,
        "dedup_key": dedup_key,
        "crawled_at": iso_now(),
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
    sample.update(metadata)
    return sample


# ---------------------------------------------------------------------------
# GitHub crawl
# ---------------------------------------------------------------------------

def github_search_space(source: str, target: int, pages_per_query: int) -> Dict[str, Dict[str, Any]]:
    repos: Dict[str, Dict[str, Any]] = {}
    queries = GITHUB_SOURCE_QUERIES[source]
    for query in queries:
        for page in range(1, pages_per_query + 1):
            if len(repos) >= target * 2:
                return repos
            print(f"Searching source={source} query={query!r} page={page} ...")
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


def analyze_github_repo(repo: Dict[str, Any], source_label: str, attempt_source_fetch: bool) -> Dict[str, Any]:
    owner = repo["owner"]["login"]
    name = repo["name"]
    full_name = repo["full_name"]
    default_branch = repo.get("default_branch") or "main"

    source_files: List[Dict[str, str]] = []
    if attempt_source_fetch:
        for path in discover_source_paths(owner, name, default_branch):
            content = fetch_raw(owner, name, path, default_branch)
            if content and len(content) > 100:
                source_files.append({"path": path, "content": content})
                if len(source_files) >= 3:
                    break

    source_blobs = [item["content"] for item in source_files]
    tools = summarize_tools_from_source(source_blobs, full_name, str(repo.get("language") or "unknown").lower()) if source_blobs else [{
        "name": name,
        "description": repo.get("description") or f"Repository {full_name}",
        "scopes": ["read"],
        "has_network": False,
        "has_file_write": False,
        "has_shell": False,
        "language": (repo.get("language") or "unknown").lower(),
    }]
    manifest = build_github_manifest(repo, tools, source_label)

    return analyze_artifact(
        artifact_id=full_name,
        artifact_url=repo["html_url"],
        source_label=source_label,
        dedup_key=full_name,
        manifest=manifest,
        tools=tools,
        source_files=source_files,
        source_code="\n\n".join(source_blobs),
        metadata={
            "query_matches": sorted(repo.get("_matched_queries", [])),
            "created_at": repo.get("created_at"),
            "updated_at": repo.get("updated_at"),
            "pushed_at": repo.get("pushed_at"),
            "default_branch": default_branch,
            "license": license_id(repo),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language") or "unknown",
            "archived": bool(repo.get("archived", False)),
            "fork": bool(repo.get("fork", False)),
        },
    )


def crawl_github_source(source: str, target: int, pages_per_query: int, cache: Dict[str, Dict[str, Any]], source_budget: int) -> Tuple[List[Dict[str, Any]], int]:
    cached_items = cached_source_samples(cache, source)
    if len(cached_items) >= target:
        print(f"Using {target} cached GitHub samples for {source}")
        return cached_items[:target], source_budget

    samples: List[Dict[str, Any]] = list(cached_items)
    remaining_source_budget = source_budget
    repos = github_search_space(source, target, pages_per_query)
    print(f"Search produced {len(repos)} unique GitHub candidates for {source}")

    for full_name, repo in repos.items():
        if len(samples) >= target:
            break
        if any(sample.get("dedup_key") == full_name for sample in samples):
            continue
        language = str(repo.get("language") or "").lower()
        attempt_source_fetch = remaining_source_budget > 0 and language in SOURCE_LANGUAGES
        try:
            sample = analyze_github_repo(repo, source, attempt_source_fetch=attempt_source_fetch)
            samples.append(sample)
            put_cached_sample(cache, source, full_name, sample)
            if attempt_source_fetch:
                remaining_source_budget -= 1
            if len(samples) % 25 == 0:
                print(f"  analyzed {len(samples)} GitHub samples for {source}")
                save_cache(cache)
        except Exception as exc:
            print(f"  skipping {full_name}: {exc}")
    save_cache(cache)
    return samples[:target], remaining_source_budget


# ---------------------------------------------------------------------------
# npm crawl
# ---------------------------------------------------------------------------

def npm_search_space(target: int) -> Dict[str, Dict[str, Any]]:
    packages: Dict[str, Dict[str, Any]] = {}
    for term in NPM_SEARCH_TERMS:
        for offset in range(0, max(target * 2, NPM_SEARCH_SIZE), NPM_SEARCH_SIZE):
            if len(packages) >= target * 2:
                return packages
            print(f"Searching npm term={term!r} offset={offset} ...")
            result = npm_search(term, offset)
            objects = result.get("objects", [])
            print(f"  Got {len(objects)} packages")
            if not objects:
                break
            for obj in objects:
                pkg = obj.get("package", {})
                name = pkg.get("name") or ""
                description = (pkg.get("description") or "").lower()
                haystack = f"{name.lower()} {description} {' '.join(pkg.get('keywords') or [])}"
                if "mcp" not in haystack and "modelcontextprotocol" not in haystack:
                    continue
                current = packages.setdefault(name, obj)
                current.setdefault("_matched_terms", [])
                if term not in current["_matched_terms"]:
                    current["_matched_terms"].append(term)
            if len(objects) < NPM_SEARCH_SIZE:
                break
    return packages


def analyze_npm_package(entry: Dict[str, Any], attempt_source_fetch: bool) -> Dict[str, Any]:
    package_meta = entry["package"]
    package_name = package_meta["name"]
    metadata = npm_package_metadata(package_name)
    latest_version = metadata.get("dist-tags", {}).get("latest")
    version_doc = (metadata.get("versions") or {}).get(latest_version or "", {})
    repository_field = version_doc.get("repository")
    if isinstance(repository_field, dict):
        repository_url = repository_field.get("url")
    else:
        repository_url = repository_field or package_meta.get("links", {}).get("repository")

    linked_repo: Optional[Dict[str, Any]] = None
    source_files: List[Dict[str, str]] = []
    owner_repo = extract_github_repo_ref(repository_url)
    if owner_repo:
        owner, repo_name = owner_repo
        try:
            linked_repo = github_repo(owner, repo_name)
        except Exception:
            linked_repo = None
    if attempt_source_fetch and linked_repo is not None:
        default_branch = linked_repo.get("default_branch") or "main"
        extra_paths = npm_entrypoint_candidates(version_doc)
        for path in discover_source_paths(owner_repo[0], owner_repo[1], default_branch, extra_paths=extra_paths):
            content = fetch_raw(owner_repo[0], owner_repo[1], path, default_branch)
            if content and len(content) > 100:
                source_files.append({"path": path, "content": content})
                if len(source_files) >= 3:
                    break
    if attempt_source_fetch and not source_files:
        tarball_url = str((version_doc.get("dist") or {}).get("tarball") or "")
        if tarball_url:
            source_files = tarball_member_texts(tarball_url, npm_entrypoint_candidates(version_doc))

    source_blobs = [item["content"] for item in source_files]
    fallback_language = str((linked_repo or {}).get("language") or "unknown").lower()
    if not source_blobs and package_meta.get("description"):
        source_blobs = [package_meta["description"]]
    tools = summarize_tools_from_source(source_blobs, package_name, fallback_language)
    manifest = build_npm_manifest(package_name, metadata, version_doc, entry, linked_repo, tools)

    license_value = version_doc.get("license") or package_meta.get("license") or license_id(linked_repo or {})
    return analyze_artifact(
        artifact_id=package_name,
        artifact_url=package_meta.get("links", {}).get("npm") or f"https://www.npmjs.com/package/{package_name}",
        source_label="npm_mcp",
        dedup_key=package_name,
        manifest=manifest,
        tools=tools,
        source_files=source_files,
        source_code="\n\n".join(source_blobs if source_files else []),
        metadata={
            "query_matches": sorted(entry.get("_matched_terms", [])),
            "created_at": package_meta.get("date"),
            "updated_at": entry.get("updated"),
            "pushed_at": None,
            "default_branch": (linked_repo or {}).get("default_branch"),
            "license": license_value or "unknown",
            "stars": int((linked_repo or {}).get("stargazers_count", 0)),
            "language": (linked_repo or {}).get("language") or fallback_language or "unknown",
            "archived": bool((linked_repo or {}).get("archived", False)),
            "fork": bool((linked_repo or {}).get("fork", False)),
            "package_version": latest_version,
            "package_weekly_downloads": entry.get("downloads", {}).get("weekly", 0),
            "linked_repository": normalize_repo_url(repository_url),
        },
    )


def crawl_npm_source(target: int, cache: Dict[str, Dict[str, Any]], source_budget: int) -> Tuple[List[Dict[str, Any]], int]:
    cached_items = cached_source_samples(cache, "npm_mcp")
    if len(cached_items) >= target:
        print(f"Using {target} cached npm samples")
        return cached_items[:target], source_budget

    samples: List[Dict[str, Any]] = list(cached_items)
    remaining_source_budget = source_budget
    packages = npm_search_space(target)
    print(f"Search produced {len(packages)} unique npm candidates")

    for package_name, entry in packages.items():
        if len(samples) >= target:
            break
        if any(sample.get("dedup_key") == package_name for sample in samples):
            continue
        attempt_source_fetch = remaining_source_budget > 0
        try:
            sample = analyze_npm_package(entry, attempt_source_fetch=attempt_source_fetch)
            samples.append(sample)
            put_cached_sample(cache, "npm_mcp", package_name, sample)
            if attempt_source_fetch and sample.get("code_availability") == "source_available":
                remaining_source_budget -= 1
            if len(samples) % 25 == 0:
                print(f"  analyzed {len(samples)} npm samples")
                save_cache(cache)
        except Exception as exc:
            print(f"  skipping npm package {package_name}: {exc}")
    save_cache(cache)
    return samples[:target], remaining_source_budget

# ---------------------------------------------------------------------------
# Hugging Face Spaces crawl
# ---------------------------------------------------------------------------

def hf_space_search_space(target: int) -> Dict[str, Dict[str, Any]]:
    spaces: Dict[str, Dict[str, Any]] = {}
    for query in ("mcp", "mcp-server", "model context protocol"):
        print(f"Searching Hugging Face Spaces query={query!r} ...")
        try:
            items = hf_spaces_search(query, HF_SEARCH_LIMIT)
        except Exception as exc:
            print(f"  query failed: {exc}")
            continue
        print(f"  Got {len(items)} spaces")
        for item in items:
            space_id = item.get("id")
            if not space_id:
                continue
            current = spaces.setdefault(space_id, item)
            current.setdefault("_matched_terms", [])
            if query not in current["_matched_terms"]:
                current["_matched_terms"].append(query)
            if len(spaces) >= target * 2:
                return spaces
    return spaces


def build_hf_manifest(space_meta: Dict[str, Any], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
    all_scopes, has_network, has_file_write, has_shell = _aggregate_tool_flags(tools)
    card = space_meta.get("cardData") or {}
    tags = space_meta.get("tags") or []
    description = card.get("title") or f"Hugging Face Space {space_meta.get('id')}"
    return {
        "name": str(space_meta.get("id") or "hf_space"),
        "description": description,
        "scopes": sorted(all_scopes)[:8] if all_scopes else ["read"],
        "annotations": {
            "readOnlyHint": not has_file_write and not has_shell,
            "destructiveHint": has_shell,
            "openWorldHint": has_network,
        },
        "publisher": space_meta.get("author") or "unknown",
        "trusted_server": int(space_meta.get("likes", 0)) >= 50 or "verified" in tags,
        "signature": None,
        "tool_count": len(tools),
        "stars": int(space_meta.get("likes", 0)),
        "language": str(card.get("sdk") or "unknown"),
        "source": "hf_spaces_mcp",
        "sdk": card.get("sdk") or "unknown",
        "host": space_meta.get("host"),
    }


def analyze_hf_space(space_entry: Dict[str, Any], attempt_source_fetch: bool) -> Dict[str, Any]:
    space_id = str(space_entry["id"])
    meta = hf_space_metadata(space_id)
    source_files: List[Dict[str, str]] = []
    if attempt_source_fetch:
        card = meta.get("cardData") or {}
        siblings = meta.get("siblings") or []
        candidate_paths: List[str] = []
        app_file = card.get("app_file")
        if isinstance(app_file, str):
            candidate_paths.append(app_file)
        for sibling in siblings:
            path = str(sibling.get("rfilename") or "")
            if path.endswith((".py", ".ts", ".js", "README.md")) and any(token in path.lower() for token in ("app", "server", "index", "main", "mcp", "readme")):
                candidate_paths.append(path)
        seen: set[str] = set()
        for path in candidate_paths:
            if path in seen:
                continue
            seen.add(path)
            content = fetch_hf_space_file(space_id, path)
            if content and len(content) > 80:
                source_files.append({"path": path, "content": content})
                if len(source_files) >= 3:
                    break

    source_blobs = [item["content"] for item in source_files if item["path"].endswith((".py", ".ts", ".js"))]
    if not source_blobs:
        readmes = [item["content"] for item in source_files if item["path"].lower().endswith("readme.md")]
        if readmes:
            source_blobs = [readmes[0]]
    fallback_language = str((meta.get("cardData") or {}).get("sdk") or "unknown").lower()
    tools = summarize_tools_from_source(source_blobs, space_id, fallback_language)
    manifest = build_hf_manifest(meta, tools)

    return analyze_artifact(
        artifact_id=space_id,
        artifact_url=f"https://huggingface.co/spaces/{space_id}",
        source_label="hf_spaces_mcp",
        dedup_key=space_id,
        manifest=manifest,
        tools=tools,
        source_files=source_files,
        source_code="\n\n".join(source_blobs),
        metadata={
            "query_matches": sorted(space_entry.get("_matched_terms", [])),
            "created_at": meta.get("createdAt"),
            "updated_at": meta.get("lastModified"),
            "pushed_at": meta.get("lastModified"),
            "default_branch": "main",
            "license": "unknown",
            "stars": int(meta.get("likes", 0)),
            "language": str((meta.get("cardData") or {}).get("sdk") or "unknown"),
            "archived": bool(meta.get("disabled", False)),
            "fork": False,
            "sdk": (meta.get("cardData") or {}).get("sdk"),
            "hf_host": meta.get("host"),
        },
    )


def crawl_hf_spaces_source(target: int, cache: Dict[str, Dict[str, Any]], source_budget: int) -> Tuple[List[Dict[str, Any]], int]:
    cached_items = cached_source_samples(cache, "hf_spaces_mcp")
    if len(cached_items) >= target:
        print(f"Using {target} cached Hugging Face spaces")
        return cached_items[:target], source_budget

    samples: List[Dict[str, Any]] = list(cached_items)
    remaining_source_budget = source_budget
    spaces = hf_space_search_space(target)
    print(f"Search produced {len(spaces)} unique Hugging Face spaces")

    for space_id, entry in spaces.items():
        if len(samples) >= target:
            break
        if any(sample.get("dedup_key") == space_id for sample in samples):
            continue
        attempt_source_fetch = remaining_source_budget > 0
        try:
            sample = analyze_hf_space(entry, attempt_source_fetch=attempt_source_fetch)
            samples.append(sample)
            put_cached_sample(cache, "hf_spaces_mcp", space_id, sample)
            if attempt_source_fetch and sample.get("code_availability") == "source_available":
                remaining_source_budget -= 1
            if len(samples) % 25 == 0:
                print(f"  analyzed {len(samples)} Hugging Face spaces")
                save_cache(cache)
        except Exception as exc:
            print(f"  skipping Hugging Face space {space_id}: {exc}")
    save_cache(cache)
    return samples[:target], remaining_source_budget


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def allocate_targets(total_target: int, enabled_sources: List[str]) -> Dict[str, int]:
    weight_sum = sum(SOURCE_WEIGHTS.get(source, 1.0) for source in enabled_sources)
    allocations: Dict[str, int] = {}
    assigned = 0
    for source in enabled_sources[:-1]:
        share = SOURCE_WEIGHTS.get(source, 1.0) / weight_sum
        quota = max(1, int(round(total_target * share)))
        allocations[source] = quota
        assigned += quota
    allocations[enabled_sources[-1]] = max(1, total_target - assigned)
    return allocations


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


def build_data_card(
    *,
    target: int,
    pages_per_query: int,
    source_budget: int,
    enabled_sources: List[str],
    samples: List[Dict[str, Any]],
    stats: Dict[str, Any],
) -> Dict[str, Any]:
    source_details: Dict[str, Any] = {}
    if "github_mcp" in enabled_sources:
        source_details["github_mcp"] = {
            "queries": GITHUB_SOURCE_QUERIES["github_mcp"],
            "pages_per_query": pages_per_query,
            "search_per_page": SEARCH_PER_PAGE,
        }
    if "npm_mcp" in enabled_sources:
        source_details["npm_mcp"] = {
            "terms": NPM_SEARCH_TERMS,
            "search_page_size": NPM_SEARCH_SIZE,
        }
    if "hf_spaces_mcp" in enabled_sources:
        source_details["hf_spaces_mcp"] = {
            "queries": ["mcp", "mcp-server", "model context protocol"],
            "search_limit": HF_SEARCH_LIMIT,
        }
    return {
        "crawl_started_goal": "Passive real-public MCP/tool/package/space measurement",
        "crawl_completed_at": iso_now(),
        "target_samples": target,
        "actual_samples": len(samples),
        "enabled_sources": enabled_sources,
        "source_details": source_details,
        "source_budget": source_budget,
        "dedup_rule": "Deduplicate by source-specific artifact identifier (GitHub full_name, npm package name, or Hugging Face space id); retain linked_repository when an upstream package points to GitHub.",
        "filter_rule": "Collect public GitHub MCP repositories, npm MCP-related packages, and Hugging Face Spaces returned by MCP-related search terms; include metadata-only samples when bounded source probing finds no recognized entrypoint.",
        "version_rule": "Record GitHub default_branch plus timestamps; record npm latest package version and package publication/update time; record Hugging Face Space sha and created/lastModified timestamps when exposed.",
        "license_rule": "Record SPDX identifier when the upstream API provides one; otherwise mark unknown.",
        "availability_rule": stats.get("code_availability", {}),
        "safety_boundary": "Passive metadata/source collection only; no third-party code execution, no destructive calls, no credential use.",
        "limitations": [
            "GitHub, npm, and Hugging Face search coverage are query-biased and incomplete.",
            "Repository-level, package-level, and space-level signals do not prove deployable vulnerabilities.",
            "Manifest-only samples retain metadata evidence but weak implementation coverage.",
            "npm and Hugging Face source coverage depends on linked public files when present.",
        ],
    }


def write_samples_jsonl(samples: List[Dict[str, Any]]) -> None:
    with SAMPLES_FILE.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(sample, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Crawl public MCP-related artifacts from GitHub, npm, and Hugging Face Spaces")
    parser.add_argument("--target", type=int, default=1000, help="Number of artifacts to retain")
    parser.add_argument("--pages-per-query", type=int, default=3, help="GitHub search pages to request for each query")
    parser.add_argument("--source-budget", type=int, default=200, help="Maximum number of artifacts for which raw source entrypoints are fetched")
    parser.add_argument("--resume", action="store_true", help="Resume from cached per-artifact samples")
    parser.add_argument("--sources", default="github_mcp,npm_mcp,hf_spaces_mcp", help="Comma-separated source set")
    parser.add_argument("--output-prefix", default="real_ecosystem", help="Output file prefix under results/ecosystem/")
    args = parser.parse_args()

    set_output_prefix(args.output_prefix)

    enabled_sources = [item.strip() for item in args.sources.split(",") if item.strip()]
    if not enabled_sources:
        raise SystemExit("No sources enabled")
    for source in enabled_sources:
        if source not in SOURCE_WEIGHTS:
            raise SystemExit(f"Unsupported source: {source}")

    print("=== Real Public Ecosystem Crawl ===")
    print(
        f"target={args.target} pages_per_query={args.pages_per_query} "
        f"source_budget={args.source_budget} resume={args.resume} "
        f"sources={enabled_sources} output_prefix={args.output_prefix}"
    )

    cache = load_cache() if args.resume else {}
    if cache:
        print(f"Loaded {len(cache)} cached artifacts")

    quotas = allocate_targets(args.target, enabled_sources)
    remaining_budget = args.source_budget
    samples: List[Dict[str, Any]] = []

    for source in enabled_sources:
        quota = quotas[source]
        if source == "github_mcp":
            source_samples, remaining_budget = crawl_github_source(source, quota, args.pages_per_query, cache, remaining_budget)
        elif source == "npm_mcp":
            source_samples, remaining_budget = crawl_npm_source(quota, cache, remaining_budget)
        elif source == "hf_spaces_mcp":
            source_samples, remaining_budget = crawl_hf_spaces_source(quota, cache, remaining_budget)
        else:
            raise SystemExit(f"Unsupported source: {source}")
        samples.extend(source_samples)

    if len(samples) < args.target:
        deficit = args.target - len(samples)
        for fallback_source in ("github_mcp", "npm_mcp"):
            if fallback_source not in enabled_sources or deficit <= 0:
                continue
            existing = {sample["dedup_key"] for sample in samples if sample["source"] == fallback_source}
            refill_target = len(existing) + deficit
            print(f"Topping up from {fallback_source} with deficit={deficit}")
            if fallback_source == "github_mcp":
                extra_samples, remaining_budget = crawl_github_source(
                    fallback_source, refill_target, args.pages_per_query, cache, remaining_budget,
                )
            else:
                extra_samples, remaining_budget = crawl_npm_source(refill_target, cache, remaining_budget)
            for sample in extra_samples:
                if sample["dedup_key"] not in existing:
                    samples.append(sample)
                    existing.add(sample["dedup_key"])
                    deficit -= 1
                    if deficit <= 0:
                        break

    samples = samples[:args.target]
    print(f"Collected {len(samples)} samples")

    stats = compute_real_stats(samples)
    data_card = build_data_card(
        target=args.target,
        pages_per_query=args.pages_per_query,
        source_budget=args.source_budget,
        enabled_sources=enabled_sources,
        samples=samples,
        stats=stats,
    )
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
